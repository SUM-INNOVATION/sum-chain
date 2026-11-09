//! The evidence layout (`evidence_meta`): the A3 evidence records under
//! versioned keys in the existing `meta` family, the first valid record per
//! slot kept (D5).
//!
//! Five groups: namespace, first-wins, corruption, rollback, dormancy. The
//! namespace group holds the namespace-collision tests the owner required
//! with the adoption of `finality/evidence/v1/` (2026-11-09): every META key
//! and prefix in the workspace stays clear of both evidence namespaces, and
//! the evidence keys cannot be confused with each other or with the other
//! `finality/` keys.
//!
//! The record checks here are STAND-INS for the merged codecs in
//! `sumchain-finality-foundations` (`evidence`), which this crate may not name
//! while both dormancy guards stand:
//! - equivocation: the 363-byte layout, magic and schema, the two vote
//!   bodies' slot fields equal, and `A.block_id < B.block_id`; the slot is
//!   read from vote A's body (the ratified vote layout). Signatures are the
//!   real verifier's job (E1, tested in `finality-foundations`).
//! - upgrade conflict: a table of known records and their sequences, since
//!   the manifest inside them (A4) is not adopted.
//!
//! The draft vectors come from `docs/proposals/g2-byte-review/vectors.json`.
//! Every key in this file is synthetic.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Barrier;

use serde_json::Value;
use sumchain_primitives::{Block, BlockHeader, BlockHeight, Hash};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutedCandidate, ExecutionSubject, JournalRecord,
};
use sumchain_storage::certified_guard::{audit_at_start, certified_block};
use sumchain_storage::certified_meta::{
    certificate_key, parse_certificate_key, CERTIFICATE_KEY_PREFIX, FINALIZED_POINTER_KEY,
};
use sumchain_storage::db::{cf, Database, ALL_CFS};
use sumchain_storage::evidence_meta::{
    audit_evidence, equivocation_record, parse_equivocation_key, parse_upgrade_conflict_key,
    record_equivocation, record_upgrade_conflict, upgrade_conflict_key, upgrade_conflict_record,
    EquivocationSlot, EquivocationVerifier, EvidenceAudit, EvidenceError, EvidenceRefusal,
    EvidenceViolation, Insert, UpgradeConflictVerifier, EQUIVOCATION_KEY_LEN,
    EQUIVOCATION_KEY_PREFIX, EQUIVOCATION_SLOT_LEN, UPGRADE_CONFLICT_KEY_LEN,
    UPGRADE_CONFLICT_KEY_PREFIX,
};
use sumchain_storage::journal::{FORMAT_HIGH_WATER_META_KEY, UNDO_HISTORY_FLOOR_META_KEY};
use sumchain_storage::messaging_store::REGISTRY_SEED_META_KEY;
use sumchain_storage::pruner::DISK_BUDGET_META_KEY;
use sumchain_storage::schema::{journal_key, meta_keys, BlockStore};
use sumchain_storage::ApplicationJournal;
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;

// ── draft vectors ────────────────────────────────────────────────────────────

const DRAFT_VECTORS: &str = include_str!("../../../docs/proposals/g2-byte-review/vectors.json");

fn draft(name: &str) -> Vec<u8> {
    let v: Value = serde_json::from_str(DRAFT_VECTORS).expect("the draft vectors are JSON");
    let hex = v["vectors"]
        .as_array()
        .expect("a vector list")
        .iter()
        .find(|x| x["name"] == name)
        .unwrap_or_else(|| panic!("draft vector {name:?}"))["hex"]
        .as_str()
        .expect("a hex string")
        .to_owned();
    hex::decode(hex).expect("valid hex")
}

fn draft_equivocation() -> Vec<u8> {
    draft("equivocation evidence idx=2 h=7 r=0 precommit")
}

fn draft_conflict() -> Vec<u8> {
    draft("upgrade-conflict evidence A/B sequence 1")
}

/// The draft record's slot: validator 2, h = 7, r = 0, precommit.
const DRAFT_SLOT: EquivocationSlot = EquivocationSlot {
    height: 7,
    round: 0,
    vote_type: 2,
    validator_index: 2,
};

// ── stand-ins for the merged codecs ──────────────────────────────────────────

/// `FEVDv1` ‖ NUL. Spelled as bytes: the adopted magic's only literal home is
/// `finality-foundations/src/evidence.rs` (check.py).
const EVIDENCE_MAGIC: [u8; 7] = [0x46, 0x45, 0x56, 0x44, 0x76, 0x31, 0x00];
const BODY: usize = 113;
const SIG: usize = 64;
const RECORD: usize = 7 + 2 + 2 * (BODY + SIG);
const A: usize = 9;
const B: usize = 9 + BODY + SIG;

fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

struct EvShape;

impl EquivocationVerifier for EvShape {
    fn verify(&self, r: &[u8]) -> Result<EquivocationSlot, EvidenceRefusal> {
        let refuse = |why: &str| Err(EvidenceRefusal(why.into()));
        if r.len() != RECORD || r[..7] != EVIDENCE_MAGIC || r[7..9] != 1u16.to_le_bytes() {
            return refuse("not a v1 equivocation record");
        }
        let (a, b) = (&r[A..A + BODY], &r[B..B + BODY]);
        // Every body field but block_id (42..74) names the slot.
        if a[..42] != b[..42] || a[74..] != b[74..] {
            return refuse("the votes are for different slots");
        }
        if a[42..74] >= b[42..74] {
            return refuse("block_id A is not below block_id B");
        }
        Ok(EquivocationSlot {
            height: le_u64(&a[34..42]),
            round: u32::from_le_bytes(a[74..78].try_into().unwrap()),
            vote_type: a[78],
            validator_index: u16::from_le_bytes(a[111..113].try_into().unwrap()),
        })
    }
}

/// A structurally valid record for `slot` naming blocks `[lo; 32]` and
/// `[hi; 32]` (lo < hi), with zero signatures.
fn equivocation(slot: EquivocationSlot, lo: u8, hi: u8) -> Vec<u8> {
    assert!(lo < hi);
    let body = |block: u8| {
        let mut b = Vec::with_capacity(BODY);
        b.extend_from_slice(&[0xc0; 32]);
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&slot.height.to_le_bytes());
        b.extend_from_slice(&[block; 32]);
        b.extend_from_slice(&slot.round.to_le_bytes());
        b.push(slot.vote_type);
        b.extend_from_slice(&[0x5a; 32]);
        b.extend_from_slice(&slot.validator_index.to_le_bytes());
        b
    };
    let mut r = EVIDENCE_MAGIC.to_vec();
    r.extend_from_slice(&1u16.to_le_bytes());
    for block in [lo, hi] {
        r.extend_from_slice(&body(block));
        r.extend_from_slice(&[0u8; SIG]);
    }
    assert_eq!(EvShape.verify(&r), Ok(slot));
    r
}

/// Accepts exactly the records in its table, for the sequence it lists.
struct UcTable(Vec<(Vec<u8>, u64)>);

impl UpgradeConflictVerifier for UcTable {
    fn verify(&self, record: &[u8]) -> Result<u64, EvidenceRefusal> {
        self.0
            .iter()
            .find(|(r, _)| r.as_slice() == record)
            .map(|(_, sequence)| *sequence)
            .ok_or_else(|| EvidenceRefusal("not a record in the table".into()))
    }
}

/// An opaque stand-in record for `sequence`, distinguished by `tag`.
fn conflict(sequence: u64, tag: u16) -> Vec<u8> {
    let mut r = b"stand-in upgrade conflict ".to_vec();
    r.extend_from_slice(&sequence.to_le_bytes());
    r.extend_from_slice(&tag.to_le_bytes());
    r
}

fn draft_table() -> UcTable {
    UcTable(vec![(draft_conflict(), 1)])
}

// ── fixtures ─────────────────────────────────────────────────────────────────

fn open(dir: &Path) -> Database {
    Database::open_default(dir).expect("open")
}

fn meta_rows(db: &Database) -> BTreeSet<(Vec<u8>, Vec<u8>)> {
    db.iter_checked_from(cf::META, None)
        .unwrap()
        .map(|e| {
            let (k, v) = e.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect()
}

fn evidence_rows(db: &Database) -> BTreeSet<(Vec<u8>, Vec<u8>)> {
    meta_rows(db)
        .into_iter()
        .filter(|(k, _)| {
            k.starts_with(EQUIVOCATION_KEY_PREFIX) || k.starts_with(UPGRADE_CONFLICT_KEY_PREFIX)
        })
        .collect()
}

fn executed<'d>(db: &'d Database, block: &Block) -> ExecutedCandidate<'d> {
    let mut cand = CandidateExecution::new(db, TEST_LIMIT);
    cand.view()
        .put(
            cf::STATE,
            format!("test-acct:{}", block.height()).as_bytes(),
            &block.hash().as_bytes()[..],
        )
        .unwrap();
    cand.finish_execution(
        ExecutionSubject::of(block).unwrap(),
        block.header.state_root,
        Vec::new(),
        BlockJournals {
            account: JournalRecord::NothingToUndo,
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    )
}

fn block(parent: Hash, height: BlockHeight) -> Block {
    Block::new(
        BlockHeader::new(
            parent,
            height,
            1_000 + height,
            Hash::ZERO,
            Hash::hash(&height.to_be_bytes()),
            [7u8; 32],
        ),
        Vec::new(),
    )
}

/// Genesis and block 1, each published by the ordinary path.
fn chain(db: &Database) -> (Block, Block) {
    let g = block(Hash::ZERO, 0);
    executed(db, &g)
        .accept_produced(&g)
        .unwrap()
        .publish()
        .unwrap();
    let b1 = block(g.hash(), 1);
    executed(db, &b1)
        .accept_imported(&b1)
        .unwrap()
        .publish()
        .unwrap();
    (g, b1)
}

// ═════════════════════════════════════════════════════════════════════════════
// Namespace
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn keys_are_the_adopted_bytes_after_a_versioned_prefix() {
    assert_eq!(EQUIVOCATION_KEY_PREFIX, b"finality/evidence/v1/");
    assert_eq!(UPGRADE_CONFLICT_KEY_PREFIX, b"upgrade/conflict/v1/");
    assert_eq!(
        (
            EQUIVOCATION_SLOT_LEN,
            EQUIVOCATION_KEY_LEN,
            UPGRADE_CONFLICT_KEY_LEN
        ),
        (15, 36, 28)
    );

    // The draft's 15-byte key, byte for byte, after the prefix.
    let slot_key = draft("equivocation evidence key");
    assert_eq!(DRAFT_SLOT.slot_bytes().as_slice(), slot_key.as_slice());
    assert_eq!(EvShape.verify(&draft_equivocation()), Ok(DRAFT_SLOT));
    let key = DRAFT_SLOT.key();
    assert_eq!(key, [EQUIVOCATION_KEY_PREFIX, &slot_key].concat());
    assert_eq!(parse_equivocation_key(&key), Some(DRAFT_SLOT));

    // The draft's 28-byte key, byte for byte.
    let conflict_key = draft("upgrade-conflict evidence key sequence 1");
    assert_eq!(upgrade_conflict_key(1), conflict_key);
    assert_eq!(parse_upgrade_conflict_key(&conflict_key), Some(1));

    // Big-endian: keys sort by height, then round, type and index.
    let s = |height, round, vote_type, validator_index| EquivocationSlot {
        height,
        round,
        vote_type,
        validator_index,
    };
    let ordered = [
        s(255, u32::MAX, 2, u16::MAX),
        s(256, 0, 1, 0),
        s(256, 0, 1, 1),
        s(256, 0, 1, 256),
        s(256, 0, 2, 0),
        s(256, 1, 1, 0),
        s(256, 256, 1, 0),
        s(u64::MAX, 0, 1, 0),
    ];
    for pair in ordered.windows(2) {
        assert!(pair[0].key() < pair[1].key(), "{pair:?}");
        assert!(pair[0] < pair[1]);
    }
    for slot in ordered {
        assert_eq!(parse_equivocation_key(&slot.key()), Some(slot));
    }
    assert!(upgrade_conflict_key(255) < upgrade_conflict_key(256));

    // Strict parse: exact prefix, exact length.
    for bad in [&key[..35], &[key.as_slice(), &[0]].concat()[..], &key[1..]] {
        assert_eq!(parse_equivocation_key(bad), None);
    }
    let mut other = key.clone();
    other[19] = b'2';
    assert_eq!(parse_equivocation_key(&other), None, "another version");
    for bad in [
        &conflict_key[..27],
        &[conflict_key.as_slice(), &[0]].concat()[..],
    ] {
        assert_eq!(parse_upgrade_conflict_key(bad), None);
    }
    assert_eq!(parse_upgrade_conflict_key(&key[..28]), None);
    assert_eq!(
        parse_equivocation_key(&[conflict_key.as_slice(), &[0; 8]].concat()),
        None
    );
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `.rs` file under `crates/*/<sub>` for each of `subs`.
fn sources(subs: &[&str]) -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        for sub in subs {
            let d = dir.join(sub);
            if d.is_dir() {
                rust_files(&d, &mut files);
            }
        }
    }
    assert!(
        files.len() > 100,
        "the scan found too few files to mean anything"
    );
    files
}

/// Every `b"…"` and `"…"` literal in `src` (simple escapes only), so a key
/// spelled either way is seen.
fn key_literals(src: &str) -> Vec<Vec<u8>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // A quote opens a literal unless it is the character literal `'"'`
        // or `'\"'`.
        let opens =
            bytes[i] == b'"' && !(i > 0 && (bytes[i - 1] == b'\\' || bytes[i - 1] == b'\''));
        if !opens {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut lit = Vec::new();
        while j < bytes.len() && bytes[j] != b'"' {
            if bytes[j] == b'\\' && j + 1 < bytes.len() {
                lit.push(match bytes[j + 1] {
                    b'0' => 0,
                    b'n' => b'\n',
                    b't' => b'\t',
                    c => c,
                });
                j += 2;
            } else {
                lit.push(bytes[j]);
                j += 1;
            }
        }
        out.push(lit);
        i = j + 1;
    }
    out
}

const OWN: &str = "storage/src/evidence_meta.rs";

/// The signer mirror's META key (B6, adopted 2026-11-09). Spelled as a literal
/// because it lands with the signer wiring (#382), not on this layout's base.
const SIGNER_MIRROR_KEY: &[u8] = b"finality/signer-mirror/v1";

/// Whether a META name is one key or the prefix of a key family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Name {
    Key,
    Prefix,
}

/// Every META key and key prefix in the workspace other than this layout's,
/// with where it is defined. Storage's own come from their constants; the
/// rest are literals, which
/// `every_known_meta_name_is_still_spelled_in_the_source` keeps current.
/// `PENDING_META_NAMES` are adopted keys whose code is not on this base.
///
/// The two `registry/` keys are spelled as `str` literals: the state crate's
/// `the_record_prefix_is_disjoint_from_every_state_key_family` keeps every
/// byte-string literal in that namespace to its own module.
fn known_meta_names() -> Vec<(&'static [u8], Name, &'static str)> {
    use Name::{Key, Prefix};
    vec![
        (meta_keys::LATEST_BLOCK_HASH, Key, "storage/src/schema.rs"),
        (meta_keys::LATEST_BLOCK_HEIGHT, Key, "storage/src/schema.rs"),
        (meta_keys::GENESIS_HASH, Key, "storage/src/schema.rs"),
        (meta_keys::CHAIN_ID, Key, "storage/src/schema.rs"),
        (meta_keys::FINALIZED_HEIGHT, Key, "storage/src/schema.rs"),
        (meta_keys::FINALIZED_HASH, Key, "storage/src/schema.rs"),
        (
            CERTIFICATE_KEY_PREFIX,
            Prefix,
            "storage/src/certified_meta.rs",
        ),
        (FINALIZED_POINTER_KEY, Key, "storage/src/certified_meta.rs"),
        (UNDO_HISTORY_FLOOR_META_KEY, Key, "storage/src/journal.rs"),
        (FORMAT_HIGH_WATER_META_KEY, Key, "storage/src/journal.rs"),
        (
            REGISTRY_SEED_META_KEY,
            Key,
            "storage/src/messaging_store.rs",
        ),
        (DISK_BUDGET_META_KEY, Key, "storage/src/pruner.rs"),
        (
            b"consensus_config/v1/record",
            Key,
            "consensus/src/consensus_config/record.rs",
        ),
        (
            b"consensus_config/v1/transition/",
            Prefix,
            "consensus/src/consensus_config/record.rs",
        ),
        (b"activation/heights", Key, "node/src/node.rs"),
        (
            "registry/freeze/v1".as_bytes(),
            Key,
            "state/src/registry_ingress.rs",
        ),
        (
            "registry/freeze/gate/v1".as_bytes(),
            Key,
            "state/src/registry_ingress.rs",
        ),
        (
            b"por_scheduler_index_backfilled",
            Key,
            "state/src/storage_metadata.rs",
        ),
        (
            b"test-only/certified/cert/",
            Prefix,
            "storage/tests/certified_commit.rs",
        ),
        (
            b"test-only/certified/finalized",
            Key,
            "storage/tests/certified_commit.rs",
        ),
    ]
}

const PENDING_META_NAMES: &[(&[u8], Name, &str)] = &[(
    SIGNER_MIRROR_KEY,
    Name::Key,
    "B6 signer mirror, with the signer wiring (#382)",
)];

/// A few slots at the edges of every field.
fn edge_slots() -> Vec<EquivocationSlot> {
    let mut out = Vec::new();
    for height in [0, 7, u64::MAX] {
        for round in [0, 1 << 20, u32::MAX] {
            for vote_type in [0, 1, 2, u8::MAX] {
                for validator_index in [0, u16::MAX] {
                    out.push(EquivocationSlot {
                        height,
                        round,
                        vote_type,
                        validator_index,
                    });
                }
            }
        }
    }
    out
}

const EDGE_SEQUENCES: [u64; 6] = [0, 1, 255, 256, 1 << 32, u64::MAX];

#[test]
fn every_known_meta_name_is_still_spelled_in_the_source() {
    let mut literals = BTreeSet::new();
    for f in sources(&["src", "tests"]) {
        // This file and the certified layout's test list the names; neither
        // counts as their definition.
        if f.ends_with("storage/tests/evidence_meta_v1.rs")
            || f.ends_with("storage/tests/certified_meta_v1.rs")
        {
            continue;
        }
        literals.extend(key_literals(&std::fs::read_to_string(&f).unwrap()));
    }
    for (name, _, home) in known_meta_names() {
        assert!(
            literals.contains(name),
            "{} ({home}) is no longer a literal; update known_meta_names",
            String::from_utf8_lossy(name)
        );
    }
}

/// No META key or key family in the workspace can collide with an evidence
/// key: no known key equals, and no known prefix starts, any
/// `finality/evidence/v1/` ‖ 15 bytes or `upgrade/conflict/v1/` ‖ 8 bytes, and
/// no known key or family lies inside either namespace. Prefix-freedom in
/// both directions is exactly that; the edge keys check it key by key.
#[test]
fn every_known_meta_name_stays_clear_of_the_evidence_keys() {
    let ours: [(&[u8], usize); 2] = [
        (EQUIVOCATION_KEY_PREFIX, EQUIVOCATION_KEY_LEN),
        (UPGRADE_CONFLICT_KEY_PREFIX, UPGRADE_CONFLICT_KEY_LEN),
    ];
    let mut keys: Vec<Vec<u8>> = edge_slots().iter().map(EquivocationSlot::key).collect();
    keys.extend(EDGE_SEQUENCES.map(upgrade_conflict_key));
    let known = known_meta_names();
    assert!(known.len() >= 20, "the known list lost entries");
    for (name, kind, home) in known.into_iter().chain(PENDING_META_NAMES.iter().copied()) {
        let shown = String::from_utf8_lossy(name);
        for (prefix, len) in ours {
            assert!(
                !prefix.starts_with(name) && !name.starts_with(prefix),
                "{shown} ({home}) and {} are not prefix-free",
                String::from_utf8_lossy(prefix)
            );
            assert!(
                kind == Name::Prefix || name.len() != len || !name.starts_with(prefix),
                "{shown} ({home}) has the shape of an evidence key"
            );
        }
        for key in &keys {
            match kind {
                Name::Key => assert_ne!(key.as_slice(), name, "{shown} ({home})"),
                Name::Prefix => assert!(!key.starts_with(name), "{shown} ({home})"),
            }
        }
    }
}

/// The 36-byte evidence key, the 28-byte conflict key and the other
/// `finality/` keys (certificate rows, the finalized pointer, the signer
/// mirror) cannot be taken for one another: their names are prefix-free,
/// their lengths differ, and each strict parser accepts only its own keys.
#[test]
fn the_evidence_keys_cannot_be_confused_with_each_other_or_the_finality_keys() {
    let names: [(&[u8], &str); 5] = [
        (EQUIVOCATION_KEY_PREFIX, "evidence"),
        (UPGRADE_CONFLICT_KEY_PREFIX, "upgrade conflict"),
        (CERTIFICATE_KEY_PREFIX, "certificate"),
        (FINALIZED_POINTER_KEY, "finalized pointer"),
        (SIGNER_MIRROR_KEY, "signer mirror"),
    ];
    for (i, (a, an)) in names.iter().enumerate() {
        for (b, bn) in names.iter().skip(i + 1) {
            assert!(
                !a.starts_with(b) && !b.starts_with(a),
                "{an} and {bn} are not prefix-free"
            );
        }
    }
    // The four `finality/` names part at the byte after `finality/`.
    let finality = [
        EQUIVOCATION_KEY_PREFIX,
        CERTIFICATE_KEY_PREFIX,
        FINALIZED_POINTER_KEY,
        SIGNER_MIRROR_KEY,
    ];
    let at = finality[0].iter().position(|&b| b == b'/').unwrap() + 1;
    assert!(finality.iter().all(|n| n[..at] == finality[0][..at]));
    let parting: BTreeSet<u8> = finality.iter().map(|n| n[at]).collect();
    assert_eq!(parting.len(), finality.len(), "one distinct byte each");

    let evidence: Vec<Vec<u8>> = edge_slots().iter().map(EquivocationSlot::key).collect();
    let conflict: Vec<Vec<u8>> = EDGE_SEQUENCES.map(upgrade_conflict_key).to_vec();
    let certificate: Vec<Vec<u8>> = [
        (0, Hash::ZERO),
        (7, Hash::hash(b"block")),
        (u64::MAX, Hash::from_slice(&[0xff; 32]).unwrap()),
    ]
    .iter()
    .map(|(height, hash)| certificate_key(*height, hash))
    .collect();
    let singles = [FINALIZED_POINTER_KEY.to_vec(), SIGNER_MIRROR_KEY.to_vec()];
    assert!(evidence.iter().all(|k| k.len() == 36));
    assert!(conflict.iter().all(|k| k.len() == 28));
    assert!(certificate.iter().all(|k| k.len() == 57));
    assert_eq!((singles[0].len(), singles[1].len()), (21, 25));

    for (slot, k) in edge_slots().into_iter().zip(&evidence) {
        assert_eq!(parse_equivocation_key(k), Some(slot));
        assert_eq!(parse_upgrade_conflict_key(k), None);
        assert_eq!(parse_certificate_key(k), None);
    }
    for (sequence, k) in EDGE_SEQUENCES.into_iter().zip(&conflict) {
        assert_eq!(parse_upgrade_conflict_key(k), Some(sequence));
        assert_eq!(parse_equivocation_key(k), None);
        assert_eq!(parse_certificate_key(k), None);
    }
    for k in &certificate {
        assert!(parse_certificate_key(k).is_some());
        assert_eq!(parse_equivocation_key(k), None);
        assert_eq!(parse_upgrade_conflict_key(k), None);
    }
    for k in &singles {
        assert_eq!(parse_equivocation_key(k), None);
        assert_eq!(parse_upgrade_conflict_key(k), None);
        assert_eq!(parse_certificate_key(k), None);
    }
    // No key of one kind lies under another kind's name.
    let kinds: [(&[Vec<u8>], &[u8]); 5] = [
        (&evidence, EQUIVOCATION_KEY_PREFIX),
        (&conflict, UPGRADE_CONFLICT_KEY_PREFIX),
        (&certificate, CERTIFICATE_KEY_PREFIX),
        (&singles[..1], FINALIZED_POINTER_KEY),
        (&singles[1..], SIGNER_MIRROR_KEY),
    ];
    for (i, (keys, _)) in kinds.iter().enumerate() {
        for (j, (_, name)) in kinds.iter().enumerate() {
            if i != j {
                assert!(keys.iter().all(|k| !k.starts_with(name)), "{i} under {j}");
            }
        }
    }
}

fn scan(db: &Database, prefix: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in db.prefix_iter_checked(cf::META, prefix).unwrap() {
        let (key, _) = entry.unwrap();
        if !key.starts_with(prefix) {
            break;
        }
        out.push(key.to_vec());
    }
    out
}

/// With a row under every other META name, the signer mirror and near misses
/// on both sides of each evidence namespace, the first valid record still
/// takes its empty slot and holds it against a second (D5; the first-wins
/// group below covers it alone). The foreign rows are untouched, each
/// prefix scan sees only its own rows, and the audit counts only evidence.
#[test]
fn foreign_meta_rows_neither_hold_an_evidence_slot_nor_move() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let mut foreign: Vec<Vec<u8>> = known_meta_names()
        .into_iter()
        .chain(PENDING_META_NAMES.iter().copied())
        .map(|(name, kind, _)| match kind {
            Name::Key => name.to_vec(),
            Name::Prefix => [name, b"row"].concat(),
        })
        .collect();
    foreign.push(certificate_key(7, &Hash::hash(b"block")));
    // Near misses, built from the prefixes: without the final `/`, and one
    // version up, each before and after the namespace in key order.
    for (prefix, tails) in [
        (
            EQUIVOCATION_KEY_PREFIX,
            [DRAFT_SLOT.slot_bytes().to_vec(), vec![0xff; 15]],
        ),
        (
            UPGRADE_CONFLICT_KEY_PREFIX,
            [1u64.to_be_bytes().to_vec(), vec![0xff; 8]],
        ),
    ] {
        let unslashed = &prefix[..prefix.len() - 1];
        let mut bumped = prefix.to_vec();
        let v = bumped.len() - 2;
        bumped[v] += 1;
        for tail in &tails {
            foreign.push([unslashed, tail].concat());
            foreign.push([bumped.as_slice(), tail].concat());
        }
    }
    for key in &foreign {
        db.put(cf::META, key, b"foreign").unwrap();
        assert_eq!(parse_equivocation_key(key), None);
        assert_eq!(parse_upgrade_conflict_key(key), None);
    }
    let before = meta_rows(&db);
    assert!(scan(&db, EQUIVOCATION_KEY_PREFIX).is_empty());
    assert!(scan(&db, UPGRADE_CONFLICT_KEY_PREFIX).is_empty());

    let table = draft_table();
    assert_eq!(
        record_equivocation(&db, &EvShape, &draft_equivocation()).unwrap(),
        Insert::Stored
    );
    assert_eq!(
        record_upgrade_conflict(&db, &table, &draft_conflict()).unwrap(),
        Insert::Stored
    );
    assert_eq!(
        record_equivocation(&db, &EvShape, &equivocation(DRAFT_SLOT, 0, 1)).unwrap(),
        Insert::SlotHeld { identical: false }
    );

    let after = meta_rows(&db);
    assert!(before.is_subset(&after), "every foreign row is unchanged");
    let added: BTreeSet<_> = after.difference(&before).cloned().collect();
    assert_eq!(
        added,
        BTreeSet::from([
            (DRAFT_SLOT.key(), draft_equivocation()),
            (upgrade_conflict_key(1), draft_conflict()),
        ])
    );
    assert_eq!(scan(&db, EQUIVOCATION_KEY_PREFIX), vec![DRAFT_SLOT.key()]);
    assert_eq!(
        scan(&db, UPGRADE_CONFLICT_KEY_PREFIX),
        vec![upgrade_conflict_key(1)]
    );
    let mut certificate_rows: Vec<Vec<u8>> = foreign
        .iter()
        .filter(|k| k.starts_with(CERTIFICATE_KEY_PREFIX))
        .cloned()
        .collect();
    certificate_rows.sort();
    assert_eq!(scan(&db, CERTIFICATE_KEY_PREFIX), certificate_rows);
    assert_eq!(
        audit_evidence(&db, &EvShape, &table).unwrap(),
        EvidenceAudit {
            equivocations: 1,
            upgrade_conflicts: 1
        }
    );
}

#[test]
fn the_prefixes_are_disjoint_from_every_other_key_in_production_code() {
    let names: [&[u8]; 2] = [EQUIVOCATION_KEY_PREFIX, UPGRADE_CONFLICT_KEY_PREFIX];
    // No production literal outside this layout, byte string or string, names
    // a key under either prefix, equals one, or is a key-family prefix (a
    // literal ending in `/`, the repository's convention for scan prefixes)
    // that a scan could reach them through. A future colliding key fails here
    // whether or not it is added to `known_meta_names`.
    let mut hits = Vec::new();
    for f in sources(&["src"]) {
        if f.ends_with(OWN) {
            continue;
        }
        for lit in key_literals(&std::fs::read_to_string(&f).unwrap()) {
            for name in names {
                if lit.starts_with(name) || (lit.ends_with(b"/") && name.starts_with(&lit)) {
                    hits.push(format!(
                        "{}: {}",
                        f.display(),
                        String::from_utf8_lossy(&lit)
                    ));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "literals overlapping the evidence keys: {hits:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// First-wins (D5)
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn the_first_valid_record_per_slot_is_kept() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let before = meta_rows(&db);

    let first = draft_equivocation();
    assert_eq!(
        record_equivocation(&db, &EvShape, &first).unwrap(),
        Insert::Stored
    );
    assert_eq!(
        record_equivocation(&db, &EvShape, &first).unwrap(),
        Insert::SlotHeld { identical: true }
    );
    // Another valid record for the same slot: kept out, the first stays.
    let other = equivocation(DRAFT_SLOT, 0x00, 0x01);
    assert_eq!(
        record_equivocation(&db, &EvShape, &other).unwrap(),
        Insert::SlotHeld { identical: false }
    );
    assert_eq!(
        equivocation_record(&db, &DRAFT_SLOT).unwrap(),
        Some(first.clone())
    );

    let after = meta_rows(&db);
    let added: Vec<_> = after.difference(&before).cloned().collect();
    assert_eq!(
        added,
        vec![(DRAFT_SLOT.key(), first)],
        "one row, the first record"
    );
}

#[test]
fn spam_costs_at_most_one_row_per_slot() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let slots = [
        DRAFT_SLOT,
        EquivocationSlot {
            round: 1,
            ..DRAFT_SLOT
        },
        EquivocationSlot {
            vote_type: 1,
            ..DRAFT_SLOT
        },
    ];
    for slot in slots {
        for lo in 0..=200u8 {
            let outcome =
                record_equivocation(&db, &EvShape, &equivocation(slot, lo, 0xff)).unwrap();
            let want = if lo == 0 {
                Insert::Stored
            } else {
                Insert::SlotHeld { identical: false }
            };
            assert_eq!(outcome, want, "{slot:?} record {lo}");
        }
    }
    let table = UcTable(
        (0..100)
            .flat_map(|tag| [(conflict(1, tag), 1), (conflict(2, tag), 2)])
            .collect(),
    );
    for (record, _) in &table.0 {
        record_upgrade_conflict(&db, &table, record).unwrap();
    }
    let rows = evidence_rows(&db);
    assert_eq!(rows.len(), slots.len() + 2);
    for slot in slots {
        assert_eq!(
            equivocation_record(&db, &slot).unwrap(),
            Some(equivocation(slot, 0, 0xff)),
            "the first record for {slot:?}"
        );
    }
    for sequence in [1, 2] {
        assert_eq!(
            upgrade_conflict_record(&db, sequence).unwrap(),
            Some(conflict(sequence, 0))
        );
    }
    assert_eq!(
        audit_evidence(&db, &EvShape, &table).unwrap(),
        EvidenceAudit {
            equivocations: 3,
            upgrade_conflicts: 2
        }
    );
}

#[test]
fn an_invalid_record_never_takes_a_slot() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let before = meta_rows(&db);
    let valid = draft_equivocation();
    // B before A, a wrong magic, a truncation.
    let mut reversed = valid[..9].to_vec();
    reversed.extend_from_slice(&valid[B..]);
    reversed.extend_from_slice(&valid[A..B]);
    let mut bad_magic = valid.clone();
    bad_magic[0] ^= 0x01;
    for invalid in [reversed, bad_magic, valid[..362].to_vec()] {
        assert!(matches!(
            record_equivocation(&db, &EvShape, &invalid),
            Err(EvidenceError::Refused(_))
        ));
    }
    assert!(matches!(
        record_upgrade_conflict(&db, &draft_table(), &conflict(1, 0)),
        Err(EvidenceError::Refused(_))
    ));
    assert_eq!(meta_rows(&db), before, "nothing written");
    assert_eq!(
        record_equivocation(&db, &EvShape, &valid).unwrap(),
        Insert::Stored
    );
    // Once the slot is held, an invalid record is still refused, never held.
    let mut flipped = valid.clone();
    flipped[7] ^= 0x01;
    assert!(matches!(
        record_equivocation(&db, &EvShape, &flipped),
        Err(EvidenceError::Refused(_))
    ));
}

#[test]
fn concurrent_writers_store_exactly_one_record_per_slot() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    const WRITERS: u8 = 8;
    let start = Barrier::new(usize::from(WRITERS));
    let outcomes: Vec<(Vec<u8>, Insert)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..WRITERS)
            .map(|i| {
                let (db, start) = (&db, &start);
                scope.spawn(move || {
                    let record = equivocation(DRAFT_SLOT, i, 0xff);
                    start.wait();
                    let outcome = record_equivocation(db, &EvShape, &record).unwrap();
                    (record, outcome)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let stored: Vec<&Vec<u8>> = outcomes
        .iter()
        .filter(|(_, o)| *o == Insert::Stored)
        .map(|(r, _)| r)
        .collect();
    let each: Vec<Insert> = outcomes.iter().map(|(_, o)| *o).collect();
    assert_eq!(stored.len(), 1, "exactly one writer stores: {each:?}");
    assert_eq!(
        outcomes
            .iter()
            .filter(|(_, o)| *o == Insert::SlotHeld { identical: false })
            .count(),
        usize::from(WRITERS) - 1
    );
    assert_eq!(
        equivocation_record(&db, &DRAFT_SLOT).unwrap().as_ref(),
        Some(stored[0])
    );
}

#[test]
fn upgrade_conflict_records_are_kept_first_wins_by_sequence() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let draft_record = draft_conflict();
    let table = UcTable(vec![
        (draft_record.clone(), 1),
        (conflict(1, 7), 1),
        (conflict(2, 7), 2),
    ]);
    assert_eq!(
        record_upgrade_conflict(&db, &table, &draft_record).unwrap(),
        Insert::Stored
    );
    assert_eq!(
        record_upgrade_conflict(&db, &table, &conflict(1, 7)).unwrap(),
        Insert::SlotHeld { identical: false }
    );
    assert_eq!(
        record_upgrade_conflict(&db, &table, &draft_record).unwrap(),
        Insert::SlotHeld { identical: true }
    );
    assert_eq!(
        record_upgrade_conflict(&db, &table, &conflict(2, 7)).unwrap(),
        Insert::Stored
    );
    assert_eq!(
        db.get(cf::META, &draft("upgrade-conflict evidence key sequence 1"))
            .unwrap(),
        Some(draft_record.clone()),
        "under the draft's 28-byte key"
    );
    assert_eq!(upgrade_conflict_record(&db, 1).unwrap(), Some(draft_record));
    assert_eq!(
        upgrade_conflict_record(&db, 2).unwrap(),
        Some(conflict(2, 7))
    );
    assert_eq!(upgrade_conflict_record(&db, 3).unwrap(), None);
}

#[test]
fn records_survive_a_reopen() {
    let dir = TempDir::new().unwrap();
    {
        let db = open(dir.path());
        record_equivocation(&db, &EvShape, &draft_equivocation()).unwrap();
        record_upgrade_conflict(&db, &draft_table(), &draft_conflict()).unwrap();
    }
    let db = open(dir.path());
    assert_eq!(
        equivocation_record(&db, &DRAFT_SLOT).unwrap(),
        Some(draft_equivocation())
    );
    assert_eq!(
        upgrade_conflict_record(&db, 1).unwrap(),
        Some(draft_conflict())
    );
    assert_eq!(
        record_equivocation(&db, &EvShape, &equivocation(DRAFT_SLOT, 0, 1)).unwrap(),
        Insert::SlotHeld { identical: false },
        "first-wins holds across a restart"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Corruption
// ═════════════════════════════════════════════════════════════════════════════

fn audit_violation(db: &Database, table: &UcTable) -> EvidenceViolation {
    match audit_evidence(db, &EvShape, table) {
        Err(EvidenceError::Violation(v)) => v,
        other => panic!("expected a violation, got {other:?}"),
    }
}

#[test]
fn the_audit_re_verifies_every_row_against_its_key() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let table = draft_table();
    record_equivocation(&db, &EvShape, &draft_equivocation()).unwrap();
    record_upgrade_conflict(&db, &table, &draft_conflict()).unwrap();
    assert_eq!(
        audit_evidence(&db, &EvShape, &table).unwrap(),
        EvidenceAudit {
            equivocations: 1,
            upgrade_conflicts: 1
        }
    );

    // A malformed key under each prefix.
    for prefix in [EQUIVOCATION_KEY_PREFIX, UPGRADE_CONFLICT_KEY_PREFIX] {
        let key = [prefix, &[0u8; 14]].concat();
        db.put(cf::META, &key, b"x").unwrap();
        assert_eq!(
            audit_violation(&db, &table),
            EvidenceViolation::MalformedKey(key.clone())
        );
        db.delete(cf::META, &key).unwrap();
    }

    // A stored record the verifier refuses: a flipped byte in the magic or
    // schema, or in one vote's slot fields (commitment, height, round, type,
    // validator-set commitment, index). Flipped signature and block bytes
    // are the real verifier's to refuse (tested in `finality-foundations`).
    let key = DRAFT_SLOT.key();
    let good = draft_equivocation();
    for i in (0..9).chain([A, A + 34, A + 74, B + 78, B + 79, B + 111]) {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        db.put(cf::META, &key, &bad).unwrap();
        assert!(
            matches!(
                audit_violation(&db, &table),
                EvidenceViolation::Refused { .. }
            ),
            "flipped byte {i}"
        );
    }
    db.put(cf::META, &key, &good).unwrap();

    // A valid record under another slot's key.
    let elsewhere = EquivocationSlot {
        validator_index: 3,
        ..DRAFT_SLOT
    }
    .key();
    db.put(cf::META, &elsewhere, &good).unwrap();
    assert_eq!(
        audit_violation(&db, &table),
        EvidenceViolation::WrongSlot {
            key: elsewhere.clone()
        }
    );
    db.delete(cf::META, &elsewhere).unwrap();
    db.put(cf::META, &upgrade_conflict_key(2), &draft_conflict())
        .unwrap();
    assert_eq!(
        audit_violation(&db, &table),
        EvidenceViolation::WrongSlot {
            key: upgrade_conflict_key(2)
        }
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Rollback
// ═════════════════════════════════════════════════════════════════════════════

fn column_families(path: &Path) -> BTreeSet<String> {
    rocksdb::DB::list_cf(&rocksdb::Options::default(), path)
        .unwrap()
        .into_iter()
        .collect()
}

#[test]
fn no_column_family_is_added() {
    let dir = TempDir::new().unwrap();
    {
        let db = open(dir.path());
        chain(&db);
    }
    let before = column_families(dir.path());
    let expected: BTreeSet<String> = ALL_CFS
        .iter()
        .map(|s| s.to_string())
        .chain(["default".to_string()])
        .collect();
    assert_eq!(before, expected);
    {
        let db = open(dir.path());
        record_equivocation(&db, &EvShape, &draft_equivocation()).unwrap();
        record_upgrade_conflict(&db, &draft_table(), &draft_conflict()).unwrap();
    }
    assert_eq!(
        column_families(dir.path()),
        before,
        "the evidence layout adds no column family"
    );
    assert!(!ALL_CFS
        .iter()
        .any(|c| c.contains("evidence") || c.contains("conflict")));
}

/// What a binary without this layout does with the volume: open it (the same
/// `ALL_CFS`), read the head, and run today's start-up audit of the
/// certified-finality records (B7), which reads only the certificate prefix
/// and the pointer. None of it reads an evidence row, and the audit passes.
#[test]
fn code_without_the_layout_and_the_start_up_audit_ignore_the_rows() {
    let dir = TempDir::new().unwrap();
    let b1;
    {
        let db = open(dir.path());
        b1 = chain(&db).1;
        record_equivocation(&db, &EvShape, &draft_equivocation()).unwrap();
        record_upgrade_conflict(&db, &draft_table(), &draft_conflict()).unwrap();
    }
    let rows_before;
    {
        let db = open(dir.path());
        let blocks = BlockStore::new(&db);
        assert_eq!(blocks.get_latest_height().unwrap(), Some(1));
        assert_eq!(blocks.get_latest_hash().unwrap(), Some(b1.hash()));
        assert!(matches!(audit_at_start(&db), Ok(None)));
        assert!(matches!(certified_block(&db), Ok(None)));
        rows_before = evidence_rows(&db);
        assert_eq!(rows_before.len(), 2);
    }
    let db = open(dir.path());
    assert_eq!(evidence_rows(&db), rows_before);
    assert_eq!(
        audit_evidence(&db, &EvShape, &draft_table()).unwrap(),
        EvidenceAudit {
            equivocations: 1,
            upgrade_conflicts: 1
        }
    );
}

/// A reorg, a block revert and the `rollback` command unwind a block by its
/// application journal. Evidence is written outside every block, so no
/// journal holds it: unwinding leaves the rows exactly as they were, whether
/// they were recorded before the block or after it.
#[test]
fn unwinding_a_block_leaves_the_rows_as_they_were() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = block(Hash::ZERO, 0);
    executed(&db, &g)
        .accept_produced(&g)
        .unwrap()
        .publish()
        .unwrap();
    record_equivocation(&db, &EvShape, &draft_equivocation()).unwrap();

    let b1 = block(g.hash(), 1);
    executed(&db, &b1)
        .accept_imported(&b1)
        .unwrap()
        .publish()
        .unwrap();
    let later = EquivocationSlot {
        height: 1,
        ..DRAFT_SLOT
    };
    record_equivocation(&db, &EvShape, &equivocation(later, 0, 1)).unwrap();
    record_upgrade_conflict(&db, &draft_table(), &draft_conflict()).unwrap();
    let rows = evidence_rows(&db);
    assert_eq!(rows.len(), 3);

    let journal = ApplicationJournal::decode_for(
        &db.get(cf::APPLICATION_JOURNAL, &journal_key(1, &b1.hash()))
            .unwrap()
            .expect("block 1 left a journal"),
        1,
        &b1.hash(),
    )
    .unwrap();
    assert!(
        journal
            .entries()
            .iter()
            .all(|e| !e.key().starts_with(EQUIVOCATION_KEY_PREFIX)
                && !e.key().starts_with(UPGRADE_CONFLICT_KEY_PREFIX)),
        "no journal entry names an evidence key"
    );
    let state_key = b"test-acct:1";
    assert!(db.get(cf::STATE, state_key).unwrap().is_some());
    journal.undo_batch(&db).unwrap().commit().unwrap();
    assert_eq!(
        db.get(cf::STATE, state_key).unwrap(),
        None,
        "block 1 unwound"
    );
    assert_eq!(evidence_rows(&db), rows, "the evidence rows are unchanged");
}

// ═════════════════════════════════════════════════════════════════════════════
// Dormancy
// ═════════════════════════════════════════════════════════════════════════════

/// Nothing outside this layout and its tests reads or writes the evidence
/// rows: no other production source names the module, its functions, its
/// verifier traits or its key prefixes, and no crate but this one's tests
/// does at all. Wiring it in is a deliberate change that edits this test.
#[test]
fn nothing_outside_the_layout_names_it() {
    let needles = [
        "evidence_meta::",
        "EquivocationVerifier",
        "UpgradeConflictVerifier",
        "record_equivocation",
        "record_upgrade_conflict",
        "audit_evidence",
        "finality/evidence/",
        "upgrade/conflict/",
    ];
    let mut hits = Vec::new();
    for f in sources(&["src", "tests", "benches", "examples"]) {
        if f.ends_with(OWN) || f.parent().is_some_and(|d| d.ends_with("storage/tests")) {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap();
        for needle in needles {
            if src.contains(needle) {
                hits.push(format!("{} names {needle}", f.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the dormant evidence layout is referenced outside its module:\n{}",
        hits.join("\n")
    );
}

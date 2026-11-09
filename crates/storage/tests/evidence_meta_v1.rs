//! The evidence layout (`evidence_meta`): the A3 evidence records under
//! versioned keys in the existing `meta` family, the first valid record per
//! slot kept (D5).
//!
//! Five groups: namespace, first-wins, corruption, rollback, dormancy.
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
use sumchain_storage::certified_meta::{CERTIFICATE_KEY_PREFIX, FINALIZED_POINTER_KEY};
use sumchain_storage::db::{cf, Database, ALL_CFS};
use sumchain_storage::evidence_meta::{
    audit_evidence, equivocation_record, parse_equivocation_key, parse_upgrade_conflict_key,
    record_equivocation, record_upgrade_conflict, upgrade_conflict_key, upgrade_conflict_record,
    EquivocationSlot, EquivocationVerifier, EvidenceAudit, EvidenceError, EvidenceRefusal,
    EvidenceViolation, Insert, UpgradeConflictVerifier, EQUIVOCATION_KEY_LEN,
    EQUIVOCATION_KEY_PREFIX, EQUIVOCATION_SLOT_LEN, UPGRADE_CONFLICT_KEY_LEN,
    UPGRADE_CONFLICT_KEY_PREFIX,
};
use sumchain_storage::schema::{journal_key, BlockStore};
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

/// Every `b"…"` literal in `src` (simple escapes only).
fn byte_literals(src: &str) -> Vec<Vec<u8>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let starts = bytes[i] == b'b'
            && bytes[i + 1] == b'"'
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'));
        if !starts {
            i += 1;
            continue;
        }
        let mut j = i + 2;
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

#[test]
fn the_prefixes_are_disjoint_from_every_other_key_in_production_code() {
    let names: [&[u8]; 2] = [EQUIVOCATION_KEY_PREFIX, UPGRADE_CONFLICT_KEY_PREFIX];
    // Prefix-free with each other and with the certified layout's keys, the
    // only other names in the `finality/` namespace.
    for (i, a) in names.iter().enumerate() {
        for b in names.iter().skip(i + 1) {
            assert!(!a.starts_with(b) && !b.starts_with(a));
        }
        for c in [CERTIFICATE_KEY_PREFIX, FINALIZED_POINTER_KEY] {
            assert!(!a.starts_with(c) && !c.starts_with(a));
        }
    }
    // No production literal outside this layout names a key under either
    // prefix, equals one, or is a key-family prefix (a literal ending in `/`,
    // the repository's convention for scan prefixes) that a scan could reach
    // them through.
    let mut hits = Vec::new();
    for f in sources(&["src"]) {
        if f.ends_with(OWN) {
            continue;
        }
        for lit in byte_literals(&std::fs::read_to_string(&f).unwrap()) {
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

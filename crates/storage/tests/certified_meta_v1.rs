//! The v1 certified layout (`certified_meta`): versioned keys in the existing
//! `meta` family, written through the dormant certified-commit seam.
//!
//! Three groups: namespace, corruption, rollback.
//!
//! The certificate check here is a STAND-IN for the merged
//! `FinalityCertificateV1` verifier: this crate may not name
//! `sumchain-finality-foundations` while both dormancy guards stand. It
//! checks the v1 header the real verifier also checks:
//! - the magic, schema and exact length `119 + 66·k`;
//! - `k ≥ 1`;
//! - height (offset 41, LE) and `block_id` (offset 49) equal to the
//!   (height, hash) being verified.
//!
//! Signatures are the real verifier's job (E1, tested in
//! `finality-foundations`). Every key in this file is synthetic.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sumchain_primitives::{Block, BlockHeader, BlockHeight, Hash};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutedCandidate, ExecutionSubject, JournalRecord,
};
use sumchain_storage::certified::{
    CertificateRefusal, CertificateVerifier, CertifiedError, CertifiedStore, CommitStep,
    FinalizedPointer, Recovery,
};
use sumchain_storage::certified_meta::{
    audit_namespace, certificate_key, decode_pointer, encode_pointer, parse_certificate_key,
    recover_v1, MetaLayoutV1, NamespaceError, NamespaceViolation, RecoverV1Error,
    CERTIFICATE_KEY_LEN, CERTIFICATE_KEY_PREFIX, FINALIZED_POINTER_KEY, FINALIZED_POINTER_LEN,
};
use sumchain_storage::db::{cf, Database, ALL_CFS};
use sumchain_storage::schema::{meta_keys, BlockStore};
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;

// ── stand-in for the merged certificate verifier ─────────────────────────────

/// `FCRTv1` ‖ NUL. Spelled as bytes: the ratified magic's only literal home
/// is `finality-foundations/src/certificate.rs` (check.py).
const CERT_MAGIC: [u8; 7] = [0x46, 0x43, 0x52, 0x54, 0x76, 0x31, 0x00];
const HEADER: usize = 119;
const ENTRY: usize = 66;

/// A structurally valid v1 certificate for (height, hash) with `k` entries
/// (indices 0..k, zero signatures).
fn v1_cert(height: BlockHeight, hash: &Hash, k: u16) -> Vec<u8> {
    let mut c = Vec::with_capacity(HEADER + ENTRY * usize::from(k));
    c.extend_from_slice(&CERT_MAGIC);
    c.extend_from_slice(&1u16.to_le_bytes());
    c.extend_from_slice(&[0xc0; 32]);
    c.extend_from_slice(&height.to_le_bytes());
    c.extend_from_slice(hash.as_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    c.extend_from_slice(&[0x5a; 32]);
    c.extend_from_slice(&k.to_le_bytes());
    for i in 0..k {
        c.extend_from_slice(&i.to_le_bytes());
        c.extend_from_slice(&[0u8; 64]);
    }
    c
}

struct V1Shape;

impl CertificateVerifier for V1Shape {
    fn verify(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        c: &[u8],
    ) -> Result<(), CertificateRefusal> {
        let refuse = |why: &str| Err(CertificateRefusal(why.into()));
        if c.len() < HEADER || c[..7] != CERT_MAGIC || c[7..9] != 1u16.to_le_bytes() {
            return refuse("not a v1 certificate header");
        }
        let k = u16::from_le_bytes([c[117], c[118]]);
        if k == 0 || c.len() != HEADER + ENTRY * usize::from(k) {
            return refuse("length is not 119 + 66k");
        }
        if u64::from_le_bytes(c[41..49].try_into().unwrap()) != height {
            return refuse("certificate names another height");
        }
        if &c[49..81] != block_hash.as_bytes() {
            return refuse("certificate names another block");
        }
        Ok(())
    }
}

fn store(db: &Database) -> CertifiedStore<'_, MetaLayoutV1, V1Shape> {
    CertifiedStore::new(db, MetaLayoutV1, V1Shape)
}

// ── chain fixtures (as in tests/certified_commit.rs) ─────────────────────────

fn open(dir: &Path) -> Database {
    Database::open_default(dir).expect("open")
}

fn root_for(height: BlockHeight, tag: u64) -> Hash {
    Hash::hash(&[height.to_be_bytes(), tag.to_be_bytes()].concat())
}

fn child(parent: &Block, tag: u64) -> Block {
    let height = parent.height() + 1;
    Block::new(
        BlockHeader::new(
            parent.hash(),
            height,
            1_000 + height * 10 + tag,
            Hash::ZERO,
            root_for(height, tag),
            [7u8; 32],
        ),
        Vec::new(),
    )
}

fn executed<'d>(db: &'d Database, block: &Block, computed: Hash) -> ExecutedCandidate<'d> {
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
        computed,
        Vec::new(),
        BlockJournals {
            account: JournalRecord::NothingToUndo,
            contract: JournalRecord::NothingToUndo,
            compute_pool: JournalRecord::NothingToUndo,
            beacon: JournalRecord::NothingToUndo,
        },
    )
}

fn genesis(db: &Database) -> Block {
    let g = Block::new(
        BlockHeader::new(Hash::ZERO, 0, 1_000, Hash::ZERO, root_for(0, 0), [7u8; 32]),
        Vec::new(),
    );
    executed(db, &g, g.header.state_root)
        .accept_produced(&g)
        .unwrap()
        .publish()
        .unwrap();
    g
}

fn certify(db: &Database, block: &Block) -> Result<FinalizedPointer, CertifiedError> {
    let accepted = executed(db, block, block.header.state_root)
        .accept_imported(block)
        .unwrap();
    store(db).commit(accepted, &v1_cert(block.height(), &block.hash(), 3))
}

/// Genesis (ordinary path), then `n` blocks committed through the v1 layout.
fn certified_chain(db: &Database, n: u64) -> Vec<Block> {
    let mut chain = vec![genesis(db)];
    for _ in 0..n {
        let b = child(chain.last().unwrap(), 0);
        certify(db, &b).unwrap();
        chain.push(b);
    }
    chain
}

/// Publish `block` by the ORDINARY (pre-v1) path.
fn publish_ordinary(db: &Database, block: &Block) {
    executed(db, block, block.header.state_root)
        .accept_imported(block)
        .unwrap()
        .publish()
        .unwrap();
}

fn meta_keys_now(db: &Database) -> BTreeSet<Vec<u8>> {
    db.iter_checked_from(cf::META, None)
        .unwrap()
        .map(|e| e.unwrap().0.to_vec())
        .collect()
}

fn violation(r: Result<Recovery, RecoverV1Error>) -> NamespaceViolation {
    match r {
        Err(RecoverV1Error::Namespace(NamespaceError::Violation(v))) => v,
        other => panic!("expected a namespace violation, got {other:?}"),
    }
}

fn seam_corrupt(r: Result<Recovery, RecoverV1Error>) -> String {
    match r {
        Err(RecoverV1Error::Seam(CertifiedError::Corrupt(why))) => why,
        other => panic!("expected the seam to refuse as corrupt, got {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Namespace
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn key_and_pointer_encodings_are_exact() {
    assert_eq!(CERTIFICATE_KEY_PREFIX, b"finality/cert/v1/");
    assert_eq!(FINALIZED_POINTER_KEY, b"finality/finalized/v1");
    let h = Hash::hash(b"block");
    let k = certificate_key(0x0102_0304_0506_0708, &h);
    assert_eq!(k.len(), CERTIFICATE_KEY_LEN);
    assert_eq!(k.len(), 57);
    assert_eq!(&k[..17], CERTIFICATE_KEY_PREFIX);
    assert_eq!(
        &k[17..25],
        &[1, 2, 3, 4, 5, 6, 7, 8],
        "height is big-endian in the key"
    );
    assert_eq!(&k[25..], h.as_bytes());
    assert_eq!(parse_certificate_key(&k), Some((0x0102_0304_0506_0708, h)));
    // Keys sort by height.
    assert!(certificate_key(255, &h) < certificate_key(256, &h));
    assert!(certificate_key(1, &Hash::ZERO) < certificate_key(2, &h));
    // Strict parse.
    for bad in [&k[..56], &[k.as_slice(), &[0]].concat()[..], &k[1..]] {
        assert_eq!(parse_certificate_key(bad), None);
    }
    let mut other_prefix = k.clone();
    other_prefix[16] = b'x';
    assert_eq!(parse_certificate_key(&other_prefix), None);

    let p = FinalizedPointer {
        height: 0x1122_3344_5566_7788,
        hash: h,
    };
    let v = encode_pointer(&p);
    assert_eq!(v.len(), FINALIZED_POINTER_LEN);
    assert_eq!(
        &v[..8],
        &0x1122_3344_5566_7788u64.to_le_bytes(),
        "height is little-endian in the value"
    );
    assert_eq!(decode_pointer(&v), Ok(p));
    for len in [0usize, 39, 41, 80] {
        assert!(
            decode_pointer(&vec![0u8; len]).is_err(),
            "{len}-byte pointer"
        );
    }
}

/// Every META key the repository uses, with where it is defined. The scan
/// below asserts each is still spelled as a byte literal in the source, so
/// the list cannot silently go stale.
const KNOWN_META_KEYS: &[(&[u8], &str)] = &[
    (b"latest_block_hash", "storage/src/schema.rs meta_keys"),
    (b"latest_block_height", "storage/src/schema.rs meta_keys"),
    (b"genesis_hash", "storage/src/schema.rs meta_keys"),
    (b"chain_id", "storage/src/schema.rs meta_keys"),
    (
        b"finalized_height",
        "storage/src/schema.rs meta_keys (legacy)",
    ),
    (
        b"finalized_hash",
        "storage/src/schema.rs meta_keys (legacy)",
    ),
    (
        b"consensus_config/v1/record",
        "consensus/src/consensus_config/record.rs",
    ),
    (
        b"consensus_config/v1/transition/",
        "consensus/src/consensus_config/record.rs (prefix)",
    ),
    (b"activation/heights", "node/src/node.rs"),
    (
        b"application_journal/undo_history_floor",
        "storage/src/journal.rs",
    ),
    (
        b"application_journal/format_high_water",
        "storage/src/journal.rs",
    ),
    (
        b"messaging/registry_seed_v1",
        "storage/src/messaging_store.rs",
    ),
    (b"node/disk_budget_bytes", "storage/src/pruner.rs"),
    (
        b"por_scheduler_index_backfilled",
        "state/src/storage_metadata.rs",
    ),
    (
        b"test-only/certified/cert/",
        "storage/tests/certified_commit.rs (prefix)",
    ),
    (
        b"test-only/certified/finalized",
        "storage/tests/certified_commit.rs",
    ),
];

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
                match bytes[j + 1] {
                    b'0' => lit.push(0),
                    b'n' => lit.push(b'\n'),
                    b't' => lit.push(b'\t'),
                    b'x' if j + 3 < bytes.len() => {
                        let h = std::str::from_utf8(&bytes[j + 2..j + 4]).unwrap_or("00");
                        lit.push(u8::from_str_radix(h, 16).unwrap_or(0));
                        j += 2;
                    }
                    c => lit.push(c),
                }
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

#[test]
fn v1_keys_are_disjoint_from_every_meta_key_in_the_repository() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        for sub in ["src", "tests"] {
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
    let own = Path::new("storage/src/certified_meta.rs");
    let this = Path::new("storage/tests/certified_meta_v1.rs");
    let mut literals: BTreeSet<Vec<u8>> = BTreeSet::new();
    for f in &files {
        if f.ends_with(own) || f.ends_with(this) {
            continue;
        }
        literals.extend(byte_literals(&std::fs::read_to_string(f).unwrap()));
    }

    // The known list is current: each key is still spelled in the source.
    for (key, home) in KNOWN_META_KEYS {
        assert!(
            literals.contains(*key),
            "{} ({home}) is no longer a literal; update KNOWN_META_KEYS",
            String::from_utf8_lossy(key)
        );
    }

    let v1: [&[u8]; 2] = [CERTIFICATE_KEY_PREFIX, FINALIZED_POINTER_KEY];
    // The two v1 names are prefix-free with each other.
    assert!(!v1[0].starts_with(v1[1]) && !v1[1].starts_with(v1[0]));
    // Prefix-free with every known META key, in both directions, so no
    // existing exact read or prefix scan can see a v1 row, and no v1 scan can
    // see an existing row.
    for (key, home) in KNOWN_META_KEYS {
        for name in v1 {
            assert!(
                !key.starts_with(name) && !name.starts_with(key),
                "{} ({home}) overlaps {}",
                String::from_utf8_lossy(key),
                String::from_utf8_lossy(name)
            );
        }
    }
    // The legacy pointer is not a prefix of the v1 namespace or vice versa.
    for legacy in [meta_keys::FINALIZED_HEIGHT, meta_keys::FINALIZED_HASH] {
        assert!(!b"finality/".starts_with(legacy) && !legacy.starts_with(b"finality/"));
    }
    // Nothing else in the repository spells a key in the `finality/`
    // namespace, and no key-family prefix (a literal ending in `/`, the
    // repository's convention for scan prefixes) is the start of a v1 name,
    // so no prefix scan reaches v1 rows. (Literals such as the state value
    // `b"final"` are not keys.)
    let reserved: Vec<String> = literals
        .iter()
        .filter(|l| l.starts_with(b"finality/"))
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    assert!(
        reserved.is_empty(),
        "other literals in the finality/ namespace: {reserved:?}"
    );
    let prefixes: Vec<String> = literals
        .iter()
        .filter(|l| l.ends_with(b"/") && v1.iter().any(|n| n.starts_with(l)))
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .collect();
    assert!(
        prefixes.is_empty(),
        "literals that are a prefix of a v1 name: {prefixes:?}"
    );
}

#[test]
fn a_certified_commit_writes_only_v1_keys_and_leaves_the_legacy_pointer_alone() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    // Legacy local-depth records, set to sentinels.
    let blocks = BlockStore::new(&db);
    blocks.set_finalized(0, &g.hash()).unwrap();
    let before = meta_keys_now(&db);

    let b1 = child(&g, 0);
    certify(&db, &b1).unwrap();
    let b2 = child(&b1, 0);
    certify(&db, &b2).unwrap();

    let after = meta_keys_now(&db);
    let added: BTreeSet<Vec<u8>> = after.difference(&before).cloned().collect();
    let expected: BTreeSet<Vec<u8>> = [
        FINALIZED_POINTER_KEY.to_vec(),
        certificate_key(1, &b1.hash()),
        certificate_key(2, &b2.hash()),
    ]
    .into();
    assert_eq!(added, expected, "the only new META keys are v1 keys");
    assert!(
        before.difference(&after).next().is_none(),
        "nothing removed"
    );
    assert_eq!(
        blocks.get_finalized_height().unwrap(),
        Some(0),
        "legacy height untouched"
    );
    assert_eq!(
        blocks.get_finalized_hash().unwrap(),
        Some(g.hash()),
        "legacy hash untouched"
    );

    assert_eq!(
        recover_v1(&db, &V1Shape).unwrap(),
        Recovery::Finalized(FinalizedPointer {
            height: 2,
            hash: b2.hash()
        })
    );
    let audit = audit_namespace(&db, &V1Shape).unwrap();
    assert_eq!(audit.certificates, 2);
    assert_eq!(
        db.get(cf::META, &certificate_key(2, &b2.hash())).unwrap(),
        Some(v1_cert(2, &b2.hash(), 3))
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Corruption (every case fails closed; nothing is repaired or rewritten)
// ═════════════════════════════════════════════════════════════════════════════

fn chain3(dir: &TempDir) -> (Database, Vec<Block>) {
    let db = open(dir.path());
    let chain = certified_chain(&db, 3);
    assert!(recover_v1(&db, &V1Shape).is_ok());
    (db, chain)
}

#[test]
fn a_truncated_or_extended_certificate_is_refused() {
    for edit in [-1i64, -66, 1, 66] {
        for height in [3u64, 2] {
            let dir = TempDir::new().unwrap();
            let (db, chain) = chain3(&dir);
            let b = &chain[height as usize];
            let key = certificate_key(height, &b.hash());
            let mut v = db.get(cf::META, &key).unwrap().unwrap();
            if edit < 0 {
                v.truncate(v.len() - (-edit) as usize);
            } else {
                v.extend(std::iter::repeat_n(0u8, edit as usize));
            }
            db.put(cf::META, &key, &v).unwrap();
            if height == 3 {
                // The pointer's certificate: the seam's own recovery refuses.
                assert!(seam_corrupt(recover_v1(&db, &V1Shape)).contains("stored certificate"));
            } else {
                assert!(matches!(
                    violation(recover_v1(&db, &V1Shape)),
                    NamespaceViolation::CertificateRefused { height: 2, .. }
                ));
            }
        }
    }
}

#[test]
fn a_flipped_byte_in_any_checked_header_field_is_refused() {
    // magic, schema, height, block_id and k: the fields that bind a
    // certificate to its key. (A flipped signature byte is refused by the
    // real verifier's E1 check, tested in finality-foundations.)
    let offsets: Vec<usize> = (0..9).chain(41..81).chain(117..119).collect();
    let dir = TempDir::new().unwrap();
    let (db, chain) = chain3(&dir);
    let key = certificate_key(2, &chain[2].hash());
    let good = db.get(cf::META, &key).unwrap().unwrap();
    for i in offsets {
        let mut v = good.clone();
        v[i] ^= 0x01;
        db.put(cf::META, &key, &v).unwrap();
        assert!(
            matches!(
                violation(recover_v1(&db, &V1Shape)),
                NamespaceViolation::CertificateRefused { height: 2, .. }
            ),
            "flip at {i}"
        );
    }
    db.put(cf::META, &key, &good).unwrap();
    assert!(recover_v1(&db, &V1Shape).is_ok(), "restored");
}

#[test]
fn a_flipped_byte_in_the_pointer_is_refused() {
    let dir = TempDir::new().unwrap();
    let (db, _chain) = chain3(&dir);
    let good = db.get(cf::META, FINALIZED_POINTER_KEY).unwrap().unwrap();
    for i in 0..FINALIZED_POINTER_LEN {
        for bit in [0x01u8, 0x80] {
            let mut v = good.clone();
            v[i] ^= bit;
            db.put(cf::META, FINALIZED_POINTER_KEY, &v).unwrap();
            assert!(
                matches!(recover_v1(&db, &V1Shape), Err(RecoverV1Error::Seam(_))),
                "pointer flip {bit:#04x} at {i} accepted"
            );
        }
    }
    for len in [0usize, 39, 41] {
        db.put(cf::META, FINALIZED_POINTER_KEY, &vec![0u8; len])
            .unwrap();
        assert!(seam_corrupt(recover_v1(&db, &V1Shape)).contains("finalized pointer"));
    }
}

#[test]
fn key_and_value_naming_different_blocks_are_refused() {
    let dir = TempDir::new().unwrap();
    let (db, chain) = chain3(&dir);
    // Block 1's certificate stored under block 2's key: height mismatch.
    let c1 = db
        .get(cf::META, &certificate_key(1, &chain[1].hash()))
        .unwrap()
        .unwrap();
    db.put(cf::META, &certificate_key(2, &chain[2].hash()), &c1)
        .unwrap();
    assert!(matches!(
        violation(recover_v1(&db, &V1Shape)),
        NamespaceViolation::CertificateRefused { height: 2, .. }
    ));
    // A certificate for another block at the same height: block mismatch.
    let other = Hash::hash(b"another block");
    db.put(
        cf::META,
        &certificate_key(2, &chain[2].hash()),
        &v1_cert(2, &other, 3),
    )
    .unwrap();
    assert!(matches!(
        violation(recover_v1(&db, &V1Shape)),
        NamespaceViolation::CertificateRefused { height: 2, .. }
    ));
}

#[test]
fn a_pointer_whose_certificate_is_missing_is_refused() {
    let dir = TempDir::new().unwrap();
    let (db, chain) = chain3(&dir);
    db.delete(cf::META, &certificate_key(3, &chain[3].hash()))
        .unwrap();
    assert!(seam_corrupt(recover_v1(&db, &V1Shape)).contains("certificate for"));
    // The audit alone reports the same record.
    assert!(matches!(
        audit_namespace(&db, &V1Shape),
        Err(NamespaceError::Violation(NamespaceViolation::PointerWithoutCertificate(p))) if p.height == 3
    ));
}

#[test]
fn certificates_without_a_pointer_are_refused() {
    let dir = TempDir::new().unwrap();
    let (db, _chain) = chain3(&dir);
    db.delete(cf::META, FINALIZED_POINTER_KEY).unwrap();
    // The seam alone would report "never certified"…
    assert_eq!(store(&db).recover().unwrap(), Recovery::NeverCertified);
    // …but certificate rows exist, so the v1 recovery refuses.
    assert!(matches!(
        violation(recover_v1(&db, &V1Shape)),
        NamespaceViolation::CertificateWithoutPointer { height: 1, .. }
    ));
}

#[test]
fn a_malformed_key_under_the_prefix_is_refused() {
    let dir = TempDir::new().unwrap();
    let (db, _chain) = chain3(&dir);
    for bad in [
        [CERTIFICATE_KEY_PREFIX, &[0u8; 39]].concat(),
        [CERTIFICATE_KEY_PREFIX, &[0u8; 41]].concat(),
        CERTIFICATE_KEY_PREFIX.to_vec(),
    ] {
        db.put(cf::META, &bad, b"x").unwrap();
        assert!(matches!(
            violation(recover_v1(&db, &V1Shape)),
            NamespaceViolation::MalformedCertificateKey(_)
        ));
        db.delete(cf::META, &bad).unwrap();
    }
    assert!(recover_v1(&db, &V1Shape).is_ok());
}

#[test]
fn a_certificate_for_a_non_canonical_block_is_refused() {
    let dir = TempDir::new().unwrap();
    let (db, chain) = chain3(&dir);
    let sibling = child(&chain[1], 9); // height 2, not canonical
    db.put(
        cf::META,
        &certificate_key(2, &sibling.hash()),
        &v1_cert(2, &sibling.hash(), 3),
    )
    .unwrap();
    assert!(matches!(
        violation(recover_v1(&db, &V1Shape)),
        NamespaceViolation::CertificateNotCanonical { height: 2, .. }
    ));
}

#[test]
fn an_aborted_commit_writes_no_v1_key_at_any_step() {
    for step in [
        CommitStep::CanonicalSetStaged,
        CommitStep::CertificateStaged,
        CommitStep::PointerStaged,
        CommitStep::BatchBuilt,
    ] {
        let dir = TempDir::new().unwrap();
        let (db, chain) = chain3(&dir);
        let before = meta_keys_now(&db);
        let next = child(chain.last().unwrap(), 0);
        let accepted = executed(&db, &next, next.header.state_root)
            .accept_imported(&next)
            .unwrap();
        let err = store(&db)
            .commit_observed(accepted, &v1_cert(4, &next.hash(), 3), &mut |s| {
                if s == step {
                    Err(CertifiedError::Injected(s))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(matches!(err, CertifiedError::Injected(s) if s == step));
        assert_eq!(meta_keys_now(&db), before, "{step:?}: META unchanged");
        assert_eq!(
            recover_v1(&db, &V1Shape).unwrap(),
            Recovery::Finalized(FinalizedPointer {
                height: 3,
                hash: chain[3].hash()
            }),
            "{step:?}"
        );
    }
}

#[test]
fn a_torn_write_is_refused_in_either_half() {
    // The seam commits one synced batch, so a torn write cannot happen
    // through it. Simulate one anyway, by writing one half of block 4's
    // records by hand.
    let dir = TempDir::new().unwrap();
    let (db, chain) = chain3(&dir);
    let next = child(chain.last().unwrap(), 0);

    // Only the certificate row: above the pointer, and its block is not
    // canonical.
    let key = certificate_key(4, &next.hash());
    db.put(cf::META, &key, &v1_cert(4, &next.hash(), 3))
        .unwrap();
    assert!(matches!(
        violation(recover_v1(&db, &V1Shape)),
        NamespaceViolation::CertificateAbovePointer { height: 4, .. }
    ));
    db.delete(cf::META, &key).unwrap();

    // Only the pointer advance: its block and certificate are missing.
    let advanced = FinalizedPointer {
        height: 4,
        hash: next.hash(),
    };
    db.put(cf::META, FINALIZED_POINTER_KEY, &encode_pointer(&advanced))
        .unwrap();
    assert!(matches!(
        recover_v1(&db, &V1Shape),
        Err(RecoverV1Error::Seam(_))
    ));
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
        genesis(&db);
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
        let g = Block::from_bytes(
            &db.get(
                cf::BLOCKS,
                BlockStore::new(&db)
                    .get_latest_hash()
                    .unwrap()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap()
            .unwrap(),
        )
        .unwrap();
        let b1 = child(&g, 0);
        certify(&db, &b1).unwrap();
        certify(&db, &child(&b1, 0)).unwrap();
    }
    assert_eq!(
        column_families(dir.path()),
        before,
        "the v1 layout adds no column family"
    );
    assert!(!ALL_CFS
        .iter()
        .any(|c| c.contains("finality") || c.contains("certificate")));
}

/// What a binary without the v1 layout does with a volume: open it (the same
/// `ALL_CFS`), read the head and the legacy pointer, and import a block by the
/// ordinary path. None of it reads a v1 key.
#[test]
fn code_without_the_v1_layout_opens_the_volume_and_ignores_the_keys() {
    let dir = TempDir::new().unwrap();
    let chain;
    {
        let db = open(dir.path());
        chain = certified_chain(&db, 3);
    }
    {
        // The pre-v1 code path: open and read only.
        let db = open(dir.path());
        let blocks = BlockStore::new(&db);
        assert_eq!(blocks.get_latest_height().unwrap(), Some(3));
        assert_eq!(blocks.get_latest_hash().unwrap(), Some(chain[3].hash()));
        assert_eq!(
            blocks.get_finalized_height().unwrap(),
            None,
            "legacy pointer never written"
        );
    }
    {
        // Back on the v1 code: consistent.
        let db = open(dir.path());
        assert_eq!(
            recover_v1(&db, &V1Shape).unwrap(),
            Recovery::Finalized(FinalizedPointer {
                height: 3,
                hash: chain[3].hash()
            })
        );
        assert_eq!(audit_namespace(&db, &V1Shape).unwrap().certificates, 3);
    }
}

/// If code without the v1 layout PUBLISHES above the pointer (a rollback
/// after certified commits had begun), the v1 code refuses on return: an
/// uncertified canonical head (S8). Nothing is reset; the v1 rows are intact.
#[test]
fn uncertified_blocks_published_by_older_code_are_refused_on_return() {
    let dir = TempDir::new().unwrap();
    let chain;
    {
        let db = open(dir.path());
        chain = certified_chain(&db, 3);
    }
    let rows_before;
    {
        let db = open(dir.path());
        rows_before = meta_keys_now(&db)
            .into_iter()
            .filter(|k| k.starts_with(b"finality/"))
            .collect::<BTreeSet<_>>();
        publish_ordinary(&db, &child(&chain[3], 0));
    }
    {
        let db = open(dir.path());
        assert!(matches!(
            recover_v1(&db, &V1Shape),
            Err(RecoverV1Error::Seam(
                CertifiedError::UncertifiedCanonicalHead { .. }
            ))
        ));
        let rows_after: BTreeSet<Vec<u8>> = meta_keys_now(&db)
            .into_iter()
            .filter(|k| k.starts_with(b"finality/"))
            .collect();
        assert_eq!(rows_after, rows_before, "the v1 rows are untouched");
    }
}

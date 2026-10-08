//! The dormant certified-commit seam (#270) against its safety requirements
//! S1 to S8 (see `src/certified.rs`).
//!
//! Everything certificate- or layout-shaped in this file is TEST-ONLY. The
//! certificate encoding, the verifier's quorum rule, the keys and the pointer
//! encoding below are fixtures, not proposals: no production encoding has been
//! ratified, and none is implied by these tests.

use sumchain_primitives::{Block, BlockHeader, BlockHeight, Hash};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutedCandidate, ExecutionSubject, JournalRecord,
};
use sumchain_storage::certified::{
    CertificateCheck, CertificateRefusal, CertificateVerifier, CertifiedError, CertifiedLayout,
    CertifiedStore, CommitStep, FinalizedPointer, Recovery,
};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::schema::meta_keys;
use tempfile::TempDir;

const TEST_LIMIT: u64 = 1 << 20;

// ── test-only certificate ───────────────────────────────────────────────────

const TEST_CERT_TAG: &[u8] = b"TEST-ONLY-CERTIFICATE";
const TEST_QUORUM: u8 = 2;

/// A stand-in for a quorum certificate: names a (height, hash) and a signer
/// count. No signatures; the verifier trusts the count. Test fixture only.
fn test_cert(height: BlockHeight, hash: &Hash, signers: u8) -> Vec<u8> {
    let mut v = TEST_CERT_TAG.to_vec();
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(hash.as_bytes());
    v.push(signers);
    v
}

struct TestVerifier;

impl CertificateVerifier for TestVerifier {
    fn verify(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
        c: &[u8],
    ) -> Result<(), CertificateRefusal> {
        let n = TEST_CERT_TAG.len();
        if c.len() != n + 8 + 32 + 1 || &c[..n] != TEST_CERT_TAG {
            return Err(CertificateRefusal("malformed test certificate".into()));
        }
        let h = u64::from_le_bytes(c[n..n + 8].try_into().unwrap());
        let hash = Hash::from_slice(&c[n + 8..n + 40]).unwrap();
        if h != height || hash != *block_hash {
            return Err(CertificateRefusal("certificate names another block".into()));
        }
        if c[n + 40] < TEST_QUORUM {
            return Err(CertificateRefusal("below quorum".into()));
        }
        Ok(())
    }
}

// ── test-only layout ────────────────────────────────────────────────────────

const TEST_CERT_PREFIX: &[u8] = b"test-only/certified/cert/";
const TEST_POINTER_KEY: &[u8] = b"test-only/certified/finalized";

struct TestLayout;

impl CertifiedLayout for TestLayout {
    fn certificate_key(&self, height: BlockHeight, block_hash: &Hash) -> (&'static str, Vec<u8>) {
        let mut k = TEST_CERT_PREFIX.to_vec();
        k.extend_from_slice(&height.to_be_bytes());
        k.extend_from_slice(block_hash.as_bytes());
        (cf::META, k)
    }
    fn pointer_key(&self) -> (&'static str, Vec<u8>) {
        (cf::META, TEST_POINTER_KEY.to_vec())
    }
    fn encode_pointer(&self, p: &FinalizedPointer) -> Vec<u8> {
        let mut v = p.height.to_le_bytes().to_vec();
        v.extend_from_slice(p.hash.as_bytes());
        v
    }
    fn decode_pointer(&self, b: &[u8]) -> Result<FinalizedPointer, String> {
        if b.len() != 40 {
            return Err(format!("pointer is {} bytes, expected 40", b.len()));
        }
        Ok(FinalizedPointer {
            height: u64::from_le_bytes(b[..8].try_into().unwrap()),
            hash: Hash::from_slice(&b[8..]).map_err(|e| e.to_string())?,
        })
    }
}

fn store(db: &Database) -> CertifiedStore<'_, TestLayout, TestVerifier> {
    CertifiedStore::new(db, TestLayout, TestVerifier)
}

// ── chain fixtures ──────────────────────────────────────────────────────────

fn open(dir: &std::path::Path) -> Database {
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

fn state_key(height: BlockHeight) -> Vec<u8> {
    format!("test-acct:{height}").into_bytes()
}

/// Execute `block` with one state write, binding `computed` as its root.
fn executed<'d>(db: &'d Database, block: &Block, computed: Hash) -> ExecutedCandidate<'d> {
    let mut cand = CandidateExecution::new(db, TEST_LIMIT);
    cand.view()
        .put(
            cf::STATE,
            &state_key(block.height()),
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

/// Block 0, published by the ORDINARY path: the pre-activation chain.
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
    store(db).commit(
        accepted,
        &test_cert(block.height(), &block.hash(), TEST_QUORUM),
    )
}

/// A chain of `n` certified blocks above genesis. Returns all blocks, genesis first.
fn certified_chain(db: &Database, n: u64) -> Vec<Block> {
    let mut chain = vec![genesis(db)];
    for _ in 0..n {
        let b = child(chain.last().unwrap(), 0);
        certify(db, &b).unwrap();
        chain.push(b);
    }
    chain
}

fn head(db: &Database) -> (BlockHeight, Hash) {
    let h = db
        .get(cf::META, meta_keys::LATEST_BLOCK_HEIGHT)
        .unwrap()
        .unwrap();
    let hash = db
        .get(cf::META, meta_keys::LATEST_BLOCK_HASH)
        .unwrap()
        .unwrap();
    (
        u64::from_be_bytes(h.try_into().unwrap()),
        Hash::from_slice(&hash).unwrap(),
    )
}

/// Which of the records a certified commit of `block` writes are present.
fn present(db: &Database, block: &Block) -> [bool; 6] {
    let h = block.height();
    let hash = block.hash();
    let (cf_c, key_c) = TestLayout.certificate_key(h, &hash);
    let ptr = store(db).finalized().unwrap();
    [
        db.get(cf::STATE, &state_key(h)).unwrap().is_some(),
        db.get(cf::BLOCKS, hash.as_bytes()).unwrap().is_some(),
        db.get(cf::BLOCK_HEIGHT, &h.to_be_bytes())
            .unwrap()
            .as_deref()
            == Some(&hash.as_bytes()[..]),
        head(db) == (h, hash),
        db.get(cf_c, &key_c).unwrap().is_some(),
        ptr == Some(FinalizedPointer { height: h, hash }),
    ]
}

fn assert_absent(db: &Database, block: &Block) {
    assert_eq!(
        present(db, block),
        [false; 6],
        "a refused or interrupted commit wrote something"
    );
}

fn assert_complete(db: &Database, block: &Block) {
    assert_eq!(
        present(db, block),
        [true; 6],
        "a certified commit is incomplete"
    );
}

// ── S1: final only with a certificate for exactly this block ────────────────

#[test]
fn s1_a_certificate_below_quorum_is_refused_and_nothing_is_written() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b = child(&g, 0);
    let accepted = executed(&db, &b, b.header.state_root)
        .accept_imported(&b)
        .unwrap();
    let err = store(&db)
        .commit(accepted, &test_cert(1, &b.hash(), TEST_QUORUM - 1))
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::CertificateRefused { .. }),
        "{err}"
    );
    assert_absent(&db, &b);
    assert_eq!(head(&db), (0, g.hash()));
}

#[test]
fn s1_a_certificate_for_another_block_is_refused() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b = child(&g, 0);
    let sibling = child(&g, 1);
    let accepted = executed(&db, &b, b.header.state_root)
        .accept_imported(&b)
        .unwrap();
    let err = store(&db)
        .commit(accepted, &test_cert(1, &sibling.hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::CertificateRefused { .. }),
        "{err}"
    );
    assert_absent(&db, &b);
}

#[test]
fn s1_malformed_certificate_bytes_are_refused() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b = child(&g, 0);
    let accepted = executed(&db, &b, b.header.state_root)
        .accept_imported(&b)
        .unwrap();
    let err = store(&db).commit(accepted, b"").unwrap_err();
    assert!(
        matches!(err, CertifiedError::CertificateRefused { .. }),
        "{err}"
    );
    assert_absent(&db, &b);
}

#[test]
fn s1_a_valid_certificate_commits_the_complete_set() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b = child(&g, 0);
    let p = certify(&db, &b).unwrap();
    assert_eq!(
        p,
        FinalizedPointer {
            height: 1,
            hash: b.hash()
        }
    );
    assert_complete(&db, &b);
}

// ── S2: one batch, all or nothing ───────────────────────────────────────────

const STEPS: [CommitStep; 5] = [
    CommitStep::CanonicalSetStaged,
    CommitStep::CertificateStaged,
    CommitStep::PointerStaged,
    CommitStep::BatchBuilt,
    CommitStep::Committed,
];

/// In-process: an error at every step before the commit leaves nothing; the
/// same commit then succeeds completely.
#[test]
fn s2_an_abort_at_any_step_before_the_commit_writes_nothing() {
    for step in &STEPS[..4] {
        let dir = TempDir::new().unwrap();
        let db = open(dir.path());
        let chain = certified_chain(&db, 1);
        let b = child(&chain[1], 0);
        let accepted = executed(&db, &b, b.header.state_root)
            .accept_imported(&b)
            .unwrap();
        let err = store(&db)
            .commit_observed(accepted, &test_cert(2, &b.hash(), TEST_QUORUM), &mut |s| {
                if s == *step {
                    Err(CertifiedError::Injected(s))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(matches!(err, CertifiedError::Injected(s) if s == *step));
        assert_absent(&db, &b);
        assert_complete(&db, &chain[1]);

        certify(&db, &b).unwrap();
        assert_complete(&db, &b);
    }
}

const CRASH_ENV: &str = "SUMCHAIN_CERTIFIED_CRASH_CHILD";

/// Child half of the process-crash test. Inert unless the parent sets
/// `CRASH_ENV` to "<step index>:<db dir>".
#[test]
fn s2_crash_child() {
    let Ok(spec) = std::env::var(CRASH_ENV) else {
        return;
    };
    let (step, dir) = spec.split_once(':').unwrap();
    let step = STEPS[step.parse::<usize>().unwrap()];
    let db = open(std::path::Path::new(dir));
    let parent =
        Block::from_bytes(&db.get(cf::BLOCKS, head(&db).1.as_bytes()).unwrap().unwrap()).unwrap();
    let b = child(&parent, 0);
    let accepted = executed(&db, &b, b.header.state_root)
        .accept_imported(&b)
        .unwrap();
    let _ = store(&db).commit_observed(
        accepted,
        &test_cert(b.height(), &b.hash(), TEST_QUORUM),
        &mut |s| {
            if s == step {
                std::process::abort();
            }
            Ok(())
        },
    );
    unreachable!("the child must have been killed at {step:?}");
}

/// A real process crash (abort, no destructors, no RocksDB shutdown) at every
/// step. After reopening, the block is either completely present (crash after
/// the synced commit) or completely absent, and recovery agrees.
#[test]
fn s2_a_process_crash_at_any_step_is_all_or_nothing() {
    for (i, step) in STEPS.iter().enumerate() {
        let dir = TempDir::new().unwrap();
        let chain = {
            let db = open(dir.path());
            certified_chain(&db, 1)
        };
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "s2_crash_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CRASH_ENV, format!("{i}:{}", dir.path().display()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "child at {step:?} was expected to crash");

        let db = open(dir.path());
        let b = child(&chain[1], 0);
        if *step == CommitStep::Committed {
            assert_complete(&db, &b);
            assert_eq!(
                store(&db).recover().unwrap(),
                Recovery::Finalized(FinalizedPointer {
                    height: 2,
                    hash: b.hash()
                })
            );
        } else {
            assert_absent(&db, &b);
            assert_eq!(
                store(&db).recover().unwrap(),
                Recovery::Finalized(FinalizedPointer {
                    height: 1,
                    hash: chain[1].hash()
                })
            );
            certify(&db, &b).unwrap();
            assert_complete(&db, &b);
        }
    }
}

/// The seam's commit is the synced one. A source guard, because fsync cannot
/// be observed from a test without fault-injecting storage.
#[test]
fn s2_the_certified_batch_is_committed_with_a_synced_wal() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/certified.rs")).unwrap();
    assert_eq!(src.matches("batch.commit_durable()?;").count(), 1);
    assert!(
        !src.contains(".commit()?"),
        "the certified path must never use the unsynced commit"
    );
}

// ── S3: monotonic, one height at a time ─────────────────────────────────────

#[test]
fn s3_the_pointer_advances_by_exactly_one_and_never_decreases() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let chain = certified_chain(&db, 3);
    let s = store(&db);
    let at3 = FinalizedPointer {
        height: 3,
        hash: chain[3].hash(),
    };
    assert_eq!(s.finalized().unwrap(), Some(at3));

    // Re-committing a final block: nothing to do.
    let again = executed(&db, &chain[2], chain[2].header.state_root)
        .accept_imported(&chain[2])
        .unwrap();
    let err = s
        .commit(again, &test_cert(2, &chain[2].hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::AlreadyFinal { height: 2, .. }),
        "{err}"
    );

    // Skipping a height.
    let b4 = child(&chain[3], 0);
    let b5 = child(&b4, 0);
    let skip = executed(&db, &b5, b5.header.state_root)
        .accept_imported(&b5)
        .unwrap();
    let err = s
        .commit(skip, &test_cert(5, &b5.hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(
            err,
            CertifiedError::DoesNotExtendFinalized { height: 5, .. }
        ),
        "{err}"
    );
    assert_absent(&db, &b5);

    // Right height, wrong parent.
    let stray = child(&chain[2], 9);
    let stray = Block::new(
        BlockHeader::new(
            stray.header.parent_hash,
            4,
            stray.header.timestamp,
            Hash::ZERO,
            stray.header.state_root,
            [7u8; 32],
        ),
        Vec::new(),
    );
    let wrong_parent = executed(&db, &stray, stray.header.state_root)
        .accept_imported(&stray)
        .unwrap();
    let err = s
        .commit(wrong_parent, &test_cert(4, &stray.hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(
            err,
            CertifiedError::DoesNotExtendFinalized { height: 4, .. }
        ),
        "{err}"
    );

    assert_eq!(s.finalized().unwrap(), Some(at3));
    assert_eq!(head(&db), (3, chain[3].hash()));

    certify(&db, &b4).unwrap();
    assert_eq!(s.finalized().unwrap().unwrap().height, 4);
}

#[test]
fn s3_the_first_certified_block_must_extend_the_canonical_head() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b1 = child(&g, 0);
    let b2 = child(&b1, 0);
    let accepted = executed(&db, &b2, b2.header.state_root)
        .accept_imported(&b2)
        .unwrap();
    let err = store(&db)
        .commit(accepted, &test_cert(2, &b2.hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::DoesNotExtendHead { .. }),
        "{err}"
    );
    assert_eq!(store(&db).finalized().unwrap(), None);
}

/// The legacy local-depth pointer is a different record and is never touched.
#[test]
fn s3_the_legacy_finalized_pointer_is_not_written() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    certified_chain(&db, 2);
    assert_eq!(db.get(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap(), None);
    assert_eq!(db.get(cf::META, meta_keys::FINALIZED_HASH).unwrap(), None);
}

// ── S4: no unwind across finality ───────────────────────────────────────────

#[test]
fn s4_an_unwind_below_the_pointer_is_refused() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let chain = certified_chain(&db, 3);
    let s = store(&db);
    for target in [0, 1, 2] {
        let err = s.check_unwind_target(target).unwrap_err();
        assert!(
            matches!(err, CertifiedError::UnwindAcrossFinality { finalized, .. } if finalized.height == 3)
        );
    }
    s.check_unwind_target(3).unwrap();
    let err = s.check_abandoned(&[chain[3].clone()]).unwrap_err();
    assert!(
        matches!(err, CertifiedError::UnwindAcrossFinality { .. }),
        "{err}"
    );
    let err = s
        .check_abandoned(&[chain[2].clone(), chain[3].clone()])
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::UnwindAcrossFinality { .. }),
        "{err}"
    );
    s.check_abandoned(&[child(&chain[3], 0)]).unwrap();
}

#[test]
fn s4_with_no_pointer_the_guards_do_not_refuse() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    store(&db).check_unwind_target(0).unwrap();
    store(&db).check_abandoned(&[g]).unwrap();
}

// ── S5: conflicting certificates ────────────────────────────────────────────

#[test]
fn s5_a_valid_certificate_for_a_different_final_block_is_refused_as_conflicting() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let chain = certified_chain(&db, 3);
    let s = store(&db);
    for h in 1..=3u64 {
        let other = child(&chain[h as usize - 1], 5);
        let err = s
            .check_certificate(h, &other.hash(), &test_cert(h, &other.hash(), TEST_QUORUM))
            .unwrap_err();
        assert!(
            matches!(err, CertifiedError::ConflictingCertificate { height, final_hash, presented_hash }
                if height == h && final_hash == chain[h as usize].hash() && presented_hash == other.hash()),
            "{err}"
        );
    }
    // Committing the conflicting block is refused the same way, and writes nothing.
    let other = child(&chain[2], 5);
    let accepted = executed(&db, &other, other.header.state_root)
        .accept_imported(&other)
        .unwrap();
    let err = s
        .commit(accepted, &test_cert(3, &other.hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(
            err,
            CertifiedError::ConflictingCertificate { height: 3, .. }
        ),
        "{err}"
    );
    assert_eq!(head(&db), (3, chain[3].hash()));
    assert_eq!(db.get(cf::BLOCKS, other.hash().as_bytes()).unwrap(), None);
}

#[test]
fn s5_an_invalid_certificate_is_never_reported_as_a_conflict() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let chain = certified_chain(&db, 2);
    let other = child(&chain[0], 5);
    let err = store(&db)
        .check_certificate(1, &other.hash(), &test_cert(1, &other.hash(), 1))
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::CertificateRefused { .. }),
        "{err}"
    );
}

#[test]
fn s5_certificate_classification() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let s = store(&db);
    assert_eq!(
        s.check_certificate(0, &g.hash(), &test_cert(0, &g.hash(), 2))
            .unwrap(),
        CertificateCheck::BelowCertifiedRange
    );
    let b1 = child(&g, 0);
    assert_eq!(
        s.check_certificate(1, &b1.hash(), &test_cert(1, &b1.hash(), 2))
            .unwrap(),
        CertificateCheck::NextHeight
    );
    certify(&db, &b1).unwrap();
    assert_eq!(
        s.check_certificate(1, &b1.hash(), &test_cert(1, &b1.hash(), 2))
            .unwrap(),
        CertificateCheck::AlreadyFinal
    );
    // Final by inclusion: genesis is below the first certified height.
    assert_eq!(
        s.check_certificate(0, &g.hash(), &test_cert(0, &g.hash(), 2))
            .unwrap(),
        CertificateCheck::AlreadyFinal
    );
    let b2 = child(&b1, 0);
    let b3 = child(&b2, 0);
    assert_eq!(
        s.check_certificate(2, &b2.hash(), &test_cert(2, &b2.hash(), 2))
            .unwrap(),
        CertificateCheck::NextHeight
    );
    assert_eq!(
        s.check_certificate(3, &b3.hash(), &test_cert(3, &b3.hash(), 2))
            .unwrap(),
        CertificateCheck::Ahead
    );
}

// ── S6: restart recovery ────────────────────────────────────────────────────

#[test]
fn s6_restart_recovers_the_same_pointer() {
    let dir = TempDir::new().unwrap();
    let expected = {
        let db = open(dir.path());
        let chain = certified_chain(&db, 4);
        FinalizedPointer {
            height: 4,
            hash: chain[4].hash(),
        }
    };
    for _ in 0..2 {
        let db = open(dir.path());
        assert_eq!(store(&db).recover().unwrap(), Recovery::Finalized(expected));
        assert_eq!(store(&db).finalized().unwrap(), Some(expected));
    }
}

#[test]
fn s6_a_database_never_certified_reports_so() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    genesis(&db);
    assert_eq!(store(&db).recover().unwrap(), Recovery::NeverCertified);
}

fn recover_err(dir: &std::path::Path) -> CertifiedError {
    store(&open(dir)).recover().unwrap_err()
}

#[test]
fn s6_a_corrupt_pointer_is_refused_and_not_reset() {
    let dir = TempDir::new().unwrap();
    {
        let db = open(dir.path());
        certified_chain(&db, 2);
        db.put(cf::META, TEST_POINTER_KEY, b"garbage").unwrap();
    }
    assert!(matches!(
        recover_err(dir.path()),
        CertifiedError::Corrupt(_)
    ));
    let db = open(dir.path());
    assert!(matches!(
        store(&db).finalized().unwrap_err(),
        CertifiedError::Corrupt(_)
    ));
    assert_eq!(
        db.get(cf::META, TEST_POINTER_KEY).unwrap().as_deref(),
        Some(&b"garbage"[..]),
        "recovery rewrote the pointer"
    );
    // And no commit proceeds on top of it.
    let parent =
        Block::from_bytes(&db.get(cf::BLOCKS, head(&db).1.as_bytes()).unwrap().unwrap()).unwrap();
    let b = child(&parent, 0);
    let accepted = executed(&db, &b, b.header.state_root)
        .accept_imported(&b)
        .unwrap();
    assert!(matches!(
        store(&db)
            .commit(accepted, &test_cert(3, &b.hash(), 2))
            .unwrap_err(),
        CertifiedError::Corrupt(_)
    ));
}

#[test]
fn s6_a_missing_certificate_is_refused() {
    let dir = TempDir::new().unwrap();
    {
        let db = open(dir.path());
        let chain = certified_chain(&db, 2);
        let (c, k) = TestLayout.certificate_key(2, &chain[2].hash());
        db.delete(c, &k).unwrap();
    }
    assert!(matches!(
        recover_err(dir.path()),
        CertifiedError::Corrupt(_)
    ));
}

#[test]
fn s6_a_certificate_that_no_longer_verifies_is_refused() {
    let dir = TempDir::new().unwrap();
    {
        let db = open(dir.path());
        let chain = certified_chain(&db, 2);
        let (c, k) = TestLayout.certificate_key(2, &chain[2].hash());
        db.put(c, &k, &test_cert(2, &chain[2].hash(), 1)).unwrap();
    }
    assert!(matches!(
        recover_err(dir.path()),
        CertifiedError::Corrupt(_)
    ));
}

#[test]
fn s6_a_pointer_whose_block_is_not_canonical_is_refused() {
    let dir = TempDir::new().unwrap();
    {
        let db = open(dir.path());
        let chain = certified_chain(&db, 2);
        db.put(
            cf::BLOCK_HEIGHT,
            &2u64.to_be_bytes(),
            chain[1].hash().as_bytes(),
        )
        .unwrap();
    }
    assert!(matches!(
        recover_err(dir.path()),
        CertifiedError::Corrupt(_)
    ));
}

#[test]
fn s6_a_pointer_whose_block_is_missing_is_refused() {
    let dir = TempDir::new().unwrap();
    {
        let db = open(dir.path());
        let chain = certified_chain(&db, 2);
        db.delete(cf::BLOCKS, chain[2].hash().as_bytes()).unwrap();
    }
    assert!(matches!(
        recover_err(dir.path()),
        CertifiedError::Corrupt(_)
    ));
}

// ── S7: exact root only ─────────────────────────────────────────────────────

#[test]
fn s7_a_legacy_force_adopted_block_cannot_be_certified() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b = child(&g, 0);
    // Height 1 is inside the legacy window, so a root mismatch is force-adopted.
    let accepted = executed(&db, &b, Hash::hash(b"not the header root"))
        .accept_imported(&b)
        .unwrap();
    assert!(!accepted.acceptance().is_verified());
    let err = store(&db)
        .commit(accepted, &test_cert(1, &b.hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::NotExactRoot { height: 1, .. }),
        "{err}"
    );
    assert_absent(&db, &b);
}

#[test]
fn s7_a_self_produced_block_can_be_certified() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let g = genesis(&db);
    let b = child(&g, 0);
    let accepted = executed(&db, &b, b.header.state_root)
        .accept_produced(&b)
        .unwrap();
    store(&db)
        .commit(accepted, &test_cert(1, &b.hash(), TEST_QUORUM))
        .unwrap();
    assert_complete(&db, &b);
}

// ── S8: no uncertified canonical head above the pointer ─────────────────────

#[test]
fn s8_an_uncertified_canonical_block_above_the_pointer_is_detected() {
    let dir = TempDir::new().unwrap();
    let db = open(dir.path());
    let chain = certified_chain(&db, 2);
    // Publish height 3 through the ORDINARY path, as a legacy binary would.
    let b3 = child(&chain[2], 0);
    executed(&db, &b3, b3.header.state_root)
        .accept_imported(&b3)
        .unwrap()
        .publish()
        .unwrap();

    assert!(matches!(
        store(&db).recover().unwrap_err(),
        CertifiedError::UncertifiedCanonicalHead { head: (3, _), .. }
    ));
    let b4 = child(&b3, 0);
    let accepted = executed(&db, &b4, b4.header.state_root)
        .accept_imported(&b4)
        .unwrap();
    let err = store(&db)
        .commit(accepted, &test_cert(4, &b4.hash(), TEST_QUORUM))
        .unwrap_err();
    assert!(
        matches!(err, CertifiedError::UncertifiedCanonicalHead { .. }),
        "{err}"
    );
}

// ── parity: the certified path publishes the same canonical set ─────────────

/// Every row the ordinary publisher writes for a block, the certified path
/// writes byte-for-byte, plus exactly the certificate and the pointer.
#[test]
fn certified_commit_writes_the_ordinary_canonical_set_plus_two_rows() {
    let ordinary = TempDir::new().unwrap();
    let certified = TempDir::new().unwrap();
    let a = open(ordinary.path());
    let c = open(certified.path());
    let ga = genesis(&a);
    let gc = genesis(&c);
    assert_eq!(ga.hash(), gc.hash());
    let b = child(&ga, 0);
    executed(&a, &b, b.header.state_root)
        .accept_imported(&b)
        .unwrap()
        .publish()
        .unwrap();
    certify(&c, &b).unwrap();

    let dump = |db: &Database| {
        let mut rows = Vec::new();
        for name in [
            cf::STATE,
            cf::BLOCKS,
            cf::BLOCK_HEIGHT,
            cf::META,
            cf::APPLICATION_JOURNAL,
        ] {
            for (k, v) in db.iter(name).unwrap() {
                rows.push((name.to_string(), k.to_vec(), v.to_vec()));
            }
        }
        rows
    };
    let ra = dump(&a);
    let rc = dump(&c);
    let extra: Vec<_> = rc.iter().filter(|r| !ra.contains(r)).collect();
    let missing: Vec<_> = ra.iter().filter(|r| !rc.contains(r)).collect();
    assert!(
        missing.is_empty(),
        "the certified path dropped ordinary rows: {missing:?}"
    );
    assert_eq!(
        extra.len(),
        2,
        "expected exactly certificate + pointer, got {extra:?}"
    );
    assert!(extra
        .iter()
        .all(|(n, k, _)| n == cf::META && k.starts_with(b"test-only/certified/")));
}

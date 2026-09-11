//! Verification is not optional, and the compiler is what enforces it.

use sumchain_primitives::Hash;
use sumchain_storage::candidate::CandidateExecution;
use sumchain_storage::db::{cf, Database};
use tempfile::TempDir;

/// Explicit fixture ceiling. The production limit is a versioned consensus
/// parameter derived from measured write sets and is not defaulted anywhere.
const TEST_LIMIT: u64 = 1 << 20;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

#[test]
fn a_verified_candidate_publishes_its_writes() {
    let (d, _g) = db();
    let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"k", b"v").unwrap();
    }
    assert_eq!(d.get(cf::STATE, b"k").unwrap(), None, "nothing yet");

    let root = Hash::hash(b"root");
    let verified = cand.verify(root, root).expect("roots match");
    assert_eq!(verified.root(), root);
    verified.into_batch().unwrap().commit().unwrap();

    assert_eq!(d.get(cf::STATE, b"k").unwrap().as_deref(), Some(&b"v"[..]));
}

#[test]
fn a_root_mismatch_destroys_the_candidate_and_leaves_the_database_untouched() {
    let (d, _g) = db();
    d.put(cf::STATE, b"existing", b"original").unwrap();

    let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
    {
        let mut view = cand.view();
        view.put(cf::STATE, b"existing", b"candidate").unwrap();
        view.put(cf::STATE, b"new", b"candidate").unwrap();
        view.delete(cf::STATE, b"existing").unwrap();
    }

    let err = cand
        .verify(Hash::hash(b"computed"), Hash::hash(b"declared"))
        .err()
        .expect("mismatched roots must not verify");
    assert!(err.to_string().contains("state root mismatch"), "{err}");

    // `verify` consumed the candidate, so the overlay is gone. Since it never
    // wrote, the rollback is the absence of a commit rather than an undo.
    assert_eq!(
        d.get(cf::STATE, b"existing").unwrap().as_deref(),
        Some(&b"original"[..])
    );
    assert_eq!(d.get(cf::STATE, b"new").unwrap(), None);
}

#[test]
fn abandoning_a_candidate_without_verifying_publishes_nothing() {
    let (d, _g) = db();
    {
        let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
        let mut view = cand.view();
        view.put(cf::STATE, b"k", b"v").unwrap();
        // dropped without verify() — e.g. execution returned an error
    }
    assert_eq!(d.get(cf::STATE, b"k").unwrap(), None);
}

#[test]
fn execution_sees_its_own_earlier_writes() {
    let (d, _g) = db();
    d.put(cf::STATE, b"a", b"disk").unwrap();

    let mut cand = CandidateExecution::new(&d, TEST_LIMIT);
    let mut view = cand.view();

    // tx 1 writes
    view.put(cf::STATE, b"a", b"tx1").unwrap();
    view.put(cf::STATE, b"b", b"tx1").unwrap();
    // tx 2 must observe tx 1
    assert_eq!(view.get(cf::STATE, b"a").unwrap().unwrap(), b"tx1".to_vec());
    assert_eq!(view.get(cf::STATE, b"b").unwrap().unwrap(), b"tx1".to_vec());
    // and a scan must agree with the point reads
    let scanned: Vec<(Vec<u8>, Vec<u8>)> =
        view.iter(cf::STATE).unwrap().map(|r| r.unwrap()).collect();
    assert_eq!(
        scanned,
        vec![
            (b"a".to_vec(), b"tx1".to_vec()),
            (b"b".to_vec(), b"tx1".to_vec())
        ]
    );
}

//! `sumchain check-finality-record` (#350), through the real binary.
//!
//! Run with the new binary on a STOPPED validator's data directory before an
//! upgrade, it reports what a start of that binary would make of the local
//! finality record (`finalized_height` / `finalized_hash`), exits 2 exactly
//! when the start would refuse it, and writes nothing: every test digests the
//! whole directory (names, lengths, modification times and contents) before
//! and after, and then asks the real start sequence (`PoAEngine::load_chain`)
//! for its verdict on the same directory.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Hash;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::schema::meta_keys;
use sumchain_storage::{cf, BlockStore, Database};

fn validator() -> KeyPair {
    KeyPair::from_bytes([31u8; 32])
}

fn genesis() -> Genesis {
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams {
            finality_depth: 2,
            ..ChainParams::default()
        },
    )
}

fn engine(db: &Arc<Database>, key: Option<KeyPair>) -> PoAEngine {
    let g = genesis();
    PoAEngine::new(
        db.clone(),
        Arc::new(StateManager::new(db.clone(), g.chain_id)),
        Arc::new(Mempool::new(MempoolConfig::default())),
        &g,
        key,
    )
    .unwrap()
}

/// A stopped node's data directory: genesis and five produced blocks, so the
/// record names height 3. Every handle is closed on return.
async fn stopped_node(dir: &Path) {
    let db = Arc::new(Database::open_default(dir).unwrap());
    let e = engine(&db, Some(validator()));
    e.init_genesis(&genesis()).unwrap();
    for _ in 0..5 {
        e.propose_block(Vec::new()).await.unwrap();
    }
    assert_eq!(e.finalized_height(), 3);
    assert_eq!(
        BlockStore::new(&db).checked_finality_record().unwrap(),
        Some((
            3,
            BlockStore::new(&db).get_hash_by_height(3).unwrap().unwrap()
        ))
    );
}

/// Change the stopped node's database with `f`, then close it.
fn alter(dir: &Path, f: impl FnOnce(&Database)) {
    let db = Database::open_default(dir).unwrap();
    f(&db);
}

fn check(dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args(["check-finality-record", "--data-dir", dir.to_str().unwrap()])
        .output()
        .expect("running the node binary")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Every entry under `dir`, by relative path: its length, its modification
/// time and the BLAKE3 of its contents (directories: zero and none).
type Tree = BTreeMap<String, (u64, std::time::SystemTime, Option<Hash>)>;

fn tree(dir: &Path) -> Tree {
    fn walk(root: &Path, at: &Path, out: &mut Tree) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::metadata(&path).unwrap();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if meta.is_dir() {
                out.insert(rel, (0, meta.modified().unwrap(), None));
                walk(root, &path, out);
            } else {
                let contents = std::fs::read(&path).unwrap();
                out.insert(
                    rel,
                    (
                        meta.len(),
                        meta.modified().unwrap(),
                        Some(Hash::hash(&contents)),
                    ),
                );
            }
        }
    }
    let mut out = Tree::new();
    walk(dir, dir, &mut out);
    out
}

/// One digest over the whole tree, for the assertion message.
fn digest(t: &Tree) -> Hash {
    let mut bytes = Vec::new();
    for (path, (len, modified, contents)) in t {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&len.to_le_bytes());
        let since = modified.duration_since(std::time::UNIX_EPOCH).unwrap();
        bytes.extend_from_slice(&since.as_nanos().to_le_bytes());
        bytes.extend_from_slice(
            contents
                .as_ref()
                .map(|h| *h.as_bytes())
                .unwrap_or([0; 32])
                .as_slice(),
        );
    }
    Hash::hash(&bytes)
}

/// Run the check and prove it wrote nothing. Returns its output.
fn checked_without_writing(dir: &Path) -> Output {
    let before = tree(dir);
    assert!(
        before.len() > 3,
        "the fixture must be a real database: {before:?}"
    );
    let out = check(dir);
    let after = tree(dir);
    assert_eq!(
        digest(&after),
        digest(&before),
        "the check changed the data directory:\nbefore {before:#?}\nafter {after:#?}"
    );
    out
}

/// What the real start sequence makes of the directory (`load_chain`, as
/// `Node::init_chain` calls it). Opens it read-write, so call it last.
fn start_verdict(dir: &Path) -> Result<(), String> {
    let db = Arc::new(Database::open_default(dir).unwrap());
    engine(&db, None)
        .load_chain()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn a_whole_record_is_accepted_and_nothing_is_written() {
    let dir = tempfile::TempDir::new().unwrap();
    stopped_node(dir.path()).await;
    let h3 = {
        let db = Database::open_read_only(dir.path()).unwrap();
        BlockStore::new(&db).get_hash_by_height(3).unwrap().unwrap()
    };

    let out = checked_without_writing(dir.path());
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(
        t.contains(&format!("Finality record: height 3, block {h3}")),
        "{t}"
    );
    assert!(t.contains("Result: START_ACCEPTS"), "{t}");
    // Twice: a read-only check leaves the directory as it found it.
    assert_eq!(checked_without_writing(dir.path()).status.code(), Some(0));

    start_verdict(dir.path()).expect("the start accepts what the check accepted");
}

#[tokio::test]
async fn no_record_at_all_is_accepted_as_the_start_accepts_it() {
    let dir = tempfile::TempDir::new().unwrap();
    stopped_node(dir.path()).await;
    alter(dir.path(), |db| {
        db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap();
        db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap();
    });

    let out = checked_without_writing(dir.path());
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("Finality record: absent"), "{t}");
    assert!(t.contains("Result: START_ACCEPTS"), "{t}");

    start_verdict(dir.path()).expect("the start accepts a database with no record");
}

/// The states the previous code's two separate writes (`finalized_height`,
/// then `finalized_hash`) can leave after an unclean stop or a failed write:
/// a height without its hash (the first record, hash write lost), the new
/// height with the previous height's hash (a later record, hash write lost),
/// and a hash without its height (height write failed, hash write did not).
#[tokio::test]
async fn a_record_torn_by_the_old_two_write_code_is_refused_and_nothing_is_written() {
    struct Case {
        what: &'static str,
        tear: fn(&Database),
        reason: &'static str,
        rollback_remedy: bool,
    }
    let cases = [
        Case {
            what: "height without its hash",
            tear: |db| db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap(),
            reason: "finalized_hash is absent",
            rollback_remedy: true,
        },
        Case {
            what: "new height, previous height's hash",
            tear: |db| {
                let h2 = BlockStore::new(db).get_hash_by_height(2).unwrap().unwrap();
                db.put(cf::META, meta_keys::FINALIZED_HASH, h2.as_bytes())
                    .unwrap()
            },
            reason: "but the canonical block at that height is",
            rollback_remedy: true,
        },
        Case {
            what: "hash without its height",
            tear: |db| db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap(),
            reason: "finalized_height is absent",
            rollback_remedy: false,
        },
    ];
    for case in cases {
        let dir = tempfile::TempDir::new().unwrap();
        stopped_node(dir.path()).await;
        alter(dir.path(), case.tear);

        let out = checked_without_writing(dir.path());
        let t = text(&out);
        assert_eq!(out.status.code(), Some(2), "{}: {t}", case.what);
        assert!(t.contains(case.reason), "{}: {t}", case.what);
        assert!(t.contains("Result: START_REFUSES"), "{}: {t}", case.what);
        assert_eq!(
            t.contains("`sumchain rollback --data-dir"),
            case.rollback_remedy,
            "{}: the rollback is offered exactly when it rewrites this record: {t}",
            case.what
        );
        assert!(
            t.contains("start the previous binary"),
            "{}: {t}",
            case.what
        );

        let refused = start_verdict(dir.path()).expect_err(case.what);
        assert!(
            refused.contains("refusing to start") && refused.contains(case.reason),
            "{}: the start refuses for the reason the check gave: {refused}",
            case.what
        );
    }
}

#[tokio::test]
async fn an_undecodable_height_is_refused_and_nothing_is_written() {
    let dir = tempfile::TempDir::new().unwrap();
    stopped_node(dir.path()).await;
    alter(dir.path(), |db| {
        db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &[3u8; 7])
            .unwrap()
    });

    let out = checked_without_writing(dir.path());
    let t = text(&out);
    assert_eq!(out.status.code(), Some(2), "{t}");
    assert!(t.contains("the finality record cannot be read"), "{t}");
    assert!(t.contains("not `sumchain rollback`"), "{t}");
    assert!(t.contains("Result: START_REFUSES"), "{t}");

    let refused = start_verdict(dir.path()).expect_err("the start refuses it too");
    assert!(
        refused.contains("refusing to start") && refused.contains("cannot be read"),
        "{refused}"
    );
}

#[test]
fn a_missing_directory_is_an_error_and_is_not_created() {
    let dir = tempfile::TempDir::new().unwrap();
    let absent = dir.path().join("no-such-data-dir");
    let out = check(&absent);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("no data directory"), "{t}");
    assert!(!t.contains("Result:"), "{t}");
    assert!(!absent.exists(), "the check created {absent:?}");
    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "the check created something beside it"
    );
}

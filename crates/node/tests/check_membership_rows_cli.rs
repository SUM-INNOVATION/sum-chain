//! `sumchain check-membership-rows` (#351, #352), through the real binary.
//!
//! The pre-upgrade check of the dormant G5 validator-set rules: on a STOPPED
//! node's data directory, a read-only run of `check_stored_rows` against the
//! schedule given on the command line must find no legacy `validator_sets`
//! row, no `vset/` row and no malformed key. Exit 0 when it finds none, 2
//! when it finds one, 1 when nothing was checked. Every test digests the whole
//! directory (names, lengths, modification times and contents) before and
//! after: the check writes nothing.
//!
//! Fixtures only: databases built here by the production engine
//! (`PoAEngine::new`), with rows planted as a pre-#266 binary or a corrupt
//! disk would leave them. Keys and values are synthetic.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Hash, ValidatorSet, ValidatorSetEntry};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::schema::ValidatorSetStore;
use sumchain_storage::{cf, Database};

/// The schedule the tests check against: L = 10, A = 1,000, so epochs 0 to
/// 100 are rowless and epoch 101 is the first with a row.
const SCHEDULE: [&str; 4] = ["--epoch-length", "10", "--activation-height", "1000"];

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

/// A stopped node's data directory: genesis and three produced blocks, by the
/// production engine, which writes no validator-set row. Every handle is
/// closed on return.
async fn stopped_node(dir: &Path) {
    let db = Arc::new(Database::open_default(dir).unwrap());
    let g = genesis();
    let e = PoAEngine::new(
        db.clone(),
        Arc::new(StateManager::new(db.clone(), g.chain_id)),
        Arc::new(Mempool::new(MempoolConfig::default())),
        &g,
        Some(validator()),
    )
    .unwrap();
    e.init_genesis(&g).unwrap();
    for _ in 0..3 {
        e.propose_block(Vec::new()).await.unwrap();
    }
}

/// Change the stopped node's database with `f`, then close it.
fn alter(dir: &Path, f: impl FnOnce(&Database)) {
    let db = Database::open_default(dir).unwrap();
    f(&db);
}

/// The `vset/` row key for `epoch`, as the G5 rules write it.
fn vset_key(epoch: u64) -> Vec<u8> {
    let mut k = b"vset/".to_vec();
    k.extend_from_slice(&epoch.to_be_bytes());
    k
}

/// A row value. The check reads keys only, as `check_stored_rows` does, so
/// no value is decoded and this one is not a record.
const ROW: &[u8] = b"synthetic row";

fn check(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args(["check-membership-rows", "--data-dir", dir.to_str().unwrap()])
        .args(args)
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

/// Run the check and prove it wrote nothing: every file byte-identical, with
/// the same name, length and modification time. Returns its output.
fn checked_without_writing(dir: &Path, args: &[&str]) -> Output {
    let before = tree(dir);
    assert!(
        before.len() > 3,
        "the fixture must be a real database: {before:?}"
    );
    let out = check(dir, args);
    let after = tree(dir);
    assert_eq!(
        after,
        before,
        "the check changed the data directory:\n{}",
        text(&out)
    );
    out
}

/// A refusal: exit 2, the finding, and the verdict.
fn assert_refused(out: &Output, finding: &str, what: &str) {
    let t = text(out);
    assert_eq!(out.status.code(), Some(2), "{what}: {t}");
    assert!(t.contains(finding), "{what}: {t}");
    assert!(t.contains("Result: ROWS_REFUSED"), "{what}: {t}");
    assert!(!t.contains("ROWS_CLEAN"), "{what}: {t}");
}

#[tokio::test]
async fn a_clean_database_passes_and_nothing_is_written() {
    let dir = tempfile::TempDir::new().unwrap();
    stopped_node(dir.path()).await;

    let out = checked_without_writing(dir.path(), &SCHEDULE);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    assert!(t.contains("(opened read-only)"), "{t}");
    assert!(t.contains("Head:            height 3"), "{t}");
    assert!(
        t.contains("Schedule:        epoch length 10, activation height 1000"),
        "{t}"
    );
    assert!(
        t.contains("no legacy validator_sets row, no vset/ row, no malformed key"),
        "{t}"
    );
    assert!(t.contains("Result: ROWS_CLEAN"), "{t}");
    // Twice: a read-only check leaves the directory as it found it.
    assert_eq!(
        checked_without_writing(dir.path(), &SCHEDULE).status.code(),
        Some(0)
    );
    // Another schedule changes nothing on a database without rows.
    let other = ["--epoch-length", "1", "--activation-height", "0"];
    assert_eq!(
        checked_without_writing(dir.path(), &other).status.code(),
        Some(0)
    );
}

#[tokio::test]
async fn a_legacy_validator_sets_row_is_refused_and_nothing_is_written() {
    // As the pre-#266 epoch writer stores it, and with a value nothing can
    // decode: the scan is key-only, so both refuse.
    type Plant = (&'static str, fn(&Database));
    let cases: [Plant; 2] = [
        ("a legacy epoch set", |db| {
            let set =
                ValidatorSet::new(3, 30, vec![ValidatorSetEntry::new([7; 32], 10, 0)], [0; 32]);
            ValidatorSetStore::new(db).put_validator_set(&set).unwrap();
        }),
        ("an undecodable legacy row", |db| {
            db.put(cf::VALIDATOR_SETS, &3u64.to_be_bytes(), b"garbage")
                .unwrap()
        }),
    ];
    for (what, plant) in cases {
        let dir = tempfile::TempDir::new().unwrap();
        stopped_node(dir.path()).await;
        alter(dir.path(), plant);

        let out = checked_without_writing(dir.path(), &SCHEDULE);
        assert_refused(
            &out,
            "the legacy validator_sets column family holds an entry (key [00, 00, 00, 00, 00, \
             00, 00, 03])",
            what,
        );
    }
}

#[tokio::test]
async fn a_vset_row_is_refused_and_nothing_is_written() {
    let cases = [
        // `check_stored_rows` refuses a row for a rowless epoch itself.
        (
            "a row for a rowless epoch",
            100,
            "a validator-set row is stored for epoch 100, which is rowless (ActivationAnchor)",
        ),
        // It accepts one for an epoch that has a row once the rules govern;
        // before they first do, there is none either.
        (
            "a row for the first epoch with a row",
            101,
            "a validator-set row is stored for epoch 101 (key [76, 73, 65, 74, 2f, 00, 00, 00, \
             00, 00, 00, 00, 65])",
        ),
        (
            "a row for a later epoch",
            5_000,
            "a validator-set row is stored for epoch 5000",
        ),
    ];
    for (what, epoch, finding) in cases {
        let dir = tempfile::TempDir::new().unwrap();
        stopped_node(dir.path()).await;
        alter(dir.path(), |db| {
            db.put(cf::STATE, &vset_key(epoch), ROW).unwrap()
        });

        let out = checked_without_writing(dir.path(), &SCHEDULE);
        assert_refused(&out, finding, what);
    }
}

#[tokio::test]
async fn a_malformed_vset_key_is_refused_and_nothing_is_written() {
    let dir = tempfile::TempDir::new().unwrap();
    stopped_node(dir.path()).await;
    alter(dir.path(), |db| {
        db.put(cf::STATE, b"vset/abc", ROW).unwrap()
    });

    let out = checked_without_writing(dir.path(), &SCHEDULE);
    assert_refused(
        &out,
        "validator-set row key [76, 73, 65, 74, 2f, 61, 62, 63] is not `vset/` followed by an \
         8-byte epoch",
        "a malformed key",
    );
}

/// Nothing is checked without a schedule: exit 1, no verdict, nothing
/// written. The same for half of one and for an epoch length of 0, which the
/// rules refuse.
#[tokio::test]
async fn a_missing_schedule_checks_nothing_and_nothing_is_written() {
    let dir = tempfile::TempDir::new().unwrap();
    stopped_node(dir.path()).await;
    // Rows the check would refuse, so that an exit of 1 cannot hide a pass.
    alter(dir.path(), |db| {
        db.put(cf::STATE, &vset_key(101), ROW).unwrap()
    });
    let cases: [(&str, &[&str], &str); 4] = [
        ("no schedule", &[], "no schedule"),
        ("no activation height", &SCHEDULE[..2], "no schedule"),
        ("no epoch length", &SCHEDULE[2..], "no schedule"),
        (
            "an epoch length of 0",
            &["--epoch-length", "0", "--activation-height", "1000"],
            "the schedule is refused (staking.epoch_length is 0",
        ),
    ];
    for (what, args, reason) in cases {
        let out = checked_without_writing(dir.path(), args);
        let t = text(&out);
        assert_eq!(out.status.code(), Some(1), "{what}: {t}");
        assert!(t.contains(reason), "{what}: {t}");
        assert!(t.contains("nothing was checked"), "{what}: {t}");
        assert!(!t.contains("Result:"), "{what}: {t}");
    }
}

#[test]
fn a_missing_directory_is_an_error_and_is_not_created() {
    let dir = tempfile::TempDir::new().unwrap();
    let absent = dir.path().join("no-such-data-dir");
    let out = check(&absent, &SCHEDULE);
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

/// An empty directory holds no database, and a database without a head holds
/// no chain: nothing is checked in either, and nothing is created or written.
#[test]
fn a_directory_without_a_chain_checks_nothing_and_nothing_is_written() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = check(dir.path(), &SCHEDULE);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("read-only"), "{t}");
    assert!(!t.contains("Result:"), "{t}");
    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "the check created a database"
    );

    alter(dir.path(), |_| {});
    let out = checked_without_writing(dir.path(), &SCHEDULE);
    let t = text(&out);
    assert_eq!(out.status.code(), Some(1), "{t}");
    assert!(t.contains("records no chain head"), "{t}");
    assert!(!t.contains("Result:"), "{t}");
}

#[test]
fn the_help_documents_the_exit_codes() {
    let out = Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args(["check-membership-rows", "--help"])
        .output()
        .expect("running the node binary");
    let t = text(&out);
    assert_eq!(out.status.code(), Some(0), "{t}");
    for needle in [
        "read-only",
        "write nothing",
        "--epoch-length",
        "--activation-height",
        "Exit status: 0",
        "2 when",
        "1 when nothing was checked",
    ] {
        assert!(t.contains(needle), "{needle}: {t}");
    }
}

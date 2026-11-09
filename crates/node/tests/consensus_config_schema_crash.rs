//! The consensus-configuration schema move, and its pre-start revert, killed
//! with SIGKILL at each write step of the REAL binary (#268).
//!
//! Each case prepares a stopped node's data directory the way production holds
//! it (a schema-3 record, written under the deployed release's policy), runs
//! `sumchain acknowledge-consensus-config-schema` or
//! `sumchain revert-consensus-config-schema` as a child process with a crash
//! barrier armed (the `failpoints` feature, enabled only for this crate's
//! tests: the child announces the barrier and blocks), and kills the child
//! with SIGKILL there — no unwinding, no destructors, no flush. Each command
//! has one write: one durable batch. The barriers sit immediately before and
//! immediately after its commit.
//!
//! After every kill the database is exactly the complete old database or
//! exactly the complete new one — every row of every column family compared
//! with a reference made without a crash — never a mix; the command can be run
//! again to the same end; and the release that reads the result starts on it.
//! A further case kills the move at spread-out moments of an uncrashed run's
//! duration, with the same verdict.
//!
//! Durability: the batch is committed with the write-ahead log synced. A killed
//! PROCESS loses nothing the WAL holds; this proves nothing about power loss
//! beyond what the synced commit gives.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use sumchain_consensus::branch_switch::failpoints::{Failpoint, BARRIER_AT_ENV, BARRIER_FILE_ENV};
use sumchain_consensus::consensus_config as ccfg;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_storage::Database;

/// The releases that wrote schema 3, the deployed one among them.
static SCHEMA_3_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2, &ccfg::SCHEMA_3],
    writes: &ccfg::SCHEMA_3,
    knows: &ccfg::SCHEMA_4,
};

fn genesis() -> Genesis {
    let v = KeyPair::from_bytes([12u8; 32]);
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![v.public_key().to_base58()],
        HashMap::from([(v.address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    )
}

type Rows = Vec<(String, Vec<u8>, Vec<u8>)>;

/// Every row of every column family.
fn all_rows(data: &Path) -> Rows {
    let db = Database::open_default(data).unwrap();
    let mut out = Vec::new();
    for name in sumchain_storage::db::ALL_CFS {
        for (k, v) in db.iter(name).unwrap() {
            out.push((name.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out
}

/// A schema-3 database, as the deployed release records it, and the move's
/// commitments.
fn schema_3_dir(root: &Path, name: &str) -> (PathBuf, String, String) {
    let data = root.join(name);
    let db = Database::open_default(&data).unwrap();
    ccfg::record::check_at_startup_with(&db, &genesis(), 0, &SCHEMA_3_RELEASE).unwrap();
    let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
    assert_eq!((p.from_schema, p.to_schema), (3, 4));
    (data, p.old.to_string(), p.new.to_string())
}

fn args(cmd: &str, data: &Path, old: &str, new: &str) -> Vec<String> {
    [
        cmd,
        "--data-dir",
        data.to_str().unwrap(),
        "--old",
        old,
        "--new",
        new,
        "--yes",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

const MOVE: &str = "acknowledge-consensus-config-schema";
const REVERT: &str = "revert-consensus-config-schema";

fn run(argv: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args(argv)
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

/// Run `argv` with the crash barrier `fp` armed, wait for the child to reach
/// it, and SIGKILL it there.
fn kill_at(fp: Failpoint, argv: &[String], marker: &Path) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args(argv)
        .env(BARRIER_AT_ENV, fp.name())
        .env(BARRIER_FILE_ENV, marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            panic!(
                "the child exited ({status}) before reaching barrier {}:\n{}",
                fp.name(),
                text(&out)
            );
        }
        assert!(
            Instant::now() < deadline,
            "the child never reached {}",
            fp.name()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.kill().expect("SIGKILL the child"); // SIGKILL on unix
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "the child must have been killed, not exited"
    );
}

/// The three states a crash may leave, each made without a crash: before the
/// move, after the move, and after the move's revert (which must equal before).
struct References {
    before: Rows,
    moved: Rows,
}

fn references(root: &Path) -> References {
    let (data, old, new) = schema_3_dir(root, "reference");
    let before = all_rows(&data);
    let out = run(&args(MOVE, &data, &old, &new));
    assert!(out.status.success(), "{}", text(&out));
    let moved = all_rows(&data);
    let out = run(&args(REVERT, &data, &new, &old));
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(all_rows(&data), before, "the revert restores every row");
    assert_ne!(before, moved);
    References { before, moved }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Expect {
    Before,
    Moved,
}

fn verify(data: &Path, refs: &References, expect: Expect, what: &str) {
    let rows = all_rows(data);
    match expect {
        Expect::Before => assert!(rows == refs.before, "{what}: not exactly the old rows"),
        Expect::Moved => assert!(rows == refs.moved, "{what}: not exactly the moved rows"),
    }
    // The release that reads the result starts on it, writing nothing.
    let db = Database::open_default(data).unwrap();
    let policy = match expect {
        Expect::Before => &SCHEMA_3_RELEASE,
        Expect::Moved => &ccfg::PRODUCTION,
    };
    assert!(matches!(
        ccfg::record::check_at_startup_with(&db, &genesis(), 0, policy).unwrap(),
        ccfg::StartupOutcome::Unchanged { .. }
    ));
    drop(db);
    assert!(all_rows(data) == rows, "{what}: the start wrote nothing");
}

/// A move killed immediately before its batch commits leaves exactly the old
/// database, which the deployed release still starts on; the move then runs
/// again to exactly the moved database.
#[test]
fn a_move_killed_before_its_commit_leaves_exactly_the_old_database() {
    let tmp = tempfile::tempdir().unwrap();
    let refs = references(tmp.path());
    let (data, old, new) = schema_3_dir(tmp.path(), "crashed");
    assert!(all_rows(&data) == refs.before);
    kill_at(
        Failpoint::SchemaTransitionBeforeCommit,
        &args(MOVE, &data, &old, &new),
        &tmp.path().join("at-barrier"),
    );
    verify(
        &data,
        &refs,
        Expect::Before,
        "killed before the move's commit",
    );
    let out = run(&args(MOVE, &data, &old, &new));
    assert!(out.status.success(), "{}", text(&out));
    verify(&data, &refs, Expect::Moved, "the move run again");
}

/// A move killed immediately after its batch commits leaves exactly the moved
/// database; running the move again refuses and writes nothing.
#[test]
fn a_move_killed_after_its_commit_leaves_exactly_the_moved_database() {
    let tmp = tempfile::tempdir().unwrap();
    let refs = references(tmp.path());
    let (data, old, new) = schema_3_dir(tmp.path(), "crashed");
    kill_at(
        Failpoint::SchemaTransitionAfterCommit,
        &args(MOVE, &data, &old, &new),
        &tmp.path().join("at-barrier"),
    );
    verify(
        &data,
        &refs,
        Expect::Moved,
        "killed after the move's commit",
    );
    let out = run(&args(MOVE, &data, &old, &new));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("already recorded in schema 4"),
        "{}",
        text(&out)
    );
    verify(&data, &refs, Expect::Moved, "the move run again");
}

/// A revert killed immediately before its batch commits leaves exactly the
/// moved database; the revert then runs again to exactly the old one.
#[test]
fn a_revert_killed_before_its_commit_leaves_exactly_the_moved_database() {
    let tmp = tempfile::tempdir().unwrap();
    let refs = references(tmp.path());
    let (data, old, new) = schema_3_dir(tmp.path(), "crashed");
    let out = run(&args(MOVE, &data, &old, &new));
    assert!(out.status.success(), "{}", text(&out));
    kill_at(
        Failpoint::SchemaRevertBeforeCommit,
        &args(REVERT, &data, &new, &old),
        &tmp.path().join("at-barrier"),
    );
    verify(
        &data,
        &refs,
        Expect::Moved,
        "killed before the revert's commit",
    );
    let out = run(&args(REVERT, &data, &new, &old));
    assert!(out.status.success(), "{}", text(&out));
    verify(&data, &refs, Expect::Before, "the revert run again");
}

/// A revert killed immediately after its batch commits leaves exactly the old
/// database, which the deployed release starts on; running the revert again
/// refuses and writes nothing.
#[test]
fn a_revert_killed_after_its_commit_leaves_exactly_the_old_database() {
    let tmp = tempfile::tempdir().unwrap();
    let refs = references(tmp.path());
    let (data, old, new) = schema_3_dir(tmp.path(), "crashed");
    let out = run(&args(MOVE, &data, &old, &new));
    assert!(out.status.success(), "{}", text(&out));
    kill_at(
        Failpoint::SchemaRevertAfterCommit,
        &args(REVERT, &data, &new, &old),
        &tmp.path().join("at-barrier"),
    );
    verify(
        &data,
        &refs,
        Expect::Before,
        "killed after the revert's commit",
    );
    let out = run(&args(REVERT, &data, &new, &old));
    assert!(!out.status.success(), "{}", text(&out));
    verify(&data, &refs, Expect::Before, "the revert run again");
}

/// The move killed with SIGKILL at moments spread over an uncrashed run's
/// duration, with no barrier: every outcome is exactly the old database or
/// exactly the moved one, and the move then completes.
#[test]
fn a_move_killed_at_any_moment_leaves_the_old_or_the_moved_database() {
    let tmp = tempfile::tempdir().unwrap();
    let refs = references(tmp.path());
    let (timed, old, new) = schema_3_dir(tmp.path(), "timed");
    let started = Instant::now();
    assert!(run(&args(MOVE, &timed, &old, &new)).status.success());
    let full = started.elapsed();
    const KILLS: u32 = 12;
    let mut seen = Vec::new();
    for i in 0..KILLS {
        let (data, old, new) = schema_3_dir(tmp.path(), &format!("killed-{i}"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_sumchain"))
            .args(args(MOVE, &data, &old, &new))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(full * (i + 1) / (KILLS + 1));
        let _ = child.kill();
        let _ = child.wait();
        let rows = all_rows(&data);
        let expect = if rows == refs.before {
            Expect::Before
        } else {
            Expect::Moved
        };
        verify(
            &data,
            &refs,
            expect,
            &format!("killed at {}/{}", i + 1, KILLS + 1),
        );
        seen.push(expect);
        if expect == Expect::Before {
            assert!(run(&args(MOVE, &data, &old, &new)).status.success());
            verify(&data, &refs, Expect::Moved, "completed after the kill");
        }
    }
    eprintln!("outcomes of {KILLS} timed kills: {seen:?}");
}

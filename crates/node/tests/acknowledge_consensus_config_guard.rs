//! `sumchain acknowledge-consensus-config` (#268), driven through the real
//! binary: it records an exactly named local change on a stopped node, and
//! refuses everything else — including running while the database is held.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Output};

use sumchain_consensus::consensus_config as ccfg;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_storage::Database;

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

fn ack(data_dir: &Path, genesis_file: &Path, old: &str, new: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "acknowledge-consensus-config",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--genesis",
            genesis_file.to_str().unwrap(),
            "--old",
            old,
            "--new",
            new,
            "--yes",
        ])
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

struct Fixture {
    _dir: tempfile::TempDir,
    data: std::path::PathBuf,
    genesis_file: std::path::PathBuf,
    old: String,
    new: String,
}

/// A database whose baseline is `genesis()`, and a genesis file that differs
/// from it in one non-gate parameter.
fn fixture() -> Fixture {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let g = genesis();
    {
        let db = Database::open_default(&data).unwrap();
        ccfg::check_at_startup(&db, &g, 0).unwrap();
    }
    let mut changed = g.clone();
    changed.params.max_contract_gas += 1;
    let genesis_file = dir.path().join("genesis.json");
    changed.to_file(&genesis_file).unwrap();
    Fixture {
        old: ccfg::build(&g).unwrap().commitment().to_string(),
        new: ccfg::build(&changed).unwrap().commitment().to_string(),
        data,
        genesis_file,
        _dir: dir,
    }
}

#[test]
fn the_command_records_an_exactly_named_change() {
    let f = fixture();
    let out = ack(&f.data, &f.genesis_file, &f.old, &f.new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Recorded transition 1"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("max_contract_gas"), "{}", text(&out));

    let db = Database::open_default(&f.data).unwrap();
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, ccfg::TransitionKind::OperatorAcknowledged);
    drop(db);

    // A second run has nothing left to acknowledge, and adds nothing.
    let again = ack(&f.data, &f.genesis_file, &f.new, &f.new);
    assert!(!again.status.success());
    let db = Database::open_default(&f.data).unwrap();
    assert_eq!(ccfg::read_transitions(&db).unwrap().len(), 1);
}

#[test]
fn the_command_refuses_wrong_commitments() {
    let f = fixture();
    let zero = format!("0x{}", "00".repeat(32));
    for (old, new) in [(&zero, &f.new), (&f.old, &zero)] {
        let out = ack(&f.data, &f.genesis_file, old, new);
        assert!(!out.status.success(), "{}", text(&out));
    }
    let out = ack(&f.data, &f.genesis_file, "not-hex", &f.new);
    assert!(!out.status.success());
    let db = Database::open_default(&f.data).unwrap();
    assert!(ccfg::read_transitions(&db).unwrap().is_empty());
}

#[test]
fn the_command_refuses_while_the_database_is_held() {
    let f = fixture();
    let held = Database::open_default(&f.data).unwrap();
    let out = ack(&f.data, &f.genesis_file, &f.old, &f.new);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("must be stopped"), "{}", text(&out));
    assert!(ccfg::read_transitions(&held).unwrap().is_empty());
}

fn ack_schema(data_dir: &Path, old: &str, new: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "acknowledge-consensus-config-schema",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--old",
            old,
            "--new",
            new,
            "--yes",
        ])
        .output()
        .expect("running the node binary")
}

/// The release that recorded schema 1: it read and wrote schema 1 and knew
/// schema 2 only as a draft. Used to create the schema-1 database it would have
/// left. It knows schema 3 only because this binary's genesis carries the
/// schema-3 gate, which a policy must be able to name to build at all; unset,
/// that gate adds nothing to the schema-1 record this writes.
static PREVIOUS: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1],
    writes: &ccfg::SCHEMA_1,
    knows: &ccfg::SCHEMA_4,
};

/// The release that wrote schema 2: it read schemas 1 and 2 and wrote 2.
static SCHEMA_2_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2],
    writes: &ccfg::SCHEMA_2,
    knows: &ccfg::SCHEMA_4,
};

/// The releases that wrote schema 3: they
/// read schemas 1, 2 and 3, wrote 3, and knew schema 4 only as a draft.
static SCHEMA_3_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2, &ccfg::SCHEMA_3],
    writes: &ccfg::SCHEMA_3,
    knows: &ccfg::SCHEMA_4,
};

/// A database whose baseline the previous release recorded (schema 1), and the
/// commitment this binary moves it to.
fn schema_1_fixture() -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let db = Database::open_default(&data).unwrap();
    ccfg::record::check_at_startup_with(&db, &genesis(), 0, &PREVIOUS).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 1);
    let pending = ccfg::pending_schema_transition(&db)
        .unwrap()
        .expect("this binary offers schema 4");
    (dir, data, r.commitment.to_string(), pending.new.to_string())
}

/// A database the schema-2 release created (schema 2), and the commitment this
/// binary moves it to.
fn schema_2_fixture() -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let db = Database::open_default(&data).unwrap();
    ccfg::record::check_at_startup_with(&db, &genesis(), 0, &SCHEMA_2_RELEASE).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 2);
    let pending = ccfg::pending_schema_transition(&db)
        .unwrap()
        .expect("this binary offers schema 4");
    (dir, data, r.commitment.to_string(), pending.new.to_string())
}

/// A database a schema-3 release created (schema 3, as a schema-3 release records),
/// and the commitment this binary moves it to.
fn schema_3_fixture() -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let db = Database::open_default(&data).unwrap();
    ccfg::record::check_at_startup_with(&db, &genesis(), 0, &SCHEMA_3_RELEASE).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 3);
    let pending = ccfg::pending_schema_transition(&db)
        .unwrap()
        .expect("this binary offers schema 4");
    (dir, data, r.commitment.to_string(), pending.new.to_string())
}

fn show_schema(data_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "acknowledge-consensus-config-schema",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--show",
        ])
        .output()
        .expect("running the node binary")
}

/// The value printed after `flag` by `--show`.
fn shown(out: &Output, flag: &str) -> Option<String> {
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.trim()
            .strip_prefix(&format!("{flag} "))
            .map(str::to_string)
    })
}

fn meta(data: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let db = Database::open_default(data).unwrap();
    db.prefix_iter_checked(sumchain_storage::cf::META, b"consensus_config/")
        .unwrap()
        .map(|e| e.unwrap())
        .take_while(|(k, _)| k.starts_with(b"consensus_config/"))
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

/// The command moves a schema-1 database to schema 4 in one step when told
/// both commitments exactly, keeps the old encoding in the history, and has
/// nothing left to do afterwards.
#[test]
fn the_schema_transition_moves_a_schema_1_database() {
    let (_dir, data, old, new) = schema_1_fixture();
    let out = ack_schema(&data, &old, &new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 1 -> 4"), "{}", text(&out));

    let db = Database::open_default(&data).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 4);
    assert_eq!(r.commitment.to_string(), new);
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, ccfg::TransitionKind::SchemaTransition);
    drop(db);

    let again = ack_schema(&data, &new, &new);
    assert!(!again.status.success(), "{}", text(&again));
    assert!(
        text(&again).contains("already recorded in schema 4"),
        "{}",
        text(&again)
    );
    let db = Database::open_default(&data).unwrap();
    assert_eq!(ccfg::read_transitions(&db).unwrap().len(), 1);
}

/// A schema-2 database moves to schema 4 the same way, adding 0x1043 and the
/// four schema-4 gates.
#[test]
fn the_schema_transition_moves_a_schema_2_database() {
    let (_dir, data, old, new) = schema_2_fixture();
    let out = ack_schema(&data, &old, &new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 2 -> 4"), "{}", text(&out));
    assert!(
        text(&out).contains("5 field(s) added absent"),
        "{}",
        text(&out)
    );
    let db = Database::open_default(&data).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 4);
    assert_eq!(r.commitment.to_string(), new);
}

/// A schema-3 database, as a schema-3 release records, moves to schema 4 the same
/// way, adding exactly the four schema-4 gates.
#[test]
fn the_schema_transition_moves_a_schema_3_database() {
    let (_dir, data, old, new) = schema_3_fixture();
    let out = ack_schema(&data, &old, &new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 3 -> 4"), "{}", text(&out));
    assert!(
        text(&out).contains("4 field(s) added absent"),
        "{}",
        text(&out)
    );
    let db = Database::open_default(&data).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 4);
    assert_eq!(r.commitment.to_string(), new);
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, ccfg::TransitionKind::SchemaTransition);
    assert_eq!(history[0].changed_ids, vec![0x1044, 0x1045, 0x1046, 0x1047]);
    assert_eq!(history[0].old_commitment.to_string(), old);
}

/// `--show` prints both commitments exactly as the move takes them and writes
/// nothing; the operator's sequence — show, then move with what it printed —
/// lands on schema 4. On a database already in schema 4 it says there is
/// nothing to move.
#[test]
fn show_prints_the_exact_move_and_writes_nothing() {
    let (_dir, data, old, new) = schema_1_fixture();
    let before = meta(&data);
    let out = show_schema(&data);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 1"), "{}", text(&out));
    assert_eq!(
        shown(&out, "--old").as_deref(),
        Some(old.as_str()),
        "{}",
        text(&out)
    );
    assert_eq!(
        shown(&out, "--new").as_deref(),
        Some(new.as_str()),
        "{}",
        text(&out)
    );
    assert_eq!(meta(&data), before, "nothing written");

    let moved = ack_schema(
        &data,
        &shown(&out, "--old").unwrap(),
        &shown(&out, "--new").unwrap(),
    );
    assert!(moved.status.success(), "{}", text(&moved));

    let after = show_schema(&data);
    assert!(after.status.success(), "{}", text(&after));
    assert!(
        text(&after).contains("no schema transition to make"),
        "{}",
        text(&after)
    );
    assert_eq!(shown(&after, "--new"), None);

    // `--show` takes no commitments.
    let both = Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "acknowledge-consensus-config-schema",
            "--data-dir",
            data.to_str().unwrap(),
            "--show",
            "--old",
            &old,
        ])
        .output()
        .unwrap();
    assert!(!both.status.success(), "{}", text(&both));
}

/// Anything but both exact commitments refuses and writes nothing.
#[test]
fn the_schema_transition_refuses_wrong_commitments() {
    let (_dir, data, old, new) = schema_1_fixture();
    let before = meta(&data);
    let zero = format!("0x{}", "00".repeat(32));
    for (o, n) in [(&zero, &new), (&old, &zero), (&new, &old), (&old, &old)] {
        let out = ack_schema(&data, o, n);
        assert!(!out.status.success(), "{o} -> {n}: {}", text(&out));
    }
    assert_eq!(meta(&data), before, "nothing written");
}

/// A database this binary created records schema 4 already: nothing to move.
#[test]
fn the_schema_transition_refuses_a_database_already_in_schema_4() {
    let f = fixture();
    let before = meta(&f.data);
    let out = ack_schema(&f.data, &f.old, &f.old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("already recorded in schema 4"),
        "{}",
        text(&out)
    );
    assert_eq!(meta(&f.data), before);
}

#[test]
fn the_schema_transition_refuses_while_the_database_is_held() {
    let f = fixture();
    let held = Database::open_default(&f.data).unwrap();
    let out = ack_schema(&f.data, &f.old, &f.old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("must be stopped"), "{}", text(&out));
    assert!(ccfg::read_transitions(&held).unwrap().is_empty());
}

fn revert_schema(data_dir: &Path, old: &str, new: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "revert-consensus-config-schema",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--old",
            old,
            "--new",
            new,
            "--yes",
        ])
        .output()
        .expect("running the node binary")
}

fn show_revert(data_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "revert-consensus-config-schema",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--show",
        ])
        .output()
        .expect("running the node binary")
}

/// Every row of every column family.
fn all_rows(data: &Path) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let db = Database::open_default(data).unwrap();
    let mut out = Vec::new();
    for name in sumchain_storage::db::ALL_CFS {
        for (k, v) in db.iter(name).unwrap() {
            out.push((name.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out
}

/// The operator's pre-start abort through the real binary: on a schema-3
/// database (as a schema-3 release records), the move, then `--show` on the revert,
/// then the revert with exactly what it printed, leaves every row of every
/// column family as it was before the move. Afterwards there is nothing to
/// revert, and the move is offered again with the same commitments.
#[test]
fn the_pre_start_revert_restores_exactly_the_rows_the_move_replaced() {
    let (_dir, data, old, new) = schema_3_fixture();
    let before = all_rows(&data);
    let nothing = show_revert(&data);
    assert!(nothing.status.success(), "{}", text(&nothing));
    assert!(
        text(&nothing).contains("No pre-start revert is available"),
        "{}",
        text(&nothing)
    );
    assert_eq!(all_rows(&data), before, "--show writes nothing");

    let moved = ack_schema(&data, &old, &new);
    assert!(moved.status.success(), "{}", text(&moved));
    let after_move = all_rows(&data);

    let out = show_revert(&data);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("restore schema 3"), "{}", text(&out));
    assert_eq!(shown(&out, "--old").as_deref(), Some(new.as_str()));
    assert_eq!(shown(&out, "--new").as_deref(), Some(old.as_str()));
    assert_eq!(all_rows(&data), after_move, "--show writes nothing");

    let done = revert_schema(
        &data,
        &shown(&out, "--old").unwrap(),
        &shown(&out, "--new").unwrap(),
    );
    assert!(done.status.success(), "{}", text(&done));
    assert!(text(&done).contains("schema 4 -> 3"), "{}", text(&done));
    assert_eq!(all_rows(&data), before, "exactly the rows before the move");

    let again = revert_schema(&data, &new, &old);
    assert!(!again.status.success(), "{}", text(&again));
    assert_eq!(all_rows(&data), before, "a second revert writes nothing");
    let offered = show_schema(&data);
    assert_eq!(shown(&offered, "--old").as_deref(), Some(old.as_str()));
    assert_eq!(shown(&offered, "--new").as_deref(), Some(new.as_str()));
}

/// Anything but both exact commitments refuses the revert and writes nothing.
#[test]
fn the_revert_refuses_wrong_commitments() {
    let (_dir, data, old, new) = schema_3_fixture();
    assert!(ack_schema(&data, &old, &new).status.success());
    let before = all_rows(&data);
    let zero = format!("0x{}", "00".repeat(32));
    for (o, n) in [(&zero, &old), (&new, &zero), (&old, &new), (&new, &new)] {
        let out = revert_schema(&data, o, n);
        assert!(!out.status.success(), "{o} -> {n}: {}", text(&out));
    }
    assert_eq!(all_rows(&data), before, "nothing written");
}

/// Once the chain has a block above the move's height, the revert is refused,
/// names forward recovery, and writes nothing.
#[test]
fn the_revert_is_refused_once_a_block_above_the_move_exists() {
    let (_dir, data, old, new) = schema_3_fixture();
    assert!(ack_schema(&data, &old, &new).status.success());
    {
        let db = Database::open_default(&data).unwrap();
        db.put(
            sumchain_storage::cf::BLOCK_HEIGHT,
            &1u64.to_be_bytes(),
            &[7u8; 32],
        )
        .unwrap();
        sumchain_storage::schema::BlockStore::new(&db)
            .set_latest_height(1)
            .unwrap();
    }
    let before = all_rows(&data);
    let show = show_revert(&data);
    assert!(show.status.success(), "{}", text(&show));
    assert!(text(&show).contains("forward only"), "{}", text(&show));
    let out = revert_schema(&data, &new, &old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("forward only"), "{}", text(&out));
    assert_eq!(all_rows(&data), before, "nothing written");
}

/// While a node holds the database, neither the move nor the revert runs, and
/// nothing is written — with the right commitments in hand.
#[test]
fn the_move_and_the_revert_refuse_while_the_database_is_held() {
    let (_dir, data, old, new) = schema_3_fixture();
    {
        let held = Database::open_default(&data).unwrap();
        let out = ack_schema(&data, &old, &new);
        assert!(!out.status.success(), "{}", text(&out));
        assert!(text(&out).contains("must be stopped"), "{}", text(&out));
        assert_eq!(
            ccfg::read_record(&held)
                .unwrap()
                .unwrap()
                .commitment
                .to_string(),
            old
        );
    }
    assert!(ack_schema(&data, &old, &new).status.success());
    let before = all_rows(&data);
    {
        let held = Database::open_default(&data).unwrap();
        let out = revert_schema(&data, &new, &old);
        assert!(!out.status.success(), "{}", text(&out));
        assert!(text(&out).contains("must be stopped"), "{}", text(&out));
        assert_eq!(
            ccfg::read_record(&held)
                .unwrap()
                .unwrap()
                .commitment
                .to_string(),
            new
        );
    }
    assert_eq!(all_rows(&data), before, "nothing written");
}

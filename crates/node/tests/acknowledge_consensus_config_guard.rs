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

/// The release before this binary: it read and wrote schema 1 and knew schema 2
/// only as a draft. Used to create the schema-1 database it would have left.
static PREVIOUS: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1],
    writes: &ccfg::SCHEMA_1,
    knows: &ccfg::SCHEMA_2,
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
        .expect("this binary offers schema 2");
    (dir, data, r.commitment.to_string(), pending.new.to_string())
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

/// The command moves a schema-1 database to schema 2 when told both
/// commitments exactly, keeps the old encoding in the history, and has nothing
/// left to do afterwards.
#[test]
fn the_schema_transition_moves_a_schema_1_database() {
    let (_dir, data, old, new) = schema_1_fixture();
    let out = ack_schema(&data, &old, &new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 1 -> 2"), "{}", text(&out));

    let db = Database::open_default(&data).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 2);
    assert_eq!(r.commitment.to_string(), new);
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, ccfg::TransitionKind::SchemaTransition);
    drop(db);

    let again = ack_schema(&data, &new, &new);
    assert!(!again.status.success(), "{}", text(&again));
    assert!(
        text(&again).contains("already recorded in schema 2"),
        "{}",
        text(&again)
    );
    let db = Database::open_default(&data).unwrap();
    assert_eq!(ccfg::read_transitions(&db).unwrap().len(), 1);
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

/// A database this binary created records schema 2 already: nothing to move.
#[test]
fn the_schema_transition_refuses_a_database_already_in_schema_2() {
    let f = fixture();
    let before = meta(&f.data);
    let out = ack_schema(&f.data, &f.old, &f.old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("already recorded in schema 2"),
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

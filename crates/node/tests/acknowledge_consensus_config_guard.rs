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

/// This binary records schema 1, so a schema-1 database has no schema to move
/// to: the schema transition refuses and writes nothing, whatever it is told.
#[test]
fn the_schema_transition_refuses_while_this_binary_records_schema_1() {
    let f = fixture();
    let before = {
        let db = Database::open_default(&f.data).unwrap();
        db.get(sumchain_storage::cf::META, ccfg::record::RECORD_KEY)
            .unwrap()
    };
    let out = ack_schema(&f.data, &f.old, &f.old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("already recorded in schema 1"),
        "{}",
        text(&out)
    );
    let db = Database::open_default(&f.data).unwrap();
    assert!(ccfg::read_transitions(&db).unwrap().is_empty());
    assert_eq!(
        db.get(sumchain_storage::cf::META, ccfg::record::RECORD_KEY)
            .unwrap(),
        before
    );
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

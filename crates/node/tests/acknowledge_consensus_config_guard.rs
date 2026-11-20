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
    knows: &ccfg::SCHEMA_5,
};

/// The release that wrote schema 2: it read schemas 1 and 2 and wrote 2.
static SCHEMA_2_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2],
    writes: &ccfg::SCHEMA_2,
    knows: &ccfg::SCHEMA_5,
};

/// The releases that wrote schema 3: they
/// read schemas 1, 2 and 3, wrote 3, and knew schema 4 only as a draft.
static SCHEMA_3_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2, &ccfg::SCHEMA_3],
    writes: &ccfg::SCHEMA_3,
    knows: &ccfg::SCHEMA_5,
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
        .expect("this binary offers schema 5");
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
        .expect("this binary offers schema 5");
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
        .expect("this binary offers schema 5");
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

/// The command moves a schema-1 database to schema 5 in one step when told
/// both commitments exactly, keeps the old encoding in the history, and has
/// nothing left to do afterwards.
#[test]
fn the_schema_transition_moves_a_schema_1_database() {
    let (_dir, data, old, new) = schema_1_fixture();
    let out = ack_schema(&data, &old, &new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 1 -> 5"), "{}", text(&out));

    let db = Database::open_default(&data).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 5);
    assert_eq!(r.commitment.to_string(), new);
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, ccfg::TransitionKind::SchemaTransition);
    drop(db);

    let again = ack_schema(&data, &new, &new);
    assert!(!again.status.success(), "{}", text(&again));
    assert!(
        text(&again).contains("already recorded in schema 5"),
        "{}",
        text(&again)
    );
    let db = Database::open_default(&data).unwrap();
    assert_eq!(ccfg::read_transitions(&db).unwrap().len(), 1);
}

/// A schema-2 database moves to schema 5 the same way, adding 0x1043, the
/// four schema-4 gates and the three schema-5 fields.
#[test]
fn the_schema_transition_moves_a_schema_2_database() {
    let (_dir, data, old, new) = schema_2_fixture();
    let out = ack_schema(&data, &old, &new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 2 -> 5"), "{}", text(&out));
    assert!(
        text(&out).contains("8 field(s) added absent"),
        "{}",
        text(&out)
    );
    let db = Database::open_default(&data).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 5);
    assert_eq!(r.commitment.to_string(), new);
}

/// A schema-3 database, as a schema-3 release records, moves to schema 5 the same
/// way, adding exactly the four schema-4 gates and the three schema-5 fields.
#[test]
fn the_schema_transition_moves_a_schema_3_database() {
    let (_dir, data, old, new) = schema_3_fixture();
    let out = ack_schema(&data, &old, &new);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("schema 3 -> 5"), "{}", text(&out));
    assert!(
        text(&out).contains("7 field(s) added absent"),
        "{}",
        text(&out)
    );
    let db = Database::open_default(&data).unwrap();
    let r = ccfg::read_record(&db).unwrap().unwrap();
    assert_eq!(r.config.schema().number, 5);
    assert_eq!(r.commitment.to_string(), new);
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, ccfg::TransitionKind::SchemaTransition);
    assert_eq!(
        history[0].changed_ids,
        vec![0x1044, 0x1045, 0x1046, 0x1047, 0x1048, 0x1049, 0x252b]
    );
    assert_eq!(history[0].old_commitment.to_string(), old);
}

/// `--show` prints both commitments exactly as the move takes them and writes
/// nothing; the operator's sequence — show, then move with what it printed —
/// lands on schema 5. On a database already in schema 5 it says there is
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

/// A database this binary created records schema 5 already: nothing to move.
#[test]
fn the_schema_transition_refuses_a_database_already_in_schema_5() {
    let f = fixture();
    let before = meta(&f.data);
    let out = ack_schema(&f.data, &f.old, &f.old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("already recorded in schema 5"),
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
    assert!(text(&done).contains("schema 5 -> 3"), "{}", text(&done));
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

// ── the start marker, through the real binary ───────────────────────────────

fn run_cmd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args(args)
        .output()
        .expect("running the node binary")
}

/// Every read-only command, run on a moved database, leaves every row of
/// every column family unchanged, writes no start marker, and leaves the
/// revert available; `revert --show` reports the marker as absent.
#[test]
fn read_only_commands_leave_a_moved_database_unchanged_and_the_revert_available() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    deployed_release_shaped(&data, &genesis(), 5);
    let (old, new) = {
        let db = Database::open_default(&data).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        (p.old.to_string(), p.new.to_string())
    };
    assert!(ack_schema(&data, &old, &new).status.success());
    let before = all_rows(&data);
    let d = data.to_str().unwrap();
    let export = dir.path().join("keys-export.json");
    let commands: Vec<Vec<&str>> = vec![
        vec!["--version"],
        vec![
            "acknowledge-consensus-config-schema",
            "--data-dir",
            d,
            "--show",
        ],
        vec!["revert-consensus-config-schema", "--data-dir", d, "--show"],
        vec!["check-finality-record", "--data-dir", d],
        vec!["inspect-v2-rows", "--data-dir", d],
        vec!["info", "--data-dir", d],
        vec![
            "export-registered-keys",
            "--data-dir",
            d,
            "--output",
            export.to_str().unwrap(),
        ],
    ];
    for args in &commands {
        let out = run_cmd(args);
        assert!(out.status.success(), "{args:?}: {}", text(&out));
        assert_eq!(all_rows(&data), before, "{args:?}: a row changed");
    }
    let show = run_cmd(&["revert-consensus-config-schema", "--data-dir", d, "--show"]);
    assert!(
        text(&show).contains("Start marker: none"),
        "{}",
        text(&show)
    );
    assert!(
        text(&show).contains("no normal start has been attempted"),
        "{}",
        text(&show)
    );
    assert_eq!(shown(&show, "--old").as_deref(), Some(new.as_str()));
    let done = revert_schema(&data, &new, &old);
    assert!(done.status.success(), "{}", text(&done));
}

/// Once a start marker exists at the move — what any normal start leaves
/// first — `--show` reports it and says no revert is available, and the revert
/// is refused with a non-zero exit and nothing written.
#[test]
fn the_revert_refuses_a_database_a_normal_start_was_attempted_on() {
    let (_dir, data, old, new) = schema_3_fixture();
    assert!(ack_schema(&data, &old, &new).status.success());
    {
        let db = Database::open_default(&data).unwrap();
        let m = ccfg::record_start(&db).unwrap();
        assert_eq!(m.attempt, 1);
    }
    let before = all_rows(&data);
    let d = data.to_str().unwrap();
    let show = run_cmd(&["revert-consensus-config-schema", "--data-dir", d, "--show"]);
    assert!(show.status.success(), "{}", text(&show));
    assert!(
        text(&show).contains("Start marker: attempt 1"),
        "{}",
        text(&show)
    );
    assert!(
        text(&show).contains("No pre-start revert is available: a normal start was attempted"),
        "{}",
        text(&show)
    );
    assert_eq!(shown(&show, "--old"), None);
    let out = revert_schema(&data, &new, &old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("a normal start was attempted"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("forward only"), "{}", text(&out));
    assert_eq!(all_rows(&data), before, "nothing written");
}

/// A directory shaped like a validator the deployed release ran: a schema-3
/// record, the activation record as that release writes it (this binary's
/// names minus the two it does not declare), the messaging backfill done, and
/// real blocks to `height` with their journals and finality record. No start
/// marker: that release writes none. Extends an existing directory's chain.
fn deployed_release_shaped(data: &Path, g: &Genesis, height: u64) {
    use sumchain_consensus::ConsensusEngine;
    use sumchain_storage::schema::BlockStore;
    let v = KeyPair::from_bytes([12u8; 32]);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let db = std::sync::Arc::new(Database::open_default(data).unwrap());
    if ccfg::read_record(&db).unwrap().is_none() {
        ccfg::record::check_at_startup_with(&db, g, 0, &SCHEMA_3_RELEASE).unwrap();
        let mut heights = g.params.recorded_activation_heights();
        heights.retain(|(n, _)| {
            n != "strict_transaction_signatures_enabled_from_height"
                && n != "staking_submit_evidence_unsupported_enabled_from_height"
        });
        db.put(
            sumchain_storage::cf::META,
            b"activation/heights",
            &bincode::serialize(&heights).unwrap(),
        )
        .unwrap();
        sumchain_storage::MessagingStore::new(&db)
            .backfill_indexes()
            .unwrap();
    }
    let state = std::sync::Arc::new(sumchain_state::StateManager::new(db.clone(), g.chain_id));
    let mempool = std::sync::Arc::new(sumchain_state::Mempool::new(
        sumchain_state::MempoolConfig::default(),
    ));
    let engine =
        sumchain_consensus::PoAEngine::new(db.clone(), state, mempool, g, Some(v)).unwrap();
    if BlockStore::new(&db).get_latest_height().unwrap().is_none() {
        engine.init_genesis(g).unwrap();
    } else {
        engine.load_chain().unwrap();
    }
    while BlockStore::new(&db)
        .get_latest_height()
        .unwrap()
        .unwrap_or(0)
        < height
    {
        rt.block_on(engine.propose_block(vec![])).unwrap();
    }
}

/// The move and the revert through the real binary on a directory shaped like
/// a validator the deployed release ran. The revert restores every row byte
/// for byte.
#[test]
fn the_revert_restores_every_row_of_a_deployed_release_shaped_directory() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let g = genesis();
    deployed_release_shaped(&data, &g, 5);
    let before = all_rows(&data);
    assert!(before
        .iter()
        .any(|(c, k, _)| c == sumchain_storage::cf::META && k == b"activation/heights"));
    let (old, new) = {
        let db = Database::open_default(&data).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        (p.old.to_string(), p.new.to_string())
    };
    let moved = ack_schema(&data, &old, &new);
    assert!(moved.status.success(), "{}", text(&moved));
    assert_ne!(all_rows(&data), before);
    let out = revert_schema(&data, &new, &old);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(all_rows(&data), before, "every row as before the move");
}

// ── rollback and restore keep the migration provenance ──────────────────────

fn rollback_cmd(data: &Path, to: u64) -> Output {
    run_cmd(&[
        "rollback",
        "--data-dir",
        data.to_str().unwrap(),
        "--to-height",
        &to.to_string(),
        "--max-blocks",
        "10",
        "--yes",
    ])
}

fn restore_cmd(backup: &Path, data: &Path, force: bool) -> Output {
    restore_cmd_with(backup, data, force, false)
}

fn restore_cmd_with(backup: &Path, data: &Path, force: bool, new_node: bool) -> Output {
    let mut args = vec![
        "restore",
        "--backup",
        backup.to_str().unwrap(),
        "--data-dir",
        data.to_str().unwrap(),
    ];
    if force {
        args.push("--force");
    }
    if new_node {
        args.push("--new-node");
    }
    run_cmd(&args)
}

/// A backup as `restore` consumes it: a complete copy of the stopped database
/// directory (`sumchain backup` itself fails on this head with "Directory
/// exists", a pre-existing defect outside this change: it creates the target
/// before RocksDB's checkpoint does; a file copy is what the restore reads).
fn backup_cmd(data: &Path, out: &Path) -> Output {
    Command::new("cp")
        .args(["-R", data.to_str().unwrap(), out.to_str().unwrap()])
        .output()
        .expect("copying the database")
}

/// A moved directory a node then started on and extended: the revert refuses.
/// `sumchain rollback` to the move's height succeeds, keeps the start marker
/// and the configuration rows byte for byte, and reports it; the revert still
/// refuses, naming the start. A rollback refused for its own reasons (a target
/// at the tip) changes nothing.
#[test]
fn rollback_keeps_the_start_marker_and_never_reopens_the_revert() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let g = genesis();
    deployed_release_shaped(&data, &g, 5);
    let (old, new) = {
        let db = Database::open_default(&data).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        (p.old.to_string(), p.new.to_string())
    };
    assert!(ack_schema(&data, &old, &new).status.success());
    {
        // What a normal start leaves first.
        let db = Database::open_default(&data).unwrap();
        ccfg::record_start(&db).unwrap();
    }
    deployed_release_shaped(&data, &g, 8);
    let provenance = |data: &Path| {
        let db = Database::open_default(data).unwrap();
        ccfg::migration_provenance(&db).unwrap()
    };
    let before = provenance(&data);
    assert!(before.marker.is_some());

    // Refused for its own reason: nothing changes.
    let rows = all_rows(&data);
    let out = rollback_cmd(&data, 8);
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(all_rows(&data), rows, "a refused rollback writes nothing");

    let out = rollback_cmd(&data, 5);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Unwound 3 block(s)"), "{}", text(&out));
    assert!(
        text(&out).contains("Migration provenance preserved: start marker attempt 1"),
        "{}",
        text(&out)
    );
    assert_eq!(
        provenance(&data),
        before,
        "the marker and the configuration rows, byte for byte"
    );
    {
        let db = Database::open_default(&data).unwrap();
        assert_eq!(
            sumchain_storage::schema::BlockStore::new(&db)
                .get_latest_height()
                .unwrap(),
            Some(5)
        );
    }
    let rows = all_rows(&data);
    let out = revert_schema(&data, &new, &old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("a normal start was attempted"),
        "{}",
        text(&out)
    );
    assert_eq!(all_rows(&data), rows, "the refused revert writes nothing");
}

/// A rollback refuses, writing nothing, when the migration provenance cannot
/// be established (an unreadable start marker) and while a schema move awaits
/// its first start or its revert.
#[test]
fn rollback_refuses_when_the_provenance_is_uncertain_or_a_revert_is_pending() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let g = genesis();
    deployed_release_shaped(&data, &g, 8);
    let (old, new) = {
        let db = Database::open_default(&data).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        (p.old.to_string(), p.new.to_string())
    };
    // The abort-3 state: moved at 8, no start.
    assert!(ack_schema(&data, &old, &new).status.success());
    let rows = all_rows(&data);
    let out = rollback_cmd(&data, 5);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("awaits its first start or its pre-start revert"),
        "{}",
        text(&out)
    );
    assert_eq!(all_rows(&data), rows, "nothing written");

    // An unreadable marker: the provenance cannot be established.
    {
        let db = Database::open_default(&data).unwrap();
        db.put(
            sumchain_storage::cf::META,
            ccfg::START_MARKER_KEY,
            b"garbage",
        )
        .unwrap();
    }
    let rows = all_rows(&data);
    let out = rollback_cmd(&data, 5);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("migration provenance cannot be established"),
        "{}",
        text(&out)
    );
    assert_eq!(all_rows(&data), rows, "nothing written");
}

/// `sumchain restore` keeps the protection. Over a database a node started on
/// after the move, a backup taken before the move is refused (it would clear
/// the start marker and change the record history), and so is one taken after
/// the move but before the start (it would clear the marker); the revert then
/// still refuses. A backup taken after the start restores, and a restore into
/// a missing directory restores. A backup whose provenance cannot be read is
/// refused. `--force` overwrites, it does not bypass. Into a missing target,
/// a backup without a start marker needs `--new-node`.
#[test]
fn restore_refuses_to_clear_the_start_marker_or_change_the_record_history() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let g = genesis();
    deployed_release_shaped(&data, &g, 5);
    let pre_move = dir.path().join("backup-pre-move");
    assert!(backup_cmd(&data, &pre_move).status.success());
    let (old, new) = {
        let db = Database::open_default(&data).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        (p.old.to_string(), p.new.to_string())
    };
    assert!(ack_schema(&data, &old, &new).status.success());
    let post_move = dir.path().join("backup-post-move");
    assert!(backup_cmd(&data, &post_move).status.success());
    {
        let db = Database::open_default(&data).unwrap();
        ccfg::record_start(&db).unwrap();
    }
    let post_start = dir.path().join("backup-post-start");
    assert!(backup_cmd(&data, &post_start).status.success());
    deployed_release_shaped(&data, &g, 7);
    let rows = all_rows(&data);

    // Without --force an existing target is refused as before.
    let out = restore_cmd(&pre_move, &data, false);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("already exists"), "{}", text(&out));
    assert_eq!(all_rows(&data), rows);

    for (what, backup, says) in [
        ("pre-move", &pre_move, "record or history differs"),
        (
            "post-move, pre-start",
            &post_move,
            "would clear the record that a normal start",
        ),
    ] {
        let out = restore_cmd(backup, &data, true);
        assert!(!out.status.success(), "{what}: {}", text(&out));
        assert!(
            text(&out).contains("refusing to restore"),
            "{what}: {}",
            text(&out)
        );
        assert!(text(&out).contains(says), "{what}: {}", text(&out));
        assert!(
            text(&out).contains("no force bypass"),
            "{what}: {}",
            text(&out)
        );
        assert_eq!(all_rows(&data), rows, "{what}: nothing changed");
    }
    let out = revert_schema(&data, &new, &old);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("a normal start was attempted"),
        "{}",
        text(&out)
    );

    // A backup whose provenance cannot be read: refused.
    let broken = dir.path().join("backup-broken");
    assert!(backup_cmd(&data, &broken).status.success());
    {
        let db = Database::open_default(&broken).unwrap();
        db.put(
            sumchain_storage::cf::META,
            ccfg::START_MARKER_KEY,
            b"garbage",
        )
        .unwrap();
    }
    let out = restore_cmd(&broken, &data, true);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("backup's migration provenance cannot be established"),
        "{}",
        text(&out)
    );
    assert_eq!(all_rows(&data), rows, "nothing changed");

    // A backup taken after the start: the same record history and a marker at
    // the same record state. It restores, and the revert still refuses.
    let expected = all_rows(&post_start);
    let out = restore_cmd(&post_start, &data, true);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Migration provenance preserved: start marker attempt 1"),
        "{}",
        text(&out)
    );
    assert_eq!(all_rows(&data), expected);
    let out = revert_schema(&data, &new, &old);
    assert!(!out.status.success(), "{}", text(&out));

    // A missing target and a backup that holds no start marker: refused
    // without --new-node, naming the flag, and nothing is created; with it,
    // restored. A backup that holds a marker restores without the flag. The
    // flag bypasses nothing on an existing target.
    let fresh = dir.path().join("fresh-target");
    let out = restore_cmd(&pre_move, &fresh, false);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("pass --new-node"), "{}", text(&out));
    assert!(
        text(&out).contains("Backup start marker:           none"),
        "{}",
        text(&out)
    );
    assert!(!fresh.exists(), "nothing created");
    let out = restore_cmd_with(&pre_move, &fresh, false, true);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Backup configuration schema:   3"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("start marker none"), "{}", text(&out));
    assert_eq!(all_rows(&fresh), all_rows(&pre_move));
    let fresh2 = dir.path().join("fresh-target-2");
    let out = restore_cmd(&post_start, &fresh2, false);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(all_rows(&fresh2), all_rows(&post_start));
    let rows = all_rows(&data);
    let out = restore_cmd_with(&pre_move, &data, true, true);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("no force bypass"), "{}", text(&out));
    assert_eq!(
        all_rows(&data),
        rows,
        "--new-node bypasses nothing on an existing target"
    );
}

/// A rollback refuses, writing nothing, when the configuration record itself
/// cannot be read: the provenance cannot be established.
#[test]
fn rollback_refuses_when_the_configuration_record_is_unreadable() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let g = genesis();
    deployed_release_shaped(&data, &g, 8);
    {
        let db = Database::open_default(&data).unwrap();
        let mut raw = db
            .get(sumchain_storage::cf::META, ccfg::record::RECORD_KEY)
            .unwrap()
            .unwrap();
        *raw.last_mut().unwrap() ^= 1;
        db.put(sumchain_storage::cf::META, ccfg::record::RECORD_KEY, &raw)
            .unwrap();
        assert!(
            ccfg::read_record(&db).is_err(),
            "the record is now unreadable"
        );
    }
    let rows = all_rows(&data);
    let out = rollback_cmd(&data, 5);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("migration provenance cannot be established"),
        "{}",
        text(&out)
    );
    assert_eq!(all_rows(&data), rows, "nothing written");
}

/// The rollback command's provenance checks, pinned in its source: the
/// provenance is read before the plan is made, the command refuses while a
/// pre-start revert is pending, and after the unwind's batch the provenance is
/// read again and compared. The last is a tripwire no correct rollback can
/// fire, so its presence is what this test checks.
#[test]
fn the_rollback_command_reads_the_provenance_before_and_after_its_batch() {
    let src = include_str!("../src/main.rs");
    let start = src
        .find("Commands::Rollback {")
        .expect("the rollback handler");
    let end = src[start..]
        .find("Commands::SetDiskBudget")
        .map(|i| start + i)
        .unwrap_or(src.len());
    let handler = &src[start..end];
    let at = |needle: &str| {
        handler
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not found in the rollback handler"))
    };
    let before = at("let provenance = ccfg::migration_provenance(&db)");
    let pending = at("ccfg::pending_schema_revert(&db).is_ok()");
    let plan = at("plan_rollback(&block_store, to_height, max_blocks");
    let execute = at("execute_rollback(&db, &state, &plan, &journals, journals.policy())");
    let after = at("let after = ccfg::migration_provenance(&db)");
    let compare = at("if after != provenance {");
    assert!(
        before < pending && pending < plan,
        "provenance and pending revert before the plan"
    );
    assert!(
        plan < execute && execute < after && after < compare,
        "re-read and compared after the batch"
    );
    assert!(handler[compare..].contains("the rollback changed the migration provenance"));
}

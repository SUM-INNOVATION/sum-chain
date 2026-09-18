//! OC-2, through the binary an operator actually runs.
//!
//! `sumchain import-registered-keys` writes `cf::MESSAGING_PUBLIC_KEYS`, a
//! family the executor READS: `SendMessage` requires the sender to hold a
//! registered key, and both the plain and the sponsored `RegisterPublicKey`
//! refuse a duplicate. A node that ran the import therefore accepts
//! transactions its peers refuse, the receipts differ, the receipts are folded
//! into the state root, and the roots differ — the previous halt's exact shape,
//! produced by an operator command with no consensus event to explain it.
//!
//! The library refusal is proven in
//! `sumchain-storage/tests/messaging_registry_seed.rs`. This file proves the
//! thing an operator can observe: that the COMMAND refuses, that it refuses
//! before it writes, that the supported shape still works, and that the marker
//! it records is still there in the next process.
//!
//! These tests drive the real binary through `CARGO_BIN_EXE_sumchain` rather
//! than a copy of its logic, because a guard that exists in a helper the binary
//! does not call is not a guard.

use std::path::Path;
use std::process::{Command, Output};

use sumchain_primitives::Address;
use sumchain_storage::db::cf;
use sumchain_storage::messaging_store::{registry_seed, MessagingStore};
use sumchain_storage::schema::BlockStore;
use sumchain_storage::Database;
use tempfile::TempDir;

/// An NDJSON line in the shape the command parses: the address must be the one
/// the public key derives to, which the command checks before anything else.
fn record_line(n: u8) -> String {
    let pubkey = [n; 32];
    let address = Address::from_public_key(&pubkey);
    format!(
        r#"{{"address":"{}","public_key":"{}","registered_at_block":0,"registered_at":1700000000,"updated_at_block":0}}"#,
        address.to_base58(),
        hex::encode(pubkey)
    )
}

fn write_input(dir: &Path, count: u8) -> std::path::PathBuf {
    let path = dir.join("keys.ndjson");
    let body: String = (1..=count)
        .map(|n| format!("{}\n", record_line(n)))
        .collect();
    std::fs::write(&path, body).unwrap();
    path
}

fn run_import(data_dir: &Path, input: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "import-registered-keys",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--yes",
        ])
        .output()
        .expect("running the node binary")
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The halt shape: an import into a node that has executed blocks.
///
/// It must fail, it must fail with a NON-ZERO exit status so a runbook or a
/// deployment script cannot walk past it, and it must leave the registry
/// exactly as it found it.
#[test]
fn the_command_refuses_on_a_database_that_has_executed_blocks() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("data");
    {
        let db = Database::open_default(&data).unwrap();
        BlockStore::new(&db).set_latest_height(42).unwrap();
    }
    let input = write_input(dir.path(), 2);

    let out = run_import(&data, &input);
    assert!(
        !out.status.success(),
        "an import above genesis must fail, not warn. Output:\n{}",
        combined(&out)
    );
    let text = combined(&out);
    assert!(
        text.contains("height 42"),
        "the refusal must name the height it refused at:\n{text}"
    );
    assert!(
        text.contains("resync"),
        "and name the only remedy there is:\n{text}"
    );

    let db = Database::open_default(&data).unwrap();
    assert_eq!(
        db.full_iter(cf::MESSAGING_PUBLIC_KEYS).unwrap().count(),
        0,
        "a refused import writes no registration"
    );
    assert_eq!(
        registry_seed(&db).unwrap(),
        None,
        "and records nothing about what it did not do"
    );
}

/// An import into a registry that already holds registrations is the same write
/// by another name, even on a database that never left genesis.
#[test]
fn the_command_refuses_a_registry_that_already_holds_registrations() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("data");
    {
        let db = Database::open_default(&data).unwrap();
        let pubkey = [200u8; 32];
        let address = Address::from_public_key(&pubkey);
        MessagingStore::new(&db)
            .set_public_key(
                &address,
                &sumchain_primitives::RegisteredPublicKey {
                    public_key: pubkey,
                    address,
                    registered_at_block: 0,
                    registered_at: 1,
                    updated_at_block: 0,
                },
            )
            .unwrap();
    }
    let input = write_input(dir.path(), 2);

    let out = run_import(&data, &input);
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("already holds"),
        "the refusal must say why:\n{}",
        combined(&out)
    );

    let db = Database::open_default(&data).unwrap();
    assert_eq!(
        db.full_iter(cf::MESSAGING_PUBLIC_KEYS).unwrap().count(),
        1,
        "the registration that was there is untouched"
    );
    assert_eq!(registry_seed(&db).unwrap(), None);
}

/// The supported shape still works, records a marker, prints the digest an
/// operator is told to compare — and the marker is still there in the NEXT
/// process, which is the only kind of record that is worth anything: the one
/// that outlives the terminal it was printed in.
#[test]
fn a_genesis_seed_succeeds_and_the_marker_outlives_the_process() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("data");
    let input = write_input(dir.path(), 3);

    let out = run_import(&data, &input);
    assert!(
        out.status.success(),
        "a genesis-height seed into an empty registry is the supported shape:\n{}",
        combined(&out)
    );

    // A separate process opens the database — the node, in production.
    let db = Database::open_default(&data).unwrap();
    let seed = registry_seed(&db)
        .unwrap()
        .expect("the seed must be recorded in the database, not only announced on stdout");
    assert_eq!(seed.key_count, 3);
    assert_eq!(seed.seeded_at_height, 0);
    assert_eq!(
        MessagingStore::new(&db).iter_all_pubkeys().unwrap().len(),
        3
    );
    assert!(
        combined(&out).contains(&seed.digest),
        "the command must print the digest an operator is told to compare:\n{}",
        combined(&out)
    );
    drop(db);

    // And a second run is refused, naming the seed already in place.
    let out = run_import(&data, &input);
    assert!(
        !out.status.success(),
        "a second seed must be refused:\n{}",
        combined(&out)
    );
    assert!(
        combined(&out).contains(&seed.digest),
        "and the refusal must name the seed this node already carries:\n{}",
        combined(&out)
    );
}

/// The `--skip-existing` merge flag is gone with the merge.
///
/// It only ever made sense for the mid-chain import: a registry that must be
/// empty has nothing to skip. Left in place it would read as an offer to merge
/// — the exact operation this change removed — so an invocation that passes it
/// fails loudly rather than quietly doing something else.
#[test]
fn the_merge_flag_is_gone() {
    let dir = TempDir::new().unwrap();
    let data = dir.path().join("data");
    let input = write_input(dir.path(), 1);

    let out = Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "import-registered-keys",
            "--data-dir",
            data.to_str().unwrap(),
            "--input",
            input.to_str().unwrap(),
            "--skip-existing",
            "--yes",
        ])
        .output()
        .expect("running the node binary");
    assert!(
        !out.status.success(),
        "--skip-existing must not be accepted:\n{}",
        combined(&out)
    );
}

/// The seed is reported at STARTUP, on every later start, not only in the
/// output of the command that applied it.
///
/// A record that only the operator who ran the import ever saw is the defect,
/// not the fix: the next person to start this node has no way to know that its
/// consensus-read registry did not come from its own execution. The RPC half of
/// this is proven behaviourally in
/// `sumchain-rpc/tests/operator_visible_activation_and_history.rs`; the startup
/// half is checked at source level here because `report_sync_capability` is
/// private to `Node` and the alternative is booting a node with a live P2P stack
/// and a consensus loop to read one log line.
#[test]
fn the_seed_is_reported_in_the_startup_capability_log() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/node.rs"))
        .expect("node.rs");
    let at = src
        .find("fn report_sync_capability(")
        .expect("Node::report_sync_capability");
    let body = &src[at..];
    let end = body.find("\n    fn ").unwrap_or(body.len());
    let body = &body[..end];

    assert!(
        body.contains("messaging_registry_seed"),
        "the startup capability report must read the messaging registry seed. \
         A node that was seeded and restarted has to still say so."
    );
    assert!(
        body.contains("warn!"),
        "and report it at WARN: a node whose consensus-read state did not come \
         from its own execution is not an informational fact."
    );
    assert!(
        body.contains("seed.digest"),
        "and must print the digest, which is the value compared across the \
         validator set. A count alone certifies two different registries as \
         matching."
    );
}

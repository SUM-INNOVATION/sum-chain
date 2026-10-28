//! The consensus-configuration baseline (#268) through the REAL boot sequence.
//!
//! `Node::with_rpc_config` is where the baseline is recorded and compared; these
//! tests construct real nodes on real directories, so construction succeeding or
//! failing is the gate's verdict, exactly as in `node_activation_boot_tests.rs`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;

use sumchain_consensus::consensus_config::{self as ccfg, record::RECORD_KEY, TransitionKind};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_storage::{cf, Database};

use super::Node;

fn validator() -> KeyPair {
    KeyPair::from_bytes([11u8; 32])
}

fn genesis() -> Genesis {
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    )
}

fn boot(dir: &Path, genesis: &Genesis) -> Result<(), String> {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    Node::with_rpc_config(
        dir.to_path_buf(),
        genesis.clone(),
        None,
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    )
    .map(drop)
    .map_err(|e| format!("{e:#}"))
}

fn record(dir: &Path) -> Option<ccfg::BaselineRecord> {
    let db = Database::open_default(dir).unwrap();
    ccfg::read_record(&db).unwrap()
}

#[test]
fn the_first_boot_records_a_baseline_and_the_next_boot_matches_it() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    let r = record(dir.path()).expect("recorded at first boot");
    assert_eq!(r.status, ccfg::BaselineStatus::UnverifiedLocalBaseline);
    assert_eq!(r.commitment, ccfg::build(&g).unwrap().commitment());
    assert_eq!(r.baseline_height, 0);
    boot(dir.path(), &g).unwrap();
    assert_eq!(record(dir.path()).unwrap(), r);
}

#[test]
fn a_boot_under_a_changed_rule_is_refused_with_the_field_named() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    let mut changed = g.clone();
    changed.params.max_metadata_bytes += 1;
    let err = boot(dir.path(), &changed).unwrap_err();
    assert!(err.contains("max_metadata_bytes"), "{err}");
    assert!(err.contains("acknowledge-consensus-config"), "{err}");
    // Still refused on the next attempt: nothing was rewritten.
    assert!(boot(dir.path(), &changed).is_err());
    assert!(boot(dir.path(), &g).is_ok());
}

#[test]
fn a_boot_that_reschedules_a_future_gate_records_the_transition() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    let mut later = g.clone();
    later.params.education_enabled_from_height = Some(1_000);
    boot(dir.path(), &later).unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let history = ccfg::read_transitions(&db).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].kind, TransitionKind::GateReschedule);
}

#[test]
fn a_boot_over_a_damaged_baseline_is_refused_and_does_not_recreate_it() {
    let dir = tempfile::TempDir::new().unwrap();
    let g = genesis();
    boot(dir.path(), &g).unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        let mut raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
        *raw.last_mut().unwrap() ^= 1;
        db.put(cf::META, RECORD_KEY, &raw).unwrap();
    }
    let damaged = {
        let db = Database::open_default(dir.path()).unwrap();
        db.get(cf::META, RECORD_KEY).unwrap()
    };
    let err = boot(dir.path(), &g).unwrap_err();
    assert!(
        err.contains("refusing to start rather than recreate it"),
        "{err}"
    );
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(db.get(cf::META, RECORD_KEY).unwrap(), damaged);
}

/// The baseline step sits after the activation-height check and before
/// anything that processes a block is built.
#[test]
fn the_baseline_runs_after_the_gate_check_and_before_consensus_exists() {
    let src = include_str!("../../src/node.rs");
    let production = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
    let at = |needle: &str| {
        production
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not found in node.rs"))
    };
    let gate = at("Self::check_activation_parameters(&db, &genesis, initial_height)?;");
    let baseline = at("Self::check_consensus_config(&db, &genesis, initial_height)?;");
    let mempool = at("Mempool::new(MempoolConfig {");
    let engine = at("ConsensusWrapper::new_poa(");
    assert!(gate < baseline, "the gate check must run first");
    assert!(
        baseline < mempool && baseline < engine,
        "nothing may process a block first"
    );
}

/// The release that recorded schema 1: it read and wrote schema 1 and knew
/// schema 2 only as a draft. Used to create the database it would have left.
/// It knows schema 3 only because this binary's genesis carries the schema-3
/// gate, which a policy must be able to name to build at all; unset, that gate
/// adds nothing to the schema-1 record this writes.
static PREVIOUS: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1],
    writes: &ccfg::SCHEMA_1,
    knows: &ccfg::SCHEMA_3,
};

/// #277's gate (schema-2 field 0x103f) through the real boot sequence:
///
/// * unset (every committed genesis), a fresh node records schema 3;
/// * set on a fresh directory, the node boots and commits the height;
/// * set as a future height on a directory this binary records, the boot is an
///   ordinary gate reschedule;
/// * set on a directory the previous release recorded (schema 1), the boot is
///   refused, naming the schema transition, and rewrites nothing; unset, that
///   directory boots unchanged; after the stopped-node transition the set
///   genesis boots as a reschedule.
#[test]
fn the_credential_schema_gate_through_the_boot_sequence() {
    const GATE: u16 = 0x103f;
    // A remediation gate needs the peer-declaration deadline at or below it.
    let set = |h| {
        let mut g = genesis();
        g.params.credential_schema_validation_enabled_from_height = Some(h);
        g.params.peer_protocol_declaration_required_from_height = Some(h);
        g
    };
    let peer_gate =
        ccfg::fields::gate_id("peer_protocol_declaration_required_from_height").unwrap();
    let g = genesis();
    assert_eq!(
        g.params.credential_schema_validation_enabled_from_height,
        None
    );

    // Unset, fresh: schema 3, the gate absent.
    let dir = tempfile::TempDir::new().unwrap();
    boot(dir.path(), &g).unwrap();
    let r = record(dir.path()).expect("recorded at first boot");
    assert_eq!(r.config.schema().number, 3);
    assert_eq!(r.config.get(GATE), Some(&ccfg::Value::Absent));
    assert_eq!(r.commitment, ccfg::build(&g).unwrap().commitment());

    // Set as a future height on this node's directory: a reschedule.
    boot(dir.path(), &set(1_000)).unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        let history = ccfg::read_transitions(&db).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].kind, TransitionKind::GateReschedule);
        let mut ids = history[0].changed_ids.clone();
        ids.sort();
        let mut expected = vec![GATE, peer_gate];
        expected.sort();
        assert_eq!(ids, expected);
    }

    // Set, fresh: committed from the first boot.
    let fresh = tempfile::TempDir::new().unwrap();
    boot(fresh.path(), &set(1_000)).unwrap();
    let r = record(fresh.path()).unwrap();
    assert_eq!(r.config.get(GATE), Some(&ccfg::Value::U64(1_000)));

    // A directory the previous release recorded.
    let old = tempfile::TempDir::new().unwrap();
    {
        let db = Database::open_default(old.path()).unwrap();
        ccfg::record::check_at_startup_with(&db, &g, 0, &PREVIOUS).unwrap();
    }
    let before = record(old.path()).unwrap();
    assert_eq!(before.config.schema().number, 1);
    let err = boot(old.path(), &set(1_000)).unwrap_err();
    assert!(
        err.contains("credential_schema_validation_enabled_from_height"),
        "{err}"
    );
    assert!(err.contains("acknowledge-consensus-config-schema"), "{err}");
    assert_eq!(record(old.path()).unwrap(), before, "nothing rewritten");
    boot(old.path(), &g).unwrap();
    assert_eq!(record(old.path()).unwrap(), before, "runs as it stands");

    {
        let db = Database::open_default(old.path()).unwrap();
        let pending = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        ccfg::acknowledge_schema_transition(&db, 0, pending.old, pending.new).unwrap();
    }
    boot(old.path(), &set(1_000)).unwrap();
    let r = record(old.path()).unwrap();
    assert_eq!(r.config.schema().number, 3);
    assert_eq!(r.config.get(GATE), Some(&ccfg::Value::U64(1_000)));
}

/// The activation heights this directory recorded at its last start.
fn activation_heights(dir: &Path) -> Vec<(String, Option<u64>)> {
    let db = Database::open_default(dir).unwrap();
    bincode::deserialize(&db.get(cf::META, b"activation/heights").unwrap().unwrap()).unwrap()
}

fn height_of(heights: &[(String, Option<u64>)], gate: &str) -> Option<u64> {
    heights
        .iter()
        .find(|(n, _)| n == gate)
        .and_then(|(_, h)| *h)
}

/// The node-registry `UpdateStatus` gate (schema-3 field 0x1043) through the
/// real boot sequence, on a directory the schema-1 release recorded:
///
/// * unset, this binary boots it unchanged, still schema 1;
/// * scheduled (with its peer-declaration deadline) before the move, the boot
///   is refused, naming the stopped-node command with both commitments, and
///   the configuration record is not rewritten. The activation-height check,
///   which runs first, has already recorded the new future heights; with the
///   genesis restored, the next boot accepts that as a future reschedule;
/// * after the move, the scheduled genesis boots as a future-gate reschedule
///   of exactly the gate and its deadline, and a fresh directory commits the
///   gate from its first boot.
#[test]
fn the_node_registry_gate_through_the_boot_sequence() {
    const GATE: u16 = 0x1043;
    const NAME: &str = "node_registry_update_status_unsupported_enabled_from_height";
    const PEER_NAME: &str = "peer_protocol_declaration_required_from_height";
    let peer_gate = ccfg::fields::gate_id(PEER_NAME).unwrap();
    let scheduled = |peer: u64, gate: u64| {
        let mut g = genesis();
        g.params.peer_protocol_declaration_required_from_height = Some(peer);
        g.params
            .node_registry_update_status_unsupported_enabled_from_height = Some(gate);
        g
    };
    let g = genesis();
    assert_eq!(
        g.params
            .node_registry_update_status_unsupported_enabled_from_height,
        None
    );

    let old = tempfile::TempDir::new().unwrap();
    {
        let db = Database::open_default(old.path()).unwrap();
        ccfg::record::check_at_startup_with(&db, &g, 0, &PREVIOUS).unwrap();
    }
    let before = record(old.path()).unwrap();
    assert_eq!(before.config.schema().number, 1);

    // Installing this binary changes nothing.
    boot(old.path(), &g).unwrap();
    assert_eq!(record(old.path()).unwrap(), before, "runs as it stands");

    // Scheduled before the move: refused, naming the exact command.
    let pending = {
        let db = Database::open_default(old.path()).unwrap();
        ccfg::pending_schema_transition(&db).unwrap().unwrap()
    };
    assert_eq!((pending.from_schema, pending.to_schema), (1, 3));
    let err = boot(old.path(), &scheduled(900, 1_000)).unwrap_err();
    assert!(err.contains(NAME), "{err}");
    assert!(
        err.contains(&format!(
            "acknowledge-consensus-config-schema --old {} --new {}",
            pending.old, pending.new
        )),
        "{err}"
    );
    assert_eq!(record(old.path()).unwrap(), before, "record not rewritten");
    let heights = activation_heights(old.path());
    assert_eq!(
        height_of(&heights, NAME),
        Some(1_000),
        "recorded by the earlier check"
    );
    assert_eq!(height_of(&heights, PEER_NAME), Some(900));

    // Genesis restored: a permitted future reschedule back to unset.
    boot(old.path(), &g).unwrap();
    assert_eq!(record(old.path()).unwrap(), before);
    assert_eq!(height_of(&activation_heights(old.path()), NAME), None);

    // The stopped-node move, then the scheduled genesis.
    {
        let db = Database::open_default(old.path()).unwrap();
        ccfg::acknowledge_schema_transition(&db, 0, pending.old, pending.new).unwrap();
    }
    boot(old.path(), &g).unwrap();
    assert_eq!(
        record(old.path()).unwrap().commitment,
        pending.new,
        "moved, unchanged"
    );
    boot(old.path(), &scheduled(900, 1_000)).unwrap();
    let r = record(old.path()).unwrap();
    assert_eq!(r.config.schema().number, 3);
    assert_eq!(r.config.get(GATE), Some(&ccfg::Value::U64(1_000)));
    {
        let db = Database::open_default(old.path()).unwrap();
        let history = ccfg::read_transitions(&db).unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.kind, TransitionKind::GateReschedule);
        let mut ids = last.changed_ids.clone();
        ids.sort();
        let mut expected = vec![GATE, peer_gate];
        expected.sort();
        assert_eq!(ids, expected);
    }

    // Fresh: committed from the first boot.
    let fresh = tempfile::TempDir::new().unwrap();
    boot(fresh.path(), &scheduled(900, 1_000)).unwrap();
    let r = record(fresh.path()).unwrap();
    assert_eq!(r.config.schema().number, 3);
    assert_eq!(r.config.get(GATE), Some(&ccfg::Value::U64(1_000)));
}

// ── an older binary's activation record after the move ──────────────────────

const H_NAME: &str = "node_registry_update_status_unsupported_enabled_from_height";
const P_NAME: &str = "peer_protocol_declaration_required_from_height";

/// Activation names a binary released before them does not declare. Such a
/// binary, started by mistake on a moved node, is refused by the schema-3
/// configuration record, but its activation-height check runs first and
/// rewrites the activation record with only the names it knows.
const NAMES_AN_OLDER_BINARY_LACKS: &[&str] = &[
    H_NAME,
    "messaging_timestamp_units_enabled_from_height",
    "contract_metering_enabled_from_height",
];

/// [`genesis`] with the peer-declaration deadline at `peer` and, when given,
/// the node-registry gate at `gate`.
fn gated(peer: u64, gate: Option<u64>) -> Genesis {
    let mut g = genesis();
    g.params.peer_protocol_declaration_required_from_height = Some(peer);
    g.params
        .node_registry_update_status_unsupported_enabled_from_height = gate;
    g
}

fn write_activation_heights(dir: &Path, heights: &[(String, Option<u64>)]) {
    let db = Database::open_default(dir).unwrap();
    db.put(
        cf::META,
        b"activation/heights",
        &bincode::serialize(heights).unwrap(),
    )
    .unwrap();
}

/// What a start of the older binary leaves in the activation record: the
/// recorded heights of the names it knows, none of the names it does not.
fn as_an_older_binary_records(dir: &Path) {
    let mut heights = activation_heights(dir);
    heights.retain(|(n, _)| !NAMES_AN_OLDER_BINARY_LACKS.contains(&n.as_str()));
    write_activation_heights(dir, &heights);
}

/// Empty blocks on `dir`, published as [`genesis`]'s one validator, up to
/// `height`.
async fn extend_to(dir: &Path, g: &Genesis, height: u64) {
    use sumchain_consensus::ConsensusEngine;
    use sumchain_storage::schema::BlockStore;
    let db = std::sync::Arc::new(Database::open_default(dir).unwrap());
    let state = std::sync::Arc::new(sumchain_state::StateManager::new(db.clone(), g.chain_id));
    let mempool = std::sync::Arc::new(sumchain_state::Mempool::new(
        sumchain_state::MempoolConfig::default(),
    ));
    let engine = sumchain_consensus::PoAEngine::new(
        db.clone(),
        state.clone(),
        mempool.clone(),
        g,
        Some(validator()),
    )
    .unwrap();
    if BlockStore::new(&db).get_latest_height().unwrap().is_none() {
        engine.init_genesis(g).unwrap();
    }
    while BlockStore::new(&db)
        .get_latest_height()
        .unwrap()
        .unwrap_or(0)
        < height
    {
        engine.propose_block(vec![]).await.unwrap();
    }
    drop(engine);
    drop(mempool);
    drop(state);
    drop(db);
}

/// A directory the schema-1 release recorded, booted by this binary, moved to
/// schema 3, booted under `scheduled` at height 0, then extended to `height`.
async fn moved_and_extended(scheduled: &Genesis, height: u64) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        ccfg::record::check_at_startup_with(&db, &genesis(), 0, &PREVIOUS).unwrap();
    }
    boot(dir.path(), &genesis()).unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        ccfg::acknowledge_schema_transition(&db, 0, p.old, p.new).unwrap();
    }
    boot(dir.path(), scheduled).unwrap();
    extend_to(dir.path(), scheduled, height).await;
    dir
}

fn refused_as_already_passed(err: &str) {
    assert!(err.contains("already passed"), "{err}");
    assert!(err.contains(H_NAME), "{err}");
}

/// (a) A moved node whose gate has passed, after an older binary dropped the
/// gate's name from the activation record: the verified schema-3
/// configuration record holds the same height, so this binary starts and
/// restores the full activation record.
#[tokio::test]
async fn a_dropped_gate_name_is_restored_from_the_verified_configuration() {
    let g = gated(2, Some(3));
    let dir = moved_and_extended(&g, 5).await;
    as_an_older_binary_records(dir.path());
    assert_eq!(height_of(&activation_heights(dir.path()), H_NAME), None);
    assert!(!activation_heights(dir.path())
        .iter()
        .any(|(n, _)| n == H_NAME));

    boot(dir.path(), &g).unwrap();
    assert_eq!(
        activation_heights(dir.path()),
        g.params.recorded_activation_heights(),
        "the full activation record is back"
    );
    assert_eq!(height_of(&activation_heights(dir.path()), H_NAME), Some(3));
    let r = record(dir.path()).unwrap();
    assert_eq!(r.config.get(0x1043), Some(&ccfg::Value::U64(3)));
    boot(dir.path(), &g).unwrap();
}

/// (b) The name is missing, but the configuration record holds a different
/// height, or none: refused exactly as before, nothing rewritten.
#[tokio::test]
async fn a_dropped_gate_name_is_not_restored_against_a_different_or_absent_height() {
    for scheduled in [gated(2, Some(4)), gated(2, None)] {
        let dir = moved_and_extended(&scheduled, 5).await;
        as_an_older_binary_records(dir.path());
        let before = activation_heights(dir.path());
        let err = boot(dir.path(), &gated(2, Some(3))).unwrap_err();
        refused_as_already_passed(&err);
        assert_eq!(activation_heights(dir.path()), before, "nothing rewritten");
    }
}

/// (c) The name is present with no height: not an older binary's omission, and
/// refused exactly as before even though the configuration holds the height.
#[tokio::test]
async fn a_gate_recorded_as_unset_is_not_restored() {
    let g = gated(2, Some(3));
    let dir = moved_and_extended(&g, 5).await;
    let mut heights = activation_heights(dir.path());
    for (n, h) in heights.iter_mut() {
        if n == H_NAME {
            *h = None;
        }
    }
    write_activation_heights(dir.path(), &heights);
    let err = boot(dir.path(), &g).unwrap_err();
    refused_as_already_passed(&err);
    assert_eq!(activation_heights(dir.path()), heights, "nothing rewritten");
}

/// (d) A node never moved: its schema-1 record cannot hold the gate, so a
/// missing name with a passed height is refused exactly as before.
#[tokio::test]
async fn without_a_schema_3_record_a_dropped_gate_name_is_not_restored() {
    let dir = tempfile::TempDir::new().unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        ccfg::record::check_at_startup_with(&db, &genesis(), 0, &PREVIOUS).unwrap();
    }
    let peer_only = gated(2, None);
    boot(dir.path(), &peer_only).unwrap();
    assert_eq!(record(dir.path()).unwrap().config.schema().number, 1);
    extend_to(dir.path(), &peer_only, 5).await;
    as_an_older_binary_records(dir.path());
    assert_eq!(height_of(&activation_heights(dir.path()), P_NAME), Some(2));
    let before = activation_heights(dir.path());
    let err = boot(dir.path(), &gated(2, Some(3))).unwrap_err();
    refused_as_already_passed(&err);
    assert_eq!(activation_heights(dir.path()), before, "nothing rewritten");
    assert_eq!(record(dir.path()).unwrap().config.schema().number, 1);
}

/// (e) The name is missing and the configuration record would hold the height,
/// but the record does not verify: nothing is restored from it, and the start
/// is refused exactly as before.
#[tokio::test]
async fn a_dropped_gate_name_is_not_restored_from_an_unverifiable_record() {
    let g = gated(2, Some(3));
    let dir = moved_and_extended(&g, 5).await;
    as_an_older_binary_records(dir.path());
    {
        let db = Database::open_default(dir.path()).unwrap();
        let mut raw = db.get(cf::META, RECORD_KEY).unwrap().unwrap();
        *raw.last_mut().unwrap() ^= 1;
        db.put(cf::META, RECORD_KEY, &raw).unwrap();
    }
    let before = activation_heights(dir.path());
    let err = boot(dir.path(), &g).unwrap_err();
    refused_as_already_passed(&err);
    assert_eq!(activation_heights(dir.path()), before, "nothing rewritten");
}

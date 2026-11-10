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
    boot_node(dir, genesis).map(drop)
}

/// The real boot sequence, keeping the node: for tests that then drive its
/// consensus engine as a running node would.
fn boot_node(dir: &Path, genesis: &Genesis) -> Result<Node, String> {
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
    knows: &ccfg::SCHEMA_4,
};

/// #277's gate (schema-2 field 0x103f) through the real boot sequence:
///
/// * unset (every committed genesis), a fresh node records schema 4;
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

    // Unset, fresh: schema 4, the gate absent.
    let dir = tempfile::TempDir::new().unwrap();
    boot(dir.path(), &g).unwrap();
    let r = record(dir.path()).expect("recorded at first boot");
    assert_eq!(r.config.schema().number, 4);
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
    assert_eq!(r.config.schema().number, 4);
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
    assert_eq!((pending.from_schema, pending.to_schema), (1, 4));
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
    assert_eq!(r.config.schema().number, 4);
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
    assert_eq!(r.config.schema().number, 4);
    assert_eq!(r.config.get(GATE), Some(&ccfg::Value::U64(1_000)));
}

// ── an older binary's activation record after the move ──────────────────────

const H_NAME: &str = "node_registry_update_status_unsupported_enabled_from_height";
const P_NAME: &str = "peer_protocol_declaration_required_from_height";

/// Activation names a binary released before them does not declare. Such a
/// binary, started by mistake on a moved node, is refused by the moved
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
/// `height`, from genesis or from the chain `dir` already holds.
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
    } else {
        engine.load_chain().unwrap();
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
/// schema 4, booted under `scheduled` at height 0, then extended to `height`.
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
/// gate's name from the activation record: the verified moved
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

// ── schema 4 through the boot sequence ──────────────────────────────────────

/// The releases that wrote schema 3, the deployed one among them: they read
/// schemas 1, 2 and 3, wrote 3, and knew schema 4 only as a draft.
static SCHEMA_3_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2, &ccfg::SCHEMA_3],
    writes: &ccfg::SCHEMA_3,
    knows: &ccfg::SCHEMA_4,
};

/// The four schema-4 gates, with a setter for each.
type SetGate = fn(&mut ChainParams, Option<u64>);
const SCHEMA_4_GATES: [(u16, &str, SetGate); 4] = [
    (
        0x1044,
        "archive_unbonding_own_challenges_enabled_from_height",
        |p, h| p.archive_unbonding_own_challenges_enabled_from_height = h,
    ),
    (
        0x1045,
        "por_attested_targets_enabled_from_height",
        |p, h| p.por_attested_targets_enabled_from_height = h,
    ),
    (
        0x1046,
        "strict_transaction_signatures_enabled_from_height",
        |p, h| p.strict_transaction_signatures_enabled_from_height = h,
    ),
    (
        0x1047,
        "staking_submit_evidence_unsupported_enabled_from_height",
        |p, h| p.staking_submit_evidence_unsupported_enabled_from_height = h,
    ),
];

/// The gate names the deployed schema-3 release does not declare: started by
/// mistake on a moved node, it rewrites the activation record without them.
const NAMES_THE_SCHEMA_3_RELEASE_LACKS: &[&str] = &[
    "strict_transaction_signatures_enabled_from_height",
    "staking_submit_evidence_unsupported_enabled_from_height",
];

/// A directory the schema-3 release recorded at height 0.
fn schema_3_directory(g: &Genesis) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    ccfg::record::check_at_startup_with(&db, g, 0, &SCHEMA_3_RELEASE).unwrap();
    dir
}

/// Each schema-4 gate through the real boot sequence, on a directory the
/// deployed schema-3 release recorded:
///
/// * unset, this binary boots it unchanged, still schema 3;
/// * set (with its peer-declaration deadline) before the move, the boot is
///   refused, naming the stopped-node command with both commitments, and the
///   configuration record is not rewritten; with the genesis restored, the
///   next boot accepts that as a future reschedule;
/// * after the move, the set genesis boots as a future-gate reschedule of
///   exactly the gate and its deadline, and a fresh directory commits the gate
///   from its first boot, in schema 4.
#[test]
fn the_schema_4_gates_through_the_boot_sequence() {
    let peer_gate =
        ccfg::fields::gate_id("peer_protocol_declaration_required_from_height").unwrap();
    let g = genesis();
    for (id, name, set_gate) in SCHEMA_4_GATES {
        let scheduled = {
            let mut s = genesis();
            s.params.peer_protocol_declaration_required_from_height = Some(900);
            set_gate(&mut s.params, Some(1_000));
            s
        };
        let dir = schema_3_directory(&g);
        let before = record(dir.path()).unwrap();
        assert_eq!(before.config.schema().number, 3);

        boot(dir.path(), &g).unwrap();
        assert_eq!(
            record(dir.path()).unwrap(),
            before,
            "{name}: runs as it stands"
        );

        let pending = {
            let db = Database::open_default(dir.path()).unwrap();
            ccfg::pending_schema_transition(&db).unwrap().unwrap()
        };
        assert_eq!((pending.from_schema, pending.to_schema), (3, 4));
        let err = boot(dir.path(), &scheduled).unwrap_err();
        assert!(err.contains(name), "{err}");
        assert!(
            err.contains(&format!(
                "acknowledge-consensus-config-schema --old {} --new {}",
                pending.old, pending.new
            )),
            "{err}"
        );
        assert_eq!(record(dir.path()).unwrap(), before, "{name}: not rewritten");
        assert_eq!(
            height_of(&activation_heights(dir.path()), name),
            Some(1_000)
        );

        boot(dir.path(), &g).unwrap();
        assert_eq!(record(dir.path()).unwrap(), before);
        assert_eq!(height_of(&activation_heights(dir.path()), name), None);

        {
            let db = Database::open_default(dir.path()).unwrap();
            ccfg::acknowledge_schema_transition(&db, 0, pending.old, pending.new).unwrap();
        }
        boot(dir.path(), &g).unwrap();
        assert_eq!(record(dir.path()).unwrap().commitment, pending.new);
        boot(dir.path(), &scheduled).unwrap();
        let r = record(dir.path()).unwrap();
        assert_eq!(r.config.schema().number, 4);
        assert_eq!(r.config.get(id), Some(&ccfg::Value::U64(1_000)), "{name}");
        {
            let db = Database::open_default(dir.path()).unwrap();
            let last = ccfg::read_transitions(&db).unwrap().pop().unwrap();
            assert_eq!(last.kind, TransitionKind::GateReschedule);
            let mut ids = last.changed_ids.clone();
            ids.sort();
            let mut expected = vec![id, peer_gate];
            expected.sort();
            assert_eq!(ids, expected, "{name}");
        }

        let fresh = tempfile::TempDir::new().unwrap();
        boot(fresh.path(), &scheduled).unwrap();
        let r = record(fresh.path()).unwrap();
        assert_eq!(r.config.schema().number, 4);
        assert_eq!(r.config.get(id), Some(&ccfg::Value::U64(1_000)), "{name}");
    }
}

type Rows = Vec<(String, Vec<u8>, Vec<u8>)>;

/// Every row of every column family.
fn all_rows(dir: &Path) -> Rows {
    let db = Database::open_default(dir).unwrap();
    let mut out = Vec::new();
    for name in sumchain_storage::db::ALL_CFS {
        for (k, v) in db.iter(name).unwrap() {
            out.push((name.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out
}

/// The rows that differ between two row sets, by key.
fn changed_keys(a: &Rows, b: &Rows) -> Vec<(String, Vec<u8>)> {
    let index = |r: &Rows| -> std::collections::BTreeMap<(String, Vec<u8>), Vec<u8>> {
        r.iter()
            .map(|(c, k, v)| ((c.clone(), k.clone()), v.clone()))
            .collect()
    };
    let (a, b) = (index(a), index(b));
    a.keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn head_of(dir: &Path) -> (u64, sumchain_primitives::Hash) {
    let db = Database::open_default(dir).unwrap();
    let b = sumchain_storage::schema::BlockStore::new(&db);
    (
        b.get_latest_height().unwrap().unwrap(),
        b.get_latest_hash().unwrap().unwrap(),
    )
}

/// The move, at the directory's head.
fn move_at_head(dir: &Path) -> ccfg::SchemaTransitioned {
    let db = Database::open_default(dir).unwrap();
    let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
    let h = sumchain_storage::schema::BlockStore::new(&db)
        .get_latest_height()
        .unwrap()
        .unwrap();
    ccfg::acknowledge_schema_transition(&db, h, p.old, p.new).unwrap()
}

fn revert(
    dir: &Path,
    moved: &ccfg::SchemaTransitioned,
) -> Result<ccfg::SchemaReverted, ccfg::ConfigError> {
    let db = Database::open_default(dir).unwrap();
    ccfg::revert_schema_transition(&db, moved.to, moved.from)
}

fn marker_of(dir: &Path) -> Option<ccfg::StartMarker> {
    let db = Database::open_default(dir).unwrap();
    ccfg::read_start_marker(&db).unwrap()
}

/// The activation record exactly as the deployed schema-3 release writes it:
/// this binary's names minus the two it does not declare.
fn as_the_schema_3_release_records(dir: &Path) {
    let mut heights = activation_heights(dir);
    heights.retain(|(n, _)| !NAMES_THE_SCHEMA_3_RELEASE_LACKS.contains(&n.as_str()));
    write_activation_heights(dir, &heights);
}

/// A production-shaped directory the deployed release ran: a schema-3 record,
/// the activation record as that release writes it, the messaging backfill
/// done, real blocks to `height` with their journals and finality record. No
/// start marker: the deployed release writes none.
async fn deployed_release_directory(g: &Genesis, height: u64) -> tempfile::TempDir {
    let dir = schema_3_directory(g);
    // This binary's boot writes the activation record and runs the backfill;
    // trim the record to the deployed release's names and remove the marker,
    // which that release does not write.
    boot(dir.path(), g).unwrap();
    as_the_schema_3_release_records(dir.path());
    {
        let db = Database::open_default(dir.path()).unwrap();
        db.delete(cf::META, ccfg::START_MARKER_KEY).unwrap();
    }
    extend_to(dir.path(), g, height).await;
    assert_eq!(marker_of(dir.path()), None);
    dir
}

/// The abort-3 state: a deployed-release directory moved at its head, with no
/// start since. Returns the directory, the move, and the rows before the move.
async fn moved_directory(
    g: &Genesis,
    height: u64,
) -> (tempfile::TempDir, ccfg::SchemaTransitioned, Rows) {
    let dir = deployed_release_directory(g, height).await;
    let before = all_rows(dir.path());
    let moved = move_at_head(dir.path());
    assert_eq!(head_of(dir.path()).0, height);
    (dir, moved, before)
}

/// Before any start, the revert restores every row of a production-shaped
/// directory: the activation record as the deployed release wrote it, the
/// messaging backfill, real blocks to 5 with journals and the finality record.
/// Byte equality over every column family, so a revert that touched any other
/// row (the activation record, say) would fail here. The schema-3 release then
/// starts on it at the same head.
#[tokio::test]
async fn before_any_start_the_revert_restores_every_row_of_a_deployed_release_directory() {
    let g = genesis();
    let (dir, moved, before) = moved_directory(&g, 5).await;
    let at = head_of(dir.path());
    assert!(before
        .iter()
        .any(|(c, k, _)| c == cf::META && k == b"activation/heights"));
    assert!(before.iter().any(|(c, _, _)| c == cf::APPLICATION_JOURNAL));
    {
        let db = Database::open_default(dir.path()).unwrap();
        let p = ccfg::pending_schema_revert(&db).unwrap();
        assert_eq!((p.at_height, p.start_marker), (5, None));
        assert_eq!(p.head_hash, Some(at.1));
    }
    let done = revert(dir.path(), &moved).unwrap();
    assert_eq!(done.at_height, 5);
    assert_eq!(all_rows(dir.path()), before, "every row as before the move");
    assert_eq!(head_of(dir.path()), at, "the same agreed height and head");
    let db = Database::open_default(dir.path()).unwrap();
    assert!(matches!(
        ccfg::record::check_at_startup_with(&db, &g, 5, &SCHEMA_3_RELEASE).unwrap(),
        ccfg::StartupOutcome::Unchanged { .. }
    ));
}

/// A normal start that imports no block closes the abort window: the revert
/// is refused and writes nothing. The start did rewrite local rows (the
/// activation record now carries this binary's names), so a revert here would
/// not have been byte-exact: that is why the marker, not the chain position,
/// decides.
#[tokio::test]
async fn a_zero_block_start_closes_the_abort_window() {
    let g = genesis();
    let (dir, moved, before) = moved_directory(&g, 5).await;
    boot(dir.path(), &g).unwrap();
    let m = marker_of(dir.path()).expect("the start wrote its marker");
    assert_eq!(m.attempt, 1);
    assert_eq!(
        m.record,
        ccfg::RecordState::Present {
            transition_count: moved.seq,
            commitment: moved.to
        }
    );
    assert_eq!(m.head, Some(head_of(dir.path())));
    let after_start = all_rows(dir.path());
    let changed = changed_keys(&before, &after_start);
    assert!(changed.contains(&(cf::META.to_string(), b"activation/heights".to_vec())));
    assert_eq!(head_of(dir.path()).0, 5, "no block was imported");

    let err = revert(dir.path(), &moved).unwrap_err();
    assert!(matches!(err, ccfg::ConfigError::Refused(_)), "{err}");
    assert!(
        err.to_string()
            .contains("a normal start was attempted on the moved record"),
        "{err}"
    );
    assert!(err.to_string().contains("forward only"), "{err}");
    assert_eq!(
        all_rows(dir.path()),
        after_start,
        "the refusal wrote nothing"
    );
    // This binary still boots on it.
    boot(dir.path(), &g).unwrap();
    assert_eq!(marker_of(dir.path()).unwrap().attempt, 2);
}

/// A start refused by a later check still closes the abort window, because
/// the marker is written first. A start refused before the database is opened
/// writes nothing and leaves the revert available.
#[tokio::test]
async fn a_failed_start_closes_the_abort_window_unless_it_failed_before_the_open() {
    let g = genesis();

    // Refused by the configuration check: a genesis that changes a rule.
    let (dir, moved, _before) = moved_directory(&g, 5).await;
    let mut other = g.clone();
    other.params.max_contract_gas += 1;
    let err = boot(dir.path(), &other).unwrap_err();
    assert!(err.contains("acknowledge-consensus-config"), "{err}");
    let m = marker_of(dir.path()).expect("the refused start wrote its marker first");
    assert_eq!(m.attempt, 1);
    let rows = all_rows(dir.path());
    let err = revert(dir.path(), &moved).unwrap_err();
    assert!(
        err.to_string().contains("a normal start was attempted"),
        "{err}"
    );
    assert_eq!(all_rows(dir.path()), rows, "nothing written");

    // Refused by the activation-height check, which rewrites the activation
    // record before it refuses: still closed, and the marker says so.
    let (dir, moved, _before) = moved_directory(&g, 5).await;
    let mut passed = g.clone();
    passed.params.peer_protocol_declaration_required_from_height = Some(1);
    passed
        .params
        .strict_transaction_signatures_enabled_from_height = Some(2);
    let err = boot(dir.path(), &passed).unwrap_err();
    assert!(err.contains("already passed"), "{err}");
    assert!(marker_of(dir.path()).is_some());
    let err = revert(dir.path(), &moved).unwrap_err();
    assert!(
        err.to_string().contains("a normal start was attempted"),
        "{err}"
    );

    // Refused before the open (an empty validator set is refused by
    // `check_protocol_v1`, before the data directory or database is touched):
    // no marker, no row changed, the revert still available.
    let (dir, moved, _before) = moved_directory(&g, 5).await;
    let rows = all_rows(dir.path());
    let mut empty = g.clone();
    empty.validators.clear();
    let err = boot(dir.path(), &empty).unwrap_err();
    assert!(!err.contains("start marker"), "{err}");
    assert_eq!(marker_of(dir.path()), None);
    assert_eq!(all_rows(dir.path()), rows, "nothing written");
    revert(dir.path(), &moved).unwrap();
}

/// If the marker cannot be committed, the start refuses at once and nothing
/// else is written: the database is exactly the moved database, and the
/// revert stays available (the pair-wide rule still goes forward, because
/// a start was issued).
#[tokio::test]
async fn a_failed_marker_write_refuses_the_start_and_writes_nothing_else() {
    use sumchain_consensus::branch_switch::failpoints::{arm, Failpoint};
    let g = genesis();
    let (dir, moved, _before) = moved_directory(&g, 5).await;
    let rows = all_rows(dir.path());
    arm(Some(Failpoint::StartMarkerCommitFails));
    let err = boot(dir.path(), &g).unwrap_err();
    arm(None);
    assert!(err.contains("the start marker was not recorded"), "{err}");
    assert!(err.contains("nothing else was written"), "{err}");
    assert_eq!(marker_of(dir.path()), None);
    assert_eq!(all_rows(dir.path()), rows, "exactly the moved database");
    let done = revert(dir.path(), &moved).unwrap();
    assert_eq!(done.at_height, 5);
}

/// An ambiguous outcome — the marker's commit was reported as failed but the
/// row was persisted — reads as a start: the marker's presence alone decides,
/// and the revert refuses.
#[tokio::test]
async fn a_persisted_marker_whose_commit_was_reported_failed_still_closes_the_window() {
    let g = genesis();
    let (dir, moved, _before) = moved_directory(&g, 5).await;
    {
        // Exactly what such a start leaves behind: the marker, and nothing else.
        let db = Database::open_default(dir.path()).unwrap();
        ccfg::record_start(&db).unwrap();
    }
    let rows = all_rows(dir.path());
    let err = revert(dir.path(), &moved).unwrap_err();
    assert!(
        err.to_string().contains("a normal start was attempted"),
        "{err}"
    );
    assert_eq!(all_rows(dir.path()), rows);
}

/// A rewind does not reopen the revert. A started node accepts blocks above
/// the move; the revert refuses. `sumchain rollback` to the move's height, run
/// exactly as the command runs it, unwinds those blocks and leaves the marker:
/// the revert still refuses, now naming the start, and writes nothing.
#[tokio::test]
async fn a_rollback_to_the_move_height_after_a_start_does_not_reopen_the_revert() {
    use sumchain_consensus::reorg::{
        execute_rollback, plan_rollback, refuse_rollback_across_certified,
    };
    use sumchain_state::reorg_undo::ActivatedJournal;
    use sumchain_state::StateManager;
    use sumchain_storage::journal::ActivationSource;
    use sumchain_storage::schema::BlockStore;
    use sumchain_storage::subsystem_journal::SubsystemGates;

    let g = genesis();
    let (dir, moved, _before) = moved_directory(&g, 5).await;
    boot(dir.path(), &g).unwrap();
    extend_to(dir.path(), &g, 8).await;
    // Refused already, and by the marker: it is read before the chain position.
    let err = revert(dir.path(), &moved).unwrap_err();
    assert!(
        err.to_string().contains("a normal start was attempted"),
        "{err}"
    );

    {
        let db = std::sync::Arc::new(Database::open_default(dir.path()).unwrap());
        let journals = ActivatedJournal::resolve(
            &db,
            ActivationSource::from_configured_height(
                g.params.application_journal_enabled_from_height,
            ),
            SubsystemGates {
                compute_pool: g.params.compute_pool_enabled_from_height,
                beacon: g.params.beacon_enabled_from_height,
            },
        )
        .unwrap();
        let store = BlockStore::new(&db);
        let plan = plan_rollback(&store, 5, 10, &journals.activation()).unwrap();
        refuse_rollback_across_certified(&db, &plan).unwrap();
        let state = StateManager::new(db.clone(), 0);
        let report = execute_rollback(&db, &state, &plan, &journals, journals.policy()).unwrap();
        assert_eq!(report.blocks, 3, "unwound 3 blocks");
    }
    assert_eq!(head_of(dir.path()).0, 5);
    {
        let db = Database::open_default(dir.path()).unwrap();
        let above = db
            .iter_checked_from(cf::BLOCK_HEIGHT, Some(&6u64.to_be_bytes()))
            .unwrap()
            .count();
        assert_eq!(above, 0, "nothing indexed above the move's height");
    }
    let m = marker_of(dir.path()).expect("the marker survives the rollback");
    assert_eq!(m.attempt, 1);
    let rows = all_rows(dir.path());
    let err = revert(dir.path(), &moved).unwrap_err();
    assert!(matches!(err, ccfg::ConfigError::Refused(_)), "{err}");
    assert!(
        err.to_string().contains("a normal start was attempted"),
        "{err}"
    );
    assert!(!err.to_string().contains("now at height"), "{err}");
    assert_eq!(all_rows(dir.path()), rows, "nothing written");
}

/// A same-height switch does not reopen the revert either. A started node that
/// switches to a sibling of the block at the move's height (lower hash, the
/// fork-choice tiebreak) keeps the head at that height with nothing indexed
/// above it, which the height check alone cannot see; the marker refuses.
#[tokio::test]
async fn a_same_height_switch_after_a_start_does_not_reopen_the_revert() {
    use sumchain_storage::schema::BlockStore;
    let g = genesis();
    // Two directories with the same chain to 4, then one block each at 5 with
    // different timestamps: siblings.
    let a = deployed_release_directory(&g, 4).await;
    let b = tempfile::TempDir::new().unwrap();
    let copied = std::process::Command::new("cp")
        .args([
            "-R",
            &format!("{}/.", a.path().display()),
            &b.path().display().to_string(),
        ])
        .status()
        .unwrap();
    assert!(copied.success());
    extend_to(a.path(), &g, 5).await;
    std::thread::sleep(std::time::Duration::from_millis(5));
    extend_to(b.path(), &g, 5).await;
    let block_at_5 = |dir: &Path| {
        let db = Database::open_default(dir).unwrap();
        BlockStore::new(&db).get_by_height(5).unwrap().unwrap()
    };
    let (ba, bb) = (block_at_5(a.path()), block_at_5(b.path()));
    assert_ne!(ba.hash(), bb.hash(), "siblings");
    assert_eq!(ba.header.parent_hash, bb.header.parent_hash);
    // The victim holds the higher hash; the sibling with the lower hash wins
    // the same-height tiebreak when imported.
    let (victim, sibling) = if ba.hash() < bb.hash() {
        (b, ba)
    } else {
        (a, bb)
    };
    let moved = move_at_head(victim.path());
    let head_before = head_of(victim.path());

    let node = boot_node(victim.path(), &g).unwrap();
    node.init_chain().unwrap();
    node.consensus.import_block(sibling.clone()).await.unwrap();
    assert_eq!(node.consensus.best_block_hash(), sibling.hash(), "switched");
    drop(node);
    let head_after = head_of(victim.path());
    assert_eq!(head_after.0, 5, "the head stays at the move's height");
    assert_ne!(head_after.1, head_before.1, "to the sibling");
    assert_eq!(head_after.1, sibling.hash());
    {
        let db = Database::open_default(victim.path()).unwrap();
        let above = db
            .iter_checked_from(cf::BLOCK_HEIGHT, Some(&6u64.to_be_bytes()))
            .unwrap()
            .count();
        assert_eq!(above, 0, "nothing indexed above the move's height");
    }
    let err = revert(victim.path(), &moved).unwrap_err();
    assert!(
        err.to_string().contains("a normal start was attempted"),
        "{err}"
    );

    // Without the marker, the chain position alone would have allowed it.
    {
        let db = Database::open_default(victim.path()).unwrap();
        db.delete(cf::META, ccfg::START_MARKER_KEY).unwrap();
        assert!(
            ccfg::pending_schema_revert(&db).is_ok(),
            "the marker is what refuses"
        );
    }
}

// ── the marker killed with SIGKILL ──────────────────────────────────────────

const MARKER_CHILD_DIR_ENV: &str = "SUMCHAIN_START_MARKER_CHILD_DIR";

/// The child half: boots the directory the parent names, with a crash barrier
/// armed through the environment. Inert in an ordinary test run.
#[test]
fn start_marker_crash_child() {
    let Ok(dir) = std::env::var(MARKER_CHILD_DIR_ENV) else {
        return;
    };
    let result = boot(Path::new(&dir), &genesis());
    panic!("the child finished its boot without reaching its barrier: {result:?}");
}

fn boot_killed_at(dir: &Path, fp: sumchain_consensus::branch_switch::failpoints::Failpoint) {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    use sumchain_consensus::branch_switch::failpoints::{BARRIER_AT_ENV, BARRIER_FILE_ENV};
    let marker = dir.join("at-barrier");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "node::consensus_config_boot_tests::start_marker_crash_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(MARKER_CHILD_DIR_ENV, dir)
        .env(BARRIER_AT_ENV, fp.name())
        .env(BARRIER_FILE_ENV, &marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            panic!(
                "the child exited ({status}) before reaching barrier {}:\n{}\n{}",
                fp.name(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
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
    assert!(!child.wait().unwrap().success());
    std::fs::remove_file(&marker).unwrap();
}

/// A start killed immediately before the marker's commit leaves exactly the
/// moved database, and the revert available; killed immediately after it, the
/// marker is the one row added, and the revert refuses.
#[tokio::test]
async fn a_start_killed_around_the_marker_commit_leaves_a_definite_state() {
    use sumchain_consensus::branch_switch::failpoints::Failpoint;
    let g = genesis();
    let (dir, moved, _before) = moved_directory(&g, 5).await;
    let data = dir.path().join("data-moved");
    std::fs::rename(dir.path().join("CURRENT"), dir.path().join("CURRENT")).unwrap();
    let _ = data;
    let rows = all_rows(dir.path());

    boot_killed_at(dir.path(), Failpoint::StartMarkerBeforeCommit);
    assert_eq!(
        all_rows(dir.path()),
        rows,
        "killed before the commit: exactly the moved database"
    );
    assert_eq!(marker_of(dir.path()), None);
    {
        let db = Database::open_default(dir.path()).unwrap();
        assert_eq!(ccfg::pending_schema_revert(&db).unwrap().at_height, 5);
    }

    boot_killed_at(dir.path(), Failpoint::StartMarkerAfterCommit);
    let after = all_rows(dir.path());
    assert_eq!(
        changed_keys(&rows, &after),
        vec![(cf::META.to_string(), ccfg::START_MARKER_KEY.to_vec())],
        "killed after the commit: the marker and nothing else"
    );
    let m = marker_of(dir.path()).unwrap();
    assert_eq!(m.attempt, 1);
    let err = revert(dir.path(), &moved).unwrap_err();
    assert!(
        err.to_string().contains("a normal start was attempted"),
        "{err}"
    );
    assert_eq!(all_rows(dir.path()), after, "nothing written");
}

/// The deployed schema-3 release, started by mistake on a moved node, drops
/// the two schema-4 names it does not declare from the activation record and
/// is refused by the schema-4 record. Unset, the missing names change
/// nothing and this binary boots; scheduled and passed, the verified schema-4
/// record holds the same height and this binary restores the name.
#[tokio::test]
async fn names_the_schema_3_release_drops_are_restored_from_a_schema_4_record() {
    let as_the_schema_3_release_records = |dir: &Path| {
        let mut heights = activation_heights(dir);
        heights.retain(|(n, _)| !NAMES_THE_SCHEMA_3_RELEASE_LACKS.contains(&n.as_str()));
        write_activation_heights(dir, &heights);
    };

    // Unset: nothing to restore.
    let g = genesis();
    let dir = schema_3_directory(&g);
    boot(dir.path(), &g).unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        ccfg::acknowledge_schema_transition(&db, 0, p.old, p.new).unwrap();
    }
    boot(dir.path(), &g).unwrap();
    as_the_schema_3_release_records(dir.path());
    boot(dir.path(), &g).unwrap();
    assert_eq!(
        activation_heights(dir.path()),
        g.params.recorded_activation_heights()
    );

    // Scheduled and passed: restored from the verified schema-4 record.
    let mut gated = genesis();
    gated.params.peer_protocol_declaration_required_from_height = Some(2);
    gated
        .params
        .strict_transaction_signatures_enabled_from_height = Some(3);
    let dir = schema_3_directory(&g);
    boot(dir.path(), &g).unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        let p = ccfg::pending_schema_transition(&db).unwrap().unwrap();
        ccfg::acknowledge_schema_transition(&db, 0, p.old, p.new).unwrap();
    }
    boot(dir.path(), &gated).unwrap();
    extend_to(dir.path(), &gated, 5).await;
    as_the_schema_3_release_records(dir.path());
    assert_eq!(
        height_of(
            &activation_heights(dir.path()),
            "strict_transaction_signatures_enabled_from_height"
        ),
        None
    );
    boot(dir.path(), &gated).unwrap();
    assert_eq!(
        activation_heights(dir.path()),
        gated.params.recorded_activation_heights(),
        "the full activation record is back"
    );
    assert_eq!(
        record(dir.path()).unwrap().config.get(0x1046),
        Some(&ccfg::Value::U64(3))
    );
}

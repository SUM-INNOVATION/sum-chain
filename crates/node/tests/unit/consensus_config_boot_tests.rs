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

/// The release before this binary: it read and wrote schema 1 and knew schema 2
/// only as a draft. Used to create the database it would have left.
static PREVIOUS: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1],
    writes: &ccfg::SCHEMA_1,
    knows: &ccfg::SCHEMA_2,
};

/// #277's gate (schema-2 field 0x103f) through the real boot sequence:
///
/// * unset (every committed genesis), a fresh node records schema 2;
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

    // Unset, fresh: schema 2, the gate absent.
    let dir = tempfile::TempDir::new().unwrap();
    boot(dir.path(), &g).unwrap();
    let r = record(dir.path()).expect("recorded at first boot");
    assert_eq!(r.config.schema().number, 2);
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
    assert_eq!(r.config.schema().number, 2);
    assert_eq!(r.config.get(GATE), Some(&ccfg::Value::U64(1_000)));
}

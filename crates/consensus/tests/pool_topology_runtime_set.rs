//! The #126 pool topology guard counts the set the running node actually uses.
//!
//! #126 asks for a guard over the *live* validator membership. Under protocol
//! v1 (G2-d, ratified) the canonical runtime membership is the static genesis
//! list at every height: the engine refuses dynamic staking epochs and
//! stake-weighted selection (asserted below), and refuses a database holding a
//! stored epoch set (asserted in `round_robin_proposer.rs`,
//! `a_database_holding_a_stored_epoch_set_is_refused_at_load`).
//! The guard in `sumchain_genesis::pool_topology` counts the genesis list. What
//! this file pins, on real engines and real databases, is that the two are the
//! same set, so the genesis-time guard is the runtime guard for as long as
//! protocol v1 holds:
//!
//! * the engine's validator set (`ConsensusQuery::validators`) is the genesis
//!   list, in declared order, at genesis, after blocks and after a restart,
//!   including for a deliberately permuted declared order that differs from
//!   the sorted order (so an engine that sorted or deduplicated through a set
//!   would fail);
//! * every proposer the engine schedules is a member of that set, and the
//!   schedule covers all of it;
//! * the guard returns the same verdict over the engine's set as over the
//!   genesis list, refusing pool enablement below 5 and reporting the 4 / 5 / 7
//!   bounds;
//! * `Genesis::validate` with the pool gate set refuses with the same count the
//!   engine reports, and at five or more validators the refusal is never the
//!   topology one (the gate stays refused for its other reasons);
//! * the guard's premise is a tripwire: if protocol v1 stopped refusing dynamic
//!   epochs, the engine would no longer be guaranteed to run the genesis list,
//!   and these tests fail.
//!
//! When #266 lifts protocol-v1 containment, the guard must move to canonical
//! membership at the activation height (see `pool_topology.rs`). Nothing here
//! activates the pool, sets a gate on a running chain or adds a parameter. All
//! keys are synthetic (`KeyPair::from_bytes([i; 32])`).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::pool_topology::{
    check_pool_activation, validator_count, CRYPTOGRAPHIC_MINIMUM, MAINTENANCE_MINIMUM,
    PRODUCT_MINIMUM,
};
use sumchain_genesis::{ChainParams, Genesis, GenesisError};
use sumchain_primitives::StakingParams;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pubkey(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

/// A genesis in exactly this validator order, built without validation, so the
/// engine's and the guard's own checks are what is under test.
fn raw_genesis(validators: &[KeyPair], params: ChainParams) -> Genesis {
    let mut alloc = HashMap::new();
    for v in validators {
        alloc.insert(v.address().to_base58(), 1_000_000u128);
    }
    Genesis::new(
        CHAIN_ID,
        0,
        validators
            .iter()
            .map(|v| v.public_key().to_base58())
            .collect(),
        alloc,
        params,
    )
}

/// The pool gate set, over default parameters otherwise.
fn pool_gate_params() -> ChainParams {
    ChainParams {
        compute_pool_enabled_from_height: Some(10),
        ..ChainParams::default()
    }
}

struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    engine: Arc<PoAEngine>,
}

fn engine_on(db: &Arc<Database>, genesis: &Genesis, key: Option<KeyPair>) -> PoAEngine {
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    PoAEngine::new(db.clone(), state, mempool, genesis, key)
        .expect("a static round-robin genesis constructs")
}

impl Node {
    fn new(genesis: &Genesis, key: Option<KeyPair>) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let engine = Arc::new(engine_on(&db, genesis, key));
        engine.init_genesis(genesis).unwrap();
        Self {
            _dir: dir,
            db,
            engine,
        }
    }
}

/// The engine's runtime validator set is the genesis list, in declared order,
/// and every scheduled proposer belongs to it.
fn assert_runtime_set_is_genesis_list(engine: &PoAEngine, genesis: &Genesis, ctx: &str) {
    let declared = genesis.validator_pubkeys().unwrap();
    assert_eq!(engine.validators(), declared, "{ctx}: runtime set");
    let members: BTreeSet<[u8; 32]> = declared.iter().copied().collect();
    let n = declared.len() as u64;
    let mut scheduled = BTreeSet::new();
    for h in 1..=(3 * n) {
        let p = engine.get_proposer(h);
        assert!(
            members.contains(&p),
            "{ctx}: proposer at {h} is not a member"
        );
        scheduled.insert(p);
    }
    assert_eq!(
        scheduled, members,
        "{ctx}: the schedule covers the whole set"
    );
}

#[test]
fn the_guard_and_the_engine_count_the_same_set() {
    for n in [2u8, 3, 4, 5, 7] {
        let keys: Vec<KeyPair> = (1..=n).map(key).collect();
        let g = raw_genesis(&keys, ChainParams::default());
        let node = Node::new(&g, None);
        assert_runtime_set_is_genesis_list(&node.engine, &g, &format!("n={n}"));

        let runtime = node.engine.validators();
        let genesis_list = g.validator_pubkeys().unwrap();
        assert_eq!(validator_count(&runtime), usize::from(n));
        assert_eq!(validator_count(&runtime), validator_count(&genesis_list));
        assert_eq!(
            check_pool_activation(&runtime),
            check_pool_activation(&genesis_list),
            "n={n}: same verdict over the runtime set and the genesis list"
        );
    }
}

#[test]
fn below_five_runtime_validators_pool_enablement_is_refused_with_all_three_bounds() {
    for n in [2u8, 3, 4] {
        let keys: Vec<KeyPair> = (1..=n).map(key).collect();
        let node = Node::new(&raw_genesis(&keys, ChainParams::default()), None);
        let refusal = check_pool_activation(&node.engine.validators())
            .expect_err("pool enablement below the product minimum is refused");
        assert_eq!(refusal.validators, usize::from(n));
        assert_eq!(refusal.cryptographic_minimum, CRYPTOGRAPHIC_MINIMUM);
        assert_eq!(refusal.product_minimum, PRODUCT_MINIMUM);
        assert_eq!(refusal.maintenance_minimum, MAINTENANCE_MINIMUM);
        let text = refusal.to_string();
        for needle in ["minimum 4", "minimum 5", "(7, #248)"] {
            assert!(
                text.contains(needle),
                "n={n}: {needle:?} missing from {text:?}"
            );
        }
    }
    for n in [5u8, 7] {
        let keys: Vec<KeyPair> = (1..=n).map(key).collect();
        let node = Node::new(&raw_genesis(&keys, ChainParams::default()), None);
        assert!(
            check_pool_activation(&node.engine.validators()).is_ok(),
            "n={n}: the topology requirement holds (nothing is admitted by it alone)"
        );
    }
}

#[test]
fn genesis_validation_refuses_the_pool_gate_over_the_count_the_engine_reports() {
    for n in [2u8, 3, 4, 5, 7] {
        let keys: Vec<KeyPair> = (1..=n).map(key).collect();
        // The engine runs the same validator list without the gate.
        let running = Node::new(&raw_genesis(&keys, ChainParams::default()), None);
        let runtime_count = validator_count(&running.engine.validators());

        let gated = raw_genesis(&keys, pool_gate_params());
        let err = gated
            .validate()
            .expect_err("the compute-pool gate is refused at every size");
        match (&err, usize::from(n) < PRODUCT_MINIMUM) {
            (GenesisError::PoolActivationTopology(refusal), true) => {
                assert_eq!(refusal.validators, runtime_count, "n={n}");
            }
            (GenesisError::PoolActivationTopology(_), false) => {
                panic!("n={n}: at or above the product minimum the refusal must not be topology")
            }
            (other, true) => panic!("n={n}: expected the topology refusal, got {other}"),
            (_, false) => {}
        }
    }
}

#[tokio::test]
async fn the_runtime_set_stays_the_genesis_list_across_blocks_and_a_restart() {
    for n in [2u8, 5] {
        let keys: Vec<KeyPair> = (1..=n).map(key).collect();
        let g = raw_genesis(&keys, ChainParams::default());
        let nodes: Vec<Node> = (1..=n).map(|i| Node::new(&g, Some(key(i)))).collect();
        for h in 1..=(2 * n as u64) {
            let expected = nodes[0].engine.get_proposer(h);
            let producer = nodes
                .iter()
                .zip(&keys)
                .find(|(_, k)| pubkey(k) == expected)
                .map(|(node, _)| node)
                .expect("the scheduled proposer is one of the running validators");
            let block = producer
                .engine
                .propose_block(Vec::new())
                .await
                .expect("the rightful proposer produces");
            for node in &nodes {
                if !Arc::ptr_eq(&node.engine, &producer.engine) {
                    node.engine
                        .import_block(block.clone())
                        .await
                        .expect("peers accept it");
                }
                assert_runtime_set_is_genesis_list(&node.engine, &g, &format!("n={n} h={h}"));
            }
        }
        // A restart reopens the same database and still runs the genesis list.
        let reopened = engine_on(&nodes[0].db, &g, Some(key(1)));
        reopened.load_chain().unwrap();
        assert_runtime_set_is_genesis_list(&reopened, &g, &format!("n={n} after restart"));
        assert_eq!(
            check_pool_activation(&reopened.validators()),
            check_pool_activation(&g.validator_pubkeys().unwrap())
        );
    }
}

/// The guard's premise. If protocol v1 stopped refusing dynamic epochs or
/// stake-weighted selection, the runtime set could diverge from the genesis
/// list the guard counts, and this test fails first.
#[test]
fn the_guards_premise_protocol_v1_still_refuses_dynamic_membership() {
    let keys: Vec<KeyPair> = (1..=5).map(key).collect();
    for (label, staking) in [
        (
            "dynamic epochs",
            StakingParams {
                epoch_length: 100,
                stake_weighted_selection: false,
                ..StakingParams::default()
            },
        ),
        (
            "stake-weighted selection",
            StakingParams {
                epoch_length: 0,
                stake_weighted_selection: true,
                ..StakingParams::default()
            },
        ),
    ] {
        let g = raw_genesis(
            &keys,
            ChainParams {
                staking: Some(staking),
                ..ChainParams::default()
            },
        );
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        assert!(
            PoAEngine::new(db, state, mempool, &g, None).is_err(),
            "{label}: the engine must refuse it, or the guard no longer counts the live set"
        );
        assert!(
            g.validate().is_err(),
            "{label}: genesis validation must refuse it"
        );
    }
}

/// The declared order, not a sorted or set order, is the set the engine runs.
/// The keys are declared deliberately out of order, and the fixture first
/// checks that this order differs from the sorted and reverse-sorted orders,
/// so an engine that sorted (or rebuilt the set through a map) cannot pass.
#[tokio::test]
async fn a_permuted_declared_order_is_kept_at_genesis_across_blocks_and_a_restart() {
    let order: [u8; 5] = [3, 1, 4, 2, 5];
    let keys: Vec<KeyPair> = order.iter().map(|&i| key(i)).collect();
    let g = raw_genesis(&keys, ChainParams::default());
    let declared = g.validator_pubkeys().unwrap();
    assert_eq!(declared, keys.iter().map(pubkey).collect::<Vec<_>>());
    let mut sorted = declared.clone();
    sorted.sort();
    assert_ne!(declared, sorted, "the fixture must not already be sorted");
    let mut reversed = sorted.clone();
    reversed.reverse();
    assert_ne!(declared, reversed, "nor reverse-sorted");

    let nodes: Vec<Node> = order.iter().map(|&i| Node::new(&g, Some(key(i)))).collect();
    for node in &nodes {
        assert_eq!(node.engine.validators(), declared, "at genesis");
    }
    let n = declared.len() as u64;
    for h in 1..=(2 * n) {
        let expected = declared[(h % n) as usize];
        let producer = nodes
            .iter()
            .zip(&keys)
            .find(|(_, k)| pubkey(k) == expected)
            .map(|(node, _)| node)
            .unwrap();
        assert_eq!(producer.engine.get_proposer(h), expected, "h={h}");
        let block = producer
            .engine
            .propose_block(Vec::new())
            .await
            .expect("the rightful proposer produces");
        assert_eq!(block.header.proposer_pubkey, expected);
        for node in &nodes {
            if !Arc::ptr_eq(&node.engine, &producer.engine) {
                node.engine
                    .import_block(block.clone())
                    .await
                    .expect("peers accept it");
            }
            assert_eq!(node.engine.validators(), declared, "h={h}");
        }
    }
    let reopened = engine_on(&nodes[0].db, &g, Some(key(order[0])));
    reopened.load_chain().unwrap();
    assert_eq!(reopened.validators(), declared, "after restart");
    assert_eq!(
        check_pool_activation(&reopened.validators()),
        check_pool_activation(&declared)
    );
}

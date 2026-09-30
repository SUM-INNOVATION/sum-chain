//! Protocol v1 proposer selection, end to end (#267).
//!
//! One rule — `proposer(height) = validators[height mod n]` over the static
//! genesis list — and one function for it,
//! `sumchain_primitives::proposer::round_robin_proposer`. What is asserted here,
//! on real engines and real databases:
//!
//! * the engine refuses stake-weighted selection, dynamic staking epochs and a
//!   bad validator set even when handed an unvalidated `Genesis::new`;
//! * a static genesis (no staking section, or `epoch_length = 0` and
//!   `stake_weighted_selection = false`) still constructs;
//! * producer and validator name the same proposer at every height, for
//!   2, 4, 5 and 7 validators, and blocks rotate through the declared order;
//! * the declared order is the schedule — not a sorted or map order;
//! * a restart keeps the schedule, and a database holding a stored epoch
//!   validator set is refused rather than adopted or ignored;
//! * a reorg re-checks every adopted block's proposer before it unwinds.
//!
//! All keys are synthetic (`KeyPair::from_bytes([i; 32])`).

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{poa::check_protocol_v1, ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    Block, BlockHeader, Hash, StakingParams, ValidatorSet, ValidatorSetEntry,
};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, BlockStore, Database, ValidatorSetStore};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pubkey(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

fn params(staking: Option<StakingParams>) -> ChainParams {
    ChainParams {
        staking,
        ..ChainParams::default()
    }
}

/// A genesis in exactly this validator order, built WITHOUT validation, so the
/// engine's own checks are what is under test.
fn raw_genesis(validators: &[KeyPair], staking: Option<StakingParams>) -> Genesis {
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
        params(staking),
    )
}

fn stake_weighted() -> StakingParams {
    StakingParams {
        stake_weighted_selection: true,
        ..StakingParams::default()
    }
}

fn dynamic_epochs(epoch_length: u64) -> StakingParams {
    StakingParams {
        epoch_length,
        ..StakingParams::default()
    }
}

struct Node {
    _dir: TempDir,
    db: Arc<Database>,
    state: Arc<StateManager>,
    engine: Arc<PoAEngine>,
    pubkey: Option<[u8; 32]>,
}

fn engine_on(
    db: &Arc<Database>,
    genesis: &Genesis,
    key: Option<KeyPair>,
) -> (
    Arc<StateManager>,
    Result<PoAEngine, sumchain_consensus::ConsensusError>,
) {
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let engine = PoAEngine::new(db.clone(), state.clone(), mempool, genesis, key);
    (state, engine)
}

impl Node {
    fn new(genesis: &Genesis, key: Option<KeyPair>) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let pubkey = key.as_ref().map(pubkey);
        let (state, engine) = engine_on(&db, genesis, key);
        let engine = Arc::new(engine.expect("a static round-robin genesis constructs"));
        engine.init_genesis(genesis).unwrap();
        Self {
            _dir: dir,
            db,
            state,
            engine,
            pubkey,
        }
    }

    fn height(&self) -> u64 {
        self.engine.current_height()
    }
}

fn refusal(genesis: &Genesis) -> String {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    match engine_on(&db, genesis, Some(key(1))).1 {
        Ok(_) => panic!("the engine must refuse this genesis"),
        Err(e) => e.to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction: refused and allowed configurations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn the_engine_refuses_stake_weighted_selection_it_was_handed_directly() {
    let g = raw_genesis(&[key(1), key(2)], Some(stake_weighted()));
    let err = refusal(&g);
    assert!(
        err.contains("stake-weighted proposer selection is unavailable in protocol v1"),
        "{err}"
    );
    assert!(err.contains("does not fall back"), "{err}");
    assert!(check_protocol_v1(&g).is_err());
    // Not coerced: the genesis still says `true` after the refusal.
    assert!(g.params.staking.as_ref().unwrap().stake_weighted_selection);
}

#[test]
fn the_engine_refuses_dynamic_epochs_it_was_handed_directly() {
    for epoch_length in [1u64, 2, 14_400, u64::MAX] {
        let g = raw_genesis(&[key(1), key(2)], Some(dynamic_epochs(epoch_length)));
        let err = refusal(&g);
        assert!(
            err.contains(&format!("staking.epoch_length = {epoch_length} is refused")),
            "{err}"
        );
        assert!(err.contains("dynamic staking epochs"), "{err}");
        assert!(err.contains("#266"), "{err}");
        assert!(err.contains("does not disable epochs silently"), "{err}");
        assert_eq!(
            g.params.staking.as_ref().unwrap().epoch_length,
            epoch_length
        );
    }
}

#[test]
fn a_genesis_with_both_faults_reports_the_proposer_rule_first() {
    let both = StakingParams {
        stake_weighted_selection: true,
        epoch_length: 100,
        ..StakingParams::default()
    };
    let err = refusal(&raw_genesis(&[key(1)], Some(both)));
    assert!(
        err.contains("stake_weighted_selection = true is refused"),
        "{err}"
    );
}

#[test]
fn the_engine_refuses_empty_and_duplicated_validator_sets() {
    let err = refusal(&raw_genesis(&[], None));
    assert!(err.contains("empty"), "{err}");
    let err = refusal(&raw_genesis(&[key(1), key(2), key(1)], None));
    assert!(err.contains("positions 0 and 2"), "{err}");
}

#[test]
fn static_membership_constructs_with_or_without_a_staking_section() {
    let vs = [key(1), key(2)];
    // No staking section: the shape of every shipped genesis.
    Node::new(&raw_genesis(&vs, None), Some(key(1)));
    // An explicitly static staking section, including the new default.
    Node::new(
        &raw_genesis(&vs, Some(StakingParams::default())),
        Some(key(1)),
    );
    Node::new(
        &raw_genesis(
            &vs,
            Some(StakingParams {
                epoch_length: 0,
                stake_weighted_selection: false,
                ..StakingParams::default()
            }),
        ),
        None,
    );
}

/// The restart path (`Node::new` → `validate_runtime_activation`) refuses the
/// same configurations through `ChainParams::validate`.
#[test]
fn the_restart_validator_refuses_the_same_configurations() {
    use sumchain_state::account_root::validate_runtime_activation;
    assert!(validate_runtime_activation(&params(Some(stake_weighted()))).is_err());
    assert!(validate_runtime_activation(&params(Some(dynamic_epochs(10)))).is_err());
    assert!(validate_runtime_activation(&params(None)).is_ok());
    assert!(validate_runtime_activation(&ChainParams::default()).is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// Producer and validator agree
// ─────────────────────────────────────────────────────────────────────────────

/// A header at `height` on top of `parent`, signed by `signer`.
fn signed_header(parent: &Block, signer: &KeyPair) -> BlockHeader {
    let mut header = BlockHeader::new(
        parent.hash(),
        parent.height() + 1,
        parent.header.timestamp + 1,
        Hash::ZERO,
        Hash::ZERO,
        pubkey(signer),
    );
    let sig = sign(header.signing_hash().as_bytes(), signer.private_key());
    header.set_signature(*sig.as_bytes());
    header
}

#[test]
fn producer_and_validator_name_the_same_proposer_at_every_height() {
    for n in [2u8, 4, 5, 7] {
        let keys: Vec<KeyPair> = (1..=n).map(key).collect();
        let g = raw_genesis(&keys, None);
        let node = Node::new(&g, None);
        let executor = BlockExecutor::new(node.state.clone(), node.db.clone(), g.params.clone());
        let validators = g.validator_pubkeys().unwrap();

        let mut parent = Block::genesis(Hash::ZERO, validators[0], 1);
        for h in 1..=(6 * n as u64 + 3) {
            let expected = validators[(h % n as u64) as usize];
            // Producer side: the engine's schedule.
            assert_eq!(node.engine.get_proposer(h), expected, "n={n} h={h}");
            // Validator side: exactly the expected signer passes the header check.
            for k in &keys {
                let header = signed_header(&parent, k);
                let verdict = executor.validate_header(&header, Some(&parent), &validators);
                if pubkey(k) == expected {
                    verdict
                        .unwrap_or_else(|e| panic!("n={n} h={h}: rightful proposer refused: {e}"));
                } else {
                    let err = verdict
                        .expect_err("an off-turn signer must be refused")
                        .to_string();
                    assert!(err.contains("Invalid proposer"), "n={n} h={h}: {err}");
                }
            }
            let rightful = keys.iter().find(|k| pubkey(k) == expected).unwrap();
            parent = Block::new(signed_header(&parent, rightful), Vec::new());
        }
    }
}

/// Real engines, one per validator: at every height only the rightful proposer
/// can produce (the drafting and screening path), every other engine imports
/// the block (the validation path), and the proposers rotate through the
/// declared order.
#[tokio::test]
async fn blocks_rotate_through_the_declared_order_across_engines() {
    for n in [2u8, 4] {
        let keys: Vec<KeyPair> = (1..=n).map(key).collect();
        let g = raw_genesis(&keys, None);
        let nodes: Vec<Node> = (1..=n).map(|i| Node::new(&g, Some(key(i)))).collect();
        for h in 1..=(3 * n as u64) {
            let expected = pubkey(&keys[(h % n as u64) as usize]);
            let mut produced = None;
            for node in &nodes {
                let result = node.engine.propose_block(Vec::new()).await;
                if node.pubkey == Some(expected) {
                    produced = Some(result.expect("the rightful proposer produces"));
                } else {
                    assert!(
                        result.is_err(),
                        "n={n} h={h}: an off-turn validator produced"
                    );
                }
            }
            let block = produced.unwrap();
            assert_eq!(block.height(), h);
            assert_eq!(block.header.proposer_pubkey, expected);
            for node in &nodes {
                if node.pubkey != Some(expected) {
                    node.engine
                        .import_block(block.clone())
                        .await
                        .expect("peers accept it");
                }
                assert_eq!(node.height(), h);
            }
        }
    }
}

/// The schedule is the DECLARED order. Keys are declared in an order that is
/// neither byte-sorted nor reverse-sorted; any sorting, hashing into a map or
/// deduplication through a set would change who proposes.
#[test]
fn the_declared_order_is_the_schedule() {
    let declared = [key(3), key(1), key(4), key(2), key(5)];
    let mut sorted: Vec<[u8; 32]> = declared.iter().map(pubkey).collect();
    sorted.sort();
    let declared_pks: Vec<[u8; 32]> = declared.iter().map(pubkey).collect();
    assert_ne!(sorted, declared_pks, "fixture must not already be sorted");
    let mut reversed_sorted = sorted.clone();
    reversed_sorted.reverse();
    assert_ne!(
        reversed_sorted, declared_pks,
        "fixture must not be reverse-sorted"
    );

    // Through the validating JSON loader, with the alloc map in a different
    // insertion order: map order must not matter, list order must.
    let g = raw_genesis(&declared, None);
    let json = g.to_json().unwrap();
    let loaded = Genesis::from_json(&json).unwrap();
    let node = Node::new(&loaded, None);
    for h in 0..50u64 {
        assert_eq!(
            node.engine.get_proposer(h),
            declared_pks[(h % 5) as usize],
            "h={h}"
        );
    }

    let rev = [key(5), key(2), key(4), key(1), key(3)];
    let node = Node::new(&raw_genesis(&rev, None), None);
    for h in 0..50u64 {
        assert_eq!(
            node.engine.get_proposer(h),
            declared_pks[4 - (h % 5) as usize],
            "h={h}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Restart
// ─────────────────────────────────────────────────────────────────────────────

fn reopen(node: &Node, genesis: &Genesis, key: Option<KeyPair>) -> Result<PoAEngine, String> {
    let (_state, engine) = engine_on(&node.db, genesis, key);
    let engine = engine.map_err(|e| e.to_string())?;
    engine.load_chain().map_err(|e| e.to_string())?;
    Ok(engine)
}

#[tokio::test]
async fn a_restart_keeps_the_proposer_sequence() {
    let keys: Vec<KeyPair> = (1..=5).map(key).collect();
    let g = raw_genesis(&keys, None);
    let nodes: Vec<Node> = (1..=5).map(|i| Node::new(&g, Some(key(i)))).collect();
    for h in 1..=7u64 {
        let idx = (h % 5) as usize;
        let block = nodes[idx].engine.propose_block(Vec::new()).await.unwrap();
        for (i, node) in nodes.iter().enumerate() {
            if i != idx {
                node.engine.import_block(block.clone()).await.unwrap();
            }
        }
    }
    let before: Vec<[u8; 32]> = (0..40).map(|h| nodes[0].engine.get_proposer(h)).collect();

    let restarted = reopen(&nodes[0], &g, Some(key(1))).expect("a static chain restarts");
    assert_eq!(restarted.current_height(), 7);
    let after: Vec<[u8; 32]> = (0..40).map(|h| restarted.get_proposer(h)).collect();
    assert_eq!(before, after);
    // Height 10 is validator 0's turn again, after the restart as before.
    assert_eq!(restarted.get_proposer(10), pubkey(&keys[0]));
}

/// A stored epoch validator set is dynamic membership history. It is refused at
/// load — not adopted, and not silently ignored in favour of the genesis list.
#[tokio::test]
async fn a_database_holding_a_stored_epoch_set_is_refused_at_load() {
    let keys: Vec<KeyPair> = (1..=2).map(key).collect();
    let g = raw_genesis(&keys, None);
    let a = Node::new(&g, Some(key(1)));
    let b = Node::new(&g, Some(key(2)));
    let block = b.engine.propose_block(Vec::new()).await.unwrap();
    a.engine.import_block(block).await.unwrap();

    // Order reversed relative to genesis: adopting it would change who proposes.
    let stored = ValidatorSet::new(
        1,
        1,
        vec![
            ValidatorSetEntry::new(pubkey(&keys[1]), 10, 0),
            ValidatorSetEntry::new(pubkey(&keys[0]), 5, 0),
        ],
        [0u8; 32],
    );
    ValidatorSetStore::new(&a.db)
        .put_validator_set(&stored)
        .unwrap();

    let err = match reopen(&a, &g, Some(key(1))) {
        Ok(_) => panic!("a stored epoch set must be refused"),
        Err(e) => e,
    };
    assert!(err.contains("stored validator set for epoch 1"), "{err}");
    assert!(err.contains("#266"), "{err}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Reorg
// ─────────────────────────────────────────────────────────────────────────────

/// Build a branch from genesis on a scratch database: each block executed,
/// given its computed root, and signed by `signers[i]` — whether or not that
/// signer is the rightful proposer.
fn build_branch(genesis: &Genesis, signers: &[&KeyPair], ts_base: u64) -> Vec<Block> {
    let scratch = Node::new(genesis, None);
    let validators = genesis.validator_pubkeys().unwrap();
    let executor = BlockExecutor::new(
        scratch.state.clone(),
        scratch.db.clone(),
        genesis.params.clone(),
    );
    let mut parent = BlockStore::new(&scratch.db).get_latest().unwrap().unwrap();
    let mut out = Vec::new();
    for (i, signer) in signers.iter().enumerate() {
        let mut block = Block::new(
            BlockHeader::new(
                parent.hash(),
                parent.height() + 1,
                ts_base + i as u64,
                Hash::ZERO,
                Hash::ZERO,
                pubkey(signer),
            ),
            Vec::new(),
        );
        block.header.tx_root = block.compute_tx_root();
        let execution = executor
            .execute_block(&block, scratch.state.state_root(), &validators)
            .unwrap();
        block.header.state_root = execution.computed_root();
        let sig = sign(block.header.signing_hash().as_bytes(), signer.private_key());
        block.header.set_signature(*sig.as_bytes());
        let (executed, _, _) = execution.into_parts();
        let accepted = executed.accept_produced(&block).unwrap();
        let accumulator = accepted.accumulator();
        accepted.publish().unwrap();
        scratch.state.set_state_root(accumulator);
        parent = block.clone();
        out.push(block);
    }
    out
}

/// Two validators. Node X holds the canonical chain to height 2. A competing
/// branch to height 3 is placed in X's block store WITHOUT validation, its
/// interior block at height 2 signed by the wrong validator, and the tip — which
/// is itself valid — is imported. The switch must be refused before the unwind:
/// X's head and height index are untouched. The control, the same branch with a
/// rightful interior block, is adopted.
#[tokio::test]
async fn a_reorg_rechecks_every_adopted_block_before_unwinding() {
    let v = [key(1), key(2)];
    let g = raw_genesis(&v, None);

    for interior_is_rightful in [false, true] {
        let x = Node::new(&g, Some(key(1)));
        let y = Node::new(&g, Some(key(2)));
        // Canonical: h1 by v[1], h2 by v[0].
        let b1 = y.engine.propose_block(Vec::new()).await.unwrap();
        x.engine.import_block(b1.clone()).await.unwrap();
        let b2 = x.engine.propose_block(Vec::new()).await.unwrap();
        assert_eq!(x.height(), 2);
        let head_before = BlockStore::new(&x.db).get_latest().unwrap().unwrap().hash();

        // Competing branch: h1' v[1] (rightful), h2' v[1] or v[0], h3' v[1] (rightful).
        let h2_signer = if interior_is_rightful { &v[0] } else { &v[1] };
        let branch = build_branch(&g, &[&v[1], h2_signer, &v[1]], 10_000);
        assert_ne!(branch[0].hash(), b1.hash());
        for b in &branch[..2] {
            x.db.put(cf::BLOCKS, b.hash().as_bytes(), &b.to_bytes())
                .unwrap();
        }

        let result = x.engine.import_block(branch[2].clone()).await;
        let store = BlockStore::new(&x.db);
        if interior_is_rightful {
            result.expect("a branch of rightful proposers is adopted");
            assert_eq!(
                store.get_latest().unwrap().unwrap().hash(),
                branch[2].hash()
            );
        } else {
            let err = result
                .expect_err("a wrong interior proposer must refuse the switch")
                .to_string();
            assert!(err.contains("reorg refused before unwinding"), "{err}");
            assert!(err.contains("Invalid proposer"), "{err}");
            assert_eq!(store.get_latest().unwrap().unwrap().hash(), head_before);
            assert_eq!(store.get_by_height(1).unwrap().unwrap().hash(), b1.hash());
            assert_eq!(store.get_by_height(2).unwrap().unwrap().hash(), b2.hash());
            assert_eq!(x.height(), 2);
        }
    }
}

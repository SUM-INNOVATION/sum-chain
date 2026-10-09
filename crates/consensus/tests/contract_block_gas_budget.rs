//! #279: `max_block_contract_gas` through the proposer and the importer.
//!
//! Above `contract_metering_enabled_from_height` a block's summed DECLARED
//! contract gas must not exceed the budget. The proposer fits its selection to
//! it; the importer refuses an over-budget block in `validate_block`, before
//! any of it executes. Below the gate neither does anything.

#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::transaction::ContractDeployData;
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

const WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "new") (param i32 i32) (result i32) (i32.const 0)))
"#;

struct Node {
    db: Arc<Database>,
    state: Arc<StateManager>,
    consensus: Arc<PoAEngine>,
    _dir: TempDir,
}

impl Node {
    fn new(genesis: &Genesis, key: [u8; 32]) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let db = Arc::new(Database::open_default(dir.path()).expect("open database"));
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool,
                genesis,
                Some(KeyPair::from_bytes(key)),
            )
            .expect("engine"),
        );
        consensus.init_genesis(genesis).expect("init genesis");
        Self {
            db,
            state,
            consensus,
            _dir: dir,
        }
    }
}

struct Fixture {
    genesis: Genesis,
    validator: KeyPair,
    senders: Vec<KeyPair>,
}

fn fixture(gate: Option<u64>, budget: Option<u64>) -> Fixture {
    let validator = KeyPair::from_bytes([0x41; 32]);
    let senders: Vec<KeyPair> = (0..3u8).map(|i| KeyPair::from_bytes([0x50 + i; 32])).collect();
    let mut params = ChainParams::with_contracts_enabled();
    params.contract_metering_enabled_from_height = gate;
    params.max_block_contract_gas = budget;
    // A valid configuration: the per-transaction ceiling is at most the budget.
    if let Some(b) = budget {
        params.max_contract_gas = params.max_contract_gas.min(b);
    }
    params.validate().expect("fixture is a valid configuration");
    let mut alloc = HashMap::from([(validator.address().to_base58(), 100_000_000u128)]);
    for s in &senders {
        alloc.insert(s.address().to_base58(), 1_000_000_000u128);
    }
    let genesis = Genesis::new(
        CHAIN_ID,
        0,
        vec![validator.public_key().to_base58()],
        alloc,
        params,
    );
    Fixture {
        genesis,
        validator,
        senders,
    }
}

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 1_000,
        nonce,
        payload,
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn deploy(kp: &KeyPair, nonce: u64, gas_limit: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::ContractDeploy(ContractDeployData {
            code: wat::parse_str(WAT).unwrap(),
            init_method: "new".to_string(),
            init_args: vec![],
            value: 0,
            gas_limit,
        }),
    )
}

fn transfer(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    signed(
        kp,
        nonce,
        TxPayload::Transfer {
            to: Address::new([8u8; 20]),
            amount: 1,
        },
    )
}

fn hashes(txs: &[SignedTransaction]) -> Vec<Hash> {
    txs.iter().map(|t| t.hash()).collect()
}

#[tokio::test]
async fn the_proposer_fits_its_block_to_the_declared_contract_gas_budget() {
    let f = fixture(Some(1), Some(2_500_000));
    let node = Node::new(&f.genesis, *f.validator.private_key().as_bytes());
    let [a, b, c] = [&f.senders[0], &f.senders[1], &f.senders[2]];
    let offered = vec![
        deploy(a, 0, 2_000_000), // fits; 500_000 left
        deploy(b, 0, 1_000_000), // does not fit: skipped, stays eligible
        transfer(b, 1),          // b's later nonce goes with it
        transfer(c, 0),
        deploy(c, 1, 400_000), // fits
    ];
    let block = node.consensus.propose_block(offered.clone()).await.expect("a block");
    assert_eq!(
        hashes(&block.transactions),
        hashes(&[offered[0].clone(), offered[3].clone(), offered[4].clone()])
    );
    assert_eq!(node.state.get_nonce(&b.address()).unwrap(), 0, "b untouched");

    // Below the gate the same offer is taken whole.
    let f = fixture(Some(2), Some(2_500_000));
    let node = Node::new(&f.genesis, *f.validator.private_key().as_bytes());
    let block = node.consensus.propose_block(offered.clone()).await.expect("a block");
    assert_eq!(hashes(&block.transactions), hashes(&offered));
}

/// A block signed by the right proposer on top of genesis, carrying `txs`.
fn forged_block(node: &Node, validator: &KeyPair, txs: Vec<SignedTransaction>) -> Block {
    let parent = node.consensus.get_block_by_height(0).expect("genesis block");
    let tx_root = Hash::merkle_root(&hashes(&txs));
    let mut header = BlockHeader::new(
        parent.hash(),
        1,
        parent.header.timestamp + 1_000,
        tx_root,
        Hash::ZERO,
        *validator.public_key().as_bytes(),
    );
    let sig = sign(header.signing_hash().as_bytes(), validator.private_key());
    header.set_signature(*sig.as_bytes());
    Block::new(header, txs)
}

#[tokio::test]
async fn the_importer_refuses_an_over_budget_block_before_executing_it() {
    let f = fixture(Some(1), Some(1_500_000));
    let node = Node::new(&f.genesis, *f.validator.private_key().as_bytes());
    let [a, b] = [&f.senders[0], &f.senders[1]];
    let block = forged_block(
        &node,
        &f.validator,
        vec![deploy(a, 0, 1_000_000), deploy(b, 0, 1_000_000)],
    );
    let err = node.consensus.import_block(block.clone()).await.unwrap_err();
    assert!(
        err.to_string().contains("declared contract gas exceeds the block budget"),
        "{err}"
    );
    // Nothing executed, nothing stored.
    assert_eq!(node.state.get_nonce(&a.address()).unwrap(), 0);
    assert!(node
        .db
        .get(cf::BLOCKS, block.hash().as_bytes())
        .unwrap()
        .is_none());
    assert_eq!(node.consensus.current_height(), 0);

    // The same block a height below the gate is not refused for its gas (it
    // may still fail for its unset state root, which is not this rule).
    let f = fixture(Some(2), Some(1_500_000));
    let node = Node::new(&f.genesis, *f.validator.private_key().as_bytes());
    let block = forged_block(
        &node,
        &f.validator,
        vec![deploy(a, 0, 1_000_000), deploy(b, 0, 1_000_000)],
    );
    if let Err(e) = node.consensus.import_block(block).await {
        assert!(!e.to_string().contains("contract gas"), "{e}");
    }
}

/// Budget = ceiling: the proposer takes exactly one ceiling transaction, the
/// importer refuses a block declaring two before executing either.
#[tokio::test]
async fn at_a_budget_equal_to_the_ceiling_one_ceiling_transaction_fits() {
    let ceiling = 2_000_000;
    let f = fixture(Some(1), Some(ceiling));
    assert_eq!(f.genesis.params.max_contract_gas, ceiling);
    let node = Node::new(&f.genesis, *f.validator.private_key().as_bytes());
    let [a, b] = [&f.senders[0], &f.senders[1]];
    let offered = vec![deploy(a, 0, ceiling), deploy(b, 0, ceiling), transfer(b, 1)];
    let block = node.consensus.propose_block(offered.clone()).await.expect("a block");
    assert_eq!(hashes(&block.transactions), hashes(&offered[..1]));

    let f = fixture(Some(1), Some(ceiling));
    let node = Node::new(&f.genesis, *f.validator.private_key().as_bytes());
    let forged = forged_block(&node, &f.validator, vec![deploy(a, 0, ceiling), deploy(b, 0, 1)]);
    let err = node.consensus.import_block(forged).await.unwrap_err();
    assert!(err.to_string().contains("declared contract gas exceeds the block budget"), "{err}");
    assert_eq!(node.state.get_nonce(&a.address()).unwrap(), 0, "nothing executed");
}

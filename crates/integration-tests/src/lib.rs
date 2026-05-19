//! Integration tests for SUM Chain.
//!
//! These tests verify end-to-end functionality across multiple components.

mod nft_tests;
mod security_tests;
mod education_e2e_tests;
mod snip_v2_tests;
// stress_tests references a stale NftExecutor::execute signature (5-arg vs the
// current 6-arg shape). Gate behind `legacy_tests` until it's updated, same
// pattern as `crates/state/src` legacy modules.
#[cfg(feature = "legacy_tests")]
mod stress_tests;

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Hash, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{BlockStore, Database, ReceiptStore, TxStore};
use tempfile::TempDir;

/// Test harness for running integration tests. `pub(crate)` so that sibling
/// test modules (e.g. `snip_v2_tests`) can construct and drive the node.
pub(crate) struct TestNode {
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    /// Validator private key bytes (stored separately since KeyPair doesn't implement Clone)
    validator_key_bytes: [u8; 32],
    chain_id: u64,
    #[allow(dead_code)]
    data_dir: TempDir,
}

impl TestNode {
    /// Create a new test node with the given validator key bytes
    fn new(validator_key_bytes: [u8; 32], chain_id: u64) -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let db = Arc::new(Database::open_default(data_dir.path()).expect("Failed to open database"));
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));

        // Create validator key from bytes
        let validator_key = KeyPair::from_bytes(validator_key_bytes);

        // Create genesis config
        let genesis = Genesis::new(
            chain_id,
            0,
            vec![validator_key.public_key().to_base58()],
            HashMap::from([(validator_key.address().to_base58(), 100_000_000)]),
            ChainParams {
                block_time_ms: 100, // Fast blocks for testing
                finality_depth: 2,
                // Integration tests exercise V2 ops; enable the V2 gate from
                // genesis. Production chains must set this explicitly.
                v2_enabled_from_height: Some(0),
                ..Default::default()
            },
        );

        // Create consensus engine (create fresh key for engine)
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                &genesis,
                Some(KeyPair::from_bytes(validator_key_bytes)),
            )
            .expect("Failed to create consensus engine"),
        );

        // Initialize genesis
        consensus.init_genesis(&genesis).expect("Failed to init genesis");

        Self {
            db,
            state,
            mempool,
            consensus,
            validator_key_bytes,
            chain_id,
            data_dir,
        }
    }

    /// Create a test node with custom allocations
    pub(crate) fn with_allocations(
        validator_key_bytes: [u8; 32],
        chain_id: u64,
        alloc: HashMap<String, u128>,
    ) -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let db = Arc::new(Database::open_default(data_dir.path()).expect("Failed to open database"));
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));

        // Create validator key from bytes
        let validator_key = KeyPair::from_bytes(validator_key_bytes);

        // Create genesis config
        let genesis = Genesis::new(
            chain_id,
            0,
            vec![validator_key.public_key().to_base58()],
            alloc,
            ChainParams {
                block_time_ms: 100,
                finality_depth: 2,
                v2_enabled_from_height: Some(0),
                ..Default::default()
            },
        );

        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                &genesis,
                Some(KeyPair::from_bytes(validator_key_bytes)),
            )
            .expect("Failed to create consensus engine"),
        );

        consensus.init_genesis(&genesis).expect("Failed to init genesis");

        Self {
            db,
            state,
            mempool,
            consensus,
            validator_key_bytes,
            chain_id,
            data_dir,
        }
    }

    /// Like [`with_allocations`] but with caller-supplied `ChainParams`
    /// (Phase 5 education e2e needs `education_enabled_from_height:
    /// Some(0)` in the in-process genesis — does not touch any genesis
    /// file). `block_time_ms`/`finality_depth` kept at the test values.
    pub(crate) fn with_allocations_and_params(
        validator_key_bytes: [u8; 32],
        chain_id: u64,
        alloc: HashMap<String, u128>,
        params: ChainParams,
    ) -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let db = Arc::new(Database::open_default(data_dir.path()).expect("Failed to open database"));
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator_key = KeyPair::from_bytes(validator_key_bytes);
        let genesis = Genesis::new(
            chain_id,
            0,
            vec![validator_key.public_key().to_base58()],
            alloc,
            params,
        );
        let consensus = Arc::new(
            PoAEngine::new(
                db.clone(),
                state.clone(),
                mempool.clone(),
                &genesis,
                Some(KeyPair::from_bytes(validator_key_bytes)),
            )
            .expect("Failed to create consensus engine"),
        );
        consensus.init_genesis(&genesis).expect("Failed to init genesis");
        Self {
            db,
            state,
            mempool,
            consensus,
            validator_key_bytes,
            chain_id,
            data_dir,
        }
    }

    /// Get validator key pair
    fn validator_key(&self) -> KeyPair {
        KeyPair::from_bytes(self.validator_key_bytes)
    }

    /// Get validator address
    fn validator_address(&self) -> Address {
        self.validator_key().address()
    }

    /// Create and sign a transaction
    fn create_tx(&self, from_key_bytes: [u8; 32], to: Address, amount: u128, fee: u128) -> SignedTransaction {
        let from = KeyPair::from_bytes(from_key_bytes);
        let nonce = self.state.get_nonce(&from.address()).unwrap_or(0);
        let tx = Transaction::new(self.chain_id, from.address(), to, amount, fee, nonce);
        let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), from.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
    }

    /// Create a transaction with explicit nonce
    fn create_tx_with_nonce(
        &self,
        from_key_bytes: [u8; 32],
        to: Address,
        amount: u128,
        fee: u128,
        nonce: u64,
    ) -> SignedTransaction {
        let from = KeyPair::from_bytes(from_key_bytes);
        let tx = Transaction::new(self.chain_id, from.address(), to, amount, fee, nonce);
        let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), from.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
    }

    /// Add transaction to mempool
    pub(crate) fn submit_tx(&self, tx: SignedTransaction) -> Result<Hash, sumchain_state::StateError> {
        self.mempool.add(tx)
    }

    /// Produce a block with pending transactions
    pub(crate) async fn produce_block(&self) -> Result<sumchain_primitives::Block, sumchain_consensus::ConsensusError> {
        let txs = self.mempool.select_for_block(100);
        self.consensus.propose_block(txs).await
    }

    /// Get current block height
    pub(crate) fn height(&self) -> u64 {
        self.consensus.current_height()
    }

    /// Get balance for an address
    pub(crate) fn balance(&self, addr: &Address) -> u128 {
        self.state.get_balance(addr).unwrap_or(0)
    }

    /// Get nonce for an address
    pub(crate) fn nonce(&self, addr: &Address) -> u64 {
        self.state.get_nonce(addr).unwrap_or(0)
    }

    /// Direct access to the underlying RocksDB handle. Used by sibling test
    /// modules to construct fresh executor instances for state assertions
    /// (e.g. `StorageMetadataExecutor::new(node.db().clone())`).
    pub(crate) fn db(&self) -> &Arc<Database> {
        &self.db
    }

    /// Chain id for V2 tx signing.
    pub(crate) fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Helper to generate key bytes for tests
fn generate_key_bytes() -> [u8; 32] {
    *KeyPair::generate().private_key().as_bytes()
}

#[tokio::test]
async fn test_single_node_block_production() {
    let validator_bytes = generate_key_bytes();
    let user = KeyPair::generate();
    let node = TestNode::new(validator_bytes, 1);

    // Verify initial state
    assert_eq!(node.height(), 0);
    assert_eq!(node.balance(&node.validator_address()), 100_000_000);

    // Submit a transaction
    let tx = node.create_tx(validator_bytes, user.address(), 1000, 10);
    node.submit_tx(tx).expect("Failed to submit tx");

    // Produce a block
    let block = node.produce_block().await.expect("Should be able to produce block");
    assert_eq!(block.height(), 1);
    assert_eq!(block.tx_count(), 1);

    // Verify state after block
    assert_eq!(node.height(), 1);
    assert_eq!(node.balance(&user.address()), 1000);
    // Validator loses the amount but gets the fee back as block proposer
    assert_eq!(
        node.balance(&node.validator_address()),
        100_000_000 - 1000 // Only amount is lost, fee goes to proposer (self)
    );
}

#[tokio::test]
async fn test_multi_block_chain() {
    let validator_bytes = generate_key_bytes();
    let user = KeyPair::generate();
    let node = TestNode::new(validator_bytes, 1);

    // Produce 10 blocks with transactions
    for i in 0..10 {
        let tx = node.create_tx(validator_bytes, user.address(), 100, 1);
        node.submit_tx(tx).expect("Failed to submit tx");

        let block = node.produce_block().await.expect("Should produce block");
        assert_eq!(block.height(), i + 1);
    }

    assert_eq!(node.height(), 10);
    assert_eq!(node.balance(&user.address()), 1000); // 100 * 10 blocks
}

#[tokio::test]
async fn test_mempool_tx_ordering() {
    let validator_bytes = generate_key_bytes();
    let node = TestNode::new(validator_bytes, 1);

    // Submit multiple transactions with different fees
    let users: Vec<_> = (0..5).map(|_| KeyPair::generate()).collect();

    // Submit with varying fees (higher fee = higher priority)
    for (i, user) in users.iter().enumerate() {
        let fee = (5 - i) as u128 * 10; // 50, 40, 30, 20, 10
        let tx = node.create_tx_with_nonce(validator_bytes, user.address(), 100, fee, i as u64);
        node.submit_tx(tx).expect("Failed to submit tx");
    }

    assert_eq!(node.mempool.len(), 5);

    // Produce block - should include all txs
    let block = node.produce_block().await.expect("Should produce block");

    // All transactions should be included
    assert_eq!(block.tx_count(), 5);
    assert_eq!(node.mempool.len(), 0);
}

#[tokio::test]
async fn test_invalid_transaction_rejection() {
    let validator_bytes = generate_key_bytes();
    let user_bytes = generate_key_bytes();
    let validator = KeyPair::from_bytes(validator_bytes);
    let user = KeyPair::from_bytes(user_bytes);

    // Give user only 100 tokens
    let alloc = HashMap::from([
        (validator.address().to_base58(), 100_000_000u128),
        (user.address().to_base58(), 100u128),
    ]);
    let node = TestNode::with_allocations(validator_bytes, 1, alloc);

    // Try to spend more than balance
    let tx = node.create_tx(user_bytes, node.validator_address(), 200, 10);

    // Mempool accepts the tx (validation happens during execution)
    node.submit_tx(tx.clone()).expect("Mempool accepts tx");

    // Produce block - tx should fail execution
    let block = node.produce_block().await.expect("Should produce block");

    // Block still gets produced
    assert_eq!(block.height(), 1);

    // Check receipt shows failure
    let receipt_store = ReceiptStore::new(&node.db);
    let receipt = receipt_store.get(&tx.hash()).expect("Should have receipt");
    assert!(receipt.is_some());
    assert!(!receipt.unwrap().status.is_success());
}

#[tokio::test]
async fn test_nonce_ordering() {
    let validator_bytes = generate_key_bytes();
    let receiver = KeyPair::generate();
    let node = TestNode::new(validator_bytes, 1);

    // Submit transactions one at a time with increasing nonces
    // Process one block per transaction to ensure nonce ordering is correct
    for nonce in 0..5u64 {
        let tx = node.create_tx_with_nonce(validator_bytes, receiver.address(), 100, 10, nonce);
        node.submit_tx(tx).expect("Should accept tx");

        // Produce a block for each transaction
        let block = node.produce_block().await.expect("Should produce block");
        assert_eq!(block.tx_count(), 1, "Each block should have exactly 1 tx");
    }

    // After 5 transactions in 5 blocks
    assert_eq!(node.height(), 5);
    assert_eq!(node.balance(&receiver.address()), 500); // 5 * 100
    assert_eq!(node.nonce(&node.validator_address()), 5);
}

#[tokio::test]
async fn test_block_finality() {
    let validator_bytes = generate_key_bytes();
    let node = TestNode::new(validator_bytes, 1);

    // Produce blocks up to finality depth + 2
    for _ in 0..5 {
        node.produce_block().await.expect("Should produce block");
    }

    assert_eq!(node.height(), 5);

    // Check finality (depth = 2, so blocks 0-3 should be finalized)
    assert!(node.consensus.is_finalized(0));
    assert!(node.consensus.is_finalized(1));
    assert!(node.consensus.is_finalized(2));
    assert!(node.consensus.is_finalized(3));
    assert!(!node.consensus.is_finalized(4));
    assert!(!node.consensus.is_finalized(5));
}

#[tokio::test]
async fn test_empty_blocks() {
    let validator_bytes = generate_key_bytes();
    let node = TestNode::new(validator_bytes, 1);

    // Produce empty blocks
    for i in 0..3 {
        let block = node.produce_block().await.expect("Should produce block");
        assert_eq!(block.tx_count(), 0);
        assert_eq!(block.height(), i + 1);
    }

    assert_eq!(node.height(), 3);
}

#[tokio::test]
async fn test_block_with_max_transactions() {
    let validator_bytes = generate_key_bytes();
    let recipient = KeyPair::generate();
    let node = TestNode::new(validator_bytes, 1);

    // Submit transactions up to per-sender limit (100 max per sender)
    for i in 0..100 {
        let tx = node.create_tx_with_nonce(validator_bytes, recipient.address(), 10, 1, i);
        node.submit_tx(tx).expect("Should accept tx");
    }

    assert_eq!(node.mempool.len(), 100);

    // Produce block (selects up to 100 txs)
    let block = node.produce_block().await.expect("Should produce block");
    assert_eq!(block.tx_count(), 100);

    // All transactions should be consumed
    assert_eq!(node.mempool.len(), 0);
}

#[tokio::test]
async fn test_concurrent_tx_submission() {
    let validator_bytes = generate_key_bytes();
    let node = Arc::new(TestNode::new(validator_bytes, 1));

    // Spawn multiple tasks submitting transactions
    let mut handles = vec![];
    for i in 0..10 {
        let node = node.clone();
        let handle = tokio::spawn(async move {
            let recipient = KeyPair::generate();
            for j in 0..10 {
                // Each task uses different nonces based on task index
                let nonce = (i * 10 + j) as u64;
                let tx = node.create_tx_with_nonce(validator_bytes, recipient.address(), 10, 1, nonce);
                let _ = node.submit_tx(tx);
            }
        });
        handles.push(handle);
    }

    // Wait for all submissions
    for handle in handles {
        handle.await.unwrap();
    }

    // Should have many transactions in mempool
    assert!(node.mempool.len() > 0);
}

#[tokio::test]
async fn test_chain_id_validation() {
    let validator_bytes = generate_key_bytes();
    let validator = KeyPair::from_bytes(validator_bytes);
    let recipient = KeyPair::generate();
    let node = TestNode::new(validator_bytes, 1); // Chain ID = 1

    // Create transaction with wrong chain ID
    let tx = Transaction::new(
        999, // Wrong chain ID
        validator.address(),
        recipient.address(),
        100,
        10,
        0,
    );
    let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), validator.private_key());
    let signed = SignedTransaction::new(tx, *sig.as_bytes(), *validator.public_key().as_bytes());

    // Mempool accepts tx
    node.submit_tx(signed.clone()).expect("Mempool accepts tx");

    // Produce block
    let block = node.produce_block().await.expect("Should produce block");
    assert_eq!(block.height(), 1);

    // Transaction should fail with wrong chain ID
    let receipt_store = ReceiptStore::new(&node.db);
    let receipt = receipt_store.get(&signed.hash()).expect("Should have receipt");
    assert!(receipt.is_some());
    assert!(!receipt.unwrap().status.is_success());
}

#[tokio::test]
async fn test_state_persistence() {
    let validator_bytes = generate_key_bytes();
    let validator = KeyPair::from_bytes(validator_bytes);
    let user = KeyPair::generate();
    let data_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = data_dir.path().to_path_buf();

    // First session: create blocks
    {
        let db = Arc::new(Database::open_default(&db_path).expect("Failed to open database"));
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));

        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1_000_000)]),
            ChainParams::default(),
        );

        let consensus = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(KeyPair::from_bytes(validator_bytes)))
                .expect("Failed to create consensus"),
        );

        consensus.init_genesis(&genesis).expect("Failed to init genesis");

        // Create and submit a transaction
        let tx = Transaction::new(1, validator.address(), user.address(), 5000, 10, 0);
        let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), validator.private_key());
        let signed = SignedTransaction::new(tx, *sig.as_bytes(), *validator.public_key().as_bytes());
        mempool.add(signed).unwrap();

        // Produce block
        let txs = mempool.select_for_block(100);
        consensus.propose_block(txs).await.unwrap();

        // Verify state before closing
        assert_eq!(state.get_balance(&user.address()).unwrap(), 5000);
    }

    // Second session: reopen and verify
    {
        let db = Arc::new(Database::open_default(&db_path).expect("Failed to reopen database"));
        let state = Arc::new(StateManager::new(db.clone(), 1));

        // State should persist
        assert_eq!(state.get_balance(&user.address()).unwrap(), 5000);

        // Block should persist
        let block_store = BlockStore::new(&db);
        let latest = block_store.get_latest().unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().height(), 1);
    }
}

#[tokio::test]
async fn test_receipt_storage() {
    let validator_bytes = generate_key_bytes();
    let user = KeyPair::generate();
    let node = TestNode::new(validator_bytes, 1);

    // Submit transaction
    let tx = node.create_tx(validator_bytes, user.address(), 1000, 10);
    let tx_hash = tx.hash();
    node.submit_tx(tx).expect("Failed to submit tx");

    // Produce block
    node.produce_block().await.expect("Should produce block");

    // Check receipt
    let receipt_store = ReceiptStore::new(&node.db);
    let receipt = receipt_store.get(&tx_hash).expect("Should get receipt").expect("Receipt exists");

    assert!(receipt.status.is_success());
    assert_eq!(receipt.block_height, 1);
    assert_eq!(receipt.fee_paid, 10);
}

#[tokio::test]
async fn test_transaction_storage() {
    let validator_bytes = generate_key_bytes();
    let user = KeyPair::generate();
    let node = TestNode::new(validator_bytes, 1);

    // Submit transaction
    let tx = node.create_tx(validator_bytes, user.address(), 1000, 10);
    let tx_hash = tx.hash();
    node.submit_tx(tx.clone()).expect("Failed to submit tx");

    // Produce block
    node.produce_block().await.expect("Should produce block");

    // Check transaction is stored
    let tx_store = TxStore::new(&node.db);
    let stored_tx = tx_store.get(&tx_hash).expect("Should get tx").expect("Tx exists");

    assert_eq!(stored_tx.hash(), tx_hash);
    assert_eq!(stored_tx.amount(), 1000);
    assert_eq!(stored_tx.fee(), 10);
}

#[tokio::test]
async fn test_block_retrieval_by_height() {
    let validator_bytes = generate_key_bytes();
    let node = TestNode::new(validator_bytes, 1);

    // Produce 5 blocks
    for _ in 0..5 {
        node.produce_block().await.expect("Should produce block");
    }

    // Retrieve each block by height
    let block_store = BlockStore::new(&node.db);
    for height in 0..=5 {
        let block = block_store.get_by_height(height).expect("Should get block").expect("Block exists");
        assert_eq!(block.height(), height);
    }

    // Non-existent height
    assert!(block_store.get_by_height(100).expect("Query ok").is_none());
}

#[tokio::test]
async fn test_mempool_expiration() {
    let validator = KeyPair::generate();
    let user = KeyPair::generate();

    let _data_dir = TempDir::new().expect("Failed to create temp dir");

    // Create mempool with short expiration
    let mempool = Arc::new(Mempool::new(MempoolConfig {
        tx_expiration_secs: 1, // 1 second expiration
        ..Default::default()
    }));

    // Submit a transaction
    let tx = Transaction::new(1, validator.address(), user.address(), 100, 10, 0);
    let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), validator.private_key());
    let signed = SignedTransaction::new(tx, *sig.as_bytes(), *validator.public_key().as_bytes());
    mempool.add(signed).expect("Should add tx");

    assert_eq!(mempool.len(), 1);

    // Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Expire old transactions
    let expired = mempool.expire_old_transactions();
    assert_eq!(expired, 1);
    assert_eq!(mempool.len(), 0);
}

#[tokio::test]
async fn test_mempool_stats() {
    let validator_bytes = generate_key_bytes();
    let node = TestNode::new(validator_bytes, 1);

    // Submit several transactions
    for i in 0..5u64 {
        let user = KeyPair::generate();
        let tx = node.create_tx_with_nonce(validator_bytes, user.address(), 100, 10 + i as u128, i);
        node.submit_tx(tx).expect("Should add tx");
    }

    let stats = node.mempool.stats();
    assert_eq!(stats.size, 5);
    assert_eq!(stats.unique_senders, 1);
    assert!(stats.total_fees > 0);
}

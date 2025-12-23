//! Performance and Stress Tests for SUM Chain
//!
//! These tests measure throughput, latency, and system behavior under load.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use sumchain_consensus::PoAEngine;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Hash, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tempfile::TempDir;

/// Performance test node
struct PerfNode {
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<PoAEngine>,
    validator_key_bytes: [u8; 32],
    chain_id: u64,
    #[allow(dead_code)]
    data_dir: TempDir,
}

impl PerfNode {
    fn new(validator_key_bytes: [u8; 32], chain_id: u64, initial_balance: u128) -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let db = Arc::new(Database::open_default(data_dir.path()).expect("Failed to open database"));
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));

        let validator_key = KeyPair::from_bytes(validator_key_bytes);

        let genesis = Genesis::new(
            chain_id,
            0,
            vec![validator_key.public_key().to_base58()],
            HashMap::from([(validator_key.address().to_base58(), initial_balance)]),
            ChainParams {
                block_time_ms: 100,
                finality_depth: 1,
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

    fn validator_key(&self) -> KeyPair {
        KeyPair::from_bytes(self.validator_key_bytes)
    }

    fn validator_address(&self) -> Address {
        self.validator_key().address()
    }

    fn create_tx_with_nonce(&self, nonce: u64) -> SignedTransaction {
        let keypair = self.validator_key();
        let tx = Transaction::new(
            self.chain_id,
            keypair.address(),
            Address::new([1u8; 20]),
            1,
            1000,
            nonce,
        );
        let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), keypair.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *keypair.public_key().as_bytes())
    }

    fn create_tx_for_sender(&self, sender: &KeyPair, nonce: u64) -> SignedTransaction {
        let tx = Transaction::new(
            self.chain_id,
            sender.address(),
            Address::new([1u8; 20]),
            1,
            1000,
            nonce,
        );
        let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), sender.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *sender.public_key().as_bytes())
    }

    fn submit_tx(&self, tx: SignedTransaction) -> Result<Hash, String> {
        self.mempool.add(tx).map_err(|e| e.to_string())
    }

    fn fund_account(&self, addr: &Address, balance: u128) {
        self.state
            .put_account(
                addr,
                &sumchain_storage::schema::AccountState { balance, nonce: 0 },
            )
            .expect("Failed to fund account");
    }
}

// ============================================================================
// Mempool Throughput Tests
// ============================================================================

#[test]
fn stress_mempool_insertion_throughput() {
    let validator_bytes = *KeyPair::generate().private_key().as_bytes();
    let node = PerfNode::new(validator_bytes, 1, u128::MAX / 2);

    const TX_COUNT: u64 = 10_000;

    let start = Instant::now();
    for i in 0..TX_COUNT {
        let tx = node.create_tx_with_nonce(i);
        node.submit_tx(tx).expect("Should submit");
    }
    let elapsed = start.elapsed();

    let tps = TX_COUNT as f64 / elapsed.as_secs_f64();
    println!(
        "Mempool insertion: {} txs in {:?} ({:.0} tx/s)",
        TX_COUNT, elapsed, tps
    );

    // Assert minimum throughput
    assert!(
        tps >= 1_000.0,
        "Mempool insertion too slow: {:.0} tx/s (expected >= 1,000)",
        tps
    );

    assert_eq!(node.mempool.stats().size, TX_COUNT as usize);
}

#[test]
fn stress_mempool_with_multiple_senders() {
    let validator_bytes = *KeyPair::generate().private_key().as_bytes();
    let node = PerfNode::new(validator_bytes, 1, u128::MAX / 2);

    const SENDER_COUNT: usize = 50;
    const TX_PER_SENDER: u64 = 100;

    // Generate and fund senders
    let senders: Vec<KeyPair> = (0..SENDER_COUNT).map(|_| KeyPair::generate()).collect();
    for sender in &senders {
        node.fund_account(&sender.address(), 1_000_000_000_000);
    }

    let start = Instant::now();
    for sender in &senders {
        for nonce in 0..TX_PER_SENDER {
            let tx = node.create_tx_for_sender(sender, nonce);
            node.submit_tx(tx).expect("Should submit");
        }
    }
    let elapsed = start.elapsed();

    let total_tx = (SENDER_COUNT as u64) * TX_PER_SENDER;
    let tps = total_tx as f64 / elapsed.as_secs_f64();
    println!(
        "Multi-sender mempool: {} txs from {} senders in {:?} ({:.0} tx/s)",
        total_tx, SENDER_COUNT, elapsed, tps
    );

    assert!(tps >= 500.0, "Multi-sender insertion too slow: {:.0} tx/s", tps);

    let stats = node.mempool.stats();
    assert_eq!(stats.size, total_tx as usize);
    assert_eq!(stats.unique_senders, SENDER_COUNT);
}

// ============================================================================
// State Access Tests
// ============================================================================

#[test]
fn stress_account_reads() {
    let validator_bytes = *KeyPair::generate().private_key().as_bytes();
    let node = PerfNode::new(validator_bytes, 1, 1_000_000);

    const ACCOUNT_COUNT: usize = 5_000;

    // Create accounts
    let accounts: Vec<Address> = (0..ACCOUNT_COUNT)
        .map(|i| {
            let mut bytes = [0u8; 20];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            Address::new(bytes)
        })
        .collect();

    // Write accounts
    for (i, addr) in accounts.iter().enumerate() {
        node.state
            .put_account(
                addr,
                &sumchain_storage::schema::AccountState {
                    balance: i as u128 * 1000,
                    nonce: i as u64,
                },
            )
            .expect("Failed to write account");
    }

    // Read accounts
    let start = Instant::now();
    for addr in &accounts {
        let _account = node.state.get_account(addr);
    }
    let elapsed = start.elapsed();

    let reads_per_sec = ACCOUNT_COUNT as f64 / elapsed.as_secs_f64();
    println!(
        "Account reads: {} in {:?} ({:.0} reads/s)",
        ACCOUNT_COUNT, elapsed, reads_per_sec
    );

    assert!(
        reads_per_sec >= 10_000.0,
        "Account reads too slow: {:.0}/s",
        reads_per_sec
    );
}

#[test]
fn stress_account_writes() {
    let validator_bytes = *KeyPair::generate().private_key().as_bytes();
    let node = PerfNode::new(validator_bytes, 1, 1_000_000);

    const WRITE_COUNT: usize = 5_000;

    let start = Instant::now();
    for i in 0..WRITE_COUNT {
        let mut bytes = [0u8; 20];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let addr = Address::new(bytes);

        node.state
            .put_account(
                &addr,
                &sumchain_storage::schema::AccountState {
                    balance: i as u128 * 1000,
                    nonce: i as u64,
                },
            )
            .expect("Failed to write account");
    }
    let elapsed = start.elapsed();

    let writes_per_sec = WRITE_COUNT as f64 / elapsed.as_secs_f64();
    println!(
        "Account writes: {} in {:?} ({:.0} writes/s)",
        WRITE_COUNT, elapsed, writes_per_sec
    );

    assert!(
        writes_per_sec >= 5_000.0,
        "Account writes too slow: {:.0}/s",
        writes_per_sec
    );
}

// ============================================================================
// NFT Performance Tests
// ============================================================================

#[test]
fn stress_nft_minting() {
    use sumchain_genesis::ChainParams;
    use sumchain_nft::collection::CollectionConfig;
    use sumchain_primitives::{NftOperation, NftTxData};
    use sumchain_state::NftExecutor;

    let validator_bytes = *KeyPair::generate().private_key().as_bytes();
    let data_dir = TempDir::new().expect("Failed to create temp dir");
    let db = Arc::new(Database::open_default(data_dir.path()).expect("Failed to open database"));
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let params = ChainParams::default();
    let nft_executor = NftExecutor::new(db.clone(), params.clone());

    let validator_key = KeyPair::from_bytes(validator_bytes);
    let validator_addr = validator_key.address();

    // Fund validator
    state
        .put_account(
            &validator_addr,
            &sumchain_storage::schema::AccountState {
                balance: u128::MAX / 2,
                nonce: 0,
            },
        )
        .expect("Failed to fund validator");

    // Create collection
    #[derive(serde::Serialize)]
    struct CreateCollectionData {
        name: String,
        symbol: String,
        description: String,
        config: CollectionConfig,
        base_uri: Option<String>,
    }

    let create_data = CreateCollectionData {
        name: "Stress Test".to_string(),
        symbol: "STRESS".to_string(),
        description: "Performance testing".to_string(),
        config: CollectionConfig::default(),
        base_uri: None,
    };

    let serialized = bincode::serialize(&create_data).expect("Failed to serialize");
    let nft_data = NftTxData {
        collection_id: [0u8; 32],
        token_id: 0,
        operation: NftOperation::CreateCollection,
        data: serialized,
    };

    let result = nft_executor
        .execute(&validator_addr, &nft_data, &state, &Address::ZERO, params.min_fee)
        .expect("Should create collection");
    let collection_id = result.collection_id.unwrap();

    // Mint many tokens
    const MINT_COUNT: u64 = 500;

    #[derive(serde::Serialize)]
    struct MintData {
        to: Address,
        metadata: Vec<u8>,
        uri_type: String,
        uri_value: Option<String>,
    }

    let start = Instant::now();
    for i in 0..MINT_COUNT {
        let mint_data = MintData {
            to: validator_addr,
            metadata: format!("{{\"id\":{}}}", i).into_bytes(),
            uri_type: "onchain".to_string(),
            uri_value: None,
        };
        let serialized = bincode::serialize(&mint_data).expect("Failed to serialize");

        // Calculate fee based on metadata size
        let metadata_size = format!("{{\"id\":{}}}", i).len();
        let fee = params.calculate_nft_storage_fee(metadata_size);

        let nft_data = NftTxData {
            collection_id,
            token_id: 0,
            operation: NftOperation::Mint,
            data: serialized,
        };

        let result = nft_executor
            .execute(&validator_addr, &nft_data, &state, &Address::ZERO, fee)
            .expect("Should mint");
        assert!(result.success, "Mint failed: {:?}", result.error);
    }
    let elapsed = start.elapsed();

    let mints_per_sec = MINT_COUNT as f64 / elapsed.as_secs_f64();
    println!(
        "NFT minting: {} tokens in {:?} ({:.0} mints/s)",
        MINT_COUNT, elapsed, mints_per_sec
    );

    assert!(
        mints_per_sec >= 100.0,
        "NFT minting too slow: {:.0}/s",
        mints_per_sec
    );
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

#[test]
fn stress_concurrent_mempool_access() {
    use std::thread;

    let validator_bytes = *KeyPair::generate().private_key().as_bytes();
    let node = Arc::new(PerfNode::new(validator_bytes, 1, u128::MAX / 2));

    const THREAD_COUNT: usize = 4;
    const TX_PER_THREAD: u64 = 500;

    // Create senders for each thread
    let senders: Vec<KeyPair> = (0..THREAD_COUNT).map(|_| KeyPair::generate()).collect();
    for sender in &senders {
        node.fund_account(&sender.address(), 1_000_000_000_000);
    }

    let start = Instant::now();
    let handles: Vec<_> = senders
        .into_iter()
        .map(|sender| {
            let node = Arc::clone(&node);
            thread::spawn(move || {
                for nonce in 0..TX_PER_THREAD {
                    let tx = node.create_tx_for_sender(&sender, nonce);
                    node.mempool.add(tx).expect("Should submit");
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
    let elapsed = start.elapsed();

    let total_tx = (THREAD_COUNT as u64) * TX_PER_THREAD;
    let tps = total_tx as f64 / elapsed.as_secs_f64();
    println!(
        "Concurrent mempool: {} txs from {} threads in {:?} ({:.0} tx/s)",
        total_tx, THREAD_COUNT, elapsed, tps
    );

    assert_eq!(node.mempool.stats().size, total_tx as usize);
    assert!(tps >= 500.0, "Concurrent insertion too slow: {:.0} tx/s", tps);
}

// ============================================================================
// Benchmark Summary
// ============================================================================

#[test]
fn benchmark_summary() {
    println!("\n========================================");
    println!("SUM Chain Performance Benchmarks");
    println!("========================================\n");
    println!("Run stress tests with:");
    println!("  cargo test -p sumchain-integration-tests stress_ -- --nocapture\n");
    println!("Target Performance:");
    println!("  - Mempool insertion: >= 1,000 tx/s");
    println!("  - Multi-sender mempool: >= 500 tx/s");
    println!("  - Account reads: >= 10,000/s");
    println!("  - Account writes: >= 5,000/s");
    println!("  - NFT minting: >= 100/s");
    println!("  - Concurrent mempool: >= 500 tx/s");
    println!("========================================\n");
}

//! Transaction mempool for SUM Chain.
//!
//! Stores pending transactions, sorted by fee for block inclusion.

use std::collections::{BTreeMap, HashMap, HashSet};

use parking_lot::RwLock;
use sumchain_primitives::{Address, Balance, Hash, Nonce, SignedTransaction};
use tracing::{debug, info};

use crate::{Result, StateError, StateManager};

/// Mempool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions
    pub max_size: usize,
    /// Maximum transactions per sender
    pub max_per_sender: usize,
    /// Minimum fee for acceptance
    pub min_fee: Balance,
    /// Transaction expiration time in seconds (0 = no expiration)
    pub tx_expiration_secs: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            max_per_sender: 100,
            min_fee: 1,
            tx_expiration_secs: 3600, // 1 hour default
        }
    }
}

/// Transaction entry in mempool
#[derive(Debug, Clone)]
struct TxEntry {
    tx: SignedTransaction,
    fee: Balance,
    #[allow(dead_code)]
    received_at: u64, // Timestamp - reserved for future eviction policy
}

/// Transaction mempool
pub struct Mempool {
    /// All transactions by hash
    txs: RwLock<HashMap<Hash, TxEntry>>,
    /// Transactions by sender address
    by_sender: RwLock<HashMap<Address, HashSet<Hash>>>,
    /// Transactions sorted by fee (descending) for selection
    by_fee: RwLock<BTreeMap<(Balance, Hash), Hash>>,
    /// Configuration
    config: MempoolConfig,
}

impl Mempool {
    /// Create a new mempool
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            txs: RwLock::new(HashMap::new()),
            by_sender: RwLock::new(HashMap::new()),
            by_fee: RwLock::new(BTreeMap::new()),
            config,
        }
    }

    /// Add a transaction to the mempool
    pub fn add(&self, tx: SignedTransaction) -> Result<Hash> {
        let hash = tx.hash();
        let sender = tx.sender();
        let fee = tx.fee();

        // Check if already exists
        if self.txs.read().contains_key(&hash) {
            return Err(StateError::TxAlreadyExists);
        }

        // Check mempool size
        if self.txs.read().len() >= self.config.max_size {
            // Try to evict lowest fee tx
            if !self.try_evict_lowest_fee(fee) {
                return Err(StateError::MempoolFull);
            }
        }

        // Check per-sender limit
        {
            let by_sender = self.by_sender.read();
            if let Some(sender_txs) = by_sender.get(&sender) {
                if sender_txs.len() >= self.config.max_per_sender {
                    return Err(StateError::MempoolFull);
                }
            }
        }

        // Check minimum fee
        if fee < self.config.min_fee {
            return Err(StateError::FeeTooLow {
                minimum: self.config.min_fee,
                got: fee,
            });
        }

        // Add to all indexes
        let entry = TxEntry {
            tx,
            fee,
            received_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        };

        self.txs.write().insert(hash, entry);
        self.by_sender
            .write()
            .entry(sender)
            .or_insert_with(HashSet::new)
            .insert(hash);

        // Use negative fee for descending order in BTreeMap
        let fee_key = (Balance::MAX - fee, hash);
        self.by_fee.write().insert(fee_key, hash);

        debug!("Added tx {} to mempool (fee: {})", hash, fee);

        Ok(hash)
    }

    /// Remove a transaction from the mempool
    pub fn remove(&self, hash: &Hash) -> Option<SignedTransaction> {
        let entry = self.txs.write().remove(hash)?;
        let sender = entry.tx.sender();

        // Remove from by_sender index
        {
            let mut by_sender = self.by_sender.write();
            if let Some(sender_txs) = by_sender.get_mut(&sender) {
                sender_txs.remove(hash);
                if sender_txs.is_empty() {
                    by_sender.remove(&sender);
                }
            }
        }

        // Remove from by_fee index
        let fee_key = (Balance::MAX - entry.fee, *hash);
        self.by_fee.write().remove(&fee_key);

        debug!("Removed tx {} from mempool", hash);

        Some(entry.tx)
    }

    /// Remove multiple transactions (e.g., after block inclusion)
    pub fn remove_batch(&self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove(hash);
        }
    }

    /// Get a transaction by hash
    pub fn get(&self, hash: &Hash) -> Option<SignedTransaction> {
        self.txs.read().get(hash).map(|e| e.tx.clone())
    }

    /// Check if a transaction exists
    pub fn contains(&self, hash: &Hash) -> bool {
        self.txs.read().contains_key(hash)
    }

    /// Get transactions for a sender
    pub fn get_by_sender(&self, sender: &Address) -> Vec<SignedTransaction> {
        let by_sender = self.by_sender.read();
        let txs = self.txs.read();

        match by_sender.get(sender) {
            Some(hashes) => hashes
                .iter()
                .filter_map(|h| txs.get(h).map(|e| e.tx.clone()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get next nonce for a sender (current nonce + pending tx count)
    pub fn pending_nonce(&self, sender: &Address, current_nonce: Nonce) -> Nonce {
        let by_sender = self.by_sender.read();
        match by_sender.get(sender) {
            Some(hashes) => current_nonce + hashes.len() as u64,
            None => current_nonce,
        }
    }

    /// Select transactions for a new block (sorted by fee, highest first)
    pub fn select_for_block(&self, max_count: usize) -> Vec<SignedTransaction> {
        let by_fee = self.by_fee.read();
        let txs = self.txs.read();

        by_fee
            .values()
            .take(max_count)
            .filter_map(|hash| txs.get(hash).map(|e| e.tx.clone()))
            .collect()
    }

    /// Get mempool size
    pub fn len(&self) -> usize {
        self.txs.read().len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.txs.read().is_empty()
    }

    /// Get all transactions in the mempool
    pub fn get_all(&self) -> Vec<SignedTransaction> {
        self.txs.read().values().map(|e| e.tx.clone()).collect()
    }

    /// Clear all transactions
    pub fn clear(&self) {
        self.txs.write().clear();
        self.by_sender.write().clear();
        self.by_fee.write().clear();
        info!("Mempool cleared");
    }

    /// Try to evict the lowest fee transaction to make room
    fn try_evict_lowest_fee(&self, new_fee: Balance) -> bool {
        let by_fee = self.by_fee.write();

        // Get lowest fee tx (last in BTreeMap since we use MAX - fee)
        if let Some((fee_key, hash)) = by_fee.iter().next_back().map(|(k, v)| (*k, *v)) {
            let lowest_fee = Balance::MAX - fee_key.0;

            if new_fee > lowest_fee {
                // New tx has higher fee, evict the old one
                drop(by_fee);
                self.remove(&hash);
                debug!("Evicted low-fee tx {} (fee: {})", hash, lowest_fee);
                return true;
            }
        }

        false
    }

    /// Revalidate all transactions against current state
    pub fn revalidate(&self, state: &StateManager, chain_id: u64) {
        let hashes: Vec<Hash> = self.txs.read().keys().cloned().collect();
        let mut to_remove = Vec::new();

        for hash in hashes {
            if let Some(tx) = self.get(&hash) {
                // Check basic validity
                if tx.chain_id() != chain_id {
                    to_remove.push(hash);
                    continue;
                }

                // Check nonce
                let sender = tx.sender();
                if let Ok(current_nonce) = state.get_nonce(&sender) {
                    if tx.nonce() < current_nonce {
                        to_remove.push(hash);
                        continue;
                    }
                }

                // Check balance
                if let Ok(balance) = state.get_balance(&sender) {
                    let total_cost = tx.amount().saturating_add(tx.fee());
                    if balance < total_cost {
                        to_remove.push(hash);
                    }
                }
            }
        }

        if !to_remove.is_empty() {
            info!("Revalidation removing {} stale transactions", to_remove.len());
            self.remove_batch(&to_remove);
        }
    }

    /// Remove expired transactions from the mempool
    /// Returns the number of transactions removed
    pub fn expire_old_transactions(&self) -> usize {
        if self.config.tx_expiration_secs == 0 {
            return 0; // Expiration disabled
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let expiration_threshold = now.saturating_sub(self.config.tx_expiration_secs * 1000);

        let mut to_remove = Vec::new();

        {
            let txs = self.txs.read();
            for (hash, entry) in txs.iter() {
                if entry.received_at < expiration_threshold {
                    to_remove.push(*hash);
                }
            }
        }

        let count = to_remove.len();
        if count > 0 {
            info!("Expiring {} old transactions from mempool", count);
            self.remove_batch(&to_remove);
        }

        count
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let txs = self.txs.read();
        let by_sender = self.by_sender.read();

        let mut total_fees = 0u128;
        let mut oldest_tx_age_ms = 0u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        for entry in txs.values() {
            total_fees += entry.fee as u128;
            let age = now.saturating_sub(entry.received_at);
            if age > oldest_tx_age_ms {
                oldest_tx_age_ms = age;
            }
        }

        MempoolStats {
            size: txs.len(),
            unique_senders: by_sender.len(),
            total_fees,
            oldest_tx_age_secs: oldest_tx_age_ms / 1000,
            max_size: self.config.max_size,
        }
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Current number of transactions
    pub size: usize,
    /// Number of unique senders
    pub unique_senders: usize,
    /// Total fees of all transactions
    pub total_fees: u128,
    /// Age of the oldest transaction in seconds
    pub oldest_tx_age_secs: u64,
    /// Maximum mempool size
    pub max_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::{sign, KeyPair};
    use sumchain_primitives::Transaction;

    fn create_signed_tx(
        kp: &KeyPair,
        to: Address,
        amount: Balance,
        fee: Balance,
        nonce: u64,
    ) -> SignedTransaction {
        let tx = Transaction::new(1, kp.address(), to, amount, fee, nonce);
        let signing_hash = tx.signing_hash();
        let sig = sign(signing_hash.as_bytes(), kp.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }

    #[test]
    fn test_add_and_get() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        let hash = tx.hash();

        mempool.add(tx.clone()).unwrap();

        assert!(mempool.contains(&hash));
        assert_eq!(mempool.get(&hash), Some(tx));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        let hash = tx.hash();

        mempool.add(tx).unwrap();
        assert!(mempool.contains(&hash));

        mempool.remove(&hash);
        assert!(!mempool.contains(&hash));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_duplicate_rejection() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);

        mempool.add(tx.clone()).unwrap();
        let result = mempool.add(tx);

        assert!(matches!(result, Err(StateError::TxAlreadyExists)));
    }

    #[test]
    fn test_fee_sorting() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx1 = create_signed_tx(&sender, recipient.address(), 100, 5, 0);
        let tx2 = create_signed_tx(&sender, recipient.address(), 100, 20, 1);
        let tx3 = create_signed_tx(&sender, recipient.address(), 100, 10, 2);

        mempool.add(tx1).unwrap();
        mempool.add(tx2.clone()).unwrap();
        mempool.add(tx3).unwrap();

        let selected = mempool.select_for_block(1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].fee(), 20); // Highest fee first
    }

    #[test]
    fn test_min_fee() {
        let config = MempoolConfig {
            min_fee: 100,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0); // Fee too low

        let result = mempool.add(tx);
        assert!(matches!(result, Err(StateError::FeeTooLow { .. })));
    }
}

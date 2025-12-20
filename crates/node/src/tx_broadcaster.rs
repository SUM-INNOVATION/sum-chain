//! Transaction rebroadcaster for SUM Chain.
//!
//! Periodically rebroadcasts pending transactions to ensure they
//! propagate across the network, handling peer churn and network partitions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use sumchain_p2p::NetworkCommand;
use sumchain_primitives::{Hash, SignedTransaction};
use sumchain_state::Mempool;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Configuration for transaction rebroadcasting
#[derive(Debug, Clone)]
pub struct TxBroadcasterConfig {
    /// Minimum time between rebroadcasts of the same transaction
    pub min_rebroadcast_interval: Duration,
    /// Maximum number of times to rebroadcast a transaction
    pub max_rebroadcast_count: u32,
    /// How often to check for transactions needing rebroadcast
    pub check_interval: Duration,
    /// Maximum age of a transaction before we stop rebroadcasting
    pub max_tx_age: Duration,
    /// Enable rebroadcasting (can be disabled for testing)
    pub enabled: bool,
}

impl Default for TxBroadcasterConfig {
    fn default() -> Self {
        Self {
            min_rebroadcast_interval: Duration::from_secs(30),
            max_rebroadcast_count: 5,
            check_interval: Duration::from_secs(10),
            max_tx_age: Duration::from_secs(300), // 5 minutes
            enabled: true,
        }
    }
}

/// Tracking information for a pending transaction
#[derive(Debug, Clone)]
struct TxTracker {
    /// When the transaction was first seen
    first_seen: Instant,
    /// When the transaction was last broadcast
    last_broadcast: Instant,
    /// Number of times the transaction has been broadcast
    broadcast_count: u32,
}

impl TxTracker {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            first_seen: now,
            last_broadcast: now,
            broadcast_count: 1,
        }
    }
}

/// Transaction broadcaster that periodically rebroadcasts pending transactions
pub struct TxBroadcaster {
    /// Configuration
    config: TxBroadcasterConfig,
    /// Tracking info for each transaction
    tracking: RwLock<HashMap<Hash, TxTracker>>,
}

impl TxBroadcaster {
    /// Create a new transaction broadcaster
    pub fn new(config: TxBroadcasterConfig) -> Self {
        Self {
            config,
            tracking: RwLock::new(HashMap::new()),
        }
    }

    /// Record that a transaction was broadcast
    pub fn record_broadcast(&self, tx_hash: Hash) {
        let mut tracking = self.tracking.write();
        tracking
            .entry(tx_hash)
            .and_modify(|t| {
                t.last_broadcast = Instant::now();
                t.broadcast_count += 1;
            })
            .or_insert_with(TxTracker::new);
    }

    /// Record that a transaction was removed (included in block or dropped)
    pub fn record_removed(&self, tx_hash: &Hash) {
        self.tracking.write().remove(tx_hash);
    }

    /// Record multiple transactions removed
    pub fn record_batch_removed(&self, tx_hashes: &[Hash]) {
        let mut tracking = self.tracking.write();
        for hash in tx_hashes {
            tracking.remove(hash);
        }
    }

    /// Get transactions that should be rebroadcast
    pub fn get_rebroadcast_candidates(&self, mempool: &Mempool) -> Vec<SignedTransaction> {
        if !self.config.enabled {
            return Vec::new();
        }

        let now = Instant::now();
        let tracking = self.tracking.read();
        let mut candidates = Vec::new();

        for tx in mempool.get_all() {
            let hash = tx.hash();

            if let Some(tracker) = tracking.get(&hash) {
                // Check if we've exceeded max rebroadcast count
                if tracker.broadcast_count >= self.config.max_rebroadcast_count {
                    continue;
                }

                // Check if transaction is too old
                if now.duration_since(tracker.first_seen) > self.config.max_tx_age {
                    continue;
                }

                // Check if enough time has passed since last broadcast
                if now.duration_since(tracker.last_broadcast) < self.config.min_rebroadcast_interval {
                    continue;
                }

                candidates.push(tx);
            } else {
                // Transaction not tracked yet, add it
                drop(tracking);
                self.record_broadcast(hash);
                // Don't add to candidates since we just recorded it as broadcast
                return self.get_rebroadcast_candidates(mempool);
            }
        }

        candidates
    }

    /// Run the rebroadcast loop
    pub async fn run(
        self: Arc<Self>,
        mempool: Arc<Mempool>,
        command_sender: mpsc::Sender<NetworkCommand>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        if !self.config.enabled {
            info!("Transaction rebroadcaster disabled");
            return;
        }

        info!(
            "Transaction rebroadcaster started (interval: {:?}, max_count: {})",
            self.config.check_interval, self.config.max_rebroadcast_count
        );

        let mut interval = tokio::time::interval(self.config.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.rebroadcast_pending(&mempool, &command_sender).await;
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Transaction rebroadcaster shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Rebroadcast pending transactions that need it
    async fn rebroadcast_pending(
        &self,
        mempool: &Mempool,
        command_sender: &mpsc::Sender<NetworkCommand>,
    ) {
        let candidates = self.get_rebroadcast_candidates(mempool);

        if candidates.is_empty() {
            return;
        }

        debug!("Rebroadcasting {} pending transactions", candidates.len());

        for tx in candidates {
            let hash = tx.hash();
            match command_sender.send(NetworkCommand::BroadcastTransaction(tx)).await {
                Ok(()) => {
                    self.record_broadcast(hash);
                    debug!("Rebroadcast transaction {}", hash);
                }
                Err(e) => {
                    warn!("Failed to rebroadcast transaction {}: {}", hash, e);
                }
            }
        }
    }

    /// Clean up tracking for transactions no longer in mempool
    pub fn cleanup(&self, mempool: &Mempool) {
        let mempool_hashes: std::collections::HashSet<_> =
            mempool.get_all().iter().map(|tx| tx.hash()).collect();

        let mut tracking = self.tracking.write();
        let before = tracking.len();
        tracking.retain(|hash, _| mempool_hashes.contains(hash));
        let removed = before - tracking.len();

        if removed > 0 {
            debug!("Cleaned up {} stale transaction trackers", removed);
        }
    }

    /// Get statistics about the broadcaster
    pub fn stats(&self) -> TxBroadcasterStats {
        let tracking = self.tracking.read();
        let now = Instant::now();

        let mut total_broadcasts = 0u64;
        let mut oldest_age = Duration::ZERO;

        for tracker in tracking.values() {
            total_broadcasts += tracker.broadcast_count as u64;
            let age = now.duration_since(tracker.first_seen);
            if age > oldest_age {
                oldest_age = age;
            }
        }

        TxBroadcasterStats {
            tracked_count: tracking.len(),
            total_broadcasts,
            oldest_tx_age_secs: oldest_age.as_secs(),
        }
    }
}

/// Statistics about the transaction broadcaster
#[derive(Debug, Clone)]
pub struct TxBroadcasterStats {
    /// Number of transactions being tracked
    pub tracked_count: usize,
    /// Total number of broadcasts performed
    pub total_broadcasts: u64,
    /// Age of the oldest tracked transaction in seconds
    pub oldest_tx_age_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::{sign, KeyPair};
    use sumchain_primitives::{Address, Transaction};
    use sumchain_state::MempoolConfig;

    fn create_signed_tx(kp: &KeyPair, nonce: u64) -> SignedTransaction {
        let recipient = Address::new([0u8; 20]); // Zero address as recipient
        let tx = Transaction::new(1, kp.address(), recipient, 100, 10, nonce);
        let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }

    #[test]
    fn test_record_broadcast() {
        let broadcaster = TxBroadcaster::new(TxBroadcasterConfig::default());
        let kp = KeyPair::generate();
        let tx = create_signed_tx(&kp, 0);
        let hash = tx.hash();

        broadcaster.record_broadcast(hash);

        let tracking = broadcaster.tracking.read();
        assert!(tracking.contains_key(&hash));
        assert_eq!(tracking.get(&hash).unwrap().broadcast_count, 1);
    }

    #[test]
    fn test_record_removed() {
        let broadcaster = TxBroadcaster::new(TxBroadcasterConfig::default());
        let kp = KeyPair::generate();
        let tx = create_signed_tx(&kp, 0);
        let hash = tx.hash();

        broadcaster.record_broadcast(hash);
        assert!(broadcaster.tracking.read().contains_key(&hash));

        broadcaster.record_removed(&hash);
        assert!(!broadcaster.tracking.read().contains_key(&hash));
    }

    #[test]
    fn test_stats() {
        let broadcaster = TxBroadcaster::new(TxBroadcasterConfig::default());
        let kp = KeyPair::generate();

        for i in 0..3 {
            let tx = create_signed_tx(&kp, i);
            broadcaster.record_broadcast(tx.hash());
        }

        let stats = broadcaster.stats();
        assert_eq!(stats.tracked_count, 3);
        assert_eq!(stats.total_broadcasts, 3);
    }

    #[test]
    fn test_disabled_broadcaster() {
        let config = TxBroadcasterConfig {
            enabled: false,
            ..Default::default()
        };
        let broadcaster = TxBroadcaster::new(config);
        let mempool = Mempool::new(MempoolConfig::default());
        let kp = KeyPair::generate();

        let tx = create_signed_tx(&kp, 0);
        mempool.add(tx.clone()).unwrap();
        broadcaster.record_broadcast(tx.hash());

        // Should return empty when disabled
        let candidates = broadcaster.get_rebroadcast_candidates(&mempool);
        assert!(candidates.is_empty());
    }
}

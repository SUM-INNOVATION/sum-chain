//! Node metrics collection and reporting.
//!
//! Provides runtime metrics for monitoring node health and performance.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Metrics collector for the node
#[derive(Debug)]
pub struct Metrics {
    /// Node start time
    start_time: Instant,

    /// Block metrics
    pub blocks: BlockMetrics,

    /// Transaction metrics
    pub transactions: TransactionMetrics,

    /// P2P metrics
    pub p2p: P2pMetrics,

    /// RPC metrics
    pub rpc: RpcMetrics,

    /// Mempool metrics
    pub mempool: MempoolMetrics,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            blocks: BlockMetrics::default(),
            transactions: TransactionMetrics::default(),
            p2p: P2pMetrics::default(),
            rpc: RpcMetrics::default(),
            mempool: MempoolMetrics::default(),
        }
    }

    /// Get node uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Generate a snapshot of all metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_seconds: self.uptime_seconds(),
            blocks: self.blocks.snapshot(),
            transactions: self.transactions.snapshot(),
            p2p: self.p2p.snapshot(),
            rpc: self.rpc.snapshot(),
            mempool: self.mempool.snapshot(),
        }
    }
}

/// Block-related metrics
#[derive(Debug, Default)]
pub struct BlockMetrics {
    /// Total blocks processed
    pub blocks_processed: AtomicU64,
    /// Blocks produced (if validator)
    pub blocks_produced: AtomicU64,
    /// Blocks imported from network
    pub blocks_imported: AtomicU64,
    /// Block processing errors
    pub block_errors: AtomicU64,
    /// Current chain height
    pub current_height: AtomicU64,
    /// Last block timestamp
    pub last_block_time: AtomicU64,
}

impl BlockMetrics {
    pub fn record_block_processed(&self) {
        self.blocks_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_block_produced(&self) {
        self.blocks_produced.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_block_imported(&self) {
        self.blocks_imported.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_block_error(&self) {
        self.block_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_height(&self, height: u64) {
        self.current_height.store(height, Ordering::Relaxed);
    }

    pub fn set_last_block_time(&self, timestamp: u64) {
        self.last_block_time.store(timestamp, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> BlockMetricsSnapshot {
        BlockMetricsSnapshot {
            blocks_processed: self.blocks_processed.load(Ordering::Relaxed),
            blocks_produced: self.blocks_produced.load(Ordering::Relaxed),
            blocks_imported: self.blocks_imported.load(Ordering::Relaxed),
            block_errors: self.block_errors.load(Ordering::Relaxed),
            current_height: self.current_height.load(Ordering::Relaxed),
            last_block_time: self.last_block_time.load(Ordering::Relaxed),
        }
    }
}

/// Transaction-related metrics
#[derive(Debug, Default)]
pub struct TransactionMetrics {
    /// Total transactions processed
    pub txs_processed: AtomicU64,
    /// Transactions received from network
    pub txs_received: AtomicU64,
    /// Transactions submitted via RPC
    pub txs_submitted: AtomicU64,
    /// Transaction validation failures
    pub tx_validation_errors: AtomicU64,
    /// Transaction execution failures
    pub tx_execution_errors: AtomicU64,
}

impl TransactionMetrics {
    pub fn record_tx_processed(&self) {
        self.txs_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_received(&self) {
        self.txs_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_submitted(&self) {
        self.txs_submitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_validation_error(&self) {
        self.tx_validation_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_execution_error(&self) {
        self.tx_execution_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TransactionMetricsSnapshot {
        TransactionMetricsSnapshot {
            txs_processed: self.txs_processed.load(Ordering::Relaxed),
            txs_received: self.txs_received.load(Ordering::Relaxed),
            txs_submitted: self.txs_submitted.load(Ordering::Relaxed),
            tx_validation_errors: self.tx_validation_errors.load(Ordering::Relaxed),
            tx_execution_errors: self.tx_execution_errors.load(Ordering::Relaxed),
        }
    }
}

/// P2P network metrics
#[derive(Debug, Default)]
pub struct P2pMetrics {
    /// Current connected peer count
    pub peer_count: AtomicU64,
    /// Total peers connected (lifetime)
    pub peers_connected: AtomicU64,
    /// Total peers disconnected (lifetime)
    pub peers_disconnected: AtomicU64,
    /// Messages received
    pub messages_received: AtomicU64,
    /// Messages sent
    pub messages_sent: AtomicU64,
}

impl P2pMetrics {
    pub fn set_peer_count(&self, count: usize) {
        self.peer_count.store(count as u64, Ordering::Relaxed);
    }

    pub fn record_peer_connected(&self) {
        self.peers_connected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_peer_disconnected(&self) {
        self.peers_disconnected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_message_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_message_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> P2pMetricsSnapshot {
        P2pMetricsSnapshot {
            peer_count: self.peer_count.load(Ordering::Relaxed),
            peers_connected: self.peers_connected.load(Ordering::Relaxed),
            peers_disconnected: self.peers_disconnected.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
        }
    }
}

/// RPC metrics
#[derive(Debug, Default)]
pub struct RpcMetrics {
    /// Total RPC requests
    pub requests_total: AtomicU64,
    /// Successful RPC requests
    pub requests_success: AtomicU64,
    /// Failed RPC requests
    pub requests_failed: AtomicU64,
    /// Requests rejected by rate limiter
    pub requests_rate_limited: AtomicU64,
    /// Requests rejected by auth
    pub requests_unauthorized: AtomicU64,
}

impl RpcMetrics {
    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.requests_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rate_limited(&self) {
        self.requests_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_unauthorized(&self) {
        self.requests_unauthorized.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RpcMetricsSnapshot {
        RpcMetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            requests_rate_limited: self.requests_rate_limited.load(Ordering::Relaxed),
            requests_unauthorized: self.requests_unauthorized.load(Ordering::Relaxed),
        }
    }
}

/// Mempool metrics
#[derive(Debug, Default)]
pub struct MempoolMetrics {
    /// Current mempool size
    pub size: AtomicU64,
    /// Transactions added to mempool
    pub txs_added: AtomicU64,
    /// Transactions removed from mempool
    pub txs_removed: AtomicU64,
    /// Transactions rejected by mempool
    pub txs_rejected: AtomicU64,
}

impl MempoolMetrics {
    pub fn set_size(&self, size: usize) {
        self.size.store(size as u64, Ordering::Relaxed);
    }

    pub fn record_tx_added(&self) {
        self.txs_added.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_removed(&self) {
        self.txs_removed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_rejected(&self) {
        self.txs_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MempoolMetricsSnapshot {
        MempoolMetricsSnapshot {
            size: self.size.load(Ordering::Relaxed),
            txs_added: self.txs_added.load(Ordering::Relaxed),
            txs_removed: self.txs_removed.load(Ordering::Relaxed),
            txs_rejected: self.txs_rejected.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// Snapshot types for serialization
// ============================================================================

/// Complete metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub uptime_seconds: u64,
    pub blocks: BlockMetricsSnapshot,
    pub transactions: TransactionMetricsSnapshot,
    pub p2p: P2pMetricsSnapshot,
    pub rpc: RpcMetricsSnapshot,
    pub mempool: MempoolMetricsSnapshot,
}

impl MetricsSnapshot {
    /// Format metrics in Prometheus exposition format
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Helper to add a metric line
        fn add_metric(out: &mut String, name: &str, help: &str, value: u64) {
            out.push_str(&format!("# HELP {} {}\n", name, help));
            out.push_str(&format!("# TYPE {} gauge\n", name));
            out.push_str(&format!("{} {}\n\n", name, value));
        }

        fn add_counter(out: &mut String, name: &str, help: &str, value: u64) {
            out.push_str(&format!("# HELP {} {}\n", name, help));
            out.push_str(&format!("# TYPE {} counter\n", name));
            out.push_str(&format!("{} {}\n\n", name, value));
        }

        // Node uptime
        add_metric(&mut output, "sumchain_uptime_seconds", "Node uptime in seconds", self.uptime_seconds);

        // Block metrics
        add_metric(&mut output, "sumchain_block_height", "Current blockchain height", self.blocks.current_height);
        add_counter(&mut output, "sumchain_blocks_processed_total", "Total blocks processed", self.blocks.blocks_processed);
        add_counter(&mut output, "sumchain_blocks_produced_total", "Total blocks produced (validator only)", self.blocks.blocks_produced);
        add_counter(&mut output, "sumchain_blocks_imported_total", "Total blocks imported from network", self.blocks.blocks_imported);
        add_counter(&mut output, "sumchain_block_errors_total", "Total block processing errors", self.blocks.block_errors);
        add_metric(&mut output, "sumchain_last_block_timestamp", "Timestamp of last block", self.blocks.last_block_time);

        // Transaction metrics
        add_counter(&mut output, "sumchain_txs_processed_total", "Total transactions processed", self.transactions.txs_processed);
        add_counter(&mut output, "sumchain_txs_received_total", "Total transactions received from network", self.transactions.txs_received);
        add_counter(&mut output, "sumchain_txs_submitted_total", "Total transactions submitted via RPC", self.transactions.txs_submitted);
        add_counter(&mut output, "sumchain_tx_validation_errors_total", "Total transaction validation errors", self.transactions.tx_validation_errors);
        add_counter(&mut output, "sumchain_tx_execution_errors_total", "Total transaction execution errors", self.transactions.tx_execution_errors);

        // P2P metrics
        add_metric(&mut output, "sumchain_peer_count", "Current number of connected peers", self.p2p.peer_count);
        add_counter(&mut output, "sumchain_peers_connected_total", "Total peers connected (lifetime)", self.p2p.peers_connected);
        add_counter(&mut output, "sumchain_peers_disconnected_total", "Total peers disconnected (lifetime)", self.p2p.peers_disconnected);
        add_counter(&mut output, "sumchain_p2p_messages_received_total", "Total P2P messages received", self.p2p.messages_received);
        add_counter(&mut output, "sumchain_p2p_messages_sent_total", "Total P2P messages sent", self.p2p.messages_sent);

        // RPC metrics
        add_counter(&mut output, "sumchain_rpc_requests_total", "Total RPC requests", self.rpc.requests_total);
        add_counter(&mut output, "sumchain_rpc_requests_success_total", "Total successful RPC requests", self.rpc.requests_success);
        add_counter(&mut output, "sumchain_rpc_requests_failed_total", "Total failed RPC requests", self.rpc.requests_failed);
        add_counter(&mut output, "sumchain_rpc_rate_limited_total", "Total requests rejected by rate limiter", self.rpc.requests_rate_limited);
        add_counter(&mut output, "sumchain_rpc_unauthorized_total", "Total unauthorized RPC requests", self.rpc.requests_unauthorized);

        // Mempool metrics
        add_metric(&mut output, "sumchain_mempool_size", "Current mempool size", self.mempool.size);
        add_counter(&mut output, "sumchain_mempool_txs_added_total", "Total transactions added to mempool", self.mempool.txs_added);
        add_counter(&mut output, "sumchain_mempool_txs_removed_total", "Total transactions removed from mempool", self.mempool.txs_removed);
        add_counter(&mut output, "sumchain_mempool_txs_rejected_total", "Total transactions rejected by mempool", self.mempool.txs_rejected);

        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetricsSnapshot {
    pub blocks_processed: u64,
    pub blocks_produced: u64,
    pub blocks_imported: u64,
    pub block_errors: u64,
    pub current_height: u64,
    pub last_block_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMetricsSnapshot {
    pub txs_processed: u64,
    pub txs_received: u64,
    pub txs_submitted: u64,
    pub tx_validation_errors: u64,
    pub tx_execution_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pMetricsSnapshot {
    pub peer_count: u64,
    pub peers_connected: u64,
    pub peers_disconnected: u64,
    pub messages_received: u64,
    pub messages_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcMetricsSnapshot {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub requests_rate_limited: u64,
    pub requests_unauthorized: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolMetricsSnapshot {
    pub size: u64,
    pub txs_added: u64,
    pub txs_removed: u64,
    pub txs_rejected: u64,
}

/// Global metrics instance (thread-safe singleton)
pub struct GlobalMetrics {
    inner: Arc<Metrics>,
}

impl GlobalMetrics {
    /// Create a new global metrics instance
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Metrics::new()),
        }
    }

    /// Get a reference to the metrics
    pub fn get(&self) -> &Metrics {
        &self.inner
    }

    /// Get a clone of the Arc for sharing
    pub fn clone_arc(&self) -> Arc<Metrics> {
        self.inner.clone()
    }
}

impl Default for GlobalMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_metrics() {
        let metrics = BlockMetrics::default();

        metrics.record_block_processed();
        metrics.record_block_produced();
        metrics.set_height(100);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.blocks_processed, 1);
        assert_eq!(snapshot.blocks_produced, 1);
        assert_eq!(snapshot.current_height, 100);
    }

    #[test]
    fn test_tx_metrics() {
        let metrics = TransactionMetrics::default();

        metrics.record_tx_received();
        metrics.record_tx_processed();
        metrics.record_validation_error();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.txs_received, 1);
        assert_eq!(snapshot.txs_processed, 1);
        assert_eq!(snapshot.tx_validation_errors, 1);
    }

    #[test]
    fn test_full_metrics_snapshot() {
        let metrics = Metrics::new();

        metrics.blocks.record_block_processed();
        metrics.transactions.record_tx_submitted();
        metrics.p2p.set_peer_count(5);
        metrics.rpc.record_request();
        metrics.mempool.set_size(10);

        let snapshot = metrics.snapshot();

        // `uptime_seconds` is a `u64` — a `>= 0` check was tautological (clippy
        // `absurd_extreme_comparisons`); the field is still exercised via `snapshot()`.
        let _ = snapshot.uptime_seconds;
        assert_eq!(snapshot.blocks.blocks_processed, 1);
        assert_eq!(snapshot.transactions.txs_submitted, 1);
        assert_eq!(snapshot.p2p.peer_count, 5);
        assert_eq!(snapshot.rpc.requests_total, 1);
        assert_eq!(snapshot.mempool.size, 10);
    }
}

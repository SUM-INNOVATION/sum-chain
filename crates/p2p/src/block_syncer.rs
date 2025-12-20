//! Block synchronization manager.
//!
//! Coordinates the process of syncing blocks from peers when a node
//! is behind the network.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use libp2p::PeerId;
use parking_lot::RwLock;
use sumchain_primitives::{Block, BlockHeight, Hash};
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

use crate::{NetworkCommand, SyncState, MAX_BLOCKS_PER_REQUEST};

/// Configuration for block syncer
#[derive(Debug, Clone)]
pub struct BlockSyncerConfig {
    /// How many blocks to request per batch
    pub batch_size: u64,
    /// Timeout for sync requests
    pub request_timeout: Duration,
    /// How often to check for sync progress
    pub check_interval: Duration,
    /// Maximum concurrent sync requests
    pub max_concurrent_requests: usize,
    /// Minimum peers to start syncing
    pub min_peers_to_sync: usize,
    /// How far behind before starting sync (blocks)
    pub sync_threshold: u64,
}

impl Default for BlockSyncerConfig {
    fn default() -> Self {
        Self {
            batch_size: MAX_BLOCKS_PER_REQUEST.min(50),
            request_timeout: Duration::from_secs(30),
            check_interval: Duration::from_secs(5),
            max_concurrent_requests: 3,
            min_peers_to_sync: 1,
            sync_threshold: 1,
        }
    }
}

/// Status of the peer for syncing purposes
#[derive(Debug, Clone)]
pub struct SyncPeerInfo {
    pub peer_id: PeerId,
    pub height: BlockHeight,
    pub best_hash: Hash,
    pub chain_id: u64,
    pub last_seen: Instant,
    /// Number of successful sync operations
    pub success_count: u32,
    /// Number of failed sync operations
    pub failure_count: u32,
}

impl SyncPeerInfo {
    /// Calculate reliability score (higher is better)
    pub fn reliability_score(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.5; // Neutral for new peers
        }
        self.success_count as f64 / total as f64
    }
}

/// Pending sync request
#[derive(Debug)]
struct PendingRequest {
    peer: PeerId,
    #[allow(dead_code)]
    from_height: BlockHeight,
    #[allow(dead_code)]
    to_height: BlockHeight,
    sent_at: Instant,
}

/// Block syncer state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncerState {
    /// Waiting for initial peer discovery and status
    Initializing,
    /// Requesting status from peers
    GatheringPeerInfo,
    /// Actively syncing blocks
    Syncing,
    /// Sync complete, monitoring for new blocks
    Idle,
    /// Sync failed, waiting to retry
    Failed { retry_at: Instant },
}

/// Block synchronization manager
pub struct BlockSyncer {
    config: BlockSyncerConfig,
    /// Our expected chain ID
    chain_id: u64,
    /// Current local height
    local_height: RwLock<BlockHeight>,
    /// Best known network height
    network_height: RwLock<BlockHeight>,
    /// Known peer sync info
    peers: RwLock<HashMap<PeerId, SyncPeerInfo>>,
    /// Pending requests
    pending_requests: RwLock<HashMap<(BlockHeight, BlockHeight), PendingRequest>>,
    /// Requested but not yet received block heights
    in_flight_ranges: RwLock<HashSet<(BlockHeight, BlockHeight)>>,
    /// Blocks received but not yet processed (out of order) - reserved for future use
    #[allow(dead_code)]
    pending_blocks: RwLock<HashMap<BlockHeight, Block>>,
    /// Current syncer state
    state: RwLock<SyncerState>,
    /// Command sender for network
    command_tx: mpsc::Sender<NetworkCommand>,
    /// Last time we requested peer status
    last_status_request: RwLock<Option<Instant>>,
}

impl BlockSyncer {
    /// Create a new block syncer
    pub fn new(
        config: BlockSyncerConfig,
        chain_id: u64,
        local_height: BlockHeight,
        command_tx: mpsc::Sender<NetworkCommand>,
    ) -> Self {
        Self {
            config,
            chain_id,
            local_height: RwLock::new(local_height),
            network_height: RwLock::new(local_height),
            peers: RwLock::new(HashMap::new()),
            pending_requests: RwLock::new(HashMap::new()),
            in_flight_ranges: RwLock::new(HashSet::new()),
            pending_blocks: RwLock::new(HashMap::new()),
            state: RwLock::new(SyncerState::Initializing),
            command_tx,
            last_status_request: RwLock::new(None),
        }
    }

    /// Get current sync state (for network service)
    pub fn sync_state(&self) -> SyncState {
        let local = *self.local_height.read();
        let network = *self.network_height.read();
        let state = *self.state.read();

        match state {
            SyncerState::Initializing | SyncerState::GatheringPeerInfo => SyncState::Initializing,
            SyncerState::Syncing => SyncState::Syncing {
                current_height: local,
                target_height: network,
            },
            SyncerState::Idle => {
                if local >= network {
                    SyncState::Synced
                } else {
                    SyncState::Behind {
                        local_height: local,
                        network_height: network,
                    }
                }
            }
            SyncerState::Failed { .. } => SyncState::Behind {
                local_height: local,
                network_height: network,
            },
        }
    }

    /// Update local height (called when a block is imported)
    pub fn set_local_height(&self, height: BlockHeight) {
        *self.local_height.write() = height;
    }

    /// Get current local height
    pub fn local_height(&self) -> BlockHeight {
        *self.local_height.read()
    }

    /// Get best known network height
    pub fn network_height(&self) -> BlockHeight {
        *self.network_height.read()
    }

    /// Handle new peer connected
    pub async fn on_peer_connected(&self, peer_id: PeerId) {
        debug!("Block syncer: new peer connected {}", peer_id);

        // Request status from this peer
        if let Err(e) = self.command_tx.send(NetworkCommand::RequestSyncStatus(peer_id)).await {
            warn!("Failed to request sync status: {}", e);
        }
    }

    /// Handle peer disconnected
    pub fn on_peer_disconnected(&self, peer_id: &PeerId) {
        debug!("Block syncer: peer disconnected {}", peer_id);
        self.peers.write().remove(peer_id);

        // Cancel any pending requests from this peer
        self.pending_requests.write().retain(|_, req| req.peer != *peer_id);
    }

    /// Handle sync status response from peer
    pub fn on_status_response(&self, peer_id: PeerId, height: BlockHeight, best_hash: Hash, chain_id: u64) {
        // Verify chain ID matches
        if chain_id != self.chain_id {
            warn!(
                "Peer {} has different chain ID {} (expected {}), ignoring",
                peer_id, chain_id, self.chain_id
            );
            return;
        }

        let info = SyncPeerInfo {
            peer_id,
            height,
            best_hash,
            chain_id,
            last_seen: Instant::now(),
            success_count: 0,
            failure_count: 0,
        };

        self.peers.write().insert(peer_id, info);

        // Update network height if higher
        let mut network_height = self.network_height.write();
        if height > *network_height {
            info!("New best network height: {} (from {})", height, peer_id);
            *network_height = height;
        }

        // Check if we need to start syncing
        let local = *self.local_height.read();
        let state = *self.state.read();

        if matches!(state, SyncerState::Initializing | SyncerState::GatheringPeerInfo) {
            if *network_height > local + self.config.sync_threshold {
                info!(
                    "Behind by {} blocks, starting sync (local: {}, network: {})",
                    *network_height - local,
                    local,
                    *network_height
                );
                *self.state.write() = SyncerState::Syncing;
            } else {
                info!("Synced with network (local: {}, network: {})", local, *network_height);
                *self.state.write() = SyncerState::Idle;
            }
        }
    }

    /// Handle blocks received from sync
    pub fn on_blocks_received(&self, peer_id: PeerId, blocks: Vec<Block>) -> Vec<Block> {
        if blocks.is_empty() {
            warn!("Received empty blocks response from {}", peer_id);
            if let Some(info) = self.peers.write().get_mut(&peer_id) {
                info.failure_count += 1;
            }
            return Vec::new();
        }

        let first_height = blocks.first().map(|b| b.height()).unwrap_or(0);
        let last_height = blocks.last().map(|b| b.height()).unwrap_or(0);

        debug!(
            "Received {} blocks ({} - {}) from {}",
            blocks.len(),
            first_height,
            last_height,
            peer_id
        );

        // Remove from pending
        self.pending_requests.write().retain(|&(from, to), req| {
            if req.peer == peer_id && from == first_height && to == last_height {
                false
            } else {
                true
            }
        });

        // Mark range as completed
        self.in_flight_ranges.write().remove(&(first_height, last_height));

        // Update peer success count
        if let Some(info) = self.peers.write().get_mut(&peer_id) {
            info.success_count += 1;
            info.last_seen = Instant::now();
        }

        // Return blocks that are at or after our local height
        let local = *self.local_height.read();
        let mut to_import: Vec<Block> = blocks.into_iter()
            .filter(|b| b.height() > local)
            .collect();

        // Sort by height to ensure proper order
        to_import.sort_by_key(|b| b.height());

        to_import
    }

    /// Handle sync request failure
    pub fn on_sync_failed(&self, peer_id: PeerId, error: &str) {
        warn!("Sync request failed from {}: {}", peer_id, error);

        // Update peer failure count
        if let Some(info) = self.peers.write().get_mut(&peer_id) {
            info.failure_count += 1;
        }

        // Remove pending requests for this peer
        let mut pending = self.pending_requests.write();
        let mut in_flight = self.in_flight_ranges.write();

        pending.retain(|(from, to), req| {
            if req.peer == peer_id {
                in_flight.remove(&(*from, *to));
                false
            } else {
                true
            }
        });
    }

    /// Check and initiate sync if needed (call periodically)
    pub async fn tick(&self) {
        let state = *self.state.read();

        match state {
            SyncerState::Initializing => {
                // Wait for peers to connect
                if !self.peers.read().is_empty() {
                    *self.state.write() = SyncerState::GatheringPeerInfo;
                }
            }

            SyncerState::GatheringPeerInfo => {
                // Request status from all connected peers periodically
                let should_request = self.last_status_request.read()
                    .map(|t| t.elapsed() > Duration::from_secs(10))
                    .unwrap_or(true);

                if should_request {
                    self.request_peer_status().await;
                }
            }

            SyncerState::Syncing => {
                self.process_sync().await;
            }

            SyncerState::Idle => {
                // Periodically check if we're still synced
                let local = *self.local_height.read();
                let network = *self.network_height.read();

                if network > local + self.config.sync_threshold {
                    info!("Fell behind, resuming sync");
                    *self.state.write() = SyncerState::Syncing;
                }
            }

            SyncerState::Failed { retry_at } => {
                if Instant::now() >= retry_at {
                    info!("Retrying sync after failure");
                    *self.state.write() = SyncerState::Syncing;
                }
            }
        }

        // Clean up timed out requests
        self.cleanup_timed_out_requests();
    }

    /// Request status from all known peers
    async fn request_peer_status(&self) {
        let peer_ids: Vec<PeerId> = self.peers.read().keys().copied().collect();

        for peer_id in peer_ids {
            if let Err(e) = self.command_tx.send(NetworkCommand::RequestSyncStatus(peer_id)).await {
                warn!("Failed to request status from {}: {}", peer_id, e);
            }
        }

        *self.last_status_request.write() = Some(Instant::now());
    }

    /// Process active sync
    async fn process_sync(&self) {
        let local = *self.local_height.read();
        let network = *self.network_height.read();

        // Check if sync is complete
        if local >= network {
            info!("Sync complete! Height: {}", local);
            *self.state.write() = SyncerState::Idle;
            return;
        }

        // Check concurrent request limit
        let pending_count = self.pending_requests.read().len();
        if pending_count >= self.config.max_concurrent_requests {
            debug!("At max concurrent requests ({}), waiting", pending_count);
            return;
        }

        // Find next range to request
        let next_start = self.find_next_start_height(local);
        if next_start > network {
            debug!("All blocks up to {} already requested", network);
            return;
        }

        let next_end = (next_start + self.config.batch_size - 1).min(network);

        // Select best peer for request
        if let Some(peer) = self.select_sync_peer() {
            self.request_blocks(peer, next_start, next_end).await;
        } else {
            warn!("No suitable peers for sync");
            *self.state.write() = SyncerState::Failed {
                retry_at: Instant::now() + Duration::from_secs(30),
            };
        }
    }

    /// Find the next height we need to request
    fn find_next_start_height(&self, local_height: BlockHeight) -> BlockHeight {
        let in_flight = self.in_flight_ranges.read();

        let mut height = local_height + 1;

        // Skip over ranges that are already in flight
        loop {
            let is_in_flight = in_flight.iter().any(|&(from, to)| {
                height >= from && height <= to
            });

            if !is_in_flight {
                break;
            }

            // Jump to after the current in-flight range
            if let Some(&(_, to)) = in_flight.iter().find(|&&(from, to)| height >= from && height <= to) {
                height = to + 1;
            } else {
                break;
            }
        }

        height
    }

    /// Select the best peer for syncing
    fn select_sync_peer(&self) -> Option<PeerId> {
        let peers = self.peers.read();
        let local = *self.local_height.read();

        // Filter peers that have blocks we need and have good reliability
        peers.values()
            .filter(|p| p.height > local)
            .filter(|p| p.last_seen.elapsed() < Duration::from_secs(60))
            .max_by(|a, b| {
                // Prefer peers with higher height and better reliability
                let score_a = a.reliability_score() + (a.height as f64 / 1000.0);
                let score_b = b.reliability_score() + (b.height as f64 / 1000.0);
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|p| p.peer_id)
    }

    /// Request blocks from a peer
    async fn request_blocks(&self, peer: PeerId, from: BlockHeight, to: BlockHeight) {
        debug!("Requesting blocks {} - {} from {}", from, to, peer);

        // Track the request
        {
            let mut pending = self.pending_requests.write();
            let mut in_flight = self.in_flight_ranges.write();

            pending.insert((from, to), PendingRequest {
                peer,
                from_height: from,
                to_height: to,
                sent_at: Instant::now(),
            });

            in_flight.insert((from, to));
        }

        // Send the request
        let cmd = NetworkCommand::RequestBlocks {
            peer,
            from_height: from,
            to_height: to,
        };

        if let Err(e) = self.command_tx.send(cmd).await {
            error!("Failed to send block request: {}", e);
            // Clean up
            self.pending_requests.write().remove(&(from, to));
            self.in_flight_ranges.write().remove(&(from, to));
        }
    }

    /// Clean up timed out requests
    fn cleanup_timed_out_requests(&self) {
        let timeout = self.config.request_timeout;
        let mut pending = self.pending_requests.write();
        let mut in_flight = self.in_flight_ranges.write();

        let timed_out: Vec<_> = pending.iter()
            .filter(|(_, req)| req.sent_at.elapsed() > timeout)
            .map(|(&key, req)| (key, req.peer))
            .collect();

        for ((from, to), peer) in timed_out {
            warn!("Sync request {} - {} to {} timed out", from, to, peer);
            pending.remove(&(from, to));
            in_flight.remove(&(from, to));

            // Update peer failure count
            let mut peers = self.peers.write();
            if let Some(info) = peers.get_mut(&peer) {
                info.failure_count += 1;
            }
        }
    }

    /// Get sync statistics
    pub fn stats(&self) -> SyncStats {
        let local = *self.local_height.read();
        let network = *self.network_height.read();
        let state = *self.state.read();
        let pending = self.pending_requests.read().len();
        let peers = self.peers.read().len();

        SyncStats {
            local_height: local,
            network_height: network,
            blocks_behind: network.saturating_sub(local),
            pending_requests: pending,
            known_peers: peers,
            state: format!("{:?}", state),
            progress_percent: if network > 0 {
                ((local as f64 / network as f64) * 100.0).min(100.0)
            } else {
                100.0
            },
        }
    }
}

/// Sync statistics
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub local_height: BlockHeight,
    pub network_height: BlockHeight,
    pub blocks_behind: u64,
    pub pending_requests: usize,
    pub known_peers: usize,
    pub state: String,
    pub progress_percent: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_syncer_initialization() {
        let (tx, _rx) = mpsc::channel(100);
        let syncer = BlockSyncer::new(
            BlockSyncerConfig::default(),
            1337,
            0,
            tx,
        );

        assert_eq!(syncer.local_height(), 0);
        assert_eq!(syncer.network_height(), 0);
        assert!(matches!(syncer.sync_state(), SyncState::Initializing));
    }

    #[tokio::test]
    async fn test_status_response_updates_network_height() {
        let (tx, _rx) = mpsc::channel(100);
        let syncer = BlockSyncer::new(
            BlockSyncerConfig::default(),
            1337,
            0,
            tx,
        );

        let peer_id = PeerId::random();
        syncer.on_status_response(peer_id, 100, Hash::default(), 1337);

        assert_eq!(syncer.network_height(), 100);
    }

    #[tokio::test]
    async fn test_wrong_chain_id_ignored() {
        let (tx, _rx) = mpsc::channel(100);
        let syncer = BlockSyncer::new(
            BlockSyncerConfig::default(),
            1337,
            0,
            tx,
        );

        let peer_id = PeerId::random();
        syncer.on_status_response(peer_id, 100, Hash::default(), 9999); // Wrong chain ID

        // Network height should not be updated
        assert_eq!(syncer.network_height(), 0);
        assert!(syncer.peers.read().is_empty());
    }

    #[tokio::test]
    async fn test_sync_state_transitions() {
        let (tx, _rx) = mpsc::channel(100);
        let syncer = BlockSyncer::new(
            BlockSyncerConfig::default(),
            1337,
            0,
            tx,
        );

        // Initially initializing
        assert!(matches!(syncer.sync_state(), SyncState::Initializing));

        // After getting status from a peer that's ahead
        let peer_id = PeerId::random();
        syncer.on_status_response(peer_id, 100, Hash::default(), 1337);

        // Should transition to syncing
        assert!(matches!(syncer.sync_state(), SyncState::Syncing { .. }));
    }

    #[tokio::test]
    async fn test_already_synced() {
        let (tx, _rx) = mpsc::channel(100);
        let syncer = BlockSyncer::new(
            BlockSyncerConfig::default(),
            1337,
            100, // Already at height 100
            tx,
        );

        let peer_id = PeerId::random();
        syncer.on_status_response(peer_id, 100, Hash::default(), 1337);

        // Should transition to idle (synced)
        assert!(matches!(syncer.sync_state(), SyncState::Synced));
    }
}

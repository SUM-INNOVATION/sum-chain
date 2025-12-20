//! Peer management and connection pool for SUM Chain.
//!
//! Handles peer scoring, reputation tracking, connection limits,
//! and automatic peer discovery/connection management.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Peer score thresholds
pub mod thresholds {
    /// Minimum score to remain connected
    pub const DISCONNECT_THRESHOLD: i64 = -100;
    /// Score below which peer is temporarily banned
    pub const BAN_THRESHOLD: i64 = -500;
    /// Default score for new peers
    pub const DEFAULT_SCORE: i64 = 0;
    /// Maximum possible score
    pub const MAX_SCORE: i64 = 1000;
    /// Minimum possible score
    pub const MIN_SCORE: i64 = -1000;
}

/// Score adjustments for peer behavior
pub mod score_adjustments {
    /// Good block received and validated
    pub const VALID_BLOCK: i64 = 10;
    /// Good transaction received and validated
    pub const VALID_TX: i64 = 1;
    /// Invalid block received
    pub const INVALID_BLOCK: i64 = -50;
    /// Invalid transaction received
    pub const INVALID_TX: i64 = -10;
    /// Sync request completed successfully
    pub const SYNC_SUCCESS: i64 = 5;
    /// Sync request failed/timed out
    pub const SYNC_FAILURE: i64 = -20;
    /// Connection timeout
    pub const CONNECTION_TIMEOUT: i64 = -5;
    /// Protocol violation
    pub const PROTOCOL_VIOLATION: i64 = -100;
    /// Slow response (but valid)
    pub const SLOW_RESPONSE: i64 = -2;
    /// Fast response
    pub const FAST_RESPONSE: i64 = 2;
    /// Peer provided useful sync data
    pub const USEFUL_SYNC_DATA: i64 = 15;
}

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Not connected
    Disconnected,
    /// Connection in progress
    Connecting,
    /// Fully connected
    Connected,
    /// Disconnecting
    Disconnecting,
    /// Temporarily banned
    Banned,
}

/// Direction of the connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// Information about a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: String,
    /// Known addresses for this peer
    pub addresses: Vec<String>,
    /// Current connection state
    pub state: PeerState,
    /// Connection direction (if connected)
    pub direction: Option<ConnectionDirection>,
    /// Reputation score
    pub score: i64,
    /// When the peer was first seen
    pub first_seen: u64,
    /// When the peer was last seen active
    pub last_seen: u64,
    /// Number of successful connections
    pub successful_connections: u32,
    /// Number of failed connection attempts
    pub failed_connections: u32,
    /// If banned, when the ban expires (timestamp)
    pub ban_expires: Option<u64>,
    /// User-provided notes/tags
    pub tags: Vec<String>,
}

/// Internal peer state
struct PeerEntry {
    peer_id: PeerId,
    addresses: Vec<Multiaddr>,
    state: PeerState,
    direction: Option<ConnectionDirection>,
    score: i64,
    first_seen: Instant,
    last_seen: Instant,
    last_score_decay: Instant,
    successful_connections: u32,
    failed_connections: u32,
    ban_until: Option<Instant>,
    tags: Vec<String>,
    /// Connection attempt history for backoff
    connection_attempts: Vec<Instant>,
}

impl PeerEntry {
    fn new(peer_id: PeerId) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            addresses: Vec::new(),
            state: PeerState::Disconnected,
            direction: None,
            score: thresholds::DEFAULT_SCORE,
            first_seen: now,
            last_seen: now,
            last_score_decay: now,
            successful_connections: 0,
            failed_connections: 0,
            ban_until: None,
            tags: Vec::new(),
            connection_attempts: Vec::new(),
        }
    }

    fn to_info(&self, start_time: Instant) -> PeerInfo {
        let now = Instant::now();
        PeerInfo {
            peer_id: self.peer_id.to_string(),
            addresses: self.addresses.iter().map(|a| a.to_string()).collect(),
            state: self.state,
            direction: self.direction,
            score: self.score,
            first_seen: (self.first_seen - start_time).as_secs(),
            last_seen: (now - start_time).as_secs() - (now - self.last_seen).as_secs(),
            successful_connections: self.successful_connections,
            failed_connections: self.failed_connections,
            ban_expires: self.ban_until.map(|t| {
                if t > now {
                    (t - now).as_secs()
                } else {
                    0
                }
            }),
            tags: self.tags.clone(),
        }
    }

    fn adjust_score(&mut self, delta: i64) {
        self.score = (self.score + delta)
            .max(thresholds::MIN_SCORE)
            .min(thresholds::MAX_SCORE);
    }

    fn apply_score_decay(&mut self, decay_rate: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_score_decay);

        // Decay every minute
        if elapsed >= Duration::from_secs(60) {
            let decay_periods = elapsed.as_secs() / 60;
            for _ in 0..decay_periods {
                // Decay towards zero
                if self.score > 0 {
                    self.score = ((self.score as f64) * (1.0 - decay_rate)) as i64;
                } else if self.score < 0 {
                    self.score = ((self.score as f64) * (1.0 - decay_rate)) as i64;
                }
            }
            self.last_score_decay = now;
        }
    }

    fn is_banned(&self) -> bool {
        if let Some(ban_until) = self.ban_until {
            Instant::now() < ban_until
        } else {
            false
        }
    }

    fn calculate_backoff(&self) -> Duration {
        // Exponential backoff: 1s, 2s, 4s, 8s, ... up to 5 minutes
        let recent_failures = self.connection_attempts
            .iter()
            .filter(|t| t.elapsed() < Duration::from_secs(300))
            .count();

        let base = Duration::from_secs(1);
        let max = Duration::from_secs(300);

        let backoff = base * 2u32.saturating_pow(recent_failures as u32);
        backoff.min(max)
    }

    fn should_attempt_connection(&self) -> bool {
        if self.is_banned() {
            return false;
        }
        if self.state != PeerState::Disconnected {
            return false;
        }

        // Check backoff
        if let Some(last_attempt) = self.connection_attempts.last() {
            let backoff = self.calculate_backoff();
            if last_attempt.elapsed() < backoff {
                return false;
            }
        }

        true
    }

    fn record_connection_attempt(&mut self) {
        self.connection_attempts.push(Instant::now());
        // Keep only last 10 attempts
        if self.connection_attempts.len() > 10 {
            self.connection_attempts.remove(0);
        }
    }
}

/// Connection limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLimits {
    /// Maximum total connections
    pub max_total: usize,
    /// Maximum inbound connections
    pub max_inbound: usize,
    /// Maximum outbound connections
    pub max_outbound: usize,
    /// Maximum connections per IP
    pub max_per_ip: usize,
    /// Score decay rate per minute (0.0 - 1.0)
    pub score_decay_rate: f64,
    /// Ban duration for misbehaving peers
    pub ban_duration: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_total: 100,
            max_inbound: 50,
            max_outbound: 50,
            max_per_ip: 3,
            score_decay_rate: 0.01,
            ban_duration: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Peer manager for connection pool management
pub struct PeerManager {
    /// Peer entries
    peers: RwLock<HashMap<PeerId, PeerEntry>>,
    /// IP to peer mapping for rate limiting
    ip_to_peers: RwLock<HashMap<IpAddr, Vec<PeerId>>>,
    /// Connection limits
    limits: ConnectionLimits,
    /// Service start time (for relative timestamps)
    start_time: Instant,
    /// Current inbound connection count
    inbound_count: RwLock<usize>,
    /// Current outbound connection count
    outbound_count: RwLock<usize>,
    /// Protected peers (never disconnect)
    protected_peers: RwLock<Vec<PeerId>>,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new(limits: ConnectionLimits) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            ip_to_peers: RwLock::new(HashMap::new()),
            limits,
            start_time: Instant::now(),
            inbound_count: RwLock::new(0),
            outbound_count: RwLock::new(0),
            protected_peers: RwLock::new(Vec::new()),
        }
    }

    /// Add a protected peer (e.g., bootnode) that won't be disconnected
    pub fn add_protected_peer(&self, peer_id: PeerId) {
        let mut protected = self.protected_peers.write();
        if !protected.contains(&peer_id) {
            protected.push(peer_id);
            info!("Added protected peer: {}", peer_id);
        }
    }

    /// Register a new peer or update existing
    pub fn register_peer(&self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        let mut peers = self.peers.write();
        let entry = peers.entry(peer_id).or_insert_with(|| PeerEntry::new(peer_id));

        for addr in addresses {
            if !entry.addresses.contains(&addr) {
                entry.addresses.push(addr);
            }
        }
        entry.last_seen = Instant::now();
        debug!("Registered peer {} with {} addresses", peer_id, entry.addresses.len());
    }

    /// Check if a new inbound connection can be accepted
    pub fn can_accept_inbound(&self, peer_id: &PeerId, remote_ip: Option<IpAddr>) -> bool {
        // Check if peer is banned
        if let Some(entry) = self.peers.read().get(peer_id) {
            if entry.is_banned() {
                debug!("Rejecting banned peer: {}", peer_id);
                return false;
            }
            if entry.score < thresholds::DISCONNECT_THRESHOLD {
                debug!("Rejecting low-score peer: {} (score: {})", peer_id, entry.score);
                return false;
            }
        }

        // Check inbound limit
        if *self.inbound_count.read() >= self.limits.max_inbound {
            debug!("Rejecting inbound connection: limit reached");
            return false;
        }

        // Check total limit
        let total = *self.inbound_count.read() + *self.outbound_count.read();
        if total >= self.limits.max_total {
            debug!("Rejecting connection: total limit reached");
            return false;
        }

        // Check per-IP limit
        if let Some(ip) = remote_ip {
            let ip_peers = self.ip_to_peers.read();
            if let Some(peers) = ip_peers.get(&ip) {
                if peers.len() >= self.limits.max_per_ip {
                    debug!("Rejecting connection from {}: per-IP limit reached", ip);
                    return false;
                }
            }
        }

        true
    }

    /// Check if a new outbound connection can be initiated
    pub fn can_connect_outbound(&self, peer_id: &PeerId) -> bool {
        // Check if peer is banned
        if let Some(entry) = self.peers.read().get(peer_id) {
            if entry.is_banned() {
                return false;
            }
            if !entry.should_attempt_connection() {
                return false;
            }
        }

        // Check outbound limit
        if *self.outbound_count.read() >= self.limits.max_outbound {
            return false;
        }

        // Check total limit
        let total = *self.inbound_count.read() + *self.outbound_count.read();
        if total >= self.limits.max_total {
            return false;
        }

        true
    }

    /// Mark peer as connected
    pub fn peer_connected(&self, peer_id: PeerId, direction: ConnectionDirection, remote_ip: Option<IpAddr>) {
        let mut peers = self.peers.write();
        let entry = peers.entry(peer_id).or_insert_with(|| PeerEntry::new(peer_id));

        entry.state = PeerState::Connected;
        entry.direction = Some(direction);
        entry.last_seen = Instant::now();
        entry.successful_connections += 1;

        match direction {
            ConnectionDirection::Inbound => *self.inbound_count.write() += 1,
            ConnectionDirection::Outbound => *self.outbound_count.write() += 1,
        }

        // Track IP mapping
        if let Some(ip) = remote_ip {
            self.ip_to_peers.write()
                .entry(ip)
                .or_insert_with(Vec::new)
                .push(peer_id);
        }

        info!(
            "Peer connected: {} ({:?}) - total: {}/{}",
            peer_id,
            direction,
            *self.inbound_count.read() + *self.outbound_count.read(),
            self.limits.max_total
        );
    }

    /// Mark peer as disconnected
    pub fn peer_disconnected(&self, peer_id: &PeerId) {
        let mut peers = self.peers.write();

        if let Some(entry) = peers.get_mut(peer_id) {
            if let Some(direction) = entry.direction {
                match direction {
                    ConnectionDirection::Inbound => {
                        let mut count = self.inbound_count.write();
                        *count = count.saturating_sub(1);
                    }
                    ConnectionDirection::Outbound => {
                        let mut count = self.outbound_count.write();
                        *count = count.saturating_sub(1);
                    }
                }
            }
            entry.state = PeerState::Disconnected;
            entry.direction = None;

            info!(
                "Peer disconnected: {} - total: {}/{}",
                peer_id,
                *self.inbound_count.read() + *self.outbound_count.read(),
                self.limits.max_total
            );
        }

        // Clean up IP mapping
        let mut ip_peers = self.ip_to_peers.write();
        for peers_list in ip_peers.values_mut() {
            peers_list.retain(|p| p != peer_id);
        }
    }

    /// Record a failed connection attempt
    pub fn connection_failed(&self, peer_id: &PeerId) {
        let mut peers = self.peers.write();
        if let Some(entry) = peers.get_mut(peer_id) {
            entry.failed_connections += 1;
            entry.record_connection_attempt();
            entry.adjust_score(score_adjustments::CONNECTION_TIMEOUT);
            entry.state = PeerState::Disconnected;
            debug!("Connection failed to {}, backoff: {:?}", peer_id, entry.calculate_backoff());
        }
    }

    /// Adjust peer score
    pub fn adjust_score(&self, peer_id: &PeerId, delta: i64, reason: &str) {
        let mut peers = self.peers.write();
        if let Some(entry) = peers.get_mut(peer_id) {
            let old_score = entry.score;
            entry.adjust_score(delta);
            debug!(
                "Peer {} score: {} -> {} ({})",
                peer_id, old_score, entry.score, reason
            );

            // Check if peer should be banned
            if entry.score <= thresholds::BAN_THRESHOLD && !entry.is_banned() {
                entry.ban_until = Some(Instant::now() + self.limits.ban_duration);
                warn!(
                    "Peer {} banned for {:?} (score: {})",
                    peer_id, self.limits.ban_duration, entry.score
                );
            }
        }
    }

    /// Report valid block from peer
    pub fn report_valid_block(&self, peer_id: &PeerId) {
        self.adjust_score(peer_id, score_adjustments::VALID_BLOCK, "valid block");
    }

    /// Report invalid block from peer
    pub fn report_invalid_block(&self, peer_id: &PeerId) {
        self.adjust_score(peer_id, score_adjustments::INVALID_BLOCK, "invalid block");
    }

    /// Report valid transaction from peer
    pub fn report_valid_tx(&self, peer_id: &PeerId) {
        self.adjust_score(peer_id, score_adjustments::VALID_TX, "valid tx");
    }

    /// Report invalid transaction from peer
    pub fn report_invalid_tx(&self, peer_id: &PeerId) {
        self.adjust_score(peer_id, score_adjustments::INVALID_TX, "invalid tx");
    }

    /// Report successful sync
    pub fn report_sync_success(&self, peer_id: &PeerId) {
        self.adjust_score(peer_id, score_adjustments::SYNC_SUCCESS, "sync success");
    }

    /// Report failed sync
    pub fn report_sync_failure(&self, peer_id: &PeerId) {
        self.adjust_score(peer_id, score_adjustments::SYNC_FAILURE, "sync failure");
    }

    /// Report protocol violation
    pub fn report_protocol_violation(&self, peer_id: &PeerId, reason: &str) {
        warn!("Protocol violation from {}: {}", peer_id, reason);
        self.adjust_score(peer_id, score_adjustments::PROTOCOL_VIOLATION, reason);
    }

    /// Manually ban a peer
    pub fn ban_peer(&self, peer_id: &PeerId, duration: Duration) {
        let mut peers = self.peers.write();
        if let Some(entry) = peers.get_mut(peer_id) {
            entry.ban_until = Some(Instant::now() + duration);
            entry.state = PeerState::Banned;
            warn!("Manually banned peer {} for {:?}", peer_id, duration);
        }
    }

    /// Unban a peer
    pub fn unban_peer(&self, peer_id: &PeerId) {
        let mut peers = self.peers.write();
        if let Some(entry) = peers.get_mut(peer_id) {
            entry.ban_until = None;
            entry.state = PeerState::Disconnected;
            info!("Unbanned peer {}", peer_id);
        }
    }

    /// Get peer info
    pub fn get_peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.read().get(peer_id).map(|e| e.to_info(self.start_time))
    }

    /// Get all peer info
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().values().map(|e| e.to_info(self.start_time)).collect()
    }

    /// Get connected peers sorted by score (highest first)
    pub fn connected_peers_by_score(&self) -> Vec<PeerId> {
        let peers = self.peers.read();
        let mut connected: Vec<_> = peers
            .iter()
            .filter(|(_, e)| e.state == PeerState::Connected)
            .collect();
        connected.sort_by(|a, b| b.1.score.cmp(&a.1.score));
        connected.into_iter().map(|(id, _)| *id).collect()
    }

    /// Get peers that should be disconnected (low score)
    pub fn get_peers_to_disconnect(&self) -> Vec<PeerId> {
        let peers = self.peers.read();
        let protected = self.protected_peers.read();

        peers
            .iter()
            .filter(|(id, e)| {
                e.state == PeerState::Connected
                    && e.score < thresholds::DISCONNECT_THRESHOLD
                    && !protected.contains(id)
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get candidate peers for new outbound connections
    pub fn get_connection_candidates(&self, count: usize) -> Vec<(PeerId, Multiaddr)> {
        let peers = self.peers.read();

        let mut candidates: Vec<_> = peers
            .iter()
            .filter(|(_, e)| e.should_attempt_connection() && !e.addresses.is_empty())
            .collect();

        // Sort by score (highest first) then by connection attempts (fewest first)
        candidates.sort_by(|a, b| {
            match b.1.score.cmp(&a.1.score) {
                std::cmp::Ordering::Equal => {
                    a.1.connection_attempts.len().cmp(&b.1.connection_attempts.len())
                }
                other => other,
            }
        });

        candidates
            .into_iter()
            .take(count)
            .filter_map(|(id, e)| e.addresses.first().map(|addr| (*id, addr.clone())))
            .collect()
    }

    /// Apply score decay to all peers
    pub fn apply_score_decay(&self) {
        let mut peers = self.peers.write();
        for entry in peers.values_mut() {
            entry.apply_score_decay(self.limits.score_decay_rate);
        }
    }

    /// Clean up stale peer entries
    pub fn cleanup_stale_peers(&self, max_age: Duration) {
        let mut peers = self.peers.write();
        let protected = self.protected_peers.read();
        let now = Instant::now();

        peers.retain(|id, entry| {
            // Keep connected peers
            if entry.state == PeerState::Connected {
                return true;
            }
            // Keep protected peers
            if protected.contains(id) {
                return true;
            }
            // Keep recently seen peers
            if now.duration_since(entry.last_seen) < max_age {
                return true;
            }
            // Keep banned peers until ban expires
            if entry.is_banned() {
                return true;
            }

            debug!("Removing stale peer: {}", id);
            false
        });
    }

    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        let peers = self.peers.read();
        let connected = peers.values().filter(|e| e.state == PeerState::Connected).count();
        let banned = peers.values().filter(|e| e.is_banned()).count();

        ConnectionStats {
            total_known: peers.len(),
            connected,
            inbound: *self.inbound_count.read(),
            outbound: *self.outbound_count.read(),
            banned,
            max_total: self.limits.max_total,
            max_inbound: self.limits.max_inbound,
            max_outbound: self.limits.max_outbound,
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Total known peers
    pub total_known: usize,
    /// Currently connected peers
    pub connected: usize,
    /// Inbound connections
    pub inbound: usize,
    /// Outbound connections
    pub outbound: usize,
    /// Banned peers
    pub banned: usize,
    /// Maximum total connections
    pub max_total: usize,
    /// Maximum inbound connections
    pub max_inbound: usize,
    /// Maximum outbound connections
    pub max_outbound: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_peer_registration() {
        let manager = PeerManager::new(ConnectionLimits::default());
        let peer = test_peer_id();

        manager.register_peer(peer, vec![]);
        assert!(manager.get_peer_info(&peer).is_some());
    }

    #[test]
    fn test_peer_scoring() {
        let manager = PeerManager::new(ConnectionLimits::default());
        let peer = test_peer_id();

        manager.register_peer(peer, vec![]);

        // Score starts at 0
        let info = manager.get_peer_info(&peer).unwrap();
        assert_eq!(info.score, 0);

        // Adjust score
        manager.report_valid_block(&peer);
        let info = manager.get_peer_info(&peer).unwrap();
        assert_eq!(info.score, score_adjustments::VALID_BLOCK);

        // Invalid block should decrease score
        manager.report_invalid_block(&peer);
        let info = manager.get_peer_info(&peer).unwrap();
        assert_eq!(info.score, score_adjustments::VALID_BLOCK + score_adjustments::INVALID_BLOCK);
    }

    #[test]
    fn test_connection_limits() {
        let limits = ConnectionLimits {
            max_total: 2,
            max_inbound: 1,
            max_outbound: 1,
            max_per_ip: 1,
            ..Default::default()
        };
        let manager = PeerManager::new(limits);

        let peer1 = test_peer_id();
        let peer2 = test_peer_id();
        let peer3 = test_peer_id();

        // First peer should connect
        assert!(manager.can_accept_inbound(&peer1, None));
        manager.peer_connected(peer1, ConnectionDirection::Inbound, None);

        // Second peer should not be able to connect inbound (limit reached)
        assert!(!manager.can_accept_inbound(&peer2, None));

        // But can connect outbound
        assert!(manager.can_connect_outbound(&peer2));
        manager.peer_connected(peer2, ConnectionDirection::Outbound, None);

        // Third peer should not connect (total limit reached)
        assert!(!manager.can_accept_inbound(&peer3, None));
        assert!(!manager.can_connect_outbound(&peer3));
    }

    #[test]
    fn test_peer_banning() {
        let manager = PeerManager::new(ConnectionLimits::default());
        let peer = test_peer_id();

        manager.register_peer(peer, vec![]);

        // Lower score until banned
        for _ in 0..10 {
            manager.report_protocol_violation(&peer, "test");
        }

        let info = manager.get_peer_info(&peer).unwrap();
        assert!(info.ban_expires.is_some());
        assert!(!manager.can_accept_inbound(&peer, None));
    }

    #[test]
    fn test_protected_peers() {
        let limits = ConnectionLimits {
            max_total: 1,
            ..Default::default()
        };
        let manager = PeerManager::new(limits);

        let bootnode = test_peer_id();
        let _regular = test_peer_id();

        manager.add_protected_peer(bootnode);
        manager.peer_connected(bootnode, ConnectionDirection::Outbound, None);

        // Lower bootnode score
        for _ in 0..10 {
            manager.report_protocol_violation(&bootnode, "test");
        }

        // Protected peer should not be in disconnect list
        let to_disconnect = manager.get_peers_to_disconnect();
        assert!(!to_disconnect.contains(&bootnode));
    }

    #[test]
    fn test_backoff_calculation() {
        let manager = PeerManager::new(ConnectionLimits::default());
        let peer = test_peer_id();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/30303".parse().unwrap();

        manager.register_peer(peer, vec![addr.clone()]);

        // First attempt should be allowed
        assert!(manager.can_connect_outbound(&peer));

        // Record failure
        manager.connection_failed(&peer);

        // Should now be in backoff
        assert!(!manager.can_connect_outbound(&peer));
    }

    #[test]
    fn test_stats() {
        let manager = PeerManager::new(ConnectionLimits::default());
        let peer1 = test_peer_id();
        let peer2 = test_peer_id();

        manager.register_peer(peer1, vec![]);
        manager.register_peer(peer2, vec![]);
        manager.peer_connected(peer1, ConnectionDirection::Inbound, None);

        let stats = manager.stats();
        assert_eq!(stats.total_known, 2);
        assert_eq!(stats.connected, 1);
        assert_eq!(stats.inbound, 1);
        assert_eq!(stats.outbound, 0);
    }
}

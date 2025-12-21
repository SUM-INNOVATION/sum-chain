//! Network service for SUM Chain.
//!
//! Manages the libp2p swarm and handles message routing.
//!
//! ## Security Features
//! - Per-peer rate limiting to prevent message flooding
//! - Connection limits via PeerManager
//! - Message validation and deduplication via gossipsub

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic}, mdns, noise,
    swarm::{SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use parking_lot::RwLock;
use sumchain_primitives::{Block, SignedTransaction};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::behaviour::{SumChainBehaviour, SumChainBehaviourEvent, SyncEvent};
use crate::config::NetworkConfig;
use crate::peer_manager::{ConnectionDirection, ConnectionLimits, ConnectionStats, PeerInfo, PeerManager};
use crate::sync::{SyncRequest, SyncResponse, SyncState};
use crate::topics;
use crate::{P2pError, Result};

/// Unique ID for sync requests
pub type SyncRequestId = u64;

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum transactions per second per peer
    pub max_tx_per_second: u32,
    /// Maximum blocks per second per peer
    pub max_blocks_per_second: u32,
    /// Maximum BFT messages per second per peer
    pub max_bft_per_second: u32,
    /// Window size for rate limiting (in seconds)
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_tx_per_second: 100,      // 100 tx/s per peer
            max_blocks_per_second: 10,    // 10 blocks/s per peer
            max_bft_per_second: 50,       // 50 BFT msgs/s per peer
            window_secs: 1,
        }
    }
}

impl RateLimitConfig {
    /// Stricter limits for production
    pub fn production() -> Self {
        Self {
            max_tx_per_second: 50,
            max_blocks_per_second: 5,
            max_bft_per_second: 30,
            window_secs: 1,
        }
    }
}

/// Per-peer rate limiter using sliding window
#[derive(Debug)]
struct PeerRateLimiter {
    /// Message counts per peer per topic: (peer_id, topic) -> (count, window_start)
    counters: RwLock<HashMap<(PeerId, MessageType), (u32, Instant)>>,
    config: RateLimitConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MessageType {
    Transaction,
    Block,
    BftMessage,
}

impl PeerRateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Check if a message from a peer should be rate limited
    /// Returns true if the message should be ALLOWED, false if it should be DROPPED
    fn check_rate_limit(&self, peer: PeerId, msg_type: MessageType) -> bool {
        let max_per_second = match msg_type {
            MessageType::Transaction => self.config.max_tx_per_second,
            MessageType::Block => self.config.max_blocks_per_second,
            MessageType::BftMessage => self.config.max_bft_per_second,
        };

        let window = Duration::from_secs(self.config.window_secs);
        let now = Instant::now();
        let key = (peer, msg_type);

        let mut counters = self.counters.write();

        if let Some((count, window_start)) = counters.get_mut(&key) {
            if now.duration_since(*window_start) >= window {
                // Window expired, reset counter
                *count = 1;
                *window_start = now;
                true
            } else if *count < max_per_second {
                // Within window and under limit
                *count += 1;
                true
            } else {
                // Rate limited
                false
            }
        } else {
            // First message from this peer for this topic
            counters.insert(key, (1, now));
            true
        }
    }

    /// Clean up expired entries (call periodically)
    fn cleanup(&self) {
        let window = Duration::from_secs(self.config.window_secs * 10); // Keep for 10 windows
        let now = Instant::now();

        self.counters.write().retain(|_, (_, window_start)| {
            now.duration_since(*window_start) < window
        });
    }
}

/// Network events
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// New transaction received
    TransactionReceived(SignedTransaction),
    /// New block received
    BlockReceived(Block),
    /// BFT proposal received
    BftProposalReceived(Vec<u8>),
    /// BFT prevote received
    BftPrevoteReceived(Vec<u8>),
    /// BFT precommit received
    BftPrecommitReceived(Vec<u8>),
    /// Sync status request received (node should respond via SendSyncStatusResponse command)
    SyncStatusRequest {
        request_id: SyncRequestId,
        peer: PeerId,
    },
    /// Sync blocks request received (node should respond via SendSyncBlocksResponse command)
    SyncBlocksRequest {
        request_id: SyncRequestId,
        peer: PeerId,
        from_height: u64,
        to_height: u64,
    },
    /// Received sync status response from peer
    SyncStatusResponse {
        peer: PeerId,
        height: u64,
        best_hash: sumchain_primitives::Hash,
        chain_id: u64,
    },
    /// Received blocks from sync
    SyncBlocksReceived {
        peer: PeerId,
        blocks: Vec<Block>,
    },
    /// Sync request failed
    SyncRequestFailed {
        peer: PeerId,
        error: String,
    },
}

/// Commands to send to the network
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a transaction
    BroadcastTransaction(SignedTransaction),
    /// Broadcast a block
    BroadcastBlock(Block),
    /// Broadcast a BFT proposal
    BroadcastBftProposal(Vec<u8>),
    /// Broadcast a BFT prevote
    BroadcastBftPrevote(Vec<u8>),
    /// Broadcast a BFT precommit
    BroadcastBftPrecommit(Vec<u8>),
    /// Connect to a peer
    Dial(Multiaddr),
    /// Request sync status from a peer
    RequestSyncStatus(PeerId),
    /// Request blocks from a peer
    RequestBlocks {
        peer: PeerId,
        from_height: u64,
        to_height: u64,
    },
    /// Send sync status response (using request_id from SyncStatusRequest event)
    SendSyncStatusResponse {
        request_id: SyncRequestId,
        height: u64,
        best_hash: sumchain_primitives::Hash,
        chain_id: u64,
    },
    /// Send blocks response (using request_id from SyncBlocksRequest event)
    SendSyncBlocksResponse {
        request_id: SyncRequestId,
        blocks: Vec<Block>,
    },
    /// Send sync error response
    SendSyncErrorResponse {
        request_id: SyncRequestId,
        error: String,
    },
}

/// Network service
pub struct NetworkService {
    /// Network configuration
    config: NetworkConfig,
    /// Local peer ID
    local_peer_id: RwLock<Option<PeerId>>,
    /// Connected peers
    peers: RwLock<HashSet<PeerId>>,
    /// Event sender
    event_tx: broadcast::Sender<NetworkEvent>,
    /// Command receiver
    command_tx: mpsc::Sender<NetworkCommand>,
    /// Running flag
    running: RwLock<bool>,
    /// Current sync state
    sync_state: RwLock<SyncState>,
    /// Peer manager for connection pool management
    peer_manager: Arc<PeerManager>,
    /// Rate limiter for incoming messages
    rate_limiter: PeerRateLimiter,
}

impl NetworkService {
    /// Create a new network service
    pub fn new(config: NetworkConfig) -> (Self, mpsc::Receiver<NetworkCommand>) {
        Self::with_rate_limit(config, RateLimitConfig::default())
    }

    /// Create a new network service with custom rate limiting
    pub fn with_rate_limit(config: NetworkConfig, rate_limit: RateLimitConfig) -> (Self, mpsc::Receiver<NetworkCommand>) {
        let (event_tx, _) = broadcast::channel(1000);
        let (command_tx, command_rx) = mpsc::channel(1000);

        // Create connection limits from config
        let limits = ConnectionLimits {
            max_total: (config.max_inbound + config.max_outbound) as usize,
            max_inbound: config.max_inbound as usize,
            max_outbound: config.max_outbound as usize,
            ..Default::default()
        };
        let peer_manager = Arc::new(PeerManager::new(limits));

        let service = Self {
            config,
            local_peer_id: RwLock::new(None),
            peers: RwLock::new(HashSet::new()),
            event_tx,
            command_tx,
            running: RwLock::new(false),
            sync_state: RwLock::new(SyncState::Initializing),
            peer_manager,
            rate_limiter: PeerRateLimiter::new(rate_limit),
        };

        (service, command_rx)
    }

    /// Create a new network service with custom connection limits
    pub fn with_limits(config: NetworkConfig, limits: ConnectionLimits) -> (Self, mpsc::Receiver<NetworkCommand>) {
        let (event_tx, _) = broadcast::channel(1000);
        let (command_tx, command_rx) = mpsc::channel(1000);

        let peer_manager = Arc::new(PeerManager::new(limits));

        let service = Self {
            config,
            local_peer_id: RwLock::new(None),
            peers: RwLock::new(HashSet::new()),
            event_tx,
            command_tx,
            running: RwLock::new(false),
            sync_state: RwLock::new(SyncState::Initializing),
            peer_manager,
            rate_limiter: PeerRateLimiter::new(RateLimitConfig::default()),
        };

        (service, command_rx)
    }

    /// Subscribe to network events
    pub fn subscribe(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Get command sender
    pub fn command_sender(&self) -> mpsc::Sender<NetworkCommand> {
        self.command_tx.clone()
    }

    /// Broadcast a transaction
    pub async fn broadcast_tx(&self, tx: SignedTransaction) -> Result<()> {
        self.command_tx
            .send(NetworkCommand::BroadcastTransaction(tx))
            .await
            .map_err(|e| P2pError::Gossip(e.to_string()))
    }

    /// Broadcast a block
    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        self.command_tx
            .send(NetworkCommand::BroadcastBlock(block))
            .await
            .map_err(|e| P2pError::Gossip(e.to_string()))
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> Option<PeerId> {
        *self.local_peer_id.read()
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }

    /// Get current sync state
    pub fn sync_state(&self) -> SyncState {
        *self.sync_state.read()
    }

    /// Set sync state
    pub fn set_sync_state(&self, state: SyncState) {
        *self.sync_state.write() = state;
    }

    /// Get connected peer IDs
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.read().iter().copied().collect()
    }

    /// Get peer manager reference
    pub fn peer_manager(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }

    /// Get peer info
    pub fn get_peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peer_manager.get_peer_info(peer_id)
    }

    /// Get all peer info
    pub fn all_peer_info(&self) -> Vec<PeerInfo> {
        self.peer_manager.all_peers()
    }

    /// Get connection statistics
    pub fn connection_stats(&self) -> ConnectionStats {
        self.peer_manager.stats()
    }

    /// Report valid block from peer (adjusts score)
    pub fn report_valid_block(&self, peer_id: &PeerId) {
        self.peer_manager.report_valid_block(peer_id);
    }

    /// Report invalid block from peer (adjusts score)
    pub fn report_invalid_block(&self, peer_id: &PeerId) {
        self.peer_manager.report_invalid_block(peer_id);
    }

    /// Report valid transaction from peer (adjusts score)
    pub fn report_valid_tx(&self, peer_id: &PeerId) {
        self.peer_manager.report_valid_tx(peer_id);
    }

    /// Report invalid transaction from peer (adjusts score)
    pub fn report_invalid_tx(&self, peer_id: &PeerId) {
        self.peer_manager.report_invalid_tx(peer_id);
    }

    /// Report successful sync from peer
    pub fn report_sync_success(&self, peer_id: &PeerId) {
        self.peer_manager.report_sync_success(peer_id);
    }

    /// Report failed sync from peer
    pub fn report_sync_failure(&self, peer_id: &PeerId) {
        self.peer_manager.report_sync_failure(peer_id);
    }

    /// Ban a peer manually
    pub fn ban_peer(&self, peer_id: &PeerId, duration: Duration) {
        self.peer_manager.ban_peer(peer_id, duration);
    }

    /// Unban a peer
    pub fn unban_peer(&self, peer_id: &PeerId) {
        self.peer_manager.unban_peer(peer_id);
    }

    /// Run the network service (blocking)
    pub async fn run(
        &self,
        mut command_rx: mpsc::Receiver<NetworkCommand>,
    ) -> Result<()> {
        info!("Starting P2P network service");

        // Load or generate keypair (persistent if node_key_file is set)
        let local_key = crate::node_key::load_or_generate_keypair(
            self.config.node_key_file.as_deref()
        )?;
        let local_peer_id = PeerId::from(local_key.public());

        *self.local_peer_id.write() = Some(local_peer_id);
        info!("Local peer ID: {}", local_peer_id);

        // Build swarm
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| P2pError::Transport(e.to_string()))?
            .with_behaviour(|key| {
                SumChainBehaviour::new(PeerId::from(key.public()), self.config.enable_mdns)
                    .expect("Failed to create behaviour")
            })
            .map_err(|e| P2pError::Transport(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Subscribe to topics
        swarm
            .behaviour_mut()
            .subscribe_topics()
            .map_err(|e| P2pError::Gossip(e.to_string()))?;

        // Listen on configured address
        let listen_addr = self
            .config
            .listen_multiaddr()
            .map_err(|e| P2pError::Listen(e.to_string()))?;

        swarm
            .listen_on(listen_addr.clone())
            .map_err(|e| P2pError::Listen(e.to_string()))?;

        info!("Listening on {}", listen_addr);

        // Connect to bootnodes
        for addr in self.config.bootnode_multiaddrs() {
            info!("Connecting to bootnode: {}", addr);
            if let Err(e) = swarm.dial(addr.clone()) {
                warn!("Failed to dial bootnode {}: {}", addr, e);
            }
        }

        *self.running.write() = true;

        // Pending sync response channels (stored locally since they can't be sent through channels)
        let mut pending_sync_responses: HashMap<
            SyncRequestId,
            libp2p::request_response::ResponseChannel<SyncResponse>,
        > = HashMap::new();
        let next_request_id = AtomicU64::new(1);

        // Event loop
        loop {
            tokio::select! {
                // Handle swarm events
                event = swarm.select_next_some() => {
                    self.handle_swarm_event_with_sync(
                        &mut swarm,
                        event,
                        &mut pending_sync_responses,
                        &next_request_id,
                    );
                }

                // Handle commands
                cmd = command_rx.recv() => {
                    match cmd {
                        Some(NetworkCommand::BroadcastTransaction(tx)) => {
                            self.publish_transaction(&mut swarm, &tx);
                        }
                        Some(NetworkCommand::BroadcastBlock(block)) => {
                            self.publish_block(&mut swarm, &block);
                        }
                        Some(NetworkCommand::BroadcastBftProposal(data)) => {
                            self.publish_bft_message(&mut swarm, topics::BFT_PROPOSALS, data);
                        }
                        Some(NetworkCommand::BroadcastBftPrevote(data)) => {
                            self.publish_bft_message(&mut swarm, topics::BFT_PREVOTES, data);
                        }
                        Some(NetworkCommand::BroadcastBftPrecommit(data)) => {
                            self.publish_bft_message(&mut swarm, topics::BFT_PRECOMMITS, data);
                        }
                        Some(NetworkCommand::Dial(addr)) => {
                            if let Err(e) = swarm.dial(addr.clone()) {
                                warn!("Failed to dial {}: {}", addr, e);
                            }
                        }
                        Some(NetworkCommand::RequestSyncStatus(peer)) => {
                            debug!("Requesting sync status from {}", peer);
                            swarm.behaviour_mut().sync.send_request(&peer, SyncRequest::GetStatus);
                        }
                        Some(NetworkCommand::RequestBlocks { peer, from_height, to_height }) => {
                            debug!("Requesting blocks {}-{} from {}", from_height, to_height, peer);
                            swarm.behaviour_mut().sync.send_request(
                                &peer,
                                SyncRequest::GetBlocks { from_height, to_height },
                            );
                        }
                        Some(NetworkCommand::SendSyncStatusResponse { request_id, height, best_hash, chain_id }) => {
                            if let Some(channel) = pending_sync_responses.remove(&request_id) {
                                let response = SyncResponse::Status { height, best_hash, chain_id };
                                if swarm.behaviour_mut().sync.send_response(channel, response).is_err() {
                                    warn!("Failed to send sync status response");
                                }
                            } else {
                                warn!("No pending response channel for request_id {}", request_id);
                            }
                        }
                        Some(NetworkCommand::SendSyncBlocksResponse { request_id, blocks }) => {
                            if let Some(channel) = pending_sync_responses.remove(&request_id) {
                                let response = SyncResponse::Blocks(blocks);
                                if swarm.behaviour_mut().sync.send_response(channel, response).is_err() {
                                    warn!("Failed to send sync blocks response");
                                }
                            } else {
                                warn!("No pending response channel for request_id {}", request_id);
                            }
                        }
                        Some(NetworkCommand::SendSyncErrorResponse { request_id, error }) => {
                            if let Some(channel) = pending_sync_responses.remove(&request_id) {
                                let response = SyncResponse::Error(error);
                                if swarm.behaviour_mut().sync.send_response(channel, response).is_err() {
                                    warn!("Failed to send sync error response");
                                }
                            } else {
                                warn!("No pending response channel for request_id {}", request_id);
                            }
                        }
                        None => {
                            info!("Command channel closed, shutting down");
                            break;
                        }
                    }
                }
            }
        }

        *self.running.write() = false;
        Ok(())
    }

    /// Handle swarm events with sync support
    fn handle_swarm_event_with_sync(
        &self,
        swarm: &mut Swarm<SumChainBehaviour>,
        event: SwarmEvent<SumChainBehaviourEvent>,
        pending_sync_responses: &mut HashMap<SyncRequestId, libp2p::request_response::ResponseChannel<SyncResponse>>,
        next_request_id: &AtomicU64,
    ) {
        match event {
            SwarmEvent::Behaviour(SumChainBehaviourEvent::Gossipsub(
                gossipsub::Event::Message {
                    propagation_source,
                    message_id: _,
                    message,
                },
            )) => {
                self.handle_gossip_message(&message.topic, &message.data, propagation_source);
            }

            SwarmEvent::Behaviour(SumChainBehaviourEvent::Mdns(mdns::Event::Discovered(
                peers,
            ))) => {
                for (peer_id, addr) in peers {
                    debug!("mDNS discovered peer: {} at {}", peer_id, addr);
                    // Register peer with peer manager
                    self.peer_manager.register_peer(peer_id, vec![addr.clone()]);

                    // Check if we can connect
                    if self.peer_manager.can_connect_outbound(&peer_id) {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        if let Err(e) = swarm.dial(addr) {
                            debug!("Failed to dial discovered peer: {}", e);
                            self.peer_manager.connection_failed(&peer_id);
                        }
                    } else {
                        debug!("Skipping connection to {} (connection limits or backoff)", peer_id);
                    }
                }
            }

            SwarmEvent::Behaviour(SumChainBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                for (peer_id, _) in peers {
                    debug!("mDNS peer expired: {}", peer_id);
                    swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                }
            }

            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                // Determine connection direction from endpoint
                let direction = if endpoint.is_dialer() {
                    ConnectionDirection::Outbound
                } else {
                    ConnectionDirection::Inbound
                };

                // Register with peer manager
                self.peer_manager.peer_connected(peer_id, direction, None);

                info!("Connected to peer: {} ({:?})", peer_id, direction);
                self.peers.write().insert(peer_id);
                let _ = self.event_tx.send(NetworkEvent::PeerConnected(peer_id));
            }

            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.peer_manager.peer_disconnected(&peer_id);
                info!("Disconnected from peer: {}", peer_id);
                self.peers.write().remove(&peer_id);
                let _ = self.event_tx.send(NetworkEvent::PeerDisconnected(peer_id));
            }

            SwarmEvent::OutgoingConnectionError { peer_id, .. } => {
                if let Some(pid) = peer_id {
                    self.peer_manager.connection_failed(&pid);
                    debug!("Outgoing connection failed to {}", pid);
                }
            }

            SwarmEvent::IncomingConnectionError { .. } => {
                debug!("Incoming connection error");
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on: {}", address);
            }

            // Handle sync protocol events
            SwarmEvent::Behaviour(SumChainBehaviourEvent::Sync(sync_event)) => {
                self.handle_sync_event(sync_event, pending_sync_responses, next_request_id);
            }

            _ => {}
        }
    }

    /// Handle sync protocol events
    fn handle_sync_event(
        &self,
        event: SyncEvent,
        pending_sync_responses: &mut HashMap<SyncRequestId, libp2p::request_response::ResponseChannel<SyncResponse>>,
        next_request_id: &AtomicU64,
    ) {
        use libp2p::request_response::{Event, Message};

        match event {
            Event::Message { peer, message } => match message {
                Message::Request { request, channel, .. } => {
                    debug!("Received sync request from {}: {:?}", peer, request);
                    match request {
                        SyncRequest::GetStatus => {
                            // Generate a unique request ID and store the channel
                            let request_id = next_request_id.fetch_add(1, Ordering::SeqCst);
                            pending_sync_responses.insert(request_id, channel);
                            // Forward to node to respond with current status
                            let _ = self.event_tx.send(NetworkEvent::SyncStatusRequest {
                                request_id,
                                peer,
                            });
                        }
                        SyncRequest::GetBlocks { from_height, to_height } => {
                            // Generate a unique request ID and store the channel
                            let request_id = next_request_id.fetch_add(1, Ordering::SeqCst);
                            pending_sync_responses.insert(request_id, channel);
                            // Forward to node to respond with blocks
                            let _ = self.event_tx.send(NetworkEvent::SyncBlocksRequest {
                                request_id,
                                peer,
                                from_height,
                                to_height,
                            });
                        }
                        SyncRequest::GetBlockByHash(_hash) => {
                            // Not implemented yet - respond with error
                            warn!("GetBlockByHash not implemented, ignoring");
                        }
                    }
                }
                Message::Response { response, .. } => {
                    debug!("Received sync response from {}: {:?}", peer, std::mem::discriminant(&response));
                    match response {
                        SyncResponse::Status {
                            height,
                            best_hash,
                            chain_id,
                        } => {
                            let _ = self.event_tx.send(NetworkEvent::SyncStatusResponse {
                                peer,
                                height,
                                best_hash,
                                chain_id,
                            });
                        }
                        SyncResponse::Blocks(blocks) => {
                            info!("Received {} blocks from {}", blocks.len(), peer);
                            let _ = self.event_tx.send(NetworkEvent::SyncBlocksReceived {
                                peer,
                                blocks,
                            });
                        }
                        SyncResponse::Block(block_opt) => {
                            if let Some(block) = block_opt {
                                let _ = self.event_tx.send(NetworkEvent::SyncBlocksReceived {
                                    peer,
                                    blocks: vec![block],
                                });
                            }
                        }
                        SyncResponse::Error(error) => {
                            warn!("Sync error from {}: {}", peer, error);
                            let _ = self.event_tx.send(NetworkEvent::SyncRequestFailed {
                                peer,
                                error,
                            });
                        }
                    }
                }
            },
            Event::OutboundFailure { peer, error, .. } => {
                warn!("Outbound sync request to {} failed: {:?}", peer, error);
                let _ = self.event_tx.send(NetworkEvent::SyncRequestFailed {
                    peer,
                    error: format!("{:?}", error),
                });
            }
            Event::InboundFailure { peer, error, .. } => {
                warn!("Inbound sync request from {} failed: {:?}", peer, error);
            }
            Event::ResponseSent { peer, .. } => {
                debug!("Sync response sent to {}", peer);
            }
        }
    }

    /// Handle incoming gossip message with rate limiting
    fn handle_gossip_message(&self, topic: &gossipsub::TopicHash, data: &[u8], source: PeerId) {
        let topic_str = topic.to_string();

        if topic_str.contains(topics::TRANSACTIONS) {
            // Apply rate limiting for transactions
            if !self.rate_limiter.check_rate_limit(source, MessageType::Transaction) {
                debug!("Rate limited transaction from {}", source);
                self.peer_manager.report_invalid_tx(&source); // Penalize for flooding
                return;
            }

            match SignedTransaction::from_bytes(data) {
                Ok(tx) => {
                    debug!("Received transaction {} from {}", tx.hash(), source);
                    let _ = self.event_tx.send(NetworkEvent::TransactionReceived(tx));
                }
                Err(e) => {
                    warn!("Failed to decode transaction from {}: {}", source, e);
                    self.peer_manager.report_invalid_tx(&source);
                }
            }
        } else if topic_str.contains(topics::BLOCKS) {
            // Apply rate limiting for blocks
            if !self.rate_limiter.check_rate_limit(source, MessageType::Block) {
                debug!("Rate limited block from {}", source);
                self.peer_manager.report_invalid_block(&source);
                return;
            }

            match Block::from_bytes(data) {
                Ok(block) => {
                    debug!(
                        "Received block {} (height {}) from {}",
                        block.hash(),
                        block.height(),
                        source
                    );
                    let _ = self.event_tx.send(NetworkEvent::BlockReceived(block));
                }
                Err(e) => {
                    warn!("Failed to decode block from {}: {}", source, e);
                    self.peer_manager.report_invalid_block(&source);
                }
            }
        } else if topic_str.contains("bft/proposal") {
            // Apply rate limiting for BFT messages
            if !self.rate_limiter.check_rate_limit(source, MessageType::BftMessage) {
                debug!("Rate limited BFT proposal from {}", source);
                return;
            }
            debug!("Received BFT proposal from {}", source);
            let _ = self.event_tx.send(NetworkEvent::BftProposalReceived(data.to_vec()));
        } else if topic_str.contains("bft/prevote") {
            if !self.rate_limiter.check_rate_limit(source, MessageType::BftMessage) {
                debug!("Rate limited BFT prevote from {}", source);
                return;
            }
            debug!("Received BFT prevote from {}", source);
            let _ = self.event_tx.send(NetworkEvent::BftPrevoteReceived(data.to_vec()));
        } else if topic_str.contains("bft/precommit") {
            if !self.rate_limiter.check_rate_limit(source, MessageType::BftMessage) {
                debug!("Rate limited BFT precommit from {}", source);
                return;
            }
            debug!("Received BFT precommit from {}", source);
            let _ = self.event_tx.send(NetworkEvent::BftPrecommitReceived(data.to_vec()));
        }
    }

    /// Publish a transaction to the network
    fn publish_transaction(&self, swarm: &mut Swarm<SumChainBehaviour>, tx: &SignedTransaction) {
        let topic = IdentTopic::new(topics::TRANSACTIONS);
        let data = tx.to_bytes();

        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
            warn!("Failed to publish transaction: {}", e);
        } else {
            debug!("Published transaction {}", tx.hash());
        }
    }

    /// Publish a block to the network
    fn publish_block(&self, swarm: &mut Swarm<SumChainBehaviour>, block: &Block) {
        let topic = IdentTopic::new(topics::BLOCKS);
        let data = block.to_bytes();

        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
            warn!(
                "Failed to publish block {} (height {}): {:?}",
                block.hash(),
                block.height(),
                e
            );
        } else {
            debug!("Published block {} (height {})", block.hash(), block.height());
        }
    }

    /// Publish a BFT consensus message to the network
    fn publish_bft_message(&self, swarm: &mut Swarm<SumChainBehaviour>, topic_name: &str, data: Vec<u8>) {
        let topic = IdentTopic::new(topic_name);

        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
            warn!("Failed to publish BFT message to {}: {:?}", topic_name, e);
        } else {
            debug!("Published BFT message to {}", topic_name);
        }
    }
}

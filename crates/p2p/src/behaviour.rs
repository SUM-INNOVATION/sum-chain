//! Custom libp2p behaviour for SUM Chain.
//!
//! Combines gossipsub for message propagation, mDNS for local discovery,
//! and request-response for block synchronization.
//!
//! ## Security Features
//! - Peer scoring to penalize misbehaving peers
//! - Rate limiting via gossipsub parameters
//! - Message validation and deduplication
//! - Eclipse attack prevention via mesh configuration

use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode, PeerScoreParams, PeerScoreThresholds, TopicScoreParams},
    identify, mdns, request_response,
    swarm::NetworkBehaviour, PeerId,
};
use std::time::Duration;

use crate::sync::{self, SyncCodec, SyncRequest, SyncResponse};
use crate::topics;

/// Combined network behaviour
#[derive(NetworkBehaviour)]
pub struct SumChainBehaviour {
    /// Gossipsub for message propagation
    pub gossipsub: gossipsub::Behaviour,
    /// mDNS for local peer discovery
    pub mdns: mdns::tokio::Behaviour,
    /// Identify protocol for peer info exchange
    pub identify: identify::Behaviour,
    /// Request-response for block sync
    pub sync: request_response::Behaviour<SyncCodec>,
}

/// Type alias for sync request-response events
pub type SyncEvent = request_response::Event<SyncRequest, SyncResponse>;

/// Network configuration for different deployment scenarios
#[derive(Debug, Clone)]
pub struct NetworkSecurityConfig {
    /// Minimum peers in mesh (eclipse attack prevention)
    pub mesh_n_low: usize,
    /// Target peers in mesh
    pub mesh_n: usize,
    /// Maximum peers in mesh
    pub mesh_n_high: usize,
    /// Minimum outbound peers (prevents isolation)
    pub mesh_outbound_min: usize,
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,
    /// Message cache time in seconds
    pub message_cache_ttl_secs: u64,
    /// Enable peer scoring
    pub enable_peer_scoring: bool,
    /// Maximum message size in bytes
    pub max_message_size: usize,
}

impl Default for NetworkSecurityConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl NetworkSecurityConfig {
    /// Configuration for small testnets (3-5 validators)
    pub fn testnet() -> Self {
        Self {
            mesh_n_low: 1,
            mesh_n: 2,
            mesh_n_high: 4,
            mesh_outbound_min: 0,
            heartbeat_interval_ms: 1000,
            message_cache_ttl_secs: 120,
            enable_peer_scoring: false, // Disable for easier testing
            max_message_size: 10 * 1024 * 1024, // 10 MB
        }
    }

    /// Configuration for production networks
    pub fn production() -> Self {
        Self {
            mesh_n_low: 4,              // Minimum 4 peers to prevent eclipse
            mesh_n: 6,                  // Target 6 peers in mesh
            mesh_n_high: 12,            // Maximum 12 peers
            mesh_outbound_min: 2,       // At least 2 outbound connections
            heartbeat_interval_ms: 700, // Faster heartbeat for BFT
            message_cache_ttl_secs: 300, // 5 minute cache
            enable_peer_scoring: true,  // Enable peer scoring
            max_message_size: 5 * 1024 * 1024, // 5 MB (smaller for DoS prevention)
        }
    }

    /// Configuration for high-security networks
    pub fn high_security() -> Self {
        Self {
            mesh_n_low: 6,
            mesh_n: 8,
            mesh_n_high: 16,
            mesh_outbound_min: 4,
            heartbeat_interval_ms: 500,
            message_cache_ttl_secs: 600,
            enable_peer_scoring: true,
            max_message_size: 2 * 1024 * 1024, // 2 MB
        }
    }
}

impl SumChainBehaviour {
    /// Create a new behaviour with the given peer ID (uses testnet config)
    pub fn new(local_peer_id: PeerId, enable_mdns: bool) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_security_config(local_peer_id, enable_mdns, NetworkSecurityConfig::testnet())
    }

    /// Create a new behaviour with custom security configuration
    pub fn with_security_config(
        local_peer_id: PeerId,
        enable_mdns: bool,
        security_config: NetworkSecurityConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Configure gossipsub with security-hardened settings
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            // Timing parameters
            .heartbeat_interval(Duration::from_millis(security_config.heartbeat_interval_ms))
            .history_length(12)          // Keep 12 heartbeats of history
            .history_gossip(3)           // Gossip about last 3 heartbeats

            // Message validation
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(|message| {
                // Use content hash as message ID to deduplicate
                let hash = sumchain_primitives::Hash::hash(&message.data);
                gossipsub::MessageId::from(hash.as_bytes().to_vec())
            })

            // Size limits (DoS prevention)
            .max_transmit_size(security_config.max_message_size)

            // Mesh configuration (eclipse attack prevention)
            .mesh_n_low(security_config.mesh_n_low)
            .mesh_n(security_config.mesh_n)
            .mesh_n_high(security_config.mesh_n_high)
            .mesh_outbound_min(security_config.mesh_outbound_min)

            // Gossip parameters
            .gossip_lazy(6)              // Peers for lazy gossip propagation
            .gossip_factor(0.25)         // 25% of peers for gossip
            .flood_publish(true)         // Flood publish for reliability

            // Fanout configuration
            .fanout_ttl(Duration::from_secs(60))

            // Duplicate message cache
            .duplicate_cache_time(Duration::from_secs(security_config.message_cache_ttl_secs))

            .build()
            .map_err(|e| format!("Failed to build gossipsub config: {}", e))?;

        // Create gossipsub with or without peer scoring
        let mut gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(libp2p::identity::Keypair::generate_ed25519()),
            gossipsub_config,
        )
        .map_err(|e| format!("Failed to create gossipsub: {}", e))?;

        // Enable peer scoring for production networks
        if security_config.enable_peer_scoring {
            let peer_score_params = Self::build_peer_score_params();
            let peer_score_thresholds = Self::build_peer_score_thresholds();
            gossipsub
                .with_peer_score(peer_score_params, peer_score_thresholds)
                .map_err(|e| format!("Failed to set peer scoring: {}", e))?;
        }

        // Configure mDNS
        let mdns = if enable_mdns {
            mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?
        } else {
            // Create disabled mDNS (will be ignored)
            mdns::tokio::Behaviour::new(
                mdns::Config {
                    ttl: Duration::from_secs(0),
                    query_interval: Duration::from_secs(u64::MAX),
                    ..Default::default()
                },
                local_peer_id,
            )?
        };

        // Configure identify
        let identify = identify::Behaviour::new(identify::Config::new(
            "/sumchain/1.0.0".to_string(),
            libp2p::identity::Keypair::generate_ed25519().public(),
        ));

        // Configure sync (request-response)
        let sync = sync::create_sync_behaviour();

        Ok(Self {
            gossipsub,
            mdns,
            identify,
            sync,
        })
    }

    /// Subscribe to all SUM Chain topics
    pub fn subscribe_topics(&mut self) -> Result<(), gossipsub::SubscriptionError> {
        let tx_topic = IdentTopic::new(topics::TRANSACTIONS);
        let block_topic = IdentTopic::new(topics::BLOCKS);
        let proposal_topic = IdentTopic::new(topics::BFT_PROPOSALS);
        let prevote_topic = IdentTopic::new(topics::BFT_PREVOTES);
        let precommit_topic = IdentTopic::new(topics::BFT_PRECOMMITS);

        self.gossipsub.subscribe(&tx_topic)?;
        self.gossipsub.subscribe(&block_topic)?;
        self.gossipsub.subscribe(&proposal_topic)?;
        self.gossipsub.subscribe(&prevote_topic)?;
        self.gossipsub.subscribe(&precommit_topic)?;

        Ok(())
    }

    /// Build peer score parameters for gossipsub
    ///
    /// This penalizes misbehaving peers and rewards good behavior:
    /// - Invalid messages: heavy penalty
    /// - Message delivery: small reward
    /// - First delivery: bonus for being first
    fn build_peer_score_params() -> PeerScoreParams {
        // Topic-specific scoring for consensus messages
        let mut topic_params = std::collections::HashMap::new();

        // BFT proposal topic - high importance
        let proposal_params = TopicScoreParams {
            topic_weight: 1.0,
            time_in_mesh_weight: 0.1,
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 3600.0,
            first_message_deliveries_weight: 1.0,
            first_message_deliveries_decay: 0.9,
            first_message_deliveries_cap: 100.0,
            mesh_message_deliveries_weight: -1.0,
            mesh_message_deliveries_decay: 0.9,
            mesh_message_deliveries_cap: 100.0,
            mesh_message_deliveries_threshold: 1.0,
            mesh_message_deliveries_window: Duration::from_secs(10),
            mesh_message_deliveries_activation: Duration::from_secs(30),
            mesh_failure_penalty_weight: -1.0,
            mesh_failure_penalty_decay: 0.9,
            invalid_message_deliveries_weight: -100.0, // Heavy penalty for invalid messages
            invalid_message_deliveries_decay: 0.1,
        };

        // Block topic - important for sync
        let block_params = TopicScoreParams {
            topic_weight: 0.8,
            time_in_mesh_weight: 0.1,
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 3600.0,
            first_message_deliveries_weight: 0.5,
            first_message_deliveries_decay: 0.9,
            first_message_deliveries_cap: 100.0,
            mesh_message_deliveries_weight: -0.5,
            mesh_message_deliveries_decay: 0.9,
            mesh_message_deliveries_cap: 100.0,
            mesh_message_deliveries_threshold: 1.0,
            mesh_message_deliveries_window: Duration::from_secs(10),
            mesh_message_deliveries_activation: Duration::from_secs(30),
            mesh_failure_penalty_weight: -0.5,
            mesh_failure_penalty_decay: 0.9,
            invalid_message_deliveries_weight: -50.0,
            invalid_message_deliveries_decay: 0.1,
        };

        // Transaction topic - lower priority
        let tx_params = TopicScoreParams {
            topic_weight: 0.5,
            time_in_mesh_weight: 0.05,
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 3600.0,
            first_message_deliveries_weight: 0.1,
            first_message_deliveries_decay: 0.9,
            first_message_deliveries_cap: 1000.0,
            mesh_message_deliveries_weight: -0.1,
            mesh_message_deliveries_decay: 0.9,
            mesh_message_deliveries_cap: 1000.0,
            mesh_message_deliveries_threshold: 5.0,
            mesh_message_deliveries_window: Duration::from_secs(60),
            mesh_message_deliveries_activation: Duration::from_secs(120),
            mesh_failure_penalty_weight: -0.1,
            mesh_failure_penalty_decay: 0.9,
            invalid_message_deliveries_weight: -10.0,
            invalid_message_deliveries_decay: 0.5,
        };

        topic_params.insert(gossipsub::TopicHash::from_raw(topics::BFT_PROPOSALS), proposal_params.clone());
        topic_params.insert(gossipsub::TopicHash::from_raw(topics::BFT_PREVOTES), proposal_params.clone());
        topic_params.insert(gossipsub::TopicHash::from_raw(topics::BFT_PRECOMMITS), proposal_params);
        topic_params.insert(gossipsub::TopicHash::from_raw(topics::BLOCKS), block_params);
        topic_params.insert(gossipsub::TopicHash::from_raw(topics::TRANSACTIONS), tx_params);

        PeerScoreParams {
            topics: topic_params,
            // Cap for topic score contribution
            topic_score_cap: 100.0,
            // Application-specific scoring
            app_specific_weight: 1.0,
            // IP colocation factor (penalize many peers from same IP)
            ip_colocation_factor_weight: -10.0,
            ip_colocation_factor_threshold: 3.0,
            ip_colocation_factor_whitelist: std::collections::HashSet::new(),
            // Behaviour penalty (exponential decay)
            behaviour_penalty_weight: -1.0,
            behaviour_penalty_decay: 0.9,
            behaviour_penalty_threshold: 1.0,
            // Decay parameters
            decay_interval: Duration::from_secs(60),
            decay_to_zero: 0.01,
            retain_score: Duration::from_secs(3600),
        }
    }

    /// Build peer score thresholds
    ///
    /// Determines when to disconnect or ignore peers based on score
    fn build_peer_score_thresholds() -> PeerScoreThresholds {
        PeerScoreThresholds {
            // Below this score, peer is ignored for gossip
            gossip_threshold: -100.0,
            // Below this score, peer is not considered for mesh
            publish_threshold: -1000.0,
            // Below this score, peer won't receive grafts
            graylist_threshold: -2500.0,
            // Below this score, peer is disconnected
            accept_px_threshold: 100.0,
            // Peers with this score can give peer exchange info
            opportunistic_graft_threshold: 5.0,
        }
    }
}

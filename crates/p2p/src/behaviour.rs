//! Custom libp2p behaviour for SUM Chain.
//!
//! Combines gossipsub for message propagation, mDNS for local discovery,
//! and request-response for block synchronization.

use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
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

impl SumChainBehaviour {
    /// Create a new behaviour with the given peer ID
    pub fn new(local_peer_id: PeerId, enable_mdns: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Configure gossipsub with settings appropriate for small networks
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(|message| {
                // Use content hash as message ID to deduplicate
                let hash = sumchain_primitives::Hash::hash(&message.data);
                gossipsub::MessageId::from(hash.as_bytes().to_vec())
            })
            .max_transmit_size(10 * 1024 * 1024) // 10 MB
            // Allow publishing with fewer peers (for small networks/testnets)
            .mesh_n_low(1)      // Min peers in mesh
            .mesh_n(2)          // Target peers in mesh
            .mesh_n_high(4)     // Max peers in mesh
            .mesh_outbound_min(0) // Allow zero outbound (for startup)
            .gossip_lazy(1)     // Peers for lazy gossip
            .flood_publish(true) // Flood publish to all peers, not just mesh
            .build()
            .map_err(|e| format!("Failed to build gossipsub config: {}", e))?;

        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(libp2p::identity::Keypair::generate_ed25519()),
            gossipsub_config,
        )
        .map_err(|e| format!("Failed to create gossipsub: {}", e))?;

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
}

//! Network configuration for SUM Chain P2P.

use std::path::PathBuf;

use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Address to listen on
    pub listen_addr: String,
    /// Bootstrap nodes to connect to
    pub bootnodes: Vec<String>,
    /// Enable mDNS for local peer discovery
    pub enable_mdns: bool,
    /// Maximum inbound connections
    pub max_inbound: u32,
    /// Maximum outbound connections
    pub max_outbound: u32,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Rate limit: max messages per second per peer
    pub rate_limit_per_peer: u32,
    /// Path to node key file (for persistent peer ID)
    #[serde(default)]
    pub node_key_file: Option<PathBuf>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/30303".to_string(),
            bootnodes: Vec::new(),
            enable_mdns: true,
            max_inbound: 50,
            max_outbound: 50,
            max_message_size: 10 * 1024 * 1024, // 10 MB
            rate_limit_per_peer: 100,
            node_key_file: None,
        }
    }
}

impl NetworkConfig {
    /// Parse listen address as Multiaddr
    pub fn listen_multiaddr(&self) -> Result<Multiaddr, libp2p::multiaddr::Error> {
        self.listen_addr.parse()
    }

    /// Parse bootnode addresses
    pub fn bootnode_multiaddrs(&self) -> Vec<Multiaddr> {
        self.bootnodes
            .iter()
            .filter_map(|addr| addr.parse().ok())
            .collect()
    }
}

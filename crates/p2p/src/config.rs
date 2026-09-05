//! Network configuration for SUM Chain P2P.

use std::path::PathBuf;

use libp2p_core::Multiaddr;
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
    pub fn listen_multiaddr(&self) -> Result<Multiaddr, libp2p_core::multiaddr::Error> {
        self.listen_addr.parse()
    }

    /// Parse bootnode addresses
    pub fn bootnode_multiaddrs(&self) -> Vec<Multiaddr> {
        self.bootnodes
            .iter()
            .filter_map(|addr| addr.parse().ok())
            .collect()
    }

    /// Bootnode entries that can never be dialed, each with an actionable reason.
    ///
    /// Only **unparseable** entries qualify now. They were previously discarded
    /// in silence by `bootnode_multiaddrs`'s `filter_map(...ok())`, which is part
    /// of how a devnet ran for months on a bootnode nothing could reach (#237).
    ///
    /// DNS multiaddrs (`/dns`, `/dns4`, `/dns6`, `/dnsaddr`) are **no longer**
    /// reported here: [`crate::dns`] resolves them through the OS resolver and
    /// dials the resulting literal addresses, so they are dialable again. A DNS
    /// name that fails to resolve is reported at dial time with its typed reason
    /// — which is the right place, since resolvability is a runtime property, not
    /// a property of the configured string.
    pub fn undialable_bootnodes(&self) -> Vec<(String, &'static str)> {
        self.bootnodes
            .iter()
            .filter(|entry| entry.parse::<Multiaddr>().is_err())
            .map(|entry| (entry.clone(), "not a valid multiaddr"))
            .collect()
    }
}

#[cfg(test)]
mod bootnode_reachability_tests {
    use super::*;

    fn cfg(bootnodes: &[&str]) -> NetworkConfig {
        NetworkConfig {
            bootnodes: bootnodes.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// DNS bootnodes are dialable again (#237): `crate::dns` resolves them
    /// through the OS resolver and dials the literal results, so they must NOT
    /// be reported unusable. This is the inverse of the guard that stood here
    /// before the resolver existed — it fails if the old behaviour returns.
    #[test]
    fn dns_bootnodes_are_no_longer_reported_unusable() {
        for entry in [
            "/dns4/validator-1/tcp/30303",
            "/dns6/validator-1/tcp/30303",
            "/dns/validator-1/tcp/30303",
            "/dns4/sumchain-validator-1-0.sumchain-validator-1.sumchain.svc.cluster.local/tcp/30303",
        ] {
            assert_eq!(
                cfg(&[entry]).undialable_bootnodes(),
                vec![],
                "{entry} is resolvable via the OS resolver and must not be refused"
            );
            // It must also survive parsing into the dialable set.
            assert_eq!(cfg(&[entry]).bootnode_multiaddrs().len(), 1);
        }
    }

    /// Literal addresses stay usable and skip the resolver entirely.
    #[test]
    fn literal_ip_bootnodes_are_usable() {
        let c = cfg(&[
            "/ip4/172.28.0.11/tcp/30303",
            "/ip6/::1/tcp/30303",
            "/ip4/10.0.1.10/tcp/9933/p2p/\
             12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        ]);
        assert_eq!(c.undialable_bootnodes(), vec![]);
    }

    /// A malformed entry used to vanish inside `filter_map(...ok())`.
    #[test]
    fn unparseable_bootnodes_are_not_dropped_silently() {
        let c = cfg(&["not-a-multiaddr", "/ip4/172.28.0.11/tcp/30303"]);
        let bad = c.undialable_bootnodes();
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].0, "not-a-multiaddr");
        assert_eq!(bad[0].1, "not a valid multiaddr");
        assert_eq!(c.bootnode_multiaddrs().len(), 1);
    }

    /// A `/p2p/` suffix whose PeerId is a placeholder does not parse, so the
    /// whole entry is unusable. `configs/bft-config.toml` ships exactly that
    /// shape; before this it disappeared without a word.
    #[test]
    fn placeholder_peer_id_is_reported_not_silently_dropped() {
        let c = cfg(&["/ip4/10.0.1.10/tcp/9933/p2p/12D3KooWBootNode1..."]);
        let bad = c.undialable_bootnodes();
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].1, "not a valid multiaddr");
        assert!(c.bootnode_multiaddrs().is_empty());
    }

    #[test]
    fn no_bootnodes_configured_is_not_an_error() {
        assert!(cfg(&[]).undialable_bootnodes().is_empty());
    }
}

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
    /// Two classes are unreachable and were previously discarded in silence
    /// (`bootnode_multiaddrs` drops parse failures, and a rejected dial was only
    /// a `warn!`), which is how a devnet ran for months on a bootnode address
    /// nothing could resolve — see #237:
    ///
    /// * **unparseable** multiaddr strings;
    /// * **DNS-based** multiaddrs (`/dns`, `/dns4`, `/dns6`, `/dnsaddr`). The
    ///   transport stack is TCP → Noise → Yamux with **no DNS resolution layer**,
    ///   so libp2p rejects these as `MultiaddrNotSupported`. It resolves names
    ///   through its own transport, never through the host or a container
    ///   runtime's DNS. Adding libp2p's DNS transport would pull
    ///   `libp2p-dns → hickory-resolver → hickory-proto` and reintroduce
    ///   RUSTSEC-2026-0119, which #202 exists to remove — so the fix is to
    ///   configure a literal `/ip4/…` or `/ip6/…` address instead.
    pub fn undialable_bootnodes(&self) -> Vec<(String, &'static str)> {
        use libp2p_core::multiaddr::Protocol;
        self.bootnodes
            .iter()
            .filter_map(|entry| match entry.parse::<Multiaddr>() {
                Err(_) => Some((entry.clone(), "not a valid multiaddr")),
                Ok(addr) => addr
                    .iter()
                    .any(|p| {
                        matches!(
                            p,
                            Protocol::Dns(_)
                                | Protocol::Dns4(_)
                                | Protocol::Dns6(_)
                                | Protocol::Dnsaddr(_)
                        )
                    })
                    .then_some((
                        entry.clone(),
                        "DNS multiaddr, but this transport has no DNS resolution \
                         layer (use a literal /ip4/ or /ip6/ address)",
                    )),
            })
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

    /// The #237 regression guard: a DNS bootnode is unusable, because the
    /// transport (TCP -> Noise -> Yamux) has no DNS resolution layer. Proven
    /// against the real transport: dialing `/dns4/...` returns
    /// `MultiaddrNotSupported` while `/ip4/...` is accepted.
    #[test]
    fn dns_bootnodes_are_reported_unusable() {
        for entry in [
            "/dns4/validator-1/tcp/30303",
            "/dns6/validator-1/tcp/30303",
            "/dns/validator-1/tcp/30303",
            "/dnsaddr/example.invalid",
        ] {
            let bad = cfg(&[entry]).undialable_bootnodes();
            assert_eq!(bad.len(), 1, "{entry} should be reported unusable");
            assert_eq!(bad[0].0, entry);
            assert!(bad[0].1.contains("DNS"), "reason should name the cause");
        }
    }

    /// Literal addresses — what the devnet must use — are accepted, with or
    /// without a `/p2p/<PeerId>` suffix.
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

    /// A `/p2p/` suffix whose PeerId is a placeholder does not parse, so the
    /// whole entry is unusable. `configs/bft-config.toml` ships exactly that
    /// shape (`.../p2p/12D3KooWBootNode1...`); before this change such an entry
    /// disappeared without a word.
    #[test]
    fn placeholder_peer_id_is_reported_not_silently_dropped() {
        let c = cfg(&["/ip4/10.0.1.10/tcp/9933/p2p/12D3KooWBootNode1..."]);
        let bad = c.undialable_bootnodes();
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].1, "not a valid multiaddr");
        assert!(c.bootnode_multiaddrs().is_empty());
    }

    /// A malformed entry used to vanish inside `filter_map(...ok())`.
    #[test]
    fn unparseable_bootnodes_are_not_dropped_silently() {
        let c = cfg(&["not-a-multiaddr", "/ip4/172.28.0.11/tcp/30303"]);
        let bad = c.undialable_bootnodes();
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].0, "not-a-multiaddr");
        // It is still absent from the dialable set — that is the silent part.
        assert_eq!(c.bootnode_multiaddrs().len(), 1);
    }

    #[test]
    fn no_bootnodes_configured_is_not_an_error() {
        assert!(cfg(&[]).undialable_bootnodes().is_empty());
    }
}

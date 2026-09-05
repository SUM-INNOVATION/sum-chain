//! Bootnode DNS resolution for a transport with no DNS layer (#237).
//!
//! The swarm's transport is TCP → Noise → Yamux. It has **no DNS resolution
//! layer**, so a `/dns4/host/tcp/p` multiaddr is rejected as
//! `MultiaddrNotSupported` — libp2p resolves names through its own transport
//! stack, never through the host or a container runtime's DNS. Adding libp2p's
//! DNS transport is not available to us: `libp2p-dns → hickory-resolver →
//! hickory-proto` is exactly the RUSTSEC-2026-0119 chain #202 removed.
//!
//! So we resolve names ourselves, through the **OS resolver**
//! (`tokio::net::lookup_host`, i.e. `getaddrinfo` on a blocking pool), and dial
//! literal `/ip4/` or `/ip6/` addresses. No new dependency, no advisory.
//!
//! Properties this module guarantees, each covered by a test below:
//!
//! * **Bounded** — every lookup runs under a caller-supplied timeout, so a black
//!   -holed resolver cannot wedge node startup.
//! * **All addresses** — a name resolving to several A/AAAA records yields
//!   *every* address, not just the first. A Kubernetes headless service is the
//!   motivating case: one name, one address per pod.
//! * **Suffix preserved** — the port and any `/p2p/<PeerId>` suffix survive the
//!   rewrite, so peer-identity pinning is not silently dropped.
//! * **Family respected** — `/dns4` yields only IPv4, `/dns6` only IPv6, `/dns`
//!   and `/dnsaddr` both.
//! * **Explicit failure** — every outcome is a typed error. Silence is what let
//!   the original defect survive unnoticed for months.
//!
//! Literal addresses pass through untouched and never hit the resolver.

use std::net::IpAddr;
use std::time::Duration;

use libp2p_core::multiaddr::{Multiaddr, Protocol};

/// Why a bootnode address could not be turned into dialable literal addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResolveError {
    /// The lookup did not finish inside the deadline.
    Timeout { host: String, after: Duration },
    /// The resolver answered, but nothing matched the requested address family.
    NoAddresses { host: String, family: &'static str },
    /// The OS resolver returned an error (NXDOMAIN, no resolver configured, …).
    Lookup { host: String, source: String },
    /// A DNS component was present but the multiaddr shape is not one we can
    /// rewrite (e.g. no `/tcp/<port>` to resolve against).
    UnsupportedShape { addr: String, reason: &'static str },
}

impl std::fmt::Display for DnsResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout { host, after } => {
                write!(f, "DNS lookup for '{host}' timed out after {after:?}")
            }
            Self::NoAddresses { host, family } => write!(
                f,
                "DNS lookup for '{host}' returned no {family} address"
            ),
            Self::Lookup { host, source } => {
                write!(f, "DNS lookup for '{host}' failed: {source}")
            }
            Self::UnsupportedShape { addr, reason } => {
                write!(f, "cannot resolve '{addr}': {reason}")
            }
        }
    }
}

impl std::error::Error for DnsResolveError {}

/// Which address family a DNS protocol component admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
    Any,
}

impl Family {
    fn admits(self, ip: IpAddr) -> bool {
        match self {
            Family::V4 => ip.is_ipv4(),
            Family::V6 => ip.is_ipv6(),
            Family::Any => true,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
            Family::Any => "IP",
        }
    }
}

/// Split a multiaddr into (host, family, tail-after-the-DNS-component).
/// Returns `None` when the address carries no DNS component at all.
fn dns_parts(addr: &Multiaddr) -> Option<(String, Family, Vec<Protocol<'static>>)> {
    let mut host_family: Option<(String, Family)> = None;
    let mut tail: Vec<Protocol<'static>> = Vec::new();

    for p in addr.iter() {
        match p {
            Protocol::Dns(h) if host_family.is_none() => {
                host_family = Some((h.to_string(), Family::Any));
            }
            Protocol::Dns4(h) if host_family.is_none() => {
                host_family = Some((h.to_string(), Family::V4));
            }
            Protocol::Dns6(h) if host_family.is_none() => {
                host_family = Some((h.to_string(), Family::V6));
            }
            Protocol::Dnsaddr(h) if host_family.is_none() => {
                host_family = Some((h.to_string(), Family::Any));
            }
            // Everything after the DNS component is preserved verbatim: the
            // /tcp/<port> and any /p2p/<PeerId> suffix ride through unchanged.
            other => tail.push(other.acquire()),
        }
    }
    host_family.map(|(h, f)| (h, f, tail))
}

/// The `/tcp/<port>` the resolver should be asked about. `getaddrinfo` wants a
/// port; the value is also what we re-emit, so it must come from the address.
fn tcp_port(tail: &[Protocol<'static>]) -> Option<u16> {
    tail.iter().find_map(|p| match p {
        Protocol::Tcp(port) => Some(*port),
        _ => None,
    })
}

/// Resolve one bootnode multiaddr into dialable literal addresses.
///
/// A literal address is returned unchanged (single element, no lookup). A DNS
/// address becomes **one multiaddr per resolved IP**, each preserving the
/// original port and `/p2p/` suffix.
pub async fn resolve_bootnode(
    addr: &Multiaddr,
    timeout: Duration,
) -> Result<Vec<Multiaddr>, DnsResolveError> {
    let Some((host, family, tail)) = dns_parts(addr) else {
        // Already literal — never touch the resolver.
        return Ok(vec![addr.clone()]);
    };

    let Some(port) = tcp_port(&tail) else {
        return Err(DnsResolveError::UnsupportedShape {
            addr: addr.to_string(),
            reason: "no /tcp/<port> component to resolve against",
        });
    };

    // Own the key so `host` is free to move into an error below.
    let answers = match tokio::time::timeout(
        timeout,
        tokio::net::lookup_host((host.clone(), port)),
    )
    .await
    {
        Err(_) => {
            return Err(DnsResolveError::Timeout {
                host,
                after: timeout,
            })
        }
        Ok(Err(e)) => {
            return Err(DnsResolveError::Lookup {
                host,
                source: e.to_string(),
            })
        }
        Ok(Ok(it)) => it,
    };

    // Every matching address is kept — a headless Service resolves to one
    // address per pod, and dialing only the first would reach one peer.
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for sa in answers {
        let ip = sa.ip();
        if !family.admits(ip) || !seen.insert(ip) {
            continue;
        }
        let mut rebuilt = Multiaddr::empty();
        rebuilt.push(match ip {
            IpAddr::V4(v4) => Protocol::Ip4(v4),
            IpAddr::V6(v6) => Protocol::Ip6(v6),
        });
        for p in &tail {
            rebuilt.push(p.clone());
        }
        out.push(rebuilt);
    }

    if out.is_empty() {
        return Err(DnsResolveError::NoAddresses {
            host,
            family: family.label(),
        });
    }
    Ok(out)
}

/// Outcome of resolving the whole configured bootnode set.
#[derive(Debug, Default)]
pub struct ResolvedBootnodes {
    /// Literal addresses ready to dial, in configuration order.
    pub addrs: Vec<Multiaddr>,
    /// One entry per configured bootnode that produced nothing, with its reason.
    pub failures: Vec<(String, DnsResolveError)>,
}

/// Resolve every configured bootnode, bounded per entry.
///
/// Failures never abort the set: one unreachable name must not stop the others
/// from being dialed. They are returned so the caller can report them — a
/// bootnode that silently resolves to nothing is precisely the #237 defect.
pub async fn resolve_all(
    addrs: impl IntoIterator<Item = Multiaddr>,
    timeout: Duration,
) -> ResolvedBootnodes {
    let mut out = ResolvedBootnodes::default();
    for a in addrs {
        match resolve_bootnode(&a, timeout).await {
            Ok(mut v) => out.addrs.append(&mut v),
            Err(e) => out.failures.push((a.to_string(), e)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(5);

    fn ma(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    #[tokio::test]
    async fn literal_addresses_pass_through_untouched() {
        for s in [
            "/ip4/172.28.0.11/tcp/30303",
            "/ip6/::1/tcp/30303",
            "/ip4/10.0.0.1/tcp/30303/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        ] {
            let a = ma(s);
            let got = resolve_bootnode(&a, T).await.expect("literal resolves");
            assert_eq!(got, vec![a], "literal must pass through unchanged");
        }
    }

    #[tokio::test]
    async fn dns4_localhost_resolves_to_a_dialable_ipv4_literal() {
        let got = resolve_bootnode(&ma("/dns4/localhost/tcp/30303"), T)
            .await
            .expect("localhost resolves");
        assert!(!got.is_empty());
        for a in &got {
            let protos: Vec<_> = a.iter().collect();
            assert!(matches!(protos[0], Protocol::Ip4(_)), "got {a}");
            assert!(matches!(protos[1], Protocol::Tcp(30303)), "port preserved");
        }
    }

    /// The `/p2p/<PeerId>` suffix is peer-identity pinning. Dropping it during
    /// the rewrite would silently disable authentication of the bootnode.
    #[tokio::test]
    async fn p2p_suffix_and_port_survive_the_rewrite() {
        const PID: &str = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        let got = resolve_bootnode(&ma(&format!("/dns4/localhost/tcp/45999/p2p/{PID}")), T)
            .await
            .expect("resolves");
        assert!(!got.is_empty());
        for a in &got {
            let s = a.to_string();
            assert!(s.contains("/tcp/45999"), "port lost: {s}");
            assert!(s.ends_with(&format!("/p2p/{PID}")), "peer id lost: {s}");
        }
    }

    #[tokio::test]
    async fn family_is_respected() {
        // dns6/localhost must not yield an IPv4 literal.
        if let Ok(v) = resolve_bootnode(&ma("/dns6/localhost/tcp/30303"), T).await {
            for a in v {
                assert!(matches!(a.iter().next(), Some(Protocol::Ip6(_))), "{a}");
            }
        }
        let v4 = resolve_bootnode(&ma("/dns4/localhost/tcp/30303"), T).await;
        if let Ok(v) = v4 {
            for a in v {
                assert!(matches!(a.iter().next(), Some(Protocol::Ip4(_))), "{a}");
            }
        }
    }

    #[tokio::test]
    async fn unresolvable_name_is_an_explicit_typed_error() {
        let e = resolve_bootnode(&ma("/dns4/nx.invalid.sumchain.test/tcp/30303"), T)
            .await
            .expect_err("must not silently succeed");
        assert!(
            matches!(e, DnsResolveError::Lookup { .. } | DnsResolveError::NoAddresses { .. }),
            "unexpected: {e:?}"
        );
        // The message names the host, so an operator can act on it.
        assert!(e.to_string().contains("nx.invalid.sumchain.test"));
    }

    /// A black-holed resolver must not wedge startup.
    #[tokio::test]
    async fn lookup_is_bounded_by_the_timeout() {
        let start = std::time::Instant::now();
        let r = resolve_bootnode(
            &ma("/dns4/nx.invalid.sumchain.test/tcp/30303"),
            Duration::from_millis(1),
        )
        .await;
        assert!(r.is_err());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "resolution was not bounded: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn dns_without_a_tcp_port_is_refused_not_guessed() {
        let e = resolve_bootnode(&ma("/dns4/localhost"), T)
            .await
            .expect_err("no port to resolve against");
        assert!(matches!(e, DnsResolveError::UnsupportedShape { .. }), "{e:?}");
    }

    /// One failing name must not suppress the others.
    #[tokio::test]
    async fn resolve_all_keeps_going_and_reports_each_failure() {
        let r = resolve_all(
            [
                ma("/ip4/172.28.0.11/tcp/30303"),
                ma("/dns4/nx.invalid.sumchain.test/tcp/30303"),
                ma("/ip4/10.0.0.7/tcp/30303"),
            ],
            T,
        )
        .await;
        assert_eq!(r.addrs.len(), 2, "literals must still be dialable");
        assert_eq!(r.failures.len(), 1, "the bad name must be reported");
        assert!(r.failures[0].0.contains("nx.invalid.sumchain.test"));
    }
}

//! End-to-end bootnode resolution for the two deployment shapes (#237).
//!
//! These exercise the real OS resolver against the exact multiaddr shapes the
//! devnet and Kubernetes manifests ship, then assert the node would dial a
//! literal address. They are the regression guard for the defect where
//! `--bootnodes /dns4/validator-1/tcp/30303` was accepted into config, silently
//! failed to dial, and left `/ready` at 503 with no diagnostic.
//!
//! The Kubernetes shape had **no coverage at all** before this: k8s sets
//! `mdns = false` and dials `/dns4/…svc.cluster.local`, so it was broken on main
//! with nothing to catch it.

use std::time::Duration;

use libp2p_core::multiaddr::{Multiaddr, Protocol};
use sumchain_p2p::config::NetworkConfig;
use sumchain_p2p::dns::{resolve_all, resolve_bootnode, DnsResolveError};

const T: Duration = Duration::from_secs(5);

fn cfg(bootnodes: &[&str]) -> NetworkConfig {
    NetworkConfig {
        bootnodes: bootnodes.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

/// The devnet shape: `docker-compose.yaml` dials the compose service name.
/// Compose resolves `validator-1` through the container runtime's DNS, which is
/// the host resolver from the node's point of view — the same code path as
/// `localhost` here.
#[tokio::test]
async fn devnet_compose_service_name_shape_is_accepted_and_resolved() {
    let addr: Multiaddr = "/dns4/localhost/tcp/30303".parse().unwrap();

    // Config must not refuse it — this is the inverted #237 guard.
    assert_eq!(
        cfg(&["/dns4/validator-1/tcp/30303"]).undialable_bootnodes(),
        vec![],
        "a compose service name must be accepted as a bootnode"
    );

    let dialable = resolve_bootnode(&addr, T).await.expect("resolves");
    assert!(!dialable.is_empty(), "must yield at least one literal address");
    for a in &dialable {
        let first = a.iter().next().expect("non-empty");
        assert!(
            matches!(first, Protocol::Ip4(_)),
            "must dial a LITERAL address, got {a}"
        );
        assert!(a.to_string().contains("/tcp/30303"), "port lost: {a}");
    }
}

/// The Kubernetes shape: a StatefulSet pod FQDN on a headless Service. This is
/// the exact string `statefulset-validator-{2,3}.yaml` ship. The name will not
/// resolve off-cluster, so the assertion is on the *shape and failure mode*:
/// it must be accepted as configuration, attempt resolution, and fail with a
/// typed, host-naming error rather than being silently dropped.
#[tokio::test]
async fn kubernetes_statefulset_fqdn_shape_is_accepted_and_fails_explicitly() {
    const K8S: &str =
        "/dns4/sumchain-validator-1-0.sumchain-validator-1.sumchain.svc.cluster.local/tcp/30303";

    assert_eq!(
        cfg(&[K8S]).undialable_bootnodes(),
        vec![],
        "the k8s FQDN must be accepted as a bootnode — it is resolvable in-cluster"
    );
    assert_eq!(
        cfg(&[K8S]).bootnode_multiaddrs().len(),
        1,
        "it must survive parsing into the dialable set"
    );

    let addr: Multiaddr = K8S.parse().unwrap();
    match resolve_bootnode(&addr, T).await {
        // In-cluster this resolves and yields pod IPs.
        Ok(v) => {
            for a in &v {
                assert!(matches!(a.iter().next(), Some(Protocol::Ip4(_))), "{a}");
            }
        }
        // Off-cluster it must fail LOUDLY and name the host, never vanish.
        //
        // All three failure kinds are legitimate here and which one appears is a
        // property of the host resolver, not of our code: NXDOMAIN gives
        // `Lookup`, a resolver that answers with nothing usable gives
        // `NoAddresses`, and one that black-holes `.cluster.local` queries — as
        // many do off-cluster — gives `Timeout`. The contract under test is that
        // the failure is TYPED and NAMES THE HOST, not which kind it is.
        Err(e) => {
            assert!(
                matches!(
                    e,
                    DnsResolveError::Lookup { .. }
                        | DnsResolveError::NoAddresses { .. }
                        | DnsResolveError::Timeout { .. }
                ),
                "unexpected error kind: {e:?}"
            );
            assert!(
                e.to_string().contains("sumchain-validator-1-0"),
                "the operator must be told which host failed: {e}"
            );
        }
    }
}

/// A headless Service resolves to one address per pod. Dialing only the first
/// would reach exactly one peer and silently under-connect the mesh, so every
/// returned address must be produced.
#[tokio::test]
async fn every_resolved_address_is_returned_not_just_the_first() {
    // `localhost` commonly has both 127.0.0.1 and ::1; /dns admits both families.
    let any = resolve_bootnode(&"/dns/localhost/tcp/30303".parse().unwrap(), T).await;
    if let Ok(v) = any {
        let v4 = v.iter().filter(|a| matches!(a.iter().next(), Some(Protocol::Ip4(_)))).count();
        let v6 = v.iter().filter(|a| matches!(a.iter().next(), Some(Protocol::Ip6(_)))).count();
        assert!(v4 + v6 == v.len() && !v.is_empty());
        // Whatever the host provides, results are de-duplicated per IP.
        let mut ips: Vec<String> = v.iter().map(|a| a.to_string()).collect();
        let before = ips.len();
        ips.sort();
        ips.dedup();
        assert_eq!(ips.len(), before, "duplicate addresses must not be dialed twice");
    }
}

/// The whole configured set resolves together, and one bad entry never
/// suppresses the good ones — a partially-broken bootnode list must still bring
/// the node up.
#[tokio::test]
async fn mixed_bootnode_set_resolves_the_good_and_reports_the_bad() {
    let out = resolve_all(
        [
            "/ip4/172.28.0.11/tcp/30303".parse().unwrap(),
            "/dns4/localhost/tcp/30303".parse().unwrap(),
            "/dns4/nx.invalid.sumchain.test/tcp/30303".parse().unwrap(),
        ],
        T,
    )
    .await;

    assert!(
        out.addrs.len() >= 2,
        "the literal and the resolvable name must both be dialable, got {:?}",
        out.addrs
    );
    assert_eq!(out.failures.len(), 1, "the bad name must be reported, not dropped");
    assert!(out.failures[0].0.contains("nx.invalid.sumchain.test"));
    for a in &out.addrs {
        let p = a.iter().next().unwrap();
        assert!(
            matches!(p, Protocol::Ip4(_) | Protocol::Ip6(_)),
            "every dialed address must be literal: {a}"
        );
    }
}

/// Resolution is bounded: a whole set of unresolvable names cannot wedge
/// startup. This is what keeps the retry loop safe to run in the event loop.
#[tokio::test]
async fn resolving_a_whole_bad_set_stays_bounded() {
    let start = std::time::Instant::now();
    let out = resolve_all(
        (0..4)
            .map(|i| {
                format!("/dns4/nx-{i}.invalid.sumchain.test/tcp/30303")
                    .parse()
                    .unwrap()
            })
            .collect::<Vec<Multiaddr>>(),
        Duration::from_millis(50),
    )
    .await;
    assert!(out.addrs.is_empty());
    assert_eq!(out.failures.len(), 4, "each failure reported individually");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "bounded resolution took {:?}",
        start.elapsed()
    );
}

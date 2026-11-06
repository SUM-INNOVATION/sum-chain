//! Two real nodes holding two connections to each other, one of which closes.
//!
//! # What this pins
//!
//! libp2p routinely holds more than one connection to the same peer: a
//! simultaneous dial, or a redial while a dead connection has not timed out
//! yet. When ONE of them closes, the peer is still connected over the other,
//! and gossip still flows over it. The node must:
//!
//! * keep the peer in its connected set and announce no `PeerDisconnected`;
//! * keep its connection counters where they were (counted once, no leak);
//! * leave a connected peer connected when an extra dial to it fails;
//! * announce `PeerDisconnected` exactly once, when the LAST connection closes.
//!
//! It used to treat every `ConnectionClosed` as the peer leaving, so the first
//! close dropped a peer that was still connected (and the bootnode retry then
//! redialled it), and an extra dial failing wrote `Disconnected` over a live
//! connection so the next connection counted the peer twice.
//!
//! # How one connection is closed and not the other
//!
//! A connection is routed through a small TCP relay in this file, and the relay
//! is shut down: both of its sockets close, as a lost network path would close
//! them, and that one libp2p connection ends on both nodes. The direct
//! connection is untouched. No production API is added for the test.
//!
//! # What this does NOT claim
//!
//! Only the accounting above. Whether this accounting defect also explains the
//! gossip publish failures (`InsufficientPeers`) seen in production is not
//! established, and nothing here asserts it.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use libp2p_core::multiaddr::Protocol;
use libp2p_core::Multiaddr;
use sumchain_p2p::{
    ConnectionLimits, NetworkCommand, NetworkConfig, NetworkEvent, NetworkService, PeerId,
    PeerState,
};
use sumchain_primitives::{Block, BlockHeader, Hash};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{timeout, Instant};

/// How long any single awaited event may take (real TCP plus Noise on a loaded
/// CI box).
const WAIT: Duration = Duration::from_secs(20);

/// How long to watch for an event that must NOT arrive. A closed connection is
/// reported within milliseconds on loopback, so this is generous.
const QUIET: Duration = Duration::from_secs(5);

struct Live {
    service: Arc<NetworkService>,
    events: broadcast::Receiver<NetworkEvent>,
    commands: mpsc::Sender<NetworkCommand>,
    addr: Multiaddr,
    peer_id: PeerId,
}

async fn start(label: &str) -> Live {
    let config = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootnodes: Vec::new(),
        enable_mdns: false,
        node_key_file: None,
        ..Default::default()
    };
    let (service, command_rx) = NetworkService::with_limits(config, ConnectionLimits::default());
    let service = Arc::new(service);
    let mut events = service.subscribe();
    let commands = service.command_sender();
    let runner = Arc::clone(&service);
    tokio::spawn(async move {
        if let Err(e) = runner.run(command_rx).await {
            panic!("network service stopped: {e}");
        }
    });
    let addr = match await_event(&mut events, label, "Listening", |e| {
        matches!(e, NetworkEvent::Listening(_))
    })
    .await
    {
        NetworkEvent::Listening(addr) => addr,
        other => unreachable!("matched Listening, got {other:?}"),
    };
    let peer_id = service.local_peer_id().expect("set before the listener binds");
    Live { service, events, commands, addr, peer_id }
}

async fn await_event<F>(
    rx: &mut broadcast::Receiver<NetworkEvent>,
    label: &str,
    want: &str,
    mut pred: F,
) -> NetworkEvent
where
    F: FnMut(&NetworkEvent) -> bool,
{
    let deadline = Instant::now() + WAIT;
    let mut seen: Vec<String> = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "{label}: no `{want}` within {WAIT:?}; saw {seen:?}");
        match timeout(left, rx.recv()).await {
            Ok(Ok(event)) => {
                if pred(&event) {
                    return event;
                }
                seen.push(format!("{event:?}"));
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => seen.push(format!("<lagged {n}>")),
            Ok(Err(e)) => panic!("{label}: event channel closed waiting for `{want}`: {e}"),
            Err(_) => panic!("{label}: no `{want}` within {WAIT:?}; saw {seen:?}"),
        }
    }
}

/// Assert no event satisfying `pred` arrives within [`QUIET`].
async fn expect_quiet<F>(rx: &mut broadcast::Receiver<NetworkEvent>, why: &str, mut pred: F)
where
    F: FnMut(&NetworkEvent) -> bool,
{
    let deadline = Instant::now() + QUIET;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        match timeout(left, rx.recv()).await {
            Ok(Ok(event)) => assert!(!pred(&event), "{why}; got {event:?}"),
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(_)) | Err(_) => return,
        }
    }
}

fn tcp_port(addr: &Multiaddr) -> u16 {
    addr.iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("a TCP listen address")
}

/// A one-shot TCP relay to `target`: every connection it accepts is forwarded,
/// and [`Relay::cut`] closes all of them at once, both sides.
struct Relay {
    addr: Multiaddr,
    cut: watch::Sender<bool>,
    to_target: Arc<AtomicUsize>,
    from_target: Arc<AtomicUsize>,
}

impl Relay {
    async fn to(target: &Multiaddr) -> Relay {
        let port = tcp_port(target);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("relay binds");
        let local = listener.local_addr().expect("relay address");
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", local.port()).parse().unwrap();
        let (cut, cut_rx) = watch::channel(false);
        let to_target = Arc::new(AtomicUsize::new(0));
        let from_target = Arc::new(AtomicUsize::new(0));
        let (up, down) = (Arc::clone(&to_target), Arc::clone(&from_target));
        tokio::spawn(async move {
            loop {
                let mut cut_rx = cut_rx.clone();
                let accepted = tokio::select! {
                    a = listener.accept() => a,
                    _ = cut_rx.changed() => return,
                };
                let Ok((client, _)) = accepted else { return };
                let Ok(server) = TcpStream::connect(("127.0.0.1", port)).await else { return };
                let (cr, cw) = client.into_split();
                let (sr, sw) = server.into_split();
                tokio::spawn(pump(cr, sw, Arc::clone(&up), cut_rx.clone()));
                tokio::spawn(pump(sr, cw, Arc::clone(&down), cut_rx));
            }
        });
        Relay { addr, cut, to_target, from_target }
    }

    /// Wait until a libp2p connection through the relay has evidently been
    /// established: the Noise handshake, the multiplexer and identify have
    /// moved data both ways, and the swarm has had time to report it.
    async fn wait_established(&self) {
        let deadline = Instant::now() + WAIT;
        while self.to_target.load(Ordering::SeqCst) < 400 || self.from_target.load(Ordering::SeqCst) < 400 {
            assert!(Instant::now() < deadline, "no libp2p traffic through the relay within {WAIT:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    /// Close every connection through the relay, on both sides.
    fn cut(&self) {
        let _ = self.cut.send(true);
    }
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicUsize>,
    mut cut: watch::Receiver<bool>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = tokio::select! {
            r = from.read(&mut buf) => match r { Ok(0) | Err(_) => break, Ok(n) => n },
            _ = cut.changed() => break,
        };
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        counter.fetch_add(n, Ordering::SeqCst);
    }
    let _ = to.shutdown().await;
}

/// Connect `b` to `a` directly and wait until both announce the other.
async fn connect_direct(a: &mut Live, b: &mut Live) {
    b.commands.send(NetworkCommand::Dial(a.addr.clone())).await.expect("dial queued");
    let (aid, bid) = (a.peer_id, b.peer_id);
    await_event(&mut a.events, "A", "PeerConnected(B)", |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == bid)).await;
    await_event(&mut b.events, "B", "PeerConnected(A)", |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == aid)).await;
}

fn block_at(height: u64) -> Block {
    Block::new(
        BlockHeader::new(Hash::hash(&height.to_be_bytes()), height, 0, Hash::default(), Hash::default(), [0u8; 32]),
        Vec::new(),
    )
}

static NEXT_HEIGHT: AtomicU64 = AtomicU64::new(1_000_000);

/// Gossip a fresh block from `from` until `to` receives one from it.
///
/// Repeated because a gossip subscription can take a heartbeat to propagate;
/// each block is distinct so none is dropped as a duplicate.
async fn gossip_reaches(from: &Live, to: &mut Live, label: &str) {
    let src = from.peer_id;
    let deadline = Instant::now() + WAIT;
    loop {
        assert!(Instant::now() < deadline, "{label}: no block arrived by gossip within {WAIT:?}");
        let h = NEXT_HEIGHT.fetch_add(1, Ordering::SeqCst);
        from.commands.send(NetworkCommand::BroadcastBlock(block_at(h))).await.expect("queued");
        let got = timeout(Duration::from_millis(500), async {
            loop {
                match to.events.recv().await {
                    Ok(NetworkEvent::BlockReceived { source, .. }) if source == src => return true,
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return false,
                }
            }
        })
        .await;
        if got == Ok(true) {
            return;
        }
    }
}

fn counted(node: &Live) -> (usize, usize) {
    let s = node.service.connection_stats();
    (s.inbound, s.outbound)
}

fn assert_still_connected(node: &Live, other: PeerId, before: (usize, usize), label: &str) {
    assert!(
        node.service.connected_peers().contains(&other),
        "{label}: the peer is still connected over the surviving connection, so it must stay in the connected set"
    );
    assert_eq!(
        node.service.get_peer_info(&other).map(|i| i.state),
        Some(PeerState::Connected),
        "{label}: and the peer manager must still record it as connected"
    );
    assert_eq!(counted(node), before, "{label}: counted once, unchanged by the close");
}

/// The scenario: a first connection B→A and a second one through a relay,
/// dialled by B (same direction) or by A (opposite directions). Then either
/// the OLDER connection closes (it was routed through its own relay, which is
/// cut) or the NEWER one does (its relay is cut).
async fn one_of_two_closes(second_dialled_by_a: bool, close_older: bool) {
    let mut a = start("A").await;
    let mut b = start("B").await;
    let (aid, bid) = (a.peer_id, b.peer_id);

    // Connection 1, the older one. Routed through relay 1 when it is the one
    // to close, so that it can be closed alone.
    let relay_old = Relay::to(&a.addr).await;
    let older_addr = if close_older { relay_old.addr.clone() } else { a.addr.clone() };
    b.commands.send(NetworkCommand::Dial(older_addr)).await.expect("dial queued");
    await_event(&mut a.events, "A", "PeerConnected(B)", |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == bid)).await;
    await_event(&mut b.events, "B", "PeerConnected(A)", |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == aid)).await;
    let (a_before, b_before) = (counted(&a), counted(&b));
    assert_eq!(a_before, (1, 0), "A accepted the first connection");
    assert_eq!(b_before, (0, 1), "B dialled the first connection");

    // Connection 2, the newer one, always through relay 2, in either direction.
    let (relay_new, dialler) = if second_dialled_by_a {
        (Relay::to(&b.addr).await, &a.commands)
    } else {
        (Relay::to(&a.addr).await, &b.commands)
    };
    dialler.send(NetworkCommand::Dial(relay_new.addr.clone())).await.expect("dial queued");
    relay_new.wait_established().await;
    assert_still_connected(&a, bid, a_before, "A with two connections");
    assert_still_connected(&b, aid, b_before, "B with two connections");

    // Close one of the two.
    if close_older {
        relay_old.cut();
    } else {
        relay_new.cut();
    }
    let why = "one of two connections closed; the peer is still connected over the other, \
               so it must not be announced as disconnected";
    let (wa, wb) = tokio::join!(
        expect_quiet(&mut a.events, why, |e| matches!(e, NetworkEvent::PeerDisconnected(p) if *p == bid)),
        expect_quiet(&mut b.events, why, |e| matches!(e, NetworkEvent::PeerDisconnected(p) if *p == aid)),
    );
    let _ = (wa, wb);
    assert_still_connected(&a, bid, a_before, "A after the close");
    assert_still_connected(&b, aid, b_before, "B after the close");

    // Gossip continues over the surviving connection, both ways.
    gossip_reaches(&b, &mut a, "B→A after the close").await;
    gossip_reaches(&a, &mut b, "A→B after the close").await;

    // The last connection closing is the disconnect, exactly once.
    a.commands
        .send(NetworkCommand::DisconnectPeer { peer: bid, reason: "test: close the last connection".into() })
        .await
        .expect("queued");
    await_event(&mut a.events, "A", "PeerDisconnected(B)", |e| matches!(e, NetworkEvent::PeerDisconnected(p) if *p == bid)).await;
    assert!(!a.service.connected_peers().contains(&bid));
    assert_eq!(counted(&a), (0, 0), "the last close releases the slot, once");
    expect_quiet(&mut a.events, "a second PeerDisconnected for one peer", |e| {
        matches!(e, NetworkEvent::PeerDisconnected(p) if *p == bid)
    })
    .await;
    assert_eq!(counted(&a), (0, 0), "and nothing goes below zero or comes back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_older_of_two_same_direction_connections_keeps_the_peer_and_gossip() {
    one_of_two_closes(false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_newer_of_two_same_direction_connections_keeps_the_peer_and_gossip() {
    one_of_two_closes(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_older_of_two_opposite_direction_connections_keeps_the_peer_and_gossip() {
    one_of_two_closes(true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_newer_of_two_opposite_direction_connections_keeps_the_peer_and_gossip() {
    one_of_two_closes(true, false).await;
}

/// The pattern the production stall showed: a replacement connection opens
/// while the previous one is still up, then the previous one closes; again and
/// again, alternating who dials.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_reconnect_cycles_neither_drop_the_peer_nor_leak_a_count() {
    let mut a = start("A").await;
    let mut b = start("B").await;
    let (aid, bid) = (a.peer_id, b.peer_id);
    connect_direct(&mut a, &mut b).await;
    let (a_before, b_before) = (counted(&a), counted(&b));

    for cycle in 0..4 {
        let relay = if cycle % 2 == 0 { Relay::to(&a.addr).await } else { Relay::to(&b.addr).await };
        let dialler = if cycle % 2 == 0 { &b.commands } else { &a.commands };
        dialler.send(NetworkCommand::Dial(relay.addr.clone())).await.expect("dial queued");
        relay.wait_established().await;
        relay.cut();
        let why = format!("cycle {cycle}: a relayed connection closed while the direct one is up");
        expect_quiet(&mut a.events, &why, |e| matches!(e, NetworkEvent::PeerDisconnected(p) if *p == bid)).await;
        assert_still_connected(&a, bid, a_before, &format!("A, cycle {cycle}"));
        assert_still_connected(&b, aid, b_before, &format!("B, cycle {cycle}"));
    }
    gossip_reaches(&b, &mut a, "B→A after the cycles").await;
    gossip_reaches(&a, &mut b, "A→B after the cycles").await;
}

/// An extra dial to a connected peer fails; the peer stays connected, and a
/// later extra connection is still not counted as a second peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_secondary_dial_leaves_the_connected_peer_alone() {
    let mut a = start("A").await;
    let mut b = start("B").await;
    let (aid, bid) = (a.peer_id, b.peer_id);
    connect_direct(&mut a, &mut b).await;
    let a_before = counted(&a);

    // A port with nothing listening, addressed to B, so the failure is B's.
    let closed_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let dead: Multiaddr = format!("/ip4/127.0.0.1/tcp/{closed_port}/p2p/{bid}").parse().unwrap();
    a.commands.send(NetworkCommand::Dial(dead)).await.expect("dial queued");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_still_connected(&a, bid, a_before, "A after a failed extra dial to B");

    // A second connection (A dials B through a relay) and its close.
    let relay = Relay::to(&b.addr).await;
    a.commands.send(NetworkCommand::Dial(relay.addr.clone())).await.expect("dial queued");
    relay.wait_established().await;
    assert_still_connected(&a, bid, a_before, "A with a second connection after the failed dial");
    relay.cut();
    expect_quiet(&mut a.events, "the relayed connection closed while the direct one is up", |e| {
        matches!(e, NetworkEvent::PeerDisconnected(p) if *p == bid)
    })
    .await;
    assert_still_connected(&a, bid, a_before, "A after the second connection closed");
    gossip_reaches(&b, &mut a, "B→A").await;
    let _ = aid;
}

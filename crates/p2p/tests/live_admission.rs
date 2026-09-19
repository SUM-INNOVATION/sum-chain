//! Two real nodes, one real TCP connection, and the admission gate actually
//! binding.
//!
//! # Why this file can exist now and could not before
//!
//! Every swarm-level claim this crate makes used to be pinned by reading
//! `src/network.rs` as TEXT — `the_disconnect_command_reaches_the_swarm_...` in
//! `protocol_enforcement.rs` still does, for the ordering it asserts. The reason
//! was not squeamishness about integration tests: `SwarmEvent::NewListenAddr`
//! was logged and discarded, so a node's bound address existed only in a log
//! line. A second node could not dial the first without a port fixed in advance,
//! and a fixed port makes a test that fails when two of them run at once.
//!
//! `NetworkEvent::Listening` and `NetworkService::listen_addrs` report the
//! address the OS actually assigned, so `/ip4/127.0.0.1/tcp/0` becomes usable
//! and two nodes can meet inside one process. That is what this file spends.
//!
//! # What it proves that a source scan cannot
//!
//! A scan proves the gate is WRITTEN. It cannot prove the gate is REACHED: that
//! `SwarmEvent::ConnectionEstablished` is the event a redial actually produces,
//! that `Swarm::disconnect_peer_id` really closes the session, that
//! `peer_disconnected` does not clear the ban on the way past, or that a refused
//! peer is never announced upward. Each of those is a property of libp2p's state
//! machine interacting with ours, and each of them has to hold for the ban to
//! refuse anything.
//!
//! # The control
//!
//! Every refusal here is paired with an admission. `a_ban_refuses_the_redial_...`
//! unbans the same peer and watches it reconnect, so a node that had simply
//! stopped accepting connections — or a test whose timeout was doing the work —
//! fails instead of passing.

use std::sync::Arc;
use std::time::Duration;

use libp2p_core::Multiaddr;
use sumchain_p2p::{
    ConnectionLimits, NetworkCommand, NetworkConfig, NetworkEvent, NetworkService, PeerId,
};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{timeout, Instant};

/// How long any single awaited event may take. Generous: these are real TCP
/// handshakes plus a Noise upgrade on a loaded CI box, and a flaky timeout here
/// would be read as a defect in the gate.
const WAIT: Duration = Duration::from_secs(20);

/// How long to watch for an event that must NOT arrive.
///
/// Shorter than [`WAIT`] on purpose, and the reason is stated because it is the
/// weak point of any negative assertion: this bounds how long the refusal is
/// observed for, not how long it holds. The positive control that follows —
/// unban, redial, connect — is what shows the window was long enough for a
/// connection to have happened in.
const QUIET: Duration = Duration::from_secs(5);

/// A running node: the service, its events, its command channel, the address it
/// actually bound, and who it is.
struct Live {
    service: Arc<NetworkService>,
    events: broadcast::Receiver<NetworkEvent>,
    commands: mpsc::Sender<NetworkCommand>,
    addr: Multiaddr,
    peer_id: PeerId,
}

/// Start a node on an OS-assigned loopback port and wait until it is bound.
///
/// `tcp/0` rather than a chosen port: two tests running concurrently must not
/// collide, and nothing here knows which ports are free. That is only usable
/// because the bind is reported — see [`NetworkEvent::Listening`].
async fn start(label: &str) -> Live {
    let config = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootnodes: Vec::new(),
        enable_mdns: false,
        // A fresh random key per node, because `node_key_file` is `None`.
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

    let peer_id = service
        .local_peer_id()
        .expect("`run` sets the local peer id before it binds a listener");

    assert!(
        service.listen_addrs().contains(&addr),
        "{label}: the polled accessor and the broadcast event must report the \
         same bind; `listen_addrs()` is for the caller that arrives after the \
         event has already gone by"
    );

    Live {
        service,
        events,
        commands,
        addr,
        peer_id,
    }
}

/// Wait for the first event satisfying `pred`, or fail with what was seen.
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
        assert!(
            !left.is_zero(),
            "{label}: no `{want}` within {WAIT:?}; saw {seen:?}"
        );
        match timeout(left, rx.recv()).await {
            Ok(Ok(event)) => {
                if pred(&event) {
                    return event;
                }
                seen.push(format!("{event:?}"));
            }
            Ok(Err(broadcast::error::RecvError::Lagged(n))) => {
                seen.push(format!("<lagged {n}>"));
            }
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
            Ok(Err(_)) => return,
            Err(_) => return,
        }
    }
}

/// Keep dialing `addr` for `QUIET`, because one refused dial proves nothing.
///
/// A node that closed the connection could simply have been busy. Dialing
/// repeatedly means the assertion that follows is about a node that had many
/// chances to let the peer in.
async fn dial_repeatedly(commands: &mpsc::Sender<NetworkCommand>, addr: &Multiaddr) {
    let deadline = Instant::now() + QUIET;
    while Instant::now() < deadline {
        commands
            .send(NetworkCommand::Dial(addr.clone()))
            .await
            .expect("the swarm loop is still running");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Two nodes meet over real TCP, and the bind that made it possible is reported.
///
/// The baseline every other test here depends on. If this fails, a refusal
/// asserted below would be indistinguishable from a network that never worked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_find_each_other_on_an_os_assigned_port() {
    let mut a = start("A").await;
    let mut b = start("B").await;

    assert_ne!(a.peer_id, b.peer_id, "two nodes must not share a peer id");
    assert_ne!(
        a.addr, b.addr,
        "`tcp/0` must yield two distinct bound ports, which is the whole reason \
         the bound address is reported rather than assumed"
    );
    assert!(
        a.addr.to_string().contains("/tcp/") && !a.addr.to_string().ends_with("/tcp/0"),
        "the reported address must be the port the OS assigned, not the `/tcp/0` \
         that was configured: got {}",
        a.addr
    );

    b.commands
        .send(NetworkCommand::Dial(a.addr.clone()))
        .await
        .expect("dial queued");

    let bid = b.peer_id;
    let aid = a.peer_id;
    await_event(
        &mut a.events,
        "A",
        "PeerConnected(B)",
        |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == bid),
    )
    .await;
    await_event(
        &mut b.events,
        "B",
        "PeerConnected(A)",
        |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == aid),
    )
    .await;

    assert!(a.service.connected_peers().contains(&bid));
    assert!(b.service.connected_peers().contains(&aid));
    // The direction each side recorded is the direction it really had.
    assert_eq!(
        a.service.connection_stats().inbound,
        1,
        "A accepted the dial, so A counts one INBOUND peer"
    );
    assert_eq!(
        b.service.connection_stats().outbound,
        1,
        "B made the dial, so B counts one OUTBOUND peer"
    );
}

/// A ban hangs up on the live session AND refuses every redial after it.
///
/// This is the property the whole refusal rests on and the one a source scan
/// cannot reach. Three separate things have to hold for it, and each has been
/// individually wrong in this crate:
///
/// 1. `NetworkCommand::DisconnectPeer` reaches `Swarm::disconnect_peer_id` and
///    the session actually ends — before this existed a banned peer kept
///    gossiping for as long as it liked.
/// 2. `peer_disconnected`, which runs on the `ConnectionClosed` the disconnect
///    causes, does not overwrite the ban — it used to write
///    `PeerState::Disconnected` over `PeerState::Banned`.
/// 3. The redial is refused inside `SwarmEvent::ConnectionEstablished`, before
///    the peer is registered or announced — so nothing above this crate ever
///    hears that the banned peer came back.
///
/// The control at the end unbans the same peer and watches it reconnect on the
/// same address, which is what distinguishes "the ban refused it" from "nothing
/// could connect".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ban_closes_the_live_session_and_refuses_every_redial_until_it_is_lifted() {
    let mut a = start("A").await;
    let mut b = start("B").await;
    let (aid, bid) = (a.peer_id, b.peer_id);

    b.commands
        .send(NetworkCommand::Dial(a.addr.clone()))
        .await
        .expect("dial queued");
    await_event(
        &mut a.events,
        "A",
        "PeerConnected(B)",
        |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == bid),
    )
    .await;
    await_event(
        &mut b.events,
        "B",
        "PeerConnected(A)",
        |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == aid),
    )
    .await;

    // (1) The ban ends the session the peer is on RIGHT NOW.
    a.service
        .ban_peer(&bid, Duration::from_secs(24 * 60 * 60))
        .await;
    await_event(
        &mut a.events,
        "A",
        "PeerDisconnected(B)",
        |e| matches!(e, NetworkEvent::PeerDisconnected(p) if *p == bid),
    )
    .await;
    assert!(
        !a.service.connected_peers().contains(&bid),
        "the banned peer must be gone from the connected set, not merely marked"
    );

    // (2) The ban survived the `ConnectionClosed` it caused.
    assert!(
        a.service.peer_manager().is_banned(&bid),
        "hanging up on a banned peer must not clear the ban: closing the \
         connection is the ENFORCEMENT of the ban, not the end of it"
    );

    // (3) And the redial is refused, repeatedly, without ever being announced.
    dial_repeatedly(&b.commands, &a.addr).await;
    expect_quiet(
        &mut a.events,
        "a banned peer's redial must never be announced as \
         a connection: the refusal sits inside `ConnectionEstablished`, before \
         `peer_connected` registers it and before `PeerConnected` tells the node \
         about it",
        |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == bid),
    )
    .await;
    assert!(
        !a.service.connected_peers().contains(&bid),
        "and it is still not in the connected set after all those attempts"
    );
    assert_eq!(
        a.service.connection_stats().inbound,
        0,
        "a refused connection must not move the inbound counter; if it did, a \
         node would refuse every inbound peer forever once enough banned peers \
         had knocked"
    );

    // The control. Same node, same address, same dial — the only thing that
    // changed is the ban.
    a.service.unban_peer(&bid);
    dial_repeatedly(&b.commands, &a.addr).await;
    await_event(
        &mut a.events,
        "A",
        "PeerConnected(B) after unban",
        |e| matches!(e, NetworkEvent::PeerConnected(p) if *p == bid),
    )
    .await;
    assert!(
        a.service.connected_peers().contains(&bid),
        "once the ban is lifted the very same peer connects on the very same \
         address, so the refusal above was the ban and not the harness"
    );
}

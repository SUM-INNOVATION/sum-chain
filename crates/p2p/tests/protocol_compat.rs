//! Machine-enforced activation/protocol compatibility on the wire.
//!
//! # What the network layer actually offers, before any design
//!
//! Established from source, because a mechanism designed against a handshake
//! that does not exist is worse than no mechanism.
//!
//! * There IS a libp2p `identify` behaviour — `crates/p2p/src/behaviour.rs:33`
//!   declares it and `:183` configures it with protocol version
//!   `"/sumchain/1.0.0"`. It is INERT. `NetworkService::handle_swarm_event`
//!   matches `Gossipsub`, `Sync` and the connection arms and ends in `_ => {}`
//!   (`crates/p2p/src/network.rs`), so no `identify` event is ever read.
//!   Worse, `behaviour.rs:184-186` builds its `Config` from a FRESHLY GENERATED
//!   keypair rather than the node's own, so what it would advertise identifies
//!   nothing. Two independent reasons not to build on it.
//! * There is NO custom version or capability exchange, and nothing on the wire
//!   carried an activation height before this change.
//! * What DOES exist is the request-response sync protocol
//!   `"/sumchain/sync/1.0.0"` (`crates/p2p/src/sync.rs:17`), and it is already
//!   used as an application-level handshake: `BlockSyncer::on_peer_connected`
//!   sends `GetStatus` to every new peer, and `on_status_response` ALREADY
//!   refuses a peer whose `chain_id` differs from ours. That is precisely the
//!   enforcement shape wanted, already precedented in this file, so the
//!   activation/protocol digest is carried the same way and refused the same
//!   way.
//!
//! # The backward-compatibility argument, which these tests are mostly about
//!
//! A refusal that fires on today's validators is worse than the defect. So the
//! rule is deliberately asymmetric:
//!
//! | what the peer does | what happens |
//! |---|---|
//! | declares the SAME digest | admitted, verified compatible |
//! | declares a DIFFERENT digest | REFUSED, permanently, and evicted |
//! | declares nothing (predates this change) | admitted, exactly as today |
//!
//! Only the middle row is new behaviour, and a node built before
//! `SyncRequest::GetProtocolId` existed can never reach it: producing a
//! mismatching digest requires decoding the request in the first place. Silence
//! is therefore not evidence, and is deliberately not treated as any.

use sumchain_p2p::sync::{SyncRequest, SyncResponse};
use sumchain_p2p::{BlockSyncer, BlockSyncerConfig, PeerId};
use sumchain_primitives::Hash;
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1337;

fn ours() -> Hash {
    Hash::hash(b"this binary's protocol digest")
}

fn theirs() -> Hash {
    Hash::hash(b"a different binary's protocol digest")
}

fn syncer() -> (BlockSyncer, mpsc::Receiver<sumchain_p2p::NetworkCommand>) {
    let (tx, rx) = mpsc::channel(100);
    (
        BlockSyncer::new(BlockSyncerConfig::default(), CHAIN_ID, ours(), None, 0, tx),
        rx,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire compatibility: the new variants are APPENDED, so nothing already on the
// wire changed meaning.
// ─────────────────────────────────────────────────────────────────────────────

/// Adding the protocol-id exchange did not renumber any existing message.
///
/// bincode encodes an enum variant as its declared index. Inserting a variant
/// rather than appending one would silently reinterpret every `GetBlocks` on the
/// network as something else — a far worse outcome than the defect being closed.
/// These are the byte-level facts that make the change additive.
#[test]
fn the_new_wire_variants_are_appended_and_renumber_nothing() {
    let enc = |v: &SyncRequest| bincode::serialize(v).expect("serialize");

    assert_eq!(enc(&SyncRequest::GetStatus)[..4], [0, 0, 0, 0]);
    assert_eq!(
        enc(&SyncRequest::GetBlocks {
            from_height: 1,
            to_height: 2
        })[..4],
        [1, 0, 0, 0]
    );
    assert_eq!(
        enc(&SyncRequest::GetBlockByHash(Hash::default()))[..4],
        [2, 0, 0, 0]
    );
    // The new one takes the next free index, after every pre-existing variant.
    assert_eq!(enc(&SyncRequest::GetProtocolId)[..4], [3, 0, 0, 0]);

    let enc = |v: &SyncResponse| bincode::serialize(v).expect("serialize");
    assert_eq!(
        enc(&SyncResponse::Status {
            height: 1,
            best_hash: Hash::default(),
            chain_id: CHAIN_ID,
        })[..4],
        [0, 0, 0, 0]
    );
    assert_eq!(enc(&SyncResponse::Blocks(vec![]))[..4], [1, 0, 0, 0]);
    assert_eq!(enc(&SyncResponse::Block(None))[..4], [2, 0, 0, 0]);
    assert_eq!(enc(&SyncResponse::Error(String::new()))[..4], [3, 0, 0, 0]);
    assert_eq!(
        enc(&SyncResponse::ProtocolId {
            digest: Hash::default()
        })[..4],
        [4, 0, 0, 0]
    );
}

/// A peer that predates this change cannot decode the new request.
///
/// This is the mechanism behind the "declares nothing" row of the table: an
/// older binary's decoder knows variants 0..=2 and fails on index 3, producing
/// an inbound failure rather than an answer. It is the reason silence has to
/// mean "unverified" and not "refused".
#[test]
fn a_peer_that_predates_the_change_cannot_decode_the_request() {
    /// `SyncRequest` exactly as it was before `GetProtocolId` was appended.
    #[derive(serde::Deserialize)]
    enum LegacySyncRequest {
        #[allow(dead_code)]
        GetStatus,
        #[allow(dead_code)]
        GetBlocks { from_height: u64, to_height: u64 },
        #[allow(dead_code)]
        GetBlockByHash(Hash),
    }

    // Everything the old peer already understood still round-trips.
    let old_wire = bincode::serialize(&SyncRequest::GetStatus).expect("serialize");
    assert!(
        bincode::deserialize::<LegacySyncRequest>(&old_wire).is_ok(),
        "appending a variant must not disturb the ones a live peer already speaks"
    );

    // The new one does not, which is exactly the "no answer" case.
    let new_wire = bincode::serialize(&SyncRequest::GetProtocolId).expect("serialize");
    assert!(
        bincode::deserialize::<LegacySyncRequest>(&new_wire).is_err(),
        "an older peer must FAIL to decode GetProtocolId rather than decode it \
         as some other request; the refusal policy depends on the difference \
         between 'no answer' and 'a wrong answer'"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The enforcement.
// ─────────────────────────────────────────────────────────────────────────────

/// A peer that declares OUR digest is admitted and can contribute.
#[tokio::test]
async fn a_peer_declaring_our_protocol_digest_is_admitted() {
    let (s, _rx) = syncer();
    let peer = PeerId::random();

    assert!(
        s.on_protocol_id_response(peer, ours()),
        "a peer enforcing our rules is compatible"
    );
    assert!(!s.is_incompatible(&peer));

    s.on_status_response(peer, 100, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.network_height(),
        100,
        "a verified-compatible peer is a usable block source"
    );
    assert_eq!(s.stats().known_peers, 1);
}

/// A peer that declares a DIFFERENT digest is refused, and stays refused.
///
/// This is the control the activation digest never was. Before this change the
/// only pre-flight signal was `Genesis::activation_digest`, logged and compared
/// BY EYE by operators — a process, not a control. Here the node makes the
/// comparison itself, before the peer can contribute a block.
#[tokio::test]
async fn a_peer_declaring_a_different_protocol_digest_is_refused() {
    let (s, _rx) = syncer();
    let peer = PeerId::random();

    assert!(
        !s.on_protocol_id_response(peer, theirs()),
        "a peer enforcing different rules is incompatible"
    );
    assert!(s.is_incompatible(&peer));

    // And nothing it says afterwards is used.
    s.on_status_response(peer, 100, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.network_height(),
        0,
        "a refused peer must not move our view of the network height; if it \
         did, this node would chase a chain it cannot reproduce"
    );
    assert_eq!(s.stats().known_peers, 0);
}

/// The two responses race, and a status that WINS the race is still undone.
///
/// `on_peer_connected` fires both requests and either may answer first. A
/// refusal that only filtered future messages would leave a mismatched peer
/// installed as a block source for as long as it took its digest to arrive.
#[tokio::test]
async fn a_status_that_arrives_before_the_mismatched_digest_is_evicted() {
    let (s, _rx) = syncer();
    let peer = PeerId::random();

    // Status first: at this point the peer looks perfectly good.
    s.on_status_response(peer, 100, Hash::default(), CHAIN_ID);
    assert_eq!(s.network_height(), 100);
    assert_eq!(s.stats().known_peers, 1);

    // Then the digest arrives and disagrees.
    assert!(!s.on_protocol_id_response(peer, theirs()));
    assert_eq!(
        s.stats().known_peers,
        0,
        "the refusal must evict what the peer already told us, not merely \
         filter what it says next"
    );
    assert!(s.is_incompatible(&peer));
}

/// A peer too old to answer is NOT refused.
///
/// The single most important test in this file. Every node on the chain today
/// is in exactly this state, and if this assertion ever flips, the mechanism
/// stops being a safety net and becomes an outage.
#[tokio::test]
async fn a_peer_that_never_declares_a_protocol_digest_is_not_refused() {
    let (s, _rx) = syncer();
    let peer = PeerId::random();

    // No `on_protocol_id_response` call at all — this peer's binary predates
    // `GetProtocolId` and answered the request with an inbound failure.
    assert!(
        !s.is_incompatible(&peer),
        "silence is not a declaration of incompatibility"
    );

    s.on_status_response(peer, 100, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.network_height(),
        100,
        "a node that predates the handshake must remain exactly as usable as it \
         is today; a refusal that fires on the current validator set would be \
         worse than the defect it closes"
    );
    assert_eq!(s.stats().known_peers, 1);
}

/// The pre-existing `chain_id` refusal is untouched.
///
/// The new check is added BEFORE it, and a regression that made the digest check
/// swallow the chain-id one would be invisible in every test above.
#[tokio::test]
async fn the_chain_id_refusal_still_fires_independently() {
    let (s, _rx) = syncer();
    let peer = PeerId::random();

    // Compatible binary, wrong chain.
    assert!(s.on_protocol_id_response(peer, ours()));
    s.on_status_response(peer, 100, Hash::default(), 9999);
    assert_eq!(s.network_height(), 0);
    assert_eq!(s.stats().known_peers, 0);
}

/// Connecting to a peer asks it for its digest.
///
/// Without this the whole mechanism is dead code: nothing else ever sends
/// `GetProtocolId`.
#[tokio::test]
async fn connecting_to_a_peer_asks_for_its_protocol_digest() {
    let (s, mut rx) = syncer();
    let peer = PeerId::random();

    s.on_peer_connected(peer).await;

    let mut asked = false;
    while let Ok(cmd) = rx.try_recv() {
        if matches!(cmd, sumchain_p2p::NetworkCommand::RequestProtocolId(p) if p == peer) {
            asked = true;
        }
    }
    assert!(
        asked,
        "a new peer must be asked which rules it enforces, or the digest never \
         crosses the wire and the refusal can never fire"
    );
}

//! The two-phase policy, and the five-row compatibility matrix it produces.
//!
//! # What `protocol_compat.rs` established, and what it left open
//!
//! That file proved the asymmetric refusal: a peer declaring a DIFFERENT
//! protocol digest is refused, a peer declaring OURS is admitted, a peer
//! declaring NOTHING is admitted exactly as today. The third row is what makes
//! the mechanism deployable onto a live chain — every validator running now is
//! in it.
//!
//! It is also correct only while nothing distinguishes the three. Below the
//! first remediation activation every node executes the same rules, so an
//! undeclared peer's blocks are blocks this node would have produced itself.
//! At that height the rules diverge and the same silence now means "this peer
//! may be enforcing the rules we just stopped enforcing" — at which point an
//! undeclared peer and an incompatible one are the same thing, and admitting
//! one is the defect.
//!
//! So the policy gains a boundary:
//! `ChainParams::peer_protocol_declaration_required_from_height`.
//!
//! | phase | `Verified` | `Undeclared` | `Incompatible` |
//! |---|---|---|---|
//! | below the height, or unset | participates | participates | refused |
//! | at or above the height | participates | REFUSED | refused |
//!
//! # What "participate in consensus" is, from source
//!
//! Production consensus is PoA — `crates/consensus/src/lib.rs:3`, and
//! `crates/consensus/src/bft/mod.rs:3` says the BFT engine is experimental and
//! not production ready. In PoA there are no votes. The single way a peer
//! influences this node is by getting a `Block` into
//! `PoAEngine::do_import_block` (`crates/consensus/src/poa.rs:603`), which is
//! where validity, fork choice (`should_switch`,
//! `crates/consensus/src/engine.rs:113`) and reorg all happen.
//!
//! That engine is handed a `Block` and nothing else — `poa.rs:603` takes no
//! `PeerId` — so the refusal cannot live inside it and lives at the two
//! network boundaries that feed it, both in `crates/node/src/node.rs`: the
//! gossip arm (`NetworkEvent::BlockReceived`) and the sync arm
//! (`NetworkEvent::SyncBlocksReceived`). The syncer's own share of that is what
//! this file exercises directly; `sumchain_p2p::PeerCompatRegistry` is the one
//! predicate both boundaries call.
//!
//! # The rows below
//!
//! "legacy" is a node that declares nothing, because its binary predates
//! `SyncRequest::GetProtocolId` and answers it with an inbound failure.
//! "upgraded" is one that declares. Each row asserts what the odd node CAN do
//! as well as what it cannot — a row that only proved something failed would
//! pass just as well against a node that refused everyone.

use sumchain_p2p::peer_compat::PeerCompat;
use sumchain_p2p::{
    BanOutcome, BlockSyncer, BlockSyncerConfig, ConnectionDirection, ConnectionLimits,
    NetworkConfig, NetworkService, PeerCompatRegistry, PeerId, PeerManager, PeerState,
};
use sumchain_primitives::{Block, BlockHeader, BlockHeight, Hash};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 1337;

/// The height at which the first remediation gate opens in these scenarios, and
/// therefore the height enforcement must have begun by.
const ENFORCE_FROM: BlockHeight = 100;

fn ours() -> Hash {
    Hash::hash(b"this binary's protocol digest")
}

fn theirs() -> Hash {
    Hash::hash(b"a different binary's protocol digest")
}

/// A syncer at `local_height`, enforcing from `enforce_from`.
fn syncer(
    enforce_from: Option<BlockHeight>,
    local_height: BlockHeight,
) -> (BlockSyncer, mpsc::Receiver<sumchain_p2p::NetworkCommand>) {
    let (tx, rx) = mpsc::channel(100);
    (
        BlockSyncer::new(
            BlockSyncerConfig::default(),
            CHAIN_ID,
            ours(),
            enforce_from,
            local_height,
            tx,
        ),
        rx,
    )
}

fn block_at(height: BlockHeight) -> Block {
    Block::new(
        BlockHeader::new(
            Hash::hash(&height.to_be_bytes()),
            height,
            0,
            Hash::default(),
            Hash::default(),
            [0u8; 32],
        ),
        Vec::new(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 1 — legacy + legacy, below the height.
// ─────────────────────────────────────────────────────────────────────────────

/// Two nodes that both predate the handshake are unaffected in every way.
///
/// The node under test here is the UPGRADED one whose genesis has not reached
/// the enforcement height; its peer is legacy. This is the configuration every
/// chain is in on the day the binary ships, and the row that must never fail:
/// the mechanism has to be inert until an operator writes a height down AND the
/// chain reaches it.
#[tokio::test]
async fn row1_legacy_peers_below_the_height_participate_exactly_as_today() {
    let (s, _rx) = syncer(Some(ENFORCE_FROM), 10);
    let peer = PeerId::random();

    // No declaration at all: the peer's binary could not decode GetProtocolId.
    assert_eq!(
        s.compat_status(&peer),
        PeerCompat::Undeclared,
        "silence must be recorded as 'nothing proven', never as a refusal"
    );
    assert!(!s.is_incompatible(&peer));

    // CAN: be a block source.
    s.on_status_response(peer, 50, Hash::default(), CHAIN_ID);
    assert_eq!(s.network_height(), 50);
    assert_eq!(s.stats().known_peers, 1);

    // CAN: have its blocks imported, right up to the boundary.
    let imported = s.on_blocks_received(peer, vec![block_at(11), block_at(99)]);
    assert_eq!(
        imported.iter().map(|b| b.height()).collect::<Vec<_>>(),
        vec![11, 99],
        "below the enforcement height an undeclared peer's blocks are blocks \
         this node would itself have produced; refusing them would be the \
         outage the whole design exists to avoid"
    );
}

/// Unset is a distinct configuration from "set high", and it is the default.
///
/// `None` is what every `genesis.json` already distributed resolves to via
/// `#[serde(default)]`. It must mean phase one at EVERY height, not phase one
/// up to some implied bound.
#[tokio::test]
async fn row1_an_unset_enforcement_height_never_refuses_an_undeclared_peer() {
    let (s, _rx) = syncer(None, 10);
    let peer = PeerId::random();

    assert_eq!(s.enforcement_height(), None);
    assert!(!s.enforcing_at(0));
    assert!(!s.enforcing_at(u64::MAX));

    s.on_status_response(peer, 1_000_000, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.network_height(),
        1_000_000,
        "a node whose genesis predates this field must behave as it does today \
         at every height, not merely at low ones"
    );
    let imported = s.on_blocks_received(peer, vec![block_at(999_999)]);
    assert_eq!(imported.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 2 — legacy + upgraded, below the height.
// ─────────────────────────────────────────────────────────────────────────────

/// An upgraded node below the height treats its legacy peer as fully usable,
/// while still refusing a peer that declares a MISMATCH.
///
/// Both halves matter. The first is backward compatibility; the second is that
/// phase one is not "no enforcement at all" — the original refusal is untouched
/// and fires at every height.
#[tokio::test]
async fn row2_below_the_height_silence_is_admitted_and_a_mismatch_is_still_refused() {
    let (s, _rx) = syncer(Some(ENFORCE_FROM), 10);
    let legacy = PeerId::random();
    let mismatched = PeerId::random();

    s.on_status_response(legacy, 50, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.stats().known_peers,
        1,
        "the legacy peer is a usable source"
    );

    assert!(!s.on_protocol_id_response(mismatched, theirs()));
    s.on_status_response(mismatched, 60, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.stats().known_peers,
        1,
        "being below the enforcement height does not soften the refusal of a \
         peer that SAID it enforces other rules; the two phases differ only in \
         how silence is read"
    );
    assert_eq!(s.network_height(), 50);
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 3 — legacy + upgraded, AT OR ABOVE the height.
// ─────────────────────────────────────────────────────────────────────────────

/// At the height, the legacy peer stops being able to influence consensus — and
/// is still not called incompatible.
///
/// The distinction is the point. "Refused because it declared other rules" and
/// "refused because the rules have diverged and it has declared nothing" are
/// different facts about the peer, and only the first is an accusation.
#[tokio::test]
async fn row3_at_the_height_an_undeclared_peer_cannot_supply_blocks() {
    // Local height one below the boundary: the next block this node wants is
    // exactly `ENFORCE_FROM`.
    let (s, _rx) = syncer(Some(ENFORCE_FROM), ENFORCE_FROM - 1);
    let legacy = PeerId::random();

    assert!(s.enforcing_at(ENFORCE_FROM));
    assert!(!s.enforcing_at(ENFORCE_FROM - 1));

    // CANNOT: be admitted as a block source.
    s.on_status_response(legacy, ENFORCE_FROM + 500, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.network_height(),
        ENFORCE_FROM - 1,
        "an undeclared peer must not move this node's view of the network \
         height above the boundary; if it did, the node would chase a chain it \
         cannot show it agrees with"
    );
    assert_eq!(s.stats().known_peers, 0);

    // ...and is STILL not incompatible: it has not said anything.
    assert_eq!(s.compat_status(&legacy), PeerCompat::Undeclared);
    assert!(
        !s.is_incompatible(&legacy),
        "refusing a peer for silence must not be recorded as the peer having \
         declared a conflict; an operator reading the two apart is how a \
         misconfigured enforcement height gets diagnosed"
    );
}

/// The boundary is applied PER BLOCK, so a batch that straddles it splits.
///
/// This is the row a whole-batch check would get wrong in the dangerous
/// direction: the peer was entitled to supply the blocks below the height, and
/// refusing those would stall a sync that should have succeeded — while the
/// blocks at or above it are exactly the ones it may not supply.
#[tokio::test]
async fn row3_a_batch_straddling_the_height_is_split_not_refused_whole() {
    let (s, _rx) = syncer(Some(ENFORCE_FROM), ENFORCE_FROM - 3);
    let legacy = PeerId::random();

    let imported = s.on_blocks_received(
        legacy,
        vec![
            block_at(ENFORCE_FROM - 2),
            block_at(ENFORCE_FROM - 1),
            block_at(ENFORCE_FROM),
            block_at(ENFORCE_FROM + 1),
        ],
    );

    assert_eq!(
        imported.iter().map(|b| b.height()).collect::<Vec<_>>(),
        vec![ENFORCE_FROM - 2, ENFORCE_FROM - 1],
        "the blocks below the boundary are ones this peer was entitled to \
         supply and must still import; the blocks at and above it are not"
    );
}

/// A legacy peer admitted below the boundary stops being SELECTED once the node
/// crosses it.
///
/// Admission and selection are separate moments and nothing re-runs at the
/// crossing, so a check made only at admission would leave a peer installed as
/// the chosen sync source across the very height it stops being allowed to be
/// one.
#[tokio::test]
async fn row3_a_peer_admitted_below_the_height_is_dropped_on_crossing_it() {
    let (s, _rx) = syncer(Some(ENFORCE_FROM), 10);
    let legacy = PeerId::random();

    s.on_status_response(legacy, 5_000, Hash::default(), CHAIN_ID);
    assert_eq!(s.stats().known_peers, 1, "admitted below the boundary");
    assert!(
        s.may_supply_blocks(&legacy, 99),
        "and usable for the blocks below it"
    );

    // The node advances across the boundary.
    s.set_local_height(ENFORCE_FROM);
    assert!(
        !s.may_supply_blocks(&legacy, ENFORCE_FROM + 1),
        "once the chain has crossed the height, the peer that was admitted \
         under the old phase must not still be a legal source"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Rows 4 and 5 — upgraded + upgraded.
// ─────────────────────────────────────────────────────────────────────────────

/// A peer declaring OUR digest participates in BOTH phases.
///
/// The enforcement height must not cost anything to a peer that has done the
/// thing the height exists to require.
#[tokio::test]
async fn row4_a_matching_peer_participates_on_both_sides_of_the_height() {
    let (s, _rx) = syncer(Some(ENFORCE_FROM), ENFORCE_FROM + 50);
    let peer = PeerId::random();

    assert!(s.on_protocol_id_response(peer, ours()));
    assert_eq!(s.compat_status(&peer), PeerCompat::Verified);

    assert!(s.may_supply_blocks(&peer, 0));
    assert!(s.may_supply_blocks(&peer, ENFORCE_FROM));
    assert!(s.may_supply_blocks(&peer, u64::MAX));

    s.on_status_response(peer, ENFORCE_FROM + 500, Hash::default(), CHAIN_ID);
    assert_eq!(s.network_height(), ENFORCE_FROM + 500);
    assert_eq!(s.stats().known_peers, 1);

    let imported = s.on_blocks_received(peer, vec![block_at(ENFORCE_FROM + 100)]);
    assert_eq!(
        imported.len(),
        1,
        "a verified peer supplies blocks above the height"
    );
}

/// A peer declaring a DIFFERENT digest participates in NEITHER phase.
///
/// Refused below the height as well as above it: the mismatch refusal predates
/// the two-phase policy and is not gated by it.
#[tokio::test]
async fn row5_a_mismatched_peer_participates_in_neither_phase() {
    let (s, _rx) = syncer(Some(ENFORCE_FROM), 10);
    let peer = PeerId::random();

    assert!(!s.on_protocol_id_response(peer, theirs()));
    assert_eq!(s.compat_status(&peer), PeerCompat::Incompatible);
    assert!(s.is_incompatible(&peer));

    assert!(!s.may_supply_blocks(&peer, 0));
    assert!(!s.may_supply_blocks(&peer, ENFORCE_FROM - 1));
    assert!(!s.may_supply_blocks(&peer, ENFORCE_FROM));

    s.on_status_response(peer, 5_000, Hash::default(), CHAIN_ID);
    assert_eq!(
        s.network_height(),
        10,
        "the refused peer must not move this node's view of the network height \
         off its own local height"
    );
    assert_eq!(s.stats().known_peers, 0);

    let imported = s.on_blocks_received(peer, vec![block_at(11)]);
    assert!(
        imported.is_empty(),
        "a peer that declared different rules supplies nothing at any height"
    );
}

/// Incompatibility is permanent: a second, matching declaration does not undo it.
///
/// The first answer was an admission that the peer's binary enforces other
/// rules. A different second answer is at best a different binary and at worst
/// a peer probing for admission.
#[tokio::test]
async fn row5_a_mismatched_peer_cannot_declare_its_way_back_in() {
    let (s, _rx) = syncer(Some(ENFORCE_FROM), 10);
    let peer = PeerId::random();

    assert!(!s.on_protocol_id_response(peer, theirs()));
    assert!(
        !s.on_protocol_id_response(peer, ours()),
        "a peer that already declared a conflict must not be readmitted by \
         declaring the right answer afterwards"
    );
    assert_eq!(s.compat_status(&peer), PeerCompat::Incompatible);
    assert!(!s.may_supply_blocks(&peer, 0));
}

// ─────────────────────────────────────────────────────────────────────────────
// The predicate itself.
// ─────────────────────────────────────────────────────────────────────────────

/// The full truth table of `may_participate_in_consensus`, stated once.
///
/// Every boundary in the node and the syncer calls this one predicate, so this
/// is the table the whole mechanism reduces to.
#[test]
fn the_participation_predicate_is_the_whole_policy() {
    let verified = PeerId::random();
    let incompatible = PeerId::random();
    let undeclared = PeerId::random();

    for (enforce_from, height, undeclared_may) in [
        // Phase one: unset means never enforce, at any height.
        (None, 0u64, true),
        (None, u64::MAX, true),
        // Phase one: below the height.
        (Some(100), 0, true),
        (Some(100), 99, true),
        // Phase two: at the height and above. `>=`, because the height names
        // the first block the remediated rules may apply to.
        (Some(100), 100, false),
        (Some(100), 101, false),
        // A height of zero is enforcement from genesis, not "no enforcement".
        (Some(0), 0, false),
    ] {
        let r = PeerCompatRegistry::new(ours(), enforce_from);
        assert!(r.on_declaration(verified, ours()));
        assert!(!r.on_declaration(incompatible, theirs()));

        assert!(
            r.may_participate_in_consensus(&verified, height),
            "a peer that declared our digest participates at every height \
             ({enforce_from:?} / {height})"
        );
        assert!(
            !r.may_participate_in_consensus(&incompatible, height),
            "a peer that declared a different digest participates at no height \
             ({enforce_from:?} / {height})"
        );
        assert_eq!(
            r.may_participate_in_consensus(&undeclared, height),
            undeclared_may,
            "undeclared peer, enforce_from={enforce_from:?}, height={height}"
        );
    }
}

/// The wire is untouched by the two-phase policy.
///
/// The enforcement height is a `ChainParams` field and a local Rust predicate.
/// `SyncRequest` / `SyncResponse` — the only types that cross the network —
/// gained nothing, so a peer speaking the pre-enforcement protocol speaks the
/// identical bytes. This restates
/// `protocol_compat.rs::the_new_wire_variants_are_appended_and_renumber_nothing`
/// from the far side of this change, because that test would keep passing if
/// this change had added a sixth response variant that an older peer could not
/// decode.
#[test]
fn the_two_phase_policy_added_nothing_to_the_wire() {
    use sumchain_p2p::sync::{SyncRequest, SyncResponse};

    let enc_req = |v: &SyncRequest| bincode::serialize(v).expect("serialize");
    assert_eq!(enc_req(&SyncRequest::GetStatus)[..4], [0, 0, 0, 0]);
    assert_eq!(enc_req(&SyncRequest::GetProtocolId)[..4], [3, 0, 0, 0]);

    let enc_res = |v: &SyncResponse| bincode::serialize(v).expect("serialize");
    assert_eq!(
        enc_res(&SyncResponse::ProtocolId {
            digest: Hash::default()
        })[..4],
        [4, 0, 0, 0],
        "ProtocolId must still be the LAST variant; a new one appended after it \
         would be fine, but one inserted before it would renumber a message \
         live peers already speak"
    );

    // And a peer that speaks only the four pre-digest responses still decodes
    // every one of them unchanged.
    #[derive(serde::Deserialize)]
    enum PreDigestSyncResponse {
        #[allow(dead_code)]
        Status {
            height: BlockHeight,
            best_hash: Hash,
            chain_id: u64,
        },
        #[allow(dead_code)]
        Blocks(Vec<Block>),
        #[allow(dead_code)]
        Block(Option<Block>),
        #[allow(dead_code)]
        Error(String),
    }
    let status = enc_res(&SyncResponse::Status {
        height: 7,
        best_hash: Hash::default(),
        chain_id: CHAIN_ID,
    });
    assert!(
        bincode::deserialize::<PreDigestSyncResponse>(&status).is_ok(),
        "the enforcement height must not have disturbed a message today's \
         validators exchange"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Row 5, continued — what the refusal actually COSTS the peer.
//
// The rows above prove a mismatching peer cannot supply blocks. That is the
// safety property, and it is not the whole claim `node.rs` makes: it says the
// peer is evicted and banned, and those are three different mechanisms living in
// three different places. A refusal proved by the predicate alone would leave
// the other two unexamined, which is how a comment comes to describe something
// the code does not do.
// ─────────────────────────────────────────────────────────────────────────────

/// A mismatching declaration evicts what the peer already told us AND the work
/// already in flight to it.
///
/// `protocol_compat.rs` proves the first half against `known_peers`. The second
/// half is the one a refusal is easy to write without: a block request already
/// sent to this peer, whose response will arrive AFTER the refusal, still has a
/// `PendingRequest` holding its range in `in_flight_ranges`. Left there, the
/// range is one the syncer believes is being fetched and will not re-request
/// from anyone else — a refused peer silently stalling the sync it was ejected
/// from.
#[tokio::test]
async fn row5_a_mismatched_peer_is_evicted_along_with_the_requests_in_flight_to_it() {
    let (s, mut rx) = syncer(Some(ENFORCE_FROM), 10);
    let peer = PeerId::random();

    // It connects and reports a chain well ahead of ours, so the syncer starts
    // fetching from it. Nothing here has asked about its digest yet, which is
    // the race the eviction exists for: the status beat the declaration.
    s.on_peer_connected(peer).await;
    s.on_status_response(peer, 500, Hash::default(), CHAIN_ID);
    s.tick().await;
    assert_eq!(
        s.stats().known_peers,
        1,
        "the peer is a sync source before it declares anything"
    );
    assert_eq!(
        s.stats().pending_requests,
        1,
        "the syncer must actually have a request in flight to this peer, or the \
         eviction below is evicting nothing and this test proves nothing"
    );

    // Now the declaration lands, and it is a mismatch.
    assert!(!s.on_protocol_id_response(peer, theirs()));

    assert!(s.is_incompatible(&peer));
    assert_eq!(
        s.stats().known_peers,
        0,
        "the refusal must evict what the peer already told us"
    );
    assert_eq!(
        s.stats().pending_requests,
        0,
        "the refusal must also drop the request already in flight to it; a \
         pending request holds its height range as in-flight, so leaving it \
         there means the syncer waits on a peer it has just ejected"
    );

    // And the refusal is total, at every height, in both phases.
    for h in [0, ENFORCE_FROM - 1, ENFORCE_FROM, 10_000] {
        assert!(
            !s.may_supply_blocks(&peer, h),
            "a mismatching peer must be refused at height {h}"
        );
    }
    drop(rx.try_recv());
}

/// A ban binds on a peer this node has never seen, and says which it did.
///
/// `PeerManager::ban_peer` used to be `if let Some(entry) = peers.get_mut(..)`:
/// on a peer with no entry it wrote nothing and returned `()`, which at the call
/// site is indistinguishable from a ban that took. The one production caller was
/// safe only because `SwarmEvent::ConnectionEstablished` calls `peer_connected`
/// first and a `ProtocolIdResponse` cannot arrive before a connection — a
/// property of the network stack, not a guarantee the function offered.
///
/// It now registers the peer to hold the ban and reports which case it was. Both
/// halves are asserted: the stranger is refused, and `BanOutcome` still tells a
/// caller that it banned someone it had never met.
#[test]
fn a_ban_binds_on_a_peer_this_node_has_never_seen() {
    let pm = PeerManager::new(ConnectionLimits::default());
    let stranger = PeerId::random();

    assert!(
        pm.can_accept_inbound(&stranger, None),
        "before the ban the stranger is welcome, which is what makes the refusal \
         below attributable to the ban"
    );

    assert_eq!(
        pm.ban_peer(&stranger, std::time::Duration::from_secs(24 * 60 * 60)),
        BanOutcome::Registered,
        "a ban on an unregistered peer must report that it had to create the \
         entry, not pretend the peer was already known"
    );

    assert!(
        pm.is_banned(&stranger),
        "the ban on an unregistered peer must BIND: a refusal that evaporates \
         because the peer has not dialled yet is worse than no refusal, because \
         the caller believes it fired"
    );
    assert!(
        !pm.peer_is_admissible(&stranger),
        "this node must not hold a connection with a peer it has banned, in \
         EITHER direction, seen before or not. `peer_is_admissible` is the \
         predicate the outbound half of the `ConnectionEstablished` gate \
         actually calls, so asserting on it asserts on the live rule rather \
         than on a dial-time composition nothing reaches"
    );
    assert!(
        !pm.can_accept_inbound(&stranger, None),
        "and must not accept its connection either"
    );
    assert_eq!(pm.stats().banned, 1);
    assert_eq!(
        pm.get_peer_info(&stranger)
            .expect("the ban created an entry")
            .state,
        PeerState::Banned
    );

    // The production ordering — connected first, then banned — is unchanged and
    // reports the other outcome. The control is `can_accept_inbound`, which is
    // `true` for a connected peer until the ban lands and `false` after, so the
    // change is attributable to the ban and to nothing else.
    let peer = PeerId::random();
    pm.peer_connected(peer, ConnectionDirection::Inbound, None);
    assert!(pm.can_accept_inbound(&peer, None));
    assert_eq!(
        pm.ban_peer(&peer, std::time::Duration::from_secs(24 * 60 * 60)),
        BanOutcome::Existing,
        "the peer already had an entry, and the caller can still tell"
    );

    let info = pm.get_peer_info(&peer).expect("the peer has an entry");
    assert_eq!(
        info.state,
        PeerState::Banned,
        "a peer whose binary declared other consensus rules must be left in \
         `Banned`, not merely scored down"
    );
    assert!(info.ban_expires.is_some());
    assert_eq!(pm.stats().banned, 2);
    assert!(!pm.peer_is_admissible(&peer));
    assert!(!pm.can_accept_inbound(&peer, None));
}

/// Banning a mismatched peer now CLOSES the session it is already on.
///
/// This crate had no outbound disconnect at all — `NetworkCommand` carried none,
/// and the only `Disconnect` in it was the inbound `PeerDisconnected` event. A
/// ban therefore refused the peer's NEXT connection and left the current one
/// open, so a mismatching peer kept gossiping at this node for as long as it
/// liked; the only thing standing between it and the engine was the permanence
/// of `PeerCompat::Incompatible`.
///
/// `NetworkService::ban_peer` now does both: it writes the ban AND sends
/// `NetworkCommand::DisconnectPeer`, which the swarm loop turns into
/// `Swarm::disconnect_peer_id`. Both halves are asserted here together, plus the
/// permanence that used to be carrying the whole load on its own — because the
/// danger was believing any one of the three covered the others.
#[tokio::test]
async fn banning_a_mismatched_peer_closes_the_connection_it_already_has() {
    let (network, mut commands) =
        NetworkService::with_limits(NetworkConfig::default(), ConnectionLimits::default());
    let peer = PeerId::random();
    network
        .peer_manager()
        .peer_connected(peer, ConnectionDirection::Inbound, None);
    assert_eq!(network.peer_manager().stats().inbound, 1);
    assert!(
        commands.try_recv().is_err(),
        "connecting a peer must not by itself queue any command"
    );

    let outcome = network
        .ban_peer(&peer, std::time::Duration::from_secs(24 * 60 * 60))
        .await;
    assert_eq!(outcome, BanOutcome::Existing);

    match commands.try_recv() {
        Ok(sumchain_p2p::NetworkCommand::DisconnectPeer { peer: p, reason }) => {
            assert_eq!(p, peer, "the disconnect must name the peer that was banned");
            assert!(
                reason.contains("banned"),
                "the reason travels to the swarm so the connection's death is \
                 attributable there: got {reason:?}"
            );
        }
        other => panic!(
            "banning a peer must queue a disconnect for the session it is ALREADY \
             on; got {other:?}"
        ),
    }

    assert!(network.peer_manager().is_banned(&peer));

    // And the third refusal, which is the one that used to be alone: every route
    // into consensus consults the registry, permanently and at every height.
    let reg = PeerCompatRegistry::new(ours(), Some(ENFORCE_FROM));
    assert!(!reg.on_declaration(peer, theirs()));
    assert_eq!(reg.status(&peer), PeerCompat::Incompatible);
    for h in [0, 1, ENFORCE_FROM - 1, ENFORCE_FROM, u64::MAX] {
        assert!(
            !reg.may_participate_in_consensus(&peer, h),
            "the mismatching peer must be refused at height {h}"
        );
    }
    // Including after it tries to take the declaration back.
    assert!(!reg.on_declaration(peer, ours()));
    assert!(!reg.may_participate_in_consensus(&peer, 0));
}

/// The ban survives the disconnect it caused, so the peer's redial is refused.
///
/// The failure mode this pins is a loop: hang up on the banned peer, the
/// `ConnectionClosed` that follows runs `peer_disconnected`, which used to
/// overwrite `PeerState::Banned` with `PeerState::Disconnected` — and then the
/// peer dials back into a node that reads its own state and sees an ordinary
/// idle peer. `ban_until` survived that overwrite, which is why `is_banned` was
/// still right; `state` was the half that lied, and `state` is what `PeerInfo`
/// hands to everything above this crate.
#[test]
fn a_banned_peer_stays_banned_through_the_disconnect_and_its_redial_is_refused() {
    let pm = PeerManager::new(ConnectionLimits::default());
    let peer = PeerId::random();

    pm.peer_connected(peer, ConnectionDirection::Inbound, None);
    pm.ban_peer(&peer, std::time::Duration::from_secs(24 * 60 * 60));

    // What `SwarmEvent::ConnectionClosed` does after `disconnect_peer_id` runs.
    pm.peer_disconnected(&peer);
    assert_eq!(
        pm.stats().inbound,
        0,
        "closing the connection releases the inbound slot"
    );

    let info = pm
        .get_peer_info(&peer)
        .expect("entry survives the disconnect");
    assert_eq!(
        info.state,
        PeerState::Banned,
        "the peer is disconnected BECAUSE it is banned; reading back as merely \
         `Disconnected` is how the refusal gets forgotten"
    );
    assert!(info.ban_expires.is_some());
    assert!(pm.is_banned(&peer));
    assert_eq!(pm.stats().banned, 1);

    // The redial, from both directions.
    assert!(
        !pm.can_accept_inbound(&peer, None),
        "the banned peer's reconnection must be refused — this is what makes the \
         refusal survive the peer dialling back"
    );
    assert!(
        !pm.peer_is_admissible(&peer),
        "and the outbound half of the gate must refuse it too — that half is \
         `peer_is_admissible`, and it is the one the swarm loop calls"
    );
}

/// The syncer hangs up too, and not only on the peers it was about to ask.
///
/// `on_protocol_id_response` already evicted a mismatching peer from the set it
/// would REQUEST blocks from, and from the requests in flight to it. Neither
/// touches the connection: the peer could still push gossip and answer requests
/// already outstanding. The eviction and the disconnect are asserted in one
/// place because the eviction reads like the whole refusal and is not.
#[tokio::test]
async fn the_syncer_hangs_up_on_a_peer_that_declares_other_rules() {
    let (s, mut rx) = syncer(Some(ENFORCE_FROM), 0);
    let peer = PeerId::random();

    s.on_status_response(peer, 500, Hash::default(), CHAIN_ID);
    assert_eq!(s.stats().known_peers, 1, "admitted before it declares");

    assert!(!s.on_protocol_id_response(peer, theirs()));

    assert_eq!(
        s.stats().known_peers,
        0,
        "the mismatching peer is evicted from the sync peer set"
    );
    let mut disconnects = Vec::new();
    while let Ok(cmd) = rx.try_recv() {
        if let sumchain_p2p::NetworkCommand::DisconnectPeer { peer: p, reason } = cmd {
            disconnects.push((p, reason));
        }
    }
    assert_eq!(
        disconnects.len(),
        1,
        "refusing a peer must queue exactly one disconnect, got {disconnects:?}"
    );
    assert_eq!(disconnects[0].0, peer);
    assert!(
        disconnects[0].1.contains("protocol digest"),
        "the reason must name what the peer did: {:?}",
        disconnects[0].1
    );
}

/// An undeclared peer is refused above the height and is NOT hung up on, in
/// either phase.
///
/// The distinction `PeerCompat` draws between `Incompatible` and `Undeclared`
/// exists so that a refusal can tell an accusation from an absence, and the
/// disconnect is where that distinction has to pay: every validator running
/// today is `Undeclared`, because its binary predates `GetProtocolId` and
/// answers with an inbound failure. A disconnect that fired on silence would
/// hang up on the entire current validator set the moment the enforcement
/// height arrived.
///
/// So: below the height the legacy peer participates and keeps its connection;
/// at and above it the peer's BLOCKS are refused and the connection still
/// stands, because the peer may simply be old rather than wrong.
#[tokio::test]
async fn an_undeclared_peer_is_refused_above_the_height_but_never_disconnected() {
    // Phase one: below the height.
    let (below, mut rx_below) = syncer(Some(ENFORCE_FROM), ENFORCE_FROM - 2);
    let legacy = PeerId::random();
    below.on_status_response(legacy, ENFORCE_FROM - 1, Hash::default(), CHAIN_ID);
    assert!(
        below.may_supply_blocks(&legacy, ENFORCE_FROM - 1),
        "below the height an undeclared peer participates exactly as today"
    );
    assert_eq!(below.stats().known_peers, 1);

    // Phase two: at and above it.
    let (above, mut rx_above) = syncer(Some(ENFORCE_FROM), ENFORCE_FROM);
    above.on_status_response(legacy, ENFORCE_FROM + 50, Hash::default(), CHAIN_ID);
    for h in [ENFORCE_FROM, ENFORCE_FROM + 1, u64::MAX] {
        assert!(
            !above.may_supply_blocks(&legacy, h),
            "at or above the height an undeclared peer may not supply block {h}"
        );
    }
    assert_eq!(
        above.compat_status(&legacy),
        PeerCompat::Undeclared,
        "silence is not an accusation, in either phase"
    );

    // Neither phase hangs up on it.
    for (label, rx) in [("below", &mut rx_below), ("above", &mut rx_above)] {
        while let Ok(cmd) = rx.try_recv() {
            assert!(
                !matches!(cmd, sumchain_p2p::NetworkCommand::DisconnectPeer { .. }),
                "{label} the enforcement height, a peer that merely declared \
                 NOTHING must not be disconnected: that is every validator \
                 running today, and hanging up on them is worse than the defect \
                 the handshake closes. Got {cmd:?}"
            );
        }
    }

    // And the peer manager agrees: nothing banned it.
    let pm = PeerManager::new(ConnectionLimits::default());
    pm.peer_connected(legacy, ConnectionDirection::Inbound, None);
    assert!(!pm.is_banned(&legacy));
    assert!(pm.can_accept_inbound(&legacy, None));
}

/// A peer that declares OUR digest is untouched by any of this.
///
/// The control for every assertion above. A refusal mechanism that also refused
/// the compatible peers would pass most of this file.
#[tokio::test]
async fn a_matching_peer_is_neither_banned_nor_disconnected() {
    let (s, mut rx) = syncer(Some(ENFORCE_FROM), ENFORCE_FROM);
    let peer = PeerId::random();

    assert!(s.on_protocol_id_response(peer, ours()));
    assert_eq!(s.compat_status(&peer), PeerCompat::Verified);
    s.on_status_response(peer, ENFORCE_FROM + 100, Hash::default(), CHAIN_ID);
    assert_eq!(s.stats().known_peers, 1, "it stays a source of blocks");
    for h in [0, ENFORCE_FROM - 1, ENFORCE_FROM, u64::MAX] {
        assert!(s.may_supply_blocks(&peer, h), "admitted at height {h}");
    }

    while let Ok(cmd) = rx.try_recv() {
        assert!(
            !matches!(cmd, sumchain_p2p::NetworkCommand::DisconnectPeer { .. }),
            "a peer that declared OUR digest must never be hung up on; got {cmd:?}"
        );
    }

    let (network, mut commands) =
        NetworkService::with_limits(NetworkConfig::default(), ConnectionLimits::default());
    network
        .peer_manager()
        .peer_connected(peer, ConnectionDirection::Inbound, None);
    assert!(!network.peer_manager().is_banned(&peer));
    assert!(network.peer_manager().can_accept_inbound(&peer, None));
    assert!(
        commands.try_recv().is_err(),
        "and nothing is queued against it"
    );
}

/// A restart forgets every declaration, and the forgetting fails CLOSED above
/// the enforcement height and open below it.
///
/// `PeerCompatRegistry` is a `RwLock<HashMap<..>>` and nothing persists it. That
/// is stated rather than fixed, because the two sides of the boundary fail in
/// opposite directions and only one of them is a defect:
///
/// * **Above the height.** A restart re-refuses a peer it had VERIFIED, until
///   the peer answers `GetProtocolId` again. A verified peer is temporarily
///   treated as undeclared — refusal, which is the safe direction.
/// * **Below the height.** The same window re-admits a peer it had marked
///   `Incompatible`. That is the real cost, and it is bounded by exactly what
///   phase one already means: below the height every node executes the same
///   rules, so an undeclared peer's blocks are blocks this node would have
///   produced itself.
///
/// The ban is forgotten too, and for the same reason — `PeerManager` is in
/// memory.
///
/// # ACCEPTED for this release, not outstanding
///
/// The below-the-height half is an ACCEPTED property of this release and not a
/// residual awaiting work: pre-enforcement compatibility state may reset on
/// restart, and post-enforcement behaviour must remain fail-closed. Persisting
/// the declarations is therefore not a prerequisite of shipping, and this test
/// is not a placeholder for it.
///
/// What is NOT accepted, and what this test exists to hold, is the other half.
/// If a future change makes the registry survive a restart, or seeds it, or
/// widens the below-the-height admission upward, the assertions over
/// `[ENFORCE_FROM, ENFORCE_FROM + 1, u64::MAX]` must keep refusing a peer that
/// has not re-declared. The accepted reset buys nothing above the height and
/// must never be allowed to leak there.
///
/// Operator-facing statement of the same two halves:
/// `docs/operations/p2p-admission-and-compatibility.md`.
#[test]
fn a_restart_forgets_declarations_and_the_window_fails_closed_above_the_height() {
    let peer = PeerId::random();

    let before = PeerCompatRegistry::new(ours(), Some(ENFORCE_FROM));
    assert!(before.on_declaration(peer, ours()));
    assert_eq!(before.status(&peer), PeerCompat::Verified);
    let other = PeerId::random();
    assert!(!before.on_declaration(other, theirs()));
    assert_eq!(before.status(&other), PeerCompat::Incompatible);

    // The restart: a brand-new registry, which is what the process gets.
    let after = PeerCompatRegistry::new(ours(), Some(ENFORCE_FROM));
    assert_eq!(
        after.status(&peer),
        PeerCompat::Undeclared,
        "a restart forgets that the peer was verified"
    );
    assert_eq!(
        after.status(&other),
        PeerCompat::Undeclared,
        "and forgets that the other one was refused"
    );

    // Above the height the window refuses BOTH — including the peer it had
    // verified. That is the direction this must keep failing in.
    for h in [ENFORCE_FROM, ENFORCE_FROM + 1, u64::MAX] {
        assert!(
            !after.may_participate_in_consensus(&peer, h),
            "above the height a re-forgotten peer is refused until it declares \
             again (height {h})"
        );
        assert!(!after.may_participate_in_consensus(&other, h));
    }

    // Re-answering is what ends the window, and only a matching answer does.
    assert!(after.on_declaration(peer, ours()));
    assert!(after.may_participate_in_consensus(&peer, ENFORCE_FROM));
    assert!(!after.on_declaration(other, theirs()));
    assert!(!after.may_participate_in_consensus(&other, ENFORCE_FROM));
    assert!(
        !after.may_participate_in_consensus(&other, 0),
        "and once it re-declares a mismatch it is refused in phase one too"
    );

    // Below the height the window ADMITS the previously-refused peer. Stated,
    // not hidden: this is the cost of holding the policy in memory.
    let fresh = PeerCompatRegistry::new(ours(), Some(ENFORCE_FROM));
    assert!(
        fresh.may_participate_in_consensus(&other, ENFORCE_FROM - 1),
        "below the height a forgotten refusal re-admits the peer, which is the \
         same admission phase one already makes for every silent peer"
    );
}

/// The two swarm-level halves of the disconnect, pinned at their source.
///
/// # What this still owns, now that `live_admission.rs` exists
///
/// The BEHAVIOUR — a banned peer being hung up on and refused when it dials
/// back — is now asserted against two real nodes over real TCP in
/// `crates/p2p/tests/live_admission.rs`, which became possible only once
/// `SwarmEvent::NewListenAddr` stopped being discarded. Read that first: it is
/// the stronger test, because it proves the gate is REACHED and not merely
/// written.
///
/// What a live test cannot see is ORDER inside the arm. A gate that ran after
/// `peer_connected` would still hang up, still keep the peer out of the
/// connected set in the end, and still pass every assertion over there — while
/// having already announced `PeerConnected` to everything above and already
/// moved the inbound counter. That window is invisible from outside and visible
/// in the source, so it is asserted here.
///
/// # And that the gate is the PREDICATE, not a second copy of it
///
/// This arm used to call `self.peer_manager.is_banned(&peer_id)` — a narrower
/// check written beside `can_accept_inbound`, which had no caller anywhere. Two
/// predicates, one of them dead, is how a refusal comes to be believed rather
/// than enforced: the connection limits and the reputation floor described a
/// policy nothing applied. The needles below are the real predicates, so
/// re-splitting them fails here.
#[test]
fn the_disconnect_command_reaches_the_swarm_and_the_admission_gate_precedes_registration() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/network.rs"),
    )
    .expect("crates/p2p/src/network.rs is readable");

    let arm = src
        .find("Some(NetworkCommand::DisconnectPeer {")
        .expect("the command loop must handle DisconnectPeer");
    let arm_body = &src[arm..arm + 800];
    assert!(
        arm_body.contains("swarm.disconnect_peer_id(peer)"),
        "the DisconnectPeer arm must actually close the connection through the \
         swarm, not merely log about it"
    );

    let established = src
        .find("SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {")
        .expect("the swarm handler must have a ConnectionEstablished arm");
    let body = &src[established..];
    let register = body
        .find("self.peer_manager.peer_connected(peer_id")
        .expect("the arm registers the peer");

    // Both halves of the admission policy, each before registration. The
    // inbound half is the full predicate including capacity; the outbound half
    // is the peer-facing part only, because refusing a connection this node
    // asked for on an inbound or per-IP limit would be refusing its own dial.
    for needle in [
        "self.peer_manager.can_accept_inbound(&peer_id, None)",
        "self.peer_manager.peer_is_admissible(&peer_id)",
    ] {
        let gate = body.find(needle).unwrap_or_else(|| {
            panic!(
                "the connection handler must consult `{needle}`. A ban, a \
                 reputation floor and a connection limit that nothing in this \
                 loop reads refuse nothing at all — which is what this arm did \
                 when it carried its own narrower `is_banned` check instead"
            )
        });
        assert!(
            gate < register,
            "`{needle}` is consulted AFTER `peer_connected` registers the peer. \
             A refusal in that order has already announced `PeerConnected` to \
             everything above and already moved the inbound counter, and no test \
             outside this process can see that it did"
        );
    }

    let hangup = body
        .find("swarm.disconnect_peer_id(peer_id)")
        .expect("the gate must hang up on a refused connection");
    assert!(
        hangup < register,
        "the refusal must close the connection, not just skip registration and \
         leave the refused peer connected and gossiping"
    );
}

/// `can_connect_outbound` does not become `pub` again without a caller.
///
/// # The rule this enforces, and why it is worth a test
///
/// `PeerManager::can_connect_outbound` was `pub` and had no production caller
/// anywhere. That is not an unused helper; from outside the crate it reads as
/// an enforced outbound admission rule, and it enforced nothing — exactly the
/// shape `can_accept_inbound` was in before the `ConnectionEstablished` arm was
/// made to call it, and exactly the shape that lets a refusal be believed
/// rather than enforced. It is now private, and its two in-file unit tests are
/// the only things that reach it.
///
/// The condition is deliberately NOT "it must stay private forever". A real
/// dial-by-`PeerId` site is a legitimate change, and on the day one exists this
/// predicate is the right thing for it to call. What must not happen is the
/// `pub` coming back WITHOUT the caller, which is the state this repository was
/// already in once. So: public is allowed only in the same change that
/// introduces a production call site.
///
/// The scan drops `//` lines, so the prose in `network.rs` and `peer_manager.rs`
/// that names this predicate while explaining why nothing calls it is not
/// mistaken for a call.
#[test]
fn the_dead_outbound_dial_predicate_is_not_public_without_a_caller() {
    const NAME: &str = "can_connect_outbound";

    let p2p_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let workspace_crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/p2p has a parent");

    let manager_path = p2p_src.join("peer_manager.rs");
    let manager = std::fs::read_to_string(&manager_path).expect("peer_manager.rs is readable");
    let decl = manager
        .find(&format!("fn {NAME}("))
        .unwrap_or_else(|| panic!("`{NAME}` must still be declared in peer_manager.rs"));
    let line_start = manager[..decl].rfind('\n').map_or(0, |i| i + 1);
    let declared_pub = manager[line_start..decl].contains("pub ");

    // Every non-comment mention outside the declaring file. A `mod tests` in
    // peer_manager.rs itself is not a production caller and is not counted; the
    // point of the rule is what a caller OUTSIDE the file can rely on.
    let mut callers: Vec<String> = Vec::new();
    let mut stack = vec![workspace_crates.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") || path == manager_path {
                continue;
            }
            // Only production source, never tests: a test calling a private
            // item cannot compile anyway, and a test calling a public one is
            // not the caller this rule is about.
            if !path.components().any(|c| c.as_os_str() == "src") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let code: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            if code.contains(&format!("{NAME}(")) {
                callers.push(path.to_string_lossy().into_owned());
            }
        }
    }

    assert!(
        !(declared_pub && callers.is_empty()),
        "`PeerManager::{NAME}` is `pub` again and still has no production \
         caller anywhere under crates/*/src. A public predicate that nothing \
         consults is not policy — it reads as an enforced outbound admission \
         rule from outside this crate and enforces nothing, which is the exact \
         state this repository was already in. Either give it a caller in the \
         same change (a real dial-by-`PeerId` site, which this crate does not \
         have: `dial_bootnodes` and `NetworkCommand::Dial` both take a \
         `Multiaddr`), or leave it private."
    );

    // And the state this tree is actually in, so the assertion above cannot be
    // satisfied vacuously by the declaration being renamed out from under it.
    assert!(
        !declared_pub,
        "`{NAME}` is expected to be private in this tree; if a dialer has been \
         added, update this assertion in the same change that adds it, and say \
         which call site now reaches it. Found callers: {callers:?}"
    );
    assert!(
        manager[line_start.saturating_sub(64)..decl].contains("#[cfg(test)]"),
        "`{NAME}` is expected to be `#[cfg(test)]`-gated as well as private, \
         so that it is compiled out of every release binary rather than \
         shipping as an uncalled admission rule. Removing the gate is how it \
         becomes live-looking again."
    );
}

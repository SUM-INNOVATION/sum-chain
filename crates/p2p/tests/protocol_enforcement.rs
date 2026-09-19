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
    BlockSyncer, BlockSyncerConfig, ConnectionDirection, ConnectionLimits, PeerCompatRegistry,
    PeerId, PeerManager, PeerState,
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

/// The ban `node.rs` applies binds only because the connection registered the
/// peer first — and that precondition is worth an assertion, not a comment.
///
/// `PeerManager::ban_peer` (`crates/p2p/src/peer_manager.rs:531`) is
/// `if let Some(entry) = peers.get_mut(peer_id)`. On a peer with no entry it
/// writes nothing and returns `()`, indistinguishable at the call site from a
/// ban that took. The production call is safe because
/// `SwarmEvent::ConnectionEstablished` (`crates/p2p/src/network.rs:763`) calls
/// `peer_connected`, which inserts the entry, and a `ProtocolIdResponse` can
/// only arrive on an established connection. That ordering is the whole
/// argument, so the no-op is pinned here: if `ban_peer` is ever called on a peer
/// this node has not connected to — from a config file, an RPC, a gossip
/// report — it will do nothing and say nothing.
#[test]
fn the_ban_on_a_mismatched_peer_binds_only_because_the_connection_registered_it_first() {
    let pm = PeerManager::new(ConnectionLimits::default());
    let stranger = PeerId::random();

    // The no-op. Banning a peer with no entry.
    pm.ban_peer(&stranger, std::time::Duration::from_secs(24 * 60 * 60));
    assert!(
        pm.get_peer_info(&stranger).is_none(),
        "banning an unknown peer must not even create an entry for it"
    );
    assert!(
        pm.can_connect_outbound(&stranger),
        "the ban on an unregistered peer is a NO-OP: nothing was written, so \
         nothing refuses it. Any call site that bans a peer it has not connected \
         to is writing a refusal that does not exist"
    );
    assert_eq!(pm.stats().banned, 0);

    // The production ordering: connected first, then banned. The control is
    // `can_accept_inbound` and not `can_connect_outbound`, because the latter is
    // already `false` for a CONNECTED peer —
    // `PeerEntry::should_attempt_connection` (`peer_manager.rs:217`) refuses any
    // state but `Disconnected` — so it could not tell a ban from a live session.
    let peer = PeerId::random();
    pm.peer_connected(peer, ConnectionDirection::Inbound, None);
    assert!(
        pm.can_accept_inbound(&peer, None),
        "before the ban this peer is welcome, which is what makes the refusal \
         below attributable to the ban"
    );
    pm.ban_peer(&peer, std::time::Duration::from_secs(24 * 60 * 60));

    let info = pm.get_peer_info(&peer).expect("the peer has an entry");
    assert_eq!(
        info.state,
        PeerState::Banned,
        "a peer whose binary declared other consensus rules must be left in \
         `Banned`, not merely scored down"
    );
    assert!(info.ban_expires.is_some());
    assert_eq!(pm.stats().banned, 1);
    assert!(
        !pm.can_connect_outbound(&peer),
        "this node must not dial a peer it has refused"
    );
    assert!(
        !pm.can_accept_inbound(&peer, None),
        "and must not accept its redial either — that is what makes the refusal \
         survive the peer reconnecting, which is the claim `node.rs` makes for it"
    );
}

/// Banning the peer does NOT hang up on it, and what holds meanwhile is the
/// permanence of `Incompatible`.
///
/// There is no disconnect anywhere in this crate's command surface —
/// `NetworkCommand` has no such variant — so `network.ban_peer(&peer, 24h)`
/// refuses the NEXT connection and leaves the current one open. A mismatching
/// peer therefore keeps gossiping at this node for as long as it likes.
///
/// That is safe, and it is safe for a different reason than the ban: every route
/// into consensus consults the registry, and `PeerCompat::Incompatible` is
/// permanent. Both halves are asserted together here because the danger is
/// believing the first one covers the second.
#[test]
fn banning_a_mismatched_peer_does_not_close_the_connection_it_already_has() {
    let pm = PeerManager::new(ConnectionLimits::default());
    let peer = PeerId::random();
    pm.peer_connected(peer, ConnectionDirection::Inbound, None);
    assert_eq!(pm.stats().inbound, 1);

    pm.ban_peer(&peer, std::time::Duration::from_secs(24 * 60 * 60));
    assert_eq!(
        pm.stats().inbound,
        1,
        "the ban did not decrement the inbound count, because it did not close \
         the connection: only `peer_disconnected` does that, and nothing calls it \
         here. The live session survives the ban"
    );

    // So what refuses the blocks still arriving on that live session is the
    // registry, permanently and at every height.
    let reg = PeerCompatRegistry::new(ours(), Some(ENFORCE_FROM));
    assert!(!reg.on_declaration(peer, theirs()));
    assert_eq!(reg.status(&peer), PeerCompat::Incompatible);
    for h in [0, 1, ENFORCE_FROM - 1, ENFORCE_FROM, u64::MAX] {
        assert!(
            !reg.may_participate_in_consensus(&peer, h),
            "the still-connected mismatching peer must be refused at height {h}"
        );
    }
    // Including after it tries to take the declaration back.
    assert!(!reg.on_declaration(peer, ours()));
    assert!(!reg.may_participate_in_consensus(&peer, 0));
}

//! Every route from a peer into consensus passes the participation check, and
//! passes it BEFORE the engine sees the message.
//!
//! # What the consensus path actually is, from source
//!
//! Established by reading, because a gate placed on the wrong path is worse
//! than none — it reports coverage it does not have.
//!
//! * Production consensus is PoA. `crates/consensus/src/lib.rs:3` says so, and
//!   `crates/consensus/src/bft/mod.rs:3` says the BFT engine is
//!   "EXPERIMENTAL - NOT PRODUCTION READY" with `propose_block()` returning
//!   `NotImplemented`.
//! * **Proposal acceptance, fork choice and reorg are one function**:
//!   `PoAEngine::do_import_block`, `crates/consensus/src/poa.rs:603`. It
//!   validates the block, classifies it against
//!   `LongestChainForkChoice::should_switch`
//!   (`crates/consensus/src/engine.rs:113`) into `DirectExtension`,
//!   `SideBranch` or `Reorg`, and publishes or reorgs. A block that reaches it
//!   has already influenced this node.
//! * **There are no PoA votes.** `crates/consensus/src/engine.rs:28` — the
//!   `ConsensusEngine` trait — has `import_block` and `propose_block` and no
//!   vote method at all. Votes exist only in the experimental BFT engine
//!   (`crates/consensus/src/bft/vote.rs`).
//! * **The engine cannot make this decision itself.** `import_block(&self,
//!   block: Block)` (`crates/consensus/src/engine.rs:50`) is handed a block and
//!   nothing else; there is no `PeerId` anywhere in the trait. So the refusal
//!   has to sit at the network boundary, which is `Node::run`'s event loop in
//!   `crates/node/src/node.rs`.
//!
//! # The hole this closes
//!
//! Blocks arrive by TWO routes and only one of them was attributed.
//! `NetworkEvent::SyncBlocksReceived` carries a `PeerId`; `BlockReceived` —
//! gossip — did not, even though `NetworkService::handle_gossip_message` has
//! the propagating peer in hand and used it for rate limiting before discarding
//! it. Refusing a peer on the sync path while its gossip went straight into
//! `do_import_block` was a control over the slower of the two routes.
//!
//! # Why this is a source scan
//!
//! The decision itself is `PeerCompatRegistry::may_participate_in_consensus`,
//! whose truth table is exercised directly in
//! `crates/p2p/tests/protocol_enforcement.rs`. What cannot be reached from a
//! unit test is the WIRING: `Node::run` is one large `async fn` with no seam,
//! and a version of it that simply never called the predicate would pass every
//! behavioural test in the workspace — the same hazard, and the same answer, as
//! `crates/state/tests/remediation_gates.rs`.
//!
//! ORDER is asserted as well as presence. A check that ran after
//! `import_block` would be a check on a block that had already been published.

use std::fs;
use std::path::Path;

/// `(event arm, the call that hands the message to consensus)`.
///
/// Each entry is one route from a peer into the engine. A sixth route added to
/// the event loop and not added here would be a hole this file does not see —
/// which is why the count below is pinned too.
const ROUTES: &[(&str, &str)] = &[
    // Gossip. The route that was unattributed.
    ("NetworkEvent::BlockReceived", "consensus.import_block("),
    // Sync. Attributed before this change, gated only on "declared a DIFFERENT
    // digest" rather than on the two-phase policy.
    (
        "NetworkEvent::SyncBlocksReceived",
        "consensus.import_block(",
    ),
    // The experimental BFT engine's proposal and its two votes. Not the
    // production path, but gated on the same predicate at the same boundary so
    // that enabling the engine does not quietly reopen the hole.
    ("NetworkEvent::BftProposalReceived", "handle_proposal("),
    ("NetworkEvent::BftPrevoteReceived", "handle_prevote("),
    ("NetworkEvent::BftPrecommitReceived", "handle_precommit("),
];

const CHECK: &str = "may_participate_in_consensus";

fn node_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/node.rs");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The body of one `NetworkEvent::X` match arm, up to the next arm.
fn arm_body<'a>(src: &'a str, arm: &str) -> &'a str {
    let at = src
        .find(arm)
        .unwrap_or_else(|| panic!("no `{arm}` arm in the node event loop"));
    let rest = &src[at + arm.len()..];
    let end = rest.find("NetworkEvent::").unwrap_or(rest.len());
    &rest[..end]
}

/// Every route into consensus checks participation, and checks it first.
#[test]
fn every_route_into_consensus_checks_participation_before_the_engine_sees_it() {
    let src = node_source();

    for (arm, call) in ROUTES {
        let body = arm_body(&src, arm);

        let check_at = body.find(CHECK).unwrap_or_else(|| {
            panic!(
                "the `{arm}` arm does not call `{CHECK}`. That route hands a peer's \
                 message straight to consensus: for a block it reaches \
                 `PoAEngine::do_import_block`, which is validity, fork choice and \
                 reorg in one function, so a peer this node cannot show it agrees \
                 with would be proposing blocks and moving the head"
            )
        });
        let call_at = body.find(call).unwrap_or_else(|| {
            panic!(
                "the `{arm}` arm no longer calls `{call}`; this guard is pinned to a \
                 shape that has changed, and must be re-derived rather than deleted"
            )
        });

        assert!(
            check_at < call_at,
            "the `{arm}` arm calls `{CHECK}` at byte {check_at}, AFTER `{call}` at \
             byte {call_at}. A check that runs after the engine has the message is \
             a check on a block that has already been executed, classified and \
             possibly published"
        );
    }
}

/// The gossip route carries the peer it arrived from.
///
/// The gate above is unenforceable without this. `NetworkEvent::BlockReceived`
/// was a bare `Block` and the propagating peer was dropped in
/// `NetworkService::handle_gossip_message`, so there was no peer to judge —
/// which is exactly how a mechanism can look complete and cover one of two
/// routes.
#[test]
fn the_gossip_routes_carry_the_peer_the_message_came_from() {
    let src = node_source();
    for (arm, _) in ROUTES {
        let head_at = src.find(arm).unwrap_or_else(|| panic!("no `{arm}` arm"));
        // The arm head runs to its `=>`.
        let head = &src[head_at..];
        let head = &head[..head.find("=>").expect("arm head ends in =>")];
        assert!(
            head.contains("source") || head.contains("peer"),
            "the `{arm}` arm binds no peer: `{head}`. Without one there is nothing \
             for the participation check to judge, and the refusal is unenforceable \
             on this route however carefully it is written"
        );
    }
}

/// Five routes, and this list is the claim about how many there are.
///
/// A new `NetworkEvent` that reaches consensus and is not listed here is a hole
/// this file cannot see. The count is asserted so that adding one is a decision
/// rather than an omission.
#[test]
fn the_routes_into_consensus_are_the_five_listed() {
    assert_eq!(ROUTES.len(), 5);

    let src = node_source();
    // Every `import_block` call in the event loop belongs to a listed route.
    // `PoAEngine` is reached only through the two of them.
    let imports = src.matches("consensus.import_block(").count();
    assert_eq!(
        imports, 2,
        "the node calls `consensus.import_block` {imports} times; the gossip and \
         sync routes account for two, so a third is an unguarded route into \
         proposal acceptance and fork choice"
    );
}

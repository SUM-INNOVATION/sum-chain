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
//!
//! # Every route into `do_import_block`, enumerated from source
//!
//! ```text
//! do_import_block            crates/consensus/src/poa.rs:603   (private)
//!   <- PoAEngine::import_block            crates/consensus/src/poa.rs:1080
//!        the ONLY caller; it is the `ConsensusEngine` trait impl
//!      <- ConsensusWrapper::import_block  crates/node/src/consensus_wrapper.rs:195
//!           <- Node::admit_peer_block     crates/node/src/node.rs   (the seam)
//!                <- NetworkEvent::BlockReceived        (gossip)
//!                <- NetworkEvent::SyncBlocksReceived   (sync)
//!      <- Arc<dyn ConsensusEngine> handed to the RPC server
//!           ConsensusWrapper::as_consensus_engine, consensus_wrapper.rs:265
//!           -> Node::start_servers, node.rs; RpcServer, crates/rpc/src/server.rs:186
//!           NOT CALLED TODAY. Asserted below, because it is callable.
//! ```
//!
//! The last edge is the one worth writing down. `as_consensus_engine` hands the
//! RPC server the SAME `Arc<PoAEngine>` the event loop holds, upcast to
//! `Arc<dyn ConsensusEngine>` — and `import_block` is a method on that trait
//! (`crates/consensus/src/engine.rs:50`). The RPC server therefore holds a live,
//! callable handle into proposal acceptance and fork choice, reachable from an
//! unauthenticated JSON-RPC method, with no `PeerId` anywhere near it and so
//! nothing for the participation predicate to judge. No RPC method calls it
//! today. Nothing in the type system stops the next one, and it would not be a
//! sixth route through the boundary — it would be a route AROUND it. It is
//! pinned by `the_rpc_surface_never_reaches_into_the_consensus_engine` below.
//!
//! Block PRODUCTION is deliberately not on this list: `PoAEngine::create_block`
//! (`crates/consensus/src/poa.rs`) commits through `accept_produced` and never
//! calls `do_import_block`, and its input is this node's own mempool rather than
//! a peer. A peer reaching the mempool is a separate surface with a separate
//! gate, and its blocks still arrive by one of the two routes above.

use std::fs;
use std::path::Path;

/// `(event arm, the call that hands the message to consensus)`.
///
/// Each entry is one route from a peer into the engine. A sixth route added to
/// the event loop and not added here would be a hole this file does not see —
/// which is why the count below is pinned too.
const ROUTES: &[(&str, &str)] = &[
    // Gossip. The route that was unattributed.
    ("NetworkEvent::BlockReceived", SEAM),
    // Sync. Attributed before this change, gated only on "declared a DIFFERENT
    // digest" rather than on the two-phase policy.
    ("NetworkEvent::SyncBlocksReceived", SEAM),
    // The experimental BFT engine's proposal and its two votes. Not the
    // production path, but gated on the same predicate at the same boundary so
    // that enabling the engine does not quietly reopen the hole.
    ("NetworkEvent::BftProposalReceived", "handle_proposal("),
    ("NetworkEvent::BftPrevoteReceived", "handle_prevote("),
    ("NetworkEvent::BftPrecommitReceived", "handle_precommit("),
];

const CHECK: &str = "may_participate_in_consensus";

/// The one function that decides AND imports.
///
/// The two block routes no longer write the check themselves — writing it twice
/// is what made it possible to write it once. They call this, and this is the
/// only thing in `crates/node/src` that calls `consensus.import_block`, so the
/// scan below is "there is one door and it is locked" rather than "both doors
/// were locked when I last looked".
const SEAM: &str = "Self::admit_peer_block(";

/// The engine call the seam owns.
const IMPORT: &str = "consensus.import_block(";

/// `node.rs` with every whole-line comment removed.
///
/// Every scan in this file runs against this rather than the raw text, and it
/// is not a nicety: the doc comment on `admit_peer_block` names
/// `NetworkEvent::BlockReceived` and quotes `consensus.import_block(`, exactly
/// as it should, and a scan that counted those would be counting prose. A guard
/// that can be satisfied — or broken — by a comment is not reading the code.
///
/// Whole-line comments only. A trailing `// ...` after code is left in place,
/// which is safe in the one direction that matters: it can only ever make the
/// scans see more than the compiler does, never less.
fn node_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/node.rs");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let code: Vec<&str> = raw
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    assert!(
        code.len() < raw.lines().count(),
        "no comment lines were stripped from node.rs, which means this helper \
         stopped working rather than that the file stopped having comments"
    );
    code.join("\n")
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

        // The two block routes delegate the whole decision to the seam, which
        // is checked as a unit by the test below. What is asserted HERE is the
        // stronger property: the arm reaches the engine only through the seam
        // and never calls `import_block` itself.
        if *call == SEAM {
            assert!(
                body.contains(SEAM),
                "the `{arm}` arm does not call `{SEAM}`. It carries a peer's \
                 block to `PoAEngine::do_import_block` — validity, fork choice \
                 and reorg in one function — so it must go through the seam that \
                 refuses a peer this node cannot show it agrees with"
            );
            assert!(
                !body.contains(IMPORT),
                "the `{arm}` arm calls `{IMPORT}` directly, going around \
                 `{SEAM}`. That is the defect this shape exists to prevent: a \
                 route into consensus whose check is optional because it is \
                 written separately from the call it guards"
            );
            continue;
        }

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
    // ONE call into the engine in the whole file, and it is inside the seam.
    // Before the seam existed this count was two — one per block route — and
    // each had to be separately proved to be preceded by the check. One call
    // site cannot be preceded by the check on some paths and not others.
    let imports = src.matches(IMPORT).count();
    assert_eq!(
        imports, 1,
        "the node calls `{IMPORT}` {imports} times; exactly one is expected, \
         inside `admit_peer_block`. A second call site is a route into proposal \
         acceptance and fork choice whose participation check is written \
         somewhere else and can therefore be forgotten"
    );
}

/// The seam itself: the predicate runs, and runs before the engine is called.
///
/// This is the assertion the two block routes delegate to it. The function is
/// short enough to read in full, which is the point — the previous shape spread
/// the same claim over two ~30-line match arms 130 lines apart.
#[test]
fn the_admission_seam_checks_participation_before_it_calls_the_engine() {
    let src = node_source();

    let at = src.find("pub(crate) async fn admit_peer_block(").expect(
        "`Node::admit_peer_block` is gone; this guard is pinned to a shape \
                 that has changed and must be re-derived rather than deleted",
    );
    let body = &src[at..];
    // To the next item at `impl` indentation. Comments are already stripped, so
    // the next `\n    pub ` is the next function and not a doc line.
    let end = body[1..]
        .find("\n    pub ")
        .map(|i| i + 1)
        .unwrap_or(body.len());
    let body = &body[..end];

    let check_at = body.find(CHECK).unwrap_or_else(|| {
        panic!(
            "`admit_peer_block` does not call `{CHECK}`, so every route through \
                it is unguarded at once"
        )
    });
    let call_at = body.find(IMPORT).unwrap_or_else(|| {
        panic!(
            "`admit_peer_block` does not call `{IMPORT}`; the seam no longer \
                owns the engine call and the one-call-site guarantee is void"
        )
    });
    assert!(
        check_at < call_at,
        "`admit_peer_block` calls `{CHECK}` at byte {check_at}, AFTER `{IMPORT}` \
         at byte {call_at}. A check that runs after the engine has the block is a \
         check on a block that has already been validated, classified against \
         fork choice and possibly published"
    );
    assert!(
        body[..call_at].contains("return PeerBlockOutcome::Refused"),
        "`admit_peer_block` computes the predicate and does not RETURN on a \
         refusal before reaching `{IMPORT}`; a check whose result is not acted \
         on is worse than no check, because it reads as coverage"
    );
}

/// The RPC surface never reaches into the consensus engine.
///
/// `ConsensusWrapper::as_consensus_engine`
/// (`crates/node/src/consensus_wrapper.rs:265`) hands `RpcServer` the same
/// `Arc<PoAEngine>` the event loop holds, as `Arc<dyn ConsensusEngine>`. That
/// trait carries `import_block` and `propose_block`
/// (`crates/consensus/src/engine.rs:50`), so the RPC server can call
/// `do_import_block` — with no `PeerId`, from an HTTP request, past every check
/// in this file. It does not today. This test is what keeps that true, because
/// the type system does not: the handle is given out precisely so the RPC can
/// read heights and finality, and `.import_block(` is one line away from every
/// place that reads them.
///
/// Scanned as text for the same reason the rest of this file is: the hazard is a
/// call that does not exist yet, and no behavioural test can fail on code nobody
/// has written.
#[test]
fn the_rpc_surface_never_reaches_into_the_consensus_engine() {
    let rpc_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rpc/src");
    let mut scanned = 0usize;
    for entry in
        fs::read_dir(&rpc_src).unwrap_or_else(|e| panic!("reading {}: {e}", rpc_src.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        scanned += 1;
        for forbidden in [".import_block(", ".propose_block("] {
            assert!(
                !text.contains(forbidden),
                "{} calls `{forbidden}` on the consensus engine. The RPC server \
                 holds the engine as `Arc<dyn ConsensusEngine>` for its read-only \
                 methods; calling `{forbidden}` from there feeds consensus from an \
                 HTTP request with no peer identity attached, which is not a sixth \
                 route through the participation boundary but a route around it",
                path.display()
            );
        }
    }
    assert!(
        scanned >= 10,
        "only {scanned} files scanned under {}; the RPC crate was reorganised and \
         this guard is now looking at almost nothing",
        rpc_src.display()
    );
}

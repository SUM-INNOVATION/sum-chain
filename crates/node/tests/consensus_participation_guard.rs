//! Every route from a peer into consensus passes the participation check, and
//! passes it BEFORE the engine sees the message.
//!
//! # What changed here, and why it had to
//!
//! This file used to carry a hand-written `ROUTES` list — five pairs of
//! `(event arm, call)` — plus an `assert_eq!(ROUTES.len(), 5)` to make adding a
//! sixth "a decision rather than an omission". That is not a guard against a new
//! route; it is a guard against a new route that somebody also remembered to
//! write down here. A list of the doors you remember is the same artefact as a
//! list of the doors you locked, and it passes for exactly as long as your
//! memory holds.
//!
//! The enumeration is now GENERATED, from two authorities that cannot drift:
//!
//! 1. **rustc.** [`classify`] is a total `match` over `sumchain_p2p::NetworkEvent`.
//!    A new variant does not fail an assertion — it fails to COMPILE, here, until
//!    somebody states what that event can do to consensus. There is no way to add
//!    an event and leave this file passing in ignorance of it.
//! 2. **The enum's own text.** The variant names are parsed out of
//!    `crates/p2p/src/network.rs` and cross-checked against the arms of
//!    [`classify`], so a parser that under-read the enum fails instead of
//!    quietly scanning fewer routes than exist.
//!
//! And the node's event loop is asserted to have NO catch-all arm, which is what
//! makes rustc's exhaustiveness check bind on the production code too: with
//! `_ => {}` in the loop, a new event would compile unhandled and this file's
//! per-arm scans would have nothing to look at.
//!
//! The set of calls that count as "reaching consensus" is derived as well —
//! from `ConsensusWrapper`'s own method list minus the `ConsensusQuery` reads
//! (see [`consensus_sinks`]) — so a new capability added to the wrapper is
//! forbidden inside an unguarded arm from the moment it is written, without an
//! edit here.
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
//!   `PoAEngine::do_import_block`, `crates/consensus/src/poa.rs`. It validates
//!   the block, classifies it against `LongestChainForkChoice::should_switch`
//!   (`crates/consensus/src/engine.rs`) into `DirectExtension`, `SideBranch` or
//!   `Reorg`, and publishes or reorgs. A block that reaches it has already
//!   influenced this node.
//! * **There are no PoA votes.** The `ConsensusEngine` trait has `import_block`
//!   and `propose_block` and no vote method at all. Votes exist only in the
//!   experimental BFT engine (`crates/consensus/src/bft/vote.rs`).
//! * **The engine cannot make this decision itself.** `import_block(&self,
//!   block: Block)` is handed a block and nothing else; there is no `PeerId`
//!   anywhere in the trait. So the refusal has to sit at the network boundary,
//!   which is `Node::run`'s event loop in `crates/node/src/node.rs`.
//!
//! # Why this is a source scan at all
//!
//! The decision itself is `PeerCompatRegistry::may_participate_in_consensus`,
//! whose truth table is exercised directly in
//! `crates/p2p/tests/protocol_enforcement.rs`, and its effect on a real engine
//! and a real database is driven in
//! `crates/node/tests/unit/peer_block_admission_tests.rs` — which is where "the
//! block did not reach the block store" is actually proved. What cannot be
//! reached from either is the WIRING: `Node::run` is one large `async fn` with
//! no seam, and a version of it that simply never called the predicate would
//! pass every behavioural test in the workspace.
//!
//! ORDER is asserted as well as presence. A check that ran after `import_block`
//! would be a check on a block that had already been published.
//!
//! # The route that was closed by TYPE rather than by this file
//!
//! `ConsensusWrapper::as_consensus_engine` used to hand the RPC server the SAME
//! `Arc<PoAEngine>` the event loop holds, upcast to `Arc<dyn ConsensusEngine>` —
//! and `import_block` is a method on that trait. The RPC server therefore held a
//! live, callable handle into proposal acceptance and fork choice, reachable
//! from an unauthenticated JSON-RPC method, with no `PeerId` anywhere near it
//! and so nothing for the participation predicate to judge. No RPC method called
//! it, but that was the result of a text search, not a property of the design,
//! and it would not have been a sixth route THROUGH the boundary — it would have
//! been a route AROUND it.
//!
//! It is now `as_consensus_query` handing out `Arc<dyn ConsensusQuery>` — the
//! reads `crates/rpc/src/server.rs` actually performs, and nothing else.
//! `crates/rpc/tests/consensus_capability_probe.rs` compiles `import_block`
//! against that trait and asserts rustc rejects it, with a control proving the
//! capability still exists on `dyn ConsensusEngine`;
//! `consensus_handle_is_query_only` in `crates/rpc/src/server.rs` pins the
//! server's field to that type.
//! [`the_rpc_surface_never_reaches_into_the_consensus_engine`] is KEPT, with its
//! claim narrowed — see its own doc comment.
//!
//! Block PRODUCTION is deliberately not a route: `PoAEngine::create_block`
//! commits through `accept_produced` and never calls `do_import_block`, and its
//! input is this node's own mempool rather than a peer. A peer reaching the
//! mempool is a separate surface with a separate gate, which is why
//! [`Route::IntoMempool`] exists as its own answer rather than being filed under
//! [`Route::Inert`].

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sumchain_p2p::NetworkEvent;

// ─── the authority: what each event can do to consensus ──────────────────────

/// What a `NetworkEvent` is permitted to do with this node's consensus engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// Carries a peer's proposal, vote or block toward the engine. Its arm must
    /// consult the participation predicate, and must do so before any call that
    /// can influence consensus.
    IntoConsensus,
    /// Answers the peer out of already-decided state. It may READ consensus and
    /// must not call anything that can change it. Note what this deliberately
    /// does NOT do: it does not refuse to serve an undeclared peer. Serving
    /// blocks to a peer cannot move this node's head, and refusing above the
    /// enforcement height would cut off every node still catching up.
    ServesReads,
    /// The compatibility handshake itself — the arm that decides what this node
    /// has PROVEN about a peer. It must reach `PeerCompatRegistry`, and it must
    /// not touch consensus.
    DecidesCompat,
    /// Reaches the mempool, which is a different surface with a different gate
    /// (`Mempool::add` plus the activation-aware admission gate the node keeps
    /// `chain_height` current for). A transaction in the mempool influences
    /// consensus only by being included in a block THIS node produces, which is
    /// this node's own decision, not the peer's.
    IntoMempool,
    /// Touches neither consensus nor the mempool.
    Inert,
}

/// Every `NetworkEvent`, and what it may do. **rustc is the enumerator.**
///
/// This function is compiled, not called: its entire job is the exhaustiveness
/// check on the `match` below. Add a variant to `sumchain_p2p::NetworkEvent` and
/// this test target stops building until the variant is classified — which is
/// the property the previous hand-written `ROUTES` list did not have and could
/// not be given, because a list has no way to know what it is missing.
///
/// The classification is then held to its word by the scans further down: an
/// arm classified anything but [`Route::IntoConsensus`] must not contain a
/// single call that can reach the engine, so declaring a new route `Inert` to
/// quiet the compiler does not buy silence.
#[allow(dead_code)]
fn classify(event: &NetworkEvent) -> (&'static str, Route) {
    match event {
        // Gossip. The route that was unattributed: `BlockReceived` was a bare
        // `Block` and the propagating peer was dropped in
        // `NetworkService::handle_gossip_message`, so there was nothing to judge.
        NetworkEvent::BlockReceived { .. } => ("BlockReceived", Route::IntoConsensus),
        // Sync. Attributed before this change, gated only on "declared a
        // DIFFERENT digest" rather than on the two-phase policy.
        NetworkEvent::SyncBlocksReceived { .. } => ("SyncBlocksReceived", Route::IntoConsensus),
        // A peer's claimed head is what this node sets its sync target from, and
        // then asks that peer for the blocks. Gated at `our_next`, because the
        // status races the declaration and can beat it.
        NetworkEvent::SyncStatusResponse { .. } => ("SyncStatusResponse", Route::IntoConsensus),
        // The experimental BFT engine's proposal and its two votes. Not the
        // production path, but gated on the same predicate at the same boundary
        // so that enabling the engine does not quietly reopen the hole.
        NetworkEvent::BftProposalReceived { .. } => ("BftProposalReceived", Route::IntoConsensus),
        NetworkEvent::BftPrevoteReceived { .. } => ("BftPrevoteReceived", Route::IntoConsensus),
        NetworkEvent::BftPrecommitReceived { .. } => ("BftPrecommitReceived", Route::IntoConsensus),
        // Serving the peer, not hearing it.
        NetworkEvent::SyncStatusRequest { .. } => ("SyncStatusRequest", Route::ServesReads),
        NetworkEvent::SyncBlocksRequest { .. } => ("SyncBlocksRequest", Route::ServesReads),
        // The handshake.
        NetworkEvent::ProtocolIdResponse { .. } => ("ProtocolIdResponse", Route::DecidesCompat),
        // Answering "which rules does this binary enforce" reads a digest fixed
        // at boot and reaches no engine.
        NetworkEvent::ProtocolIdRequest { .. } => ("ProtocolIdRequest", Route::Inert),
        NetworkEvent::TransactionReceived(_) => ("TransactionReceived", Route::IntoMempool),
        NetworkEvent::PeerConnected(_) => ("PeerConnected", Route::Inert),
        NetworkEvent::PeerDisconnected(_) => ("PeerDisconnected", Route::Inert),
        NetworkEvent::SyncRequestFailed { .. } => ("SyncRequestFailed", Route::Inert),
        // The swarm bound an address. Carries no peer at all.
        NetworkEvent::Listening(_) => ("Listening", Route::Inert),
    }
}

// ─── reading source without reading prose ────────────────────────────────────

/// `src` with every comment and every string literal's CONTENTS blanked out,
/// byte offsets preserved.
///
/// Both halves matter and both have burned this file's predecessors:
///
/// * The doc comment on `admit_peer_block` names `NetworkEvent::BlockReceived`
///   and quotes `import_block`, exactly as it should. A scan that counted those
///   would be counting prose, which is why the previous version of this file
///   stripped whole-line comments.
/// * The event arms are full of `warn!("Refusing {:?} ...")`. Those braces are
///   not code, and an arm-splitter that counts them lands in the wrong place.
///   Blanking string interiors is what makes brace-matching safe.
///
/// Offsets are preserved (one blank byte per masked byte, newlines kept) so a
/// position found in the mask is a position in the real file.
///
/// The files read here have no block comments, no raw strings and no char
/// literals — see [`the_masker_matches_the_lexical_shape_of_the_files_it_reads`],
/// which fails if that stops being true rather than letting this quietly
/// mis-read.
fn mask(src: &str) -> String {
    let b = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        if b[i] == b'"' {
            out.push(b'"');
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    out.push(b' ');
                    i += 1;
                    if i < b.len() {
                        out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                        i += 1;
                    }
                    continue;
                }
                if b[i] == b'"' {
                    out.push(b'"');
                    i += 1;
                    break;
                }
                out.push(if b[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).expect("masking replaces bytes with ASCII and keeps the rest")
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_masked(path: &Path) -> String {
    let raw =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let masked = mask(&raw);
    assert_eq!(
        masked.len(),
        raw.len(),
        "the mask must preserve byte offsets in {}",
        path.display()
    );
    masked
}

fn node_source() -> String {
    read_masked(&crate_dir().join("src/node.rs"))
}

/// The balanced `{ .. }` block that follows `opener`, braces included.
fn block_after(src: &str, opener: &str, what: &str) -> String {
    let at = src.find(opener).unwrap_or_else(|| {
        panic!(
            "no `{opener}` in {what}; this guard is pinned to a shape that has \
             changed and must be re-derived rather than deleted"
        )
    });
    let rest = &src[at..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("`{opener}` in {what} is not followed by a block"));
    let bytes = rest.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[open..=i].to_string();
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced braces after `{opener}` in {what}");
}

/// Split a `match` body (braces included) into `(head, body)` per arm.
///
/// Depth-aware, so a struct pattern's own braces (`Ev::X { a, b } =>`) do not
/// end the arm, and string interiors are already blank so a `"{}"` inside a
/// `warn!` cannot either.
fn match_arms(match_block: &str) -> Vec<(String, String)> {
    let inner = &match_block[1..match_block.len() - 1];
    let b = inner.as_bytes();
    let mut arms = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b',') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let head_start = i;
        let mut depth = 0i32;
        let mut arrow = None;
        while i < b.len() {
            match b[i] {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => depth -= 1,
                b'=' if depth == 0 && i + 1 < b.len() && b[i + 1] == b'>' => {
                    arrow = Some(i);
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        let Some(arrow) = arrow else { break };
        let head = inner[head_start..arrow].trim().to_string();
        i = arrow + 2;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let body_start = i;
        if i < b.len() && b[i] == b'{' {
            let mut depth = 0usize;
            while i < b.len() {
                match b[i] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        } else {
            let mut depth = 0i32;
            while i < b.len() {
                match b[i] {
                    b'{' | b'(' | b'[' => depth += 1,
                    b'}' | b')' | b']' => depth -= 1,
                    b',' if depth == 0 => break,
                    _ => {}
                }
                i += 1;
            }
        }
        arms.push((head, inner[body_start..i].to_string()));
    }
    arms
}

/// Identifiers declared at the top level of an `enum` or `trait` block.
fn top_level_names(block: &str, want_upper: bool) -> BTreeSet<String> {
    let inner = &block[1..block.len() - 1];
    let b = inner.as_bytes();
    let mut depth = 0i32;
    let mut out = BTreeSet::new();
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'{' | b'(' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b')' | b']' => {
                depth -= 1;
                i += 1;
            }
            c if depth == 0 && (c.is_ascii_alphabetic() || c == b'_') => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let word = &inner[start..i];
                if want_upper == word.as_bytes()[0].is_ascii_uppercase() {
                    out.insert(word.to_string());
                }
            }
            _ => i += 1,
        }
    }
    out
}

// ─── the generated enumeration ───────────────────────────────────────────────

/// Every `NetworkEvent` variant name, read out of the enum that declares them.
fn declared_event_variants() -> BTreeSet<String> {
    let p2p = crate_dir().join("../p2p/src/network.rs");
    let src = read_masked(&p2p);
    let block = block_after(&src, "pub enum NetworkEvent", "crates/p2p/src/network.rs");
    let names = top_level_names(&block, true);
    assert!(
        names.len() >= 10,
        "only {} NetworkEvent variants parsed out of {}; the parser has stopped \
         working rather than the enum having shrunk, and a guard that scans \
         fewer routes than exist is worse than none",
        names.len(),
        p2p.display()
    );
    names
}

/// The `(variant, route)` table, read back out of [`classify`]'s own arms.
///
/// The values cannot be obtained by CALLING `classify` — that would mean
/// constructing a `Block`, a `SignedTransaction` and a `Multiaddr` apiece — so
/// they are read from this file's source. The pairing is safe because the same
/// arms are simultaneously checked by rustc: `classify` is a total match, so no
/// variant is missing from it, and `the_route_table_is_generated_from_the_event_enum`
/// asserts the parse below found every variant the enum declares. Neither
/// authority can shrink without the other noticing.
fn route_table() -> Vec<(String, Route)> {
    let me = crate_dir().join("tests/consensus_participation_guard.rs");
    let src = read_masked(&me);
    let body = block_after(&src, "fn classify(event: &NetworkEvent)", "this file");
    let mut out = Vec::new();
    for arm in body.split("NetworkEvent::").skip(1) {
        let name: String = arm
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let route_at = arm
            .find("Route::")
            .unwrap_or_else(|| panic!("the `{name}` arm of `classify` names no `Route::`"));
        let route: String = arm[route_at + "Route::".len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        let route = match route.as_str() {
            "IntoConsensus" => Route::IntoConsensus,
            "ServesReads" => Route::ServesReads,
            "DecidesCompat" => Route::DecidesCompat,
            "IntoMempool" => Route::IntoMempool,
            "Inert" => Route::Inert,
            other => panic!("`classify` names an unknown route `Route::{other}` for `{name}`"),
        };
        out.push((name, route));
    }
    out
}

/// Reads of already-decided state that `ConsensusQuery` happens not to carry.
///
/// `best_block_hash` and `get_block_by_height` are absent from that trait
/// because the RPC server does not call them, not because they can change
/// anything: each returns state already decided and takes nothing from the peer
/// but a height. They are named here so that the omission is a decision.
///
/// The subtraction fails in the safe direction. Forgetting to add a genuinely
/// pure read makes an honest arm FAIL this guard, loudly. There is no
/// corresponding way for it to make a dangerous arm pass.
const READS_OF_DECIDED_STATE: &[&str] = &["best_block_hash", "get_block_by_height"];

/// The calls on the consensus handle that can INFLUENCE consensus, derived.
///
/// `ConsensusWrapper`'s own public method list, minus the methods of
/// `ConsensusQuery` — the trait that exists to say, in the type system, which
/// of them are pure reads of already-decided state — minus
/// [`READS_OF_DECIDED_STATE`].
///
/// Deriving it rather than listing it is the point. `as_poa`, `as_bft` and
/// `as_consensus_query` hand out the engine itself and are therefore capability
/// escapes; nobody listing "calls that reach consensus" by hand writes those
/// down, and the subtraction does. A new method on the wrapper is forbidden
/// inside an unguarded arm from the moment it is written.
fn consensus_sinks() -> BTreeSet<String> {
    let wrapper = read_masked(&crate_dir().join("src/consensus_wrapper.rs"));
    let block = block_after(&wrapper, "impl ConsensusWrapper", "consensus_wrapper.rs");
    let mut methods = BTreeSet::new();
    for piece in block.split("fn ").skip(1) {
        let name: String = piece
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            methods.insert(name);
        }
    }
    assert!(
        methods.len() >= 15,
        "only {} methods parsed off `ConsensusWrapper`; the parser stopped \
         working and the derived sink set is now nearly empty: {methods:?}",
        methods.len()
    );

    let engine = read_masked(&crate_dir().join("../consensus/src/engine.rs"));
    let query = block_after(
        &engine,
        "pub trait ConsensusQuery",
        "crates/consensus/src/engine.rs",
    );
    let mut reads = top_level_names(&query, false);
    // A lowercase scan of a trait body also picks up `fn`, `self` and return
    // types; only the names that are really methods of the wrapper matter.
    reads.retain(|r| methods.contains(r));
    assert!(
        reads.contains("current_height"),
        "`ConsensusQuery` no longer declares `current_height`; the read/write \
         split this derivation rests on has moved and must be re-derived"
    );
    for r in READS_OF_DECIDED_STATE {
        assert!(
            methods.contains(*r),
            "`{r}` is named as a pure read of decided state but is not a method \
             of `ConsensusWrapper`; this subtraction now removes nothing and \
             must be re-derived rather than left to rot"
        );
        reads.insert(r.to_string());
    }

    let sinks: BTreeSet<String> = methods.difference(&reads).cloned().collect();
    for must in [
        "import_block",
        "handle_proposal",
        "handle_prevote",
        "handle_precommit",
        "as_poa",
        "as_bft",
    ] {
        assert!(
            sinks.contains(must),
            "`{must}` must count as reaching consensus and does not. Derived \
             sinks were {sinks:?}; either the wrapper was renamed or something \
             was subtracted as a read that is not one"
        );
    }
    sinks
}

/// The one function that decides AND imports.
///
/// The two block routes no longer write the check themselves — writing it twice
/// is what made it possible to write it once. They call this, and this is the
/// only thing in `crates/node/src` that calls `import_block`, so the scan below
/// is "there is one door and it is locked" rather than "both doors were locked
/// when I last looked".
const SEAM: &str = "Self::admit_peer_block(";

/// The predicate. The whole two-phase policy is this one call.
const CHECK: &str = "may_participate_in_consensus";

/// The engine call the seam owns.
const IMPORT: &str = ".import_block(";

/// The node's `match` over `NetworkEvent`, arm by arm.
fn event_loop_arms(src: &str) -> Vec<(String, String)> {
    let select_arm = block_after(
        src,
        "Ok(event) = network_events.recv()",
        "the node event loop",
    );
    let match_block = block_after(&select_arm, "match event", "the network event arm");
    match_arms(&match_block)
}

/// The arm for one variant.
fn arm_for<'a>(arms: &'a [(String, String)], variant: &str) -> &'a str {
    let needle = format!("NetworkEvent::{variant}");
    arms.iter()
        .find(|(head, _)| {
            head.starts_with(&needle)
                && !head[needle.len()..]
                    .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        })
        .map(|(_, body)| body.as_str())
        .unwrap_or_else(|| panic!("no `NetworkEvent::{variant}` arm in the node event loop"))
}

// ─── the tests ───────────────────────────────────────────────────────────────

/// The two authorities agree, and neither can be smaller than the other.
///
/// rustc guarantees [`classify`] covers every variant. This guarantees the enum
/// parse saw every variant too — so the scans below run over the whole event
/// surface rather than over whichever part of it a parser happened to read.
#[test]
fn the_route_table_is_generated_from_the_event_enum() {
    let declared = declared_event_variants();
    let table = route_table();
    let classified: BTreeSet<String> = table.iter().map(|(n, _)| n.clone()).collect();

    assert_eq!(
        classified, declared,
        "the variants `classify` names and the variants `NetworkEvent` declares \
         must be the same set. rustc already refuses a `classify` that is \
         missing one; a difference here means the enum parser under-read the \
         file, and every scan in this guard would then be running over fewer \
         routes than exist"
    );
    assert_eq!(
        table.len(),
        classified.len(),
        "`classify` names a variant twice: {table:?}"
    );

    // A route table in which nothing reaches consensus would satisfy every
    // other test in this file by covering nothing.
    assert!(
        table
            .iter()
            .filter(|(_, r)| *r == Route::IntoConsensus)
            .count()
            >= 5,
        "fewer than five events reach consensus; either the loop was gutted or \
         routes are being classified away: {table:?}"
    );
}

/// The event loop has an arm per variant and NO catch-all.
///
/// This is what makes rustc's exhaustiveness check bind on the production code.
/// With a `_ => {}` in the loop, a new `NetworkEvent` compiles unhandled — no
/// arm, nothing for the per-arm scans below to read, and a route this file would
/// report as absent rather than as unguarded.
#[test]
fn the_event_loop_handles_every_event_and_has_no_catch_all() {
    let src = node_source();
    let arms = event_loop_arms(&src);
    assert!(
        !arms.is_empty(),
        "no arms parsed out of the node event loop"
    );

    for (head, _) in &arms {
        assert!(
            head.starts_with("NetworkEvent::"),
            "the node's network event loop has a non-`NetworkEvent::` arm: \
             `{head}`. A catch-all (or any wildcard) there means rustc stops \
             enforcing that every event is handled, and a new route into \
             consensus would arrive silently"
        );
    }

    let handled: BTreeSet<String> = arms
        .iter()
        .map(|(head, _)| {
            head["NetworkEvent::".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect();
    assert_eq!(
        handled,
        declared_event_variants(),
        "the event loop's arms and the `NetworkEvent` enum must match exactly"
    );
}

/// Every route into consensus checks participation, and checks it first.
///
/// And — the half a hand-written list could never do — every route that is NOT
/// into consensus is held to that classification: it may not contain a single
/// call that can influence the engine. Adding a new event, classifying it
/// `Inert` so [`classify`] compiles, and then wiring it into `import_block`
/// fails HERE.
#[test]
fn every_route_is_held_to_its_classification() {
    let src = node_source();
    let arms = event_loop_arms(&src);
    let sinks = consensus_sinks();

    for (variant, route) in route_table() {
        let body = arm_for(&arms, &variant);
        let first_sink = sinks
            .iter()
            .filter_map(|s| body.find(&format!("consensus.{s}(")).map(|at| (at, s)))
            .min();

        match route {
            Route::IntoConsensus => {
                let check_at = body
                    .find(CHECK)
                    .or_else(|| body.find(SEAM))
                    .unwrap_or_else(|| {
                        panic!(
                            "the `{variant}` arm calls neither `{CHECK}` nor `{SEAM}`. \
                         It carries a peer's message toward the engine — for a \
                         block that is `PoAEngine::do_import_block`, which is \
                         validity, fork choice and reorg in one function — so a \
                         peer this node cannot show it agrees with would be \
                         proposing blocks and moving the head"
                        )
                    });
                if let Some((sink_at, sink)) = first_sink {
                    assert!(
                        check_at < sink_at,
                        "the `{variant}` arm calls `consensus.{sink}(` at byte \
                         {sink_at}, BEFORE its participation check at byte \
                         {check_at}. A check that runs after the engine has the \
                         message is a check on a block that has already been \
                         executed, classified against fork choice and possibly \
                         published"
                    );
                }
            }
            Route::ServesReads | Route::DecidesCompat | Route::IntoMempool | Route::Inert => {
                assert!(
                    first_sink.is_none(),
                    "the `{variant}` arm is classified `{route:?}` — meaning it \
                     cannot influence consensus — and it calls `consensus.{}(`. \
                     Either the classification is wrong, in which case this is an \
                     UNGUARDED route into proposal acceptance and fork choice, or \
                     the call is. Both are defects and neither is fixed by \
                     editing this test",
                    first_sink.unwrap().1
                );
                if route == Route::DecidesCompat {
                    assert!(
                        body.contains("peer_compat.on_declaration("),
                        "the `{variant}` arm is the compatibility handshake and \
                         does not record the declaration; every refusal in this \
                         mechanism reads the state this arm writes"
                    );
                }
            }
        }
    }
}

/// Every route into consensus carries the peer the message came from.
///
/// The gate is unenforceable without this. `NetworkEvent::BlockReceived` was a
/// bare `Block` and the propagating peer was dropped in
/// `NetworkService::handle_gossip_message`, so there was no peer to judge —
/// which is exactly how a mechanism can look complete and cover one of two
/// routes.
#[test]
fn every_route_into_consensus_carries_the_peer_it_came_from() {
    let src = node_source();
    let arms = event_loop_arms(&src);
    for (variant, route) in route_table() {
        if route != Route::IntoConsensus {
            continue;
        }
        let needle = format!("NetworkEvent::{variant}");
        let head = arms
            .iter()
            .find(|(h, _)| h.starts_with(&needle))
            .map(|(h, _)| h.clone())
            .unwrap_or_else(|| panic!("no `{needle}` arm"));
        assert!(
            head.contains("source") || head.contains("peer"),
            "the `{variant}` arm binds no peer: `{head}`. Without one there is \
             nothing for the participation check to judge, and the refusal is \
             unenforceable on this route however carefully it is written"
        );
    }
}

/// One call into the engine's import path in the whole node, and it is the seam.
///
/// Counted over the entire masked file rather than over the arms, so an alias
/// (`let engine = consensus.as_poa()` then `engine.import_block(..)`) is caught
/// too.
#[test]
fn the_node_imports_a_peers_block_in_exactly_one_place() {
    let src = node_source();
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
    let body = block_after(
        &src,
        "pub(crate) async fn admit_peer_block(",
        "crates/node/src/node.rs",
    );

    let check_at = body.find(CHECK).unwrap_or_else(|| {
        panic!(
            "`admit_peer_block` does not call `{CHECK}`, so every route through \
             it is unguarded at once"
        )
    });
    let call_at = body.find(IMPORT).unwrap_or_else(|| {
        panic!(
            "`admit_peer_block` does not call `{IMPORT}`; the seam no longer owns \
             the engine call and the one-call-site guarantee is void"
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

/// The masker's assumptions about the files it reads, asserted rather than hoped.
///
/// [`mask`] handles `//` comments and `"` strings and nothing else, which is
/// correct for these files today. If a block comment or a raw string appears,
/// the mask silently mis-reads and every scan above becomes unreliable in the
/// direction that matters — a sink hidden inside what the masker believes is a
/// string would not be seen. So the assumption is a test.
#[test]
fn the_masker_matches_the_lexical_shape_of_the_files_it_reads() {
    for rel in [
        "src/node.rs",
        "src/consensus_wrapper.rs",
        "../p2p/src/network.rs",
        "../consensus/src/engine.rs",
    ] {
        let path = crate_dir().join(rel);
        let raw =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        let masked = mask(&raw);
        assert_eq!(
            masked.len(),
            raw.len(),
            "{} masked to a different length",
            path.display()
        );
        for needle in ["/*", "r\"", "r#\""] {
            assert!(
                !masked.contains(needle),
                "{} contains `{needle}` outside a comment or a string, and the \
                 masker understands neither block comments nor raw strings; it \
                 would mis-read this file rather than fail on it",
                path.display()
            );
        }
    }

    // The mask really did remove prose: `admit_peer_block`'s doc comment quotes
    // `import_block`, so a masker that left comments in place would make
    // `the_node_imports_a_peers_block_in_exactly_one_place` count prose.
    let raw = fs::read_to_string(crate_dir().join("src/node.rs")).expect("node.rs");
    assert!(
        raw.matches(IMPORT).count() > mask(&raw).matches(IMPORT).count(),
        "`{IMPORT}` appears the same number of times before and after masking, \
         which means the mask stopped removing comments"
    );
}

/// The RPC surface never reaches into ANY consensus engine, by any route.
///
/// # Why this is no longer the primary control
///
/// It used to be the only one. The RPC server was handed
/// `Arc<dyn ConsensusEngine>`, `import_block` was a method on it, and nothing
/// but this scan stood between a future handler and `do_import_block`. The
/// handle is now `Arc<dyn ConsensusQuery>`, which has no such method;
/// `crates/rpc/tests/consensus_capability_probe.rs` proves that by compiling
/// the call and reading rustc's rejection, and
/// `consensus_handle_is_query_only` (`crates/rpc/src/server.rs`) proves the
/// server's field is that type. A handler that writes `self.consensus.
/// import_block(b)` now fails to build; this scan can no longer be the thing
/// that catches it, because the code never gets far enough to be scanned.
///
/// # Why it is kept rather than retired
///
/// Narrowing a handle's type says nothing about engines reached by some OTHER
/// route. An RPC handler holds `Arc<Database>`, `Arc<StateManager>` and
/// `Arc<Mempool>` — everything `PoAEngine::new` needs — so it could construct
/// its own engine and call `import_block` on THAT, feeding the same
/// `do_import_block` from the same HTTP request with the same absent `PeerId`.
/// No type on the RPC server's fields can forbid that; a source scan can see
/// it. That is the residual hazard this test now owns, and it is the reason
/// its needles are bare method names rather than `self.consensus.`-qualified
/// ones.
///
/// Scanned as text for the same reason the rest of this file is: the hazard is
/// a call that does not exist yet, and no behavioural test can fail on code
/// nobody has written.
#[test]
fn the_rpc_surface_never_reaches_into_the_consensus_engine() {
    let rpc_src = crate_dir().join("../rpc/src");
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
                "{} calls `{forbidden}`. The RPC server's own handle is \
                 `Arc<dyn ConsensusQuery>` and has no such method, so this call \
                 must be on an engine obtained by another route — most likely one \
                 the handler built itself from the db/state/mempool it holds. \
                 Either way it feeds proposal acceptance and fork choice from an \
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

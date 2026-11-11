//! The two-phase peer-compatibility policy: who may take part in consensus.
//!
//! # The gap this closes
//!
//! The protocol-digest handshake ([`crate::sync::SyncRequest::GetProtocolId`])
//! sorts peers into three states, not two:
//!
//! | what the peer does | what it means |
//! |---|---|
//! | declares OUR digest | [`PeerCompat::Verified`] — proven to enforce our rules |
//! | declares a DIFFERENT digest | [`PeerCompat::Incompatible`] — proven not to |
//! | declares nothing | [`PeerCompat::Undeclared`] — nothing is proven either way |
//!
//! Admitting the third row is what makes the handshake deployable: every
//! validator running today predates `GetProtocolId`, cannot decode it, answers
//! with an inbound failure, and must stay exactly as usable as it is now. A
//! refusal that fires on the current validator set is worse than the defect it
//! closes.
//!
//! It is also correct only while it is true that nothing distinguishes the
//! three. Below the first remediation activation every node executes the same
//! rules, so an undeclared peer's blocks are blocks this node would have
//! produced itself. At that height the rules diverge, and the same silence now
//! means "this peer may be enforcing the rules we just stopped enforcing". An
//! undeclared peer and an incompatible one become the same thing.
//!
//! # The two phases
//!
//! So the policy has a boundary, and the boundary is a chain height configured
//! in `genesis.json`
//! (`ChainParams::peer_protocol_declaration_required_from_height`):
//!
//! | phase | height | `Verified` | `Undeclared` | `Incompatible` |
//! |---|---|---|---|---|
//! | one | below the height, or the height unset | participates | participates | refused |
//! | two | at or above the height | participates | REFUSED | refused |
//!
//! Only the `Undeclared` column changes, and only above a height an operator
//! has to write down. A node whose genesis does not carry the field at all —
//! every genesis distributed before this change — resolves it to `None` and
//! stays in phase one forever, which is byte-for-byte today's behaviour.
//!
//! # Why the height is in `ChainParams` and not in this binary
//!
//! Two nodes holding different values partition the network: the one with the
//! lower height refuses peers the other still talks to, and neither can tell
//! that is why. That is the definition of a value that must be coordinated and
//! comparable — which is what `ChainParams` plus `activation_heights()` is for.
//! Being a `ChainParams` gate, it is folded into the activation digest and
//! therefore into the protocol digest itself, so a disagreement about WHEN to
//! enforce is reported by the very mechanism it configures.
//!
//! A compiled-in constant would have been the other candidate and is rejected
//! for the reason `protocol_digest.rs` gives about the limits it folds: leaving
//! a consensus-relevant number in the binary does not remove it, it moves it
//! somewhere nothing can compare it.
//!
//! # What "participate in consensus" means here
//!
//! Established from source rather than assumed. Production consensus is PoA
//! (`crates/consensus/src/lib.rs:3`; `crates/consensus/src/bft/mod.rs:3` says
//! the BFT engine is experimental and not production ready). In PoA the ONLY
//! way a peer influences this node is by getting a `Block` into
//! `PoAEngine::do_import_block` (`crates/consensus/src/poa.rs:603`), which is
//! where validity, fork choice
//! (`LongestChainForkChoice::should_switch`, `crates/consensus/src/engine.rs:113`)
//! and reorg all happen. There are no PoA votes. Refusing a peer's blocks at
//! the node's network boundary is therefore refusing it proposal acceptance and
//! fork-choice influence in one place.
//!
//! # This registry is in memory, and that is ACCEPTED
//!
//! `PeerCompatRegistry::declared` is a `RwLock<HashMap<..>>` and nothing
//! persists it, so a restart forgets every declaration. The two sides of the
//! enforcement boundary fail in opposite directions, and the release position
//! on each is different:
//!
//! * **Below the height — ACCEPTED.** A restart re-admits a peer this node had
//!   marked [`PeerCompat::Incompatible`]. Pre-enforcement compatibility state
//!   may reset on restart. The cost is bounded by what phase one already
//!   means: below the height every node executes the same rules, so the
//!   re-admitted peer's blocks are blocks this node would have produced
//!   itself. This is a decided property of the release, not a residual waiting
//!   on a persistence change, and it should not be recorded as outstanding
//!   work.
//! * **At or above the height — NOT negotiable.** A restart re-refuses a peer
//!   it had VERIFIED, until that peer answers `GetProtocolId` again. Post-
//!   enforcement behaviour must remain fail-closed: an unverified peer is
//!   refused, and no change to the reset behaviour above may relax that.
//!
//! `protocol_enforcement.rs::a_restart_forgets_declarations_and_the_window_fails_closed_above_the_height`
//! pins both halves — the accepted one so that it is a recorded decision rather
//! than an accident, and the fail-closed one so that it cannot be traded away
//! while making the first survive a restart.
//! `docs/operations/p2p-admission-and-compatibility.md` states them for
//! operators.
//!
//! See `crates/p2p/tests/protocol_enforcement.rs` for the phase matrix and
//! `crates/node/src/node.rs` for the two arrival paths it is applied to.

use std::collections::HashMap;

use libp2p_identity::PeerId;
use parking_lot::RwLock;
use sumchain_primitives::{BlockHeight, Hash};
use tracing::warn;

/// What this node has PROVEN about one peer's rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCompat {
    /// The peer declared a protocol digest equal to ours. It enforces the same
    /// activation heights and the same compiled-in constants, so a block it
    /// accepts is a block this node accepts.
    Verified,
    /// The peer declared a protocol digest DIFFERENT from ours. It said, in its
    /// own words, that it enforces other rules. Permanent: a peer never leaves
    /// this state, however it answers later.
    Incompatible,
    /// The peer has declared nothing. Not evidence of anything — a node built
    /// before `GetProtocolId` existed cannot decode the request and answers
    /// with an inbound failure, which is indistinguishable here from a peer
    /// whose answer is merely still in flight.
    Undeclared,
}

/// The digest this binary enforces, the height enforcement begins, and what
/// every peer has declared.
///
/// One object so that the policy has ONE implementation. Both the block syncer
/// and the node event loop consult it; before this existed they each kept a
/// `HashSet<PeerId>` and re-derived the rule, which is two chances to get a
/// two-phase policy wrong instead of one.
pub struct PeerCompatRegistry {
    /// `sumchain_state::protocol_digest::protocol_digest` for THIS binary and
    /// THIS genesis.
    ours: Hash,
    /// The height from which an [`PeerCompat::Undeclared`] peer stops being
    /// allowed to take part. `None` is phase one forever, and is what a genesis
    /// written before the field existed resolves to.
    enforce_from: Option<BlockHeight>,
    /// Declared states only. Absence is [`PeerCompat::Undeclared`], which is
    /// why this is not a pair of sets: "not yet answered" and "answered
    /// compatibly" are different, and phase two acts on the difference.
    declared: RwLock<HashMap<PeerId, PeerCompat>>,
}

impl PeerCompatRegistry {
    /// A registry enforcing `ours` from `enforce_from`.
    ///
    /// `enforce_from` is
    /// `ChainParams::peer_protocol_declaration_required_from_height`, passed in
    /// rather than read here so this crate does not depend on `genesis`.
    pub fn new(ours: Hash, enforce_from: Option<BlockHeight>) -> Self {
        Self {
            ours,
            enforce_from,
            declared: RwLock::new(HashMap::new()),
        }
    }

    /// The protocol digest this binary enforces.
    pub fn protocol_digest(&self) -> Hash {
        self.ours
    }

    /// The configured enforcement height, or `None` for phase one forever.
    pub fn enforcement_height(&self) -> Option<BlockHeight> {
        self.enforce_from
    }

    /// Whether a declaration is REQUIRED at `height`.
    ///
    /// `>=`, not `>`: the height names the first block at which the remediated
    /// rules may apply, so it is the first block for which an undeclared peer's
    /// opinion is already unusable.
    pub fn enforcing_at(&self, height: BlockHeight) -> bool {
        self.enforce_from.is_some_and(|from| height >= from)
    }

    /// Record a peer's declared digest. Returns `true` if it matched ours.
    ///
    /// A peer that once declared a mismatch stays [`PeerCompat::Incompatible`]
    /// even if it later declares a match: the first answer was an admission
    /// that its binary enforces other rules, and a second answer is at best a
    /// different binary and at worst a peer probing for admission.
    pub fn on_declaration(&self, peer: PeerId, digest: Hash) -> bool {
        let mut declared = self.declared.write();
        if declared.get(&peer) == Some(&PeerCompat::Incompatible) {
            return false;
        }
        if digest == self.ours {
            declared.insert(peer, PeerCompat::Verified);
            true
        } else {
            warn!(
                "Peer {} declared protocol digest {} but this binary enforces {}; \
                 marking it incompatible. The two disagree about an activation \
                 height or a consensus constant, so blocks one produces the other \
                 cannot reproduce.",
                peer, digest, self.ours
            );
            declared.insert(peer, PeerCompat::Incompatible);
            false
        }
    }

    /// What has been proven about `peer`.
    pub fn status(&self, peer: &PeerId) -> PeerCompat {
        self.declared
            .read()
            .get(peer)
            .copied()
            .unwrap_or(PeerCompat::Undeclared)
    }

    /// Whether `peer` declared a digest different from ours.
    ///
    /// Distinct from "may not participate": in phase two an undeclared peer may
    /// not participate and is still not incompatible, because it has not said
    /// anything. The two are separate so that a log line, a metric or a ban
    /// decision can tell a refusal from an absence.
    pub fn is_incompatible(&self, peer: &PeerId) -> bool {
        self.status(peer) == PeerCompat::Incompatible
    }

    /// Whether `peer` may propose a block, vote, or move this node's fork
    /// choice, at chain height `height`.
    ///
    /// The whole two-phase policy, in one predicate, consulted at every point a
    /// peer's message could reach the consensus engine.
    pub fn may_participate_in_consensus(&self, peer: &PeerId, height: BlockHeight) -> bool {
        match self.status(peer) {
            PeerCompat::Verified => true,
            PeerCompat::Incompatible => false,
            PeerCompat::Undeclared => !self.enforcing_at(height),
        }
    }
}

//! Bootstrap-authorization acceptance (G2-c, ratified 2026-10-16).
//!
//! The ratified rule: a quorum-signed, sequence-chained authorization, shipped
//! with the release, authorizes a consensus upgrade at an activation height H.
//!
//! * Genesis membership authenticates the first authorization (sequence 1)
//!   only. A later sequence is authenticated by the membership recorded when
//!   the previous sequence was applied.
//! * Handshake announcements ([`Hint`]) never authorize and never halt:
//!   [`BootstrapState::assess_hint`] takes `&self`, and no API turns a hint
//!   into an accepted authorization.
//! * Two fully verified authorizations (chain identity, membership and quorum
//!   signatures all valid) for the same sequence with different bodies are
//!   kept as evidence. The node halts before the earlier of their activation
//!   heights, applies neither, and reverts nothing already applied.
//! * Late arrival never invalidates an authentic authorization: acceptance
//!   never compares the local head or clock with the signing deadline, and
//!   applied entries are never removed.
//!
//! Only a binary containing this framework can be stopped by it (see the crate
//! documentation).
//!
//! # What the caller supplies
//!
//! The authorization's byte encoding, its body digest and the membership
//! commitment are all unratified. An [`Authorization`] is therefore a decoded
//! value whose `body_digest` the caller's codec computed over the
//! domain-separated body without signatures. Until a codec exists, binding the
//! digest to the other fields is the caller's obligation. Signatures are
//! checked by an injected [`SignatureVerifier`] over `body_digest`.
//!
//! # Persistence
//!
//! [`BootstrapState`] is plain in-memory state. A wiring change must persist
//! it atomically with the block that changes it (in particular, recording an
//! authorization as applied belongs in block H's batch, so the handler runs
//! exactly once).

use thiserror::Error;

use crate::containment::{check_membership_transition, DynamicMembershipBeforeCertifiedFinality};
use crate::Digest;

/// A validator set as an ordered list of public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// Public keys in declared order; a signature's index refers to it.
    pub members: Vec<Vec<u8>>,
    /// Caller-computed commitment to `members` (encoding unratified).
    pub commitment: Digest,
}

impl Membership {
    /// Signatures needed: ⌊2n/3⌋+1 distinct members.
    pub fn quorum(&self) -> usize {
        self.members.len() * 2 / 3 + 1
    }
}

/// A block by height and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    pub height: u64,
    pub hash: Digest,
}

/// Identifies the upgrade handler (name, version and migration, in whatever
/// encoding is ratified). Opaque here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerId(pub Digest);

/// One member's signature over the authorization's body digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedSignature {
    pub index: u32,
    pub signature: Vec<u8>,
}

/// A decoded bootstrap authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// Chain identity.
    pub genesis_hash: Digest,
    /// 1 for the first authorization; each later one increments it.
    pub sequence: u64,
    /// Body digest of the previous authorization; all zero for sequence 1.
    pub previous_digest: Digest,
    pub old_commitment: Digest,
    pub new_commitment: Digest,
    pub checkpoint: BlockRef,
    /// H: the first block processed under the new rules.
    pub activation_height: u64,
    /// Signer policy. Nodes check only its ordering, never lateness.
    pub signing_deadline: u64,
    /// Must equal the authenticating membership's commitment.
    pub membership_commitment: Digest,
    pub handler: HandlerId,
    /// The authorization's identity: digest of its body without signatures.
    pub body_digest: Digest,
    /// Strictly ascending member indices.
    pub signatures: Vec<IndexedSignature>,
}

/// Verifies one member signature over a body digest.
///
/// **Required: strict Ed25519 verification.** Every implementation used for new
/// finality or upgrade signatures must:
/// - require canonical S < L and canonical R and A encodings;
/// - reject small-order A and R;
/// - use the cofactorless equation (ed25519-dalek `verify_strict` semantics).
///
/// Strict verification is the approved design direction (owner, 2026-10-16,
/// choice E1). The signature bytes themselves are still unratified.
///
/// This trait does not change any existing verification path. Historical
/// signatures, including every `sumchain-crypto` `verify` caller, are verified
/// exactly as before.
pub trait SignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &Digest, signature: &[u8]) -> bool;
}

/// Read access to the local canonical chain.
pub trait CanonicalChain {
    fn head_height(&self) -> u64;
    fn canonical_hash(&self, height: u64) -> Option<Digest>;
}

/// An authorization recorded as applied at its activation height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEntry {
    pub authorization: Authorization,
    /// Membership in force after this authorization; it authenticates the next.
    pub membership_after: Membership,
}

/// Two fully verified authorizations for one sequence with different bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEvidence {
    pub sequence: u64,
    pub first: Authorization,
    pub second: Authorization,
    /// The node processes no block at or above this height.
    pub halt_before: u64,
}

/// Why an authorization is not usable yet. Nothing is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deferral {
    /// Its authenticating membership is not known until an earlier sequence
    /// is applied.
    SequenceAhead { expected: u64 },
    /// The checkpoint is above the local head; retry after syncing.
    CheckpointAhead { checkpoint: u64, head: u64 },
}

/// Outcome of a fully verified authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acceptance {
    /// Scheduled for its activation height.
    Accepted {
        sequence: u64,
        activation_height: u64,
    },
    /// Authentic, but the local canonical chain already contains block H
    /// processed under the old rules. Recorded as pending so the node halts;
    /// nothing is reverted.
    AcceptedPastActivation {
        sequence: u64,
        activation_height: u64,
    },
    /// Identical to the pending or an applied authorization.
    AlreadyKnown {
        sequence: u64,
    },
    /// Conflicting with a fully verified authorization for the same sequence.
    Conflict {
        sequence: u64,
        halt_before: u64,
    },
    Deferred(Deferral),
}

/// Why an authorization was refused. Nothing is recorded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Refusal {
    #[error("authorization is for another chain")]
    WrongChain,
    #[error("sequence must start at 1")]
    BadSequence,
    #[error("signed for a membership other than the authenticating one")]
    MembershipMismatch,
    #[error("signature indices must be strictly ascending")]
    NonAscendingIndices,
    #[error("signature index {index} is not a member")]
    IndexOutOfRange { index: u32 },
    #[error("signature by member {index} does not verify")]
    BadSignature { index: u32 },
    #[error("{valid} valid signatures; {needed} needed")]
    NoQuorum { valid: usize, needed: usize },
    #[error("previous digest does not chain onto applied history")]
    BadChaining,
    #[error("old commitment is not this node's effective commitment")]
    CommitmentMismatch,
    #[error("checkpoint, deadline, notice and activation height are out of order")]
    BadOrdering,
    #[error("checkpoint is not on the local canonical chain")]
    CheckpointNotCanonical,
}

/// What the node must do before processing a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockAction {
    Proceed,
    /// Run the handler inside this block's atomic batch, then record the
    /// authorization as applied in the same batch.
    RunHandlerOnce {
        sequence: u64,
        handler: HandlerId,
    },
    Halt(HaltReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltReason {
    /// This binary does not know the authorized handler: stop before H.
    UpgradeNeeded { sequence: u64, handler: HandlerId },
    /// Conflicting fully verified authorizations.
    ConflictingAuthorizations { halt_before: u64 },
    /// The chain is past H without having applied the authorization.
    MissedActivation {
        sequence: u64,
        activation_height: u64,
    },
}

/// Recording an authorization as applied was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApplyError {
    #[error("no pending authorization with this sequence")]
    NotPending,
    #[error("halted by conflicting authorizations")]
    Halted,
    #[error(transparent)]
    Containment(#[from] DynamicMembershipBeforeCertifiedFinality),
}

/// A peer's handshake announcement. Information only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    pub genesis_hash: Digest,
    pub applied_count: u64,
    /// Body digest of the peer's last applied authorization (zero if none).
    pub applied_tip: Digest,
    pub next: Option<HintNext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HintNext {
    pub sequence: u64,
    pub digest: Digest,
    pub activation_height: u64,
}

/// How a peer's applied history relates to ours. Never a halt or an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintAssessment {
    OtherChain,
    InSync,
    /// The peer's history is a prefix of ours.
    PeerBehind,
    /// The peer claims more history; we may be behind. Anything fetched must
    /// still pass [`BootstrapState::accept`].
    PeerAhead,
    Diverged,
}

/// Applied history, the pending authorization and conflict evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapState {
    genesis_hash: Digest,
    genesis_membership: Membership,
    genesis_commitment: Digest,
    applied: Vec<AppliedEntry>,
    pending: Option<Authorization>,
    evidence: Vec<ConflictEvidence>,
    halt_before: Option<u64>,
}

impl BootstrapState {
    pub fn new(
        genesis_hash: Digest,
        genesis_membership: Membership,
        genesis_commitment: Digest,
    ) -> Self {
        Self {
            genesis_hash,
            genesis_membership,
            genesis_commitment,
            applied: Vec::new(),
            pending: None,
            evidence: Vec::new(),
            halt_before: None,
        }
    }

    pub fn applied(&self) -> &[AppliedEntry] {
        &self.applied
    }

    pub fn pending(&self) -> Option<&Authorization> {
        self.pending.as_ref()
    }

    pub fn evidence(&self) -> &[ConflictEvidence] {
        &self.evidence
    }

    pub fn halt_before(&self) -> Option<u64> {
        self.halt_before
    }

    /// The configuration commitment in force after applied history.
    pub fn effective_commitment(&self) -> Digest {
        self.applied
            .last()
            .map_or(self.genesis_commitment, |e| e.authorization.new_commitment)
    }

    /// How many applied authorizations are in force at `height`; replay
    /// selects rules by this number.
    pub fn rules_at(&self, height: u64) -> u64 {
        self.applied
            .iter()
            .filter(|e| e.authorization.activation_height <= height)
            .count() as u64
    }

    /// Membership that authenticates `sequence`, if it is known yet.
    fn authenticating_membership(&self, sequence: u64) -> Option<&Membership> {
        match sequence {
            0 => None,
            1 => Some(&self.genesis_membership),
            s => self
                .applied
                .get(usize::try_from(s - 2).ok()?)
                .map(|e| &e.membership_after),
        }
    }

    fn applied_digest(&self, sequence: u64) -> Option<Digest> {
        let i = usize::try_from(sequence.checked_sub(1)?).ok()?;
        self.applied.get(i).map(|e| e.authorization.body_digest)
    }

    /// Verify `auth` and, if it is usable, record it as pending.
    ///
    /// `notice_blocks` is the minimum distance between the signing deadline
    /// and H. Its value is unratified, so the caller must supply it.
    pub fn accept(
        &mut self,
        auth: &Authorization,
        verifier: &impl SignatureVerifier,
        chain: &impl CanonicalChain,
        notice_blocks: u64,
    ) -> Result<Acceptance, Refusal> {
        if auth.genesis_hash != self.genesis_hash {
            return Err(Refusal::WrongChain);
        }
        if auth.sequence == 0 {
            return Err(Refusal::BadSequence);
        }
        let next_sequence = self.applied.len() as u64 + 1;
        let Some(membership) = self.authenticating_membership(auth.sequence) else {
            return Ok(Acceptance::Deferred(Deferral::SequenceAhead {
                expected: next_sequence,
            }));
        };
        if auth.membership_commitment != membership.commitment {
            return Err(Refusal::MembershipMismatch);
        }
        verify_quorum(auth, membership, verifier)?;

        // Fully verified from here on: a different body at a known sequence is
        // a conflict, whatever its content says.
        if let Some(applied) = self.applied_digest(auth.sequence) {
            if applied == auth.body_digest {
                return Ok(Acceptance::AlreadyKnown {
                    sequence: auth.sequence,
                });
            }
            let first = self.applied[(auth.sequence - 1) as usize]
                .authorization
                .clone();
            return Ok(self.record_conflict(first, auth.clone()));
        }
        if let Some(previous) = self.evidence.iter().find(|e| e.sequence == auth.sequence) {
            if previous.first.body_digest == auth.body_digest
                || previous.second.body_digest == auth.body_digest
            {
                return Ok(Acceptance::AlreadyKnown {
                    sequence: auth.sequence,
                });
            }
            let first = previous.first.clone();
            return Ok(self.record_conflict(first, auth.clone()));
        }
        if let Some(pending) = self.pending.as_ref() {
            if pending.sequence == auth.sequence {
                if pending.body_digest == auth.body_digest {
                    return Ok(Acceptance::AlreadyKnown {
                        sequence: auth.sequence,
                    });
                }
                let first = pending.clone();
                self.pending = None;
                return Ok(self.record_conflict(first, auth.clone()));
            }
        }

        // Content checks for the next sequence.
        let expected_previous = match auth.sequence {
            1 => [0u8; 32],
            s => self.applied_digest(s - 1).ok_or(Refusal::BadChaining)?,
        };
        if auth.previous_digest != expected_previous {
            return Err(Refusal::BadChaining);
        }
        if auth.old_commitment != self.effective_commitment() {
            return Err(Refusal::CommitmentMismatch);
        }
        let latest_deadline = auth
            .activation_height
            .checked_sub(notice_blocks)
            .ok_or(Refusal::BadOrdering)?;
        let after_previous = self
            .applied
            .last()
            .is_none_or(|e| e.authorization.activation_height < auth.activation_height);
        if !(auth.checkpoint.height < auth.signing_deadline
            && auth.signing_deadline <= latest_deadline
            && after_previous)
        {
            return Err(Refusal::BadOrdering);
        }
        let head = chain.head_height();
        if auth.checkpoint.height > head {
            return Ok(Acceptance::Deferred(Deferral::CheckpointAhead {
                checkpoint: auth.checkpoint.height,
                head,
            }));
        }
        if chain.canonical_hash(auth.checkpoint.height) != Some(auth.checkpoint.hash) {
            return Err(Refusal::CheckpointNotCanonical);
        }

        self.pending = Some(auth.clone());
        if head >= auth.activation_height {
            Ok(Acceptance::AcceptedPastActivation {
                sequence: auth.sequence,
                activation_height: auth.activation_height,
            })
        } else {
            Ok(Acceptance::Accepted {
                sequence: auth.sequence,
                activation_height: auth.activation_height,
            })
        }
    }

    fn record_conflict(&mut self, first: Authorization, second: Authorization) -> Acceptance {
        let halt = first.activation_height.min(second.activation_height);
        let halt_before = self.halt_before.map_or(halt, |h| h.min(halt));
        self.halt_before = Some(halt_before);
        let sequence = second.sequence;
        self.evidence.push(ConflictEvidence {
            sequence,
            first,
            second,
            halt_before: halt,
        });
        Acceptance::Conflict {
            sequence,
            halt_before,
        }
    }

    /// Pure decision taken before processing block `next_height`.
    pub fn block_action(
        &self,
        next_height: u64,
        supports: impl Fn(&HandlerId) -> bool,
    ) -> BlockAction {
        if let Some(halt_before) = self.halt_before {
            if next_height >= halt_before {
                return BlockAction::Halt(HaltReason::ConflictingAuthorizations { halt_before });
            }
        }
        if let Some(p) = self.pending.as_ref() {
            if next_height == p.activation_height {
                return if supports(&p.handler) {
                    BlockAction::RunHandlerOnce {
                        sequence: p.sequence,
                        handler: p.handler.clone(),
                    }
                } else {
                    BlockAction::Halt(HaltReason::UpgradeNeeded {
                        sequence: p.sequence,
                        handler: p.handler.clone(),
                    })
                };
            }
            if next_height > p.activation_height {
                return BlockAction::Halt(HaltReason::MissedActivation {
                    sequence: p.sequence,
                    activation_height: p.activation_height,
                });
            }
        }
        BlockAction::Proceed
    }

    /// Record the pending authorization as applied (inside block H's batch).
    ///
    /// G2-d: the membership may change only if certified finality is active.
    pub fn on_applied(
        &mut self,
        sequence: u64,
        membership_after: Membership,
        certified_finality_active: bool,
    ) -> Result<(), ApplyError> {
        let pending = self
            .pending
            .as_ref()
            .filter(|p| p.sequence == sequence)
            .ok_or(ApplyError::NotPending)?;
        if self
            .halt_before
            .is_some_and(|h| pending.activation_height >= h)
        {
            return Err(ApplyError::Halted);
        }
        let current = self
            .authenticating_membership(sequence)
            .ok_or(ApplyError::NotPending)?;
        check_membership_transition(
            &current.commitment,
            &membership_after.commitment,
            certified_finality_active,
        )?;
        let authorization = self.pending.take().ok_or(ApplyError::NotPending)?;
        self.applied.push(AppliedEntry {
            authorization,
            membership_after,
        });
        Ok(())
    }

    /// Compare a peer's announcement with our applied history. Never changes
    /// state, never authorizes, never halts.
    pub fn assess_hint(&self, hint: &Hint) -> HintAssessment {
        if hint.genesis_hash != self.genesis_hash {
            return HintAssessment::OtherChain;
        }
        let ours = self.applied.len() as u64;
        let tip_at = |count: u64| -> Digest {
            if count == 0 {
                [0u8; 32]
            } else {
                self.applied[(count - 1) as usize].authorization.body_digest
            }
        };
        match hint.applied_count.cmp(&ours) {
            std::cmp::Ordering::Equal if hint.applied_tip == tip_at(ours) => HintAssessment::InSync,
            std::cmp::Ordering::Less if hint.applied_tip == tip_at(hint.applied_count) => {
                HintAssessment::PeerBehind
            }
            std::cmp::Ordering::Greater => HintAssessment::PeerAhead,
            _ => HintAssessment::Diverged,
        }
    }

    /// Our own announcement, built only from verified authorizations.
    pub fn local_hint(&self) -> Hint {
        Hint {
            genesis_hash: self.genesis_hash,
            applied_count: self.applied.len() as u64,
            applied_tip: self
                .applied
                .last()
                .map_or([0u8; 32], |e| e.authorization.body_digest),
            next: self.pending.as_ref().map(|p| HintNext {
                sequence: p.sequence,
                digest: p.body_digest,
                activation_height: p.activation_height,
            }),
        }
    }
}

fn verify_quorum(
    auth: &Authorization,
    membership: &Membership,
    verifier: &impl SignatureVerifier,
) -> Result<(), Refusal> {
    let mut previous: Option<u32> = None;
    for s in &auth.signatures {
        if previous.is_some_and(|p| s.index <= p) {
            return Err(Refusal::NonAscendingIndices);
        }
        previous = Some(s.index);
        let key = membership
            .members
            .get(s.index as usize)
            .ok_or(Refusal::IndexOutOfRange { index: s.index })?;
        if !verifier.verify(key, &auth.body_digest, &s.signature) {
            return Err(Refusal::BadSignature { index: s.index });
        }
    }
    let needed = membership.quorum();
    if auth.signatures.len() < needed {
        return Err(Refusal::NoQuorum {
            valid: auth.signatures.len(),
            needed,
        });
    }
    Ok(())
}

//! Authenticated execution context + epoch membership snapshot (draft §1.3, §4.1,
//! §8.2, §11).
//!
//! #164 deferred actor binding to #127; it cannot be deferred again. Every beacon
//! transition takes an [`ExecContext`] carrying the **authenticated tx signer**, the
//! **epoch membership snapshot** (the canonical 0-based index order, §1.3/§4.1), the
//! block height + phase, and the chain/epoch it runs under. The transitions enforce
//! that the signer *is* the actor the carrier names (registrant ↔ `j`, dealer ↔ `i`,
//! complainant ↔ `j`, partial signer ↔ `j`), that every index is a valid membership
//! index (`< n`), that chain/epoch match, and that the operation is in its allowed
//! phase / cutoff window. None of these are decodable from the carrier bytes alone —
//! they need the authenticated envelope + the snapshot, which is exactly what this
//! context supplies.

use std::collections::BTreeMap;

/// A validator's stable identity within an epoch (the authenticated tx signer). A
/// 32-byte opaque id — the executor maps its account/authority identity onto this;
/// the runtime treats it as an opaque, orderable key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ValidatorId(pub [u8; 32]);

impl ValidatorId {
    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Failure building an [`EpochMembership`] snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    /// The snapshot was empty — a beacon epoch needs `n ≥ 1` members.
    #[error("empty membership snapshot")]
    Empty,
    /// A validator identity appeared twice — the index order must be a bijection.
    #[error("duplicate validator identity in membership snapshot")]
    Duplicate,
}

/// The canonical epoch membership snapshot (draft §1.3, §4.1): the ordered set of
/// participant identities whose position defines the 0-based membership index `j`
/// and thus the scalar evaluation point `x_j = j + 1` (§3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochMembership {
    members: Vec<ValidatorId>,
    index_of: BTreeMap<ValidatorId, u32>,
}

impl EpochMembership {
    /// Build a snapshot from the canonical index order. Rejects an empty snapshot or
    /// any duplicate identity (the index order must be a bijection).
    pub fn new(members: Vec<ValidatorId>) -> Result<Self, MembershipError> {
        if members.is_empty() {
            return Err(MembershipError::Empty);
        }
        let mut index_of = BTreeMap::new();
        for (i, m) in members.iter().enumerate() {
            if index_of.insert(*m, i as u32).is_some() {
                return Err(MembershipError::Duplicate);
            }
        }
        Ok(EpochMembership { members, index_of })
    }

    /// The committee size `n = |members|`.
    pub fn n(&self) -> u32 {
        self.members.len() as u32
    }

    /// The 0-based membership index of `id`, if it is a member.
    pub fn index_of(&self, id: &ValidatorId) -> Option<u32> {
        self.index_of.get(id).copied()
    }

    /// Whether `idx` is a valid membership index (`idx < n`).
    pub fn contains_index(&self, idx: u32) -> bool {
        idx < self.n()
    }

    /// The identity at membership index `idx`, if in range.
    pub fn id_at(&self, idx: u32) -> Option<ValidatorId> {
        self.members.get(idx as usize).copied()
    }

    /// The ordered member identities (index order). Used to persist the fixed epoch
    /// snapshot.
    pub fn members(&self) -> &[ValidatorId] {
        &self.members
    }
}

/// The within-epoch lifecycle phase of a beacon operation, in ratified STRICT PHASE
/// SEPARATION order (draft §11.3, §6.5, §8). Each op kind is valid ONLY in its own
/// window; the executor derives the block's phase from the authoritative
/// `BeaconSchedule` and threads it here. A between-windows gap is represented as
/// `None` in [`ExecContext::phase`], and admits no operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconPhase {
    /// K-rotate encryption-key registration window (`RegisterBeaconKey`).
    KeyRegistration,
    /// DKG deal window (`DkgDeal`).
    Deal,
    /// Complaint-adjudication window (`DkgComplaint`).
    Complaint,
    /// Threshold-signing / output window (`BeaconPartial`, `BeaconFinalize`).
    Signing,
}

/// The authenticated execution context threaded into every beacon transition.
///
/// `signer` is the **authenticated** tx signer (from the envelope, not the payload);
/// `tx_ref` is the hash of that signed envelope; `membership` is the epoch snapshot;
/// `phase`, `block_height`, `chain_id`, and `epoch` come from the executing block +
/// the authoritative `BeaconSchedule`. `phase` is `None` in a between-windows gap,
/// where every operation is rejected.
#[derive(Clone, Copy, Debug)]
pub struct ExecContext<'a> {
    /// The authenticated tx signer's epoch identity.
    pub signer: ValidatorId,
    /// The **authenticated reference** to the signed transaction envelope carrying
    /// this operation — its 32-byte hash. Retained in equivocation evidence so a
    /// stored conflicting record is individually attributable to a signed tx (the
    /// evidence references the envelope, not merely an unsigned payload). The
    /// executor supplies the real `SignedTransaction` hash; the runtime treats it as
    /// an opaque authenticated handle.
    pub tx_ref: [u8; 32],
    /// The chain id the transaction binds.
    pub chain_id: u64,
    /// The beacon epoch the transaction targets.
    pub epoch: u64,
    /// The height of the executing block.
    pub block_height: u64,
    /// The block's within-epoch phase derived from the authoritative schedule, or
    /// `None` for a between-windows gap (no operation is valid).
    pub phase: Option<BeaconPhase>,
    /// The epoch membership snapshot.
    pub membership: &'a EpochMembership,
}

/// An authenticated-binding / membership / phase / cutoff violation (draft §1.3,
/// §8.2, §11) — the actor-binding checks #164 could not perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContextError {
    /// The carrier's `chain_id` does not equal the context's.
    #[error("chain_id mismatch: carrier != context")]
    ChainIdMismatch,
    /// The carrier's `epoch` does not equal the context's.
    #[error("epoch mismatch: carrier != context")]
    EpochMismatch,
    /// The operation's phase does not match the enclosing payload phase.
    #[error("phase mismatch: operation is not valid in this payload phase")]
    PhaseMismatch,
    /// The authenticated signer is not a member of the epoch snapshot.
    #[error("signer is not a member of the epoch")]
    SignerNotMember,
    /// The authenticated signer's membership index does not equal the actor index
    /// the carrier claims (registrant/dealer/complainant/partial-signer).
    #[error("signer identity does not match the claimed actor index")]
    ActorIndexMismatch,
    /// A carrier index (dealer/recipient/witness) is out of range (`>= n`).
    #[error("index out of membership range (>= n)")]
    IndexOutOfRange,
}

impl ExecContext<'_> {
    /// Enforce the chain/epoch binding common to every carrier.
    pub(crate) fn check_chain_epoch(&self, chain_id: u64, epoch: u64) -> Result<(), ContextError> {
        if chain_id != self.chain_id {
            return Err(ContextError::ChainIdMismatch);
        }
        if epoch != self.epoch {
            return Err(ContextError::EpochMismatch);
        }
        Ok(())
    }

    /// Enforce that the authenticated signer occupies membership index
    /// `claimed_index` (registrant ↔ j, dealer ↔ i, complainant ↔ j, signer ↔ j).
    pub(crate) fn check_signer_is(&self, claimed_index: u32) -> Result<(), ContextError> {
        let signer_index = self
            .membership
            .index_of(&self.signer)
            .ok_or(ContextError::SignerNotMember)?;
        if signer_index != claimed_index {
            return Err(ContextError::ActorIndexMismatch);
        }
        Ok(())
    }

    /// Enforce that `idx` is a valid membership index (`< n`).
    pub(crate) fn check_index(&self, idx: u32) -> Result<(), ContextError> {
        if self.membership.contains_index(idx) {
            Ok(())
        } else {
            Err(ContextError::IndexOutOfRange)
        }
    }

    /// Enforce the block's phase equals `expected` (a between-windows gap, `None`,
    /// rejects every operation).
    pub(crate) fn check_phase(&self, expected: BeaconPhase) -> Result<(), ContextError> {
        if self.phase == Some(expected) {
            Ok(())
        } else {
            Err(ContextError::PhaseMismatch)
        }
    }
}

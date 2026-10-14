//! C1 dormant compute-pool state (issue #130) — PURE IN-MEMORY model.
//!
//! This module carries ONLY the ratified, wire-independent *structure* of the
//! compute pool as a pure in-memory model: the internal (non-wire) data model,
//! the deterministic scheduler inputs + canonical ordering, the
//! capacity/exposure relations, the write-once accepted-leaf and
//! unique-entitlement enforcement, and the lifecycle. Everything here is
//! **dormant**: the `compute_pool_enabled_from_height` gate stays `None`, no
//! `TxPayload` ordinal is added, and no consensus bytes are chosen.
//!
//! ## Why in-memory only (no persistence here)
//!
//! This module holds state in typed maps keyed by typed tuples (`WorkItemKey`,
//! `UnitKey`), never serialized bytes. The identity of accepted leaves /
//! assignments is the ratified composite `(job_id, unit_id, generation)`.
//! Persistence, the record codec and the composite key bytes live in
//! [`crate::compute_pool_store`]; their stored encoding is what the C1 state
//! digest commits once the gate opens (#215, codec option (a)).
//!
//! ## Deliberate typed boundaries (unresolved layouts — NOT chosen here)
//!
//! * [`Beacon`], [`Score`], [`Dic`] and the id newtypes ([`JobId`], …) are
//!   **opaque 32-byte values**. The module uses them only as typed map/compare
//!   keys; their *derivation/preimage* is owned by the frozen-wire spec.
//! * [`AssignmentScorer`] is the seam for the ratified assignment score
//!   `blake3::derive_key("OMNINODE-POOL-ASSIGN:v1:", beacon ‖ job_id ‖ unit_id
//!   ‖ generation ‖ payment_addr ‖ offer_bond_id)`. The **preimage byte layout
//!   is intentionally not implemented here** (it binds BR1 beacon bytes and the
//!   unresolved id encodings). C1 implements only the deterministic, proposer-
//!   independent *selection* over scores.
//! * [`DerivedInputCommitmentScheme`] is the seam for `DerivedInputCommitmentV1`.
//!   C1 implements the ratified *same-predecessor-manifest* structural check but
//!   not the DIC hash preimage.
//! * B0 numeric params (`B_offer`, `max_generations`, `max_retention_files_per_job`,
//!   reimbursement amounts, …) are **function parameters**, never baked
//!   constants. The ratified formulas ([`compute_job_max_retention_files`],
//!   [`compute_requester_debit`]) are implemented; the numbers are injected.
//!
//! ## Retention kernels (issue #129)
//!
//! [`retention_satisfied`], [`retention_tracker_dirty`], [`RecomputeCursor`]
//! and [`RetentionReverseIndex`] are dormant pieces of C-RETENTION; the
//! per-chunk count is [`crate::storage_metadata::active_replica_counts_from`].
//! Nothing calls them, and every bound is an argument. Two #129 questions are
//! open and none of these pieces answers them: what `height` means for a
//! replica count (D-H) and which assignment epochs count (D-E). Whatever
//! depends on them (the epochs and archives a tracker depends on, and the
//! tracker key's epoch commitment) is supplied by the caller.

use std::collections::{BTreeMap, BTreeSet};

use sumchain_primitives::{Address, Hash};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Opaque identifiers / values (typed boundaries).
//
// Each wraps 32 opaque bytes. Using an opaque id as a typed map/compare key does
// NOT commit to how the id is derived from wire data — that derivation
// (preimage / byte layout) is owned by the not-yet-frozen wire spec. These
// types intentionally derive NO serialization: the module chooses no bytes.
// ---------------------------------------------------------------------------

macro_rules! opaque_id32 {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap already-canonical id bytes. C1 never derives these bytes;
            /// the derivation is a typed boundary owned by the frozen-wire spec.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw id bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "(0x{})"), hex::encode(self.0))
            }
        }
    };
}

opaque_id32!(
    /// Job identifier. Opaque; derivation owned by the frozen-wire spec.
    JobId
);
opaque_id32!(
    /// Work-unit identifier within a job's graph.
    UnitId
);
opaque_id32!(
    /// Bonded-offer lock handle (`B_offer`).
    OfferBondId
);
opaque_id32!(
    /// Commit-bond lock handle (`B_commit`), taken at accept.
    CommitBondId
);
opaque_id32!(
    /// Entitlement (reimbursement) record identifier — must be unique.
    EntitlementId
);
opaque_id32!(
    /// Output-slot identifier referenced by a downstream required input.
    SlotId
);
opaque_id32!(
    /// The unbiasable chained beacon value for a given `(epoch, round)`.
    ///
    /// BR1 (#127) owns the beacon's derivation and byte encoding. C1 treats it
    /// as an opaque value and only distinguishes *defined* (`Some`) from
    /// *undefined* (`None` → [`ScheduleOutcome::Halted`]).
    Beacon
);
opaque_id32!(
    /// A candidate's assignment score. Compared lexicographically over its raw
    /// bytes (matches the rendezvous-KDF precedent). Produced by an
    /// [`AssignmentScorer`]; the preimage is a typed boundary.
    Score
);
opaque_id32!(
    /// `DerivedInputCommitmentV1` value. Produced by a
    /// [`DerivedInputCommitmentScheme`]; the preimage is a typed boundary.
    Dic
);
opaque_id32!(
    /// A retention tracker's key (#129 scope (3)). Its preimage includes
    /// `file_assignment_epoch_commitment`, whose definition depends on the
    /// open epoch question (D-E), so no derivation exists here. It is used
    /// only as an ordered key: the reverse indexes and the recompute order.
    TrackerKey
);

// ---------------------------------------------------------------------------
// Composite typed identity keys.
//
// These are typed tuples (Rust structs with derived `Ord`), NOT invented byte
// layouts. Ordering is field-wise structural comparison used only for in-memory
// `BTreeMap` placement — no serialized preimage is chosen.
// ---------------------------------------------------------------------------

/// Identity of a graph node: `(job_id, unit_id)`. A unit belongs to exactly one
/// job; keying by the pair avoids cross-job `unit_id` collisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitKey {
    pub job_id: JobId,
    pub unit_id: UnitId,
}

impl UnitKey {
    pub fn new(job_id: JobId, unit_id: UnitId) -> Self {
        Self { job_id, unit_id }
    }
}

/// Ratified composite identity of an accepted leaf / assignment:
/// `(job_id, unit_id, generation)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkItemKey {
    pub job_id: JobId,
    pub unit_id: UnitId,
    pub generation: u64,
}

impl WorkItemKey {
    pub fn new(job_id: JobId, unit_id: UnitId, generation: u64) -> Self {
        Self {
            job_id,
            unit_id,
            generation,
        }
    }

    /// The `(job_id, unit_id)` graph-node key this work item belongs to.
    pub fn unit_key(&self) -> UnitKey {
        UnitKey {
            job_id: self.job_id,
            unit_id: self.unit_id,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors (typed; never receipt-code integers).
// ---------------------------------------------------------------------------

/// C1 business/enforcement errors. These are internal typed errors — NOT wire
/// receipt codes (issue #130 mentions `Failed(430)`; the numeric code is a
/// frozen-wire concern and is deliberately not encoded here).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PoolError {
    /// A checked-arithmetic step overflowed (`u128`). The `&'static str` names
    /// the relation so the exposure/retention bounds fail closed, never wrap.
    #[error("arithmetic overflow in {0}")]
    Overflow(&'static str),

    /// Capacity reservation would exceed the offer: `reserved + req > offered`.
    #[error("capacity exceeded: reserved+req {requested} > offered {offered}")]
    CapacityExceeded { offered: u128, requested: u128 },

    /// `job_max_retention_files` exceeds the (injected) per-job cap.
    #[error("retention files {files} exceed cap {cap}")]
    RetentionCapExceeded { files: u128, cap: u128 },

    /// Requester debit (Q + allowance incl. global reassign reserve) exceeds
    /// available funds.
    #[error("underfunded: debit {debit} > available {available}")]
    Underfunded { debit: u128, available: u128 },

    /// Write-once accepted-leaf: a leaf already exists for this work item.
    #[error("accepted leaf already exists for this (job, unit, generation)")]
    LeafAlreadyAccepted,

    /// Entitlement ids must be unique.
    #[error("duplicate entitlement id")]
    DuplicateEntitlement,

    /// One active offer per identity (enforced from model state).
    #[error("identity already has an active bonded offer")]
    DuplicateActiveOffer,

    /// Duplicate offer-bond id.
    #[error("offer-bond id already published")]
    DuplicateOffer,

    /// A job with this id already exists.
    #[error("job id already exists")]
    DuplicateJob,

    /// A unit id is repeated within a job (batch or already present).
    #[error("duplicate unit id within job")]
    DuplicateUnitId,

    /// Illegal unit-state transition.
    #[error("invalid unit-state transition {from:?} -> {to:?}")]
    InvalidTransition { from: UnitState, to: UnitState },

    /// Downstream became eligible before all predecessors are `InputReady`.
    #[error("predecessors are not all InputReady")]
    PredecessorsNotReady,

    /// Two required inputs from the SAME predecessor disagree on the
    /// predecessor output-manifest root.
    #[error("same-predecessor manifest mismatch")]
    ManifestMismatch,

    /// A `job_id` was referenced by a unit that does not belong to it.
    #[error("work unit does not belong to the job")]
    UnitJobMismatch,

    /// Illegal job-state transition.
    #[error("invalid job-state transition {from:?} -> {to:?}")]
    InvalidJobTransition { from: JobState, to: JobState },

    /// A referenced work unit is not present in the model.
    #[error("unknown work unit")]
    UnknownUnit,

    /// A referenced job is not present in the model.
    #[error("unknown job")]
    UnknownJob,

    /// The retention tracker is already in the reverse index.
    #[error("retention tracker already indexed")]
    RetentionTrackerAlreadyIndexed,

    /// The retention tracker is not in the reverse index.
    #[error("unknown retention tracker")]
    UnknownRetentionTracker,

    /// A retention tracker must be indexed under at least one assignment
    /// epoch of its file, or no file event could find it.
    #[error("retention tracker has no file epoch to index")]
    RetentionTrackerWithoutEpoch,

    /// The job's reverse-index entries would exceed the injected
    /// `max_reverse_index_entries`.
    #[error("reverse-index entries {entries} for the job would exceed cap {cap}")]
    ReverseIndexCapExceeded { entries: u64, cap: u64 },
}

/// C1 result alias.
pub type PoolResult<T> = Result<T, PoolError>;

// ---------------------------------------------------------------------------
// Lifecycle.
// ---------------------------------------------------------------------------

/// Work-unit lifecycle states (issue #130 state machine).
///
/// `Blocked → Eligible → Assigned → Accepted`, with `Assigned → Reassignable`
/// on decline/expire/timeout (Decision-A: reputation/suspend, never slash), and
/// `AssignmentHalted` when the beacon is undefined (safe halt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitState {
    /// Predecessors not all `InputReady`.
    Blocked,
    /// All predecessors `InputReady`; awaiting assignment.
    Eligible,
    /// A winner has been selected (not yet accepted).
    Assigned,
    /// The winner accepted; a write-once leaf exists.
    Accepted,
    /// Timeout/decline/expire returned the unit to the assignable pool.
    Reassignable,
    /// Safe halt: the beacon for the collection round is undefined.
    AssignmentHalted,
}

impl UnitState {
    /// Terminal-ish states hold no pending scheduler obligation.
    pub fn is_settled(self) -> bool {
        matches!(self, UnitState::Accepted | UnitState::AssignmentHalted)
    }

    /// Validate a lifecycle transition. Returns the new state on success,
    /// [`PoolError::InvalidTransition`] otherwise. This is the *structure*; the
    /// guards that decide *when* to call it (predecessor readiness, beacon
    /// definedness) live in the scheduler/eligibility helpers.
    pub fn transition(self, to: UnitState) -> PoolResult<UnitState> {
        use UnitState::*;
        let ok = matches!(
            (self, to),
            (Blocked, Eligible)
                | (Eligible, Assigned)
                | (Eligible, AssignmentHalted)
                | (Assigned, Accepted)
                | (Assigned, Reassignable)
                | (Assigned, AssignmentHalted)
                | (Reassignable, Assigned)
                | (Reassignable, AssignmentHalted)
        );
        if ok {
            Ok(to)
        } else {
            Err(PoolError::InvalidTransition { from: self, to })
        }
    }
}

// ---------------------------------------------------------------------------
// Internal data structures (non-wire, in-memory).
// ---------------------------------------------------------------------------

/// A compute-pool job (requester-owned). `r_job` and `job_max_retention_files`
/// are snapshotted at creation from injected values (never baked constants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub job_id: JobId,
    pub requester: Address,
    /// `R_job` snapshotted from `ChainParams::assignment_replication_factor`
    /// at `CreateComputePoolJob` (value supplied by the caller).
    pub r_job: u32,
    /// Ratified retention-file bound computed at creation and snapshotted.
    pub job_max_retention_files: u128,
    /// Total requester debit `Q + allowance` (incl. the global reassign reserve).
    pub requester_debit: u128,
    pub state: JobState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Open,
    Cancelled,
    Halted,
}

impl JobState {
    /// Validate a job-state transition (structure only; the economic effects of
    /// cancellation/halt — refunds, bond releases — are B0/settlement concerns
    /// deliberately out of scope here). A job leaves `Open` exactly once.
    pub fn transition(self, to: JobState) -> PoolResult<JobState> {
        use JobState::*;
        let ok = matches!((self, to), (Open, Cancelled) | (Open, Halted));
        if ok {
            Ok(to)
        } else {
            Err(PoolError::InvalidJobTransition { from: self, to })
        }
    }
}

/// A required input a downstream unit consumes from a predecessor's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredInput {
    pub predecessor: UnitId,
    pub required_output_slot_id: SlotId,
    /// The predecessor output-manifest root this input binds to. All inputs
    /// sharing a predecessor MUST agree on this (same-predecessor-manifest).
    pub pred_output_manifest_root: Hash,
    pub required_slot_state_object_root: Hash,
}

/// A node in a job's dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkUnit {
    pub job_id: JobId,
    pub unit_id: UnitId,
    /// Predecessor unit ids (DAG edges). Iterated in slice order — deterministic.
    pub predecessors: Vec<UnitId>,
    pub required_inputs: Vec<RequiredInput>,
    pub generation: u64,
    pub state: UnitState,
}

impl WorkUnit {
    /// A predecessor is `InputReady` once it is `Accepted` (its write-once leaf
    /// exists). Downstream eligibility requires ALL predecessors ready.
    pub fn all_predecessors_ready<F>(&self, state_of: F) -> bool
    where
        F: Fn(&UnitId) -> Option<UnitState>,
    {
        self.predecessors
            .iter()
            .all(|p| state_of(p) == Some(UnitState::Accepted))
    }

    /// Structural `DerivedInputCommitmentV1` guard: every group of required
    /// inputs that share a predecessor must reference the SAME predecessor
    /// output-manifest root. Independent of the DIC hash preimage (a typed
    /// boundary), this catches linear/fan-in/fan-out (incl. residual + KV)
    /// manifest disagreement.
    pub fn validate_same_predecessor_manifest(&self) -> PoolResult<()> {
        let mut seen: BTreeMap<&UnitId, &Hash> = BTreeMap::new();
        for input in &self.required_inputs {
            match seen.get(&input.predecessor) {
                Some(root) if **root != input.pred_output_manifest_root => {
                    return Err(PoolError::ManifestMismatch);
                }
                Some(_) => {}
                None => {
                    seen.insert(&input.predecessor, &input.pred_output_manifest_root);
                }
            }
        }
        Ok(())
    }
}

/// A capacity offer bonded BEFORE the beacon exists (address-grind is bounded by
/// `K * B_offer`). `offered` bytes cap what may be reserved against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondedOffer {
    pub offer_bond_id: OfferBondId,
    /// The provider identity. At most one active offer per identity.
    pub identity: Address,
    /// Payment address (also the scheduler tie-break key).
    pub payment_addr: Address,
    /// Offered capacity in bytes.
    pub offered_bytes: u128,
    /// Chained offer sequence for this identity.
    pub offer_seq: u64,
    /// The bond amount `B_offer` locked (injected value, never baked).
    pub bond_locked: u128,
    pub active: bool,
}

/// A write-once accepted leaf: the immutable record that a work item's
/// assignment was accepted. Written exactly once per `(job, unit, generation)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedLeaf {
    pub key: WorkItemKey,
    pub offer_bond_id: OfferBondId,
    pub commit_bond_id: CommitBondId,
    pub accepted_bytes: u128,
}

/// Capacity reservation ledger for one offer. Invariant: `reserved ≤ offered`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub offer_bond_id: OfferBondId,
    pub offered: u128,
    pub reserved: u128,
}

impl Reservation {
    pub fn new(offer_bond_id: OfferBondId, offered: u128) -> Self {
        Self {
            offer_bond_id,
            offered,
            reserved: 0,
        }
    }

    /// Ratified capacity relation: reserve `req` bytes iff
    /// `reserved + req ≤ offered`, else [`PoolError::CapacityExceeded`].
    /// Checked add — never wraps.
    pub fn try_reserve(&mut self, req: u128) -> PoolResult<()> {
        let requested = self
            .reserved
            .checked_add(req)
            .ok_or(PoolError::Overflow("reservation"))?;
        if requested > self.offered {
            return Err(PoolError::CapacityExceeded {
                offered: self.offered,
                requested,
            });
        }
        self.reserved = requested;
        Ok(())
    }

    /// Release previously-reserved bytes (e.g. on reassign). Saturating: never
    /// underflows below zero.
    pub fn release(&mut self, req: u128) {
        self.reserved = self.reserved.saturating_sub(req);
    }

    /// The consensus capacity invariant.
    pub fn invariant_holds(&self) -> bool {
        self.reserved <= self.offered
    }
}

/// Assignment-index entry: the winner selected for a work item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentIndexEntry {
    pub key: WorkItemKey,
    pub winner_offer_bond_id: OfferBondId,
    pub winner_payment_addr: Address,
}

/// The kind of reimbursement an entitlement encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementKind {
    AcceptReimb,
    ReassignReimb,
    ReprovisionReimb,
}

/// A reimbursement entitlement. `entitlement_id` must be globally unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementRecord {
    pub entitlement_id: EntitlementId,
    pub beneficiary: Address,
    pub kind: EntitlementKind,
    /// Injected reimbursement amount (never a baked constant).
    pub amount: u128,
}

// ---------------------------------------------------------------------------
// Ratified pure relations (structure implemented; numeric params injected).
// ---------------------------------------------------------------------------

/// Per-unit retention-sizing inputs. `slots` counts the unit's extra retained
/// artifacts (e.g. KV / residual slots). Kept minimal and injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitSizing {
    pub slots: u64,
}

/// Ratified retention-file count:
/// `job_max_retention_files = Σ_units (1 + slots) * max_generations + final`.
///
/// `max_generations` and `final_files` are injected B0 params (never baked).
/// Fully checked `u128`; returns `None` on overflow so callers fail closed.
pub fn compute_job_max_retention_files(
    units: &[UnitSizing],
    max_generations: u64,
    final_files: u64,
) -> Option<u128> {
    let mut acc: u128 = 0;
    for u in units {
        let per_unit = (u.slots as u128)
            .checked_add(1)?
            .checked_mul(max_generations as u128)?;
        acc = acc.checked_add(per_unit)?;
    }
    acc.checked_add(final_files as u128)
}

/// Reject a job whose retention-file count exceeds the injected per-job cap
/// (`max_retention_files_per_job`). This is retention relation 5 of issue #129.
/// Relations 1–4 are checked by
/// [`crate::compute_pool_retention::validate_retention_relations`].
pub fn validate_retention_within_cap(files: u128, cap: u128) -> PoolResult<()> {
    if files > cap {
        Err(PoolError::RetentionCapExceeded { files, cap })
    } else {
        Ok(())
    }
}

/// #129 scope (7): `RetentionSatisfied(tracker) := not Dirty AND
/// since.is_some() AND head >= since + output_availability_blocks`.
///
/// `dirty` is [`retention_tracker_dirty`] evaluated at the same read, `since`
/// is the tracker's `coverage_satisfied_since_height`, and
/// `output_availability_blocks` is injected; relations 1 and 2, checked where
/// the value is declared, bound it from below. The addition is checked: if
/// `since + output_availability_blocks` overflows `u64`, the tracker is not
/// satisfied. Pure; C4's settlement revalidation is separate.
pub fn retention_satisfied(
    dirty: bool,
    since: Option<u64>,
    head: u64,
    output_availability_blocks: u64,
) -> bool {
    !dirty
        && since
            .and_then(|since| since.checked_add(output_availability_blocks))
            .is_some_and(|matures_at| head >= matures_at)
}

/// #129 scope (4): whether a tracker is Dirty at this read.
///
/// Not Dirty iff both hold:
/// * every recorded `(archive, generation)` pair matches
///   `current_generation(archive)`; and
/// * the recorded archives are exactly the set `recomputed_dependencies`.
///
/// `recomputed_dependencies` is the tracker's dependency set recomputed by
/// the caller at this read. Which archives belong in it depends on the open
/// epoch question (D-E), so it is an argument; duplicates in it are one
/// archive. `current_generation` is the per-archive `status_generation` read,
/// which #129 scope (1) adds and this does not.
///
/// Fails closed. An archive with no generation (`None`) and a recorded list
/// that names one archive twice both make the tracker Dirty, since neither
/// can come from a valid recompute.
pub fn retention_tracker_dirty<G>(
    recorded: &[(Address, u64)],
    recomputed_dependencies: &[Address],
    current_generation: G,
) -> bool
where
    G: Fn(&Address) -> Option<u64>,
{
    let mut recorded_archives = BTreeSet::new();
    for (archive, generation) in recorded {
        if !recorded_archives.insert(*archive) {
            return true;
        }
        if current_generation(archive) != Some(*generation) {
            return true;
        }
    }
    let recomputed: BTreeSet<Address> = recomputed_dependencies.iter().copied().collect();
    recorded_archives != recomputed
}

/// Requester-exposure inputs. All values injected from B0 params / the job
/// request; none are baked here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposureInputs {
    /// Base job quote `Q`.
    pub q: u128,
    /// Reprovision allowance derived from `max_reprovision_attempts_total`.
    pub reprovision_allowance: u128,
    /// The job's retention-file bound (from [`compute_job_max_retention_files`]).
    pub job_max_retention_files: u128,
    /// `max_reassignments_per_file`.
    pub max_reassignments_per_file: u128,
    /// Per-reassignment reimbursement `reassign_reimb`.
    pub reassign_reimb: u128,
}

/// Ratified requester debit / exposure bound:
/// `requester_debit = Q + reprovision_allowance
///   + (job_max_retention_files * max_reassignments_per_file * reassign_reimb)`.
///
/// The last term is the globally-bounded reassignment reserve. Fully checked
/// `u128`; `None` on overflow so exposure is never understated by wraparound.
pub fn compute_requester_debit(inp: &ExposureInputs) -> Option<u128> {
    let reassign_attempts_total = inp
        .job_max_retention_files
        .checked_mul(inp.max_reassignments_per_file)?;
    let reassign_reserve = reassign_attempts_total.checked_mul(inp.reassign_reimb)?;
    let allowance = inp.reprovision_allowance.checked_add(reassign_reserve)?;
    inp.q.checked_add(allowance)
}

/// Reject an underfunded requester (available funds < computed debit).
pub fn validate_funding(debit: u128, available: u128) -> PoolResult<()> {
    if debit > available {
        Err(PoolError::Underfunded { debit, available })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deterministic, proposer-independent scheduler.
// ---------------------------------------------------------------------------

/// The fields the ratified assignment score binds. The concrete preimage byte
/// layout is a typed boundary (see [`AssignmentScorer`]).
#[derive(Debug, Clone, Copy)]
pub struct ScoreContext<'a> {
    pub job_id: &'a JobId,
    pub unit_id: &'a UnitId,
    pub generation: u64,
    pub payment_addr: &'a Address,
    pub offer_bond_id: &'a OfferBondId,
}

/// Typed seam for the ratified assignment score
/// `blake3::derive_key("OMNINODE-POOL-ASSIGN:v1:", beacon ‖ job_id ‖ unit_id ‖
/// generation ‖ payment_addr ‖ offer_bond_id)`.
///
/// The **preimage byte layout is intentionally not chosen in C1** — it binds
/// BR1's beacon encoding and the unresolved id encodings. C1 depends only on
/// this being a *pure function of `(beacon, context)`* so that assignment is
/// proposer-independent. The concrete implementation lands with the frozen
/// wire/beacon spec.
pub trait AssignmentScorer {
    fn score(&self, beacon: &Beacon, ctx: &ScoreContext<'_>) -> Score;
}

/// BLAKE3 `derive_key` context for the ratified v1 assignment score (#130/#217 B8).
pub const ASSIGN_SCORE_CONTEXT: &str = "OMNINODE-POOL-ASSIGN:v1:";

/// The ratified v1 assignment scorer. Now byte-complete: BR1's `beacon_output` is
/// RATIFIED v1 (#223, on main) and the id/address encodings are fixed-width, so
/// the preimage is frozen. The score is a pure function of `(beacon, context)`,
/// hence proposer-independent:
///
/// ```text
/// score = BLAKE3::derive_key(
///     "OMNINODE-POOL-ASSIGN:v1:",
///     beacon[32] ‖ job_id[32] ‖ unit_id[32] ‖ generation(u64 LE) ‖
///     payment_addr[20] ‖ offer_bond_id[32])
/// ```
///
/// `beacon` is BR1's `beacon_output` (opaque 32 bytes to C1). DORMANT: reached
/// only on the (gate-closed) assignment path.
pub struct RatifiedAssignmentScorer;

impl AssignmentScorer for RatifiedAssignmentScorer {
    fn score(&self, beacon: &Beacon, ctx: &ScoreContext<'_>) -> Score {
        let mut m = Vec::with_capacity(32 + 32 + 32 + 8 + 20 + 32);
        m.extend_from_slice(beacon.as_bytes());
        m.extend_from_slice(ctx.job_id.as_bytes());
        m.extend_from_slice(ctx.unit_id.as_bytes());
        m.extend_from_slice(&ctx.generation.to_le_bytes());
        m.extend_from_slice(ctx.payment_addr.as_bytes());
        m.extend_from_slice(ctx.offer_bond_id.as_bytes());
        Score::from_bytes(blake3::derive_key(ASSIGN_SCORE_CONTEXT, &m))
    }
}

/// Typed seam for `DerivedInputCommitmentV1`. C1 does not choose the preimage;
/// it implements the ratified same-predecessor-manifest structural guard on
/// [`WorkUnit`] instead.
pub trait DerivedInputCommitmentScheme {
    fn commit(&self, input: &RequiredInput) -> Dic;
}

/// One offer competing for a unit. Distinct `offer_bond_id`s (one active offer
/// per identity guarantees this upstream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub offer_bond_id: OfferBondId,
    pub payment_addr: Address,
}

/// The selected winner for a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Winner {
    pub offer_bond_id: OfferBondId,
    pub payment_addr: Address,
    pub score: Score,
}

/// Result of running the scheduler for a single unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleOutcome {
    /// A winner was selected.
    Assigned(Winner),
    /// The beacon for the round is undefined — safe halt (no assignment).
    Halted,
    /// No eligible candidates in the collection window.
    NoCandidates,
}

/// Deterministic, proposer-independent winner selection.
///
/// The result is a pure function of `(scorer, beacon, ids, candidate set)`:
/// it consumes NO proposer-controlled input (timestamp, tx-set, tx order), so a
/// proposer cannot bias any assignment. Winner = `min(score, payment_addr)`
/// (score compared lexicographically, matching the rendezvous-KDF precedent),
/// with candidates iterated in a canonical `(offer_bond_id)` order so the walk
/// is fully deterministic regardless of input ordering. An undefined beacon
/// yields [`ScheduleOutcome::Halted`] (safe halt).
pub fn select_winner<S: AssignmentScorer>(
    scorer: &S,
    beacon: Option<&Beacon>,
    job_id: &JobId,
    unit_id: &UnitId,
    generation: u64,
    candidates: &[Candidate],
) -> ScheduleOutcome {
    let Some(beacon) = beacon else {
        return ScheduleOutcome::Halted;
    };
    if candidates.is_empty() {
        return ScheduleOutcome::NoCandidates;
    }

    // Canonical iteration order: sort a local copy by offer_bond_id. This makes
    // the walk independent of the caller's collection order (no map-iteration
    // nondeterminism). `min` over the set is itself order-independent; sorting
    // additionally guarantees reproducible tie handling.
    let mut ordered: Vec<Candidate> = candidates.to_vec();
    ordered.sort_by_key(|c| c.offer_bond_id);

    let mut best: Option<Winner> = None;
    for cand in &ordered {
        let ctx = ScoreContext {
            job_id,
            unit_id,
            generation,
            payment_addr: &cand.payment_addr,
            offer_bond_id: &cand.offer_bond_id,
        };
        let score = scorer.score(beacon, &ctx);
        let take = match &best {
            None => true,
            // min(score, payment_addr): lower score wins; ties broken by the
            // lexicographically smaller payment address.
            Some(cur) => (score, cand.payment_addr) < (cur.score, cur.payment_addr),
        };
        if take {
            best = Some(Winner {
                offer_bond_id: cand.offer_bond_id,
                payment_addr: cand.payment_addr,
                score,
            });
        }
    }

    ScheduleOutcome::Assigned(best.expect("non-empty candidates yield a winner"))
}

// ---------------------------------------------------------------------------
// In-memory model.
//
// Enforces every C1 invariant in memory, validate-all-before-mutate: an op
// performs ALL checks before ANY map insert, so a failing op leaves the model
// byte-for-byte unchanged (proved in tests via a `Clone` snapshot). NOTHING is
// serialized: persistence + reorg wiring are blocked on codec ratification.
// ---------------------------------------------------------------------------

/// The dormant compute-pool state model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComputePoolModel {
    jobs: BTreeMap<JobId, Job>,
    units: BTreeMap<UnitKey, WorkUnit>,
    offers: BTreeMap<OfferBondId, BondedOffer>,
    /// The current active offer per identity — the source of truth for the
    /// one-active-offer-per-identity invariant.
    active_offer_by_identity: BTreeMap<Address, OfferBondId>,
    reservations: BTreeMap<OfferBondId, Reservation>,
    accepted_leaves: BTreeMap<WorkItemKey, AcceptedLeaf>,
    assignments: BTreeMap<WorkItemKey, AssignmentIndexEntry>,
    entitlements: BTreeMap<EntitlementId, EntitlementRecord>,
}

impl ComputePoolModel {
    pub fn new() -> Self {
        Self::default()
    }

    // --- reads ---

    pub fn get_job(&self, id: &JobId) -> Option<&Job> {
        self.jobs.get(id)
    }

    pub fn get_unit(&self, key: &UnitKey) -> Option<&WorkUnit> {
        self.units.get(key)
    }

    pub fn get_offer(&self, id: &OfferBondId) -> Option<&BondedOffer> {
        self.offers.get(id)
    }

    pub fn active_offer_for_identity(&self, identity: &Address) -> Option<&OfferBondId> {
        self.active_offer_by_identity.get(identity)
    }

    pub fn get_reservation(&self, id: &OfferBondId) -> Option<&Reservation> {
        self.reservations.get(id)
    }

    pub fn get_accepted_leaf(&self, key: &WorkItemKey) -> Option<&AcceptedLeaf> {
        self.accepted_leaves.get(key)
    }

    pub fn get_assignment(&self, key: &WorkItemKey) -> Option<&AssignmentIndexEntry> {
        self.assignments.get(key)
    }

    pub fn get_entitlement(&self, id: &EntitlementId) -> Option<&EntitlementRecord> {
        self.entitlements.get(id)
    }

    /// Whether a unit is currently eligible: all predecessors (within the same
    /// job) are `Accepted` (`InputReady`). `None` if the unit is unknown.
    pub fn is_unit_eligible(&self, job_id: &JobId, unit_id: &UnitId) -> Option<bool> {
        let unit = self.units.get(&UnitKey::new(*job_id, *unit_id))?;
        Some(unit.all_predecessors_ready(|pred| {
            self.units
                .get(&UnitKey::new(*job_id, *pred))
                .map(|u| u.state)
        }))
    }

    /// All graph nodes in canonical `(job_id, unit_id)` order. Backed by an
    /// ordered map (never a hash map), so the cross-unit iteration a scheduler
    /// consumes is deterministic and independent of insertion order — no
    /// map-iteration nondeterminism, no timestamp/proposer/tx-set dependence.
    pub fn units_in_canonical_order(&self) -> impl Iterator<Item = &WorkUnit> {
        self.units.values()
    }

    // Read-only enumerators. These let a FUTURE persistence adapter snapshot
    // every record WITHOUT this module dictating a codec or key byte layout:
    // each record carries its own typed id/key, and callers choose their own
    // serialization over the typed fields. Nothing here serializes anything.

    pub fn jobs(&self) -> impl Iterator<Item = &Job> {
        self.jobs.values()
    }

    pub fn offers(&self) -> impl Iterator<Item = &BondedOffer> {
        self.offers.values()
    }

    pub fn reservations(&self) -> impl Iterator<Item = &Reservation> {
        self.reservations.values()
    }

    pub fn accepted_leaves(&self) -> impl Iterator<Item = &AcceptedLeaf> {
        self.accepted_leaves.values()
    }

    pub fn assignments(&self) -> impl Iterator<Item = &AssignmentIndexEntry> {
        self.assignments.values()
    }

    pub fn entitlements(&self) -> impl Iterator<Item = &EntitlementRecord> {
        self.entitlements.values()
    }

    // --- operations (validate-all, THEN mutate). ---

    /// `CreateComputePoolJob` (structure): validate the retention bound against
    /// the cap, the requester debit against available funds, every unit's
    /// same-predecessor-manifest guard and job membership, and reject any
    /// duplicate `unit_id` (within the batch or already present) and a
    /// duplicate `job_id` — ALL before writing anything. Only if every check
    /// passes are the job + graph inserted. A failure on any path leaves the
    /// model unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn create_job(
        &mut self,
        job_id: JobId,
        requester: Address,
        r_job: u32,
        units: Vec<WorkUnit>,
        sizing: &[UnitSizing],
        max_generations: u64,
        final_files: u64,
        retention_cap: u128,
        exposure_without_retention: ExposureInputs,
        available_funds: u128,
    ) -> PoolResult<Job> {
        // --- validate-all (no mutation yet) ---
        let job_max_retention_files =
            compute_job_max_retention_files(sizing, max_generations, final_files)
                .ok_or(PoolError::Overflow("job_max_retention_files"))?;
        validate_retention_within_cap(job_max_retention_files, retention_cap)?;

        let exposure = ExposureInputs {
            job_max_retention_files,
            ..exposure_without_retention
        };
        let requester_debit =
            compute_requester_debit(&exposure).ok_or(PoolError::Overflow("requester_debit"))?;
        validate_funding(requester_debit, available_funds)?;

        if self.jobs.contains_key(&job_id) {
            return Err(PoolError::DuplicateJob);
        }

        let mut batch_keys: BTreeSet<UnitKey> = BTreeSet::new();
        for unit in &units {
            if unit.job_id != job_id {
                return Err(PoolError::UnitJobMismatch);
            }
            unit.validate_same_predecessor_manifest()?;
            let key = UnitKey::new(job_id, unit.unit_id);
            if !batch_keys.insert(key) || self.units.contains_key(&key) {
                return Err(PoolError::DuplicateUnitId);
            }
        }

        // --- commit ---
        let job = Job {
            job_id,
            requester,
            r_job,
            job_max_retention_files,
            requester_debit,
            state: JobState::Open,
        };
        self.jobs.insert(job_id, job.clone());
        for unit in units {
            let key = UnitKey::new(job_id, unit.unit_id);
            self.units.insert(key, unit);
        }
        Ok(job)
    }

    /// `PublishBondedOfferV1` (structure): enforce one active offer per identity
    /// FROM the model's own state and reject a duplicate offer-bond id, then
    /// lock the offer. Validate-before-mutate.
    pub fn publish_offer(&mut self, offer: BondedOffer) -> PoolResult<()> {
        if offer.active && self.active_offer_by_identity.contains_key(&offer.identity) {
            return Err(PoolError::DuplicateActiveOffer);
        }
        if self.offers.contains_key(&offer.offer_bond_id) {
            return Err(PoolError::DuplicateOffer);
        }
        let (id, identity, active) = (offer.offer_bond_id, offer.identity, offer.active);
        self.offers.insert(id, offer);
        if active {
            self.active_offer_by_identity.insert(identity, id);
        }
        Ok(())
    }

    /// Reserve `req` bytes against an offer's capacity ledger, enforcing
    /// `reserved + req ≤ offered`. The checked relation is applied to a LOCAL
    /// copy first; the model is updated only on success.
    pub fn reserve_capacity(
        &mut self,
        offer_bond_id: OfferBondId,
        offered: u128,
        req: u128,
    ) -> PoolResult<Reservation> {
        let mut reservation = self
            .reservations
            .get(&offer_bond_id)
            .cloned()
            .unwrap_or_else(|| Reservation::new(offer_bond_id, offered));
        reservation.try_reserve(req)?;
        self.reservations.insert(offer_bond_id, reservation.clone());
        Ok(reservation)
    }

    /// `AcceptWorkUnitV1` write-once leaf: reject if a leaf already exists for
    /// the `(job, unit, generation)` work item, else record it. The presence
    /// check runs before any mutation.
    pub fn accept_leaf(&mut self, leaf: AcceptedLeaf) -> PoolResult<()> {
        if self.accepted_leaves.contains_key(&leaf.key) {
            return Err(PoolError::LeafAlreadyAccepted);
        }
        self.accepted_leaves.insert(leaf.key, leaf);
        Ok(())
    }

    /// Record the scheduler's winner for a work item in the assignment index.
    pub fn put_assignment(&mut self, entry: AssignmentIndexEntry) -> PoolResult<()> {
        self.assignments.insert(entry.key, entry);
        Ok(())
    }

    /// Register a reimbursement entitlement, enforcing id uniqueness. The
    /// presence check runs before any mutation.
    pub fn register_entitlement(&mut self, record: EntitlementRecord) -> PoolResult<()> {
        if self.entitlements.contains_key(&record.entitlement_id) {
            return Err(PoolError::DuplicateEntitlement);
        }
        self.entitlements.insert(record.entitlement_id, record);
        Ok(())
    }

    /// Advance a work unit through its lifecycle, validating the edge BEFORE
    /// mutating. An unknown unit or an illegal edge returns an error and leaves
    /// the model unchanged (the transition is validated on a copy of the state
    /// before it is written back).
    pub fn transition_unit(&mut self, unit_key: &UnitKey, to: UnitState) -> PoolResult<()> {
        let unit = self.units.get_mut(unit_key).ok_or(PoolError::UnknownUnit)?;
        let next = unit.state.transition(to)?; // validate before mutate
        unit.state = next;
        Ok(())
    }

    /// Cancel a job (structure only; refunds/releases are out of scope).
    /// Validates the `Open -> Cancelled` edge before mutating.
    pub fn cancel_job(&mut self, job_id: &JobId) -> PoolResult<()> {
        self.set_job_state(job_id, JobState::Cancelled)
    }

    /// Halt a job's assignments (structure only). Validates `Open -> Halted`.
    pub fn halt_job(&mut self, job_id: &JobId) -> PoolResult<()> {
        self.set_job_state(job_id, JobState::Halted)
    }

    fn set_job_state(&mut self, job_id: &JobId, to: JobState) -> PoolResult<()> {
        let job = self.jobs.get_mut(job_id).ok_or(PoolError::UnknownJob)?;
        let next = job.state.transition(to)?; // validate before mutate
        job.state = next;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Retention trackers (issue #129): bounded recompute cursor and reverse index.
//
// Both are containers over tracker keys, in memory. Neither decides which
// trackers are Dirty, nor which epochs and archives a tracker depends on: the
// caller supplies those, because they turn on the open epoch question (D-E).
// Every bound is an argument.
// ---------------------------------------------------------------------------

/// Where the #129 scope (5) background recompute resumes: after the last
/// tracker key it visited, or at the start. The caller keeps it between
/// blocks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecomputeCursor {
    last: Option<TrackerKey>,
}

/// One block's recompute selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecomputeBatch {
    /// The trackers to recompute in this block, in visiting order.
    pub selected: Vec<TrackerKey>,
    /// Where the next block's selection resumes.
    pub next: RecomputeCursor,
}

impl RecomputeCursor {
    /// A cursor before every key.
    pub fn start() -> Self {
        Self { last: None }
    }

    /// A cursor that resumes after `key`.
    pub fn after(key: TrackerKey) -> Self {
        Self { last: Some(key) }
    }

    /// The last key visited, if any.
    pub fn last(&self) -> Option<&TrackerKey> {
        self.last.as_ref()
    }

    /// Select at most `max_retention_updates_per_block` keys of `pending`,
    /// ascending from the first key after the cursor and wrapping past the
    /// end to the start once, so no key is selected twice in one block.
    ///
    /// * Deterministic: the result depends only on the cursor, the set and
    ///   the bound. A key that has left `pending` is simply not there.
    /// * Fair: while `pending` is unchanged, every key is selected within
    ///   `ceil(|pending| / bound)` consecutive blocks.
    /// * Fail-closed on overflow: selecting removes nothing and marks nothing
    ///   clean. A key over the bound stays in `pending`, and Dirty is a
    ///   read-time predicate over generations, so a tracker that is not
    ///   recomputed stays Dirty and unsatisfied.
    ///
    /// `pending` is the caller's set of trackers awaiting recompute, for
    /// example the trackers [`RetentionReverseIndex::affected_trackers`]
    /// returns. A bound of zero selects nothing and leaves the cursor where it
    /// is.
    pub fn select(
        &self,
        pending: &BTreeSet<TrackerKey>,
        max_retention_updates_per_block: u64,
    ) -> RecomputeBatch {
        use std::ops::Bound::{Excluded, Included, Unbounded};

        let limit = usize::try_from(max_retention_updates_per_block).unwrap_or(usize::MAX);
        let selected: Vec<TrackerKey> = match self.last {
            None => pending.iter().take(limit).copied().collect(),
            Some(last) => pending
                .range((Excluded(last), Unbounded))
                .chain(pending.range((Unbounded, Included(last))))
                .take(limit)
                .copied()
                .collect(),
        };
        let next = selected.last().map_or(*self, |key| Self::after(*key));
        RecomputeBatch { selected, next }
    }
}

/// One `file_root -> {(tracker_key, R_job, interval_version, epoch)}` entry
/// of the #129 scope (6) file index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileIndexEntry {
    pub tracker_key: TrackerKey,
    pub r_job: u32,
    pub interval_version: u32,
    pub epoch: u64,
}

/// What one tracker puts in the reverse indexes.
///
/// `job_id`, `file_root`, `r_job` and `interval_version` are fixed for the
/// tracker's life; all four are in its key. `epochs` and `archives` are the
/// caller's: which epochs a tracker is indexed under, and which archives it
/// depends on, is what the open epoch question (D-E) decides. They are sets,
/// so a repeat in the caller's list is one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerIndexRecord {
    pub job_id: JobId,
    pub file_root: Hash,
    pub r_job: u32,
    pub interval_version: u32,
    pub epochs: BTreeSet<u64>,
    pub archives: BTreeSet<Address>,
}

impl TrackerIndexRecord {
    /// The entries this tracker occupies: one job entry, one file entry per
    /// epoch and one archive entry per archive. `None` if that overflows
    /// `u64`.
    pub fn entry_count(&self) -> Option<u64> {
        let epochs = u64::try_from(self.epochs.len()).ok()?;
        let archives = u64::try_from(self.archives.len()).ok()?;
        epochs.checked_add(archives)?.checked_add(1)
    }
}

/// The #129 scope (6) reverse indexes, in memory: `archive -> {tracker_key}`,
/// `file_root -> {(tracker_key, R_job, interval_version, epoch)}` and
/// `job_id -> {tracker_key}`.
///
/// * Every change is atomic: a refused call leaves the index unchanged.
/// * Emptied buckets are pruned, so removing every tracker gives back an
///   index equal to [`RetentionReverseIndex::new`].
/// * `max_reverse_index_entries` is injected on every call that can grow the
///   index and bounds one job's entries, the quantity relation 4 sizes
///   (`max_retention_files_per_job × (2 + R_max)`). A call that would take
///   the job over it is refused.
/// * [`Self::affected_trackers`] suppresses duplicates: a tracker reached
///   through several changes in one block is listed once.
///
/// Persisting it, journalling it and reverting it on reorg belong to the
/// caller that stores it; nothing stores it yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionReverseIndex {
    trackers: BTreeMap<TrackerKey, TrackerIndexRecord>,
    by_archive: BTreeMap<Address, BTreeSet<TrackerKey>>,
    by_file: BTreeMap<[u8; 32], BTreeSet<FileIndexEntry>>,
    by_job: BTreeMap<JobId, BTreeSet<TrackerKey>>,
    job_entries: BTreeMap<JobId, u64>,
}

impl RetentionReverseIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a tracker at tracking start. Refused if `key` is already
    /// indexed, if `record.epochs` is empty, or if the job's entries would
    /// exceed `max_reverse_index_entries`.
    pub fn insert_tracker(
        &mut self,
        key: TrackerKey,
        record: TrackerIndexRecord,
        max_reverse_index_entries: u64,
    ) -> PoolResult<()> {
        if self.trackers.contains_key(&key) {
            return Err(PoolError::RetentionTrackerAlreadyIndexed);
        }
        let job_total = self.job_total_with(&record, 0, max_reverse_index_entries)?;
        self.link(key, &record);
        self.job_entries.insert(record.job_id, job_total);
        self.trackers.insert(key, record);
        Ok(())
    }

    /// Replace a tracker's epochs and archives, on an epoch or reassignment
    /// update; its job, file, `R_job` and interval version are kept. Refused
    /// if the tracker is unknown, if `epochs` is empty, or if the job's
    /// entries would exceed `max_reverse_index_entries`.
    pub fn replace_dependencies(
        &mut self,
        key: &TrackerKey,
        epochs: BTreeSet<u64>,
        archives: BTreeSet<Address>,
        max_reverse_index_entries: u64,
    ) -> PoolResult<()> {
        let old = self
            .trackers
            .get(key)
            .ok_or(PoolError::UnknownRetentionTracker)?
            .clone();
        let new = TrackerIndexRecord {
            epochs,
            archives,
            ..old
        };
        let old_count = old
            .entry_count()
            .ok_or(PoolError::Overflow("reverse-index entries"))?;
        let job_total = self.job_total_with(&new, old_count, max_reverse_index_entries)?;
        self.unlink(key, &old);
        self.link(*key, &new);
        self.job_entries.insert(new.job_id, job_total);
        self.trackers.insert(*key, new);
        Ok(())
    }

    /// Remove a tracker (at settlement, incomplete, cancel or
    /// reprovision-supersede) and return what it had indexed.
    pub fn remove_tracker(&mut self, key: &TrackerKey) -> PoolResult<TrackerIndexRecord> {
        let record = self
            .trackers
            .remove(key)
            .ok_or(PoolError::UnknownRetentionTracker)?;
        self.unlink(key, &record);
        // The record was counted when it was indexed, so this cannot fail; if
        // it did, 0 would leave the job's total high, never low.
        let count = record.entry_count().unwrap_or(0);
        let remaining = self
            .job_entries
            .get(&record.job_id)
            .copied()
            .unwrap_or(0)
            .saturating_sub(count);
        if remaining == 0 {
            self.job_entries.remove(&record.job_id);
        } else {
            self.job_entries.insert(record.job_id, remaining);
        }
        Ok(record)
    }

    /// What `key` has indexed, if it is indexed.
    pub fn tracker(&self, key: &TrackerKey) -> Option<&TrackerIndexRecord> {
        self.trackers.get(key)
    }

    /// Trackers indexed under `archive`, in key order.
    pub fn trackers_for_archive(
        &self,
        archive: &Address,
    ) -> impl Iterator<Item = &TrackerKey> + '_ {
        self.by_archive.get(archive).into_iter().flatten()
    }

    /// File-index entries under `file_root`, in order.
    pub fn file_entries(&self, file_root: &Hash) -> impl Iterator<Item = &FileIndexEntry> + '_ {
        self.by_file.get(file_root.as_bytes()).into_iter().flatten()
    }

    /// Trackers indexed under `job_id`, in key order.
    pub fn trackers_for_job(&self, job_id: &JobId) -> impl Iterator<Item = &TrackerKey> + '_ {
        self.by_job.get(job_id).into_iter().flatten()
    }

    /// The reverse-index entries `job_id` occupies, as the cap counts them.
    pub fn job_entry_count(&self, job_id: &JobId) -> u64 {
        self.job_entries.get(job_id).copied().unwrap_or(0)
    }

    /// The trackers to enqueue for one block's changes: every tracker indexed
    /// under a changed archive or a changed file root, each once, in key
    /// order. Which changes the caller reports (status transitions,
    /// reassignments) is the caller's.
    pub fn affected_trackers(
        &self,
        changed_archives: &[Address],
        changed_files: &[Hash],
    ) -> BTreeSet<TrackerKey> {
        let mut affected = BTreeSet::new();
        for archive in changed_archives {
            affected.extend(self.trackers_for_archive(archive).copied());
        }
        for file_root in changed_files {
            affected.extend(self.file_entries(file_root).map(|entry| entry.tracker_key));
        }
        affected
    }

    /// The job's entry total once `record` takes the place of `replaced` of
    /// its entries, refused over `cap`.
    fn job_total_with(
        &self,
        record: &TrackerIndexRecord,
        replaced: u64,
        cap: u64,
    ) -> PoolResult<u64> {
        if record.epochs.is_empty() {
            return Err(PoolError::RetentionTrackerWithoutEpoch);
        }
        let entries = record
            .entry_count()
            .and_then(|added| {
                self.job_entry_count(&record.job_id)
                    .checked_sub(replaced)?
                    .checked_add(added)
            })
            .ok_or(PoolError::Overflow("reverse-index entries"))?;
        if entries > cap {
            return Err(PoolError::ReverseIndexCapExceeded { entries, cap });
        }
        Ok(entries)
    }

    fn file_entry(key: TrackerKey, record: &TrackerIndexRecord, epoch: u64) -> FileIndexEntry {
        FileIndexEntry {
            tracker_key: key,
            r_job: record.r_job,
            interval_version: record.interval_version,
            epoch,
        }
    }

    fn link(&mut self, key: TrackerKey, record: &TrackerIndexRecord) {
        self.by_job.entry(record.job_id).or_default().insert(key);
        let file = self
            .by_file
            .entry(*record.file_root.as_bytes())
            .or_default();
        for &epoch in &record.epochs {
            file.insert(Self::file_entry(key, record, epoch));
        }
        for archive in &record.archives {
            self.by_archive.entry(*archive).or_default().insert(key);
        }
    }

    fn unlink(&mut self, key: &TrackerKey, record: &TrackerIndexRecord) {
        remove_pruning(&mut self.by_job, &record.job_id, key);
        for &epoch in &record.epochs {
            let entry = Self::file_entry(*key, record, epoch);
            remove_pruning(&mut self.by_file, record.file_root.as_bytes(), &entry);
        }
        for archive in &record.archives {
            remove_pruning(&mut self.by_archive, archive, key);
        }
    }
}

/// Remove `value` from `map[bucket]`, and the bucket once it is empty.
fn remove_pruning<K: Ord, V: Ord>(map: &mut BTreeMap<K, BTreeSet<V>>, bucket: &K, value: &V) {
    if let Some(set) = map.get_mut(bucket) {
        set.remove(value);
        if set.is_empty() {
            map.remove(bucket);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deterministic, test-only scorer. This is NOT the ratified preimage
    // (which is a typed boundary): it just needs to be a pure function of
    // (beacon, ctx) to exercise the selection logic.
    struct XorScorer;
    impl AssignmentScorer for XorScorer {
        fn score(&self, beacon: &Beacon, ctx: &ScoreContext<'_>) -> Score {
            let mut out = *beacon.as_bytes();
            for (i, b) in ctx.offer_bond_id.as_bytes().iter().enumerate() {
                out[i] ^= b;
            }
            for (i, b) in ctx.unit_id.as_bytes().iter().enumerate() {
                out[i] ^= b.rotate_left(1);
            }
            out[0] ^= ctx.generation as u8;
            Score::from_bytes(out)
        }
    }

    fn addr(seed: u8) -> Address {
        Address::new([seed; 20])
    }

    fn job(seed: u8) -> JobId {
        JobId::from_bytes([seed; 32])
    }
    fn unit(seed: u8) -> UnitId {
        UnitId::from_bytes([seed; 32])
    }
    fn offer(seed: u8) -> OfferBondId {
        OfferBondId::from_bytes([seed; 32])
    }
    fn beacon(seed: u8) -> Beacon {
        Beacon::from_bytes([seed; 32])
    }

    fn cand(bond: u8, pay: u8) -> Candidate {
        Candidate {
            offer_bond_id: offer(bond),
            payment_addr: addr(pay),
        }
    }

    /// The RATIFIED v1 `beacon_output` KAT value (crates/beacon-runtime/src/wire.rs
    /// `tests::beacon_output_kat_ratified_v1`, #223, now on main). Binding the
    /// assignment score to this exact value is the point of #217 B8.
    const BEACON_OUTPUT_KAT: [u8; 32] = [
        0x69, 0x04, 0xae, 0x11, 0x98, 0x1e, 0x78, 0xd5, 0x60, 0xb3, 0x45, 0x00, 0xbb, 0x42, 0xb1,
        0x74, 0x90, 0x85, 0xc4, 0x5e, 0xd6, 0x8c, 0x7a, 0x7b, 0xfe, 0x3d, 0x26, 0xf9, 0xe3, 0xe9,
        0x21, 0x04,
    ];

    #[test]
    fn ratified_assignment_score_kat_binds_beacon_output() {
        let bk = Beacon::from_bytes(BEACON_OUTPUT_KAT);
        let (j, u, pay, ob) = (job(0x11), unit(0x22), addr(0x07), offer(0x33));
        let ctx = ScoreContext {
            job_id: &j,
            unit_id: &u,
            generation: 5,
            payment_addr: &pay,
            offer_bond_id: &ob,
        };
        let s = RatifiedAssignmentScorer.score(&bk, &ctx);

        // Independent recomputation of the exact ratified preimage (a separate path
        // from RatifiedAssignmentScorer::score).
        let mut m = Vec::new();
        m.extend_from_slice(&BEACON_OUTPUT_KAT);
        m.extend_from_slice(&[0x11u8; 32]); // job_id
        m.extend_from_slice(&[0x22u8; 32]); // unit_id
        m.extend_from_slice(&5u64.to_le_bytes()); // generation
        m.extend_from_slice(&[0x07u8; 20]); // payment_addr
        m.extend_from_slice(&[0x33u8; 32]); // offer_bond_id
        assert_eq!(*s.as_bytes(), blake3::derive_key(ASSIGN_SCORE_CONTEXT, &m));

        // Frozen KAT (regression vector).
        assert_eq!(hex::encode(s.as_bytes()), "7639c7ce3be9fd2c5e5366233f6eec6748212218cfc52592858ff3ba90f7e527");

        // Binds the beacon output: a different beacon yields a different score.
        assert_ne!(s, RatifiedAssignmentScorer.score(&beacon(0x00), &ctx));

        // Binds every context field (local bindings keep the refs alive).
        let (j2, u2, a2, o2) = (job(0x99), unit(0x99), addr(0x99), offer(0x99));
        assert_ne!(s, RatifiedAssignmentScorer.score(&bk, &ScoreContext { job_id: &j2, ..ctx }));
        assert_ne!(s, RatifiedAssignmentScorer.score(&bk, &ScoreContext { unit_id: &u2, ..ctx }));
        assert_ne!(s, RatifiedAssignmentScorer.score(&bk, &ScoreContext { generation: 6, ..ctx }));
        assert_ne!(s, RatifiedAssignmentScorer.score(&bk, &ScoreContext { payment_addr: &a2, ..ctx }));
        assert_ne!(s, RatifiedAssignmentScorer.score(&bk, &ScoreContext { offer_bond_id: &o2, ..ctx }));
    }

    fn simple_unit(j: JobId, u: UnitId) -> WorkUnit {
        WorkUnit {
            job_id: j,
            unit_id: u,
            predecessors: vec![],
            required_inputs: vec![],
            generation: 0,
            state: UnitState::Blocked,
        }
    }

    fn safe_exposure() -> ExposureInputs {
        // job_max_retention_files is overwritten inside create_job.
        ExposureInputs {
            q: 100,
            reprovision_allowance: 10,
            job_max_retention_files: 0,
            max_reassignments_per_file: 2,
            reassign_reimb: 5,
        }
    }

    // ---- scheduler ----

    #[test]
    fn scheduler_is_deterministic_and_order_independent() {
        let b = beacon(7);
        let j = job(1);
        let u = unit(2);
        let a = cand(10, 100);
        let b2 = cand(20, 101);
        let c = cand(30, 102);

        let w1 = select_winner(&XorScorer, Some(&b), &j, &u, 0, &[a, b2, c]);
        let w2 = select_winner(&XorScorer, Some(&b), &j, &u, 0, &[c, a, b2]);
        let w3 = select_winner(&XorScorer, Some(&b), &j, &u, 0, &[b2, c, a]);
        assert_eq!(w1, w2);
        assert_eq!(w1, w3);
        assert!(matches!(w1, ScheduleOutcome::Assigned(_)));
    }

    #[test]
    fn scheduler_is_proposer_independent() {
        let j = job(1);
        let u = unit(2);
        let set = [cand(10, 100), cand(11, 99), cand(12, 200)];
        let b1 = beacon(5);
        let w_b1 = select_winner(&XorScorer, Some(&b1), &j, &u, 0, &set);
        let w_b1_again = select_winner(&XorScorer, Some(&b1), &j, &u, 0, &set);
        assert_eq!(w_b1, w_b1_again, "same beacon => same winner");
    }

    #[test]
    fn undefined_beacon_halts() {
        let out = select_winner(&XorScorer, None, &job(1), &unit(2), 0, &[cand(10, 100)]);
        assert_eq!(out, ScheduleOutcome::Halted);
    }

    #[test]
    fn empty_candidates_is_no_candidates() {
        let b = beacon(3);
        let out = select_winner(&XorScorer, Some(&b), &job(1), &unit(2), 0, &[]);
        assert_eq!(out, ScheduleOutcome::NoCandidates);
    }

    #[test]
    fn tie_break_prefers_smaller_payment_addr() {
        struct ConstScorer;
        impl AssignmentScorer for ConstScorer {
            fn score(&self, _b: &Beacon, _c: &ScoreContext<'_>) -> Score {
                Score::from_bytes([9u8; 32])
            }
        }
        let b = beacon(3);
        let set = [cand(10, 200), cand(20, 50), cand(30, 120)];
        match select_winner(&ConstScorer, Some(&b), &job(1), &unit(2), 0, &set) {
            ScheduleOutcome::Assigned(w) => assert_eq!(w.payment_addr, addr(50)),
            other => panic!("expected Assigned, got {other:?}"),
        }
    }

    // ---- pure relations ----

    #[test]
    fn retention_formula_matches_ratified_shape() {
        // Σ (1+slots)*g + final. Units {slots:0, slots:2}, g=3, final=4:
        // (1+0)*3 + (1+2)*3 + 4 = 3 + 9 + 4 = 16.
        let units = [UnitSizing { slots: 0 }, UnitSizing { slots: 2 }];
        assert_eq!(compute_job_max_retention_files(&units, 3, 4).unwrap(), 16);
    }

    #[test]
    fn retention_overflow_fails_closed() {
        // A single (1+u64::MAX)*u64::MAX term fits in u128; summing two of them
        // overflows the accumulator, which must return None (never wrap).
        let units = [
            UnitSizing { slots: u64::MAX },
            UnitSizing { slots: u64::MAX },
        ];
        assert_eq!(compute_job_max_retention_files(&units, u64::MAX, 0), None);
    }

    #[test]
    fn retention_cap_rejected() {
        assert_eq!(
            validate_retention_within_cap(17, 16),
            Err(PoolError::RetentionCapExceeded { files: 17, cap: 16 })
        );
        assert!(validate_retention_within_cap(16, 16).is_ok());
    }

    #[test]
    fn requester_debit_includes_global_reassign_reserve() {
        // debit = q + reprovision + files*perFile*reimb
        //       = 100 + 10 + (16 * 2 * 5) = 270.
        let inp = ExposureInputs {
            q: 100,
            reprovision_allowance: 10,
            job_max_retention_files: 16,
            max_reassignments_per_file: 2,
            reassign_reimb: 5,
        };
        assert_eq!(compute_requester_debit(&inp), Some(270));
    }

    #[test]
    fn requester_debit_overflow_fails_closed() {
        let inp = ExposureInputs {
            q: 0,
            reprovision_allowance: 0,
            job_max_retention_files: u128::MAX,
            max_reassignments_per_file: 2,
            reassign_reimb: 1,
        };
        assert_eq!(compute_requester_debit(&inp), None);
    }

    #[test]
    fn underfunded_rejected() {
        assert_eq!(
            validate_funding(270, 269),
            Err(PoolError::Underfunded {
                debit: 270,
                available: 269
            })
        );
        assert!(validate_funding(270, 270).is_ok());
    }

    #[test]
    fn capacity_relation_holds_and_rejects_over_offer() {
        let mut r = Reservation::new(offer(1), 100);
        r.try_reserve(60).unwrap();
        assert!(r.invariant_holds());
        assert_eq!(
            r.try_reserve(50),
            Err(PoolError::CapacityExceeded {
                offered: 100,
                requested: 110
            })
        );
        assert_eq!(r.reserved, 60, "rejected reserve must not mutate");
        r.try_reserve(40).unwrap();
        assert_eq!(r.reserved, 100);
        assert!(r.invariant_holds());
        r.release(100);
        assert_eq!(r.reserved, 0);
    }

    #[test]
    fn same_predecessor_manifest_enforced() {
        let pred = unit(9);
        let root_a = Hash::new([1; 32]);
        let root_b = Hash::new([2; 32]);
        let mk = |root: Hash, slot: u8| RequiredInput {
            predecessor: pred,
            required_output_slot_id: SlotId::from_bytes([slot; 32]),
            pred_output_manifest_root: root,
            required_slot_state_object_root: Hash::new([slot; 32]),
        };
        // fan-in from the same predecessor, two slots (residual + KV):
        // agreeing manifest roots pass.
        let ok_unit = WorkUnit {
            job_id: job(1),
            unit_id: unit(2),
            predecessors: vec![pred],
            required_inputs: vec![mk(root_a, 1), mk(root_a, 2)],
            generation: 0,
            state: UnitState::Blocked,
        };
        assert!(ok_unit.validate_same_predecessor_manifest().is_ok());
        // disagreeing manifest roots from the SAME predecessor are rejected.
        let bad_unit = WorkUnit {
            required_inputs: vec![mk(root_a, 1), mk(root_b, 2)],
            ..ok_unit.clone()
        };
        assert_eq!(
            bad_unit.validate_same_predecessor_manifest(),
            Err(PoolError::ManifestMismatch)
        );
    }

    #[test]
    fn lifecycle_transitions_enforced() {
        use UnitState::*;
        assert_eq!(Blocked.transition(Eligible).unwrap(), Eligible);
        assert_eq!(Eligible.transition(Assigned).unwrap(), Assigned);
        assert_eq!(Assigned.transition(Accepted).unwrap(), Accepted);
        assert_eq!(Assigned.transition(Reassignable).unwrap(), Reassignable);
        assert_eq!(Reassignable.transition(Assigned).unwrap(), Assigned);
        assert_eq!(
            Eligible.transition(AssignmentHalted).unwrap(),
            AssignmentHalted
        );
        assert!(Blocked.transition(Accepted).is_err());
        assert!(Accepted.transition(Assigned).is_err());
        assert!(Accepted.transition(Reassignable).is_err());
    }

    // ---- in-memory model invariants ----

    #[test]
    fn create_job_records_job_graph_and_snapshots_retention() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        m.create_job(
            j,
            addr(9),
            3,
            vec![simple_unit(j, unit(2)), simple_unit(j, unit(3))],
            &[UnitSizing { slots: 0 }, UnitSizing { slots: 2 }],
            3,
            4,
            1_000,
            safe_exposure(),
            1_000_000,
        )
        .unwrap();
        assert_eq!(m.get_job(&j).unwrap().job_max_retention_files, 16);
        assert_eq!(m.get_job(&j).unwrap().requester_debit, 270);
        assert!(m.get_unit(&UnitKey::new(j, unit(2))).is_some());
        assert!(m.get_unit(&UnitKey::new(j, unit(3))).is_some());
    }

    #[test]
    fn duplicate_unit_id_rejected_leaves_model_unchanged() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        let before = m.clone();
        // Two units with the SAME unit_id => rejected before any mutation.
        let err = m
            .create_job(
                j,
                addr(9),
                3,
                vec![simple_unit(j, unit(2)), simple_unit(j, unit(2))],
                &[UnitSizing { slots: 0 }],
                3,
                4,
                1_000,
                safe_exposure(),
                1_000_000,
            )
            .unwrap_err();
        assert_eq!(err, PoolError::DuplicateUnitId);
        assert_eq!(m, before, "failed create_job must leave model unchanged");
    }

    #[test]
    fn validate_before_mutate_over_cap_writes_nothing() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        let before = m.clone();
        // retention = (1)*3 + (1+2)*3 + 4 = 16 > cap 15.
        let err = m
            .create_job(
                j,
                addr(9),
                3,
                vec![simple_unit(j, unit(2))],
                &[UnitSizing { slots: 0 }, UnitSizing { slots: 2 }],
                3,
                4,
                15,
                safe_exposure(),
                1_000_000,
            )
            .unwrap_err();
        assert_eq!(err, PoolError::RetentionCapExceeded { files: 16, cap: 15 });
        assert_eq!(m, before);
    }

    #[test]
    fn validate_before_mutate_underfunded_writes_nothing() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        let before = m.clone();
        // debit = 100 + 10 + 16*2*5 = 270; funds one short.
        let err = m
            .create_job(
                j,
                addr(9),
                3,
                vec![simple_unit(j, unit(2))],
                &[UnitSizing { slots: 0 }, UnitSizing { slots: 2 }],
                3,
                4,
                1_000,
                safe_exposure(),
                269,
            )
            .unwrap_err();
        assert_eq!(
            err,
            PoolError::Underfunded {
                debit: 270,
                available: 269
            }
        );
        assert_eq!(m, before);
    }

    #[test]
    fn write_once_leaf_rejects_second_accept() {
        let mut m = ComputePoolModel::new();
        let key = WorkItemKey::new(job(1), unit(2), 0);
        let leaf = AcceptedLeaf {
            key,
            offer_bond_id: offer(4),
            commit_bond_id: CommitBondId::from_bytes([5; 32]),
            accepted_bytes: 100,
        };
        m.accept_leaf(leaf.clone()).unwrap();
        let before = m.clone();
        let second = AcceptedLeaf {
            accepted_bytes: 999,
            ..leaf
        };
        assert_eq!(m.accept_leaf(second), Err(PoolError::LeafAlreadyAccepted));
        assert_eq!(m, before, "rejected re-accept must not mutate");
        assert_eq!(m.get_accepted_leaf(&key).unwrap().accepted_bytes, 100);
    }

    #[test]
    fn accepted_leaf_generation_is_part_of_identity() {
        // Same (job, unit) but different generation => distinct work items;
        // both leaves coexist (write-once is per composite key).
        let mut m = ComputePoolModel::new();
        let g0 = WorkItemKey::new(job(1), unit(2), 0);
        let g1 = WorkItemKey::new(job(1), unit(2), 1);
        let mk = |key| AcceptedLeaf {
            key,
            offer_bond_id: offer(4),
            commit_bond_id: CommitBondId::from_bytes([5; 32]),
            accepted_bytes: 1,
        };
        m.accept_leaf(mk(g0)).unwrap();
        m.accept_leaf(mk(g1)).unwrap();
        assert!(m.get_accepted_leaf(&g0).is_some());
        assert!(m.get_accepted_leaf(&g1).is_some());
        // The composite key exposes its owning graph node.
        assert_eq!(g1.unit_key(), UnitKey::new(job(1), unit(2)));
    }

    #[test]
    fn one_active_offer_per_identity_from_model_state() {
        let mut m = ComputePoolModel::new();
        let identity = addr(3);
        let first = BondedOffer {
            offer_bond_id: offer(1),
            identity,
            payment_addr: addr(4),
            offered_bytes: 1_000,
            offer_seq: 0,
            bond_locked: 500,
            active: true,
        };
        m.publish_offer(first).unwrap();
        let before = m.clone();
        // Second active offer for the SAME identity => rejected from model state.
        let second = BondedOffer {
            offer_bond_id: offer(2),
            identity,
            payment_addr: addr(4),
            offered_bytes: 1_000,
            offer_seq: 1,
            bond_locked: 500,
            active: true,
        };
        assert_eq!(
            m.publish_offer(second),
            Err(PoolError::DuplicateActiveOffer)
        );
        assert_eq!(m, before);
        assert_eq!(*m.active_offer_for_identity(&identity).unwrap(), offer(1));
    }

    #[test]
    fn duplicate_offer_bond_id_rejected() {
        let mut m = ComputePoolModel::new();
        let o = BondedOffer {
            offer_bond_id: offer(1),
            identity: addr(3),
            payment_addr: addr(4),
            offered_bytes: 1_000,
            offer_seq: 0,
            bond_locked: 500,
            active: false,
        };
        m.publish_offer(o.clone()).unwrap();
        let before = m.clone();
        assert_eq!(m.publish_offer(o), Err(PoolError::DuplicateOffer));
        assert_eq!(m, before);
    }

    #[test]
    fn duplicate_entitlement_id_rejected() {
        let mut m = ComputePoolModel::new();
        let rec = EntitlementRecord {
            entitlement_id: EntitlementId::from_bytes([1; 32]),
            beneficiary: addr(2),
            kind: EntitlementKind::ReassignReimb,
            amount: 7,
        };
        m.register_entitlement(rec.clone()).unwrap();
        let before = m.clone();
        assert_eq!(
            m.register_entitlement(rec),
            Err(PoolError::DuplicateEntitlement)
        );
        assert_eq!(m, before);
    }

    #[test]
    fn capacity_reservation_persists_and_rejects_over_offer() {
        let mut m = ComputePoolModel::new();
        let o = offer(1);
        m.reserve_capacity(o, 100, 60).unwrap();
        assert_eq!(m.get_reservation(&o).unwrap().reserved, 60);
        let before = m.clone();
        assert_eq!(
            m.reserve_capacity(o, 100, 50),
            Err(PoolError::CapacityExceeded {
                offered: 100,
                requested: 110
            })
        );
        assert_eq!(m, before, "rejected reserve must not mutate the model");
        assert!(m.get_reservation(&o).unwrap().invariant_holds());
    }

    #[test]
    fn eligibility_requires_all_predecessors_accepted() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        let (p1, p2, child) = (unit(11), unit(12), unit(13));
        let mut u_p1 = simple_unit(j, p1);
        let mut u_p2 = simple_unit(j, p2);
        let mut u_child = simple_unit(j, child);
        u_child.predecessors = vec![p1, p2];

        u_p1.state = UnitState::Accepted;
        u_p2.state = UnitState::Assigned;
        m.units.insert(UnitKey::new(j, p1), u_p1);
        m.units.insert(UnitKey::new(j, p2), u_p2.clone());
        m.units.insert(UnitKey::new(j, child), u_child);

        // Only one predecessor accepted => not eligible.
        assert_eq!(m.is_unit_eligible(&j, &child), Some(false));
        // Accept the second predecessor => eligible.
        u_p2.state = UnitState::Accepted;
        m.units.insert(UnitKey::new(j, p2), u_p2);
        assert_eq!(m.is_unit_eligible(&j, &child), Some(true));
        // Unknown unit => None.
        assert_eq!(m.is_unit_eligible(&j, &unit(99)), None);
    }

    #[test]
    fn cross_unit_iteration_is_canonical_and_insertion_order_independent() {
        // Two models with units inserted in OPPOSITE orders must enumerate
        // units in the identical canonical (job_id, unit_id) order.
        let j = job(1);
        let mut a = ComputePoolModel::new();
        a.create_job(
            j,
            addr(9),
            1,
            vec![
                simple_unit(j, unit(2)),
                simple_unit(j, unit(5)),
                simple_unit(j, unit(3)),
            ],
            &[UnitSizing { slots: 0 }],
            1,
            0,
            1_000,
            safe_exposure(),
            1_000_000,
        )
        .unwrap();
        let mut b = ComputePoolModel::new();
        b.create_job(
            j,
            addr(9),
            1,
            vec![
                simple_unit(j, unit(3)),
                simple_unit(j, unit(2)),
                simple_unit(j, unit(5)),
            ],
            &[UnitSizing { slots: 0 }],
            1,
            0,
            1_000,
            safe_exposure(),
            1_000_000,
        )
        .unwrap();
        let order_a: Vec<UnitId> = a.units_in_canonical_order().map(|u| u.unit_id).collect();
        let order_b: Vec<UnitId> = b.units_in_canonical_order().map(|u| u.unit_id).collect();
        assert_eq!(order_a, order_b, "canonical order is insertion-independent");
        assert_eq!(
            order_a,
            vec![unit(2), unit(3), unit(5)],
            "sorted by UnitKey"
        );
    }

    #[test]
    fn transition_unit_validates_and_failure_leaves_model_unchanged() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        m.create_job(
            j,
            addr(9),
            1,
            vec![simple_unit(j, unit(2))],
            &[UnitSizing { slots: 0 }],
            1,
            0,
            1_000,
            safe_exposure(),
            1_000_000,
        )
        .unwrap();
        let key = UnitKey::new(j, unit(2));
        // Blocked -> Eligible -> Assigned is valid.
        m.transition_unit(&key, UnitState::Eligible).unwrap();
        m.transition_unit(&key, UnitState::Assigned).unwrap();
        assert_eq!(m.get_unit(&key).unwrap().state, UnitState::Assigned);

        let before = m.clone();
        // Assigned -> Eligible is illegal: rejected, model unchanged.
        assert!(matches!(
            m.transition_unit(&key, UnitState::Eligible),
            Err(PoolError::InvalidTransition { .. })
        ));
        assert_eq!(m, before);
        // Unknown unit rejected.
        assert_eq!(
            m.transition_unit(&UnitKey::new(j, unit(99)), UnitState::Eligible),
            Err(PoolError::UnknownUnit)
        );
    }

    #[test]
    fn reassignable_cycle_is_permitted() {
        // Assigned -> Reassignable (decline/expire) -> Assigned (reassign).
        let mut m = ComputePoolModel::new();
        let j = job(1);
        m.create_job(
            j,
            addr(9),
            1,
            vec![simple_unit(j, unit(2))],
            &[UnitSizing { slots: 0 }],
            1,
            0,
            1_000,
            safe_exposure(),
            1_000_000,
        )
        .unwrap();
        let key = UnitKey::new(j, unit(2));
        for to in [
            UnitState::Eligible,
            UnitState::Assigned,
            UnitState::Reassignable,
            UnitState::Assigned,
        ] {
            m.transition_unit(&key, to).unwrap();
        }
        assert_eq!(m.get_unit(&key).unwrap().state, UnitState::Assigned);
    }

    #[test]
    fn cancel_and_halt_job_validated_and_unchanged_on_failure() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        m.create_job(
            j,
            addr(9),
            1,
            vec![],
            &[],
            1,
            0,
            1_000,
            safe_exposure(),
            1_000_000,
        )
        .unwrap();
        m.cancel_job(&j).unwrap();
        assert_eq!(m.get_job(&j).unwrap().state, JobState::Cancelled);

        let before = m.clone();
        // Already left Open: cannot cancel or halt again; model unchanged.
        assert!(matches!(
            m.cancel_job(&j),
            Err(PoolError::InvalidJobTransition { .. })
        ));
        assert!(matches!(
            m.halt_job(&j),
            Err(PoolError::InvalidJobTransition { .. })
        ));
        assert_eq!(m, before);
        // Unknown job rejected.
        assert_eq!(m.cancel_job(&job(99)), Err(PoolError::UnknownJob));
    }

    #[test]
    fn enumerators_expose_all_records_for_a_future_adapter() {
        let mut m = ComputePoolModel::new();
        let j = job(1);
        m.create_job(
            j,
            addr(9),
            1,
            vec![simple_unit(j, unit(2)), simple_unit(j, unit(3))],
            &[UnitSizing { slots: 0 }],
            1,
            0,
            1_000,
            safe_exposure(),
            1_000_000,
        )
        .unwrap();
        assert_eq!(m.jobs().count(), 1);
        assert_eq!(m.units_in_canonical_order().count(), 2);
        assert_eq!(m.offers().count(), 0);
        assert_eq!(m.reservations().count(), 0);
        assert_eq!(m.accepted_leaves().count(), 0);
        assert_eq!(m.assignments().count(), 0);
        assert_eq!(m.entitlements().count(), 0);
    }

    // --- Retention kernels (issue #129) ---------------------------------------

    fn tk(seed: u8) -> TrackerKey {
        TrackerKey::from_bytes([seed; 32])
    }

    fn generations(pairs: &[(Address, u64)]) -> BTreeMap<Address, u64> {
        pairs.iter().copied().collect()
    }

    fn index_record(
        j: u8,
        file: u8,
        r_job: u32,
        epochs: &[u64],
        archives: &[u8],
    ) -> TrackerIndexRecord {
        TrackerIndexRecord {
            job_id: job(j),
            file_root: Hash::new([file; 32]),
            r_job,
            interval_version: 1,
            epochs: epochs.iter().copied().collect(),
            archives: archives.iter().map(|&a| addr(a)).collect(),
        }
    }

    #[test]
    fn retention_satisfied_needs_a_clean_since_and_the_full_interval() {
        let oab = 200;
        assert!(retention_satisfied(false, Some(1_000), 1_200, oab));
        assert!(retention_satisfied(false, Some(1_000), 1_201, oab));
        assert!(
            !retention_satisfied(false, Some(1_000), 1_199, oab),
            "one block short"
        );
        assert!(!retention_satisfied(true, Some(1_000), 1_200, oab), "dirty");
        assert!(
            !retention_satisfied(true, Some(1_000), u64::MAX, oab),
            "dirty never matures"
        );
        assert!(!retention_satisfied(false, None, u64::MAX, oab), "no since");
        assert!(
            !retention_satisfied(false, Some(1_000), 999, oab),
            "since after head"
        );
    }

    #[test]
    fn retention_satisfied_fails_closed_on_overflow() {
        assert!(!retention_satisfied(
            false,
            Some(u64::MAX - 5),
            u64::MAX,
            10
        ));
        assert!(!retention_satisfied(false, Some(u64::MAX), u64::MAX, 1));
        assert!(!retention_satisfied(false, Some(1), u64::MAX, u64::MAX));
        // The largest sum that fits still matures.
        assert!(retention_satisfied(
            false,
            Some(u64::MAX - 10),
            u64::MAX,
            10
        ));
    }

    #[test]
    fn a_moved_generation_makes_the_tracker_dirty() {
        let (a, b) = (addr(1), addr(2));
        let recorded = [(a, 4), (b, 7)];
        for (current, dirty) in [
            (generations(&[(a, 4), (b, 7)]), false),
            // A slash, exit or unbond of either dependency bumps its generation.
            (generations(&[(a, 5), (b, 7)]), true),
            (generations(&[(a, 4), (b, 8)]), true),
            // Slashed and reactivated: back to Active, but two generations on.
            (generations(&[(a, 6), (b, 7)]), true),
        ] {
            let current_gen = |x: &Address| current.get(x).copied();
            assert_eq!(
                retention_tracker_dirty(&recorded, &[a, b], current_gen),
                dirty
            );
        }
    }

    #[test]
    fn a_changed_dependency_set_makes_the_tracker_dirty() {
        let (a, b, c) = (addr(1), addr(2), addr(3));
        let recorded = [(a, 1), (b, 1)];
        let current = generations(&[(a, 1), (b, 1), (c, 1)]);
        let current_gen = |x: &Address| current.get(x).copied();
        // The same set in another order, with repeats (an archive in several
        // epochs): clean.
        assert!(!retention_tracker_dirty(
            &recorded,
            &[b, a, b, a],
            current_gen
        ));
        // An archive joins or leaves the set, every generation unchanged.
        assert!(retention_tracker_dirty(&recorded, &[a, b, c], current_gen));
        assert!(retention_tracker_dirty(&recorded, &[a], current_gen));
        assert!(retention_tracker_dirty(&recorded, &[], current_gen));
        assert!(!retention_tracker_dirty(&[], &[], current_gen));
    }

    #[test]
    fn dirty_fails_closed_on_a_missing_generation_or_a_repeated_record() {
        let (a, b) = (addr(1), addr(2));
        let current = generations(&[(a, 1)]);
        let current_gen = |x: &Address| current.get(x).copied();
        assert!(retention_tracker_dirty(
            &[(a, 1), (b, 0)],
            &[a, b],
            current_gen
        ));
        assert!(retention_tracker_dirty(
            &[(a, 1), (a, 1)],
            &[a],
            current_gen
        ));
    }

    #[test]
    fn below_r_coverage_cannot_mature() {
        use crate::storage_metadata::{
            active_replica_counts_from, coverage_ok, ReplicaAttestation,
        };
        // Chunk 1 has R_job - 1 = 2 replicas.
        let (both, first) = ([0b11u8], [0b01u8]);
        let entries: Vec<ReplicaAttestation<'_>> =
            [(1, &both[..]), (2, &both[..]), (3, &first[..])]
                .into_iter()
                .map(|(seed, bitmap)| ReplicaAttestation {
                    epoch: 100,
                    archive: addr(seed),
                    active: true,
                    bitmap: Some(bitmap),
                })
                .collect();
        let counts = active_replica_counts_from(2, &entries);
        assert_eq!(counts, vec![3, 2]);
        assert!(!coverage_ok(&counts, 3));
        assert!(coverage_ok(&counts, 2));
        // Scope (5) leaves `since` unset when coverage fails, and an unset
        // `since` never matures.
        assert!(!retention_satisfied(false, None, u64::MAX, 200));
    }

    #[test]
    fn recompute_cursor_is_bounded_ordered_fair_and_wraps() {
        let pending: BTreeSet<TrackerKey> = [5, 1, 4, 2, 3].into_iter().map(tk).collect();
        let mut cursor = RecomputeCursor::start();
        let mut visits = Vec::new();
        for _ in 0..3 {
            let batch = cursor.select(&pending, 2);
            visits.push(batch.selected);
            cursor = batch.next;
        }
        assert_eq!(
            visits,
            vec![vec![tk(1), tk(2)], vec![tk(3), tk(4)], vec![tk(5), tk(1)]]
        );
        // Every key within ceil(5 / 2) = 3 blocks.
        assert_eq!(
            visits.concat().into_iter().collect::<BTreeSet<_>>(),
            pending
        );
        assert_eq!(cursor.last(), Some(&tk(1)));

        // A bound at or above the set visits each key once, after the cursor.
        assert_eq!(
            RecomputeCursor::after(tk(3)).select(&pending, 99).selected,
            vec![tk(4), tk(5), tk(1), tk(2), tk(3)]
        );
        // A key that has left the set is skipped; the order resumes after it.
        let fewer: BTreeSet<TrackerKey> = [1, 2, 4].into_iter().map(tk).collect();
        assert_eq!(
            RecomputeCursor::after(tk(3)).select(&fewer, 2).selected,
            vec![tk(4), tk(1)]
        );
        // Bound 0, or nothing pending: nothing selected, the cursor stays.
        let at = RecomputeCursor::after(tk(2));
        let nothing = RecomputeBatch {
            selected: Vec::new(),
            next: at,
        };
        assert_eq!(at.select(&pending, 0), nothing);
        assert_eq!(at.select(&BTreeSet::new(), 3), nothing);
    }

    #[test]
    fn a_tracker_the_bound_skips_stays_dirty_and_cannot_mature() {
        // Three trackers wait and the bound recomputes one per block. Tracker
        // 3's only dependency was slashed (generation 1 -> 2) long after its
        // `since`, and its deadline `since + oab` is far behind the head.
        let a = addr(1);
        let recorded = [(a, 1)];
        let current = generations(&[(a, 2)]);
        let current_gen = |x: &Address| current.get(x).copied();
        let (since, oab) = (Some(100), 200);
        let pending: BTreeSet<TrackerKey> = [1, 2, 3].into_iter().map(tk).collect();
        let mut cursor = RecomputeCursor::start();
        for head in [10_000u64, 10_001] {
            let batch = cursor.select(&pending, 1);
            assert!(!batch.selected.contains(&tk(3)));
            cursor = batch.next;
            // Not recomputed, so still Dirty by generation: never satisfied.
            let dirty = retention_tracker_dirty(&recorded, &[a], current_gen);
            assert!(dirty);
            assert!(!retention_satisfied(dirty, since, head, oab));
        }
        // Still pending, and reached on the next block.
        assert_eq!(cursor.select(&pending, 1).selected, vec![tk(3)]);
    }

    #[test]
    fn a_stale_since_never_settles() {
        // `since` was recorded over {a, b}. Since then the dependency set has
        // changed with no generation bump: a reassignment added archive c
        // (both epoch readings) or replaced b by c (latest-only reading).
        let (a, b, c) = (addr(1), addr(2), addr(3));
        let recorded = [(a, 1), (b, 1)];
        let current = generations(&[(a, 1), (b, 1), (c, 1)]);
        let current_gen = |x: &Address| current.get(x).copied();
        for recomputed in [vec![a, b, c], vec![a, c]] {
            let dirty = retention_tracker_dirty(&recorded, &recomputed, current_gen);
            assert!(dirty);
            for head in [300, 10_000, u64::MAX] {
                assert!(!retention_satisfied(dirty, Some(100), head, 200));
            }
        }
        // Unchanged set and generations: the same `since` matures.
        let clean = retention_tracker_dirty(&recorded, &[a, b], current_gen);
        assert!(retention_satisfied(clean, Some(100), 300, 200));
    }

    #[test]
    fn reverse_index_insert_lookup_and_remove_round_trip() {
        let mut idx = RetentionReverseIndex::new();
        let record = index_record(1, 9, 3, &[100], &[1, 2]);
        idx.insert_tracker(tk(1), record.clone(), 4).unwrap();
        assert_eq!(
            idx.trackers_for_job(&job(1)).collect::<Vec<_>>(),
            vec![&tk(1)]
        );
        assert_eq!(
            idx.trackers_for_archive(&addr(1)).collect::<Vec<_>>(),
            vec![&tk(1)]
        );
        assert_eq!(
            idx.trackers_for_archive(&addr(2)).collect::<Vec<_>>(),
            vec![&tk(1)]
        );
        assert_eq!(idx.trackers_for_archive(&addr(3)).count(), 0);
        assert_eq!(
            idx.file_entries(&Hash::new([9; 32])).collect::<Vec<_>>(),
            vec![&FileIndexEntry {
                tracker_key: tk(1),
                r_job: 3,
                interval_version: 1,
                epoch: 100,
            }]
        );
        assert_eq!(idx.job_entry_count(&job(1)), 4);
        assert_eq!(idx.tracker(&tk(1)), Some(&record));

        assert_eq!(idx.remove_tracker(&tk(1)), Ok(record));
        // Pruned: nothing is left behind.
        assert_eq!(idx, RetentionReverseIndex::new());
        assert_eq!(
            idx.remove_tracker(&tk(1)),
            Err(PoolError::UnknownRetentionTracker)
        );
    }

    #[test]
    fn reverse_index_cap_is_per_job_and_a_refusal_changes_nothing() {
        let mut idx = RetentionReverseIndex::new();
        // 1 job + 1 file + 2 archive entries = 4, exactly the cap.
        idx.insert_tracker(tk(1), index_record(1, 9, 3, &[100], &[1, 2]), 4)
            .unwrap();
        // A second tracker of the same job needs 3 more: 7 > 4.
        let second = index_record(1, 8, 3, &[100], &[3]);
        let before = idx.clone();
        assert_eq!(
            idx.insert_tracker(tk(2), second.clone(), 4),
            Err(PoolError::ReverseIndexCapExceeded { entries: 7, cap: 4 })
        );
        assert_eq!(idx, before);
        // Boundary: refused at 6, accepted at 7.
        assert_eq!(
            idx.clone().insert_tracker(tk(2), second.clone(), 6),
            Err(PoolError::ReverseIndexCapExceeded { entries: 7, cap: 6 })
        );
        let mut at_cap = idx.clone();
        at_cap.insert_tracker(tk(2), second, 7).unwrap();
        assert_eq!(at_cap.job_entry_count(&job(1)), 7);
        // Another job has its own budget.
        idx.insert_tracker(tk(3), index_record(2, 9, 3, &[100], &[1, 2]), 4)
            .unwrap();
        assert_eq!(idx.job_entry_count(&job(1)), 4);
        assert_eq!(idx.job_entry_count(&job(2)), 4);
        // Repeats in the caller's lists are one entry each.
        let mut repeats = RetentionReverseIndex::new();
        repeats
            .insert_tracker(tk(1), index_record(1, 9, 3, &[100, 100], &[1, 1, 2]), 4)
            .unwrap();
        assert_eq!(repeats.job_entry_count(&job(1)), 4);
    }

    #[test]
    fn reverse_index_refuses_a_repeated_key_and_a_tracker_without_epoch() {
        let mut idx = RetentionReverseIndex::new();
        idx.insert_tracker(tk(1), index_record(1, 9, 3, &[100], &[1]), 100)
            .unwrap();
        let before = idx.clone();
        assert_eq!(
            idx.insert_tracker(tk(1), index_record(2, 8, 2, &[100], &[2]), 100),
            Err(PoolError::RetentionTrackerAlreadyIndexed)
        );
        assert_eq!(
            idx.insert_tracker(tk(2), index_record(1, 9, 3, &[], &[1]), 100),
            Err(PoolError::RetentionTrackerWithoutEpoch)
        );
        assert_eq!(
            idx.replace_dependencies(&tk(1), BTreeSet::new(), BTreeSet::new(), 100),
            Err(PoolError::RetentionTrackerWithoutEpoch)
        );
        assert_eq!(
            idx.replace_dependencies(&tk(9), BTreeSet::from([100]), BTreeSet::new(), 100),
            Err(PoolError::UnknownRetentionTracker)
        );
        assert_eq!(idx, before);
    }

    #[test]
    fn reverse_index_replace_serves_either_epoch_reading() {
        let root = Hash::new([9; 32]);
        let mut idx = RetentionReverseIndex::new();
        idx.insert_tracker(tk(1), index_record(1, 9, 3, &[100], &[1, 2]), 10)
            .unwrap();

        // A reassignment at 210 moves chunks from archive 1 to archive 3. What
        // the tracker now depends on is the caller's answer; two answers:
        // (i) every epoch, and every archive that attested in any of them;
        let mut union = idx.clone();
        union
            .replace_dependencies(
                &tk(1),
                BTreeSet::from([100, 210]),
                [1, 2, 3].into_iter().map(addr).collect(),
                10,
            )
            .unwrap();
        assert_eq!(union.trackers_for_archive(&addr(1)).count(), 1);
        assert_eq!(
            union
                .file_entries(&root)
                .map(|e| e.epoch)
                .collect::<Vec<_>>(),
            vec![100, 210]
        );
        assert_eq!(union.job_entry_count(&job(1)), 1 + 2 + 3);
        // (ii) the latest epoch and its archives only.
        let mut latest = idx.clone();
        latest
            .replace_dependencies(
                &tk(1),
                BTreeSet::from([210]),
                [2, 3].into_iter().map(addr).collect(),
                10,
            )
            .unwrap();
        assert_eq!(latest.trackers_for_archive(&addr(1)).count(), 0);
        assert!(
            !latest.by_archive.contains_key(&addr(1)),
            "emptied bucket pruned"
        );
        assert_eq!(
            latest.trackers_for_archive(&addr(3)).collect::<Vec<_>>(),
            vec![&tk(1)]
        );
        assert_eq!(
            latest
                .file_entries(&root)
                .map(|e| e.epoch)
                .collect::<Vec<_>>(),
            vec![210]
        );
        assert_eq!(latest.job_entry_count(&job(1)), 1 + 1 + 2);
        // Kept: job, file, R_job and interval version.
        let kept = latest.tracker(&tk(1)).unwrap();
        assert_eq!(
            (
                kept.job_id,
                kept.file_root,
                kept.r_job,
                kept.interval_version
            ),
            (job(1), root, 3, 1)
        );
        // A replacement over the cap changes nothing.
        let before = idx.clone();
        assert_eq!(
            idx.replace_dependencies(
                &tk(1),
                BTreeSet::from([100, 210]),
                [1, 2, 3].into_iter().map(addr).collect(),
                5,
            ),
            Err(PoolError::ReverseIndexCapExceeded { entries: 6, cap: 5 })
        );
        assert_eq!(idx, before);
        // Removing after a replacement leaves nothing behind.
        latest.remove_tracker(&tk(1)).unwrap();
        assert_eq!(latest, RetentionReverseIndex::new());
    }

    #[test]
    fn affected_trackers_lists_each_tracker_once_per_block() {
        let mut idx = RetentionReverseIndex::new();
        idx.insert_tracker(tk(1), index_record(1, 9, 3, &[100], &[1, 2]), 100)
            .unwrap();
        idx.insert_tracker(tk(2), index_record(1, 8, 3, &[100], &[2]), 100)
            .unwrap();
        idx.insert_tracker(tk(3), index_record(2, 9, 2, &[100], &[3]), 100)
            .unwrap();
        idx.insert_tracker(tk(4), index_record(2, 7, 2, &[100], &[4]), 100)
            .unwrap();
        // Archives 2 (reported twice) and 1 change status and file 9 is
        // reassigned, all in one block.
        let affected = idx.affected_trackers(&[addr(2), addr(1), addr(2)], &[Hash::new([9; 32])]);
        assert_eq!(
            affected.into_iter().collect::<Vec<_>>(),
            vec![tk(1), tk(2), tk(3)]
        );
        // Merging into a pending set is idempotent.
        let mut pending = BTreeSet::new();
        pending.extend(idx.affected_trackers(&[addr(2)], &[]));
        pending.extend(idx.affected_trackers(&[addr(1)], &[Hash::new([9; 32])]));
        assert_eq!(pending.len(), 3);
        assert!(idx
            .affected_trackers(&[addr(5)], &[Hash::new([6; 32])])
            .is_empty());
    }

    #[test]
    fn two_jobs_on_one_file_root_are_indexed_independently() {
        let root = Hash::new([9; 32]);
        let mut idx = RetentionReverseIndex::new();
        idx.insert_tracker(tk(1), index_record(1, 9, 2, &[100], &[1, 2]), 4)
            .unwrap();
        idx.insert_tracker(tk(2), index_record(2, 9, 3, &[100], &[1, 2]), 4)
            .unwrap();
        assert_eq!(
            idx.file_entries(&root)
                .map(|e| (e.tracker_key, e.r_job))
                .collect::<Vec<_>>(),
            vec![(tk(1), 2), (tk(2), 3)]
        );
        idx.remove_tracker(&tk(1)).unwrap();
        assert_eq!(
            idx.file_entries(&root)
                .map(|e| e.tracker_key)
                .collect::<Vec<_>>(),
            vec![tk(2)]
        );
        assert_eq!(
            idx.trackers_for_archive(&addr(1)).collect::<Vec<_>>(),
            vec![&tk(2)]
        );
        assert_eq!(idx.job_entry_count(&job(1)), 0);
        assert_eq!(idx.job_entry_count(&job(2)), 4);
    }
}

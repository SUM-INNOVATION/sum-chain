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
//! Persisting these records would require choosing an exact on-disk consensus
//! value layout (a serialization codec) and the canonical composite row keys.
//! Those are **owner-ratified consensus decisions that are not yet made**, so
//! this module persists NOTHING: it holds state in typed maps keyed by typed
//! tuples (`WorkItemKey`, `UnitKey`), never serialized bytes. The identity of
//! accepted leaves / assignments is the ratified composite
//! `(job_id, unit_id, generation)` — modeled as a typed key, not an invented
//! byte preimage.
//!
//! Wiring this model into revertible chain storage (so C1 rows participate in
//! reorg like other state) is **blocked on codec ratification**: it needs (a) an
//! owner-ratified versioned canonical codec for each record and (b) the
//! ratified composite key byte layout. Choosing either here is prohibited.
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
/// (`max_retention_files_per_job`).
pub fn validate_retention_within_cap(files: u128, cap: u128) -> PoolResult<()> {
    if files > cap {
        Err(PoolError::RetentionCapExceeded { files, cap })
    } else {
        Ok(())
    }
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
}

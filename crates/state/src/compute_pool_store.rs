//! C1 compute-pool PERSISTENCE + REVERT contract (issue #130).
//!
//! This is a **storage/revert adapter** (NOT wired to the live PoA reorg
//! handler): the persistence boundary that sits *after* the merged pure
//! in-memory model in [`crate::compute_pool`]. It never touches that module's
//! ratified types — it reads them through their public fields / id accessors and
//! materializes them into revertible chain storage. The model stays byte-free;
//! the codec lives here.
//!
//! ## Why this is an evidence-grounded design, not an invented protocol
//!
//! Every choice below reuses an existing sum-chain convention. Nothing here is a
//! consensus/wire decision: C1 is **dormant** (no `*_enabled_from_height` gate,
//! no `TxPayload` ordinal, no receipt code) and these rows are **never hashed
//! into a state root**. Like `state_diffs` / `contract_state_diffs`, they exist
//! only for local persistence and block-rollback revert, so the at-rest layout
//! is a local storage concern (migratable via [`C1_SCHEMA_VERSION`]), not frozen
//! bytes.
//!
//! * **Value codec** — `bincode` fixint little-endian, the near-universal
//!   at-rest convention in `sumchain-storage` (`AccountState`, `ContractMutation`,
//!   `StorageMetadataV2`, tokens, NFTs, …). ONE explicit config ([`c1_codec`]:
//!   fixint + little-endian + size limit) drives BOTH encode and decode, so they
//!   cannot drift; the decoder adds only the decode-time-only
//!   `.reject_trailing_bytes()`. That strict-decode discipline is lifted from
//!   `sumchain_wire::SignedTransaction::from_bytes` (the frozen-wire crate's
//!   canonical decoder). The `.with_limit()` anti-DoS ceiling bounds allocation.
//! * **Record versioning** — every value's first field is `schema_version: u8`,
//!   checked on decode. Forward migration = bump the tag. (Mirrors the `_v2` CF
//!   naming + `SUM-…:v1` digest domain tags used elsewhere.)
//! * **Keys** — manual, domain-prefixed, fixed-width **big-endian** composites,
//!   exactly like `StateStore`'s `b"acct" ‖ addr`, the NFT `collection ‖ token_id`
//!   key, and `storage_metadata`'s `root ‖ epoch_height ‖ archive`. Big-endian so
//!   composite ordering matches numeric ordering for range scans.
//! * **Revert** — a [`ComputePoolStateDiff`] journal of `(key, old, new)` records
//!   replayed in reverse into a single [`sumchain_storage::Database::batch`],
//!   deleting the journal in the same batch. This is the exact shape of
//!   `ContractStateDiff` + `StateManager::revert_block_state_diffs`, but this
//!   adapter drives it in isolation; it is not connected to the live PoA reorg
//!   path.
//!
//! ## Frozen identities
//!
//! [`crate::compute_pool::WorkItemKey`] `{ job_id, unit_id, generation }` and
//! [`UnitKey`](crate::compute_pool::UnitKey) `{ job_id, unit_id }` are preserved
//! unchanged; their persisted key bytes are defined by [`work_item_key_bytes`] /
//! [`unit_key_bytes`]. No transaction ordinal or receipt code is assigned.
//!
//! ## Deliberate boundary: storage/revert adapter, not wired to live PoA
//!
//! The subsystem is dormant, so nothing writes a C1 diff during live block
//! execution. To honor "no activation-path integration", this module is NOT
//! called from `consensus`'s `handle_reorg` / `StateManager::revert_block_state_
//! diffs`. Hooking it into the live PoA reorg driver is a separate, gated step.
//! The revert machinery here is complete and proven by the tests in isolation
//! (apply → revert → reapply).

use std::collections::BTreeMap;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, BlockHeight, Hash};
use sumchain_storage::{cf, Database};

use crate::compute_pool::{
    AcceptedLeaf, AssignmentIndexEntry, BondedOffer, ComputePoolModel, EntitlementId,
    EntitlementKind, EntitlementRecord, Job, JobId, JobState, OfferBondId, RequiredInput,
    Reservation, SlotId, UnitId, UnitState, WorkItemKey, WorkUnit,
};
use crate::{Result, StateError};

/// On-disk schema version stamped as the first byte of every C1 record value.
/// A future ratified layout bumps this; decoders reject any other value.
pub const C1_SCHEMA_VERSION: u8 = 1;

/// Local anti-DoS ceiling on a single decoded C1 record, in bytes. This is NOT a
/// consensus or economic cap (it is not `max_generations`, a retention cap, a
/// bond, or any B0 magnitude): it only bounds how many bytes a corrupt/hostile
/// value may make the decoder allocate. Records are tiny; 1 MiB is generous.
pub const C1_DECODE_BYTE_LIMIT: u64 = 1 << 20;

/// Domain tag for [`ComputePoolStore::state_digest`]. Separates the C1 state
/// commitment from every other digest domain (mirrors the `SUM-…:v1` /
/// `sumchain.supply.v1` domain-tag convention used elsewhere).
///
/// **Explicitly versioned** (`…state.v1`). This byte string is a FROZEN
/// consensus value once the compute-pool gate can open: it is committed into the
/// block state root, so any change to it (including the version suffix) is a
/// consensus-breaking change that REQUIRES a deliberate protocol version bump
/// (`…state.v2`) coordinated with activation — never an incidental edit. The
/// exact bytes are pinned by the golden test `c1_state_digest_domain_is_frozen`.
const C1_STATE_DIGEST_DOMAIN: &[u8] = b"sumchain.compute_pool.state.v1";

/// Encode a field byte-length as the canonical 4-byte little-endian frame prefix
/// used by [`ComputePoolStore::state_digest`], rejecting any length that does not
/// fit in `u32`.
///
/// A raw `len as u32` cast would SILENTLY TRUNCATE a `> u32::MAX` length,
/// producing an ambiguous frame (two different fields hashing identically) — a
/// consensus hazard. This checked conversion fails closed instead. For every
/// realistic length (`≤ u32::MAX`) the emitted bytes are byte-for-byte identical
/// to the old cast, so no frozen golden vector changes.
fn frame_len(n: usize) -> Result<[u8; 4]> {
    let framed = u32::try_from(n).map_err(|_| {
        StateError::InvalidOperation(format!(
            "C1 state digest: field length {n} exceeds u32::MAX; cannot frame unambiguously"
        ))
    })?;
    Ok(framed.to_le_bytes())
}

/// 1-byte domain/type prefixes for the shared C1 keyspace. Distinct per record
/// category, so two categories can never alias even at equal body length.
mod domain {
    pub const JOB: u8 = 0x01;
    pub const UNIT: u8 = 0x02;
    pub const OFFER: u8 = 0x03;
    pub const ACTIVE_OFFER_INDEX: u8 = 0x04;
    pub const RESERVATION: u8 = 0x05;
    pub const ACCEPTED_LEAF: u8 = 0x06;
    pub const ASSIGNMENT: u8 = 0x07;
    pub const ENTITLEMENT: u8 = 0x08;
}

// ---------------------------------------------------------------------------
// Canonical key encoders (domain prefix ‖ fixed-width big-endian body).
// ---------------------------------------------------------------------------

/// `[JOB] ‖ job_id(32)` (33 bytes).
pub fn job_key_bytes(job_id: &JobId) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(domain::JOB);
    k.extend_from_slice(job_id.as_bytes());
    k
}

/// `[UNIT] ‖ job_id(32) ‖ unit_id(32)` (65 bytes). Job id precedes unit id, so a
/// `unit_id` reused across two jobs yields two distinct keys (no collision).
pub fn unit_key_bytes(job_id: &JobId, unit_id: &UnitId) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32 + 32);
    k.push(domain::UNIT);
    k.extend_from_slice(job_id.as_bytes());
    k.extend_from_slice(unit_id.as_bytes());
    k
}

/// `[OFFER] ‖ offer_bond_id(32)` (33 bytes).
pub fn offer_key_bytes(offer_bond_id: &OfferBondId) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(domain::OFFER);
    k.extend_from_slice(offer_bond_id.as_bytes());
    k
}

/// `[ACTIVE_OFFER_INDEX] ‖ identity(20)` (21 bytes). Source-of-truth index for
/// the one-active-offer-per-identity invariant.
pub fn active_offer_index_key_bytes(identity: &Address) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 20);
    k.push(domain::ACTIVE_OFFER_INDEX);
    k.extend_from_slice(identity.as_bytes());
    k
}

/// `[RESERVATION] ‖ offer_bond_id(32)` (33 bytes).
pub fn reservation_key_bytes(offer_bond_id: &OfferBondId) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(domain::RESERVATION);
    k.extend_from_slice(offer_bond_id.as_bytes());
    k
}

/// Composite body for a [`WorkItemKey`]: `job_id(32) ‖ unit_id(32) ‖
/// generation(8, big-endian)`. Generation is big-endian so leaves/assignments
/// for a `(job, unit)` sort by generation.
fn work_item_body(key: &WorkItemKey) -> [u8; 72] {
    let mut b = [0u8; 72];
    b[0..32].copy_from_slice(key.job_id.as_bytes());
    b[32..64].copy_from_slice(key.unit_id.as_bytes());
    b[64..72].copy_from_slice(&key.generation.to_be_bytes());
    b
}

/// `[ACCEPTED_LEAF] ‖ job_id(32) ‖ unit_id(32) ‖ generation(8 BE)` (73 bytes).
pub fn accepted_leaf_key_bytes(key: &WorkItemKey) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 72);
    k.push(domain::ACCEPTED_LEAF);
    k.extend_from_slice(&work_item_body(key));
    k
}

/// `[ASSIGNMENT] ‖ job_id(32) ‖ unit_id(32) ‖ generation(8 BE)` (73 bytes).
pub fn assignment_key_bytes(key: &WorkItemKey) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 72);
    k.push(domain::ASSIGNMENT);
    k.extend_from_slice(&work_item_body(key));
    k
}

/// The frozen composite [`WorkItemKey`] key bytes (accepted-leaf domain). Exposed
/// so callers/tests can name the ratified identity's on-disk encoding directly.
pub fn work_item_key_bytes(key: &WorkItemKey) -> Vec<u8> {
    accepted_leaf_key_bytes(key)
}

/// `[ENTITLEMENT] ‖ entitlement_id(32)` (33 bytes).
pub fn entitlement_key_bytes(id: &EntitlementId) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32);
    k.push(domain::ENTITLEMENT);
    k.extend_from_slice(id.as_bytes());
    k
}

// ---------------------------------------------------------------------------
// Canonical value codec — ONE explicit config for BOTH encode and decode.
//
// [`c1_codec`] fully pins the byte format (fixint + little-endian + size limit);
// encode and decode both derive from it, so they can never drift. This produces
// exactly `bincode::serialize`'s fixint-LE bytes, but is explicit rather than
// relying on the top-level defaults. `.reject_trailing_bytes()` is the only
// decode-time-only refinement (an encoder cannot emit trailing bytes); it makes
// the decoder demand exactly one record and nothing more, exactly as the
// `sumchain_wire::SignedTransaction::from_bytes` canonical decoder does.
// ---------------------------------------------------------------------------

/// The single, explicit C1 record codec configuration (fixint, little-endian,
/// size-limited). Both [`c1_encode`] and [`c1_decode`] build on this, so the
/// encoder and decoder share one source of truth for the byte format.
fn c1_codec() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(C1_DECODE_BYTE_LIMIT)
}

fn c1_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    c1_codec()
        .serialize(value)
        .map_err(|e| StateError::SerializationError(e.to_string()))
}

fn c1_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    c1_codec()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| StateError::DeserializationError(e.to_string()))
}

// --- enum <-> canonical u8 tag (explicit; invalid tags are rejected) ---

fn job_state_tag(s: JobState) -> u8 {
    match s {
        JobState::Open => 0,
        JobState::Cancelled => 1,
        JobState::Halted => 2,
    }
}
fn job_state_from_tag(t: u8) -> Result<JobState> {
    match t {
        0 => Ok(JobState::Open),
        1 => Ok(JobState::Cancelled),
        2 => Ok(JobState::Halted),
        other => Err(StateError::DeserializationError(format!(
            "invalid JobState tag {other}"
        ))),
    }
}

fn unit_state_tag(s: UnitState) -> u8 {
    match s {
        UnitState::Blocked => 0,
        UnitState::Eligible => 1,
        UnitState::Assigned => 2,
        UnitState::Accepted => 3,
        UnitState::Reassignable => 4,
        UnitState::AssignmentHalted => 5,
    }
}
fn unit_state_from_tag(t: u8) -> Result<UnitState> {
    match t {
        0 => Ok(UnitState::Blocked),
        1 => Ok(UnitState::Eligible),
        2 => Ok(UnitState::Assigned),
        3 => Ok(UnitState::Accepted),
        4 => Ok(UnitState::Reassignable),
        5 => Ok(UnitState::AssignmentHalted),
        other => Err(StateError::DeserializationError(format!(
            "invalid UnitState tag {other}"
        ))),
    }
}

fn entitlement_kind_tag(k: EntitlementKind) -> u8 {
    match k {
        EntitlementKind::AcceptReimb => 0,
        EntitlementKind::ReassignReimb => 1,
        EntitlementKind::ReprovisionReimb => 2,
    }
}
fn entitlement_kind_from_tag(t: u8) -> Result<EntitlementKind> {
    match t {
        0 => Ok(EntitlementKind::AcceptReimb),
        1 => Ok(EntitlementKind::ReassignReimb),
        2 => Ok(EntitlementKind::ReprovisionReimb),
        other => Err(StateError::DeserializationError(format!(
            "invalid EntitlementKind tag {other}"
        ))),
    }
}

fn check_version(v: u8) -> Result<()> {
    if v == C1_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(StateError::DeserializationError(format!(
            "unsupported C1 schema version {v} (expected {C1_SCHEMA_VERSION})"
        )))
    }
}

// ---------------------------------------------------------------------------
// Stored value DTOs. Pure `serde` mirrors of the model records (ids as raw
// fixed-width arrays, enums as u8 tags). `schema_version` is the first field so
// it is byte 0 of every value. These are `pub` so adversarial tests can build
// malformed bytes; they are NOT the model types and carry no invariants of their
// own beyond canonical decode + tag/version validity.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredJob {
    pub schema_version: u8,
    pub job_id: [u8; 32],
    pub requester: [u8; 20],
    pub r_job: u32,
    pub job_max_retention_files: u128,
    pub requester_debit: u128,
    pub state_tag: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRequiredInput {
    pub predecessor: [u8; 32],
    pub required_output_slot_id: [u8; 32],
    pub pred_output_manifest_root: [u8; 32],
    pub required_slot_state_object_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWorkUnit {
    pub schema_version: u8,
    pub job_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub predecessors: Vec<[u8; 32]>,
    pub required_inputs: Vec<StoredRequiredInput>,
    pub generation: u64,
    pub state_tag: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredOffer {
    pub schema_version: u8,
    pub offer_bond_id: [u8; 32],
    pub identity: [u8; 20],
    pub payment_addr: [u8; 20],
    pub offered_bytes: u128,
    pub offer_seq: u64,
    pub bond_locked: u128,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredActiveOfferIndex {
    pub schema_version: u8,
    pub identity: [u8; 20],
    pub offer_bond_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReservation {
    pub schema_version: u8,
    pub offer_bond_id: [u8; 32],
    pub offered: u128,
    pub reserved: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAcceptedLeaf {
    pub schema_version: u8,
    pub job_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub generation: u64,
    pub offer_bond_id: [u8; 32],
    pub commit_bond_id: [u8; 32],
    pub accepted_bytes: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAssignment {
    pub schema_version: u8,
    pub job_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub generation: u64,
    pub winner_offer_bond_id: [u8; 32],
    pub winner_payment_addr: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEntitlement {
    pub schema_version: u8,
    pub entitlement_id: [u8; 32],
    pub beneficiary: [u8; 20],
    pub kind_tag: u8,
    pub amount: u128,
}

// --- model -> Stored (persist path) ---

impl StoredJob {
    fn from_model(j: &Job) -> Self {
        Self {
            schema_version: C1_SCHEMA_VERSION,
            job_id: *j.job_id.as_bytes(),
            requester: *j.requester.as_bytes(),
            r_job: j.r_job,
            job_max_retention_files: j.job_max_retention_files,
            requester_debit: j.requester_debit,
            state_tag: job_state_tag(j.state),
        }
    }
    /// The typed [`JobState`], validating the stored tag.
    pub fn state(&self) -> Result<JobState> {
        job_state_from_tag(self.state_tag)
    }
}

impl StoredWorkUnit {
    fn from_model(u: &WorkUnit) -> Self {
        Self {
            schema_version: C1_SCHEMA_VERSION,
            job_id: *u.job_id.as_bytes(),
            unit_id: *u.unit_id.as_bytes(),
            predecessors: u.predecessors.iter().map(|p| *p.as_bytes()).collect(),
            required_inputs: u
                .required_inputs
                .iter()
                .map(|ri| StoredRequiredInput {
                    predecessor: *ri.predecessor.as_bytes(),
                    required_output_slot_id: *ri.required_output_slot_id.as_bytes(),
                    pred_output_manifest_root: *ri.pred_output_manifest_root.as_bytes(),
                    required_slot_state_object_root: *ri.required_slot_state_object_root.as_bytes(),
                })
                .collect(),
            generation: u.generation,
            state_tag: unit_state_tag(u.state),
        }
    }
    /// The typed [`UnitState`], validating the stored tag.
    pub fn state(&self) -> Result<UnitState> {
        unit_state_from_tag(self.state_tag)
    }
    /// Reconstruct the model [`WorkUnit`] (validating enum tag).
    pub fn to_model(&self) -> Result<WorkUnit> {
        Ok(WorkUnit {
            job_id: JobId::from_bytes(self.job_id),
            unit_id: UnitId::from_bytes(self.unit_id),
            predecessors: self
                .predecessors
                .iter()
                .map(|p| UnitId::from_bytes(*p))
                .collect(),
            required_inputs: self
                .required_inputs
                .iter()
                .map(|ri| RequiredInput {
                    predecessor: UnitId::from_bytes(ri.predecessor),
                    required_output_slot_id: SlotId::from_bytes(ri.required_output_slot_id),
                    pred_output_manifest_root: Hash::new(ri.pred_output_manifest_root),
                    required_slot_state_object_root: Hash::new(ri.required_slot_state_object_root),
                })
                .collect(),
            generation: self.generation,
            state: self.state()?,
        })
    }
}

impl StoredOffer {
    fn from_model(o: &BondedOffer) -> Self {
        Self {
            schema_version: C1_SCHEMA_VERSION,
            offer_bond_id: *o.offer_bond_id.as_bytes(),
            identity: *o.identity.as_bytes(),
            payment_addr: *o.payment_addr.as_bytes(),
            offered_bytes: o.offered_bytes,
            offer_seq: o.offer_seq,
            bond_locked: o.bond_locked,
            active: o.active,
        }
    }
}

impl StoredReservation {
    fn from_model(r: &Reservation) -> Self {
        Self {
            schema_version: C1_SCHEMA_VERSION,
            offer_bond_id: *r.offer_bond_id.as_bytes(),
            offered: r.offered,
            reserved: r.reserved,
        }
    }
    /// Storage-level consistency guard (corruption detection): a persisted
    /// reservation must satisfy the ratified `reserved <= offered` invariant.
    fn validate_invariant(&self) -> Result<()> {
        if self.reserved > self.offered {
            return Err(StateError::DeserializationError(format!(
                "corrupt reservation: reserved {} > offered {}",
                self.reserved, self.offered
            )));
        }
        Ok(())
    }
}

impl StoredAcceptedLeaf {
    fn from_model(l: &AcceptedLeaf) -> Self {
        Self {
            schema_version: C1_SCHEMA_VERSION,
            job_id: *l.key.job_id.as_bytes(),
            unit_id: *l.key.unit_id.as_bytes(),
            generation: l.key.generation,
            offer_bond_id: *l.offer_bond_id.as_bytes(),
            commit_bond_id: *l.commit_bond_id.as_bytes(),
            accepted_bytes: l.accepted_bytes,
        }
    }
    /// The composite [`WorkItemKey`] this leaf belongs to.
    pub fn work_item_key(&self) -> WorkItemKey {
        WorkItemKey::new(
            JobId::from_bytes(self.job_id),
            UnitId::from_bytes(self.unit_id),
            self.generation,
        )
    }
}

impl StoredAssignment {
    fn from_model(a: &AssignmentIndexEntry) -> Self {
        Self {
            schema_version: C1_SCHEMA_VERSION,
            job_id: *a.key.job_id.as_bytes(),
            unit_id: *a.key.unit_id.as_bytes(),
            generation: a.key.generation,
            winner_offer_bond_id: *a.winner_offer_bond_id.as_bytes(),
            winner_payment_addr: *a.winner_payment_addr.as_bytes(),
        }
    }
}

impl StoredEntitlement {
    fn from_model(e: &EntitlementRecord) -> Self {
        Self {
            schema_version: C1_SCHEMA_VERSION,
            entitlement_id: *e.entitlement_id.as_bytes(),
            beneficiary: *e.beneficiary.as_bytes(),
            kind_tag: entitlement_kind_tag(e.kind),
            amount: e.amount,
        }
    }
    /// The typed [`EntitlementKind`], validating the stored tag.
    pub fn kind(&self) -> Result<EntitlementKind> {
        entitlement_kind_from_tag(self.kind_tag)
    }
}

// --- typed public decoders (canonical decode + version + tag/invariant checks) ---

macro_rules! typed_decoder {
    ($name:ident, $ty:ty, $doc:literal) => {
        #[doc = $doc]
        pub fn $name(bytes: &[u8]) -> Result<$ty> {
            let v: $ty = c1_decode(bytes)?;
            check_version(v.schema_version)?;
            Ok(v)
        }
    };
}

typed_decoder!(
    decode_job,
    StoredJob,
    "Canonically decode a stored job value."
);
typed_decoder!(
    decode_offer,
    StoredOffer,
    "Canonically decode a stored bonded-offer value."
);
typed_decoder!(
    decode_active_offer_index,
    StoredActiveOfferIndex,
    "Canonically decode a stored active-offer index value."
);
typed_decoder!(
    decode_accepted_leaf,
    StoredAcceptedLeaf,
    "Canonically decode a stored accepted-leaf value."
);
typed_decoder!(
    decode_assignment,
    StoredAssignment,
    "Canonically decode a stored assignment value."
);

/// Canonically decode a stored work-unit value, validating version and the unit
/// state tag.
pub fn decode_work_unit(bytes: &[u8]) -> Result<StoredWorkUnit> {
    let v: StoredWorkUnit = c1_decode(bytes)?;
    check_version(v.schema_version)?;
    v.state()?; // reject an invalid unit-state tag eagerly
    Ok(v)
}

/// Canonically decode a stored reservation, validating version and the
/// `reserved <= offered` consistency invariant.
pub fn decode_reservation(bytes: &[u8]) -> Result<StoredReservation> {
    let v: StoredReservation = c1_decode(bytes)?;
    check_version(v.schema_version)?;
    v.validate_invariant()?;
    Ok(v)
}

/// Canonically decode a stored entitlement, validating version and kind tag.
pub fn decode_entitlement(bytes: &[u8]) -> Result<StoredEntitlement> {
    let v: StoredEntitlement = c1_decode(bytes)?;
    check_version(v.schema_version)?;
    v.kind()?;
    Ok(v)
}

// ---------------------------------------------------------------------------
// Per-block revert journal (mirrors `ContractStateDiff`).
// ---------------------------------------------------------------------------

/// One C1 state mutation captured for block-rollback revert. `key` is the raw
/// domain-prefixed row key in [`cf::COMPUTE_POOL_STATE`]; `old`/`new` are the
/// pre/post value bytes (`None` = absent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputePoolMutation {
    pub key: Vec<u8>,
    pub old: Option<Vec<u8>>,
    pub new: Option<Vec<u8>>,
}

/// Per-block journal of C1 state mutations for block-rollback revert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputePoolStateDiff {
    pub records: Vec<ComputePoolMutation>,
}

impl ComputePoolStateDiff {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Sort mutations deterministically by key. Called before persistence so the
    /// journal bytes are insertion-order independent.
    pub fn sort(&mut self) {
        self.records.sort_by(|a, b| a.key.cmp(&b.key));
    }
}

// ---------------------------------------------------------------------------
// Store: materialize a model, persist a validated transition atomically, revert.
// ---------------------------------------------------------------------------

/// Persistence adapter for the dormant C1 compute-pool state.
pub struct ComputePoolStore<'a> {
    db: &'a Database,
}

impl<'a> ComputePoolStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// The canonical `key -> value` row set for a model snapshot. Built from the
    /// model's public enumerators, so it is a deterministic function of model
    /// *content* only — never of map insertion order (every backing map is a
    /// `BTreeMap`). The active-offer index is derived from `active` offers, which
    /// is exactly the model's own source of truth for that invariant.
    ///
    /// A `BTreeMap` is returned so iteration/serialization is canonical.
    pub fn materialize(model: &ComputePoolModel) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

        for j in model.jobs() {
            rows.insert(
                job_key_bytes(&j.job_id),
                c1_encode(&StoredJob::from_model(j))?,
            );
        }
        for u in model.units_in_canonical_order() {
            rows.insert(
                unit_key_bytes(&u.job_id, &u.unit_id),
                c1_encode(&StoredWorkUnit::from_model(u))?,
            );
        }
        for o in model.offers() {
            rows.insert(
                offer_key_bytes(&o.offer_bond_id),
                c1_encode(&StoredOffer::from_model(o))?,
            );
            // Derive the active-offer index from the offer's own `active` flag —
            // the model guarantees at most one active offer per identity.
            if o.active {
                rows.insert(
                    active_offer_index_key_bytes(&o.identity),
                    c1_encode(&StoredActiveOfferIndex {
                        schema_version: C1_SCHEMA_VERSION,
                        identity: *o.identity.as_bytes(),
                        offer_bond_id: *o.offer_bond_id.as_bytes(),
                    })?,
                );
            }
        }
        for r in model.reservations() {
            rows.insert(
                reservation_key_bytes(&r.offer_bond_id),
                c1_encode(&StoredReservation::from_model(r))?,
            );
        }
        for l in model.accepted_leaves() {
            rows.insert(
                accepted_leaf_key_bytes(&l.key),
                c1_encode(&StoredAcceptedLeaf::from_model(l))?,
            );
        }
        for a in model.assignments() {
            rows.insert(
                assignment_key_bytes(&a.key),
                c1_encode(&StoredAssignment::from_model(a))?,
            );
        }
        for e in model.entitlements() {
            rows.insert(
                entitlement_key_bytes(&e.entitlement_id),
                c1_encode(&StoredEntitlement::from_model(e))?,
            );
        }
        Ok(rows)
    }

    /// Read the full persisted C1 `key -> value` row set (canonical order).
    pub fn load_state_map(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut map = BTreeMap::new();
        for (k, v) in self.db.iter(cf::COMPUTE_POOL_STATE)? {
            map.insert(k.to_vec(), v.to_vec());
        }
        Ok(map)
    }

    /// Deterministic, domain-separated digest over the FULL persisted C1 state.
    ///
    /// Built from [`load_state_map`](Self::load_state_map), whose rows are
    /// `BTreeMap`-ordered and content-addressed (never insertion-order
    /// dependent), so every validator computes the identical digest. The block
    /// executor folds this into the block state root **only when the compute-pool
    /// gate is open**, binding every persisted C1 row into the consensus
    /// commitment; while the gate is `None` (production default) it is never
    /// folded, so dormant block roots are byte-for-byte unchanged.
    ///
    /// Encoding: `DOMAIN ‖ for each (key, value): key_len(u32 LE) ‖ key ‖
    /// val_len(u32 LE) ‖ value`. Length prefixes make the concatenation
    /// unambiguous; the empty state hashes to the domain-only digest.
    pub fn state_digest(&self) -> Result<Hash> {
        let rows = self.load_state_map()?;
        let mut buf: Vec<u8> = Vec::with_capacity(C1_STATE_DIGEST_DOMAIN.len());
        buf.extend_from_slice(C1_STATE_DIGEST_DOMAIN);
        for (k, v) in &rows {
            buf.extend_from_slice(&frame_len(k.len())?);
            buf.extend_from_slice(k);
            buf.extend_from_slice(&frame_len(v.len())?);
            buf.extend_from_slice(v);
        }
        Ok(Hash::hash(&buf))
    }

    /// Load + canonically decode the per-height revert journal (`None` if absent,
    /// e.g. always under the dormant gate, which writes no journal).
    pub fn load_journal(&self, height: BlockHeight) -> Result<Option<ComputePoolStateDiff>> {
        match self
            .db
            .get(cf::COMPUTE_POOL_STATE_DIFFS, &height.to_be_bytes())?
        {
            Some(bytes) => Ok(Some(c1_decode(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Persist the transition `before -> after` for `height` **atomically**.
    ///
    /// Exactly ONE finalized C1 transition may commit per block height. This is
    /// enforced with two hard preconditions checked BEFORE any write:
    ///
    /// * **Duplicate-height rejection** — if a journal already exists at
    ///   `height`, the call is rejected ([`StateError::InvalidOperation`]) so a
    ///   later transition can never overwrite an earlier journal (which would
    ///   silently drop the earlier block's mutations and make block-rollback
    ///   revert incomplete).
    /// * **Stale-predecessor rejection** — the caller's claimed predecessor
    ///   (`before`, materialized; `None` = empty) must byte-for-byte match the
    ///   live persisted C1 state. If it does not, the call is rejected rather
    ///   than silently deriving a transition against a different live state.
    ///
    /// The delta is every key whose value differs between the two model
    /// snapshots. Because `before` is verified equal to the live state, the
    /// captured `old` (from the live state) is exactly the claimed predecessor,
    /// so a later [`revert_block`] restores precisely what was there. ALL record
    /// writes/deletes and the journal write are staged into a single
    /// [`Database::batch`] and committed once: any error returns before `commit`,
    /// so a rejected/failed transition writes nothing (no partial state).
    ///
    /// Returns the number of mutated rows.
    pub fn persist_transition(
        &self,
        before: Option<&ComputePoolModel>,
        after: &ComputePoolModel,
        height: BlockHeight,
    ) -> Result<usize> {
        // (1) Duplicate-height guard: one finalized transition per block. Checked
        // first, before any computation or write.
        if self.has_journal(height)? {
            return Err(StateError::InvalidOperation(format!(
                "C1 transition already finalized at height {height}; refusing to \
                 overwrite the existing journal"
            )));
        }

        let before_rows = match before {
            Some(m) => Self::materialize(m)?,
            None => BTreeMap::new(),
        };

        // (2) Stale-predecessor guard: the claimed `before` must match live state.
        let live = self.load_state_map()?;
        if before_rows != live {
            return Err(StateError::InvalidOperation(
                "C1 persist_transition: stale `before` snapshot does not match the \
                 live persisted state; refusing to derive a transition from a \
                 different predecessor"
                    .to_string(),
            ));
        }

        let after_rows = Self::materialize(after)?;

        // Union of touched keys (BTreeSet-like via BTreeMap keys), canonical order.
        let mut keys: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        for k in before_rows.keys().chain(after_rows.keys()) {
            keys.insert(k.clone(), ());
        }

        // --- validate-all / build the whole batch BEFORE committing anything ---
        let mut diff = ComputePoolStateDiff::new();
        let mut batch = self.db.batch();
        for key in keys.keys() {
            let new = after_rows.get(key).cloned();
            // `old` is the verified predecessor value (live == before_rows).
            let old = live.get(key).cloned();
            if old == new {
                continue; // unchanged; nothing to journal
            }
            match &new {
                Some(v) => batch.put(cf::COMPUTE_POOL_STATE, key, v)?,
                None => batch.delete(cf::COMPUTE_POOL_STATE, key)?,
            }
            diff.records.push(ComputePoolMutation {
                key: key.clone(),
                old,
                new,
            });
        }

        if diff.is_empty() {
            return Ok(0); // no-op; do not write an empty journal
        }
        diff.sort();
        let journal = c1_encode(&diff)?;
        batch.put(
            cf::COMPUTE_POOL_STATE_DIFFS,
            &height.to_be_bytes(),
            &journal,
        )?;

        let mutated = diff.records.len();
        batch.commit()?; // single atomic commit — all-or-nothing
        Ok(mutated)
    }

    /// Whether a per-block C1 journal exists for `height`.
    pub fn has_journal(&self, height: BlockHeight) -> Result<bool> {
        Ok(self
            .db
            .contains(cf::COMPUTE_POOL_STATE_DIFFS, &height.to_be_bytes())?)
    }

    /// Stage the reverse-replay of the per-height C1 journal (and the journal's
    /// own deletion) into a caller-provided
    /// [`WriteBatch`](sumchain_storage::db::WriteBatch), returning whether
    /// anything was staged (`false` when no journal exists at `height` — e.g.
    /// ALWAYS under the dormant gate, which writes no journal).
    ///
    /// This is the seam that lets the C1 revert compose into the SAME atomic
    /// write as the account + contract revert: the live reorg driver
    /// ([`crate::state::StateManager::revert_block_state_diffs`]) stages account,
    /// contract, AND C1 restores into one batch and commits once, so a crash can
    /// never leave a partially-reverted node (all families revert or none do).
    ///
    /// Mutations are replayed in REVERSE record order (restore `old`, or delete
    /// when `old` is `None`). Every key's domain prefix is validated BEFORE it is
    /// staged, so a corrupt journal returns an error with nothing staged; because
    /// the caller only commits on success, a corrupt C1 journal aborts the whole
    /// multi-family revert and preserves every diff for retry.
    pub fn stage_block_revert(
        &self,
        batch: &mut sumchain_storage::db::WriteBatch<'_>,
        height: BlockHeight,
    ) -> Result<bool> {
        let hkey = height.to_be_bytes();
        let Some(bytes) = self.db.get(cf::COMPUTE_POOL_STATE_DIFFS, &hkey)? else {
            return Ok(false); // nothing to revert
        };
        let diff: ComputePoolStateDiff = c1_decode(&bytes)?;

        for record in diff.records.iter().rev() {
            // Validate the key domain before staging (corruption guard).
            match record.key.first() {
                Some(
                    &domain::JOB
                    | &domain::UNIT
                    | &domain::OFFER
                    | &domain::ACTIVE_OFFER_INDEX
                    | &domain::RESERVATION
                    | &domain::ACCEPTED_LEAF
                    | &domain::ASSIGNMENT
                    | &domain::ENTITLEMENT,
                ) => {}
                other => {
                    return Err(StateError::InvalidOperation(format!(
                        "C1 revert: unrecognized key domain {other:?} at height {height}"
                    )));
                }
            }
            match &record.old {
                Some(v) => batch.put(cf::COMPUTE_POOL_STATE, &record.key, v)?,
                None => batch.delete(cf::COMPUTE_POOL_STATE, &record.key)?,
            }
        }
        batch.delete(cf::COMPUTE_POOL_STATE_DIFFS, &hkey)?;
        Ok(true)
    }

    /// Atomically revert the C1 state mutations recorded for `height` in
    /// isolation (its own [`Database::batch`]).
    ///
    /// Thin wrapper over [`stage_block_revert`](Self::stage_block_revert): stages
    /// the reverse-replay into a fresh batch and commits it. A corrupt journal
    /// propagates the error with nothing committed and the journal preserved for
    /// retry. Retained for the standalone store/manager tests; the LIVE reorg
    /// path drives `stage_block_revert` into the unified account+contract+C1
    /// batch instead (one commit, crash-consistent across all families).
    pub fn revert_block(&self, height: BlockHeight) -> Result<()> {
        let mut batch = self.db.batch();
        if self.stage_block_revert(&mut batch, height)? {
            batch.commit()?; // single atomic commit
        }
        Ok(())
    }

    // --- typed point reads (canonical decode) ---

    /// Read + canonically decode the stored job for `job_id`.
    pub fn get_job(&self, job_id: &JobId) -> Result<Option<StoredJob>> {
        match self
            .db
            .get(cf::COMPUTE_POOL_STATE, &job_key_bytes(job_id))?
        {
            Some(b) => {
                let j = decode_job(&b)?;
                if &j.job_id != job_id.as_bytes() {
                    return Err(StateError::DeserializationError(
                        "job value/key id mismatch (corruption)".into(),
                    ));
                }
                Ok(Some(j))
            }
            None => Ok(None),
        }
    }

    /// Read + canonically decode the stored work unit for `(job_id, unit_id)`.
    pub fn get_unit(&self, job_id: &JobId, unit_id: &UnitId) -> Result<Option<StoredWorkUnit>> {
        match self
            .db
            .get(cf::COMPUTE_POOL_STATE, &unit_key_bytes(job_id, unit_id))?
        {
            Some(b) => Ok(Some(decode_work_unit(&b)?)),
            None => Ok(None),
        }
    }

    /// Read + canonically decode the stored offer for `offer_bond_id`.
    pub fn get_offer(&self, offer_bond_id: &OfferBondId) -> Result<Option<StoredOffer>> {
        match self
            .db
            .get(cf::COMPUTE_POOL_STATE, &offer_key_bytes(offer_bond_id))?
        {
            Some(b) => Ok(Some(decode_offer(&b)?)),
            None => Ok(None),
        }
    }

    /// Read the active-offer id for an identity (the one-active-offer index).
    pub fn active_offer_of(&self, identity: &Address) -> Result<Option<OfferBondId>> {
        match self.db.get(
            cf::COMPUTE_POOL_STATE,
            &active_offer_index_key_bytes(identity),
        )? {
            Some(b) => {
                let idx = decode_active_offer_index(&b)?;
                Ok(Some(OfferBondId::from_bytes(idx.offer_bond_id)))
            }
            None => Ok(None),
        }
    }

    /// Read + canonically decode the stored reservation for `offer_bond_id`.
    pub fn get_reservation(
        &self,
        offer_bond_id: &OfferBondId,
    ) -> Result<Option<StoredReservation>> {
        match self.db.get(
            cf::COMPUTE_POOL_STATE,
            &reservation_key_bytes(offer_bond_id),
        )? {
            Some(b) => Ok(Some(decode_reservation(&b)?)),
            None => Ok(None),
        }
    }

    /// Read + canonically decode the accepted leaf for a work item.
    pub fn get_accepted_leaf(&self, key: &WorkItemKey) -> Result<Option<StoredAcceptedLeaf>> {
        match self
            .db
            .get(cf::COMPUTE_POOL_STATE, &accepted_leaf_key_bytes(key))?
        {
            Some(b) => Ok(Some(decode_accepted_leaf(&b)?)),
            None => Ok(None),
        }
    }

    /// Read + canonically decode the assignment for a work item.
    pub fn get_assignment(&self, key: &WorkItemKey) -> Result<Option<StoredAssignment>> {
        match self
            .db
            .get(cf::COMPUTE_POOL_STATE, &assignment_key_bytes(key))?
        {
            Some(b) => Ok(Some(decode_assignment(&b)?)),
            None => Ok(None),
        }
    }

    /// Read + canonically decode the entitlement for `id`.
    pub fn get_entitlement(&self, id: &EntitlementId) -> Result<Option<StoredEntitlement>> {
        match self
            .db
            .get(cf::COMPUTE_POOL_STATE, &entitlement_key_bytes(id))?
        {
            Some(b) => Ok(Some(decode_entitlement(&b)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_pool::{
        BondedOffer, CommitBondId, ComputePoolModel, EntitlementKind, EntitlementRecord,
        ExposureInputs, UnitSizing, WorkUnit,
    };
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn open_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    // ── C1 state-commitment golden vectors (issue #163) ──────────────────────
    //
    // These FREEZE the deterministic C1 state digest that the block executor
    // folds into the block state root once the compute-pool gate is open. They
    // are a CONSENSUS surface at activation: if any value below changes, the
    // on-chain commitment changed, and the digest MUST be re-versioned
    // (`C1_STATE_DIGEST_DOMAIN` → `…state.v2`) as a deliberate, activation-
    // coordinated protocol bump — never an incidental edit.

    /// The domain tag is EXPLICITLY VERSIONED (`…state.v1`) and its exact bytes
    /// are frozen. A change requires a deliberate `v2` bump (see the const doc).
    #[test]
    fn c1_state_digest_domain_is_frozen() {
        assert_eq!(C1_STATE_DIGEST_DOMAIN, b"sumchain.compute_pool.state.v1");
        assert_eq!(
            hex::encode(C1_STATE_DIGEST_DOMAIN),
            "73756d636861696e2e636f6d707574655f706f6f6c2e73746174652e7631"
        );
        assert!(
            C1_STATE_DIGEST_DOMAIN.ends_with(b".v1"),
            "domain must carry an explicit version tag"
        );
    }

    /// Empty-store digest == the domain-only blake3 (frozen).
    #[test]
    fn c1_state_digest_empty_is_frozen() {
        let (db, _d) = open_db();
        assert_eq!(
            hex::encode(ComputePoolStore::new(&db).state_digest().unwrap().as_bytes()),
            "6ef6a51fb97c160d331253b7848af5306d7b67d1d669a2e3175a4a7af0271e75"
        );
    }

    /// Fixed one-row digest (frozen).
    #[test]
    fn c1_state_digest_one_row_is_frozen() {
        let (db, _d) = open_db();
        db.put(cf::COMPUTE_POOL_STATE, &[0x01, 0x02, 0x03], &[0xAA, 0xBB])
            .unwrap();
        assert_eq!(
            hex::encode(ComputePoolStore::new(&db).state_digest().unwrap().as_bytes()),
            "55f9b92fa394be2d2392c07fa0d197600dbee9aa62f9ee2ca1bb1f49ec060414"
        );
    }

    /// Fixed multi-row digest (frozen) with PROOF of (a) canonical key ordering
    /// and (b) insertion-order independence: a scrambled and a sorted insertion
    /// order produce the identical frozen digest.
    #[test]
    fn c1_state_digest_multi_row_is_frozen_and_order_independent() {
        const MULTI_HEX: &str =
            "c5ea8d063768eb42a69ac3989f44c86e4ba5e020fe1d7310673c3026415c302c";
        let rows: [(&[u8], &[u8]); 3] =
            [(b"\x01k1", b"v1"), (b"\x02k2", b"val2"), (b"\x03k3", b"value3")];

        // Sorted insertion order.
        let (db_sorted, _s) = open_db();
        for (k, v) in rows {
            db_sorted.put(cf::COMPUTE_POOL_STATE, k, v).unwrap();
        }
        let d_sorted = ComputePoolStore::new(&db_sorted).state_digest().unwrap();

        // Scrambled insertion order.
        let (db_scram, _c) = open_db();
        for (k, v) in [rows[2], rows[0], rows[1]] {
            db_scram.put(cf::COMPUTE_POOL_STATE, k, v).unwrap();
        }
        let d_scram = ComputePoolStore::new(&db_scram).state_digest().unwrap();

        assert_eq!(hex::encode(d_sorted.as_bytes()), MULTI_HEX, "multi-row digest drifted");
        assert_eq!(
            d_sorted, d_scram,
            "digest must be insertion-order independent (canonical key order)"
        );
    }

    /// The u32 length prefixes make the concatenation UNAMBIGUOUS: `(key="ab",
    /// val="c")` and `(key="a", val="bc")` share identical unframed bytes yet
    /// hash to DIFFERENT frozen digests.
    #[test]
    fn c1_state_digest_length_framing_is_unambiguous() {
        let (db1, _d1) = open_db();
        db1.put(cf::COMPUTE_POOL_STATE, b"ab", b"c").unwrap();
        let ab_c = ComputePoolStore::new(&db1).state_digest().unwrap();

        let (db2, _d2) = open_db();
        db2.put(cf::COMPUTE_POOL_STATE, b"a", b"bc").unwrap();
        let a_bc = ComputePoolStore::new(&db2).state_digest().unwrap();

        assert_eq!(
            hex::encode(ab_c.as_bytes()),
            "3046df96a519ddd677fe8a2dea8ce95f755549bb7b358e6f7e4a7d48f5c9b4fa"
        );
        assert_eq!(
            hex::encode(a_bc.as_bytes()),
            "e73b22e6b2b6e45668e03488aaf501c17d195fa268ccd335e1f294f2d6045418"
        );
        assert_ne!(
            ab_c, a_bc,
            "length framing must disambiguate equal concatenated bytes"
        );
    }

    /// `frame_len` is the CHECKED u32 conversion (replaces a silent `as u32`
    /// truncation): normal lengths emit exact LE bytes byte-identical to the old
    /// cast (so no golden moves), while a `> u32::MAX` length is REJECTED rather
    /// than framed ambiguously.
    #[test]
    fn frame_len_is_checked_and_matches_old_cast_in_range() {
        assert_eq!(frame_len(0).unwrap(), [0, 0, 0, 0]);
        assert_eq!(frame_len(5).unwrap(), 5u32.to_le_bytes());
        assert_eq!(frame_len(u32::MAX as usize).unwrap(), u32::MAX.to_le_bytes());
        // Byte-identical to the previous unchecked `n as u32` cast for every
        // in-range length ⇒ the checked conversion changes no frozen vector.
        for n in [1usize, 2, 3, 255, 256, 65_535, 1_000_000] {
            assert_eq!(frame_len(n).unwrap(), (n as u32).to_le_bytes());
        }
        // A length that overflows u32 is rejected (usize is 64-bit here).
        #[cfg(target_pointer_width = "64")]
        {
            let too_big = (u32::MAX as usize) + 1;
            assert!(matches!(
                frame_len(too_big),
                Err(StateError::InvalidOperation(_))
            ));
        }
    }

    fn jid(b: u8) -> JobId {
        JobId::from_bytes([b; 32])
    }
    fn uid(b: u8) -> UnitId {
        UnitId::from_bytes([b; 32])
    }
    fn oid(b: u8) -> OfferBondId {
        OfferBondId::from_bytes([b; 32])
    }
    fn addr(b: u8) -> Address {
        Address::new([b; 20])
    }

    fn exposure() -> ExposureInputs {
        ExposureInputs {
            q: 100,
            reprovision_allowance: 10,
            job_max_retention_files: 0, // overwritten in create_job
            max_reassignments_per_file: 2,
            reassign_reimb: 5,
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

    fn add_job(m: &mut ComputePoolModel, job: JobId, units: Vec<WorkUnit>) {
        let sizing: Vec<UnitSizing> = units.iter().map(|_| UnitSizing { slots: 0 }).collect();
        m.create_job(
            job,
            addr(9),
            1,
            units,
            &sizing,
            1,
            0,
            1_000,
            exposure(),
            1_000_000,
        )
        .unwrap();
    }

    fn active_offer(id: OfferBondId, identity: Address) -> BondedOffer {
        BondedOffer {
            offer_bond_id: id,
            identity,
            payment_addr: addr(50),
            offered_bytes: 1_000,
            offer_seq: 0,
            bond_locked: 500,
            active: true,
        }
    }

    /// A model exercising every persisted record category.
    fn full_model() -> ComputePoolModel {
        let mut m = ComputePoolModel::new();
        let j = jid(1);
        add_job(
            &mut m,
            j,
            vec![simple_unit(j, uid(2)), simple_unit(j, uid(3))],
        );
        m.publish_offer(active_offer(oid(3), addr(8))).unwrap();
        m.reserve_capacity(oid(3), 1_000, 60).unwrap();
        m.accept_leaf(AcceptedLeaf {
            key: WorkItemKey::new(j, uid(2), 0),
            offer_bond_id: oid(3),
            commit_bond_id: CommitBondId::from_bytes([4; 32]),
            accepted_bytes: 100,
        })
        .unwrap();
        m.put_assignment(AssignmentIndexEntry {
            key: WorkItemKey::new(j, uid(3), 0),
            winner_offer_bond_id: oid(3),
            winner_payment_addr: addr(50),
        })
        .unwrap();
        m.register_entitlement(EntitlementRecord {
            entitlement_id: EntitlementId::from_bytes([6; 32]),
            beneficiary: addr(7),
            kind: EntitlementKind::AcceptReimb,
            amount: 50,
        })
        .unwrap();
        m
    }

    // ---- round trip + faithful mapping ----

    #[test]
    fn persist_then_load_matches_materialize() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let m = full_model();

        let mutated = store.persist_transition(None, &m, 1).unwrap();
        assert!(mutated > 0);
        assert_eq!(
            store.load_state_map().unwrap(),
            ComputePoolStore::materialize(&m).unwrap(),
            "on-disk rows must equal the model's canonical materialization"
        );

        // Typed getters decode canonically and match the model content.
        assert_eq!(store.get_job(&jid(1)).unwrap().unwrap().r_job, 1);
        assert_eq!(
            store.get_reservation(&oid(3)).unwrap().unwrap().reserved,
            60
        );
        assert_eq!(
            store
                .get_accepted_leaf(&WorkItemKey::new(jid(1), uid(2), 0))
                .unwrap()
                .unwrap()
                .accepted_bytes,
            100
        );
        assert_eq!(
            store.active_offer_of(&addr(8)).unwrap(),
            Some(oid(3)),
            "active-offer index derived from the offer's active flag"
        );
    }

    #[test]
    fn reapplying_same_model_is_a_noop() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let m = full_model();
        store.persist_transition(None, &m, 1).unwrap();
        // before == after => zero mutations, no journal written.
        assert_eq!(store.persist_transition(Some(&m), &m, 2).unwrap(), 0);
        assert!(!store.has_journal(2).unwrap());
    }

    // ---- key identity: collision resistance, generation, prefix/type confusion ----

    #[test]
    fn cross_job_unit_id_collision_resistance() {
        // Same unit_id under two different jobs must yield distinct keys/rows.
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let mut m = ComputePoolModel::new();
        add_job(&mut m, jid(1), vec![simple_unit(jid(1), uid(9))]);
        add_job(&mut m, jid(2), vec![simple_unit(jid(2), uid(9))]);
        store.persist_transition(None, &m, 1).unwrap();

        assert_ne!(
            unit_key_bytes(&jid(1), &uid(9)),
            unit_key_bytes(&jid(2), &uid(9))
        );
        assert!(store.get_unit(&jid(1), &uid(9)).unwrap().is_some());
        assert!(store.get_unit(&jid(2), &uid(9)).unwrap().is_some());
        // Distinct rows.
        assert_eq!(store.load_state_map().unwrap().len(), 4); // 2 jobs + 2 units
    }

    #[test]
    fn generation_is_part_of_leaf_identity() {
        let g0 = WorkItemKey::new(jid(1), uid(2), 0);
        let g1 = WorkItemKey::new(jid(1), uid(2), 1);
        assert_ne!(accepted_leaf_key_bytes(&g0), accepted_leaf_key_bytes(&g1));
        // Big-endian generation => key order matches numeric order.
        assert!(accepted_leaf_key_bytes(&g0) < accepted_leaf_key_bytes(&g1));

        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let mut m = ComputePoolModel::new();
        add_job(&mut m, jid(1), vec![simple_unit(jid(1), uid(2))]);
        for g in [0u64, 1u64] {
            m.accept_leaf(AcceptedLeaf {
                key: WorkItemKey::new(jid(1), uid(2), g),
                offer_bond_id: oid(3),
                commit_bond_id: CommitBondId::from_bytes([4; 32]),
                accepted_bytes: 1,
            })
            .unwrap();
        }
        store.persist_transition(None, &m, 1).unwrap();
        assert!(store.get_accepted_leaf(&g0).unwrap().is_some());
        assert!(store.get_accepted_leaf(&g1).unwrap().is_some());
    }

    #[test]
    fn key_prefix_separates_categories_and_blocks_type_confusion() {
        // A job id and an offer id with identical 32 body bytes differ only by the
        // domain prefix => distinct keys, no collision.
        let same = [7u8; 32];
        assert_ne!(
            job_key_bytes(&JobId::from_bytes(same)),
            offer_key_bytes(&OfferBondId::from_bytes(same))
        );
        // Accepted-leaf vs assignment share the composite body but differ by prefix.
        let k = WorkItemKey::new(jid(1), uid(2), 0);
        assert_ne!(accepted_leaf_key_bytes(&k), assignment_key_bytes(&k));
        assert_eq!(
            accepted_leaf_key_bytes(&k)[1..],
            assignment_key_bytes(&k)[1..]
        );

        // Decoding a job value as an offer is rejected (length/shape mismatch).
        let job_bytes = c1_encode(&StoredJob::from_model(&Job {
            job_id: jid(1),
            requester: addr(9),
            r_job: 1,
            job_max_retention_files: 2,
            requester_debit: 130,
            state: JobState::Open,
        }))
        .unwrap();
        assert!(decode_offer(&job_bytes).is_err(), "type confusion rejected");
    }

    // ---- canonical decode: version, tag, truncation, trailing, oversized ----

    #[test]
    fn malformed_version_rejected() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        store.persist_transition(None, &full_model(), 1).unwrap();
        let mut bytes = db
            .get(cf::COMPUTE_POOL_STATE, &job_key_bytes(&jid(1)))
            .unwrap()
            .unwrap();
        assert!(decode_job(&bytes).is_ok());
        bytes[0] = C1_SCHEMA_VERSION.wrapping_add(1); // corrupt version byte
        assert!(decode_job(&bytes).is_err());
    }

    #[test]
    fn malformed_enum_tag_rejected() {
        // Invalid unit-state tag rejected at decode.
        let mut u = StoredWorkUnit {
            schema_version: C1_SCHEMA_VERSION,
            job_id: [1; 32],
            unit_id: [2; 32],
            predecessors: vec![],
            required_inputs: vec![],
            generation: 0,
            state_tag: 99,
        };
        assert!(decode_work_unit(&c1_encode(&u).unwrap()).is_err());
        u.state_tag = unit_state_tag(UnitState::Eligible);
        assert!(decode_work_unit(&c1_encode(&u).unwrap()).is_ok());

        // Invalid entitlement-kind tag rejected at decode.
        let ent = StoredEntitlement {
            schema_version: C1_SCHEMA_VERSION,
            entitlement_id: [6; 32],
            beneficiary: [7; 20],
            kind_tag: 200,
            amount: 1,
        };
        assert!(decode_entitlement(&c1_encode(&ent).unwrap()).is_err());
    }

    #[test]
    fn truncation_and_trailing_bytes_rejected() {
        let valid = c1_encode(&StoredEntitlement {
            schema_version: C1_SCHEMA_VERSION,
            entitlement_id: [6; 32],
            beneficiary: [7; 20],
            kind_tag: 0,
            amount: 1,
        })
        .unwrap();
        assert!(decode_entitlement(&valid).is_ok());
        // Truncated by one byte.
        assert!(decode_entitlement(&valid[..valid.len() - 1]).is_err());
        // One trailing byte appended.
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(decode_entitlement(&trailing).is_err());
        // A second full record concatenated is also rejected (no silent split).
        let mut doubled = valid.clone();
        doubled.extend_from_slice(&valid);
        assert!(decode_entitlement(&doubled).is_err());
    }

    #[test]
    fn oversized_collection_length_rejected() {
        // version(1) + job_id(32) + unit_id(32) + predecessors_len(u64 LE = huge).
        let mut bytes = vec![C1_SCHEMA_VERSION];
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        // Decoder must refuse (byte-limit / short buffer), never pre-allocate.
        assert!(decode_work_unit(&bytes).is_err());
    }

    #[test]
    fn corrupt_reservation_invariant_rejected() {
        // reserved > offered is a storage-level corruption; decode rejects it.
        let bad = c1_encode(&StoredReservation {
            schema_version: C1_SCHEMA_VERSION,
            offer_bond_id: [3; 32],
            offered: 100,
            reserved: 101,
        })
        .unwrap();
        assert!(decode_reservation(&bad).is_err());
    }

    // ---- insertion-order independence ----

    #[test]
    fn materialization_is_insertion_order_independent() {
        let j = jid(1);
        let mut a = ComputePoolModel::new();
        add_job(
            &mut a,
            j,
            vec![
                simple_unit(j, uid(2)),
                simple_unit(j, uid(5)),
                simple_unit(j, uid(3)),
            ],
        );
        let mut b = ComputePoolModel::new();
        add_job(
            &mut b,
            j,
            vec![
                simple_unit(j, uid(3)),
                simple_unit(j, uid(2)),
                simple_unit(j, uid(5)),
            ],
        );
        assert_eq!(
            ComputePoolStore::materialize(&a).unwrap(),
            ComputePoolStore::materialize(&b).unwrap(),
            "canonical row set is independent of unit insertion order"
        );
    }

    // ---- block-rollback revert: apply / revert / reapply, multi-record atomicity ----

    #[test]
    fn multi_record_apply_revert_reapply_is_exact() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let m = full_model();
        let target = ComputePoolStore::materialize(&m).unwrap();

        // Apply a block that writes many related records atomically.
        store.persist_transition(None, &m, 10).unwrap();
        assert_eq!(store.load_state_map().unwrap(), target);
        assert!(store.has_journal(10).unwrap());

        // Revert the whole block: every record disappears together.
        store.revert_block(10).unwrap();
        assert!(store.load_state_map().unwrap().is_empty());
        assert!(
            !store.has_journal(10).unwrap(),
            "journal consumed on revert"
        );

        // Reapply: byte-identical to the first application.
        store.persist_transition(None, &m, 10).unwrap();
        assert_eq!(store.load_state_map().unwrap(), target);
    }

    #[test]
    fn write_once_leaf_survives_apply_revert_reapply() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let key = WorkItemKey::new(jid(1), uid(2), 0);

        let mut m = ComputePoolModel::new();
        add_job(&mut m, jid(1), vec![simple_unit(jid(1), uid(2))]);
        m.accept_leaf(AcceptedLeaf {
            key,
            offer_bond_id: oid(3),
            commit_bond_id: CommitBondId::from_bytes([4; 32]),
            accepted_bytes: 100,
        })
        .unwrap();

        store.persist_transition(None, &m, 5).unwrap();
        assert_eq!(
            store
                .get_accepted_leaf(&key)
                .unwrap()
                .unwrap()
                .accepted_bytes,
            100
        );
        store.revert_block(5).unwrap();
        assert!(
            store.get_accepted_leaf(&key).unwrap().is_none(),
            "leaf gone after revert"
        );
        store.persist_transition(None, &m, 5).unwrap();
        assert_eq!(
            store
                .get_accepted_leaf(&key)
                .unwrap()
                .unwrap()
                .accepted_bytes,
            100,
            "leaf restored on reapply"
        );
    }

    #[test]
    fn one_active_offer_invariant_reverts_on_rollback() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let identity = addr(8);

        // Block 1: identity's active offer is A.
        let mut m1 = ComputePoolModel::new();
        m1.publish_offer(active_offer(oid(0xAA), identity)).unwrap();
        store.persist_transition(None, &m1, 1).unwrap();
        assert_eq!(store.active_offer_of(&identity).unwrap(), Some(oid(0xAA)));

        // Block 2: A is retired (inactive) and B becomes the active offer.
        let mut m2 = ComputePoolModel::new();
        m2.publish_offer(BondedOffer {
            active: false,
            ..active_offer(oid(0xAA), identity)
        })
        .unwrap();
        m2.publish_offer(BondedOffer {
            offer_seq: 1,
            ..active_offer(oid(0xBB), identity)
        })
        .unwrap();
        store.persist_transition(Some(&m1), &m2, 2).unwrap();
        assert_eq!(
            store.active_offer_of(&identity).unwrap(),
            Some(oid(0xBB)),
            "index now points at B"
        );

        // Roll back block 2: the one-active-offer index is restored to A.
        store.revert_block(2).unwrap();
        assert_eq!(
            store.active_offer_of(&identity).unwrap(),
            Some(oid(0xAA)),
            "active-offer index restored to A after reverting block 2"
        );
        assert!(
            store.get_offer(&oid(0xBB)).unwrap().is_none(),
            "offer B removed"
        );
    }

    #[test]
    fn corrupt_journal_revert_aborts_with_state_intact() {
        // A journal whose mutation key has an unrecognized domain prefix must
        // abort the whole revert BEFORE commit: no record is touched and the
        // journal is preserved (no partial application).
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);
        let m = full_model();
        store.persist_transition(None, &m, 1).unwrap();
        let before = store.load_state_map().unwrap();

        // Craft a corrupt journal at height 2 with a bad-domain mutation.
        let mut diff = ComputePoolStateDiff::new();
        diff.records.push(ComputePoolMutation {
            key: vec![0xFF, 1, 2, 3], // 0xFF is not a valid domain prefix
            old: Some(vec![9, 9, 9]),
            new: None,
        });
        db.put(
            cf::COMPUTE_POOL_STATE_DIFFS,
            &2u64.to_be_bytes(),
            &c1_encode(&diff).unwrap(),
        )
        .unwrap();

        assert!(
            store.revert_block(2).is_err(),
            "corrupt journal aborts revert"
        );
        assert_eq!(
            store.load_state_map().unwrap(),
            before,
            "state unchanged after aborted revert (no partial writes)"
        );
        assert!(
            store.has_journal(2).unwrap(),
            "corrupt journal preserved for retry"
        );
    }

    // ---- one finalized transition per height (duplicate-height rejection) ----

    #[test]
    fn second_transition_at_same_height_is_hard_rejected_state_intact() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);

        // First transition at height 7 commits normally.
        let m1 = full_model();
        store.persist_transition(None, &m1, 7).unwrap();
        let after_first = store.load_state_map().unwrap();
        let journal_first = db
            .get(cf::COMPUTE_POOL_STATE_DIFFS, &7u64.to_be_bytes())
            .unwrap()
            .unwrap();

        // A DIFFERENT transition at the SAME height must be hard-rejected so it
        // cannot overwrite the first journal (which would lose block 7's undo
        // information). Use the correct predecessor so ONLY the duplicate-height
        // guard can be responsible for the rejection.
        let mut m2 = m1.clone();
        m2.register_entitlement(EntitlementRecord {
            entitlement_id: EntitlementId::from_bytes([0x77; 32]),
            beneficiary: addr(1),
            kind: EntitlementKind::ReassignReimb,
            amount: 999,
        })
        .unwrap();
        let err = store.persist_transition(Some(&m1), &m2, 7).unwrap_err();
        assert!(
            matches!(err, StateError::InvalidOperation(_)),
            "duplicate height must be InvalidOperation, got {err:?}"
        );

        // State AND journal are exactly the first transition's (nothing written).
        assert_eq!(
            store.load_state_map().unwrap(),
            after_first,
            "rejected duplicate-height transition must not mutate state"
        );
        assert_eq!(
            db.get(cf::COMPUTE_POOL_STATE_DIFFS, &7u64.to_be_bytes())
                .unwrap()
                .unwrap(),
            journal_first,
            "the original journal for the height is preserved intact"
        );

        // And the preserved journal still rolls the block back exactly.
        store.revert_block(7).unwrap();
        assert!(store.load_state_map().unwrap().is_empty());
    }

    // ---- stale-predecessor rejection ----

    #[test]
    fn stale_before_snapshot_is_rejected_no_write() {
        let (db, _d) = open_db();
        let store = ComputePoolStore::new(&db);

        // Live state is `full_model()` at height 1.
        let live_model = full_model();
        store.persist_transition(None, &live_model, 1).unwrap();
        let live_rows = store.load_state_map().unwrap();

        // Caller claims an EMPTY predecessor (before = None) at height 2, but the
        // live state is non-empty => stale => reject, nothing written.
        let target = full_model();
        let err = store.persist_transition(None, &target, 2).unwrap_err();
        assert!(
            matches!(err, StateError::InvalidOperation(_)),
            "got {err:?}"
        );
        assert!(
            !store.has_journal(2).unwrap(),
            "no journal on rejected write"
        );
        assert_eq!(
            store.load_state_map().unwrap(),
            live_rows,
            "state untouched"
        );

        // Caller claims a DIFFERENT non-empty predecessor => also stale => reject.
        let mut wrong_before = ComputePoolModel::new();
        wrong_before
            .publish_offer(active_offer(oid(0xEE), addr(200)))
            .unwrap();
        let err2 = store
            .persist_transition(Some(&wrong_before), &target, 2)
            .unwrap_err();
        assert!(
            matches!(err2, StateError::InvalidOperation(_)),
            "got {err2:?}"
        );
        assert_eq!(
            store.load_state_map().unwrap(),
            live_rows,
            "state untouched"
        );

        // The CORRECT predecessor is accepted (control): a genuine no-op here.
        assert_eq!(
            store
                .persist_transition(Some(&live_model), &live_model, 2)
                .unwrap(),
            0
        );
    }

    // ---- codec byte-stability: committed golden vector ----

    /// Exact expected bytes of `StoredJob` for a fixed record, under the single
    /// [`c1_codec`] configuration (fixint, little-endian). If this changes, the
    /// on-disk format changed and `C1_SCHEMA_VERSION` must be bumped + migrated.
    ///
    /// Layout: `schema_version(u8) | job_id[32] | requester[20] | r_job(u32 LE)
    /// | job_max_retention_files(u128 LE) | requester_debit(u128 LE)
    /// | state_tag(u8)` = 90 bytes.
    const GOLDEN_STORED_JOB_HEX: &str = concat!(
        "01",                                                               // schema_version = 1
        "1111111111111111111111111111111111111111111111111111111111111111", // job_id = [0x11; 32]
        "2222222222222222222222222222222222222222", // requester = [0x22; 20]
        "07000000",                                 // r_job = 7 (u32 LE)
        "02000000000000000000000000000000",         // job_max_retention_files = 2 (u128 LE)
        "82000000000000000000000000000000",         // requester_debit = 130 (u128 LE)
        "00",                                       // state_tag = 0 (Open)
    );

    #[test]
    fn stored_job_matches_committed_golden_vector() {
        let job = Job {
            job_id: JobId::from_bytes([0x11; 32]),
            requester: Address::new([0x22; 20]),
            r_job: 7,
            job_max_retention_files: 2,
            requester_debit: 130,
            state: JobState::Open,
        };
        let bytes = c1_encode(&StoredJob::from_model(&job)).unwrap();
        assert_eq!(
            hex::encode(&bytes),
            GOLDEN_STORED_JOB_HEX,
            "StoredJob byte layout drifted from the committed golden vector"
        );
        assert_eq!(bytes.len(), 90);
        // The single codec config round-trips its own golden bytes.
        assert_eq!(decode_job(&bytes).unwrap(), StoredJob::from_model(&job));
    }
}

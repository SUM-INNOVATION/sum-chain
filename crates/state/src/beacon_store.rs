//! BR1 randomness-beacon PERSISTENCE + REVERT contract (issue #127).
//!
//! The storage/revert boundary for the dormant beacon epoch/round state. It follows
//! the merged **C1 pattern** (`crate::compute_pool_store`) exactly — same digest
//! framing, same single-batch `persist_transition`, same journal-driven
//! `stage_block_revert` composed into the unified reorg batch — but for the beacon
//! keyspace. Because the beacon subsystem is **dormant by default**
//! (`beacon_enabled_from_height == None`), nothing writes a beacon journal during
//! live block execution, so the digest fold and the revert are byte/state-identical
//! no-ops under the production gate; they become live only once the gate opens.
//!
//! ## What is / isn't wired
//!
//! * **Wired (dormant, journal-presence-driven):** [`BeaconStore::state_digest`] is
//!   folded into the block state root **only when the beacon gate is open**
//!   (`crate::executor::compute_block_state_root`); [`BeaconStore::stage_block_revert`]
//!   is composed into the SAME atomic batch as account + contract + C1 revert
//!   (`crate::state::StateManager::revert_block_state_diffs`). Both are no-ops while
//!   no journal exists (always, under the `None` gate), so dormant behavior is
//!   unchanged.
//! * **Wired (live producer):** [`BeaconStore::materialize`] serializes the runtime
//!   epoch/round state into rows, and [`BeaconStore::load_materialized`] de-serializes
//!   them back for [`DkgEpoch::rehydrate`] / `BeaconChain::rehydrate`. The executor's
//!   per-block accumulator (`crate::beacon_manager::BeaconBlockState`) drives this on
//!   the gate-open path: a VALID beacon tx is accumulated and persisted as EXACTLY ONE
//!   journal per block (`materialize(rehydrate(rows)) == rows`, so a block persists a
//!   delta against the true prior state). Still a no-op under the `None` gate.
//!
//! The row set is a domain-prefixed `key -> value` map; the runtime supplies a
//! materialized snapshot and this module commits/reverts it. Rows are opaque bytes
//! to the store (validated only by their 1-byte domain prefix on revert), so the
//! runtime's serialization can evolve without touching this adapter.

use std::collections::BTreeMap;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sumchain_beacon_runtime::context::ValidatorId;
use sumchain_beacon_runtime::dkg::{
    DealEquivocationEvidence, DealView, DkgEpoch, KeyEquivocationEvidence, KeyView, RehydrateInput,
    SignedRecordRef,
};
use sumchain_beacon_runtime::rounds::BeaconChain;

/// Convert a runtime authenticated record ref → its persisted form.
fn to_stored_ref(r: &SignedRecordRef) -> StoredSignedRef {
    StoredSignedRef {
        signer: *r.signer.as_bytes(),
        tx_ref: r.tx_ref,
        carrier: r.carrier.clone(),
    }
}
/// Convert a persisted record ref → the runtime form.
fn from_stored_ref(s: &StoredSignedRef) -> SignedRecordRef {
    SignedRecordRef {
        signer: ValidatorId(s.signer),
        tx_ref: s.tx_ref,
        carrier: s.carrier.clone(),
    }
}
use sumchain_primitives::{BlockHeight, Hash};
use sumchain_storage::candidate::JournalRecord;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::{cf, Database};

use crate::{Result, StateError};

/// Local anti-DoS ceiling on a single decoded beacon journal, in bytes. NOT a
/// consensus/economic cap — it only bounds decoder allocation on a corrupt value.
pub const BEACON_DECODE_BYTE_LIMIT: u64 = 1 << 20;

/// On-disk schema version stamped as the first field of every typed beacon record.
/// A future ratified layout bumps this; decoders reject any other value. A change is
/// a consensus event once the gate can open (records feed [`BeaconStore::state_digest`]).
pub const BEACON_RECORD_VERSION: u8 = 1;

/// Canonical compressed G1 width (bytes) — encryption keys, carriers, commitments.
const G1_LEN: usize = 48;
/// Canonical compressed G2 width (bytes) — combined round signature `Σ_r`.
const G2_LEN: usize = 96;
/// ECIES body width (bytes) — `ct_{ij}`.
const CT_LEN: usize = 48;
/// Beacon output width (bytes).
const OUT_LEN: usize = 32;

/// Domain tag for [`BeaconStore::state_digest`]. **Explicitly versioned**
/// (`…state.v1`) — a FROZEN consensus value once the beacon gate can open (it is
/// committed into the block state root), so any change requires a deliberate,
/// activation-coordinated `…state.v2` bump, never an incidental edit. Pinned by the
/// golden test `beacon_state_digest_domain_is_frozen`.
const BEACON_STATE_DIGEST_DOMAIN: &[u8] = b"sumchain.beacon.state.v1";

/// Checked 4-byte little-endian frame prefix (rejects `> u32::MAX`, which would make
/// the digest concatenation ambiguous — a consensus hazard). Byte-identical to a
/// `len as u32` cast for every realistic length.
fn frame_len(n: usize) -> Result<[u8; 4]> {
    let framed = u32::try_from(n).map_err(|_| {
        StateError::InvalidOperation(format!(
            "beacon state digest: field length {n} exceeds u32::MAX; cannot frame unambiguously"
        ))
    })?;
    Ok(framed.to_le_bytes())
}

/// 1-byte domain/type prefixes for the beacon keyspace. Every persisted row key is
/// `DOMAIN(1) ‖ epoch(8 BE) ‖ body` so no category aliases another AND different
/// epochs never collide (issue #127 correction 1: epoch in persistence keys).
pub mod domain {
    /// Registered per-epoch encryption key `EK_j` (+ authenticated record ref).
    pub const KEY: u8 = 0x01;
    /// A `(dealer, recipient)` deal record (+ authenticated record ref).
    pub const DEAL: u8 = 0x02;
    /// A disqualified dealer.
    pub const VERDICT: u8 = 0x03;
    /// A finalized round's combined signature.
    pub const ROUND: u8 = 0x04;
    /// A finalized round's beacon output.
    pub const OUTPUT: u8 = 0x05;
    /// The FIXED per-epoch membership snapshot (validator set at the epoch boundary).
    pub const MEMBERSHIP: u8 = 0x06;
    /// A slashed false-accuser (recipient index).
    pub const FALSE_ACCUSER: u8 = 0x07;
    /// An adjudicated `(dealer, recipient)` complaint pair (idempotence / no
    /// double-jeopardy).
    pub const ADJUDICATED: u8 = 0x08;
    /// Retained authenticated KEY equivocation evidence.
    pub const KEY_EQUIV: u8 = 0x09;
    /// Retained authenticated DEAL equivocation evidence.
    pub const DEAL_EQUIV: u8 = 0x0A;
}

/// True iff `key`'s first byte is a recognized beacon domain prefix.
fn is_beacon_domain(key: &[u8]) -> bool {
    matches!(
        key.first(),
        Some(
            &domain::KEY
                | &domain::DEAL
                | &domain::VERDICT
                | &domain::ROUND
                | &domain::OUTPUT
                | &domain::MEMBERSHIP
                | &domain::FALSE_ACCUSER
                | &domain::ADJUDICATED
                | &domain::KEY_EQUIV
                | &domain::DEAL_EQUIV
        )
    )
}

/// Extract the epoch a row key belongs to (`DOMAIN(1) ‖ epoch(8 BE) ‖ …`), or `None`
/// if too short.
fn key_epoch(key: &[u8]) -> Option<u64> {
    if key.len() < 9 {
        return None;
    }
    let mut e = [0u8; 8];
    e.copy_from_slice(&key[1..9]);
    Some(u64::from_be_bytes(e))
}

/// Push `DOMAIN ‖ epoch(8 BE)` — the common prefix of every beacon row key.
fn key_prefix(domain: u8, epoch: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8 + 8);
    k.push(domain);
    k.extend_from_slice(&epoch.to_be_bytes());
    k
}

// --- journal codec (bincode fixint LE + limit + reject-trailing, per C1) ---

fn beacon_codec() -> impl Options {
    bincode::options()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(BEACON_DECODE_BYTE_LIMIT)
}

fn beacon_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    beacon_codec()
        .serialize(value)
        .map_err(|e| StateError::SerializationError(e.to_string()))
}

fn beacon_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    beacon_codec()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| StateError::DeserializationError(e.to_string()))
}

// ---------------------------------------------------------------------------
// Canonical key encoders — domain prefix ‖ fixed-width big-endian body (Item 2).
// Big-endian so composite ordering matches numeric ordering for range scans.
// ---------------------------------------------------------------------------

/// `[KEY] ‖ epoch(8) ‖ validator_index(u32 BE)`.
pub fn key_row_key(epoch: u64, validator_index: u32) -> Vec<u8> {
    let mut k = key_prefix(domain::KEY, epoch);
    k.extend_from_slice(&validator_index.to_be_bytes());
    k
}
/// `[DEAL] ‖ epoch(8) ‖ dealer_i(u32 BE) ‖ recipient_j(u32 BE)`.
pub fn deal_row_key(epoch: u64, dealer_i: u32, recipient_j: u32) -> Vec<u8> {
    let mut k = key_prefix(domain::DEAL, epoch);
    k.extend_from_slice(&dealer_i.to_be_bytes());
    k.extend_from_slice(&recipient_j.to_be_bytes());
    k
}
/// `[VERDICT] ‖ epoch(8) ‖ dealer_i(u32 BE)` — a disqualification.
pub fn disqualified_row_key(epoch: u64, dealer_i: u32) -> Vec<u8> {
    let mut k = key_prefix(domain::VERDICT, epoch);
    k.extend_from_slice(&dealer_i.to_be_bytes());
    k
}
/// `[ROUND] ‖ epoch(8) ‖ round(u64 BE)` — a finalized `Σ_r`.
pub fn round_row_key(epoch: u64, round: u64) -> Vec<u8> {
    let mut k = key_prefix(domain::ROUND, epoch);
    k.extend_from_slice(&round.to_be_bytes());
    k
}
/// `[OUTPUT] ‖ epoch(8) ‖ round(u64 BE)` — a beacon output.
pub fn output_row_key(epoch: u64, round: u64) -> Vec<u8> {
    let mut k = key_prefix(domain::OUTPUT, epoch);
    k.extend_from_slice(&round.to_be_bytes());
    k
}
/// `[MEMBERSHIP] ‖ epoch(8)` — the fixed per-epoch membership snapshot.
pub fn membership_row_key(epoch: u64) -> Vec<u8> {
    key_prefix(domain::MEMBERSHIP, epoch)
}
/// `[FALSE_ACCUSER] ‖ epoch(8) ‖ recipient_j(u32 BE)`.
pub fn false_accuser_row_key(epoch: u64, recipient_j: u32) -> Vec<u8> {
    let mut k = key_prefix(domain::FALSE_ACCUSER, epoch);
    k.extend_from_slice(&recipient_j.to_be_bytes());
    k
}
/// `[ADJUDICATED] ‖ epoch(8) ‖ dealer_i(u32 BE) ‖ recipient_j(u32 BE)`.
pub fn adjudicated_row_key(epoch: u64, dealer_i: u32, recipient_j: u32) -> Vec<u8> {
    let mut k = key_prefix(domain::ADJUDICATED, epoch);
    k.extend_from_slice(&dealer_i.to_be_bytes());
    k.extend_from_slice(&recipient_j.to_be_bytes());
    k
}
/// `[KEY_EQUIV] ‖ epoch(8) ‖ first_tx_ref(32) ‖ second_tx_ref(32)` — one row per
/// conflicting signed-tx pair (deterministic, collision-free).
pub fn key_equiv_row_key(epoch: u64, first_tx_ref: &[u8; 32], second_tx_ref: &[u8; 32]) -> Vec<u8> {
    let mut k = key_prefix(domain::KEY_EQUIV, epoch);
    k.extend_from_slice(first_tx_ref);
    k.extend_from_slice(second_tx_ref);
    k
}
/// `[DEAL_EQUIV] ‖ epoch(8) ‖ first_tx_ref(32) ‖ second_tx_ref(32)`.
pub fn deal_equiv_row_key(
    epoch: u64,
    first_tx_ref: &[u8; 32],
    second_tx_ref: &[u8; 32],
) -> Vec<u8> {
    let mut k = key_prefix(domain::DEAL_EQUIV, epoch);
    k.extend_from_slice(first_tx_ref);
    k.extend_from_slice(second_tx_ref);
    k
}

// ---------------------------------------------------------------------------
// Typed record DTOs — `schema_version` first; point fields are length-validated
// `Vec<u8>` (strict decode + bounds). Canonical serialization is `beacon_codec`
// (bincode fixint LE), identical for encode + decode. These pin the EXACT bytes a
// runtime state materializes into a store row (Item 2).
// ---------------------------------------------------------------------------

/// An **authenticated** signed-record reference (Item 3 durability): signer identity,
/// signed-tx-envelope hash, and canonical carrier bytes. Persisted so evidence
/// attribution survives restart/reorg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSignedRef {
    /// Authenticated signer identity (32 bytes).
    pub signer: [u8; 32],
    /// Signed-tx-envelope hash (32 bytes).
    pub tx_ref: [u8; 32],
    /// Canonical carrier bytes.
    pub carrier: Vec<u8>,
}

/// A registered epoch encryption key `EK_j` (draft §2.3, §11) + its authenticated
/// record reference (so a later equivocation attributes the first record correctly).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconKey {
    /// Record schema version (byte 0).
    pub schema_version: u8,
    /// 0-based validator/membership index `j`.
    pub validator_index: u32,
    /// Canonical compressed G1 `EK_j` (48 bytes).
    pub ek: Vec<u8>,
    /// The authenticated record reference for the accepted registration.
    pub record: StoredSignedRef,
}

/// An accepted `(dealer i → recipient j)` deal (draft §8) + its authenticated record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconDeal {
    /// Record schema version.
    pub schema_version: u8,
    /// Dealer index `i`.
    pub dealer_i: u32,
    /// Recipient index `j`.
    pub recipient_j: u32,
    /// Feldman commitments `C_{i,*}`, each canonical compressed G1 (48 bytes).
    pub commitments: Vec<Vec<u8>>,
    /// Carrier `R_{ij}` (48 bytes).
    pub r_ij: Vec<u8>,
    /// ECIES body `ct_{ij}` (48 bytes).
    pub ct_ij: Vec<u8>,
    /// The authenticated record reference for the accepted deal.
    pub record: StoredSignedRef,
}

/// The FIXED per-epoch membership snapshot (validator set at the epoch boundary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconMembership {
    /// Record schema version.
    pub schema_version: u8,
    /// The epoch.
    pub epoch: u64,
    /// The ordered validator identities (index order).
    pub members: Vec<[u8; 32]>,
}

/// A slashed false-accuser (draft §6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconFalseAccuser {
    /// Record schema version.
    pub schema_version: u8,
    /// The slashed recipient index.
    pub recipient_j: u32,
}

/// An adjudicated `(dealer, recipient)` complaint pair (idempotence / no
/// double-jeopardy, draft §6.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconAdjudicated {
    /// Record schema version.
    pub schema_version: u8,
    /// Dealer index `i`.
    pub dealer_i: u32,
    /// Recipient index `j`.
    pub recipient_j: u32,
}

/// Retained KEY equivocation evidence: two conflicting authenticated registrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconKeyEquivocation {
    /// Record schema version.
    pub schema_version: u8,
    /// The equivocating validator index.
    pub validator_index: u32,
    /// The first (authoritative) authenticated record.
    pub first: StoredSignedRef,
    /// The conflicting authenticated record.
    pub second: StoredSignedRef,
}

/// Retained DEAL equivocation evidence: two conflicting authenticated deals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconDealEquivocation {
    /// Record schema version.
    pub schema_version: u8,
    /// The dealer index.
    pub dealer_i: u32,
    /// The first (accepted) authenticated record.
    pub first: StoredSignedRef,
    /// The conflicting authenticated record.
    pub second: StoredSignedRef,
}

/// A disqualified dealer (draft §4.2 / §6.1 verdict).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconDisqualified {
    /// Record schema version.
    pub schema_version: u8,
    /// The disqualified dealer index.
    pub dealer_i: u32,
}

/// A finalized round's combined signature `Σ_r` (draft §4.3, §12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconRound {
    /// Record schema version.
    pub schema_version: u8,
    /// The round.
    pub round: u64,
    /// Canonical compressed G2 `Σ_r` (96 bytes).
    pub sigma_r: Vec<u8>,
}

/// A finalized round's beacon output (draft §12.1 OUT domain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBeaconOutput {
    /// Record schema version.
    pub schema_version: u8,
    /// The round.
    pub round: u64,
    /// The 32-byte beacon output.
    pub output: Vec<u8>,
}

fn check_version(v: u8) -> Result<()> {
    if v == BEACON_RECORD_VERSION {
        Ok(())
    } else {
        Err(StateError::DeserializationError(format!(
            "unsupported beacon record schema version {v} (expected {BEACON_RECORD_VERSION})"
        )))
    }
}

fn check_len(field: &str, got: usize, want: usize) -> Result<()> {
    if got == want {
        Ok(())
    } else {
        Err(StateError::DeserializationError(format!(
            "beacon record: {field} length {got} != {want}"
        )))
    }
}

/// Strictly decode a [`StoredBeaconKey`] (version + `ek` length).
pub fn decode_key(bytes: &[u8]) -> Result<StoredBeaconKey> {
    let v: StoredBeaconKey = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("ek", v.ek.len(), G1_LEN)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconDeal`] (version + all point lengths).
pub fn decode_deal(bytes: &[u8]) -> Result<StoredBeaconDeal> {
    let v: StoredBeaconDeal = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("r_ij", v.r_ij.len(), G1_LEN)?;
    check_len("ct_ij", v.ct_ij.len(), CT_LEN)?;
    if v.commitments.is_empty() {
        return Err(StateError::DeserializationError(
            "beacon deal: empty commitment vector".into(),
        ));
    }
    for c in &v.commitments {
        check_len("commitment", c.len(), G1_LEN)?;
    }
    Ok(v)
}
/// Strictly decode a [`StoredBeaconDisqualified`] (version).
pub fn decode_disqualified(bytes: &[u8]) -> Result<StoredBeaconDisqualified> {
    let v: StoredBeaconDisqualified = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconRound`] (version + `Σ_r` length).
pub fn decode_round(bytes: &[u8]) -> Result<StoredBeaconRound> {
    let v: StoredBeaconRound = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("sigma_r", v.sigma_r.len(), G2_LEN)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconOutput`] (version + output length).
pub fn decode_output(bytes: &[u8]) -> Result<StoredBeaconOutput> {
    let v: StoredBeaconOutput = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    check_len("output", v.output.len(), OUT_LEN)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconMembership`] (version).
pub fn decode_membership(bytes: &[u8]) -> Result<StoredBeaconMembership> {
    let v: StoredBeaconMembership = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconFalseAccuser`] (version).
pub fn decode_false_accuser(bytes: &[u8]) -> Result<StoredBeaconFalseAccuser> {
    let v: StoredBeaconFalseAccuser = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconAdjudicated`] (version).
pub fn decode_adjudicated(bytes: &[u8]) -> Result<StoredBeaconAdjudicated> {
    let v: StoredBeaconAdjudicated = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconKeyEquivocation`] (version).
pub fn decode_key_equivocation(bytes: &[u8]) -> Result<StoredBeaconKeyEquivocation> {
    let v: StoredBeaconKeyEquivocation = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    Ok(v)
}
/// Strictly decode a [`StoredBeaconDealEquivocation`] (version).
pub fn decode_deal_equivocation(bytes: &[u8]) -> Result<StoredBeaconDealEquivocation> {
    let v: StoredBeaconDealEquivocation = beacon_decode(bytes)?;
    check_version(v.schema_version)?;
    Ok(v)
}

/// One beacon state mutation captured for block-rollback revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconMutation {
    /// The domain-prefixed row key.
    pub key: Vec<u8>,
    /// Pre-value (`None` = absent).
    pub old: Option<Vec<u8>>,
    /// Post-value (`None` = deleted).
    pub new: Option<Vec<u8>>,
}

/// Per-block journal of beacon state mutations for block-rollback revert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconStateDiff {
    /// The mutations, canonical-key-sorted before persistence.
    pub records: Vec<BeaconMutation>,
}

impl BeaconStateDiff {
    /// Decode a journal produced by
    /// [`BeaconStore::stage_transition`](BeaconStore::stage_transition).
    ///
    /// Public because the journal is now an artifact that travels out of
    /// execution — bound to the candidate, written by the publisher, and read
    /// back by the reorg driver. A type whose bytes leave the module needs a way
    /// back in that is not every reader re-deriving the codec.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        beacon_decode(bytes)
    }

    /// Whether the journal is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    fn sort(&mut self) {
        self.records.sort_by(|a, b| a.key.cmp(&b.key));
    }
}

/// Persistence adapter for the dormant BR1 beacon state.
pub struct BeaconStore<'a> {
    db: &'a Database,
}

impl<'a> BeaconStore<'a> {
    /// Wrap a database handle.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// **Materialize** the runtime beacon state for `epoch` into the canonical
    /// `key -> value` row set — the producer's runtime→row mapping, byte-pinned and
    /// epoch-keyed. Emits the FIXED membership snapshot, registered keys + deals (with
    /// authenticated records), disqualifications, false-accuser + adjudicated
    /// (idempotence/slash-once) state, key/deal equivocation evidence, and — if a
    /// signing chain is supplied — finalized rounds + outputs. Deterministic in state
    /// *content* only (every backing collection is ordered).
    pub fn materialize(
        epoch: u64,
        dkg: &DkgEpoch,
        chain: Option<&BeaconChain>,
        membership: &[[u8; 32]],
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut rows: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for k in dkg.authenticated_keys() {
            rows.insert(
                key_row_key(epoch, k.validator_index),
                beacon_encode(&StoredBeaconKey {
                    schema_version: BEACON_RECORD_VERSION,
                    validator_index: k.validator_index,
                    ek: k.ek.to_vec(),
                    record: to_stored_ref(&k.record),
                })?,
            );
        }
        for d in dkg.accepted_deals() {
            rows.insert(
                deal_row_key(epoch, d.dealer_i, d.recipient_j),
                beacon_encode(&StoredBeaconDeal {
                    schema_version: BEACON_RECORD_VERSION,
                    dealer_i: d.dealer_i,
                    recipient_j: d.recipient_j,
                    commitments: d.commitments.iter().map(|c| c.to_vec()).collect(),
                    r_ij: d.r_ij.to_vec(),
                    ct_ij: d.ct_ij.to_vec(),
                    record: to_stored_ref(&d.record),
                })?,
            );
        }
        for i in dkg.disqualified() {
            rows.insert(
                disqualified_row_key(epoch, *i),
                beacon_encode(&StoredBeaconDisqualified {
                    schema_version: BEACON_RECORD_VERSION,
                    dealer_i: *i,
                })?,
            );
        }
        for j in dkg.false_accusers() {
            rows.insert(
                false_accuser_row_key(epoch, *j),
                beacon_encode(&StoredBeaconFalseAccuser {
                    schema_version: BEACON_RECORD_VERSION,
                    recipient_j: *j,
                })?,
            );
        }
        for (i, j) in dkg.adjudicated() {
            rows.insert(
                adjudicated_row_key(epoch, *i, *j),
                beacon_encode(&StoredBeaconAdjudicated {
                    schema_version: BEACON_RECORD_VERSION,
                    dealer_i: *i,
                    recipient_j: *j,
                })?,
            );
        }
        for e in dkg.key_equivocations() {
            rows.insert(
                key_equiv_row_key(epoch, &e.first.tx_ref, &e.second.tx_ref),
                beacon_encode(&StoredBeaconKeyEquivocation {
                    schema_version: BEACON_RECORD_VERSION,
                    validator_index: e.validator_index,
                    first: to_stored_ref(&e.first),
                    second: to_stored_ref(&e.second),
                })?,
            );
        }
        for e in dkg.deal_equivocations() {
            rows.insert(
                deal_equiv_row_key(epoch, &e.first.tx_ref, &e.second.tx_ref),
                beacon_encode(&StoredBeaconDealEquivocation {
                    schema_version: BEACON_RECORD_VERSION,
                    dealer_i: e.dealer_i,
                    first: to_stored_ref(&e.first),
                    second: to_stored_ref(&e.second),
                })?,
            );
        }
        if let Some(chain) = chain {
            for (r, sigma_r, output) in chain.finalized_rounds() {
                rows.insert(
                    round_row_key(epoch, r),
                    beacon_encode(&StoredBeaconRound {
                        schema_version: BEACON_RECORD_VERSION,
                        round: r,
                        sigma_r: sigma_r.to_vec(),
                    })?,
                );
                rows.insert(
                    output_row_key(epoch, r),
                    beacon_encode(&StoredBeaconOutput {
                        schema_version: BEACON_RECORD_VERSION,
                        round: r,
                        output: output.to_vec(),
                    })?,
                );
            }
        }
        // MEMBERSHIP AT THE EPOCH BOUNDARY (Correction 1): the FIXED per-epoch snapshot
        // is emitted whenever a non-empty snapshot is supplied — i.e. the executor's
        // per-block accumulator persists it at the epoch boundary (`height ==
        // epoch_start`) INDEPENDENT of any beacon tx, and re-emits the identical row
        // (zero delta) on later blocks. The standalone lifecycle coordinator passes an
        // empty snapshot (`&[]`) and therefore writes no membership row. The snapshot is
        // frozen: mid-epoch validator-set churn never reaches this row (later blocks
        // LOAD the persisted set rather than re-sampling the active set).
        if !membership.is_empty() {
            rows.insert(
                membership_row_key(epoch),
                beacon_encode(&StoredBeaconMembership {
                    schema_version: BEACON_RECORD_VERSION,
                    epoch,
                    members: membership.to_vec(),
                })?,
            );
        }
        Ok(rows)
    }

    /// Read the full persisted beacon `key -> value` row set (canonical order).
    pub fn load_state_map(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut map = BTreeMap::new();
        for (k, v) in self.db.iter(cf::BEACON_STATE)? {
            map.insert(k.to_vec(), v.to_vec());
        }
        Ok(map)
    }

    /// Read the FIXED membership snapshot persisted for `epoch`, if any.
    pub fn get_membership(&self, epoch: u64) -> Result<Option<Vec<[u8; 32]>>> {
        match self.db.get(cf::BEACON_STATE, &membership_row_key(epoch))? {
            Some(bytes) => Ok(Some(decode_membership(&bytes)?.members)),
            None => Ok(None),
        }
    }

    /// **De-materialize** the persisted rows for `epoch` back into the runtime
    /// rehydration inputs (rows → runtime): a [`RehydrateInput`] (keys, deals,
    /// disqualified, false-accusers, adjudicated, equivocations) + the finalized
    /// rounds. The inverse of [`materialize`](Self::materialize) restricted to
    /// `epoch`; strict-decodes every typed record. Feeds `DkgEpoch::rehydrate` /
    /// `BeaconChain::rehydrate`.
    #[allow(clippy::type_complexity)]
    pub fn load_materialized(
        &self,
        epoch: u64,
    ) -> Result<(RehydrateInput, Vec<(u64, [u8; G2_LEN], [u8; OUT_LEN])>)> {
        Self::materialized_from(&self.load_state_map()?, epoch)
    }

    /// De-materialize the rows THIS BLOCK sees, so the accumulator is rehydrated
    /// from the candidate rather than from the parent.
    ///
    /// Rehydration is how the block accumulator learns what the epoch already
    /// contains. Reading committed state here would rebuild it from the
    /// parent's rows, so a second beacon op in a block would be validated
    /// against a state missing the first one's — a duplicate key registration
    /// or deal would look novel and be accepted twice.
    #[allow(clippy::type_complexity)]
    pub fn v_load_materialized(
        view: &ExecutionView<'_, '_>,
        epoch: u64,
    ) -> Result<(RehydrateInput, Vec<(u64, [u8; G2_LEN], [u8; OUT_LEN])>)> {
        Self::materialized_from(&Self::v_load_state_map(view)?, epoch)
    }

    /// The de-materialization itself, over an already-loaded row set. Shared, so
    /// the committed and candidate paths cannot decode the same rows differently.
    #[allow(clippy::type_complexity)]
    fn materialized_from(
        rows: &BTreeMap<Vec<u8>, Vec<u8>>,
        epoch: u64,
    ) -> Result<(RehydrateInput, Vec<(u64, [u8; G2_LEN], [u8; OUT_LEN])>)> {
        let mut input = RehydrateInput::default();
        let mut round_sig: BTreeMap<u64, [u8; G2_LEN]> = BTreeMap::new();
        let mut round_out: BTreeMap<u64, [u8; OUT_LEN]> = BTreeMap::new();

        let as_arr = |v: &[u8], n: usize| -> Result<Vec<u8>> {
            if v.len() != n {
                return Err(StateError::DeserializationError(
                    "bad persisted length".into(),
                ));
            }
            Ok(v.to_vec())
        };
        let fixed = |v: &[u8]| -> Result<[u8; G1_LEN]> {
            let mut a = [0u8; G1_LEN];
            a.copy_from_slice(&as_arr(v, G1_LEN)?);
            Ok(a)
        };

        for (k, v) in rows {
            // Only this epoch's rows (epoch is bytes [1..9] of every key).
            if key_epoch(k) != Some(epoch) {
                continue;
            }
            match k.first() {
                Some(&domain::MEMBERSHIP) => {
                    decode_membership(v)?; // validate; membership loaded via get_membership
                }
                Some(&domain::KEY) => {
                    let sk = decode_key(v)?;
                    input.keys.push(KeyView {
                        validator_index: sk.validator_index,
                        ek: fixed(&sk.ek)?,
                        record: from_stored_ref(&sk.record),
                    });
                }
                Some(&domain::DEAL) => {
                    let sd = decode_deal(v)?;
                    let mut ct_ij = [0u8; CT_LEN];
                    ct_ij.copy_from_slice(&as_arr(&sd.ct_ij, CT_LEN)?);
                    let mut commitments = Vec::with_capacity(sd.commitments.len());
                    for c in &sd.commitments {
                        commitments.push(fixed(c)?);
                    }
                    input.deals.push(DealView {
                        dealer_i: sd.dealer_i,
                        recipient_j: sd.recipient_j,
                        commitments,
                        r_ij: fixed(&sd.r_ij)?,
                        ct_ij,
                        record: from_stored_ref(&sd.record),
                    });
                }
                Some(&domain::VERDICT) => input.disqualified.push(decode_disqualified(v)?.dealer_i),
                Some(&domain::FALSE_ACCUSER) => input
                    .false_accusers
                    .push(decode_false_accuser(v)?.recipient_j),
                Some(&domain::ADJUDICATED) => {
                    let a = decode_adjudicated(v)?;
                    input.adjudicated.push((a.dealer_i, a.recipient_j));
                }
                Some(&domain::KEY_EQUIV) => {
                    let e = decode_key_equivocation(v)?;
                    input.key_equivocations.push(KeyEquivocationEvidence {
                        validator_index: e.validator_index,
                        first: from_stored_ref(&e.first),
                        second: from_stored_ref(&e.second),
                    });
                }
                Some(&domain::DEAL_EQUIV) => {
                    let e = decode_deal_equivocation(v)?;
                    input.deal_equivocations.push(DealEquivocationEvidence {
                        dealer_i: e.dealer_i,
                        first: from_stored_ref(&e.first),
                        second: from_stored_ref(&e.second),
                    });
                }
                Some(&domain::ROUND) => {
                    let sr = decode_round(v)?;
                    let mut sig = [0u8; G2_LEN];
                    sig.copy_from_slice(&as_arr(&sr.sigma_r, G2_LEN)?);
                    round_sig.insert(sr.round, sig);
                }
                Some(&domain::OUTPUT) => {
                    let so = decode_output(v)?;
                    let mut out = [0u8; OUT_LEN];
                    out.copy_from_slice(&as_arr(&so.output, OUT_LEN)?);
                    round_out.insert(so.round, out);
                }
                _ => {
                    return Err(StateError::DeserializationError(
                        "unrecognized beacon row domain".into(),
                    ));
                }
            }
        }
        let rounds: Vec<(u64, [u8; G2_LEN], [u8; OUT_LEN])> = round_sig
            .into_iter()
            .filter_map(|(r, sig)| round_out.get(&r).map(|out| (r, sig, *out)))
            .collect();
        Ok((input, rounds))
    }

    /// Deterministic, domain-separated digest over the FULL persisted beacon state.
    /// `DOMAIN ‖ for each (key, value): key_len(u32 LE) ‖ key ‖ val_len(u32 LE) ‖
    /// value` over `BTreeMap`-ordered rows. The block executor folds this into the
    /// state root **only when the beacon gate is open**; while dormant it is never
    /// folded, so dormant roots are byte-for-byte unchanged.
    pub fn state_digest(&self) -> Result<Hash> {
        Self::digest_of(&self.load_state_map()?)
    }

    /// The digest encoder itself, over an already-loaded row set.
    ///
    /// Both [`state_digest`](Self::state_digest) and
    /// [`v_state_digest`](Self::v_state_digest) call this, so the committed and
    /// candidate digests cannot drift apart: the rows differ, the encoding
    /// cannot. The fold is part of the block state root, so two encoders that
    /// disagree by one byte split the network.
    fn digest_of(rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<Hash> {
        let mut buf: Vec<u8> = Vec::with_capacity(BEACON_STATE_DIGEST_DOMAIN.len());
        buf.extend_from_slice(BEACON_STATE_DIGEST_DOMAIN);
        for (k, v) in rows {
            buf.extend_from_slice(&frame_len(k.len())?);
            buf.extend_from_slice(k);
            buf.extend_from_slice(&frame_len(v.len())?);
            buf.extend_from_slice(v);
        }
        Ok(Hash::hash(&buf))
    }

    // ── Execution-path API (candidate-scoped) ───────────────────────────────
    //
    // Block execution reads and writes beacon rows only through these. They take
    // an `ExecutionView`, never `&self`: without a receiver there is no
    // `self.db` to reach, so a committed read on the execution path is not
    // expressible.
    //
    // The `&self` methods stay, and stay committed-state, for RPC and for the
    // reorg driver — which answer about the published chain.

    /// The live beacon row set as this block sees it: the parent's rows,
    /// overlaid with everything this block has already staged.
    pub fn v_load_state_map(
        view: &ExecutionView<'_, '_>,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        let mut map = BTreeMap::new();
        // The merged scan is fallible. A read error must end it, not truncate
        // it: a short row set produces a different digest, and that digest is
        // folded into the block state root.
        for entry in view.iter(cf::BEACON_STATE)? {
            let (k, v) = entry?;
            map.insert(k, v);
        }
        Ok(map)
    }

    /// The beacon state digest over the candidate's rows.
    ///
    /// Reading committed state here would commit the root to the PARENT's beacon
    /// state while publishing the child's rows, so every validator would compute
    /// a root that disagrees with the state it stores.
    pub fn v_state_digest(view: &ExecutionView<'_, '_>) -> Result<Hash> {
        Self::digest_of(&Self::v_load_state_map(view)?)
    }

    /// The FIXED membership snapshot for `epoch`, as this block sees it.
    ///
    /// The membership row is staged during block finalization, so the executor's
    /// only current caller — `beacon_epoch_membership`, which runs at block
    /// START — cannot observe a difference between this and the committed read:
    /// at the boundary neither finds a row and the active set is used directly,
    /// and past the boundary an earlier block has already published one.
    ///
    /// This exists so that the whole beacon read surface goes through the view,
    /// not because that call site needs it. A subsystem with one read left on
    /// the committed handle is a subsystem whose reads can disagree: the moment
    /// anything stages a membership row mid-block, every other beacon read would
    /// see it and that one would not. Keeping the surface uniform is what makes
    /// "beacon execution reads the candidate" a property rather than a habit.
    pub fn v_get_membership(
        view: &ExecutionView<'_, '_>,
        epoch: u64,
    ) -> Result<Option<Vec<[u8; 32]>>> {
        match view.get(cf::BEACON_STATE, &membership_row_key(epoch))? {
            Some(bytes) => Ok(Some(decode_membership(&bytes)?.members)),
            None => Ok(None),
        }
    }

    /// Whether this block published a beacon journal.
    pub fn has_journal(&self, height: BlockHeight, block_hash: &Hash) -> Result<bool> {
        Ok(self.journal_bytes(height, block_hash)?.is_some())
    }

    /// Load + canonically decode the revert journal published for
    /// `(height, block_hash)` (`None` if absent — always under the dormant gate,
    /// which produces no journal).
    pub fn load_journal(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
    ) -> Result<Option<BeaconStateDiff>> {
        match self.journal_bytes(height, block_hash)? {
            Some(bytes) => Ok(Some(beacon_decode(&bytes)?)),
            None => Ok(None),
        }
    }

    /// The raw journal row published for `(height, block_hash)`.
    ///
    /// Beacon journals are written by the publisher under
    /// [`sumchain_storage::schema::journal_key`], the same `(height,
    /// block_hash)` key the account and contract families use. This reader was
    /// left on the height-only key when those were re-keyed, so it could not
    /// find a journal the publisher had written. Reachable in the integration
    /// stack: with the gate open, `stage_block_revert` returns "nothing to
    /// revert" for every block and a reorg keeps the losing branch's beacon
    /// rows. Not reachable on a deployed chain, where the gate is `None` and no
    /// journal is written at all — so this is a defect the local stack can
    /// execute, not an observed failure of a running network.
    ///
    /// # A pre-#253 row fails closed
    ///
    /// The account and contract families fall back to the height-only key so an
    /// upgrading node can still revert a block an older binary wrote. Beacon
    /// does not, for the same reason compute-pool does not.
    ///
    /// A height-only row names a height and nothing else. Where two blocks
    /// competed at that height it cannot say which one it undoes, and applying
    /// the wrong block's undo record writes a predecessor that never existed
    /// into canonical state — silently, since every mutation in it decodes
    /// cleanly. Beacon has no history to preserve: the gate is `None` in
    /// production, so no beacon journal has ever been written at any height by
    /// any binary. A height-only row here cannot be a legitimate legacy journal.
    ///
    /// So it refuses, names the height, and requires the row to be removed or
    /// re-keyed offline where an operator can establish which block it came
    /// from — including when this block's own journal is present, since a stray
    /// row left behind would mislead the next reader. The row is never deleted:
    /// it is the only evidence of what it belonged to.
    fn journal_bytes(
        &self,
        height: BlockHeight,
        block_hash: &Hash,
    ) -> Result<Option<Vec<u8>>> {
        if self
            .db
            .contains(cf::BEACON_STATE_DIFFS, &height.to_be_bytes())?
        {
            return Err(StateError::InvalidOperation(format!(
                "beacon journal at height {height} is keyed by height alone. No \
                 beacon journal is written under the dormant gate, so this row \
                 cannot be identified with a block, and applying it could undo a \
                 different block's transition. Remove or re-key it offline \
                 before reverting."
            )));
        }
        self.db
            .get(
                cf::BEACON_STATE_DIFFS,
                &sumchain_storage::schema::journal_key(height, block_hash),
            )
            .map_err(Into::into)
    }

    // `persist_epoch_transition` and `persist_transition` are gone. Both
    // committed their own `WriteBatch` — beacon rows and a height-keyed journal
    // reaching canonical storage during execution, before anything had checked
    // the block's root. `stage_epoch_transition` and `stage_transition` replace
    // them. Keeping either as a convenience would have preserved exactly the
    // escape hatch this work removes.

    /// Stage a single **epoch's** transition into the block's candidate:
    /// replace exactly the rows of `epoch` (all other epochs' rows carried
    /// forward unchanged) with `current_epoch_rows`.
    ///
    /// The predecessor is read from the CANDIDATE, so the carried-forward rows
    /// are what this block sees rather than what its parent published.
    pub fn stage_epoch_transition(
        view: &mut ExecutionView<'_, '_>,
        epoch: u64,
        current_epoch_rows: BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(usize, JournalRecord)> {
        let before = Self::v_load_state_map(view)?;
        // after = (live rows NOT in this epoch) ∪ (this epoch's fresh materialization).
        let mut after: BTreeMap<Vec<u8>, Vec<u8>> = before
            .iter()
            .filter(|(k, _)| key_epoch(k) != Some(epoch))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        after.extend(current_epoch_rows);
        Self::stage_transition(view, &before, &after)
    }

    /// Stage the transition `before -> after` into the block's candidate and
    /// return its undo journal as an artifact.
    ///
    /// This replaces the removed `persist_transition` on the execution path, and
    /// differs from it in three ways that matter.
    ///
    /// **Nothing is committed.** Row writes and deletes are buffered into the
    /// view, so a block that is rejected or loses fork choice leaves no beacon
    /// row behind.
    ///
    /// **The journal is returned, not written.** It travels back to
    /// `execute_block`, is bound to the candidate at `finish_execution`, and is
    /// written by the publisher under `(height, block_hash)`. There is
    /// deliberately no `height` parameter: the old code keyed the journal by
    /// height alone, which two blocks at the same height share, so a side
    /// branch's journal overwrote the canonical one — and the duplicate-height
    /// guard meant to prevent that instead REFUSED the side branch's legitimate
    /// transition. Removing the parameter makes both mistakes unrepresentable.
    ///
    /// **The predecessor is the candidate's state, not the chain's.**
    ///
    /// Returns the number of mutated rows and the journal (`NothingToUndo` for a
    /// genuine no-op, which stages nothing).
    pub fn stage_transition(
        view: &mut ExecutionView<'_, '_>,
        before: &BTreeMap<Vec<u8>, Vec<u8>>,
        after: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(usize, JournalRecord)> {
        // One beacon transition per block. The old guard asked the committed
        // store whether a journal existed at this height, which conflated two
        // blocks at the same height; this asks the candidate whether it has
        // already staged beacon rows, which is the question that was meant.
        //
        // A transition that mutated nothing stages nothing and so is not
        // detected here — correctly: it produced no journal either, and there is
        // nothing for a second call to overwrite.
        if view.preimages_for(cf::BEACON_STATE).next().is_some() {
            return Err(StateError::InvalidOperation(
                "beacon transition already staged for this block; refusing to \
                 stage a second one over it"
                    .into(),
            ));
        }

        // Every row key must carry a recognized beacon domain prefix.
        for k in before.keys().chain(after.keys()) {
            if !is_beacon_domain(k) {
                return Err(StateError::InvalidOperation(
                    "beacon stage_transition: row key has no recognized domain prefix".into(),
                ));
            }
        }

        // Stale-predecessor guard, against the candidate.
        let live = Self::v_load_state_map(view)?;
        if *before != live {
            return Err(StateError::InvalidOperation(
                "beacon stage_transition: stale `before` snapshot does not match \
                 the candidate's live state"
                    .into(),
            ));
        }

        let mut keys: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
        for k in before.keys().chain(after.keys()) {
            keys.insert(k.clone(), ());
        }

        let mut diff = BeaconStateDiff::default();
        for key in keys.keys() {
            let new = after.get(key).cloned();
            let old = live.get(key).cloned();
            if old == new {
                continue;
            }
            diff.records.push(BeaconMutation {
                key: key.clone(),
                old,
                new,
            });
        }
        if diff.is_empty() {
            return Ok((0, JournalRecord::NothingToUndo));
        }
        diff.sort();
        // Everything fallible that does not touch the view happens first: the
        // journal is encoded before a single row is staged, so an encoding
        // failure leaves the candidate untouched rather than half-written.
        let journal = beacon_encode(&diff)?;

        for record in &diff.records {
            match &record.new {
                Some(v) => view.put(cf::BEACON_STATE, &record.key, v)?,
                None => view.delete(cf::BEACON_STATE, &record.key)?,
            }
        }
        Ok((diff.records.len(), JournalRecord::Recorded(journal)))
    }

    /// Stage the reverse-replay of the per-height beacon journal (and the journal's
    /// own deletion) into a caller-provided [`WriteBatch`](sumchain_storage::db::
    /// WriteBatch), returning whether anything was staged (`false` when no journal
    /// exists — ALWAYS under the dormant gate). This composes into the SAME atomic
    /// write as the account + contract + C1 revert, so a crash can never leave a
    /// partially-reverted node. Every key's domain prefix is validated BEFORE it is
    /// staged, so a corrupt journal aborts the whole multi-family revert.
    pub fn stage_block_revert(
        &self,
        batch: &mut sumchain_storage::db::WriteBatch<'_>,
        height: BlockHeight,
        block_hash: &Hash,
    ) -> Result<bool> {
        let Some(bytes) = self.journal_bytes(height, block_hash)? else {
            return Ok(false);
        };
        let diff: BeaconStateDiff = beacon_decode(&bytes)?;
        for record in diff.records.iter().rev() {
            if !is_beacon_domain(&record.key) {
                return Err(StateError::InvalidOperation(format!(
                    "beacon revert: unrecognized key domain at height {height}"
                )));
            }
            match &record.old {
                Some(v) => batch.put(cf::BEACON_STATE, &record.key, v)?,
                None => batch.delete(cf::BEACON_STATE, &record.key)?,
            }
        }
        // Only this block's key. A height-only row is never reached here —
        // `journal_bytes` refuses before returning — and deleting one silently
        // would destroy the evidence an operator needs to attribute it.
        batch.delete(
            cf::BEACON_STATE_DIFFS,
            &sumchain_storage::schema::journal_key(height, block_hash),
        )?;
        Ok(true)
    }

    /// Atomically revert the beacon mutations recorded for `height` in isolation
    /// (its own [`Database::batch`]). Thin wrapper over [`stage_block_revert`](Self::
    /// stage_block_revert); retained for the standalone store tests. The LIVE reorg
    /// path drives `stage_block_revert` into the unified batch instead.
    pub fn revert_block(&self, height: BlockHeight, block_hash: &Hash) -> Result<()> {
        let mut batch = self.db.batch();
        if self.stage_block_revert(&mut batch, height, block_hash)? {
            batch.commit()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_storage::overlay::ApplicationOverlay;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    /// A stand-in block hash for `height`, distinct per `variant` where a test
    /// needs two blocks at one height.
    fn bh(height: BlockHeight, variant: u8) -> Hash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&height.to_be_bytes());
        b[31] = variant;
        Hash::new(b)
    }

    /// Publish one transition, standing in for the block pipeline: stage it into
    /// a candidate, then commit the journal's rows and the journal itself under
    /// the publisher's `(height, block_hash)` key.
    ///
    /// TEST FIXTURE, not an API. `ApplicationOverlay::into_batch` is
    /// crate-private to `sumchain-storage` — deliberately, so that outside that
    /// crate only `AcceptedCandidate::publish` turns a candidate into canonical
    /// state. These are storage-codec unit tests that need committed rows to
    /// exercise revert and cross-block sequences; driving a real block through
    /// acceptance to set them up would couple them to consensus for nothing.
    /// Rows are replayed from the journal the staging produced, so the fixture
    /// cannot publish rows the candidate did not stage.
    fn publish_transition(
        db: &Database,
        before: &BTreeMap<Vec<u8>, Vec<u8>>,
        after: &BTreeMap<Vec<u8>, Vec<u8>>,
        height: BlockHeight,
        block_hash: &Hash,
    ) -> Result<usize> {
        let mut overlay = ApplicationOverlay::new(db, 1 << 30);
        let (mutated, journal) = {
            let mut view = ExecutionView::new(&mut overlay);
            BeaconStore::stage_transition(&mut view, before, after)?
        };
        drop(overlay);
        if let JournalRecord::Recorded(bytes) = &journal {
            let diff = BeaconStateDiff::decode(bytes)?;
            let mut batch = db.batch();
            for r in &diff.records {
                match &r.new {
                    Some(v) => batch.put(cf::BEACON_STATE, &r.key, v)?,
                    None => batch.delete(cf::BEACON_STATE, &r.key)?,
                }
            }
            batch.put(
                cf::BEACON_STATE_DIFFS,
                &sumchain_storage::schema::journal_key(height, block_hash),
                bytes,
            )?;
            batch.commit()?;
        }
        Ok(mutated)
    }

    fn open_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    fn row(prefix: u8, k: &[u8], v: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut key = vec![prefix];
        key.extend_from_slice(k);
        (key, v.to_vec())
    }

    #[test]
    fn beacon_state_digest_domain_is_frozen() {
        assert_eq!(BEACON_STATE_DIGEST_DOMAIN, b"sumchain.beacon.state.v1");
        assert!(BEACON_STATE_DIGEST_DOMAIN.ends_with(b".v1"));
    }

    #[test]
    fn empty_digest_is_domain_only() {
        let (db, _d) = open_db();
        assert_eq!(
            BeaconStore::new(&db).state_digest().unwrap(),
            Hash::hash(BEACON_STATE_DIGEST_DOMAIN),
            "empty beacon state hashes to the domain-only digest"
        );
    }

    #[test]
    fn digest_is_insertion_order_independent_and_length_framed() {
        let a = row(domain::KEY, b"aa", b"1");
        let b = row(domain::DEAL, b"bb", b"22");
        let (db1, _dir1) = open_db();
        db1.put(cf::BEACON_STATE, &a.0, &a.1).unwrap();
        db1.put(cf::BEACON_STATE, &b.0, &b.1).unwrap();
        let d1 = BeaconStore::new(&db1).state_digest().unwrap();
        let (db2, _dir2) = open_db();
        db2.put(cf::BEACON_STATE, &b.0, &b.1).unwrap();
        db2.put(cf::BEACON_STATE, &a.0, &a.1).unwrap();
        let d2 = BeaconStore::new(&db2).state_digest().unwrap();
        assert_eq!(d1, d2, "digest is insertion-order independent");

        // Length framing disambiguates equal concatenations.
        let (db3, _dir3) = open_db();
        db3.put(cf::BEACON_STATE, &[domain::KEY, b'a', b'b'], b"c")
            .unwrap();
        let (db4, _dir4) = open_db();
        db4.put(cf::BEACON_STATE, &[domain::KEY, b'a'], b"bc")
            .unwrap();
        assert_ne!(
            BeaconStore::new(&db3).state_digest().unwrap(),
            BeaconStore::new(&db4).state_digest().unwrap()
        );
    }

    #[test]
    fn persist_revert_reapply_roundtrip() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let (k1, v1) = row(domain::KEY, b"v0", b"ek0");
        let (k2, v2) = row(domain::ROUND, b"r0", b"sig0");

        let mut after = BTreeMap::new();
        after.insert(k1.clone(), v1.clone());
        after.insert(k2.clone(), v2.clone());
        let before = BTreeMap::new();

        let n = publish_transition(&db, &before, &after, 1, &bh(1, 0)).unwrap();
        assert_eq!(n, 2);
        assert_eq!(store.load_state_map().unwrap(), after);
        let committed = store.state_digest().unwrap();

        // Revert restores the empty predecessor.
        store.revert_block(1, &bh(1, 0)).unwrap();
        assert!(store.load_state_map().unwrap().is_empty());
        assert_eq!(
            store.state_digest().unwrap(),
            Hash::hash(BEACON_STATE_DIGEST_DOMAIN)
        );
        assert!(!store.has_journal(1, &bh(1, 0)).unwrap());

        // Reapply reproduces the identical committed state.
        publish_transition(&db, &before, &after, 1, &bh(1, 0)).unwrap();
        assert_eq!(store.state_digest().unwrap(), committed);
    }

    #[test]
    fn duplicate_height_and_stale_predecessor_rejected() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let (k1, v1) = row(domain::KEY, b"v0", b"ek0");
        let mut after = BTreeMap::new();
        after.insert(k1, v1);
        let before = BTreeMap::new();
        publish_transition(&db, &before, &after, 1, &bh(1, 0)).unwrap();

        // Duplicate height rejected.
        assert!(publish_transition(&db, &before, &after, 1, &bh(1, 0)).is_err());
        // Stale predecessor (claims empty but live is non-empty) rejected at height 2.
        let after2 = after.clone();
        assert!(publish_transition(&db, &BTreeMap::new(), &after2, 2, &bh(2, 0))
            .is_err());
    }

    #[test]
    fn non_beacon_domain_row_rejected() {
        let (db, _d) = open_db();
        let store = BeaconStore::new(&db);
        let mut after = BTreeMap::new();
        after.insert(vec![0xFF, 0x00], b"x".to_vec()); // 0xFF is not a beacon domain
        assert!(publish_transition(&db, &BTreeMap::new(), &after, 1, &bh(1, 0))
            .is_err());
    }

    // ── Item 2: frozen typed-record codec + key layouts + strict decode ──────

    fn null_ref() -> StoredSignedRef {
        StoredSignedRef {
            signer: [0u8; 32],
            tx_ref: [0u8; 32],
            carrier: vec![],
        }
    }

    #[test]
    fn record_version_and_key_layouts_are_frozen() {
        assert_eq!(BEACON_RECORD_VERSION, 1);
        // Epoch-keyed domain-prefixed big-endian composite keys (exact bytes pinned):
        // DOMAIN(1) ‖ epoch(8 BE) ‖ body.
        assert_eq!(
            key_row_key(7, 2),
            vec![0x01, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 2]
        );
        assert_eq!(
            deal_row_key(7, 1, 2),
            vec![0x02, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 2]
        );
        assert_eq!(
            disqualified_row_key(7, 4),
            vec![0x03, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 4]
        );
        assert_eq!(
            round_row_key(7, 5),
            vec![0x04, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 5]
        );
        assert_eq!(
            output_row_key(7, 6),
            vec![0x05, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 6]
        );
        assert_eq!(membership_row_key(7), vec![0x06, 0, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(
            false_accuser_row_key(7, 1),
            vec![0x07, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1]
        );
        assert_eq!(
            adjudicated_row_key(7, 1, 2),
            vec![0x08, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 2]
        );
        // Equivocation keys embed both conflicting tx refs (collision-free).
        assert_eq!(
            key_equiv_row_key(7, &[0xAA; 32], &[0xBB; 32]).len(),
            1 + 8 + 32 + 32
        );
        assert_eq!(deal_equiv_row_key(7, &[0xAA; 32], &[0xBB; 32])[0], 0x0A);
    }

    #[test]
    fn stored_records_roundtrip_and_bytes_are_frozen() {
        // A key record with a fixed ek + null ref → frozen canonical prefix + strict
        // decode. bincode fixint LE: version(1) ‖ u32_le(idx) ‖ len(u64_le=48) ‖ ek ‖
        // record{ signer(32) ‖ tx_ref(32) ‖ carrier_len(u64_le=0) }.
        let k = StoredBeaconKey {
            schema_version: BEACON_RECORD_VERSION,
            validator_index: 2,
            ek: vec![0xAB; G1_LEN],
            record: null_ref(),
        };
        let kb = beacon_encode(&k).unwrap();
        assert_eq!(&kb[0..1], &[0x01]);
        assert_eq!(&kb[1..5], &2u32.to_le_bytes());
        assert_eq!(&kb[5..13], &48u64.to_le_bytes());
        assert_eq!(kb.len(), 1 + 4 + 8 + G1_LEN + 32 + 32 + 8);
        assert_eq!(decode_key(&kb).unwrap(), k);

        // Round / output / disqualified / membership / false-accuser / adjudicated /
        // equivocation round-trips.
        let r = StoredBeaconRound {
            schema_version: BEACON_RECORD_VERSION,
            round: 9,
            sigma_r: vec![0x11; G2_LEN],
        };
        assert_eq!(decode_round(&beacon_encode(&r).unwrap()).unwrap(), r);
        let o = StoredBeaconOutput {
            schema_version: BEACON_RECORD_VERSION,
            round: 9,
            output: vec![0x22; OUT_LEN],
        };
        assert_eq!(decode_output(&beacon_encode(&o).unwrap()).unwrap(), o);
        let d = StoredBeaconDisqualified {
            schema_version: BEACON_RECORD_VERSION,
            dealer_i: 3,
        };
        assert_eq!(decode_disqualified(&beacon_encode(&d).unwrap()).unwrap(), d);
        let mem = StoredBeaconMembership {
            schema_version: BEACON_RECORD_VERSION,
            epoch: 7,
            members: vec![[1u8; 32], [2u8; 32]],
        };
        assert_eq!(
            decode_membership(&beacon_encode(&mem).unwrap()).unwrap(),
            mem
        );
        let fa = StoredBeaconFalseAccuser {
            schema_version: BEACON_RECORD_VERSION,
            recipient_j: 4,
        };
        assert_eq!(
            decode_false_accuser(&beacon_encode(&fa).unwrap()).unwrap(),
            fa
        );
        let adj = StoredBeaconAdjudicated {
            schema_version: BEACON_RECORD_VERSION,
            dealer_i: 1,
            recipient_j: 2,
        };
        assert_eq!(
            decode_adjudicated(&beacon_encode(&adj).unwrap()).unwrap(),
            adj
        );
        let ke = StoredBeaconKeyEquivocation {
            schema_version: BEACON_RECORD_VERSION,
            validator_index: 0,
            first: null_ref(),
            second: StoredSignedRef {
                signer: [9u8; 32],
                tx_ref: [8u8; 32],
                carrier: vec![1, 2, 3],
            },
        };
        assert_eq!(
            decode_key_equivocation(&beacon_encode(&ke).unwrap()).unwrap(),
            ke
        );
    }

    #[test]
    fn strict_decode_rejects_bad_version_length_and_trailing() {
        // Wrong version.
        let bad_ver = StoredBeaconKey {
            schema_version: 2,
            validator_index: 0,
            ek: vec![0; G1_LEN],
            record: null_ref(),
        };
        assert!(decode_key(&beacon_encode(&bad_ver).unwrap()).is_err());
        // Wrong ek length.
        let bad_len = StoredBeaconKey {
            schema_version: BEACON_RECORD_VERSION,
            validator_index: 0,
            ek: vec![0; G1_LEN - 1],
            record: null_ref(),
        };
        assert!(decode_key(&beacon_encode(&bad_len).unwrap()).is_err());
        // Trailing bytes rejected by the canonical decoder.
        let mut trailing = beacon_encode(&StoredBeaconKey {
            schema_version: BEACON_RECORD_VERSION,
            validator_index: 0,
            ek: vec![0; G1_LEN],
            record: null_ref(),
        })
        .unwrap();
        trailing.push(0xFF);
        assert!(decode_key(&trailing).is_err());
        // A deal with an empty commitment vector is rejected.
        let bad_deal = StoredBeaconDeal {
            schema_version: BEACON_RECORD_VERSION,
            dealer_i: 0,
            recipient_j: 0,
            commitments: vec![],
            r_ij: vec![0; G1_LEN],
            ct_ij: vec![0; CT_LEN],
            record: null_ref(),
        };
        assert!(decode_deal(&beacon_encode(&bad_deal).unwrap()).is_err());
    }
}

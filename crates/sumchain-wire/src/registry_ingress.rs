//! C5 registry ingress (#242): the payloads of the proposed governance-v1
//! operations 8 (register) and 9 (disable).
//!
//! UNWIRED: [`crate::governance::GovernanceOperation`] has no variant 8 or 9,
//! so no transaction decodes to these payloads. Adding the two wire variants is
//! the separately authorized activation change (a coordinated, same-window
//! upgrade).
//!
//! PROPOSED, NOT RATIFIED. The mechanism, layouts, signing domains, threshold
//! source and lifecycle rules are those of the C5 proposal (mechanism B). The
//! full byte specification, its open questions and the vectors are in
//! `docs/proposals/c5-registry-ingress/`. Nothing here is a byte ratification.
//!
//! DORMANT. Every named parameter in [`RegistryIngressParams`] is unvalued, and
//! an operation refuses unless all of them are set ([`RegistryIngressParams::complete`]).
//! The production value (`sumchain_state::registry_ingress::REGISTRY_INGRESS_PARAMS`)
//! is [`RegistryIngressParams::UNSET`].
//!
//! Conventions: little-endian integers (D0); `decode_exact` refuses trailing
//! bytes; approvals are carried in strictly ascending pubkey order, so every
//! accepted payload has exactly one encoding.

use core::cmp::Ordering;

use crate::b0::codec::{DecodeError, Reader, Writer};
use crate::b0::enums::Candidate;
use crate::registry_wire::{RegistryRecordV1, RegistryStatus};
use crate::validator_authority::ValidatorApproval;
use crate::ChainId;

/// MAGIC of [`RegistryRegisterV1`] (PROPOSED).
pub const REGISTRY_REGISTER_MAGIC: [u8; 7] = *b"RRGRv1\0";
/// MAGIC of [`RegistryDisableV1`] (PROPOSED).
pub const REGISTRY_DISABLE_MAGIC: [u8; 7] = *b"RDISv1\0";
/// The only schema value either operation accepts.
pub const REGISTRY_INGRESS_SCHEMA_VERSION: u16 = 1;

/// Signing domain of a register approval (PROPOSED). NUL-terminated, like the
/// registry family's KDF tags, and distinct from each of them.
pub const REGISTRY_REGISTER_DOMAIN: &[u8] = b"SUMCHAIN/REGISTRY/REGISTER/v1\0";
/// Signing domain of a disable approval (PROPOSED).
pub const REGISTRY_DISABLE_DOMAIN: &[u8] = b"SUMCHAIN/REGISTRY/DISABLE/v1\0";

/// One approval on the wire: pubkey (32) ‖ Ed25519 signature (64).
pub const REGISTRY_APPROVAL_LEN: usize = 96;

/// The proof systems a registry record may name.
///
/// Not chosen here: B0-FINAL fixed `proof_system_id` as RISC0 (discriminant 2).
/// `registry_dryRunAdmit` and the register operation read this one list.
pub fn admitted_proof_systems() -> [u16; 1] {
    [Candidate::Risc0.to_repr()]
}

// ── Named parameters (PROPOSED, unvalued) ───────────────────────────────────

/// The C5 named parameters. `None` is "not ratified". The structure (two
/// optional values, no defaults, paired presence, `1..=u32::MAX`, checked
/// arithmetic) was accepted by the owner on 2026-10-23; the values are not
/// decided.
///
/// No field has a value in this binary, and none is invented here. Operations
/// 8 and 9 refuse unless every field is `Some` ([`Self::complete`]).
///
/// Decided by the owner on 2026-10-22, and therefore not parameters:
/// - **Q17:** register is authorized at the authenticated governance threshold,
///   `GovernanceParams.validator_authority_threshold_bps`.
/// - **B2 (2026-10-23):** disable is authorized at the stored record's
///   `approval_threshold_bps`, which register made at least the governance
///   threshold of its time; later governance changes do not move it.
/// - **Q3:** a record `approval_threshold_bps` default is a tooling-only
///   convenience. No consensus path has or reads one: the applicable threshold
///   always comes from authenticated state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryIngressParams {
    /// `T_min`: register at height `h` needs `activation_height ≥ h + T_min`
    /// (#217 B6, #212).
    pub registry_min_timelock_blocks: Option<u64>,
    /// The approval window: the largest `valid_until − h` accepted.
    pub registry_max_approval_window: Option<u64>,
}

/// Why a set of named parameters cannot be used (owner, 2026-10-23: paired
/// presence, each value in `1..=u32::MAX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryParamsError {
    /// One value is set and the other is not; they come as a pair.
    Partial,
    /// A value is outside `1..=u32::MAX`.
    OutOfRange { name: &'static str, value: u64 },
}

/// Every named parameter, present. Obtainable only through
/// [`RegistryIngressParams::complete`] by the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryIngressValues {
    pub min_timelock_blocks: u64,
    pub max_approval_window: u64,
}

impl RegistryIngressParams {
    /// Every parameter unset: operations 8 and 9 refuse.
    pub const UNSET: Self = Self {
        registry_min_timelock_blocks: None,
        registry_max_approval_window: None,
    };

    /// Paired presence, and each value in `1..=u32::MAX`. Both unset is valid:
    /// it is the dormant state, in which the operations refuse.
    pub fn validate(&self) -> Result<(), RegistryParamsError> {
        match (
            self.registry_min_timelock_blocks,
            self.registry_max_approval_window,
        ) {
            (None, None) => Ok(()),
            (Some(t_min), Some(window)) => {
                for (name, value) in [
                    ("registry_min_timelock_blocks", t_min),
                    ("registry_max_approval_window", window),
                ] {
                    if !(1..=u32::MAX as u64).contains(&value) {
                        return Err(RegistryParamsError::OutOfRange { name, value });
                    }
                }
                Ok(())
            }
            _ => Err(RegistryParamsError::Partial),
        }
    }

    /// Both values, only when both are set and [`Self::validate`] accepts
    /// them; otherwise `None`. A missing or invalid value can therefore never
    /// be defaulted on the way to execution.
    pub fn complete(&self) -> Option<RegistryIngressValues> {
        self.validate().ok()?;
        Some(RegistryIngressValues {
            min_timelock_blocks: self.registry_min_timelock_blocks?,
            max_approval_window: self.registry_max_approval_window?,
        })
    }
}

/// The record's provenance commitments that are all zero, by name, in a fixed
/// order. #217 B1 makes all three mandatory; a zero commitment commits to
/// nothing. Register refuses a record with any (Q9, owner 2026-10-22), and
/// `registry_dryRunAdmit` reports exactly these names, so the two cannot
/// disagree.
pub fn unset_commitments(record: &RegistryRecordV1) -> Vec<&'static str> {
    [
        ("audit_commitment", &record.audit_commitment),
        ("source_commitment", &record.source_commitment),
        ("ceremony_commitment", &record.ceremony_commitment),
    ]
    .into_iter()
    .filter(|(_, c)| c.iter().all(|&b| b == 0))
    .map(|(name, _)| name)
    .collect()
}

// ── Approvals ───────────────────────────────────────────────────────────────

fn check_ascending(prev: &[u8; 32], next: &[u8; 32], ctx: &'static str) -> Result<(), DecodeError> {
    match prev.cmp(next) {
        Ordering::Less => Ok(()),
        Ordering::Equal => Err(DecodeError::DuplicateEntry { ctx }),
        Ordering::Greater => Err(DecodeError::NonCanonicalOrder { ctx }),
    }
}

fn write_approvals(
    w: &mut Writer,
    approvals: &[ValidatorApproval],
    ctx: &'static str,
) -> Result<(), DecodeError> {
    let k = u16::try_from(approvals.len()).map_err(|_| DecodeError::CountExceedsMax {
        ctx,
        count: approvals.len() as u64,
        max: u16::MAX as u64,
    })?;
    for pair in approvals.windows(2) {
        check_ascending(&pair[0].pubkey, &pair[1].pubkey, ctx)?;
    }
    w.u16(k);
    for a in approvals {
        w.bytes(&a.pubkey);
        w.bytes(&a.signature);
    }
    Ok(())
}

fn read_approvals(r: &mut Reader, ctx: &'static str) -> Result<Vec<ValidatorApproval>, DecodeError> {
    let k = r.read_u16(ctx)? as usize;
    // Every entry must be present before anything is allocated for it.
    let needed = k * REGISTRY_APPROVAL_LEN;
    if r.remaining() < needed {
        return Err(DecodeError::Truncated {
            needed,
            remaining: r.remaining(),
            ctx,
        });
    }
    let mut out: Vec<ValidatorApproval> = Vec::with_capacity(k);
    for _ in 0..k {
        let pubkey = r.read_array::<32>(ctx)?;
        let signature = r.read_array::<64>(ctx)?;
        if let Some(prev) = out.last() {
            check_ascending(&prev.pubkey, &pubkey, ctx)?;
        }
        out.push(ValidatorApproval { pubkey, signature });
    }
    Ok(out)
}

fn read_header(r: &mut Reader, magic: [u8; 7], ctx: &'static str) -> Result<u64, DecodeError> {
    if r.read_array::<7>(ctx)? != magic {
        return Err(DecodeError::BadTag { ctx });
    }
    let schema = r.read_u16(ctx)?;
    if schema != REGISTRY_INGRESS_SCHEMA_VERSION {
        return Err(DecodeError::BadFixedScalar {
            ctx,
            value: schema as u64,
        });
    }
    r.read_u64(ctx)
}

// ── Operation 8: register ───────────────────────────────────────────────────

/// `GovernanceTxData.data` of operation 8, `173 + 96·k` bytes:
///
/// ```text
///   0    MAGIC[7] = "RRGRv1\0"
///   7    schema        u16 = 1
///   9    valid_until   u64
///   17   record        RegistryRecordV1 (154, frozen bytes)
///   171  k             u16
///   173  k × (pubkey[32] ‖ signature[64]), pubkeys strictly ascending
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRegisterV1 {
    pub valid_until: u64,
    pub record: RegistryRecordV1,
    pub approvals: Vec<ValidatorApproval>,
}

impl RegistryRegisterV1 {
    /// The canonical encoding. Refuses approvals that are not strictly
    /// ascending, or more than `u16::MAX` of them.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        let mut w = Writer::new();
        w.bytes(&REGISTRY_REGISTER_MAGIC);
        w.u16(REGISTRY_INGRESS_SCHEMA_VERSION);
        w.u64(self.valid_until);
        w.bytes(&self.record.try_encode()?);
        write_approvals(&mut w, &self.approvals, "RegistryRegisterV1")?;
        Ok(w.into_bytes())
    }

    /// Decode a complete buffer: wrong MAGIC, any schema but 1, a malformed
    /// record, a truncation, unordered or repeated pubkeys and trailing bytes
    /// are all refused.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let valid_until = read_header(&mut r, REGISTRY_REGISTER_MAGIC, "RegistryRegisterV1")?;
        let record = RegistryRecordV1::decode(&mut r)?;
        let approvals = read_approvals(&mut r, "RegistryRegisterV1")?;
        r.finish("RegistryRegisterV1")?;
        Ok(Self {
            valid_until,
            record,
            approvals,
        })
    }
}

/// The bytes each validator signs to approve registering `record`, 232 bytes:
///
/// `REGISTRY_REGISTER_DOMAIN[30] ‖ chain_id u64 ‖ genesis_block_hash[32] ‖
/// valid_until u64 ‖ record[154]`
pub fn registry_register_signing_bytes(
    chain_id: ChainId,
    genesis_block_hash: &[u8; 32],
    valid_until: u64,
    record: &RegistryRecordV1,
) -> Result<Vec<u8>, DecodeError> {
    let record = record.try_encode()?;
    let mut m = Vec::with_capacity(REGISTRY_REGISTER_DOMAIN.len() + 8 + 32 + 8 + record.len());
    m.extend_from_slice(REGISTRY_REGISTER_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(genesis_block_hash);
    m.extend_from_slice(&valid_until.to_le_bytes());
    m.extend_from_slice(&record);
    Ok(m)
}

// ── Operation 9: disable ────────────────────────────────────────────────────

/// `GovernanceTxData.data` of operation 9, `51 + 96·k` bytes:
///
/// ```text
///   0    MAGIC[7] = "RDISv1\0"
///   7    schema        u16 = 1
///   9    valid_until   u64
///   17   id            [32]
///   49   k             u16
///   51   k × (pubkey[32] ‖ signature[64]), pubkeys strictly ascending
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryDisableV1 {
    pub valid_until: u64,
    pub id: [u8; 32],
    pub approvals: Vec<ValidatorApproval>,
}

impl RegistryDisableV1 {
    /// The canonical encoding; refuses approvals as [`RegistryRegisterV1::try_encode`] does.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        let mut w = Writer::new();
        w.bytes(&REGISTRY_DISABLE_MAGIC);
        w.u16(REGISTRY_INGRESS_SCHEMA_VERSION);
        w.u64(self.valid_until);
        w.bytes(&self.id);
        write_approvals(&mut w, &self.approvals, "RegistryDisableV1")?;
        Ok(w.into_bytes())
    }

    /// Decode a complete buffer, with the refusals of [`RegistryRegisterV1::decode_exact`].
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let valid_until = read_header(&mut r, REGISTRY_DISABLE_MAGIC, "RegistryDisableV1")?;
        let id = r.read_array::<32>("RegistryDisableV1")?;
        let approvals = read_approvals(&mut r, "RegistryDisableV1")?;
        r.finish("RegistryDisableV1")?;
        Ok(Self {
            valid_until,
            id,
            approvals,
        })
    }
}

/// The bytes each validator signs to approve disabling `id`, 109 bytes:
///
/// `REGISTRY_DISABLE_DOMAIN[29] ‖ chain_id u64 ‖ genesis_block_hash[32] ‖
/// valid_until u64 ‖ id[32]`
pub fn registry_disable_signing_bytes(
    chain_id: ChainId,
    genesis_block_hash: &[u8; 32],
    valid_until: u64,
    id: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(REGISTRY_DISABLE_DOMAIN.len() + 8 + 32 + 8 + 32);
    m.extend_from_slice(REGISTRY_DISABLE_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(genesis_block_hash);
    m.extend_from_slice(&valid_until.to_le_bytes());
    m.extend_from_slice(id);
    m
}

// ── Height rules ────────────────────────────────────────────────────────────

/// `activation_height ≥ h + T_min`, in exact arithmetic: a sum past `u64::MAX`
/// is one no `u64` activation height reaches.
pub fn timelock_satisfied(activation_height: u64, height: u64, min_timelock_blocks: u64) -> bool {
    activation_height as u128 >= height as u128 + min_timelock_blocks as u128
}

/// `h ≤ valid_until` and `valid_until − h ≤ max_window`.
pub fn approval_window_open(height: u64, valid_until: u64, max_window: u64) -> bool {
    match valid_until.checked_sub(height) {
        Some(remaining) => remaining <= max_window,
        None => false,
    }
}

// ── Commit side (#128's runtime check) ──────────────────────────────────────

/// Why a consumer may not reference a registry record at its execution point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryCommitRefusal {
    /// No record has this id.
    Unknown,
    /// The record was disabled before this point.
    Disabled,
    /// `h < activation_height`: the timelock has not passed.
    BeforeActivation { activation_height: u64, height: u64 },
}

/// A commit at height `h` may reference `record` only if it exists, is
/// Enabled and `h ≥ activation_height`. `record` is the registry state at the
/// commit's own execution point, so a disable earlier in the same block
/// already applies and one later does not.
pub fn check_commit(record: Option<&RegistryRecordV1>, height: u64) -> Result<(), RegistryCommitRefusal> {
    let record = record.ok_or(RegistryCommitRefusal::Unknown)?;
    if record.status != RegistryStatus::Enabled {
        return Err(RegistryCommitRefusal::Disabled);
    }
    if height < record.activation_height {
        return Err(RegistryCommitRefusal::BeforeActivation {
            activation_height: record.activation_height,
            height,
        });
    }
    Ok(())
}

// ── Activation-change encodings (PROPOSED, dormant, unwired) ────────────────
//
// The byte forms the activation proposal (README §16, §17) relies on, defined
// here so that they have one implementation, vectors and refusal tests before
// the activation change exists. Nothing calls them: no root folds `P(h)` or
// `R(h)`, and no node writes the freeze record or the gate pin.

/// Domain of the registry-parameters digest `P(h)` (PROPOSED).
pub const REGISTRY_PARAMS_DIGEST_DOMAIN: &[u8] = b"SUMCHAIN/REGISTRY/PARAMS/v1\0";
/// Domain of the registry-state digest `R(h)` (PROPOSED).
pub const REGISTRY_STATE_DIGEST_DOMAIN: &[u8] = b"SUMCHAIN/REGISTRY/STATE/v1\0";

/// The preimage of `P(h)`. Integers are **big-endian**, like the state root's
/// own integers:
///
/// `REGISTRY_PARAMS_DIGEST_DOMAIN[28] ‖ gov_tag u8 [‖ threshold_bps u16] ‖
/// reg_tag u8 [‖ T_min u64 ‖ W u64]`
///
/// A tag is 0 when its values are absent and 1 when present. `T_min` and `W`
/// are present or absent together (paired presence).
pub fn registry_params_digest_preimage(
    governance_threshold_bps: Option<u16>,
    timelock_and_window: Option<(u64, u64)>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(REGISTRY_PARAMS_DIGEST_DOMAIN.len() + 1 + 2 + 1 + 16);
    m.extend_from_slice(REGISTRY_PARAMS_DIGEST_DOMAIN);
    match governance_threshold_bps {
        Some(bps) => {
            m.push(1);
            m.extend_from_slice(&bps.to_be_bytes());
        }
        None => m.push(0),
    }
    match timelock_and_window {
        Some((t_min, w)) => {
            m.push(1);
            m.extend_from_slice(&t_min.to_be_bytes());
            m.extend_from_slice(&w.to_be_bytes());
        }
        None => m.push(0),
    }
    m
}

/// `P(h)` = BLAKE3 of [`registry_params_digest_preimage`].
pub fn registry_params_digest(
    governance_threshold_bps: Option<u16>,
    timelock_and_window: Option<(u64, u64)>,
) -> crate::hash::Hash {
    crate::hash::Hash::hash(&registry_params_digest_preimage(
        governance_threshold_bps,
        timelock_and_window,
    ))
}

/// The preimage of `R(h)` over `rows`, which the caller supplies in ascending
/// key order, each an id and that record's frozen bytes. The count is a
/// **big-endian** u64 after the rows:
///
/// `REGISTRY_STATE_DIGEST_DOMAIN[27] ‖ (id[32] ‖ record[154])* ‖ count u64`
///
/// The row rule (the key is `registry/v1/` ‖ id, the record decodes and its id
/// is the key's) is checked where the rows are read, by
/// `sumchain_state::registry_ingress::checked_registry_row`.
pub fn registry_state_digest_preimage<'a>(
    rows: impl IntoIterator<Item = (&'a [u8; 32], &'a [u8; RegistryRecordV1::LEN])>,
) -> Vec<u8> {
    let mut m = REGISTRY_STATE_DIGEST_DOMAIN.to_vec();
    let mut count: u64 = 0;
    for (id, record) in rows {
        m.extend_from_slice(id);
        m.extend_from_slice(record);
        count += 1;
    }
    m.extend_from_slice(&count.to_be_bytes());
    m
}

/// MAGIC of the node-local freeze record (PROPOSED).
pub const REGISTRY_FREEZE_MAGIC: [u8; 7] = *b"RFRZv1\0";
/// Length of [`RegistryFreezeRecordV1`]: 7 + 8 + 2 + 8 + 8 + 8.
pub const REGISTRY_FREEZE_RECORD_LEN: usize = 41;

/// The node-local freeze record (README §17 (a), PROPOSED). Not consensus
/// state: it lives in `cf::META`, outside the generic journal, and says which
/// values this node committed to at its first publish at or above A. Integers
/// are **little-endian**, like the ConsensusConfig record:
///
/// `REGISTRY_FREEZE_MAGIC[7] ‖ gate_a u64 ‖ threshold_bps u16 ‖ t_min u64 ‖
/// w u64 ‖ first_height u64`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryFreezeRecordV1 {
    /// The registry activation height A, as configured.
    pub gate_a: u64,
    /// The governance threshold the block at `first_height` executed with.
    pub threshold_bps: u16,
    /// T_min the block at `first_height` executed with.
    pub t_min: u64,
    /// W the block at `first_height` executed with.
    pub w: u64,
    /// The height of the block whose publication wrote the record (≥ A).
    pub first_height: u64,
}

impl RegistryFreezeRecordV1 {
    /// The 41-byte encoding.
    pub fn encode(&self) -> [u8; REGISTRY_FREEZE_RECORD_LEN] {
        let mut out = [0u8; REGISTRY_FREEZE_RECORD_LEN];
        out[..7].copy_from_slice(&REGISTRY_FREEZE_MAGIC);
        out[7..15].copy_from_slice(&self.gate_a.to_le_bytes());
        out[15..17].copy_from_slice(&self.threshold_bps.to_le_bytes());
        out[17..25].copy_from_slice(&self.t_min.to_le_bytes());
        out[25..33].copy_from_slice(&self.w.to_le_bytes());
        out[33..41].copy_from_slice(&self.first_height.to_le_bytes());
        out
    }

    /// Decode exactly 41 bytes. Any other length, or another magic, is
    /// refused: an unreadable record refuses start, never "no record".
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let ctx: &'static str = "RegistryFreezeRecordV1";
        let mut r = Reader::new(bytes);
        if r.read_array::<7>(ctx)? != REGISTRY_FREEZE_MAGIC {
            return Err(DecodeError::BadTag { ctx });
        }
        let gate_a = r.read_u64(ctx)?;
        let threshold_bps = r.read_u16(ctx)?;
        let t_min = r.read_u64(ctx)?;
        let w = r.read_u64(ctx)?;
        let first_height = r.read_u64(ctx)?;
        r.finish(ctx)?;
        Ok(Self {
            gate_a,
            threshold_bps,
            t_min,
            w,
            first_height,
        })
    }
}

/// MAGIC of the node-local gate pin (PROPOSED).
pub const REGISTRY_GATE_PIN_MAGIC: [u8; 7] = *b"RFGTv1\0";
/// Length of [`RegistryGatePinV1`]: 7 + 8.
pub const REGISTRY_GATE_PIN_LEN: usize = 15;

/// The node-local gate pin (README §17 (a), PROPOSED), written by the explicit
/// recovery rollback in the batch that deletes the freeze record. The integer
/// is **little-endian**:
///
/// `REGISTRY_GATE_PIN_MAGIC[7] ‖ gate_a u64`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryGatePinV1 {
    /// The registry activation height A that the deleted freeze record held.
    pub gate_a: u64,
}

impl RegistryGatePinV1 {
    /// The 15-byte encoding.
    pub fn encode(&self) -> [u8; REGISTRY_GATE_PIN_LEN] {
        let mut out = [0u8; REGISTRY_GATE_PIN_LEN];
        out[..7].copy_from_slice(&REGISTRY_GATE_PIN_MAGIC);
        out[7..15].copy_from_slice(&self.gate_a.to_le_bytes());
        out
    }

    /// Decode exactly 15 bytes. Any other length, or another magic, is
    /// refused: an unreadable pin refuses start.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let ctx: &'static str = "RegistryGatePinV1";
        let mut r = Reader::new(bytes);
        if r.read_array::<7>(ctx)? != REGISTRY_GATE_PIN_MAGIC {
            return Err(DecodeError::BadTag { ctx });
        }
        let gate_a = r.read_u64(ctx)?;
        r.finish(ctx)?;
        Ok(Self { gate_a })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_wire::{GRAPH_DEFINITION_TAG, TOKENIZER_ID_TAG, VK_ID_TAG};
    use crate::validator_authority::{
        GOV_CANCEL_PROPOSAL_DOMAIN, GOV_REGISTER_ASSET_DOMAIN, GOV_REGISTER_EQUITY_CLASS_DOMAIN,
        INFERENCE_RESOLVE_DISPUTE_DOMAIN,
    };

    fn record() -> RegistryRecordV1 {
        RegistryRecordV1 {
            id: [0x11; 32],
            proof_system_id: 2,
            audit_commitment: [0xA1; 32],
            source_commitment: [0xB2; 32],
            ceremony_commitment: [0xC3; 32],
            verifier_binary_version: 7,
            activation_height: 1_000,
            status: RegistryStatus::Enabled,
            approval_threshold_bps: 6_667,
        }
    }

    fn approval(b: u8) -> ValidatorApproval {
        ValidatorApproval {
            pubkey: [b; 32],
            signature: [b ^ 0xFF; 64],
        }
    }

    fn register(k: u8) -> RegistryRegisterV1 {
        RegistryRegisterV1 {
            valid_until: 0x0102_0304_0506_0708,
            record: record(),
            approvals: (1..=k).map(approval).collect(),
        }
    }

    fn disable(k: u8) -> RegistryDisableV1 {
        RegistryDisableV1 {
            valid_until: 0x0102_0304_0506_0708,
            id: [0x11; 32],
            approvals: (1..=k).map(approval).collect(),
        }
    }

    #[test]
    fn lengths_are_the_proposed_tables() {
        assert_eq!(7 + 2 + 8 + RegistryRecordV1::LEN + 2, 173);
        assert_eq!(7 + 2 + 8 + 32 + 2, 51);
        for k in 0..4u8 {
            let n = k as usize * REGISTRY_APPROVAL_LEN;
            assert_eq!(register(k).try_encode().unwrap().len(), 173 + n);
            assert_eq!(disable(k).try_encode().unwrap().len(), 51 + n);
        }
        assert_eq!(REGISTRY_REGISTER_DOMAIN.len(), 30);
        assert_eq!(REGISTRY_DISABLE_DOMAIN.len(), 29);
        assert_eq!(
            registry_register_signing_bytes(1, &[0; 32], 0, &record()).unwrap().len(),
            232
        );
        assert_eq!(registry_disable_signing_bytes(1, &[0; 32], 0, &[0; 32]).len(), 109);
    }

    #[test]
    fn register_offsets_match_an_independent_construction() {
        let op = register(2);
        let mut want = Vec::new();
        want.extend_from_slice(b"RRGRv1\0");
        want.extend_from_slice(&1u16.to_le_bytes());
        want.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        want.extend_from_slice(&record().try_encode().unwrap());
        assert_eq!(want.len(), 171);
        want.extend_from_slice(&2u16.to_le_bytes());
        for b in [1u8, 2] {
            want.extend_from_slice(&[b; 32]);
            want.extend_from_slice(&[b ^ 0xFF; 64]);
        }
        let got = op.try_encode().unwrap();
        assert_eq!(got, want);
        // Spot offsets of the specification table.
        assert_eq!(&got[0..7], b"RRGRv1\0");
        assert_eq!(&got[9..17], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&got[17..24], b"RREGv1\0");
        assert_eq!(&got[169..171], &6_667u16.to_le_bytes());
        assert_eq!(&got[171..173], &[2, 0]);
        assert_eq!(&got[173..205], &[1u8; 32]);
        assert_eq!(&got[269..301], &[2u8; 32]);
        assert_eq!(RegistryRegisterV1::decode_exact(&got).unwrap(), op);
    }

    #[test]
    fn disable_offsets_match_an_independent_construction() {
        let op = disable(1);
        let mut want = Vec::new();
        want.extend_from_slice(b"RDISv1\0");
        want.extend_from_slice(&1u16.to_le_bytes());
        want.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        want.extend_from_slice(&[0x11; 32]);
        want.extend_from_slice(&1u16.to_le_bytes());
        want.extend_from_slice(&[1u8; 32]);
        want.extend_from_slice(&[0xFE; 64]);
        let got = op.try_encode().unwrap();
        assert_eq!(got, want);
        assert_eq!(RegistryDisableV1::decode_exact(&got).unwrap(), op);
    }

    #[test]
    fn signing_preimages_match_an_independent_construction() {
        let genesis = [0x47u8; 32];
        let mut want = Vec::new();
        want.extend_from_slice(b"SUMCHAIN/REGISTRY/REGISTER/v1\0");
        want.extend_from_slice(&1337u64.to_le_bytes());
        want.extend_from_slice(&genesis);
        want.extend_from_slice(&9u64.to_le_bytes());
        want.extend_from_slice(&record().try_encode().unwrap());
        assert_eq!(
            registry_register_signing_bytes(1337, &genesis, 9, &record()).unwrap(),
            want
        );

        let mut want = Vec::new();
        want.extend_from_slice(b"SUMCHAIN/REGISTRY/DISABLE/v1\0");
        want.extend_from_slice(&1337u64.to_le_bytes());
        want.extend_from_slice(&genesis);
        want.extend_from_slice(&9u64.to_le_bytes());
        want.extend_from_slice(&[0x11; 32]);
        assert_eq!(registry_disable_signing_bytes(1337, &genesis, 9, &[0x11; 32]), want);
    }

    #[test]
    fn every_bound_field_changes_the_preimage() {
        let g = [0x47u8; 32];
        let base = registry_register_signing_bytes(1, &g, 9, &record()).unwrap();
        assert_ne!(base, registry_register_signing_bytes(2, &g, 9, &record()).unwrap());
        assert_ne!(base, registry_register_signing_bytes(1, &[0x48; 32], 9, &record()).unwrap());
        assert_ne!(base, registry_register_signing_bytes(1, &g, 10, &record()).unwrap());
        let mut other = record();
        other.approval_threshold_bps = 6_666;
        assert_ne!(base, registry_register_signing_bytes(1, &g, 9, &other).unwrap());

        let base = registry_disable_signing_bytes(1, &g, 9, &[0x11; 32]);
        assert_ne!(base, registry_disable_signing_bytes(2, &g, 9, &[0x11; 32]));
        assert_ne!(base, registry_disable_signing_bytes(1, &[0x48; 32], 9, &[0x11; 32]));
        assert_ne!(base, registry_disable_signing_bytes(1, &g, 10, &[0x11; 32]));
        assert_ne!(base, registry_disable_signing_bytes(1, &g, 9, &[0x12; 32]));
    }

    #[test]
    fn domains_are_prefix_free_against_every_registry_and_validator_domain() {
        let all: [&[u8]; 11] = [
            REGISTRY_REGISTER_DOMAIN,
            REGISTRY_DISABLE_DOMAIN,
            REGISTRY_PARAMS_DIGEST_DOMAIN,
            REGISTRY_STATE_DIGEST_DOMAIN,
            VK_ID_TAG,
            TOKENIZER_ID_TAG,
            GRAPH_DEFINITION_TAG,
            GOV_REGISTER_ASSET_DOMAIN,
            GOV_CANCEL_PROPOSAL_DOMAIN,
            GOV_REGISTER_EQUITY_CLASS_DOMAIN,
            INFERENCE_RESOLVE_DISPUTE_DOMAIN,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "{a:?} prefixes {b:?}");
                }
            }
        }
        for d in [
            REGISTRY_REGISTER_DOMAIN,
            REGISTRY_DISABLE_DOMAIN,
            REGISTRY_PARAMS_DIGEST_DOMAIN,
            REGISTRY_STATE_DIGEST_DOMAIN,
        ] {
            assert_eq!(d.iter().filter(|&&b| b == 0).count(), 1);
            assert_eq!(*d.last().unwrap(), 0);
        }
        assert_eq!(REGISTRY_PARAMS_DIGEST_DOMAIN.len(), 28);
        assert_eq!(REGISTRY_STATE_DIGEST_DOMAIN.len(), 27);
    }

    #[test]
    fn params_digest_preimage_layout_and_every_field_matters() {
        let d = REGISTRY_PARAMS_DIGEST_DOMAIN;
        // Both tags absent: domain ‖ 0 ‖ 0.
        assert_eq!(registry_params_digest_preimage(None, None), [d, &[0, 0]].concat());
        // Both present, big-endian.
        let both = registry_params_digest_preimage(Some(6667), Some((10, 100)));
        let mut want = d.to_vec();
        want.push(1);
        want.extend_from_slice(&6667u16.to_be_bytes());
        want.push(1);
        want.extend_from_slice(&10u64.to_be_bytes());
        want.extend_from_slice(&100u64.to_be_bytes());
        assert_eq!(both, want);
        assert_eq!(both.len(), 28 + 1 + 2 + 1 + 16);
        // Any differing field, presence or order gives a different digest.
        let cases = [
            registry_params_digest(Some(6667), Some((10, 100))),
            registry_params_digest(Some(6668), Some((10, 100))),
            registry_params_digest(Some(6667), Some((11, 100))),
            registry_params_digest(Some(6667), Some((10, 101))),
            registry_params_digest(Some(6667), Some((100, 10))),
            registry_params_digest(None, Some((10, 100))),
            registry_params_digest(Some(6667), None),
            registry_params_digest(None, None),
        ];
        for (i, a) in cases.iter().enumerate() {
            for (j, b) in cases.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "cases {i} and {j} collide");
                }
            }
        }
    }

    #[test]
    fn state_digest_preimage_layout() {
        let d = REGISTRY_STATE_DIGEST_DOMAIN;
        assert_eq!(registry_state_digest_preimage([]), [d, &0u64.to_be_bytes()].concat());
        let id = [0x11u8; 32];
        let rec = [0x22u8; RegistryRecordV1::LEN];
        let one = registry_state_digest_preimage([(&id, &rec)]);
        assert_eq!(one, [d, &id[..], &rec[..], &1u64.to_be_bytes()].concat());
        assert_eq!(one.len(), 27 + 32 + 154 + 8);
    }

    #[test]
    fn freeze_record_and_gate_pin_encode_decode_and_refuse() {
        let rec = RegistryFreezeRecordV1 {
            gate_a: 500_000,
            threshold_bps: 6667,
            t_min: 10,
            w: 100,
            first_height: 500_001,
        };
        let b = rec.encode();
        assert_eq!(&b[..7], b"RFRZv1\0");
        assert_eq!(b[7..15], 500_000u64.to_le_bytes());
        assert_eq!(b[15..17], 6667u16.to_le_bytes());
        assert_eq!(b[17..25], 10u64.to_le_bytes());
        assert_eq!(b[25..33], 100u64.to_le_bytes());
        assert_eq!(b[33..41], 500_001u64.to_le_bytes());
        assert_eq!(RegistryFreezeRecordV1::decode_exact(&b), Ok(rec));
        assert!(RegistryFreezeRecordV1::decode_exact(&b[..40]).is_err());
        assert!(RegistryFreezeRecordV1::decode_exact(&[&b[..], &[0]].concat()).is_err());
        let mut bad = b;
        bad[0] ^= 1;
        assert!(matches!(RegistryFreezeRecordV1::decode_exact(&bad), Err(DecodeError::BadTag { .. })));

        let pin = RegistryGatePinV1 { gate_a: 500_000 };
        let p = pin.encode();
        assert_eq!(p.len(), 15);
        assert_eq!(&p[..7], b"RFGTv1\0");
        assert_eq!(p[7..15], 500_000u64.to_le_bytes());
        assert_eq!(RegistryGatePinV1::decode_exact(&p), Ok(pin));
        assert!(RegistryGatePinV1::decode_exact(&p[..14]).is_err());
        assert!(RegistryGatePinV1::decode_exact(&[&p[..], &[0]].concat()).is_err());
        // A freeze record is never read as a pin, nor a pin as a record.
        assert!(RegistryGatePinV1::decode_exact(&b).is_err());
        assert!(RegistryFreezeRecordV1::decode_exact(&p).is_err());
        let mut badp = p;
        badp[6] = 1;
        assert!(matches!(RegistryGatePinV1::decode_exact(&badp), Err(DecodeError::BadTag { .. })));
    }

    #[test]
    fn wrong_magic_schema_and_cross_operation_bytes_refused() {
        let reg = register(1).try_encode().unwrap();
        let dis = disable(1).try_encode().unwrap();
        assert!(matches!(RegistryDisableV1::decode_exact(&reg), Err(DecodeError::BadTag { .. })));
        assert!(matches!(RegistryRegisterV1::decode_exact(&dis), Err(DecodeError::BadTag { .. })));
        for schema in [0u16, 2, 0x0100, u16::MAX] {
            let mut b = reg.clone();
            b[7..9].copy_from_slice(&schema.to_le_bytes());
            assert!(matches!(
                RegistryRegisterV1::decode_exact(&b),
                Err(DecodeError::BadFixedScalar { .. })
            ));
            let mut b = dis.clone();
            b[7..9].copy_from_slice(&schema.to_le_bytes());
            assert!(matches!(
                RegistryDisableV1::decode_exact(&b),
                Err(DecodeError::BadFixedScalar { .. })
            ));
        }
        // The frozen record inside keeps its own refusals.
        let mut b = reg.clone();
        b[17] ^= 0xFF;
        assert!(matches!(RegistryRegisterV1::decode_exact(&b), Err(DecodeError::BadTag { .. })));
        let mut b = reg;
        b[17 + 151] = 2; // record.status
        assert!(matches!(RegistryRegisterV1::decode_exact(&b), Err(DecodeError::BadValue { .. })));
    }

    #[test]
    fn every_truncation_and_any_trailing_byte_refused() {
        for bytes in [
            register(0).try_encode().unwrap(),
            register(3).try_encode().unwrap(),
        ] {
            for cut in 0..bytes.len() {
                assert!(RegistryRegisterV1::decode_exact(&bytes[..cut]).is_err(), "cut {cut}");
            }
            let mut long = bytes.clone();
            long.push(0);
            assert!(matches!(
                RegistryRegisterV1::decode_exact(&long),
                Err(DecodeError::TrailingBytes { remaining: 1, .. })
            ));
        }
        for bytes in [disable(0).try_encode().unwrap(), disable(3).try_encode().unwrap()] {
            for cut in 0..bytes.len() {
                assert!(RegistryDisableV1::decode_exact(&bytes[..cut]).is_err(), "cut {cut}");
            }
            let mut long = bytes.clone();
            long.push(0);
            assert!(matches!(
                RegistryDisableV1::decode_exact(&long),
                Err(DecodeError::TrailingBytes { remaining: 1, .. })
            ));
        }
    }

    #[test]
    fn a_count_larger_than_the_entries_is_refused_before_allocation() {
        let mut b = disable(1).try_encode().unwrap();
        b[49..51].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            RegistryDisableV1::decode_exact(&b),
            Err(DecodeError::Truncated { needed, .. }) if needed == 65_535 * 96
        ));
        let mut b = disable(2).try_encode().unwrap();
        b[49..51].copy_from_slice(&1u16.to_le_bytes());
        assert!(matches!(
            RegistryDisableV1::decode_exact(&b),
            Err(DecodeError::TrailingBytes { remaining: 96, .. })
        ));
    }

    #[test]
    fn unordered_or_repeated_approvals_refused_both_ways() {
        let mut op = disable(3);
        op.approvals.swap(1, 2);
        assert!(matches!(op.try_encode(), Err(DecodeError::NonCanonicalOrder { .. })));
        let mut op = disable(2);
        op.approvals[1] = op.approvals[0].clone();
        assert!(matches!(op.try_encode(), Err(DecodeError::DuplicateEntry { .. })));

        // The same refusals on bytes no encoder would write.
        let good = disable(2).try_encode().unwrap();
        let (a, b) = (51..147, 147..243);
        let mut swapped = good.clone();
        swapped[a.clone()].copy_from_slice(&good[b.clone()]);
        swapped[b.clone()].copy_from_slice(&good[a.clone()]);
        assert!(matches!(
            RegistryDisableV1::decode_exact(&swapped),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
        let mut repeated = good.clone();
        repeated[b].copy_from_slice(&good[a]);
        assert!(matches!(
            RegistryDisableV1::decode_exact(&repeated),
            Err(DecodeError::DuplicateEntry { .. })
        ));
        let mut op = register(3);
        op.approvals.reverse();
        assert!(matches!(op.try_encode(), Err(DecodeError::NonCanonicalOrder { .. })));
    }

    #[test]
    fn ordering_is_bytewise_from_the_first_byte() {
        let mut lo = approval(0);
        lo.pubkey = [0; 32];
        lo.pubkey[31] = 0xFF;
        let mut hi = approval(0);
        hi.pubkey = [0; 32];
        hi.pubkey[0] = 0x01;
        let op = RegistryDisableV1 {
            valid_until: 0,
            id: [0; 32],
            approvals: vec![lo.clone(), hi.clone()],
        };
        assert!(op.try_encode().is_ok());
        let op = RegistryDisableV1 {
            valid_until: 0,
            id: [0; 32],
            approvals: vec![hi, lo],
        };
        assert!(op.try_encode().is_err());
    }

    #[test]
    fn named_parameters_complete_only_when_all_are_set() {
        assert_eq!(RegistryIngressParams::UNSET.complete(), None);
        let full = RegistryIngressParams {
            registry_min_timelock_blocks: Some(1),
            registry_max_approval_window: Some(1),
        };
        assert!(full.complete().is_some());
        let missing: [RegistryIngressParams; 2] = [
            RegistryIngressParams { registry_min_timelock_blocks: None, ..full },
            RegistryIngressParams { registry_max_approval_window: None, ..full },
        ];
        for p in missing {
            assert_eq!(p.complete(), None, "{p:?}");
            assert_eq!(p.validate(), Err(RegistryParamsError::Partial), "{p:?}");
        }
        assert_eq!(RegistryIngressParams::UNSET.validate(), Ok(()));
    }

    #[test]
    fn named_parameters_are_each_in_one_to_u32_max() {
        let with = |t: u64, w: u64| RegistryIngressParams {
            registry_min_timelock_blocks: Some(t),
            registry_max_approval_window: Some(w),
        };
        let top = u32::MAX as u64;
        for (t, w) in [(1, 1), (top, top), (1, top), (top, 1)] {
            assert_eq!(with(t, w).validate(), Ok(()));
            assert!(with(t, w).complete().is_some());
        }
        for (t, w, name, value) in [
            (0, 1, "registry_min_timelock_blocks", 0),
            (1, 0, "registry_max_approval_window", 0),
            (top + 1, 1, "registry_min_timelock_blocks", top + 1),
            (1, u64::MAX, "registry_max_approval_window", u64::MAX),
        ] {
            assert_eq!(
                with(t, w).validate(),
                Err(RegistryParamsError::OutOfRange { name, value })
            );
            assert_eq!(with(t, w).complete(), None);
        }
    }

    #[test]
    fn unset_commitments_names_each_zero_commitment_in_order() {
        assert!(unset_commitments(&record()).is_empty());
        let mut r = record();
        r.source_commitment = [0; 32];
        assert_eq!(unset_commitments(&r), ["source_commitment"]);
        r.audit_commitment = [0; 32];
        r.ceremony_commitment = [0; 32];
        assert_eq!(
            unset_commitments(&r),
            ["audit_commitment", "source_commitment", "ceremony_commitment"]
        );
        // One non-zero byte anywhere is set.
        r.ceremony_commitment[31] = 1;
        assert_eq!(unset_commitments(&r), ["audit_commitment", "source_commitment"]);
    }

    #[test]
    fn height_rules_at_their_boundaries() {
        assert!(timelock_satisfied(110, 100, 10));
        assert!(!timelock_satisfied(109, 100, 10));
        assert!(timelock_satisfied(100, 100, 0));
        assert!(!timelock_satisfied(u64::MAX, 1, u64::MAX));
        assert!(timelock_satisfied(u64::MAX, 0, u64::MAX));

        assert!(approval_window_open(100, 100, 0));
        assert!(!approval_window_open(101, 100, u64::MAX));
        assert!(approval_window_open(100, 110, 10));
        assert!(!approval_window_open(100, 111, 10));
        assert!(approval_window_open(0, u64::MAX, u64::MAX));
    }

    #[test]
    fn commit_side_rules() {
        let mut r = record();
        assert_eq!(check_commit(None, 5), Err(RegistryCommitRefusal::Unknown));
        assert_eq!(
            check_commit(Some(&r), 999),
            Err(RegistryCommitRefusal::BeforeActivation {
                activation_height: 1_000,
                height: 999
            })
        );
        assert_eq!(check_commit(Some(&r), 1_000), Ok(()));
        r.status = RegistryStatus::Disabled;
        assert_eq!(check_commit(Some(&r), 1_000), Err(RegistryCommitRefusal::Disabled));
    }

    #[test]
    fn admitted_proof_systems_is_risc0_only() {
        assert_eq!(admitted_proof_systems(), [2]);
    }
}

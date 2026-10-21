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

/// Where each operation's quorum threshold comes from.
///
/// Only the proposal's recommendation exists. B1 (both operations at the
/// governance threshold) is not implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryThresholdSource {
    /// B2: register is authorized at `GovernanceParams.validator_authority_threshold_bps`
    /// and the record's `approval_threshold_bps` must be at least that value;
    /// disable is authorized at the stored record's `approval_threshold_bps`.
    GovernanceThenRecord,
}

/// The C5 named parameters. `None` is "not ratified".
///
/// No field has a value in this binary, and none is invented here. Operations
/// 8 and 9 refuse unless every field is `Some` ([`Self::complete`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryIngressParams {
    /// `T_min`: register at height `h` needs `activation_height ≥ h + T_min`
    /// (#217 B6, #212).
    pub registry_min_timelock_blocks: Option<u64>,
    /// The threshold source, and with it the use of
    /// `validator_authority_threshold_bps` for registry approvals.
    pub registry_threshold_source: Option<RegistryThresholdSource>,
    /// The record `approval_threshold_bps` default (#212). The proposal gives it
    /// no consensus rule; it is required to be set and is otherwise unread.
    pub registry_record_default_approval_threshold_bps: Option<u16>,
    /// The approval window: the largest `valid_until − h` accepted. `u64::MAX`
    /// would express "no bound".
    pub registry_max_approval_window: Option<u64>,
}

/// Every named parameter, present. Obtainable only through
/// [`RegistryIngressParams::complete`] by the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryIngressValues {
    pub min_timelock_blocks: u64,
    pub threshold_source: RegistryThresholdSource,
    pub record_default_approval_threshold_bps: u16,
    pub max_approval_window: u64,
}

impl RegistryIngressParams {
    /// Every parameter unset: operations 8 and 9 refuse.
    pub const UNSET: Self = Self {
        registry_min_timelock_blocks: None,
        registry_threshold_source: None,
        registry_record_default_approval_threshold_bps: None,
        registry_max_approval_window: None,
    };

    /// All four values, or `None` if any is missing. A missing value can
    /// therefore never be defaulted on the way to execution.
    pub fn complete(&self) -> Option<RegistryIngressValues> {
        Some(RegistryIngressValues {
            min_timelock_blocks: self.registry_min_timelock_blocks?,
            threshold_source: self.registry_threshold_source?,
            record_default_approval_threshold_bps: self
                .registry_record_default_approval_threshold_bps?,
            max_approval_window: self.registry_max_approval_window?,
        })
    }
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
        let all: [&[u8]; 9] = [
            REGISTRY_REGISTER_DOMAIN,
            REGISTRY_DISABLE_DOMAIN,
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
        for d in [REGISTRY_REGISTER_DOMAIN, REGISTRY_DISABLE_DOMAIN] {
            assert_eq!(d.iter().filter(|&&b| b == 0).count(), 1);
            assert_eq!(*d.last().unwrap(), 0);
        }
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
            registry_threshold_source: Some(RegistryThresholdSource::GovernanceThenRecord),
            registry_record_default_approval_threshold_bps: Some(1),
            registry_max_approval_window: Some(1),
        };
        assert!(full.complete().is_some());
        let missing: [RegistryIngressParams; 4] = [
            RegistryIngressParams { registry_min_timelock_blocks: None, ..full },
            RegistryIngressParams { registry_threshold_source: None, ..full },
            RegistryIngressParams { registry_record_default_approval_threshold_bps: None, ..full },
            RegistryIngressParams { registry_max_approval_window: None, ..full },
        ];
        for p in missing {
            assert_eq!(p.complete(), None, "{p:?}");
        }
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

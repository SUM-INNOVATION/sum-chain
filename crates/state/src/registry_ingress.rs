//! C5 registry ingress (#242): validation and state for the proposed
//! governance-v1 operations 8 (register) and 9 (disable).
//!
//! PROPOSED, NOT RATIFIED, DORMANT, UNWIRED. Nothing on the wire reaches this
//! module: `GovernanceOperation` has no variant 8 or 9, so a transaction
//! naming either is refused at decode exactly as before this module existed.
//! Only `governance_executor::execute_registry_ingress`, called directly by
//! tests, runs it. That entry applies the governance-v1 gate and
//! `ChainParams::governance`, then refuses (`302`, no fee, no nonce) unless
//! every named parameter and the genesis block hash are present. Adding the
//! wire variants, supplying [`REGISTRY_INGRESS_PARAMS`] with ratified values
//! and the genesis hash, is the separately authorized activation change.
//! Specification: `docs/proposals/c5-registry-ingress/README.md`.
//!
//! Approvals are checked strictly (`verify_validator_quorum_strict`,
//! ed25519-dalek `verify_strict`; owner, 2026-10-23). Every other governance
//! operation keeps governance-v1 `verify`.
//!
//! Once ready, every refusal below is semantic: `303`, with the Policy-B fee
//! and nonce. The checks are independent, so their order changes no receipt;
//! signatures are verified last because they cost the most.

use sumchain_primitives::governance::GovernanceParams;
use sumchain_primitives::ChainId;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::StorageError;
use sumchain_wire::registry_ingress::{
    admitted_proof_systems, approval_window_open, check_commit, registry_disable_signing_bytes,
    registry_register_signing_bytes, timelock_satisfied, unset_commitments, RegistryCommitRefusal,
    RegistryDisableV1, RegistryIngressParams, RegistryIngressValues, RegistryRegisterV1,
};
use sumchain_wire::registry_wire::{RegistryRecordV1, RegistryStatus};

use crate::validator_quorum::{check_threshold_bps, verify_validator_quorum_strict};
use crate::{Result, StateError};

/// The named parameters of this binary: every one unset, so the operations
/// would refuse even if something reached them. A ratified value is a
/// reviewed change here, part of the activation change.
pub const REGISTRY_INGRESS_PARAMS: RegistryIngressParams = RegistryIngressParams::UNSET;

/// The most records the registry may store, Enabled and Disabled together
/// (owner, 2026-10-23: a deterministic consensus bound on the per-block
/// registry scan). PROPOSED value; dormant.
///
/// A register that would store record `MAX_REGISTRY_RECORDS + 1` is refused
/// with `303`. Every stored record counts, including disabled ones, because
/// the proposed registry-state fold covers them all; a disabled record never
/// frees capacity. Disable adds no record and stays allowed at the limit.
///
/// Rationale for 4,096:
/// - one proof system is admitted today ([`admitted_proof_systems`]);
/// - records name verifier keys, program images, tokenizers and models, and
///   each one needs a validator quorum and a fee, so the expected count is in
///   the tens to low hundreds over years, which leaves at least 16× headroom;
/// - at the limit the fold hashes [`MAX_REGISTRY_FOLDED_BYTES`] (761,891 bytes)
///   per block. That is about 0.6 ms of BLAKE3 on one core (measured on an
///   arm64 workstation), plus a 4,096-row scan, which costs about 0.7 ms at the
///   account root's reference of 40 ms per 250,000 rows (`account_root.rs`).
///   Together that is under 0.1% of the 1,506 ms block interval.
///
/// Not in `protocol_digest::consensus_limits` while dormant, because no
/// transaction reaches the check. The activation change adds it there, and so
/// to the protocol digest every node declares at the handshake. It also gives
/// it the ConsensusConfig field id that every consensus limit has
/// (`0x2000–0x20ff`) in the new schema. Changing it after activation is a
/// coordinated upgrade.
pub const MAX_REGISTRY_RECORDS: u64 = 4_096;

/// The most bytes the proposed registry-state fold hashes per block at
/// [`MAX_REGISTRY_RECORDS`]: per record, its id (32 bytes) and its frozen
/// `RegistryRecordV1` (154 bytes); plus the proposed fold domain
/// `SUMCHAIN/REGISTRY/STATE/v1\0` (27 bytes, provisional with the activation
/// proposal) and the `u64` record count (8 bytes). 4,096 × 186 + 35 =
/// 761,891 bytes. Derived; not a separate parameter.
pub const MAX_REGISTRY_FOLDED_BYTES: u64 =
    MAX_REGISTRY_RECORDS * (32 + RegistryRecordV1::LEN as u64) + 27 + 8;

/// Which proposed operation an internal call runs. Deliberately not a
/// `GovernanceOperation` variant: no transaction decodes to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryIngressOp {
    /// Proposed operation 8; `data` is a `RegistryRegisterV1`.
    Register,
    /// Proposed operation 9; `data` is a `RegistryDisableV1`.
    Disable,
}

/// What operations 8 and 9 need beyond `ChainParams`.
#[derive(Debug, Clone, Copy)]
pub struct RegistryIngressContext<'a> {
    pub params: &'a RegistryIngressParams,
    /// The chain's genesis block hash (`Genesis::create_genesis_block().hash()`,
    /// consensus-configuration field `0x0005`). `None` refuses both operations.
    pub genesis_block_hash: Option<&'a [u8; 32]>,
}

/// Everything a registry operation needs from outside its own bytes, present.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ready {
    values: RegistryIngressValues,
    genesis_block_hash: [u8; 32],
}

/// `Some` only when every named parameter and the genesis hash are present.
pub(crate) fn ready(ctx: &RegistryIngressContext<'_>) -> Option<Ready> {
    Some(Ready {
        values: ctx.params.complete()?,
        genesis_block_hash: *ctx.genesis_block_hash?,
    })
}

/// Register, executed at `height`. Returns the record to store.
pub(crate) fn validate_register(
    view: &ExecutionView<'_, '_>,
    gp: &GovernanceParams,
    ready: &Ready,
    chain_id: ChainId,
    height: u64,
    active_validator_pubkeys: &[[u8; 32]],
    req: &RegistryRegisterV1,
) -> std::result::Result<RegistryRecordV1, u32> {
    let v = &ready.values;
    let record = &req.record;
    if !approval_window_open(height, req.valid_until, v.max_approval_window) {
        return Err(303);
    }
    if record.status != RegistryStatus::Enabled
        || check_threshold_bps(record.approval_threshold_bps).is_err()
        || !admitted_proof_systems().contains(&record.proof_system_id)
        || !unset_commitments(record).is_empty()
        || !timelock_satisfied(record.activation_height, height, v.min_timelock_blocks)
    {
        return Err(303);
    }
    // Q17 (owner, 2026-10-22): the authenticated governance threshold, from
    // chain parameters, never from the operation or a tooling default.
    let threshold = gp.validator_authority_threshold_bps;
    // B2 (adopted 2026-10-23): the record's own threshold is at least the
    // governance threshold effective at its registration.
    if record.approval_threshold_bps < threshold {
        return Err(303);
    }
    // Disabled is terminal: a disabled id is still present, so it can never
    // be registered again.
    if v_get_record(view, &record.id).map_err(|_| 303u32)?.is_some() {
        return Err(303);
    }
    // The size bound: this register would store one more record, so it is
    // refused once MAX_REGISTRY_RECORDS records, Enabled or Disabled, exist.
    if v_count_records_up_to(view, MAX_REGISTRY_RECORDS).map_err(|_| 303u32)?
        >= MAX_REGISTRY_RECORDS
    {
        return Err(303);
    }
    let signing =
        registry_register_signing_bytes(chain_id, &ready.genesis_block_hash, req.valid_until, record)
            .map_err(|_| 303u32)?;
    verify_validator_quorum_strict(&req.approvals, &signing, active_validator_pubkeys, threshold)
        .map_err(|_| 303u32)?;
    Ok(record.clone())
}

/// Disable, executed at `height`. Returns the stored record, now Disabled.
pub(crate) fn validate_disable(
    view: &ExecutionView<'_, '_>,
    ready: &Ready,
    chain_id: ChainId,
    height: u64,
    active_validator_pubkeys: &[[u8; 32]],
    req: &RegistryDisableV1,
) -> std::result::Result<RegistryRecordV1, u32> {
    let v = &ready.values;
    if !approval_window_open(height, req.valid_until, v.max_approval_window) {
        return Err(303);
    }
    let stored = v_get_record(view, &req.id)
        .map_err(|_| 303u32)?
        .ok_or(303u32)?;
    if stored.status != RegistryStatus::Enabled {
        return Err(303);
    }
    // B2 (adopted 2026-10-23): the stored record's own threshold, accepted at
    // its registration. A later change to the governance threshold does not
    // touch it, so a disable never gets harder over time.
    let threshold = stored.approval_threshold_bps;
    let signing =
        registry_disable_signing_bytes(chain_id, &ready.genesis_block_hash, req.valid_until, &req.id);
    verify_validator_quorum_strict(&req.approvals, &signing, active_validator_pubkeys, threshold)
        .map_err(|_| 303u32)?;
    Ok(RegistryRecordV1 {
        status: RegistryStatus::Disabled,
        ..stored
    })
}

// ── State ───────────────────────────────────────────────────────────────────
//
// Storage ADOPTED by the owner (2026-10-23): the existing `state` column
// family under `registry/v1/` ‖ id. No column family is added. Rows are
// written only through `ExecutionView`, so they land in the block's single
// atomic batch and the generic application journal unwinds them on a rollback.
// The prefix is disjoint from the account rows (`acct`, the only family scan
// of `state` on main: the account root, snapshot export and legacy revert) and
// from G5's proposed `vset/` (#342); tests pin both. While dormant nothing folds
// these rows into a root; the registry digest belongs to the activation
// proposal.

/// Prefix of every registry record key in `cf::STATE`.
pub const REGISTRY_RECORD_KEY_PREFIX: &[u8] = b"registry/v1/";

/// The key of the record with `id`: prefix ‖ id (32), 44 bytes.
pub fn registry_record_key(id: &[u8; 32]) -> Vec<u8> {
    [REGISTRY_RECORD_KEY_PREFIX, id].concat()
}

/// The record stored under `id`, as this block's candidate sees it. A row that
/// does not decode, or names another id, is an error, never "no record".
pub fn v_get_record(
    view: &ExecutionView<'_, '_>,
    id: &[u8; 32],
) -> Result<Option<RegistryRecordV1>> {
    let Some(bytes) = view
        .get(cf::STATE, &registry_record_key(id))
        .map_err(StateError::Storage)?
    else {
        return Ok(None);
    };
    let record = RegistryRecordV1::decode_exact(&bytes)
        .map_err(|e| StateError::Storage(StorageError::InvalidData(format!("registry record: {e}"))))?;
    if record.id != *id {
        return Err(StateError::Storage(StorageError::InvalidData(
            "registry record stored under another id".to_string(),
        )));
    }
    Ok(Some(record))
}

/// How many records are stored, Enabled and Disabled, as this block's
/// candidate sees them, counting at most `limit`.
///
/// It is a bounded prefix scan over `registry/v1/` in `cf::STATE`, not a count
/// row:
/// - it reads the rows the registry fold would hash, so it cannot drift from
///   them;
/// - it adds no key, and so no collision surface;
/// - it needs no second write to keep in step, and the candidate overlay,
///   atomic publication and generic journal already cover the rows it counts.
///
/// It sees this block's own staged registers, and stops after `limit` rows, so
/// one register reads at most `MAX_REGISTRY_RECORDS` keys. A read error is an
/// error, never a short count.
pub fn v_count_records_up_to(view: &ExecutionView<'_, '_>, limit: u64) -> Result<u64> {
    let mut count = 0u64;
    if limit == 0 {
        return Ok(count);
    }
    for entry in view
        .prefix_iter(cf::STATE, REGISTRY_RECORD_KEY_PREFIX)
        .map_err(StateError::Storage)?
    {
        let (key, _) = entry.map_err(StateError::Storage)?;
        if !key.starts_with(REGISTRY_RECORD_KEY_PREFIX) {
            break;
        }
        count += 1;
        if count == limit {
            break;
        }
    }
    Ok(count)
}

/// Stage `record` under its id.
pub fn v_put_record(view: &mut ExecutionView<'_, '_>, record: &RegistryRecordV1) -> Result<()> {
    let bytes = record
        .try_encode()
        .map_err(|e| StateError::Storage(StorageError::InvalidData(format!("registry record: {e}"))))?;
    view.put(cf::STATE, &registry_record_key(&record.id), &bytes)
        .map_err(StateError::Storage)
}

/// #128's commit-side check against registry state at this execution point.
/// No consumer calls it yet; which transactions do, and with which receipt,
/// is an open question of the proposal.
pub fn v_check_commit(
    view: &ExecutionView<'_, '_>,
    id: &[u8; 32],
    height: u64,
) -> Result<std::result::Result<(), RegistryCommitRefusal>> {
    Ok(check_commit(v_get_record(view, id)?.as_ref(), height))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> RegistryIngressParams {
        RegistryIngressParams {
            registry_min_timelock_blocks: Some(1),
            registry_max_approval_window: Some(1),
        }
    }

    #[test]
    fn ready_needs_every_parameter_and_the_genesis_hash() {
        let hash = [7u8; 32];
        let params = full();
        assert!(ready(&RegistryIngressContext { params: &params, genesis_block_hash: Some(&hash) }).is_some());
        assert!(ready(&RegistryIngressContext { params: &params, genesis_block_hash: None }).is_none());
        let unset = REGISTRY_INGRESS_PARAMS;
        assert_eq!(unset, RegistryIngressParams::UNSET);
        assert!(ready(&RegistryIngressContext { params: &unset, genesis_block_hash: Some(&hash) }).is_none());
    }
}

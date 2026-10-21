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
    registry_register_signing_bytes, timelock_satisfied, RegistryCommitRefusal, RegistryDisableV1,
    RegistryIngressParams, RegistryIngressValues, RegistryRegisterV1, RegistryThresholdSource,
};
use sumchain_wire::registry_wire::{RegistryRecordV1, RegistryStatus};

use crate::validator_quorum::{check_threshold_bps, verify_validator_quorum};
use crate::{Result, StateError};

/// The named parameters of this binary: every one unset, so the operations
/// would refuse even if something reached them. A ratified value is a
/// reviewed change here, part of the activation change.
pub const REGISTRY_INGRESS_PARAMS: RegistryIngressParams = RegistryIngressParams::UNSET;

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
        || !timelock_satisfied(record.activation_height, height, v.min_timelock_blocks)
    {
        return Err(303);
    }
    let threshold = match v.threshold_source {
        RegistryThresholdSource::GovernanceThenRecord => gp.validator_authority_threshold_bps,
    };
    if record.approval_threshold_bps < threshold {
        return Err(303);
    }
    // Disabled is terminal: a disabled id is still present, so it can never
    // be registered again.
    if v_get_record(view, &record.id).map_err(|_| 303u32)?.is_some() {
        return Err(303);
    }
    let signing =
        registry_register_signing_bytes(chain_id, &ready.genesis_block_hash, req.valid_until, record)
            .map_err(|_| 303u32)?;
    verify_validator_quorum(&req.approvals, &signing, active_validator_pubkeys, threshold)
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
    let threshold = match v.threshold_source {
        RegistryThresholdSource::GovernanceThenRecord => stored.approval_threshold_bps,
    };
    let signing =
        registry_disable_signing_bytes(chain_id, &ready.genesis_block_hash, req.valid_until, &req.id);
    verify_validator_quorum(&req.approvals, &signing, active_validator_pubkeys, threshold)
        .map_err(|_| 303u32)?;
    Ok(RegistryRecordV1 {
        status: RegistryStatus::Disabled,
        ..stored
    })
}

// ── State ───────────────────────────────────────────────────────────────────

/// The record stored under `id`, as this block's candidate sees it. A row that
/// does not decode, or names another id, is an error, never "no record".
pub fn v_get_record(
    view: &ExecutionView<'_, '_>,
    id: &[u8; 32],
) -> Result<Option<RegistryRecordV1>> {
    let Some(bytes) = view
        .get(cf::REGISTRY_RECORDS, id)
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

/// Stage `record` under its id.
pub fn v_put_record(view: &mut ExecutionView<'_, '_>, record: &RegistryRecordV1) -> Result<()> {
    let bytes = record
        .try_encode()
        .map_err(|e| StateError::Storage(StorageError::InvalidData(format!("registry record: {e}"))))?;
    view.put(cf::REGISTRY_RECORDS, &record.id, &bytes)
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
    use sumchain_wire::registry_ingress::RegistryThresholdSource;

    fn full() -> RegistryIngressParams {
        RegistryIngressParams {
            registry_min_timelock_blocks: Some(1),
            registry_threshold_source: Some(RegistryThresholdSource::GovernanceThenRecord),
            registry_record_default_approval_threshold_bps: Some(1),
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

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
//! and nonce. The checks are independent, so their order changes no receipt.
//! The quorum is verified next to last, and the size-bound scan runs last, so
//! only a register that is otherwise valid, quorum included, pays for the scan.
//!
//! A storage failure (an unreadable row, a row of the wrong shape, a read
//! error) is never a receipt: it is returned as an execution error, as the
//! executor treats every other storage failure, because a node-local failure
//! must not become a consensus-visible outcome.

use sumchain_primitives::governance::GovernanceParams;
use sumchain_primitives::ChainId;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::StorageError;
use sumchain_wire::registry_ingress::{
    admitted_proof_systems, approval_window_open, check_commit, registry_disable_signing_bytes,
    registry_register_signing_bytes, timelock_satisfied, unset_commitments, RegistryCommitRefusal,
    RegistryDisableV1, RegistryIngressParams, RegistryIngressValues, RegistryLimits,
    RegistryRegisterV1,
};
use sumchain_wire::registry_wire::{RegistryRecordV1, RegistryStatus};

use crate::validator_quorum::{check_threshold_bps, verify_validator_quorum_strict};
use crate::{Result, StateError};

/// The named parameters of this binary: every one unset, so the operations
/// would refuse even if something reached them. A ratified value is a
/// reviewed change here, part of the activation change.
pub const REGISTRY_INGRESS_PARAMS: RegistryIngressParams = RegistryIngressParams::UNSET;

/// The binary's registry limits: the **single source** of both consensus
/// limits (owner 2026-10-26: both are committed in `P(h)`; rule and values
/// PROPOSED; dormant).
///
/// Execution reads them only through [`RegistryIngressContext::limits`] (the
/// size bound in register), the activation change's block-validity cap reads
/// the same context value, and [`registry_params_digest_for`] commits that
/// same value in `P(h)`. [`MAX_REGISTRY_RECORDS`] and
/// [`MAX_REGISTRY_OPS_PER_BLOCK`] are derived from it, so the census rows and
/// the protocol-digest entries the activation change adds cannot name another
/// number.
pub const REGISTRY_LIMITS: RegistryLimits =
    RegistryLimits { max_records: 4_096, max_ops_per_block: 8 };

/// The most records the registry may store, Enabled and Disabled together.
/// A deterministic consensus bound on the per-block registry scan, required by
/// the owner 2026-10-23; rule and value PROPOSED; dormant.
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
///   once per block, about 0.6 ms of BLAKE3 on one core (measured on an arm64
///   workstation). One 4,096-row scan costs about 0.7 ms at the account
///   root's reference of 40 ms per 250,000 rows (`account_root.rs`). Only an
///   otherwise valid register, quorum included, scans. With the proposed
///   per-block cap of 8 registry operations, a block costs at most about 6 ms,
///   about 0.4% of the 1,506 ms block interval.
///
/// The cost bound relies on a per-block cap on registry operations, a
/// block-validity rule of the activation change (README §12.1). Without one, a
/// validator quorum could put many validly signed registers in one block, and
/// each would scan.
///
/// Not in `protocol_digest::consensus_limits` while dormant, because no
/// transaction reaches the check. The activation change adds it there, and so
/// to the protocol digest every node declares at the handshake. ConsensusConfig
/// id: unallocated. Changing it after activation is a coordinated upgrade.
pub const MAX_REGISTRY_RECORDS: u64 = REGISTRY_LIMITS.max_records as u64;

/// The most bytes the proposed registry-state fold hashes per block at
/// [`MAX_REGISTRY_RECORDS`]: per record, its id (32 bytes) and its frozen
/// `RegistryRecordV1` (154 bytes); plus the proposed fold domain
/// `SUMCHAIN/REGISTRY/STATE/v1\0` (27 bytes, provisional with the activation
/// proposal) and the `u64` record count (8 bytes). 4,096 × 186 + 35 =
/// 761,891 bytes. Derived; not a separate parameter.
pub const MAX_REGISTRY_FOLDED_BYTES: u64 =
    MAX_REGISTRY_RECORDS * (32 + RegistryRecordV1::LEN as u64) + 27 + 8;

/// The most governance transactions naming operation 8 or 9 one block may
/// carry, registers and disables together, whatever their outcome. Required by
/// the owner 2026-10-23; rule and value PROPOSED; dormant and read by no code.
///
/// It is a block-validity rule of the activation change (README §12.1 (b)): a
/// block at or above A carrying more is invalid as a whole. It is defined here,
/// unwired, so that its value has one home, a census row and a pin before the
/// activation change, which adds it to `protocol_digest::consensus_limits`.
/// ConsensusConfig id: unallocated.
pub const MAX_REGISTRY_OPS_PER_BLOCK: u64 = REGISTRY_LIMITS.max_ops_per_block as u64;

/// `cf::META` key of the node-local freeze record (README §17 (a), PROPOSED;
/// key name provisional). No code writes it while dormant.
pub const REGISTRY_FREEZE_META_KEY: &[u8] = b"registry/freeze/v1";

/// `cf::META` key of the node-local gate pin (README §17 (a), PROPOSED; key
/// name provisional). No code writes it while dormant.
pub const REGISTRY_GATE_PIN_META_KEY: &[u8] = b"registry/freeze/gate/v1";

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
    /// The consensus limits this node enforces and commits in `P(h)`. Always
    /// [`REGISTRY_LIMITS`] in a production binary; a value that fails
    /// [`RegistryLimits::validate`] refuses both operations (`302`).
    pub limits: RegistryLimits,
    /// The chain's genesis block hash (`Genesis::create_genesis_block().hash()`,
    /// consensus-configuration field `0x0005`). `None` refuses both operations.
    pub genesis_block_hash: Option<&'a [u8; 32]>,
}

/// Everything a registry operation needs from outside its own bytes, present.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ready {
    values: RegistryIngressValues,
    genesis_block_hash: [u8; 32],
    limits: RegistryLimits,
}

/// `Some` only when every named parameter and the genesis hash are present.
pub(crate) fn ready(ctx: &RegistryIngressContext<'_>) -> Option<Ready> {
    ctx.limits.validate().ok()?;
    Some(Ready {
        values: ctx.params.complete()?,
        genesis_block_hash: *ctx.genesis_block_hash?,
        limits: ctx.limits,
    })
}

/// Register, executed at `height`.
///
/// `Ok(Ok(record))` is the record to store, and `Ok(Err(code))` a semantic
/// refusal, a receipt. `Err(_)` is a storage failure: an execution error,
/// never a receipt.
pub(crate) fn validate_register(
    view: &ExecutionView<'_, '_>,
    gp: &GovernanceParams,
    ready: &Ready,
    chain_id: ChainId,
    height: u64,
    active_validator_pubkeys: &[[u8; 32]],
    req: &RegistryRegisterV1,
) -> Result<std::result::Result<RegistryRecordV1, u32>> {
    let v = &ready.values;
    let record = &req.record;
    if !approval_window_open(height, req.valid_until, v.max_approval_window) {
        return Ok(Err(303));
    }
    if record.status != RegistryStatus::Enabled
        || check_threshold_bps(record.approval_threshold_bps).is_err()
        || !admitted_proof_systems().contains(&record.proof_system_id)
        || !unset_commitments(record).is_empty()
        || !timelock_satisfied(record.activation_height, height, v.min_timelock_blocks)
    {
        return Ok(Err(303));
    }
    // Q17 (owner, 2026-10-22): the authenticated governance threshold, from
    // chain parameters, never from the operation or a tooling default.
    let threshold = gp.validator_authority_threshold_bps;
    // B2 (adopted 2026-10-23): the record's own threshold is at least the
    // governance threshold effective at its registration.
    if record.approval_threshold_bps < threshold {
        return Ok(Err(303));
    }
    // Disabled is terminal: a disabled id is still present, so it can never
    // be registered again.
    if v_get_record(view, &record.id)?.is_some() {
        return Ok(Err(303));
    }
    // The record encodes by construction (it decoded); a failure here is the
    // operation's own bytes, deterministic on every node.
    let Ok(signing) =
        registry_register_signing_bytes(chain_id, &ready.genesis_block_hash, req.valid_until, record)
    else {
        return Ok(Err(303));
    };
    if verify_validator_quorum_strict(&req.approvals, &signing, active_validator_pubkeys, threshold)
        .is_err()
    {
        return Ok(Err(303));
    }
    // The size bound, last: only an otherwise valid register, quorum included,
    // pays for the scan. This register would store one more record, so it is
    // refused once `max_records` records, Enabled or Disabled, exist. The
    // limit is the context's, the value `P(h)` commits.
    let max_records = u64::from(ready.limits.max_records);
    if v_count_records_up_to(view, max_records)? >= max_records {
        return Ok(Err(303));
    }
    Ok(Ok(record.clone()))
}

/// Disable, executed at `height`: `Ok(Ok(record))` is the stored record, now
/// Disabled; `Ok(Err(code))` a receipt; `Err(_)` a storage failure, never a
/// receipt.
pub(crate) fn validate_disable(
    view: &ExecutionView<'_, '_>,
    ready: &Ready,
    chain_id: ChainId,
    height: u64,
    active_validator_pubkeys: &[[u8; 32]],
    req: &RegistryDisableV1,
) -> Result<std::result::Result<RegistryRecordV1, u32>> {
    let v = &ready.values;
    if !approval_window_open(height, req.valid_until, v.max_approval_window) {
        return Ok(Err(303));
    }
    let Some(stored) = v_get_record(view, &req.id)? else {
        return Ok(Err(303));
    };
    if stored.status != RegistryStatus::Enabled {
        return Ok(Err(303));
    }
    // B2 (adopted 2026-10-23): the stored record's own threshold, accepted at
    // its registration. A later change to the governance threshold does not
    // touch it, so a disable never gets harder over time.
    let threshold = stored.approval_threshold_bps;
    let signing =
        registry_disable_signing_bytes(chain_id, &ready.genesis_block_hash, req.valid_until, &req.id);
    if verify_validator_quorum_strict(&req.approvals, &signing, active_validator_pubkeys, threshold)
        .is_err()
    {
        return Ok(Err(303));
    }
    Ok(Ok(RegistryRecordV1 {
        status: RegistryStatus::Disabled,
        ..stored
    }))
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

/// One stored registry row, under the rule the count and the proposed
/// registry-state fold share: the key is exactly `registry/v1/` ‖ id (12 + 32
/// bytes), the value decodes as a `RegistryRecordV1`, and the record's id is
/// the key's. Anything else is an error, never skipped, counted or "no record".
pub fn checked_registry_row(key: &[u8], value: &[u8]) -> Result<RegistryRecordV1> {
    let invalid = |why: String| StateError::Storage(StorageError::InvalidData(why));
    let key_id = key
        .strip_prefix(REGISTRY_RECORD_KEY_PREFIX)
        .filter(|id| id.len() == 32)
        .ok_or_else(|| invalid(format!("registry row key of {} bytes", key.len())))?;
    let record = RegistryRecordV1::decode_exact(value)
        .map_err(|e| invalid(format!("registry record: {e}")))?;
    if record.id[..] != *key_id {
        return Err(invalid("registry record stored under another id".to_string()));
    }
    Ok(record)
}

/// The record stored under `id`, as this block's candidate sees it. A row that
/// breaks [`checked_registry_row`] is an error, never "no record".
pub fn v_get_record(
    view: &ExecutionView<'_, '_>,
    id: &[u8; 32],
) -> Result<Option<RegistryRecordV1>> {
    let key = registry_record_key(id);
    let Some(bytes) = view.get(cf::STATE, &key).map_err(StateError::Storage)? else {
        return Ok(None);
    };
    checked_registry_row(&key, &bytes).map(Some)
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
/// one register reads at most `MAX_REGISTRY_RECORDS` rows. Every row it
/// counts must pass [`checked_registry_row`]. A row that does not, or a read
/// error, is an error, never a short count.
pub fn v_count_records_up_to(view: &ExecutionView<'_, '_>, limit: u64) -> Result<u64> {
    let mut count = 0u64;
    if limit == 0 {
        return Ok(count);
    }
    for entry in view
        .prefix_iter(cf::STATE, REGISTRY_RECORD_KEY_PREFIX)
        .map_err(StateError::Storage)?
    {
        let (key, value) = entry.map_err(StateError::Storage)?;
        if !key.starts_with(REGISTRY_RECORD_KEY_PREFIX) {
            break;
        }
        checked_registry_row(&key, &value)?;
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

/// `P(h)` for the values this context gives execution (README §16 §1.3,
/// PROPOSED): the context's limits, which the size bound and the per-block cap
/// read, the governance threshold the caller reads from `ChainParams`, and the
/// named parameters when complete. Passing the same context to execution and to
/// this function is what makes the committed and the enforced values one
/// value; nothing here accepts a limit from anywhere else.
pub fn registry_params_digest_for(
    ctx: &RegistryIngressContext<'_>,
    governance_threshold_bps: Option<u16>,
) -> sumchain_primitives::Hash {
    let values = ctx
        .params
        .complete()
        .map(|v| (v.min_timelock_blocks, v.max_approval_window));
    sumchain_wire::registry_ingress::registry_params_digest(
        &ctx.limits,
        governance_threshold_bps,
        values,
    )
}

/// The proposed registry-state digest `R(h)` over this block's candidate view
/// (README §16 §1.3, PROPOSED). Dormant: no root folds it.
///
/// It reads every row under `registry/v1/` in ascending key order, the rows the
/// size-bound count reads. Each must pass [`checked_registry_row`]: a row that
/// does not, or a read error, is an error that fails the block, never skipped
/// or folded around. The preimage is
/// [`sumchain_wire::registry_ingress::registry_state_digest_preimage`].
pub fn v_registry_state_digest(view: &ExecutionView<'_, '_>) -> Result<sumchain_primitives::Hash> {
    let mut rows: Vec<([u8; 32], [u8; RegistryRecordV1::LEN])> = Vec::new();
    for entry in view
        .prefix_iter(cf::STATE, REGISTRY_RECORD_KEY_PREFIX)
        .map_err(StateError::Storage)?
    {
        let (key, value) = entry.map_err(StateError::Storage)?;
        if !key.starts_with(REGISTRY_RECORD_KEY_PREFIX) {
            break;
        }
        let record = checked_registry_row(&key, &value)?;
        let bytes: [u8; RegistryRecordV1::LEN] = value[..].try_into().map_err(|_| {
            StateError::Storage(StorageError::InvalidData(format!(
                "registry record of {} bytes",
                value.len()
            )))
        })?;
        rows.push((record.id, bytes));
    }
    let preimage = sumchain_wire::registry_ingress::registry_state_digest_preimage(
        rows.iter().map(|(id, bytes)| (id, bytes)),
    );
    Ok(sumchain_primitives::Hash::hash(&preimage))
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
        assert!(ready(&RegistryIngressContext { params: &params, limits: REGISTRY_LIMITS, genesis_block_hash: Some(&hash) }).is_some());
        assert!(ready(&RegistryIngressContext { params: &params, limits: REGISTRY_LIMITS, genesis_block_hash: None }).is_none());
        let unset = REGISTRY_INGRESS_PARAMS;
        assert_eq!(unset, RegistryIngressParams::UNSET);
        assert!(ready(&RegistryIngressContext { params: &unset, limits: REGISTRY_LIMITS, genesis_block_hash: Some(&hash) }).is_none());
    }
}

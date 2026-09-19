//! SRC-82X Tax & Compliance Executor
//!
//! A minimal implementation that handles core tax operations.

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    Address, Balance, BlockHeight, Hash, Timestamp,
    TaxClaimTypeEntry, TaxIssuer, TaxIssuerStatus, TaxOperation,
    TaxPolicy, TaxProofEnvelope, TaxDisclosureEnvelope, TaxTxData,
    ClaimTypeStatus,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, StateError, StateManager};

/// Result of Tax operation execution
#[derive(Debug)]
pub struct TaxExecutionResult {
    pub success: bool,
    pub policy_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl TaxExecutionResult {
    pub fn success_with_policy(policy_id: [u8; 32]) -> Self {
        Self { success: true, policy_id: Some(policy_id), proof_id: None, error: None }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self { success: true, policy_id: None, proof_id: Some(proof_id), error: None }
    }

    pub fn success() -> Self {
        Self { success: true, policy_id: None, proof_id: None, error: None }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self { success: false, policy_id: None, proof_id: None, error: Some(error.into()) }
    }
}

/// Tax executor for SRC-82X transactions.
///
/// No database handle, by construction: every operation takes the block's
/// `ExecutionView` and no `self`, so `self.db` is not something this file can
/// name. The committed twins stay in `sumchain_storage::tax_store` for the RPC
/// server.
pub struct TaxExecutor;

/// The activation decisions a Tax transaction executes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TaxGates {
    /// The claim-type registry is writable only by a registered, active issuer.
    /// ACTIVATION-AUDIT row AU-19.
    pub authorization: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
    /// The proof store and `TAX_SUBJECT_INDEX` stop disagreeing.
    /// ACTIVATION-AUDIT rows OV-1, OV-2 and OV-3.
    pub proof_lifecycle: bool,
    /// `VerifyProof` refuses as UNSUPPORTED, for every payload.
    /// ACTIVATION-AUDIT AU-20 (= PR-1). Supersedes the retired presence check: no
    /// verifier exists in this tree, so the operation cannot be performed
    /// and must not report success.
    pub proof_unsupported: bool,
    /// A transaction's sizing inputs are checked against a limit BEFORE the
    /// value they size is built: an oversized payload is refused before it is
    /// decoded, and a `TAX_SUBJECT_INDEX` row past the limit is refused before
    /// it is decoded, appended to and re-encoded. ACTIVATION-AUDIT row AL-1.
    pub allocation_bound: bool,
    /// `RegisterIssuer` refuses as UNSUPPORTED, for every payload.
    /// ACTIVATION-AUDIT row AU-18. No registrar exists for this subsystem's
    /// issuer classes, so the registry can only record what the applicant
    /// claimed about itself.
    pub issuer_self_registration_unsupported: bool,
}

impl TaxGates {
    /// The stored-row length limit this gate imposes, or `None` when closed.
    ///
    /// `None` is what the unbounded reader means, so a closed gate reads
    /// byte-for-byte what it read before the bound existed.
    #[inline]
    pub fn row_limit(self) -> Option<usize> {
        self.allocation_bound
            .then_some(crate::MAX_ACCUMULATING_ROW_BYTES)
    }

    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
        proof_lifecycle: false,
        proof_unsupported: false,
        allocation_bound: false,
        issuer_self_registration_unsupported: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
        proof_lifecycle: true,
        proof_unsupported: true,
        allocation_bound: true,
        issuer_self_registration_unsupported: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: TaxExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            proof_lifecycle: TaxExecutor::proof_lifecycle_gate_open(params, block_height),
            proof_unsupported: crate::subsystem_proof_unsupported_gate_open(params, block_height),
            allocation_bound: crate::subsystem_allocation_bound_gate_open(params, block_height),
            issuer_self_registration_unsupported:
                crate::subsystem_issuer_self_registration_unsupported_gate_open(
                    params,
                    block_height,
                ),
        }
    }
}

impl TaxExecutor {
    /// The activation height for the Tax claim-type authority check.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-84X Tax claim-type authority. Dormant by default (`None` ->
    /// /// never open). Below the gate claim-type registration, update and
    /// /// deprecation have no authority check at all: all three guard only on
    /// /// row presence or absence, so any funded account writes the chain's
    /// /// claim-type registry. At and above the gate the sender must be a
    /// /// registered tax issuer whose status is still Active. Activation is a
    /// /// consensus change and needs a coordinated validator upgrade.
    /// #[serde(default)]
    /// pub tax_authorization_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and every pinning test that records the gap still passes.
    #[inline]
    fn authorization_activation(params: &ChainParams) -> Option<u64> {
        params.tax_authorization_enabled_from_height
    }

    /// Whether the Tax claim-type authority check is active at `block_height`.
    #[inline]
    pub fn authorization_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::authorization_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the Tax proof lifecycle rules.
    ///
    /// Reads `params.tax_proof_lifecycle_enabled_from_height`, and nothing else.
    /// `None` -- the default, and what a genesis written before the field
    /// existed resolves to -- closes the gate, so a node executes exactly what
    /// it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT rows OV-1, OV-2 and OV-3):
    ///
    ///   * `IssueClaim` overwrites any existing proof row, because the proof id
    ///     is chosen by the sender and nothing checks whether it is taken;
    ///   * `RevokeClaim` reads its 32-byte payload field as a PROOF ID while
    ///     calling it a subject nullifier, so revocation by subject never finds
    ///     anything;
    ///   * deleting a proof leaves its `TAX_SUBJECT_INDEX` entry behind.
    ///
    /// At and above it a duplicate proof id is refused, `RevokeClaim` resolves
    /// its payload through the subject index, and the index row goes with the
    /// proofs it named.
    #[inline]
    fn proof_lifecycle_activation(params: &ChainParams) -> Option<u64> {
        params.tax_proof_lifecycle_enabled_from_height
    }

    /// Whether the Tax proof lifecycle rules are active at `block_height`.
    #[inline]
    pub fn proof_lifecycle_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::proof_lifecycle_activation(params), Some(h) if block_height >= h)
    }

    /// Is `sender` a registered tax issuer whose standing is still `Active`?
    fn issuer_in_good_standing(view: &ExecutionView<'_, '_>, sender: &Address) -> Result<bool> {
        Ok(match Self::v_get_issuer(view, sender)? {
            Some(issuer) => issuer.status == TaxIssuerStatus::Active,
            None => false,
        })
    }

    /// Execute a Tax transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &TaxTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<TaxExecutionResult> {
        Self::execute_with_gates(
            view,
            sender,
            data,
            proposer,
            fee,
            block_height,
            block_timestamp,
            tx_index,
            tx_hash,
            TaxGates::from_params(params, block_height),
        )
    }

    /// Execute a Tax transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &TaxTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: TaxGates,
    ) -> Result<TaxExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);

        // ACTIVATION-AUDIT row AL-1, and the Tax half of AL-12. Every arm below
        // opens with `bincode::deserialize(&data.data)` and no length check
        // ahead of it, so the only thing bounding a Tax payload today is
        // `max_block_bytes`. One check here rather than one per arm, for the
        // reason the DocClass executor gives at the same seam: the arms are
        // many and the rule is one.
        //
        // A refusal, not an error, and it charges nothing: every arm below
        // deducts the fee itself, and every pre-existing `failure()` that fires
        // before that deduction is already free.
        if gates.allocation_bound && data.data.len() > crate::MAX_SUBSYSTEM_PAYLOAD_BYTES {
            return Ok(TaxExecutionResult::failure(format!(
                "Tax payload too large: {} bytes, limit {}",
                data.data.len(),
                crate::MAX_SUBSYSTEM_PAYLOAD_BYTES
            )));
        }

        // AU-19: claim-type registration, update and deprecation have no
        // authority check at all below the gate -- all three guard only on row
        // presence or absence, so any funded account writes the chain's
        // claim-type registry. One check covers all three because they are the
        // same registry and the same question.
        if gates.authorization
            && matches!(
                data.operation,
                TaxOperation::RegisterClaimType
                    | TaxOperation::UpdateClaimType
                    | TaxOperation::DeprecateClaimType
            )
            && !Self::issuer_in_good_standing(view, sender)?
        {
            return Ok(TaxExecutionResult::failure(
                "Only a registered, active tax issuer can write the claim-type registry",
            ));
        }

        match data.operation {
            TaxOperation::RegisterClaimType => {
                let entry: TaxClaimTypeEntry = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_claim_type(view, &entry.claim_type)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_claim_type(view, &entry)?;
                debug!("Claim type registered: {}", entry.claim_type);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::UpdateClaimType => {
                let entry: TaxClaimTypeEntry = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_claim_type(view, &entry.claim_type)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_claim_type(view, &entry)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::DeprecateClaimType => {
                #[derive(serde::Deserialize)]
                struct Data { claim_type: String }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let mut entry = match Self::v_get_claim_type(view, &d.claim_type)? {
                    Some(e) => e,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                entry.status = ClaimTypeStatus::Deprecated;
                Self::v_put_claim_type(view, &entry)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::RegisterIssuer => {
                // ACTIVATION-AUDIT row AU-18. Below the gate this arm writes the
                // applicant's own payload into the issuer registry: the only
                // guards are that the profile names the sender and that the
                // sender is not registered already, so the CLASS -- `TaxIssuerClass::TaxAuthority`
                // included -- and the STATUS are whatever the applicant typed.
                // One funded account becomes an authority the rest of this
                // subsystem then resolves its authorization rules against.
                //
                // At and above the gate the arm refuses as UNSUPPORTED. A
                // registrar is what is missing, and there is none to consult:
                // no `ChainParams` field names one for Tax, nothing in
                // `genesis.json` seeds this registry, and no governance path in
                // this tree writes to it. Inventing one here would be a rule
                // nobody set.
                //
                // Refused BEFORE the deduct and before the payload is decoded,
                // where this arm's own duplicate refusal returns, so a refused
                // registration writes nothing and costs nothing.
                //
                // The cost is stated rather than hidden: with no registrar a
                // chain at this height cannot obtain a Tax issuer at all, so
                // every arm that requires one is unsatisfiable and the
                // subsystem is DEFERRED. Nothing that ever worked is stranded,
                // because there has never been a lawful issuer here to strand.
                if gates.issuer_self_registration_unsupported {
                    return Ok(TaxExecutionResult::failure(
                        crate::ISSUER_SELF_REGISTRATION_UNSUPPORTED,
                    ));
                }

                let issuer: TaxIssuer = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.address != *sender {
                    return Ok(TaxExecutionResult::failure("Address must be sender"));
                }

                if Self::v_get_issuer(view, sender)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already registered"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_issuer(view, &issuer)?;
                debug!("Tax issuer registered: {}", issuer.address);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::UpdateIssuer => {
                let issuer: TaxIssuer = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.address != *sender {
                    return Ok(TaxExecutionResult::failure("Can only update own"));
                }

                if Self::v_get_issuer(view, sender)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not registered"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_issuer(view, &issuer)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::SuspendIssuer | TaxOperation::RevokeIssuer => {
                #[derive(serde::Deserialize)]
                struct Data { issuer_address: Address }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let mut issuer = match Self::v_get_issuer(view, &d.issuer_address)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                if d.issuer_address != *sender {
                    return Ok(TaxExecutionResult::failure("Not authorized"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                issuer.status = if data.operation == TaxOperation::SuspendIssuer {
                    TaxIssuerStatus::Suspended
                } else {
                    TaxIssuerStatus::Revoked
                };
                issuer.updated_at = block_timestamp;
                Self::v_put_issuer(view, &issuer)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::CreatePolicy => {
                let policy: TaxPolicy = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if policy.creator != *sender {
                    return Ok(TaxExecutionResult::failure("Creator must be sender"));
                }

                if Self::v_get_policy(view, &policy.policy_id)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let policy_id = policy.policy_id;
                Self::v_put_policy(view, &policy)?;
                debug!("Tax policy created: {:?}", policy_id);
                Ok(TaxExecutionResult::success_with_policy(policy_id))
            }

            TaxOperation::UpdatePolicy => {
                let policy: TaxPolicy = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let existing = match Self::v_get_policy(view, &policy.policy_id)? {
                    Some(p) => p,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                if existing.creator != *sender {
                    return Ok(TaxExecutionResult::failure("Only creator can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let policy_id = policy.policy_id;
                Self::v_put_policy(view, &policy)?;
                Ok(TaxExecutionResult::success_with_policy(policy_id))
            }

            TaxOperation::IssueClaim => {
                let proof: TaxProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not registered")),
                };

                if issuer.status != TaxIssuerStatus::Active {
                    return Ok(TaxExecutionResult::failure("Not active"));
                }

                // OV-1: the proof id comes from the sender's payload and nothing
                // below the gate checks whether it is taken, so issuing a claim
                // is a blind overwrite of anybody's proof -- and the replaced
                // proof's subject-index entry is left naming a row whose subject
                // is now somebody else's. Refused before the fee, like every
                // other duplicate guard in this file.
                if gates.proof_lifecycle && Self::v_get_proof(view, &proof.proof_id)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Proof already exists"));
                }

                // ACTIVATION-AUDIT row AL-1. `v_put_proof` appends to the
                // subject index, which is an accumulating `Vec<ProofId>` under
                // one key: it decodes the whole stored list into owned values,
                // linear-searches it, pushes and re-encodes it, once per
                // `IssueClaim`, and the attacker chooses the entry count by
                // repeating the transaction against one nullifier it also
                // chooses. Below the gate the only ceiling is the write-set
                // ceiling, which is charged AFTER the replacement value has
                // been built. At and above it the STORED length is compared
                // before anything is decoded, so the refusal costs one
                // comparison. The length is read here rather than inside
                // `v_add_to_subject_index` so the refusal lands before the fee,
                // beside the duplicate guard above it.
                if let Some(max) = gates.row_limit() {
                    if let Some(n) = Self::v_subject_index_row_len(view, &proof.subject_nullifier)?
                    {
                        if n > max {
                            return Ok(TaxExecutionResult::failure(format!(
                                "Subject index too large to extend: {n} bytes, limit {max}"
                            )));
                        }
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Tax proof issued: {:?}", proof_id);
                Ok(TaxExecutionResult::success_with_proof(proof_id))
            }

            TaxOperation::RevokeClaim => {
                #[derive(serde::Deserialize)]
                struct Data { subject_nullifier: [u8; 32] }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not registered")),
                };

                if issuer.status != TaxIssuerStatus::Active {
                    return Ok(TaxExecutionResult::failure("Not active"));
                }

                // OV-2 and OV-3. The payload field is a SUBJECT NULLIFIER and is
                // named one; below the gate it is handed straight to the proof
                // store, which keys by proof id, so a revocation naming a subject
                // finds nothing and a revocation naming a proof id succeeds. At
                // and above the gate it is resolved through the subject index,
                // which is what it is a key for, and every proof the subject has
                // goes -- together with the index row, so the deletion stops
                // leaving a pointer to rows that are gone.
                if gates.proof_lifecycle {
                    if Self::v_get_subject_proof_ids(view, &d.subject_nullifier)?.is_empty() {
                        return Ok(TaxExecutionResult::failure("Not found"));
                    }

                    StateManager::v_deduct(view, sender, fee)?;
                    StateManager::v_credit(view, proposer, fee)?;
                    StateManager::v_increment_nonce(view, sender)?;
                    Self::v_delete_subject_proofs(view, &d.subject_nullifier)?;
                    return Ok(TaxExecutionResult::success());
                }

                if Self::v_get_proof(view, &d.subject_nullifier)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_delete_proof(view, &d.subject_nullifier)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::VerifyProof => {
                // ACTIVATION-AUDIT AU-20 (= PR-1). Below the gate this arm reads no
                // payload and no proof and returns SUCCESS, so the chain reports a
                // verified proof for a proof it has never held, for a payload that
                // is not a proof id, and for proof bytes nothing has ever looked
                // at. At and above the gate it refuses as UNSUPPORTED, for every
                // payload: no verifier for Tax proofs exists in this tree --
                // nothing checks `proof_data` against `public_inputs`, there is no
                // proof system in the workspace, no verifying key anywhere, and no
                // wire type for a verification request -- and an operation that
                // cannot be performed must say so rather than succeed.
                //
                // The proof family is deliberately NOT consulted. Whether the named
                // proof is present is not a fact about whether it is valid, and
                // branching on it would restore the implication that a present
                // proof was checked. That is why the presence gate this replaces
                // is retired rather than kept beneath this one.
                //
                // Refused BEFORE the deduct, which is where the sibling
                // `SubmitProof` arm's duplicate-id refusal returns, so a refused
                // proof operation costs the same in both.
                if gates.proof_unsupported {
                    return Ok(TaxExecutionResult::failure(crate::VERIFY_PROOF_UNSUPPORTED));
                }
                // Verify a submitted proof - just record verification request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Proof verification requested by: {}", sender);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::AttachDisclosure => {
                let disclosure: TaxDisclosureEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_put_disclosure(view, &disclosure)?;
                debug!("Disclosure attached: {:?}", disclosure.payload_hash);
                Ok(TaxExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sumchain_primitives::TaxIssuerClass;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_register_issuer() {
        let (db, _dir, _state) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = ChainParams::default();

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &issuer_addr, 1_000_000_000_000).unwrap();

        let issuer = TaxIssuer {
            address: issuer_addr,
            tax_class: TaxIssuerClass::TaxAuthority,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [0u8; 32],
            attributes_schema_hash: [0u8; 32],
            registered_at: 1000000,
            updated_at: 1000000,
            status: TaxIssuerStatus::Active,
            expires_at: None,
        };

        let tx_data = TaxTxData {
            operation: TaxOperation::RegisterIssuer,
            data: bincode::serialize(&issuer).unwrap(),
            recipient: Address::ZERO,
        };

        let result = TaxExecutor::execute(
            view,
            &params,
            &issuer_addr,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Register issuer failed: {:?}", result.error);

        // Read the CANDIDATE: this executor stages now.
        let retrieved = TaxExecutor::v_get_issuer(view, &issuer_addr)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.tax_class, TaxIssuerClass::TaxAuthority);
    }
}

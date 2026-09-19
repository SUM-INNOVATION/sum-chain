//! SRC-88X Employment & HR Executor
//!
//! Transaction executor for:
//! - SRC-881: Employer & Payroll Issuer Profile
//! - SRC-882: Employment Relationship Credential
//! - SRC-883: Income / Payroll Attestation
//! - SRC-885: 88X Proof Profiles

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    employment::{
        EmploymentCredential, EmploymentIssuerProfile, EmploymentOperation, EmploymentProofEnvelope,
        EmploymentStatus, EmploymentTxData, IncomeAttestation, IssuerStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, SchemaValidator, StateError, StateManager};

/// Result of Employment operation execution
#[derive(Debug)]
pub struct EmploymentExecutionResult {
    pub success: bool,
    pub issuer_address: Option<Address>,
    pub employment_id: Option<[u8; 32]>,
    pub attestation_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl EmploymentExecutionResult {
    pub fn success_with_issuer(issuer_address: Address) -> Self {
        Self {
            success: true,
            issuer_address: Some(issuer_address),
            employment_id: None,
            attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_employment(employment_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            employment_id: Some(employment_id),
            attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_attestation(attestation_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            employment_id: None,
            attestation_id: Some(attestation_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            employment_id: None,
            attestation_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            issuer_address: None,
            employment_id: None,
            attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            issuer_address: None,
            employment_id: None,
            attestation_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Employment executor for SRC-88X transactions.
///
/// No database handle, by construction: every operation takes the block's
/// `ExecutionView` and no `self`, so `self.db` is not something this file can
/// name. The committed twins stay in `sumchain_storage::employment_store` for
/// callers that answer about the published chain.
///
/// The `ChainParams` the old constructor took were never read — the field was
/// `#[allow(dead_code)]` — and the `SchemaValidator` was built from
/// `SchemaValidator::new()` once per executor. It is built here per call from
/// the same constructor, so it carries the same default config and validates
/// identically.
pub struct EmploymentExecutor;

/// The activation decisions an Employment transaction executes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmploymentGates {
    /// The subsystem's issuer-standing rule is enforced. ACTIVATION-AUDIT row
    /// AU-27.
    pub authorization: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
    /// `VerifyProof` refuses a payload that does not name a proof this
    /// subsystem holds. ACTIVATION-AUDIT row AU-29 (= PR-2).
    pub proof_presence: bool,
}

impl EmploymentGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
        proof_presence: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
        proof_presence: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: EmploymentExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            proof_presence: crate::subsystem_proof_presence_gate_open(params, block_height),
        }
    }
}

impl EmploymentExecutor {
    /// The activation height for the Employment issuer-standing rule.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-88X Employment issuer-standing rule. Dormant by default (`None`
    /// /// -> never open). Below the gate only `CreateEmployment` and
    /// /// `CreateIncomeAttestation` require an active issuer; every mutation
    /// /// checks only the address recorded on the row, so a suspended or
    /// /// revoked issuer keeps full control of everything it ever issued. At
    /// /// and above the gate every mutation asks the same question the creation
    /// /// paths ask. Activation is a consensus change and needs a coordinated
    /// /// validator upgrade.
    /// #[serde(default)]
    /// pub employment_authorization_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and `a_suspended_issuer_can_still_revoke_but_not_create` still
    /// passes with the asymmetry its name describes.
    #[inline]
    fn authorization_activation(params: &ChainParams) -> Option<u64> {
        params.employment_authorization_enabled_from_height
    }

    /// Whether the Employment issuer-standing rule is active at `block_height`.
    #[inline]
    pub fn authorization_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::authorization_activation(params), Some(h) if block_height >= h)
    }

    /// Is `sender` a registered issuer whose standing is still active?
    ///
    /// The exact question `CreateEmployment` and `CreateIncomeAttestation` ask
    /// inline, asked of the same row from the mutation paths.
    fn issuer_in_good_standing(view: &ExecutionView<'_, '_>, sender: &Address) -> Result<bool> {
        Ok(match Self::v_get_issuer(view, sender)? {
            Some(issuer) => issuer.status.is_active(),
            None => false,
        })
    }

    /// Execute an Employment transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &EmploymentTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<EmploymentExecutionResult> {
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
            EmploymentGates::from_params(params, block_height),
        )
    }

    /// Execute an Employment transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &EmploymentTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: EmploymentGates,
    ) -> Result<EmploymentExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);
        let schema_validator = SchemaValidator::new();

        match data.operation {
            // =================================================================
            // SRC-881: Issuer Registry Operations
            // =================================================================
            EmploymentOperation::RegisterIssuer => {
                let issuer: EmploymentIssuerProfile = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_issuer_exists(view, &issuer.issuer_address)? {
                    return Ok(EmploymentExecutionResult::failure("Issuer already exists"));
                }

                // PRIVACY ENFORCEMENT: Validate display_name doesn't contain PII
                if let Err(reason) = schema_validator
                    .validate_institutional_name(&issuer.display_name, "display_name")
                {
                    debug!(
                        "Schema validation failed for issuer {}: {}",
                        issuer.issuer_address, reason
                    );
                    return Ok(EmploymentExecutionResult::failure(format!(
                        "Schema validation failed: {}",
                        reason
                    )));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let issuer_addr = issuer.issuer_address;
                Self::v_put_issuer(view, &issuer)?;
                debug!("Employment issuer registered: {}", issuer_addr);
                Ok(EmploymentExecutionResult::success_with_issuer(issuer_addr))
            }

            EmploymentOperation::UpdateIssuer => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    status: IssuerStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not found")),
                };

                if issuer.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(view, sender, update.status, block_timestamp)?;
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::SuspendIssuer => {
                if !Self::v_issuer_exists(view, sender)? {
                    return Ok(EmploymentExecutionResult::failure("Issuer not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(
                    view,
                    sender,
                    IssuerStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Employment issuer suspended: {}", sender);
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::RevokeIssuer => {
                if !Self::v_issuer_exists(view, sender)? {
                    return Ok(EmploymentExecutionResult::failure("Issuer not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(view, sender, IssuerStatus::Revoked, block_timestamp)?;
                debug!("Employment issuer revoked: {}", sender);
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::ReactivateIssuer => {
                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not found")),
                };

                if issuer.status != IssuerStatus::Suspended {
                    return Ok(EmploymentExecutionResult::failure("Issuer is not suspended"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(view, sender, IssuerStatus::Active, block_timestamp)?;
                debug!("Employment issuer reactivated: {}", sender);
                Ok(EmploymentExecutionResult::success())
            }

            // =================================================================
            // SRC-882: Employment Credential Operations
            // =================================================================
            EmploymentOperation::CreateEmployment => {
                let credential: EmploymentCredential = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(EmploymentExecutionResult::failure("Issuer is not active"));
                        }
                    }
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_credential_exists(view, &credential.employment_id)? {
                    return Ok(EmploymentExecutionResult::failure("Employment credential already exists"));
                }

                // PRIVACY ENFORCEMENT: Validate schema to prevent PII in free-form fields
                // Hard rejection at consensus level for SRC-882 employment credentials
                let validation_result =
                    schema_validator.validate_employment_credential(&credential, _block_height);
                if !validation_result.is_valid() {
                    if let crate::ValidationResult::Invalid { reason } = validation_result {
                        debug!(
                            "Schema validation failed for employment credential {:?}: {}",
                            credential.employment_id, reason
                        );
                        return Ok(EmploymentExecutionResult::failure(format!(
                            "Schema validation failed: {}",
                            reason
                        )));
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let employment_id = credential.employment_id;
                Self::v_put_credential(view, &credential)?;
                debug!("Employment credential created: {:?}", employment_id);
                Ok(EmploymentExecutionResult::success_with_employment(employment_id))
            }

            EmploymentOperation::UpdateEmployment => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    employment_id: [u8; 32],
                    status: EmploymentStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_credential(view, &d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can update"));
                }

                // AU-27: below the gate this path checks only the address on
                // the row, so a suspended or revoked issuer keeps full control
                // of everything it ever issued. The two creation paths ask this
                // same question inline; the asymmetry is the defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(EmploymentExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_credential_status(
                    view,
                    &d.employment_id,
                    d.status,
                    block_timestamp,
                )?;
                debug!("Employment credential updated: {:?}", d.employment_id);
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::SuspendEmployment => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    employment_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_credential(view, &d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can suspend"));
                }

                // AU-27: below the gate this path checks only the address on
                // the row, so a suspended or revoked issuer keeps full control
                // of everything it ever issued. The two creation paths ask this
                // same question inline; the asymmetry is the defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(EmploymentExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_credential_status(
                    view,
                    &d.employment_id,
                    EmploymentStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Employment credential suspended: {:?}", d.employment_id);
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::EndEmployment => {
                #[derive(serde::Deserialize)]
                struct EndData {
                    employment_id: [u8; 32],
                }
                let d: EndData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_credential(view, &d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can end"));
                }

                // AU-27: below the gate this path checks only the address on
                // the row, so a suspended or revoked issuer keeps full control
                // of everything it ever issued. The two creation paths ask this
                // same question inline; the asymmetry is the defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(EmploymentExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_credential_status(
                    view,
                    &d.employment_id,
                    EmploymentStatus::Ended,
                    block_timestamp,
                )?;
                debug!("Employment ended: {:?}", d.employment_id);
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::RevokeEmployment => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    employment_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_credential(view, &d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can revoke"));
                }

                // AU-27: below the gate this path checks only the address on
                // the row, so a suspended or revoked issuer keeps full control
                // of everything it ever issued. The two creation paths ask this
                // same question inline; the asymmetry is the defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(EmploymentExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_credential(
                    view,
                    &d.employment_id,
                    d.revocation_ref,
                    block_timestamp,
                )?;
                debug!("Employment credential revoked: {:?}", d.employment_id);
                Ok(EmploymentExecutionResult::success())
            }

            // =================================================================
            // SRC-883: Income Attestation Operations
            // =================================================================
            EmploymentOperation::CreateIncomeAttestation => {
                let attestation: IncomeAttestation = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if attestation.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(EmploymentExecutionResult::failure("Issuer is not active"));
                        }
                    }
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_attestation_exists(view, &attestation.attestation_id)? {
                    return Ok(EmploymentExecutionResult::failure("Income attestation already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let attestation_id = attestation.attestation_id;
                Self::v_put_attestation(view, &attestation)?;
                debug!("Income attestation created: {:?}", attestation_id);
                Ok(EmploymentExecutionResult::success_with_attestation(attestation_id))
            }

            EmploymentOperation::UpdateIncomeAttestation => {
                // For now, we only support updating via revoke and re-issue
                Ok(EmploymentExecutionResult::failure("Update not supported, use revoke and re-issue"))
            }

            EmploymentOperation::RevokeIncomeAttestation => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    attestation_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let attestation = match Self::v_get_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(EmploymentExecutionResult::failure("Income attestation not found")),
                };

                if attestation.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can revoke"));
                }

                // AU-27: below the gate this path checks only the address on
                // the row, so a suspended or revoked issuer keeps full control
                // of everything it ever issued. The two creation paths ask this
                // same question inline; the asymmetry is the defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(EmploymentExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_attestation(
                    view,
                    &d.attestation_id,
                    d.revocation_ref,
                    block_timestamp,
                )?;
                debug!("Income attestation revoked: {:?}", d.attestation_id);
                Ok(EmploymentExecutionResult::success())
            }

            // =================================================================
            // SRC-885: Proof Operations
            // =================================================================
            EmploymentOperation::SubmitProof => {
                let proof: EmploymentProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_proof_exists(view, &proof.proof_id)? {
                    return Ok(EmploymentExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Employment proof submitted: {:?}", proof_id);
                Ok(EmploymentExecutionResult::success_with_proof(proof_id))
            }

            EmploymentOperation::VerifyProof => {
                // ACTIVATION-AUDIT AU-29 (= PR-2). Below the gate this arm reads no
                // payload and no proof, and reports success for a proof the chain
                // has never held. At and above it the payload must be the 32 bytes
                // of a proof id and that proof must be present. Presence is NOT
                // verification and this does not claim to be: nothing in this tree
                // checks `proof_data` against `public_inputs`. What it removes is
                // the false positive.
                //
                // Refused BEFORE the deduct, which is where the sibling
                // `SubmitProof` arm's duplicate-id refusal returns, so a refused
                // proof operation costs the same in both.
                if gates.proof_presence {
                    let Some(proof_id) = crate::verify_proof_target(&data.data) else {
                        return Ok(EmploymentExecutionResult::failure(format!(
                            "VerifyProof payload must be a {}-byte proof id, got {} bytes",
                            crate::PROOF_ID_BYTES,
                            data.data.len()
                        )));
                    };
                    if !Self::v_proof_exists(view, &proof_id)? {
                        return Ok(EmploymentExecutionResult::failure("Proof not found"));
                    }
                }
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Employment proof verification requested by: {}", sender);
                Ok(EmploymentExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sumchain_primitives::employment::{EmploymentIssuerClass, EmploymentType};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    fn issuer_profile(sender: Address) -> EmploymentIssuerProfile {
        EmploymentIssuerProfile {
            issuer_address: sender,
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            display_name: "Payroll Co".to_string(),
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US-CA".to_string(),
            policy_id: [3u8; 32],
            status: IssuerStatus::Active,
            registered_at_height: 100,
            created_at: 1000,
            updated_at: 1000,
        }
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

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

        let issuer = issuer_profile(sender);
        let tx_data = EmploymentTxData {
            operation: EmploymentOperation::RegisterIssuer,
            data: bincode::serialize(&issuer).unwrap(),
            recipient: Address::ZERO,
        };

        let result = EmploymentExecutor::execute(
            view,
            &params,
            &sender,
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
        assert_eq!(result.issuer_address, Some(sender));

        // Read the CANDIDATE: this executor stages now.
        let retrieved = EmploymentExecutor::v_get_issuer(view, &sender)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA");
    }

    #[test]
    fn test_create_employment_credential() {
        let (db, _dir, _state) = setup();
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = ChainParams::default();

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

        // First register issuer
        let tx_data = EmploymentTxData {
            operation: EmploymentOperation::RegisterIssuer,
            data: bincode::serialize(&issuer_profile(sender)).unwrap(),
            recipient: Address::ZERO,
        };
        EmploymentExecutor::execute(
            view,
            &params,
            &sender,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        // Now create employment credential
        let credential = EmploymentCredential {
            employment_id: [10u8; 32],
            employee_address: Address::new([77u8; 20]),
            employee_ref: [11u8; 32],
            employer_ref: [12u8; 32],
            status: EmploymentStatus::Active,
            tenure_commitment: [13u8; 32],
            role_commitment: Some([14u8; 32]),
            employment_type: EmploymentType::FullTime,
            valid_from: 1000,
            expiry: 0,
            policy_id: [15u8; 32],
            revocation_ref: None,
            issuer_address: sender,
            issuer_name: "Payroll Co".to_string(),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            created_at: 1000,
            updated_at: 1000,
        };

        let tx_data = EmploymentTxData {
            operation: EmploymentOperation::CreateEmployment,
            data: bincode::serialize(&credential).unwrap(),
            recipient: Address::ZERO,
        };

        let result = EmploymentExecutor::execute(
            view,
            &params,
            &sender,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            1,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Create employment failed: {:?}", result.error);
        assert_eq!(result.employment_id, Some([10u8; 32]));

        // Read the CANDIDATE, not the database: nothing is committed here.
        let retrieved = EmploymentExecutor::v_get_credential(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.employment_type, EmploymentType::FullTime);
    }
}

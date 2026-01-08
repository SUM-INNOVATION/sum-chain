//! SRC-88X Employment & HR Executor
//!
//! Transaction executor for:
//! - SRC-881: Employer & Payroll Issuer Profile
//! - SRC-882: Employment Relationship Credential
//! - SRC-883: Income / Payroll Attestation
//! - SRC-885: 88X Proof Profiles

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    employment::{
        EmploymentCredential, EmploymentIssuerProfile, EmploymentOperation, EmploymentProofEnvelope,
        EmploymentStatus, EmploymentTxData, IncomeAttestation, IssuerStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use sumchain_storage::{Database, EmploymentStore};
use tracing::debug;

use crate::{Result, StateError, StateManager};

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

/// Employment executor for SRC-88X transactions
pub struct EmploymentExecutor {
    db: Arc<Database>,
    #[allow(dead_code)]
    params: ChainParams,
}

impl EmploymentExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Execute an Employment transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &EmploymentTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<EmploymentExecutionResult> {
        let store = EmploymentStore::new(&self.db);

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

                if store.issuers().exists(&issuer.issuer_address)? {
                    return Ok(EmploymentExecutionResult::failure("Issuer already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let issuer_addr = issuer.issuer_address;
                store.issuers().put(&issuer)?;
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

                let issuer = match store.issuers().get(sender)? {
                    Some(i) => i,
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not found")),
                };

                if issuer.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.issuers().update_status(sender, update.status, block_timestamp)?;
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::SuspendIssuer => {
                if !store.issuers().exists(sender)? {
                    return Ok(EmploymentExecutionResult::failure("Issuer not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.issuers().update_status(sender, IssuerStatus::Suspended, block_timestamp)?;
                debug!("Employment issuer suspended: {}", sender);
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::RevokeIssuer => {
                if !store.issuers().exists(sender)? {
                    return Ok(EmploymentExecutionResult::failure("Issuer not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.issuers().update_status(sender, IssuerStatus::Revoked, block_timestamp)?;
                debug!("Employment issuer revoked: {}", sender);
                Ok(EmploymentExecutionResult::success())
            }

            EmploymentOperation::ReactivateIssuer => {
                let issuer = match store.issuers().get(sender)? {
                    Some(i) => i,
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not found")),
                };

                if issuer.status != IssuerStatus::Suspended {
                    return Ok(EmploymentExecutionResult::failure("Issuer is not suspended"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.issuers().update_status(sender, IssuerStatus::Active, block_timestamp)?;
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
                match store.issuers().get(sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(EmploymentExecutionResult::failure("Issuer is not active"));
                        }
                    }
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not registered")),
                }

                if store.credentials().exists(&credential.employment_id)? {
                    return Ok(EmploymentExecutionResult::failure("Employment credential already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let employment_id = credential.employment_id;
                store.credentials().put(&credential)?;
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

                let credential = match store.credentials().get(&d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.credentials().update_status(&d.employment_id, d.status, block_timestamp)?;
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

                let credential = match store.credentials().get(&d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can suspend"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.credentials().update_status(&d.employment_id, EmploymentStatus::Suspended, block_timestamp)?;
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

                let credential = match store.credentials().get(&d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can end"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.credentials().update_status(&d.employment_id, EmploymentStatus::Ended, block_timestamp)?;
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

                let credential = match store.credentials().get(&d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can revoke"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.credentials().revoke(&d.employment_id, d.revocation_ref, block_timestamp)?;
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
                match store.issuers().get(sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(EmploymentExecutionResult::failure("Issuer is not active"));
                        }
                    }
                    None => return Ok(EmploymentExecutionResult::failure("Issuer not registered")),
                }

                if store.income_attestations().exists(&attestation.attestation_id)? {
                    return Ok(EmploymentExecutionResult::failure("Income attestation already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let attestation_id = attestation.attestation_id;
                store.income_attestations().put(&attestation)?;
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

                let attestation = match store.income_attestations().get(&d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(EmploymentExecutionResult::failure("Income attestation not found")),
                };

                if attestation.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can revoke"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.income_attestations().revoke(&d.attestation_id, d.revocation_ref, block_timestamp)?;
                debug!("Income attestation revoked: {:?}", d.attestation_id);
                Ok(EmploymentExecutionResult::success())
            }

            // =================================================================
            // SRC-885: Proof Operations
            // =================================================================
            EmploymentOperation::SubmitProof => {
                let proof: EmploymentProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.proofs().exists(&proof.proof_id)? {
                    return Ok(EmploymentExecutionResult::failure("Proof already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let proof_id = proof.proof_id;
                store.proofs().put(&proof)?;
                debug!("Employment proof submitted: {:?}", proof_id);
                Ok(EmploymentExecutionResult::success_with_proof(proof_id))
            }

            EmploymentOperation::VerifyProof => {
                // Verification is read-only - just record the request
                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                debug!("Employment proof verification requested by: {}", sender);
                Ok(EmploymentExecutionResult::success())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::employment::{EmploymentIssuerClass, EmploymentType};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_employment_executor_creation() {
        let (db, _dir, _state) = setup();
        let _executor = EmploymentExecutor::new(db, ChainParams::default());
    }

    #[test]
    fn test_register_issuer() {
        let (db, _dir, state) = setup();
        let executor = EmploymentExecutor::new(db.clone(), ChainParams::default());

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        state.credit(&sender, 1_000_000_000_000).unwrap();

        let issuer = EmploymentIssuerProfile {
            issuer_address: sender,
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US-CA".to_string(),
            policy_id: [3u8; 32],
            status: IssuerStatus::Active,
            registered_at_height: 100,
            created_at: 1000,
            updated_at: 1000,
        };

        let tx_data = EmploymentTxData {
            operation: EmploymentOperation::RegisterIssuer,
            data: bincode::serialize(&issuer).unwrap(),
        };

        let result = executor.execute(
            &sender, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default(),
        ).unwrap();

        assert!(result.success, "Register issuer failed: {:?}", result.error);
        assert_eq!(result.issuer_address, Some(sender));

        // Verify storage
        let store = EmploymentStore::new(&db);
        let retrieved = store.issuers().get(&sender).unwrap().unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA");
    }

    #[test]
    fn test_create_employment_credential() {
        let (db, _dir, state) = setup();
        let executor = EmploymentExecutor::new(db.clone(), ChainParams::default());

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        state.credit(&sender, 1_000_000_000_000).unwrap();

        // First register issuer
        let issuer = EmploymentIssuerProfile {
            issuer_address: sender,
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US-CA".to_string(),
            policy_id: [3u8; 32],
            status: IssuerStatus::Active,
            registered_at_height: 100,
            created_at: 1000,
            updated_at: 1000,
        };

        let tx_data = EmploymentTxData {
            operation: EmploymentOperation::RegisterIssuer,
            data: bincode::serialize(&issuer).unwrap(),
        };
        executor.execute(&sender, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default()).unwrap();

        // Now create employment credential
        let credential = EmploymentCredential {
            employment_id: [10u8; 32],
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
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            created_at: 1000,
            updated_at: 1000,
        };

        let tx_data = EmploymentTxData {
            operation: EmploymentOperation::CreateEmployment,
            data: bincode::serialize(&credential).unwrap(),
        };

        let result = executor.execute(
            &sender, &tx_data, &state, &proposer, 1000, 100, 1000000, 1, Hash::default(),
        ).unwrap();

        assert!(result.success, "Create employment failed: {:?}", result.error);
        assert_eq!(result.employment_id, Some([10u8; 32]));

        // Verify storage
        let store = EmploymentStore::new(&db);
        let retrieved = store.credentials().get(&[10u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved.employment_type, EmploymentType::FullTime);
    }
}

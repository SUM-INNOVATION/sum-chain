//! SRC-82X Tax & Compliance Executor
//!
//! A minimal implementation that handles core tax operations.

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Balance, BlockHeight, Hash, Timestamp,
    TaxClaimTypeEntry, TaxIssuer, TaxIssuerStatus, TaxOperation,
    TaxPolicy, TaxProofEnvelope, TaxDisclosureEnvelope, TaxTxData,
    ClaimTypeStatus,
};
use sumchain_storage::{Database, TaxStore};
use tracing::debug;

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

/// Tax executor for SRC-82X transactions
pub struct TaxExecutor {
    db: Arc<Database>,
    #[allow(dead_code)]
    params: ChainParams,
}

impl TaxExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Execute a Tax transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &TaxTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<TaxExecutionResult> {
        let store = TaxStore::new(&self.db);

        match data.operation {
            TaxOperation::RegisterClaimType => {
                let entry: TaxClaimTypeEntry = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.claim_types().get(&entry.claim_type)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claim_types().put(&entry)?;
                debug!("Claim type registered: {}", entry.claim_type);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::UpdateClaimType => {
                let entry: TaxClaimTypeEntry = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.claim_types().get(&entry.claim_type)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claim_types().put(&entry)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::DeprecateClaimType => {
                #[derive(serde::Deserialize)]
                struct Data { claim_type: String }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let mut entry = match store.claim_types().get(&d.claim_type)? {
                    Some(e) => e,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                entry.status = ClaimTypeStatus::Deprecated;
                store.claim_types().put(&entry)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::RegisterIssuer => {
                let issuer: TaxIssuer = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.address != *sender {
                    return Ok(TaxExecutionResult::failure("Address must be sender"));
                }

                if store.issuers().get(sender)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already registered"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.issuers().put(&issuer)?;
                debug!("Tax issuer registered: {}", issuer.address);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::UpdateIssuer => {
                let issuer: TaxIssuer = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.address != *sender {
                    return Ok(TaxExecutionResult::failure("Can only update own"));
                }

                if store.issuers().get(sender)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not registered"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.issuers().put(&issuer)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::SuspendIssuer | TaxOperation::RevokeIssuer => {
                #[derive(serde::Deserialize)]
                struct Data { issuer_address: Address }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let mut issuer = match store.issuers().get(&d.issuer_address)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                if d.issuer_address != *sender {
                    return Ok(TaxExecutionResult::failure("Not authorized"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;

                issuer.status = if data.operation == TaxOperation::SuspendIssuer {
                    TaxIssuerStatus::Suspended
                } else {
                    TaxIssuerStatus::Revoked
                };
                issuer.updated_at = block_timestamp;
                store.issuers().put(&issuer)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::CreatePolicy => {
                let policy: TaxPolicy = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if policy.creator != *sender {
                    return Ok(TaxExecutionResult::failure("Creator must be sender"));
                }

                if store.policies().get(&policy.policy_id)?.is_some() {
                    return Ok(TaxExecutionResult::failure("Already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let policy_id = policy.policy_id;
                store.policies().put(&policy)?;
                debug!("Tax policy created: {:?}", policy_id);
                Ok(TaxExecutionResult::success_with_policy(policy_id))
            }

            TaxOperation::UpdatePolicy => {
                let policy: TaxPolicy = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let existing = match store.policies().get(&policy.policy_id)? {
                    Some(p) => p,
                    None => return Ok(TaxExecutionResult::failure("Not found")),
                };

                if existing.creator != *sender {
                    return Ok(TaxExecutionResult::failure("Only creator can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let policy_id = policy.policy_id;
                store.policies().put(&policy)?;
                Ok(TaxExecutionResult::success_with_policy(policy_id))
            }

            TaxOperation::IssueClaim => {
                let proof: TaxProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match store.issuers().get(sender)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not registered")),
                };

                if issuer.status != TaxIssuerStatus::Active {
                    return Ok(TaxExecutionResult::failure("Not active"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let proof_id = proof.proof_id;
                store.proofs().put(&proof)?;
                debug!("Tax proof issued: {:?}", proof_id);
                Ok(TaxExecutionResult::success_with_proof(proof_id))
            }

            TaxOperation::RevokeClaim => {
                #[derive(serde::Deserialize)]
                struct Data { subject_nullifier: [u8; 32] }
                let d: Data = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match store.issuers().get(sender)? {
                    Some(i) => i,
                    None => return Ok(TaxExecutionResult::failure("Not registered")),
                };

                if issuer.status != TaxIssuerStatus::Active {
                    return Ok(TaxExecutionResult::failure("Not active"));
                }

                if store.proofs().get(&d.subject_nullifier)?.is_none() {
                    return Ok(TaxExecutionResult::failure("Not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.proofs().delete(&d.subject_nullifier)?;
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::VerifyProof => {
                // Verify a submitted proof - just record verification request
                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                debug!("Proof verification requested by: {}", sender);
                Ok(TaxExecutionResult::success())
            }

            TaxOperation::AttachDisclosure => {
                let disclosure: TaxDisclosureEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.disclosures().put(&disclosure)?;
                debug!("Disclosure attached: {:?}", disclosure.payload_hash);
                Ok(TaxExecutionResult::success())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_tax_executor_creation() {
        let (db, _dir, _state) = setup();
        let _executor = TaxExecutor::new(db, ChainParams::default());
    }

    #[test]
    fn test_register_issuer() {
        let (db, _dir, state) = setup();
        let executor = TaxExecutor::new(db.clone(), ChainParams::default());

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        state.credit(&issuer_addr, 1_000_000_000_000).unwrap();

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
        };

        let result = executor.execute(
            &issuer_addr, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default(),
        ).unwrap();

        assert!(result.success, "Register issuer failed: {:?}", result.error);

        let store = TaxStore::new(&db);
        let retrieved = store.issuers().get(&issuer_addr).unwrap().unwrap();
        assert_eq!(retrieved.tax_class, TaxIssuerClass::TaxAuthority);
    }
}

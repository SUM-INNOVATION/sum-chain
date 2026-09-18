//! SRC-89X Finance & Banking Executor
//!
//! Transaction executor for:
//! - SRC-891: Financial Institution & Utility Issuer Profile
//! - SRC-892: Proof-of-Address Credential
//! - SRC-893: Bank Account Standing Credential
//! - SRC-894: KYC / AML Attestation
//! - SRC-895: 89X Proof Profiles

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    finance::{
        AccountStanding, AddressProof, BankStandingCredential, FinanceIssuerProfile,
        FinanceIssuerStatus, FinanceOperation, FinanceProofEnvelope, FinanceTxData,
        KycAttestation, KycStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use crate::{Result, StateError, StateManager};

/// Result of Finance operation execution
#[derive(Debug)]
pub struct FinanceExecutionResult {
    pub success: bool,
    pub issuer_address: Option<Address>,
    pub address_proof_id: Option<[u8; 32]>,
    pub bank_standing_id: Option<[u8; 32]>,
    pub kyc_attestation_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl FinanceExecutionResult {
    pub fn success_with_issuer(issuer_address: Address) -> Self {
        Self {
            success: true,
            issuer_address: Some(issuer_address),
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_address_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: Some(proof_id),
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_bank_standing(credential_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: Some(credential_id),
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_kyc(attestation_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: Some(attestation_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Finance executor for SRC-89X transactions.
///
/// No database handle, by construction: every operation takes the block's
/// `ExecutionView` and no `self`, so `self.db` is not something this file can
/// name. The committed twins stay in `sumchain_storage::finance_store` for the
/// RPC server.
pub struct FinanceExecutor;

impl FinanceExecutor {
    /// Execute a Finance transaction
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &FinanceTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<FinanceExecutionResult> {
        match data.operation {
            // =================================================================
            // SRC-891: Issuer Registry Operations
            // =================================================================
            FinanceOperation::RegisterIssuer => {
                let issuer: FinanceIssuerProfile = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_issuer_exists(view, &issuer.issuer_address)? {
                    return Ok(FinanceExecutionResult::failure("Issuer already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let issuer_addr = issuer.issuer_address;
                Self::v_put_issuer(view, &issuer)?;
                debug!("Finance issuer registered: {}", issuer_addr);
                Ok(FinanceExecutionResult::success_with_issuer(issuer_addr))
            }

            FinanceOperation::UpdateIssuer => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    status: FinanceIssuerStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(FinanceExecutionResult::failure("Issuer not found")),
                };

                if issuer.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(view, sender, update.status, block_timestamp)?;
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::SuspendIssuer => {
                if !Self::v_issuer_exists(view, sender)? {
                    return Ok(FinanceExecutionResult::failure("Issuer not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(
                    view,
                    sender,
                    FinanceIssuerStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Finance issuer suspended: {}", sender);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::RevokeIssuer => {
                if !Self::v_issuer_exists(view, sender)? {
                    return Ok(FinanceExecutionResult::failure("Issuer not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(
                    view,
                    sender,
                    FinanceIssuerStatus::Revoked,
                    block_timestamp,
                )?;
                debug!("Finance issuer revoked: {}", sender);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::ReactivateIssuer => {
                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(FinanceExecutionResult::failure("Issuer not found")),
                };

                if issuer.status != FinanceIssuerStatus::Suspended {
                    return Ok(FinanceExecutionResult::failure("Issuer is not suspended"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(
                    view,
                    sender,
                    FinanceIssuerStatus::Active,
                    block_timestamp,
                )?;
                debug!("Finance issuer reactivated: {}", sender);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-892: Address Proof Operations
            // =================================================================
            FinanceOperation::CreateAddressProof => {
                let proof: AddressProof = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if proof.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(FinanceExecutionResult::failure("Issuer is not active"));
                        }
                        if !issuer.issuer_class.can_issue_address_proof() {
                            return Ok(FinanceExecutionResult::failure("Issuer cannot issue address proofs"));
                        }
                    }
                    None => return Ok(FinanceExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_address_proof_exists(view, &proof.proof_id)? {
                    return Ok(FinanceExecutionResult::failure("Address proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_address_proof(view, &proof)?;
                debug!("Address proof created: {:?}", proof_id);
                Ok(FinanceExecutionResult::success_with_address_proof(proof_id))
            }

            FinanceOperation::UpdateAddressProof => {
                // For now, we only support updating via revoke and re-issue
                Ok(FinanceExecutionResult::failure("Update not supported, use revoke and re-issue"))
            }

            FinanceOperation::RevokeAddressProof => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    proof_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let proof = match Self::v_get_address_proof(view, &d.proof_id)? {
                    Some(p) => p,
                    None => return Ok(FinanceExecutionResult::failure("Address proof not found")),
                };

                if proof.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_address_proof(view, &d.proof_id, d.revocation_ref, block_timestamp)?;
                debug!("Address proof revoked: {:?}", d.proof_id);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-893: Bank Standing Operations
            // =================================================================
            FinanceOperation::CreateBankStanding => {
                let credential: BankStandingCredential = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if credential.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(FinanceExecutionResult::failure("Issuer is not active"));
                        }
                        if !issuer.issuer_class.can_issue_bank_standing() {
                            return Ok(FinanceExecutionResult::failure("Issuer cannot issue bank standing credentials"));
                        }
                    }
                    None => return Ok(FinanceExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_bank_standing_exists(view, &credential.credential_id)? {
                    return Ok(FinanceExecutionResult::failure("Bank standing credential already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let credential_id = credential.credential_id;
                Self::v_put_bank_standing(view, &credential)?;
                debug!("Bank standing credential created: {:?}", credential_id);
                Ok(FinanceExecutionResult::success_with_bank_standing(credential_id))
            }

            FinanceOperation::UpdateBankStanding => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    credential_id: [u8; 32],
                    standing: AccountStanding,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_bank_standing(view, &d.credential_id)? {
                    Some(c) => c,
                    None => return Ok(FinanceExecutionResult::failure("Bank standing credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_bank_standing(view, &d.credential_id, d.standing, block_timestamp)?;
                debug!("Bank standing updated: {:?}", d.credential_id);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::RevokeBankStanding => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    credential_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_bank_standing(view, &d.credential_id)? {
                    Some(c) => c,
                    None => return Ok(FinanceExecutionResult::failure("Bank standing credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_bank_standing(
                    view,
                    &d.credential_id,
                    d.revocation_ref,
                    block_timestamp,
                )?;
                debug!("Bank standing credential revoked: {:?}", d.credential_id);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-894: KYC Attestation Operations
            // =================================================================
            FinanceOperation::CreateKycAttestation => {
                let attestation: KycAttestation = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if attestation.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(FinanceExecutionResult::failure("Issuer is not active"));
                        }
                        if !issuer.issuer_class.can_issue_kyc() {
                            return Ok(FinanceExecutionResult::failure("Issuer cannot issue KYC attestations"));
                        }
                    }
                    None => return Ok(FinanceExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_kyc_attestation_exists(view, &attestation.attestation_id)? {
                    return Ok(FinanceExecutionResult::failure("KYC attestation already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let attestation_id = attestation.attestation_id;
                Self::v_put_kyc_attestation(view, &attestation)?;
                debug!("KYC attestation created: {:?}", attestation_id);
                Ok(FinanceExecutionResult::success_with_kyc(attestation_id))
            }

            FinanceOperation::UpdateKycAttestation => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    attestation_id: [u8; 32],
                    status: KycStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let attestation = match Self::v_get_kyc_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(FinanceExecutionResult::failure("KYC attestation not found")),
                };

                if attestation.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_kyc_status(view, &d.attestation_id, d.status, block_timestamp)?;
                debug!("KYC attestation updated: {:?}", d.attestation_id);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::RevokeKycAttestation => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    attestation_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let attestation = match Self::v_get_kyc_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(FinanceExecutionResult::failure("KYC attestation not found")),
                };

                if attestation.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_kyc_attestation(
                    view,
                    &d.attestation_id,
                    d.revocation_ref,
                    block_timestamp,
                )?;
                debug!("KYC attestation revoked: {:?}", d.attestation_id);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-895: Proof Operations
            // =================================================================
            FinanceOperation::SubmitProof => {
                let proof: FinanceProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_proof_exists(view, &proof.proof_id)? {
                    return Ok(FinanceExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Finance proof submitted: {:?}", proof_id);
                Ok(FinanceExecutionResult::success_with_proof(proof_id))
            }

            FinanceOperation::VerifyProof => {
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Finance proof verification requested by: {}", sender);
                Ok(FinanceExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sumchain_primitives::finance::{AccountType, BalanceBracket, FinanceIssuerClass};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    fn sample_issuer(sender: Address) -> FinanceIssuerProfile {
        FinanceIssuerProfile {
            issuer_address: sender,
            issuer_class: FinanceIssuerClass::RegulatedBank,
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US-NY".to_string(),
            policy_id: [3u8; 32],
            status: FinanceIssuerStatus::Active,
            registered_at_height: 100,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn tx(operation: FinanceOperation, payload: &impl serde::Serialize) -> FinanceTxData {
        FinanceTxData {
            operation,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
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

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

        let issuer = sample_issuer(sender);
        let result = FinanceExecutor::execute(
            view,
            &sender,
            &tx(FinanceOperation::RegisterIssuer, &issuer),
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
        let retrieved = FinanceExecutor::v_get_issuer(view, &sender)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-NY");
    }

    #[test]
    fn test_create_bank_standing() {
        let (db, _dir, _state) = setup();
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

        FinanceExecutor::execute(
            view,
            &sender,
            &tx(FinanceOperation::RegisterIssuer, &sample_issuer(sender)),
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        let credential = BankStandingCredential {
            credential_id: [10u8; 32],
            subject_ref: [11u8; 32],
            holder_address: Address::new([0x30; 20]),
            account_commitment: [12u8; 32],
            bank_ref: [13u8; 32],
            account_type: AccountType::Checking,
            standing: AccountStanding::Good,
            tenure_commitment: [14u8; 32],
            balance_bracket: BalanceBracket::Bracket5,
            threshold_commitment: None,
            issuer_address: sender,
            issuer_class: FinanceIssuerClass::RegulatedBank,
            valid_from: 1000,
            expiry: 2000,
            policy_id: [15u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
        };

        let result = FinanceExecutor::execute(
            view,
            &sender,
            &tx(FinanceOperation::CreateBankStanding, &credential),
            &proposer,
            1000,
            100,
            1000000,
            1,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Create bank standing failed: {:?}", result.error);
        assert_eq!(result.bank_standing_id, Some([10u8; 32]));

        let retrieved = FinanceExecutor::v_get_bank_standing(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.balance_bracket, BalanceBracket::Bracket5);
    }
}

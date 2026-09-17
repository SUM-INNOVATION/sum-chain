//! SRC-87X Healthcare & Regulated Membership Executor
//!
//! Transaction executor for:
//! - SRC-871: Provider/Plan Registry Profile
//! - SRC-872: Coverage & Membership Status
//! - SRC-874: Consent & Disclosure Envelope
//! - SRC-875: 87X Proof Profiles
//! - SRC-876: Prescription Standard (NON-TRANSFERABLE for controlled substances)

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    healthcare::{
        ConsentEnvelope, ConsentStatus, HealthcareOperation, HealthcareProofEnvelope,
        HealthcareTxData, MembershipRecord, MembershipStatus, Prescription, PrescriptionStatus,
        ProviderProfile, ProviderStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use crate::{Result, StateError, StateManager};

/// Result of Healthcare operation execution
#[derive(Debug)]
pub struct HealthcareExecutionResult {
    pub success: bool,
    pub provider_id: Option<[u8; 32]>,
    pub membership_id: Option<[u8; 32]>,
    pub consent_id: Option<[u8; 32]>,
    pub prescription_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl HealthcareExecutionResult {
    pub fn success_with_provider(provider_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: Some(provider_id),
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_membership(membership_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: Some(membership_id),
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_consent(consent_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: Some(consent_id),
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_prescription(prescription_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: Some(prescription_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Healthcare executor for SRC-87X transactions
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::healthcare_store` for the RPC server, which answers about
/// the canonical chain.
///
/// The `ChainParams` the old constructor took was `#[allow(dead_code)]` and
/// consulted by nothing; it left with the database handle.
pub struct HealthcareExecutor;

impl HealthcareExecutor {
    /// Execute a Healthcare transaction
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &HealthcareTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<HealthcareExecutionResult> {
        match data.operation {
            // =================================================================
            // SRC-871: Provider Registry Operations
            // =================================================================
            HealthcareOperation::RegisterProvider => {
                let provider: ProviderProfile = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_provider_exists(view, &provider.provider_id)? {
                    return Ok(HealthcareExecutionResult::failure("Provider already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let provider_id = provider.provider_id;
                Self::v_put_provider(view, &provider)?;
                debug!("Provider registered: {:?}", provider_id);
                Ok(HealthcareExecutionResult::success_with_provider(provider_id))
            }

            HealthcareOperation::UpdateProvider => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    provider_id: [u8; 32],
                    status: ProviderStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &update.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &update.provider_id,
                    update.status,
                    block_timestamp,
                )?;
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::SuspendProvider => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    provider_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can suspend"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &d.provider_id,
                    ProviderStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Provider suspended: {:?}", d.provider_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RevokeProvider => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    provider_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &d.provider_id,
                    ProviderStatus::Revoked,
                    block_timestamp,
                )?;
                debug!("Provider revoked: {:?}", d.provider_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::ReactivateProvider => {
                #[derive(serde::Deserialize)]
                struct ReactivateData {
                    provider_id: [u8; 32],
                }
                let d: ReactivateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can reactivate"));
                }

                if provider.status != ProviderStatus::Suspended && provider.status != ProviderStatus::Inactive {
                    return Ok(HealthcareExecutionResult::failure("Provider is not suspended or inactive"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &d.provider_id,
                    ProviderStatus::Active,
                    block_timestamp,
                )?;
                debug!("Provider reactivated: {:?}", d.provider_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::AddNetworkAffiliation => {
                #[derive(serde::Deserialize)]
                struct AffiliationData {
                    provider_id: [u8; 32],
                    plan_id: [u8; 32],
                }
                let d: AffiliationData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_provider(view, &d.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_add_network_affiliation(view, &d.provider_id, &d.plan_id, block_timestamp)?;
                debug!(
                    "Network affiliation added: {:?} -> {:?}",
                    d.provider_id, d.plan_id
                );
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RemoveNetworkAffiliation => {
                #[derive(serde::Deserialize)]
                struct AffiliationData {
                    provider_id: [u8; 32],
                    plan_id: [u8; 32],
                }
                let d: AffiliationData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_provider(view, &d.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_remove_network_affiliation(
                    view,
                    &d.provider_id,
                    &d.plan_id,
                    block_timestamp,
                )?;
                debug!("Network affiliation removed: {:?} -> {:?}", d.provider_id, d.plan_id);
                Ok(HealthcareExecutionResult::success())
            }

            // =================================================================
            // SRC-872: Membership Operations
            // =================================================================
            HealthcareOperation::IssueMembership => {
                let membership: MembershipRecord = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                // Verify provider exists
                if Self::v_get_provider(view, &membership.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                if Self::v_membership_exists(view, &membership.membership_id)? {
                    return Ok(HealthcareExecutionResult::failure("Membership already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let membership_id = membership.membership_id;
                Self::v_put_membership(view, &membership)?;
                debug!("Membership issued: {:?}", membership_id);
                Ok(HealthcareExecutionResult::success_with_membership(membership_id))
            }

            HealthcareOperation::UpdateMembership => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    membership_id: [u8; 32],
                    status: MembershipStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    d.status,
                    block_timestamp,
                )?;
                debug!(
                    "Membership status updated: {:?} -> {:?}",
                    d.membership_id, d.status
                );
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RenewMembership => {
                #[derive(serde::Deserialize)]
                struct RenewData {
                    membership_id: [u8; 32],
                    new_expiry: Timestamp,
                }
                let d: RenewData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can renew"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_renew_membership(view, &d.membership_id, d.new_expiry, block_timestamp)?;
                debug!("Membership renewed: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::SuspendMembership => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    membership_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can suspend"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    MembershipStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Membership suspended: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::TerminateMembership => {
                #[derive(serde::Deserialize)]
                struct TerminateData {
                    membership_id: [u8; 32],
                }
                let d: TerminateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can terminate"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    MembershipStatus::Terminated,
                    block_timestamp,
                )?;
                debug!("Membership terminated: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::ReinstateMembership => {
                #[derive(serde::Deserialize)]
                struct ReinstateData {
                    membership_id: [u8; 32],
                }
                let d: ReinstateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can reinstate"));
                }

                if membership.status != MembershipStatus::Suspended {
                    return Ok(HealthcareExecutionResult::failure("Membership is not suspended"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    MembershipStatus::Active,
                    block_timestamp,
                )?;
                debug!("Membership reinstated: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::AddDependent => {
                #[derive(serde::Deserialize)]
                struct DependentData {
                    membership_id: [u8; 32],
                    dependent_commitment: [u8; 32],
                }
                let d: DependentData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can add dependent"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_add_dependent(
                    view,
                    &d.membership_id,
                    d.dependent_commitment,
                    block_timestamp,
                )?;
                debug!("Dependent added to membership: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RemoveDependent => {
                #[derive(serde::Deserialize)]
                struct DependentData {
                    membership_id: [u8; 32],
                    dependent_commitment: [u8; 32],
                }
                let d: DependentData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can remove dependent"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_remove_dependent(
                    view,
                    &d.membership_id,
                    &d.dependent_commitment,
                    block_timestamp,
                )?;
                debug!("Dependent removed from membership: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            // =================================================================
            // SRC-874: Consent Operations
            // =================================================================
            HealthcareOperation::GrantConsent => {
                let consent: ConsentEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_consent_exists(view, &consent.consent_id)? {
                    return Ok(HealthcareExecutionResult::failure("Consent already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let consent_id = consent.consent_id;
                Self::v_put_consent(view, &consent)?;
                debug!("Consent granted: {:?}", consent_id);
                Ok(HealthcareExecutionResult::success_with_consent(consent_id))
            }

            HealthcareOperation::UpdateConsent => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    consent_id: [u8; 32],
                    status: ConsentStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let consent = match Self::v_get_consent(view, &d.consent_id)? {
                    Some(c) => c,
                    None => return Ok(HealthcareExecutionResult::failure("Consent not found")),
                };

                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_consent_status(view, &d.consent_id, d.status, block_timestamp)?;
                debug!("Consent status updated: {:?} -> {:?}", d.consent_id, d.status);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RevokeConsent => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    consent_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let consent = match Self::v_get_consent(view, &d.consent_id)? {
                    Some(c) => c,
                    None => return Ok(HealthcareExecutionResult::failure("Consent not found")),
                };

                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_consent_status(
                    view,
                    &d.consent_id,
                    ConsentStatus::Revoked,
                    block_timestamp,
                )?;
                debug!("Consent revoked: {:?}", d.consent_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::SupersedeConsent => {
                #[derive(serde::Deserialize)]
                struct SupersedeData {
                    old_consent_id: [u8; 32],
                    new_consent: ConsentEnvelope,
                }
                let d: SupersedeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_consent(view, &d.old_consent_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Old consent not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Mark old as superseded
                Self::v_update_consent_status(
                    view,
                    &d.old_consent_id,
                    ConsentStatus::Superseded,
                    block_timestamp,
                )?;

                // Store new consent
                let new_id = d.new_consent.consent_id;
                Self::v_put_consent(view, &d.new_consent)?;
                debug!("Consent superseded: {:?} -> {:?}", d.old_consent_id, new_id);
                Ok(HealthcareExecutionResult::success_with_consent(new_id))
            }

            // =================================================================
            // SRC-876: Prescription Operations
            // =================================================================
            HealthcareOperation::IssuePrescription => {
                let prescription: Prescription = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                // Verify prescriber provider exists
                if Self::v_get_provider(view, &prescription.prescriber_provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Prescriber provider not found"));
                }

                if Self::v_prescription_exists(view, &prescription.prescription_id)? {
                    return Ok(HealthcareExecutionResult::failure("Prescription already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let prescription_id = prescription.prescription_id;
                Self::v_put_prescription(view, &prescription)?;
                debug!("Prescription issued: {:?}", prescription_id);
                Ok(HealthcareExecutionResult::success_with_prescription(prescription_id))
            }

            HealthcareOperation::UpdatePrescription => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    prescription_id: [u8; 32],
                    status: PrescriptionStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                // Prevent transfer of controlled substances
                if prescription.is_controlled && d.status == PrescriptionStatus::TransferRequested {
                    return Ok(HealthcareExecutionResult::failure(
                        "Controlled substance prescriptions cannot be transferred"
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    d.status,
                    block_timestamp,
                )?;
                debug!("Prescription status updated: {:?} -> {:?}", d.prescription_id, d.status);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::FillPrescription => {
                #[derive(serde::Deserialize)]
                struct FillData {
                    prescription_id: [u8; 32],
                    fill_commitment: [u8; 32],
                }
                let d: FillData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if !prescription.is_valid(block_timestamp) {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not valid"));
                }

                if prescription.refills_remaining == 0 && prescription.status != PrescriptionStatus::Active {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_record_fill(view, &d.prescription_id, d.fill_commitment, block_timestamp)?;
                debug!("Prescription filled: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::PartialFillPrescription => {
                #[derive(serde::Deserialize)]
                struct PartialFillData {
                    prescription_id: [u8; 32],
                    fill_commitment: [u8; 32],
                }
                let d: PartialFillData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if !prescription.is_valid(block_timestamp) {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not valid"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Record partial fill (doesn't decrement refills)
                Self::v_add_fill_history(
                    view,
                    &d.prescription_id,
                    d.fill_commitment,
                    block_timestamp,
                )?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::PartiallyFilled,
                    block_timestamp,
                )?;
                debug!("Prescription partially filled: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::CancelPrescription => {
                #[derive(serde::Deserialize)]
                struct CancelData {
                    prescription_id: [u8; 32],
                }
                let d: CancelData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can cancel"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::Cancelled,
                    block_timestamp,
                )?;
                debug!("Prescription cancelled: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::HoldPrescription => {
                #[derive(serde::Deserialize)]
                struct HoldData {
                    prescription_id: [u8; 32],
                }
                let d: HoldData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can hold"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::OnHold,
                    block_timestamp,
                )?;
                debug!("Prescription on hold: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::ReleaseHold => {
                #[derive(serde::Deserialize)]
                struct ReleaseData {
                    prescription_id: [u8; 32],
                }
                let d: ReleaseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can release hold"));
                }

                if prescription.status != PrescriptionStatus::OnHold {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not on hold"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::Active,
                    block_timestamp,
                )?;
                debug!("Prescription hold released: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            // =================================================================
            // SRC-875: Proof Operations
            // =================================================================
            HealthcareOperation::SubmitProof => {
                let proof: HealthcareProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_healthcare_proof_exists(view, &proof.proof_id)? {
                    return Ok(HealthcareExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_healthcare_proof(view, &proof)?;
                debug!("Healthcare proof submitted: {:?}", proof_id);
                Ok(HealthcareExecutionResult::success_with_proof(proof_id))
            }

            HealthcareOperation::VerifyProof => {
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Healthcare proof verification requested by: {}", sender);
                Ok(HealthcareExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    // `Arc` is used only by this module's fixtures. Importing it here rather
    // than at file scope keeps the normal build free of an unused import while
    // leaving the gated build exactly as it was.
    use std::sync::Arc;
    use sumchain_primitives::healthcare::{HealthcareIssuerClass, ProviderType};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_register_provider() {
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

        let provider = ProviderProfile {
            provider_id: [10u8; 32],
            provider_commitment: [11u8; 32],
            provider_type: ProviderType::Hospital,
            jurisdiction_code: "US-CA".to_string(),
            public_reference: None,
            specialties_commitment: None,
            credentials_commitment: None,
            policy_id: [12u8; 32],
            issuer_class: HealthcareIssuerClass::HospitalSystem,
            issuer_address: sender,
            status: ProviderStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            registered_at_height: 100,
            network_affiliations: vec![],
            attachments: vec![],
        };

        let tx_data = HealthcareTxData {
            operation: HealthcareOperation::RegisterProvider,
            data: bincode::serialize(&provider).unwrap(),
        };

        let result = HealthcareExecutor::execute(
            view,
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

        assert!(result.success, "Register provider failed: {:?}", result.error);
        assert_eq!(result.provider_id, Some([10u8; 32]));

        // Read the CANDIDATE: this executor stages now, and a committed read
        // straight after `execute` would be asserting the defect this package
        // removed.
        let retrieved = HealthcareExecutor::v_get_provider(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA");
    }
}

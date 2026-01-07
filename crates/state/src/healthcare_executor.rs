//! SRC-87X Healthcare & Regulated Membership Executor
//!
//! Transaction executor for:
//! - SRC-871: Provider/Plan Registry Profile
//! - SRC-872: Coverage & Membership Status
//! - SRC-874: Consent & Disclosure Envelope
//! - SRC-875: 87X Proof Profiles
//! - SRC-876: Prescription Standard (NON-TRANSFERABLE for controlled substances)

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    healthcare::{
        ConsentEnvelope, ConsentStatus, HealthcareOperation, HealthcareProofEnvelope,
        HealthcareTxData, MembershipRecord, MembershipStatus, Prescription, PrescriptionStatus,
        ProviderProfile, ProviderStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use sumchain_storage::{Database, HealthcareStore};
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
pub struct HealthcareExecutor {
    db: Arc<Database>,
    #[allow(dead_code)]
    params: ChainParams,
}

impl HealthcareExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Execute a Healthcare transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &HealthcareTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<HealthcareExecutionResult> {
        let store = HealthcareStore::new(&self.db);

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

                if store.providers().exists(&provider.provider_id)? {
                    return Ok(HealthcareExecutionResult::failure("Provider already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let provider_id = provider.provider_id;
                store.providers().put(&provider)?;
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

                let provider = match store.providers().get(&update.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.providers().update_status(&update.provider_id, update.status, block_timestamp)?;
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::SuspendProvider => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    provider_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match store.providers().get(&d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can suspend"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.providers().update_status(&d.provider_id, ProviderStatus::Suspended, block_timestamp)?;
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

                let provider = match store.providers().get(&d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.providers().update_status(&d.provider_id, ProviderStatus::Revoked, block_timestamp)?;
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

                let provider = match store.providers().get(&d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can reactivate"));
                }

                if provider.status != ProviderStatus::Suspended && provider.status != ProviderStatus::Inactive {
                    return Ok(HealthcareExecutionResult::failure("Provider is not suspended or inactive"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.providers().update_status(&d.provider_id, ProviderStatus::Active, block_timestamp)?;
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

                if store.providers().get(&d.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.providers().add_network_affiliation(&d.provider_id, &d.plan_id, block_timestamp)?;
                debug!("Network affiliation added: {:?} -> {:?}", d.provider_id, d.plan_id);
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

                if store.providers().get(&d.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.providers().remove_network_affiliation(&d.provider_id, &d.plan_id, block_timestamp)?;
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
                if store.providers().get(&membership.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                if store.memberships().exists(&membership.membership_id)? {
                    return Ok(HealthcareExecutionResult::failure("Membership already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let membership_id = membership.membership_id;
                store.memberships().put(&membership)?;
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

                let membership = match store.memberships().get(&d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.memberships().update_status(&d.membership_id, d.status, block_timestamp)?;
                debug!("Membership status updated: {:?} -> {:?}", d.membership_id, d.status);
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

                let membership = match store.memberships().get(&d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can renew"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.memberships().renew(&d.membership_id, d.new_expiry, block_timestamp)?;
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

                let membership = match store.memberships().get(&d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can suspend"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.memberships().update_status(&d.membership_id, MembershipStatus::Suspended, block_timestamp)?;
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

                let membership = match store.memberships().get(&d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can terminate"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.memberships().update_status(&d.membership_id, MembershipStatus::Terminated, block_timestamp)?;
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

                let membership = match store.memberships().get(&d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can reinstate"));
                }

                if membership.status != MembershipStatus::Suspended {
                    return Ok(HealthcareExecutionResult::failure("Membership is not suspended"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.memberships().update_status(&d.membership_id, MembershipStatus::Active, block_timestamp)?;
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

                let membership = match store.memberships().get(&d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can add dependent"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.memberships().add_dependent(&d.membership_id, d.dependent_commitment, block_timestamp)?;
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

                let membership = match store.memberships().get(&d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can remove dependent"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.memberships().remove_dependent(&d.membership_id, &d.dependent_commitment, block_timestamp)?;
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

                if store.consents().exists(&consent.consent_id)? {
                    return Ok(HealthcareExecutionResult::failure("Consent already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let consent_id = consent.consent_id;
                store.consents().put(&consent)?;
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

                let consent = match store.consents().get(&d.consent_id)? {
                    Some(c) => c,
                    None => return Ok(HealthcareExecutionResult::failure("Consent not found")),
                };

                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.consents().update_status(&d.consent_id, d.status, block_timestamp)?;
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

                let consent = match store.consents().get(&d.consent_id)? {
                    Some(c) => c,
                    None => return Ok(HealthcareExecutionResult::failure("Consent not found")),
                };

                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.consents().update_status(&d.consent_id, ConsentStatus::Revoked, block_timestamp)?;
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

                if store.consents().get(&d.old_consent_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Old consent not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;

                // Mark old as superseded
                store.consents().update_status(&d.old_consent_id, ConsentStatus::Superseded, block_timestamp)?;

                // Store new consent
                let new_id = d.new_consent.consent_id;
                store.consents().put(&d.new_consent)?;
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
                if store.providers().get(&prescription.prescriber_provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Prescriber provider not found"));
                }

                if store.prescriptions().exists(&prescription.prescription_id)? {
                    return Ok(HealthcareExecutionResult::failure("Prescription already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let prescription_id = prescription.prescription_id;
                store.prescriptions().put(&prescription)?;
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

                let prescription = match store.prescriptions().get(&d.prescription_id)? {
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

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.prescriptions().update_status(&d.prescription_id, d.status, block_timestamp)?;
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

                let prescription = match store.prescriptions().get(&d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if !prescription.is_valid(block_timestamp) {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not valid"));
                }

                if prescription.refills_remaining == 0 && prescription.status != PrescriptionStatus::Active {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.prescriptions().record_fill(&d.prescription_id, d.fill_commitment, block_timestamp)?;
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

                let prescription = match store.prescriptions().get(&d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if !prescription.is_valid(block_timestamp) {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not valid"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;

                // Record partial fill (doesn't decrement refills)
                store.prescriptions().add_fill_history(&d.prescription_id, d.fill_commitment, block_timestamp)?;
                store.prescriptions().update_status(&d.prescription_id, PrescriptionStatus::PartiallyFilled, block_timestamp)?;
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

                let prescription = match store.prescriptions().get(&d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can cancel"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.prescriptions().update_status(&d.prescription_id, PrescriptionStatus::Cancelled, block_timestamp)?;
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

                let prescription = match store.prescriptions().get(&d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can hold"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.prescriptions().update_status(&d.prescription_id, PrescriptionStatus::OnHold, block_timestamp)?;
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

                let prescription = match store.prescriptions().get(&d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can release hold"));
                }

                if prescription.status != PrescriptionStatus::OnHold {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not on hold"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.prescriptions().update_status(&d.prescription_id, PrescriptionStatus::Active, block_timestamp)?;
                debug!("Prescription hold released: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            // =================================================================
            // SRC-875: Proof Operations
            // =================================================================
            HealthcareOperation::SubmitProof => {
                let proof: HealthcareProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.proofs().exists(&proof.proof_id)? {
                    return Ok(HealthcareExecutionResult::failure("Proof already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let proof_id = proof.proof_id;
                store.proofs().put(&proof)?;
                debug!("Healthcare proof submitted: {:?}", proof_id);
                Ok(HealthcareExecutionResult::success_with_proof(proof_id))
            }

            HealthcareOperation::VerifyProof => {
                // Verification is read-only - just record the request
                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                debug!("Healthcare proof verification requested by: {}", sender);
                Ok(HealthcareExecutionResult::success())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_healthcare_executor_creation() {
        let (db, _dir, _state) = setup();
        let _executor = HealthcareExecutor::new(db, ChainParams::default());
    }

    #[test]
    fn test_register_provider() {
        let (db, _dir, state) = setup();
        let executor = HealthcareExecutor::new(db.clone(), ChainParams::default());

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        state.credit(&sender, 1_000_000_000_000).unwrap();

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

        let result = executor.execute(
            &sender, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default(),
        ).unwrap();

        assert!(result.success, "Register provider failed: {:?}", result.error);
        assert_eq!(result.provider_id, Some([10u8; 32]));

        // Verify storage
        let store = HealthcareStore::new(&db);
        let retrieved = store.providers().get(&[10u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA");
    }
}

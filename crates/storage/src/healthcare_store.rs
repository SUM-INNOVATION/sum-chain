//! SRC-87X Healthcare & Membership Storage
//!
//! Storage layer for:
//! - SRC-871: Provider/Plan Registry
//! - SRC-872: Coverage & Membership Status
//! - SRC-874: Consent & Disclosure Envelopes
//! - SRC-875: Healthcare Proofs
//! - SRC-876: Prescriptions (NON-TRANSFERABLE)

use sumchain_primitives::{
    healthcare::{
        ConsentEnvelope, ConsentStatus, HealthcareEvent, HealthcareProofEnvelope, MembershipRecord,
        MembershipStatus, Prescription, PrescriptionStatus, ProviderProfile, ProviderStatus,
    },
    BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// Type aliases for clarity
pub type ProviderId = [u8; 32];
pub type MembershipId = [u8; 32];
pub type ConsentId = [u8; 32];
pub type PrescriptionId = [u8; 32];
pub type ProofId = [u8; 32];

// =============================================================================
// Provider Profile Storage (SRC-871)
// =============================================================================

/// Storage for Provider Profiles (SRC-871)
pub struct ProviderStore<'a> {
    db: &'a Database,
}

impl<'a> ProviderStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a provider profile
    pub fn put(&self, provider: &ProviderProfile) -> Result<()> {
        let bytes = bincode::serialize(provider)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::HEALTHCARE_PROVIDERS, &provider.provider_id, &bytes)?;

        // Update network affiliations index
        for plan_id in &provider.network_affiliations {
            self.add_to_network_index(&provider.provider_id, plan_id)?;
        }

        Ok(())
    }

    /// Get a provider by ID
    pub fn get(&self, provider_id: &ProviderId) -> Result<Option<ProviderProfile>> {
        match self.db.get(cf::HEALTHCARE_PROVIDERS, provider_id)? {
            Some(bytes) => {
                let provider: ProviderProfile = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(provider))
            }
            None => Ok(None),
        }
    }

    /// Check if provider exists
    pub fn exists(&self, provider_id: &ProviderId) -> Result<bool> {
        self.db.contains(cf::HEALTHCARE_PROVIDERS, provider_id)
    }

    /// Update provider status
    pub fn update_status(
        &self,
        provider_id: &ProviderId,
        status: ProviderStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(provider_id)? {
            Some(mut provider) => {
                provider.status = status;
                provider.updated_at = timestamp;
                let bytes = bincode::serialize(&provider)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_PROVIDERS, provider_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Provider not found: {:?}",
                provider_id
            ))),
        }
    }

    /// Add network affiliation
    pub fn add_network_affiliation(
        &self,
        provider_id: &ProviderId,
        plan_id: &ProviderId,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(provider_id)? {
            Some(mut provider) => {
                if !provider.network_affiliations.contains(plan_id) {
                    provider.network_affiliations.push(*plan_id);
                    provider.updated_at = timestamp;
                    let bytes = bincode::serialize(&provider)
                        .map_err(|e| StorageError::Serialization(e.to_string()))?;
                    self.db.put(cf::HEALTHCARE_PROVIDERS, provider_id, &bytes)?;
                    self.add_to_network_index(provider_id, plan_id)?;
                }
                Ok(())
            }
            None => Err(StorageError::NotFound(format!(
                "Provider not found: {:?}",
                provider_id
            ))),
        }
    }

    /// Remove network affiliation
    pub fn remove_network_affiliation(
        &self,
        provider_id: &ProviderId,
        plan_id: &ProviderId,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(provider_id)? {
            Some(mut provider) => {
                provider.network_affiliations.retain(|p| p != plan_id);
                provider.updated_at = timestamp;
                let bytes = bincode::serialize(&provider)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_PROVIDERS, provider_id, &bytes)?;
                self.remove_from_network_index(provider_id, plan_id)?;
                Ok(())
            }
            None => Err(StorageError::NotFound(format!(
                "Provider not found: {:?}",
                provider_id
            ))),
        }
    }

    /// Get providers in network
    pub fn get_by_network(&self, plan_id: &ProviderId) -> Result<Vec<ProviderProfile>> {
        let ids = self.get_network_provider_ids(plan_id)?;
        let mut providers = Vec::new();
        for id in ids {
            if let Some(provider) = self.get(&id)? {
                providers.push(provider);
            }
        }
        Ok(providers)
    }

    /// List active providers
    pub fn list_active(&self) -> Result<Vec<ProviderProfile>> {
        let mut providers = Vec::new();
        for (_, value) in self.db.iter(cf::HEALTHCARE_PROVIDERS)? {
            let provider: ProviderProfile = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if provider.status == ProviderStatus::Active {
                providers.push(provider);
            }
        }
        Ok(providers)
    }

    // Index helpers
    fn add_to_network_index(&self, provider_id: &ProviderId, plan_id: &ProviderId) -> Result<()> {
        let mut ids = self.get_network_provider_ids(plan_id)?;
        if !ids.contains(provider_id) {
            ids.push(*provider_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, plan_id, &bytes)?;
        }
        Ok(())
    }

    fn remove_from_network_index(&self, provider_id: &ProviderId, plan_id: &ProviderId) -> Result<()> {
        let mut ids = self.get_network_provider_ids(plan_id)?;
        ids.retain(|id| id != provider_id);
        let bytes = bincode::serialize(&ids)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, plan_id, &bytes)?;
        Ok(())
    }

    fn get_network_provider_ids(&self, plan_id: &ProviderId) -> Result<Vec<ProviderId>> {
        match self.db.get(cf::HEALTHCARE_PROVIDER_NETWORK_INDEX, plan_id)? {
            Some(bytes) => {
                let ids: Vec<ProviderId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Membership Storage (SRC-872)
// =============================================================================

/// Storage for Membership Records (SRC-872)
pub struct MembershipStore<'a> {
    db: &'a Database,
}

impl<'a> MembershipStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a membership record
    pub fn put(&self, membership: &MembershipRecord) -> Result<()> {
        let bytes = bincode::serialize(membership)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::HEALTHCARE_MEMBERSHIPS, &membership.membership_id, &bytes)?;

        // Update member index
        self.add_to_member_index(&membership.member_nullifier, &membership.membership_id)?;

        Ok(())
    }

    /// Get a membership by ID
    pub fn get(&self, membership_id: &MembershipId) -> Result<Option<MembershipRecord>> {
        match self.db.get(cf::HEALTHCARE_MEMBERSHIPS, membership_id)? {
            Some(bytes) => {
                let membership: MembershipRecord = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(membership))
            }
            None => Ok(None),
        }
    }

    /// Check if membership exists
    pub fn exists(&self, membership_id: &MembershipId) -> Result<bool> {
        self.db.contains(cf::HEALTHCARE_MEMBERSHIPS, membership_id)
    }

    /// Update membership status
    pub fn update_status(
        &self,
        membership_id: &MembershipId,
        status: MembershipStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(membership_id)? {
            Some(mut membership) => {
                membership.status = status;
                membership.updated_at = timestamp;
                let bytes = bincode::serialize(&membership)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_MEMBERSHIPS, membership_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Membership not found: {:?}",
                membership_id
            ))),
        }
    }

    /// Renew membership with new expiry date
    pub fn renew(
        &self,
        membership_id: &MembershipId,
        new_expiry: Timestamp,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(membership_id)? {
            Some(mut membership) => {
                membership.expiry = Some(new_expiry);
                membership.status = MembershipStatus::Active;
                membership.updated_at = timestamp;
                let bytes = bincode::serialize(&membership)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_MEMBERSHIPS, membership_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Membership not found: {:?}",
                membership_id
            ))),
        }
    }

    /// Add dependent
    pub fn add_dependent(
        &self,
        membership_id: &MembershipId,
        dependent_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(membership_id)? {
            Some(mut membership) => {
                if !membership.dependents.contains(&dependent_commitment) {
                    membership.dependents.push(dependent_commitment);
                    membership.updated_at = timestamp;
                    let bytes = bincode::serialize(&membership)
                        .map_err(|e| StorageError::Serialization(e.to_string()))?;
                    self.db.put(cf::HEALTHCARE_MEMBERSHIPS, membership_id, &bytes)?;
                }
                Ok(())
            }
            None => Err(StorageError::NotFound(format!(
                "Membership not found: {:?}",
                membership_id
            ))),
        }
    }

    /// Remove dependent
    pub fn remove_dependent(
        &self,
        membership_id: &MembershipId,
        dependent_commitment: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(membership_id)? {
            Some(mut membership) => {
                membership.dependents.retain(|d| d != dependent_commitment);
                membership.updated_at = timestamp;
                let bytes = bincode::serialize(&membership)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_MEMBERSHIPS, membership_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Membership not found: {:?}",
                membership_id
            ))),
        }
    }

    /// Get memberships by member nullifier
    pub fn get_by_member(&self, member_nullifier: &[u8; 32]) -> Result<Vec<MembershipRecord>> {
        let ids = self.get_member_membership_ids(member_nullifier)?;
        let mut memberships = Vec::new();
        for id in ids {
            if let Some(membership) = self.get(&id)? {
                memberships.push(membership);
            }
        }
        Ok(memberships)
    }

    /// Get active memberships by member
    pub fn get_active_by_member(
        &self,
        member_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<MembershipRecord>> {
        let all = self.get_by_member(member_nullifier)?;
        Ok(all.into_iter().filter(|m| m.is_active(current_time)).collect())
    }

    // Index helpers
    fn add_to_member_index(&self, member_nullifier: &[u8; 32], membership_id: &MembershipId) -> Result<()> {
        let mut ids = self.get_member_membership_ids(member_nullifier)?;
        if !ids.contains(membership_id) {
            ids.push(*membership_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::HEALTHCARE_MEMBER_INDEX, member_nullifier, &bytes)?;
        }
        Ok(())
    }

    fn get_member_membership_ids(&self, member_nullifier: &[u8; 32]) -> Result<Vec<MembershipId>> {
        match self.db.get(cf::HEALTHCARE_MEMBER_INDEX, member_nullifier)? {
            Some(bytes) => {
                let ids: Vec<MembershipId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Consent Storage (SRC-874)
// =============================================================================

/// Storage for Consent Envelopes (SRC-874)
pub struct ConsentStore<'a> {
    db: &'a Database,
}

impl<'a> ConsentStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a consent envelope
    pub fn put(&self, consent: &ConsentEnvelope) -> Result<()> {
        let bytes = bincode::serialize(consent)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::HEALTHCARE_CONSENTS, &consent.consent_id, &bytes)?;

        // Update subject consent index
        self.add_to_subject_index(&consent.subject_nullifier, &consent.consent_id)?;

        Ok(())
    }

    /// Get a consent by ID
    pub fn get(&self, consent_id: &ConsentId) -> Result<Option<ConsentEnvelope>> {
        match self.db.get(cf::HEALTHCARE_CONSENTS, consent_id)? {
            Some(bytes) => {
                let consent: ConsentEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(consent))
            }
            None => Ok(None),
        }
    }

    /// Check if consent exists
    pub fn exists(&self, consent_id: &ConsentId) -> Result<bool> {
        self.db.contains(cf::HEALTHCARE_CONSENTS, consent_id)
    }

    /// Update consent status (e.g., revoke)
    pub fn update_status(
        &self,
        consent_id: &ConsentId,
        status: ConsentStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(consent_id)? {
            Some(mut consent) => {
                consent.status = status;
                consent.updated_at = timestamp;
                let bytes = bincode::serialize(&consent)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_CONSENTS, consent_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Consent not found: {:?}",
                consent_id
            ))),
        }
    }

    /// Get consents by subject nullifier
    pub fn get_by_subject(&self, subject_nullifier: &[u8; 32]) -> Result<Vec<ConsentEnvelope>> {
        let ids = self.get_subject_consent_ids(subject_nullifier)?;
        let mut consents = Vec::new();
        for id in ids {
            if let Some(consent) = self.get(&id)? {
                consents.push(consent);
            }
        }
        Ok(consents)
    }

    /// Get valid consents by subject
    pub fn get_valid_by_subject(
        &self,
        subject_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<ConsentEnvelope>> {
        let all = self.get_by_subject(subject_nullifier)?;
        Ok(all.into_iter().filter(|c| c.is_valid(current_time)).collect())
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_nullifier: &[u8; 32], consent_id: &ConsentId) -> Result<()> {
        let mut ids = self.get_subject_consent_ids(subject_nullifier)?;
        if !ids.contains(consent_id) {
            ids.push(*consent_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::HEALTHCARE_SUBJECT_CONSENT_INDEX, subject_nullifier, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_consent_ids(&self, subject_nullifier: &[u8; 32]) -> Result<Vec<ConsentId>> {
        match self.db.get(cf::HEALTHCARE_SUBJECT_CONSENT_INDEX, subject_nullifier)? {
            Some(bytes) => {
                let ids: Vec<ConsentId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Prescription Storage (SRC-876) - NON-TRANSFERABLE for controlled substances
// =============================================================================

/// Storage for Prescriptions (SRC-876)
pub struct PrescriptionStore<'a> {
    db: &'a Database,
}

impl<'a> PrescriptionStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a prescription
    pub fn put(&self, prescription: &Prescription) -> Result<()> {
        let bytes = bincode::serialize(prescription)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::HEALTHCARE_PRESCRIPTIONS, &prescription.prescription_id, &bytes)?;

        // Update patient index
        self.add_to_patient_index(&prescription.patient_nullifier, &prescription.prescription_id)?;

        // Update prescriber index
        self.add_to_prescriber_index(&prescription.prescriber_provider_id, &prescription.prescription_id)?;

        Ok(())
    }

    /// Get a prescription by ID
    pub fn get(&self, prescription_id: &PrescriptionId) -> Result<Option<Prescription>> {
        match self.db.get(cf::HEALTHCARE_PRESCRIPTIONS, prescription_id)? {
            Some(bytes) => {
                let prescription: Prescription = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(prescription))
            }
            None => Ok(None),
        }
    }

    /// Check if prescription exists
    pub fn exists(&self, prescription_id: &PrescriptionId) -> Result<bool> {
        self.db.contains(cf::HEALTHCARE_PRESCRIPTIONS, prescription_id)
    }

    /// Update prescription status
    pub fn update_status(
        &self,
        prescription_id: &PrescriptionId,
        status: PrescriptionStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(prescription_id)? {
            Some(mut prescription) => {
                prescription.status = status;
                prescription.updated_at = timestamp;
                let bytes = bincode::serialize(&prescription)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_PRESCRIPTIONS, prescription_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Prescription not found: {:?}",
                prescription_id
            ))),
        }
    }

    /// Record a fill (decrements refills)
    pub fn record_fill(
        &self,
        prescription_id: &PrescriptionId,
        fill_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(prescription_id)? {
            Some(mut prescription) => {
                if prescription.refills_remaining == 0 && prescription.status != PrescriptionStatus::Active {
                    return Err(StorageError::InvalidData(
                        "No refills remaining".to_string(),
                    ));
                }
                prescription.fill_history.push(fill_commitment);
                if prescription.refills_remaining > 0 {
                    prescription.refills_remaining = prescription.refills_remaining.saturating_sub(1);
                }
                prescription.status = if prescription.refills_remaining == 0 {
                    PrescriptionStatus::Filled
                } else {
                    PrescriptionStatus::PartiallyFilled
                };
                prescription.updated_at = timestamp;
                let bytes = bincode::serialize(&prescription)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_PRESCRIPTIONS, prescription_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Prescription not found: {:?}",
                prescription_id
            ))),
        }
    }

    /// Add to fill history (without decrementing refills, for partial fills)
    pub fn add_fill_history(
        &self,
        prescription_id: &PrescriptionId,
        fill_commitment: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(prescription_id)? {
            Some(mut prescription) => {
                prescription.fill_history.push(fill_commitment);
                prescription.updated_at = timestamp;
                let bytes = bincode::serialize(&prescription)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::HEALTHCARE_PRESCRIPTIONS, prescription_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Prescription not found: {:?}",
                prescription_id
            ))),
        }
    }

    /// Get prescriptions by patient nullifier
    pub fn get_by_patient(&self, patient_nullifier: &[u8; 32]) -> Result<Vec<Prescription>> {
        let ids = self.get_patient_rx_ids(patient_nullifier)?;
        let mut prescriptions = Vec::new();
        for id in ids {
            if let Some(rx) = self.get(&id)? {
                prescriptions.push(rx);
            }
        }
        Ok(prescriptions)
    }

    /// Get valid prescriptions by patient
    pub fn get_valid_by_patient(
        &self,
        patient_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<Prescription>> {
        let all = self.get_by_patient(patient_nullifier)?;
        Ok(all.into_iter().filter(|rx| rx.is_valid(current_time)).collect())
    }

    /// Get prescriptions by prescriber
    pub fn get_by_prescriber(&self, prescriber_id: &ProviderId) -> Result<Vec<Prescription>> {
        let ids = self.get_prescriber_rx_ids(prescriber_id)?;
        let mut prescriptions = Vec::new();
        for id in ids {
            if let Some(rx) = self.get(&id)? {
                prescriptions.push(rx);
            }
        }
        Ok(prescriptions)
    }

    // Index helpers
    fn add_to_patient_index(&self, patient_nullifier: &[u8; 32], prescription_id: &PrescriptionId) -> Result<()> {
        let mut ids = self.get_patient_rx_ids(patient_nullifier)?;
        if !ids.contains(prescription_id) {
            ids.push(*prescription_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::HEALTHCARE_PATIENT_RX_INDEX, patient_nullifier, &bytes)?;
        }
        Ok(())
    }

    fn add_to_prescriber_index(&self, prescriber_id: &ProviderId, prescription_id: &PrescriptionId) -> Result<()> {
        let mut ids = self.get_prescriber_rx_ids(prescriber_id)?;
        if !ids.contains(prescription_id) {
            ids.push(*prescription_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::HEALTHCARE_PRESCRIBER_RX_INDEX, prescriber_id, &bytes)?;
        }
        Ok(())
    }

    fn get_patient_rx_ids(&self, patient_nullifier: &[u8; 32]) -> Result<Vec<PrescriptionId>> {
        match self.db.get(cf::HEALTHCARE_PATIENT_RX_INDEX, patient_nullifier)? {
            Some(bytes) => {
                let ids: Vec<PrescriptionId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    fn get_prescriber_rx_ids(&self, prescriber_id: &ProviderId) -> Result<Vec<PrescriptionId>> {
        match self.db.get(cf::HEALTHCARE_PRESCRIBER_RX_INDEX, prescriber_id)? {
            Some(bytes) => {
                let ids: Vec<PrescriptionId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Healthcare Proof Storage (SRC-875)
// =============================================================================

/// Storage for Healthcare Proofs (SRC-875)
pub struct HealthcareProofStore<'a> {
    db: &'a Database,
}

impl<'a> HealthcareProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a healthcare proof
    pub fn put(&self, proof: &HealthcareProofEnvelope) -> Result<()> {
        let bytes = bincode::serialize(proof)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::HEALTHCARE_PROOFS, &proof.proof_id, &bytes)
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<HealthcareProofEnvelope>> {
        match self.db.get(cf::HEALTHCARE_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: HealthcareProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::HEALTHCARE_PROOFS, proof_id)
    }

    /// Check if proof is valid (not expired)
    pub fn is_valid(&self, proof_id: &ProofId, current_time: Timestamp) -> Result<bool> {
        match self.get(proof_id)? {
            Some(proof) => Ok(current_time < proof.expires_at),
            None => Ok(false),
        }
    }
}

// =============================================================================
// Healthcare Event Storage
// =============================================================================

/// Storage for Healthcare Events
pub struct HealthcareEventStore<'a> {
    db: &'a Database,
}

impl<'a> HealthcareEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a healthcare event
    pub fn put(&self, height: BlockHeight, index: u32, event: &HealthcareEvent) -> Result<()> {
        let key = Self::make_key(height, index);
        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::HEALTHCARE_SYSTEM_EVENTS, &key, &bytes)
    }

    /// Get events by block height
    pub fn get_by_height(&self, height: BlockHeight) -> Result<Vec<HealthcareEvent>> {
        let prefix = height.to_be_bytes();
        let mut events = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::HEALTHCARE_SYSTEM_EVENTS, &prefix)? {
            let event: HealthcareEvent = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }

    fn make_key(height: BlockHeight, index: u32) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&height.to_be_bytes());
        key[8..].copy_from_slice(&index.to_be_bytes());
        key
    }
}

// =============================================================================
// Combined Healthcare Store
// =============================================================================

/// Combined storage interface for all SRC-87X operations
pub struct HealthcareStore<'a> {
    db: &'a Database,
}

impl<'a> HealthcareStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get provider store
    pub fn providers(&self) -> ProviderStore<'_> {
        ProviderStore::new(self.db)
    }

    /// Get membership store
    pub fn memberships(&self) -> MembershipStore<'_> {
        MembershipStore::new(self.db)
    }

    /// Get consent store
    pub fn consents(&self) -> ConsentStore<'_> {
        ConsentStore::new(self.db)
    }

    /// Get prescription store
    pub fn prescriptions(&self) -> PrescriptionStore<'_> {
        PrescriptionStore::new(self.db)
    }

    /// Get proof store
    pub fn proofs(&self) -> HealthcareProofStore<'_> {
        HealthcareProofStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> HealthcareEventStore<'_> {
        HealthcareEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DatabaseConfig;
    use sumchain_primitives::{
        healthcare::{
            ConsentType, CoverageTier, DisclosureScope, HealthcareIssuerClass, MembershipType,
            PrescriptionType, ProviderType,
        },
        agreement::PartyRef,
        Address,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    fn sample_provider() -> ProviderProfile {
        ProviderProfile {
            provider_id: [1u8; 32],
            provider_commitment: [2u8; 32],
            provider_type: ProviderType::Hospital,
            jurisdiction_code: "US-CA".to_string(),
            public_reference: None,
            specialties_commitment: None,
            credentials_commitment: None,
            policy_id: [3u8; 32],
            issuer_class: HealthcareIssuerClass::GovernmentHealthAgency,
            issuer_address: Address::new([4u8; 20]),
            status: ProviderStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            registered_at_height: 100,
            network_affiliations: vec![],
            attachments: vec![],
        }
    }

    fn sample_membership() -> MembershipRecord {
        MembershipRecord {
            membership_id: [5u8; 32],
            provider_id: [1u8; 32],
            membership_type: MembershipType::IndividualHealth,
            membership_commitment: [6u8; 32],
            member_ref: PartyRef::Commitment([7u8; 32]),
            member_nullifier: [8u8; 32],
            coverage_tier: Some(CoverageTier::Individual),
            group_commitment: None,
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: Address::new([9u8; 20]),
            issuer_class: HealthcareIssuerClass::InsuranceCompany,
            policy_id: [10u8; 32],
            revocation_ref: None,
            status: MembershipStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            issued_at_height: 100,
            prior_membership_id: None,
            dependents: vec![],
            attachments: vec![],
        }
    }

    fn sample_consent() -> ConsentEnvelope {
        ConsentEnvelope {
            consent_id: [11u8; 32],
            consent_type: ConsentType::HipaaAuthorization,
            consent_commitment: [12u8; 32],
            subject_ref: PartyRef::Commitment([13u8; 32]),
            subject_nullifier: [14u8; 32],
            recipient_ref: PartyRef::Commitment([15u8; 32]),
            purpose_commitment: [16u8; 32],
            scope: DisclosureScope::TreatmentOnly,
            scope_commitment: None,
            effective_from: 1000,
            expiry: Some(2000),
            issuer_address: Address::new([17u8; 20]),
            issuer_class: HealthcareIssuerClass::MedicalPractice,
            policy_id: [18u8; 32],
            revocation_ref: None,
            status: ConsentStatus::Granted,
            created_at: 1000,
            updated_at: 1000,
            recorded_at_height: 100,
            supersedes: None,
            attachments: vec![],
        }
    }

    fn sample_prescription() -> Prescription {
        Prescription {
            prescription_id: [19u8; 32],
            prescription_type: PrescriptionType::StandardPrescription,
            prescription_commitment: [20u8; 32],
            patient_ref: PartyRef::Commitment([21u8; 32]),
            patient_nullifier: [22u8; 32],
            prescriber_ref: PartyRef::Commitment([23u8; 32]),
            prescriber_provider_id: [1u8; 32],
            pharmacy_ref: None,
            medication_commitment: [24u8; 32],
            quantity_commitment: [25u8; 32],
            days_supply_commitment: None,
            refills_authorized: 3,
            refills_remaining: 3,
            is_controlled: false,
            date_written: 900,
            effective_from: Some(1000),
            expiry: 2000,
            issuer_address: Address::new([26u8; 20]),
            issuer_class: HealthcareIssuerClass::MedicalPractice,
            policy_id: [27u8; 32],
            revocation_ref: None,
            status: PrescriptionStatus::Active,
            created_at: 900,
            updated_at: 900,
            recorded_at_height: 100,
            supersedes: None,
            fill_history: vec![],
            attachments: vec![],
        }
    }

    #[test]
    fn test_provider_store() {
        let (db, _dir) = temp_db();
        let store = ProviderStore::new(&db);

        let provider = sample_provider();
        store.put(&provider).unwrap();

        let retrieved = store.get(&provider.provider_id).unwrap().unwrap();
        assert_eq!(retrieved.provider_id, provider.provider_id);
        assert_eq!(retrieved.jurisdiction_code, "US-CA");

        // Test status update
        store.update_status(&provider.provider_id, ProviderStatus::Suspended, 1100).unwrap();
        let updated = store.get(&provider.provider_id).unwrap().unwrap();
        assert_eq!(updated.status, ProviderStatus::Suspended);
    }

    #[test]
    fn test_membership_store() {
        let (db, _dir) = temp_db();
        let store = MembershipStore::new(&db);

        let membership = sample_membership();
        store.put(&membership).unwrap();

        let retrieved = store.get(&membership.membership_id).unwrap().unwrap();
        assert_eq!(retrieved.membership_id, membership.membership_id);

        // Test member index
        let by_member = store.get_by_member(&membership.member_nullifier).unwrap();
        assert_eq!(by_member.len(), 1);

        // Test active filter
        let active = store.get_active_by_member(&membership.member_nullifier, 1500).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_consent_store() {
        let (db, _dir) = temp_db();
        let store = ConsentStore::new(&db);

        let consent = sample_consent();
        store.put(&consent).unwrap();

        let retrieved = store.get(&consent.consent_id).unwrap().unwrap();
        assert_eq!(retrieved.consent_id, consent.consent_id);

        // Test subject index
        let by_subject = store.get_by_subject(&consent.subject_nullifier).unwrap();
        assert_eq!(by_subject.len(), 1);

        // Test valid filter
        let valid = store.get_valid_by_subject(&consent.subject_nullifier, 1500).unwrap();
        assert_eq!(valid.len(), 1);

        // Revoke and check
        store.update_status(&consent.consent_id, ConsentStatus::Revoked, 1600).unwrap();
        let valid_after_revoke = store.get_valid_by_subject(&consent.subject_nullifier, 1700).unwrap();
        assert_eq!(valid_after_revoke.len(), 0);
    }

    #[test]
    fn test_prescription_store() {
        let (db, _dir) = temp_db();
        let store = PrescriptionStore::new(&db);

        let rx = sample_prescription();
        store.put(&rx).unwrap();

        let retrieved = store.get(&rx.prescription_id).unwrap().unwrap();
        assert_eq!(retrieved.prescription_id, rx.prescription_id);
        assert_eq!(retrieved.refills_remaining, 3);

        // Test fill
        store.record_fill(&rx.prescription_id, [50u8; 32], 1100).unwrap();
        let after_fill = store.get(&rx.prescription_id).unwrap().unwrap();
        assert_eq!(after_fill.refills_remaining, 2);
        assert_eq!(after_fill.fill_history.len(), 1);

        // Test patient index
        let by_patient = store.get_by_patient(&rx.patient_nullifier).unwrap();
        assert_eq!(by_patient.len(), 1);

        // Test prescriber index
        let by_prescriber = store.get_by_prescriber(&rx.prescriber_provider_id).unwrap();
        assert_eq!(by_prescriber.len(), 1);
    }

    #[test]
    fn test_healthcare_store_combined() {
        let (db, _dir) = temp_db();
        let store = HealthcareStore::new(&db);

        // Store all types
        let provider = sample_provider();
        store.providers().put(&provider).unwrap();

        let membership = sample_membership();
        store.memberships().put(&membership).unwrap();

        let consent = sample_consent();
        store.consents().put(&consent).unwrap();

        let rx = sample_prescription();
        store.prescriptions().put(&rx).unwrap();

        // Verify all stored
        assert!(store.providers().exists(&provider.provider_id).unwrap());
        assert!(store.memberships().exists(&membership.membership_id).unwrap());
        assert!(store.consents().exists(&consent.consent_id).unwrap());
        assert!(store.prescriptions().exists(&rx.prescription_id).unwrap());
    }
}

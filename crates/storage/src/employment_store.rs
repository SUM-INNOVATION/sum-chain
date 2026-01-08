//! SRC-88X Employment & HR Storage
//!
//! Storage layer for:
//! - SRC-881: Employer & Payroll Issuer Profile
//! - SRC-882: Employment Relationship Credential
//! - SRC-883: Income / Payroll Attestation
//! - SRC-885: 88X Proof Profiles

use sumchain_primitives::{
    employment::{
        EmploymentCredential, EmploymentEvent, EmploymentIssuerProfile, EmploymentProofEnvelope,
        EmploymentStatus, IncomeAttestation, IssuerStatus,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// Type aliases for clarity
pub type EmploymentId = [u8; 32];
pub type IncomeAttestationId = [u8; 32];
pub type ProofId = [u8; 32];
pub type SubjectRef = [u8; 32];
pub type EmployerRef = [u8; 32];

// =============================================================================
// Issuer Profile Storage (SRC-881)
// =============================================================================

/// Storage for Employment Issuer Profiles (SRC-881)
pub struct EmploymentIssuerStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentIssuerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an issuer profile
    pub fn put(&self, issuer: &EmploymentIssuerProfile) -> Result<()> {
        let bytes = bincode::serialize(issuer)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EMPLOYMENT_ISSUERS, issuer.issuer_address.as_bytes(), &bytes)
    }

    /// Get an issuer by address
    pub fn get(&self, issuer_address: &Address) -> Result<Option<EmploymentIssuerProfile>> {
        match self.db.get(cf::EMPLOYMENT_ISSUERS, issuer_address.as_bytes())? {
            Some(bytes) => {
                let issuer: EmploymentIssuerProfile = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(issuer))
            }
            None => Ok(None),
        }
    }

    /// Check if issuer exists
    pub fn exists(&self, issuer_address: &Address) -> Result<bool> {
        self.db.contains(cf::EMPLOYMENT_ISSUERS, issuer_address.as_bytes())
    }

    /// Update issuer status
    pub fn update_status(
        &self,
        issuer_address: &Address,
        status: IssuerStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(issuer_address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                let bytes = bincode::serialize(&issuer)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::EMPLOYMENT_ISSUERS, issuer_address.as_bytes(), &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Issuer not found: {:?}",
                issuer_address
            ))),
        }
    }

    /// List all active issuers
    pub fn list_active(&self) -> Result<Vec<EmploymentIssuerProfile>> {
        let mut issuers = Vec::new();
        for (_, value) in self.db.iter(cf::EMPLOYMENT_ISSUERS)? {
            let issuer: EmploymentIssuerProfile = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if issuer.status.is_active() {
                issuers.push(issuer);
            }
        }
        Ok(issuers)
    }
}

// =============================================================================
// Employment Credential Storage (SRC-882)
// =============================================================================

/// Storage for Employment Credentials (SRC-882)
pub struct EmploymentCredentialStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentCredentialStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an employment credential
    pub fn put(&self, credential: &EmploymentCredential) -> Result<()> {
        let bytes = bincode::serialize(credential)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EMPLOYMENT_CREDENTIALS, &credential.employment_id, &bytes)?;

        // Update indexes
        self.add_to_employee_index(&credential.employee_ref, &credential.employment_id)?;
        self.add_to_employer_index(&credential.employer_ref, &credential.employment_id)?;

        Ok(())
    }

    /// Get a credential by ID
    pub fn get(&self, employment_id: &EmploymentId) -> Result<Option<EmploymentCredential>> {
        match self.db.get(cf::EMPLOYMENT_CREDENTIALS, employment_id)? {
            Some(bytes) => {
                let credential: EmploymentCredential = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(credential))
            }
            None => Ok(None),
        }
    }

    /// Check if credential exists
    pub fn exists(&self, employment_id: &EmploymentId) -> Result<bool> {
        self.db.contains(cf::EMPLOYMENT_CREDENTIALS, employment_id)
    }

    /// Update employment status
    pub fn update_status(
        &self,
        employment_id: &EmploymentId,
        status: EmploymentStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(employment_id)? {
            Some(mut credential) => {
                credential.status = status;
                credential.updated_at = timestamp;
                let bytes = bincode::serialize(&credential)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::EMPLOYMENT_CREDENTIALS, employment_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Employment credential not found: {:?}",
                employment_id
            ))),
        }
    }

    /// Revoke employment credential
    pub fn revoke(
        &self,
        employment_id: &EmploymentId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(employment_id)? {
            Some(mut credential) => {
                credential.status = EmploymentStatus::Ended;
                credential.revocation_ref = Some(revocation_ref);
                credential.updated_at = timestamp;
                let bytes = bincode::serialize(&credential)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::EMPLOYMENT_CREDENTIALS, employment_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Employment credential not found: {:?}",
                employment_id
            ))),
        }
    }

    /// Get credentials by employee
    pub fn get_by_employee(&self, employee_ref: &SubjectRef) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employee_credential_ids(employee_ref)?;
        let mut credentials = Vec::new();
        for id in ids {
            if let Some(credential) = self.get(&id)? {
                credentials.push(credential);
            }
        }
        Ok(credentials)
    }

    /// Get active credentials by employee
    pub fn get_active_by_employee(
        &self,
        employee_ref: &SubjectRef,
        current_time: Timestamp,
    ) -> Result<Vec<EmploymentCredential>> {
        let all = self.get_by_employee(employee_ref)?;
        Ok(all.into_iter().filter(|c| c.is_valid(current_time)).collect())
    }

    /// Get credentials by employer
    pub fn get_by_employer(&self, employer_ref: &EmployerRef) -> Result<Vec<EmploymentCredential>> {
        let ids = self.get_employer_credential_ids(employer_ref)?;
        let mut credentials = Vec::new();
        for id in ids {
            if let Some(credential) = self.get(&id)? {
                credentials.push(credential);
            }
        }
        Ok(credentials)
    }

    // Index helpers
    fn add_to_employee_index(&self, employee_ref: &SubjectRef, employment_id: &EmploymentId) -> Result<()> {
        let mut ids = self.get_employee_credential_ids(employee_ref)?;
        if !ids.contains(employment_id) {
            ids.push(*employment_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::EMPLOYMENT_EMPLOYEE_INDEX, employee_ref, &bytes)?;
        }
        Ok(())
    }

    fn add_to_employer_index(&self, employer_ref: &EmployerRef, employment_id: &EmploymentId) -> Result<()> {
        let mut ids = self.get_employer_credential_ids(employer_ref)?;
        if !ids.contains(employment_id) {
            ids.push(*employment_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::EMPLOYMENT_EMPLOYER_INDEX, employer_ref, &bytes)?;
        }
        Ok(())
    }

    fn get_employee_credential_ids(&self, employee_ref: &SubjectRef) -> Result<Vec<EmploymentId>> {
        match self.db.get(cf::EMPLOYMENT_EMPLOYEE_INDEX, employee_ref)? {
            Some(bytes) => {
                let ids: Vec<EmploymentId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    fn get_employer_credential_ids(&self, employer_ref: &EmployerRef) -> Result<Vec<EmploymentId>> {
        match self.db.get(cf::EMPLOYMENT_EMPLOYER_INDEX, employer_ref)? {
            Some(bytes) => {
                let ids: Vec<EmploymentId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Income Attestation Storage (SRC-883)
// =============================================================================

/// Storage for Income Attestations (SRC-883)
pub struct IncomeAttestationStore<'a> {
    db: &'a Database,
}

impl<'a> IncomeAttestationStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an income attestation
    pub fn put(&self, attestation: &IncomeAttestation) -> Result<()> {
        let bytes = bincode::serialize(attestation)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EMPLOYMENT_INCOME_ATTESTATIONS, &attestation.attestation_id, &bytes)?;

        // Update subject index
        self.add_to_subject_index(&attestation.subject_ref, &attestation.attestation_id)?;

        Ok(())
    }

    /// Get an attestation by ID
    pub fn get(&self, attestation_id: &IncomeAttestationId) -> Result<Option<IncomeAttestation>> {
        match self.db.get(cf::EMPLOYMENT_INCOME_ATTESTATIONS, attestation_id)? {
            Some(bytes) => {
                let attestation: IncomeAttestation = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(attestation))
            }
            None => Ok(None),
        }
    }

    /// Check if attestation exists
    pub fn exists(&self, attestation_id: &IncomeAttestationId) -> Result<bool> {
        self.db.contains(cf::EMPLOYMENT_INCOME_ATTESTATIONS, attestation_id)
    }

    /// Revoke attestation
    pub fn revoke(
        &self,
        attestation_id: &IncomeAttestationId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(attestation_id)? {
            Some(mut attestation) => {
                attestation.revocation_ref = Some(revocation_ref);
                attestation.updated_at = timestamp;
                let bytes = bincode::serialize(&attestation)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::EMPLOYMENT_INCOME_ATTESTATIONS, attestation_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Income attestation not found: {:?}",
                attestation_id
            ))),
        }
    }

    /// Get attestations by subject
    pub fn get_by_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<IncomeAttestation>> {
        let ids = self.get_subject_attestation_ids(subject_ref)?;
        let mut attestations = Vec::new();
        for id in ids {
            if let Some(attestation) = self.get(&id)? {
                attestations.push(attestation);
            }
        }
        Ok(attestations)
    }

    /// Get valid attestations by subject
    pub fn get_valid_by_subject(
        &self,
        subject_ref: &SubjectRef,
        current_time: Timestamp,
    ) -> Result<Vec<IncomeAttestation>> {
        let all = self.get_by_subject(subject_ref)?;
        Ok(all.into_iter().filter(|a| a.is_valid(current_time)).collect())
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_ref: &SubjectRef, attestation_id: &IncomeAttestationId) -> Result<()> {
        let mut ids = self.get_subject_attestation_ids(subject_ref)?;
        if !ids.contains(attestation_id) {
            ids.push(*attestation_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::EMPLOYMENT_SUBJECT_INCOME_INDEX, subject_ref, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_attestation_ids(&self, subject_ref: &SubjectRef) -> Result<Vec<IncomeAttestationId>> {
        match self.db.get(cf::EMPLOYMENT_SUBJECT_INCOME_INDEX, subject_ref)? {
            Some(bytes) => {
                let ids: Vec<IncomeAttestationId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Employment Proof Storage (SRC-885)
// =============================================================================

/// Storage for Employment Proofs (SRC-885)
pub struct EmploymentProofStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an employment proof
    pub fn put(&self, proof: &EmploymentProofEnvelope) -> Result<()> {
        let bytes = bincode::serialize(proof)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EMPLOYMENT_PROOFS, &proof.proof_id, &bytes)
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<EmploymentProofEnvelope>> {
        match self.db.get(cf::EMPLOYMENT_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: EmploymentProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::EMPLOYMENT_PROOFS, proof_id)
    }

    /// Check if proof is valid (not expired)
    pub fn is_valid(&self, proof_id: &ProofId, current_time: Timestamp) -> Result<bool> {
        match self.get(proof_id)? {
            Some(proof) => Ok(proof.is_valid(current_time)),
            None => Ok(false),
        }
    }
}

// =============================================================================
// Employment Event Storage
// =============================================================================

/// Storage for Employment Events
pub struct EmploymentEventStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an employment event
    pub fn put(&self, height: BlockHeight, index: u32, event: &EmploymentEvent) -> Result<()> {
        let key = Self::make_key(height, index);
        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EMPLOYMENT_SYSTEM_EVENTS, &key, &bytes)
    }

    /// Get events by block height
    pub fn get_by_height(&self, height: BlockHeight) -> Result<Vec<EmploymentEvent>> {
        let prefix = height.to_be_bytes();
        let mut events = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::EMPLOYMENT_SYSTEM_EVENTS, &prefix)? {
            let event: EmploymentEvent = bincode::deserialize(&value)
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
// Combined Employment Store
// =============================================================================

/// Combined storage interface for all SRC-88X operations
pub struct EmploymentStore<'a> {
    db: &'a Database,
}

impl<'a> EmploymentStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get issuer store
    pub fn issuers(&self) -> EmploymentIssuerStore<'_> {
        EmploymentIssuerStore::new(self.db)
    }

    /// Get credential store
    pub fn credentials(&self) -> EmploymentCredentialStore<'_> {
        EmploymentCredentialStore::new(self.db)
    }

    /// Get income attestation store
    pub fn income_attestations(&self) -> IncomeAttestationStore<'_> {
        IncomeAttestationStore::new(self.db)
    }

    /// Get proof store
    pub fn proofs(&self) -> EmploymentProofStore<'_> {
        EmploymentProofStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> EmploymentEventStore<'_> {
        EmploymentEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::employment::{
        EmploymentIssuerClass, EmploymentType, IncomeBracket, IncomePeriod,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    fn sample_issuer() -> EmploymentIssuerProfile {
        EmploymentIssuerProfile {
            issuer_address: Address::new([1u8; 20]),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US-CA".to_string(),
            policy_id: [3u8; 32],
            status: IssuerStatus::Active,
            registered_at_height: 100,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn sample_credential() -> EmploymentCredential {
        EmploymentCredential {
            employment_id: [4u8; 32],
            employee_ref: [5u8; 32],
            employer_ref: [6u8; 32],
            status: EmploymentStatus::Active,
            tenure_commitment: [7u8; 32],
            role_commitment: Some([8u8; 32]),
            employment_type: EmploymentType::FullTime,
            valid_from: 1000,
            expiry: 0,
            policy_id: [9u8; 32],
            revocation_ref: None,
            issuer_address: Address::new([10u8; 20]),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn sample_attestation() -> IncomeAttestation {
        IncomeAttestation {
            attestation_id: [11u8; 32],
            subject_ref: [12u8; 32],
            period_commitment: [13u8; 32],
            period_type: IncomePeriod::Annual,
            income_bracket: IncomeBracket::Bracket4,
            threshold_commitment: None,
            employment_id: Some([4u8; 32]),
            issuer_address: Address::new([14u8; 20]),
            issuer_class: EmploymentIssuerClass::PayrollProcessor,
            valid_from: 1000,
            expiry: 2000,
            policy_id: [15u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    #[test]
    fn test_issuer_store() {
        let (db, _dir) = temp_db();
        let store = EmploymentIssuerStore::new(&db);

        let issuer = sample_issuer();
        store.put(&issuer).unwrap();

        let retrieved = store.get(&issuer.issuer_address).unwrap().unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA");
        assert!(retrieved.status.is_active());

        // Test status update
        store.update_status(&issuer.issuer_address, IssuerStatus::Suspended, 1100).unwrap();
        let updated = store.get(&issuer.issuer_address).unwrap().unwrap();
        assert!(!updated.status.is_active());
    }

    #[test]
    fn test_credential_store() {
        let (db, _dir) = temp_db();
        let store = EmploymentCredentialStore::new(&db);

        let credential = sample_credential();
        store.put(&credential).unwrap();

        let retrieved = store.get(&credential.employment_id).unwrap().unwrap();
        assert_eq!(retrieved.employment_id, credential.employment_id);
        assert!(retrieved.status.is_currently_employed());

        // Test employee index
        let by_employee = store.get_by_employee(&credential.employee_ref).unwrap();
        assert_eq!(by_employee.len(), 1);

        // Test employer index
        let by_employer = store.get_by_employer(&credential.employer_ref).unwrap();
        assert_eq!(by_employer.len(), 1);

        // Test active filter
        let active = store.get_active_by_employee(&credential.employee_ref, 1500).unwrap();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_income_attestation_store() {
        let (db, _dir) = temp_db();
        let store = IncomeAttestationStore::new(&db);

        let attestation = sample_attestation();
        store.put(&attestation).unwrap();

        let retrieved = store.get(&attestation.attestation_id).unwrap().unwrap();
        assert_eq!(retrieved.attestation_id, attestation.attestation_id);
        assert_eq!(retrieved.income_bracket, IncomeBracket::Bracket4);

        // Test subject index
        let by_subject = store.get_by_subject(&attestation.subject_ref).unwrap();
        assert_eq!(by_subject.len(), 1);

        // Test valid filter
        let valid = store.get_valid_by_subject(&attestation.subject_ref, 1500).unwrap();
        assert_eq!(valid.len(), 1);

        // Revoke and check
        store.revoke(&attestation.attestation_id, [99u8; 32], 1600).unwrap();
        let valid_after_revoke = store.get_valid_by_subject(&attestation.subject_ref, 1700).unwrap();
        assert_eq!(valid_after_revoke.len(), 0);
    }

    #[test]
    fn test_employment_store_combined() {
        let (db, _dir) = temp_db();
        let store = EmploymentStore::new(&db);

        // Store all types
        let issuer = sample_issuer();
        store.issuers().put(&issuer).unwrap();

        let credential = sample_credential();
        store.credentials().put(&credential).unwrap();

        let attestation = sample_attestation();
        store.income_attestations().put(&attestation).unwrap();

        // Verify all stored
        assert!(store.issuers().exists(&issuer.issuer_address).unwrap());
        assert!(store.credentials().exists(&credential.employment_id).unwrap());
        assert!(store.income_attestations().exists(&attestation.attestation_id).unwrap());
    }
}

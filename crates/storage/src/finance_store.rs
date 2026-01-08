//! SRC-89X Finance & Banking Storage
//!
//! Storage layer for:
//! - SRC-891: Financial Institution & Utility Issuer Profile
//! - SRC-892: Proof-of-Address Credential
//! - SRC-893: Bank Account Standing Credential
//! - SRC-894: KYC / AML Attestation
//! - SRC-895: 89X Proof Profiles

use sumchain_primitives::{
    finance::{
        AccountStanding, AddressProof, BankStandingCredential, FinanceEvent, FinanceIssuerProfile,
        FinanceIssuerStatus, FinanceProofEnvelope, KycAttestation, KycStatus,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// Type aliases for clarity
pub type AddressProofId = [u8; 32];
pub type BankStandingId = [u8; 32];
pub type KycAttestationId = [u8; 32];
pub type ProofId = [u8; 32];
pub type SubjectRef = [u8; 32];

// =============================================================================
// Issuer Profile Storage (SRC-891)
// =============================================================================

/// Storage for Finance Issuer Profiles (SRC-891)
pub struct FinanceIssuerStore<'a> {
    db: &'a Database,
}

impl<'a> FinanceIssuerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an issuer profile
    pub fn put(&self, issuer: &FinanceIssuerProfile) -> Result<()> {
        let bytes = bincode::serialize(issuer)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::FINANCE_ISSUERS, issuer.issuer_address.as_bytes(), &bytes)?;

        // Update jurisdiction index
        self.add_to_jurisdiction_index(&issuer.jurisdiction_code, &issuer.issuer_address)?;

        Ok(())
    }

    /// Get an issuer by address
    pub fn get(&self, issuer_address: &Address) -> Result<Option<FinanceIssuerProfile>> {
        match self.db.get(cf::FINANCE_ISSUERS, issuer_address.as_bytes())? {
            Some(bytes) => {
                let issuer: FinanceIssuerProfile = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(issuer))
            }
            None => Ok(None),
        }
    }

    /// Check if issuer exists
    pub fn exists(&self, issuer_address: &Address) -> Result<bool> {
        self.db.contains(cf::FINANCE_ISSUERS, issuer_address.as_bytes())
    }

    /// Update issuer status
    pub fn update_status(
        &self,
        issuer_address: &Address,
        status: FinanceIssuerStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(issuer_address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                let bytes = bincode::serialize(&issuer)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::FINANCE_ISSUERS, issuer_address.as_bytes(), &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Issuer not found: {:?}",
                issuer_address
            ))),
        }
    }

    /// List all active issuers
    pub fn list_active(&self) -> Result<Vec<FinanceIssuerProfile>> {
        let mut issuers = Vec::new();
        for (_, value) in self.db.iter(cf::FINANCE_ISSUERS)? {
            let issuer: FinanceIssuerProfile = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if issuer.status.is_active() {
                issuers.push(issuer);
            }
        }
        Ok(issuers)
    }

    /// Get issuers by jurisdiction
    pub fn get_by_jurisdiction(&self, jurisdiction_code: &str) -> Result<Vec<FinanceIssuerProfile>> {
        let addresses = self.get_jurisdiction_issuer_addresses(jurisdiction_code)?;
        let mut issuers = Vec::new();
        for addr in addresses {
            if let Some(issuer) = self.get(&addr)? {
                issuers.push(issuer);
            }
        }
        Ok(issuers)
    }

    // Index helpers
    fn add_to_jurisdiction_index(&self, jurisdiction_code: &str, issuer_address: &Address) -> Result<()> {
        let mut addresses = self.get_jurisdiction_issuer_addresses(jurisdiction_code)?;
        if !addresses.contains(issuer_address) {
            addresses.push(*issuer_address);
            let bytes = bincode::serialize(&addresses)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::FINANCE_JURISDICTION_INDEX, jurisdiction_code.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    fn get_jurisdiction_issuer_addresses(&self, jurisdiction_code: &str) -> Result<Vec<Address>> {
        match self.db.get(cf::FINANCE_JURISDICTION_INDEX, jurisdiction_code.as_bytes())? {
            Some(bytes) => {
                let addresses: Vec<Address> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(addresses)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Address Proof Storage (SRC-892)
// =============================================================================

/// Storage for Address Proofs (SRC-892)
pub struct AddressProofStore<'a> {
    db: &'a Database,
}

impl<'a> AddressProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an address proof
    pub fn put(&self, proof: &AddressProof) -> Result<()> {
        let bytes = bincode::serialize(proof)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::FINANCE_ADDRESS_PROOFS, &proof.proof_id, &bytes)?;

        // Update subject index
        self.add_to_subject_index(&proof.subject_ref, &proof.proof_id)?;

        Ok(())
    }

    /// Get an address proof by ID
    pub fn get(&self, proof_id: &AddressProofId) -> Result<Option<AddressProof>> {
        match self.db.get(cf::FINANCE_ADDRESS_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: AddressProof = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &AddressProofId) -> Result<bool> {
        self.db.contains(cf::FINANCE_ADDRESS_PROOFS, proof_id)
    }

    /// Revoke address proof
    pub fn revoke(
        &self,
        proof_id: &AddressProofId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(proof_id)? {
            Some(mut proof) => {
                proof.revocation_ref = Some(revocation_ref);
                proof.updated_at = timestamp;
                let bytes = bincode::serialize(&proof)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::FINANCE_ADDRESS_PROOFS, proof_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Address proof not found: {:?}",
                proof_id
            ))),
        }
    }

    /// Get proofs by subject
    pub fn get_by_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<AddressProof>> {
        let ids = self.get_subject_proof_ids(subject_ref)?;
        let mut proofs = Vec::new();
        for id in ids {
            if let Some(proof) = self.get(&id)? {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }

    /// Get valid proofs by subject
    pub fn get_valid_by_subject(
        &self,
        subject_ref: &SubjectRef,
        current_time: Timestamp,
    ) -> Result<Vec<AddressProof>> {
        let all = self.get_by_subject(subject_ref)?;
        Ok(all.into_iter().filter(|p| p.is_valid(current_time)).collect())
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_ref: &SubjectRef, proof_id: &AddressProofId) -> Result<()> {
        let mut ids = self.get_subject_proof_ids(subject_ref)?;
        if !ids.contains(proof_id) {
            ids.push(*proof_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::FINANCE_SUBJECT_ADDRESS_INDEX, subject_ref, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_proof_ids(&self, subject_ref: &SubjectRef) -> Result<Vec<AddressProofId>> {
        match self.db.get(cf::FINANCE_SUBJECT_ADDRESS_INDEX, subject_ref)? {
            Some(bytes) => {
                let ids: Vec<AddressProofId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Bank Standing Storage (SRC-893)
// =============================================================================

/// Storage for Bank Standing Credentials (SRC-893)
pub struct BankStandingStore<'a> {
    db: &'a Database,
}

impl<'a> BankStandingStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a bank standing credential
    pub fn put(&self, credential: &BankStandingCredential) -> Result<()> {
        let bytes = bincode::serialize(credential)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::FINANCE_BANK_STANDINGS, &credential.credential_id, &bytes)?;

        // Update subject index
        self.add_to_subject_index(&credential.subject_ref, &credential.credential_id)?;

        Ok(())
    }

    /// Get a bank standing credential by ID
    pub fn get(&self, credential_id: &BankStandingId) -> Result<Option<BankStandingCredential>> {
        match self.db.get(cf::FINANCE_BANK_STANDINGS, credential_id)? {
            Some(bytes) => {
                let credential: BankStandingCredential = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(credential))
            }
            None => Ok(None),
        }
    }

    /// Check if credential exists
    pub fn exists(&self, credential_id: &BankStandingId) -> Result<bool> {
        self.db.contains(cf::FINANCE_BANK_STANDINGS, credential_id)
    }

    /// Update standing
    pub fn update_standing(
        &self,
        credential_id: &BankStandingId,
        standing: AccountStanding,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(credential_id)? {
            Some(mut credential) => {
                credential.standing = standing;
                credential.updated_at = timestamp;
                let bytes = bincode::serialize(&credential)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::FINANCE_BANK_STANDINGS, credential_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Bank standing credential not found: {:?}",
                credential_id
            ))),
        }
    }

    /// Revoke credential
    pub fn revoke(
        &self,
        credential_id: &BankStandingId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(credential_id)? {
            Some(mut credential) => {
                credential.revocation_ref = Some(revocation_ref);
                credential.updated_at = timestamp;
                let bytes = bincode::serialize(&credential)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::FINANCE_BANK_STANDINGS, credential_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Bank standing credential not found: {:?}",
                credential_id
            ))),
        }
    }

    /// Get credentials by subject
    pub fn get_by_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<BankStandingCredential>> {
        let ids = self.get_subject_credential_ids(subject_ref)?;
        let mut credentials = Vec::new();
        for id in ids {
            if let Some(credential) = self.get(&id)? {
                credentials.push(credential);
            }
        }
        Ok(credentials)
    }

    /// Get valid credentials by subject
    pub fn get_valid_by_subject(
        &self,
        subject_ref: &SubjectRef,
        current_time: Timestamp,
    ) -> Result<Vec<BankStandingCredential>> {
        let all = self.get_by_subject(subject_ref)?;
        Ok(all.into_iter().filter(|c| c.is_valid(current_time)).collect())
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_ref: &SubjectRef, credential_id: &BankStandingId) -> Result<()> {
        let mut ids = self.get_subject_credential_ids(subject_ref)?;
        if !ids.contains(credential_id) {
            ids.push(*credential_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::FINANCE_SUBJECT_BANK_INDEX, subject_ref, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_credential_ids(&self, subject_ref: &SubjectRef) -> Result<Vec<BankStandingId>> {
        match self.db.get(cf::FINANCE_SUBJECT_BANK_INDEX, subject_ref)? {
            Some(bytes) => {
                let ids: Vec<BankStandingId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// KYC Attestation Storage (SRC-894)
// =============================================================================

/// Storage for KYC Attestations (SRC-894)
pub struct KycAttestationStore<'a> {
    db: &'a Database,
}

impl<'a> KycAttestationStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a KYC attestation
    pub fn put(&self, attestation: &KycAttestation) -> Result<()> {
        let bytes = bincode::serialize(attestation)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::FINANCE_KYC_ATTESTATIONS, &attestation.attestation_id, &bytes)?;

        // Update subject index
        self.add_to_subject_index(&attestation.subject_ref, &attestation.attestation_id)?;

        Ok(())
    }

    /// Get a KYC attestation by ID
    pub fn get(&self, attestation_id: &KycAttestationId) -> Result<Option<KycAttestation>> {
        match self.db.get(cf::FINANCE_KYC_ATTESTATIONS, attestation_id)? {
            Some(bytes) => {
                let attestation: KycAttestation = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(attestation))
            }
            None => Ok(None),
        }
    }

    /// Check if attestation exists
    pub fn exists(&self, attestation_id: &KycAttestationId) -> Result<bool> {
        self.db.contains(cf::FINANCE_KYC_ATTESTATIONS, attestation_id)
    }

    /// Update status
    pub fn update_status(
        &self,
        attestation_id: &KycAttestationId,
        status: KycStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(attestation_id)? {
            Some(mut attestation) => {
                attestation.status = status;
                attestation.updated_at = timestamp;
                let bytes = bincode::serialize(&attestation)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::FINANCE_KYC_ATTESTATIONS, attestation_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "KYC attestation not found: {:?}",
                attestation_id
            ))),
        }
    }

    /// Revoke attestation
    pub fn revoke(
        &self,
        attestation_id: &KycAttestationId,
        revocation_ref: [u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(attestation_id)? {
            Some(mut attestation) => {
                attestation.status = KycStatus::Revoked;
                attestation.revocation_ref = Some(revocation_ref);
                attestation.updated_at = timestamp;
                let bytes = bincode::serialize(&attestation)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::FINANCE_KYC_ATTESTATIONS, attestation_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "KYC attestation not found: {:?}",
                attestation_id
            ))),
        }
    }

    /// Get attestations by subject
    pub fn get_by_subject(&self, subject_ref: &SubjectRef) -> Result<Vec<KycAttestation>> {
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
    ) -> Result<Vec<KycAttestation>> {
        let all = self.get_by_subject(subject_ref)?;
        Ok(all.into_iter().filter(|a| a.is_valid(current_time)).collect())
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_ref: &SubjectRef, attestation_id: &KycAttestationId) -> Result<()> {
        let mut ids = self.get_subject_attestation_ids(subject_ref)?;
        if !ids.contains(attestation_id) {
            ids.push(*attestation_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::FINANCE_SUBJECT_KYC_INDEX, subject_ref, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_attestation_ids(&self, subject_ref: &SubjectRef) -> Result<Vec<KycAttestationId>> {
        match self.db.get(cf::FINANCE_SUBJECT_KYC_INDEX, subject_ref)? {
            Some(bytes) => {
                let ids: Vec<KycAttestationId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Finance Proof Storage (SRC-895)
// =============================================================================

/// Storage for Finance Proofs (SRC-895)
pub struct FinanceProofStore<'a> {
    db: &'a Database,
}

impl<'a> FinanceProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a finance proof
    pub fn put(&self, proof: &FinanceProofEnvelope) -> Result<()> {
        let bytes = bincode::serialize(proof)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::FINANCE_PROOFS, &proof.proof_id, &bytes)
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<FinanceProofEnvelope>> {
        match self.db.get(cf::FINANCE_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: FinanceProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::FINANCE_PROOFS, proof_id)
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
// Finance Event Storage
// =============================================================================

/// Storage for Finance Events
pub struct FinanceEventStore<'a> {
    db: &'a Database,
}

impl<'a> FinanceEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a finance event
    pub fn put(&self, height: BlockHeight, index: u32, event: &FinanceEvent) -> Result<()> {
        let key = Self::make_key(height, index);
        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::FINANCE_SYSTEM_EVENTS, &key, &bytes)
    }

    /// Get events by block height
    pub fn get_by_height(&self, height: BlockHeight) -> Result<Vec<FinanceEvent>> {
        let prefix = height.to_be_bytes();
        let mut events = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::FINANCE_SYSTEM_EVENTS, &prefix)? {
            let event: FinanceEvent = bincode::deserialize(&value)
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
// Combined Finance Store
// =============================================================================

/// Combined storage interface for all SRC-89X operations
pub struct FinanceStore<'a> {
    db: &'a Database,
}

impl<'a> FinanceStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get issuer store
    pub fn issuers(&self) -> FinanceIssuerStore<'_> {
        FinanceIssuerStore::new(self.db)
    }

    /// Get address proof store
    pub fn address_proofs(&self) -> AddressProofStore<'_> {
        AddressProofStore::new(self.db)
    }

    /// Get bank standing store
    pub fn bank_standings(&self) -> BankStandingStore<'_> {
        BankStandingStore::new(self.db)
    }

    /// Get KYC attestation store
    pub fn kyc_attestations(&self) -> KycAttestationStore<'_> {
        KycAttestationStore::new(self.db)
    }

    /// Get proof store
    pub fn proofs(&self) -> FinanceProofStore<'_> {
        FinanceProofStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> FinanceEventStore<'_> {
        FinanceEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::finance::{
        AccountType, AddressProofType, AmlRisk, BalanceBracket, FinanceIssuerClass, KycLevel,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    fn sample_issuer() -> FinanceIssuerProfile {
        FinanceIssuerProfile {
            issuer_address: Address::new([1u8; 20]),
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

    fn sample_address_proof() -> AddressProof {
        AddressProof {
            proof_id: [4u8; 32],
            subject_ref: [5u8; 32],
            address_commitment: [6u8; 32],
            jurisdiction_code: "US-NY".to_string(),
            postal_commitment: [7u8; 32],
            proof_type: AddressProofType::UtilityBill,
            document_date: 900,
            issuer_address: Address::new([8u8; 20]),
            issuer_class: FinanceIssuerClass::RegulatedUtility,
            valid_from: 1000,
            expiry: 2000,
            policy_id: [9u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn sample_bank_standing() -> BankStandingCredential {
        BankStandingCredential {
            credential_id: [10u8; 32],
            subject_ref: [11u8; 32],
            account_commitment: [12u8; 32],
            bank_ref: [13u8; 32],
            account_type: AccountType::Checking,
            standing: AccountStanding::Good,
            tenure_commitment: [14u8; 32],
            balance_bracket: BalanceBracket::Bracket5,
            threshold_commitment: None,
            issuer_address: Address::new([15u8; 20]),
            issuer_class: FinanceIssuerClass::RegulatedBank,
            valid_from: 1000,
            expiry: 2000,
            policy_id: [16u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn sample_kyc_attestation() -> KycAttestation {
        KycAttestation {
            attestation_id: [17u8; 32],
            subject_ref: [18u8; 32],
            kyc_level: KycLevel::Enhanced,
            aml_risk: AmlRisk::Low,
            identity_commitment: [19u8; 32],
            subject_jurisdiction: "US".to_string(),
            methods_commitment: [20u8; 32],
            status: KycStatus::Active,
            issuer_address: Address::new([21u8; 20]),
            issuer_class: FinanceIssuerClass::RegulatedBank,
            valid_from: 1000,
            expiry: 2000,
            policy_id: [22u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    #[test]
    fn test_issuer_store() {
        let (db, _dir) = temp_db();
        let store = FinanceIssuerStore::new(&db);

        let issuer = sample_issuer();
        store.put(&issuer).unwrap();

        let retrieved = store.get(&issuer.issuer_address).unwrap().unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-NY");
        assert!(retrieved.status.is_active());

        // Test jurisdiction index
        let by_jurisdiction = store.get_by_jurisdiction("US-NY").unwrap();
        assert_eq!(by_jurisdiction.len(), 1);

        // Test status update
        store.update_status(&issuer.issuer_address, FinanceIssuerStatus::Suspended, 1100).unwrap();
        let updated = store.get(&issuer.issuer_address).unwrap().unwrap();
        assert!(!updated.status.is_active());
    }

    #[test]
    fn test_address_proof_store() {
        let (db, _dir) = temp_db();
        let store = AddressProofStore::new(&db);

        let proof = sample_address_proof();
        store.put(&proof).unwrap();

        let retrieved = store.get(&proof.proof_id).unwrap().unwrap();
        assert_eq!(retrieved.proof_id, proof.proof_id);
        assert_eq!(retrieved.jurisdiction_code, "US-NY");

        // Test subject index
        let by_subject = store.get_by_subject(&proof.subject_ref).unwrap();
        assert_eq!(by_subject.len(), 1);

        // Test valid filter
        let valid = store.get_valid_by_subject(&proof.subject_ref, 1500).unwrap();
        assert_eq!(valid.len(), 1);

        // Revoke and check
        store.revoke(&proof.proof_id, [99u8; 32], 1600).unwrap();
        let valid_after_revoke = store.get_valid_by_subject(&proof.subject_ref, 1700).unwrap();
        assert_eq!(valid_after_revoke.len(), 0);
    }

    #[test]
    fn test_bank_standing_store() {
        let (db, _dir) = temp_db();
        let store = BankStandingStore::new(&db);

        let credential = sample_bank_standing();
        store.put(&credential).unwrap();

        let retrieved = store.get(&credential.credential_id).unwrap().unwrap();
        assert_eq!(retrieved.credential_id, credential.credential_id);
        assert_eq!(retrieved.balance_bracket, BalanceBracket::Bracket5);

        // Test subject index
        let by_subject = store.get_by_subject(&credential.subject_ref).unwrap();
        assert_eq!(by_subject.len(), 1);

        // Test standing update
        store.update_standing(&credential.credential_id, AccountStanding::Poor, 1100).unwrap();
        let updated = store.get(&credential.credential_id).unwrap().unwrap();
        assert_eq!(updated.standing, AccountStanding::Poor);
    }

    #[test]
    fn test_kyc_attestation_store() {
        let (db, _dir) = temp_db();
        let store = KycAttestationStore::new(&db);

        let attestation = sample_kyc_attestation();
        store.put(&attestation).unwrap();

        let retrieved = store.get(&attestation.attestation_id).unwrap().unwrap();
        assert_eq!(retrieved.attestation_id, attestation.attestation_id);
        assert_eq!(retrieved.kyc_level, KycLevel::Enhanced);

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
    fn test_finance_store_combined() {
        let (db, _dir) = temp_db();
        let store = FinanceStore::new(&db);

        // Store all types
        let issuer = sample_issuer();
        store.issuers().put(&issuer).unwrap();

        let address_proof = sample_address_proof();
        store.address_proofs().put(&address_proof).unwrap();

        let bank_standing = sample_bank_standing();
        store.bank_standings().put(&bank_standing).unwrap();

        let kyc = sample_kyc_attestation();
        store.kyc_attestations().put(&kyc).unwrap();

        // Verify all stored
        assert!(store.issuers().exists(&issuer.issuer_address).unwrap());
        assert!(store.address_proofs().exists(&address_proof.proof_id).unwrap());
        assert!(store.bank_standings().exists(&bank_standing.credential_id).unwrap());
        assert!(store.kyc_attestations().exists(&kyc.attestation_id).unwrap());
    }
}

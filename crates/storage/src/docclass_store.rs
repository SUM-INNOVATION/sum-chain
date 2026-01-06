//! DocClass Storage Module (SRC-80X/81X)
//!
//! Provides persistent storage for DocClass credentials:
//! - Identity Roots (SRC-800)
//! - Eligibility Attestations (SRC-802)
//! - Academic/Professional Credentials (SRC-810-813)
//! - Revocation Records (SRC-805)
//! - Issuer Registry

use sumchain_primitives::{
    Address, AcademicCredential, BlockHeight, CredentialId, DocClassEvent, DocClassIssuer,
    DocClassIssuerStatus, DocSubcode, EligibilityAttestation, IdentityRoot, IdentityStatus,
    RevocationRecord, RevocationStatus, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// =============================================================================
// Identity Root Storage (SRC-800)
// =============================================================================

/// Storage for Identity Root records (SRC-800)
pub struct IdentityRootStore<'a> {
    db: &'a Database,
}

impl<'a> IdentityRootStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an identity root
    pub fn put(&self, identity: &IdentityRoot) -> Result<()> {
        let bytes = bincode::serialize(identity)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::DOCCLASS_IDENTITY_ROOTS, &identity.identity_id, &bytes)?;

        // Index by subject commitment
        self.add_to_subject_index(&identity.subject_commitment, &identity.identity_id, DocSubcode::IdentityRoot)?;

        Ok(())
    }

    /// Get an identity root by ID
    pub fn get(&self, identity_id: &CredentialId) -> Result<Option<IdentityRoot>> {
        match self.db.get(cf::DOCCLASS_IDENTITY_ROOTS, identity_id)? {
            Some(bytes) => {
                let identity: IdentityRoot = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(identity))
            }
            None => Ok(None),
        }
    }

    /// Check if identity exists
    pub fn exists(&self, identity_id: &CredentialId) -> Result<bool> {
        self.db.contains(cf::DOCCLASS_IDENTITY_ROOTS, identity_id)
    }

    /// Get identity by controller address
    pub fn get_by_controller(&self, controller: &Address) -> Result<Vec<IdentityRoot>> {
        let mut identities = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_IDENTITY_ROOTS)? {
            let identity: IdentityRoot = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if identity.controller == *controller ||
               identity.additional_controllers.contains(controller) {
                identities.push(identity);
            }
        }

        Ok(identities)
    }

    /// Update identity status
    pub fn update_status(&self, identity_id: &CredentialId, status: IdentityStatus, timestamp: Timestamp) -> Result<()> {
        match self.get(identity_id)? {
            Some(mut identity) => {
                identity.status = status;
                identity.updated_at = timestamp;
                self.put(&identity)
            }
            None => Err(StorageError::NotFound(format!("Identity not found: {:?}", identity_id))),
        }
    }

    /// Helper to add to subject index
    fn add_to_subject_index(&self, subject_commitment: &[u8; 32], credential_id: &CredentialId, subcode: DocSubcode) -> Result<()> {
        let mut index = self.get_by_subject(subject_commitment)?;
        let entry = (*credential_id, subcode);
        if !index.iter().any(|(id, _)| id == credential_id) {
            index.push(entry);
            let bytes = bincode::serialize(&index)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::DOCCLASS_SUBJECT_INDEX, subject_commitment, &bytes)?;
        }
        Ok(())
    }

    /// Get all credential IDs for a subject commitment
    pub fn get_by_subject(&self, subject_commitment: &[u8; 32]) -> Result<Vec<(CredentialId, DocSubcode)>> {
        match self.db.get(cf::DOCCLASS_SUBJECT_INDEX, subject_commitment)? {
            Some(bytes) => {
                let index: Vec<(CredentialId, DocSubcode)> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(index)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Eligibility Attestation Storage (SRC-802)
// =============================================================================

/// Storage for Eligibility Attestations (SRC-802)
pub struct EligibilityStore<'a> {
    db: &'a Database,
}

impl<'a> EligibilityStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an eligibility attestation
    pub fn put(&self, attestation: &EligibilityAttestation) -> Result<()> {
        let bytes = bincode::serialize(attestation)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::DOCCLASS_ELIGIBILITY, &attestation.credential_id, &bytes)?;

        // Index by subject commitment
        self.add_to_subject_index(&attestation.subject_commitment, &attestation.credential_id)?;

        // Index by issuer
        self.add_to_issuer_index(&attestation.issuer, &attestation.credential_id)?;

        Ok(())
    }

    /// Get an eligibility attestation by ID
    pub fn get(&self, credential_id: &CredentialId) -> Result<Option<EligibilityAttestation>> {
        match self.db.get(cf::DOCCLASS_ELIGIBILITY, credential_id)? {
            Some(bytes) => {
                let attestation: EligibilityAttestation = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(attestation))
            }
            None => Ok(None),
        }
    }

    /// Check if attestation exists
    pub fn exists(&self, credential_id: &CredentialId) -> Result<bool> {
        self.db.contains(cf::DOCCLASS_ELIGIBILITY, credential_id)
    }

    /// Get attestations by issuer
    pub fn get_by_issuer(&self, issuer: &Address) -> Result<Vec<EligibilityAttestation>> {
        let credential_ids = self.get_issuer_credentials(issuer)?;
        let mut attestations = Vec::new();

        for credential_id in credential_ids {
            if let Some(attestation) = self.get(&credential_id)? {
                attestations.push(attestation);
            }
        }

        Ok(attestations)
    }

    /// Get attestations by subject commitment
    pub fn get_by_subject(&self, subject_commitment: &[u8; 32]) -> Result<Vec<EligibilityAttestation>> {
        let credential_ids = self.get_subject_credentials(subject_commitment)?;
        let mut attestations = Vec::new();

        for credential_id in credential_ids {
            if let Some(attestation) = self.get(&credential_id)? {
                attestations.push(attestation);
            }
        }

        Ok(attestations)
    }

    /// Get valid (non-expired, non-revoked) attestations for a subject
    pub fn get_valid_for_subject(&self, subject_commitment: &[u8; 32], current_time: Timestamp) -> Result<Vec<EligibilityAttestation>> {
        let attestations = self.get_by_subject(subject_commitment)?;
        Ok(attestations.into_iter().filter(|a| {
            a.revocation_status == RevocationStatus::Active &&
            (a.expires_at == 0 || a.expires_at > current_time) &&
            a.valid_from <= current_time
        }).collect())
    }

    /// Update revocation status
    pub fn update_revocation(&self, credential_id: &CredentialId, status: RevocationStatus, superseded_by: Option<CredentialId>) -> Result<()> {
        match self.get(credential_id)? {
            Some(mut attestation) => {
                attestation.revocation_status = status;
                attestation.superseded_by = superseded_by;
                self.put(&attestation)
            }
            None => Err(StorageError::NotFound(format!("Attestation not found: {:?}", credential_id))),
        }
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_commitment: &[u8; 32], credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_subject_credentials(subject_commitment)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = bincode::serialize(&index)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::DOCCLASS_SUBJECT_INDEX, subject_commitment, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_credentials(&self, subject_commitment: &[u8; 32]) -> Result<Vec<CredentialId>> {
        match self.db.get(cf::DOCCLASS_SUBJECT_INDEX, subject_commitment)? {
            Some(bytes) => {
                let index: Vec<CredentialId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(index)
            }
            None => Ok(Vec::new()),
        }
    }

    fn add_to_issuer_index(&self, issuer: &Address, credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_issuer_credentials(issuer)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = bincode::serialize(&index)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::DOCCLASS_ISSUER_INDEX, issuer.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    fn get_issuer_credentials(&self, issuer: &Address) -> Result<Vec<CredentialId>> {
        match self.db.get(cf::DOCCLASS_ISSUER_INDEX, issuer.as_bytes())? {
            Some(bytes) => {
                let index: Vec<CredentialId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(index)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Academic/Professional Credential Storage (SRC-810-813)
// =============================================================================

/// Storage for Academic/Professional Credentials (SRC-810-813)
pub struct CredentialStore<'a> {
    db: &'a Database,
}

impl<'a> CredentialStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an academic/professional credential
    pub fn put(&self, credential: &AcademicCredential) -> Result<()> {
        let bytes = bincode::serialize(credential)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::DOCCLASS_CREDENTIALS, &credential.credential_id, &bytes)?;

        // Index by subject commitment
        self.add_to_subject_index(&credential.subject_commitment, &credential.credential_id)?;

        // Index by issuer
        self.add_to_issuer_index(&credential.issuer, &credential.credential_id)?;

        Ok(())
    }

    /// Get a credential by ID
    pub fn get(&self, credential_id: &CredentialId) -> Result<Option<AcademicCredential>> {
        match self.db.get(cf::DOCCLASS_CREDENTIALS, credential_id)? {
            Some(bytes) => {
                let credential: AcademicCredential = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(credential))
            }
            None => Ok(None),
        }
    }

    /// Check if credential exists
    pub fn exists(&self, credential_id: &CredentialId) -> Result<bool> {
        self.db.contains(cf::DOCCLASS_CREDENTIALS, credential_id)
    }

    /// Get credentials by subcode
    pub fn get_by_subcode(&self, subcode: DocSubcode) -> Result<Vec<AcademicCredential>> {
        let mut credentials = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_CREDENTIALS)? {
            let credential: AcademicCredential = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if credential.subcode == subcode {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Get credentials by issuer
    pub fn get_by_issuer(&self, issuer: &Address) -> Result<Vec<AcademicCredential>> {
        let credential_ids = self.get_issuer_credentials(issuer)?;
        let mut credentials = Vec::new();

        for credential_id in credential_ids {
            if let Some(credential) = self.get(&credential_id)? {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Get credentials by subject commitment
    pub fn get_by_subject(&self, subject_commitment: &[u8; 32]) -> Result<Vec<AcademicCredential>> {
        let credential_ids = self.get_subject_credentials(subject_commitment)?;
        let mut credentials = Vec::new();

        for credential_id in credential_ids {
            if let Some(credential) = self.get(&credential_id)? {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    /// Get valid credentials for a subject
    pub fn get_valid_for_subject(&self, subject_commitment: &[u8; 32], current_time: Timestamp) -> Result<Vec<AcademicCredential>> {
        let credentials = self.get_by_subject(subject_commitment)?;
        Ok(credentials.into_iter().filter(|c| {
            c.revocation_status == RevocationStatus::Active &&
            (c.expires_at == 0 || c.expires_at > current_time) &&
            c.valid_from <= current_time
        }).collect())
    }

    /// Update revocation status
    pub fn update_revocation(&self, credential_id: &CredentialId, status: RevocationStatus, superseded_by: Option<CredentialId>) -> Result<()> {
        match self.get(credential_id)? {
            Some(mut credential) => {
                credential.revocation_status = status;
                credential.superseded_by = superseded_by;
                self.put(&credential)
            }
            None => Err(StorageError::NotFound(format!("Credential not found: {:?}", credential_id))),
        }
    }

    // Index helpers
    fn add_to_subject_index(&self, subject_commitment: &[u8; 32], credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_subject_credentials(subject_commitment)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = bincode::serialize(&index)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::DOCCLASS_SUBJECT_INDEX, subject_commitment, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_credentials(&self, subject_commitment: &[u8; 32]) -> Result<Vec<CredentialId>> {
        match self.db.get(cf::DOCCLASS_SUBJECT_INDEX, subject_commitment)? {
            Some(bytes) => {
                let index: Vec<CredentialId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(index)
            }
            None => Ok(Vec::new()),
        }
    }

    fn add_to_issuer_index(&self, issuer: &Address, credential_id: &CredentialId) -> Result<()> {
        let mut index = self.get_issuer_credentials(issuer)?;
        if !index.contains(credential_id) {
            index.push(*credential_id);
            let bytes = bincode::serialize(&index)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::DOCCLASS_ISSUER_INDEX, issuer.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    fn get_issuer_credentials(&self, issuer: &Address) -> Result<Vec<CredentialId>> {
        match self.db.get(cf::DOCCLASS_ISSUER_INDEX, issuer.as_bytes())? {
            Some(bytes) => {
                let index: Vec<CredentialId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(index)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Revocation Record Storage (SRC-805)
// =============================================================================

/// Storage for Revocation Records (SRC-805)
pub struct RevocationStore<'a> {
    db: &'a Database,
}

impl<'a> RevocationStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Create key for revocation record
    fn revocation_key(credential_id: &CredentialId, revoked_at: BlockHeight) -> Vec<u8> {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(credential_id);
        key.extend_from_slice(&revoked_at.to_be_bytes());
        key
    }

    /// Store a revocation record
    pub fn put(&self, record: &RevocationRecord) -> Result<()> {
        let key = Self::revocation_key(&record.credential_id, record.revoked_at_height);
        let bytes = bincode::serialize(record)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::DOCCLASS_REVOCATIONS, &key, &bytes)
    }

    /// Get revocation records for a credential
    pub fn get_for_credential(&self, credential_id: &CredentialId) -> Result<Vec<RevocationRecord>> {
        let mut records = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::DOCCLASS_REVOCATIONS, credential_id)? {
            if key.len() == 40 && &key[..32] == credential_id {
                let record: RevocationRecord = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                records.push(record);
            }
        }

        // Sort by revoked_at_height descending (most recent first)
        records.sort_by(|a, b| b.revoked_at_height.cmp(&a.revoked_at_height));

        Ok(records)
    }

    /// Get the latest revocation record for a credential
    pub fn get_latest(&self, credential_id: &CredentialId) -> Result<Option<RevocationRecord>> {
        let records = self.get_for_credential(credential_id)?;
        Ok(records.into_iter().next())
    }

    /// Check if credential is revoked
    pub fn is_revoked(&self, credential_id: &CredentialId) -> Result<bool> {
        match self.get_latest(credential_id)? {
            Some(record) => Ok(record.status == RevocationStatus::Revoked),
            None => Ok(false),
        }
    }

    /// Get current revocation status
    pub fn get_status(&self, credential_id: &CredentialId) -> Result<RevocationStatus> {
        match self.get_latest(credential_id)? {
            Some(record) => Ok(record.status),
            None => Ok(RevocationStatus::Active),
        }
    }

    /// Get all revocations by revoker
    pub fn get_by_revoker(&self, revoker: &Address) -> Result<Vec<RevocationRecord>> {
        let mut records = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_REVOCATIONS)? {
            let record: RevocationRecord = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if record.revoker == *revoker {
                records.push(record);
            }
        }

        Ok(records)
    }
}

// =============================================================================
// DocClass Issuer Registry Storage
// =============================================================================

/// Storage for DocClass Issuer Registry
pub struct DocClassIssuerStore<'a> {
    db: &'a Database,
}

impl<'a> DocClassIssuerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Register or update an issuer
    pub fn put(&self, issuer: &DocClassIssuer) -> Result<()> {
        let bytes = bincode::serialize(issuer)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::DOCCLASS_ISSUERS, issuer.address.as_bytes(), &bytes)
    }

    /// Get an issuer by address
    pub fn get(&self, address: &Address) -> Result<Option<DocClassIssuer>> {
        match self.db.get(cf::DOCCLASS_ISSUERS, address.as_bytes())? {
            Some(bytes) => {
                let issuer: DocClassIssuer = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(issuer))
            }
            None => Ok(None),
        }
    }

    /// Check if issuer is registered
    pub fn is_registered(&self, address: &Address) -> Result<bool> {
        self.db.contains(cf::DOCCLASS_ISSUERS, address.as_bytes())
    }

    /// Check if issuer is active and can issue credentials
    pub fn can_issue(&self, address: &Address) -> Result<bool> {
        match self.get(address)? {
            Some(issuer) => Ok(issuer.status.can_issue()),
            None => Ok(false),
        }
    }

    /// Check if issuer can issue a specific subcode in a jurisdiction
    pub fn can_issue_subcode(&self, address: &Address, subcode: DocSubcode, jurisdiction: &str) -> Result<bool> {
        match self.get(address)? {
            Some(issuer) => {
                if !issuer.status.can_issue() {
                    return Ok(false);
                }
                // Check if subcode is authorized
                if !issuer.authorized_subcodes.contains(&subcode) {
                    return Ok(false);
                }
                // Check if jurisdiction is authorized (empty list = all jurisdictions)
                if !issuer.jurisdictions.is_empty() &&
                   !issuer.jurisdictions.iter().any(|j| j == jurisdiction || j == "*") {
                    return Ok(false);
                }
                // Check issuer type compatibility
                if !issuer.issuer_type.can_issue(subcode) {
                    return Ok(false);
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Update issuer status
    pub fn update_status(&self, address: &Address, status: DocClassIssuerStatus, timestamp: Timestamp) -> Result<()> {
        match self.get(address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                self.put(&issuer)
            }
            None => Err(StorageError::NotFound(format!("Issuer not found: {}", address))),
        }
    }

    /// Get all registered issuers
    pub fn get_all(&self) -> Result<Vec<DocClassIssuer>> {
        let mut issuers = Vec::new();

        for (_, value) in self.db.iter(cf::DOCCLASS_ISSUERS)? {
            let issuer: DocClassIssuer = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            issuers.push(issuer);
        }

        Ok(issuers)
    }

    /// Get all active issuers
    pub fn get_active(&self) -> Result<Vec<DocClassIssuer>> {
        let all = self.get_all()?;
        Ok(all.into_iter().filter(|i| i.status.can_issue()).collect())
    }

    /// Get issuers by jurisdiction
    pub fn get_by_jurisdiction(&self, jurisdiction: &str) -> Result<Vec<DocClassIssuer>> {
        let all = self.get_all()?;
        Ok(all.into_iter().filter(|i| {
            i.jurisdictions.is_empty() ||
            i.jurisdictions.iter().any(|j| j == jurisdiction || j == "*")
        }).collect())
    }

    /// Get issuers by authorized subcode
    pub fn get_by_subcode(&self, subcode: DocSubcode) -> Result<Vec<DocClassIssuer>> {
        let all = self.get_all()?;
        Ok(all.into_iter().filter(|i| i.authorized_subcodes.contains(&subcode)).collect())
    }

    /// Delete an issuer
    pub fn delete(&self, address: &Address) -> Result<()> {
        self.db.delete(cf::DOCCLASS_ISSUERS, address.as_bytes())
    }
}

// =============================================================================
// DocClass Event Storage
// =============================================================================

/// Storage for DocClass Events (for indexing/querying)
pub struct DocClassEventStore<'a> {
    db: &'a Database,
}

impl<'a> DocClassEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Create key for event storage
    /// Format: block_height (8 bytes BE) + tx_index (4 bytes BE) + event_index (2 bytes BE)
    fn event_key(block_height: BlockHeight, tx_index: u32, event_index: u16) -> Vec<u8> {
        let mut key = Vec::with_capacity(14);
        key.extend_from_slice(&block_height.to_be_bytes());
        key.extend_from_slice(&tx_index.to_be_bytes());
        key.extend_from_slice(&event_index.to_be_bytes());
        key
    }

    /// Store an event
    pub fn put(&self, block_height: BlockHeight, tx_index: u32, event_index: u16, event: &DocClassEvent) -> Result<()> {
        let key = Self::event_key(block_height, tx_index, event_index);
        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::DOCCLASS_EVENTS, &key, &bytes)
    }

    /// Get events in a block range
    pub fn get_events_in_range(&self, start_height: BlockHeight, end_height: BlockHeight) -> Result<Vec<(BlockHeight, DocClassEvent)>> {
        let mut events = Vec::new();
        let start_key = Self::event_key(start_height, 0, 0);

        for (key, value) in self.db.prefix_iter(cf::DOCCLASS_EVENTS, &start_key[..8])? {
            if key.len() >= 8 {
                let mut height_bytes = [0u8; 8];
                height_bytes.copy_from_slice(&key[..8]);
                let height = BlockHeight::from_be_bytes(height_bytes);

                if height > end_height {
                    break;
                }

                let event: DocClassEvent = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                events.push((height, event));
            }
        }

        Ok(events)
    }

    /// Get events for a specific block
    pub fn get_events_at_height(&self, block_height: BlockHeight) -> Result<Vec<DocClassEvent>> {
        let prefix = block_height.to_be_bytes();
        let mut events = Vec::new();

        for (key, value) in self.db.prefix_iter(cf::DOCCLASS_EVENTS, &prefix)? {
            if key.len() >= 8 && &key[..8] == prefix.as_slice() {
                let event: DocClassEvent = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                events.push(event);
            }
        }

        Ok(events)
    }
}

// =============================================================================
// Combined DocClass Store
// =============================================================================

/// Unified DocClass store providing access to all credential types
pub struct DocClassStore<'a> {
    db: &'a Database,
}

impl<'a> DocClassStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get identity root store
    pub fn identity_roots(&self) -> IdentityRootStore<'_> {
        IdentityRootStore::new(self.db)
    }

    /// Get eligibility store
    pub fn eligibility(&self) -> EligibilityStore<'_> {
        EligibilityStore::new(self.db)
    }

    /// Get academic/professional credential store
    pub fn credentials(&self) -> CredentialStore<'_> {
        CredentialStore::new(self.db)
    }

    /// Get revocation store
    pub fn revocations(&self) -> RevocationStore<'_> {
        RevocationStore::new(self.db)
    }

    /// Get issuer registry store
    pub fn issuers(&self) -> DocClassIssuerStore<'_> {
        DocClassIssuerStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> DocClassEventStore<'_> {
        DocClassEventStore::new(self.db)
    }

    /// Verify a credential is valid at a given time
    /// Checks: exists, not expired, not revoked, issuer is valid
    pub fn verify_credential(&self, credential_id: &CredentialId, current_time: Timestamp) -> Result<bool> {
        // Check eligibility attestations first
        if let Some(attestation) = self.eligibility().get(credential_id)? {
            // Check expiry
            if attestation.expires_at > 0 && attestation.expires_at <= current_time {
                return Ok(false);
            }
            // Check valid from
            if attestation.valid_from > current_time {
                return Ok(false);
            }
            // Check revocation
            if !attestation.revocation_status.is_valid() {
                return Ok(false);
            }
            // Check issuer is still valid
            if !self.issuers().can_issue(&attestation.issuer)? {
                return Ok(false);
            }
            return Ok(true);
        }

        // Check academic credentials
        if let Some(credential) = self.credentials().get(credential_id)? {
            // Check expiry
            if credential.expires_at > 0 && credential.expires_at <= current_time {
                return Ok(false);
            }
            // Check valid from
            if credential.valid_from > current_time {
                return Ok(false);
            }
            // Check revocation
            if !credential.revocation_status.is_valid() {
                return Ok(false);
            }
            // Check issuer is still valid
            if !self.issuers().can_issue(&credential.issuer)? {
                return Ok(false);
            }
            return Ok(true);
        }

        // Credential not found
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use tempfile::TempDir;
    use sumchain_primitives::{
        DocClassIssuerType, EligibilityType, IssuerKey, KeyType,
    };

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    fn sample_issuer(address: Address) -> DocClassIssuer {
        DocClassIssuer {
            address,
            name: "Test Issuer".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![IssuerKey {
                key_id: "key1".to_string(),
                public_key: [1u8; 32],
                key_type: KeyType::Ed25519,
                added_at: 1000,
                expires_at: 0,
                active: true,
                is_primary: true,
            }],
            registered_at: 1000,
            updated_at: 1000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        }
    }

    #[test]
    fn test_issuer_registration() {
        let (db, _dir) = temp_db();
        let store = DocClassIssuerStore::new(&db);

        let addr = Address::new([1u8; 20]);
        let issuer = sample_issuer(addr);

        store.put(&issuer).unwrap();
        assert!(store.is_registered(&addr).unwrap());

        let retrieved = store.get(&addr).unwrap().unwrap();
        assert_eq!(retrieved.name, "Test Issuer");
        assert!(store.can_issue(&addr).unwrap());
    }

    #[test]
    fn test_issuer_subcode_authorization() {
        let (db, _dir) = temp_db();
        let store = DocClassIssuerStore::new(&db);

        let addr = Address::new([1u8; 20]);
        let issuer = sample_issuer(addr);
        store.put(&issuer).unwrap();

        // Can issue authorized subcode in authorized jurisdiction
        assert!(store.can_issue_subcode(&addr, DocSubcode::EligibilityAttestation, "US").unwrap());

        // Cannot issue unauthorized subcode
        assert!(!store.can_issue_subcode(&addr, DocSubcode::Diploma, "US").unwrap());

        // Cannot issue in unauthorized jurisdiction
        assert!(!store.can_issue_subcode(&addr, DocSubcode::EligibilityAttestation, "UK").unwrap());
    }

    #[test]
    fn test_revocation_tracking() {
        let (db, _dir) = temp_db();
        let store = RevocationStore::new(&db);

        let credential_id = [42u8; 32];
        let record = RevocationRecord {
            credential_id,
            status: RevocationStatus::Revoked,
            reason: sumchain_primitives::RevocationReason::KeyCompromise,
            reason_details: Some("Key was leaked".to_string()),
            revoker: Address::new([1u8; 20]),
            revoked_at: 1234567890,
            revoked_at_height: 100,
            superseded_by: None,
            signature: [0u8; 64],
        };

        store.put(&record).unwrap();

        assert!(store.is_revoked(&credential_id).unwrap());
        assert_eq!(store.get_status(&credential_id).unwrap(), RevocationStatus::Revoked);

        let retrieved = store.get_latest(&credential_id).unwrap().unwrap();
        assert_eq!(retrieved.revoked_at_height, 100);
    }

    #[test]
    fn test_eligibility_attestation_storage() {
        let (db, _dir) = temp_db();
        let store = EligibilityStore::new(&db);

        let subject_commitment = [99u8; 32];
        let attestation = EligibilityAttestation {
            credential_id: [1u8; 32],
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment,
            issuer: Address::new([2u8; 20]),
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000,
            valid_from: 1000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };

        store.put(&attestation).unwrap();

        assert!(store.exists(&attestation.credential_id).unwrap());

        let by_subject = store.get_by_subject(&subject_commitment).unwrap();
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_subject[0].credential_id, attestation.credential_id);

        let valid = store.get_valid_for_subject(&subject_commitment, 2000).unwrap();
        assert_eq!(valid.len(), 1);
    }
}

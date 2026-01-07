//! SRC-82X Tax & Compliance Storage Module
//!
//! Provides persistent storage for Tax & Compliance domain:
//! - SRC-821: Tax Claim Type Registry
//! - SRC-822: Tax Issuers
//! - SRC-823: Tax Policies
//! - SRC-824: Tax Proof Envelopes
//! - SRC-825: Tax Disclosure Envelopes

use sumchain_primitives::{
    tax::{
        PolicyId, ProofId, TaxClaimType, TaxClaimTypeEntry, TaxDisclosureEnvelope,
        TaxEvent, TaxIssuer, TaxIssuerStatus, TaxPolicy, TaxProofEnvelope,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// =============================================================================
// Tax Claim Type Registry Storage (SRC-821)
// =============================================================================

/// Storage for Tax Claim Type Registry (SRC-821)
pub struct TaxClaimTypeStore<'a> {
    db: &'a Database,
}

impl<'a> TaxClaimTypeStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Register a new claim type
    pub fn put(&self, entry: &TaxClaimTypeEntry) -> Result<()> {
        let key = entry.claim_type.as_bytes();
        let bytes =
            bincode::serialize(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::TAX_CLAIM_TYPES, key, &bytes)
    }

    /// Get a claim type entry
    pub fn get(&self, claim_type: &TaxClaimType) -> Result<Option<TaxClaimTypeEntry>> {
        match self.db.get(cf::TAX_CLAIM_TYPES, claim_type.as_bytes())? {
            Some(bytes) => {
                let entry: TaxClaimTypeEntry = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Check if claim type exists
    pub fn exists(&self, claim_type: &TaxClaimType) -> Result<bool> {
        self.db.contains(cf::TAX_CLAIM_TYPES, claim_type.as_bytes())
    }

    /// List all registered claim types
    pub fn list_all(&self) -> Result<Vec<TaxClaimTypeEntry>> {
        let mut entries = Vec::new();
        for (_, value) in self.db.iter(cf::TAX_CLAIM_TYPES)? {
            let entry: TaxClaimTypeEntry = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// List claim types by prefix (e.g., "tax.filed." returns all filing-related types)
    pub fn list_by_prefix(&self, prefix: &str) -> Result<Vec<TaxClaimTypeEntry>> {
        let mut entries = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::TAX_CLAIM_TYPES, prefix.as_bytes())? {
            let entry: TaxClaimTypeEntry = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Deprecate a claim type
    pub fn deprecate(
        &self,
        claim_type: &TaxClaimType,
        deprecated_at: Timestamp,
    ) -> Result<()> {
        match self.get(claim_type)? {
            Some(mut entry) => {
                entry.status = sumchain_primitives::tax::ClaimTypeStatus::Deprecated;
                self.put(&entry)
            }
            None => Err(StorageError::NotFound(format!(
                "Claim type not found: {}",
                claim_type
            ))),
        }
    }
}

// =============================================================================
// Tax Issuer Storage (SRC-822)
// =============================================================================

/// Storage for Tax Issuers (SRC-822)
/// Keyed by issuer address
pub struct TaxIssuerStore<'a> {
    db: &'a Database,
}

impl<'a> TaxIssuerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Register a tax issuer (keyed by address)
    pub fn put(&self, issuer: &TaxIssuer) -> Result<()> {
        let bytes =
            bincode::serialize(issuer).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::TAX_ISSUERS, issuer.address.as_ref(), &bytes)
    }

    /// Get a tax issuer by address
    pub fn get(&self, address: &Address) -> Result<Option<TaxIssuer>> {
        match self.db.get(cf::TAX_ISSUERS, address.as_ref())? {
            Some(bytes) => {
                let issuer: TaxIssuer = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(issuer))
            }
            None => Ok(None),
        }
    }

    /// Get tax issuer by address (alias for get)
    pub fn get_by_address(&self, address: &Address) -> Result<Option<TaxIssuer>> {
        self.get(address)
    }

    /// Check if issuer exists
    pub fn exists(&self, address: &Address) -> Result<bool> {
        self.db.contains(cf::TAX_ISSUERS, address.as_ref())
    }

    /// Update issuer status
    pub fn update_status(
        &self,
        address: &Address,
        status: TaxIssuerStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(address)? {
            Some(mut issuer) => {
                issuer.status = status;
                issuer.updated_at = timestamp;
                self.put(&issuer)
            }
            None => Err(StorageError::NotFound(format!(
                "Issuer not found: {:?}",
                address
            ))),
        }
    }

    /// List all issuers by class
    pub fn list_by_class(
        &self,
        class: sumchain_primitives::tax::TaxIssuerClass,
    ) -> Result<Vec<TaxIssuer>> {
        let mut issuers = Vec::new();
        for (_, value) in self.db.iter(cf::TAX_ISSUERS)? {
            let issuer: TaxIssuer = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if issuer.tax_class == class {
                issuers.push(issuer);
            }
        }
        Ok(issuers)
    }

    /// List all active issuers
    pub fn list_active(&self) -> Result<Vec<TaxIssuer>> {
        let mut issuers = Vec::new();
        for (_, value) in self.db.iter(cf::TAX_ISSUERS)? {
            let issuer: TaxIssuer = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if issuer.status == TaxIssuerStatus::Active {
                issuers.push(issuer);
            }
        }
        Ok(issuers)
    }
}

// =============================================================================
// Tax Policy Storage (SRC-823)
// =============================================================================

/// Storage for Tax Policies (SRC-823)
pub struct TaxPolicyStore<'a> {
    db: &'a Database,
}

impl<'a> TaxPolicyStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a tax policy
    pub fn put(&self, policy: &TaxPolicy) -> Result<()> {
        let bytes =
            bincode::serialize(policy).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::TAX_POLICIES, &policy.policy_id, &bytes)
    }

    /// Get a tax policy by ID
    pub fn get(&self, policy_id: &PolicyId) -> Result<Option<TaxPolicy>> {
        match self.db.get(cf::TAX_POLICIES, policy_id)? {
            Some(bytes) => {
                let policy: TaxPolicy = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(policy))
            }
            None => Ok(None),
        }
    }

    /// Check if policy exists
    pub fn exists(&self, policy_id: &PolicyId) -> Result<bool> {
        self.db.contains(cf::TAX_POLICIES, policy_id)
    }

    /// List all policies
    pub fn list_all(&self) -> Result<Vec<TaxPolicy>> {
        let mut policies = Vec::new();
        for (_, value) in self.db.iter(cf::TAX_POLICIES)? {
            let policy: TaxPolicy = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            policies.push(policy);
        }
        Ok(policies)
    }

    /// List policies by template type
    pub fn list_by_template(
        &self,
        template: sumchain_primitives::tax::TaxPolicyTemplate,
    ) -> Result<Vec<TaxPolicy>> {
        let mut policies = Vec::new();
        for (_, value) in self.db.iter(cf::TAX_POLICIES)? {
            let policy: TaxPolicy = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if policy.template == template {
                policies.push(policy);
            }
        }
        Ok(policies)
    }
}

// =============================================================================
// Tax Proof Storage (SRC-824)
// =============================================================================

/// Storage for Tax Proof Envelopes (SRC-824)
pub struct TaxProofStore<'a> {
    db: &'a Database,
}

impl<'a> TaxProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a tax proof envelope
    pub fn put(&self, proof: &TaxProofEnvelope) -> Result<()> {
        let bytes =
            bincode::serialize(proof).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::TAX_PROOFS, &proof.proof_id, &bytes)?;

        // Index by subject nullifier
        self.add_to_subject_index(&proof.subject_nullifier, &proof.proof_id)?;

        Ok(())
    }

    /// Get a tax proof envelope by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<TaxProofEnvelope>> {
        match self.db.get(cf::TAX_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: TaxProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::TAX_PROOFS, proof_id)
    }

    /// Delete a proof
    pub fn delete(&self, proof_id: &ProofId) -> Result<()> {
        self.db.delete(cf::TAX_PROOFS, proof_id)
    }

    /// Get proofs by subject nullifier
    pub fn get_by_subject(&self, subject_nullifier: &[u8; 32]) -> Result<Vec<TaxProofEnvelope>> {
        let proof_ids = self.get_subject_proof_ids(subject_nullifier)?;
        let mut proofs = Vec::new();
        for proof_id in proof_ids {
            if let Some(proof) = self.get(&proof_id)? {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }

    /// Get valid proofs for a subject (not expired)
    pub fn get_valid_for_subject(
        &self,
        subject_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<TaxProofEnvelope>> {
        let proofs = self.get_by_subject(subject_nullifier)?;
        Ok(proofs
            .into_iter()
            .filter(|p| p.expires_at == 0 || p.expires_at > current_time)
            .collect())
    }

    /// Get proofs by profile ID
    pub fn get_by_profile(&self, profile_id: &str) -> Result<Vec<TaxProofEnvelope>> {
        let mut proofs = Vec::new();
        for (_, value) in self.db.iter(cf::TAX_PROOFS)? {
            let proof: TaxProofEnvelope = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if proof.profile_id == profile_id {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }

    // Index helpers
    fn add_to_subject_index(
        &self,
        subject_nullifier: &[u8; 32],
        proof_id: &ProofId,
    ) -> Result<()> {
        let mut proof_ids = self.get_subject_proof_ids(subject_nullifier)?;
        if !proof_ids.contains(proof_id) {
            proof_ids.push(*proof_id);
            let bytes = bincode::serialize(&proof_ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db
                .put(cf::TAX_SUBJECT_INDEX, subject_nullifier, &bytes)?;
        }
        Ok(())
    }

    fn get_subject_proof_ids(&self, subject_nullifier: &[u8; 32]) -> Result<Vec<ProofId>> {
        match self.db.get(cf::TAX_SUBJECT_INDEX, subject_nullifier)? {
            Some(bytes) => {
                let proof_ids: Vec<ProofId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(proof_ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Tax Disclosure Storage (SRC-825)
// =============================================================================

/// Storage for Tax Disclosure Envelopes (SRC-825)
/// Keyed by payload_hash
pub struct TaxDisclosureStore<'a> {
    db: &'a Database,
}

impl<'a> TaxDisclosureStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a tax disclosure envelope (keyed by payload_hash)
    pub fn put(&self, disclosure: &TaxDisclosureEnvelope) -> Result<()> {
        let bytes = bincode::serialize(disclosure)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db
            .put(cf::TAX_DISCLOSURES, &disclosure.payload_hash, &bytes)
    }

    /// Get a disclosure envelope by payload hash
    pub fn get(&self, payload_hash: &[u8; 32]) -> Result<Option<TaxDisclosureEnvelope>> {
        match self.db.get(cf::TAX_DISCLOSURES, payload_hash)? {
            Some(bytes) => {
                let disclosure: TaxDisclosureEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(disclosure))
            }
            None => Ok(None),
        }
    }

    /// Check if disclosure exists
    pub fn exists(&self, payload_hash: &[u8; 32]) -> Result<bool> {
        self.db.contains(cf::TAX_DISCLOSURES, payload_hash)
    }

    /// Delete a disclosure
    pub fn delete(&self, payload_hash: &[u8; 32]) -> Result<()> {
        self.db.delete(cf::TAX_DISCLOSURES, payload_hash)
    }

    /// Get disclosures by proof ID
    pub fn get_by_proof(&self, proof_id: &ProofId) -> Result<Vec<TaxDisclosureEnvelope>> {
        let mut disclosures = Vec::new();
        for (_, value) in self.db.iter(cf::TAX_DISCLOSURES)? {
            let disclosure: TaxDisclosureEnvelope = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if disclosure.proof_id.as_ref() == Some(proof_id) {
                disclosures.push(disclosure);
            }
        }
        Ok(disclosures)
    }
}

// =============================================================================
// Tax Event Storage
// =============================================================================

/// Storage for Tax Events (indexing and audit trail)
pub struct TaxEventStore<'a> {
    db: &'a Database,
}

impl<'a> TaxEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a tax event
    pub fn put(&self, block_height: BlockHeight, event_index: u32, event: &TaxEvent) -> Result<()> {
        let key = Self::make_key(block_height, event_index);
        let bytes =
            bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::TAX_EVENTS, &key, &bytes)
    }

    /// Get events for a block
    pub fn get_by_block(&self, block_height: BlockHeight) -> Result<Vec<TaxEvent>> {
        let prefix = block_height.to_be_bytes();
        let mut events = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::TAX_EVENTS, &prefix)? {
            let event: TaxEvent = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }

    /// Get events in a block range
    pub fn get_by_range(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
    ) -> Result<Vec<TaxEvent>> {
        let mut events = Vec::new();
        for height in start_height..=end_height {
            events.extend(self.get_by_block(height)?);
        }
        Ok(events)
    }

    fn make_key(block_height: BlockHeight, event_index: u32) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&block_height.to_be_bytes());
        key[8..].copy_from_slice(&event_index.to_be_bytes());
        key
    }
}

// =============================================================================
// Unified Tax Store
// =============================================================================

/// Unified access to all SRC-82X storage
pub struct TaxStore<'a> {
    db: &'a Database,
}

impl<'a> TaxStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn claim_types(&self) -> TaxClaimTypeStore<'a> {
        TaxClaimTypeStore::new(self.db)
    }

    pub fn issuers(&self) -> TaxIssuerStore<'a> {
        TaxIssuerStore::new(self.db)
    }

    pub fn policies(&self) -> TaxPolicyStore<'a> {
        TaxPolicyStore::new(self.db)
    }

    pub fn proofs(&self) -> TaxProofStore<'a> {
        TaxProofStore::new(self.db)
    }

    pub fn disclosures(&self) -> TaxDisclosureStore<'a> {
        TaxDisclosureStore::new(self.db)
    }

    pub fn events(&self) -> TaxEventStore<'a> {
        TaxEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::tax::{
        ClaimTypeStatus, DisclosureContentType, IssuerRequirements, QuorumRule,
        TaxIssuerClass, TaxPolicyTemplate, TaxProofType, TaxRiskLevel,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_claim_type_store() {
        let (db, _dir) = temp_db();
        let store = TaxClaimTypeStore::new(&db);

        let entry = TaxClaimTypeEntry {
            claim_type: "tax.filed.return".to_string(),
            schema_hash: [1u8; 32],
            risk_level: TaxRiskLevel::Medium,
            recommended_validity_secs: 31536000,
            required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: 1000,
            updated_at: 1000,
        };

        store.put(&entry).unwrap();
        let retrieved = store.get(&"tax.filed.return".to_string()).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().claim_type, "tax.filed.return");
    }

    #[test]
    fn test_issuer_store() {
        let (db, _dir) = temp_db();
        let store = TaxIssuerStore::new(&db);

        let issuer = TaxIssuer {
            address: Address::from([3u8; 20]),
            tax_class: TaxIssuerClass::TaxAuthority,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [4u8; 32],
            attributes_schema_hash: [5u8; 32],
            registered_at: 1000,
            updated_at: 1000,
            status: TaxIssuerStatus::Active,
            expires_at: None,
        };

        store.put(&issuer).unwrap();
        let retrieved = store.get_by_address(&issuer.address).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tax_class, TaxIssuerClass::TaxAuthority);
    }

    #[test]
    fn test_policy_store() {
        let (db, _dir) = temp_db();
        let store = TaxPolicyStore::new(&db);

        let policy = TaxPolicy {
            policy_id: [5u8; 32],
            template: TaxPolicyTemplate::Filed,
            claim_types: vec!["tax.filed.return".to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![vec![TaxIssuerClass::TaxAuthority]],
                quorum: QuorumRule::Any,
            },
            jurisdictions: vec!["US".to_string()],
            tax_years: vec![2024],
            max_age_secs: 31536000,
            revocation_check: true,
            creator: Address::from([3u8; 20]),
            created_at: 1000,
        };

        store.put(&policy).unwrap();
        let retrieved = store.get(&[5u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().template, TaxPolicyTemplate::Filed);
    }

    #[test]
    fn test_proof_store() {
        let (db, _dir) = temp_db();
        let store = TaxProofStore::new(&db);

        let proof = TaxProofEnvelope {
            proof_id: [6u8; 32],
            profile_id: "tax.filed.v1".to_string(),
            policy_ids: vec![[5u8; 32]],
            claim_ids: vec![[7u8; 32]],
            public_inputs: vec![1, 2, 3, 4],
            proof_data: vec![5, 6, 7, 8],
            proof_type: TaxProofType::Mock,
            subject_nullifier: [8u8; 32],
            generated_at: 1000,
            expires_at: 2000,
        };

        store.put(&proof).unwrap();

        // Get by ID
        let retrieved = store.get(&[6u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_id, "tax.filed.v1");

        // Get by subject nullifier
        let by_subject = store.get_by_subject(&[8u8; 32]).unwrap();
        assert_eq!(by_subject.len(), 1);
    }

    #[test]
    fn test_disclosure_store() {
        let (db, _dir) = temp_db();
        let store = TaxDisclosureStore::new(&db);

        let disclosure = TaxDisclosureEnvelope {
            payload_hash: [10u8; 32],
            payload_size: 1024,
            hint_uri: Some("ipfs://QmTest".to_string()),
            encryption_meta: None,
            content_type: DisclosureContentType::TaxReturn,
            claim_id: Some([7u8; 32]),
            proof_id: Some([6u8; 32]),
            created_at: 1000,
        };

        store.put(&disclosure).unwrap();
        let retrieved = store.get(&[10u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().payload_size, 1024);

        // Get by proof ID
        let by_proof = store.get_by_proof(&[6u8; 32]).unwrap();
        assert_eq!(by_proof.len(), 1);
    }
}

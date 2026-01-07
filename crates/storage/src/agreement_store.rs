//! SRC-84X Agreement & IP Storage
//!
//! Storage layer for:
//! - SRC-841: Agreement Commitments
//! - SRC-842: Party Signatures
//! - SRC-843: Notary Attestations
//! - SRC-844: IP Rights Actions
//! - SRC-845: Executor Links
//! - SRC-846: Agreement Proofs

use sumchain_primitives::{
    agreement::{
        AgreementCommitment, AgreementEvent, AgreementProofEnvelope, AgreementStatus,
        AttestationId, AttestationPacket, AttestationStatus, ExecutorLink, ExecutorLinkId,
        ExecutorState, IpActionStatus, IpAssetId, IpRightsAction, PartySignature, SignatureId,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// Type aliases for clarity
pub type AgreementId = [u8; 32];
pub type ProofId = [u8; 32];

// =============================================================================
// Agreement Commitment Storage (SRC-841)
// =============================================================================

/// Storage for Agreement Commitments (SRC-841)
pub struct AgreementCommitmentStore<'a> {
    db: &'a Database,
}

impl<'a> AgreementCommitmentStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an agreement commitment
    pub fn put(&self, agreement: &AgreementCommitment) -> Result<()> {
        let bytes = bincode::serialize(agreement)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::AGREEMENT_COMMITMENTS, &agreement.agreement_id, &bytes)?;

        // Update party indexes
        for party in &agreement.parties {
            self.add_to_party_index(&party.party_ref.as_hash(), &agreement.agreement_id)?;
        }

        Ok(())
    }

    /// Get an agreement by ID
    pub fn get(&self, agreement_id: &AgreementId) -> Result<Option<AgreementCommitment>> {
        match self.db.get(cf::AGREEMENT_COMMITMENTS, agreement_id)? {
            Some(bytes) => {
                let agreement: AgreementCommitment = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(agreement))
            }
            None => Ok(None),
        }
    }

    /// Check if agreement exists
    pub fn exists(&self, agreement_id: &AgreementId) -> Result<bool> {
        self.db.contains(cf::AGREEMENT_COMMITMENTS, agreement_id)
    }

    /// Update agreement status
    pub fn update_status(
        &self,
        agreement_id: &AgreementId,
        status: AgreementStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(agreement_id)? {
            Some(mut agreement) => {
                agreement.status = status;
                agreement.updated_at = timestamp;
                let bytes = bincode::serialize(&agreement)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::AGREEMENT_COMMITMENTS, agreement_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Agreement not found: {:?}",
                agreement_id
            ))),
        }
    }

    /// Get agreements by party reference hash
    pub fn get_by_party(&self, party_ref_hash: &[u8; 32]) -> Result<Vec<AgreementCommitment>> {
        let agreement_ids = self.get_party_agreement_ids(party_ref_hash)?;
        let mut agreements = Vec::new();
        for id in agreement_ids {
            if let Some(agreement) = self.get(&id)? {
                agreements.push(agreement);
            }
        }
        Ok(agreements)
    }

    /// List active agreements
    pub fn list_active(&self) -> Result<Vec<AgreementCommitment>> {
        let mut agreements = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_COMMITMENTS)? {
            let agreement: AgreementCommitment = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if matches!(
                agreement.status,
                AgreementStatus::Active | AgreementStatus::Executed | AgreementStatus::PendingSignatures
            ) {
                agreements.push(agreement);
            }
        }
        Ok(agreements)
    }

    /// Mark party as signed in agreement
    pub fn mark_party_signed(
        &self,
        agreement_id: &AgreementId,
        party_ref_hash: &[u8; 32],
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(agreement_id)? {
            Some(mut agreement) => {
                for party in &mut agreement.parties {
                    if party.party_ref.as_hash() == *party_ref_hash {
                        party.signed = true;
                        party.signed_at = Some(timestamp);
                    }
                }
                agreement.updated_at = timestamp;

                // Check if all parties signed
                if agreement.is_fully_signed() && agreement.status == AgreementStatus::PendingSignatures {
                    agreement.status = AgreementStatus::Executed;
                }

                let bytes = bincode::serialize(&agreement)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::AGREEMENT_COMMITMENTS, agreement_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Agreement not found: {:?}",
                agreement_id
            ))),
        }
    }

    // Index helpers
    fn add_to_party_index(&self, party_ref_hash: &[u8; 32], agreement_id: &AgreementId) -> Result<()> {
        let mut ids = self.get_party_agreement_ids(party_ref_hash)?;
        if !ids.contains(agreement_id) {
            ids.push(*agreement_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::AGREEMENT_PARTY_INDEX, party_ref_hash, &bytes)?;
        }
        Ok(())
    }

    fn get_party_agreement_ids(&self, party_ref_hash: &[u8; 32]) -> Result<Vec<AgreementId>> {
        match self.db.get(cf::AGREEMENT_PARTY_INDEX, party_ref_hash)? {
            Some(bytes) => {
                let ids: Vec<AgreementId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Party Signature Storage (SRC-842)
// =============================================================================

/// Storage for Party Signatures (SRC-842)
pub struct SignatureStore<'a> {
    db: &'a Database,
}

impl<'a> SignatureStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a signature
    pub fn put(&self, signature: &PartySignature) -> Result<()> {
        let bytes = bincode::serialize(signature)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::AGREEMENT_SIGNATURES, &signature.signature_id, &bytes)
    }

    /// Get a signature by ID
    pub fn get(&self, signature_id: &SignatureId) -> Result<Option<PartySignature>> {
        match self.db.get(cf::AGREEMENT_SIGNATURES, signature_id)? {
            Some(bytes) => {
                let sig: PartySignature = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(sig))
            }
            None => Ok(None),
        }
    }

    /// Check if signature exists
    pub fn exists(&self, signature_id: &SignatureId) -> Result<bool> {
        self.db.contains(cf::AGREEMENT_SIGNATURES, signature_id)
    }

    /// Delete a signature (for revocation)
    pub fn delete(&self, signature_id: &SignatureId) -> Result<()> {
        self.db.delete(cf::AGREEMENT_SIGNATURES, signature_id)
    }

    /// Get signatures for an agreement
    pub fn get_by_agreement(&self, agreement_id: &AgreementId) -> Result<Vec<PartySignature>> {
        let mut signatures = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_SIGNATURES)? {
            let sig: PartySignature = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if sig.agreement_id == *agreement_id {
                signatures.push(sig);
            }
        }
        Ok(signatures)
    }
}

// =============================================================================
// Attestation Storage (SRC-843)
// =============================================================================

/// Storage for Attestation Packets (SRC-843)
pub struct AttestationStore<'a> {
    db: &'a Database,
}

impl<'a> AttestationStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an attestation
    pub fn put(&self, attestation: &AttestationPacket) -> Result<()> {
        let bytes = bincode::serialize(attestation)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::AGREEMENT_ATTESTATIONS, &attestation.attestation_id, &bytes)
    }

    /// Get an attestation by ID
    pub fn get(&self, attestation_id: &AttestationId) -> Result<Option<AttestationPacket>> {
        match self.db.get(cf::AGREEMENT_ATTESTATIONS, attestation_id)? {
            Some(bytes) => {
                let att: AttestationPacket = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(att))
            }
            None => Ok(None),
        }
    }

    /// Check if attestation exists
    pub fn exists(&self, attestation_id: &AttestationId) -> Result<bool> {
        self.db.contains(cf::AGREEMENT_ATTESTATIONS, attestation_id)
    }

    /// Update attestation status
    pub fn update_status(
        &self,
        attestation_id: &AttestationId,
        status: AttestationStatus,
    ) -> Result<()> {
        match self.get(attestation_id)? {
            Some(mut att) => {
                att.status = status;
                let bytes = bincode::serialize(&att)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::AGREEMENT_ATTESTATIONS, attestation_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Attestation not found: {:?}",
                attestation_id
            ))),
        }
    }

    /// Get attestations by issuer
    pub fn get_by_issuer(&self, issuer: &Address) -> Result<Vec<AttestationPacket>> {
        let mut attestations = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_ATTESTATIONS)? {
            let att: AttestationPacket = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if att.issuer_address == *issuer {
                attestations.push(att);
            }
        }
        Ok(attestations)
    }

    /// Get active attestations
    pub fn list_active(&self) -> Result<Vec<AttestationPacket>> {
        let mut attestations = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_ATTESTATIONS)? {
            let att: AttestationPacket = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if att.status == AttestationStatus::Active {
                attestations.push(att);
            }
        }
        Ok(attestations)
    }
}

// =============================================================================
// IP Rights Action Storage (SRC-844)
// =============================================================================

/// Storage for IP Rights Actions (SRC-844)
pub struct IpActionStore<'a> {
    db: &'a Database,
}

impl<'a> IpActionStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an IP action
    pub fn put(&self, action: &IpRightsAction) -> Result<()> {
        let bytes = bincode::serialize(action)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::AGREEMENT_IP_ACTIONS, &action.action_id, &bytes)
    }

    /// Get an IP action by ID
    pub fn get(&self, action_id: &IpAssetId) -> Result<Option<IpRightsAction>> {
        match self.db.get(cf::AGREEMENT_IP_ACTIONS, action_id)? {
            Some(bytes) => {
                let action: IpRightsAction = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(action))
            }
            None => Ok(None),
        }
    }

    /// Check if IP action exists
    pub fn exists(&self, action_id: &IpAssetId) -> Result<bool> {
        self.db.contains(cf::AGREEMENT_IP_ACTIONS, action_id)
    }

    /// Update IP action status
    pub fn update_status(
        &self,
        action_id: &IpAssetId,
        status: IpActionStatus,
    ) -> Result<()> {
        match self.get(action_id)? {
            Some(mut action) => {
                action.status = status;
                let bytes = bincode::serialize(&action)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::AGREEMENT_IP_ACTIONS, action_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "IP action not found: {:?}",
                action_id
            ))),
        }
    }

    /// Get IP actions by rightsholder
    pub fn get_by_rightsholder(&self, rightsholder_hash: &[u8; 32]) -> Result<Vec<IpRightsAction>> {
        let mut actions = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_IP_ACTIONS)? {
            let action: IpRightsAction = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if action.rightsholder_ref.as_hash() == *rightsholder_hash {
                actions.push(action);
            }
        }
        Ok(actions)
    }

    /// Get active IP actions
    pub fn list_active(&self) -> Result<Vec<IpRightsAction>> {
        let mut actions = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_IP_ACTIONS)? {
            let action: IpRightsAction = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if action.status == IpActionStatus::Active {
                actions.push(action);
            }
        }
        Ok(actions)
    }
}

// =============================================================================
// Executor Link Storage (SRC-845)
// =============================================================================

/// Storage for Executor Links (SRC-845)
pub struct ExecutorLinkStore<'a> {
    db: &'a Database,
}

impl<'a> ExecutorLinkStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an executor link
    pub fn put(&self, link: &ExecutorLink) -> Result<()> {
        let bytes = bincode::serialize(link)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::AGREEMENT_EXECUTOR_LINKS, &link.link_id, &bytes)?;

        // Update executor index
        self.add_to_executor_index(&link.executor_contract, &link.link_id)?;

        Ok(())
    }

    /// Get an executor link by ID
    pub fn get(&self, link_id: &ExecutorLinkId) -> Result<Option<ExecutorLink>> {
        match self.db.get(cf::AGREEMENT_EXECUTOR_LINKS, link_id)? {
            Some(bytes) => {
                let link: ExecutorLink = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(link))
            }
            None => Ok(None),
        }
    }

    /// Check if executor link exists
    pub fn exists(&self, link_id: &ExecutorLinkId) -> Result<bool> {
        self.db.contains(cf::AGREEMENT_EXECUTOR_LINKS, link_id)
    }

    /// Update executor link state
    pub fn update_state(
        &self,
        link_id: &ExecutorLinkId,
        state: ExecutorState,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(link_id)? {
            Some(mut link) => {
                link.state = state;
                link.updated_at = timestamp;
                let bytes = bincode::serialize(&link)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::AGREEMENT_EXECUTOR_LINKS, link_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Executor link not found: {:?}",
                link_id
            ))),
        }
    }

    /// Get executor links by agreement
    pub fn get_by_agreement(&self, agreement_id: &AgreementId) -> Result<Vec<ExecutorLink>> {
        let mut links = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_EXECUTOR_LINKS)? {
            let link: ExecutorLink = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if link.agreement_id == *agreement_id {
                links.push(link);
            }
        }
        Ok(links)
    }

    /// Get executor links by executor contract
    pub fn get_by_executor(&self, executor: &Address) -> Result<Vec<ExecutorLink>> {
        let link_ids = self.get_executor_link_ids(executor)?;
        let mut links = Vec::new();
        for id in link_ids {
            if let Some(link) = self.get(&id)? {
                links.push(link);
            }
        }
        Ok(links)
    }

    /// Get active executor links
    pub fn list_active(&self) -> Result<Vec<ExecutorLink>> {
        let mut links = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_EXECUTOR_LINKS)? {
            let link: ExecutorLink = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if link.state == ExecutorState::Active {
                links.push(link);
            }
        }
        Ok(links)
    }

    // Index helpers
    fn add_to_executor_index(&self, executor: &Address, link_id: &ExecutorLinkId) -> Result<()> {
        let mut ids = self.get_executor_link_ids(executor)?;
        if !ids.contains(link_id) {
            ids.push(*link_id);
            let bytes = bincode::serialize(&ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::AGREEMENT_EXECUTOR_INDEX, executor.as_ref(), &bytes)?;
        }
        Ok(())
    }

    fn get_executor_link_ids(&self, executor: &Address) -> Result<Vec<ExecutorLinkId>> {
        match self.db.get(cf::AGREEMENT_EXECUTOR_INDEX, executor.as_ref())? {
            Some(bytes) => {
                let ids: Vec<ExecutorLinkId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Agreement Proof Storage (SRC-846)
// =============================================================================

/// Storage for Agreement Proofs (SRC-846)
pub struct AgreementProofStore<'a> {
    db: &'a Database,
}

impl<'a> AgreementProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a proof
    pub fn put(&self, proof: &AgreementProofEnvelope) -> Result<()> {
        let bytes = bincode::serialize(proof)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::AGREEMENT_PROOFS, &proof.proof_id, &bytes)
    }

    /// Get a proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<AgreementProofEnvelope>> {
        match self.db.get(cf::AGREEMENT_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: AgreementProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::AGREEMENT_PROOFS, proof_id)
    }

    /// Delete a proof
    pub fn delete(&self, proof_id: &ProofId) -> Result<()> {
        self.db.delete(cf::AGREEMENT_PROOFS, proof_id)
    }

    /// Get valid proofs for subject (not expired)
    pub fn get_valid_for_subject(
        &self,
        subject_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<AgreementProofEnvelope>> {
        let mut proofs = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_PROOFS)? {
            let proof: AgreementProofEnvelope = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if proof.subject_nullifier == *subject_nullifier
                && (proof.expires_at == 0 || proof.expires_at > current_time)
            {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }

    /// Get proofs by profile ID
    pub fn get_by_profile(&self, profile_id: &str) -> Result<Vec<AgreementProofEnvelope>> {
        let mut proofs = Vec::new();
        for (_, value) in self.db.iter(cf::AGREEMENT_PROOFS)? {
            let proof: AgreementProofEnvelope = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if proof.profile_id == profile_id {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }
}

// =============================================================================
// Agreement Event Storage
// =============================================================================

/// Storage for Agreement Events
pub struct AgreementEventStore<'a> {
    db: &'a Database,
}

impl<'a> AgreementEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an event
    pub fn put(&self, block_height: BlockHeight, tx_index: u32, event: &AgreementEvent) -> Result<()> {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&block_height.to_be_bytes());
        key[8..12].copy_from_slice(&tx_index.to_be_bytes());

        let bytes = bincode::serialize(event)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::AGREEMENT_EVENTS, &key, &bytes)
    }

    /// Get events by block height range
    pub fn get_by_height_range(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
    ) -> Result<Vec<(BlockHeight, u32, AgreementEvent)>> {
        let mut events = Vec::new();
        for (key, value) in self.db.iter(cf::AGREEMENT_EVENTS)? {
            if key.len() < 12 {
                continue;
            }
            let mut height_bytes = [0u8; 8];
            let mut idx_bytes = [0u8; 4];
            height_bytes.copy_from_slice(&key[..8]);
            idx_bytes.copy_from_slice(&key[8..12]);

            let height = u64::from_be_bytes(height_bytes);
            let idx = u32::from_be_bytes(idx_bytes);

            if height >= start_height && height <= end_height {
                let event: AgreementEvent = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                events.push((height, idx, event));
            }
        }
        Ok(events)
    }
}

// =============================================================================
// Main Agreement Store (Facade)
// =============================================================================

/// Main facade for all SRC-84X storage operations
pub struct AgreementStore<'a> {
    db: &'a Database,
}

impl<'a> AgreementStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get agreement commitment store
    pub fn agreements(&self) -> AgreementCommitmentStore {
        AgreementCommitmentStore::new(self.db)
    }

    /// Get signature store
    pub fn signatures(&self) -> SignatureStore {
        SignatureStore::new(self.db)
    }

    /// Get attestation store
    pub fn attestations(&self) -> AttestationStore {
        AttestationStore::new(self.db)
    }

    /// Get IP action store
    pub fn ip_actions(&self) -> IpActionStore {
        IpActionStore::new(self.db)
    }

    /// Get executor link store
    pub fn executor_links(&self) -> ExecutorLinkStore {
        ExecutorLinkStore::new(self.db)
    }

    /// Get proof store
    pub fn proofs(&self) -> AgreementProofStore {
        AgreementProofStore::new(self.db)
    }

    /// Get event store
    pub fn events(&self) -> AgreementEventStore {
        AgreementEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::agreement::{
        AgreementRole, AttestationTarget, AttestationType, AttestationIssuerClass,
        IpActionType, IpAssetType, PartyBinding, PartyRef, AgreementProofProfile,
        AgreementProofType,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_agreement_commitment_store() {
        let (db, _dir) = temp_db();
        let store = AgreementCommitmentStore::new(&db);

        let party1 = PartyBinding {
            party_ref: PartyRef::Commitment([1u8; 32]),
            role: AgreementRole::Buyer,
            signed: false,
            signed_at: None,
        };
        let party2 = PartyBinding {
            party_ref: PartyRef::Commitment([2u8; 32]),
            role: AgreementRole::Seller,
            signed: false,
            signed_at: None,
        };

        let agreement = AgreementCommitment {
            agreement_id: [10u8; 32],
            agreement_commitment: [11u8; 32],
            parties: vec![party1, party2],
            jurisdiction_code: "US-DE".to_string(),
            effective_from: Some(1000),
            expiry: Some(2000),
            attachments: vec![],
            policy_id: [12u8; 32],
            status: AgreementStatus::PendingSignatures,
            created_at: 1000,
            updated_at: 1000,
            created_at_height: 100,
            supersedes: None,
        };

        store.put(&agreement).unwrap();
        let retrieved = store.get(&[10u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().jurisdiction_code, "US-DE");

        // Test party index
        let by_party = store.get_by_party(&[1u8; 32]).unwrap();
        assert_eq!(by_party.len(), 1);
    }

    #[test]
    fn test_signature_store() {
        let (db, _dir) = temp_db();
        let store = SignatureStore::new(&db);

        let sig = PartySignature {
            signature_id: [20u8; 32],
            agreement_id: [10u8; 32],
            party_ref: PartyRef::Commitment([1u8; 32]),
            role: AgreementRole::Buyer,
            signature_type: sumchain_primitives::agreement::SignatureType::Single,
            signature: vec![1, 2, 3, 4],
            signer_key: [21u8; 32],
            signed_at: 1000,
            recorded_at_height: 100,
            witness_attestation_id: None,
        };

        store.put(&sig).unwrap();
        let retrieved = store.get(&[20u8; 32]).unwrap();
        assert!(retrieved.is_some());

        let by_agreement = store.get_by_agreement(&[10u8; 32]).unwrap();
        assert_eq!(by_agreement.len(), 1);
    }

    #[test]
    fn test_attestation_store() {
        let (db, _dir) = temp_db();
        let store = AttestationStore::new(&db);

        let attestation = AttestationPacket {
            attestation_id: [30u8; 32],
            target_ref: AttestationTarget::Agreement([10u8; 32]),
            issuer_address: Address::new([5u8; 20]),
            issuer_class: AttestationIssuerClass::NotaryPublic,
            attestation_type: AttestationType::Notarization,
            notary_commitment: [31u8; 32],
            jurisdiction_code: "US-NY".to_string(),
            valid_from: 1000,
            expiry: Some(2000),
            revocation_ref: None,
            status: AttestationStatus::Active,
            created_at: 1000,
            recorded_at_height: 100,
            policy_id: [32u8; 32],
        };

        store.put(&attestation).unwrap();
        let retrieved = store.get(&[30u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().jurisdiction_code, "US-NY");
    }

    #[test]
    fn test_ip_action_store() {
        let (db, _dir) = temp_db();
        let store = IpActionStore::new(&db);

        let action = IpRightsAction {
            action_id: [40u8; 32],
            ip_asset_commitment: [41u8; 32],
            asset_type: IpAssetType::Patent,
            action_type: IpActionType::Assignment,
            scope_commitment: [42u8; 32],
            rightsholder_ref: PartyRef::Commitment([1u8; 32]),
            counterparty_ref: Some(PartyRef::Commitment([2u8; 32])),
            policy_id: [43u8; 32],
            valid_from: 1000,
            expiry: None,
            revocation_ref: None,
            status: IpActionStatus::Active,
            created_at: 1000,
            recorded_at_height: 100,
            agreement_id: Some([10u8; 32]),
            attachments: vec![],
        };

        store.put(&action).unwrap();
        let retrieved = store.get(&[40u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().asset_type, IpAssetType::Patent);
    }

    #[test]
    fn test_executor_link_store() {
        let (db, _dir) = temp_db();
        let store = ExecutorLinkStore::new(&db);

        let link = ExecutorLink {
            link_id: [50u8; 32],
            agreement_id: [10u8; 32],
            executor_contract: Address::new([6u8; 20]),
            executor_interface_id: [51u8; 32],
            terms_commitment: [52u8; 32],
            activation_policy_id: [53u8; 32],
            state: ExecutorState::Draft,
            created_at: 1000,
            updated_at: 1000,
            created_at_height: 100,
            activation_proof_id: None,
        };

        store.put(&link).unwrap();
        let retrieved = store.get(&[50u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().state, ExecutorState::Draft);

        // Test executor index
        let by_executor = store.get_by_executor(&Address::new([6u8; 20])).unwrap();
        assert_eq!(by_executor.len(), 1);
    }

    #[test]
    fn test_agreement_proof_store() {
        let (db, _dir) = temp_db();
        let store = AgreementProofStore::new(&db);

        let proof = AgreementProofEnvelope {
            proof_id: [60u8; 32],
            profile: AgreementProofProfile::SignedByRoles,
            profile_id: "agreement.signed_by_roles.v1".to_string(),
            policy_ids: vec![[61u8; 32]],
            public_inputs: vec![1, 2, 3],
            proof_data: vec![4, 5, 6],
            proof_type: AgreementProofType::Mock,
            subject_nullifier: [62u8; 32],
            generated_at: 1000,
            expires_at: 2000,
        };

        store.put(&proof).unwrap();
        let retrieved = store.get(&[60u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_id, "agreement.signed_by_roles.v1");

        // Test get by profile
        let by_profile = store.get_by_profile("agreement.signed_by_roles.v1").unwrap();
        assert_eq!(by_profile.len(), 1);
    }

    #[test]
    fn test_mark_party_signed() {
        let (db, _dir) = temp_db();
        let store = AgreementCommitmentStore::new(&db);

        let party1 = PartyBinding {
            party_ref: PartyRef::Commitment([1u8; 32]),
            role: AgreementRole::Buyer,
            signed: false,
            signed_at: None,
        };
        let party2 = PartyBinding {
            party_ref: PartyRef::Commitment([2u8; 32]),
            role: AgreementRole::Seller,
            signed: false,
            signed_at: None,
        };

        let agreement = AgreementCommitment {
            agreement_id: [10u8; 32],
            agreement_commitment: [11u8; 32],
            parties: vec![party1, party2],
            jurisdiction_code: "US-DE".to_string(),
            effective_from: Some(1000),
            expiry: Some(2000),
            attachments: vec![],
            policy_id: [12u8; 32],
            status: AgreementStatus::PendingSignatures,
            created_at: 1000,
            updated_at: 1000,
            created_at_height: 100,
            supersedes: None,
        };

        store.put(&agreement).unwrap();

        // Sign first party
        store.mark_party_signed(&[10u8; 32], &[1u8; 32], 1100).unwrap();
        let updated = store.get(&[10u8; 32]).unwrap().unwrap();
        assert_eq!(updated.signed_count(), 1);
        assert_eq!(updated.status, AgreementStatus::PendingSignatures);

        // Sign second party - should transition to Executed
        store.mark_party_signed(&[10u8; 32], &[2u8; 32], 1200).unwrap();
        let executed = store.get(&[10u8; 32]).unwrap().unwrap();
        assert_eq!(executed.signed_count(), 2);
        assert_eq!(executed.status, AgreementStatus::Executed);
    }
}

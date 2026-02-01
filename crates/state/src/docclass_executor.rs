//! SRC-80X/81X DocClass Executor
//!
//! Executes DocClass credential transactions including:
//! - Identity Root operations (SRC-800)
//! - Eligibility Attestations (SRC-802)
//! - Revocations (SRC-805)
//! - Academic/Professional Credentials (SRC-810-813)
//! - Issuer Registry management

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, AcademicCredential, Balance, BlockHeight, CredentialId, DocClassEvent,
    DocClassIssuer, DocClassIssuerStatus, DocClassOperation, DocClassTxData, DocSubcode,
    EligibilityAttestation, Hash, IdentityKey, IdentityRoot, IdentityStatus, IssuerKey,
    RevocationReason, RevocationRecord, RevocationStatus, ServiceEndpoint, Timestamp,
};
use sumchain_storage::{Database, DocClassStore};
use tracing::{debug, warn};

use crate::{Result, SchemaValidator, StateError, StateManager};

/// Result of DocClass execution
#[derive(Debug)]
pub struct DocClassExecutionResult {
    pub success: bool,
    pub credential_id: Option<CredentialId>,
    pub error: Option<String>,
}

impl DocClassExecutionResult {
    pub fn success(credential_id: Option<CredentialId>) -> Self {
        Self {
            success: true,
            credential_id,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            credential_id: None,
            error: Some(error.into()),
        }
    }
}

/// DocClass executor for SRC-80X/81X transactions
pub struct DocClassExecutor {
    db: Arc<Database>,
    params: ChainParams,
    schema_validator: SchemaValidator,
}

impl DocClassExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self {
            db,
            params,
            schema_validator: SchemaValidator::new(),
        }
    }

    /// Execute a DocClass transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &DocClassTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<DocClassExecutionResult> {
        let store = DocClassStore::new(&self.db);

        match data.operation {
            // Identity operations (SRC-800)
            DocClassOperation::CreateIdentityRoot => {
                self.create_identity_root(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::AddKey => {
                self.identity_add_key(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::RemoveKey => {
                self.identity_remove_key(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::RotateKey => {
                self.identity_rotate_key(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::AddController => {
                self.identity_add_controller(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::RemoveController => {
                self.identity_remove_controller(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::UpdateService => {
                self.identity_update_service(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::DeactivateIdentity => {
                self.deactivate_identity(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }
            DocClassOperation::ReactivateIdentity => {
                self.reactivate_identity(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }

            // Credential operations (SRC-802, SRC-810-813)
            DocClassOperation::IssueCredential => {
                self.issue_credential(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::UpdateCredential => {
                self.update_credential(sender, &data.data, state, proposer, fee, &store)
            }

            // Revocation operations (SRC-805)
            DocClassOperation::RevokeCredential => {
                self.revoke_credential(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }
            DocClassOperation::SuspendCredential => {
                self.suspend_credential(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }
            DocClassOperation::ReactivateCredential => {
                self.reactivate_credential(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }
            DocClassOperation::SupersedeCredential => {
                self.supersede_credential(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }

            // Issuer Registry operations
            DocClassOperation::RegisterIssuer => {
                self.register_issuer(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::UpdateIssuer => {
                self.update_issuer(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::RotateIssuerKey => {
                self.rotate_issuer_key(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            DocClassOperation::DeactivateIssuer => {
                self.deactivate_issuer(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }
        }
    }

    // ========================================================================
    // Identity Root Operations (SRC-800)
    // ========================================================================

    fn create_identity_root(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        let identity: IdentityRoot = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid identity data: {}", e)))?;

        if identity.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Controller must be sender"));
        }

        if store.identity_roots().exists(&identity.identity_id)? {
            return Ok(DocClassExecutionResult::failure("Identity already exists"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.identity_roots().put(&identity)?;

        let event = DocClassEvent::IdentityRootCreated {
            identity_id: identity.identity_id,
            controller: identity.controller,
            subject_commitment: identity.subject_commitment,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        debug!("Identity root created: {:?}", identity.identity_id);
        Ok(DocClassExecutionResult::success(Some(identity.identity_id)))
    }

    fn identity_add_key(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct AddKeyData {
            identity_id: CredentialId,
            key: IdentityKey,
        }

        let add_data: AddKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match store.identity_roots().get(&add_data.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        identity.keys.push(add_data.key.clone());
        store.identity_roots().put(&identity)?;

        let event = DocClassEvent::KeyAdded {
            identity_id: add_data.identity_id,
            key_id: add_data.key.key_id,
            key_type: add_data.key.key_type,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(add_data.identity_id)))
    }

    fn identity_remove_key(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RemoveKeyData {
            identity_id: CredentialId,
            key_id: String,
        }

        let remove_data: RemoveKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match store.identity_roots().get(&remove_data.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        identity.keys.retain(|k| k.key_id != remove_data.key_id);
        store.identity_roots().put(&identity)?;

        let event = DocClassEvent::KeyRemoved {
            identity_id: remove_data.identity_id,
            key_id: remove_data.key_id,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(remove_data.identity_id)))
    }

    fn identity_rotate_key(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RotateKeyData {
            identity_id: CredentialId,
            old_key_id: String,
            new_key: IdentityKey,
        }

        let rotate_data: RotateKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match store.identity_roots().get(&rotate_data.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        identity.keys.retain(|k| k.key_id != rotate_data.old_key_id);
        let new_key_id = rotate_data.new_key.key_id.clone();
        identity.keys.push(rotate_data.new_key);
        store.identity_roots().put(&identity)?;

        let event = DocClassEvent::KeyRotated {
            identity_id: rotate_data.identity_id,
            old_key_id: rotate_data.old_key_id,
            new_key_id,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(rotate_data.identity_id)))
    }

    fn identity_add_controller(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct AddControllerData {
            identity_id: CredentialId,
            controller: Address,
        }

        let add_data: AddControllerData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match store.identity_roots().get(&add_data.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if identity.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only primary controller can add"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        if !identity.additional_controllers.contains(&add_data.controller) {
            identity.additional_controllers.push(add_data.controller);
        }
        store.identity_roots().put(&identity)?;

        let event = DocClassEvent::ControllerAdded {
            identity_id: add_data.identity_id,
            controller: add_data.controller,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(add_data.identity_id)))
    }

    fn identity_remove_controller(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RemoveControllerData {
            identity_id: CredentialId,
            controller: Address,
        }

        let remove_data: RemoveControllerData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match store.identity_roots().get(&remove_data.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if identity.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only primary controller can remove"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        identity.additional_controllers.retain(|c| c != &remove_data.controller);
        store.identity_roots().put(&identity)?;

        let event = DocClassEvent::ControllerRemoved {
            identity_id: remove_data.identity_id,
            controller: remove_data.controller,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(remove_data.identity_id)))
    }

    fn identity_update_service(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct UpdateServiceData {
            identity_id: CredentialId,
            service: ServiceEndpoint,
        }

        let update_data: UpdateServiceData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut identity = match store.identity_roots().get(&update_data.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if identity.controller != *sender && !identity.additional_controllers.contains(sender) {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let service_id = update_data.service.service_id.clone();
        if let Some(s) = identity.services.iter_mut().find(|s| s.service_id == update_data.service.service_id) {
            *s = update_data.service;
        } else {
            identity.services.push(update_data.service);
        }
        store.identity_roots().put(&identity)?;

        let event = DocClassEvent::ServiceUpdated {
            identity_id: update_data.identity_id,
            service_id,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(update_data.identity_id)))
    }

    fn deactivate_identity(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct DeactivateData {
            identity_id: CredentialId,
        }

        let deactivate: DeactivateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let existing = match store.identity_roots().get(&deactivate.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if existing.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only controller can deactivate"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.identity_roots().update_status(&deactivate.identity_id, IdentityStatus::Deactivated, block_timestamp)?;

        let event = DocClassEvent::IdentityStatusChanged {
            identity_id: deactivate.identity_id,
            new_status: IdentityStatus::Deactivated,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(deactivate.identity_id)))
    }

    fn reactivate_identity(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct ReactivateData {
            identity_id: CredentialId,
        }

        let reactivate: ReactivateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let existing = match store.identity_roots().get(&reactivate.identity_id)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Identity not found")),
        };

        if existing.controller != *sender {
            return Ok(DocClassExecutionResult::failure("Only controller can reactivate"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.identity_roots().update_status(&reactivate.identity_id, IdentityStatus::Active, block_timestamp)?;

        let event = DocClassEvent::IdentityStatusChanged {
            identity_id: reactivate.identity_id,
            new_status: IdentityStatus::Active,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(reactivate.identity_id)))
    }

    // ========================================================================
    // Credential Operations
    // ========================================================================

    fn issue_credential(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        // Try academic credential first
        if let Ok(cred) = bincode::deserialize::<AcademicCredential>(data) {
            return self.issue_academic_credential(sender, cred, state, proposer, fee, block_height, tx_index, store);
        }
        // Try eligibility attestation
        if let Ok(att) = bincode::deserialize::<EligibilityAttestation>(data) {
            return self.issue_eligibility(sender, att, state, proposer, fee, block_height, tx_index, store);
        }
        Ok(DocClassExecutionResult::failure("Invalid credential data"))
    }

    fn issue_academic_credential(
        &self,
        sender: &Address,
        credential: AcademicCredential,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        if credential.issuer != *sender {
            return Ok(DocClassExecutionResult::failure("Issuer must be sender"));
        }

        let jurisdiction = credential.jurisdiction.as_str();

        if !store.issuers().can_issue_subcode(sender, credential.subcode, jurisdiction)? {
            return Ok(DocClassExecutionResult::failure("Issuer not authorized"));
        }

        if store.credentials().exists(&credential.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Credential exists"));
        }

        // PRIVACY ENFORCEMENT: Validate schema to prevent PII on-chain
        // Hard rejection at consensus level for SRC-81X credentials (810/811/812)
        let validation_result = self.schema_validator.validate_academic_credential(&credential, block_height);
        if !validation_result.is_valid() {
            if let crate::ValidationResult::Invalid { reason } = validation_result {
                warn!(
                    "Schema validation failed for credential {:?}: {}",
                    credential.credential_id, reason
                );
                return Ok(DocClassExecutionResult::failure(format!(
                    "Schema validation failed: {}",
                    reason
                )));
            }
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.credentials().put(&credential)?;

        let event = DocClassEvent::CredentialIssued {
            credential_id: credential.credential_id,
            subcode: credential.subcode,
            issuer: credential.issuer,
            jurisdiction: jurisdiction.to_string(),
            subject_commitment: credential.subject_commitment,
            schema_hash: credential.schema_hash,
            expires_at: credential.expires_at,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        debug!("Credential issued: {:?}", credential.credential_id);
        Ok(DocClassExecutionResult::success(Some(credential.credential_id)))
    }

    fn issue_eligibility(
        &self,
        sender: &Address,
        attestation: EligibilityAttestation,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        if attestation.issuer != *sender {
            return Ok(DocClassExecutionResult::failure("Issuer must be sender"));
        }

        if !store.issuers().can_issue_subcode(sender, DocSubcode::EligibilityAttestation, &attestation.jurisdiction)? {
            return Ok(DocClassExecutionResult::failure("Issuer not authorized"));
        }

        if store.eligibility().exists(&attestation.credential_id)? {
            return Ok(DocClassExecutionResult::failure("Credential exists"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.eligibility().put(&attestation)?;

        let event = DocClassEvent::CredentialIssued {
            credential_id: attestation.credential_id,
            subcode: DocSubcode::EligibilityAttestation,
            issuer: attestation.issuer,
            jurisdiction: attestation.jurisdiction.clone(),
            subject_commitment: attestation.subject_commitment,
            schema_hash: attestation.schema_hash,
            expires_at: attestation.expires_at,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        debug!("Eligibility issued: {:?}", attestation.credential_id);
        Ok(DocClassExecutionResult::success(Some(attestation.credential_id)))
    }

    fn update_credential(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct UpdateData {
            credential_id: CredentialId,
        }

        let update: UpdateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        // Just check authorization for now
        let is_authorized = if let Some(c) = store.credentials().get(&update.credential_id)? {
            c.issuer == *sender
        } else if let Some(a) = store.eligibility().get(&update.credential_id)? {
            a.issuer == *sender
        } else {
            return Ok(DocClassExecutionResult::failure("Credential not found"));
        };

        if !is_authorized {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        Ok(DocClassExecutionResult::success(Some(update.credential_id)))
    }

    // ========================================================================
    // Revocation Operations
    // ========================================================================

    fn revoke_credential(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RevokeData {
            credential_id: CredentialId,
            reason: RevocationReason,
        }

        let revoke: RevokeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !self.check_revoke_auth(sender, &revoke.credential_id, store)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let record = RevocationRecord {
            credential_id: revoke.credential_id,
            status: RevocationStatus::Revoked,
            reason: revoke.reason,
            reason_details: None,
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: None,
            signature: [0u8; 64],
        };
        store.revocations().put(&record)?;

        if store.eligibility().exists(&revoke.credential_id)? {
            store.eligibility().update_revocation(&revoke.credential_id, RevocationStatus::Revoked, None)?;
        } else if store.credentials().exists(&revoke.credential_id)? {
            store.credentials().update_revocation(&revoke.credential_id, RevocationStatus::Revoked, None)?;
        }

        let event = DocClassEvent::CredentialRevoked {
            credential_id: revoke.credential_id,
            issuer: *sender,
            reason: revoke.reason,
            timestamp: block_timestamp,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(revoke.credential_id)))
    }

    fn suspend_credential(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct SuspendData {
            credential_id: CredentialId,
            reason: RevocationReason,
        }

        let suspend: SuspendData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !self.check_revoke_auth(sender, &suspend.credential_id, store)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let record = RevocationRecord {
            credential_id: suspend.credential_id,
            status: RevocationStatus::Suspended,
            reason: suspend.reason,
            reason_details: None,
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: None,
            signature: [0u8; 64],
        };
        store.revocations().put(&record)?;

        if store.eligibility().exists(&suspend.credential_id)? {
            store.eligibility().update_revocation(&suspend.credential_id, RevocationStatus::Suspended, None)?;
        } else if store.credentials().exists(&suspend.credential_id)? {
            store.credentials().update_revocation(&suspend.credential_id, RevocationStatus::Suspended, None)?;
        }

        let event = DocClassEvent::CredentialSuspended {
            credential_id: suspend.credential_id,
            issuer: *sender,
            reason: suspend.reason,
            timestamp: block_timestamp,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(suspend.credential_id)))
    }

    fn reactivate_credential(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct ReactivateData {
            credential_id: CredentialId,
        }

        let reactivate: ReactivateData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !self.check_revoke_auth(sender, &reactivate.credential_id, store)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        let status = store.revocations().get_status(&reactivate.credential_id)?;
        if status != RevocationStatus::Suspended {
            return Ok(DocClassExecutionResult::failure("Only suspended can be reactivated"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let record = RevocationRecord {
            credential_id: reactivate.credential_id,
            status: RevocationStatus::Active,
            reason: RevocationReason::Unspecified,
            reason_details: Some("Reactivated".to_string()),
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: None,
            signature: [0u8; 64],
        };
        store.revocations().put(&record)?;

        if store.eligibility().exists(&reactivate.credential_id)? {
            store.eligibility().update_revocation(&reactivate.credential_id, RevocationStatus::Active, None)?;
        } else if store.credentials().exists(&reactivate.credential_id)? {
            store.credentials().update_revocation(&reactivate.credential_id, RevocationStatus::Active, None)?;
        }

        let event = DocClassEvent::CredentialReactivated {
            credential_id: reactivate.credential_id,
            issuer: *sender,
            timestamp: block_timestamp,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(reactivate.credential_id)))
    }

    fn supersede_credential(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct SupersedeData {
            old_credential_id: CredentialId,
            new_credential_id: CredentialId,
        }

        let supersede: SupersedeData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if !self.check_revoke_auth(sender, &supersede.old_credential_id, store)? {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let record = RevocationRecord {
            credential_id: supersede.old_credential_id,
            status: RevocationStatus::Superseded,
            reason: RevocationReason::Superseded,
            reason_details: None,
            revoker: *sender,
            revoked_at: block_timestamp,
            revoked_at_height: block_height,
            superseded_by: Some(supersede.new_credential_id),
            signature: [0u8; 64],
        };
        store.revocations().put(&record)?;

        if store.eligibility().exists(&supersede.old_credential_id)? {
            store.eligibility().update_revocation(&supersede.old_credential_id, RevocationStatus::Superseded, Some(supersede.new_credential_id))?;
        } else if store.credentials().exists(&supersede.old_credential_id)? {
            store.credentials().update_revocation(&supersede.old_credential_id, RevocationStatus::Superseded, Some(supersede.new_credential_id))?;
        }

        let event = DocClassEvent::CredentialSuperseded {
            old_credential_id: supersede.old_credential_id,
            new_credential_id: supersede.new_credential_id,
            issuer: *sender,
            timestamp: block_timestamp,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(Some(supersede.new_credential_id)))
    }

    fn check_revoke_auth(&self, sender: &Address, credential_id: &CredentialId, store: &DocClassStore) -> Result<bool> {
        if let Some(a) = store.eligibility().get(credential_id)? {
            return Ok(a.issuer == *sender);
        }
        if let Some(c) = store.credentials().get(credential_id)? {
            return Ok(c.issuer == *sender);
        }
        Ok(false)
    }

    // ========================================================================
    // Issuer Registry
    // ========================================================================

    fn register_issuer(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        let issuer: DocClassIssuer = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if issuer.address != *sender {
            return Ok(DocClassExecutionResult::failure("Address must be sender"));
        }

        if store.issuers().is_registered(sender)? {
            return Ok(DocClassExecutionResult::failure("Already registered"));
        }

        if let Some(ref p) = self.params.docclass {
            if p.min_issuer_stake > 0 && issuer.stake_amount < p.min_issuer_stake {
                return Ok(DocClassExecutionResult::failure("Insufficient stake"));
            }
        }

        let total = fee.saturating_add(issuer.stake_amount);
        state.deduct(sender, total)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let subcodes = issuer.authorized_subcodes.clone();
        store.issuers().put(&issuer)?;

        let event = DocClassEvent::IssuerRegistered {
            issuer: issuer.address,
            issuer_type: issuer.issuer_type,
            jurisdictions: issuer.jurisdictions,
            subcodes,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        debug!("Issuer registered: {}", issuer.address);
        Ok(DocClassExecutionResult::success(None))
    }

    fn update_issuer(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        let updated: DocClassIssuer = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        if updated.address != *sender {
            return Ok(DocClassExecutionResult::failure("Can only update own profile"));
        }

        if !store.issuers().is_registered(sender)? {
            return Ok(DocClassExecutionResult::failure("Not registered"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.issuers().put(&updated)?;

        let event = DocClassEvent::IssuerUpdated {
            issuer: updated.address,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(None))
    }

    fn rotate_issuer_key(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RotateKeyData {
            new_key: IssuerKey,
            old_key_id: String,
        }

        let rotate: RotateKeyData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut issuer = match store.issuers().get(sender)? {
            Some(i) => i,
            None => return Ok(DocClassExecutionResult::failure("Not registered")),
        };

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        for key in &mut issuer.keys {
            if key.key_id == rotate.old_key_id {
                key.active = false;
                key.is_primary = false;
            }
        }

        if rotate.new_key.is_primary {
            for key in &mut issuer.keys {
                key.is_primary = false;
            }
        }

        let new_key_id = rotate.new_key.key_id.clone();
        issuer.keys.push(rotate.new_key);
        store.issuers().put(&issuer)?;

        let event = DocClassEvent::IssuerKeyRotated {
            issuer: *sender,
            old_key_id: rotate.old_key_id,
            new_key_id,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        Ok(DocClassExecutionResult::success(None))
    }

    fn deactivate_issuer(
        &self,
        sender: &Address,
        data: &[u8],
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        store: &DocClassStore,
    ) -> Result<DocClassExecutionResult> {
        #[derive(serde::Deserialize)]
        struct DeactivateIssuerData {
            issuer_address: Address,
        }

        let deactivate: DeactivateIssuerData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let is_admin = self.is_docclass_admin(sender);
        let is_self = deactivate.issuer_address == *sender;

        if !is_admin && !is_self {
            return Ok(DocClassExecutionResult::failure("Not authorized"));
        }

        if !store.issuers().is_registered(&deactivate.issuer_address)? {
            return Ok(DocClassExecutionResult::failure("Not registered"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.issuers().update_status(&deactivate.issuer_address, DocClassIssuerStatus::Suspended, block_timestamp)?;

        let event = DocClassEvent::IssuerStatusChanged {
            issuer: deactivate.issuer_address,
            new_status: DocClassIssuerStatus::Suspended,
        };
        store.events().put(block_height, tx_index, 0, &event)?;

        warn!("Issuer deactivated: {}", deactivate.issuer_address);
        Ok(DocClassExecutionResult::success(None))
    }

    fn is_docclass_admin(&self, sender: &Address) -> bool {
        if let Some(ref p) = self.params.docclass {
            if let Some(ref admin_str) = p.admin {
                if let Ok(admin) = Address::from_base58(admin_str)
                    .or_else(|_| Address::from_hex(admin_str)) {
                    return &admin == sender;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::{
        DocClassIssuerType, EligibilityType, KeyPurpose, KeyType, Hash,
    };
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    fn test_params() -> ChainParams {
        let mut params = ChainParams::default();
        // Set min_issuer_stake to 0 for testing
        if let Some(ref mut docclass) = params.docclass {
            docclass.min_issuer_stake = 0;
        }
        params
    }

    fn sample_issuer_key() -> IssuerKey {
        IssuerKey {
            key_id: "key1".to_string(),
            public_key: [1u8; 32],
            key_type: KeyType::Ed25519,
            added_at: 1000,
            expires_at: 0,
            active: true,
            is_primary: true,
        }
    }

    fn sample_identity_key() -> IdentityKey {
        IdentityKey {
            key_id: "auth1".to_string(),
            key_type: KeyType::Ed25519,
            public_key: [2u8; 32],
            purposes: vec![KeyPurpose::Authentication],
            added_at: 1000,
            expires_at: 0,
            active: true,
        }
    }

    fn make_tx_data<T: serde::Serialize>(operation: DocClassOperation, subcode: DocSubcode, op_data: &T) -> DocClassTxData {
        DocClassTxData {
            operation,
            subcode,
            data: bincode::serialize(op_data).unwrap(),
        }
    }

    #[test]
    fn test_docclass_executor_creation() {
        let (db, _dir, _state) = setup();
        let params = test_params();
        let _executor = DocClassExecutor::new(db, params);
    }

    #[test]
    fn test_register_issuer() {
        let (db, _dir, state) = setup();
        let params = test_params();
        let executor = DocClassExecutor::new(db.clone(), params);

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the issuer account
        state.credit(&issuer_addr, 1_000_000_000_000).unwrap();

        // Create full DocClassIssuer for registration
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Test University".to_string(),
            issuer_type: DocClassIssuerType::Educational,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::Diploma, DocSubcode::EnrollmentVerification],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };

        let tx_data = make_tx_data(
            DocClassOperation::RegisterIssuer,
            DocSubcode::IdentityRoot,
            &issuer,
        );

        let result = executor.execute(
            &issuer_addr,
            &tx_data,
            &state,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success, "Register issuer failed: {:?}", result.error);

        // Verify issuer is registered
        let store = DocClassStore::new(&db);
        let retrieved = store.issuers().get(&issuer_addr).unwrap().unwrap();
        assert_eq!(retrieved.name, "Test University");
        assert!(store.issuers().can_issue_subcode(&issuer_addr, DocSubcode::Diploma, "US").unwrap());
    }

    #[test]
    fn test_create_identity_root() {
        let (db, _dir, state) = setup();
        let params = test_params();
        let executor = DocClassExecutor::new(db.clone(), params);

        let controller = Address::new([2u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the controller account
        state.credit(&controller, 1_000_000_000_000).unwrap();

        let subject_commitment = [42u8; 32];
        let identity_id = [100u8; 32];

        // Create full IdentityRoot
        let identity = IdentityRoot {
            identity_id,
            subject_commitment,
            controller,
            additional_controllers: vec![],
            keys: vec![sample_identity_key()],
            services: vec![],
            created_at: 1000000,
            updated_at: 1000000,
            status: IdentityStatus::Active,
            schema_hash: [0u8; 32],
        };

        let tx_data = make_tx_data(
            DocClassOperation::CreateIdentityRoot,
            DocSubcode::IdentityRoot,
            &identity,
        );

        let result = executor.execute(
            &controller,
            &tx_data,
            &state,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success);

        // Verify identity was created
        let store = DocClassStore::new(&db);
        let retrieved = store.identity_roots().get(&identity_id).unwrap().unwrap();
        assert_eq!(retrieved.controller, controller);
        assert_eq!(retrieved.subject_commitment, subject_commitment);
        assert_eq!(retrieved.keys.len(), 1);
    }

    #[test]
    fn test_issue_eligibility() {
        let (db, _dir, state) = setup();
        let params = test_params();
        let executor = DocClassExecutor::new(db.clone(), params);

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the issuer account
        state.credit(&issuer_addr, 1_000_000_000_000).unwrap();

        // First register the issuer
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Government Agency".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };

        let tx_data = make_tx_data(
            DocClassOperation::RegisterIssuer,
            DocSubcode::IdentityRoot,
            &issuer,
        );

        let result = executor.execute(
            &issuer_addr,
            &tx_data,
            &state,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        ).unwrap();
        assert!(result.success);

        // Now issue an eligibility attestation
        let credential_id = [200u8; 32];
        let subject_commitment = [42u8; 32];

        let eligibility = EligibilityAttestation {
            credential_id,
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment,
            issuer: issuer_addr,
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000000,
            valid_from: 1000000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };

        let tx_data = make_tx_data(
            DocClassOperation::IssueCredential,
            DocSubcode::EligibilityAttestation,
            &eligibility,
        );

        let result = executor.execute(
            &issuer_addr,
            &tx_data,
            &state,
            &proposer,
            1000,
            101,
            1000001,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success);

        // Verify credential was issued
        let store = DocClassStore::new(&db);
        let retrieved = store.eligibility().get(&credential_id).unwrap().unwrap();
        assert_eq!(retrieved.subject_commitment, subject_commitment);
        assert_eq!(retrieved.revocation_status, RevocationStatus::Active);
    }

    #[test]
    fn test_revoke_credential() {
        let (db, _dir, state) = setup();
        let params = test_params();
        let executor = DocClassExecutor::new(db.clone(), params);

        let issuer_addr = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund the issuer account
        state.credit(&issuer_addr, 1_000_000_000_000).unwrap();

        // Register issuer
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Government Agency".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };
        let tx_data = make_tx_data(DocClassOperation::RegisterIssuer, DocSubcode::IdentityRoot, &issuer);
        executor.execute(&issuer_addr, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default()).unwrap();

        // Issue credential
        let credential_id = [200u8; 32];
        let eligibility = EligibilityAttestation {
            credential_id,
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment: [42u8; 32],
            issuer: issuer_addr,
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000000,
            valid_from: 1000000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };
        let tx_data = make_tx_data(DocClassOperation::IssueCredential, DocSubcode::EligibilityAttestation, &eligibility);
        executor.execute(&issuer_addr, &tx_data, &state, &proposer, 1000, 101, 1000001, 0, Hash::default()).unwrap();

        // Now revoke the credential using inline struct matching the executor
        #[derive(serde::Serialize)]
        struct RevokeData {
            credential_id: CredentialId,
            reason: RevocationReason,
        }

        let revoke = RevokeData {
            credential_id,
            reason: RevocationReason::KeyCompromise,
        };

        let tx_data = make_tx_data(DocClassOperation::RevokeCredential, DocSubcode::IdentityRoot, &revoke);

        let result = executor.execute(
            &issuer_addr,
            &tx_data,
            &state,
            &proposer,
            1000,
            102,
            1000002,
            0,
            Hash::default(),
        ).unwrap();

        assert!(result.success);

        // Verify credential is revoked
        let store = DocClassStore::new(&db);
        assert!(store.revocations().is_revoked(&credential_id).unwrap());

        let status = store.revocations().get_status(&credential_id).unwrap();
        assert_eq!(status, RevocationStatus::Revoked);
    }

    #[test]
    fn test_unauthorized_issuer_fails() {
        let (db, _dir, state) = setup();
        let params = test_params();
        let executor = DocClassExecutor::new(db.clone(), params);

        let issuer_addr = Address::new([1u8; 20]);
        let unauthorized_addr = Address::new([5u8; 20]);
        let proposer = Address::new([99u8; 20]);

        // Fund accounts
        state.credit(&issuer_addr, 1_000_000_000_000).unwrap();
        state.credit(&unauthorized_addr, 1_000_000_000_000).unwrap();

        // Register issuer for eligibility only
        let issuer = DocClassIssuer {
            address: issuer_addr,
            name: "Government Agency".to_string(),
            issuer_type: DocClassIssuerType::Government,
            jurisdictions: vec!["US".to_string()],
            authorized_subcodes: vec![DocSubcode::EligibilityAttestation],
            keys: vec![sample_issuer_key()],
            registered_at: 1000000,
            updated_at: 1000000,
            status: DocClassIssuerStatus::Active,
            stake_amount: 0,
            metadata: None,
        };
        let tx_data = make_tx_data(DocClassOperation::RegisterIssuer, DocSubcode::IdentityRoot, &issuer);
        executor.execute(&issuer_addr, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default()).unwrap();

        // Try to issue with unregistered address (should fail)
        let eligibility = EligibilityAttestation {
            credential_id: [200u8; 32],
            subcode: DocSubcode::EligibilityAttestation,
            subject_commitment: [42u8; 32],
            issuer: unauthorized_addr, // Wrong issuer
            jurisdiction: "US".to_string(),
            eligibility_type: EligibilityType::Citizenship,
            schema_hash: [3u8; 32],
            content_commitment: [4u8; 32],
            issued_at: 1000000,
            valid_from: 1000000,
            expires_at: 0,
            payload_hash: None,
            payload_hint: None,
            issuer_signature: [0u8; 64],
            issuer_key_id: "key1".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };

        let tx_data = make_tx_data(DocClassOperation::IssueCredential, DocSubcode::EligibilityAttestation, &eligibility);

        let result = executor.execute(
            &unauthorized_addr,
            &tx_data,
            &state,
            &proposer,
            1000,
            101,
            1000001,
            0,
            Hash::default(),
        ).unwrap();

        // Should fail because unauthorized_addr is not a registered issuer
        assert!(!result.success);
    }
}

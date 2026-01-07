//! SRC-83X Business & Equity Storage Module
//!
//! Provides persistent storage for Business & Equity domain:
//! - SRC-831: Entity Identity Profile
//! - SRC-832: Governance Actions
//! - SRC-833: Equity Tokens
//! - SRC-834: Equity Controllers
//! - SRC-835: Corporate Actions
//! - SRC-836: Ownership Proofs

use sumchain_primitives::{
    equity::{
        ActionId, ClassId, CorporateAction, CorporateActionStatus, EntityProfile, EntityStatus,
        EquityControllerConfig, EquityEvent, EquityToken, GovernanceAction, GovernanceActionStatus,
        OwnershipProofEnvelope, OwnershipSnapshot, ProofId, SnapshotId, SubjectId, TokenStatus,
    },
    Address, BlockHeight, Timestamp,
};

use crate::db::{cf, Database};
use crate::{Result, StorageError};

// =============================================================================
// Entity Profile Storage (SRC-831)
// =============================================================================

/// Storage for Entity Identity Profiles (SRC-831)
pub struct EntityProfileStore<'a> {
    db: &'a Database,
}

impl<'a> EntityProfileStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an entity profile
    pub fn put(&self, entity: &EntityProfile) -> Result<()> {
        let bytes =
            bincode::serialize(entity).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EQUITY_ENTITIES, &entity.subject_id, &bytes)
    }

    /// Get an entity profile by subject ID
    pub fn get(&self, subject_id: &SubjectId) -> Result<Option<EntityProfile>> {
        match self.db.get(cf::EQUITY_ENTITIES, subject_id)? {
            Some(bytes) => {
                let entity: EntityProfile = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(entity))
            }
            None => Ok(None),
        }
    }

    /// Check if entity exists
    pub fn exists(&self, subject_id: &SubjectId) -> Result<bool> {
        self.db.contains(cf::EQUITY_ENTITIES, subject_id)
    }

    /// Update entity status
    pub fn update_status(
        &self,
        subject_id: &SubjectId,
        status: EntityStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(subject_id)? {
            Some(mut entity) => {
                entity.status = status;
                entity.updated_at = timestamp;
                self.put(&entity)
            }
            None => Err(StorageError::NotFound(format!(
                "Entity not found: {:?}",
                subject_id
            ))),
        }
    }

    /// Get entities by controller address
    pub fn get_by_controller(&self, controller: &Address) -> Result<Vec<EntityProfile>> {
        let mut entities = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_ENTITIES)? {
            let entity: EntityProfile = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if entity.controllers.contains(controller) {
                entities.push(entity);
            }
        }
        Ok(entities)
    }

    /// List all active entities
    pub fn list_active(&self) -> Result<Vec<EntityProfile>> {
        let mut entities = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_ENTITIES)? {
            let entity: EntityProfile = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if entity.status == EntityStatus::Active {
                entities.push(entity);
            }
        }
        Ok(entities)
    }

    /// List entities by organization type
    pub fn list_by_org_type(
        &self,
        org_type: sumchain_primitives::equity::OrgType,
    ) -> Result<Vec<EntityProfile>> {
        let mut entities = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_ENTITIES)? {
            let entity: EntityProfile = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if entity.org_type == org_type {
                entities.push(entity);
            }
        }
        Ok(entities)
    }
}

// =============================================================================
// Governance Action Storage (SRC-832)
// =============================================================================

/// Storage for Governance Actions (SRC-832)
pub struct GovernanceActionStore<'a> {
    db: &'a Database,
}

impl<'a> GovernanceActionStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a governance action
    pub fn put(&self, action: &GovernanceAction) -> Result<()> {
        let bytes =
            bincode::serialize(action).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EQUITY_GOVERNANCE, &action.action_id, &bytes)?;

        // Index by entity
        self.add_to_entity_index(&action.org_subject, &action.action_id)?;

        Ok(())
    }

    /// Get a governance action by ID
    pub fn get(&self, action_id: &ActionId) -> Result<Option<GovernanceAction>> {
        match self.db.get(cf::EQUITY_GOVERNANCE, action_id)? {
            Some(bytes) => {
                let action: GovernanceAction = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(action))
            }
            None => Ok(None),
        }
    }

    /// Check if action exists
    pub fn exists(&self, action_id: &ActionId) -> Result<bool> {
        self.db.contains(cf::EQUITY_GOVERNANCE, action_id)
    }

    /// Get actions by entity
    pub fn get_by_entity(&self, entity_subject_id: &SubjectId) -> Result<Vec<GovernanceAction>> {
        let action_ids = self.get_entity_action_ids(entity_subject_id)?;
        let mut actions = Vec::new();
        for action_id in action_ids {
            if let Some(action) = self.get(&action_id)? {
                actions.push(action);
            }
        }
        Ok(actions)
    }

    /// Update action status
    pub fn update_status(
        &self,
        action_id: &ActionId,
        status: GovernanceActionStatus,
        _timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(action_id)? {
            Some(mut action) => {
                action.status = status;
                let bytes = bincode::serialize(&action)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::EQUITY_GOVERNANCE, action_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Action not found: {:?}",
                action_id
            ))),
        }
    }

    // Index helpers
    fn add_to_entity_index(
        &self,
        entity_subject_id: &SubjectId,
        action_id: &ActionId,
    ) -> Result<()> {
        let mut action_ids = self.get_entity_action_ids(entity_subject_id)?;
        if !action_ids.contains(action_id) {
            action_ids.push(*action_id);
            let bytes = bincode::serialize(&action_ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db
                .put(cf::EQUITY_ENTITY_INDEX, entity_subject_id, &bytes)?;
        }
        Ok(())
    }

    fn get_entity_action_ids(&self, entity_subject_id: &SubjectId) -> Result<Vec<ActionId>> {
        match self.db.get(cf::EQUITY_ENTITY_INDEX, entity_subject_id)? {
            Some(bytes) => {
                let action_ids: Vec<ActionId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(action_ids)
            }
            None => Ok(Vec::new()),
        }
    }
}

// =============================================================================
// Equity Token Storage (SRC-833)
// =============================================================================

/// Storage for Equity Tokens (SRC-833)
pub struct EquityTokenStore<'a> {
    db: &'a Database,
}

impl<'a> EquityTokenStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an equity token class
    pub fn put(&self, token: &EquityToken) -> Result<()> {
        let bytes =
            bincode::serialize(token).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EQUITY_TOKENS, &token.class_id, &bytes)
    }

    /// Get an equity token by class ID
    pub fn get(&self, class_id: &ClassId) -> Result<Option<EquityToken>> {
        match self.db.get(cf::EQUITY_TOKENS, class_id)? {
            Some(bytes) => {
                let token: EquityToken = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    /// Check if token exists
    pub fn exists(&self, class_id: &ClassId) -> Result<bool> {
        self.db.contains(cf::EQUITY_TOKENS, class_id)
    }

    /// Update token status
    pub fn update_status(
        &self,
        class_id: &ClassId,
        status: TokenStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(class_id)? {
            Some(mut token) => {
                token.status = status;
                token.updated_at = timestamp;
                self.put(&token)
            }
            None => Err(StorageError::NotFound(format!(
                "Token not found: {:?}",
                class_id
            ))),
        }
    }

    /// Get tokens by issuer subject
    pub fn get_by_issuer(&self, issuer_subject: &SubjectId) -> Result<Vec<EquityToken>> {
        let mut tokens = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_TOKENS)? {
            let token: EquityToken = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if token.issuer_subject == *issuer_subject {
                tokens.push(token);
            }
        }
        Ok(tokens)
    }

    /// List all active tokens
    pub fn list_active(&self) -> Result<Vec<EquityToken>> {
        let mut tokens = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_TOKENS)? {
            let token: EquityToken = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if token.status == TokenStatus::Active {
                tokens.push(token);
            }
        }
        Ok(tokens)
    }

    /// Update issued shares (for mint/burn operations)
    pub fn update_issued_shares(
        &self,
        class_id: &ClassId,
        new_supply: u128,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(class_id)? {
            Some(mut token) => {
                token.issued_shares = new_supply;
                token.updated_at = timestamp;
                self.put(&token)
            }
            None => Err(StorageError::NotFound(format!(
                "Token not found: {:?}",
                class_id
            ))),
        }
    }
}

// =============================================================================
// Equity Balance Storage
// =============================================================================

/// Storage for equity balances (holder -> class_id -> balance)
pub struct EquityBalanceStore<'a> {
    db: &'a Database,
}

impl<'a> EquityBalanceStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Get balance for a holder in a token class
    pub fn get_balance(&self, class_id: &ClassId, holder_commitment: &[u8; 32]) -> Result<u64> {
        let key = Self::make_key(class_id, holder_commitment);
        match self.db.get(cf::EQUITY_BALANCES, &key)? {
            Some(bytes) => {
                let balance: u64 = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(balance)
            }
            None => Ok(0),
        }
    }

    /// Set balance for a holder
    pub fn set_balance(
        &self,
        class_id: &ClassId,
        holder_commitment: &[u8; 32],
        balance: u64,
    ) -> Result<()> {
        let key = Self::make_key(class_id, holder_commitment);
        if balance == 0 {
            // Remove zero balances
            self.db.delete(cf::EQUITY_BALANCES, &key)?;
            self.remove_from_holder_index(holder_commitment, class_id)?;
        } else {
            let bytes = bincode::serialize(&balance)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db.put(cf::EQUITY_BALANCES, &key, &bytes)?;
            self.add_to_holder_index(holder_commitment, class_id)?;
        }
        Ok(())
    }

    /// Transfer balance between holders
    pub fn transfer(
        &self,
        class_id: &ClassId,
        from_commitment: &[u8; 32],
        to_commitment: &[u8; 32],
        amount: u64,
    ) -> Result<()> {
        let from_balance = self.get_balance(class_id, from_commitment)?;
        if from_balance < amount {
            return Err(StorageError::InvalidData("Insufficient balance".to_string()));
        }

        let to_balance = self.get_balance(class_id, to_commitment)?;

        self.set_balance(class_id, from_commitment, from_balance - amount)?;
        self.set_balance(class_id, to_commitment, to_balance + amount)?;

        Ok(())
    }

    /// Get all holders for a token class
    pub fn get_holders(&self, class_id: &ClassId) -> Result<Vec<([u8; 32], u64)>> {
        let prefix = class_id;
        let mut holders = Vec::new();
        for (key, value) in self.db.prefix_iter(cf::EQUITY_BALANCES, prefix)? {
            if key.len() == 64 {
                let mut holder = [0u8; 32];
                holder.copy_from_slice(&key[32..64]);
                let balance: u64 = bincode::deserialize(&value)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                holders.push((holder, balance));
            }
        }
        Ok(holders)
    }

    /// Get all token classes held by a holder
    pub fn get_holdings(&self, holder_commitment: &[u8; 32]) -> Result<Vec<ClassId>> {
        match self.db.get(cf::EQUITY_HOLDER_INDEX, holder_commitment)? {
            Some(bytes) => {
                let class_ids: Vec<ClassId> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(class_ids)
            }
            None => Ok(Vec::new()),
        }
    }

    fn make_key(class_id: &ClassId, holder_commitment: &[u8; 32]) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(class_id);
        key[32..].copy_from_slice(holder_commitment);
        key
    }

    fn add_to_holder_index(
        &self,
        holder_commitment: &[u8; 32],
        class_id: &ClassId,
    ) -> Result<()> {
        let mut class_ids = self.get_holdings(holder_commitment)?;
        if !class_ids.contains(class_id) {
            class_ids.push(*class_id);
            let bytes = bincode::serialize(&class_ids)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.db
                .put(cf::EQUITY_HOLDER_INDEX, holder_commitment, &bytes)?;
        }
        Ok(())
    }

    fn remove_from_holder_index(
        &self,
        holder_commitment: &[u8; 32],
        class_id: &ClassId,
    ) -> Result<()> {
        let mut class_ids = self.get_holdings(holder_commitment)?;
        if let Some(pos) = class_ids.iter().position(|id| id == class_id) {
            class_ids.remove(pos);
            if class_ids.is_empty() {
                self.db.delete(cf::EQUITY_HOLDER_INDEX, holder_commitment)?;
            } else {
                let bytes = bincode::serialize(&class_ids)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db
                    .put(cf::EQUITY_HOLDER_INDEX, holder_commitment, &bytes)?;
            }
        }
        Ok(())
    }
}

// =============================================================================
// Equity Controller Storage (SRC-834)
// =============================================================================

/// Storage for Equity Controller Configs (SRC-834)
/// Controllers are stored by class_id (equity token class)
pub struct EquityControllerStore<'a> {
    db: &'a Database,
}

impl<'a> EquityControllerStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a controller config for a class
    pub fn put(&self, class_id: &ClassId, config: &EquityControllerConfig) -> Result<()> {
        let bytes =
            bincode::serialize(config).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EQUITY_CONTROLLERS, class_id, &bytes)
    }

    /// Get a controller config by class ID
    pub fn get(&self, class_id: &ClassId) -> Result<Option<EquityControllerConfig>> {
        match self.db.get(cf::EQUITY_CONTROLLERS, class_id)? {
            Some(bytes) => {
                let config: EquityControllerConfig = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    /// Check if controller config exists
    pub fn exists(&self, class_id: &ClassId) -> Result<bool> {
        self.db.contains(cf::EQUITY_CONTROLLERS, class_id)
    }

    /// Update controller config for a class
    pub fn update(&self, class_id: &ClassId, config: &EquityControllerConfig) -> Result<()> {
        if !self.exists(class_id)? {
            return Err(StorageError::NotFound(format!(
                "Controller config not found: {:?}",
                class_id
            )));
        }
        self.put(class_id, config)
    }

    /// Delete controller config
    pub fn delete(&self, class_id: &ClassId) -> Result<()> {
        self.db.delete(cf::EQUITY_CONTROLLERS, class_id)
    }
}

// =============================================================================
// Corporate Action Storage (SRC-835)
// =============================================================================

/// Storage for Corporate Actions (SRC-835)
pub struct CorporateActionStore<'a> {
    db: &'a Database,
}

impl<'a> CorporateActionStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a corporate action
    pub fn put(&self, action: &CorporateAction) -> Result<()> {
        let bytes =
            bincode::serialize(action).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db
            .put(cf::EQUITY_CORPORATE_ACTIONS, &action.action_id, &bytes)
    }

    /// Get a corporate action by ID
    pub fn get(&self, action_id: &ActionId) -> Result<Option<CorporateAction>> {
        match self.db.get(cf::EQUITY_CORPORATE_ACTIONS, action_id)? {
            Some(bytes) => {
                let action: CorporateAction = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(action))
            }
            None => Ok(None),
        }
    }

    /// Check if corporate action exists
    pub fn exists(&self, action_id: &ActionId) -> Result<bool> {
        self.db.contains(cf::EQUITY_CORPORATE_ACTIONS, action_id)
    }

    /// Update corporate action status
    pub fn update_status(
        &self,
        action_id: &ActionId,
        status: CorporateActionStatus,
        timestamp: Timestamp,
    ) -> Result<()> {
        match self.get(action_id)? {
            Some(mut action) => {
                action.status = status;
                action.executed_at = if status == CorporateActionStatus::Completed {
                    Some(timestamp)
                } else {
                    action.executed_at
                };
                let bytes = bincode::serialize(&action)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                self.db.put(cf::EQUITY_CORPORATE_ACTIONS, action_id, &bytes)
            }
            None => Err(StorageError::NotFound(format!(
                "Corporate action not found: {:?}",
                action_id
            ))),
        }
    }

    /// Get corporate actions by token class
    pub fn get_by_class(&self, class_id: &ClassId) -> Result<Vec<CorporateAction>> {
        let mut actions = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_CORPORATE_ACTIONS)? {
            let action: CorporateAction = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if action.class_id == *class_id {
                actions.push(action);
            }
        }
        Ok(actions)
    }

    /// Get pending corporate actions
    pub fn get_pending(&self) -> Result<Vec<CorporateAction>> {
        let mut actions = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_CORPORATE_ACTIONS)? {
            let action: CorporateAction = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if action.status == CorporateActionStatus::Proposed {
                actions.push(action);
            }
        }
        Ok(actions)
    }
}

// =============================================================================
// Ownership Snapshot Storage
// =============================================================================

/// Storage for Ownership Snapshots (SRC-835)
pub struct OwnershipSnapshotStore<'a> {
    db: &'a Database,
}

impl<'a> OwnershipSnapshotStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store a snapshot
    pub fn put(&self, snapshot: &OwnershipSnapshot) -> Result<()> {
        let bytes =
            bincode::serialize(snapshot).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db
            .put(cf::EQUITY_SNAPSHOTS, &snapshot.snapshot_id, &bytes)
    }

    /// Get a snapshot by ID
    pub fn get(&self, snapshot_id: &SnapshotId) -> Result<Option<OwnershipSnapshot>> {
        match self.db.get(cf::EQUITY_SNAPSHOTS, snapshot_id)? {
            Some(bytes) => {
                let snapshot: OwnershipSnapshot = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    /// Check if snapshot exists
    pub fn exists(&self, snapshot_id: &SnapshotId) -> Result<bool> {
        self.db.contains(cf::EQUITY_SNAPSHOTS, snapshot_id)
    }

    /// Get snapshots by token class
    pub fn get_by_class(&self, class_id: &ClassId) -> Result<Vec<OwnershipSnapshot>> {
        let mut snapshots = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_SNAPSHOTS)? {
            let snapshot: OwnershipSnapshot = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if snapshot.class_id == *class_id {
                snapshots.push(snapshot);
            }
        }
        // Sort by block height descending
        snapshots.sort_by(|a, b| b.block_height.cmp(&a.block_height));
        Ok(snapshots)
    }

    /// Get latest snapshot for a token class
    pub fn get_latest(&self, class_id: &ClassId) -> Result<Option<OwnershipSnapshot>> {
        let snapshots = self.get_by_class(class_id)?;
        Ok(snapshots.into_iter().next())
    }
}

// =============================================================================
// Ownership Proof Storage (SRC-836)
// =============================================================================

/// Storage for Ownership Proof Envelopes (SRC-836)
pub struct OwnershipProofStore<'a> {
    db: &'a Database,
}

impl<'a> OwnershipProofStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an ownership proof
    pub fn put(&self, proof: &OwnershipProofEnvelope) -> Result<()> {
        let bytes =
            bincode::serialize(proof).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EQUITY_PROOFS, &proof.proof_id, &bytes)
    }

    /// Get an ownership proof by ID
    pub fn get(&self, proof_id: &ProofId) -> Result<Option<OwnershipProofEnvelope>> {
        match self.db.get(cf::EQUITY_PROOFS, proof_id)? {
            Some(bytes) => {
                let proof: OwnershipProofEnvelope = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(proof))
            }
            None => Ok(None),
        }
    }

    /// Check if proof exists
    pub fn exists(&self, proof_id: &ProofId) -> Result<bool> {
        self.db.contains(cf::EQUITY_PROOFS, proof_id)
    }

    /// Delete a proof
    pub fn delete(&self, proof_id: &ProofId) -> Result<()> {
        self.db.delete(cf::EQUITY_PROOFS, proof_id)
    }

    /// Get valid proofs by subject nullifier (not expired)
    pub fn get_valid_by_subject(
        &self,
        subject_nullifier: &[u8; 32],
        current_time: Timestamp,
    ) -> Result<Vec<OwnershipProofEnvelope>> {
        let mut proofs = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_PROOFS)? {
            let proof: OwnershipProofEnvelope = bincode::deserialize(&value)
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
    pub fn get_by_profile(&self, profile_id: &str) -> Result<Vec<OwnershipProofEnvelope>> {
        let mut proofs = Vec::new();
        for (_, value) in self.db.iter(cf::EQUITY_PROOFS)? {
            let proof: OwnershipProofEnvelope = bincode::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            if proof.profile_id == profile_id {
                proofs.push(proof);
            }
        }
        Ok(proofs)
    }
}

// =============================================================================
// Equity Event Storage
// =============================================================================

/// Storage for Equity Events (indexing and audit trail)
pub struct EquityEventStore<'a> {
    db: &'a Database,
}

impl<'a> EquityEventStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Store an equity event
    pub fn put(
        &self,
        block_height: BlockHeight,
        event_index: u32,
        event: &EquityEvent,
    ) -> Result<()> {
        let key = Self::make_key(block_height, event_index);
        let bytes =
            bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(cf::EQUITY_EVENTS, &key, &bytes)
    }

    /// Get events for a block
    pub fn get_by_block(&self, block_height: BlockHeight) -> Result<Vec<EquityEvent>> {
        let prefix = block_height.to_be_bytes();
        let mut events = Vec::new();
        for (_, value) in self.db.prefix_iter(cf::EQUITY_EVENTS, &prefix)? {
            let event: EquityEvent = bincode::deserialize(&value)
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
    ) -> Result<Vec<EquityEvent>> {
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
// Unified Equity Store
// =============================================================================

/// Unified access to all SRC-83X storage
pub struct EquityStore<'a> {
    db: &'a Database,
}

impl<'a> EquityStore<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub fn entities(&self) -> EntityProfileStore<'a> {
        EntityProfileStore::new(self.db)
    }

    pub fn governance(&self) -> GovernanceActionStore<'a> {
        GovernanceActionStore::new(self.db)
    }

    pub fn tokens(&self) -> EquityTokenStore<'a> {
        EquityTokenStore::new(self.db)
    }

    pub fn balances(&self) -> EquityBalanceStore<'a> {
        EquityBalanceStore::new(self.db)
    }

    pub fn controllers(&self) -> EquityControllerStore<'a> {
        EquityControllerStore::new(self.db)
    }

    pub fn corporate_actions(&self) -> CorporateActionStore<'a> {
        CorporateActionStore::new(self.db)
    }

    pub fn snapshots(&self) -> OwnershipSnapshotStore<'a> {
        OwnershipSnapshotStore::new(self.db)
    }

    pub fn proofs(&self) -> OwnershipProofStore<'a> {
        OwnershipProofStore::new(self.db)
    }

    pub fn events(&self) -> EquityEventStore<'a> {
        EquityEventStore::new(self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::equity::{
        ControllerModel, GovernanceActionType, OrgType, OwnershipProofType, ShareClassType,
    };
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_entity_profile_store() {
        let (db, _dir) = temp_db();
        let store = EntityProfileStore::new(&db);

        let entity = EntityProfile {
            subject_id: [1u8; 32],
            org_type: OrgType::Corporation,
            name_commitment: [2u8; 32],
            jurisdiction: Some("US-DE".to_string()),
            registration_commitment: None,
            controller_model: ControllerModel::SingleSigner,
            controllers: vec![Address::from([3u8; 20])],
            multisig_threshold: None,
            services: vec![],
            metadata_hash: [0u8; 32],
            created_at: 1000,
            updated_at: 1000,
            status: EntityStatus::Active,
        };

        store.put(&entity).unwrap();
        let retrieved = store.get(&[1u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().org_type, OrgType::Corporation);
    }

    #[test]
    fn test_governance_action_store() {
        let (db, _dir) = temp_db();
        let store = GovernanceActionStore::new(&db);

        let action = GovernanceAction {
            action_id: [4u8; 32],
            org_subject: [1u8; 32],
            action_type: GovernanceActionType::BoardResolutionApproved,
            policy_id: [5u8; 32],
            action_commitment: [6u8; 32],
            effective_at: 1000,
            expires_at: 0,
            attachments: None,
            approvers: vec![Address::from([3u8; 20])],
            required_threshold: 1,
            status: GovernanceActionStatus::Approved,
            created_at: 1000,
            recorded_at_height: 100,
        };

        store.put(&action).unwrap();
        let retrieved = store.get(&[4u8; 32]).unwrap();
        assert!(retrieved.is_some());

        let by_entity = store.get_by_entity(&[1u8; 32]).unwrap();
        assert_eq!(by_entity.len(), 1);
    }

    #[test]
    fn test_equity_token_store() {
        let (db, _dir) = temp_db();
        let store = EquityTokenStore::new(&db);

        let token = EquityToken {
            issuer_subject: [1u8; 32],
            class_id: [6u8; 32],
            share_class_type: ShareClassType::Common,
            name: "Common Stock".to_string(),
            symbol: "ACME-A".to_string(),
            authorized_shares: 10_000_000,
            issued_shares: 1_000_000,
            votes_per_share: 1,
            economic_rights_hash: [7u8; 32],
            liquidation_preference_hash: None,
            dividend_policy_hash: None,
            conversion_rules_hash: None,
            controller: Address::from([3u8; 20]),
            par_value: Some(1),
            created_at: 1000,
            updated_at: 1000,
            status: TokenStatus::Active,
        };

        store.put(&token).unwrap();
        let retrieved = store.get(&[6u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().symbol, "ACME-A");
    }

    #[test]
    fn test_equity_balance_store() {
        let (db, _dir) = temp_db();
        let store = EquityBalanceStore::new(&db);

        let class_id = [6u8; 32];
        let holder1 = [10u8; 32];
        let holder2 = [11u8; 32];

        // Set balances
        store.set_balance(&class_id, &holder1, 1000).unwrap();
        store.set_balance(&class_id, &holder2, 500).unwrap();

        assert_eq!(store.get_balance(&class_id, &holder1).unwrap(), 1000);
        assert_eq!(store.get_balance(&class_id, &holder2).unwrap(), 500);

        // Transfer
        store.transfer(&class_id, &holder1, &holder2, 200).unwrap();
        assert_eq!(store.get_balance(&class_id, &holder1).unwrap(), 800);
        assert_eq!(store.get_balance(&class_id, &holder2).unwrap(), 700);

        // Get holders
        let holders = store.get_holders(&class_id).unwrap();
        assert_eq!(holders.len(), 2);

        // Get holdings
        let holdings = store.get_holdings(&holder1).unwrap();
        assert_eq!(holdings.len(), 1);
    }

    #[test]
    fn test_ownership_proof_store() {
        let (db, _dir) = temp_db();
        let store = OwnershipProofStore::new(&db);

        let proof = OwnershipProofEnvelope {
            proof_id: [20u8; 32],
            profile_id: "ownership.membership.v1".to_string(),
            policy_ids: vec![[21u8; 32]],
            public_inputs: vec![1, 2, 3, 4],
            proof_data: vec![5, 6, 7, 8],
            proof_type: OwnershipProofType::Mock,
            subject_nullifier: [22u8; 32],
            generated_at: 1000,
            expires_at: 2000,
        };

        store.put(&proof).unwrap();
        let retrieved = store.get(&[20u8; 32]).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().profile_id, "ownership.membership.v1");

        // Get by profile
        let by_profile = store.get_by_profile("ownership.membership.v1").unwrap();
        assert_eq!(by_profile.len(), 1);
    }
}

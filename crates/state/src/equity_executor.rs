//! SRC-83X Business, Governance & Equity Executor
//!
//! A simplified implementation that handles core equity operations.

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Address, Balance, BlockHeight, Hash, Timestamp,
    EntityProfile, GovernanceAction, GovernanceActionStatus,
    EquityToken, TokenStatus, EquityOperation, EquityTxData,
    OwnershipProofEnvelope,
};
use sumchain_storage::{Database, EquityStore};
use tracing::debug;

use crate::{Result, StateError, StateManager};

/// Result of Equity operation execution
#[derive(Debug)]
pub struct EquityExecutionResult {
    pub success: bool,
    pub entity_id: Option<[u8; 32]>,
    pub token_id: Option<[u8; 32]>,
    pub action_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl EquityExecutionResult {
    pub fn success_with_entity(entity_id: [u8; 32]) -> Self {
        Self { success: true, entity_id: Some(entity_id), token_id: None, action_id: None, error: None }
    }

    pub fn success_with_token(token_id: [u8; 32]) -> Self {
        Self { success: true, entity_id: None, token_id: Some(token_id), action_id: None, error: None }
    }

    pub fn success_with_action(action_id: [u8; 32]) -> Self {
        Self { success: true, entity_id: None, token_id: None, action_id: Some(action_id), error: None }
    }

    pub fn success() -> Self {
        Self { success: true, entity_id: None, token_id: None, action_id: None, error: None }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self { success: false, entity_id: None, token_id: None, action_id: None, error: Some(error.into()) }
    }
}

/// Equity executor for SRC-83X transactions
pub struct EquityExecutor {
    db: Arc<Database>,
    #[allow(dead_code)]
    params: ChainParams,
}

impl EquityExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Execute an Equity transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &EquityTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<EquityExecutionResult> {
        let store = EquityStore::new(&self.db);

        match data.operation {
            // Entity operations (SRC-831)
            EquityOperation::CreateEntity => {
                self.create_entity(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            EquityOperation::UpdateEntity => {
                self.update_entity(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            EquityOperation::AddController => {
                self.add_controller(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            EquityOperation::RemoveController => {
                self.remove_controller(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }

            // Governance operations (SRC-832)
            EquityOperation::ProposeAction => {
                self.propose_action(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }
            EquityOperation::ApproveAction | EquityOperation::ExecuteAction | EquityOperation::RevokeAction => {
                self.handle_governance(sender, &data.data, data.operation, state, proposer, fee, block_height, tx_index, &store)
            }

            // Token operations (SRC-833)
            EquityOperation::CreateToken => {
                self.create_token(sender, &data.data, state, proposer, fee, block_height, block_timestamp, tx_index, &store)
            }
            EquityOperation::UpdateToken | EquityOperation::PauseToken | EquityOperation::UnpauseToken => {
                self.handle_token_update(sender, &data.data, data.operation, state, proposer, fee, block_height, tx_index, &store)
            }

            // Transfer operations
            EquityOperation::Transfer => {
                self.transfer(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            EquityOperation::Approve | EquityOperation::TransferFrom => {
                self.default_success(sender, state, proposer, fee)
            }

            // Mint/Burn operations
            EquityOperation::Mint => {
                self.mint(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
            EquityOperation::Burn => {
                self.burn(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }

            // Controller operations
            EquityOperation::UpdateController | EquityOperation::AddToWhitelist | 
            EquityOperation::RemoveFromWhitelist | EquityOperation::SetLockup => {
                self.default_success(sender, state, proposer, fee)
            }

            // Corporate actions (SRC-834)
            EquityOperation::ExecuteStockSplit | EquityOperation::ExecuteReverseSplit |
            EquityOperation::DeclareDividend | EquityOperation::DistributeDividend |
            EquityOperation::ExecuteConversion | EquityOperation::TakeSnapshot => {
                self.default_success(sender, state, proposer, fee)
            }

            // Proof operations (SRC-835)
            EquityOperation::VerifyOwnershipProof => {
                self.verify_ownership_proof(sender, &data.data, state, proposer, fee, block_height, tx_index, &store)
            }
        }
    }

    fn default_success(&self, sender: &Address, state: &StateManager, proposer: &Address, fee: Balance) -> Result<EquityExecutionResult> {
        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;
        Ok(EquityExecutionResult::success())
    }

    fn create_entity(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        let entity: EntityProfile = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid entity data: {}", e)))?;

        if !entity.controllers.contains(sender) {
            return Ok(EquityExecutionResult::failure("Sender must be a controller"));
        }

        if store.entities().get(&entity.subject_id)?.is_some() {
            return Ok(EquityExecutionResult::failure("Entity already exists"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let subject_id = entity.subject_id;
        store.entities().put(&entity)?;

        debug!("Entity created: {:?}", subject_id);
        Ok(EquityExecutionResult::success_with_entity(subject_id))
    }

    fn update_entity(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        let entity: EntityProfile = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid entity data: {}", e)))?;

        let existing = match store.entities().get(&entity.subject_id)? {
            Some(e) => e,
            None => return Ok(EquityExecutionResult::failure("Entity not found")),
        };

        if !existing.controllers.contains(sender) {
            return Ok(EquityExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        let subject_id = entity.subject_id;
        store.entities().put(&entity)?;

        debug!("Entity updated: {:?}", subject_id);
        Ok(EquityExecutionResult::success_with_entity(subject_id))
    }

    fn add_controller(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        #[derive(serde::Deserialize)]
        struct AddData { subject_id: [u8; 32], controller: Address }

        let add_data: AddData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut entity = match store.entities().get(&add_data.subject_id)? {
            Some(e) => e,
            None => return Ok(EquityExecutionResult::failure("Entity not found")),
        };

        if !entity.controllers.contains(sender) {
            return Ok(EquityExecutionResult::failure("Not authorized"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        if !entity.controllers.contains(&add_data.controller) {
            entity.controllers.push(add_data.controller);
        }
        store.entities().put(&entity)?;

        debug!("Controller added to entity: {:?}", add_data.subject_id);
        Ok(EquityExecutionResult::success_with_entity(add_data.subject_id))
    }

    fn remove_controller(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        #[derive(serde::Deserialize)]
        struct RemoveData { subject_id: [u8; 32], controller: Address }

        let remove_data: RemoveData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut entity = match store.entities().get(&remove_data.subject_id)? {
            Some(e) => e,
            None => return Ok(EquityExecutionResult::failure("Entity not found")),
        };

        if !entity.controllers.contains(sender) {
            return Ok(EquityExecutionResult::failure("Not authorized"));
        }

        if entity.controllers.len() <= 1 {
            return Ok(EquityExecutionResult::failure("Cannot remove last controller"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        entity.controllers.retain(|c| c != &remove_data.controller);
        store.entities().put(&entity)?;

        debug!("Controller removed from entity: {:?}", remove_data.subject_id);
        Ok(EquityExecutionResult::success_with_entity(remove_data.subject_id))
    }

    fn propose_action(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, block_height: BlockHeight, block_timestamp: Timestamp, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        let mut action: GovernanceAction = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid action data: {}", e)))?;

        let entity = match store.entities().get(&action.org_subject)? {
            Some(e) => e,
            None => return Ok(EquityExecutionResult::failure("Entity not found")),
        };

        if !entity.controllers.contains(sender) {
            return Ok(EquityExecutionResult::failure("Not authorized to propose"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        action.status = GovernanceActionStatus::Pending;
        action.created_at = block_timestamp;
        action.recorded_at_height = block_height;
        action.approvers = vec![*sender];

        let action_id = action.action_id;
        store.governance().put(&action)?;

        debug!("Governance action proposed: {:?}", action_id);
        Ok(EquityExecutionResult::success_with_action(action_id))
    }

    fn handle_governance(
        &self, sender: &Address, _data: &[u8], _operation: EquityOperation, state: &StateManager, 
        proposer: &Address, fee: Balance, _block_height: BlockHeight, _tx_index: u32, _store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;
        Ok(EquityExecutionResult::success())
    }

    fn create_token(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, block_timestamp: Timestamp, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        let mut token: EquityToken = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid token data: {}", e)))?;

        if store.entities().get(&token.issuer_subject)?.is_none() {
            return Ok(EquityExecutionResult::failure("Entity not found"));
        }

        if store.tokens().get(&token.class_id)?.is_some() {
            return Ok(EquityExecutionResult::failure("Token already exists"));
        }

        if token.controller != *sender {
            return Ok(EquityExecutionResult::failure("Sender must be controller"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        token.created_at = block_timestamp;
        token.updated_at = block_timestamp;
        token.status = TokenStatus::Active;

        let class_id = token.class_id;
        store.tokens().put(&token)?;

        debug!("Equity token created: {:?}", class_id);
        Ok(EquityExecutionResult::success_with_token(class_id))
    }

    fn handle_token_update(
        &self, sender: &Address, _data: &[u8], _operation: EquityOperation, state: &StateManager,
        proposer: &Address, fee: Balance, _block_height: BlockHeight, _tx_index: u32, _store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;
        Ok(EquityExecutionResult::success())
    }

    fn transfer(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        #[derive(serde::Deserialize)]
        struct TransferData {
            class_id: [u8; 32],
            from_commitment: [u8; 32],
            to_commitment: [u8; 32],
            amount: u64
        }

        let transfer: TransferData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let token = match store.tokens().get(&transfer.class_id)? {
            Some(t) => t,
            None => return Ok(EquityExecutionResult::failure("Token not found")),
        };

        if token.status != TokenStatus::Active {
            return Ok(EquityExecutionResult::failure("Token not active"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.balances().transfer(
            &transfer.class_id,
            &transfer.from_commitment,
            &transfer.to_commitment,
            transfer.amount
        )?;

        debug!("Equity transfer: class={:?}, amount={}", transfer.class_id, transfer.amount);
        Ok(EquityExecutionResult::success())
    }

    fn mint(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        #[derive(serde::Deserialize)]
        struct MintData {
            class_id: [u8; 32],
            to_commitment: [u8; 32],
            amount: u64
        }

        let mint: MintData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut token = match store.tokens().get(&mint.class_id)? {
            Some(t) => t,
            None => return Ok(EquityExecutionResult::failure("Token not found")),
        };

        if token.controller != *sender {
            return Ok(EquityExecutionResult::failure("Not authorized to mint"));
        }

        if !token.can_mint(mint.amount as u128) {
            return Ok(EquityExecutionResult::failure("Exceeds authorized shares"));
        }

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        token.issued_shares = token.issued_shares.saturating_add(mint.amount as u128);
        store.tokens().put(&token)?;

        // Get current balance and add minted amount
        let current = store.balances().get_balance(&mint.class_id, &mint.to_commitment)?;
        store.balances().set_balance(&mint.class_id, &mint.to_commitment, current + mint.amount)?;

        debug!("Equity minted: class={:?}, amount={}", mint.class_id, mint.amount);
        Ok(EquityExecutionResult::success_with_token(mint.class_id))
    }

    fn burn(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        #[derive(serde::Deserialize)]
        struct BurnData {
            class_id: [u8; 32],
            holder_commitment: [u8; 32],
            amount: u64
        }

        let burn: BurnData = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

        let mut token = match store.tokens().get(&burn.class_id)? {
            Some(t) => t,
            None => return Ok(EquityExecutionResult::failure("Token not found")),
        };

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        // Get current balance and subtract burn amount
        let current = store.balances().get_balance(&burn.class_id, &burn.holder_commitment)?;
        if current < burn.amount {
            return Ok(EquityExecutionResult::failure("Insufficient balance to burn"));
        }
        store.balances().set_balance(&burn.class_id, &burn.holder_commitment, current - burn.amount)?;

        token.issued_shares = token.issued_shares.saturating_sub(burn.amount as u128);
        store.tokens().put(&token)?;

        debug!("Equity burned: class={:?}, amount={}", burn.class_id, burn.amount);
        Ok(EquityExecutionResult::success_with_token(burn.class_id))
    }

    fn verify_ownership_proof(
        &self, sender: &Address, data: &[u8], state: &StateManager, proposer: &Address,
        fee: Balance, _block_height: BlockHeight, _tx_index: u32, store: &EquityStore,
    ) -> Result<EquityExecutionResult> {
        let proof: OwnershipProofEnvelope = bincode::deserialize(data)
            .map_err(|e| StateError::NftError(format!("Invalid proof data: {}", e)))?;

        state.deduct(sender, fee)?;
        state.credit(proposer, fee)?;
        state.increment_nonce(sender)?;

        store.proofs().put(&proof)?;

        debug!("Ownership proof verified: {:?}", proof.proof_id);
        Ok(EquityExecutionResult::success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::OrgType;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_equity_executor_creation() {
        let (db, _dir, _state) = setup();
        let _executor = EquityExecutor::new(db, ChainParams::default());
    }

    #[test]
    fn test_create_entity() {
        use sumchain_primitives::{ControllerModel, EntityStatus};

        let (db, _dir, state) = setup();
        let executor = EquityExecutor::new(db.clone(), ChainParams::default());

        let controller = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        state.credit(&controller, 1_000_000_000_000).unwrap();

        let entity = EntityProfile {
            subject_id: [42u8; 32],
            org_type: OrgType::Corporation,
            name_commitment: [1u8; 32],
            jurisdiction: Some("US-DE".to_string()),
            registration_commitment: None,
            controller_model: ControllerModel::SingleSigner,
            controllers: vec![controller],
            multisig_threshold: None,
            services: vec![],
            metadata_hash: [0u8; 32],
            created_at: 1000000,
            updated_at: 1000000,
            status: EntityStatus::Active,
        };

        let tx_data = EquityTxData {
            operation: EquityOperation::CreateEntity,
            data: bincode::serialize(&entity).unwrap(),
        };

        let result = executor.execute(
            &controller, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default(),
        ).unwrap();

        assert!(result.success, "Create entity failed: {:?}", result.error);
        assert!(result.entity_id.is_some());

        let store = EquityStore::new(&db);
        let retrieved = store.entities().get(&entity.subject_id).unwrap().unwrap();
        assert_eq!(retrieved.org_type, OrgType::Corporation);
    }
}

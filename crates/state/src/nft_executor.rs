//! NFT Transaction Executor
//!
//! Handles execution of SUM-721 NFT operations including:
//! - Collection creation
//! - Token minting (standard and document)
//! - Transfers, approvals, burns
//! - Metadata updates

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sumchain_nft::collection::{CollectionConfig, CollectionId};
use sumchain_primitives::{Address, Balance, NftOperation, NftTxData};
use sumchain_storage::{Database, NftCollectionData, NftStore, NftTokenData};
use tracing::{debug, info};

use crate::{Result, StateError, StateManager};

/// Result of executing an NFT operation
#[derive(Debug)]
pub struct NftExecutionResult {
    /// Whether the operation succeeded
    pub success: bool,
    /// Collection ID (for create/mint operations)
    pub collection_id: Option<[u8; 32]>,
    /// Token ID (for mint operations)
    pub token_id: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
}

impl NftExecutionResult {
    fn success() -> Self {
        Self {
            success: true,
            collection_id: None,
            token_id: None,
            error: None,
        }
    }

    fn success_with_collection(collection_id: [u8; 32]) -> Self {
        Self {
            success: true,
            collection_id: Some(collection_id),
            token_id: None,
            error: None,
        }
    }

    fn success_with_token(collection_id: [u8; 32], token_id: u64) -> Self {
        Self {
            success: true,
            collection_id: Some(collection_id),
            token_id: Some(token_id),
            error: None,
        }
    }

    fn failure(error: String) -> Self {
        Self {
            success: false,
            collection_id: None,
            token_id: None,
            error: Some(error),
        }
    }
}

/// NFT Executor for processing NFT transactions
pub struct NftExecutor {
    db: Arc<Database>,
}

impl NftExecutor {
    /// Create a new NFT executor
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Get current timestamp in milliseconds
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Execute an NFT operation from transaction data
    pub fn execute(
        &self,
        sender: &Address,
        nft_data: &NftTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
    ) -> Result<NftExecutionResult> {
        let store = NftStore::new(&self.db);

        // Deduct fee from sender
        self.deduct_fee(state, sender, fee, proposer)?;

        match nft_data.operation {
            NftOperation::CreateCollection => {
                self.execute_create_collection(&store, sender, &nft_data.data)
            }
            NftOperation::Mint => {
                self.execute_mint(&store, sender, &nft_data.collection_id, &nft_data.data, false)
            }
            NftOperation::MintDocument => {
                self.execute_mint(&store, sender, &nft_data.collection_id, &nft_data.data, true)
            }
            NftOperation::BatchMint => {
                self.execute_batch_mint(&store, sender, &nft_data.collection_id, &nft_data.data)
            }
            NftOperation::Transfer => self.execute_transfer(
                &store,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
            ),
            NftOperation::Approve => self.execute_approve(
                &store,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
            ),
            NftOperation::SetApprovalForAll => {
                // For simplicity, we don't implement operator approvals in MVP
                Ok(NftExecutionResult::failure(
                    "SetApprovalForAll not yet implemented".to_string(),
                ))
            }
            NftOperation::Burn => {
                self.execute_burn(&store, sender, &nft_data.collection_id, nft_data.token_id)
            }
            NftOperation::UpdateMetadata => self.execute_update_metadata(
                &store,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
            ),
            NftOperation::TransferCollectionOwnership => self.execute_transfer_collection(
                &store,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
            ),
            NftOperation::UpdateCollectionConfig => self.execute_update_collection_config(
                &store,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
            ),
            NftOperation::LockToken => {
                self.execute_lock_token(&store, sender, &nft_data.collection_id, nft_data.token_id)
            }
            NftOperation::UnlockToken => self.execute_unlock_token(
                &store,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
            ),
        }
    }

    /// Deduct fee from sender and credit to proposer
    fn deduct_fee(
        &self,
        state: &StateManager,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        let sender_balance = state.get_balance(sender)?;
        if sender_balance < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: sender_balance,
            });
        }

        // Debit sender
        let mut sender_account = state.get_account(sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        state.put_account(sender, &sender_account)?;

        // Credit proposer
        if !proposer.is_zero() {
            let mut proposer_account = state.get_account(proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            state.put_account(proposer, &proposer_account)?;
        }

        Ok(())
    }

    /// Create a new NFT collection
    fn execute_create_collection(
        &self,
        store: &NftStore,
        sender: &Address,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Deserialize collection creation data
        #[derive(serde::Deserialize)]
        struct CreateCollectionData {
            name: String,
            symbol: String,
            description: String,
            config: CollectionConfig,
            base_uri: Option<String>,
        }

        let create_data: CreateCollectionData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid collection data: {}", e)))?;

        // Validate config
        create_data
            .config
            .validate()
            .map_err(|e| StateError::BlockValidation(format!("Invalid config: {}", e)))?;

        // Generate collection ID
        let nonce = Self::now_ms();
        let collection_id = CollectionId::new(sender, &create_data.name, nonce);

        // Check if collection already exists
        if store.collection_exists(collection_id.as_bytes())? {
            return Ok(NftExecutionResult::failure(
                "Collection already exists".to_string(),
            ));
        }

        // Create collection data
        let collection_data = NftCollectionData {
            name: create_data.name.clone(),
            symbol: create_data.symbol,
            description: create_data.description,
            owner: *sender,
            max_supply: create_data.config.max_supply,
            total_supply: 0,
            next_token_id: 1,
            transferable: create_data.config.transferable,
            burnable: create_data.config.burnable,
            metadata_updatable: create_data.config.metadata_updatable,
            owner_only_minting: create_data.config.owner_only_minting,
            royalty_bps: create_data.config.royalty_bps,
            royalty_recipient: if create_data.config.royalty_bps > 0 {
                create_data.config.royalty_recipient
            } else {
                Address::ZERO
            },
            base_uri: create_data.base_uri,
            created_at: Self::now_ms(),
        };

        store.put_collection(collection_id.as_bytes(), &collection_data)?;

        info!(
            "Created NFT collection '{}' with ID {}",
            create_data.name, collection_id
        );

        Ok(NftExecutionResult::success_with_collection(
            *collection_id.as_bytes(),
        ))
    }

    /// Mint a new token
    fn execute_mint(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
        is_document: bool,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = store.get_collection(collection_id)?.ok_or_else(|| {
            StateError::BlockValidation("Collection not found".to_string())
        })?;

        // Check minting permission
        if collection.owner_only_minting && collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Only collection owner can mint".to_string(),
            ));
        }

        // Check max supply
        if collection.max_supply > 0 && collection.total_supply >= collection.max_supply {
            return Ok(NftExecutionResult::failure("Max supply reached".to_string()));
        }

        // Deserialize mint data
        #[derive(serde::Deserialize)]
        struct MintData {
            to: Address,
            metadata: Vec<u8>,
            uri_type: String,
            uri_value: Option<String>,
        }

        let mint_data: MintData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid mint data: {}", e)))?;

        let token_id = collection.next_token_id;

        // Create token data
        let token_data = NftTokenData {
            collection_id: *collection_id,
            token_id,
            owner: mint_data.to,
            creator: *sender,
            metadata: mint_data.metadata,
            is_document,
            uri_type: mint_data.uri_type,
            uri_value: mint_data.uri_value,
            approved: None,
            locked: false,
            transfer_count: 0,
            minted_at: Self::now_ms(),
        };

        // Store token
        store.put_token(collection_id, token_id, &token_data)?;

        // Update indices
        store.add_to_owner_index(&mint_data.to, collection_id, token_id)?;
        store.add_to_collection_index(collection_id, token_id)?;

        // Update collection
        collection.total_supply += 1;
        collection.next_token_id += 1;
        store.put_collection(collection_id, &collection)?;

        debug!(
            "Minted token {} in collection {:?} to {}",
            token_id,
            hex::encode(collection_id),
            mint_data.to
        );

        Ok(NftExecutionResult::success_with_token(*collection_id, token_id))
    }

    /// Batch mint tokens
    fn execute_batch_mint(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = store.get_collection(collection_id)?.ok_or_else(|| {
            StateError::BlockValidation("Collection not found".to_string())
        })?;

        // Check minting permission
        if collection.owner_only_minting && collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Only collection owner can mint".to_string(),
            ));
        }

        // Deserialize batch mint data
        #[derive(serde::Deserialize)]
        struct BatchMintData {
            requests: Vec<BatchMintRequest>,
        }

        #[derive(serde::Deserialize)]
        struct BatchMintRequest {
            to: Address,
            metadata: Vec<u8>,
        }

        let batch_data: BatchMintData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid batch data: {}", e)))?;

        let count = batch_data.requests.len() as u64;

        // Check max supply
        if collection.max_supply > 0 && collection.total_supply + count > collection.max_supply {
            return Ok(NftExecutionResult::failure(
                "Batch would exceed max supply".to_string(),
            ));
        }

        let first_token_id = collection.next_token_id;

        for (i, request) in batch_data.requests.iter().enumerate() {
            let token_id = first_token_id + i as u64;

            let token_data = NftTokenData {
                collection_id: *collection_id,
                token_id,
                owner: request.to,
                creator: *sender,
                metadata: request.metadata.clone(),
                is_document: false,
                uri_type: "onchain".to_string(),
                uri_value: None,
                approved: None,
                locked: false,
                transfer_count: 0,
                minted_at: Self::now_ms(),
            };

            store.put_token(collection_id, token_id, &token_data)?;
            store.add_to_owner_index(&request.to, collection_id, token_id)?;
            store.add_to_collection_index(collection_id, token_id)?;
        }

        // Update collection
        collection.total_supply += count;
        collection.next_token_id += count;
        store.put_collection(collection_id, &collection)?;

        info!(
            "Batch minted {} tokens in collection {:?}",
            count,
            hex::encode(collection_id)
        );

        Ok(NftExecutionResult::success_with_token(
            *collection_id,
            first_token_id,
        ))
    }

    /// Transfer a token
    fn execute_transfer(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = store.get_collection(collection_id)?.ok_or_else(|| {
            StateError::BlockValidation("Collection not found".to_string())
        })?;

        if !collection.transferable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow transfers".to_string(),
            ));
        }

        // Get token
        let token = store.get_token(collection_id, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership or approval
        let is_owner = token.owner == *sender;
        let is_approved = token.approved.as_ref() == Some(sender);

        if !is_owner && !is_approved {
            return Ok(NftExecutionResult::failure(
                "Not owner or approved".to_string(),
            ));
        }

        // Check if locked
        if token.locked {
            return Ok(NftExecutionResult::failure("Token is locked".to_string()));
        }

        // Deserialize recipient
        #[derive(serde::Deserialize)]
        struct TransferData {
            to: Address,
        }

        let transfer_data: TransferData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        // Execute transfer
        store.transfer_token(collection_id, token_id, &token.owner, &transfer_data.to)?;

        debug!(
            "Transferred token {}:{} from {} to {}",
            hex::encode(collection_id),
            token_id,
            token.owner,
            transfer_data.to
        );

        Ok(NftExecutionResult::success())
    }

    /// Approve an address to transfer a token
    fn execute_approve(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = store.get_token(collection_id, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        // Deserialize approval data
        #[derive(serde::Deserialize)]
        struct ApproveData {
            approved: Option<Address>,
        }

        let approve_data: ApproveData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid approve data: {}", e)))?;

        token.approved = approve_data.approved;
        store.put_token(collection_id, token_id, &token)?;

        debug!(
            "Set approval for token {}:{} to {:?}",
            hex::encode(collection_id),
            token_id,
            approve_data.approved
        );

        Ok(NftExecutionResult::success())
    }

    /// Burn a token
    fn execute_burn(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = store.get_collection(collection_id)?.ok_or_else(|| {
            StateError::BlockValidation("Collection not found".to_string())
        })?;

        if !collection.burnable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow burns".to_string(),
            ));
        }

        // Get token
        let token = store.get_token(collection_id, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        // Check if locked
        if token.locked {
            return Ok(NftExecutionResult::failure("Token is locked".to_string()));
        }

        // Burn token
        store.burn_token(collection_id, token_id, &token.owner)?;

        info!(
            "Burned token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Update token metadata
    fn execute_update_metadata(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = store.get_collection(collection_id)?.ok_or_else(|| {
            StateError::BlockValidation("Collection not found".to_string())
        })?;

        if !collection.metadata_updatable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow metadata updates".to_string(),
            ));
        }

        // Get token
        let mut token = store.get_token(collection_id, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Only owner or creator can update
        if token.owner != *sender && token.creator != *sender {
            return Ok(NftExecutionResult::failure(
                "Not owner or creator".to_string(),
            ));
        }

        // Update metadata
        token.metadata = data.to_vec();
        store.put_token(collection_id, token_id, &token)?;

        debug!(
            "Updated metadata for token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Transfer collection ownership
    fn execute_transfer_collection(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = store.get_collection(collection_id)?.ok_or_else(|| {
            StateError::BlockValidation("Collection not found".to_string())
        })?;

        // Check ownership
        if collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Not collection owner".to_string(),
            ));
        }

        // Deserialize new owner
        #[derive(serde::Deserialize)]
        struct TransferOwnerData {
            new_owner: Address,
        }

        let transfer_data: TransferOwnerData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        collection.owner = transfer_data.new_owner;
        store.put_collection(collection_id, &collection)?;

        info!(
            "Transferred collection {:?} ownership to {}",
            hex::encode(collection_id),
            transfer_data.new_owner
        );

        Ok(NftExecutionResult::success())
    }

    /// Update collection config
    fn execute_update_collection_config(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = store.get_collection(collection_id)?.ok_or_else(|| {
            StateError::BlockValidation("Collection not found".to_string())
        })?;

        // Check ownership
        if collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Not collection owner".to_string(),
            ));
        }

        // Deserialize config update
        #[derive(serde::Deserialize)]
        struct ConfigUpdateData {
            new_royalty_recipient: Option<Address>,
            new_base_uri: Option<String>,
        }

        let update_data: ConfigUpdateData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid config data: {}", e)))?;

        if let Some(recipient) = update_data.new_royalty_recipient {
            collection.royalty_recipient = recipient;
        }
        if let Some(uri) = update_data.new_base_uri {
            collection.base_uri = Some(uri);
        }

        store.put_collection(collection_id, &collection)?;

        debug!(
            "Updated config for collection {:?}",
            hex::encode(collection_id)
        );

        Ok(NftExecutionResult::success())
    }

    /// Lock a token
    fn execute_lock_token(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = store.get_token(collection_id, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        if token.locked {
            return Ok(NftExecutionResult::failure(
                "Token already locked".to_string(),
            ));
        }

        token.locked = true;
        store.put_token(collection_id, token_id, &token)?;

        debug!(
            "Locked token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Unlock a token
    fn execute_unlock_token(
        &self,
        store: &NftStore,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = store.get_token(collection_id, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        if !token.locked {
            return Ok(NftExecutionResult::failure("Token not locked".to_string()));
        }

        token.locked = false;
        store.put_token(collection_id, token_id, &token)?;

        debug!(
            "Unlocked token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        (db, dir)
    }

    #[test]
    fn test_create_collection() {
        let (db, _dir) = setup();
        let executor = NftExecutor::new(db.clone());
        let store = NftStore::new(&db);

        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        // Create collection data
        #[derive(serde::Serialize)]
        struct CreateData {
            name: String,
            symbol: String,
            description: String,
            config: CollectionConfig,
            base_uri: Option<String>,
        }

        let create_data = CreateData {
            name: "Test Collection".to_string(),
            symbol: "TEST".to_string(),
            description: "A test collection".to_string(),
            config: CollectionConfig::default(),
            base_uri: None,
        };

        let data = bincode::serialize(&create_data).unwrap();

        let result = executor
            .execute_create_collection(&store, &sender, &data)
            .unwrap();

        assert!(result.success);
        assert!(result.collection_id.is_some());

        // Verify collection exists
        let collection_id = result.collection_id.unwrap();
        let collection = store.get_collection(&collection_id).unwrap().unwrap();
        assert_eq!(collection.name, "Test Collection");
        assert_eq!(collection.symbol, "TEST");
        assert_eq!(collection.owner, sender);
    }
}

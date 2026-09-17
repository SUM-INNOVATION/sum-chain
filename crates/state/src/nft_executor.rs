//! NFT Transaction Executor
//!
//! Handles execution of SUM-721 NFT operations including:
//! - Collection creation
//! - Token minting (standard and document)
//! - Transfers, approvals, burns
//! - Metadata updates
//!
//! ## Security Features
//!
//! - **Per-byte storage pricing**: Metadata size affects transaction fees to prevent state bloat
//! - **Issuer registry**: Only registered issuers can mint certified document NFTs
//! - **Metadata size limits**: Maximum metadata size enforced per chain params

use sumchain_storage::exec_view::ExecutionView;

use sumchain_genesis::ChainParams;
use sumchain_nft::collection::CollectionId;
use sumchain_nft::ops::{
    CreateCollectionData, NftApproveData, NftBatchMintData, NftMintData,
    NftTransferCollectionOwnershipData, NftTransferData, NftUpdateCollectionConfigData,
};
use sumchain_primitives::{Address, Balance, NftOperation, NftTxData};
use sumchain_storage::{NftCollectionData, NftTokenData};
use tracing::{debug, info, warn};

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

/// NFT Executor for processing NFT transactions.
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::schema` for the RPC server.
///
/// `ChainParams` travels as a parameter for the same reason. It used to ride on
/// the receiver beside the database handle, and the only way to be sure the
/// handle is gone is for there to be no receiver at all.
pub struct NftExecutor;

impl NftExecutor {
    /// Get current timestamp in milliseconds (now uses block timestamp for determinism)
    fn now_ms(block_timestamp: u64) -> u64 {
        block_timestamp
    }

    /// Execute an NFT operation from transaction data
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
    ) -> Result<NftExecutionResult> {
        // Deduct fee from sender
        Self::deduct_fee(view, sender, fee, proposer)?;

        match nft_data.operation {
            NftOperation::CreateCollection => {
                Self::execute_create_collection(view, sender, &nft_data.data, block_timestamp)
            }
            NftOperation::Mint => Self::execute_mint(
                view,
                params,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
                false,
                fee,
                block_timestamp,
            ),
            NftOperation::MintDocument => Self::execute_mint(
                view,
                params,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
                true,
                fee,
                block_timestamp,
            ),
            NftOperation::BatchMint => Self::execute_batch_mint(
                view,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
                block_timestamp,
            ),
            NftOperation::Transfer => Self::execute_transfer(
                view,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
            ),
            NftOperation::Approve => Self::execute_approve(
                view,
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
                Self::execute_burn(view, sender, &nft_data.collection_id, nft_data.token_id)
            }
            NftOperation::UpdateMetadata => Self::execute_update_metadata(
                view,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
            ),
            NftOperation::TransferCollectionOwnership => Self::execute_transfer_collection(
                view,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
            ),
            NftOperation::UpdateCollectionConfig => Self::execute_update_collection_config(
                view,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
            ),
            NftOperation::LockToken => {
                Self::execute_lock_token(view, sender, &nft_data.collection_id, nft_data.token_id)
            }
            NftOperation::UnlockToken => {
                Self::execute_unlock_token(view, sender, &nft_data.collection_id, nft_data.token_id)
            }
        }
    }

    /// Deduct fee from sender and credit to proposer
    fn deduct_fee(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        let sender_balance = StateManager::v_get_balance(view, sender)?;
        if sender_balance < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: sender_balance,
            });
        }

        // Debit sender
        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        StateManager::v_put_account(view, sender, &sender_account)?;

        // Credit proposer
        if !proposer.is_zero() {
            let mut proposer_account = StateManager::v_get_account(view, proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            StateManager::v_put_account(view, proposer, &proposer_account)?;
        }

        Ok(())
    }

    /// Create a new NFT collection
    fn execute_create_collection(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        block_timestamp: u64,
    ) -> Result<NftExecutionResult> {
        // Deserialize collection creation data
        // Shared wire struct (issue #89)
        let create_data: CreateCollectionData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid collection data: {}", e)))?;

        // Validate config
        create_data
            .config
            .validate()
            .map_err(|e| StateError::BlockValidation(format!("Invalid config: {}", e)))?;

        // Generate collection ID
        let nonce = Self::now_ms(block_timestamp);
        let collection_id = CollectionId::new(sender, &create_data.name, nonce);

        // Check if collection already exists
        if Self::v_collection_exists(view, collection_id.as_bytes())? {
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
            created_at: Self::now_ms(block_timestamp),
        };

        Self::v_put_collection(view, collection_id.as_bytes(), &collection_data)?;

        info!(
            "Created NFT collection '{}' with ID {}",
            create_data.name, collection_id
        );

        Ok(NftExecutionResult::success_with_collection(
            *collection_id.as_bytes(),
        ))
    }

    /// Mint a new token
    #[allow(clippy::too_many_arguments)]
    fn execute_mint(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
        is_document: bool,
        fee: Balance,
        block_timestamp: u64,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

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
        // Shared wire struct (issue #89)
        let mint_data: NftMintData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid mint data: {}", e)))?;

        // Security: Validate metadata size
        let metadata_size = mint_data.metadata.len();
        if !params.validate_metadata_size(metadata_size) {
            return Ok(NftExecutionResult::failure(format!(
                "Metadata too large: {} bytes exceeds maximum of {} bytes",
                metadata_size, params.max_metadata_bytes
            )));
        }

        // Security: Validate storage fee (per-byte pricing)
        let required_fee = params.calculate_nft_storage_fee(metadata_size);
        if fee < required_fee {
            return Ok(NftExecutionResult::failure(format!(
                "Insufficient storage fee: {} required for {} bytes of metadata, got {}",
                required_fee, metadata_size, fee
            )));
        }

        // Security: For document minting, verify issuer is registered
        if is_document {
            let current_time = Self::now_ms(block_timestamp);

            if !Self::v_can_mint_documents(view, sender, None, current_time)? {
                warn!(
                    "Unauthorized document minting attempt by {} - not a registered issuer",
                    sender
                );
                return Ok(NftExecutionResult::failure(
                    "Sender is not a registered document issuer. Only verified issuers can mint certified documents.".to_string(),
                ));
            }

            debug!(
                "Verified issuer {} for document minting",
                sender
            );
        }

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
            minted_at: Self::now_ms(block_timestamp),
        };

        // Store token
        Self::v_put_token(view, collection_id, token_id, &token_data)?;

        // Update indices
        Self::v_add_to_owner_index(view, &mint_data.to, collection_id, token_id)?;
        Self::v_add_to_collection_index(view, collection_id, token_id)?;

        // Update collection
        collection.total_supply += 1;
        collection.next_token_id += 1;
        Self::v_put_collection(view, collection_id, &collection)?;

        debug!(
            "Minted token {} in collection {:?} to {} (metadata: {} bytes, fee: {})",
            token_id,
            hex::encode(collection_id),
            mint_data.to,
            metadata_size,
            fee
        );

        Ok(NftExecutionResult::success_with_token(*collection_id, token_id))
    }

    /// Batch mint tokens
    fn execute_batch_mint(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
        block_timestamp: u64,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        // Check minting permission
        if collection.owner_only_minting && collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Only collection owner can mint".to_string(),
            ));
        }

        // Deserialize batch mint data
        // Shared wire struct (issue #89)
        let batch_data: NftBatchMintData = bincode::deserialize(data)
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
                minted_at: Self::now_ms(block_timestamp),
            };

            Self::v_put_token(view, collection_id, token_id, &token_data)?;
            Self::v_add_to_owner_index(view, &request.to, collection_id, token_id)?;
            Self::v_add_to_collection_index(view, collection_id, token_id)?;
        }

        // Update collection
        collection.total_supply += count;
        collection.next_token_id += count;
        Self::v_put_collection(view, collection_id, &collection)?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        if !collection.transferable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow transfers".to_string(),
            ));
        }

        // Get token
        let token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

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
        // Shared wire struct (issue #89)
        let transfer_data: NftTransferData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        // Execute transfer
        Self::v_transfer_token(
            view,
            collection_id,
            token_id,
            &token.owner,
            &transfer_data.to,
        )?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        // Deserialize approval data
        // Shared wire struct (issue #89)
        let approve_data: NftApproveData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid approve data: {}", e)))?;

        token.approved = approve_data.approved;
        Self::v_put_token(view, collection_id, token_id, &token)?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        if !collection.burnable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow burns".to_string(),
            ));
        }

        // Get token
        let token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        // Check if locked
        if token.locked {
            return Ok(NftExecutionResult::failure("Token is locked".to_string()));
        }

        // Burn token
        Self::v_burn_token(view, collection_id, token_id, &token.owner)?;

        info!(
            "Burned token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Update token metadata
    fn execute_update_metadata(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        if !collection.metadata_updatable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow metadata updates".to_string(),
            ));
        }

        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Only owner or creator can update
        if token.owner != *sender && token.creator != *sender {
            return Ok(NftExecutionResult::failure(
                "Not owner or creator".to_string(),
            ));
        }

        // Update metadata
        token.metadata = data.to_vec();
        Self::v_put_token(view, collection_id, token_id, &token)?;

        debug!(
            "Updated metadata for token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Transfer collection ownership
    fn execute_transfer_collection(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        // Check ownership
        if collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Not collection owner".to_string(),
            ));
        }

        // Deserialize new owner
        // Shared wire struct (issue #89)
        let transfer_data: NftTransferCollectionOwnershipData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        collection.owner = transfer_data.new_owner;
        Self::v_put_collection(view, collection_id, &collection)?;

        info!(
            "Transferred collection {:?} ownership to {}",
            hex::encode(collection_id),
            transfer_data.new_owner
        );

        Ok(NftExecutionResult::success())
    }

    /// Update collection config
    fn execute_update_collection_config(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        // Check ownership
        if collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Not collection owner".to_string(),
            ));
        }

        // Deserialize config update
        // Shared wire struct (issue #89)
        let update_data: NftUpdateCollectionConfigData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid config data: {}", e)))?;

        if let Some(recipient) = update_data.new_royalty_recipient {
            collection.royalty_recipient = recipient;
        }
        if let Some(uri) = update_data.new_base_uri {
            collection.base_uri = Some(uri);
        }

        Self::v_put_collection(view, collection_id, &collection)?;

        debug!(
            "Updated config for collection {:?}",
            hex::encode(collection_id)
        );

        Ok(NftExecutionResult::success())
    }

    /// Lock a token
    fn execute_lock_token(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

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
        Self::v_put_token(view, collection_id, token_id, &token)?;

        debug!(
            "Locked token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Unlock a token
    fn execute_unlock_token(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        if !token.locked {
            return Ok(NftExecutionResult::failure("Token not locked".to_string()));
        }

        token.locked = false;
        Self::v_put_token(view, collection_id, token_id, &token)?;

        debug!(
            "Unlocked token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use sumchain_nft::collection::CollectionConfig;
    use sumchain_storage::candidate::CandidateExecution;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Database, ChainParams, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let params = ChainParams::default();
        (db, params, dir)
    }

    #[test]
    fn test_create_collection() {
        let (db, _params, _dir) = setup();

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

        // The executor stages into a block candidate, so this opens one. It is
        // never published: the collection is read back through the candidate.
        let mut candidate = CandidateExecution::new(&db, 1 << 30);
        let mut view = candidate.view();

        let result =
            NftExecutor::execute_create_collection(&mut view, &sender, &data, 1_000_000_000)
                .unwrap();

        assert!(result.success);
        assert!(result.collection_id.is_some());

        // Verify collection exists
        let collection_id = result.collection_id.unwrap();
        let collection = NftExecutor::v_get_collection(&view, &collection_id)
            .unwrap()
            .unwrap();
        assert_eq!(collection.name, "Test Collection");
        assert_eq!(collection.symbol, "TEST");
        assert_eq!(collection.owner, sender);
    }
}

//! SRC-20 Token Transaction Executor
//!
//! Handles execution of SRC-20 token operations including:
//! - Token creation
//! - Minting and burning
//! - Transfers and approvals
//! - Pause/unpause functionality
//!
//! ## Security Features
//!
//! - **Role-based access control**: Owner-only operations, minter whitelist
//! - **Overflow protection**: All arithmetic uses checked/saturating operations
//! - **Pause mechanism**: Token transfers can be paused by owner

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, Balance, BlockHeight, Hash, TokenOperation, TokenTxData};
use sumchain_storage::{Database, Src20TokenData, TokenStore};
use tracing::{debug, info};

use crate::{Result, StateError, StateManager};

/// Result of executing a token operation
#[derive(Debug)]
pub struct TokenExecutionResult {
    /// Whether the operation succeeded
    pub success: bool,
    /// Token ID (for create operations)
    pub token_id: Option<[u8; 32]>,
    /// Error message if failed
    pub error: Option<String>,
}

impl TokenExecutionResult {
    fn success() -> Self {
        Self {
            success: true,
            token_id: None,
            error: None,
        }
    }

    fn success_with_token(token_id: [u8; 32]) -> Self {
        Self {
            success: true,
            token_id: Some(token_id),
            error: None,
        }
    }

    fn failure(error: String) -> Self {
        Self {
            success: false,
            token_id: None,
            error: Some(error),
        }
    }
}

/// SRC-20 Token Executor for processing token transactions
pub struct TokenExecutor {
    db: Arc<Database>,
    #[allow(dead_code)]
    params: ChainParams,
}

impl TokenExecutor {
    /// Create a new token executor
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Get current timestamp in milliseconds (now uses block timestamp for determinism)
    fn now_ms(block_timestamp: u64) -> u64 {
        block_timestamp
    }

    /// Generate a token ID from creator, name, and nonce
    fn generate_token_id(creator: &Address, name: &str, nonce: u64) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(creator.as_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&nonce.to_be_bytes());
        let hash = Hash::hash(&data);
        *hash.as_bytes()
    }

    /// Execute a token operation from transaction data
    pub fn execute(
        &self,
        sender: &Address,
        token_data: &TokenTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<TokenExecutionResult> {
        let store = TokenStore::new(&self.db);

        // Deduct fee from sender
        self.deduct_fee(state, sender, fee, proposer)?;

        match token_data.operation {
            TokenOperation::Create => {
                self.execute_create(&store, sender, &token_data.data, block_height, block_timestamp)
            }
            TokenOperation::Mint => {
                self.execute_mint(&store, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Burn => {
                self.execute_burn(&store, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Transfer => {
                self.execute_transfer(&store, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Approve => {
                self.execute_approve(&store, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::TransferFrom => {
                self.execute_transfer_from(&store, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Pause => {
                self.execute_pause(&store, sender, &token_data.token_id)
            }
            TokenOperation::Unpause => {
                self.execute_unpause(&store, sender, &token_data.token_id)
            }
            TokenOperation::TransferOwnership => {
                self.execute_transfer_ownership(&store, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::AddMinter => {
                self.execute_add_minter(&store, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::RemoveMinter => {
                self.execute_remove_minter(&store, sender, &token_data.token_id, &token_data.data)
            }
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

    /// Create a new SRC-20 token
    fn execute_create(
        &self,
        store: &TokenStore,
        sender: &Address,
        data: &[u8],
        block_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<TokenExecutionResult> {
        // Deserialize creation data
        #[derive(serde::Deserialize)]
        struct CreateData {
            name: String,
            symbol: String,
            decimals: u8,
            initial_supply: u128,
            max_supply: u128,
            mintable: bool,
            burnable: bool,
            pausable: bool,
        }

        let create_data: CreateData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid token creation data: {}", e)))?;

        // Validate parameters
        if create_data.name.is_empty() || create_data.name.len() > 64 {
            return Ok(TokenExecutionResult::failure(
                "Token name must be 1-64 characters".to_string(),
            ));
        }

        if create_data.symbol.is_empty() || create_data.symbol.len() > 16 {
            return Ok(TokenExecutionResult::failure(
                "Token symbol must be 1-16 characters".to_string(),
            ));
        }

        if create_data.decimals > 18 {
            return Ok(TokenExecutionResult::failure(
                "Decimals must be <= 18".to_string(),
            ));
        }

        if create_data.max_supply > 0 && create_data.initial_supply > create_data.max_supply {
            return Ok(TokenExecutionResult::failure(
                "Initial supply exceeds max supply".to_string(),
            ));
        }

        // Generate token ID
        let nonce = Self::now_ms(block_timestamp);
        let token_id = Self::generate_token_id(sender, &create_data.name, nonce);

        // Check if token already exists
        if store.token_exists(&token_id)? {
            return Ok(TokenExecutionResult::failure(
                "Token ID collision - try again".to_string(),
            ));
        }

        // Create token data
        let token_data = Src20TokenData {
            name: create_data.name.clone(),
            symbol: create_data.symbol,
            decimals: create_data.decimals,
            owner: *sender,
            total_supply: create_data.initial_supply,
            max_supply: create_data.max_supply,
            mintable: create_data.mintable,
            burnable: create_data.burnable,
            pausable: create_data.pausable,
            paused: false,
            minters: vec![*sender], // Owner is initial minter
            created_at: Self::now_ms(block_timestamp),
            created_at_block: block_height,
        };

        // Store token
        store.put_token(&token_id, &token_data)?;

        // Set initial balance if non-zero
        if create_data.initial_supply > 0 {
            store.set_balance(&token_id, sender, create_data.initial_supply)?;
        }

        info!(
            "Created SRC-20 token '{}' ({}) with ID {} by {}",
            create_data.name,
            token_data.symbol,
            hex::encode(token_id),
            sender
        );

        Ok(TokenExecutionResult::success_with_token(token_id))
    }

    /// Mint new tokens
    fn execute_mint(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check if token is mintable
        if !token.mintable {
            return Ok(TokenExecutionResult::failure(
                "Token is not mintable".to_string(),
            ));
        }

        // Check if sender is owner or minter
        let is_minter = token.owner == *sender || token.minters.contains(sender);
        if !is_minter {
            return Ok(TokenExecutionResult::failure(
                "Not authorized to mint".to_string(),
            ));
        }

        // Deserialize mint data
        #[derive(serde::Deserialize)]
        struct MintData {
            to: Address,
            amount: u128,
        }

        let mint_data: MintData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid mint data: {}", e)))?;

        if mint_data.amount == 0 {
            return Ok(TokenExecutionResult::failure(
                "Amount must be > 0".to_string(),
            ));
        }

        // Check max supply
        let new_supply = token.total_supply.saturating_add(mint_data.amount);
        if token.max_supply > 0 && new_supply > token.max_supply {
            return Ok(TokenExecutionResult::failure(
                "Would exceed max supply".to_string(),
            ));
        }

        // Update supply
        token.total_supply = new_supply;
        store.put_token(token_id, &token)?;

        // Update recipient balance
        let recipient_balance = store.get_balance(token_id, &mint_data.to)?;
        store.set_balance(token_id, &mint_data.to, recipient_balance.saturating_add(mint_data.amount))?;

        debug!(
            "Minted {} tokens {} to {}",
            mint_data.amount,
            hex::encode(token_id),
            mint_data.to
        );

        Ok(TokenExecutionResult::success())
    }

    /// Burn tokens
    fn execute_burn(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check if token is burnable
        if !token.burnable {
            return Ok(TokenExecutionResult::failure(
                "Token is not burnable".to_string(),
            ));
        }

        // Deserialize burn data
        #[derive(serde::Deserialize)]
        struct BurnData {
            amount: u128,
        }

        let burn_data: BurnData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid burn data: {}", e)))?;

        if burn_data.amount == 0 {
            return Ok(TokenExecutionResult::failure(
                "Amount must be > 0".to_string(),
            ));
        }

        // Check sender balance
        let sender_balance = store.get_balance(token_id, sender)?;
        if sender_balance < burn_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient balance to burn".to_string(),
            ));
        }

        // Update supply
        token.total_supply = token.total_supply.saturating_sub(burn_data.amount);
        store.put_token(token_id, &token)?;

        // Update sender balance
        store.set_balance(token_id, sender, sender_balance.saturating_sub(burn_data.amount))?;

        debug!(
            "Burned {} tokens {} from {}",
            burn_data.amount,
            hex::encode(token_id),
            sender
        );

        Ok(TokenExecutionResult::success())
    }

    /// Transfer tokens
    fn execute_transfer(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check if paused
        if token.paused {
            return Ok(TokenExecutionResult::failure(
                "Token transfers are paused".to_string(),
            ));
        }

        // Deserialize transfer data
        #[derive(serde::Deserialize)]
        struct TransferData {
            to: Address,
            amount: u128,
        }

        let transfer_data: TransferData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        if transfer_data.amount == 0 {
            return Ok(TokenExecutionResult::failure(
                "Amount must be > 0".to_string(),
            ));
        }

        // Check sender balance
        let sender_balance = store.get_balance(token_id, sender)?;
        if sender_balance < transfer_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient balance".to_string(),
            ));
        }

        // Execute transfer
        store.set_balance(token_id, sender, sender_balance.saturating_sub(transfer_data.amount))?;
        let recipient_balance = store.get_balance(token_id, &transfer_data.to)?;
        store.set_balance(token_id, &transfer_data.to, recipient_balance.saturating_add(transfer_data.amount))?;

        debug!(
            "Transferred {} tokens {} from {} to {}",
            transfer_data.amount,
            hex::encode(token_id),
            sender,
            transfer_data.to
        );

        Ok(TokenExecutionResult::success())
    }

    /// Approve spending allowance
    fn execute_approve(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Check token exists
        if !store.token_exists(token_id)? {
            return Ok(TokenExecutionResult::failure(
                "Token not found".to_string(),
            ));
        }

        // Deserialize approve data
        #[derive(serde::Deserialize)]
        struct ApproveData {
            spender: Address,
            amount: u128,
        }

        let approve_data: ApproveData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid approve data: {}", e)))?;

        // Set allowance
        store.set_allowance(token_id, sender, &approve_data.spender, approve_data.amount)?;

        debug!(
            "Approved {} tokens {} for {} to spend from {}",
            approve_data.amount,
            hex::encode(token_id),
            approve_data.spender,
            sender
        );

        Ok(TokenExecutionResult::success())
    }

    /// Transfer tokens using allowance
    fn execute_transfer_from(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check if paused
        if token.paused {
            return Ok(TokenExecutionResult::failure(
                "Token transfers are paused".to_string(),
            ));
        }

        // Deserialize transfer from data
        #[derive(serde::Deserialize)]
        struct TransferFromData {
            from: Address,
            to: Address,
            amount: u128,
        }

        let transfer_data: TransferFromData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer_from data: {}", e)))?;

        if transfer_data.amount == 0 {
            return Ok(TokenExecutionResult::failure(
                "Amount must be > 0".to_string(),
            ));
        }

        // Check allowance
        let allowance = store.get_allowance(token_id, &transfer_data.from, sender)?;
        if allowance < transfer_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient allowance".to_string(),
            ));
        }

        // Check balance
        let from_balance = store.get_balance(token_id, &transfer_data.from)?;
        if from_balance < transfer_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient balance".to_string(),
            ));
        }

        // Update allowance
        store.set_allowance(
            token_id,
            &transfer_data.from,
            sender,
            allowance.saturating_sub(transfer_data.amount),
        )?;

        // Execute transfer
        store.set_balance(token_id, &transfer_data.from, from_balance.saturating_sub(transfer_data.amount))?;
        let to_balance = store.get_balance(token_id, &transfer_data.to)?;
        store.set_balance(token_id, &transfer_data.to, to_balance.saturating_add(transfer_data.amount))?;

        debug!(
            "TransferFrom {} tokens {} from {} to {} by {}",
            transfer_data.amount,
            hex::encode(token_id),
            transfer_data.from,
            transfer_data.to,
            sender
        );

        Ok(TokenExecutionResult::success())
    }

    /// Pause token transfers
    fn execute_pause(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(TokenExecutionResult::failure(
                "Only owner can pause".to_string(),
            ));
        }

        // Check if pausable
        if !token.pausable {
            return Ok(TokenExecutionResult::failure(
                "Token is not pausable".to_string(),
            ));
        }

        // Check if already paused
        if token.paused {
            return Ok(TokenExecutionResult::failure(
                "Token already paused".to_string(),
            ));
        }

        token.paused = true;
        store.put_token(token_id, &token)?;

        info!("Paused token {}", hex::encode(token_id));

        Ok(TokenExecutionResult::success())
    }

    /// Unpause token transfers
    fn execute_unpause(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(TokenExecutionResult::failure(
                "Only owner can unpause".to_string(),
            ));
        }

        // Check if not paused
        if !token.paused {
            return Ok(TokenExecutionResult::failure(
                "Token not paused".to_string(),
            ));
        }

        token.paused = false;
        store.put_token(token_id, &token)?;

        info!("Unpaused token {}", hex::encode(token_id));

        Ok(TokenExecutionResult::success())
    }

    /// Transfer token ownership
    fn execute_transfer_ownership(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(TokenExecutionResult::failure(
                "Only owner can transfer ownership".to_string(),
            ));
        }

        // Deserialize new owner
        #[derive(serde::Deserialize)]
        struct TransferOwnerData {
            new_owner: Address,
        }

        let transfer_data: TransferOwnerData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer ownership data: {}", e)))?;

        // Update owner
        token.owner = transfer_data.new_owner;
        store.put_token(token_id, &token)?;

        info!(
            "Transferred ownership of token {} to {}",
            hex::encode(token_id),
            transfer_data.new_owner
        );

        Ok(TokenExecutionResult::success())
    }

    /// Add a minter
    fn execute_add_minter(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(TokenExecutionResult::failure(
                "Only owner can add minters".to_string(),
            ));
        }

        // Check if mintable
        if !token.mintable {
            return Ok(TokenExecutionResult::failure(
                "Token is not mintable".to_string(),
            ));
        }

        // Deserialize minter
        #[derive(serde::Deserialize)]
        struct MinterData {
            minter: Address,
        }

        let minter_data: MinterData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid minter data: {}", e)))?;

        // Check if already a minter
        if token.minters.contains(&minter_data.minter) {
            return Ok(TokenExecutionResult::failure(
                "Already a minter".to_string(),
            ));
        }

        // Add minter
        token.minters.push(minter_data.minter);
        store.put_token(token_id, &token)?;

        debug!(
            "Added minter {} to token {}",
            minter_data.minter,
            hex::encode(token_id)
        );

        Ok(TokenExecutionResult::success())
    }

    /// Remove a minter
    fn execute_remove_minter(
        &self,
        store: &TokenStore,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = store.get_token(token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(TokenExecutionResult::failure(
                "Only owner can remove minters".to_string(),
            ));
        }

        // Deserialize minter
        #[derive(serde::Deserialize)]
        struct MinterData {
            minter: Address,
        }

        let minter_data: MinterData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid minter data: {}", e)))?;

        // Check if is a minter
        if !token.minters.contains(&minter_data.minter) {
            return Ok(TokenExecutionResult::failure(
                "Not a minter".to_string(),
            ));
        }

        // Remove minter
        token.minters.retain(|m| m != &minter_data.minter);
        store.put_token(token_id, &token)?;

        debug!(
            "Removed minter {} from token {}",
            minter_data.minter,
            hex::encode(token_id)
        );

        Ok(TokenExecutionResult::success())
    }
}

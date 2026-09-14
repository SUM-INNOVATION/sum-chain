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

use sumchain_storage::exec_view::ExecutionView;
use std::time::{SystemTime, UNIX_EPOCH};

use sumchain_primitives::token_ops::{
    CreateTokenData, TokenApproveData, TokenBurnData, TokenMintData, TokenMinterData,
    TokenTransferData, TokenTransferFromData, TokenTransferOwnershipData,
};
use sumchain_primitives::{Address, Balance, BlockHeight, Hash, TokenOperation, TokenTxData};
use sumchain_storage::Src20TokenData;
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
/// Token execution.
///
/// A namespace, not a handle. Every function on it is an associated function
/// taking an `ExecutionView`, and the type holds no `Arc<Database>` for one to
/// reach — which is what makes a committed write on an execution path a compile
/// error rather than a review comment.
pub struct TokenExecutor;

impl TokenExecutor {

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
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_data: &TokenTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<TokenExecutionResult> {

        // Deduct fee from sender
        Self::deduct_fee(view, sender, fee, proposer)?;

        match token_data.operation {
            TokenOperation::Create => {
                Self::execute_create(view, sender, &token_data.data, block_height, block_timestamp)
            }
            TokenOperation::Mint => {
                Self::execute_mint(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Burn => {
                Self::execute_burn(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Transfer => {
                Self::execute_transfer(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Approve => {
                Self::execute_approve(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::TransferFrom => {
                Self::execute_transfer_from(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::Pause => {
                Self::execute_pause(view, sender, &token_data.token_id)
            }
            TokenOperation::Unpause => {
                Self::execute_unpause(view, sender, &token_data.token_id)
            }
            TokenOperation::TransferOwnership => {
                Self::execute_transfer_ownership(
                    view,
                    sender,
                    &token_data.token_id,
                    &token_data.data,
                )
            }
            TokenOperation::AddMinter => {
                Self::execute_add_minter(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::RemoveMinter => {
                Self::execute_remove_minter(view, sender, &token_data.token_id, &token_data.data)
            }
        }
    }

    /// Dispatch a single **allowlisted token-admin op** as `sender`, WITHOUT any
    /// fee/nonce handling (Governance-v2 Policy-Account dispatch, #90). The caller
    /// (the Policy-Account executor) already owns fee/nonce accounting; this entry
    /// only mutates token state, and only for the five ops a Policy Account may
    /// run on behalf of its address: Pause, Unpause, AddMinter, RemoveMinter,
    /// TransferOwnership. Every other `TokenOperation` returns a failure result
    /// (fail-closed) and writes no token state — each handler validates fully and
    /// performs its single `put_token` only on success, so a rejected op leaves no
    /// partial state. Reuses the exact per-op handlers used by the fee-charging
    /// `execute` path (no duplicated logic).
    pub fn apply_policy_admin_op(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_data: &TokenTxData,
    ) -> Result<TokenExecutionResult> {
        match token_data.operation {
            TokenOperation::Pause => Self::execute_pause(view, sender, &token_data.token_id),
            TokenOperation::Unpause => Self::execute_unpause(view, sender, &token_data.token_id),
            TokenOperation::AddMinter => {
                Self::execute_add_minter(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::RemoveMinter => {
                Self::execute_remove_minter(view, sender, &token_data.token_id, &token_data.data)
            }
            TokenOperation::TransferOwnership => Self::execute_transfer_ownership(
                view,
                sender,
                &token_data.token_id,
                &token_data.data,
            ),
            // Fail closed: not an allowlisted Policy-Account admin op.
            _ => Ok(TokenExecutionResult::failure(
                "Token operation not allowed via Policy Account".to_string(),
            )),
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

    /// Create a new SRC-20 token
    fn execute_create(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        block_height: BlockHeight,
        block_timestamp: u64,
    ) -> Result<TokenExecutionResult> {
        // Deserialize creation data (shared wire struct — issue #89)
        let create_data: CreateTokenData = bincode::deserialize(data)
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
        if Self::v_token_exists(view, &token_id)? {
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
        Self::v_put_token(view, &token_id, &token_data)?;

        // Set initial balance if non-zero
        if create_data.initial_supply > 0 {
            Self::v_set_balance(view, &token_id, sender, create_data.initial_supply)?;
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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
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

        // Deserialize mint data (shared wire struct — issue #89)
        let mint_data: TokenMintData = bincode::deserialize(data)
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
        Self::v_put_token(view, token_id, &token)?;

        // Update recipient balance
        let recipient_balance = Self::v_get_balance(view, token_id, &mint_data.to)?;
        Self::v_set_balance(
            view,
            token_id,
            &mint_data.to,
            recipient_balance.saturating_add(mint_data.amount),
        )?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check if token is burnable
        if !token.burnable {
            return Ok(TokenExecutionResult::failure(
                "Token is not burnable".to_string(),
            ));
        }

        // Deserialize burn data (shared wire struct — issue #89)
        let burn_data: TokenBurnData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid burn data: {}", e)))?;

        if burn_data.amount == 0 {
            return Ok(TokenExecutionResult::failure(
                "Amount must be > 0".to_string(),
            ));
        }

        // Check sender balance
        let sender_balance = Self::v_get_balance(view, token_id, sender)?;
        if sender_balance < burn_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient balance to burn".to_string(),
            ));
        }

        // Update supply
        token.total_supply = token.total_supply.saturating_sub(burn_data.amount);
        Self::v_put_token(view, token_id, &token)?;

        // Update sender balance
        Self::v_set_balance(
            view,
            token_id,
            sender,
            sender_balance.saturating_sub(burn_data.amount),
        )?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check if paused
        if token.paused {
            return Ok(TokenExecutionResult::failure(
                "Token transfers are paused".to_string(),
            ));
        }

        // Deserialize transfer data (shared wire struct — issue #89)
        let transfer_data: TokenTransferData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        if transfer_data.amount == 0 {
            return Ok(TokenExecutionResult::failure(
                "Amount must be > 0".to_string(),
            ));
        }

        // Check sender balance
        let sender_balance = Self::v_get_balance(view, token_id, sender)?;
        if sender_balance < transfer_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient balance".to_string(),
            ));
        }

        // Execute transfer
        Self::v_set_balance(
            view,
            token_id,
            sender,
            sender_balance.saturating_sub(transfer_data.amount),
        )?;
        let recipient_balance = Self::v_get_balance(view, token_id, &transfer_data.to)?;
        Self::v_set_balance(
            view,
            token_id,
            &transfer_data.to,
            recipient_balance.saturating_add(transfer_data.amount),
        )?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Check token exists
        if !Self::v_token_exists(view, token_id)? {
            return Ok(TokenExecutionResult::failure(
                "Token not found".to_string(),
            ));
        }

        // Deserialize approve data (shared wire struct — issue #89)
        let approve_data: TokenApproveData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid approve data: {}", e)))?;

        // Set allowance
        Self::v_set_allowance(view, token_id, sender, &approve_data.spender, approve_data.amount)?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check if paused
        if token.paused {
            return Ok(TokenExecutionResult::failure(
                "Token transfers are paused".to_string(),
            ));
        }

        // Deserialize transfer from data (shared wire struct — issue #89)
        let transfer_data: TokenTransferFromData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer_from data: {}", e)))?;

        if transfer_data.amount == 0 {
            return Ok(TokenExecutionResult::failure(
                "Amount must be > 0".to_string(),
            ));
        }

        // Check allowance
        let allowance = Self::v_get_allowance(view, token_id, &transfer_data.from, sender)?;
        if allowance < transfer_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient allowance".to_string(),
            ));
        }

        // Check balance
        let from_balance = Self::v_get_balance(view, token_id, &transfer_data.from)?;
        if from_balance < transfer_data.amount {
            return Ok(TokenExecutionResult::failure(
                "Insufficient balance".to_string(),
            ));
        }

        // Update allowance
        Self::v_set_allowance(view,
            token_id,
            &transfer_data.from,
            sender,
            allowance.saturating_sub(transfer_data.amount),
        )?;

        // Execute transfer
        Self::v_set_balance(
            view,
            token_id,
            &transfer_data.from,
            from_balance.saturating_sub(transfer_data.amount),
        )?;
        let to_balance = Self::v_get_balance(view, token_id, &transfer_data.to)?;
        Self::v_set_balance(
            view,
            token_id,
            &transfer_data.to,
            to_balance.saturating_add(transfer_data.amount),
        )?;

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
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
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
        Self::v_put_token(view, token_id, &token)?;

        info!("Paused token {}", hex::encode(token_id));

        Ok(TokenExecutionResult::success())
    }

    /// Unpause token transfers
    fn execute_unpause(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
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
        Self::v_put_token(view, token_id, &token)?;

        info!("Unpaused token {}", hex::encode(token_id));

        Ok(TokenExecutionResult::success())
    }

    /// Transfer token ownership
    fn execute_transfer_ownership(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(TokenExecutionResult::failure(
                "Only owner can transfer ownership".to_string(),
            ));
        }

        // Deserialize new owner (shared wire struct — issue #89)
        let transfer_data: TokenTransferOwnershipData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer ownership data: {}", e)))?;

        // Update owner
        token.owner = transfer_data.new_owner;
        Self::v_put_token(view, token_id, &token)?;

        info!(
            "Transferred ownership of token {} to {}",
            hex::encode(token_id),
            transfer_data.new_owner
        );

        Ok(TokenExecutionResult::success())
    }

    /// Add a minter
    fn execute_add_minter(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
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

        // Deserialize minter (shared wire struct — issue #89)
        let minter_data: TokenMinterData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid minter data: {}", e)))?;

        // Check if already a minter
        if token.minters.contains(&minter_data.minter) {
            return Ok(TokenExecutionResult::failure(
                "Already a minter".to_string(),
            ));
        }

        // Add minter
        token.minters.push(minter_data.minter);
        Self::v_put_token(view, token_id, &token)?;

        debug!(
            "Added minter {} to token {}",
            minter_data.minter,
            hex::encode(token_id)
        );

        Ok(TokenExecutionResult::success())
    }

    /// Remove a minter
    fn execute_remove_minter(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        token_id: &[u8; 32],
        data: &[u8],
    ) -> Result<TokenExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, token_id)?.ok_or_else(|| {
            StateError::BlockValidation("Token not found".to_string())
        })?;

        // Check ownership
        if token.owner != *sender {
            return Ok(TokenExecutionResult::failure(
                "Only owner can remove minters".to_string(),
            ));
        }

        // Deserialize minter (shared wire struct — issue #89)
        let minter_data: TokenMinterData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid minter data: {}", e)))?;

        // Check if is a minter
        if !token.minters.contains(&minter_data.minter) {
            return Ok(TokenExecutionResult::failure(
                "Not a minter".to_string(),
            ));
        }

        // Remove minter
        token.minters.retain(|m| m != &minter_data.minter);
        Self::v_put_token(view, token_id, &token)?;

        debug!(
            "Removed minter {} from token {}",
            minter_data.minter,
            hex::encode(token_id)
        );

        Ok(TokenExecutionResult::success())
    }
}

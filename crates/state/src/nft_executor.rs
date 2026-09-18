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

/// The largest number of tokens one `BatchMint` may name.
///
/// Read only where the allocation-bound gate is open. The loop that services a
/// batch rebuilds the owner index and the collection index once per request, so
/// the transaction's cost is quadratic in this number: at 512 the owner index is
/// rebuilt 512 times at an average of 256 forty-byte entries, about five
/// megabytes of churn, and at the 2,000,000-byte block limit with no bound at
/// all it is tens of gigabytes.
///
/// A binary constant rather than a `ChainParams` field, for the reason given on
/// `MAX_SUBSYSTEM_PAYLOAD_BYTES`: the activation digest covers `Option<u64>`
/// gates and nothing else, so a configurable limit is a consensus-relevant
/// number with nothing to compare it against.
pub const MAX_NFT_BATCH_MINT_REQUESTS: usize = 512;

/// One value per chain-defined activation height this executor is gated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NftGates {
    /// An operation naming an absent collection or token, or carrying an
    /// undecodable payload, produces a `Failed` receipt instead of making the
    /// whole block unexecutable. ACTIVATION-AUDIT row OV-?? / the receipt-failure
    /// rule.
    pub receipt_failure: bool,
    /// A transaction's sizing inputs are checked against a limit BEFORE the
    /// value they size is built: an oversized payload is refused before it is
    /// decoded, and a `BatchMint` naming more than
    /// [`MAX_NFT_BATCH_MINT_REQUESTS`] tokens is refused before the loop that
    /// rebuilds the owner index once per request. ACTIVATION-AUDIT row AL-9.
    pub allocation_bound: bool,
}

impl NftGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        receipt_failure: false,
        allocation_bound: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        receipt_failure: true,
        allocation_bound: true,
    };
}

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

    /// The activation height for bounding a transaction's sizing inputs.
    ///
    /// Reads `params.subsystem_allocation_bound_enabled_from_height` through
    /// `crate::subsystem_allocation_bound_gate_open`, which is the same field
    /// the DocClass bound reads. ACTIVATION-AUDIT row AL-9.
    ///
    /// Not its own field. The DocClass and NFT bounds are one rule at one seam
    /// -- check the size before building the value -- with the same blast radius
    /// on both sides, and an attacker refused by one simply uses the other. The
    /// argument is spelled out on the field itself in `crates/genesis/src/lib.rs`.
    #[inline]
    fn allocation_bound_gate_open(params: &ChainParams, block_height: u64) -> bool {
        crate::subsystem_allocation_bound_gate_open(params, block_height)
    }

    /// The activation height for the NFT receipt-failure rule.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-721 receipt-failure rule. Dormant by default (`None` -> never
    /// /// open). Below the gate, an NFT operation naming an absent collection
    /// /// or token, carrying an undecodable payload, carrying an out-of-range
    /// /// royalty, or draining the sender's balance inside the block, returns
    /// /// `Err(StateError::BlockValidation)` and makes the whole block
    /// /// unexecutable. At and above the gate the same conditions produce a
    /// /// `Failed` receipt that charges the sender and leaves the block valid.
    /// /// Activation is a consensus change and needs a coordinated validator
    /// /// upgrade: two nodes that disagree about this height disagree about
    /// /// whether a block exists at all.
    /// #[serde(default)]
    /// pub nft_receipt_failure_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so the production behaviour
    /// is bit-identical to the behaviour before this change: the gate is closed
    /// and the `Err` still propagates. The gated side is not dead, though — it
    /// is reachable through [`NftExecutor::execute_with_gate`], which is what
    /// the mixed-version tests drive.
    #[inline]
    fn receipt_failure_activation(params: &ChainParams) -> Option<u64> {
        params.nft_receipt_failure_enabled_from_height
    }

    /// Whether the NFT receipt-failure rule is active at `block_height`.
    #[inline]
    fn receipt_failure_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::receipt_failure_activation(params), Some(h) if block_height >= h)
    }

    /// The errors the receipt-failure rule converts into a `Failed` receipt.
    ///
    /// Deliberately narrow. Storage and encoding errors are node-local faults
    /// and must still abort the block; only the conditions an ordinary sender
    /// chooses from its own payload are converted.
    fn as_receipt_failure(err: &StateError) -> Option<String> {
        match err {
            StateError::BlockValidation(msg) => Some(msg.clone()),
            StateError::InsufficientBalance {
                required,
                available,
            } => Some(format!(
                "Insufficient balance: required {}, available {}",
                required, available
            )),
            _ => None,
        }
    }

    /// Execute an NFT operation from transaction data.
    ///
    /// Reads the receipt-failure activation height out of `params` and
    /// dispatches through [`Self::execute_with_gate`].
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        block_height: u64,
    ) -> Result<NftExecutionResult> {
        Self::execute_with_gates(
            view,
            params,
            sender,
            nft_data,
            proposer,
            fee,
            block_timestamp,
            NftGates {
                receipt_failure: Self::receipt_failure_gate_open(params, block_height),
                allocation_bound: Self::allocation_bound_gate_open(params, block_height),
            },
        )
    }

    /// Execute an NFT operation with the receipt-failure gate supplied directly.
    ///
    /// The seam the mixed-version tests use. `receipt_failure_gate_open` is the
    /// only thing that differs between a node below the activation height and a
    /// node at or above it, so driving both values through one entry point is
    /// what makes the divergence observable rather than asserted.
    ///
    /// Every error site inside the operation bodies fires strictly before that
    /// body's first write — verified site by site — so converting the error at
    /// this boundary cannot leave a half-applied operation in the overlay. The
    /// fee is the one exception, and it is deducted deliberately: it is
    /// deducted at `:execute_ungated` before the match, which is the same
    /// position the pre-existing `failure()` guards already charge from.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gate(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        receipt_failure_gate_open: bool,
    ) -> Result<NftExecutionResult> {
        Self::execute_with_gates(
            view,
            params,
            sender,
            nft_data,
            proposer,
            fee,
            block_timestamp,
            NftGates {
                receipt_failure: receipt_failure_gate_open,
                allocation_bound: false,
            },
        )
    }

    /// Execute an NFT operation with every activation decision supplied
    /// directly.
    ///
    /// [`Self::execute_with_gate`] is the one-gate spelling this replaced, kept
    /// so that every mixed-version test written against the receipt-failure gate
    /// still drives the seam it was written for. It supplies
    /// `allocation_bound: false`, which is that binary's behaviour.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        let receipt_failure_gate_open = gates.receipt_failure;
        let outcome = Self::execute_ungated(
            view,
            params,
            sender,
            nft_data,
            proposer,
            fee,
            block_timestamp,
            gates,
        );

        let err = match outcome {
            Ok(result) => return Ok(result),
            Err(err) => err,
        };

        if !receipt_failure_gate_open {
            return Err(err);
        }

        let Some(message) = Self::as_receipt_failure(&err) else {
            return Err(err);
        };

        // An insufficient-balance refusal never reached `deduct_fee`'s writes,
        // so nothing advanced the sender's nonce. Advance it here, or the
        // refused transaction stays replayable at the same nonce while still
        // occupying a receipt slot in the block.
        if matches!(err, StateError::InsufficientBalance { .. }) {
            let mut sender_account = StateManager::v_get_account(view, sender)?;
            sender_account.nonce += 1;
            StateManager::v_put_account(view, sender, &sender_account)?;
        }

        warn!(
            "NFT {:?} refused with a receipt rather than aborting the block: {}",
            nft_data.operation, message
        );
        Ok(NftExecutionResult::failure(message))
    }

    /// The operation bodies, with no gate applied.
    #[allow(clippy::too_many_arguments)]
    fn execute_ungated(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        // ACTIVATION-AUDIT row AL-9, and the NFT half of AL-12. Every arm below
        // opens with `bincode::deserialize(&nft_data.data)` and no length check
        // ahead of it. One check here rather than one per arm, for the reason
        // the DocClass dispatch gives: the arms are many and the rule is one.
        //
        // AFTER the fee deduction, deliberately. Every pre-existing refusal in
        // this executor charges the sender -- `deduct_fee` is the first thing
        // `execute_ungated` does and every `failure()` below it returns having
        // paid -- and an unpaid refusal would be the cheaper transaction to
        // spam, which is the opposite of the point.
        Self::deduct_fee(view, sender, fee, proposer)?;

        if gates.allocation_bound && nft_data.data.len() > crate::MAX_SUBSYSTEM_PAYLOAD_BYTES {
            return Ok(NftExecutionResult::failure(format!(
                "NFT payload too large: {} bytes, limit {}",
                nft_data.data.len(),
                crate::MAX_SUBSYSTEM_PAYLOAD_BYTES
            )));
        }

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
                gates,
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
        gates: NftGates,
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

        // ACTIVATION-AUDIT row AL-9. The loop below calls
        // `v_add_to_owner_index` and `v_add_to_collection_index` once per
        // request, and each of those reads an accumulating index, appends one
        // entry and re-encodes the WHOLE of it. So the work this one
        // transaction does is QUADRATIC in a count the payload declares: with
        // `n` requests the owner index is rebuilt `n` times at an average size
        // of `n/2` entries. The count is checked here, before the first
        // rebuild, rather than being discovered when the candidate ceiling
        // refuses the write partway through -- by which time the quadratic work
        // has already been done and the whole block is unexecutable.
        if gates.allocation_bound && count as usize > MAX_NFT_BATCH_MINT_REQUESTS {
            return Ok(NftExecutionResult::failure(format!(
                "BatchMint of {count} tokens exceeds the limit of \
                 {MAX_NFT_BATCH_MINT_REQUESTS}"
            )));
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

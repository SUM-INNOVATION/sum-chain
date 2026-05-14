//! RPC API trait definition using jsonrpsee.

use jsonrpsee::proc_macros::rpc;

use crate::metrics::MetricsSnapshot;
use crate::policy_account_types::{
    CancelProposalRequest, CancelProposalResponse, CreatePolicyAccountRequest,
    CreatePolicyAccountResponse, ExecuteProposalRequest, ExecuteProposalResponse,
    PolicyAccountInfo, ProposalInfo, SubmitProposalRequest, SubmitProposalResponse,
};
use crate::types::{
    AccountInfo, BlockHeightInfo, BlockInfo, ContractCallResult, ContractInfo,
    CreateEmploymentCredentialRequest,
    CreateEmploymentCredentialResponse, DelegationRpcInfo, DelegatorSummary, DocClassConfigInfo,
    DocClassCredentialInfo, DocClassIdentityInfo, DocClassIssuerInfo, DocClassSummary,
    EmploymentCredentialInfo, EmploymentIssuerInfo, EmploymentSummary, EmploymentVerificationResult,
    AssignmentCoverageV2, ChainParamsInfo, EpochInfo, FinalityInfo, GasEstimateResult, HealthResponse, IncomeAttestationInfo, NodeRecordInfo, PushableFileInfoV2, StorageFileInfoV2, TxStatusV2,
    InboxFilterInfo, IssueAcademicCredentialRequest, IssueAcademicCredentialResponse,
    MessageDataInfo, MessageEventInfo, MessagingConfigInfo, MessagingQuotaInfo,
    NftCollectionInfo, NftOwnerTokens, NftTokenInfo, NodeInfo, P2pStats, PendingPaymentInfo,
    PublicKeyInfo, ReceiptInfo, RegisterAcademicIssuerRequest, RegisterAcademicIssuerResponse,
    RegisterEmploymentIssuerRequest, RegisterEmploymentIssuerResponse,
    RevokeAcademicCredentialRequest, RevokeAcademicCredentialResponse,
    RevokeEmploymentCredentialRequest, RevokeEmploymentCredentialResponse,
    RpcPeerInfo, SendTxResponse, SlashingRecordRpcInfo, SlashingSummary, SpamReportInfo,
    SponsoredRegistrationRequest, SponsoredRegistrationResponse, StakingParamsInfo, StakingSummary,
    StakingValidatorInfo, SubmitSponsoredMessageRequest, TokenHoldings, TokenInfo,
    TransactionHistoryResponse, TransactionInfo, UnbondingDelegationRpcInfo,
    ValidatorDelegationSummary, ValidatorSetInfo, ValidatorSetRpcInfo, ValidatorSigningRpcInfo,
    ViewCallRequest,
    InferenceAttestationInfo, InferenceAttestationStatusInfo,
};

/// SUM Chain RPC API
#[rpc(server, client)]
pub trait SumChainApi {
    /// Get chain ID
    #[method(name = "chain_id")]
    async fn chain_id(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get latest block
    #[method(name = "get_latest_block")]
    async fn get_latest_block(&self) -> Result<BlockInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get block by height
    #[method(name = "get_block_by_height")]
    async fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get block by hash
    #[method(name = "get_block_by_hash")]
    async fn get_block_by_hash(
        &self,
        hash: String,
    ) -> Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account balance
    #[method(name = "get_balance")]
    async fn get_balance(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account nonce
    #[method(name = "get_nonce")]
    async fn get_nonce(&self, address: String) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account info
    #[method(name = "get_account")]
    async fn get_account(
        &self,
        address: String,
    ) -> Result<AccountInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Send raw transaction (hex encoded)
    #[method(name = "send_raw_transaction")]
    async fn send_raw_transaction(
        &self,
        raw_tx: String,
    ) -> Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction by hash
    #[method(name = "get_transaction")]
    async fn get_transaction(
        &self,
        tx_hash: String,
    ) -> Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction receipt
    #[method(name = "get_receipt")]
    async fn get_receipt(
        &self,
        tx_hash: String,
    ) -> Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Health check
    #[method(name = "health")]
    async fn health(&self) -> Result<HealthResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending transaction count in mempool
    #[method(name = "pending_tx_count")]
    async fn pending_tx_count(&self) -> Result<usize, jsonrpsee::types::ErrorObjectOwned>;

    /// Get latest block number (Ethereum-compatible, hex format)
    #[method(name = "eth_blockNumber")]
    async fn eth_block_number(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get balance in hex format (Ethereum-compatible)
    #[method(name = "eth_getBalance")]
    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SUM Chain Native Aliases (sum_* prefix for brand consistency)
    // These mirror the unprefixed methods but with sum_ prefix
    // ========================================================================

    /// Get block number (SUM native alias)
    #[method(name = "sum_blockNumber")]
    async fn sum_block_number(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get latest block (SUM native alias)
    #[method(name = "sum_getLatestBlock")]
    async fn sum_get_latest_block(&self) -> Result<BlockInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get block by height (SUM native alias)
    #[method(name = "sum_getBlockByHeight")]
    async fn sum_get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account balance (SUM native alias)
    #[method(name = "sum_getBalance")]
    async fn sum_get_balance(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account nonce (SUM native alias)
    #[method(name = "sum_getNonce")]
    async fn sum_get_nonce(&self, address: String) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Send raw transaction (SUM native alias)
    #[method(name = "sum_sendRawTransaction")]
    async fn sum_send_raw_transaction(
        &self,
        raw_tx: String,
    ) -> Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction by hash (SUM native alias)
    #[method(name = "sum_getTransaction")]
    async fn sum_get_transaction(
        &self,
        tx_hash: String,
    ) -> Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction receipt (SUM native alias)
    #[method(name = "sum_getReceipt")]
    async fn sum_get_receipt(
        &self,
        tx_hash: String,
    ) -> Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending transactions (SUM native alias)
    #[method(name = "sum_getPendingTransactions")]
    async fn sum_get_pending_transactions(&self) -> Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a single `InferenceAttestation` record for `(session_id, verifier_address)`.
    /// Returns `None` if no attestation has been committed for that pair.
    /// OmniNode Stage 6 / chain Phase 4.
    #[method(name = "sum_getInferenceAttestation")]
    async fn sum_get_inference_attestation(
        &self,
        session_id: String,
        verifier_address: String,
    ) -> Result<Option<InferenceAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List every verifier's `InferenceAttestation` for a given session.
    /// Returns an empty vec if no attestations exist. Used by OmniNode
    /// coordinators to determine quorum.
    #[method(name = "sum_listInferenceAttestations")]
    async fn sum_list_inference_attestations(
        &self,
        session_id: String,
    ) -> Result<Vec<InferenceAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the chain-side status of an `InferenceAttestation` tx by hash.
    /// Four states (`submitted`, `included`, `finalized`, `failed`) plus
    /// `unknown` for unrecognized hashes. `Dropped` is not tracked in
    /// v1 — see `crates/rpc/src/types.rs::InferenceAttestationStatusInfo`.
    #[method(name = "sum_getInferenceAttestationStatus")]
    async fn sum_get_inference_attestation_status(
        &self,
        tx_hash: String,
    ) -> Result<InferenceAttestationStatusInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validators (SUM native alias)
    #[method(name = "sum_getValidators")]
    async fn sum_get_validators(&self) -> Result<ValidatorSetInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending transactions from mempool
    #[method(name = "get_pending_transactions")]
    async fn get_pending_transactions(&self) -> Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get current validator set
    #[method(name = "get_validators")]
    async fn get_validators(&self) -> Result<ValidatorSetInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get multiple blocks in a range
    #[method(name = "get_blocks")]
    async fn get_blocks(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get node metrics
    #[method(name = "get_metrics")]
    async fn get_metrics(&self) -> Result<MetricsSnapshot, jsonrpsee::types::ErrorObjectOwned>;

    /// Get node info (version, network, etc.)
    #[method(name = "node_info")]
    async fn node_info(&self) -> Result<NodeInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get finality information
    #[method(name = "get_finality")]
    async fn get_finality(&self) -> Result<FinalityInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a block at a given height is finalized
    #[method(name = "is_block_finalized")]
    async fn is_block_finalized(&self, height: u64) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the live consensus parameters this node is using. SNIP V2 Phase 2.
    ///
    /// Returns the actual `ChainParams` from the node's live config, NOT
    /// hardcoded library defaults — so SNIP clients can read
    /// `assignment_replication_factor`, `max_chunk_count_per_file`, etc.
    /// at runtime instead of baking them in. If a future chain config tunes
    /// any of these values, SNIP picks them up without a client release.
    ///
    /// Flat wire shape (no nested `staking`/`messaging`/`docclass` sub-configs)
    /// since SNIP V2 clients don't use those. Additive; new fields can be
    /// appended without breaking existing clients.
    #[method(name = "chain_getChainParams")]
    async fn chain_get_chain_params(
        &self,
    ) -> Result<ChainParamsInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the chain's current block height. SNIP V2 Ask 8 (Phase 0b).
    ///
    /// `finality` selector: `Some("finalized")` returns the finalized height
    /// (safe for expiry calculations under PoA reorgs); `None` or
    /// `Some("latest")` returns the head height. The return value's
    /// `finality` field echoes which view was returned.
    #[method(name = "chain_getBlockHeight")]
    async fn chain_get_block_height(
        &self,
        finality: Option<String>,
    ) -> Result<BlockHeightInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the inclusion / finality status of a transaction by hash.
    /// SNIP V2 Ask 11 (Phase 0b).
    ///
    /// Returns one of: `Unknown` (never seen), `Pending` (in mempool),
    /// `Included { block_height }` (in a block, not finalized),
    /// `Finalized { block_height }` (finalized per consensus mode —
    /// depth=3 under PoA, depth=0 under BFT), or `Failed { ... }`.
    /// `Dropped` is reserved but not currently returned.
    #[method(name = "chain_getTransactionStatus")]
    async fn chain_get_transaction_status(
        &self,
        tx_hash: String,
    ) -> Result<TxStatusV2, jsonrpsee::types::ErrorObjectOwned>;

    /// Get list of connected peers
    #[method(name = "get_peers")]
    async fn get_peers(&self) -> Result<Vec<RpcPeerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get P2P network statistics
    #[method(name = "get_p2p_stats")]
    async fn get_p2p_stats(&self) -> Result<P2pStats, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // NFT (SUM-721) Endpoints
    // ========================================================================

    /// Get NFT collection by ID
    #[method(name = "nft_getCollection")]
    async fn nft_get_collection(
        &self,
        collection_id: String,
    ) -> Result<Option<NftCollectionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get NFT token by collection ID and token ID
    #[method(name = "nft_getToken")]
    async fn nft_get_token(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> Result<Option<NftTokenInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all tokens owned by an address
    #[method(name = "nft_getTokensByOwner")]
    async fn nft_get_tokens_by_owner(
        &self,
        owner: String,
    ) -> Result<NftOwnerTokens, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all token IDs in a collection
    #[method(name = "nft_getTokensInCollection")]
    async fn nft_get_tokens_in_collection(
        &self,
        collection_id: String,
    ) -> Result<Vec<u64>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the number of tokens owned by an address
    #[method(name = "nft_balanceOf")]
    async fn nft_balance_of(
        &self,
        owner: String,
    ) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the owner of a specific token
    #[method(name = "nft_ownerOf")]
    async fn nft_owner_of(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a token exists
    #[method(name = "nft_tokenExists")]
    async fn nft_token_exists(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SRC-20 Token Endpoints
    // ========================================================================

    /// Get SRC-20 token by ID
    #[method(name = "token_getToken")]
    async fn token_get_token(
        &self,
        token_id: String,
    ) -> Result<Option<TokenInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get SRC-20 token balance for an address
    #[method(name = "token_balanceOf")]
    async fn token_balance_of(
        &self,
        token_id: String,
        owner: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all SRC-20 tokens held by an address
    #[method(name = "token_getTokensByOwner")]
    async fn token_get_tokens_by_owner(
        &self,
        owner: String,
    ) -> Result<TokenHoldings, jsonrpsee::types::ErrorObjectOwned>;

    /// Get SRC-20 token allowance
    #[method(name = "token_allowance")]
    async fn token_allowance(
        &self,
        token_id: String,
        owner: String,
        spender: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get total supply of an SRC-20 token
    #[method(name = "token_totalSupply")]
    async fn token_total_supply(
        &self,
        token_id: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an SRC-20 token exists
    #[method(name = "token_exists")]
    async fn token_exists(
        &self,
        token_id: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Smart Contract (SUMC) Endpoints
    // ========================================================================

    /// Get contract info by address
    #[method(name = "contract_getContract")]
    async fn contract_get_contract(
        &self,
        address: String,
    ) -> Result<Option<ContractInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an address is a contract
    #[method(name = "contract_isContract")]
    async fn contract_is_contract(
        &self,
        address: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Execute a view call (read-only, no state changes)
    #[method(name = "contract_call")]
    async fn contract_call(
        &self,
        request: ViewCallRequest,
    ) -> Result<ContractCallResult, jsonrpsee::types::ErrorObjectOwned>;

    /// Estimate gas for a contract call
    #[method(name = "contract_estimateGas")]
    async fn contract_estimate_gas(
        &self,
        request: ViewCallRequest,
    ) -> Result<GasEstimateResult, jsonrpsee::types::ErrorObjectOwned>;

    /// Get contract code hash
    #[method(name = "contract_getCodeHash")]
    async fn contract_get_code_hash(
        &self,
        address: String,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get contract storage at a specific key
    #[method(name = "contract_getStorageAt")]
    async fn contract_get_storage_at(
        &self,
        address: String,
        key: String,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get contract balance
    #[method(name = "contract_getBalance")]
    async fn contract_get_balance(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Staking Endpoints
    // ========================================================================

    /// Get staking validator by public key (hex)
    #[method(name = "staking_getValidator")]
    async fn staking_get_validator(
        &self,
        pubkey: String,
    ) -> Result<Option<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all staking validators
    #[method(name = "staking_getValidators")]
    async fn staking_get_validators(
        &self,
    ) -> Result<Vec<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get active staking validators only
    #[method(name = "staking_getActiveValidators")]
    async fn staking_get_active_validators(
        &self,
    ) -> Result<Vec<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get staking summary (totals and parameters)
    #[method(name = "staking_getSummary")]
    async fn staking_get_summary(
        &self,
    ) -> Result<StakingSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get staking parameters
    #[method(name = "staking_getParams")]
    async fn staking_get_params(
        &self,
    ) -> Result<StakingParamsInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get total staked amount
    #[method(name = "staking_getTotalStake")]
    async fn staking_get_total_stake(
        &self,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator by address (base58)
    #[method(name = "staking_getValidatorByAddress")]
    async fn staking_get_validator_by_address(
        &self,
        address: String,
    ) -> Result<Option<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Delegation Endpoints
    // ========================================================================

    /// Get delegation info for a delegator to a specific validator
    #[method(name = "delegation_getDelegation")]
    async fn delegation_get_delegation(
        &self,
        delegator: String,
        validator_pubkey: String,
    ) -> Result<Option<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all delegations for a delegator
    #[method(name = "delegation_getDelegationsByDelegator")]
    async fn delegation_get_delegations_by_delegator(
        &self,
        delegator: String,
    ) -> Result<Vec<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all delegations to a validator
    #[method(name = "delegation_getDelegationsByValidator")]
    async fn delegation_get_delegations_by_validator(
        &self,
        validator_pubkey: String,
    ) -> Result<Vec<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get delegator summary (total delegated, rewards, unbonding)
    #[method(name = "delegation_getDelegatorSummary")]
    async fn delegation_get_delegator_summary(
        &self,
        delegator: String,
    ) -> Result<DelegatorSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get unbonding delegations for a delegator
    #[method(name = "delegation_getUnbondingDelegations")]
    async fn delegation_get_unbonding_delegations(
        &self,
        delegator: String,
    ) -> Result<Vec<UnbondingDelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator delegation summary (total delegated, delegator count)
    #[method(name = "delegation_getValidatorDelegationSummary")]
    async fn delegation_get_validator_delegation_summary(
        &self,
        validator_pubkey: String,
    ) -> Result<ValidatorDelegationSummary, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Slashing Endpoints
    // ========================================================================

    /// Get slashing records for a validator
    #[method(name = "slashing_getRecords")]
    async fn slashing_get_records(
        &self,
        validator_pubkey: String,
    ) -> Result<Vec<SlashingRecordRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator signing info (liveness tracking)
    #[method(name = "slashing_getSigningInfo")]
    async fn slashing_get_signing_info(
        &self,
        validator_pubkey: String,
    ) -> Result<Option<ValidatorSigningRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all signing info for all validators
    #[method(name = "slashing_getAllSigningInfo")]
    async fn slashing_get_all_signing_info(
        &self,
    ) -> Result<Vec<ValidatorSigningRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get slashing summary (totals across all validators)
    #[method(name = "slashing_getSummary")]
    async fn slashing_get_summary(
        &self,
    ) -> Result<SlashingSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a validator is tombstoned (permanently jailed)
    #[method(name = "slashing_isTombstoned")]
    async fn slashing_is_tombstoned(
        &self,
        validator_pubkey: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Get recent slashing records across all validators
    #[method(name = "slashing_getRecentRecords")]
    async fn slashing_get_recent_records(
        &self,
        limit: u32,
    ) -> Result<Vec<SlashingRecordRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Validator Set Endpoints
    // ========================================================================

    /// Get current epoch info
    #[method(name = "epoch_getInfo")]
    async fn epoch_get_info(
        &self,
    ) -> Result<EpochInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get current active validator set
    #[method(name = "validatorSet_getCurrent")]
    async fn validator_set_get_current(
        &self,
    ) -> Result<Option<ValidatorSetRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator set for a specific epoch
    #[method(name = "validatorSet_getByEpoch")]
    async fn validator_set_get_by_epoch(
        &self,
        epoch: u64,
    ) -> Result<Option<ValidatorSetRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the proposer for a given height
    #[method(name = "validatorSet_getProposer")]
    async fn validator_set_get_proposer(
        &self,
        height: u64,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SRC-201 Messaging Endpoints
    // ========================================================================

    /// Get messaging configuration
    #[method(name = "messaging_getConfig")]
    async fn messaging_get_config(
        &self,
    ) -> Result<MessagingConfigInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get sender's messaging quota
    #[method(name = "messaging_getQuota")]
    async fn messaging_get_quota(
        &self,
        address: String,
    ) -> Result<MessagingQuotaInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get recipient's inbox filter
    #[method(name = "messaging_getInboxFilter")]
    async fn messaging_get_inbox_filter(
        &self,
        address: String,
    ) -> Result<Option<InboxFilterInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get messages for a recipient (by recipient hash)
    #[method(name = "messaging_getMessages")]
    async fn messaging_get_messages(
        &self,
        recipient_hash: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get messages sent by an address
    #[method(name = "messaging_getSentMessages")]
    async fn messaging_get_sent_messages(
        &self,
        sender: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a specific message by transaction hash (for debugging)
    #[method(name = "messaging_getMessageByTxHash")]
    async fn messaging_get_message_by_tx_hash(
        &self,
        tx_hash: String,
    ) -> Result<Option<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all messages in a specific block (for debugging)
    #[method(name = "messaging_getMessagesInBlock")]
    async fn messaging_get_messages_in_block(
        &self,
        block_height: u64,
        limit: Option<u32>,
    ) -> Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the encrypted message data for a specific message by transaction hash
    #[method(name = "messaging_getMessageData")]
    async fn messaging_get_message_data(
        &self,
        tx_hash: String,
    ) -> Result<Option<MessageDataInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending payment by message ID
    #[method(name = "messaging_getPendingPayment")]
    async fn messaging_get_pending_payment(
        &self,
        message_id: String,
    ) -> Result<Option<PendingPaymentInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all pending payments for a recipient
    #[method(name = "messaging_getPendingPayments")]
    async fn messaging_get_pending_payments(
        &self,
        recipient: String,
    ) -> Result<Vec<PendingPaymentInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get sender's trust stake
    #[method(name = "messaging_getTrustStake")]
    async fn messaging_get_trust_stake(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get sender's spam score
    #[method(name = "messaging_getSpamScore")]
    async fn messaging_get_spam_score(
        &self,
        address: String,
    ) -> Result<SpamReportInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an address is a contact of another
    #[method(name = "messaging_isContact")]
    async fn messaging_is_contact(
        &self,
        owner: String,
        contact: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an address is blocked by another
    #[method(name = "messaging_isBlocked")]
    async fn messaging_is_blocked(
        &self,
        owner: String,
        sender: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Submit a sponsored message (meta-transaction)
    #[method(name = "messaging_submitSponsored")]
    async fn messaging_submit_sponsored(
        &self,
        request: SubmitSponsoredMessageRequest,
    ) -> Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Register public key with gas sponsorship (no balance required)
    /// This allows new users to register for SUMail without needing any Koppa
    #[method(name = "messaging_registerSponsored")]
    async fn messaging_register_sponsored(
        &self,
        request: SponsoredRegistrationRequest,
    ) -> Result<SponsoredRegistrationResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get registered public key for an address
    #[method(name = "account_getPublicKey")]
    async fn account_get_public_key(
        &self,
        address: String,
    ) -> Result<Option<PublicKeyInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the X25519 encryption pubkey registered for an account.
    /// SNIP V2 Ask 3 (Phase 0b checkpoint 2).
    ///
    /// Returns `Some(hex-encoded 32-byte Montgomery U-coordinate)` if the
    /// account has registered an encryption pubkey via
    /// `NodeRegistryOperationV2::RegisterEncryptionKey`, else `None`.
    /// Hex is `0x`-prefixed, lowercase.
    ///
    /// Distinct from `account_getPublicKey`, which returns the SRC-201 messaging
    /// public key (Ed25519). The two are stored in separate column families and
    /// serve different purposes; SNIP recipients must register an X25519 key
    /// before anyone can share a Private file with them.
    #[method(name = "account_getEncryptionPublicKey")]
    async fn account_get_encryption_public_key(
        &self,
        address: String,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SRC-80X/81X DocClass Endpoints
    // ========================================================================

    /// Get DocClass configuration
    #[method(name = "docclass_getConfig")]
    async fn docclass_get_config(
        &self,
    ) -> Result<DocClassConfigInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get DocClass summary statistics
    #[method(name = "docclass_getSummary")]
    async fn docclass_get_summary(
        &self,
    ) -> Result<DocClassSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get identity root by ID (hex)
    #[method(name = "docclass_getIdentity")]
    async fn docclass_get_identity(
        &self,
        identity_id: String,
    ) -> Result<Option<DocClassIdentityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get identity root by controller address
    #[method(name = "docclass_getIdentityByController")]
    async fn docclass_get_identity_by_controller(
        &self,
        controller: String,
    ) -> Result<Option<DocClassIdentityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get credential by ID (hex)
    #[method(name = "docclass_getCredential")]
    async fn docclass_get_credential(
        &self,
        credential_id: String,
    ) -> Result<Option<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get credentials by subject commitment (hex)
    #[method(name = "docclass_getCredentialsBySubject")]
    async fn docclass_get_credentials_by_subject(
        &self,
        subject_commitment: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get credentials by issuer address
    #[method(name = "docclass_getCredentialsByIssuer")]
    async fn docclass_get_credentials_by_issuer(
        &self,
        issuer: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a credential is valid (not revoked, not expired)
    #[method(name = "docclass_isCredentialValid")]
    async fn docclass_is_credential_valid(
        &self,
        credential_id: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Get issuer by address
    #[method(name = "docclass_getIssuer")]
    async fn docclass_get_issuer(
        &self,
        address: String,
    ) -> Result<Option<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all registered issuers
    #[method(name = "docclass_getIssuers")]
    async fn docclass_get_issuers(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get issuers by jurisdiction
    #[method(name = "docclass_getIssuersByJurisdiction")]
    async fn docclass_get_issuers_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> Result<Vec<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an issuer can issue a specific subcode in a jurisdiction
    #[method(name = "docclass_canIssue")]
    async fn docclass_can_issue(
        &self,
        issuer: String,
        subcode: u16,
        jurisdiction: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Transaction History Endpoints
    // ========================================================================

    /// Get transactions by address (both sent and received)
    /// Returns transactions with pagination support
    #[method(name = "sum_getTransactionsByAddress")]
    async fn sum_get_transactions_by_address(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transactions sent by an address
    #[method(name = "sum_getTransactionsBySender")]
    async fn sum_get_transactions_by_sender(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transactions received by an address
    #[method(name = "sum_getTransactionsByRecipient")]
    async fn sum_get_transactions_by_recipient(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction count for an address
    #[method(name = "sum_getTransactionCount")]
    async fn sum_get_transaction_count(
        &self,
        address: String,
    ) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-88X Employment & HR Endpoints
    // =========================================================================

    /// Get employment issuer by address (SRC-881)
    #[method(name = "employment_getIssuer")]
    async fn employment_get_issuer(
        &self,
        issuer_address: String,
    ) -> Result<Option<EmploymentIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all active employment issuers
    #[method(name = "employment_listIssuers")]
    async fn employment_list_issuers(
        &self,
    ) -> Result<Vec<EmploymentIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment credential by ID (SRC-882)
    #[method(name = "employment_getCredential")]
    async fn employment_get_credential(
        &self,
        employment_id: String,
    ) -> Result<Option<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment credentials by employee reference
    #[method(name = "employment_getCredentialsByEmployee")]
    async fn employment_get_credentials_by_employee(
        &self,
        employee_ref: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get active employment credentials by employee reference
    #[method(name = "employment_getActiveCredentialsByEmployee")]
    async fn employment_get_active_credentials_by_employee(
        &self,
        employee_ref: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment credentials by employer reference
    #[method(name = "employment_getCredentialsByEmployer")]
    async fn employment_get_credentials_by_employer(
        &self,
        employer_ref: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Verify if an employee is currently employed by a specific employer
    #[method(name = "employment_verifyEmployment")]
    async fn employment_verify_employment(
        &self,
        employee_ref: String,
        employer_ref: String,
    ) -> Result<EmploymentVerificationResult, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment summary for an employee
    #[method(name = "employment_getSummary")]
    async fn employment_get_summary(
        &self,
        employee_ref: String,
    ) -> Result<EmploymentSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get income attestation by ID (SRC-883)
    #[method(name = "employment_getIncomeAttestation")]
    async fn employment_get_income_attestation(
        &self,
        attestation_id: String,
    ) -> Result<Option<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get income attestations by subject reference
    #[method(name = "employment_getIncomeAttestationsBySubject")]
    async fn employment_get_income_attestations_by_subject(
        &self,
        subject_ref: String,
    ) -> Result<Vec<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-88X Employment - Address-based queries (token ownership)
    // =========================================================================

    /// Get employment credentials by employee wallet address
    #[method(name = "employment_getCredentialsByEmployeeAddress")]
    async fn employment_get_credentials_by_employee_address(
        &self,
        employee_address: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get active employment credentials by employee wallet address
    #[method(name = "employment_getActiveCredentialsByEmployeeAddress")]
    async fn employment_get_active_credentials_by_employee_address(
        &self,
        employee_address: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get income attestations by holder wallet address
    #[method(name = "employment_getIncomeAttestationsByHolderAddress")]
    async fn employment_get_income_attestations_by_holder_address(
        &self,
        holder_address: String,
    ) -> Result<Vec<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-88X Employment Write Operations (Token-gated access)
    // =========================================================================

    /// Register as an employment issuer (SRC-881)
    /// Requires signing the transaction with issuer's private key
    #[method(name = "employment_registerIssuer")]
    async fn employment_register_issuer(
        &self,
        request: RegisterEmploymentIssuerRequest,
    ) -> Result<RegisterEmploymentIssuerResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Create an employment credential (SRC-882)
    /// Requires the caller to be a registered issuer
    #[method(name = "employment_createCredential")]
    async fn employment_create_credential(
        &self,
        request: CreateEmploymentCredentialRequest,
    ) -> Result<CreateEmploymentCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Revoke an employment credential (SRC-882)
    /// Requires the caller to be the original issuer of the credential
    #[method(name = "employment_revokeCredential")]
    async fn employment_revoke_credential(
        &self,
        request: RevokeEmploymentCredentialRequest,
    ) -> Result<RevokeEmploymentCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-81X Academic Credential Write Operations
    // =========================================================================

    /// Register as an academic issuer (educational institution)
    /// Requires signing the transaction with issuer's private key
    /// Requires stake amount (>= 1000 Ϙ)
    #[method(name = "docclass_registerAcademicIssuer")]
    async fn docclass_register_academic_issuer(
        &self,
        request: RegisterAcademicIssuerRequest,
    ) -> Result<RegisterAcademicIssuerResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Issue an academic credential (SRC-810/811/812)
    /// Requires the caller to be a registered academic issuer
    /// Subcodes: 810=Transcript, 811=Diploma, 812=Enrollment
    #[method(name = "docclass_issueAcademicCredential")]
    async fn docclass_issue_academic_credential(
        &self,
        request: IssueAcademicCredentialRequest,
    ) -> Result<IssueAcademicCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Revoke an academic credential (SRC-810/811/812)
    /// Requires the caller to be the original issuer of the credential
    #[method(name = "docclass_revokeAcademicCredential")]
    async fn docclass_revoke_academic_credential(
        &self,
        request: RevokeAcademicCredentialRequest,
    ) -> Result<RevokeAcademicCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get academic credentials by holder address
    /// Returns all academic credentials (810/811/812) owned by the given address
    #[method(name = "docclass_getAcademicCredentialsByHolder")]
    async fn docclass_get_academic_credentials_by_holder(
        &self,
        holder_address: String,
    ) -> Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // Policy Account Methods (Group Governance)
    // =========================================================================

    /// Create a new policy account (group-governed address)
    #[method(name = "policy_createAccount")]
    async fn policy_create_account(
        &self,
        request: CreatePolicyAccountRequest,
    ) -> Result<CreatePolicyAccountResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get policy account information by ID
    #[method(name = "policy_getAccount")]
    async fn policy_get_account(
        &self,
        policy_account_id: String,
    ) -> Result<PolicyAccountInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get policy account by controlled address
    #[method(name = "policy_getAccountByAddress")]
    async fn policy_get_account_by_address(
        &self,
        address: String,
    ) -> Result<Option<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List policy accounts where the address is a member
    #[method(name = "policy_listMemberAccounts")]
    async fn policy_list_member_accounts(
        &self,
        member_address: String,
    ) -> Result<Vec<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Submit a proposal for group-authorized action
    #[method(name = "policy_submitProposal")]
    async fn policy_submit_proposal(
        &self,
        request: SubmitProposalRequest,
    ) -> Result<SubmitProposalResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Execute a proposal once threshold is met
    #[method(name = "policy_executeProposal")]
    async fn policy_execute_proposal(
        &self,
        request: ExecuteProposalRequest,
    ) -> Result<ExecuteProposalResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Cancel a pending proposal (proposer only)
    #[method(name = "policy_cancelProposal")]
    async fn policy_cancel_proposal(
        &self,
        request: CancelProposalRequest,
    ) -> Result<CancelProposalResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get proposal information by ID
    #[method(name = "policy_getProposal")]
    async fn policy_get_proposal(
        &self,
        proposal_id: String,
    ) -> Result<ProposalInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// List all proposals for a policy account
    #[method(name = "policy_listProposals")]
    async fn policy_list_proposals(
        &self,
        policy_account_id: String,
    ) -> Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List pending proposals for a policy account
    #[method(name = "policy_listPendingProposals")]
    async fn policy_list_pending_proposals(
        &self,
        policy_account_id: String,
    ) -> Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Storage Metadata Methods
    // ========================================================================

    /// Get storage file metadata and access list by merkle root
    #[method(name = "storage_getAccessList")]
    async fn storage_get_access_list(
        &self,
        merkle_root: String,
    ) -> Result<Option<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all active storage challenges assigned to a specific node
    #[method(name = "storage_getActiveChallenges")]
    async fn storage_get_active_challenges(
        &self,
        node_address: String,
    ) -> Result<Vec<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all files with a non-zero fee pool (the storage market)
    #[method(name = "storage_getFundedFiles")]
    async fn storage_get_funded_files(
        &self,
    ) -> Result<Vec<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a node's registry record (stake, role, status)
    #[method(name = "storage_getNodeRecord")]
    async fn storage_get_node_record(
        &self,
        node_address: String,
    ) -> Result<Option<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get full V2 file metadata with a paginated access-list window.
    /// SNIP V2 Phase 1c (plan v3.2 §4, Ask 6).
    ///
    /// `access_offset` indexes into the file's `access_list`; `access_limit`
    /// caps the returned window (default 256, hard cap 1024). The total
    /// access-list size is returned in `access_total`. For Public files the
    /// `encrypted_key_bundle` field of every entry is JSON `null`; for Private
    /// files it's the `0x`-prefixed hex of the 80-byte bundle.
    ///
    /// Returns `None` if the file is not registered.
    #[method(name = "storage_getFileInfoV2")]
    async fn storage_get_file_info_v2(
        &self,
        merkle_root: String,
        access_offset: Option<u32>,
        access_limit: Option<u32>,
    ) -> Result<Option<StorageFileInfoV2>, jsonrpsee::types::ErrorObjectOwned>;

    /// List V2 files in a "pushable" lifecycle (Pending or Active);
    /// Abandoned files are excluded. SNIP V2 Phase 1c (plan v3.2 §4, Ask 9).
    ///
    /// Used by archive nodes as a warm-cache source: when a push request
    /// arrives, the archive can decide locally whether the file is known
    /// without per-push RPC chatter. `Pending` means still ramping up;
    /// `Active` means a resync push (the activation race rule from Ask 14).
    ///
    /// Paginated (offset/limit) so a hosted endpoint can serve a registry
    /// of arbitrary size without unbounded response bodies. Files are
    /// returned in `merkle_root` lexicographic order — stable under
    /// concurrent appends, **eventually-consistent** under concurrent
    /// lifecycle transitions (a file moving Pending→Active stays in the
    /// list with its new lifecycle; one moving to Abandoned drops). Default
    /// `limit = 256`, hard cap `1024`. Callers paginate with
    /// `offset += returned.len()`.
    #[method(name = "storage_getPushableFilesV2")]
    async fn storage_get_pushable_files_v2(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<PushableFileInfoV2>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get coverage state for a Pending V2 file. SNIP V2 Phase 1b (plan v3.2 §4).
    ///
    /// Returns popcount summaries + a paginated window of missing chunk indices
    /// — never raw `Vec<u32>` per archive. Owners poll until `can_activate_now`
    /// is true; archives use `per_archive[i].assigned_count` to know what to push.
    ///
    /// `missing_offset` is a **chunk-index lower bound** (not an offset into the
    /// filtered missing list). Pagination is stable under concurrent
    /// `AcceptAssignmentV2` writes — the next call uses
    /// `missing_offset = last_returned_index + 1`.
    #[method(name = "storage_getAssignmentCoverageV2")]
    async fn storage_get_assignment_coverage_v2(
        &self,
        merkle_root: String,
        missing_offset: Option<u32>,
        missing_limit: Option<u32>,
    ) -> Result<Option<AssignmentCoverageV2>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the active-archive-node set as snapshotted at the largest stored
    /// height `≤ height`. SNIP V2 Ask 15 (Phase 0b checkpoint 2b).
    ///
    /// Lookup semantics (plan v3 §5.3):
    /// - For `height == 0` or `height` < first post-genesis change → returns
    ///   the genesis snapshot (empty array unless genesis pre-loaded archives,
    ///   which it doesn't today).
    /// - For `height` between two snapshot heights, returns the snapshot at
    ///   the earlier height — assignments captured then are stable per the
    ///   "no reassignment" rule.
    /// - For `height` > head height, returns the most recent snapshot
    ///   (no Err — saves a round-trip for clients querying near head).
    ///
    /// Each entry is a [`NodeRecordInfo`]: base58 `address`, role/status as
    /// strings, `staked_balance` as a native `u64`, `registered_at` as block
    /// height. Wire shape locked by JSON-shape tests in the server crate.
    #[method(name = "storage_getActiveNodesAtHeight")]
    async fn storage_get_active_nodes_at_height(
        &self,
        height: u64,
    ) -> Result<Vec<NodeRecordInfo>, jsonrpsee::types::ErrorObjectOwned>;
}

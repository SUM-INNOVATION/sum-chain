//! RPC API trait definition using jsonrpsee.

use jsonrpsee::proc_macros::rpc;

use crate::metrics::MetricsSnapshot;
use crate::types::{
    AccountInfo, BlockInfo, ContractCallResult, ContractInfo, DelegationRpcInfo,
    DelegatorSummary, DocClassConfigInfo, DocClassCredentialInfo, DocClassIdentityInfo,
    DocClassIssuerInfo, DocClassSummary, EmploymentCredentialInfo, EmploymentIssuerInfo,
    EmploymentSummary, EmploymentVerificationResult, EpochInfo, FinalityInfo, GasEstimateResult,
    HealthResponse, IncomeAttestationInfo, InboxFilterInfo, MessageDataInfo, MessageEventInfo,
    MessagingConfigInfo, MessagingQuotaInfo, NftCollectionInfo, NftOwnerTokens, NftTokenInfo,
    NodeInfo, P2pStats, PendingPaymentInfo, PublicKeyInfo, ReceiptInfo, RpcPeerInfo, SendTxResponse,
    SlashingRecordRpcInfo, SlashingSummary, SpamReportInfo, SponsoredRegistrationRequest,
    SponsoredRegistrationResponse, StakingParamsInfo, StakingSummary, StakingValidatorInfo,
    SubmitSponsoredMessageRequest, TokenHoldings, TokenInfo, TransactionHistoryResponse,
    TransactionInfo, UnbondingDelegationRpcInfo, ValidatorDelegationSummary, ValidatorSetInfo,
    ValidatorSetRpcInfo, ValidatorSigningRpcInfo, ViewCallRequest,
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
}

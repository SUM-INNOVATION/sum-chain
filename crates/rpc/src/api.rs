//! RPC API trait definition using jsonrpsee.

use jsonrpsee::proc_macros::rpc;

use crate::metrics::MetricsSnapshot;
use crate::types::{
    AccountInfo, BlockInfo, ContractCallResult, ContractInfo, DelegationRpcInfo,
    DelegatorSummary, EpochInfo, FinalityInfo, GasEstimateResult, HealthResponse,
    NftCollectionInfo, NftOwnerTokens, NftTokenInfo, NodeInfo, P2pStats, ReceiptInfo,
    RpcPeerInfo, SendTxResponse, SlashingRecordRpcInfo, SlashingSummary, StakingParamsInfo,
    StakingSummary, StakingValidatorInfo, TokenHoldings, TokenInfo, TransactionInfo,
    UnbondingDelegationRpcInfo, ValidatorDelegationSummary, ValidatorSetInfo,
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
}

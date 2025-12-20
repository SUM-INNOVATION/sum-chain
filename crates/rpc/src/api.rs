//! RPC API trait definition using jsonrpsee.

use jsonrpsee::proc_macros::rpc;

use crate::metrics::MetricsSnapshot;
use crate::types::*;

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

    /// Get latest block number (Ethereum-compatible)
    #[method(name = "eth_blockNumber")]
    async fn eth_block_number(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get balance in hex format (Ethereum-compatible)
    #[method(name = "eth_getBalance")]
    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

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
}

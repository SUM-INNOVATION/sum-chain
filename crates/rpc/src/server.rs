//! RPC server implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use jsonrpsee::server::{Server, ServerHandle};
use sumchain_consensus::ConsensusEngine;
use sumchain_primitives::{Address, Block, Hash, SignedTransaction};
use sumchain_state::{Mempool, StateManager};
use sumchain_storage::{BlockStore, Database, NftStore, ReceiptStore, TokenStore, TxStore};
use tokio::sync::mpsc;
use tracing::info;

use crate::api::SumChainApiServer;
use crate::auth::{ApiKeyValidator, RpcAuthConfig};
use crate::health::HealthCheck;
use crate::metrics::{Metrics, MetricsSnapshot};
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::types::*;
use crate::{RpcError, Result};

/// Node version constant
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Peer info provider function type
pub type PeerInfoProvider = Arc<dyn Fn() -> Vec<RpcPeerInfo> + Send + Sync>;
/// P2P stats provider function type
pub type P2pStatsProvider = Arc<dyn Fn() -> P2pStats + Send + Sync>;

/// RPC server timeout configuration
#[derive(Debug, Clone)]
pub struct RpcTimeoutConfig {
    /// Request timeout (how long before a request times out)
    pub request_timeout: Duration,
    /// Connection timeout for new connections
    pub connection_timeout: Duration,
    /// Maximum number of concurrent connections
    pub max_connections: u32,
    /// Maximum request body size in bytes
    pub max_request_body_size: u32,
    /// Maximum response body size in bytes
    pub max_response_body_size: u32,
}

impl Default for RpcTimeoutConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
            max_connections: 100,
            max_request_body_size: 10 * 1024 * 1024, // 10MB
            max_response_body_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl RpcTimeoutConfig {
    /// Create a config with short timeouts for testing
    pub fn for_testing() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(2),
            max_connections: 10,
            max_request_body_size: 1024 * 1024, // 1MB
            max_response_body_size: 1024 * 1024, // 1MB
        }
    }

    /// Create a config with no timeouts (use with caution)
    pub fn no_timeout() -> Self {
        Self {
            request_timeout: Duration::from_secs(0), // 0 means no timeout
            connection_timeout: Duration::from_secs(0),
            max_connections: 1000,
            max_request_body_size: 100 * 1024 * 1024, // 100MB
            max_response_body_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// RPC server
pub struct RpcServer {
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<dyn ConsensusEngine>,
    tx_sender: mpsc::Sender<SignedTransaction>,
    peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    peer_id: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    is_synced: Arc<dyn Fn() -> bool + Send + Sync>,
    auth_validator: Arc<ApiKeyValidator>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<Metrics>,
    health_check: Arc<HealthCheck>,
    /// Optional peer info provider for get_peers RPC
    peer_info_provider: Option<PeerInfoProvider>,
    /// Optional P2P stats provider for get_p2p_stats RPC
    p2p_stats_provider: Option<P2pStatsProvider>,
    /// Timeout configuration
    timeout_config: RpcTimeoutConfig,
    /// Contract executor for smart contract RPCs
    contract_executor: Option<Arc<sumchain_state::ContractExecutorState>>,
}

impl RpcServer {
    /// Create a new RPC server
    #[allow(dead_code)]
    pub fn new(
        db: Arc<Database>,
        state: Arc<StateManager>,
        mempool: Arc<Mempool>,
        consensus: Arc<dyn ConsensusEngine>,
        tx_sender: mpsc::Sender<SignedTransaction>,
        peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    ) -> Self {
        Self::with_full_config(
            db,
            state,
            mempool,
            consensus,
            tx_sender,
            peer_count,
            Arc::new(|| None),
            Arc::new(|| true), // Default to synced
            RpcAuthConfig::disabled(),
            RateLimitConfig::disabled(),
            Arc::new(Metrics::new()),
        )
    }

    /// Create a new RPC server with authentication config
    #[allow(dead_code)]
    pub fn with_auth(
        db: Arc<Database>,
        state: Arc<StateManager>,
        mempool: Arc<Mempool>,
        consensus: Arc<dyn ConsensusEngine>,
        tx_sender: mpsc::Sender<SignedTransaction>,
        peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
        auth_config: RpcAuthConfig,
    ) -> Self {
        Self::with_full_config(
            db,
            state,
            mempool,
            consensus,
            tx_sender,
            peer_count,
            Arc::new(|| None),
            Arc::new(|| true), // Default to synced
            auth_config,
            RateLimitConfig::disabled(),
            Arc::new(Metrics::new()),
        )
    }

    /// Create a new RPC server with auth and rate limit config
    #[allow(dead_code)]
    pub fn with_config(
        db: Arc<Database>,
        state: Arc<StateManager>,
        mempool: Arc<Mempool>,
        consensus: Arc<dyn ConsensusEngine>,
        tx_sender: mpsc::Sender<SignedTransaction>,
        peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
        auth_config: RpcAuthConfig,
        rate_limit_config: RateLimitConfig,
    ) -> Self {
        Self::with_full_config(
            db,
            state,
            mempool,
            consensus,
            tx_sender,
            peer_count,
            Arc::new(|| None),
            Arc::new(|| true), // Default to synced
            auth_config,
            rate_limit_config,
            Arc::new(Metrics::new()),
        )
    }

    /// Create a new RPC server with full configuration including metrics
    pub fn with_full_config(
        db: Arc<Database>,
        state: Arc<StateManager>,
        mempool: Arc<Mempool>,
        consensus: Arc<dyn ConsensusEngine>,
        tx_sender: mpsc::Sender<SignedTransaction>,
        peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
        peer_id: Arc<dyn Fn() -> Option<String> + Send + Sync>,
        is_synced: Arc<dyn Fn() -> bool + Send + Sync>,
        auth_config: RpcAuthConfig,
        rate_limit_config: RateLimitConfig,
        metrics: Arc<Metrics>,
    ) -> Self {
        let auth_validator = Arc::new(ApiKeyValidator::new(&auth_config));
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config));

        // Create health check provider
        let is_synced_clone = is_synced.clone();
        let peer_count_clone = peer_count.clone();
        let consensus_clone = consensus.clone();
        let health_check = Arc::new(HealthCheck::new(
            is_synced_clone,
            peer_count_clone,
            Arc::new(move || consensus_clone.current_height()),
        ));

        Self {
            db,
            state,
            mempool,
            consensus,
            tx_sender,
            peer_count,
            peer_id,
            is_synced,
            auth_validator,
            rate_limiter,
            metrics,
            health_check,
            peer_info_provider: None,
            p2p_stats_provider: None,
            timeout_config: RpcTimeoutConfig::default(),
            contract_executor: None,
        }
    }

    /// Set the peer info provider for get_peers RPC
    pub fn with_peer_info(mut self, provider: PeerInfoProvider) -> Self {
        self.peer_info_provider = Some(provider);
        self
    }

    /// Set the P2P stats provider for get_p2p_stats RPC
    pub fn with_p2p_stats(mut self, provider: P2pStatsProvider) -> Self {
        self.p2p_stats_provider = Some(provider);
        self
    }

    /// Set the timeout configuration
    pub fn with_timeout(mut self, config: RpcTimeoutConfig) -> Self {
        self.timeout_config = config;
        self
    }

    /// Set the contract executor for smart contract RPCs
    pub fn with_contract_executor(mut self, executor: Arc<sumchain_state::ContractExecutorState>) -> Self {
        self.contract_executor = Some(executor);
        self
    }

    /// Get the auth validator (for adding/removing keys at runtime)
    pub fn auth_validator(&self) -> &Arc<ApiKeyValidator> {
        &self.auth_validator
    }

    /// Get the rate limiter
    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }

    /// Get the metrics collector
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Get the health check provider
    pub fn health_check(&self) -> &Arc<HealthCheck> {
        &self.health_check
    }

    /// Get the timeout configuration
    pub fn timeout_config(&self) -> &RpcTimeoutConfig {
        &self.timeout_config
    }

    /// Start the RPC server
    pub async fn start(self, addr: SocketAddr) -> std::result::Result<ServerHandle, std::io::Error> {
        info!("Starting RPC server on {}", addr);
        if self.auth_validator.is_enabled() {
            info!("RPC authentication is ENABLED");
        } else {
            info!("RPC authentication is DISABLED (all requests allowed)");
        }
        if self.rate_limiter.is_enabled() {
            info!("RPC rate limiting is ENABLED");
        } else {
            info!("RPC rate limiting is DISABLED");
        }
        info!(
            "RPC timeouts: request={:?}, max_connections={}",
            self.timeout_config.request_timeout,
            self.timeout_config.max_connections
        );

        let server = Server::builder()
            .max_connections(self.timeout_config.max_connections)
            .max_request_body_size(self.timeout_config.max_request_body_size)
            .max_response_body_size(self.timeout_config.max_response_body_size)
            .build(addr)
            .await?;

        let handle = server.start(self.into_rpc());

        info!("RPC server started");
        Ok(handle)
    }

    /// Convert block to RPC type
    fn block_to_info(&self, block: &Block) -> BlockInfo {
        BlockInfo {
            hash: block.hash().to_hex(),
            height: block.height(),
            parent_hash: block.header.parent_hash.to_hex(),
            timestamp: block.header.timestamp,
            tx_root: block.header.tx_root.to_hex(),
            state_root: block.header.state_root.to_hex(),
            proposer: hex::encode(block.header.proposer_pubkey),
            tx_count: block.tx_count(),
            transactions: block.transactions.iter().map(|tx| tx.hash().to_hex()).collect(),
        }
    }

    /// Convert transaction to RPC type
    fn tx_to_info(&self, tx: &SignedTransaction, receipt: Option<&sumchain_primitives::Receipt>) -> TransactionInfo {
        TransactionInfo {
            hash: tx.hash().to_hex(),
            from: tx.sender().to_base58(),
            to: tx.recipient().map(|r| r.to_base58()).unwrap_or_default(),
            amount: tx.amount().to_string(),
            fee: tx.fee().to_string(),
            nonce: tx.nonce(),
            chain_id: tx.chain_id(),
            signature: hex::encode(tx.signature),
            block_height: receipt.map(|r| r.block_height),
            status: receipt.map(|r| r.status.description().to_string()),
        }
    }

    /// Parse address from string
    fn parse_address(&self, s: &str) -> Result<Address> {
        Address::from_base58(s)
            .or_else(|_| Address::from_hex(s))
            .map_err(|_| RpcError::InvalidParams(format!("Invalid address: {}", s)))
    }

    /// Parse hash from string
    fn parse_hash(&self, s: &str) -> Result<Hash> {
        Hash::from_hex(s)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid hash: {}", e)))
    }

    /// Parse collection ID from hex string
    fn parse_collection_id(&self, s: &str) -> Result<[u8; 32]> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid collection ID: {}", e)))?;
        if bytes.len() != 32 {
            return Err(RpcError::InvalidParams(format!(
                "Invalid collection ID length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Parse token ID from hex string
    fn parse_token_id(&self, s: &str) -> Result<[u8; 32]> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid token ID: {}", e)))?;
        if bytes.len() != 32 {
            return Err(RpcError::InvalidParams(format!(
                "Invalid token ID length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[async_trait::async_trait]
impl SumChainApiServer for RpcServer {
    async fn chain_id(&self) -> std::result::Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        Ok(self.state.chain_id())
    }

    async fn get_latest_block(&self) -> std::result::Result<BlockInfo, jsonrpsee::types::ErrorObjectOwned> {
        let block_store = BlockStore::new(&self.db);

        let block = block_store
            .get_latest()
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .ok_or_else(|| RpcError::NotFound("No blocks found".to_string()))?;

        Ok(self.block_to_info(&block))
    }

    async fn get_block_by_height(
        &self,
        height: u64,
    ) -> std::result::Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let block_store = BlockStore::new(&self.db);

        let block = block_store
            .get_by_height(height)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(block.map(|b| self.block_to_info(&b)))
    }

    async fn get_block_by_hash(
        &self,
        hash: String,
    ) -> std::result::Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = self.parse_hash(&hash)?;
        let block_store = BlockStore::new(&self.db);

        let block = block_store
            .get_by_hash(&hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(block.map(|b| self.block_to_info(&b)))
    }

    async fn get_balance(
        &self,
        address: String,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let balance = self
            .state
            .get_balance(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(balance.to_string())
    }

    async fn get_nonce(
        &self,
        address: String,
    ) -> std::result::Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let nonce = self
            .state
            .get_nonce(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(nonce)
    }

    async fn get_account(
        &self,
        address: String,
    ) -> std::result::Result<AccountInfo, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let account = self
            .state
            .get_account(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(AccountInfo {
            address: addr.to_base58(),
            balance: account.balance.to_string(),
            nonce: account.nonce,
        })
    }

    async fn send_raw_transaction(
        &self,
        raw_tx: String,
    ) -> std::result::Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned> {
        let tx = SignedTransaction::from_hex(&raw_tx)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid transaction: {}", e)))?;

        let tx_hash = tx.hash();

        // Add to mempool
        self.mempool
            .add(tx.clone())
            .map_err(|e| RpcError::TxRejected(e.to_string()))?;

        // Send to network via channel
        self.tx_sender
            .send(tx)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to broadcast: {}", e)))?;

        info!("Transaction {} submitted", tx_hash);

        Ok(SendTxResponse {
            tx_hash: tx_hash.to_hex(),
        })
    }

    async fn get_transaction(
        &self,
        tx_hash: String,
    ) -> std::result::Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = self.parse_hash(&tx_hash)?;

        let tx_store = TxStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);

        let tx = tx_store
            .get(&hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        match tx {
            Some(tx) => {
                let receipt = receipt_store
                    .get(&hash)
                    .map_err(|e| RpcError::Internal(e.to_string()))?;

                Ok(Some(self.tx_to_info(&tx, receipt.as_ref())))
            }
            None => {
                // Check mempool
                if let Some(tx) = self.mempool.get(&hash) {
                    Ok(Some(self.tx_to_info(&tx, None)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    async fn get_receipt(
        &self,
        tx_hash: String,
    ) -> std::result::Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = self.parse_hash(&tx_hash)?;
        let receipt_store = ReceiptStore::new(&self.db);

        let receipt = receipt_store
            .get(&hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(receipt.map(|r| ReceiptInfo {
            tx_hash: r.tx_hash.to_hex(),
            block_height: r.block_height,
            tx_index: r.tx_index,
            status: r.status.description().to_string(),
            fee_paid: r.fee_paid.to_string(),
        }))
    }

    async fn health(&self) -> std::result::Result<HealthResponse, jsonrpsee::types::ErrorObjectOwned> {
        Ok(HealthResponse {
            status: "ok".to_string(),
            chain_id: self.state.chain_id(),
            height: self.consensus.current_height(),
            peer_count: (self.peer_count)(),
            is_validator: self.consensus.is_validator(),
            is_synced: (self.is_synced)(),
        })
    }

    async fn pending_tx_count(&self) -> std::result::Result<usize, jsonrpsee::types::ErrorObjectOwned> {
        Ok(self.mempool.len())
    }

    async fn eth_block_number(&self) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let height = self.consensus.current_height();
        Ok(format!("0x{:x}", height))
    }

    async fn eth_get_balance(
        &self,
        address: String,
        _block: Option<String>,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let balance = self
            .state
            .get_balance(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        // Return balance in hex format (Ethereum-compatible)
        Ok(format!("0x{:x}", balance))
    }

    async fn get_pending_transactions(&self) -> std::result::Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let pending = self.mempool.get_all();
        let txs: Vec<TransactionInfo> = pending
            .iter()
            .map(|tx| self.tx_to_info(tx, None))
            .collect();
        Ok(txs)
    }

    async fn get_validators(&self) -> std::result::Result<ValidatorSetInfo, jsonrpsee::types::ErrorObjectOwned> {
        let validators = self.consensus.validators();
        let current_height = self.consensus.current_height();
        let proposer_index = (current_height as usize) % validators.len();

        let validator_infos: Vec<ValidatorInfo> = validators
            .iter()
            .enumerate()
            .map(|(idx, pubkey)| {
                let address = Address::from_public_key(pubkey);
                ValidatorInfo {
                    public_key: hex::encode(pubkey),
                    address: address.to_base58(),
                    is_current_proposer: idx == proposer_index,
                }
            })
            .collect();

        Ok(ValidatorSetInfo {
            validators: validator_infos,
            current_height,
            current_proposer_index: proposer_index,
        })
    }

    async fn get_blocks(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> std::result::Result<Vec<BlockInfo>, jsonrpsee::types::ErrorObjectOwned> {
        if to_height < from_height {
            return Err(RpcError::InvalidParams("to_height must be >= from_height".to_string()).into());
        }

        // Limit to prevent DoS
        const MAX_BLOCKS: u64 = 100;
        if to_height - from_height > MAX_BLOCKS {
            return Err(RpcError::InvalidParams(format!("Cannot fetch more than {} blocks at once", MAX_BLOCKS)).into());
        }

        let block_store = BlockStore::new(&self.db);
        let mut blocks = Vec::new();

        for height in from_height..=to_height {
            if let Some(block) = block_store
                .get_by_height(height)
                .map_err(|e| RpcError::Internal(e.to_string()))?
            {
                blocks.push(self.block_to_info(&block));
            }
        }

        Ok(blocks)
    }

    async fn get_metrics(&self) -> std::result::Result<MetricsSnapshot, jsonrpsee::types::ErrorObjectOwned> {
        // Update dynamic metrics before snapshot
        self.metrics.blocks.set_height(self.consensus.current_height());
        self.metrics.p2p.set_peer_count((self.peer_count)());
        self.metrics.mempool.set_size(self.mempool.len());

        Ok(self.metrics.snapshot())
    }

    async fn node_info(&self) -> std::result::Result<NodeInfo, jsonrpsee::types::ErrorObjectOwned> {
        Ok(NodeInfo {
            version: VERSION.to_string(),
            chain_id: self.state.chain_id(),
            network: format!("sumchain-{}", self.state.chain_id()),
            peer_id: (self.peer_id)(),
            is_validator: self.consensus.is_validator(),
            current_height: self.consensus.current_height(),
            peer_count: (self.peer_count)(),
            mempool_size: self.mempool.len(),
            uptime_seconds: self.metrics.uptime_seconds(),
        })
    }

    async fn get_finality(&self) -> std::result::Result<FinalityInfo, jsonrpsee::types::ErrorObjectOwned> {
        let finalized_height = self.consensus.finalized_height();
        let finalized_hash = self.consensus.finalized_hash();
        let current_height = self.consensus.current_height();
        let finality_depth = self.consensus.finality_depth();

        // Calculate pending finality (blocks that are not yet finalized)
        let pending_finality = if current_height > finalized_height {
            current_height - finalized_height
        } else {
            0
        };

        Ok(FinalityInfo {
            finalized_height,
            finalized_hash: finalized_hash.to_hex(),
            current_height,
            finality_depth,
            pending_finality,
        })
    }

    async fn is_block_finalized(&self, height: u64) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        Ok(self.consensus.is_finalized(height))
    }

    async fn get_peers(&self) -> std::result::Result<Vec<RpcPeerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        match &self.peer_info_provider {
            Some(provider) => Ok(provider()),
            None => Ok(Vec::new()), // Return empty if not configured
        }
    }

    async fn get_p2p_stats(&self) -> std::result::Result<P2pStats, jsonrpsee::types::ErrorObjectOwned> {
        match &self.p2p_stats_provider {
            Some(provider) => Ok(provider()),
            None => {
                // Return basic stats from peer_count if full provider not available
                let peer_count = (self.peer_count)();
                Ok(P2pStats {
                    total_known_peers: peer_count,
                    connected_peers: peer_count,
                    inbound_connections: 0,
                    outbound_connections: peer_count,
                    banned_peers: 0,
                    max_connections: 100,
                    max_inbound: 50,
                    max_outbound: 50,
                })
            }
        }
    }

    // ========================================================================
    // SUM Chain Native Aliases (sum_* prefix)
    // These delegate to the unprefixed methods for brand consistency
    // ========================================================================

    async fn sum_block_number(&self) -> std::result::Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        Ok(self.consensus.current_height())
    }

    async fn sum_get_latest_block(&self) -> std::result::Result<BlockInfo, jsonrpsee::types::ErrorObjectOwned> {
        self.get_latest_block().await
    }

    async fn sum_get_block_by_height(
        &self,
        height: u64,
    ) -> std::result::Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.get_block_by_height(height).await
    }

    async fn sum_get_balance(
        &self,
        address: String,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        self.get_balance(address).await
    }

    async fn sum_get_nonce(&self, address: String) -> std::result::Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        self.get_nonce(address).await
    }

    async fn sum_send_raw_transaction(
        &self,
        raw_tx: String,
    ) -> std::result::Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned> {
        self.send_raw_transaction(raw_tx).await
    }

    async fn sum_get_transaction(
        &self,
        tx_hash: String,
    ) -> std::result::Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.get_transaction(tx_hash).await
    }

    async fn sum_get_receipt(
        &self,
        tx_hash: String,
    ) -> std::result::Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.get_receipt(tx_hash).await
    }

    async fn sum_get_pending_transactions(&self) -> std::result::Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        self.get_pending_transactions().await
    }

    async fn sum_get_validators(&self) -> std::result::Result<ValidatorSetInfo, jsonrpsee::types::ErrorObjectOwned> {
        self.get_validators().await
    }

    // ========================================================================
    // NFT (SUM-721) Endpoints
    // ========================================================================

    async fn nft_get_collection(
        &self,
        collection_id: String,
    ) -> std::result::Result<Option<NftCollectionInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let collection_bytes = self.parse_collection_id(&collection_id)?;
        let nft_store = NftStore::new(&self.db);

        let collection = nft_store
            .get_collection(&collection_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(collection.map(|c| NftCollectionInfo {
            collection_id: format!("0x{}", hex::encode(collection_bytes)),
            name: c.name,
            symbol: c.symbol,
            description: c.description,
            owner: c.owner.to_base58(),
            max_supply: c.max_supply,
            total_supply: c.total_supply,
            transferable: c.transferable,
            burnable: c.burnable,
            metadata_updatable: c.metadata_updatable,
            royalty_bps: c.royalty_bps,
            royalty_recipient: c.royalty_recipient.to_base58(),
            base_uri: c.base_uri,
            created_at: c.created_at,
        }))
    }

    async fn nft_get_token(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> std::result::Result<Option<NftTokenInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let collection_bytes = self.parse_collection_id(&collection_id)?;
        let nft_store = NftStore::new(&self.db);

        let token = nft_store
            .get_token(&collection_bytes, token_id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(token.map(|t| NftTokenInfo {
            collection_id: format!("0x{}", hex::encode(t.collection_id)),
            token_id: t.token_id,
            owner: t.owner.to_base58(),
            creator: t.creator.to_base58(),
            metadata: if t.metadata.is_empty() {
                String::new()
            } else {
                // Try to parse as JSON, otherwise hex encode
                String::from_utf8(t.metadata.clone())
                    .unwrap_or_else(|_| format!("0x{}", hex::encode(&t.metadata)))
            },
            is_document: t.is_document,
            uri_type: t.uri_type,
            uri_value: t.uri_value,
            approved: t.approved.map(|a| a.to_base58()),
            locked: t.locked,
            transfer_count: t.transfer_count,
            minted_at: t.minted_at,
        }))
    }

    async fn nft_get_tokens_by_owner(
        &self,
        owner: String,
    ) -> std::result::Result<NftOwnerTokens, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&owner)?;
        let nft_store = NftStore::new(&self.db);

        let tokens = nft_store
            .get_owner_tokens(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let token_refs: Vec<NftTokenRef> = tokens
            .iter()
            .map(|(cid, tid)| NftTokenRef {
                collection_id: format!("0x{}", hex::encode(cid)),
                token_id: *tid,
            })
            .collect();

        Ok(NftOwnerTokens {
            owner: addr.to_base58(),
            count: token_refs.len() as u64,
            tokens: token_refs,
        })
    }

    async fn nft_get_tokens_in_collection(
        &self,
        collection_id: String,
    ) -> std::result::Result<Vec<u64>, jsonrpsee::types::ErrorObjectOwned> {
        let collection_bytes = self.parse_collection_id(&collection_id)?;
        let nft_store = NftStore::new(&self.db);

        let tokens = nft_store
            .get_collection_tokens(&collection_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(tokens)
    }

    async fn nft_balance_of(
        &self,
        owner: String,
    ) -> std::result::Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&owner)?;
        let nft_store = NftStore::new(&self.db);

        let count = nft_store
            .get_owner_token_count(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(count)
    }

    async fn nft_owner_of(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> std::result::Result<Option<String>, jsonrpsee::types::ErrorObjectOwned> {
        let collection_bytes = self.parse_collection_id(&collection_id)?;
        let nft_store = NftStore::new(&self.db);

        let token = nft_store
            .get_token(&collection_bytes, token_id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(token.map(|t| t.owner.to_base58()))
    }

    async fn nft_token_exists(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let collection_bytes = self.parse_collection_id(&collection_id)?;
        let nft_store = NftStore::new(&self.db);

        let exists = nft_store
            .token_exists(&collection_bytes, token_id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(exists)
    }

    // ========================================================================
    // SRC-20 Token Endpoints
    // ========================================================================

    async fn token_get_token(
        &self,
        token_id: String,
    ) -> std::result::Result<Option<TokenInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let token_bytes = self.parse_token_id(&token_id)?;
        let token_store = TokenStore::new(&self.db);

        match token_store.get_token(&token_bytes) {
            Ok(Some(data)) => Ok(Some(TokenInfo {
                token_id: format!("0x{}", hex::encode(token_bytes)),
                name: data.name,
                symbol: data.symbol,
                decimals: data.decimals,
                owner: Address::new({
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(data.owner.as_bytes());
                    arr
                }).to_base58(),
                total_supply: data.total_supply.to_string(),
                max_supply: data.max_supply.to_string(),
                mintable: data.mintable,
                burnable: data.burnable,
                pausable: data.pausable,
                paused: data.paused,
                created_at: data.created_at,
                created_at_block: data.created_at_block,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn token_balance_of(
        &self,
        token_id: String,
        owner: String,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let token_bytes = self.parse_token_id(&token_id)?;
        let owner_addr = self.parse_address(&owner)?;

        let token_store = TokenStore::new(&self.db);
        let balance = token_store
            .get_balance(&token_bytes, &owner_addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(balance.to_string())
    }

    async fn token_get_tokens_by_owner(
        &self,
        owner: String,
    ) -> std::result::Result<TokenHoldings, jsonrpsee::types::ErrorObjectOwned> {
        let owner_addr = self.parse_address(&owner)?;

        let token_store = TokenStore::new(&self.db);
        let token_ids = token_store
            .get_holder_tokens(&owner_addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let mut tokens = Vec::new();
        for token_id_vec in &token_ids {
            if token_id_vec.len() != 32 {
                continue;
            }
            let mut token_bytes = [0u8; 32];
            token_bytes.copy_from_slice(token_id_vec);

            if let Ok(Some(token_data)) = token_store.get_token(&token_bytes) {
                if let Ok(balance) = token_store.get_balance(&token_bytes, &owner_addr) {
                    tokens.push(TokenBalance {
                        token_id: format!("0x{}", hex::encode(token_bytes)),
                        symbol: token_data.symbol,
                        decimals: token_data.decimals,
                        balance: balance.to_string(),
                    });
                }
            }
        }

        Ok(TokenHoldings {
            owner: owner_addr.to_base58(),
            count: tokens.len() as u64,
            tokens,
        })
    }

    async fn token_allowance(
        &self,
        token_id: String,
        owner: String,
        spender: String,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let token_bytes = self.parse_token_id(&token_id)?;
        let owner_addr = self.parse_address(&owner)?;
        let spender_addr = self.parse_address(&spender)?;

        let token_store = TokenStore::new(&self.db);
        let allowance = token_store
            .get_allowance(&token_bytes, &owner_addr, &spender_addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(allowance.to_string())
    }

    async fn token_total_supply(
        &self,
        token_id: String,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let token_bytes = self.parse_token_id(&token_id)?;
        let token_store = TokenStore::new(&self.db);

        match token_store.get_token(&token_bytes) {
            Ok(Some(data)) => Ok(data.total_supply.to_string()),
            Ok(None) => Err(RpcError::NotFound("Token not found".to_string()).into()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn token_exists(
        &self,
        token_id: String,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let token_bytes = self.parse_token_id(&token_id)?;
        let token_store = TokenStore::new(&self.db);

        let exists = token_store
            .token_exists(&token_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(exists)
    }

    // ========================================================================
    // Smart Contract (SUMC) Endpoints
    // ========================================================================

    async fn contract_get_contract(
        &self,
        address: String,
    ) -> std::result::Result<Option<ContractInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;

        // Get contract executor if available
        if let Some(ref executor) = self.contract_executor {
            if let Some(metadata) = executor.get_metadata(&addr) {
                let balance = self.state.get_balance(&addr)
                    .map_err(|e| RpcError::Internal(e.to_string()))?;

                return Ok(Some(ContractInfo {
                    address: addr.to_base58(),
                    code_hash: format!("0x{}", hex::encode(metadata.code_hash)),
                    owner: metadata.owner.to_base58(),
                    balance: balance.to_string(),
                    upgradeable: metadata.upgradeable,
                    deployed_at: metadata.deployed_at,
                    deployed_at_block: metadata.deployed_block,
                }));
            }
        }

        Ok(None)
    }

    async fn contract_is_contract(
        &self,
        address: String,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;

        if let Some(ref executor) = self.contract_executor {
            let exists = executor.contract_exists(&addr)
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            return Ok(exists);
        }

        Ok(false)
    }

    async fn contract_call(
        &self,
        request: ViewCallRequest,
    ) -> std::result::Result<ContractCallResult, jsonrpsee::types::ErrorObjectOwned> {
        let contract_addr = self.parse_address(&request.contract)?;
        let from_addr = if let Some(ref from) = request.from {
            Some(self.parse_address(from)?)
        } else {
            None
        };

        let args = hex::decode(request.args.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid args hex: {}", e)))?;

        if let Some(ref executor) = self.contract_executor {
            // Get current block info
            let block_store = BlockStore::new(&self.db);
            let height = block_store.get_latest_height()
                .map_err(|e| RpcError::Internal(e.to_string()))?
                .unwrap_or(0);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            match executor.view_call(
                &contract_addr,
                &request.method,
                args,
                from_addr,
                height,
                timestamp,
                self.state.chain_id(),
            ) {
                Ok(return_data) => {
                    return Ok(ContractCallResult {
                        tx_hash: None,
                        return_data: format!("0x{}", hex::encode(&return_data)),
                        gas_used: 0, // View calls don't consume gas
                        success: true,
                        error: None,
                        events: Vec::new(),
                    });
                }
                Err(e) => {
                    return Ok(ContractCallResult {
                        tx_hash: None,
                        return_data: String::new(),
                        gas_used: 0,
                        success: false,
                        error: Some(e.to_string()),
                        events: Vec::new(),
                    });
                }
            }
        }

        Err(RpcError::Internal("Contract executor not available".to_string()).into())
    }

    async fn contract_estimate_gas(
        &self,
        request: ViewCallRequest,
    ) -> std::result::Result<GasEstimateResult, jsonrpsee::types::ErrorObjectOwned> {
        // For now, return a fixed estimate - in production this would actually run the call
        // and measure gas consumption
        let base_gas: u64 = 21000;
        let per_byte_gas: u64 = 16;

        let args = hex::decode(request.args.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid args hex: {}", e)))?;

        let estimated_gas = base_gas + (args.len() as u64 * per_byte_gas);
        let gas_price: u128 = 1_000_000; // 0.001 Koppa per gas unit
        let total_cost = (estimated_gas as u128) * gas_price;

        Ok(GasEstimateResult {
            gas_estimate: estimated_gas,
            gas_price: gas_price.to_string(),
            total_cost: total_cost.to_string(),
        })
    }

    async fn contract_get_code_hash(
        &self,
        address: String,
    ) -> std::result::Result<Option<String>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;

        if let Some(ref executor) = self.contract_executor {
            if let Some(metadata) = executor.get_metadata(&addr) {
                return Ok(Some(format!("0x{}", hex::encode(metadata.code_hash))));
            }
        }

        Ok(None)
    }

    async fn contract_get_storage_at(
        &self,
        _address: String,
        _key: String,
    ) -> std::result::Result<Option<String>, jsonrpsee::types::ErrorObjectOwned> {
        // Contract storage reading would require direct access to the contract storage backend
        // This is a placeholder implementation
        Err(RpcError::Internal("Storage querying not yet implemented".to_string()).into())
    }

    async fn contract_get_balance(
        &self,
        address: String,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;

        let balance = self.state.get_balance(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(balance.to_string())
    }
}


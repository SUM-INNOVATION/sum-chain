//! RPC server implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use jsonrpsee::server::{Server, ServerHandle};
use sumchain_consensus::ConsensusEngine;
use sumchain_primitives::{Address, Block, Hash, SignedTransaction};
use sumchain_state::{Mempool, StateManager};
use sumchain_storage::{BlockStore, Database, DelegationStore, DocClassStore, MessagingStore, NftStore, ReceiptStore, SlashingStore, StakingStore, TokenStore, TxIndexStore, TxStore, ValidatorSetStore};
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

    /// Parse public key from hex string
    fn parse_pubkey(&self, s: &str) -> Result<[u8; 32]> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid public key: {}", e)))?;
        if bytes.len() != 32 {
            return Err(RpcError::InvalidParams(format!(
                "Invalid public key length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Convert Address (20 bytes) to delegator key format (32 bytes, padded with zeros)
    fn address_to_delegator_key(&self, addr: &Address) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..20].copy_from_slice(addr.as_bytes());
        key
    }

    /// Convert delegator key (32 bytes) back to Address (first 20 bytes)
    fn delegator_key_to_address(&self, key: &[u8; 32]) -> Address {
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&key[..20]);
        Address::new(arr)
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

    // ========================================================================
    // Staking Endpoints
    // ========================================================================

    async fn staking_get_validator(
        &self,
        pubkey: String,
    ) -> std::result::Result<Option<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let pubkey_bytes = self.parse_pubkey(&pubkey)?;
        let staking_store = StakingStore::new(&self.db);

        match staking_store.get_validator(&pubkey_bytes) {
            Ok(Some(validator)) => {
                let address = Address::from_public_key(&validator.pubkey);
                Ok(Some(StakingValidatorInfo {
                    pubkey: format!("0x{}", hex::encode(validator.pubkey)),
                    address: address.to_base58(),
                    stake: validator.stake.to_string(),
                    commission_bps: validator.commission_bps,
                    status: format!("{:?}", validator.status),
                    joined_at: validator.joined_at,
                    jailed_until: validator.jailed_until,
                    slash_count: validator.slash_count,
                    pending_rewards: validator.pending_rewards.to_string(),
                    metadata: if validator.metadata.is_empty() {
                        None
                    } else {
                        String::from_utf8(validator.metadata).ok()
                    },
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn staking_get_validators(
        &self,
    ) -> std::result::Result<Vec<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let staking_store = StakingStore::new(&self.db);

        let validators = staking_store
            .get_all_validators()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(validators
            .into_iter()
            .map(|v| {
                let address = Address::from_public_key(&v.pubkey);
                StakingValidatorInfo {
                    pubkey: format!("0x{}", hex::encode(v.pubkey)),
                    address: address.to_base58(),
                    stake: v.stake.to_string(),
                    commission_bps: v.commission_bps,
                    status: format!("{:?}", v.status),
                    joined_at: v.joined_at,
                    jailed_until: v.jailed_until,
                    slash_count: v.slash_count,
                    pending_rewards: v.pending_rewards.to_string(),
                    metadata: if v.metadata.is_empty() {
                        None
                    } else {
                        String::from_utf8(v.metadata).ok()
                    },
                }
            })
            .collect())
    }

    async fn staking_get_active_validators(
        &self,
    ) -> std::result::Result<Vec<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let staking_store = StakingStore::new(&self.db);

        let validators = staking_store
            .get_active_validators()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(validators
            .into_iter()
            .map(|v| {
                let address = Address::from_public_key(&v.pubkey);
                StakingValidatorInfo {
                    pubkey: format!("0x{}", hex::encode(v.pubkey)),
                    address: address.to_base58(),
                    stake: v.stake.to_string(),
                    commission_bps: v.commission_bps,
                    status: format!("{:?}", v.status),
                    joined_at: v.joined_at,
                    jailed_until: v.jailed_until,
                    slash_count: v.slash_count,
                    pending_rewards: v.pending_rewards.to_string(),
                    metadata: if v.metadata.is_empty() {
                        None
                    } else {
                        String::from_utf8(v.metadata).ok()
                    },
                }
            })
            .collect())
    }

    async fn staking_get_summary(
        &self,
    ) -> std::result::Result<StakingSummary, jsonrpsee::types::ErrorObjectOwned> {
        let staking_store = StakingStore::new(&self.db);

        let all_validators = staking_store
            .get_all_validators()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let active_validators = staking_store
            .get_active_validators()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let total_stake = staking_store
            .get_total_stake()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        // Get staking params from consensus/genesis
        let min_stake = 1_000_000_000_000_000_000u128; // Default 1000 Koppa
        let max_validators = 100u32;
        let unbonding_period = 100_800u64;

        Ok(StakingSummary {
            total_validators: all_validators.len(),
            active_validators: active_validators.len(),
            total_stake: total_stake.to_string(),
            min_validator_stake: min_stake.to_string(),
            max_validators,
            unbonding_period,
        })
    }

    async fn staking_get_params(
        &self,
    ) -> std::result::Result<StakingParamsInfo, jsonrpsee::types::ErrorObjectOwned> {
        // These are the default staking params - in production would come from genesis
        Ok(StakingParamsInfo {
            min_validator_stake: "1000000000000000000".to_string(), // 1000 Koppa
            max_validators: 100,
            unbonding_period: 100_800, // ~7 days
            max_commission_bps: 10000, // 100%
            double_sign_slash_bps: 500, // 5%
            downtime_slash_bps: 10, // 0.1%
            double_sign_jail_duration: 14400, // ~24 hours
            downtime_jail_duration: 2400, // ~4 hours
            downtime_threshold: 500,
        })
    }

    async fn staking_get_total_stake(
        &self,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let staking_store = StakingStore::new(&self.db);

        let total_stake = staking_store
            .get_total_stake()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(total_stake.to_string())
    }

    async fn staking_get_validator_by_address(
        &self,
        address: String,
    ) -> std::result::Result<Option<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let staking_store = StakingStore::new(&self.db);

        // Get all validators and find by address
        let validators = staking_store
            .get_all_validators()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        for v in validators {
            let validator_address = Address::from_public_key(&v.pubkey);
            if validator_address == addr {
                return Ok(Some(StakingValidatorInfo {
                    pubkey: format!("0x{}", hex::encode(v.pubkey)),
                    address: validator_address.to_base58(),
                    stake: v.stake.to_string(),
                    commission_bps: v.commission_bps,
                    status: format!("{:?}", v.status),
                    joined_at: v.joined_at,
                    jailed_until: v.jailed_until,
                    slash_count: v.slash_count,
                    pending_rewards: v.pending_rewards.to_string(),
                    metadata: if v.metadata.is_empty() {
                        None
                    } else {
                        String::from_utf8(v.metadata).ok()
                    },
                }));
            }
        }

        Ok(None)
    }

    // ========================================================================
    // Delegation Endpoints
    // ========================================================================

    async fn delegation_get_delegation(
        &self,
        delegator: String,
        validator_pubkey: String,
    ) -> std::result::Result<Option<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let delegator_addr = self.parse_address(&delegator)?;
        let delegator_key = self.address_to_delegator_key(&delegator_addr);
        let validator_bytes = self.parse_pubkey(&validator_pubkey)?;
        let delegation_store = DelegationStore::new(&self.db);

        match delegation_store.get_delegation(&delegator_key, &validator_bytes) {
            Ok(Some(delegation)) => {
                let validator_address = Address::from_public_key(&delegation.validator_pubkey);
                Ok(Some(DelegationRpcInfo {
                    delegator: delegator_addr.to_base58(),
                    validator_address: validator_address.to_base58(),
                    validator_pubkey: format!("0x{}", hex::encode(delegation.validator_pubkey)),
                    amount: delegation.amount.to_string(),
                    pending_rewards: delegation.pending_rewards.to_string(),
                    delegated_at: delegation.delegated_at,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn delegation_get_delegations_by_delegator(
        &self,
        delegator: String,
    ) -> std::result::Result<Vec<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let delegator_addr = self.parse_address(&delegator)?;
        let delegator_key = self.address_to_delegator_key(&delegator_addr);
        let delegation_store = DelegationStore::new(&self.db);

        let delegations = delegation_store
            .get_delegations_by_delegator(&delegator_key)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(delegations
            .into_iter()
            .map(|d| {
                let validator_address = Address::from_public_key(&d.validator_pubkey);
                let del_addr = self.delegator_key_to_address(&d.delegator);
                DelegationRpcInfo {
                    delegator: del_addr.to_base58(),
                    validator_address: validator_address.to_base58(),
                    validator_pubkey: format!("0x{}", hex::encode(d.validator_pubkey)),
                    amount: d.amount.to_string(),
                    pending_rewards: d.pending_rewards.to_string(),
                    delegated_at: d.delegated_at,
                }
            })
            .collect())
    }

    async fn delegation_get_delegations_by_validator(
        &self,
        validator_pubkey: String,
    ) -> std::result::Result<Vec<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let validator_bytes = self.parse_pubkey(&validator_pubkey)?;
        let delegation_store = DelegationStore::new(&self.db);

        let delegations = delegation_store
            .get_delegations_by_validator(&validator_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let validator_address = Address::from_public_key(&validator_bytes);

        Ok(delegations
            .into_iter()
            .map(|d| {
                let del_addr = self.delegator_key_to_address(&d.delegator);
                DelegationRpcInfo {
                    delegator: del_addr.to_base58(),
                    validator_address: validator_address.to_base58(),
                    validator_pubkey: format!("0x{}", hex::encode(d.validator_pubkey)),
                    amount: d.amount.to_string(),
                    pending_rewards: d.pending_rewards.to_string(),
                    delegated_at: d.delegated_at,
                }
            })
            .collect())
    }

    async fn delegation_get_delegator_summary(
        &self,
        delegator: String,
    ) -> std::result::Result<DelegatorSummary, jsonrpsee::types::ErrorObjectOwned> {
        let delegator_addr = self.parse_address(&delegator)?;
        let delegator_key = self.address_to_delegator_key(&delegator_addr);
        let delegation_store = DelegationStore::new(&self.db);

        let delegations = delegation_store
            .get_delegations_by_delegator(&delegator_key)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let unbondings = delegation_store
            .get_unbondings_by_delegator(&delegator_key)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let total_delegated: u128 = delegations.iter().map(|d| d.amount).sum();
        let total_pending_rewards: u128 = delegations.iter().map(|d| d.pending_rewards).sum();
        let total_unbonding: u128 = unbondings.iter().map(|u| u.amount).sum();

        Ok(DelegatorSummary {
            delegator: delegator_addr.to_base58(),
            total_delegated: total_delegated.to_string(),
            total_pending_rewards: total_pending_rewards.to_string(),
            total_unbonding: total_unbonding.to_string(),
            delegation_count: delegations.len(),
            unbonding_count: unbondings.len(),
        })
    }

    async fn delegation_get_unbonding_delegations(
        &self,
        delegator: String,
    ) -> std::result::Result<Vec<UnbondingDelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let delegator_addr = self.parse_address(&delegator)?;
        let delegator_key = self.address_to_delegator_key(&delegator_addr);
        let delegation_store = DelegationStore::new(&self.db);
        let current_height = self.consensus.current_height();

        let unbondings = delegation_store
            .get_unbondings_by_delegator(&delegator_key)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(unbondings
            .into_iter()
            .map(|u| {
                let validator_address = Address::from_public_key(&u.validator_pubkey);
                let del_addr = self.delegator_key_to_address(&u.delegator);
                UnbondingDelegationRpcInfo {
                    delegator: del_addr.to_base58(),
                    validator_address: validator_address.to_base58(),
                    validator_pubkey: format!("0x{}", hex::encode(u.validator_pubkey)),
                    amount: u.amount.to_string(),
                    completion_height: u.completion_height,
                    is_complete: current_height >= u.completion_height,
                }
            })
            .collect())
    }

    async fn delegation_get_validator_delegation_summary(
        &self,
        validator_pubkey: String,
    ) -> std::result::Result<ValidatorDelegationSummary, jsonrpsee::types::ErrorObjectOwned> {
        let validator_bytes = self.parse_pubkey(&validator_pubkey)?;
        let delegation_store = DelegationStore::new(&self.db);

        let delegations = delegation_store
            .get_delegations_by_validator(&validator_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let total_delegated: u128 = delegations.iter().map(|d| d.amount).sum();
        let validator_address = Address::from_public_key(&validator_bytes);

        Ok(ValidatorDelegationSummary {
            validator_pubkey: format!("0x{}", hex::encode(validator_bytes)),
            validator_address: validator_address.to_base58(),
            total_delegated: total_delegated.to_string(),
            delegator_count: delegations.len(),
        })
    }

    // ========================================================================
    // Slashing Endpoints
    // ========================================================================

    async fn slashing_get_records(
        &self,
        validator_pubkey: String,
    ) -> std::result::Result<Vec<SlashingRecordRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let pubkey_bytes = self.parse_pubkey(&validator_pubkey)?;
        let slashing_store = SlashingStore::new(&self.db);

        let records = slashing_store
            .get_slashing_records(&pubkey_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let validator_address = Address::from_public_key(&pubkey_bytes);

        Ok(records
            .into_iter()
            .map(|r| SlashingRecordRpcInfo {
                validator_pubkey: format!("0x{}", hex::encode(r.validator_pubkey)),
                validator_address: validator_address.to_base58(),
                evidence_type: format!("{:?}", r.evidence_type),
                slashed_at: r.slashed_at,
                validator_slash_amount: r.validator_slash_amount.to_string(),
                delegation_slash_amount: r.delegation_slash_amount.to_string(),
                jailed_until: r.jailed_until,
                tombstoned: r.tombstoned,
                slash_fraction_bps: r.slash_fraction_bps,
            })
            .collect())
    }

    async fn slashing_get_signing_info(
        &self,
        validator_pubkey: String,
    ) -> std::result::Result<Option<ValidatorSigningRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let pubkey_bytes = self.parse_pubkey(&validator_pubkey)?;
        let slashing_store = SlashingStore::new(&self.db);

        match slashing_store.get_signing_info(&pubkey_bytes) {
            Ok(Some(info)) => {
                let validator_address = Address::from_public_key(&pubkey_bytes);
                Ok(Some(ValidatorSigningRpcInfo {
                    validator_pubkey: format!("0x{}", hex::encode(info.validator_pubkey)),
                    validator_address: validator_address.to_base58(),
                    start_height: info.start_height,
                    index_offset: info.index_offset,
                    missed_blocks_counter: info.missed_blocks_counter,
                    tombstoned: info.tombstoned,
                    jailed_until: info.jailed_until,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn slashing_get_all_signing_info(
        &self,
    ) -> std::result::Result<Vec<ValidatorSigningRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let slashing_store = SlashingStore::new(&self.db);

        let all_info = slashing_store
            .get_all_signing_info()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(all_info
            .into_iter()
            .map(|info| {
                let validator_address = Address::from_public_key(&info.validator_pubkey);
                ValidatorSigningRpcInfo {
                    validator_pubkey: format!("0x{}", hex::encode(info.validator_pubkey)),
                    validator_address: validator_address.to_base58(),
                    start_height: info.start_height,
                    index_offset: info.index_offset,
                    missed_blocks_counter: info.missed_blocks_counter,
                    tombstoned: info.tombstoned,
                    jailed_until: info.jailed_until,
                }
            })
            .collect())
    }

    async fn slashing_get_summary(
        &self,
    ) -> std::result::Result<SlashingSummary, jsonrpsee::types::ErrorObjectOwned> {
        let slashing_store = SlashingStore::new(&self.db);
        let staking_store = StakingStore::new(&self.db);

        // Get all slashing records
        let recent_records = slashing_store
            .get_recent_slashing_records(1000) // Get up to 1000 records for summary
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let total_slashing_events = recent_records.len();
        let mut total_validator_slashed: u128 = 0;
        let mut total_delegation_slashed: u128 = 0;

        for record in &recent_records {
            total_validator_slashed += record.validator_slash_amount;
            total_delegation_slashed += record.delegation_slash_amount;
        }

        // Count tombstoned and jailed validators
        let all_signing_info = slashing_store
            .get_all_signing_info()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let tombstoned_count = all_signing_info.iter().filter(|info| info.tombstoned).count();

        // Get jailed count from validators
        let all_validators = staking_store
            .get_all_validators()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let current_height = self.consensus.current_height();
        let jailed_count = all_validators
            .iter()
            .filter(|v| v.jailed_until > current_height)
            .count();

        Ok(SlashingSummary {
            total_slashing_events,
            total_validator_slashed: total_validator_slashed.to_string(),
            total_delegation_slashed: total_delegation_slashed.to_string(),
            tombstoned_count,
            jailed_count,
        })
    }

    async fn slashing_is_tombstoned(
        &self,
        validator_pubkey: String,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let pubkey_bytes = self.parse_pubkey(&validator_pubkey)?;
        let slashing_store = SlashingStore::new(&self.db);

        let is_tombstoned = slashing_store
            .is_tombstoned(&pubkey_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(is_tombstoned)
    }

    async fn slashing_get_recent_records(
        &self,
        limit: u32,
    ) -> std::result::Result<Vec<SlashingRecordRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let slashing_store = SlashingStore::new(&self.db);

        let records = slashing_store
            .get_recent_slashing_records(limit as usize)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(records
            .into_iter()
            .map(|r| {
                let validator_address = Address::from_public_key(&r.validator_pubkey);
                SlashingRecordRpcInfo {
                    validator_pubkey: format!("0x{}", hex::encode(r.validator_pubkey)),
                    validator_address: validator_address.to_base58(),
                    evidence_type: format!("{:?}", r.evidence_type),
                    slashed_at: r.slashed_at,
                    validator_slash_amount: r.validator_slash_amount.to_string(),
                    delegation_slash_amount: r.delegation_slash_amount.to_string(),
                    jailed_until: r.jailed_until,
                    tombstoned: r.tombstoned,
                    slash_fraction_bps: r.slash_fraction_bps,
                }
            })
            .collect())
    }

    // ========================================================================
    // Epoch & Validator Set Endpoints
    // ========================================================================

    async fn epoch_get_info(
        &self,
    ) -> std::result::Result<EpochInfo, jsonrpsee::types::ErrorObjectOwned> {
        let current_height = self.consensus.current_height();

        // Get staking params - use defaults for now
        // In production, this would come from genesis/state
        let epoch_length: u64 = 14400; // ~24 hours at 6s blocks
        let stake_weighted_selection = true;

        let current_epoch = current_height / epoch_length;
        let epoch_start_height = current_epoch * epoch_length;
        let epoch_end_height = epoch_start_height + epoch_length - 1;
        let blocks_remaining = if current_height <= epoch_end_height {
            epoch_end_height - current_height
        } else {
            0
        };

        Ok(EpochInfo {
            current_epoch,
            current_height,
            epoch_length,
            epoch_start_height,
            epoch_end_height,
            blocks_remaining,
            stake_weighted_selection,
        })
    }

    async fn validator_set_get_current(
        &self,
    ) -> std::result::Result<Option<ValidatorSetRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let validator_set_store = ValidatorSetStore::new(&self.db);

        match validator_set_store.get_current_validator_set() {
            Ok(Some(set)) => {
                let total_vp = set.total_voting_power;
                let validators: Vec<ValidatorSetEntryRpcInfo> = set
                    .validators
                    .iter()
                    .map(|v| {
                        let address = Address::from_public_key(&v.pubkey);
                        let power_pct_bps = if total_vp > 0 {
                            ((v.voting_power as u128 * 10000) / total_vp) as u16
                        } else {
                            0
                        };
                        ValidatorSetEntryRpcInfo {
                            pubkey: format!("0x{}", hex::encode(v.pubkey)),
                            address: address.to_base58(),
                            voting_power: v.voting_power.to_string(),
                            commission_bps: v.commission_bps,
                            power_percentage_bps: power_pct_bps,
                        }
                    })
                    .collect();

                Ok(Some(ValidatorSetRpcInfo {
                    epoch: set.epoch,
                    active_from: set.active_from,
                    validators,
                    total_voting_power: total_vp.to_string(),
                    proposer_seed: format!("0x{}", hex::encode(set.proposer_seed)),
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn validator_set_get_by_epoch(
        &self,
        epoch: u64,
    ) -> std::result::Result<Option<ValidatorSetRpcInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let validator_set_store = ValidatorSetStore::new(&self.db);

        match validator_set_store.get_validator_set(epoch) {
            Ok(Some(set)) => {
                let total_vp = set.total_voting_power;
                let validators: Vec<ValidatorSetEntryRpcInfo> = set
                    .validators
                    .iter()
                    .map(|v| {
                        let address = Address::from_public_key(&v.pubkey);
                        let power_pct_bps = if total_vp > 0 {
                            ((v.voting_power as u128 * 10000) / total_vp) as u16
                        } else {
                            0
                        };
                        ValidatorSetEntryRpcInfo {
                            pubkey: format!("0x{}", hex::encode(v.pubkey)),
                            address: address.to_base58(),
                            voting_power: v.voting_power.to_string(),
                            commission_bps: v.commission_bps,
                            power_percentage_bps: power_pct_bps,
                        }
                    })
                    .collect();

                Ok(Some(ValidatorSetRpcInfo {
                    epoch: set.epoch,
                    active_from: set.active_from,
                    validators,
                    total_voting_power: total_vp.to_string(),
                    proposer_seed: format!("0x{}", hex::encode(set.proposer_seed)),
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn validator_set_get_proposer(
        &self,
        height: u64,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let proposer = self.consensus.get_proposer(height);
        let address = Address::from_public_key(&proposer);
        Ok(address.to_base58())
    }

    // ========================================================================
    // SRC-201 Messaging Endpoints Implementation
    // ========================================================================

    async fn messaging_get_config(
        &self,
    ) -> std::result::Result<MessagingConfigInfo, jsonrpsee::types::ErrorObjectOwned> {
        let store = MessagingStore::new(&self.db);
        let daily_quota = store.get_daily_quota().map_err(|e| RpcError::Internal(e.to_string()))?;
        let max_message_size = store.get_max_message_size().map_err(|e| RpcError::Internal(e.to_string()))?;
        let min_trust_stake = store.get_min_trust_stake().map_err(|e| RpcError::Internal(e.to_string()))?;
        let sponsorship_enabled = store.is_sponsorship_enabled().map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(MessagingConfigInfo {
            daily_quota,
            max_message_size,
            min_trust_stake: min_trust_stake.to_string(),
            sponsorship_enabled,
        })
    }

    async fn messaging_get_quota(
        &self,
        address: String,
    ) -> std::result::Result<MessagingQuotaInfo, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = MessagingStore::new(&self.db);
        let base_quota = store.get_daily_quota().map_err(|e| RpcError::Internal(e.to_string()))?;
        let min_trust_stake = store.get_min_trust_stake().map_err(|e| RpcError::Internal(e.to_string()))?;
        let trust_stake = store.get_stake_balance(&addr).map_err(|e| RpcError::Internal(e.to_string()))?;

        // Get today's day number
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let today = (now / 86400) as u32;
        let used_today = store.get_daily_message_count(&addr, today).map_err(|e| RpcError::Internal(e.to_string()))?;

        // Staked senders get 5x quota
        let daily_quota = if trust_stake >= min_trust_stake {
            base_quota.saturating_mul(5)
        } else {
            base_quota
        };

        let remaining = daily_quota.saturating_sub(used_today);

        Ok(MessagingQuotaInfo {
            address: addr.to_base58(),
            daily_quota,
            used_today,
            remaining,
            has_trust_stake: trust_stake >= min_trust_stake,
            trust_stake: if trust_stake > 0 {
                Some(trust_stake.to_string())
            } else {
                None
            },
        })
    }

    async fn messaging_get_inbox_filter(
        &self,
        address: String,
    ) -> std::result::Result<Option<InboxFilterInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        // Compute recipient hash from address
        let recipient_hash = *blake3::hash(addr.as_bytes()).as_bytes();

        let store = MessagingStore::new(&self.db);
        let filter = store.get_inbox_filter(&recipient_hash).map_err(|e| RpcError::Internal(e.to_string()))?;

        let mode = match filter {
            sumchain_primitives::InboxFilter::AcceptAll => "accept_all",
            sumchain_primitives::InboxFilter::ContactsOnly => "contacts_only",
            sumchain_primitives::InboxFilter::StakedOnly => "staked_only",
        };

        Ok(Some(InboxFilterInfo {
            mode: mode.to_string(),
        }))
    }

    async fn messaging_get_messages(
        &self,
        recipient_hash: String,
        limit: Option<u32>,
        _offset: Option<u32>,
    ) -> std::result::Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash_bytes = hex::decode(recipient_hash.strip_prefix("0x").unwrap_or(&recipient_hash))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid recipient hash: {}", e)))?;

        if hash_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Recipient hash must be 32 bytes".to_string()).into());
        }

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash_bytes);

        let store = MessagingStore::new(&self.db);
        // Get messages from block 0 to latest (u64::MAX)
        let events = store
            .get_messages_by_recipient(&hash_arr, 0, u64::MAX, limit.unwrap_or(100) as usize)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let results: Vec<MessageEventInfo> = events
            .into_iter()
            .map(|e| MessageEventInfo {
                tx_hash: format!("0x{}", hex::encode(e.message_id.as_bytes())),
                block_height: e.block_height,
                sender: e.sender.to_base58(),
                recipient_hash: format!("0x{}", hex::encode(e.recipient_hash)),
                content_type: 0, // Not stored in MessageEvent
                flags: 0, // Not stored in MessageEvent
                has_payment: e.has_payment,
                payment_amount: None, // Amount not stored in MessageEvent
            })
            .collect();

        Ok(results)
    }

    async fn messaging_get_sent_messages(
        &self,
        _sender: String,
        _limit: Option<u32>,
        _offset: Option<u32>,
    ) -> std::result::Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned> {
        // Sender-based indexing is not yet implemented in MessagingStore
        // Would require iterating all events which is expensive
        Err(RpcError::Internal("Sender-based message indexing not yet implemented".to_string()).into())
    }

    async fn messaging_get_pending_payment(
        &self,
        message_id: String,
    ) -> std::result::Result<Option<PendingPaymentInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = Hash::from_hex(&message_id)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid message ID: {}", e)))?;

        let store = MessagingStore::new(&self.db);
        match store.get_pending_payment(&hash) {
            Ok(Some(payment)) => Ok(Some(PendingPaymentInfo {
                message_id: format!("0x{}", hex::encode(hash.as_bytes())),
                sender: payment.sender.to_base58(),
                recipient_hash: format!("0x{}", hex::encode(payment.recipient_hash)),
                amount: payment.amount.to_string(),
                expiry: payment.expiry,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn messaging_get_pending_payments(
        &self,
        _recipient: String,
    ) -> std::result::Result<Vec<PendingPaymentInfo>, jsonrpsee::types::ErrorObjectOwned> {
        // Recipient-based pending payment listing is not yet implemented
        // Would require iterating all payments which is expensive
        Err(RpcError::Internal("Pending payment listing not yet implemented".to_string()).into())
    }

    async fn messaging_get_trust_stake(
        &self,
        address: String,
    ) -> std::result::Result<String, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = MessagingStore::new(&self.db);
        let stake = store.get_stake_balance(&addr).map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(stake.to_string())
    }

    async fn messaging_get_spam_score(
        &self,
        address: String,
    ) -> std::result::Result<SpamReportInfo, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = MessagingStore::new(&self.db);
        let spam_score = store.get_spam_score(&addr).map_err(|e| RpcError::Internal(e.to_string()))?;

        // Consider sender restricted if spam score is 50 or higher
        let is_restricted = spam_score >= 50;

        Ok(SpamReportInfo {
            sender: addr.to_base58(),
            spam_score,
            report_count: 0, // Not tracked separately in current implementation
            is_restricted,
        })
    }

    async fn messaging_is_contact(
        &self,
        owner: String,
        contact: String,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let owner_addr = Address::from_base58(&owner)
            .or_else(|_| Address::from_hex(&owner))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid owner address: {}", e)))?;

        let contact_addr = Address::from_base58(&contact)
            .or_else(|_| Address::from_hex(&contact))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid contact address: {}", e)))?;

        // Compute hashes
        let owner_hash = *blake3::hash(owner_addr.as_bytes()).as_bytes();
        let contact_hash = *blake3::hash(contact_addr.as_bytes()).as_bytes();

        let store = MessagingStore::new(&self.db);
        store
            .is_contact(&owner_hash, &contact_hash)
            .map_err(|e| RpcError::Internal(e.to_string()).into())
    }

    async fn messaging_is_blocked(
        &self,
        owner: String,
        sender: String,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let owner_addr = Address::from_base58(&owner)
            .or_else(|_| Address::from_hex(&owner))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid owner address: {}", e)))?;

        let sender_addr = Address::from_base58(&sender)
            .or_else(|_| Address::from_hex(&sender))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid sender address: {}", e)))?;

        // Compute owner hash
        let owner_hash = *blake3::hash(owner_addr.as_bytes()).as_bytes();

        let store = MessagingStore::new(&self.db);
        store
            .is_blocked(&owner_hash, &sender_addr)
            .map_err(|e| RpcError::Internal(e.to_string()).into())
    }

    async fn messaging_submit_sponsored(
        &self,
        _request: SubmitSponsoredMessageRequest,
    ) -> std::result::Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned> {
        // Sponsored message submission requires a relay service
        // For now, return an error indicating this endpoint requires additional setup
        Err(RpcError::Internal(
            "Sponsored message submission requires a relay service configuration".to_string(),
        )
        .into())
    }

    async fn account_get_public_key(
        &self,
        address: String,
    ) -> std::result::Result<Option<PublicKeyInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = MessagingStore::new(&self.db);
        match store.get_public_key(&addr) {
            Ok(Some(key)) => Ok(Some(PublicKeyInfo {
                public_key: format!("0x{}", hex::encode(key.public_key)),
                address: key.address.to_base58(),
                registered_at_block: key.registered_at_block,
                registered_at: key.registered_at,
                updated_at_block: key.updated_at_block,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    // ========================================================================
    // SRC-80X/81X DocClass Endpoints
    // ========================================================================

    async fn docclass_get_config(
        &self,
    ) -> std::result::Result<DocClassConfigInfo, jsonrpsee::types::ErrorObjectOwned> {
        // Return DocClass configuration from genesis params
        // This is a simplified implementation - in production would read from chain state
        Ok(DocClassConfigInfo {
            min_issuer_stake: "1000000000000".to_string(), // 1000 SUM
            require_issuer_stake: true,
            max_credential_validity: 315360000, // 10 years in seconds
            admin: None,
        })
    }

    async fn docclass_get_summary(
        &self,
    ) -> std::result::Result<DocClassSummary, jsonrpsee::types::ErrorObjectOwned> {
        let store = DocClassStore::new(&self.db);

        // Count issuers (has get_all method)
        let total_issuers = store
            .issuers()
            .get_all()
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .len() as u64;

        // Note: Identity/credential/revocation counts would require full iteration
        // For now, return placeholder values - in production would add count methods to stores
        Ok(DocClassSummary {
            total_identities: 0, // Would need to iterate DOCCLASS_IDENTITY_ROOTS
            total_credentials: 0, // Would need to iterate DOCCLASS_CREDENTIALS + DOCCLASS_ELIGIBILITY
            total_issuers,
            total_revocations: 0, // Would need to iterate DOCCLASS_REVOCATIONS
        })
    }

    async fn docclass_get_identity(
        &self,
        identity_id: String,
    ) -> std::result::Result<Option<DocClassIdentityInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id_bytes: [u8; 32] = hex::decode(identity_id.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid identity ID hex: {}", e)))?
            .try_into()
            .map_err(|_| RpcError::InvalidParams("Identity ID must be 32 bytes".to_string()))?;

        let store = DocClassStore::new(&self.db);
        let identity = store
            .identity_roots()
            .get(&id_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(identity.map(|i| self.identity_to_rpc_info(&i)))
    }

    async fn docclass_get_identity_by_controller(
        &self,
        controller: String,
    ) -> std::result::Result<Option<DocClassIdentityInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&controller)
            .or_else(|_| Address::from_hex(&controller))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid controller address: {}", e)))?;

        let store = DocClassStore::new(&self.db);
        let identities = store
            .identity_roots()
            .get_by_controller(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        // Return the first identity found for this controller
        Ok(identities.into_iter().next().map(|i| self.identity_to_rpc_info(&i)))
    }

    async fn docclass_get_credential(
        &self,
        credential_id: String,
    ) -> std::result::Result<Option<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id_bytes: [u8; 32] = hex::decode(credential_id.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid credential ID hex: {}", e)))?
            .try_into()
            .map_err(|_| RpcError::InvalidParams("Credential ID must be 32 bytes".to_string()))?;

        let store = DocClassStore::new(&self.db);

        // Try eligibility first
        if let Some(eligibility) = store
            .eligibility()
            .get(&id_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            return Ok(Some(self.eligibility_to_rpc_info(&eligibility)));
        }

        // Try academic credential
        if let Some(credential) = store
            .credentials()
            .get(&id_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            return Ok(Some(self.academic_to_rpc_info(&credential)));
        }

        Ok(None)
    }

    async fn docclass_get_credentials_by_subject(
        &self,
        subject_commitment: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> std::result::Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let commitment_bytes: [u8; 32] = hex::decode(subject_commitment.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid subject commitment hex: {}", e)))?
            .try_into()
            .map_err(|_| RpcError::InvalidParams("Subject commitment must be 32 bytes".to_string()))?;

        let store = DocClassStore::new(&self.db);
        let limit = limit.unwrap_or(100) as usize;
        let offset = offset.unwrap_or(0) as usize;

        let mut results = Vec::new();

        // Get eligibility attestations by subject
        let eligibilities = store
            .eligibility()
            .get_by_subject(&commitment_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        for eligibility in eligibilities {
            results.push(self.eligibility_to_rpc_info(&eligibility));
        }

        // Get academic credentials by subject
        let credentials = store
            .credentials()
            .get_by_subject(&commitment_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        for credential in credentials {
            results.push(self.academic_to_rpc_info(&credential));
        }

        // Apply pagination
        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn docclass_get_credentials_by_issuer(
        &self,
        issuer: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> std::result::Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&issuer)
            .or_else(|_| Address::from_hex(&issuer))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid issuer address: {}", e)))?;

        let store = DocClassStore::new(&self.db);
        let limit = limit.unwrap_or(100) as usize;
        let offset = offset.unwrap_or(0) as usize;

        let mut results = Vec::new();

        // Get eligibility attestations by issuer
        let eligibilities = store
            .eligibility()
            .get_by_issuer(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        for eligibility in eligibilities {
            results.push(self.eligibility_to_rpc_info(&eligibility));
        }

        // Get academic credentials by issuer
        let credentials = store
            .credentials()
            .get_by_issuer(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        for credential in credentials {
            results.push(self.academic_to_rpc_info(&credential));
        }

        // Apply pagination
        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn docclass_is_credential_valid(
        &self,
        credential_id: String,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let id_bytes: [u8; 32] = hex::decode(credential_id.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid credential ID hex: {}", e)))?
            .try_into()
            .map_err(|_| RpcError::InvalidParams("Credential ID must be 32 bytes".to_string()))?;

        let store = DocClassStore::new(&self.db);

        // Check if revoked via revocation store
        if store
            .revocations()
            .is_revoked(&id_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            return Ok(false);
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Check eligibility attestation
        if let Some(eligibility) = store
            .eligibility()
            .get(&id_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            // Check revocation status
            if !eligibility.revocation_status.is_valid() {
                return Ok(false);
            }
            // Check expiry
            if eligibility.expires_at > 0 && eligibility.expires_at < current_time {
                return Ok(false);
            }
            return Ok(true);
        }

        // Check academic credential
        if let Some(credential) = store
            .credentials()
            .get(&id_bytes)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            // Check revocation status
            if !credential.revocation_status.is_valid() {
                return Ok(false);
            }
            // Check expiry
            if credential.expires_at > 0 && credential.expires_at < current_time {
                return Ok(false);
            }
            return Ok(true);
        }

        // Credential not found
        Ok(false)
    }

    async fn docclass_get_issuer(
        &self,
        address: String,
    ) -> std::result::Result<Option<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = DocClassStore::new(&self.db);
        let issuer = store
            .issuers()
            .get(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(issuer.map(|i| self.issuer_to_rpc_info(&i)))
    }

    async fn docclass_get_issuers(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> std::result::Result<Vec<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = DocClassStore::new(&self.db);
        let limit = limit.unwrap_or(100) as usize;
        let offset = offset.unwrap_or(0) as usize;

        let issuers = store
            .issuers()
            .get_all()
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|i| self.issuer_to_rpc_info(&i))
            .collect();

        Ok(issuers)
    }

    async fn docclass_get_issuers_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> std::result::Result<Vec<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = DocClassStore::new(&self.db);

        let issuers = store
            .issuers()
            .get_by_jurisdiction(&jurisdiction)
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .into_iter()
            .map(|i| self.issuer_to_rpc_info(&i))
            .collect();

        Ok(issuers)
    }

    async fn docclass_can_issue(
        &self,
        issuer: String,
        subcode: u16,
        jurisdiction: String,
    ) -> std::result::Result<bool, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&issuer)
            .or_else(|_| Address::from_hex(&issuer))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid issuer address: {}", e)))?;

        let doc_subcode = sumchain_primitives::DocSubcode::from_u16(subcode)
            .ok_or_else(|| RpcError::InvalidParams(format!("Invalid subcode: {}", subcode)))?;

        let store = DocClassStore::new(&self.db);
        store
            .issuers()
            .can_issue_subcode(&addr, doc_subcode, &jurisdiction)
            .map_err(|e| RpcError::Internal(e.to_string()).into())
    }

    // ========================================================================
    // Transaction History Endpoints Implementation
    // ========================================================================

    async fn sum_get_transactions_by_address(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> std::result::Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let limit = limit.unwrap_or(50).min(100) as usize;
        let offset = offset.unwrap_or(0);

        let tx_index_store = TxIndexStore::new(&self.db);
        let (entries, has_more) = tx_index_store
            .get_transactions_by_address(&addr, None, limit + 1)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let tx_store = TxStore::new(&self.db);
        let block_store = BlockStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);

        let mut transactions = Vec::new();
        for entry in entries.into_iter().skip(offset as usize).take(limit) {
            if let Ok(Some(tx)) = tx_store.get(&entry.tx_hash) {
                let status = receipt_store
                    .get(&entry.tx_hash)
                    .ok()
                    .flatten()
                    .map(|r| format!("{:?}", r.status))
                    .unwrap_or_else(|| "unknown".to_string());

                let timestamp = block_store
                    .get_by_height(entry.block_height)
                    .ok()
                    .flatten()
                    .map(|b| b.header.timestamp)
                    .unwrap_or(0);

                transactions.push(TransactionHistoryEntry {
                    tx_hash: entry.tx_hash.to_hex(),
                    block_height: entry.block_height,
                    tx_index: entry.tx_index,
                    from: tx.sender().to_base58(),
                    to: tx.recipient().map(|a| a.to_base58()).unwrap_or_default(),
                    amount: tx.amount().to_string(),
                    fee: tx.fee().to_string(),
                    status,
                    timestamp,
                });
            }
        }

        let total_count = tx_index_store
            .get_transaction_count(&addr)
            .unwrap_or(0);

        Ok(TransactionHistoryResponse {
            address: addr.to_base58(),
            transactions,
            total_count,
            has_more,
            offset,
            limit: limit as u32,
        })
    }

    async fn sum_get_transactions_by_sender(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> std::result::Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let limit = limit.unwrap_or(50).min(100) as usize;
        let offset = offset.unwrap_or(0);

        let tx_index_store = TxIndexStore::new(&self.db);
        let (entries, has_more) = tx_index_store
            .get_transactions_by_sender(&addr, None, limit + 1)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let tx_store = TxStore::new(&self.db);
        let block_store = BlockStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);

        let mut transactions = Vec::new();
        for entry in entries.into_iter().skip(offset as usize).take(limit) {
            if let Ok(Some(tx)) = tx_store.get(&entry.tx_hash) {
                let status = receipt_store
                    .get(&entry.tx_hash)
                    .ok()
                    .flatten()
                    .map(|r| format!("{:?}", r.status))
                    .unwrap_or_else(|| "unknown".to_string());

                let timestamp = block_store
                    .get_by_height(entry.block_height)
                    .ok()
                    .flatten()
                    .map(|b| b.header.timestamp)
                    .unwrap_or(0);

                transactions.push(TransactionHistoryEntry {
                    tx_hash: entry.tx_hash.to_hex(),
                    block_height: entry.block_height,
                    tx_index: entry.tx_index,
                    from: tx.sender().to_base58(),
                    to: tx.recipient().map(|a| a.to_base58()).unwrap_or_default(),
                    amount: tx.amount().to_string(),
                    fee: tx.fee().to_string(),
                    status,
                    timestamp,
                });
            }
        }

        Ok(TransactionHistoryResponse {
            address: addr.to_base58(),
            transactions,
            total_count: 0, // Not computed for sender-only queries
            has_more,
            offset,
            limit: limit as u32,
        })
    }

    async fn sum_get_transactions_by_recipient(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> std::result::Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let limit = limit.unwrap_or(50).min(100) as usize;
        let offset = offset.unwrap_or(0);

        let tx_index_store = TxIndexStore::new(&self.db);
        let (entries, has_more) = tx_index_store
            .get_transactions_by_recipient(&addr, None, limit + 1)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let tx_store = TxStore::new(&self.db);
        let block_store = BlockStore::new(&self.db);
        let receipt_store = ReceiptStore::new(&self.db);

        let mut transactions = Vec::new();
        for entry in entries.into_iter().skip(offset as usize).take(limit) {
            if let Ok(Some(tx)) = tx_store.get(&entry.tx_hash) {
                let status = receipt_store
                    .get(&entry.tx_hash)
                    .ok()
                    .flatten()
                    .map(|r| format!("{:?}", r.status))
                    .unwrap_or_else(|| "unknown".to_string());

                let timestamp = block_store
                    .get_by_height(entry.block_height)
                    .ok()
                    .flatten()
                    .map(|b| b.header.timestamp)
                    .unwrap_or(0);

                transactions.push(TransactionHistoryEntry {
                    tx_hash: entry.tx_hash.to_hex(),
                    block_height: entry.block_height,
                    tx_index: entry.tx_index,
                    from: tx.sender().to_base58(),
                    to: tx.recipient().map(|a| a.to_base58()).unwrap_or_default(),
                    amount: tx.amount().to_string(),
                    fee: tx.fee().to_string(),
                    status,
                    timestamp,
                });
            }
        }

        Ok(TransactionHistoryResponse {
            address: addr.to_base58(),
            transactions,
            total_count: 0, // Not computed for recipient-only queries
            has_more,
            offset,
            limit: limit as u32,
        })
    }

    async fn sum_get_transaction_count(
        &self,
        address: String,
    ) -> std::result::Result<u64, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&address)
            .or_else(|_| Address::from_hex(&address))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let tx_index_store = TxIndexStore::new(&self.db);
        tx_index_store
            .get_transaction_count(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()).into())
    }
}

// Helper methods for DocClass RPC conversions
impl RpcServer {
    fn identity_to_rpc_info(&self, identity: &sumchain_primitives::IdentityRoot) -> DocClassIdentityInfo {
        DocClassIdentityInfo {
            identity_id: hex::encode(identity.identity_id),
            subject_commitment: hex::encode(identity.subject_commitment),
            controller: identity.controller.to_base58(),
            additional_controllers: identity.additional_controllers.iter().map(|c| c.to_base58()).collect(),
            keys: identity.keys.iter().map(|k| DocClassKeyInfo {
                key_id: k.key_id.clone(),
                key_type: format!("{:?}", k.key_type),
                public_key: hex::encode(k.public_key),
                purposes: k.purposes.iter().map(|p| format!("{:?}", p)).collect(),
                added_at: k.added_at,
                expires_at: k.expires_at,
                active: k.active,
            }).collect(),
            services: identity.services.iter().map(|s| DocClassServiceInfo {
                service_id: s.service_id.clone(),
                service_type: s.service_type.clone(),
                endpoint: s.endpoint.clone(),
                description: s.description.clone(),
            }).collect(),
            created_at: identity.created_at,
            updated_at: identity.updated_at,
            status: format!("{:?}", identity.status),
        }
    }

    fn eligibility_to_rpc_info(&self, eligibility: &sumchain_primitives::EligibilityAttestation) -> DocClassCredentialInfo {
        DocClassCredentialInfo {
            credential_id: hex::encode(eligibility.credential_id),
            subcode: eligibility.subcode.as_u16(),
            subcode_name: eligibility.subcode.name().to_string(),
            subject_commitment: hex::encode(eligibility.subject_commitment),
            issuer: eligibility.issuer.to_base58(),
            jurisdiction: eligibility.jurisdiction.clone(),
            schema_hash: hex::encode(eligibility.schema_hash),
            content_commitment: hex::encode(eligibility.content_commitment),
            issued_at: eligibility.issued_at,
            valid_from: eligibility.valid_from,
            expires_at: eligibility.expires_at,
            revocation_status: format!("{:?}", eligibility.revocation_status),
            superseded_by: eligibility.superseded_by.map(|id| hex::encode(id)),
            metadata: None,
        }
    }

    fn academic_to_rpc_info(&self, credential: &sumchain_primitives::AcademicCredential) -> DocClassCredentialInfo {
        DocClassCredentialInfo {
            credential_id: hex::encode(credential.credential_id),
            subcode: credential.subcode.as_u16(),
            subcode_name: credential.subcode.name().to_string(),
            subject_commitment: hex::encode(credential.subject_commitment),
            issuer: credential.issuer.to_base58(),
            jurisdiction: credential.jurisdiction.clone(),
            schema_hash: hex::encode(credential.schema_hash),
            content_commitment: hex::encode(credential.content_commitment),
            issued_at: credential.issued_at,
            valid_from: credential.valid_from,
            expires_at: credential.expires_at,
            revocation_status: format!("{:?}", credential.revocation_status),
            superseded_by: credential.superseded_by.map(|id| hex::encode(id)),
            metadata: Some(DocClassCredentialMetadata {
                title: credential.metadata.title.clone(),
                credential_type: credential.metadata.credential_type.clone(),
                program: credential.metadata.program.clone(),
                issue_date: credential.metadata.issue_date.clone(),
                completion_date: credential.metadata.completion_date.clone(),
            }),
        }
    }

    fn issuer_to_rpc_info(&self, issuer: &sumchain_primitives::DocClassIssuer) -> DocClassIssuerInfo {
        DocClassIssuerInfo {
            address: issuer.address.to_base58(),
            name: issuer.name.clone(),
            issuer_type: format!("{:?}", issuer.issuer_type),
            jurisdictions: issuer.jurisdictions.clone(),
            authorized_subcodes: issuer.authorized_subcodes.iter().map(|s| s.as_u16()).collect(),
            keys: issuer.keys.iter().map(|k| DocClassIssuerKeyInfo {
                key_id: k.key_id.clone(),
                public_key: hex::encode(k.public_key),
                key_type: format!("{:?}", k.key_type),
                added_at: k.added_at,
                expires_at: k.expires_at,
                active: k.active,
                is_primary: k.is_primary,
            }).collect(),
            registered_at: issuer.registered_at,
            updated_at: issuer.updated_at,
            status: format!("{:?}", issuer.status),
            stake_amount: issuer.stake_amount.to_string(),
        }
    }
}


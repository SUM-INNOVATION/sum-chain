//! RPC server implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use jsonrpsee::server::{Server, ServerHandle};
use sumchain_consensus::ConsensusEngine;
use sumchain_primitives::{Address, Block, Hash, SignedTransaction, MessagingTxData, MessagingOperation, SponsoredMessage, TxPayload};
use sumchain_state::{Mempool, StateManager};
use sumchain_storage::{BlockStore, Database, DelegationStore, DocClassStore, EmploymentCredentialStore, EmploymentIssuerStore, IncomeAttestationStore, MessagingStore, NftStore, ReceiptStore, SlashingStore, StakingStore, TokenStore, TxIndexStore, TxStore, ValidatorSetStore};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::api::SumChainApiServer;
use crate::auth::{ApiKeyValidator, RpcAuthConfig};
use crate::health::HealthCheck;
use crate::metrics::{Metrics, MetricsSnapshot};
use crate::policy_account_types::*;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::types::*;
use crate::{RpcError, Result};

/// Node version constant
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Classify a transaction's status given its receipt (if any), mempool presence,
/// and a finality check. Pure function — extracted from `chain_get_transaction_status`
/// to make the dispatch logic testable without a full RPC server harness.
pub(crate) fn classify_tx_status(
    receipt: Option<&sumchain_primitives::Receipt>,
    in_mempool: bool,
    is_finalized: impl Fn(sumchain_primitives::BlockHeight) -> bool,
) -> TxStatusV2 {
    if let Some(receipt) = receipt {
        return if receipt.is_success() {
            if is_finalized(receipt.block_height) {
                TxStatusV2::Finalized { block_height: receipt.block_height }
            } else {
                TxStatusV2::Included { block_height: receipt.block_height }
            }
        } else {
            TxStatusV2::Failed {
                block_height: Some(receipt.block_height),
                reason: receipt.status.description().to_string(),
            }
        };
    }
    if in_mempool {
        TxStatusV2::Pending
    } else {
        TxStatusV2::Unknown
    }
}

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
    /// Consensus chain parameters. Read by RPCs that need to compute against
    /// consensus values (e.g. SNIP V2 `assignment_replication_factor` for
    /// `storage_getAssignmentCoverageV2`). Defaults to `ChainParams::default()`;
    /// production callers MUST set via `with_chain_params` to match the chain
    /// they're serving.
    chain_params: sumchain_genesis::ChainParams,
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
            chain_params: sumchain_genesis::ChainParams::default(),
        }
    }

    /// Set the consensus chain parameters this server should reference for
    /// RPCs that depend on consensus values (currently:
    /// `storage_getAssignmentCoverageV2` reads `assignment_replication_factor`).
    /// Production callers MUST call this with the same `ChainParams` the
    /// chain is running, otherwise the RPC's reported `assigned_count` per
    /// archive will disagree with `AcceptAssignmentV2` validity.
    pub fn with_chain_params(mut self, params: sumchain_genesis::ChainParams) -> Self {
        self.chain_params = params;
        self
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
                // Address is the 20-byte derived address
                let address = Address::from_public_key(pubkey);
                // Public key displayed as base58 (same format as in genesis)
                ValidatorInfo {
                    public_key: bs58::encode(pubkey).into_string(),
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

    async fn chain_get_chain_params(
        &self,
    ) -> std::result::Result<ChainParamsInfo, jsonrpsee::types::ErrorObjectOwned> {
        // Read from the live ChainParams plumbed into RpcServer at construction
        // (Phase 1b: `with_chain_params(self.genesis.params.clone())`). Do NOT
        // call `ChainParams::default()` here — that would silently disagree
        // with the chain's actual config on any non-default setting.
        let p = &self.chain_params;
        Ok(ChainParamsInfo {
            chain_id: self.state.chain_id(),
            block_time_ms: p.block_time_ms,
            max_block_bytes: p.max_block_bytes,
            max_txs_per_block: p.max_txs_per_block,
            min_fee: p.min_fee,
            finality_depth: p.finality_depth,
            storage_fee_per_byte: p.storage_fee_per_byte,
            max_metadata_bytes: p.max_metadata_bytes,
            max_access_list_bytes: p.max_access_list_bytes,
            activation_grace_blocks: p.activation_grace_blocks,
            abandonment_fee_percent: p.abandonment_fee_percent,
            max_chunk_count_per_file: p.max_chunk_count_per_file,
            max_chunk_indices_per_tx: p.max_chunk_indices_per_tx,
            assignment_replication_factor: p.assignment_replication_factor,
            v2_enabled_from_height: p.v2_enabled_from_height,
        })
    }

    async fn chain_get_block_height(
        &self,
        finality: Option<String>,
    ) -> std::result::Result<BlockHeightInfo, jsonrpsee::types::ErrorObjectOwned> {
        // Default to latest; "finalized" returns the depth-aware finalized head.
        match finality.as_deref() {
            Some("finalized") => Ok(BlockHeightInfo {
                height: self.consensus.finalized_height(),
                finality: "finalized".to_string(),
            }),
            None | Some("latest") => Ok(BlockHeightInfo {
                height: self.consensus.current_height(),
                finality: "latest".to_string(),
            }),
            Some(other) => Err(RpcError::InvalidParams(format!(
                "finality must be \"latest\" or \"finalized\", got {:?}",
                other
            ))
            .into()),
        }
    }

    async fn chain_get_transaction_status(
        &self,
        tx_hash: String,
    ) -> std::result::Result<TxStatusV2, jsonrpsee::types::ErrorObjectOwned> {
        let hash = self.parse_hash(&tx_hash)?;

        let receipt = ReceiptStore::new(&self.db)
            .get(&hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        let in_mempool = self.mempool.get(&hash).is_some();

        Ok(classify_tx_status(receipt.as_ref(), in_mempool, |h| {
            self.consensus.is_finalized(h)
        }))
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

    async fn messaging_get_message_by_tx_hash(
        &self,
        tx_hash: String,
    ) -> std::result::Result<Option<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash_bytes = hex::decode(tx_hash.strip_prefix("0x").unwrap_or(&tx_hash))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid tx hash: {}", e)))?;

        if hash_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Tx hash must be 32 bytes".to_string()).into());
        }

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&hash_bytes);

        let store = MessagingStore::new(&self.db);
        match store.get_message_by_tx_hash(&hash_arr) {
            Ok(Some(event)) => Ok(Some(MessageEventInfo {
                tx_hash: format!("0x{}", hex::encode(event.message_id.as_bytes())),
                block_height: event.block_height,
                sender: event.sender.to_base58(),
                recipient_hash: format!("0x{}", hex::encode(event.recipient_hash)),
                content_type: 0,
                flags: 0,
                has_payment: event.has_payment,
                payment_amount: None,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn messaging_get_messages_in_block(
        &self,
        block_height: u64,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = MessagingStore::new(&self.db);
        let events = store
            .get_messages_in_block(block_height, limit.unwrap_or(100) as usize)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let results: Vec<MessageEventInfo> = events
            .into_iter()
            .map(|e| MessageEventInfo {
                tx_hash: format!("0x{}", hex::encode(e.message_id.as_bytes())),
                block_height: e.block_height,
                sender: e.sender.to_base58(),
                recipient_hash: format!("0x{}", hex::encode(e.recipient_hash)),
                content_type: 0,
                flags: 0,
                has_payment: e.has_payment,
                payment_amount: None,
            })
            .collect();

        Ok(results)
    }

    async fn messaging_get_message_data(
        &self,
        tx_hash: String,
    ) -> std::result::Result<Option<MessageDataInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = Hash::from_hex(&tx_hash)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid tx hash: {}", e)))?;

        // Get the transaction from storage
        let tx_store = TxStore::new(&self.db);
        let tx = match tx_store.get(&hash) {
            Ok(Some(tx)) => tx,
            Ok(None) => return Ok(None),
            Err(e) => return Err(RpcError::Internal(e.to_string()).into()),
        };

        // Get the receipt to find block height
        let receipt_store = ReceiptStore::new(&self.db);
        let block_height = match receipt_store.get(&hash) {
            Ok(Some(receipt)) => receipt.block_height,
            Ok(None) => 0,
            Err(_) => 0,
        };

        // Extract the payload from the transaction
        let payload = match &tx.inner {
            sumchain_primitives::TxInner::V2(tx_v2) => &tx_v2.payload,
            _ => return Err(RpcError::InvalidParams("Not a V2 transaction".to_string()).into()),
        };

        // Check if this is a messaging transaction
        let messaging_data = match payload {
            TxPayload::Messaging(data) => data,
            _ => return Err(RpcError::InvalidParams("Not a messaging transaction".to_string()).into()),
        };

        // Check if this is a SendMessage (sponsored) operation
        if messaging_data.operation != MessagingOperation::SendMessage {
            return Err(RpcError::InvalidParams("Not a sponsored message transaction".to_string()).into());
        }

        // Deserialize the SponsoredMessage from the data
        let sponsored_msg: SponsoredMessage = bincode::deserialize(&messaging_data.data)
            .map_err(|e| RpcError::Internal(format!("Failed to deserialize message: {}", e)))?;

        // Derive sender address from public key
        let sender = Address::from_public_key(&sponsored_msg.sender_pubkey);

        Ok(Some(MessageDataInfo {
            tx_hash: format!("0x{}", hex::encode(hash.as_bytes())),
            block_height,
            sender: sender.to_base58(),
            recipient_hash: format!("0x{}", hex::encode(sponsored_msg.recipient_hash)),
            message_data: format!("0x{}", hex::encode(&sponsored_msg.message_data)),
            sender_pubkey: format!("0x{}", hex::encode(sponsored_msg.sender_pubkey)),
            has_payment: sponsored_msg.koppa_amount.is_some(),
            payment_amount: sponsored_msg.koppa_amount.map(|a| a.to_string()),
        }))
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
        request: SubmitSponsoredMessageRequest,
    ) -> std::result::Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::{MessagingOperation, MessagingTxData, SponsoredMessage, TransactionV2};

        // Load sponsor keypair from environment variable or default path
        let sponsor_key_path = std::env::var("SUMAIL_SPONSOR_KEY")
            .unwrap_or_else(|_| "keys/sumail.json".to_string());

        let key_json = std::fs::read_to_string(&sponsor_key_path)
            .map_err(|e| RpcError::Internal(format!(
                "Sponsor key not configured. Set SUMAIL_SPONSOR_KEY env var or place key at keys/sumail.json: {}", e
            )))?;

        let key_bytes: [u8; 32] = serde_json::from_str(&key_json)
            .map_err(|e| RpcError::Internal(format!("Invalid sponsor key format: {}", e)))?;

        let sponsor_keypair = sumchain_crypto::KeyPair::from_bytes(key_bytes);

        // Parse sender's public key
        let sender_pubkey_hex = request.sender_pubkey.strip_prefix("0x").unwrap_or(&request.sender_pubkey);
        let sender_pubkey_bytes = hex::decode(sender_pubkey_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid sender pubkey hex: {}", e)))?;

        if sender_pubkey_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Sender pubkey must be 32 bytes".to_string()).into());
        }

        let mut sender_pubkey: [u8; 32] = [0u8; 32];
        sender_pubkey.copy_from_slice(&sender_pubkey_bytes);

        // Derive sender address from public key
        let sender_address = Address::from_public_key(&sender_pubkey);

        // Verify sender has registered their public key
        let store = MessagingStore::new(&self.db);
        if !store.has_public_key(&sender_address).unwrap_or(false) {
            return Err(RpcError::InvalidParams(
                "Sender must register public key first via messaging_registerSponsored".to_string()
            ).into());
        }

        // Parse signature
        let sig_hex = request.signature.strip_prefix("0x").unwrap_or(&request.signature);
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid signature hex: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(RpcError::InvalidParams("Signature must be 64 bytes".to_string()).into());
        }

        let mut sig_array: [u8; 64] = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);

        // Parse message data
        let message_data_hex = request.message_data.strip_prefix("0x").unwrap_or(&request.message_data);
        let message_data = hex::decode(message_data_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid message data hex: {}", e)))?;

        // Parse recipient hash
        let recipient_hash_hex = request.recipient_hash.strip_prefix("0x").unwrap_or(&request.recipient_hash);
        let recipient_hash_bytes = hex::decode(recipient_hash_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid recipient hash hex: {}", e)))?;

        if recipient_hash_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Recipient hash must be 32 bytes".to_string()).into());
        }

        let mut recipient_hash: [u8; 32] = [0u8; 32];
        recipient_hash.copy_from_slice(&recipient_hash_bytes);

        // Verify the sender's signature over the sponsored message request
        // Format: "SUMCHAIN_SPONSORED_MSG:{nonce}:{expiry}:{recipient_hash}:{message_data_hash}"
        let message_data_hash = blake3::hash(&message_data);
        let sign_message = format!(
            "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
            request.nonce,
            request.expiry,
            recipient_hash_hex,
            hex::encode(message_data_hash.as_bytes())
        );

        if sumchain_crypto::verify_bytes(sign_message.as_bytes(), &sig_array, &sender_pubkey).is_err() {
            return Err(RpcError::InvalidParams("Invalid sender signature".to_string()).into());
        }

        // Check expiry
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if request.expiry < now {
            return Err(RpcError::InvalidParams("Sponsored message request has expired".to_string()).into());
        }

        // Parse optional koppa amount
        let koppa_amount = if let Some(ref amount_str) = request.koppa_amount {
            let amount: u128 = amount_str.parse()
                .map_err(|_| RpcError::InvalidParams("Invalid koppa_amount format".to_string()))?;
            if amount > 0 { Some(amount) } else { None }
        } else {
            None
        };

        // Build the SponsoredMessage structure (includes sender_pubkey for executor to derive real sender)
        let sponsored_msg = SponsoredMessage {
            message_data,
            recipient_hash,
            signature: sig_array,
            sender_pubkey,
            nonce: request.nonce,
            expiry: request.expiry,
            koppa_amount,
        };

        let messaging_data = MessagingTxData {
            operation: MessagingOperation::SendMessage, // Use sponsored message operation
            data: bincode::serialize(&sponsored_msg)
                .map_err(|e| RpcError::Internal(format!("Failed to serialize sponsored message: {}", e)))?,
        };

        // Get sponsor's current nonce
        let sponsor_address = sponsor_keypair.address();
        let sponsor_nonce = self.state.get_nonce(&sponsor_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get sponsor nonce: {}", e)))?;

        // Create the messaging transaction
        // tx.from = sponsor_address (matches the signer)
        // The real message sender is in the SponsoredMessage.sender_pubkey
        let chain_id = self.state.chain_id();
        let fee = 1_000_000u128; // 0.001 Koppa fee

        let tx = TransactionV2::messaging(
            chain_id,
            sponsor_address, // Sponsor address as tx.from (matches signer)
            fee,
            sponsor_nonce,
            messaging_data,
        );

        // Sign the transaction with sponsor's key
        let signing_hash = tx.signing_hash();
        let signature = sumchain_crypto::sign(signing_hash.as_bytes(), sponsor_keypair.private_key());
        let signed_tx = SignedTransaction::new_v2(
            tx,
            *signature.as_bytes(),
            *sponsor_keypair.public_key().as_bytes(),
        );

        let tx_hash = signed_tx.hash();

        // Add to mempool
        self.mempool
            .add(signed_tx.clone())
            .map_err(|e| RpcError::TxRejected(format!("Mempool rejected: {}", e)))?;

        // Broadcast to network
        self.tx_sender
            .send(signed_tx)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to broadcast: {}", e)))?;

        tracing::info!(
            "Sponsored message submitted: {} (sponsor: {}, sender: {})",
            tx_hash,
            sponsor_address.to_base58(),
            sender_address.to_base58()
        );

        Ok(SendTxResponse {
            tx_hash: tx_hash.to_hex(),
        })
    }

    async fn messaging_register_sponsored(
        &self,
        request: SponsoredRegistrationRequest,
    ) -> std::result::Result<SponsoredRegistrationResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::RegisteredPublicKey;

        // Parse the public key from hex
        let pubkey_hex = request.public_key.strip_prefix("0x").unwrap_or(&request.public_key);
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid public key hex: {}", e)))?;

        if pubkey_bytes.len() != 32 {
            return Ok(SponsoredRegistrationResponse {
                address: String::new(),
                success: false,
                error: Some("Public key must be 32 bytes".to_string()),
            });
        }

        let mut pubkey: [u8; 32] = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);

        // Derive address from public key
        let address = Address::from_public_key(&pubkey);

        // Parse and verify signature
        let sig_hex = request.signature.strip_prefix("0x").unwrap_or(&request.signature);
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid signature hex: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Ok(SponsoredRegistrationResponse {
                address: address.to_base58(),
                success: false,
                error: Some("Signature must be 64 bytes".to_string()),
            });
        }

        let mut sig_array: [u8; 64] = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);

        // Verify signature over the registration message
        let message = format!("SUMCHAIN_REGISTER:{}", pubkey_hex);
        if sumchain_crypto::verify_bytes(message.as_bytes(), &sig_array, &pubkey).is_err() {
            return Ok(SponsoredRegistrationResponse {
                address: address.to_base58(),
                success: false,
                error: Some("Invalid signature".to_string()),
            });
        }

        // Check if already registered
        let store = MessagingStore::new(&self.db);
        if store.has_public_key(&address).unwrap_or(false) {
            return Ok(SponsoredRegistrationResponse {
                address: address.to_base58(),
                success: false,
                error: Some("Public key already registered".to_string()),
            });
        }

        // Get current block info for timestamps
        let block_store = BlockStore::new(&self.db);
        let (block_height, block_timestamp) = match block_store.get_latest() {
            Ok(Some(block)) => (block.header.height, block.header.timestamp),
            _ => (0, std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64),
        };

        // Register the public key directly (bypassing transaction validation)
        let registered = RegisteredPublicKey {
            public_key: pubkey,
            address,
            registered_at_block: block_height,
            registered_at: block_timestamp,
            updated_at_block: 0,
        };

        if let Err(e) = store.set_public_key(&address, &registered) {
            return Ok(SponsoredRegistrationResponse {
                address: address.to_base58(),
                success: false,
                error: Some(format!("Failed to register: {}", e)),
            });
        }

        tracing::info!(
            "Sponsored registration: {} registered public key",
            address.to_base58()
        );

        Ok(SponsoredRegistrationResponse {
            address: address.to_base58(),
            success: true,
            error: None,
        })
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

    async fn account_get_encryption_public_key(
        &self,
        address: String,
    ) -> std::result::Result<Option<String>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let registry = sumchain_state::NodeRegistryExecutor::new(self.db.clone());
        match registry
            .get_encryption_pubkey(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            Some(pk) => Ok(Some(format!("0x{}", hex::encode(pk)))),
            None => Ok(None),
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

    // =========================================================================
    // SRC-88X Employment & HR Endpoints Implementation
    // =========================================================================

    async fn employment_get_issuer(
        &self,
        issuer_address: String,
    ) -> std::result::Result<Option<EmploymentIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let address = Address::from_base58(&issuer_address)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = EmploymentIssuerStore::new(&self.db);
        match store.get(&address) {
            Ok(Some(issuer)) => Ok(Some(self.employment_issuer_to_rpc(&issuer))),
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_list_issuers(
        &self,
    ) -> std::result::Result<Vec<EmploymentIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = EmploymentIssuerStore::new(&self.db);
        match store.list_active() {
            Ok(issuers) => Ok(issuers.iter().map(|i| self.employment_issuer_to_rpc(i)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_get_credential(
        &self,
        employment_id: String,
    ) -> std::result::Result<Option<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id_bytes = hex::decode(employment_id.strip_prefix("0x").unwrap_or(&employment_id))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employment ID: {}", e)))?;

        if id_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Employment ID must be 32 bytes".to_string()).into());
        }

        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&id_bytes);

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get(&id_arr) {
            Ok(Some(cred)) => Ok(Some(self.employment_credential_to_rpc(&cred, current_time))),
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_get_credentials_by_employee(
        &self,
        employee_ref: String,
    ) -> std::result::Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let ref_bytes = hex::decode(employee_ref.strip_prefix("0x").unwrap_or(&employee_ref))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employee ref: {}", e)))?;

        if ref_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Employee ref must be 32 bytes".to_string()).into());
        }

        let mut ref_arr = [0u8; 32];
        ref_arr.copy_from_slice(&ref_bytes);

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get_by_employee(&ref_arr) {
            Ok(creds) => Ok(creds.iter().map(|c| self.employment_credential_to_rpc(c, current_time)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_get_active_credentials_by_employee(
        &self,
        employee_ref: String,
    ) -> std::result::Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let ref_bytes = hex::decode(employee_ref.strip_prefix("0x").unwrap_or(&employee_ref))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employee ref: {}", e)))?;

        if ref_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Employee ref must be 32 bytes".to_string()).into());
        }

        let mut ref_arr = [0u8; 32];
        ref_arr.copy_from_slice(&ref_bytes);

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get_active_by_employee(&ref_arr, current_time) {
            Ok(creds) => Ok(creds.iter().map(|c| self.employment_credential_to_rpc(c, current_time)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_get_credentials_by_employer(
        &self,
        employer_ref: String,
    ) -> std::result::Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let ref_bytes = hex::decode(employer_ref.strip_prefix("0x").unwrap_or(&employer_ref))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employer ref: {}", e)))?;

        if ref_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Employer ref must be 32 bytes".to_string()).into());
        }

        let mut ref_arr = [0u8; 32];
        ref_arr.copy_from_slice(&ref_bytes);

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get_by_employer(&ref_arr) {
            Ok(creds) => Ok(creds.iter().map(|c| self.employment_credential_to_rpc(c, current_time)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_verify_employment(
        &self,
        employee_ref: String,
        employer_ref: String,
    ) -> std::result::Result<EmploymentVerificationResult, jsonrpsee::types::ErrorObjectOwned> {
        let employee_bytes = hex::decode(employee_ref.strip_prefix("0x").unwrap_or(&employee_ref))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employee ref: {}", e)))?;
        let employer_bytes = hex::decode(employer_ref.strip_prefix("0x").unwrap_or(&employer_ref))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employer ref: {}", e)))?;

        if employee_bytes.len() != 32 || employer_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("References must be 32 bytes".to_string()).into());
        }

        let mut employee_arr = [0u8; 32];
        let mut employer_arr = [0u8; 32];
        employee_arr.copy_from_slice(&employee_bytes);
        employer_arr.copy_from_slice(&employer_bytes);

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let creds = store.get_active_by_employee(&employee_arr, current_time)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let matching = creds.into_iter().find(|c| c.employer_ref == employer_arr);

        Ok(EmploymentVerificationResult {
            is_employed: matching.is_some(),
            credential: matching.map(|c| self.employment_credential_to_rpc(&c, current_time)),
            verified_at: current_time,
        })
    }

    async fn employment_get_summary(
        &self,
        employee_ref: String,
    ) -> std::result::Result<EmploymentSummary, jsonrpsee::types::ErrorObjectOwned> {
        let ref_bytes = hex::decode(employee_ref.strip_prefix("0x").unwrap_or(&employee_ref))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employee ref: {}", e)))?;

        if ref_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Employee ref must be 32 bytes".to_string()).into());
        }

        let mut ref_arr = [0u8; 32];
        ref_arr.copy_from_slice(&ref_bytes);

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let all_creds = store.get_by_employee(&ref_arr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let active_creds: Vec<_> = all_creds.iter()
            .filter(|c| c.is_valid(current_time))
            .collect();

        let ended_count = all_creds.iter()
            .filter(|c| c.status == sumchain_primitives::employment::EmploymentStatus::Ended)
            .count();

        Ok(EmploymentSummary {
            employee_ref: format!("0x{}", hex::encode(&ref_arr)),
            total_credentials: all_creds.len() as u32,
            active_credentials: active_creds.len() as u32,
            ended_credentials: ended_count as u32,
            active_employment: active_creds.iter().map(|c| self.employment_credential_to_rpc(c, current_time)).collect(),
        })
    }

    async fn employment_get_income_attestation(
        &self,
        attestation_id: String,
    ) -> std::result::Result<Option<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id_bytes = hex::decode(attestation_id.strip_prefix("0x").unwrap_or(&attestation_id))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid attestation ID: {}", e)))?;

        if id_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Attestation ID must be 32 bytes".to_string()).into());
        }

        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&id_bytes);

        let store = IncomeAttestationStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get(&id_arr) {
            Ok(Some(att)) => Ok(Some(self.income_attestation_to_rpc(&att, current_time))),
            Ok(None) => Ok(None),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_get_income_attestations_by_subject(
        &self,
        subject_ref: String,
    ) -> std::result::Result<Vec<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let ref_bytes = hex::decode(subject_ref.strip_prefix("0x").unwrap_or(&subject_ref))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid subject ref: {}", e)))?;

        if ref_bytes.len() != 32 {
            return Err(RpcError::InvalidParams("Subject ref must be 32 bytes".to_string()).into());
        }

        let mut ref_arr = [0u8; 32];
        ref_arr.copy_from_slice(&ref_bytes);

        let store = IncomeAttestationStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get_by_subject(&ref_arr) {
            Ok(atts) => Ok(atts.iter().map(|a| self.income_attestation_to_rpc(a, current_time)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    // =========================================================================
    // SRC-88X Employment - Address-based queries (token ownership)
    // =========================================================================

    async fn employment_get_credentials_by_employee_address(
        &self,
        employee_address: String,
    ) -> std::result::Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let address = Address::from_base58(&employee_address)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get_by_employee_address(&address) {
            Ok(creds) => Ok(creds.iter().map(|c| self.employment_credential_to_rpc(c, current_time)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_get_active_credentials_by_employee_address(
        &self,
        employee_address: String,
    ) -> std::result::Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let address = Address::from_base58(&employee_address)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = EmploymentCredentialStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get_active_by_employee_address(&address, current_time) {
            Ok(creds) => Ok(creds.iter().map(|c| self.employment_credential_to_rpc(c, current_time)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    async fn employment_get_income_attestations_by_holder_address(
        &self,
        holder_address: String,
    ) -> std::result::Result<Vec<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let address = Address::from_base58(&holder_address)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid address: {}", e)))?;

        let store = IncomeAttestationStore::new(&self.db);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match store.get_by_holder_address(&address) {
            Ok(atts) => Ok(atts.iter().map(|a| self.income_attestation_to_rpc(a, current_time)).collect()),
            Err(e) => Err(RpcError::Internal(e.to_string()).into()),
        }
    }

    // =========================================================================
    // SRC-88X Employment Write Operations (Token-gated access)
    // =========================================================================

    async fn employment_register_issuer(
        &self,
        request: RegisterEmploymentIssuerRequest,
    ) -> std::result::Result<RegisterEmploymentIssuerResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::employment::{
            EmploymentIssuerClass, EmploymentIssuerProfile, EmploymentOperation, EmploymentTxData,
            IssuerStatus,
        };
        use sumchain_primitives::{TransactionV2, TxPayload};

        // Parse private key from hex
        let key_hex = request.private_key.strip_prefix("0x").unwrap_or(&request.private_key);
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Ok(RegisterEmploymentIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: String::new(),
                error: Some("Private key must be 32 bytes".to_string()),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let keypair = sumchain_crypto::KeyPair::from_bytes(key_array);
        let issuer_address = keypair.address();

        // Parse issuer class
        let issuer_class = match request.issuer_class.as_str() {
            "GovernmentLabor" => EmploymentIssuerClass::GovernmentLabor,
            "PayrollProcessor" => EmploymentIssuerClass::PayrollProcessor,
            "RegulatedHrPlatform" => EmploymentIssuerClass::RegulatedHrPlatform,
            "Peo" => EmploymentIssuerClass::Peo,
            "Employer" => EmploymentIssuerClass::Employer,
            "HrPlatform" => EmploymentIssuerClass::HrPlatform,
            "StaffingAgency" => EmploymentIssuerClass::StaffingAgency,
            "GigPlatform" => EmploymentIssuerClass::GigPlatform,
            _ => {
                return Ok(RegisterEmploymentIssuerResponse {
                    success: false,
                    tx_hash: None,
                    issuer_address: issuer_address.to_base58(),
                    error: Some(format!("Invalid issuer class: {}. Valid values: GovernmentLabor, PayrollProcessor, RegulatedHrPlatform, Peo, Employer, HrPlatform, StaffingAgency, GigPlatform", request.issuer_class)),
                });
            }
        };

        // Parse issuer commitment
        let commitment_hex = request.issuer_commitment.strip_prefix("0x").unwrap_or(&request.issuer_commitment);
        let commitment_bytes = hex::decode(commitment_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid issuer commitment hex: {}", e)))?;

        if commitment_bytes.len() != 32 {
            return Ok(RegisterEmploymentIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some("Issuer commitment must be 32 bytes".to_string()),
            });
        }

        let mut issuer_commitment = [0u8; 32];
        issuer_commitment.copy_from_slice(&commitment_bytes);

        // Parse policy ID
        let policy_hex = request.policy_id.strip_prefix("0x").unwrap_or(&request.policy_id);
        let policy_bytes = hex::decode(policy_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid policy ID hex: {}", e)))?;

        if policy_bytes.len() != 32 {
            return Ok(RegisterEmploymentIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some("Policy ID must be 32 bytes".to_string()),
            });
        }

        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&policy_bytes);

        // Check if issuer already exists
        let store = EmploymentIssuerStore::new(&self.db);
        if store.exists(&issuer_address).unwrap_or(false) {
            return Ok(RegisterEmploymentIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some("Issuer already registered".to_string()),
            });
        }

        // Get current block info for timestamps
        let block_store = BlockStore::new(&self.db);
        let (block_height, block_timestamp) = match block_store.get_latest() {
            Ok(Some(block)) => (block.header.height, block.header.timestamp),
            _ => (0, std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64),
        };

        // Create the issuer profile
        let issuer_profile = EmploymentIssuerProfile {
            issuer_address,
            issuer_class,
            display_name: request.display_name.clone(),
            issuer_commitment,
            jurisdiction_code: request.jurisdiction_code.clone(),
            policy_id,
            status: IssuerStatus::Active,
            registered_at_height: block_height,
            created_at: block_timestamp,
            updated_at: block_timestamp,
        };

        // Serialize the issuer profile
        let issuer_data = bincode::serialize(&issuer_profile)
            .map_err(|e| RpcError::Internal(format!("Failed to serialize issuer profile: {}", e)))?;

        // Create employment transaction data
        // For issuer registration, the issuer is both sender and recipient (they own their issuer profile token)
        let employment_tx_data = EmploymentTxData {
            operation: EmploymentOperation::RegisterIssuer,
            data: issuer_data,
            recipient: issuer_address,
        };

        // Get nonce for the issuer address
        let nonce = self.state.get_nonce(&issuer_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;

        // Create the transaction
        let chain_id = self.state.chain_id();
        let fee = 1_000_000u128; // 0.001 Koppa fee

        let tx = TransactionV2 {
            chain_id,
            from: issuer_address,
            fee,
            nonce,
            payload: TxPayload::Employment(employment_tx_data),
        };

        // Sign the transaction
        let signing_hash = tx.signing_hash();
        let signature = sumchain_crypto::sign(signing_hash.as_bytes(), keypair.private_key());
        let signed_tx = SignedTransaction::new_v2(
            tx,
            *signature.as_bytes(),
            *keypair.public_key().as_bytes(),
        );

        let tx_hash = signed_tx.hash();

        // Add to mempool
        if let Err(e) = self.mempool.add(signed_tx.clone()) {
            return Ok(RegisterEmploymentIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some(format!("Transaction rejected: {}", e)),
            });
        }

        // Broadcast to network
        if let Err(e) = self.tx_sender.send(signed_tx).await {
            return Ok(RegisterEmploymentIssuerResponse {
                success: false,
                tx_hash: Some(tx_hash.to_hex()),
                issuer_address: issuer_address.to_base58(),
                error: Some(format!("Failed to broadcast: {}", e)),
            });
        }

        info!("Employment issuer registration submitted: {} (tx: {})", issuer_address, tx_hash);

        Ok(RegisterEmploymentIssuerResponse {
            success: true,
            tx_hash: Some(tx_hash.to_hex()),
            issuer_address: issuer_address.to_base58(),
            error: None,
        })
    }

    async fn employment_create_credential(
        &self,
        request: CreateEmploymentCredentialRequest,
    ) -> std::result::Result<CreateEmploymentCredentialResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::employment::{
            EmploymentCredential, EmploymentOperation, EmploymentStatus, EmploymentTxData,
            EmploymentType,
        };
        use sumchain_primitives::{TransactionV2, TxPayload};

        // Parse private key from hex
        let key_hex = request.private_key.strip_prefix("0x").unwrap_or(&request.private_key);
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                employment_id: None,
                error: Some("Private key must be 32 bytes".to_string()),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let keypair = sumchain_crypto::KeyPair::from_bytes(key_array);
        let issuer_address = keypair.address();

        // Verify issuer is registered and active
        let issuer_store = EmploymentIssuerStore::new(&self.db);
        let issuer = match issuer_store.get(&issuer_address) {
            Ok(Some(i)) => i,
            Ok(None) => {
                return Ok(CreateEmploymentCredentialResponse {
                    success: false,
                    tx_hash: None,
                    employment_id: None,
                    error: Some("Issuer not registered. Register first with employment_registerIssuer".to_string()),
                });
            }
            Err(e) => {
                return Ok(CreateEmploymentCredentialResponse {
                    success: false,
                    tx_hash: None,
                    employment_id: None,
                    error: Some(format!("Failed to check issuer: {}", e)),
                });
            }
        };

        if !issuer.status.is_active() {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                employment_id: None,
                error: Some("Issuer is not active".to_string()),
            });
        }

        // Parse employee address
        let employee_address = Address::from_base58(&request.employee_address)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employee address: {}", e)))?;

        // Parse employee reference
        let employee_ref_hex = request.employee_ref.strip_prefix("0x").unwrap_or(&request.employee_ref);
        let employee_ref_bytes = hex::decode(employee_ref_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employee ref hex: {}", e)))?;

        if employee_ref_bytes.len() != 32 {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                employment_id: None,
                error: Some("Employee ref must be 32 bytes".to_string()),
            });
        }

        let mut employee_ref = [0u8; 32];
        employee_ref.copy_from_slice(&employee_ref_bytes);

        // Parse employer reference
        let employer_ref_hex = request.employer_ref.strip_prefix("0x").unwrap_or(&request.employer_ref);
        let employer_ref_bytes = hex::decode(employer_ref_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employer ref hex: {}", e)))?;

        if employer_ref_bytes.len() != 32 {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                employment_id: None,
                error: Some("Employer ref must be 32 bytes".to_string()),
            });
        }

        let mut employer_ref = [0u8; 32];
        employer_ref.copy_from_slice(&employer_ref_bytes);

        // Parse tenure commitment
        let tenure_hex = request.tenure_commitment.strip_prefix("0x").unwrap_or(&request.tenure_commitment);
        let tenure_bytes = hex::decode(tenure_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid tenure commitment hex: {}", e)))?;

        if tenure_bytes.len() != 32 {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                employment_id: None,
                error: Some("Tenure commitment must be 32 bytes".to_string()),
            });
        }

        let mut tenure_commitment = [0u8; 32];
        tenure_commitment.copy_from_slice(&tenure_bytes);

        // Parse optional role commitment
        let role_commitment = if let Some(ref role_hex_str) = request.role_commitment {
            let role_hex = role_hex_str.strip_prefix("0x").unwrap_or(role_hex_str);
            let role_bytes = hex::decode(role_hex)
                .map_err(|e| RpcError::InvalidParams(format!("Invalid role commitment hex: {}", e)))?;

            if role_bytes.len() != 32 {
                return Ok(CreateEmploymentCredentialResponse {
                    success: false,
                    tx_hash: None,
                    employment_id: None,
                    error: Some("Role commitment must be 32 bytes".to_string()),
                });
            }

            let mut role = [0u8; 32];
            role.copy_from_slice(&role_bytes);
            Some(role)
        } else {
            None
        };

        // Parse employment type
        let employment_type = match request.employment_type.as_str() {
            "FullTime" => EmploymentType::FullTime,
            "PartTime" => EmploymentType::PartTime,
            "Contract" => EmploymentType::Contract,
            "Temporary" => EmploymentType::Temporary,
            "Internship" => EmploymentType::Internship,
            "Freelance" => EmploymentType::Freelance,
            "Gig" => EmploymentType::Gig,
            _ => {
                return Ok(CreateEmploymentCredentialResponse {
                    success: false,
                    tx_hash: None,
                    employment_id: None,
                    error: Some(format!("Invalid employment type: {}. Valid values: FullTime, PartTime, Contract, Temporary, Internship, Freelance, Gig", request.employment_type)),
                });
            }
        };

        // Parse policy ID
        let policy_hex = request.policy_id.strip_prefix("0x").unwrap_or(&request.policy_id);
        let policy_bytes = hex::decode(policy_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid policy ID hex: {}", e)))?;

        if policy_bytes.len() != 32 {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                employment_id: None,
                error: Some("Policy ID must be 32 bytes".to_string()),
            });
        }

        let mut policy_id = [0u8; 32];
        policy_id.copy_from_slice(&policy_bytes);

        // Get current timestamp
        let block_store = BlockStore::new(&self.db);
        let (_, block_timestamp) = match block_store.get_latest() {
            Ok(Some(block)) => (block.header.height, block.header.timestamp),
            _ => (0, std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64),
        };

        // Generate employment ID
        let nonce = self.state.get_nonce(&issuer_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;
        let employment_id = EmploymentCredential::generate_id(
            &employee_ref,
            &employer_ref,
            &tenure_commitment,
            nonce,
        );

        // Create the credential
        let credential = EmploymentCredential {
            employment_id,
            employee_address,
            employee_ref,
            employer_ref,
            status: EmploymentStatus::Active,
            tenure_commitment,
            role_commitment,
            employment_type,
            valid_from: request.valid_from,
            expiry: request.expiry,
            policy_id,
            revocation_ref: None,
            issuer_address,
            issuer_name: issuer.display_name.clone(),
            issuer_class: issuer.issuer_class,
            created_at: block_timestamp,
            updated_at: block_timestamp,
        };

        // Serialize the credential
        let credential_data = bincode::serialize(&credential)
            .map_err(|e| RpcError::Internal(format!("Failed to serialize credential: {}", e)))?;

        // Create employment transaction data
        // The employee is the recipient - they own the credential token
        let employment_tx_data = EmploymentTxData {
            operation: EmploymentOperation::CreateEmployment,
            data: credential_data,
            recipient: employee_address,
        };

        // Create the transaction
        let chain_id = self.state.chain_id();
        let fee = 1_000_000u128; // 0.001 Koppa fee

        let tx = TransactionV2 {
            chain_id,
            from: issuer_address,
            fee,
            nonce,
            payload: TxPayload::Employment(employment_tx_data),
        };

        // Sign the transaction
        let signing_hash = tx.signing_hash();
        let signature = sumchain_crypto::sign(signing_hash.as_bytes(), keypair.private_key());
        let signed_tx = SignedTransaction::new_v2(
            tx,
            *signature.as_bytes(),
            *keypair.public_key().as_bytes(),
        );

        let tx_hash = signed_tx.hash();

        // Add to mempool
        if let Err(e) = self.mempool.add(signed_tx.clone()) {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                employment_id: None,
                error: Some(format!("Transaction rejected: {}", e)),
            });
        }

        // Broadcast to network
        if let Err(e) = self.tx_sender.send(signed_tx).await {
            return Ok(CreateEmploymentCredentialResponse {
                success: false,
                tx_hash: Some(tx_hash.to_hex()),
                employment_id: Some(format!("0x{}", hex::encode(employment_id))),
                error: Some(format!("Failed to broadcast: {}", e)),
            });
        }

        info!("Employment credential creation submitted: {:?} (tx: {})", employment_id, tx_hash);

        Ok(CreateEmploymentCredentialResponse {
            success: true,
            tx_hash: Some(tx_hash.to_hex()),
            employment_id: Some(format!("0x{}", hex::encode(employment_id))),
            error: None,
        })
    }

    async fn employment_revoke_credential(
        &self,
        request: RevokeEmploymentCredentialRequest,
    ) -> std::result::Result<RevokeEmploymentCredentialResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::employment::{EmploymentOperation, EmploymentTxData};
        use sumchain_primitives::{TransactionV2, TxPayload};

        // Parse private key from hex
        let key_hex = request.private_key.strip_prefix("0x").unwrap_or(&request.private_key);
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Ok(RevokeEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                revocation_ref: None,
                error: Some("Private key must be 32 bytes".to_string()),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let keypair = sumchain_crypto::KeyPair::from_bytes(key_array);
        let caller_address = keypair.address();

        // Parse employment ID
        let id_hex = request.employment_id.strip_prefix("0x").unwrap_or(&request.employment_id);
        let id_bytes = hex::decode(id_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid employment ID hex: {}", e)))?;

        if id_bytes.len() != 32 {
            return Ok(RevokeEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                revocation_ref: None,
                error: Some("Employment ID must be 32 bytes".to_string()),
            });
        }

        let mut employment_id = [0u8; 32];
        employment_id.copy_from_slice(&id_bytes);

        // Get the credential to verify ownership
        let cred_store = EmploymentCredentialStore::new(&self.db);
        let credential = match cred_store.get(&employment_id) {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Ok(RevokeEmploymentCredentialResponse {
                    success: false,
                    tx_hash: None,
                    revocation_ref: None,
                    error: Some("Credential not found".to_string()),
                });
            }
            Err(e) => {
                return Ok(RevokeEmploymentCredentialResponse {
                    success: false,
                    tx_hash: None,
                    revocation_ref: None,
                    error: Some(format!("Failed to get credential: {}", e)),
                });
            }
        };

        // Verify caller is the original issuer
        if credential.issuer_address != caller_address {
            return Ok(RevokeEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                revocation_ref: None,
                error: Some("Only the original issuer can revoke this credential".to_string()),
            });
        }

        // Check if already revoked
        if credential.revocation_ref.is_some() {
            return Ok(RevokeEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                revocation_ref: credential.revocation_ref.map(|r| format!("0x{}", hex::encode(r))),
                error: Some("Credential is already revoked".to_string()),
            });
        }

        // Get current timestamp
        let block_store = BlockStore::new(&self.db);
        let block_timestamp = match block_store.get_latest() {
            Ok(Some(block)) => block.header.timestamp,
            _ => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        // Generate revocation reference (hash of employment_id + timestamp + optional reason)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&employment_id);
        hasher.update(&block_timestamp.to_le_bytes());
        if let Some(ref reason) = request.reason {
            hasher.update(reason.as_bytes());
        }
        let revocation_ref: [u8; 32] = *hasher.finalize().as_bytes();

        // Create revocation data structure
        #[derive(serde::Serialize)]
        struct RevocationData {
            employment_id: [u8; 32],
            revocation_ref: [u8; 32],
            timestamp: u64,
            reason: Option<String>,
        }

        let revocation_data = RevocationData {
            employment_id,
            revocation_ref,
            timestamp: block_timestamp,
            reason: request.reason.clone(),
        };

        let data = bincode::serialize(&revocation_data)
            .map_err(|e| RpcError::Internal(format!("Failed to serialize revocation data: {}", e)))?;

        // Create employment transaction data
        let employment_tx_data = EmploymentTxData {
            operation: EmploymentOperation::RevokeEmployment,
            data,
            recipient: credential.employee_address, // The employee still owns the (now revoked) token
        };

        // Get nonce
        let nonce = self.state.get_nonce(&caller_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;

        // Create the transaction
        let chain_id = self.state.chain_id();
        let fee = 1_000_000u128; // 0.001 Koppa fee

        let tx = TransactionV2 {
            chain_id,
            from: caller_address,
            fee,
            nonce,
            payload: TxPayload::Employment(employment_tx_data),
        };

        // Sign the transaction
        let signing_hash = tx.signing_hash();
        let signature = sumchain_crypto::sign(signing_hash.as_bytes(), keypair.private_key());
        let signed_tx = SignedTransaction::new_v2(
            tx,
            *signature.as_bytes(),
            *keypair.public_key().as_bytes(),
        );

        let tx_hash = signed_tx.hash();

        // Add to mempool
        if let Err(e) = self.mempool.add(signed_tx.clone()) {
            return Ok(RevokeEmploymentCredentialResponse {
                success: false,
                tx_hash: None,
                revocation_ref: None,
                error: Some(format!("Transaction rejected: {}", e)),
            });
        }

        // Broadcast to network
        if let Err(e) = self.tx_sender.send(signed_tx).await {
            return Ok(RevokeEmploymentCredentialResponse {
                success: false,
                tx_hash: Some(tx_hash.to_hex()),
                revocation_ref: Some(format!("0x{}", hex::encode(revocation_ref))),
                error: Some(format!("Failed to broadcast: {}", e)),
            });
        }

        info!("Employment credential revocation submitted: {:?} (tx: {})", employment_id, tx_hash);

        Ok(RevokeEmploymentCredentialResponse {
            success: true,
            tx_hash: Some(tx_hash.to_hex()),
            revocation_ref: Some(format!("0x{}", hex::encode(revocation_ref))),
            error: None,
        })
    }

    async fn docclass_register_academic_issuer(
        &self,
        request: RegisterAcademicIssuerRequest,
    ) -> std::result::Result<RegisterAcademicIssuerResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::docclass::{
            DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType, DocClassOperation,
            DocClassTxData, DocSubcode, IssuerKey, KeyType,
        };
        use sumchain_primitives::{TransactionV2, TxPayload};

        // Parse private key from hex
        let key_hex = request.private_key.strip_prefix("0x").unwrap_or(&request.private_key);
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Ok(RegisterAcademicIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: String::new(),
                error: Some("Private key must be 32 bytes".to_string()),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let keypair = sumchain_crypto::KeyPair::from_bytes(key_array);
        let issuer_address = keypair.address();

        // Parse stake amount
        let stake_amount: u128 = request.stake_amount.parse()
            .map_err(|e| RpcError::InvalidParams(format!("Invalid stake amount: {}", e)))?;

        // Validate minimum stake (1000 Ϙ = 1_000_000_000 Koppa)
        const MIN_STAKE: u128 = 1_000_000_000;
        if stake_amount < MIN_STAKE {
            return Ok(RegisterAcademicIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some(format!("Minimum stake is {} Koppa (1000 Ϙ)", MIN_STAKE)),
            });
        }

        // Validate balance
        let balance = self.state.get_balance(&issuer_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get balance: {}", e)))?;

        if balance < stake_amount {
            return Ok(RegisterAcademicIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some(format!("Insufficient balance. Have: {} Koppa, Need: {} Koppa", balance, stake_amount)),
            });
        }

        // Parse jurisdiction code
        if request.jurisdiction_code.len() != 2 {
            return Ok(RegisterAcademicIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some("Jurisdiction code must be ISO 3166-1 alpha-2 (2 characters)".to_string()),
            });
        }

        // Validate authorized subcodes (must be educational: 810, 811, 812)
        for &subcode in &request.authorized_subcodes {
            if !(810..=812).contains(&subcode) {
                return Ok(RegisterAcademicIssuerResponse {
                    success: false,
                    tx_hash: None,
                    issuer_address: issuer_address.to_base58(),
                    error: Some(format!("Invalid subcode: {}. Educational issuers can only use 810 (Transcript), 811 (Diploma), 812 (Enrollment)", subcode)),
                });
            }
        }

        if request.authorized_subcodes.is_empty() {
            return Ok(RegisterAcademicIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some("At least one authorized subcode is required".to_string()),
            });
        }

        // Get current timestamp
        let block_store = BlockStore::new(&self.db);
        let block_timestamp = match block_store.get_latest() {
            Ok(Some(block)) => block.header.timestamp,
            _ => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        // Create issuer key
        let issuer_key = IssuerKey {
            key_id: "primary-key".to_string(),
            public_key: *keypair.public_key().as_bytes(),
            key_type: KeyType::Ed25519,
            added_at: block_timestamp,
            expires_at: 0, // No expiry
            active: true,
            is_primary: true,
        };

        // Parse subcodes
        let subcodes: Vec<DocSubcode> = request.authorized_subcodes.iter().map(|&code| {
            match code {
                810 => DocSubcode::AcademicTranscript,
                811 => DocSubcode::Diploma,
                812 => DocSubcode::EnrollmentVerification,
                _ => DocSubcode::AcademicTranscript, // Default fallback
            }
        }).collect();

        // Get first subcode for transaction before moving subcodes
        let subcode = subcodes[0];

        // Create issuer struct
        let issuer = DocClassIssuer {
            address: issuer_address,
            name: request.institution_name.clone(),
            issuer_type: DocClassIssuerType::Educational,
            jurisdictions: vec![request.jurisdiction_code.clone()],
            authorized_subcodes: subcodes,
            keys: vec![issuer_key],
            registered_at: block_timestamp,
            updated_at: block_timestamp,
            status: DocClassIssuerStatus::Active,
            stake_amount,
            metadata: None,
        };

        // Serialize the issuer data
        let issuer_data = bincode::serialize(&issuer)
            .map_err(|e| RpcError::Internal(format!("Failed to serialize issuer: {}", e)))?;

        // Create DocClass transaction data
        // Use first authorized subcode as the subcode for the transaction
        let docclass_tx_data = DocClassTxData {
            operation: DocClassOperation::RegisterIssuer,
            subcode,
            data: issuer_data,
            recipient: issuer_address, // Issuer is the recipient
        };

        // Create the transaction
        let chain_id = self.state.chain_id();
        let nonce = self.state.get_nonce(&issuer_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;
        let fee = 1_000_000u128; // 0.001 Koppa fee

        let tx = TransactionV2 {
            chain_id,
            from: issuer_address,
            fee,
            nonce,
            payload: TxPayload::DocClass(docclass_tx_data),
        };

        // Sign the transaction
        let signing_hash = tx.signing_hash();
        let signature = sumchain_crypto::sign(signing_hash.as_bytes(), keypair.private_key());
        let signed_tx = SignedTransaction::new_v2(
            tx,
            *signature.as_bytes(),
            *keypair.public_key().as_bytes(),
        );

        let tx_hash = signed_tx.hash();

        // Add to mempool
        if let Err(e) = self.mempool.add(signed_tx.clone()) {
            return Ok(RegisterAcademicIssuerResponse {
                success: false,
                tx_hash: None,
                issuer_address: issuer_address.to_base58(),
                error: Some(format!("Transaction rejected: {}", e)),
            });
        }

        // Broadcast to network
        if let Err(e) = self.tx_sender.send(signed_tx).await {
            return Ok(RegisterAcademicIssuerResponse {
                success: false,
                tx_hash: Some(tx_hash.to_hex()),
                issuer_address: issuer_address.to_base58(),
                error: Some(format!("Failed to broadcast: {}", e)),
            });
        }

        info!("Academic issuer registration submitted: {} (tx: {})", issuer_address, tx_hash);

        Ok(RegisterAcademicIssuerResponse {
            success: true,
            tx_hash: Some(tx_hash.to_hex()),
            issuer_address: issuer_address.to_base58(),
            error: None,
        })
    }

    async fn docclass_issue_academic_credential(
        &self,
        request: IssueAcademicCredentialRequest,
    ) -> std::result::Result<IssueAcademicCredentialResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::docclass::{
            AcademicCredential, CredentialAttribute, CredentialMetadata, DocClassOperation,
            DocClassTxData, DocSubcode, RevocationStatus,
        };
        use sumchain_primitives::{TransactionV2, TxPayload};
        use sumchain_storage::DocClassIssuerStore;

        // Parse private key from hex
        let key_hex = request.private_key.strip_prefix("0x").unwrap_or(&request.private_key);
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some("Private key must be 32 bytes".to_string()),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let keypair = sumchain_crypto::KeyPair::from_bytes(key_array);
        let issuer_address = keypair.address();

        // Verify issuer is registered and active
        let issuer_store = DocClassIssuerStore::new(&self.db);
        let issuer = match issuer_store.get(&issuer_address) {
            Ok(Some(i)) => i,
            Ok(None) => {
                return Ok(IssueAcademicCredentialResponse {
                    success: false,
                    tx_hash: None,
                    credential_id: None,
                    error: Some("Issuer not registered. Register first with docclass_registerAcademicIssuer".to_string()),
                });
            }
            Err(e) => {
                return Ok(IssueAcademicCredentialResponse {
                    success: false,
                    tx_hash: None,
                    credential_id: None,
                    error: Some(format!("Failed to check issuer: {}", e)),
                });
            }
        };

        if !issuer.status.can_issue() {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some("Issuer is not active or cannot issue credentials".to_string()),
            });
        }

        // Validate subcode
        let subcode = match request.subcode {
            810 => DocSubcode::AcademicTranscript,
            811 => DocSubcode::Diploma,
            812 => DocSubcode::EnrollmentVerification,
            _ => {
                return Ok(IssueAcademicCredentialResponse {
                    success: false,
                    tx_hash: None,
                    credential_id: None,
                    error: Some(format!("Invalid subcode: {}. Valid values: 810 (Transcript), 811 (Diploma), 812 (Enrollment)", request.subcode)),
                });
            }
        };

        // Verify issuer is authorized for this subcode
        if !issuer.authorized_subcodes.contains(&subcode) {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some(format!("Issuer not authorized for subcode {}", request.subcode)),
            });
        }

        // Parse holder address
        let holder_address = Address::from_base58(&request.holder_address)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid holder address: {}", e)))?;

        // Parse subject commitment
        let subject_hex = request.subject_commitment.strip_prefix("0x").unwrap_or(&request.subject_commitment);
        let subject_bytes = hex::decode(subject_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid subject commitment hex: {}", e)))?;

        if subject_bytes.len() != 32 {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some("Subject commitment must be 32 bytes".to_string()),
            });
        }

        let mut subject_commitment = [0u8; 32];
        subject_commitment.copy_from_slice(&subject_bytes);

        // Parse schema hash
        let schema_hex = request.schema_hash.strip_prefix("0x").unwrap_or(&request.schema_hash);
        let schema_bytes = hex::decode(schema_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid schema hash hex: {}", e)))?;

        if schema_bytes.len() != 32 {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some("Schema hash must be 32 bytes".to_string()),
            });
        }

        let mut schema_hash = [0u8; 32];
        schema_hash.copy_from_slice(&schema_bytes);

        // Parse content commitment
        let content_hex = request.content_commitment.strip_prefix("0x").unwrap_or(&request.content_commitment);
        let content_bytes = hex::decode(content_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid content commitment hex: {}", e)))?;

        if content_bytes.len() != 32 {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some("Content commitment must be 32 bytes".to_string()),
            });
        }

        let mut content_commitment = [0u8; 32];
        content_commitment.copy_from_slice(&content_bytes);

        // Parse attributes - convert RPC format to credential format
        let mut attributes: Vec<CredentialAttribute> = Vec::new();
        for attr in &request.attributes {
            // For now, store the commitment hex as the value
            // In a real implementation, this would be the non-PII public value
            attributes.push(CredentialAttribute {
                name: attr.name.clone(),
                value: attr.value_commitment.clone(),
            });
        }

        // Get current timestamp
        let block_store = BlockStore::new(&self.db);
        let block_timestamp = match block_store.get_latest() {
            Ok(Some(block)) => block.header.timestamp,
            _ => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        // Get issuer jurisdiction
        let jurisdiction = issuer.jurisdictions.first()
            .ok_or_else(|| RpcError::Internal("Issuer has no jurisdictions".to_string()))?
            .clone();

        // Generate credential ID
        let nonce = self.state.get_nonce(&issuer_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&subject_commitment);
        hasher.update(issuer_address.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&(request.subcode as u16).to_le_bytes());
        let credential_id: [u8; 32] = *hasher.finalize().as_bytes();

        // Create metadata
        let metadata = CredentialMetadata {
            title: request.metadata.as_ref()
                .and_then(|m| m.title.clone())
                .unwrap_or_else(|| format!("Credential {}", request.subcode)),
            credential_type: match request.subcode {
                810 => "academic_transcript".to_string(),
                811 => "diploma".to_string(),
                812 => "enrollment_verification".to_string(),
                _ => "academic_credential".to_string(),
            },
            program: request.metadata.as_ref().and_then(|m| m.program.clone()),
            issue_date: request.metadata.as_ref()
                .and_then(|m| m.issue_date.clone())
                .unwrap_or_else(|| {
                    // Simple timestamp-based date formatting
                    let days_since_epoch = (block_timestamp / 1000) / 86400;
                    let year = 1970 + (days_since_epoch / 365);
                    format!("{}-01-01", year) // Simplified date format
                }),
            completion_date: request.metadata.as_ref().and_then(|m| m.completion_date.clone()),
            attributes,
        };

        // Create the credential
        let credential = AcademicCredential {
            credential_id,
            subject_address: holder_address,
            subcode,
            subject_commitment,
            issuer: issuer_address,
            institution_id: issuer.name.clone(),
            jurisdiction: jurisdiction.clone(),
            schema_hash,
            content_commitment,
            metadata,
            issued_at: block_timestamp,
            valid_from: request.valid_from,
            expires_at: request.expires_at,
            payload_hash: request.metadata.as_ref()
                .and_then(|m| m.ipfs_cid.as_ref())
                .and_then(|cid| {
                    // Convert IPFS CID to hash if provided
                    let hash_bytes = blake3::hash(cid.as_bytes());
                    Some(*hash_bytes.as_bytes())
                }),
            payload_hint: request.metadata.as_ref()
                .and_then(|m| m.ipfs_cid.clone())
                .map(|cid| format!("ipfs://{}", cid)),
            encryption_meta: None,
            issuer_signature: [0u8; 64], // Will be filled by transaction processor
            issuer_key_id: "primary-key".to_string(),
            revocation_status: RevocationStatus::Active,
            superseded_by: None,
        };

        // Serialize the credential
        let credential_data = bincode::serialize(&credential)
            .map_err(|e| RpcError::Internal(format!("Failed to serialize credential: {}", e)))?;

        // Create DocClass transaction data
        let docclass_tx_data = DocClassTxData {
            operation: DocClassOperation::IssueCredential,
            subcode,
            data: credential_data,
            recipient: holder_address, // Holder is the recipient
        };

        // Create the transaction
        let chain_id = self.state.chain_id();
        let fee = 1_000_000u128; // 0.001 Koppa fee

        let tx = TransactionV2 {
            chain_id,
            from: issuer_address,
            fee,
            nonce,
            payload: TxPayload::DocClass(docclass_tx_data),
        };

        // Sign the transaction
        let signing_hash = tx.signing_hash();
        let signature = sumchain_crypto::sign(signing_hash.as_bytes(), keypair.private_key());
        let signed_tx = SignedTransaction::new_v2(
            tx,
            *signature.as_bytes(),
            *keypair.public_key().as_bytes(),
        );

        let tx_hash = signed_tx.hash();

        // Add to mempool
        if let Err(e) = self.mempool.add(signed_tx.clone()) {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some(format!("Transaction rejected: {}", e)),
            });
        }

        // Broadcast to network
        if let Err(e) = self.tx_sender.send(signed_tx).await {
            return Ok(IssueAcademicCredentialResponse {
                success: false,
                tx_hash: Some(tx_hash.to_hex()),
                credential_id: Some(format!("0x{}", hex::encode(credential_id))),
                error: Some(format!("Failed to broadcast: {}", e)),
            });
        }

        info!("Academic credential issuance submitted: {:?} (tx: {})", credential_id, tx_hash);

        Ok(IssueAcademicCredentialResponse {
            success: true,
            tx_hash: Some(tx_hash.to_hex()),
            credential_id: Some(format!("0x{}", hex::encode(credential_id))),
            error: None,
        })
    }

    async fn docclass_revoke_academic_credential(
        &self,
        request: RevokeAcademicCredentialRequest,
    ) -> std::result::Result<RevokeAcademicCredentialResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::docclass::{
            DocClassOperation, DocClassTxData, DocSubcode, RevocationReason,
        };
        use sumchain_primitives::{TransactionV2, TxPayload};

        // Parse private key
        let key_hex = request.private_key.strip_prefix("0x").unwrap_or(&request.private_key);
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid private key hex: {}", e)))?;

        if key_bytes.len() != 32 {
            return Ok(RevokeAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some("Private key must be 32 bytes".to_string()),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        let keypair = sumchain_crypto::KeyPair::from_bytes(key_array);
        let caller_address = keypair.address();

        // Parse credential ID
        let id_hex = request.credential_id.strip_prefix("0x").unwrap_or(&request.credential_id);
        let id_bytes = hex::decode(id_hex)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid credential ID hex: {}", e)))?;

        if id_bytes.len() != 32 {
            return Ok(RevokeAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some("Credential ID must be 32 bytes".to_string()),
            });
        }

        let mut credential_id = [0u8; 32];
        credential_id.copy_from_slice(&id_bytes);

        // Verify caller is a registered issuer
        let issuer_store = sumchain_storage::DocClassIssuerStore::new(&self.db);
        match issuer_store.get(&caller_address) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Ok(RevokeAcademicCredentialResponse {
                    success: false,
                    tx_hash: None,
                    credential_id: None,
                    error: Some("Caller is not a registered issuer".to_string()),
                });
            }
            Err(e) => {
                return Ok(RevokeAcademicCredentialResponse {
                    success: false,
                    tx_hash: None,
                    credential_id: None,
                    error: Some(format!("Failed to check issuer: {}", e)),
                });
            }
        };

        // Parse revocation reason
        let reason = match request.reason.unwrap_or(0) {
            0 => RevocationReason::Unspecified,
            1 => RevocationReason::KeyCompromise,
            2 => RevocationReason::IssuerCompromise,
            3 => RevocationReason::AffiliationChanged,
            4 => RevocationReason::Superseded,
            5 => RevocationReason::CessationOfOperation,
            6 => RevocationReason::CertificateHold,
            7 => RevocationReason::PrivilegeWithdrawn,
            _ => RevocationReason::Unspecified,
        };

        // Create revocation data
        #[derive(serde::Serialize)]
        struct RevokeData {
            credential_id: [u8; 32],
            reason: RevocationReason,
        }

        let revoke_data = RevokeData {
            credential_id,
            reason,
        };

        let data = bincode::serialize(&revoke_data)
            .map_err(|e| RpcError::Internal(format!("Failed to serialize: {}", e)))?;

        // Create DocClass transaction
        let docclass_tx_data = DocClassTxData {
            operation: DocClassOperation::RevokeCredential,
            subcode: DocSubcode::Diploma, // subcode context
            data,
            recipient: caller_address, // issuer is the caller
        };

        // Get nonce
        let nonce = self.state.get_nonce(&caller_address)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;

        // Create the transaction
        let chain_id = self.state.chain_id();
        let fee = 1_000_000u128;

        let tx = TransactionV2 {
            chain_id,
            from: caller_address,
            fee,
            nonce,
            payload: TxPayload::DocClass(docclass_tx_data),
        };

        // Sign the transaction
        let signing_hash = tx.signing_hash();
        let signature = sumchain_crypto::sign(signing_hash.as_bytes(), keypair.private_key());
        let signed_tx = SignedTransaction::new_v2(
            tx,
            *signature.as_bytes(),
            *keypair.public_key().as_bytes(),
        );

        let tx_hash = signed_tx.hash();

        // Add to mempool
        if let Err(e) = self.mempool.add(signed_tx.clone()) {
            return Ok(RevokeAcademicCredentialResponse {
                success: false,
                tx_hash: None,
                credential_id: None,
                error: Some(format!("Transaction rejected: {}", e)),
            });
        }

        // Broadcast to network
        if let Err(e) = self.tx_sender.send(signed_tx).await {
            return Ok(RevokeAcademicCredentialResponse {
                success: false,
                tx_hash: Some(tx_hash.to_hex()),
                credential_id: Some(format!("0x{}", hex::encode(credential_id))),
                error: Some(format!("Failed to broadcast: {}", e)),
            });
        }

        info!("Academic credential revocation submitted: {:?} (tx: {})", credential_id, tx_hash);

        Ok(RevokeAcademicCredentialResponse {
            success: true,
            tx_hash: Some(tx_hash.to_hex()),
            credential_id: Some(format!("0x{}", hex::encode(credential_id))),
            error: None,
        })
    }

    async fn docclass_get_academic_credentials_by_holder(
        &self,
        holder_address: String,
    ) -> std::result::Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_storage::DocClassStore;

        // Parse holder address
        let holder = Address::from_base58(&holder_address)
            .map_err(|e| RpcError::InvalidParams(format!("Invalid holder address: {}", e)))?;

        let docclass_store = DocClassStore::new(&self.db);
        let credential_store = docclass_store.credentials();

        // Get all credentials and filter by subject_address (holder)
        // Note: This could be optimized with an index in the future
        let mut results = Vec::new();

        // Iterate through all credentials (academic subcodes: 810, 811, 812)
        use sumchain_primitives::docclass::DocSubcode;
        for subcode in [DocSubcode::AcademicTranscript, DocSubcode::Diploma, DocSubcode::EnrollmentVerification] {
            match credential_store.get_by_subcode(subcode) {
                Ok(credentials) => {
                    for credential in credentials {
                        // Filter by holder address
                        if credential.subject_address == holder {
                            // Convert to RPC format
                            let info = DocClassCredentialInfo {
                                credential_id: format!("0x{}", hex::encode(credential.credential_id)),
                                subcode: credential.subcode as u16,
                                subcode_name: match credential.subcode {
                                    DocSubcode::AcademicTranscript => "AcademicTranscript".to_string(),
                                    DocSubcode::Diploma => "Diploma".to_string(),
                                    DocSubcode::EnrollmentVerification => "EnrollmentVerification".to_string(),
                                    _ => format!("{:?}", credential.subcode),
                                },
                                subject_commitment: format!("0x{}", hex::encode(credential.subject_commitment)),
                                issuer: credential.issuer.to_base58(),
                                jurisdiction: credential.jurisdiction.clone(),
                                schema_hash: format!("0x{}", hex::encode(credential.schema_hash)),
                                content_commitment: format!("0x{}", hex::encode(credential.content_commitment)),
                                issued_at: credential.issued_at,
                                valid_from: credential.valid_from,
                                expires_at: credential.expires_at,
                                revocation_status: match credential.revocation_status {
                                    sumchain_primitives::docclass::RevocationStatus::Active => "Active".to_string(),
                                    sumchain_primitives::docclass::RevocationStatus::Suspended => "Suspended".to_string(),
                                    sumchain_primitives::docclass::RevocationStatus::Revoked => "Revoked".to_string(),
                                    sumchain_primitives::docclass::RevocationStatus::Superseded => "Superseded".to_string(),
                                    sumchain_primitives::docclass::RevocationStatus::Expired => "Expired".to_string(),
                                },
                                superseded_by: credential.superseded_by.map(|id| format!("0x{}", hex::encode(id))),
                                metadata: Some(DocClassCredentialMetadata {
                                    title: credential.metadata.title,
                                    credential_type: credential.metadata.credential_type,
                                    program: credential.metadata.program,
                                    issue_date: credential.metadata.issue_date,
                                    completion_date: credential.metadata.completion_date,
                                }),
                                payload_hash: credential.payload_hash.map(|h| format!("0x{}", hex::encode(h))),
                                payload_hint: credential.payload_hint.clone(),
                            };
                            results.push(info);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to get credentials for subcode {:?}: {}", subcode, e);
                }
            }
        }

        Ok(results)
    }

    async fn policy_create_account(&self, _request: CreatePolicyAccountRequest) -> std::result::Result<CreatePolicyAccountResponse, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_get_account(&self, _policy_account_id: String) -> std::result::Result<PolicyAccountInfo, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_get_account_by_address(&self, _address: String) -> std::result::Result<Option<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_list_member_accounts(&self, _member_address: String) -> std::result::Result<Vec<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_submit_proposal(&self, _request: SubmitProposalRequest) -> std::result::Result<SubmitProposalResponse, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_execute_proposal(&self, _request: ExecuteProposalRequest) -> std::result::Result<ExecuteProposalResponse, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_cancel_proposal(&self, _request: CancelProposalRequest) -> std::result::Result<CancelProposalResponse, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_get_proposal(&self, _proposal_id: String) -> std::result::Result<ProposalInfo, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_list_proposals(&self, _policy_account_id: String) -> std::result::Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn policy_list_pending_proposals(&self, _policy_account_id: String) -> std::result::Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned> {
        Err(RpcError::Internal("Not yet implemented".to_string()).into())
    }

    async fn storage_get_access_list(
        &self,
        merkle_root: String,
    ) -> std::result::Result<Option<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned> {
        let hash = self.parse_hash(&merkle_root)?;

        let executor = sumchain_state::StorageMetadataExecutor::new(self.db.clone());
        let meta = executor
            .get_metadata(&hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        match meta {
            Some(m) => Ok(Some(serde_json::json!({
                "merkle_root": format!("0x{}", hex::encode(m.merkle_root.as_bytes())),
                "owner": m.owner.to_base58(),
                "total_size_bytes": m.total_size_bytes,
                "access_list": m.access_list.iter().map(|a| a.to_base58()).collect::<Vec<_>>(),
                "fee_pool": m.fee_pool,
                "created_at": m.created_at,
            }))),
            None => Ok(None),
        }
    }

    async fn storage_get_active_challenges(
        &self,
        node_address: String,
    ) -> std::result::Result<Vec<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&node_address)?;

        let executor = sumchain_state::StorageMetadataExecutor::new(self.db.clone());
        let challenges = executor
            .get_challenges_by_node(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let result: Vec<serde_json::Value> = challenges
            .iter()
            .map(|c| serde_json::json!({
                "challenge_id": format!("0x{}", hex::encode(c.challenge_id.as_bytes())),
                "merkle_root": format!("0x{}", hex::encode(c.merkle_root.as_bytes())),
                "chunk_index": c.chunk_index,
                "target_node": c.target_node.to_base58(),
                "created_at_height": c.created_at_height,
                "expires_at_height": c.expires_at_height,
            }))
            .collect();

        Ok(result)
    }

    async fn storage_get_funded_files(
        &self,
    ) -> std::result::Result<Vec<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned> {
        let executor = sumchain_state::StorageMetadataExecutor::new(self.db.clone());

        let roots = executor
            .get_funded_file_roots()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let mut files = Vec::with_capacity(roots.len());
        for root in &roots {
            if let Some(m) = executor
                .get_metadata(root)
                .map_err(|e| RpcError::Internal(e.to_string()))?
            {
                files.push(serde_json::json!({
                    "merkle_root": format!("0x{}", hex::encode(m.merkle_root.as_bytes())),
                    "owner": m.owner.to_base58(),
                    "total_size_bytes": m.total_size_bytes,
                    "access_list": m.access_list.iter().map(|a| a.to_base58()).collect::<Vec<_>>(),
                    "fee_pool": m.fee_pool,
                    "created_at": m.created_at,
                }));
            }
        }

        Ok(files)
    }

    async fn storage_get_node_record(
        &self,
        node_address: String,
    ) -> std::result::Result<Option<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&node_address)?;

        let executor = sumchain_state::NodeRegistryExecutor::new(self.db.clone());
        let record = executor
            .get_node(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        match record {
            Some(r) => Ok(Some(serde_json::json!({
                "address": r.address.to_base58(),
                "role": format!("{:?}", r.role),
                "staked_balance": r.staked_balance,
                "status": format!("{:?}", r.status),
                "registered_at": r.registered_at,
            }))),
            None => Ok(None),
        }
    }

    async fn storage_get_file_info_v2(
        &self,
        merkle_root: String,
        access_offset: Option<u32>,
        access_limit: Option<u32>,
    ) -> std::result::Result<Option<StorageFileInfoV2>, jsonrpsee::types::ErrorObjectOwned> {
        let root = self.parse_hash(&merkle_root)?;
        let offset = access_offset.unwrap_or(0);
        // Default 256, hard cap 1024 — keeps RPC body small on Private files
        // (1024 entries × ~110B = 110 KB, fits comfortably under the default
        // max_response_body_size = 10 MB).
        let limit = access_limit.unwrap_or(256).min(1024);

        let storage = sumchain_state::StorageMetadataExecutor::new(self.db.clone());
        let row = match storage
            .get_metadata_v2(&root)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            Some(r) => r,
            None => return Ok(None),
        };

        let total = row.access_list.len() as u32;
        let start = (offset as usize).min(row.access_list.len());
        let end = start.saturating_add(limit as usize).min(row.access_list.len());
        let window: Vec<AccessEntryRpcV2> = row.access_list[start..end]
            .iter()
            .map(|e| AccessEntryRpcV2 {
                address: e.address.to_base58(),
                encrypted_key_bundle: e
                    .encrypted_key_bundle
                    .as_ref()
                    .map(|b| format!("0x{}", hex::encode(b.0))),
                expires_at: e.expires_at,
            })
            .collect();

        Ok(Some(StorageFileInfoV2 {
            merkle_root: row.merkle_root.to_hex(),
            owner: row.owner.to_base58(),
            plaintext_size_bytes: row.plaintext_size_bytes,
            stored_size_bytes: row.stored_size_bytes,
            chunk_count: row.chunk_count,
            fee_pool: row.fee_pool,
            created_at: row.created_at,
            activated_at_height: row.activated_at_height,
            abandoned_at_height: row.abandoned_at_height,
            assignment_height: row.assignment_height,
            visibility: row.visibility as u8,
            lifecycle: row.lifecycle as u8,
            access_list: window,
            access_total: total,
            access_offset: offset,
            predecessor_root: row.predecessor_root.map(|h| h.to_hex()),
        }))
    }

    async fn storage_get_pushable_files_v2(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<PushableFileInfoV2>, jsonrpsee::types::ErrorObjectOwned> {
        let off = offset.unwrap_or(0) as usize;
        let lim = limit.unwrap_or(256).min(1024) as usize;

        let storage = sumchain_state::StorageMetadataExecutor::new(self.db.clone());
        let mut files = storage
            .list_pushable_files_v2()
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        // RocksDB prefix iteration over `[b'F', b'2', merkle_root]` returns
        // rows in lex-asc order on the merkle_root, so the natural iteration
        // order is already stable. Sort defensively in case storage layout
        // ever changes — cheap relative to the list size.
        files.sort_by(|a, b| a.merkle_root.as_bytes().cmp(b.merkle_root.as_bytes()));

        let start = off.min(files.len());
        let end = start.saturating_add(lim).min(files.len());
        Ok(files[start..end]
            .iter()
            .map(|r| PushableFileInfoV2 {
                merkle_root: r.merkle_root.to_hex(),
                chunk_count: r.chunk_count,
                lifecycle: r.lifecycle as u8,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn storage_get_assignment_coverage_v2(
        &self,
        merkle_root: String,
        missing_offset: Option<u32>,
        missing_limit: Option<u32>,
    ) -> std::result::Result<Option<AssignmentCoverageV2>, jsonrpsee::types::ErrorObjectOwned> {
        let root = self.parse_hash(&merkle_root)?;
        // Default 1024, hard cap 16384 per plan §4.
        let limit = missing_limit.unwrap_or(1024).min(16384);
        let offset = missing_offset.unwrap_or(0);

        let storage = sumchain_state::StorageMetadataExecutor::new(self.db.clone());
        let registry = sumchain_state::NodeRegistryExecutor::new(self.db.clone());

        // Read replication_factor from the consensus params this server was
        // configured with — must match the value the executor uses to
        // validate `AcceptAssignmentV2`, otherwise SNIP clients see wrong
        // `assigned_count` per archive.
        let replication_factor = self.chain_params.assignment_replication_factor;

        let summary = match storage
            .compute_coverage_v2(&root, &registry, replication_factor)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            Some(s) => s,
            None => return Ok(None),
        };

        // Per-archive wire entries. `assigned_count` is `Some(n)` when chunk_count
        // was small enough for the chain to compute it (under the safety cap);
        // otherwise `None` is rendered to JSON — clients with very large files
        // compute counts locally via the deterministic assignment function.
        let per_archive_wire: Vec<ArchiveCoverageSummaryV2> = summary
            .per_archive
            .iter()
            .map(|p| ArchiveCoverageSummaryV2 {
                archive: p.archive.to_base58(),
                assigned_count: p.assigned_count,
                attested_count: p.attested_count,
                currently_active: p.currently_active,
            })
            .collect();

        // Compute missing_indices window: ascending i >= offset where union[i] == 0.
        let mut missing_indices = Vec::new();
        for i in offset..summary.chunk_count {
            if (missing_indices.len() as u32) >= limit {
                break;
            }
            let byte = summary.union.get((i / 8) as usize).copied().unwrap_or(0);
            if (byte >> (i % 8)) & 1 == 0 {
                missing_indices.push(i);
            }
        }

        let missing_total = summary.chunk_count - summary.covered_count;
        let can_activate_now = summary.covered_count == summary.chunk_count
            && summary.lifecycle == sumchain_primitives::FileLifecycleV2::Pending;

        Ok(Some(AssignmentCoverageV2 {
            chunk_count: summary.chunk_count,
            covered_count: summary.covered_count,
            can_activate_now,
            missing_total,
            missing_offset: offset,
            missing_indices,
            per_archive: per_archive_wire,
        }))
    }

    async fn storage_get_active_nodes_at_height(
        &self,
        height: u64,
    ) -> std::result::Result<Vec<NodeRecordInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let executor = sumchain_state::NodeRegistryExecutor::new(self.db.clone());
        let records = executor
            .get_active_archive_nodes_at_height(height)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(records
            .into_iter()
            .map(|r| NodeRecordInfo {
                address: r.address.to_base58(),
                role: format!("{:?}", r.role),
                staked_balance: r.staked_balance,
                status: format!("{:?}", r.status),
                registered_at: r.registered_at,
            })
            .collect())
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
            payload_hash: None,
            payload_hint: None,
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
            payload_hash: credential.payload_hash.map(|h| format!("0x{}", hex::encode(h))),
            payload_hint: credential.payload_hint.clone(),
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

    // Helper methods for employment conversions
    fn employment_issuer_to_rpc(&self, issuer: &sumchain_primitives::employment::EmploymentIssuerProfile) -> EmploymentIssuerInfo {
        EmploymentIssuerInfo {
            issuer_address: issuer.issuer_address.to_base58(),
            issuer_class: format!("{:?}", issuer.issuer_class),
            display_name: issuer.display_name.clone(),
            issuer_commitment: format!("0x{}", hex::encode(issuer.issuer_commitment)),
            jurisdiction: issuer.jurisdiction_code.clone(),
            policy_id: format!("0x{}", hex::encode(issuer.policy_id)),
            status: format!("{:?}", issuer.status),
            risk_level: issuer.issuer_class.default_risk_level().name().to_string(),
            registered_at_height: issuer.registered_at_height,
            created_at: issuer.created_at,
            updated_at: issuer.updated_at,
        }
    }

    fn employment_credential_to_rpc(&self, cred: &sumchain_primitives::employment::EmploymentCredential, current_time: u64) -> EmploymentCredentialInfo {
        EmploymentCredentialInfo {
            employment_id: format!("0x{}", hex::encode(cred.employment_id)),
            employee_address: cred.employee_address.to_base58(),
            employee_ref: format!("0x{}", hex::encode(cred.employee_ref)),
            employer_ref: format!("0x{}", hex::encode(cred.employer_ref)),
            status: cred.status.name().to_string(),
            tenure_commitment: format!("0x{}", hex::encode(cred.tenure_commitment)),
            role_commitment: cred.role_commitment.map(|r| format!("0x{}", hex::encode(r))),
            employment_type: format!("{:?}", cred.employment_type),
            valid_from: cred.valid_from,
            expiry: cred.expiry,
            policy_id: format!("0x{}", hex::encode(cred.policy_id)),
            revocation_ref: cred.revocation_ref.map(|r| format!("0x{}", hex::encode(r))),
            issuer_address: cred.issuer_address.to_base58(),
            issuer_name: cred.issuer_name.clone(),
            issuer_class: format!("{:?}", cred.issuer_class),
            is_valid: cred.is_valid(current_time),
            created_at: cred.created_at,
            updated_at: cred.updated_at,
        }
    }

    fn income_attestation_to_rpc(&self, att: &sumchain_primitives::employment::IncomeAttestation, current_time: u64) -> IncomeAttestationInfo {
        IncomeAttestationInfo {
            attestation_id: format!("0x{}", hex::encode(att.attestation_id)),
            holder_address: att.holder_address.to_base58(),
            subject_ref: format!("0x{}", hex::encode(att.subject_ref)),
            employment_id: att.employment_id.map(|e| format!("0x{}", hex::encode(e))),
            bracket_commitment: att.threshold_commitment.map(|c| format!("0x{}", hex::encode(c))).unwrap_or_else(|| "none".to_string()),
            period_commitment: format!("0x{}", hex::encode(att.period_commitment)),
            currency_code: format!("{:?}", att.income_bracket),
            attestation_type: format!("{:?}", att.period_type),
            valid_from: att.valid_from,
            expiry: att.expiry,
            policy_id: format!("0x{}", hex::encode(att.policy_id)),
            issuer_address: att.issuer_address.to_base58(),
            is_valid: att.is_valid(current_time),
            created_at: att.created_at,
        }
    }
}

// ============================================================================
// Phase 0b checkpoint 1 — RPC contract tests (SNIP V2 Asks 8, 11)
//
// These tests cover the dispatch logic and JSON wire shape for
// chain_getBlockHeight + chain_getTransactionStatus without requiring a full
// RpcServer harness. The dispatch logic is in `classify_tx_status` (above);
// for `chain_getBlockHeight`, the parameter→branch mapping is exercised
// indirectly via the `BlockHeightInfo` JSON shape tests since that contract
// is what SNIP serializes against.
// ============================================================================
#[cfg(test)]
mod phase_0b_rpc_tests {
    use super::*;
    use sumchain_primitives::{Hash, Receipt, TxStatus};

    fn mk_receipt(status: TxStatus, block_height: u64) -> Receipt {
        Receipt::new(Hash::hash(b"tx"), block_height, 0, status, 10)
    }

    // ------- classify_tx_status --------------------------------------------

    #[test]
    fn classify_unknown_when_no_receipt_and_no_mempool() {
        let s = classify_tx_status(None, false, |_| true);
        assert!(matches!(s, TxStatusV2::Unknown));
    }

    #[test]
    fn classify_pending_when_in_mempool_only() {
        let s = classify_tx_status(None, true, |_| true);
        assert!(matches!(s, TxStatusV2::Pending));
    }

    #[test]
    fn classify_finalized_when_success_receipt_in_finalized_block() {
        let r = mk_receipt(TxStatus::Success, 42);
        let s = classify_tx_status(Some(&r), false, |h| h == 42);
        assert!(matches!(s, TxStatusV2::Finalized { block_height: 42 }));
    }

    #[test]
    fn classify_included_when_success_receipt_in_unfinalized_block() {
        let r = mk_receipt(TxStatus::Success, 42);
        let s = classify_tx_status(Some(&r), false, |_| false);
        assert!(matches!(s, TxStatusV2::Included { block_height: 42 }));
    }

    #[test]
    fn classify_failed_carries_block_height_and_reason() {
        let r = mk_receipt(TxStatus::InvalidNonce, 17);
        let s = classify_tx_status(Some(&r), false, |_| true);
        match s {
            TxStatusV2::Failed { block_height, reason } => {
                assert_eq!(block_height, Some(17));
                assert_eq!(reason, "invalid nonce");
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn classify_failed_does_not_depend_on_finality() {
        // Documented caveat: Failed { block_height } is returned regardless
        // of whether the block is finalized. SNIP treats this as terminal.
        let r = mk_receipt(TxStatus::Failed(7), 99);
        let finalized = classify_tx_status(Some(&r), false, |_| true);
        let unfinalized = classify_tx_status(Some(&r), false, |_| false);
        assert!(matches!(finalized,   TxStatusV2::Failed { block_height: Some(99), .. }));
        assert!(matches!(unfinalized, TxStatusV2::Failed { block_height: Some(99), .. }));
    }

    #[test]
    fn classify_receipt_takes_precedence_over_mempool() {
        // Edge case: tx is both in receipt store and mempool (e.g., mempool
        // hasn't pruned yet after inclusion). Receipt wins.
        let r = mk_receipt(TxStatus::Success, 5);
        let s = classify_tx_status(Some(&r), true, |h| h == 5);
        assert!(matches!(s, TxStatusV2::Finalized { block_height: 5 }));
    }

    // ------- TxStatusV2 JSON wire shape ------------------------------------

    #[test]
    fn tx_status_v2_json_shape_unknown() {
        let json = serde_json::to_value(&TxStatusV2::Unknown).unwrap();
        assert_eq!(json, serde_json::json!({ "kind": "unknown" }));
    }

    #[test]
    fn tx_status_v2_json_shape_pending() {
        let json = serde_json::to_value(&TxStatusV2::Pending).unwrap();
        assert_eq!(json, serde_json::json!({ "kind": "pending" }));
    }

    #[test]
    fn tx_status_v2_json_shape_included() {
        let json = serde_json::to_value(&TxStatusV2::Included { block_height: 42 }).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "included", "block_height": 42 })
        );
    }

    #[test]
    fn tx_status_v2_json_shape_finalized() {
        let json = serde_json::to_value(&TxStatusV2::Finalized { block_height: 100 }).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "finalized", "block_height": 100 })
        );
    }

    #[test]
    fn tx_status_v2_json_shape_failed_with_height() {
        let v = TxStatusV2::Failed {
            block_height: Some(7),
            reason: "invalid nonce".to_string(),
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "failed", "block_height": 7, "reason": "invalid nonce" })
        );
    }

    #[test]
    fn tx_status_v2_json_shape_failed_without_height() {
        let v = TxStatusV2::Failed {
            block_height: None,
            reason: "rejected".to_string(),
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "failed", "block_height": null, "reason": "rejected" })
        );
    }

    #[test]
    fn tx_status_v2_json_round_trip() {
        let cases = vec![
            TxStatusV2::Unknown,
            TxStatusV2::Pending,
            TxStatusV2::Included { block_height: 1 },
            TxStatusV2::Finalized { block_height: 2 },
            TxStatusV2::Failed { block_height: Some(3), reason: "x".to_string() },
            TxStatusV2::Dropped,
        ];
        for c in cases {
            let s = serde_json::to_string(&c).unwrap();
            let back: TxStatusV2 = serde_json::from_str(&s).unwrap();
            // PartialEq isn't derived; compare via re-serialization.
            assert_eq!(s, serde_json::to_string(&back).unwrap());
        }
    }

    // ------- BlockHeightInfo JSON wire shape -------------------------------

    #[test]
    fn block_height_info_json_shape() {
        let v = BlockHeightInfo { height: 42, finality: "finalized".to_string() };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json, serde_json::json!({ "height": 42, "finality": "finalized" }));
    }

    #[test]
    fn block_height_info_round_trip() {
        let v = BlockHeightInfo { height: 7, finality: "latest".to_string() };
        let s = serde_json::to_string(&v).unwrap();
        let back: BlockHeightInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(back.height, 7);
        assert_eq!(back.finality, "latest");
    }

    // ------- NodeRecordInfo JSON wire shape (Ask 15) ------------------------

    #[test]
    fn node_record_info_json_shape() {
        let v = NodeRecordInfo {
            address: "1A1zP1eP".to_string(),
            role: "ArchiveNode".to_string(),
            staked_balance: 1_000_000_000,
            status: "Active".to_string(),
            registered_at: 42,
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "address": "1A1zP1eP",
                "role": "ArchiveNode",
                "staked_balance": 1_000_000_000u64,
                "status": "Active",
                "registered_at": 42u64,
            })
        );
    }

    // ------- AssignmentCoverageV2 JSON wire shape (Phase 1b, Ask 12) ---------

    /// Plan v3.2 §4 — wire-shape lock. SNIP clients serialize against this
    /// struct; field-name drift or `Option<u32>` → `u32` regressions break
    /// SNIP code that already shipped against the documented shape.
    #[test]
    fn assignment_coverage_v2_json_shape() {
        let v = AssignmentCoverageV2 {
            chunk_count: 4,
            covered_count: 3,
            can_activate_now: false,
            missing_total: 1,
            missing_offset: 0,
            missing_indices: vec![3],
            per_archive: vec![ArchiveCoverageSummaryV2 {
                archive: "ArchiveAddr1".to_string(),
                assigned_count: Some(2),
                attested_count: 2,
                currently_active: true,
            }],
        };
        let got = serde_json::to_value(&v).unwrap();
        let want = serde_json::json!({
            "chunk_count": 4,
            "covered_count": 3,
            "can_activate_now": false,
            "missing_total": 1,
            "missing_offset": 0,
            "missing_indices": [3],
            "per_archive": [{
                "archive": "ArchiveAddr1",
                "assigned_count": 2,
                "attested_count": 2,
                "currently_active": true,
            }],
        });
        assert_eq!(got, want);
    }

    /// `assigned_count == None` (large-file path, above the
    /// MAX_ASSIGNED_COUNT_CHUNK_COUNT cap) must serialize as JSON null —
    /// SNIP clients use that as the signal to compute counts locally via the
    /// deterministic assignment function.
    #[test]
    fn assignment_coverage_v2_assigned_count_none_serializes_as_null() {
        let v = AssignmentCoverageV2 {
            chunk_count: 100_000,
            covered_count: 0,
            can_activate_now: false,
            missing_total: 100_000,
            missing_offset: 0,
            missing_indices: Vec::new(),
            per_archive: vec![ArchiveCoverageSummaryV2 {
                archive: "BigArchive".to_string(),
                assigned_count: None,
                attested_count: 0,
                currently_active: true,
            }],
        };
        let got = serde_json::to_value(&v).unwrap();
        assert_eq!(
            got["per_archive"][0]["assigned_count"],
            serde_json::Value::Null
        );
    }

    /// Round-trip — every field deserializes back to the same value, locking
    /// the deserialize side too (catches the case where a SNIP client serializes
    /// the struct, sends it back, and we have to read it).
    #[test]
    fn assignment_coverage_v2_round_trip() {
        let v = AssignmentCoverageV2 {
            chunk_count: 16,
            covered_count: 10,
            can_activate_now: false,
            missing_total: 6,
            missing_offset: 4,
            missing_indices: vec![6, 8, 9, 12, 14, 15],
            per_archive: vec![
                ArchiveCoverageSummaryV2 {
                    archive: "A".to_string(),
                    assigned_count: Some(5),
                    attested_count: 4,
                    currently_active: true,
                },
                ArchiveCoverageSummaryV2 {
                    archive: "B".to_string(),
                    assigned_count: None,
                    attested_count: 6,
                    currently_active: false,
                },
            ],
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: AssignmentCoverageV2 = serde_json::from_str(&s).unwrap();
        // Re-serialize and compare strings — PartialEq isn't derived on the type.
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
    }

    // ------- StorageFileInfoV2 / PushableFileInfoV2 JSON wire shapes (Phase 1c, Asks 4/6/9/12/13) -------

    #[test]
    fn storage_file_info_v2_json_shape() {
        let v = StorageFileInfoV2 {
            merkle_root: "deadbeef".to_string(),
            owner: "OwnerAddr".to_string(),
            plaintext_size_bytes: 1024,
            stored_size_bytes: 1024,
            chunk_count: 1,
            fee_pool: 5_000_000,
            created_at: 100,
            activated_at_height: Some(105),
            abandoned_at_height: None,
            assignment_height: 100,
            visibility: 0,
            lifecycle: 1,
            access_list: vec![AccessEntryRpcV2 {
                address: "Recipient1".to_string(),
                encrypted_key_bundle: None,
                expires_at: None,
            }],
            access_total: 1,
            access_offset: 0,
            predecessor_root: None,
        };
        let got = serde_json::to_value(&v).unwrap();
        let want = serde_json::json!({
            "merkle_root": "deadbeef",
            "owner": "OwnerAddr",
            "plaintext_size_bytes": 1024,
            "stored_size_bytes": 1024,
            "chunk_count": 1,
            "fee_pool": 5000000,
            "created_at": 100,
            "activated_at_height": 105,
            "abandoned_at_height": null,
            "assignment_height": 100,
            "visibility": 0,
            "lifecycle": 1,
            "access_list": [{
                "address": "Recipient1",
                "encrypted_key_bundle": null,
                "expires_at": null,
            }],
            "access_total": 1,
            "access_offset": 0,
            "predecessor_root": null,
        });
        assert_eq!(got, want);
    }

    /// Private file: `encrypted_key_bundle` serializes as `0x`-prefixed hex.
    #[test]
    fn access_entry_rpc_v2_private_bundle_serializes_as_hex() {
        let e = AccessEntryRpcV2 {
            address: "PrivAddr".to_string(),
            encrypted_key_bundle: Some(format!("0x{}", "ab".repeat(80))),
            expires_at: Some(12345),
        };
        let got = serde_json::to_value(&e).unwrap();
        assert_eq!(got["encrypted_key_bundle"].as_str().unwrap().len(), 162); // 0x + 160 hex chars
        assert!(got["encrypted_key_bundle"].as_str().unwrap().starts_with("0x"));
        assert_eq!(got["expires_at"], 12345);
    }

    #[test]
    fn pushable_file_info_v2_json_shape() {
        let v = PushableFileInfoV2 {
            merkle_root: "abc123".to_string(),
            chunk_count: 8,
            lifecycle: 0, // Pending
            created_at: 50,
        };
        let got = serde_json::to_value(&v).unwrap();
        assert_eq!(
            got,
            serde_json::json!({
                "merkle_root": "abc123",
                "chunk_count": 8,
                "lifecycle": 0,
                "created_at": 50,
            })
        );
    }

    #[test]
    fn storage_file_info_v2_round_trip() {
        let v = StorageFileInfoV2 {
            merkle_root: "rt".to_string(),
            owner: "owner".to_string(),
            plaintext_size_bytes: 1,
            stored_size_bytes: 1,
            chunk_count: 1,
            fee_pool: 0,
            created_at: 0,
            activated_at_height: None,
            abandoned_at_height: Some(42),
            assignment_height: 0,
            visibility: 1,
            lifecycle: 2, // Abandoned — sets abandoned_at_height to Some
            access_list: Vec::new(),
            access_total: 0,
            access_offset: 0,
            predecessor_root: Some("predecessor-hash".to_string()),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: StorageFileInfoV2 = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
    }

    // ------- ChainParamsInfo JSON wire shape (Phase 2) ----------------------

    /// Plan v3.2 + reviewer advice: `chain_getChainParams` must return live
    /// values, never hardcoded library defaults. This shape test locks the
    /// flat layout (no nested sub-configs) and JSON field names so SNIP
    /// clients can deserialize stably.
    #[test]
    fn chain_params_info_json_shape() {
        let v = ChainParamsInfo {
            chain_id: 1337,
            block_time_ms: 2000,
            max_block_bytes: 1_000_000,
            max_txs_per_block: 1000,
            min_fee: 1,
            finality_depth: 3,
            storage_fee_per_byte: 100,
            max_metadata_bytes: 16_384,
            max_access_list_bytes: 16_384,
            activation_grace_blocks: 50,
            abandonment_fee_percent: 10,
            max_chunk_count_per_file: 1_048_576,
            max_chunk_indices_per_tx: 65_536,
            assignment_replication_factor: 3,
            v2_enabled_from_height: None,  // disabled (production-safe default)
        };
        let got = serde_json::to_value(&v).unwrap();
        let want = serde_json::json!({
            "chain_id": 1337,
            "block_time_ms": 2000,
            "max_block_bytes": 1_000_000,
            "max_txs_per_block": 1000,
            "min_fee": 1,
            "finality_depth": 3,
            "storage_fee_per_byte": 100,
            "max_metadata_bytes": 16_384,
            "max_access_list_bytes": 16_384,
            "activation_grace_blocks": 50,
            "abandonment_fee_percent": 10,
            "max_chunk_count_per_file": 1_048_576,
            "max_chunk_indices_per_tx": 65_536,
            "assignment_replication_factor": 3,
            "v2_enabled_from_height": null,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn chain_params_info_round_trip() {
        let v = ChainParamsInfo {
            chain_id: 9001,
            block_time_ms: 3000,
            max_block_bytes: 2_000_000,
            max_txs_per_block: 500,
            min_fee: 100_000,
            finality_depth: 6,
            storage_fee_per_byte: 200,
            max_metadata_bytes: 32_768,
            max_access_list_bytes: 32_768,
            activation_grace_blocks: 150,
            abandonment_fee_percent: 5,
            max_chunk_count_per_file: 524_288,
            max_chunk_indices_per_tx: 32_768,
            assignment_replication_factor: 5,
            v2_enabled_from_height: Some(1_000_000),  // activation height
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChainParamsInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
    }

    #[test]
    fn node_record_info_round_trip() {
        let v = NodeRecordInfo {
            address: "TestAddr".to_string(),
            role: "ArchiveNode".to_string(),
            staked_balance: 12345,
            status: "Slashed".to_string(),
            registered_at: 100,
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: NodeRecordInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(back.address, "TestAddr");
        assert_eq!(back.role, "ArchiveNode");
        assert_eq!(back.staked_balance, 12345);
        assert_eq!(back.status, "Slashed");
        assert_eq!(back.registered_at, 100);
    }
}


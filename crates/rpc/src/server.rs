//! RPC server implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use jsonrpsee::server::{Server, ServerHandle};
use sumchain_consensus::ConsensusEngine;
use sumchain_primitives::{Address, Block, Hash, SignedTransaction, MessagingTxData, MessagingOperation, SponsoredMessage, TxPayload};
use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
use sumchain_state::education_executor::{
    EducationExecutor, StoredAssessment, StoredCatalogEntry, StoredEnrollmentLink,
    StoredGradeRecord, StoredOffering, StoredSubmissionReceipt, MAX_EDU_LIST_LIMIT,
};
use sumchain_state::{Mempool, StateManager};
use sumchain_storage::{BlockStore, Database, DelegationStore, DocClassStore, EmploymentCredentialStore, EmploymentIssuerStore, IncomeAttestationStore, MessagingStore, NftStore, PolicyAccountStorage, ReceiptStore, SlashingStore, StakingStore, TokenStore, TxIndexStore, TxStore, ValidatorSetStore, MESSAGING_LIST_DEFAULT};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::api::SumChainApiServer;
use crate::auth::{ApiKeyValidator, RpcAuthConfig};
use crate::health::HealthCheck;
use crate::metrics::{Metrics, MetricsSnapshot};
use crate::governance_types::*;
use crate::policy_account_types::*;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::types::*;
use crate::{RpcError, Result};

/// Node version constant
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default fee (Koppa base units) for policy-account builder helpers when the
/// request omits one. Matches the house default used by other write builders
/// (0.001 Koppa).
const POLICY_DEFAULT_FEE: u128 = 1_000_000;
const GOV_DEFAULT_FEE: u128 = 1_000_000;

/// Parse a Tax issuer class from its variant name (as emitted by the read
/// DTOs) for the `tax_getIssuersByClass` filter.
fn parse_tax_issuer_class(s: &str) -> Option<sumchain_primitives::tax::TaxIssuerClass> {
    use sumchain_primitives::tax::TaxIssuerClass;
    match s {
        "TaxAuthority" => Some(TaxIssuerClass::TaxAuthority),
        "EmployerPayroll" => Some(TaxIssuerClass::EmployerPayroll),
        "BankBroker" => Some(TaxIssuerClass::BankBroker),
        "AuditorCpa" => Some(TaxIssuerClass::AuditorCpa),
        "TaxFilingProvider" => Some(TaxIssuerClass::TaxFilingProvider),
        _ => None,
    }
}

/// Parse an Equity org type from its variant name (as emitted by the read
/// DTOs) for the `equity_getEntitiesByOrgType` filter.
fn parse_equity_org_type(s: &str) -> Option<sumchain_primitives::equity::OrgType> {
    use sumchain_primitives::equity::OrgType;
    match s {
        "Corporation" => Some(OrgType::Corporation),
        "LLC" => Some(OrgType::LLC),
        "Partnership" => Some(OrgType::Partnership),
        "DAO" => Some(OrgType::DAO),
        "Foundation" => Some(OrgType::Foundation),
        "Trust" => Some(OrgType::Trust),
        "Cooperative" => Some(OrgType::Cooperative),
        "Other" => Some(OrgType::Other),
        _ => None,
    }
}

/// SRC-871 institutional-provider allowlist (issue #41). Default-deny: only
/// these organizational provider types are exposed via the healthcare provider
/// reads. Every other type — individual clinicians, non-allowlisted org/plan
/// types, membership orgs, and `Other` — is excluded.
fn is_institutional_provider(t: sumchain_primitives::healthcare::ProviderType) -> bool {
    use sumchain_primitives::healthcare::ProviderType;
    matches!(
        t,
        ProviderType::Hospital
            | ProviderType::HealthInsurer
            | ProviderType::Clinic
            | ProviderType::Pharmacy
            | ProviderType::Laboratory
    )
}

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
    /// Whether a contract executor is wired (powers contract_* RPCs). Used by
    /// the node crate's production-wiring tripwire test.
    pub fn has_contract_executor(&self) -> bool {
        self.contract_executor.is_some()
    }

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

    /// Derive read-time semantic labels for a transaction from its already-public
    /// payload. Returns `(tx_type, action, asset_ref, asset_kind)`.
    ///
    /// Nothing here is persisted or inferred beyond what the payload proves:
    /// `tx_type`/`action` are the enum variant identifiers, `asset_ref` is a
    /// direct payload field (SRC-20 `token_id` / NFT `collection_id`), and
    /// `asset_kind` is a coarse class hint. Consumers (SDK/explorer/SUMaillet)
    /// map these stable machine tokens to human labels.
    fn tx_semantics(
        tx: &SignedTransaction,
    ) -> (String, Option<String>, Option<String>, Option<String>) {
        use sumchain_primitives::{TxInner, TxType};

        // Leading variant identifier of a `{:?}` rendering, so struct/tuple
        // variants that carry fields still yield a clean token.
        fn ident(dbg: String) -> String {
            dbg.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect()
        }
        fn to_hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }

        let tx_type = match tx.tx_type() {
            TxType::Transfer => "Transfer",
            TxType::Nft => "Nft",
            TxType::Token => "Token",
            TxType::ContractDeploy => "ContractDeploy",
            TxType::ContractCall => "ContractCall",
            TxType::Staking => "Staking",
            TxType::Messaging => "Messaging",
            TxType::DocClass => "DocClass",
            TxType::Tax => "Tax",
            TxType::Equity => "Equity",
            TxType::Agreement => "Agreement",
            TxType::Legal => "Legal",
            TxType::Property => "Property",
            TxType::Healthcare => "Healthcare",
            TxType::Employment => "Employment",
            TxType::Finance => "Finance",
            TxType::PolicyAccount => "PolicyAccount",
            TxType::NodeRegistry => "NodeRegistry",
            TxType::StorageMetadata => "StorageMetadata",
            TxType::NodeRegistryV2 => "NodeRegistryV2",
            TxType::StorageMetadataV2 => "StorageMetadataV2",
            TxType::InferenceAttestation => "InferenceAttestation",
            TxType::Education => "Education",
            TxType::Governance => "Governance",
            TxType::InferenceSettlement => "InferenceSettlement",
        }
        .to_string();

        let payload = match &tx.inner {
            // Legacy envelope is always a native Koppa transfer.
            TxInner::Legacy(_) => {
                return (tx_type, None, None, Some("native".to_string()));
            }
            TxInner::V2(v2) => &v2.payload,
        };

        let action = match payload {
            TxPayload::Transfer { .. }
            | TxPayload::ContractDeploy(_)
            | TxPayload::ContractCall(_)
            | TxPayload::InferenceAttestation(_) => None,
            TxPayload::Nft(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Token(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Staking(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Messaging(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::DocClass(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Tax(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Equity(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Agreement(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Legal(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Property(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Healthcare(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Employment(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Finance(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::PolicyAccount(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::NodeRegistry(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::StorageMetadata(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::NodeRegistryV2(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::StorageMetadataV2(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Governance(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::InferenceSettlement(d) => Some(ident(format!("{:?}", d.operation))),
            TxPayload::Education(d) => {
                Some(format!("{}Op{}", ident(format!("{:?}", d.standard)), d.operation))
            }
        };

        let asset_ref = match payload {
            TxPayload::Token(d) => {
                if d.token_id == [0u8; 32] {
                    None
                } else {
                    Some(to_hex(&d.token_id))
                }
            }
            TxPayload::Nft(d) => Some(to_hex(&d.collection_id)),
            _ => None,
        };

        let asset_kind = match payload {
            TxPayload::Transfer { .. } => Some("native"),
            TxPayload::Token(_) => Some("src20"),
            TxPayload::Nft(_) => Some("nft"),
            _ => None,
        }
        .map(|s| s.to_string());

        (tx_type, action, asset_ref, asset_kind)
    }

    /// Convert transaction to RPC type
    fn tx_to_info(&self, tx: &SignedTransaction, receipt: Option<&sumchain_primitives::Receipt>) -> TransactionInfo {
        let (tx_type, action, asset_ref, asset_kind) = Self::tx_semantics(tx);
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
            tx_type,
            action,
            asset_ref,
            asset_kind,
        }
    }

    /// Parse address from string
    fn parse_address(&self, s: &str) -> Result<Address> {
        Address::from_base58(s)
            .or_else(|_| Address::from_hex(s))
            .map_err(|_| RpcError::InvalidParams(format!("Invalid address: {}", s)))
    }

    /// Assemble an unsigned policy-account `TransactionV2`, filling chain id and
    /// the sender's current nonce. Returns bincode(tx) hex + signing hash. The
    /// builder never signs; the client signs `signing_hash` with the `from`
    /// key and submits the resulting transaction via `sum_sendRawTransaction`.
    fn build_unsigned_policy_tx(
        &self,
        from: Address,
        fee: u128,
        data: sumchain_primitives::policy_account::PolicyAccountTxData,
    ) -> Result<PolicyBuildResponse> {
        use sumchain_primitives::{TransactionV2, TxPayload};
        let nonce = self
            .state
            .get_nonce(&from)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;
        let chain_id = self.state.chain_id();
        let tx = TransactionV2 {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::PolicyAccount(data),
        };
        let signing_hash = tx.signing_hash();
        let unsigned = bincode::serialize(&tx)
            .map_err(|e| RpcError::Internal(format!("Failed to encode tx: {}", e)))?;
        Ok(PolicyBuildResponse {
            unsigned_tx: format!("0x{}", hex::encode(unsigned)),
            signing_hash: format!("0x{}", hex::encode(signing_hash.as_bytes())),
            from: from.to_base58(),
            nonce,
            fee,
            chain_id,
            policy_account_id: None,
            address: None,
            proposal_id: None,
            action_hash: None,
        })
    }

    /// Build an unsigned `TxPayload::Governance` transaction (no private key).
    /// Fills `chain_id` + `nonce`; returns the unsigned bytes + signing hash.
    fn build_unsigned_governance_tx(
        &self,
        from: Address,
        fee: u128,
        data: sumchain_primitives::governance::GovernanceTxData,
    ) -> Result<GovBuildResponse> {
        use sumchain_primitives::{TransactionV2, TxPayload};
        let nonce = self
            .state
            .get_nonce(&from)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;
        let chain_id = self.state.chain_id();
        let tx = TransactionV2 { chain_id, from, fee, nonce, payload: TxPayload::Governance(data) };
        let signing_hash = tx.signing_hash();
        let unsigned = bincode::serialize(&tx)
            .map_err(|e| RpcError::Internal(format!("Failed to encode tx: {}", e)))?;
        Ok(GovBuildResponse {
            unsigned_tx: format!("0x{}", hex::encode(unsigned)),
            signing_hash: format!("0x{}", hex::encode(signing_hash.as_bytes())),
            from: from.to_base58(),
            nonce,
            fee,
            chain_id,
            // The proposal id depends on the execution block height (unknown at
            // build time); discover via gov_listProposals after inclusion.
            proposal_id: None,
        })
    }

    /// Build an unsigned `TransactionV2` carrying an inference-settlement
    /// operation (issue #61). No private keys — returns the hex-encoded unsigned
    /// tx + signing hash for the client to sign.
    fn build_unsigned_settlement_tx(
        &self,
        from: Address,
        fee: u128,
        operation: sumchain_primitives::inference_settlement::InferenceSettlementOperation,
    ) -> std::result::Result<
        crate::inference_settlement_types::OmniSettlementBuildResponse,
        jsonrpsee::types::ErrorObjectOwned,
    > {
        use sumchain_primitives::inference_settlement::InferenceSettlementTxData;
        use sumchain_primitives::{TransactionV2, TxPayload};
        let nonce = self
            .state
            .get_nonce(&from)
            .map_err(|e| RpcError::Internal(format!("Failed to get nonce: {}", e)))?;
        let chain_id = self.state.chain_id();
        let data = InferenceSettlementTxData { operation };
        let tx = TransactionV2 {
            chain_id,
            from,
            fee,
            nonce,
            payload: TxPayload::InferenceSettlement(data),
        };
        let signing_hash = tx.signing_hash();
        let unsigned = bincode::serialize(&tx)
            .map_err(|e| RpcError::Internal(format!("Failed to encode tx: {}", e)))?;
        Ok(crate::inference_settlement_types::OmniSettlementBuildResponse {
            unsigned_tx: format!("0x{}", hex::encode(unsigned)),
            signing_hash: format!("0x{}", hex::encode(signing_hash.as_bytes())),
            from: from.to_base58(),
            nonce,
            fee,
            chain_id,
        })
    }

    /// Convert an on-disk `InferenceAttestationRecord` to its RPC view.
    /// All binary fields hex-encoded with `0x` prefix; addresses use
    /// base58 with checksum (chain's canonical Address::to_base58).
    /// `finalized` is computed against live chain height + chain-param
    /// `finality_depth` — same convention as `is_block_finalized` RPC.
    fn attestation_record_to_info(
        &self,
        record: &sumchain_primitives::inference_attestation::InferenceAttestationRecord,
        verifier_address: &Address,
    ) -> crate::types::InferenceAttestationInfo {
        let current = self.consensus.current_height();
        let finality_depth = self.consensus.finality_depth();
        let finalized = current >= record.included_at_height.saturating_add(finality_depth);
        crate::types::InferenceAttestationInfo {
            session_id: record.digest.session_id.clone(),
            verifier_address: verifier_address.to_base58(),
            model_hash: format!("0x{}", hex::encode(record.digest.model_hash)),
            manifest_root: format!("0x{}", hex::encode(record.digest.manifest_root)),
            response_hash: format!("0x{}", hex::encode(record.digest.response_hash)),
            proof_root: format!("0x{}", hex::encode(record.digest.proof_root)),
            verifier_signature: format!("0x{}", hex::encode(record.verifier_signature)),
            included_at_height: record.included_at_height,
            tx_hash: record.tx_hash.to_hex(),
            finalized,
        }
    }

    /// Parse a `0x`-prefixed (or bare) 64-hex-char string into `[u8;32]`.
    /// Used for education id/commitment params (never an address).
    fn parse_hex32(&self, s: &str) -> Result<[u8; 32]> {
        edu_parse_hex32(s).map_err(RpcError::InvalidParams)
    }

    /// Decode builder-supplied validator approvals (hex pubkey + hex signature)
    /// into wire `ValidatorApproval`s embedded in the unsigned tx.
    fn parse_approvals(
        &self,
        inputs: &[crate::types::ValidatorApprovalInput],
    ) -> Result<Vec<sumchain_primitives::ValidatorApproval>> {
        inputs
            .iter()
            .map(|a| {
                let pk = hex::decode(a.pubkey.trim_start_matches("0x"))
                    .map_err(|_| RpcError::InvalidParams("invalid approval pubkey hex".into()))?;
                let sig = hex::decode(a.signature.trim_start_matches("0x"))
                    .map_err(|_| RpcError::InvalidParams("invalid approval signature hex".into()))?;
                let pubkey: [u8; 32] = pk
                    .try_into()
                    .map_err(|_| RpcError::InvalidParams("approval pubkey must be 32 bytes".into()))?;
                let signature: [u8; 64] = sig.try_into().map_err(|_| {
                    RpcError::InvalidParams("approval signature must be 64 bytes".into())
                })?;
                Ok(sumchain_primitives::ValidatorApproval { pubkey, signature })
            })
            .collect()
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
            omninode_enabled_from_height: p.omninode_enabled_from_height,
            education_enabled_from_height: p.education_enabled_from_height,
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

    // ====================================================================
    // OmniNode `InferenceAttestation` endpoints (Phase 4 read-only RPC)
    // ====================================================================

    async fn sum_get_inference_attestation(
        &self,
        session_id: String,
        verifier_address: String,
    ) -> std::result::Result<Option<crate::types::InferenceAttestationInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::inference_attestation::inference_attestation_key;
        let addr = self.parse_address(&verifier_address)?;
        let key = inference_attestation_key(&session_id, &addr);
        let executor = InferenceAttestationExecutor::new(self.db.clone());
        let maybe = executor
            .get(&key)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(maybe.map(|record| self.attestation_record_to_info(&record, &addr)))
    }

    async fn sum_list_inference_attestations(
        &self,
        session_id: String,
    ) -> std::result::Result<Vec<crate::types::InferenceAttestationInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::inference_attestation::inference_attestation_key;
        let executor = InferenceAttestationExecutor::new(self.db.clone());
        let verifiers = executor
            .list_verifiers_by_session(&session_id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        let mut out = Vec::with_capacity(verifiers.len());
        for verifier in verifiers {
            let key = inference_attestation_key(&session_id, &verifier);
            if let Some(record) = executor
                .get(&key)
                .map_err(|e| RpcError::Internal(e.to_string()))?
            {
                out.push(self.attestation_record_to_info(&record, &verifier));
            }
        }
        Ok(out)
    }

    async fn sum_get_inference_attestation_status(
        &self,
        tx_hash: String,
    ) -> std::result::Result<crate::types::InferenceAttestationStatusInfo, jsonrpsee::types::ErrorObjectOwned> {
        let hash = self.parse_hash(&tx_hash)?;

        // Fetch the four inputs the pure classifier needs.
        let tx_store = TxStore::new(&self.db);
        let stored_tx = tx_store
            .get(&hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        let mempool_tx = self.mempool.get(&hash);
        let receipt_store = ReceiptStore::new(&self.db);
        let receipt = receipt_store
            .get(&hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(sumchain_primitives::inference_attestation::classify_inference_attestation_status(
            stored_tx.as_ref(),
            mempool_tx.as_ref(),
            receipt.as_ref(),
            self.consensus.current_height(),
            self.consensus.finality_depth(),
        ))
    }

    // ========================================================================
    // SRC-817/818 Education suite — read-only RPC (Phase 4)
    // Read-only: never touches executor/mempool/fee/nonce. Reads work
    // regardless of the education activation gate. Student lookup is
    // ONLY by `student_commitment` (a hash, never an address).
    // ========================================================================

    async fn src817_get_catalog_entry(
        &self,
        catalog_id: String,
    ) -> std::result::Result<Option<CatalogEntryInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&catalog_id)?;
        let ex = EducationExecutor::new(self.db.clone());
        let rec = ex.get_catalog(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rec.as_ref().map(edu_catalog_to_info))
    }

    async fn src817_get_catalog_content(
        &self,
        catalog_id: String,
    ) -> std::result::Result<Vec<CatalogContentRefInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&catalog_id)?;
        let ex = EducationExecutor::new(self.db.clone());
        let rows = ex
            .get_catalog_content(&id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|(kind, m)| CatalogContentRefInfo {
                kind,
                kind_label: edu_content_kind_label(kind),
                r#ref: edu_snip_to_info(&m),
            })
            .collect())
    }

    async fn src817_list_catalogs_by_institution(
        &self,
        institution_id: String,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<CatalogEntryInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&institution_id)?;
        let lim = limit.map(|l| l as usize).unwrap_or(MAX_EDU_LIST_LIMIT);
        let ex = EducationExecutor::new(self.db.clone());
        let rows = ex
            .list_catalogs_by_institution(&id, lim)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rows.iter().map(edu_catalog_to_info).collect())
    }

    async fn src817_list_catalogs_by_code(
        &self,
        department: String,
        course_code: String,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<CatalogEntryInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let lim = limit.map(|l| l as usize).unwrap_or(MAX_EDU_LIST_LIMIT);
        let ex = EducationExecutor::new(self.db.clone());
        let rows = ex
            .list_catalogs_by_code(&department, &course_code, lim)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rows.iter().map(edu_catalog_to_info).collect())
    }

    async fn src818_get_offering(
        &self,
        offering_id: String,
    ) -> std::result::Result<Option<OfferingInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&offering_id)?;
        let ex = EducationExecutor::new(self.db.clone());
        let rec = ex.get_offering(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rec.as_ref().map(edu_offering_to_info))
    }

    async fn src818_list_offerings_by_catalog(
        &self,
        catalog_id: String,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<OfferingInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&catalog_id)?;
        let lim = limit.map(|l| l as usize).unwrap_or(MAX_EDU_LIST_LIMIT);
        let ex = EducationExecutor::new(self.db.clone());
        let rows = ex
            .list_offerings_by_catalog(&id, lim)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rows.iter().map(edu_offering_to_info).collect())
    }

    async fn src818_list_assessments(
        &self,
        offering_id: String,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<AssessmentInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&offering_id)?;
        let lim = limit.map(|l| l as usize).unwrap_or(MAX_EDU_LIST_LIMIT);
        let ex = EducationExecutor::new(self.db.clone());
        let rows = ex
            .list_assessments(&id, lim)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rows.iter().map(edu_assessment_to_info).collect())
    }

    async fn src818_get_assessment(
        &self,
        offering_id: String,
        assessment_id: String,
    ) -> std::result::Result<Option<AssessmentInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let oid = self.parse_hex32(&offering_id)?;
        let aid = self.parse_hex32(&assessment_id)?;
        let ex = EducationExecutor::new(self.db.clone());
        let rec = ex
            .get_assessment(&oid, &aid)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rec.as_ref().map(edu_assessment_to_info))
    }

    async fn src818_get_enrollment_link(
        &self,
        offering_id: String,
        student_commitment: String,
    ) -> std::result::Result<Option<EnrollmentLinkInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let oid = self.parse_hex32(&offering_id)?;
        let sc = self.parse_hex32(&student_commitment)?;
        let ex = EducationExecutor::new(self.db.clone());
        let rec = ex
            .get_enrollment_link(&oid, &sc)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rec.as_ref().map(edu_enrollment_to_info))
    }

    async fn src818_get_submission_receipt(
        &self,
        offering_id: String,
        assessment_id: String,
        student_commitment: String,
        attempt: u16,
    ) -> std::result::Result<Option<SubmissionReceiptInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let oid = self.parse_hex32(&offering_id)?;
        let aid = self.parse_hex32(&assessment_id)?;
        let sc = self.parse_hex32(&student_commitment)?;
        let ex = EducationExecutor::new(self.db.clone());
        let rec = ex
            .get_submission_receipt(&oid, &aid, &sc, attempt)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rec.as_ref().map(edu_submission_to_info))
    }

    async fn src818_list_submissions_by_student_commitment(
        &self,
        student_commitment: String,
        limit: Option<u32>,
    ) -> std::result::Result<Vec<SubmissionReceiptInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let sc = self.parse_hex32(&student_commitment)?;
        let lim = limit.map(|l| l as usize).unwrap_or(MAX_EDU_LIST_LIMIT);
        let ex = EducationExecutor::new(self.db.clone());
        let rows = ex
            .list_submissions_by_student_commitment(&sc, lim)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rows.iter().map(edu_submission_to_info).collect())
    }

    async fn src818_get_grade_record(
        &self,
        offering_id: String,
        assessment_id: String,
        student_commitment: String,
    ) -> std::result::Result<Option<GradeRecordInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let oid = self.parse_hex32(&offering_id)?;
        let aid = self.parse_hex32(&assessment_id)?;
        let sc = self.parse_hex32(&student_commitment)?;
        let ex = EducationExecutor::new(self.db.clone());
        let rec = ex
            .get_grade_record(&oid, &aid, &sc)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(rec.as_ref().map(edu_grade_to_info))
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

    async fn token_get_minters(
        &self,
        token_id: String,
    ) -> std::result::Result<Option<TokenMintersInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let token_bytes = self.parse_token_id(&token_id)?;
        let token_store = TokenStore::new(&self.db);
        // Base58-encode a stored token-config `Address` the same way the rest of
        // the token RPC does.
        fn addr_b58(a: &sumchain_primitives::Address) -> String {
            Address::new({
                let mut arr = [0u8; 20];
                arr.copy_from_slice(a.as_bytes());
                arr
            })
            .to_base58()
        }
        match token_store.get_token(&token_bytes) {
            Ok(Some(data)) => Ok(Some(TokenMintersInfo {
                token_id: format!("0x{}", hex::encode(token_bytes)),
                owner: addr_b58(&data.owner),
                minters: data.minters.iter().map(addr_b58).collect(),
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
        let contract_addr = self.parse_address(&request.contract)?;
        let from_addr = match request.from {
            Some(ref from) => Some(self.parse_address(from)?),
            None => None,
        };
        let args = hex::decode(request.args.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid args hex: {}", e)))?;

        let executor = self
            .contract_executor
            .as_ref()
            .ok_or_else(|| RpcError::Internal("Contract executor not available".to_string()))?;

        if !executor
            .contract_exists(&contract_addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            return Err(RpcError::InvalidParams("Contract not found".to_string()).into());
        }

        let height = BlockStore::new(&self.db)
            .get_latest_height()
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .unwrap_or(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Metered dry-run; surface failure/out-of-gas as an error, never a
        // fabricated estimate.
        let gas_estimate = executor
            .estimate_gas(
                &contract_addr,
                &request.method,
                args,
                from_addr,
                height,
                timestamp,
                self.state.chain_id(),
            )
            .map_err(|e| RpcError::Internal(format!("gas estimation failed: {}", e)))?;

        let gas_price: u128 = 1_000_000; // 0.001 Koppa per gas unit
        let total_cost = (gas_estimate as u128) * gas_price;

        Ok(GasEstimateResult {
            gas_estimate,
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
        address: String,
        key: String,
    ) -> std::result::Result<Option<String>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let key_bytes = hex::decode(key.trim_start_matches("0x"))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid storage key hex: {}", e)))?;

        let executor = self
            .contract_executor
            .as_ref()
            .ok_or_else(|| RpcError::Internal("Contract executor not available".to_string()))?;

        // Gate on contract existence: a non-contract (or unknown address)
        // returns None rather than an empty-vs-present ambiguity.
        if !executor
            .contract_exists(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            return Ok(None);
        }

        // Raw contract_storage CF key: address(20) || b':' || key.
        let mut full_key = Vec::with_capacity(addr.as_bytes().len() + 1 + key_bytes.len());
        full_key.extend_from_slice(addr.as_bytes());
        full_key.push(b':');
        full_key.extend_from_slice(&key_bytes);

        match self
            .db
            .get(sumchain_storage::cf::CONTRACT_STORAGE, &full_key)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            Some(value) => Ok(Some(format!("0x{}", hex::encode(value)))),
            None => Ok(None),
        }
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
        let min_stake = 1_000_000_000_000_000_000u128; // 1e18 base units = 1B Koppa (must match StakingParams::default)
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
            min_validator_stake: "1000000000000000000".to_string(), // 1e18 base units = 1B Koppa
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
        sender: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> std::result::Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&sender)
            .or_else(|_| Address::from_hex(&sender))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid sender address: {}", e)))?;

        let store = MessagingStore::new(&self.db);
        let limit = limit.map(|l| l as usize).unwrap_or(MESSAGING_LIST_DEFAULT);
        let offset = offset.unwrap_or(0) as usize;
        let events = store
            .get_messages_by_sender(&addr, limit, offset)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let results: Vec<MessageEventInfo> = events
            .into_iter()
            .map(|e| MessageEventInfo {
                tx_hash: format!("0x{}", hex::encode(e.message_id.as_bytes())),
                block_height: e.block_height,
                sender: e.sender.to_base58(),
                recipient_hash: format!("0x{}", hex::encode(e.recipient_hash)),
                content_type: 0, // Not stored in MessageEvent
                flags: 0,        // Not stored in MessageEvent
                has_payment: e.has_payment,
                payment_amount: None, // Amount not stored in MessageEvent
            })
            .collect();

        Ok(results)
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
        recipient: String,
    ) -> std::result::Result<Vec<PendingPaymentInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = Address::from_base58(&recipient)
            .or_else(|_| Address::from_hex(&recipient))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid recipient address: {}", e)))?;
        let recipient_hash = sumchain_crypto::recipient_hash(&addr);

        let store = MessagingStore::new(&self.db);
        let payments = store
            .get_pending_payments_by_recipient(&recipient_hash)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        let results: Vec<PendingPaymentInfo> = payments
            .into_iter()
            .map(|(message_id, payment)| PendingPaymentInfo {
                message_id: format!("0x{}", hex::encode(message_id.as_bytes())),
                sender: payment.sender.to_base58(),
                recipient_hash: format!("0x{}", hex::encode(payment.recipient_hash)),
                amount: payment.amount.to_string(),
                expiry: payment.expiry,
            })
            .collect();

        Ok(results)
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

    // ── SRC-82X Tax registry reads (issue #26) ──────────────────────────────

    async fn tax_get_claim_type(
        &self,
        claim_type: String,
    ) -> std::result::Result<Option<TaxClaimTypeInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::TaxClaimTypeStore::new(&self.db);
        let entry = store.get(&claim_type).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(entry.as_ref().map(TaxClaimTypeInfo::from))
    }

    async fn tax_list_claim_types(
        &self,
    ) -> std::result::Result<Vec<TaxClaimTypeInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::TaxClaimTypeStore::new(&self.db);
        let all = store.list_all().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(all.iter().map(TaxClaimTypeInfo::from).collect())
    }

    async fn tax_get_issuer(
        &self,
        address: String,
    ) -> std::result::Result<Option<TaxIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let store = sumchain_storage::TaxIssuerStore::new(&self.db);
        let issuer = store.get(&addr).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(issuer.as_ref().map(TaxIssuerInfo::from))
    }

    async fn tax_get_active_issuers(
        &self,
    ) -> std::result::Result<Vec<TaxIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::TaxIssuerStore::new(&self.db);
        let issuers = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(issuers.iter().map(TaxIssuerInfo::from).collect())
    }

    async fn tax_get_issuers_by_class(
        &self,
        tax_class: String,
    ) -> std::result::Result<Vec<TaxIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let class = parse_tax_issuer_class(&tax_class)
            .ok_or_else(|| RpcError::InvalidParams(format!("Unknown tax issuer class: {}", tax_class)))?;
        let store = sumchain_storage::TaxIssuerStore::new(&self.db);
        let issuers = store.list_by_class(class).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(issuers.iter().map(TaxIssuerInfo::from).collect())
    }

    async fn tax_get_policy(
        &self,
        policy_id: String,
    ) -> std::result::Result<Option<TaxPolicyInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&policy_id)?;
        let store = sumchain_storage::TaxPolicyStore::new(&self.db);
        let policy = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(policy.as_ref().map(TaxPolicyInfo::from))
    }

    async fn tax_list_policies(
        &self,
    ) -> std::result::Result<Vec<TaxPolicyInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::TaxPolicyStore::new(&self.db);
        let all = store.list_all().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(all.iter().map(TaxPolicyInfo::from).collect())
    }

    // ── SRC-83X Equity registry reads (issue #26) ───────────────────────────

    async fn equity_get_entity(
        &self,
        subject_id: String,
    ) -> std::result::Result<Option<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&subject_id)?;
        let store = sumchain_storage::EntityProfileStore::new(&self.db);
        let entity = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(entity.as_ref().map(EquityEntityInfo::from))
    }

    async fn equity_get_active_entities(
        &self,
    ) -> std::result::Result<Vec<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::EntityProfileStore::new(&self.db);
        let entities = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(entities.iter().map(EquityEntityInfo::from).collect())
    }

    async fn equity_get_entities_by_org_type(
        &self,
        org_type: String,
    ) -> std::result::Result<Vec<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let org = parse_equity_org_type(&org_type)
            .ok_or_else(|| RpcError::InvalidParams(format!("Unknown org type: {}", org_type)))?;
        let store = sumchain_storage::EntityProfileStore::new(&self.db);
        let entities = store.list_by_org_type(org).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(entities.iter().map(EquityEntityInfo::from).collect())
    }

    async fn equity_get_entities_by_controller(
        &self,
        controller: String,
    ) -> std::result::Result<Vec<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&controller)?;
        let store = sumchain_storage::EntityProfileStore::new(&self.db);
        let entities = store.get_by_controller(&addr).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(entities.iter().map(EquityEntityInfo::from).collect())
    }

    async fn equity_get_share_class(
        &self,
        class_id: String,
    ) -> std::result::Result<Option<EquityShareClassInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&class_id)?;
        let store = sumchain_storage::EquityTokenStore::new(&self.db);
        let token = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(token.as_ref().map(EquityShareClassInfo::from))
    }

    async fn equity_get_active_share_classes(
        &self,
    ) -> std::result::Result<Vec<EquityShareClassInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::EquityTokenStore::new(&self.db);
        let tokens = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(tokens.iter().map(EquityShareClassInfo::from).collect())
    }

    async fn equity_get_share_classes_by_issuer(
        &self,
        issuer_subject: String,
    ) -> std::result::Result<Vec<EquityShareClassInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&issuer_subject)?;
        let store = sumchain_storage::EquityTokenStore::new(&self.db);
        let tokens = store.get_by_issuer(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(tokens.iter().map(EquityShareClassInfo::from).collect())
    }

    async fn equity_get_controller_config(
        &self,
        class_id: String,
    ) -> std::result::Result<Option<EquityControllerConfigInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&class_id)?;
        let store = sumchain_storage::EquityControllerStore::new(&self.db);
        let cfg = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(cfg.as_ref().map(EquityControllerConfigInfo::from))
    }

    // ── SRC-84X Agreement executor-link reads (issue #26) ───────────────────

    async fn agreement_get_executor_link(
        &self,
        link_id: String,
    ) -> std::result::Result<Option<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&link_id)?;
        let store = sumchain_storage::ExecutorLinkStore::new(&self.db);
        let link = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(link.as_ref().map(ExecutorLinkInfo::from))
    }

    async fn agreement_get_executor_links_by_agreement(
        &self,
        agreement_id: String,
    ) -> std::result::Result<Vec<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&agreement_id)?;
        let store = sumchain_storage::ExecutorLinkStore::new(&self.db);
        let links = store.get_by_agreement(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(links.iter().map(ExecutorLinkInfo::from).collect())
    }

    async fn agreement_get_executor_links_by_executor(
        &self,
        executor_address: String,
    ) -> std::result::Result<Vec<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&executor_address)?;
        let store = sumchain_storage::ExecutorLinkStore::new(&self.db);
        let links = store.get_by_executor(&addr).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(links.iter().map(ExecutorLinkInfo::from).collect())
    }

    async fn agreement_get_active_executor_links(
        &self,
    ) -> std::result::Result<Vec<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::ExecutorLinkStore::new(&self.db);
        let links = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(links.iter().map(ExecutorLinkInfo::from).collect())
    }

    // ── SRC-86X Property asset-anchor reads (issue #26) ─────────────────────

    async fn property_get_asset(
        &self,
        asset_id: String,
    ) -> std::result::Result<Option<AssetInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&asset_id)?;
        let store = sumchain_storage::AssetStore::new(&self.db);
        let asset = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(asset.as_ref().map(AssetInfo::from))
    }

    async fn property_get_active_assets(
        &self,
    ) -> std::result::Result<Vec<AssetInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::AssetStore::new(&self.db);
        let assets = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(assets.iter().map(AssetInfo::from).collect())
    }

    async fn property_get_assets_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> std::result::Result<Vec<AssetInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::AssetStore::new(&self.db);
        let assets = store
            .get_by_jurisdiction(&jurisdiction)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(assets.iter().map(AssetInfo::from).collect())
    }

    // ── SRC-89X Finance issuer-registry reads (issue #26) ───────────────────

    async fn finance_get_issuer(
        &self,
        issuer_address: String,
    ) -> std::result::Result<Option<FinanceIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&issuer_address)?;
        let store = sumchain_storage::FinanceIssuerStore::new(&self.db);
        let issuer = store.get(&addr).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(issuer.as_ref().map(FinanceIssuerInfo::from))
    }

    async fn finance_get_active_issuers(
        &self,
    ) -> std::result::Result<Vec<FinanceIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::FinanceIssuerStore::new(&self.db);
        let issuers = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(issuers.iter().map(FinanceIssuerInfo::from).collect())
    }

    async fn finance_get_issuers_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> std::result::Result<Vec<FinanceIssuerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::FinanceIssuerStore::new(&self.db);
        let issuers = store
            .get_by_jurisdiction(&jurisdiction)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(issuers.iter().map(FinanceIssuerInfo::from).collect())
    }

    // ── SRC-85X Legal case-anchor reads (issue #26) ─────────────────────────
    // Sealed cases are never returned; filtering is applied here in the RPC
    // layer (no storage change).

    async fn legal_get_case(
        &self,
        case_id: String,
    ) -> std::result::Result<Option<CaseInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::legal::CaseStatus;
        let id = self.parse_hex32(&case_id)?;
        let store = sumchain_storage::CaseStore::new(&self.db);
        let case = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        // Sealed cases must never be returned; report as not found.
        Ok(case
            .filter(|c| c.status != CaseStatus::Sealed)
            .as_ref()
            .map(CaseInfo::from))
    }

    async fn legal_get_active_cases(
        &self,
    ) -> std::result::Result<Vec<CaseInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::legal::CaseStatus;
        let store = sumchain_storage::CaseStore::new(&self.db);
        // list_active() returns open (Filed/Active) anchors; defensively drop
        // any Sealed just in case the helper contract changes.
        let cases = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(cases
            .iter()
            .filter(|c| c.status != CaseStatus::Sealed)
            .map(CaseInfo::from)
            .collect())
    }

    async fn legal_get_cases_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> std::result::Result<Vec<CaseInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::legal::CaseStatus;
        let store = sumchain_storage::CaseStore::new(&self.db);
        let cases = store
            .get_by_jurisdiction(&jurisdiction)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        // Jurisdiction index returns all statuses incl. Sealed; filter them out.
        Ok(cases
            .iter()
            .filter(|c| c.status != CaseStatus::Sealed)
            .map(CaseInfo::from)
            .collect())
    }

    // ── SRC-871 Healthcare institutional provider reads (issue #41) ──────────
    // The provider store is broad (mixes organizations and individual
    // clinicians); this RPC layer restricts results to an explicit allowlist of
    // organizational provider types. No new store/index/CF.

    async fn healthcare_get_institutional_provider(
        &self,
        provider_id: String,
    ) -> std::result::Result<Option<HealthcareProviderInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&provider_id)?;
        let store = sumchain_storage::ProviderStore::new(&self.db);
        let provider = store.get(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        // Return None (indistinguishable from not-found) for non-allowlisted
        // provider types; status-agnostic for allowlisted institutions.
        Ok(provider
            .filter(|p| is_institutional_provider(p.provider_type))
            .as_ref()
            .map(HealthcareProviderInfo::from))
    }

    async fn healthcare_get_active_institutional_providers(
        &self,
    ) -> std::result::Result<Vec<HealthcareProviderInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::ProviderStore::new(&self.db);
        // list_active() returns Active-only; restrict to the institutional allowlist.
        let providers = store.list_active().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(providers
            .iter()
            .filter(|p| is_institutional_provider(p.provider_type))
            .map(HealthcareProviderInfo::from)
            .collect())
    }

    // ── On-chain governance v1 (issue #50) — builders + reads ────────────────

    async fn gov_build_create_proposal(
        &self,
        request: GovBuildCreateProposalRequest,
    ) -> std::result::Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::governance::{
            CreateProposalRequest, ExternalRef, GovAssetKind, GovernanceOperation, GovernanceTxData,
        };
        let from = self.parse_address(&request.from)?;
        let token_id = self.parse_hex32(&request.token_id)?;
        let class = parse_gov_class(&request.class)
            .ok_or_else(|| RpcError::InvalidParams(format!("Unknown class: {}", request.class)))?;
        let execution_kind = parse_execution_kind(&request.execution_kind)
            .ok_or_else(|| RpcError::InvalidParams(format!("Unknown execution_kind: {}", request.execution_kind)))?;
        let content_hash = self.parse_hex32(&request.external_ref_content_hash)?;
        let treasury_beneficiary = match &request.treasury_beneficiary {
            Some(s) => Some(self.parse_address(s)?),
            None => None,
        };
        let req = CreateProposalRequest {
            asset: GovAssetKind::Src20Token(token_id),
            class,
            execution_kind,
            external_ref: ExternalRef { url: request.external_ref_url, content_hash },
            treasury_beneficiary,
            treasury_amount: request.treasury_amount,
        };
        let data = GovernanceTxData {
            operation: GovernanceOperation::CreateProposal,
            data: bincode::serialize(&req).map_err(|e| RpcError::Internal(e.to_string()))?,
        };
        let fee = request.fee.unwrap_or(GOV_DEFAULT_FEE);
        Ok(self.build_unsigned_governance_tx(from, fee, data)?)
    }

    async fn gov_build_cast_vote(
        &self,
        request: GovBuildCastVoteRequest,
    ) -> std::result::Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::governance::{CastVoteRequest, GovernanceOperation, GovernanceTxData};
        let from = self.parse_address(&request.from)?;
        let proposal_id = self.parse_hex32(&request.proposal_id)?;
        let choice = parse_vote_choice(&request.choice)
            .ok_or_else(|| RpcError::InvalidParams(format!("Unknown choice: {}", request.choice)))?;
        let req = CastVoteRequest { proposal_id, choice };
        let data = GovernanceTxData {
            operation: GovernanceOperation::CastVote,
            data: bincode::serialize(&req).map_err(|e| RpcError::Internal(e.to_string()))?,
        };
        let fee = request.fee.unwrap_or(GOV_DEFAULT_FEE);
        Ok(self.build_unsigned_governance_tx(from, fee, data)?)
    }

    async fn gov_build_execute_proposal(
        &self,
        request: GovBuildExecuteProposalRequest,
    ) -> std::result::Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::governance::{ExecuteProposalRequest, GovernanceOperation, GovernanceTxData};
        let from = self.parse_address(&request.from)?;
        let proposal_id = self.parse_hex32(&request.proposal_id)?;
        let req = ExecuteProposalRequest { proposal_id };
        let data = GovernanceTxData {
            operation: GovernanceOperation::ExecuteProposal,
            data: bincode::serialize(&req).map_err(|e| RpcError::Internal(e.to_string()))?,
        };
        let fee = request.fee.unwrap_or(GOV_DEFAULT_FEE);
        Ok(self.build_unsigned_governance_tx(from, fee, data)?)
    }

    async fn gov_build_cancel_proposal(
        &self,
        request: GovBuildCancelProposalRequest,
    ) -> std::result::Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::governance::{CancelProposalRequest, GovernanceOperation, GovernanceTxData};
        let from = self.parse_address(&request.from)?;
        let proposal_id = self.parse_hex32(&request.proposal_id)?;
        let req = CancelProposalRequest {
            proposal_id,
            approvals: self.parse_approvals(&request.approvals)?,
        };
        let data = GovernanceTxData {
            operation: GovernanceOperation::CancelProposal,
            data: bincode::serialize(&req).map_err(|e| RpcError::Internal(e.to_string()))?,
        };
        let fee = request.fee.unwrap_or(GOV_DEFAULT_FEE);
        Ok(self.build_unsigned_governance_tx(from, fee, data)?)
    }

    // ── OmniNode Inference Settlement (issue #61) ───────────────────────────

    async fn omninode_get_inference_session(
        &self,
        session_id: String,
    ) -> std::result::Result<Option<crate::inference_settlement_types::InferenceSessionInfo>, jsonrpsee::types::ErrorObjectOwned>
    {
        use crate::inference_settlement_types::{InferenceConsistencyInfo, InferenceSessionInfo};
        let exec = sumchain_state::inference_settlement_executor::InferenceSettlementExecutor::new(
            self.db.clone(),
        );
        let s = exec.get_session(&session_id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(s.map(|s| InferenceSessionInfo {
            session_id: s.session_id,
            funder: s.funder.to_base58(),
            reward_per_verifier: s.reward_per_verifier,
            max_verifiers: s.max_verifiers,
            remaining_escrow: s.remaining_escrow,
            claims_count: s.claims_count,
            dispute_window_blocks: s.dispute_window_blocks,
            status: format!("{:?}", s.status),
            created_at_height: s.created_at_height,
            expires_at_height: s.expires_at_height,
            consistency: s.consistency.map(|c| InferenceConsistencyInfo {
                min_matching_verifiers: c.min_matching_verifiers,
                threshold_bps: c.threshold_bps,
            }),
        }))
    }

    async fn omninode_get_inference_claims(
        &self,
        session_id: String,
    ) -> std::result::Result<Vec<crate::inference_settlement_types::InferenceClaimInfo>, jsonrpsee::types::ErrorObjectOwned>
    {
        use crate::inference_settlement_types::InferenceClaimInfo;
        let exec = sumchain_state::inference_settlement_executor::InferenceSettlementExecutor::new(
            self.db.clone(),
        );
        let claims = exec.list_claims(&session_id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(claims
            .into_iter()
            .map(|c| InferenceClaimInfo {
                session_id: c.session_id,
                verifier: c.verifier.to_base58(),
                amount: c.amount,
                claimed_at_height: c.claimed_at_height,
                status: format!("{:?}", c.status),
            })
            .collect())
    }

    async fn omninode_get_inference_disputes(
        &self,
        session_id: String,
    ) -> std::result::Result<Vec<crate::inference_settlement_types::InferenceDisputeInfo>, jsonrpsee::types::ErrorObjectOwned>
    {
        use crate::inference_settlement_types::InferenceDisputeInfo;
        let exec = sumchain_state::inference_settlement_executor::InferenceSettlementExecutor::new(
            self.db.clone(),
        );
        let disputes =
            exec.list_disputes(&session_id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(disputes
            .into_iter()
            .map(|d| InferenceDisputeInfo {
                session_id: d.session_id,
                verifier: d.verifier.to_base58(),
                opener: d.opener.to_base58(),
                evidence_commitment: format!("0x{}", hex::encode(d.evidence_commitment)),
                status: format!("{:?}", d.status),
                opened_at_height: d.opened_at_height,
                resolved_at_height: d.resolved_at_height,
                allow_claim: d.allow_claim,
            })
            .collect())
    }

    async fn omninode_get_claimable_reward(
        &self,
        session_id: String,
        verifier: String,
    ) -> std::result::Result<crate::inference_settlement_types::ClaimableRewardInfo, jsonrpsee::types::ErrorObjectOwned>
    {
        use crate::inference_settlement_types::{ClaimConsistencyEval, ClaimableRewardInfo};
        use sumchain_primitives::inference_attestation::inference_attestation_key;
        use sumchain_primitives::inference_settlement::InferenceDisputeStatus;

        let v = self.parse_address(&verifier)?;
        let sexec = sumchain_state::inference_settlement_executor::InferenceSettlementExecutor::new(
            self.db.clone(),
        );
        let aexec = sumchain_state::inference_attestation_executor::InferenceAttestationExecutor::new(
            self.db.clone(),
        );
        let base = |eligible, amount, unlock, reason: &str| ClaimableRewardInfo {
            session_id: session_id.clone(),
            verifier: v.to_base58(),
            eligible,
            amount,
            unlock_height: unlock,
            reason: reason.to_string(),
            consistency: None,
        };

        let session = match sexec.get_session(&session_id).map_err(|e| RpcError::Internal(e.to_string()))? {
            Some(s) => s,
            None => return Ok(base(false, None, None, "session not found")),
        };
        if !matches!(session.status, sumchain_primitives::InferenceSessionStatus::Open) {
            return Ok(base(false, None, None, "session not open"));
        }
        let att = aexec
            .get(&inference_attestation_key(&session_id, &v))
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        let att = match att {
            Some(a) => a,
            None => return Ok(base(false, None, None, "no attestation for verifier")),
        };
        // Maturity = finality (attestation finalized) + dispute window elapsed.
        let unlock = att
            .included_at_height
            .saturating_add(self.consensus.finality_depth())
            .saturating_add(session.dispute_window_blocks);
        if sexec.get_claim(&session_id, &v).map_err(|e| RpcError::Internal(e.to_string()))?.is_some() {
            return Ok(base(false, None, Some(unlock), "already claimed"));
        }
        if let Some(d) = sexec.get_dispute(&session_id, &v).map_err(|e| RpcError::Internal(e.to_string()))? {
            match d.status {
                InferenceDisputeStatus::Open => return Ok(base(false, None, Some(unlock), "blocked by open dispute")),
                InferenceDisputeStatus::ResolvedDenyClaim => return Ok(base(false, None, Some(unlock), "claim denied by dispute")),
                InferenceDisputeStatus::ResolvedAllowClaim => {}
            }
        }
        if session.claims_count >= session.max_verifiers {
            return Ok(base(false, None, Some(unlock), "max_verifiers reached"));
        }
        if session.remaining_escrow < session.reward_per_verifier {
            return Ok(base(false, None, Some(unlock), "insufficient remaining escrow"));
        }
        let current = self.consensus.current_height();
        if current < unlock {
            return Ok(base(false, Some(session.reward_per_verifier), Some(unlock), "not yet mature"));
        }
        // Consistency/plurality evaluation (issue #77), only when the session opted
        // in. The group is computed against the claimant's OWN full digest tuple.
        if let Some(cfg) = session.consistency {
            let matching = sexec
                .consistency_group_size(&session_id, &att.digest, current, self.consensus.finality_depth())
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            let meets_min = matching >= cfg.min_matching_verifiers;
            let meets_bps = cfg.threshold_bps == 0
                || (matching as u64 * 10_000
                    >= session.max_verifiers as u64 * cfg.threshold_bps as u64);
            let satisfied = meets_min && meets_bps;
            let eval = ClaimConsistencyEval {
                required_min: cfg.min_matching_verifiers,
                threshold_bps: cfg.threshold_bps,
                max_verifiers: session.max_verifiers,
                matching_count: matching,
                satisfied,
            };
            let reason = if satisfied {
                "eligible"
            } else {
                "insufficient consistency"
            };
            return Ok(ClaimableRewardInfo {
                session_id: session_id.clone(),
                verifier: v.to_base58(),
                eligible: satisfied,
                amount: Some(session.reward_per_verifier),
                unlock_height: Some(unlock),
                reason: reason.to_string(),
                consistency: Some(eval),
            });
        }
        Ok(base(true, Some(session.reward_per_verifier), Some(unlock), "eligible"))
    }

    async fn omninode_get_inference_consistency(
        &self,
        session_id: String,
    ) -> std::result::Result<crate::inference_settlement_types::InferenceConsistencyReport, jsonrpsee::types::ErrorObjectOwned>
    {
        use crate::inference_settlement_types::{
            InferenceConsistencyGroupInfo, InferenceConsistencyInfo, InferenceConsistencyReport,
        };
        use sumchain_primitives::inference_attestation::inference_attestation_key;
        use sumchain_primitives::inference_settlement::InferenceDisputeStatus;

        let sexec = sumchain_state::inference_settlement_executor::InferenceSettlementExecutor::new(
            self.db.clone(),
        );
        let aexec = sumchain_state::inference_attestation_executor::InferenceAttestationExecutor::new(
            self.db.clone(),
        );
        let session = sexec
            .get_session(&session_id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        let (consistency, max_verifiers) = match &session {
            Some(s) => (
                s.consistency.map(|c| InferenceConsistencyInfo {
                    min_matching_verifiers: c.min_matching_verifiers,
                    threshold_bps: c.threshold_bps,
                }),
                s.max_verifiers,
            ),
            None => (None, 0),
        };

        let hx = |b: &[u8; 32]| format!("0x{}", hex::encode(b));
        let height = self.consensus.current_height();
        let finality_depth = self.consensus.finality_depth();

        // Group verifiers by the full digest tuple. Keyed by the concatenated
        // 128 bytes so `response_hash` alone never merges distinct tuples.
        let mut groups: std::collections::HashMap<[u8; 128], (sumchain_primitives::inference_attestation::InferenceAttestationDigest, Vec<String>, u32)> =
            std::collections::HashMap::new();
        for vf in aexec
            .list_verifiers_by_session(&session_id)
            .map_err(|e| RpcError::Internal(e.to_string()))?
        {
            let att = match aexec
                .get(&inference_attestation_key(&session_id, &vf))
                .map_err(|e| RpcError::Internal(e.to_string()))?
            {
                Some(a) => a,
                None => continue,
            };
            let mut key = [0u8; 128];
            key[..32].copy_from_slice(&att.digest.model_hash);
            key[32..64].copy_from_slice(&att.digest.manifest_root);
            key[64..96].copy_from_slice(&att.digest.response_hash);
            key[96..].copy_from_slice(&att.digest.proof_root);
            // Eligible = finalized at current height AND not open/denied disputed.
            let finalized = att.included_at_height.saturating_add(finality_depth) <= height;
            let disputed = matches!(
                sexec
                    .get_dispute(&session_id, &vf)
                    .map_err(|e| RpcError::Internal(e.to_string()))?
                    .map(|d| d.status),
                Some(InferenceDisputeStatus::Open) | Some(InferenceDisputeStatus::ResolvedDenyClaim)
            );
            let entry = groups
                .entry(key)
                .or_insert_with(|| (att.digest.clone(), Vec::new(), 0));
            entry.1.push(vf.to_base58());
            if finalized && !disputed {
                entry.2 = entry.2.saturating_add(1);
            }
        }

        let mut groups: Vec<InferenceConsistencyGroupInfo> = groups
            .into_values()
            .map(|(digest, verifiers, eligible)| InferenceConsistencyGroupInfo {
                model_hash: hx(&digest.model_hash),
                manifest_root: hx(&digest.manifest_root),
                response_hash: hx(&digest.response_hash),
                proof_root: hx(&digest.proof_root),
                verifier_count: verifiers.len() as u32,
                eligible_count: eligible,
                verifiers,
            })
            .collect();
        // Deterministic ordering: eligible desc, then total desc, then tuple hex.
        groups.sort_by(|a, b| {
            b.eligible_count
                .cmp(&a.eligible_count)
                .then(b.verifier_count.cmp(&a.verifier_count))
                .then(a.model_hash.cmp(&b.model_hash))
                .then(a.response_hash.cmp(&b.response_hash))
                .then(a.proof_root.cmp(&b.proof_root))
        });

        Ok(InferenceConsistencyReport { session_id, consistency, max_verifiers, groups })
    }

    async fn omninode_build_open_inference_session(
        &self,
        request: crate::inference_settlement_types::OmniBuildOpenSessionRequest,
    ) -> std::result::Result<crate::inference_settlement_types::OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>
    {
        use sumchain_primitives::inference_settlement::*;
        let from = self.parse_address(&request.from)?;
        let op = InferenceSettlementOperation::OpenSession(OpenInferenceSessionRequest {
            session_id: request.session_id,
            reward_per_verifier: request.reward_per_verifier,
            max_verifiers: request.max_verifiers,
            dispute_window_blocks: request.dispute_window_blocks,
            expires_at_height: request.expires_at_height,
            deposit: request.deposit,
            consistency: request.consistency.map(|c| InferenceConsistencyConfig {
                min_matching_verifiers: c.min_matching_verifiers,
                threshold_bps: c.threshold_bps,
            }),
        });
        self.build_unsigned_settlement_tx(from, request.fee.unwrap_or(GOV_DEFAULT_FEE), op)
    }

    async fn omninode_build_fund_inference_session(
        &self,
        request: crate::inference_settlement_types::OmniBuildFundSessionRequest,
    ) -> std::result::Result<crate::inference_settlement_types::OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>
    {
        use sumchain_primitives::inference_settlement::*;
        let from = self.parse_address(&request.from)?;
        let op = InferenceSettlementOperation::FundSession(FundInferenceSessionRequest {
            session_id: request.session_id,
            amount: request.amount,
        });
        self.build_unsigned_settlement_tx(from, request.fee.unwrap_or(GOV_DEFAULT_FEE), op)
    }

    async fn omninode_build_claim_inference_reward(
        &self,
        request: crate::inference_settlement_types::OmniBuildClaimRewardRequest,
    ) -> std::result::Result<crate::inference_settlement_types::OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>
    {
        use sumchain_primitives::inference_settlement::*;
        let from = self.parse_address(&request.from)?;
        let op = InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest {
            session_id: request.session_id,
        });
        self.build_unsigned_settlement_tx(from, request.fee.unwrap_or(GOV_DEFAULT_FEE), op)
    }

    async fn omninode_build_open_inference_dispute(
        &self,
        request: crate::inference_settlement_types::OmniBuildOpenDisputeRequest,
    ) -> std::result::Result<crate::inference_settlement_types::OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>
    {
        use sumchain_primitives::inference_settlement::*;
        let from = self.parse_address(&request.from)?;
        let verifier = self.parse_address(&request.verifier)?;
        let evidence_commitment = self.parse_hex32(&request.evidence_commitment)?;
        let op = InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest {
            session_id: request.session_id,
            verifier,
            evidence_commitment,
        });
        self.build_unsigned_settlement_tx(from, request.fee.unwrap_or(GOV_DEFAULT_FEE), op)
    }

    async fn omninode_build_resolve_inference_dispute(
        &self,
        request: crate::inference_settlement_types::OmniBuildResolveDisputeRequest,
    ) -> std::result::Result<crate::inference_settlement_types::OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>
    {
        use sumchain_primitives::inference_settlement::*;
        let from = self.parse_address(&request.from)?;
        let verifier = self.parse_address(&request.verifier)?;
        let approvals = self.parse_approvals(&request.approvals)?;
        let op = InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest {
            session_id: request.session_id,
            verifier,
            allow_claim: request.allow_claim,
            approvals,
        });
        self.build_unsigned_settlement_tx(from, request.fee.unwrap_or(GOV_DEFAULT_FEE), op)
    }

    async fn omninode_build_refund_inference_session(
        &self,
        request: crate::inference_settlement_types::OmniBuildRefundSessionRequest,
    ) -> std::result::Result<crate::inference_settlement_types::OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>
    {
        use sumchain_primitives::inference_settlement::*;
        let from = self.parse_address(&request.from)?;
        let op = InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest {
            session_id: request.session_id,
        });
        self.build_unsigned_settlement_tx(from, request.fee.unwrap_or(GOV_DEFAULT_FEE), op)
    }

    async fn gov_get_proposal(
        &self,
        proposal_id: String,
    ) -> std::result::Result<Option<GovProposalInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&proposal_id)?;
        let store = sumchain_storage::GovStore::new(&self.db);
        let p = store.get_proposal(&id).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(p.as_ref().map(GovProposalInfo::from))
    }

    async fn gov_list_proposals(
        &self,
    ) -> std::result::Result<Vec<GovProposalInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::GovStore::new(&self.db);
        let all = store.list_proposals().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(all.iter().map(GovProposalInfo::from).collect())
    }

    async fn gov_list_active_proposals(
        &self,
    ) -> std::result::Result<Vec<GovProposalInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::governance::GovProposalStatus;
        let store = sumchain_storage::GovStore::new(&self.db);
        let active = store
            .list_proposals_by_status(GovProposalStatus::Voting)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(active.iter().map(GovProposalInfo::from).collect())
    }

    async fn gov_get_tally(
        &self,
        proposal_id: String,
    ) -> std::result::Result<Option<GovTallyInfo>, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::governance::VoteChoice;
        let id = self.parse_hex32(&proposal_id)?;
        let store = sumchain_storage::GovStore::new(&self.db);
        if store.get_proposal(&id).map_err(|e| RpcError::Internal(e.to_string()))?.is_none() {
            return Ok(None);
        }
        let snapshot_total: u128 = store
            .list_snapshot(&id)
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .iter()
            .map(|(_, w)| *w)
            .sum();
        let (mut yes, mut no, mut abstain): (u128, u128, u128) = (0, 0, 0);
        for v in store.list_votes(&id).map_err(|e| RpcError::Internal(e.to_string()))? {
            match v.choice {
                VoteChoice::Yes => yes += v.weight,
                VoteChoice::No => no += v.weight,
                VoteChoice::Abstain => abstain += v.weight,
            }
        }
        let participation = yes + no + abstain;
        let (quorum_met, passed, projected_status) = match self.chain_params.governance.as_ref() {
            Some(gp) => {
                if participation == 0 {
                    (Some(false), Some(false), "Expired".to_string())
                } else {
                    let q = participation.saturating_mul(10_000)
                        >= (gp.quorum_bps as u128).saturating_mul(snapshot_total);
                    let p = yes.saturating_mul(10_000)
                        >= (gp.pass_threshold_bps as u128).saturating_mul(yes + no);
                    let status = if !q {
                        "QuorumNotMet"
                    } else if p {
                        "Passed"
                    } else {
                        "Rejected"
                    };
                    (Some(q), Some(p), status.to_string())
                }
            }
            None => (None, None, "CountsOnly".to_string()),
        };
        Ok(Some(GovTallyInfo {
            proposal_id: format!("0x{}", hex::encode(id)),
            snapshot_total: snapshot_total.to_string(),
            yes: yes.to_string(),
            no: no.to_string(),
            abstain: abstain.to_string(),
            participation: participation.to_string(),
            quorum_met,
            passed,
            projected_status,
        }))
    }

    async fn gov_get_vote(
        &self,
        proposal_id: String,
        voter: String,
    ) -> std::result::Result<Option<GovVoteInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&proposal_id)?;
        let addr = self.parse_address(&voter)?;
        let store = sumchain_storage::GovStore::new(&self.db);
        let v = store.get_vote(&id, &addr).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(v.as_ref().map(GovVoteInfo::from))
    }

    async fn gov_get_voting_power(
        &self,
        proposal_id: String,
        holder: String,
    ) -> std::result::Result<Option<GovVotingPowerInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&proposal_id)?;
        let addr = self.parse_address(&holder)?;
        let store = sumchain_storage::GovStore::new(&self.db);
        let w = store.get_snapshot(&id, &addr).map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(w.map(|weight| GovVotingPowerInfo {
            proposal_id: format!("0x{}", hex::encode(id)),
            holder: addr.to_base58(),
            weight: weight.to_string(),
        }))
    }

    async fn gov_list_eligible_assets(
        &self,
    ) -> std::result::Result<Vec<GovAssetInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let store = sumchain_storage::GovStore::new(&self.db);
        let assets = store.list_assets().map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(assets.iter().map(GovAssetInfo::from).collect())
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

                let (tx_type, action, asset_ref, asset_kind) = Self::tx_semantics(&tx);
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
                    tx_type,
                    action,
                    asset_ref,
                    asset_kind,
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

                let (tx_type, action, asset_ref, asset_kind) = Self::tx_semantics(&tx);
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
                    tx_type,
                    action,
                    asset_ref,
                    asset_kind,
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

                let (tx_type, action, asset_ref, asset_kind) = Self::tx_semantics(&tx);
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
                    tx_type,
                    action,
                    asset_ref,
                    asset_kind,
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

    async fn policy_build_create_account(
        &self,
        request: BuildCreateAccountRequest,
    ) -> std::result::Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::policy_account::{PolicyAccount, PolicyAccountOperation, PolicyAccountTxData};
        use sumchain_state::policy_account_executor::CreatePolicyAccountRequest as ExecCreate;

        let from = self.parse_address(&request.from)?;
        let mut members = Vec::with_capacity(request.members.len());
        for m in &request.members {
            members.push(m.to_member().map_err(RpcError::InvalidParams)?);
        }
        let policy = request.policy.to_config().map_err(RpcError::InvalidParams)?;
        let salt = hex::decode(request.salt.strip_prefix("0x").unwrap_or(&request.salt))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid salt hex: {}", e)))?;

        let id = PolicyAccount::compute_id(&members, &salt);
        let address = PolicyAccount::id_to_address(&id);

        let exec_req = ExecCreate { members, policy, salt };
        let data = PolicyAccountTxData {
            operation: PolicyAccountOperation::Create,
            data: bincode::serialize(&exec_req)
                .map_err(|e| RpcError::Internal(format!("encode failed: {}", e)))?,
            recipient: from,
        };
        let fee = request.fee.unwrap_or(POLICY_DEFAULT_FEE);
        let mut resp = self.build_unsigned_policy_tx(from, fee, data)?;
        resp.policy_account_id = Some(format!("0x{}", hex::encode(id)));
        resp.address = Some(address.to_base58());
        Ok(resp)
    }

    async fn policy_get_account(&self, policy_account_id: String) -> std::result::Result<PolicyAccountInfo, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&policy_account_id)?;
        let account = PolicyAccountStorage::new(&self.db)
            .policy_accounts()
            .get(&id)
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .ok_or_else(|| RpcError::InvalidParams("Policy account not found".to_string()))?;
        Ok(PolicyAccountInfo::from_account(&account))
    }

    async fn policy_get_account_by_address(&self, address: String) -> std::result::Result<Option<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&address)?;
        let account = PolicyAccountStorage::new(&self.db)
            .policy_accounts()
            .get_by_address(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(account.map(|a| PolicyAccountInfo::from_account(&a)))
    }

    async fn policy_list_member_accounts(&self, member_address: String) -> std::result::Result<Vec<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&member_address)?;
        let accounts = PolicyAccountStorage::new(&self.db)
            .policy_accounts()
            .list_by_member(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(accounts.iter().map(PolicyAccountInfo::from_account).collect())
    }

    async fn policy_build_submit_proposal(
        &self,
        request: BuildSubmitProposalRequest,
    ) -> std::result::Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::policy_account::{PolicyAccountOperation, PolicyAccountTxData, Proposal};
        use sumchain_primitives::Hash;
        use sumchain_state::policy_account_executor::SubmitProposalRequest as ExecSubmit;

        let from = self.parse_address(&request.from)?;
        let policy_account_id = self.parse_hex32(&request.policy_account_id)?;
        let action_payload = hex::decode(request.action_data.strip_prefix("0x").unwrap_or(&request.action_data))
            .map_err(|e| RpcError::InvalidParams(format!("Invalid action_data hex: {}", e)))?;

        let mut approvals = Vec::with_capacity(request.approvals.len());
        for a in &request.approvals {
            approvals.push(a.to_member_approval().map_err(RpcError::InvalidParams)?);
        }

        // Derive the proposal id against the account's current policy nonce.
        let account = PolicyAccountStorage::new(&self.db)
            .policy_accounts()
            .get(&policy_account_id)
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .ok_or_else(|| RpcError::InvalidParams("Policy account not found".to_string()))?;
        let action_hash = Hash::hash(&action_payload);
        let proposal_id = Proposal::compute_id(&policy_account_id, account.nonce, &action_hash);

        let exec_req = ExecSubmit {
            policy_account_id,
            action_payload,
            approvals,
            expires_at: request.expires_at,
        };
        let data = PolicyAccountTxData {
            operation: PolicyAccountOperation::SubmitProposal,
            data: bincode::serialize(&exec_req)
                .map_err(|e| RpcError::Internal(format!("encode failed: {}", e)))?,
            recipient: from,
        };
        let fee = request.fee.unwrap_or(POLICY_DEFAULT_FEE);
        let mut resp = self.build_unsigned_policy_tx(from, fee, data)?;
        resp.proposal_id = Some(format!("0x{}", hex::encode(proposal_id)));
        resp.action_hash = Some(format!("0x{}", hex::encode(action_hash.as_bytes())));
        Ok(resp)
    }

    async fn policy_build_execute_proposal(
        &self,
        request: BuildExecuteProposalRequest,
    ) -> std::result::Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::policy_account::{PolicyAccountOperation, PolicyAccountTxData};
        use sumchain_state::policy_account_executor::ExecuteProposalRequest as ExecExec;

        let from = self.parse_address(&request.from)?;
        let proposal_id = self.parse_hex32(&request.proposal_id)?;
        let exec_req = ExecExec { proposal_id };
        let data = PolicyAccountTxData {
            operation: PolicyAccountOperation::ExecuteProposal,
            data: bincode::serialize(&exec_req)
                .map_err(|e| RpcError::Internal(format!("encode failed: {}", e)))?,
            recipient: from,
        };
        let fee = request.fee.unwrap_or(POLICY_DEFAULT_FEE);
        Ok(self.build_unsigned_policy_tx(from, fee, data)?)
    }

    async fn policy_build_cancel_proposal(
        &self,
        request: BuildCancelProposalRequest,
    ) -> std::result::Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned> {
        use sumchain_primitives::policy_account::{PolicyAccountOperation, PolicyAccountTxData};

        let from = self.parse_address(&request.from)?;
        let proposal_id = self.parse_hex32(&request.proposal_id)?;
        // CancelProposal's executor decodes a raw `ProposalId`, not a request
        // wrapper — encode the 32-byte id directly so the on-chain payload is
        // exactly `CancelProposal + ProposalId`.
        let data = PolicyAccountTxData {
            operation: PolicyAccountOperation::CancelProposal,
            data: bincode::serialize(&proposal_id)
                .map_err(|e| RpcError::Internal(format!("encode failed: {}", e)))?,
            recipient: from,
        };
        let fee = request.fee.unwrap_or(POLICY_DEFAULT_FEE);
        Ok(self.build_unsigned_policy_tx(from, fee, data)?)
    }

    async fn policy_get_proposal(&self, proposal_id: String) -> std::result::Result<ProposalInfo, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&proposal_id)?;
        let proposal = PolicyAccountStorage::new(&self.db)
            .proposals()
            .get(&id)
            .map_err(|e| RpcError::Internal(e.to_string()))?
            .ok_or_else(|| RpcError::InvalidParams("Proposal not found".to_string()))?;
        Ok(ProposalInfo::from_proposal(&proposal))
    }

    async fn policy_list_proposals(&self, policy_account_id: String) -> std::result::Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&policy_account_id)?;
        let proposals = PolicyAccountStorage::new(&self.db)
            .proposals()
            .list_by_policy_account(&id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(proposals.iter().map(ProposalInfo::from_proposal).collect())
    }

    async fn policy_list_pending_proposals(&self, policy_account_id: String) -> std::result::Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let id = self.parse_hex32(&policy_account_id)?;
        let proposals = PolicyAccountStorage::new(&self.db)
            .proposals()
            .list_pending(&id)
            .map_err(|e| RpcError::Internal(e.to_string()))?;
        Ok(proposals.iter().map(ProposalInfo::from_proposal).collect())
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

    async fn storage_get_archive_unbonding(
        &self,
        operator_address: String,
    ) -> std::result::Result<Option<ArchiveUnbondingInfo>, jsonrpsee::types::ErrorObjectOwned> {
        let addr = self.parse_address(&operator_address)?;

        let executor = sumchain_state::NodeRegistryExecutor::new(self.db.clone());
        let record = executor
            .get_archive_unbonding(&addr)
            .map_err(|e| RpcError::Internal(e.to_string()))?;

        Ok(record.map(|r| ArchiveUnbondingInfo {
            operator: r.operator.to_base58(),
            amount: r.amount,
            started_height: r.started_height,
            unlock_height: r.unlock_height,
            remaining_amount: r.remaining_amount,
        }))
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
        fn map_per_archive(
            entries: &[sumchain_state::storage_metadata::ArchivePerEntry],
        ) -> Vec<ArchiveCoverageSummaryV2> {
            entries
                .iter()
                .map(|p| ArchiveCoverageSummaryV2 {
                    archive: p.archive.to_base58(),
                    assigned_count: p.assigned_count,
                    attested_count: p.attested_count,
                    currently_active: p.currently_active,
                })
                .collect()
        }

        // Top-level `per_archive` is epoch-0-only (issue #62, backward-compatible).
        let per_archive_wire = map_per_archive(&summary.per_archive);

        // Per-epoch detail (issue #62). Reassignment-aware clients read this.
        let per_epoch_wire: Vec<AssignmentEpochCoverageV2> = summary
            .per_epoch
            .iter()
            .map(|e| AssignmentEpochCoverageV2 {
                epoch_height: e.epoch_height,
                is_epoch_zero: e.is_epoch_zero,
                covered_count: e.covered_count,
                per_archive: map_per_archive(&e.per_archive),
            })
            .collect();

        // Compute missing_indices window over the AGGREGATE union: ascending
        // i >= offset where union[i] == 0.
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
            assignment_epochs: summary.assignment_epochs.clone(),
            latest_assignment_epoch: summary.latest_assignment_epoch,
            reassignment_needed: summary.reassignment_needed,
            per_epoch: per_epoch_wire,
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
// ============================================================================
// SRC-817/818 Education suite — stored → RPC-view converters (Phase 4)
// Pure functions; no DB access. 32-byte fields => 0x+hex; Addresses =>
// base58 (chain canonical). Status/kind/audience => numeric + label.
// Never emits raw grade/submission/answer-key/decryption material —
// the stored records only ever hold commitments + refs.
// ============================================================================

fn edu_hex0x(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Parse a `0x`-prefixed (or bare) 64-hex string into `[u8;32]`.
/// Free fn so it is unit-testable without an `RpcServer`.
fn edu_parse_hex32(s: &str) -> std::result::Result<[u8; 32], String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes =
        hex::decode(trimmed).map_err(|_| format!("Invalid hex32: {s}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "expected 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn edu_cat_status_label(c: u8) -> String {
    match c {
        0 => "Draft",
        1 => "Active",
        2 => "Deprecated",
        3 => "Archived",
        _ => "Unknown",
    }
    .to_string()
}

fn edu_off_status_label(c: u8) -> String {
    match c {
        0 => "Draft",
        1 => "Active",
        2 => "EnrollmentClosed",
        3 => "Completed",
        4 => "Archived",
        5 => "Suspended",
        6 => "Cancelled",
        _ => "Unknown",
    }
    .to_string()
}

fn edu_assess_status_label(c: u8) -> String {
    match c {
        0 => "Draft",
        1 => "Open",
        2 => "Closed",
        3 => "Graded",
        _ => "Unknown",
    }
    .to_string()
}

fn edu_content_kind_label(c: u8) -> String {
    match c {
        0 => "Description",
        1 => "LearningOutcomes",
        2 => "DefaultSyllabus",
        3 => "DefaultAssessmentPolicy",
        _ => "Unknown",
    }
    .to_string()
}

fn edu_policy_to_info(
    p: &sumchain_primitives::education::ContentAccessPolicy,
) -> crate::types::ContentAccessPolicyInfo {
    use sumchain_primitives::education::AccessAudience::*;
    let (kind, label, sc) = match &p.audience {
        Public => (0u8, "Public", None),
        EnrolledStudents => (1, "EnrolledStudents", None),
        InstructorsOnly => (2, "InstructorsOnly", None),
        StaffOnly => (3, "StaffOnly", None),
        IndividualStudent(c) => (4, "IndividualStudent", Some(edu_hex0x(c))),
    };
    crate::types::ContentAccessPolicyInfo {
        opens_at: p.opens_at,
        closes_at: p.closes_at,
        grace_until: p.grace_until,
        audience_kind: kind,
        audience_label: label.to_string(),
        audience_student_commitment: sc,
        revoke_on_course_archive: p.revoke_on_course_archive,
    }
}

fn edu_snip_to_info(
    m: &sumchain_primitives::education::ManagedSnipRef,
) -> crate::types::ManagedSnipRefInfo {
    crate::types::ManagedSnipRefInfo {
        content_root: edu_hex0x(&m.snip_ref.content_root),
        snip_file_id: m.snip_ref.snip_file_id.as_ref().map(edu_hex0x),
        size_bytes: m.snip_ref.size_bytes,
        schema_version: m.snip_ref.schema_version,
        access_policy: edu_policy_to_info(&m.access_policy),
    }
}

fn edu_catalog_to_info(c: &StoredCatalogEntry) -> crate::types::CatalogEntryInfo {
    crate::types::CatalogEntryInfo {
        catalog_id: edu_hex0x(&c.catalog_id),
        institution_id: edu_hex0x(&c.institution_id),
        department: c.department.clone(),
        course_code: c.course_code.clone(),
        course_title: c.course_title.clone(),
        title_commitment: c.title_commitment.as_ref().map(edu_hex0x),
        course_level: c.course_level,
        credit_hours: c.credit_hours,
        credit_commitment: c.credit_commitment.as_ref().map(edu_hex0x),
        prerequisites_count: c.prerequisites_count,
        prerequisites_root: edu_hex0x(&c.prerequisites_root),
        accreditation_count: c.accreditation_count,
        accreditation_root: edu_hex0x(&c.accreditation_root),
        status_code: c.status,
        status_label: edu_cat_status_label(c.status),
        version: c.version,
        supersedes: c.supersedes.as_ref().map(edu_hex0x),
        superseded_by: c.superseded_by.as_ref().map(edu_hex0x),
        owner: c.owner.to_base58(),
        created_at_height: c.created_at_height,
        updated_at_height: c.updated_at_height,
        nonce: c.nonce,
    }
}

fn edu_offering_to_info(o: &StoredOffering) -> crate::types::OfferingInfo {
    crate::types::OfferingInfo {
        offering_id: edu_hex0x(&o.offering_id),
        catalog_id: edu_hex0x(&o.catalog_id),
        term: o.term.clone(),
        section: o.section.clone(),
        instruction_start_at: o.instruction_start_at,
        instruction_end_at: o.instruction_end_at,
        final_grade_submission_deadline: o.final_grade_submission_deadline,
        owner: o.owner.to_base58(),
        status_code: o.status,
        status_label: edu_off_status_label(o.status),
        instructor_count: o.instructor_count,
        instructor_root: edu_hex0x(&o.instructor_root),
        content_count: o.content_count,
        content_root: edu_hex0x(&o.content_root),
        assessment_count: o.assessment_count,
        assessment_root: edu_hex0x(&o.assessment_root),
        enrollment_count: o.enrollment_count,
        enrollment_root: edu_hex0x(&o.enrollment_root),
        created_at_height: o.created_at_height,
        updated_at_height: o.updated_at_height,
        nonce: o.nonce,
    }
}

fn edu_assessment_to_info(a: &StoredAssessment) -> crate::types::AssessmentInfo {
    crate::types::AssessmentInfo {
        offering_id: edu_hex0x(&a.offering_id),
        assessment_id: edu_hex0x(&a.assessment_id),
        kind: a.kind,
        kind_label: match a.kind {
            0 => "Assignment",
            1 => "Exam",
            2 => "Quiz",
            3 => "Project",
            _ => "Unknown",
        }
        .to_string(),
        instructions: edu_snip_to_info(&a.instructions),
        spec_commitment: edu_hex0x(&a.spec_commitment),
        opens_at: a.opens_at,
        due_at: a.due_at,
        max_attempts: a.max_attempts,
        weight_bps: a.weight_bps,
        answer_key_commitment: a.answer_key_commitment.as_ref().map(edu_hex0x),
        answer_key_access: a.answer_key_access.as_ref().map(edu_policy_to_info),
        status_code: a.status,
        status_label: edu_assess_status_label(a.status),
        created_at_height: a.created_at_height,
    }
}

fn edu_enrollment_to_info(
    e: &StoredEnrollmentLink,
) -> crate::types::EnrollmentLinkInfo {
    crate::types::EnrollmentLinkInfo {
        student_commitment: edu_hex0x(&e.student_commitment),
        enrollment_ref: edu_hex0x(&e.enrollment_ref),
        linked_at_height: e.linked_at_height,
    }
}

fn edu_submission_to_info(
    s: &StoredSubmissionReceipt,
) -> crate::types::SubmissionReceiptInfo {
    crate::types::SubmissionReceiptInfo {
        offering_id: edu_hex0x(&s.offering_id),
        assessment_id: edu_hex0x(&s.assessment_id),
        student_commitment: edu_hex0x(&s.student_commitment),
        attempt: s.attempt,
        submission_commitment: edu_hex0x(&s.submission_commitment),
        work: edu_snip_to_info(&s.work),
        student_auth_commitment: s.student_auth_commitment.as_ref().map(edu_hex0x),
        enrollment_ref: edu_hex0x(&s.enrollment_ref),
        submitter: s.submitter.to_base58(),
        late: s.late,
        submitted_at_height: s.submitted_at_height,
        submitted_at_ts: s.submitted_at_ts,
        status_code: s.status,
        status_label: match s.status {
            0 => "Submitted",
            1 => "Graded",
            2 => "Resubmitted",
            3 => "Voided",
            _ => "Unknown",
        }
        .to_string(),
    }
}

fn edu_grade_to_info(g: &StoredGradeRecord) -> crate::types::GradeRecordInfo {
    crate::types::GradeRecordInfo {
        offering_id: edu_hex0x(&g.offering_id),
        assessment_id: edu_hex0x(&g.assessment_id),
        student_commitment: edu_hex0x(&g.student_commitment),
        grade_commitment: edu_hex0x(&g.grade_commitment),
        feedback: g.feedback.as_ref().map(edu_snip_to_info),
        grader: g.grader.to_base58(),
        grader_role: g.grader_role,
        graded_at_height: g.graded_at_height,
        status_code: g.status,
        status_label: match g.status {
            0 => "Provisional",
            1 => "Finalized",
            2 => "Revised",
            _ => "Unknown",
        }
        .to_string(),
        finalized: g.finalized,
    }
}

#[cfg(test)]
mod phase_0b_rpc_tests {
    // The pure `classify_inference_attestation_status` tests now live
    // in `sumchain-primitives` (with the classifier itself) so they
    // can run without the rpc crate's storage transitive deps. See
    // `crates/primitives/tests/inference_attestation_fixtures.rs`.
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
            assignment_epochs: vec![100],
            latest_assignment_epoch: 100,
            reassignment_needed: false,
            per_epoch: vec![AssignmentEpochCoverageV2 {
                epoch_height: 100,
                is_epoch_zero: true,
                covered_count: 3,
                per_archive: vec![ArchiveCoverageSummaryV2 {
                    archive: "ArchiveAddr1".to_string(),
                    assigned_count: Some(2),
                    attested_count: 2,
                    currently_active: true,
                }],
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
            "assignment_epochs": [100],
            "latest_assignment_epoch": 100,
            "reassignment_needed": false,
            "per_epoch": [{
                "epoch_height": 100,
                "is_epoch_zero": true,
                "covered_count": 3,
                "per_archive": [{
                    "archive": "ArchiveAddr1",
                    "assigned_count": 2,
                    "attested_count": 2,
                    "currently_active": true,
                }],
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
            assignment_epochs: vec![0],
            latest_assignment_epoch: 0,
            reassignment_needed: false,
            per_epoch: vec![AssignmentEpochCoverageV2 {
                epoch_height: 0,
                is_epoch_zero: true,
                covered_count: 0,
                per_archive: vec![ArchiveCoverageSummaryV2 {
                    archive: "BigArchive".to_string(),
                    assigned_count: None,
                    attested_count: 0,
                    currently_active: true,
                }],
            }],
        };
        let got = serde_json::to_value(&v).unwrap();
        assert_eq!(
            got["per_archive"][0]["assigned_count"],
            serde_json::Value::Null
        );
        // The per_epoch mirror also renders `assigned_count` as JSON null.
        assert_eq!(
            got["per_epoch"][0]["per_archive"][0]["assigned_count"],
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
            assignment_epochs: vec![50, 120],
            latest_assignment_epoch: 120,
            reassignment_needed: true,
            per_epoch: vec![
                AssignmentEpochCoverageV2 {
                    epoch_height: 50,
                    is_epoch_zero: true,
                    covered_count: 8,
                    per_archive: vec![ArchiveCoverageSummaryV2 {
                        archive: "A".to_string(),
                        assigned_count: Some(5),
                        attested_count: 4,
                        currently_active: true,
                    }],
                },
                AssignmentEpochCoverageV2 {
                    epoch_height: 120,
                    is_epoch_zero: false,
                    covered_count: 2,
                    per_archive: vec![ArchiveCoverageSummaryV2 {
                        archive: "C".to_string(),
                        assigned_count: Some(3),
                        attested_count: 2,
                        currently_active: true,
                    }],
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
            omninode_enabled_from_height: None,  // disabled (production-safe default)
            education_enabled_from_height: None,  // disabled (production-safe default)
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
            "omninode_enabled_from_height": null,
            "education_enabled_from_height": null,
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
            omninode_enabled_from_height: Some(1_250_000),  // distinct activation height
            education_enabled_from_height: Some(1_500_000),  // distinct activation height
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: ChainParamsInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), s);
        assert_eq!(back.v2_enabled_from_height, Some(1_000_000));
        assert_eq!(back.omninode_enabled_from_height, Some(1_250_000));
        assert_eq!(back.education_enabled_from_height, Some(1_500_000));
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


#[cfg(test)]
mod education_rpc_phase4_tests {
    use super::*;
    use sumchain_primitives::education::{
        AccessAudience, ContentAccessPolicy, ManagedSnipRef, SnipRef,
    };
    use sumchain_primitives::Address;

    fn snip() -> ManagedSnipRef {
        ManagedSnipRef {
            snip_ref: SnipRef {
                content_root: [0x11; 32],
                snip_file_id: Some([0x22; 32]),
                size_bytes: 4096,
                schema_version: 1,
            },
            access_policy: ContentAccessPolicy {
                opens_at: Some(1),
                closes_at: None,
                grace_until: None,
                audience: AccessAudience::IndividualStudent([0x33; 32]),
                revoke_on_course_archive: true,
            },
        }
    }

    #[test]
    fn parse_hex32_accepts_0x_and_bare_rejects_bad() {
        let bare = "ab".repeat(32);
        assert_eq!(edu_parse_hex32(&bare).unwrap(), [0xab; 32]);
        assert_eq!(
            edu_parse_hex32(&format!("0x{bare}")).unwrap(),
            [0xab; 32]
        );
        assert!(edu_parse_hex32("0xzz").is_err()); // non-hex
        assert!(edu_parse_hex32("0xabcd").is_err()); // too short
        assert!(edu_parse_hex32(&"ab".repeat(33)).is_err()); // too long
    }

    #[test]
    fn managed_snip_ref_info_round_trips_and_hex_encodes() {
        let info = edu_snip_to_info(&snip());
        assert_eq!(info.content_root, format!("0x{}", "11".repeat(32)));
        assert_eq!(info.snip_file_id.as_deref(), Some(format!("0x{}", "22".repeat(32)).as_str()));
        assert_eq!(info.access_policy.audience_kind, 4);
        assert_eq!(info.access_policy.audience_label, "IndividualStudent");
        assert_eq!(
            info.access_policy.audience_student_commitment,
            Some(format!("0x{}", "33".repeat(32)))
        );
        let j = serde_json::to_string(&info).unwrap();
        let back: crate::types::ManagedSnipRefInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
    }

    #[test]
    fn catalog_to_info_shape_and_owner_base58() {
        let owner = Address::from([7u8; 20]);
        let c = StoredCatalogEntry {
            catalog_id: [1; 32],
            institution_id: [2; 32],
            department: "CS".into(),
            course_code: "CS101".into(),
            course_title: Some("Intro".into()),
            title_commitment: None,
            course_level: 0,
            credit_hours: Some(3),
            credit_commitment: None,
            prerequisites_count: 0,
            prerequisites_root: [0; 32],
            accreditation_count: 0,
            accreditation_root: [0; 32],
            status: 1,
            version: 1,
            supersedes: None,
            superseded_by: None,
            owner,
            created_at_height: 10,
            updated_at_height: 11,
            nonce: 7,
        };
        let info = edu_catalog_to_info(&c);
        assert_eq!(info.catalog_id, format!("0x{}", "01".repeat(32)));
        assert_eq!(info.status_code, 1);
        assert_eq!(info.status_label, "Active");
        assert_eq!(info.owner, owner.to_base58());
        // Round-trip the JSON contract.
        let j = serde_json::to_string(&info).unwrap();
        let back: crate::types::CatalogEntryInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
    }

    #[test]
    fn submission_receipt_info_privacy_no_raw_student_address() {
        // A distinctive 20-byte "raw student address" pattern that must
        // never appear in the serialized receipt view.
        const FORBIDDEN_STUDENT_ADDR: [u8; 20] = [0x7E; 20];
        let submitter = Address::from([9u8; 20]); // sponsor (allowed)
        let r = StoredSubmissionReceipt {
            offering_id: [1; 32],
            assessment_id: [2; 32],
            student_commitment: [0x44; 32], // hash, never an address
            attempt: 0,
            submission_commitment: [0x55; 32],
            work: snip(),
            student_auth_commitment: None,
            enrollment_ref: [0x66; 32],
            submitter,
            late: false,
            submitted_at_height: 5,
            submitted_at_ts: 99,
            status: 0,
        };
        let info = edu_submission_to_info(&r);
        let j = serde_json::to_string(&info).unwrap();
        // No raw student address pattern anywhere in the response.
        let forbidden_hex = hex::encode(FORBIDDEN_STUDENT_ADDR);
        assert!(!j.contains(&forbidden_hex));
        // Student only as a 32-byte commitment.
        assert_eq!(info.student_commitment, format!("0x{}", "44".repeat(32)));
        // Submitter is the sponsor (base58), explicitly not the student.
        assert_eq!(info.submitter, submitter.to_base58());
        assert_ne!(info.submitter, info.student_commitment);
        let back: crate::types::SubmissionReceiptInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
    }

    #[test]
    fn grade_record_info_exposes_commitment_not_raw_grade() {
        let g = StoredGradeRecord {
            offering_id: [1; 32],
            assessment_id: [2; 32],
            student_commitment: [0x44; 32],
            grade_commitment: [0xAB; 32],
            feedback: Some(snip()),
            grader: Address::from([3u8; 20]),
            grader_role: 1,
            graded_at_height: 7,
            status: 1,
            finalized: true,
        };
        let info = edu_grade_to_info(&g);
        // Only a commitment is present; there is no raw-grade field on
        // the type at all (compile-time guarantee) and the value is the
        // committed hash.
        assert_eq!(info.grade_commitment, format!("0x{}", "ab".repeat(32)));
        assert_eq!(info.status_label, "Finalized");
        assert!(info.finalized);
        let j = serde_json::to_string(&info).unwrap();
        let back: crate::types::GradeRecordInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), j);
    }

    #[test]
    fn status_labels_cover_all_codes() {
        for c in 0u8..=3 {
            assert_ne!(edu_cat_status_label(c), "Unknown");
        }
        for c in 0u8..=6 {
            assert_ne!(edu_off_status_label(c), "Unknown");
        }
        assert_eq!(edu_cat_status_label(99), "Unknown");
        assert_eq!(edu_off_status_label(99), "Unknown");
    }

    // ── JSON shape / round-trip for the remaining Info types ──

    fn pol() -> crate::types::ContentAccessPolicyInfo {
        edu_policy_to_info(&ContentAccessPolicy {
            opens_at: Some(1),
            closes_at: Some(9),
            grace_until: None,
            audience: AccessAudience::EnrolledStudents,
            revoke_on_course_archive: true,
        })
    }

    fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T) -> String {
        let j = serde_json::to_string(v).unwrap();
        let back: T = serde_json::from_str(&j).unwrap();
        let j2 = serde_json::to_string(&back).unwrap();
        assert_eq!(j, j2, "round-trip mismatch");
        j
    }

    #[test]
    fn content_access_policy_info_shape() {
        let p = pol();
        assert_eq!(p.audience_kind, 1);
        assert_eq!(p.audience_label, "EnrolledStudents");
        assert!(p.audience_student_commitment.is_none());
        let j = round_trip(&p);
        for k in ["opens_at", "closes_at", "grace_until", "audience_kind", "audience_label", "audience_student_commitment", "revoke_on_course_archive"] {
            assert!(j.contains(k), "missing field {k}");
        }
    }

    #[test]
    fn managed_snip_ref_and_catalog_content_ref_info_shape() {
        let m = edu_snip_to_info(&snip());
        round_trip(&m);
        let c = crate::types::CatalogContentRefInfo {
            kind: 2,
            kind_label: edu_content_kind_label(2),
            r#ref: m,
        };
        assert_eq!(c.kind_label, "DefaultSyllabus");
        let j = round_trip(&c);
        assert!(j.contains("\"ref\""), "field must serialize as `ref`");
        assert!(j.contains("\"kind\"") && j.contains("\"kind_label\""));
    }

    #[test]
    fn offering_info_shape() {
        let o = StoredOffering {
            offering_id: [1; 32],
            catalog_id: [2; 32],
            term: "2026FA".into(),
            section: "A".into(),
            instruction_start_at: 1,
            instruction_end_at: 2,
            final_grade_submission_deadline: 3,
            owner: Address::from([8u8; 20]),
            status: 2,
            instructor_count: 1,
            instructor_root: [3; 32],
            content_count: 0,
            content_root: [0; 32],
            assessment_count: 0,
            assessment_root: [0; 32],
            enrollment_count: 0,
            enrollment_root: [0; 32],
            created_at_height: 5,
            updated_at_height: 6,
            nonce: 7,
        };
        let i = edu_offering_to_info(&o);
        assert_eq!(i.status_code, 2);
        assert_eq!(i.status_label, "EnrollmentClosed");
        assert_eq!(i.offering_id, format!("0x{}", "01".repeat(32)));
        assert_eq!(i.owner, o.owner.to_base58());
        round_trip(&i);
    }

    #[test]
    fn assessment_info_shape() {
        let a = StoredAssessment {
            offering_id: [1; 32],
            assessment_id: [2; 32],
            kind: 1,
            instructions: snip(),
            spec_commitment: [3; 32],
            opens_at: 0,
            due_at: 100,
            max_attempts: 2,
            weight_bps: 1000,
            answer_key_commitment: Some([0xAB; 32]),
            answer_key_access: Some(ContentAccessPolicy {
                opens_at: None,
                closes_at: None,
                grace_until: None,
                audience: AccessAudience::StaffOnly,
                revoke_on_course_archive: true,
            }),
            status: 1,
            created_at_height: 9,
        };
        let i = edu_assessment_to_info(&a);
        assert_eq!(i.kind_label, "Exam");
        assert_eq!(i.status_label, "Open");
        // Answer key is a commitment only — never plaintext.
        assert_eq!(i.answer_key_commitment, Some(format!("0x{}", "ab".repeat(32))));
        assert!(i.answer_key_access.is_some());
        round_trip(&i);
    }

    #[test]
    fn enrollment_link_info_shape() {
        let e = StoredEnrollmentLink {
            student_commitment: [0x44; 32],
            enrollment_ref: [0x66; 32],
            linked_at_height: 12,
        };
        let i = edu_enrollment_to_info(&e);
        assert_eq!(i.student_commitment, format!("0x{}", "44".repeat(32)));
        let j = round_trip(&i);
        // Only commitment + ref + height — no address-shaped field.
        assert!(j.contains("student_commitment") && j.contains("enrollment_ref"));
    }

    // ── DB-backed read-path tests (executor helper + converter, the
    //    exact substance each RPC handler runs) ──

    use sumchain_crypto::{sign, KeyPair};
    use sumchain_genesis::ChainParams;
    use sumchain_primitives::education::{
        catalog_op, offering_op, student_commitment, AddAssessmentData, AssessmentKind,
        CourseLevel, CreateCatalogEntryData, CreateOfferingData, EducationStandard,
        EducationTxData, GradeSubmissionData, LinkEnrollmentData, OpenEnrollmentData,
        PublishCatalogContentData, SubmitAssignmentReceiptData,
    };
    use sumchain_primitives::{SignedTransaction, TransactionV2, TxPayload};
    use sumchain_state::executor::BlockExecutor;
    use sumchain_state::state::StateManager;
    use sumchain_storage::Database;
    use std::sync::Arc;
    use tempfile::TempDir;

    const CID_CHAIN: u64 = 1;
    const FEE: u128 = 1_000;

    fn p_enabled() -> ChainParams {
        let mut p = ChainParams::default();
        p.education_enabled_from_height = Some(0);
        p
    }

    fn etx(sp: &KeyPair, nonce: u64, std_: EducationStandard, op: u16, data: Vec<u8>) -> SignedTransaction {
        let tx = TransactionV2 {
            chain_id: CID_CHAIN,
            from: sp.address(),
            fee: FEE,
            nonce,
            payload: TxPayload::Education(EducationTxData {
                standard: std_,
                operation: op,
                data,
                recipient: Address::ZERO,
            }),
        };
        let h = tx.signing_hash();
        let s = sign(h.as_bytes(), sp.private_key());
        SignedTransaction::new_v2(tx, *s.as_bytes(), *sp.public_key().as_bytes())
    }

    fn b<T: serde::Serialize>(v: &T) -> Vec<u8> {
        bincode::serialize(v).unwrap()
    }

    /// Commit a full education chain; return db + key ids for read tests.
    fn seed() -> (TempDir, Arc<Database>, [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CID_CHAIN));
        let ex = BlockExecutor::new(state.clone(), db.clone(), p_enabled());
        let sp = KeyPair::generate();
        let prop = KeyPair::generate();
        state
            .put_account(&sp.address(), &sumchain_storage::schema::AccountState { balance: 1_000_000, nonce: 0 })
            .unwrap();
        let inst = [0x21u8; 32];
        let cid = sumchain_primitives::education::catalog_id(&inst, "CS", "101", 1, 1);
        let mut n = 0u64;
        let mut hh = 1u64;
        macro_rules! run {
            ($s:expr,$o:expr,$d:expr) => {{
                let r = ex.execute_tx(&etx(&sp, n, $s, $o, $d), &prop.address(), hh, 50).unwrap();
                assert!(matches!(r.status, sumchain_primitives::TxStatus::Success), "seed step: {:?}", r.status);
                n += 1; hh += 1;
            }};
        }
        run!(EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, b(&CreateCatalogEntryData {
            catalog_id: cid, institution_id: inst, department: "CS".into(), course_code: "101".into(),
            course_title: Some("Intro".into()), title_commitment: None, course_level: CourseLevel::Undergraduate as u8,
            credit_hours: Some(3), credit_commitment: None, prerequisites_count: 0, prerequisites_root: None,
            version: 1, supersedes: None, nonce: 1,
        }));
        run!(EducationStandard::CourseCatalog, catalog_op::PUBLISH_CATALOG_CONTENT, b(&PublishCatalogContentData {
            catalog_id: cid, description_ref: Some(snip()), learning_outcomes_ref: None,
            default_syllabus_ref: None, default_assessment_policy_ref: None, nonce: 2,
        }));
        let oid = sumchain_primitives::education::offering_id(&cid, "2026FA", "A", &Address::ZERO, 1);
        run!(EducationStandard::CourseOffering, offering_op::CREATE_OFFERING, b(&CreateOfferingData {
            offering_id: oid, catalog_id: cid, term: "2026FA".into(), section: "A".into(),
            instruction_start_at: 0, instruction_end_at: 1000, final_grade_submission_deadline: 2000, nonce: 1,
        }));
        run!(EducationStandard::CourseOffering, offering_op::OPEN_ENROLLMENT, b(&OpenEnrollmentData { offering_id: oid, nonce: 2 }));
        let aid = [0x5au8; 32];
        run!(EducationStandard::CourseOffering, offering_op::ADD_ASSESSMENT, b(&AddAssessmentData {
            offering_id: oid, assessment_id: aid, kind: AssessmentKind::Assignment as u8, instructions: snip(),
            spec_commitment: [0; 32], opens_at: 0, due_at: 100, max_attempts: 2, weight_bps: 1000,
            answer_key_commitment: None, answer_key_access: None, nonce: 3,
        }));
        let sc = student_commitment(&[0xC1; 32], &oid, &[0xD1; 32]);
        run!(EducationStandard::CourseOffering, offering_op::LINK_ENROLLMENT, b(&LinkEnrollmentData {
            offering_id: oid, student_commitment: sc, enrollment_ref: [0xEE; 32], nonce: 4,
        }));
        run!(EducationStandard::CourseOffering, offering_op::SUBMIT_ASSIGNMENT, b(&SubmitAssignmentReceiptData {
            offering_id: oid, assessment_id: aid, student_commitment: sc, submission_commitment: [0xAA; 32],
            work: snip(), attempt: 0, enrollment_ref: [0xEE; 32], student_auth_commitment: None,
        }));
        run!(EducationStandard::CourseOffering, offering_op::GRADE_SUBMISSION, b(&GradeSubmissionData {
            offering_id: oid, assessment_id: aid, student_commitment: sc, grade_commitment: [0x12; 32],
            feedback: Some(snip()), grader_role: 1, nonce: 8,
        }));
        (dir, db, cid, oid, aid, sc)
    }

    #[test]
    fn db_backed_reads_present_and_missing() {
        let (_d, db, cid, oid, aid, sc) = seed();
        let ex = EducationExecutor::new(db.clone());

        // Present.
        let c = ex.get_catalog(&cid).unwrap().unwrap();
        let ci = edu_catalog_to_info(&c);
        assert_eq!(ci.catalog_id, edu_hex0x(&cid));
        assert_eq!(ci.status_label, "Active"); // published -> Active

        let content = ex.get_catalog_content(&cid).unwrap();
        assert_eq!(content.len(), 1); // only description_ref set
        assert_eq!(content[0].0, 0); // kind Description

        let o = ex.get_offering(&oid).unwrap().unwrap();
        assert_eq!(edu_offering_to_info(&o).status_label, "Active");

        let asmts = ex.list_assessments(&oid, 256).unwrap();
        assert_eq!(asmts.len(), 1);
        let ai = edu_assessment_to_info(&asmts[0]);
        assert_eq!(ai.assessment_id, edu_hex0x(&aid));

        assert!(ex.get_assessment(&oid, &aid).unwrap().is_some());
        let link = ex.get_enrollment_link(&oid, &sc).unwrap().unwrap();
        assert_eq!(edu_enrollment_to_info(&link).student_commitment, edu_hex0x(&sc));

        let rec = ex.get_submission_receipt(&oid, &aid, &sc, 0).unwrap().unwrap();
        assert_eq!(edu_submission_to_info(&rec).submission_commitment, edu_hex0x(&[0xAA; 32]));

        let subs = ex.list_submissions_by_student_commitment(&sc, 256).unwrap();
        assert_eq!(subs.len(), 1);

        let g = ex.get_grade_record(&oid, &aid, &sc).unwrap().unwrap();
        assert_eq!(edu_grade_to_info(&g).grade_commitment, edu_hex0x(&[0x12; 32]));

        // Missing → None.
        assert!(ex.get_catalog(&[0xFF; 32]).unwrap().is_none());
        assert!(ex.get_offering(&[0xFF; 32]).unwrap().is_none());
        assert!(ex.get_assessment(&oid, &[0xFF; 32]).unwrap().is_none());
        assert!(ex.get_enrollment_link(&oid, &[0xFF; 32]).unwrap().is_none());
        assert!(ex.get_submission_receipt(&oid, &aid, &sc, 99).unwrap().is_none());
        assert!(ex.get_grade_record(&oid, &[0xFF; 32], &sc).unwrap().is_none());
        assert!(ex.get_catalog_content(&[0xFF; 32]).unwrap().is_empty());
    }

    #[test]
    fn db_backed_list_by_index_and_limit_clamp() {
        // 3 catalogs under one institution; assert limit clamp.
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CID_CHAIN));
        let bex = BlockExecutor::new(state.clone(), db.clone(), p_enabled());
        let sp = KeyPair::generate();
        let prop = KeyPair::generate();
        state.put_account(&sp.address(), &sumchain_storage::schema::AccountState { balance: 1_000_000, nonce: 0 }).unwrap();
        let inst = [0x31u8; 32];
        for (i, code) in ["A", "B", "C"].iter().enumerate() {
            let cid = sumchain_primitives::education::catalog_id(&inst, "CS", code, 1, 1);
            let r = bex.execute_tx(&etx(&sp, i as u64, EducationStandard::CourseCatalog, catalog_op::CREATE_CATALOG_ENTRY, b(&CreateCatalogEntryData {
                catalog_id: cid, institution_id: inst, department: "CS".into(), course_code: (*code).into(),
                course_title: None, title_commitment: None, course_level: 0, credit_hours: Some(3),
                credit_commitment: None, prerequisites_count: 0, prerequisites_root: None, version: 1,
                supersedes: None, nonce: 1,
            })), &prop.address(), (i as u64) + 1, 0).unwrap();
            assert!(matches!(r.status, sumchain_primitives::TxStatus::Success));
        }
        let ex = EducationExecutor::new(db.clone());
        assert_eq!(ex.list_catalogs_by_institution(&inst, 256).unwrap().len(), 3);
        // Clamp: requesting 2 returns at most 2.
        assert_eq!(ex.list_catalogs_by_institution(&inst, 2).unwrap().len(), 2);
        // by_code returns exactly the one matching (department, code).
        assert_eq!(ex.list_catalogs_by_code("CS", "B", 256).unwrap().len(), 1);
        assert_eq!(ex.list_catalogs_by_code("CS", "ZZ", 256).unwrap().len(), 0);
        // offerings-by-catalog empty when none.
        assert!(ex.list_offerings_by_catalog(&[0x99; 32], 256).unwrap().is_empty());
    }

    #[test]
    fn bad_hex_param_is_invalid_params() {
        // The handler path's only failure mode before the executor is
        // hex parsing; assert it maps to InvalidParams (no panic, no
        // Internal). edu_parse_hex32 backs RpcServer::parse_hex32.
        assert!(edu_parse_hex32("nothex").is_err());
        assert!(edu_parse_hex32("0x1234").is_err());
        assert!(edu_parse_hex32(&"00".repeat(32)).is_ok());
    }

    #[test]
    fn all_response_types_privacy_serialization_scan() {
        // Build one of EVERY education Info response from seeded DB rows
        // and assert the combined JSON exposes no raw student address,
        // raw grade, submission body, answer-key plaintext, or SNIP
        // decryption material.
        const FORBIDDEN_STUDENT_ADDR: [u8; 20] = [0x7E; 20];
        let (_d, db, cid, oid, aid, sc) = seed();
        let ex = EducationExecutor::new(db.clone());

        let mut blobs: Vec<String> = Vec::new();
        blobs.push(serde_json::to_string(&edu_catalog_to_info(&ex.get_catalog(&cid).unwrap().unwrap())).unwrap());
        for (k, m) in ex.get_catalog_content(&cid).unwrap() {
            blobs.push(serde_json::to_string(&crate::types::CatalogContentRefInfo {
                kind: k, kind_label: edu_content_kind_label(k), r#ref: edu_snip_to_info(&m),
            }).unwrap());
        }
        blobs.push(serde_json::to_string(&edu_offering_to_info(&ex.get_offering(&oid).unwrap().unwrap())).unwrap());
        blobs.push(serde_json::to_string(&edu_assessment_to_info(&ex.get_assessment(&oid, &aid).unwrap().unwrap())).unwrap());
        blobs.push(serde_json::to_string(&edu_enrollment_to_info(&ex.get_enrollment_link(&oid, &sc).unwrap().unwrap())).unwrap());
        blobs.push(serde_json::to_string(&edu_submission_to_info(&ex.get_submission_receipt(&oid, &aid, &sc, 0).unwrap().unwrap())).unwrap());
        blobs.push(serde_json::to_string(&edu_grade_to_info(&ex.get_grade_record(&oid, &aid, &sc).unwrap().unwrap())).unwrap());
        let all = blobs.join("\n");

        // No raw student address pattern anywhere.
        assert!(!all.contains(&hex::encode(FORBIDDEN_STUDENT_ADDR)));
        // No raw-grade / plaintext / decryption-material field names.
        for banned in [
            "grade_value", "raw_grade", "plaintext", "answer_key_plaintext",
            "decryption", "decrypt_key", "submission_body", "work_bytes",
            "private_key", "secret",
        ] {
            assert!(!all.contains(banned), "leaked banned token: {banned}");
        }
        // Grade is exposed ONLY as a commitment.
        let gi = edu_grade_to_info(&ex.get_grade_record(&oid, &aid, &sc).unwrap().unwrap());
        assert_eq!(gi.grade_commitment, edu_hex0x(&[0x12; 32]));
        // Student appears only as a 32-byte commitment hex (64 chars).
        let si = edu_submission_to_info(&ex.get_submission_receipt(&oid, &aid, &sc, 0).unwrap().unwrap());
        assert_eq!(si.student_commitment, edu_hex0x(&sc));
        assert!(si.submitter != si.student_commitment);
    }
}

#[cfg(test)]
mod policy_rpc_tests {
    //! Coverage for the policy-account RPC surface (issue #23): the six read
    //! handlers and four no-key `policy_build*` helpers, driven through a real
    //! `RpcServer` over a temp-backed state. Builder outputs are decoded back
    //! into a `TransactionV2` and asserted field-by-field.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::policy_account::{
        ActionClass, PolicyAccount, PolicyAccountOperation, PolicyAccountStatus, PolicyAccountTxData,
        PolicyConfig, PolicyMember, PolicyProfile, Proposal, ProposalStatus,
    };
    use sumchain_primitives::{Hash, TransactionV2, TxPayload};
    use sumchain_state::policy_account_executor::{
        CreatePolicyAccountRequest as ExecCreate, ExecuteProposalRequest as ExecExec,
        SubmitProposalRequest as ExecSubmit,
    };
    use sumchain_state::MempoolConfig;
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, Arc<StateManager>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
            ChainParams::with_v2_enabled(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(64);
        let srv = RpcServer::new(
            db.clone(),
            state.clone(),
            mempool,
            engine,
            tx_sender,
            Arc::new(|| 0usize),
        );
        (srv, db, state, dir)
    }

    fn single_member_account(db: &Arc<Database>, member: &KeyPair) -> PolicyAccount {
        let members = vec![PolicyMember::new(member.address())];
        let salt = vec![7u8; 32];
        let id = PolicyAccount::compute_id(&members, &salt);
        let address = PolicyAccount::id_to_address(&id);
        let account = PolicyAccount {
            id,
            address,
            members,
            policy: PolicyConfig { profile: PolicyProfile::Personal, overrides: vec![] },
            nonce: 0,
            status: PolicyAccountStatus::Active,
            created_at: 0,
            created_timestamp: 0,
        };
        PolicyAccountStorage::new(db).policy_accounts().put(&account).unwrap();
        account
    }

    fn put_proposal(db: &Arc<Database>, account: &PolicyAccount, proposer: &KeyPair) -> Proposal {
        let action_data = vec![1u8, 2, 3];
        let action_hash = Hash::hash(&action_data);
        let id = Proposal::compute_id(&account.id, account.nonce, &action_hash);
        let proposal = Proposal {
            id,
            policy_account_id: account.id,
            policy_nonce: account.nonce,
            proposer: proposer.address(),
            action_class: ActionClass::TransferNative,
            action_data,
            action_hash,
            approvals: vec![],
            status: ProposalStatus::Pending,
            expires_at: 9_000_000_000_000,
            created_at: 0,
            created_height: 0,
        };
        PolicyAccountStorage::new(db).proposals().put(&proposal).unwrap();
        proposal
    }

    fn decode_tx(resp: &PolicyBuildResponse) -> TransactionV2 {
        let raw = hex::decode(resp.unsigned_tx.trim_start_matches("0x")).unwrap();
        bincode::deserialize(&raw).unwrap()
    }

    fn policy_payload(tx: &TransactionV2) -> &PolicyAccountTxData {
        match &tx.payload {
            TxPayload::PolicyAccount(d) => d,
            other => panic!("expected PolicyAccount payload, got {:?}", other),
        }
    }

    // ---------------- reads ----------------

    #[tokio::test]
    async fn read_get_account_and_by_address_and_member_list() {
        let (srv, db, _state, _dir) = server();
        let m = KeyPair::generate();
        let account = single_member_account(&db, &m);
        let id_hex = format!("0x{}", hex::encode(account.id));

        let by_id = srv.policy_get_account(id_hex.clone()).await.unwrap();
        assert_eq!(by_id.id, id_hex);
        assert_eq!(by_id.members.len(), 1);
        assert_eq!(by_id.nonce, 0);
        assert_eq!(by_id.status, "Active");

        let by_addr = srv.policy_get_account_by_address(account.address.to_base58()).await.unwrap();
        assert!(by_addr.is_some());
        assert_eq!(by_addr.unwrap().id, id_hex);

        // Unknown address -> None (not an error).
        let none = srv.policy_get_account_by_address(KeyPair::generate().address().to_base58()).await.unwrap();
        assert!(none.is_none());

        let mine = srv.policy_list_member_accounts(m.address().to_base58()).await.unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, id_hex);
    }

    #[tokio::test]
    async fn read_get_account_not_found_is_error() {
        let (srv, _db, _state, _dir) = server();
        let missing = format!("0x{}", hex::encode([9u8; 32]));
        assert!(srv.policy_get_account(missing).await.is_err());
    }

    #[tokio::test]
    async fn read_proposal_get_and_lists() {
        let (srv, db, _state, _dir) = server();
        let m = KeyPair::generate();
        let account = single_member_account(&db, &m);
        let proposal = put_proposal(&db, &account, &m);
        let pid_hex = format!("0x{}", hex::encode(proposal.id));
        let id_hex = format!("0x{}", hex::encode(account.id));

        let got = srv.policy_get_proposal(pid_hex.clone()).await.unwrap();
        assert_eq!(got.id, pid_hex);
        assert_eq!(got.status, "Pending");
        assert_eq!(got.action_class, "TransferNative");

        let all = srv.policy_list_proposals(id_hex.clone()).await.unwrap();
        assert_eq!(all.len(), 1);
        let pending = srv.policy_list_pending_proposals(id_hex).await.unwrap();
        assert_eq!(pending.len(), 1);
    }

    // ---------------- builders ----------------

    #[tokio::test]
    async fn build_create_account_encodes_unsigned_create() {
        let (srv, _db, _state, _dir) = server();
        let from = KeyPair::generate();
        let member = KeyPair::generate();
        let req = BuildCreateAccountRequest {
            from: from.address().to_base58(),
            members: vec![PolicyMemberInfo { address: member.address().to_base58(), weight: 1 }],
            policy: PolicyConfigInfo { profile: "Personal".to_string(), overrides: vec![] },
            salt: format!("0x{}", hex::encode([3u8; 32])),
            fee: None,
        };
        let resp = srv.policy_build_create_account(req).await.unwrap();

        // No signing happened; defaults filled.
        assert_eq!(resp.from, from.address().to_base58());
        assert_eq!(resp.nonce, 0);
        assert_eq!(resp.chain_id, 1);
        assert_eq!(resp.fee, POLICY_DEFAULT_FEE);

        let tx = decode_tx(&resp);
        assert_eq!(tx.from, from.address());
        assert_eq!(tx.chain_id, 1);
        assert_eq!(resp.signing_hash, format!("0x{}", hex::encode(tx.signing_hash().as_bytes())));

        let data = policy_payload(&tx);
        assert!(matches!(data.operation, PolicyAccountOperation::Create));
        let inner: ExecCreate = bincode::deserialize(&data.data).unwrap();
        assert_eq!(inner.members.len(), 1);
        assert_eq!(inner.members[0].address, member.address());
        assert_eq!(inner.salt, vec![3u8; 32]);

        // Derived ids match canonical computation.
        let expect_id = PolicyAccount::compute_id(&inner.members, &inner.salt);
        assert_eq!(resp.policy_account_id, Some(format!("0x{}", hex::encode(expect_id))));
        assert_eq!(resp.address, Some(PolicyAccount::id_to_address(&expect_id).to_base58()));
    }

    #[tokio::test]
    async fn build_submit_proposal_encodes_unsigned_submit() {
        let (srv, db, _state, _dir) = server();
        let m = KeyPair::generate();
        let account = single_member_account(&db, &m);
        let action = TxPayload::Transfer { to: KeyPair::generate().address(), amount: 5 };
        let action_payload = bincode::serialize(&action).unwrap();
        let approval = ApprovalInfo {
            approver_address: m.address().to_base58(),
            approver_pubkey: format!("0x{}", hex::encode(m.public_key().as_bytes())),
            signature: format!("0x{}", hex::encode([0u8; 64])),
        };
        let req = BuildSubmitProposalRequest {
            from: m.address().to_base58(),
            policy_account_id: format!("0x{}", hex::encode(account.id)),
            action_data: format!("0x{}", hex::encode(&action_payload)),
            approvals: vec![approval],
            expires_at: 9_000_000_000_000,
            fee: Some(2_500),
        };
        let resp = srv.policy_build_submit_proposal(req).await.unwrap();
        assert_eq!(resp.fee, 2_500);

        let tx = decode_tx(&resp);
        let data = policy_payload(&tx);
        assert!(matches!(data.operation, PolicyAccountOperation::SubmitProposal));
        let inner: ExecSubmit = bincode::deserialize(&data.data).unwrap();
        assert_eq!(inner.policy_account_id, account.id);
        assert_eq!(inner.action_payload, action_payload);
        assert_eq!(inner.approvals.len(), 1);
        assert_eq!(inner.approvals[0].approver_pubkey, *m.public_key().as_bytes());

        // Derived proposal id/action hash against the account's current nonce.
        let ah = Hash::hash(&action_payload);
        let pid = Proposal::compute_id(&account.id, account.nonce, &ah);
        assert_eq!(resp.proposal_id, Some(format!("0x{}", hex::encode(pid))));
        assert_eq!(resp.action_hash, Some(format!("0x{}", hex::encode(ah.as_bytes()))));
    }

    #[tokio::test]
    async fn build_execute_proposal_encodes_request_wrapper() {
        let (srv, _db, _state, _dir) = server();
        let from = KeyPair::generate();
        let pid = [4u8; 32];
        let resp = srv
            .policy_build_execute_proposal(BuildExecuteProposalRequest {
                from: from.address().to_base58(),
                proposal_id: format!("0x{}", hex::encode(pid)),
                fee: None,
            })
            .await
            .unwrap();
        let tx = decode_tx(&resp);
        let data = policy_payload(&tx);
        assert!(matches!(data.operation, PolicyAccountOperation::ExecuteProposal));
        let inner: ExecExec = bincode::deserialize(&data.data).unwrap();
        assert_eq!(inner.proposal_id, pid);
        assert_eq!(resp.signing_hash, format!("0x{}", hex::encode(tx.signing_hash().as_bytes())));
    }

    #[tokio::test]
    async fn build_cancel_proposal_encodes_raw_proposal_id() {
        // Blocker fix: the cancel payload must be exactly `CancelProposal`
        // plus a raw `ProposalId` (32 bytes), NOT an ExecuteProposalRequest
        // wrapper.
        let (srv, _db, _state, _dir) = server();
        let from = KeyPair::generate();
        let pid = [6u8; 32];
        let resp = srv
            .policy_build_cancel_proposal(BuildCancelProposalRequest {
                from: from.address().to_base58(),
                proposal_id: format!("0x{}", hex::encode(pid)),
                fee: None,
            })
            .await
            .unwrap();
        let tx = decode_tx(&resp);
        let data = policy_payload(&tx);
        assert!(matches!(data.operation, PolicyAccountOperation::CancelProposal));

        // Exactly the 32-byte id — bincode of a single [u8;32] is 32 raw bytes.
        assert_eq!(data.data.len(), 32, "cancel payload must be a raw ProposalId");
        assert_eq!(data.data, pid.to_vec());
        let decoded: [u8; 32] = bincode::deserialize(&data.data).unwrap();
        assert_eq!(decoded, pid);

        assert_eq!(resp.signing_hash, format!("0x{}", hex::encode(tx.signing_hash().as_bytes())));
    }
}

#[cfg(test)]
mod messaging_rpc_tests {
    //! Coverage for messaging_getSentMessages and messaging_getPendingPayments
    //! (issue #24) over a real RpcServer, reading only the new indexes.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::{Address, Hash, MessageEvent, PendingPayment};
    use sumchain_state::MempoolConfig;
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
            ChainParams::with_v2_enabled(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(64);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn event(sender: &Address, block: u64, tag: u8) -> MessageEvent {
        MessageEvent {
            sender: *sender,
            recipient_hash: [1u8; 32],
            message_id: Hash::hash(&[block as u8, tag]),
            size: 10,
            has_payment: false,
            block_height: block,
            timestamp: 0,
        }
    }

    #[tokio::test]
    async fn get_sent_messages_paginates_over_index() {
        let (srv, db, _dir) = server();
        let alice = Address::new([0xAA; 20]);
        let store = MessagingStore::new(&db);
        store.store_message_event(&event(&alice, 1, 0), 0).unwrap();
        store.store_message_event(&event(&alice, 2, 0), 0).unwrap();
        store.store_message_event(&event(&alice, 3, 0), 0).unwrap();

        let all = srv
            .messaging_get_sent_messages(alice.to_base58(), Some(100), Some(0))
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].sender, alice.to_base58());
        assert_eq!(all[0].block_height, 1);

        // offset 1, limit 1 -> the middle event.
        let page = srv
            .messaging_get_sent_messages(alice.to_base58(), Some(1), Some(1))
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].block_height, 2);

        // Unknown sender -> empty.
        let empty = srv
            .messaging_get_sent_messages(Address::new([0xCC; 20]).to_base58(), None, None)
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn get_pending_payments_lists_for_recipient() {
        let (srv, db, _dir) = server();
        let recipient = Address::new([0xDD; 20]);
        let rh = sumchain_crypto::recipient_hash(&recipient);
        let id = Hash::hash(b"pay1");
        MessagingStore::new(&db)
            .set_pending_payment(
                &id,
                &PendingPayment { recipient_hash: rh, amount: 250, expiry: 9, sender: Address::new([1; 20]) },
            )
            .unwrap();

        let listed = srv.messaging_get_pending_payments(recipient.to_base58()).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].message_id, format!("0x{}", hex::encode(id.as_bytes())));
        assert_eq!(listed[0].amount, "250");

        // Unrelated recipient -> empty.
        let empty = srv
            .messaging_get_pending_payments(Address::new([0xEE; 20]).to_base58())
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn invalid_address_is_rejected() {
        let (srv, _db, _dir) = server();
        assert!(srv.messaging_get_sent_messages("not-an-address".to_string(), None, None).await.is_err());
        assert!(srv.messaging_get_pending_payments("not-an-address".to_string()).await.is_err());
    }

    // Issue #20: storage_getArchiveUnbonding read shape.
    #[tokio::test]
    async fn archive_unbonding_read_roundtrips_and_absent_is_none() {
        let (srv, db, _dir) = server();
        let op = Address::new([0x2A; 20]);

        // No record yet -> None.
        assert!(srv
            .storage_get_archive_unbonding(op.to_base58())
            .await
            .unwrap()
            .is_none());

        // Persist a record directly, then read it back through the RPC.
        sumchain_state::NodeRegistryExecutor::new(db.clone())
            .put_archive_unbonding(&sumchain_primitives::ArchiveUnbondingRecord {
                operator: op,
                amount: 1_000_000_000,
                started_height: 7,
                unlock_height: 107,
                remaining_amount: 950_000_000,
            })
            .unwrap();

        let info = srv
            .storage_get_archive_unbonding(op.to_base58())
            .await
            .unwrap()
            .expect("record present");
        assert_eq!(info.operator, op.to_base58());
        assert_eq!(info.amount, 1_000_000_000);
        assert_eq!(info.started_height, 7);
        assert_eq!(info.unlock_height, 107);
        assert_eq!(info.remaining_amount, 950_000_000);

        // Malformed address is rejected, not silently None.
        assert!(srv
            .storage_get_archive_unbonding("not-an-address".to_string())
            .await
            .is_err());
    }

    // Issue #61: settlement builder round-trip + empty reads.
    #[tokio::test]
    async fn omninode_build_open_session_roundtrips() {
        use crate::inference_settlement_types::OmniBuildOpenSessionRequest;
        use sumchain_primitives::inference_settlement::InferenceSettlementOperation;
        use sumchain_primitives::{TransactionV2, TxPayload};
        let (srv, _db, _dir) = server();
        let from = KeyPair::generate();
        let resp = srv
            .omninode_build_open_inference_session(OmniBuildOpenSessionRequest {
                from: from.address().to_base58(),
                session_id: "s".to_string(),
                reward_per_verifier: 1_000_000,
                max_verifiers: 2,
                dispute_window_blocks: 10,
                expires_at_height: 1000,
                deposit: 2_000_000,
                fee: Some(1000),
                consistency: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.from, from.address().to_base58());
        assert_eq!(resp.fee, 1000);
        let bytes = hex::decode(resp.unsigned_tx.trim_start_matches("0x")).unwrap();
        let tx = TransactionV2::from_bytes(&bytes).unwrap();
        match tx.payload {
            TxPayload::InferenceSettlement(d) => match d.operation {
                InferenceSettlementOperation::OpenSession(o) => {
                    assert_eq!(o.session_id, "s");
                    assert_eq!(o.deposit, 2_000_000);
                    assert_eq!(o.max_verifiers, 2);
                }
                other => panic!("wrong op: {:?}", other),
            },
            other => panic!("wrong payload: {:?}", other),
        }
    }

    #[tokio::test]
    async fn omninode_settlement_reads_empty_and_reason() {
        let (srv, _db, _dir) = server();
        assert!(srv.omninode_get_inference_session("nope".to_string()).await.unwrap().is_none());
        assert!(srv.omninode_get_inference_claims("nope".to_string()).await.unwrap().is_empty());
        assert!(srv.omninode_get_inference_disputes("nope".to_string()).await.unwrap().is_empty());
        let c = srv
            .omninode_get_claimable_reward("nope".to_string(), KeyPair::generate().address().to_base58())
            .await
            .unwrap();
        assert!(!c.eligible);
        assert_eq!(c.reason, "session not found");
    }

    // Issue #77: consistency read groups attestations by the FULL digest tuple.
    #[tokio::test]
    async fn omninode_get_inference_consistency_groups_by_full_tuple() {
        use sumchain_primitives::inference_attestation::{
            inference_attestation_key, InferenceAttestationDigest, InferenceAttestationRecord,
        };
        use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
        let (srv, db, _dir) = server();
        let aexec = InferenceAttestationExecutor::new(db.clone());

        let mk = |v: u8, tuple: (u8, u8, u8, u8)| {
            let verifier = sumchain_primitives::Address::new([v; 20]);
            let digest = InferenceAttestationDigest {
                session_id: "s".to_string(),
                model_hash: [tuple.0; 32],
                manifest_root: [tuple.1; 32],
                response_hash: [tuple.2; 32],
                proof_root: [tuple.3; 32],
            };
            let rec = InferenceAttestationRecord {
                digest,
                verifier_signature: [0u8; 64],
                included_at_height: 1,
                tx_hash: sumchain_primitives::Hash::new([v; 32]),
            };
            aexec.put(&inference_attestation_key("s", &verifier), &rec, &verifier).unwrap();
        };
        // Two verifiers agree on tuple A; one holds tuple B; a fourth shares only
        // response_hash with A but differs elsewhere → its own singleton group.
        mk(0x11, (1, 2, 3, 4));
        mk(0x22, (1, 2, 3, 4));
        mk(0x33, (9, 9, 9, 9));
        mk(0x44, (7, 7, 3, 7)); // same response_hash (3), different tuple

        let report = srv.omninode_get_inference_consistency("s".to_string()).await.unwrap();
        assert_eq!(report.session_id, "s");
        assert!(report.consistency.is_none(), "no session opened → no config");
        // Three distinct full tuples ⇒ three groups; response_hash alone never merges.
        assert_eq!(report.groups.len(), 3, "groups: {:?}", report.groups);
        // Sorted: the 2-member tuple-A group is first.
        assert_eq!(report.groups[0].verifier_count, 2);
        assert_eq!(report.groups[0].verifiers.len(), 2);
        assert!(report.groups[1..].iter().all(|g| g.verifier_count == 1));
    }
}

#[cfg(test)]
mod contract_rpc_tests {
    //! Coverage for contract_getStorageAt + contract_estimateGas (issue #25).
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::transaction::ContractDeployData;
    use sumchain_primitives::Address;
    use sumchain_state::{ContractExecutorState, MempoolConfig};
    use tempfile::TempDir;

    // `new` writes key "k"->"VAL"; `one`/`two` write 1/2 slots; `boom` traps.
    const WAT: &str = r#"
    (module
      (import "env" "storage_write" (func $sw (param i32 i32 i32 i32)))
      (memory (export "memory") 1)
      (global $bump (mut i32) (i32.const 1024))
      (data (i32.const 0) "k")
      (data (i32.const 8) "VAL")
      (data (i32.const 16) "k2")
      (func (export "alloc") (param i32) (result i32)
        (local $p i32) (local.set $p (global.get $bump))
        (global.set $bump (i32.add (global.get $bump) (local.get 0))) (local.get $p))
      (func (export "new") (param i32 i32) (result i32)
        (call $sw (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3)) (i32.const 0))
      (func (export "one") (param i32 i32) (result i32)
        (call $sw (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3)) (i32.const 0))
      (func (export "two") (param i32 i32) (result i32)
        (call $sw (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
        (call $sw (i32.const 16) (i32.const 2) (i32.const 8) (i32.const 3)) (i32.const 0))
      (func (export "boom") (param i32 i32) (result i32) (unreachable)))
    "#;

    // Returns (server, deployed contract address).
    fn server_with_contract() -> (RpcServer, Address, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let params = ChainParams::with_contracts_enabled();

        // Deploy a storage-writing contract through the shared executor.
        let cexec = Arc::new(ContractExecutorState::new(db.clone(), params.clone()));
        let deployer = KeyPair::generate();
        let proposer = KeyPair::generate();
        state
            .put_account(
                &deployer.address(),
                &sumchain_storage::schema::AccountState { balance: 10_000_000, nonce: 0 },
            )
            .unwrap();
        let deploy_data = ContractDeployData {
            code: wat::parse_str(WAT).unwrap(),
            init_method: "new".to_string(),
            init_args: vec![],
            value: 0,
            gas_limit: 5_000_000,
        };
        let res = cexec
            .deploy(&deployer.address(), &deploy_data, &state, &proposer.address(), 1_000, 1, 1000)
            .unwrap();
        assert!(res.success, "deploy failed: {:?}", res.error);
        let addr = res.contract_address;

        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
            params,
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(64);
        let srv = RpcServer::new(db, state, mempool, engine, tx_sender, Arc::new(|| 0usize))
            .with_contract_executor(cexec);
        (srv, addr, dir)
    }

    fn view(contract: &Address, method: &str) -> ViewCallRequest {
        ViewCallRequest {
            contract: contract.to_base58(),
            method: method.to_string(),
            args: "0x".to_string(),
            from: None,
        }
    }

    #[tokio::test]
    async fn get_storage_at_present_missing_and_invalid() {
        let (srv, addr, _dir) = server_with_contract();

        // Present slot "k" (0x6b) -> "VAL" (0x56414c).
        let got = srv.contract_get_storage_at(addr.to_base58(), "0x6b".to_string()).await.unwrap();
        assert_eq!(got, Some("0x56414c".to_string()));

        // Missing slot -> None.
        let missing = srv.contract_get_storage_at(addr.to_base58(), "0xdead".to_string()).await.unwrap();
        assert!(missing.is_none());

        // Unknown contract address -> None (gated on existence).
        let none = srv
            .contract_get_storage_at(Address::new([9u8; 20]).to_base58(), "0x6b".to_string())
            .await
            .unwrap();
        assert!(none.is_none());

        // Invalid key hex -> error.
        assert!(srv.contract_get_storage_at(addr.to_base58(), "0xzz".to_string()).await.is_err());
    }

    #[tokio::test]
    async fn estimate_gas_varies_with_work_and_fails_loudly() {
        let (srv, addr, _dir) = server_with_contract();

        let one = srv.contract_estimate_gas(view(&addr, "one")).await.unwrap();
        let two = srv.contract_estimate_gas(view(&addr, "two")).await.unwrap();
        assert!(one.gas_estimate > 0, "estimate should be a real metered value");
        assert!(two.gas_estimate > one.gas_estimate, "more storage work => more gas");

        // A trapping method returns an error, not a fabricated estimate.
        assert!(srv.contract_estimate_gas(view(&addr, "boom")).await.is_err());
        // Unknown contract -> error.
        assert!(srv.contract_estimate_gas(view(&Address::new([9u8; 20]), "one")).await.is_err());
    }
}

#[cfg(test)]
mod tax_rpc_tests {
    //! Issue #26: Tax registry read RPCs over a real RpcServer (registry data
    //! only — claim types, issuers, policies).
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::tax::{
        ClaimTypeStatus, IssuerRequirements, QuorumRule, TaxClaimTypeEntry, TaxIssuer,
        TaxIssuerClass, TaxIssuerStatus, TaxPolicy, TaxPolicyTemplate, TaxRiskLevel,
    };
    use sumchain_primitives::Address;
    use sumchain_state::MempoolConfig;
    use sumchain_storage::{TaxClaimTypeStore, TaxIssuerStore, TaxPolicyStore};
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn seed(db: &Arc<Database>, active_issuer: Address, revoked_issuer: Address) {
        let ct = |id: &str| TaxClaimTypeEntry {
            claim_type: id.to_string(),
            schema_hash: [1u8; 32],
            risk_level: TaxRiskLevel::Medium,
            recommended_validity_secs: 86_400,
            required_issuer_classes: vec![vec![TaxIssuerClass::TaxAuthority]],
            status: ClaimTypeStatus::Active,
            version: 1,
            created_at: 100,
            updated_at: 100,
        };
        let cts = TaxClaimTypeStore::new(db);
        cts.put(&ct("tax.filed.return")).unwrap();
        cts.put(&ct("tax.paid.status")).unwrap();

        let iss = |addr: Address, class: TaxIssuerClass, status: TaxIssuerStatus| TaxIssuer {
            address: addr,
            tax_class: class,
            jurisdictions: vec!["US".to_string()],
            attributes_hash: [2u8; 32],
            attributes_schema_hash: [3u8; 32],
            registered_at: 200,
            updated_at: 200,
            status,
            expires_at: None,
        };
        let is = TaxIssuerStore::new(db);
        is.put(&iss(active_issuer, TaxIssuerClass::TaxAuthority, TaxIssuerStatus::Active)).unwrap();
        is.put(&iss(revoked_issuer, TaxIssuerClass::BankBroker, TaxIssuerStatus::Revoked)).unwrap();

        let ps = TaxPolicyStore::new(db);
        ps.put(&TaxPolicy {
            policy_id: [7u8; 32],
            template: TaxPolicyTemplate::Filed,
            claim_types: vec!["tax.filed.return".to_string()],
            issuer_requirements: IssuerRequirements {
                groups: vec![vec![TaxIssuerClass::AuditorCpa]],
                quorum: QuorumRule::Any,
            },
            jurisdictions: vec!["US".to_string()],
            tax_years: vec![2024],
            max_age_secs: 31_536_000,
            revocation_check: true,
            creator: Address::new([9u8; 20]),
            created_at: 300,
        })
        .unwrap();
    }

    #[tokio::test]
    async fn claim_type_reads() {
        let (srv, db, _dir) = server();
        seed(&db, Address::new([0xA1; 20]), Address::new([0xB2; 20]));

        let got = srv.tax_get_claim_type("tax.filed.return".to_string()).await.unwrap().unwrap();
        assert_eq!(got.claim_type, "tax.filed.return");
        assert_eq!(got.status, "Active");
        assert_eq!(got.risk_level, "Medium");
        assert_eq!(got.schema_hash, format!("0x{}", hex::encode([1u8; 32])));
        assert_eq!(got.required_issuer_classes, vec![vec!["TaxAuthority".to_string()]]);

        assert!(srv.tax_get_claim_type("tax.nope".to_string()).await.unwrap().is_none());
        assert_eq!(srv.tax_list_claim_types().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn issuer_reads() {
        let (srv, db, _dir) = server();
        let a = Address::new([0xA1; 20]);
        seed(&db, a, Address::new([0xB2; 20]));

        let got = srv.tax_get_issuer(a.to_base58()).await.unwrap().unwrap();
        assert_eq!(got.address, a.to_base58());
        assert_eq!(got.tax_class, "TaxAuthority");
        assert_eq!(got.attributes_hash, format!("0x{}", hex::encode([2u8; 32])));
        assert_eq!(got.status, "Active");

        assert!(srv.tax_get_issuer(Address::new([0xCC; 20]).to_base58()).await.unwrap().is_none());
        // Only the Active issuer.
        assert_eq!(srv.tax_get_active_issuers().await.unwrap().len(), 1);
        // Class filter + invalid class error.
        assert_eq!(srv.tax_get_issuers_by_class("TaxAuthority".to_string()).await.unwrap().len(), 1);
        assert_eq!(srv.tax_get_issuers_by_class("AuditorCpa".to_string()).await.unwrap().len(), 0);
        assert!(srv.tax_get_issuers_by_class("Bogus".to_string()).await.is_err());
    }

    #[tokio::test]
    async fn policy_reads() {
        let (srv, db, _dir) = server();
        seed(&db, Address::new([0xA1; 20]), Address::new([0xB2; 20]));

        let id_hex = format!("0x{}", hex::encode([7u8; 32]));
        let got = srv.tax_get_policy(id_hex.clone()).await.unwrap().unwrap();
        assert_eq!(got.policy_id, id_hex);
        assert_eq!(got.template, "Filed");
        assert_eq!(got.issuer_requirements.quorum, "Any");
        assert_eq!(got.creator, Address::new([9u8; 20]).to_base58());

        assert!(srv.tax_get_policy(format!("0x{}", hex::encode([0u8; 32]))).await.unwrap().is_none());
        assert_eq!(srv.tax_list_policies().await.unwrap().len(), 1);
    }
}

#[cfg(test)]
mod equity_rpc_tests {
    //! Issue #26: Equity registry read RPCs over a real RpcServer (entities,
    //! share classes, controller config only — no holder/ownership data).
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::equity::{
        ControllerModel, EntityProfile, EntityStatus, EquityControllerConfig, EquityToken, OrgType,
        ShareClassType, TokenStatus,
    };
    use sumchain_primitives::Address;
    use sumchain_state::MempoolConfig;
    use sumchain_storage::{EntityProfileStore, EquityControllerStore, EquityTokenStore};
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn seed(db: &Arc<Database>, ctrl: Address) {
        let es = EntityProfileStore::new(db);
        es.put(&EntityProfile {
            subject_id: [0xE1; 32],
            org_type: OrgType::Corporation,
            name_commitment: [1u8; 32],
            jurisdiction: Some("US-DE".to_string()),
            registration_commitment: None,
            controller_model: ControllerModel::SingleSigner,
            controllers: vec![ctrl],
            multisig_threshold: None,
            services: vec![],
            metadata_hash: [2u8; 32],
            created_at: 100,
            updated_at: 100,
            status: EntityStatus::Active,
        })
        .unwrap();

        let ts = EquityTokenStore::new(db);
        ts.put(&EquityToken {
            issuer_subject: [0xE1; 32],
            class_id: [0xA1; 32],
            share_class_type: ShareClassType::Common,
            name: "Common".to_string(),
            symbol: "CMN".to_string(),
            authorized_shares: 1_000_000,
            issued_shares: 250_000,
            votes_per_share: 1,
            economic_rights_hash: [3u8; 32],
            liquidation_preference_hash: None,
            dividend_policy_hash: None,
            conversion_rules_hash: None,
            controller: Address::new([9u8; 20]),
            par_value: Some(1),
            created_at: 200,
            updated_at: 200,
            status: TokenStatus::Active,
        })
        .unwrap();

        let cs = EquityControllerStore::new(db);
        cs.put(
            &[0xA1; 32],
            &EquityControllerConfig {
                address: Address::new([7u8; 20]),
                whitelist_enabled: true,
                trading_windows: vec![],
                transfer_limit: 0,
                governance_policy_id: [4u8; 32],
                paused: false,
            },
        )
        .unwrap();
    }

    #[tokio::test]
    async fn entity_reads() {
        let (srv, db, _dir) = server();
        let ctrl = Address::new([0xC1; 20]);
        seed(&db, ctrl);
        let id = format!("0x{}", hex::encode([0xE1; 32]));

        let got = srv.equity_get_entity(id.clone()).await.unwrap().unwrap();
        assert_eq!(got.subject_id, id);
        assert_eq!(got.org_type, "Corporation");
        assert_eq!(got.name_commitment, format!("0x{}", hex::encode([1u8; 32])));
        assert_eq!(got.controllers, vec![ctrl.to_base58()]);

        assert!(srv.equity_get_entity(format!("0x{}", hex::encode([0u8; 32]))).await.unwrap().is_none());
        assert_eq!(srv.equity_get_active_entities().await.unwrap().len(), 1);
        assert_eq!(srv.equity_get_entities_by_org_type("Corporation".to_string()).await.unwrap().len(), 1);
        assert_eq!(srv.equity_get_entities_by_org_type("LLC".to_string()).await.unwrap().len(), 0);
        assert!(srv.equity_get_entities_by_org_type("Bogus".to_string()).await.is_err());
        assert_eq!(srv.equity_get_entities_by_controller(ctrl.to_base58()).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn share_class_reads_exclude_issued_shares() {
        let (srv, db, _dir) = server();
        seed(&db, Address::new([0xC1; 20]));
        let cid = format!("0x{}", hex::encode([0xA1; 32]));

        let got = srv.equity_get_share_class(cid.clone()).await.unwrap().unwrap();
        assert_eq!(got.class_id, cid);
        assert_eq!(got.symbol, "CMN");
        assert_eq!(got.share_class_type, "Common");
        assert_eq!(got.authorized_shares, "1000000");
        // issued_shares must NOT be present: serialize to JSON and assert absence.
        let json = serde_json::to_string(&got).unwrap();
        assert!(!json.contains("issued_shares"), "issued_shares must not be exposed");
        assert!(json.contains("authorized_shares"));

        assert!(srv.equity_get_share_class(format!("0x{}", hex::encode([0u8; 32]))).await.unwrap().is_none());
        assert_eq!(srv.equity_get_active_share_classes().await.unwrap().len(), 1);
        assert_eq!(
            srv.equity_get_share_classes_by_issuer(format!("0x{}", hex::encode([0xE1; 32]))).await.unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn controller_config_read() {
        let (srv, db, _dir) = server();
        seed(&db, Address::new([0xC1; 20]));
        let cid = format!("0x{}", hex::encode([0xA1; 32]));

        let got = srv.equity_get_controller_config(cid).await.unwrap().unwrap();
        assert!(got.whitelist_enabled);
        assert_eq!(got.governance_policy_id, format!("0x{}", hex::encode([4u8; 32])));
        assert!(srv.equity_get_controller_config(format!("0x{}", hex::encode([0u8; 32]))).await.unwrap().is_none());
    }
}

#[cfg(test)]
mod agreement_rpc_tests {
    //! Issue #26: Agreement executor-link read RPCs over a real RpcServer.
    //! Executor links only — no commitments/parties/signatures/etc.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::agreement::{ExecutorLink, ExecutorState};
    use sumchain_primitives::Address;
    use sumchain_state::MempoolConfig;
    use sumchain_storage::ExecutorLinkStore;
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn seed(db: &Arc<Database>, exec: Address) {
        let store = ExecutorLinkStore::new(db);
        store
            .put(&ExecutorLink {
                link_id: [0x01; 32],
                agreement_id: [0xA1; 32],
                executor_contract: exec,
                executor_interface_id: [1u8; 32],
                terms_commitment: [2u8; 32],
                activation_policy_id: [3u8; 32],
                state: ExecutorState::Active,
                created_at: 100,
                updated_at: 100,
                created_at_height: 5,
                activation_proof_id: None,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn executor_link_reads() {
        let (srv, db, _dir) = server();
        let exec = Address::new([0xE1; 20]);
        seed(&db, exec);
        let lid = format!("0x{}", hex::encode([0x01; 32]));
        let aid = format!("0x{}", hex::encode([0xA1; 32]));

        let got = srv.agreement_get_executor_link(lid.clone()).await.unwrap().unwrap();
        assert_eq!(got.link_id, lid);
        assert_eq!(got.agreement_id, aid);
        assert_eq!(got.executor_contract, exec.to_base58());
        assert_eq!(got.state, "Active");
        assert_eq!(got.activation_proof_id, None);

        // Excluded/deferred fields must never appear in the serialized DTO.
        let json = serde_json::to_string(&got).unwrap();
        for banned in ["parties", "attachments", "hint_uri", "signed", "payload_hash", "encryption"] {
            assert!(!json.contains(banned), "ExecutorLinkInfo leaked banned field: {}", banned);
        }

        assert!(srv.agreement_get_executor_link(format!("0x{}", hex::encode([0u8; 32]))).await.unwrap().is_none());
        assert_eq!(srv.agreement_get_executor_links_by_agreement(aid).await.unwrap().len(), 1);
        assert_eq!(srv.agreement_get_executor_links_by_executor(exec.to_base58()).await.unwrap().len(), 1);
        assert_eq!(srv.agreement_get_active_executor_links().await.unwrap().len(), 1);
    }
}

#[cfg(test)]
mod property_rpc_tests {
    //! Issue #26: Property asset-anchor read RPCs over a real RpcServer.
    //! Asset anchors only — no title/encumbrance/coverage/claim/proof/event
    //! reads, no party identities, no public_reference, no off-chain content.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::property::{AssetAnchor, AssetStatus, AssetType, PropertyIssuerClass};
    use sumchain_primitives::Address;
    use sumchain_state::MempoolConfig;
    use sumchain_storage::AssetStore;
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn asset(asset_id: [u8; 32], jurisdiction: &str, issuer: Address, status: AssetStatus) -> AssetAnchor {
        AssetAnchor {
            asset_id,
            asset_commitment: [2u8; 32],
            asset_type: AssetType::SingleFamilyResidence,
            jurisdiction_code: jurisdiction.to_string(),
            // opt-in real-world identifier — must NOT surface in the DTO
            public_reference: Some("APN-1234-567-890".to_string()),
            policy_id: [3u8; 32],
            issuer_class: PropertyIssuerClass::LandRegistry,
            issuer_address: issuer,
            status,
            created_at: 1000,
            updated_at: 1100,
            anchored_at_height: 5,
            related_assets: vec![[0xAB; 32]],
            attachments: vec![],
        }
    }

    #[tokio::test]
    async fn asset_anchor_reads() {
        let (srv, db, _dir) = server();
        let store = AssetStore::new(&db);
        let issuer = Address::new([0xE1; 20]);
        store.put(&asset([0x01; 32], "US-CA-LA", issuer, AssetStatus::Active)).unwrap();
        store.put(&asset([0x02; 32], "US-CA-LA", issuer, AssetStatus::Deregistered)).unwrap();
        store.put(&asset([0x03; 32], "US-NY-NY", issuer, AssetStatus::Active)).unwrap();

        let aid = format!("0x{}", hex::encode([0x01; 32]));
        let got = srv.property_get_asset(aid.clone()).await.unwrap().unwrap();
        assert_eq!(got.asset_id, aid);
        assert_eq!(got.asset_type, "SingleFamilyResidence");
        assert_eq!(got.jurisdiction_code, "US-CA-LA");
        assert_eq!(got.issuer_class, "LandRegistry");
        assert_eq!(got.issuer_address, issuer.to_base58());
        assert_eq!(got.status, "Active");
        assert_eq!(got.anchored_at_height, 5);
        assert_eq!(got.related_assets, vec![format!("0x{}", hex::encode([0xAB; 32]))]);

        // Excluded/deferred fields must never appear in the serialized DTO.
        let json = serde_json::to_string(&got).unwrap();
        for banned in [
            "public_reference", "attachments", "hint_uri", "encryption", "grantor",
            "grantee", "holder", "obligor", "insured", "claimant", "premium", "loss_amount", "proof",
        ] {
            assert!(!json.contains(banned), "AssetInfo leaked banned field: {}", banned);
        }

        assert!(srv.property_get_asset(format!("0x{}", hex::encode([0u8; 32]))).await.unwrap().is_none());
        // list_active excludes the Deregistered asset
        assert_eq!(srv.property_get_active_assets().await.unwrap().len(), 2);
        assert_eq!(srv.property_get_assets_by_jurisdiction("US-CA-LA".to_string()).await.unwrap().len(), 2);
        assert_eq!(srv.property_get_assets_by_jurisdiction("US-NY-NY".to_string()).await.unwrap().len(), 1);
        assert_eq!(srv.property_get_assets_by_jurisdiction("US-TX-AU".to_string()).await.unwrap().len(), 0);
    }
}

#[cfg(test)]
mod finance_rpc_tests {
    //! Issue #26: Finance issuer-registry read RPCs over a real RpcServer.
    //! Institution issuer profiles only — no address proofs, bank-standing,
    //! KYC attestations, proofs, events, or any subject/holder data.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::finance::{FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus};
    use sumchain_primitives::Address;
    use sumchain_state::MempoolConfig;
    use sumchain_storage::FinanceIssuerStore;
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn issuer(addr: Address, jurisdiction: &str, status: FinanceIssuerStatus) -> FinanceIssuerProfile {
        FinanceIssuerProfile {
            issuer_address: addr,
            issuer_class: FinanceIssuerClass::RegulatedBank,
            issuer_commitment: [2u8; 32],
            jurisdiction_code: jurisdiction.to_string(),
            policy_id: [3u8; 32],
            status,
            registered_at_height: 5,
            created_at: 1000,
            updated_at: 1100,
        }
    }

    #[tokio::test]
    async fn finance_issuer_reads() {
        let (srv, db, _dir) = server();
        let store = FinanceIssuerStore::new(&db);
        let a = Address::new([0xA1; 20]);
        let b = Address::new([0xB2; 20]);
        let c = Address::new([0xC3; 20]);
        store.put(&issuer(a, "US", FinanceIssuerStatus::Active)).unwrap();
        store.put(&issuer(b, "US", FinanceIssuerStatus::Revoked)).unwrap();
        store.put(&issuer(c, "GB", FinanceIssuerStatus::Active)).unwrap();

        let got = srv.finance_get_issuer(a.to_base58()).await.unwrap().unwrap();
        assert_eq!(got.issuer_address, a.to_base58());
        assert_eq!(got.issuer_class, "RegulatedBank");
        assert_eq!(got.issuer_commitment, format!("0x{}", hex::encode([2u8; 32])));
        assert_eq!(got.jurisdiction_code, "US");
        assert_eq!(got.status, "Active");
        assert_eq!(got.registered_at_height, 5);

        // Excluded sensitive surfaces must never appear in the serialized DTO.
        let json = serde_json::to_string(&got).unwrap();
        for banned in [
            "subject", "holder", "account", "balance", "bracket", "kyc", "aml",
            "identity", "tenure", "address_commitment", "postal", "proof",
        ] {
            assert!(!json.contains(banned), "FinanceIssuerInfo leaked banned field: {}", banned);
        }

        // unknown address -> None
        assert!(srv.finance_get_issuer(Address::new([0u8; 20]).to_base58()).await.unwrap().is_none());
        // list_active excludes the Revoked issuer
        assert_eq!(srv.finance_get_active_issuers().await.unwrap().len(), 2);
        assert_eq!(srv.finance_get_issuers_by_jurisdiction("US".to_string()).await.unwrap().len(), 2);
        assert_eq!(srv.finance_get_issuers_by_jurisdiction("GB".to_string()).await.unwrap().len(), 1);
        assert_eq!(srv.finance_get_issuers_by_jurisdiction("FR".to_string()).await.unwrap().len(), 0);
    }
}

#[cfg(test)]
mod legal_rpc_tests {
    //! Issue #26: Legal case-anchor read RPCs over a real RpcServer.
    //! Case/docket anchors only — no case_type/public_reference/related_cases,
    //! no process events/orders/benefits/proofs/parties. Sealed cases are
    //! never returned.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::legal::{CaseAnchor, CaseStatus, CaseType, LegalIssuerClass};
    use sumchain_primitives::Address;
    use sumchain_state::MempoolConfig;
    use sumchain_storage::CaseStore;
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn case(case_id: [u8; 32], jurisdiction: &str, status: CaseStatus, related: Vec<[u8; 32]>) -> CaseAnchor {
        CaseAnchor {
            case_id,
            case_commitment: [2u8; 32],
            jurisdiction_code: jurisdiction.to_string(),
            // stigmatizing category + docket ref — must NOT surface in the DTO
            case_type: Some(CaseType::Criminal),
            public_reference: Some("2024-CR-12345".to_string()),
            policy_id: [3u8; 32],
            issuer_class: LegalIssuerClass::CourtSystem,
            issuer_address: Address::new([0xE1; 20]),
            status,
            created_at: 1000,
            updated_at: 1100,
            anchored_at_height: 5,
            related_cases: related,
        }
    }

    #[tokio::test]
    async fn case_anchor_reads_exclude_sealed_and_sensitive_fields() {
        let (srv, db, _dir) = server();
        let store = CaseStore::new(&db);
        // Active case in US-NY with a populated related_cases link.
        let linked = [0xCC; 32];
        store.put(&case([0x01; 32], "US-NY", CaseStatus::Active, vec![linked])).unwrap();
        store.put(&case([0x02; 32], "US-NY", CaseStatus::Filed, vec![])).unwrap();
        store.put(&case([0x03; 32], "US-NY", CaseStatus::Closed, vec![])).unwrap();
        store.put(&case([0x04; 32], "US-NY", CaseStatus::Sealed, vec![])).unwrap();
        store.put(&case([0x05; 32], "US-CA", CaseStatus::Active, vec![])).unwrap();

        let aid = format!("0x{}", hex::encode([0x01; 32]));
        let got = srv.legal_get_case(aid.clone()).await.unwrap().unwrap();
        assert_eq!(got.case_id, aid);
        assert_eq!(got.case_commitment, format!("0x{}", hex::encode([2u8; 32])));
        assert_eq!(got.jurisdiction_code, "US-NY");
        assert_eq!(got.issuer_class, "CourtSystem");
        assert_eq!(got.issuer_address, Address::new([0xE1; 20]).to_base58());
        assert_eq!(got.status, "Active");
        assert_eq!(got.anchored_at_height, 5);

        // Omitted/excluded fields must never appear in the serialized DTO —
        // including the populated related_cases link id.
        let json = serde_json::to_string(&got).unwrap();
        let linked_hex = hex::encode(linked);
        for banned in [
            "case_type", "Criminal", "public_reference", "2024-CR", "related_cases",
            linked_hex.as_str(), "parties", "party", "attachments", "hint_uri",
            "order", "benefit", "subject", "nullifier", "proof", "event",
        ] {
            assert!(!json.contains(banned), "CaseInfo leaked banned field: {}", banned);
        }

        // Sealed case must be reported as not found by get.
        assert!(srv.legal_get_case(format!("0x{}", hex::encode([0x04; 32]))).await.unwrap().is_none());
        // Unknown id -> None.
        assert!(srv.legal_get_case(format!("0x{}", hex::encode([0u8; 32]))).await.unwrap().is_none());

        // Active list = open (Filed/Active), excludes Sealed and Closed.
        let active = srv.legal_get_active_cases().await.unwrap();
        assert_eq!(active.len(), 3); // 0x01 Active, 0x02 Filed, 0x05 Active
        assert!(active.iter().all(|c| c.status == "Active" || c.status == "Filed"));

        // Jurisdiction list excludes the Sealed case (0x04).
        let ny = srv.legal_get_cases_by_jurisdiction("US-NY".to_string()).await.unwrap();
        assert_eq!(ny.len(), 3); // 0x01, 0x02, 0x03 (Closed retained); 0x04 Sealed excluded
        assert!(ny.iter().all(|c| c.status != "Sealed"));
        assert_eq!(srv.legal_get_cases_by_jurisdiction("US-CA".to_string()).await.unwrap().len(), 1);
        assert_eq!(srv.legal_get_cases_by_jurisdiction("US-TX".to_string()).await.unwrap().len(), 0);
    }
}

#[cfg(test)]
mod healthcare_rpc_tests {
    //! Issue #41: Healthcare institutional-only provider read RPCs over a real
    //! RpcServer. Organizational providers only (explicit allowlist); no
    //! individual clinicians, memberships, consents, prescriptions, proofs,
    //! events, or member/patient/subject data; no by-network query.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::healthcare::{
        HealthcareIssuerClass, ProviderProfile, ProviderStatus, ProviderType,
    };
    use sumchain_primitives::Address;
    use sumchain_state::MempoolConfig;
    use sumchain_storage::ProviderStore;
    use tempfile::TempDir;

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn provider(id: u8, ptype: ProviderType, status: ProviderStatus) -> ProviderProfile {
        ProviderProfile {
            provider_id: [id; 32],
            provider_commitment: [2u8; 32],
            provider_type: ptype,
            jurisdiction_code: "US-CA".to_string(),
            // individual-identifier field — must never surface in the DTO
            public_reference: Some("NPI-1234".to_string()),
            specialties_commitment: Some([3u8; 32]),
            credentials_commitment: Some([4u8; 32]),
            policy_id: [5u8; 32],
            issuer_class: HealthcareIssuerClass::AccreditationBody,
            issuer_address: Address::new([0xE1; 20]),
            status,
            created_at: 1000,
            updated_at: 1100,
            registered_at_height: 5,
            network_affiliations: vec![[0xAB; 32]],
            attachments: vec![],
        }
    }

    const ALLOWLIST: [ProviderType; 5] = [
        ProviderType::Hospital,
        ProviderType::HealthInsurer,
        ProviderType::Clinic,
        ProviderType::Pharmacy,
        ProviderType::Laboratory,
    ];

    // Representative non-allowlisted types: individual clinicians, org/plan
    // types outside the allowlist, a membership org, and Other.
    const EXCLUDED: [ProviderType; 10] = [
        ProviderType::Physician,
        ProviderType::Specialist,
        ProviderType::MentalHealthProvider,
        ProviderType::Dentist,
        ProviderType::Chiropractor,
        ProviderType::Telemedicine,
        ProviderType::Medicare,
        ProviderType::NursingFacility,
        ProviderType::GymFitness,
        ProviderType::Other,
    ];

    #[tokio::test]
    async fn allowlisted_institutions_returned() {
        let (srv, db, _dir) = server();
        let store = ProviderStore::new(&db);
        for (i, t) in ALLOWLIST.iter().enumerate() {
            store.put(&provider(i as u8 + 1, *t, ProviderStatus::Active)).unwrap();
        }
        // each allowlisted type is returned by get and present in the active list
        for i in 0..ALLOWLIST.len() {
            let pid = format!("0x{}", hex::encode([i as u8 + 1; 32]));
            assert!(srv.healthcare_get_institutional_provider(pid).await.unwrap().is_some());
        }
        assert_eq!(srv.healthcare_get_active_institutional_providers().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn non_allowlisted_types_excluded() {
        let (srv, db, _dir) = server();
        let store = ProviderStore::new(&db);
        for (i, t) in EXCLUDED.iter().enumerate() {
            store.put(&provider(i as u8 + 1, *t, ProviderStatus::Active)).unwrap();
        }
        // get returns None for every excluded type; active list is empty
        for i in 0..EXCLUDED.len() {
            let pid = format!("0x{}", hex::encode([i as u8 + 1; 32]));
            assert!(
                srv.healthcare_get_institutional_provider(pid).await.unwrap().is_none(),
                "excluded provider type leaked via get: {:?}", EXCLUDED[i]
            );
        }
        assert_eq!(srv.healthcare_get_active_institutional_providers().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn active_list_excludes_inactive_but_get_is_status_agnostic() {
        let (srv, db, _dir) = server();
        let store = ProviderStore::new(&db);
        // allowlisted but Suspended: absent from active list, still gettable by id
        store.put(&provider(1, ProviderType::Hospital, ProviderStatus::Suspended)).unwrap();
        store.put(&provider(2, ProviderType::Pharmacy, ProviderStatus::Active)).unwrap();

        assert_eq!(srv.healthcare_get_active_institutional_providers().await.unwrap().len(), 1);

        let suspended = srv
            .healthcare_get_institutional_provider(format!("0x{}", hex::encode([1u8; 32])))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(suspended.status, "Suspended");
        assert_eq!(suspended.jurisdiction_code, "US-CA");
        assert_eq!(suspended.issuer_class, "AccreditationBody");
        assert_eq!(suspended.issuer_address, Address::new([0xE1; 20]).to_base58());
        assert_eq!(suspended.registered_at_height, 5);

        // Omitted/excluded fields must never appear in the serialized DTO.
        let json = serde_json::to_string(&suspended).unwrap();
        let net_hex = hex::encode([0xAB; 32]);
        for banned in [
            "provider_type", "Hospital", "public_reference", "NPI-1234", "attachments",
            "network_affiliations", net_hex.as_str(), "member", "patient", "subject",
            "nullifier", "consent", "prescription", "medication", "proof", "event",
        ] {
            assert!(!json.contains(banned), "HealthcareProviderInfo leaked banned field: {}", banned);
        }
    }
}

#[cfg(test)]
mod governance_rpc_tests {
    //! Issue #50 Phase 4: governance builders (unsigned tx, no keys) + reads
    //! over a real RpcServer. Governance stays dormant; reads are gate-agnostic.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::governance::{
        ExecutionKind, ExternalRef, GovAsset, GovAssetKind, GovAssetStatus, GovProposal,
        GovProposalClass, GovProposalStatus, GovVote, GovernanceParams, VoteChoice, WeightRule,
    };
    use sumchain_primitives::{Address, TransactionV2, TxPayload};
    use sumchain_state::MempoolConfig;
    use sumchain_storage::GovStore;
    use tempfile::TempDir;

    const TOKEN: [u8; 32] = [0x7A; 32];

    fn gov_params() -> GovernanceParams {
        GovernanceParams {
            validator_authority_threshold_bps: 6_667,
            quorum_bps: 2_000,
            pass_threshold_bps: 5_000,
            voting_period_blocks: 100,
            max_snapshot_holders: 64,
            proposal_bond: 0,
            treasury: None,
        }
    }

    fn server(governance: Option<GovernanceParams>) -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let mut params = ChainParams::with_v2_enabled();
        params.governance_enabled_from_height = Some(0);
        params.governance = governance;
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            params.clone(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize))
            .with_chain_params(params);
        (srv, db, dir)
    }

    fn proposal(id: u8, status: GovProposalStatus) -> GovProposal {
        GovProposal {
            id: [id; 32],
            proposer: Address::new([0xA1; 20]),
            class: GovProposalClass::RoutineProcess,
            execution_kind: ExecutionKind::RecordOnly,
            external_ref: ExternalRef { url: "https://x/pr/1".into(), content_hash: [0xAB; 32] },
            asset: GovAssetKind::Src20Token(TOKEN),
            voting_start_height: 5,
            status,
            created_at: 1000,
            created_at_height: 5,
            expires_at: 1000,
            bond: 0,
            bond_state: sumchain_primitives::governance::BondState::Escrowed,
            treasury_beneficiary: None,
            treasury_amount: None,
        }
    }

    #[tokio::test]
    async fn builder_create_proposal_decodes_and_carries_no_key() {
        let (srv, _db, _dir) = server(Some(gov_params()));
        let from = Address::new([0x11; 20]);
        let resp = srv
            .gov_build_create_proposal(GovBuildCreateProposalRequest {
                from: from.to_base58(),
                token_id: format!("0x{}", hex::encode(TOKEN)),
                class: "RoutineProcess".into(),
                execution_kind: "RecordOnly".into(),
                external_ref_url: "https://x/pr/1".into(),
                external_ref_content_hash: format!("0x{}", hex::encode([0xAB; 32])),
                treasury_beneficiary: None,
                treasury_amount: None,
                fee: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.from, from.to_base58());
        assert_eq!(resp.nonce, 0);
        assert_eq!(resp.chain_id, 1);
        assert_eq!(resp.fee, GOV_DEFAULT_FEE);
        assert!(resp.proposal_id.is_none(), "no build-time proposal id in v1");

        // The response carries no key material; decode the unsigned tx.
        let bytes = hex::decode(resp.unsigned_tx.strip_prefix("0x").unwrap()).unwrap();
        let tx: TransactionV2 = bincode::deserialize(&bytes).unwrap();
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.chain_id, 1);
        match tx.payload {
            TxPayload::Governance(g) => {
                assert_eq!(g.operation, sumchain_primitives::governance::GovernanceOperation::CreateProposal);
                let req: sumchain_primitives::governance::CreateProposalRequest =
                    bincode::deserialize(&g.data).unwrap();
                assert_eq!(req.asset, GovAssetKind::Src20Token(TOKEN));
                assert_eq!(req.class, GovProposalClass::RoutineProcess);
            }
            other => panic!("expected Governance payload, got {:?}", other),
        }
        // Signing hash present; serialized DTO exposes no private-key field.
        assert!(resp.signing_hash.starts_with("0x"));
        assert!(!serde_json::to_string(&resp).unwrap().contains("private"));
    }

    #[tokio::test]
    async fn builders_cast_vote_and_execute_encode_ops_and_fee_override() {
        let (srv, _db, _dir) = server(Some(gov_params()));
        let from = Address::new([0x11; 20]);
        let pid = format!("0x{}", hex::encode([1u8; 32]));

        let vote = srv
            .gov_build_cast_vote(GovBuildCastVoteRequest { from: from.to_base58(), proposal_id: pid.clone(), choice: "Yes".into(), fee: Some(42) })
            .await
            .unwrap();
        assert_eq!(vote.fee, 42, "fee override");
        let tx: TransactionV2 = bincode::deserialize(&hex::decode(vote.unsigned_tx.strip_prefix("0x").unwrap()).unwrap()).unwrap();
        assert!(matches!(tx.payload, TxPayload::Governance(g) if g.operation == sumchain_primitives::governance::GovernanceOperation::CastVote));

        let exec = srv
            .gov_build_execute_proposal(GovBuildExecuteProposalRequest { from: from.to_base58(), proposal_id: pid, fee: None })
            .await
            .unwrap();
        let tx: TransactionV2 = bincode::deserialize(&hex::decode(exec.unsigned_tx.strip_prefix("0x").unwrap()).unwrap()).unwrap();
        assert!(matches!(tx.payload, TxPayload::Governance(g) if g.operation == sumchain_primitives::governance::GovernanceOperation::ExecuteProposal));

        // Invalid enum inputs are rejected.
        assert!(srv.gov_build_cast_vote(GovBuildCastVoteRequest { from: from.to_base58(), proposal_id: format!("0x{}", hex::encode([1u8;32])), choice: "Maybe".into(), fee: None }).await.is_err());
    }

    #[tokio::test]
    async fn reads_map_proposals_and_active_filter() {
        let (srv, db, _dir) = server(Some(gov_params()));
        let store = GovStore::new(&db);
        store.put_proposal(&proposal(1, GovProposalStatus::Voting)).unwrap();
        store.put_proposal(&proposal(2, GovProposalStatus::Recorded)).unwrap();

        let one = srv.gov_get_proposal(format!("0x{}", hex::encode([1u8; 32]))).await.unwrap().unwrap();
        assert_eq!(one.status, "Voting");
        assert_eq!(one.asset_token_id, format!("0x{}", hex::encode(TOKEN)));
        assert!(srv.gov_get_proposal(format!("0x{}", hex::encode([9u8; 32]))).await.unwrap().is_none());
        assert_eq!(srv.gov_list_proposals().await.unwrap().len(), 2);
        assert_eq!(srv.gov_list_active_proposals().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tally_with_params_computes_quorum_and_pass() {
        let (srv, db, _dir) = server(Some(gov_params()));
        let store = GovStore::new(&db);
        let pid = [1u8; 32];
        store.put_proposal(&proposal(1, GovProposalStatus::Voting)).unwrap();
        // snapshot total 1000; A=600 votes Yes, B=400 no vote.
        let a = Address::new([0xA1; 20]);
        let b = Address::new([0xB2; 20]);
        store.put_snapshot(&pid, &a, 600).unwrap();
        store.put_snapshot(&pid, &b, 400).unwrap();
        store.put_vote(&GovVote { proposal_id: pid, voter: a, weight: 600, choice: VoteChoice::Yes, cast_at_height: 6 }).unwrap();

        let t = srv.gov_get_tally(format!("0x{}", hex::encode(pid))).await.unwrap().unwrap();
        assert_eq!(t.snapshot_total, "1000");
        assert_eq!(t.yes, "600");
        assert_eq!(t.participation, "600");
        assert_eq!(t.quorum_met, Some(true)); // 600/1000 = 60% >= 20%
        assert_eq!(t.passed, Some(true));     // 600/600 = 100% >= 50%
        assert_eq!(t.projected_status, "Passed");
    }

    #[tokio::test]
    async fn tally_without_params_is_counts_only() {
        let (srv, db, _dir) = server(None); // governance params absent
        let store = GovStore::new(&db);
        let pid = [1u8; 32];
        store.put_proposal(&proposal(1, GovProposalStatus::Voting)).unwrap();
        store.put_snapshot(&pid, &Address::new([0xA1; 20]), 100).unwrap();

        let t = srv.gov_get_tally(format!("0x{}", hex::encode(pid))).await.unwrap().unwrap();
        assert_eq!(t.quorum_met, None);
        assert_eq!(t.passed, None);
        assert_eq!(t.projected_status, "CountsOnly");
    }

    #[tokio::test]
    async fn vote_and_voting_power_and_assets() {
        let (srv, db, _dir) = server(Some(gov_params()));
        let store = GovStore::new(&db);
        let pid = [1u8; 32];
        let voter = Address::new([0x11; 20]);
        store.put_vote(&GovVote { proposal_id: pid, voter, weight: 250, choice: VoteChoice::Yes, cast_at_height: 6 }).unwrap();
        store.put_snapshot(&pid, &voter, 250).unwrap();
        store.put_asset(&GovAsset { asset: GovAssetKind::Src20Token(TOKEN), create_threshold: 10, vote_weight_rule: WeightRule::Linear, status: GovAssetStatus::Enabled, effective_height: 0 }).unwrap();

        let v = srv.gov_get_vote(format!("0x{}", hex::encode(pid)), voter.to_base58()).await.unwrap().unwrap();
        assert_eq!(v.weight, "250");
        assert_eq!(v.choice, "Yes");
        let vp = srv.gov_get_voting_power(format!("0x{}", hex::encode(pid)), voter.to_base58()).await.unwrap().unwrap();
        assert_eq!(vp.weight, "250");
        // Missing rows → None.
        assert!(srv.gov_get_vote(format!("0x{}", hex::encode(pid)), Address::new([0x99; 20]).to_base58()).await.unwrap().is_none());
        assert!(srv.gov_get_voting_power(format!("0x{}", hex::encode(pid)), Address::new([0x99; 20]).to_base58()).await.unwrap().is_none());

        let assets = srv.gov_list_eligible_assets().await.unwrap();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].token_id, format!("0x{}", hex::encode(TOKEN)));
        assert_eq!(assets[0].status, "Enabled");
    }

    #[tokio::test]
    async fn dormant_reads_are_empty_and_safe() {
        let (srv, _db, _dir) = server(None); // no params, empty store
        assert!(srv.gov_list_proposals().await.unwrap().is_empty());
        assert!(srv.gov_list_active_proposals().await.unwrap().is_empty());
        assert!(srv.gov_list_eligible_assets().await.unwrap().is_empty());
        assert!(srv.gov_get_proposal(format!("0x{}", hex::encode([1u8; 32]))).await.unwrap().is_none());
        assert!(srv.gov_get_tally(format!("0x{}", hex::encode([1u8; 32]))).await.unwrap().is_none());
    }
}

#[cfg(test)]
mod tx_semantics_tests {
    //! Coverage for read-time transaction semantic labels (`tx_semantics`) and
    //! the token-scoped `token_getMinters` handler (issue #64). Both are derived
    //! from already-public data; nothing here persists or infers beyond the
    //! payload / token config.
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_crypto::KeyPair;
    use sumchain_genesis::{ChainParams, Genesis};
    use sumchain_primitives::governance::{GovernanceOperation, GovernanceTxData};
    use sumchain_primitives::inference_attestation::{
        InferenceAttestationDigest, InferenceAttestationTxData,
    };
    use sumchain_primitives::storage_metadata::{
        StorageMetadataOperationV2, StorageMetadataV2TxData,
    };
    use sumchain_primitives::{
        Address, Hash, NftOperation, NftTxData, SignedTransaction, TokenOperation, TokenTxData,
        Transaction, TransactionV2, TxPayload,
    };
    use sumchain_state::MempoolConfig;
    use sumchain_storage::Src20TokenData;
    use tempfile::TempDir;

    fn v2(payload: TxPayload) -> SignedTransaction {
        let tx = TransactionV2 {
            chain_id: 1,
            from: Address::new([1u8; 20]),
            fee: 1000,
            nonce: 0,
            payload,
        };
        SignedTransaction::new_v2(tx, [0u8; 64], [0u8; 32])
    }

    #[test]
    fn legacy_transfer_is_native() {
        let tx = SignedTransaction::new(
            Transaction {
                chain_id: 1,
                from: Address::new([1u8; 20]),
                to: Address::new([2u8; 20]),
                amount: 5,
                fee: 1000,
                nonce: 0,
            },
            [0u8; 64],
            [0u8; 32],
        );
        let (t, a, r, k) = RpcServer::tx_semantics(&tx);
        assert_eq!(t, "Transfer");
        assert_eq!(a, None);
        assert_eq!(r, None);
        assert_eq!(k.as_deref(), Some("native"));
    }

    #[test]
    fn v2_transfer_is_native() {
        let tx = v2(TxPayload::Transfer { to: Address::new([2u8; 20]), amount: 7 });
        let (t, a, _r, k) = RpcServer::tx_semantics(&tx);
        assert_eq!(t, "Transfer");
        assert_eq!(a, None);
        assert_eq!(k.as_deref(), Some("native"));
    }

    #[test]
    fn token_mint_action_and_asset() {
        let tx = v2(TxPayload::Token(TokenTxData {
            token_id: [9u8; 32],
            operation: TokenOperation::Mint,
            data: vec![],
        }));
        let (t, a, r, k) = RpcServer::tx_semantics(&tx);
        assert_eq!(t, "Token");
        assert_eq!(a.as_deref(), Some("Mint"));
        assert_eq!(r.as_deref(), Some("09".repeat(32).as_str()));
        assert_eq!(k.as_deref(), Some("src20"));
    }

    #[test]
    fn token_create_zero_id_has_no_asset_ref() {
        let tx = v2(TxPayload::Token(TokenTxData {
            token_id: [0u8; 32],
            operation: TokenOperation::Create,
            data: vec![],
        }));
        let (_t, a, r, _k) = RpcServer::tx_semantics(&tx);
        assert_eq!(a.as_deref(), Some("Create"));
        assert_eq!(r, None);
    }

    #[test]
    fn nft_asset_ref_is_collection() {
        let tx = v2(TxPayload::Nft(NftTxData {
            collection_id: [7u8; 32],
            token_id: 3,
            operation: NftOperation::Mint,
            data: vec![],
        }));
        let (t, a, r, k) = RpcServer::tx_semantics(&tx);
        assert_eq!(t, "Nft");
        assert_eq!(a.as_deref(), Some("Mint"));
        assert_eq!(r.as_deref(), Some("07".repeat(32).as_str()));
        assert_eq!(k.as_deref(), Some("nft"));
    }

    #[test]
    fn storage_v2_reassign_action() {
        let tx = v2(TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: Hash::hash(b"f") },
        }));
        let (t, a, r, k) = RpcServer::tx_semantics(&tx);
        assert_eq!(t, "StorageMetadataV2");
        assert_eq!(a.as_deref(), Some("ReassignChunksV2"));
        assert_eq!(r, None);
        assert_eq!(k, None);
    }

    #[test]
    fn governance_castvote_action() {
        let tx = v2(TxPayload::Governance(GovernanceTxData {
            operation: GovernanceOperation::CastVote,
            data: vec![],
        }));
        let (t, a, _r, _k) = RpcServer::tx_semantics(&tx);
        assert_eq!(t, "Governance");
        assert_eq!(a.as_deref(), Some("CastVote"));
    }

    #[test]
    fn inference_attestation_has_no_action() {
        let digest = InferenceAttestationDigest {
            session_id: "s".into(),
            model_hash: [0u8; 32],
            manifest_root: [0u8; 32],
            response_hash: [0u8; 32],
            proof_root: [0u8; 32],
        };
        let tx = v2(TxPayload::InferenceAttestation(InferenceAttestationTxData {
            digest,
            verifier_signature: [0u8; 64],
        }));
        let (t, a, r, k) = RpcServer::tx_semantics(&tx);
        assert_eq!(t, "InferenceAttestation");
        assert_eq!(a, None);
        assert_eq!(r, None);
        assert_eq!(k, None);
    }

    fn server() -> (RpcServer, Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1_000_000u128)]),
            ChainParams::with_v2_enabled(),
        );
        let engine = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator))
                .unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(64);
        let srv = RpcServer::new(db.clone(), state, mempool, engine, tx_sender, Arc::new(|| 0usize));
        (srv, db, dir)
    }

    fn put_token(db: &Arc<Database>, id: [u8; 32], owner: Address, minters: Vec<Address>) {
        let data = Src20TokenData {
            name: "T".into(),
            symbol: "T".into(),
            decimals: 9,
            owner,
            total_supply: 0,
            max_supply: 0,
            mintable: true,
            burnable: false,
            pausable: false,
            paused: false,
            minters,
            created_at: 0,
            created_at_block: 0,
        };
        TokenStore::new(db).put_token(&id, &data).unwrap();
    }

    #[tokio::test]
    async fn minters_owner_and_explicit_then_removed_reflects_live() {
        let (srv, db, _dir) = server();
        let owner = Address::new([3u8; 20]);
        let minter = Address::new([4u8; 20]);
        let id = [1u8; 32];
        put_token(&db, id, owner, vec![minter]);
        let hex_id = format!("0x{}", hex::encode(id));

        let info = srv.token_get_minters(hex_id.clone()).await.unwrap().unwrap();
        assert_eq!(info.owner, owner.to_base58());
        assert_eq!(info.minters, vec![minter.to_base58()]);

        // Minter removed → read reflects current config immediately (no staleness).
        put_token(&db, id, owner, vec![]);
        let info2 = srv.token_get_minters(hex_id).await.unwrap().unwrap();
        assert_eq!(info2.owner, owner.to_base58());
        assert!(info2.minters.is_empty());
    }

    #[tokio::test]
    async fn minters_absent_token_is_none() {
        let (srv, _db, _dir) = server();
        let hex_id = format!("0x{}", hex::encode([9u8; 32]));
        assert!(srv.token_get_minters(hex_id).await.unwrap().is_none());
    }
}

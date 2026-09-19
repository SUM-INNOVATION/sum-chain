//! # SUM Chain RPC
//!
//! JSON-RPC server for querying chain state and submitting transactions.

pub mod api;
pub mod auth;
pub mod governance_types;
pub mod inference_settlement_types;
pub mod health;
pub mod metrics;
pub mod pagination;
pub mod policy_account_types;
pub mod registry_types;
pub mod rate_limit;
pub mod server;
pub mod types;

pub use auth::{generate_api_key, ApiKeyValidator, RpcAuthConfig};
pub use health::{HealthCheck, HealthServer, HealthServerHandle, LivenessStatus, MetricsProvider, ReadinessChecks, ReadinessStatus};
pub use jsonrpsee::server::ServerHandle;
pub use metrics::{GlobalMetrics, Metrics, MetricsSnapshot};
pub use pagination::{page_of, RPC_PAGE_DEFAULT, RPC_PAGE_MAX, RPC_PAGE_OFFSET_MAX};
pub use rate_limit::{RateLimitConfig, RateLimitError, RateLimiter};
pub use server::{P2pStatsProvider, PeerInfoProvider, RpcServer, RpcTimeoutConfig};
pub use types::*;

use thiserror::Error;

/// RPC errors
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Server error: {0}")]
    Server(String),

    #[error("Invalid params: {0}")]
    InvalidParams(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Transaction rejected: {0}")]
    TxRejected(String),

    /// This node cannot answer for the height it was asked about, because the
    /// state that would answer it was never on this machine.
    ///
    /// Its own error code, deliberately. Every other way of declining a
    /// historical question — `null` from a block lookup, an empty list, `false`
    /// from a finality check — is ALSO the answer for a height that simply has
    /// nothing at it, and a caller cannot tell the two apart. A node seeded from
    /// a snapshot at height `h` holds no state and no blocks below `h`: "absent"
    /// and "I cannot know" are different claims, and only one of them is true.
    #[error("Below this node's state-history floor: {0}")]
    BelowHistoryFloor(String),

    /// The caller asked for a page this node will not serve.
    ///
    /// Its own error code, for the same reason `BelowHistoryFloor` has one: the
    /// alternative is to CLAMP the request down to the maximum and answer it,
    /// and a clamped answer is a truncated answer that looks exactly like a
    /// complete one. A caller who asks for 100,000 rows and silently receives
    /// 1,000 has no way to learn that the other 99,000 exist. Refusing says so,
    /// and says it in a code a client can branch on rather than in prose.
    #[error("Page out of bounds: {0}")]
    PageOutOfBounds(String),
}

impl From<RpcError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(e: RpcError) -> Self {
        match e {
            RpcError::InvalidParams(msg) => {
                jsonrpsee::types::ErrorObject::owned(-32602, msg, None::<()>)
            }
            RpcError::NotFound(msg) => jsonrpsee::types::ErrorObject::owned(-32001, msg, None::<()>),
            RpcError::TxRejected(msg) => {
                jsonrpsee::types::ErrorObject::owned(-32002, msg, None::<()>)
            }
            // Distinct from -32001 (Not found) on purpose: -32001 says the thing
            // is not there, -32003 says this node is not in a position to say.
            RpcError::BelowHistoryFloor(msg) => {
                jsonrpsee::types::ErrorObject::owned(-32003, msg, None::<()>)
            }
            // Distinct from -32602 (Invalid params) on purpose: the parameter
            // is well formed and the node understood it, and refused it. A
            // client that retries with a smaller page is doing the right thing;
            // a client that treats it as a malformed request is not.
            RpcError::PageOutOfBounds(msg) => {
                jsonrpsee::types::ErrorObject::owned(-32004, msg, None::<()>)
            }
            _ => jsonrpsee::types::ErrorObject::owned(-32603, e.to_string(), None::<()>),
        }
    }
}

pub type Result<T> = std::result::Result<T, RpcError>;

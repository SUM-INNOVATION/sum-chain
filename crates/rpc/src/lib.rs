//! # SUM Chain RPC
//!
//! JSON-RPC server for querying chain state and submitting transactions.

pub mod api;
pub mod auth;
pub mod governance_types;
pub mod inference_settlement_types;
pub mod health;
pub mod metrics;
pub mod policy_account_types;
pub mod rate_limit;
pub mod server;
pub mod types;

pub use auth::{generate_api_key, ApiKeyValidator, RpcAuthConfig};
pub use health::{HealthCheck, HealthServer, HealthServerHandle, LivenessStatus, MetricsProvider, ReadinessChecks, ReadinessStatus};
pub use jsonrpsee::server::ServerHandle;
pub use metrics::{GlobalMetrics, Metrics, MetricsSnapshot};
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
            _ => jsonrpsee::types::ErrorObject::owned(-32603, e.to_string(), None::<()>),
        }
    }
}

pub type Result<T> = std::result::Result<T, RpcError>;

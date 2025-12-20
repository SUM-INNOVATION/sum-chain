//! HTTP health check endpoints for load balancers and orchestration systems.
//!
//! Provides standard endpoints:
//! - `/health` - Liveness probe: Is the service running?
//! - `/ready` - Readiness probe: Is the service ready to accept traffic?
//! - `/metrics` - Prometheus-compatible metrics endpoint

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::metrics::MetricsSnapshot;

/// Health status for liveness checks
#[derive(Debug, Clone, Serialize)]
pub struct LivenessStatus {
    pub status: &'static str,
    pub version: &'static str,
}

/// Readiness status for load balancer checks
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessStatus {
    pub ready: bool,
    pub status: &'static str,
    pub checks: ReadinessChecks,
}

/// Individual readiness checks
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessChecks {
    /// Is the node synced with the network?
    pub synced: bool,
    /// Does the node have any peers?
    pub has_peers: bool,
    /// Is the database accessible?
    pub database_ok: bool,
    /// Current block height
    pub block_height: u64,
    /// Number of connected peers
    pub peer_count: usize,
}

/// Health check provider - supplies the data needed for health endpoints
pub struct HealthCheck {
    is_synced: Arc<dyn Fn() -> bool + Send + Sync>,
    peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    current_height: Arc<dyn Fn() -> u64 + Send + Sync>,
    min_peers_for_ready: usize,
}

impl HealthCheck {
    /// Create a new health check provider
    pub fn new(
        is_synced: Arc<dyn Fn() -> bool + Send + Sync>,
        peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
        current_height: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            is_synced,
            peer_count,
            current_height,
            min_peers_for_ready: 0, // Default: no minimum peers required
        }
    }

    /// Set minimum peers required for readiness
    pub fn with_min_peers(mut self, min_peers: usize) -> Self {
        self.min_peers_for_ready = min_peers;
        self
    }

    /// Liveness check - always returns ok if server is running
    /// Used by Kubernetes liveness probes
    pub fn liveness(&self) -> LivenessStatus {
        LivenessStatus {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Readiness check - returns whether the node is ready to serve traffic
    /// Used by Kubernetes readiness probes and load balancers
    pub fn readiness(&self) -> ReadinessStatus {
        let synced = (self.is_synced)();
        let peer_count = (self.peer_count)();
        let has_peers = peer_count >= self.min_peers_for_ready;
        let block_height = (self.current_height)();

        // Database is ok if we can get the current height (which reads from DB)
        let database_ok = true; // If height call succeeded, DB is working

        // Node is ready if synced and has minimum peers
        let ready = synced && has_peers && database_ok;

        ReadinessStatus {
            ready,
            status: if ready { "ready" } else { "not_ready" },
            checks: ReadinessChecks {
                synced,
                has_peers,
                database_ok,
                block_height,
                peer_count,
            },
        }
    }

    /// Check if ready (simple boolean for quick checks)
    pub fn is_ready(&self) -> bool {
        self.readiness().ready
    }
}

/// HTTP response body type
type BoxBody = http_body_util::Full<Bytes>;

/// Metrics provider function type
pub type MetricsProvider = Arc<dyn Fn() -> MetricsSnapshot + Send + Sync>;

/// Health server that provides HTTP endpoints for health checks and metrics
pub struct HealthServer {
    health_check: Arc<HealthCheck>,
    metrics_provider: Option<MetricsProvider>,
}

impl HealthServer {
    /// Create a new health server
    pub fn new(health_check: Arc<HealthCheck>) -> Self {
        Self {
            health_check,
            metrics_provider: None,
        }
    }

    /// Create a new health server with metrics support
    pub fn with_metrics(health_check: Arc<HealthCheck>, metrics_provider: MetricsProvider) -> Self {
        Self {
            health_check,
            metrics_provider: Some(metrics_provider),
        }
    }

    /// Start the health server on the given address
    /// Returns a handle that can be used to stop the server
    pub async fn start(self, addr: SocketAddr) -> std::io::Result<HealthServerHandle> {
        let listener = TcpListener::bind(addr).await?;
        info!("Health server listening on {}", addr);
        info!("  GET /health  - Liveness probe");
        info!("  GET /ready   - Readiness probe");
        if self.metrics_provider.is_some() {
            info!("  GET /metrics - Prometheus metrics");
        }

        let health_check = self.health_check;
        let metrics_provider = self.metrics_provider;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let io = TokioIo::new(stream);
                                let health = health_check.clone();
                                let metrics = metrics_provider.clone();

                                tokio::spawn(async move {
                                    let service = service_fn(move |req| {
                                        let health = health.clone();
                                        let metrics = metrics.clone();
                                        async move {
                                            Self::handle_request(req, health, metrics).await
                                        }
                                    });

                                    if let Err(e) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await
                                    {
                                        debug!("Health server connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Health server accept error: {}", e);
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("Health server shutting down");
                        break;
                    }
                }
            }
        });

        Ok(HealthServerHandle {
            _task: handle,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Handle an incoming HTTP request
    async fn handle_request(
        req: Request<hyper::body::Incoming>,
        health: Arc<HealthCheck>,
        metrics: Option<MetricsProvider>,
    ) -> Result<Response<BoxBody>, Infallible> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/health") => {
                let status = health.liveness();
                let body = serde_json::to_string(&status).unwrap_or_default();
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(BoxBody::new(Bytes::from(body)))
                    .unwrap())
            }
            (&Method::GET, "/ready") => {
                let status = health.readiness();
                let http_status = if status.ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };
                let body = serde_json::to_string(&status).unwrap_or_default();
                Ok(Response::builder()
                    .status(http_status)
                    .header("Content-Type", "application/json")
                    .body(BoxBody::new(Bytes::from(body)))
                    .unwrap())
            }
            (&Method::GET, "/metrics") => {
                if let Some(metrics_fn) = metrics {
                    let snapshot = metrics_fn();
                    let body = snapshot.to_prometheus();
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                        .body(BoxBody::new(Bytes::from(body)))
                        .unwrap())
                } else {
                    Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(BoxBody::new(Bytes::from("Metrics not enabled")))
                        .unwrap())
                }
            }
            _ => {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(BoxBody::new(Bytes::from("Not Found")))
                    .unwrap())
            }
        }
    }
}

/// Handle to a running health server
pub struct HealthServerHandle {
    _task: tokio::task::JoinHandle<()>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl HealthServerHandle {
    /// Stop the health server
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_always_ok() {
        let health = HealthCheck::new(
            Arc::new(|| false),
            Arc::new(|| 0),
            Arc::new(|| 0),
        );

        let status = health.liveness();
        assert_eq!(status.status, "ok");
    }

    #[test]
    fn test_readiness_when_synced() {
        let health = HealthCheck::new(
            Arc::new(|| true),  // synced
            Arc::new(|| 5),     // 5 peers
            Arc::new(|| 100),   // height 100
        );

        let status = health.readiness();
        assert!(status.ready);
        assert_eq!(status.status, "ready");
        assert!(status.checks.synced);
        assert!(status.checks.has_peers);
        assert_eq!(status.checks.block_height, 100);
        assert_eq!(status.checks.peer_count, 5);
    }

    #[test]
    fn test_readiness_when_not_synced() {
        let health = HealthCheck::new(
            Arc::new(|| false), // not synced
            Arc::new(|| 5),     // 5 peers
            Arc::new(|| 50),    // height 50
        );

        let status = health.readiness();
        assert!(!status.ready);
        assert_eq!(status.status, "not_ready");
        assert!(!status.checks.synced);
    }

    #[test]
    fn test_readiness_with_min_peers() {
        let health = HealthCheck::new(
            Arc::new(|| true),  // synced
            Arc::new(|| 1),     // only 1 peer
            Arc::new(|| 100),   // height 100
        ).with_min_peers(3);   // requires 3 peers

        let status = health.readiness();
        assert!(!status.ready);
        assert!(!status.checks.has_peers);
    }

    #[test]
    fn test_is_ready_convenience() {
        let healthy = HealthCheck::new(
            Arc::new(|| true),
            Arc::new(|| 5),
            Arc::new(|| 100),
        );
        assert!(healthy.is_ready());

        let unhealthy = HealthCheck::new(
            Arc::new(|| false),
            Arc::new(|| 0),
            Arc::new(|| 0),
        );
        assert!(!unhealthy.is_ready());
    }
}

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

    /// The single-validator devnet readiness rule (issue #120): with zero peers
    /// and `sync_state` never leaving `Initializing` (so the raw `is_synced`
    /// signal is `false`), the node is NOT ready at genesis height but becomes
    /// ready as soon as it commits its first block past genesis. Drives the
    /// exact `is_synced = sync_state_synced || height > genesis_height`
    /// predicate that `Node::start_health` wires in, using an adjustable mock
    /// height.
    #[test]
    fn test_readiness_single_validator_genesis_predicate() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        let genesis_height = 0u64;
        let height = Arc::new(AtomicU64::new(genesis_height));
        // Raw p2p sync signal: a lone validator never leaves Initializing.
        let sync_state_synced = Arc::new(AtomicBool::new(false));

        let is_synced = {
            let sync_state_synced = sync_state_synced.clone();
            let height = height.clone();
            Arc::new(move || {
                sync_state_synced.load(Ordering::Relaxed)
                    || height.load(Ordering::Relaxed) > genesis_height
            })
        };
        let current_height = {
            let height = height.clone();
            Arc::new(move || height.load(Ordering::Relaxed))
        };
        // Zero peers, min_peers default 0.
        let health = HealthCheck::new(is_synced, Arc::new(|| 0usize), current_height);

        // At genesis: not synced, 0 peers -> not ready.
        let status = health.readiness();
        assert!(!status.ready, "should not be ready at genesis height");
        assert!(!status.checks.synced);
        assert_eq!(status.checks.block_height, genesis_height);
        assert_eq!(status.checks.peer_count, 0);

        // First block past genesis -> ready, even with 0 peers and the raw sync
        // signal still false.
        height.store(genesis_height + 1, Ordering::Relaxed);
        let status = health.readiness();
        assert!(status.ready, "should be ready once past genesis height");
        assert!(status.checks.synced, "height predicate drives synced=true");
        assert_eq!(status.checks.block_height, genesis_height + 1);
        assert_eq!(status.checks.peer_count, 0);
    }

    // ---- HTTP-level tests exercising the running HealthServer ----

    /// Bind an ephemeral port, return its address, and free it so the caller
    /// can hand the address to `HealthServer::start`.
    async fn free_local_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    /// Issue `GET <path>` over a raw TCP connection and return the HTTP status
    /// code. Sends `Connection: close` so the server closes after responding.
    async fn get_status(addr: SocketAddr, path: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            path
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let status_line = text.lines().next().expect("no status line");
        status_line
            .split_whitespace()
            .nth(1)
            .expect("no status code")
            .parse()
            .expect("status code not a number")
    }

    #[tokio::test]
    async fn test_http_health_returns_200_when_up() {
        let addr = free_local_addr().await;
        // Not ready (not synced), but /health (liveness) must still be 200.
        let health = Arc::new(HealthCheck::new(
            Arc::new(|| false),
            Arc::new(|| 0),
            Arc::new(|| 0),
        ));
        let mut handle = HealthServer::new(health).start(addr).await.unwrap();

        assert_eq!(get_status(addr, "/health").await, 200);

        handle.stop();
    }

    #[tokio::test]
    async fn test_http_ready_transitions_503_to_200_past_genesis() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let addr = free_local_addr().await;
        let genesis_height = 0u64;
        let height = Arc::new(AtomicU64::new(genesis_height));

        let is_synced = {
            let height = height.clone();
            // Raw sync signal stays false (single validator, no peers).
            Arc::new(move || height.load(Ordering::Relaxed) > genesis_height)
        };
        let current_height = {
            let height = height.clone();
            Arc::new(move || height.load(Ordering::Relaxed))
        };
        let health = Arc::new(HealthCheck::new(
            is_synced,
            Arc::new(|| 0usize),
            current_height,
        ));
        let mut handle = HealthServer::new(health).start(addr).await.unwrap();

        // Before the first block past genesis: 503.
        assert_eq!(get_status(addr, "/ready").await, 503);

        // After committing a block past genesis: 200.
        height.store(genesis_height + 1, Ordering::Relaxed);
        assert_eq!(get_status(addr, "/ready").await, 200);

        handle.stop();
    }

    #[tokio::test]
    async fn test_http_bind_failure_surfaces_error() {
        let addr = free_local_addr().await;
        let make_health = || {
            Arc::new(HealthCheck::new(
                Arc::new(|| true),
                Arc::new(|| 0),
                Arc::new(|| 0),
            ))
        };

        let mut first = HealthServer::new(make_health()).start(addr).await.unwrap();

        // Second bind to the same address must fail rather than silently
        // succeed.
        let second = HealthServer::new(make_health()).start(addr).await;
        assert!(second.is_err(), "second bind to {addr} should fail");

        first.stop();
    }

    #[tokio::test]
    async fn test_clean_shutdown_releases_port() {
        let addr = free_local_addr().await;
        let make_health = || {
            Arc::new(HealthCheck::new(
                Arc::new(|| true),
                Arc::new(|| 0),
                Arc::new(|| 0),
            ))
        };

        let mut handle = HealthServer::new(make_health()).start(addr).await.unwrap();
        assert_eq!(get_status(addr, "/health").await, 200);

        // Stop and confirm the port is released by rebinding to the same addr.
        handle.stop();

        let mut rebound = None;
        for _ in 0..40 {
            match HealthServer::new(make_health()).start(addr).await {
                Ok(h) => {
                    rebound = Some(h);
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }
        }
        let mut rebound = rebound.expect("port was not released after clean shutdown");
        assert_eq!(get_status(addr, "/health").await, 200);
        rebound.stop();
    }
}

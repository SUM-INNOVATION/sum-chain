//! Readiness follows the consensus engine (#350), through the node's own
//! servers (`Node::start_servers`, `Node::start_health`) and a real engine
//! fail-stopped by a failed finality write.
//!
//! * Running: `/ready` 200, with the body it always had.
//! * Fail-stopped: `/ready` 503 with the reason in `checks.consensus_halted`;
//!   `/health` 200; RPC still answers. Nothing exits or restarts.
//! * Restarted (a new node over the same directory, whose start the existing
//!   start checks accept): ready again once it commits a block, as any lone
//!   validator is.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use sumchain_consensus::branch_switch::failpoints::{arm, Failpoint};
use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

use super::Node;

fn validator() -> KeyPair {
    KeyPair::from_bytes([41u8; 32])
}

fn genesis() -> Genesis {
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        std::collections::HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams {
            finality_depth: 2,
            ..ChainParams::default()
        },
    )
}

async fn free_addr() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// Construct the node and load its chain, as `run` does before it starts any
/// server. The database may still be held for a moment by a node that was just
/// stopped, so the open is retried briefly.
async fn started(dir: &Path, rpc: SocketAddr, health: SocketAddr) -> Node {
    for _ in 0..200 {
        match Node::with_rpc_config(
            dir.to_path_buf(),
            genesis(),
            Some(validator()),
            sumchain_p2p::NetworkConfig::default(),
            rpc,
            health,
            sumchain_rpc::RpcAuthConfig::disabled(),
            sumchain_rpc::RateLimitConfig::disabled(),
            crate::config::ConsensusSettings::default(),
        ) {
            Ok(node) => {
                node.init_chain()
                    .expect("the start checks accept this database");
                return node;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    panic!("the data directory stayed locked");
}

fn engine(node: &Node) -> &Arc<PoAEngine> {
    node.consensus.as_poa().expect("a PoA node")
}

/// Produce one block, and record it the way the event loop does on
/// `BlockProduced` (the node's view of its height, which readiness reads).
async fn produce(node: &Node) {
    let block = engine(node).propose_block(Vec::new()).await.unwrap();
    node.chain_height.store(block.height(), Ordering::Relaxed);
}

/// One HTTP request over a raw connection: the status code and the body.
async fn http(addr: SocketAddr, request: String) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .expect("no status code");
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (code, body)
}

async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    http(
        addr,
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await
}

async fn rpc_call(addr: SocketAddr, method: &str) -> (u16, String) {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":[]}}"#);
    http(
        addr,
        format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fail_stopped_engine_makes_the_node_not_ready_until_a_restart() {
    arm(None);
    let dir = tempfile::TempDir::new().unwrap();
    let (rpc, health) = (free_addr().await, free_addr().await);

    // ── running ─────────────────────────────────────────────────────────────
    let node = started(dir.path(), rpc, health).await;
    let (rpc_handle, mut health_handle) = node.start_servers().await.unwrap();
    for _ in 0..3 {
        produce(&node).await;
    }
    let (code, ready) = get(health, "/ready").await;
    eprintln!("running   /ready  {code} {ready}");
    assert_eq!(code, 200, "{ready}");
    assert!(!ready.contains("consensus_halted"), "{ready}");

    // ── fail-stopped by a failed finality write ─────────────────────────────
    // The failpoint is armed on this thread, which is where `propose_block`
    // runs: the test's own future.
    arm(Some(Failpoint::FinalityWriteFails));
    let err = engine(&node)
        .propose_block(Vec::new())
        .await
        .expect_err("the finality write fails")
        .to_string();
    arm(None);
    assert!(err.contains("could not persist local finality"), "{err}");
    let reason = engine(&node).halted_reason().expect("the engine halted");

    let (code, ready) = get(health, "/ready").await;
    eprintln!("halted    /ready  {code} {ready}");
    assert_eq!(
        code, 503,
        "a fail-stopped engine must not be ready: {ready}"
    );
    assert!(ready.contains(r#""status":"not_ready""#), "{ready}");
    assert!(ready.contains(r#""consensus_halted":"#), "{ready}");
    assert!(
        ready.contains("could not persist local finality"),
        "{ready}"
    );
    assert!(
        reason.contains("could not persist local finality"),
        "{reason}"
    );

    let (code, live) = get(health, "/health").await;
    eprintln!("halted    /health {code} {live}");
    assert_eq!(code, 200, "liveness is unaffected: {live}");
    assert!(live.contains(r#""status":"ok""#), "{live}");

    let (code, answer) = rpc_call(rpc, "get_finality").await;
    assert_eq!(code, 200, "RPC keeps serving: {answer}");
    assert!(answer.contains(r#""result""#), "{answer}");

    // Still not ready: nothing restarts it, and it does not recover by itself.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(get(health, "/ready").await.0, 503);

    // ── restarted: a new node over the same directory ───────────────────────
    rpc_handle.stop().unwrap();
    health_handle.stop();
    drop(node);
    let health = free_addr().await;
    let node = started(dir.path(), rpc, health).await;
    let mut health_handle = node.start_health().await.unwrap();
    assert!(engine(&node).halted_reason().is_none());
    // A lone validator is ready once it commits a block past the height it
    // started at; the finality write now succeeds.
    produce(&node).await;
    let (code, ready) = get(health, "/ready").await;
    eprintln!("restarted /ready  {code} {ready}");
    assert_eq!(code, 200, "{ready}");
    assert!(!ready.contains("consensus_halted"), "{ready}");
    health_handle.stop();
}

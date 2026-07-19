//! Node orchestration - wires together all components.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use sumchain_consensus::{
    bft::{Proposal, Vote, VoteType},
    ConsensusEngine, ConsensusEvent,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::Genesis;
use sumchain_p2p::{NetworkCommand, NetworkConfig, NetworkEvent, NetworkService, SyncState, MAX_BLOCKS_PER_REQUEST};
use sumchain_primitives::SignedTransaction;
use sumchain_rpc::{
    HealthCheck, HealthServer, HealthServerHandle, Metrics, RateLimitConfig, RpcAuthConfig,
    RpcServer, ServerHandle,
};
use sumchain_state::education_executor::EducationExecutor;
use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
use sumchain_state::mempool::{EducationAdmission, InferenceAttestationAdmission};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::{BlockStore, Database};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::consensus_wrapper::ConsensusWrapper;

/// Full node
pub struct Node {
    /// Database
    db: Arc<Database>,
    /// State manager
    state: Arc<StateManager>,
    /// Transaction mempool
    mempool: Arc<Mempool>,
    /// Consensus engine
    consensus: ConsensusWrapper,
    /// Network service
    network: Arc<NetworkService>,
    /// Network command receiver
    network_command_rx: mpsc::Receiver<NetworkCommand>,
    /// Genesis config
    genesis: Genesis,
    /// RPC address
    rpc_addr: SocketAddr,
    /// Health/readiness HTTP server address (separate from the JSON-RPC addr)
    health_addr: SocketAddr,
    /// Height the node started at (its on-disk tip at construction). Used as
    /// the readiness `genesis_height` baseline: a single validator with no
    /// peers becomes ready once it commits its first block past this height.
    genesis_height: u64,
    /// RPC authentication config
    rpc_auth_config: RpcAuthConfig,
    /// RPC rate limit config
    rpc_rate_limit_config: RateLimitConfig,
    /// Metrics collector
    metrics: Arc<Metrics>,
    /// Transaction sender for RPC -> network
    tx_sender: mpsc::Sender<SignedTransaction>,
    /// Transaction receiver
    tx_receiver: mpsc::Receiver<SignedTransaction>,
    /// Shutdown flag for graceful termination
    shutdown: Arc<AtomicBool>,
    /// Live chain-tip height, consumed by `InferenceAttestationAdmission`
    /// in the mempool's admission gate. Bumped on every BlockProduced or
    /// BlockImported event so admission decisions track the chain. On
    /// cold start, initialized from `BlockStore::get_latest_height()`.
    chain_height: Arc<AtomicU64>,
}

impl Node {
    /// Create a new node (without RPC auth or rate limiting)
    #[allow(dead_code)]
    pub fn new(
        data_dir: PathBuf,
        genesis: Genesis,
        validator_key: Option<KeyPair>,
        network_config: NetworkConfig,
        rpc_addr: SocketAddr,
        health_addr: SocketAddr,
        consensus_config: crate::config::ConsensusSettings,
    ) -> Result<Self> {
        Self::with_rpc_config(
            data_dir,
            genesis,
            validator_key,
            network_config,
            rpc_addr,
            health_addr,
            RpcAuthConfig::disabled(),
            RateLimitConfig::disabled(),
            consensus_config,
        )
    }

    /// Create a new node with RPC authentication
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn with_rpc_auth(
        data_dir: PathBuf,
        genesis: Genesis,
        validator_key: Option<KeyPair>,
        network_config: NetworkConfig,
        rpc_addr: SocketAddr,
        health_addr: SocketAddr,
        rpc_auth_config: RpcAuthConfig,
        consensus_config: crate::config::ConsensusSettings,
    ) -> Result<Self> {
        Self::with_rpc_config(
            data_dir,
            genesis,
            validator_key,
            network_config,
            rpc_addr,
            health_addr,
            rpc_auth_config,
            RateLimitConfig::disabled(),
            consensus_config,
        )
    }

    /// Create a new node with full RPC configuration
    #[allow(clippy::too_many_arguments)]
    pub fn with_rpc_config(
        data_dir: PathBuf,
        genesis: Genesis,
        validator_key: Option<KeyPair>,
        network_config: NetworkConfig,
        rpc_addr: SocketAddr,
        health_addr: SocketAddr,
        rpc_auth_config: RpcAuthConfig,
        rpc_rate_limit_config: RateLimitConfig,
        consensus_config: crate::config::ConsensusSettings,
    ) -> Result<Self> {
        // Create data directory
        std::fs::create_dir_all(&data_dir)?;

        // Open database
        let db = Arc::new(Database::open_default(&data_dir)?);

        // One-time, idempotent backfill of the messaging sender/payment
        // indexes from primary records. Must complete before RPC/consensus
        // start so messaging_getSentMessages / messaging_getPendingPayments
        // never read partial indexes; a failure here fails startup.
        let backfill = sumchain_storage::MessagingStore::new(&db)
            .backfill_indexes()
            .map_err(|e| anyhow::anyhow!("messaging index backfill failed: {}", e))?;
        if backfill.ran {
            info!(
                "Messaging index backfill complete: {} sender-event rows, {} pending-payment rows",
                backfill.sender_events, backfill.pending_payments
            );
        }

        // Create state manager
        let state = Arc::new(StateManager::new(db.clone(), genesis.chain_id));

        // Initialize live chain-height from on-disk state. The mempool's
        // OmniNode admission gate reads this; cold start without on-disk
        // blocks resolves to 0, which keeps every gate closed unless
        // `omninode_enabled_from_height: Some(0)` is set in genesis.
        let initial_height = BlockStore::new(&db)
            .get_latest_height()?
            .unwrap_or(0);
        let chain_height = Arc::new(AtomicU64::new(initial_height));

        // Build the InferenceAttestation admission context. Carries the
        // narrowest set of handles needed for the three admission checks:
        // the storage executor that owns the canonical CF, the chain's
        // activation params, and a shared atomic for live chain-tip.
        // Without this, `sum_sendRawTransaction` would let attestation
        // txs bypass the activation gate and permanent CF dedup — Phase
        // 3 ships the mechanism, but only this wiring makes it
        // load-bearing for the production submit path.
        let inference_admission = InferenceAttestationAdmission {
            executor: Arc::new(InferenceAttestationExecutor::new(db.clone())),
            params: Arc::new(genesis.params.clone()),
            current_height: chain_height.clone(),
        };

        // SRC-817/818 Education admission context. Same narrow shape;
        // reuses the SAME live `chain_height` Arc so the education gate
        // and the inference gate observe an identical chain tip. Phase
        // 3 ships the filter; this wiring makes it load-bearing for the
        // production submit path (read-only — executor authoritative).
        let education_admission = EducationAdmission {
            executor: Arc::new(EducationExecutor::new(db.clone())),
            params: Arc::new(genesis.params.clone()),
            current_height: chain_height.clone(),
        };

        // Create mempool with admission wired in.
        let mempool = Arc::new(
            Mempool::new(MempoolConfig {
                min_fee: genesis.params.min_fee,
                ..Default::default()
            })
            .with_inference_admission(inference_admission)
            .with_education_admission(education_admission),
        );

        // Create consensus engine based on config
        use crate::config::ConsensusEngine as ConsensusEngineType;
        let consensus = match consensus_config.engine {
            ConsensusEngineType::Poa => {
                ConsensusWrapper::new_poa(
                    db.clone(),
                    state.clone(),
                    mempool.clone(),
                    &genesis,
                    validator_key,
                )?
            }
            ConsensusEngineType::Bft => {
                if validator_key.is_none() {
                    return Err(anyhow::anyhow!("BFT consensus requires validator key"));
                }
                ConsensusWrapper::new_bft(
                    db.clone(),
                    state.clone(),
                    mempool.clone(),
                    &genesis,
                    validator_key,
                )?
            }
        };

        // Create network service
        let (network, network_command_rx) = NetworkService::new(network_config);
        let network = Arc::new(network);

        // Create metrics collector
        let metrics = Arc::new(Metrics::new());

        // Create transaction channel
        let (tx_sender, tx_receiver) = mpsc::channel(1000);

        Ok(Self {
            db,
            state,
            mempool,
            consensus,
            network,
            network_command_rx,
            genesis,
            rpc_addr,
            health_addr,
            genesis_height: initial_height,
            rpc_auth_config,
            rpc_rate_limit_config,
            metrics,
            tx_sender,
            tx_receiver,
            shutdown: Arc::new(AtomicBool::new(false)),
            chain_height,
        })
    }

    /// Run the node
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting node");

        // Initialize or load chain
        self.init_chain()?;

        // Start consensus
        self.consensus.start().await?;

        // Start the RPC and health servers together. `start_servers` performs
        // partial-start rollback: if the health server fails to bind after the
        // RPC server is already up, it explicitly stops the RPC server before
        // returning the error, so a health bind failure fails node startup
        // without leaking the RPC port.
        let (rpc_handle, health_handle) = self.start_servers().await?;

        // Subscribe to events
        let mut consensus_events = self.consensus.subscribe();
        let mut network_events = self.network.subscribe();
        let command_sender = self.network.command_sender();

        // Clone references for async tasks
        let consensus = self.consensus.clone();
        let mempool = self.mempool.clone();
        let network = self.network.clone();
        let metrics = self.metrics.clone();
        let chain_height = self.chain_height.clone();

        // Spawn network task
        let network_clone = network.clone();
        let network_command_rx = std::mem::replace(
            &mut self.network_command_rx,
            mpsc::channel(1).1,
        );
        let network_task = tokio::spawn(async move {
            if let Err(e) = network_clone.run(network_command_rx).await {
                error!("Network error: {}", e);
            }
        });

        // Spawn block producer task (validators only)
        let consensus_clone = consensus.clone();
        let block_producer_task = tokio::spawn(async move {
            consensus_clone.run_block_producer().await;
        });

        // Main event loop
        info!("Node running. Press Ctrl+C to stop.");

        loop {
            tokio::select! {
                // Handle consensus events
                Ok(event) = consensus_events.recv() => {
                    match event {
                        ConsensusEvent::BlockProduced(block) => {
                            info!("Produced block {} at height {}", block.hash(), block.height());
                            metrics.blocks.record_block_produced();
                            metrics.blocks.record_block_processed();
                            metrics.blocks.set_height(block.height());
                            metrics.blocks.set_last_block_time(block.header.timestamp);
                            // Advance mempool admission gate's view of chain
                            // height so InferenceAttestation activation
                            // decisions track the live chain.
                            chain_height.store(block.height(), Ordering::Relaxed);
                            // Broadcast to network
                            let _ = command_sender.send(NetworkCommand::BroadcastBlock(block)).await;
                        }
                        ConsensusEvent::BlockImported(block) => {
                            debug!("Imported block {} at height {}", block.hash(), block.height());
                            metrics.blocks.record_block_imported();
                            metrics.blocks.record_block_processed();
                            metrics.blocks.set_height(block.height());
                            metrics.blocks.set_last_block_time(block.header.timestamp);
                            // Same as BlockProduced — admission must see
                            // every height advance, whether the block came
                            // from this node or a peer.
                            chain_height.store(block.height(), Ordering::Relaxed);
                        }
                        ConsensusEvent::BlockFinalized(hash, height) => {
                            debug!("Block {} finalized at height {}", hash, height);
                        }
                        ConsensusEvent::Reorg { old_head, new_head, depth } => {
                            warn!("Chain reorg: {} -> {} (depth {})", old_head, new_head, depth);
                        }
                    }
                }

                // Handle network events
                Ok(event) = network_events.recv() => {
                    match event {
                        NetworkEvent::PeerConnected(peer) => {
                            info!("Peer connected: {}", peer);
                            metrics.p2p.record_peer_connected();
                            metrics.p2p.set_peer_count(network.peer_count());
                            // Request sync status from new peer to check if we need to sync
                            let _ = command_sender.send(NetworkCommand::RequestSyncStatus(peer)).await;
                        }
                        NetworkEvent::PeerDisconnected(peer) => {
                            info!("Peer disconnected: {}", peer);
                            metrics.p2p.record_peer_disconnected();
                            metrics.p2p.set_peer_count(network.peer_count());
                        }
                        NetworkEvent::TransactionReceived(tx) => {
                            debug!("Received transaction: {}", tx.hash());
                            metrics.transactions.record_tx_received();
                            metrics.p2p.record_message_received();
                            // Add to mempool
                            if let Err(e) = mempool.add(tx) {
                                debug!("Failed to add tx to mempool: {}", e);
                                metrics.mempool.record_tx_rejected();
                            } else {
                                metrics.mempool.record_tx_added();
                            }
                        }
                        NetworkEvent::BlockReceived(block) => {
                            debug!("Received block: {} (height {})", block.hash(), block.height());
                            metrics.p2p.record_message_received();
                            // Import block
                            if let Err(e) = consensus.import_block(block).await {
                                warn!("Failed to import block: {}", e);
                                metrics.blocks.record_block_error();
                            }
                        }
                        // Handle sync status requests from peers
                        NetworkEvent::SyncStatusRequest { request_id, peer } => {
                            debug!("Sync status request from {} (id={})", peer, request_id);
                            let height = consensus.current_height();
                            let best_hash = consensus.best_block_hash();
                            let chain_id = self.genesis.chain_id;
                            let _ = command_sender.send(NetworkCommand::SendSyncStatusResponse {
                                request_id,
                                height,
                                best_hash,
                                chain_id,
                            }).await;
                        }
                        // Handle sync blocks requests from peers
                        NetworkEvent::SyncBlocksRequest { request_id, peer, from_height, to_height } => {
                            debug!("Sync blocks request from {} (id={}, range={}-{})", peer, request_id, from_height, to_height);
                            // Limit the range to prevent abuse
                            let actual_to = to_height.min(from_height + MAX_BLOCKS_PER_REQUEST - 1);
                            let mut blocks = Vec::new();
                            for h in from_height..=actual_to {
                                if let Some(block) = consensus.get_block_by_height(h) {
                                    blocks.push(block);
                                }
                            }
                            let _ = command_sender.send(NetworkCommand::SendSyncBlocksResponse {
                                request_id,
                                blocks,
                            }).await;
                        }
                        // Handle sync status responses - check if we need to sync
                        NetworkEvent::SyncStatusResponse { peer, height, best_hash: _, chain_id } => {
                            debug!("Sync status from {}: height={}, chain_id={}", peer, height, chain_id);
                            if chain_id != self.genesis.chain_id {
                                warn!("Peer {} has different chain_id: {} vs {}", peer, chain_id, self.genesis.chain_id);
                            } else {
                                let our_height = consensus.current_height();
                                if height > our_height {
                                    info!("Peer {} is ahead: {} vs {} (we're behind by {} blocks)", peer, height, our_height, height - our_height);
                                    // Request blocks we're missing
                                    let from = our_height + 1;
                                    let to = (from + MAX_BLOCKS_PER_REQUEST - 1).min(height);
                                    network.set_sync_state(SyncState::Syncing {
                                        current_height: our_height,
                                        target_height: height,
                                    });
                                    let _ = command_sender.send(NetworkCommand::RequestBlocks {
                                        peer,
                                        from_height: from,
                                        to_height: to,
                                    }).await;
                                } else if height == our_height {
                                    network.set_sync_state(SyncState::Synced);
                                }
                            }
                        }
                        // Handle received blocks from sync
                        NetworkEvent::SyncBlocksReceived { peer, blocks } => {
                            info!("Received {} blocks from {} via sync", blocks.len(), peer);
                            let mut last_imported_height = 0;
                            for block in blocks {
                                match consensus.import_block(block.clone()).await {
                                    Ok(()) => {
                                        last_imported_height = block.height();
                                        metrics.blocks.record_block_imported();
                                        metrics.blocks.record_block_processed();
                                        metrics.blocks.set_height(block.height());
                                        metrics.blocks.set_last_block_time(block.header.timestamp);
                                    }
                                    Err(e) => {
                                        warn!("Failed to import synced block {}: {}", block.hash(), e);
                                        metrics.blocks.record_block_error();
                                        break;
                                    }
                                }
                            }
                            // Check if we need more blocks
                            if let SyncState::Syncing { target_height, .. } = network.sync_state() {
                                if last_imported_height < target_height && last_imported_height > 0 {
                                    // Request more blocks
                                    let from = last_imported_height + 1;
                                    let to = (from + MAX_BLOCKS_PER_REQUEST - 1).min(target_height);
                                    network.set_sync_state(SyncState::Syncing {
                                        current_height: last_imported_height,
                                        target_height,
                                    });
                                    let _ = command_sender.send(NetworkCommand::RequestBlocks {
                                        peer,
                                        from_height: from,
                                        to_height: to,
                                    }).await;
                                } else {
                                    info!("Sync complete at height {}", last_imported_height);
                                    network.set_sync_state(SyncState::Synced);
                                }
                            }
                        }
                        // Handle sync failures
                        NetworkEvent::SyncRequestFailed { peer, error } => {
                            warn!("Sync request to {} failed: {}", peer, error);
                            // Could try another peer here
                        }

                        // BFT consensus messages
                        NetworkEvent::BftProposalReceived(data) => {
                            if let Ok(proposal) = Proposal::from_bytes(&data) {
                                info!("Received BFT proposal for height {}", proposal.view.height);

                                // Handle proposal and create prevote
                                if let Ok(Some(prevote)) = self.consensus.handle_proposal(proposal) {
                                    // Broadcast prevote
                                    let vote_data = prevote.to_bytes();
                                    let _ = command_sender
                                        .send(NetworkCommand::BroadcastBftPrevote(vote_data))
                                        .await;
                                }
                            }
                        }

                        NetworkEvent::BftPrevoteReceived(data) => {
                            if let Ok(vote) = Vote::from_bytes(&data) {
                                if vote.vote_type == VoteType::Prevote {
                                    debug!("Received BFT prevote for height {}", vote.view.height);

                                    // Handle prevote and create precommit if quorum reached
                                    if let Ok(Some(precommit)) = self.consensus.handle_prevote(vote) {
                                        // Broadcast precommit
                                        let vote_data = precommit.to_bytes();
                                        let _ = command_sender
                                            .send(NetworkCommand::BroadcastBftPrecommit(vote_data))
                                            .await;
                                    }
                                }
                            }
                        }

                        NetworkEvent::BftPrecommitReceived(data) => {
                            if let Ok(vote) = Vote::from_bytes(&data) {
                                if vote.vote_type == VoteType::Precommit {
                                    debug!("Received BFT precommit for height {}", vote.view.height);

                                    // Handle precommit and commit block if quorum reached
                                    if let Ok(Some(block_hash)) = self.consensus.handle_precommit(vote) {
                                        info!("BFT consensus reached for block {}", block_hash);
                                        // Block should already be in cache from proposal
                                        // Execute and commit it
                                        // (This integrates with existing block execution code)
                                    }
                                }
                            }
                        }
                    }
                }

                // Handle transactions from RPC
                Some(tx) = self.tx_receiver.recv() => {
                    debug!("Broadcasting transaction: {}", tx.hash());
                    metrics.transactions.record_tx_submitted();
                    metrics.p2p.record_message_sent();
                    let _ = command_sender.send(NetworkCommand::BroadcastTransaction(tx)).await;
                }

                // Handle shutdown signal
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        // Graceful shutdown sequence
        info!("Shutting down node...");

        // Set shutdown flag to notify all components
        self.shutdown.store(true, Ordering::SeqCst);

        // 1. Stop consensus engine (stops block production)
        info!("Stopping consensus engine...");
        self.consensus.stop().await?;

        // 2. Stop BOTH the RPC and health servers. `stop_servers` runs the
        //    health shutdown first (infallible) and surfaces any RPC-shutdown
        //    error only after both stop() calls have run — so neither service's
        //    shutdown is skipped because the other errored.
        info!("Stopping RPC and health servers...");
        let servers_stop_result = Self::stop_servers(rpc_handle, health_handle);

        // 3. Give running tasks a grace period to finish
        info!("Waiting for tasks to complete...");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // 4. Abort remaining tasks
        network_task.abort();
        block_producer_task.abort();

        // 5. Ensure database is flushed
        info!("Flushing database...");
        if let Err(e) = self.db.flush() {
            warn!("Failed to flush database: {}", e);
        }

        info!("Node shutdown complete");

        // Surface any RPC-shutdown error only now, after the full teardown
        // sequence (including health shutdown, task aborts, and DB flush) has
        // run, so an error in one step never skips the others.
        servers_stop_result
    }

    /// Initialize or load the chain
    fn init_chain(&self) -> Result<()> {
        // Try to load existing chain
        if let Some(block) = self.consensus.load_chain()? {
            info!("Loaded existing chain at height {}", block.height());
            return Ok(());
        }

        // Initialize from genesis
        info!("Initializing new chain from genesis");
        self.consensus.init_genesis(&self.genesis)?;

        Ok(())
    }

    /// Start the RPC server
    async fn start_rpc(&self) -> Result<ServerHandle> {
        let peer_count = {
            let network = self.network.clone();
            Arc::new(move || network.peer_count())
        };

        let peer_id = {
            let network = self.network.clone();
            Arc::new(move || network.local_peer_id().map(|p| p.to_string()))
        };

        let is_synced = {
            let network = self.network.clone();
            Arc::new(move || network.sync_state().is_synced())
        };

        // Build the fully-configured RPC server through the shared helper so
        // production and the wiring tripwire test share one construction path
        // (including the contract executor wiring).
        let rpc = build_rpc_server(
            self.db.clone(),
            self.state.clone(),
            self.mempool.clone(),
            self.consensus.as_consensus_engine(),
            self.tx_sender.clone(),
            peer_count,
            peer_id,
            is_synced,
            self.rpc_auth_config.clone(),
            self.rpc_rate_limit_config.clone(),
            self.metrics.clone(),
            self.genesis.params.clone(),
        );

        let handle = rpc.start(self.rpc_addr).await?;

        info!("RPC server listening on {}", self.rpc_addr);

        Ok(handle)
    }

    /// Start the standalone health/readiness HTTP server.
    ///
    /// Serves `GET /health` (liveness) and `GET /ready` (readiness) on the
    /// configured `health_addr` (default `0.0.0.0:8546`), separate from the
    /// JSON-RPC server. Wires the readiness predicate so a single-validator
    /// devnet with no peers becomes ready once it commits its first block past
    /// the height it started at (`genesis_height`); see issue #120 and
    /// [`single_validator_synced`].
    async fn start_health(&self) -> Result<HealthServerHandle> {
        // Readiness `is_synced`: true if the p2p sync state says synced OR the
        // chain has advanced past the startup height. The latter is what lets a
        // lone validator (no peers, `sync_state` stuck at `Initializing`) flip
        // ready after producing its first block.
        let is_synced = {
            let network = self.network.clone();
            let chain_height = self.chain_height.clone();
            let genesis_height = self.genesis_height;
            Arc::new(move || {
                single_validator_synced(
                    network.sync_state().is_synced(),
                    chain_height.load(Ordering::Relaxed),
                    genesis_height,
                )
            })
        };

        let peer_count = {
            let network = self.network.clone();
            Arc::new(move || network.peer_count())
        };

        let current_height = {
            let chain_height = self.chain_height.clone();
            Arc::new(move || chain_height.load(Ordering::Relaxed))
        };

        // `HealthCheck::new` defaults `min_peers_for_ready` to 0, so a
        // single-validator devnet is not blocked on peers.
        let health_check = Arc::new(HealthCheck::new(is_synced, peer_count, current_height));
        let server = HealthServer::new(health_check);

        let handle = server
            .start(self.health_addr)
            .await
            .with_context(|| format!("Failed to bind health server to {}", self.health_addr))?;

        Ok(handle)
    }

    /// Start the RPC server, then the health server, with partial-start
    /// rollback.
    ///
    /// The RPC server binds first. If the health server then fails to bind, the
    /// already-started RPC server is explicitly stopped (we do NOT rely on drop
    /// semantics) so its port is released before the health error is
    /// propagated. On success both handles are returned to the caller.
    async fn start_servers(&self) -> Result<(ServerHandle, HealthServerHandle)> {
        let rpc_handle = self.start_rpc().await?;

        match self.start_health().await {
            Ok(health_handle) => Ok((rpc_handle, health_handle)),
            Err(e) => {
                error!(
                    "Health server failed to start; rolling back the already-started RPC server"
                );
                if let Err(rpc_stop_err) = rpc_handle.stop() {
                    error!(
                        "Failed to stop RPC server during health-start rollback: {}",
                        rpc_stop_err
                    );
                }
                Err(e)
            }
        }
    }

    /// Stop both servers, guaranteeing neither shutdown is skipped because the
    /// other errored.
    ///
    /// Routes through [`shutdown_both`], which runs the (infallible) health
    /// shutdown first and surfaces any RPC-shutdown error only after both
    /// stop() calls have run.
    fn stop_servers(rpc_handle: ServerHandle, mut health_handle: HealthServerHandle) -> Result<()> {
        shutdown_both(
            || {
                info!("Stopping health server...");
                health_handle.stop();
            },
            || {
                info!("Stopping RPC server...");
                rpc_handle.stop().map_err(anyhow::Error::from)
            },
        )
    }
}

/// Readiness override for a single-validator devnet.
///
/// The node counts as "synced" for readiness purposes if the p2p sync state
/// reports synced OR it has committed at least one block past the height it
/// started at (`genesis_height`). A lone validator with no peers never reaches
/// `SyncState::Synced`, so without the height clause its `/ready` probe would
/// never return 200. See issue #120.
fn single_validator_synced(
    sync_state_synced: bool,
    current_height: u64,
    genesis_height: u64,
) -> bool {
    sync_state_synced || current_height > genesis_height
}

/// Run both shutdown steps, health first, so a failing RPC shutdown can never
/// skip the health shutdown. Any RPC-shutdown error is surfaced only after the
/// health shutdown has run. Generic over the two shutdown actions so the
/// ordering guarantee is unit-testable with an injected RPC-shutdown failure.
fn shutdown_both(stop_health: impl FnOnce(), stop_rpc: impl FnOnce() -> Result<()>) -> Result<()> {
    stop_health();
    stop_rpc()
}

// Production-wiring contract is enforced by tests in
// `crates/state/tests/inference_attestation_mempool.rs`:
//   - `production_wiring_rejects_attestation_pre_activation`
//   - `production_wiring_height_advance_opens_gate`
// They mirror the exact admission recipe in `Node::new` above.
// If you refactor the wiring (the `InferenceAttestationAdmission { ... }`
// or `EducationAdmission { ... }` literals, the `.with_*_admission(...)`
// builder chain, the `chain_height.store(...)` calls in the event loop,
// or the `Arc::new(BlockStore::new(&db).get_latest_height()…)`
// initialization), update those tests too — they are intentionally a
// verbatim mirror so that drift produces compile or assertion failures
// rather than silent security regressions. `EducationAdmission` shares
// the SAME `chain_height` Arc, so the event-loop `chain_height.store`
// calls cover both admission gates.

/// Build the fully-configured production RPC server.
///
/// Single construction path shared by `Node::start_rpc` and the wiring
/// tripwire test, so the contract-executor wiring cannot silently regress.
/// The contract executor is a dedicated RPC/view instance (separate from the
/// consensus `BlockExecutor`'s internal executor) sharing the live DB + chain
/// params; it powers the read/view contract RPCs
/// (`contract_getContract`/`getCodeHash`/`getStorageAt`/`estimateGas`). These
/// read committed state directly and are NOT gated by
/// `contracts_enabled_from_height` (the activation gate governs execution —
/// deploy/call in the block executor — not reads).
#[allow(clippy::too_many_arguments)]
fn build_rpc_server(
    db: Arc<Database>,
    state: Arc<StateManager>,
    mempool: Arc<Mempool>,
    consensus: Arc<dyn ConsensusEngine>,
    tx_sender: mpsc::Sender<SignedTransaction>,
    peer_count: Arc<dyn Fn() -> usize + Send + Sync>,
    peer_id: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    is_synced: Arc<dyn Fn() -> bool + Send + Sync>,
    rpc_auth_config: RpcAuthConfig,
    rpc_rate_limit_config: RateLimitConfig,
    metrics: Arc<Metrics>,
    params: sumchain_genesis::ChainParams,
) -> RpcServer {
    let contract_executor = Arc::new(sumchain_state::ContractExecutorState::new(
        db.clone(),
        params.clone(),
    ));
    RpcServer::with_full_config(
        db,
        state,
        mempool,
        consensus,
        tx_sender,
        peer_count,
        peer_id,
        is_synced,
        rpc_auth_config,
        rpc_rate_limit_config,
        metrics,
    )
    .with_chain_params(params)
    .with_contract_executor(contract_executor)
}

#[cfg(test)]
mod health_wiring_tests {
    use super::single_validator_synced;

    /// The single-validator readiness predicate: a fresh validator (started at
    /// genesis height 0, no peers, `sync_state` = Initializing so
    /// `sync_state_synced = false`) is NOT ready at genesis, but becomes ready
    /// the moment it commits its first block past genesis. This is the exact
    /// predicate `Node::start_health` wires into the `HealthCheck` `is_synced`
    /// callback.
    #[test]
    fn ready_only_after_first_block_past_genesis() {
        let genesis = 0u64;

        // At genesis, not peer-synced, zero peers -> not ready.
        assert!(!single_validator_synced(false, genesis, genesis));

        // First block past genesis -> ready, even with sync_state Initializing.
        assert!(single_validator_synced(false, genesis + 1, genesis));

        // Peer-synced is independently sufficient (normal multi-node path).
        assert!(single_validator_synced(true, genesis, genesis));
    }

    /// On restart, `genesis_height` is the on-disk tip at startup, so readiness
    /// requires committing a NEW block past that tip.
    #[test]
    fn restart_requires_progress_past_startup_tip() {
        let startup_tip = 100u64;
        assert!(!single_validator_synced(false, startup_tip, startup_tip));
        assert!(single_validator_synced(false, startup_tip + 1, startup_tip));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::collections::HashMap;
    use sumchain_genesis::ChainParams;
    use tempfile::TempDir;

    /// Build a real single-validator Node bound to the given RPC and health
    /// addresses. Returns the `TempDir` so the on-disk DB outlives the test.
    fn test_node(rpc_addr: SocketAddr, health_addr: SocketAddr) -> (Node, TempDir) {
        let dir = TempDir::new().unwrap();
        let validator = KeyPair::generate();
        let genesis = Genesis::new(
            1,
            0,
            vec![validator.public_key().to_base58()],
            HashMap::from([(validator.address().to_base58(), 1u128)]),
            ChainParams::default(),
        );
        let node = Node::with_rpc_config(
            dir.path().to_path_buf(),
            genesis,
            Some(validator),
            NetworkConfig::default(),
            rpc_addr,
            health_addr,
            RpcAuthConfig::disabled(),
            RateLimitConfig::disabled(),
            crate::config::ConsensusSettings::default(),
        )
        .unwrap();
        (node, dir)
    }

    /// Bind an ephemeral port and free it, returning the address so a server
    /// can rebind it.
    async fn free_addr() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    /// Poll until `addr` is bindable again (its port has been released), up to
    /// ~1s.
    async fn port_is_rebindable(addr: SocketAddr) -> bool {
        for _ in 0..40 {
            if tokio::net::TcpListener::bind(addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    /// Item 3.1: an occupied health port must FAIL node startup AND roll back
    /// the already-started RPC server so its port is released (re-bindable).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_bind_failure_fails_startup_and_releases_rpc_port() {
        let rpc_addr = free_addr().await;
        let health_addr = free_addr().await;

        // Occupy the health port for the whole startup attempt.
        let _blocker = tokio::net::TcpListener::bind(health_addr).await.unwrap();

        let (node, _dir) = test_node(rpc_addr, health_addr);
        let result = node.start_servers().await;
        assert!(
            result.is_err(),
            "startup must fail when the health port is already bound"
        );

        // Rollback must have stopped the RPC server, freeing its port.
        assert!(
            port_is_rebindable(rpc_addr).await,
            "RPC port must be released after a failed (rolled-back) startup"
        );
    }

    /// Item 3.3: a normal shutdown releases BOTH the RPC and health ports.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn normal_shutdown_releases_both_ports() {
        let rpc_addr = free_addr().await;
        let health_addr = free_addr().await;
        let (node, _dir) = test_node(rpc_addr, health_addr);

        let (rpc_handle, health_handle) = node
            .start_servers()
            .await
            .expect("both servers should start");

        // Both ports are occupied while the servers are running.
        assert!(tokio::net::TcpListener::bind(rpc_addr).await.is_err());
        assert!(tokio::net::TcpListener::bind(health_addr).await.is_err());

        Node::stop_servers(rpc_handle, health_handle).expect("clean shutdown should succeed");

        assert!(
            port_is_rebindable(rpc_addr).await,
            "RPC port must be released after shutdown"
        );
        assert!(
            port_is_rebindable(health_addr).await,
            "health port must be released after shutdown"
        );
    }

    /// Item 3.2: an injected RPC-shutdown failure must NOT skip the health
    /// shutdown. Exercises the real production `shutdown_both` helper that
    /// `Node::stop_servers` routes through.
    #[test]
    fn rpc_shutdown_error_does_not_skip_health_shutdown() {
        use std::cell::Cell;

        let health_ran = Cell::new(false);
        let result = shutdown_both(
            || health_ran.set(true),
            || Err(anyhow::anyhow!("injected RPC shutdown failure")),
        );

        assert!(
            health_ran.get(),
            "health shutdown must run even when the RPC shutdown errors"
        );
        assert!(
            result.is_err(),
            "the RPC-shutdown error must still be surfaced"
        );
    }
}

#[cfg(test)]
mod rpc_wiring_tests {
    use super::*;
    use std::collections::HashMap;
    use sumchain_consensus::PoAEngine;
    use sumchain_genesis::{ChainParams, Genesis};
    use tempfile::TempDir;

    /// Tripwire: the production RPC builder MUST wire the contract executor,
    /// or contract_getStorageAt / estimateGas silently return "unavailable" on
    /// a real node. `Node::start_rpc` builds through this same function.
    #[test]
    fn production_rpc_wires_contract_executor() {
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
        let engine: Arc<dyn ConsensusEngine> = Arc::new(
            PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator)).unwrap(),
        );
        let (tx_sender, _rx) = mpsc::channel(8);

        let server = build_rpc_server(
            db,
            state,
            mempool,
            engine,
            tx_sender,
            Arc::new(|| 0usize),
            Arc::new(|| None),
            Arc::new(|| true),
            RpcAuthConfig::disabled(),
            RateLimitConfig::disabled(),
            Arc::new(Metrics::new()),
            genesis.params.clone(),
        );

        assert!(
            server.has_contract_executor(),
            "production RPC must wire the contract executor"
        );
    }
}

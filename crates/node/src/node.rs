//! Node orchestration - wires together all components.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use sumchain_consensus::{
    bft::{Proposal, Vote, VoteType},
    ConsensusEngine, ConsensusEvent,
};
use sumchain_crypto::KeyPair;
use sumchain_genesis::Genesis;
use sumchain_p2p::{NetworkCommand, NetworkConfig, NetworkEvent, NetworkService, SyncState, MAX_BLOCKS_PER_REQUEST};
use sumchain_primitives::SignedTransaction;
use sumchain_rpc::{Metrics, RateLimitConfig, RpcAuthConfig, RpcServer, ServerHandle};
use sumchain_state::inference_attestation_executor::InferenceAttestationExecutor;
use sumchain_state::mempool::InferenceAttestationAdmission;
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
        consensus_config: crate::config::ConsensusSettings,
    ) -> Result<Self> {
        Self::with_rpc_config(
            data_dir,
            genesis,
            validator_key,
            network_config,
            rpc_addr,
            RpcAuthConfig::disabled(),
            RateLimitConfig::disabled(),
            consensus_config,
        )
    }

    /// Create a new node with RPC authentication
    #[allow(dead_code)]
    pub fn with_rpc_auth(
        data_dir: PathBuf,
        genesis: Genesis,
        validator_key: Option<KeyPair>,
        network_config: NetworkConfig,
        rpc_addr: SocketAddr,
        rpc_auth_config: RpcAuthConfig,
        consensus_config: crate::config::ConsensusSettings,
    ) -> Result<Self> {
        Self::with_rpc_config(
            data_dir,
            genesis,
            validator_key,
            network_config,
            rpc_addr,
            rpc_auth_config,
            RateLimitConfig::disabled(),
            consensus_config,
        )
    }

    /// Create a new node with full RPC configuration
    pub fn with_rpc_config(
        data_dir: PathBuf,
        genesis: Genesis,
        validator_key: Option<KeyPair>,
        network_config: NetworkConfig,
        rpc_addr: SocketAddr,
        rpc_auth_config: RpcAuthConfig,
        rpc_rate_limit_config: RateLimitConfig,
        consensus_config: crate::config::ConsensusSettings,
    ) -> Result<Self> {
        // Create data directory
        std::fs::create_dir_all(&data_dir)?;

        // Open database
        let db = Arc::new(Database::open_default(&data_dir)?);

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

        // Create mempool with admission wired in.
        let mempool = Arc::new(
            Mempool::new(MempoolConfig {
                min_fee: genesis.params.min_fee,
                ..Default::default()
            })
            .with_inference_admission(inference_admission),
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

        // Start RPC server
        let rpc_handle = self.start_rpc().await?;

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

        // 2. Stop RPC server (stops accepting new requests)
        info!("Stopping RPC server...");
        rpc_handle.stop()?;

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
        Ok(())
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

        let rpc = RpcServer::with_full_config(
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
        )
        // Bind the live chain's `ChainParams` to the RPC so RPCs that read
        // consensus values (currently `storage_getAssignmentCoverageV2` —
        // `assignment_replication_factor`) match the executor's validation.
        // Without this, non-default chains would serve the V2 coverage RPC
        // with the default R=3 and disagree with `AcceptAssignmentV2` on
        // chains tuned to a different value.
        .with_chain_params(self.genesis.params.clone());

        let handle = rpc.start(self.rpc_addr).await?;

        info!("RPC server listening on {}", self.rpc_addr);

        Ok(handle)
    }
}

// Production-wiring contract is enforced by tests in
// `crates/state/tests/inference_attestation_mempool.rs`:
//   - `production_wiring_rejects_attestation_pre_activation`
//   - `production_wiring_height_advance_opens_gate`
// They mirror the exact admission recipe in `Node::new` above.
// If you refactor the wiring (the `InferenceAttestationAdmission { ... }`
// literal, the `chain_height.store(...)` calls in the event loop, or the
// `Arc::new(BlockStore::new(&db).get_latest_height()…)` initialization),
// update those tests too — they are intentionally a verbatim mirror so
// that drift produces compile or assertion failures rather than silent
// security regressions.

//! # SUM Chain P2P
//!
//! Peer-to-peer networking for SUM Chain using libp2p.
//! Handles transaction and block gossip, peer discovery, message routing,
//! and block synchronization.

pub mod behaviour;
pub mod block_syncer;
pub mod config;
pub mod network;
pub mod node_key;
pub mod peer_manager;
pub mod sync;

pub use behaviour::{NetworkSecurityConfig, SumChainBehaviour};
pub use block_syncer::{BlockSyncer, BlockSyncerConfig, SyncPeerInfo, SyncStats, SyncerState};
pub use config::NetworkConfig;
pub use network::{NetworkCommand, NetworkEvent, NetworkService, RateLimitConfig, SyncRequestId};
pub use node_key::load_or_generate_keypair;
pub use peer_manager::{
    ConnectionDirection, ConnectionLimits, ConnectionStats, PeerInfo, PeerManager, PeerState,
};
pub use sync::{SyncRequest, SyncResponse, SyncState, MAX_BLOCKS_PER_REQUEST};

use thiserror::Error;

/// P2P networking errors
#[derive(Debug, Error)]
pub enum P2pError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Dial error: {0}")]
    Dial(String),

    #[error("Listen error: {0}")]
    Listen(String),

    #[error("Gossip error: {0}")]
    Gossip(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Network not started")]
    NotStarted,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, P2pError>;

/// Gossip topic names
pub mod topics {
    pub const TRANSACTIONS: &str = "sumchain/tx/1";
    pub const BLOCKS: &str = "sumchain/block/1";
    pub const BFT_PROPOSALS: &str = "sumchain/bft/proposal/1";
    pub const BFT_PREVOTES: &str = "sumchain/bft/prevote/1";
    pub const BFT_PRECOMMITS: &str = "sumchain/bft/precommit/1";
}

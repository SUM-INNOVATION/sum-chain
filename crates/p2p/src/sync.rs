//! Block synchronization protocol.
//!
//! Provides request/response messaging for syncing blocks between peers.

use std::io;
use std::time::Duration;

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::{self, Codec, ProtocolSupport};
use libp2p::StreamProtocol;
use serde::{Deserialize, Serialize};
use sumchain_primitives::{Block, BlockHeight, Hash};

/// Protocol name for block sync
pub const SYNC_PROTOCOL: &str = "/sumchain/sync/1.0.0";

/// Maximum number of blocks in a single response
pub const MAX_BLOCKS_PER_REQUEST: u64 = 100;

/// Request timeout for sync operations
pub const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Sync request messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Request the peer's current chain tip
    GetStatus,
    /// Request blocks in a height range (inclusive)
    GetBlocks {
        from_height: BlockHeight,
        to_height: BlockHeight,
    },
    /// Request a specific block by hash
    GetBlockByHash(Hash),
}

/// Sync response messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    /// Chain status response
    Status {
        /// Current chain height
        height: BlockHeight,
        /// Current best block hash
        best_hash: Hash,
        /// Chain ID
        chain_id: u64,
    },
    /// Blocks response
    Blocks(Vec<Block>),
    /// Single block response
    Block(Option<Block>),
    /// Error response
    Error(String),
}

/// Codec for sync protocol messages
#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Sanity check on length
        if len > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Request too large",
            ));
        }

        // Read message
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;

        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Sanity check on length (responses can be larger - blocks)
        if len > 100 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Response too large",
            ));
        }

        // Read message
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;

        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Write length prefix
        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        io.flush().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&res)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // Write length prefix
        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        io.flush().await?;

        Ok(())
    }
}

/// Create sync behaviour
pub fn create_sync_behaviour() -> request_response::Behaviour<SyncCodec> {
    let protocol = StreamProtocol::new(SYNC_PROTOCOL);
    let config = request_response::Config::default()
        .with_request_timeout(SYNC_REQUEST_TIMEOUT);

    request_response::Behaviour::new(
        [(protocol, ProtocolSupport::Full)],
        config,
    )
}

/// Sync state tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Node is synchronized with the network
    Synced,
    /// Node is actively syncing blocks
    Syncing {
        current_height: BlockHeight,
        target_height: BlockHeight,
    },
    /// Node is behind but not actively syncing (no peers or waiting)
    Behind {
        local_height: BlockHeight,
        network_height: BlockHeight,
    },
    /// Initial state, gathering information
    Initializing,
}

impl SyncState {
    /// Check if node is fully synced
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncState::Synced)
    }

    /// Get sync progress as percentage (0-100)
    pub fn progress(&self) -> u8 {
        match self {
            SyncState::Synced => 100,
            SyncState::Syncing {
                current_height,
                target_height,
            } => {
                if *target_height == 0 {
                    100
                } else {
                    ((current_height * 100) / target_height).min(100) as u8
                }
            }
            SyncState::Behind { .. } => 0,
            SyncState::Initializing => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state() {
        assert!(SyncState::Synced.is_synced());
        assert!(!SyncState::Initializing.is_synced());

        let syncing = SyncState::Syncing {
            current_height: 50,
            target_height: 100,
        };
        assert!(!syncing.is_synced());
        assert_eq!(syncing.progress(), 50);
    }

    #[test]
    fn test_request_serialization() {
        let req = SyncRequest::GetBlocks {
            from_height: 10,
            to_height: 20,
        };
        let bytes = bincode::serialize(&req).unwrap();
        let decoded: SyncRequest = bincode::deserialize(&bytes).unwrap();

        match decoded {
            SyncRequest::GetBlocks {
                from_height,
                to_height,
            } => {
                assert_eq!(from_height, 10);
                assert_eq!(to_height, 20);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_response_serialization() {
        let resp = SyncResponse::Status {
            height: 100,
            best_hash: Hash::default(),
            chain_id: 1337,
        };
        let bytes = bincode::serialize(&resp).unwrap();
        let decoded: SyncResponse = bincode::deserialize(&bytes).unwrap();

        match decoded {
            SyncResponse::Status {
                height, chain_id, ..
            } => {
                assert_eq!(height, 100);
                assert_eq!(chain_id, 1337);
            }
            _ => panic!("Wrong variant"),
        }
    }
}

//! State snapshot for fast sync.
//!
//! Allows nodes to create and restore state snapshots for fast sync
//! without replaying all blocks from genesis.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, Balance, BlockHeight, Hash, Nonce};
use sumchain_storage::{schema::AccountState, Database, StateStore, BlockStore};
use tracing::{debug, info, warn};

use crate::{Result, StateError};

/// Snapshot format version
const SNAPSHOT_VERSION: u32 = 1;

/// Magic bytes to identify snapshot files
const SNAPSHOT_MAGIC: &[u8; 8] = b"SUMSNAP\0";

/// Account state in snapshot format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAccount {
    pub address: [u8; 20],
    pub balance: Balance,
    pub nonce: Nonce,
}

/// Snapshot header with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotHeader {
    /// Snapshot format version
    pub version: u32,
    /// Chain ID
    pub chain_id: u64,
    /// Block height this snapshot was taken at
    pub height: BlockHeight,
    /// Block hash at this height
    pub block_hash: Hash,
    /// State root at this height
    pub state_root: Hash,
    /// Number of accounts in snapshot
    pub account_count: u64,
    /// Timestamp when snapshot was created
    pub created_at: u64,
}

/// Complete snapshot data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub header: SnapshotHeader,
    pub accounts: Vec<SnapshotAccount>,
}

/// Snapshot manager for creating and restoring snapshots
pub struct SnapshotManager {
    db: Arc<Database>,
    chain_id: u64,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new(db: Arc<Database>, chain_id: u64) -> Self {
        Self { db, chain_id }
    }

    /// Create a snapshot at the current chain tip
    pub fn create_snapshot(&self) -> Result<Snapshot> {
        let block_store = BlockStore::new(&self.db);
        let state_store = StateStore::new(&self.db);

        // Get current chain tip
        let latest_block = block_store.get_latest()?
            .ok_or_else(|| StateError::Genesis("No blocks found".to_string()))?;

        let height = latest_block.height();
        let block_hash = latest_block.hash();
        let state_root = latest_block.header.state_root;

        info!("Creating snapshot at height {} ({})", height, block_hash);

        // Export all accounts
        let accounts = self.export_accounts(&state_store)?;

        let header = SnapshotHeader {
            version: SNAPSHOT_VERSION,
            chain_id: self.chain_id,
            height,
            block_hash,
            state_root,
            account_count: accounts.len() as u64,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        info!(
            "Snapshot created with {} accounts, state root: {}",
            accounts.len(),
            state_root
        );

        Ok(Snapshot { header, accounts })
    }

    /// Export all accounts from state store
    fn export_accounts(&self, store: &StateStore<'_>) -> Result<Vec<SnapshotAccount>> {
        let accounts = store.iter_all_accounts()?;

        Ok(accounts.into_iter().map(|(addr, state)| {
            SnapshotAccount {
                address: *addr.as_bytes(),
                balance: state.balance,
                nonce: state.nonce,
            }
        }).collect())
    }

    /// Restore state from a snapshot
    pub fn restore_snapshot(&self, snapshot: &Snapshot) -> Result<RestoreResult> {
        // Verify chain ID
        if snapshot.header.chain_id != self.chain_id {
            return Err(StateError::Genesis(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.chain_id, snapshot.header.chain_id
            )));
        }

        // Verify version compatibility
        if snapshot.header.version > SNAPSHOT_VERSION {
            return Err(StateError::Genesis(format!(
                "Unsupported snapshot version: {} (max supported: {})",
                snapshot.header.version, SNAPSHOT_VERSION
            )));
        }

        info!(
            "Restoring snapshot from height {} ({} accounts)",
            snapshot.header.height, snapshot.header.account_count
        );

        let state_store = StateStore::new(&self.db);
        let mut restored_count = 0u64;

        // Import all accounts
        for account in &snapshot.accounts {
            let address = Address::new(account.address);
            state_store.put_account(
                &address,
                &AccountState {
                    balance: account.balance,
                    nonce: account.nonce,
                },
            )?;
            restored_count += 1;

            if restored_count % 10000 == 0 {
                debug!("Restored {} accounts...", restored_count);
            }
        }

        info!(
            "Snapshot restored: {} accounts at height {}",
            restored_count, snapshot.header.height
        );

        Ok(RestoreResult {
            height: snapshot.header.height,
            block_hash: snapshot.header.block_hash,
            state_root: snapshot.header.state_root,
            accounts_restored: restored_count,
        })
    }

    /// Save snapshot to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, snapshot: &Snapshot, path: P) -> Result<()> {
        let path = path.as_ref();
        info!("Saving snapshot to {:?}", path);

        let file = File::create(path)
            .map_err(|e| StateError::Genesis(format!("Failed to create file: {}", e)))?;
        let mut writer = BufWriter::new(file);

        // Write magic bytes
        writer.write_all(SNAPSHOT_MAGIC)
            .map_err(|e| StateError::Genesis(format!("Failed to write magic: {}", e)))?;

        // Serialize and write snapshot
        let data = bincode::serialize(snapshot)
            .map_err(|e| StateError::Genesis(format!("Failed to serialize: {}", e)))?;

        writer.write_all(&data)
            .map_err(|e| StateError::Genesis(format!("Failed to write data: {}", e)))?;

        writer.flush()
            .map_err(|e| StateError::Genesis(format!("Failed to flush: {}", e)))?;

        info!("Snapshot saved ({} bytes)", data.len() + SNAPSHOT_MAGIC.len());
        Ok(())
    }

    /// Load snapshot from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Snapshot> {
        let path = path.as_ref();
        info!("Loading snapshot from {:?}", path);

        let file = File::open(path)
            .map_err(|e| StateError::Genesis(format!("Failed to open file: {}", e)))?;
        let mut reader = BufReader::new(file);

        // Verify magic bytes
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)
            .map_err(|e| StateError::Genesis(format!("Failed to read magic: {}", e)))?;

        if &magic != SNAPSHOT_MAGIC {
            return Err(StateError::Genesis("Invalid snapshot file format".to_string()));
        }

        // Read and deserialize snapshot
        let mut data = Vec::new();
        reader.read_to_end(&mut data)
            .map_err(|e| StateError::Genesis(format!("Failed to read data: {}", e)))?;

        let snapshot: Snapshot = bincode::deserialize(&data)
            .map_err(|e| StateError::Genesis(format!("Failed to deserialize: {}", e)))?;

        info!(
            "Snapshot loaded: version {}, height {}, {} accounts",
            snapshot.header.version,
            snapshot.header.height,
            snapshot.header.account_count
        );

        Ok(snapshot)
    }

    /// Verify snapshot integrity by checking account count and state root
    pub fn verify_snapshot(&self, snapshot: &Snapshot) -> Result<bool> {
        // Verify account count matches
        if snapshot.accounts.len() as u64 != snapshot.header.account_count {
            warn!(
                "Account count mismatch: header says {}, actual {}",
                snapshot.header.account_count,
                snapshot.accounts.len()
            );
            return Ok(false);
        }

        // Compute state root from accounts and compare
        let computed_root = self.compute_state_root(&snapshot.accounts)?;
        if computed_root != snapshot.header.state_root {
            warn!(
                "State root mismatch: header says {}, computed {}",
                snapshot.header.state_root, computed_root
            );
            return Ok(false);
        }

        info!("Snapshot verification passed");
        Ok(true)
    }

    /// Compute state root from accounts
    fn compute_state_root(&self, accounts: &[SnapshotAccount]) -> Result<Hash> {
        // Sort accounts by address for deterministic ordering
        let mut sorted: Vec<_> = accounts.iter().collect();
        sorted.sort_by_key(|a| a.address);

        // Hash sorted (address, balance) pairs
        let mut data = Vec::new();
        for account in sorted {
            data.extend_from_slice(&account.address);
            data.extend_from_slice(&account.balance.to_be_bytes());
        }

        Ok(Hash::hash(&data))
    }

    /// Get snapshot info without loading full data
    pub fn get_snapshot_info<P: AsRef<Path>>(path: P) -> Result<SnapshotHeader> {
        let snapshot = Self::load_from_file(path)?;
        Ok(snapshot.header)
    }
}

/// Result of snapshot restoration
#[derive(Debug, Clone)]
pub struct RestoreResult {
    pub height: BlockHeight,
    pub block_hash: Hash,
    pub state_root: Hash,
    pub accounts_restored: u64,
}

/// Snapshot sync configuration
#[derive(Debug, Clone)]
pub struct SnapshotSyncConfig {
    /// Minimum height difference to trigger snapshot sync
    pub min_height_diff: u64,
    /// How often to create automatic snapshots (in blocks)
    pub snapshot_interval: u64,
    /// Maximum number of snapshots to keep
    pub max_snapshots: usize,
    /// Directory to store snapshots
    pub snapshot_dir: String,
}

impl Default for SnapshotSyncConfig {
    fn default() -> Self {
        Self {
            min_height_diff: 1000,  // Use snapshot sync if >1000 blocks behind
            snapshot_interval: 10000, // Create snapshot every 10k blocks
            max_snapshots: 3,
            snapshot_dir: "snapshots".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_db() -> (Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        (db, dir)
    }

    #[test]
    fn test_snapshot_account_serialization() {
        let account = SnapshotAccount {
            address: [1u8; 20],
            balance: 1_000_000,
            nonce: 5,
        };

        let bytes = bincode::serialize(&account).unwrap();
        let decoded: SnapshotAccount = bincode::deserialize(&bytes).unwrap();

        assert_eq!(account.address, decoded.address);
        assert_eq!(account.balance, decoded.balance);
        assert_eq!(account.nonce, decoded.nonce);
    }

    #[test]
    fn test_snapshot_header_serialization() {
        let header = SnapshotHeader {
            version: 1,
            chain_id: 1337,
            height: 100,
            block_hash: Hash::default(),
            state_root: Hash::default(),
            account_count: 10,
            created_at: 12345678,
        };

        let bytes = bincode::serialize(&header).unwrap();
        let decoded: SnapshotHeader = bincode::deserialize(&bytes).unwrap();

        assert_eq!(header.version, decoded.version);
        assert_eq!(header.chain_id, decoded.chain_id);
        assert_eq!(header.height, decoded.height);
        assert_eq!(header.account_count, decoded.account_count);
    }

    #[test]
    fn test_snapshot_file_roundtrip() {
        let (db, dir) = setup_db();
        let manager = SnapshotManager::new(db, 1337);

        let snapshot = Snapshot {
            header: SnapshotHeader {
                version: 1,
                chain_id: 1337,
                height: 50,
                block_hash: Hash::default(),
                state_root: Hash::default(),
                account_count: 2,
                created_at: 12345,
            },
            accounts: vec![
                SnapshotAccount {
                    address: [1u8; 20],
                    balance: 100,
                    nonce: 0,
                },
                SnapshotAccount {
                    address: [2u8; 20],
                    balance: 200,
                    nonce: 1,
                },
            ],
        };

        let path = dir.path().join("test_snapshot.snap");
        manager.save_to_file(&snapshot, &path).unwrap();

        let loaded = SnapshotManager::load_from_file(&path).unwrap();

        assert_eq!(loaded.header.height, 50);
        assert_eq!(loaded.accounts.len(), 2);
    }

    #[test]
    fn test_verify_account_count() {
        let (db, _dir) = setup_db();
        let manager = SnapshotManager::new(db, 1337);

        // Create snapshot with mismatched account count
        let snapshot = Snapshot {
            header: SnapshotHeader {
                version: 1,
                chain_id: 1337,
                height: 50,
                block_hash: Hash::default(),
                state_root: Hash::default(),
                account_count: 5, // Says 5 accounts
                created_at: 12345,
            },
            accounts: vec![
                SnapshotAccount {
                    address: [1u8; 20],
                    balance: 100,
                    nonce: 0,
                },
            ], // But only 1 account
        };

        // Verification should fail
        assert!(!manager.verify_snapshot(&snapshot).unwrap());
    }

    #[test]
    fn test_restore_wrong_chain_id() {
        let (db, _dir) = setup_db();
        let manager = SnapshotManager::new(db, 1337);

        let snapshot = Snapshot {
            header: SnapshotHeader {
                version: 1,
                chain_id: 9999, // Different chain ID
                height: 50,
                block_hash: Hash::default(),
                state_root: Hash::default(),
                account_count: 0,
                created_at: 12345,
            },
            accounts: vec![],
        };

        let result = manager.restore_snapshot(&snapshot);
        assert!(result.is_err());
    }
}

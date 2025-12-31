//! RocksDB wrapper for SUM Chain.
//!
//! Provides a unified interface for persistent storage with
//! multiple column families for different data types.

use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, Options, DB};
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

use crate::{Result, StorageError};

/// Information about a database backup
#[derive(Debug, Clone)]
pub struct BackupInfo {
    /// Path to the backup directory
    pub path: PathBuf,
    /// Size of the backup in bytes
    pub size_bytes: u64,
    /// Unix timestamp when the backup was created
    pub timestamp: u64,
}

impl BackupInfo {
    /// Format the backup size in human-readable form
    pub fn size_human(&self) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if self.size_bytes >= GB {
            format!("{:.2} GB", self.size_bytes as f64 / GB as f64)
        } else if self.size_bytes >= MB {
            format!("{:.2} MB", self.size_bytes as f64 / MB as f64)
        } else if self.size_bytes >= KB {
            format!("{:.2} KB", self.size_bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", self.size_bytes)
        }
    }
}

/// Column family names
pub mod cf {
    /// Blocks indexed by hash
    pub const BLOCKS: &str = "blocks";
    /// Block hash indexed by height
    pub const BLOCK_HEIGHT: &str = "block_height";
    /// Account state (balances, nonces)
    pub const STATE: &str = "state";
    /// Transactions indexed by hash
    pub const TRANSACTIONS: &str = "transactions";
    /// Transaction receipts
    pub const RECEIPTS: &str = "receipts";
    /// Chain metadata (latest block, etc.)
    pub const META: &str = "meta";
    /// State diffs for reorgs
    pub const STATE_DIFFS: &str = "state_diffs";
    /// NFT collections
    pub const NFT_COLLECTIONS: &str = "nft_collections";
    /// NFT tokens (indexed by collection_id + token_id)
    pub const NFT_TOKENS: &str = "nft_tokens";
    /// NFT owner index (owner -> collection_id:token_id list)
    pub const NFT_OWNER_INDEX: &str = "nft_owner_index";
    /// NFT collection index (collection_id -> token_id list)
    pub const NFT_COLLECTION_INDEX: &str = "nft_collection_index";
    /// Issuer registry for certified documents
    pub const ISSUER_REGISTRY: &str = "issuer_registry";
    /// SRC-20 fungible tokens
    pub const TOKENS: &str = "tokens";
    /// SRC-20 token balances (token_id + owner -> balance)
    pub const TOKEN_BALANCES: &str = "token_balances";
    /// SRC-20 token allowances (token_id + owner + spender -> allowance)
    pub const TOKEN_ALLOWANCES: &str = "token_allowances";
    /// SRC-20 token holder index (owner -> token_id list)
    pub const TOKEN_HOLDER_INDEX: &str = "token_holder_index";
}

/// All column families used by the database
pub const ALL_CFS: &[&str] = &[
    cf::BLOCKS,
    cf::BLOCK_HEIGHT,
    cf::STATE,
    cf::TRANSACTIONS,
    cf::RECEIPTS,
    cf::META,
    cf::STATE_DIFFS,
    cf::NFT_COLLECTIONS,
    cf::NFT_TOKENS,
    cf::NFT_OWNER_INDEX,
    cf::NFT_COLLECTION_INDEX,
    cf::ISSUER_REGISTRY,
    cf::TOKENS,
    cf::TOKEN_BALANCES,
    cf::TOKEN_ALLOWANCES,
    cf::TOKEN_HOLDER_INDEX,
];

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Path to the database directory
    pub path: String,
    /// Create if missing
    pub create_if_missing: bool,
    /// Maximum open files
    pub max_open_files: i32,
    /// Write buffer size in bytes
    pub write_buffer_size: usize,
    /// Maximum write buffers
    pub max_write_buffer_number: i32,
    /// Try to repair database on corruption
    pub auto_repair: bool,
    /// Enable paranoid checks for data integrity
    pub paranoid_checks: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "data/sumchain".to_string(),
            create_if_missing: true,
            max_open_files: 512,
            write_buffer_size: 64 * 1024 * 1024, // 64MB
            max_write_buffer_number: 3,
            auto_repair: true,
            paranoid_checks: true,
        }
    }
}

/// RocksDB database wrapper
pub struct Database {
    db: DB,
    path: String,
}

impl Database {
    /// Open or create a database at the given path
    pub fn open(config: &DatabaseConfig) -> Result<Self> {
        info!("Opening database at {}", config.path);

        let mut opts = Options::default();
        opts.create_if_missing(config.create_if_missing);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);

        // Enable paranoid checks for data integrity
        if config.paranoid_checks {
            opts.set_paranoid_checks(true);
        }

        // Create column family descriptors
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_write_buffer_size(config.write_buffer_size);
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        // Try to open the database
        match DB::open_cf_descriptors(&opts, &config.path, cf_descriptors) {
            Ok(db) => {
                debug!("Database opened successfully with {} column families", ALL_CFS.len());
                Ok(Database { db, path: config.path.clone() })
            }
            Err(e) => {
                error!("Failed to open database: {}", e);

                // Attempt repair if enabled and this looks like corruption
                if config.auto_repair && Self::is_corruption_error(&e) {
                    warn!("Database appears corrupted, attempting repair...");

                    if let Err(repair_err) = Self::repair(&config.path) {
                        error!("Database repair failed: {}", repair_err);
                        return Err(StorageError::RocksDb(e));
                    }

                    info!("Database repair completed, retrying open...");

                    // Recreate descriptors after repair
                    let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
                        .iter()
                        .map(|name| {
                            let mut cf_opts = Options::default();
                            cf_opts.set_write_buffer_size(config.write_buffer_size);
                            ColumnFamilyDescriptor::new(*name, cf_opts)
                        })
                        .collect();

                    let db = DB::open_cf_descriptors(&opts, &config.path, cf_descriptors)?;
                    info!("Database opened successfully after repair");
                    Ok(Database { db, path: config.path.clone() })
                } else {
                    Err(StorageError::RocksDb(e))
                }
            }
        }
    }

    /// Open a database with default configuration
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = DatabaseConfig {
            path: path.as_ref().to_string_lossy().to_string(),
            ..Default::default()
        };
        Self::open(&config)
    }

    /// Check if an error indicates database corruption
    fn is_corruption_error(e: &rocksdb::Error) -> bool {
        let msg = e.to_string().to_lowercase();
        msg.contains("corruption")
            || msg.contains("checksum")
            || msg.contains("manifest")
            || msg.contains("current")
            || msg.contains("invalid argument")
    }

    /// Attempt to repair a corrupted database
    pub fn repair<P: AsRef<Path>>(path: P) -> Result<()> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        info!("Attempting to repair database at {}", path_str);

        let mut opts = Options::default();
        opts.create_if_missing(false);

        DB::repair(&opts, &path_str)?;

        info!("Database repair completed for {}", path_str);
        Ok(())
    }

    /// Get the database path
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Perform a consistency check on the database
    pub fn verify_integrity(&self) -> Result<bool> {
        // Try to read from all column families to verify they're accessible
        for cf_name in ALL_CFS {
            if let Err(e) = self.cf(cf_name) {
                error!("Column family {} is not accessible: {}", cf_name, e);
                return Ok(false);
            }
        }

        // Verify we can read the latest block (basic sanity check)
        match self.get(cf::META, b"latest_block_hash") {
            Ok(_) => {}
            Err(StorageError::NotFound(_)) => {} // Ok, might be new database
            Err(e) => {
                error!("Failed to read metadata: {}", e);
                return Ok(false);
            }
        }

        debug!("Database integrity check passed");
        Ok(true)
    }

    /// Compact the entire database to reclaim space and improve performance
    pub fn compact(&self) -> Result<()> {
        info!("Compacting database...");
        for cf_name in ALL_CFS {
            if let Ok(cf) = self.cf(cf_name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            }
        }
        info!("Database compaction completed");
        Ok(())
    }

    /// Get approximate database size in bytes
    pub fn approximate_size(&self) -> u64 {
        let mut total = 0u64;
        if let Ok(Some(size_str)) = self.db.property_value("rocksdb.estimate-live-data-size") {
            if let Ok(size) = size_str.parse::<u64>() {
                total = size;
            }
        }
        total
    }

    /// Create a backup of the database to the specified directory
    ///
    /// This creates a consistent point-in-time backup that can be restored later.
    /// The backup directory must not exist or be empty.
    pub fn create_backup<P: AsRef<Path>>(&self, backup_dir: P) -> Result<BackupInfo> {
        let backup_path = backup_dir.as_ref();
        info!("Creating database backup to {:?}", backup_path);

        // Ensure backup directory exists
        std::fs::create_dir_all(backup_path).map_err(|e| {
            StorageError::InvalidData(format!("Failed to create backup directory: {}", e))
        })?;

        // Flush all pending writes first
        self.flush()?;

        // Create checkpoint (RocksDB's built-in backup mechanism)
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)?;
        checkpoint.create_checkpoint(backup_path)?;

        // Get backup metadata
        let size = Self::dir_size(backup_path);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        info!(
            "Backup created successfully: {:?} ({} bytes)",
            backup_path, size
        );

        Ok(BackupInfo {
            path: backup_path.to_path_buf(),
            size_bytes: size,
            timestamp,
        })
    }

    /// Restore a database from a backup
    ///
    /// This will replace the current database with the backup.
    /// The current database must be closed before calling this.
    pub fn restore_from_backup<P: AsRef<Path>, Q: AsRef<Path>>(
        backup_dir: P,
        target_dir: Q,
    ) -> Result<()> {
        let backup_path = backup_dir.as_ref();
        let target_path = target_dir.as_ref();

        info!(
            "Restoring database from {:?} to {:?}",
            backup_path, target_path
        );

        // Verify backup exists
        if !backup_path.exists() {
            return Err(StorageError::NotFound(format!(
                "Backup directory not found: {:?}",
                backup_path
            )));
        }

        // Remove existing target if it exists
        if target_path.exists() {
            warn!("Removing existing database at {:?}", target_path);
            std::fs::remove_dir_all(target_path).map_err(|e| {
                StorageError::InvalidData(format!("Failed to remove existing database: {}", e))
            })?;
        }

        // Copy backup to target
        Self::copy_dir_recursive(backup_path, target_path)?;

        info!("Database restored successfully to {:?}", target_path);
        Ok(())
    }

    /// List available backups in a directory
    pub fn list_backups<P: AsRef<Path>>(backups_root: P) -> Result<Vec<BackupInfo>> {
        let root = backups_root.as_ref();
        let mut backups = Vec::new();

        if !root.exists() {
            return Ok(backups);
        }

        let entries = std::fs::read_dir(root).map_err(|e| {
            StorageError::InvalidData(format!("Failed to read backups directory: {}", e))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Check if it looks like a RocksDB database
                if path.join("CURRENT").exists() {
                    let metadata = std::fs::metadata(&path).ok();
                    let timestamp = metadata
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    backups.push(BackupInfo {
                        path: path.clone(),
                        size_bytes: Self::dir_size(&path),
                        timestamp,
                    });
                }
            }
        }

        // Sort by timestamp, newest first
        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(backups)
    }

    /// Calculate total size of a directory
    fn dir_size<P: AsRef<Path>>(path: P) -> u64 {
        let mut size = 0u64;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    size += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                } else if path.is_dir() {
                    size += Self::dir_size(&path);
                }
            }
        }
        size
    }

    /// Recursively copy a directory
    fn copy_dir_recursive<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> Result<()> {
        let src = src.as_ref();
        let dst = dst.as_ref();

        std::fs::create_dir_all(dst).map_err(|e| {
            StorageError::InvalidData(format!("Failed to create directory {:?}: {}", dst, e))
        })?;

        for entry in std::fs::read_dir(src)
            .map_err(|e| StorageError::InvalidData(format!("Failed to read {:?}: {}", src, e)))?
        {
            let entry = entry.map_err(|e| {
                StorageError::InvalidData(format!("Failed to read entry: {}", e))
            })?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                Self::copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path).map_err(|e| {
                    StorageError::InvalidData(format!(
                        "Failed to copy {:?} to {:?}: {}",
                        src_path, dst_path, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    /// Get a column family handle
    fn cf(&self, name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::NotFound(format!("Column family: {}", name)))
    }

    /// Put a key-value pair into a column family
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db.put_cf(cf, key, value)?;
        Ok(())
    }

    /// Get a value by key from a column family
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(cf_name)?;
        Ok(self.db.get_cf(cf, key)?)
    }

    /// Delete a key from a column family
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf(cf_name)?;
        self.db.delete_cf(cf, key)?;
        Ok(())
    }

    /// Check if a key exists in a column family
    pub fn contains(&self, cf_name: &str, key: &[u8]) -> Result<bool> {
        Ok(self.get(cf_name, key)?.is_some())
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Get database statistics
    pub fn stats(&self) -> Option<String> {
        self.db.property_value("rocksdb.stats").ok().flatten()
    }

    /// Create a write batch for atomic operations
    pub fn batch(&self) -> WriteBatch<'_> {
        WriteBatch {
            inner: rocksdb::WriteBatch::default(),
            db: &self.db,
        }
    }

    /// Get an iterator over a column family
    pub fn iter(&self, cf_name: &str) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_> {
        let cf = self.cf(cf_name)?;
        Ok(self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .filter_map(|r| r.ok()))
    }

    /// Get an iterator with a prefix
    pub fn prefix_iter(
        &self,
        cf_name: &str,
        prefix: &[u8],
    ) -> Result<impl Iterator<Item = (Box<[u8]>, Box<[u8]>)> + '_> {
        let cf = self.cf(cf_name)?;
        Ok(self.db.prefix_iterator_cf(cf, prefix).filter_map(|r| r.ok()))
    }
}

/// Atomic write batch
pub struct WriteBatch<'a> {
    inner: rocksdb::WriteBatch,
    db: &'a DB,
}

impl<'a> WriteBatch<'a> {
    /// Put a key-value pair
    pub fn put(&mut self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::NotFound(format!("Column family: {}", cf_name)))?;
        self.inner.put_cf(cf, key, value);
        Ok(())
    }

    /// Delete a key
    pub fn delete(&mut self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StorageError::NotFound(format!("Column family: {}", cf_name)))?;
        self.inner.delete_cf(cf, key);
        Ok(())
    }

    /// Commit the batch atomically
    pub fn commit(self) -> Result<()> {
        self.db.write(self.inner)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn test_put_get() {
        let (db, _dir) = temp_db();

        db.put(cf::META, b"key1", b"value1").unwrap();
        let value = db.get(cf::META, b"key1").unwrap();

        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_get_nonexistent() {
        let (db, _dir) = temp_db();

        let value = db.get(cf::META, b"nonexistent").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn test_delete() {
        let (db, _dir) = temp_db();

        db.put(cf::META, b"key", b"value").unwrap();
        assert!(db.contains(cf::META, b"key").unwrap());

        db.delete(cf::META, b"key").unwrap();
        assert!(!db.contains(cf::META, b"key").unwrap());
    }

    #[test]
    fn test_batch_commit() {
        let (db, _dir) = temp_db();

        let mut batch = db.batch();
        batch.put(cf::META, b"k1", b"v1").unwrap();
        batch.put(cf::META, b"k2", b"v2").unwrap();
        batch.commit().unwrap();

        assert_eq!(db.get(cf::META, b"k1").unwrap(), Some(b"v1".to_vec()));
        assert_eq!(db.get(cf::META, b"k2").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn test_all_column_families() {
        let (db, _dir) = temp_db();

        // Verify all column families are accessible
        for cf_name in ALL_CFS {
            db.put(cf_name, b"test", b"value").unwrap();
            assert_eq!(db.get(cf_name, b"test").unwrap(), Some(b"value".to_vec()));
        }
    }
}

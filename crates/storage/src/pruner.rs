//! Database pruning for SUM Chain.
//!
//! Provides configurable pruning of historical data to manage disk usage
//! while maintaining chain integrity.

use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::db::{cf, Database};
use crate::Result;

/// Pruning configuration
#[derive(Debug, Clone)]
pub struct PrunerConfig {
    /// Keep this many blocks of history (0 = keep all)
    pub blocks_to_keep: u64,
    /// Keep this many state diffs for reorgs (0 = keep all)
    pub state_diffs_to_keep: u64,
    /// Maximum database size in bytes (0 = no limit)
    pub max_db_size_bytes: u64,
    /// Compact database after pruning
    pub compact_after_prune: bool,
    /// Enable pruning
    pub enabled: bool,
}

impl Default for PrunerConfig {
    fn default() -> Self {
        Self {
            blocks_to_keep: 10000,        // Keep ~10k blocks of full history
            state_diffs_to_keep: 1000,    // Keep 1k state diffs for reorg handling
            max_db_size_bytes: 0,         // No size limit by default
            compact_after_prune: true,
            enabled: false, // Disabled by default for safety
        }
    }
}

/// Database pruning statistics
#[derive(Debug, Clone, Default)]
pub struct PruneStats {
    /// Number of blocks pruned
    pub blocks_pruned: u64,
    /// Number of transactions pruned
    pub transactions_pruned: u64,
    /// Number of receipts pruned
    pub receipts_pruned: u64,
    /// Number of state diffs pruned
    pub state_diffs_pruned: u64,
    /// Bytes freed (approximate)
    pub bytes_freed: u64,
    /// Whether compaction was performed
    pub compacted: bool,
}

/// Database pruner
pub struct Pruner {
    db: Arc<Database>,
    config: PrunerConfig,
}

impl Pruner {
    /// Create a new pruner
    pub fn new(db: Arc<Database>, config: PrunerConfig) -> Self {
        Self { db, config }
    }

    /// Check if pruning is needed based on configuration
    pub fn needs_pruning(&self, current_height: u64) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check block height threshold
        if self.config.blocks_to_keep > 0 && current_height > self.config.blocks_to_keep {
            return true;
        }

        // Check database size
        if self.config.max_db_size_bytes > 0 {
            let current_size = self.db.approximate_size();
            if current_size > self.config.max_db_size_bytes {
                return true;
            }
        }

        false
    }

    /// Prune old data from the database
    pub fn prune(&self, current_height: u64) -> Result<PruneStats> {
        if !self.config.enabled {
            return Ok(PruneStats::default());
        }

        let size_before = self.db.approximate_size();
        let mut stats = PruneStats::default();

        info!(
            "Starting database pruning at height {} (keeping {} blocks)",
            current_height, self.config.blocks_to_keep
        );

        // Prune old blocks
        if self.config.blocks_to_keep > 0 && current_height > self.config.blocks_to_keep {
            let prune_below = current_height.saturating_sub(self.config.blocks_to_keep);
            stats.blocks_pruned = self.prune_blocks_below(prune_below)?;
        }

        // Prune old state diffs
        if self.config.state_diffs_to_keep > 0 && current_height > self.config.state_diffs_to_keep {
            let prune_below = current_height.saturating_sub(self.config.state_diffs_to_keep);
            stats.state_diffs_pruned = self.prune_state_diffs_below(prune_below)?;
        }

        // Compact if configured
        if self.config.compact_after_prune
            && (stats.blocks_pruned > 0 || stats.state_diffs_pruned > 0)
        {
            info!("Compacting database after pruning...");
            self.db.compact()?;
            stats.compacted = true;
        }

        let size_after = self.db.approximate_size();
        stats.bytes_freed = size_before.saturating_sub(size_after);

        info!(
            "Pruning complete: {} blocks, {} txs, {} receipts, {} state diffs removed. ~{} bytes freed",
            stats.blocks_pruned,
            stats.transactions_pruned,
            stats.receipts_pruned,
            stats.state_diffs_pruned,
            stats.bytes_freed
        );

        Ok(stats)
    }

    /// Prune blocks below a certain height
    fn prune_blocks_below(&self, height: u64) -> Result<u64> {
        let mut pruned = 0u64;
        let mut block_hashes_to_prune = Vec::new();

        // Collect block hashes to prune by iterating height index
        for (key, value) in self.db.iter(cf::BLOCK_HEIGHT)? {
            if key.len() == 8 {
                let block_height = u64::from_be_bytes(key[..8].try_into().unwrap());
                if block_height < height {
                    block_hashes_to_prune.push((block_height, value.to_vec()));
                }
            }
        }

        // Prune each block and associated data
        for (block_height, block_hash) in block_hashes_to_prune {
            if let Err(e) = self.prune_block(&block_hash, block_height) {
                warn!("Failed to prune block at height {}: {}", block_height, e);
                continue;
            }
            pruned += 1;

            if pruned % 1000 == 0 {
                debug!("Pruned {} blocks...", pruned);
            }
        }

        Ok(pruned)
    }

    /// Prune a single block and its associated data
    fn prune_block(&self, _block_hash: &[u8], height: u64) -> Result<()> {
        // We keep the block header but could prune transaction data
        // For now, just remove from height index to prevent re-processing
        let height_key = height.to_be_bytes();
        self.db.delete(cf::BLOCK_HEIGHT, &height_key)?;

        // Note: We intentionally keep block data by hash for potential lookups
        // Only the height index is removed to indicate it's "pruned"
        // Full block removal would need transaction hash collection first

        debug!("Pruned block at height {}", height);
        Ok(())
    }

    /// Prune state diffs below a certain height
    fn prune_state_diffs_below(&self, height: u64) -> Result<u64> {
        let mut pruned = 0u64;
        let mut keys_to_delete = Vec::new();

        // Collect state diff keys to delete
        for (key, _) in self.db.iter(cf::STATE_DIFFS)? {
            if key.len() >= 8 {
                let diff_height = u64::from_be_bytes(key[..8].try_into().unwrap());
                if diff_height < height {
                    keys_to_delete.push(key.to_vec());
                }
            }
        }

        // Delete in batches for efficiency
        let batch_size = 1000;
        for chunk in keys_to_delete.chunks(batch_size) {
            let mut batch = self.db.batch();
            for key in chunk {
                batch.delete(cf::STATE_DIFFS, key)?;
                pruned += 1;
            }
            batch.commit()?;
        }

        Ok(pruned)
    }

    /// Get current database statistics
    pub fn db_stats(&self) -> DbStats {
        let size_bytes = self.db.approximate_size();
        let size_limit = self.config.max_db_size_bytes;

        DbStats {
            size_bytes,
            size_limit_bytes: size_limit,
            usage_percent: if size_limit > 0 {
                (size_bytes as f64 / size_limit as f64 * 100.0) as u8
            } else {
                0
            },
            blocks_to_keep: self.config.blocks_to_keep,
            state_diffs_to_keep: self.config.state_diffs_to_keep,
            pruning_enabled: self.config.enabled,
        }
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DbStats {
    /// Current database size in bytes
    pub size_bytes: u64,
    /// Maximum allowed size (0 = no limit)
    pub size_limit_bytes: u64,
    /// Current usage as percentage of limit
    pub usage_percent: u8,
    /// Number of blocks to keep
    pub blocks_to_keep: u64,
    /// Number of state diffs to keep
    pub state_diffs_to_keep: u64,
    /// Whether pruning is enabled
    pub pruning_enabled: bool,
}

impl DbStats {
    /// Format size in human-readable form
    pub fn size_human(&self) -> String {
        format_bytes(self.size_bytes)
    }

    /// Format size limit in human-readable form
    pub fn limit_human(&self) -> String {
        if self.size_limit_bytes == 0 {
            "unlimited".to_string()
        } else {
            format_bytes(self.size_limit_bytes)
        }
    }
}

/// Format bytes in human-readable form
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_db() -> (Arc<Database>, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        (db, dir)
    }

    #[test]
    fn test_pruner_disabled_by_default() {
        let (db, _dir) = temp_db();
        let pruner = Pruner::new(db, PrunerConfig::default());

        assert!(!pruner.needs_pruning(100000));
    }

    #[test]
    fn test_pruner_needs_pruning() {
        let (db, _dir) = temp_db();
        let config = PrunerConfig {
            enabled: true,
            blocks_to_keep: 1000,
            ..Default::default()
        };
        let pruner = Pruner::new(db, config);

        assert!(!pruner.needs_pruning(500));
        assert!(pruner.needs_pruning(1500));
    }

    #[test]
    fn test_db_stats() {
        let (db, _dir) = temp_db();
        let config = PrunerConfig {
            enabled: true,
            blocks_to_keep: 5000,
            max_db_size_bytes: 1024 * 1024 * 1024, // 1GB
            ..Default::default()
        };
        let pruner = Pruner::new(db, config);

        let stats = pruner.db_stats();
        assert!(stats.pruning_enabled);
        assert_eq!(stats.blocks_to_keep, 5000);
        assert_eq!(stats.size_limit_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 bytes");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }
}

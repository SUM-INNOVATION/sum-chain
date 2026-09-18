//! The pruning RULE, and the machinery an operator would need to run it.
//!
//! # Nothing in this tree runs a pruner
//!
//! Said first because the old sentence here — "provides configurable pruning of
//! historical data to manage disk usage" — described behaviour this build does
//! not perform. [`PrunerConfig::enabled`] defaults to `false`, nothing in
//! `crates/node` constructs a [`Pruner`], and no loop calls one. A reader who
//! took that sentence at face value would provision disk for a node that prunes
//! and get a node whose undo families grow for the life of the database.
//!
//! That is the SHIPPED DECISION, not an omission (§12.1 of
//! `docs/lane-a/JOURNAL-CONTRACT.md`): a pruner that never runs cannot delete a
//! journal a reorg still needs, and the failure it would cause — a self-inflicted
//! outage mid-switch, with the chain already committed to unwinding — is worse
//! than the failure it prevents, which is visible in advance, has a metric and
//! is recoverable.
//!
//! # What this module therefore is
//!
//! Two things, both real:
//!
//! * [`UNDO_RETENTION_FLOOR`] and the retention rule around it — the constraint
//!   any pruning must satisfy, enforced by [`Pruner::undo_retention`] so an
//!   operator who turns pruning on cannot configure a window shorter than the
//!   deepest reorg this engine will plan;
//! * the CAPACITY machinery below — [`CapacityGuard`], the recorded disk budget,
//!   and the verdicts the engine consults before producing a block. That part IS
//!   wired, and it is what gives a node a defined behaviour as it approaches the
//!   disk it was given instead of discovering the end of it inside a
//!   `WriteBatch`.
//!
//! The disk forecast, the capacity requirement, the alert thresholds and the
//! fail-safe are §§12.3–12.7 of the contract.

use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::db::{cf, Database};
use crate::Result;

/// The deepest reorg this node will ever execute, and therefore the shallowest
/// height at which undo data may be discarded.
///
/// `sumchain_consensus::poa::MAX_REORG_WALK` bounds the ancestor walk at 4096
/// blocks, so a block within 4096 of the head is REVERTIBLE: a plan can name it
/// on an abandoned branch, and the unwind then needs its journal. Pruning that
/// journal turns a reorg the node is willing to plan into a reorg it must
/// refuse — post-activation, `load_for_revert` halts on a missing record, which
/// is the correct behaviour and a self-inflicted outage.
///
/// So undo retention has a FLOOR, not merely a default. `PrunerConfig` may ask
/// to keep more; it cannot ask to keep less. Duplicated as a constant rather
/// than imported because `sumchain-storage` sits below `sumchain-consensus`;
/// `crates/storage/src/pruner.rs`'s test
/// `the_undo_retention_floor_covers_the_deepest_reorg_the_node_will_plan`
/// pins the two together, and the consensus side asserts the same equality from
/// its own constant.
pub const UNDO_RETENTION_FLOOR: u64 = 4_096;

// ═══════════════════════════════════════════════════════════════════════════
// DISK CAPACITY: what a node does as it approaches the space it was given
// ═══════════════════════════════════════════════════════════════════════════
//
// Release blocker 8. This tree ships with pruning DISABLED — `PrunerConfig`
// defaults `enabled` to `false` and nothing constructs a `Pruner` — so the undo
// families grow monotonically for the life of the database. That is a decision,
// not an oversight (see §12.1 of `docs/lane-a/JOURNAL-CONTRACT.md`), and the
// obligation it creates is this: a node must have a defined behaviour as it
// approaches the disk it was provisioned with, rather than discovering the end
// of the disk inside a `WriteBatch`.

/// `META` key holding the disk budget, in bytes, this node was provisioned for.
///
/// Node-local operator configuration, not consensus and not chain state. Absent
/// means unbounded, which is the shipped default and today's behaviour exactly.
pub const DISK_BUDGET_META_KEY: &[u8] = b"node/disk_budget_bytes";

/// Fraction of the budget at which a node warns. Percent, to keep the whole
/// calculation in integers.
pub const CAPACITY_WARN_PERCENT: u64 = 80;

/// Fraction of the budget at which a node STOPS PRODUCING BLOCKS.
pub const CAPACITY_STOP_PERCENT: u64 = 95;

/// What a node should do about the space it is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityVerdict {
    /// Under [`CAPACITY_WARN_PERCENT`] of the budget, or no budget set.
    Healthy,
    /// At or above [`CAPACITY_WARN_PERCENT`]. Keep running, say so loudly: this
    /// is the point at which an operator still has time to add disk or turn
    /// pruning on.
    Warn { used: u64, budget: u64 },
    /// At or above [`CAPACITY_STOP_PERCENT`]. Stop PRODUCING blocks.
    ///
    /// Producing is the part of a node's behaviour that is optional and that
    /// adds to the problem; following the chain is neither. So this brakes
    /// production and leaves import alone, which is the honest shape of the
    /// guarantee: **it delays exhaustion, it does not prevent it.** A node that
    /// keeps importing keeps growing, and the operator's actual remedy is more
    /// disk or a pruner.
    StopProducing { used: u64, budget: u64 },
}

impl CapacityVerdict {
    pub fn is_stop(&self) -> bool {
        matches!(self, CapacityVerdict::StopProducing { .. })
    }
}

/// The disk budget a node was provisioned for, and the verdicts it implies.
#[derive(Debug, Clone, Copy)]
pub struct CapacityGuard {
    budget_bytes: u64,
}

impl CapacityGuard {
    /// `0` means unbounded — the shipped default, and today's behaviour.
    pub fn new(budget_bytes: u64) -> Self {
        Self { budget_bytes }
    }

    pub fn unbounded() -> Self {
        Self { budget_bytes: 0 }
    }

    /// The budget an operator recorded for this database, or unbounded.
    pub fn from_db(db: &Database) -> Result<Self> {
        Ok(Self::new(disk_budget(db)?.unwrap_or(0)))
    }

    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    /// Integer-only, so the thresholds are exact at every size and there is no
    /// floating-point edge to argue about at 95%.
    pub fn assess(&self, used: u64) -> CapacityVerdict {
        if self.budget_bytes == 0 {
            return CapacityVerdict::Healthy;
        }
        let budget = self.budget_bytes;
        if used.saturating_mul(100) >= budget.saturating_mul(CAPACITY_STOP_PERCENT) {
            CapacityVerdict::StopProducing { used, budget }
        } else if used.saturating_mul(100) >= budget.saturating_mul(CAPACITY_WARN_PERCENT) {
            CapacityVerdict::Warn { used, budget }
        } else {
            CapacityVerdict::Healthy
        }
    }

    /// The verdict for a live database, using RocksDB's own live-data estimate.
    pub fn assess_db(&self, db: &Database) -> CapacityVerdict {
        self.assess(db.approximate_size())
    }
}

/// Read the recorded disk budget. `None` = unbounded.
pub fn disk_budget(db: &Database) -> Result<Option<u64>> {
    match db.get(cf::META, DISK_BUDGET_META_KEY)? {
        None => Ok(None),
        Some(v) if v.len() == 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&v);
            Ok(Some(u64::from_be_bytes(b)))
        }
        Some(v) => Err(crate::StorageError::InvalidData(format!(
            "the disk budget row is {} byte(s); it is an 8-byte big-endian byte count",
            v.len()
        ))),
    }
}

/// Record the disk budget this node is provisioned for. `0` clears it.
pub fn record_disk_budget(db: &Database, bytes: u64) -> Result<()> {
    db.put(cf::META, DISK_BUDGET_META_KEY, &bytes.to_be_bytes())
}

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
    /// Number of generic application-journal records pruned
    pub application_journals_pruned: u64,
    /// Bytes freed (approximate)
    pub bytes_freed: u64,
    /// Whether compaction was performed
    pub compacted: bool,
}

/// A pruner an operator could construct. **Nothing in this tree constructs one.**
///
/// The type exists, its retention floor is enforced, and its behaviour is
/// tested — none of which is the same as pruning running. No `crates/node` code
/// path builds a `Pruner`, no loop calls [`Pruner::prune`], and
/// [`PrunerConfig::enabled`] is `false` by default, so on this build the undo
/// families grow monotonically for the life of the database. See the module
/// documentation for why that is the shipped decision and what it obliges.
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

        // Prune old undo data — the legacy account state diffs AND the generic
        // application journal — below the SAME height, which is never closer to
        // the head than `UNDO_RETENTION_FLOOR`.
        //
        // One height for both, because a reorg crossing the journal activation
        // boundary consumes both: blocks at or above it from the application
        // journal, blocks below it from the legacy diffs. Pruning them to
        // different depths would leave a band of heights revertible by one
        // record and not the other, which is the shape the contract's per-block
        // classification exists to avoid.
        let undo_retention = self.undo_retention();
        if current_height > undo_retention {
            let prune_below = current_height.saturating_sub(undo_retention);
            stats.state_diffs_pruned = self.prune_state_diffs_below(prune_below)?;
            stats.application_journals_pruned =
                self.prune_application_journals_below(prune_below)?;
        }

        // Compact if configured
        if self.config.compact_after_prune
            && (stats.blocks_pruned > 0
                || stats.state_diffs_pruned > 0
                || stats.application_journals_pruned > 0)
        {
            info!("Compacting database after pruning...");
            self.db.compact()?;
            stats.compacted = true;
        }

        let size_after = self.db.approximate_size();
        stats.bytes_freed = size_before.saturating_sub(size_after);

        info!(
            "Pruning complete: {} blocks, {} txs, {} receipts, {} state diffs, {} application journals removed. ~{} bytes freed",
            stats.blocks_pruned,
            stats.transactions_pruned,
            stats.receipts_pruned,
            stats.state_diffs_pruned,
            stats.application_journals_pruned,
            stats.bytes_freed
        );

        Ok(stats)
    }

    /// How many blocks of undo data this pruner keeps.
    ///
    /// The configured `state_diffs_to_keep` RAISED to [`UNDO_RETENTION_FLOOR`],
    /// never lowered below it, and `0` ("keep all") keeps all. A configuration
    /// asking to keep 1,000 diffs on a node that will plan a 4,096-block reorg
    /// is asking for an unrevertible branch, so the floor wins and the request
    /// is honoured as "at least".
    pub fn undo_retention(&self) -> u64 {
        if self.config.state_diffs_to_keep == 0 {
            return u64::MAX;
        }
        self.config.state_diffs_to_keep.max(UNDO_RETENTION_FLOOR)
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

    /// Prune generic application-journal records below a certain height.
    ///
    /// The key is an 8-byte big-endian height followed by the 32-byte block
    /// hash, so the height is a prefix and the decision needs no decode. A row
    /// whose key is shorter than eight bytes is left alone rather than guessed
    /// at: this function deletes undo data, and the one thing it must never do
    /// is delete a record it could not identify.
    fn prune_application_journals_below(&self, height: u64) -> Result<u64> {
        let mut pruned = 0u64;
        let mut keys_to_delete = Vec::new();

        for (key, _) in self.db.iter(cf::APPLICATION_JOURNAL)? {
            if key.len() < 8 {
                warn!(
                    "application journal row with a {}-byte key left in place: every key is \
                     an 8-byte height followed by a 32-byte block hash, and undo data whose \
                     height cannot be read is not data to delete on a guess",
                    key.len()
                );
                continue;
            }
            let record_height = u64::from_be_bytes(key[..8].try_into().unwrap());
            if record_height < height {
                keys_to_delete.push(key.to_vec());
            }
        }

        let batch_size = 1000;
        for chunk in keys_to_delete.chunks(batch_size) {
            let mut batch = self.db.batch();
            for key in chunk {
                batch.delete(cf::APPLICATION_JOURNAL, key)?;
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

    /// Write one journal-shaped row per height, keyed the way the publisher
    /// keys them: 8-byte big-endian height then a 32-byte block hash.
    fn seed_journal_rows(db: &Database, heights: impl IntoIterator<Item = u64>) {
        let mut batch = db.batch();
        for h in heights {
            let mut key = Vec::with_capacity(40);
            key.extend_from_slice(&h.to_be_bytes());
            key.extend_from_slice(&[0u8; 32]);
            batch.put(cf::APPLICATION_JOURNAL, &key, b"record").unwrap();
            batch.put(cf::STATE_DIFFS, &key, b"diff").unwrap();
        }
        batch.commit().unwrap();
    }

    fn journal_heights(db: &Database) -> Vec<u64> {
        let mut out: Vec<u64> = db
            .iter(cf::APPLICATION_JOURNAL)
            .unwrap()
            .map(|(k, _)| u64::from_be_bytes(k[..8].try_into().unwrap()))
            .collect();
        out.sort_unstable();
        out
    }

    /// The retention floor is the deepest reorg the node will plan.
    ///
    /// `MAX_REORG_WALK` lives in `sumchain-consensus`, which sits ABOVE this
    /// crate, so the number is duplicated rather than imported. This pins the
    /// copy; `reorg_execution.rs` asserts the same equality from the other side,
    /// so the two cannot drift apart without one of them failing.
    #[test]
    fn the_undo_retention_floor_covers_the_deepest_reorg_the_node_will_plan() {
        assert_eq!(
            UNDO_RETENTION_FLOOR, 4_096,
            "the floor must equal sumchain_consensus::poa::MAX_REORG_WALK; a floor \
             below it lets pruning delete undo data for a block plan_reorg will \
             still name on an abandoned branch"
        );
    }

    /// A configuration asking to keep less undo data than the deepest reorg is
    /// honoured as "at least", not obeyed literally.
    #[test]
    fn a_configuration_below_the_floor_is_raised_to_it_rather_than_obeyed() {
        let (db, _dir) = temp_db();
        let pruner = Pruner::new(
            db,
            PrunerConfig {
                enabled: true,
                state_diffs_to_keep: 10,
                ..Default::default()
            },
        );
        assert_eq!(pruner.undo_retention(), UNDO_RETENTION_FLOOR);

        let pruner_above = Pruner::new(
            pruner.db.clone(),
            PrunerConfig {
                enabled: true,
                state_diffs_to_keep: UNDO_RETENTION_FLOOR * 2,
                ..Default::default()
            },
        );
        assert_eq!(pruner_above.undo_retention(), UNDO_RETENTION_FLOOR * 2);

        let keep_all = Pruner::new(
            pruner.db.clone(),
            PrunerConfig {
                enabled: true,
                state_diffs_to_keep: 0,
                ..Default::default()
            },
        );
        assert_eq!(keep_all.undo_retention(), u64::MAX);
    }

    /// Pruning removes journals only for heights that can no longer be reverted,
    /// and removes them for BOTH undo families at the same depth.
    #[test]
    fn pruning_keeps_every_journal_whose_block_is_still_revertible() {
        let (db, _dir) = temp_db();
        let head = UNDO_RETENTION_FLOOR + 10;
        seed_journal_rows(&db, 0..=head);

        let pruner = Pruner::new(
            db.clone(),
            PrunerConfig {
                enabled: true,
                blocks_to_keep: 0,
                state_diffs_to_keep: 1,
                compact_after_prune: false,
                ..Default::default()
            },
        );
        let stats = pruner.prune(head).unwrap();

        // `state_diffs_to_keep: 1` asked for a one-block window. The floor
        // overrides it, so the oldest surviving journal is exactly
        // `head - UNDO_RETENTION_FLOOR`.
        let survivors = journal_heights(&db);
        assert_eq!(
            survivors.first().copied(),
            Some(head - UNDO_RETENTION_FLOOR),
            "the shallowest surviving journal must be exactly the retention floor \
             below the head; anything deeper is a revertible block with no undo data"
        );
        assert_eq!(survivors.last().copied(), Some(head));
        assert_eq!(
            survivors.len() as u64,
            UNDO_RETENTION_FLOOR + 1,
            "every height inside the reorg horizon must still have its journal"
        );
        assert_eq!(
            stats.application_journals_pruned,
            head - UNDO_RETENTION_FLOOR
        );
        assert_eq!(
            stats.state_diffs_pruned, stats.application_journals_pruned,
            "the two undo families must be pruned to the same depth, or a band of \
             heights is revertible by one record and not the other"
        );
    }

    /// A journal row whose key cannot be read as a height is left in place.
    #[test]
    fn an_unrecognisable_journal_key_is_not_deleted_on_a_guess() {
        let (db, _dir) = temp_db();
        seed_journal_rows(&db, 0..=UNDO_RETENTION_FLOOR + 10);
        let mut batch = db.batch();
        batch.put(cf::APPLICATION_JOURNAL, b"short", b"x").unwrap();
        batch.commit().unwrap();

        let pruner = Pruner::new(
            db.clone(),
            PrunerConfig {
                enabled: true,
                blocks_to_keep: 0,
                state_diffs_to_keep: 1,
                compact_after_prune: false,
                ..Default::default()
            },
        );
        pruner.prune(UNDO_RETENTION_FLOOR + 10).unwrap();

        assert!(
            db.get(cf::APPLICATION_JOURNAL, b"short").unwrap().is_some(),
            "undo data whose height could not be read must survive: deleting it \
             would be deleting a record this code could not identify"
        );
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

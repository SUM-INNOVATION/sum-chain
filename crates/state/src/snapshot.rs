//! State snapshot for fast sync, and what a snapshot can and cannot prove.
//!
//! A snapshot is the account family, lifted out of one node's database and
//! carried to another, so the receiving node reaches the chain tip without
//! replaying every block from genesis. That makes it the one path by which a
//! node acquires canonical state it did not compute — which is exactly the path
//! an account-state commitment has to reach, and the one it did not.
//!
//! # What this file did before the account commitment
//!
//! `verify_snapshot` recomputed a digest over `(address, balance)` pairs — no
//! domain separator, no nonce, no count — and compared it to
//! `header.state_root`, which is a BLOCK state root: a fold over header fields,
//! receipt outcomes, gated subsystem digests and the previous root. The two
//! values are computed from different inputs under different rules, so the
//! comparison could not succeed on any real snapshot, and a caller that treated
//! `Ok(false)` as "corrupt" would reject every snapshot ever produced. It was a
//! verification in name. `the_old_verification_could_never_have_succeeded` in
//! `crates/state/tests/snapshot_commitment.rs` reproduces that rather than
//! asserting it.
//!
//! # What it does now
//!
//! The snapshot carries [`SnapshotHeader::account_digest`], computed by
//! [`account_state_digest`] — the SAME function, over the same record layout,
//! that a validator recomputes over committed state and that
//! `compute_block_state_root` folds once the gate is open. Three consequences:
//!
//! * **Creation is self-checking.** The exported row list and the producing
//!   database are digested independently and must agree, so a snapshot cannot be
//!   written from a scan that saw a different account set than the commitment
//!   would.
//! * **Verification is real.** The rows in the file are folded through the one
//!   encoder and compared to the digest the file carries.
//! * **Restore is checked against the database, not the file.** After the rows
//!   land, the committed scan is rerun and must reproduce the digest — so a
//!   write that silently dropped or mangled a row fails here rather than at the
//!   next block.
//!
//! # What a snapshot still cannot prove, and where the proof comes from
//!
//! The digest in the header is a claim by whoever produced the file. Nothing in
//! the file ties it to the chain. What ties it to the chain is the commitment
//! itself: **above `account_root_enabled_from_height`, the first block the
//! restored node imports folds `v_account_state_digest` over the restored rows.**
//! If they are wrong by one unit in one balance, the computed root differs from
//! the header root and `accept_imported` refuses the block. A fast-synced node
//! therefore verifies what it restored at its first imported block, and cannot
//! proceed on state the chain did not agree to.
//!
//! Below the gate, none of that holds, and it is worth saying plainly: a
//! pre-activation fast sync is unverifiable by construction, because the
//! authoritative commitment does not cover account state at all.
//! [`RestoreResult::consensus_verified_from`] reports which case a given restore
//! is in rather than leaving the caller to infer it.
//!
//! # The undo history a snapshot does not carry
//!
//! The application journal is node-local: never hashed into a block, never
//! folded into a root, never sent over the wire. A snapshot is canonical state
//! and nothing else, so **a node that restores one has zero undo history** — it
//! can revert only blocks it has itself published or imported since.
//!
//! That is not a detail. `sumchain_consensus::poa::MAX_REORG_WALK` is 4,096
//! blocks and `UNDO_RETENTION_FLOOR` retains records to match, so a node that
//! advertises the configured horizon immediately after a restore is advertising
//! a depth it cannot perform: the walk would reach blocks with no record, and the
//! reorg would halt partway with the branch half-applied. [`usable_reorg_depth`]
//! is the honest number — zero at the restore height, growing one per block —
//! and [`RestoreResult::journal_history_begins_at`] is where a node's own
//! records start.
//!
//! The clamp itself belongs to the reorg planner, which this file does not own;
//! see the crate-level report for what is required there and what is not yet
//! wired.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, Balance, BlockHeight, Hash, Nonce};
use sumchain_storage::pruner::UNDO_RETENTION_FLOOR;
use sumchain_storage::{schema::AccountState, BlockStore, Database, StateStore};
use tracing::{debug, info, warn};

use crate::account_root::{account_state_digest, account_state_digest_of};
use crate::{Result, StateError};

/// Snapshot format version.
///
/// v2 adds the account-state commitment to the header. The bump is not
/// cosmetic: a v1 header carries a `state_root` that was compared against a
/// digest computed under a different rule, so a v1 file records no value this
/// code can check anything against. Snapshots are node-local artefacts — never
/// hashed into a block, never sent as consensus data — so raising the floor
/// costs nothing but a re-export.
const SNAPSHOT_VERSION: u32 = 2;

/// The oldest snapshot format this binary will restore.
///
/// Equal to [`SNAPSHOT_VERSION`]: a v1 snapshot is refused by NAME rather than
/// failing later inside bincode, because "unsupported version 1, re-export"
/// is an answer an operator can act on and a deserialization error is not.
const MIN_SUPPORTED_SNAPSHOT_VERSION: u32 = 2;

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
    /// Block state root at this height, as provenance.
    ///
    /// Kept because it names the block this snapshot claims to be state for. It
    /// is NOT what the account rows are checked against — it is a fold over
    /// header fields, receipt outcomes and gated subsystem digests, and below
    /// the account-commitment gate it does not depend on the account rows at
    /// all. [`Self::account_digest`] is the checkable value.
    pub state_root: Hash,
    /// The ACCOUNT-STATE COMMITMENT over the rows in this snapshot.
    ///
    /// Computed by `crate::account_root::account_state_digest` — the same
    /// function, over the same record layout, that a validator recomputes over
    /// committed state and that `compute_block_state_root` folds once the gate
    /// is open. That identity is the whole point: a snapshot verified against a
    /// digest of its own invention would prove only that the file is internally
    /// consistent.
    pub account_digest: Hash,
    /// The producer's `account_root_enabled_from_height`.
    ///
    /// Recorded so a consumer can say whether [`Self::account_digest`] is bound
    /// to consensus at [`Self::height`] or is merely the producer's own claim.
    /// See [`RestoreResult::consensus_verified_from`].
    pub account_root_activation: Option<u64>,
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
    /// The chain parameters this node runs on.
    ///
    /// Needed for exactly one thing: `account_root_enabled_from_height`, which
    /// decides whether a restored node's state will be checked by the chain at
    /// its first imported block or not checked at all. A snapshot manager that
    /// did not know it could not tell the caller which of those two a restore
    /// was.
    params: ChainParams,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new(db: Arc<Database>, chain_id: u64, params: ChainParams) -> Self {
        Self {
            db,
            chain_id,
            params,
        }
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

        // The commitment over the database, through the function consensus uses.
        let account_digest = account_state_digest(&self.db)?;

        // ...and the commitment over the rows actually written into the file,
        // through the same encoder. These are two different scans — the exported
        // list comes from `iter_all_accounts`, the digest above from the strict
        // prefix fold — and a snapshot is only worth producing if they agree. A
        // disagreement means the file describes an account set the commitment
        // would not, which is precisely the divergence a snapshot must never
        // carry, so it fails here rather than on the restoring node.
        let exported_digest = account_state_digest_of(rows_of(&accounts))?;
        if exported_digest != account_digest {
            return Err(StateError::Genesis(format!(
                "refusing to write a snapshot at height {height}: the exported \
                 account list digests to {exported_digest} but this database's \
                 account family digests to {account_digest}; the file would \
                 describe a state the commitment does not"
            )));
        }

        let header = SnapshotHeader {
            version: SNAPSHOT_VERSION,
            chain_id: self.chain_id,
            height,
            block_hash,
            state_root,
            account_digest,
            account_root_activation: self.params.account_root_enabled_from_height,
            account_count: accounts.len() as u64,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        info!(
            "Snapshot created with {} accounts, block state root {}, account \
             commitment {}",
            accounts.len(),
            state_root,
            account_digest
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

    /// Restore state from a snapshot.
    ///
    /// Three checks, in the order that makes each one mean something:
    ///
    /// 1. **Before any write** — chain id, format version, and the full
    ///    [`Self::verify_snapshot`] fold. A file that fails here has touched
    ///    nothing, so the node is exactly where it was.
    /// 2. **After the write** — the committed scan is rerun against RocksDB and
    ///    must reproduce the digest. This is a different question from (1): (1)
    ///    asks whether the file is self-consistent, this asks whether what
    ///    landed in the database is what the file said. A dropped row, a
    ///    re-encoded balance or a pre-existing account row this snapshot did not
    ///    overwrite all fail here and nowhere else.
    /// 3. **At the first imported block, by the chain** — see the module note.
    ///    Only (3) is a verification against the network, and only above the
    ///    activation gate; [`RestoreResult::consensus_verified_from`] says which.
    ///
    /// A failure at (2) leaves the rows written. That is deliberate and it is
    /// stated rather than hidden: the alternative is a partial rollback whose
    /// own correctness is unproven, and a node whose restore failed must not
    /// continue from either outcome. The error names the height so the operator
    /// re-inits from a known-good directory.
    pub fn restore_snapshot(&self, snapshot: &Snapshot) -> Result<RestoreResult> {
        // Verify chain ID
        if snapshot.header.chain_id != self.chain_id {
            return Err(StateError::Genesis(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.chain_id, snapshot.header.chain_id
            )));
        }

        // Verify version compatibility, in both directions. A newer format
        // carries fields this binary cannot check; an older one carries no
        // account commitment at all, so nothing it holds is checkable.
        if snapshot.header.version > SNAPSHOT_VERSION {
            return Err(StateError::Genesis(format!(
                "Unsupported snapshot version: {} (max supported: {})",
                snapshot.header.version, SNAPSHOT_VERSION
            )));
        }
        if snapshot.header.version < MIN_SUPPORTED_SNAPSHOT_VERSION {
            return Err(StateError::Genesis(format!(
                "snapshot format v{} carries no account-state commitment, so \
                 nothing in it can be verified; re-export at v{}",
                snapshot.header.version, SNAPSHOT_VERSION
            )));
        }

        // The whole fold, before a single row is written.
        self.verify_snapshot(snapshot)?;

        info!(
            "Restoring snapshot from height {} ({} accounts, account commitment {})",
            snapshot.header.height, snapshot.header.account_count, snapshot.header.account_digest
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

        // What the DATABASE now holds, through the function consensus uses —
        // not what the file claimed. The two differ whenever the write did
        // something other than what was asked, and whenever this database
        // already held account rows the snapshot does not mention: a restore
        // into a non-empty directory leaves those rows in place, they are folded
        // by the commitment, and the node would carry an account set no other
        // node has.
        let committed = account_state_digest(&self.db)?;
        if committed != snapshot.header.account_digest {
            return Err(StateError::Genesis(format!(
                "snapshot restore at height {} did not reproduce the commitment: \
                 the file claims {} and this database now digests to {}. The rows \
                 are written; this directory must not be used. Re-initialise and \
                 restore into an empty state.",
                snapshot.header.height, snapshot.header.account_digest, committed
            )));
        }

        info!(
            "Snapshot restored: {} accounts at height {}, commitment {} reproduced \
             from committed state",
            restored_count, snapshot.header.height, committed
        );

        Ok(RestoreResult {
            height: snapshot.header.height,
            block_hash: snapshot.header.block_hash,
            state_root: snapshot.header.state_root,
            account_digest: committed,
            consensus_verified_from: self
                .params
                .account_root_enabled_from_height
                .map(|activation| activation.max(snapshot.header.height + 1)),
            journal_history_begins_at: snapshot.header.height + 1,
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

    /// Verify a snapshot against the account-state commitment it carries.
    ///
    /// `Result<()>` rather than `Result<bool>`, because every way this can fail
    /// is a different fact and a boolean erases all of them. The previous
    /// signature returned `Ok(false)` for a count mismatch, a duplicate address
    /// and a digest mismatch alike — three findings an operator must
    /// distinguish, since only the last can be a transport error.
    ///
    /// What is checked:
    ///
    /// * the declared account count equals the rows present;
    /// * no address appears twice (a duplicate is a file that describes two
    ///   states, and whichever row is written last silently wins);
    /// * the rows, folded through the ONE encoder in ascending address order,
    ///   reproduce [`SnapshotHeader::account_digest`].
    ///
    /// The rows are sorted here rather than required to arrive sorted: a file is
    /// a transport, and the commitment is a function of the account SET, so a
    /// reordered file is not a corrupt one. Order is still load-bearing inside
    /// the fold — it is what makes the digest well-defined — and a duplicate
    /// address, which sorting would otherwise hide next to its twin, is caught
    /// explicitly before the fold runs.
    pub fn verify_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        if snapshot.accounts.len() as u64 != snapshot.header.account_count {
            warn!(
                "Account count mismatch: header says {}, actual {}",
                snapshot.header.account_count,
                snapshot.accounts.len()
            );
            return Err(StateError::Genesis(format!(
                "snapshot at height {} declares {} accounts and carries {}",
                snapshot.header.height,
                snapshot.header.account_count,
                snapshot.accounts.len()
            )));
        }

        let mut rows: Vec<(Address, AccountState)> = rows_of(&snapshot.accounts);
        rows.sort_by_key(|(addr, _)| *addr);
        for pair in rows.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(StateError::Genesis(format!(
                    "snapshot at height {} carries address {} twice; the file \
                     describes two different states and the restore would pick \
                     one of them by write order",
                    snapshot.header.height, pair[0].0
                )));
            }
        }

        let computed = account_state_digest_of(rows)?;
        if computed != snapshot.header.account_digest {
            warn!(
                "Account commitment mismatch: header says {}, computed {}",
                snapshot.header.account_digest, computed
            );
            return Err(StateError::Genesis(format!(
                "snapshot at height {} claims account commitment {} but its {} \
                 rows fold to {}",
                snapshot.header.height,
                snapshot.header.account_digest,
                snapshot.header.account_count,
                computed
            )));
        }

        info!(
            "Snapshot verification passed: {} accounts fold to {}",
            snapshot.header.account_count, computed
        );
        Ok(())
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
    /// The account commitment RECOMPUTED from committed state after the write,
    /// not the value the file claimed. They are equal or the restore failed.
    pub account_digest: Hash,
    /// The first height at which the CHAIN will check this node's account state,
    /// or `None` if it never will.
    ///
    /// `None` means `account_root_enabled_from_height` is unset: the block state
    /// root does not cover account rows at any height, so nothing this node
    /// imports can detect that the restore put it on a different account set
    /// than its peers. A fast sync in that configuration is unverifiable by
    /// construction, and this field says so rather than leaving a caller to
    /// conclude "verified" from the absence of an error.
    ///
    /// `Some(h)` is the first block whose root folds the account digest AND
    /// which this node will actually execute — `max(activation, restore + 1)`,
    /// because a node restored above the activation height is checked at its
    /// very next block, and one restored below it is checked when the chain
    /// reaches the gate.
    pub consensus_verified_from: Option<BlockHeight>,
    /// The first height for which this node holds an undo record.
    ///
    /// Always `restore height + 1`. A snapshot carries canonical state and no
    /// journals — the journal is node-local, never transmitted — so this node
    /// can unwind only what it has published or imported since. See
    /// [`usable_reorg_depth`].
    pub journal_history_begins_at: BlockHeight,
    pub accounts_restored: u64,
}

/// How deep a reorg a snapshot-restored node can actually perform.
///
/// `0` at the restore height, one more per block, capped at
/// [`UNDO_RETENTION_FLOOR`] — which equals
/// `sumchain_consensus::poa::MAX_REORG_WALK`, the depth the planner will
/// otherwise attempt.
///
/// # Why this is not the configured horizon
///
/// The application journal is node-local: never hashed into a block, never
/// folded into a state root, never sent over the wire. A node that arrives by
/// snapshot therefore holds canonical state at height `restored_at` and NO undo
/// record for any block at or below it. There are only two ways it could obtain
/// them — replay the blocks from below `restored_at`, which is the fast sync it
/// just avoided, or receive them from a peer, which the contract forbids because
/// they are not consensus data and nothing authenticates them. So it does not
/// obtain them: it accumulates its own, one per block, from `restored_at + 1`.
///
/// Until it has `UNDO_RETENTION_FLOOR` of them, a planner that walks the full
/// horizon will reach a block with no record and halt partway, with the branch
/// half-applied. This function is the number that must bound the walk instead.
///
/// The bound is stated here and applied by the reorg planner, which this file
/// does not own.
pub fn usable_reorg_depth(restored_at: BlockHeight, current_height: BlockHeight) -> u64 {
    current_height
        .saturating_sub(restored_at)
        .min(UNDO_RETENTION_FLOOR)
}

/// `(Address, AccountState)` pairs from snapshot rows, for the one encoder.
///
/// A free function rather than a `From` impl: it exists so that the snapshot
/// row type never needs to know how the commitment encodes an account, and the
/// commitment never needs to know a snapshot row type exists.
fn rows_of(accounts: &[SnapshotAccount]) -> Vec<(Address, AccountState)> {
    accounts
        .iter()
        .map(|a| {
            (
                Address::new(a.address),
                AccountState {
                    balance: a.balance,
                    nonce: a.nonce,
                },
            )
        })
        .collect()
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

    fn manager(db: Arc<Database>) -> SnapshotManager {
        SnapshotManager::new(db, 1337, ChainParams::with_v2_enabled())
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
            account_digest: Hash::default(),
            account_root_activation: None,
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
        let manager = manager(db);

        let snapshot = Snapshot {
            header: SnapshotHeader {
                version: 1,
                chain_id: 1337,
                height: 50,
                block_hash: Hash::default(),
                state_root: Hash::default(),
                account_digest: Hash::default(),
                account_root_activation: None,
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
        let manager = manager(db);

        // Create snapshot with mismatched account count
        let snapshot = Snapshot {
            header: SnapshotHeader {
                version: 1,
                chain_id: 1337,
                height: 50,
                block_hash: Hash::default(),
                state_root: Hash::default(),
                account_digest: Hash::default(),
                account_root_activation: None,
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

        // Verification must fail, and NAME the count discrepancy: a boolean
        // would not distinguish this from a digest mismatch, which is a
        // different fault with a different cause.
        let err = manager
            .verify_snapshot(&snapshot)
            .expect_err("a header that declares 5 accounts over 1 row must be refused")
            .to_string();
        assert!(
            err.contains("declares 5 accounts and carries 1"),
            "the refusal must name the count discrepancy: {err}"
        );
    }

    #[test]
    fn test_restore_wrong_chain_id() {
        let (db, _dir) = setup_db();
        let manager = manager(db);

        let snapshot = Snapshot {
            header: SnapshotHeader {
                version: 1,
                chain_id: 9999, // Different chain ID
                height: 50,
                block_hash: Hash::default(),
                state_root: Hash::default(),
                account_digest: Hash::default(),
                account_root_activation: None,
                account_count: 0,
                created_at: 12345,
            },
            accounts: vec![],
        };

        let result = manager.restore_snapshot(&snapshot);
        assert!(result.is_err());
    }
}

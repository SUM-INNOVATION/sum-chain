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
//! # Fast sync is DISABLED, and why that is the resolution
//!
//! None of the above makes a snapshot a SYNC. A snapshot carries the account
//! family and nothing else, and `compute_block_state_root` folds the supply
//! digest today, with no activation gate — so a node restored from one cannot
//! reproduce the root of the next block it imports at any height, however
//! perfectly its account rows landed. Contract state, tokens, NFTs, storage
//! metadata and the validator set are missing too, and the compute-pool and
//! beacon digests join the root the moment their gates open.
//!
//! So [`SnapshotManager::restore_snapshot`] refuses. Structurally, not by a
//! flag: the file declares what it carries ([`SnapshotHeader::families`]), a
//! constant declares what a sync requires
//! ([`REQUIRED_FAST_SYNC_FAMILIES`]), and the difference is the refusal. When
//! the format grows a family, [`SNAPSHOT_CARRIES`] grows with it and the refusal
//! lifts itself — nobody has to remember a second place.
//!
//! [`SnapshotManager::import_account_family`] is what remains available: the
//! same fully-checked import of the account family, which does not claim to be a
//! sync and does not leave the node believing it is one.
//!
//! # What an account-family import still cannot prove, and where the proof comes from
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
//! Both facts are RECORDED rather than returned and forgotten. The import height
//! goes into `cf::META`, and [`sync_capability`] reads it back — so the startup
//! log, the RPC surface and any future clamp all answer from one place and
//! cannot drift into three different answers about the same node. A node that
//! learned its undo history began at H+1 and then restarted would otherwise go
//! straight back to advertising the full horizon.
//!
//! [`can_serve_history_at`] is the same idea for reads: a query path asks it
//! before answering a historical state question, because a walk that runs off
//! the bottom of this node's history and returns whatever it finds there is
//! worse than an error — the caller cannot tell.
//!
//! Applying the depth as a bound on the reorg WALK belongs to the reorg planner,
//! which this file does not own. This side reports the number; that side is
//! where it becomes a limit.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, Balance, BlockHeight, Hash, Nonce};
use sumchain_storage::messaging_store::RegistrySeed;
use sumchain_storage::pruner::UNDO_RETENTION_FLOOR;
use sumchain_storage::{schema::AccountState, BlockStore, Database, StateStore};
use tracing::{debug, info, warn};

use crate::account_root::{account_state_digest, account_state_digest_of};
use crate::{Result, StateError};

/// Snapshot format version.
///
/// v2 added the account-state commitment to the header. v3 adds the list of
/// state families the file CARRIES, which is what turns "fast sync is
/// incomplete" from a fact somebody has to remember into a fact the file states
/// and the restore path enforces. Snapshots are node-local artefacts — never
/// hashed into a block, never sent as consensus data — so raising the floor
/// costs nothing but a re-export.
const SNAPSHOT_VERSION: u32 = 3;

/// The oldest snapshot format this binary will restore.
///
/// Equal to [`SNAPSHOT_VERSION`]: an older snapshot is refused by NAME rather
/// than failing later inside bincode, because "unsupported version 2, re-export"
/// is an answer an operator can act on and a deserialization error is not.
const MIN_SUPPORTED_SNAPSHOT_VERSION: u32 = 3;

/// The state families this snapshot format actually carries.
///
/// One entry, and that is the whole problem. Written into every file this
/// binary produces, so a snapshot says what it holds rather than leaving a
/// consumer to assume it holds everything.
pub const SNAPSHOT_CARRIES: &[&str] = &["state:accounts"];

/// The state families a snapshot must carry before restoring from one is a SYNC
/// rather than a partial state import.
///
/// Derived from what a node needs in order to execute the next block and
/// reproduce its root, not from what is convenient to export:
///
/// * `state:accounts` — balances and nonces, folded by the account commitment.
/// * `supply` — the supply ledger and protocol reserve. Folded into every block
///   state root through `SupplyStore::v_state_digest`, TODAY, with no activation
///   gate. A node missing it cannot reproduce a root at any height.
/// * `contracts`, `contract_storage` — persistent contract state. The contracts
///   gate is open on mainnet (height 8,900,000) and the contract digest is
///   folded above it.
/// * `tokens`, `nft` — SUM-721 and token balances, allowances and indexes.
/// * `compute_pool`, `beacon` — dormant today, folded the moment their gates
///   open, which is the point at which forgetting them becomes a chain split.
/// * `storage_metadata`, `validators` — SNIP V2 file/chunk/assignment records
///   and the validator/delegation set, both read during execution.
///
/// A family appearing here is a claim that a restored node needs it. A family
/// missing from here is a claim that it does not. Neither is safe to leave
/// implicit, which is why [`missing_for_fast_sync`] compares the two lists
/// instead of a human comparing them.
pub const REQUIRED_FAST_SYNC_FAMILIES: &[&str] = &[
    "state:accounts",
    "supply",
    "contracts",
    "contract_storage",
    "tokens",
    "nft",
    "compute_pool",
    "beacon",
    "storage_metadata",
    "validators",
];

/// `META` key holding what a snapshot import did to this database.
///
/// Re-exported rather than redeclared: the key, its encoding and its decode
/// failure live together in [`sumchain_storage::journal`], so there is one
/// answer to "what is in that row" and one answer to "what if it is
/// unreadable".
///
/// There used to be a second row, `snapshot/imported_at`, recording the same
/// fact under a different write rule. Two rows for one fact do not conflict,
/// they diverge, and no module that owns one of them can detect it.
pub use sumchain_storage::journal::UNDO_HISTORY_FLOOR_META_KEY as SNAPSHOT_IMPORT_META_KEY;

/// The families [`REQUIRED_FAST_SYNC_FAMILIES`] demands and
/// [`SNAPSHOT_CARRIES`] does not supply.
///
/// Empty means a snapshot of this format is a complete sync. It is not empty.
pub fn missing_for_fast_sync(carried: &[String]) -> Vec<&'static str> {
    REQUIRED_FAST_SYNC_FAMILIES
        .iter()
        .copied()
        .filter(|required| !carried.iter().any(|c| c == required))
        .collect()
}

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
    /// The state families this file CARRIES.
    ///
    /// Written from [`SNAPSHOT_CARRIES`] by the producer and compared against
    /// [`REQUIRED_FAST_SYNC_FAMILIES`] by the consumer. A self-describing file:
    /// a consumer never has to assume what a producer included, and a producer
    /// that starts including more does not need the consumer changed to notice.
    pub families: Vec<String>,
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
            families: SNAPSHOT_CARRIES.iter().map(|s| s.to_string()).collect(),
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

    /// Fast sync from a snapshot. **Refused: this format cannot perform one.**
    ///
    /// A snapshot carries the account family and nothing else. Restoring from it
    /// and then importing the next block does not work and cannot be made to
    /// work by checking the account rows harder:
    /// `compute_block_state_root` folds the supply digest today, with no
    /// activation gate, and `cf::SUPPLY` is not in the file. Contract state,
    /// tokens, NFTs, storage metadata and the validator set are not in it
    /// either, and the compute-pool and beacon digests join the root the moment
    /// their gates open.
    ///
    /// So this is not a gap to be documented. Until the format carries
    /// [`REQUIRED_FAST_SYNC_FAMILIES`], fast sync is **disabled**, and it is
    /// disabled here — at the entry point, by comparing what the file says it
    /// carries against what a sync requires — rather than by a flag someone can
    /// set. When the format grows a family, [`SNAPSHOT_CARRIES`] grows with it
    /// and this refusal lifts itself.
    ///
    /// [`Self::import_account_family`] is what remains available: a checked
    /// import of the account family that does not claim to be a sync and does
    /// not leave the node believing it is synced.
    pub fn restore_snapshot(&self, snapshot: &Snapshot) -> Result<RestoreResult> {
        self.check_header(snapshot)?;

        let missing = missing_for_fast_sync(&snapshot.header.families);
        if !missing.is_empty() {
            return Err(StateError::Genesis(format!(
                "fast sync is DISABLED: a snapshot at height {} carries {:?} and a \
                 sync requires {:?} — missing {:?}. A node restored from this file \
                 could not reproduce the state root of the next block it imported, \
                 because `compute_block_state_root` folds state this file does not \
                 contain. Sync by replaying blocks, or extend the snapshot format \
                 to carry every family above.",
                snapshot.header.height,
                snapshot.header.families,
                REQUIRED_FAST_SYNC_FAMILIES,
                missing
            )));
        }

        // Unreachable while `SNAPSHOT_CARRIES` is one family. Left as the real
        // body rather than an `unreachable!()` so that extending the format is
        // an edit to one constant and not a rediscovery of what restore does.
        self.import_account_family(snapshot)
    }

    /// Import the ACCOUNT FAMILY from a snapshot. **Not a sync.**
    ///
    /// Everything [`Self::restore_snapshot`] would do to the account rows, fully
    /// checked, with no claim that the resulting node is synced. What it is for:
    /// seeding a node whose other families arrive by some other route, and
    /// testing the account commitment against a state the node did not compute.
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
    /// A failure at (2) leaves the rows written, and the undo-history floor
    /// with them. That is deliberate and it is stated rather than hidden: the
    /// alternative is a partial rollback whose own correctness is unproven, and
    /// a node whose import failed must not continue from either outcome. The
    /// error names the height so the operator re-inits from a known-good
    /// directory.
    ///
    /// The import RECORDS what it did, in `cf::META`, because the consequences
    /// outlive the process: this node holds no undo record for any block at or
    /// below the import height and can reconstruct no historical state below
    /// it. See [`sync_capability`] and [`state_history_floor`]. The record is
    /// staged into the FIRST batch of rows rather than written after the last,
    /// so no crash can leave restored state that does not know its own floor.
    pub fn import_account_family(&self, snapshot: &Snapshot) -> Result<RestoreResult> {
        self.check_header(snapshot)?;

        // The whole fold, before a single row is written.
        self.verify_snapshot(snapshot)?;

        info!(
            "Importing the account family from height {} ({} accounts, account \
             commitment {}). This is NOT a sync.",
            snapshot.header.height, snapshot.header.account_count, snapshot.header.account_digest
        );

        // The rows and the undo-history floor go in together, through the store
        // that owns both encodings. This path deliberately holds no batch of
        // its own: the ordering that closes the crash window — the floor staged
        // into the FIRST batch of rows, never written after the last — is not
        // something a caller should be able to get wrong, so the caller does
        // not get to choose it. See `StateStore::import_accounts`.
        let restored_count = StateStore::new(&self.db)
            .import_accounts(
                snapshot.accounts.iter().map(|a| {
                    (
                        Address::new(a.address),
                        AccountState {
                            balance: a.balance,
                            nonce: a.nonce,
                        },
                    )
                }),
                snapshot.header.height,
            )
            .map_err(|e| {
                StateError::Genesis(format!(
                    "importing the account family at height {} failed: {e}",
                    snapshot.header.height
                ))
            })?;
        debug!("Imported {} accounts", restored_count);

        // What the DATABASE now holds, through the function consensus uses —
        // not what the file claimed. The two differ whenever the write did
        // something other than what was asked, and whenever this database
        // already held account rows the snapshot does not mention: an import
        // into a non-empty directory leaves those rows in place, they are folded
        // by the commitment, and the node would carry an account set no other
        // node has.
        let committed = account_state_digest(&self.db)?;
        if committed != snapshot.header.account_digest {
            return Err(StateError::Genesis(format!(
                "snapshot import at height {} did not reproduce the commitment: \
                 the file claims {} and this database now digests to {}. The rows \
                 are written; this directory must not be used. Re-initialise and \
                 import into an empty state.",
                snapshot.header.height, snapshot.header.account_digest, committed
            )));
        }

        info!(
            "Account family imported: {} accounts at height {}, commitment {} \
             reproduced from committed state. Undo history begins at {}; \
             historical state below {} is unavailable on this node.",
            restored_count,
            snapshot.header.height,
            committed,
            snapshot.header.height + 1,
            snapshot.header.height
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

    /// Chain id and format version. Shared by both entry points, so neither can
    /// acquire a laxer version rule than the other.
    fn check_header(&self, snapshot: &Snapshot) -> Result<()> {
        if snapshot.header.chain_id != self.chain_id {
            return Err(StateError::Genesis(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.chain_id, snapshot.header.chain_id
            )));
        }
        if snapshot.header.version > SNAPSHOT_VERSION {
            return Err(StateError::Genesis(format!(
                "Unsupported snapshot version: {} (max supported: {})",
                snapshot.header.version, SNAPSHOT_VERSION
            )));
        }
        if snapshot.header.version < MIN_SUPPORTED_SNAPSHOT_VERSION {
            return Err(StateError::Genesis(format!(
                "snapshot format v{} predates the self-describing family list, so \
                 nothing in it can be checked against what a sync requires; \
                 re-export at v{}",
                snapshot.header.version, SNAPSHOT_VERSION
            )));
        }
        Ok(())
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

/// What a node that imported a snapshot may claim about itself.
///
/// One value, read from the database rather than from whatever the process that
/// performed the import happened to return, because the import and the claim are
/// usually in different processes: a node imports, restarts, and then has to
/// answer questions about its own history.
///
/// A node that never imported one is `imported_at == None`, and every field
/// below reads as "no restriction" — which is the correct answer for a node that
/// built its state by executing every block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncCapability {
    /// The height a snapshot was imported at, if one ever was.
    pub imported_at: Option<BlockHeight>,
    /// Whether this binary's snapshot format can perform a fast sync at all.
    ///
    /// `false` while [`SNAPSHOT_CARRIES`] is short of
    /// [`REQUIRED_FAST_SYNC_FAMILIES`]. Reported rather than assumed, because
    /// "this node was fast-synced" and "this node could be" are different
    /// questions and an operator asks both.
    pub fast_sync_available: bool,
    /// The families a sync requires and this format does not carry.
    pub missing_families: Vec<&'static str>,
    /// The lowest height this node can answer a historical STATE question for.
    ///
    /// `None` for a node that executed its whole chain. `Some(h)` for an
    /// imported node: state below `h` was never on this machine and cannot be
    /// reconstructed from what is.
    pub state_history_floor: Option<BlockHeight>,
    /// The first height this node holds an undo record for.
    pub journal_history_begins_at: Option<BlockHeight>,
    /// The deepest reorg this node may ADVERTISE, at `current_height`.
    pub usable_reorg_depth: u64,
    /// The chain height this was computed against.
    pub current_height: BlockHeight,
    /// What an operator seed did to this node's SRC-201 public-key registry.
    ///
    /// `None` on every node that built the family by executing blocks, which is
    /// the normal state. `Some(_)` says this node's messaging registry did NOT
    /// come from its own execution — it was written by `sumchain
    /// import-registered-keys` before the first block above genesis — and
    /// carries the digest a peer compares against its own to find out whether
    /// the two were seeded from the same set. The family is read by consensus,
    /// so two nodes seeded differently disagree about receipts; this is the
    /// value that makes that answerable before the first messaging transaction
    /// rather than after a diverged root.
    pub messaging_registry_seed: Option<RegistrySeed>,
}

/// Read what a snapshot import did to this database, and what follows from it.
///
/// The single place the node's startup log, its RPC surface and any future
/// reorg-depth clamp should all read from, so the three cannot drift into three
/// different answers about the same node.
///
/// It also reports the one OPERATOR-applied provenance a node can carry:
/// [`SyncCapability::messaging_registry_seed`]. A snapshot import and a registry
/// seed are the same kind of fact — state on this machine that this machine did
/// not produce — and they are answered from one place for the same reason.
pub fn sync_capability(db: &Database, current_height: BlockHeight) -> Result<SyncCapability> {
    let imported_at = imported_at(db)?;
    let carried: Vec<String> = SNAPSHOT_CARRIES.iter().map(|s| s.to_string()).collect();
    let missing_families = missing_for_fast_sync(&carried);
    Ok(SyncCapability {
        imported_at,
        fast_sync_available: missing_families.is_empty(),
        missing_families,
        state_history_floor: imported_at,
        journal_history_begins_at: imported_at.map(|h| h + 1),
        usable_reorg_depth: match imported_at {
            Some(h) => usable_reorg_depth(h, current_height),
            // Not imported: this node executed every block it holds, so the
            // pruner's retention floor is the only bound, and it is not this
            // module's to report.
            None => UNDO_RETENTION_FLOOR,
        },
        current_height,
        // Read here rather than at each reporting site for the reason this
        // whole function exists: the startup log and the RPC surface must not
        // be able to give two different answers about the same node.
        messaging_registry_seed: sumchain_storage::messaging_store::registry_seed(db)
            .map_err(|e| StateError::Genesis(e.to_string()))?,
    })
}

/// The height a snapshot was imported at, or `None`.
pub fn imported_at(db: &Database) -> Result<Option<BlockHeight>> {
    sumchain_storage::journal::undo_history_floor(db)
        .map_err(|e| StateError::Genesis(e.to_string()))
}

/// May this node answer a historical STATE question at `height`?
///
/// The rule a query path applies, factored out so every path applies the same
/// one. A node that imported a snapshot at `h` holds no state for any height
/// below `h` and cannot derive it: the blocks are not there, and if they were,
/// replaying them is the sync the import avoided. The answer is a refusal, not
/// a best effort — a walk that runs off the bottom of this node's history and
/// returns whatever it found there is worse than an error, because the caller
/// cannot tell.
pub fn can_serve_history_at(db: &Database, height: BlockHeight) -> Result<bool> {
    Ok(match imported_at(db)? {
        Some(floor) => height >= floor,
        None => true,
    })
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
            families: SNAPSHOT_CARRIES.iter().map(|s| s.to_string()).collect(),
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
                families: SNAPSHOT_CARRIES.iter().map(|s| s.to_string()).collect(),
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
                families: SNAPSHOT_CARRIES.iter().map(|s| s.to_string()).collect(),
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
                families: SNAPSHOT_CARRIES.iter().map(|s| s.to_string()).collect(),
                account_count: 0,
                created_at: 12345,
            },
            accounts: vec![],
        };

        let result = manager.restore_snapshot(&snapshot);
        assert!(result.is_err());
    }
}

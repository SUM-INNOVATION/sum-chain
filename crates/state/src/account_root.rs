//! The account-state commitment.
//!
//! `compute_block_state_root` folds header fields, receipt outcomes, the gated
//! contract / supply / compute-pool / beacon digests and the previous root. It
//! reads the account rows in [`cf::STATE`] nowhere. Balances and nonces reach
//! the root only indirectly, through `receipt.fee_paid`, and only for the
//! accounts a transaction happened to touch. Two nodes can therefore hold
//! different balances for every account on the chain and still publish
//! identical block hashes, so the commitment cannot detect the disagreement —
//! and nothing built on top of it (light client, fast-sync check, fraud proof)
//! can either.
//!
//! This module is the missing term. It defines ONE digest over the account
//! family, computed two ways that must agree — over a block's candidate
//! ([`v_account_state_digest`], what the root folds) and over committed state
//! ([`account_state_digest`], what a node that stored the block recomputes).
//!
//! # The structure, and why this one
//!
//! A domain-separated, streaming, address-ordered fold over every account row,
//! one fixed-width 44-byte record per account, with the account count folded in
//! at the end:
//!
//! ```text
//! blake3( DOMAIN
//!         ‖ for each account in ascending address order:
//!               address[20] ‖ balance:u128 BE[16] ‖ nonce:u64 BE[8]
//!         ‖ count:u64 BE[8] )
//! ```
//!
//! Three alternatives were considered and rejected.
//!
//! * **A Merkle root over the account family.** It is the only one of the three
//!   that also yields *inclusion proofs* — the thing a light client eventually
//!   wants. It is rejected here because a Merkle root that is cheap to update
//!   per block needs a persistent authenticated tree (a trie whose interior
//!   nodes are stored and re-pathed on write), which is a storage-layout change
//!   of its own, with its own reorg-revert story, its own snapshot/fast-sync
//!   story and its own activation. Building the tree from scratch each block
//!   instead is strictly MORE expensive than this fold — the same O(n) scan
//!   plus O(n) interior hashing and O(n) allocation. Nothing about this design
//!   forecloses it: the gate below is `account_root_enabled_from_height`, and a
//!   future `v2` domain can replace the fold at a second, later height.
//!
//! * **An incremental accumulator** — a homomorphic multiset hash carried from
//!   block to block and updated only by the accounts this block touched, in
//!   O(touched) rather than O(n). It is the obviously cheaper scheme and it is
//!   rejected because it commits to the *history of writes*, not to the *rows*.
//!   A node whose stored row for an untouched account is wrong — a reorg that
//!   failed to restore it, a corrupted write, a divergent earlier execution
//!   whose journal was replayed — carries a stale accumulator that still agrees
//!   with the honest node's, and stays undetected until that account is next
//!   touched. That is precisely the blindness this work exists to remove: the
//!   reproduction case (a row written behind the executor's back, never
//!   touched again) would still pass. The requirement is a commitment that is a
//!   function of ACCOUNT STATE ALONE, and only a scan of the rows is that.
//!
//! * **An order-independent additive combiner** (sum or XOR of per-account
//!   leaf hashes) instead of an ordered fold. It buys order-independence
//!   without the scan being sorted — which is worth nothing here, because
//!   RocksDB and the overlay's merged iterator both yield keys in ascending
//!   order already — and it pays for it in collision resistance: a 256-bit
//!   additive multiset hash is subject to generalized-birthday (Wagner k-tree)
//!   subset attacks well below its nominal security, and an attacker who
//!   controls the balances of accounts they own controls many of the summands.
//!   The ordered fold's collision resistance is just blake3's.
//!
//! # Determinism
//!
//! The digest is a function of the account SET, nothing else. Insertion order
//! cannot matter (the fold is over ascending address order, and RocksDB stores
//! by key); process, memory layout and iterator batching cannot matter (the
//! records are fixed-width and the fold is streaming); and the ascending-order
//! assumption is not trusted, it is CHECKED — a scan that yields a key out of
//! order fails the block with [`StateError::AccountScanOutOfOrder`] rather than
//! producing a plausible-looking root over a differently-ordered fold.
//!
//! # Cost, measured — with a cold cache, against a count that is not yet known
//!
//! O(n) in the number of accounts, PER BLOCK, with O(1) memory: no map is
//! built, no 44·n buffer is materialised, the hasher is fed 44 bytes at a time.
//! That per-block O(n) is the cost of committing to state rather than to a
//! write history, and it is the reason the ceiling below matters.
//!
//! An earlier version of this note reported warm-cache synthetic figures
//! against a 2-second block budget and said the scheme was impractical past ten
//! million accounts. Three things about that were guesses. All three are now
//! measured, and two of them were wrong.
//!
//! ## The block budget is 1.5 seconds, not 2
//!
//! `block_time_ms` on live mainnet is 3,000, but that is a PROPOSER SLOT. The
//! chain runs two validators in round-robin, so blocks arrive every 1,506 ms —
//! measured over 920,593 blocks of real history (heights 12,000,000 to
//! 12,920,593, 2026-09-17), which is 57,361 blocks per day. Every node executes
//! every block, so that interval, not the slot, is what this scan has to fit
//! inside. The budget is TIGHTER than the earlier note assumed.
//!
//! ## The production STORED-ROW count is not established
//!
//! The cost is linear in the number of account ROWS RocksDB holds, and that
//! number has not been measured, because no production database is available in
//! the environment this work was done in. What was measured over RPC is a
//! different quantity, and conflating the two would be the whole error:
//!
//! **18 accounts hold value on mainnet.** Enumerated by walking the transaction
//! graph out from the two genesis allocations through
//! `sum_getTransactionsByAddress` to closure — 88 transactions, 18 addresses —
//! and cross-checked against the chain's own accounting: those 18 balances sum
//! to 999,998,997,000,000,000, which is
//! `chain_getSupplyInfo.accounted_account_supply` to the base unit.
//!
//! That is a **lower bound** on stored rows and nothing more. Each of the 18
//! holds a nonzero balance, so each is certainly a stored row; 18 ≤ rows. It is
//! **not an upper bound**, for two reasons that are not hypothetical:
//!
//! * A row whose balance and nonce are both zero is invisible to every RPC.
//!   `get_account` flattens absence into `{balance: 0, nonce: 0}`, so
//!   `sum_getBalance` cannot distinguish a stored zero row from no row — and the
//!   two cost exactly the same to fold.
//! * A row can exist at an address that never appears in the transaction index.
//!   `ContractExecutorState` credits the CONTRACT address on a deployment
//!   carrying value (`contract_executor.rs`, `v_credit(view,
//!   &result.contract_address, …)`), and a contract address is not a
//!   transaction's `to` field, so no recipient-index walk reaches it. The
//!   contracts gate has been open on mainnet since height 8,900,000.
//!
//! The measurement was attempted, on 2026-09-18, and could not be taken. There
//! is no SUM Chain data directory on this machine — every database this work
//! touched was created by a test and destroyed with it — and the public mainnet
//! RPC answers `-32601 Method not found` for `chain_getSyncCapability`, because
//! that node runs a binary predating this work. No other RPC on the surface
//! exposes a state-size or account-count statistic; that was checked rather than
//! assumed.
//!
//! So the number this cost model needs is **unmeasured — ≥ 18, upper bound
//! unknown** — and the instrument for measuring it ships here rather than the
//! measurement: [`account_row_count`]
//! runs the same scan as [`account_state_digest`], through the same prefix bound
//! and the same stop condition, so it reports exactly the count the fold will
//! pay for. It is exposed at node startup and as
//! `chain_getSyncCapability.account_rows`, and the activation runbook makes
//! taking that reading on a production node a prerequisite rather than a
//! suggestion.
//!
//! ## Cold cache costs about 12%, not an order of magnitude
//!
//! The account family is small and the scan is sequential, so a cold read is
//! bandwidth-bound on a contiguous 223 MB at ten million accounts, not
//! seek-bound. Measured by
//! `the_cost_of_the_account_commitment_with_a_cold_cache` in
//! `crates/state/tests/account_state_root.rs` in three states: warm; RocksDB
//! reopened with an empty block cache; and with the OS page cache evicted by
//! 24 GiB of ballast on a 16 GiB machine.
//!
//! Release build, Apple M5 (10 cores, 16 GiB), RocksDB on local NVMe:
//!
//! | accounts | family on disk | warm | cold block cache | cold page cache | µs/account | share of a 1.5 s block |
//! |---------:|---------------:|-----:|-----------------:|----------------:|-----------:|----------------------:|
//! |   **18** |        < 1 KiB | 4.6 µs |         29.6 µs |               — |      1.646 |             0.002 % |
//! |     100k |         3.4 MB | 12.0 ms |        14.7 ms |         15.3 ms |      0.153 |               1.0 % |
//! |       1M |        23.6 MB | 147 ms |         147 ms |          152 ms |      0.152 |              10   % |
//! |      10M |         223 MB |  1.45 s |         1.46 s |          1.62 s |      0.162 |             108   % |
//!
//! Flat at ~0.15 µs per account from 100k to 10M, cold or warm, which is the
//! linear streaming scan the design claims. The 18-account row is dominated by
//! fixed iterator and open cost, not by the fold.
//!
//! ## The verdict
//!
//! **At any row count near the value-holding count, this is free.** 18 rows
//! costs 4.6 microseconds per block, three millionths of the interval. There is
//! no performance argument against shipping the commitment at a count in that
//! region, and nine orders of magnitude of headroom before one appears.
//!
//! **The ceiling is real and it is closer than the old note said.** At ten
//! million rows the coldest scan is 1.62 s against a 1,506 ms interval: it does
//! not fit inside one block at all. Interpolating at 0.16 µs/row, the scan
//! reaches 10% of the interval at about 940,000 rows and 50% at about 4.7
//! million. The practical ceiling is a few million, and the replacement at that
//! point is the persistent authenticated trie rejected above, whose per-block
//! work is O(touched · log n) rather than O(n), activated at its own later
//! height under its own domain separator.
//!
//! **The distance to that ceiling is not known and must not be extrapolated.**
//! An earlier version of this note computed a growth rate from 18 accounts over
//! 12.9 million blocks and concluded that a million accounts was tens of
//! thousands of years away. That figure is withdrawn. It divided an unmeasured
//! quantity by the chain's whole lifetime and presented the quotient as a safety
//! margin; historical usage of a chain with 88 transactions bounds nothing about
//! its adoption, and a single integration can add more rows in a day than this
//! chain has produced in its life. The honest statement is narrower and more
//! useful: **the cost is linear and the input is observable**, so the ceiling is
//! approached visibly rather than suddenly — provided somebody is looking.
//!
//! That is what the operational threshold is for, and it is a threshold on a
//! MEASURED count rather than a projected one:
//!
//! | rows | scan | share of 1,506 ms | action |
//! |-----:|-----:|------------------:|--------|
//! |  250,000 |  40 ms | 2.7 % | warn; begin tracking the trend per week |
//! |  500,000 |  80 ms | 5.3 % | design the trie replacement and its activation |
//! | 2,000,000 | 320 ms | 21 % | the replacement must be scheduled, with a height |
//! | 4,000,000 | 640 ms | 43 % | the replacement must be ACTIVE |
//!
//! See `docs/operations/ACCOUNT-ROOT-ACTIVATION.md` for how the count is read
//! and at what cadence — it is an O(n) scan, the same one the commitment pays
//! for, so it is not a value to poll at scrape frequency.
//!
//! Two limits remain on the numbers. The eviction is approximate — there is no
//! portable way to drop the OS page cache, so the harness applies 24 GiB of
//! pressure to a 223 MB database rather than proving every page was dropped,
//! which makes the cold-page figure a lower bound on a truly cold device. And
//! the fold is single-threaded; it is order-dependent, so it does not
//! parallelise without changing the construction.

use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, Hash};
use sumchain_storage::candidate::LEGACY_ROOT_COMPATIBILITY_HEIGHT;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::pruner::UNDO_RETENTION_FLOOR;
use sumchain_storage::schema::decode_account;
use sumchain_storage::schema::AccountState;
use sumchain_storage::schema::ACCOUNT_KEY_PREFIX;
use sumchain_storage::{cf, Database, StateStore};

use crate::{Result, StateError};

/// Domain separator for the account-state commitment.
///
/// Versioned in the string. A future scheme (a Merkle root, say) activates at
/// its own height under its own domain, so a digest computed under one scheme
/// can never be mistaken for a digest computed under another.
pub const ACCOUNT_STATE_DIGEST_DOMAIN: &[u8] = b"sumchain/account-state/v1";

/// Account-state commitment activation gate.
///
/// Returns `true` when the block state root at `block_height` folds the account
/// digest. Production-safe default: `params.account_root_enabled_from_height ==
/// None` is closed at every height, so the root formula is byte-for-byte the
/// one an un-upgraded node computes.
///
/// Opening this gate is a CONSENSUS-BREAKING change — it adds a field to the
/// authoritative root — and therefore a coordinated validator upgrade, exactly
/// like `contracts_enabled_from_height`. Mirrors the contracts / compute-pool /
/// beacon gate idiom.
#[inline]
pub fn account_root_gate_open(params: &ChainParams, block_height: u64) -> bool {
    matches!(params.account_root_enabled_from_height, Some(h) if block_height >= h)
}

/// What an activation height must satisfy before any block is executed under it.
///
/// A pure function of [`ChainParams`]: no database, no block, no height. That is
/// deliberate — the failures below are configuration failures, and a
/// configuration failure has to be reachable at startup, where it stops a node
/// from joining, rather than at the activation boundary, where it stops a node
/// that has already been publishing.
///
/// # The two constraints, and why each one
///
/// **Above [`LEGACY_ROOT_COMPATIBILITY_HEIGHT`].** At or below that height
/// `accept_imported` adopts a mismatching header root rather than refusing the
/// block. An activation inside the window would therefore produce exactly the
/// outcome the commitment exists to prevent: an upgraded and an un-upgraded node
/// computing different roots, both publishing the proposer's, and neither able
/// to tell. Pinned by
/// `account_state_root.rs::a_boundary_inside_the_legacy_window_would_be_absorbed_not_detected`.
///
/// **A pinned journal height, at least a full reorg horizon below.** Once the
/// root folds account rows, a reorg has to be able to put those rows back — a
/// branch that unwinds without restoring them leaves a node whose recomputed
/// root disagrees with the chain's, and the chain can then neither revert nor
/// agree. Two parts:
///
/// * `application_journal_enabled_from_height` must be `Some(j)`. `None` means
///   "observed from this node's own chain", which is a NODE-LOCAL boundary —
///   correct for a node-local record, and not a thing a consensus commitment can
///   rest on, because two nodes may legitimately hold different answers.
/// * `j + UNDO_RETENTION_FLOOR <= h`. `UNDO_RETENTION_FLOOR` equals
///   `sumchain_consensus::poa::MAX_REORG_WALK`, so a reorg at the activation
///   height itself can walk that far back. If records begin later than that, the
///   walk reaches blocks the root commits to and the journal cannot restore.
///
/// # Ownership
///
/// The invariant `application_journal_enabled_from_height <=
/// account_root_enabled_from_height` is the journal workstream's, and its
/// authoritative call site is `ChainParams::validate` — which runs on every
/// genesis load, and therefore on every boot. This function is the
/// account-commitment side of the same invariant, in the stricter form the
/// reorg horizon requires, called from [`crate::state::StateManager::init_from_genesis`]
/// so that a chain cannot be INITIALISED on a pair that does not satisfy it.
/// The one runtime activation check, used by BOTH a new chain and a restarted
/// one.
///
/// Two entry points used to enforce different rules. `StateManager::init_from_genesis`
/// called [`validate_account_root_activation`], which owns the two invariants
/// the genesis crate cannot express -- `LEGACY_ROOT_COMPATIBILITY_HEIGHT` lives
/// in `sumchain-storage` and `UNDO_RETENTION_FLOOR` in its pruner, and
/// `sumchain-genesis` depends on neither. `Node::new` called
/// `ChainParams::validate`, which owns the two it can. So a NEW chain checked
/// the legacy window and the reorg horizon, and a RESTARTED chain did not.
///
/// A rule that binds only when a chain is created is not a rule. Both call this.
///
/// Order is deliberate and is asserted by
/// `the_shared_validator_reports_the_ordering_fault_before_the_window_fault`:
/// the structural faults first (is the journal gate pinned at all, does it
/// precede the account gate), then the ones that need chain constants. A node
/// whose pair is wrong in two ways should hear about the simpler one.
pub fn validate_runtime_activation(params: &ChainParams) -> Result<()> {
    params
        .validate()
        .map_err(|e| StateError::ActivationParams(e.to_string()))?;
    validate_account_root_activation(params)
}

pub fn validate_account_root_activation(params: &ChainParams) -> Result<()> {
    let Some(account) = params.account_root_enabled_from_height else {
        // Dormant: the root formula is byte-for-byte the one an un-upgraded node
        // computes, and nothing below is required of the journal.
        return Ok(());
    };

    if account <= LEGACY_ROOT_COMPATIBILITY_HEIGHT {
        return Err(StateError::AccountRootActivationInsideLegacyWindow {
            height: account,
            cutoff: LEGACY_ROOT_COMPATIBILITY_HEIGHT,
        });
    }

    let Some(journal) = params.application_journal_enabled_from_height else {
        return Err(StateError::AccountRootActivationWithoutPinnedJournal { height: account });
    };

    // Saturating, so a journal height above the account height reports the same
    // failure as one too close below it rather than underflowing into success.
    if account.saturating_sub(journal) < UNDO_RETENTION_FLOOR {
        return Err(StateError::AccountRootActivationOutrunsJournal {
            account,
            journal,
            horizon: UNDO_RETENTION_FLOOR,
        });
    }

    Ok(())
}

/// The one account-commitment encoder.
///
/// Both [`v_account_state_digest`] (candidate) and [`account_state_digest`]
/// (committed) feed this and nothing else. A second copy of the record layout
/// would be a consensus divergence waiting to happen: the rows are allowed to
/// differ between the two call sites, the encoding is not.
struct AccountDigest {
    hasher: blake3::Hasher,
    count: u64,
    /// The previous address folded, for the ascending-order check.
    previous: Option<[u8; 20]>,
}

impl AccountDigest {
    fn new() -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ACCOUNT_STATE_DIGEST_DOMAIN);
        Self {
            hasher,
            count: 0,
            previous: None,
        }
    }

    /// Fold one `(key, value)` pair from a scan of the account family.
    ///
    /// Returns `false` for a key that is not an account key, which is the
    /// signal to STOP: both scans start at the `acct` prefix and overrun it
    /// (RocksDB's `prefix_iterator_cf` does not bound itself, and the overlay
    /// reproduces that), and every key carrying the prefix is contiguous in
    /// lexicographic order, so the first key without it is past the family.
    fn fold(&mut self, key: &[u8], value: &[u8]) -> Result<bool> {
        if !key.starts_with(ACCOUNT_KEY_PREFIX) {
            return Ok(false);
        }
        // Prefix but not an account key: the only writer of this prefix is
        // `StateStore::account_key`, which is fixed-width, so this is
        // unreachable today. It is skipped rather than folded, matching
        // `StateStore::iter_all_accounts`, so the digest and the store's own
        // account reader always see the same set.
        let Some(address) = StateStore::address_in_account_key(key) else {
            return Ok(true);
        };
        let address = *address.as_bytes();
        // The ascending-order assumption is checked rather than trusted, in
        // `fold_decoded` below: a fold over a differently-ordered scan is a
        // different digest, and a different digest with no error is a silent
        // chain split.
        //
        // The DECODED balance and nonce, not the stored bytes. The commitment
        // is over what the account IS, so it is immune to a change in the row
        // encoding — and a row this node cannot decode fails the block instead
        // of being folded as opaque bytes.
        let account = decode_account(value)?;
        self.fold_decoded(&address, &account)?;
        Ok(true)
    }

    /// Fold one already-decoded account.
    ///
    /// THE record layout, and the only place it is written. Every caller — the
    /// candidate scan, the committed scan and the snapshot verifier — arrives
    /// here, so a snapshot cannot be checked against a digest computed under a
    /// different encoding than the one consensus uses.
    ///
    /// The ascending-order check lives here rather than in [`Self::fold`]
    /// because it is a property of the FOLD, not of the storage scan: a caller
    /// holding rows in memory has to satisfy it too, and a duplicate address
    /// fails it for the same reason an out-of-order one does.
    fn fold_decoded(&mut self, address: &[u8; 20], account: &AccountState) -> Result<()> {
        if let Some(previous) = self.previous {
            if *address <= previous {
                return Err(StateError::AccountScanOutOfOrder {
                    previous: hex::encode(previous),
                    got: hex::encode(address),
                });
            }
        }
        self.previous = Some(*address);
        self.hasher.update(address);
        self.hasher.update(&account.balance.to_be_bytes());
        self.hasher.update(&account.nonce.to_be_bytes());
        self.count += 1;
        Ok(())
    }

    fn finish(mut self) -> Hash {
        self.hasher.update(&self.count.to_be_bytes());
        Hash::new(*self.hasher.finalize().as_bytes())
    }
}

/// The account-state digest over THIS BLOCK'S CANDIDATE.
///
/// This is the value the block state root folds once the gate is open, so it
/// must see this block's own transition. Reading committed state here would
/// commit the root to the PARENT's account state while publishing the child's
/// rows — every validator would compute a root that disagrees with the state it
/// stores. Mirrors `ComputePoolStore::v_state_digest`.
pub fn v_account_state_digest(view: &ExecutionView<'_, '_>) -> Result<Hash> {
    let mut digest = AccountDigest::new();
    // The merged scan is fallible. A read error must end it, not truncate it: a
    // short account set produces a different digest, and that digest is folded
    // into the block state root.
    for entry in view.prefix_iter(cf::STATE, ACCOUNT_KEY_PREFIX)? {
        let (key, value) = entry?;
        if !digest.fold(&key, &value)? {
            break;
        }
    }
    Ok(digest.finish())
}

/// The stored-row count at which the fold's cost starts being worth watching.
///
/// 250,000 rows is ~40 ms per block, 2.7% of the 1,506 ms interval between
/// blocks. Nothing is wrong at this count; what is wrong is nobody knowing the
/// count is moving. Crossing it means start tracking the trend.
///
/// A constant rather than a line in a runbook, so the number a node warns at and
/// the number the runbook names cannot drift apart.
pub const ACCOUNT_ROW_WARN_THRESHOLD: u64 = 250_000;

/// The stored-row count at which the replacement has to be designed.
///
/// 500,000 rows is ~80 ms per block, 5.3% of the interval — still comfortable,
/// and the last count at which "comfortable" and "we have time to build the
/// replacement" are both true. The replacement is the persistent authenticated
/// trie, whose per-block work is O(touched · log n) rather than O(n).
///
/// Deliberately far below the point where the fold stops fitting in a block
/// (~10M rows, 1.62 s against 1,506 ms): a trie is a storage-layout change with
/// its own reorg, snapshot and activation story, and starting it at the ceiling
/// would be starting it too late.
pub const ACCOUNT_ROW_ACT_THRESHOLD: u64 = 500_000;

/// How many account rows this database STORES.
///
/// Not how many hold value. The commitment folds one record per stored row, and
/// the per-block cost is linear in that count, so the count that matters is the
/// one RocksDB holds — including a row whose balance and nonce are both zero,
/// which is indistinguishable from an absent account by value and entirely
/// distinguishable from one by cost.
///
/// The same scan as [`account_state_digest`], through the same prefix bound and
/// the same stop condition, so the number it reports is exactly the number of
/// records the commitment will fold. A count derived any other way — from an
/// index, from a balance query, from a transaction graph — is a count of
/// something else.
pub fn account_row_count(db: &Database) -> Result<u64> {
    let mut rows = 0u64;
    for entry in db.prefix_iter_checked(cf::STATE, ACCOUNT_KEY_PREFIX)? {
        let (key, _) = entry?;
        if !key.starts_with(ACCOUNT_KEY_PREFIX) {
            break;
        }
        // Skip, not count, a prefixed key that is not an account key — matching
        // `AccountDigest::fold`, so this stays the fold's row count and not an
        // approximation of it.
        if StateStore::address_in_account_key(&key).is_none() {
            continue;
        }
        rows += 1;
    }
    Ok(rows)
}

/// The account-state digest over rows held IN MEMORY.
///
/// The third caller of the one encoder, and the reason the encoder is factored
/// out at all: a snapshot arriving over the network is a list of accounts, not a
/// database, and the only useful thing to check it against is the digest
/// consensus computes. A second transcription of the record layout here would
/// let a snapshot verify against a digest the chain never agreed to.
///
/// Rows must arrive in strictly ascending address order — the same rule the two
/// scans satisfy by construction. A shuffled or duplicated list is an error, not
/// a differently-ordered digest.
pub fn account_state_digest_of<I>(rows: I) -> Result<Hash>
where
    I: IntoIterator<Item = (Address, AccountState)>,
{
    let mut digest = AccountDigest::new();
    for (address, account) in rows {
        digest.fold_decoded(address.as_bytes(), &account)?;
    }
    Ok(digest.finish())
}

/// The account-state digest over COMMITTED state.
///
/// What a node that stored the block recomputes, and what a proposer's
/// candidate digest must equal once its block is published. Not reachable from
/// block execution — it takes a `&Database`, which execution is not given.
pub fn account_state_digest(db: &Database) -> Result<Hash> {
    let mut digest = AccountDigest::new();
    for entry in db.prefix_iter_checked(cf::STATE, ACCOUNT_KEY_PREFIX)? {
        let (key, value) = entry?;
        if !digest.fold(&key, &value)? {
            break;
        }
    }
    Ok(digest.finish())
}

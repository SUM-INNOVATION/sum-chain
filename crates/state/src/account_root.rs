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
//! # Cost, measured — on the production account count and with a cold cache
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
//! ## The production account count is 18
//!
//! Not an estimate. Enumerated by walking the transaction graph out from the
//! two genesis allocations through `sum_getTransactionsByAddress` to closure —
//! 88 transactions, 18 addresses — and cross-checked against the chain's own
//! accounting: those 18 balances sum to 999,998,997,000,000,000, which is
//! `chain_getSupplyInfo.accounted_account_supply` to the base unit. There is no
//! nineteenth account holding value.
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
//! **At the production account count this costs 4.6 microseconds per block —
//! three millionths of the interval between blocks.** The scheme is not
//! marginal here; it is free, by nine orders of magnitude.
//!
//! **The ceiling is real and it is closer than the old note said.** At ten
//! million accounts the coldest scan is 1.62 s against a 1,506 ms interval: it
//! does not fit inside one block at all. Interpolating at 0.16 µs/account, the
//! scan reaches 10% of the interval at about 940,000 accounts and 50% at about
//! 4.7 million. So the practical ceiling is a few million, and the replacement
//! at that point is the persistent authenticated trie rejected above, whose
//! per-block work is O(touched · log n) rather than O(n), activated at its own
//! later height under its own domain separator.
//!
//! **The distance to that ceiling is the whole argument.** 18 accounts in
//! 12.9 million blocks is roughly 0.04 new accounts per day. Reaching one
//! million at that rate takes about 68,000 years; at a thousand times the
//! historical rate it takes 68 years; at a million times, 25 days. Only the last
//! of those is a deployment risk, and it is a risk with a warning signal
//! attached, because the account count is observable and the cost is linear in
//! it.
//!
//! So the trie is not revisited as work to do now. It is revisited as a
//! TRIGGER: the operational threshold is 500,000 accounts, at which this scan
//! costs ~80 ms — 5% of the interval, still comfortable, and roughly a year of
//! warning at any growth rate that reaches it. The gate below and the versioned
//! domain are what make that replacement a coordinated upgrade rather than a
//! rewrite.
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

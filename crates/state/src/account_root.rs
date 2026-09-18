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
//! # Cost, measured
//!
//! O(n) in the number of accounts, PER BLOCK, with O(1) memory: no map is
//! built, no 44·n buffer is materialised, the hasher is fed 44 bytes at a time.
//! That per-block O(n) is the cost of committing to state rather than to a
//! write history, and it is the reason the ceiling below matters.
//!
//! Measured by `the_cost_of_the_account_commitment_at_a_realistic_account_count`
//! in `crates/state/tests/account_state_root.rs` (release build, Apple silicon,
//! warm cache, RocksDB on local SSD):
//!
//! | accounts | scan per block | µs/account | share of a 2 s block |
//! |---------:|---------------:|-----------:|---------------------:|
//! |     100k |          12 ms |      0.123 |                0.6 % |
//! |       1M |         117 ms |      0.117 |                5.9 % |
//! |       5M |         632 ms |      0.126 |               32   % |
//! |      10M |        1.18 s  |      0.118 |               59   % |
//!
//! Flat at ~0.12 µs per account across two orders of magnitude, which is the
//! linear streaming scan the design claims and not an accident of one size.
//!
//! **The honest conclusion: this scheme is practical to a few million accounts
//! and NOT practical past roughly ten million.** At 10M it consumes more than
//! half a 2-second block budget on every node on every block, which is not a
//! cost a chain can carry; the replacement at that point is a persistent
//! authenticated trie whose per-block work is O(touched · log n) rather than
//! O(n), activated at its own later height under its own domain separator. The
//! gate and the versioned domain above are what make that replacement a
//! coordinated upgrade rather than a rewrite.
//!
//! Two limits on the numbers. They are WARM-cache: nothing portable drops the
//! OS page cache, so a node whose account family does not fit in memory will
//! pay disk for this scan and these figures are a lower bound. And they are
//! single-threaded; the fold is order-dependent, so it does not parallelise
//! without changing the construction.

use sumchain_genesis::ChainParams;
use sumchain_primitives::Hash;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::schema::decode_account;
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
        // The ascending-order assumption, checked rather than trusted. A fold
        // over a differently-ordered scan is a different digest, and a
        // different digest with no error is a silent chain split.
        if let Some(previous) = self.previous {
            if address <= previous {
                return Err(StateError::AccountScanOutOfOrder {
                    previous: hex::encode(previous),
                    got: hex::encode(address),
                });
            }
        }
        self.previous = Some(address);

        // The DECODED balance and nonce, not the stored bytes. The commitment
        // is over what the account IS, so it is immune to a change in the row
        // encoding — and a row this node cannot decode fails the block instead
        // of being folded as opaque bytes.
        let account = decode_account(value)?;
        self.hasher.update(&address);
        self.hasher.update(&account.balance.to_be_bytes());
        self.hasher.update(&account.nonce.to_be_bytes());
        self.count += 1;
        Ok(true)
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

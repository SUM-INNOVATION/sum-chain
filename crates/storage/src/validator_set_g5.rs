//! **G5 validator-set transitions (#266): semantics ratified 2026-10-21;
//! dormant; no values; not activated.**
//!
//! This module implements the G5 semantics the owner ratified on 2026-10-21:
//! * Q0, Q1, Q2 and Q4 with N_min = 5;
//! * Q5;
//! * `max_validators` ≤ 29,127;
//! * S1(a) and S2(a).
//!
//! The ratification selects no activation height, stake minimum, epoch length
//! or `max_validators` value, and nothing here does either.
//!
//! **Nothing calls this module.**
//! * No crate outside `sumchain-storage` names it.
//! * No module of this crate refers to it, other than the two dormant
//!   validator-set seams it builds on.
//! * `tests/validator_set_record_dormant.rs` and `tests/validator_set_g5.rs`
//!   fail if that changes.
//!
//! Membership is still the static genesis list (protocol v1, #272). The
//! consensus engine refuses `staking.epoch_length != 0` and stake-weighted
//! selection, and it refuses a database holding a legacy stored epoch set.
//! Nothing here activates dynamic membership.
//!
//! # The ratified rules
//!
//! L is `staking.epoch_length` > 0. A is the activation height, the first
//! height these rules govern (A = 0 is "from genesis"). F = max(A, 1) is the
//! first block executed under them. E_a = ⌊F / L⌋ is the *anchor epoch*.
//!
//! | id | rule | here |
//! |----|------|------|
//! | Q0 | The set in block T's post-state governs T+1 onward; a certificate for height h verifies against `set(h)`. | [`EpochSchedule::governing_epoch`], [`resolve_set`] |
//! | Q1 | Only a block T where (T+1) mod L = 0 writes `row[(T+1)/L]`. Epoch numbers are absolute: epoch(h) = ⌊h/L⌋. Epoch 0 is the genesis list. A missing row is an error, except for the named exceptions below. | [`EpochSchedule::transition_epoch`], [`stage_transition_row`], [`resolve_set`] |
//! | Q2 | A set governs blocks only once its transition block e·L − 1 is certified. | [`EpochSchedule::transition_block`], [`require_transition_certified`] |
//! | Q4 | Eligible: Active, not jailed, self-stake + delegations ≥ `min_validator_stake`. Order by that total descending, then public key ascending; truncate to `max_validators`, which must be ≤ [`EFFECTIVE_VALIDATOR_CAP`] (29,127). A read error fails the block. Below N_min = 5 the previous set carries forward, never the genesis list. | [`select_members`], [`read_candidates`] |
//! | Q5 | Rows in the `STATE` family under `vset/` ‖ epoch (u64 big-endian). A database holding legacy rows resynchronizes from genesis. | [`VsetLayout`], [`check_stored_rows`] |
//!
//! ## Exceptions to the missing-row rule ([`RowlessEpoch`])
//!
//! An epoch e is *rowless* exactly when e ≤ E_a, i.e. its transition block
//! e·L − 1 would precede F. A rowless epoch is governed by the anchor
//! membership: it has no row, needs no certificate, and no block writes it.
//! Every other epoch's row is required, and a missing one is an error, never a
//! fallback. There are exactly three cases, checked in this order:
//!
//! * [`RowlessEpoch::Genesis`] (Q1): epoch 0.
//! * [`RowlessEpoch::GenesisBlockNeverTransitions`] (S1(a)): L = 1 and e = 1.
//!   Its transition block would be block 0, which genesis initialization
//!   creates and nothing executes. So with L = 1, heights 0 and 1 use the
//!   genesis membership and block 1 writes `row[2]`.
//! * [`RowlessEpoch::ActivationAnchor`] (S2(a)): 1 ≤ e ≤ E_a otherwise, so
//!   e·L − 1 < A. Its transition block ran before activation and wrote nothing.
//!   Activation itself writes nothing. The first row is `row[E_a + 1]`, written
//!   by block (E_a + 1)·L − 1, the first boundary at or after F. Q4 computes it
//!   over that block's post-state, with the anchor membership as `previous`.
//!   * If A is one block before a boundary, block A itself is that first
//!     transition.
//!   * If A is on a boundary, the whole epoch A/L is an anchor.
//!   * If A is after a boundary, the anchor covers the rest of its epoch.
//!
//! With A = 0 and L ≥ 2, only [`RowlessEpoch::Genesis`] occurs, and the rules
//! are the ledger's Q0–Q2 as written.
//!
//! ## The anchor membership (assumption)
//!
//! The anchor is the authenticated static membership that precedes
//! activation. Under G2-d (protocol v1) that is the genesis list: the
//! ConsensusConfigV1 field 0x0003 (`validators`, declared order) that the
//! node's ConsensusConfig commitment authenticates (#268). It cannot change
//! before activation, because the engine refuses `staking.epoch_length != 0`
//! and stake-weighted selection.
//!
//! This module does not authenticate the list. The `genesis` argument of
//! [`resolve_set`] and the anchor `previous` of [`select_members`] must be
//! exactly that list. If static membership could ever change before G5
//! activates, this assumption would have to be revisited.
//!
//! ## Derived properties
//!
//! * **Overflow.** Every step that can overflow is checked:
//!   * T + 1 (`checked_add`). T = `u64::MAX` is refused with
//!     [`G5Error::HeightOverflow`], since the height it would govern does not
//!     exist.
//!   * e·L − 1 (`checked_mul`, `checked_sub`), refused with
//!     [`G5Error::EpochOverflow`].
//!
//!   ⌊h/L⌋, (T+1) mod L, ⌊(T+1)/L⌋ and ⌊F/L⌋ cannot overflow, and L = 0 is
//!   unrepresentable ([`EpochSchedule::new`] refuses it). No step saturates or
//!   wraps.
//! * **Certifying a transition block.** Block T = e·L − 1 lies in epoch e − 1
//!   (T < e·L). By Q0 its certificate verifies against the epoch e − 1 set
//!   (the anchor membership if e − 1 is rowless), never against the `row[e]`
//!   it writes. By Q2, `row[e]` governs from e·L only once that preceding set
//!   has certified T.
//! * **Stored rows (Q5).** [`check_stored_rows`] runs before these rules first
//!   govern a database, and at every start after that. It refuses:
//!   * any entry in the pre-#266 `validator_sets` column family, whatever its
//!     key and value, decodable or not ("resynchronize from genesis");
//!   * a `vset/` key that is not 13 bytes;
//!   * a `vset/` row for a rowless epoch.
//!
//!   A static-membership database holds none of these, so it passes with
//!   nothing to migrate:
//!   * the only writer of `validator_sets` is the engine's epoch update, which
//!     returns before writing when L = 0;
//!   * protocol v1 refuses L ≠ 0 at construction;
//!   * nothing writes `vset/` rows while this module is dormant.
//!
//! # Not in this module
//!
//! * **Values.** No `epoch_length`, activation height, stake minimum or
//!   `max_validators` is chosen here; each one is a parameter.
//!   [`EFFECTIVE_VALIDATOR_CAP`] is a ratified upper bound, not a value for
//!   `max_validators`.
//!   N_min is a parameter too. The ratified value, 5, is
//!   `pool_topology::PRODUCT_MINIMUM` in `sumchain-consensus`, which this crate
//!   cannot name, so the wiring passes it.
//! * **Activation, heights and gates.** None.
//! * **Q3-commit.** Rows stay uncommitted application state (#313, D2). Folding
//!   a set digest into the state root is a separate, gated decision.
//! * **Execution reads.** [`read_candidates`] reads committed state through a
//!   [`Database`]. A wired transition must read the block's own
//!   [`crate::exec_view::ExecutionView`] instead; that is part of wiring.
//! * **The engine's legacy-row refusal.** It is unchanged.
//!   [`check_stored_rows`] is its G5 counterpart, applied when this is wired.

use std::cmp::Ordering;

use sumchain_primitives::{Balance, BlockHeight};

use crate::db::{cf, Database};
use crate::exec_view::ExecutionView;
use crate::schema::{DelegationStore, StakingStore};
use crate::validator_set_record::{ValidatorSetRecord, ValidatorSetRecordError};
use crate::validator_set_state::{
    read, stage_insert, Presence, RowSource, StateError, ValidatorSetLayout,
};
use crate::StorageError;

/// The ratified upper bound on `max_validators` (VS-6 option (a),
/// 2026-10-21): the most validators the ConsensusConfigV1 field 0x0003 can
/// encode under its 1 MiB field bound, 4 + 36 · 29,127 = 2^20
/// (`consensus_config::codec::MAX_ENCODABLE_VALIDATORS`, #338). It is below
/// the 65,535 vote/certificate cap. A bound, not a chosen `max_validators`.
pub const EFFECTIVE_VALIDATOR_CAP: usize = 29_127;

/// Q5 layout: `STATE` family, key `vset/` ‖ epoch (u64 big-endian).
///
/// Disjoint from the account rows (`acct` ‖ address), the only range the
/// `STATE` family's readers and the account-root digest scan, because no key
/// beginning `vset/` begins `acct`; [`VsetLayout::row_key`] is checked against
/// that in the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VsetLayout;

impl VsetLayout {
    /// The key prefix shared by every row.
    pub fn prefix() -> &'static [u8] {
        b"vset/"
    }

    /// The row key for `epoch`.
    pub fn row_key(epoch: u64) -> Vec<u8> {
        let mut k = Self::prefix().to_vec();
        k.extend_from_slice(&epoch.to_be_bytes());
        k
    }
}

impl ValidatorSetLayout for VsetLayout {
    fn row_location(&self, key: u64) -> (&'static str, Vec<u8>) {
        (cf::STATE, Self::row_key(key))
    }
}

/// Why a G5 step refused.
#[derive(Debug, thiserror::Error)]
pub enum G5Error {
    #[error("staking.epoch_length is 0: protocol v1 static membership, no transitions")]
    StaticMembership,
    #[error(
        "block {height} is not a transition block for epoch length {epoch_length} (first dynamic \
         block {first_dynamic_block})"
    )]
    NotATransitionBlock {
        height: BlockHeight,
        epoch_length: u64,
        first_dynamic_block: BlockHeight,
    },
    #[error("block {height} has no successor height: T + 1 overflows u64")]
    HeightOverflow { height: BlockHeight },
    #[error("the transition block of epoch {epoch} ({epoch} × {epoch_length} − 1) overflows u64")]
    EpochOverflow { epoch: u64, epoch_length: u64 },
    #[error(
        "the legacy validator_sets column family holds an entry (key {key:02x?}): pre-#266 \
         epoch-set history is neither adopted nor ignored; resynchronize from genesis"
    )]
    LegacyEpochSet { key: Vec<u8> },
    #[error("validator-set row key {key:02x?} is not `vset/` followed by an 8-byte epoch")]
    MalformedRowKey { key: Vec<u8> },
    #[error(
        "a validator-set row is stored for epoch {epoch}, which is rowless ({why:?}); no \
         transition block writes it"
    )]
    RowForRowlessEpoch { epoch: u64, why: RowlessEpoch },
    #[error("scanning stored validator-set rows failed: {0}")]
    Scan(StorageError),
    #[error(
        "the set for height {height} (epoch {epoch}) is written by block {transition}, which is \
         not certified (certified height {certified:?})"
    )]
    TransitionNotCertified {
        height: BlockHeight,
        epoch: u64,
        transition: BlockHeight,
        certified: Option<BlockHeight>,
    },
    #[error("validator-set row: {0}")]
    Row(#[from] StateError),
    #[error("validator-set record: {0}")]
    Record(#[from] ValidatorSetRecordError),
    #[error("reading staking state for the transition failed: {0}")]
    StakingRead(StorageError),
    #[error("the previous set is empty; a carried-forward set must have members")]
    EmptyPrevious,
    #[error("max_validators {configured} is above the effective validator cap {cap}")]
    MaxValidatorsAboveCap { configured: usize, cap: usize },
}

/// Why an epoch has no row: the named exceptions to Q1's missing-row rule. Any
/// epoch that is none of these needs its row, and a missing one is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowlessEpoch {
    /// Q1: epoch 0 is the genesis list.
    Genesis,
    /// S1(a): with L = 1, epoch 1's transition block would be block 0, which
    /// genesis initialization creates and nothing executes.
    GenesisBlockNeverTransitions,
    /// S2(a): an epoch e ≥ 1 whose transition block e·L − 1 ran before
    /// activation (e ≤ E_a), including the epoch containing activation.
    ActivationAnchor,
}

/// When the rules apply: epoch length L > 0 and activation height A.
///
/// Both are the caller's values (a #268 upgrade would select them); the
/// ratification chose neither, and nothing here does. Protocol v1 static membership has no schedule:
/// [`EpochSchedule::new`] refuses L = 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSchedule {
    epoch_length: u64,
    activation: BlockHeight,
}

impl EpochSchedule {
    pub fn new(epoch_length: u64, activation: BlockHeight) -> Result<Self, G5Error> {
        if epoch_length == 0 {
            return Err(G5Error::StaticMembership);
        }
        Ok(Self {
            epoch_length,
            activation,
        })
    }

    pub fn epoch_length(&self) -> u64 {
        self.epoch_length
    }

    pub fn activation(&self) -> BlockHeight {
        self.activation
    }

    /// F = max(A, 1), the first block executed under these rules. Block 0 is
    /// created by genesis initialization and never executed, so it is never a
    /// transition block (S1(a)).
    pub fn first_dynamic_block(&self) -> BlockHeight {
        self.activation.max(1)
    }

    /// E_a = ⌊F / L⌋: it and every earlier epoch are rowless.
    pub fn anchor_epoch(&self) -> u64 {
        self.first_dynamic_block() / self.epoch_length
    }

    /// Which exception, if any, makes `epoch` rowless; `None` means its row is
    /// required.
    pub fn rowless(&self, epoch: u64) -> Option<RowlessEpoch> {
        if epoch == 0 {
            Some(RowlessEpoch::Genesis)
        } else if epoch > self.anchor_epoch() {
            None
        } else if self.epoch_length == 1 && epoch == 1 {
            Some(RowlessEpoch::GenesisBlockNeverTransitions)
        } else {
            Some(RowlessEpoch::ActivationAnchor)
        }
    }

    /// Q0 + Q1: the epoch whose set governs `height`, ⌊height / L⌋.
    pub fn governing_epoch(&self, height: BlockHeight) -> u64 {
        height / self.epoch_length
    }

    /// Q1: the epoch whose row block `height` writes, if it is a transition
    /// block. A block at or after F with (T+1) mod L = 0 writes `row[(T+1)/L]`,
    /// never a rowless epoch's. `None` for every other block, including block
    /// 0 and every block before activation. T = `u64::MAX` is refused.
    pub fn transition_epoch(&self, height: BlockHeight) -> Result<Option<u64>, G5Error> {
        if height < self.first_dynamic_block() {
            return Ok(None);
        }
        let next = height
            .checked_add(1)
            .ok_or(G5Error::HeightOverflow { height })?;
        Ok((next % self.epoch_length == 0).then_some(next / self.epoch_length))
    }

    /// Q2: the block that writes `epoch`'s row, e·L − 1 (the block T with
    /// T+1 = e·L). `None` for a rowless epoch. An unrepresentable e·L − 1 is
    /// refused.
    pub fn transition_block(&self, epoch: u64) -> Result<Option<BlockHeight>, G5Error> {
        if self.rowless(epoch).is_some() {
            return Ok(None);
        }
        epoch
            .checked_mul(self.epoch_length)
            .and_then(|end| end.checked_sub(1))
            .map(Some)
            .ok_or(G5Error::EpochOverflow {
                epoch,
                epoch_length: self.epoch_length,
            })
    }
}

/// Q0 + Q1: the ordered set that validates `height`, read from `rows`
/// (committed state, or a block's own view).
///
/// A rowless epoch ([`RowlessEpoch`]) is governed by `genesis`, which must be
/// the authenticated anchor membership (module docs). For every other epoch
/// the row is required: a missing, corrupt or foreign row is an error, never
/// "fall back to genesis". For a transition block e·L − 1 this is the epoch
/// e − 1 set, the one that certifies it.
pub fn resolve_set<S>(
    rows: &S,
    genesis: &[[u8; 32]],
    height: BlockHeight,
    schedule: &EpochSchedule,
) -> Result<Vec<[u8; 32]>, G5Error>
where
    S: RowSource + ?Sized,
{
    let epoch = schedule.governing_epoch(height);
    if schedule.rowless(epoch).is_some() {
        return Ok(genesis.to_vec());
    }
    let record = read(rows, &VsetLayout, epoch, Presence::Required)?
        .expect("a required read returns a row or an error");
    Ok(record.members().to_vec())
}

/// Q2: the set for `height` may govern only once its transition block is
/// certified (by the preceding set). A rowless epoch needs no transition.
pub fn require_transition_certified(
    height: BlockHeight,
    schedule: &EpochSchedule,
    certified_height: Option<BlockHeight>,
) -> Result<(), G5Error> {
    let epoch = schedule.governing_epoch(height);
    let Some(transition) = schedule.transition_block(epoch)? else {
        return Ok(());
    };
    match certified_height {
        Some(c) if c >= transition => Ok(()),
        certified => Err(G5Error::TransitionNotCertified {
            height,
            epoch,
            transition,
            certified,
        }),
    }
}

/// One staking validator as Q4 sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub pubkey: [u8; 32],
    pub active: bool,
    pub jailed: bool,
    pub self_stake: Balance,
    pub delegated: Balance,
}

impl Candidate {
    fn total(&self) -> Balance {
        self.self_stake.saturating_add(self.delegated)
    }
}

/// The outcome of Q4 for one transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// At least `n_min` eligible validators: the new ordered set.
    Selected(Vec<[u8; 32]>),
    /// Fewer than `n_min` eligible: the previous set, unchanged. Never the
    /// genesis list unless the previous set is the genesis list.
    CarriedForward {
        members: Vec<[u8; 32]>,
        eligible: usize,
    },
}

impl Selection {
    pub fn members(&self) -> &[[u8; 32]] {
        match self {
            Selection::Selected(m) => m,
            Selection::CarriedForward { members, .. } => members,
        }
    }
}

/// Q4: the members of the next set.
///
/// Eligible: active, not jailed, self-stake + delegations ≥ `min_stake`.
/// Ordered by that total descending, then public key ascending (so equal
/// totals have one order on every node), truncated to `max_validators`, which
/// is refused above [`EFFECTIVE_VALIDATOR_CAP`]. Below `n_min` (ratified: 5)
/// eligible validators the `previous` set carries forward unchanged. At the
/// first transition after activation, `previous` is the anchor membership.
pub fn select_members(
    candidates: &[Candidate],
    min_stake: Balance,
    max_validators: usize,
    n_min: usize,
    previous: &[[u8; 32]],
) -> Result<Selection, G5Error> {
    if max_validators > EFFECTIVE_VALIDATOR_CAP {
        return Err(G5Error::MaxValidatorsAboveCap {
            configured: max_validators,
            cap: EFFECTIVE_VALIDATOR_CAP,
        });
    }
    let mut eligible: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| c.active && !c.jailed && c.total() >= min_stake)
        .collect();
    eligible.sort_by(|a, b| match b.total().cmp(&a.total()) {
        Ordering::Equal => a.pubkey.cmp(&b.pubkey),
        other => other,
    });
    eligible.truncate(max_validators);
    if eligible.len() < n_min {
        if previous.is_empty() {
            return Err(G5Error::EmptyPrevious);
        }
        return Ok(Selection::CarriedForward {
            members: previous.to_vec(),
            eligible: eligible.len(),
        });
    }
    let members: Vec<[u8; 32]> = eligible.iter().map(|c| c.pubkey).collect();
    // The row codec applies protocol v1's own set rule (non-empty, no
    // duplicates); a duplicate staking entry is refused rather than counted.
    ValidatorSetRecord::new(0, members.clone())?;
    Ok(Selection::Selected(members))
}

/// Q4 inputs from committed staking state. Any read failure is an error: no
/// delegation total defaults to zero.
pub fn read_candidates(db: &Database) -> Result<Vec<Candidate>, G5Error> {
    let staking = StakingStore::new(db);
    let delegation = DelegationStore::new(db);
    let validators = staking.get_all_validators().map_err(G5Error::StakingRead)?;
    let mut out = Vec::with_capacity(validators.len());
    for v in validators {
        let delegated = delegation
            .get_total_delegated_to_validator(&v.pubkey)
            .map_err(G5Error::StakingRead)?;
        out.push(Candidate {
            pubkey: v.pubkey,
            active: v.status == sumchain_primitives::ValidatorStatus::Active,
            jailed: v.is_jailed(),
            self_stake: v.stake,
            delegated,
        });
    }
    Ok(out)
}

/// Q1 write: stage `members` as the row block `height` writes.
///
/// Refuses a block that is not a transition block (including every block
/// before activation, and block 0), and (through the seam) an occupied row:
/// each epoch's row is written once, by its transition block.
pub fn stage_transition_row(
    view: &mut ExecutionView<'_, '_>,
    height: BlockHeight,
    schedule: &EpochSchedule,
    members: Vec<[u8; 32]>,
) -> Result<u64, G5Error> {
    let epoch = schedule
        .transition_epoch(height)?
        .ok_or(G5Error::NotATransitionBlock {
            height,
            epoch_length: schedule.epoch_length(),
            first_dynamic_block: schedule.first_dynamic_block(),
        })?;
    let record = ValidatorSetRecord::new(epoch, members)?;
    stage_insert(view, &VsetLayout, &record)?;
    Ok(epoch)
}

/// Q5: the stored-row preconditions for running these rules over `db`,
/// checked before they first govern it and at every start after that.
///
/// Refuses any entry at all in the legacy `validator_sets` family (a key-only
/// scan, so an undecodable value refuses too), a `vset/` key that is not
/// `vset/` ‖ 8 bytes, and a row for a rowless epoch. A static-membership
/// database has none of these and passes with nothing to migrate. Read errors
/// are propagated, never read as "no rows".
pub fn check_stored_rows(db: &Database, schedule: &EpochSchedule) -> Result<(), G5Error> {
    let mut legacy = db
        .iter_checked_from(cf::VALIDATOR_SETS, None)
        .map_err(G5Error::Scan)?;
    if let Some(entry) = legacy.next() {
        let (key, _) = entry.map_err(G5Error::Scan)?;
        return Err(G5Error::LegacyEpochSet { key: key.to_vec() });
    }
    let prefix = VsetLayout::prefix();
    for entry in db
        .iter_checked_from(cf::STATE, Some(prefix))
        .map_err(G5Error::Scan)?
    {
        let (key, _) = entry.map_err(G5Error::Scan)?;
        let Some(suffix) = key.strip_prefix(prefix) else {
            break;
        };
        let epoch = <[u8; 8]>::try_from(suffix)
            .map(u64::from_be_bytes)
            .map_err(|_| G5Error::MalformedRowKey { key: key.to_vec() })?;
        if let Some(why) = schedule.rowless(epoch) {
            return Err(G5Error::RowForRowlessEpoch { epoch, why });
        }
    }
    Ok(())
}

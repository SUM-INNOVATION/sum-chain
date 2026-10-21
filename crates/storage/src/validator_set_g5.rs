//! **PROPOSED, NOT RATIFIED — G5 validator-set transitions (#266), DORMANT.**
//!
//! This module implements the *recommendations* recorded in the decision
//! ledger's G5 table (Q0, Q1, Q2, Q4, Q5) so they can be reviewed as code. None
//! of them is ratified. Nothing calls this module: no crate outside
//! `sumchain-storage` names it, no module of this crate other than the two
//! dormant validator-set seams it builds on refers to it, and
//! `tests/validator_set_record_dormant.rs` / `tests/validator_set_g5_proposed.rs`
//! fail if that changes. Membership is still the static genesis list
//! (protocol v1, #272): the consensus engine refuses `staking.epoch_length != 0`
//! and stake-weighted selection, and refuses a database holding a legacy
//! stored epoch set. Nothing here activates dynamic membership.
//!
//! # The proposed rules
//!
//! | id | PROPOSED rule (ledger §G5) | here |
//! |----|-----------------------------|------|
//! | Q0 | The set in block T's post-state governs T+1 onward; a certificate for height h verifies against `set(h)`. | [`EpochSchedule::governing_epoch`], [`resolve_set`] |
//! | Q1 | With L = `staking.epoch_length` > 0, only the block T where (T+1) mod L = 0 writes `row[(T+1)/L]`. Epoch 0 is the genesis list. A missing row for h ≥ L is an error. | [`EpochSchedule::transition_epoch`], [`stage_transition_row`], [`resolve_set`] |
//! | Q2 | A set governs blocks only once its transition block is certified. | [`EpochSchedule::transition_block`], [`require_transition_certified`] |
//! | Q4 | Eligible: Active, not jailed, self-stake + delegations ≥ `min_validator_stake`. Order by that total descending, then public key ascending; truncate to `max_validators`. A read error fails the block. Below N_min the previous set carries forward, never the genesis list. N_min = 5 (PROPOSED; the ratified product minimum). | [`select_members`], [`read_candidates`] |
//! | Q5 | Rows in the `STATE` family under `vset/` ‖ epoch (u64 big-endian). | [`VsetLayout`] |
//!
//! # Boundary rules (PROPOSED; for review before ratification)
//!
//! Notation: A is the activation height (the first height these rules govern;
//! A = 0 is "from genesis"), F = max(A, 1), and E_a = ⌊F / L⌋ is the *anchor
//! epoch*. With A = 0 and L ≥ 2, E_a = 0 and B1–B5 reduce exactly to Q0–Q2 as
//! the ledger records them. B1 and B3 go beyond the ledger and are open
//! sub-questions (below).
//!
//! * **B1, L = 1.** Read literally, Q1 makes the genesis block (T = 0) the
//!   transition block of epoch 1. But block 0 is created by genesis
//!   initialization, not executed, so nothing would write `row[1]`, and no
//!   certificate exists for it. Proposed (G5-S1): block 0 is never a transition
//!   block, and the first transition block is the first *executed* block under
//!   these rules, F. For L = 1 and A = 0, epochs 0 and 1 are therefore anchor
//!   epochs: heights 0 and 1 run on the genesis list, and block 1 writes
//!   `row[2]`.
//! * **B2, arithmetic.** Every step that can overflow is checked:
//!   * T + 1 (`checked_add`). T = `u64::MAX` is refused with
//!     [`G5Error::HeightOverflow`], since the height it would govern doesn't
//!     exist.
//!   * e·L − 1 (`checked_mul`, `checked_sub`), refused with
//!     [`G5Error::EpochOverflow`].
//!
//!   ⌊h/L⌋, (T+1) mod L, ⌊(T+1)/L⌋ and ⌊F/L⌋ cannot overflow, and L = 0 is
//!   unrepresentable ([`EpochSchedule::new`] refuses it). No step saturates or
//!   wraps.
//! * **B3, activation after genesis.** Proposed (G5-S2):
//!   * Epochs keep the genesis-anchored numbering ⌊h/L⌋.
//!   * Every epoch ≤ E_a is governed by the genesis list (the static set in
//!     force when the rules activate). It has no row and needs no certificate.
//!   * Activation writes nothing.
//!   * The first row is `row[E_a + 1]`. It is written by block
//!     (E_a + 1)·L − 1, the first transition block at or after F, by Q4 over
//!     that block's post-state, with the genesis list as `previous`.
//!   * If A falls between boundaries, the genesis list governs the rest of
//!     epoch E_a (1 to L heights from A).
//!   * If A is a boundary, the genesis list governs all of epoch E_a, whose own
//!     transition block, A − 1, ran before activation and wrote nothing.
//!
//!   No activation height or epoch length is chosen here.
//! * **B4, legacy rows.** [`check_stored_rows`] runs before these rules first
//!   govern a database and at every start after that. It refuses:
//!   * any entry in the pre-#266 `validator_sets` column family, whatever its
//!     key and value and whether or not it decodes, with "resynchronize from
//!     genesis" ([`G5Error::LegacyEpochSet`]);
//!   * a `vset/` key that is not 13 bytes ([`G5Error::MalformedRowKey`]);
//!   * a `vset/` row for an epoch ≤ E_a ([`G5Error::RowInAnchorEpoch`]), which
//!     no transition block writes.
//!
//!   A static-membership database holds none of these, so it passes with
//!   nothing to migrate:
//!   * the only writer of `validator_sets` is the engine's epoch update, which
//!     returns before writing when L = 0;
//!   * protocol v1 refuses L ≠ 0 at construction;
//!   * nothing writes `vset/` rows while this module is dormant.
//! * **B5, who certifies a transition block.** Block T = e·L − 1 lies in epoch
//!   e − 1 (T < e·L). By Q0 its certificate verifies against `set(T)`, the
//!   epoch e − 1 set (the genesis list if e − 1 ≤ E_a), never against the
//!   `row[e]` it writes. By Q2, `row[e]` governs from e·L only once that
//!   preceding set has certified T. A set never certifies its own creation.
//!
//! # Open G5 sub-questions (options; nothing here selects one)
//!
//! * **G5-S1: when the boundary is genesis (L = 1), who writes the first
//!   row?**
//!   * (a) *Recommended:* block 0 is never a transition block (B1). There is
//!     no genesis-time write, no certificate for block 0, and one rule for
//!     every L.
//!   * (b) Genesis initialization writes `row[1]` = the genesis list, and block
//!     0 counts as certified by construction. This adds a second row writer and
//!     a certification axiom.
//!   * (c) Refuse L = 1 when the configuration is validated. This is
//!     compatible with (a) and worth weighing when L is chosen: with L = 1
//!     every block is a transition block, so by Q2 no block can be validated
//!     until its parent is certified.
//! * **G5-S2: activation after genesis.**
//!   * (a) *Recommended:* the anchor epoch E_a (B3). Epoch numbers and row keys
//!     are unchanged, and A = 0 is the ledger's rule.
//!   * (b) As (a), but A must also be an epoch boundary. That is only a
//!     restriction on the activation value; (a) already handles it.
//!   * (c) Re-number epochs from A, epoch(h) = ⌊(h − A)/L⌋. Every reader of
//!     an epoch number then depends on A.
//!   * (d) Write the first row at activation (block A, or an upgrade
//!     migration). That is a second writer of rows, outside transition blocks,
//!     with no certified transition block behind it.
//!
//! # What this module deliberately does NOT decide
//!
//! * **Values.** No `epoch_length`, activation height, stake minimum,
//!   `max_validators` or N_min is defined here: every one is a parameter the
//!   caller supplies. N_min = 5 is the ledger's proposal; it is passed in,
//!   not hard-coded.
//! * **Q3-commit.** Rows stay uncommitted application state (#313, D2). Folding
//!   a set digest into the state root is a separate, gated decision.
//! * **Activation, heights and gates.** None.
//! * **The validator cap interaction.** Truncation uses the caller's
//!   `max_validators`. Whether that must also respect the unresolved VS-6
//!   encodable cap (29,127) or the 65,535 vote cap is not decided here.
//! * **Execution reads.** [`read_candidates`] reads committed state through a
//!   [`Database`]; a wired transition must read the block's own
//!   [`crate::exec_view::ExecutionView`] instead. That is part of wiring.
//! * **The legacy-row refusal.** The engine's existing startup refusal of a
//!   stored legacy epoch set is unchanged. [`check_stored_rows`] is the
//!   proposed G5 counterpart (B4), applied when this is wired.

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

/// PROPOSED Q5 layout: `STATE` family, key `vset/` ‖ epoch (u64 big-endian).
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

/// Why a PROPOSED G5 step refused.
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
        "a validator-set row is stored for epoch {epoch}, at or below the anchor epoch {anchor}; \
         no transition block writes it"
    )]
    RowInAnchorEpoch { epoch: u64, anchor: u64 },
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
}

/// When the PROPOSED rules apply: epoch length L > 0 and activation height A.
///
/// Both are the caller's values (a #268 upgrade would select them); none is
/// chosen here. Protocol v1 static membership has no schedule:
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

    /// B1: F = max(A, 1), the first block executed under these rules. Block 0
    /// is created by genesis initialization and never executed, so it is never
    /// a transition block.
    pub fn first_dynamic_block(&self) -> BlockHeight {
        self.activation.max(1)
    }

    /// B3: E_a = ⌊F / L⌋. It and every earlier epoch are governed by the
    /// genesis list; no row is written or read for them.
    pub fn anchor_epoch(&self) -> u64 {
        self.first_dynamic_block() / self.epoch_length
    }

    /// Q0 + Q1: the epoch whose set governs `height`, ⌊height / L⌋.
    pub fn governing_epoch(&self, height: BlockHeight) -> u64 {
        height / self.epoch_length
    }

    /// Q1 + B1 + B2: the epoch whose row block `height` writes, if it is a
    /// transition block: a block at or after F with (T+1) mod L = 0 writes
    /// `row[(T+1)/L]`, always an epoch after E_a. `None` for every other block,
    /// including every block before activation. T = `u64::MAX` is refused.
    pub fn transition_epoch(&self, height: BlockHeight) -> Result<Option<u64>, G5Error> {
        if height < self.first_dynamic_block() {
            return Ok(None);
        }
        let next = height
            .checked_add(1)
            .ok_or(G5Error::HeightOverflow { height })?;
        Ok((next % self.epoch_length == 0).then_some(next / self.epoch_length))
    }

    /// Q2 + B2: the block that writes `epoch`'s row, e·L − 1 (the block T with
    /// T+1 = e·L). `None` for an anchor epoch, which has no row.
    pub fn transition_block(&self, epoch: u64) -> Result<Option<BlockHeight>, G5Error> {
        if epoch <= self.anchor_epoch() {
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

/// Q0 + Q1 + B3: the ordered set that validates `height`, read from `rows`
/// (committed state, or a block's own view).
///
/// An anchor epoch (≤ E_a) is `genesis`. For any later epoch the row is
/// required: a missing, corrupt or foreign row is an error, never "fall back
/// to genesis". B5: for a transition block e·L − 1 this is the epoch e − 1
/// set, the one that certifies it.
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
    if epoch <= schedule.anchor_epoch() {
        return Ok(genesis.to_vec());
    }
    let record = read(rows, &VsetLayout, epoch, Presence::Required)?
        .expect("a required read returns a row or an error");
    Ok(record.members().to_vec())
}

/// Q2 + B5: the set for `height` may govern only once its transition block is
/// certified (by the preceding set). An anchor epoch needs no transition.
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

/// Q4 (PROPOSED): the members of the next set.
///
/// Eligible: active, not jailed, self-stake + delegations ≥ `min_stake`.
/// Ordered by that total descending, then public key ascending (so equal
/// totals have one order on every node), truncated to `max_validators`. Below
/// `n_min` eligible validators the `previous` set carries forward unchanged.
/// At the first transition after activation, `previous` is the genesis list
/// (B3).
pub fn select_members(
    candidates: &[Candidate],
    min_stake: Balance,
    max_validators: usize,
    n_min: usize,
    previous: &[[u8; 32]],
) -> Result<Selection, G5Error> {
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

/// Q1 write (PROPOSED): stage `members` as the row block `height` writes.
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

/// B4 (PROPOSED): the stored-row preconditions for running these rules over
/// `db`, checked before they first govern it and at every start after that.
///
/// Refuses any entry at all in the legacy `validator_sets` family (a key-only
/// scan, so an undecodable value refuses too), a `vset/` key that is not
/// `vset/` ‖ 8 bytes, and a row for an anchor epoch. A static-membership
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
        if epoch <= schedule.anchor_epoch() {
            return Err(G5Error::RowInAnchorEpoch {
                epoch,
                anchor: schedule.anchor_epoch(),
            });
        }
    }
    Ok(())
}

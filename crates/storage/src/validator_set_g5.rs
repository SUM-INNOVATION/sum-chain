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
//! | Q0 | The set in block T's post-state governs T+1 onward; a certificate for height h verifies against `set(h)`. | [`governing_epoch`], [`resolve_set`] |
//! | Q1 | With L = `staking.epoch_length` > 0, only the block T where (T+1) mod L = 0 writes `row[(T+1)/L]`. Epoch 0 is the genesis list. A missing row for h ≥ L is an error. | [`transition_epoch`], [`stage_transition_row`], [`resolve_set`] |
//! | Q2 | A set governs blocks only once its transition block is certified. | [`require_transition_certified`] |
//! | Q4 | Eligible: Active, not jailed, self-stake + delegations ≥ `min_validator_stake`. Order by that total descending, then public key ascending; truncate to `max_validators`. A read error fails the block. Below N_min the previous set carries forward, never the genesis list. N_min = 5 (PROPOSED; the ratified product minimum). | [`select_members`], [`read_candidates`] |
//! | Q5 | Rows in the `STATE` family under `vset/` ‖ epoch (u64 big-endian). | [`VsetLayout`] |
//!
//! # What this module deliberately does NOT decide
//!
//! * **Values.** No `epoch_length`, stake minimum, `max_validators` or N_min is
//!   defined here: every one is a parameter the caller supplies from the
//!   existing staking configuration. N_min = 5 is the ledger's proposal; it is
//!   passed in, not hard-coded.
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
//!   stored legacy epoch set is unchanged; Q5's "resynchronize from genesis"
//!   wording is applied when this is wired, not here.

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
    /// The row key for `epoch`.
    pub fn row_key(epoch: u64) -> Vec<u8> {
        let mut k = b"vset/".to_vec();
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
    #[error("block {height} is not a transition block for epoch length {epoch_length}")]
    NotATransitionBlock {
        height: BlockHeight,
        epoch_length: u64,
    },
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

/// Q1: the epoch whose row block `height` writes, if it is a transition block.
///
/// `None` for every block when `epoch_length` is 0 (protocol v1), and for
/// every block that is not the last of an epoch. Epoch 0 is never written: it
/// is the genesis list.
pub fn transition_epoch(height: BlockHeight, epoch_length: u64) -> Option<u64> {
    if epoch_length == 0 {
        return None;
    }
    let next = height.checked_add(1)?;
    (next % epoch_length == 0).then_some(next / epoch_length)
}

/// Q0 + Q1: the epoch whose set governs `height`. Epoch 0 (the genesis list)
/// governs every height below `epoch_length`, and every height when
/// `epoch_length` is 0.
pub fn governing_epoch(height: BlockHeight, epoch_length: u64) -> u64 {
    if epoch_length == 0 {
        0
    } else {
        height / epoch_length
    }
}

/// Q0 + Q1: the ordered set that validates `height`, read from `rows`
/// (committed state, or a block's own view).
///
/// Epoch 0 is `genesis`. For any later epoch the row is required: a missing,
/// corrupt or foreign row is an error, never "fall back to genesis".
pub fn resolve_set<S>(
    rows: &S,
    genesis: &[[u8; 32]],
    height: BlockHeight,
    epoch_length: u64,
) -> Result<Vec<[u8; 32]>, G5Error>
where
    S: RowSource + ?Sized,
{
    let epoch = governing_epoch(height, epoch_length);
    if epoch == 0 {
        return Ok(genesis.to_vec());
    }
    let record = read(rows, &VsetLayout, epoch, Presence::Required)?
        .expect("a required read returns a row or an error");
    Ok(record.members().to_vec())
}

/// Q2: the set for `height` may govern only once its transition block is
/// certified. Epoch 0 (genesis) needs no transition.
pub fn require_transition_certified(
    height: BlockHeight,
    epoch_length: u64,
    certified_height: Option<BlockHeight>,
) -> Result<(), G5Error> {
    let epoch = governing_epoch(height, epoch_length);
    if epoch == 0 {
        return Ok(());
    }
    // The transition block of epoch e is e·L − 1 (the block T with T+1 = e·L).
    let transition = epoch * epoch_length - 1;
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
/// Refuses a block that is not a transition block, and (through the seam) an
/// occupied row: each epoch's row is written once, by its transition block.
pub fn stage_transition_row(
    view: &mut ExecutionView<'_, '_>,
    height: BlockHeight,
    epoch_length: u64,
    members: Vec<[u8; 32]>,
) -> Result<u64, G5Error> {
    if epoch_length == 0 {
        return Err(G5Error::StaticMembership);
    }
    let epoch = transition_epoch(height, epoch_length).ok_or(G5Error::NotATransitionBlock {
        height,
        epoch_length,
    })?;
    let record = ValidatorSetRecord::new(epoch, members)?;
    stage_insert(view, &VsetLayout, &record)?;
    Ok(epoch)
}

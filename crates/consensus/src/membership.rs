//! The engine's side of the dormant G5 validator-set wiring (#351).
//!
//! [`crate::PoAEngine::new_with_dormant_membership`] is the only constructor
//! that gives the engine a configuration, and no production path calls it
//! (`crates/storage/tests/validator_set_g5.rs` fails if one does).
//! [`crate::PoAEngine::new`] passes none, and then nothing in this module runs.
//!
//! The rules themselves, and why each step below is the one the ratified
//! semantics require, are in `sumchain_storage::validator_set_g5`. With a
//! configuration the engine does the following.
//!
//! * **Anchor.** [`authenticated_anchor`] takes the anchor membership from
//!   field 0x0003 (`validators`) of this database's verified ConsensusConfig
//!   record (#268). It refuses a missing or unreadable record, and a record
//!   whose list differs from the genesis list the engine runs. The assumption
//!   it rests on: static membership does not change before activation.
//! * **Stored rows.** `check_stored_rows` runs before the engine exists, and
//!   [`check_restart`] runs whenever it loads its chain. A refusal names the
//!   resynchronization requirement.
//! * **Header validation and the proposer.** The set for block H is
//!   `governing_set`, read from the rows of H's parent's ancestry. Q2's
//!   certified height is the certified pointer, capped where that ancestry
//!   leaves the canonical chain, so only rows the ancestry shares with the
//!   canonical chain can govern. They are read from committed state for a
//!   block that arrives or is proposed, and from the replacement branch's
//!   layer for a block of a chain switch.
//! * **No membership in memory.** Every use resolves from rows. The legacy
//!   in-memory set the engine keeps for protocol v1 is not read.

use std::sync::Arc;

use sumchain_genesis::pool_topology::PRODUCT_MINIMUM;
use sumchain_primitives::{Balance, Block, BlockHeight};
use sumchain_storage::branch::BranchState;
use sumchain_storage::validator_set_g5::{
    certified_height, check_stored_rows, governing_set, BranchRows, EpochSchedule, G5Error,
};
use sumchain_storage::{BlockStore, Database};

pub use sumchain_storage::validator_set_g5::G5Membership;

use crate::consensus_config::{read_record, Value};
use crate::{ConsensusError, Result};

/// The values a dormant configuration is built from.
///
/// None of them is chosen anywhere in production: an activation height, an
/// epoch length, a stake minimum and `max_validators` all belong to #352. N_min
/// is not a field: the engine passes the ratified value,
/// `pool_topology::PRODUCT_MINIMUM` (5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DormantMembershipRules {
    /// L > 0. Separate from `staking.epoch_length`, which protocol v1 still
    /// requires to be 0.
    pub epoch_length: u64,
    /// A, the first height the rules govern (0 is "from genesis").
    pub activation: BlockHeight,
    /// Q4's `min_validator_stake`.
    pub min_stake: Balance,
    /// Q4's `max_validators`, at most 29,127.
    pub max_validators: usize,
}

fn refused(e: G5Error) -> ConsensusError {
    ConsensusError::Membership(e.to_string())
}

fn resynchronize(e: G5Error) -> ConsensusError {
    ConsensusError::Genesis(format!(
        "this database cannot be proven canonical under the validator-set rules ({e}); \
         resynchronize from genesis"
    ))
}

/// The anchor membership: field 0x0003 of this database's ConsensusConfig
/// record, which `read_record` verifies against its commitment and its whole
/// transition history.
///
/// Refuses a database with no record (a node records one before it builds its
/// engine), an unreadable record, a field that is not a list of 32-byte keys,
/// and a list that differs from `genesis_validators`, the list the engine was
/// built from.
pub fn authenticated_anchor(
    db: &Database,
    genesis_validators: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>> {
    let record = read_record(db)
        .map_err(|e| {
            ConsensusError::Membership(format!(
                "the anchor membership is authenticated by the consensus-configuration record, \
                 which cannot be read: {e}"
            ))
        })?
        .ok_or_else(|| {
            ConsensusError::Membership(
                "the anchor membership is field 0x0003 of the consensus-configuration record, and \
                 this database holds no record; it is recorded at node start, before the engine \
                 is built"
                    .to_string(),
            )
        })?;
    let Some(Value::List(items)) = record.config.get(0x0003) else {
        return Err(ConsensusError::Membership(
            "the consensus-configuration record holds no validator list (field 0x0003)".to_string(),
        ));
    };
    let anchor = items
        .iter()
        .map(|item| <[u8; 32]>::try_from(item.as_slice()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| {
            ConsensusError::Membership(
                "the consensus-configuration record's validator list (field 0x0003) holds an \
                 entry that is not a 32-byte key"
                    .to_string(),
            )
        })?;
    if anchor != genesis_validators {
        return Err(ConsensusError::Membership(format!(
            "the consensus-configuration record's validator list (field 0x0003, {} key(s)) \
             differs from the genesis list this engine runs ({} key(s)); the anchor membership \
             must be the authenticated static membership",
            anchor.len(),
            genesis_validators.len()
        )));
    }
    Ok(anchor)
}

/// The configuration the engine and its executor run under, built from
/// `rules` and the [`authenticated_anchor`], after `check_stored_rows` has
/// accepted the database.
pub(crate) fn build(
    db: &Database,
    genesis_validators: &[[u8; 32]],
    rules: DormantMembershipRules,
) -> Result<Arc<G5Membership>> {
    let anchor = authenticated_anchor(db, genesis_validators)?;
    let schedule = EpochSchedule::new(rules.epoch_length, rules.activation).map_err(refused)?;
    let membership = G5Membership::new(
        schedule,
        PRODUCT_MINIMUM,
        rules.max_validators,
        rules.min_stake,
        anchor,
    )
    .map_err(refused)?;
    check_stored_rows(db, membership.schedule()).map_err(resynchronize)?;
    Ok(Arc::new(membership))
}

/// Restart: the stored-row check, then the set after the canonical head,
/// resolved from committed state. Any failure refuses the start.
pub(crate) fn check_restart(
    db: &Database,
    membership: &G5Membership,
    head_height: BlockHeight,
) -> Result<()> {
    sumchain_storage::validator_set_g5::check_restart(db, membership, head_height)
        .map(|_| ())
        .map_err(resynchronize)
}

/// The set for block `height` whose parent's ancestry leaves the canonical
/// chain at `fork_height` (the parent's own height when the parent is
/// canonical), read from committed state.
///
/// Q2's certified height is capped at `fork_height`, so a set whose transition
/// block is above the fork point does not govern, and every row that does is
/// one the canonical chain and the parent's ancestry share.
pub(crate) fn set_on_canonical_ancestry(
    db: &Database,
    membership: &G5Membership,
    height: BlockHeight,
    fork_height: BlockHeight,
) -> Result<Vec<[u8; 32]>> {
    let certified = certified_height(db)
        .map_err(refused)?
        .map(|c| c.min(fork_height));
    governing_set(db, height, membership, certified).map_err(refused)
}

/// The set for an arriving block, whose parent may be on any branch.
///
/// The fork point is the parent's highest canonical ancestor, found by
/// following parent links for at most `walk_limit` blocks.
pub(crate) fn set_for_arriving_block(
    db: &Database,
    membership: &G5Membership,
    block: &Block,
    parent: Option<&Block>,
    walk_limit: u64,
) -> Result<Vec<[u8; 32]>> {
    let Some(parent) = parent else {
        // Height 0 is governed by the anchor and needs no certificate.
        return set_on_canonical_ancestry(db, membership, block.height(), 0);
    };
    let store = BlockStore::new(db);
    let mut cursor = parent.clone();
    for _ in 0..=walk_limit {
        if store.get_hash_by_height(cursor.height())? == Some(cursor.hash()) {
            return set_on_canonical_ancestry(db, membership, block.height(), cursor.height());
        }
        if cursor.height() == 0 {
            break;
        }
        cursor = store
            .get_by_hash(&cursor.header.parent_hash)?
            .ok_or(ConsensusError::ParentNotFound)?;
    }
    Err(ConsensusError::Membership(format!(
        "block {} at height {}: no canonical ancestor of its parent within {walk_limit} block(s), \
         so the validator set that governs it cannot be resolved",
        block.hash(),
        block.height()
    )))
}

/// The set for block `height` of a replacement branch that forks at
/// `ancestor_height`, read from the branch layer: the block's own parent state.
pub(crate) fn set_on_branch(
    db: &Database,
    layer: &BranchState,
    membership: &G5Membership,
    height: BlockHeight,
    ancestor_height: BlockHeight,
) -> std::result::Result<Vec<[u8; 32]>, G5Error> {
    let certified = certified_height(db)?.map(|c| c.min(ancestor_height));
    governing_set(&BranchRows::new(layer, db), height, membership, certified)
}

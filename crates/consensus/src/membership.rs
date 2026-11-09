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
//!   certified height is the certified pointer as the reorg and rollback
//!   guard reads it (`certified_guard::certified_block`, the one reader of
//!   the certified height), capped where that ancestry leaves the canonical
//!   chain, so only rows the ancestry shares with the canonical chain can
//!   govern. They are read from committed state for a block that arrives or
//!   is proposed, and from the replacement branch's layer for a block of a
//!   chain switch. An arriving block whose parent is on a side branch must
//!   show its proposer and signature under that set before its ancestry is
//!   walked ([`set_for_arriving_block`]).
//! * **No membership in memory.** Every use resolves from rows. The legacy
//!   in-memory set the engine keeps for protocol v1 is not read.

use std::sync::Arc;

use sumchain_crypto::verify_bytes;
use sumchain_genesis::pool_topology::PRODUCT_MINIMUM;
use sumchain_primitives::proposer::round_robin_proposer;
use sumchain_primitives::{Balance, Block, BlockHeight};
use sumchain_storage::branch::BranchState;
use sumchain_storage::certified_guard::{certified_block, CrossingRefusal};
use sumchain_storage::validator_set_g5::{
    check_stored_rows, governing_set, resolve_set, BranchRows, EpochSchedule, G5Error,
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

/// Q2's certified height: the height of the certified block the reorg and
/// rollback guard reads, `certified_guard::certified_block`, so the two never
/// disagree (#351). Fail-closed: an unreadable or undecodable pointer,
/// and certificate rows with no pointer, are `G5Error::CertifiedPointer`, never
/// "nothing certified". Certificates are not re-verified here; that is the
/// start-up audit's (`certified_guard::audit_at_start`).
fn certified_height(db: &Database) -> std::result::Result<Option<BlockHeight>, G5Error> {
    certified_block(db)
        .map(|certified| certified.map(|c| c.height))
        .map_err(|refusal| {
            G5Error::CertifiedPointer(match refusal {
                CrossingRefusal::UnreadablePointer(why) => why,
                CrossingRefusal::CertificatesWithoutPointer { .. } => {
                    "certificate rows exist but the finalized pointer is absent".to_string()
                }
                // A reorg or rollback verdict, which the reader never returns.
                verdict => verdict.to_string(),
            })
        })
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
/// following parent links for at most `walk_limit` blocks. A canonical parent
/// needs no walk. Before walking from a side-branch parent, the block must pass
/// [`authenticate_before_walk`], so a block no validator signed costs one row
/// read and one signature check, never up to `walk_limit` block reads.
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
    let mut authenticated = false;
    for _ in 0..=walk_limit {
        if store.get_hash_by_height(cursor.height())? == Some(cursor.hash()) {
            return set_on_canonical_ancestry(db, membership, block.height(), cursor.height());
        }
        if !authenticated {
            // The parent is on a side branch: the walk below is the expensive
            // part, so the block earns it first.
            authenticate_before_walk(db, membership, block)?;
            authenticated = true;
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

/// What an arriving block whose parent is on a side branch must show before
/// its ancestry is walked: its proposer is the round-robin proposer of its
/// height over the set the canonical rows give that height, and its header is
/// signed by that key.
///
/// If the block can be governed at all, that is exactly the set it is
/// validated against. Q2 caps the certified height at the fork point, so a
/// transition that governs lies on the prefix the branch shares with the
/// canonical chain, and [`set_on_canonical_ancestry`] reads the same committed
/// rows this does. A block refused here is therefore refused by the full path
/// as well, only later.
///
/// * A bad signature is a verdict on the block: `InvalidBlock`.
/// * A proposer that is not the canonical rows' proposer for its height, and a
///   height whose set those rows cannot give (its transition is above the
///   canonical head, or the row is unreadable), are `Membership`, not a
///   verdict: with the canonical chain as it stands nothing can govern the
///   block, which is also what the walk would conclude, by Q2.
fn authenticate_before_walk(db: &Database, membership: &G5Membership, block: &Block) -> Result<()> {
    let header = &block.header;
    let set = resolve_set(
        db,
        membership.anchor(),
        header.height,
        membership.schedule(),
    )
    .map_err(refused)?;
    let expected = round_robin_proposer(header.height, &set).map_err(|e| {
        ConsensusError::Membership(format!("no proposer for height {}: {e}", header.height))
    })?;
    if header.proposer_pubkey != expected {
        return Err(ConsensusError::Membership(format!(
            "block {} at height {}: its proposer is not that height's round-robin proposer under \
             the set the canonical rows give it, the only set that could govern it; refused \
             before walking its side-branch ancestry",
            block.hash(),
            header.height
        )));
    }
    verify_bytes(
        header.signing_hash().as_bytes(),
        &header.proposer_sig,
        &header.proposer_pubkey,
    )
    .map_err(|_| {
        ConsensusError::InvalidBlock(format!(
            "block {} at height {}: invalid proposer signature; refused before walking its \
             side-branch ancestry",
            block.hash(),
            header.height
        ))
    })
}

/// A configuration for this crate's unit tests only: `anchor`, epoch length
/// `epoch_length`, activation 0, N_min the ratified 5, `max_validators` 5,
/// minimum stake 1. Every value is a test fixture.
#[cfg(test)]
pub(crate) fn test_configuration(anchor: Vec<[u8; 32]>, epoch_length: u64) -> Arc<G5Membership> {
    let schedule = EpochSchedule::new(epoch_length, 0).unwrap();
    Arc::new(G5Membership::new(schedule, PRODUCT_MINIMUM, 5, 1, anchor).unwrap())
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

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::{sign, KeyPair};
    use sumchain_primitives::{BlockHeader, Hash};
    use sumchain_storage::cf;
    use tempfile::TempDir;

    const WALK: u64 = 4_096;

    fn key(i: u8) -> KeyPair {
        KeyPair::from_bytes([i; 32])
    }

    fn pk(k: &KeyPair) -> [u8; 32] {
        *k.public_key().as_bytes()
    }

    /// Five anchor validators; with L = 1,000 every height below is in the
    /// rowless genesis epoch, so the set is the anchor.
    fn anchor_keys() -> Vec<KeyPair> {
        (1..=5).map(key).collect()
    }

    fn open() -> (TempDir, Database) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (dir, db)
    }

    /// A block at `height` over `parent_hash`, naming `proposer` and signed by
    /// `signer`.
    fn block(parent_hash: Hash, height: u64, proposer: &KeyPair, signer: &KeyPair) -> Block {
        let mut b = Block::new(
            BlockHeader::new(
                parent_hash,
                height,
                1_000 + height,
                Hash::ZERO,
                Hash::ZERO,
                pk(proposer),
            ),
            Vec::new(),
        );
        let s = sign(b.header.signing_hash().as_bytes(), signer.private_key());
        b.header.set_signature(*s.as_bytes());
        b
    }

    /// Archived, not canonical: no height-index entry names it.
    fn archive(db: &Database, b: &Block) {
        db.put(cf::BLOCKS, b.hash().as_bytes(), &b.to_bytes())
            .unwrap();
    }

    /// F361-2: a side-branch parent whose own parent is missing from the store,
    /// so any walk fails with `ParentNotFound`. A block no validator signed over
    /// it is refused before that walk (an outsider's proposal as membership, a
    /// forged signature as an invalid block); an authenticated one still walks.
    #[test]
    fn a_block_no_validator_signed_is_refused_before_its_side_branch_ancestry_is_walked() {
        let (_dir, db) = open();
        let keys = anchor_keys();
        let m = test_configuration(keys.iter().map(pk).collect(), 1_000);
        let side_parent = block(Hash::hash(b"not stored"), 5, &keys[0], &keys[0]);
        archive(&db, &side_parent);
        let rightful = &keys[6 % 5];
        let outsider = key(0x77);

        // A proposer outside the set, with its own valid signature: nothing
        // can govern it (membership, not a verdict).
        let b = block(side_parent.hash(), 6, &outsider, &outsider);
        let r = set_for_arriving_block(&db, &m, &b, Some(&side_parent), WALK);
        assert!(matches!(r, Err(ConsensusError::Membership(_))), "{r:?}");

        // The rightful proposer's key, signed by someone else.
        let b = block(side_parent.hash(), 6, rightful, &outsider);
        let r = set_for_arriving_block(&db, &m, &b, Some(&side_parent), WALK);
        assert!(matches!(r, Err(ConsensusError::InvalidBlock(_))), "{r:?}");

        // The rightful proposer, rightly signed: the walk runs and finds the
        // missing ancestor, as before.
        let b = block(side_parent.hash(), 6, rightful, rightful);
        let r = set_for_arriving_block(&db, &m, &b, Some(&side_parent), WALK);
        assert!(matches!(r, Err(ConsensusError::ParentNotFound)), "{r:?}");
    }

    /// A canonical parent needs no walk, so nothing is checked early: the set
    /// is returned and header validation refuses a wrong proposer later, as it
    /// always did.
    #[test]
    fn a_canonical_parent_is_resolved_without_the_early_check() {
        let (_dir, db) = open();
        let keys = anchor_keys();
        let m = test_configuration(keys.iter().map(pk).collect(), 1_000);
        let parent = block(Hash::hash(b"not stored"), 5, &keys[0], &keys[0]);
        BlockStore::new(&db).put(&parent).unwrap();
        let outsider = key(0x77);
        let b = block(parent.hash(), 6, &outsider, &outsider);
        let set = set_for_arriving_block(&db, &m, &b, Some(&parent), WALK).unwrap();
        assert_eq!(set, keys.iter().map(pk).collect::<Vec<_>>());
    }

    /// #351: Q2's certified height, at both of its call sites (a block on the
    /// canonical ancestry, a block of a replacement branch), is the height the
    /// reorg and rollback guard read, `certified_guard::certified_block`, in
    /// every state of the pointer, and the refusals read as they did.
    #[test]
    fn both_q2_call_sites_see_the_certified_guard_height_in_every_state() {
        use sumchain_storage::certified_meta::{
            certificate_key, decode_pointer, FINALIZED_POINTER_KEY,
        };

        let (_dir, db) = open();
        // L = 4, activation 0: block 8 is governed by epoch 2, whose transition
        // block 7 is above every certified height below, so Q2 refuses it and
        // names the certified height it was given.
        let m = test_configuration(anchor_keys().iter().map(pk).collect(), 4);
        let layer = BranchState::new(1 << 16);
        let not_certified = |certified| G5Error::TransitionNotCertified {
            height: 8,
            epoch: 2,
            transition: 7,
            certified,
        };
        // Block 8 on an ancestry that leaves the canonical chain at `fork`:
        // the canonical call site's refusal as the engine reports it, and the
        // branch call site's.
        let both = |fork: BlockHeight| -> (String, String) {
            let canonical = set_on_canonical_ancestry(&db, &m, 8, fork).unwrap_err();
            let branch = set_on_branch(&db, &layer, &m, 8, fork).unwrap_err();
            (canonical.to_string(), branch.to_string())
        };
        let expect = |e: G5Error| -> (String, String) {
            let text = e.to_string();
            (refused(e).to_string(), text)
        };

        // Absent: nothing certified.
        assert_eq!(certified_block(&db).unwrap(), None);
        assert_eq!(both(100), expect(not_certified(None)));

        // A certificate row without a pointer: refused, never "nothing
        // certified".
        db.put(cf::META, &certificate_key(4, &Hash::hash(b"b4")), b"cert")
            .unwrap();
        assert_eq!(
            certified_block(&db),
            Err(CrossingRefusal::CertificatesWithoutPointer { height: Some(4) })
        );
        let lost = G5Error::CertifiedPointer(
            "certificate rows exist but the finalized pointer is absent".to_string(),
        );
        assert_eq!(
            lost.to_string(),
            "the certified finalized pointer cannot be read (certificate rows exist but the \
             finalized pointer is absent); refusing rather than guessing which transitions are \
             certified"
        );
        assert_eq!(both(100), expect(lost));

        // Present (height LE ‖ hash, as the certified-commit layout writes
        // it): the pointer's height, capped at the fork point.
        let hash = Hash::hash(b"b5");
        let mut pointer = 5u64.to_le_bytes().to_vec();
        pointer.extend_from_slice(hash.as_bytes());
        assert_eq!(decode_pointer(&pointer).unwrap().height, 5);
        db.put(cf::META, FINALIZED_POINTER_KEY, &pointer).unwrap();
        let guard = certified_block(&db).unwrap().map(|c| (c.height, c.hash));
        assert_eq!(guard, Some((5, hash)));
        assert_eq!(both(6), expect(not_certified(Some(5))));
        assert_eq!(both(5), expect(not_certified(Some(5))));
        assert_eq!(both(3), expect(not_certified(Some(3))));

        // Undecodable: refused with the guard's reason.
        db.put(cf::META, FINALIZED_POINTER_KEY, b"short").unwrap();
        let Err(CrossingRefusal::UnreadablePointer(why)) = certified_block(&db) else {
            panic!("the guard refuses an undecodable pointer");
        };
        assert_eq!(why, "pointer is 5 bytes, not 40");
        let unreadable = G5Error::CertifiedPointer(why);
        assert_eq!(
            unreadable.to_string(),
            "the certified finalized pointer cannot be read (pointer is 5 bytes, not 40); \
             refusing rather than guessing which transitions are certified"
        );
        assert_eq!(both(100), expect(unreadable));
    }
}

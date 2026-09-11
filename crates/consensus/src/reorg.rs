//! Resolving a reorg into a plan, before anything is executed or reverted.
//!
//! A reorg is only safe to perform once three questions have been answered, and
//! all three have to be answered *before* state is touched:
//!
//! 1. Which block do the two branches share? By hash, never by height — two
//!    distinct blocks at one height is the whole reason a reorg exists.
//! 2. Is every block on both branches actually present? A branch with a hole in
//!    it cannot be reverted or replayed, and discovering that halfway through is
//!    discovering it too late.
//! 3. Does the switch reach below finality? A reorg that unwinds a finalized
//!    block is not a reorg, it is a rewrite, and must be refused rather than
//!    performed carefully.
//!
//! [`plan_reorg`] answers all three and returns a [`ReorgPlan`], or an error.
//! It reads; it never writes. A caller that gets a plan back knows the switch is
//! describable — which is a precondition for executing it against an overlay and
//! publishing the result atomically, not a substitute for doing so.
//!
//! # The loop this replaces
//!
//! The previous ancestor walk advanced only when `get_by_hash` returned a block:
//!
//! ```text
//! if let Some(parent) = block_store.get_by_hash(&old_tip_parent)? {
//!     old_chain.push(parent);
//! }
//! ```
//!
//! A missing parent pushed nothing, the tips therefore never changed, and the
//! `while` condition never became false. A node that reorged across a gap in its
//! own block store — a pruned parent, a partially-synced branch — did not fail.
//! It hung, inside consensus, holding the block it was importing.

use sumchain_primitives::{Block, BlockHeight, Hash};
use sumchain_storage::schema::BlockStore;

use crate::{ConsensusError, Result};

/// A resolved, validated description of a chain switch. Read-only: producing one
/// mutates nothing.
#[derive(Debug, Clone)]
pub struct ReorgPlan {
    /// Last block the two branches agree on.
    pub ancestor_hash: Hash,
    pub ancestor_height: BlockHeight,
    /// Blocks to abandon, ordered from just-above-ancestor to the old head.
    /// Empty when the old head *is* the ancestor (a pure extension).
    pub old_branch: Vec<Block>,
    /// Blocks to adopt, ordered from just-above-ancestor to the new head.
    pub new_branch: Vec<Block>,
}

impl ReorgPlan {
    /// How many blocks are abandoned. This is the number that matters for
    /// finality and for operator alarm — not the number adopted.
    pub fn depth(&self) -> u64 {
        self.old_branch.len() as u64
    }

    /// A switch that abandons nothing is an extension of the current chain.
    pub fn is_extension(&self) -> bool {
        self.old_branch.is_empty()
    }
}

/// Walk both branches back to their common ancestor.
///
/// `finalized_height` is the highest block this node considers final;
/// `max_depth` bounds the walk so a malformed or hostile branch cannot make this
/// allocate without limit.
///
/// Refuses, rather than proceeding, when:
/// * a parent named by a header is absent from the store (a gap),
/// * the walk would pass below `finalized_height`,
/// * either branch exceeds `max_depth`,
/// * the two branches share no ancestor at all.
pub fn plan_reorg(
    block_store: &BlockStore,
    old_head: &Block,
    new_head: &Block,
    finalized_height: BlockHeight,
    max_depth: u64,
) -> Result<ReorgPlan> {
    if old_head.hash() == new_head.hash() {
        return Ok(ReorgPlan {
            ancestor_hash: old_head.hash(),
            ancestor_height: old_head.height(),
            old_branch: Vec::new(),
            new_branch: Vec::new(),
        });
    }

    // Tips walk backwards; each vector holds the blocks strictly above the
    // eventual ancestor, nearest-tip first. They are reversed before returning.
    let mut old_walk = vec![old_head.clone()];
    let mut new_walk = vec![new_head.clone()];

    loop {
        let old_tip = old_walk.last().expect("non-empty");
        let new_tip = new_walk.last().expect("non-empty");

        if old_tip.hash() == new_tip.hash() {
            break;
        }

        if old_walk.len() as u64 > max_depth || new_walk.len() as u64 > max_depth {
            return Err(ConsensusError::InvalidBlock(format!(
                "reorg exceeds the maximum depth of {max_depth} blocks \
                 (old branch {}, new branch {}); refusing to plan a switch this deep",
                old_walk.len(),
                new_walk.len()
            )));
        }

        // Step the deeper tip (or both, when level). Stepping only the deeper
        // one keeps the two walks aligned by height, which is what lets the
        // hash comparison above be meaningful.
        let old_h = old_tip.height();
        let new_h = new_tip.height();
        let step_old = old_h >= new_h;
        let step_new = new_h >= old_h;

        if step_old {
            let parent_hash = old_tip.header.parent_hash;
            let height = old_tip.height();
            // Genesis has no parent: reaching it without meeting means the two
            // heads belong to different chains.
            if height == 0 {
                return Err(ConsensusError::InvalidBlock(
                    "reorg walked the current branch to genesis without meeting the \
                     candidate branch: the two heads are not on the same chain"
                        .to_string(),
                ));
            }
            if height.saturating_sub(1) < finalized_height {
                return Err(ConsensusError::InvalidBlock(format!(
                    "reorg would unwind block {height} at or below the finalized \
                     height {finalized_height}; refusing to abandon finalized history"
                )));
            }
            let parent = block_store.get_by_hash(&parent_hash)?.ok_or_else(|| {
                // This is the hang. Report it.
                ConsensusError::InvalidBlock(format!(
                    "reorg cannot proceed: parent {parent_hash} of block {height} on the \
                     current branch is missing from the block store"
                ))
            })?;
            old_walk.push(parent);
        }

        if step_new {
            let parent_hash = new_tip.header.parent_hash;
            let height = new_tip.height();
            if height == 0 {
                return Err(ConsensusError::InvalidBlock(
                    "reorg walked the candidate branch to genesis without meeting the \
                     current branch: the two heads are not on the same chain"
                        .to_string(),
                ));
            }
            if height.saturating_sub(1) < finalized_height {
                return Err(ConsensusError::InvalidBlock(format!(
                    "reorg would adopt a branch forking at block {height}, at or below \
                     the finalized height {finalized_height}; refusing"
                )));
            }
            let parent = block_store.get_by_hash(&parent_hash)?.ok_or_else(|| {
                ConsensusError::InvalidBlock(format!(
                    "reorg cannot proceed: parent {parent_hash} of block {height} on the \
                     candidate branch is missing from the block store"
                ))
            })?;
            new_walk.push(parent);
        }
    }

    let ancestor = old_walk.pop().expect("loop breaks with a shared tip");
    new_walk.pop();

    if ancestor.height() < finalized_height {
        return Err(ConsensusError::InvalidBlock(format!(
            "reorg forks at block {} below the finalized height {finalized_height}",
            ancestor.height()
        )));
    }

    old_walk.reverse();
    new_walk.reverse();

    Ok(ReorgPlan {
        ancestor_hash: ancestor.hash(),
        ancestor_height: ancestor.height(),
        old_branch: old_walk,
        new_branch: new_walk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::BlockHeader;
    use sumchain_storage::db::Database;
    use tempfile::TempDir;

    fn db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    /// A block whose hash is distinguishable from any sibling by `tag`, so two
    /// blocks can share a height and a parent yet differ — which is the entire
    /// situation a reorg exists to handle.
    fn block(parent: Hash, height: BlockHeight, tag: u64) -> Block {
        let header = BlockHeader::new(
            parent,
            height,
            1_000 + tag,
            Hash::hash(&tag.to_be_bytes()),
            Hash::hash(&(tag * 7).to_be_bytes()),
            [0u8; 32],
        );
        Block::new(header, Vec::new())
    }

    /// Genesis plus a linear run, stored. Returns every block, index == height.
    fn chain(store: &BlockStore, len: u64, tag: u64) -> Vec<Block> {
        let mut out = vec![block(Hash::ZERO, 0, 0)];
        store.put(&out[0]).unwrap();
        for h in 1..len {
            let parent = out[(h - 1) as usize].hash();
            let b = block(parent, h, tag * 1000 + h);
            store.put(&b).unwrap();
            out.push(b);
        }
        out
    }

    const NO_FINALITY: BlockHeight = 0;
    const DEEP: u64 = 1024;

    #[test]
    fn a_sibling_at_the_same_height_resolves_to_their_shared_parent() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 3, 1); // 0,1,2

        // A different block at height 2, same parent as main[2].
        let sibling = block(main[1].hash(), 2, 999);
        store.put(&sibling).unwrap();
        assert_ne!(sibling.hash(), main[2].hash(), "must be a real sibling");

        let plan = plan_reorg(&store, &main[2], &sibling, NO_FINALITY, DEEP).unwrap();

        assert_eq!(plan.ancestor_hash, main[1].hash());
        assert_eq!(plan.ancestor_height, 1);
        assert_eq!(plan.depth(), 1);
        assert_eq!(plan.old_branch.len(), 1);
        assert_eq!(plan.old_branch[0].hash(), main[2].hash());
        assert_eq!(plan.new_branch.len(), 1);
        assert_eq!(plan.new_branch[0].hash(), sibling.hash());
    }

    #[test]
    fn branches_of_unequal_length_align_by_height_then_meet_by_hash() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 3, 1); // fork point will be height 1

        // Candidate forks at height 1 and runs two blocks longer.
        let f2 = block(main[1].hash(), 2, 500);
        let f3 = block(f2.hash(), 3, 501);
        let f4 = block(f3.hash(), 4, 502);
        for b in [&f2, &f3, &f4] {
            store.put(b).unwrap();
        }

        let plan = plan_reorg(&store, &main[2], &f4, NO_FINALITY, DEEP).unwrap();

        assert_eq!(plan.ancestor_height, 1);
        assert_eq!(plan.depth(), 1, "one block abandoned");
        let adopted: Vec<u64> = plan.new_branch.iter().map(|b| b.height()).collect();
        assert_eq!(adopted, vec![2, 3, 4], "adopted in ancestor-to-head order");
    }

    #[test]
    fn an_identical_head_is_a_no_op_plan() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 2, 1);
        let plan = plan_reorg(&store, &main[1], &main[1], NO_FINALITY, DEEP).unwrap();
        assert!(plan.is_extension());
        assert_eq!(plan.depth(), 0);
        assert!(plan.new_branch.is_empty());
    }

    /// The regression that matters most: a missing parent must ERROR, not spin.
    ///
    /// The previous walk advanced only when `get_by_hash` returned a block, so a
    /// gap left both tips unchanged and the `while` condition never became
    /// false. This test completes — which is itself the assertion — and the
    /// error names the missing block.
    #[test]
    fn a_gap_in_the_block_store_is_refused_and_does_not_hang() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 3, 1);

        // A candidate whose parent was never stored.
        let orphan_parent = block(main[1].hash(), 2, 77);
        let orphan = block(orphan_parent.hash(), 3, 78);
        store.put(&orphan).unwrap(); // parent deliberately NOT stored

        let err = plan_reorg(&store, &main[2], &orphan, NO_FINALITY, DEEP)
            .expect_err("a gap must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("missing from the block store"),
            "error must name the gap: {msg}"
        );
    }

    #[test]
    fn a_reorg_below_finality_is_refused() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 5, 1);

        let sibling = block(main[1].hash(), 2, 999);
        store.put(&sibling).unwrap();

        // Finalized at 3: unwinding heights 4 and 3 is not permitted.
        let err = plan_reorg(&store, &main[4], &sibling, 3, DEEP)
            .expect_err("must refuse to unwind finalized history");
        let msg = err.to_string();
        assert!(
            msg.contains("finalized"),
            "error must say finality is the reason: {msg}"
        );
    }

    #[test]
    fn a_reorg_above_finality_is_allowed() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 5, 1);
        let sibling = block(main[3].hash(), 4, 999);
        store.put(&sibling).unwrap();

        // Finalized at 3, forking at 3 -> abandons only height 4.
        let plan = plan_reorg(&store, &main[4], &sibling, 3, DEEP).unwrap();
        assert_eq!(plan.ancestor_height, 3);
        assert_eq!(plan.depth(), 1);
    }

    #[test]
    fn an_excessively_deep_reorg_is_refused() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 12, 1);
        let sibling = block(main[1].hash(), 2, 999);
        store.put(&sibling).unwrap();

        let err = plan_reorg(&store, &main[11], &sibling, NO_FINALITY, 4)
            .expect_err("must refuse beyond max_depth");
        assert!(err.to_string().contains("maximum depth"), "{err}");
    }

    #[test]
    fn planning_never_writes() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 3, 1);
        let sibling = block(main[1].hash(), 2, 999);
        store.put(&sibling).unwrap();

        let before = d.iter(sumchain_storage::db::cf::BLOCKS).unwrap().count();
        let _ = plan_reorg(&store, &main[2], &sibling, NO_FINALITY, DEEP).unwrap();
        let after = d.iter(sumchain_storage::db::cf::BLOCKS).unwrap().count();
        assert_eq!(before, after, "planning must be read-only");
    }

    /// Demonstrates that the ORIGINAL walk really did spin, rather than merely
    /// asserting it in a comment.
    ///
    /// This reproduces the old loop verbatim, with an iteration cap standing in
    /// for the missing termination. Running the real thing would hang the suite,
    /// which is the point: the cap is exceeded, so the loop had no exit.
    #[test]
    fn the_original_walk_would_have_spun_on_the_same_gap() {
        let (d, _g) = db();
        let store = BlockStore::new(&d);
        let main = chain(&store, 3, 1);
        let orphan_parent = block(main[1].hash(), 2, 77);
        let orphan = block(orphan_parent.hash(), 3, 78);
        store.put(&orphan).unwrap(); // parent absent, exactly as above

        let mut old_chain = vec![main[2].clone()];
        let mut new_chain = vec![orphan.clone()];

        const CAP: usize = 10_000;
        let mut spins = 0usize;
        while old_chain.last().unwrap().hash() != new_chain.last().unwrap().hash() {
            spins += 1;
            if spins > CAP {
                break;
            }
            let old_tip_height = old_chain.last().unwrap().height();
            let new_tip_height = new_chain.last().unwrap().height();
            let old_tip_parent = old_chain.last().unwrap().header.parent_hash;
            let new_tip_parent = new_chain.last().unwrap().header.parent_hash;

            if old_tip_height >= new_tip_height {
                if let Some(parent) = store.get_by_hash(&old_tip_parent).unwrap() {
                    old_chain.push(parent);
                }
            }
            if new_tip_height >= old_tip_height {
                if let Some(parent) = store.get_by_hash(&new_tip_parent).unwrap() {
                    new_chain.push(parent);
                }
            }
        }

        assert!(
            spins > CAP,
            "the original loop terminated after {spins} iterations; if this ever \
             passes, the hang being fixed here did not exist as described"
        );

        // And the replacement refuses the same input promptly.
        assert!(plan_reorg(&store, &main[2], &orphan, NO_FINALITY, DEEP).is_err());
    }
}

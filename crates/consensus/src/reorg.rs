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
use sumchain_state::executor::BlockExecutor;
use sumchain_state::reorg_undo::{
    stage_branch_unwind, stage_head_reset, BranchJournal, MissingJournalPolicy, UnwindReport,
};
use sumchain_state::state::StateManager;
use sumchain_storage::candidate::{stage_deindex, Acceptance};
use sumchain_storage::journal::{JournalActivation, JournalRequirement};
use sumchain_storage::schema::BlockStore;
use sumchain_storage::Database;

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

/// Plan a switch, and refuse one deeper than the undo history this node
/// actually holds.
///
/// This is the entry point the engine uses. [`plan_reorg`] stays as it was and
/// answers "what would this switch be"; this answers "and may this node perform
/// it", which is a different question with a different input.
///
/// # Why this is not just a smaller `max_depth`
///
/// `max_depth` bounds BOTH walks, and the constraint here is on one of them. A
/// node that can unwind 200 blocks may still legitimately adopt a branch
/// thousands long — catching up after being offline, where the fork point is
/// recent and the adopted branch is not. Passing the usable depth as `max_depth`
/// would refuse that, which is a different and much larger restriction than the
/// one intended. So the walk budget stays at the engine's limit and the
/// ABANDONED branch is checked against the undo history separately.
///
/// # What the undo history has to do with it
///
/// The application journal is node-local: never committed, never folded into a
/// root, never transmitted. A node that arrived by snapshot restore or fast sync
/// therefore holds canonical state and NO undo records, and journals cannot be
/// shipped with a snapshot — a pre-image is not derivable from a post-state. Its
/// usable reorg depth on arrival is ZERO, and it REBUILDS one block at a time as
/// it publishes, because publishing is the only thing that writes a journal.
///
/// `UNDO_RETENTION_FLOOR = 4_096` says nothing about such a node: retention is a
/// promise not to DISCARD undo history, never a claim to HAVE it.
///
/// So a node must never accept a reorg deeper than
/// `JournalActivation::advertisable_reorg_depth`, which is the same number it
/// reports about itself. Refusing here rather than at the unwind means the
/// refusal happens before the plan is acted on, and names the depth rather than
/// the first block whose record is missing.
///
/// `stage_branch_unwind`'s activation checkpoint still refuses the same branch
/// if this is bypassed — the two agree by construction, because a branch deeper
/// than `head - boundary + 1` is exactly a branch reaching below `boundary`.
/// This is the earlier and more legible of the two, not a replacement for it.
pub fn plan_reorg_within_undo_history(
    block_store: &BlockStore,
    old_head: &Block,
    new_head: &Block,
    finalized_height: BlockHeight,
    max_depth: u64,
    activation: &JournalActivation,
) -> Result<ReorgPlan> {
    let plan = plan_reorg(block_store, old_head, new_head, finalized_height, max_depth)?;
    refuse_beyond_undo_history(&plan, activation, old_head.height(), max_depth)?;
    Ok(plan)
}

/// The depth check on its own, so it can be applied to a plan built elsewhere
/// and tested without a fork.
pub fn refuse_beyond_undo_history(
    plan: &ReorgPlan,
    activation: &JournalActivation,
    head_height: BlockHeight,
    engine_max: u64,
) -> Result<()> {
    // Only where the generic journal GOVERNS the head. Below the boundary the
    // chain has not activated over this range at all — the four legacy
    // per-subsystem journals are the undo record, incomplete as they are, and
    // §7.1 of the contract leaves that behaviour alone. Refusing there would
    // refuse every reorg on a chain whose boundary is pinned above its head,
    // which is a far larger claim than this one and not the one being made.
    //
    // This is the same predicate `crosses_activation_checkpoint` uses, stated
    // the other way round: a branch deeper than `head - boundary + 1` under a
    // head at or above `boundary` is exactly a branch reaching below it.
    if activation.requirement_at(head_height) != JournalRequirement::Required {
        return Ok(());
    }
    let usable = activation.advertisable_reorg_depth(head_height, engine_max);
    if plan.depth() > usable {
        return Err(ConsensusError::InvalidBlock(format!(
            "refusing a {}-block switch: this node holds undo history for only {} block(s) \
             below its head at {}. The application journal is node-local — it is never \
             committed, never folded into a state root and never transmitted — so a node \
             restored from a snapshot or fast sync arrives with canonical state and no \
             undo records at all, and rebuilds them only by publishing blocks itself. \
             This node's journal boundary is {:?}; the retention floor is a promise not to \
             discard undo history, never a claim to hold it. Reverting these blocks \
             without their records would leave the rows they wrote applied under a chain \
             that no longer contains them",
            plan.depth(),
            usable,
            head_height,
            activation.boundary(),
        )));
    }
    Ok(())
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

// ─────────────────────────────────────────────────────────────────────────────
// Executing a plan
// ─────────────────────────────────────────────────────────────────────────────

/// What a switch actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReorgOutcome {
    /// Blocks abandoned, records replayed, checks performed.
    pub unwound: UnwindReport,
    /// Blocks adopted.
    pub applied: u64,
    /// Of those, how many were adopted because their header root EQUALLED the
    /// root replay computed.
    pub verified: u64,
    /// Of those, how many were adopted under the historical compatibility
    /// window despite a root mismatch.
    ///
    /// Reported rather than hidden. `LEGACY_ROOT_COMPATIBILITY_HEIGHT` is
    /// 496,720, so below it `accept_imported` force-adopts a mismatching header
    /// root, and a reorg over that range can "succeed" while the state it
    /// replayed disagrees with the branch it adopted. A caller that treats a
    /// force-adopted switch as a verified one is asserting something the chain
    /// never checked; this is the number that makes the difference visible, and
    /// a test that wants to prove the replay reproduced the branch asserts this
    /// is zero.
    pub force_adopted: u64,
}

/// The accumulator a node should be holding for `head`.
///
/// The block state root is a CHAINED accumulator: `compute_block_state_root`
/// mixes the node's current root into every block's, so the in-memory value is
/// part of the execution input and not a derivable summary of stored rows. It
/// does not survive a restart, and it is not restored by unwinding state.
///
/// It is recoverable, exactly, from one place: the head block's own header. A
/// node that has published block H holds H's accumulator, and `H.state_root` is
/// that value — the publisher committed the block and the accumulator together.
/// So this is the whole of accumulator recovery, for a restart and for a reorg
/// alike.
pub fn accumulator_of(head: &Block) -> Hash {
    head.header.state_root
}

/// The head the database records, or `None` before anything is published.
///
/// Read from `META`, which the publisher writes in the SAME batch as the block's
/// state. The head therefore never names a block whose state is partly applied,
/// and that is what makes it a safe recovery point rather than a hint.
pub fn recorded_head(block_store: &BlockStore) -> Result<Option<Block>> {
    let Some(hash) = block_store.get_latest_hash()? else {
        return Ok(None);
    };
    Ok(block_store.get_by_hash(&hash)?)
}

/// Unwind the abandoned branch, then apply the adopted one.
///
/// # Order, and why it is not negotiable
///
/// 1. **Unwind, newest-first, as one atomic batch**, including the head reset to
///    the ancestor. Until this commits the node is on the old branch; after it
///    the node is on the ancestor. There is no interior.
/// 2. **Restore the accumulator** to the ancestor's, from the ancestor's header.
/// 3. **Apply the new branch in order**, through the ordinary publication path —
///    `execute_block`, `accept_imported`, `publish` — one block at a time, each
///    its own atomic batch carrying its own head pointer.
///
/// Applying before unwinding would execute the new branch against the abandoned
/// branch's state, and the roots it computed would be roots of a chain nobody
/// has. Unwinding without restoring the accumulator would leave every adopted
/// block's computed root chained from the wrong value, so `accept_imported`
/// would reject the first of them — loudly, which is the safe direction, but for
/// a reason that has nothing to do with the block.
///
/// # Interruption
///
/// Every write here is a commit of a batch that also carries the head pointer.
/// Interrupt anywhere and the reopened database names a head whose state is
/// fully applied: the old tip, the ancestor, or some prefix of the new branch.
/// [`resume`] takes it from there.
pub fn execute_reorg(
    db: &Database,
    state: &StateManager,
    executor: &BlockExecutor,
    plan: &ReorgPlan,
    validators: &[[u8; 32]],
    journal: &dyn BranchJournal,
    missing: MissingJournalPolicy,
) -> Result<ReorgOutcome> {
    let block_store = BlockStore::new(db);
    let ancestor = block_store
        .get_by_hash(&plan.ancestor_hash)?
        .ok_or_else(|| {
            ConsensusError::InvalidBlock(format!(
                "reorg cannot be executed: the common ancestor {} named by the plan is not \
                 in the block store",
                plan.ancestor_hash
            ))
        })?;

    // ONE batch: the state restore, the journal deletions, the de-indexing and
    // the head reset. A `WriteBatch` has no interior, so an interruption leaves
    // either all of it or none of it, and the head pointer moves with the state
    // it names rather than beside it.
    let unwound = if plan.old_branch.is_empty() {
        UnwindReport::default()
    } else {
        let mut batch = db.batch();
        let report = stage_branch_unwind(db, &mut batch, &plan.old_branch, journal, missing)
            .map_err(|e| ConsensusError::InvalidBlock(format!("reorg unwind refused: {e}")))?;
        // The inverse of publication's index writes, in the SAME batch. Lives in
        // `sumchain-storage` beside `publish`, so a family added to one and not
        // the other is a compile-unit apart rather than a crate apart.
        for abandoned in &plan.old_branch {
            stage_deindex(&mut batch, abandoned)?;
        }
        stage_head_reset(&mut batch, &ancestor)?;
        batch.commit()?;
        report
    };

    // Only after the unwind is durable. Setting it earlier would leave the node
    // holding the ancestor's accumulator over the old branch's state if the
    // commit failed.
    state.set_state_root(accumulator_of(&ancestor));

    let mut outcome = apply_branch(db, state, executor, &plan.new_branch, validators)?;
    outcome.unwound = unwound;
    Ok(outcome)
}

/// Apply `branch` (ancestor-to-head order) through the ordinary publication
/// path, skipping any prefix already published.
///
/// The skip is what makes this a resume rather than a replay: after an
/// interrupted apply the head names some block on the branch, and re-executing
/// it would run it against its own output. A block is "already applied" when the
/// recorded head IS it — not when its rows happen to be present, which is a
/// weaker condition that a partially-written batch could also satisfy, except
/// that no partially-written batch can exist here.
pub fn apply_branch(
    db: &Database,
    state: &StateManager,
    executor: &BlockExecutor,
    branch: &[Block],
    validators: &[[u8; 32]],
) -> Result<ReorgOutcome> {
    let block_store = BlockStore::new(db);
    let head = block_store.get_latest_hash()?;

    // Everything up to and including the recorded head is already published.
    let start = match head {
        Some(h) => match branch.iter().position(|b| b.hash() == h) {
            Some(i) => i + 1,
            None => 0,
        },
        None => 0,
    };

    let mut outcome = ReorgOutcome::default();
    for block in &branch[start..] {
        let execution = executor.execute_block(block, state.state_root(), validators)?;
        let (executed, _account_diff, _contract_diff) = execution.into_parts();
        let accepted = executed.accept_imported(block).map_err(|e| {
            ConsensusError::InvalidBlock(format!(
                "reorg refused block {} at height {}: {e}",
                block.hash(),
                block.height()
            ))
        })?;
        let accumulator = accepted.accumulator();
        match accepted.acceptance() {
            Acceptance::ExactRoot => outcome.verified += 1,
            Acceptance::LegacyCompatibility { .. } => outcome.force_adopted += 1,
            // Unreachable on this path: `accept_imported` never produces it.
            Acceptance::Produced => {}
        }
        accepted.publish()?;
        // After the commit, never before: the accumulator the next block chains
        // from must be one that is durably published.
        state.set_state_root(accumulator);
        outcome.applied += 1;
    }
    Ok(outcome)
}

/// Bring a node that was interrupted mid-reorg to the plan's target.
///
/// Reads the head the database records, restores the accumulator from that
/// block's header, and then does whatever remains:
///
/// * head is the OLD tip — nothing committed. Run the whole switch.
/// * head is the ANCESTOR — the unwind committed, the apply had not started or
///   had not committed its first block. Apply the new branch.
/// * head is a block ON the new branch — apply the rest.
///
/// Those are the only three, because every write in [`execute_reorg`] is a batch
/// carrying its own head pointer. Recovery therefore needs no crash marker and
/// no journal of its own: the head IS the marker, and it is written by the same
/// atomic write as the state it names.
pub fn resume(
    db: &Database,
    state: &StateManager,
    executor: &BlockExecutor,
    plan: &ReorgPlan,
    validators: &[[u8; 32]],
    journal: &dyn BranchJournal,
    missing: MissingJournalPolicy,
) -> Result<ReorgOutcome> {
    let block_store = BlockStore::new(db);
    let head = recorded_head(&block_store)?.ok_or_else(|| {
        ConsensusError::InvalidBlock(
            "cannot resume a reorg on a database with no recorded head".to_string(),
        )
    })?;
    let head_hash = head.hash();

    if plan.new_branch.iter().any(|b| b.hash() == head_hash) || head_hash == plan.ancestor_hash {
        // The unwind is already durable. Restore the accumulator from the head
        // and finish applying.
        state.set_state_root(accumulator_of(&head));
        return apply_branch(db, state, executor, &plan.new_branch, validators);
    }

    // The head is still on the abandoned branch: nothing was committed.
    state.set_state_root(accumulator_of(&head));
    execute_reorg(db, state, executor, plan, validators, journal, missing)
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator rollback
//
// `sum-node rollback` used to walk the tip down with its own loop, reverting
// ACCOUNT rows out of `cf::STATE_DIFFS` and nothing else: it consulted neither
// the contract diff, nor the compute-pool and beacon journals, nor the generic
// application journal, and it never asked where the activation boundary was. On
// a chain past activation that under-reverts — it reports success while leaving
// every row outside `cf::STATE` applied under a chain that no longer contains
// the blocks that wrote them — and it was a third, divergent implementation of
// an unwind the tree already had two correct halves of.
//
// It is now the same unwind the reorg path uses, which means it gets the same
// per-block journal classification, the same missing-record halt, the same
// activation checkpoint and the same single-batch atomicity. It lives here, in
// the planner, rather than in `main.rs`, because a correctness-critical unwind
// that only a binary can reach is one no test can reach either.
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved, validated operator rollback. Producing one mutates nothing.
#[derive(Debug, Clone)]
pub struct RollbackPlan {
    /// The block the chain will be left on.
    pub target: Block,
    /// Blocks to unwind, ANCESTOR-TO-HEAD order, exactly as `ReorgPlan` uses.
    pub abandoned: Vec<Block>,
}

impl RollbackPlan {
    pub fn depth(&self) -> u64 {
        self.abandoned.len() as u64
    }
}

/// Plan a rollback to `to_height`, refusing anything this node cannot reverse.
///
/// Refuses, before anything is written, when:
///
/// * `to_height` is not below the current tip — there is nothing to roll back;
/// * any block in the range is missing from the store, which would make the
///   unwind's own input incomplete;
/// * the range is deeper than the undo history this node holds
///   ([`refuse_beyond_undo_history`]) — the same rule the reorg path applies,
///   for the same reason, and the reason an operator most needs to hear it:
///   rolling back past the point where records exist would leave rows applied
///   under a chain that no longer contains the blocks that wrote them.
///
/// `max_depth` is the operator's own limit, and is checked against the range so
/// a mistyped height is refused rather than executed.
pub fn plan_rollback(
    block_store: &BlockStore,
    to_height: BlockHeight,
    max_depth: u64,
    activation: &JournalActivation,
) -> Result<RollbackPlan> {
    let current = block_store.get_latest_height()?.ok_or_else(|| {
        ConsensusError::InvalidBlock(
            "cannot roll back a database with no recorded height".to_string(),
        )
    })?;
    if to_height >= current {
        return Err(ConsensusError::InvalidBlock(format!(
            "target height {to_height} must be strictly below the current tip {current}"
        )));
    }
    let depth = current - to_height;
    if depth > max_depth {
        return Err(ConsensusError::InvalidBlock(format!(
            "refusing to roll back {depth} block(s): the limit for this invocation is \
             {max_depth}"
        )));
    }

    let target = block_store.get_by_height(to_height)?.ok_or_else(|| {
        ConsensusError::InvalidBlock(format!("no block at target height {to_height}"))
    })?;
    let mut abandoned = Vec::with_capacity(depth as usize);
    for height in to_height + 1..=current {
        let block = block_store.get_by_height(height)?.ok_or_else(|| {
            ConsensusError::InvalidBlock(format!(
                "no block at height {height}; the rollback range has a gap, and unwinding \
                 across one would leave the missing block's rows applied"
            ))
        })?;
        abandoned.push(block);
    }

    let plan = RollbackPlan { target, abandoned };
    // Same predicate, same message, same reason as a reorg: a rollback is a
    // switch whose adopted branch is empty.
    refuse_beyond_undo_history(
        &ReorgPlan {
            ancestor_hash: plan.target.hash(),
            ancestor_height: plan.target.height(),
            old_branch: plan.abandoned.clone(),
            new_branch: Vec::new(),
        },
        activation,
        current,
        max_depth,
    )?;
    Ok(plan)
}

/// Execute a rollback in ONE batch, through the same unwind a reorg uses.
///
/// The batch carries the state restores, every consumed journal's deletion, the
/// de-indexing, the removal of the rolled-back block rows, the head reset and
/// any finality pull-back. A `WriteBatch` has no interior, so an interrupted
/// rollback leaves either the old tip or the target — never a half-rolled-back
/// chain — which is the same argument §6.2 of the journal contract makes about
/// a reorg, and for the same reason: the head IS the marker.
///
/// The block ROWS are deleted, which is what the previous implementation did and
/// what an operator asks for: a rollback is not a fork choice, and leaving the
/// rolled-back blocks retrievable by hash would leave the tool's effect
/// ambiguous. This differs from a reorg, which keeps them so the branch can be
/// re-adopted.
pub fn execute_rollback(
    db: &Database,
    state: &StateManager,
    plan: &RollbackPlan,
    journal: &dyn BranchJournal,
    missing: MissingJournalPolicy,
) -> Result<UnwindReport> {
    let block_store = BlockStore::new(db);
    let mut batch = db.batch();
    let report = stage_branch_unwind(db, &mut batch, &plan.abandoned, journal, missing)
        .map_err(|e| ConsensusError::InvalidBlock(format!("rollback unwind refused: {e}")))?;
    for abandoned in &plan.abandoned {
        stage_deindex(&mut batch, abandoned)?;
        batch.delete(sumchain_storage::cf::BLOCKS, abandoned.hash().as_bytes())?;
    }
    stage_head_reset(&mut batch, &plan.target)?;

    // Finality cannot outlive the tip. Staged into the SAME batch, not applied
    // after it: a crash between the two would leave a node claiming finality for
    // a block it no longer has.
    if let Some(finalized) = block_store.get_finalized_height()? {
        if finalized > plan.target.height() {
            use sumchain_storage::schema::meta_keys;
            batch.put(
                sumchain_storage::cf::META,
                meta_keys::FINALIZED_HEIGHT,
                &plan.target.height().to_be_bytes(),
            )?;
            batch.put(
                sumchain_storage::cf::META,
                meta_keys::FINALIZED_HASH,
                plan.target.hash().as_bytes(),
            )?;
        }
    }

    batch.commit()?;
    // Only after the commit, for the same reason `execute_reorg` waits.
    state.set_state_root(accumulator_of(&plan.target));
    Ok(report)
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

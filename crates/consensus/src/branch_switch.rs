//! Branch-state execution for chain switches (#269).
//!
//! A replacement branch is executed and validated in full against its OWN
//! parent state before anything canonical changes, and is then adopted in one
//! atomic batch. The sequence:
//!
//! 1. **Structural checks.** Depth, cumulative block bytes and transaction
//!    count against [`BranchLimits`]; every block's header, round-robin
//!    proposer, signature, transaction root and size limits through
//!    [`crate::reorg::validate_branch`].
//! 2. **Historical parent.** The fork parent's state is reconstructed as a
//!    [`BranchState`] layer over the committed database from the generic
//!    application journals of the abandoned canonical blocks, newest first,
//!    each record checked against its block identity
//!    ([`ApplicationJournal::decode_for`]) and against the state it unwinds
//!    ([`BranchState::restore_parent`]). A block with no generic journal —
//!    published before the journal existed, or below a snapshot restore —
//!    cannot be reconstructed exactly, and the switch is refused.
//! 3. **Speculative execution.** Each replacement block executes on its own
//!    overlay over that layer (`BlockExecutor::execute_block_on_branch`), its
//!    root chained from its parent's accumulator, and must pass
//!    `accept_imported` — root, receipts, subject — before its net writes are
//!    absorbed into the layer for the next block. Nothing is written.
//! 4. **Adoption.** One batch (`build_adoption_batch`) carries the unwind, the
//!    replacement state, every replacement block's publication and the head.
//!
//! A failure in 1–3 leaves the database byte-for-byte unchanged and the
//! in-memory head, accumulator and mempool untouched.
//!
//! # Two kinds of failure, never confused
//!
//! [`SwitchError::Rejected`] is a verdict on the branch: a block of it is
//! structurally invalid, fails execution, or its root, receipts or subject do
//! not check. [`SwitchError::Local`] is a statement about THIS NODE: its local
//! resource budget was exceeded, or the undo records it needs to reconstruct the
//! fork parent are missing or do not describe its own state. The branch may be
//! perfectly valid, and refusing it as invalid would give a different answer
//! from a node with more memory or intact records — so the engine treats a
//! `Local` failure as a fail-stop, never as a rejection.

use std::sync::Arc;

use sumchain_primitives::{Block, Hash};
use sumchain_state::executor::BlockExecutor;
use sumchain_storage::branch::BranchState;
use sumchain_storage::candidate::{build_adoption_batch, AdoptionReport, SpeculativeBlock};
use sumchain_storage::db::{cf, Database, WriteBatch};
use sumchain_storage::journal::{ApplicationJournal, JournalActivation};
use sumchain_storage::StorageError;

use crate::reorg::{accumulator_of, ReorgPlan};

/// Local resource bounds on one chain switch.
///
/// Consensus-neutral: none of them decides whether a branch is valid. Hitting
/// one is [`SwitchError::Local`], which the engine turns into a fail-stop.
/// The depth bound is not new — the reorg planner already refuses a walk past
/// `MAX_REORG_WALK` or past the undo history this node holds — and is checked
/// again here so the speculative stage never relies on its caller for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BranchLimits {
    /// Most replacement blocks executed speculatively in one switch.
    pub max_depth: u64,
    /// Most serialized bytes across the replacement blocks.
    pub max_block_bytes: u64,
    /// Most transactions across the replacement blocks.
    pub max_transactions: u64,
    /// Most key-plus-value bytes the branch layer may hold: reconstructed
    /// pre-images plus every replacement block's net writes.
    pub max_branch_state_bytes: u64,
    /// Most logical bytes the adoption batch may charge.
    pub max_adoption_bytes: u64,
}

impl BranchLimits {
    /// The production bounds.
    ///
    /// * depth: `MAX_REORG_WALK`, the engine's existing walk limit;
    /// * block bytes: 256 MiB, the per-block write-set ceiling — far above any
    ///   branch the reorg horizon and current block sizes can produce;
    /// * transactions: one million;
    /// * branch state: 1 GiB of held key-plus-value bytes;
    /// * adoption: 2 GiB, room for the branch state plus every block's derived
    ///   records and journals, all in one batch.
    ///
    /// Measured at depths 1, 6 and 64 in `crates/consensus/tests/branch_state_reorg.rs`;
    /// the figures are in the #269 report.
    pub const PRODUCTION: BranchLimits = BranchLimits {
        max_depth: crate::poa::MAX_REORG_WALK,
        max_block_bytes: 256 << 20,
        max_transactions: 1_000_000,
        max_branch_state_bytes: 1 << 30,
        max_adoption_bytes: 2 << 30,
    };
}

/// Why a switch did not happen.
#[derive(Debug, thiserror::Error)]
pub enum SwitchError {
    /// The branch is invalid, or cannot be proven valid from the records this
    /// node holds. Nothing changed.
    #[error("replacement branch rejected: {0}")]
    Rejected(String),
    /// A local condition — resource budget, or this node's own undo records —
    /// stopped the evaluation. Nothing changed, and the branch may be valid: a
    /// fail-stop, not a verdict.
    #[error("this node cannot evaluate the replacement branch: {0}")]
    Local(String),
}

fn local_or_rejected(context: &str, e: StorageError) -> SwitchError {
    match e {
        StorageError::BranchStateLimitExceeded { .. } => {
            SwitchError::Local(format!("{context}: {e}"))
        }
        other => SwitchError::Rejected(format!("{context}: {other}")),
    }
}

/// A replacement branch executed and accepted in full, ready to adopt.
#[derive(Debug)]
pub struct ValidatedBranch {
    layer: BranchState,
    adopted: Vec<SpeculativeBlock>,
    abandoned_journal_rows: Vec<(String, Vec<u8>)>,
}

impl ValidatedBranch {
    /// The accumulator of the replacement branch's tip.
    pub fn tip_accumulator(&self) -> Hash {
        self.adopted
            .last()
            .map(SpeculativeBlock::accumulator)
            .expect("a validated branch has at least one block")
    }

    pub fn adopted(&self) -> &[SpeculativeBlock] {
        &self.adopted
    }

    /// Bytes the branch layer holds.
    pub fn layer_bytes(&self) -> u64 {
        self.layer.bytes()
    }

    /// Pre-image bytes restored from journals.
    pub fn restored_bytes(&self) -> u64 {
        self.layer.restored_bytes()
    }

    /// Keys the layer overrides.
    pub fn layer_keys(&self) -> usize {
        self.layer.len()
    }
}

/// Every journal row an abandoned block owns: the generic application journal
/// and the four legacy per-subsystem journals, all keyed by `(height, hash)`.
fn journal_rows(block: &Block) -> Vec<(String, Vec<u8>)> {
    let key = sumchain_storage::schema::journal_key(block.height(), &block.hash());
    [
        cf::APPLICATION_JOURNAL,
        cf::STATE_DIFFS,
        cf::CONTRACT_STATE_DIFFS,
        cf::COMPUTE_POOL_STATE_DIFFS,
        cf::BEACON_STATE_DIFFS,
    ]
    .into_iter()
    .map(|c| (c.to_string(), key.clone()))
    .collect()
}

/// Stages 1–3: check, reconstruct and execute the replacement branch in full,
/// writing nothing.
pub fn validate_replacement(
    db: &Database,
    executor: &BlockExecutor,
    plan: &ReorgPlan,
    activation: &JournalActivation,
    validators: &[[u8; 32]],
    limits: &BranchLimits,
) -> Result<ValidatedBranch, SwitchError> {
    // ── 1. structural bounds, before anything is allocated for the branch ──
    let depth = plan.new_branch.len() as u64;
    if depth == 0 {
        return Err(SwitchError::Rejected(
            "a replacement branch must contain at least one block".to_string(),
        ));
    }
    if depth > limits.max_depth {
        return Err(SwitchError::Local(format!(
            "replacement branch has {depth} blocks; this node evaluates at most {}",
            limits.max_depth
        )));
    }
    let block_bytes: u64 = plan
        .new_branch
        .iter()
        .map(|b| b.to_bytes().len() as u64)
        .sum();
    if block_bytes > limits.max_block_bytes {
        return Err(SwitchError::Local(format!(
            "replacement branch carries {block_bytes} block bytes; this node evaluates at \
             most {}",
            limits.max_block_bytes
        )));
    }
    let txs: u64 = plan
        .new_branch
        .iter()
        .map(|b| b.transactions.len() as u64)
        .sum();
    if txs > limits.max_transactions {
        return Err(SwitchError::Local(format!(
            "replacement branch carries {txs} transactions; this node evaluates at most {}",
            limits.max_transactions
        )));
    }
    crate::reorg::validate_branch(db, executor, plan, validators)
        .map_err(|e| SwitchError::Rejected(e.to_string()))?;

    // ── 2. the fork parent, reconstructed exactly or not at all ────────────
    let block_store = sumchain_storage::schema::BlockStore::new(db);
    let ancestor = block_store
        .get_by_hash(&plan.ancestor_hash)
        .map_err(|e| SwitchError::Rejected(format!("reading the fork parent: {e}")))?
        .ok_or_else(|| {
            SwitchError::Rejected(format!(
                "the fork parent {} is not in the block store",
                plan.ancestor_hash
            ))
        })?;
    let mut layer = BranchState::new(limits.max_branch_state_bytes);
    for abandoned in plan.old_branch.iter().rev() {
        let journal: ApplicationJournal = activation
            .load_for_revert(db, abandoned.height(), &abandoned.hash())
            .map_err(|e| {
                SwitchError::Local(format!(
                    "the undo record of abandoned block {} at height {} is unusable: {e}",
                    abandoned.hash(),
                    abandoned.height()
                ))
            })?
            .ok_or_else(|| {
                SwitchError::Local(format!(
                    "abandoned block {} at height {} has no generic application journal, so \
                     its parent state cannot be reconstructed exactly; refusing the switch \
                     rather than executing the replacement on the wrong state",
                    abandoned.hash(),
                    abandoned.height()
                ))
            })?;
        layer
            .restore_parent(db, &journal)
            .map_err(|e| SwitchError::Local(format!("reconstructing the fork parent: {e}")))?;
    }

    // ── 3. every replacement block, on its own parent ──────────────────────
    let mut layer = Arc::new(layer);
    let mut accumulator = accumulator_of(&ancestor);
    let mut adopted: Vec<SpeculativeBlock> = Vec::with_capacity(plan.new_branch.len());
    for (index, block) in plan.new_branch.iter().enumerate() {
        #[cfg(feature = "failpoints")]
        if failpoints::hit(failpoints::Failpoint::SpeculativeExecution(index)) {
            return Err(SwitchError::Rejected(format!(
                "injected failure executing replacement block {index}"
            )));
        }
        #[cfg(not(feature = "failpoints"))]
        let _ = index;
        let spec = {
            let execution = executor
                .execute_block_on_branch(block, accumulator, validators, layer.clone())
                .map_err(|e| {
                    SwitchError::Rejected(format!(
                        "replacement block {} at height {} failed execution: {e}",
                        block.hash(),
                        block.height()
                    ))
                })?;
            let (executed, _state_diff, _contract_diff) = execution.into_parts();
            let accepted = executed.accept_imported(block).map_err(|e| {
                SwitchError::Rejected(format!(
                    "replacement block {} at height {} rejected: {e}",
                    block.hash(),
                    block.height()
                ))
            })?;
            accepted.into_speculative().map_err(|e| {
                SwitchError::Rejected(format!(
                    "replacement block {} at height {}: {e}",
                    block.hash(),
                    block.height()
                ))
            })?
        };
        // The candidate and the contract backend have released the layer; the
        // next block reads this block's writes through it.
        let held = Arc::get_mut(&mut layer).ok_or_else(|| {
            SwitchError::Rejected(
                "the branch layer is still referenced after its block finished; refusing to \
                 continue a switch whose isolation cannot be shown"
                    .to_string(),
            )
        })?;
        held.absorb_net_writes(spec.net_writes())
            .map_err(|e| local_or_rejected("absorbing a replacement block", e))?;
        accumulator = spec.accumulator();
        adopted.push(spec);
    }

    let layer = Arc::try_unwrap(layer).map_err(|_| {
        SwitchError::Rejected("the branch layer is still referenced after execution".to_string())
    })?;
    let abandoned_journal_rows = plan.old_branch.iter().flat_map(journal_rows).collect();
    Ok(ValidatedBranch {
        layer,
        adopted,
        abandoned_journal_rows,
    })
}

/// Stage 4: the one batch that adopts a validated branch. Not committed.
pub fn adoption_batch<'db>(
    db: &'db Database,
    plan: &ReorgPlan,
    branch: &ValidatedBranch,
    limits: &BranchLimits,
) -> Result<(WriteBatch<'db>, AdoptionReport), SwitchError> {
    build_adoption_batch(
        db,
        &plan.old_branch,
        &branch.abandoned_journal_rows,
        &branch.layer,
        &branch.adopted,
        limits.max_adoption_bytes,
    )
    .map_err(|e| match e {
        StorageError::OverlayLimitExceeded { .. }
        | StorageError::BranchStateLimitExceeded { .. } => {
            SwitchError::Local(format!("building the adoption batch: {e}"))
        }
        other => SwitchError::Rejected(format!("building the adoption batch: {other}")),
    })
}

/// Deterministic failure injection for the switch path. Compiled only with the
/// `failpoints` feature, which no production build enables.
#[cfg(feature = "failpoints")]
pub mod failpoints {
    use std::cell::Cell;

    /// Where to fail.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Failpoint {
        /// F1: the speculative execution of replacement block `n` (0-based) errors.
        SpeculativeExecution(usize),
        /// F4: a database failure while preparing the adoption, before commit.
        BeforeCommit,
        /// F5: the atomic commit itself fails (nothing is applied).
        CommitFails,
        /// F6: the process "crashes" immediately before the commit.
        CrashBeforeCommit,
        /// F7: the process "crashes" immediately after the commit, before memory.
        CrashAfterCommit,
        /// F8: mempool reconciliation fails after the commit.
        MempoolReconcile,
        /// F9: canonical-event emission fails after the commit.
        EventEmission,
        /// The whole branch validated; the adoption batch is not yet built.
        AfterValidation,
        /// Part-way through post-commit mempool reconciliation.
        MidReconcile,
    }

    impl Failpoint {
        /// Stable name, for selecting a crash barrier from a child process.
        pub fn name(self) -> String {
            match self {
                Failpoint::SpeculativeExecution(n) => format!("speculative-execution-{n}"),
                Failpoint::BeforeCommit => "before-commit".into(),
                Failpoint::CommitFails => "commit-fails".into(),
                Failpoint::CrashBeforeCommit => "crash-before-commit".into(),
                Failpoint::CrashAfterCommit => "crash-after-commit".into(),
                Failpoint::MempoolReconcile => "mempool-reconcile".into(),
                Failpoint::EventEmission => "event-emission".into(),
                Failpoint::AfterValidation => "after-validation".into(),
                Failpoint::MidReconcile => "mid-reconcile".into(),
            }
        }
    }

    thread_local! {
        static BEFORE_HEAD_PIN: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Install (or with `None` remove) a hook run immediately before the
    /// canonical-head pin is checked, on this thread. A test uses it to move the
    /// head from outside the engine, the way a foreign writer would.
    pub fn set_before_head_pin(hook: Option<Box<dyn FnMut()>>) {
        BEFORE_HEAD_PIN.with(|h| *h.borrow_mut() = hook);
    }

    /// Run the hook installed by [`set_before_head_pin`], if any.
    pub fn before_head_pin() {
        BEFORE_HEAD_PIN.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f();
            }
        });
    }

    /// Environment variable naming the crash barrier a child process stops at.
    pub const BARRIER_AT_ENV: &str = "SUMCHAIN_CRASH_BARRIER_AT";
    /// Environment variable naming the file the barrier creates on arrival.
    pub const BARRIER_FILE_ENV: &str = "SUMCHAIN_CRASH_BARRIER_FILE";

    /// A crash barrier for real-process crash tests.
    ///
    /// When this process was started with [`BARRIER_AT_ENV`] naming `fp`, it
    /// announces its arrival by creating [`BARRIER_FILE_ENV`] and then blocks
    /// forever, so the parent test can kill it with SIGKILL at exactly this
    /// point — no unwinding, no destructors, no flush. Inert otherwise.
    pub fn barrier(fp: Failpoint) {
        let Ok(at) = std::env::var(BARRIER_AT_ENV) else {
            return;
        };
        if at != fp.name() {
            return;
        }
        let marker = std::env::var(BARRIER_FILE_ENV)
            .expect("a crash barrier needs SUMCHAIN_CRASH_BARRIER_FILE");
        std::fs::write(&marker, at.as_bytes()).expect("announce the crash barrier");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    thread_local! {
        static ARMED: Cell<Option<Failpoint>> = const { Cell::new(None) };
    }

    /// Arm (or with `None` disarm) one failpoint on this thread.
    pub fn arm(fp: Option<Failpoint>) {
        ARMED.with(|a| a.set(fp));
    }

    /// Whether `fp` is armed on this thread.
    pub fn hit(fp: Failpoint) -> bool {
        ARMED.with(|a| a.get() == Some(fp))
    }
}

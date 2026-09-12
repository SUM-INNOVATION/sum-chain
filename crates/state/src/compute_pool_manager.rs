//! C1 dormant compute-pool MANAGER (issue #130) — the gated coordinator that
//! joins the pure in-memory model to the persistence/revert adapter.
//!
//! This is the next dormant C1 layer *above* the two merged pieces:
//!
//! * [`crate::compute_pool::ComputePoolModel`] — the pure in-memory model that
//!   enforces every C1 invariant validate-before-mutate (#155).
//! * [`crate::compute_pool_store::ComputePoolStore`] — the row codec and
//!   revert-journal adapter (#157).
//!
//! Neither piece, on its own, *drives* the other: the model never persists, and
//! the store's [`ComputePoolStore::stage_transition`] must be handed an explicit
//! `before`/`after` model pair by some coordinator. [`ComputePoolManager`] is that
//! coordinator. It owns the authoritative in-memory model and, for each applied
//! block, updates the model and stages the row delta into that block's candidate
//! in lockstep, then reverts them together on reorg. It composes the two existing
//! pieces the way [`crate::state::StateManager`] composes an account model with a
//! `StateStore` and a `StateDiff` revert journal — no new architecture.
//!
//! Staging, not persisting: the rows go into the block's candidate and the undo
//! journal comes back as an artifact. Nothing here reaches canonical storage —
//! `AcceptedCandidate::publish` does that, after the block's root has been
//! checked.
//!
//! ## Strictly dormant / NON-ACTIVATION
//!
//! * The activation gate [`compute_pool_gate_open`] mirrors the private
//!   `*_gate_open` helpers in [`crate::executor`] one-for-one
//!   (`matches!(params.compute_pool_enabled_from_height, Some(h) if height >= h)`).
//!   The production default is `None`, so the gate is **closed at every height**.
//! * [`ComputePoolManager::new_enabled`] returns `None` while the gate is closed,
//!   so the manager is **never constructed** on a dormant chain: the whole layer
//!   is inert (no model, no store handle, no writes). The gate-off test proves a
//!   closed gate constructs nothing and touches no column family.
//! * This module is **not wired into consensus / PoA block application / the live
//!   `handle_reorg` path**. Nothing calls it during live block execution. Hooking
//!   [`apply_block`](ComputePoolManager::apply_block) /
//!   [`revert_block`](ComputePoolManager::revert_block) into the live driver is a
//!   separate, gated step and is deliberately out of scope here.
//! * It introduces **no** `TxPayload` ordinal, receipt code, activation height, or
//!   economic magnitude. Block transitions are expressed as closures over the
//!   model's already-ratified operations, so no new state-transition semantics are
//!   invented — the manager only *sequences and persists* the ratified ops.
//!
//! ## Per-block revert symmetry
//!
//! Each published block leaves a [`ComputePoolStateDiff`](crate::compute_pool_store::ComputePoolStateDiff)
//! keyed by `(height, block_hash)`, so a rolled-back block restores the exact
//! persisted bytes — and two blocks competing at one height keep separate
//! journals rather than overwriting each other. The manager keeps the
//! model-level analog: a per-height map of the model state *as it was before*
//! that height's transition. A single [`revert_block`](ComputePoolManager::revert_block)
//! therefore rolls back BOTH the persisted rows (via the store journal) and the
//! in-memory model (via the retained pre-state) to precisely the prior state.

use std::collections::BTreeMap;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{BlockHeight, Hash};
use sumchain_storage::candidate::JournalRecord;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::Database;

use crate::compute_pool::{ComputePoolModel, PoolResult};
use crate::compute_pool_store::ComputePoolStore;
use crate::{Result, StateError};

/// Compute-pool subprotocol activation gate. Returns `true` only when the
/// subprotocol is enabled at `block_height`.
///
/// Same dormant-deploy semantics as every other `*_gate_open` helper in
/// [`crate::executor`]: the production default is
/// `compute_pool_enabled_from_height == None`, which is **closed at every
/// height**. Activation would require a coordinated validator upgrade that sets
/// the gate — out of scope for this dormant layer, which must keep it `None`.
#[inline]
pub fn compute_pool_gate_open(params: &ChainParams, block_height: u64) -> bool {
    matches!(params.compute_pool_enabled_from_height, Some(h) if block_height >= h)
}

/// Gated coordinator over the dormant C1 model + persistence adapter.
///
/// Owns the authoritative in-memory [`ComputePoolModel`] and drives the
/// [`ComputePoolStore`] so an applied block updates both in lockstep and reverts
/// cleanly per height. Constructed only via [`ComputePoolManager::new_enabled`],
/// which yields `None` while the gate is closed — so on a dormant chain the type
/// is never instantiated and the layer does nothing.
pub struct ComputePoolManager<'a> {
    db: &'a Database,
    /// Snapshot of the chain params, consulted for the per-height gate check.
    params: ChainParams,
    /// Authoritative in-memory model. Because this manager is the sole writer of
    /// the C1 keyspace, `model` always equals the live persisted state, so it is
    /// the correct `before` snapshot for the next transition.
    model: ComputePoolModel,
    /// Per-height in-memory undo journal: `height -> model state BEFORE the
    /// transition finalized at that height`. The model-level analog of the
    /// store's per-height `ComputePoolStateDiff`; consumed by `revert_block`.
    undo: BTreeMap<BlockHeight, ComputePoolModel>,
}

impl<'a> ComputePoolManager<'a> {
    /// Construct the manager **iff** the compute-pool gate is open at `height`.
    ///
    /// Returns `None` when the gate is closed (the production default, since
    /// `compute_pool_enabled_from_height` is `None`). This is the layer's
    /// dormancy guarantee: a dormant chain never constructs the manager, so it
    /// holds no model, opens no store, and writes nothing.
    ///
    /// The manager starts from an empty model. While dormant, the C1 keyspace is
    /// always empty, so the empty model matches the live persisted state. (Re-
    /// hydrating a *non-empty* persisted keyspace into a model on restart would
    /// need a ratified rows -> model decoder, which is intentionally not built
    /// here — see the crate-level notes on unresolved codec ratification.)
    pub fn new_enabled(
        db: &'a Database,
        params: &ChainParams,
        height: BlockHeight,
    ) -> Option<Self> {
        if compute_pool_gate_open(params, height) {
            Some(Self {
                db,
                params: params.clone(),
                model: ComputePoolModel::new(),
                undo: BTreeMap::new(),
            })
        } else {
            None
        }
    }

    /// The authoritative in-memory model (read-only).
    pub fn model(&self) -> &ComputePoolModel {
        &self.model
    }

    /// A store handle bound to this manager's database, for typed point reads of
    /// the persisted rows (e.g. in tests / future read paths).
    pub fn store(&self) -> ComputePoolStore<'_> {
        ComputePoolStore::new(self.db)
    }

    /// Whether the gate is open at `height` for this manager's params.
    pub fn is_enabled_at(&self, height: BlockHeight) -> bool {
        compute_pool_gate_open(&self.params, height)
    }

    /// Whether an in-memory undo entry is retained for `height` (i.e. a mutating
    /// transition was applied and persisted at that height and not yet reverted).
    pub fn has_pending_undo(&self, height: BlockHeight) -> bool {
        self.undo.contains_key(&height)
    }

    /// Apply one block's worth of compute-pool state transitions at `height`,
    /// updating the in-memory model and staging the row delta into the block's
    /// candidate. Nothing is committed.
    ///
    /// `apply` runs the caller's sequence of ratified model operations
    /// (`create_job`, `publish_offer`, `reserve_capacity`, `accept_leaf`,
    /// `put_assignment`, `register_entitlement`, `transition_unit`, `cancel_job`,
    /// `halt_job`, …) against a working copy of the model. Only if it succeeds is
    /// the transition staged via [`ComputePoolStore::stage_transition`], which
    /// buffers the delta into the candidate and hands back the undo journal for
    /// the caller to bind. The in-memory model is updated only after staging
    /// succeeds; the pre-state is retained as the per-height undo entry.
    ///
    /// Failure isolation:
    /// * gate closed at `height` -> rejected, nothing touched;
    /// * `apply` returns a [`crate::compute_pool::PoolError`] -> mapped to
    ///   [`StateError::InvalidOperation`]; the model, store, and undo journal are
    ///   left byte-for-byte unchanged (the op ran on a throwaway working copy);
    /// * `stage_transition` rejects (a transition already staged for this block,
    ///   or a stale predecessor) -> the error propagates, the in-memory model is
    ///   left unchanged, and the candidate is left byte-identical.
    ///
    /// Returns the number of mutated rows (`0` for a genuine no-op transition,
    /// which produces no journal and records no undo entry) and the undo journal
    /// itself, which the caller binds to the candidate.
    pub fn apply_block<F>(
        &mut self,
        view: &mut ExecutionView<'_, '_>,
        height: BlockHeight,
        apply: F,
    ) -> Result<(usize, JournalRecord)>
    where
        F: FnOnce(&mut ComputePoolModel) -> PoolResult<()>,
    {
        if !compute_pool_gate_open(&self.params, height) {
            return Err(StateError::InvalidOperation(format!(
                "compute-pool subprotocol not enabled at height {height}; \
                 refusing to apply a dormant C1 transition"
            )));
        }

        // Snapshot the authoritative pre-state (== the live persisted state,
        // since this manager is the sole writer), then run the caller's ops on a
        // throwaway working copy so a failing op leaves the model untouched.
        let before = self.model.clone();
        let mut working = before.clone();
        apply(&mut working)
            .map_err(|e| StateError::InvalidOperation(format!("compute-pool transition: {e}")))?;

        // Stage before -> working into the block's candidate. Nothing is
        // committed here: the rows are buffered and the journal comes back as an
        // artifact for the caller to bind, so a block that is rejected or loses
        // fork choice leaves no compute-pool row and no journal behind.
        // `before` is verified equal to the CANDIDATE's live state inside the
        // store, which is what makes a second transition in one block compare
        // against the first one's output.
        let (mutated, journal) = ComputePoolStore::stage_transition(view, Some(&before), &working)?;

        // Commit in-memory only after staging succeeded. Retain the pre-state as
        // the undo entry ONLY when a journal was actually produced, keeping the
        // in-memory undo journal in exact correspondence with the store journals.
        if mutated > 0 {
            self.undo.insert(height, before);
        }
        self.model = working;
        Ok((mutated, journal))
    }

    /// Revert the compute-pool state finalized at `height`, rolling back BOTH the
    /// persisted rows and the in-memory model to the exact prior state.
    ///
    /// Delegates persistence rollback to [`ComputePoolStore::revert_block`] (one
    /// atomic batch that restores `old` values and consumes the journal), then
    /// restores the in-memory model from the retained per-height pre-state. Both
    /// halves are no-ops when nothing was applied at `height`.
    ///
    /// Reverts must be issued tip-first (descending height), matching a real
    /// reorg: the retained pre-state for `height` is the model *before* that
    /// height, so restoring it discards exactly that height's transition.
    pub fn revert_block(&mut self, height: BlockHeight, block_hash: &Hash) -> Result<()> {
        {
            let store = ComputePoolStore::new(self.db);
            store.revert_block(height, block_hash)?;
        }
        if let Some(prev) = self.undo.remove(&height) {
            self.model = prev;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_pool::{
        AcceptedLeaf, AssignmentIndexEntry, BondedOffer, CommitBondId, EntitlementId,
        EntitlementKind, EntitlementRecord, ExposureInputs, JobId, OfferBondId, PoolError, UnitId,
        UnitSizing, UnitState, WorkItemKey, WorkUnit,
    };
    use sumchain_primitives::Address;
    use sumchain_storage::overlay::ApplicationOverlay;
    use sumchain_storage::{cf, Database};
    use tempfile::TempDir;

    fn open_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    /// A stand-in block hash for `height`.
    fn bh(height: BlockHeight) -> Hash {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&height.to_be_bytes());
        Hash::new(b)
    }

    /// Apply one block through the manager into a throwaway candidate.
    ///
    /// Staging only — nothing is committed, which is what the tests that expect
    /// a REJECTION want: they assert the store is untouched, and now it cannot
    /// be touched at all.
    fn apply_only<F>(
        db: &Database,
        mgr: &mut ComputePoolManager<'_>,
        height: BlockHeight,
        ops: F,
    ) -> Result<(usize, JournalRecord)>
    where
        F: FnOnce(&mut ComputePoolModel) -> PoolResult<()>,
    {
        let mut overlay = ApplicationOverlay::new(db, 1 << 30);
        let mut view = ExecutionView::new(&mut overlay);
        mgr.apply_block(&mut view, height, ops)
    }

    /// Apply one block and publish what it staged, standing in for the block
    /// pipeline: the staged rows and the returned journal, committed together
    /// under the publisher's `(height, block_hash)` key.
    ///
    /// TEST FIXTURE. `ApplicationOverlay::into_batch` is crate-private to
    /// `sumchain-storage`, so outside that crate only `AcceptedCandidate::
    /// publish` makes a candidate canonical; these are manager unit tests and
    /// driving a real block through acceptance would couple them to consensus.
    /// The delta is re-derived from the model's own materialization, the same
    /// source `stage_transition` used, so the fixture cannot publish rows the
    /// candidate did not stage.
    fn apply_and_publish<F>(
        db: &Database,
        mgr: &mut ComputePoolManager<'_>,
        height: BlockHeight,
        ops: F,
    ) -> Result<usize>
    where
        F: FnOnce(&mut ComputePoolModel) -> PoolResult<()>,
    {
        let before_rows = ComputePoolStore::materialize(mgr.model())?;
        let (mutated, journal) = apply_only(db, mgr, height, ops)?;
        let after_rows = ComputePoolStore::materialize(mgr.model())?;

        let mut batch = db.batch();
        for (k, v) in &after_rows {
            if before_rows.get(k) != Some(v) {
                batch.put(cf::COMPUTE_POOL_STATE, k, v)?;
            }
        }
        for k in before_rows.keys() {
            if !after_rows.contains_key(k) {
                batch.delete(cf::COMPUTE_POOL_STATE, k)?;
            }
        }
        if let JournalRecord::Recorded(bytes) = &journal {
            batch.put(
                cf::COMPUTE_POOL_STATE_DIFFS,
                &sumchain_storage::schema::journal_key(height, &bh(height)),
                bytes,
            )?;
        }
        batch.commit()?;
        Ok(mutated)
    }

    /// Params with the compute-pool gate CLOSED — the production default. This is
    /// a plain in-memory `ChainParams`; it does NOT flip any committed genesis or
    /// touch the gate definition in `sumchain-genesis`.
    fn dormant_params() -> ChainParams {
        let p = ChainParams::default();
        assert_eq!(
            p.compute_pool_enabled_from_height, None,
            "production default must keep the compute-pool gate dormant"
        );
        p
    }

    /// Params with the gate opened at `h`, used ONLY to exercise the enabled code
    /// path in tests (mirrors how executor tests set `*_enabled_from_height`).
    fn params_enabled_from(h: u64) -> ChainParams {
        ChainParams {
            compute_pool_enabled_from_height: Some(h),
            ..ChainParams::default()
        }
    }

    fn jid(b: u8) -> JobId {
        JobId::from_bytes([b; 32])
    }
    fn uid(b: u8) -> UnitId {
        UnitId::from_bytes([b; 32])
    }
    fn oid(b: u8) -> OfferBondId {
        OfferBondId::from_bytes([b; 32])
    }
    fn addr(b: u8) -> Address {
        Address::new([b; 20])
    }

    fn exposure() -> ExposureInputs {
        ExposureInputs {
            q: 100,
            reprovision_allowance: 10,
            job_max_retention_files: 0, // overwritten in create_job
            max_reassignments_per_file: 2,
            reassign_reimb: 5,
        }
    }

    fn simple_unit(j: JobId, u: UnitId) -> WorkUnit {
        WorkUnit {
            job_id: j,
            unit_id: u,
            predecessors: vec![],
            required_inputs: vec![],
            generation: 0,
            state: UnitState::Blocked,
        }
    }

    fn add_job(m: &mut ComputePoolModel, job: JobId, units: Vec<WorkUnit>) -> PoolResult<()> {
        let sizing: Vec<UnitSizing> = units.iter().map(|_| UnitSizing { slots: 0 }).collect();
        m.create_job(
            job,
            addr(9),
            1,
            units,
            &sizing,
            1,
            0,
            1_000,
            exposure(),
            1_000_000,
        )
        .map(|_| ())
    }

    // ---- gate-off inertness: the whole layer does nothing while dormant ----

    #[test]
    fn gate_off_constructs_nothing_and_writes_nothing() {
        let (db, _d) = open_db();
        let params = dormant_params();

        // The gate helper agrees the subprotocol is closed at every probed height.
        assert!(!compute_pool_gate_open(&params, 0));
        assert!(!compute_pool_gate_open(&params, 1));
        assert!(!compute_pool_gate_open(&params, u64::MAX));

        // The manager is never constructed while the gate is closed.
        assert!(
            ComputePoolManager::new_enabled(&db, &params, 100).is_none(),
            "dormant gate must not construct a manager"
        );

        // And nothing was persisted: both C1 column families are empty.
        let store = ComputePoolStore::new(&db);
        assert!(
            store.load_state_map().unwrap().is_empty(),
            "gate-off path must not write any C1 state rows"
        );
        assert!(
            !store.has_journal(100, &bh(100)).unwrap(),
            "gate-off path must not write any C1 revert journal"
        );
    }

    #[test]
    fn apply_below_the_gate_is_rejected_on_a_constructed_manager() {
        // Even a manager constructed at/above the gate refuses to apply a
        // transition at a height BELOW the activation gate.
        let (db, _d) = open_db();
        let mut mgr = ComputePoolManager::new_enabled(&db, &params_enabled_from(5), 5).unwrap();
        assert!(!mgr.is_enabled_at(4));
        let err = apply_and_publish(&db, &mut mgr, 4, |m| add_job(m, jid(1), vec![simple_unit(jid(1), uid(2))]))
            .unwrap_err();
        assert!(
            matches!(err, StateError::InvalidOperation(_)),
            "got {err:?}"
        );
        assert!(mgr.model().get_job(&jid(1)).is_none());
        assert!(mgr.store().load_state_map().unwrap().is_empty());
    }

    // ---- apply -> persist -> read-back round trip through the store ----

    #[test]
    fn apply_drives_model_and_store_round_trip() {
        let (db, _d) = open_db();
        let mut mgr = ComputePoolManager::new_enabled(&db, &params_enabled_from(5), 5).unwrap();

        let mutated = apply_and_publish(&db, &mut mgr, 5, |m| {
                add_job(m, jid(1), vec![simple_unit(jid(1), uid(2))])?;
                m.publish_offer(BondedOffer {
                    offer_bond_id: oid(3),
                    identity: addr(8),
                    payment_addr: addr(50),
                    offered_bytes: 1_000,
                    offer_seq: 0,
                    bond_locked: 500,
                    active: true,
                })?;
                m.reserve_capacity(oid(3), 1_000, 60)?;
                m.accept_leaf(AcceptedLeaf {
                    key: WorkItemKey::new(jid(1), uid(2), 0),
                    offer_bond_id: oid(3),
                    commit_bond_id: CommitBondId::from_bytes([4; 32]),
                    accepted_bytes: 100,
                })?;
                m.put_assignment(AssignmentIndexEntry {
                    key: WorkItemKey::new(jid(1), uid(2), 0),
                    winner_offer_bond_id: oid(3),
                    winner_payment_addr: addr(50),
                })?;
                m.register_entitlement(EntitlementRecord {
                    entitlement_id: EntitlementId::from_bytes([6; 32]),
                    beneficiary: addr(7),
                    kind: EntitlementKind::AcceptReimb,
                    amount: 50,
                })
            })
            .unwrap();
        assert!(mutated > 0);

        // In-memory model updated.
        assert_eq!(mgr.model().get_job(&jid(1)).unwrap().r_job, 1);

        // Persisted rows equal the model's canonical materialization, and a fresh
        // store reads the records back (round trip through persistence).
        let store = ComputePoolStore::new(&db);
        assert_eq!(
            store.load_state_map().unwrap(),
            ComputePoolStore::materialize(mgr.model()).unwrap()
        );
        assert_eq!(store.get_job(&jid(1)).unwrap().unwrap().r_job, 1);
        assert_eq!(
            store.get_reservation(&oid(3)).unwrap().unwrap().reserved,
            60
        );
        assert_eq!(
            store
                .get_accepted_leaf(&WorkItemKey::new(jid(1), uid(2), 0))
                .unwrap()
                .unwrap()
                .accepted_bytes,
            100
        );
        assert_eq!(store.active_offer_of(&addr(8)).unwrap(), Some(oid(3)));
        assert!(store.has_journal(5, &bh(5)).unwrap());
        assert!(mgr.has_pending_undo(5));
    }

    // ---- per-height revert restores the prior model AND persisted state ----

    #[test]
    fn per_height_revert_restores_prior_state() {
        let (db, _d) = open_db();
        let mut mgr = ComputePoolManager::new_enabled(&db, &params_enabled_from(5), 5).unwrap();

        // Height 5: create job A.
        apply_and_publish(&db, &mut mgr, 5, |m| add_job(m, jid(1), vec![simple_unit(jid(1), uid(2))]))
            .unwrap();
        let model_after_5 = mgr.model().clone();
        let rows_after_5 = mgr.store().load_state_map().unwrap();

        // Height 6: add an offer + a second job on top.
        apply_and_publish(&db, &mut mgr, 6, |m| {
            m.publish_offer(BondedOffer {
                offer_bond_id: oid(3),
                identity: addr(8),
                payment_addr: addr(50),
                offered_bytes: 1_000,
                offer_seq: 0,
                bond_locked: 500,
                active: true,
            })?;
            add_job(m, jid(2), vec![simple_unit(jid(2), uid(9))])
        })
        .unwrap();
        assert_ne!(mgr.model(), &model_after_5, "height 6 changed the model");
        assert!(mgr.store().get_offer(&oid(3)).unwrap().is_some());

        // Revert height 6: both the in-memory model and the persisted rows return
        // to exactly the post-height-5 state.
        mgr.revert_block(6, &bh(6)).unwrap();
        assert_eq!(
            mgr.model(),
            &model_after_5,
            "model restored to post-height-5"
        );
        assert_eq!(
            mgr.store().load_state_map().unwrap(),
            rows_after_5,
            "persisted rows restored to post-height-5"
        );
        assert!(!mgr.store().has_journal(6, &bh(6)).unwrap(), "journal consumed");
        assert!(!mgr.has_pending_undo(6), "undo entry consumed");
        assert!(mgr.store().get_offer(&oid(3)).unwrap().is_none());

        // Height 5's state is untouched and still reverts cleanly afterwards.
        assert!(mgr.model().get_job(&jid(1)).is_some());
        mgr.revert_block(5, &bh(5)).unwrap();
        assert_eq!(mgr.model(), &ComputePoolModel::new(), "back to empty");
        assert!(mgr.store().load_state_map().unwrap().is_empty());
    }

    // ---- a failing op composes through the manager unchanged ----

    #[test]
    fn failed_op_leaves_model_store_and_journal_unchanged() {
        let (db, _d) = open_db();
        let mut mgr = ComputePoolManager::new_enabled(&db, &params_enabled_from(5), 5).unwrap();
        apply_and_publish(&db, &mut mgr, 5, |m| add_job(m, jid(1), vec![simple_unit(jid(1), uid(2))]))
            .unwrap();
        let model_after_5 = mgr.model().clone();
        let rows_after_5 = mgr.store().load_state_map().unwrap();

        // Height 6: attempt a duplicate job — the model op fails (DuplicateJob),
        // so nothing is persisted and nothing in memory changes.
        let err = apply_and_publish(&db, &mut mgr, 6, |m| add_job(m, jid(1), vec![simple_unit(jid(1), uid(7))]))
            .unwrap_err();
        match err {
            StateError::InvalidOperation(msg) => {
                assert!(
                    msg.contains(&PoolError::DuplicateJob.to_string()),
                    "got {msg}"
                )
            }
            other => panic!("expected InvalidOperation, got {other:?}"),
        }
        assert_eq!(
            mgr.model(),
            &model_after_5,
            "model unchanged after failed op"
        );
        assert_eq!(mgr.store().load_state_map().unwrap(), rows_after_5);
        assert!(
            !mgr.store().has_journal(6, &bh(6)).unwrap(),
            "no journal on failed op"
        );
        assert!(!mgr.has_pending_undo(6), "no undo entry on failed op");
    }

    // ---- a genuine no-op transition writes no journal / undo entry ----

    #[test]
    fn noop_transition_records_no_journal_or_undo() {
        let (db, _d) = open_db();
        let mut mgr = ComputePoolManager::new_enabled(&db, &params_enabled_from(5), 5).unwrap();
        apply_and_publish(&db, &mut mgr, 5, |m| add_job(m, jid(1), vec![simple_unit(jid(1), uid(2))]))
            .unwrap();

        // Height 6 applies no mutation => zero mutated rows, no journal, no undo.
        let mutated = apply_and_publish(&db, &mut mgr, 6, |_m| Ok(())).unwrap();
        assert_eq!(mutated, 0);
        assert!(!mgr.store().has_journal(6, &bh(6)).unwrap());
        assert!(!mgr.has_pending_undo(6));
    }
}

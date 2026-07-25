//! BR1 beacon PRODUCER (issue #127) — the gated coordinator that drives the runtime
//! and persists its accepted epoch/round state (Item 1).
//!
//! This is the beacon analog of [`crate::compute_pool_manager::ComputePoolManager`]:
//! it owns the authoritative in-memory runtime working state (a
//! [`sumchain_beacon_runtime::dkg::DkgEpoch`] plus an optional signing
//! [`sumchain_beacon_runtime::rounds::BeaconChain`]) and, for each applied block,
//! drives the ratified runtime transitions and persists the resulting state into the
//! [`crate::beacon_store::BeaconStore`] via `persist_transition` — exactly one
//! atomic journal per block — then reverts them together on reorg.
//!
//! ## Strictly dormant / NON-ACTIVATION
//!
//! * Constructed only via [`BeaconManager::new_enabled`], which returns `None` while
//!   `beacon_enabled_from_height` is `None` (the production default), so on a dormant
//!   chain the type is never instantiated and nothing is written. `gate None` is
//!   byte/state/root-identical.
//! * It introduces no `TxPayload` ordinal, receipt code, activation height, or
//!   economic magnitude. Block transitions are closures over the runtime's already-
//!   built transitions; the manager only *sequences and persists* them.
//! ## Two entry points
//!
//! * [`BeaconManager`] — the standalone lifecycle coordinator (fresh working state +
//!   in-memory undo journal), retained for the isolation lifecycle tests.
//! * [`BeaconBlockState`] — the per-BLOCK accumulator the executor drives across a
//!   block's beacon txs. It **rehydrates** the working state from the store at block
//!   start (rows → runtime, via `DkgEpoch::rehydrate` / `BeaconChain::rehydrate`), so
//!   restart + cross-block persistence work: a block's persisted transition is a delta
//!   against the true prior state, `materialize(rehydrate(rows)) == rows`.

use std::collections::BTreeMap;

use sumchain_beacon_runtime::context::{EpochCutoffs, EpochMembership, ExecContext};
use sumchain_beacon_runtime::dkg::{DkgConfig, DkgEpoch, DkgOutcome};
use sumchain_beacon_runtime::rounds::BeaconChain;
use sumchain_beacon_runtime::signing::QualifiedEpoch;
use sumchain_genesis::ChainParams;
use sumchain_primitives::beacon_wire::BeaconOperation;
use sumchain_primitives::BlockHeight;
use sumchain_storage::Database;

use crate::beacon_executor::beacon_gate_open;
use crate::beacon_store::BeaconStore;
use crate::{Result, StateError};

/// The authoritative in-memory beacon working state: the DKG epoch plus the optional
/// signing chain. Cloneable so a block's transition runs on a throwaway copy that a
/// failing op leaves untouched.
#[derive(Clone)]
pub struct BeaconWorking {
    /// The DKG epoch setup state (keys, deals, verdicts, QUAL inputs).
    pub epoch: DkgEpoch,
    /// The signing-phase chain (finalized rounds + outputs), once QUAL succeeds.
    pub chain: Option<BeaconChain>,
}

impl BeaconWorking {
    /// A fresh working state for `cfg` (empty DKG epoch, no signing chain yet).
    pub fn new(cfg: DkgConfig) -> Self {
        BeaconWorking {
            epoch: DkgEpoch::new(cfg),
            chain: None,
        }
    }
}

/// Gated coordinator over the beacon runtime + persistence adapter.
///
/// Owns the authoritative [`BeaconWorking`] and drives the [`BeaconStore`] so an
/// applied block updates both in lockstep and reverts cleanly per height.
/// Constructed only via [`BeaconManager::new_enabled`] (yields `None` while the gate
/// is closed — the production default).
pub struct BeaconManager<'a> {
    db: &'a Database,
    params: ChainParams,
    working: BeaconWorking,
    undo: BTreeMap<BlockHeight, BeaconWorking>,
}

impl<'a> BeaconManager<'a> {
    /// Construct the manager **iff** the beacon gate is open at `height` (else
    /// `None`, the production default). Starts from a fresh working state for `cfg`.
    pub fn new_enabled(
        db: &'a Database,
        params: &ChainParams,
        height: BlockHeight,
        cfg: DkgConfig,
    ) -> Option<Self> {
        if beacon_gate_open(params, height) {
            Some(Self {
                db,
                params: params.clone(),
                working: BeaconWorking::new(cfg),
                undo: BTreeMap::new(),
            })
        } else {
            None
        }
    }

    /// The authoritative in-memory working state (read-only).
    pub fn working(&self) -> &BeaconWorking {
        &self.working
    }

    /// A store handle bound to this manager's database.
    pub fn store(&self) -> BeaconStore<'_> {
        BeaconStore::new(self.db)
    }

    /// Whether the gate is open at `height` for this manager's params.
    pub fn is_enabled_at(&self, height: BlockHeight) -> bool {
        beacon_gate_open(&self.params, height)
    }

    /// Whether an in-memory undo entry is retained for `height`.
    pub fn has_pending_undo(&self, height: BlockHeight) -> bool {
        self.undo.contains_key(&height)
    }

    /// Apply one block's worth of beacon transitions at `height`, updating BOTH the
    /// in-memory runtime state AND the persisted rows atomically (one journal/block).
    ///
    /// `apply` runs the caller's sequence of ratified runtime transitions
    /// (`register_key`, `submit_deal`, `apply_complaint`, finalize/round drives)
    /// against a throwaway working copy — so a failing op leaves the state untouched.
    /// Only on success is the resulting state materialized and persisted via
    /// [`BeaconStore::persist_transition`] (one atomic batch + one per-height revert
    /// journal). The in-memory state is committed only after persistence; the
    /// pre-state is retained as the undo entry (only when a journal was written).
    ///
    /// Returns the number of mutated rows (`0` for a genuine no-op — no journal, no
    /// undo). Rejects if the gate is closed at `height`.
    pub fn apply_block<F>(&mut self, height: BlockHeight, apply: F) -> Result<usize>
    where
        F: FnOnce(&mut BeaconWorking) -> Result<()>,
    {
        if !beacon_gate_open(&self.params, height) {
            return Err(StateError::InvalidOperation(format!(
                "beacon subprotocol not enabled at height {height}; refusing to apply"
            )));
        }

        let before = self.working.clone();
        let mut working = before.clone();
        apply(&mut working)?;

        // Materialize before/after runtime states → row sets, persist the delta.
        let before_rows = BeaconStore::materialize(&before.epoch, before.chain.as_ref())?;
        let after_rows = BeaconStore::materialize(&working.epoch, working.chain.as_ref())?;
        let mutated = {
            let store = BeaconStore::new(self.db);
            store.persist_transition(&before_rows, &after_rows, height)?
        };

        if mutated > 0 {
            self.undo.insert(height, before);
        }
        self.working = working;
        Ok(mutated)
    }

    /// Revert the beacon state finalized at `height`, rolling back BOTH the persisted
    /// rows and the in-memory runtime state to the exact prior state. Reverts must be
    /// issued tip-first (descending height), matching a real reorg.
    pub fn revert_block(&mut self, height: BlockHeight) -> Result<()> {
        {
            let store = BeaconStore::new(self.db);
            store.revert_block(height)?;
        }
        if let Some(prev) = self.undo.remove(&height) {
            self.working = prev;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-BLOCK accumulator — the interior-mutable producer the executor drives across
// a block's beacon txs (the runtime is stateful within a block/epoch). Rehydrated
// from the store at block start; each valid op is accumulated; the block's whole
// transition is materialized + persisted ONCE at block finalization.
// ---------------------------------------------------------------------------

/// One block's beacon accumulator. Rehydrated from the live store at block start so
/// the block's persisted transition is a delta against the TRUE prior state (enabling
/// cross-block persistence + restart). Owned (no `db` borrow) so it can live in the
/// executor's interior-mutable per-block slot across the per-tx dispatch loop.
pub struct BeaconBlockState {
    cfg: DkgConfig,
    membership: EpochMembership,
    cutoffs: EpochCutoffs,
    genesis: [u8; 32],
    working: BeaconWorking,
}

impl BeaconBlockState {
    /// Rehydrate the accumulator from the persisted store (rows → runtime).
    pub fn load_from_store(
        db: &Database,
        cfg: DkgConfig,
        membership: EpochMembership,
        cutoffs: EpochCutoffs,
        genesis: [u8; 32],
    ) -> Result<Self> {
        let store = BeaconStore::new(db);
        let (keys, deals, disqualified, rounds) = store.load_materialized()?;
        let epoch = DkgEpoch::rehydrate(cfg, keys, deals, disqualified)
            .map_err(|e| StateError::DeserializationError(format!("beacon rehydrate: {e:?}")))?;
        let chain = if rounds.is_empty() {
            None
        } else {
            // Persisted rounds imply a successful DKG; rebuild the signing chain.
            match epoch.finalize() {
                DkgOutcome::Success { group_key, .. } => {
                    let qc = epoch.qualified_commitments().unwrap_or_default();
                    let qe =
                        QualifiedEpoch::new(cfg.chain_id, cfg.epoch, cfg.params, group_key, qc);
                    Some(BeaconChain::rehydrate(qe, genesis, rounds).map_err(|e| {
                        StateError::DeserializationError(format!("beacon round rehydrate: {e:?}"))
                    })?)
                }
                DkgOutcome::SafeHalt { .. } => None,
            }
        };
        Ok(BeaconBlockState {
            cfg,
            membership,
            cutoffs,
            genesis,
            working: BeaconWorking { epoch, chain },
        })
    }

    /// The epoch membership snapshot (validator-set at the epoch boundary).
    pub fn membership(&self) -> &EpochMembership {
        &self.membership
    }
    /// The static epoch config (chain/epoch/params).
    pub fn cfg(&self) -> DkgConfig {
        self.cfg
    }
    /// The epoch timing cutoffs.
    pub fn cutoffs(&self) -> EpochCutoffs {
        self.cutoffs
    }
    /// The accumulated working state (read-only).
    pub fn working(&self) -> &BeaconWorking {
        &self.working
    }

    /// Drive ONE authenticated beacon operation through the runtime. Returns `true`
    /// iff every runtime + crypto + actor/membership/cutoff check passed (the op was
    /// validly processed and accumulated) — the SUCCESS receipt condition. Returns
    /// `false` (FAIL CLOSED) on any error, leaving the working state unchanged for
    /// that op.
    pub fn apply_op(&mut self, ctx: &ExecContext, op: &BeaconOperation) -> bool {
        match op {
            BeaconOperation::RegisterBeaconKey(k) => {
                self.working.epoch.register_key(ctx, k).is_ok()
            }
            BeaconOperation::DkgDeal(d) => self.working.epoch.submit_deal(ctx, d).is_ok(),
            BeaconOperation::DkgComplaint(c) => self.working.epoch.apply_complaint(ctx, c).is_ok(),
            BeaconOperation::BeaconPartial(p) => {
                self.ensure_chain()
                    && self
                        .working
                        .chain
                        .as_mut()
                        .expect("ensure_chain")
                        .accept_partial(ctx, p)
                        .is_ok()
            }
            BeaconOperation::BeaconFinalize(f) => {
                self.ensure_chain()
                    && self
                        .working
                        .chain
                        .as_mut()
                        .expect("ensure_chain")
                        .finalize_round(ctx, f)
                        .is_ok()
            }
        }
    }

    /// Lazily build the signing chain once the DKG has succeeded (QUAL). Returns
    /// `false` if the DKG safe-halts (no group key ⇒ signing is impossible).
    fn ensure_chain(&mut self) -> bool {
        if self.working.chain.is_some() {
            return true;
        }
        match self.working.epoch.finalize() {
            DkgOutcome::Success { group_key, .. } => {
                let qc = self
                    .working
                    .epoch
                    .qualified_commitments()
                    .unwrap_or_default();
                let qe = QualifiedEpoch::new(
                    self.cfg.chain_id,
                    self.cfg.epoch,
                    self.cfg.params,
                    group_key,
                    qc,
                );
                self.working.chain = Some(BeaconChain::new(qe, self.genesis));
                true
            }
            DkgOutcome::SafeHalt { .. } => false,
        }
    }

    /// Materialize + persist this block's whole accumulated transition into the store
    /// as EXACTLY ONE per-height journal (delta against the live pre-block state).
    /// Returns the number of mutated rows (`0` for a no-op block — no journal).
    pub fn persist(&self, db: &Database, height: BlockHeight) -> Result<usize> {
        let store = BeaconStore::new(db);
        let before = store.load_state_map()?; // live == pre-block (no beacon write yet this block)
        let after = BeaconStore::materialize(&self.working.epoch, self.working.chain.as_ref())?;
        store.persist_transition(&before, &after, height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_beacon_crypto::SecretScalar;
    use sumchain_beacon_runtime::context::{
        BeaconPhase, EpochCutoffs, EpochMembership, ExecContext, ValidatorId,
    };
    use sumchain_beacon_runtime::dkg::{DealOutcome, RegistrationOutcome};
    use sumchain_beacon_runtime::params::BeaconParams;
    use sumchain_primitives::beacon_wire::{DkgDealV1, RegisterBeaconKeyV1};
    use tempfile::TempDir;

    const CHAIN_ID: u64 = 0x0102_0304_0506_0708;
    const EPOCH: u64 = 7;
    const N: u32 = 5;

    fn open_db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    /// Production default — beacon gate dormant (`None`).
    fn dormant_params() -> ChainParams {
        let p = ChainParams::default();
        assert_eq!(p.beacon_enabled_from_height, None);
        p
    }
    /// Test-local gate open at `h` (in-memory only; the genesis loader forbids this).
    fn params_enabled_from(h: u64) -> ChainParams {
        ChainParams {
            beacon_enabled_from_height: Some(h),
            ..ChainParams::default()
        }
    }

    fn seed(tag: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, out) in b.iter_mut().enumerate() {
            *out = tag.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1);
        }
        b[31] = 0;
        b
    }
    fn vid(i: u32) -> ValidatorId {
        ValidatorId([i as u8; 32])
    }
    fn membership() -> EpochMembership {
        EpochMembership::new((0..N).map(vid).collect()).unwrap()
    }
    fn cfg() -> DkgConfig {
        DkgConfig {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            params: BeaconParams::proposed_default(),
        }
    }
    fn ctx(m: &EpochMembership, signer: u32, tx_ref: [u8; 32]) -> ExecContext<'_> {
        ExecContext {
            signer: vid(signer),
            tx_ref,
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            block_height: 10,
            phase: BeaconPhase::Setup,
            membership: m,
            cutoffs: EpochCutoffs {
                deal_cutoff: 100,
                complaint_deadline: 200,
            },
        }
    }
    fn reg(secret: &SecretScalar) -> RegisterBeaconKeyV1 {
        RegisterBeaconKeyV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            ek_j: secret.public_g1().to_compressed(),
            pop: secret.pop_prove().to_compressed(),
        }
    }
    fn deal(i: u32, j: u32) -> DkgDealV1 {
        let a0 = SecretScalar::from_bytes_le(&seed(0x10 + i as u8)).unwrap();
        let a1 = SecretScalar::from_bytes_le(&seed(0x20 + i as u8)).unwrap();
        let ek = SecretScalar::from_bytes_le(&seed(0x40 + j as u8)).unwrap();
        let r = SecretScalar::from_bytes_le(&seed(0x60 + (i * 8 + j) as u8)).unwrap();
        let r_pt = r.public_g1();
        let ek_pt = ek.public_g1();
        let d = r.ecdh(&ek_pt).unwrap();
        let x_j = (j as u64) + 1;
        let share = sumchain_beacon_crypto::eval_share_le(
            &[seed(0x10 + i as u8), seed(0x20 + i as u8)],
            x_j,
        )
        .unwrap();
        let ctx = sumchain_beacon_crypto::EciesContext {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            dealer_i: i,
            recipient_j: j,
            r_ij: r_pt,
            ek_j: ek_pt,
        };
        let ct = sumchain_beacon_crypto::ecies_seal(&d, &ctx, &share).unwrap();
        DkgDealV1 {
            chain_id: CHAIN_ID,
            epoch: EPOCH,
            dealer_i: i,
            recipient_j: j,
            commitments: vec![
                a0.public_g1().to_compressed(),
                a1.public_g1().to_compressed(),
            ],
            r_ij: r_pt.to_compressed(),
            ct_ij: ct,
        }
    }

    #[test]
    fn gate_off_constructs_nothing_and_writes_nothing() {
        let (db, _d) = open_db();
        let params = dormant_params();
        assert!(!beacon_gate_open(&params, 0));
        assert!(!beacon_gate_open(&params, u64::MAX));
        assert!(BeaconManager::new_enabled(&db, &params, 100, cfg()).is_none());
        let store = BeaconStore::new(&db);
        assert!(store.load_state_map().unwrap().is_empty());
        assert!(!store.has_journal(100).unwrap());
    }

    #[test]
    fn rehydrate_roundtrip_reproduces_materialization() {
        use sumchain_beacon_runtime::dkg::DkgEpoch;
        let (db, _d) = open_db();
        let m = membership();
        // Build a runtime state (key + deal), materialize + persist it.
        let mut mgr = BeaconManager::new_enabled(&db, &params_enabled_from(5), 5, cfg()).unwrap();
        mgr.apply_block(5, |w| {
            w.epoch
                .register_key(
                    &ctx(&m, 0, [1u8; 32]),
                    &reg(&SecretScalar::from_bytes_le(&seed(0x40)).unwrap()),
                )
                .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?;
            w.epoch
                .submit_deal(&ctx(&m, 0, [2u8; 32]), &deal(0, 0))
                .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?;
            Ok(())
        })
        .unwrap();
        let original = BeaconStore::materialize(&mgr.working().epoch, None).unwrap();

        // Rows → runtime (load_materialized + DkgEpoch::rehydrate) → rows again.
        let store = BeaconStore::new(&db);
        let (keys, deals, disqualified, _rounds) = store.load_materialized().unwrap();
        let rehydrated = DkgEpoch::rehydrate(cfg(), keys, deals, disqualified).unwrap();
        let reproduced = BeaconStore::materialize(&rehydrated, None).unwrap();
        assert_eq!(
            original, reproduced,
            "materialize(rehydrate(rows)) must byte-reproduce the persisted rows"
        );
    }

    #[test]
    fn valid_ops_succeed_and_materialize_then_revert_and_reapply() {
        let (db, _d) = open_db();
        let m = membership();
        let mut mgr = BeaconManager::new_enabled(&db, &params_enabled_from(5), 5, cfg()).unwrap();

        // Height 5: register key j=0 + a deal 0->0 (VALID ops → succeed → materialize).
        let mutated = mgr
            .apply_block(5, |w| {
                assert_eq!(
                    w.epoch
                        .register_key(
                            &ctx(&m, 0, [1u8; 32]),
                            &reg(&SecretScalar::from_bytes_le(&seed(0x40)).unwrap())
                        )
                        .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?,
                    RegistrationOutcome::Accepted
                );
                assert_eq!(
                    w.epoch
                        .submit_deal(&ctx(&m, 0, [2u8; 32]), &deal(0, 0))
                        .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?,
                    DealOutcome::Accepted
                );
                Ok(())
            })
            .unwrap();
        assert!(mutated > 0, "valid ops materialized rows");

        // Persisted rows equal the runtime's canonical materialization, and decode.
        let store = BeaconStore::new(&db);
        let live = store.load_state_map().unwrap();
        assert_eq!(
            live,
            BeaconStore::materialize(&mgr.working().epoch, None).unwrap()
        );
        let key_row = live.get(&crate::beacon_store::key_row_key(0)).unwrap();
        assert_eq!(
            crate::beacon_store::decode_key(key_row)
                .unwrap()
                .validator_index,
            0
        );
        let deal_row = live.get(&crate::beacon_store::deal_row_key(0, 0)).unwrap();
        assert_eq!(
            crate::beacon_store::decode_deal(deal_row).unwrap().dealer_i,
            0
        );
        assert!(store.has_journal(5).unwrap());
        assert!(mgr.has_pending_undo(5));
        let digest_after_5 = store.state_digest().unwrap();

        // Height 6: a second deal 1->0 on top.
        mgr.apply_block(6, |w| {
            w.epoch
                .submit_deal(&ctx(&m, 1, [3u8; 32]), &deal(1, 0))
                .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?;
            Ok(())
        })
        .unwrap();
        assert_ne!(
            store.state_digest().unwrap(),
            digest_after_5,
            "height 6 changed state"
        );

        // Revert height 6 → back to post-height-5 (rows + in-memory + digest).
        mgr.revert_block(6).unwrap();
        assert_eq!(
            store.state_digest().unwrap(),
            digest_after_5,
            "reverted to post-5"
        );
        assert!(!store.has_journal(6).unwrap());
        assert!(mgr.working().epoch.registered_key(0).is_some());

        // Reapply height 6 reproduces the identical committed state (determinism).
        let d6_first = {
            mgr.apply_block(6, |w| {
                w.epoch
                    .submit_deal(&ctx(&m, 1, [3u8; 32]), &deal(1, 0))
                    .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?;
                Ok(())
            })
            .unwrap();
            store.state_digest().unwrap()
        };
        mgr.revert_block(6).unwrap();
        mgr.apply_block(6, |w| {
            w.epoch
                .submit_deal(&ctx(&m, 1, [3u8; 32]), &deal(1, 0))
                .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            store.state_digest().unwrap(),
            d6_first,
            "reapply is deterministic"
        );

        // Height 5 still reverts cleanly to empty afterwards.
        mgr.revert_block(6).unwrap();
        mgr.revert_block(5).unwrap();
        assert!(store.load_state_map().unwrap().is_empty());
    }

    #[test]
    fn invalid_op_leaves_state_and_journal_unchanged() {
        let (db, _d) = open_db();
        let m = membership();
        let mut mgr = BeaconManager::new_enabled(&db, &params_enabled_from(5), 5, cfg()).unwrap();
        // A deal whose signer != dealer_i is an authenticated-binding failure ⇒ the
        // whole transition errors and nothing is persisted.
        let err = mgr.apply_block(5, |w| {
            w.epoch
                .submit_deal(&ctx(&m, 1, [9u8; 32]), &deal(0, 0)) // signer 1, dealer 0
                .map_err(|e| StateError::InvalidOperation(format!("{e:?}")))?;
            Ok(())
        });
        assert!(err.is_err());
        assert!(BeaconStore::new(&db).load_state_map().unwrap().is_empty());
        assert!(!BeaconStore::new(&db).has_journal(5).unwrap());
    }
}

//! C1 compute-pool (#130) transaction execution: GATED and dormant.
//!
//! A `TxPayload::ComputePool` transaction (TxType 27) carries one frozen
//! [`ComputePoolOperation`] encoding. This module decides what such a
//! transaction does once the compute-pool gate is open. While the gate is
//! closed (the production default, `compute_pool_enabled_from_height ==
//! None`, refused at genesis load on every network) none of it runs: the
//! executor builds no [`ComputePoolBlockState`] and keeps the fail-closed
//! seam, `Failed(0)` with no fee and no state, exactly as before.
//!
//! ## What executes
//!
//! Only operations whose rules are settled. None is yet: every operation
//! decodes and is refused ([`ComputePoolReject::NotExecutable`]).
//!
//! ## Receipts
//!
//! A refusal is free and stateless. Its receipt is the executor's generic
//! `Failed(0)`, as for the dormant seam and the beacon; the reason is the
//! typed [`ComputePoolReject`], and no receipt code is allocated (D2-7.6(g)).
//! A success charges the fee and advances the nonce, like any other payload.
//!
//! ## One transition per block
//!
//! C1 rows are staged once per block, at the executor's apply seam, by
//! [`crate::compute_pool_manager::ComputePoolManager`]. Each transaction is
//! decided against [`ComputePoolBlockState`], the model as the block's earlier
//! transactions left it, and each step that succeeds is recorded. The seam
//! rebuilds the model from the candidate's rows, replays the steps through the
//! manager, and stages the delta. Account effects (fee, nonce, bond) are
//! staged by the transaction itself. Both revert in the one reorg batch: the
//! accounts with the account journal, the rows with the C1 journal.

use sumchain_genesis::ChainParams;
use sumchain_primitives::transaction::ComputePoolTxData;
use sumchain_primitives::{Address, Balance, BlockHeight};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_wire::b0::codec::DecodeError;
use sumchain_wire::compute_pool_wire::ComputePoolOperation;
use thiserror::Error;

use crate::compute_pool::{ComputePoolModel, PoolError, PoolResult};
use crate::compute_pool_store::ComputePoolStore;
use crate::state::StateManager;
use crate::{Result, StateError};

/// Why a ComputePool transaction was refused. Internal and typed: every
/// variant reaches the receipt as the generic `Failed(0)`.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum ComputePoolReject {
    /// The operation bytes are not a canonical `ComputePoolOperation`.
    #[error("undecodable compute-pool operation: {0:?}")]
    Undecodable(DecodeError),

    /// The operation decodes, but its execution rules are not decided, so it
    /// does nothing.
    #[error("compute-pool operation {op:#06x} has no execution rules yet")]
    NotExecutable { op: u16 },

    /// The sender cannot pay the fee and the bond together.
    #[error("balance {available} cannot pay fee {fee} plus bond {bond}")]
    InsufficientBalance {
        fee: Balance,
        bond: Balance,
        available: Balance,
    },

    /// The model refused the step.
    #[error("{0}")]
    Pool(PoolError),
}

/// What one executable operation does to the model, with everything it needs
/// from the transaction and the chain parameters already resolved.
///
/// Applying a step is a pure function of the model, which is what lets the
/// seam replay a block's steps onto the model rebuilt from the candidate's
/// rows and arrive where the block's transactions did. No operation executes
/// yet, so there is no step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolStep {}

impl PoolStep {
    /// The step a decoded operation from `sender` executes, or why it does
    /// not execute at all. Reads no state.
    pub fn resolve(
        op: &ComputePoolOperation,
        _chain_id: u64,
        _sender: &Address,
        _params: &ChainParams,
    ) -> std::result::Result<Self, ComputePoolReject> {
        Err(ComputePoolReject::NotExecutable { op: op.op() })
    }

    /// What the sender pays into a bond when the step succeeds.
    pub fn bond(&self) -> Balance {
        match *self {}
    }

    /// Whether the step applies to `model`. Changes nothing.
    pub fn check(&self, _model: &ComputePoolModel) -> PoolResult<()> {
        match *self {}
    }

    /// Apply the step. The model operations validate before they mutate, so a
    /// refusal leaves `model` unchanged.
    pub fn apply(&self, _model: &mut ComputePoolModel) -> PoolResult<()> {
        match *self {}
    }

    /// Apply `steps` in order: what the seam hands the manager.
    pub fn replay(steps: &[PoolStep], model: &mut ComputePoolModel) -> PoolResult<()> {
        steps.iter().try_for_each(|step| step.apply(model))
    }
}

/// One block's compute-pool work: the model as the block's earlier
/// ComputePool transactions left it, and the steps they took.
///
/// Built at block start, only when the gate is open at the block's height,
/// and kept in the executor's slot across the transaction loop. It holds no
/// database: the model is loaded from the candidate it is handed.
#[derive(Debug)]
pub struct ComputePoolBlockState {
    height: BlockHeight,
    /// `None` until the block's first ComputePool transaction loads it from
    /// the candidate's rows, so a block without one never reads them here.
    model: Option<ComputePoolModel>,
    steps: Vec<PoolStep>,
}

impl ComputePoolBlockState {
    /// The state for the block at `height`, before any of its transactions.
    pub fn new(height: BlockHeight) -> Self {
        Self {
            height,
            model: None,
            steps: Vec::new(),
        }
    }

    /// The height of the block this state belongs to.
    pub fn height(&self) -> BlockHeight {
        self.height
    }

    /// The steps that succeeded, in block order.
    pub fn into_steps(self) -> Vec<PoolStep> {
        self.steps
    }

    /// The block's model, loaded from the candidate's rows on first use.
    ///
    /// Nothing writes C1 rows between block start and the apply seam, so the
    /// rows read here are the parent's, the same rows the seam rebuilds from.
    fn model(&mut self, view: &ExecutionView<'_, '_>) -> Result<&mut ComputePoolModel> {
        let model = match self.model.take() {
            Some(model) => model,
            None => ComputePoolStore::v_load_model(view)?,
        };
        Ok(self.model.insert(model))
    }

    /// Apply a step whose check passed, and record it for the seam.
    fn record(&mut self, step: PoolStep) -> Result<()> {
        let model = self.model.as_mut().ok_or_else(|| {
            StateError::InvalidOperation(
                "C1 step recorded before the block's model was loaded".to_string(),
            )
        })?;
        step.apply(model).map_err(|e| {
            StateError::InvalidOperation(format!("C1 step refused after its check passed: {e}"))
        })?;
        self.steps.push(step);
        Ok(())
    }
}

/// Execute one ComputePool transaction against the block's state.
///
/// `Ok(Ok(()))`: the operation succeeded and the fee was charged.
/// `Ok(Err(reason))`: it was refused, free, with nothing staged and the model
/// untouched. `Err`: a storage failure, which fails the block as on every
/// other path.
///
/// Every check runs before any write. The writes (fee, nonce and bond, all on
/// the candidate's accounts) come next and the model changes last, so a write
/// that fails, a storage error or the transaction crossing its write-set
/// bound, leaves the model as the block's earlier transactions left it.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    view: &mut ExecutionView<'_, '_>,
    block: &mut ComputePoolBlockState,
    chain_id: u64,
    params: &ChainParams,
    sender: &Address,
    fee: Balance,
    proposer: &Address,
    data: &ComputePoolTxData,
) -> Result<std::result::Result<(), ComputePoolReject>> {
    let op = match data.decode_operation() {
        Ok(op) => op,
        Err(e) => return Ok(Err(ComputePoolReject::Undecodable(e))),
    };
    let step = match PoolStep::resolve(&op, chain_id, sender, params) {
        Ok(step) => step,
        Err(reject) => return Ok(Err(reject)),
    };
    if let Err(e) = step.check(block.model(view)?) {
        return Ok(Err(ComputePoolReject::Pool(e)));
    }

    // `validate_tx` approved the fee on its own; the bond is paid with it.
    let bond = step.bond();
    let available = StateManager::v_get_balance(view, sender)?;
    let required = match fee.checked_add(bond) {
        Some(required) if required <= available => required,
        _ => {
            return Ok(Err(ComputePoolReject::InsufficientBalance {
                fee,
                bond,
                available,
            }))
        }
    };

    StateManager::v_deduct(view, sender, required)?;
    StateManager::v_credit(view, proposer, fee)?;
    StateManager::v_increment_nonce(view, sender)?;
    block.record(step)?;
    Ok(Ok(()))
}

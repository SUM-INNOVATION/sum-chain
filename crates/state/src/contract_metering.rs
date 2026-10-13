//! The contract metering gate and the block-level contract gas budget (#279).
//!
//! Dormant. Both read [`ChainParams::contract_metering_enabled_from_height`],
//! which defaults to `None`; below it (or with it unset) a contract runs on the
//! unmetered engine and no block budget exists, exactly as before the gate.
//!
//! The block budget is over DECLARED gas limits, so it is decidable from a
//! block's transactions alone: an importer refuses an over-budget block before
//! executing any of it, and a proposer can fit its selection to it without
//! executing anything.

use std::collections::HashSet;

use sumc_runtime::ExecutionMode;
use sumchain_genesis::ChainParams;
use sumchain_primitives::{SignedTransaction, TxInner, TxPayload};

/// Whether contracts at `height` run on the metered engine.
pub fn contract_metering_gate_open(params: &ChainParams, height: u64) -> bool {
    matches!(params.contract_metering_enabled_from_height, Some(h) if height >= h)
}

/// The engine a contract deploy or call at `height` runs on.
pub fn contract_execution_mode(params: &ChainParams, height: u64) -> ExecutionMode {
    if contract_metering_gate_open(params, height) {
        ExecutionMode::MeteredV1Provisional
    } else {
        ExecutionMode::Unmetered
    }
}

/// The block contract gas budget in force at `height`: `max_block_contract_gas`
/// where the metering gate is open, otherwise none.
pub fn block_contract_gas_budget(params: &ChainParams, height: u64) -> Option<u64> {
    if contract_metering_gate_open(params, height) {
        params.max_block_contract_gas
    } else {
        None
    }
}

/// The largest `gas_limit` a `ContractDeploy` at `height` may declare:
/// `max_contract_deploy_gas` where the metering gate is open and it is set,
/// otherwise `max_contract_gas`, the bound every deploy had before it.
pub fn contract_deploy_gas_ceiling(params: &ChainParams, height: u64) -> u64 {
    match params.max_contract_deploy_gas {
        Some(ceiling) if contract_metering_gate_open(params, height) => ceiling,
        _ => params.max_contract_gas,
    }
}

/// The gas limit a transaction declares for contract execution, if it is a
/// contract transaction.
pub fn declared_contract_gas(tx: &SignedTransaction) -> Option<u64> {
    match tx.inner() {
        TxInner::V2(v2) => match &v2.payload {
            TxPayload::ContractDeploy(d) => Some(d.gas_limit),
            TxPayload::ContractCall(c) => Some(c.gas_limit),
            _ => None,
        },
        _ => None,
    }
}

/// Refuse `txs` at `height` if their summed declared contract gas exceeds the
/// budget in force. Checked arithmetic: a sum that overflows `u64` is over
/// any budget. Reads declared limits only; executes nothing.
pub fn check_block_contract_gas(
    params: &ChainParams,
    height: u64,
    txs: &[SignedTransaction],
) -> Result<(), String> {
    let Some(budget) = block_contract_gas_budget(params, height) else {
        return Ok(());
    };
    let mut declared: u64 = 0;
    for gas in txs.iter().filter_map(declared_contract_gas) {
        declared = declared.checked_add(gas).ok_or_else(|| {
            format!("declared contract gas overflows u64 (block budget {budget})")
        })?;
        if declared > budget {
            return Err(format!(
                "declared contract gas exceeds the block budget: more than {budget}"
            ));
        }
    }
    Ok(())
}

/// A proposer's selection fitted to the budget in force at `height`, in the
/// order given.
///
/// A contract transaction whose declared gas does not fit what is left is
/// skipped, and selection carries on with the rest. Skipping it also skips
/// every LATER transaction from the same sender: nonces are contiguous, and
/// keeping them would hand them `InvalidNonce` receipts in this block. Nothing
/// is evicted; a skipped transaction stays in the mempool for a later block.
pub fn select_within_block_contract_gas(
    params: &ChainParams,
    height: u64,
    txs: Vec<SignedTransaction>,
) -> Vec<SignedTransaction> {
    let Some(budget) = block_contract_gas_budget(params, height) else {
        return txs;
    };
    let mut remaining = budget;
    let mut skipped = HashSet::new();
    let mut selected = Vec::with_capacity(txs.len());
    for tx in txs {
        let sender = tx.sender();
        if skipped.contains(&sender) {
            continue;
        }
        if let Some(gas) = declared_contract_gas(&tx) {
            if gas > remaining {
                skipped.insert(sender);
                continue;
            }
            remaining -= gas;
        }
        selected.push(tx);
    }
    selected
}

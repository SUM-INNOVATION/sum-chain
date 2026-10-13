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
//!
//! The loaded-code cap (D8) bounds a block's compilation work. Compiling a
//! contract on a metered-cache miss is outside gas accounting, so gas never
//! depends on cache state. What bounds the work is how much code one block can
//! make a node load: the deployed code plus the code of every DISTINCT contract
//! it calls, the latter measured in the block's parent state. That is decidable
//! before execution too, because a call's target is declared in the transaction
//! and a contract's code never changes after deploy. Cache state never enters
//! the decision.

use std::collections::HashSet;
use std::sync::Arc;

use sumc_runtime::storage::ContractStorageBackend;
use sumc_runtime::{metering, ExecutionMode, RocksDbStorage};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, SignedTransaction, TxInner, TxPayload};
use sumchain_storage::Database;

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
///
/// The declared limit is the whole deploy's budget, its init call included.
/// That is the PROPOSED behaviour, not a ratified one (see
/// `ChainParams::max_contract_deploy_gas`).
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

// ── loaded-code cap (D8) ────────────────────────────────────────────────────

/// The loaded-code cap in force at `height`: the metered cost schedule's
/// `max_block_loaded_code_bytes` where the metering gate is open, otherwise
/// none.
pub fn block_loaded_code_cap(params: &ChainParams, height: u64) -> Option<u64> {
    contract_metering_gate_open(params, height)
        .then(|| u64::from(metering::METERED_COST_SCHEDULE.max_block_loaded_code_bytes))
}

/// What one transaction makes a block load, given the contracts the block
/// already counted: a deploy's code length, or the parent-state code length of
/// a call's target the first time the block calls it. A call to a contract that
/// does not exist in the parent state (deployed earlier in the same block, or
/// nowhere) adds nothing: a same-block deploy was counted when deployed.
fn loaded_by<F>(
    tx: &SignedTransaction,
    seen: &HashSet<Address>,
    code_len: &mut F,
) -> Result<Option<(Option<Address>, u64)>, String>
where
    F: FnMut(&Address) -> Result<Option<u64>, String>,
{
    let TxInner::V2(v2) = tx.inner() else {
        return Ok(None);
    };
    match &v2.payload {
        TxPayload::ContractDeploy(d) => Ok(Some((None, d.code.len() as u64))),
        TxPayload::ContractCall(c) if seen.contains(&c.contract) => Ok(Some((None, 0))),
        TxPayload::ContractCall(c) => Ok(Some((
            Some(c.contract),
            code_len(&c.contract)?.unwrap_or(0),
        ))),
        _ => Ok(None),
    }
}

/// The code `txs` make a block load. Checked arithmetic: an overflowing sum
/// is an error.
pub fn loaded_code_bytes<F>(txs: &[SignedTransaction], mut code_len: F) -> Result<u64, String>
where
    F: FnMut(&Address) -> Result<Option<u64>, String>,
{
    let mut seen = HashSet::new();
    let mut total: u64 = 0;
    for tx in txs {
        if let Some((target, bytes)) = loaded_by(tx, &seen, &mut code_len)? {
            if let Some(t) = target {
                seen.insert(t);
            }
            total = total
                .checked_add(bytes)
                .ok_or_else(|| "loaded contract code overflows u64".to_string())?;
        }
    }
    Ok(total)
}

/// Refuse `txs` at `height` if the code they make the block load exceeds the
/// cap in force. `code_len` reads a contract's code length in the block's
/// PARENT state. Executes nothing.
pub fn check_block_loaded_code<F>(
    params: &ChainParams,
    height: u64,
    txs: &[SignedTransaction],
    code_len: F,
) -> Result<(), String>
where
    F: FnMut(&Address) -> Result<Option<u64>, String>,
{
    let Some(cap) = block_loaded_code_cap(params, height) else {
        return Ok(());
    };
    let loaded = loaded_code_bytes(txs, code_len)?;
    if loaded > cap {
        return Err(format!(
            "the block loads {loaded} bytes of contract code, above the {cap}-byte cap"
        ));
    }
    Ok(())
}

/// A proposer's selection fitted to the loaded-code cap at `height`, in the
/// order given. A contract transaction that would push the block over the cap
/// is skipped, with every later transaction from the same sender (nonces are
/// contiguous). A transaction whose lookup fails is skipped too: the proposer
/// cannot show that it fits. Nothing is evicted.
pub fn select_within_block_loaded_code<F>(
    params: &ChainParams,
    height: u64,
    txs: Vec<SignedTransaction>,
    mut code_len: F,
) -> Vec<SignedTransaction>
where
    F: FnMut(&Address) -> Result<Option<u64>, String>,
{
    let Some(cap) = block_loaded_code_cap(params, height) else {
        return txs;
    };
    let mut remaining = cap;
    let mut seen = HashSet::new();
    let mut skipped = HashSet::new();
    let mut selected = Vec::with_capacity(txs.len());
    for tx in txs {
        let sender = tx.sender();
        if skipped.contains(&sender) {
            continue;
        }
        match loaded_by(&tx, &seen, &mut code_len) {
            Ok(None) => {}
            Ok(Some((target, bytes))) if bytes <= remaining => {
                remaining -= bytes;
                if let Some(t) = target {
                    seen.insert(t);
                }
            }
            Ok(Some(_)) | Err(_) => {
                skipped.insert(sender);
                continue;
            }
        }
        selected.push(tx);
    }
    selected
}

/// A contract's code length in COMMITTED (canonical) state, for a proposer
/// building on the canonical head. Reads through a fresh, unbound backend, so
/// no branch layer an earlier execution left bound can leak in.
pub fn committed_contract_code_len(
    db: &Arc<Database>,
    address: &Address,
) -> Result<Option<u64>, String> {
    RocksDbStorage::new(db.clone())
        .get_code(address)
        .map(|code| code.map(|c| c.len() as u64))
        .map_err(|e| e.to_string())
}

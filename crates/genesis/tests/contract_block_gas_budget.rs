//! #279: a block contract gas budget is set together with the metering gate or
//! not at all, and where both are set the budget must be at least the
//! per-transaction ceiling. Structural only: neither value is ratified here.

use std::collections::HashMap;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis, GenesisError};

fn params(gate: Option<u64>, budget: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_contracts_enabled();
    p.contract_metering_enabled_from_height = gate;
    p.max_block_contract_gas = budget;
    p
}

fn genesis_json(p: ChainParams) -> String {
    let v = KeyPair::from_bytes([3u8; 32]);
    Genesis::new(
        1,
        0,
        vec![v.public_key().to_base58()],
        HashMap::from([(v.address().to_base58(), 1_000u128)]),
        p,
    )
    .to_json()
    .unwrap()
}

#[test]
fn a_budget_below_the_tx_ceiling_is_refused_at_load() {
    let ceiling = ChainParams::default().max_contract_gas;
    let p = params(Some(1), Some(ceiling - 1));
    assert!(matches!(
        p.validate(),
        Err(GenesisError::BlockContractGasBelowTxCeiling { budget, ceiling: c })
            if budget == ceiling - 1 && c == ceiling
    ));
    // Loading the file refuses too, which is what refuses node start.
    let err = Genesis::from_json(&genesis_json(p)).unwrap_err();
    assert!(err.to_string().contains("max_block_contract_gas"), "{err}");
}

#[test]
fn a_budget_at_or_above_the_ceiling_or_an_inert_one_is_accepted() {
    let ceiling = ChainParams::default().max_contract_gas;
    for p in [
        params(Some(1), Some(ceiling)),
        params(Some(1), Some(ceiling + 1)),
        params(Some(1), Some(u64::MAX)),
        params(Some(1), None), // no block limit
        params(None, None),
    ] {
        p.validate().unwrap();
        Genesis::from_json(&genesis_json(p)).unwrap();
    }
    // The ceiling itself may move; the rule follows it.
    let mut p = params(Some(1), Some(500));
    p.max_contract_gas = 500;
    p.validate().unwrap();
    p.max_contract_gas = 501;
    assert!(p.validate().is_err());
}

#[test]
fn a_budget_without_the_metering_gate_is_refused_at_load() {
    for budget in [0, 1, ChainParams::default().max_contract_gas, u64::MAX] {
        let p = params(None, Some(budget));
        assert!(matches!(
            p.validate(),
            Err(GenesisError::BlockContractGasWithoutMetering { budget: b }) if b == budget
        ));
        let err = Genesis::from_json(&genesis_json(p)).unwrap_err();
        assert!(err.to_string().contains("max_block_contract_gas"), "{err}");
        assert!(
            err.to_string()
                .contains("contract_metering_enabled_from_height"),
            "{err}"
        );
    }
}

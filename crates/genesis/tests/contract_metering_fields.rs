//! #279: the contract-metering genesis fields, declared dormant.
//!
//! `contract_metering_enabled_from_height` and `max_block_contract_gas` default
//! to `None`, which every genesis written before they existed resolves to. This
//! binary has no metered engine, so it refuses the gate at load. The budget is
//! set together with the gate or not at all, and where both are set it must be
//! at least the per-transaction ceiling. Structural only: no value is chosen.

use std::collections::HashMap;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis, GenesisError, REMEDIATION_GATES};

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
fn both_fields_default_to_none_and_an_older_genesis_resolves_to_none() {
    let d = ChainParams::default();
    assert_eq!(d.contract_metering_enabled_from_height, None);
    assert_eq!(d.max_block_contract_gas, None);
    let c = ChainParams::with_contracts_enabled();
    assert_eq!(c.contract_metering_enabled_from_height, None);
    assert_eq!(c.max_block_contract_gas, None);

    // A genesis written before the fields existed: remove them from the JSON.
    let mut v: serde_json::Value =
        serde_json::from_str(&genesis_json(ChainParams::default())).unwrap();
    let params = v["params"].as_object_mut().unwrap();
    assert!(params
        .remove("contract_metering_enabled_from_height")
        .is_some());
    assert!(params.remove("max_block_contract_gas").is_some());
    let g = Genesis::from_json(&v.to_string()).unwrap();
    assert_eq!(g.params.contract_metering_enabled_from_height, None);
    assert_eq!(g.params.max_block_contract_gas, None);
}

#[test]
fn the_gate_is_an_activation_gate_and_not_yet_a_remediation_gate() {
    let gates = ChainParams::default().activation_heights();
    assert_eq!(
        gates
            .iter()
            .filter(|(n, _)| *n == "contract_metering_enabled_from_height")
            .count(),
        1
    );
    assert!(!REMEDIATION_GATES.contains(&"contract_metering_enabled_from_height"));
    assert!(!gates.iter().any(|(n, _)| *n == "max_block_contract_gas"));
}

#[test]
fn the_gate_is_refused_at_load_in_this_binary() {
    let ceiling = ChainParams::default().max_contract_gas;
    for h in [0, 1, 1_000, u64::MAX] {
        for budget in [None, Some(ceiling), Some(u64::MAX)] {
            let p = params(Some(h), budget);
            assert!(matches!(
                p.validate(),
                Err(GenesisError::ContractMeteringUnavailable { height }) if height == h
            ));
            let err = Genesis::from_json(&genesis_json(p)).unwrap_err();
            assert!(
                err.to_string()
                    .contains("contract_metering_enabled_from_height"),
                "{err}"
            );
        }
    }
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

#[test]
fn a_budget_below_the_tx_ceiling_is_refused_before_the_gate() {
    let ceiling = ChainParams::default().max_contract_gas;
    let p = params(Some(1), Some(ceiling - 1));
    assert!(matches!(
        p.validate(),
        Err(GenesisError::BlockContractGasBelowTxCeiling { budget, ceiling: c })
            if budget == ceiling - 1 && c == ceiling
    ));
    let err = Genesis::from_json(&genesis_json(p)).unwrap_err();
    assert!(err.to_string().contains("max_block_contract_gas"), "{err}");
    // The ceiling itself may move; the rule follows it.
    let mut p = params(Some(1), Some(500));
    p.max_contract_gas = 500;
    assert!(matches!(
        p.validate(),
        Err(GenesisError::ContractMeteringUnavailable { .. })
    ));
    p.max_contract_gas = 501;
    assert!(matches!(
        p.validate(),
        Err(GenesisError::BlockContractGasBelowTxCeiling { .. })
    ));
}

#[test]
fn unset_fields_change_nothing() {
    params(None, None).validate().unwrap();
    ChainParams::default().validate().unwrap();
}

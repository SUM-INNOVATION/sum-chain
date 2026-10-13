//! #279: `max_contract_deploy_gas`, the deploy ceiling above the metering
//! gate. It defaults to `None` (deploys bounded by `max_contract_gas`), which is
//! also what every genesis written before it existed resolves to. Set, it
//! requires the gate, must be at least `max_contract_gas`, and a set block
//! budget must be at least it. Structural only: no value is chosen.

use std::collections::HashMap;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis, GenesisError};

fn params(gate: Option<u64>, deploy: Option<u64>, budget: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_contracts_enabled();
    p.contract_metering_enabled_from_height = gate;
    p.max_contract_deploy_gas = deploy;
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

fn tx() -> u64 {
    ChainParams::default().max_contract_gas
}

#[test]
fn it_defaults_to_none_and_an_older_genesis_resolves_to_none() {
    assert_eq!(ChainParams::default().max_contract_deploy_gas, None);
    assert_eq!(
        ChainParams::with_contracts_enabled().max_contract_deploy_gas,
        None
    );
    let mut v: serde_json::Value =
        serde_json::from_str(&genesis_json(ChainParams::default())).unwrap();
    let params = v["params"].as_object_mut().unwrap();
    assert!(params.remove("max_contract_deploy_gas").is_some());
    let g = Genesis::from_json(&v.to_string()).unwrap();
    assert_eq!(g.params.max_contract_deploy_gas, None);
}

#[test]
fn without_the_metering_gate_it_is_refused_at_load() {
    for deploy in [0, tx(), u64::MAX] {
        let p = params(None, Some(deploy), None);
        assert!(matches!(
            p.validate(),
            Err(GenesisError::ContractDeployGasWithoutMetering { ceiling }) if ceiling == deploy
        ));
        let err = Genesis::from_json(&genesis_json(p)).unwrap_err();
        assert!(err.to_string().contains("max_contract_deploy_gas"), "{err}");
    }
}

#[test]
fn below_the_per_transaction_ceiling_it_is_refused_at_load() {
    let p = params(Some(1), Some(tx() - 1), None);
    assert!(matches!(
        p.validate(),
        Err(GenesisError::ContractDeployGasBelowTxCeiling { deploy, ceiling })
            if deploy == tx() - 1 && ceiling == tx()
    ));
}

#[test]
fn a_block_budget_below_it_is_refused_at_load() {
    let p = params(Some(1), Some(2 * tx()), Some(2 * tx() - 1));
    assert!(matches!(
        p.validate(),
        Err(GenesisError::BlockContractGasBelowDeployCeiling { budget, deploy })
            if budget == 2 * tx() - 1 && deploy == 2 * tx()
    ));
    let err = Genesis::from_json(&genesis_json(p)).unwrap_err();
    assert!(err.to_string().contains("max_contract_deploy_gas"), "{err}");
}

#[test]
fn consistent_settings_are_accepted() {
    for p in [
        params(None, None, None),
        params(Some(1), None, None),
        params(Some(1), Some(tx()), None),
        params(Some(1), Some(2 * tx()), None),
        params(Some(1), Some(2 * tx()), Some(2 * tx())),
        params(Some(1), Some(2 * tx()), Some(u64::MAX)),
        params(Some(1), Some(u64::MAX), Some(u64::MAX)),
    ] {
        p.validate().unwrap();
        Genesis::from_json(&genesis_json(p)).unwrap();
    }
}

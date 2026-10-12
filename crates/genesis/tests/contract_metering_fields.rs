//! #279: the contract-metering genesis fields default to `None`, which is also
//! what every genesis written before they existed resolves to. The gate is an
//! activation gate and is not (yet) a remediation gate. Budget validation is in
//! `contract_block_gas_budget.rs`.

use std::collections::HashMap;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis, REMEDIATION_GATES};

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

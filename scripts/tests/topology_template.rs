//! Issue #118's tracked topology template, `genesis/snip-mirror-genesis.template.json`.
//!
//! SYNTHETIC TEST TOPOLOGY: every key here is a throwaway key generated for one
//! test. Nothing in this file describes, proposes or changes a production
//! validator set.
//!
//! The template is the reviewable description of the genesis `setup-local-testnet
//! --mode topology` provisions. These tests hold it to that:
//!
//! * the loader refuses it until its placeholders are substituted;
//! * substituted, it loads and has the topology shape (chain id 1337, at least
//!   five funded validators, consensus only);
//! * substituted with a provisioned topology's own keys, it is exactly the
//!   genesis that provisioning wrote, apart from the genesis time;
//! * substitution refuses a missing or an unused value;
//! * fewer than five validator slots fail the shape check, and an opened pool or
//!   beacon gate is refused by the loader itself.
//!
//! Issue #118's checklist also asks for the compute-pool and beacon gates at
//! `Some(0)` and a beacon `n_min` of 5. Neither is here, on purpose: the loader
//! refuses both gates at any value, their parameters are not ratified, and
//! `BeaconParamsConfig` has no `n_min` field. The last test pins that refusal.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sumchain_crypto::KeyPair;
use sumchain_genesis::Genesis;
use sumchain_scripts::{
    check_topology_shape, provision_topology, substitute_template, topology_template_values,
    DEVNET_CHAIN_ID, SMOKE_ROLE_NAMES, TOPOLOGY_DEFAULT_VALIDATORS, TOPOLOGY_TEMPLATE,
};

fn template_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .join(TOPOLOGY_TEMPLATE)
}

fn template() -> String {
    std::fs::read_to_string(template_path()).expect("read the tracked template")
}

/// Fresh throwaway values for every placeholder of a five-slot template.
fn synthetic_values() -> (BTreeMap<String, String>, Vec<String>) {
    let mut values = BTreeMap::new();
    let mut validators = Vec::new();
    for n in 1..=TOPOLOGY_DEFAULT_VALIDATORS {
        let kp = KeyPair::generate();
        let pubkey = kp.public_key().to_base58();
        values.insert(format!("DEVNET_VALIDATOR{n}_PUBKEY"), pubkey.clone());
        values.insert(
            format!("DEVNET_VALIDATOR{n}_ADDRESS"),
            kp.address().to_base58(),
        );
        validators.push(pubkey);
    }
    for role in SMOKE_ROLE_NAMES {
        values.insert(
            format!("DEVNET_{}_ADDRESS", role.to_ascii_uppercase()),
            KeyPair::generate().address().to_base58(),
        );
    }
    (values, validators)
}

/// Comparable form of a genesis: its JSON with the genesis time set to 0.
fn comparable(g: &Genesis) -> serde_json::Value {
    let mut v = serde_json::to_value(g).expect("genesis to JSON");
    v["genesis_time"] = serde_json::json!(0);
    v
}

#[test]
fn the_template_is_refused_until_its_placeholders_are_substituted() {
    let err = Genesis::from_file(template_path()).expect_err("a template is not a genesis");
    assert_eq!(
        err.to_string(),
        "Invalid validator public key: validator[0]: DEVNET_VALIDATOR1_PUBKEY"
    );
    assert!(template().contains("\"_comment\""));
}

#[test]
fn the_substituted_template_loads_with_the_topology_shape() {
    let (values, validators) = synthetic_values();
    let json = substitute_template(&template(), &values).expect("substitute");
    let g = Genesis::from_json(&json).expect("the genesis loader accepts it");
    check_topology_shape(&g).expect("topology shape");

    assert_eq!(g.chain_id, DEVNET_CHAIN_ID);
    assert_eq!(g.validators, validators, "slot order is round-robin order");
    assert_eq!(g.alloc.len(), validators.len() + SMOKE_ROLE_NAMES.len());
    assert!(g.alloc.values().all(|&b| b > 0), "every identity is funded");
    let p = &g.params;
    assert_eq!(p.compute_pool_enabled_from_height, None);
    assert_eq!(p.beacon_enabled_from_height, None);
    assert!(p.compute_pool_params.is_none());
    assert!(p.beacon_params.is_none());
    assert!(p.beacon_schedule.is_none());
}

#[test]
fn the_template_describes_exactly_what_topology_mode_provisions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = provision_topology(dir.path(), TOPOLOGY_DEFAULT_VALIDATORS).expect("provision");
    let provisioned = Genesis::from_file(&a.genesis_path).expect("provisioned genesis");

    let json = substitute_template(&template(), &topology_template_values(&a))
        .expect("every provisioned identity has a placeholder, and the reverse");
    let from_template = Genesis::from_json(&json).expect("substituted template");

    assert_eq!(comparable(&from_template), comparable(&provisioned));
}

#[test]
fn substitution_refuses_a_missing_or_an_unused_value() {
    let (mut values, _) = synthetic_values();

    let mut short = values.clone();
    short.remove("DEVNET_VERIFIER_ADDRESS");
    let err = substitute_template(&template(), &short).unwrap_err();
    assert!(err.to_string().contains("DEVNET_VERIFIER_ADDRESS"), "{err}");

    values.insert(
        "DEVNET_VALIDATOR6_PUBKEY".to_string(),
        KeyPair::generate().public_key().to_base58(),
    );
    let err = substitute_template(&template(), &values).unwrap_err();
    assert!(
        err.to_string().contains("DEVNET_VALIDATOR6_PUBKEY"),
        "{err}"
    );
}

#[test]
fn a_template_with_fewer_than_five_validator_slots_fails_the_shape_check() {
    let mut doc: serde_json::Value = serde_json::from_str(&template()).unwrap();
    doc["validators"]
        .as_array_mut()
        .unwrap()
        .retain(|v| v != "DEVNET_VALIDATOR5_PUBKEY");
    doc["alloc"]
        .as_object_mut()
        .unwrap()
        .remove("DEVNET_VALIDATOR5_ADDRESS");
    let (mut values, _) = synthetic_values();
    values.remove("DEVNET_VALIDATOR5_PUBKEY");
    values.remove("DEVNET_VALIDATOR5_ADDRESS");

    let json = substitute_template(&doc.to_string(), &values).expect("substitute");
    let g = Genesis::from_json(&json).expect("four validators still load");
    let err = check_topology_shape(&g).expect_err("four validators are too few");
    assert!(err.to_string().contains("at least 5"), "{err}");
}

#[test]
fn the_pool_and_beacon_gates_cannot_be_opened_at_zero() {
    // Issue #118's checklist asks for both gates at Some(0). The loader refuses
    // each of them at 0, so the topology template leaves them null.
    for gate in [
        "compute_pool_enabled_from_height",
        "beacon_enabled_from_height",
    ] {
        let mut doc: serde_json::Value = serde_json::from_str(&template()).unwrap();
        doc["params"][gate] = serde_json::json!(0);
        let (values, _) = synthetic_values();
        let json = substitute_template(&doc.to_string(), &values).expect("substitute");
        assert!(
            Genesis::from_json(&json).is_err(),
            "{gate} = 0 must be refused by the genesis loader"
        );
    }
}

//! Unknown genesis fields are refused (#268).
//!
//! Before this, a misspelled or misplaced field was ignored: a gate written as
//! `beacon_enabled_from_heigth`, or a parameter put one level too high, parsed
//! as "not set". Every object a genesis document is read into now refuses a
//! field it does not define, and the error names the field. That covers the
//! document itself, `params`, and each structure nested in `params`.
//!
//! What is accepted keeps its meaning: the same document parses to the same
//! values and writes back the same JSON (see also
//! `crates/consensus/tests/genesis_strict_fields_identity.rs`, which pins the
//! identity of every tracked genesis file).
//!
//! Keys are synthetic.

use std::collections::HashMap;

use serde_json::{json, Value};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{
    BeaconParamsConfig, ChainParams, DocClassParams, Genesis, GenesisError, MessagingParams,
};
use sumchain_primitives::beacon_schedule::BeaconSchedule;
use sumchain_primitives::{GovernanceParams, StakingParams};

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

/// TEST_ONLY compute-pool values: structurally valid, nothing more.
fn compute_pool_params() -> Value {
    json!({
        "b_offer": 0, "b_commit": 0, "b_check": 0,
        "c_layer": 0, "c_tok": 0, "c_sel": 0, "c_emit": 0,
        "accept_reimb": 0, "commit_verify_reimb": 0, "publish_reimb": 0,
        "observe_reimb": 0, "check_reimb": 0, "settle_reimb": 0, "reassign_reimb": 0,
        "max_work_units": 1, "max_generations": 1, "max_reprovisionable_units": 1,
        "max_attempts_per_unit": 1, "max_reassignments_per_file": 1,
        "k_susp": 0, "w_susp": 0, "s_susp": 0, "n_invite_max": 0,
        "max_retention_files_per_job": 1, "max_retention_updates_per_block": 1,
        "max_reverse_index_entries": 1, "output_availability_blocks": 200,
        "d_avail": 0, "d_ack": 0, "d_final": 0
    })
}

/// A loadable genesis in which every nested parameter structure is present.
fn full_genesis() -> Genesis {
    let params = ChainParams {
        staking: Some(StakingParams::default()),
        messaging: Some(MessagingParams {
            registry_admin: Some(key(40).address().to_base58()),
            ..MessagingParams::default()
        }),
        docclass: Some(DocClassParams {
            admin: Some(key(41).address().to_base58()),
            initial_issuers: vec![key(43).address().to_base58()],
            max_credential_validity: 1_000,
            ..DocClassParams::default()
        }),
        governance: Some(GovernanceParams {
            validator_authority_threshold_bps: 6_000,
            quorum_bps: 3_000,
            pass_threshold_bps: 5_000,
            voting_period_blocks: 1_000,
            max_snapshot_holders: 100,
            proposal_bond: 1_000,
            treasury: Some(key(42).address()),
            min_koppa_for_eligibility: 10,
        }),
        beacon_params: Some(BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: 5,
        }),
        compute_pool_params: Some(serde_json::from_value(compute_pool_params()).unwrap()),
        beacon_schedule: Some(BeaconSchedule {
            start_height: 1_000,
            epoch_length: 10_000,
            key_cutoff_offset: 100,
            deal_start_offset: 200,
            deal_cutoff_offset: 300,
            complaint_start_offset: 400,
            complaint_deadline_offset: 500,
        }),
        inference_settlement_dispute_threshold_bps: Some(100),
        ..ChainParams::default()
    };
    let mut alloc = HashMap::new();
    alloc.insert(key(1).address().to_base58(), 1_000u128);
    Genesis::new(
        7,
        1_700_000_000_000,
        vec![
            key(1).public_key().to_base58(),
            key(2).public_key().to_base58(),
        ],
        alloc,
        params,
    )
}

fn full_value() -> Value {
    serde_json::from_str(&full_genesis().to_json().unwrap()).unwrap()
}

/// The object at a `/`-separated path (`""` is the document itself).
fn object_at<'a>(v: &'a mut Value, path: &str) -> &'a mut serde_json::Map<String, Value> {
    let mut cur = v;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        cur = cur
            .get_mut(part)
            .unwrap_or_else(|| panic!("no {part} in {path}"));
    }
    cur.as_object_mut()
        .unwrap_or_else(|| panic!("{path} is not an object"))
}

/// Rename `field` of the object at `path` to `to`, keeping its value.
fn renamed(path: &str, field: &str, to: &str) -> String {
    let mut v = full_value();
    let obj = object_at(&mut v, path);
    let value = obj
        .remove(field)
        .unwrap_or_else(|| panic!("{path} has no {field}"));
    obj.insert(to.to_string(), value);
    serde_json::to_string_pretty(&v).unwrap()
}

/// Add `field` to the object at `path`.
fn with_extra(path: &str, field: &str, value: Value) -> String {
    let mut v = full_value();
    object_at(&mut v, path).insert(field.to_string(), value);
    serde_json::to_string_pretty(&v).unwrap()
}

/// The loader refuses `text` as JSON, naming `field`.
fn assert_refused_naming(text: &str, field: &str) {
    match Genesis::from_json(text) {
        Err(GenesisError::Json(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains(&format!("unknown field `{field}`")),
                "the error must name `{field}`: {msg}"
            );
        }
        other => panic!("`{field}` must be refused as an unknown field, got {other:?}"),
    }
    // The file loader is the same parser.
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("genesis.json");
    std::fs::write(&file, text).unwrap();
    let err = Genesis::from_file(&file).unwrap_err().to_string();
    assert!(err.contains(&format!("unknown field `{field}`")), "{err}");
}

/// Every object a genesis is read into, with one field it defines.
const OBJECTS: &[(&str, &str)] = &[
    ("", "validators"),
    ("params", "max_txs_per_block"),
    ("params/staking", "epoch_length"),
    ("params/messaging", "daily_quota"),
    ("params/docclass", "admin"),
    ("params/governance", "quorum_bps"),
    ("params/beacon_params", "q_dkg"),
    ("params/compute_pool_params", "max_work_units"),
    ("params/beacon_schedule", "deal_start_offset"),
];

#[test]
fn the_fixture_loads_and_declares_every_nested_structure() {
    let v = full_value();
    Genesis::from_json(&v.to_string()).expect("the fixture is a valid genesis");
    for (path, field) in OBJECTS {
        let mut v = v.clone();
        assert!(
            object_at(&mut v, path).contains_key(*field),
            "{path} must be declared, with {field}"
        );
    }
}

#[test]
fn a_misspelled_field_is_refused_in_every_structure() {
    for (path, field) in OBJECTS {
        // Drop the last letter: the kind of typo that used to read as "unset".
        let typo = &field[..field.len() - 1];
        assert_refused_naming(&renamed(path, field, typo), typo);
        // Transposed letters.
        let mut chars: Vec<char> = field.chars().collect();
        let n = chars.len();
        chars.swap(n - 1, n - 2);
        let swapped: String = chars.into_iter().collect();
        assert_refused_naming(&renamed(path, field, &swapped), &swapped);
    }
}

#[test]
fn an_unknown_field_is_refused_in_every_structure() {
    for (path, _) in OBJECTS {
        assert_refused_naming(&with_extra(path, "not_a_field", json!(1)), "not_a_field");
        assert_refused_naming(&with_extra(path, "not_a_field", Value::Null), "not_a_field");
    }
}

#[test]
fn a_misspelled_gate_is_refused_not_read_as_unset() {
    // A gate that is unset in the fixture, so its misspelling would previously
    // have parsed to exactly the fixture.
    assert_refused_naming(
        &with_extra("params", "beacon_enabled_from_heigth", json!(100)),
        "beacon_enabled_from_heigth",
    );
    assert_refused_naming(
        &with_extra("params", "compute_pool_enabled_from_hieght", json!(100)),
        "compute_pool_enabled_from_hieght",
    );
}

#[test]
fn a_parameter_at_the_wrong_level_is_refused() {
    // A gate written next to `params` instead of inside it.
    assert_refused_naming(
        &with_extra("", "contracts_enabled_from_height", json!(100)),
        "contracts_enabled_from_height",
    );
    // A staking parameter written directly in `params`.
    assert_refused_naming(
        &with_extra("params", "epoch_length", json!(0)),
        "epoch_length",
    );
    // A `params` field written inside a nested structure.
    assert_refused_naming(
        &with_extra("params/staking", "min_fee", json!(1)),
        "min_fee",
    );
}

/// `_comment` is accepted at the top level of the document only, and ignored,
/// as before: `genesis/mainnet_genesis.json` carries one. Anywhere else it is
/// an unknown field like any other.
#[test]
fn a_top_level_comment_is_accepted_and_ignored() {
    let plain = full_genesis().to_json().unwrap();
    for comment in [json!("a note"), json!({"any": ["shape"]}), Value::Null] {
        let text = with_extra("", "_comment", comment);
        let g = Genesis::from_json(&text).expect("a top-level _comment is accepted");
        assert_eq!(
            g.to_json().unwrap(),
            plain,
            "_comment is not kept or interpreted"
        );
    }
    for (path, _) in &OBJECTS[1..] {
        assert_refused_naming(&with_extra(path, "_comment", json!("x")), "_comment");
    }
}

/// Everything the loader writes, it reads back unchanged: the strict readers
/// accept every field each structure serializes, with the same values.
#[test]
fn what_is_written_reads_back_identically() {
    let g = full_genesis();
    let text = g.to_json().unwrap();
    let back = Genesis::from_json(&text).unwrap();
    assert_eq!(back.to_json().unwrap(), text);
    let p = &back.params;
    assert_eq!(p.staking, g.params.staking);
    assert_eq!(p.governance, g.params.governance);
    assert_eq!(p.beacon_params, g.params.beacon_params);
    assert_eq!(p.compute_pool_params, g.params.compute_pool_params);
    assert_eq!(p.beacon_schedule, g.params.beacon_schedule);

    // A staking section with every value moved off its default, so a field the
    // strict reader dropped or swapped could not go unnoticed.
    let staking = StakingParams {
        min_validator_stake: 11,
        max_validators: 12,
        unbonding_period: 13,
        max_commission_bps: 14,
        double_sign_slash_bps: 15,
        downtime_slash_bps: 16,
        double_sign_jail_duration: 17,
        downtime_jail_duration: 18,
        downtime_threshold: 19,
        epoch_length: 0,
        stake_weighted_selection: false,
    };
    let params = ChainParams {
        staking: Some(staking.clone()),
        ..ChainParams::default()
    };
    let json = serde_json::to_string(&params).unwrap();
    let read: ChainParams = serde_json::from_str(&json).unwrap();
    assert_eq!(read.staking, Some(staking));
    assert_eq!(serde_json::to_string(&read).unwrap(), json);
}

/// Absent and `null` nested structures still mean "not declared", and
/// required fields are still required: only unknown fields changed.
#[test]
fn absence_null_and_missing_fields_behave_as_before() {
    for field in [
        "staking",
        "messaging",
        "docclass",
        "governance",
        "beacon_params",
        "compute_pool_params",
        "beacon_schedule",
    ] {
        let mut v = full_value();
        object_at(&mut v, "params").remove(field);
        let absent = Genesis::from_json(&v.to_string()).unwrap();
        object_at(&mut v, "params").insert(field.to_string(), Value::Null);
        let null = Genesis::from_json(&v.to_string()).unwrap();
        assert_eq!(
            absent.to_json().unwrap(),
            null.to_json().unwrap(),
            "{field}"
        );
        let declared = serde_json::to_value(&null.params).unwrap();
        assert_eq!(declared[field], Value::Null, "{field}");
    }
    // A required staking field left out is still "missing", not defaulted.
    let mut v = full_value();
    object_at(&mut v, "params/staking").remove("epoch_length");
    let err = Genesis::from_json(&v.to_string()).unwrap_err().to_string();
    assert!(err.contains("missing field `epoch_length`"), "{err}");
    // So is a required top-level field.
    let mut v = full_value();
    object_at(&mut v, "").remove("genesis_time");
    let err = Genesis::from_json(&v.to_string()).unwrap_err().to_string();
    assert!(err.contains("missing field `genesis_time`"), "{err}");
}

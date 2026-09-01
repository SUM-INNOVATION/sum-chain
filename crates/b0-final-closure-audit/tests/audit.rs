//! Audit of the committed B0-FINAL closure record against the committed protocol +
//! official-evidence manifest. Binds all three at compile time (`include_str!`).

use b0_final_closure_audit::{qualifies, validate};
use serde_json::Value;

const CLOSURE: &str = include_str!("../../../docs/b0-final/b0-final-closure.v1.json");
const PROTOCOL: &str = include_str!("../../../docs/b0-pre/protocol/b0-pre-protocol-v1.json");
const MANIFEST: &str =
    include_str!("../../../docs/b0-final/b0-final-official-evidence-manifest.v1.json");

fn mutate(f: impl FnOnce(&mut Value)) -> String {
    let mut v: Value = serde_json::from_str(CLOSURE).unwrap();
    f(&mut v);
    serde_json::to_string(&v).unwrap()
}

#[test]
fn committed_closure_record_validates() {
    validate(CLOSURE, PROTOCOL, MANIFEST).expect("committed closure record must validate");
}

#[test]
fn risc0_is_the_unique_qualifier_under_frozen_gates() {
    let p: Value = serde_json::from_str(PROTOCOL).unwrap();
    let g = &p["qualification_gates"];
    let gp99 = g["verify_p99_gate_ns"].as_u64().unwrap();
    let m = g["max_accepted_proofs_per_block"].as_u64().unwrap();
    let agg = g["aggregate_verify_budget_ns_per_block"].as_u64().unwrap();
    assert!(
        qualifies(3_200_000, gp99, m, agg),
        "RISC0 (3.2ms) qualifies"
    );
    assert!(
        !qualifies(212_100_000, gp99, m, agg),
        "SP1 (212.1ms) does not"
    );
    let n = [3_200_000u64, 212_100_000]
        .iter()
        .filter(|&&x| qualifies(x, gp99, m, agg))
        .count();
    assert_eq!(n, 1, "exactly one candidate qualifies");
}

#[test]
fn refuses_changed_seal() {
    let s = mutate(|v| v["authority"]["official_seal_blake3"] = Value::from("0".repeat(64)));
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

#[test]
fn refuses_changed_candidate_selection() {
    let s = mutate(|v| {
        v["selection"]["selected"] = Value::from("Sp1");
        v["selection"]["unique_qualifier"] = Value::from("Sp1");
    });
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

#[test]
fn refuses_flipped_verdict() {
    let s = mutate(|v| {
        for c in v["selection"]["candidates"].as_array_mut().unwrap() {
            if c["candidate"].as_str() == Some("Sp1") {
                c["verdict"] = Value::from("qualified");
                c["failed_gates"] = Value::Array(vec![]);
            }
        }
    });
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

#[test]
fn refuses_changed_threshold_constant() {
    let s = mutate(|v| {
        for it in v["included_constants"].as_array_mut().unwrap() {
            if it["name"].as_str() == Some("verify_p99_gate_ns") {
                it["value"] = Value::from(999_000_000u64);
            }
        }
    });
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

#[test]
fn refuses_changed_workload_constant() {
    let s = mutate(|v| {
        for it in v["included_constants"].as_array_mut().unwrap() {
            if it["name"].as_str() == Some("max_output_tokens") {
                it["value"] = Value::from(9999u64);
            }
        }
    });
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

#[test]
fn refuses_changed_evidence_digest() {
    let mut man: Value = serde_json::from_str(MANIFEST).unwrap();
    man["members"][0]["blake3"] = Value::from("0".repeat(64));
    let s = serde_json::to_string(&man).unwrap();
    assert!(validate(CLOSURE, PROTOCOL, &s).is_err());
}

#[test]
fn refuses_prohibited_scope_constant_included() {
    let s = mutate(|v| {
        v["included_constants"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "name": "C_layer", "value": 7, "unit": "cost", "source": "selection:selected"
            }));
    });
    assert!(
        validate(&s, PROTOCOL, MANIFEST).is_err(),
        "prohibited economic/scope constant must be refused"
    );
}

#[test]
fn refuses_included_excluded_overlap() {
    let s = mutate(|v| {
        v["excluded_constants"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "group": "bogus", "names": ["weight_schedule_version"], "owner_issues": [130],
                "reason": "test contradiction"
            }));
    });
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

#[test]
fn refuses_incomplete_excluded_owner() {
    let s = mutate(|v| {
        v["excluded_constants"].as_array_mut().unwrap()[0]["owner_issues"] = Value::Array(vec![]);
    });
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

#[test]
fn refuses_drifted_authority_root() {
    // flip the bound historical tooling authority commit
    let s = mutate(|v| v["authority"]["tooling_authority_commit"] = Value::from("0".repeat(40)));
    assert!(validate(&s, PROTOCOL, MANIFEST).is_err());
}

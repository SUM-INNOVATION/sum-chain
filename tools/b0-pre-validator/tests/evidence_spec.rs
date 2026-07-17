//! Reference agreement with the compact evidence-harness spec fixture: the
//! reference generator+verifier must reproduce the committed result-set hash
//! and aggregates.

use b0_pre_validator::harness;

const SPEC: &str = include_str!("../../../docs/b0-pre/fixtures/evidence-harness/spec.json");

fn hx(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[test]
fn reference_evidence_matches_spec() {
    let j: serde_json::Value = serde_json::from_str(SPEC).unwrap();
    assert_eq!(j["label"].as_str().unwrap(), "NON_SELECTION / TEST_ONLY");
    let e = &j["expected"];

    let ev = harness::generate();
    let r = harness::verify_evidence(&ev).expect("valid");
    assert_eq!(
        hx(&r.result_set_hash),
        e["result_set_hash"].as_str().unwrap()
    );
    assert_eq!(
        r.worst_arch_p99_verify_ns,
        e["worst_arch_p99_verify_ns"].as_u64().unwrap()
    );
    assert_eq!(
        r.max_proof_bytes as u64,
        e["max_proof_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        r.verifier_material_bytes,
        e["verifier_material_bytes"].as_u64().unwrap()
    );
    assert_eq!(
        r.worst_arch_verifier_rss_bytes,
        e["worst_arch_verifier_rss_bytes"].as_u64().unwrap()
    );
    assert_eq!(r.qualification, e["qualification"].as_bool().unwrap());
}

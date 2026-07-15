//! Circularity regression suite for the B0-PRE two-stage lifecycle.
//!
//! Stage 1 computes `b0_pre_spec_hash` over the normative protocol + three
//! Stage-1 categories, BEFORE any guest exists. Guests then embed that hash, so
//! `r0_guest_set_hash` and guest-program identities are derived afterwards and
//! can never feed back into the spec-hash preimage. These tests pin that
//! boundary against re-introducing the inversion.

use b0_pre_validator::protocol::{self, B0PreProtocolV1, PendingInputs};
use b0_pre_validator::schema::bench::{BenchmarkRssRecordV1, BenchmarkSampleV1};
use b0_pre_validator::schema::envelope::R0ProofArtifactEnvelopeV1;
use b0_pre_validator::schema::provenance::ArchRunProvenanceV1;
use b0_pre_validator::schema::result_set::R0ResultSetV1;
use b0_pre_validator::schema::statement::{self, R0ComputationStatementV2};
use b0_pre_validator::{protocol_hash, protocol_hash_preimage, ProtocolHashError};

const STAGE1: [&str; 3] = [
    "candidate_container_digests",
    "cargo_lock_hashes",
    "verifier_material_manifests",
];

#[test]
fn frozen_artifact_blocked_on_exactly_the_three_stage1_categories() {
    let p = B0PreProtocolV1::frozen();
    assert!(!p.is_finalizable());
    assert_eq!(p.finalization.blocked_on, STAGE1);
    assert_eq!(p.pending_inputs.absent(), STAGE1);
}

#[test]
fn resolving_exactly_the_three_categories_makes_it_finalizable() {
    // the TEST_ONLY builder fills exactly the three Stage-1 categories (no guest
    // fields) and becomes finalizable + hashable.
    let p = protocol::test_only_finalizable_artifact();
    assert!(p.is_finalizable());
    assert!(p.semantic_violations().is_empty());
    assert!(
        protocol_hash(&p).is_ok(),
        "spec hash must compute before any guest exists"
    );
}

#[test]
fn pending_inputs_has_no_field_capable_of_accepting_guest_closure() {
    // Every field a fully-populated PendingInputs can serialize — there is no
    // slot for a guest identity or the guest-set hash.
    let full = PendingInputs {
        candidate_container_digests: Some(vec![]),
        cargo_lock_hashes: Some(vec![]),
        verifier_material_manifests: Some(vec![]),
    };
    let obj: serde_json::Value = serde_json::to_value(&full).unwrap();
    let keys: Vec<&str> = obj
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, STAGE1);
    // and deserialization rejects a guest field outright (deny_unknown_fields)
    let bad = r#"{"r0_guest_set_hash":"00"}"#;
    assert!(serde_json::from_str::<PendingInputs>(bad).is_err());
    let bad2 = r#"{"guest_program_identities":[]}"#;
    assert!(serde_json::from_str::<PendingInputs>(bad2).is_err());
}

#[test]
fn guest_closure_never_enters_the_spec_hash_preimage() {
    // The invariant is structural: no guest-closure DATA field exists in the
    // preimage's pending_inputs. (The lifecycle section legitimately names guest
    // closure in prose to document that it is post-spec; that is not a data
    // field and does not feed the hash of any guest identity.)
    let pre = protocol_hash_preimage(&protocol::test_only_finalizable_artifact()).unwrap();
    let json = &pre[b0_pre_validator::tags::SPEC_PREFIX.len()..];
    let v: serde_json::Value = serde_json::from_slice(json).unwrap();
    let pend = v["pending_inputs"].as_object().unwrap();
    for forbidden in [
        "r0_guest_set_hash",
        "guest_program_identities",
        "guest_program_id",
    ] {
        assert!(
            !pend.contains_key(forbidden),
            "pending_inputs must not carry {forbidden}"
        );
    }
    assert_eq!(pend.len(), 3, "exactly the three Stage-1 categories");
}

#[test]
fn final_statement_materialization_requires_the_spec_hash() {
    // A template zeroes the spec-hash range; the final statement inserts it.
    let tlg = b0_pre_validator::workload::build_tlg(b"official-workload-v1", 7);
    let template = statement::template_bytes(tlg.statement.clone());
    let range = R0ComputationStatementV2::SPEC_HASH_RANGE;
    assert!(
        template[range.clone()].iter().all(|&b| b == 0),
        "template must zero the spec-hash range"
    );

    let spec_hash = [0xABu8; 32];
    let final_bytes = statement::materialize_final(&template, &spec_hash).unwrap();
    // final == template everywhere EXCEPT the spec-hash range, which now carries it
    assert_eq!(&final_bytes[range.clone()], &spec_hash);
    let mut reverted = final_bytes.clone();
    reverted[range].copy_from_slice(&[0u8; 32]);
    assert_eq!(
        reverted, template,
        "materialization changes only the spec-hash range"
    );
    assert_ne!(
        final_bytes, template,
        "final statement bytes depend on the spec hash"
    );
}

#[test]
fn lifecycle_orders_spec_hash_before_guest_set() {
    let p = B0PreProtocolV1::frozen();
    let inc = &p.lifecycle.stage1_spec_hash_includes;
    let exc = &p.lifecycle.stage1_spec_hash_excludes;
    let steps = &p.lifecycle.post_spec_hash_steps;

    // guest closure is excluded from Stage 1, never included
    assert!(exc.iter().any(|s| s.contains("r0_guest_set_hash")));
    assert!(exc
        .iter()
        .any(|s| s.to_lowercase().contains("populated") && s.contains("Allowlist")));
    assert!(!inc.iter().any(|s| s.contains("r0_guest_set_hash")));

    // post-spec steps: materialize (needs spec hash) precedes guest build, which
    // precedes computing r0_guest_set_hash
    let idx = |needle: &str| steps.iter().position(|s| s.contains(needle)).unwrap();
    assert!(idx("materialize") < idx("build guests"));
    assert!(idx("build guests") < idx("r0_guest_set_hash"));
}

#[test]
fn r0_time_schemas_still_bind_both_closure_hashes() {
    // Compile-time proof: these field accesses fail to compile if either the
    // b0_pre_spec_hash or r0_guest_set_hash binding is removed from any R0-time
    // schema. Removing guest closure from PendingInputs must not touch these.
    type Both = ([u8; 32], [u8; 32]);
    fn envelope(e: &R0ProofArtifactEnvelopeV1) -> Both {
        (e.b0_pre_spec_hash, e.r0_guest_set_hash)
    }
    fn result_set(r: &R0ResultSetV1) -> Both {
        (r.b0_pre_spec_hash, r.r0_guest_set_hash)
    }
    fn sample(s: &BenchmarkSampleV1) -> Both {
        (s.b0_pre_spec_hash, s.r0_guest_set_hash)
    }
    fn rss(s: &BenchmarkRssRecordV1) -> Both {
        (s.b0_pre_spec_hash, s.r0_guest_set_hash)
    }
    fn provenance(a: &ArchRunProvenanceV1) -> Both {
        (a.b0_pre_spec_hash, a.r0_guest_set_hash)
    }
    // reference the checkers so the field accesses are compiled
    let _: &[fn(&R0ProofArtifactEnvelopeV1) -> Both] = &[envelope];
    let _: &[fn(&R0ResultSetV1) -> Both] = &[result_set];
    let _: &[fn(&BenchmarkSampleV1) -> Both] = &[sample];
    let _: &[fn(&BenchmarkRssRecordV1) -> Both] = &[rss];
    let _: &[fn(&ArchRunProvenanceV1) -> Both] = &[provenance];
}

#[test]
fn frozen_artifact_hash_stays_blocked_until_stage1_inputs_exist() {
    let p = B0PreProtocolV1::frozen();
    assert_eq!(
        protocol_hash(&p),
        Err(ProtocolHashError::NotFinalizable(
            STAGE1.map(String::from).to_vec()
        ))
    );
}

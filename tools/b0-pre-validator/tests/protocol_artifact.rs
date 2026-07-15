//! The committed normative artifact is byte-locked to `protocol::frozen()`,
//! strict-parses, validates against its committed schema, is `not_finalizable`,
//! and rejects unknown fields.

use b0_pre_validator::protocol::B0PreProtocolV1;

const ARTIFACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/protocol/b0-pre-protocol-v1.json"
));
const SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/protocol/b0-pre-protocol-v1.schema.json"
));

#[test]
fn artifact_byte_locked_to_frozen_model() {
    let regen = format!(
        "{}\n",
        serde_json::to_string_pretty(&B0PreProtocolV1::frozen()).unwrap()
    );
    assert_eq!(
        regen, ARTIFACT,
        "committed artifact drifted from protocol::frozen(); re-run `cargo run --example emit_protocol`"
    );
}

#[test]
fn artifact_is_not_finalizable_and_semantically_consistent() {
    let p = B0PreProtocolV1::frozen();
    assert!(!p.is_finalizable());
    assert_eq!(p.finalization.state, "not_finalizable");
    assert_eq!(
        p.finalization.blocked_on,
        vec![
            "candidate_container_digests",
            "cargo_lock_hashes",
            "verifier_material_manifests",
        ]
    );
    assert!(
        p.semantic_violations().is_empty(),
        "{:?}",
        p.semantic_violations()
    );
    // both official statements present, distinct indices
    assert_eq!(p.official_statements.statements.len(), 2);
    assert_ne!(
        p.official_statements.statements[0].statement_index,
        p.official_statements.statements[1].statement_index
    );
    // toolchains stay distinct (1.85 floor vs 1.88 container)
    assert_ne!(
        p.toolchains.validator_tool_rust_floor,
        p.toolchains.candidate_container_rust
    );
}

#[test]
fn committed_artifact_strict_parses_and_canonicalizes() {
    let v = b0_pre_validator::json::parse_strict(ARTIFACT.as_bytes()).expect("strict parse");
    let canon = b0_pre_validator::json::to_canonical(&v).expect("canonical");
    let v2 = b0_pre_validator::json::parse_strict(&canon).expect("strict re-parse");
    assert_eq!(b0_pre_validator::json::to_canonical(&v2).unwrap(), canon);
    // The canonicalizer rejects null values outright (NullForbidden); a
    // successful canonicalization is itself the proof that the artifact carries
    // no null — absent optional fields are omitted.
}

fn schema_errors(schema: serde_json::Value, inst: serde_json::Value) -> Vec<String> {
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("compile schema");
    let mut msgs = Vec::new();
    match compiled.validate(&inst) {
        Ok(()) => {}
        Err(errors) => {
            msgs = errors
                .map(|e| format!("{e} @ {}", e.instance_path))
                .collect();
        }
    }
    msgs
}

#[test]
fn artifact_validates_against_committed_schema() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    let inst: serde_json::Value = serde_json::from_str(ARTIFACT).unwrap();
    let errs = schema_errors(schema, inst);
    assert!(
        errs.is_empty(),
        "artifact failed schema validation: {errs:?}"
    );
}

#[test]
fn semantic_validation_catches_inconsistencies_json_schema_cannot() {
    // lying about finalization state while pending inputs are absent
    let mut a = B0PreProtocolV1::frozen();
    a.finalization.state = "finalizable".into();
    assert!(a
        .semantic_violations()
        .iter()
        .any(|s| s.contains("finalization.state")));

    // dimensions exceeding the official bounds
    let mut b = B0PreProtocolV1::frozen();
    b.dimensions.d_model = 9;
    assert!(b
        .semantic_violations()
        .iter()
        .any(|s| s.contains("d_model exceeds")));

    // collapsing the two distinct toolchains
    let mut c = B0PreProtocolV1::frozen();
    c.toolchains.candidate_container_rust = c.toolchains.validator_tool_rust_floor.clone();
    assert!(c
        .semantic_violations()
        .iter()
        .any(|s| s.contains("distinct")));

    // dropping an official statement
    let mut d = B0PreProtocolV1::frozen();
    d.official_statements.statements.pop();
    assert!(d
        .semantic_violations()
        .iter()
        .any(|s| s.contains("two official statements")));
}

#[test]
fn deny_unknown_fields_rejects_extra_keys() {
    let mut v: serde_json::Value = serde_json::from_str(ARTIFACT).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("bogus_key".into(), serde_json::json!(1));
    let parsed: Result<B0PreProtocolV1, _> = serde_json::from_str(&v.to_string());
    assert!(
        parsed.is_err(),
        "deny_unknown_fields must reject extra keys"
    );
}

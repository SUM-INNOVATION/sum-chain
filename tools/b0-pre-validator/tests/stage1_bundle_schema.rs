//! The committed Stage-1 result-bundle JSON Schema is byte-locked to the typed
//! Rust model: regenerating it with `schemars` must reproduce the committed file
//! exactly, and every object must forbid additional properties.

use b0_pre_validator::schema::stage1_bundle::Stage1ResultBundleV1;

const SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/protocol/stage1-result-bundle-v1.schema.json"
));

#[test]
fn stage1_bundle_schema_byte_locked_to_typed_model() {
    let regen = format!(
        "{}\n",
        serde_json::to_string_pretty(&schemars::schema_for!(Stage1ResultBundleV1)).unwrap()
    );
    assert_eq!(
        regen, SCHEMA,
        "committed stage1 bundle schema drifted; re-run `cargo run --example emit_stage1_bundle_schema`"
    );
}

#[test]
fn stage1_bundle_schema_forbids_additional_properties_everywhere() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    // root
    assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    // every named definition is CLOSED: an object forbids additional properties; a
    // string classification enum is closed by its `enum` value list.
    let defs = schema["definitions"]
        .as_object()
        .expect("definitions present");
    assert!(!defs.is_empty());
    for (name, def) in defs {
        if def.get("properties").is_some() || def["type"] == serde_json::json!("object") {
            assert_eq!(
                def["additionalProperties"],
                serde_json::json!(false),
                "object definition {name} must forbid additional properties"
            );
        } else {
            // a scalar / enum definition (e.g. BundleClassification) must be closed
            // to an explicit value set.
            assert!(
                def.get("enum").and_then(|e| e.as_array()).is_some(),
                "non-object definition {name} must be a closed enum"
            );
        }
    }
}

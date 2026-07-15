//! The committed JSON Schema is byte-locked to the typed Rust model: regenerating
//! it with `schemars` must reproduce the committed file exactly.

use b0_pre_validator::protocol::B0PreProtocolV1;

const SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/protocol/b0-pre-protocol-v1.schema.json"
));

#[test]
fn schema_byte_locked_to_typed_model() {
    let regen = format!(
        "{}\n",
        serde_json::to_string_pretty(&schemars::schema_for!(B0PreProtocolV1)).unwrap()
    );
    assert_eq!(
        regen, SCHEMA,
        "committed schema drifted from the typed model; re-run `cargo run --example emit_protocol_schema`"
    );
}

#[test]
fn schema_forbids_additional_properties_on_root() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
    assert_eq!(
        schema["additionalProperties"],
        serde_json::json!(false),
        "root object must forbid additional properties"
    );
}

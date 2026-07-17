//! Generate the committed JSON Schema for `b0-pre-protocol-v1` from the
//! authoritative typed Rust model with `schemars`. The schema is byte-locked by
//! `tests/protocol_schema.rs`, and the artifact is validated against it with the
//! `jsonschema` crate.

use std::fs;
use std::path::Path;

use b0_pre_validator::protocol::B0PreProtocolV1;

fn main() {
    let schema = schemars::schema_for!(B0PreProtocolV1);
    let json = serde_json::to_string_pretty(&schema).expect("serialize schema");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/protocol");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(
        dir.join("b0-pre-protocol-v1.schema.json"),
        format!("{json}\n"),
    )
    .expect("write");
    eprintln!(
        "wrote b0-pre-protocol-v1.schema.json ({} bytes)",
        json.len() + 1
    );
}

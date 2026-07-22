//! Generate the committed JSON Schema for the strict Stage-1 result bundle
//! (`b0-pre-stage1-result-bundle-v1`) from the authoritative typed Rust model
//! with `schemars`. Every object forbids additional properties. The schema is
//! byte-locked by `tests/stage1_bundle_schema.rs`.

use std::fs;
use std::path::Path;

use b0_pre_validator::schema::stage1_bundle::Stage1ResultBundleV1;

fn main() {
    let schema = schemars::schema_for!(Stage1ResultBundleV1);
    let json = serde_json::to_string_pretty(&schema).expect("serialize schema");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/protocol");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(
        dir.join("stage1-result-bundle-v1.schema.json"),
        format!("{json}\n"),
    )
    .expect("write");
    eprintln!(
        "wrote stage1-result-bundle-v1.schema.json ({} bytes)",
        json.len() + 1
    );
}

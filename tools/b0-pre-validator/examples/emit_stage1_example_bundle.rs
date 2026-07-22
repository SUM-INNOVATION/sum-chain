//! Emit a TEST_ONLY, structurally-valid `b0-pre-stage1-result-bundle-v1` to
//! stdout by driving the PRODUCTION Stage-6 assembler with real-shaped synthetic
//! venue outputs (no real installer metadata required).
//!
//! It is NOT venue evidence and it is NOT the production bridge: the assembler is.
//! This example is a thin caller of `stage6::test_only_bundle`, so there is one
//! bundle-construction path. Its container/lock digests are synthetic (BLAKE3 of
//! labels), its verifier-material identities are genuine (computed through the
//! shared canonical primitive), and its tool identities carry the
//! `TEST_ONLY_SYNTHETIC` sentinel. The emitted bundle is `TEST_ONLY`-classified, so
//! `stage1-ingest` REFUSES it (only `AUTHORITATIVE_STAGE1` reaches finalization);
//! use `stage6-assemble --validate-test-only <bundle>` to exercise its full
//! validation without any route to a finalizable artifact.

use b0_pre_validator::schema::stage6::test_only_bundle;

fn main() {
    let bundle = test_only_bundle();
    println!("{}", serde_json::to_string_pretty(&bundle).unwrap());
}

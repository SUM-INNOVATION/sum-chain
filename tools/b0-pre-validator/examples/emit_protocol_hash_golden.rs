//! Emit TEST_ONLY canonical preimage golden vectors for the protocol hash path.
//!
//! Uses a synthetic *finalizable* artifact (fixed placeholder values, not real
//! digests). The produced hash is NOT the real `b0_pre_spec_hash`; it only pins
//! the canonical-JSON + `SPEC_PREFIX` preimage construction so it cannot drift.

use std::fs;
use std::path::Path;

use b0_pre_validator::protocol::test_only_finalizable_artifact;
use b0_pre_validator::tags::SPEC_PREFIX;
use b0_pre_validator::{canonical_protocol_json, protocol_hash, protocol_hash_preimage};

fn hx(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn main() {
    let p = test_only_finalizable_artifact();
    assert!(
        p.semantic_violations().is_empty(),
        "{:?}",
        p.semantic_violations()
    );
    assert!(p.is_finalizable());

    let canon = canonical_protocol_json(&p).expect("canon");
    let preimage = protocol_hash_preimage(&p).expect("preimage");
    let hash = protocol_hash(&p).expect("hash");

    assert!(
        preimage.starts_with(SPEC_PREFIX),
        "preimage must start with SPEC_PREFIX"
    );
    assert_eq!(preimage.len(), SPEC_PREFIX.len() + canon.len());

    // The SPEC_PREFIX ends in a newline (0x0a), which cannot appear in a
    // strict-canonical B0-PRE string; it is carried only as hex.
    let json = format!(
        "{{\n  \"label\": \"TEST_ONLY canonical preimage golden vectors; synthetic finalizable \
         artifact; NOT the real b0_pre_spec_hash\",\n  \"spec_prefix_hex\": \"{}\",\n  \
         \"canonical_json_len\": {},\n  \"canonical_json_blake3\": \"{}\",\n  \"preimage_len\": \
         {},\n  \"preimage_blake3\": \"{}\"\n}}\n",
        hx(SPEC_PREFIX),
        canon.len(),
        hx(blake3::hash(&canon).as_bytes()),
        preimage.len(),
        hx(&hash),
    );

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/protocol");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("hash-golden.json"), json).expect("write");
    eprintln!(
        "wrote hash-golden.json: preimage_len={} hash={}",
        preimage.len(),
        hx(&hash)
    );
}

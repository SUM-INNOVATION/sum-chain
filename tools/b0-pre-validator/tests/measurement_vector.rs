//! The committed real-orchestrator measurement vector: deterministically
//! regenerable through `measurement.rs`, both bundles accepted/rejected exactly as
//! the frozen rules require, and every record bound to the merged `b0_pre_spec_hash`
//! plus the canonical `r0_guest_set_hash` recomputed from the committed allowlist.

use b0_pre_validator::enums::Candidate;
use b0_pre_validator::harness::verify_evidence;
use b0_pre_validator::hashing;
use b0_pre_validator::measurement::{deterministic_demo_vector, parse_vector, serialize_vector};
use b0_pre_validator::schema::allowlist::GuestProgramAllowlistV1;
use b0_pre_validator::schema::result_set::R0ResultSetV1;

const VECTOR: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/fixtures/measurement-vector/real-orchestrator-vector.bin"
));
const FINGERPRINT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/fixtures/measurement-vector/real-orchestrator-vector.bin.blake3"
));
const MERGED_SPEC_HEX: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";

fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}
fn spec_bytes() -> [u8; 32] {
    let mut a = [0u8; 32];
    for (i, byte) in a.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&MERGED_SPEC_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

#[test]
fn vector_is_deterministically_regenerable() {
    // Re-run the real orchestrator; the bytes and fingerprint must match the
    // committed fixture exactly. Drift => re-run emit_measurement_vector + review.
    let (allowlist, mia, report, inv, bundles) = deterministic_demo_vector();
    let bytes = serialize_vector(&allowlist, &mia, &report, &inv, &bundles);
    assert_eq!(
        bytes.len(),
        VECTOR.len(),
        "regenerated vector length drifted from the committed fixture"
    );
    assert!(
        bytes == VECTOR,
        "regenerated vector bytes drifted; re-run `cargo run --example emit_measurement_vector` and review"
    );
    assert_eq!(
        hx(&hashing::plain(VECTOR)),
        FINGERPRINT.trim(),
        "committed .blake3 fingerprint drifted from the vector"
    );
}

#[test]
fn both_bundles_verify_exactly_as_the_frozen_rules_require() {
    let (allowlist_bytes, _mia, _report, _inv, bundles) =
        parse_vector(VECTOR).expect("vector parses");
    // Recompute the canonical guest-set hash from the committed allowlist.
    let gs = GuestProgramAllowlistV1::decode_exact(&allowlist_bytes)
        .expect("allowlist decodes")
        .guest_set_hash();
    let spec = spec_bytes();
    assert_eq!(bundles.len(), 2);

    let mut saw_sp1 = false;
    let mut saw_risc0 = false;
    for (candidate, ev) in &bundles {
        let rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        assert_eq!(
            rs.b0_pre_spec_hash, spec,
            "binds the merged b0_pre_spec_hash"
        );
        assert_eq!(
            rs.r0_guest_set_hash, gs,
            "binds the canonical guest-set hash recomputed from the allowlist"
        );
        match candidate {
            Candidate::Sp1 => {
                saw_sp1 = true;
                let r = verify_evidence(ev).expect("SP1 complete native matrix verifies");
                assert!(r.qualification, "SP1 qualifies (p99 < gate)");
                assert_eq!(rs.completeness.measured_proof_count, 40);
            }
            Candidate::Risc0 => {
                saw_risc0 = true;
                let e = verify_evidence(ev).expect_err("RISC0 x86-only matrix is disqualified");
                assert!(
                    e.contains("MeasuredProofGrid") || e.contains("completeness"),
                    "RISC0 aarch64 absent -> incomplete grid; got: {e}"
                );
            }
        }
    }
    assert!(saw_sp1 && saw_risc0, "both candidate bundles present");
}

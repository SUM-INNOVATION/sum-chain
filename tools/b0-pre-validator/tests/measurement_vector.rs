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
const MERGED_SPEC_HEX: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";

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
    let (allowlist, mia, report, inv, elig, bundles) = deterministic_demo_vector();
    let bytes = serialize_vector(&allowlist, &mia, &report, &inv, &elig, &bundles);
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
    let (allowlist_bytes, _mia, _report, _inv, _elig, bundles) =
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
        // Two-cell model: BOTH candidates carry their complete x86_64-only native matrix (20 proofs)
        // and BOTH verify + qualify — they are the two eligible measurement cells. aarch64 is never
        // measured, so no bundle implies ARM performance.
        assert_eq!(
            rs.completeness.measured_proof_count, 20,
            "x86_64-only grid → 20 measured proofs"
        );
        for m in &rs.measured_proofs {
            assert_eq!(
                m.arch,
                b0_pre_validator::enums::Arch::X86_64,
                "no aarch64 measured cell may exist"
            );
        }
        let r = verify_evidence(ev).expect("complete x86_64-only native matrix verifies");
        assert!(r.qualification, "p99 < gate → qualifies");
        match candidate {
            Candidate::Sp1 => saw_sp1 = true,
            Candidate::Risc0 => saw_risc0 = true,
        }
    }
    assert!(saw_sp1 && saw_risc0, "both candidate bundles present");
}

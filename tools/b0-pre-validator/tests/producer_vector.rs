//! The committed producer self-test vector (TEST-ONLY): deterministically
//! regenerable by `measure-produce --dry-run`, and accepted byte-for-byte by the
//! reference verifier for SP1 (qualified) and rejected for RISC0 (x86-only →
//! `MeasuredProofGrid`). The independent crate re-verifies the same bytes in
//! `tools/b0-pre-independent/tests/producer_vector.rs`.

use b0_pre_validator::enums::Candidate;
use b0_pre_validator::harness::verify_evidence;
use b0_pre_validator::hashing;
use b0_pre_validator::measurement::parse_vector;
use b0_pre_validator::producer::{dry_run_raw_facts, produce};
use b0_pre_validator::schema::allowlist::GuestProgramAllowlistV1;
use b0_pre_validator::schema::result_set::R0ResultSetV1;

const VECTOR: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/fixtures/producer-selftest/producer-dry-run-testonly.bin"
));
const FINGERPRINT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/fixtures/producer-selftest/producer-dry-run-testonly.bin.blake3"
));

fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn producer_selftest_vector_is_deterministically_regenerable() {
    let pkg = produce(&dry_run_raw_facts()).expect("producer dry-run assembles");
    assert!(
        pkg.vector == VECTOR,
        "measure-produce --dry-run drifted from the committed self-test vector; re-run it and review"
    );
    assert_eq!(
        hx(&hashing::plain(VECTOR)),
        FINGERPRINT.trim(),
        "committed .blake3 (package_id) drifted"
    );
    assert_eq!(hx(&pkg.package_id), FINGERPRINT.trim());
}

#[test]
fn producer_vector_both_bundles_verify_and_bind_guest_set() {
    let (allowlist_bytes, _mia, _report, _inv, bundles) =
        parse_vector(VECTOR).expect("vector parses");
    let gs = GuestProgramAllowlistV1::decode_exact(&allowlist_bytes)
        .expect("allowlist decodes")
        .guest_set_hash();
    assert_eq!(bundles.len(), 2);
    for (candidate, ev) in &bundles {
        let rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        assert_eq!(
            rs.r0_guest_set_hash, gs,
            "record binds the guest-set hash recomputed from the allowlist"
        );
        match candidate {
            Candidate::Sp1 => assert!(verify_evidence(ev).unwrap().qualification),
            Candidate::Risc0 => {
                let e = verify_evidence(ev).unwrap_err();
                assert!(
                    e.contains("MeasuredProofGrid") || e.contains("completeness"),
                    "RISC0 x86-only → disqualified; got: {e}"
                );
            }
        }
    }
}

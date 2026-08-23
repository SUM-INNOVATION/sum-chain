//! INDEPENDENT mirror of the validator's `dependency_seed_anchor_*` tests: the sealed-import cargo
//! dependency-SEED anchor (`closure::bind_dependency_seed`) binds a double-build proof's fresh-per-build
//! cargo seed to the from-scratch-authenticated, retained `DependencySeedV1`. The triple is taken from a
//! real `harness::generate()` bundle (attestation + double-build proof + the sealed per-candidate
//! dependency-seed JSON), so the positive case exercises the exact bytes the harness seals; the negatives
//! reproduce the reference's decisive substitution attacks.

use b0_pre_independent::closure;
use b0_pre_independent::dependency_seed::DependencySeedV1;
use b0_pre_independent::harness;

/// A consistent (attestation, double-build proof, retained DependencySeedV1) triple from a generated SP1
/// bundle: the proof's cargo seed origin (== materialized A == B) equals the dep-seed's host-cargo-home
/// seed-content, and the attestation binds the dep-seed's authenticated record address.
fn dep_seed_triple() -> (
    closure::RunnerAtt,
    closure::DoubleBuildProof,
    DependencySeedV1,
) {
    let ev = harness::generate(); // SP1 / X86_64
    let att = closure::decode_runner_attestation(&ev.runner_attestations[0])
        .expect("attestation decodes");
    let proof = closure::decode_runner_double_build_proof(&ev.double_build_proofs[0])
        .expect("double-build proof decodes");
    let seed =
        DependencySeedV1::from_json(&ev.dependency_seed_json).expect("dep-seed JSON decodes");
    (att, proof, seed)
}

#[test]
fn dependency_seed_anchor_positive() {
    let (att, proof, seed) = dep_seed_triple();
    closure::bind_dependency_seed(&att, &proof, &seed).unwrap();
}

#[test]
fn dependency_seed_anchor_mutually_edited_proof_refused() {
    // THE DECISIVE NEGATIVE: forge origin == A == B to the SAME value (so the proof's OWN 3-way equality
    // enforced by `bind_runner_recipe` still holds) but keep the AUTHENTIC retained seed. The anchor
    // refuses because the origin no longer equals the independently-authenticated seed's host content.
    let (att, mut proof, seed) = dep_seed_triple();
    let forged = [0x99u8; 32];
    proof.cargo_seed_origin_blake3 = forged;
    proof.build_a.materialized_cargo_seed_blake3 = forged;
    proof.build_b.materialized_cargo_seed_blake3 = forged;
    let e = closure::bind_dependency_seed(&att, &proof, &seed).unwrap_err();
    assert!(
        e.contains("cargo_seed_origin != retained dependency-seed"),
        "got: {e}"
    );
}

#[test]
fn dependency_seed_anchor_edit_both_refused_via_record_address() {
    // Editing BOTH the proof (origin/A/B) AND the retained seed's host content to agree STILL fails:
    // mutating the seed's host unit seed_address changes its recomputed record address, which no longer
    // equals the attestation's bound dependency_seed_address (the seed's own authority binding).
    let (att, mut proof, _seed) = dep_seed_triple();
    let forged = [0x99u8; 32];
    proof.cargo_seed_origin_blake3 = forged;
    proof.build_a.materialized_cargo_seed_blake3 = forged;
    proof.build_b.materialized_cargo_seed_blake3 = forged;
    let (json2, _addr2) = DependencySeedV1::synthetic_json("sp1", forged); // host == forged
    let seed2 = DependencySeedV1::from_json(&json2).unwrap();
    let e = closure::bind_dependency_seed(&att, &proof, &seed2).unwrap_err();
    assert!(
        e.contains("record address != attestation dependency_seed_address"),
        "got: {e}"
    );
}

#[test]
fn dependency_seed_anchor_cross_candidate_refused() {
    // A risc0 dependency-seed under an sp1 attestation is refused by verify(candidate).
    let (att, proof, _seed) = dep_seed_triple(); // att candidate = sp1
    let (json_r0, _a) = DependencySeedV1::synthetic_json("risc0", [1u8; 32]);
    let seed_r0 = DependencySeedV1::from_json(&json_r0).unwrap();
    let e = closure::bind_dependency_seed(&att, &proof, &seed_r0).unwrap_err();
    assert!(e.to_lowercase().contains("candidate"), "got: {e}");
}

#[test]
fn dependency_seed_anchor_cross_arch_refused() {
    let (mut att, proof, seed) = dep_seed_triple();
    att.arch = 2; // proof.arch stays 1 (X86_64)
    let e = closure::bind_dependency_seed(&att, &proof, &seed).unwrap_err();
    assert!(e.contains("candidate/arch"), "got: {e}");
}

#[test]
fn dependency_seed_anchor_mutated_record_refused() {
    // A mutated retained seed (a changed graph hash, `address` left stale) recomputes to a different
    // address and is refused by its own authority binding.
    let (att, proof, seed) = dep_seed_triple();
    let mut bad = seed.clone();
    bad.graphs[0].lock_sha256 = "0".repeat(64);
    assert!(closure::bind_dependency_seed(&att, &proof, &bad).is_err());
}

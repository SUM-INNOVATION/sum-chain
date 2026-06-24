//! Pure-logic tests for the Proof Eligibility Registry (v1, register-only).
//!
//! `REGISTRY` is empty in v1, so identity/resolution behaviour is exercised on
//! synthetic in-test records. These prove the full-tuple identity contract:
//! records that share hashes but differ in `halo2_version` or `backend_id` are
//! *distinct profiles* and do not supersede each other.

use sumchain_primitives::proof_eligibility::{
    all_records, current_record, is_admissible, is_current, EligibilityState,
    ProofEligibilityRecord, ProofSystem, REGISTER_ONLY_DISCLAIMER, REGISTRY,
};

/// Build a synthetic record. All three hashes are fixed, so identity differs
/// only by `backend_id` / `halo2_version` / `proof_system` — exactly the fields
/// the full-tuple key must distinguish beyond the hashes.
fn record(
    entry_id: u32,
    supersedes_entry_id: Option<u32>,
    backend_id: &'static str,
    halo2_version: &'static str,
    state: EligibilityState,
) -> ProofEligibilityRecord {
    ProofEligibilityRecord {
        entry_id,
        supersedes_entry_id,
        proof_system: ProofSystem::Stage11dProductionFixedPointMlp,
        backend_id,
        model_format: "ProductionFixedPointMlp",
        circuit_id: [0xAA; 32],
        model_hash: [0xBB; 32],
        verification_key_hash: [0xCC; 32],
        halo2_version,
        eligibility_state: state,
        state_reason: "test",
        chain_team_review_ref: "test-ref",
        note: REGISTER_ONLY_DISCLAIMER,
    }
}

#[test]
fn registry_is_mechanism_only_with_no_active_record() {
    assert!(REGISTRY.is_empty(), "v1 ships mechanism-only: zero records");
    assert!(all_records().is_empty());
    // Invariant survives future record additions: no Active record may ship
    // without an explicit governance PR.
    assert!(
        !all_records()
            .iter()
            .any(|r| matches!(r.eligibility_state, EligibilityState::Active)),
        "no Active record may ship in this PR"
    );
}

#[test]
fn same_hashes_different_halo2_version_are_distinct_profiles() {
    let a = record(
        1,
        None,
        "backend-x",
        "halo2-0.3.0",
        EligibilityState::CandidateRefused,
    );
    let b = record(
        2,
        None,
        "backend-x",
        "halo2-0.3.1",
        EligibilityState::CandidateRefused,
    );
    let recs = [a, b];

    assert_ne!(
        a.profile_key(),
        b.profile_key(),
        "halo2_version disambiguates"
    );
    // Distinct profiles: both are current, neither supersedes the other.
    assert!(is_current(&recs, &a));
    assert!(is_current(&recs, &b));
    assert_eq!(current_record(&recs, &a.profile_key()).unwrap().entry_id, 1);
    assert_eq!(current_record(&recs, &b.profile_key()).unwrap().entry_id, 2);
}

#[test]
fn same_hashes_different_backend_id_are_distinct_profiles() {
    let a = record(
        1,
        None,
        "backend-x",
        "halo2-0.3.0",
        EligibilityState::CandidateRefused,
    );
    let b = record(
        2,
        None,
        "backend-y",
        "halo2-0.3.0",
        EligibilityState::CandidateRefused,
    );
    let recs = [a, b];

    assert_ne!(a.profile_key(), b.profile_key(), "backend_id disambiguates");
    assert!(is_current(&recs, &a));
    assert!(is_current(&recs, &b));
    assert_eq!(current_record(&recs, &a.profile_key()).unwrap().entry_id, 1);
    assert_eq!(current_record(&recs, &b.profile_key()).unwrap().entry_id, 2);
}

#[test]
fn same_key_supersession_resolves_to_head() {
    let a = record(
        1,
        None,
        "backend-x",
        "halo2-0.3.0",
        EligibilityState::CandidateRefused,
    );
    let c = record(
        3,
        Some(1),
        "backend-x",
        "halo2-0.3.0",
        EligibilityState::Active,
    );
    let recs = [a, c];

    assert_eq!(a.profile_key(), c.profile_key(), "same identity tuple");
    assert!(!is_current(&recs, &a), "superseded record is not current");
    assert!(is_current(&recs, &c));
    assert_eq!(current_record(&recs, &a.profile_key()).unwrap().entry_id, 3);
}

#[test]
fn cross_key_supersede_is_ignored() {
    // `d` points at entry 1 but differs in halo2_version, so its supersede
    // pointer crosses profile keys and must NOT mark entry 1 non-current.
    let a = record(
        1,
        None,
        "backend-x",
        "halo2-0.3.0",
        EligibilityState::CandidateRefused,
    );
    let d = record(
        4,
        Some(1),
        "backend-x",
        "halo2-9.9.9",
        EligibilityState::Active,
    );
    let recs = [a, d];

    assert_ne!(a.profile_key(), d.profile_key());
    assert!(is_current(&recs, &a), "cross-key supersede is ignored");
    assert!(is_current(&recs, &d));
    assert_eq!(current_record(&recs, &a.profile_key()).unwrap().entry_id, 1);
}

#[test]
fn admission_refuses_non_active_and_gates_active() {
    let candidate = record(1, None, "b", "h", EligibilityState::CandidateRefused);
    let revoked = record(2, None, "b", "h", EligibilityState::Revoked);
    let active = record(3, None, "b", "h", EligibilityState::Active);

    // CandidateRefused / Revoked: refused by construction, regardless of gate.
    assert!(!is_admissible(&candidate, Some(0), 100));
    assert!(!is_admissible(&revoked, Some(0), 100));
    // Active but gate closed: refused.
    assert!(!is_admissible(&active, None, 100));
    // Active but below activation height: refused.
    assert!(!is_admissible(&active, Some(200), 100));
    // Active and gate open at/after height: admissible.
    assert!(is_admissible(&active, Some(100), 100));
    assert!(is_admissible(&active, Some(50), 100));
}

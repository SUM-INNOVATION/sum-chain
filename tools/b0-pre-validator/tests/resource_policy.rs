//! Regression suite for the corrected B0-PRE contributor-resource policy.
//!
//! Preregistration correction: OmniNode participation is device-neutral (no
//! hardware/resource eligibility); prover performance is reported-only and never
//! gates or breaks ties; the validator-side verification baseline still bounds
//! chain-side verification (on DETECTED hardware, not just configured limits);
//! and paired candidates must run on the SAME controlled host, enforced inside
//! the real verification path. These tests lock that intent against regression.

use b0_pre_validator::enums::{Arch, Candidate, ProvenanceRole};
use b0_pre_validator::golden;
use b0_pre_validator::harness;
use b0_pre_validator::protocol::B0PreProtocolV1;
use b0_pre_validator::schema::provenance::ArchRunProvenanceV1;
use b0_pre_validator::validation::{self, Reason};

fn proving() -> ArchRunProvenanceV1 {
    golden::official_provenance_proving()
}

fn verification() -> ArchRunProvenanceV1 {
    let mut v = proving();
    v.provenance_role = ProvenanceRole::Verification;
    v.physical_core_count = 4;
    v.logical_cpu_count = 8;
    v.total_ram_bytes = 8u64 << 30;
    v.configured_cpuset_core_limit = 4;
    v.configured_memory_limit_bytes = 8u64 << 30;
    v
}

// (1) A low-resource contributor record is schema-valid and not disqualified for
//     its hardware.
#[test]
fn low_resource_contributor_is_schema_valid_and_eligible() {
    let mut p = proving();
    p.physical_core_count = 2;
    p.logical_cpu_count = 2;
    p.total_ram_bytes = 4u64 << 30;
    p.configured_cpuset_core_limit = 1;
    p.configured_memory_limit_bytes = 1u64 << 30;
    // schema-valid: canonical encode/decode roundtrips
    assert_eq!(ArchRunProvenanceV1::decode_exact(&p.encode()).unwrap(), p);
    // not disqualified for its hardware
    assert_eq!(validation::provenance_eligible(&p), Ok(()));

    // a 1-core / 512-MiB device is likewise eligible
    p.physical_core_count = 1;
    p.total_ram_bytes = 512u64 << 20;
    assert_eq!(validation::provenance_eligible(&p), Ok(()));
}

// (2) Prover time / RAM / cores never change qualification or the B0-FINAL
//     tie-break.
#[test]
fn prover_performance_never_gates_or_breaks_ties() {
    // Behavioral: proving eligibility is invariant across wildly different sizes.
    let small = {
        let mut p = proving();
        p.physical_core_count = 1;
        p.total_ram_bytes = 1u64 << 30;
        p.configured_cpuset_core_limit = 1;
        p.configured_memory_limit_bytes = 1u64 << 30;
        p
    };
    let huge = {
        let mut p = proving();
        p.physical_core_count = 256;
        p.total_ram_bytes = 1024u64 << 30;
        p.configured_cpuset_core_limit = 200; // would have failed the old 35% cap
        p.configured_memory_limit_bytes = 900u64 << 30;
        p
    };
    assert_eq!(validation::provenance_eligible(&small), Ok(()));
    assert_eq!(
        validation::provenance_eligible(&small),
        validation::provenance_eligible(&huge),
    );

    // Declared: prover performance is never-disqualifying and tie-break-excluded.
    let a = B0PreProtocolV1::frozen();
    assert!(a
        .qualification_criteria
        .never_disqualifies
        .iter()
        .any(|s| s.contains("prover wall-clock time")));
    assert!(a
        .qualification_criteria
        .never_disqualifies
        .iter()
        .any(|s| s.contains("prover peak RAM")));
    assert!(a
        .aggregation
        .tiebreak_excludes
        .iter()
        .any(|s| s.contains("prover wall-clock time")));
    assert!(
        a.aggregation
            .b0_final_tiebreak
            .iter()
            .all(|s| !s.to_lowercase().contains("prover")),
        "the B0-FINAL tie-break must not mention prover performance"
    );
}

// (3) Validator verification limits still disqualify a candidate that exceeds
//     them, on DETECTED hardware as well as configured limits.
#[test]
fn validator_verification_limits_still_bind() {
    // The reference baseline (>= 4 detected cores, >= 8 GiB detected RAM, pinned
    // 4-core / 8-GiB configured run) is enforced.
    assert_eq!(validation::provenance_eligible(&verification()), Ok(()));

    // detected hardware below the reference minimum is rejected
    let mut under_phys = verification();
    under_phys.physical_core_count = 2;
    assert_eq!(
        validation::provenance_eligible(&under_phys),
        Err(Reason::ProvenanceIneligible("verify_phys"))
    );
    let mut under_ram = verification();
    under_ram.total_ram_bytes = 4u64 << 30;
    assert_eq!(
        validation::provenance_eligible(&under_ram),
        Err(Reason::ProvenanceIneligible("verify_ram"))
    );

    // configured verification run not pinned to exactly 4 cores / 8 GiB rejected
    let mut over_cores = verification();
    over_cores.configured_cpuset_core_limit = 8;
    assert_eq!(
        validation::provenance_eligible(&over_cores),
        Err(Reason::ProvenanceIneligible("verify_cpuset"))
    );
    let mut over_mem = verification();
    over_mem.configured_memory_limit_bytes = 16u64 << 30;
    assert_eq!(
        validation::provenance_eligible(&over_mem),
        Err(Reason::ProvenanceIneligible("verify_mem"))
    );

    // A candidate that fails the verify p99 gate is a consistent DISQUALIFIED
    // result: completeness accepts the disqualification (does not mask it), and
    // claiming it qualified while carrying a failure code is rejected.
    let mut disq = golden::official_result_set();
    disq.aggregates.worst_arch_p99_verify_ns = harness::P99_GATE_NS + 1;
    disq.qualification_result = false;
    disq.failure_codes = vec![3];
    assert_eq!(validation::validate_official_completeness(&disq), Ok(()));
    disq.qualification_result = true;
    assert_eq!(
        validation::validate_official_completeness(&disq),
        Err(Reason::QualificationInconsistent)
    );
}

// (4) Paired benchmark environment mismatches are rejected on every controlled
//     host/environment field (including DETECTED cores/RAM: the "same physical
//     host" rule); candidate-specific identity differences do not trigger it.
#[test]
fn paired_environment_mismatch_rejected() {
    let a = proving();

    // identical controlled host/environment is consistent
    assert_eq!(
        validation::paired_environment_consistent(&a, &proving()),
        Ok(())
    );

    // candidate-specific identity differences do NOT trigger an environment
    // mismatch (they differ by design between the two candidates)
    let mut other_candidate = proving();
    other_candidate.candidate = Candidate::Risc0;
    other_candidate.guest_program_id = [0x77; 32];
    other_candidate.candidate_dep_lock_hash = [0x88; 32];
    other_candidate.verifier_material_manifest_hash = [0x99; 32];
    other_candidate.builder_container_digest = [0xAA; 32];
    assert_eq!(
        validation::paired_environment_consistent(&a, &other_candidate),
        Ok(())
    );

    // every controlled host/environment field difference is rejected
    type Mutate = fn(&mut ArchRunProvenanceV1);
    let cases: &[(&'static str, Mutate)] = &[
        ("arch", |p| p.arch = Arch::Aarch64),
        ("host_os", |p| p.host_os = "other-os".into()),
        ("kernel", |p| p.kernel = "9.9.9".into()),
        ("cpu_vendor", |p| p.cpu_vendor = "OtherVendor".into()),
        ("cpu_model", |p| p.cpu_model = "other-cpu".into()),
        ("physical_core_count", |p| p.physical_core_count = 999),
        ("logical_cpu_count", |p| p.logical_cpu_count += 1),
        ("total_ram_bytes", |p| p.total_ram_bytes = 999u64 << 30),
        ("cpuset", |p| p.configured_cpuset_core_limit += 1),
        ("memlimit", |p| p.configured_memory_limit_bytes += 1),
        ("governor", |p| p.governor = "powersave".into()),
        ("turbo", |p| p.turbo_enabled = true),
        ("clock_source", |p| p.clock_source = "hpet".into()),
        ("cgroup_version", |p| p.cgroup_version = 1),
        ("cgroup_scope_label", |p| {
            p.cgroup_scope_label = "other.slice".into()
        }),
        ("benchmark_harness_source_hash", |p| {
            p.benchmark_harness_source_hash[0] ^= 1
        }),
    ];
    for &(tag, mutate) in cases {
        let mut b = proving();
        mutate(&mut b);
        assert_eq!(
            validation::paired_environment_consistent(&a, &b),
            Err(Reason::PairedEnvironmentMismatch(tag)),
            "field {tag} must trigger a paired-environment mismatch"
        );
    }
}

// (5) Incomplete / watchdog-terminated runs cannot close R0 but are NOT candidate
//     disqualifications: the failure is a structural completeness reason, never a
//     resource / performance / eligibility reason.
#[test]
fn incomplete_run_blocks_r0_without_being_a_disqualification() {
    let mut rs = golden::official_result_set();
    // A watchdog timeout drops the last measured proof -> the grid is incomplete.
    rs.measured_proofs.pop();
    let err = validation::validate_official_completeness(&rs).unwrap_err();
    // Cannot close R0 ...
    assert!(matches!(
        err,
        Reason::MeasuredProofGrid | Reason::CompletenessCount(_)
    ));
    // ... but the reason is structural incompleteness, never a resource /
    // performance / eligibility disqualification.
    assert!(!matches!(
        err,
        Reason::ProvenanceIneligible(_) | Reason::PairedEnvironmentMismatch(_)
    ));

    // The normative artifact frames the prove watchdog as run-management only.
    let a = B0PreProtocolV1::frozen();
    assert!(a
        .contributor_resource_policy
        .prove_watchdog
        .to_lowercase()
        .contains("not a candidate performance failure"));
}

// (6) The integrated paired-verification path accepts the official SP1 fixture
//     paired with a same-host RISC0 peer (candidate-specific identity
//     differences do not trip pairing), and rejects pairing a bundle with itself.
#[test]
fn official_fixture_passes_integrated_pairing() {
    let sp1 = harness::generate();
    let risc0 = harness::generate_candidate(Candidate::Risc0);
    assert_eq!(
        harness::verify_paired_evidence(&sp1, &risc0),
        Ok(()),
        "official SP1 fixture paired with a same-host RISC0 peer must pass"
    );
    // same candidate on both sides is not a valid pair
    assert!(harness::verify_paired_evidence(&sp1, &sp1).is_err());
}

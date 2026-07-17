//! R0 closure validation (plan §13/§15/§23): the completeness, non-mixability,
//! and aggregate-recomputation rules that gate B0-FINAL selection. This layer
//! sits on top of the byte decoders and is mirrored, independently, by
//! `b0-pre-independent` — a bug in a single implementation could admit mixed or
//! incomplete evidence, so both must agree.

use crate::consts;
use crate::enums::{Arch, MetricKind, ProvenanceRole, RssScope, SampleKind, StatementIndex};
use crate::schema::envelope::R0ProofArtifactEnvelopeV1;
use crate::schema::provenance::ArchRunProvenanceV1;
use crate::schema::result_set::R0ResultSetV1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    MeasuredProofGrid,
    ProvenanceSet,
    CompletenessCount(&'static str),
    SampleSum(&'static str),
    RssSum(&'static str),
    QualificationInconsistent,
    RecordMixed(&'static str),
    ProvenanceIneligible(&'static str),
    PairedEnvironmentMismatch(&'static str),
}

/// The exact set of `(arch, statement, iteration)` keys an official result set
/// must contain — 2 architectures × 2 statements × 10 iterations, in canonical
/// ascending order.
pub fn expected_proof_grid() -> Vec<(u8, u8, u32)> {
    let mut v = Vec::with_capacity(consts::OFFICIAL_MEASURED_PROOFS as usize);
    for arch in [Arch::X86_64, Arch::Aarch64] {
        for stmt in [StatementIndex::Tlg, StatementIndex::SelectToken] {
            for iter in 0..consts::OFFICIAL_ITERATIONS_PER_CELL {
                v.push((arch.to_repr(), stmt.to_repr(), iter));
            }
        }
    }
    v
}

/// The exact 4 `(arch, role)` provenance snapshots.
pub fn expected_provenance_set() -> Vec<(u8, u8)> {
    let mut v = Vec::with_capacity(consts::OFFICIAL_PROVENANCE_SNAPSHOTS as usize);
    for arch in [Arch::X86_64, Arch::Aarch64] {
        for role in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
            v.push((arch.to_repr(), role.to_repr()));
        }
    }
    v
}

/// Enforce every frozen completeness rule against a decoded result set.
pub fn validate_official_completeness(rs: &R0ResultSetV1) -> Result<(), Reason> {
    let keys: Vec<(u8, u8, u32)> = rs
        .measured_proofs
        .iter()
        .map(|m| {
            (
                m.arch.to_repr(),
                m.statement_index.to_repr(),
                m.iteration_index,
            )
        })
        .collect();
    if keys != expected_proof_grid() {
        return Err(Reason::MeasuredProofGrid);
    }

    let pkeys: Vec<(u8, u8)> = rs
        .arch_provenance
        .iter()
        .map(|a| (a.arch.to_repr(), a.role.to_repr()))
        .collect();
    if pkeys != expected_provenance_set() {
        return Err(Reason::ProvenanceSet);
    }

    let c = &rs.completeness;
    if c.measured_proof_count != consts::OFFICIAL_MEASURED_PROOFS {
        return Err(Reason::CompletenessCount("measured_proof_count"));
    }
    if c.verify_timing_sample_count != consts::OFFICIAL_VERIFY_TIMING_SAMPLES {
        return Err(Reason::CompletenessCount("verify_timing_sample_count"));
    }
    if c.proving_time_sample_count != consts::OFFICIAL_PROVE_TIME_SAMPLES {
        return Err(Reason::CompletenessCount("proving_time_sample_count"));
    }
    if c.proving_run_rss_count != consts::OFFICIAL_PROVING_RUN_RSS {
        return Err(Reason::CompletenessCount("proving_run_rss_count"));
    }
    if c.verify_batch_rss_count != consts::OFFICIAL_VERIFY_BATCH_RSS {
        return Err(Reason::CompletenessCount("verify_batch_rss_count"));
    }

    let measured_sum = |metric: MetricKind| -> u64 {
        rs.sample_bundles
            .iter()
            .filter(|b| b.sample_kind == SampleKind::Measured && b.metric_kind == metric)
            .map(|b| b.sample_count as u64)
            .sum()
    };
    if measured_sum(MetricKind::HostVerifyNs) != consts::OFFICIAL_VERIFY_TIMING_SAMPLES as u64 {
        return Err(Reason::SampleSum("host_verify_ns"));
    }
    if measured_sum(MetricKind::HostProveWrapNs) != consts::OFFICIAL_PROVE_TIME_SAMPLES as u64 {
        return Err(Reason::SampleSum("host_prove_wrap_ns"));
    }
    if measured_sum(MetricKind::ProofBytes) != consts::OFFICIAL_PROOF_BYTES_SAMPLES as u64 {
        return Err(Reason::SampleSum("proof_bytes"));
    }
    if measured_sum(MetricKind::HostSetupNs) != consts::OFFICIAL_SETUP_SAMPLES as u64 {
        return Err(Reason::SampleSum("host_setup_ns"));
    }

    let rss_sum = |scope: RssScope| -> u64 {
        rs.rss_bundles
            .iter()
            .filter(|b| b.rss_scope == scope)
            .map(|b| b.record_count as u64)
            .sum()
    };
    if rss_sum(RssScope::ProvingRun) != consts::OFFICIAL_PROVING_RUN_RSS as u64 {
        return Err(Reason::RssSum("proving_run"));
    }
    if rss_sum(RssScope::VerifyBatch) != consts::OFFICIAL_VERIFY_BATCH_RSS as u64 {
        return Err(Reason::RssSum("verify_batch"));
    }

    // Qualified ⇒ no disqualifying failure codes; not qualified ⇒ at least one.
    // Valid iff qualification_result == failure_codes.is_empty().
    if rs.qualification_result != rs.failure_codes.is_empty() {
        return Err(Reason::QualificationInconsistent);
    }
    Ok(())
}

/// Every raw record must bind the same spec / guest-set / candidate / material
/// identities as the result set, and reference one of the two official
/// statements. Rejects cross-protocol/guest-set/candidate/material/statement
/// mixing.
pub fn envelope_binds_result_set(
    env: &R0ProofArtifactEnvelopeV1,
    rs: &R0ResultSetV1,
) -> Result<(), Reason> {
    if env.b0_pre_spec_hash != rs.b0_pre_spec_hash {
        return Err(Reason::RecordMixed("b0_pre_spec_hash"));
    }
    if env.r0_guest_set_hash != rs.r0_guest_set_hash {
        return Err(Reason::RecordMixed("r0_guest_set_hash"));
    }
    if env.candidate != rs.candidate {
        return Err(Reason::RecordMixed("candidate"));
    }
    if env.verifier_material_manifest_hash != rs.verifier_material_manifest_hash {
        return Err(Reason::RecordMixed("verifier_material"));
    }
    let sh = env.computation_statement_hash;
    if sh != rs.official_statement_hash_tlg && sh != rs.official_statement_hash_st {
        return Err(Reason::RecordMixed("statement"));
    }
    Ok(())
}

/// Controlled-benchmark measurement integrity plus the validator verification
/// baseline for a provenance snapshot (plan §23, as corrected).
///
/// Proving contributors have NO hardware/resource eligibility: no minimum CPU,
/// RAM, GPU, storage, or device class. A proving snapshot's cores, RAM, and
/// cpuset/memory limits are recorded (reported-only) and never gate — a valid
/// proof from any device is protocol-eligible; a slower device only takes
/// longer. What is still enforced is (a) measurement-environment integrity,
/// which is device-neutral (any device can meet it on the controlled benchmark
/// host), and (b) the controlled chain-verification reference envelope for the
/// Verification role: the run must be configured to exactly the reference cpuset
/// and memory limit (2 cores / 4 GiB). Detected host hardware is NOT gated --
/// validators have no CPU/RAM minimum; this is a candidate-comparison envelope,
/// not a hardware-eligibility gate. Qualification is performance-based (verify
/// p99 / per-block budget), enforced over the result set.
pub fn provenance_eligible(p: &ArchRunProvenanceV1) -> Result<(), Reason> {
    // Provenance self-consistency (evidence integrity, NOT hardware eligibility):
    // a configured limit cannot exceed the detected resource it constrains, and
    // resource values must be nonzero. This rejects impossible records (e.g. a
    // 2-core cpuset on a host reporting fewer than 2 logical CPUs, or a 4-GiB
    // limit above detected RAM) without imposing any absolute hardware minimum.
    if p.physical_core_count == 0
        || p.logical_cpu_count == 0
        || p.total_ram_bytes == 0
        || p.configured_cpuset_core_limit == 0
        || p.configured_memory_limit_bytes == 0
    {
        return Err(Reason::ProvenanceIneligible("zero_resource"));
    }
    if p.configured_cpuset_core_limit > p.logical_cpu_count {
        return Err(Reason::ProvenanceIneligible("cpuset_exceeds_logical"));
    }
    if p.configured_memory_limit_bytes > p.total_ram_bytes {
        return Err(Reason::ProvenanceIneligible("memlimit_exceeds_ram"));
    }
    // Controlled-benchmark measurement integrity (both roles). Not a
    // hardware-size gate; excludes no device class.
    if p.governor != "performance" {
        return Err(Reason::ProvenanceIneligible("governor"));
    }
    if p.turbo_enabled {
        return Err(Reason::ProvenanceIneligible("turbo"));
    }
    if p.dirty_tree_flag {
        return Err(Reason::ProvenanceIneligible("dirty"));
    }
    match p.provenance_role {
        // No proving-role hardware/resource gate: cores, RAM, and cpuset/memory
        // limits are reported-only.
        ProvenanceRole::Proving => {}
        ProvenanceRole::Verification => {
            // Controlled reference envelope: the verification run must be
            // configured to exactly the reference cpuset / memory limit. Detected
            // hardware is NOT gated -- any machine able to establish these limits
            // qualifies; there is no validator CPU/RAM minimum.
            if p.configured_cpuset_core_limit != consts::VALIDATOR_VERIFY_REFERENCE_CORES {
                return Err(Reason::ProvenanceIneligible("verify_cpuset"));
            }
            if p.configured_memory_limit_bytes != consts::VALIDATOR_VERIFY_REFERENCE_RAM_BYTES {
                return Err(Reason::ProvenanceIneligible("verify_mem"));
            }
        }
    }
    Ok(())
}

/// Fair-benchmark pairing: for a given `(architecture, provenance_role)`, the two
/// candidates' provenance must represent the SAME controlled host and
/// environment, so their measurements are comparable. This enforces the "same
/// physical host" rule: not only the configured cpuset/memory knobs but the
/// detected hardware (physical/logical cores, total RAM, CPU vendor/model), the
/// OS/kernel/clock, the cgroup scope, and the benchmark-harness identity must
/// match. Candidate-specific identities (guest program id, lock hash, verifier
/// material, container digest) are deliberately NOT compared — those differ by
/// design. Device neutrality means there is no absolute minimum for a
/// contributor; it does NOT mean the two paired candidates may run on different
/// hardware.
pub fn paired_environment_consistent(
    a: &ArchRunProvenanceV1,
    b: &ArchRunProvenanceV1,
) -> Result<(), Reason> {
    let m = Reason::PairedEnvironmentMismatch;
    if a.arch != b.arch {
        return Err(m("arch"));
    }
    if a.host_os != b.host_os {
        return Err(m("host_os"));
    }
    if a.kernel != b.kernel {
        return Err(m("kernel"));
    }
    if a.cpu_vendor != b.cpu_vendor {
        return Err(m("cpu_vendor"));
    }
    if a.cpu_model != b.cpu_model {
        return Err(m("cpu_model"));
    }
    if a.physical_core_count != b.physical_core_count {
        return Err(m("physical_core_count"));
    }
    if a.logical_cpu_count != b.logical_cpu_count {
        return Err(m("logical_cpu_count"));
    }
    if a.total_ram_bytes != b.total_ram_bytes {
        return Err(m("total_ram_bytes"));
    }
    if a.configured_cpuset_core_limit != b.configured_cpuset_core_limit {
        return Err(m("cpuset"));
    }
    if a.configured_memory_limit_bytes != b.configured_memory_limit_bytes {
        return Err(m("memlimit"));
    }
    if a.governor != b.governor {
        return Err(m("governor"));
    }
    if a.turbo_enabled != b.turbo_enabled {
        return Err(m("turbo"));
    }
    if a.clock_source != b.clock_source {
        return Err(m("clock_source"));
    }
    if a.cgroup_version != b.cgroup_version {
        return Err(m("cgroup_version"));
    }
    if a.cgroup_scope_label != b.cgroup_scope_label {
        return Err(m("cgroup_scope_label"));
    }
    if a.benchmark_harness_source_hash != b.benchmark_harness_source_hash {
        return Err(m("benchmark_harness_source_hash"));
    }
    Ok(())
}

/// Result-set failure code: worst-arch verify p99 exceeds the per-proof gate.
pub const FAILCODE_VERIFY_P99: u16 = 3;
/// Result-set failure code: the aggregate per-block verification budget is
/// exceeded (or the checked multiplication overflows).
pub const FAILCODE_VERIFY_AGGREGATE: u16 = 4;

/// The two frozen chain-verification performance gates, evaluated INDEPENDENTLY:
/// the per-proof p99 gate (`worst_arch_p99_verify_ns <= p99_gate_ns`) and the
/// aggregate per-block gate (`worst_arch_p99_verify_ns * max_proofs_per_block <=
/// aggregate_budget_ns`, checked; overflow => fail). Gates are passed explicitly
/// so callers/tests can exercise them independently; do not rely on the numerical
/// coincidence that `max_proofs * p99_gate == aggregate_budget`.
pub fn qualification_gates_pass(
    worst_arch_p99_verify_ns: u64,
    max_proofs_per_block: u64,
    p99_gate_ns: u64,
    aggregate_budget_ns: u64,
) -> bool {
    let p99_ok = worst_arch_p99_verify_ns <= p99_gate_ns;
    let aggregate_ok = match worst_arch_p99_verify_ns.checked_mul(max_proofs_per_block) {
        Some(agg) => agg <= aggregate_budget_ns,
        None => false, // overflow => over budget
    };
    p99_ok && aggregate_ok
}

/// `qualification_gates_pass` bound to the frozen official constants. Called by
/// the real evidence verifier, not only by tests.
pub fn official_qualification(worst_arch_p99_verify_ns: u64) -> bool {
    qualification_gates_pass(
        worst_arch_p99_verify_ns,
        consts::MAX_ACCEPTED_PROOFS_PER_BLOCK,
        crate::harness::P99_GATE_NS,
        consts::VALIDATOR_AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK,
    )
}

/// Sorted failure codes for the performance gates a given worst-arch p99 fails
/// (empty iff `official_qualification` is true).
pub fn qualification_failure_codes(worst_arch_p99_verify_ns: u64) -> Vec<u16> {
    let mut v = Vec::new();
    if worst_arch_p99_verify_ns > crate::harness::P99_GATE_NS {
        v.push(FAILCODE_VERIFY_P99);
    }
    let over_budget =
        match worst_arch_p99_verify_ns.checked_mul(consts::MAX_ACCEPTED_PROOFS_PER_BLOCK) {
            Some(agg) => agg > consts::VALIDATOR_AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK,
            None => true, // overflow => over budget
        };
    if over_budget {
        v.push(FAILCODE_VERIFY_AGGREGATE);
    }
    v
}

/// Nearest-rank p99 of an ascending-sorted slice (the frozen aggregation).
pub fn nearest_rank_p99(sorted_ascending: &[u64]) -> Option<u64> {
    let n = sorted_ascending.len();
    if n == 0 {
        return None;
    }
    // rank = ceil(0.99 * n), 1-based
    let rank = (99 * n).div_ceil(100).max(1);
    Some(sorted_ascending[rank - 1])
}

/// Maximum of a slice (frozen aggregation for proof bytes / RSS).
pub fn max_u64(values: &[u64]) -> Option<u64> {
    values.iter().copied().max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden;

    #[test]
    fn official_result_set_is_complete() {
        assert_eq!(
            validate_official_completeness(&golden::official_result_set()),
            Ok(())
        );
    }

    #[test]
    fn wrong_measured_count_rejected() {
        let mut rs = golden::official_result_set();
        rs.completeness.measured_proof_count = 39;
        assert_eq!(
            validate_official_completeness(&rs),
            Err(Reason::CompletenessCount("measured_proof_count"))
        );
    }

    #[test]
    fn missing_proof_breaks_grid() {
        let mut rs = golden::official_result_set();
        rs.measured_proofs.pop();
        assert_eq!(
            validate_official_completeness(&rs),
            Err(Reason::MeasuredProofGrid)
        );
    }

    #[test]
    fn dropping_a_provenance_snapshot_rejected() {
        let mut rs = golden::official_result_set();
        rs.arch_provenance.pop();
        assert_eq!(
            validate_official_completeness(&rs),
            Err(Reason::ProvenanceSet)
        );
    }

    #[test]
    fn short_verify_bundle_sum_rejected() {
        let mut rs = golden::official_result_set();
        // knock 1 off a host_verify_ns bundle so the measured sum != 4000
        for b in &mut rs.sample_bundles {
            if matches!(b.metric_kind, MetricKind::HostVerifyNs) {
                b.sample_count -= 1;
                break;
            }
        }
        assert_eq!(
            validate_official_completeness(&rs),
            Err(Reason::SampleSum("host_verify_ns"))
        );
    }

    #[test]
    fn qualified_with_failures_rejected() {
        let mut rs = golden::official_result_set();
        rs.failure_codes = vec![3];
        assert_eq!(
            validate_official_completeness(&rs),
            Err(Reason::QualificationInconsistent)
        );
    }

    #[test]
    fn envelope_binding_matches_and_rejects_mismatch() {
        let rs = golden::official_result_set();
        let env = golden::official_envelope();
        assert_eq!(envelope_binds_result_set(&env, &rs), Ok(()));

        let mut e2 = env.clone();
        e2.r0_guest_set_hash[0] ^= 0x01;
        assert_eq!(
            envelope_binds_result_set(&e2, &rs),
            Err(Reason::RecordMixed("r0_guest_set_hash"))
        );

        let mut e3 = env.clone();
        e3.computation_statement_hash = [0xEE; 32]; // neither official statement
        assert_eq!(
            envelope_binds_result_set(&e3, &rs),
            Err(Reason::RecordMixed("statement"))
        );
    }

    #[test]
    fn p99_nearest_rank_and_max() {
        let v: Vec<u64> = (1..=100).collect(); // 1..100 ascending
        assert_eq!(nearest_rank_p99(&v), Some(99)); // ceil(0.99*100)=99 -> index 98 -> value 99
        assert_eq!(max_u64(&v), Some(100));
        assert_eq!(nearest_rank_p99(&[]), None);
    }
}

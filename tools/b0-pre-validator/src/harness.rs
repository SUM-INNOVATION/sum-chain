//! Deterministic R0 evidence harness (NON_SELECTION / TEST_ONLY).
//!
//! `generate()` builds the full canonical evidence grid from a compact seed —
//! 40 proof envelopes; 4000 measured `host_verify_ns`, 40 `host_prove_wrap_ns`,
//! 40 `proof_bytes`, and 40 `host_setup_ns` samples; 40 proving-run + 40
//! verify-batch RSS records; 4 provenance snapshots; and the canonical
//! verifier-material manifest — plus the `R0ResultSetV1` whose bundle hashes and
//! aggregates are *derived from* those raw records.
//!
//! `verify_evidence()` decodes every record, enforces the full binding matrix
//! (spec/guest-set/candidate/material/program/lock/container/statement/
//! provenance), the exact proof grid, per-record classification, and
//! recomputes every bundle hash, the verifier-material byte total (from the
//! canonical manifest), and every aggregate from the raw bytes, rejecting any
//! disagreement with the result set. `host_setup_ns` is one per initialized
//! verification batch and is excluded from `host_verify_ns` and the p99.
//!
//! All timings are synthetic test data; they are NOT selection evidence and are
//! not part of `b0_pre_spec_hash`.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::enums::{
    Arch, Candidate, MetricKind, ProvenanceRole, RssScope, SampleKind, StatementIndex, Status,
    Unit, VerifierMaterialRole,
};
use crate::schema::bench::{BenchmarkRssRecordV1, BenchmarkSampleV1};
use crate::schema::cpuset_chain::CpusetProbeChainV1;
use crate::schema::envelope::R0ProofArtifactEnvelopeV1;
use crate::schema::identity_record::Phase1IdentityRecordV1;
use crate::schema::provenance::{ArchRunProvenanceV1, DvfsProvenance};
use crate::schema::result_set::{
    Aggregates, ArchProvenanceRef, Completeness, MeasuredProofRef, R0ResultSetV1, RssBundle,
    SampleBundle,
};
use crate::schema::runner_attestation::RunnerAttestationV1;
use crate::schema::verifier_material::{VerifierMaterialEntry, VerifierMaterialManifestV1};
use crate::tags::{RSSBUNDLE_PREFIX, SAMPLEBUNDLE_PREFIX};
use crate::validation::nearest_rank_p99;

pub const NON_SELECTION_LABEL: &str = "NON_SELECTION / TEST_ONLY";
pub const SEED: [u8; 32] = [0x5A; 32];
pub const P99_GATE_NS: u64 = 75_000_000;
/// SP1's single immutable Groth16 verifying-key blob byte length. This is SP1's
/// value ONLY — never a cross-candidate constant, universal max, or
/// encoded-manifest size. The verifier-material byte total is checked
/// per-candidate against that candidate's own manifest, never against this
/// literal (see `generate_with` / `verify_evidence`).
pub const SP1_GROTH16_VK_BYTES: u64 = 292;
/// RISC Zero's four Groth16-receipt material blobs (TEST_ONLY synthetic lengths;
/// distinct per role and summing to a total that is deliberately not SP1's 292).
const RISC0_GROTH16_VK_BYTES: u64 = 256;
const RISC0_CONTROL_ROOT_BYTES: u64 = 32;
const RISC0_CONTROL_ID_BYTES: u64 = 32;
const RISC0_VERIFIER_PARAMS_BYTES: u64 = 32;
const REPS: u32 = 100;
const ARCHES: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];
const STMTS: [StatementIndex; 2] = [StatementIndex::Tlg, StatementIndex::SelectToken];
// bundle metric order per cell (ascending discriminant): prove(4), verify(5), setup(6), proof_bytes(7)
const BUNDLE_METRICS: [MetricKind; 4] = [
    MetricKind::HostProveWrapNs,
    MetricKind::HostVerifyNs,
    MetricKind::HostSetupNs,
    MetricKind::ProofBytes,
];

type SortKey = ([u8; 32], u32);
type RawRec = (SortKey, Vec<u8>);
type HashCount = ([u8; 32], u32);

fn id(label: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&SEED);
    h.update(label);
    h.finalize().into()
}
fn spec_hash() -> [u8; 32] {
    id(b"spec")
}
fn guest_set_hash() -> [u8; 32] {
    id(b"guest_set")
}
/// Per-candidate identities. Environment stays candidate-independent (a paired
/// benchmark runs both candidates on the same host); only these differ by
/// candidate. Sp1's values equal the historical labels, so the committed
/// evidence fixture stays byte-stable.
#[derive(Clone, Copy)]
struct Ids {
    candidate: Candidate,
    program: [u8; 32],
    lock: [u8; 32],
    container: [u8; 32],
    builder: [u8; 32],
    vk: [u8; 32],
}
fn ids_for(candidate: Candidate) -> Ids {
    let lbl = |base: &[u8]| -> [u8; 32] {
        match candidate {
            Candidate::Sp1 => id(base),
            Candidate::Risc0 => {
                let mut v = base.to_vec();
                v.extend_from_slice(b"_risc0");
                id(&v)
            }
        }
    };
    Ids {
        candidate,
        program: lbl(b"program"),
        lock: lbl(b"lock"),
        container: lbl(b"container"),
        builder: lbl(b"builder"),
        vk: lbl(b"vk"),
    }
}

/// Per-role detected/configured resources recorded in a provenance snapshot.
#[derive(Clone, Copy)]
struct RoleRes {
    phys: u32,
    logical: u32,
    ram: u64,
    cpuset: u32,
    mem: u64,
}

/// The controlled host/environment recorded in every provenance snapshot. Both
/// paired candidates must share it (enforced by `paired_environment_consistent`);
/// `default_env()` reproduces the historical fixture exactly.
#[derive(Clone)]
struct Env {
    host_os: String,
    kernel: String,
    cpu_vendor: String,
    cpu_model: String,
    governor: String,
    clock_source: String,
    cgroup_scope_label: String,
    turbo: bool,
    cgroup_version: u8,
    proving: RoleRes,
    verification: RoleRes,
    harness_hash: [u8; 32],
    envcap_hash: [u8; 32],
}
fn default_env() -> Env {
    Env {
        host_os: "linux".into(),
        kernel: "6.8.0".into(),
        cpu_vendor: "GenuineIntel".into(),
        cpu_model: "test".into(),
        governor: "performance".into(),
        clock_source: "tsc".into(),
        cgroup_scope_label: "b0-pre.slice".into(),
        turbo: false,
        cgroup_version: 2,
        proving: RoleRes {
            phys: 16,
            logical: 32,
            ram: 64u64 << 30,
            cpuset: 5,
            mem: 22u64 << 30,
        },
        verification: RoleRes {
            phys: 2,
            logical: 4,
            ram: 4u64 << 30,
            cpuset: 2,
            mem: 4u64 << 30,
        },
        harness_hash: id(b"harness"),
        envcap_hash: id(b"envcap"),
    }
}
fn stmt_hash(s: StatementIndex) -> [u8; 32] {
    match s {
        StatementIndex::Tlg => id(b"stmt_tlg"),
        StatementIndex::SelectToken => id(b"stmt_st"),
    }
}
fn proof_hash(a: Arch, s: StatementIndex, iter: u32) -> [u8; 32] {
    id(&[b"proof", &[a.to_repr(), s.to_repr(), iter as u8][..]].concat())
}

fn verifier_material_for(ids: Ids) -> VerifierMaterialManifestV1 {
    match ids.candidate {
        // SP1: one groth16_vk blob. The historical uppercase label is retained so
        // the committed evidence fixture stays byte-stable; it is synthetic R0
        // timing evidence, not the canonical extractor path.
        Candidate::Sp1 => VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![VerifierMaterialEntry {
                label: "GROTH16_VK_BYTES".to_string(),
                role: VerifierMaterialRole::Groth16Vk,
                byte_len: SP1_GROTH16_VK_BYTES,
                hash: ids.vk,
            }],
        },
        // RISC Zero: the four canonical roles its Groth16 receipt path consumes.
        // Distinct byte lengths -> a per-candidate total that is not SP1's 292.
        Candidate::Risc0 => VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [
                (
                    VerifierMaterialRole::Groth16Vk,
                    RISC0_GROTH16_VK_BYTES,
                    ids.vk,
                ),
                (
                    VerifierMaterialRole::ControlRoot,
                    RISC0_CONTROL_ROOT_BYTES,
                    id(b"risc0_control_root"),
                ),
                (
                    VerifierMaterialRole::ControlId,
                    RISC0_CONTROL_ID_BYTES,
                    id(b"risc0_control_id"),
                ),
                (
                    VerifierMaterialRole::VerifierParams,
                    RISC0_VERIFIER_PARAMS_BYTES,
                    id(b"risc0_verifier_params"),
                ),
            ],
        ),
    }
}
/// SP1 verifier material (public no-arg API preserved).
pub fn verifier_material() -> VerifierMaterialManifestV1 {
    verifier_material_for(ids_for(Candidate::Sp1))
}
fn vmat_id(ids: Ids) -> [u8; 32] {
    // The harness builds statically-canonical (byte-encodable) manifests; the
    // fallible codec cannot fail here, so surfacing the error as a panic is a
    // genuine invariant, not silent handling on the authority path.
    verifier_material_for(ids)
        .identity()
        .expect("harness verifier-material manifest encodes")
}

/// Build a synthetic provenance record PLUS its two retained artifacts, all mutually consistent
/// (the two content addresses are derived FROM the artifacts, never placeholders).
fn provenance(
    a: Arch,
    role: ProvenanceRole,
    ids: Ids,
    env: &Env,
) -> (
    ArchRunProvenanceV1,
    CpusetProbeChainV1,
    RunnerAttestationV1,
    Phase1IdentityRecordV1,
    crate::schema::runner_build_recipe::RunnerBuildRecipeV1,
    crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    crate::schema::runner_double_build_proof::RunnerDoubleBuildProofV1,
    crate::schema::runner_leakage_report::RunnerLeakageReportV1,
) {
    let r = match role {
        ProvenanceRole::Proving => env.proving,
        ProvenanceRole::Verification => env.verification,
    };
    let scope = env.cgroup_scope_label.clone();
    let raw = format!("0-{}", r.cpuset.saturating_sub(1));
    let entries = crate::measurement::leaf_cpuset_chain(&scope, &raw);
    let cpuset_probe_chain_blake3 = crate::schema::provenance::cpuset_probe_chain_hash(&entries);
    // The retained Phase-1 identity record (production_binary_blake3 == the synth runner_blake3).
    let record = crate::measurement::synth_phase1_identity_record(
        ids.candidate,
        a,
        &"0".repeat(40),
        spec_hash(),
        *blake3::hash(b"runner-blake3").as_bytes(),
    );
    // Attestation with the run/provenance binding injected + bound to the retained record.
    let mut att = crate::measurement::synth_runner_attestation(a, &"0".repeat(40), &|s: &str| {
        *blake3::hash(s.as_bytes()).as_bytes()
    });
    att.candidate = ids.candidate;
    att.provenance_role = role;
    att.b0_pre_spec_hash = spec_hash();
    att.r0_guest_set_hash = guest_set_hash();
    att.build_target_arch = a;
    att.phase1_production_binary_blake3 = record.production_binary_blake3;
    att.phase1_identity_record_blake3 = record.hash();
    // Retained runner path-independence five-artifact set (built for THIS candidate/arch); set the
    // attestation's v6 fields to their addresses so `check_bound_runner_recipe` binds them.
    let (recipe, inventory_a, inventory_b, proof, leakage) =
        crate::measurement::synth_runner_recipe_artifacts(
            ids.candidate,
            a,
            &"0".repeat(40),
            &|s: &str| *blake3::hash(s.as_bytes()).as_bytes(),
        );
    att.runner_build_recipe_blake3 = recipe.hash();
    att.rustc_invocation_inventory_a_blake3 = inventory_a.hash();
    att.rustc_invocation_inventory_b_blake3 = inventory_b.hash();
    att.runner_double_build_proof_blake3 = proof.hash();
    att.runner_leakage_report_blake3 = leakage.hash();
    att.per_arch_toolchain_identity = recipe.per_arch_toolchain_identity;
    att.runner_build_recipe_id = recipe.recipe_id;
    let runner_attestation_blake3 = att.hash();
    let chain = CpusetProbeChainV1 {
        candidate: ids.candidate,
        arch: a,
        provenance_role: role,
        b0_pre_spec_hash: spec_hash(),
        r0_guest_set_hash: guest_set_hash(),
        leaf_scope: scope.clone(),
        source_cgroup_path: scope.clone(),
        summary_raw: raw.clone(),
        summary_inherited: false,
        summary_count: r.cpuset,
        entries,
    };
    let p = ArchRunProvenanceV1 {
        provenance_role: role,
        b0_pre_spec_hash: spec_hash(),
        r0_guest_set_hash: guest_set_hash(),
        candidate: ids.candidate,
        guest_program_id: ids.program,
        candidate_dep_lock_hash: ids.lock,
        verifier_material_manifest_hash: vmat_id(ids),
        arch: a,
        source_commit: "0".repeat(40),
        dirty_tree_flag: false,
        builder_container_digest: ids.builder,
        host_os: env.host_os.clone(),
        kernel: env.kernel.clone(),
        cpu_vendor: env.cpu_vendor.clone(),
        cpu_model: env.cpu_model.clone(),
        physical_core_count: r.phys,
        logical_cpu_count: r.logical,
        total_ram_bytes: r.ram,
        configured_cpuset_core_limit: r.cpuset,
        configured_memory_limit_bytes: r.mem,
        dvfs: DvfsProvenance::Observable {
            turbo_enabled: env.turbo,
            governor: env.governor.clone(),
        },
        clock_source: env.clock_source.clone(),
        cgroup_version: env.cgroup_version,
        cgroup_scope_label: env.cgroup_scope_label.clone(),
        benchmark_harness_source_hash: env.harness_hash,
        raw_environment_capture_hash: env.envcap_hash,
        cpuset_source_cgroup_path: scope,
        cpuset_raw: raw,
        cpuset_inherited: false,
        cpuset_probe_chain_blake3,
        runner_attestation_blake3,
    };
    (
        p,
        chain,
        att,
        record,
        recipe,
        inventory_a,
        inventory_b,
        proof,
        leakage,
    )
}

fn envelope(
    a: Arch,
    s: StatementIndex,
    iter: u32,
    proving_prov: [u8; 32],
    ids: Ids,
) -> R0ProofArtifactEnvelopeV1 {
    R0ProofArtifactEnvelopeV1 {
        candidate: ids.candidate,
        candidate_dep_lock_hash: ids.lock,
        guest_program_id: ids.program,
        verifier_material_manifest_hash: vmat_id(ids),
        computation_statement_hash: stmt_hash(s),
        b0_pre_spec_hash: spec_hash(),
        r0_guest_set_hash: guest_set_hash(),
        arch_run_provenance: proving_prov,
        arch: a,
        sample_kind: SampleKind::Measured,
        iteration_index: iter,
        proof_hash: proof_hash(a, s, iter),
        artifact_hashes: vec![],
    }
}

#[allow(clippy::too_many_arguments)]
fn sample(
    a: Arch,
    s: StatementIndex,
    metric: MetricKind,
    unit: Unit,
    value: u64,
    iter: u32,
    ph: [u8; 32],
    ids: Ids,
) -> BenchmarkSampleV1 {
    BenchmarkSampleV1 {
        b0_pre_spec_hash: spec_hash(),
        r0_guest_set_hash: guest_set_hash(),
        computation_statement_hash: stmt_hash(s),
        candidate: ids.candidate,
        guest_program_id: ids.program,
        verifier_material_manifest_hash: vmat_id(ids),
        candidate_dep_lock_hash: ids.lock,
        container_image_digest: ids.container,
        arch: a,
        sample_kind: SampleKind::Measured,
        metric_kind: metric,
        unit,
        value,
        proof_hash: ph,
        iteration_index: iter,
        status: Status::Ok,
    }
}

fn rss(
    a: Arch,
    scope: RssScope,
    peak: u64,
    run: u32,
    ph: [u8; 32],
    ids: Ids,
) -> BenchmarkRssRecordV1 {
    BenchmarkRssRecordV1 {
        b0_pre_spec_hash: spec_hash(),
        r0_guest_set_hash: guest_set_hash(),
        computation_statement_hash: id(b"rss-context"),
        candidate: ids.candidate,
        guest_program_id: ids.program,
        verifier_material_manifest_hash: vmat_id(ids),
        candidate_dep_lock_hash: ids.lock,
        container_image_digest: ids.container,
        arch: a,
        rss_scope: scope,
        proof_hash: ph,
        run_index: run,
        peak_rss_bytes: peak,
    }
}

fn verify_value(a: Arch, s: StatementIndex, iter: u32, rep: u32) -> u64 {
    40_000_000
        + (rep as u64) * 200_000
        + (iter as u64) * 1_000
        + (s.to_repr() as u64) * 100
        + (a.to_repr() as u64) * 10
}
fn prove_value(a: Arch, s: StatementIndex, iter: u32) -> u64 {
    5_000_000_000 + (iter as u64) * 10 + (s.to_repr() as u64) * 3 + a.to_repr() as u64
}
fn setup_value(iter: u32) -> u64 {
    1_000_000 + iter as u64
}
fn proof_bytes_value(iter: u32) -> u64 {
    200 + iter as u64
}
fn proving_rss_value(iter: u32) -> u64 {
    (2u64 << 30) + iter as u64
}
fn verify_rss_value(a: Arch, iter: u32) -> u64 {
    (100u64 << 20) + (a.to_repr() as u64) * 4096 + iter as u64
}

fn stmt_index_of(h: [u8; 32], tlg: [u8; 32], st: [u8; 32]) -> Result<StatementIndex, String> {
    if h == tlg {
        Ok(StatementIndex::Tlg)
    } else if h == st {
        Ok(StatementIndex::SelectToken)
    } else {
        Err("statement binding".into())
    }
}

/// The RAW typed records a grid run produces, plus the run identities. This is the
/// ONLY input to [`assemble_result_set`]: the caller (synthetic `generate_with` or
/// the real venue orchestrator) supplies the already-bound records; the assembler
/// owns every DERIVED value — sort keys, bundle hashes, aggregates, completeness,
/// qualification, and the result-set encoding. Callers therefore NEVER compute a
/// bundle hash or an aggregate, and there is exactly one canonical bundle algorithm
/// ([`bundle_hash`], kept private).
///
/// Record order in `envelopes` / `samples` / `rss` / `provenances` is preserved
/// verbatim into the `Evidence` byte vectors; the result-set's bundles and
/// measured-proof / provenance references are re-derived and canonically ordered.
pub struct AssemblyInput {
    pub candidate: Candidate,
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub official_statement_hash_tlg: [u8; 32],
    pub official_statement_hash_st: [u8; 32],
    pub verifier_material: VerifierMaterialManifestV1,
    pub provenances: Vec<ArchRunProvenanceV1>,
    /// Retained cpuset probe-chain artifacts, one per provenance (SAME order); the assembler binds
    /// each to its provenance and rejects a mismatch before encoding.
    pub cpuset_chains: Vec<CpusetProbeChainV1>,
    /// Retained runner-attestation artifacts, one per provenance (SAME order).
    pub runner_attestations: Vec<RunnerAttestationV1>,
    /// Retained Phase-1 identity-record artifacts, one per provenance (SAME order); the assembler binds
    /// each to its runner attestation and rejects a mismatch before encoding.
    pub identity_records: Vec<Phase1IdentityRecordV1>,
    /// Retained runner path-independence artifacts, one per provenance (SAME order): build recipe,
    /// build-A + build-B rustc invocation inventories, double-build proof, leakage report. The assembler
    /// binds each set to its runner attestation (`check_bound_runner_recipe`) before encoding.
    pub recipes: Vec<crate::schema::runner_build_recipe::RunnerBuildRecipeV1>,
    pub inventories_a: Vec<crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1>,
    pub inventories_b: Vec<crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1>,
    pub double_build_proofs:
        Vec<crate::schema::runner_double_build_proof::RunnerDoubleBuildProofV1>,
    pub leakage_reports: Vec<crate::schema::runner_leakage_report::RunnerLeakageReportV1>,
    pub envelopes: Vec<R0ProofArtifactEnvelopeV1>,
    pub samples: Vec<BenchmarkSampleV1>,
    pub rss: Vec<BenchmarkRssRecordV1>,
    pub malformed_corpus_result_hash: [u8; 32],
}

/// Assemble the canonical `R0ResultSetV1` + `Evidence` from raw typed records.
///
/// This is the SINGLE canonical assembler; `generate_with` (synthetic) and the real
/// venue orchestrator both delegate here so the sort keys, bundle hashes, and
/// aggregates have exactly one implementation. `verify_evidence` remains an
/// INDEPENDENT re-derivation of everything this produces.
///
/// Fail-closed: every record must bind the run's `b0_pre_spec_hash`,
/// `r0_guest_set_hash`, candidate, and verifier-material identity; every proof /
/// sample statement must resolve to one of the two official statement hashes. The
/// completeness counts are the ACTUAL record counts (a short/duplicated grid stays
/// short here and is rejected downstream by `validate_official_completeness`, never
/// papered over).
pub fn assemble_result_set(input: &AssemblyInput) -> Result<Evidence, String> {
    let spec = input.b0_pre_spec_hash;
    let gs = input.r0_guest_set_hash;
    let cand = input.candidate;
    let tlg = input.official_statement_hash_tlg;
    let st = input.official_statement_hash_st;
    let vmat = input
        .verifier_material
        .identity()
        .map_err(|e| format!("verifier-material identity: {e}"))?;

    // Guardrail: every record binds both hashes + the candidate + the material.
    for p in &input.provenances {
        if p.b0_pre_spec_hash != spec
            || p.r0_guest_set_hash != gs
            || p.candidate != cand
            || p.verifier_material_manifest_hash != vmat
        {
            return Err("provenance binding".into());
        }
    }
    for e in &input.envelopes {
        if e.b0_pre_spec_hash != spec
            || e.r0_guest_set_hash != gs
            || e.candidate != cand
            || e.verifier_material_manifest_hash != vmat
        {
            return Err("envelope binding".into());
        }
    }
    for s in &input.samples {
        if s.b0_pre_spec_hash != spec
            || s.r0_guest_set_hash != gs
            || s.candidate != cand
            || s.verifier_material_manifest_hash != vmat
        {
            return Err("sample binding".into());
        }
    }
    for r in &input.rss {
        if r.b0_pre_spec_hash != spec
            || r.r0_guest_set_hash != gs
            || r.candidate != cand
            || r.verifier_material_manifest_hash != vmat
        {
            return Err("rss binding".into());
        }
    }

    // Measured-proof references (canonically ordered by arch, statement, iteration).
    let mut measured_proofs = Vec::with_capacity(input.envelopes.len());
    for e in &input.envelopes {
        measured_proofs.push(MeasuredProofRef {
            arch: e.arch,
            statement_index: stmt_index_of(e.computation_statement_hash, tlg, st)?,
            iteration_index: e.iteration_index,
            envelope_hash: crate::hashing::plain(&e.encode()),
        });
    }
    measured_proofs.sort_by_key(|m| {
        (
            m.arch.to_repr(),
            m.statement_index.to_repr(),
            m.iteration_index,
        )
    });

    // Provenance references (canonically ordered by arch, role).
    let mut arch_provenance: Vec<ArchProvenanceRef> = input
        .provenances
        .iter()
        .map(|p| ArchProvenanceRef {
            arch: p.arch,
            role: p.provenance_role,
            provenance_hash: p.provenance_hash(),
        })
        .collect();
    arch_provenance.sort_by_key(|r| (r.arch.to_repr(), r.role.to_repr()));

    // Sample bundles, keyed (arch, statement, metric); each hashed over its records
    // sorted by (proof_hash, iteration_index) — the one canonical bundle algorithm.
    let mut sgroups: HashMap<(u8, u8, u8), Vec<RawRec>> = HashMap::new();
    let mut verify_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut max_pb = 0u64;
    for s in &input.samples {
        let si = stmt_index_of(s.computation_statement_hash, tlg, st)?;
        sgroups
            .entry((s.arch.to_repr(), si.to_repr(), s.metric_kind.to_repr()))
            .or_default()
            .push(((s.proof_hash, s.iteration_index), s.encode()));
        if s.metric_kind == MetricKind::HostVerifyNs {
            verify_by_arch
                .entry(s.arch.to_repr())
                .or_default()
                .push(s.value);
        }
        if s.metric_kind == MetricKind::ProofBytes {
            max_pb = max_pb.max(s.value);
        }
    }
    let mut sample_bundles = Vec::new();
    for a in ARCHES {
        for s in STMTS {
            for m in BUNDLE_METRICS {
                if let Some(recs) = sgroups.get(&(a.to_repr(), s.to_repr(), m.to_repr())) {
                    let (h, c) = bundle_hash(SAMPLEBUNDLE_PREFIX, recs.clone());
                    sample_bundles.push(SampleBundle {
                        arch: a,
                        statement_index: s,
                        metric_kind: m,
                        sample_kind: SampleKind::Measured,
                        sample_count: c,
                        bundle_hash: h,
                    });
                }
            }
        }
    }

    // RSS bundles, keyed (arch, scope).
    let mut rgroups: HashMap<(u8, u8), Vec<RawRec>> = HashMap::new();
    let mut vrss_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    for r in &input.rss {
        rgroups
            .entry((r.arch.to_repr(), r.rss_scope.to_repr()))
            .or_default()
            .push(((r.proof_hash, r.run_index), r.encode()));
        if r.rss_scope == RssScope::VerifyBatch {
            vrss_by_arch
                .entry(r.arch.to_repr())
                .or_default()
                .push(r.peak_rss_bytes);
        }
    }
    let mut rss_bundles = Vec::new();
    for a in ARCHES {
        for scope in [RssScope::ProvingRun, RssScope::VerifyBatch] {
            if let Some(recs) = rgroups.get(&(a.to_repr(), scope.to_repr())) {
                let (h, c) = bundle_hash(RSSBUNDLE_PREFIX, recs.clone());
                rss_bundles.push(RssBundle {
                    arch: a,
                    rss_scope: scope,
                    record_count: c,
                    bundle_hash: h,
                });
            }
        }
    }

    // Aggregates over whatever arches are genuinely present (a missing arch stays
    // missing — it is not synthesized; downstream completeness rejects the grid).
    let worst_p99 = ARCHES
        .iter()
        .filter_map(|a| {
            verify_by_arch.get(&a.to_repr()).map(|v| {
                let mut v = v.clone();
                v.sort_unstable();
                nearest_rank_p99(&v).unwrap_or(0)
            })
        })
        .max()
        .unwrap_or(0);
    let worst_vrss = ARCHES
        .iter()
        .filter_map(|a| {
            vrss_by_arch
                .get(&a.to_repr())
                .and_then(|v| v.iter().max().copied())
        })
        .max()
        .unwrap_or(0);
    let qualification = crate::validation::official_qualification(worst_p99);
    let failure_codes = crate::validation::qualification_failure_codes(worst_p99);
    let vmat_total = input
        .verifier_material
        .verifier_material_bytes()
        .map_err(|e| format!("verifier-material total: {e}"))?;

    let rs = R0ResultSetV1 {
        b0_pre_spec_hash: spec,
        r0_guest_set_hash: gs,
        candidate: cand,
        verifier_material_manifest_hash: vmat,
        official_statement_hash_tlg: tlg,
        official_statement_hash_st: st,
        arch_provenance,
        measured_proofs,
        sample_bundles,
        rss_bundles,
        malformed_corpus_result_hash: input.malformed_corpus_result_hash,
        cycle_bundle: None,
        completeness: Completeness {
            measured_proof_count: input.envelopes.len() as u32,
            verify_timing_sample_count: input
                .samples
                .iter()
                .filter(|s| s.metric_kind == MetricKind::HostVerifyNs)
                .count() as u32,
            proving_time_sample_count: input
                .samples
                .iter()
                .filter(|s| s.metric_kind == MetricKind::HostProveWrapNs)
                .count() as u32,
            proving_run_rss_count: input
                .rss
                .iter()
                .filter(|r| r.rss_scope == RssScope::ProvingRun)
                .count() as u32,
            verify_batch_rss_count: input
                .rss
                .iter()
                .filter(|r| r.rss_scope == RssScope::VerifyBatch)
                .count() as u32,
        },
        aggregates: Aggregates {
            max_proof_bytes: max_pb as u32,
            worst_arch_p99_verify_ns: worst_p99,
            verifier_material_bytes: vmat_total,
            worst_arch_verifier_rss_bytes: worst_vrss,
        },
        qualification_result: qualification,
        failure_codes,
    };

    // Retained artifacts: exactly one per provenance (SAME order), each bound to its provenance
    // BEFORE encoding — the sealed package can never carry a chain/attestation that does not
    // recompute to its provenance's address (the importer re-checks this from the bytes alone).
    if input.cpuset_chains.len() != input.provenances.len() {
        return Err("retained cpuset-chain count != provenance count".into());
    }
    if input.runner_attestations.len() != input.provenances.len() {
        return Err("retained runner-attestation count != provenance count".into());
    }
    for (p, c) in input.provenances.iter().zip(&input.cpuset_chains) {
        bind_cpuset_chain(c, p)?;
    }
    for (p, a) in input.provenances.iter().zip(&input.runner_attestations) {
        bind_runner_attestation(a, p)?;
    }
    // Retained Phase-1 identity records: one per provenance; bind each runner attestation to its
    // record (address + triple runner-binary equality + candidate/arch/measured-source/tooling/spec)
    // BEFORE encoding, and require the exact identity set — the sealed package carries the authentic
    // Phase-1 anchor, not a copied hash.
    if input.identity_records.len() != input.provenances.len() {
        return Err("retained identity-record count != provenance count".into());
    }
    for (a, r) in input
        .runner_attestations
        .iter()
        .zip(&input.identity_records)
    {
        a.check_bound_identity_record(r)?;
    }
    // Retained runner path-independence set: one per provenance; bind each runner attestation to its
    // (recipe, inventory A, inventory B, double-build proof, leakage) via `check_bound_runner_recipe`.
    if input.recipes.len() != input.provenances.len()
        || input.inventories_a.len() != input.provenances.len()
        || input.inventories_b.len() != input.provenances.len()
        || input.double_build_proofs.len() != input.provenances.len()
        || input.leakage_reports.len() != input.provenances.len()
    {
        return Err("retained runner-recipe artifact count != provenance count".into());
    }
    for (i, a) in input.runner_attestations.iter().enumerate() {
        a.check_bound_runner_recipe(
            &input.recipes[i],
            &input.inventories_a[i],
            &input.inventories_b[i],
            &input.double_build_proofs[i],
            &input.leakage_reports[i],
        )?;
    }
    // (The EXACT identity set is enforced by the producer's `validate_identity_set` on the mandatory
    // input and re-enforced at sealed import in `verify_evidence`; the synthetic harness legitimately
    // fingerprints a superset per candidate, so it is not gated in the shared assembler.)

    Ok(Evidence {
        samples: input.samples.iter().map(|s| s.encode()).collect(),
        rss: input.rss.iter().map(|r| r.encode()).collect(),
        envelopes: input.envelopes.iter().map(|e| e.encode()).collect(),
        provenances: input.provenances.iter().map(|p| p.encode()).collect(),
        cpuset_chains: input.cpuset_chains.iter().map(|c| c.encode()).collect(),
        runner_attestations: input
            .runner_attestations
            .iter()
            .map(|a| a.encode())
            .collect(),
        identity_records: input.identity_records.iter().map(|r| r.encode()).collect(),
        recipes: input.recipes.iter().map(|r| r.encode()).collect(),
        inventories_a: input.inventories_a.iter().map(|r| r.encode()).collect(),
        inventories_b: input.inventories_b.iter().map(|r| r.encode()).collect(),
        double_build_proofs: input
            .double_build_proofs
            .iter()
            .map(|r| r.encode())
            .collect(),
        leakage_reports: input.leakage_reports.iter().map(|r| r.encode()).collect(),
        verifier_material: input
            .verifier_material
            .encode()
            .map_err(|e| format!("verifier-material encode: {e}"))?,
        result_set: rs.encode(),
    })
}

/// The EXACT retained Phase-1 identity set for a candidate: distinct arches must be exactly the
/// eligible set (Sp1 {x86_64, aarch64}, Risc0 {x86_64}); never Risc0/aarch64, missing, or extra.
pub fn require_exact_identity_set(
    candidate: Candidate,
    records: &[Phase1IdentityRecordV1],
) -> Result<(), String> {
    use std::collections::BTreeSet;
    let mut arches: BTreeSet<u8> = BTreeSet::new();
    for r in records {
        if r.candidate != candidate {
            return Err("retained identity record candidate != bundle candidate".into());
        }
        if candidate == Candidate::Risc0 && r.arch == Arch::Aarch64 {
            return Err("retained Risc0/aarch64 identity record; refused".into());
        }
        arches.insert(r.arch.to_repr());
    }
    let want: BTreeSet<u8> = match candidate {
        Candidate::Sp1 => [Arch::X86_64.to_repr(), Arch::Aarch64.to_repr()]
            .into_iter()
            .collect(),
        Candidate::Risc0 => [Arch::X86_64.to_repr()].into_iter().collect(),
    };
    if arches != want {
        return Err(format!(
            "retained identity set arches {arches:?} != required {want:?}"
        ));
    }
    Ok(())
}

fn bundle_hash(prefix: &[u8], mut recs: Vec<RawRec>) -> ([u8; 32], u32) {
    recs.sort_by_key(|r| r.0);
    let mut h = blake3::Hasher::new();
    h.update(prefix);
    for (_, b) in &recs {
        h.update(b);
    }
    (h.finalize().into(), recs.len() as u32)
}

#[derive(Debug, Clone)]
pub struct Evidence {
    pub samples: Vec<Vec<u8>>,
    pub rss: Vec<Vec<u8>>,
    pub envelopes: Vec<Vec<u8>>,
    pub provenances: Vec<Vec<u8>>,
    /// Retained canonical `CpusetProbeChainV1` bytes, one per provenance (SAME order).
    pub cpuset_chains: Vec<Vec<u8>>,
    /// Retained canonical `RunnerAttestationV1` bytes, one per provenance (SAME order).
    pub runner_attestations: Vec<Vec<u8>>,
    /// Retained canonical `Phase1IdentityRecordV1` bytes, one per provenance (SAME order).
    pub identity_records: Vec<Vec<u8>>,
    /// Retained canonical `RunnerBuildRecipeV1` bytes, one per provenance (SAME order).
    pub recipes: Vec<Vec<u8>>,
    /// Retained build-A `RustcInvocationInventoryV1` bytes, one per provenance (SAME order).
    pub inventories_a: Vec<Vec<u8>>,
    /// Retained build-B `RustcInvocationInventoryV1` bytes, one per provenance (SAME order).
    pub inventories_b: Vec<Vec<u8>>,
    /// Retained canonical `RunnerDoubleBuildProofV1` bytes, one per provenance (SAME order).
    pub double_build_proofs: Vec<Vec<u8>>,
    /// Retained canonical `RunnerLeakageReportV1` bytes, one per provenance (SAME order).
    pub leakage_reports: Vec<Vec<u8>>,
    pub verifier_material: Vec<u8>,
    pub result_set: Vec<u8>,
}

/// Bind a retained cpuset-chain artifact to its provenance record (production side; the importer
/// re-derives this independently). Structural rules + address + candidate/arch/run/summary binding.
pub fn bind_cpuset_chain(
    chain: &CpusetProbeChainV1,
    p: &ArchRunProvenanceV1,
) -> Result<(), String> {
    chain.structural_check()?;
    if chain.candidate != p.candidate
        || chain.arch != p.arch
        || chain.provenance_role != p.provenance_role
        || chain.b0_pre_spec_hash != p.b0_pre_spec_hash
        || chain.r0_guest_set_hash != p.r0_guest_set_hash
    {
        return Err(
            "cpuset chain binding (candidate/arch/role/spec/guest_set) != provenance".into(),
        );
    }
    if chain.source_cgroup_path != p.cpuset_source_cgroup_path
        || chain.summary_raw != p.cpuset_raw
        || chain.summary_inherited != p.cpuset_inherited
        || chain.summary_count != p.configured_cpuset_core_limit
    {
        return Err("cpuset chain summary != provenance summary".into());
    }
    if chain.bound_address() != p.cpuset_probe_chain_blake3 {
        return Err("cpuset chain address != provenance cpuset_probe_chain_blake3".into());
    }
    Ok(())
}

/// Bind a retained runner-attestation artifact to its provenance record.
pub fn bind_runner_attestation(
    att: &RunnerAttestationV1,
    p: &ArchRunProvenanceV1,
) -> Result<(), String> {
    att.check_self_consistency()?;
    // Runner continuity: the Phase-1 identity runner binary == the measurement runner binary.
    att.check_runner_continuity()?;
    if att.candidate != p.candidate
        || att.provenance_role != p.provenance_role
        || att.build_target_arch != p.arch
        || att.b0_pre_spec_hash != p.b0_pre_spec_hash
        || att.r0_guest_set_hash != p.r0_guest_set_hash
    {
        return Err(
            "runner attestation binding (candidate/arch/role/spec/guest_set) != provenance".into(),
        );
    }
    if att.hash() != p.runner_attestation_blake3 {
        return Err("runner attestation address != provenance runner_attestation_blake3".into());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Recomputed {
    pub max_proof_bytes: u32,
    pub worst_arch_p99_verify_ns: u64,
    pub verifier_material_bytes: u64,
    pub worst_arch_verifier_rss_bytes: u64,
    pub qualification: bool,
    pub failure_codes: Vec<u16>,
    pub result_set_hash: [u8; 32],
}

pub fn generate() -> Evidence {
    generate_with(Candidate::Sp1, &default_env())
}

/// Generate a full evidence bundle for `candidate` on the default environment.
/// Used to build the peer candidate of a paired benchmark.
pub fn generate_candidate(candidate: Candidate) -> Evidence {
    generate_with(candidate, &default_env())
}

fn generate_with(candidate: Candidate, env: &Env) -> Evidence {
    let ids = ids_for(candidate);

    // Provenances (4: arch × role) + their retained artifacts. Envelopes bind the PROVING prov hash.
    let mut provenances = Vec::new();
    let mut cpuset_chains = Vec::new();
    let mut runner_attestations = Vec::new();
    let mut identity_records = Vec::new();
    let mut recipes = Vec::new();
    let mut inventories_a = Vec::new();
    let mut inventories_b = Vec::new();
    let mut double_build_proofs = Vec::new();
    let mut leakage_reports = Vec::new();
    let mut proving_prov: HashMap<u8, [u8; 32]> = HashMap::new();
    for a in ARCHES {
        for role in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
            let (p, chain, att, rec, recipe, inv_a, inv_b, proof, leak) =
                provenance(a, role, ids, env);
            if role == ProvenanceRole::Proving {
                proving_prov.insert(a.to_repr(), p.provenance_hash());
            }
            provenances.push(p);
            cpuset_chains.push(chain);
            runner_attestations.push(att);
            identity_records.push(rec);
            recipes.push(recipe);
            inventories_a.push(inv_a);
            inventories_b.push(inv_b);
            double_build_proofs.push(proof);
            leakage_reports.push(leak);
        }
    }

    // The 2×2×10 grid, in canonical order: per cell one envelope, REPS verify
    // samples, one each prove/setup/proof_bytes, and one proving + one verify RSS.
    // Raw typed records only — the shared assembler derives every bundle/aggregate.
    let mut envelopes = Vec::new();
    let mut samples = Vec::new();
    let mut rss_records = Vec::new();
    for a in ARCHES {
        for s in STMTS {
            for iter in 0..crate::consts::OFFICIAL_ITERATIONS_PER_CELL {
                let ph = proof_hash(a, s, iter);
                envelopes.push(envelope(a, s, iter, proving_prov[&a.to_repr()], ids));
                for rep in 0..REPS {
                    samples.push(sample(
                        a,
                        s,
                        MetricKind::HostVerifyNs,
                        Unit::Nanoseconds,
                        verify_value(a, s, iter, rep),
                        rep,
                        ph,
                        ids,
                    ));
                }
                samples.push(sample(
                    a,
                    s,
                    MetricKind::HostProveWrapNs,
                    Unit::Nanoseconds,
                    prove_value(a, s, iter),
                    iter,
                    ph,
                    ids,
                ));
                samples.push(sample(
                    a,
                    s,
                    MetricKind::HostSetupNs,
                    Unit::Nanoseconds,
                    setup_value(iter),
                    iter,
                    ph,
                    ids,
                ));
                samples.push(sample(
                    a,
                    s,
                    MetricKind::ProofBytes,
                    Unit::Bytes,
                    proof_bytes_value(iter),
                    iter,
                    ph,
                    ids,
                ));
                rss_records.push(rss(
                    a,
                    RssScope::ProvingRun,
                    proving_rss_value(iter),
                    iter,
                    ph,
                    ids,
                ));
                rss_records.push(rss(
                    a,
                    RssScope::VerifyBatch,
                    verify_rss_value(a, iter),
                    iter,
                    ph,
                    ids,
                ));
            }
        }
    }

    assemble_result_set(&AssemblyInput {
        candidate,
        b0_pre_spec_hash: spec_hash(),
        r0_guest_set_hash: guest_set_hash(),
        official_statement_hash_tlg: stmt_hash(StatementIndex::Tlg),
        official_statement_hash_st: stmt_hash(StatementIndex::SelectToken),
        verifier_material: verifier_material_for(ids),
        provenances,
        cpuset_chains,
        runner_attestations,
        identity_records,
        recipes,
        inventories_a,
        inventories_b,
        double_build_proofs,
        leakage_reports,
        envelopes,
        samples,
        rss: rss_records,
        malformed_corpus_result_hash: id(b"malformed"),
    })
    .expect("synthetic grid assembles")
}

fn stmt_of(h: [u8; 32], tlg: [u8; 32], st: [u8; 32]) -> Result<u8, String> {
    if h == tlg {
        Ok(0)
    } else if h == st {
        Ok(1)
    } else {
        Err("statement binding".into())
    }
}

/// Full end-to-end verification: recompute every bundle hash, the
/// verifier-material total (from the canonical manifest), and every aggregate
/// from raw bytes and compare with the result set.
pub fn verify_evidence(ev: &Evidence) -> Result<Recomputed, String> {
    let rs = R0ResultSetV1::decode_exact(&ev.result_set).map_err(|e| format!("result_set: {e}"))?;
    crate::validation::validate_official_completeness(&rs)
        .map_err(|e| format!("completeness: {e:?}"))?;

    let spec = rs.b0_pre_spec_hash;
    let gs = rs.r0_guest_set_hash;
    let vm = rs.verifier_material_manifest_hash;
    let tlg = rs.official_statement_hash_tlg;
    let st = rs.official_statement_hash_st;

    // verifier-material byte total recomputed from the canonical manifest record
    let vmm = VerifierMaterialManifestV1::decode_exact(&ev.verifier_material)
        .map_err(|e| format!("vmat: {e}"))?;
    if vmm.identity().map_err(|e| format!("vmat identity: {e}"))? != vm {
        return Err("verifier-material identity".into());
    }
    let vmat_bytes = vmm
        .verifier_material_bytes()
        .map_err(|e| format!("vmat sum: {e}"))?;
    if rs.aggregates.verifier_material_bytes != vmat_bytes {
        return Err("verifier_material_bytes mismatch".into());
    }

    let mut programs: HashSet<[u8; 32]> = HashSet::new();
    let mut locks: HashSet<[u8; 32]> = HashSet::new();
    let mut containers: HashSet<[u8; 32]> = HashSet::new();

    // provenances (exactly 4; each eligible; hashes bound; proving hashes per arch)
    if ev.provenances.len() != 4 {
        return Err("provenance count".into());
    }
    let mut prov_h: HashMap<(u8, u8), [u8; 32]> = HashMap::new();
    let mut proving: HashMap<u8, [u8; 32]> = HashMap::new();
    for b in &ev.provenances {
        let p = ArchRunProvenanceV1::decode_exact(b).map_err(|e| format!("prov: {e}"))?;
        if p.b0_pre_spec_hash != spec
            || p.r0_guest_set_hash != gs
            || p.verifier_material_manifest_hash != vm
            || p.candidate != rs.candidate
        {
            return Err("prov binding".into());
        }
        crate::validation::provenance_eligible(&p).map_err(|e| format!("prov eligible: {e:?}"))?;
        programs.insert(p.guest_program_id);
        locks.insert(p.candidate_dep_lock_hash);
        if prov_h
            .insert(
                (p.arch.to_repr(), p.provenance_role.to_repr()),
                crate::hashing::prefixed(crate::tags::ARCHPROV_PREFIX, b),
            )
            .is_some()
        {
            return Err("duplicate provenance".into());
        }
        if p.provenance_role == ProvenanceRole::Proving {
            proving.insert(
                p.arch.to_repr(),
                crate::hashing::prefixed(crate::tags::ARCHPROV_PREFIX, b),
            );
        }
    }
    // Retained artifacts: EXACTLY one cpuset-chain + one runner-attestation per provenance (SAME
    // order). Decode each from the retained bytes, structurally re-validate, recompute its
    // domain-separated address, and require it equals the bound provenance field + binds the same
    // candidate/arch/run/provenance. A hash-only provenance field is thereby never trusted alone;
    // missing/extra (count), malformed (decode), swapped (binding), mutated / well-formed-false hash
    // (address) all refuse here.
    if ev.cpuset_chains.len() != ev.provenances.len() {
        return Err("retained cpuset-chain count != provenance count".into());
    }
    if ev.runner_attestations.len() != ev.provenances.len() {
        return Err("retained runner-attestation count != provenance count".into());
    }
    if ev.identity_records.len() != ev.provenances.len() {
        return Err("retained identity-record count != provenance count".into());
    }
    if ev.recipes.len() != ev.provenances.len()
        || ev.inventories_a.len() != ev.provenances.len()
        || ev.inventories_b.len() != ev.provenances.len()
        || ev.double_build_proofs.len() != ev.provenances.len()
        || ev.leakage_reports.len() != ev.provenances.len()
    {
        return Err("retained runner-recipe artifact count != provenance count".into());
    }
    let mut artifact_keys: HashSet<(u8, u8)> = HashSet::new();
    for (i, pb) in ev.provenances.iter().enumerate() {
        let p = ArchRunProvenanceV1::decode_exact(pb).map_err(|e| format!("prov: {e}"))?;
        let chain =
            crate::schema::cpuset_chain::CpusetProbeChainV1::decode_exact(&ev.cpuset_chains[i])
                .map_err(|e| format!("cpuset chain artifact: {e}"))?;
        bind_cpuset_chain(&chain, &p).map_err(|e| format!("cpuset chain: {e}"))?;
        let att = RunnerAttestationV1::decode_exact(&ev.runner_attestations[i])
            .map_err(|e| format!("runner attestation artifact: {e}"))?;
        bind_runner_attestation(&att, &p).map_err(|e| format!("runner attestation: {e}"))?;
        // Sealed-import runner CONTINUITY, anchored to the INDEPENDENTLY-decoded retained Phase-1
        // identity record: recompute its address, require it equals the attestation's bound address,
        // and require production_binary_blake3 == phase1_production_binary_blake3 == runner_blake3 +
        // the same candidate/arch/measured-source/tooling/spec. This per-provenance binding, together
        // with the count check above, is the EXACT record↔provenance correspondence (a dropped/extra
        // record fails the count; a swapped/cross-candidate/replaced record fails the binding). The
        // eligible mapping (no Risc0/aarch64) is enforced by the producer's `validate_identity_set` on
        // the mandatory input and by native-eligibility of the measurement cells.
        let rec = Phase1IdentityRecordV1::decode_exact(&ev.identity_records[i])
            .map_err(|e| format!("identity record artifact: {e}"))?;
        att.check_bound_identity_record(&rec)
            .map_err(|e| format!("runner continuity: {e}"))?;
        // Sealed-import runner PATH-INDEPENDENCE, anchored to the INDEPENDENTLY-decoded retained
        // five-artifact set: recipe (exact bytes), build-A + build-B inventories (exact remap argv +
        // record-address agreement), double-build proof (runner A==B==attested; RISC0 guest A==B), and
        // the cross-bound leakage report. Re-run the SAME binding the assembler enforced at production.
        let recipe =
            crate::schema::runner_build_recipe::RunnerBuildRecipeV1::decode_exact(&ev.recipes[i])
                .map_err(|e| format!("runner build recipe artifact: {e}"))?;
        let inv_a =
            crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1::decode_exact(
                &ev.inventories_a[i],
            )
            .map_err(|e| format!("build-A invocation inventory artifact: {e}"))?;
        let inv_b =
            crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1::decode_exact(
                &ev.inventories_b[i],
            )
            .map_err(|e| format!("build-B invocation inventory artifact: {e}"))?;
        let proof =
            crate::schema::runner_double_build_proof::RunnerDoubleBuildProofV1::decode_exact(
                &ev.double_build_proofs[i],
            )
            .map_err(|e| format!("runner double-build proof artifact: {e}"))?;
        let leakage = crate::schema::runner_leakage_report::RunnerLeakageReportV1::decode_exact(
            &ev.leakage_reports[i],
        )
        .map_err(|e| format!("runner leakage report artifact: {e}"))?;
        att.check_bound_runner_recipe(&recipe, &inv_a, &inv_b, &proof, &leakage)
            .map_err(|e| format!("runner path-independence: {e}"))?;
        if !artifact_keys.insert((p.arch.to_repr(), p.provenance_role.to_repr())) {
            return Err("duplicate retained artifact (arch, role)".into());
        }
    }

    for ap in &rs.arch_provenance {
        match prov_h.get(&(ap.arch.to_repr(), ap.role.to_repr())) {
            Some(h) if *h == ap.provenance_hash => {}
            _ => return Err("provenance hash mismatch".into()),
        }
    }

    // envelopes -> grid, unique proof hashes, envelope hash, provenance link
    let mut grid: BTreeSet<(u8, u8, u32)> = BTreeSet::new();
    let mut proof_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut env_hash: HashMap<(u8, u8, u32), [u8; 32]> = HashMap::new();
    for b in &ev.envelopes {
        let e = R0ProofArtifactEnvelopeV1::decode_exact(b).map_err(|e| format!("env: {e}"))?;
        if e.encode() != *b {
            return Err("env non-canonical".into());
        }
        if e.b0_pre_spec_hash != spec
            || e.r0_guest_set_hash != gs
            || e.verifier_material_manifest_hash != vm
            || e.candidate != rs.candidate
        {
            return Err("env binding".into());
        }
        let si = stmt_of(e.computation_statement_hash, tlg, st)?;
        if proving.get(&e.arch.to_repr()) != Some(&e.arch_run_provenance) {
            return Err("env provenance link".into());
        }
        programs.insert(e.guest_program_id);
        locks.insert(e.candidate_dep_lock_hash);
        if !grid.insert((e.arch.to_repr(), si, e.iteration_index)) {
            return Err("duplicate proof cell".into());
        }
        if !proof_hashes.insert(e.proof_hash) {
            return Err("duplicate proof hash".into());
        }
        env_hash.insert(
            (e.arch.to_repr(), si, e.iteration_index),
            crate::hashing::plain(b),
        );
    }
    if grid != expected_grid() {
        return Err("proof grid".into());
    }
    for m in &rs.measured_proofs {
        match env_hash.get(&(
            m.arch.to_repr(),
            m.statement_index.to_repr(),
            m.iteration_index,
        )) {
            Some(h) if *h == m.envelope_hash => {}
            _ => return Err("measured proof mismatch".into()),
        }
    }

    // samples -> bundles + aggregates
    let mut verify_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut max_pb = 0u64;
    let mut per: HashMap<(u8, u8, u8), Vec<RawRec>> = HashMap::new();
    for b in &ev.samples {
        let s = BenchmarkSampleV1::decode_exact(b).map_err(|e| format!("sample: {e}"))?;
        if s.encode() != *b {
            return Err("sample non-canonical".into());
        }
        if s.b0_pre_spec_hash != spec
            || s.r0_guest_set_hash != gs
            || s.verifier_material_manifest_hash != vm
            || s.candidate != rs.candidate
        {
            return Err("sample binding".into());
        }
        if s.sample_kind != SampleKind::Measured {
            return Err("sample warmup".into());
        }
        if s.status != Status::Ok {
            return Err("sample status".into());
        }
        let expected_unit = if s.metric_kind == MetricKind::ProofBytes {
            Unit::Bytes
        } else {
            Unit::Nanoseconds
        };
        if s.unit != expected_unit {
            return Err("sample unit".into());
        }
        if !proof_hashes.contains(&s.proof_hash) {
            return Err("sample orphan".into());
        }
        programs.insert(s.guest_program_id);
        locks.insert(s.candidate_dep_lock_hash);
        containers.insert(s.container_image_digest);
        let si = stmt_of(s.computation_statement_hash, tlg, st)?;
        per.entry((s.arch.to_repr(), si, s.metric_kind.to_repr()))
            .or_default()
            .push(((s.proof_hash, s.iteration_index), b.clone()));
        match s.metric_kind {
            MetricKind::HostVerifyNs => verify_by_arch
                .entry(s.arch.to_repr())
                .or_default()
                .push(s.value),
            MetricKind::ProofBytes => max_pb = max_pb.max(s.value),
            _ => {}
        }
    }
    let claimed: HashMap<(u8, u8, u8), HashCount> = rs
        .sample_bundles
        .iter()
        .map(|b| {
            (
                (
                    b.arch.to_repr(),
                    b.statement_index.to_repr(),
                    b.metric_kind.to_repr(),
                ),
                (b.bundle_hash, b.sample_count),
            )
        })
        .collect();
    if per.len() != claimed.len() {
        return Err("sample bundle set".into());
    }
    for (k, recs) in per {
        let (h, c) = bundle_hash(SAMPLEBUNDLE_PREFIX, recs);
        match claimed.get(&k) {
            Some((ch, cc)) if *ch == h && *cc == c => {}
            _ => return Err("sample bundle mismatch".into()),
        }
    }

    // rss -> bundles + aggregate
    let mut vrss_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut rper: HashMap<(u8, u8), Vec<RawRec>> = HashMap::new();
    for b in &ev.rss {
        let r = BenchmarkRssRecordV1::decode_exact(b).map_err(|e| format!("rss: {e}"))?;
        if r.encode() != *b {
            return Err("rss non-canonical".into());
        }
        if r.b0_pre_spec_hash != spec
            || r.r0_guest_set_hash != gs
            || r.verifier_material_manifest_hash != vm
            || r.candidate != rs.candidate
        {
            return Err("rss binding".into());
        }
        if !proof_hashes.contains(&r.proof_hash) {
            return Err("rss orphan".into());
        }
        programs.insert(r.guest_program_id);
        locks.insert(r.candidate_dep_lock_hash);
        containers.insert(r.container_image_digest);
        if r.rss_scope == RssScope::VerifyBatch {
            vrss_by_arch
                .entry(r.arch.to_repr())
                .or_default()
                .push(r.peak_rss_bytes);
        }
        rper.entry((r.arch.to_repr(), r.rss_scope.to_repr()))
            .or_default()
            .push(((r.proof_hash, r.run_index), b.clone()));
    }
    let claimed_rss: HashMap<(u8, u8), HashCount> = rs
        .rss_bundles
        .iter()
        .map(|b| {
            (
                (b.arch.to_repr(), b.rss_scope.to_repr()),
                (b.bundle_hash, b.record_count),
            )
        })
        .collect();
    if rper.len() != claimed_rss.len() {
        return Err("rss bundle set".into());
    }
    for (k, recs) in rper {
        let (h, c) = bundle_hash(RSSBUNDLE_PREFIX, recs);
        match claimed_rss.get(&k) {
            Some((ch, cc)) if *ch == h && *cc == c => {}
            _ => return Err("rss bundle mismatch".into()),
        }
    }

    // program / lock / container must be globally consistent
    if programs.len() != 1 {
        return Err("program identity".into());
    }
    if locks.len() != 1 {
        return Err("lock identity".into());
    }
    if containers.len() != 1 {
        return Err("container identity".into());
    }

    // aggregates
    let worst_p99 = ARCHES
        .iter()
        .map(|a| {
            let mut v = verify_by_arch
                .get(&a.to_repr())
                .cloned()
                .unwrap_or_default();
            v.sort_unstable();
            nearest_rank_p99(&v).unwrap_or(0)
        })
        .max()
        .unwrap();
    let worst_vrss = ARCHES
        .iter()
        .map(|a| {
            vrss_by_arch
                .get(&a.to_repr())
                .and_then(|v| v.iter().max().copied())
                .unwrap_or(0)
        })
        .max()
        .unwrap();
    let qualification = crate::validation::official_qualification(worst_p99);
    let failure_codes = crate::validation::qualification_failure_codes(worst_p99);

    if rs.aggregates.max_proof_bytes as u64 != max_pb {
        return Err("max_proof_bytes mismatch".into());
    }
    if rs.aggregates.worst_arch_p99_verify_ns != worst_p99 {
        return Err("p99 mismatch".into());
    }
    if rs.aggregates.worst_arch_verifier_rss_bytes != worst_vrss {
        return Err("verifier rss mismatch".into());
    }
    if rs.qualification_result != qualification || rs.failure_codes != failure_codes {
        return Err("qualification mismatch".into());
    }

    Ok(Recomputed {
        max_proof_bytes: max_pb as u32,
        worst_arch_p99_verify_ns: worst_p99,
        verifier_material_bytes: vmat_bytes,
        worst_arch_verifier_rss_bytes: worst_vrss,
        qualification,
        failure_codes,
        result_set_hash: rs.result_set_hash(),
    })
}

/// Verify a PAIRED benchmark end-to-end: each candidate's evidence bundle
/// individually, then that for every `(arch, role)` both candidates' provenance
/// describe the SAME controlled host/environment. This is the paired-evidence
/// verification path — `paired_environment_consistent` is enforced here, not only
/// by unit tests — so two candidates benchmarked on different hardware are
/// rejected even though each bundle is internally valid.
pub fn verify_paired_evidence(a: &Evidence, b: &Evidence) -> Result<(), String> {
    verify_evidence(a).map_err(|e| format!("candidate A: {e}"))?;
    verify_evidence(b).map_err(|e| format!("candidate B: {e}"))?;

    let rsa =
        R0ResultSetV1::decode_exact(&a.result_set).map_err(|e| format!("A result_set: {e}"))?;
    let rsb =
        R0ResultSetV1::decode_exact(&b.result_set).map_err(|e| format!("B result_set: {e}"))?;
    if rsa.candidate == rsb.candidate {
        return Err("paired evidence must be two distinct candidates".into());
    }
    if rsa.b0_pre_spec_hash != rsb.b0_pre_spec_hash {
        return Err("paired candidates bind different b0_pre_spec_hash".into());
    }
    if rsa.r0_guest_set_hash != rsb.r0_guest_set_hash {
        return Err("paired candidates bind different r0_guest_set_hash".into());
    }

    let index = |ev: &Evidence| -> Result<HashMap<(u8, u8), ArchRunProvenanceV1>, String> {
        let mut m = HashMap::new();
        for pb in &ev.provenances {
            let p = ArchRunProvenanceV1::decode_exact(pb).map_err(|e| format!("prov: {e}"))?;
            if m.insert((p.arch.to_repr(), p.provenance_role.to_repr()), p)
                .is_some()
            {
                return Err("duplicate provenance in bundle".into());
            }
        }
        Ok(m)
    };
    let ma = index(a)?;
    let mb = index(b)?;
    if ma.len() != mb.len() {
        return Err("paired provenance sets differ in shape".into());
    }
    for (k, pa) in &ma {
        let pb = mb
            .get(k)
            .ok_or_else(|| format!("candidate B missing provenance for arch/role {k:?}"))?;
        crate::validation::paired_environment_consistent(pa, pb)
            .map_err(|e| format!("paired environment mismatch at {k:?}: {e:?}"))?;
    }
    Ok(())
}

fn expected_grid() -> BTreeSet<(u8, u8, u32)> {
    let mut g = BTreeSet::new();
    for a in ARCHES {
        for s in STMTS {
            for i in 0..crate::consts::OFFICIAL_ITERATIONS_PER_CELL {
                g.insert((a.to_repr(), s.to_repr(), i));
            }
        }
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clone_ev(ev: &Evidence) -> Evidence {
        Evidence {
            samples: ev.samples.clone(),
            rss: ev.rss.clone(),
            envelopes: ev.envelopes.clone(),
            provenances: ev.provenances.clone(),
            cpuset_chains: ev.cpuset_chains.clone(),
            runner_attestations: ev.runner_attestations.clone(),
            identity_records: ev.identity_records.clone(),
            recipes: ev.recipes.clone(),
            inventories_a: ev.inventories_a.clone(),
            inventories_b: ev.inventories_b.clone(),
            double_build_proofs: ev.double_build_proofs.clone(),
            leakage_reports: ev.leakage_reports.clone(),
            verifier_material: ev.verifier_material.clone(),
            result_set: ev.result_set.clone(),
        }
    }
    fn with_rs(ev: &Evidence, f: impl Fn(&mut R0ResultSetV1)) -> Evidence {
        let mut e = clone_ev(ev);
        let mut rs = R0ResultSetV1::decode_exact(&e.result_set).unwrap();
        f(&mut rs);
        e.result_set = rs.encode();
        e
    }

    fn evidence_fingerprint(ev: &Evidence) -> String {
        let mut h = blake3::Hasher::new();
        for v in [
            &ev.samples,
            &ev.rss,
            &ev.envelopes,
            &ev.provenances,
            &ev.cpuset_chains,
            &ev.runner_attestations,
            &ev.identity_records,
            &ev.recipes,
            &ev.inventories_a,
            &ev.inventories_b,
            &ev.double_build_proofs,
            &ev.leakage_reports,
        ] {
            for r in v {
                h.update(r);
            }
        }
        h.update(&ev.verifier_material);
        h.update(&ev.result_set);
        h.finalize().to_hex().to_string()
    }

    /// GUARDRAIL: routing `generate_with` through the shared `assemble_result_set`
    /// must not change a single output byte. These fingerprints of the FULL Evidence
    /// (every record + verifier material + result set) were frozen BEFORE the shared
    /// assembler existed; any drift here is a refactor regression, not a new golden.
    /// (Re-frozen for the RUNNER PATH-INDEPENDENCE v5 transition: the runner attestation gained its five
    /// v5 fields (the three retained-artifact addresses + per-arch toolchain identity + structural recipe
    /// id) and the Evidence gained three retained per-provenance artifact lists — recipes / inventories /
    /// leakage_reports — now folded into this fingerprint. The attestation + the new lists moved the
    /// bytes; every other record stays at the unchanged global schema version 1. This is that one
    /// sanctioned move.)
    ///
    /// (Re-frozen for the CANONICAL-BUILD-PATH correction: the runner recipe is v3 — it gained
    /// `canonical_build_path`, renamed each side's `source_from` -> `original_root`, and dropped the
    /// source remap so each side carries TWO remaps (cargo, target). The double-build proof is v2 — each
    /// side gained the authenticated `origin_manifest_blake3` + `materialized_manifest_blake3` addresses
    /// (4-way source-input equality). These moved the recipe/proof bytes folded into this fingerprint.)
    /// (Re-frozen for the RUNNER TOOLCHAIN + OFFLINE-SEED correction: the runner attestation is v7 — it
    /// gained the three v7 offline-provisioning authority addresses (host toolchain / dependency seed /
    /// protoc). These moved the attestation bytes folded into this fingerprint.)
    #[test]
    fn generate_output_is_byte_stable() {
        assert_eq!(
            evidence_fingerprint(&generate()),
            "ede8dd4e691bbf2c3ffcefd8f8b71c3dff5746cb28ee7ebe6c9077936edf4176",
            "SP1 generate() output drifted from the frozen (retained cpuset+attestation+identity+recipe) bytes"
        );
        assert_eq!(
            evidence_fingerprint(&generate_candidate(Candidate::Risc0)),
            "f1d97699e11aa8141b7e08dd5f72a17863156fb8ecbe5759ec0330b6f42d8d8c",
            "RISC0 generate_candidate() output drifted from the frozen (retained cpuset+attestation+identity+recipe) bytes"
        );
    }

    #[test]
    fn generated_evidence_verifies() {
        let ev = generate();
        assert_eq!(ev.envelopes.len(), 40);
        assert_eq!(ev.samples.len(), 4000 + 40 + 40 + 40); // + host_setup_ns
        assert_eq!(ev.rss.len(), 80);
        assert_eq!(ev.provenances.len(), 4);
        let r = verify_evidence(&ev).expect("valid");
        assert!(r.qualification);
        assert_eq!(r.verifier_material_bytes, 292); // SP1's own per-candidate total
    }

    // Retained-artifact refusals on import: a hash-only provenance field is never trusted alone.
    #[test]
    fn retained_cpuset_chain_refusals() {
        assert!(verify_evidence(&generate()).is_ok());
        // missing (count)
        let mut e = clone_ev(&generate());
        e.cpuset_chains.pop();
        assert!(verify_evidence(&e)
            .unwrap_err()
            .contains("cpuset-chain count"));
        // extra (count)
        let mut e = clone_ev(&generate());
        e.cpuset_chains.push(e.cpuset_chains[0].clone());
        assert!(verify_evidence(&e)
            .unwrap_err()
            .contains("cpuset-chain count"));
        // mutated bytes (== a well-formed-false address: recomputed != declared)
        let mut e = clone_ev(&generate());
        let n = e.cpuset_chains[0].len();
        e.cpuset_chains[0][n - 1] ^= 1;
        assert!(verify_evidence(&e).is_err());
        // swapped across (arch, role) → binding refuses
        let mut e = clone_ev(&generate());
        e.cpuset_chains.swap(0, 3);
        assert!(verify_evidence(&e)
            .unwrap_err()
            .to_lowercase()
            .contains("cpuset chain"));
    }

    #[test]
    fn retained_runner_attestation_refusals() {
        // missing (count)
        let mut e = clone_ev(&generate());
        e.runner_attestations.pop();
        assert!(verify_evidence(&e)
            .unwrap_err()
            .contains("runner-attestation count"));
        // mutated bytes → recomputed address != declared
        let mut e = clone_ev(&generate());
        let n = e.runner_attestations[0].len();
        e.runner_attestations[0][n - 1] ^= 1;
        assert!(verify_evidence(&e).is_err());
        // swapped across (arch, role) → binding refuses
        let mut e = clone_ev(&generate());
        e.runner_attestations.swap(0, 3);
        assert!(verify_evidence(&e)
            .unwrap_err()
            .to_lowercase()
            .contains("runner attestation"));
    }

    // Sealed-import retained Phase-1 identity-record refusals (the continuity anchor).
    #[test]
    fn retained_identity_record_refusals() {
        assert!(verify_evidence(&generate()).is_ok());
        // dropped record (count)
        let mut e = clone_ev(&generate());
        e.identity_records.pop();
        assert!(verify_evidence(&e)
            .unwrap_err()
            .contains("identity-record count"));
        // extra record (count)
        let mut e = clone_ev(&generate());
        e.identity_records.push(e.identity_records[0].clone());
        assert!(verify_evidence(&e)
            .unwrap_err()
            .contains("identity-record count"));
        // tampered record bytes → address no longer matches the attestation's bound address
        let mut e = clone_ev(&generate());
        let n = e.identity_records[0].len();
        e.identity_records[0][n - 1] ^= 1;
        assert!(verify_evidence(&e).is_err());
        // swapped records across (arch, role) → binding (candidate/arch or address) refuses
        let mut e = clone_ev(&generate());
        e.identity_records.swap(0, 3);
        assert!(verify_evidence(&e).is_err());
        // cross-candidate: a record from candidate B cannot back candidate A's attestation
        let a = generate();
        let b = generate_candidate(Candidate::Risc0);
        let mut e = clone_ev(&a);
        e.identity_records[0] = b.identity_records[0].clone();
        assert!(verify_evidence(&e).is_err());
    }

    // Cross-candidate substitution: a chain/attestation from candidate B cannot back candidate A's
    // provenance (the candidate binding differs).
    #[test]
    fn cross_candidate_artifact_substitution_refused() {
        let a = generate(); // Sp1
        let b = generate_candidate(Candidate::Risc0);
        let mut e = clone_ev(&a);
        e.cpuset_chains[0] = b.cpuset_chains[0].clone();
        assert!(verify_evidence(&e).is_err());
        let mut e2 = clone_ev(&a);
        e2.runner_attestations[0] = b.runner_attestations[0].clone();
        assert!(verify_evidence(&e2).is_err());
    }

    /// TEST_ONLY synthetic RISC Zero material total: the Σ of the four synthetic
    /// per-role lengths this evidence generator uses. It is NOT a protocol
    /// constant, candidate requirement, qualification limit, preregistered
    /// expected result, or venue acceptance condition — an authoritative RISC Zero
    /// bundle may carry ANY own-consistent total (proved by
    /// `stage1_bundle::authoritative_risc0_may_carry_any_total_checked_against_own_manifest`).
    const TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL: u64 = RISC0_GROTH16_VK_BYTES
        + RISC0_CONTROL_ROOT_BYTES
        + RISC0_CONTROL_ID_BYTES
        + RISC0_VERIFIER_PARAMS_BYTES;

    #[test]
    fn per_candidate_verifier_material_total_is_independent_not_a_shared_292() {
        // SP1's total is its single groth16_vk (292); RISC Zero's is the Σ of its
        // four synthetic canonical-role lengths. The verifier recomputes each from
        // the candidate's own manifest — there is no shared 292 constant, and the
        // RISC0 total is synthetic (never checked against a fixed 352).
        let sp1 = verify_evidence(&generate_candidate(Candidate::Sp1)).expect("sp1 valid");
        let risc0 = verify_evidence(&generate_candidate(Candidate::Risc0)).expect("risc0 valid");
        assert_eq!(sp1.verifier_material_bytes, SP1_GROTH16_VK_BYTES);
        assert_eq!(
            risc0.verifier_material_bytes,
            TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL
        );
        assert_ne!(sp1.verifier_material_bytes, risc0.verifier_material_bytes);

        // and the RISC Zero manifest is canonically labelled with all four roles
        let vmm = VerifierMaterialManifestV1::decode_exact(
            &generate_candidate(Candidate::Risc0).verifier_material,
        )
        .unwrap();
        assert_eq!(vmm.validate_canonical(), Ok(()));
        let labels: Vec<&str> = vmm.entries.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "groth16_vk",
                "control_root",
                "control_id",
                "verifier_params"
            ]
        );
    }

    #[test]
    fn paired_same_host_verifies_paired_different_host_rejected() {
        let sp1 = generate();
        // same-host RISC0 peer: candidate + candidate-specific ids differ, host is
        // identical -> the integrated paired path accepts it.
        let risc0 = generate_candidate(Candidate::Risc0);
        assert!(verify_paired_evidence(&sp1, &risc0).is_ok());

        // each alt-host RISC0 peer is internally valid but recorded on a DIFFERENT
        // host in one controlled field; the integrated paired path must reject it.
        let reject_on = |name: &str, mutate: &dyn Fn(&mut Env)| {
            let mut env = default_env();
            mutate(&mut env);
            let alt = generate_with(Candidate::Risc0, &env);
            assert!(
                verify_evidence(&alt).is_ok(),
                "{name}: alt-host bundle must be internally valid"
            );
            assert!(
                verify_paired_evidence(&sp1, &alt).is_err(),
                "e2e paired mismatch on `{name}` must reject"
            );
        };
        reject_on("cpu_model", &|e| e.cpu_model = "alt-cpu".into());
        reject_on("kernel", &|e| e.kernel = "9.9.9".into());
        reject_on("clock_source", &|e| e.clock_source = "hpet".into());
        reject_on("proving_phys", &|e| {
            e.proving.phys = 8;
            e.proving.logical = 16;
        });
        reject_on("proving_ram", &|e| e.proving.ram = 32u64 << 30);
        reject_on("harness_hash", &|e| e.harness_hash = id(b"harness_alt"));
    }

    #[test]
    fn adversarial_matrix_all_reject() {
        let base = generate();
        type M = Box<dyn Fn(&Evidence) -> Evidence>;
        let cases: Vec<(&str, M)> = vec![
            // --- identity & provenance ---
            (
                "wrong_guest_set",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][66] ^= 1;
                    e
                }),
            ),
            (
                "wrong_candidate",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][130] = 2;
                    e
                }),
            ),
            (
                "wrong_program",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][132] ^= 1;
                    e
                }),
            ),
            (
                "wrong_vmat_in_record",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][164] ^= 1;
                    e
                }),
            ),
            (
                "wrong_lock",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][196] ^= 1;
                    e
                }),
            ),
            (
                "wrong_container",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][228] ^= 1;
                    e
                }),
            ),
            (
                "wrong_provenance_hash",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances[0][208] ^= 1;
                    e
                }),
            ),
            (
                "provenance_wrong_arch",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances[0][165] ^= 3;
                    e
                }),
            ),
            (
                "missing_provenance",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances.pop();
                    e
                }),
            ),
            (
                "duplicate_provenance",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.provenances.push(e.provenances[0].clone());
                    e
                }),
            ),
            // --- grid & iteration ---
            (
                "delete_envelope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.envelopes.pop();
                    e
                }),
            ),
            (
                "duplicate_envelope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.envelopes.push(e.envelopes[0].clone());
                    e
                }),
            ),
            (
                "delete_verify_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples.remove(0);
                    e
                }),
            ),
            (
                "duplicate_verify_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples.push(e.samples[0].clone());
                    e
                }),
            ),
            (
                "changed_iteration_index",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][304] ^= 0x40;
                    e
                }),
            ),
            (
                "move_architecture",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][260] = 2;
                    e
                }),
            ),
            (
                "move_statement",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let st = stmt_hash(StatementIndex::SelectToken);
                    e.samples[0][98..130].copy_from_slice(&st);
                    e
                }),
            ),
            (
                "move_proof",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let ph = proof_hash(Arch::X86_64, StatementIndex::Tlg, 5);
                    e.samples[0][272..304].copy_from_slice(&ph);
                    e
                }),
            ),
            (
                "proof_hash_not_matching_envelope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.envelopes[0][267] ^= 1;
                    e
                }),
            ),
            // --- classification ---
            (
                "wrong_metric_kind",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][262] = 3;
                    e
                }),
            ),
            (
                "wrong_unit",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][263] = 2;
                    e
                }),
            ),
            (
                "warmup_substituted",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][261] = 0;
                    e
                }),
            ),
            (
                "failed_status",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.samples[0][308] = 1;
                    e
                }),
            ),
            (
                "wrong_rss_scope",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.rss[0][261] ^= 1;
                    e
                }),
            ),
            (
                "delete_setup_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let i = e.samples.iter().position(|b| b[262] == 6).unwrap();
                    e.samples.remove(i);
                    e
                }),
            ),
            (
                "duplicate_setup_sample",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let i = e.samples.iter().position(|b| b[262] == 6).unwrap();
                    e.samples.push(e.samples[i].clone());
                    e
                }),
            ),
            // --- aggregates & outcome ---
            (
                "falsified_max_pb",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.max_proof_bytes += 1)),
            ),
            (
                "falsified_vmat_total",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.verifier_material_bytes = 999)),
            ),
            (
                "falsified_vrss",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.worst_arch_verifier_rss_bytes += 1)),
            ),
            (
                "falsified_qualification",
                Box::new(|e| with_rs(e, |rs| rs.qualification_result = false)),
            ),
            (
                "qualifying_with_failure_code",
                Box::new(|e| with_rs(e, |rs| rs.failure_codes = vec![3])),
            ),
            (
                "falsified_p99_with_consistent_bundles",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.worst_arch_p99_verify_ns += 1)),
            ),
            // --- verifier material from manifest ---
            (
                "vmat_entry_bytelen_updated_hash",
                Box::new(|e| {
                    let mut m = verifier_material();
                    m.entries[0].byte_len = 293;
                    let mut e = with_rs(e, move |rs| {
                        rs.verifier_material_manifest_hash = m.identity().unwrap()
                    });
                    let mut m2 = verifier_material();
                    m2.entries[0].byte_len = 293;
                    e.verifier_material = m2.encode().unwrap();
                    e
                }),
            ),
            (
                "vmat_omitted_entry",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.verifier_material = VerifierMaterialManifestV1 {
                        candidate: Candidate::Sp1,
                        entries: vec![],
                    }
                    .encode()
                    .unwrap();
                    e
                }),
            ),
            (
                "vmat_wrong_candidate",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let mut m = verifier_material();
                    m.candidate = Candidate::Risc0;
                    e.verifier_material = m.encode().unwrap();
                    e
                }),
            ),
        ];
        for (name, mutate) in &cases {
            let ev = mutate(&base);
            assert!(
                verify_evidence(&ev).is_err(),
                "case `{name}` must be rejected"
            );
        }
    }
}

//! Real (post-spec-hash) measurement-grid orchestrator.
//!
//! The venue runner collects ONLY raw facts — proof hashes, timings, verification
//! samples, RSS, per-(arch,role) cgroup/cpuset provenance, and venue-built
//! guest/program identities. It NEVER supplies a bundle hash or an aggregate.
//!
//! This module injects the two canonical hashes (`b0_pre_spec_hash` and the
//! `r0_guest_set_hash` derived from the populated allowlist) into every record and
//! delegates to the SINGLE shared assembler [`crate::harness::assemble_result_set`]
//! — the same code path the synthetic `generate_with` uses. It therefore has no
//! bundle/aggregate logic of its own, and it NEVER fabricates a cell: RISC Zero on
//! aarch64 is native-ineligible, so no such cell may be supplied; the resulting
//! genuinely-incomplete native matrix is rejected downstream by the frozen verifier
//! (`Reason::MeasuredProofGrid`), which is how a candidate is disqualified.
//!
//! All values here are still NON_SELECTION test scaffolding until the venue runs;
//! selecting a candidate is B0-FINAL and lives elsewhere.

use std::collections::HashMap;

use crate::enums::{
    Arch, Candidate, MetricKind, ProvenanceRole, RssScope, SampleKind, StatementIndex, Status, Unit,
};
use crate::harness::{assemble_result_set, AssemblyInput, Evidence};
use crate::schema::allowlist::{GuestProgramAllowlistV1, GuestProgramEntryV1};
use crate::schema::bench::{BenchmarkRssRecordV1, BenchmarkSampleV1};
use crate::schema::cpuset_chain::CpusetProbeChainV1;
use crate::schema::envelope::{ArtifactHash, R0ProofArtifactEnvelopeV1};
use crate::schema::identity_record::Phase1IdentityRecordV1;
use crate::schema::provenance::{
    cpuset_probe_chain_hash, ArchRunProvenanceV1, CpusetObsV1, CpusetProbeEntryV1, DvfsProvenance,
};
use crate::schema::runner_attestation::RunnerAttestationV1;
use crate::schema::verifier_material::VerifierMaterialManifestV1;

/// A single-entry, leaf-observed cpuset probe chain (readable-nonempty leaf). The real venue chain
/// comes from the host-provenance reader; this builds a canonical, structurally-valid chain for the
/// synthetic/dry-run assembly paths so the retained artifact is always present.
pub fn leaf_cpuset_chain(scope: &str, raw: &str) -> Vec<CpusetProbeEntryV1> {
    let obs = CpusetObsV1 {
        state: 2,
        raw: raw.to_string(),
        file_type: "regular".into(),
        is_symlink: false,
        dev: Some(1),
        inode: Some(2),
        size: Some(raw.len() as u64),
        mtime_secs: Some(0),
        mtime_nanos: Some(0),
        read_error_class: None,
    };
    vec![CpusetProbeEntryV1 {
        cgroup_path: scope.to_string(),
        order: 0,
        first: obs.clone(),
        second: obs,
    }]
}

/// The domain-separated address of a leaf-observed chain (matches [`cpuset_probe_chain_hash`]).
pub fn leaf_cpuset_chain_address(scope: &str, raw: &str) -> [u8; 32] {
    cpuset_probe_chain_hash(&leaf_cpuset_chain(scope, raw))
}

/// A synthetic Phase-1 identity record for the synthetic/dry-run assembly paths, matching the synth
/// runner attestation (same measured-source/tooling/spec; `production_binary_blake3` == the attestation
/// `runner_blake3`). NEVER used on the real path (which builds the record from the venue identity set).
pub fn synth_phase1_identity_record(
    candidate: Candidate,
    arch: Arch,
    measured_source_commit: &str,
    spec: [u8; 32],
    production_binary_blake3: [u8; 32],
) -> Phase1IdentityRecordV1 {
    Phase1IdentityRecordV1 {
        candidate,
        arch,
        source_commit: measured_source_commit.to_string(),
        tooling_commit: "1234567890abcdef1234567890abcdef12345678".to_string(),
        tooling_pathset_blake3: "70".repeat(32),
        b0_pre_spec_hash: spec,
        production_binary_blake3,
    }
}

/// The FIXED synthetic cargo seed-content address every synthetic assembly path uses as the
/// double-build proof's `cargo_seed_origin` (and the host-cargo-home seed-content of the synthetic
/// [`DependencySeedV1`]). Seed-fn-independent, so harness + demo produce identical, mutually-consistent
/// dependency-seed artifacts. NEVER the real venue path.
pub fn synth_cargo_seed_content() -> [u8; 32] {
    *blake3::hash(b"b0-final-synth-cargo-seed-content/v1").as_bytes()
}

/// FIXED synthetic risc0 toolchain-home authority manifest address (RISC0 real embed only). Byte-identical
/// to the independent harness's `synth_risc0_home_content`, so both crates' generators agree cross-crate.
pub fn synth_risc0_home_content() -> [u8; 32] {
    *blake3::hash(b"b0-final-synth-risc0-home-authority/v1").as_bytes()
}

/// The synthetic self-consistent [`DependencySeedV1`] for `candidate` matching [`synth_cargo_seed_content`]:
/// returns `(json_bytes, record_address)`. The synthetic attestation's `dependency_seed_address` is set to
/// `record_address` and the bundle seals `json_bytes`, so the sealed-import cargo dependency-seed anchor
/// accepts. NEVER the real venue path (which retains the venue-produced dependency-seed JSON).
pub fn synth_dependency_seed(candidate: Candidate) -> (Vec<u8>, [u8; 32]) {
    let cand = match candidate {
        Candidate::Sp1 => "sp1",
        Candidate::Risc0 => "risc0",
    };
    let (json, addr, _host) = crate::venue::dependency_seed::DependencySeedV1::synthetic_json(
        cand,
        synth_cargo_seed_content(),
    );
    (json, addr)
}

/// A runner attestation for synthetic/dry-run assembly. `hex32`/`ctx` binding fields are placeholders
/// the orchestrator overwrites with the run's candidate/role/spec/guest_set; the venue-produced fields
/// carry deterministic self-consistent values (build_git_sha == measured_source_commit; recomputed ==
/// ratified path-set; protoc version fixed). NEVER used on the real path (which parses the venue JSON).
pub fn synth_runner_attestation(
    arch: Arch,
    measured_source_commit: &str,
    seed: &dyn Fn(&str) -> [u8; 32],
) -> RunnerAttestationV1 {
    let (recipe, inv_a, inv_b, proof, leak) =
        synth_runner_recipe_artifacts(Candidate::Sp1, arch, measured_source_commit, seed);
    RunnerAttestationV1 {
        candidate: Candidate::Sp1,
        provenance_role: ProvenanceRole::Proving,
        b0_pre_spec_hash: [0; 32],
        r0_guest_set_hash: [0; 32],
        build_target_arch: arch,
        execution_tooling_checkout_head: "1234567890abcdef1234567890abcdef12345678".into(),
        ratified_tooling_commit: recipe.tooling_commit.clone(),
        ratified_pathset_blake3: recipe.tooling_pathset_blake3.clone(),
        recomputed_pathset_blake3: recipe.tooling_pathset_blake3.clone(),
        measured_source_commit: measured_source_commit.to_string(),
        build_git_sha: measured_source_commit.to_string(),
        measured_source_context_blake3: seed("measured-ctx"),
        runner_sha256: proof.build_a.runner_sha256,
        runner_blake3: proof.build_a.runner_blake3,
        immutable_builder_identity: seed("builder"),
        protobuf_authority_sha256: recipe.protobuf_authority_sha256,
        protobuf_authority_blake3: recipe.protobuf_authority_blake3,
        native_protoc_sha256: seed("protoc-sha256"),
        native_protoc_blake3: seed("protoc-blake3"),
        native_protoc_version: "libprotoc 3.21.12".into(),
        docker_argv_blake3: seed("docker-argv"),
        reproducibility_pair_blake3: proof.reproducibility_pair_blake3,
        // Runner continuity: the Phase-1 runner binary equals the measurement runner (runner_blake3).
        phase1_production_binary_blake3: proof.build_a.runner_blake3,
        // Placeholder; the orchestrator/harness sets this from the retained Phase-1 identity record.
        phase1_identity_record_blake3: [0; 32],
        // Runner path-independence: addresses of the five synthetic retained artifacts.
        runner_build_recipe_blake3: recipe.hash(),
        rustc_invocation_inventory_a_blake3: inv_a.hash(),
        rustc_invocation_inventory_b_blake3: inv_b.hash(),
        runner_double_build_proof_blake3: proof.hash(),
        runner_leakage_report_blake3: leak.hash(),
        per_arch_toolchain_identity: recipe.per_arch_toolchain_identity,
        runner_build_recipe_id: recipe.recipe_id,
        // v7 offline-provisioning authority addresses (synthetic, deterministic seeds).
        host_toolchain_attestation_address: seed("host-toolchain-addr"),
        dependency_seed_address: seed("dependency-seed-addr"),
        protoc_authority_address: seed("protoc-authority-addr"),
        // v8 canonical SP1 guest artifact address (synthetic; SP1 candidate in this synth path).
        canonical_sp1_guest_artifact_address: seed("canonical-sp1-guest-addr"),
        measurement_input_authority_address: seed("measurement-input-authority-addr"),
    }
}

/// The five synthetic, self-consistent retained runner-build artifacts matching
/// [`synth_runner_attestation`] (TEST_ONLY vector orchestration; NEVER the real venue path):
/// recipe (exact bytes), build-A + build-B inventories, double-build proof, leakage report.
#[allow(clippy::type_complexity)]
pub fn synth_runner_recipe_artifacts(
    candidate: Candidate,
    arch: Arch,
    measured_source_commit: &str,
    seed: &dyn Fn(&str) -> [u8; 32],
) -> (
    crate::schema::runner_build_recipe::RunnerBuildRecipeV1,
    crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    crate::schema::runner_double_build_proof::RunnerDoubleBuildProofV1,
    crate::schema::runner_leakage_report::RunnerLeakageReportV1,
) {
    use crate::schema::runner_build_recipe::{
        BuildSide, RunnerBuildRecipeV1, CANON_CARGO, CANON_TARGET, CANON_TOOLING,
    };
    use crate::schema::runner_double_build_proof::{BuildFacts, RunnerDoubleBuildProofV1};
    use crate::schema::runner_leakage_report::RunnerLeakageReportV1;
    use crate::schema::rustc_invocation_inventory::{canonical_inventory, InvocationRecord};
    let wrapper = seed("wrapper-blake3");
    let (manifest, artifact) = match candidate {
        Candidate::Sp1 => (
            "tools/b0-pre-measure-sp1/Cargo.toml",
            "release/b0-pre-measure-sp1",
        ),
        Candidate::Risc0 => (
            "tools/b0-pre-measure-risc0/Cargo.toml",
            "release/b0-pre-measure-risc0",
        ),
    };
    let enc = |target: &str| -> Vec<u8> {
        format!("--remap-path-prefix={target}={CANON_TARGET}").into_bytes()
    };
    let side = |t: &str| BuildSide {
        original_root: format!("/b0-input/{t}/tooling"),
        target_from: format!("/b0-input/{t}/target"),
        encoded_rustflags: enc(&format!("/b0-input/{t}/target")),
    };
    let recipe = RunnerBuildRecipeV1 {
        candidate,
        arch,
        recipe_id: RunnerBuildRecipeV1::compute_recipe_id(measured_source_commit, &wrapper),
        build_argv: vec![
            "cargo".into(),
            "build".into(),
            "--release".into(),
            "--locked".into(),
            "--offline".into(),
            "--features".into(),
            "real-backend".into(),
            "--manifest-path".into(),
            manifest.into(),
        ],
        build_env: vec![
            ("BUILD_GIT_SHA".into(), measured_source_commit.to_string()),
            ("SOURCE_DATE_EPOCH".into(), "0".into()),
            ("B0_VENUE_EMBED".into(), "0".into()),
        ],
        manifest_path: manifest.into(),
        artifact_path: artifact.into(),
        cargo_ident: "cargo".into(),
        b0_venue_embed: "0".into(),
        canonical_build_path: CANON_TOOLING.into(),
        canonical_cargo_home: CANON_CARGO.into(),
        build_a: side("a"),
        build_b: side("b"),
        measured_source_commit: measured_source_commit.to_string(),
        tooling_commit: "1234567890abcdef1234567890abcdef12345678".into(),
        tooling_pathset_blake3: "70".repeat(32),
        per_arch_toolchain_identity: seed("per-arch-toolchain"),
        protobuf_authority_sha256: seed("pb-sha256"),
        protobuf_authority_blake3: seed("pb-blake3"),
        wrapper_blake3: wrapper,
    };
    let compile_rec = |t: &str| {
        let mut rec = InvocationRecord {
            kind: "compile".into(),
            remap_args: vec![format!(
                "--remap-path-prefix=/b0-input/{t}/target={CANON_TARGET}"
            )],
            record_address: [0; 32],
        };
        rec.record_address = rec.recompute_address();
        rec
    };
    let inv_a = canonical_inventory(candidate, arch, 0, vec![compile_rec("a")]);
    let inv_b = canonical_inventory(candidate, arch, 1, vec![compile_rec("b")]);
    let runner_sha = seed("runner-sha256");
    let runner_b3 = seed("runner-blake3");
    let guest_img = if candidate == Candidate::Risc0 {
        seed("guest-img")
    } else {
        [0; 32]
    };
    let guest_mb = seed("guest-methods");
    let src_manifest = seed("source-input-manifest");
    // FIXED (seed-fn-independent) synthetic cargo seed-content address, so every synthetic assembly path
    // (harness + demo) shares one host seed and can build the SAME self-consistent DependencySeedV1.
    let cargo_seed = synth_cargo_seed_content();
    // RISC0 real embed only: a fixed synthetic risc0 toolchain-home authority address (3-way equal); SP1 = 0.
    let risc0_home = if candidate == Candidate::Risc0 {
        synth_risc0_home_content()
    } else {
        [0u8; 32]
    };
    let facts = |t: &str, inv_addr: [u8; 32], s: u64, e: u64| BuildFacts {
        original_root: format!("/b0-input/{t}/tooling"),
        target_from: format!("/b0-input/{t}/target"),
        runner_sha256: runner_sha,
        runner_blake3: runner_b3,
        guest_image_id: guest_img,
        guest_methods_blake3: guest_mb,
        inventory_address: inv_addr,
        origin_manifest_blake3: src_manifest,
        materialized_manifest_blake3: src_manifest,
        materialized_cargo_seed_blake3: cargo_seed,
        materialized_risc0_home_blake3: risc0_home,
        start_unix: s,
        end_unix: e,
    };
    let fa = facts("a", inv_a.hash(), 100, 200);
    let fb = facts("b", inv_b.hash(), 200, 300);
    let proof = RunnerDoubleBuildProofV1 {
        candidate,
        arch,
        wrapper_blake3: wrapper,
        cargo_seed_origin_blake3: cargo_seed,
        risc0_home_origin_blake3: risc0_home,
        reproducibility_pair_blake3: RunnerDoubleBuildProofV1::compute_reproducibility_pair(
            &fa, &fb,
        ),
        build_a: fa,
        build_b: fb,
        byte_equal: true,
    };
    let mut refused = vec![
        "/b0-input/a/tooling".to_string(),
        "/b0-input/a/target".to_string(),
        "/b0-input/b/tooling".to_string(),
        "/b0-input/b/target".to_string(),
        "/tmp/b0-evid".to_string(),
    ];
    refused.sort();
    refused.dedup();
    let mut permitted = vec![
        CANON_CARGO.to_string(),
        CANON_TARGET.to_string(),
        CANON_TOOLING.to_string(),
    ];
    if candidate == Candidate::Risc0 {
        permitted.push(crate::schema::runner_build_recipe::CANON_GUESTHOME.to_string());
    }
    permitted.sort();
    let leak = RunnerLeakageReportV1 {
        candidate,
        arch,
        scanned_binary_blake3: runner_b3,
        clean: true,
        evidence_root: "/tmp/b0-evid".into(),
        refused_prefixes: refused,
        permitted_prefixes: permitted,
    };
    (recipe, inv_a, inv_b, proof, leak)
}

/// The allowlist canonical bytes plus one per-candidate evidence bundle each — the
/// content of a committed measurement vector.
/// `(allowlist, measurement_input_authority_json, malformed_corpus_report_json,
/// harness_source_inventory_manifest, eligibility_matrix_json, bundles)` — the VEC8 layout.
pub type MeasurementVector = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    // VEC9: the retained Phase-1 guest-identity record set (encoded Phase1IdentityRecordV2 blobs).
    Vec<Vec<u8>>,
    Vec<(Candidate, Evidence)>,
);

/// Whether `candidate` can produce a NATIVE terminal proof on `arch` — native terminal-MEASUREMENT
/// eligibility under the reviewed two-cell model. Only x86_64 is terminal-measurable:
///
/// * RISC0/aarch64 — the RISC Zero Groth16 receipt path is x86_64-only (VENUE section 2).
/// * SP1/aarch64 terminal Groth16 — no first-party linux/arm64 gnark backend exists (`sp1-gnark` is
///   amd64-only; the stark2snark wrap `docker run`s that image), so it cannot run natively on aarch64.
///
/// Both are ratified fail-closed — see [`crate::venue::eligibility_matrix::EligibilityMatrixV1`], whose
/// `native_measurement_eligible` MUST agree with this function (checked in its `verify`). The SP1/aarch64
/// *identity* stays Phase-1 eligible (the guest set), but is NEVER a measurement. Never emulated/synthesized.
pub fn native_eligible(candidate: Candidate, arch: Arch) -> bool {
    matches!(
        (candidate, arch),
        (Candidate::Sp1, Arch::X86_64) | (Candidate::Risc0, Arch::X86_64)
    )
}

/// The arches on which `candidate` must produce native measurements, derived
/// mechanically from [`native_eligible`] over the frozen two-arch set. RISC Zero
/// yields only x86_64, so its native matrix is genuinely incomplete against the
/// frozen both-arches grid — the frozen, non-fabricating outcome.
pub fn native_matrix(candidate: Candidate) -> Vec<Arch> {
    [Arch::X86_64, Arch::Aarch64]
        .into_iter()
        .filter(|a| native_eligible(candidate, *a))
        .collect()
}

/// Raw per-(arch,role) environment/provenance facts the venue captures. No derived
/// identity hashes — the orchestrator injects `b0_pre_spec_hash`, `r0_guest_set_hash`,
/// candidate, program, lock, and verifier-material identity.
#[derive(Clone)]
pub struct ProvenanceFacts {
    pub arch: Arch,
    pub role: ProvenanceRole,
    pub source_commit: String,
    pub dirty_tree_flag: bool,
    pub builder_container_digest: [u8; 32],
    pub host_os: String,
    pub kernel: String,
    pub cpu_vendor: String,
    pub cpu_model: String,
    pub physical_core_count: u32,
    pub logical_cpu_count: u32,
    pub total_ram_bytes: u64,
    pub configured_cpuset_core_limit: u32,
    pub configured_memory_limit_bytes: u64,
    pub dvfs: DvfsProvenance,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
    pub benchmark_harness_source_hash: [u8; 32],
    pub raw_environment_capture_hash: [u8; 32],
    pub cpuset_source_cgroup_path: String,
    pub cpuset_raw: String,
    pub cpuset_inherited: bool,
    pub cpuset_probe_chain_blake3: [u8; 32],
    /// The full retained probe-chain entries (the address's preimage) — the orchestrator seals these
    /// as a `CpusetProbeChainV1` artifact bound to this provenance.
    pub cpuset_chain_entries: Vec<CpusetProbeEntryV1>,
    /// The parsed runner attestation (venue fields + arch; candidate/role/spec/guest_set binding is
    /// INJECTED by the orchestrator, which then computes `runner_attestation_blake3`).
    pub runner_attestation: RunnerAttestationV1,
    /// v7 offline-provisioning authority addresses (from the recipe facts) the orchestrator binds into
    /// the attestation: the NATIVE host toolchain, the dependency graph-set seed, and (SP1) protoc.
    pub host_toolchain_attestation_address: [u8; 32],
    pub dependency_seed_address: [u8; 32],
    pub protoc_authority_address: [u8; 32],
    /// v8: address of the ONE canonical SP1 guest artifact this measurement proved (SP1 only; ALL-ZERO
    /// for RISC0). Bound into the attestation so measurement-time == Phase-1 guest identity.
    pub canonical_sp1_guest_artifact_address: [u8; 32],
    /// v9: the measurement-wide MeasurementInputAuthorityV1 address (ALL candidates), injected into the
    /// attestation.
    pub measurement_input_authority_address: [u8; 32],
    /// The RETAINED Phase-1 identity record for this provenance's arch. The orchestrator binds the
    /// attestation to it (sets `phase1_production_binary_blake3` + `phase1_identity_record_blake3`) and
    /// seals it as a mandatory package artifact for independent sealed-import re-checking.
    pub phase1_identity_record: Phase1IdentityRecordV1,
    /// The RETAINED runner path-independence artifact set (venue-produced). The orchestrator injects
    /// candidate/arch, sets the attestation's v6 addresses (+ per-arch toolchain + structural recipe
    /// id) from them, binds via `check_bound_runner_recipe`, and seals them as mandatory artifacts.
    pub runner_build_recipe: crate::schema::runner_build_recipe::RunnerBuildRecipeV1,
    pub rustc_invocation_inventory_a:
        crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    pub rustc_invocation_inventory_b:
        crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    pub runner_double_build_proof:
        crate::schema::runner_double_build_proof::RunnerDoubleBuildProofV1,
    pub runner_leakage_report: crate::schema::runner_leakage_report::RunnerLeakageReportV1,
}

/// Raw per-cell measured facts the venue records (never derived).
pub struct CellFacts {
    pub arch: Arch,
    pub statement: StatementIndex,
    pub iteration: u32,
    pub proof_hash: [u8; 32],
    pub artifact_hashes: Vec<(String, [u8; 32])>,
    pub prove_ns: u64,
    pub setup_ns: u64,
    pub proof_bytes: u64,
    pub verify_ns: Vec<u64>,
    pub proving_run_rss_bytes: u64,
    pub verify_batch_rss_bytes: u64,
}

/// The run identities + material that bind every record.
pub struct RunIdentities {
    pub candidate: Candidate,
    pub guest_program_id: [u8; 32],
    pub candidate_dep_lock_hash: [u8; 32],
    pub container_image_digest: [u8; 32],
    pub verifier_material: VerifierMaterialManifestV1,
    pub official_statement_hash_tlg: [u8; 32],
    pub official_statement_hash_st: [u8; 32],
    pub malformed_corpus_result_hash: [u8; 32],
}

/// A venue-built guest identity (per candidate) for the allowlist.
pub struct GuestBuild {
    pub candidate: Candidate,
    pub guest_source_tree_hash: [u8; 32],
    pub candidate_dep_lock_hash: [u8; 32],
    pub builder_arches: Vec<crate::schema::allowlist::BuilderArch>,
    pub guest_image_hash: [u8; 32],
    pub program_id: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub build_command_hash: [u8; 32],
    pub reproducible: bool,
}

/// Populate the guest-program allowlist from venue-built guest identities, binding
/// each entry to `spec`. The canonical `r0_guest_set_hash` is then the allowlist's
/// own `guest_set_hash()` — the ONE canonical computation, never re-implemented.
pub fn official_allowlist(spec: [u8; 32], builds: &[GuestBuild]) -> GuestProgramAllowlistV1 {
    let mut entries: Vec<GuestProgramEntryV1> = builds
        .iter()
        .map(|b| GuestProgramEntryV1 {
            candidate: b.candidate,
            b0_pre_spec_hash: spec,
            guest_source_tree_hash: b.guest_source_tree_hash,
            candidate_dep_lock_hash: b.candidate_dep_lock_hash,
            arches: b.builder_arches.clone(),
            guest_image_hash: b.guest_image_hash,
            program_id: b.program_id,
            verifier_material_manifest_hash: b.verifier_material_manifest_hash,
            build_command_hash: b.build_command_hash,
            reproducible: b.reproducible,
        })
        .collect();
    entries.sort_by_key(|e| e.candidate.to_repr());
    GuestProgramAllowlistV1 { entries }
}

/// The canonical `r0_guest_set_hash` of a populated allowlist.
pub fn r0_guest_set_hash(allowlist: &GuestProgramAllowlistV1) -> [u8; 32] {
    allowlist.guest_set_hash()
}

/// Orchestrate one candidate's evidence from raw venue facts: inject BOTH hashes
/// into every record and delegate to the shared assembler. Fail-closed — a
/// native-ineligible cell (RISC Zero on aarch64) is refused, never synthesized.
pub fn orchestrate_grid(
    spec: [u8; 32],
    guest_set: [u8; 32],
    ids: &RunIdentities,
    provenances: &[ProvenanceFacts],
    cells: &[CellFacts],
    // The measurement-wide MeasurementInputAuthorityV1 address, derived by `produce` from the retained
    // authority bytes and injected into EVERY attestation (never a recipe address string).
    measurement_input_authority_address: [u8; 32],
    // The retained per-CANDIDATE DependencySeedV1 JSON bytes to SEAL + authenticate. REQUIRED (no
    // synthesize-on-absent fallback in this production assembler): the assembler decodes + anchors it and
    // seals it into the VEC7 bundle, so the cargo seed origin is NEVER producer-trusted. The synthetic
    // vector generators call [`orchestrate_grid_synthetic`] (TEST_ONLY), which constructs the record and
    // stamps its address onto the synthetic attestations before delegating here.
    dependency_seed_json: &[u8],
) -> Result<Evidence, String> {
    let dependency_seed_json: Vec<u8> = dependency_seed_json.to_vec();
    let vmat = ids
        .verifier_material
        .identity()
        .map_err(|e| format!("verifier-material identity: {e}"))?;

    // Build provenance records (inject derived hashes); index proving hashes per arch. For each
    // provenance we ALSO build its retained artifacts (cpuset chain + runner attestation), inject the
    // candidate/run/provenance binding, and derive the two content addresses FROM the artifacts — so
    // the sealed package's addresses are provably backed by retained bytes, never asserted alone.
    let mut built_prov = Vec::with_capacity(provenances.len());
    let mut built_chains: Vec<CpusetProbeChainV1> = Vec::with_capacity(provenances.len());
    let mut built_atts: Vec<RunnerAttestationV1> = Vec::with_capacity(provenances.len());
    let mut built_ids: Vec<Phase1IdentityRecordV1> = Vec::with_capacity(provenances.len());
    let mut built_recipes: Vec<crate::schema::runner_build_recipe::RunnerBuildRecipeV1> =
        Vec::with_capacity(provenances.len());
    let mut built_invs_a: Vec<
        crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    > = Vec::with_capacity(provenances.len());
    let mut built_invs_b: Vec<
        crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    > = Vec::with_capacity(provenances.len());
    let mut built_proofs: Vec<crate::schema::runner_double_build_proof::RunnerDoubleBuildProofV1> =
        Vec::with_capacity(provenances.len());
    let mut built_leaks: Vec<crate::schema::runner_leakage_report::RunnerLeakageReportV1> =
        Vec::with_capacity(provenances.len());
    let mut proving_prov: HashMap<u8, [u8; 32]> = HashMap::new();
    for pf in provenances {
        // The RETAINED Phase-1 identity record for this provenance, with the run spec + candidate/arch
        // bound. Its domain-separated address anchors the attestation's continuity.
        let mut rec = pf.phase1_identity_record.clone();
        rec.b0_pre_spec_hash = spec;
        rec.candidate = ids.candidate;
        rec.arch = pf.arch;
        // Inject the run/provenance binding into the venue-produced attestation, bind it to the
        // retained record (continuity), and derive its address.
        let mut att = pf.runner_attestation.clone();
        att.candidate = ids.candidate;
        att.provenance_role = pf.role;
        att.b0_pre_spec_hash = spec;
        att.r0_guest_set_hash = guest_set;
        att.build_target_arch = pf.arch;
        att.phase1_production_binary_blake3 = rec.production_binary_blake3;
        att.phase1_identity_record_blake3 = rec.hash();
        // The RETAINED runner path-independence artifact set (venue-produced), candidate/arch bound;
        // inject the attestation's v6 addresses + per-arch toolchain + structural recipe id from them.
        let mut recipe = pf.runner_build_recipe.clone();
        recipe.candidate = ids.candidate;
        recipe.arch = pf.arch;
        let mut inventory_a = pf.rustc_invocation_inventory_a.clone();
        inventory_a.candidate = ids.candidate;
        inventory_a.arch = pf.arch;
        inventory_a.build_tag = 0;
        let mut inventory_b = pf.rustc_invocation_inventory_b.clone();
        inventory_b.candidate = ids.candidate;
        inventory_b.arch = pf.arch;
        inventory_b.build_tag = 1;
        let mut proof = pf.runner_double_build_proof.clone();
        proof.candidate = ids.candidate;
        proof.arch = pf.arch;
        // The REAL produce() path builds the proof from the RECIPE's candidate (via `build_runner_artifacts`):
        // RISC0 already carries the recipe's risc0 toolchain-home authority (non-zero, and `check_double_build`
        // guarantees it) and SP1 is all-zero — that real risc0-home is PRESERVED here (identity == measurement).
        // ONLY the TEST_ONLY synthetic path (`orchestrate_grid_synthetic`, whose provenance arrives SP1-shaped
        // and never passes through `build_runner_artifacts`) arrives with an all-zero RISC0 risc0-home; supply
        // the fixed synthetic authority for it. A real RISC0 proof is never all-zero here.
        if ids.candidate == Candidate::Risc0 && proof.risc0_home_origin_blake3 == [0u8; 32] {
            let r0 = synth_risc0_home_content();
            proof.risc0_home_origin_blake3 = r0;
            proof.build_a.materialized_risc0_home_blake3 = r0;
            proof.build_b.materialized_risc0_home_blake3 = r0;
        }
        proof.build_a.inventory_address = inventory_a.hash();
        proof.build_b.inventory_address = inventory_b.hash();
        let mut leakage = pf.runner_leakage_report.clone();
        leakage.candidate = ids.candidate;
        leakage.arch = pf.arch;
        // Same TEST_ONLY accommodation as the risc0-home above: synthetic provenance arrives SP1-shaped
        // (3 permitted prefixes). When re-labeled RISC0, add the pinned guest-embed HOME so the leakage
        // matches the candidate-canonical permitted set. The real produce() path already carries it (the
        // recipe's leakage permitted set is validated candidate-correctly in `build_runner_artifacts`), so
        // this is a no-op there.
        if ids.candidate == Candidate::Risc0
            && !leakage
                .permitted_prefixes
                .iter()
                .any(|p| p == "/b0/guesthome")
        {
            leakage.permitted_prefixes.push("/b0/guesthome".to_string());
            leakage.permitted_prefixes.sort();
        }
        att.runner_build_recipe_blake3 = recipe.hash();
        att.rustc_invocation_inventory_a_blake3 = inventory_a.hash();
        att.rustc_invocation_inventory_b_blake3 = inventory_b.hash();
        att.runner_double_build_proof_blake3 = proof.hash();
        att.runner_leakage_report_blake3 = leakage.hash();
        att.per_arch_toolchain_identity = recipe.per_arch_toolchain_identity;
        att.runner_build_recipe_id = recipe.recipe_id;
        // v7: bind the offline-provisioning authority addresses (host toolchain / dependency seed /
        // protoc) the venue recipe facts carried.
        att.host_toolchain_attestation_address = pf.host_toolchain_attestation_address;
        att.dependency_seed_address = pf.dependency_seed_address;
        att.protoc_authority_address = pf.protoc_authority_address;
        // v8: only SP1 measurements consume the shared canonical guest artifact; RISC0 embeds its own
        // locked native guest, so its attestation carries NO canonical address (enforced here, not
        // merely trusted from the recipe facts).
        att.canonical_sp1_guest_artifact_address = if att.candidate == Candidate::Sp1 {
            pf.canonical_sp1_guest_artifact_address
        } else {
            [0u8; 32]
        };
        // v9: EVERY candidate binds the measurement-wide authority address (the shared measurement-input
        // context), derived by `produce` from the retained MIA bytes — never candidate-gated, never a
        // recipe string.
        att.measurement_input_authority_address = measurement_input_authority_address;
        let runner_attestation_blake3 = att.hash();
        // Build the retained cpuset-chain artifact bound to this provenance.
        let chain = CpusetProbeChainV1 {
            candidate: ids.candidate,
            arch: pf.arch,
            provenance_role: pf.role,
            b0_pre_spec_hash: spec,
            r0_guest_set_hash: guest_set,
            leaf_scope: pf.cgroup_scope_label.clone(),
            source_cgroup_path: pf.cpuset_source_cgroup_path.clone(),
            summary_raw: pf.cpuset_raw.clone(),
            summary_inherited: pf.cpuset_inherited,
            summary_count: pf.configured_cpuset_core_limit,
            entries: pf.cpuset_chain_entries.clone(),
        };
        chain.structural_check()?;
        if chain.bound_address() != pf.cpuset_probe_chain_blake3 {
            return Err(
                "cpuset chain entries do not hash to the declared cpuset_probe_chain_blake3".into(),
            );
        }
        // Runner continuity anchored to the retained record (the same check sealed import re-runs).
        att.check_runner_continuity()?;
        att.check_bound_identity_record(&rec)?;
        // Runner path-independence anchored to the retained five-artifact set (the same check sealed
        // import re-runs): recipe, inventory A, inventory B, double-build proof, leakage report.
        att.check_bound_runner_recipe(&recipe, &inventory_a, &inventory_b, &proof, &leakage)?;
        // v8: a RISC0 attestation must carry NO canonical SP1 guest artifact address (cross-candidate
        // substitution guard). SP1's address is bound from the harness-verified package and re-decoded
        // against the retained artifact bytes at guest-set assembly.
        if att.candidate == Candidate::Risc0 {
            att.check_no_canonical_sp1_guest_artifact()?;
        }
        let p = ArchRunProvenanceV1 {
            provenance_role: pf.role,
            b0_pre_spec_hash: spec,
            r0_guest_set_hash: guest_set,
            candidate: ids.candidate,
            guest_program_id: ids.guest_program_id,
            candidate_dep_lock_hash: ids.candidate_dep_lock_hash,
            verifier_material_manifest_hash: vmat,
            arch: pf.arch,
            source_commit: pf.source_commit.clone(),
            dirty_tree_flag: pf.dirty_tree_flag,
            builder_container_digest: pf.builder_container_digest,
            host_os: pf.host_os.clone(),
            kernel: pf.kernel.clone(),
            cpu_vendor: pf.cpu_vendor.clone(),
            cpu_model: pf.cpu_model.clone(),
            physical_core_count: pf.physical_core_count,
            logical_cpu_count: pf.logical_cpu_count,
            total_ram_bytes: pf.total_ram_bytes,
            configured_cpuset_core_limit: pf.configured_cpuset_core_limit,
            configured_memory_limit_bytes: pf.configured_memory_limit_bytes,
            dvfs: pf.dvfs.clone(),
            clock_source: pf.clock_source.clone(),
            cgroup_version: pf.cgroup_version,
            cgroup_scope_label: pf.cgroup_scope_label.clone(),
            benchmark_harness_source_hash: pf.benchmark_harness_source_hash,
            raw_environment_capture_hash: pf.raw_environment_capture_hash,
            cpuset_source_cgroup_path: pf.cpuset_source_cgroup_path.clone(),
            cpuset_raw: pf.cpuset_raw.clone(),
            cpuset_inherited: pf.cpuset_inherited,
            cpuset_probe_chain_blake3: pf.cpuset_probe_chain_blake3,
            runner_attestation_blake3,
        };
        if pf.role == ProvenanceRole::Proving {
            proving_prov.insert(pf.arch.to_repr(), p.provenance_hash());
        }
        built_prov.push(p);
        built_chains.push(chain);
        built_atts.push(att);
        built_ids.push(rec);
        built_recipes.push(recipe);
        built_invs_a.push(inventory_a);
        built_invs_b.push(inventory_b);
        built_proofs.push(proof);
        built_leaks.push(leakage);
    }

    let csh_of = |s: StatementIndex| match s {
        StatementIndex::Tlg => ids.official_statement_hash_tlg,
        StatementIndex::SelectToken => ids.official_statement_hash_st,
    };

    let mut envelopes = Vec::new();
    let mut samples = Vec::new();
    let mut rss = Vec::new();
    for c in cells {
        if !native_eligible(ids.candidate, c.arch) {
            return Err(format!(
                "native-ineligible cell {:?}/{:?}: no measurement may be produced (never synthesized)",
                ids.candidate, c.arch
            ));
        }
        let prov = *proving_prov
            .get(&c.arch.to_repr())
            .ok_or_else(|| format!("missing proving provenance for arch {:?}", c.arch))?;
        let csh = csh_of(c.statement);
        envelopes.push(R0ProofArtifactEnvelopeV1 {
            candidate: ids.candidate,
            candidate_dep_lock_hash: ids.candidate_dep_lock_hash,
            guest_program_id: ids.guest_program_id,
            verifier_material_manifest_hash: vmat,
            computation_statement_hash: csh,
            b0_pre_spec_hash: spec,
            r0_guest_set_hash: guest_set,
            arch_run_provenance: prov,
            arch: c.arch,
            sample_kind: SampleKind::Measured,
            iteration_index: c.iteration,
            proof_hash: c.proof_hash,
            artifact_hashes: c
                .artifact_hashes
                .iter()
                .map(|(l, h)| ArtifactHash {
                    label: l.clone(),
                    hash: *h,
                })
                .collect(),
        });
        let mk_sample =
            |metric: MetricKind, unit: Unit, value: u64, index: u32| BenchmarkSampleV1 {
                b0_pre_spec_hash: spec,
                r0_guest_set_hash: guest_set,
                computation_statement_hash: csh,
                candidate: ids.candidate,
                guest_program_id: ids.guest_program_id,
                verifier_material_manifest_hash: vmat,
                candidate_dep_lock_hash: ids.candidate_dep_lock_hash,
                container_image_digest: ids.container_image_digest,
                arch: c.arch,
                sample_kind: SampleKind::Measured,
                metric_kind: metric,
                unit,
                value,
                proof_hash: c.proof_hash,
                iteration_index: index,
                status: Status::Ok,
            };
        for (rep, &v) in c.verify_ns.iter().enumerate() {
            samples.push(mk_sample(
                MetricKind::HostVerifyNs,
                Unit::Nanoseconds,
                v,
                rep as u32,
            ));
        }
        samples.push(mk_sample(
            MetricKind::HostProveWrapNs,
            Unit::Nanoseconds,
            c.prove_ns,
            c.iteration,
        ));
        samples.push(mk_sample(
            MetricKind::HostSetupNs,
            Unit::Nanoseconds,
            c.setup_ns,
            c.iteration,
        ));
        samples.push(mk_sample(
            MetricKind::ProofBytes,
            Unit::Bytes,
            c.proof_bytes,
            c.iteration,
        ));
        let mk_rss = |scope: RssScope, peak: u64| BenchmarkRssRecordV1 {
            b0_pre_spec_hash: spec,
            r0_guest_set_hash: guest_set,
            // Each RSS record binds the statement of the cell it measures (identical to that cell's
            // proof envelope + samples, keyed by the shared `proof_hash`) — NOT a caller-supplied
            // global. The verifier re-derives `stmt_of(computation_statement_hash)` and requires it
            // to equal the statement of the envelope carrying the same `proof_hash`, so an operator
            // cannot redirect a cell's RSS to another statement.
            computation_statement_hash: csh,
            candidate: ids.candidate,
            guest_program_id: ids.guest_program_id,
            verifier_material_manifest_hash: vmat,
            candidate_dep_lock_hash: ids.candidate_dep_lock_hash,
            container_image_digest: ids.container_image_digest,
            arch: c.arch,
            rss_scope: scope,
            proof_hash: c.proof_hash,
            run_index: c.iteration,
            peak_rss_bytes: peak,
        };
        rss.push(mk_rss(RssScope::ProvingRun, c.proving_run_rss_bytes));
        rss.push(mk_rss(RssScope::VerifyBatch, c.verify_batch_rss_bytes));
    }

    assemble_result_set(&AssemblyInput {
        candidate: ids.candidate,
        b0_pre_spec_hash: spec,
        r0_guest_set_hash: guest_set,
        official_statement_hash_tlg: ids.official_statement_hash_tlg,
        official_statement_hash_st: ids.official_statement_hash_st,
        verifier_material: ids.verifier_material.clone(),
        provenances: built_prov,
        cpuset_chains: built_chains,
        runner_attestations: built_atts,
        identity_records: built_ids,
        recipes: built_recipes,
        inventories_a: built_invs_a,
        inventories_b: built_invs_b,
        double_build_proofs: built_proofs,
        leakage_reports: built_leaks,
        dependency_seed_json,
        envelopes,
        samples,
        rss,
        malformed_corpus_result_hash: ids.malformed_corpus_result_hash,
    })
}

/// TEST_ONLY synthetic wrapper around [`orchestrate_grid`]: constructs the self-consistent
/// [`synth_dependency_seed`] for `ids.candidate`, STAMPS its record address onto every provenance's
/// attestation (the shared synthetic facts carry a candidate-agnostic placeholder), and delegates to the
/// production assembler with the synthesized bytes. NEVER a production path — production callers
/// (`produce`) pass the REAL retained dependency-seed bytes to `orchestrate_grid` directly, and a
/// synthesize-on-absent fallback deliberately does NOT exist there. Used only by the deterministic demo
/// vector generator + the measurement tests (pre-seal synthetic evidence).
pub fn orchestrate_grid_synthetic(
    spec: [u8; 32],
    guest_set: [u8; 32],
    ids: &RunIdentities,
    provenances: &[ProvenanceFacts],
    cells: &[CellFacts],
    measurement_input_authority_address: [u8; 32],
) -> Result<Evidence, String> {
    let (dep_json, dep_addr) = synth_dependency_seed(ids.candidate);
    let mut pfs = provenances.to_vec();
    for pf in &mut pfs {
        pf.dependency_seed_address = dep_addr;
    }
    orchestrate_grid(
        spec,
        guest_set,
        ids,
        &pfs,
        cells,
        measurement_input_authority_address,
        &dep_json,
    )
}

/// Compact length-prefixed transport for a committed real-orchestrator vector: the
/// canonical guest-allowlist bytes plus one per-candidate evidence bundle each.
/// This is an envelope only — it carries NO bundle hash or aggregate; both the
/// reference and the independent verifier recompute everything from the records
/// inside. Format: magic `B0PREMEASVEC1`, then `u32 len‖bytes` for the allowlist,
/// then `u32 n_bundles`, then per bundle: `u16 candidate`, four record lists (each
/// `u32 count` then `u32 len‖bytes`), then `u32 len‖bytes` for verifier_material and
/// result_set. All integers big-endian.
pub fn serialize_vector(
    allowlist_canonical: &[u8],
    measurement_input_authority: &[u8],
    malformed_corpus_report: &[u8],
    harness_source_inventory: &[u8],
    eligibility_matrix: &[u8],
    // VEC9: the complete, self-contained retained Phase-1 GUEST-IDENTITY record set (three encoded
    // Phase1IdentityRecordV2 blobs, canonical order Sp1/x86_64, Sp1/aarch64, Risc0/x86_64). Both verifiers
    // decode these from scratch, authenticate the exact set, DERIVE the allowlist + r0_guest_set_hash from
    // them, and require the top-level allowlist / package guest-set / manifest to match — records-authoritative.
    guest_identity_records_v2: &[Vec<u8>],
    bundles: &[(Candidate, Evidence)],
) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    let mut out = Vec::new();
    // VEC7: adds a per-CANDIDATE retained DependencySeedV1 JSON blob per bundle (after result_set) — so
    // both verifiers re-decode + authenticate the dependency-seed record from scratch and anchor each
    // double-build proof's cargo seed origin to its host-cargo-home seed-content address (never a
    // producer-trusted origin).
    // VEC6 adds three TOP-LEVEL retained measurement-input blobs after the allowlist — the
    // MeasurementInputAuthorityV1 JSON, the complete MalformedCorpusReportV1 JSON, and the complete
    // benchmark-harness source inventory manifest — so both verifiers re-decode the report + inventory
    // and recompute the two addresses the authority binds (never a duplicated caller hash).
    // (VEC5 added the retained-artifact lists; VEC4 the runner path-independence artifacts.)
    // VEC8 adds a FIFTH top-level retained blob after the harness inventory — the EligibilityMatrixV1
    // JSON (the reviewed two-cell model: 3 identities, 2 native-measurement cells, exact unsupported
    // set) — bound by address into the MeasurementInputAuthorityV1, so both verifiers re-decode +
    // recompute it and confirm the authority binds exactly it.
    // VEC9 adds the self-contained retained Phase-1 guest-identity record set (records-authoritative
    // guest set) as a SIXTH top-level retained list after the eligibility matrix. The prior production
    // vector version (VEC8) is REFUSED by the parser — a producer-baked-allowlist package can never be
    // imported under the records-authoritative contract.
    out.extend_from_slice(b"B0PREMEASVEC9");
    put(&mut out, allowlist_canonical);
    put(&mut out, measurement_input_authority);
    put(&mut out, malformed_corpus_report);
    put(&mut out, harness_source_inventory);
    put(&mut out, eligibility_matrix);
    out.extend_from_slice(&(guest_identity_records_v2.len() as u32).to_be_bytes());
    for r in guest_identity_records_v2 {
        put(&mut out, r);
    }
    out.extend_from_slice(&(bundles.len() as u32).to_be_bytes());
    for (c, ev) in bundles {
        out.extend_from_slice(&c.to_repr().to_be_bytes());
        for list in [
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
            out.extend_from_slice(&(list.len() as u32).to_be_bytes());
            for r in list {
                put(&mut out, r);
            }
        }
        put(&mut out, &ev.dependency_seed_json);
        put(&mut out, &ev.verifier_material);
        put(&mut out, &ev.result_set);
    }
    out
}

/// Parse a vector produced by [`serialize_vector`]. Returns the allowlist canonical
/// bytes and the per-candidate bundles.
pub fn parse_vector(bytes: &[u8]) -> Result<MeasurementVector, String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        let s = bytes.get(*p..*p + n).ok_or("vector truncated")?;
        *p += n;
        Ok(s)
    };
    let u32_at = |p: &mut usize| -> Result<usize, String> {
        let b = take(p, 4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let blob = |p: &mut usize| -> Result<Vec<u8>, String> {
        let n = u32_at(p)?;
        Ok(take(p, n)?.to_vec())
    };
    // Refuse the prior production vector version explicitly (records-authoritative contract): a VEC8
    // package derived its guest set from a producer-baked allowlist and carries no retained V2 record set.
    if bytes.get(0..13) == Some(b"B0PREMEASVEC8".as_slice()) {
        return Err(
            "sealed vector version B0PREMEASVEC8 is refused; the records-authoritative contract requires \
             B0PREMEASVEC9 (retained Phase-1 guest-identity record set)"
                .into(),
        );
    }
    if take(&mut p, 13)? != b"B0PREMEASVEC9" {
        return Err("bad magic".into());
    }
    let allowlist = blob(&mut p)?;
    let measurement_input_authority = blob(&mut p)?;
    let malformed_corpus_report = blob(&mut p)?;
    let harness_source_inventory = blob(&mut p)?;
    let eligibility_matrix = blob(&mut p)?;
    // VEC9: the retained Phase-1 guest-identity record set (canonical order Sp1/x86_64, Sp1/aarch64,
    // Risc0/x86_64) — decoded/authenticated + used to DERIVE the guest set by both verifiers.
    let n_guest_records = u32_at(&mut p)?;
    let mut guest_identity_records_v2 = Vec::with_capacity(n_guest_records);
    for _ in 0..n_guest_records {
        guest_identity_records_v2.push(blob(&mut p)?);
    }
    let n_bundles = u32_at(&mut p)?;
    let mut bundles = Vec::new();
    for _ in 0..n_bundles {
        let cb = take(&mut p, 2)?;
        let candidate = Candidate::from_repr(u16::from_be_bytes([cb[0], cb[1]]))
            .map_err(|_| "bad candidate".to_string())?;
        let mut lists: Vec<Vec<Vec<u8>>> = Vec::with_capacity(12);
        for _ in 0..12 {
            let count = u32_at(&mut p)?;
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(blob(&mut p)?);
            }
            lists.push(v);
        }
        let dependency_seed_json = blob(&mut p)?;
        let verifier_material = blob(&mut p)?;
        let result_set = blob(&mut p)?;
        let mut it = lists.into_iter();
        bundles.push((
            candidate,
            Evidence {
                samples: it.next().unwrap(),
                rss: it.next().unwrap(),
                envelopes: it.next().unwrap(),
                provenances: it.next().unwrap(),
                cpuset_chains: it.next().unwrap(),
                runner_attestations: it.next().unwrap(),
                identity_records: it.next().unwrap(),
                recipes: it.next().unwrap(),
                inventories_a: it.next().unwrap(),
                inventories_b: it.next().unwrap(),
                double_build_proofs: it.next().unwrap(),
                leakage_reports: it.next().unwrap(),
                dependency_seed_json,
                verifier_material,
                result_set,
            },
        ));
    }
    if p != bytes.len() {
        return Err("trailing bytes".into());
    }
    Ok((
        allowlist,
        measurement_input_authority,
        malformed_corpus_report,
        harness_source_inventory,
        eligibility_matrix,
        guest_identity_records_v2,
        bundles,
    ))
}

/// Build the ONE canonical committed measurement vector deterministically through
/// the real orchestrator. Reviewed two-cell model: BOTH candidates carry their
/// complete x86_64-only native matrix (SP1/x86_64 and RISC0/x86_64 — the two
/// native-measurement-eligible cells). aarch64 terminal measurement is
/// ratified-unsupported for both, so no aarch64 cell/provenance is present; a
/// fabricated aarch64 cell would be refused by the orchestrator as
/// native-ineligible. Bound to the merged `b0_pre_spec_hash`. Returns the
/// allowlist canonical bytes and the two bundles. No hand-authored result sets.
pub fn deterministic_demo_vector() -> MeasurementVector {
    use crate::enums::VerifierMaterialRole::{ControlId, ControlRoot, Groth16Vk, VerifierParams};
    use crate::schema::allowlist::BuilderArch;

    fn dv(tag: &[u8]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"b0-pre-measurement-vector/v1");
        h.update(tag);
        h.finalize().into()
    }
    fn hex32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        for (i, byte) in a.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        a
    }
    // Merged, ratified b0_pre_spec_hash.
    let spec = hex32("e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2");

    let sp1_material = VerifierMaterialManifestV1::from_canonical(
        Candidate::Sp1,
        [(Groth16Vk, 292u64, dv(b"sp1-vk"))],
    );
    let risc0_material = VerifierMaterialManifestV1::from_canonical(
        Candidate::Risc0,
        [
            (Groth16Vk, 256, dv(b"r0-vk")),
            (ControlRoot, 32, dv(b"r0-cr")),
            (ControlId, 32, dv(b"r0-ci")),
            (VerifierParams, 32, dv(b"r0-vp")),
        ],
    );

    // Venue-built guest identities -> populated allowlist -> canonical guest-set hash.
    let builds = [
        GuestBuild {
            candidate: Candidate::Sp1,
            guest_source_tree_hash: dv(b"sp1-src"),
            candidate_dep_lock_hash: dv(b"sp1-lock"),
            builder_arches: vec![
                BuilderArch {
                    arch: Arch::X86_64,
                    builder_container_digest: dv(b"sp1-bx"),
                },
                BuilderArch {
                    arch: Arch::Aarch64,
                    builder_container_digest: dv(b"sp1-ba"),
                },
            ],
            guest_image_hash: dv(b"sp1-img"),
            program_id: dv(b"sp1-prog"),
            verifier_material_manifest_hash: sp1_material.identity().unwrap(),
            build_command_hash: dv(b"sp1-cmd"),
            reproducible: true,
        },
        GuestBuild {
            candidate: Candidate::Risc0,
            guest_source_tree_hash: dv(b"r0-src"),
            candidate_dep_lock_hash: dv(b"r0-lock"),
            builder_arches: vec![BuilderArch {
                arch: Arch::X86_64,
                builder_container_digest: dv(b"r0-bx"),
            }],
            guest_image_hash: dv(b"r0-img"),
            program_id: dv(b"r0-prog"),
            verifier_material_manifest_hash: risc0_material.identity().unwrap(),
            build_command_hash: dv(b"r0-cmd"),
            reproducible: true,
        },
    ];
    let allowlist = official_allowlist(spec, &builds);
    let guest_set = r0_guest_set_hash(&allowlist);

    const PROV_MSC: &str = "eff3aae18b49969212c4c1493da20f97af195de2";
    // TEST_ONLY VEC9 guest-identity record set for this minimal serialize/parse demo (empty top-level
    // authority blobs). The full authority mirror is exercised by the real producer-selftest vector.
    #[allow(clippy::too_many_arguments)]
    let v2 = |c: Candidate,
              a: Arch,
              tree: [u8; 32],
              lock: [u8; 32],
              img: [u8; 32],
              prog: [u8; 32],
              builder: [u8; 32],
              vmat: [u8; 32],
              cmd: [u8; 32],
              prodbin: [u8; 32]|
     -> Vec<u8> {
        crate::schema::identity_record::Phase1IdentityRecordV2 {
            candidate: c,
            arch: a,
            source_commit: PROV_MSC.to_string(),
            tooling_commit: "1".repeat(40),
            tooling_pathset_blake3: "7".repeat(64),
            b0_pre_spec_hash: spec,
            production_binary_blake3: prodbin,
            guest_source_tree_hash: tree,
            candidate_dep_lock_hash: lock,
            guest_image_hash: img,
            program_id: prog,
            builder_container_digest: builder,
            verifier_material_manifest_hash: vmat,
            build_command_hash: cmd,
            toolchain_identity: if a == Arch::X86_64 {
                "e0".repeat(32)
            } else {
                "e1".repeat(32)
            },
            canonical_sp1_guest_artifact_address: if c == Candidate::Sp1 {
                "ca".repeat(32)
            } else {
                String::new()
            },
        }
        .encode()
    };
    let sp1_vmat = sp1_material.identity().unwrap();
    let r0_vmat = risc0_material.identity().unwrap();
    let v2_records: Vec<Vec<u8>> = vec![
        v2(
            Candidate::Sp1,
            Arch::X86_64,
            dv(b"sp1-src"),
            dv(b"sp1-lock"),
            dv(b"sp1-img"),
            dv(b"sp1-prog"),
            dv(b"sp1-bx"),
            sp1_vmat,
            dv(b"sp1-cmd"),
            dv(b"sp1-runner"),
        ),
        v2(
            Candidate::Sp1,
            Arch::Aarch64,
            dv(b"sp1-src"),
            dv(b"sp1-lock"),
            dv(b"sp1-img"),
            dv(b"sp1-prog"),
            dv(b"sp1-ba"),
            sp1_vmat,
            dv(b"sp1-cmd"),
            dv(b"sp1-runner-arm"),
        ),
        v2(
            Candidate::Risc0,
            Arch::X86_64,
            dv(b"r0-src"),
            dv(b"r0-lock"),
            dv(b"r0-img"),
            dv(b"r0-prog"),
            dv(b"r0-bx"),
            r0_vmat,
            dv(b"r0-cmd"),
            dv(b"r0-runner"),
        ),
    ];
    let prov_seed = |s: &str| dv(s.as_bytes());
    let prov = |arch: Arch, role: ProvenanceRole| -> ProvenanceFacts {
        let (cpuset, mem, phys, logical, ram) = match role {
            ProvenanceRole::Proving => (5u32, 22u64 << 30, 16u32, 32u32, 64u64 << 30),
            ProvenanceRole::Verification => (2u32, 4u64 << 30, 2u32, 4u32, 4u64 << 30),
        };
        ProvenanceFacts {
            arch,
            role,
            // Match the synth attestation's seeded v7 authority addresses (dv == prov_seed).
            host_toolchain_attestation_address: dv(b"host-toolchain-addr"),
            dependency_seed_address: dv(b"dependency-seed-addr"),
            protoc_authority_address: dv(b"protoc-authority-addr"),
            canonical_sp1_guest_artifact_address: dv(b"canonical-sp1-guest-addr"),
            measurement_input_authority_address: dv(b"measurement-input-authority-addr"),
            source_commit: "eff3aae18b49969212c4c1493da20f97af195de2".to_string(),
            dirty_tree_flag: false,
            builder_container_digest: dv(b"builder"),
            host_os: "linux".into(),
            kernel: "6.8.0".into(),
            cpu_vendor: "GenuineIntel".into(),
            cpu_model: "reference".into(),
            physical_core_count: phys,
            logical_cpu_count: logical,
            total_ram_bytes: ram,
            configured_cpuset_core_limit: cpuset,
            configured_memory_limit_bytes: mem,
            dvfs: DvfsProvenance::Observable {
                turbo_enabled: false,
                governor: "performance".into(),
            },
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "b0-pre.slice".into(),
            benchmark_harness_source_hash: dv(b"runner"),
            raw_environment_capture_hash: dv(b"envcap"),
            cpuset_source_cgroup_path: "b0-pre.slice".into(),
            cpuset_raw: if cpuset == 5 { "0-4" } else { "0-1" }.into(),
            cpuset_inherited: false,
            cpuset_probe_chain_blake3: leaf_cpuset_chain_address(
                "b0-pre.slice",
                if cpuset == 5 { "0-4" } else { "0-1" },
            ),
            cpuset_chain_entries: leaf_cpuset_chain(
                "b0-pre.slice",
                if cpuset == 5 { "0-4" } else { "0-1" },
            ),
            runner_attestation: synth_runner_attestation(
                arch,
                "eff3aae18b49969212c4c1493da20f97af195de2",
                &|s: &str| dv(s.as_bytes()),
            ),
            phase1_identity_record: synth_phase1_identity_record(
                Candidate::Sp1,
                arch,
                "eff3aae18b49969212c4c1493da20f97af195de2",
                [0; 32],
                dv(b"runner-blake3"),
            ),
            runner_build_recipe: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                PROV_MSC,
                &prov_seed,
            )
            .0,
            rustc_invocation_inventory_a: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                PROV_MSC,
                &prov_seed,
            )
            .1,
            rustc_invocation_inventory_b: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                PROV_MSC,
                &prov_seed,
            )
            .2,
            runner_double_build_proof: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                PROV_MSC,
                &prov_seed,
            )
            .3,
            runner_leakage_report: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                PROV_MSC,
                &prov_seed,
            )
            .4,
        }
    };
    // Two-cell model: x86_64-only provenance (no aarch64 snapshot may exist).
    let x86 = Arch::X86_64;
    let mut all_prov = Vec::new();
    for r in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
        all_prov.push(prov(x86, r));
    }

    let cell = |cand: &str, arch: Arch, s: StatementIndex, iter: u32| -> CellFacts {
        let key = [cand.as_bytes(), &[arch.to_repr(), s.to_repr(), iter as u8]].concat();
        CellFacts {
            arch,
            statement: s,
            iteration: iter,
            proof_hash: dv(&key),
            artifact_hashes: vec![("receipt".to_string(), dv(&[b"rcpt", &key[..]].concat()))],
            prove_ns: 5_000_000_000 + iter as u64,
            setup_ns: 1_000_000,
            proof_bytes: 200 + iter as u64,
            verify_ns: (0..100)
                .map(|r| 40_000_000 + (r as u64) * 1000 + iter as u64)
                .collect(),
            proving_run_rss_bytes: (2u64 << 30) + iter as u64,
            verify_batch_rss_bytes: (100u64 << 20) + iter as u64,
        }
    };
    let grid = |cand: &str, arches: &[Arch]| -> Vec<CellFacts> {
        let mut v = Vec::new();
        for &a in arches {
            for s in [StatementIndex::Tlg, StatementIndex::SelectToken] {
                for iter in 0..crate::consts::OFFICIAL_ITERATIONS_PER_CELL {
                    v.push(cell(cand, a, s, iter));
                }
            }
        }
        v
    };

    let sp1_ids = RunIdentities {
        candidate: Candidate::Sp1,
        guest_program_id: dv(b"sp1-prog"),
        candidate_dep_lock_hash: dv(b"sp1-lock"),
        container_image_digest: dv(b"sp1-container"),
        verifier_material: sp1_material,
        official_statement_hash_tlg: dv(b"stmt-tlg"),
        official_statement_hash_st: dv(b"stmt-st"),
        malformed_corpus_result_hash: dv(b"malformed"),
    };
    let risc0_ids = RunIdentities {
        candidate: Candidate::Risc0,
        guest_program_id: dv(b"r0-prog"),
        candidate_dep_lock_hash: dv(b"r0-lock"),
        container_image_digest: dv(b"r0-container"),
        verifier_material: risc0_material,
        official_statement_hash_tlg: dv(b"stmt-tlg"),
        official_statement_hash_st: dv(b"stmt-st"),
        malformed_corpus_result_hash: dv(b"malformed"),
    };

    let sp1_ev = orchestrate_grid_synthetic(
        spec,
        guest_set,
        &sp1_ids,
        &all_prov,
        &grid("sp1", &[Arch::X86_64]),
        [7u8; 32],
    )
    .expect("sp1 assembles");
    let risc0_ev = orchestrate_grid_synthetic(
        spec,
        guest_set,
        &risc0_ids,
        &all_prov,
        &grid("risc0", &[Arch::X86_64]),
        [7u8; 32],
    )
    .expect("risc0 assembles");

    (
        allowlist.encode(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        // Minimal serialize/parse demo carries empty top-level authority blobs (MIA/report/inventory/
        // eligibility) — it exercises the bundle path, not the authority path (the full producer-selftest
        // vector carries the real eligibility record + MIA binding).
        Vec::new(),
        v2_records,
        vec![(Candidate::Sp1, sp1_ev), (Candidate::Risc0, risc0_ev)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::verify_evidence;
    use crate::schema::allowlist::BuilderArch;
    use crate::schema::result_set::R0ResultSetV1;
    use crate::schema::verifier_material::VerifierMaterialManifestV1;

    fn h(tag: &[u8]) -> [u8; 32] {
        let mut hh = blake3::Hasher::new();
        hh.update(b"measure-test");
        hh.update(tag);
        hh.finalize().into()
    }
    const SPEC: [u8; 32] = [0x11; 32];

    fn sp1_material() -> VerifierMaterialManifestV1 {
        VerifierMaterialManifestV1::from_canonical(
            Candidate::Sp1,
            [(
                crate::enums::VerifierMaterialRole::Groth16Vk,
                292u64,
                h(b"vk"),
            )],
        )
    }

    fn ids() -> RunIdentities {
        RunIdentities {
            candidate: Candidate::Sp1,
            guest_program_id: h(b"program"),
            candidate_dep_lock_hash: h(b"lock"),
            container_image_digest: h(b"container"),
            verifier_material: sp1_material(),
            official_statement_hash_tlg: h(b"tlg"),
            official_statement_hash_st: h(b"st"),
            malformed_corpus_result_hash: h(b"malformed"),
        }
    }

    // Provenance facts that pass validation::provenance_eligible for each role.
    fn prov_facts(arch: Arch, role: ProvenanceRole) -> ProvenanceFacts {
        let (cpuset, mem, phys, logical, ram) = match role {
            ProvenanceRole::Proving => (5u32, 22u64 << 30, 16u32, 32u32, 64u64 << 30),
            ProvenanceRole::Verification => (2u32, 4u64 << 30, 2u32, 4u32, 4u64 << 30),
        };
        ProvenanceFacts {
            arch,
            role,
            host_toolchain_attestation_address: [20; 32],
            dependency_seed_address: [21; 32],
            protoc_authority_address: [22; 32],
            canonical_sp1_guest_artifact_address: [23; 32],
            measurement_input_authority_address: [24; 32],
            source_commit: "0".repeat(40),
            dirty_tree_flag: false,
            builder_container_digest: h(b"builder"),
            host_os: "linux".into(),
            kernel: "6.8.0".into(),
            cpu_vendor: "GenuineIntel".into(),
            cpu_model: "test".into(),
            physical_core_count: phys,
            logical_cpu_count: logical,
            total_ram_bytes: ram,
            configured_cpuset_core_limit: cpuset,
            configured_memory_limit_bytes: mem,
            dvfs: DvfsProvenance::Observable {
                turbo_enabled: false,
                governor: "performance".into(),
            },
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "b0-pre.slice".into(),
            benchmark_harness_source_hash: h(b"harness"),
            raw_environment_capture_hash: h(b"envcap"),
            cpuset_source_cgroup_path: "b0-pre.slice".into(),
            cpuset_raw: if cpuset == 5 { "0-4" } else { "0-1" }.into(),
            cpuset_inherited: false,
            cpuset_probe_chain_blake3: leaf_cpuset_chain_address(
                "b0-pre.slice",
                if cpuset == 5 { "0-4" } else { "0-1" },
            ),
            cpuset_chain_entries: leaf_cpuset_chain(
                "b0-pre.slice",
                if cpuset == 5 { "0-4" } else { "0-1" },
            ),
            runner_attestation: synth_runner_attestation(arch, &"0".repeat(40), &|s: &str| {
                h(s.as_bytes())
            }),
            phase1_identity_record: synth_phase1_identity_record(
                Candidate::Sp1,
                arch,
                &"0".repeat(40),
                [0; 32],
                h(b"runner-blake3"),
            ),
            runner_build_recipe: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                &"0".repeat(40),
                &|s: &str| h(s.as_bytes()),
            )
            .0,
            rustc_invocation_inventory_a: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                &"0".repeat(40),
                &|s: &str| h(s.as_bytes()),
            )
            .1,
            rustc_invocation_inventory_b: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                &"0".repeat(40),
                &|s: &str| h(s.as_bytes()),
            )
            .2,
            runner_double_build_proof: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                &"0".repeat(40),
                &|s: &str| h(s.as_bytes()),
            )
            .3,
            runner_leakage_report: synth_runner_recipe_artifacts(
                Candidate::Sp1,
                arch,
                &"0".repeat(40),
                &|s: &str| h(s.as_bytes()),
            )
            .4,
        }
    }

    // Two-cell model: the complete provenance set is x86_64 only (proving +
    // verification). No aarch64 snapshot — aarch64 is never measured.
    fn all_provenance() -> Vec<ProvenanceFacts> {
        let mut v = Vec::new();
        for r in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
            v.push(prov_facts(Arch::X86_64, r));
        }
        v
    }

    fn cell(arch: Arch, s: StatementIndex, iter: u32) -> CellFacts {
        let ph = h(&[b"ph", &[arch.to_repr(), s.to_repr(), iter as u8][..]].concat());
        CellFacts {
            arch,
            statement: s,
            iteration: iter,
            proof_hash: ph,
            artifact_hashes: vec![],
            prove_ns: 5_000_000_000,
            setup_ns: 1_000_000,
            proof_bytes: 200 + iter as u64,
            verify_ns: vec![40_000_000 + iter as u64; 100],
            proving_run_rss_bytes: (2u64 << 30) + iter as u64,
            verify_batch_rss_bytes: (100u64 << 20) + iter as u64,
        }
    }

    // A full 2×2×10 native grid over the given arches (SP1: both; RISC0: x86 only).
    fn grid(arches: &[Arch]) -> Vec<CellFacts> {
        let mut cells = Vec::new();
        for &a in arches {
            for s in [StatementIndex::Tlg, StatementIndex::SelectToken] {
                for iter in 0..crate::consts::OFFICIAL_ITERATIONS_PER_CELL {
                    cells.push(cell(a, s, iter));
                }
            }
        }
        cells
    }

    #[test]
    fn allowlist_guest_set_hash_is_canonical_and_binds_spec() {
        let build = GuestBuild {
            candidate: Candidate::Sp1,
            guest_source_tree_hash: h(b"src"),
            candidate_dep_lock_hash: h(b"lock"),
            builder_arches: vec![
                BuilderArch {
                    arch: Arch::X86_64,
                    builder_container_digest: h(b"bx"),
                },
                BuilderArch {
                    arch: Arch::Aarch64,
                    builder_container_digest: h(b"ba"),
                },
            ],
            guest_image_hash: h(b"img"),
            program_id: h(b"program"),
            verifier_material_manifest_hash: sp1_material().identity().unwrap(),
            build_command_hash: h(b"cmd"),
            reproducible: true,
        };
        let al = official_allowlist(SPEC, &[build]);
        // canonical: equals the schema's own guest_set_hash; decodes strictly.
        assert_eq!(r0_guest_set_hash(&al), al.guest_set_hash());
        GuestProgramAllowlistV1::decode_exact(&al.encode()).expect("allowlist decodes");
        assert_eq!(al.entries[0].b0_pre_spec_hash, SPEC);
    }

    #[test]
    fn sp1_real_input_grid_produces_and_verifies() {
        let gs = h(b"guest-set");
        let ev = orchestrate_grid_synthetic(
            SPEC,
            gs,
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .expect("assembles");
        // The frozen verifier INDEPENDENTLY re-derives every bundle + aggregate.
        let r = verify_evidence(&ev).expect("verifies");
        assert!(r.qualification, "40ms p99 < 75ms gate qualifies");
        // Every record binds both hashes: spot-check the result set.
        let rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        assert_eq!(rs.b0_pre_spec_hash, SPEC);
        assert_eq!(rs.r0_guest_set_hash, gs);
        // Two-cell model: x86_64-only grid → 20 measured proofs (was 40).
        assert_eq!(rs.completeness.measured_proof_count, 20);
    }

    #[test]
    fn native_matrix_is_x86_only_for_both_candidates() {
        // Reviewed two-cell model: aarch64 terminal measurement is ratified-unsupported
        // for BOTH candidates. SP1/aarch64 is identity-only, never measured.
        assert_eq!(native_matrix(Candidate::Sp1), vec![Arch::X86_64]);
        assert_eq!(native_matrix(Candidate::Risc0), vec![Arch::X86_64]);
        assert!(!native_eligible(Candidate::Sp1, Arch::Aarch64));
        assert!(!native_eligible(Candidate::Risc0, Arch::Aarch64));
        assert!(native_eligible(Candidate::Sp1, Arch::X86_64));
        assert!(native_eligible(Candidate::Risc0, Arch::X86_64));
    }

    #[test]
    fn risc0_aarch64_cell_is_refused_never_synthesized() {
        let mut r0 = ids();
        r0.candidate = Candidate::Risc0;
        r0.verifier_material = VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [
                (crate::enums::VerifierMaterialRole::Groth16Vk, 256, h(b"vk")),
                (
                    crate::enums::VerifierMaterialRole::ControlRoot,
                    32,
                    h(b"cr"),
                ),
                (crate::enums::VerifierMaterialRole::ControlId, 32, h(b"ci")),
                (
                    crate::enums::VerifierMaterialRole::VerifierParams,
                    32,
                    h(b"vp"),
                ),
            ],
        );
        let cells = vec![cell(Arch::Aarch64, StatementIndex::Tlg, 0)];
        assert!(orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &r0,
            &all_provenance(),
            &cells,
            [7u8; 32]
        )
        .unwrap_err()
        .contains("native-ineligible"));
    }

    #[test]
    fn sp1_aarch64_cell_is_refused_never_synthesized() {
        // Two-cell model: SP1/aarch64 terminal Groth16 is ratified-unsupported. A
        // fabricated aarch64 SP1 cell must be refused before any measurement is
        // synthesized — never treated as an ARM measurement.
        let cells = vec![cell(Arch::Aarch64, StatementIndex::Tlg, 0)];
        assert!(orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(), // ids() is the SP1 candidate
            &all_provenance(),
            &cells,
            [7u8; 32]
        )
        .unwrap_err()
        .contains("native-ineligible"));
    }

    #[test]
    fn risc0_x86_only_grid_is_complete_and_verifies_under_two_cell() {
        let mut r0 = ids();
        r0.candidate = Candidate::Risc0;
        r0.verifier_material = VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [
                (crate::enums::VerifierMaterialRole::Groth16Vk, 256, h(b"vk")),
                (
                    crate::enums::VerifierMaterialRole::ControlRoot,
                    32,
                    h(b"cr"),
                ),
                (crate::enums::VerifierMaterialRole::ControlId, 32, h(b"ci")),
                (
                    crate::enums::VerifierMaterialRole::VerifierParams,
                    32,
                    h(b"vp"),
                ),
            ],
        );
        // Reviewed two-cell model: x86_64 IS RISC0's complete native matrix. The
        // x86-only grid is therefore complete (20 proofs) and the frozen verifier
        // ACCEPTS it — this is one of the two eligible measurement cells.
        let ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &r0,
            &all_provenance(),
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .expect("assembles the complete x86-only matrix");
        let r = verify_evidence(&ev).expect("x86-only RISC0 is a complete two-cell measurement");
        let rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        assert_eq!(rs.completeness.measured_proof_count, 20);
        assert!(r.qualification, "40ms p99 < 75ms gate qualifies");
    }

    #[test]
    fn duplicate_cell_is_rejected() {
        let mut cells = grid(&[Arch::X86_64]);
        // Duplicate the first cell (same arch/stmt/iteration) -> not a valid grid.
        cells.push(cell(Arch::X86_64, StatementIndex::Tlg, 0));
        let res = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &cells,
            [7u8; 32],
        );
        // Either assembly (duplicate measured-proof key) or verification rejects it.
        let rejected = match res {
            Err(_) => true,
            Ok(ev) => verify_evidence(&ev).is_err(),
        };
        assert!(rejected, "a duplicated cell must be rejected");
    }

    #[test]
    fn missing_cell_is_rejected() {
        let mut cells = grid(&[Arch::X86_64]);
        cells.pop(); // drop one cell -> incomplete grid
        let ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &cells,
            [7u8; 32],
        )
        .unwrap();
        assert!(
            verify_evidence(&ev).is_err(),
            "a missing cell must be rejected"
        );
    }

    #[test]
    fn post_result_threshold_mutation_is_rejected() {
        let ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .unwrap();
        verify_evidence(&ev).expect("baseline verifies");
        // Tamper the recorded aggregate p99 after the fact -> verifier recomputes and rejects.
        let mut rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        rs.aggregates.worst_arch_p99_verify_ns += 1;
        let mut tampered = ev;
        tampered.result_set = rs.encode();
        assert!(
            verify_evidence(&tampered).is_err(),
            "a mutated aggregate must be rejected"
        );
    }

    #[test]
    fn altered_proof_binding_is_rejected() {
        // Re-point one sample's proof_hash to a foreign value -> orphaned sample
        // (no matching envelope); the frozen verifier rejects it.
        let mut ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .unwrap();
        let mut s = BenchmarkSampleV1::decode_exact(&ev.samples[0]).unwrap();
        s.proof_hash = h(b"foreign-proof");
        ev.samples[0] = s.encode();
        assert!(
            verify_evidence(&ev).is_err(),
            "an orphaned proof binding must be rejected"
        );
    }

    #[test]
    fn wrong_bundle_aggregate_is_rejected() {
        let ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .unwrap();
        let mut rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        rs.sample_bundles[0].bundle_hash[0] ^= 1;
        let mut tampered = ev;
        tampered.result_set = rs.encode();
        assert!(
            verify_evidence(&tampered).is_err(),
            "a wrong bundle hash must be rejected"
        );
    }

    #[test]
    fn missing_verification_samples_are_rejected() {
        // 99 verify samples in one cell instead of 100 -> short sample count.
        let mut cells = grid(&[Arch::X86_64]);
        cells[0].verify_ns.pop();
        let ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &cells,
            [7u8; 32],
        )
        .unwrap();
        assert!(
            verify_evidence(&ev).is_err(),
            "a short verification-sample count must be rejected"
        );
    }

    #[test]
    fn missing_rss_record_is_rejected() {
        let mut ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .unwrap();
        ev.rss.pop();
        assert!(
            verify_evidence(&ev).is_err(),
            "a missing RSS record must be rejected"
        );
    }

    #[test]
    fn altered_guest_set_hash_is_rejected() {
        let ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .unwrap();
        let mut rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        rs.r0_guest_set_hash[0] ^= 1; // now disagrees with every record's binding
        let mut tampered = ev;
        tampered.result_set = rs.encode();
        assert!(
            verify_evidence(&tampered).is_err(),
            "a mutated guest-set hash must be rejected"
        );
    }

    #[test]
    fn emulated_or_ineligible_provenance_is_rejected() {
        // A verification host that is not the frozen reference (turbo enabled) is
        // ineligible; the whole evidence set is refused (never scored).
        let mut prov = all_provenance();
        for p in &mut prov {
            if p.role == ProvenanceRole::Verification {
                p.dvfs = DvfsProvenance::Observable {
                    turbo_enabled: true,
                    governor: "performance".into(),
                };
            }
        }
        let ev = orchestrate_grid_synthetic(
            SPEC,
            h(b"gs"),
            &ids(),
            &prov,
            &grid(&[Arch::X86_64]),
            [7u8; 32],
        )
        .unwrap();
        assert!(
            verify_evidence(&ev).is_err(),
            "an ineligible/emulated provenance must be rejected"
        );
    }
}

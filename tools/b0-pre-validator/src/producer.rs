//! Official B0-FINAL venue-side measurement PRODUCER.
//!
//! Rust owns the typed records and canonical hashes; the venue shell orchestrates
//! containers (guest builds + prover runs) and emits ONLY raw facts as JSON. This
//! module never trusts a derived value from the shell: it recomputes the guest-set
//! hash from the built identities, materialises statements through the frozen path,
//! and feeds raw facts into the ONE canonical [`crate::measurement::orchestrate_grid`]
//! / [`crate::harness::assemble_result_set`] — it does NOT duplicate bundle hashing
//! or aggregate calculation.
//!
//! Fail-closed before any assembly:
//!   * lifecycle mode MUST be `measurement` and the spec hash MUST equal the merged,
//!     finalized `b0_pre_spec_hash`;
//!   * every provenance host MUST report turbo DISABLED (the runner refuses a
//!     turbo-enabled host; it never alters host settings itself);
//!   * RISC Zero on aarch64 MUST be absent (native-only) — never fabricated; its
//!     genuine incomplete matrix drives the frozen `MeasuredProofGrid` disqualification.
//!
//! The output is a deterministic, content-addressed measurement package (the vector
//! both verifiers accept, plus an inventory) — regenerating from the same raw facts
//! yields byte-identical bytes and the same package id.

use serde::{Deserialize, Serialize};

use crate::enums::{Arch, Candidate, ProvenanceRole, StatementIndex, VerifierMaterialRole};
use crate::measurement::{
    official_allowlist, orchestrate_grid, r0_guest_set_hash, serialize_vector, CellFacts,
    GuestBuild, ProvenanceFacts, RunIdentities,
};
use crate::schema::allowlist::BuilderArch;
use crate::schema::identity_record::Phase1IdentityRecordV1;
use crate::schema::provenance::{
    check_cpuset_probe_chain, cpuset_probe_chain_hash, CpusetObsV1, CpusetProbeEntryV1,
    DvfsProvenance, HypervisorUnobservableDvfs,
};
use crate::schema::runner_attestation::RunnerAttestationV1;
use crate::schema::verifier_material::VerifierMaterialManifestV1;

/// The merged, finalized `b0_pre_spec_hash`. Measurement mode binds to EXACTLY this.
pub const MERGED_SPEC_HASH_HEX: &str =
    "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";

// ---------------------------------------------------------------------------
// Raw-facts contract: what the venue runner writes. NO bundle hash, NO aggregate,
// NO derived guest-set/spec identity beyond the declared spec hash it must match.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RawFacts {
    pub lifecycle_mode: String,
    pub b0_pre_spec_hash: String,
    pub candidates: Vec<CandidateFacts>,
    /// The retained measurement-input artifacts (VEC6): the assembled MeasurementInputAuthorityV1 JSON,
    /// the complete MalformedCorpusReportV1 JSON, and the complete benchmark-harness source inventory
    /// manifest. Populated by `measure-produce --facts` from the pre-grid generated files; the producer
    /// verifies + seals them, and derives every candidate's `malformed_corpus_result_hash` from the
    /// report (never an operator value).
    #[serde(default)]
    pub measurement_input_authority: String,
    #[serde(default)]
    pub malformed_corpus_report: String,
    #[serde(default)]
    pub harness_source_inventory: String,
    /// The retained eligibility/unsupported matrix (`EligibilityMatrixV1`) JSON — the reviewed
    /// two-cell model (3 identities, 2 native-measurement cells, exact unsupported set). The producer
    /// decodes + recomputes its address, requires the authority to bind exactly it, and cross-checks
    /// the unsupported set. Sealed into the measurement container so both verifiers recompute it.
    #[serde(default)]
    pub eligibility_matrix: String,
}

#[derive(Deserialize)]
pub struct CandidateFacts {
    pub candidate: String,
    pub container_image_digest: String,
    pub statement_hash_tlg: String,
    pub statement_hash_st: String,
    pub guest: GuestFacts,
    pub verifier_material: Vec<VmEntryFacts>,
    pub provenance: Vec<ProvFacts>,
    pub cells: Vec<CellFactsJson>,
    /// The complete typed Phase-1 `GuestIdentityRecord` set for this candidate (one per eligible
    /// arch) — MANDATORY input for runner-continuity. Carries `production_binary_blake3` (the
    /// compiled runner that emitted the guest identity), which is required to equal the measurement
    /// `runner_blake3`. SP1: {x86_64, aarch64}; RISC0: {x86_64} (never aarch64).
    pub identity_records: Vec<IdentityRecordFacts>,
    /// The retained per-candidate `DependencySeedV1` JSON (the venue `--dep-seed-json` bytes). Sealed
    /// into the bundle and authenticated at import; every provenance's double-build proof cargo-seed
    /// origin is anchored to its host-cargo-home seed-content address (never producer-trusted).
    /// serde-default so pre-correction facts parse; an empty value fails closed at `produce` (the anchor
    /// decodes it from scratch).
    #[serde(default)]
    pub dependency_seed_json: String,
}

/// The continuity-relevant subset of the Phase-1 `GuestIdentityRecord` (measurement-only; NEVER added
/// to `GuestProgramAllowlistV1`). `GuestBuild` drops `production_binary_blake3`, so it is carried here.
#[derive(Deserialize, Clone)]
pub struct IdentityRecordFacts {
    pub arch: String,
    pub source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub b0_pre_spec_hash: String,
    pub production_binary_blake3: String,
}

#[derive(Deserialize)]
pub struct GuestFacts {
    pub guest_source_tree_hash: String,
    pub candidate_dep_lock_hash: String,
    pub guest_image_hash: String,
    pub program_id: String,
    pub build_command_hash: String,
    pub reproducible: bool,
    pub builder: Vec<BuilderFacts>,
}

#[derive(Deserialize)]
pub struct BuilderFacts {
    pub arch: String,
    pub builder_container_digest: String,
}

#[derive(Deserialize)]
pub struct VmEntryFacts {
    pub role: String,
    pub byte_len: u64,
    pub hash: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ProvFacts {
    pub arch: String,
    pub role: String,
    pub source_commit: String,
    pub dirty_tree_flag: bool,
    pub builder_container_digest: String,
    pub host_os: String,
    pub kernel: String,
    pub cpu_vendor: String,
    pub cpu_model: String,
    pub physical_core_count: u32,
    pub logical_cpu_count: u32,
    pub total_ram_bytes: u64,
    pub configured_cpuset_core_limit: u32,
    pub configured_memory_limit_bytes: u64,
    pub dvfs: DvfsFacts,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
    pub benchmark_harness_source_hash: String,
    pub raw_environment_capture_hash: String,
    // ---- v3: effective-cpuset provenance (summary + full retained chain) + runner attestation ----
    pub cpuset_source_cgroup_path: String,
    pub cpuset_raw: String,
    pub cpuset_inherited: bool,
    pub cpuset_probe_chain: Vec<CpusetProbeEntryJson>,
    pub runner_attestation: RunnerAttestationJson,
    // ---- v6: runner path-independence recipe facts (venue-produced by double_build_runner.sh) ----
    pub runner_recipe: RunnerRecipeJson,
}

/// JSON twin of the venue runner-build recipe facts (exact bytes for BOTH builds). The producer builds
/// the five retained, independently-addressed artifacts (`RunnerBuildRecipeV1`, build-A + build-B
/// `RustcInvocationInventoryV1`, `RunnerDoubleBuildProofV1`, `RunnerLeakageReportV1`) from these facts;
/// the structural recipe id + canonical destinations + derived hashes are recomputed (never trusted).
#[derive(Deserialize, Serialize, Clone)]
pub struct RunnerRecipeJson {
    pub candidate: String,
    pub arch: String,
    pub manifest_path: String,
    pub artifact_path: String,
    pub cargo_ident: String,
    pub b0_venue_embed: String,
    pub canonical_build_path: String,
    /// The literal canonical compiler-visible CARGO_HOME (== /b0/cargo), materialized fresh per build.
    /// serde-default so pre-correction recipe fixtures parse; an empty value is refused by
    /// `check_self_consistent`.
    #[serde(default)]
    pub canonical_cargo_home: String,
    pub per_arch_toolchain_identity: String,
    pub wrapper_blake3: String,
    pub build_argv: Vec<String>,
    pub build_env: Vec<(String, String)>,
    pub build_a: BuildSideJson,
    pub build_b: BuildSideJson,
    pub byte_equal: bool,
    pub leakage_refused_prefixes: Vec<String>,
    pub leakage_permitted_prefixes: Vec<String>,
    pub leakage_clean: bool,
    pub evidence_root: String,
    // ---- offline dependency provisioning (this correction); serde-default so pre-correction recipe
    // fixtures still parse. The `address` fields are the venue authorities' own domain-separated
    // addresses; the producer binds them into the v7 attestation and both verifiers recompute them. ----
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub cargo_net_offline: bool,
    #[serde(default)]
    pub dependency_seed: AuthorityRefJson,
    #[serde(default)]
    pub host_toolchain_attestation: AuthorityRefJson,
    #[serde(default)]
    pub protoc_authority: Option<AuthorityRefJson>,
    #[serde(default)]
    pub risc0_guest_embed: Option<GuestEmbedJson>,
    /// v8: the ONE canonical SP1 guest artifact this measurement consumed (SP1 only). Its SHA-256
    /// address is bound into the attestation; absent for RISC0.
    #[serde(default)]
    pub canonical_sp1_guest_artifact: Option<AuthorityRefJson>,
    /// The fresh-per-build cargo dependency-seed materialization equality (origin == materialized_A ==
    /// materialized_B). serde-default so pre-correction recipe fixtures parse; the producer maps these
    /// into the double-build proof, where the 3-way equality + non-zero origin is re-verified.
    #[serde(default)]
    pub cargo_seed: CargoSeedJson,
    /// (RISC0 real embed only) The fresh-per-build risc0 TOOLCHAIN-HOME working-copy authentication
    /// equality (origin == materialized_A == materialized_B, each authenticated content-equal to the
    /// sealed read-only authority). serde-default/absent for SP1; the producer maps it into the
    /// double-build proof, where the 3-way equality + non-zero origin is re-verified from bytes.
    #[serde(default)]
    pub risc0_home_seed: Option<Risc0HomeSeedJson>,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct CargoSeedJson {
    #[serde(default)]
    pub origin_address: String,
    #[serde(default)]
    pub materialized_a: String,
    #[serde(default)]
    pub materialized_b: String,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct Risc0HomeSeedJson {
    #[serde(default)]
    pub origin_address: String,
    #[serde(default)]
    pub materialized_a: String,
    #[serde(default)]
    pub materialized_b: String,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct AuthorityRefJson {
    pub address: String,
    #[serde(default)]
    pub json_sha256: String,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct GuestEmbedJson {
    pub guest_elf_sha256: String,
    pub guest_elf_blake3: String,
    #[serde(default)]
    pub risc0_build_locked: bool,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct BuildSideJson {
    pub original_root: String,
    pub target_from: String,
    pub encoded_rustflags_hex: String,
    pub runner_sha256: String,
    pub runner_blake3: String,
    pub guest_image_id: String,
    pub guest_methods_blake3: String,
    pub origin_manifest_blake3: String,
    pub materialized_manifest_blake3: String,
    pub start_unix: u64,
    pub end_unix: u64,
    pub invocations: Vec<InvocationRecordJson>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct InvocationRecordJson {
    pub kind: String,
    pub remap_args: Vec<String>,
    pub record_address: String,
}

/// JSON twin of the host-provenance reader's `CpusetObservation`.
#[derive(Deserialize, Serialize, Clone)]
pub struct CpusetObsJson {
    /// "absent" | "readable-empty" | "readable-nonempty" (reader kebab-case).
    pub state: String,
    #[serde(default)]
    pub raw: Option<String>,
    pub file_type: String,
    pub is_symlink: bool,
    #[serde(default)]
    pub dev: Option<u64>,
    #[serde(default)]
    pub inode: Option<u64>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub mtime_secs: Option<i64>,
    #[serde(default)]
    pub mtime_nanos: Option<i64>,
    #[serde(default)]
    pub read_error_class: Option<String>,
}

/// JSON twin of the reader's `CpusetProbeEntry`.
#[derive(Deserialize, Serialize, Clone)]
pub struct CpusetProbeEntryJson {
    pub cgroup_path: String,
    pub order: u32,
    pub first: CpusetObsJson,
    pub second: CpusetObsJson,
}

impl CpusetObsJson {
    fn to_schema(&self) -> Result<CpusetObsV1, String> {
        let state = match self.state.as_str() {
            "absent" => 0u8,
            "readable-empty" => 1,
            "readable-nonempty" => 2,
            other => return Err(format!("bad cpuset observation state {other:?}")),
        };
        Ok(CpusetObsV1 {
            state,
            raw: self.raw.clone().unwrap_or_default(),
            file_type: self.file_type.clone(),
            is_symlink: self.is_symlink,
            dev: self.dev,
            inode: self.inode,
            size: self.size,
            mtime_secs: self.mtime_secs,
            mtime_nanos: self.mtime_nanos,
            read_error_class: self.read_error_class.clone(),
        })
    }
}
impl CpusetProbeEntryJson {
    fn to_schema(&self) -> Result<CpusetProbeEntryV1, String> {
        Ok(CpusetProbeEntryV1 {
            cgroup_path: self.cgroup_path.clone(),
            order: self.order,
            first: self.first.to_schema()?,
            second: self.second.to_schema()?,
        })
    }
}

/// JSON twin of [`RunnerAttestationV1`] (all 32-byte digests as lowercase hex). `Serialize` is
/// derived so the typed generator (`generate_runner_attestation`) can emit canonical bytes for
/// `provenance.json` and re-decode them for a round-trip check before returning success.
#[derive(Deserialize, Serialize, Clone)]
pub struct RunnerAttestationJson {
    pub build_target_arch: String,
    pub execution_tooling_checkout_head: String,
    pub ratified_tooling_commit: String,
    pub ratified_pathset_blake3: String,
    pub recomputed_pathset_blake3: String,
    pub measured_source_commit: String,
    pub build_git_sha: String,
    pub measured_source_context_blake3: String,
    pub runner_sha256: String,
    pub runner_blake3: String,
    pub immutable_builder_identity: String,
    pub protobuf_authority_sha256: String,
    pub protobuf_authority_blake3: String,
    pub native_protoc_sha256: String,
    pub native_protoc_blake3: String,
    pub native_protoc_version: String,
    pub docker_argv_blake3: String,
    pub reproducibility_pair_blake3: String,
}

impl RunnerAttestationJson {
    fn to_schema(&self) -> Result<RunnerAttestationV1, String> {
        Ok(RunnerAttestationV1 {
            // Binding placeholders: the orchestrator injects the run's candidate/role/spec/guest_set
            // (the venue JSON twin carries only the arch + venue-produced fields).
            candidate: Candidate::Sp1,
            provenance_role: ProvenanceRole::Proving,
            b0_pre_spec_hash: [0; 32],
            r0_guest_set_hash: [0; 32],
            build_target_arch: parse_arch(&self.build_target_arch)?,
            execution_tooling_checkout_head: self.execution_tooling_checkout_head.clone(),
            ratified_tooling_commit: self.ratified_tooling_commit.clone(),
            ratified_pathset_blake3: self.ratified_pathset_blake3.clone(),
            recomputed_pathset_blake3: self.recomputed_pathset_blake3.clone(),
            measured_source_commit: self.measured_source_commit.clone(),
            build_git_sha: self.build_git_sha.clone(),
            measured_source_context_blake3: hex32(
                &self.measured_source_context_blake3,
                "runner.measured_source_context_blake3",
            )?,
            runner_sha256: hex32(&self.runner_sha256, "runner.runner_sha256")?,
            runner_blake3: hex32(&self.runner_blake3, "runner.runner_blake3")?,
            immutable_builder_identity: hex32(
                &self.immutable_builder_identity,
                "runner.immutable_builder_identity",
            )?,
            protobuf_authority_sha256: hex32(
                &self.protobuf_authority_sha256,
                "runner.protobuf_authority_sha256",
            )?,
            protobuf_authority_blake3: hex32(
                &self.protobuf_authority_blake3,
                "runner.protobuf_authority_blake3",
            )?,
            native_protoc_sha256: hex32(&self.native_protoc_sha256, "runner.native_protoc_sha256")?,
            native_protoc_blake3: hex32(&self.native_protoc_blake3, "runner.native_protoc_blake3")?,
            native_protoc_version: self.native_protoc_version.clone(),
            docker_argv_blake3: hex32(&self.docker_argv_blake3, "runner.docker_argv_blake3")?,
            reproducibility_pair_blake3: hex32(
                &self.reproducibility_pair_blake3,
                "runner.reproducibility_pair_blake3",
            )?,
            // Runner-continuity placeholders: the orchestrator resolves the retained Phase-1 identity
            // record and sets both from it (production_binary_blake3 + its domain-separated address).
            phase1_production_binary_blake3: [0; 32],
            phase1_identity_record_blake3: [0; 32],
            // Runner path-independence placeholders: the orchestrator builds the three retained
            // artifacts from the venue recipe facts and injects their addresses + per-arch toolchain +
            // structural recipe id.
            runner_build_recipe_blake3: [0; 32],
            rustc_invocation_inventory_a_blake3: [0; 32],
            rustc_invocation_inventory_b_blake3: [0; 32],
            runner_double_build_proof_blake3: [0; 32],
            runner_leakage_report_blake3: [0; 32],
            per_arch_toolchain_identity: [0; 32],
            runner_build_recipe_id: [0; 32],
            // v7 offline-provisioning authority addresses: orchestrator-injected from the recipe facts
            // (verified against the retained authority JSONs) — placeholders here.
            host_toolchain_attestation_address: [0; 32],
            dependency_seed_address: [0; 32],
            protoc_authority_address: [0; 32],
            // v8 injected by the orchestrator from the recipe facts (like the v7 addresses above).
            canonical_sp1_guest_artifact_address: [0; 32],
            // v9 injected by the orchestrator from the recipe facts.
            measurement_input_authority_address: [0; 32],
        })
    }
}

/// JSON twin of the host-provenance DVFS state (matches `b0-pre-host-provenance`'s `DvfsState`).
/// Deserialized from the runner's facts; converted to the sealed [`DvfsProvenance`] schema type.
#[derive(Deserialize, Serialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DvfsFacts {
    Observable {
        turbo_enabled: bool,
        governor: String,
    },
    HypervisorManagedUnobservable {
        cpu_arch: String,
        cpu_identity: String,
        virtualization: String,
        virtualization_source: String,
        absent_controls: Vec<String>,
        raw_evidence_blake3: String,
    },
}

impl DvfsFacts {
    /// Convert to the sealed schema type (parsing the evidence hash hex). Fails closed on bad hex.
    fn to_schema(&self) -> Result<DvfsProvenance, String> {
        Ok(match self {
            DvfsFacts::Observable {
                turbo_enabled,
                governor,
            } => DvfsProvenance::Observable {
                turbo_enabled: *turbo_enabled,
                governor: governor.clone(),
            },
            DvfsFacts::HypervisorManagedUnobservable {
                cpu_arch,
                cpu_identity,
                virtualization,
                virtualization_source,
                absent_controls,
                raw_evidence_blake3,
            } => DvfsProvenance::HypervisorManagedUnobservable(HypervisorUnobservableDvfs {
                cpu_arch: cpu_arch.clone(),
                cpu_identity: cpu_identity.clone(),
                virtualization: virtualization.clone(),
                virtualization_source: virtualization_source.clone(),
                absent_controls: absent_controls.clone(),
                raw_evidence_blake3: hex32(raw_evidence_blake3, "prov.dvfs.raw_evidence_blake3")?,
            }),
        })
    }

    /// Is this an OBSERVED turbo-enabled host? (The unobservable state is never turbo-enabled.)
    fn observed_turbo_enabled(&self) -> bool {
        matches!(
            self,
            DvfsFacts::Observable {
                turbo_enabled: true,
                ..
            }
        )
    }
}

#[derive(Deserialize, Clone)]
pub struct CellFactsJson {
    pub arch: String,
    pub statement: String,
    pub iteration: u32,
    pub proof_hash: String,
    #[serde(default)]
    pub artifact_hashes: Vec<[String; 2]>,
    pub prove_ns: u64,
    pub setup_ns: u64,
    pub proof_bytes: u64,
    pub verify_ns: Vec<u64>,
    pub proving_run_rss_bytes: u64,
    pub verify_batch_rss_bytes: u64,
}

// ---------------------------------------------------------------------------
// Parsing helpers (fail-closed; the shell's strings are untrusted).
// ---------------------------------------------------------------------------

fn hex32(s: &str, ctx: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{ctx}: expected 64 lowercase hex chars"));
    }
    let mut a = [0u8; 32];
    for (i, byte) in a.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("{ctx}: bad hex"))?;
    }
    Ok(a)
}

/// Like [`hex32`] but an EMPTY string yields the all-zero address — used for the v7 offline-provisioning
/// authority addresses so pre-correction recipe fixtures (which lack these fields) still convert.
fn opt_hex32(s: &str, ctx: &str) -> Result<[u8; 32], String> {
    if s.is_empty() {
        Ok([0u8; 32])
    } else {
        hex32(s, ctx)
    }
}

/// Decode an even-length lowercase-hex string to raw bytes (e.g. the exact CARGO_ENCODED_RUSTFLAGS,
/// which contains non-printable `\x1f` separators and so travels hex-encoded in the venue facts).
fn hexbytes(s: &str, ctx: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{ctx}: expected even-length lowercase hex"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("{ctx}: bad hex"))
        })
        .collect()
}
fn parse_candidate(s: &str) -> Result<Candidate, String> {
    match s {
        "Sp1" => Ok(Candidate::Sp1),
        "Risc0" => Ok(Candidate::Risc0),
        other => Err(format!("unknown candidate {other}")),
    }
}
fn parse_arch(s: &str) -> Result<Arch, String> {
    match s {
        "x86_64" | "X86_64" => Ok(Arch::X86_64),
        "aarch64" | "Aarch64" => Ok(Arch::Aarch64),
        other => Err(format!("unknown arch {other}")),
    }
}
fn parse_role(s: &str) -> Result<ProvenanceRole, String> {
    match s {
        "Proving" => Ok(ProvenanceRole::Proving),
        "Verification" => Ok(ProvenanceRole::Verification),
        other => Err(format!("unknown provenance role {other}")),
    }
}
fn parse_stmt(s: &str) -> Result<StatementIndex, String> {
    match s {
        "Tlg" => Ok(StatementIndex::Tlg),
        "SelectToken" => Ok(StatementIndex::SelectToken),
        other => Err(format!("unknown statement {other}")),
    }
}
fn parse_vm_role(s: &str) -> Result<VerifierMaterialRole, String> {
    match s {
        "Groth16Vk" => Ok(VerifierMaterialRole::Groth16Vk),
        "ControlRoot" => Ok(VerifierMaterialRole::ControlRoot),
        "ControlId" => Ok(VerifierMaterialRole::ControlId),
        "VerifierParams" => Ok(VerifierMaterialRole::VerifierParams),
        other => Err(format!("unknown verifier-material role {other}")),
    }
}

/// One candidate's verdict inside the package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateVerdict {
    /// Complete native matrix that the frozen verifier accepts, with qualification.
    Qualified,
    /// Complete native matrix the frozen verifier accepts but that fails a gate.
    DisqualifiedByGate(Vec<u16>),
    /// A genuinely incomplete native matrix the frozen verifier rejects (e.g. RISC
    /// Zero, whose aarch64 cells are native-ineligible). NOT a fabrication.
    IncompleteNativeMatrix(String),
}

/// A deterministic, content-addressed measurement package.
#[derive(Debug)]
pub struct MeasurementPackage {
    /// The serialized real-orchestrator vector (allowlist + per-candidate bundles);
    /// both `b0-pre-validator` and the independent crate accept these exact bytes.
    pub vector: Vec<u8>,
    /// blake3 of `vector` — the content address.
    pub package_id: [u8; 32],
    /// The canonical `r0_guest_set_hash` recomputed from the built identities.
    pub r0_guest_set_hash: [u8; 32],
    /// Per-candidate verdicts in the order produced.
    pub verdicts: Vec<(Candidate, CandidateVerdict)>,
}

impl MeasurementPackage {
    /// A JSON inventory of the package (identities + per-candidate verdict + counts).
    /// Descriptive only; the authoritative bytes are `vector` and `package_id`.
    pub fn inventory(&self) -> serde_json::Value {
        let hx = crate::producer::hx;
        serde_json::json!({
            "package_kind": "b0-final-measurement-package-v1",
            "b0_pre_spec_hash": MERGED_SPEC_HASH_HEX,
            "r0_guest_set_hash": hx(&self.r0_guest_set_hash),
            "package_id": hx(&self.package_id),
            "vector_bytes": self.vector.len(),
            "candidates": self.verdicts.iter().map(|(c, v)| {
                serde_json::json!({
                    "candidate": match c { Candidate::Sp1 => "Sp1", Candidate::Risc0 => "Risc0" },
                    "verdict": match v {
                        CandidateVerdict::Qualified => "qualified".to_string(),
                        CandidateVerdict::DisqualifiedByGate(codes) => format!("disqualified_by_gate:{codes:?}"),
                        CandidateVerdict::IncompleteNativeMatrix(r) => format!("incomplete_native_matrix:{r}"),
                    },
                })
            }).collect::<Vec<_>>(),
        })
    }
}

pub(crate) fn hx(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Structural pre-proving validation of RawFacts. Runs BEFORE any expensive proving
/// so an operator learns of a malformed grid / wrong hash immediately. Checks the
/// lifecycle gate, spec hash, and — per candidate — the native-eligible arch set, the
/// 2-statement x 10-iteration grid, 100 verification samples per cell, present
/// provenance, disabled turbo, and well-formed hex identities. It NEVER assembles or
/// proves; `produce` re-runs the authoritative checks through the canonical assembler.
/// Refuse ANY legacy caller-supplied measurement-input hash in a facts / fragment JSON. All three were
/// REMOVED by the MeasurementInputAuthorityV1 correction — RSS context is derived per-cell, the
/// malformed-corpus result is the retained report's address, and the harness-source hash is the
/// provenance-computed inventory digest — so a JSON carrying any of them is a stale or forged operator
/// input and is refused (never silently ignored). Note `benchmark_harness_source_hash` (the legitimate
/// provenance-computed inventory digest) is NOT one of these keys.
pub fn refuse_legacy_operator_hashes(v: &serde_json::Value) -> Result<(), String> {
    const LEGACY: &[&str] = &[
        "rss_context_hash",
        "malformed_corpus_result_hash",
        "harness_source_hash",
    ];
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                if LEGACY.contains(&k.as_str()) {
                    return Err(format!(
                        "legacy operator hash `{k}` present in facts JSON; removed by the \
                         measurement-input-authority correction (derived from retained artifacts now)"
                    ));
                }
                refuse_legacy_operator_hashes(val)?;
            }
            Ok(())
        }
        serde_json::Value::Array(a) => {
            for x in a {
                refuse_legacy_operator_hashes(x)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn validate_raw_facts(raw: &RawFacts) -> Result<(), String> {
    if raw.lifecycle_mode != "measurement" {
        return Err(format!(
            "lifecycle mode must be `measurement`, got `{}`",
            raw.lifecycle_mode
        ));
    }
    if raw.b0_pre_spec_hash != MERGED_SPEC_HASH_HEX {
        return Err(format!(
            "b0_pre_spec_hash {} != merged finalized {}",
            raw.b0_pre_spec_hash, MERGED_SPEC_HASH_HEX
        ));
    }
    if raw.candidates.is_empty() {
        return Err("no candidate facts supplied (unpopulated)".into());
    }
    for c in &raw.candidates {
        let cand = parse_candidate(&c.candidate)?;
        // The native-eligible arches for this candidate (RISC Zero => x86_64 only).
        let want: Vec<Arch> = crate::measurement::native_matrix(cand);
        // Verify identities are well-formed hex.
        for (label, h) in [
            ("guest_source_tree_hash", &c.guest.guest_source_tree_hash),
            ("candidate_dep_lock_hash", &c.guest.candidate_dep_lock_hash),
            ("guest_image_hash", &c.guest.guest_image_hash),
            ("program_id", &c.guest.program_id),
            ("build_command_hash", &c.guest.build_command_hash),
            ("container_image_digest", &c.container_image_digest),
            ("statement_hash_tlg", &c.statement_hash_tlg),
            ("statement_hash_st", &c.statement_hash_st),
        ] {
            hex32(h, label)?;
        }
        if c.verifier_material.is_empty() {
            return Err(format!("{}: verifier material is empty", c.candidate));
        }
        if c.provenance.is_empty() {
            return Err(format!("{}: no provenance snapshots", c.candidate));
        }
        for p in &c.provenance {
            if p.dvfs.observed_turbo_enabled() {
                return Err(format!(
                    "{}: turbo ENABLED on {} host; refused",
                    c.candidate, p.arch
                ));
            }
        }
        // Grid: exactly (native arches) x {Tlg,SelectToken} x 10, each with 100 verify samples;
        // and NO cell on a non-native arch (fabricated RISC-Zero-ARM).
        use std::collections::BTreeSet;
        let mut seen: BTreeSet<(u8, u8, u32)> = BTreeSet::new();
        for cell in &c.cells {
            let a = parse_arch(&cell.arch)?;
            let s = parse_stmt(&cell.statement)?;
            if !crate::measurement::native_eligible(cand, a) {
                return Err(format!(
                    "{}: native-ineligible cell on {} (never fabricated)",
                    c.candidate, cell.arch
                ));
            }
            if cell.verify_ns.len() != 100 {
                return Err(format!(
                    "{}: cell {}/{}/{} has {} verification samples, need 100",
                    c.candidate,
                    cell.arch,
                    cell.statement,
                    cell.iteration,
                    cell.verify_ns.len()
                ));
            }
            if cell.iteration >= 10 {
                return Err(format!(
                    "{}: iteration {} out of range (0..10)",
                    c.candidate, cell.iteration
                ));
            }
            if !seen.insert((a.to_repr(), s.to_repr(), cell.iteration)) {
                return Err(format!(
                    "{}: duplicate cell {}/{}/{}",
                    c.candidate, cell.arch, cell.statement, cell.iteration
                ));
            }
        }
        // Every native-eligible cell must be present (10 per statement per arch).
        let want_cells = want.len() * 2 * 10;
        if seen.len() != want_cells {
            return Err(format!(
                "{}: {} native cells present, expected {} ({} arches x 2 statements x 10)",
                c.candidate,
                seen.len(),
                want_cells,
                want.len()
            ));
        }
    }
    Ok(())
}

/// Produce a deterministic content-addressed measurement package from raw venue
/// facts. Fail-closed on lifecycle mode, spec hash, turbo, and native-arch rules.
pub fn produce(raw: &RawFacts) -> Result<MeasurementPackage, String> {
    // --- lifecycle + spec-hash gate ---
    if raw.lifecycle_mode != "measurement" {
        return Err(format!(
            "lifecycle mode must be `measurement`, got `{}`",
            raw.lifecycle_mode
        ));
    }
    if raw.b0_pre_spec_hash != MERGED_SPEC_HASH_HEX {
        return Err(format!(
            "b0_pre_spec_hash {} != merged finalized {}",
            raw.b0_pre_spec_hash, MERGED_SPEC_HASH_HEX
        ));
    }
    validate_raw_facts(raw)?;
    let spec = hex32(&raw.b0_pre_spec_hash, "b0_pre_spec_hash")?;

    // FAIL-CLOSED measurement-input authority gate: decode the retained MeasurementInputAuthorityV1 +
    // its malformed-corpus report + harness-source inventory (never operator hashes), verify the
    // authority self-consistency + its bindings to the retained report/inventory bytes, and derive the
    // report address. `measurement_input_authority_address` is injected into every attestation; the
    // report address becomes every candidate's `malformed_corpus_result_hash`. (The venue pre-grid gate
    // additionally ties the authority's tooling commit/path-set to the ratified tooling authority.)
    let mia = crate::venue::measurement_input_authority::MeasurementInputAuthorityV1::from_json(
        raw.measurement_input_authority.as_bytes(),
    )?;
    let mia_address = mia.verify(
        crate::guest_set::RATIFIED_SOURCE_COMMIT,
        &raw.b0_pre_spec_hash,
    )?;
    mia.verify_binds(
        raw.harness_source_inventory.as_bytes(),
        raw.malformed_corpus_report.as_bytes(),
        raw.eligibility_matrix.as_bytes(),
        crate::guest_set::RATIFIED_SOURCE_COMMIT,
        &raw.b0_pre_spec_hash,
    )?;
    // FAIL-CLOSED eligibility gate: independently decode + verify the retained eligibility/unsupported
    // matrix (two-cell model) and cross-check that its native-measurement cells are EXACTLY the two
    // candidate/arch pairs actually measured, and its unsupported set is EXACTLY the ratified pair.
    // `verify_binds` already tied the MIA to this record's address; here we enforce the model against
    // the actual candidates so a package can never measure a cell the matrix forbids.
    let elig = crate::venue::eligibility_matrix::EligibilityMatrixV1::from_json(
        raw.eligibility_matrix.as_bytes(),
    )?;
    elig.verify(&raw.b0_pre_spec_hash)?;
    {
        use std::collections::BTreeSet;
        let want_measure: BTreeSet<(String, String)> =
            elig.measurement_cells().into_iter().collect();
        let mut have_measure: BTreeSet<(String, String)> = BTreeSet::new();
        for c in &raw.candidates {
            for cell in &c.cells {
                have_measure.insert((c.candidate.clone(), cell.arch.clone()));
            }
        }
        if have_measure != want_measure {
            return Err(format!(
                "eligibility matrix measurement cells {want_measure:?} != actual measured cells {have_measure:?} \
                 (a package may only measure the ratified two-cell set)"
            ));
        }
        let unsupported = elig.unsupported_cells();
        let want_unsupported: Vec<(String, String)> = vec![
            ("Sp1".into(), "aarch64".into()),
            ("Risc0".into(), "aarch64".into()),
        ];
        if unsupported != want_unsupported {
            return Err(format!(
                "eligibility matrix unsupported set {unsupported:?} != ratified {want_unsupported:?}"
            ));
        }
    }
    let malformed_report_addr =
        crate::venue::malformed_corpus_report::MalformedCorpusReportV1::from_json(
            raw.malformed_corpus_report.as_bytes(),
        )?
        .verify(
            crate::guest_set::RATIFIED_SOURCE_COMMIT,
            &raw.b0_pre_spec_hash,
        )?;

    // --- build the guest allowlist from the built identities -> canonical guest-set ---
    let mut builds = Vec::new();
    for c in &raw.candidates {
        let cand = parse_candidate(&c.candidate)?;
        let mut arches = Vec::new();
        for b in &c.guest.builder {
            arches.push(BuilderArch {
                arch: parse_arch(&b.arch)?,
                builder_container_digest: hex32(
                    &b.builder_container_digest,
                    "builder_container_digest",
                )?,
            });
        }
        builds.push(GuestBuild {
            candidate: cand,
            guest_source_tree_hash: hex32(
                &c.guest.guest_source_tree_hash,
                "guest_source_tree_hash",
            )?,
            candidate_dep_lock_hash: hex32(
                &c.guest.candidate_dep_lock_hash,
                "candidate_dep_lock_hash",
            )?,
            builder_arches: arches,
            guest_image_hash: hex32(&c.guest.guest_image_hash, "guest_image_hash")?,
            program_id: hex32(&c.guest.program_id, "program_id")?,
            verifier_material_manifest_hash: build_material(c)?
                .identity()
                .map_err(|e| e.to_string())?,
            build_command_hash: hex32(&c.guest.build_command_hash, "build_command_hash")?,
            reproducible: c.guest.reproducible,
        });
    }
    let allowlist = official_allowlist(spec, &builds);
    let guest_set = r0_guest_set_hash(&allowlist);

    // --- per-candidate orchestration through the ONE canonical assembler ---
    let mut bundles = Vec::new();
    let mut verdicts = Vec::new();
    for c in &raw.candidates {
        let cand = parse_candidate(&c.candidate)?;
        let material = build_material(c)?;

        // turbo preflight: refuse a turbo-enabled host (never alter the host).
        for p in &c.provenance {
            if p.dvfs.observed_turbo_enabled() {
                return Err(format!(
                    "{}: turbo is ENABLED on the {} host; refusing (the runner never alters host settings)",
                    c.candidate, p.arch
                ));
            }
        }

        let ids = RunIdentities {
            candidate: cand,
            guest_program_id: hex32(&c.guest.program_id, "program_id")?,
            candidate_dep_lock_hash: hex32(
                &c.guest.candidate_dep_lock_hash,
                "candidate_dep_lock_hash",
            )?,
            container_image_digest: hex32(&c.container_image_digest, "container_image_digest")?,
            verifier_material: material,
            official_statement_hash_tlg: hex32(&c.statement_hash_tlg, "statement_hash_tlg")?,
            official_statement_hash_st: hex32(&c.statement_hash_st, "statement_hash_st")?,
            // DERIVED from the retained malformed-corpus report address (never an operator value).
            malformed_corpus_result_hash: malformed_report_addr,
        };

        // RUNNER CONTINUITY: the complete typed Phase-1 identity record set is a MANDATORY input.
        // Validate the exact eligible arch set for this candidate (no missing/duplicate/Risc0-aarch64),
        // then for each provenance resolve its arch's record and require the Phase-1 runner binary
        // (production_binary_blake3) EQUAL the measurement runner (runner_blake3), plus the same
        // candidate/arch/measured-source/tooling/spec on both sides.
        validate_identity_set(cand, &c.identity_records)?;
        // Build ONE retained, independently-addressed Phase-1 identity record per arch from the
        // mandatory identity set. These are RETAINED in the sealed package; sealed import decodes them
        // from scratch and re-checks continuity against them (not against a copied hash claim).
        let mut retained_ids: Vec<Phase1IdentityRecordV1> = Vec::new();
        for idr in &c.identity_records {
            retained_ids.push(Phase1IdentityRecordV1 {
                candidate: cand,
                arch: parse_arch(&idr.arch)?,
                source_commit: idr.source_commit.clone(),
                tooling_commit: idr.tooling_commit.clone(),
                tooling_pathset_blake3: idr.tooling_pathset_blake3.clone(),
                b0_pre_spec_hash: hex32(&idr.b0_pre_spec_hash, "identity.b0_pre_spec_hash")?,
                production_binary_blake3: hex32(
                    &idr.production_binary_blake3,
                    "identity.production_binary_blake3",
                )?,
            });
        }
        let mut provenances = Vec::new();
        for p in &c.provenance {
            let mut pf = prov_facts(p)?;
            let arch = parse_arch(&p.arch)?;
            let rec = retained_ids
                .iter()
                .find(|r| r.arch == arch)
                .ok_or_else(|| format!("missing Phase-1 identity record for arch {}", p.arch))?;
            let att = &pf.runner_attestation;
            if rec.source_commit != att.measured_source_commit {
                return Err(format!(
                    "{}/{}: Phase-1 source_commit != measurement measured_source_commit",
                    c.candidate, p.arch
                ));
            }
            if rec.tooling_commit != att.ratified_tooling_commit
                || rec.tooling_pathset_blake3 != att.ratified_pathset_blake3
            {
                return Err(format!(
                    "{}/{}: Phase-1 tooling authority != measurement tooling authority",
                    c.candidate, p.arch
                ));
            }
            if rec.b0_pre_spec_hash != spec {
                return Err(format!(
                    "{}/{}: Phase-1 spec != run spec",
                    c.candidate, p.arch
                ));
            }
            if rec.production_binary_blake3 != att.runner_blake3 {
                return Err(format!(
                    "{}/{}: Phase-1 production_binary_blake3 != measurement runner_blake3 (a \
                     different compiled runner binary was used)",
                    c.candidate, p.arch
                ));
            }
            // Carry the RETAINED record; orchestrate_grid binds the attestation to it (sets the two
            // phase1 fields from the record) and seals it as a mandatory package artifact.
            pf.phase1_identity_record = rec.clone();
            provenances.push(pf);
        }
        let mut cells = Vec::new();
        for cell in &c.cells {
            cells.push(cell_facts(cell)?);
        }

        // orchestrate_grid itself refuses a native-ineligible (RISC0/aarch64) cell. The retained
        // per-candidate dependency-seed JSON is SEALED + authenticated; every double-build proof's cargo
        // seed origin is anchored to its host-cargo-home seed-content address (real path: Some).
        let ev = orchestrate_grid(
            spec,
            guest_set,
            &ids,
            &provenances,
            &cells,
            mia_address,
            c.dependency_seed_json.as_bytes(),
        )?;
        // The frozen verifier INDEPENDENTLY re-derives the verdict.
        let verdict = match crate::harness::verify_evidence(&ev) {
            Ok(r) if r.qualification => CandidateVerdict::Qualified,
            Ok(r) => CandidateVerdict::DisqualifiedByGate(r.failure_codes),
            Err(e) => CandidateVerdict::IncompleteNativeMatrix(e),
        };
        verdicts.push((cand, verdict));
        bundles.push((cand, ev));
    }

    let vector = serialize_vector(
        &allowlist.encode(),
        raw.measurement_input_authority.as_bytes(),
        raw.malformed_corpus_report.as_bytes(),
        raw.harness_source_inventory.as_bytes(),
        raw.eligibility_matrix.as_bytes(),
        &bundles,
    );
    let package_id = crate::hashing::plain(&vector);
    Ok(MeasurementPackage {
        vector,
        package_id,
        r0_guest_set_hash: guest_set,
        verdicts,
    })
}

fn build_material(c: &CandidateFacts) -> Result<VerifierMaterialManifestV1, String> {
    let cand = parse_candidate(&c.candidate)?;
    let mut entries = Vec::new();
    for e in &c.verifier_material {
        entries.push((
            parse_vm_role(&e.role)?,
            e.byte_len,
            hex32(&e.hash, "verifier_material.hash")?,
        ));
    }
    Ok(VerifierMaterialManifestV1::from_canonical(cand, entries))
}

/// The FIVE retained runner path-independence artifacts derived from the venue recipe facts.
pub(crate) struct RunnerArtifacts {
    pub runner_build_recipe: crate::schema::runner_build_recipe::RunnerBuildRecipeV1,
    pub rustc_invocation_inventory_a:
        crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    pub rustc_invocation_inventory_b:
        crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
    pub runner_double_build_proof:
        crate::schema::runner_double_build_proof::RunnerDoubleBuildProofV1,
    pub runner_leakage_report: crate::schema::runner_leakage_report::RunnerLeakageReportV1,
}

/// Build + self/consistency-check the five retained runner path-independence artifacts from the venue
/// recipe facts. The structural recipe id, canonical destinations, and every derived hash are RECOMPUTED
/// (never trusted). `attestation` supplies the run-bound scalars (candidate/arch/measured-source/tooling
/// authority/protobuf authority/runner_blake3). Shared by [`prov_facts`] (sealed import) and
/// [`generate_runner_attestation`] (venue pre-proving generation) so both compute an identical
/// `RunnerDoubleBuildProofV1::reproducibility_pair_blake3`.
pub(crate) fn build_runner_artifacts(
    rr: &RunnerRecipeJson,
    attestation: &RunnerAttestationV1,
) -> Result<RunnerArtifacts, String> {
    // The RECIPE is the candidate source of truth (it carries the candidate-specific risc0-home seed +
    // leakage permitted set); the attestation's candidate is a pre-injection placeholder at the venue-facts
    // stage. Driving `cand` from the recipe makes the RISC0 artifacts (risc0-home 3-way + /b0/guesthome
    // leakage) validate correctly here — the same code the generator and sealed import both run.
    let cand = parse_candidate_lenient(&rr.candidate)?;
    let arch = attestation.build_target_arch;
    let wrapper_blake3 = hex32(&rr.wrapper_blake3, "recipe.wrapper_blake3")?;
    // The build IS offline: require BOTH the executed argv carry `--offline` (enforced below by
    // `check_argv`'s full-vector equality — exactly one `--offline` in the canonical vector) AND the
    // redundant offline facts be true. A false boolean while the argv is offline (or vice versa) is refused.
    if !rr.offline || !rr.cargo_net_offline {
        return Err(
            "recipe is not marked offline: offline + cargo_net_offline must both be true (the build \
             runs --offline; the argv and the facts must agree)"
                .into(),
        );
    }
    let build_side =
        |b: &BuildSideJson| -> Result<crate::schema::runner_build_recipe::BuildSide, String> {
            Ok(crate::schema::runner_build_recipe::BuildSide {
                original_root: b.original_root.clone(),
                target_from: b.target_from.clone(),
                encoded_rustflags: hexbytes(
                    &b.encoded_rustflags_hex,
                    "recipe.encoded_rustflags_hex",
                )?,
            })
        };
    let runner_build_recipe = {
        use crate::schema::runner_build_recipe::RunnerBuildRecipeV1;
        let rec = RunnerBuildRecipeV1 {
            candidate: cand,
            arch,
            recipe_id: RunnerBuildRecipeV1::compute_recipe_id(
                &attestation.measured_source_commit,
                &wrapper_blake3,
            ),
            build_argv: rr.build_argv.clone(),
            build_env: rr.build_env.clone(),
            manifest_path: rr.manifest_path.clone(),
            artifact_path: rr.artifact_path.clone(),
            cargo_ident: rr.cargo_ident.clone(),
            b0_venue_embed: rr.b0_venue_embed.clone(),
            canonical_build_path: rr.canonical_build_path.clone(),
            canonical_cargo_home: rr.canonical_cargo_home.clone(),
            build_a: build_side(&rr.build_a)?,
            build_b: build_side(&rr.build_b)?,
            measured_source_commit: attestation.measured_source_commit.clone(),
            tooling_commit: attestation.ratified_tooling_commit.clone(),
            tooling_pathset_blake3: attestation.ratified_pathset_blake3.clone(),
            per_arch_toolchain_identity: hex32(
                &rr.per_arch_toolchain_identity,
                "recipe.per_arch_toolchain_identity",
            )?,
            protobuf_authority_sha256: attestation.protobuf_authority_sha256,
            protobuf_authority_blake3: attestation.protobuf_authority_blake3,
            wrapper_blake3,
        };
        rec.check_self_consistent()?;
        rec
    };
    let build_inventory = |b: &BuildSideJson,
                           tag: u8|
     -> Result<
        crate::schema::rustc_invocation_inventory::RustcInvocationInventoryV1,
        String,
    > {
        use crate::schema::rustc_invocation_inventory::{canonical_inventory, InvocationRecord};
        let recs: Vec<InvocationRecord> = b
            .invocations
            .iter()
            .map(|i| {
                Ok::<_, String>(InvocationRecord {
                    kind: i.kind.clone(),
                    remap_args: i.remap_args.clone(),
                    record_address: hex32(&i.record_address, "recipe.invocation.record_address")?,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(canonical_inventory(cand, arch, tag, recs))
    };
    let rustc_invocation_inventory_a = build_inventory(&rr.build_a, 0)?;
    let rustc_invocation_inventory_b = build_inventory(&rr.build_b, 1)?;
    let runner_double_build_proof = {
        use crate::schema::runner_double_build_proof::{BuildFacts, RunnerDoubleBuildProofV1};
        let facts = |b: &BuildSideJson,
                     inv_addr: [u8; 32],
                     mat_cargo_seed: [u8; 32],
                     mat_risc0_home: [u8; 32]|
         -> Result<BuildFacts, String> {
            Ok(BuildFacts {
                original_root: b.original_root.clone(),
                target_from: b.target_from.clone(),
                runner_sha256: hex32(&b.runner_sha256, "recipe.runner_sha256")?,
                runner_blake3: hex32(&b.runner_blake3, "recipe.runner_blake3")?,
                guest_image_id: hex32(&b.guest_image_id, "recipe.guest_image_id")?,
                guest_methods_blake3: hex32(
                    &b.guest_methods_blake3,
                    "recipe.guest_methods_blake3",
                )?,
                inventory_address: inv_addr,
                origin_manifest_blake3: hex32(
                    &b.origin_manifest_blake3,
                    "recipe.origin_manifest_blake3",
                )?,
                materialized_manifest_blake3: hex32(
                    &b.materialized_manifest_blake3,
                    "recipe.materialized_manifest_blake3",
                )?,
                materialized_cargo_seed_blake3: mat_cargo_seed,
                materialized_risc0_home_blake3: mat_risc0_home,
                start_unix: b.start_unix,
                end_unix: b.end_unix,
            })
        };
        // Fresh-per-build cargo dependency-seed materialization equality: the venue authenticated each
        // build's materialized /b0/cargo seed against the retained authority (origin) fail-hard; carry
        // origin + per-build materialized addresses so the 3-way equality is re-verified from bytes.
        let cargo_seed_origin_blake3 = hex32(
            &rr.cargo_seed.origin_address,
            "recipe.cargo_seed.origin_address",
        )?;
        let mat_cargo_a = hex32(
            &rr.cargo_seed.materialized_a,
            "recipe.cargo_seed.materialized_a",
        )?;
        let mat_cargo_b = hex32(
            &rr.cargo_seed.materialized_b,
            "recipe.cargo_seed.materialized_b",
        )?;
        // Fresh-per-build risc0 TOOLCHAIN-HOME working copy (RISC0 real embed only): origin + per-build
        // materialized manifest addresses so the 3-way equality is re-verified from bytes. Absent for SP1.
        // Gate on the PROOF candidate (== attestation candidate), so a recipe whose candidate field drifts
        // from the sealed proof candidate can never smuggle a risc0-home into an SP1 proof (or omit it from
        // a RISC0 proof — an absent seed on a RISC0 proof yields all-zero, which check_double_build refuses).
        let (risc0_home_origin_blake3, mat_r0_a, mat_r0_b) = if cand == Candidate::Risc0 {
            match &rr.risc0_home_seed {
                Some(h) => (
                    hex32(&h.origin_address, "recipe.risc0_home_seed.origin_address")?,
                    hex32(&h.materialized_a, "recipe.risc0_home_seed.materialized_a")?,
                    hex32(&h.materialized_b, "recipe.risc0_home_seed.materialized_b")?,
                ),
                None => ([0u8; 32], [0u8; 32], [0u8; 32]),
            }
        } else {
            ([0u8; 32], [0u8; 32], [0u8; 32])
        };
        let fa = facts(
            &rr.build_a,
            rustc_invocation_inventory_a.hash(),
            mat_cargo_a,
            mat_r0_a,
        )?;
        let fb = facts(
            &rr.build_b,
            rustc_invocation_inventory_b.hash(),
            mat_cargo_b,
            mat_r0_b,
        )?;
        RunnerDoubleBuildProofV1 {
            candidate: cand,
            arch,
            wrapper_blake3,
            cargo_seed_origin_blake3,
            risc0_home_origin_blake3,
            reproducibility_pair_blake3: RunnerDoubleBuildProofV1::compute_reproducibility_pair(
                &fa, &fb,
            ),
            build_a: fa,
            build_b: fb,
            byte_equal: rr.byte_equal,
        }
    };
    let runner_leakage_report = {
        use crate::schema::runner_leakage_report::RunnerLeakageReportV1;
        let mut refused = rr.leakage_refused_prefixes.clone();
        refused.sort();
        refused.dedup();
        let mut permitted = rr.leakage_permitted_prefixes.clone();
        permitted.sort();
        permitted.dedup();
        let lk = RunnerLeakageReportV1 {
            candidate: cand,
            arch,
            scanned_binary_blake3: attestation.runner_blake3,
            clean: rr.leakage_clean,
            evidence_root: rr.evidence_root.clone(),
            refused_prefixes: refused,
            permitted_prefixes: permitted,
        };
        lk.check_clean_and_exact(&runner_build_recipe)?;
        lk
    };
    runner_double_build_proof.check_double_build(
        &runner_build_recipe,
        &rustc_invocation_inventory_a,
        &rustc_invocation_inventory_b,
    )?;
    Ok(RunnerArtifacts {
        runner_build_recipe,
        rustc_invocation_inventory_a,
        rustc_invocation_inventory_b,
        runner_double_build_proof,
        runner_leakage_report,
    })
}

/// Venue-produced scalar inputs for [`generate_runner_attestation`] — assembled by
/// `measure_fragment.sh` from the retained authorities (protobuf-include authority, builder evidence,
/// tooling-pathset recompute, git HEAD). Everything security-critical (construction of the typed
/// record, the binding checks, canonical serialization, and the round-trip) happens in the typed
/// generator; these are only the authenticated scalar facts it binds. No shell assembles the object.
#[derive(Deserialize)]
pub struct RunnerAttestationGenInputs {
    pub arch: String,
    /// The venue-attested measured-source commit (must equal `guest_set::RATIFIED_SOURCE_COMMIT`).
    pub source_commit: String,
    /// `BUILD_GIT_SHA` the runner build was stamped with; defaults to `source_commit`.
    #[serde(default)]
    pub build_git_sha: Option<String>,
    pub execution_tooling_checkout_head: String,
    /// Path-set digest recomputed over the tooling root at run time (must equal the ratified constant).
    pub recomputed_pathset_blake3: String,
    pub immutable_builder_identity: String,
    /// `staged_context_blake3` from `build_container.sh` (guest-source staged context).
    pub measured_source_context_blake3: String,
    pub protobuf_authority_sha256: String,
    pub protobuf_authority_blake3: String,
    pub native_protoc_sha256: String,
    pub native_protoc_blake3: String,
    pub native_protoc_version: String,
    /// The exact controlled `docker run` argv + mount spec string (protobuf-include authority); the
    /// generator content-addresses it (`docker_argv_blake3 = blake3(argv)`) — never shell.
    pub docker_argv: String,
}

/// Candidate parse that accepts BOTH the capitalized identity-record spelling (`Sp1`/`Risc0`) and the
/// lowercase recipe spelling the runner writes (`sp1`/`risc0`, from `double_build_runner --candidate`).
/// The strict [`parse_candidate`] is retained for the capitalized fragment/candidate JSON.
fn parse_candidate_lenient(s: &str) -> Result<Candidate, String> {
    match s {
        "Sp1" | "sp1" => Ok(Candidate::Sp1),
        "Risc0" | "risc0" => Ok(Candidate::Risc0),
        other => Err(format!("unknown candidate {other}")),
    }
}

/// Resolve the UNIQUE Phase-1 identity record for `(candidate, arch)`; refuse missing/duplicate.
fn resolve_phase1(
    records: &[crate::guest_set::GuestIdentityRecord],
    cand: Candidate,
    arch: Arch,
) -> Result<&crate::guest_set::GuestIdentityRecord, String> {
    let mut it = records.iter().filter(|r| {
        parse_candidate_lenient(&r.candidate)
            .map(|c| c == cand)
            .unwrap_or(false)
            && parse_arch(&r.arch).map(|a| a == arch).unwrap_or(false)
    });
    let first = it
        .next()
        .ok_or_else(|| format!("no Phase-1 identity record for {cand:?}/{arch:?}"))?;
    if it.next().is_some() {
        return Err(format!(
            "duplicate Phase-1 identity records for {cand:?}/{arch:?}"
        ));
    }
    Ok(first)
}

/// The self-consistency + measured-source + tooling + Phase-1 continuity checks the SEALED importer
/// enforces (`produce`'s per-provenance block + `RunnerAttestationV1::check_self_consistency`), applied
/// to a venue `RunnerAttestationJson`. Shared by the generator (over its output, twice) and reused in
/// spirit by [`validate_provenance`] (which additionally runs the full `prov_facts` recipe binder).
fn check_generated_attestation(
    json: &RunnerAttestationJson,
    cand: Candidate,
    arch: Arch,
    phase1_records: &[crate::guest_set::GuestIdentityRecord],
) -> Result<(), String> {
    if json.measured_source_commit != crate::guest_set::RATIFIED_SOURCE_COMMIT {
        return Err(format!(
            "measured_source_commit {} != ratified source {}",
            json.measured_source_commit,
            crate::guest_set::RATIFIED_SOURCE_COMMIT
        ));
    }
    let mut att = json.to_schema()?;
    att.candidate = cand;
    att.check_self_consistency()?;
    if att.build_target_arch != arch {
        return Err(format!(
            "runner attestation arch {:?} != requested arch {arch:?}",
            att.build_target_arch
        ));
    }
    let rec = resolve_phase1(phase1_records, cand, arch)?;
    if rec.source_commit != att.measured_source_commit {
        return Err("Phase-1 source_commit != measurement measured_source_commit".into());
    }
    if rec.tooling_commit != att.ratified_tooling_commit
        || rec.tooling_pathset_blake3 != att.ratified_pathset_blake3
    {
        return Err("Phase-1 tooling authority != measurement tooling authority".into());
    }
    if rec.b0_pre_spec_hash != crate::guest_set::MERGED_SPEC_HASH_HEX {
        return Err("Phase-1 spec != merged spec hash".into());
    }
    if rec.production_binary_blake3 != hx(&att.runner_blake3) {
        return Err(
            "Phase-1 production_binary_blake3 != measurement runner_blake3 (a different compiled \
             runner binary)"
                .into(),
        );
    }
    Ok(())
}

/// Typed generator for the per-arch `provenance.json` `runner_attestation`. Builds the 18-field venue
/// twin from the retained recipe + Phase-1 record + authenticated scalar inputs (deriving
/// `docker_argv_blake3` and — via the SHARED [`build_runner_artifacts`] the importer uses —
/// `reproducibility_pair_blake3`), runs the sealed-import self-consistency + continuity checks, and
/// emits canonical JSON bytes it immediately RE-DECODES and re-checks before returning. `measure_fragment`
/// splices the returned bytes verbatim into every provenance role.
pub fn generate_runner_attestation(
    inputs: &RunnerAttestationGenInputs,
    recipe: &RunnerRecipeJson,
    phase1_records: &[crate::guest_set::GuestIdentityRecord],
) -> Result<String, String> {
    let cand = parse_candidate_lenient(&recipe.candidate)?;
    let arch = parse_arch(&inputs.arch)?;
    if parse_arch(&recipe.arch)? != arch {
        return Err(format!(
            "recipe arch {} != requested arch {}",
            recipe.arch, inputs.arch
        ));
    }
    // The measurement runner is a byte-identical double build (A == B).
    if !recipe.byte_equal || recipe.build_a.runner_blake3 != recipe.build_b.runner_blake3 {
        return Err(
            "recipe is not a byte-equal double build (build_a.runner_blake3 != build_b)".into(),
        );
    }
    let build_git_sha = inputs
        .build_git_sha
        .clone()
        .unwrap_or_else(|| inputs.source_commit.clone());

    // Provisional twin (real values except reproducibility_pair) drives the SHARED recipe-artifact
    // builder; the pair is read back from the built double-build proof, so it is computed by the exact
    // code the importer re-derives (the independent verifier cross-checks att pair == proof pair).
    let provisional = RunnerAttestationJson {
        build_target_arch: inputs.arch.clone(),
        execution_tooling_checkout_head: inputs.execution_tooling_checkout_head.clone(),
        ratified_tooling_commit: crate::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_COMMIT
            .to_string(),
        ratified_pathset_blake3:
            crate::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3.to_string(),
        recomputed_pathset_blake3: inputs.recomputed_pathset_blake3.clone(),
        measured_source_commit: inputs.source_commit.clone(),
        build_git_sha,
        measured_source_context_blake3: inputs.measured_source_context_blake3.clone(),
        runner_sha256: recipe.build_a.runner_sha256.clone(),
        runner_blake3: recipe.build_a.runner_blake3.clone(),
        immutable_builder_identity: inputs.immutable_builder_identity.clone(),
        protobuf_authority_sha256: inputs.protobuf_authority_sha256.clone(),
        protobuf_authority_blake3: inputs.protobuf_authority_blake3.clone(),
        native_protoc_sha256: inputs.native_protoc_sha256.clone(),
        native_protoc_blake3: inputs.native_protoc_blake3.clone(),
        native_protoc_version: inputs.native_protoc_version.clone(),
        docker_argv_blake3: blake3::hash(inputs.docker_argv.as_bytes())
            .to_hex()
            .to_string(),
        reproducibility_pair_blake3: "0".repeat(64),
    };
    let mut att = provisional.to_schema()?;
    att.candidate = cand; // to_schema hardcodes Sp1; the recipe candidate drives risc0-home handling
    let arts = build_runner_artifacts(recipe, &att)?;
    let repro = hx(&arts.runner_double_build_proof.reproducibility_pair_blake3);

    let json = RunnerAttestationJson {
        reproducibility_pair_blake3: repro,
        ..provisional
    };
    check_generated_attestation(&json, cand, arch, phase1_records)?;

    // Canonical bytes + round-trip: re-decode and re-check the emitted bytes before returning.
    let bytes = format!(
        "{}\n",
        serde_json::to_string_pretty(&json)
            .map_err(|e| format!("serialize runner_attestation: {e}"))?
    );
    let reparsed: RunnerAttestationJson =
        serde_json::from_str(&bytes).map_err(|e| format!("re-decode runner_attestation: {e}"))?;
    check_generated_attestation(&reparsed, cand, arch, phase1_records)?;
    Ok(bytes)
}

/// PRE-PROVING gate. Parse the COMPLETE assembled `provenance.json` and run the SAME per-record binder
/// the sealed importer runs (`prov_facts` — attestation self-consistency, recipe path-independence
/// artifacts, double-build proof) plus the Phase-1 continuity checks (`produce`'s block), refusing
/// before any proof launches if the production provenance record is not acceptable. Returns the number
/// of provenance roles validated. SP1 and RISC0 use this identical path.
pub fn validate_provenance(
    provenance_json: &str,
    phase1_records: &[crate::guest_set::GuestIdentityRecord],
) -> Result<usize, String> {
    let provs: Vec<ProvFacts> =
        serde_json::from_str(provenance_json).map_err(|e| format!("parse provenance: {e}"))?;
    if provs.is_empty() {
        return Err("provenance JSON is an empty array".into());
    }
    for p in &provs {
        let cand = parse_candidate_lenient(&p.runner_recipe.candidate)?;
        let arch = parse_arch(&p.arch)?;
        // Full per-record binder (self-consistency + recipe artifacts + double-build proof).
        let pf = prov_facts(p)?;
        let att = &pf.runner_attestation;
        if att.measured_source_commit != crate::guest_set::RATIFIED_SOURCE_COMMIT {
            return Err(format!(
                "{arch:?}: measured_source_commit {} != ratified source {}",
                att.measured_source_commit,
                crate::guest_set::RATIFIED_SOURCE_COMMIT
            ));
        }
        let rec = resolve_phase1(phase1_records, cand, arch)?;
        if rec.source_commit != att.measured_source_commit {
            return Err(format!(
                "{cand:?}/{arch:?}: Phase-1 source_commit != measurement measured_source_commit"
            ));
        }
        if rec.tooling_commit != att.ratified_tooling_commit
            || rec.tooling_pathset_blake3 != att.ratified_pathset_blake3
        {
            return Err(format!(
                "{cand:?}/{arch:?}: Phase-1 tooling authority != measurement tooling authority"
            ));
        }
        if rec.b0_pre_spec_hash != crate::guest_set::MERGED_SPEC_HASH_HEX {
            return Err(format!(
                "{cand:?}/{arch:?}: Phase-1 spec != merged spec hash"
            ));
        }
        if rec.production_binary_blake3 != hx(&att.runner_blake3) {
            return Err(format!(
                "{cand:?}/{arch:?}: Phase-1 production_binary_blake3 != measurement runner_blake3"
            ));
        }
    }
    Ok(provs.len())
}

fn prov_facts(p: &ProvFacts) -> Result<ProvenanceFacts, String> {
    // Effective-cpuset provenance: reconstruct the retained probe chain, re-run ALL canonical
    // inheritance rules over it (nearest-first ordering, first==second, ancestor-of-leaf, stop at
    // the first readable-nonempty source, count recomputed from raw, inherited flag), and content
    // address the chain. The summary + count are the record-bound fields; the chain is retained
    // evidence bound by its address.
    let chain: Vec<CpusetProbeEntryV1> = p
        .cpuset_probe_chain
        .iter()
        .map(CpusetProbeEntryJson::to_schema)
        .collect::<Result<_, _>>()?;
    check_cpuset_probe_chain(
        &chain,
        &p.cgroup_scope_label,
        &p.cpuset_source_cgroup_path,
        &p.cpuset_raw,
        p.cpuset_inherited,
        p.configured_cpuset_core_limit,
    )?;
    let cpuset_probe_chain_blake3 = cpuset_probe_chain_hash(&chain);

    // Runner attestation: parse, run SELF-consistency (build_git_sha==measured, recomputed==ratified
    // path set, protoc version). The measured-source binding to RATIFIED_SOURCE_COMMIT and the tooling
    // authority binding are enforced by the venue preflight + the validator's two-authority gate, not
    // by this per-record twin conversion. Content address it for the record.
    let attestation = p.runner_attestation.to_schema()?;
    attestation.check_self_consistency()?;
    if attestation.build_target_arch != parse_arch(&p.arch)? {
        return Err(format!(
            "runner attestation arch {:?} != provenance arch {}",
            attestation.build_target_arch, p.arch
        ));
    }

    // ---- v6: build the FIVE retained runner path-independence artifacts from the venue recipe facts
    // (exact bytes for both builds), self/consistency-checked. Shared with the typed provenance
    // generator (`generate_runner_attestation`) so the venue-produced `reproducibility_pair_blake3`
    // is computed by the SAME code the importer re-derives (a divergence would fail the independent
    // cross-check `att.reproducibility_pair == proof.reproducibility_pair`).
    let RunnerArtifacts {
        runner_build_recipe,
        rustc_invocation_inventory_a,
        rustc_invocation_inventory_b,
        runner_double_build_proof,
        runner_leakage_report,
    } = build_runner_artifacts(&p.runner_recipe, &attestation)?;

    Ok(ProvenanceFacts {
        arch: parse_arch(&p.arch)?,
        role: parse_role(&p.role)?,
        // v7 offline-provisioning authority addresses from the recipe facts (empty -> zero for
        // pre-correction fixtures). RISC0 has no protoc -> None -> zero.
        host_toolchain_attestation_address: opt_hex32(
            &p.runner_recipe.host_toolchain_attestation.address,
            "recipe.host_toolchain_attestation.address",
        )?,
        dependency_seed_address: opt_hex32(
            &p.runner_recipe.dependency_seed.address,
            "recipe.dependency_seed.address",
        )?,
        protoc_authority_address: match &p.runner_recipe.protoc_authority {
            Some(pa) => opt_hex32(&pa.address, "recipe.protoc_authority.address")?,
            None => [0u8; 32],
        },
        // v8: SP1 carries the canonical guest artifact address; RISC0 (None) -> zero.
        canonical_sp1_guest_artifact_address: match &p.runner_recipe.canonical_sp1_guest_artifact {
            Some(a) => opt_hex32(&a.address, "recipe.canonical_sp1_guest_artifact.address")?,
            None => [0u8; 32],
        },
        // v9: placeholder — the measurement-wide authority address is NOT a recipe string; `produce`
        // decodes the retained MIA bytes and injects the derived address into EVERY attestation.
        measurement_input_authority_address: [0u8; 32],
        source_commit: p.source_commit.clone(),
        dirty_tree_flag: p.dirty_tree_flag,
        builder_container_digest: hex32(
            &p.builder_container_digest,
            "prov.builder_container_digest",
        )?,
        host_os: p.host_os.clone(),
        kernel: p.kernel.clone(),
        cpu_vendor: p.cpu_vendor.clone(),
        cpu_model: p.cpu_model.clone(),
        physical_core_count: p.physical_core_count,
        logical_cpu_count: p.logical_cpu_count,
        total_ram_bytes: p.total_ram_bytes,
        configured_cpuset_core_limit: p.configured_cpuset_core_limit,
        configured_memory_limit_bytes: p.configured_memory_limit_bytes,
        dvfs: p.dvfs.to_schema()?,
        clock_source: p.clock_source.clone(),
        cgroup_version: p.cgroup_version,
        cgroup_scope_label: p.cgroup_scope_label.clone(),
        benchmark_harness_source_hash: hex32(
            &p.benchmark_harness_source_hash,
            "benchmark_harness_source_hash",
        )?,
        raw_environment_capture_hash: hex32(
            &p.raw_environment_capture_hash,
            "raw_environment_capture_hash",
        )?,
        cpuset_source_cgroup_path: p.cpuset_source_cgroup_path.clone(),
        cpuset_raw: p.cpuset_raw.clone(),
        cpuset_inherited: p.cpuset_inherited,
        cpuset_probe_chain_blake3,
        cpuset_chain_entries: chain,
        runner_attestation: attestation,
        runner_build_recipe,
        rustc_invocation_inventory_a,
        rustc_invocation_inventory_b,
        runner_double_build_proof,
        runner_leakage_report,
        // Placeholder: produce() overwrites this with the resolved retained Phase-1 identity record.
        phase1_identity_record: Phase1IdentityRecordV1 {
            candidate: Candidate::Sp1,
            arch: parse_arch(&p.arch)?,
            source_commit: "0".repeat(40),
            tooling_commit: "1".repeat(40),
            tooling_pathset_blake3: "7".repeat(64),
            b0_pre_spec_hash: [0; 32],
            production_binary_blake3: [0; 32],
        },
    })
}

/// Validate the complete Phase-1 identity record set for a candidate: exact eligible arch set, no
/// duplicate, no `Risc0/aarch64`, and each record well-formed.
fn is_hex_len(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn validate_identity_set(cand: Candidate, records: &[IdentityRecordFacts]) -> Result<(), String> {
    use std::collections::BTreeSet;
    let mut arches: BTreeSet<u8> = BTreeSet::new();
    for r in records {
        let a = parse_arch(&r.arch)?;
        if cand == Candidate::Risc0 && a == Arch::Aarch64 {
            return Err(
                "Risc0/aarch64 Phase-1 identity record is native-ineligible; refused".into(),
            );
        }
        if !arches.insert(a.to_repr()) {
            return Err(format!(
                "duplicate Phase-1 identity record for arch {}",
                r.arch
            ));
        }
        if !is_hex_len(&r.source_commit, 40) || !is_hex_len(&r.tooling_commit, 40) {
            return Err("identity source_commit/tooling_commit must be 40 lowercase hex".into());
        }
        hex32(&r.tooling_pathset_blake3, "identity.tooling_pathset_blake3")?;
        hex32(&r.b0_pre_spec_hash, "identity.b0_pre_spec_hash")?;
        hex32(
            &r.production_binary_blake3,
            "identity.production_binary_blake3",
        )?;
    }
    // Two-cell measurement model: a MEASUREMENT candidate carries exactly the identity records for the
    // arches it is natively measured on (`native_matrix`). SP1/aarch64 is native-ineligible for terminal
    // measurement (no arm64 gnark backend) so it is NOT a measurement candidate arch here — its Phase-1
    // *identity* travels in the shared guest set (records/all.json → derive_guest_set, which independently
    // requires all THREE identities), never as a measurement. Risc0 is x86_64-only as before.
    let want: BTreeSet<u8> = crate::measurement::native_matrix(cand)
        .iter()
        .map(|a| a.to_repr())
        .collect();
    if arches != want {
        return Err(format!(
            "{cand:?}: measurement-candidate identity set arches {arches:?} != natively-measurable {want:?}"
        ));
    }
    Ok(())
}

fn cell_facts(c: &CellFactsJson) -> Result<CellFacts, String> {
    let mut artifact_hashes = Vec::new();
    for a in &c.artifact_hashes {
        artifact_hashes.push((a[0].clone(), hex32(&a[1], "artifact_hash")?));
    }
    Ok(CellFacts {
        arch: parse_arch(&c.arch)?,
        statement: parse_stmt(&c.statement)?,
        iteration: c.iteration,
        proof_hash: hex32(&c.proof_hash, "proof_hash")?,
        artifact_hashes,
        prove_ns: c.prove_ns,
        setup_ns: c.setup_ns,
        proof_bytes: c.proof_bytes,
        verify_ns: c.verify_ns.clone(),
        proving_run_rss_bytes: c.proving_run_rss_bytes,
        verify_batch_rss_bytes: c.verify_batch_rss_bytes,
    })
}

/// Deterministic dry-run raw facts: SP1's complete native matrix (both arches) and
/// RISC Zero's genuine x86_64-only matrix (aarch64 absent). Exercises the full
/// production path off-venue; the real runner replaces these with measured facts.
pub fn dry_run_raw_facts() -> RawFacts {
    fn dv(tag: &str) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"b0-final-dry-run/v1");
        h.update(tag.as_bytes());
        hx(h.finalize().as_bytes())
    }
    let prov = |cand: &str, arch: &str, role: &str| -> ProvFacts {
        // The self-consistent synthetic dependency-seed for THIS candidate: its record address anchors
        // the attestation's dependency_seed_address, and its host-cargo-home content == the proof's cargo
        // seed origin (the fixed synthetic cargo seed content). Deterministic; TEST_ONLY.
        let dep_candidate = if cand == "Sp1" || cand == "sp1" {
            crate::enums::Candidate::Sp1
        } else {
            crate::enums::Candidate::Risc0
        };
        let hexb = |bytes: &[u8]| -> String {
            use std::fmt::Write as _;
            bytes.iter().fold(String::new(), |mut a, b| {
                let _ = write!(a, "{b:02x}");
                a
            })
        };
        let (_dep_json, dep_addr) = crate::measurement::synth_dependency_seed(dep_candidate);
        let dep_addr_hex: String = hexb(&dep_addr);
        let cargo_seed_hex: String = hexb(&crate::measurement::synth_cargo_seed_content());
        let (cpuset, mem, phys, log, ram) = if role == "Proving" {
            (5u32, 22u64 << 30, 16u32, 32u32, 64u64 << 30)
        } else {
            (2, 4u64 << 30, 2, 4, 4u64 << 30)
        };
        let cpuset_raw = if cpuset == 5 { "0-4" } else { "0-1" }.to_string();
        let obs = CpusetObsJson {
            state: "readable-nonempty".into(),
            raw: Some(cpuset_raw.clone()),
            file_type: "regular".into(),
            is_symlink: false,
            dev: Some(1),
            inode: Some(2),
            size: Some(cpuset_raw.len() as u64),
            mtime_secs: Some(0),
            mtime_nanos: Some(0),
            read_error_class: None,
        };
        let tooling = "1234567890abcdef1234567890abcdef12345678".to_string();
        let pathset = dv("tooling-pathset");
        ProvFacts {
            arch: arch.into(),
            role: role.into(),
            source_commit: "eff3aae18b49969212c4c1493da20f97af195de2".into(),
            dirty_tree_flag: false,
            builder_container_digest: dv("builder"),
            host_os: "linux".into(),
            kernel: "6.8.0".into(),
            cpu_vendor: "GenuineIntel".into(),
            cpu_model: "reference".into(),
            physical_core_count: phys,
            logical_cpu_count: log,
            total_ram_bytes: ram,
            configured_cpuset_core_limit: cpuset,
            configured_memory_limit_bytes: mem,
            dvfs: DvfsFacts::Observable {
                turbo_enabled: false,
                governor: "performance".into(),
            },
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "b0-pre.slice".into(),
            benchmark_harness_source_hash: dv("runner"),
            raw_environment_capture_hash: dv("envcap"),
            cpuset_source_cgroup_path: "b0-pre.slice".into(),
            cpuset_raw: cpuset_raw.clone(),
            cpuset_inherited: false,
            // Leaf-observed single-entry chain (order 0 = readable-nonempty source).
            cpuset_probe_chain: vec![CpusetProbeEntryJson {
                cgroup_path: "b0-pre.slice".into(),
                order: 0,
                first: obs.clone(),
                second: obs.clone(),
            }],
            runner_attestation: RunnerAttestationJson {
                build_target_arch: arch.into(),
                // Off-venue placeholder tooling identity (the tooling authority + measured-source
                // binding are enforced at the venue, not in this deterministic dry run).
                execution_tooling_checkout_head: tooling.clone(),
                ratified_tooling_commit: tooling.clone(),
                ratified_pathset_blake3: pathset.clone(),
                recomputed_pathset_blake3: pathset.clone(),
                measured_source_commit: "eff3aae18b49969212c4c1493da20f97af195de2".into(),
                build_git_sha: "eff3aae18b49969212c4c1493da20f97af195de2".into(),
                measured_source_context_blake3: dv("measured-ctx"),
                runner_sha256: dv("runner-sha256"),
                runner_blake3: dv("runner-blake3"),
                immutable_builder_identity: dv("builder"),
                protobuf_authority_sha256: dv("pb-sha256"),
                protobuf_authority_blake3: dv("pb-blake3"),
                native_protoc_sha256: dv("protoc-sha256"),
                native_protoc_blake3: dv("protoc-blake3"),
                native_protoc_version: "libprotoc 3.21.12".into(),
                docker_argv_blake3: dv("docker-argv"),
                reproducibility_pair_blake3: dv("repro-pair"),
            },
            runner_recipe: {
                let enc_hex = |t: &str| -> String {
                    use std::fmt::Write as _;
                    let s = format!("--remap-path-prefix=/b0-input/{t}/target=/b0/target");
                    s.bytes().fold(String::new(), |mut acc, b| {
                        let _ = write!(acc, "{b:02x}");
                        acc
                    })
                };
                let rec_addr = |t: &str| -> String {
                    let body = format!(
                        "b0-final-rustc-invocation/v2\nkind=compile\nremap_arg=--remap-path-prefix=/b0-input/{t}/target=/b0/target"
                    );
                    blake3::hash(body.as_bytes()).to_hex().to_string()
                };
                let side = |t: &str, s: u64, e: u64| BuildSideJson {
                    original_root: format!("/b0-input/{t}/tooling"),
                    target_from: format!("/b0-input/{t}/target"),
                    encoded_rustflags_hex: enc_hex(t),
                    runner_sha256: dv("runner-sha256"),
                    runner_blake3: dv("runner-blake3"),
                    guest_image_id: dv("guest-img"),
                    guest_methods_blake3: dv("guest-methods"),
                    origin_manifest_blake3: dv("src-manifest"),
                    materialized_manifest_blake3: dv("src-manifest"),
                    start_unix: s,
                    end_unix: e,
                    invocations: vec![InvocationRecordJson {
                        kind: "compile".into(),
                        remap_args: vec![format!(
                            "--remap-path-prefix=/b0-input/{t}/target=/b0/target"
                        )],
                        record_address: rec_addr(t),
                    }],
                };
                let mut refused: Vec<String> = ["a", "b"]
                    .iter()
                    .flat_map(|t| {
                        vec![
                            format!("/b0-input/{t}/tooling"),
                            format!("/b0-input/{t}/target"),
                        ]
                    })
                    .collect();
                refused.push("/tmp/b0-evid".into());
                refused.sort();
                RunnerRecipeJson {
                    candidate: cand.into(),
                    arch: arch.into(),
                    manifest_path: "tools/b0-pre-measure-sp1/Cargo.toml".into(),
                    artifact_path: "release/b0-pre-measure-sp1".into(),
                    cargo_ident: "cargo".into(),
                    b0_venue_embed: "0".into(),
                    canonical_build_path: "/b0/tooling".into(),
                    canonical_cargo_home: "/b0/cargo".into(),
                    per_arch_toolchain_identity: dv("per-arch-toolchain"),
                    wrapper_blake3: dv("wrapper-blake3"),
                    build_argv: vec![
                        "cargo".into(),
                        "build".into(),
                        "--release".into(),
                        "--locked".into(),
                        "--offline".into(),
                        "--features".into(),
                        "real-backend".into(),
                        "--manifest-path".into(),
                        "tools/b0-pre-measure-sp1/Cargo.toml".into(),
                    ],
                    build_env: vec![
                        (
                            "BUILD_GIT_SHA".into(),
                            "eff3aae18b49969212c4c1493da20f97af195de2".into(),
                        ),
                        ("SOURCE_DATE_EPOCH".into(), "0".into()),
                        ("B0_VENUE_EMBED".into(), "0".into()),
                    ],
                    build_a: side("a", 100, 200),
                    build_b: side("b", 200, 300),
                    byte_equal: true,
                    leakage_refused_prefixes: refused,
                    leakage_permitted_prefixes: {
                        let mut p: Vec<String> = vec![
                            "/b0/cargo".into(),
                            "/b0/target".into(),
                            "/b0/tooling".into(),
                        ];
                        if cand == "risc0" || cand == "Risc0" {
                            p.push("/b0/guesthome".into());
                        }
                        p
                    },
                    leakage_clean: true,
                    evidence_root: "/tmp/b0-evid".into(),
                    offline: true,
                    cargo_net_offline: true,
                    dependency_seed: AuthorityRefJson {
                        address: dep_addr_hex.clone(),
                        json_sha256: dv("dep-seed-json"),
                    },
                    host_toolchain_attestation: AuthorityRefJson {
                        address: dv("host-tc-addr"),
                        json_sha256: dv("host-tc-json"),
                    },
                    canonical_sp1_guest_artifact: None,
                    protoc_authority: Some(AuthorityRefJson {
                        address: dv("protoc-addr"),
                        json_sha256: dv("protoc-json"),
                    }),
                    risc0_guest_embed: None,
                    cargo_seed: CargoSeedJson {
                        origin_address: cargo_seed_hex.clone(),
                        materialized_a: cargo_seed_hex.clone(),
                        materialized_b: cargo_seed_hex.clone(),
                    },
                    // RISC0 real embed only: the fresh-per-build risc0 toolchain-home authority (3-way equal).
                    // The producer maps this only when the PROOF candidate is RISC0; SP1 proofs force zero.
                    risc0_home_seed: if cand == "Risc0" || cand == "risc0" {
                        let r0 = hexb(&crate::measurement::synth_risc0_home_content());
                        Some(Risc0HomeSeedJson {
                            origin_address: r0.clone(),
                            materialized_a: r0.clone(),
                            materialized_b: r0,
                        })
                    } else {
                        None
                    },
                }
            },
        }
    };
    let cell = |cand: &str, arch: &str, s: &str, iter: u32| -> CellFactsJson {
        let key = format!("{cand}:{arch}:{s}:{iter}");
        CellFactsJson {
            arch: arch.into(),
            statement: s.into(),
            iteration: iter,
            proof_hash: dv(&format!("ph:{key}")),
            artifact_hashes: vec![["receipt".to_string(), dv(&format!("rcpt:{key}"))]],
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
    let grid = |cand: &str, arches: &[&str]| -> Vec<CellFactsJson> {
        let mut v = Vec::new();
        for a in arches {
            for s in ["Tlg", "SelectToken"] {
                for iter in 0..10u32 {
                    v.push(cell(cand, a, s, iter));
                }
            }
        }
        v
    };
    let provset = |cand: &str, arches: &[&str]| -> Vec<ProvFacts> {
        let mut v = Vec::new();
        for a in arches {
            for r in ["Proving", "Verification"] {
                v.push(prov(cand, a, r));
            }
        }
        v
    };
    let guest = |c: &str, arches: &[&str]| GuestFacts {
        guest_source_tree_hash: dv(&format!("{c}-src")),
        candidate_dep_lock_hash: dv(&format!("{c}-lock")),
        guest_image_hash: dv(&format!("{c}-img")),
        program_id: dv(&format!("{c}-prog")),
        build_command_hash: dv(&format!("{c}-cmd")),
        reproducible: true,
        builder: arches
            .iter()
            .map(|a| BuilderFacts {
                arch: (*a).into(),
                builder_container_digest: dv(&format!("{c}-b-{a}")),
            })
            .collect(),
    };
    // Phase-1 identity records matching each provenance's runner attestation (production_binary_blake3
    // == the dry-run runner_blake3; same measured-source/tooling/spec).
    let idrecs = |arches: &[&str]| -> Vec<IdentityRecordFacts> {
        arches
            .iter()
            .map(|a| IdentityRecordFacts {
                arch: (*a).into(),
                source_commit: "eff3aae18b49969212c4c1493da20f97af195de2".into(),
                tooling_commit: "1234567890abcdef1234567890abcdef12345678".into(),
                tooling_pathset_blake3: dv("tooling-pathset"),
                b0_pre_spec_hash: MERGED_SPEC_HASH_HEX.into(),
                production_binary_blake3: dv("runner-blake3"),
            })
            .collect()
    };
    let sp1 = CandidateFacts {
        candidate: "Sp1".into(),
        container_image_digest: dv("sp1-container"),
        statement_hash_tlg: dv("stmt-tlg"),
        statement_hash_st: dv("stmt-st"),
        // Two-cell model: SP1's GUEST is built for BOTH arches (its arch-independent program_id
        // reconciles across x86_64 + aarch64 builders — this is the retained 3-identity guest set and
        // is what the ratified r0_guest_set_hash binds). But SP1 is natively TERMINAL-MEASURED on
        // x86_64 ONLY (SP1/aarch64 terminal Groth16 is ratified unsupported), so its cells, provenance,
        // and runner-continuity identity records are x86_64-only. The SP1/aarch64 guest identity thus
        // travels in the guest set, never as a measurement.
        guest: guest("sp1", &["x86_64", "aarch64"]),
        verifier_material: vec![VmEntryFacts {
            role: "Groth16Vk".into(),
            byte_len: 292,
            hash: dv("sp1-vk"),
        }],
        provenance: provset("sp1", &["x86_64"]),
        cells: grid("sp1", &["x86_64"]),
        identity_records: idrecs(&["x86_64"]),
        dependency_seed_json: String::from_utf8(
            crate::measurement::synth_dependency_seed(crate::enums::Candidate::Sp1).0,
        )
        .expect("synthetic dependency-seed JSON is UTF-8"),
    };
    let risc0 = CandidateFacts {
        candidate: "Risc0".into(),
        container_image_digest: dv("r0-container"),
        statement_hash_tlg: dv("stmt-tlg"),
        statement_hash_st: dv("stmt-st"),
        guest: guest("r0", &["x86_64"]),
        verifier_material: vec![
            VmEntryFacts {
                role: "Groth16Vk".into(),
                byte_len: 256,
                hash: dv("r0-vk"),
            },
            VmEntryFacts {
                role: "ControlRoot".into(),
                byte_len: 32,
                hash: dv("r0-cr"),
            },
            VmEntryFacts {
                role: "ControlId".into(),
                byte_len: 32,
                hash: dv("r0-ci"),
            },
            VmEntryFacts {
                role: "VerifierParams".into(),
                byte_len: 32,
                hash: dv("r0-vp"),
            },
        ],
        // RISC Zero: x86_64-only provenance AND cells (aarch64 genuinely absent).
        provenance: provset("risc0", &["x86_64"]),
        cells: grid("r0", &["x86_64"]),
        identity_records: idrecs(&["x86_64"]),
        dependency_seed_json: String::from_utf8(
            crate::measurement::synth_dependency_seed(crate::enums::Candidate::Risc0).0,
        )
        .expect("synthetic dependency-seed JSON is UTF-8"),
    };
    RawFacts {
        lifecycle_mode: "measurement".into(),
        b0_pre_spec_hash: MERGED_SPEC_HASH_HEX.into(),
        candidates: vec![sp1, risc0],
        // TEST_ONLY fixtures (bind the non-authoritative sentinel tooling commit 1234…5678; measured
        // 507281e2 / spec e933e732): the retained MeasurementInputAuthorityV1 + its malformed-corpus
        // report + harness-source inventory. These exercise encoding/verification mechanics only — the
        // production `--verify-authority` gate REFUSES the sentinel — and the venue generates the REAL
        // authority from the clean ratified tree (see docs/b0-pre/fixtures/.../README.md).
        measurement_input_authority: include_str!(
            "../../../docs/b0-pre/fixtures/measurement-input-authority/measurement-input-authority.v1.json"
        )
        .to_string(),
        malformed_corpus_report: include_str!(
            "../../../docs/b0-pre/fixtures/measurement-input-authority/malformed-corpus-report.v1.json"
        )
        .to_string(),
        harness_source_inventory: include_str!(
            "../../../docs/b0-pre/fixtures/measurement-input-authority/harness-source-inventory.txt"
        )
        .to_string(),
        // The retained two-cell eligibility/unsupported matrix, built through the sole canonical
        // constructor and bound (by address) into the MeasurementInputAuthorityV1 above.
        eligibility_matrix: crate::venue::eligibility_matrix::EligibilityMatrixV1::canonical(
            MERGED_SPEC_HASH_HEX,
        )
        .to_json(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::verify_evidence;
    use crate::measurement::parse_vector;

    #[test]
    fn legacy_operator_hashes_are_refused_not_ignored() {
        // Each of the three removed operator inputs must be refused wherever it appears — top level,
        // nested in a candidate, or nested in an array element — so a stale/forged facts JSON cannot
        // slip an unauthenticated measurement input past the derived authority.
        for (where_, jv) in [
            (
                "top-level rss_context_hash",
                serde_json::json!({ "rss_context_hash": "00".repeat(32) }),
            ),
            (
                "top-level malformed_corpus_result_hash",
                serde_json::json!({ "malformed_corpus_result_hash": "11".repeat(32) }),
            ),
            (
                "top-level harness_source_hash",
                serde_json::json!({ "harness_source_hash": "22".repeat(32) }),
            ),
            (
                "nested-in-candidate",
                serde_json::json!({ "candidates": [ { "candidate": "Sp1", "rss_context_hash": "33".repeat(32) } ] }),
            ),
        ] {
            let e =
                refuse_legacy_operator_hashes(&jv).expect_err(&format!("{where_} must be refused"));
            assert!(e.contains("legacy operator hash"), "{where_}: {e}");
        }
        // The legitimate provenance-computed inventory digest key is NOT a legacy operator hash.
        let ok = serde_json::json!({ "benchmark_harness_source_hash": "44".repeat(32) });
        assert!(
            refuse_legacy_operator_hashes(&ok).is_ok(),
            "benchmark_harness_source_hash must not be mistaken for the legacy harness_source_hash"
        );
    }

    #[test]
    fn dry_run_produces_and_verifies_both_verdicts() {
        let pkg = produce(&dry_run_raw_facts()).expect("produces");
        // Reviewed two-cell model: BOTH candidates carry their complete x86_64-only native matrix,
        // so BOTH qualify (each is one of the two eligible measurement cells). Neither is an
        // "incomplete native matrix" any longer — x86_64 IS the complete native matrix.
        assert_eq!(
            pkg.verdicts[0],
            (Candidate::Sp1, CandidateVerdict::Qualified)
        );
        assert_eq!(
            pkg.verdicts[1],
            (Candidate::Risc0, CandidateVerdict::Qualified)
        );
        // The package vector is accepted by the frozen verifier for BOTH candidates.
        let (_al, _mia, _report, _inv, _elig, bundles) = parse_vector(&pkg.vector).unwrap();
        for (_c, ev) in &bundles {
            assert!(
                verify_evidence(ev).unwrap().qualification,
                "both x86-only measurement cells verify + qualify"
            );
        }
        // inventory names both verdicts + the content address.
        let inv = pkg.inventory();
        assert_eq!(inv["package_id"], hx(&pkg.package_id));
    }

    // ---- TYPED runner-attestation GENERATOR (provenance producer gap fix) --------------------------
    // A mutually-consistent fixture: the dry-run recipe (valid, self-checking double-build facts) + a
    // Phase-1 identity record + venue scalar inputs, all bound to the REAL ratified constants (source
    // commit, tooling authority, spec) so `generate_runner_attestation`'s production checks apply.
    // idx 0 == Sp1, idx 1 == Risc0 (both exercise the identical generator path).
    fn ratified_gen_fixture(
        idx: usize,
    ) -> (
        RunnerRecipeJson,
        RunnerAttestationGenInputs,
        Vec<crate::guest_set::GuestIdentityRecord>,
    ) {
        let raw = dry_run_raw_facts();
        let c = &raw.candidates[idx];
        let p = &c.provenance[0];
        let mut recipe = p.runner_recipe.clone();
        // In production the runner is stamped BUILD_GIT_SHA == the measured source; the dry-run synth
        // uses a placeholder. Bind it to the ratified source so the recipe self-consistency (build_env
        // BUILD_GIT_SHA == measured_source_commit) holds under the generator's ratified measured source.
        for kv in recipe.build_env.iter_mut() {
            if kv.0 == "BUILD_GIT_SHA" {
                kv.1 = crate::guest_set::RATIFIED_SOURCE_COMMIT.to_string();
            }
        }
        // The dry-run synth hardcodes recipe.candidate = "sp1" for both cells (prov_facts ignores it,
        // using the attestation's placeholder); the real double_build_runner writes the cell candidate.
        recipe.candidate = c.candidate.to_lowercase();
        let arch = p.arch.clone();
        let runner_blake3 = recipe.build_a.runner_blake3.clone();
        let rec = crate::guest_set::GuestIdentityRecord {
            candidate: c.candidate.clone(),
            arch: arch.clone(),
            source_commit: crate::guest_set::RATIFIED_SOURCE_COMMIT.to_string(),
            clean_tree: true,
            guest_source_tree_hash: "11".repeat(32),
            candidate_dep_lock_hash: "22".repeat(32),
            guest_image_hash: "33".repeat(32),
            program_id: "44".repeat(32),
            builder_container_digest: "55".repeat(32),
            toolchain_identity: "66".repeat(32),
            verifier_material_manifest_hash: "77".repeat(32),
            build_command_hash: "88".repeat(32),
            production_binary_blake3: runner_blake3,
            real_backend: true,
            real_guest_embedded: true,
            b0_pre_spec_hash: MERGED_SPEC_HASH_HEX.to_string(),
            tooling_commit: crate::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_COMMIT
                .to_string(),
            tooling_pathset_blake3:
                crate::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3.to_string(),
            canonical_sp1_guest_artifact_address: String::new(),
        };
        let inputs = RunnerAttestationGenInputs {
            arch,
            source_commit: crate::guest_set::RATIFIED_SOURCE_COMMIT.to_string(),
            build_git_sha: None,
            execution_tooling_checkout_head:
                crate::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_COMMIT.to_string(),
            recomputed_pathset_blake3:
                crate::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3.to_string(),
            immutable_builder_identity: "aa".repeat(32),
            measured_source_context_blake3: "bb".repeat(32),
            protobuf_authority_sha256: "cc".repeat(32),
            protobuf_authority_blake3: "dd".repeat(32),
            native_protoc_sha256: "ee".repeat(32),
            native_protoc_blake3: "ff".repeat(32),
            native_protoc_version: "libprotoc 3.21.12".to_string(),
            docker_argv: "docker run --rm --platform linux/amd64 -v /a:/b:ro builder@sha256:x"
                .to_string(),
        };
        (recipe, inputs, vec![rec])
    }

    // e2e (per-record): real recipe + Phase-1 identity -> generated runner_attestation that passes the
    // sealed-import self-consistency + continuity + double-build binding, for BOTH candidates. The
    // generator computes reproducibility_pair via the SAME shared builder the importer re-derives.
    #[test]
    fn generate_runner_attestation_accepts_both_candidates() {
        for idx in 0..2 {
            let (recipe, inputs, records) = ratified_gen_fixture(idx);
            let bytes = generate_runner_attestation(&inputs, &recipe, &records)
                .unwrap_or_else(|e| panic!("generate idx {idx}: {e}"));
            let json: RunnerAttestationJson = serde_json::from_str(&bytes).unwrap();
            assert_eq!(
                json.ratified_tooling_commit,
                crate::tooling_authority::RATIFIED_MEASUREMENT_TOOLING_COMMIT
            );
            assert_eq!(
                json.docker_argv_blake3,
                blake3::hash(inputs.docker_argv.as_bytes())
                    .to_hex()
                    .to_string()
            );
            assert_ne!(json.reproducibility_pair_blake3, "0".repeat(64));
            assert_eq!(json.runner_blake3, recipe.build_a.runner_blake3);
            assert_eq!(json.measured_source_commit, json.build_git_sha);
        }
    }

    // NEGATIVE: swapped identity — the Phase-1 production_binary_blake3 is not this runner.
    #[test]
    fn generate_refuses_swapped_identity() {
        let (recipe, inputs, mut records) = ratified_gen_fixture(0);
        records[0].production_binary_blake3 = "00".repeat(32);
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // NEGATIVE: wrong runner hash — a byte-equal double build of a DIFFERENT binary than Phase-1 pinned.
    #[test]
    fn generate_refuses_wrong_runner_hash() {
        let (mut recipe, inputs, records) = ratified_gen_fixture(0);
        recipe.build_a.runner_blake3 = "09".repeat(32);
        recipe.build_b.runner_blake3 = "09".repeat(32); // still byte-equal, but != Phase-1 pin
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // NEGATIVE: wrong tooling authority in the Phase-1 record.
    #[test]
    fn generate_refuses_wrong_tooling() {
        let (recipe, inputs, mut records) = ratified_gen_fixture(0);
        records[0].tooling_commit = "0a".repeat(20);
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // NEGATIVE: wrong recipe — not a byte-equal double build.
    #[test]
    fn generate_refuses_wrong_recipe() {
        let (mut recipe, inputs, records) = ratified_gen_fixture(0);
        recipe.byte_equal = false;
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // NEGATIVE: dirty tooling root — recomputed path-set != ratified (self-consistency).
    #[test]
    fn generate_refuses_dirty_tooling_pathset() {
        let (recipe, mut inputs, records) = ratified_gen_fixture(0);
        inputs.recomputed_pathset_blake3 = "0b".repeat(32);
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // NEGATIVE: measured source is not the ratified frozen source.
    #[test]
    fn generate_refuses_non_ratified_source() {
        let (recipe, mut inputs, records) = ratified_gen_fixture(0);
        inputs.source_commit = "0c".repeat(20);
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // NEGATIVE: wrong native protoc version pin.
    #[test]
    fn generate_refuses_wrong_protoc_version() {
        let (recipe, mut inputs, records) = ratified_gen_fixture(0);
        inputs.native_protoc_version = "libprotoc 3.20.0".into();
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // NEGATIVE: the argv is offline (contains --offline) but an offline FACT is false — the redundant
    // enforcement must agree with the argv. Either boolean being false is refused.
    #[test]
    fn generate_refuses_recipe_not_marked_offline() {
        let (mut recipe, inputs, records) = ratified_gen_fixture(0);
        assert!(recipe.build_argv.iter().any(|a| a == "--offline"));
        recipe.offline = false;
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
        let (mut recipe2, inputs2, records2) = ratified_gen_fixture(0);
        recipe2.cargo_net_offline = false;
        assert!(generate_runner_attestation(&inputs2, &recipe2, &records2).is_err());
    }

    // NEGATIVE: the offline FACTS are true but the executed argv dropped --offline — refused by check_argv.
    #[test]
    fn generate_refuses_argv_missing_offline_while_facts_true() {
        let (mut recipe, inputs, records) = ratified_gen_fixture(0);
        assert!(recipe.offline && recipe.cargo_net_offline);
        recipe.build_argv.retain(|a| a != "--offline");
        assert!(generate_runner_attestation(&inputs, &recipe, &records).is_err());
    }

    // e2e (pre-proving gate): a generated runner_attestation spliced into a complete provenance record
    // is ACCEPTED by `validate_provenance` (measure-runner parse -> per-record binder -> continuity);
    // dropping the field (the exact venue bug) or mutually editing it is REFUSED before any proof.
    #[test]
    fn validate_provenance_accepts_generated_and_refuses_missing_or_edited() {
        let (recipe, inputs, records) = ratified_gen_fixture(0);
        let att_bytes = generate_runner_attestation(&inputs, &recipe, &records).unwrap();
        let att: RunnerAttestationJson = serde_json::from_str(&att_bytes).unwrap();

        let raw = dry_run_raw_facts();
        let mut base = raw.candidates[0].provenance[0].clone();
        base.runner_recipe = recipe.clone();
        base.runner_attestation = att;

        let prov_json = serde_json::to_string(&vec![&base]).unwrap();
        assert_eq!(validate_provenance(&prov_json, &records).unwrap(), 1);

        // NEGATIVE (missing): the field the runner requires is absent -> serde parse fails closed.
        let mut v: serde_json::Value = serde_json::from_str(&prov_json).unwrap();
        v[0].as_object_mut().unwrap().remove("runner_attestation");
        let err = validate_provenance(&v.to_string(), &records).unwrap_err();
        assert!(err.contains("runner_attestation"), "unexpected: {err}");

        // NEGATIVE (mutually edited): flip measured source off the ratified frozen source -> refused.
        let mut v2: serde_json::Value = serde_json::from_str(&prov_json).unwrap();
        v2[0]["runner_attestation"]["measured_source_commit"] = serde_json::json!("0d".repeat(20));
        assert!(validate_provenance(&v2.to_string(), &records).is_err());
    }

    // RUNNER CONTINUITY — positive: the two eligible MEASUREMENT mappings (Sp1/x86, Risc0/x86) each
    // resolve a Phase-1 identity record whose production_binary_blake3 == the measurement runner_blake3,
    // and the retained attestation re-enforces it on import. Under the two-cell model there is NO
    // SP1/aarch64 measurement runner (aarch64 terminal Groth16 is ratified-unsupported), so no
    // aarch64 runner-continuity mapping exists — the SP1/aarch64 identity lives in the guest set.
    #[test]
    fn runner_continuity_positive_both_measurement_mappings() {
        let pkg = produce(&dry_run_raw_facts()).expect("produces");
        let (_al, _mia, _report, _inv, _elig, bundles) = parse_vector(&pkg.vector).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for (c, ev) in &bundles {
            for ab in &ev.runner_attestations {
                let a = crate::schema::runner_attestation::RunnerAttestationV1::decode_exact(ab)
                    .unwrap();
                a.check_runner_continuity()
                    .expect("phase1 == runner_blake3");
                seen.insert((format!("{c:?}"), format!("{:?}", a.build_target_arch)));
            }
            // import re-enforces continuity via bind_runner_attestation
            let _ = verify_evidence(ev);
        }
        // Exactly the two x86_64 measurement mappings — never an aarch64 measurement runner.
        assert!(seen.contains(&("Sp1".into(), "X86_64".into())));
        assert!(seen.contains(&("Risc0".into(), "X86_64".into())));
        assert!(!seen.contains(&("Sp1".into(), "Aarch64".into())));
        assert!(!seen.iter().any(|(_, arch)| arch == "Aarch64"));
    }

    // RUNNER CONTINUITY — negatives, mutating ONLY the runner binary on ONE side while leaving the
    // shared tooling authority (commit + path-set) untouched.
    #[test]
    fn runner_continuity_negatives() {
        // (a) Phase-1 production_binary_blake3 changed → != measurement runner_blake3 → refuse.
        let mut raw = dry_run_raw_facts();
        raw.candidates[0].identity_records[0].production_binary_blake3 = "aa".repeat(32);
        assert!(produce(&raw)
            .unwrap_err()
            .contains("production_binary_blake3 != measurement runner_blake3"));
        // (b) measurement runner_blake3 changed → != Phase-1 → refuse (tooling authority unchanged).
        let mut raw = dry_run_raw_facts();
        raw.candidates[0].provenance[0]
            .runner_attestation
            .runner_blake3 = "bb".repeat(32);
        assert!(produce(&raw).is_err());
        // (c) missing identity record for a measured arch → refuse. Under the two-cell model SP1's
        // measurement-candidate identity set is x86_64-only (its single record); dropping it leaves
        // the set incomplete versus the natively-measurable arches.
        let mut raw = dry_run_raw_facts();
        raw.candidates[0].identity_records.pop(); // drop SP1 x86_64 record → empty set
        assert!(produce(&raw)
            .unwrap_err()
            .to_lowercase()
            .contains("identity set"));
        // (d) Risc0/aarch64 identity record → refuse.
        let mut raw = dry_run_raw_facts();
        let mut extra = raw.candidates[1].identity_records[0].clone();
        extra.arch = "aarch64".into();
        raw.candidates[1].identity_records.push(extra);
        assert!(produce(&raw).unwrap_err().contains("Risc0/aarch64"));
        // (e) duplicate candidate/arch identity → refuse.
        let mut raw = dry_run_raw_facts();
        let dup = raw.candidates[0].identity_records[0].clone();
        raw.candidates[0].identity_records.push(dup);
        assert!(produce(&raw)
            .unwrap_err()
            .to_lowercase()
            .contains("identity"));
    }

    #[test]
    fn produce_is_deterministic() {
        let a = produce(&dry_run_raw_facts()).unwrap();
        let b = produce(&dry_run_raw_facts()).unwrap();
        assert_eq!(a.package_id, b.package_id, "regeneration drift");
        assert_eq!(a.vector, b.vector);
    }

    #[test]
    fn refuses_wrong_spec_hash() {
        let mut f = dry_run_raw_facts();
        f.b0_pre_spec_hash = "0".repeat(64);
        assert!(produce(&f).unwrap_err().contains("!= merged finalized"));
    }

    #[test]
    fn refuses_non_measurement_mode() {
        let mut f = dry_run_raw_facts();
        f.lifecycle_mode = "preregistration".into();
        assert!(produce(&f).unwrap_err().contains("must be `measurement`"));
    }

    #[test]
    fn refuses_turbo_enabled_host() {
        let mut f = dry_run_raw_facts();
        f.candidates[0].provenance[0].dvfs = DvfsFacts::Observable {
            turbo_enabled: true,
            governor: "performance".into(),
        };
        assert!(produce(&f).unwrap_err().to_lowercase().contains("turbo"));
    }

    #[test]
    fn refuses_fabricated_risc0_aarch64_cell() {
        let mut f = dry_run_raw_facts();
        // inject an aarch64 cell into RISC0 (candidate index 1)
        let mut fake = f.candidates[1].cells[0].clone();
        fake.arch = "aarch64".into();
        f.candidates[1].cells.push(fake);
        assert!(produce(&f).unwrap_err().contains("native-ineligible"));
    }

    #[test]
    fn refuses_missing_verification_samples() {
        let mut f = dry_run_raw_facts();
        f.candidates[0].cells[0].verify_ns.pop(); // 99 instead of 100
                                                  // pre-proving validation fails fast on a short sample count.
        assert!(produce(&f).unwrap_err().contains("need 100"));
    }

    #[test]
    fn validate_accepts_dry_run() {
        validate_raw_facts(&dry_run_raw_facts()).expect("dry-run facts are valid");
    }

    #[test]
    fn validate_refuses_empty_candidates() {
        let mut f = dry_run_raw_facts();
        f.candidates.clear();
        assert!(validate_raw_facts(&f).unwrap_err().contains("unpopulated"));
    }

    #[test]
    fn validate_refuses_duplicate_cell() {
        let mut f = dry_run_raw_facts();
        let dup = f.candidates[0].cells[0].clone();
        f.candidates[0].cells.push(dup);
        assert!(validate_raw_facts(&f)
            .unwrap_err()
            .contains("duplicate cell"));
    }

    #[test]
    fn validate_refuses_risc0_aarch64_cell() {
        let mut f = dry_run_raw_facts();
        let mut fake = f.candidates[1].cells[0].clone();
        fake.arch = "aarch64".into();
        f.candidates[1].cells.push(fake);
        assert!(validate_raw_facts(&f)
            .unwrap_err()
            .contains("native-ineligible"));
    }

    #[test]
    fn validate_refuses_wrong_verification_sample_count() {
        let mut f = dry_run_raw_facts();
        f.candidates[0].cells[0].verify_ns.pop();
        assert!(validate_raw_facts(&f).unwrap_err().contains("need 100"));
    }

    #[test]
    fn validate_refuses_incomplete_grid() {
        let mut f = dry_run_raw_facts();
        f.candidates[0].cells.pop();
        assert!(validate_raw_facts(&f)
            .unwrap_err()
            .contains("native cells present"));
    }

    #[test]
    fn dirty_or_emulated_provenance_disqualifies() {
        // A non-native/emulated (or dirty-tree) host is ineligible; the frozen verifier
        // rejects it, so the candidate does NOT come back Qualified.
        let mut f = dry_run_raw_facts();
        for p in &mut f.candidates[0].provenance {
            p.dirty_tree_flag = true;
        }
        let pkg = produce(&f).expect("assembles");
        assert_ne!(
            pkg.verdicts[0].1,
            CandidateVerdict::Qualified,
            "dirty provenance must not qualify"
        );
    }

    #[test]
    fn altered_guest_identity_changes_package_and_guest_set() {
        // Tampering a built identity changes the recomputed guest-set hash and the
        // content address — a modified runner/guest/container is detectable.
        let base = produce(&dry_run_raw_facts()).unwrap();
        let mut f = dry_run_raw_facts();
        f.candidates[0].guest.program_id = "1".repeat(64);
        let tampered = produce(&f).unwrap();
        assert_ne!(base.r0_guest_set_hash, tampered.r0_guest_set_hash);
        assert_ne!(base.package_id, tampered.package_id);
    }

    #[test]
    fn altered_container_identity_changes_package() {
        let base = produce(&dry_run_raw_facts()).unwrap();
        let mut f = dry_run_raw_facts();
        f.candidates[0].container_image_digest = "2".repeat(64);
        let tampered = produce(&f).unwrap();
        assert_ne!(
            base.package_id, tampered.package_id,
            "container identity is bound into every sample"
        );
    }
}

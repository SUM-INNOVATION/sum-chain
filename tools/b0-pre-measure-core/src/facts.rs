//! Serialize twins of the frozen `RawFacts` contract that the venue runner emits and
//! `b0-pre-validator`'s `producer::RawFacts` re-validates. Field names + JSON shape are
//! byte-for-byte the contract; the E2E test feeds an emitted fragment back through the
//! real validator so this can never silently drift.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct RawFacts {
    pub lifecycle_mode: String,
    pub b0_pre_spec_hash: String,
    pub candidates: Vec<CandidateFacts>,
}

#[derive(Serialize, Debug)]
pub struct CandidateFacts {
    pub candidate: String,
    pub container_image_digest: String,
    pub statement_hash_tlg: String,
    pub statement_hash_st: String,
    pub guest: GuestFacts,
    pub verifier_material: Vec<VmEntryFacts>,
    pub provenance: Vec<ProvFacts>,
    pub cells: Vec<CellFactsJson>,
    /// Complete typed Phase-1 identity record set (one per eligible arch) — MANDATORY runner-continuity
    /// input; carries `production_binary_blake3` (required == the measurement `runner_blake3`).
    pub identity_records: Vec<IdentityRecordFacts>,
}

/// Continuity-relevant subset of the Phase-1 `GuestIdentityRecord` (measurement-only twin).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdentityRecordFacts {
    pub arch: String,
    pub source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub b0_pre_spec_hash: String,
    pub production_binary_blake3: String,
}

#[derive(Serialize, Debug)]
pub struct GuestFacts {
    pub guest_source_tree_hash: String,
    pub candidate_dep_lock_hash: String,
    pub guest_image_hash: String,
    pub program_id: String,
    pub build_command_hash: String,
    pub reproducible: bool,
    pub builder: Vec<BuilderFacts>,
}

#[derive(Serialize, Debug)]
pub struct BuilderFacts {
    pub arch: String,
    pub builder_container_digest: String,
}

#[derive(Serialize, Debug)]
pub struct VmEntryFacts {
    pub role: String,
    pub byte_len: u64,
    pub hash: String,
}

/// JSON twin of the host-provenance DVFS state (matches `b0-pre-host-provenance`'s `DvfsState`
/// and the validator's reader). `Observable` is the ordinary turbo+governor state;
/// `HypervisorManagedUnobservable` is the distinct native-aarch64/Microsoft state (never
/// turbo=false/performance), carrying structured evidence.
#[derive(Serialize, Deserialize, Clone, Debug)]
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

/// Provenance is produced by the separately-tested `b0-pre-host-provenance` binary; the
/// runner reads its JSON into this struct (validating shape) and re-emits it verbatim.
#[derive(Serialize, Deserialize, Clone, Debug)]
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
    // ---- v3: effective-cpuset provenance (summary + retained chain) + runner attestation ----
    pub cpuset_source_cgroup_path: String,
    pub cpuset_raw: String,
    pub cpuset_inherited: bool,
    pub cpuset_probe_chain: Vec<CpusetProbeEntryFacts>,
    pub runner_attestation: RunnerAttestationFacts,
    // ---- v5: runner path-independence recipe facts (produced by double_build_runner.sh; carried
    // verbatim by the runner and re-validated by b0-pre-validator's producer) ----
    pub runner_recipe: RunnerRecipeFacts,
}

/// Serialize/Deserialize twin of the venue runner-build recipe facts (exact bytes for BOTH builds). The
/// validator builds the five retained artifacts (`RunnerBuildRecipeV1`, build-A + build-B
/// `RustcInvocationInventoryV1`, `RunnerDoubleBuildProofV1`, `RunnerLeakageReportV1`) from these; the
/// structural recipe id + canonical destinations + derived hashes are recomputed there, never trusted.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunnerRecipeFacts {
    pub candidate: String,
    pub arch: String,
    pub manifest_path: String,
    pub artifact_path: String,
    pub cargo_ident: String,
    pub b0_venue_embed: String,
    pub canonical_build_path: String,
    /// The literal canonical compiler-visible CARGO_HOME (== /b0/cargo), materialized fresh per build.
    pub canonical_cargo_home: String,
    pub per_arch_toolchain_identity: String,
    pub wrapper_blake3: String,
    pub build_argv: Vec<String>,
    pub build_env: Vec<(String, String)>,
    pub build_a: BuildSideFacts,
    pub build_b: BuildSideFacts,
    pub byte_equal: bool,
    /// The build IS offline: `build_argv` carries exactly one `--offline`, and these redundant facts
    /// must agree (`true`). The runner PRESERVES them from the spliced recipe into the fragment so the
    /// validator's `--facts` offline gate (`build_runner_artifacts`) sees the truthful values; without
    /// them here the runner would silently drop the fields on re-serialization. serde-default so
    /// pre-correction recipe fixtures still parse.
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub cargo_net_offline: bool,
    /// The fresh-per-build cargo dependency-seed materialization equality (origin == materialized_A ==
    /// materialized_B).
    pub cargo_seed: CargoSeedFacts,
    pub leakage_refused_prefixes: Vec<String>,
    pub leakage_permitted_prefixes: Vec<String>,
    pub leakage_clean: bool,
    pub evidence_root: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CargoSeedFacts {
    pub origin_address: String,
    pub materialized_a: String,
    pub materialized_b: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BuildSideFacts {
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
    pub invocations: Vec<RustcInvocationFacts>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RustcInvocationFacts {
    pub kind: String,
    pub remap_args: Vec<String>,
    pub record_address: String,
}

/// Serialize/Deserialize twin of the host-provenance reader's `CpusetObservation`; `state` is the
/// reader's kebab-case string, carried through verbatim (the validator's producer re-validates it).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CpusetObsFacts {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    pub file_type: String,
    pub is_symlink: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_secs: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_nanos: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_error_class: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CpusetProbeEntryFacts {
    pub cgroup_path: String,
    pub order: u32,
    pub first: CpusetObsFacts,
    pub second: CpusetObsFacts,
}

/// Serialize/Deserialize twin of `RunnerAttestationV1` (all digests as lowercase hex). The runner
/// assembles this per arch from the double-build + protobuf-provisioning attestation blocks.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunnerAttestationFacts {
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

#[derive(Serialize, Debug)]
pub struct CellFactsJson {
    pub arch: String,
    pub statement: String,
    pub iteration: u32,
    pub proof_hash: String,
    pub artifact_hashes: Vec<[String; 2]>,
    pub prove_ns: u64,
    pub setup_ns: u64,
    pub proof_bytes: u64,
    pub verify_ns: Vec<u64>,
    pub proving_run_rss_bytes: u64,
    pub verify_batch_rss_bytes: u64,
}

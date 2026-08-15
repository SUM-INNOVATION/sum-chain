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
    pub rss_context_hash: String,
    pub malformed_corpus_result_hash: String,
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

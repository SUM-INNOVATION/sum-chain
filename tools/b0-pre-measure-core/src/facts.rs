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

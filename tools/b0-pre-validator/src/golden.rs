//! The documented golden inputs, shared by the `emit_golden` example and the
//! golden regression test so the two never drift. The independent crate holds a
//! separate copy of the same documented inputs.

use crate::enums::{
    Arch, Candidate, InputSlotKind, MetricKind, ObjectKind, ProvenanceRole, RssScope, SampleKind,
    SlotKind, StatementIndex, Status, Unit, UnitKind, VerifierMaterialRole,
};
use crate::merkle;
use crate::schema::allowlist::GuestProgramAllowlistV1;
use crate::schema::bench::{BenchmarkRssRecordV1, BenchmarkSampleV1};
use crate::schema::derived_input::DerivedInputV1;
use crate::schema::envelope::R0ProofArtifactEnvelopeV1;
use crate::schema::manifest::{
    InputManifestV1, InputSlotDescriptorV1, OutputManifestV1, SlotDescriptorV1,
};
use crate::schema::object::ObjectCommitmentV1;
use crate::schema::provenance::ArchRunProvenanceV1;
use crate::schema::result_set::{
    Aggregates, ArchProvenanceRef, Completeness, MeasuredProofRef, R0ResultSetV1, RssBundle,
    SampleBundle,
};
use crate::schema::statement::R0ComputationStatementV2;
use crate::schema::verifier_material::{VerifierMaterialEntry, VerifierMaterialManifestV1};

pub const GOLDEN_MODEL: &[u8] = b"golden-model";
pub const G: &[u8] = b"g";
pub const SPEC_HASH: [u8; 32] = [0x9c; 32];

pub fn multichunk_buf() -> Vec<u8> {
    let n = 2 * merkle::CHUNK + 7;
    let mut buf = vec![0u8; n];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i as u64 * 31 + 7) & 0xff) as u8;
    }
    buf
}

pub fn derived_input() -> DerivedInputV1 {
    DerivedInputV1 {
        job_id: [0x11; 32],
        session_id: [0x22; 32],
        unit_id: [0x33; 32],
        generation_index: 7,
        model_id: [0x44; 32],
        model_commitment_identity: [0x55; 32],
        layer_start: 0,
        layer_end: 1,
        prior_residual_commitment_identity: [0x66; 32],
        prior_kv_commitment_identity: [0x77; 32],
        token_prefix_commitment_identity: [0x88; 32],
        position: 7,
        sequence_length: 8,
    }
}

pub fn output_manifest() -> OutputManifestV1 {
    OutputManifestV1 {
        slots: vec![
            SlotDescriptorV1 {
                slot_kind: SlotKind::ResidualStream,
                slot_index: 7,
                commitment: ObjectCommitmentV1::commit(ObjectKind::ResidualState, G),
            },
            SlotDescriptorV1 {
                slot_kind: SlotKind::KvCache,
                slot_index: 7,
                commitment: ObjectCommitmentV1::commit(ObjectKind::KvState, G),
            },
        ],
    }
}

pub fn input_manifest() -> InputManifestV1 {
    InputManifestV1 {
        slots: vec![
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorResidual,
                slot_index: 0,
                commitment: ObjectCommitmentV1::commit(ObjectKind::PriorResidual, G),
            },
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorKv,
                slot_index: 0,
                commitment: ObjectCommitmentV1::commit(ObjectKind::PriorKv, G),
            },
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::TokenPrefix,
                slot_index: 0,
                commitment: ObjectCommitmentV1::commit(ObjectKind::TokenPrefix, G),
            },
        ],
    }
}

pub fn statement() -> R0ComputationStatementV2 {
    let oc = |k| ObjectCommitmentV1::commit(k, G);
    R0ComputationStatementV2 {
        b0_pre_spec_hash: [0; 32],
        job_id: [0x11; 32],
        session_id: [0x22; 32],
        unit_id: [0x33; 32],
        unit_kind: UnitKind::TransformerLayerGroup,
        unit_index: 14,
        generation_index: 7,
        model_id: [0x44; 32],
        model_commitment: oc(ObjectKind::Model),
        tokenizer_id: [0x55; 32],
        head_dim: 4,
        ffn_dim: 16,
        layer_start: 0,
        layer_end: 1,
        vocab_size: 16,
        d_model: 8,
        n_heads: 2,
        derived_input_commitment: oc(ObjectKind::DerivedInput),
        prior_residual_stream: oc(ObjectKind::PriorResidual),
        prior_kv_cache: oc(ObjectKind::PriorKv),
        token_prefix: oc(ObjectKind::TokenPrefix),
        input_manifest: oc(ObjectKind::InputManifest),
        sequence_length: 8,
        position: 7,
        output_manifest: oc(ObjectKind::OutputManifest),
        selected_token: u32::MAX,
        updated_token_seq_commitment: oc(ObjectKind::TokenSeq),
        eos_flag: 0,
        max_cycles: 0,
        max_d_model: 8,
        max_seq_len: 8,
        max_output_tokens: 8,
        max_manifest_slots: 3,
        max_state_bytes: 2761,
    }
}

// --- R0 closure golden (a completeness-valid result set + a matching envelope) ---

pub const RS_SPEC_HASH: [u8; 32] = [1; 32];
pub const RS_GUEST_SET_HASH: [u8; 32] = [2; 32];
pub const RS_VERIFIER_MATERIAL: [u8; 32] = [3; 32];
pub const RS_STMT_TLG: [u8; 32] = [4; 32];
pub const RS_STMT_ST: [u8; 32] = [5; 32];

fn h(seed: u8, i: usize) -> [u8; 32] {
    let mut a = [seed; 32];
    a[0] = i as u8;
    a[1] = seed;
    a
}

/// A result set that satisfies every frozen completeness rule (§13/§23): the
/// exact 40-proof grid, the 4-provenance set, correct counts, and bundle sums.
pub fn official_result_set() -> R0ResultSetV1 {
    let mut measured_proofs = Vec::new();
    for arch in [Arch::X86_64, Arch::Aarch64] {
        for stmt in [StatementIndex::Tlg, StatementIndex::SelectToken] {
            for iter in 0..crate::consts::OFFICIAL_ITERATIONS_PER_CELL {
                measured_proofs.push(MeasuredProofRef {
                    arch,
                    statement_index: stmt,
                    iteration_index: iter,
                    envelope_hash: h(0x20, measured_proofs.len()),
                });
            }
        }
    }
    let mut arch_provenance = Vec::new();
    for arch in [Arch::X86_64, Arch::Aarch64] {
        for role in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
            arch_provenance.push(ArchProvenanceRef {
                arch,
                role,
                provenance_hash: h(0x30, arch_provenance.len()),
            });
        }
    }
    let mut sample_bundles = Vec::new();
    for arch in [Arch::X86_64, Arch::Aarch64] {
        for stmt in [StatementIndex::Tlg, StatementIndex::SelectToken] {
            for metric in [
                MetricKind::HostProveWrapNs,
                MetricKind::HostVerifyNs,
                MetricKind::HostSetupNs,
                MetricKind::ProofBytes,
            ] {
                let sample_count = if matches!(metric, MetricKind::HostVerifyNs) {
                    1000
                } else {
                    10
                };
                sample_bundles.push(SampleBundle {
                    arch,
                    statement_index: stmt,
                    metric_kind: metric,
                    sample_kind: SampleKind::Measured,
                    sample_count,
                    bundle_hash: h(0x40, sample_bundles.len()),
                });
            }
        }
    }
    let mut rss_bundles = Vec::new();
    for arch in [Arch::X86_64, Arch::Aarch64] {
        for scope in [RssScope::ProvingRun, RssScope::VerifyBatch] {
            rss_bundles.push(RssBundle {
                arch,
                rss_scope: scope,
                record_count: 20,
                bundle_hash: h(0x50, rss_bundles.len()),
            });
        }
    }
    R0ResultSetV1 {
        b0_pre_spec_hash: RS_SPEC_HASH,
        r0_guest_set_hash: RS_GUEST_SET_HASH,
        candidate: Candidate::Sp1,
        verifier_material_manifest_hash: RS_VERIFIER_MATERIAL,
        official_statement_hash_tlg: RS_STMT_TLG,
        official_statement_hash_st: RS_STMT_ST,
        arch_provenance,
        measured_proofs,
        sample_bundles,
        rss_bundles,
        malformed_corpus_result_hash: [6; 32],
        cycle_bundle: None,
        completeness: Completeness {
            measured_proof_count: 40,
            verify_timing_sample_count: 4000,
            proving_time_sample_count: 40,
            proving_run_rss_count: 40,
            verify_batch_rss_count: 40,
        },
        aggregates: Aggregates {
            max_proof_bytes: 260,
            worst_arch_p99_verify_ns: 74_000_000,
            verifier_material_bytes: 292,
            worst_arch_verifier_rss_bytes: 100u64 << 20,
        },
        qualification_result: true,
        failure_codes: vec![],
    }
}

/// An envelope whose bindings match `official_result_set` (statement = TLG).
pub fn official_envelope() -> R0ProofArtifactEnvelopeV1 {
    R0ProofArtifactEnvelopeV1 {
        candidate: Candidate::Sp1,
        candidate_dep_lock_hash: [7; 32],
        guest_program_id: [8; 32],
        verifier_material_manifest_hash: RS_VERIFIER_MATERIAL,
        computation_statement_hash: RS_STMT_TLG,
        b0_pre_spec_hash: RS_SPEC_HASH,
        r0_guest_set_hash: RS_GUEST_SET_HASH,
        arch_run_provenance: [9; 32],
        arch: Arch::X86_64,
        sample_kind: SampleKind::Measured,
        iteration_index: 0,
        proof_hash: [10; 32],
        artifact_hashes: vec![],
    }
}

/// The SP1 verifier-material manifest (single GROTH16_VK_BYTES entry).
pub fn official_verifier_material() -> VerifierMaterialManifestV1 {
    VerifierMaterialManifestV1 {
        candidate: Candidate::Sp1,
        entries: vec![VerifierMaterialEntry {
            label: "GROTH16_VK_BYTES".to_string(),
            role: VerifierMaterialRole::Groth16Vk,
            byte_len: 292,
            hash: [0xAB; 32],
        }],
    }
}

/// An eligible proving-role provenance snapshot (16 cores / 64 GiB, 35% caps).
pub fn official_provenance_proving() -> ArchRunProvenanceV1 {
    ArchRunProvenanceV1 {
        provenance_role: ProvenanceRole::Proving,
        b0_pre_spec_hash: RS_SPEC_HASH,
        r0_guest_set_hash: RS_GUEST_SET_HASH,
        candidate: Candidate::Sp1,
        guest_program_id: [8; 32],
        candidate_dep_lock_hash: [7; 32],
        verifier_material_manifest_hash: RS_VERIFIER_MATERIAL,
        arch: Arch::X86_64,
        source_commit: "0".repeat(40),
        dirty_tree_flag: false,
        builder_container_digest: [9; 32],
        host_os: "linux".into(),
        kernel: "6.8.0".into(),
        cpu_vendor: "GenuineIntel".into(),
        cpu_model: "Xeon Gold".into(),
        physical_core_count: 16,
        logical_cpu_count: 32,
        total_ram_bytes: 64u64 << 30,
        configured_cpuset_core_limit: 5,
        configured_memory_limit_bytes: 22u64 << 30,
        governor: "performance".into(),
        turbo_enabled: false,
        clock_source: "tsc".into(),
        cgroup_version: 2,
        cgroup_scope_label: "b0-pre.slice".into(),
        benchmark_harness_source_hash: [0x1A; 32],
        raw_environment_capture_hash: [0x1B; 32],
    }
}

/// The stage-1 empty guest-program allowlist.
pub fn official_allowlist_empty() -> GuestProgramAllowlistV1 {
    GuestProgramAllowlistV1 { entries: vec![] }
}

pub fn official_sample() -> BenchmarkSampleV1 {
    BenchmarkSampleV1 {
        b0_pre_spec_hash: RS_SPEC_HASH,
        r0_guest_set_hash: RS_GUEST_SET_HASH,
        computation_statement_hash: RS_STMT_TLG,
        candidate: Candidate::Sp1,
        guest_program_id: [8; 32],
        verifier_material_manifest_hash: RS_VERIFIER_MATERIAL,
        candidate_dep_lock_hash: [7; 32],
        container_image_digest: [0x0C; 32],
        arch: Arch::X86_64,
        sample_kind: SampleKind::Measured,
        metric_kind: MetricKind::HostVerifyNs,
        unit: Unit::Nanoseconds,
        value: 42_000,
        proof_hash: [10; 32],
        iteration_index: 0,
        status: Status::Ok,
    }
}

pub fn official_rss() -> BenchmarkRssRecordV1 {
    BenchmarkRssRecordV1 {
        b0_pre_spec_hash: RS_SPEC_HASH,
        r0_guest_set_hash: RS_GUEST_SET_HASH,
        computation_statement_hash: RS_STMT_TLG,
        candidate: Candidate::Sp1,
        guest_program_id: [8; 32],
        verifier_material_manifest_hash: RS_VERIFIER_MATERIAL,
        candidate_dep_lock_hash: [7; 32],
        container_image_digest: [0x0C; 32],
        arch: Arch::X86_64,
        rss_scope: RssScope::VerifyBatch,
        proof_hash: [10; 32],
        run_index: 0,
        peak_rss_bytes: 100u64 << 20,
    }
}

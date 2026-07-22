//! The machine-readable B0-PRE normative protocol artifact (`b0-pre-protocol-v1`).
//!
//! This module defines the authoritative *typed* model of every frozen B0-PRE
//! field and assembles it, by `frozen()`, from this crate's own constants,
//! enums, tags, and encoders - so the emitted JSON artifact cannot drift from
//! the behavior the rest of the crate implements. The JSON Schema is generated
//! from these same types with `schemars` (see the `emit_protocol_schema`
//! example), and the canonical-JSON hash preimage is built by
//! [`crate::protocol_hash`].
//!
//! The artifact is deliberately **not finalizable** while any of the three
//! Stage-1 implementation-produced categories (candidate container digests,
//! candidate dependency lock hashes, candidate verifier-material manifests) is
//! absent. Those are typed placeholders (`Option`, omitted from the committed
//! artifact since canonical B0-PRE JSON forbids null); no fabricated or temporary
//! digest values are inserted. `finalization.state` is `not_finalizable` until
//! all three are resolved, and [`crate::protocol_hash`] refuses to run until then.
//!
//! Guest closure (`r0_guest_set_hash`, guest-program / image / vkey identities,
//! populated allowlist) is a **post-spec-hash** stage: guests embed the finalized
//! `b0_pre_spec_hash`, so their identities cannot be spec-hash inputs. The
//! `lifecycle` section documents this two-stage boundary.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::consts;
use crate::enums::{
    Arch, Candidate, InputSlotKind, MetricKind, ObjectKind, ProofRefKind, ProvenanceRole, RssScope,
    SampleKind, SlotKind, StatementIndex, Status, Unit, UnitKind, VerifierMaterialRole,
};
use crate::exp;
use crate::merkle;
use crate::tags;

/// Stable identifier of this normative artifact.
pub const ARTIFACT_ID: &str = "b0-pre-protocol-v1";

/// The two candidate identities, as their canonical string keys (== the
/// `Candidate` enum variant names). No other candidate string is accepted in the
/// Stage-1 coverage checks.
pub const CANDIDATE_NAMES: [&str; 2] = ["Sp1", "Risc0"];
/// The two per-architecture container roles: a base runtime image and a builder
/// image. Both are architecture-specific, enumerated separately.
pub const CONTAINER_ROLES: [&str; 2] = ["base", "builder"];
/// The two architectures every candidate/role pair is enumerated over (== the
/// `Arch` enum variant names).
pub const ARCH_NAMES: [&str; 2] = ["X86_64", "Aarch64"];

/// Rust toolchain floor for building/running the B0-PRE validator tools.
pub const VALIDATOR_TOOL_RUST_FLOOR: &str = "1.85.0";
/// Distinct, separately-frozen Rust toolchain for candidate proving containers.
/// Not conflated with the validator-tool floor.
pub const CANDIDATE_CONTAINER_RUST: &str = "1.88.0";

// Committed artifact identities. Each is re-locked in tests against both a fresh
// recomputation and the committed file, so these literals cannot silently drift.
pub const EXP_TABLE_HASH_HEX: &str =
    "50231bbd8f0aad16ea8b65e13811e6b9042ab2717a7b07f036893878305c92e8";
pub const EXP_CERT_HASH_HEX: &str =
    "5d7bc03ba31822f005451df82755a8d5ab961b5ee8daf6690eac371c916326be";
pub const OFFICIAL_TLG_TEMPLATE_HASH_HEX: &str =
    "7301ee63f420bcb5b50c7be7802e6e242e068978c8200671569777ed212f9969";
pub const OFFICIAL_SELECT_TEMPLATE_HASH_HEX: &str =
    "a31799c2f5740173a6088979e30d85c60eefeb2b4a15b0913cf5d2568768c72a";
pub const OFFICIAL_MODEL_ID_HEX: &str =
    "d3f7c07b230d2747b5e9365bec124f17f0948d03a55389ce0b6574101b8d4022";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// --- Typed artifact model ---------------------------------------------------

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct B0PreProtocolV1 {
    pub artifact_id: String,
    pub spec_version: String,
    pub finalization: Finalization,
    pub toolchains: Toolchains,
    pub domains: Domains,
    pub versions: Vec<NamedU64>,
    pub enums: Vec<EnumSpec>,
    pub dimensions: Dimensions,
    pub bounds: Bounds,
    pub unit_kind_rules: Vec<UnitKindRule>,
    pub schema_layouts: Vec<SchemaLayout>,
    pub commitment_merkle: CommitmentMerkle,
    pub json_rules: JsonRules,
    pub exp_table: ExpTableSpec,
    pub transformer: TransformerSpec,
    pub official_statements: OfficialStatements,
    pub witness_binding: WitnessBinding,
    pub candidate_eligibility: CandidateEligibility,
    pub evidence_completeness: EvidenceCompleteness,
    pub qualification_gates: QualificationGates,
    pub qualification_criteria: QualificationCriteria,
    pub contributor_resource_policy: ContributorResourcePolicy,
    pub reported_only_metrics: Vec<String>,
    pub aggregation: Aggregation,
    pub hash_preimage_rules: HashPreimageRules,
    pub lifecycle: Lifecycle,
    pub pending_inputs: PendingInputs,
}

/// The frozen two-stage lifecycle. Stage 1 computes `b0_pre_spec_hash` over the
/// normative protocol and Stage-1 inputs; guests then embed that hash and their
/// closure (guest-set hash, identities, populated allowlist) is derived
/// afterwards, at R0 time.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    pub stage1_spec_hash_includes: Vec<String>,
    pub stage1_spec_hash_excludes: Vec<String>,
    pub post_spec_hash_steps: Vec<String>,
    pub note: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Finalization {
    /// `not_finalizable` while any `pending_inputs` field is absent, else
    /// `finalizable`.
    pub state: String,
    /// Names of the absent implementation-produced fields blocking finalization.
    pub blocked_on: Vec<String>,
    pub note: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Toolchains {
    pub validator_tool_rust_floor: String,
    pub validator_tool_rust_floor_note: String,
    pub candidate_container_rust: String,
    pub candidate_container_rust_note: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Domains {
    pub structured_tags: Vec<StructuredTag>,
    pub hash_prefixes: Vec<HashPrefix>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct StructuredTag {
    pub name: String,
    pub ascii: String,
    /// The 32-byte zero-padded tag, lowercase hex (64 chars).
    pub bytes_hex: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct HashPrefix {
    pub name: String,
    pub ascii: String,
    /// Exact terminator byte (`\0` or `\n`), as a two-hex-digit string.
    pub terminator_hex: String,
    pub bytes_hex: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct NamedU64 {
    pub name: String,
    pub value: u64,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct EnumSpec {
    pub name: String,
    pub repr_bits: u32,
    pub variants: Vec<NamedU64>,
    pub reserved: Vec<NamedU64>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Dimensions {
    pub d_model: u32,
    pub n_heads: u32,
    pub head_dim: u16,
    pub ffn_dim: u16,
    pub vocab_size: u32,
    pub max_seq: u32,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    pub official: Vec<NamedU64>,
    pub decoder_maxima: Vec<NamedU64>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct UnitKindRule {
    pub unit_kind: String,
    pub wire_value: u64,
    pub layer_start: u32,
    pub layer_end: u32,
    pub rule: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct SchemaLayout {
    pub name: String,
    /// Encoded byte length of the representative/official instance.
    pub encoded_bytes: u64,
    pub note: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct CommitmentMerkle {
    pub object_tag_ascii: String,
    pub commitment_encoded_bytes: u64,
    pub identity_rule: String,
    pub merkle_chunk_bytes: u64,
    pub merkle_rule: String,
    pub empty_object_rule: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct JsonRules {
    pub strict_scan: Vec<String>,
    pub canonical: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ExpTableSpec {
    pub z_max: u32,
    pub entries: u32,
    pub scale: u32,
    pub scale_bits: u32,
    pub max_terms: u32,
    pub table_at_zero: u32,
    pub table_at_z_max: u32,
    pub lookup_rule: String,
    pub certification_rule: String,
    pub table_hash_hex: String,
    pub certificate_hash_hex: String,
    pub table_domain_ascii: String,
    pub certificate_domain_ascii: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct TransformerSpec {
    pub model_encoded_bytes: u64,
    pub model_magic: u32,
    pub model_version: u16,
    pub fixed_point_scale_log2: u8,
    pub model_layout: Vec<String>,
    pub rmsnorm_rule: String,
    pub attention_rule: String,
    pub ffn_rule: String,
    pub requantize_rule: String,
    pub select_argmax_rule: String,
    pub eos_token: u32,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct OfficialStatements {
    pub model_id_hex: String,
    pub statement_encoded_bytes: u64,
    pub spec_hash_zeroed_range: Vec<u64>,
    pub statements: Vec<OfficialStatement>,
    pub fixture_path: String,
    pub note: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct OfficialStatement {
    pub name: String,
    pub unit_kind: String,
    pub statement_index: u8,
    pub position: u32,
    pub sequence_length: u32,
    pub template_hash_hex: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct WitnessBinding {
    pub contract_steps: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct CandidateEligibility {
    pub candidates: Vec<NamedU64>,
    pub rules: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCompleteness {
    pub iterations_per_cell: u32,
    pub measured_proofs: u32,
    pub verify_timing_samples: u32,
    pub prove_time_samples: u32,
    pub proof_bytes_samples: u32,
    pub setup_samples: u32,
    pub proving_run_rss: u32,
    pub verify_batch_rss: u32,
    pub provenance_snapshots: u32,
    pub grid_rule: String,
    pub provenance_rule: String,
    pub non_mixability_rule: String,
}

/// Chain-side proof-verification qualification, under a controlled reference
/// envelope (a configured cpuset / memory limit). These are performance gates,
/// not hardware-class gates: neither validators nor contributors have a CPU/RAM
/// minimum. `reference_cpuset_cores` / `reference_memory_bytes` are the configured
/// candidate-comparison envelope, never a deployment or consensus hardware
/// minimum. Insufficient performance is an operational-liveness condition, not a
/// consensus / proof-system disqualification.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct QualificationGates {
    pub verify_p99_gate_ns: u64,
    pub aggregate_verify_budget_ns_per_block: u64,
    pub max_accepted_proofs_per_block: u32,
    pub reference_cpuset_cores: u32,
    pub reference_memory_bytes: u64,
    pub max_cycles: u64,
    pub validator_eligibility: String,
    pub scope: String,
    pub gates: Vec<String>,
    pub qualification_failure_codes: Vec<String>,
}

/// What a candidate qualifies on, and what can never disqualify it. Prover
/// performance and device resources are reported-only and appear in
/// `never_disqualifies`.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct QualificationCriteria {
    pub qualifies_on: Vec<String>,
    pub never_disqualifies: Vec<String>,
    pub note: String,
}

/// The corrected contributor-resource policy. OmniNode participation is
/// device-neutral: no minimum CPU, RAM, GPU, storage, or device class. Prover
/// resources are recorded for transparency only. The 35% budget is a local
/// operator default, not a selection gate.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContributorResourcePolicy {
    pub hardware_eligibility: String,
    pub reported_only_resources: Vec<String>,
    pub local_resource_budget: LocalResourceBudget,
    pub fair_benchmark_pairing: FairBenchmarkPairing,
    pub prove_watchdog: String,
    pub note: String,
}

/// A recommended default resource-budget an operator may configure per device.
/// Not consensus, proof validity, candidate selection, or hardware eligibility.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct LocalResourceBudget {
    pub default_fraction_percent: u32,
    pub scope: String,
}

/// Benchmark fairness is achieved by running both candidates under identical
/// controlled conditions on the same physical host per architecture, not by
/// excluding weaker devices or requiring a particular absolute host size.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct FairBenchmarkPairing {
    pub per_architecture_controls: Vec<String>,
    pub rule: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Aggregation {
    pub deterministic_rules: Vec<String>,
    pub failure_codes: Vec<String>,
    pub b0_final_tiebreak: Vec<String>,
    pub tiebreak_excludes: Vec<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct HashPreimageRules {
    pub spec_hash_prefix_ascii: String,
    pub spec_hash_prefix_hex: String,
    pub statement_template_prefix_ascii: String,
    pub guest_set_prefix_ascii: String,
    pub canonical_json_rule: String,
    pub finalization_rule: String,
}

/// Typed placeholders for the **Stage-1** implementation-produced fields that
/// must exist before `b0_pre_spec_hash` can be computed. Exactly three
/// categories: candidate container digests (base + per-architecture builder),
/// candidate dependency lock hashes, and candidate verifier-material manifests.
///
/// Post-spec-hash guest closure (`r0_guest_set_hash`, guest-program / image /
/// vkey identities, populated `GuestProgramAllowlistV1`) is deliberately NOT
/// here: guests embed the finalized spec hash, so their identities cannot be a
/// spec-hash input without circularity. There is no field capable of accepting
/// a guest identity or the guest-set hash.
///
/// Every field is absent in the committed artifact (omitted, never `null`);
/// no fabricated or temporary values are ever written here.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct PendingInputs {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub candidate_container_digests: Option<Vec<ContainerDigest>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cargo_lock_hashes: Option<Vec<LockHash>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verifier_material_manifests: Option<Vec<VerifierMaterialManifestRef>>,
}

/// One immutable container identity. `role` distinguishes the base runtime image
/// from the per-architecture builder image, so base and builder digests are
/// enumerated separately.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerDigest {
    pub candidate: String,
    /// `base` or `builder`.
    pub role: String,
    pub arch: String,
    /// The OCI manifest identity as a full `sha256:<64hex>` digest (one coherent
    /// representation with `lib.sh`/`VENUE.md`/the Dockerfiles/`BASE_DIGEST`); the
    /// `sha256:` algorithm prefix is never stripped.
    pub image_digest: String,
    pub domain_ascii: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct LockHash {
    pub name: String,
    pub blake3_hex: String,
    pub domain_ascii: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct VerifierMaterialManifestRef {
    pub candidate: String,
    pub manifest_hash_hex: String,
    pub total_bytes: u64,
    pub domain_ascii: String,
}

impl PendingInputs {
    /// Names of the absent Stage-1 implementation-produced categories, in a
    /// stable order. Exactly three categories can ever appear.
    pub fn absent(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.candidate_container_digests.is_none() {
            v.push("candidate_container_digests".into());
        }
        if self.cargo_lock_hashes.is_none() {
            v.push("cargo_lock_hashes".into());
        }
        if self.verifier_material_manifests.is_none() {
            v.push("verifier_material_manifests".into());
        }
        v
    }

    /// True only when every Stage-1 category is present.
    pub fn all_present(&self) -> bool {
        self.absent().is_empty()
    }
}

impl B0PreProtocolV1 {
    /// True only when every `pending_inputs` field is resolved.
    pub fn is_finalizable(&self) -> bool {
        self.pending_inputs.all_present()
    }

    /// Cross-field semantic checks JSON Schema cannot express. Returns the list
    /// of violations (empty = consistent).
    pub fn semantic_violations(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.artifact_id != ARTIFACT_ID {
            v.push(format!("artifact_id must be {ARTIFACT_ID}"));
        }
        let expect_state = if self.is_finalizable() {
            "finalizable"
        } else {
            "not_finalizable"
        };
        if self.finalization.state != expect_state {
            v.push(format!(
                "finalization.state is {:?} but pending inputs imply {expect_state:?}",
                self.finalization.state
            ));
        }
        if self.finalization.blocked_on != self.pending_inputs.absent() {
            v.push("finalization.blocked_on must list exactly the absent pending inputs".into());
        }
        if self.toolchains.validator_tool_rust_floor == self.toolchains.candidate_container_rust {
            v.push(
                "validator-tool floor and candidate-container toolchain must stay distinct".into(),
            );
        }
        // dimensions must not exceed the official bounds
        if u64::from(self.dimensions.d_model) > self.bounds_official("max_d_model") {
            v.push("d_model exceeds max_d_model".into());
        }
        if u64::from(self.dimensions.max_seq) > self.bounds_official("max_seq_len") {
            v.push("max_seq exceeds max_seq_len".into());
        }
        // both official statements present, distinct indices
        if self.official_statements.statements.len() != 2 {
            v.push("exactly two official statements required".into());
        }
        // validator verification baseline must be internally consistent
        if self
            .qualification_gates
            .aggregate_verify_budget_ns_per_block
            < self.qualification_gates.verify_p99_gate_ns
        {
            v.push("aggregate verify budget must be >= the per-proof verify p99 gate".into());
        }
        if self.qualification_gates.max_accepted_proofs_per_block == 0 {
            v.push("max_accepted_proofs_per_block must be >= 1".into());
        }
        // the 35% budget is a local operating default, never an eligibility fraction > 100%
        if self
            .contributor_resource_policy
            .local_resource_budget
            .default_fraction_percent
            > 100
        {
            v.push("local resource budget fraction must be <= 100".into());
        }
        // Stage-1 coverage / uniqueness / domain checks for any present category.
        self.pending_input_violations(&mut v);
        v
    }

    /// Cross-field coverage rules for the Stage-1 `pending_inputs`. A category that
    /// is absent (not yet resolved) contributes nothing; a category that is present
    /// must be exactly complete. An empty array (`Some(vec![])`) is therefore never
    /// finalizable: it fails the exact-count rule here, so `protocol_hash_preimage`
    /// refuses it.
    ///
    /// Enforced when present:
    ///   * exactly 8 container digests = 2 candidates x 2 roles (base, builder) x
    ///     2 arches, every `(candidate, role, arch)` tuple exactly once (no
    ///     missing / duplicate / extra), unknown candidate/role/arch rejected;
    ///   * exactly 2 dependency lock hashes, one per candidate, unique;
    ///   * exactly 2 verifier-material manifests, one per candidate, unique,
    ///     non-zero total_bytes;
    ///   * every entry carries its exact frozen domain tag and a 64-hex identity.
    fn pending_input_violations(&self, v: &mut Vec<String>) {
        let is_hex64 = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        let container_tag = ascii_of(&tags::CONTAINER_TAG);
        let lock_tag = ascii_of(&tags::CARGO_LOCK_TAG);
        let vmat_tag = ascii_of(&tags::VERIFIER_MATERIAL_TAG);

        if let Some(containers) = &self.pending_inputs.candidate_container_digests {
            // The full 2x2x2 coverage, each tuple required exactly once.
            let mut required: std::collections::BTreeSet<(&str, &str, &str)> =
                std::collections::BTreeSet::new();
            for c in CANDIDATE_NAMES {
                for role in CONTAINER_ROLES {
                    for arch in ARCH_NAMES {
                        required.insert((c, role, arch));
                    }
                }
            }
            let mut seen: std::collections::BTreeSet<(String, String, String)> =
                std::collections::BTreeSet::new();
            for cd in containers {
                if !CANDIDATE_NAMES.contains(&cd.candidate.as_str()) {
                    v.push(format!(
                        "container digest has unknown candidate {:?}",
                        cd.candidate
                    ));
                }
                if !CONTAINER_ROLES.contains(&cd.role.as_str()) {
                    v.push(format!("container digest has unknown role {:?}", cd.role));
                }
                if !ARCH_NAMES.contains(&cd.arch.as_str()) {
                    v.push(format!("container digest has unknown arch {:?}", cd.arch));
                }
                if cd.domain_ascii != container_tag {
                    v.push("container digest domain_ascii must be the CONTAINER tag".into());
                }
                // OCI manifest identity: full `sha256:<64hex>` (algorithm prefix
                // required, never bare hex or another algorithm).
                let oci_ok = cd
                    .image_digest
                    .strip_prefix("sha256:")
                    .is_some_and(is_hex64);
                if !oci_ok {
                    v.push(
                        "container image_digest must be a full sha256:<64hex> OCI manifest identity"
                            .into(),
                    );
                }
                let key = (cd.candidate.clone(), cd.role.clone(), cd.arch.clone());
                if !seen.insert(key) {
                    v.push(format!(
                        "duplicate container tuple ({}, {}, {})",
                        cd.candidate, cd.role, cd.arch
                    ));
                }
            }
            let present: std::collections::BTreeSet<(&str, &str, &str)> = seen
                .iter()
                .map(|(c, r, a)| (c.as_str(), r.as_str(), a.as_str()))
                .collect();
            for missing in required.difference(&present) {
                v.push(format!(
                    "missing container tuple ({}, {}, {})",
                    missing.0, missing.1, missing.2
                ));
            }
            for extra in present.difference(&required) {
                v.push(format!(
                    "extra container tuple ({}, {}, {})",
                    extra.0, extra.1, extra.2
                ));
            }
            if containers.len() != 8 {
                v.push(format!(
                    "exactly 8 container digests required (2 candidates x 2 roles x 2 arches), got {}",
                    containers.len()
                ));
            }
        }

        if let Some(locks) = &self.pending_inputs.cargo_lock_hashes {
            let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
            for lk in locks {
                if !CANDIDATE_NAMES.contains(&lk.name.as_str()) {
                    v.push(format!(
                        "dependency lock has unknown candidate {:?}",
                        lk.name
                    ));
                }
                if lk.domain_ascii != lock_tag {
                    v.push("dependency lock domain_ascii must be the CARGO_LOCK tag".into());
                }
                if !is_hex64(&lk.blake3_hex) {
                    v.push("dependency lock blake3_hex must be 64 lowercase hex".into());
                }
                if !names.insert(lk.name.as_str()) {
                    v.push(format!(
                        "duplicate dependency lock for candidate {}",
                        lk.name
                    ));
                }
            }
            if locks.len() != 2 {
                v.push(format!(
                    "exactly 2 dependency lock hashes required (one per candidate), got {}",
                    locks.len()
                ));
            }
        }

        if let Some(manifests) = &self.pending_inputs.verifier_material_manifests {
            let mut cands: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
            for m in manifests {
                if !CANDIDATE_NAMES.contains(&m.candidate.as_str()) {
                    v.push(format!(
                        "verifier-material manifest has unknown candidate {:?}",
                        m.candidate
                    ));
                }
                if m.domain_ascii != vmat_tag {
                    v.push("verifier-material manifest domain_ascii must be the VMAT tag".into());
                }
                if !is_hex64(&m.manifest_hash_hex) {
                    v.push("verifier-material manifest_hash_hex must be 64 lowercase hex".into());
                }
                if m.total_bytes == 0 {
                    v.push("verifier-material manifest total_bytes must be non-zero".into());
                }
                if !cands.insert(m.candidate.as_str()) {
                    v.push(format!(
                        "duplicate verifier-material manifest for candidate {}",
                        m.candidate
                    ));
                }
            }
            if manifests.len() != 2 {
                v.push(format!(
                    "exactly 2 verifier-material manifests required (one per candidate), got {}",
                    manifests.len()
                ));
            }
        }
    }

    fn bounds_official(&self, name: &str) -> u64 {
        self.bounds
            .official
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.value)
            .unwrap_or(u64::MAX)
    }

    /// Assemble the frozen artifact from this crate's own definitions. All
    /// `pending_inputs` are absent, so the result is `not_finalizable`.
    pub fn frozen() -> Self {
        let pending = PendingInputs::default();
        let blocked_on = pending.absent();

        let table = exp::table_cached();

        Self {
            artifact_id: ARTIFACT_ID.into(),
            spec_version: crate::SPEC_VERSION.into(),
            finalization: Finalization {
                state: "not_finalizable".into(),
                blocked_on,
                note: "Blocked until the three Stage-1 categories exist: candidate container \
                       digests (base + per-arch builder), candidate dependency lock hashes, and \
                       candidate verifier-material manifests. Guest closure (r0_guest_set_hash, \
                       guest-program identities, populated allowlist) is post-spec-hash and is NOT \
                       required here. No fabricated values are inserted; protocol_hash refuses to \
                       run until then."
                    .into(),
            },
            toolchains: Toolchains {
                validator_tool_rust_floor: VALIDATOR_TOOL_RUST_FLOOR.into(),
                validator_tool_rust_floor_note:
                    "Minimum Rust for building/running the B0-PRE validator tool crates.".into(),
                candidate_container_rust: CANDIDATE_CONTAINER_RUST.into(),
                candidate_container_rust_note:
                    "Separately-frozen toolchain for candidate proving containers; distinct from \
                     the validator-tool floor and not conflated with it."
                        .into(),
            },
            domains: frozen_domains(),
            versions: frozen_versions(),
            enums: frozen_enums(),
            dimensions: Dimensions {
                d_model: consts::D_MODEL,
                n_heads: consts::N_HEADS,
                head_dim: consts::HEAD_DIM,
                ffn_dim: consts::FFN_DIM,
                vocab_size: consts::VOCAB_SIZE,
                max_seq: consts::MAX_SEQ,
            },
            bounds: frozen_bounds(),
            unit_kind_rules: vec![
                UnitKindRule {
                    unit_kind: "TransformerLayerGroup".into(),
                    wire_value: UnitKind::TransformerLayerGroup.to_repr() as u64,
                    layer_start: 0,
                    layer_end: 1,
                    rule: "Single frozen layer group; runs RMSNorm+attention+FFN and emits the \
                           residual/KV state. selected_token and eos are sentinels."
                        .into(),
                },
                UnitKindRule {
                    unit_kind: "SelectToken".into(),
                    wire_value: UnitKind::SelectToken.to_repr() as u64,
                    layer_start: 0,
                    layer_end: 0,
                    rule: "Projects the final residual to logits and selects the argmax token \
                           (lowest index on ties); empty prior-KV and empty output manifest."
                        .into(),
                },
            ],
            schema_layouts: frozen_layouts(),
            commitment_merkle: CommitmentMerkle {
                object_tag_ascii: ascii_of(&tags::OBJECT_TAG),
                commitment_encoded_bytes: 80,
                identity_rule:
                    "ObjectCommitmentV1 = OBJECT_TAG || kind || byte_len || chunk_count || \
                     merkle_root; identity() = BLAKE3 over the 80-byte encoding."
                        .into(),
                merkle_chunk_bytes: merkle::CHUNK as u64,
                merkle_rule:
                    "chunk_count = ceil(byte_len / CHUNK); leaves are BLAKE3 of each chunk; \
                     binary Merkle over leaves; single leaf is its own root."
                        .into(),
                empty_object_rule:
                    "Empty object: byte_len 0, chunk_count 0, all-zero merkle_root.".into(),
            },
            json_rules: JsonRules {
                strict_scan: vec![
                    "UTF-8 only; reject BOM and control chars outside strings".into(),
                    "reject duplicate object keys".into(),
                    "reject leading zeros, '+' signs, and bare/ trailing decimal points".into(),
                    "reject NaN, Infinity, and exponent-only anomalies".into(),
                    "reject trailing bytes after the top-level value".into(),
                    "integers above u64::MAX are preserved via arbitrary_precision, never coerced \
                     to f64"
                        .into(),
                ],
                canonical: vec![
                    "object keys sorted by UTF-8 byte order".into(),
                    "minimal number form: no leading zeros, no exponent, no trailing zeros".into(),
                    "the canonical byte stream is ASCII; any non-ASCII character is \\u-escaped, \
                     and the minimal escape set is used"
                        .into(),
                    "null is not permitted; absent optional fields are omitted, never null".into(),
                    "no insignificant whitespace".into(),
                ],
            },
            exp_table: ExpTableSpec {
                z_max: exp::Z_MAX,
                entries: exp::Z_MAX + 1,
                scale: exp::SCALE,
                scale_bits: exp::SCALE_BITS,
                max_terms: exp::MAX_TERMS as u32,
                table_at_zero: table[0],
                table_at_z_max: table[exp::Z_MAX as usize],
                lookup_rule: "z <= Z_MAX reads table[z]; z > Z_MAX yields 0.".into(),
                certification_rule:
                    "Each entry is the unique Q16 rounding of exp(-z/SCALE) proven by a \
                     big-rational interval enclosure; no floating point."
                        .into(),
                table_hash_hex: EXP_TABLE_HASH_HEX.into(),
                certificate_hash_hex: EXP_CERT_HASH_HEX.into(),
                table_domain_ascii: ascii_of(&tags::EXP_TABLE_TAG),
                certificate_domain_ascii: ascii_of(&tags::EXP_CERT_TAG),
            },
            transformer: TransformerSpec {
                model_encoded_bytes: 1334,
                model_magic: 0x5230_4D44,
                model_version: 1,
                fixed_point_scale_log2: consts::FIXED_POINT_SCALE_LOG2,
                model_layout: vec![
                    "magic:u32".into(),
                    "version:u16".into(),
                    "attn_gamma[8]".into(),
                    "wq[8x8] wk[8x8] wv[8x8] wo[8x8]".into(),
                    "ffn_gamma[8]".into(),
                    "w1[8x16] w2[16x8]".into(),
                    "final_gamma[8]".into(),
                    "lmhead[8x16]".into(),
                    "all i16 LE, row-major [in][out]".into(),
                ],
                rmsnorm_rule: "isqrt(ss/8 + 1) with RHAZ requantize by 256".into(),
                attention_rule:
                    "2 heads, head_dim 4, masked softmax; score / 512; weights from the exp table; \
                     denominator floored at 65536"
                        .into(),
                ffn_rule: "8->16->8 with ReLU; RHAZ requantize by 256".into(),
                requantize_rule: "RHAZ(value, 256) - round half away from zero".into(),
                select_argmax_rule: "argmax over logits; lowest index wins ties".into(),
                eos_token: 15,
            },
            official_statements: OfficialStatements {
                model_id_hex: OFFICIAL_MODEL_ID_HEX.into(),
                statement_encoded_bytes: 996,
                spec_hash_zeroed_range: vec![
                    crate::schema::statement::R0ComputationStatementV2::SPEC_HASH_RANGE.start as u64,
                    crate::schema::statement::R0ComputationStatementV2::SPEC_HASH_RANGE.end as u64,
                ],
                statements: vec![
                    OfficialStatement {
                        name: "official-tlg".into(),
                        unit_kind: "TransformerLayerGroup".into(),
                        statement_index: StatementIndex::Tlg.to_repr(),
                        position: 7,
                        sequence_length: 8,
                        template_hash_hex: OFFICIAL_TLG_TEMPLATE_HASH_HEX.into(),
                    },
                    OfficialStatement {
                        name: "official-select".into(),
                        unit_kind: "SelectToken".into(),
                        statement_index: StatementIndex::SelectToken.to_repr(),
                        position: 6,
                        sequence_length: 7,
                        template_hash_hex: OFFICIAL_SELECT_TEMPLATE_HASH_HEX.into(),
                    },
                ],
                fixture_path: "docs/b0-pre/fixtures/workload/official.json".into(),
                note: "The only two canonical B0-PRE workload statements. Both are byte-locked, \
                       independently, by both tool crates (NON_SELECTION / TEST_ONLY weights)."
                    .into(),
            },
            witness_binding: WitnessBinding {
                contract_steps: vec![
                    "authenticate model + inputs against the public commitments".into(),
                    "reconstruct DerivedInputV1 and check its commitment".into(),
                    "enforce frozen dims/bounds and the checked max_state_bytes".into(),
                    "execute the frozen unit and recompute the output manifest".into(),
                    "rebuild the full statement template and compare byte-for-byte".into(),
                ],
            },
            candidate_eligibility: CandidateEligibility {
                candidates: vec![
                    NamedU64 { name: "Sp1".into(), value: Candidate::Sp1.to_repr() as u64 },
                    NamedU64 { name: "Risc0".into(), value: Candidate::Risc0.to_repr() as u64 },
                ],
                rules: vec![
                    "Exactly two candidates (SP1=1, RISC0=2); 0 is not a candidate.".into(),
                    "At R0 time (after b0_pre_spec_hash is finalized), a candidate is eligible only \
                     with complete, non-mixed evidence bound to BOTH hashes: b0_pre_spec_hash and \
                     the post-spec r0_guest_set_hash, plus its container digest, tool lock hashes, \
                     guest-program identities, and verifier material."
                        .into(),
                    "Candidate proving containers build under the candidate-container toolchain \
                     (Rust 1.88.0), distinct from the validator-tool floor (Rust 1.85.0)."
                        .into(),
                    "OmniNode contributor eligibility is device-neutral: no minimum CPU, RAM, GPU, \
                     storage, or device class determines whether a contributor is protocol-eligible. \
                     A valid proof from any device is eligible; a slower device only takes longer. \
                     Prover time, memory, cores, architecture, GPU, storage, and timing variance are \
                     reported-only and never determine eligibility, qualification, or the B0-FINAL \
                     tie-break."
                        .into(),
                ],
            },
            evidence_completeness: EvidenceCompleteness {
                iterations_per_cell: consts::OFFICIAL_ITERATIONS_PER_CELL,
                measured_proofs: consts::OFFICIAL_MEASURED_PROOFS,
                verify_timing_samples: consts::OFFICIAL_VERIFY_TIMING_SAMPLES,
                prove_time_samples: consts::OFFICIAL_PROVE_TIME_SAMPLES,
                proof_bytes_samples: consts::OFFICIAL_PROOF_BYTES_SAMPLES,
                setup_samples: consts::OFFICIAL_SETUP_SAMPLES,
                proving_run_rss: consts::OFFICIAL_PROVING_RUN_RSS,
                verify_batch_rss: consts::OFFICIAL_VERIFY_BATCH_RSS,
                provenance_snapshots: consts::OFFICIAL_PROVENANCE_SNAPSHOTS,
                grid_rule: "Measured grid: 2 statements x 2 architectures x 10 iterations = 40 \
                            measured proofs, in canonical ascending order."
                    .into(),
                provenance_rule: "4 provenance snapshots: {x86_64, aarch64} x {proving, \
                                  verification}."
                    .into(),
                non_mixability_rule: "Every record must bind the same spec/guest-set/candidate/ \
                                      material/program/lock/container identities; mixed evidence is \
                                      rejected."
                    .into(),
            },
            qualification_gates: QualificationGates {
                verify_p99_gate_ns: crate::harness::P99_GATE_NS,
                aggregate_verify_budget_ns_per_block:
                    consts::VALIDATOR_AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK,
                max_accepted_proofs_per_block: consts::MAX_ACCEPTED_PROOFS_PER_BLOCK as u32,
                reference_cpuset_cores: consts::VALIDATOR_VERIFY_REFERENCE_CORES,
                reference_memory_bytes: consts::VALIDATOR_VERIFY_REFERENCE_RAM_BYTES,
                max_cycles: consts::MAX_CYCLES,
                validator_eligibility: "Validator qualification is performance-based, not \
                        hardware-class-based: no minimum physical cores or RAM, and detected host \
                        hardware is never an eligibility gate. A node of any CPU/RAM configuration \
                        may participate; reference_cpuset_cores / reference_memory_bytes are only \
                        the controlled candidate-comparison envelope, not a deployment or consensus \
                        hardware minimum. Operators remain responsible for network liveness under \
                        their workload; a machine that cannot keep the verification pace has an \
                        operational capacity condition, not a proof-system disqualification or \
                        consensus invalidity."
                    .into(),
                scope: "Chain-side proof verification under a controlled reference envelope: the \
                        verification run is pinned to exactly reference_cpuset_cores cores and \
                        reference_memory_bytes of memory (2 cores / 4 GiB). Detected host hardware \
                        need only be sufficient to establish those limits and is never gated. This \
                        is a candidate-comparison envelope, not a validator hardware minimum."
                    .into(),
                gates: vec![
                    "host_verify_ns p99 (nearest-rank, host_setup_ns excluded) must be <= \
                     verify_p99_gate_ns on the worst architecture"
                        .into(),
                    "aggregate_verify_ns_per_block = worst_arch_p99_verify_ns * \
                     max_accepted_proofs_per_block (checked; overflow disqualifies) must be <= \
                     aggregate_verify_budget_ns_per_block; evaluated INDEPENDENTLY of the \
                     per-proof p99 gate (their product equalling the budget is a coincidence)"
                        .into(),
                    "the verification run must be configured to exactly reference_cpuset_cores \
                     cores and reference_memory_bytes memory; detected host hardware is not an \
                     eligibility gate, but provenance must be self-consistent (configured limits \
                     <= detected resources, all nonzero)"
                        .into(),
                    "each candidate's result_set.verifier_material_bytes must equal the Sum of \
                     byte_len over THAT candidate's own preregistered verifier-material manifest, \
                     checked independently per candidate. There is no cross-candidate \
                     verifier-material byte constant and no universal maximum: SP1's 292-byte \
                     Groth16 VK is SP1's value only, never a shared gate."
                        .into(),
                    "max_cycles is a reported bound; official statements set it to 0".into(),
                ],
                qualification_failure_codes: vec![
                    "3 = worst-arch verify p99 exceeds verify_p99_gate_ns".into(),
                    "4 = aggregate (worst-arch p99 * max_accepted_proofs_per_block, checked) \
                     exceeds aggregate_verify_budget_ns_per_block, or the multiplication overflows"
                        .into(),
                ],
            },
            qualification_criteria: QualificationCriteria {
                qualifies_on: vec![
                    "correctness against the frozen witness-binding contract".into(),
                    "a valid terminal proof verified through the pinned verifier".into(),
                    "verifier identity / security (verifier material bound and authentic)".into(),
                    "reproducibility (digest-pinned container, lock hashes, guest identities)"
                        .into(),
                    "cross-architecture semantic equivalence (x86_64 and aarch64 agree)".into(),
                    "stable / no-advisory dependency policy".into(),
                    "validator-side verification limits (verify p99 and per-block budget)".into(),
                ],
                never_disqualifies: vec![
                    "prover wall-clock time".into(),
                    "prover peak RAM".into(),
                    "configured or physical core count".into(),
                    "device architecture, GPU use, or storage usage".into(),
                    "timing variance".into(),
                    "device class or absolute host size".into(),
                ],
                note: "A valid candidate is never disqualified by prover performance or device \
                       resources, and none of these enter the B0-FINAL tie-break."
                    .into(),
            },
            contributor_resource_policy: ContributorResourcePolicy {
                hardware_eligibility: "none: no minimum CPU, RAM, GPU, storage, or device class \
                                       gates OmniNode participation. Preregistration correction \
                                       removing the former >=16-core / >=64-GiB / 35%-cap \
                                       proving-resource gate (resource_gate_proving)."
                    .into(),
                reported_only_resources: vec![
                    "prover_time_ns".into(),
                    "prover_peak_ram_bytes".into(),
                    "configured_cpuset_core_limit".into(),
                    "physical_core_count".into(),
                    "total_ram_bytes".into(),
                    "device_architecture".into(),
                    "gpu_use".into(),
                    "storage_usage".into(),
                    "timing_variance".into(),
                ],
                local_resource_budget: LocalResourceBudget {
                    default_fraction_percent: consts::LOCAL_RESOURCE_BUDGET_DEFAULT_PERCENT,
                    scope: "A recommended default local resource-budget an OmniNode operator may \
                            configure for their device. It is not consensus, proof validity, \
                            candidate selection, or hardware eligibility."
                        .into(),
                },
                fair_benchmark_pairing: FairBenchmarkPairing {
                    per_architecture_controls: vec![
                        "same controlled physical host".into(),
                        "same host OS and kernel".into(),
                        "same CPU vendor and model".into(),
                        "same detected physical and logical core counts".into(),
                        "same detected total RAM".into(),
                        "same configured cpuset and memory limit".into(),
                        "same governor, turbo state, clock source, and cgroup version/scope".into(),
                        "same isolation".into(),
                        "same benchmark-harness source identity".into(),
                        "same workload, warmup, and iteration policy".into(),
                    ],
                    rule: "For each (architecture, provenance role) the two candidates' provenance \
                           must represent the same controlled host and environment; this is \
                           enforced in the paired-evidence verification path, not merely \
                           documented. Candidate-specific identities (guest program, lock hash, \
                           verifier material, container digest) are not compared. No particular \
                           absolute host size is required (device neutrality), so weaker hardware \
                           only takes longer -- but the two paired candidates may not run on \
                           different hardware."
                        .into(),
                },
                prove_watchdog: "Run-management timeout only. A timeout produces an incomplete run \
                                 requiring continuation/retry; it is not a candidate performance \
                                 failure or a disqualification."
                    .into(),
                note: "Neither validators nor contributors have hardware-class eligibility. \
                       Validator qualification is performance-based under a controlled reference \
                       envelope (see qualification_gates); contributors have no resource gate at \
                       all. A valid proof remains valid regardless of the device that produced it, \
                       and a validator that cannot keep the verification pace has an \
                       operational-liveness condition, not a consensus disqualification."
                    .into(),
            },
            reported_only_metrics: vec![
                "GuestCyclesModelAuth".into(),
                "GuestCyclesTransformer".into(),
                "GuestCyclesStateHash".into(),
                "GuestCyclesTotal".into(),
                "HostProveWrapNs".into(),
                "HostSetupNs".into(),
                "ProofBytes".into(),
            ],
            aggregation: Aggregation {
                deterministic_rules: vec![
                    "Samples sorted by (arch, statement, iteration); aggregates recomputed from \
                     raw bytes."
                        .into(),
                    "p99 via nearest-rank; bundle hashes are domain-prefixed BLAKE3 over the \
                     sorted raw records."
                        .into(),
                ],
                failure_codes: vec![
                    "MeasuredProofGrid".into(),
                    "ProvenanceSet".into(),
                    "CompletenessCount".into(),
                    "SampleSum".into(),
                    "RssSum".into(),
                    "QualificationInconsistent".into(),
                    "RecordMixed".into(),
                    "ProvenanceIneligible".into(),
                    "PairedEnvironmentMismatch".into(),
                ],
                b0_final_tiebreak: vec![
                    "Among qualified candidates, break ties by lowest verify-p99, then lowest \
                     proof_bytes, then lowest candidate discriminant (SP1 before RISC0)."
                        .into(),
                ],
                tiebreak_excludes: vec![
                    "prover wall-clock time".into(),
                    "prover peak RAM".into(),
                    "core count, device architecture, GPU, or storage".into(),
                    "timing variance".into(),
                ],
            },
            hash_preimage_rules: HashPreimageRules {
                spec_hash_prefix_ascii: ascii_prefix(tags::SPEC_PREFIX),
                spec_hash_prefix_hex: hex(tags::SPEC_PREFIX),
                statement_template_prefix_ascii: ascii_prefix(tags::STMT_TEMPLATE_PREFIX),
                guest_set_prefix_ascii: ascii_prefix(tags::GUESTSET_PREFIX),
                canonical_json_rule:
                    "b0_pre_spec_hash = BLAKE3(SPEC_PREFIX || canonical_protocol_json), where the \
                     canonical JSON follows the canonical rules above."
                        .into(),
                finalization_rule:
                    "The preimage may only be built from a finalized artifact; a not_finalizable \
                     artifact (any Stage-1 input absent) cannot be hashed. r0_guest_set_hash and \
                     guest-program identities are post-spec and never enter this preimage."
                        .into(),
            },
            lifecycle: frozen_lifecycle(),
            pending_inputs: pending,
        }
    }
}

fn frozen_lifecycle() -> Lifecycle {
    let s = |x: &str| x.to_string();
    Lifecycle {
        stage1_spec_hash_includes: vec![
            s("the complete normative protocol and workload"),
            s("candidate dependency lock hashes"),
            s("immutable base and per-architecture builder container identities"),
            s("candidate verifier-material manifests and their identities"),
            s("exp table and certificate identities"),
            s("both official zero-hash statement templates and their template hashes"),
            s("statement materialization rule: insert b0_pre_spec_hash into the template's \
               b0_pre_spec_hash range [34,66) to form each final statement"),
            s("the empty GuestProgramAllowlistV1 schema and its hashing rules"),
            s("provenance/result-set schemas, eligibility rules, aggregation rules, failure codes"),
        ],
        stage1_spec_hash_excludes: vec![
            s("final materialized statement bytes"),
            s("guest sources and binaries"),
            s("guest_program_id / program / image identities"),
            s("populated GuestProgramAllowlistV1"),
            s("r0_guest_set_hash"),
            s("provenance records"),
            s("measurement / result records"),
        ],
        post_spec_hash_steps: vec![
            s("1. materialize the two final statements by inserting b0_pre_spec_hash"),
            s("2. build guests that embed B0_PRE_SPEC_HASH"),
            s("3. derive guest image / vkey / program identities"),
            s("4. populate GuestProgramAllowlistV1"),
            s("5. compute r0_guest_set_hash"),
            s("6. bind all R0 evidence to both b0_pre_spec_hash and r0_guest_set_hash"),
        ],
        note: "Two stages, in order. Stage 1 hashes only the material above into b0_pre_spec_hash \
               before any guest exists. Guests then embed that hash, so r0_guest_set_hash and \
               guest identities are derived afterwards and can never feed back into the spec-hash \
               preimage."
            .into(),
    }
}

/// A **TEST_ONLY** finalizable artifact: the frozen artifact with the three
/// Stage-1 categories filled by fixed synthetic values (NOT real container
/// digests, lock hashes, or verifier material). It contains NO guest identity or
/// guest-set hash (those are post-spec). Used solely to exercise the canonical
/// preimage / hash path and its golden vectors. The hash it produces is NOT the
/// real `b0_pre_spec_hash`.
pub fn test_only_finalizable_artifact() -> B0PreProtocolV1 {
    use crate::enums::VerifierMaterialRole::{ControlId, ControlRoot, Groth16Vk, VerifierParams};
    use crate::schema::verifier_material::VerifierMaterialManifestV1;

    let h = |b: u8| hex(&[b; 32]);
    let cd = |candidate: &str, role: &str, arch: &str, b: u8| ContainerDigest {
        candidate: candidate.into(),
        role: role.into(),
        arch: arch.into(),
        // Full sha256:<64hex> OCI manifest identity (the one coherent representation).
        image_digest: format!("sha256:{}", h(b)),
        domain_ascii: ascii_of(&tags::CONTAINER_TAG),
    };
    let lock = |candidate: &str, b: u8| LockHash {
        name: candidate.into(),
        blake3_hex: h(b),
        domain_ascii: ascii_of(&tags::CARGO_LOCK_TAG),
    };
    // Build the two canonical manifests from raw synthetic entries so the ref's
    // manifest_hash_hex is BLAKE3(VerifierMaterialManifestV1::encode()) and its
    // total_bytes is that candidate's own Sum(byte_len) — never a shared 292.
    let sp1_vmm =
        VerifierMaterialManifestV1::from_canonical(Candidate::Sp1, [(Groth16Vk, 292, [0x71; 32])]);
    let risc0_vmm = VerifierMaterialManifestV1::from_canonical(
        Candidate::Risc0,
        [
            (Groth16Vk, 256, [0x72; 32]),
            (ControlRoot, 32, [0x73; 32]),
            (ControlId, 32, [0x74; 32]),
            (VerifierParams, 32, [0x75; 32]),
        ],
    );
    let vmat_ref = |m: &VerifierMaterialManifestV1| VerifierMaterialManifestRef {
        candidate: match m.candidate {
            Candidate::Sp1 => "Sp1".into(),
            Candidate::Risc0 => "Risc0".into(),
        },
        // TEST_ONLY canonical manifests always encode; a codec error here would be
        // an invariant break, not a runtime input condition.
        manifest_hash_hex: hex(&m.identity().expect("canonical TEST_ONLY manifest encodes")),
        total_bytes: m.verifier_material_bytes().expect("no overflow"),
        domain_ascii: ascii_of(&tags::VERIFIER_MATERIAL_TAG),
    };

    let mut p = B0PreProtocolV1::frozen();
    p.pending_inputs = PendingInputs {
        // 8 = 2 candidates x 2 roles (base, builder) x 2 arches; base AND builder
        // are architecture-specific, enumerated separately.
        candidate_container_digests: Some(vec![
            cd("Sp1", "base", "X86_64", 0x21),
            cd("Sp1", "base", "Aarch64", 0x22),
            cd("Sp1", "builder", "X86_64", 0x23),
            cd("Sp1", "builder", "Aarch64", 0x24),
            cd("Risc0", "base", "X86_64", 0x25),
            cd("Risc0", "base", "Aarch64", 0x26),
            cd("Risc0", "builder", "X86_64", 0x27),
            cd("Risc0", "builder", "Aarch64", 0x28),
        ]),
        // one in-container dependency lock per candidate.
        cargo_lock_hashes: Some(vec![lock("Sp1", 0x33), lock("Risc0", 0x34)]),
        // one verifier-material manifest per candidate; SP1's total is 292, RISC
        // Zero's is its own four-role Sum (352), so RISC Zero never carries 292.
        verifier_material_manifests: Some(vec![vmat_ref(&sp1_vmm), vmat_ref(&risc0_vmm)]),
    };
    p.finalization.state = "finalizable".into();
    p.finalization.blocked_on = Vec::new();
    p
}

fn ascii_of(tag: &[u8; 32]) -> String {
    let n = tags::ascii_len(tag);
    String::from_utf8_lossy(&tag[..n]).into_owned()
}

fn ascii_prefix(prefix: &[u8]) -> String {
    // strip the trailing terminator for display
    let body = &prefix[..prefix.len() - 1];
    String::from_utf8_lossy(body).into_owned()
}

fn frozen_domains() -> Domains {
    let structured: &[(&str, [u8; 32])] = &[
        ("OBJECT_TAG", tags::OBJECT_TAG),
        ("STATEMENT_TAG", tags::STATEMENT_TAG),
        ("ENVELOPE_TAG", tags::ENVELOPE_TAG),
        ("OUTPUT_MANIFEST_TAG", tags::OUTPUT_MANIFEST_TAG),
        ("INPUT_MANIFEST_TAG", tags::INPUT_MANIFEST_TAG),
        ("BENCH_SAMPLE_TAG", tags::BENCH_SAMPLE_TAG),
        ("BENCH_RSS_TAG", tags::BENCH_RSS_TAG),
        ("RESEARCH_CHAIN_TAG", tags::RESEARCH_CHAIN_TAG),
        ("DERIVED_INPUT_TAG", tags::DERIVED_INPUT_TAG),
        ("EXP_TABLE_TAG", tags::EXP_TABLE_TAG),
        ("EXP_CERT_TAG", tags::EXP_CERT_TAG),
        ("VERIFIER_MATERIAL_TAG", tags::VERIFIER_MATERIAL_TAG),
        ("CARGO_LOCK_TAG", tags::CARGO_LOCK_TAG),
        ("CONTAINER_TAG", tags::CONTAINER_TAG),
    ];
    let prefixes: &[(&str, &[u8])] = &[
        ("FIXTURE_PREFIX", tags::FIXTURE_PREFIX),
        ("ID_PREFIX", tags::ID_PREFIX),
        ("DATA_PREFIX", tags::DATA_PREFIX),
        ("SPEC_PREFIX", tags::SPEC_PREFIX),
        ("STMT_TEMPLATE_PREFIX", tags::STMT_TEMPLATE_PREFIX),
        ("GUESTSET_PREFIX", tags::GUESTSET_PREFIX),
        ("GUESTSRC_PREFIX", tags::GUESTSRC_PREFIX),
        ("BUILDCMD_PREFIX", tags::BUILDCMD_PREFIX),
        ("ARCHPROV_PREFIX", tags::ARCHPROV_PREFIX),
        ("RESULTSET_PREFIX", tags::RESULTSET_PREFIX),
        ("HARNESS_PREFIX", tags::HARNESS_PREFIX),
        ("ENVCAP_PREFIX", tags::ENVCAP_PREFIX),
        ("SAMPLEBUNDLE_PREFIX", tags::SAMPLEBUNDLE_PREFIX),
        ("RSSBUNDLE_PREFIX", tags::RSSBUNDLE_PREFIX),
    ];
    Domains {
        structured_tags: structured
            .iter()
            .map(|(name, tag)| StructuredTag {
                name: (*name).into(),
                ascii: ascii_of(tag),
                bytes_hex: hex(tag),
            })
            .collect(),
        hash_prefixes: prefixes
            .iter()
            .map(|(name, p)| HashPrefix {
                name: (*name).into(),
                ascii: ascii_prefix(p),
                terminator_hex: format!("{:02x}", p[p.len() - 1]),
                bytes_hex: hex(p),
            })
            .collect(),
    }
}

fn frozen_versions() -> Vec<NamedU64> {
    vec![
        ("schema_version", consts::SCHEMA_VERSION as u64),
        ("algorithm_version", consts::ALGORITHM_VERSION as u64),
        ("softmax_variant_id", consts::SOFTMAX_VARIANT_ID as u64),
        (
            "token_input_scheme_id",
            consts::TOKEN_INPUT_SCHEME_ID as u64,
        ),
        ("fixed_point_version", consts::FIXED_POINT_VERSION as u64),
        (
            "fixed_point_scale_log2",
            consts::FIXED_POINT_SCALE_LOG2 as u64,
        ),
        ("workload_arch_id", consts::WORKLOAD_ARCH_ID as u64),
        (
            "weight_schedule_version",
            consts::WEIGHT_SCHEDULE_VERSION as u64,
        ),
        (
            "output_manifest_schema_version",
            consts::OUTPUT_MANIFEST_SCHEMA_VERSION as u64,
        ),
    ]
    .into_iter()
    .map(|(name, value)| NamedU64 {
        name: name.into(),
        value,
    })
    .collect()
}

fn frozen_enums() -> Vec<EnumSpec> {
    fn spec(
        name: &str,
        bits: u32,
        catalog: &[(&'static str, u64)],
        reserved: &[(&'static str, u64)],
    ) -> EnumSpec {
        EnumSpec {
            name: name.into(),
            repr_bits: bits,
            variants: catalog
                .iter()
                .map(|(n, v)| NamedU64 {
                    name: (*n).into(),
                    value: *v,
                })
                .collect(),
            reserved: reserved
                .iter()
                .map(|(n, v)| NamedU64 {
                    name: (*n).into(),
                    value: *v,
                })
                .collect(),
        }
    }
    vec![
        spec(
            "ObjectKind",
            ObjectKind::REPR_BITS,
            ObjectKind::CATALOG,
            ObjectKind::RESERVED,
        ),
        spec(
            "SlotKind",
            SlotKind::REPR_BITS,
            SlotKind::CATALOG,
            SlotKind::RESERVED,
        ),
        spec(
            "InputSlotKind",
            InputSlotKind::REPR_BITS,
            InputSlotKind::CATALOG,
            InputSlotKind::RESERVED,
        ),
        spec(
            "Candidate",
            Candidate::REPR_BITS,
            Candidate::CATALOG,
            Candidate::RESERVED,
        ),
        spec(
            "UnitKind",
            UnitKind::REPR_BITS,
            UnitKind::CATALOG,
            UnitKind::RESERVED,
        ),
        spec(
            "ProofRefKind",
            ProofRefKind::REPR_BITS,
            ProofRefKind::CATALOG,
            ProofRefKind::RESERVED,
        ),
        spec(
            "MetricKind",
            MetricKind::REPR_BITS,
            MetricKind::CATALOG,
            MetricKind::RESERVED,
        ),
        spec("Unit", Unit::REPR_BITS, Unit::CATALOG, Unit::RESERVED),
        spec(
            "RssScope",
            RssScope::REPR_BITS,
            RssScope::CATALOG,
            RssScope::RESERVED,
        ),
        spec(
            "SampleKind",
            SampleKind::REPR_BITS,
            SampleKind::CATALOG,
            SampleKind::RESERVED,
        ),
        spec(
            "Status",
            Status::REPR_BITS,
            Status::CATALOG,
            Status::RESERVED,
        ),
        spec("Arch", Arch::REPR_BITS, Arch::CATALOG, Arch::RESERVED),
        spec(
            "ProvenanceRole",
            ProvenanceRole::REPR_BITS,
            ProvenanceRole::CATALOG,
            ProvenanceRole::RESERVED,
        ),
        spec(
            "VerifierMaterialRole",
            VerifierMaterialRole::REPR_BITS,
            VerifierMaterialRole::CATALOG,
            VerifierMaterialRole::RESERVED,
        ),
        spec(
            "StatementIndex",
            StatementIndex::REPR_BITS,
            StatementIndex::CATALOG,
            StatementIndex::RESERVED,
        ),
    ]
}

fn frozen_bounds() -> Bounds {
    Bounds {
        official: vec![
            ("max_d_model", consts::MAX_D_MODEL as u64),
            ("max_seq_len", consts::MAX_SEQ_LEN as u64),
            ("max_output_tokens", consts::MAX_OUTPUT_TOKENS as u64),
            ("max_manifest_slots", consts::MAX_MANIFEST_SLOTS as u64),
            ("max_state_bytes", consts::MAX_STATE_BYTES),
            ("max_cycles", consts::MAX_CYCLES),
        ]
        .into_iter()
        .map(|(name, value)| NamedU64 {
            name: name.into(),
            value,
        })
        .collect(),
        decoder_maxima: vec![
            (
                "output_manifest_max_slots",
                consts::OUTPUT_MANIFEST_MAX_SLOTS as u64,
            ),
            (
                "input_manifest_max_slots",
                consts::INPUT_MANIFEST_MAX_SLOTS as u64,
            ),
        ]
        .into_iter()
        .map(|(name, value)| NamedU64 {
            name: name.into(),
            value,
        })
        .collect(),
    }
}

fn frozen_layouts() -> Vec<SchemaLayout> {
    let l = |name: &str, bytes: u64, note: &str| SchemaLayout {
        name: name.into(),
        encoded_bytes: bytes,
        note: note.into(),
    };
    vec![
        l(
            "ObjectCommitmentV1",
            80,
            "tag || kind || byte_len || chunk_count || merkle_root",
        ),
        l(
            "DerivedInputV1",
            350,
            "ids, model_id, commitment identities, position, sequence_length",
        ),
        l(
            "InputManifestV1(empty)",
            38,
            "tag || schema_version || count",
        ),
        l("InputManifestV1(3 slots)", 293, "38 + 3 x 85"),
        l("OutputManifestV1(2 slots)", 208, "38 + 2 x 85"),
        l(
            "R0ComputationStatementV2",
            996,
            "full public statement; template zeroes b0_pre_spec_hash",
        ),
        l(
            "GuestProgramAllowlistV1(empty)",
            6,
            "schema_version(2) + count(4); only the EMPTY allowlist schema + hashing rule is in the \
             spec hash. A populated allowlist (228 header + 33 bytes/entry) is post-spec.",
        ),
        l(
            "R0ProofArtifactEnvelopeV1",
            3503,
            "proof envelope with embedded artifact bytes",
        ),
        l(
            "BenchmarkSampleV1",
            309,
            "domain || identities || metric || value",
        ),
    ]
}

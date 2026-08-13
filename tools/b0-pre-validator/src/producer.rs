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

use serde::Deserialize;

use crate::enums::{Arch, Candidate, ProvenanceRole, StatementIndex, VerifierMaterialRole};
use crate::measurement::{
    official_allowlist, orchestrate_grid, r0_guest_set_hash, serialize_vector, CellFacts,
    GuestBuild, ProvenanceFacts, RunIdentities,
};
use crate::schema::allowlist::BuilderArch;
use crate::schema::provenance::{DvfsProvenance, HypervisorUnobservableDvfs};
use crate::schema::verifier_material::VerifierMaterialManifestV1;

/// The merged, finalized `b0_pre_spec_hash`. Measurement mode binds to EXACTLY this.
pub const MERGED_SPEC_HASH_HEX: &str =
    "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";

// ---------------------------------------------------------------------------
// Raw-facts contract: what the venue runner writes. NO bundle hash, NO aggregate,
// NO derived guest-set/spec identity beyond the declared spec hash it must match.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RawFacts {
    pub lifecycle_mode: String,
    pub b0_pre_spec_hash: String,
    pub candidates: Vec<CandidateFacts>,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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

/// JSON twin of the host-provenance DVFS state (matches `b0-pre-host-provenance`'s `DvfsState`).
/// Deserialized from the runner's facts; converted to the sealed [`DvfsProvenance`] schema type.
#[derive(Deserialize, Clone)]
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
            rss_context_hash: hex32(&c.rss_context_hash, "rss_context_hash")?,
            malformed_corpus_result_hash: hex32(
                &c.malformed_corpus_result_hash,
                "malformed_corpus_result_hash",
            )?,
        };

        let mut provenances = Vec::new();
        for p in &c.provenance {
            provenances.push(prov_facts(p)?);
        }
        let mut cells = Vec::new();
        for cell in &c.cells {
            cells.push(cell_facts(cell)?);
        }

        // orchestrate_grid itself refuses a native-ineligible (RISC0/aarch64) cell.
        let ev = orchestrate_grid(spec, guest_set, &ids, &provenances, &cells)?;
        // The frozen verifier INDEPENDENTLY re-derives the verdict.
        let verdict = match crate::harness::verify_evidence(&ev) {
            Ok(r) if r.qualification => CandidateVerdict::Qualified,
            Ok(r) => CandidateVerdict::DisqualifiedByGate(r.failure_codes),
            Err(e) => CandidateVerdict::IncompleteNativeMatrix(e),
        };
        verdicts.push((cand, verdict));
        bundles.push((cand, ev));
    }

    let vector = serialize_vector(&allowlist.encode(), &bundles);
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

fn prov_facts(p: &ProvFacts) -> Result<ProvenanceFacts, String> {
    Ok(ProvenanceFacts {
        arch: parse_arch(&p.arch)?,
        role: parse_role(&p.role)?,
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
    })
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
    let prov = |arch: &str, role: &str| -> ProvFacts {
        let (cpuset, mem, phys, log, ram) = if role == "Proving" {
            (5u32, 22u64 << 30, 16u32, 32u32, 64u64 << 30)
        } else {
            (2, 4u64 << 30, 2, 4, 4u64 << 30)
        };
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
    let provset = |arches: &[&str]| -> Vec<ProvFacts> {
        let mut v = Vec::new();
        for a in arches {
            for r in ["Proving", "Verification"] {
                v.push(prov(a, r));
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
    let sp1 = CandidateFacts {
        candidate: "Sp1".into(),
        container_image_digest: dv("sp1-container"),
        statement_hash_tlg: dv("stmt-tlg"),
        statement_hash_st: dv("stmt-st"),
        rss_context_hash: dv("rss-ctx"),
        malformed_corpus_result_hash: dv("malformed"),
        guest: guest("sp1", &["x86_64", "aarch64"]),
        verifier_material: vec![VmEntryFacts {
            role: "Groth16Vk".into(),
            byte_len: 292,
            hash: dv("sp1-vk"),
        }],
        provenance: provset(&["x86_64", "aarch64"]),
        cells: grid("sp1", &["x86_64", "aarch64"]),
    };
    let risc0 = CandidateFacts {
        candidate: "Risc0".into(),
        container_image_digest: dv("r0-container"),
        statement_hash_tlg: dv("stmt-tlg"),
        statement_hash_st: dv("stmt-st"),
        rss_context_hash: dv("rss-ctx"),
        malformed_corpus_result_hash: dv("malformed"),
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
        provenance: provset(&["x86_64"]),
        cells: grid("r0", &["x86_64"]),
    };
    RawFacts {
        lifecycle_mode: "measurement".into(),
        b0_pre_spec_hash: MERGED_SPEC_HASH_HEX.into(),
        candidates: vec![sp1, risc0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::verify_evidence;
    use crate::measurement::parse_vector;

    #[test]
    fn dry_run_produces_and_verifies_both_verdicts() {
        let pkg = produce(&dry_run_raw_facts()).expect("produces");
        // SP1 qualifies; RISC0's x86-only matrix is an incomplete native matrix.
        assert_eq!(
            pkg.verdicts[0],
            (Candidate::Sp1, CandidateVerdict::Qualified)
        );
        assert!(matches!(
            pkg.verdicts[1].1,
            CandidateVerdict::IncompleteNativeMatrix(_)
        ));
        // The package vector is accepted by the frozen verifier for SP1 and rejected
        // (as MeasuredProofGrid) for RISC0.
        let (_al, bundles) = parse_vector(&pkg.vector).unwrap();
        for (c, ev) in &bundles {
            match c {
                Candidate::Sp1 => assert!(verify_evidence(ev).unwrap().qualification),
                Candidate::Risc0 => {
                    let e = verify_evidence(ev).unwrap_err();
                    assert!(
                        e.contains("MeasuredProofGrid") || e.contains("completeness"),
                        "{e}"
                    );
                }
            }
        }
        // inventory names both verdicts + the content address.
        let inv = pkg.inventory();
        assert_eq!(inv["package_id"], hx(&pkg.package_id));
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

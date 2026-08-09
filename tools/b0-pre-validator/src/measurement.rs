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
use crate::schema::envelope::{ArtifactHash, R0ProofArtifactEnvelopeV1};
use crate::schema::provenance::ArchRunProvenanceV1;
use crate::schema::verifier_material::VerifierMaterialManifestV1;

/// The allowlist canonical bytes plus one per-candidate evidence bundle each — the
/// content of a committed measurement vector.
pub type MeasurementVector = (Vec<u8>, Vec<(Candidate, Evidence)>);

/// Whether `candidate` can produce a NATIVE terminal proof on `arch`. RISC Zero's
/// Groth16 receipt path is x86_64-only (VENUE §2); on aarch64 it is native-ineligible
/// — never emulated, never synthesized. SP1 is native on both arches.
pub fn native_eligible(candidate: Candidate, arch: Arch) -> bool {
    !matches!((candidate, arch), (Candidate::Risc0, Arch::Aarch64))
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
    pub governor: String,
    pub turbo_enabled: bool,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
    pub benchmark_harness_source_hash: [u8; 32],
    pub raw_environment_capture_hash: [u8; 32],
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
    pub rss_context_hash: [u8; 32],
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
) -> Result<Evidence, String> {
    let vmat = ids
        .verifier_material
        .identity()
        .map_err(|e| format!("verifier-material identity: {e}"))?;

    // Build provenance records (inject derived hashes); index proving hashes per arch.
    let mut built_prov = Vec::with_capacity(provenances.len());
    let mut proving_prov: HashMap<u8, [u8; 32]> = HashMap::new();
    for pf in provenances {
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
            governor: pf.governor.clone(),
            turbo_enabled: pf.turbo_enabled,
            clock_source: pf.clock_source.clone(),
            cgroup_version: pf.cgroup_version,
            cgroup_scope_label: pf.cgroup_scope_label.clone(),
            benchmark_harness_source_hash: pf.benchmark_harness_source_hash,
            raw_environment_capture_hash: pf.raw_environment_capture_hash,
        };
        if pf.role == ProvenanceRole::Proving {
            proving_prov.insert(pf.arch.to_repr(), p.provenance_hash());
        }
        built_prov.push(p);
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
            computation_statement_hash: ids.rss_context_hash,
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
        envelopes,
        samples,
        rss,
        malformed_corpus_result_hash: ids.malformed_corpus_result_hash,
    })
}

/// Compact length-prefixed transport for a committed real-orchestrator vector: the
/// canonical guest-allowlist bytes plus one per-candidate evidence bundle each.
/// This is an envelope only — it carries NO bundle hash or aggregate; both the
/// reference and the independent verifier recompute everything from the records
/// inside. Format: magic `B0PREMEASVEC1`, then `u32 len‖bytes` for the allowlist,
/// then `u32 n_bundles`, then per bundle: `u16 candidate`, four record lists (each
/// `u32 count` then `u32 len‖bytes`), then `u32 len‖bytes` for verifier_material and
/// result_set. All integers big-endian.
pub fn serialize_vector(allowlist_canonical: &[u8], bundles: &[(Candidate, Evidence)]) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"B0PREMEASVEC1");
    put(&mut out, allowlist_canonical);
    out.extend_from_slice(&(bundles.len() as u32).to_be_bytes());
    for (c, ev) in bundles {
        out.extend_from_slice(&c.to_repr().to_be_bytes());
        for list in [&ev.samples, &ev.rss, &ev.envelopes, &ev.provenances] {
            out.extend_from_slice(&(list.len() as u32).to_be_bytes());
            for r in list {
                put(&mut out, r);
            }
        }
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
    if take(&mut p, 13)? != b"B0PREMEASVEC1" {
        return Err("bad magic".into());
    }
    let allowlist = blob(&mut p)?;
    let n_bundles = u32_at(&mut p)?;
    let mut bundles = Vec::new();
    for _ in 0..n_bundles {
        let cb = take(&mut p, 2)?;
        let candidate = Candidate::from_repr(u16::from_be_bytes([cb[0], cb[1]]))
            .map_err(|_| "bad candidate".to_string())?;
        let mut lists: Vec<Vec<Vec<u8>>> = Vec::with_capacity(4);
        for _ in 0..4 {
            let count = u32_at(&mut p)?;
            let mut v = Vec::with_capacity(count);
            for _ in 0..count {
                v.push(blob(&mut p)?);
            }
            lists.push(v);
        }
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
                verifier_material,
                result_set,
            },
        ));
    }
    if p != bytes.len() {
        return Err("trailing bytes".into());
    }
    Ok((allowlist, bundles))
}

/// Build the ONE canonical committed measurement vector deterministically through
/// the real orchestrator: SP1's complete native matrix (both arches → qualifies) and
/// RISC Zero's genuine x86_64-only matrix (aarch64 absent → the frozen verifier
/// derives `MeasuredProofGrid`). Bound to the merged `b0_pre_spec_hash`. Returns the
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
    let spec = hex32("201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3");

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

    let prov = |arch: Arch, role: ProvenanceRole| -> ProvenanceFacts {
        let (cpuset, mem, phys, logical, ram) = match role {
            ProvenanceRole::Proving => (5u32, 22u64 << 30, 16u32, 32u32, 64u64 << 30),
            ProvenanceRole::Verification => (2u32, 4u64 << 30, 2u32, 4u32, 4u64 << 30),
        };
        ProvenanceFacts {
            arch,
            role,
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
            governor: "performance".into(),
            turbo_enabled: false,
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "b0-pre.slice".into(),
            benchmark_harness_source_hash: dv(b"runner"),
            raw_environment_capture_hash: dv(b"envcap"),
        }
    };
    let mut all_prov = Vec::new();
    for a in [Arch::X86_64, Arch::Aarch64] {
        for r in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
            all_prov.push(prov(a, r));
        }
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
        rss_context_hash: dv(b"rss-ctx"),
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
        rss_context_hash: dv(b"rss-ctx"),
        malformed_corpus_result_hash: dv(b"malformed"),
    };

    let sp1_ev = orchestrate_grid(
        spec,
        guest_set,
        &sp1_ids,
        &all_prov,
        &grid("sp1", &[Arch::X86_64, Arch::Aarch64]),
    )
    .expect("sp1 assembles");
    let risc0_ev = orchestrate_grid(
        spec,
        guest_set,
        &risc0_ids,
        &all_prov,
        &grid("risc0", &[Arch::X86_64]),
    )
    .expect("risc0 assembles");

    (
        allowlist.encode(),
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
            rss_context_hash: h(b"rss-ctx"),
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
            governor: "performance".into(),
            turbo_enabled: false,
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "b0-pre.slice".into(),
            benchmark_harness_source_hash: h(b"harness"),
            raw_environment_capture_hash: h(b"envcap"),
        }
    }

    fn all_provenance() -> Vec<ProvenanceFacts> {
        let mut v = Vec::new();
        for a in [Arch::X86_64, Arch::Aarch64] {
            for r in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
                v.push(prov_facts(a, r));
            }
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
        let ev = orchestrate_grid(
            SPEC,
            gs,
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64, Arch::Aarch64]),
        )
        .expect("assembles");
        // The frozen verifier INDEPENDENTLY re-derives every bundle + aggregate.
        let r = verify_evidence(&ev).expect("verifies");
        assert!(r.qualification, "40ms p99 < 75ms gate qualifies");
        // Every record binds both hashes: spot-check the result set.
        let rs = R0ResultSetV1::decode_exact(&ev.result_set).unwrap();
        assert_eq!(rs.b0_pre_spec_hash, SPEC);
        assert_eq!(rs.r0_guest_set_hash, gs);
        assert_eq!(rs.completeness.measured_proof_count, 40);
    }

    #[test]
    fn risc0_native_matrix_is_x86_only() {
        assert_eq!(
            native_matrix(Candidate::Sp1),
            vec![Arch::X86_64, Arch::Aarch64]
        );
        assert_eq!(native_matrix(Candidate::Risc0), vec![Arch::X86_64]);
        assert!(!native_eligible(Candidate::Risc0, Arch::Aarch64));
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
        assert!(
            orchestrate_grid(SPEC, h(b"gs"), &r0, &all_provenance(), &cells)
                .unwrap_err()
                .contains("native-ineligible")
        );
    }

    #[test]
    fn risc0_x86_only_grid_is_a_genuine_incomplete_matrix_rejected_as_grid() {
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
        // Only x86 cells exist — the native matrix is genuinely incomplete. Assembly
        // succeeds (nothing fabricated); the FROZEN verifier derives the failure.
        let ev = orchestrate_grid(
            SPEC,
            h(b"gs"),
            &r0,
            &all_provenance(),
            &grid(&[Arch::X86_64]),
        )
        .expect("assembles the genuine partial matrix");
        let err = verify_evidence(&ev).expect_err("incomplete grid must be rejected");
        assert!(
            err.contains("completeness") || err.contains("MeasuredProofGrid"),
            "got: {err}"
        );
    }

    #[test]
    fn duplicate_cell_is_rejected() {
        let mut cells = grid(&[Arch::X86_64, Arch::Aarch64]);
        // Duplicate the first cell (same arch/stmt/iteration) -> not a valid grid.
        cells.push(cell(Arch::X86_64, StatementIndex::Tlg, 0));
        let res = orchestrate_grid(SPEC, h(b"gs"), &ids(), &all_provenance(), &cells);
        // Either assembly (duplicate measured-proof key) or verification rejects it.
        let rejected = match res {
            Err(_) => true,
            Ok(ev) => verify_evidence(&ev).is_err(),
        };
        assert!(rejected, "a duplicated cell must be rejected");
    }

    #[test]
    fn missing_cell_is_rejected() {
        let mut cells = grid(&[Arch::X86_64, Arch::Aarch64]);
        cells.pop(); // drop one cell -> incomplete grid
        let ev = orchestrate_grid(SPEC, h(b"gs"), &ids(), &all_provenance(), &cells).unwrap();
        assert!(
            verify_evidence(&ev).is_err(),
            "a missing cell must be rejected"
        );
    }

    #[test]
    fn post_result_threshold_mutation_is_rejected() {
        let ev = orchestrate_grid(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64, Arch::Aarch64]),
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
        let mut ev = orchestrate_grid(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64, Arch::Aarch64]),
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
        let ev = orchestrate_grid(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64, Arch::Aarch64]),
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
        let mut cells = grid(&[Arch::X86_64, Arch::Aarch64]);
        cells[0].verify_ns.pop();
        let ev = orchestrate_grid(SPEC, h(b"gs"), &ids(), &all_provenance(), &cells).unwrap();
        assert!(
            verify_evidence(&ev).is_err(),
            "a short verification-sample count must be rejected"
        );
    }

    #[test]
    fn missing_rss_record_is_rejected() {
        let mut ev = orchestrate_grid(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64, Arch::Aarch64]),
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
        let ev = orchestrate_grid(
            SPEC,
            h(b"gs"),
            &ids(),
            &all_provenance(),
            &grid(&[Arch::X86_64, Arch::Aarch64]),
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
                p.turbo_enabled = true;
            }
        }
        let ev = orchestrate_grid(
            SPEC,
            h(b"gs"),
            &ids(),
            &prov,
            &grid(&[Arch::X86_64, Arch::Aarch64]),
        )
        .unwrap();
        assert!(
            verify_evidence(&ev).is_err(),
            "an ineligible/emulated provenance must be rejected"
        );
    }
}

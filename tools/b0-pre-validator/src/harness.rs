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
use crate::schema::envelope::R0ProofArtifactEnvelopeV1;
use crate::schema::provenance::ArchRunProvenanceV1;
use crate::schema::result_set::{
    Aggregates, ArchProvenanceRef, Completeness, MeasuredProofRef, R0ResultSetV1, RssBundle,
    SampleBundle,
};
use crate::schema::verifier_material::{VerifierMaterialEntry, VerifierMaterialManifestV1};
use crate::tags::{RSSBUNDLE_PREFIX, SAMPLEBUNDLE_PREFIX};
use crate::validation::nearest_rank_p99;

pub const NON_SELECTION_LABEL: &str = "NON_SELECTION / TEST_ONLY";
pub const SEED: [u8; 32] = [0x5A; 32];
pub const P99_GATE_NS: u64 = 75_000_000;
pub const VERIFIER_MATERIAL_BYTES: u64 = 292;
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
            phys: 4,
            logical: 8,
            ram: 8u64 << 30,
            cpuset: 4,
            mem: 8u64 << 30,
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
    VerifierMaterialManifestV1 {
        candidate: ids.candidate,
        entries: vec![VerifierMaterialEntry {
            label: "GROTH16_VK_BYTES".to_string(),
            role: VerifierMaterialRole::Groth16Vk,
            byte_len: VERIFIER_MATERIAL_BYTES,
            hash: ids.vk,
        }],
    }
}
/// SP1 verifier material (public no-arg API preserved).
pub fn verifier_material() -> VerifierMaterialManifestV1 {
    verifier_material_for(ids_for(Candidate::Sp1))
}
fn vmat_id(ids: Ids) -> [u8; 32] {
    verifier_material_for(ids).identity()
}

fn provenance(a: Arch, role: ProvenanceRole, ids: Ids, env: &Env) -> ArchRunProvenanceV1 {
    let r = match role {
        ProvenanceRole::Proving => env.proving,
        ProvenanceRole::Verification => env.verification,
    };
    ArchRunProvenanceV1 {
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
        governor: env.governor.clone(),
        turbo_enabled: env.turbo,
        clock_source: env.clock_source.clone(),
        cgroup_version: env.cgroup_version,
        cgroup_scope_label: env.cgroup_scope_label.clone(),
        benchmark_harness_source_hash: env.harness_hash,
        raw_environment_capture_hash: env.envcap_hash,
    }
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

fn bundle_hash(prefix: &[u8], mut recs: Vec<RawRec>) -> ([u8; 32], u32) {
    recs.sort_by_key(|r| r.0);
    let mut h = blake3::Hasher::new();
    h.update(prefix);
    for (_, b) in &recs {
        h.update(b);
    }
    (h.finalize().into(), recs.len() as u32)
}

pub struct Evidence {
    pub samples: Vec<Vec<u8>>,
    pub rss: Vec<Vec<u8>>,
    pub envelopes: Vec<Vec<u8>>,
    pub provenances: Vec<Vec<u8>>,
    pub verifier_material: Vec<u8>,
    pub result_set: Vec<u8>,
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
    let mut samples = Vec::new();
    let mut rss_records = Vec::new();
    let mut envelopes = Vec::new();
    let mut provenances = Vec::new();

    let mut proving_prov: HashMap<u8, [u8; 32]> = HashMap::new();
    let mut arch_provenance = Vec::new();
    for a in ARCHES {
        for role in [ProvenanceRole::Proving, ProvenanceRole::Verification] {
            let p = provenance(a, role, ids, env);
            let h = p.provenance_hash();
            if role == ProvenanceRole::Proving {
                proving_prov.insert(a.to_repr(), h);
            }
            arch_provenance.push(ArchProvenanceRef {
                arch: a,
                role,
                provenance_hash: h,
            });
            provenances.push(p.encode());
        }
    }

    let mut measured_proofs = Vec::new();
    // (arch, stmt, metric) -> raw records
    let mut sbundle: HashMap<(u8, u8, u8), Vec<RawRec>> = HashMap::new();
    let mut prss: HashMap<u8, Vec<RawRec>> = HashMap::new();
    let mut vrss: HashMap<u8, Vec<RawRec>> = HashMap::new();
    let mut verify_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut vrss_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut max_pb = 0u64;

    for a in ARCHES {
        for s in STMTS {
            for iter in 0..crate::consts::OFFICIAL_ITERATIONS_PER_CELL {
                let ph = proof_hash(a, s, iter);
                let eb = envelope(a, s, iter, proving_prov[&a.to_repr()], ids).encode();
                measured_proofs.push(MeasuredProofRef {
                    arch: a,
                    statement_index: s,
                    iteration_index: iter,
                    envelope_hash: crate::hashing::plain(&eb),
                });
                envelopes.push(eb);
                for rep in 0..REPS {
                    let v = verify_value(a, s, iter, rep);
                    let b = sample(
                        a,
                        s,
                        MetricKind::HostVerifyNs,
                        Unit::Nanoseconds,
                        v,
                        rep,
                        ph,
                        ids,
                    )
                    .encode();
                    sbundle
                        .entry((a.to_repr(), s.to_repr(), 5))
                        .or_default()
                        .push(((ph, rep), b.clone()));
                    verify_by_arch.entry(a.to_repr()).or_default().push(v);
                    samples.push(b);
                }
                let push = |sbundle: &mut HashMap<(u8, u8, u8), Vec<RawRec>>,
                            samples: &mut Vec<Vec<u8>>,
                            m: MetricKind,
                            u: Unit,
                            v: u64| {
                    let b = sample(a, s, m, u, v, iter, ph, ids).encode();
                    sbundle
                        .entry((a.to_repr(), s.to_repr(), m.to_repr()))
                        .or_default()
                        .push(((ph, iter), b.clone()));
                    samples.push(b);
                };
                push(
                    &mut sbundle,
                    &mut samples,
                    MetricKind::HostProveWrapNs,
                    Unit::Nanoseconds,
                    prove_value(a, s, iter),
                );
                push(
                    &mut sbundle,
                    &mut samples,
                    MetricKind::HostSetupNs,
                    Unit::Nanoseconds,
                    setup_value(iter),
                );
                let pbv = proof_bytes_value(iter);
                max_pb = max_pb.max(pbv);
                push(
                    &mut sbundle,
                    &mut samples,
                    MetricKind::ProofBytes,
                    Unit::Bytes,
                    pbv,
                );

                let prb = rss(
                    a,
                    RssScope::ProvingRun,
                    proving_rss_value(iter),
                    iter,
                    ph,
                    ids,
                )
                .encode();
                prss.entry(a.to_repr())
                    .or_default()
                    .push(((ph, iter), prb.clone()));
                rss_records.push(prb);
                let vrv = verify_rss_value(a, iter);
                vrss_by_arch.entry(a.to_repr()).or_default().push(vrv);
                let vrb = rss(a, RssScope::VerifyBatch, vrv, iter, ph, ids).encode();
                vrss.entry(a.to_repr())
                    .or_default()
                    .push(((ph, iter), vrb.clone()));
                rss_records.push(vrb);
            }
        }
    }

    let mut sample_bundles = Vec::new();
    for a in ARCHES {
        for s in STMTS {
            for m in BUNDLE_METRICS {
                let recs = sbundle[&(a.to_repr(), s.to_repr(), m.to_repr())].clone();
                let (h, c) = bundle_hash(SAMPLEBUNDLE_PREFIX, recs);
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
    let mut rss_bundles = Vec::new();
    for a in ARCHES {
        for (scope, coll) in [
            (RssScope::ProvingRun, &prss),
            (RssScope::VerifyBatch, &vrss),
        ] {
            let (h, c) = bundle_hash(RSSBUNDLE_PREFIX, coll[&a.to_repr()].clone());
            rss_bundles.push(RssBundle {
                arch: a,
                rss_scope: scope,
                record_count: c,
                bundle_hash: h,
            });
        }
    }

    let worst_p99 = ARCHES
        .iter()
        .map(|a| {
            let mut v = verify_by_arch[&a.to_repr()].clone();
            v.sort_unstable();
            nearest_rank_p99(&v).unwrap()
        })
        .max()
        .unwrap();
    let worst_vrss = ARCHES
        .iter()
        .map(|a| *vrss_by_arch[&a.to_repr()].iter().max().unwrap())
        .max()
        .unwrap();
    let qualification = worst_p99 <= P99_GATE_NS;
    let failure_codes: Vec<u16> = if qualification { vec![] } else { vec![3] };

    let rs = R0ResultSetV1 {
        b0_pre_spec_hash: spec_hash(),
        r0_guest_set_hash: guest_set_hash(),
        candidate: ids.candidate,
        verifier_material_manifest_hash: vmat_id(ids),
        official_statement_hash_tlg: stmt_hash(StatementIndex::Tlg),
        official_statement_hash_st: stmt_hash(StatementIndex::SelectToken),
        arch_provenance,
        measured_proofs,
        sample_bundles,
        rss_bundles,
        malformed_corpus_result_hash: id(b"malformed"),
        cycle_bundle: None,
        completeness: Completeness {
            measured_proof_count: 40,
            verify_timing_sample_count: 4000,
            proving_time_sample_count: 40,
            proving_run_rss_count: 40,
            verify_batch_rss_count: 40,
        },
        aggregates: Aggregates {
            max_proof_bytes: max_pb as u32,
            worst_arch_p99_verify_ns: worst_p99,
            verifier_material_bytes: VERIFIER_MATERIAL_BYTES,
            worst_arch_verifier_rss_bytes: worst_vrss,
        },
        qualification_result: qualification,
        failure_codes,
    };

    Evidence {
        samples,
        rss: rss_records,
        envelopes,
        provenances,
        verifier_material: verifier_material_for(ids).encode(),
        result_set: rs.encode(),
    }
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
    if vmm.identity() != vm {
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
    let qualification = worst_p99 <= P99_GATE_NS;
    let failure_codes: Vec<u16> = if qualification { vec![] } else { vec![3] };

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

    #[test]
    fn generated_evidence_verifies() {
        let ev = generate();
        assert_eq!(ev.envelopes.len(), 40);
        assert_eq!(ev.samples.len(), 4000 + 40 + 40 + 40); // + host_setup_ns
        assert_eq!(ev.rss.len(), 80);
        assert_eq!(ev.provenances.len(), 4);
        let r = verify_evidence(&ev).expect("valid");
        assert!(r.qualification);
        assert_eq!(r.verifier_material_bytes, 292);
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
                        rs.verifier_material_manifest_hash = m.identity()
                    });
                    let mut m2 = verifier_material();
                    m2.entries[0].byte_len = 293;
                    e.verifier_material = m2.encode();
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
                    .encode();
                    e
                }),
            ),
            (
                "vmat_wrong_candidate",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let mut m = verifier_material();
                    m.candidate = Candidate::Risc0;
                    e.verifier_material = m.encode();
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

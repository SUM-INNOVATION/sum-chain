//! Independent R0 evidence harness (NON_SELECTION / TEST_ONLY).
//!
//! From-scratch mirror of the reference harness: its own encoders build the full
//! canonical evidence grid (incl. `host_setup_ns` and the verifier-material
//! manifest record) from the same seed, and its own verifier recomputes every
//! bundle hash, the verifier-material total (from the canonical manifest), and
//! every aggregate from the raw bytes, enforcing the full binding matrix. Shares
//! no encoder/verifier/mutation code with the reference; agreement is proven via
//! the compact seed fixture. Timings are synthetic test data, not selection
//! evidence.

use std::collections::{HashMap, HashSet};

use crate::closure::{self, nearest_rank_p99};
use crate::tags;

pub const NON_SELECTION_LABEL: &str = "NON_SELECTION / TEST_ONLY";
pub const SEED: [u8; 32] = [0x5A; 32];
pub const P99_GATE_NS: u64 = 75_000_000;
pub const VERIFIER_MATERIAL_BYTES: u64 = 292;
const REPS: u32 = 100;
const ITERS: u32 = 10;
const ARCHES: [u8; 2] = [1, 2];
const STMTS: [u8; 2] = [0, 1];
const BUNDLE_METRICS: [u8; 4] = [4, 5, 6, 7]; // prove, verify, setup, proof_bytes

fn id(label: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&SEED);
    h.update(label);
    h.finalize().into()
}
fn stmt_hash(s: u8) -> [u8; 32] {
    if s == 0 {
        id(b"stmt_tlg")
    } else {
        id(b"stmt_st")
    }
}
fn proof_hash(a: u8, s: u8, iter: u32) -> [u8; 32] {
    let mut l = b"proof".to_vec();
    l.push(a);
    l.push(s);
    l.push(iter as u8);
    id(&l)
}
fn push_str(b: &mut Vec<u8>, s: &[u8]) {
    b.extend_from_slice(&(s.len() as u16).to_le_bytes());
    b.extend_from_slice(s);
}

fn enc_vmat_with(byte_len: u64, candidate: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::VERIFIER_MATERIAL);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&candidate.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    let label = b"GROTH16_VK_BYTES";
    b.extend_from_slice(&(label.len() as u16).to_le_bytes());
    b.extend_from_slice(label);
    b.push(0);
    b.extend_from_slice(&byte_len.to_le_bytes());
    b.extend_from_slice(&id(b"vk"));
    b
}
fn enc_vmat() -> Vec<u8> {
    enc_vmat_with(VERIFIER_MATERIAL_BYTES, 1)
}
fn vmat_id() -> [u8; 32] {
    crate::plain(&enc_vmat())
}

fn enc_prov(arch: u8, role: u8) -> Vec<u8> {
    let (cpuset, mem, phys, ram) = if role == 0 {
        (5u32, 22u64 << 30, 16u32, 64u64 << 30)
    } else {
        (4u32, 8u64 << 30, 4u32, 8u64 << 30)
    };
    let mut b = Vec::new();
    b.extend_from_slice(&1u16.to_le_bytes());
    b.push(role);
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"program"));
    b.extend_from_slice(&id(b"lock"));
    b.extend_from_slice(&vmat_id());
    b.push(arch);
    let sc = vec![b'0'; 40];
    b.push(sc.len() as u8);
    b.extend_from_slice(&sc);
    b.push(0);
    b.extend_from_slice(&id(b"builder"));
    push_str(&mut b, b"linux");
    push_str(&mut b, b"6.8.0");
    push_str(&mut b, b"GenuineIntel");
    push_str(&mut b, b"test");
    b.extend_from_slice(&phys.to_le_bytes());
    b.extend_from_slice(&(phys * 2).to_le_bytes());
    b.extend_from_slice(&ram.to_le_bytes());
    b.extend_from_slice(&cpuset.to_le_bytes());
    b.extend_from_slice(&mem.to_le_bytes());
    push_str(&mut b, b"performance");
    b.push(0);
    push_str(&mut b, b"tsc");
    b.push(2);
    push_str(&mut b, b"b0-pre.slice");
    b.extend_from_slice(&id(b"harness"));
    b.extend_from_slice(&id(b"envcap"));
    b
}
fn prov_h(arch: u8, role: u8) -> [u8; 32] {
    crate::prefixed(tags::ARCHPROV_PREFIX, &enc_prov(arch, role))
}

fn enc_env(arch: u8, stmt: u8, iter: u32, pprov: [u8; 32]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::ENVELOPE);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"lock"));
    b.extend_from_slice(&id(b"program"));
    b.extend_from_slice(&vmat_id());
    b.extend_from_slice(&stmt_hash(stmt));
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&pprov);
    b.push(arch);
    b.push(1);
    b.extend_from_slice(&iter.to_le_bytes());
    b.push(1);
    b.extend_from_slice(&proof_hash(arch, stmt, iter));
    b.extend_from_slice(&0u32.to_le_bytes());
    b
}

#[allow(clippy::too_many_arguments)]
fn enc_sample(
    arch: u8,
    stmt: u8,
    metric: u8,
    unit: u8,
    value: u64,
    iter: u32,
    ph: [u8; 32],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::BENCH_SAMPLE);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&stmt_hash(stmt));
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"program"));
    b.extend_from_slice(&vmat_id());
    b.extend_from_slice(&id(b"lock"));
    b.extend_from_slice(&id(b"container"));
    b.push(arch);
    b.push(1);
    b.push(metric);
    b.push(unit);
    b.extend_from_slice(&value.to_le_bytes());
    b.extend_from_slice(&ph);
    b.extend_from_slice(&iter.to_le_bytes());
    b.push(0);
    b
}

fn enc_rss(arch: u8, scope: u8, peak: u64, run: u32, ph: [u8; 32]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&tags::BENCH_RSS);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&id(b"rss-context"));
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"program"));
    b.extend_from_slice(&vmat_id());
    b.extend_from_slice(&id(b"lock"));
    b.extend_from_slice(&id(b"container"));
    b.push(arch);
    b.push(scope);
    b.extend_from_slice(&ph);
    b.extend_from_slice(&run.to_le_bytes());
    b.extend_from_slice(&peak.to_le_bytes());
    b
}

fn verify_value(a: u8, s: u8, iter: u32, rep: u32) -> u64 {
    40_000_000 + (rep as u64) * 200_000 + (iter as u64) * 1_000 + (s as u64) * 100 + (a as u64) * 10
}
fn prove_value(a: u8, s: u8, iter: u32) -> u64 {
    5_000_000_000 + (iter as u64) * 10 + (s as u64) * 3 + a as u64
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
fn verify_rss_value(a: u8, iter: u32) -> u64 {
    (100u64 << 20) + (a as u64) * 4096 + iter as u64
}

type Rec = (([u8; 32], u32), Vec<u8>);
fn bundle_hash(prefix: &[u8], mut recs: Vec<Rec>) -> ([u8; 32], u32) {
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
    let mut samples = Vec::new();
    let mut rss = Vec::new();
    let mut envelopes = Vec::new();
    let mut provenances = Vec::new();

    let mut arch_prov: Vec<(u8, u8, [u8; 32])> = Vec::new();
    let mut proving: HashMap<u8, [u8; 32]> = HashMap::new();
    for a in ARCHES {
        for role in [0u8, 1] {
            let h = prov_h(a, role);
            if role == 0 {
                proving.insert(a, h);
            }
            arch_prov.push((a, role, h));
            provenances.push(enc_prov(a, role));
        }
    }

    let mut measured: Vec<(u8, u8, u32, [u8; 32])> = Vec::new();
    let mut sbundle: HashMap<(u8, u8, u8), Vec<Rec>> = HashMap::new();
    let mut prss: HashMap<u8, Vec<Rec>> = HashMap::new();
    let mut vrss: HashMap<u8, Vec<Rec>> = HashMap::new();
    let mut verify_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut vrss_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut max_pb = 0u64;

    for a in ARCHES {
        for s in STMTS {
            for iter in 0..ITERS {
                let ph = proof_hash(a, s, iter);
                let eb = enc_env(a, s, iter, proving[&a]);
                measured.push((a, s, iter, crate::plain(&eb)));
                envelopes.push(eb);
                for rep in 0..REPS {
                    let v = verify_value(a, s, iter, rep);
                    let b = enc_sample(a, s, 5, 1, v, rep, ph);
                    sbundle
                        .entry((a, s, 5))
                        .or_default()
                        .push(((ph, rep), b.clone()));
                    verify_by_arch.entry(a).or_default().push(v);
                    samples.push(b);
                }
                for (metric, unit, value) in [
                    (4u8, 1u8, prove_value(a, s, iter)),
                    (6, 1, setup_value(iter)),
                    (7, 2, proof_bytes_value(iter)),
                ] {
                    let b = enc_sample(a, s, metric, unit, value, iter, ph);
                    sbundle
                        .entry((a, s, metric))
                        .or_default()
                        .push(((ph, iter), b.clone()));
                    samples.push(b);
                }
                max_pb = max_pb.max(proof_bytes_value(iter));
                let b = enc_rss(a, 0, proving_rss_value(iter), iter, ph);
                prss.entry(a).or_default().push(((ph, iter), b.clone()));
                rss.push(b);
                let vrv = verify_rss_value(a, iter);
                vrss_by_arch.entry(a).or_default().push(vrv);
                let b = enc_rss(a, 1, vrv, iter, ph);
                vrss.entry(a).or_default().push(((ph, iter), b.clone()));
                rss.push(b);
            }
        }
    }

    let mut sample_bundles: Vec<(u8, u8, u8, u8, u32, [u8; 32])> = Vec::new();
    for a in ARCHES {
        for s in STMTS {
            for m in BUNDLE_METRICS {
                let (h, c) = bundle_hash(tags::SAMPLEBUNDLE_PREFIX, sbundle[&(a, s, m)].clone());
                sample_bundles.push((a, s, m, 1, c, h));
            }
        }
    }
    let mut rss_bundles: Vec<(u8, u8, u32, [u8; 32])> = Vec::new();
    for a in ARCHES {
        for (scope, coll) in [(0u8, &prss), (1, &vrss)] {
            let (h, c) = bundle_hash(tags::RSSBUNDLE_PREFIX, coll[&a].clone());
            rss_bundles.push((a, scope, c, h));
        }
    }

    let worst_p99 = ARCHES
        .iter()
        .map(|a| {
            let mut v = verify_by_arch[a].clone();
            v.sort_unstable();
            nearest_rank_p99(&v).unwrap()
        })
        .max()
        .unwrap();
    let worst_vrss = ARCHES
        .iter()
        .map(|a| *vrss_by_arch[a].iter().max().unwrap())
        .max()
        .unwrap();
    let qualification = worst_p99 <= P99_GATE_NS;
    let failure_codes: Vec<u16> = if qualification { vec![] } else { vec![3] };

    let result_set = enc_result_set(
        &arch_prov,
        &measured,
        &sample_bundles,
        &rss_bundles,
        (
            max_pb as u32,
            worst_p99,
            VERIFIER_MATERIAL_BYTES,
            worst_vrss,
        ),
        qualification,
        &failure_codes,
    );

    Evidence {
        samples,
        rss,
        envelopes,
        provenances,
        verifier_material: enc_vmat(),
        result_set,
    }
}

#[allow(clippy::type_complexity)]
fn enc_result_set(
    arch_prov: &[(u8, u8, [u8; 32])],
    measured: &[(u8, u8, u32, [u8; 32])],
    sample_bundles: &[(u8, u8, u8, u8, u32, [u8; 32])],
    rss_bundles: &[(u8, u8, u32, [u8; 32])],
    agg: (u32, u64, u64, u64),
    qualification: bool,
    failure_codes: &[u16],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&id(b"spec"));
    b.extend_from_slice(&id(b"guest_set"));
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&vmat_id());
    b.extend_from_slice(&stmt_hash(0));
    b.extend_from_slice(&stmt_hash(1));
    b.extend_from_slice(&(arch_prov.len() as u32).to_le_bytes());
    for (a, r, h) in arch_prov {
        b.push(*a);
        b.push(*r);
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&(measured.len() as u32).to_le_bytes());
    for (a, s, it, h) in measured {
        b.push(*a);
        b.push(*s);
        b.extend_from_slice(&it.to_le_bytes());
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&(sample_bundles.len() as u32).to_le_bytes());
    for (a, s, m, sk, c, h) in sample_bundles {
        b.push(*a);
        b.push(*s);
        b.push(*m);
        b.push(*sk);
        b.extend_from_slice(&c.to_le_bytes());
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&(rss_bundles.len() as u32).to_le_bytes());
    for (a, sc, c, h) in rss_bundles {
        b.push(*a);
        b.push(*sc);
        b.extend_from_slice(&c.to_le_bytes());
        b.extend_from_slice(h);
    }
    b.extend_from_slice(&id(b"malformed"));
    b.push(0);
    for c in [40u32, 4000, 40, 40, 40] {
        b.extend_from_slice(&c.to_le_bytes());
    }
    b.extend_from_slice(&agg.0.to_le_bytes());
    b.extend_from_slice(&agg.1.to_le_bytes());
    b.extend_from_slice(&agg.2.to_le_bytes());
    b.extend_from_slice(&agg.3.to_le_bytes());
    b.push(if qualification { 1 } else { 0 });
    b.extend_from_slice(&(failure_codes.len() as u32).to_le_bytes());
    for c in failure_codes {
        b.extend_from_slice(&c.to_le_bytes());
    }
    b
}

pub fn verify_evidence(ev: &Evidence) -> Result<Recomputed, String> {
    let rs =
        closure::decode_result_set(&ev.result_set).map_err(|e| format!("result_set: {e:?}"))?;
    closure::validate_completeness(&rs).map_err(|e| format!("completeness: {e}"))?;

    let spec = rs.b0_pre_spec_hash;
    let gs = rs.r0_guest_set_hash;
    let vm = rs.verifier_material_manifest_hash;
    let tlg = rs.stmt_tlg;
    let st = rs.stmt_st;
    let stmt_of = |h: [u8; 32]| -> Result<u8, String> {
        if h == tlg {
            Ok(0)
        } else if h == st {
            Ok(1)
        } else {
            Err("statement binding".into())
        }
    };

    // verifier-material total from the canonical manifest record
    let vmm = closure::decode_vm(&ev.verifier_material).map_err(|e| format!("vmat: {e:?}"))?;
    if closure::Vm::identity(&ev.verifier_material) != vm {
        return Err("verifier-material identity".into());
    }
    let vmat_bytes = vmm.verifier_material_bytes().ok_or("vmat overflow")?;
    if rs.aggregates.2 != vmat_bytes {
        return Err("verifier_material_bytes mismatch".into());
    }

    let mut programs: HashSet<[u8; 32]> = HashSet::new();
    let mut locks: HashSet<[u8; 32]> = HashSet::new();
    let mut containers: HashSet<[u8; 32]> = HashSet::new();

    // provenances
    if ev.provenances.len() != 4 {
        return Err("provenance count".into());
    }
    let mut prov_h: HashMap<(u8, u8), [u8; 32]> = HashMap::new();
    let mut proving: HashMap<u8, [u8; 32]> = HashMap::new();
    for b in &ev.provenances {
        let p = closure::decode_prov(b).map_err(|e| format!("prov: {e:?}"))?;
        if p.spec != spec || p.guest_set != gs || p.vmat != vm || p.candidate != rs.candidate {
            return Err("prov binding".into());
        }
        closure::provenance_eligible(&p).map_err(|e| format!("prov eligible: {e}"))?;
        programs.insert(p.program);
        locks.insert(p.lock);
        let h = closure::provenance_hash(b);
        if prov_h.insert((p.arch, p.role), h).is_some() {
            return Err("duplicate provenance".into());
        }
        if p.role == 0 {
            proving.insert(p.arch, h);
        }
    }
    for (a, r, h) in &rs.arch_provenance {
        match prov_h.get(&(*a, *r)) {
            Some(x) if x == h => {}
            _ => return Err("provenance hash mismatch".into()),
        }
    }

    // envelopes
    let mut proof_hashes: HashSet<[u8; 32]> = HashSet::new();
    let mut env_hash: HashMap<(u8, u8, u32), [u8; 32]> = HashMap::new();
    for b in &ev.envelopes {
        let e = closure::decode_env(b).map_err(|e| format!("env: {e:?}"))?;
        if e.b0_pre_spec_hash != spec
            || e.r0_guest_set_hash != gs
            || e.verifier_material_manifest_hash != vm
            || e.candidate != rs.candidate
        {
            return Err("env binding".into());
        }
        let si = stmt_of(e.computation_statement_hash)?;
        if proving.get(&e.arch) != Some(&e.arch_run_provenance) {
            return Err("env provenance link".into());
        }
        programs.insert(e.guest_program_id);
        locks.insert(e.candidate_dep_lock_hash);
        if !proof_hashes.insert(e.proof_hash) {
            return Err("dup proof hash".into());
        }
        if env_hash
            .insert((e.arch, si, e.iteration_index), crate::plain(b))
            .is_some()
        {
            return Err("dup proof cell".into());
        }
    }
    // grid
    for a in ARCHES {
        for s in STMTS {
            for i in 0..ITERS {
                if !env_hash.contains_key(&(a, s, i)) {
                    return Err("grid".into());
                }
            }
        }
    }
    if env_hash.len() != 40 {
        return Err("grid size".into());
    }
    for (a, s, it, h) in &rs.measured_proofs {
        match env_hash.get(&(*a, *s, *it)) {
            Some(x) if x == h => {}
            _ => return Err("measured proof mismatch".into()),
        }
    }

    // samples
    let mut verify_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut max_pb = 0u64;
    let mut per: HashMap<(u8, u8, u8), Vec<Rec>> = HashMap::new();
    for b in &ev.samples {
        let s = closure::decode_sample(b).map_err(|e| format!("sample: {e:?}"))?;
        if s.spec != spec || s.guest_set != gs || s.vmat != vm || s.candidate != rs.candidate {
            return Err("sample binding".into());
        }
        if s.sample_kind != 1 {
            return Err("sample warmup".into());
        }
        if s.status != 0 {
            return Err("sample status".into());
        }
        let expected_unit = if s.metric_kind == 7 { 2 } else { 1 };
        if s.unit != expected_unit {
            return Err("sample unit".into());
        }
        if !proof_hashes.contains(&s.proof_hash) {
            return Err("sample orphan".into());
        }
        programs.insert(s.program);
        locks.insert(s.lock);
        containers.insert(s.container);
        let si = stmt_of(s.stmt)?;
        per.entry((s.arch, si, s.metric_kind))
            .or_default()
            .push(((s.proof_hash, s.iteration_index), b.clone()));
        match s.metric_kind {
            5 => verify_by_arch.entry(s.arch).or_default().push(s.value),
            7 => max_pb = max_pb.max(s.value),
            _ => {}
        }
    }
    let claimed: HashMap<(u8, u8, u8), ([u8; 32], u32)> = rs
        .sample_bundles
        .iter()
        .map(|b| ((b.0, b.1, b.2), (b.5, b.4)))
        .collect();
    if per.len() != claimed.len() {
        return Err("sample bundle set".into());
    }
    for (k, recs) in per {
        let (h, c) = bundle_hash(tags::SAMPLEBUNDLE_PREFIX, recs);
        match claimed.get(&k) {
            Some((ch, cc)) if *ch == h && *cc == c => {}
            _ => return Err("sample bundle mismatch".into()),
        }
    }

    // rss
    let mut vrss_by_arch: HashMap<u8, Vec<u64>> = HashMap::new();
    let mut rper: HashMap<(u8, u8), Vec<Rec>> = HashMap::new();
    for b in &ev.rss {
        let r = closure::decode_rss(b).map_err(|e| format!("rss: {e:?}"))?;
        if r.spec != spec || r.guest_set != gs || r.vmat != vm || r.candidate != rs.candidate {
            return Err("rss binding".into());
        }
        if !proof_hashes.contains(&r.proof_hash) {
            return Err("rss orphan".into());
        }
        programs.insert(r.program);
        locks.insert(r.lock);
        containers.insert(r.container);
        if r.rss_scope == 1 {
            vrss_by_arch
                .entry(r.arch)
                .or_default()
                .push(r.peak_rss_bytes);
        }
        rper.entry((r.arch, r.rss_scope))
            .or_default()
            .push(((r.proof_hash, r.run_index), b.clone()));
    }
    let claimed_rss: HashMap<(u8, u8), ([u8; 32], u32)> = rs
        .rss_bundles
        .iter()
        .map(|b| ((b.0, b.1), (b.3, b.2)))
        .collect();
    if rper.len() != claimed_rss.len() {
        return Err("rss bundle set".into());
    }
    for (k, recs) in rper {
        let (h, c) = bundle_hash(tags::RSSBUNDLE_PREFIX, recs);
        match claimed_rss.get(&k) {
            Some((ch, cc)) if *ch == h && *cc == c => {}
            _ => return Err("rss bundle mismatch".into()),
        }
    }

    if programs.len() != 1 {
        return Err("program identity".into());
    }
    if locks.len() != 1 {
        return Err("lock identity".into());
    }
    if containers.len() != 1 {
        return Err("container identity".into());
    }

    let worst_p99 = ARCHES
        .iter()
        .map(|a| {
            let mut v = verify_by_arch.get(a).cloned().unwrap_or_default();
            v.sort_unstable();
            nearest_rank_p99(&v).unwrap_or(0)
        })
        .max()
        .unwrap();
    let worst_vrss = ARCHES
        .iter()
        .map(|a| {
            vrss_by_arch
                .get(a)
                .and_then(|v| v.iter().max().copied())
                .unwrap_or(0)
        })
        .max()
        .unwrap();
    let qualification = worst_p99 <= P99_GATE_NS;
    let failure_codes: Vec<u16> = if qualification { vec![] } else { vec![3] };

    let (cpb, cp99, _cvm, cvrss) = rs.aggregates;
    if cpb as u64 != max_pb {
        return Err("max_proof_bytes mismatch".into());
    }
    if cp99 != worst_p99 {
        return Err("p99 mismatch".into());
    }
    if cvrss != worst_vrss {
        return Err("verifier rss mismatch".into());
    }
    if rs.qualification != qualification || rs.failure_codes != failure_codes {
        return Err("qualification mismatch".into());
    }

    Ok(Recomputed {
        max_proof_bytes: max_pb as u32,
        worst_arch_p99_verify_ns: worst_p99,
        verifier_material_bytes: vmat_bytes,
        worst_arch_verifier_rss_bytes: worst_vrss,
        qualification,
        failure_codes,
        result_set_hash: closure::ResultSet::result_set_hash(&ev.result_set),
    })
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
    // decode -> mutate parts -> re-encode (identities are regenerated identically)
    fn with_rs(ev: &Evidence, f: impl Fn(&mut closure::ResultSet)) -> Evidence {
        let mut e = clone_ev(ev);
        let mut rs = closure::decode_result_set(&e.result_set).unwrap();
        f(&mut rs);
        e.result_set = enc_result_set(
            &rs.arch_provenance,
            &rs.measured_proofs,
            &rs.sample_bundles,
            &rs.rss_bundles,
            rs.aggregates,
            rs.qualification,
            &rs.failure_codes,
        );
        e
    }

    #[test]
    fn generated_verifies() {
        let ev = generate();
        assert_eq!(ev.envelopes.len(), 40);
        assert_eq!(ev.samples.len(), 4000 + 40 + 40 + 40);
        assert_eq!(ev.rss.len(), 80);
        let r = verify_evidence(&ev).expect("valid");
        assert!(r.qualification);
        assert_eq!(r.verifier_material_bytes, 292);
    }

    #[test]
    fn adversarial_matrix_all_reject() {
        let base = generate();
        type M = Box<dyn Fn(&Evidence) -> Evidence>;
        let cases: Vec<(&str, M)> = vec![
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
                    let st = stmt_hash(1);
                    e.samples[0][98..130].copy_from_slice(&st);
                    e
                }),
            ),
            (
                "move_proof",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let ph = proof_hash(1, 0, 5);
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
            (
                "falsified_max_pb",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.0 += 1)),
            ),
            (
                "falsified_vmat_total",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.2 = 999)),
            ),
            (
                "falsified_vrss",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.3 += 1)),
            ),
            (
                "falsified_qualification",
                Box::new(|e| with_rs(e, |rs| rs.qualification = false)),
            ),
            (
                "qualifying_with_failure_code",
                Box::new(|e| with_rs(e, |rs| rs.failure_codes = vec![3])),
            ),
            (
                "falsified_p99_with_consistent_bundles",
                Box::new(|e| with_rs(e, |rs| rs.aggregates.1 += 1)),
            ),
            (
                "vmat_entry_bytelen_updated_hash",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.verifier_material = enc_vmat_with(293, 1);
                    let newid = crate::plain(&e.verifier_material);
                    e.result_set[68..100].copy_from_slice(&newid); // rs.verifier_material_manifest_hash
                    e
                }),
            ),
            (
                "vmat_omitted_entry",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    let mut m = Vec::new();
                    m.extend_from_slice(&tags::VERIFIER_MATERIAL);
                    m.extend_from_slice(&1u16.to_le_bytes());
                    m.extend_from_slice(&1u16.to_le_bytes());
                    m.extend_from_slice(&0u32.to_le_bytes());
                    e.verifier_material = m;
                    e
                }),
            ),
            (
                "vmat_wrong_candidate",
                Box::new(|e| {
                    let mut e = clone_ev(e);
                    e.verifier_material = enc_vmat_with(VERIFIER_MATERIAL_BYTES, 2);
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

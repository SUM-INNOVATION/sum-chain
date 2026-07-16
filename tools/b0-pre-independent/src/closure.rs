//! Independent decoders + validation for the R0 closure formats that gate
//! B0-FINAL selection (envelope, verifier material, allowlist, provenance,
//! benchmark records, result set). From-scratch code over the independent
//! reader; no shared codec with the reference. It consumes canonical bytes the
//! reference produces, parses them independently, recomputes every
//! selection-relevant identity/aggregate, and rejects invalid or mixed evidence.

use crate::rd::{Rd, E};
use crate::tags;

// Frozen completeness (documented; plan §13/§23).
const ITERS: u32 = 10;
const MEASURED_PROOFS: u32 = 40;
const VERIFY_TIMING: u32 = 4000;
const PROVE_TIME: u32 = 40;
const PROOF_BYTES: u32 = 40;
const SETUP_SAMPLES: u32 = 40;
const PROVING_RSS: u32 = 40;
const VERIFY_RSS: u32 = 40;

fn candidate(v: u16) -> Result<u16, E> {
    if v == 1 || v == 2 {
        Ok(v)
    } else {
        Err(E::BadEnum)
    }
}
fn one_of(v: u8, max: u8) -> Result<u8, E> {
    if v <= max {
        Ok(v)
    } else {
        Err(E::BadEnum)
    }
}
fn arch(v: u8) -> Result<u8, E> {
    if v == 1 || v == 2 {
        Ok(v)
    } else {
        Err(E::BadEnum)
    }
}
fn boolean(v: u8) -> Result<bool, E> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(E::Value),
    }
}

// ---------- VerifierMaterialManifestV1 ----------

pub struct VmEntry {
    pub label: String,
    pub role: u8,
    pub byte_len: u64,
    pub hash: [u8; 32],
}
pub struct Vm {
    pub candidate: u16,
    pub entries: Vec<VmEntry>,
}
impl Vm {
    /// Single self-domain identity: `BLAKE3(canonical_bytes)` (no double prefix).
    pub fn identity(canonical_bytes: &[u8]) -> [u8; 32] {
        crate::plain(canonical_bytes)
    }
    pub fn verifier_material_bytes(&self) -> Option<u64> {
        let mut t = 0u64;
        for e in &self.entries {
            t = t.checked_add(e.byte_len)?;
        }
        Some(t)
    }
}

pub fn decode_vm(b: &[u8]) -> Result<Vm, E> {
    let mut r = Rd::new(b);
    r.tag32(&tags::VERIFIER_MATERIAL)?;
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let count = r.u32()?;
    if count > 64 {
        return Err(E::Count);
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut prev: Option<(u8, Vec<u8>)> = None;
    for _ in 0..count {
        let label = r.str16(64)?;
        if label.is_empty() {
            return Err(E::Value);
        }
        let role = one_of(r.u8()?, 3)?;
        let byte_len = r.u64()?;
        let hash = r.arr::<32>()?;
        let key = (role, label.as_bytes().to_vec());
        if let Some(p) = &prev {
            if *p == key {
                return Err(E::Dup);
            }
            if key < *p {
                return Err(E::Order);
            }
        }
        prev = Some(key);
        entries.push(VmEntry {
            label,
            role,
            byte_len,
            hash,
        });
    }
    r.end()?;
    Ok(Vm { candidate, entries })
}

// ---------- R0ProofArtifactEnvelopeV1 ----------

pub struct Env {
    pub candidate: u16,
    pub candidate_dep_lock_hash: [u8; 32],
    pub guest_program_id: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub computation_statement_hash: [u8; 32],
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub arch_run_provenance: [u8; 32],
    pub arch: u8,
    pub sample_kind: u8,
    pub iteration_index: u32,
    pub proof_hash: [u8; 32],
}

pub fn decode_env(b: &[u8]) -> Result<Env, E> {
    let mut r = Rd::new(b);
    r.tag32(&tags::ENVELOPE)?;
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let candidate_dep_lock_hash = r.arr::<32>()?;
    let guest_program_id = r.arr::<32>()?;
    let verifier_material_manifest_hash = r.arr::<32>()?;
    let computation_statement_hash = r.arr::<32>()?;
    let b0_pre_spec_hash = r.arr::<32>()?;
    let r0_guest_set_hash = r.arr::<32>()?;
    let arch_run_provenance = r.arr::<32>()?;
    let arch = arch(r.u8()?)?;
    let sample_kind = one_of(r.u8()?, 1)?;
    let iteration_index = r.u32()?;
    if r.u8()? != 1 {
        return Err(E::BadEnum); // ProofRefKind::ContentDigest
    }
    let proof_hash = r.arr::<32>()?;
    let count = r.u32()?;
    if count > 32 {
        return Err(E::Count);
    }
    let mut prev: Option<Vec<u8>> = None;
    for _ in 0..count {
        let ll = r.u32()?;
        if ll == 0 || ll > 64 {
            return Err(E::Range);
        }
        let lb = r.take(ll as usize)?.to_vec();
        if !lb.iter().all(|&x| (0x20..=0x7E).contains(&x)) {
            return Err(E::Value);
        }
        if let Some(p) = &prev {
            if lb == *p {
                return Err(E::Dup);
            }
            if lb.as_slice() < p.as_slice() {
                return Err(E::Order);
            }
        }
        prev = Some(lb);
        let _hash = r.arr::<32>()?;
    }
    r.end()?;
    Ok(Env {
        candidate,
        candidate_dep_lock_hash,
        guest_program_id,
        verifier_material_manifest_hash,
        computation_statement_hash,
        b0_pre_spec_hash,
        r0_guest_set_hash,
        arch_run_provenance,
        arch,
        sample_kind,
        iteration_index,
        proof_hash,
    })
}

// ---------- BenchmarkSampleV1 (309) / BenchmarkRssRecordV1 (306) ----------

pub struct Sample {
    pub spec: [u8; 32],
    pub guest_set: [u8; 32],
    pub stmt: [u8; 32],
    pub candidate: u16,
    pub vmat: [u8; 32],
    pub program: [u8; 32],
    pub lock: [u8; 32],
    pub container: [u8; 32],
    pub arch: u8,
    pub sample_kind: u8,
    pub metric_kind: u8,
    pub unit: u8,
    pub value: u64,
    pub proof_hash: [u8; 32],
    pub iteration_index: u32,
    pub status: u8,
}

pub fn decode_sample(b: &[u8]) -> Result<Sample, E> {
    let mut r = Rd::new(b);
    r.tag32(&tags::BENCH_SAMPLE)?;
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let spec = r.arr::<32>()?;
    let guest_set = r.arr::<32>()?;
    let stmt = r.arr::<32>()?;
    let candidate = candidate(r.u16()?)?;
    let program = r.arr::<32>()?;
    let vmat = r.arr::<32>()?;
    let lock = r.arr::<32>()?;
    let container = r.arr::<32>()?;
    let arch = arch(r.u8()?)?;
    let sample_kind = one_of(r.u8()?, 1)?;
    let metric_kind = one_of(r.u8()?, 7)?;
    let unit = one_of(r.u8()?, 2)?;
    let value = r.u64()?;
    let proof_hash = r.arr::<32>()?;
    let iteration_index = r.u32()?;
    let status = one_of(r.u8()?, 2)?;
    r.end()?;
    Ok(Sample {
        spec,
        guest_set,
        stmt,
        candidate,
        vmat,
        program,
        lock,
        container,
        arch,
        sample_kind,
        metric_kind,
        unit,
        value,
        proof_hash,
        iteration_index,
        status,
    })
}

pub struct Rss {
    pub spec: [u8; 32],
    pub guest_set: [u8; 32],
    pub candidate: u16,
    pub vmat: [u8; 32],
    pub program: [u8; 32],
    pub lock: [u8; 32],
    pub container: [u8; 32],
    pub arch: u8,
    pub rss_scope: u8,
    pub proof_hash: [u8; 32],
    pub run_index: u32,
    pub peak_rss_bytes: u64,
}

pub fn decode_rss(b: &[u8]) -> Result<Rss, E> {
    let mut r = Rd::new(b);
    r.tag32(&tags::BENCH_RSS)?;
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let spec = r.arr::<32>()?;
    let guest_set = r.arr::<32>()?;
    let _stmt = r.arr::<32>()?;
    let candidate = candidate(r.u16()?)?;
    let program = r.arr::<32>()?;
    let vmat = r.arr::<32>()?;
    let lock = r.arr::<32>()?;
    let container = r.arr::<32>()?;
    let arch = arch(r.u8()?)?;
    let rss_scope = one_of(r.u8()?, 1)?;
    let proof_hash = r.arr::<32>()?;
    let run_index = r.u32()?;
    let peak_rss_bytes = r.u64()?;
    r.end()?;
    Ok(Rss {
        spec,
        guest_set,
        candidate,
        vmat,
        program,
        lock,
        container,
        arch,
        rss_scope,
        proof_hash,
        run_index,
        peak_rss_bytes,
    })
}

// ---------- ArchRunProvenanceV1 ----------

pub struct Prov {
    pub role: u8,
    pub spec: [u8; 32],
    pub guest_set: [u8; 32],
    pub candidate: u16,
    pub program: [u8; 32],
    pub lock: [u8; 32],
    pub vmat: [u8; 32],
    pub arch: u8,
    pub dirty: bool,
    pub host_os: String,
    pub kernel: String,
    pub cpu_vendor: String,
    pub cpu_model: String,
    pub phys: u32,
    pub logical: u32,
    pub ram: u64,
    pub cpuset: u32,
    pub memlimit: u64,
    pub governor: String,
    pub turbo: bool,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
    pub harness_hash: [u8; 32],
}

pub fn decode_prov(b: &[u8]) -> Result<Prov, E> {
    let mut r = Rd::new(b);
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let role = one_of(r.u8()?, 1)?;
    let spec = r.arr::<32>()?;
    let guest_set = r.arr::<32>()?;
    let candidate = candidate(r.u16()?)?;
    let program = r.arr::<32>()?;
    let lock = r.arr::<32>()?;
    let vmat = r.arr::<32>()?;
    let arch = arch(r.u8()?)?;
    let sc_len = r.u8()?;
    if sc_len != 40 && sc_len != 64 {
        return Err(E::Value);
    }
    let sc = r.take(sc_len as usize)?;
    if !sc
        .iter()
        .all(|&x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    {
        return Err(E::Value);
    }
    let dirty = boolean(r.u8()?)?;
    let _builder = r.arr::<32>()?;
    let host_os = r.str16(128)?;
    let kernel = r.str16(128)?;
    let cpu_vendor = r.str16(64)?;
    let cpu_model = r.str16(128)?;
    let phys = r.u32()?;
    let logical = r.u32()?;
    let ram = r.u64()?;
    let cpuset = r.u32()?;
    let memlimit = r.u64()?;
    let governor = r.str16(32)?;
    let turbo = boolean(r.u8()?)?;
    let clock_source = r.str16(32)?;
    let cgroup_version = r.u8()?;
    if cgroup_version != 1 && cgroup_version != 2 {
        return Err(E::Value);
    }
    let cgroup_scope_label = r.str16(128)?;
    let harness_hash = r.arr::<32>()?;
    let _envcap = r.arr::<32>()?;
    r.end()?;
    Ok(Prov {
        role,
        spec,
        guest_set,
        candidate,
        program,
        lock,
        vmat,
        arch,
        dirty,
        host_os,
        kernel,
        cpu_vendor,
        cpu_model,
        phys,
        logical,
        ram,
        cpuset,
        memlimit,
        governor,
        turbo,
        clock_source,
        cgroup_version,
        cgroup_scope_label,
        harness_hash,
    })
}

pub fn provenance_hash(canonical_bytes: &[u8]) -> [u8; 32] {
    crate::prefixed(tags::ARCHPROV_PREFIX, canonical_bytes)
}

/// Controlled-benchmark measurement integrity plus the validator verification
/// baseline (plan §23, as corrected). Proving contributors have NO hardware or
/// resource eligibility: cores, RAM, and cpuset/memory limits are reported-only
/// and never gate. Only device-neutral measurement integrity (governor / turbo /
/// clean tree) and the Verification-role baseline (detected >= 4 cores / 8 GiB,
/// configured run pinned to 4 cores / 8 GiB) gate.
pub fn provenance_eligible(p: &Prov) -> Result<(), &'static str> {
    if p.governor != "performance" {
        return Err("governor");
    }
    if p.turbo {
        return Err("turbo");
    }
    if p.dirty {
        return Err("dirty");
    }
    match p.role {
        // proving contributor: no hardware/resource eligibility (reported-only)
        0 => {}
        1 => {
            // verification validator baseline: DETECTED >= 4 cores / 8 GiB, and a
            // configured run pinned to exactly 4 cores / 8 GiB
            if p.phys < 4 {
                return Err("verify_phys");
            }
            if p.ram < 8u64 << 30 {
                return Err("verify_ram");
            }
            if p.cpuset != 4 {
                return Err("verify_cpuset");
            }
            if p.memlimit != 8u64 << 30 {
                return Err("verify_mem");
            }
        }
        _ => return Err("role"),
    }
    Ok(())
}

/// Fair-benchmark pairing (independent mirror): for a given (arch, role), the two
/// candidates' provenance must represent the SAME controlled host and
/// environment (the "same physical host" rule) — detected cores/RAM and CPU
/// vendor/model and OS/kernel/clock/cgroup/harness identity, not just the
/// configured cpuset/memory. Candidate-specific identities (guest/lock/verifier
/// material/container) are NOT compared. Device neutrality means no absolute
/// contributor minimum; it does not permit the two candidates to run on
/// different hardware.
pub fn paired_environment_consistent(a: &Prov, b: &Prov) -> Result<(), &'static str> {
    if a.arch != b.arch {
        return Err("arch");
    }
    if a.host_os != b.host_os {
        return Err("host_os");
    }
    if a.kernel != b.kernel {
        return Err("kernel");
    }
    if a.cpu_vendor != b.cpu_vendor {
        return Err("cpu_vendor");
    }
    if a.cpu_model != b.cpu_model {
        return Err("cpu_model");
    }
    if a.phys != b.phys {
        return Err("physical_core_count");
    }
    if a.logical != b.logical {
        return Err("logical_cpu_count");
    }
    if a.ram != b.ram {
        return Err("total_ram_bytes");
    }
    if a.cpuset != b.cpuset {
        return Err("cpuset");
    }
    if a.memlimit != b.memlimit {
        return Err("memlimit");
    }
    if a.governor != b.governor {
        return Err("governor");
    }
    if a.turbo != b.turbo {
        return Err("turbo");
    }
    if a.clock_source != b.clock_source {
        return Err("clock_source");
    }
    if a.cgroup_version != b.cgroup_version {
        return Err("cgroup_version");
    }
    if a.cgroup_scope_label != b.cgroup_scope_label {
        return Err("cgroup_scope_label");
    }
    if a.harness_hash != b.harness_hash {
        return Err("benchmark_harness_source_hash");
    }
    Ok(())
}

// ---------- GuestProgramAllowlistV1 ----------

pub struct AllowEntry {
    pub candidate: u16,
    pub arches: Vec<u8>,
    pub program_id: [u8; 32],
    pub reproducible: bool,
}
pub struct Allowlist {
    pub entries: Vec<AllowEntry>,
}
impl Allowlist {
    pub fn guest_set_hash(canonical_bytes: &[u8]) -> [u8; 32] {
        crate::prefixed(tags::GUESTSET_PREFIX, canonical_bytes)
    }
}

pub fn decode_allowlist(b: &[u8]) -> Result<Allowlist, E> {
    let mut r = Rd::new(b);
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let count = r.u32()?;
    if count > 64 {
        return Err(E::Count);
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut prev_c: Option<u16> = None;
    for _ in 0..count {
        let candidate = candidate(r.u16()?)?;
        let _spec = r.arr::<32>()?;
        let _tree = r.arr::<32>()?;
        let _lock = r.arr::<32>()?;
        let arch_count = r.u8()?;
        if arch_count == 0 || arch_count > 8 {
            return Err(E::Count);
        }
        let mut arches = Vec::with_capacity(arch_count as usize);
        let mut prev_a: Option<u8> = None;
        for _ in 0..arch_count {
            let a = arch(r.u8()?)?;
            let _digest = r.arr::<32>()?;
            if let Some(p) = prev_a {
                if a == p {
                    return Err(E::Dup);
                }
                if a < p {
                    return Err(E::Order);
                }
            }
            prev_a = Some(a);
            arches.push(a);
        }
        let _image = r.arr::<32>()?;
        let program_id = r.arr::<32>()?;
        let _vm = r.arr::<32>()?;
        let _build = r.arr::<32>()?;
        let reproducible = boolean(r.u8()?)?;
        if let Some(p) = prev_c {
            if candidate == p {
                return Err(E::Dup);
            }
            if candidate < p {
                return Err(E::Order);
            }
        }
        prev_c = Some(candidate);
        entries.push(AllowEntry {
            candidate,
            arches,
            program_id,
            reproducible,
        });
    }
    r.end()?;
    Ok(Allowlist { entries })
}

// ---------- R0ResultSetV1 ----------

pub struct ResultSet {
    pub candidate: u16,
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub stmt_tlg: [u8; 32],
    pub stmt_st: [u8; 32],
    pub arch_provenance: Vec<(u8, u8, [u8; 32])>,
    pub measured_proofs: Vec<(u8, u8, u32, [u8; 32])>,
    pub sample_bundles: Vec<(u8, u8, u8, u8, u32, [u8; 32])>, // arch, stmt, metric, sk, count, hash
    pub rss_bundles: Vec<(u8, u8, u32, [u8; 32])>,            // arch, scope, count, hash
    pub completeness: (u32, u32, u32, u32, u32),
    pub aggregates: (u32, u64, u64, u64),
    pub qualification: bool,
    pub failure_codes: Vec<u16>,
}
impl ResultSet {
    pub fn result_set_hash(canonical_bytes: &[u8]) -> [u8; 32] {
        crate::prefixed(tags::RESULTSET_PREFIX, canonical_bytes)
    }
}

pub fn decode_result_set(b: &[u8]) -> Result<ResultSet, E> {
    let mut r = Rd::new(b);
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let b0_pre_spec_hash = r.arr::<32>()?;
    let r0_guest_set_hash = r.arr::<32>()?;
    let candidate = candidate(r.u16()?)?;
    let verifier_material_manifest_hash = r.arr::<32>()?;
    let stmt_tlg = r.arr::<32>()?;
    let stmt_st = r.arr::<32>()?;

    let ap = r.u32()?;
    if ap > 8 {
        return Err(E::Count);
    }
    let mut arch_provenance = Vec::with_capacity(ap as usize);
    let mut prevp: Option<(u8, u8)> = None;
    for _ in 0..ap {
        let a = arch(r.u8()?)?;
        let role = one_of(r.u8()?, 1)?;
        let h = r.arr::<32>()?;
        ord(&mut prevp, (a, role))?;
        arch_provenance.push((a, role, h));
    }

    let mp = r.u32()?;
    if mp > 256 {
        return Err(E::Count);
    }
    let mut measured_proofs = Vec::with_capacity(mp as usize);
    let mut prevm: Option<(u8, u8, u32)> = None;
    for _ in 0..mp {
        let a = arch(r.u8()?)?;
        let s = one_of(r.u8()?, 1)?;
        let it = r.u32()?;
        let h = r.arr::<32>()?;
        ord(&mut prevm, (a, s, it))?;
        measured_proofs.push((a, s, it, h));
    }

    let sb = r.u32()?;
    if sb > 256 {
        return Err(E::Count);
    }
    let mut sample_bundles = Vec::with_capacity(sb as usize);
    let mut prevs: Option<(u8, u8, u8, u8)> = None;
    for _ in 0..sb {
        let a = arch(r.u8()?)?;
        let s = one_of(r.u8()?, 1)?;
        let m = one_of(r.u8()?, 7)?;
        let sk = one_of(r.u8()?, 1)?;
        let count = r.u32()?;
        let h = r.arr::<32>()?;
        ord(&mut prevs, (a, s, m, sk))?;
        sample_bundles.push((a, s, m, sk, count, h));
    }

    let rb = r.u32()?;
    if rb > 64 {
        return Err(E::Count);
    }
    let mut rss_bundles = Vec::with_capacity(rb as usize);
    let mut prevr: Option<(u8, u8)> = None;
    for _ in 0..rb {
        let a = arch(r.u8()?)?;
        let sc = one_of(r.u8()?, 1)?;
        let count = r.u32()?;
        let h = r.arr::<32>()?;
        ord(&mut prevr, (a, sc))?;
        rss_bundles.push((a, sc, count, h));
    }

    let _malformed = r.arr::<32>()?;
    if boolean(r.u8()?)? {
        let _cc = r.u32()?;
        let _ch = r.arr::<32>()?;
    }
    let completeness = (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
    let aggregates = (r.u32()?, r.u64()?, r.u64()?, r.u64()?);
    let qualification = boolean(r.u8()?)?;
    let fc = r.u32()?;
    if fc > 64 {
        return Err(E::Count);
    }
    let mut failure_codes = Vec::with_capacity(fc as usize);
    let mut prevf: Option<u16> = None;
    for _ in 0..fc {
        let c = r.u16()?;
        if let Some(p) = prevf {
            if c == p {
                return Err(E::Dup);
            }
            if c < p {
                return Err(E::Order);
            }
        }
        prevf = Some(c);
        failure_codes.push(c);
    }
    r.end()?;

    Ok(ResultSet {
        candidate,
        b0_pre_spec_hash,
        r0_guest_set_hash,
        verifier_material_manifest_hash,
        stmt_tlg,
        stmt_st,
        arch_provenance,
        measured_proofs,
        sample_bundles,
        rss_bundles,
        completeness,
        aggregates,
        qualification,
        failure_codes,
    })
}

fn ord<K: Ord + Copy>(prev: &mut Option<K>, key: K) -> Result<(), E> {
    if let Some(p) = *prev {
        if key == p {
            return Err(E::Dup);
        }
        if key < p {
            return Err(E::Order);
        }
    }
    *prev = Some(key);
    Ok(())
}

// ---------- validation (mirror of the reference) ----------

pub fn validate_completeness(rs: &ResultSet) -> Result<(), &'static str> {
    let mut grid = Vec::new();
    for a in [1u8, 2] {
        for s in [0u8, 1] {
            for i in 0..ITERS {
                grid.push((a, s, i));
            }
        }
    }
    let mp: Vec<(u8, u8, u32)> = rs.measured_proofs.iter().map(|m| (m.0, m.1, m.2)).collect();
    if mp != grid {
        return Err("measured_proof_grid");
    }
    let mut pset = Vec::new();
    for a in [1u8, 2] {
        for role in [0u8, 1] {
            pset.push((a, role));
        }
    }
    let ap: Vec<(u8, u8)> = rs.arch_provenance.iter().map(|p| (p.0, p.1)).collect();
    if ap != pset {
        return Err("provenance_set");
    }
    if rs.completeness
        != (
            MEASURED_PROOFS,
            VERIFY_TIMING,
            PROVE_TIME,
            PROVING_RSS,
            VERIFY_RSS,
        )
    {
        return Err("completeness_count");
    }
    let ssum = |metric: u8| -> u64 {
        rs.sample_bundles
            .iter()
            .filter(|b| b.3 == 1 && b.2 == metric)
            .map(|b| b.4 as u64)
            .sum()
    };
    if ssum(5) != VERIFY_TIMING as u64 {
        return Err("host_verify_ns");
    }
    if ssum(4) != PROVE_TIME as u64 {
        return Err("host_prove_wrap_ns");
    }
    if ssum(7) != PROOF_BYTES as u64 {
        return Err("proof_bytes");
    }
    if ssum(6) != SETUP_SAMPLES as u64 {
        return Err("host_setup_ns");
    }
    let rsum = |scope: u8| -> u64 {
        rs.rss_bundles
            .iter()
            .filter(|b| b.1 == scope)
            .map(|b| b.2 as u64)
            .sum()
    };
    if rsum(0) != PROVING_RSS as u64 {
        return Err("proving_run");
    }
    if rsum(1) != VERIFY_RSS as u64 {
        return Err("verify_batch");
    }
    if rs.qualification != rs.failure_codes.is_empty() {
        return Err("qualification");
    }
    Ok(())
}

pub fn envelope_binds(env: &Env, rs: &ResultSet) -> Result<(), &'static str> {
    if env.b0_pre_spec_hash != rs.b0_pre_spec_hash {
        return Err("spec");
    }
    if env.r0_guest_set_hash != rs.r0_guest_set_hash {
        return Err("guest_set");
    }
    if env.candidate != rs.candidate {
        return Err("candidate");
    }
    if env.verifier_material_manifest_hash != rs.verifier_material_manifest_hash {
        return Err("material");
    }
    if env.computation_statement_hash != rs.stmt_tlg && env.computation_statement_hash != rs.stmt_st
    {
        return Err("statement");
    }
    Ok(())
}

pub fn nearest_rank_p99(sorted_ascending: &[u64]) -> Option<u64> {
    let n = sorted_ascending.len();
    if n == 0 {
        return None;
    }
    let rank = (99 * n).div_ceil(100).max(1);
    Some(sorted_ascending[rank - 1])
}

pub fn max_u64(values: &[u64]) -> Option<u64> {
    values.iter().copied().max()
}

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

/// Independent mirror of the reference `DvfsProvenance` sum type: `Observable` is the
/// ordinary directly-observed governor+turbo state; `Unobservable` is the DISTINCT
/// hypervisor-managed state (never turbo=false/performance) carrying structured evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dvfs {
    Observable { turbo: bool, governor: String },
    Unobservable(Unobservable),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unobservable {
    pub cpu_arch: String,
    pub cpu_identity: String,
    pub virtualization: String,
    pub virtualization_source: String,
    pub absent_controls: Vec<String>,
    pub raw_evidence_blake3: [u8; 32],
}

/// Domain-separated DVFS unobservable evidence hash — the byte-identical rule the
/// reference validator and the host-provenance reader also use, so all three agree:
/// `BLAKE3("b0-final-dvfs-unobservable-evidence/v1\0" ‖ canonical)`.
pub fn recompute_dvfs_evidence_hash(e: &Unobservable) -> [u8; 32] {
    let canonical = format!(
        "b0-final-dvfs-unobservable/v1|arch={}|id={}|virt={}|virt_src={}|absent={}",
        e.cpu_arch,
        e.cpu_identity,
        e.virtualization,
        e.virtualization_source,
        e.absent_controls.join(",")
    );
    let mut h = blake3::Hasher::new();
    h.update(b"b0-final-dvfs-unobservable-evidence/v1\0");
    h.update(canonical.as_bytes());
    *h.finalize().as_bytes()
}

/// Read a `u8`-length-prefixed printable-ASCII string (mirrors the reference `read_u8_ascii`).
fn rd_u8_ascii(r: &mut Rd<'_>) -> Result<String, E> {
    let n = r.u8()? as usize;
    let s = r.take(n)?;
    if !s.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return Err(E::Value);
    }
    Ok(String::from_utf8(s.to_vec()).expect("ascii"))
}

/// Decode the `DvfsProvenance` sum type (tag 0 = Observable, tag 1 = Unobservable),
/// mirroring the reference byte layout exactly. Unknown tag and non-canonical
/// (non-strictly-sorted / duplicate) absent-control ordering fail closed.
fn decode_dvfs(r: &mut Rd<'_>) -> Result<Dvfs, E> {
    match r.u8()? {
        0 => {
            let governor = r.str16(32)?;
            let turbo = boolean(r.u8()?)?;
            Ok(Dvfs::Observable { turbo, governor })
        }
        1 => {
            let cpu_arch = rd_u8_ascii(r)?;
            let cpu_identity = r.str16(128)?;
            let virtualization = rd_u8_ascii(r)?;
            let virtualization_source = r.str16(256)?;
            let n = r.u8()?;
            let mut absent_controls = Vec::with_capacity(n as usize);
            let mut prev: Option<String> = None;
            for _ in 0..n {
                let c = r.str16(128)?;
                if let Some(p) = &prev {
                    if p.as_str() >= c.as_str() {
                        return Err(E::Value);
                    }
                }
                prev = Some(c.clone());
                absent_controls.push(c);
            }
            let raw_evidence_blake3 = r.arr::<32>()?;
            Ok(Dvfs::Unobservable(Unobservable {
                cpu_arch,
                cpu_identity,
                virtualization,
                virtualization_source,
                absent_controls,
                raw_evidence_blake3,
            }))
        }
        _ => Err(E::Value),
    }
}

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
    pub dvfs: Dvfs,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
    pub harness_hash: [u8; 32],
    pub cpuset_source_cgroup_path: String,
    pub cpuset_raw: String,
    pub cpuset_inherited: bool,
    pub cpuset_probe_chain_blake3: [u8; 32],
    pub runner_attestation_blake3: [u8; 32],
}

pub fn decode_prov(b: &[u8]) -> Result<Prov, E> {
    let mut r = Rd::new(b);
    // Provenance-LOCAL schema version: v3 (DvfsProvenance sum type + effective-cpuset provenance +
    // runner-attestation address tail). A pre-v3 record is rejected here; the global schema version of
    // every OTHER record stays 1 (unchanged layout).
    if r.u16()? != 3 {
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
    let dvfs = decode_dvfs(&mut r)?;
    let clock_source = r.str16(32)?;
    let cgroup_version = r.u8()?;
    if cgroup_version != 1 && cgroup_version != 2 {
        return Err(E::Value);
    }
    let cgroup_scope_label = r.str16(128)?;
    let harness_hash = r.arr::<32>()?;
    let _envcap = r.arr::<32>()?;
    // v3 tail: effective-cpuset provenance summary + two content-address hashes.
    let cpuset_source_cgroup_path = r.str16(128)?;
    let cpuset_raw = r.str16(256)?;
    let cpuset_inherited = boolean(r.u8()?)?;
    let cpuset_probe_chain_blake3 = r.arr::<32>()?;
    let runner_attestation_blake3 = r.arr::<32>()?;
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
        dvfs,
        clock_source,
        cgroup_version,
        cgroup_scope_label,
        harness_hash,
        cpuset_source_cgroup_path,
        cpuset_raw,
        cpuset_inherited,
        cpuset_probe_chain_blake3,
        runner_attestation_blake3,
    })
}

pub fn provenance_hash(canonical_bytes: &[u8]) -> [u8; 32] {
    crate::prefixed(tags::ARCHPROV_PREFIX, canonical_bytes)
}

/// Controlled-benchmark measurement integrity plus the validator verification
/// baseline (plan §23, as corrected). Proving contributors have NO hardware or
/// resource eligibility: cores, RAM, and cpuset/memory limits are reported-only
/// and never gate. Only device-neutral measurement integrity (governor / turbo /
/// clean tree) and the controlled Verification reference envelope (configured run
/// pinned to 2 cores / 4 GiB; detected hardware not gated) gate.
pub fn provenance_eligible(p: &Prov) -> Result<(), &'static str> {
    // Provenance self-consistency (evidence integrity, not hardware eligibility):
    // configured limits cannot exceed detected resources, and values are nonzero.
    if p.phys == 0 || p.logical == 0 || p.ram == 0 || p.cpuset == 0 || p.memlimit == 0 {
        return Err("zero_resource");
    }
    if p.cpuset > p.logical {
        return Err("cpuset_exceeds_logical");
    }
    if p.memlimit > p.ram {
        return Err("memlimit_exceeds_ram");
    }
    // DVFS is a SUM: Observable is the ordinary governor+turbo gate; Unobservable is a DISTINCT
    // state (NEVER turbo=false/performance) accepted ONLY under proven native aarch64 + Microsoft
    // venue with the raw evidence independently recomputed and no contradiction with the record arch.
    match &p.dvfs {
        Dvfs::Observable { turbo, governor } => {
            if governor != "performance" {
                return Err("governor");
            }
            if *turbo {
                return Err("turbo");
            }
        }
        Dvfs::Unobservable(e) => {
            // aarch64 == 2 (frozen Arch discriminant); the record's own arch must agree.
            if e.cpu_arch != "aarch64" || p.arch != 2 {
                return Err("dvfs_unobservable_arch");
            }
            if e.virtualization != "microsoft" {
                return Err("dvfs_unobservable_virt");
            }
            if e.absent_controls.is_empty() {
                return Err("dvfs_unobservable_no_evidence");
            }
            if recompute_dvfs_evidence_hash(e) != e.raw_evidence_blake3 {
                return Err("dvfs_unobservable_evidence_hash");
            }
        }
    }
    if p.dirty {
        return Err("dirty");
    }
    match p.role {
        // proving contributor: no hardware/resource eligibility (reported-only)
        0 => {}
        1 => {
            // controlled verification reference envelope: configured run pinned
            // to exactly 2 cores / 4 GiB. Detected hardware is not gated -- no
            // validator CPU/RAM minimum.
            if p.cpuset != 2 {
                return Err("verify_cpuset");
            }
            if p.memlimit != 4u64 << 30 {
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
    // Paired candidates must share the SAME effective-cpuset provenance (same controlled host).
    if a.cpuset_source_cgroup_path != b.cpuset_source_cgroup_path {
        return Err("cpuset_source_cgroup_path");
    }
    if a.cpuset_raw != b.cpuset_raw {
        return Err("cpuset_raw");
    }
    if a.cpuset_inherited != b.cpuset_inherited {
        return Err("cpuset_inherited");
    }
    if a.memlimit != b.memlimit {
        return Err("memlimit");
    }
    if a.dvfs != b.dvfs {
        return Err("dvfs");
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

/// Frozen chain-verification performance gates (independent mirror). The two
/// controls are evaluated INDEPENDENTLY; `MAX_ACCEPTED_PROOFS_PER_BLOCK *
/// P99_GATE_NS == AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK` is a coincidence.
pub const P99_GATE_NS: u64 = 75_000_000;
pub const MAX_ACCEPTED_PROOFS_PER_BLOCK: u64 = 4;
pub const AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK: u64 = 300_000_000;
pub const FAILCODE_VERIFY_P99: u16 = 3;
pub const FAILCODE_VERIFY_AGGREGATE: u16 = 4;

/// Per-proof p99 gate AND aggregate per-block gate (checked; overflow => fail),
/// evaluated independently. Gates passed explicitly for independent testing.
pub fn qualification_gates_pass(
    worst_arch_p99_verify_ns: u64,
    max_proofs_per_block: u64,
    p99_gate_ns: u64,
    aggregate_budget_ns: u64,
) -> bool {
    let p99_ok = worst_arch_p99_verify_ns <= p99_gate_ns;
    let aggregate_ok = match worst_arch_p99_verify_ns.checked_mul(max_proofs_per_block) {
        Some(agg) => agg <= aggregate_budget_ns,
        None => false,
    };
    p99_ok && aggregate_ok
}
/// `qualification_gates_pass` bound to the frozen constants; called by the real
/// evidence verifier, not only tests.
pub fn official_qualification(worst_arch_p99_verify_ns: u64) -> bool {
    qualification_gates_pass(
        worst_arch_p99_verify_ns,
        MAX_ACCEPTED_PROOFS_PER_BLOCK,
        P99_GATE_NS,
        AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK,
    )
}
/// Sorted failure codes for the gates a worst-arch p99 fails (empty iff qualified).
pub fn qualification_failure_codes(worst_arch_p99_verify_ns: u64) -> Vec<u16> {
    let mut v = Vec::new();
    if worst_arch_p99_verify_ns > P99_GATE_NS {
        v.push(FAILCODE_VERIFY_P99);
    }
    let over_budget = match worst_arch_p99_verify_ns.checked_mul(MAX_ACCEPTED_PROOFS_PER_BLOCK) {
        Some(agg) => agg > AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK,
        None => true,
    };
    if over_budget {
        v.push(FAILCODE_VERIFY_AGGREGATE);
    }
    v
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

// ===================== retained-artifact decoders (independent mirror) =====================
//
// The reference seals two retained artifacts per provenance — the canonical `CpusetProbeChainV1` and
// `RunnerAttestationV1` bytes behind the provenance's two content addresses. This independent code
// decodes those bytes from scratch, recomputes each domain-separated address, structurally
// re-validates the cpuset inheritance rules, and binds each artifact to its provenance. A hash-only
// provenance field is never trusted alone here either.

const CPUSET_CHAIN_KIND: &[u8; 32] = b"b0-final-cpuset-probe-chain-v1\0\0";
const RUNNER_ATT_PREFIX: &[u8] = b"b0-final-runner-attestation/v1\0";

/// One decoded observation (independent).
struct IObs {
    state: u8,
    raw: String,
    file_type: String,
    is_symlink: bool,
    dev: Option<u64>,
    inode: Option<u64>,
    size: Option<u64>,
    mtime_secs: Option<i64>,
    mtime_nanos: Option<i64>,
    read_error_class: Option<String>,
}
struct IEntry {
    cgroup_path: String,
    order: u32,
    first: IObs,
    second: IObs,
}
/// Decoded cpuset-chain artifact (independent).
pub struct CpusetChain {
    pub candidate: u16,
    pub arch: u8,
    pub role: u8,
    pub spec: [u8; 32],
    pub guest_set: [u8; 32],
    pub leaf_scope: String,
    pub source_cgroup_path: String,
    pub summary_raw: String,
    pub summary_inherited: bool,
    pub summary_count: u32,
    entries: Vec<IEntry>,
}

fn opt_u64(r: &mut Rd) -> Result<Option<u64>, E> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.u64()?)),
        _ => Err(E::Value),
    }
}
fn opt_i64(r: &mut Rd) -> Result<Option<i64>, E> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.u64()? as i64)),
        _ => Err(E::Value),
    }
}
fn opt_str(r: &mut Rd) -> Result<Option<String>, E> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.str16(256)?)),
        _ => Err(E::Value),
    }
}
fn read_obs(r: &mut Rd) -> Result<IObs, E> {
    let state = r.u8()?;
    if state > 2 {
        return Err(E::Value);
    }
    let raw = r.str16(256)?;
    let file_type = r.str16(32)?;
    let is_symlink = boolean(r.u8()?)?;
    Ok(IObs {
        state,
        raw,
        file_type,
        is_symlink,
        dev: opt_u64(r)?,
        inode: opt_u64(r)?,
        size: opt_u64(r)?,
        mtime_secs: opt_i64(r)?,
        mtime_nanos: opt_i64(r)?,
        read_error_class: opt_str(r)?,
    })
}

pub fn decode_cpuset_chain(b: &[u8]) -> Result<CpusetChain, E> {
    let mut r = Rd::new(b);
    r.tag32(CPUSET_CHAIN_KIND)?;
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let arch = arch(r.u8()?)?;
    let role = one_of(r.u8()?, 1)?;
    let spec = r.arr::<32>()?;
    let guest_set = r.arr::<32>()?;
    let leaf_scope = r.str16(128)?;
    let source_cgroup_path = r.str16(128)?;
    let summary_raw = r.str16(256)?;
    let summary_inherited = boolean(r.u8()?)?;
    let summary_count = r.u32()?;
    let n = r.u32()?;
    if n > 4096 {
        return Err(E::Count);
    }
    let mut entries = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let cgroup_path = r.str16(128)?;
        let order = r.u32()?;
        let first = read_obs(&mut r)?;
        let second = read_obs(&mut r)?;
        entries.push(IEntry {
            cgroup_path,
            order,
            first,
            second,
        });
    }
    r.end()?;
    Ok(CpusetChain {
        candidate,
        arch,
        role,
        spec,
        guest_set,
        leaf_scope,
        source_cgroup_path,
        summary_raw,
        summary_inherited,
        summary_count,
        entries,
    })
}

fn obs_canon(o: &IObs) -> String {
    let ou = |x: &Option<u64>| x.map(|v| v.to_string()).unwrap_or_else(|| "_".into());
    let oi = |x: &Option<i64>| x.map(|v| v.to_string()).unwrap_or_else(|| "_".into());
    let oe = o.read_error_class.clone().unwrap_or_else(|| "_".into());
    format!(
        "{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
        o.state,
        o.raw,
        o.file_type,
        o.is_symlink as u8,
        ou(&o.dev),
        ou(&o.inode),
        ou(&o.size),
        oi(&o.mtime_secs),
        oi(&o.mtime_nanos),
        oe
    )
}

/// The cpuset probe-chain content address (the SAME domain-separated rule the reference uses).
pub fn cpuset_chain_address(c: &CpusetChain) -> [u8; 32] {
    let mut canonical = String::from("b0-final-cpuset-probe-chain/v1");
    for e in &c.entries {
        canonical.push_str(&format!(
            "|entry:{}:{}:[{}]:[{}]",
            e.order,
            e.cgroup_path,
            obs_canon(&e.first),
            obs_canon(&e.second)
        ));
    }
    let mut h = blake3::Hasher::new();
    h.update(b"b0-final-cpuset-probe-chain-hash/v1\0");
    h.update(canonical.as_bytes());
    *h.finalize().as_bytes()
}

fn count_cpu_list_i(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty".into());
    }
    let mut total = 0u32;
    for tok in s.split(',') {
        let tok = tok.trim();
        if let Some((a, b)) = tok.split_once('-') {
            let lo: u32 = a.trim().parse().map_err(|_| "lo")?;
            let hi: u32 = b.trim().parse().map_err(|_| "hi")?;
            if hi < lo {
                return Err("inverted".into());
            }
            total += hi - lo + 1;
        } else {
            tok.parse::<u32>().map_err(|_| "idx")?;
            total += 1;
        }
    }
    Ok(total)
}
fn is_anc_or_self(anc: &str, leaf: &str) -> bool {
    anc == leaf || anc == "/" || matches!(leaf.strip_prefix(anc), Some(r) if r.starts_with('/'))
}

/// Structurally re-validate the retained chain against its own summary (independent mirror of the
/// reference's canonical inheritance rules).
pub fn cpuset_chain_structural(c: &CpusetChain) -> Result<(), String> {
    if c.entries.is_empty() {
        return Err("empty chain".into());
    }
    for (i, e) in c.entries.iter().enumerate() {
        if e.order as usize != i {
            return Err("order".into());
        }
        let m1 = &e.first;
        let m2 = &e.second;
        if m1.state != m2.state
            || m1.raw != m2.raw
            || m1.file_type != m2.file_type
            || m1.is_symlink != m2.is_symlink
            || m1.dev != m2.dev
            || m1.inode != m2.inode
            || m1.size != m2.size
            || m1.mtime_secs != m2.mtime_secs
            || m1.mtime_nanos != m2.mtime_nanos
            || m1.read_error_class != m2.read_error_class
        {
            return Err("first != second".into());
        }
        if !is_anc_or_self(&e.cgroup_path, &c.leaf_scope) {
            return Err("not ancestor of leaf".into());
        }
        let last = i + 1 == c.entries.len();
        match e.first.state {
            2 if !last => return Err("nonempty before source".into()),
            0 | 1 if last => return Err("source not nonempty".into()),
            0..=2 => {}
            _ => return Err("bad state".into()),
        }
    }
    if c.entries[0].cgroup_path != c.leaf_scope {
        return Err("entry0 != leaf".into());
    }
    let src = c.entries.last().unwrap();
    if src.cgroup_path != c.source_cgroup_path {
        return Err("source path != summary".into());
    }
    if src.first.raw != c.summary_raw {
        return Err("source raw != summary".into());
    }
    if count_cpu_list_i(&c.summary_raw)? != c.summary_count {
        return Err("count".into());
    }
    if (src.order != 0) != c.summary_inherited {
        return Err("inherited".into());
    }
    Ok(())
}

/// Decoded runner-attestation binding + self-consistency fields (independent).
pub struct RunnerAtt {
    pub candidate: u16,
    pub role: u8,
    pub arch: u8,
    pub spec: [u8; 32],
    pub guest_set: [u8; 32],
    pub measured_source_commit: String,
    pub build_git_sha: String,
    pub ratified_pathset: String,
    pub recomputed_pathset: String,
    pub protoc_version: String,
    pub runner_blake3: [u8; 32],
    pub phase1_production_binary_blake3: [u8; 32],
    pub phase1_identity_record_blake3: [u8; 32],
    pub ratified_tooling_commit: String,
}

fn hexstr(r: &mut Rd, n: usize) -> Result<String, E> {
    let len = r.u8()? as usize;
    if len != n {
        return Err(E::Value);
    }
    let s = r.take(len)?;
    if !s
        .iter()
        .all(|&x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    {
        return Err(E::Value);
    }
    Ok(String::from_utf8(s.to_vec()).expect("hex"))
}

pub fn decode_runner_attestation(b: &[u8]) -> Result<RunnerAtt, E> {
    let mut r = Rd::new(b);
    if r.u16()? != 4 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let role = one_of(r.u8()?, 1)?;
    let spec = r.arr::<32>()?;
    let guest_set = r.arr::<32>()?;
    let arch = arch(r.u8()?)?;
    let _exec_head = hexstr(&mut r, 40)?;
    let ratified_tooling_commit = hexstr(&mut r, 40)?;
    let ratified_pathset = hexstr(&mut r, 64)?;
    let recomputed_pathset = hexstr(&mut r, 64)?;
    let measured_source_commit = hexstr(&mut r, 40)?;
    let build_git_sha = hexstr(&mut r, 40)?;
    let _measured_ctx = r.arr::<32>()?;
    let _runner_sha = r.arr::<32>()?;
    let runner_blake3 = r.arr::<32>()?;
    let _builder = r.arr::<32>()?;
    let _pb_sha = r.arr::<32>()?;
    let _pb_blake = r.arr::<32>()?;
    let _protoc_sha = r.arr::<32>()?;
    let _protoc_blake = r.arr::<32>()?;
    let vlen = r.u8()? as u32;
    let protoc_version = {
        let s = r.take(vlen as usize)?;
        if !s.iter().all(|&x| (0x20..=0x7E).contains(&x)) {
            return Err(E::Value);
        }
        String::from_utf8(s.to_vec()).expect("ascii")
    };
    let _docker = r.arr::<32>()?;
    let _repro = r.arr::<32>()?;
    let phase1_production_binary_blake3 = r.arr::<32>()?;
    let phase1_identity_record_blake3 = r.arr::<32>()?;
    r.end()?;
    Ok(RunnerAtt {
        candidate,
        role,
        arch,
        spec,
        guest_set,
        measured_source_commit,
        build_git_sha,
        ratified_pathset,
        recomputed_pathset,
        protoc_version,
        runner_blake3,
        phase1_production_binary_blake3,
        phase1_identity_record_blake3,
        ratified_tooling_commit,
    })
}

/// The runner-attestation content address = BLAKE3(prefix ‖ canonical bytes). Because the retained
/// bytes ARE the canonical encoding (decode enforced no trailing bytes), the address is over them.
pub fn runner_attestation_address(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(RUNNER_ATT_PREFIX);
    h.update(canonical_bytes);
    *h.finalize().as_bytes()
}

/// Bind a retained cpuset chain to its provenance (independent).
pub fn bind_cpuset_chain(c: &CpusetChain, p: &Prov, addr: [u8; 32]) -> Result<(), String> {
    cpuset_chain_structural(c)?;
    if c.candidate != p.candidate
        || c.arch != p.arch
        || c.role != p.role
        || c.spec != p.spec
        || c.guest_set != p.guest_set
    {
        return Err("cpuset chain binding".into());
    }
    if c.source_cgroup_path != p.cpuset_source_cgroup_path
        || c.summary_raw != p.cpuset_raw
        || c.summary_inherited != p.cpuset_inherited
        || c.summary_count != p.cpuset
    {
        return Err("cpuset chain summary".into());
    }
    if cpuset_chain_address(c) != p.cpuset_probe_chain_blake3 {
        return Err("cpuset chain address".into());
    }
    if addr != p.cpuset_probe_chain_blake3 {
        return Err("cpuset chain address (recomputed) != provenance".into());
    }
    Ok(())
}

/// Bind a retained runner attestation to its provenance (independent).
pub fn bind_runner_attestation(a: &RunnerAtt, p: &Prov, addr: [u8; 32]) -> Result<(), String> {
    if a.build_git_sha != a.measured_source_commit {
        return Err("build_git_sha != measured".into());
    }
    if a.recomputed_pathset != a.ratified_pathset {
        return Err("recomputed path-set != ratified".into());
    }
    if a.protoc_version != "libprotoc 3.21.12" {
        return Err("protoc version".into());
    }
    // Runner continuity: the Phase-1 identity runner binary equals the measurement runner binary.
    if a.phase1_production_binary_blake3 != a.runner_blake3 {
        return Err(
            "phase1 production_binary_blake3 != runner_blake3 (runner substitution)".into(),
        );
    }
    if a.candidate != p.candidate
        || a.role != p.role
        || a.arch != p.arch
        || a.spec != p.spec
        || a.guest_set != p.guest_set
    {
        return Err("runner attestation binding".into());
    }
    if addr != p.runner_attestation_blake3 {
        return Err("runner attestation address != provenance".into());
    }
    Ok(())
}

// ===================== retained Phase-1 identity record (independent mirror) =====================
//
// The reference retains the authentic Phase-1 identity record per provenance and binds the runner
// attestation to it (`phase1_identity_record_blake3`). This independent code decodes it from scratch,
// recomputes its domain-separated address, requires it equals the bound attestation field, enforces
// the exact identity set, and requires
// `production_binary_blake3 == phase1_production_binary_blake3 == runner_blake3` plus the same
// candidate/arch/measured-source/tooling/spec — the sealed-import continuity anchor.

const PHASE1_IDENTITY_KIND: &[u8; 32] = b"b0-final-phase1-identity-rec-v1\0";
const PHASE1_IDENTITY_PREFIX: &[u8] = b"b0-final-phase1-identity-record/v1\0";

pub struct IdentityRec {
    pub candidate: u16,
    pub arch: u8,
    pub source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub spec: [u8; 32],
    pub production_binary_blake3: [u8; 32],
}

pub fn decode_identity_record(b: &[u8]) -> Result<IdentityRec, E> {
    let mut r = Rd::new(b);
    r.tag32(PHASE1_IDENTITY_KIND)?;
    if r.u16()? != 1 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let arch = arch(r.u8()?)?;
    let source_commit = hexstr(&mut r, 40)?;
    let tooling_commit = hexstr(&mut r, 40)?;
    let tooling_pathset_blake3 = hexstr(&mut r, 64)?;
    let spec = r.arr::<32>()?;
    let production_binary_blake3 = r.arr::<32>()?;
    r.end()?;
    Ok(IdentityRec {
        candidate,
        arch,
        source_commit,
        tooling_commit,
        tooling_pathset_blake3,
        spec,
        production_binary_blake3,
    })
}

/// The Phase-1 identity record address = BLAKE3(prefix ‖ canonical bytes) (retained bytes == encode).
pub fn identity_record_address(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PHASE1_IDENTITY_PREFIX);
    h.update(canonical_bytes);
    *h.finalize().as_bytes()
}

/// Bind a retained Phase-1 identity record to its runner attestation (independent).
pub fn bind_identity_record(
    rec: &IdentityRec,
    att: &RunnerAtt,
    addr: [u8; 32],
) -> Result<(), String> {
    if addr != att.phase1_identity_record_blake3 {
        return Err("retained identity record address != attestation bound address".into());
    }
    if rec.production_binary_blake3 != att.phase1_production_binary_blake3
        || rec.production_binary_blake3 != att.runner_blake3
    {
        return Err(
            "retained production_binary_blake3 != phase1/runner_blake3 (substitution or mutually-edited \
             attestation)"
                .into(),
        );
    }
    if rec.candidate != att.candidate || rec.arch != att.arch {
        return Err("retained identity record candidate/arch != attestation".into());
    }
    if rec.source_commit != att.measured_source_commit {
        return Err("retained source_commit != measured_source_commit".into());
    }
    if rec.tooling_commit != att.ratified_tooling_commit {
        return Err("retained tooling_commit != attestation".into());
    }
    if rec.tooling_pathset_blake3 != att.ratified_pathset {
        return Err("retained tooling path-set != attestation".into());
    }
    if rec.spec != att.spec {
        return Err("retained spec != attestation spec".into());
    }
    Ok(())
}

/// Exact retained Phase-1 identity set (distinct arches; no Risc0/aarch64/missing/extra).
pub fn require_exact_identity_set(candidate: u16, records: &[IdentityRec]) -> Result<(), String> {
    use std::collections::BTreeSet;
    let mut arches: BTreeSet<u8> = BTreeSet::new();
    for r in records {
        if r.candidate != candidate {
            return Err("retained identity record candidate != bundle".into());
        }
        if candidate == 2 && r.arch == 2 {
            return Err("retained Risc0/aarch64 identity record".into());
        }
        arches.insert(r.arch);
    }
    let want: BTreeSet<u8> = if candidate == 1 {
        [1u8, 2].into_iter().collect()
    } else {
        [1u8].into_iter().collect()
    };
    if arches != want {
        return Err("retained identity set arches != required".into());
    }
    Ok(())
}

//! Independent decoders + validation for the R0 closure formats that gate
//! B0-FINAL selection (envelope, verifier material, allowlist, provenance,
//! benchmark records, result set). From-scratch code over the independent
//! reader; no shared codec with the reference. It consumes canonical bytes the
//! reference produces, parses them independently, recomputes every
//! selection-relevant identity/aggregate, and rejects invalid or mixed evidence.

use crate::rd::{Rd, E};
use crate::tags;

// Frozen completeness under the reviewed two-cell measurement model (each candidate is measured on
// x86_64 ONLY; SP1/aarch64 terminal Groth16 and RISC0/aarch64 are ratified-UNSUPPORTED). x86_64-only
// grid = 1 arch × 2 statements × 10 iters = 20 measured proofs; 2000 verify-timing samples; 20 each of
// prove-time / proof-bytes / setup / proving-run-rss / verify-batch-rss. `ITERS` stays 10.
const ITERS: u32 = 10;
const MEASURED_PROOFS: u32 = 20;
const VERIFY_TIMING: u32 = 2000;
const PROVE_TIME: u32 = 20;
const PROOF_BYTES: u32 = 20;
const SETUP_SAMPLES: u32 = 20;
const PROVING_RSS: u32 = 20;
const VERIFY_RSS: u32 = 20;

/// The natively-measured arch set (x86_64 = repr 1 ONLY). Named const so the grid / provenance-set
/// loops are not `single_element_loop` clippy violations. A fabricated aarch64 (repr 2) measurement is
/// refused because it cannot appear in the expected grid built from this set.
const ARCHES: [u8; 1] = [1];

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
    pub stmt: [u8; 32],
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
    let stmt = r.arr::<32>()?;
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
        stmt,
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
    pub malformed_corpus_result_hash: [u8; 32],
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

    let malformed_corpus_result_hash = r.arr::<32>()?;
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
        malformed_corpus_result_hash,
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
    for a in ARCHES {
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
    for a in ARCHES {
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
    // v6 runner path-independence
    pub runner_build_recipe_blake3: [u8; 32],
    pub rustc_invocation_inventory_a_blake3: [u8; 32],
    pub rustc_invocation_inventory_b_blake3: [u8; 32],
    pub runner_double_build_proof_blake3: [u8; 32],
    pub runner_leakage_report_blake3: [u8; 32],
    pub per_arch_toolchain_identity: [u8; 32],
    pub runner_build_recipe_id: [u8; 32],
    pub protobuf_authority_sha256: [u8; 32],
    pub protobuf_authority_blake3: [u8; 32],
    // v7: the retained DependencySeedV1 record address the attestation BINDS (the cargo dependency-seed
    // anchor requires it == the independently-authenticated retained record's address).
    pub dependency_seed_address: [u8; 32],
    // v8: the canonical SP1 guest artifact address (SP1 only; all-zero for RISC0).
    pub canonical_sp1_guest_artifact_address: [u8; 32],
    pub measurement_input_authority_address: [u8; 32],
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

// v9: independent mirror of RunnerAttestationV1 — decodes the measurement-input authority address.
pub fn decode_runner_attestation(b: &[u8]) -> Result<RunnerAtt, E> {
    let mut r = Rd::new(b);
    if r.u16()? != 9 {
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
    let protobuf_authority_sha256 = r.arr::<32>()?;
    let protobuf_authority_blake3 = r.arr::<32>()?;
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
    let runner_build_recipe_blake3 = r.arr::<32>()?;
    let rustc_invocation_inventory_a_blake3 = r.arr::<32>()?;
    let rustc_invocation_inventory_b_blake3 = r.arr::<32>()?;
    let runner_double_build_proof_blake3 = r.arr::<32>()?;
    let runner_leakage_report_blake3 = r.arr::<32>()?;
    let per_arch_toolchain_identity = r.arr::<32>()?;
    let runner_build_recipe_id = r.arr::<32>()?;
    // v7: offline-provisioning authority addresses (host toolchain / dependency seed / protoc). The
    // dependency-seed address is CAPTURED (not discarded) so the sealed-import anchor can require it to
    // equal the independently-authenticated retained DependencySeedV1 record's address; the other two are
    // covered by the canonical-bytes attestation address (re-hashed over the exact retained bytes).
    let _host_toolchain_attestation_address = r.arr::<32>()?;
    let dependency_seed_address = r.arr::<32>()?;
    let _protoc_authority_address = r.arr::<32>()?;
    // v8: the canonical SP1 guest artifact address (SP1 only; all-zero for RISC0). CAPTURED (not
    // discarded) so the independent verifier can re-check the same measurement-time == Phase-1 mapping.
    let canonical_sp1_guest_artifact_address = r.arr::<32>()?;
    // v9: the measurement-wide MeasurementInputAuthorityV1 address (ALL candidates).
    let measurement_input_authority_address = r.arr::<32>()?;
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
        runner_build_recipe_blake3,
        rustc_invocation_inventory_a_blake3,
        rustc_invocation_inventory_b_blake3,
        runner_double_build_proof_blake3,
        runner_leakage_report_blake3,
        per_arch_toolchain_identity,
        runner_build_recipe_id,
        protobuf_authority_sha256,
        protobuf_authority_blake3,
        dependency_seed_address,
        canonical_sp1_guest_artifact_address,
        measurement_input_authority_address,
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

// ==== v9: records-authoritative guest set — independent from-scratch mirror (Phase1IdentityRecordV2) ====
//
// The retained V2 record set is the AUTHORITATIVE source of the multi-arch guest set. This mirror decodes
// the three V2 records from scratch, authenticates their canonical encoding, requires the EXACT canonical
// set, then RE-DERIVES the allowlist bytes + r0_guest_set_hash FROM the records (reconciling the two SP1
// arches into one entry) — never trusting the producer-baked allowlist. It cross-binds each V2 record to
// its continuity V1 subset. V2 carries its OWN domain/kind (never decodes a V1 record and vice versa).
const PHASE1_IDENTITY_V2_KIND: &[u8; 32] = b"b0-final-phase1-identity-rec-v2\0";
const PHASE1_IDENTITY_V2_PREFIX: &[u8] = b"b0-final-phase1-identity-record/v2\0";

#[derive(Clone)]
pub struct IdentityRecV2 {
    // continuity subset (cross-bound to the corresponding V1 record)
    pub candidate: u16,
    pub arch: u8,
    pub source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub spec: [u8; 32],
    pub production_binary_blake3: [u8; 32],
    // full Phase-1 guest identity
    pub guest_source_tree_hash: [u8; 32],
    pub candidate_dep_lock_hash: [u8; 32],
    pub guest_image_hash: [u8; 32],
    pub program_id: [u8; 32],
    pub builder_container_digest: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub build_command_hash: [u8; 32],
    pub toolchain_identity: String,                   // 64-hex
    pub canonical_sp1_guest_artifact_address: String, // SP1: 64-hex; RISC0: empty
}

/// Read a hex string that is EITHER empty (len 0) OR exactly `n` hex chars.
fn hexstr_0_or(r: &mut Rd, n: usize) -> Result<String, E> {
    let len = r.u8()? as usize;
    if len != 0 && len != n {
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

pub fn decode_identity_record_v2(b: &[u8]) -> Result<IdentityRecV2, E> {
    let mut r = Rd::new(b);
    r.tag32(PHASE1_IDENTITY_V2_KIND)?;
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
    let guest_source_tree_hash = r.arr::<32>()?;
    let candidate_dep_lock_hash = r.arr::<32>()?;
    let guest_image_hash = r.arr::<32>()?;
    let program_id = r.arr::<32>()?;
    let builder_container_digest = r.arr::<32>()?;
    let verifier_material_manifest_hash = r.arr::<32>()?;
    let build_command_hash = r.arr::<32>()?;
    let toolchain_identity = hexstr(&mut r, 64)?;
    let canonical_sp1_guest_artifact_address = hexstr_0_or(&mut r, 64)?;
    r.end()?;
    Ok(IdentityRecV2 {
        candidate,
        arch,
        source_commit,
        tooling_commit,
        tooling_pathset_blake3,
        spec,
        production_binary_blake3,
        guest_source_tree_hash,
        candidate_dep_lock_hash,
        guest_image_hash,
        program_id,
        builder_container_digest,
        verifier_material_manifest_hash,
        build_command_hash,
        toolchain_identity,
        canonical_sp1_guest_artifact_address,
    })
}

fn w_hexstr_v2(w: &mut Vec<u8>, s: &str) {
    w.push(s.len() as u8);
    w.extend_from_slice(s.as_bytes());
}

/// Canonical re-encode (mirror of `Phase1IdentityRecordV2::encode`, LE codec). Used to authenticate the
/// retained record is canonically encoded (byte-identical re-encode) and to recompute its address.
pub fn encode_identity_record_v2(v: &IdentityRecV2) -> Vec<u8> {
    let mut w = Vec::new();
    w.extend_from_slice(PHASE1_IDENTITY_V2_KIND);
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&v.candidate.to_le_bytes());
    w.push(v.arch);
    w_hexstr_v2(&mut w, &v.source_commit);
    w_hexstr_v2(&mut w, &v.tooling_commit);
    w_hexstr_v2(&mut w, &v.tooling_pathset_blake3);
    w.extend_from_slice(&v.spec);
    w.extend_from_slice(&v.production_binary_blake3);
    w.extend_from_slice(&v.guest_source_tree_hash);
    w.extend_from_slice(&v.candidate_dep_lock_hash);
    w.extend_from_slice(&v.guest_image_hash);
    w.extend_from_slice(&v.program_id);
    w.extend_from_slice(&v.builder_container_digest);
    w.extend_from_slice(&v.verifier_material_manifest_hash);
    w.extend_from_slice(&v.build_command_hash);
    w_hexstr_v2(&mut w, &v.toolchain_identity);
    w_hexstr_v2(&mut w, &v.canonical_sp1_guest_artifact_address);
    w
}

/// Domain-separated V2 address = BLAKE3(prefix ‖ canonical bytes).
pub fn identity_record_v2_address(canonical_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PHASE1_IDENTITY_V2_PREFIX);
    h.update(canonical_bytes);
    *h.finalize().as_bytes()
}

/// True iff the V1 continuity record equals the V2 record's continuity subset (neither substitutable).
pub fn v2_matches_v1_continuity(v1: &IdentityRec, v2: &IdentityRecV2) -> bool {
    v1.candidate == v2.candidate
        && v1.arch == v2.arch
        && v1.source_commit == v2.source_commit
        && v1.tooling_commit == v2.tooling_commit
        && v1.tooling_pathset_blake3 == v2.tooling_pathset_blake3
        && v1.spec == v2.spec
        && v1.production_binary_blake3 == v2.production_binary_blake3
}

/// EXACT retained V2 identity set in canonical order: SP1/x86_64, SP1/aarch64 (identity-only), RISC0/x86_64.
/// Refuses missing/duplicate/reordered/extra and RISC0/aarch64.
pub fn require_exact_v2_identity_set(records: &[IdentityRecV2]) -> Result<(), String> {
    let want: [(u16, u8); 3] = [(1, 1), (1, 2), (2, 1)];
    if records.len() != want.len() {
        return Err(format!(
            "expected exactly {} retained V2 identity records (Sp1 x86_64/aarch64, Risc0 x86_64), got {}",
            want.len(),
            records.len()
        ));
    }
    for (i, (wc, wa)) in want.iter().enumerate() {
        if records[i].candidate != *wc || records[i].arch != *wa {
            return Err(format!(
                "retained V2 identity set member {i} != required canonical (candidate {wc}, arch {wa})"
            ));
        }
    }
    Ok(())
}

fn need_hex32_str(s: &str, ctx: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("{ctx}: expected 64-hex, got {} chars", s.len()));
    }
    let mut o = [0u8; 32];
    for (i, out) in o.iter_mut().enumerate() {
        *out =
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| format!("{ctx}: not hex"))?;
    }
    Ok(o)
}

#[allow(clippy::too_many_arguments)]
fn push_allow_entry(
    w: &mut Vec<u8>,
    candidate: u16,
    spec: &[u8; 32],
    guest_source_tree_hash: &[u8; 32],
    candidate_dep_lock_hash: &[u8; 32],
    arches: &[(u8, [u8; 32])],
    guest_image_hash: &[u8; 32],
    program_id: &[u8; 32],
    verifier_material_manifest_hash: &[u8; 32],
    build_command_hash: &[u8; 32],
    reproducible: bool,
) {
    w.extend_from_slice(&candidate.to_le_bytes());
    w.extend_from_slice(spec);
    w.extend_from_slice(guest_source_tree_hash);
    w.extend_from_slice(candidate_dep_lock_hash);
    w.push(arches.len() as u8);
    for (a, d) in arches {
        w.push(*a);
        w.extend_from_slice(d);
    }
    w.extend_from_slice(guest_image_hash);
    w.extend_from_slice(program_id);
    w.extend_from_slice(verifier_material_manifest_hash);
    w.extend_from_slice(build_command_hash);
    w.push(if reproducible { 1 } else { 0 });
}

/// From-scratch mirror of `derive_guest_set`: validate each V2 record against the ratified measured source,
/// merged spec, and two-root tooling shape; reconcile the two SP1 arches into one entry; then ENCODE the
/// canonical allowlist bytes (mirror of `GuestProgramAllowlistV1::encode`) and compute the guest-set hash.
/// Returns `(allowlist_bytes, r0_guest_set_hash)` — the caller requires the retained allowlist to equal
/// these exact bytes. `spec_hex` is the merged finalized spec (64-hex); `measured_source` is ratified 40-hex.
pub fn derive_guest_set_from_v2(
    records: &[IdentityRecV2],
    spec_hex: &str,
    measured_source: &str,
) -> Result<(Vec<u8>, [u8; 32]), String> {
    require_exact_v2_identity_set(records)?;
    let spec_bytes = need_hex32_str(spec_hex, "spec")?;
    let sp1_x86 = &records[0];
    let sp1_arm = &records[1];
    let risc0_x86 = &records[2];

    // Per-record admissibility (mirror of validate_record's identity-relevant rules).
    for r in records {
        if r.spec != spec_bytes {
            return Err(format!(
                "{}/{}: record spec != merged finalized spec",
                r.candidate, r.arch
            ));
        }
        // EXACT measured-source authority.
        if r.source_commit != measured_source {
            return Err(format!(
                "{}/{}: source commit {} != ratified measured source",
                r.candidate, r.arch, r.source_commit
            ));
        }
        // Two-root separation: tooling_commit must be a 40-hex commit distinct from the measured source.
        if r.tooling_commit.len() != 40 {
            return Err(format!(
                "{}/{}: tooling_commit not 40-hex",
                r.candidate, r.arch
            ));
        }
        if r.tooling_commit == measured_source {
            return Err(format!(
                "{}/{}: tooling_commit equals the measured-source commit (two-root model forbids conflation)",
                r.candidate, r.arch
            ));
        }
        // Canonical SP1 guest artifact: SP1 records MUST bind a 64-hex address; RISC0 must NOT carry one.
        match r.candidate {
            1 => {
                if r.canonical_sp1_guest_artifact_address.len() != 64 {
                    return Err(format!(
                        "Sp1/{}: missing 64-hex canonical SP1 guest artifact address",
                        r.arch
                    ));
                }
            }
            _ => {
                if !r.canonical_sp1_guest_artifact_address.is_empty() {
                    return Err(format!(
                        "Risc0/{}: must NOT carry a canonical SP1 guest artifact address",
                        r.arch
                    ));
                }
            }
        }
    }

    // All records share ONE reconciled source checkout.
    if sp1_x86.source_commit != risc0_x86.source_commit {
        return Err("records span different source commits".into());
    }

    // SP1 x86_64/aarch64 must agree on the shared guest identity + two-root authority + canonical artifact.
    let disagree = |field: &str, ok: bool| -> Result<(), String> {
        if ok {
            Ok(())
        } else {
            Err(format!("SP1 x86_64/aarch64 disagree on {field}"))
        }
    };
    disagree("program_id", sp1_x86.program_id == sp1_arm.program_id)?;
    disagree(
        "guest_image_hash",
        sp1_x86.guest_image_hash == sp1_arm.guest_image_hash,
    )?;
    disagree(
        "guest_source_tree_hash",
        sp1_x86.guest_source_tree_hash == sp1_arm.guest_source_tree_hash,
    )?;
    disagree(
        "candidate_dep_lock_hash",
        sp1_x86.candidate_dep_lock_hash == sp1_arm.candidate_dep_lock_hash,
    )?;
    disagree(
        "verifier_material_manifest_hash",
        sp1_x86.verifier_material_manifest_hash == sp1_arm.verifier_material_manifest_hash,
    )?;
    disagree(
        "build_command_hash",
        sp1_x86.build_command_hash == sp1_arm.build_command_hash,
    )?;
    disagree(
        "source_commit",
        sp1_x86.source_commit == sp1_arm.source_commit,
    )?;
    disagree(
        "tooling_commit",
        sp1_x86.tooling_commit == sp1_arm.tooling_commit,
    )?;
    disagree(
        "tooling_pathset_blake3",
        sp1_x86.tooling_pathset_blake3 == sp1_arm.tooling_pathset_blake3,
    )?;
    disagree(
        "canonical_sp1_guest_artifact_address",
        sp1_x86.canonical_sp1_guest_artifact_address
            == sp1_arm.canonical_sp1_guest_artifact_address,
    )?;

    // Encode the canonical allowlist: entries sorted by candidate.to_repr() (Sp1=1 then Risc0=2).
    let mut al = Vec::new();
    al.extend_from_slice(&1u16.to_le_bytes()); // SCHEMA_VERSION
    al.extend_from_slice(&2u32.to_le_bytes()); // two entries
    push_allow_entry(
        &mut al,
        1,
        &spec_bytes,
        &sp1_x86.guest_source_tree_hash,
        &sp1_x86.candidate_dep_lock_hash,
        &[
            (1, sp1_x86.builder_container_digest),
            (2, sp1_arm.builder_container_digest),
        ],
        &sp1_x86.guest_image_hash,
        &sp1_x86.program_id,
        &sp1_x86.verifier_material_manifest_hash,
        &sp1_x86.build_command_hash,
        true,
    );
    push_allow_entry(
        &mut al,
        2,
        &spec_bytes,
        &risc0_x86.guest_source_tree_hash,
        &risc0_x86.candidate_dep_lock_hash,
        &[(1, risc0_x86.builder_container_digest)],
        &risc0_x86.guest_image_hash,
        &risc0_x86.program_id,
        &risc0_x86.verifier_material_manifest_hash,
        &risc0_x86.build_command_hash,
        true,
    );
    let gs = Allowlist::guest_set_hash(&al);
    Ok((al, gs))
}

// ============ v6: runner path-independence (independent from-scratch mirror, exact bytes) ============
const RUNNER_BUILD_RECIPE_KIND: &[u8; 32] = b"b0-final-runner-build-recipe-v4\0";
const RUNNER_BUILD_RECIPE_PREFIX: &[u8] = b"b0-final-runner-build-recipe/v4\0";
const RUSTC_INV_KIND: &[u8; 32] = b"b0-final-rustc-invoc-inv-v2\0\0\0\0\0";
const RUSTC_INV_PREFIX: &[u8] = b"b0-final-rustc-invocation-inventory/v2\0";
const DBP_KIND: &[u8; 32] = b"b0-final-runner-dbl-build-proof0";
const DBP_PREFIX: &[u8] = b"b0-final-runner-double-build-proof/v4\0";
const REPRO_PAIR_DOMAIN: &[u8] = b"b0-final-runner-reproducibility-pair/v1\0";
const LEAK_KIND: &[u8; 32] = b"b0-final-runner-leak-report-v2\0\0";
const LEAK_PREFIX: &[u8] = b"b0-final-runner-leakage-report/v2\0";
const CANON_TOOLING: &str = "/b0/tooling";
const CANON_CARGO: &str = "/b0/cargo";
const CANON_TARGET: &str = "/b0/target";
// RISC0-only permitted prefix: the pinned guest-embed HOME the RISC0 guest build materializes fresh
// per build (SP1 has no embedded guest home). Must match the validator's `CANON_GUESTHOME`.
const CANON_GUESTHOME: &str = "/b0/guesthome";
const REMAP_RECIPE_DOMAIN: &str = "b0-final-runner-remap-recipe/v1";
const UNIT_SEP: u8 = 0x1f;
const INVOCATION_RECORD_HEADER: &str = "b0-final-rustc-invocation/v2";

fn str16(r: &mut Rd, max: usize) -> Result<String, E> {
    let len = r.u16()? as usize;
    if len > max {
        return Err(E::Value);
    }
    let s = r.take(len)?;
    if !s.iter().all(|&c| (0x20..=0x7e).contains(&c)) {
        return Err(E::Value);
    }
    Ok(String::from_utf8(s.to_vec()).expect("ascii"))
}
fn blob32(r: &mut Rd, max: usize) -> Result<Vec<u8>, E> {
    let n = r.u32()? as usize;
    if n > max {
        return Err(E::Value);
    }
    Ok(r.take(n)?.to_vec())
}
fn vec_str(r: &mut Rd, maxcount: usize, maxstr: usize) -> Result<Vec<String>, E> {
    let n = r.u32()? as usize;
    if n > maxcount {
        return Err(E::Value);
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(str16(r, maxstr)?);
    }
    Ok(v)
}
/// Parse a `--remap-path-prefix=FROM=TO` arg into `(from, to)`.
fn parse_remap_arg(s: &str) -> Result<(String, String), String> {
    let rest = s
        .strip_prefix("--remap-path-prefix=")
        .ok_or_else(|| "not a --remap-path-prefix arg".to_string())?;
    let eq = rest
        .rfind('=')
        .ok_or_else(|| "remap arg has no FROM=TO".to_string())?;
    Ok((rest[..eq].to_string(), rest[eq + 1..].to_string()))
}

pub fn compute_recipe_id(measured_source_commit: &str, wrapper_blake3: &[u8; 32]) -> [u8; 32] {
    use std::fmt::Write as _;
    let mut wh = String::with_capacity(64);
    for b in wrapper_blake3 {
        let _ = write!(wh, "{b:02x}");
    }
    let pre = format!(
        "{REMAP_RECIPE_DOMAIN}|build_at={CANON_TOOLING}|cargo_home={CANON_CARGO}(canonical-by-construction,fresh-per-build)|remap:target={CANON_TARGET}|encoded_rustflags=unit-separator-1-remap|flags=--locked|SOURCE_DATE_EPOCH=0|BUILD_GIT_SHA={measured_source_commit}|toolchain=ratified-per-arch(authority-record)|wrapper_blake3={wh}"
    );
    *blake3::hash(pre.as_bytes()).as_bytes()
}

pub struct RecipeSide {
    pub original_root: String,
    pub target_from: String,
    pub encoded_rustflags: Vec<u8>,
}
impl RecipeSide {
    fn decode(r: &mut Rd) -> Result<Self, E> {
        Ok(Self {
            original_root: str16(r, 4096)?,
            target_from: str16(r, 4096)?,
            encoded_rustflags: blob32(r, 65536)?,
        })
    }
    /// Parse the exact encoded rustflags into the SINGLE `(from, to)` remap. Enforces exactly ONE
    /// `--remap-path-prefix=FROM=TO` arg (no unit separator; the canonical cargo home is NOT remapped —
    /// canonical by construction).
    fn parse_one_remap(&self) -> Result<(String, String), String> {
        let parts: Vec<&[u8]> = self.encoded_rustflags.split(|&b| b == UNIT_SEP).collect();
        if parts.len() != 1 {
            return Err("encoded rustflags is not exactly one remap".into());
        }
        let s = std::str::from_utf8(parts[0]).map_err(|_| "remap arg not UTF-8".to_string())?;
        parse_remap_arg(s)
    }
    fn check(&self, which: &str) -> Result<(), String> {
        let (f0, t0) = self.parse_one_remap()?;
        if f0 != self.target_from || t0 != CANON_TARGET {
            return Err(format!("build {which} target remap != recipe root"));
        }
        if self.original_root == self.target_from {
            return Err(format!("build {which} roots not distinct"));
        }
        if self
            .target_from
            .starts_with(&format!("{}/", self.original_root))
            || self
                .original_root
                .starts_with(&format!("{}/", self.target_from))
        {
            return Err(format!("build {which} roots overlap"));
        }
        Ok(())
    }
}

pub struct BuildRecipe {
    pub candidate: u16,
    pub arch: u8,
    pub recipe_id: [u8; 32],
    pub build_argv: Vec<String>,
    pub build_env: Vec<(String, String)>,
    pub manifest_path: String,
    pub cargo_ident: String,
    pub b0_venue_embed: String,
    pub canonical_build_path: String,
    pub canonical_cargo_home: String,
    pub build_a: RecipeSide,
    pub build_b: RecipeSide,
    pub measured_source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub per_arch_toolchain_identity: [u8; 32],
    pub protobuf_authority_sha256: [u8; 32],
    pub protobuf_authority_blake3: [u8; 32],
    pub wrapper_blake3: [u8; 32],
}
pub fn decode_runner_build_recipe(b: &[u8]) -> Result<BuildRecipe, E> {
    let mut r = Rd::new(b);
    r.tag32(RUNNER_BUILD_RECIPE_KIND)?;
    if r.u16()? != 4 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let arch = arch(r.u8()?)?;
    let recipe_id = r.arr::<32>()?;
    let build_argv = vec_str(&mut r, 64, 4096)?;
    let env_n = r.u32()? as usize;
    if env_n > 64 {
        return Err(E::Value);
    }
    let mut build_env = Vec::with_capacity(env_n);
    for _ in 0..env_n {
        let k = str16(&mut r, 256)?;
        let v = str16(&mut r, 4096)?;
        build_env.push((k, v));
    }
    let manifest_path = str16(&mut r, 4096)?;
    let _artifact_path = str16(&mut r, 4096)?;
    let cargo_ident = str16(&mut r, 4096)?;
    let b0_venue_embed = str16(&mut r, 8)?;
    let canonical_build_path = str16(&mut r, 4096)?;
    let canonical_cargo_home = str16(&mut r, 4096)?;
    let build_a = RecipeSide::decode(&mut r)?;
    let build_b = RecipeSide::decode(&mut r)?;
    let measured_source_commit = hexstr(&mut r, 40)?;
    let tooling_commit = hexstr(&mut r, 40)?;
    let tooling_pathset_blake3 = hexstr(&mut r, 64)?;
    let per_arch_toolchain_identity = r.arr::<32>()?;
    let protobuf_authority_sha256 = r.arr::<32>()?;
    let protobuf_authority_blake3 = r.arr::<32>()?;
    let wrapper_blake3 = r.arr::<32>()?;
    r.end()?;
    Ok(BuildRecipe {
        candidate,
        arch,
        recipe_id,
        build_argv,
        build_env,
        manifest_path,
        cargo_ident,
        b0_venue_embed,
        canonical_build_path,
        canonical_cargo_home,
        build_a,
        build_b,
        measured_source_commit,
        tooling_commit,
        tooling_pathset_blake3,
        per_arch_toolchain_identity,
        protobuf_authority_sha256,
        protobuf_authority_blake3,
        wrapper_blake3,
    })
}
pub fn runner_build_recipe_address(b: &[u8]) -> [u8; 32] {
    crate::prefixed(RUNNER_BUILD_RECIPE_PREFIX, b)
}

pub struct InvEntry {
    pub kind: String,
    pub remap_args: Vec<String>,
    pub record_address: [u8; 32],
}
impl InvEntry {
    fn reconstruct(&self) -> String {
        let mut s = String::from(INVOCATION_RECORD_HEADER);
        s.push_str("\nkind=");
        s.push_str(&self.kind);
        for a in &self.remap_args {
            s.push_str("\nremap_arg=");
            s.push_str(a);
        }
        s
    }
}
pub struct InvInventory {
    pub candidate: u16,
    pub arch: u8,
    pub build_tag: u8,
    pub entries: Vec<InvEntry>,
}
pub fn decode_rustc_invocation_inventory(b: &[u8]) -> Result<InvInventory, E> {
    let mut r = Rd::new(b);
    r.tag32(RUSTC_INV_KIND)?;
    if r.u16()? != 2 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let arch = arch(r.u8()?)?;
    let build_tag = r.u8()?;
    if build_tag > 1 {
        return Err(E::Value);
    }
    let count = r.u32()? as usize;
    if count == 0 || count > 4096 {
        return Err(E::Value);
    }
    let mut prev: Option<Vec<u8>> = None;
    let mut entries = Vec::new();
    for _ in 0..count {
        let kind = str16(&mut r, 16)?;
        if kind != "compile" && kind != "probe" {
            return Err(E::Value);
        }
        let nargs = r.u32()? as usize;
        if nargs > 16 {
            return Err(E::Value);
        }
        let mut remap_args = Vec::with_capacity(nargs);
        for _ in 0..nargs {
            remap_args.push(str16(&mut r, 8192)?);
        }
        let record_address = r.arr::<32>()?;
        // Rebuild the entry's canonical key (matches the validator encode) for the ascending check.
        let mut key = Vec::new();
        key.extend_from_slice(&(kind.len() as u16).to_le_bytes());
        key.extend_from_slice(kind.as_bytes());
        key.extend_from_slice(&(remap_args.len() as u32).to_le_bytes());
        for a in &remap_args {
            key.extend_from_slice(&(a.len() as u16).to_le_bytes());
            key.extend_from_slice(a.as_bytes());
        }
        key.extend_from_slice(&record_address);
        if let Some(pk) = &prev {
            if *pk >= key {
                return Err(E::Value);
            }
        }
        prev = Some(key);
        entries.push(InvEntry {
            kind,
            remap_args,
            record_address,
        });
    }
    r.end()?;
    Ok(InvInventory {
        candidate,
        arch,
        build_tag,
        entries,
    })
}
pub fn rustc_invocation_inventory_address(b: &[u8]) -> [u8; 32] {
    crate::prefixed(RUSTC_INV_PREFIX, b)
}

pub struct ProofSide {
    pub original_root: String,
    pub target_from: String,
    pub runner_sha256: [u8; 32],
    pub runner_blake3: [u8; 32],
    pub guest_image_id: [u8; 32],
    pub guest_methods_blake3: [u8; 32],
    pub inventory_address: [u8; 32],
    pub origin_manifest_blake3: [u8; 32],
    pub materialized_manifest_blake3: [u8; 32],
    pub materialized_cargo_seed_blake3: [u8; 32],
    pub materialized_risc0_home_blake3: [u8; 32],
    pub start_unix: u64,
    pub end_unix: u64,
}
impl ProofSide {
    fn decode(r: &mut Rd) -> Result<Self, E> {
        Ok(Self {
            original_root: str16(r, 4096)?,
            target_from: str16(r, 4096)?,
            runner_sha256: r.arr::<32>()?,
            runner_blake3: r.arr::<32>()?,
            guest_image_id: r.arr::<32>()?,
            guest_methods_blake3: r.arr::<32>()?,
            inventory_address: r.arr::<32>()?,
            origin_manifest_blake3: r.arr::<32>()?,
            materialized_manifest_blake3: r.arr::<32>()?,
            materialized_cargo_seed_blake3: r.arr::<32>()?,
            materialized_risc0_home_blake3: r.arr::<32>()?,
            start_unix: r.u64()?,
            end_unix: r.u64()?,
        })
    }
}
pub struct DoubleBuildProof {
    pub candidate: u16,
    pub arch: u8,
    pub wrapper_blake3: [u8; 32],
    pub build_a: ProofSide,
    pub build_b: ProofSide,
    pub cargo_seed_origin_blake3: [u8; 32],
    pub risc0_home_origin_blake3: [u8; 32],
    pub byte_equal: bool,
    pub reproducibility_pair_blake3: [u8; 32],
}
impl DoubleBuildProof {
    fn compute_repro(a: &ProofSide, b: &ProofSide) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(REPRO_PAIR_DOMAIN);
        h.update(&a.runner_sha256);
        h.update(&a.runner_blake3);
        h.update(&b.runner_sha256);
        h.update(&b.runner_blake3);
        *h.finalize().as_bytes()
    }
}
pub fn decode_runner_double_build_proof(b: &[u8]) -> Result<DoubleBuildProof, E> {
    let mut r = Rd::new(b);
    r.tag32(DBP_KIND)?;
    if r.u16()? != 4 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let arch = arch(r.u8()?)?;
    let wrapper_blake3 = r.arr::<32>()?;
    let build_a = ProofSide::decode(&mut r)?;
    let build_b = ProofSide::decode(&mut r)?;
    let cargo_seed_origin_blake3 = r.arr::<32>()?;
    let risc0_home_origin_blake3 = r.arr::<32>()?;
    let byte_equal = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(E::Value),
    };
    let reproducibility_pair_blake3 = r.arr::<32>()?;
    r.end()?;
    Ok(DoubleBuildProof {
        candidate,
        arch,
        wrapper_blake3,
        build_a,
        build_b,
        cargo_seed_origin_blake3,
        risc0_home_origin_blake3,
        byte_equal,
        reproducibility_pair_blake3,
    })
}
pub fn runner_double_build_proof_address(b: &[u8]) -> [u8; 32] {
    crate::prefixed(DBP_PREFIX, b)
}

pub struct LeakReport {
    pub candidate: u16,
    pub arch: u8,
    pub scanned_binary_blake3: [u8; 32],
    pub clean: bool,
    pub evidence_root: String,
    pub refused: Vec<String>,
    pub permitted: Vec<String>,
}
pub fn decode_runner_leakage_report(b: &[u8]) -> Result<LeakReport, E> {
    let mut r = Rd::new(b);
    r.tag32(LEAK_KIND)?;
    if r.u16()? != 2 {
        return Err(E::Value);
    }
    let candidate = candidate(r.u16()?)?;
    let arch = arch(r.u8()?)?;
    let scanned_binary_blake3 = r.arr::<32>()?;
    let clean = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(E::Value),
    };
    let evidence_root = str16(&mut r, 8192)?;
    fn read_list(r: &mut Rd, max: usize) -> Result<Vec<String>, E> {
        let n = r.u32()? as usize;
        if n > max {
            return Err(E::Value);
        }
        let mut v = Vec::new();
        let mut prev: Option<String> = None;
        for _ in 0..n {
            let s = str16(r, 8192)?;
            if let Some(p) = &prev {
                if *p >= s {
                    return Err(E::Value);
                }
            }
            prev = Some(s.clone());
            v.push(s);
        }
        Ok(v)
    }
    let refused = read_list(&mut r, 4096)?;
    let permitted = read_list(&mut r, 16)?;
    r.end()?;
    Ok(LeakReport {
        candidate,
        arch,
        scanned_binary_blake3,
        clean,
        evidence_root,
        refused,
        permitted,
    })
}
pub fn runner_leakage_report_address(b: &[u8]) -> [u8; 32] {
    crate::prefixed(LEAK_PREFIX, b)
}

/// Bind the retained runner path-independence FIVE-artifact set to the attestation (independent mirror
/// of the validator's `check_bound_runner_recipe`).
#[allow(clippy::too_many_arguments)]
pub fn bind_runner_recipe(
    a: &RunnerAtt,
    recipe: &BuildRecipe,
    recipe_addr: [u8; 32],
    inv_a: &InvInventory,
    inv_a_addr: [u8; 32],
    inv_b: &InvInventory,
    inv_b_addr: [u8; 32],
    proof: &DoubleBuildProof,
    proof_addr: [u8; 32],
    leak: &LeakReport,
    leak_addr: [u8; 32],
) -> Result<(), String> {
    // 1. addresses
    if recipe_addr != a.runner_build_recipe_blake3 {
        return Err("recipe address".into());
    }
    if inv_a_addr != a.rustc_invocation_inventory_a_blake3 {
        return Err("inventory A address".into());
    }
    if inv_b_addr != a.rustc_invocation_inventory_b_blake3 {
        return Err("inventory B address".into());
    }
    if proof_addr != a.runner_double_build_proof_blake3 {
        return Err("double-build proof address".into());
    }
    if leak_addr != a.runner_leakage_report_blake3 {
        return Err("leakage address".into());
    }
    // 2. recipe self-consistency over retained bytes + structural id
    if recipe.b0_venue_embed != "0" && recipe.b0_venue_embed != "1" {
        return Err("recipe b0_venue_embed invalid".into());
    }
    // EXACT canonical argv: `<cargo> [+tc] build --release --locked --features real-backend
    // --manifest-path <manifest>` — no duplicates, no extra features/subcommands/args, no alternate
    // manifest (a token-presence check would accept all of those).
    {
        let mut want: Vec<&str> = recipe.cargo_ident.split_whitespace().collect();
        match want.len() {
            1 => {}
            2 if want[1].starts_with('+') => {}
            _ => return Err("recipe cargo_ident must be `<cargo>` or `<cargo> +<tc>`".into()),
        }
        want.extend_from_slice(&[
            "build",
            "--release",
            "--locked",
            "--offline",
            "--features",
            "real-backend",
            "--manifest-path",
            recipe.manifest_path.as_str(),
        ]);
        let got: Vec<&str> = recipe.build_argv.iter().map(String::as_str).collect();
        if got != want {
            return Err("recipe build argv is not the exact canonical command".into());
        }
    }
    // EXACT canonical env: [(BUILD_GIT_SHA, measured), (SOURCE_DATE_EPOCH, "0"), (B0_VENUE_EMBED, embed)]
    // — no duplicate/omission/conflict/extra.
    {
        let want: [(&str, &str); 3] = [
            ("BUILD_GIT_SHA", recipe.measured_source_commit.as_str()),
            ("SOURCE_DATE_EPOCH", "0"),
            ("B0_VENUE_EMBED", recipe.b0_venue_embed.as_str()),
        ];
        if recipe.build_env.len() != want.len() {
            return Err("recipe build_env is not the canonical 3-entry vector".into());
        }
        for (i, (k, v)) in want.iter().enumerate() {
            if recipe.build_env[i].0 != *k || recipe.build_env[i].1 != *v {
                return Err("recipe build_env entry != canonical".into());
            }
        }
    }
    if recipe.canonical_build_path != CANON_TOOLING {
        return Err("recipe canonical_build_path != ratified /b0/tooling".into());
    }
    if recipe.canonical_cargo_home != CANON_CARGO {
        return Err("recipe canonical_cargo_home != ratified /b0/cargo".into());
    }
    recipe.build_a.check("A")?;
    recipe.build_b.check("B")?;
    if recipe.build_a.original_root == recipe.build_b.original_root {
        return Err("recipe build A and B share the same original checkout root".into());
    }
    if recipe.recipe_id != compute_recipe_id(&recipe.measured_source_commit, &recipe.wrapper_blake3)
    {
        return Err("recipe id != recomputed".into());
    }
    if recipe.recipe_id != a.runner_build_recipe_id {
        return Err("recipe id != attestation".into());
    }
    if compute_recipe_id(&a.measured_source_commit, &recipe.wrapper_blake3)
        != a.runner_build_recipe_id
    {
        return Err("attestation recipe id != recomputed".into());
    }
    // 3. recipe <-> attestation
    if recipe.candidate != a.candidate || recipe.arch != a.arch {
        return Err("recipe candidate/arch".into());
    }
    if recipe.measured_source_commit != a.measured_source_commit {
        return Err("recipe measured source".into());
    }
    if recipe.tooling_commit != a.ratified_tooling_commit
        || recipe.tooling_pathset_blake3 != a.ratified_pathset
    {
        return Err("recipe tooling".into());
    }
    if recipe.protobuf_authority_sha256 != a.protobuf_authority_sha256
        || recipe.protobuf_authority_blake3 != a.protobuf_authority_blake3
    {
        return Err("recipe protobuf".into());
    }
    if recipe.per_arch_toolchain_identity != a.per_arch_toolchain_identity {
        return Err("recipe toolchain".into());
    }
    // 4. inventories prove per-build remaps + record-address agreement
    let prove =
        |inv: &InvInventory, side: &RecipeSide, tag: u8, which: &str| -> Result<(), String> {
            if inv.candidate != a.candidate || inv.arch != a.arch {
                return Err(format!("inventory {which} candidate/arch"));
            }
            if inv.build_tag != tag {
                return Err(format!("inventory {which} build tag"));
            }
            let mut compiles = 0usize;
            for e in &inv.entries {
                if *blake3::hash(e.reconstruct().as_bytes()).as_bytes() != e.record_address {
                    return Err(format!(
                        "inventory {which} record address != BLAKE3(record)"
                    ));
                }
                if e.kind != "compile" {
                    continue;
                }
                compiles += 1;
                if e.remap_args.len() != 1 {
                    return Err(format!("inventory {which} compile has != 1 remap arg"));
                }
                let (f, t) = parse_remap_arg(&e.remap_args[0])?;
                if f != side.target_from || t != CANON_TARGET {
                    return Err(format!("inventory {which} compile remap != recipe root"));
                }
            }
            if compiles == 0 {
                return Err(format!("inventory {which} has no compile"));
            }
            Ok(())
        };
    prove(inv_a, &recipe.build_a, 0, "A")?;
    prove(inv_b, &recipe.build_b, 1, "B")?;
    // 5. double-build proof
    if proof.candidate != a.candidate || proof.arch != a.arch {
        return Err("proof candidate/arch".into());
    }
    if proof.wrapper_blake3 != recipe.wrapper_blake3 {
        return Err("proof wrapper != recipe".into());
    }
    if proof.build_a.original_root != recipe.build_a.original_root
        || proof.build_a.target_from != recipe.build_a.target_from
        || proof.build_b.original_root != recipe.build_b.original_root
        || proof.build_b.target_from != recipe.build_b.target_from
    {
        return Err("proof roots != recipe roots".into());
    }
    if proof.build_a.original_root == proof.build_b.original_root {
        return Err("proof build A and B share the same original checkout root".into());
    }
    // Authenticated 4-way: origin_A == materialized_A, origin_B == materialized_B, origin_A == origin_B.
    if proof.build_a.origin_manifest_blake3 != proof.build_a.materialized_manifest_blake3 {
        return Err("proof build A materialized manifest != origin manifest".into());
    }
    if proof.build_b.origin_manifest_blake3 != proof.build_b.materialized_manifest_blake3 {
        return Err("proof build B materialized manifest != origin manifest".into());
    }
    if proof.build_a.origin_manifest_blake3 != proof.build_b.origin_manifest_blake3 {
        return Err(
            "proof build A and B origin manifests differ (not the same build inputs)".into(),
        );
    }
    // Fresh-per-build cargo dependency SEED: each build independently materialized the SAME
    // authenticated seed into the canonical cargo home /b0/cargo — origin == materialized_A ==
    // materialized_B (canonical path != shared build state), and the origin address is non-zero.
    if proof.cargo_seed_origin_blake3 == [0u8; 32] {
        return Err("proof cargo dependency-seed origin address is all-zero (unbound seed)".into());
    }
    if proof.build_a.materialized_cargo_seed_blake3 != proof.cargo_seed_origin_blake3 {
        return Err("proof build A materialized cargo seed != seed origin".into());
    }
    if proof.build_b.materialized_cargo_seed_blake3 != proof.cargo_seed_origin_blake3 {
        return Err("proof build B materialized cargo seed != seed origin".into());
    }
    // Fresh-per-build RISC0 TOOLCHAIN-HOME working copy (RISC0 real embed only): each build materialized a
    // copy of the SEALED read-only toolchain authority, authenticated content-equal to it before use —
    // origin == materialized_A == materialized_B (recomputed here from the retained addresses, independent
    // of the reference verifier). SP1 carries all-zero.
    if proof.candidate == 2 {
        if proof.risc0_home_origin_blake3 == [0u8; 32] {
            return Err(
                "proof RISC0 toolchain-home authority address is all-zero (unbound)".into(),
            );
        }
        if proof.build_a.materialized_risc0_home_blake3 != proof.risc0_home_origin_blake3 {
            return Err(
                "proof build A materialized risc0 toolchain-home != sealed authority".into(),
            );
        }
        if proof.build_b.materialized_risc0_home_blake3 != proof.risc0_home_origin_blake3 {
            return Err(
                "proof build B materialized risc0 toolchain-home != sealed authority".into(),
            );
        }
    } else if proof.risc0_home_origin_blake3 != [0u8; 32]
        || proof.build_a.materialized_risc0_home_blake3 != [0u8; 32]
        || proof.build_b.materialized_risc0_home_blake3 != [0u8; 32]
    {
        return Err(
            "proof non-RISC0 candidate carries a risc0 toolchain-home address (must be zero)"
                .into(),
        );
    }
    if proof.build_a.inventory_address != inv_a_addr
        || proof.build_b.inventory_address != inv_b_addr
    {
        return Err("proof inventory address != retained".into());
    }
    if proof.build_a.runner_sha256 != proof.build_b.runner_sha256
        || proof.build_a.runner_blake3 != proof.build_b.runner_blake3
    {
        return Err("runner A != runner B".into());
    }
    let eq = proof.build_a.runner_sha256 == proof.build_b.runner_sha256
        && proof.build_a.runner_blake3 == proof.build_b.runner_blake3;
    if proof.byte_equal != eq {
        return Err("proof byte_equal != retained hashes".into());
    }
    if proof.candidate == 2 // Risc0 repr
        && (proof.build_a.guest_image_id != proof.build_b.guest_image_id
            || proof.build_a.guest_methods_blake3 != proof.build_b.guest_methods_blake3)
    {
        return Err("RISC0 embedded guest A != B".into());
    }
    if DoubleBuildProof::compute_repro(&proof.build_a, &proof.build_b)
        != proof.reproducibility_pair_blake3
    {
        return Err("reproducibility pair != recomputed".into());
    }
    if proof.build_b.start_unix < proof.build_a.end_unix {
        return Err("proof build B started before A finished".into());
    }
    if proof.build_a.runner_blake3 != a.runner_blake3 {
        return Err("proof runner != attested runner".into());
    }
    // 6. leakage cross-bound to the recipe roots + evidence root
    if leak.candidate != a.candidate || leak.arch != a.arch {
        return Err("leakage candidate/arch".into());
    }
    if !leak.clean {
        return Err("leakage not clean".into());
    }
    let want = {
        let mut v = vec![
            CANON_CARGO.to_string(),
            CANON_TARGET.to_string(),
            CANON_TOOLING.to_string(),
        ];
        if leak.candidate == 2 {
            // RISC0: the guest-embed build also touches the pinned guest HOME (matches the validator's
            // candidate-canonical permitted set); SP1 has no embedded guest home.
            v.push(CANON_GUESTHOME.to_string());
        }
        v.sort();
        v
    };
    if leak.permitted != want {
        return Err("leakage permitted != canonical".into());
    }
    let refused: std::collections::BTreeSet<&str> =
        leak.refused.iter().map(|s| s.as_str()).collect();
    for req in [
        recipe.build_a.original_root.as_str(),
        recipe.build_a.target_from.as_str(),
        recipe.build_b.original_root.as_str(),
        recipe.build_b.target_from.as_str(),
        leak.evidence_root.as_str(),
    ] {
        if !refused.contains(req) {
            return Err("leakage refused set omits a required root".into());
        }
    }
    if leak.scanned_binary_blake3 != a.runner_blake3 {
        return Err("leakage scanned != runner".into());
    }
    Ok(())
}

/// SEALED-IMPORT cargo dependency-SEED anchor (independent mirror of the reference
/// `check_bound_dependency_seed`): bind the double-build proof's fresh-per-build cargo seed to the
/// INDEPENDENTLY-retained, from-scratch-authenticated [`crate::dependency_seed::DependencySeedV1`] — so
/// the seed origin is NOT producer-trusted. Enforces:
///   1. `seed.verify(candidate)` re-authenticates the record (schema/counts/roles/64-hex/recompute==
///      address) and refuses a cross-candidate seed, returning the authenticated record address;
///   2. that address == the attestation's bound `dependency_seed_address` (a swapped/mutated/unbound
///      record re-addresses and fails here — the seed's own authority binding);
///   3. the proof's candidate/arch agree with the attestation (cross-arch/candidate guard);
///   4. `proof.cargo_seed_origin_blake3` == the record's host-cargo-home SEED-CONTENT address
///      (origin==materialized_A==materialized_B is already enforced by [`bind_runner_recipe`], so a
///      mutually-edited proof that substitutes a matching forged origin/A/B still fails this check).
pub fn bind_dependency_seed(
    a: &RunnerAtt,
    proof: &DoubleBuildProof,
    seed: &crate::dependency_seed::DependencySeedV1,
) -> Result<(), String> {
    let candidate_str = if a.candidate == 1 { "sp1" } else { "risc0" };
    // Authenticates the record from scratch (shape + recompute==address); refuses a cross-candidate seed.
    let record_address = seed.verify(candidate_str)?;
    if record_address != a.dependency_seed_address {
        return Err(
            "retained DependencySeedV1 record address != attestation dependency_seed_address \
             (swapped/mutated/unbound dependency-seed artifact)"
                .into(),
        );
    }
    if proof.candidate != a.candidate || proof.arch != a.arch {
        return Err(
            "double-build proof candidate/arch != attestation (dependency-seed anchor)".into(),
        );
    }
    let content_address = seed.host_cargo_home_seed_address()?;
    if proof.cargo_seed_origin_blake3 != content_address {
        return Err(
            "double-build proof cargo_seed_origin != retained dependency-seed host-cargo-home \
             seed-content address (a producer-trusted / mutually-edited origin, not the authentic \
             authenticated seed)"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod runner_recipe_bind_tests {
    //! Independent mirror of the validator's `check_bound_runner_recipe` negatives (5-artifact set).
    //! Addresses are matched by equality; the structs are built directly with the new fields.
    use super::*;

    fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn enc(t: &str) -> Vec<u8> {
        format!("--remap-path-prefix=/b0-input/{t}/target=/b0/target").into_bytes()
    }
    fn side(t: &str) -> RecipeSide {
        RecipeSide {
            original_root: format!("/b0-input/{t}/tooling"),
            target_from: format!("/b0-input/{t}/target"),
            encoded_rustflags: enc(t),
        }
    }
    fn inv(t: &str, tag: u8) -> InvInventory {
        let remap_args = vec![format!(
            "--remap-path-prefix=/b0-input/{t}/target=/b0/target"
        )];
        let e = InvEntry {
            kind: "compile".into(),
            record_address: {
                let mut s = String::from(INVOCATION_RECORD_HEADER);
                s.push_str("\nkind=compile");
                for a in &remap_args {
                    s.push_str("\nremap_arg=");
                    s.push_str(a);
                }
                *blake3::hash(s.as_bytes()).as_bytes()
            },
            remap_args,
        };
        InvInventory {
            candidate: 1,
            arch: 1,
            build_tag: tag,
            entries: vec![e],
        }
    }
    fn pside(t: &str, inv_addr: [u8; 32], s: u64, e: u64) -> ProofSide {
        ProofSide {
            original_root: format!("/b0-input/{t}/tooling"),
            target_from: format!("/b0-input/{t}/target"),
            runner_sha256: h(30),
            runner_blake3: h(9),
            guest_image_id: h(0),
            guest_methods_blake3: h(31),
            inventory_address: inv_addr,
            origin_manifest_blake3: h(21),
            materialized_manifest_blake3: h(21),
            materialized_cargo_seed_blake3: h(31),
            materialized_risc0_home_blake3: [0u8; 32],
            start_unix: s,
            end_unix: e,
        }
    }

    #[allow(clippy::type_complexity)]
    fn set() -> (
        RunnerAtt,
        BuildRecipe,
        [u8; 32],
        InvInventory,
        [u8; 32],
        InvInventory,
        [u8; 32],
        DoubleBuildProof,
        [u8; 32],
        LeakReport,
        [u8; 32],
    ) {
        let msc = "5".repeat(40);
        let wrapper = h(7);
        let rid = compute_recipe_id(&msc, &wrapper);
        let inv_a = inv("a", 0);
        let inv_b = inv("b", 1);
        // Independent-style addresses (equality-matched, not real content hashes here).
        let (recipe_addr, inv_a_addr, inv_b_addr, proof_addr, leak_addr) =
            (h(20), h(21), h(22), h(23), h(24));
        let fa = pside("a", inv_a_addr, 100, 200);
        let fb = pside("b", inv_b_addr, 200, 300);
        let proof = DoubleBuildProof {
            candidate: 1,
            arch: 1,
            wrapper_blake3: wrapper,
            cargo_seed_origin_blake3: h(31),
            risc0_home_origin_blake3: [0u8; 32],
            reproducibility_pair_blake3: DoubleBuildProof::compute_repro(&fa, &fb),
            build_a: fa,
            build_b: fb,
            byte_equal: true,
        };
        let recipe = BuildRecipe {
            candidate: 1,
            arch: 1,
            recipe_id: rid,
            build_argv: [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--offline",
                "--features",
                "real-backend",
                "--manifest-path",
                "tools/b0-pre-measure-sp1/Cargo.toml",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            build_env: vec![
                ("BUILD_GIT_SHA".into(), msc.clone()),
                ("SOURCE_DATE_EPOCH".into(), "0".into()),
                ("B0_VENUE_EMBED".into(), "0".into()),
            ],
            manifest_path: "tools/b0-pre-measure-sp1/Cargo.toml".into(),
            cargo_ident: "cargo".into(),
            b0_venue_embed: "0".into(),
            canonical_build_path: "/b0/tooling".into(),
            canonical_cargo_home: "/b0/cargo".into(),
            build_a: side("a"),
            build_b: side("b"),
            measured_source_commit: msc.clone(),
            tooling_commit: "1".repeat(40),
            tooling_pathset_blake3: "b".repeat(64),
            per_arch_toolchain_identity: h(8),
            protobuf_authority_sha256: h(5),
            protobuf_authority_blake3: h(6),
            wrapper_blake3: wrapper,
        };
        let mut permitted = vec![
            CANON_CARGO.to_string(),
            CANON_TARGET.to_string(),
            CANON_TOOLING.to_string(),
        ];
        permitted.sort();
        let mut refused = vec![
            "/b0-input/a/tooling".to_string(),
            "/b0-input/a/target".into(),
            "/b0-input/b/tooling".into(),
            "/b0-input/b/target".into(),
            "/tmp/b0-evid".into(),
        ];
        refused.sort();
        let leak = LeakReport {
            candidate: 1,
            arch: 1,
            scanned_binary_blake3: h(9),
            clean: true,
            evidence_root: "/tmp/b0-evid".into(),
            refused,
            permitted,
        };
        let att = RunnerAtt {
            candidate: 1,
            role: 0,
            arch: 1,
            spec: h(0),
            guest_set: h(0),
            measured_source_commit: msc.clone(),
            build_git_sha: msc,
            ratified_pathset: "b".repeat(64),
            recomputed_pathset: "b".repeat(64),
            protoc_version: "libprotoc 3.21.12".into(),
            runner_blake3: h(9),
            phase1_production_binary_blake3: h(9),
            phase1_identity_record_blake3: h(0),
            ratified_tooling_commit: "1".repeat(40),
            runner_build_recipe_blake3: recipe_addr,
            rustc_invocation_inventory_a_blake3: inv_a_addr,
            rustc_invocation_inventory_b_blake3: inv_b_addr,
            runner_double_build_proof_blake3: proof_addr,
            runner_leakage_report_blake3: leak_addr,
            per_arch_toolchain_identity: h(8),
            runner_build_recipe_id: rid,
            protobuf_authority_sha256: h(5),
            protobuf_authority_blake3: h(6),
            dependency_seed_address: h(21),
            canonical_sp1_guest_artifact_address: h(7),
            measurement_input_authority_address: h(4),
        };
        (
            att,
            recipe,
            recipe_addr,
            inv_a,
            inv_a_addr,
            inv_b,
            inv_b_addr,
            proof,
            proof_addr,
            leak,
            leak_addr,
        )
    }

    #[test]
    fn positive_binds() {
        let (a, r, ra, ia, iaa, ib, iba, p, pa, l, la) = set();
        bind_runner_recipe(&a, &r, ra, &ia, iaa, &ib, iba, &p, pa, &l, la).unwrap();
    }

    #[test]
    fn wrong_recipe_address_refused() {
        let (a, r, _ra, ia, iaa, ib, iba, p, pa, l, la) = set();
        assert!(
            bind_runner_recipe(&a, &r, h(99), &ia, iaa, &ib, iba, &p, pa, &l, la)
                .unwrap_err()
                .contains("recipe address")
        );
    }

    #[test]
    fn cross_arch_refused() {
        let (mut a, r, ra, ia, iaa, ib, iba, p, pa, l, la) = set();
        a.arch = 2;
        assert!(
            bind_runner_recipe(&a, &r, ra, &ia, iaa, &ib, iba, &p, pa, &l, la)
                .unwrap_err()
                .contains("candidate/arch")
        );
    }

    #[test]
    fn inventory_from_not_matching_recipe_refused() {
        let (a, r, ra, _ia, iaa, ib, iba, p, pa, l, la) = set();
        // Build-A inventory that proves DIFFERENT roots than the recipe's build A.
        let bad = inv("x", 0);
        // Rebind the proof/attestation address to the bad inventory so the address check passes.
        let mut a = a;
        a.rustc_invocation_inventory_a_blake3 = iaa;
        let mut p = p;
        let _ = &mut p;
        assert!(
            bind_runner_recipe(&a, &r, ra, &bad, iaa, &ib, iba, &p, pa, &l, la)
                .unwrap_err()
                .contains("recipe root")
        );
    }

    #[test]
    fn leakage_omits_root_refused() {
        let (a, r, ra, ia, iaa, ib, iba, p, pa, mut l, la) = set();
        l.refused.retain(|s| s != "/b0-input/b/target");
        assert!(
            bind_runner_recipe(&a, &r, ra, &ia, iaa, &ib, iba, &p, pa, &l, la)
                .unwrap_err()
                .contains("omits a required root")
        );
    }

    #[test]
    fn scanned_other_binary_refused() {
        let (mut a, r, ra, ia, iaa, ib, iba, p, pa, l, la) = set();
        a.runner_blake3 = h(77);
        assert!(
            bind_runner_recipe(&a, &r, ra, &ia, iaa, &ib, iba, &p, pa, &l, la)
                .unwrap_err()
                .contains("attested runner")
        );
    }

    #[test]
    fn unfaithful_materialization_refused() {
        let (a, r, ra, ia, iaa, ib, iba, mut p, pa, l, la) = set();
        p.build_b.materialized_manifest_blake3 = h(99);
        assert!(
            bind_runner_recipe(&a, &r, ra, &ia, iaa, &ib, iba, &p, pa, &l, la)
                .unwrap_err()
                .contains("materialized manifest != origin")
        );
    }

    #[test]
    fn differing_origin_manifests_refused() {
        let (a, r, ra, ia, iaa, ib, iba, mut p, pa, l, la) = set();
        p.build_b.origin_manifest_blake3 = h(98);
        p.build_b.materialized_manifest_blake3 = h(98);
        assert!(
            bind_runner_recipe(&a, &r, ra, &ia, iaa, &ib, iba, &p, pa, &l, la)
                .unwrap_err()
                .contains("origin manifests differ")
        );
    }
}

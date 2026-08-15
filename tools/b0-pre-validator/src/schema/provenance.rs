//! `ArchRunProvenanceV1` — variable (plan §8/§23).
//!
//! Canonical hardware/OS facts for one measurement run. No leading 32-byte tag;
//! `arch_run_provenance_hash = BLAKE3(ARCHPROV ‖ canonical_bytes)`. Only
//! non-secret facts belong here (the anonymization scan is enforced by the
//! provenance-validation tool and CI); the full capture is bound only by
//! `raw_environment_capture_hash`.

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::enums::{Arch, Candidate, ProvenanceRole};
use crate::hashing;
use crate::tags::ARCHPROV_PREFIX;

fn read_bool(r: &mut Reader, ctx: &'static str) -> Result<bool, DecodeError> {
    match r.read_u8(ctx)? {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        }),
    }
}

/// Read a `u8`-length-prefixed ASCII string (fail closed on non-ASCII).
fn read_u8_ascii(r: &mut Reader, ctx: &'static str) -> Result<String, DecodeError> {
    let n = r.read_u8(ctx)?;
    let b = r.read_bytes(n as usize, ctx)?;
    if !b.iter().all(|c| c.is_ascii()) {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(String::from_utf8(b.to_vec()).expect("ascii"))
}

/// The DVFS (turbo/governor) provenance state — a SUM type so the hypervisor-unobservable case is
/// explicit and can NEVER be interpreted as `turbo=false`/`performance`.
///
/// * `Observable` — the ordinary directly-observed state; its `(governor, turbo_enabled)` body is
///   encoded exactly as the pre-v2 flat fields (preserving Observable eligibility SEMANTICS; the
///   full v2 record is intentionally not byte-compatible with v1, which the version bump enforces).
/// * `HypervisorManagedUnobservable` — no DVFS control surface exists (hypervisor owns DVFS);
///   carries STRUCTURED evidence whose `raw_evidence_blake3` is independently recomputed + verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DvfsProvenance {
    Observable {
        turbo_enabled: bool,
        governor: String,
    },
    HypervisorManagedUnobservable(HypervisorUnobservableDvfs),
}

/// Structured evidence for [`DvfsProvenance::HypervisorManagedUnobservable`]. `absent_controls` is
/// canonical: strictly sorted + unique (the decoder rejects any other order or a duplicate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HypervisorUnobservableDvfs {
    pub cpu_arch: String,
    pub cpu_identity: String,
    pub virtualization: String,
    pub virtualization_source: String,
    pub absent_controls: Vec<String>,
    pub raw_evidence_blake3: [u8; 32],
}

/// Recompute the DVFS unobservable evidence hash — the SAME domain-separated rule the
/// host-provenance reader and the independent verifier use, so all three agree byte-for-byte:
/// `BLAKE3("b0-final-dvfs-unobservable-evidence/v1\0" ‖ canonical)`.
pub fn recompute_dvfs_evidence_hash(e: &HypervisorUnobservableDvfs) -> [u8; 32] {
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

impl DvfsProvenance {
    pub fn encode(&self, w: &mut Writer) {
        match self {
            DvfsProvenance::Observable {
                turbo_enabled,
                governor,
            } => {
                w.u8(0);
                w.u16(governor.len() as u16);
                w.bytes(governor.as_bytes());
                w.u8(u8::from(*turbo_enabled));
            }
            DvfsProvenance::HypervisorManagedUnobservable(e) => {
                w.u8(1);
                w.u8(e.cpu_arch.len() as u8);
                w.bytes(e.cpu_arch.as_bytes());
                w.u16(e.cpu_identity.len() as u16);
                w.bytes(e.cpu_identity.as_bytes());
                w.u8(e.virtualization.len() as u8);
                w.bytes(e.virtualization.as_bytes());
                w.u16(e.virtualization_source.len() as u16);
                w.bytes(e.virtualization_source.as_bytes());
                w.u8(e.absent_controls.len() as u8);
                for c in &e.absent_controls {
                    w.u16(c.len() as u16);
                    w.bytes(c.as_bytes());
                }
                w.bytes(&e.raw_evidence_blake3);
            }
        }
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.read_u8("DvfsProvenance.tag")? {
            0 => {
                let governor = r.read_ascii_str(32, "DvfsProvenance.governor")?;
                let turbo_enabled = read_bool(r, "DvfsProvenance.turbo_enabled")?;
                Ok(DvfsProvenance::Observable {
                    turbo_enabled,
                    governor,
                })
            }
            1 => {
                let cpu_arch = read_u8_ascii(r, "DvfsProvenance.cpu_arch")?;
                let cpu_identity = r.read_ascii_str(128, "DvfsProvenance.cpu_identity")?;
                let virtualization = read_u8_ascii(r, "DvfsProvenance.virtualization")?;
                let virtualization_source =
                    r.read_ascii_str(256, "DvfsProvenance.virtualization_source")?;
                let n = r.read_u8("DvfsProvenance.absent_controls.count")?;
                let mut absent_controls = Vec::with_capacity(n as usize);
                let mut prev: Option<String> = None;
                for _ in 0..n {
                    let c = r.read_ascii_str(128, "DvfsProvenance.absent_control")?;
                    // Canonical: strictly sorted + unique.
                    if let Some(p) = &prev {
                        if p.as_str() >= c.as_str() {
                            return Err(DecodeError::BadValue {
                                ctx: "DvfsProvenance.absent_controls_sorted_unique",
                            });
                        }
                    }
                    prev = Some(c.clone());
                    absent_controls.push(c);
                }
                let raw_evidence_blake3 =
                    r.read_array::<32>("DvfsProvenance.raw_evidence_blake3")?;
                Ok(DvfsProvenance::HypervisorManagedUnobservable(
                    HypervisorUnobservableDvfs {
                        cpu_arch,
                        cpu_identity,
                        virtualization,
                        virtualization_source,
                        absent_controls,
                        raw_evidence_blake3,
                    },
                ))
            }
            v => Err(DecodeError::BadFixedScalar {
                ctx: "DvfsProvenance.tag",
                value: v as u64,
            }),
        }
    }
}

// ===================== effective-cpuset PROVENANCE (v3, inheritance-aware) =====================
//
// The measurement host's effective cpuset is read with cgroup-v2 inheritance: when the process leaf
// scope does not expose `cpuset.cpus.effective`, the value is INHERITED from the nearest canonical
// ancestor that does — never defaulted to all host CPUs. The retained NEAREST-FIRST probe chain (one
// entry per visited cgroup, TWO complete observations each) is the audit trail. Only its 32-byte
// domain-separated content address ([`cpuset_probe_chain_hash`]) lives in the canonical record; the
// full chain travels as retained evidence and every consumer (producer, validator, independent
// verifier) recomputes the address AND re-checks the canonical rules over the retained chain.

/// One retained observation of the effective-cpuset file at a probed cgroup. Twin of the reader's
/// `CpusetObservation` (this crate does not depend on the reader crate; the JSON is the contract).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpusetObsV1 {
    /// 0 = absent, 1 = readable-empty, 2 = readable-nonempty.
    pub state: u8,
    pub raw: String,
    pub file_type: String,
    pub is_symlink: bool,
    pub dev: Option<u64>,
    pub inode: Option<u64>,
    pub size: Option<u64>,
    pub mtime_secs: Option<i64>,
    pub mtime_nanos: Option<i64>,
    pub read_error_class: Option<String>,
}

/// One nearest-first probe-chain entry with two complete observations that MUST be equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpusetProbeEntryV1 {
    pub cgroup_path: String,
    pub order: u32,
    pub first: CpusetObsV1,
    pub second: CpusetObsV1,
}

fn cpuset_obs_canon(o: &CpusetObsV1) -> String {
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

/// The domain-separated content address over the retained nearest-first probe chain. The SAME rule
/// is recomputed by the independent verifier (a shared committed golden pins the value), so the two
/// implementations cannot diverge.
pub fn cpuset_probe_chain_hash(entries: &[CpusetProbeEntryV1]) -> [u8; 32] {
    let mut canonical = String::from("b0-final-cpuset-probe-chain/v1");
    for e in entries {
        canonical.push_str(&format!(
            "|entry:{}:{}:[{}]:[{}]",
            e.order,
            e.cgroup_path,
            cpuset_obs_canon(&e.first),
            cpuset_obs_canon(&e.second)
        ));
    }
    let mut h = blake3::Hasher::new();
    h.update(b"b0-final-cpuset-probe-chain-hash/v1\0");
    h.update(canonical.as_bytes());
    *h.finalize().as_bytes()
}

/// Count the CPUs in a Linux cpu-list ("0-3,7"), fail-closed (an unreadable cpuset is never "all").
/// A local twin of the reader's `count_cpu_list` so the validator recomputes the count independently.
pub fn count_cpu_list(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty cpu list".into());
    }
    let mut total: u32 = 0;
    for tok in s.split(',') {
        let tok = tok.trim();
        if let Some((a, b)) = tok.split_once('-') {
            let lo: u32 = a
                .trim()
                .parse()
                .map_err(|_| format!("bad range lo: {tok}"))?;
            let hi: u32 = b
                .trim()
                .parse()
                .map_err(|_| format!("bad range hi: {tok}"))?;
            if hi < lo {
                return Err(format!("inverted range: {tok}"));
            }
            total += hi - lo + 1;
        } else {
            tok.parse::<u32>()
                .map_err(|_| format!("bad index: {tok}"))?;
            total += 1;
        }
    }
    Ok(total)
}

/// `true` iff `ancestor` is `leaf` or a canonical ancestor of it (cgroup-root-relative paths).
fn cgroup_is_ancestor_or_self(ancestor: &str, leaf: &str) -> bool {
    if ancestor == leaf || ancestor == "/" {
        return true;
    }
    matches!(leaf.strip_prefix(ancestor), Some(rest) if rest.starts_with('/'))
}

/// Re-check ALL canonical cpuset-inheritance rules over a retained probe chain + the summary fields
/// bound in the record. Fail-closed; this is the exact rule the independent verifier mirrors:
///   * chain non-empty; `order` is 0,1,2,... contiguous; entry 0 is the process leaf;
///   * every entry's two observations are equal (first == second);
///   * every entry is an ancestor-or-self of the leaf (never a sibling);
///   * exactly the LAST entry is readable-nonempty (the selected source); all earlier entries are
///     stable absent or readable-empty (a read error / malformed / symlink / non-regular is never a
///     retained state, so it cannot appear here);
///   * the source path/raw equal the summary; `count == count_cpu_list(raw)`;
///   * `inherited == (source_order != 0)`.
pub fn check_cpuset_probe_chain(
    entries: &[CpusetProbeEntryV1],
    leaf_scope: &str,
    summary_source_path: &str,
    summary_raw: &str,
    summary_inherited: bool,
    summary_count: u32,
) -> Result<(), String> {
    if entries.is_empty() {
        return Err("cpuset probe chain is empty".into());
    }
    for (i, e) in entries.iter().enumerate() {
        if e.order as usize != i {
            return Err(format!("cpuset chain order {} != position {i}", e.order));
        }
        if e.first != e.second {
            return Err(format!(
                "cpuset chain entry {} first != second (state changed between reads)",
                e.cgroup_path
            ));
        }
        if !cgroup_is_ancestor_or_self(&e.cgroup_path, leaf_scope) {
            return Err(format!(
                "cpuset chain entry {} is not an ancestor-or-self of leaf {leaf_scope}",
                e.cgroup_path
            ));
        }
        let is_last = i + 1 == entries.len();
        match e.first.state {
            2 => {
                if !is_last {
                    return Err(format!(
                        "cpuset chain has a readable-nonempty entry {} before the source (chain must \
                         stop at the first source)",
                        e.cgroup_path
                    ));
                }
            }
            0 | 1 => {
                if is_last {
                    return Err(
                        "cpuset chain's last (source) entry is not readable-nonempty".into(),
                    );
                }
            }
            other => return Err(format!("cpuset chain entry has invalid state {other}")),
        }
    }
    if entries[0].cgroup_path != leaf_scope {
        return Err(format!(
            "cpuset chain entry 0 {} != process leaf {leaf_scope}",
            entries[0].cgroup_path
        ));
    }
    let source = entries.last().expect("nonempty");
    if source.cgroup_path != summary_source_path {
        return Err(format!(
            "cpuset source {} != summary source {summary_source_path}",
            source.cgroup_path
        ));
    }
    if source.first.raw != summary_raw {
        return Err("cpuset source raw != summary raw".into());
    }
    let recomputed = count_cpu_list(summary_raw)?;
    if recomputed != summary_count {
        return Err(format!(
            "cpuset count {summary_count} != recomputed {recomputed} from raw {summary_raw:?}"
        ));
    }
    let expected_inherited = source.order != 0;
    if expected_inherited != summary_inherited {
        return Err(format!(
            "cpuset inherited flag {summary_inherited} != expected {expected_inherited} (source order {})",
            source.order
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchRunProvenanceV1 {
    pub provenance_role: ProvenanceRole,
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub candidate: Candidate,
    pub guest_program_id: [u8; 32],
    pub candidate_dep_lock_hash: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub arch: Arch,
    pub source_commit: String, // 40 or 64 lowercase hex
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
    pub dvfs: DvfsProvenance,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
    pub benchmark_harness_source_hash: [u8; 32],
    pub raw_environment_capture_hash: [u8; 32],
    // ---- v3 tail: effective-cpuset provenance + runner attestation content addresses ----
    /// The cgroup path (cgroup-root-relative) the effective cpuset was READ from: the process leaf
    /// when leaf-observed, else the nearest ancestor exposing it.
    pub cpuset_source_cgroup_path: String,
    /// The RAW effective cpu-list read from the source cgroup (`configured_cpuset_core_limit` recounts
    /// from this).
    pub cpuset_raw: String,
    /// false = observed at the leaf; true = inherited from an ancestor.
    pub cpuset_inherited: bool,
    /// Content address over the retained nearest-first probe chain ([`cpuset_probe_chain_hash`]).
    pub cpuset_probe_chain_blake3: [u8; 32],
    /// Content address over the per-arch [`super::runner_attestation::RunnerAttestationV1`] retained
    /// evidence — the two-root tooling/measured authority binding. Bound in measurement provenance
    /// ONLY (never in the allowlist / guest identity).
    pub runner_attestation_blake3: [u8; 32],
}

impl ArchRunProvenanceV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        // Provenance-LOCAL schema version (v2 = DvfsProvenance sum type). Deliberately NOT the
        // global `consts::SCHEMA_VERSION`, so advancing this record's layout does not disturb the
        // canonical bytes of any other (R0 protocol or measurement) record.
        w.u16(consts::ARCH_RUN_PROVENANCE_SCHEMA_VERSION);
        w.u8(self.provenance_role.to_repr());
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.u16(self.candidate.to_repr());
        w.bytes(&self.guest_program_id);
        w.bytes(&self.candidate_dep_lock_hash);
        w.bytes(&self.verifier_material_manifest_hash);
        w.u8(self.arch.to_repr());
        w.u8(self.source_commit.len() as u8);
        w.bytes(self.source_commit.as_bytes());
        w.u8(if self.dirty_tree_flag { 1 } else { 0 });
        w.bytes(&self.builder_container_digest);
        w.u16(self.host_os.len() as u16);
        w.bytes(self.host_os.as_bytes());
        w.u16(self.kernel.len() as u16);
        w.bytes(self.kernel.as_bytes());
        w.u16(self.cpu_vendor.len() as u16);
        w.bytes(self.cpu_vendor.as_bytes());
        w.u16(self.cpu_model.len() as u16);
        w.bytes(self.cpu_model.as_bytes());
        w.u32(self.physical_core_count);
        w.u32(self.logical_cpu_count);
        w.u64(self.total_ram_bytes);
        w.u32(self.configured_cpuset_core_limit);
        w.u64(self.configured_memory_limit_bytes);
        self.dvfs.encode(&mut w);
        w.u16(self.clock_source.len() as u16);
        w.bytes(self.clock_source.as_bytes());
        w.u8(self.cgroup_version);
        w.u16(self.cgroup_scope_label.len() as u16);
        w.bytes(self.cgroup_scope_label.as_bytes());
        w.bytes(&self.benchmark_harness_source_hash);
        w.bytes(&self.raw_environment_capture_hash);
        // v3 tail.
        w.u16(self.cpuset_source_cgroup_path.len() as u16);
        w.bytes(self.cpuset_source_cgroup_path.as_bytes());
        w.u16(self.cpuset_raw.len() as u16);
        w.bytes(self.cpuset_raw.as_bytes());
        w.u8(if self.cpuset_inherited { 1 } else { 0 });
        w.bytes(&self.cpuset_probe_chain_blake3);
        w.bytes(&self.runner_attestation_blake3);
        w.into_bytes()
    }

    pub fn provenance_hash(&self) -> [u8; 32] {
        hashing::prefixed(ARCHPROV_PREFIX, &self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let sv = r.read_u16("ArchRunProvenanceV1.schema_version")?;
        // Precise local-version gate: a pre-DVFS (v1) provenance record is rejected here, naming
        // this record's own schema_version and the offending value — no other record is affected.
        if sv != consts::ARCH_RUN_PROVENANCE_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "ArchRunProvenanceV1.schema_version",
                value: sv as u64,
            });
        }
        let provenance_role =
            ProvenanceRole::from_repr(r.read_u8("ArchRunProvenanceV1.provenance_role")?)?;
        let b0_pre_spec_hash = r.read_array::<32>("ArchRunProvenanceV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("ArchRunProvenanceV1.r0_guest_set_hash")?;
        let candidate = Candidate::from_repr(r.read_u16("ArchRunProvenanceV1.candidate_id")?)?;
        let guest_program_id = r.read_array::<32>("ArchRunProvenanceV1.guest_program_id")?;
        let candidate_dep_lock_hash =
            r.read_array::<32>("ArchRunProvenanceV1.candidate_dep_lock_hash")?;
        let verifier_material_manifest_hash =
            r.read_array::<32>("ArchRunProvenanceV1.verifier_material_manifest_hash")?;
        let arch = Arch::from_repr(r.read_u8("ArchRunProvenanceV1.arch")?)?;

        let sc_len = r.read_u8("ArchRunProvenanceV1.source_commit_len")?;
        if sc_len != 40 && sc_len != 64 {
            return Err(DecodeError::BadValue {
                ctx: "ArchRunProvenanceV1.source_commit_len",
            });
        }
        let sc = r.read_bytes(sc_len as usize, "ArchRunProvenanceV1.source_commit")?;
        if !sc
            .iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DecodeError::BadValue {
                ctx: "ArchRunProvenanceV1.source_commit_hex",
            });
        }
        let source_commit = String::from_utf8(sc.to_vec()).expect("ascii");

        let dirty_tree_flag = read_bool(r, "ArchRunProvenanceV1.dirty_tree_flag")?;
        let builder_container_digest =
            r.read_array::<32>("ArchRunProvenanceV1.builder_container_digest")?;
        let host_os = r.read_ascii_str(128, "ArchRunProvenanceV1.host_os")?;
        let kernel = r.read_ascii_str(128, "ArchRunProvenanceV1.kernel")?;
        let cpu_vendor = r.read_ascii_str(64, "ArchRunProvenanceV1.cpu_vendor")?;
        let cpu_model = r.read_ascii_str(128, "ArchRunProvenanceV1.cpu_model")?;
        let physical_core_count = r.read_u32("ArchRunProvenanceV1.physical_core_count")?;
        let logical_cpu_count = r.read_u32("ArchRunProvenanceV1.logical_cpu_count")?;
        let total_ram_bytes = r.read_u64("ArchRunProvenanceV1.total_ram_bytes")?;
        let configured_cpuset_core_limit =
            r.read_u32("ArchRunProvenanceV1.configured_cpuset_core_limit")?;
        let configured_memory_limit_bytes =
            r.read_u64("ArchRunProvenanceV1.configured_memory_limit_bytes")?;
        let dvfs = DvfsProvenance::decode(r)?;
        let clock_source = r.read_ascii_str(32, "ArchRunProvenanceV1.clock_source")?;
        let cgroup_version = r.read_u8("ArchRunProvenanceV1.cgroup_version")?;
        if cgroup_version != 1 && cgroup_version != 2 {
            return Err(DecodeError::BadValue {
                ctx: "ArchRunProvenanceV1.cgroup_version",
            });
        }
        let cgroup_scope_label = r.read_ascii_str(128, "ArchRunProvenanceV1.cgroup_scope_label")?;
        let benchmark_harness_source_hash =
            r.read_array::<32>("ArchRunProvenanceV1.benchmark_harness_source_hash")?;
        let raw_environment_capture_hash =
            r.read_array::<32>("ArchRunProvenanceV1.raw_environment_capture_hash")?;
        // v3 tail.
        let cpuset_source_cgroup_path =
            r.read_ascii_str(128, "ArchRunProvenanceV1.cpuset_source_cgroup_path")?;
        let cpuset_raw = r.read_ascii_str(256, "ArchRunProvenanceV1.cpuset_raw")?;
        let cpuset_inherited = read_bool(r, "ArchRunProvenanceV1.cpuset_inherited")?;
        let cpuset_probe_chain_blake3 =
            r.read_array::<32>("ArchRunProvenanceV1.cpuset_probe_chain_blake3")?;
        let runner_attestation_blake3 =
            r.read_array::<32>("ArchRunProvenanceV1.runner_attestation_blake3")?;

        Ok(Self {
            provenance_role,
            b0_pre_spec_hash,
            r0_guest_set_hash,
            candidate,
            guest_program_id,
            candidate_dep_lock_hash,
            verifier_material_manifest_hash,
            arch,
            source_commit,
            dirty_tree_flag,
            builder_container_digest,
            host_os,
            kernel,
            cpu_vendor,
            cpu_model,
            physical_core_count,
            logical_cpu_count,
            total_ram_bytes,
            configured_cpuset_core_limit,
            configured_memory_limit_bytes,
            dvfs,
            clock_source,
            cgroup_version,
            cgroup_scope_label,
            benchmark_harness_source_hash,
            raw_environment_capture_hash,
            cpuset_source_cgroup_path,
            cpuset_raw,
            cpuset_inherited,
            cpuset_probe_chain_blake3,
            runner_attestation_blake3,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("ArchRunProvenanceV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ArchRunProvenanceV1 {
        ArchRunProvenanceV1 {
            provenance_role: ProvenanceRole::Proving,
            b0_pre_spec_hash: [1; 32],
            r0_guest_set_hash: [2; 32],
            candidate: Candidate::Sp1,
            guest_program_id: [3; 32],
            candidate_dep_lock_hash: [4; 32],
            verifier_material_manifest_hash: [5; 32],
            arch: Arch::X86_64,
            source_commit: "0".repeat(40),
            dirty_tree_flag: false,
            builder_container_digest: [6; 32],
            host_os: "linux".into(),
            kernel: "6.8.0".into(),
            cpu_vendor: "GenuineIntel".into(),
            cpu_model: "Xeon Gold".into(),
            physical_core_count: 16,
            logical_cpu_count: 32,
            total_ram_bytes: 64 * (1 << 30),
            configured_cpuset_core_limit: 5,
            configured_memory_limit_bytes: 22 * (1 << 30),
            dvfs: DvfsProvenance::Observable {
                turbo_enabled: false,
                governor: "performance".into(),
            },
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "b0-pre.slice".into(),
            benchmark_harness_source_hash: [7; 32],
            raw_environment_capture_hash: [8; 32],
            cpuset_source_cgroup_path: "/b0-pre.slice".into(),
            cpuset_raw: "0-4".into(),
            cpuset_inherited: false,
            cpuset_probe_chain_blake3: [9; 32],
            runner_attestation_blake3: [10; 32],
        }
    }

    #[test]
    fn roundtrips_and_hash_is_prefixed() {
        let p = sample();
        assert_eq!(ArchRunProvenanceV1::decode_exact(&p.encode()).unwrap(), p);
        assert_eq!(
            p.provenance_hash(),
            hashing::prefixed(ARCHPROV_PREFIX, &p.encode())
        );
    }

    #[test]
    fn bad_source_commit_length_rejected() {
        let mut p = sample();
        p.source_commit = "0".repeat(50); // neither 40 nor 64
        assert!(matches!(
            ArchRunProvenanceV1::decode_exact(&p.encode()),
            Err(DecodeError::BadValue {
                ctx: "ArchRunProvenanceV1.source_commit_len"
            })
        ));
    }

    #[test]
    fn bad_dirty_flag_rejected() {
        let p = sample();
        let mut bytes = p.encode();
        // dirty_tree_flag offset = 2+1+32+32+2+32+32+32+1 (=166) + 1 (sc_len) + 40 (sc) = 207
        assert_eq!(bytes[207], 0); // sanity: the flag we set false
        bytes[207] = 2;
        assert!(matches!(
            ArchRunProvenanceV1::decode_exact(&bytes),
            Err(DecodeError::BadFixedScalar {
                ctx: "ArchRunProvenanceV1.dirty_tree_flag",
                ..
            })
        ));
    }

    #[test]
    fn over_long_string_rejected() {
        let mut p = sample();
        p.dvfs = DvfsProvenance::Observable {
            turbo_enabled: false,
            governor: "x".repeat(33), // max 32
        };
        assert!(matches!(
            ArchRunProvenanceV1::decode_exact(&p.encode()),
            Err(DecodeError::LengthExceedsMax {
                ctx: "DvfsProvenance.governor",
                ..
            })
        ));
    }

    fn obs(state: u8, raw: &str, ft: &str) -> CpusetObsV1 {
        CpusetObsV1 {
            state,
            raw: raw.into(),
            file_type: ft.into(),
            is_symlink: false,
            dev: Some(1),
            inode: Some(2),
            size: Some(raw.len() as u64),
            mtime_secs: Some(100),
            mtime_nanos: Some(200),
            read_error_class: None,
        }
    }
    // Inherited chain: leaf (order 0) absent, ancestor (order 1) readable-nonempty "0-1".
    fn inherited_chain() -> Vec<CpusetProbeEntryV1> {
        vec![
            CpusetProbeEntryV1 {
                cgroup_path: "/b0.slice/measure".into(),
                order: 0,
                first: obs(0, "", "absent"),
                second: obs(0, "", "absent"),
            },
            CpusetProbeEntryV1 {
                cgroup_path: "/b0.slice".into(),
                order: 1,
                first: obs(2, "0-1", "regular"),
                second: obs(2, "0-1", "regular"),
            },
        ]
    }

    #[test]
    fn cpuset_chain_hash_is_stable_cross_impl_golden() {
        // SHARED committed golden — the independent verifier (b0-pre-independent) pins the SAME value
        // for the SAME chain in tests/cpuset_probe_chain_cross_impl.rs, so the two implementations of
        // the canonical rule cannot silently diverge.
        let h = cpuset_probe_chain_hash(&inherited_chain());
        let mut hex = String::new();
        for b in h {
            hex.push_str(&format!("{b:02x}"));
        }
        assert_eq!(
            hex,
            "3b01b8cfa7bfc1cfee72837366799bb7873de915b7a0a6ba38312b3322dae1aa"
        );
    }

    #[test]
    fn cpuset_chain_rules_accept_inherited_and_reject_violations() {
        let chain = inherited_chain();
        // inherited source at order 1, raw "0-1" -> count 2, inherited=true.
        assert!(
            check_cpuset_probe_chain(&chain, "/b0.slice/measure", "/b0.slice", "0-1", true, 2)
                .is_ok()
        );
        // wrong count refused
        assert!(
            check_cpuset_probe_chain(&chain, "/b0.slice/measure", "/b0.slice", "0-1", true, 3)
                .is_err()
        );
        // wrong inherited flag refused
        assert!(check_cpuset_probe_chain(
            &chain,
            "/b0.slice/measure",
            "/b0.slice",
            "0-1",
            false,
            2
        )
        .is_err());
        // nonempty entry before the source refused (source must be the last, first-found)
        let mut bad = chain.clone();
        bad[0].first = obs(2, "0-3", "regular");
        bad[0].second = obs(2, "0-3", "regular");
        assert!(
            check_cpuset_probe_chain(&bad, "/b0.slice/measure", "/b0.slice", "0-1", true, 2)
                .is_err()
        );
        // first != second refused
        let mut chg = chain.clone();
        chg[1].second = obs(2, "0-2", "regular");
        assert!(
            check_cpuset_probe_chain(&chg, "/b0.slice/measure", "/b0.slice", "0-1", true, 2)
                .is_err()
        );
        // a sibling (non-ancestor) entry refused
        let mut sib = chain.clone();
        sib[1].cgroup_path = "/other.slice".into();
        assert!(check_cpuset_probe_chain(
            &sib,
            "/b0.slice/measure",
            "/other.slice",
            "0-1",
            true,
            2
        )
        .is_err());
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let bytes = sample().encode();
        assert!(matches!(
            ArchRunProvenanceV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            ArchRunProvenanceV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}

#[cfg(test)]
mod dvfs_codec_tests {
    use super::*;

    fn enc(d: &DvfsProvenance) -> Vec<u8> {
        let mut w = Writer::new();
        d.encode(&mut w);
        w.into_bytes()
    }
    fn dec(b: &[u8]) -> Result<DvfsProvenance, DecodeError> {
        let mut r = Reader::new(b);
        let d = DvfsProvenance::decode(&mut r)?;
        r.finish("DvfsProvenance")?;
        Ok(d)
    }
    fn unobs() -> HypervisorUnobservableDvfs {
        let mut e = HypervisorUnobservableDvfs {
            cpu_arch: "aarch64".into(),
            cpu_identity: "CPU implementer=0x41 CPU part=0xd0c".into(),
            virtualization: "microsoft".into(),
            virtualization_source: "/sys/class/dmi/id/sys_vendor=Microsoft Corporation".into(),
            absent_controls: vec![
                "a/intel_pstate/no_turbo".into(),
                "b/cpufreq/boost".into(),
                "c/scaling_governor".into(),
            ],
            raw_evidence_blake3: [0u8; 32],
        };
        e.raw_evidence_blake3 = recompute_dvfs_evidence_hash(&e);
        e
    }

    #[test]
    fn observable_roundtrips() {
        let d = DvfsProvenance::Observable {
            turbo_enabled: false,
            governor: "performance".into(),
        };
        assert_eq!(dec(&enc(&d)).unwrap(), d);
    }

    #[test]
    fn unobservable_roundtrips_and_recompute_matches() {
        let d = DvfsProvenance::HypervisorManagedUnobservable(unobs());
        let back = dec(&enc(&d)).unwrap();
        assert_eq!(back, d);
        match back {
            DvfsProvenance::HypervisorManagedUnobservable(e) => {
                assert_eq!(recompute_dvfs_evidence_hash(&e), e.raw_evidence_blake3);
                // Shared cross-implementation golden: the independent verifier
                // (`b0-pre-independent`, tests/dvfs_unobservable_cross_impl.rs) pins the SAME
                // value for the SAME evidence, so the domain-separated hash rule cannot diverge.
                let mut hexs = String::new();
                for b in e.raw_evidence_blake3 {
                    hexs.push_str(&format!("{b:02x}"));
                }
                assert_eq!(
                    hexs,
                    "6aa1924a8679315c415be5f0769a29c36b602ba2477b7fc79868354ea892b7c6"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn unknown_tag_fails_closed() {
        assert!(matches!(
            dec(&[2u8]),
            Err(DecodeError::BadFixedScalar {
                ctx: "DvfsProvenance.tag",
                ..
            })
        ));
    }

    #[test]
    fn absent_controls_must_be_sorted_and_unique() {
        let mut unsorted = unobs();
        unsorted.absent_controls = vec!["zzz".into(), "aaa".into()];
        assert!(matches!(
            dec(&enc(&DvfsProvenance::HypervisorManagedUnobservable(
                unsorted
            ))),
            Err(DecodeError::BadValue {
                ctx: "DvfsProvenance.absent_controls_sorted_unique"
            })
        ));
        let mut dup = unobs();
        dup.absent_controls = vec!["dup".into(), "dup".into()];
        assert!(matches!(
            dec(&enc(&DvfsProvenance::HypervisorManagedUnobservable(dup))),
            Err(DecodeError::BadValue {
                ctx: "DvfsProvenance.absent_controls_sorted_unique"
            })
        ));
    }
}

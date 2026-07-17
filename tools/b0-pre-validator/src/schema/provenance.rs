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
    pub governor: String,
    pub turbo_enabled: bool,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
    pub benchmark_harness_source_hash: [u8; 32],
    pub raw_environment_capture_hash: [u8; 32],
}

impl ArchRunProvenanceV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(consts::SCHEMA_VERSION);
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
        w.u16(self.governor.len() as u16);
        w.bytes(self.governor.as_bytes());
        w.u8(if self.turbo_enabled { 1 } else { 0 });
        w.u16(self.clock_source.len() as u16);
        w.bytes(self.clock_source.as_bytes());
        w.u8(self.cgroup_version);
        w.u16(self.cgroup_scope_label.len() as u16);
        w.bytes(self.cgroup_scope_label.as_bytes());
        w.bytes(&self.benchmark_harness_source_hash);
        w.bytes(&self.raw_environment_capture_hash);
        w.into_bytes()
    }

    pub fn provenance_hash(&self) -> [u8; 32] {
        hashing::prefixed(ARCHPROV_PREFIX, &self.encode())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let sv = r.read_u16("ArchRunProvenanceV1.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
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
        let governor = r.read_ascii_str(32, "ArchRunProvenanceV1.governor")?;
        let turbo_enabled = read_bool(r, "ArchRunProvenanceV1.turbo_enabled")?;
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
            governor,
            turbo_enabled,
            clock_source,
            cgroup_version,
            cgroup_scope_label,
            benchmark_harness_source_hash,
            raw_environment_capture_hash,
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
            governor: "performance".into(),
            turbo_enabled: false,
            clock_source: "tsc".into(),
            cgroup_version: 2,
            cgroup_scope_label: "b0-pre.slice".into(),
            benchmark_harness_source_hash: [7; 32],
            raw_environment_capture_hash: [8; 32],
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
        p.governor = "x".repeat(33); // max 32
        assert!(matches!(
            ArchRunProvenanceV1::decode_exact(&p.encode()),
            Err(DecodeError::LengthExceedsMax {
                ctx: "ArchRunProvenanceV1.governor",
                ..
            })
        ));
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

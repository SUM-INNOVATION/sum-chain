//! `CpusetProbeChainV1` — the RETAINED canonical effective-cpuset probe-chain artifact.
//!
//! `ArchRunProvenanceV1.cpuset_probe_chain_blake3` is a content ADDRESS; it is not self-sufficient.
//! This artifact is the mandatory retained EVIDENCE the address commits to: the complete nearest-first
//! probe chain (every entry, both observations) plus the candidate/arch/run/provenance binding and the
//! leaf/source/summary. Every authoritative per-arch measurement package retains one such artifact per
//! provenance record; the validator and independent verifier decode it, structurally re-validate the
//! canonical inheritance rules, recompute the domain-separated address from the retained bytes, and
//! require it equals the bound provenance field. A hash-only field is thereby never trusted alone.

use crate::codec::{DecodeError, Reader, Writer};
use crate::enums::{Arch, Candidate, ProvenanceRole};
use crate::schema::provenance::{
    check_cpuset_probe_chain, cpuset_probe_chain_hash, CpusetObsV1, CpusetProbeEntryV1,
};

/// Record-local schema version.
pub const CPUSET_PROBE_CHAIN_SCHEMA_VERSION: u16 = 1;
/// 32-byte kind tag (leads the canonical bytes, so a foreign record can never masquerade).
pub const CPUSET_PROBE_CHAIN_KIND: &[u8; 32] = b"b0-final-cpuset-probe-chain-v1\0\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpusetProbeChainV1 {
    // ---- binding: candidate / arch / run / provenance ----
    pub candidate: Candidate,
    pub arch: Arch,
    pub provenance_role: ProvenanceRole,
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    // ---- leaf / source / summary (must match the provenance record) ----
    pub leaf_scope: String,
    pub source_cgroup_path: String,
    pub summary_raw: String,
    pub summary_inherited: bool,
    pub summary_count: u32,
    // ---- the exact probe entries (two complete observations each) ----
    pub entries: Vec<CpusetProbeEntryV1>,
}

fn w_str(w: &mut Writer, s: &str) {
    w.u16(s.len() as u16);
    w.bytes(s.as_bytes());
}
fn r_str(r: &mut Reader, max: u32, ctx: &'static str) -> Result<String, DecodeError> {
    r.read_ascii_str(max, ctx)
}
fn w_opt_u64(w: &mut Writer, v: Option<u64>) {
    match v {
        Some(x) => {
            w.u8(1);
            w.u64(x);
        }
        None => w.u8(0),
    }
}
fn r_opt_u64(r: &mut Reader, ctx: &'static str) -> Result<Option<u64>, DecodeError> {
    match r.read_u8(ctx)? {
        0 => Ok(None),
        1 => Ok(Some(r.read_u64(ctx)?)),
        v => Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        }),
    }
}
fn w_opt_i64(w: &mut Writer, v: Option<i64>) {
    match v {
        Some(x) => {
            w.u8(1);
            w.u64(x as u64); // two's-complement bit pattern; reversible
        }
        None => w.u8(0),
    }
}
fn r_opt_i64(r: &mut Reader, ctx: &'static str) -> Result<Option<i64>, DecodeError> {
    match r.read_u8(ctx)? {
        0 => Ok(None),
        1 => Ok(Some(r.read_u64(ctx)? as i64)),
        v => Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        }),
    }
}
fn w_opt_str(w: &mut Writer, v: &Option<String>) {
    match v {
        Some(s) => {
            w.u8(1);
            w_str(w, s);
        }
        None => w.u8(0),
    }
}
fn r_opt_str(r: &mut Reader, ctx: &'static str) -> Result<Option<String>, DecodeError> {
    match r.read_u8(ctx)? {
        0 => Ok(None),
        1 => Ok(Some(r_str(r, 256, ctx)?)),
        v => Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        }),
    }
}

fn w_obs(w: &mut Writer, o: &CpusetObsV1) {
    w.u8(o.state);
    w_str(w, &o.raw);
    w_str(w, &o.file_type);
    w.u8(u8::from(o.is_symlink));
    w_opt_u64(w, o.dev);
    w_opt_u64(w, o.inode);
    w_opt_u64(w, o.size);
    w_opt_i64(w, o.mtime_secs);
    w_opt_i64(w, o.mtime_nanos);
    w_opt_str(w, &o.read_error_class);
}
fn r_obs(r: &mut Reader) -> Result<CpusetObsV1, DecodeError> {
    let state = r.read_u8("CpusetObs.state")?;
    if state > 2 {
        return Err(DecodeError::BadFixedScalar {
            ctx: "CpusetObs.state",
            value: state as u64,
        });
    }
    let raw = r_str(r, 256, "CpusetObs.raw")?;
    let file_type = r_str(r, 32, "CpusetObs.file_type")?;
    let is_symlink = match r.read_u8("CpusetObs.is_symlink")? {
        0 => false,
        1 => true,
        v => {
            return Err(DecodeError::BadFixedScalar {
                ctx: "CpusetObs.is_symlink",
                value: v as u64,
            })
        }
    };
    let dev = r_opt_u64(r, "CpusetObs.dev")?;
    let inode = r_opt_u64(r, "CpusetObs.inode")?;
    let size = r_opt_u64(r, "CpusetObs.size")?;
    let mtime_secs = r_opt_i64(r, "CpusetObs.mtime_secs")?;
    let mtime_nanos = r_opt_i64(r, "CpusetObs.mtime_nanos")?;
    let read_error_class = r_opt_str(r, "CpusetObs.read_error_class")?;
    Ok(CpusetObsV1 {
        state,
        raw,
        file_type,
        is_symlink,
        dev,
        inode,
        size,
        mtime_secs,
        mtime_nanos,
        read_error_class,
    })
}

impl CpusetProbeChainV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(CPUSET_PROBE_CHAIN_KIND);
        w.u16(CPUSET_PROBE_CHAIN_SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u8(self.arch.to_repr());
        w.u8(self.provenance_role.to_repr());
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w_str(&mut w, &self.leaf_scope);
        w_str(&mut w, &self.source_cgroup_path);
        w_str(&mut w, &self.summary_raw);
        w.u8(u8::from(self.summary_inherited));
        w.u32(self.summary_count);
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            w_str(&mut w, &e.cgroup_path);
            w.u32(e.order);
            w_obs(&mut w, &e.first);
            w_obs(&mut w, &e.second);
        }
        w.into_bytes()
    }

    /// The bound address = the SAME rule `ArchRunProvenanceV1.cpuset_probe_chain_blake3` commits to
    /// (over the entries alone).
    pub fn bound_address(&self) -> [u8; 32] {
        cpuset_probe_chain_hash(&self.entries)
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let kind = r.read_array::<32>("CpusetProbeChainV1.kind")?;
        if &kind != CPUSET_PROBE_CHAIN_KIND {
            return Err(DecodeError::BadTag {
                ctx: "CpusetProbeChainV1.kind",
            });
        }
        let sv = r.read_u16("CpusetProbeChainV1.schema_version")?;
        if sv != CPUSET_PROBE_CHAIN_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "CpusetProbeChainV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("CpusetProbeChainV1.candidate")?)?;
        let arch = Arch::from_repr(r.read_u8("CpusetProbeChainV1.arch")?)?;
        let provenance_role =
            ProvenanceRole::from_repr(r.read_u8("CpusetProbeChainV1.provenance_role")?)?;
        let b0_pre_spec_hash = r.read_array::<32>("CpusetProbeChainV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("CpusetProbeChainV1.r0_guest_set_hash")?;
        let leaf_scope = r_str(r, 128, "CpusetProbeChainV1.leaf_scope")?;
        let source_cgroup_path = r_str(r, 128, "CpusetProbeChainV1.source_cgroup_path")?;
        let summary_raw = r_str(r, 256, "CpusetProbeChainV1.summary_raw")?;
        let summary_inherited = match r.read_u8("CpusetProbeChainV1.summary_inherited")? {
            0 => false,
            1 => true,
            v => {
                return Err(DecodeError::BadFixedScalar {
                    ctx: "CpusetProbeChainV1.summary_inherited",
                    value: v as u64,
                })
            }
        };
        let summary_count = r.read_u32("CpusetProbeChainV1.summary_count")?;
        let n = r.read_u32("CpusetProbeChainV1.entry_count")?;
        if n > 4096 {
            return Err(DecodeError::CountExceedsMax {
                ctx: "CpusetProbeChainV1.entry_count",
                count: n as u64,
                max: 4096,
            });
        }
        let mut entries = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let cgroup_path = r_str(r, 128, "CpusetProbeChainV1.entry.cgroup_path")?;
            let order = r.read_u32("CpusetProbeChainV1.entry.order")?;
            let first = r_obs(r)?;
            let second = r_obs(r)?;
            entries.push(CpusetProbeEntryV1 {
                cgroup_path,
                order,
                first,
                second,
            });
        }
        Ok(Self {
            candidate,
            arch,
            provenance_role,
            b0_pre_spec_hash,
            r0_guest_set_hash,
            leaf_scope,
            source_cgroup_path,
            summary_raw,
            summary_inherited,
            summary_count,
            entries,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("CpusetProbeChainV1")?;
        Ok(v)
    }

    /// Structurally re-validate the retained chain against its own summary (the full canonical
    /// inheritance rules). Independent of any provenance record.
    pub fn structural_check(&self) -> Result<(), String> {
        check_cpuset_probe_chain(
            &self.entries,
            &self.leaf_scope,
            &self.source_cgroup_path,
            &self.summary_raw,
            self.summary_inherited,
            self.summary_count,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn sample() -> CpusetProbeChainV1 {
        CpusetProbeChainV1 {
            candidate: Candidate::Sp1,
            arch: Arch::X86_64,
            provenance_role: ProvenanceRole::Proving,
            b0_pre_spec_hash: [1; 32],
            r0_guest_set_hash: [2; 32],
            leaf_scope: "/b0.slice/measure".into(),
            source_cgroup_path: "/b0.slice".into(),
            summary_raw: "0-1".into(),
            summary_inherited: true,
            summary_count: 2,
            entries: vec![
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
            ],
        }
    }

    #[test]
    fn roundtrips_structural_and_bound_address() {
        let c = sample();
        assert_eq!(CpusetProbeChainV1::decode_exact(&c.encode()).unwrap(), c);
        assert!(c.structural_check().is_ok());
        // bound address equals the reference rule over the entries
        assert_eq!(c.bound_address(), cpuset_probe_chain_hash(&c.entries));
    }

    #[test]
    fn foreign_kind_and_truncation_and_trailing_rejected() {
        let bytes = sample().encode();
        // wrong kind
        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            CpusetProbeChainV1::decode_exact(&bad),
            Err(DecodeError::BadTag { .. })
        ));
        assert!(matches!(
            CpusetProbeChainV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            CpusetProbeChainV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn mutated_chain_fails_structural_or_changes_address() {
        let mut c = sample();
        // mutate an observation raw -> structural (count) mismatch OR address changes
        c.entries[1].first.raw = "0-3".into();
        c.entries[1].second.raw = "0-3".into();
        // summary still says count 2 / raw 0-1 -> structural refuses
        assert!(c.structural_check().is_err());
    }
}

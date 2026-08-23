//! `RustcInvocationInventoryV1` — the RETAINED, per-build (A or B), sorted-canonical set of the DISTINCT
//! rustc invocations the transparent wrapper recorded, holding the EXACT `--remap-path-prefix` ARGV bytes
//! for each invocation (not a destination CSV). The transparent wrapper writes one content-addressed
//! record per invocation (`b0-final-rustc-invocation/v2`); the inventory is their sorted, de-duplicated
//! union tagged with its build. At import both verifiers decode it from scratch and, against the
//! corresponding build side of `RunnerBuildRecipeV1`, prove: at least one real crate COMPILE; every
//! compile carries EXACTLY ONE remap arg whose FROM root equals that build's retained target root and
//! whose destination is exactly /b0/target (neither the source NOR the canonical cargo home is remapped —
//! the source is compiled at the canonical build path /b0/tooling and the cargo home is the literal
//! canonical /b0/cargo); no second remap; and each record's content address re-derives from the exact
//! record bytes. Its domain-separated [`hash`] is bound (per build) by the runner double-build proof +
//! attestation.

use super::runner_build_recipe::{r_str, w_str, BuildSide, CANON_TARGET};
use crate::codec::{DecodeError, Reader, Writer};
use crate::enums::{Arch, Candidate};

pub const RUSTC_INVOCATION_INVENTORY_SCHEMA_VERSION: u16 = 2;
pub const RUSTC_INVOCATION_INVENTORY_KIND: &[u8; 32] = b"b0-final-rustc-invoc-inv-v2\0\0\0\0\0";
pub const RUSTC_INVOCATION_INVENTORY_PREFIX: &[u8] = b"b0-final-rustc-invocation-inventory/v2\0";

/// The exact record header the wrapper writes (v2). The importer reconstructs the record bytes from
/// (kind, remap_args) and requires BLAKE3(record) == the retained `record_address`.
pub const INVOCATION_RECORD_HEADER: &str = "b0-final-rustc-invocation/v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationRecord {
    pub kind: String, // "compile" | "probe"
    /// The exact `--remap-path-prefix=FROM=TO` args, in the order rustc saw them.
    pub remap_args: Vec<String>,
    /// The content address the wrapper filed the record under (== BLAKE3 of the record bytes).
    pub record_address: [u8; 32],
}

/// Parse a `--remap-path-prefix=FROM=TO` arg into `(from, to)` (TO is after the last `=`).
pub fn parse_remap_arg(s: &str) -> Result<(String, String), String> {
    let rest = s
        .strip_prefix("--remap-path-prefix=")
        .ok_or_else(|| format!("not a --remap-path-prefix arg: {s:?}"))?;
    let eq = rest
        .rfind('=')
        .ok_or_else(|| format!("remap arg has no FROM=TO: {s:?}"))?;
    Ok((rest[..eq].to_string(), rest[eq + 1..].to_string()))
}

impl InvocationRecord {
    fn encode(&self, w: &mut Writer) {
        w_str(w, &self.kind);
        w.u32(self.remap_args.len() as u32);
        for a in &self.remap_args {
            w_str(w, a);
        }
        w.bytes(&self.record_address);
    }
    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let kind = r_str(r, 16, "InvocationRecord.kind")?;
        if kind != "compile" && kind != "probe" {
            return Err(DecodeError::BadValue {
                ctx: "InvocationRecord.kind",
            });
        }
        let n = r.read_u32("InvocationRecord.remap_args.count")? as usize;
        if n > 16 {
            return Err(DecodeError::BadValue {
                ctx: "InvocationRecord.remap_args.count",
            });
        }
        let mut remap_args = Vec::with_capacity(n);
        for _ in 0..n {
            remap_args.push(r_str(r, 8192, "InvocationRecord.remap_arg")?);
        }
        let record_address = r.read_array::<32>("InvocationRecord.record_address")?;
        Ok(Self {
            kind,
            remap_args,
            record_address,
        })
    }
    fn key(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.into_bytes()
    }
    /// The exact wrapper record bytes for this invocation (no trailing newline), so the content
    /// address can be re-derived and compared to `record_address`.
    pub fn reconstruct_record(&self) -> String {
        let mut s = String::from(INVOCATION_RECORD_HEADER);
        s.push_str("\nkind=");
        s.push_str(&self.kind);
        for a in &self.remap_args {
            s.push_str("\nremap_arg=");
            s.push_str(a);
        }
        s
    }
    /// Recomputed content address == BLAKE3(reconstructed record bytes).
    pub fn recompute_address(&self) -> [u8; 32] {
        *blake3::hash(self.reconstruct_record().as_bytes()).as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustcInvocationInventoryV1 {
    pub candidate: Candidate,
    pub arch: Arch,
    /// 0 = build A, 1 = build B.
    pub build_tag: u8,
    pub entries: Vec<InvocationRecord>,
}

impl RustcInvocationInventoryV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(RUSTC_INVOCATION_INVENTORY_KIND);
        w.u16(RUSTC_INVOCATION_INVENTORY_SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u8(self.arch.to_repr());
        w.u8(self.build_tag);
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            e.encode(&mut w);
        }
        w.into_bytes()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(RUSTC_INVOCATION_INVENTORY_PREFIX);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let kind = r.read_array::<32>("RustcInvocationInventoryV1.kind")?;
        if &kind != RUSTC_INVOCATION_INVENTORY_KIND {
            return Err(DecodeError::BadTag {
                ctx: "RustcInvocationInventoryV1.kind",
            });
        }
        let sv = r.read_u16("RustcInvocationInventoryV1.schema_version")?;
        if sv != RUSTC_INVOCATION_INVENTORY_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "RustcInvocationInventoryV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("RustcInvocationInventoryV1.candidate")?)?;
        let arch = Arch::from_repr(r.read_u8("RustcInvocationInventoryV1.arch")?)?;
        let build_tag = r.read_u8("RustcInvocationInventoryV1.build_tag")?;
        if build_tag > 1 {
            return Err(DecodeError::BadValue {
                ctx: "RustcInvocationInventoryV1.build_tag",
            });
        }
        let count = r.read_u32("RustcInvocationInventoryV1.count")? as usize;
        if count == 0 || count > 4096 {
            return Err(DecodeError::BadValue {
                ctx: "RustcInvocationInventoryV1.count",
            });
        }
        let mut entries = Vec::with_capacity(count);
        let mut prev: Option<Vec<u8>> = None;
        for _ in 0..count {
            let e = InvocationRecord::decode(r)?;
            let k = e.key();
            if let Some(p) = &prev {
                if *p >= k {
                    return Err(DecodeError::BadValue {
                        ctx: "RustcInvocationInventoryV1.unsorted_or_duplicate",
                    });
                }
            }
            prev = Some(k);
            entries.push(e);
        }
        Ok(Self {
            candidate,
            arch,
            build_tag,
            entries,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("RustcInvocationInventoryV1")?;
        Ok(v)
    }

    /// Fail-closed: for the given build SIDE (the recipe's build_a or build_b roots), at least one
    /// COMPILE; every compile carries exactly the ONE canonical target remap for that build's target
    /// root and no second (the canonical cargo home is NOT remapped); and EVERY record's content address
    /// re-derives from its exact bytes.
    pub fn check_proves_remaps(&self, side: &BuildSide) -> Result<(), String> {
        let mut compiles = 0usize;
        for e in &self.entries {
            // Every record's filename hash must agree with its bytes (no forged/altered record).
            if e.recompute_address() != e.record_address {
                return Err("invocation record content address != BLAKE3(record bytes)".into());
            }
            if e.kind != "compile" {
                continue;
            }
            compiles += 1;
            if e.remap_args.len() != 1 {
                return Err(format!(
                    "compile invocation has {} remap args (require exactly 1: the target; the \
                     canonical cargo home is not remapped)",
                    e.remap_args.len()
                ));
            }
            let (f, t) = parse_remap_arg(&e.remap_args[0])?;
            if f != side.target_from || t != CANON_TARGET {
                return Err(format!(
                    "compile remap is {f}={t} != {}={CANON_TARGET} (recipe side target root)",
                    side.target_from
                ));
            }
        }
        if compiles == 0 {
            return Err(
                "inventory has no COMPILE invocation (the remaps never reached a crate compile)"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Build a canonical inventory from an UNSORTED set of records (sorts + dedups). Used by producer +
/// independent generator; decode enforces the same invariant on import.
pub fn canonical_inventory(
    candidate: Candidate,
    arch: Arch,
    build_tag: u8,
    mut records: Vec<InvocationRecord>,
) -> RustcInvocationInventoryV1 {
    records.sort_by_key(|a| a.key());
    records.dedup_by(|a, b| a.key() == b.key());
    RustcInvocationInventoryV1 {
        candidate,
        arch,
        build_tag,
        entries: records,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_rec(target: &str) -> InvocationRecord {
        let remap_args = vec![format!("--remap-path-prefix={target}={CANON_TARGET}")];
        let mut rec = InvocationRecord {
            kind: "compile".into(),
            remap_args,
            record_address: [0; 32],
        };
        rec.record_address = rec.recompute_address();
        rec
    }

    fn side() -> BuildSide {
        BuildSide {
            original_root: "/b0-input/a/tooling".into(),
            target_from: "/b0-input/a/target".into(),
            encoded_rustflags: vec![],
        }
    }

    pub(crate) fn sample() -> RustcInvocationInventoryV1 {
        let probe = InvocationRecord {
            kind: "probe".into(),
            remap_args: vec![],
            record_address: [0; 32],
        };
        let mut probe = probe;
        probe.record_address = probe.recompute_address();
        canonical_inventory(
            Candidate::Sp1,
            Arch::X86_64,
            0,
            vec![compile_rec("/b0-input/a/target"), probe],
        )
    }

    #[test]
    fn roundtrips_and_proves_remaps() {
        let a = sample();
        assert_eq!(
            RustcInvocationInventoryV1::decode_exact(&a.encode()).unwrap(),
            a
        );
        assert_ne!(a.hash(), *blake3::hash(&a.encode()).as_bytes());
        a.check_proves_remaps(&side()).unwrap();
    }

    #[test]
    fn no_compile_refused() {
        let mut p = InvocationRecord {
            kind: "probe".into(),
            remap_args: vec![],
            record_address: [0; 32],
        };
        p.record_address = p.recompute_address();
        let inv = canonical_inventory(Candidate::Sp1, Arch::X86_64, 0, vec![p]);
        assert!(inv
            .check_proves_remaps(&side())
            .unwrap_err()
            .contains("no COMPILE"));
    }

    #[test]
    fn compile_from_not_matching_side_refused() {
        let inv = canonical_inventory(
            Candidate::Sp1,
            Arch::X86_64,
            0,
            vec![compile_rec("/b0-input/a/OTHER")],
        );
        assert!(inv
            .check_proves_remaps(&side())
            .unwrap_err()
            .contains("recipe side target root"));
    }

    #[test]
    fn forged_record_address_refused() {
        let mut rec = compile_rec("/b0-input/a/target");
        rec.record_address = [0xAB; 32]; // no longer BLAKE3(record bytes)
        let inv = canonical_inventory(Candidate::Sp1, Arch::X86_64, 0, vec![rec]);
        assert!(inv
            .check_proves_remaps(&side())
            .unwrap_err()
            .contains("content address"));
    }

    #[test]
    fn second_remap_refused() {
        // A fake cargo-home remap alongside the target remap is refused (only the target is remapped).
        let mut rec = compile_rec("/b0-input/a/target");
        rec.remap_args
            .push("--remap-path-prefix=/b0-input/a/cargo=/b0/cargo".into());
        rec.record_address = rec.recompute_address();
        let inv = canonical_inventory(Candidate::Sp1, Arch::X86_64, 0, vec![rec]);
        assert!(inv
            .check_proves_remaps(&side())
            .unwrap_err()
            .contains("exactly 1"));
    }
}

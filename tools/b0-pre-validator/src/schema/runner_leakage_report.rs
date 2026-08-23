//! `RunnerLeakageReportV1` — the RETAINED result of the exact-prefix leakage scan over the reproducible
//! runner binary. It records the scanned binary's BLAKE3, the permitted absolute prefixes (exactly
//! /b0/cargo,/b0/target,/b0/tooling), the refused prefixes the scan confirmed ABSENT, and the
//! evidence/temp root the wrapper wrote under. At sealed import both verifiers CROSS-BIND it to
//! `RunnerBuildRecipeV1`: the refused set must CONTAIN every retained A/B original + target root AND the
//! evidence root (a merely nonempty set is insufficient); the canonical cargo home /b0/cargo is a
//! PERMITTED prefix, NOT refused (there is no per-build cargo root to leak); the scan must be clean; the
//! permitted set must be exactly the canonical three; and the scanned binary must be the measurement
//! runner. Its domain-separated [`hash`] is bound by `RunnerAttestationV1.runner_leakage_report_blake3`.

use super::runner_build_recipe::{
    r_str, w_str, RunnerBuildRecipeV1, CANON_CARGO, CANON_TARGET, CANON_TOOLING,
};
use crate::codec::{DecodeError, Reader, Writer};
use crate::enums::{Arch, Candidate};

pub const RUNNER_LEAKAGE_REPORT_SCHEMA_VERSION: u16 = 2;
pub const RUNNER_LEAKAGE_REPORT_KIND: &[u8; 32] = b"b0-final-runner-leak-report-v2\0\0";
pub const RUNNER_LEAKAGE_REPORT_PREFIX: &[u8] = b"b0-final-runner-leakage-report/v2\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerLeakageReportV1 {
    pub candidate: Candidate,
    pub arch: Arch,
    pub scanned_binary_blake3: [u8; 32],
    pub clean: bool,
    /// The exact uncontrolled evidence/temp root the wrapper wrote under (must be in `refused_prefixes`).
    pub evidence_root: String,
    pub refused_prefixes: Vec<String>, // sorted + distinct; CONTAINS every A/B root + evidence_root
    pub permitted_prefixes: Vec<String>, // sorted; exactly the canonical three
}

fn w_list(w: &mut Writer, v: &[String]) {
    w.u32(v.len() as u32);
    for s in v {
        w_str(w, s);
    }
}
fn r_list(r: &mut Reader, max: usize, ctx: &'static str) -> Result<Vec<String>, DecodeError> {
    let n = r.read_u32(ctx)? as usize;
    if n > max {
        return Err(DecodeError::BadValue { ctx });
    }
    let mut v = Vec::with_capacity(n);
    let mut prev: Option<String> = None;
    for _ in 0..n {
        let s = r_str(r, 8192, ctx)?;
        if let Some(p) = &prev {
            if *p >= s {
                return Err(DecodeError::BadValue { ctx });
            }
        }
        prev = Some(s.clone());
        v.push(s);
    }
    Ok(v)
}

impl RunnerLeakageReportV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(RUNNER_LEAKAGE_REPORT_KIND);
        w.u16(RUNNER_LEAKAGE_REPORT_SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u8(self.arch.to_repr());
        w.bytes(&self.scanned_binary_blake3);
        w.u8(self.clean as u8);
        w_str(&mut w, &self.evidence_root);
        w_list(&mut w, &self.refused_prefixes);
        w_list(&mut w, &self.permitted_prefixes);
        w.into_bytes()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(RUNNER_LEAKAGE_REPORT_PREFIX);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let kind = r.read_array::<32>("RunnerLeakageReportV1.kind")?;
        if &kind != RUNNER_LEAKAGE_REPORT_KIND {
            return Err(DecodeError::BadTag {
                ctx: "RunnerLeakageReportV1.kind",
            });
        }
        let sv = r.read_u16("RunnerLeakageReportV1.schema_version")?;
        if sv != RUNNER_LEAKAGE_REPORT_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "RunnerLeakageReportV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("RunnerLeakageReportV1.candidate")?)?;
        let arch = Arch::from_repr(r.read_u8("RunnerLeakageReportV1.arch")?)?;
        let scanned_binary_blake3 =
            r.read_array::<32>("RunnerLeakageReportV1.scanned_binary_blake3")?;
        let clean = match r.read_u8("RunnerLeakageReportV1.clean")? {
            0 => false,
            1 => true,
            _ => {
                return Err(DecodeError::BadValue {
                    ctx: "RunnerLeakageReportV1.clean",
                })
            }
        };
        let evidence_root = r_str(r, 8192, "RunnerLeakageReportV1.evidence_root")?;
        let refused_prefixes = r_list(r, 4096, "RunnerLeakageReportV1.refused_prefixes")?;
        let permitted_prefixes = r_list(r, 16, "RunnerLeakageReportV1.permitted_prefixes")?;
        Ok(Self {
            candidate,
            arch,
            scanned_binary_blake3,
            clean,
            evidence_root,
            refused_prefixes,
            permitted_prefixes,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("RunnerLeakageReportV1")?;
        Ok(v)
    }

    fn canonical_permitted() -> Vec<String> {
        let mut v = vec![
            CANON_CARGO.to_string(),
            CANON_TARGET.to_string(),
            CANON_TOOLING.to_string(),
        ];
        v.sort();
        v
    }

    /// Fail-closed + CROSS-BOUND to the recipe: clean; permitted is exactly the canonical three; the
    /// refused set CONTAINS every retained A/B original/CARGO_HOME/target root AND the evidence root.
    pub fn check_clean_and_exact(&self, recipe: &RunnerBuildRecipeV1) -> Result<(), String> {
        if !self.clean {
            return Err("leakage report is not clean".into());
        }
        if self.permitted_prefixes != Self::canonical_permitted() {
            return Err("leakage permitted set != the canonical /b0/{cargo,target,tooling}".into());
        }
        let refused: std::collections::BTreeSet<&str> =
            self.refused_prefixes.iter().map(|s| s.as_str()).collect();
        let mut required = vec![
            recipe.build_a.original_root.as_str(),
            recipe.build_a.target_from.as_str(),
            recipe.build_b.original_root.as_str(),
            recipe.build_b.target_from.as_str(),
            self.evidence_root.as_str(),
        ];
        required.sort();
        required.dedup();
        for req in required {
            if !refused.contains(req) {
                return Err(format!(
                    "leakage refused set omits a required uncontrolled root: {req}"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe() -> RunnerBuildRecipeV1 {
        super::super::runner_build_recipe::tests_sample()
    }

    pub(crate) fn sample() -> RunnerLeakageReportV1 {
        let rc = recipe();
        let mut refused = vec![
            rc.build_a.original_root.clone(),
            rc.build_a.target_from.clone(),
            rc.build_b.original_root.clone(),
            rc.build_b.target_from.clone(),
            "/tmp/b0-evid".to_string(),
        ];
        refused.sort();
        refused.dedup();
        RunnerLeakageReportV1 {
            candidate: rc.candidate,
            arch: rc.arch,
            scanned_binary_blake3: [9; 32],
            clean: true,
            evidence_root: "/tmp/b0-evid".into(),
            refused_prefixes: refused,
            permitted_prefixes: RunnerLeakageReportV1::canonical_permitted(),
        }
    }

    #[test]
    fn roundtrips_and_cross_binds() {
        let a = sample();
        assert_eq!(RunnerLeakageReportV1::decode_exact(&a.encode()).unwrap(), a);
        assert_ne!(a.hash(), *blake3::hash(&a.encode()).as_bytes());
        a.check_clean_and_exact(&recipe()).unwrap();
    }

    #[test]
    fn refused_omitting_a_root_refused() {
        let mut a = sample();
        // Drop build B's target root from the refused set.
        let drop = recipe().build_b.target_from;
        a.refused_prefixes.retain(|s| s != &drop);
        assert!(a
            .check_clean_and_exact(&recipe())
            .unwrap_err()
            .contains("omits a required uncontrolled root"));
    }

    #[test]
    fn refused_omitting_evidence_root_refused() {
        let mut a = sample();
        let ev = a.evidence_root.clone();
        a.refused_prefixes.retain(|s| s != &ev);
        assert!(a
            .check_clean_and_exact(&recipe())
            .unwrap_err()
            .contains("omits a required uncontrolled root"));
    }

    #[test]
    fn unclean_and_wrong_permitted_refused() {
        let mut a = sample();
        a.clean = false;
        assert!(a
            .check_clean_and_exact(&recipe())
            .unwrap_err()
            .contains("not clean"));
        let mut b = sample();
        b.permitted_prefixes = vec!["/b0/tooling".into()];
        assert!(b
            .check_clean_and_exact(&recipe())
            .unwrap_err()
            .contains("permitted set"));
    }
}

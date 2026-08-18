//! `RunnerDoubleBuildProofV1` — the RETAINED proof that TWO clean builds from genuinely-distinct ORIGINAL
//! checkout roots — both materialized + compiled at the one canonical build path — produced the SAME
//! runner (and, for RISC Zero, the SAME embedded guest). It holds, for BOTH build A and build B
//! independently: that build's original root / CARGO_HOME / target roots, its runner SHA-256 + BLAKE3,
//! its RISC Zero embedded-guest image id + canonical methods.rs digest, its rustc-invocation inventory
//! ADDRESS, its authenticated ORIGIN + MATERIALIZED full-build-input manifest addresses, and its
//! start/end timestamps; plus the shared wrapper identity, the derived byte-equality verdict, and the
//! reproducibility-pair digest (recomputed from the A/B runner hashes).
//!
//! At sealed import both verifiers, against `RunnerBuildRecipeV1` and the two retained inventories,
//! require: A and B original roots genuinely DIFFER and equal the recipe's per-build roots; the
//! authenticated source inputs agree 4-way (origin_A == materialized_A == origin_B == materialized_B);
//! each inventory address matches the retained inventory and that inventory proves the canonical remaps
//! for its build; runner A == runner B (sha256 AND blake3); for RISC0 embedded guest A == B; the verdict
//! and reproducibility pair recompute; and build B started only after build A finished.

use super::runner_build_recipe::RunnerBuildRecipeV1;
use super::rustc_invocation_inventory::RustcInvocationInventoryV1;
use crate::codec::{DecodeError, Reader, Writer};
use crate::enums::{Arch, Candidate};

pub const RUNNER_DOUBLE_BUILD_PROOF_SCHEMA_VERSION: u16 = 2;
pub const RUNNER_DOUBLE_BUILD_PROOF_KIND: &[u8; 32] = b"b0-final-runner-dbl-build-proof0";
pub const RUNNER_DOUBLE_BUILD_PROOF_PREFIX: &[u8] = b"b0-final-runner-double-build-proof/v2\0";
pub const REPRODUCIBILITY_PAIR_DOMAIN: &[u8] = b"b0-final-runner-reproducibility-pair/v1\0";

use super::runner_build_recipe::{r_str, w_str};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildFacts {
    pub original_root: String,
    pub cargo_from: String,
    pub target_from: String,
    pub runner_sha256: [u8; 32],
    pub runner_blake3: [u8; 32],
    /// RISC Zero embedded-guest image id (32 bytes packed from `_ID: [u32; 8]`); all-zero for SP1/stub.
    pub guest_image_id: [u8; 32],
    /// BLAKE3 of the canonical `methods.rs` (binds the include form + image id); empty-blake3 for stub.
    pub guest_methods_blake3: [u8; 32],
    /// Domain-separated address of this build's retained `RustcInvocationInventoryV1`.
    pub inventory_address: [u8; 32],
    /// Authenticated full-build-input manifest address of this build's ORIGIN checkout root.
    pub origin_manifest_blake3: [u8; 32],
    /// Authenticated manifest address of the source AS MATERIALIZED at the canonical build path (must
    /// equal `origin_manifest_blake3` — the materialization reproduced the origin exactly).
    pub materialized_manifest_blake3: [u8; 32],
    pub start_unix: u64,
    pub end_unix: u64,
}

impl BuildFacts {
    fn encode(&self, w: &mut Writer) {
        w_str(w, &self.original_root);
        w_str(w, &self.cargo_from);
        w_str(w, &self.target_from);
        w.bytes(&self.runner_sha256);
        w.bytes(&self.runner_blake3);
        w.bytes(&self.guest_image_id);
        w.bytes(&self.guest_methods_blake3);
        w.bytes(&self.inventory_address);
        w.bytes(&self.origin_manifest_blake3);
        w.bytes(&self.materialized_manifest_blake3);
        w.u64(self.start_unix);
        w.u64(self.end_unix);
    }
    fn decode(r: &mut Reader, ctx: &'static str) -> Result<Self, DecodeError> {
        Ok(Self {
            original_root: r_str(r, 4096, ctx)?,
            cargo_from: r_str(r, 4096, ctx)?,
            target_from: r_str(r, 4096, ctx)?,
            runner_sha256: r.read_array::<32>(ctx)?,
            runner_blake3: r.read_array::<32>(ctx)?,
            guest_image_id: r.read_array::<32>(ctx)?,
            guest_methods_blake3: r.read_array::<32>(ctx)?,
            inventory_address: r.read_array::<32>(ctx)?,
            origin_manifest_blake3: r.read_array::<32>(ctx)?,
            materialized_manifest_blake3: r.read_array::<32>(ctx)?,
            start_unix: r.read_u64(ctx)?,
            end_unix: r.read_u64(ctx)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerDoubleBuildProofV1 {
    pub candidate: Candidate,
    pub arch: Arch,
    pub wrapper_blake3: [u8; 32],
    pub build_a: BuildFacts,
    pub build_b: BuildFacts,
    pub byte_equal: bool,
    pub reproducibility_pair_blake3: [u8; 32],
}

impl RunnerDoubleBuildProofV1 {
    /// Reproducibility-pair digest recomputed from the A/B runner hashes (never trusted as stored).
    pub fn compute_reproducibility_pair(a: &BuildFacts, b: &BuildFacts) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(REPRODUCIBILITY_PAIR_DOMAIN);
        h.update(&a.runner_sha256);
        h.update(&a.runner_blake3);
        h.update(&b.runner_sha256);
        h.update(&b.runner_blake3);
        *h.finalize().as_bytes()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(RUNNER_DOUBLE_BUILD_PROOF_KIND);
        w.u16(RUNNER_DOUBLE_BUILD_PROOF_SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u8(self.arch.to_repr());
        w.bytes(&self.wrapper_blake3);
        self.build_a.encode(&mut w);
        self.build_b.encode(&mut w);
        w.u8(self.byte_equal as u8);
        w.bytes(&self.reproducibility_pair_blake3);
        w.into_bytes()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(RUNNER_DOUBLE_BUILD_PROOF_PREFIX);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let kind = r.read_array::<32>("RunnerDoubleBuildProofV1.kind")?;
        if &kind != RUNNER_DOUBLE_BUILD_PROOF_KIND {
            return Err(DecodeError::BadTag {
                ctx: "RunnerDoubleBuildProofV1.kind",
            });
        }
        let sv = r.read_u16("RunnerDoubleBuildProofV1.schema_version")?;
        if sv != RUNNER_DOUBLE_BUILD_PROOF_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "RunnerDoubleBuildProofV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("RunnerDoubleBuildProofV1.candidate")?)?;
        let arch = Arch::from_repr(r.read_u8("RunnerDoubleBuildProofV1.arch")?)?;
        let wrapper_blake3 = r.read_array::<32>("RunnerDoubleBuildProofV1.wrapper_blake3")?;
        let build_a = BuildFacts::decode(r, "RunnerDoubleBuildProofV1.build_a")?;
        let build_b = BuildFacts::decode(r, "RunnerDoubleBuildProofV1.build_b")?;
        let byte_equal = match r.read_u8("RunnerDoubleBuildProofV1.byte_equal")? {
            0 => false,
            1 => true,
            _ => {
                return Err(DecodeError::BadValue {
                    ctx: "RunnerDoubleBuildProofV1.byte_equal",
                })
            }
        };
        let reproducibility_pair_blake3 =
            r.read_array::<32>("RunnerDoubleBuildProofV1.reproducibility_pair_blake3")?;
        Ok(Self {
            candidate,
            arch,
            wrapper_blake3,
            build_a,
            build_b,
            byte_equal,
            reproducibility_pair_blake3,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("RunnerDoubleBuildProofV1")?;
        Ok(v)
    }

    /// Fail-closed: A/B roots genuinely differ and equal the recipe's per-build roots; each inventory
    /// address matches the retained inventory and that inventory proves the canonical remaps for its
    /// build; runner A == runner B; (RISC0) embedded guest A == B; verdict + pair recompute; chronology.
    pub fn check_double_build(
        &self,
        recipe: &RunnerBuildRecipeV1,
        inv_a: &RustcInvocationInventoryV1,
        inv_b: &RustcInvocationInventoryV1,
    ) -> Result<(), String> {
        if self.candidate != recipe.candidate || self.arch != recipe.arch {
            return Err("double-build proof candidate/arch != recipe".into());
        }
        if self.wrapper_blake3 != recipe.wrapper_blake3 {
            return Err("double-build proof wrapper != recipe wrapper".into());
        }
        // A/B roots equal the recipe's per-build roots.
        let side_ok = |f: &BuildFacts,
                       s: &super::runner_build_recipe::BuildSide,
                       w: &str|
         -> Result<(), String> {
            if f.original_root != s.original_root
                || f.cargo_from != s.cargo_from
                || f.target_from != s.target_from
            {
                return Err(format!(
                    "double-build proof build {w} roots != recipe build {w} roots"
                ));
            }
            Ok(())
        };
        side_ok(&self.build_a, &recipe.build_a, "A")?;
        side_ok(&self.build_b, &recipe.build_b, "B")?;
        // Genuine distinction: the two original checkout roots differ.
        if self.build_a.original_root == self.build_b.original_root {
            return Err(
                "double-build proof: build A and build B share the same original checkout root"
                    .into(),
            );
        }
        // Authenticated source inputs: the two builds are the SAME build inputs, and each canonical-path
        // materialization reproduced its origin EXACTLY — origin_A == materialized_A, origin_B ==
        // materialized_B, origin_A == origin_B (distinct PATHS alone are insufficient; this binds the
        // full-build-input manifest addresses the shell authenticated).
        if self.build_a.origin_manifest_blake3 != self.build_a.materialized_manifest_blake3 {
            return Err("double-build proof: build A materialized manifest != origin manifest (materialization not faithful)".into());
        }
        if self.build_b.origin_manifest_blake3 != self.build_b.materialized_manifest_blake3 {
            return Err("double-build proof: build B materialized manifest != origin manifest (materialization not faithful)".into());
        }
        if self.build_a.origin_manifest_blake3 != self.build_b.origin_manifest_blake3 {
            return Err("double-build proof: build A and build B origin manifests differ (not the same build inputs)".into());
        }
        // Inventories: addresses match the retained inventories, correct build tags, prove remaps.
        if inv_a.hash() != self.build_a.inventory_address {
            return Err("build A inventory address != retained inventory".into());
        }
        if inv_b.hash() != self.build_b.inventory_address {
            return Err("build B inventory address != retained inventory".into());
        }
        if inv_a.build_tag != 0 || inv_b.build_tag != 1 {
            return Err("inventory build tags are not (A=0, B=1)".into());
        }
        if inv_a.candidate != self.candidate
            || inv_a.arch != self.arch
            || inv_b.candidate != self.candidate
            || inv_b.arch != self.arch
        {
            return Err("inventory candidate/arch != proof".into());
        }
        inv_a.check_proves_remaps(&recipe.build_a)?;
        inv_b.check_proves_remaps(&recipe.build_b)?;
        // Runner A == runner B (sha256 AND blake3).
        if self.build_a.runner_sha256 != self.build_b.runner_sha256
            || self.build_a.runner_blake3 != self.build_b.runner_blake3
        {
            return Err("runner A != runner B (not reproducible)".into());
        }
        // Verdict derived from the retained hashes.
        let eq = self.build_a.runner_sha256 == self.build_b.runner_sha256
            && self.build_a.runner_blake3 == self.build_b.runner_blake3;
        if self.byte_equal != eq {
            return Err("byte_equal verdict does not match the retained runner hashes".into());
        }
        // RISC Zero: embedded guest A == B (image id AND canonical methods.rs digest).
        if self.candidate == Candidate::Risc0
            && (self.build_a.guest_image_id != self.build_b.guest_image_id
                || self.build_a.guest_methods_blake3 != self.build_b.guest_methods_blake3)
        {
            return Err("RISC0 embedded guest A != B (image id / methods.rs digest)".into());
        }
        // Reproducibility pair recomputes from the retained hashes.
        if Self::compute_reproducibility_pair(&self.build_a, &self.build_b)
            != self.reproducibility_pair_blake3
        {
            return Err(
                "reproducibility_pair_blake3 != recomputed from retained runner hashes".into(),
            );
        }
        // Chronology: build B started only after build A finished (separate runs, separate roots).
        if self.build_b.start_unix < self.build_a.end_unix {
            return Err("double-build proof: build B started before build A finished".into());
        }
        Ok(())
    }
}

/// A self-consistent (recipe, inventory A, inventory B, proof) set for cross-module tests.
#[cfg(test)]
pub(crate) fn tests_parts() -> (
    RunnerBuildRecipeV1,
    RustcInvocationInventoryV1,
    RustcInvocationInventoryV1,
    RunnerDoubleBuildProofV1,
) {
    tests::parts()
}

#[cfg(test)]
mod tests {
    use super::super::rustc_invocation_inventory::{canonical_inventory, InvocationRecord};
    use super::*;

    fn compile_rec(cargo: &str, target: &str) -> InvocationRecord {
        use super::super::runner_build_recipe::{CANON_CARGO, CANON_TARGET};
        let mut rec = InvocationRecord {
            kind: "compile".into(),
            remap_args: vec![
                format!("--remap-path-prefix={cargo}={CANON_CARGO}"),
                format!("--remap-path-prefix={target}={CANON_TARGET}"),
            ],
            record_address: [0; 32],
        };
        rec.record_address = rec.recompute_address();
        rec
    }

    pub(crate) fn parts() -> (
        RunnerBuildRecipeV1,
        RustcInvocationInventoryV1,
        RustcInvocationInventoryV1,
        RunnerDoubleBuildProofV1,
    ) {
        let recipe = super::super::runner_build_recipe::tests_sample();
        let inv_a = canonical_inventory(
            recipe.candidate,
            recipe.arch,
            0,
            vec![compile_rec(
                &recipe.build_a.cargo_from,
                &recipe.build_a.target_from,
            )],
        );
        let inv_b = canonical_inventory(
            recipe.candidate,
            recipe.arch,
            1,
            vec![compile_rec(
                &recipe.build_b.cargo_from,
                &recipe.build_b.target_from,
            )],
        );
        let fa = BuildFacts {
            original_root: recipe.build_a.original_root.clone(),
            cargo_from: recipe.build_a.cargo_from.clone(),
            target_from: recipe.build_a.target_from.clone(),
            runner_sha256: [11; 32],
            runner_blake3: [12; 32],
            guest_image_id: [0; 32],
            guest_methods_blake3: [13; 32],
            inventory_address: inv_a.hash(),
            origin_manifest_blake3: [21; 32],
            materialized_manifest_blake3: [21; 32],
            start_unix: 100,
            end_unix: 200,
        };
        let fb = BuildFacts {
            original_root: recipe.build_b.original_root.clone(),
            cargo_from: recipe.build_b.cargo_from.clone(),
            target_from: recipe.build_b.target_from.clone(),
            runner_sha256: [11; 32],
            runner_blake3: [12; 32],
            guest_image_id: [0; 32],
            guest_methods_blake3: [13; 32],
            inventory_address: inv_b.hash(),
            origin_manifest_blake3: [21; 32],
            materialized_manifest_blake3: [21; 32],
            start_unix: 200,
            end_unix: 300,
        };
        let proof = RunnerDoubleBuildProofV1 {
            candidate: recipe.candidate,
            arch: recipe.arch,
            wrapper_blake3: recipe.wrapper_blake3,
            reproducibility_pair_blake3: RunnerDoubleBuildProofV1::compute_reproducibility_pair(
                &fa, &fb,
            ),
            build_a: fa,
            build_b: fb,
            byte_equal: true,
        };
        (recipe, inv_a, inv_b, proof)
    }

    #[test]
    fn roundtrips_and_checks() {
        let (recipe, inv_a, inv_b, proof) = parts();
        assert_eq!(
            RunnerDoubleBuildProofV1::decode_exact(&proof.encode()).unwrap(),
            proof
        );
        assert_ne!(proof.hash(), *blake3::hash(&proof.encode()).as_bytes());
        proof.check_double_build(&recipe, &inv_a, &inv_b).unwrap();
    }

    #[test]
    fn runner_a_ne_b_refused() {
        let (recipe, inv_a, inv_b, mut proof) = parts();
        proof.build_b.runner_blake3 = [99; 32];
        proof.reproducibility_pair_blake3 =
            RunnerDoubleBuildProofV1::compute_reproducibility_pair(&proof.build_a, &proof.build_b);
        proof.byte_equal = false;
        assert!(proof
            .check_double_build(&recipe, &inv_a, &inv_b)
            .unwrap_err()
            .contains("runner A != runner B"));
    }

    #[test]
    fn unfaithful_materialization_refused() {
        // Build B's materialized manifest != its origin manifest -> refused (a stale/mutated copy).
        let (recipe, inv_a, inv_b, mut proof) = parts();
        proof.build_b.materialized_manifest_blake3 = [99; 32];
        assert!(proof
            .check_double_build(&recipe, &inv_a, &inv_b)
            .unwrap_err()
            .contains("materialized manifest != origin manifest"));
    }

    #[test]
    fn differing_origin_manifests_refused() {
        // A and B origin manifests differ -> not the same build inputs -> refused.
        let (recipe, inv_a, inv_b, mut proof) = parts();
        proof.build_b.origin_manifest_blake3 = [98; 32];
        proof.build_b.materialized_manifest_blake3 = [98; 32];
        assert!(proof
            .check_double_build(&recipe, &inv_a, &inv_b)
            .unwrap_err()
            .contains("origin manifests differ"));
    }

    #[test]
    fn forged_repro_pair_refused() {
        let (recipe, inv_a, inv_b, mut proof) = parts();
        proof.reproducibility_pair_blake3 = [7; 32];
        assert!(proof
            .check_double_build(&recipe, &inv_a, &inv_b)
            .unwrap_err()
            .contains("reproducibility_pair"));
    }

    #[test]
    fn risc0_guest_ab_mismatch_refused() {
        let (mut recipe, mut inv_a, mut inv_b, mut proof) = parts();
        recipe.candidate = Candidate::Risc0;
        recipe.recipe_id = RunnerBuildRecipeV1::compute_recipe_id(
            &recipe.measured_source_commit,
            &recipe.wrapper_blake3,
        );
        inv_a.candidate = Candidate::Risc0;
        inv_b.candidate = Candidate::Risc0;
        proof.candidate = Candidate::Risc0;
        proof.build_a.inventory_address = inv_a.hash();
        proof.build_b.inventory_address = inv_b.hash();
        proof.build_a.guest_image_id = [1; 32];
        proof.build_b.guest_image_id = [2; 32];
        assert!(proof
            .check_double_build(&recipe, &inv_a, &inv_b)
            .unwrap_err()
            .contains("guest A != B"));
    }
}

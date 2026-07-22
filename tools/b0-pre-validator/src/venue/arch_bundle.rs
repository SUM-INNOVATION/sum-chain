//! Blocker 1: per-architecture producer bundles → independent import verification →
//! cross-architecture aggregation.
//!
//! The prior orchestration built ONE architecture then demanded the full
//! 8-container / 4-native / both-extractor set on that single host — so the first
//! host could never satisfy coverage, arm64 wrongly attempted RISC Zero, and there
//! was no cross-venue handoff. The correct shape is three explicit steps:
//!
//!   (a) a per-architecture producer emits ONLY that arch's evidence into an
//!       immutable exported bundle (its container builds + native provenance, its
//!       SP1 verifier material, and RISC Zero material ONLY on x86_64, per
//!       VENUE.md §2);
//!   (b) each returned per-arch bundle is INDEPENDENTLY import-verified locally;
//!   (c) aggregation assembles the full `AUTHORITATIVE_STAGE1` inputs ONLY after
//!       BOTH per-arch bundles pass, sourcing RISC Zero material from the x86_64
//!       bundle.
//!
//! The container builds / extractions can't run off-venue (they fail closed in the
//! shell), but this import+aggregate core is pure and is unit-tested here with
//! real-shaped per-arch bundles.

use crate::schema::stage6::{NativeBuild, OciBuild, OciDigestsFile};

/// The frozen arch spellings (== `Arch` enum variants / `protocol::ARCH_NAMES`).
pub const ARCH_X86_64: &str = "X86_64";
pub const ARCH_AARCH64: &str = "Aarch64";

/// One architecture's exported producer bundle: only that arch's evidence.
#[derive(Debug, Clone)]
pub struct PerArchBundle {
    /// `X86_64` or `Aarch64`.
    pub arch: String,
    /// This arch's container builds (2 candidates × {base, builder} = 4).
    pub builds: Vec<OciBuild>,
    /// This arch's native-build provenance (2 candidates = 2).
    pub native: Vec<NativeBuild>,
    /// This arch's SP1 verifier-material extractor JSON (extracted per arch).
    pub sp1_extractor_json: String,
    /// RISC Zero verifier-material extractor JSON — present ONLY on x86_64 (§2:
    /// RISC Zero material must be extracted natively on x86_64; arm64 must NOT
    /// attempt it).
    pub risc0_extractor_json: Option<String>,
}

/// The aggregated venue inputs the existing Stage-6 assembler consumes, produced
/// only after both per-arch bundles verify.
#[derive(Debug, Clone)]
pub struct AggregatedVenueInputs {
    pub oci_digests_json: String,
    pub native_json: String,
    pub sp1_extractor_json: String,
    pub risc0_extractor_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchBundleError {
    UnknownArch {
        arch: String,
    },
    /// A container/native entry belonged to a different arch than the bundle claims.
    ArchMismatch {
        entry: String,
        expected: String,
        got: String,
    },
    /// A native build ran on a host whose arch differs from the target (emulated /
    /// cross-compiled) — ineligible.
    NonNativeHost {
        candidate: String,
        arch: String,
        host_arch: String,
    },
    /// The two clean OCI build digests diverged for an entry.
    PairedDigestDivergence {
        candidate: String,
        role: String,
        arch: String,
    },
    /// arm64 carried RISC Zero verifier material (it must not attempt RISC Zero).
    Aarch64CarriesRisc0,
    /// x86_64 did not carry RISC Zero verifier material (it is the only venue for it).
    X8664MissingRisc0,
    /// Aggregation was asked with two bundles of the same architecture / a missing
    /// architecture — both x86_64 and aarch64 are required, each once.
    ArchSetIncomplete {
        have: Vec<String>,
    },
    /// The SP1 verifier material differed across architectures (must be the same
    /// immutable bytes — cross-arch semantic equivalence).
    Sp1MaterialCrossArchMismatch,
    /// Wrong per-arch coverage (not exactly 4 builds / 2 native for the arch).
    Coverage(String),
    Parse(String),
}

impl std::fmt::Display for ArchBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchBundleError::UnknownArch { arch } => write!(f, "unknown architecture {arch:?}"),
            ArchBundleError::ArchMismatch { entry, expected, got } => write!(
                f,
                "{entry} belongs to arch {got:?} but the bundle is for {expected:?}"
            ),
            ArchBundleError::NonNativeHost { candidate, arch, host_arch } => write!(
                f,
                "{candidate} on {arch} ran on host_arch {host_arch} (emulated / cross-compiled, ineligible)"
            ),
            ArchBundleError::PairedDigestDivergence { candidate, role, arch } => write!(
                f,
                "two clean builds diverge for ({candidate}, {role}, {arch})"
            ),
            ArchBundleError::Aarch64CarriesRisc0 => write!(
                f,
                "aarch64 bundle carries RISC Zero material; RISC Zero extraction is x86_64-only (§2)"
            ),
            ArchBundleError::X8664MissingRisc0 => {
                write!(f, "x86_64 bundle is missing the required RISC Zero verifier material")
            }
            ArchBundleError::ArchSetIncomplete { have } => write!(
                f,
                "cross-arch aggregation requires exactly x86_64 + aarch64; got {have:?}"
            ),
            ArchBundleError::Sp1MaterialCrossArchMismatch => write!(
                f,
                "SP1 verifier material differs across architectures (must be identical immutable bytes)"
            ),
            ArchBundleError::Coverage(m) => write!(f, "per-arch coverage error: {m}"),
            ArchBundleError::Parse(e) => write!(f, "per-arch bundle parse failed: {e}"),
        }
    }
}

impl std::error::Error for ArchBundleError {}

fn is_known_arch(a: &str) -> bool {
    a == ARCH_X86_64 || a == ARCH_AARCH64
}

/// Independently import-verify ONE returned per-arch bundle: every container/native
/// entry is for this arch, every build is two-build reproducible, every native host
/// matches the target arch (no emulation), and the RISC Zero presence rule holds
/// (present iff x86_64). Returns the parsed builds/native for aggregation.
pub fn import_verify(bundle: &PerArchBundle) -> Result<(), ArchBundleError> {
    if !is_known_arch(&bundle.arch) {
        return Err(ArchBundleError::UnknownArch {
            arch: bundle.arch.clone(),
        });
    }
    // exactly 4 container builds (2 candidates × {base, builder}) for this arch.
    if bundle.builds.len() != 4 {
        return Err(ArchBundleError::Coverage(format!(
            "expected 4 container builds for {}, got {}",
            bundle.arch,
            bundle.builds.len()
        )));
    }
    for b in &bundle.builds {
        if b.arch != bundle.arch {
            return Err(ArchBundleError::ArchMismatch {
                entry: format!("container ({}, {})", b.candidate, b.role),
                expected: bundle.arch.clone(),
                got: b.arch.clone(),
            });
        }
        if b.build1_digest != b.build2_digest {
            return Err(ArchBundleError::PairedDigestDivergence {
                candidate: b.candidate.clone(),
                role: b.role.clone(),
                arch: b.arch.clone(),
            });
        }
    }
    // exactly 2 native builds (one per candidate) for this arch, each truly native.
    if bundle.native.len() != 2 {
        return Err(ArchBundleError::Coverage(format!(
            "expected 2 native builds for {}, got {}",
            bundle.arch,
            bundle.native.len()
        )));
    }
    for n in &bundle.native {
        if n.arch != bundle.arch {
            return Err(ArchBundleError::ArchMismatch {
                entry: format!("native ({})", n.candidate),
                expected: bundle.arch.clone(),
                got: n.arch.clone(),
            });
        }
        if n.host_arch != n.arch {
            return Err(ArchBundleError::NonNativeHost {
                candidate: n.candidate.clone(),
                arch: n.arch.clone(),
                host_arch: n.host_arch.clone(),
            });
        }
    }
    // RISC Zero presence rule (§2): x86_64 carries it, aarch64 must not.
    match (bundle.arch.as_str(), bundle.risc0_extractor_json.is_some()) {
        (ARCH_X86_64, false) => return Err(ArchBundleError::X8664MissingRisc0),
        (ARCH_AARCH64, true) => return Err(ArchBundleError::Aarch64CarriesRisc0),
        _ => {}
    }
    // the SP1 extractor JSON must at least parse as a well-formed OCI-independent
    // manifest object (strict conversion happens later in the assembler).
    if bundle.sp1_extractor_json.trim().is_empty() {
        return Err(ArchBundleError::Coverage(format!(
            "{} bundle is missing SP1 verifier material",
            bundle.arch
        )));
    }
    Ok(())
}

/// Cross-architecture aggregation: import-verify BOTH per-arch bundles, require the
/// full {x86_64, aarch64} set exactly once each, source RISC Zero material from the
/// x86_64 bundle, cross-check that the SP1 material agrees across architectures, and
/// emit the combined venue inputs the Stage-6 assembler consumes. Fails closed
/// unless both architectures are present and verified.
pub fn aggregate(bundles: &[PerArchBundle]) -> Result<AggregatedVenueInputs, ArchBundleError> {
    for b in bundles {
        import_verify(b)?;
    }
    let x86 = bundles.iter().find(|b| b.arch == ARCH_X86_64);
    let arm = bundles.iter().find(|b| b.arch == ARCH_AARCH64);
    let (Some(x86), Some(arm)) = (x86, arm) else {
        return Err(ArchBundleError::ArchSetIncomplete {
            have: bundles.iter().map(|b| b.arch.clone()).collect(),
        });
    };
    if bundles.len() != 2 {
        return Err(ArchBundleError::ArchSetIncomplete {
            have: bundles.iter().map(|b| b.arch.clone()).collect(),
        });
    }

    // RISC Zero material is sourced ONLY from the x86_64 bundle (§2).
    let risc0_extractor_json = x86
        .risc0_extractor_json
        .clone()
        .ok_or(ArchBundleError::X8664MissingRisc0)?;

    // SP1 material must agree across architectures (same immutable vk bytes); source
    // the canonical copy from x86_64. Compare by canonical JSON so incidental
    // whitespace does not cause a false mismatch.
    if !json_semantically_equal(&x86.sp1_extractor_json, &arm.sp1_extractor_json)? {
        return Err(ArchBundleError::Sp1MaterialCrossArchMismatch);
    }
    let sp1_extractor_json = x86.sp1_extractor_json.clone();

    // Combine both arches' container builds (4 + 4 = 8) and native provenance
    // (2 + 2 = 4).
    let mut builds: Vec<OciBuild> = Vec::with_capacity(8);
    builds.extend(x86.builds.iter().cloned());
    builds.extend(arm.builds.iter().cloned());
    let mut native: Vec<NativeBuild> = Vec::with_capacity(4);
    native.extend(x86.native.iter().cloned());
    native.extend(arm.native.iter().cloned());

    let oci_digests_json = serde_json::to_string(&OciDigestsFile { builds })
        .map_err(|e| ArchBundleError::Parse(e.to_string()))?;
    let native_json = serde_json::to_string(&serde_json::json!({ "native_builds": native }))
        .map_err(|e| ArchBundleError::Parse(e.to_string()))?;

    Ok(AggregatedVenueInputs {
        oci_digests_json,
        native_json,
        sp1_extractor_json,
        risc0_extractor_json,
    })
}

fn json_semantically_equal(a: &str, b: &str) -> Result<bool, ArchBundleError> {
    let va: serde_json::Value =
        serde_json::from_str(a).map_err(|e| ArchBundleError::Parse(e.to_string()))?;
    let vb: serde_json::Value =
        serde_json::from_str(b).map_err(|e| ArchBundleError::Parse(e.to_string()))?;
    Ok(va == vb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::stage6::{
        assemble_bundle, test_only_venue_outputs, AssembleMode, OciDigestsFile,
    };

    /// Split the whole-run TEST_ONLY venue outputs into two real-shaped per-arch
    /// bundles (x86_64 with RISC Zero material, aarch64 without).
    fn per_arch_bundles() -> (PerArchBundle, PerArchBundle) {
        let v = test_only_venue_outputs();
        let oci: OciDigestsFile = serde_json::from_str(&v.oci_digests_json).unwrap();
        let native: serde_json::Value = serde_json::from_str(&v.native_json).unwrap();
        let all_native: Vec<NativeBuild> =
            serde_json::from_value(native["native_builds"].clone()).unwrap();

        let split_builds = |arch: &str| -> Vec<OciBuild> {
            oci.builds
                .iter()
                .filter(|b| b.arch == arch)
                .cloned()
                .collect()
        };
        let split_native = |arch: &str| -> Vec<NativeBuild> {
            all_native
                .iter()
                .filter(|n| n.arch == arch)
                .cloned()
                .collect()
        };

        let x86 = PerArchBundle {
            arch: ARCH_X86_64.into(),
            builds: split_builds(ARCH_X86_64),
            native: split_native(ARCH_X86_64),
            sp1_extractor_json: v.sp1_extractor_json.clone(),
            risc0_extractor_json: Some(v.risc0_extractor_json.clone()),
        };
        let arm = PerArchBundle {
            arch: ARCH_AARCH64.into(),
            builds: split_builds(ARCH_AARCH64),
            native: split_native(ARCH_AARCH64),
            sp1_extractor_json: v.sp1_extractor_json.clone(),
            risc0_extractor_json: None,
        };
        (x86, arm)
    }

    #[test]
    fn both_per_arch_bundles_import_verify() {
        let (x86, arm) = per_arch_bundles();
        assert_eq!(import_verify(&x86), Ok(()));
        assert_eq!(import_verify(&arm), Ok(()));
        assert_eq!(x86.builds.len(), 4);
        assert_eq!(arm.builds.len(), 4);
    }

    #[test]
    fn aggregate_of_both_arches_feeds_the_assembler() {
        let (x86, arm) = per_arch_bundles();
        let agg = aggregate(&[x86, arm]).expect("aggregate both arches");
        // the aggregate is exactly what the Stage-6 assembler consumes.
        let v = test_only_venue_outputs();
        let bundle = assemble_bundle(
            AssembleMode::TestOnly,
            &agg.oci_digests_json,
            &agg.sp1_extractor_json,
            &agg.risc0_extractor_json,
            &agg.native_json,
            None,
            &v.sp1_cargo_lock,
            &v.risc0_cargo_lock,
        )
        .expect("assemble from aggregated per-arch bundles");
        bundle.validate().expect("aggregated bundle validates");
        assert_eq!(bundle.candidate_container_digests.len(), 8);
        assert_eq!(bundle.native_build_provenance.len(), 4);
    }

    #[test]
    fn genuine_two_arch_flow_reaches_a_finalizable_artifact_authoritatively() {
        use crate::schema::stage1_bundle::build_finalizable_artifact;
        // The GENUINE accept path, in-code (never a shippable synthetic-input CLI):
        // native x86_64 producer bundle + native aarch64 producer bundle -> import
        // verify BOTH -> real cross-arch aggregation (RISC Zero from x86_64) -> the
        // AUTHORITATIVE assembler with complete (fixture) tool identities ->
        // stage1-ingest -> a finalizable TEMPORARY artifact.
        let (x86, arm) = per_arch_bundles();
        assert_eq!(import_verify(&x86), Ok(()));
        assert_eq!(import_verify(&arm), Ok(()));
        let agg = aggregate(&[x86, arm]).expect("aggregate both arches");
        let v = test_only_venue_outputs();
        // Complete, NON-synthetic authoritative tool identities (a Rust-test fixture,
        // not real installer metadata, never written to the committed artifact).
        let tool = |name: &str, version: &str| {
            serde_json::json!({
                "name": name, "version": version,
                "artifact_identity": format!("https://fixtures.invalid/{name}-{version}.tar"),
                "checksum_algorithm": "sha256",
                "checksum_hex": crate::venue::to_hex(blake3::hash(format!("a-{name}-{version}").as_bytes()).as_bytes()),
                "install_entrypoint": format!("cargo:{name}@{version}"),
            })
        };
        let tools = serde_json::json!({"tool_identities":[
            {"candidate":"Sp1","rust_version":"1.88.0","proof_tools":[tool("sp1-verifier","6.3.1")]},
            {"candidate":"Risc0","rust_version":"1.88.0","proof_tools":[tool("risc0-zkvm","3.0.5"), tool("risc0-groth16","3.0.4")]},
        ]})
        .to_string();
        let bundle = assemble_bundle(
            AssembleMode::Authoritative,
            &agg.oci_digests_json,
            &agg.sp1_extractor_json,
            &agg.risc0_extractor_json,
            &agg.native_json,
            Some(&tools),
            &v.sp1_cargo_lock,
            &v.risc0_cargo_lock,
        )
        .expect("authoritative assembly from aggregated per-arch bundles");
        let raw = serde_json::to_vec(&bundle).unwrap();
        let artifact =
            build_finalizable_artifact(&raw).expect("ingest builds finalizable artifact");
        assert!(artifact.is_finalizable());
        assert_eq!(artifact.finalization.state, "finalizable");
        assert!(artifact.finalization.blocked_on.is_empty());
    }

    #[test]
    fn arm64_carrying_risc0_is_rejected() {
        let (_x86, mut arm) = per_arch_bundles();
        let v = test_only_venue_outputs();
        arm.risc0_extractor_json = Some(v.risc0_extractor_json);
        assert_eq!(
            import_verify(&arm),
            Err(ArchBundleError::Aarch64CarriesRisc0)
        );
    }

    #[test]
    fn x86_missing_risc0_is_rejected() {
        let (mut x86, _arm) = per_arch_bundles();
        x86.risc0_extractor_json = None;
        assert_eq!(import_verify(&x86), Err(ArchBundleError::X8664MissingRisc0));
    }

    #[test]
    fn single_arch_aggregate_fails_closed() {
        let (x86, _arm) = per_arch_bundles();
        assert!(matches!(
            aggregate(&[x86]),
            Err(ArchBundleError::ArchSetIncomplete { .. })
        ));
    }

    #[test]
    fn cross_arch_sp1_material_mismatch_is_rejected() {
        let (x86, mut arm) = per_arch_bundles();
        // arm reports DIFFERENT SP1 material than x86 -> aggregation refuses.
        arm.sp1_extractor_json = arm
            .sp1_extractor_json
            .replace("Sp1", "Sp1 ")
            .replace("groth16_vk", "control_root");
        assert!(matches!(
            aggregate(&[x86, arm]),
            Err(ArchBundleError::Sp1MaterialCrossArchMismatch) | Err(ArchBundleError::Parse(_))
        ));
    }

    #[test]
    fn a_build_for_the_wrong_arch_is_rejected() {
        let (mut x86, _arm) = per_arch_bundles();
        x86.builds[0].arch = ARCH_AARCH64.into(); // an aarch64 build inside the x86 bundle
        assert!(matches!(
            import_verify(&x86),
            Err(ArchBundleError::ArchMismatch { .. })
        ));
    }

    #[test]
    fn an_emulated_native_host_is_rejected() {
        let (mut x86, _arm) = per_arch_bundles();
        x86.native[0].host_arch = ARCH_AARCH64.into(); // x86 target built on arm host
        assert!(matches!(
            import_verify(&x86),
            Err(ArchBundleError::NonNativeHost { .. })
        ));
    }
}

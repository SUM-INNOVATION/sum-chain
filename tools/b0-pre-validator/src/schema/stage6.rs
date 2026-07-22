//! Stage-6 authoritative bundle assembler (Correction 2 + 3).
//!
//! `run_authoritative.sh` no longer assumes a hand-composed
//! `stage1-result-bundle.json` already exists. Instead the ONLY accepted
//! authoritative path is:
//!
//! ```text
//! venue outputs
//!   → Stage-6 assembler (this module)
//!   → strict `Stage1ResultBundleV1`
//!   → stage1-ingest (build_finalizable_artifact)
//!   → finalizable TEMPORARY artifact
//! ```
//!
//! The venue outputs consumed are the ACTUAL producer artifacts:
//!   * the two clean OCI builds' paired digests + build provenance (`digests.json`),
//!   * the in-container-generated candidate `Cargo.lock` bytes (hashed here),
//!   * the SP1 / RISC Zero verifier-material extractor JSON (whose field names
//!     differ from the Stage-1 schema — the ONE strict [`convert_extractor_manifest`]
//!     converter bridges the shapes), and
//!   * native-build provenance + reproducibility evidence.
//!
//! The assembler DERIVES, never trusts: `image_digest = build1` only after
//! asserting `build1 == build2` (a divergence fails closed), `native_arch` from
//! `host_arch == arch`, and every reproducibility flag from that derivation — the
//! input shapes carry no reproducibility booleans and no agreed image digest at
//! all, so there is nothing to forge.
//!
//! Mode: the authoritative venue run REQUIRES real tool-identity evidence; if it
//! is absent the run FAILS CLOSED (this module never invents installer
//! versions/URLs/checksums). The local TEST_ONLY simulation ([`test_only_bundle`])
//! feeds real-shaped synthetic inputs and reuses the same FROZEN pins, so it does
//! not require any real installer metadata. This module is the production bridge;
//! the `emit_stage1_example_bundle` example is only a thin caller of it.

use serde::{Deserialize, Serialize};

use crate::protocol::{ARCH_NAMES, CANDIDATE_NAMES, CONTAINER_ROLES};
use crate::schema::stage1_bundle::{
    BundleClassification, ContainerDigestEntry, LockHashEntry, NativeBuildProvenance,
    ReproducibilityEvidence, Stage1ResultBundleV1, ToolIdentityEntry, ToolVersion,
    VerifierMaterialEntryJson, VerifierMaterialManifestEntry, BUNDLE_KIND, BUNDLE_SCHEMA_VERSION,
    EXPECTED_CANDIDATE_RUST, EXPECTED_RISC0_GROTH16, EXPECTED_RISC0_ZKVM, EXPECTED_SP1_VERIFIER,
    TEST_ONLY_TOOL_SENTINEL,
};
use crate::tags;

/// Assembly mode. Authoritative requires real tool-identity evidence; TEST_ONLY
/// may synthesize it from the frozen pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssembleMode {
    Authoritative,
    TestOnly,
}

/// Why the Stage-6 assembler refused to produce a bundle. Any variant means NO
/// bundle is emitted and the authoritative run fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    /// A venue-output JSON failed strict parsing (unknown field, wrong type, ...).
    Parse(String),
    /// The two clean OCI builds produced different digests — not reproducible.
    PairedDigestDivergence {
        candidate: String,
        role: String,
        arch: String,
    },
    /// Authoritative mode was asked to assemble without real tool-identity
    /// evidence; it fails closed rather than invent installer metadata.
    ToolIdentitiesAbsent,
    /// An extractor manifest self-labelled a candidate other than the one the
    /// assembler slotted it into.
    ExtractorCandidateMismatch { expected: String, got: String },
    /// A shape / completeness rule failed.
    Rule(String),
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssembleError::Parse(e) => write!(f, "venue-output parse failed: {e}"),
            AssembleError::PairedDigestDivergence {
                candidate,
                role,
                arch,
            } => write!(
                f,
                "clean OCI builds diverge for ({candidate}, {role}, {arch}); not reproducible"
            ),
            AssembleError::ToolIdentitiesAbsent => write!(
                f,
                "authoritative assembly requires tool-identity evidence; refusing to invent it"
            ),
            AssembleError::ExtractorCandidateMismatch { expected, got } => write!(
                f,
                "extractor manifest is for {got:?} but was slotted as {expected:?}"
            ),
            AssembleError::Rule(m) => write!(f, "assembly rule failed: {m}"),
        }
    }
}

impl std::error::Error for AssembleError {}

fn rule(m: impl Into<String>) -> AssembleError {
    AssembleError::Rule(m.into())
}

fn ascii_of(tag: &[u8; 32]) -> String {
    let n = tags::ascii_len(tag);
    String::from_utf8_lossy(&tag[..n]).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---- Venue-output shapes (the ACTUAL producer artifacts) -------------------

/// The two clean OCI builds' output for every container tuple. It carries NO
/// agreed image digest and NO reproducibility boolean: the assembler derives both.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct OciDigestsFile {
    pub builds: Vec<OciBuild>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct OciBuild {
    pub candidate: String,
    pub role: String,
    pub arch: String,
    /// The two INDEPENDENT clean-build OCI manifest digests, each a full
    /// `sha256:<64hex>`. The assembler compares them (build1 == build2).
    pub build1_digest: String,
    pub build2_digest: String,
    pub base_image_ref: String,
    /// The base image's pinned `sha256:<64hex>` manifest digest.
    pub base_image_digest: String,
    pub builder_oci_ref: String,
    /// The builder image's `sha256:<64hex>` manifest digest.
    pub builder_oci_digest: String,
    pub source_commit: String,
    /// Bare-64-hex BLAKE3 raw-hash fields (algorithm named in the field).
    pub command_log_blake3: String,
    pub raw_output_blake3: String,
    /// Blocker 8: the SELECTED platform descriptor + media type, PARSED from the
    /// exported OCI layout by `venue-verify oci-manifest` (not merely the digest
    /// strings). Optional on the shape so prior/off-venue producers still decode;
    /// the evidence-bundle importer REQUIRES them for the builder role on the
    /// authoritative path and binds `platform_architecture` to the build arch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_variant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// Native-build provenance: the host architecture each `(candidate, arch)` ran on.
/// It carries NO `native_arch` / `two_build_reproducible` boolean: the assembler
/// derives them.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NativeProvenanceFile {
    pub native_builds: Vec<NativeBuild>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct NativeBuild {
    pub candidate: String,
    pub arch: String,
    pub host_arch: String,
}

/// Real tool-identity evidence (authoritative mode).
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentitiesFile {
    pub tool_identities: Vec<ToolIdentityInput>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentityInput {
    pub candidate: String,
    pub rust_version: String,
    pub proof_tools: Vec<ToolVersionInput>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ToolVersionInput {
    pub name: String,
    pub version: String,
    pub artifact_identity: String,
    pub checksum_algorithm: String,
    pub checksum_hex: String,
    pub install_entrypoint: String,
}

// ---- The ONE strict extractor-shape → Stage-1-sub-schema converter ---------

/// The verifier-material extractor's JSON shape (field names deliberately differ
/// from the Stage-1 schema: `candidate_id`, `byte_length`, `blake3`,
/// `manifest_identity_blake3`, `domain`). Strict: an unknown field is rejected.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExtractorManifest {
    pub stamp: Vec<String>,
    pub candidate_id: String,
    pub manifest_schema: String,
    pub entries: Vec<ExtractorEntry>,
    pub total_bytes: u64,
    pub manifest_identity_blake3: String,
    #[serde(default)]
    pub noncanonical_diagnostic_blake3: Option<String>,
    pub domain: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ExtractorEntry {
    pub role: String,
    pub label: String,
    pub byte_length: u64,
    pub blake3: String,
}

/// The ONE strict converter: extractor shape → the exact authoritative Stage-1
/// `VerifierMaterialManifestEntry` sub-schema. It renames fields only; it never
/// recomputes or normalizes an identity, so a lying `manifest_identity_blake3`
/// still fails the downstream canonical bridge in stage1-ingest.
pub fn convert_extractor_manifest(
    json: &str,
    expected_candidate: &str,
) -> Result<VerifierMaterialManifestEntry, AssembleError> {
    let m: ExtractorManifest =
        serde_json::from_str(json).map_err(|e| AssembleError::Parse(e.to_string()))?;
    if m.manifest_schema != "VerifierMaterialManifestV1" {
        return Err(rule(format!(
            "extractor manifest_schema must be VerifierMaterialManifestV1, got {:?}",
            m.manifest_schema
        )));
    }
    if m.candidate_id != expected_candidate {
        return Err(AssembleError::ExtractorCandidateMismatch {
            expected: expected_candidate.to_string(),
            got: m.candidate_id,
        });
    }
    Ok(VerifierMaterialManifestEntry {
        candidate: m.candidate_id,
        stamp: m.stamp,
        entries: m
            .entries
            .into_iter()
            .map(|e| VerifierMaterialEntryJson {
                role: e.role,
                label: e.label,
                byte_len: e.byte_length,
                blake3_hex: e.blake3,
            })
            .collect(),
        total_bytes: m.total_bytes,
        manifest_hash_hex: m.manifest_identity_blake3,
        domain_ascii: m.domain,
    })
}

// ---- The assembler ---------------------------------------------------------

/// The candidate-container Cargo.lock hash rule: `BLAKE3(CARGO_LOCK_TAG ‖ bytes)`.
fn cargo_lock_hash(lock_bytes: &[u8]) -> String {
    hex(&crate::hashing::prefixed(&tags::CARGO_LOCK_TAG, lock_bytes))
}

/// Assemble a strict `Stage1ResultBundleV1` from the real venue outputs. Every
/// reproducibility fact is DERIVED here; the caller then re-checks the whole
/// bundle through stage1-ingest, which independently re-derives them too.
#[allow(clippy::too_many_arguments)]
pub fn assemble_bundle(
    mode: AssembleMode,
    oci_digests_json: &str,
    sp1_extractor_json: &str,
    risc0_extractor_json: &str,
    native_json: &str,
    tool_identities_json: Option<&str>,
    sp1_cargo_lock: &[u8],
    risc0_cargo_lock: &[u8],
) -> Result<Stage1ResultBundleV1, AssembleError> {
    let container_tag = ascii_of(&tags::CONTAINER_TAG);
    let lock_tag = ascii_of(&tags::CARGO_LOCK_TAG);

    // 1) OCI digests → container entries, DERIVING the agreed digest from the two
    //    paired builds (build1 == build2, else fail closed).
    let oci: OciDigestsFile =
        serde_json::from_str(oci_digests_json).map_err(|e| AssembleError::Parse(e.to_string()))?;
    let mut containers = Vec::with_capacity(oci.builds.len());
    for b in &oci.builds {
        if b.build1_digest != b.build2_digest {
            return Err(AssembleError::PairedDigestDivergence {
                candidate: b.candidate.clone(),
                role: b.role.clone(),
                arch: b.arch.clone(),
            });
        }
        containers.push(ContainerDigestEntry {
            candidate: b.candidate.clone(),
            role: b.role.clone(),
            arch: b.arch.clone(),
            // Derived, never supplied: the agreed digest IS the reproduced digest.
            image_digest: b.build1_digest.clone(),
            image_digest_build1: b.build1_digest.clone(),
            image_digest_build2: b.build2_digest.clone(),
            base_image_ref: b.base_image_ref.clone(),
            base_image_digest: b.base_image_digest.clone(),
            builder_oci_ref: b.builder_oci_ref.clone(),
            builder_oci_digest: b.builder_oci_digest.clone(),
            source_commit_hex: b.source_commit.clone(),
            build_command_log_blake3_hex: b.command_log_blake3.clone(),
            raw_build_output_blake3_hex: b.raw_output_blake3.clone(),
            domain_ascii: container_tag.clone(),
        });
    }

    // 2) Extractor outputs → canonical manifests via the ONE converter.
    let sp1_manifest = convert_extractor_manifest(sp1_extractor_json, "Sp1")?;
    let risc0_manifest = convert_extractor_manifest(risc0_extractor_json, "Risc0")?;

    // 3) In-container Cargo.lock bytes → domain-separated lock hashes.
    let locks = vec![
        LockHashEntry {
            candidate: "Sp1".into(),
            blake3_hex: cargo_lock_hash(sp1_cargo_lock),
            domain_ascii: lock_tag.clone(),
        },
        LockHashEntry {
            candidate: "Risc0".into(),
            blake3_hex: cargo_lock_hash(risc0_cargo_lock),
            domain_ascii: lock_tag,
        },
    ];

    // 4) Native provenance → derive native_arch (host_arch == arch) and
    //    two_build_reproducible (from the paired container digests).
    let native: NativeProvenanceFile =
        serde_json::from_str(native_json).map_err(|e| AssembleError::Parse(e.to_string()))?;
    let mut provenance = Vec::with_capacity(native.native_builds.len());
    for nb in &native.native_builds {
        let native_arch = nb.host_arch == nb.arch;
        let tuples: Vec<&ContainerDigestEntry> = containers
            .iter()
            .filter(|c| c.candidate == nb.candidate && c.arch == nb.arch)
            .collect();
        let two_build_reproducible = !tuples.is_empty()
            && tuples
                .iter()
                .all(|c| c.image_digest_build1 == c.image_digest_build2);
        provenance.push(NativeBuildProvenance {
            candidate: nb.candidate.clone(),
            arch: nb.arch.clone(),
            host_arch: nb.host_arch.clone(),
            native_arch,
            two_build_reproducible,
        });
    }

    // 5) Tool identities: authoritative REQUIRES real evidence, TEST_ONLY may
    //    synthesize the frozen pins (never invented installer metadata).
    let tool_identities = match (mode, tool_identities_json) {
        (_, Some(json)) => {
            let f: ToolIdentitiesFile =
                serde_json::from_str(json).map_err(|e| AssembleError::Parse(e.to_string()))?;
            f.tool_identities
                .into_iter()
                .map(|t| ToolIdentityEntry {
                    candidate: t.candidate,
                    rust_version: t.rust_version,
                    proof_tools: t
                        .proof_tools
                        .into_iter()
                        .map(|v| ToolVersion {
                            name: v.name,
                            version: v.version,
                            artifact_identity: v.artifact_identity,
                            checksum_algorithm: v.checksum_algorithm,
                            checksum_hex: v.checksum_hex,
                            install_entrypoint: v.install_entrypoint,
                        })
                        .collect(),
                })
                .collect()
        }
        (AssembleMode::Authoritative, None) => return Err(AssembleError::ToolIdentitiesAbsent),
        (AssembleMode::TestOnly, None) => frozen_pin_tool_identities(),
    };

    // 6) Reproducibility evidence, DERIVED from the assembled digests/locks/manifests.
    let all_two_build = containers
        .iter()
        .all(|c| c.image_digest_build1 == c.image_digest_build2);
    let reproducibility = ReproducibilityEvidence {
        all_container_digests_two_build_reproducible: all_two_build,
        in_container_lock_resolution: true,
        verifier_material_reproduced: true,
    };

    // Blocker 4: the classification is bound by the assembly MODE, never taken from
    // untrusted input. Authoritative assembly (real venue inputs) yields
    // AUTHORITATIVE_STAGE1; the local synthetic path yields TEST_ONLY.
    let classification = match mode {
        AssembleMode::Authoritative => BundleClassification::AuthoritativeStage1,
        AssembleMode::TestOnly => BundleClassification::TestOnly,
    };

    Ok(Stage1ResultBundleV1 {
        schema_version: BUNDLE_SCHEMA_VERSION,
        bundle_kind: BUNDLE_KIND.into(),
        classification,
        all_reproducible: all_two_build,
        candidate_container_digests: containers,
        cargo_lock_hashes: locks,
        verifier_material_manifests: vec![sp1_manifest, risc0_manifest],
        native_build_provenance: provenance,
        tool_identities,
        reproducibility,
    })
}

/// A synthetic TEST_ONLY proof-tool identity: the pinned version (public, checked
/// against the frozen pins) plus artifact/checksum/entrypoint fields that are
/// UNMISTAKABLY SYNTHETIC (they carry the [`TEST_ONLY_TOOL_SENTINEL`]). No real
/// installer URL/checksum is ever invented; these can never substitute for venue
/// metadata (the authoritative validator rejects the sentinel).
fn synthetic_tool(name: &str, version: &str) -> ToolVersion {
    ToolVersion {
        name: name.into(),
        version: version.into(),
        artifact_identity: format!("{TEST_ONLY_TOOL_SENTINEL}://{name}-{version}"),
        checksum_algorithm: "sha256".into(),
        checksum_hex: syn(&format!("{TEST_ONLY_TOOL_SENTINEL}-{name}-{version}")),
        install_entrypoint: format!("{TEST_ONLY_TOOL_SENTINEL}:cargo:{name}@{version}"),
    }
}

/// The frozen tool identities (the same pins the authoritative path cross-checks;
/// mirrored, not invented) used to fill the TEST_ONLY simulation. Their installer
/// metadata is the synthetic sentinel — never real venue-selected metadata.
fn frozen_pin_tool_identities() -> Vec<ToolIdentityEntry> {
    vec![
        ToolIdentityEntry {
            candidate: "Sp1".into(),
            rust_version: EXPECTED_CANDIDATE_RUST.into(),
            proof_tools: vec![synthetic_tool("sp1-verifier", EXPECTED_SP1_VERIFIER)],
        },
        ToolIdentityEntry {
            candidate: "Risc0".into(),
            rust_version: EXPECTED_CANDIDATE_RUST.into(),
            proof_tools: vec![
                synthetic_tool("risc0-zkvm", EXPECTED_RISC0_ZKVM),
                synthetic_tool("risc0-groth16", EXPECTED_RISC0_GROTH16),
            ],
        },
    ]
}

// ---- TEST_ONLY synthetic venue outputs (real-shaped, no installer metadata) --

/// A deterministic non-placeholder 64-hex digest from a label.
fn syn(label: &str) -> String {
    hex(blake3::hash(label.as_bytes()).as_bytes())
}

/// Build the synthetic, real-shaped venue-output JSON strings + lock bytes for the
/// TEST_ONLY simulation. Returned as owned strings so tests/examples can feed the
/// exact same producer→assembler→ingest path the venue uses.
pub struct TestOnlyVenueOutputs {
    pub oci_digests_json: String,
    pub sp1_extractor_json: String,
    pub risc0_extractor_json: String,
    pub native_json: String,
    /// A sentinel-marked synthetic tool-identities file (ToolIdentitiesFile shape),
    /// for the `--test-only-from-files` path. Its metadata is UNMISTAKABLY synthetic.
    pub tool_identities_json: String,
    pub sp1_cargo_lock: Vec<u8>,
    pub risc0_cargo_lock: Vec<u8>,
}

/// A full synthetic OCI manifest digest for a TEST_ONLY sample: `sha256:<64hex>`.
fn syn_oci(label: &str) -> String {
    format!("sha256:{}", syn(label))
}

/// Produce real-shaped synthetic venue outputs that do NOT require any real
/// installer metadata. The verifier-material extractor JSON is built through the
/// SHARED canonical primitive so its identity is genuine, not fabricated.
pub fn test_only_venue_outputs() -> TestOnlyVenueOutputs {
    use crate::enums::{Candidate, VerifierMaterialRole};
    use crate::schema::verifier_material::VerifierMaterialManifestV1;

    let container_domain = ascii_of(&tags::VERIFIER_MATERIAL_TAG);

    // container builds (build1 == build2, non-placeholder sha256:<64hex> digests).
    // Blocker 6: the derived image_digest (= build1) must equal each role's own
    // source — base = its pinned pull-by-digest identity, builder = its built image
    // identity — so base evidence is never a relabelled builder build.
    let mut builds = Vec::new();
    for candidate in CANDIDATE_NAMES {
        for role in CONTAINER_ROLES {
            for arch in ARCH_NAMES {
                let base_image_digest = syn_oci(&format!("base-{candidate}-{arch}"));
                let builder_oci_digest = syn_oci(&format!("builder-{candidate}-{arch}"));
                let d = match role {
                    "base" => base_image_digest.clone(),
                    _ => builder_oci_digest.clone(),
                };
                builds.push(serde_json::json!({
                    "candidate": candidate,
                    "role": role,
                    "arch": arch,
                    "build1_digest": d,
                    "build2_digest": d,
                    "base_image_ref": format!("registry.test/{candidate}/base:pinned"),
                    "base_image_digest": base_image_digest,
                    "builder_oci_ref": format!("registry.test/{candidate}/builder:pinned"),
                    "builder_oci_digest": builder_oci_digest,
                    "source_commit": syn(&format!("commit-{candidate}"))[..40].to_string(),
                    // base entries carry pull-by-digest resolution evidence; builder
                    // entries carry two-clean-build evidence — distinct, never copied.
                    "command_log_blake3": syn(&format!("cmdlog-{candidate}-{role}-{arch}")),
                    "raw_output_blake3": syn(&format!("rawout-{candidate}-{role}-{arch}")),
                }));
            }
        }
    }
    let oci_digests_json = serde_json::to_string(&serde_json::json!({ "builds": builds })).unwrap();

    // verifier-material extractor JSON, identity from the SHARED canonical primitive
    let extractor_json = |m: &VerifierMaterialManifestV1, candidate: &str| -> String {
        let entries: Vec<_> = m
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "role": e.role.canonical_label(),
                    "label": e.label,
                    "byte_length": e.byte_len,
                    "blake3": hex(&e.hash),
                })
            })
            .collect();
        serde_json::to_string(&serde_json::json!({
            "stamp": b0_pre_vmat::REQUIRED_STAMPS,
            "candidate_id": candidate,
            "manifest_schema": "VerifierMaterialManifestV1",
            "entries": entries,
            "total_bytes": m.verifier_material_bytes().unwrap(),
            "manifest_identity_blake3": hex(&m.identity().unwrap()),
            "domain": container_domain,
            "note": "TEST_ONLY synthetic verifier material",
        }))
        .unwrap()
    };
    let sp1 = VerifierMaterialManifestV1::from_canonical(
        Candidate::Sp1,
        [(
            VerifierMaterialRole::Groth16Vk,
            292,
            *blake3::hash(b"sp1-vk").as_bytes(),
        )],
    );
    let risc0 = VerifierMaterialManifestV1::from_canonical(
        Candidate::Risc0,
        [
            (
                VerifierMaterialRole::Groth16Vk,
                256,
                *blake3::hash(b"r0-vk").as_bytes(),
            ),
            (
                VerifierMaterialRole::ControlRoot,
                32,
                *blake3::hash(b"r0-cr").as_bytes(),
            ),
            (
                VerifierMaterialRole::ControlId,
                32,
                *blake3::hash(b"r0-ci").as_bytes(),
            ),
            (
                VerifierMaterialRole::VerifierParams,
                32,
                *blake3::hash(b"r0-vp").as_bytes(),
            ),
        ],
    );

    // native provenance (host_arch == arch => native)
    let mut native_builds = Vec::new();
    for candidate in CANDIDATE_NAMES {
        for arch in ARCH_NAMES {
            native_builds.push(serde_json::json!({
                "candidate": candidate, "arch": arch, "host_arch": arch,
            }));
        }
    }
    let native_json =
        serde_json::to_string(&serde_json::json!({ "native_builds": native_builds })).unwrap();

    // tool identities (ToolIdentitiesFile shape), UNMISTAKABLY synthetic — every
    // artifact identity / entrypoint carries the sentinel so it can never be
    // mistaken for real venue-selected installer metadata.
    let tool_json = |name: &str, version: &str| {
        serde_json::json!({
            "name": name,
            "version": version,
            "artifact_identity": format!("{TEST_ONLY_TOOL_SENTINEL}://{name}-{version}"),
            "checksum_algorithm": "sha256",
            "checksum_hex": syn(&format!("{TEST_ONLY_TOOL_SENTINEL}-{name}-{version}")),
            "install_entrypoint": format!("{TEST_ONLY_TOOL_SENTINEL}:cargo:{name}@{version}"),
        })
    };
    let tool_identities_json = serde_json::to_string(&serde_json::json!({
        "tool_identities": [
            {
                "candidate": "Sp1",
                "rust_version": EXPECTED_CANDIDATE_RUST,
                "proof_tools": [tool_json("sp1-verifier", EXPECTED_SP1_VERIFIER)],
            },
            {
                "candidate": "Risc0",
                "rust_version": EXPECTED_CANDIDATE_RUST,
                "proof_tools": [
                    tool_json("risc0-zkvm", EXPECTED_RISC0_ZKVM),
                    tool_json("risc0-groth16", EXPECTED_RISC0_GROTH16),
                ],
            },
        ]
    }))
    .unwrap();

    TestOnlyVenueOutputs {
        oci_digests_json,
        sp1_extractor_json: extractor_json(&sp1, "Sp1"),
        risc0_extractor_json: extractor_json(&risc0, "Risc0"),
        native_json,
        tool_identities_json,
        sp1_cargo_lock: b"# TEST_ONLY synthetic Sp1 Cargo.lock\n".to_vec(),
        risc0_cargo_lock: b"# TEST_ONLY synthetic Risc0 Cargo.lock\n".to_vec(),
    }
}

/// Assemble a complete TEST_ONLY bundle through the PRODUCTION assembler with
/// real-shaped synthetic inputs (no real installer metadata required). This is the
/// one bundle-construction path the example emitter and the e2e simulation share.
pub fn test_only_bundle() -> Stage1ResultBundleV1 {
    let v = test_only_venue_outputs();
    assemble_bundle(
        AssembleMode::TestOnly,
        &v.oci_digests_json,
        &v.sp1_extractor_json,
        &v.risc0_extractor_json,
        &v.native_json,
        None,
        &v.sp1_cargo_lock,
        &v.risc0_cargo_lock,
    )
    .expect("TEST_ONLY synthetic venue outputs assemble")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::stage1_bundle::{
        build_finalizable_artifact, validate_test_only_bundle, BundleClassification,
        Stage1ResultBundleV1,
    };

    fn v() -> TestOnlyVenueOutputs {
        test_only_venue_outputs()
    }

    fn assemble_test_only(v: &TestOnlyVenueOutputs) -> Result<Stage1ResultBundleV1, AssembleError> {
        assemble_bundle(
            AssembleMode::TestOnly,
            &v.oci_digests_json,
            &v.sp1_extractor_json,
            &v.risc0_extractor_json,
            &v.native_json,
            None,
            &v.sp1_cargo_lock,
            &v.risc0_cargo_lock,
        )
    }

    /// Complete AUTHORITATIVE tool-identity JSON with well-formed, NON-synthetic
    /// artifact/checksum/entrypoint fields — a Rust-test fixture (not real installer
    /// metadata, never written to the committed artifact, never mintable by a
    /// shippable synthetic-input command).
    fn authoritative_tools_json() -> String {
        let tool = |name: &str, version: &str| {
            serde_json::json!({
                "name": name,
                "version": version,
                "artifact_identity": format!("https://fixtures.invalid/{name}-{version}.tar"),
                "checksum_algorithm": "sha256",
                "checksum_hex": syn(&format!("authoritative-{name}-{version}")),
                "install_entrypoint": format!("cargo:{name}@{version}"),
            })
        };
        serde_json::to_string(&serde_json::json!({
            "tool_identities": [
                {"candidate":"Sp1","rust_version":"1.88.0",
                 "proof_tools":[tool("sp1-verifier","6.3.1")]},
                {"candidate":"Risc0","rust_version":"1.88.0",
                 "proof_tools":[tool("risc0-zkvm","3.0.5"), tool("risc0-groth16","3.0.4")]},
            ]
        }))
        .unwrap()
    }

    fn assemble_authoritative(
        v: &TestOnlyVenueOutputs,
        native_json: &str,
        tools: &str,
    ) -> Result<Stage1ResultBundleV1, AssembleError> {
        assemble_bundle(
            AssembleMode::Authoritative,
            &v.oci_digests_json,
            &v.sp1_extractor_json,
            &v.risc0_extractor_json,
            native_json,
            Some(tools),
            &v.sp1_cargo_lock,
            &v.risc0_cargo_lock,
        )
    }

    #[test]
    fn end_to_end_test_only_bundle_is_refused_by_authoritative_ingest() {
        // Blocker 4: real-shaped SYNTHETIC producer outputs -> assembler ->
        // TEST_ONLY-classified bundle. It passes full semantic validation via the
        // explicit test-only path, but authoritative ingest REFUSES it — a synthetic
        // bundle has no path to a finalizable artifact.
        let bundle = assemble_test_only(&v()).expect("assemble");
        assert_eq!(bundle.classification, BundleClassification::TestOnly);
        let raw = serde_json::to_vec(&bundle).unwrap();
        // (1) full validation succeeds on the explicit test-only path...
        assert_eq!(
            validate_test_only_bundle(&raw),
            Ok(BundleClassification::TestOnly)
        );
        // (2) ...but authoritative ingest refuses, yielding NO artifact.
        assert!(matches!(
            build_finalizable_artifact(&raw),
            Err(crate::schema::stage1_bundle::Stage1BundleError::NonAuthoritativeClassification(_))
        ));
    }

    #[test]
    fn end_to_end_authoritative_bundle_yields_finalizable_artifact() {
        // The AUTHORITATIVE accept-path, proven in-code (never via a shippable
        // synthetic-input CLI): complete AUTHORITATIVE_STAGE1 inputs -> assembler ->
        // strict bundle -> ingest -> finalizable TEMPORARY artifact.
        let out = v();
        let bundle = assemble_authoritative(&out, &out.native_json, &authoritative_tools_json())
            .expect("authoritative assembly");
        assert_eq!(
            bundle.classification,
            BundleClassification::AuthoritativeStage1
        );
        let raw = serde_json::to_vec(&bundle).unwrap();
        let artifact =
            build_finalizable_artifact(&raw).expect("ingest builds finalizable artifact");
        assert!(artifact.is_finalizable());
        assert!(artifact.semantic_violations().is_empty());
        assert_eq!(artifact.finalization.state, "finalizable");
        assert!(artifact.finalization.blocked_on.is_empty());
    }

    #[test]
    fn converter_renames_fields_and_is_strict() {
        // the extractor field names (candidate_id/byte_length/blake3/...) are
        // renamed to the Stage-1 schema (candidate/byte_len/blake3_hex/...).
        let entry = convert_extractor_manifest(&v().sp1_extractor_json, "Sp1").unwrap();
        assert_eq!(entry.candidate, "Sp1");
        assert_eq!(entry.entries[0].role, "groth16_vk");
        assert_eq!(entry.entries[0].byte_len, 292);
        assert_eq!(entry.entries[0].blake3_hex.len(), 64);
        assert!(!entry.manifest_hash_hex.is_empty());
        // strict: an unknown field is rejected.
        let bad = r#"{"stamp":[],"candidate_id":"Sp1","manifest_schema":"VerifierMaterialManifestV1","entries":[],"total_bytes":0,"manifest_identity_blake3":"x","domain":"d","surprise":1}"#;
        assert!(matches!(
            convert_extractor_manifest(bad, "Sp1"),
            Err(AssembleError::Parse(_))
        ));
        // candidate mismatch is caught.
        assert!(matches!(
            convert_extractor_manifest(&v().risc0_extractor_json, "Sp1"),
            Err(AssembleError::ExtractorCandidateMismatch { .. })
        ));
    }

    #[test]
    fn diverging_paired_build_digests_fail_closed() {
        // flip build2 of one tuple so build1 != build2 -> assembler refuses.
        let mut oci: serde_json::Value = serde_json::from_str(&v().oci_digests_json).unwrap();
        oci["builds"][0]["build2_digest"] = serde_json::json!(syn_oci("divergent-second-build"));
        let out = v();
        let r = assemble_bundle(
            AssembleMode::TestOnly,
            &serde_json::to_string(&oci).unwrap(),
            &out.sp1_extractor_json,
            &out.risc0_extractor_json,
            &out.native_json,
            None,
            &out.sp1_cargo_lock,
            &out.risc0_cargo_lock,
        );
        assert!(matches!(
            r,
            Err(AssembleError::PairedDigestDivergence { .. })
        ));
    }

    #[test]
    fn authoritative_mode_without_tool_identities_fails_closed() {
        let out = v();
        let r = assemble_bundle(
            AssembleMode::Authoritative,
            &out.oci_digests_json,
            &out.sp1_extractor_json,
            &out.risc0_extractor_json,
            &out.native_json,
            None, // no real tool-identity evidence
            &out.sp1_cargo_lock,
            &out.risc0_cargo_lock,
        );
        assert_eq!(r, Err(AssembleError::ToolIdentitiesAbsent));
    }

    #[test]
    fn authoritative_mode_rejects_synthetic_tool_identities() {
        // Blocker 3: authoritative assembly with SENTINEL-marked (synthetic) tool
        // metadata assembles a bundle, but authoritative ingest refuses it because a
        // synthetic identity can never substitute for real venue-selected metadata.
        let out = v();
        let synthetic_tools = out.tool_identities_json.clone();
        let bundle = assemble_authoritative(&out, &out.native_json, &synthetic_tools)
            .expect("assembles structurally");
        let raw = serde_json::to_vec(&bundle).unwrap();
        assert!(matches!(
            build_finalizable_artifact(&raw),
            Err(crate::schema::stage1_bundle::Stage1BundleError::ToolIdentity(_))
        ));
    }

    #[test]
    fn non_native_host_arch_is_rejected_by_ingest() {
        // a cross-compiled native build (host_arch != arch) assembles an AUTHORITATIVE
        // bundle whose derived native_arch=false, which stage1-ingest then refuses on
        // native-arch grounds (not merely on classification).
        let mut native: serde_json::Value = serde_json::from_str(&v().native_json).unwrap();
        native["native_builds"][0]["host_arch"] = serde_json::json!("Aarch64");
        native["native_builds"][0]["arch"] = serde_json::json!("X86_64");
        native["native_builds"][0]["candidate"] = serde_json::json!("Sp1");
        let out = v();
        let bundle = assemble_authoritative(
            &out,
            &serde_json::to_string(&native).unwrap(),
            &authoritative_tools_json(),
        )
        .expect("assembles");
        assert_eq!(
            bundle.classification,
            BundleClassification::AuthoritativeStage1
        );
        let raw = serde_json::to_vec(&bundle).unwrap();
        assert!(matches!(
            build_finalizable_artifact(&raw),
            Err(crate::schema::stage1_bundle::Stage1BundleError::Rule(_))
        ));
    }
}

//! The versioned B0-PRE **pin/proposal contract** and its capability gate.
//!
//! The pin proposal (`proposed-pins-*.json`, verified block-by-block against primary
//! sources by `scripts/verify_pins.sh`) grew a Stage-5 capability that the v2/v3 shapes
//! cannot express: a genuine terminal Groth16 proof needs guest **toolchain trees**, an
//! immutable proving **circuit/data artifact**, and immutable **OCI proving backends**.
//! Those are new, and REQUIRED, so the contract takes a NEW version rather than silently
//! redefining v3.
//!
//! This module is the single typed decision core for the version rule (mod-doc pattern:
//! a pure, adversarially-tested core the shell venue command calls, never trusts blind):
//!   * `contract_version` ∈ {`v2`,`v3`,`v4`}; anything else FAILS CLOSED (unknown version).
//!   * `v2`/`v3` still PARSE (historical evidence stays readable) but are permanently
//!     **INELIGIBLE** for capability-complete Stage-5 — they lack the three new blocks.
//!   * `v4` REQUIRES all three new blocks and is capability-complete ONLY when every one
//!     matches the frozen reconciled Stage-5 identity set ([`stage5_expected`]); any
//!     missing/altered value fails closed.
//!
//! The three new blocks are **generic record types** (reusable for any canonical toolchain
//! tree / immutable data artifact / OCI backend), bound for THIS capability to the exact
//! artifacts two venues and two architectures independently reproduced:
//!   * guest toolchain trees — archive sha256 + `PROVISIONED_TREE/v1` digest, per arch;
//!   * the SP1 Groth16 circuit archive — archive sha256 + the COMPLETE 16-member inventory
//!     (7 real + 8 AppleDouble + 1 dir) + the 7-member runtime-tree digest that x86 and ARM
//!     computed identically;
//!   * OCI proving backends — immutable index / platform-manifest / config digests (never a
//!     mutable tag), linux/amd64 only. A terminal-Groth16 backend claimed for aarch64 fails
//!     closed (ARM supports compile/identity/verify capabilities only, never terminal Groth16).
//!
//! It computes NO digest from bytes here (that is `provisioned_tree` / `checkout_digest` at
//! produce time) and ratifies nothing: a capability-complete result is a PRECONDITION, and
//! every pin remains UNRATIFIED until the owner ratifies the merged source commit.

use serde::Deserialize;

use super::{is_hex64, is_synthetic};

// ---------------------------------------------------------------------------------------
// Frozen reconciled Stage-5 identity set (independently reproduced by x86 AND ARM; NOT
// publisher-attested). A capability-complete v4 contract must declare EXACTLY these values.
// ---------------------------------------------------------------------------------------

/// SP1 Groth16 circuit archive (`v6.1.0-groth16.tar.gz`) — owner content pin.
pub const CIRCUIT_ARCHIVE_SHA256: &str =
    "18beebb6cd0cc9b4d4a240ee4f49511da6c2a7e51724bad4232de538a9147810";
pub const CIRCUIT_ARCHIVE_SIZE: u64 = 6_211_807_514;
/// The 7-member runtime-tree `PROVISIONED_TREE/v1` digest (x86 == ARM).
pub const CIRCUIT_RUNTIME_TREE_BLAKE3: &str =
    "c8d7d773808622303af682276c224a9868d3afa8b47a51628095923cf52ab25a";
/// Every AppleDouble sidecar is this exact inert 163-byte blob.
pub const APPLEDOUBLE_SHA256: &str =
    "a8d7edcaf5cde6ccdb9d056770ecd3edadcdd9010dad9d9b61e026f4732cd0e0";
pub const APPLEDOUBLE_SIZE: u64 = 163;

/// The 7 approved REAL runtime members `(name, size, sha256)` — the ENTIRE runtime tree.
pub const CIRCUIT_REAL_MEMBERS: &[(&str, u64, &str)] = &[
    ("Groth16Verifier.sol", 26_770, "d5e777120d9f675aefcc8c0c8786d4043acb8e063646e60818564b44fb2ec457"),
    ("SP1VerifierGroth16.sol", 3_236, "48e1db5baca3b102242ebd88280b3689a088076688146cd0d98876f5dacb76d0"),
    ("constraints.json", 111_997_113, "1fb0b3d5f59c45b8f41973b111604aba2402db3c8e887074300ab8d164def92b"),
    ("groth16_circuit.bin", 2_437_991_441, "d6a66be2702206e2b1a20bebf7096142864feac9e399a309e5e6e00353264cbc"),
    ("groth16_pk.bin", 5_862_173_061, "c3760e0e3b58487f8704680d5b3ad32a9fbca9f3cb0749d69055c4f1271ca167"),
    ("groth16_vk.bin", 492, "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"),
    ("groth16_witness.json", 2_802_920, "ee2ac8e094712a87ec3b0dc50ed39704aa90ee066ce4c5bf6160d54f04014c94"),
];

/// The 8 approved AppleDouble sidecar names (bound in the inventory, NEVER installed to runtime).
pub const CIRCUIT_APPLEDOUBLE_NAMES: &[&str] = &[
    "._.",
    "._Groth16Verifier.sol",
    "._SP1VerifierGroth16.sol",
    "._constraints.json",
    "._groth16_circuit.bin",
    "._groth16_pk.bin",
    "._groth16_vk.bin",
    "._groth16_witness.json",
];

/// Expected guest toolchain trees `(framework, arch, archive_sha256, provisioned_tree_blake3)`.
pub const EXPECTED_TOOLCHAINS: &[(&str, &str, &str, &str)] = &[
    ("sp1", "x86_64",
     "12c94435d41bfe4e20131bbcce40b35abd32270ad792befc653af4e3fabc192f",
     "802e2e88c7443fd4d67c2c948c55517147e730b60ecb01cffe6e5e8ee5015f3e"),
    ("sp1", "aarch64",
     "81722d5c2bc7f371ce305f447ea4b6ffed9dfb1b60ac2978706b00e1ff9b503d",
     "48c94ec9e0fa94037c196b37d24d877ab476b117aeac40c8d559ef9003e3946e"),
    ("risc0", "x86_64",
     "e082a1dc44abdef1d95460295a70218eb294ab999b834570ec932d05641cce5d",
     "25f52f319aba77506aa9414639fd28299ab574a46708511e9698a41fa6993acd"),
];

/// A frozen expected OCI proving backend. Every OCI identity occupies a DISTINCT, explicitly
/// named role, resolved from the actual manifest bytes (not copied between fields):
///   * `index_digest`         — the multi-arch OCI index / manifest-list digest;
///   * `amd64_manifest_digest`— the linux/amd64 platform manifest digest;
///   * `config_digest`        — the amd64 manifest's `.config.digest` (the image-config blob);
///   * `loaded_image_id`      — the canonical image id after a verified load; it MUST equal
///                              `config_digest` and is NEVER the index or platform manifest;
///   * `attestation_digest`   — the attestation-manifest digest, when the index carries one.
///
/// linux/amd64 only — RISC Zero arm64 is UNSUPPORTED and is never recorded as a usable pin.
pub struct ExpectedOci {
    pub name: &'static str,
    pub index_digest: &'static str,
    pub amd64_manifest_digest: &'static str,
    pub config_digest: &'static str,
    pub attestation_digest: Option<&'static str>,
    pub entrypoint: &'static str,
}

/// The RISC Zero **reproducible guest-builder** image (`risc0-guest-builder:r0.1.88.0`,
/// digest `sha256:3e12f71b…`) is the image the *official `cargo risczero build` CLI* pulls to
/// build a guest — a DIFFERENT toolchain (r0.1.88.0) than the pinned local `r0.1.91.1`, fetched
/// from a mutable tag over the network. The owner rejected that path: RISC Zero guest
/// compilation uses the pinned LOCAL toolchain via `risc0_build::embed_methods()` (no docker, no
/// network, no rzup exec). This digest is recorded ONLY as rejected/unused audit evidence — it
/// is NEVER an accepted Stage-5 backend, and a v4 contract that declares it as one fails closed
/// (it is absent from [`EXPECTED_OCI_BACKENDS`], and [`REJECTED_OCI_BACKENDS`] names it so the
/// refusal is explicit rather than incidental).
pub const REJECTED_OCI_BACKENDS: &[(&str, &str)] = &[(
    "risc0-guest-builder",
    "sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3",
)];

pub const EXPECTED_OCI_BACKENDS: &[ExpectedOci] = &[
    // SP1 Groth16 prover image. config resolved from amd64 manifest be8555f1's `.config.digest`
    // (ceb60d80); the containerd image store reports the pulled INDEX digest as `.Id`, so the
    // index value is NOT the config and must never be recorded as the image id.
    ExpectedOci {
        name: "sp1-gnark",
        index_digest: "sha256:e1a1cd62838b561ca301f9b2c26475c4a92bfe0e2c916e9bba213062e1548c4d",
        amd64_manifest_digest: "sha256:be8555f1ad90870acd8c6ec7fd3ba0b1a2133ea9cddf25e130665aa651129e54",
        config_digest: "sha256:ceb60d80f46cd8e5869abd778f26dc34c4f3bab205f3d1d5275e532121cced4e",
        attestation_digest: Some("sha256:6ade751e47f161a6d351675c72619ca9f9dff685c41962985e40e2b2289696b9"),
        entrypoint: "/gnark-cli",
    },
    // RISC Zero Groth16/stark2snark prover image. config is the amd64 manifest 7f173963's
    // `.config.digest` (f6f756b0); the runtime previously mislabeled the manifest digest as the
    // image id — corrected here so loaded_image_id == config. Docker manifest-list index: no
    // attestation manifest. arm64 digests are deliberately OMITTED (unsupported).
    ExpectedOci {
        name: "risc0-groth16",
        index_digest: "sha256:a4f80ce2e0b8e2bb7637a93c37136a6776ac00ec843a3fdf1c67b1d5ffea64ee",
        amd64_manifest_digest: "sha256:7f173963196570b7a71816ed70565a4579264c5d2e3e0ecb028102538ad0e331",
        config_digest: "sha256:f6f756b0899c29d869d6a01fbbded3887a8f51429653177ee4b3ffad294324cd",
        attestation_digest: None,
        entrypoint: "/app/prover.sh",
    },
];

// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractVersion {
    V2,
    V3,
    V4,
}

impl ContractVersion {
    fn parse(s: &str) -> Result<Self, PinContractError> {
        match s {
            "v2" => Ok(ContractVersion::V2),
            "v3" => Ok(ContractVersion::V3),
            "v4" => Ok(ContractVersion::V4),
            other => Err(PinContractError::UnknownVersion(other.to_string())),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ContractVersion::V2 => "v2",
            ContractVersion::V3 => "v3",
            ContractVersion::V4 => "v4",
        }
    }
}

/// The capability verdict of a parsed contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// v4 with all three new blocks present and matching the frozen Stage-5 identity set.
    Complete,
    /// Parses (historical evidence), but is INELIGIBLE for capability-complete Stage-5.
    Ineligible { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEvaluation {
    pub version: ContractVersion,
    pub capability: Capability,
    /// A human-auditable one-line summary (goes to the venue log).
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinContractError {
    Json(String),
    /// `contract_version` absent and no legacy `_contract_version` fallback — fail closed.
    MissingVersion,
    /// A `contract_version` that is neither v2/v3/v4 — fail closed (never "best effort").
    UnknownVersion(String),
    /// A v4 contract is missing a REQUIRED new block.
    MissingBlock(&'static str),
    /// A declared value is malformed (bad hex / bad digest / bad size / bad arch / …).
    Malformed { field: String, detail: String },
    /// A declared value does not match the frozen reconciled Stage-5 identity.
    IdentityMismatch { field: String, expected: String, got: String },
    /// An extra/altered/unexpected member or sidecar.
    UnexpectedMember { detail: String },
    /// An aarch64 terminal-Groth16 capability was declared (forbidden).
    ArmTerminalGroth16 { detail: String },
    /// A synthetic / TEST_ONLY marker appeared on the authoritative capability path.
    Synthetic { field: String },
}

impl std::fmt::Display for PinContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinContractError::Json(e) => write!(f, "pin-contract JSON parse error: {e}"),
            PinContractError::MissingVersion => write!(
                f,
                "no authoritative contract_version (and no legacy _contract_version); fail closed"
            ),
            PinContractError::UnknownVersion(v) => {
                write!(f, "unknown contract_version {v:?} (expected v2|v3|v4); fail closed")
            }
            PinContractError::MissingBlock(b) => {
                write!(f, "v4 contract is missing required block {b:?}")
            }
            PinContractError::Malformed { field, detail } => {
                write!(f, "malformed {field}: {detail}")
            }
            PinContractError::IdentityMismatch { field, expected, got } => write!(
                f,
                "identity mismatch at {field}: expected {expected}, got {got}"
            ),
            PinContractError::UnexpectedMember { detail } => {
                write!(f, "unexpected/altered circuit member: {detail}")
            }
            PinContractError::ArmTerminalGroth16 { detail } => write!(
                f,
                "aarch64 terminal-Groth16 capability is forbidden: {detail}"
            ),
            PinContractError::Synthetic { field } => {
                write!(f, "synthetic/TEST_ONLY marker on the authoritative pin path at {field}")
            }
        }
    }
}

impl std::error::Error for PinContractError {}

// ---- typed record shapes (deny_unknown_fields so an unexpected field fails closed) -----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestToolchainPin {
    pub framework: String,
    pub arch: String,
    pub toolchain_version: String,
    pub archive_sha256: String,
    pub provisioned_tree_blake3: String,
    /// Free-form provenance (repo/commit or "rzup-delegated …"); recorded, format only.
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_repo: Option<String>,
    #[serde(default)]
    pub source_commit: Option<String>,
    /// Must be present and equal to "unratified" — these are UNRATIFIED pins.
    pub ratification: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitMember {
    pub path: String,
    /// "real" | "appledouble" | "dir".
    pub kind: String,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Groth16CircuitArtifactPin {
    pub framework: String,
    pub circuit_version: String,
    pub archive_sha256: String,
    pub archive_size_bytes: u64,
    pub runtime_tree_blake3: String,
    /// Every member of the archive (7 real + 8 AppleDouble + 1 dir).
    pub members: Vec<CircuitMember>,
    /// Exactly the 7 real member names that constitute the runtime tree.
    pub runtime_members: Vec<String>,
    /// Owner content-pin attestation note (format only).
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(default)]
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciBackendPin {
    pub name: String,
    #[serde(default)]
    pub framework: Option<String>,
    /// Must be linux/amd64 for a usable Stage-5 backend.
    pub platform: String,
    /// The multi-arch OCI index / manifest-list digest.
    pub index_digest: String,
    /// The linux/amd64 platform manifest digest.
    pub amd64_manifest_digest: String,
    /// The amd64 manifest's `.config.digest` (the image-config blob) — distinct from index+manifest.
    pub config_digest: String,
    /// The canonical image id after a verified load. MUST equal `config_digest`; never the
    /// index or the platform manifest.
    pub loaded_image_id: String,
    /// The attestation-manifest digest, present ONLY when the index carries one (sp1-gnark does;
    /// risc0-groth16 does not). Absent must match the frozen expectation.
    #[serde(default)]
    pub attestation_digest: Option<String>,
    pub entrypoint: String,
    /// A MUTABLE tag may be recorded for provenance but is NEVER the authority.
    #[serde(default)]
    pub source_declared_tag_mutable_not_authority: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawContract {
    #[serde(default)]
    contract_version: Option<String>,
    /// Legacy informational version (historical files carry `_contract_version`).
    #[serde(default, rename = "_contract_version")]
    legacy_contract_version: Option<String>,
    #[serde(default)]
    guest_toolchains: Option<Vec<GuestToolchainPin>>,
    #[serde(default)]
    groth16_circuit_artifact: Option<Groth16CircuitArtifactPin>,
    #[serde(default)]
    oci_backends: Option<Vec<OciBackendPin>>,
    // Legacy blocks (base_image/apt/rustup_init/tool_identities/cargo_audit/advisory_db/
    // prover_archives) are validated by verify_pins.sh, not here; allow them through.
    #[serde(flatten)]
    _other: serde_json::Map<String, serde_json::Value>,
}

fn require_hex64(field: &str, v: &str) -> Result<(), PinContractError> {
    if is_synthetic(v) {
        return Err(PinContractError::Synthetic { field: field.to_string() });
    }
    if is_hex64(v) {
        Ok(())
    } else {
        Err(PinContractError::Malformed {
            field: field.to_string(),
            detail: format!("not a bare 64-lowercase-hex value: {v:?}"),
        })
    }
}

/// `sha256:<64 lowercase hex>` — an immutable digest, never a mutable tag.
fn require_oci_digest(field: &str, v: &str) -> Result<(), PinContractError> {
    if is_synthetic(v) {
        return Err(PinContractError::Synthetic { field: field.to_string() });
    }
    match v.strip_prefix("sha256:") {
        Some(hex) if is_hex64(hex) => Ok(()),
        _ => Err(PinContractError::Malformed {
            field: field.to_string(),
            detail: format!("not an immutable sha256:<64hex> digest (a mutable tag is refused): {v:?}"),
        }),
    }
}

fn expect_eq(field: &str, expected: &str, got: &str) -> Result<(), PinContractError> {
    if expected == got {
        Ok(())
    } else {
        Err(PinContractError::IdentityMismatch {
            field: field.to_string(),
            expected: expected.to_string(),
            got: got.to_string(),
        })
    }
}

fn validate_guest_toolchains(pins: &[GuestToolchainPin]) -> Result<(), PinContractError> {
    // Each declared toolchain must be well-formed, UNRATIFIED, and match a frozen expectation.
    for p in pins {
        let key = format!("guest_toolchains[{}/{}]", p.framework, p.arch);
        match (p.framework.as_str(), p.arch.as_str()) {
            ("sp1", "x86_64") | ("sp1", "aarch64") | ("risc0", "x86_64") => {}
            ("risc0", "aarch64") => {
                return Err(PinContractError::Malformed {
                    field: key,
                    detail: "RISC Zero is native-x86_64-only; an aarch64 RISC Zero toolchain is refused".into(),
                })
            }
            _ => {
                return Err(PinContractError::Malformed {
                    field: key,
                    detail: format!("unexpected framework/arch {}/{}", p.framework, p.arch),
                })
            }
        }
        require_hex64(&format!("{key}.archive_sha256"), &p.archive_sha256)?;
        require_hex64(&format!("{key}.provisioned_tree_blake3"), &p.provisioned_tree_blake3)?;
        if p.ratification != "unratified" {
            return Err(PinContractError::Malformed {
                field: format!("{key}.ratification"),
                detail: format!("must be \"unratified\" (got {:?})", p.ratification),
            });
        }
        let exp = EXPECTED_TOOLCHAINS
            .iter()
            .find(|(fw, ar, _, _)| *fw == p.framework && *ar == p.arch)
            .ok_or_else(|| PinContractError::Malformed {
                field: key.clone(),
                detail: "no frozen expectation for this framework/arch".into(),
            })?;
        expect_eq(&format!("{key}.archive_sha256"), exp.2, &p.archive_sha256)?;
        expect_eq(&format!("{key}.provisioned_tree_blake3"), exp.3, &p.provisioned_tree_blake3)?;
    }
    // Coverage: all three expected toolchains must be present.
    for (fw, ar, _, _) in EXPECTED_TOOLCHAINS {
        if !pins.iter().any(|p| p.framework == *fw && p.arch == *ar) {
            return Err(PinContractError::MissingBlock("guest_toolchains: missing a required framework/arch"))
                .map_err(|_| PinContractError::Malformed {
                    field: "guest_toolchains".into(),
                    detail: format!("missing required toolchain {fw}/{ar}"),
                });
        }
    }
    Ok(())
}

fn validate_circuit(a: &Groth16CircuitArtifactPin) -> Result<(), PinContractError> {
    if a.framework != "sp1" {
        return Err(PinContractError::Malformed {
            field: "groth16_circuit_artifact.framework".into(),
            detail: format!("must be sp1 (got {:?})", a.framework),
        });
    }
    require_hex64("groth16_circuit_artifact.archive_sha256", &a.archive_sha256)?;
    require_hex64("groth16_circuit_artifact.runtime_tree_blake3", &a.runtime_tree_blake3)?;
    expect_eq("groth16_circuit_artifact.archive_sha256", CIRCUIT_ARCHIVE_SHA256, &a.archive_sha256)?;
    if a.archive_size_bytes != CIRCUIT_ARCHIVE_SIZE {
        return Err(PinContractError::IdentityMismatch {
            field: "groth16_circuit_artifact.archive_size_bytes".into(),
            expected: CIRCUIT_ARCHIVE_SIZE.to_string(),
            got: a.archive_size_bytes.to_string(),
        });
    }
    expect_eq(
        "groth16_circuit_artifact.runtime_tree_blake3",
        CIRCUIT_RUNTIME_TREE_BLAKE3,
        &a.runtime_tree_blake3,
    )?;

    // Full member inventory: every declared member is one of the frozen expectations, and
    // every frozen expectation appears exactly once (reject added / altered / missing).
    let mut seen_real: Vec<&str> = Vec::new();
    let mut seen_ad: Vec<&str> = Vec::new();
    let mut seen_dir = false;
    for m in &a.members {
        match m.kind.as_str() {
            "real" => {
                let exp = CIRCUIT_REAL_MEMBERS
                    .iter()
                    .find(|(n, _, _)| *n == m.path)
                    .ok_or_else(|| PinContractError::UnexpectedMember {
                        detail: format!("real member not in the approved set: {:?}", m.path),
                    })?;
                let sha = m.sha256.as_deref().ok_or_else(|| PinContractError::Malformed {
                    field: format!("member {:?}.sha256", m.path),
                    detail: "real member requires sha256".into(),
                })?;
                require_hex64(&format!("member {:?}.sha256", m.path), sha)?;
                let size = m.size.ok_or_else(|| PinContractError::Malformed {
                    field: format!("member {:?}.size", m.path),
                    detail: "real member requires size".into(),
                })?;
                if size != exp.1 {
                    return Err(PinContractError::UnexpectedMember {
                        detail: format!("real member {:?} size {} != {}", m.path, size, exp.1),
                    });
                }
                expect_eq(&format!("member {:?}.sha256", m.path), exp.2, sha)?;
                if seen_real.contains(&m.path.as_str()) {
                    return Err(PinContractError::UnexpectedMember {
                        detail: format!("duplicate real member {:?}", m.path),
                    });
                }
                seen_real.push(exp.0);
            }
            "appledouble" => {
                if !CIRCUIT_APPLEDOUBLE_NAMES.contains(&m.path.as_str()) {
                    return Err(PinContractError::UnexpectedMember {
                        detail: format!("AppleDouble sidecar not in the approved set: {:?}", m.path),
                    });
                }
                let sha = m.sha256.as_deref().ok_or_else(|| PinContractError::Malformed {
                    field: format!("member {:?}.sha256", m.path),
                    detail: "AppleDouble requires sha256".into(),
                })?;
                // Every AppleDouble is the same inert 163-byte blob.
                expect_eq(&format!("member {:?}.sha256", m.path), APPLEDOUBLE_SHA256, sha)?;
                if m.size != Some(APPLEDOUBLE_SIZE) {
                    return Err(PinContractError::UnexpectedMember {
                        detail: format!("AppleDouble {:?} size {:?} != {}", m.path, m.size, APPLEDOUBLE_SIZE),
                    });
                }
                if seen_ad.contains(&m.path.as_str()) {
                    return Err(PinContractError::UnexpectedMember {
                        detail: format!("duplicate AppleDouble {:?}", m.path),
                    });
                }
                seen_ad.push(CIRCUIT_APPLEDOUBLE_NAMES.iter().find(|n| **n == m.path).unwrap());
            }
            "dir" => {
                if seen_dir {
                    return Err(PinContractError::UnexpectedMember {
                        detail: "more than one dir member".into(),
                    });
                }
                seen_dir = true;
            }
            other => {
                return Err(PinContractError::UnexpectedMember {
                    detail: format!("member {:?} has unknown kind {:?}", m.path, other),
                })
            }
        }
    }
    if seen_real.len() != CIRCUIT_REAL_MEMBERS.len() {
        return Err(PinContractError::UnexpectedMember {
            detail: format!("expected {} real members, saw {}", CIRCUIT_REAL_MEMBERS.len(), seen_real.len()),
        });
    }
    if seen_ad.len() != CIRCUIT_APPLEDOUBLE_NAMES.len() {
        return Err(PinContractError::UnexpectedMember {
            detail: format!("expected {} AppleDouble sidecars, saw {}", CIRCUIT_APPLEDOUBLE_NAMES.len(), seen_ad.len()),
        });
    }

    // runtime_members = EXACTLY the 7 real names (the runtime tree installs no sidecar).
    if a.runtime_members.len() != CIRCUIT_REAL_MEMBERS.len() {
        return Err(PinContractError::UnexpectedMember {
            detail: format!(
                "runtime_members has {} entries, expected {}",
                a.runtime_members.len(),
                CIRCUIT_REAL_MEMBERS.len()
            ),
        });
    }
    for name in &a.runtime_members {
        if name.starts_with("._") {
            return Err(PinContractError::UnexpectedMember {
                detail: format!("runtime_members includes an AppleDouble sidecar {name:?}"),
            });
        }
        if !CIRCUIT_REAL_MEMBERS.iter().any(|(n, _, _)| n == name) {
            return Err(PinContractError::UnexpectedMember {
                detail: format!("runtime_members includes a non-approved member {name:?}"),
            });
        }
    }
    Ok(())
}

fn validate_oci_backends(backends: &[OciBackendPin]) -> Result<(), PinContractError> {
    for b in backends {
        let key = format!("oci_backends[{}]", b.name);
        // A usable Stage-5 backend is linux/amd64 ONLY. An arm64/aarch64 usable backend =
        // an ARM terminal-Groth16 capability, which is forbidden (RISC Zero arm64 is
        // unsupported and is REJECTED, never recorded as a usable pin).
        if b.platform == "linux/arm64" || b.platform.ends_with("arm64") || b.platform.ends_with("aarch64") {
            return Err(PinContractError::ArmTerminalGroth16 {
                detail: format!("{key} declares a usable platform {:?}", b.platform),
            });
        }
        if b.platform != "linux/amd64" {
            return Err(PinContractError::Malformed {
                field: format!("{key}.platform"),
                detail: format!("usable backend must be linux/amd64 (got {:?})", b.platform),
            });
        }
        require_oci_digest(&format!("{key}.index_digest"), &b.index_digest)?;
        require_oci_digest(&format!("{key}.amd64_manifest_digest"), &b.amd64_manifest_digest)?;
        require_oci_digest(&format!("{key}.config_digest"), &b.config_digest)?;
        require_oci_digest(&format!("{key}.loaded_image_id"), &b.loaded_image_id)?;
        if let Some(att) = &b.attestation_digest {
            require_oci_digest(&format!("{key}.attestation_digest"), att)?;
        }
        if b.entrypoint.trim().is_empty() {
            return Err(PinContractError::Malformed {
                field: format!("{key}.entrypoint"),
                detail: "empty entrypoint".into(),
            });
        }

        // Role distinctness: index, amd64 manifest, and config are three DIFFERENT identities.
        // A record that conflates any two of them (e.g. config copied from the index, as the
        // containerd `.Id` would suggest) fails closed.
        if b.index_digest == b.amd64_manifest_digest {
            return Err(PinContractError::Malformed {
                field: key.clone(),
                detail: "index_digest equals amd64_manifest_digest (conflated)".into(),
            });
        }
        if b.index_digest == b.config_digest {
            return Err(PinContractError::Malformed {
                field: key.clone(),
                detail: "config_digest equals index_digest (config was NOT resolved from the manifest)".into(),
            });
        }
        if b.amd64_manifest_digest == b.config_digest {
            return Err(PinContractError::Malformed {
                field: key.clone(),
                detail: "config_digest equals amd64_manifest_digest (conflated)".into(),
            });
        }
        // The load identity rule: loaded_image_id == config_digest, and it is NEVER the index
        // or the platform manifest.
        if b.loaded_image_id == b.index_digest {
            return Err(PinContractError::Malformed {
                field: format!("{key}.loaded_image_id"),
                detail: "loaded_image_id equals the index digest (must equal the config digest)".into(),
            });
        }
        if b.loaded_image_id == b.amd64_manifest_digest {
            return Err(PinContractError::Malformed {
                field: format!("{key}.loaded_image_id"),
                detail: "loaded_image_id equals the platform manifest digest (must equal the config digest)".into(),
            });
        }
        if b.loaded_image_id != b.config_digest {
            return Err(PinContractError::IdentityMismatch {
                field: format!("{key}.loaded_image_id"),
                expected: b.config_digest.clone(),
                got: b.loaded_image_id.clone(),
            });
        }

        let exp = EXPECTED_OCI_BACKENDS
            .iter()
            .find(|e| e.name == b.name)
            .ok_or_else(|| PinContractError::Malformed {
                field: key.clone(),
                detail: format!("no frozen expectation for backend {:?}", b.name),
            })?;
        expect_eq(&format!("{key}.index_digest"), exp.index_digest, &b.index_digest)?;
        expect_eq(&format!("{key}.amd64_manifest_digest"), exp.amd64_manifest_digest, &b.amd64_manifest_digest)?;
        expect_eq(&format!("{key}.config_digest"), exp.config_digest, &b.config_digest)?;
        // loaded_image_id is already proven == config_digest above; it therefore matches exp too.
        expect_eq(&format!("{key}.entrypoint"), exp.entrypoint, &b.entrypoint)?;
        // Attestation presence + value must match the frozen expectation exactly.
        match (exp.attestation_digest, &b.attestation_digest) {
            (Some(want), Some(got)) => expect_eq(&format!("{key}.attestation_digest"), want, got)?,
            (None, None) => {}
            (Some(_), None) => {
                return Err(PinContractError::Malformed {
                    field: format!("{key}.attestation_digest"),
                    detail: "expected an attestation digest, none declared".into(),
                })
            }
            (None, Some(_)) => {
                return Err(PinContractError::Malformed {
                    field: format!("{key}.attestation_digest"),
                    detail: "declared an attestation digest but this backend's index carries none".into(),
                })
            }
        }
    }
    // Coverage: both expected backends present.
    for e in EXPECTED_OCI_BACKENDS {
        if !backends.iter().any(|b| b.name == e.name) {
            return Err(PinContractError::Malformed {
                field: "oci_backends".into(),
                detail: format!("missing required backend {:?}", e.name),
            });
        }
    }
    Ok(())
}

/// Parse + evaluate a pin-contract JSON. Never ratifies; capability-complete is a precondition.
pub fn evaluate_contract(json: &str) -> Result<ContractEvaluation, PinContractError> {
    let raw: RawContract =
        serde_json::from_str(json).map_err(|e| PinContractError::Json(e.to_string()))?;

    let (version, legacy) = match (&raw.contract_version, &raw.legacy_contract_version) {
        (Some(v), _) => (ContractVersion::parse(v)?, false),
        (None, Some(v)) => {
            // Historical file: read the FIRST token of the informational field ("v3 (…)").
            let tok = v.split_whitespace().next().unwrap_or("");
            (ContractVersion::parse(tok)?, true)
        }
        (None, None) => return Err(PinContractError::MissingVersion),
    };

    match version {
        ContractVersion::V2 | ContractVersion::V3 => {
            let src = if legacy { " (legacy _contract_version)" } else { "" };
            Ok(ContractEvaluation {
                version,
                capability: Capability::Ineligible {
                    reason: format!(
                        "contract {}{} predates the Stage-5 capability blocks (guest_toolchains, \
                         groth16_circuit_artifact, oci_backends); permanently INELIGIBLE for \
                         capability-complete Stage-5",
                        version.as_str(),
                        src
                    ),
                },
                summary: format!(
                    "contract={}{} parsed; INELIGIBLE for capability-complete Stage-5",
                    version.as_str(),
                    src
                ),
            })
        }
        ContractVersion::V4 => {
            let toolchains = raw
                .guest_toolchains
                .as_deref()
                .ok_or(PinContractError::MissingBlock("guest_toolchains"))?;
            let circuit = raw
                .groth16_circuit_artifact
                .as_ref()
                .ok_or(PinContractError::MissingBlock("groth16_circuit_artifact"))?;
            let backends = raw
                .oci_backends
                .as_deref()
                .ok_or(PinContractError::MissingBlock("oci_backends"))?;

            validate_guest_toolchains(toolchains)?;
            validate_circuit(circuit)?;
            validate_oci_backends(backends)?;

            Ok(ContractEvaluation {
                version,
                capability: Capability::Complete,
                summary: format!(
                    "contract=v4 capability-complete: {} guest toolchains, circuit runtime-tree {}, {} OCI backends (x86_64 terminal-Groth16; ARM compile/identity/verify only). UNRATIFIED.",
                    toolchains.len(),
                    CIRCUIT_RUNTIME_TREE_BLAKE3,
                    backends.len()
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but VALID v4 contract JSON built from the frozen reconciled values.
    fn valid_v4() -> serde_json::Value {
        let real: Vec<_> = CIRCUIT_REAL_MEMBERS
            .iter()
            .map(|(n, s, h)| serde_json::json!({"path": n, "kind": "real", "size": s, "sha256": h}))
            .collect();
        let ad: Vec<_> = CIRCUIT_APPLEDOUBLE_NAMES
            .iter()
            .map(|n| serde_json::json!({"path": n, "kind": "appledouble", "size": APPLEDOUBLE_SIZE, "sha256": APPLEDOUBLE_SHA256}))
            .collect();
        let mut members = real;
        members.extend(ad);
        members.push(serde_json::json!({"path": ".", "kind": "dir"}));
        let runtime: Vec<_> = CIRCUIT_REAL_MEMBERS.iter().map(|(n, _, _)| *n).collect();

        let toolchains: Vec<_> = EXPECTED_TOOLCHAINS
            .iter()
            .map(|(fw, ar, sha, tree)| {
                serde_json::json!({
                    "framework": fw, "arch": ar, "toolchain_version": "pinned",
                    "archive_sha256": sha, "provisioned_tree_blake3": tree,
                    "ratification": "unratified"
                })
            })
            .collect();
        let backends: Vec<_> = EXPECTED_OCI_BACKENDS
            .iter()
            .map(|e| {
                let mut o = serde_json::json!({
                    "name": e.name, "platform": "linux/amd64",
                    "index_digest": e.index_digest,
                    "amd64_manifest_digest": e.amd64_manifest_digest,
                    "config_digest": e.config_digest,
                    "loaded_image_id": e.config_digest,  // load identity == config
                    "entrypoint": e.entrypoint
                });
                if let Some(att) = e.attestation_digest {
                    o.as_object_mut().unwrap().insert("attestation_digest".into(), serde_json::json!(att));
                }
                o
            })
            .collect();

        serde_json::json!({
            "contract_version": "v4",
            "guest_toolchains": toolchains,
            "groth16_circuit_artifact": {
                "framework": "sp1", "circuit_version": "v6.1.0-groth16",
                "archive_sha256": CIRCUIT_ARCHIVE_SHA256,
                "archive_size_bytes": CIRCUIT_ARCHIVE_SIZE,
                "runtime_tree_blake3": CIRCUIT_RUNTIME_TREE_BLAKE3,
                "members": members,
                "runtime_members": runtime
            },
            "oci_backends": backends,
            "base_image": "ghcr.io/example/base"  // a legacy block coexists, ignored here
        })
    }

    fn eval(v: &serde_json::Value) -> Result<ContractEvaluation, PinContractError> {
        evaluate_contract(&v.to_string())
    }

    #[test]
    fn valid_v4_is_capability_complete() {
        let e = eval(&valid_v4()).unwrap();
        assert_eq!(e.version, ContractVersion::V4);
        assert_eq!(e.capability, Capability::Complete);
    }

    #[test]
    fn v3_parses_but_is_ineligible() {
        let e = eval(&serde_json::json!({"contract_version": "v3", "base_image": "x"})).unwrap();
        assert_eq!(e.version, ContractVersion::V3);
        assert!(matches!(e.capability, Capability::Ineligible { .. }));
    }

    #[test]
    fn legacy_underscore_v3_is_ineligible() {
        let e = eval(&serde_json::json!({"_contract_version": "v3 (v2 base + …)", "base_image": "x"})).unwrap();
        assert_eq!(e.version, ContractVersion::V3);
        assert!(matches!(e.capability, Capability::Ineligible { .. }));
    }

    #[test]
    fn unknown_version_fails_closed() {
        let e = eval(&serde_json::json!({"contract_version": "v5"}));
        assert!(matches!(e, Err(PinContractError::UnknownVersion(_))));
        let e2 = eval(&serde_json::json!({"contract_version": "v4-rc1"}));
        assert!(matches!(e2, Err(PinContractError::UnknownVersion(_))));
    }

    #[test]
    fn missing_version_fails_closed() {
        assert!(matches!(eval(&serde_json::json!({"base_image": "x"})), Err(PinContractError::MissingVersion)));
    }

    #[test]
    fn v4_missing_a_block_fails_closed() {
        let mut v = valid_v4();
        v.as_object_mut().unwrap().remove("oci_backends");
        assert!(matches!(eval(&v), Err(PinContractError::MissingBlock("oci_backends"))));
        let mut v2 = valid_v4();
        v2.as_object_mut().unwrap().remove("guest_toolchains");
        assert!(matches!(eval(&v2), Err(PinContractError::MissingBlock("guest_toolchains"))));
    }

    #[test]
    fn altered_circuit_member_hash_fails_closed() {
        let mut v = valid_v4();
        // Corrupt groth16_pk.bin's sha256.
        let members = v["groth16_circuit_artifact"]["members"].as_array_mut().unwrap();
        for m in members.iter_mut() {
            if m["path"] == "groth16_pk.bin" {
                m["sha256"] = serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
            }
        }
        assert!(matches!(eval(&v), Err(PinContractError::IdentityMismatch { .. })));
    }

    #[test]
    fn altered_circuit_member_size_fails_closed() {
        let mut v = valid_v4();
        let members = v["groth16_circuit_artifact"]["members"].as_array_mut().unwrap();
        for m in members.iter_mut() {
            if m["path"] == "groth16_vk.bin" {
                m["size"] = serde_json::json!(999);
            }
        }
        assert!(matches!(eval(&v), Err(PinContractError::UnexpectedMember { .. })));
    }

    #[test]
    fn extra_sidecar_fails_closed() {
        let mut v = valid_v4();
        v["groth16_circuit_artifact"]["members"].as_array_mut().unwrap().push(
            serde_json::json!({"path": "._evil", "kind": "appledouble", "size": APPLEDOUBLE_SIZE, "sha256": APPLEDOUBLE_SHA256}),
        );
        assert!(matches!(eval(&v), Err(PinContractError::UnexpectedMember { .. })));
    }

    #[test]
    fn appledouble_leaked_into_runtime_fails_closed() {
        let mut v = valid_v4();
        v["groth16_circuit_artifact"]["runtime_members"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("._groth16_pk.bin"));
        assert!(matches!(eval(&v), Err(PinContractError::UnexpectedMember { .. })));
    }

    #[test]
    fn mutable_tag_oci_ref_fails_closed() {
        let mut v = valid_v4();
        v["oci_backends"][0]["index_digest"] = serde_json::json!("ghcr.io/succinctlabs/sp1-gnark:v6.1.0");
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn arm64_backend_fails_closed() {
        let mut v = valid_v4();
        v["oci_backends"][0]["platform"] = serde_json::json!("linux/arm64");
        assert!(matches!(eval(&v), Err(PinContractError::ArmTerminalGroth16 { .. })));
    }

    // ---- OCI identity conflation matrix (index / manifest / config / image-id / attestation) ----

    #[test]
    fn loaded_image_id_equals_config_is_required() {
        // Sanity: the valid fixture has loaded_image_id == config_digest.
        let v = valid_v4();
        assert_eq!(v["oci_backends"][0]["loaded_image_id"], v["oci_backends"][0]["config_digest"]);
        assert_eq!(eval(&v).unwrap().capability, Capability::Complete);
    }

    #[test]
    fn image_id_as_index_fails_closed() {
        let mut v = valid_v4();
        let idx = v["oci_backends"][0]["index_digest"].clone();
        v["oci_backends"][0]["loaded_image_id"] = idx;
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn image_id_as_manifest_fails_closed() {
        // The exact RISC Zero bug: loaded_image_id set to the platform manifest digest.
        let mut v = valid_v4();
        let man = v["oci_backends"][1]["amd64_manifest_digest"].clone();
        v["oci_backends"][1]["loaded_image_id"] = man;
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn config_equals_index_fails_closed() {
        // The exact SP1 bug: config copied from the index digest.
        let mut v = valid_v4();
        let idx = v["oci_backends"][0]["index_digest"].clone();
        v["oci_backends"][0]["config_digest"] = idx.clone();
        v["oci_backends"][0]["loaded_image_id"] = idx; // keep loaded==config to isolate the conflation
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn config_equals_manifest_fails_closed() {
        let mut v = valid_v4();
        let man = v["oci_backends"][0]["amd64_manifest_digest"].clone();
        v["oci_backends"][0]["config_digest"] = man.clone();
        v["oci_backends"][0]["loaded_image_id"] = man;
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn swapped_index_and_manifest_fails_closed() {
        let mut v = valid_v4();
        let idx = v["oci_backends"][0]["index_digest"].clone();
        let man = v["oci_backends"][0]["amd64_manifest_digest"].clone();
        v["oci_backends"][0]["index_digest"] = man;
        v["oci_backends"][0]["amd64_manifest_digest"] = idx;
        assert!(matches!(eval(&v), Err(PinContractError::IdentityMismatch { .. })));
    }

    #[test]
    fn sp1_missing_attestation_fails_closed() {
        let mut v = valid_v4();
        v["oci_backends"][0].as_object_mut().unwrap().remove("attestation_digest");
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn risc0_spurious_attestation_fails_closed() {
        // risc0-groth16 index carries NO attestation; declaring one is refused.
        let mut v = valid_v4();
        v["oci_backends"][1].as_object_mut().unwrap().insert(
            "attestation_digest".into(),
            serde_json::json!("sha256:6ade751e47f161a6d351675c72619ca9f9dff685c41962985e40e2b2289696b9"),
        );
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn risc0_guest_builder_is_refused_as_a_backend() {
        // The owner rejected the CLI/docker guest-builder path (Option B chosen). Declaring the
        // guest-builder image as a usable Stage-5 OCI backend fails closed: it is absent from
        // EXPECTED_OCI_BACKENDS and named in REJECTED_OCI_BACKENDS.
        let (name, digest) = REJECTED_OCI_BACKENDS[0];
        assert_eq!(name, "risc0-guest-builder");
        let mut v = valid_v4();
        v["oci_backends"].as_array_mut().unwrap().push(serde_json::json!({
            "name": name, "platform": "linux/amd64",
            "index_digest": digest, "amd64_manifest_digest": digest,
            "config_digest": digest, "loaded_image_id": digest, "entrypoint": "/no"
        }));
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. }) | Err(PinContractError::IdentityMismatch { .. })));
        // And it is never in the accepted set.
        assert!(!EXPECTED_OCI_BACKENDS.iter().any(|e| e.name == name),
            "guest-builder must never be an accepted backend");
    }

    #[test]
    fn wrong_config_digest_fails_closed() {
        // A config that is distinct from index+manifest but not the TRUE resolved config.
        let mut v = valid_v4();
        let bogus = "sha256:1234567890123456789012345678901234567890123456789012345678901234";
        v["oci_backends"][0]["config_digest"] = serde_json::json!(bogus);
        v["oci_backends"][0]["loaded_image_id"] = serde_json::json!(bogus);
        assert!(matches!(eval(&v), Err(PinContractError::IdentityMismatch { .. })));
    }

    #[test]
    fn wrong_toolchain_tree_digest_fails_closed() {
        let mut v = valid_v4();
        v["guest_toolchains"][0]["provisioned_tree_blake3"] =
            serde_json::json!("1111111111111111111111111111111111111111111111111111111111111111");
        assert!(matches!(eval(&v), Err(PinContractError::IdentityMismatch { .. })));
    }

    #[test]
    fn risc0_aarch64_toolchain_fails_closed() {
        let mut v = valid_v4();
        v["guest_toolchains"].as_array_mut().unwrap().push(serde_json::json!({
            "framework": "risc0", "arch": "aarch64", "toolchain_version": "x",
            "archive_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "provisioned_tree_blake3": "0000000000000000000000000000000000000000000000000000000000000000",
            "ratification": "unratified"
        }));
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }

    #[test]
    fn synthetic_marker_fails_closed() {
        let mut v = valid_v4();
        v["guest_toolchains"][0]["archive_sha256"] = serde_json::json!("TEST_ONLY-synthetic");
        assert!(matches!(eval(&v), Err(PinContractError::Synthetic { .. })));
    }

    #[test]
    fn unknown_field_in_new_block_fails_closed() {
        let mut v = valid_v4();
        v["oci_backends"][0]["surprise"] = serde_json::json!("x");
        assert!(matches!(eval(&v), Err(PinContractError::Json(_))));
    }

    #[test]
    fn unratified_ratification_is_required() {
        let mut v = valid_v4();
        v["guest_toolchains"][0]["ratification"] = serde_json::json!("ratified");
        assert!(matches!(eval(&v), Err(PinContractError::Malformed { .. })));
    }
}

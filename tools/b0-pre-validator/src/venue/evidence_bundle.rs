//! Blocker 1 + 7: full evidence import via a typed, hashed, immutable per-arch
//! bundle — `PerArchEvidenceBundleV1`.
//!
//! The prior per-arch path (`arch_bundle::import_verify`) read a MUTABLE directory
//! of files directly and only checked container coverage + reproducibility; the
//! lock provenance, Stage-2 audit, tool bindings, and Stage-5 results were verified
//! (if at all) in separate steps, and nothing hashed the bundle as a whole, so a
//! file could be swapped between "verify a directory" and "later copy mutable
//! files". This module closes that: a per-arch bundle is a SEALED manifest that
//! records the BLAKE3 of EVERY required file plus a single content hash, and
//! [`import_verify`] recomputes every hash, rejects any unmanifested or missing
//! file, and then decodes + validates the TYPED stage records (lock provenance,
//! Stage-2 audit, tool bindings, Stage-5 result, container/native builds, verifier
//! material), binding all of them to ONE architecture + ONE source commit. It
//! returns an in-memory [`ImportedArchBundle`]; cross-arch [`aggregate_imported`]
//! consumes ONLY those typed objects, never a directory, so a post-import file swap
//! cannot affect aggregation.
//!
//! The container builds / extractions / installs run only on-venue (they fail
//! closed off-venue); this seal + import + aggregate core is pure and is unit-tested
//! here with real-shaped bundles and adversarial mutations.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::schema::stage6::{NativeBuild, OciBuild};

use super::arch_bundle::{self, AggregatedVenueInputs, ArchBundleError, PerArchBundle};
use super::audit::Stage2AuditRecord;
use super::lock_provenance::{verify_in_container_provenance, LockBinding, LockProvenance};
use super::stage5::Stage5Result;
use super::tool_install::{InstallMode, ToolBindingRecord};

/// The frozen sealed-bundle kind + schema version.
pub const EVIDENCE_BUNDLE_KIND: &str = "b0-pre-per-arch-evidence-bundle-v1";
pub const EVIDENCE_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// The sealed manifest file name (never itself listed in `files`).
pub const MANIFEST_FILE: &str = "arch-evidence-manifest.json";

/// Domain separation for the whole-bundle content hash (venue-internal; NOT a
/// protocol spec tag and never part of `b0_pre_spec_hash`).
const ARCH_EVIDENCE_PREFIX: &[u8] = b"SUMCHAIN/B0PRE/ARCHEVIDENCE/v1\n";

const CANDIDATES: [&str; 2] = ["Sp1", "Risc0"];

/// The canonical per-candidate file names inside a sealed per-arch bundle. Arch is
/// implied by the bundle, so file names are NOT arch-suffixed.
fn container_file(c: &str) -> String {
    format!("{c}.container.json")
}
fn native_file(c: &str) -> String {
    format!("{c}.native.json")
}
fn lock_file(c: &str) -> String {
    format!("{c}.Cargo.lock")
}
fn lock_prov_file(c: &str) -> String {
    format!("{c}.lock-provenance.json")
}
fn stage2_file(c: &str) -> String {
    format!("{c}.stage2-audit.json")
}
fn tool_binding_file(c: &str) -> String {
    format!("{c}.tool-binding.json")
}
fn stage5_file(c: &str) -> String {
    format!("{c}.stage5-result.json")
}
const SP1_MATERIAL: &str = "sp1-verifier-material.json";
const RISC0_MATERIAL: &str = "risc0-verifier-material.json";

/// The exact set of required file names for a per-arch bundle. x86_64 additionally
/// carries the RISC Zero verifier material + RISC Zero Stage-5 result (§2:
/// x86_64-only); aarch64 must NOT.
pub fn required_files(arch: &str) -> Vec<String> {
    let mut v = Vec::new();
    for c in CANDIDATES {
        v.push(container_file(c));
        v.push(native_file(c));
        v.push(lock_file(c));
        v.push(lock_prov_file(c));
        v.push(stage2_file(c));
        v.push(tool_binding_file(c));
    }
    v.push(stage5_file("Sp1"));
    v.push(SP1_MATERIAL.to_string());
    if arch == arch_bundle::ARCH_X86_64 {
        v.push(stage5_file("Risc0"));
        v.push(RISC0_MATERIAL.to_string());
    }
    v.sort();
    v
}

/// One manifested file: its name, the BLAKE3 (bare 64-hex) of its bytes, and its
/// byte length. Strict: unknown fields are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestedFile {
    pub name: String,
    pub blake3_hex: String,
    pub byte_len: u64,
}

/// The sealed per-arch evidence manifest. Records the hash of every required file
/// plus a single content hash binding them together, all under ONE arch + ONE
/// source commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerArchEvidenceBundleV1 {
    pub schema_version: u32,
    pub bundle_kind: String,
    /// `X86_64` or `Aarch64`.
    pub arch: String,
    /// The single clean source commit every record in the bundle is bound to.
    pub source_commit: String,
    /// The hash of every required file (sorted by name).
    pub files: Vec<ManifestedFile>,
    /// `BLAKE3(ARCH_EVIDENCE_PREFIX ‖ arch ‖ source_commit ‖ sorted file tuples)`.
    pub bundle_content_hash: String,
}

/// The successfully-imported, typed per-arch bundle held in memory. Cross-arch
/// aggregation consumes ONLY this — never a directory.
#[derive(Debug, Clone)]
pub struct ImportedArchBundle {
    pub arch: String,
    pub source_commit: String,
    pub builds: Vec<OciBuild>,
    pub native: Vec<NativeBuild>,
    pub sp1_extractor_json: String,
    pub risc0_extractor_json: Option<String>,
    pub lock_bindings: Vec<LockBinding>,
    pub tool_bindings: Vec<ToolBindingRecord>,
    pub stage2_reports: Vec<Stage2AuditRecord>,
    pub stage5_results: Vec<Stage5Result>,
    /// Item 6: the VERIFIED candidate lock bytes retained during import (each hash
    /// was already checked against its provenance record), so cross-arch aggregation
    /// can emit `<Candidate>.Cargo.lock` from the TYPED bundle, never a directory copy.
    pub verified_locks: Vec<(String, Vec<u8>)>,
    /// The verified whole-bundle content hash.
    pub content_hash: String,
}

impl ImportedArchBundle {
    /// The container/native/material view the reused cross-arch aggregator consumes.
    pub fn to_per_arch_bundle(&self) -> PerArchBundle {
        PerArchBundle {
            arch: self.arch.clone(),
            builds: self.builds.clone(),
            native: self.native.clone(),
            sp1_extractor_json: self.sp1_extractor_json.clone(),
            risc0_extractor_json: self.risc0_extractor_json.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    Io(String),
    Parse {
        file: String,
        error: String,
    },
    SchemaVersion {
        got: u32,
    },
    BundleKind {
        got: String,
    },
    UnknownArch {
        arch: String,
    },
    BadSourceCommit {
        commit: String,
    },
    /// A file present in the bundle directory was not listed in the manifest.
    UnmanifestedFile {
        name: String,
    },
    /// A required file was absent from the manifest / directory.
    MissingFile {
        name: String,
    },
    /// A listed file's recomputed BLAKE3 / length did not match the manifest.
    FileHashMismatch {
        name: String,
        recorded: String,
        recomputed: String,
    },
    /// The whole-bundle content hash did not match.
    ContentHashMismatch {
        recorded: String,
        recomputed: String,
    },
    /// A record's architecture disagreed with the bundle arch.
    ArchBinding {
        file: String,
        got: String,
    },
    /// A record's source commit disagreed with the bundle source commit.
    SourceCommitBinding {
        file: String,
        got: String,
    },
    /// A record's container digest was not bound to this candidate's builder image.
    ContainerBinding {
        file: String,
        got: String,
        expected: String,
    },
    /// A lock provenance record was rejected.
    Lock {
        candidate: String,
        error: String,
    },
    /// A Stage-2 audit record was rejected.
    Stage2 {
        candidate: String,
        error: String,
    },
    /// A tool binding record was rejected.
    Tool {
        candidate: String,
        error: String,
    },
    /// A Stage-5 result was rejected.
    Stage5 {
        candidate: String,
        error: String,
    },
    /// The container/native coverage / reproducibility / RISC-Zero rule failed.
    ArchBundle(ArchBundleError),
    /// A builder-role OciBuild was missing its parsed platform / media-type proof
    /// (Blocker 8), or the platform did not match the build arch.
    PlatformBinding {
        candidate: String,
        detail: String,
    },
    /// The Stage-5 tool identity was not bound to a verified tool binding.
    Stage5ToolUnbound {
        candidate: String,
    },
    /// A candidate's evidence was absent (coverage).
    CandidateCoverage {
        kind: &'static str,
        candidate: String,
    },
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceError::Io(e) => write!(f, "bundle io error: {e}"),
            EvidenceError::Parse { file, error } => write!(f, "{file}: strict parse failed: {error}"),
            EvidenceError::SchemaVersion { got } => {
                write!(f, "manifest schema_version must be {EVIDENCE_BUNDLE_SCHEMA_VERSION}, got {got}")
            }
            EvidenceError::BundleKind { got } => {
                write!(f, "manifest bundle_kind must be {EVIDENCE_BUNDLE_KIND:?}, got {got:?}")
            }
            EvidenceError::UnknownArch { arch } => write!(f, "unknown bundle arch {arch:?}"),
            EvidenceError::BadSourceCommit { commit } => {
                write!(f, "bundle source_commit invalid: {commit:?}")
            }
            EvidenceError::UnmanifestedFile { name } => write!(
                f,
                "file {name:?} is present in the bundle but NOT listed in the sealed manifest"
            ),
            EvidenceError::MissingFile { name } => {
                write!(f, "required bundle file {name:?} is missing")
            }
            EvidenceError::FileHashMismatch { name, recorded, recomputed } => write!(
                f,
                "file {name:?} hash mismatch: manifest {recorded} != recomputed {recomputed}"
            ),
            EvidenceError::ContentHashMismatch { recorded, recomputed } => write!(
                f,
                "bundle content hash mismatch: manifest {recorded} != recomputed {recomputed}"
            ),
            EvidenceError::ArchBinding { file, got } => {
                write!(f, "{file}: architecture {got:?} disagrees with the bundle arch")
            }
            EvidenceError::SourceCommitBinding { file, got } => {
                write!(f, "{file}: source_commit {got:?} disagrees with the bundle source_commit")
            }
            EvidenceError::ContainerBinding { file, got, expected } => write!(
                f,
                "{file}: container_digest {got:?} is not this candidate's builder digest {expected:?}"
            ),
            EvidenceError::Lock { candidate, error } => {
                write!(f, "{candidate} lock provenance rejected: {error}")
            }
            EvidenceError::Stage2 { candidate, error } => {
                write!(f, "{candidate} Stage-2 audit rejected: {error}")
            }
            EvidenceError::Tool { candidate, error } => {
                write!(f, "{candidate} tool binding rejected: {error}")
            }
            EvidenceError::Stage5 { candidate, error } => {
                write!(f, "{candidate} Stage-5 result rejected: {error}")
            }
            EvidenceError::ArchBundle(e) => write!(f, "container/native import failed: {e}"),
            EvidenceError::PlatformBinding { candidate, detail } => {
                write!(f, "{candidate} builder platform/media-type binding invalid: {detail}")
            }
            EvidenceError::Stage5ToolUnbound { candidate } => write!(
                f,
                "{candidate} Stage-5 tool_identity_hex is not bound to any verified tool binding"
            ),
            EvidenceError::CandidateCoverage { kind, candidate } => {
                write!(f, "missing {kind} evidence for candidate {candidate}")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

fn io<E: std::fmt::Display>(e: E) -> EvidenceError {
    EvidenceError::Io(e.to_string())
}

fn is_known_arch(a: &str) -> bool {
    a == arch_bundle::ARCH_X86_64 || a == arch_bundle::ARCH_AARCH64
}

fn valid_commit(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && !s.bytes().all(|b| b == b'0')
}

/// The OCI platform spelling for a schema arch.
fn oci_arch(arch: &str) -> &'static str {
    match arch {
        a if a == arch_bundle::ARCH_X86_64 => "amd64",
        _ => "arm64",
    }
}

fn blake3_hex(bytes: &[u8]) -> String {
    super::to_hex(blake3::hash(bytes).as_bytes())
}

/// The whole-bundle content hash over the arch, source commit, and the sorted file
/// tuples — the single value that makes the manifest an immutable object.
fn content_hash(arch: &str, source_commit: &str, files: &[ManifestedFile]) -> String {
    let mut sorted: Vec<&ManifestedFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut pre = ARCH_EVIDENCE_PREFIX.to_vec();
    pre.extend_from_slice(arch.as_bytes());
    pre.push(0);
    pre.extend_from_slice(source_commit.as_bytes());
    pre.push(0);
    for f in sorted {
        pre.extend_from_slice(f.name.as_bytes());
        pre.push(0);
        pre.extend_from_slice(f.blake3_hex.as_bytes());
        pre.push(0);
        pre.extend_from_slice(f.byte_len.to_le_bytes().as_slice());
        pre.push(b'\n');
    }
    blake3_hex(&pre)
}

/// Seal a curated per-arch bundle directory: require it to contain EXACTLY the
/// required files (no unmanifested extras, none missing), hash each, and write the
/// immutable manifest via the durable create-new path. Returns the manifest.
pub fn seal(
    dir: &Path,
    arch: &str,
    source_commit: &str,
) -> Result<PerArchEvidenceBundleV1, EvidenceError> {
    if !is_known_arch(arch) {
        return Err(EvidenceError::UnknownArch {
            arch: arch.to_string(),
        });
    }
    if !valid_commit(source_commit) {
        return Err(EvidenceError::BadSourceCommit {
            commit: source_commit.to_string(),
        });
    }
    let required: BTreeSet<String> = required_files(arch).into_iter().collect();
    // The directory must contain exactly the required files (the manifest is written
    // afterwards). Any extra file is refused; any missing file is refused.
    let mut present: BTreeSet<String> = BTreeSet::new();
    for e in std::fs::read_dir(dir).map_err(io)? {
        let e = e.map_err(io)?;
        if let Some(name) = e.file_name().to_str() {
            if name == MANIFEST_FILE {
                continue;
            }
            present.insert(name.to_string());
        }
    }
    if let Some(extra) = present.difference(&required).next() {
        return Err(EvidenceError::UnmanifestedFile {
            name: extra.clone(),
        });
    }
    if let Some(missing) = required.difference(&present).next() {
        return Err(EvidenceError::MissingFile {
            name: missing.clone(),
        });
    }
    let mut files = Vec::with_capacity(required.len());
    for name in &required {
        let bytes = std::fs::read(dir.join(name)).map_err(io)?;
        files.push(ManifestedFile {
            name: name.clone(),
            blake3_hex: blake3_hex(&bytes),
            byte_len: bytes.len() as u64,
        });
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    let content = content_hash(arch, source_commit, &files);
    let manifest = PerArchEvidenceBundleV1 {
        schema_version: EVIDENCE_BUNDLE_SCHEMA_VERSION,
        bundle_kind: EVIDENCE_BUNDLE_KIND.to_string(),
        arch: arch.to_string(),
        source_commit: source_commit.to_string(),
        files,
        bundle_content_hash: content,
    };
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| EvidenceError::Parse {
        file: MANIFEST_FILE.into(),
        error: e.to_string(),
    })?;
    let out = dir.join(MANIFEST_FILE);
    let tmp = dir.join(format!("{MANIFEST_FILE}.tmp.{}", std::process::id()));
    crate::durable::write_durably(&tmp, &out, format!("{json}\n").as_bytes())
        .map_err(EvidenceError::Io)?;
    Ok(manifest)
}

fn read_file(dir: &Path, name: &str) -> Result<Vec<u8>, EvidenceError> {
    std::fs::read(dir.join(name)).map_err(|e| EvidenceError::Io(format!("read {name}: {e}")))
}

fn parse<T: for<'de> Deserialize<'de>>(name: &str, bytes: &[u8]) -> Result<T, EvidenceError> {
    serde_json::from_slice(bytes).map_err(|e| EvidenceError::Parse {
        file: name.to_string(),
        error: e.to_string(),
    })
}

/// The builder-role image digest for a candidate (what lock/stage2/tool/stage5
/// records must be bound to).
fn builder_digest_for(builds: &[OciBuild], candidate: &str) -> Option<String> {
    builds
        .iter()
        .find(|b| b.candidate == candidate && b.role == "builder")
        .map(|b| b.builder_oci_digest.clone())
}

/// Fully import-verify a sealed per-arch bundle directory. Recomputes every file
/// hash, rejects unmanifested/missing files, re-derives the content hash, then
/// decodes and validates every typed record and binds them to ONE arch + source
/// commit. Returns the in-memory typed bundle for aggregation.
pub fn import_verify(dir: &Path) -> Result<ImportedArchBundle, EvidenceError> {
    // (1) sealed manifest.
    let manifest_bytes = read_file(dir, MANIFEST_FILE)?;
    let manifest: PerArchEvidenceBundleV1 = parse(MANIFEST_FILE, &manifest_bytes)?;
    if manifest.schema_version != EVIDENCE_BUNDLE_SCHEMA_VERSION {
        return Err(EvidenceError::SchemaVersion {
            got: manifest.schema_version,
        });
    }
    if manifest.bundle_kind != EVIDENCE_BUNDLE_KIND {
        return Err(EvidenceError::BundleKind {
            got: manifest.bundle_kind,
        });
    }
    if !is_known_arch(&manifest.arch) {
        return Err(EvidenceError::UnknownArch {
            arch: manifest.arch.clone(),
        });
    }
    if !valid_commit(&manifest.source_commit) {
        return Err(EvidenceError::BadSourceCommit {
            commit: manifest.source_commit.clone(),
        });
    }
    let arch = manifest.arch.clone();

    // (2) coverage: the manifest must list EXACTLY the required files for this arch.
    let required: BTreeSet<String> = required_files(&arch).into_iter().collect();
    let listed: BTreeSet<String> = manifest.files.iter().map(|f| f.name.clone()).collect();
    if listed.len() != manifest.files.len() {
        return Err(EvidenceError::Parse {
            file: MANIFEST_FILE.into(),
            error: "duplicate file entry in manifest".into(),
        });
    }
    if let Some(missing) = required.difference(&listed).next() {
        return Err(EvidenceError::MissingFile {
            name: missing.clone(),
        });
    }
    if let Some(extra) = listed.difference(&required).next() {
        return Err(EvidenceError::UnmanifestedFile {
            name: extra.clone(),
        });
    }

    // (3) no unmanifested file on disk (besides the manifest itself).
    for e in std::fs::read_dir(dir).map_err(io)? {
        let e = e.map_err(io)?;
        if let Some(name) = e.file_name().to_str() {
            if name == MANIFEST_FILE {
                continue;
            }
            if !listed.contains(name) {
                return Err(EvidenceError::UnmanifestedFile {
                    name: name.to_string(),
                });
            }
        }
    }

    // (4) recompute EVERY listed file's hash + length.
    for f in &manifest.files {
        let bytes = read_file(dir, &f.name)?;
        let recomputed = blake3_hex(&bytes);
        if recomputed != f.blake3_hex || bytes.len() as u64 != f.byte_len {
            return Err(EvidenceError::FileHashMismatch {
                name: f.name.clone(),
                recorded: f.blake3_hex.clone(),
                recomputed,
            });
        }
    }

    // (5) whole-bundle content hash.
    let recomputed_content = content_hash(&arch, &manifest.source_commit, &manifest.files);
    if recomputed_content != manifest.bundle_content_hash {
        return Err(EvidenceError::ContentHashMismatch {
            recorded: manifest.bundle_content_hash.clone(),
            recomputed: recomputed_content,
        });
    }

    // (6) container + native builds (typed) — and the platform/media-type binding.
    let mut builds: Vec<OciBuild> = Vec::new();
    let mut native: Vec<NativeBuild> = Vec::new();
    for c in CANDIDATES {
        let cf = container_file(c);
        let cv: Vec<OciBuild> = parse(&cf, &read_file(dir, &cf)?)?;
        for b in &cv {
            if b.arch != arch {
                return Err(EvidenceError::ArchBinding {
                    file: cf.clone(),
                    got: b.arch.clone(),
                });
            }
            if b.source_commit != manifest.source_commit {
                return Err(EvidenceError::SourceCommitBinding {
                    file: cf.clone(),
                    got: b.source_commit.clone(),
                });
            }
            // Blocker 8: the builder role must carry the parsed platform + media type.
            if b.role == "builder" {
                let plat = b.platform_architecture.as_deref().unwrap_or("");
                if plat != oci_arch(&arch) {
                    return Err(EvidenceError::PlatformBinding {
                        candidate: c.to_string(),
                        detail: format!(
                            "platform_architecture {plat:?} != expected {:?}",
                            oci_arch(&arch)
                        ),
                    });
                }
                if b.media_type.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(EvidenceError::PlatformBinding {
                        candidate: c.to_string(),
                        detail: "media_type is absent".into(),
                    });
                }
                if b.platform_os.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(EvidenceError::PlatformBinding {
                        candidate: c.to_string(),
                        detail: "platform_os is absent".into(),
                    });
                }
            }
        }
        builds.extend(cv);

        let nf = native_file(c);
        let nv: Vec<NativeBuild> = parse(&nf, &read_file(dir, &nf)?)?;
        for n in &nv {
            if n.arch != arch {
                return Err(EvidenceError::ArchBinding {
                    file: nf.clone(),
                    got: n.arch.clone(),
                });
            }
        }
        native.extend(nv);
    }

    // (7) verifier material JSON (SP1 always; RISC Zero x86_64-only).
    let sp1_extractor_json =
        String::from_utf8(read_file(dir, SP1_MATERIAL)?).map_err(|e| EvidenceError::Parse {
            file: SP1_MATERIAL.into(),
            error: e.to_string(),
        })?;
    let risc0_extractor_json = if arch == arch_bundle::ARCH_X86_64 {
        Some(
            String::from_utf8(read_file(dir, RISC0_MATERIAL)?).map_err(|e| {
                EvidenceError::Parse {
                    file: RISC0_MATERIAL.into(),
                    error: e.to_string(),
                }
            })?,
        )
    } else {
        None
    };

    // (8) reuse the tested container/native/material import (coverage,
    //     reproducibility, RISC-Zero-only-on-x86_64).
    let per_arch = PerArchBundle {
        arch: arch.clone(),
        builds: builds.clone(),
        native: native.clone(),
        sp1_extractor_json: sp1_extractor_json.clone(),
        risc0_extractor_json: risc0_extractor_json.clone(),
    };
    arch_bundle::import_verify(&per_arch).map_err(EvidenceError::ArchBundle)?;

    // (9) lock provenance — BOTH candidates, recomputed from exported bytes + bound.
    // Retain the verified lock bytes so cross-arch aggregation emits the lock from the
    // typed bundle (item 6), never a later `cp` from the mutable directory.
    let mut lock_bindings: Vec<LockBinding> = Vec::new();
    let mut verified_locks: Vec<(String, Vec<u8>)> = Vec::new();
    for c in CANDIDATES {
        let pf = lock_prov_file(c);
        let prov: LockProvenance = parse(&pf, &read_file(dir, &pf)?)?;
        let lock_bytes = read_file(dir, &lock_file(c))?;
        let binding = verify_in_container_provenance(&prov, &lock_bytes).map_err(|e| {
            EvidenceError::Lock {
                candidate: c.to_string(),
                error: e.to_string(),
            }
        })?;
        if binding.arch != arch {
            return Err(EvidenceError::ArchBinding {
                file: pf.clone(),
                got: binding.arch.clone(),
            });
        }
        if binding.source_commit != manifest.source_commit {
            return Err(EvidenceError::SourceCommitBinding {
                file: pf.clone(),
                got: binding.source_commit.clone(),
            });
        }
        let expected = builder_digest_for(&builds, c).ok_or(EvidenceError::CandidateCoverage {
            kind: "builder-container",
            candidate: c.to_string(),
        })?;
        if binding.container_digest != expected {
            return Err(EvidenceError::ContainerBinding {
                file: pf.clone(),
                got: binding.container_digest.clone(),
                expected,
            });
        }
        lock_bindings.push(binding);
        verified_locks.push((c.to_string(), lock_bytes));
    }

    // (10) Stage-2 audit — BOTH candidates, non-fatal + required crates + bound.
    let mut stage2_reports: Vec<Stage2AuditRecord> = Vec::new();
    for c in CANDIDATES {
        let sf = stage2_file(c);
        let rec: Stage2AuditRecord = parse(&sf, &read_file(dir, &sf)?)?;
        rec.validate().map_err(|e| EvidenceError::Stage2 {
            candidate: c.to_string(),
            error: e.to_string(),
        })?;
        if rec.candidate != c {
            return Err(EvidenceError::Stage2 {
                candidate: c.to_string(),
                error: format!("record candidate {:?} != {c}", rec.candidate),
            });
        }
        if rec.arch != arch {
            return Err(EvidenceError::ArchBinding {
                file: sf.clone(),
                got: rec.arch.clone(),
            });
        }
        if rec.source_commit != manifest.source_commit {
            return Err(EvidenceError::SourceCommitBinding {
                file: sf.clone(),
                got: rec.source_commit.clone(),
            });
        }
        let expected = builder_digest_for(&builds, c).unwrap_or_default();
        if rec.container_digest != expected {
            return Err(EvidenceError::ContainerBinding {
                file: sf.clone(),
                got: rec.container_digest.clone(),
                expected,
            });
        }
        // bind the audit to the resolved lock hash for this candidate.
        let lock_hash = lock_bindings
            .iter()
            .find(|b| b.candidate == c)
            .map(|b| b.lock_blake3_hex.clone())
            .unwrap_or_default();
        if rec.lock_blake3_hex != lock_hash {
            return Err(EvidenceError::Stage2 {
                candidate: c.to_string(),
                error: format!(
                    "lock_blake3_hex {} is not the resolved candidate lock hash {lock_hash}",
                    rec.lock_blake3_hex
                ),
            });
        }
        stage2_reports.push(rec);
    }

    // (11) tool bindings — BOTH candidates, verified + bound.
    let mut tool_bindings: Vec<ToolBindingRecord> = Vec::new();
    for c in CANDIDATES {
        let tf = tool_binding_file(c);
        let recs: Vec<ToolBindingRecord> = parse(&tf, &read_file(dir, &tf)?)?;
        if recs.is_empty() {
            return Err(EvidenceError::CandidateCoverage {
                kind: "tool-binding",
                candidate: c.to_string(),
            });
        }
        let expected = builder_digest_for(&builds, c).unwrap_or_default();
        for rec in &recs {
            rec.validate(InstallMode::Authoritative)
                .map_err(|e| EvidenceError::Tool {
                    candidate: c.to_string(),
                    error: e.to_string(),
                })?;
            if rec.candidate != c {
                return Err(EvidenceError::Tool {
                    candidate: c.to_string(),
                    error: format!("record candidate {:?} != {c}", rec.candidate),
                });
            }
            if rec.container_digest != expected {
                return Err(EvidenceError::ContainerBinding {
                    file: tf.clone(),
                    got: rec.container_digest.clone(),
                    expected: expected.clone(),
                });
            }
            if rec.source_commit != manifest.source_commit {
                return Err(EvidenceError::SourceCommitBinding {
                    file: tf.clone(),
                    got: rec.source_commit.clone(),
                });
            }
        }
        tool_bindings.extend(recs);
    }

    // (12) Stage-5 results — SP1 (both arches) + RISC Zero (x86_64 only), bound.
    let mut stage5_results: Vec<Stage5Result> = Vec::new();
    let mut stage5_candidates = vec!["Sp1"];
    if arch == arch_bundle::ARCH_X86_64 {
        stage5_candidates.push("Risc0");
    }
    for c in stage5_candidates {
        let s5f = stage5_file(c);
        let res: Stage5Result = parse(&s5f, &read_file(dir, &s5f)?)?;
        res.validate().map_err(|e| EvidenceError::Stage5 {
            candidate: c.to_string(),
            error: e.to_string(),
        })?;
        if res.candidate != c {
            return Err(EvidenceError::Stage5 {
                candidate: c.to_string(),
                error: format!("record candidate {:?} != {c}", res.candidate),
            });
        }
        if res.arch != arch {
            return Err(EvidenceError::ArchBinding {
                file: s5f.clone(),
                got: res.arch.clone(),
            });
        }
        if res.source_commit != manifest.source_commit {
            return Err(EvidenceError::SourceCommitBinding {
                file: s5f.clone(),
                got: res.source_commit.clone(),
            });
        }
        let expected = builder_digest_for(&builds, c).unwrap_or_default();
        if res.container_digest != expected {
            return Err(EvidenceError::ContainerBinding {
                file: s5f.clone(),
                got: res.container_digest.clone(),
                expected,
            });
        }
        // Stage-5 must be bound to a VERIFIED tool binding for this candidate.
        let bound = tool_bindings
            .iter()
            .any(|t| t.candidate == c && t.installed_binary_sha256_hex == res.tool_identity_hex);
        if !bound {
            return Err(EvidenceError::Stage5ToolUnbound {
                candidate: c.to_string(),
            });
        }
        stage5_results.push(res);
    }

    Ok(ImportedArchBundle {
        arch,
        source_commit: manifest.source_commit,
        builds,
        native,
        sp1_extractor_json,
        risc0_extractor_json,
        lock_bindings,
        tool_bindings,
        stage2_reports,
        stage5_results,
        verified_locks,
        content_hash: manifest.bundle_content_hash,
    })
}

/// The full set of Stage-6 inputs produced by cross-arch aggregation from TYPED
/// bundles: the arch-level aggregate PLUS the candidate-scoped verified lock bytes and
/// the authoritative tool identities derived from the verified binding records (item
/// 6). Every field is sourced from an import-verified typed object, never a directory
/// copy, so the orchestrator no longer needs any `cp`.
pub struct AggregatedStage6Inputs {
    pub venue: AggregatedVenueInputs,
    /// (candidate, verified lock bytes) — canonical from the x86_64 bundle.
    pub locks: Vec<(String, Vec<u8>)>,
    /// `{"tool_identities":[...]}` built from the verified tool-binding records.
    pub tool_identities_json: String,
}

/// Cross-architecture aggregation from TYPED, already-imported bundles ONLY. It never
/// re-reads a directory, so a file swapped after import cannot change the result.
/// Requires exactly {x86_64, aarch64}, sources RISC Zero material + the candidate-
/// scoped locks/tool-identities from x86_64 (VENUE.md §2), and cross-checks SP1
/// material — reusing the tested aggregator.
pub fn aggregate_imported(
    bundles: &[ImportedArchBundle],
) -> Result<AggregatedStage6Inputs, ArchBundleError> {
    let per_arch: Vec<PerArchBundle> = bundles.iter().map(|b| b.to_per_arch_bundle()).collect();
    let venue = arch_bundle::aggregate(&per_arch)?;
    // Candidate-scoped values come from the x86_64 bundle (the canonical verifier-
    // material venue). arch_bundle::aggregate already enforced that exactly {x86_64,
    // aarch64} are present, so this find() always succeeds.
    let x86 = bundles
        .iter()
        .find(|b| b.arch == arch_bundle::ARCH_X86_64)
        .ok_or_else(|| ArchBundleError::Coverage("no x86_64 bundle after aggregate".into()))?;
    let tool_identities_json = tool_identities_json_from(&x86.tool_bindings);
    Ok(AggregatedStage6Inputs {
        venue,
        locks: x86.verified_locks.clone(),
        tool_identities_json,
    })
}

/// Build the authoritative `tool-identities.json` body from VERIFIED tool-binding
/// records (item 6) — the `ToolVersion` shape `stage6-assemble` consumes, derived
/// from the binding record rather than the raw declaration file.
fn tool_identities_json_from(bindings: &[ToolBindingRecord]) -> String {
    // Emit the per-candidate Stage-6 tool-identity shape
    // ({candidate, rust_version, proof_tools}) that stage6-assemble consumes, grouping
    // the import-verified tool bindings by candidate in first-appearance order.
    // `proof_tools` is sourced ENTIRELY from the verified binding records. `rust_version`
    // is the FROZEN protocol toolchain constant every candidate must build with (Stage-1
    // re-enforces `rust_version == CANDIDATE_CONTAINER_RUST`); the actual toolchain is
    // pinned by the sealed builder-image digest, not by this declared string.
    let mut order: Vec<&str> = Vec::new();
    let mut by_cand: BTreeMap<&str, Vec<serde_json::Value>> = BTreeMap::new();
    for b in bindings {
        if !order.contains(&b.candidate.as_str()) {
            order.push(b.candidate.as_str());
        }
        by_cand
            .entry(b.candidate.as_str())
            .or_default()
            .push(serde_json::json!({
                "name": b.name,
                "version": b.version,
                "artifact_identity": b.artifact_identity,
                "checksum_algorithm": b.checksum_algorithm,
                "checksum_hex": b.declared_checksum_hex,
                "install_entrypoint": b.install_entrypoint,
            }));
    }
    let identities: Vec<serde_json::Value> = order
        .iter()
        .map(|c| {
            serde_json::json!({
                "candidate": c,
                "rust_version": crate::protocol::CANDIDATE_CONTAINER_RUST,
                "proof_tools": by_cand.get(c).cloned().unwrap_or_default(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({ "tool_identities": identities }))
        .unwrap_or_else(|_| "{\"tool_identities\":[]}".to_string())
}

/// TEST_ONLY dry-run scaffold: write a COMPLETE, internally-consistent per-arch
/// evidence bundle directory — the exact `required_files()` shapes, cross-referenced
/// (same builder digest / source commit / lock hash across every record) so
/// `import_verify` accepts it — using the frozen synthetic venue outputs. Every value
/// is synthetic (`test_only_venue_outputs`, fixed COMMIT); a bundle built this way is
/// TEST_ONLY and can never finalize. This is the SAME construction the bundle tests
/// build and verify, exposed so the dry-run producer path reuses it instead of
/// re-deriving the cross-references in fragile shell.
pub fn write_test_only_bundle_dir(dir: &Path, arch: &str) -> Result<(), String> {
    if arch != arch_bundle::ARCH_X86_64 && arch != arch_bundle::ARCH_AARCH64 {
        return Err(format!("arch must be X86_64|Aarch64, got {arch:?}"));
    }
    let commit = "abcdef0123456789abcdef0123456789abcdef01"; // 40-hex, not all-zero
    let bh = |label: &str| crate::venue::to_hex(blake3::hash(label.as_bytes()).as_bytes());
    let oci = |label: &str| format!("sha256:{}", bh(label));
    let oci_arch = if arch == arch_bundle::ARCH_X86_64 {
        "amd64"
    } else {
        "arm64"
    };
    let w = |name: &str, bytes: &[u8]| -> Result<(), String> {
        std::fs::write(dir.join(name), bytes).map_err(|e| format!("write {name}: {e}"))
    };
    let material = crate::schema::stage6::test_only_venue_outputs();
    for c in CANDIDATES {
        let lc = c.to_lowercase();
        let builder = oci(&format!("builder-{lc}-{arch}"));
        let base = oci(&format!("base-{lc}-{arch}"));
        let builds = serde_json::json!([
            {"candidate":c,"role":"base","arch":arch,"build1_digest":base,"build2_digest":base,
             "base_image_ref":format!("registry.test/{lc}/base:pinned"),"base_image_digest":base,
             "builder_oci_ref":format!("oci:local/b0pre-{lc}-{arch}"),"builder_oci_digest":builder,
             "source_commit":commit,"command_log_blake3":bh(&format!("base-cmd-{lc}-{arch}")),
             "raw_output_blake3":bh(&format!("base-out-{lc}-{arch}"))},
            {"candidate":c,"role":"builder","arch":arch,"build1_digest":builder,"build2_digest":builder,
             "base_image_ref":format!("registry.test/{lc}/base:pinned"),"base_image_digest":base,
             "builder_oci_ref":format!("oci:local/b0pre-{lc}-{arch}"),"builder_oci_digest":builder,
             "source_commit":commit,"command_log_blake3":bh(&format!("builder-cmd-{lc}-{arch}")),
             "raw_output_blake3":bh(&format!("builder-out-{lc}-{arch}")),
             "platform_architecture":oci_arch,"platform_os":"linux",
             "media_type":"application/vnd.oci.image.manifest.v1+json"},
        ]);
        w(&container_file(c), &serde_json::to_vec(&builds).unwrap())?;
        let native = serde_json::json!([{"candidate":c,"arch":arch,"host_arch":arch}]);
        w(&native_file(c), &serde_json::to_vec(&native).unwrap())?;
        let lock_bytes =
            format!("# {c} in-container Cargo.lock ({arch})\nversion = 3\n").into_bytes();
        w(&lock_file(c), &lock_bytes)?;
        let lock_hash = crate::venue::lock_provenance::recompute_lock_hash(&lock_bytes);
        let prov = serde_json::json!({"candidate":c,"arch":arch,
            "origin":crate::venue::lock_provenance::IN_CONTAINER_ORIGIN,
            "container_digest":builder,"source_commit":commit,
            "command_log_blake3_hex":bh(&format!("lockcmd-{lc}-{arch}")),"lock_blake3_hex":lock_hash});
        w(
            &lock_prov_file(c),
            &serde_json::to_vec_pretty(&prov).unwrap(),
        )?;
        let nodes: Vec<serde_json::Value> = if c == "Sp1" {
            vec![
                serde_json::json!({"name":"sp1","version":"6.3.1","source":"registry","license":"MIT OR Apache-2.0"}),
                serde_json::json!({"name":"p3-field","version":"0.1.0-alpha.1","source":"registry","license":"MIT"}),
            ]
        } else {
            vec![
                serde_json::json!({"name":"risc0-zkvm","version":"3.0.5","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-build","version":"3.0.5","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-groth16","version":"3.0.4","source":"registry","license":"Apache-2.0"}),
                serde_json::json!({"name":"risc0-zkvm-platform","version":"2.2.2","source":"registry","license":"Apache-2.0"}),
            ]
        };
        let stage2 = serde_json::json!({"candidate":c,"arch":arch,"lock_blake3_hex":lock_hash,
            "container_digest":builder,"source_commit":commit,
            "command_log_blake3_hex":bh(&format!("stage2cmd-{lc}-{arch}")),
            "audit_tool_identity":"cargo-metadata 1.0 + cargo-audit 0.21",
            "advisory_db_snapshot":"rustsec-db@2026-07-01",
            "allowed_licenses":["MIT","Apache-2.0","MIT OR Apache-2.0"],"nodes":nodes,"advisories":[]});
        w(
            &stage2_file(c),
            &serde_json::to_vec_pretty(&stage2).unwrap(),
        )?;
        let tools: Vec<(&str, &str)> = if c == "Sp1" {
            vec![("sp1-verifier", "6.3.1")]
        } else {
            vec![("risc0-zkvm", "3.0.5"), ("risc0-groth16", "3.0.4")]
        };
        let mut bindings = Vec::new();
        let mut first_installed = String::new();
        for (i, (name, ver)) in tools.iter().enumerate() {
            let declared = bh(&format!("artifact-{name}-{ver}"));
            let installed = bh(&format!("installed-{name}-{ver}"));
            if i == 0 {
                first_installed = installed.clone();
            }
            bindings.push(serde_json::json!({"candidate":c,"name":name,"version":ver,
                "artifact_identity":format!("https://fixtures.invalid/{name}-{ver}.tar"),
                "checksum_algorithm":"sha256","declared_checksum_hex":declared,
                "verified_artifact_hex":declared,"installed_binary_sha256_hex":installed,
                "install_entrypoint":format!("cargo:{name}@{ver}"),
                "container_digest":builder,"source_commit":commit,"test_only":false}));
        }
        w(
            &tool_binding_file(c),
            &serde_json::to_vec_pretty(&bindings).unwrap(),
        )?;
        if c == "Sp1" || arch == arch_bundle::ARCH_X86_64 {
            let cases: Vec<serde_json::Value> = crate::venue::stage5::REQUIRED_MUTATION_CASES
                .iter()
                .map(|n| serde_json::json!({"name":n,"expected_rejected":true,"actual_rejected":true}))
                .collect();
            let s5 = serde_json::json!({"candidate":c,"arch":arch,
                "fixture_hashes":[{"label":"terminal-proof","blake3_hex":bh(&format!("fx-{lc}-{arch}")),"byte_len":512}],
                "verifier_identity":format!("pinned-{lc}-verifier@1"),"mutation_cases":cases,
                "tool_identity_hex":first_installed,"container_digest":builder,"source_commit":commit,
                "command_log_blake3_hex":bh(&format!("stage5cmd-{lc}-{arch}")),
                "overall_pass":true});
            w(&stage5_file(c), &serde_json::to_vec_pretty(&s5).unwrap())?;
        }
    }
    w(SP1_MATERIAL, material.sp1_extractor_json.as_bytes())?;
    if arch == arch_bundle::ARCH_X86_64 {
        w(RISC0_MATERIAL, material.risc0_extractor_json.as_bytes())?;
    }
    Ok(())
}

/// The directory `import_verify` would read (helper for the CLI).
pub fn bundle_dir(dir: &str) -> PathBuf {
    PathBuf::from(dir)
}

#[cfg(test)]
mod tests {
    include!("evidence_bundle_tests.rs");
}

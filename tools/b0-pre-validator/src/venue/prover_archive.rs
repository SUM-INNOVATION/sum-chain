//! Item 8: prover-toolchain ARCHIVE-MEMBER identity schema + consumer.
//!
//! RISC Zero / SP1 prover subcommands and the r0vm server are delivered by EXTRACTING named
//! members from pinned release ARCHIVES — never by an opaque `curl | tar` install entrypoint
//! and never via `rzup` (production never invokes it). This module models each delivered
//! executable as an archive MEMBER with a full verified identity, so the consumer can require
//! — and FAIL CLOSED on the absence of — every binding fact.
//!
//! The archives already cover: `cargo-prove` (x86_64 + aarch64), `cargo-risczero` (x86_64),
//! `r0vm` (x86_64). `cargo-risczero` and `r0vm` are modelled as TWO executable identities that
//! SHARE ONE archive. Cargo subcommands are delivered on an ISOLATED verified PATH directory
//! (so `cargo <sub>` resolves ONLY the extracted, hash-verified binary); `r0vm` is delivered
//! by the EXACT verified `RISC0_SERVER_PATH` (never discovered on PATH).
//!
//! The member SHA-256, the native `--version` output, and the point-of-use SHA-256 are
//! VENUE-only values (resolved on the native x86 venue, deliberately unresolved here). This
//! schema makes each of them a MANDATORY field and refuses a record that is missing any of
//! them; it NEVER inserts a placeholder or infers a value. Records are deliberately NOT bound
//! to a source commit — final source ratification waits for the merge SHA — and stay
//! UNRATIFIED until the native venue resolves the values and a reviewer accepts them.

use super::{is_hex64, is_synthetic};

/// Assembly mode, mirroring [`super::tool_install::InstallMode`]: the authoritative venue path
/// forbids synthetic metadata; the TEST_ONLY simulation requires it (so it can never
/// masquerade as real).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveMode {
    Authoritative,
    TestOnly,
}

/// How an extracted executable is delivered to its point of use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    /// Cargo subcommand (`cargo-prove`, `cargo-risczero`): placed on an ISOLATED verified PATH
    /// directory so `cargo <sub>` resolves ONLY the extracted, hash-verified binary.
    IsolatedPath,
    /// `r0vm`: delivered by the EXACT verified `RISC0_SERVER_PATH` pointing at the extracted
    /// binary (never discovered on PATH).
    Risc0ServerPath,
}

/// One executable delivered from a member of a pinned prover archive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMemberExecutable {
    /// The executable name as invoked (`cargo-prove`, `cargo-risczero`, `r0vm`).
    pub executable_name: String,
    /// The member path WITHIN the archive that is extracted for this executable.
    pub archive_member: String,
    /// SHA-256 (bare 64-hex) of the extracted member bytes. VENUE-resolved; MANDATORY.
    pub member_sha256: String,
    /// The exact argv used to capture the version (trusted; e.g. `["cargo","prove","--version"]`
    /// or `["r0vm","--version"]`). MANDATORY and non-empty.
    pub version_invocation: Vec<String>,
    /// The exact version output the invocation produced. VENUE-resolved; MANDATORY. It is
    /// ARCH-SPECIFIC and is NOT required to match the other architecture's output (e.g. cargo-prove
    /// embeds a per-build timestamp that differs across arches).
    pub version_output: String,
    /// OPTIONAL expected release identity that MUST appear verbatim in `version_output` — the token
    /// that IS stable across architectures even when the full output differs. For `cargo-prove`
    /// this is the SP1 release's short commit (which the venue further validates as a prefix of the
    /// ratified `vX.Y.Z` tag commit); for a tool whose output literally carries its version this is
    /// that version. When present it is required; a `version_output` not containing it fails closed.
    #[serde(default)]
    pub expected_release_commit: Option<String>,
    /// SHA-256 (bare 64-hex) recomputed at the POINT OF USE (the binary actually invoked).
    /// VENUE-resolved; MANDATORY. Must equal `member_sha256` (extract == use).
    pub point_of_use_sha256: String,
    /// Delivery mechanism (isolated PATH for cargo subcommands; `RISC0_SERVER_PATH` for r0vm).
    pub delivery: Delivery,
    /// Target architecture (`x86_64` | `aarch64`).
    pub arch: String,
}

/// A pinned prover archive + every executable it provides. `cargo-risczero` and `r0vm` share
/// ONE archive (two member executables of the same archive); `cargo-prove` ships in its own.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProverArchive {
    /// Logical archive name (e.g. `risc0-toolchain`, `sp1-prover`).
    pub archive_name: String,
    pub version: String,
    /// Immutable archive identity / download URL.
    pub artifact_identity: String,
    /// `sha256` | `blake3`.
    pub checksum_algorithm: String,
    /// The declared checksum of the WHOLE archive bytes (bare 64-hex).
    pub archive_checksum_hex: String,
    /// Every executable extracted from this archive (>= 1).
    pub members: Vec<ArchiveMemberExecutable>,
    /// Target arch this archive is pinned for (`x86_64` | `aarch64`).
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProverArchiveError {
    /// A MANDATORY field was absent/empty — the venue value is unresolved. Fails closed; no
    /// placeholder is ever inserted.
    Missing(&'static str),
    /// A hex field was not bare 64-hex (e.g. a placeholder like `TBD` or a truncated value).
    BadHash(&'static str),
    /// `checksum_algorithm` is not one we can verify.
    UnsupportedAlgorithm { algo: String },
    /// `arch` is not `x86_64` / `aarch64`.
    BadArch { arch: String },
    /// A member's arch disagreed with its archive's arch.
    MemberArchMismatch {
        member: String,
        member_arch: String,
        archive_arch: String,
    },
    /// point_of_use_sha256 != member_sha256 (the bytes extracted are not the bytes used).
    PointOfUseMismatch { member: String },
    /// The delivery mechanism does not match the executable kind (cargo subcommand must use an
    /// isolated PATH; r0vm must use RISC0_SERVER_PATH).
    WrongDelivery { executable: String },
    /// A RISC Zero executable (cargo-risczero / r0vm) declared a non-x86_64 arch.
    Risc0NotX86 { executable: String, arch: String },
    /// `version_invocation`'s first token does not name the executable it versions.
    VersionInvocationMismatch { executable: String, first: String },
    /// The pinned expected release identity (e.g. cargo-prove's SP1 short commit) did not appear in
    /// the arch-specific version output.
    VersionMissingRelease {
        executable: String,
        expected: String,
    },
    /// Authoritative mode was handed synthetic metadata (fails closed off-venue).
    SyntheticRefused { field: &'static str },
    /// TEST_ONLY mode was handed metadata that is not unmistakably synthetic.
    NotSynthetic { field: &'static str },
    /// The archive provided no member executables.
    NoMembers { archive: String },
    /// Required prover coverage was not met (a named executable/arch is absent).
    MissingCoverage { what: &'static str },
    /// cargo-risczero and r0vm did not share ONE archive (they must be members of the same
    /// archive identity).
    SharedArchiveViolation { detail: &'static str },
}

impl std::fmt::Display for ProverArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProverArchiveError::Missing(field) => write!(
                f,
                "prover archive-member field {field} is absent (unresolved venue value; fails \
                 closed — no placeholder is inserted)"
            ),
            ProverArchiveError::BadHash(field) => {
                write!(f, "prover archive-member {field} is not bare 64-hex")
            }
            ProverArchiveError::UnsupportedAlgorithm { algo } => {
                write!(f, "unsupported checksum algorithm {algo:?}")
            }
            ProverArchiveError::BadArch { arch } => {
                write!(f, "arch must be x86_64|aarch64 (got {arch:?})")
            }
            ProverArchiveError::MemberArchMismatch {
                member,
                member_arch,
                archive_arch,
            } => write!(
                f,
                "member {member:?} arch {member_arch:?} != archive arch {archive_arch:?}"
            ),
            ProverArchiveError::PointOfUseMismatch { member } => write!(
                f,
                "member {member:?}: point_of_use_sha256 != member_sha256 (extracted bytes are \
                 not the bytes used)"
            ),
            ProverArchiveError::WrongDelivery { executable } => write!(
                f,
                "executable {executable:?} has the wrong delivery mechanism (cargo subcommands \
                 use an isolated PATH; r0vm uses RISC0_SERVER_PATH)"
            ),
            ProverArchiveError::Risc0NotX86 { executable, arch } => write!(
                f,
                "RISC Zero executable {executable:?} declares arch {arch:?}; cargo-risczero and \
                 r0vm are native-x86_64-only (VENUE.md §2)"
            ),
            ProverArchiveError::VersionMissingRelease {
                executable,
                expected,
            } => write!(
                f,
                "version output for {executable:?} does not contain the pinned release identity \
                 {expected:?}"
            ),
            ProverArchiveError::VersionInvocationMismatch { executable, first } => write!(
                f,
                "version_invocation for {executable:?} starts with {first:?}, which does not name \
                 the executable"
            ),
            ProverArchiveError::SyntheticRefused { field } => {
                write!(f, "authoritative prover archive refused synthetic {field}")
            }
            ProverArchiveError::NotSynthetic { field } => {
                write!(
                    f,
                    "TEST_ONLY prover archive requires an unmistakably synthetic {field}"
                )
            }
            ProverArchiveError::NoMembers { archive } => {
                write!(
                    f,
                    "prover archive {archive:?} provides no member executables"
                )
            }
            ProverArchiveError::MissingCoverage { what } => {
                write!(f, "required prover coverage not met: {what}")
            }
            ProverArchiveError::SharedArchiveViolation { detail } => {
                write!(f, "cargo-risczero/r0vm shared-archive violation: {detail}")
            }
        }
    }
}

impl std::error::Error for ProverArchiveError {}

fn is_cargo_subcommand(exe: &str) -> bool {
    exe.starts_with("cargo-")
}

fn is_risc0_native_x86_only(exe: &str) -> bool {
    exe == "cargo-risczero" || exe == "r0vm"
}

impl ArchiveMemberExecutable {
    /// Validate one member executable. Every VENUE-resolved field is MANDATORY: an absent
    /// member_sha256 / version_output / point_of_use_sha256 fails closed (never a placeholder).
    fn validate(&self, archive_arch: &str, mode: ArchiveMode) -> Result<(), ProverArchiveError> {
        if self.executable_name.trim().is_empty() {
            return Err(ProverArchiveError::Missing("executable_name"));
        }
        if self.archive_member.trim().is_empty() {
            return Err(ProverArchiveError::Missing("archive_member"));
        }
        // MANDATORY venue value — empty is fail-closed, a non-hex placeholder is BadHash.
        if self.member_sha256.trim().is_empty() {
            return Err(ProverArchiveError::Missing("member_sha256"));
        }
        if !is_hex64(&self.member_sha256) {
            return Err(ProverArchiveError::BadHash("member_sha256"));
        }
        if self.version_invocation.is_empty()
            || self.version_invocation.iter().all(|t| t.trim().is_empty())
        {
            return Err(ProverArchiveError::Missing("version_invocation"));
        }
        // The invocation must actually name this executable (cargo subcommand -> "cargo";
        // r0vm -> "r0vm"). A cargo subcommand cargo-<sub> is invoked as `cargo <sub>`.
        let first = self.version_invocation[0].trim();
        let names_exe = if is_cargo_subcommand(&self.executable_name) {
            first == "cargo" || first == self.executable_name
        } else {
            first == self.executable_name
        };
        if !names_exe {
            return Err(ProverArchiveError::VersionInvocationMismatch {
                executable: self.executable_name.clone(),
                first: first.to_string(),
            });
        }
        // MANDATORY venue value.
        if self.version_output.trim().is_empty() {
            return Err(ProverArchiveError::Missing("version_output"));
        }
        // If an expected release identity is pinned, the (arch-specific) version output MUST carry
        // it verbatim — the stable cross-arch anchor even when the full output differs by timestamp.
        if let Some(rel) = &self.expected_release_commit {
            if rel.trim().is_empty() {
                return Err(ProverArchiveError::Missing("expected_release_commit"));
            }
            if !self.version_output.contains(rel.trim()) {
                return Err(ProverArchiveError::VersionMissingRelease {
                    executable: self.executable_name.clone(),
                    expected: rel.trim().to_string(),
                });
            }
        }
        // MANDATORY venue value — empty fails closed, non-hex is BadHash.
        if self.point_of_use_sha256.trim().is_empty() {
            return Err(ProverArchiveError::Missing("point_of_use_sha256"));
        }
        if !is_hex64(&self.point_of_use_sha256) {
            return Err(ProverArchiveError::BadHash("point_of_use_sha256"));
        }
        // Extract == use: the point-of-use hash must equal the extracted member hash.
        if self.point_of_use_sha256 != self.member_sha256 {
            return Err(ProverArchiveError::PointOfUseMismatch {
                member: self.executable_name.clone(),
            });
        }
        // Arch consistency + RISC Zero x86-only policy.
        match self.arch.as_str() {
            "x86_64" | "aarch64" => {}
            other => {
                return Err(ProverArchiveError::BadArch {
                    arch: other.to_string(),
                })
            }
        }
        if self.arch != archive_arch {
            return Err(ProverArchiveError::MemberArchMismatch {
                member: self.executable_name.clone(),
                member_arch: self.arch.clone(),
                archive_arch: archive_arch.to_string(),
            });
        }
        if is_risc0_native_x86_only(&self.executable_name) && self.arch != "x86_64" {
            return Err(ProverArchiveError::Risc0NotX86 {
                executable: self.executable_name.clone(),
                arch: self.arch.clone(),
            });
        }
        // Delivery must match the executable kind: cargo subcommands are resolved on an
        // isolated PATH; r0vm is delivered by RISC0_SERVER_PATH (never on PATH).
        let delivery_ok = match self.delivery {
            Delivery::IsolatedPath => is_cargo_subcommand(&self.executable_name),
            Delivery::Risc0ServerPath => self.executable_name == "r0vm",
        };
        if !delivery_ok {
            return Err(ProverArchiveError::WrongDelivery {
                executable: self.executable_name.clone(),
            });
        }
        // Synthecity policy (authoritative refuses synthetic; TEST_ONLY requires it).
        let synthetic = is_synthetic(&self.archive_member) || is_synthetic(&self.version_output);
        match mode {
            ArchiveMode::Authoritative => {
                if synthetic {
                    return Err(ProverArchiveError::SyntheticRefused { field: "member" });
                }
            }
            ArchiveMode::TestOnly => {
                if !synthetic {
                    return Err(ProverArchiveError::NotSynthetic { field: "member" });
                }
            }
        }
        Ok(())
    }
}

impl ProverArchive {
    /// Validate the archive + every member it provides. Fails closed on any absent MANDATORY
    /// venue value; never infers or substitutes a placeholder.
    pub fn validate(&self, mode: ArchiveMode) -> Result<(), ProverArchiveError> {
        if self.archive_name.trim().is_empty() {
            return Err(ProverArchiveError::Missing("archive_name"));
        }
        if self.version.trim().is_empty() {
            return Err(ProverArchiveError::Missing("version"));
        }
        if self.artifact_identity.trim().is_empty() {
            return Err(ProverArchiveError::Missing("artifact_identity"));
        }
        match self.checksum_algorithm.as_str() {
            "sha256" | "blake3" => {}
            other => {
                return Err(ProverArchiveError::UnsupportedAlgorithm {
                    algo: other.to_string(),
                })
            }
        }
        if self.archive_checksum_hex.trim().is_empty() {
            return Err(ProverArchiveError::Missing("archive_checksum_hex"));
        }
        if !is_hex64(&self.archive_checksum_hex) {
            return Err(ProverArchiveError::BadHash("archive_checksum_hex"));
        }
        match self.arch.as_str() {
            "x86_64" | "aarch64" => {}
            other => {
                return Err(ProverArchiveError::BadArch {
                    arch: other.to_string(),
                })
            }
        }
        // Authoritative refuses a synthetic archive identity; TEST_ONLY requires it.
        let synthetic = is_synthetic(&self.artifact_identity);
        match mode {
            ArchiveMode::Authoritative => {
                if synthetic {
                    return Err(ProverArchiveError::SyntheticRefused {
                        field: "artifact_identity",
                    });
                }
            }
            ArchiveMode::TestOnly => {
                if !synthetic {
                    return Err(ProverArchiveError::NotSynthetic {
                        field: "artifact_identity",
                    });
                }
            }
        }
        if self.members.is_empty() {
            return Err(ProverArchiveError::NoMembers {
                archive: self.archive_name.clone(),
            });
        }
        for m in &self.members {
            m.validate(&self.arch, mode)?;
        }
        Ok(())
    }
}

/// Consumer: validate a full set of prover archives AND the required coverage. The archives
/// must provide, at minimum: `cargo-prove` on x86_64 AND aarch64; `cargo-risczero` on x86_64;
/// `r0vm` on x86_64. `cargo-risczero` and `r0vm` MUST be members of ONE shared archive (same
/// archive_name + artifact_identity + version). Any absent value fails closed; nothing is
/// inferred. Records validated here remain UNRATIFIED (not bound to a source commit).
pub fn validate_prover_archive_set(
    archives: &[ProverArchive],
    mode: ArchiveMode,
) -> Result<(), ProverArchiveError> {
    for a in archives {
        a.validate(mode)?;
    }
    // Coverage: locate each required (executable, arch).
    let has = |exe: &str, arch: &str| {
        archives.iter().any(|a| {
            a.members
                .iter()
                .any(|m| m.executable_name == exe && m.arch == arch)
        })
    };
    if !has("cargo-prove", "x86_64") {
        return Err(ProverArchiveError::MissingCoverage {
            what: "cargo-prove x86_64",
        });
    }
    if !has("cargo-prove", "aarch64") {
        return Err(ProverArchiveError::MissingCoverage {
            what: "cargo-prove aarch64",
        });
    }
    if !has("cargo-risczero", "x86_64") {
        return Err(ProverArchiveError::MissingCoverage {
            what: "cargo-risczero x86_64",
        });
    }
    if !has("r0vm", "x86_64") {
        return Err(ProverArchiveError::MissingCoverage {
            what: "r0vm x86_64",
        });
    }
    // cargo-risczero and r0vm must be members of the SAME archive identity.
    let owner_of = |exe: &str| -> Option<(&str, &str, &str)> {
        archives.iter().find_map(|a| {
            if a.members
                .iter()
                .any(|m| m.executable_name == exe && m.arch == "x86_64")
            {
                Some((
                    a.archive_name.as_str(),
                    a.artifact_identity.as_str(),
                    a.version.as_str(),
                ))
            } else {
                None
            }
        })
    };
    match (owner_of("cargo-risczero"), owner_of("r0vm")) {
        (Some(rz), Some(rv)) if rz == rv => {}
        (Some(_), Some(_)) => {
            return Err(ProverArchiveError::SharedArchiveViolation {
                detail: "cargo-risczero and r0vm are provided by different archives",
            })
        }
        _ => {
            return Err(ProverArchiveError::SharedArchiveViolation {
                detail: "cargo-risczero or r0vm archive not found",
            })
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::venue::sha256;

    const SENT: &str = super::super::TEST_ONLY_SENTINEL;

    fn h(s: &str) -> String {
        sha256::hex_digest(s.as_bytes())
    }

    /// A well-formed TEST_ONLY member (synthetic member path + version output; real-shaped
    /// hashes). `poh` overrides the point-of-use hash (defaults to the member hash).
    fn member(
        exe: &str,
        arch: &str,
        delivery: Delivery,
        invocation: &[&str],
        member_hash: &str,
    ) -> ArchiveMemberExecutable {
        ArchiveMemberExecutable {
            executable_name: exe.into(),
            archive_member: format!("{SENT}/bin/{exe}"),
            member_sha256: member_hash.into(),
            version_invocation: invocation.iter().map(|s| s.to_string()).collect(),
            version_output: format!("{SENT} {exe} 3.0.5"),
            expected_release_commit: None,
            point_of_use_sha256: member_hash.into(),
            delivery,
            arch: arch.into(),
        }
    }

    fn risc0_archive() -> ProverArchive {
        // cargo-risczero + r0vm SHARE this one archive (x86_64).
        ProverArchive {
            archive_name: "risc0-toolchain".into(),
            version: "3.0.5".into(),
            artifact_identity: format!("{SENT}://risc0-toolchain-3.0.5-x86_64.tar"),
            checksum_algorithm: "sha256".into(),
            archive_checksum_hex: h("risc0-archive"),
            members: vec![
                member(
                    "cargo-risczero",
                    "x86_64",
                    Delivery::IsolatedPath,
                    &["cargo", "risczero", "--version"],
                    &h("cargo-risczero-bin"),
                ),
                member(
                    "r0vm",
                    "x86_64",
                    Delivery::Risc0ServerPath,
                    &["r0vm", "--version"],
                    &h("r0vm-bin"),
                ),
            ],
            arch: "x86_64".into(),
        }
    }

    fn cargo_prove_archive(arch: &str) -> ProverArchive {
        ProverArchive {
            archive_name: format!("sp1-prover-{arch}"),
            version: "6.3.1".into(),
            artifact_identity: format!("{SENT}://sp1-prover-6.3.1-{arch}.tar"),
            checksum_algorithm: "sha256".into(),
            archive_checksum_hex: h(&format!("sp1-archive-{arch}")),
            members: vec![member(
                "cargo-prove",
                arch,
                Delivery::IsolatedPath,
                &["cargo", "prove", "--version"],
                &h(&format!("cargo-prove-bin-{arch}")),
            )],
            arch: arch.into(),
        }
    }

    fn full_set() -> Vec<ProverArchive> {
        vec![
            cargo_prove_archive("x86_64"),
            cargo_prove_archive("aarch64"),
            risc0_archive(),
        ]
    }

    #[test]
    fn well_formed_test_only_set_validates_and_covers() {
        let set = full_set();
        assert_eq!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Ok(())
        );
    }

    #[test]
    fn absent_member_sha256_fails_closed_no_placeholder() {
        let mut set = full_set();
        set[2].members[0].member_sha256 = String::new(); // unresolved venue value
        assert_eq!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::Missing("member_sha256"))
        );
    }

    #[test]
    fn placeholder_member_sha256_is_bad_hash() {
        let mut set = full_set();
        set[2].members[1].member_sha256 = "TBD".into();
        set[2].members[1].point_of_use_sha256 = "TBD".into();
        assert_eq!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::BadHash("member_sha256"))
        );
    }

    #[test]
    fn absent_version_output_fails_closed() {
        let mut set = full_set();
        set[0].members[0].version_output = String::new();
        assert_eq!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::Missing("version_output"))
        );
    }

    #[test]
    fn point_of_use_must_equal_member_hash() {
        let mut set = full_set();
        set[2].members[0].point_of_use_sha256 = h("a-different-binary");
        assert!(matches!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::PointOfUseMismatch { .. })
        ));
    }

    #[test]
    fn r0vm_with_isolated_path_delivery_is_refused() {
        let mut set = full_set();
        set[2].members[1].delivery = Delivery::IsolatedPath; // r0vm must use RISC0_SERVER_PATH
        assert!(matches!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::WrongDelivery { .. })
        ));
    }

    #[test]
    fn cargo_subcommand_with_server_path_delivery_is_refused() {
        let mut set = full_set();
        set[2].members[0].delivery = Delivery::Risc0ServerPath; // cargo-risczero must use PATH
        assert!(matches!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::WrongDelivery { .. })
        ));
    }

    #[test]
    fn risc0_executable_on_aarch64_is_refused() {
        // Build an aarch64 archive carrying r0vm — refused (RISC Zero is x86-only).
        let mut a = risc0_archive();
        a.arch = "aarch64".into();
        a.members[0].arch = "aarch64".into();
        a.members[1].arch = "aarch64".into();
        assert!(matches!(
            a.validate(ArchiveMode::TestOnly),
            Err(ProverArchiveError::Risc0NotX86 { .. })
        ));
    }

    #[test]
    fn missing_cargo_prove_aarch64_coverage_is_refused() {
        let set = vec![cargo_prove_archive("x86_64"), risc0_archive()];
        assert_eq!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::MissingCoverage {
                what: "cargo-prove aarch64"
            })
        );
    }

    #[test]
    fn cargo_risczero_and_r0vm_must_share_one_archive() {
        // Split r0vm into its own archive -> shared-archive violation.
        let mut rz = risc0_archive();
        let r0 = rz.members.remove(1); // pull r0vm out
        let mut r0_archive = ProverArchive {
            archive_name: "r0vm-only".into(),
            version: "3.0.5".into(),
            artifact_identity: format!("{SENT}://r0vm-only-3.0.5-x86_64.tar"),
            checksum_algorithm: "sha256".into(),
            archive_checksum_hex: h("r0vm-only-archive"),
            members: vec![r0],
            arch: "x86_64".into(),
        };
        // keep r0vm's own hashes self-consistent
        r0_archive.members[0].point_of_use_sha256 = r0_archive.members[0].member_sha256.clone();
        let set = vec![
            cargo_prove_archive("x86_64"),
            cargo_prove_archive("aarch64"),
            rz,
            r0_archive,
        ];
        assert!(matches!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::SharedArchiveViolation { .. })
        ));
    }

    #[test]
    fn authoritative_refuses_synthetic_and_test_requires_it() {
        // The TEST_ONLY set carries the synthetic sentinel -> refused on the authoritative path.
        let set = full_set();
        assert!(matches!(
            validate_prover_archive_set(&set, ArchiveMode::Authoritative),
            Err(ProverArchiveError::SyntheticRefused { .. })
        ));
    }

    #[test]
    fn version_invocation_must_name_the_executable() {
        let mut set = full_set();
        set[2].members[1].version_invocation = vec!["not-r0vm".into(), "--version".into()];
        assert!(matches!(
            validate_prover_archive_set(&set, ArchiveMode::TestOnly),
            Err(ProverArchiveError::VersionInvocationMismatch { .. })
        ));
    }

    #[test]
    fn round_trips_through_json() {
        let a = risc0_archive();
        let s = serde_json::to_string(&a).unwrap();
        let back: ProverArchive = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
        // An unknown field is rejected (deny_unknown_fields).
        let bad = s.replace("\"members\"", "\"bogus\":1,\"members\"");
        assert!(serde_json::from_str::<ProverArchive>(&bad).is_err());
    }

    // cargo-prove ships an arch-specific version output whose ONLY stable cross-arch anchor is the
    // SP1 release short commit; the x86 and aarch64 outputs differ by embedded timestamp. Both must
    // validate against the SAME expected_release_commit, and NEITHER is required to equal the other.
    fn cargo_prove_member(arch: &str, output: &str, member_hash: &str) -> ArchiveMemberExecutable {
        ArchiveMemberExecutable {
            executable_name: "cargo-prove".into(),
            archive_member: "cargo-prove".into(),
            member_sha256: member_hash.into(),
            version_invocation: vec!["cargo-prove".into(), "prove".into(), "--version".into()],
            version_output: output.into(),
            expected_release_commit: Some("8252c29".into()), // prefix of the ratified v6.3.1 tag commit
            point_of_use_sha256: member_hash.into(),
            delivery: Delivery::IsolatedPath,
            arch: arch.into(),
        }
    }

    #[test]
    fn cargo_prove_arch_specific_outputs_share_the_release_commit() {
        // The real verified x86 + aarch64 outputs (different timestamps) both validate.
        let x86 = cargo_prove_member(
            "x86_64",
            "cargo-prove sp1 (8252c29 2026-06-25T11:50:01.543258355Z)",
            &"a".repeat(64),
        );
        let arm = cargo_prove_member(
            "aarch64",
            "cargo-prove sp1 (8252c29 2026-06-25T11:49:20.735796629Z)",
            &"b".repeat(64),
        );
        assert_ne!(
            x86.version_output, arm.version_output,
            "outputs differ by timestamp"
        );
        assert_eq!(x86.validate("x86_64", ArchiveMode::Authoritative), Ok(()));
        assert_eq!(arm.validate("aarch64", ArchiveMode::Authoritative), Ok(()));
    }

    #[test]
    fn cargo_prove_output_without_the_release_commit_is_refused() {
        let bad = cargo_prove_member("x86_64", "cargo-prove sp1 (deadbee ...)", &"a".repeat(64));
        assert!(matches!(
            bad.validate("x86_64", ArchiveMode::Authoritative),
            Err(ProverArchiveError::VersionMissingRelease { .. })
        ));
    }
}

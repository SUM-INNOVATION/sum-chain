//! Blocker 3: proof-tool identity — download → verify checksum → install → verify
//! installed binary → bind.
//!
//! A well-formed JSON tool assertion is NOT evidence that the executable bytes are
//! what was preregistered. The authoritative path must, for each proof tool: read
//! the exact declared artifact, verify its declared checksum over the downloaded
//! bytes, install via the declared entrypoint, verify the installed binary, and
//! bind BOTH the verified artifact hash and the installed-binary hash into
//! provenance before any extraction runs on that pinned environment.
//!
//! Off-venue there is no real installer metadata (it is owner-selected `[MISS]`) and
//! no toolchain to install, so the authoritative path fails closed. The two pure
//! cores — checksum verification and installed-binary hash binding — are unit-tested
//! here with clearly-synthetic (`TEST_ONLY_SYNTHETIC`) inputs that can never be
//! mistaken for real metadata.

use super::{is_hex64, is_synthetic, sha256};

/// Assembly mode: the authoritative venue path forbids synthetic metadata; the
/// TEST_ONLY simulation requires it (so it can never masquerade as real).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    Authoritative,
    TestOnly,
}

/// The exact declared artifact for one proof tool (what the owner preregisters).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredArtifact {
    pub name: String,
    pub version: String,
    /// Immutable artifact identity / download URL.
    pub artifact_identity: String,
    /// `sha256` or `blake3`.
    pub checksum_algorithm: String,
    /// The declared checksum of the artifact bytes, lowercase hex.
    pub checksum_hex: String,
    /// The installation command / entrypoint.
    pub install_entrypoint: String,
}

/// The bound, verified tool identity — produced only after the declared checksum is
/// verified over the real bytes AND the installed binary is hashed. This is what
/// enters provenance; a bare version/JSON assertion never does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolBinding {
    pub name: String,
    pub version: String,
    pub artifact_identity: String,
    pub checksum_algorithm: String,
    /// The checksum RE-VERIFIED over the downloaded artifact bytes (equals the
    /// declared value only because it was recomputed and matched).
    pub verified_artifact_hex: String,
    /// SHA-256 of the actually-installed binary bytes.
    pub installed_binary_sha256_hex: String,
    pub install_entrypoint: String,
    /// True when this binding came from the TEST_ONLY simulation (synthetic
    /// metadata). An authoritative binding is always `false`.
    pub test_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    /// The declared checksum algorithm is not one we can verify.
    UnsupportedAlgorithm { algo: String },
    /// The declared checksum hex length disagrees with its algorithm.
    MalformedChecksum { algo: String },
    /// The recomputed checksum over the artifact bytes did not match the declared
    /// one — the downloaded bytes are not the preregistered artifact.
    ChecksumMismatch { declared: String, actual: String },
    /// Authoritative mode was handed synthetic metadata (no real installer evidence
    /// exists off-venue); it fails closed rather than accept a synthetic identity.
    SyntheticMetadataRefused { field: &'static str },
    /// TEST_ONLY mode was handed metadata that is NOT unmistakably synthetic, so it
    /// could be confused with real metadata.
    NotSynthetic { field: &'static str },
    /// The installed binary was empty / could not be hashed.
    EmptyInstalledBinary,
    /// A required field was empty.
    Missing(&'static str),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::UnsupportedAlgorithm { algo } => {
                write!(f, "unsupported checksum algorithm {algo:?}")
            }
            ToolError::MalformedChecksum { algo } => {
                write!(f, "declared checksum hex length is wrong for {algo}")
            }
            ToolError::ChecksumMismatch { declared, actual } => write!(
                f,
                "artifact checksum mismatch: declared {declared} but bytes hash to {actual}"
            ),
            ToolError::SyntheticMetadataRefused { field } => write!(
                f,
                "authoritative install refused synthetic {field}; real venue-selected installer \
                 metadata is required (off-venue this field is [MISS])"
            ),
            ToolError::NotSynthetic { field } => {
                write!(
                    f,
                    "TEST_ONLY install requires an unmistakably synthetic {field}"
                )
            }
            ToolError::EmptyInstalledBinary => write!(f, "installed binary is empty"),
            ToolError::Missing(field) => write!(f, "required tool field {field} is empty"),
        }
    }
}

impl std::error::Error for ToolError {}

/// Verify a declared checksum over the artifact bytes. Recomputes with the declared
/// algorithm (`sha256` via the dependency-free primitive, `blake3` natively) and
/// requires equality. Returns the verified hex on success. This is the real "these
/// bytes ARE the preregistered artifact" check — not a shape assertion.
pub fn verify_declared_checksum(
    declared: &DeclaredArtifact,
    artifact_bytes: &[u8],
) -> Result<String, ToolError> {
    let (want_len, actual) = match declared.checksum_algorithm.as_str() {
        "sha256" => (64usize, sha256::hex_digest(artifact_bytes)),
        "blake3" => (
            64usize,
            super::to_hex(blake3::hash(artifact_bytes).as_bytes()),
        ),
        other => {
            return Err(ToolError::UnsupportedAlgorithm {
                algo: other.to_string(),
            })
        }
    };
    if declared.checksum_hex.len() != want_len || !is_hex64(&declared.checksum_hex) {
        return Err(ToolError::MalformedChecksum {
            algo: declared.checksum_algorithm.clone(),
        });
    }
    if actual != declared.checksum_hex {
        return Err(ToolError::ChecksumMismatch {
            declared: declared.checksum_hex.clone(),
            actual,
        });
    }
    Ok(actual)
}

/// The full download→verify→install→verify→bind decision for one proof tool.
///
/// `artifact_bytes` are the downloaded artifact; `installed_binary_bytes` are the
/// bytes of the binary the declared entrypoint installed. On the authoritative path
/// synthetic metadata is refused (fail-closed off-venue); on the TEST_ONLY path the
/// metadata MUST be unmistakably synthetic. The returned [`ToolBinding`] carries the
/// re-verified artifact hash AND the installed-binary hash — the evidence that
/// gates extraction.
pub fn install_and_bind(
    mode: InstallMode,
    declared: &DeclaredArtifact,
    artifact_bytes: &[u8],
    installed_binary_bytes: &[u8],
) -> Result<ToolBinding, ToolError> {
    if declared.name.trim().is_empty() {
        return Err(ToolError::Missing("name"));
    }
    if declared.version.trim().is_empty() {
        return Err(ToolError::Missing("version"));
    }
    if declared.artifact_identity.trim().is_empty() {
        return Err(ToolError::Missing("artifact_identity"));
    }
    if declared.install_entrypoint.trim().is_empty() {
        return Err(ToolError::Missing("install_entrypoint"));
    }

    let synthetic_identity = is_synthetic(&declared.artifact_identity);
    let synthetic_entrypoint = is_synthetic(&declared.install_entrypoint);
    match mode {
        InstallMode::Authoritative => {
            if synthetic_identity {
                return Err(ToolError::SyntheticMetadataRefused {
                    field: "artifact_identity",
                });
            }
            if synthetic_entrypoint {
                return Err(ToolError::SyntheticMetadataRefused {
                    field: "install_entrypoint",
                });
            }
        }
        InstallMode::TestOnly => {
            if !synthetic_identity {
                return Err(ToolError::NotSynthetic {
                    field: "artifact_identity",
                });
            }
            if !synthetic_entrypoint {
                return Err(ToolError::NotSynthetic {
                    field: "install_entrypoint",
                });
            }
        }
    }

    // Verify the declared checksum over the downloaded bytes.
    let verified_artifact_hex = verify_declared_checksum(declared, artifact_bytes)?;

    // Install (venue) then verify the installed binary by hashing its bytes.
    if installed_binary_bytes.is_empty() {
        return Err(ToolError::EmptyInstalledBinary);
    }
    let installed_binary_sha256_hex = sha256::hex_digest(installed_binary_bytes);

    Ok(ToolBinding {
        name: declared.name.clone(),
        version: declared.version.clone(),
        artifact_identity: declared.artifact_identity.clone(),
        checksum_algorithm: declared.checksum_algorithm.clone(),
        verified_artifact_hex,
        installed_binary_sha256_hex,
        install_entrypoint: declared.install_entrypoint.clone(),
        test_only: matches!(mode, InstallMode::TestOnly),
    })
}

/// Blocker 6: the SERIALIZABLE, candidate-bound tool-binding record — the
/// AUTHORITATIVE tool entry that flows to Stage 6, NOT the owner's raw declaration.
///
/// `tool_identities.sh` used to bind the tools then copy the ORIGINAL owner metadata
/// (a bare version/URL declaration, no verified hashes) into `<Candidate>.tool.json`.
/// That discards the evidence. This record instead carries EVERY verified fact —
/// the declared checksum, the checksum RE-VERIFIED over the downloaded bytes, the
/// installed-binary hash, the entrypoint, and the container/source binding — so the
/// evidence-bundle importer can require and re-check them and reject a missing or
/// mismatched binding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBindingRecord {
    pub candidate: String,
    pub name: String,
    pub version: String,
    pub artifact_identity: String,
    pub checksum_algorithm: String,
    /// The checksum the owner DECLARED for the artifact.
    pub declared_checksum_hex: String,
    /// The checksum RE-VERIFIED over the downloaded artifact bytes; must equal the
    /// declared value (it only does because it was recomputed and matched).
    pub verified_artifact_hex: String,
    /// SHA-256 of the actually-installed binary bytes.
    pub installed_binary_sha256_hex: String,
    pub install_entrypoint: String,
    /// The builder-image `sha256:<64hex>` digest the tool was installed inside.
    pub container_digest: String,
    /// The clean source commit (40/64-hex) the run was bound to.
    pub source_commit: String,
    /// True only for the TEST_ONLY simulation; an authoritative binding is `false`.
    pub test_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    Missing(&'static str),
    UnknownCandidate {
        candidate: String,
    },
    /// A binding hex field was not bare 64-hex.
    BadHash(&'static str),
    /// The verified artifact hash did not equal the declared checksum — the record
    /// asserts a binding it did not actually verify.
    VerifiedDeclaredMismatch {
        declared: String,
        verified: String,
    },
    /// The container digest was not a full sha256:<64hex>.
    BadContainerDigest {
        digest: String,
    },
    /// Authoritative binding carried synthetic metadata (fails closed off-venue).
    SyntheticRefused {
        field: &'static str,
    },
    /// TEST_ONLY binding was not unmistakably synthetic.
    NotSynthetic {
        field: &'static str,
    },
    /// The authoritative/test-only flag disagreed with the metadata's synthecity.
    ModeMismatch,
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::Missing(field) => write!(f, "tool-binding field {field} is empty"),
            BindingError::UnknownCandidate { candidate } => {
                write!(f, "unknown candidate {candidate:?}")
            }
            BindingError::BadHash(field) => write!(f, "tool-binding {field} is not bare 64-hex"),
            BindingError::VerifiedDeclaredMismatch { declared, verified } => write!(
                f,
                "verified artifact hash {verified} != declared checksum {declared}"
            ),
            BindingError::BadContainerDigest { digest } => {
                write!(f, "tool-binding container_digest invalid: {digest:?}")
            }
            BindingError::SyntheticRefused { field } => {
                write!(f, "authoritative tool binding refused synthetic {field}")
            }
            BindingError::NotSynthetic { field } => {
                write!(
                    f,
                    "TEST_ONLY tool binding requires an unmistakably synthetic {field}"
                )
            }
            BindingError::ModeMismatch => write!(
                f,
                "tool-binding test_only flag disagrees with the metadata's synthecity"
            ),
        }
    }
}

impl std::error::Error for BindingError {}

impl ToolBindingRecord {
    /// Build the authoritative binding record from a verified [`ToolBinding`],
    /// stamping in the candidate + container/source binding. Only callable from a
    /// binding that already passed [`install_and_bind`].
    pub fn from_binding(
        candidate: &str,
        binding: &ToolBinding,
        declared_checksum_hex: &str,
        container_digest: &str,
        source_commit: &str,
    ) -> Self {
        ToolBindingRecord {
            candidate: candidate.to_string(),
            name: binding.name.clone(),
            version: binding.version.clone(),
            artifact_identity: binding.artifact_identity.clone(),
            checksum_algorithm: binding.checksum_algorithm.clone(),
            declared_checksum_hex: declared_checksum_hex.to_string(),
            verified_artifact_hex: binding.verified_artifact_hex.clone(),
            installed_binary_sha256_hex: binding.installed_binary_sha256_hex.clone(),
            install_entrypoint: binding.install_entrypoint.clone(),
            container_digest: container_digest.to_string(),
            source_commit: source_commit.to_string(),
            test_only: binding.test_only,
        }
    }

    /// Re-validate the binding record: the record must carry BOTH the verified
    /// artifact hash and the installed-binary hash, its verified hash must equal the
    /// declared checksum, its container digest must be a full sha256, and (on the
    /// authoritative path) its metadata must not be synthetic. This is what makes
    /// the BINDING — not a bare declaration — the authoritative tool entry.
    pub fn validate(&self, mode: InstallMode) -> Result<(), BindingError> {
        if self.name.trim().is_empty() {
            return Err(BindingError::Missing("name"));
        }
        if self.version.trim().is_empty() {
            return Err(BindingError::Missing("version"));
        }
        if self.artifact_identity.trim().is_empty() {
            return Err(BindingError::Missing("artifact_identity"));
        }
        if self.install_entrypoint.trim().is_empty() {
            return Err(BindingError::Missing("install_entrypoint"));
        }
        if self.candidate != "Sp1" && self.candidate != "Risc0" {
            return Err(BindingError::UnknownCandidate {
                candidate: self.candidate.clone(),
            });
        }
        if !is_hex64(&self.declared_checksum_hex) {
            return Err(BindingError::BadHash("declared_checksum_hex"));
        }
        if !is_hex64(&self.verified_artifact_hex) {
            return Err(BindingError::BadHash("verified_artifact_hex"));
        }
        if !is_hex64(&self.installed_binary_sha256_hex) {
            return Err(BindingError::BadHash("installed_binary_sha256_hex"));
        }
        // The binding's proof: the checksum re-verified over the bytes equals the
        // declared one. If they differ the record never actually verified the bytes.
        if self.verified_artifact_hex != self.declared_checksum_hex {
            return Err(BindingError::VerifiedDeclaredMismatch {
                declared: self.declared_checksum_hex.clone(),
                verified: self.verified_artifact_hex.clone(),
            });
        }
        match self.container_digest.strip_prefix("sha256:") {
            Some(hex) if is_hex64(hex) && !is_synthetic(&self.container_digest) => {}
            _ => {
                return Err(BindingError::BadContainerDigest {
                    digest: self.container_digest.clone(),
                })
            }
        }
        if self.source_commit.trim().is_empty() {
            return Err(BindingError::Missing("source_commit"));
        }
        // Synthecity policy, mirroring install_and_bind.
        let synthetic =
            is_synthetic(&self.artifact_identity) || is_synthetic(&self.install_entrypoint);
        match mode {
            InstallMode::Authoritative => {
                if is_synthetic(&self.artifact_identity) {
                    return Err(BindingError::SyntheticRefused {
                        field: "artifact_identity",
                    });
                }
                if is_synthetic(&self.install_entrypoint) {
                    return Err(BindingError::SyntheticRefused {
                        field: "install_entrypoint",
                    });
                }
                if self.test_only {
                    return Err(BindingError::ModeMismatch);
                }
            }
            InstallMode::TestOnly => {
                if !is_synthetic(&self.artifact_identity) {
                    return Err(BindingError::NotSynthetic {
                        field: "artifact_identity",
                    });
                }
                if !is_synthetic(&self.install_entrypoint) {
                    return Err(BindingError::NotSynthetic {
                        field: "install_entrypoint",
                    });
                }
                if !self.test_only {
                    return Err(BindingError::ModeMismatch);
                }
            }
        }
        // defensive: an authoritative record can never be silently synthetic.
        if matches!(mode, InstallMode::Authoritative) && synthetic {
            return Err(BindingError::SyntheticRefused {
                field: "artifact_identity",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clearly-synthetic declared artifact whose checksum genuinely matches the
    /// (synthetic) artifact bytes, so the checksum-verify path is real while the
    /// metadata can never be mistaken for real venue evidence.
    fn synthetic_declared(name: &str, version: &str, artifact_bytes: &[u8]) -> DeclaredArtifact {
        DeclaredArtifact {
            name: name.into(),
            version: version.into(),
            artifact_identity: format!("{}://{name}-{version}", super::super::TEST_ONLY_SENTINEL),
            checksum_algorithm: "sha256".into(),
            checksum_hex: sha256::hex_digest(artifact_bytes),
            install_entrypoint: format!(
                "{}:cargo:{name}@{version}",
                super::super::TEST_ONLY_SENTINEL
            ),
        }
    }

    #[test]
    fn checksum_verify_matches_and_rejects_tampering() {
        let bytes = b"TEST_ONLY_SYNTHETIC artifact payload";
        let d = synthetic_declared("sp1-verifier", "6.3.1", bytes);
        // correct checksum over the real bytes
        assert_eq!(verify_declared_checksum(&d, bytes).unwrap(), d.checksum_hex);
        // tampered bytes -> mismatch
        assert!(matches!(
            verify_declared_checksum(&d, b"tampered bytes"),
            Err(ToolError::ChecksumMismatch { .. })
        ));
        // blake3 algorithm also verifies
        let mut db = d.clone();
        db.checksum_algorithm = "blake3".into();
        db.checksum_hex = super::super::to_hex(blake3::hash(bytes).as_bytes());
        assert_eq!(
            verify_declared_checksum(&db, bytes).unwrap(),
            db.checksum_hex
        );
        // an unsupported algorithm fails closed
        let mut dm = d.clone();
        dm.checksum_algorithm = "md5".into();
        assert!(matches!(
            verify_declared_checksum(&dm, bytes),
            Err(ToolError::UnsupportedAlgorithm { .. })
        ));
    }

    #[test]
    fn binary_hash_binding_over_synthetic_inputs() {
        let artifact = b"TEST_ONLY_SYNTHETIC sp1-verifier-6.3.1.tar";
        let installed = b"TEST_ONLY_SYNTHETIC installed sp1-verifier binary bytes";
        let d = synthetic_declared("sp1-verifier", "6.3.1", artifact);
        let binding = install_and_bind(InstallMode::TestOnly, &d, artifact, installed).unwrap();
        assert!(binding.test_only);
        assert_eq!(binding.verified_artifact_hex, sha256::hex_digest(artifact));
        assert_eq!(
            binding.installed_binary_sha256_hex,
            sha256::hex_digest(installed)
        );
        // the installed-binary hash is over the INSTALLED bytes, distinct from the
        // downloaded artifact hash.
        assert_ne!(
            binding.installed_binary_sha256_hex,
            binding.verified_artifact_hex
        );
    }

    #[test]
    fn authoritative_mode_fails_closed_on_synthetic_metadata() {
        // Off-venue there is no real installer metadata; the synthetic sentinel is
        // refused on the authoritative path (never accepted as real).
        let artifact = b"payload";
        let d = synthetic_declared("risc0-zkvm", "3.0.5", artifact);
        assert!(matches!(
            install_and_bind(InstallMode::Authoritative, &d, artifact, b"bin"),
            Err(ToolError::SyntheticMetadataRefused {
                field: "artifact_identity"
            })
        ));
    }

    #[test]
    fn test_only_mode_requires_unmistakably_synthetic_metadata() {
        // A real-looking (non-synthetic) identity on the TEST_ONLY path is refused —
        // so a synthetic run can never quietly carry real-looking metadata.
        let artifact = b"payload";
        let mut d = synthetic_declared("sp1-verifier", "6.3.1", artifact);
        d.artifact_identity = "https://example.invalid/sp1-verifier-6.3.1.tar".into();
        assert!(matches!(
            install_and_bind(InstallMode::TestOnly, &d, artifact, b"bin"),
            Err(ToolError::NotSynthetic {
                field: "artifact_identity"
            })
        ));
    }

    #[test]
    fn authoritative_binding_over_nonsynthetic_fixture_binds_both_hashes() {
        // A Rust-test fixture (NOT real installer metadata, never written to the
        // committed artifact): a non-synthetic identity with a correct checksum binds
        // both the verified artifact hash and the installed-binary hash.
        let artifact = b"real-shaped artifact bytes";
        let installed = b"real-shaped installed binary";
        let d = DeclaredArtifact {
            name: "sp1-verifier".into(),
            version: "6.3.1".into(),
            artifact_identity: "https://fixtures.invalid/sp1-verifier-6.3.1.tar".into(),
            checksum_algorithm: "sha256".into(),
            checksum_hex: sha256::hex_digest(artifact),
            install_entrypoint: "cargo:sp1-verifier@6.3.1".into(),
        };
        let binding =
            install_and_bind(InstallMode::Authoritative, &d, artifact, installed).unwrap();
        assert!(!binding.test_only);
        assert_eq!(binding.verified_artifact_hex, sha256::hex_digest(artifact));
        assert_eq!(
            binding.installed_binary_sha256_hex,
            sha256::hex_digest(installed)
        );
    }

    fn real_container_digest(label: &str) -> String {
        format!("sha256:{}", sha256::hex_digest(label.as_bytes()))
    }

    #[test]
    fn authoritative_binding_record_is_the_verified_entry_not_the_declaration() {
        // The binding record carries the VERIFIED hashes (Blocker 6): it re-validates
        // only because verified == declared and both hashes are present + bound.
        let artifact = b"real-shaped artifact bytes";
        let installed = b"real-shaped installed binary";
        let d = DeclaredArtifact {
            name: "sp1-verifier".into(),
            version: "6.3.1".into(),
            artifact_identity: "https://fixtures.invalid/sp1-verifier-6.3.1.tar".into(),
            checksum_algorithm: "sha256".into(),
            checksum_hex: sha256::hex_digest(artifact),
            install_entrypoint: "cargo:sp1-verifier@6.3.1".into(),
        };
        let binding =
            install_and_bind(InstallMode::Authoritative, &d, artifact, installed).unwrap();
        let rec = ToolBindingRecord::from_binding(
            "Sp1",
            &binding,
            &d.checksum_hex,
            &real_container_digest("builder-sp1"),
            &"a".repeat(40),
        );
        assert_eq!(rec.validate(InstallMode::Authoritative), Ok(()));
        assert_eq!(rec.verified_artifact_hex, sha256::hex_digest(artifact));
        assert_eq!(
            rec.installed_binary_sha256_hex,
            sha256::hex_digest(installed)
        );
    }

    #[test]
    fn binding_record_with_mismatched_verified_hash_is_rejected() {
        // A record whose verified hash does not equal the declared checksum asserts a
        // binding it did not actually perform -> refused.
        let artifact = b"payload";
        let installed = b"bin";
        let d = DeclaredArtifact {
            name: "risc0-zkvm".into(),
            version: "3.0.5".into(),
            artifact_identity: "https://fixtures.invalid/risc0-zkvm-3.0.5.tar".into(),
            checksum_algorithm: "sha256".into(),
            checksum_hex: sha256::hex_digest(artifact),
            install_entrypoint: "cargo:risc0-zkvm@3.0.5".into(),
        };
        let binding =
            install_and_bind(InstallMode::Authoritative, &d, artifact, installed).unwrap();
        let mut rec = ToolBindingRecord::from_binding(
            "Risc0",
            &binding,
            &d.checksum_hex,
            &real_container_digest("builder-risc0"),
            &"b".repeat(40),
        );
        // tamper: claim a different declared checksum than what was verified.
        rec.declared_checksum_hex = sha256::hex_digest(b"a-different-artifact");
        assert!(matches!(
            rec.validate(InstallMode::Authoritative),
            Err(BindingError::VerifiedDeclaredMismatch { .. })
        ));
    }

    #[test]
    fn authoritative_binding_record_refuses_synthetic_metadata() {
        let artifact = b"payload";
        let installed = b"bin";
        let d = synthetic_declared("sp1-verifier", "6.3.1", artifact);
        let binding = install_and_bind(InstallMode::TestOnly, &d, artifact, installed).unwrap();
        // A synthetic (test_only) binding presented as authoritative fails closed.
        let rec = ToolBindingRecord::from_binding(
            "Sp1",
            &binding,
            &d.checksum_hex,
            &real_container_digest("builder-sp1"),
            &"c".repeat(40),
        );
        assert!(matches!(
            rec.validate(InstallMode::Authoritative),
            Err(BindingError::SyntheticRefused { .. })
        ));
        // but it is a valid TEST_ONLY binding.
        assert_eq!(rec.validate(InstallMode::TestOnly), Ok(()));
    }
}

//! A focused, STRUCTURAL parser for the `[[package]]` array of a `Cargo.lock`, used by
//! the evidence-bundle importer to prove that a sealed Stage-5 verifier runner lock
//! actually pins the expected terminal-verifier SDK (name + version) from a registry
//! source with a checksum — NOT a text grep for a version string.
//!
//! It is deliberately NOT a general TOML parser: the reference validator carries only
//! `serde`/`serde_json`/`blake3` (a minimal supply-chain surface for a security tool),
//! and a `Cargo.lock` is a canonical, restricted TOML subset that cargo emits. This
//! parser walks the table structure and extracts the scalar string fields
//! name/version/source/checksum per `[[package]]`; array keys (`dependencies = [...]`)
//! and other tables (`[metadata]`, `[[patch...]]`) end package scope. A `[[package]]`
//! missing name or version is malformed and refused.
//!
//! FORMAT ASSUMPTION (validated by the differential tests below): it targets cargo's
//! canonical Cargo.lock **v3/v4** output — double-quoted scalars and INLINE `checksum`
//! fields — which the pinned toolchain (Rust 1.88) emits. Syntax OUTSIDE that assumption
//! FAILS CLOSED, never mis-accepts: an old v1/v2 lock (checksums under a `[metadata]`
//! table) yields `SdkChecksumMissing` rather than an unverified accept, and a
//! `[metadata]` checksum line cannot leak into a package's inline checksum. If a future
//! cargo format ever required parsing beyond this (e.g. non-fail-closed cases), switch to
//! a maintained TOML parser rather than expanding this ad-hoc one.

/// One `[[package]]` entry's identity-relevant scalar fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    /// The `source` field (e.g. `registry+https://...`); absent for path/workspace deps.
    pub source: Option<String>,
    /// The `checksum` field (registry packages carry one in Cargo.lock v3+).
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoLockError {
    NotUtf8,
    /// The lock had no `[[package]]` entries at all.
    NoPackages,
    /// A `[[package]]` block was missing name or version.
    MalformedPackage {
        detail: String,
    },
    SdkPackageMissing {
        name: String,
    },
    SdkPackageDuplicated {
        name: String,
    },
    SdkVersionMismatch {
        name: String,
        want: String,
        got: String,
    },
    /// The SDK package's source is absent or not a registry source (a path/git-injected
    /// verifier SDK cannot pin the published bytes the identity claims).
    SdkSourceInvalid {
        name: String,
        detail: String,
    },
    /// The SDK package (a registry dep) carries no checksum, so its bytes are unpinned.
    SdkChecksumMissing {
        name: String,
    },
}

impl std::fmt::Display for CargoLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CargoLockError::NotUtf8 => write!(f, "Cargo.lock is not valid UTF-8"),
            CargoLockError::NoPackages => write!(f, "Cargo.lock has no [[package]] entries"),
            CargoLockError::MalformedPackage { detail } => {
                write!(f, "malformed [[package]] in Cargo.lock: {detail}")
            }
            CargoLockError::SdkPackageMissing { name } => {
                write!(
                    f,
                    "expected verifier SDK package {name:?} is absent from the runner lock"
                )
            }
            CargoLockError::SdkPackageDuplicated { name } => {
                write!(
                    f,
                    "verifier SDK package {name:?} appears more than once in the runner lock"
                )
            }
            CargoLockError::SdkVersionMismatch { name, want, got } => write!(
                f,
                "verifier SDK package {name:?} is pinned at {got:?}, not the declared {want:?}"
            ),
            CargoLockError::SdkSourceInvalid { name, detail } => {
                write!(f, "verifier SDK package {name:?} source invalid: {detail}")
            }
            CargoLockError::SdkChecksumMissing { name } => write!(
                f,
                "verifier SDK package {name:?} has no checksum (its registry bytes are unpinned)"
            ),
        }
    }
}

impl std::error::Error for CargoLockError {}

#[derive(Default)]
struct Partial {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
}

/// Extract a `key = "value"` pair whose value is a single quoted scalar. Returns `None`
/// for array values (`deps = [...]`), inline tables, or non-scalar/unterminated lines,
/// so only the identity scalars are consumed.
fn scalar_kv(line: &str) -> Option<(&str, String)> {
    let (k, rest) = line.split_once('=')?;
    let k = k.trim();
    let rest = rest.trim();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some((k, inner[..end].to_string()))
}

/// Parse the `[[package]]` entries of a Cargo.lock structurally.
pub fn parse_packages(bytes: &[u8]) -> Result<Vec<LockPackage>, CargoLockError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CargoLockError::NotUtf8)?;
    let mut pkgs: Vec<LockPackage> = Vec::new();
    let mut cur: Option<Partial> = None;

    fn finalize(cur: Option<Partial>, pkgs: &mut Vec<LockPackage>) -> Result<(), CargoLockError> {
        if let Some(p) = cur {
            let name = p.name.ok_or(CargoLockError::MalformedPackage {
                detail: "a [[package]] has no name".into(),
            })?;
            let version = p.version.ok_or_else(|| CargoLockError::MalformedPackage {
                detail: format!("package {name:?} has no version"),
            })?;
            pkgs.push(LockPackage {
                name,
                version,
                source: p.source,
                checksum: p.checksum,
            });
        }
        Ok(())
    }

    for raw in text.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            finalize(cur.take(), &mut pkgs)?;
            cur = Some(Partial::default());
            continue;
        }
        // Any other table header ([metadata], [[patch...]], [root]) ends package scope.
        if line.starts_with('[') {
            finalize(cur.take(), &mut pkgs)?;
            cur = None;
            continue;
        }
        if let Some(p) = cur.as_mut() {
            if let Some((k, v)) = scalar_kv(line) {
                match k {
                    "name" => p.name = Some(v),
                    "version" => p.version = Some(v),
                    "source" => p.source = Some(v),
                    "checksum" => p.checksum = Some(v),
                    _ => {}
                }
            }
        }
    }
    finalize(cur.take(), &mut pkgs)?;

    if pkgs.is_empty() {
        return Err(CargoLockError::NoPackages);
    }
    Ok(pkgs)
}

/// Require the expected verifier SDK package to appear EXACTLY once at the declared
/// version, from a registry source, with a checksum. Returns the matched package.
pub fn require_sdk_package<'a>(
    pkgs: &'a [LockPackage],
    name: &str,
    version: &str,
) -> Result<&'a LockPackage, CargoLockError> {
    let mut matches = pkgs.iter().filter(|p| p.name == name);
    let first = matches.next().ok_or(CargoLockError::SdkPackageMissing {
        name: name.to_string(),
    })?;
    if matches.next().is_some() {
        return Err(CargoLockError::SdkPackageDuplicated {
            name: name.to_string(),
        });
    }
    if first.version != version {
        return Err(CargoLockError::SdkVersionMismatch {
            name: name.to_string(),
            want: version.to_string(),
            got: first.version.clone(),
        });
    }
    // A published SDK must come from a registry source (registry+/sparse+); a path or git
    // source cannot pin the published bytes the recorded identity claims.
    match &first.source {
        Some(s) if s.starts_with("registry+") || s.starts_with("sparse+") => {}
        Some(s) => {
            return Err(CargoLockError::SdkSourceInvalid {
                name: name.to_string(),
                detail: format!("non-registry source {s:?}"),
            })
        }
        None => {
            return Err(CargoLockError::SdkSourceInvalid {
                name: name.to_string(),
                detail: "no source (a path/workspace dependency cannot pin published SDK bytes)"
                    .into(),
            })
        }
    }
    // A registry package carries a checksum in Cargo.lock; its absence leaves the bytes
    // unpinned. (This is "validate the checksum where available" — for a registry source
    // it IS available and required.)
    if first
        .checksum
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        return Err(CargoLockError::SdkChecksumMissing {
            name: name.to_string(),
        });
    }
    Ok(first)
}

/// A minimal, structurally-valid synthetic verifier runner `Cargo.lock` that pins
/// exactly one SDK package from a registry source with a synthetic checksum. Used by
/// TEST_ONLY bundle construction (and tests); the caller content-addresses the bytes via
/// `recompute_lock_hash`. Never a substitute for a genuine in-container lock.
pub fn synthetic_runner_lock(sdk_name: &str, sdk_version: &str) -> String {
    format!(
        "# TEST_ONLY synthetic verifier runner lock (not a real in-container resolution)\n\
         version = 3\n\n\
         [[package]]\n\
         name = \"{sdk_name}\"\n\
         version = \"{sdk_version}\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"{}\"\n",
        "0".repeat(64)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "libc"
version = "0.2.155"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "97b3888a4b0f6f0aa89a70b1 e28de6e13a4b5c8"

[[package]]
name = "sp1-verifier"
version = "6.3.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0"
dependencies = [
 "libc",
]

[metadata]
"some" = "thing"
"#;

    #[test]
    fn parses_packages_and_requires_the_sdk() {
        let pkgs = parse_packages(REAL.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 2, "metadata table must not become a package");
        let sdk = require_sdk_package(&pkgs, "sp1-verifier", "6.3.1").unwrap();
        assert_eq!(sdk.version, "6.3.1");
        assert!(sdk.source.as_ref().unwrap().starts_with("registry+"));
        assert!(sdk.checksum.is_some());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let pkgs = parse_packages(REAL.as_bytes()).unwrap();
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.0"),
            Err(CargoLockError::SdkVersionMismatch { .. })
        ));
    }

    #[test]
    fn missing_sdk_is_rejected() {
        let pkgs = parse_packages(REAL.as_bytes()).unwrap();
        assert!(matches!(
            require_sdk_package(&pkgs, "risc0-zkvm", "3.0.5"),
            Err(CargoLockError::SdkPackageMissing { .. })
        ));
    }

    #[test]
    fn path_source_sdk_is_rejected() {
        let lock = "[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.1\"\n";
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.1"),
            Err(CargoLockError::SdkSourceInvalid { .. })
        ));
    }

    #[test]
    fn registry_sdk_without_checksum_is_rejected() {
        let lock = "[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.1"),
            Err(CargoLockError::SdkChecksumMissing { .. })
        ));
    }

    #[test]
    fn duplicated_sdk_is_rejected() {
        let dup = format!("{REAL}\n[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.1\"\nsource = \"registry+x\"\nchecksum = \"ab\"\n");
        let pkgs = parse_packages(dup.as_bytes()).unwrap();
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.1"),
            Err(CargoLockError::SdkPackageDuplicated { .. })
        ));
    }

    #[test]
    fn a_package_without_version_is_malformed() {
        let bad = "[[package]]\nname = \"x\"\n";
        assert!(matches!(
            parse_packages(bad.as_bytes()),
            Err(CargoLockError::MalformedPackage { .. })
        ));
    }

    #[test]
    fn empty_or_packageless_lock_is_rejected() {
        assert!(matches!(
            parse_packages(b"version = 3\n"),
            Err(CargoLockError::NoPackages)
        ));
    }

    // ---- Differential tests against representative real Cargo.lock shapes --------
    // The parser targets cargo's canonical v3/v4 output (inline `checksum`, double-quoted
    // scalars), which the pinned toolchain (1.88) emits. These assert it reads real shapes
    // AND fails CLOSED (never mis-accepts) on shapes outside that assumption.

    #[test]
    fn v4_format_with_reordered_fields_and_comments_parses() {
        // v4 lock; fields deliberately reordered; comments + blank lines interspersed.
        let lock = r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
version = "6.3.1"
name = "sp1-verifier"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "sha2",
 "substrate-bn",
]

[[package]]
name = "sha2"
version = "0.10.8"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        let sdk = require_sdk_package(&pkgs, "sp1-verifier", "6.3.1").unwrap();
        assert_eq!(sdk.version, "6.3.1");
        assert!(sdk.checksum.is_some());
    }

    #[test]
    fn sparse_registry_source_is_accepted() {
        let lock = "[[package]]\nname = \"risc0-zkvm\"\nversion = \"3.0.5\"\nsource = \"sparse+https://index.crates.io/\"\nchecksum = \"cc\"\n";
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        assert!(require_sdk_package(&pkgs, "risc0-zkvm", "3.0.5").is_ok());
    }

    #[test]
    fn git_source_sdk_is_rejected() {
        let lock = "[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.1\"\nsource = \"git+https://github.com/x/y?rev=abc#abc\"\nchecksum = \"dd\"\n";
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.1"),
            Err(CargoLockError::SdkSourceInvalid { .. })
        ));
    }

    #[test]
    fn same_name_two_versions_is_ambiguous_for_the_sdk() {
        // A legitimately duplicated crate name at two versions: for the pinned SDK this is
        // ambiguous and must be refused (we cannot tell which bytes verified).
        let lock = "[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.1\"\nsource = \"registry+x\"\nchecksum = \"a\"\n\n[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.0\"\nsource = \"registry+x\"\nchecksum = \"b\"\n";
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.1"),
            Err(CargoLockError::SdkPackageDuplicated { .. })
        ));
    }

    #[test]
    fn v2_metadata_checksum_format_fails_closed_not_accepted() {
        // Old (v1/v2) Cargo.lock put checksums in a [metadata] table, NOT inline. The
        // pinned toolchain never emits this, but if one appears the parser must FAIL
        // CLOSED (no inline checksum -> SdkChecksumMissing), never silently accept it.
        let lock = r#"[[package]]
name = "sp1-verifier"
version = "6.3.1"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
"checksum sp1-verifier 6.3.1 (registry+https://github.com/rust-lang/crates.io-index)" = "eeeeeeee"
"#;
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        // The [metadata] table is not a package; the SDK has no INLINE checksum -> refused.
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.1"),
            Err(CargoLockError::SdkChecksumMissing { .. }),
        ));
    }

    #[test]
    fn a_metadata_checksum_line_does_not_leak_into_a_package() {
        // Ensure the metadata `"checksum ..." = "..."` line (whose key contains the word
        // checksum) can never be misattributed as a package's checksum field: it lives
        // under [metadata], where package scope is closed.
        let lock = r#"[[package]]
name = "sp1-verifier"
version = "6.3.1"
source = "registry+x"

[metadata]
"checksum sp1-verifier 6.3.1 (registry+x)" = "ffff"
"#;
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        let sdk = pkgs.iter().find(|p| p.name == "sp1-verifier").unwrap();
        assert!(
            sdk.checksum.is_none(),
            "a [metadata] checksum entry must NOT populate the package's inline checksum"
        );
    }

    #[test]
    fn empty_checksum_value_is_treated_as_missing() {
        let lock = "[[package]]\nname = \"sp1-verifier\"\nversion = \"6.3.1\"\nsource = \"registry+x\"\nchecksum = \"\"\n";
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        assert!(matches!(
            require_sdk_package(&pkgs, "sp1-verifier", "6.3.1"),
            Err(CargoLockError::SdkChecksumMissing { .. })
        ));
    }

    #[test]
    fn crlf_line_endings_parse() {
        let lock = "[[package]]\r\nname = \"sp1-verifier\"\r\nversion = \"6.3.1\"\r\nsource = \"registry+x\"\r\nchecksum = \"aa\"\r\n";
        let pkgs = parse_packages(lock.as_bytes()).unwrap();
        assert!(require_sdk_package(&pkgs, "sp1-verifier", "6.3.1").is_ok());
    }
}

//! Canonical RETAINED verification artifacts for the committed-source-of-truth lock.
//!
//! The provenance carries three artifact identities (`locked_command_log_blake3_hex`,
//! `vendor_inputs_blake3_hex`, `materialized_closure_blake3_hex`). A hex-shape-only check let a
//! well-formed FALSE value pass, because the verifier never received the bound artifacts. This
//! module defines the three canonical artifacts, their domain-separated identities recomputed FROM
//! the artifact BYTES, and the structural + semantic validation each must satisfy. The verifier is
//! given the artifact bytes and RECOMPUTES each identity, so a caller-supplied hash without its
//! corresponding bytes is impossible to accept.
//!
//! * **Locked command log** — the exact `cargo … --locked` argv / working context / candidate /
//!   target / immutable builder identity / exit status the venue executed to MATERIALIZE the
//!   committed lock. It PROVES `--locked` was used and NO authoritative `cargo generate-lockfile`
//!   ran. It is structured data (argv arrays), never serialized shell source or operator prose.
//! * **Vendor-input inventory** — for every vendored file required by the graph: package
//!   name/version/source/checksum, relative path, size, and content sha256, in a canonical strictly
//!   increasing order with no duplicates. Authenticates the vendor tree without retaining it.
//! * **Materialized closure** — the sealed target-closure record ([`super::third_party_notices::
//!   TargetClosure`]), lock-bound (`lock_blake3_hex` == the committed lock's domain-separated hash).

use super::third_party_notices::TargetClosure;
use super::{is_hex64, to_hex};
use crate::hashing::prefixed;
use crate::tags::{LOCK_CMDLOG_TAG, MAT_CLOSURE_TAG, VENDOR_INV_TAG};

pub const COMMAND_LOG_SCHEMA: &str = "b0-final-locked-command-log/v1";
pub const VENDOR_INVENTORY_SCHEMA: &str = "b0-final-vendor-input-inventory/v1";

/// The registry source every vendored crate in the candidate graphs resolves from. A vendored
/// entry MUST carry a registry source + a 64-hex registry checksum (the graphs contain no git deps).
pub const REGISTRY_SOURCE_PREFIX: &str = "registry+";

/// Domain-separated identity of the locked-command-log artifact, recomputed from its exact bytes.
pub fn recompute_command_log_hash(bytes: &[u8]) -> String {
    to_hex(&prefixed(&LOCK_CMDLOG_TAG, bytes))
}
/// Domain-separated identity of the vendor-input-inventory artifact, recomputed from its exact bytes.
pub fn recompute_vendor_inventory_hash(bytes: &[u8]) -> String {
    to_hex(&prefixed(&VENDOR_INV_TAG, bytes))
}
/// Domain-separated identity of the materialized target-closure artifact, recomputed from its bytes.
pub fn recompute_materialized_closure_hash(bytes: &[u8]) -> String {
    to_hex(&prefixed(&MAT_CLOSURE_TAG, bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandLog {
    pub schema: String,
    pub candidate: String,
    pub arch: String,
    pub builder_container_digest: String,
    pub commands: Vec<CommandEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEntry {
    /// "vendor" | "metadata".
    pub op: String,
    /// The EXACT executed argv (argv[0] == "cargo"); the command authority, not a shell string.
    pub argv: Vec<String>,
    /// The in-container working directory the command ran in.
    pub cwd: String,
    /// The build target for a metadata command; empty for vendor.
    pub target: String,
    /// The process exit status (must be 0).
    pub exit_status: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorInventory {
    pub schema: String,
    pub candidate: String,
    pub arch: String,
    pub entries: Vec<VendorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorEntry {
    pub name: String,
    pub version: String,
    pub source: String,
    /// The package's registry checksum (64-hex); binds the file to the locked package.
    pub checksum: String,
    /// Path of the vendored file relative to the vendor root.
    pub path: String,
    pub size: u64,
    /// SHA-256 (64-hex) of the vendored file's exact bytes.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// The artifact bytes did not parse as the expected canonical JSON schema.
    Malformed { which: &'static str, detail: String },
    /// The artifact's declared schema string is wrong.
    WrongSchema { which: &'static str, got: String },
    /// candidate/arch inside the artifact disagrees with the provenance (swapped run/candidate).
    Binding {
        which: &'static str,
        field: &'static str,
        got: String,
        expected: String,
    },
    /// The recomputed domain-separated hash != the provenance-recorded hash.
    HashMismatch {
        which: &'static str,
        recorded: String,
        recomputed: String,
    },
    /// A command used no `--locked`, injected `generate-lockfile`, exited nonzero, or is malformed.
    Command { detail: String },
    /// A vendor entry field is malformed, out of canonical order, or duplicated.
    Vendor { detail: String },
    /// The materialized closure is not bound to the committed lock.
    ClosureLockBinding { got: String, expected: String },
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactError::Malformed { which, detail } => {
                write!(f, "{which} artifact malformed: {detail}")
            }
            ArtifactError::WrongSchema { which, got } => {
                write!(f, "{which} artifact schema {got:?} is not the expected schema")
            }
            ArtifactError::Binding {
                which,
                field,
                got,
                expected,
            } => write!(
                f,
                "{which} artifact {field} {got:?} != provenance {expected:?} (swapped candidate/run)"
            ),
            ArtifactError::HashMismatch {
                which,
                recorded,
                recomputed,
            } => write!(
                f,
                "{which} artifact hash recorded {recorded} != recomputed-from-bytes {recomputed}"
            ),
            ArtifactError::Command { detail } => write!(f, "locked-command-log invalid: {detail}"),
            ArtifactError::Vendor { detail } => write!(f, "vendor-input inventory invalid: {detail}"),
            ArtifactError::ClosureLockBinding { got, expected } => write!(
                f,
                "materialized closure lock_blake3_hex {got} != committed lock {expected}"
            ),
        }
    }
}

impl std::error::Error for ArtifactError {}

/// Recompute the command-log identity from `bytes`, require it equals `recorded_hash`, and validate
/// the log structurally + semantically: right schema, bound to (candidate, arch, container_digest),
/// nonempty, every command a `cargo … --locked` (vendor|metadata) that exited 0 and is NOT a
/// `generate-lockfile`, and at least one vendor + one metadata command.
pub fn verify_command_log(
    bytes: &[u8],
    recorded_hash: &str,
    candidate: &str,
    arch: &str,
    container_digest: &str,
) -> Result<(), ArtifactError> {
    let recomputed = recompute_command_log_hash(bytes);
    if recomputed != recorded_hash {
        return Err(ArtifactError::HashMismatch {
            which: "command-log",
            recorded: recorded_hash.to_string(),
            recomputed,
        });
    }
    let log: CommandLog = serde_json::from_slice(bytes).map_err(|e| ArtifactError::Malformed {
        which: "command-log",
        detail: e.to_string(),
    })?;
    if log.schema != COMMAND_LOG_SCHEMA {
        return Err(ArtifactError::WrongSchema {
            which: "command-log",
            got: log.schema,
        });
    }
    check_binding("command-log", "candidate", &log.candidate, candidate)?;
    check_binding("command-log", "arch", &log.arch, arch)?;
    check_binding(
        "command-log",
        "builder_container_digest",
        &log.builder_container_digest,
        container_digest,
    )?;
    if log.commands.is_empty() {
        return Err(ArtifactError::Command {
            detail: "no commands recorded".into(),
        });
    }
    let mut saw_vendor = false;
    let mut saw_metadata = false;
    for c in &log.commands {
        if c.exit_status != 0 {
            return Err(ArtifactError::Command {
                detail: format!(
                    "nonzero exit status {} for argv {:?}",
                    c.exit_status, c.argv
                ),
            });
        }
        if c.cwd.trim().is_empty() {
            return Err(ArtifactError::Command {
                detail: format!("empty cwd for argv {:?}", c.argv),
            });
        }
        if c.argv.first().map(String::as_str) != Some("cargo") {
            return Err(ArtifactError::Command {
                detail: format!("argv[0] is not cargo: {:?}", c.argv),
            });
        }
        if c.argv.iter().any(|a| a == "generate-lockfile") {
            return Err(ArtifactError::Command {
                detail: format!("forbidden generate-lockfile in argv {:?}", c.argv),
            });
        }
        if !c.argv.iter().any(|a| a == "--locked") {
            return Err(ArtifactError::Command {
                detail: format!("command is not --locked: {:?}", c.argv),
            });
        }
        match c.op.as_str() {
            "vendor" => {
                if c.argv.get(1).map(String::as_str) != Some("vendor") {
                    return Err(ArtifactError::Command {
                        detail: format!("op=vendor but argv[1] != vendor: {:?}", c.argv),
                    });
                }
                saw_vendor = true;
            }
            "metadata" => {
                if c.argv.get(1).map(String::as_str) != Some("metadata") {
                    return Err(ArtifactError::Command {
                        detail: format!("op=metadata but argv[1] != metadata: {:?}", c.argv),
                    });
                }
                if c.target.trim().is_empty() {
                    return Err(ArtifactError::Command {
                        detail: "metadata command has empty target".into(),
                    });
                }
                saw_metadata = true;
            }
            other => {
                return Err(ArtifactError::Command {
                    detail: format!("unknown op {other:?}"),
                });
            }
        }
    }
    if !saw_vendor || !saw_metadata {
        return Err(ArtifactError::Command {
            detail: "must contain at least one vendor and one metadata command".into(),
        });
    }
    Ok(())
}

/// Recompute the vendor-inventory identity from `bytes`, require it equals `recorded_hash`, and
/// validate structure: right schema, bound to (candidate, arch), every entry well-formed (registry
/// source + 64-hex checksum + 64-hex sha256 + nonempty path), and STRICTLY canonical order by
/// (name, version, source, path) with NO duplicate key (so a reordered/duplicated inventory is
/// refused even if its recorded hash were updated). An empty inventory (empty graph) is permitted.
pub fn verify_vendor_inventory(
    bytes: &[u8],
    recorded_hash: &str,
    candidate: &str,
    arch: &str,
) -> Result<(), ArtifactError> {
    let recomputed = recompute_vendor_inventory_hash(bytes);
    if recomputed != recorded_hash {
        return Err(ArtifactError::HashMismatch {
            which: "vendor-inventory",
            recorded: recorded_hash.to_string(),
            recomputed,
        });
    }
    let inv: VendorInventory =
        serde_json::from_slice(bytes).map_err(|e| ArtifactError::Malformed {
            which: "vendor-inventory",
            detail: e.to_string(),
        })?;
    if inv.schema != VENDOR_INVENTORY_SCHEMA {
        return Err(ArtifactError::WrongSchema {
            which: "vendor-inventory",
            got: inv.schema,
        });
    }
    check_binding("vendor-inventory", "candidate", &inv.candidate, candidate)?;
    check_binding("vendor-inventory", "arch", &inv.arch, arch)?;
    let mut prev: Option<(&str, &str, &str, &str)> = None;
    for e in &inv.entries {
        if e.name.trim().is_empty() || e.version.trim().is_empty() || e.path.trim().is_empty() {
            return Err(ArtifactError::Vendor {
                detail: format!("empty name/version/path in entry {:?}", e.path),
            });
        }
        if !e.source.starts_with(REGISTRY_SOURCE_PREFIX) {
            return Err(ArtifactError::Vendor {
                detail: format!("non-registry source {:?} for {}", e.source, e.name),
            });
        }
        if !is_hex64(&e.checksum) {
            return Err(ArtifactError::Vendor {
                detail: format!("checksum not 64-hex for {} {}", e.name, e.version),
            });
        }
        if !is_hex64(&e.sha256) {
            return Err(ArtifactError::Vendor {
                detail: format!("file sha256 not 64-hex for {}", e.path),
            });
        }
        let key = (
            e.name.as_str(),
            e.version.as_str(),
            e.source.as_str(),
            e.path.as_str(),
        );
        if let Some(p) = prev {
            if key <= p {
                return Err(ArtifactError::Vendor {
                    detail: format!(
                        "entries not strictly canonical-ordered / duplicated at {:?}",
                        e.path
                    ),
                });
            }
        }
        prev = Some(key);
    }
    Ok(())
}

/// Recompute the materialized-closure identity from `bytes`, require it equals `recorded_hash`, and
/// validate it parses, is bound to (candidate, arch), and is LOCK-BOUND: its `lock_blake3_hex`
/// equals the committed lock's domain-separated hash.
pub fn verify_materialized_closure(
    bytes: &[u8],
    recorded_hash: &str,
    candidate: &str,
    arch: &str,
    committed_lock_blake3_hex: &str,
) -> Result<(), ArtifactError> {
    let recomputed = recompute_materialized_closure_hash(bytes);
    if recomputed != recorded_hash {
        return Err(ArtifactError::HashMismatch {
            which: "materialized-closure",
            recorded: recorded_hash.to_string(),
            recomputed,
        });
    }
    let closure: TargetClosure =
        serde_json::from_slice(bytes).map_err(|e| ArtifactError::Malformed {
            which: "materialized-closure",
            detail: e.to_string(),
        })?;
    check_binding(
        "materialized-closure",
        "candidate",
        &closure.candidate,
        candidate,
    )?;
    check_binding("materialized-closure", "arch", &closure.arch, arch)?;
    if closure.lock_blake3_hex != committed_lock_blake3_hex {
        return Err(ArtifactError::ClosureLockBinding {
            got: closure.lock_blake3_hex,
            expected: committed_lock_blake3_hex.to_string(),
        });
    }
    Ok(())
}

fn check_binding(
    which: &'static str,
    field: &'static str,
    got: &str,
    expected: &str,
) -> Result<(), ArtifactError> {
    if got != expected {
        return Err(ArtifactError::Binding {
            which,
            field,
            got: got.to_string(),
            expected: expected.to_string(),
        });
    }
    Ok(())
}

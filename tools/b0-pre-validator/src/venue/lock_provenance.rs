//! Blocker 2: candidate `Cargo.lock` provenance — generated-in-container only.
//!
//! An authoritative candidate lock is the full transitive source of truth resolved
//! by `cargo generate-lockfile` INSIDE the pinned builder image. A lock that
//! originated on the host (a developer's checkout, a path injected via
//! `SP1_CONTAINER_LOCK` / `RISC0_CONTAINER_LOCK` that points at a host file) is NOT
//! authoritative and must be rejected — never silently accepted.
//!
//! This module carries the decision the resolver depends on: a lock is accepted
//! only with provenance proving `origin = generated-in-container`, bound to
//! `(candidate, arch, container_digest, source_commit, command_log)`, and only when
//! its recorded BLAKE3 is RECOMPUTED from the EXPORTED bytes (so a stale or swapped
//! lock cannot ride in behind a correct-looking hash). Off-venue the container run
//! can't happen (fails closed); this logic is unit-tested directly.

use super::is_hex64;
use crate::hashing::prefixed;
use crate::tags::CARGO_LOCK_TAG;

/// The ONE accepted lock origin: resolved by `cargo generate-lockfile` inside the
/// pinned builder image and exported out. Anything else is host-originated.
pub const IN_CONTAINER_ORIGIN: &str = "generated-in-container";

/// The recorded provenance the resolver attaches to an exported candidate lock.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockProvenance {
    pub candidate: String,
    pub arch: String,
    /// Must be [`IN_CONTAINER_ORIGIN`]; a host path / injected host origin is refused.
    pub origin: String,
    /// The full `sha256:<64hex>` digest of the builder image the lock was generated
    /// inside — binds the lock to the exact container.
    pub container_digest: String,
    /// The clean source commit resolved against (40- or 64-hex).
    pub source_commit: String,
    /// BLAKE3 (bare 64-hex) of the in-container `cargo generate-lockfile` command log.
    pub command_log_blake3_hex: String,
    /// The CLAIMED domain-separated lock hash. It is never trusted; it is recomputed
    /// from the exported bytes and must match.
    pub lock_blake3_hex: String,
}

/// The accepted, fully-bound lock identity. Only produced after in-container
/// provenance and the recomputed-from-exported-bytes hash both check out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockBinding {
    pub candidate: String,
    pub arch: String,
    pub container_digest: String,
    pub source_commit: String,
    pub command_log_blake3_hex: String,
    /// `BLAKE3(CARGO_LOCK_TAG ‖ exported_bytes)`, recomputed here.
    pub lock_blake3_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// The lock did not come from an in-container resolution (host-originated).
    HostOriginated { origin: String },
    /// The builder container digest is absent / not a full sha256 / synthetic.
    BadContainerDigest { digest: String },
    /// The source commit is not 40/64-hex.
    BadSourceCommit { commit: String },
    /// The command log hash is not 64-hex.
    BadCommandLog,
    /// The recorded lock hash does not equal `BLAKE3(tag ‖ exported bytes)`.
    HashMismatch {
        recorded: String,
        recomputed: String,
    },
    /// A required field was empty.
    Missing(&'static str),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::HostOriginated { origin } => write!(
                f,
                "host-originated lock refused: origin {origin:?} is not {IN_CONTAINER_ORIGIN:?}"
            ),
            LockError::BadContainerDigest { digest } => {
                write!(f, "builder container digest invalid/synthetic: {digest:?}")
            }
            LockError::BadSourceCommit { commit } => write!(f, "source commit invalid: {commit:?}"),
            LockError::BadCommandLog => write!(f, "command-log hash is not 64-hex"),
            LockError::HashMismatch {
                recorded,
                recomputed,
            } => write!(
                f,
                "lock hash recorded {recorded} != recomputed-from-exported-bytes {recomputed}"
            ),
            LockError::Missing(field) => {
                write!(f, "required lock-provenance field {field} is empty")
            }
        }
    }
}

impl std::error::Error for LockError {}

/// The domain-separated lock hash rule, recomputed from the EXPORTED bytes:
/// `BLAKE3(CARGO_LOCK_TAG ‖ bytes)`. Identical to the Stage-6 assembler's rule, so
/// the resolver and the assembler agree on one identity.
pub fn recompute_lock_hash(exported_bytes: &[u8]) -> String {
    super::to_hex(&prefixed(&CARGO_LOCK_TAG, exported_bytes))
}

/// True iff a full, non-synthetic `sha256:<64hex>` builder-image digest.
fn is_real_container_digest(d: &str) -> bool {
    match d.strip_prefix("sha256:") {
        Some(hex) => is_hex64(hex) && !super::is_synthetic(d),
        None => false,
    }
}

/// Accept a candidate lock ONLY when its provenance proves it was generated in the
/// pinned container and its recorded hash equals `BLAKE3(tag ‖ exported bytes)`.
/// Any host-originated lock, missing binding field, or hash that does not match the
/// exported bytes is refused — the resolver never accepts a host lock.
pub fn verify_in_container_provenance(
    prov: &LockProvenance,
    exported_bytes: &[u8],
) -> Result<LockBinding, LockError> {
    if prov.candidate.trim().is_empty() {
        return Err(LockError::Missing("candidate"));
    }
    if prov.arch.trim().is_empty() {
        return Err(LockError::Missing("arch"));
    }
    // (1) Origin must be in-container. A host path / injected host origin is refused
    //     BEFORE any hash is even considered.
    if prov.origin != IN_CONTAINER_ORIGIN {
        return Err(LockError::HostOriginated {
            origin: prov.origin.clone(),
        });
    }
    // (2) Bind to the exact builder container (real, non-synthetic sha256).
    if !is_real_container_digest(&prov.container_digest) {
        return Err(LockError::BadContainerDigest {
            digest: prov.container_digest.clone(),
        });
    }
    // (3) Clean source commit + real command-log hash.
    let commit_ok = (prov.source_commit.len() == 40 || prov.source_commit.len() == 64)
        && prov
            .source_commit
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && !prov.source_commit.bytes().all(|b| b == b'0');
    if !commit_ok {
        return Err(LockError::BadSourceCommit {
            commit: prov.source_commit.clone(),
        });
    }
    if !is_hex64(&prov.command_log_blake3_hex) {
        return Err(LockError::BadCommandLog);
    }
    // (4) Recompute the lock hash FROM THE EXPORTED BYTES — never trust the recorded
    //     value. A swapped / stale lock produces a mismatch here.
    let recomputed = recompute_lock_hash(exported_bytes);
    if recomputed != prov.lock_blake3_hex {
        return Err(LockError::HashMismatch {
            recorded: prov.lock_blake3_hex.clone(),
            recomputed,
        });
    }
    Ok(LockBinding {
        candidate: prov.candidate.clone(),
        arch: prov.arch.clone(),
        container_digest: prov.container_digest.clone(),
        source_commit: prov.source_commit.clone(),
        command_log_blake3_hex: prov.command_log_blake3_hex.clone(),
        lock_blake3_hex: recomputed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_digest(label: &str) -> String {
        format!(
            "sha256:{}",
            super::super::sha256::hex_digest(label.as_bytes())
        )
    }

    fn good_prov(exported: &[u8]) -> LockProvenance {
        LockProvenance {
            candidate: "Sp1".into(),
            arch: "X86_64".into(),
            origin: IN_CONTAINER_ORIGIN.into(),
            container_digest: real_digest("builder-sp1-x86_64"),
            source_commit: "a".repeat(40),
            command_log_blake3_hex: super::super::to_hex(
                blake3::hash(b"cargo generate-lockfile").as_bytes(),
            ),
            lock_blake3_hex: recompute_lock_hash(exported),
        }
    }

    #[test]
    fn accepts_in_container_lock_with_matching_recomputed_hash() {
        let exported = b"# in-container Cargo.lock\nversion = 3\n";
        let binding = verify_in_container_provenance(&good_prov(exported), exported).unwrap();
        assert_eq!(binding.candidate, "Sp1");
        assert_eq!(binding.lock_blake3_hex, recompute_lock_hash(exported));
    }

    #[test]
    fn rejects_host_originated_lock() {
        let exported = b"host lock";
        // an operator tries to pass a host checkout / injected host path as the lock
        let mut prov = good_prov(exported);
        prov.origin = "host-path:/home/dev/candidates/sp1/Cargo.lock".into();
        assert!(matches!(
            verify_in_container_provenance(&prov, exported),
            Err(LockError::HostOriginated { .. })
        ));
        // even the bare "host" origin is refused
        prov.origin = "host".into();
        assert!(matches!(
            verify_in_container_provenance(&prov, exported),
            Err(LockError::HostOriginated { .. })
        ));
    }

    #[test]
    fn rejects_synthetic_or_truncated_container_digest() {
        let exported = b"lock";
        let mut prov = good_prov(exported);
        // a synthetic (sentinel-marked) digest is not a real builder image identity
        prov.container_digest = format!("{}://x", super::super::TEST_ONLY_SENTINEL);
        assert!(matches!(
            verify_in_container_provenance(&prov, exported),
            Err(LockError::BadContainerDigest { .. })
        ));
        // truncated
        prov.container_digest = "sha256:deadbeef".into();
        assert!(matches!(
            verify_in_container_provenance(&prov, exported),
            Err(LockError::BadContainerDigest { .. })
        ));
        // missing algorithm prefix
        prov.container_digest = "a".repeat(64);
        assert!(matches!(
            verify_in_container_provenance(&prov, exported),
            Err(LockError::BadContainerDigest { .. })
        ));
    }

    #[test]
    fn recompute_is_over_exported_bytes_so_a_swap_is_caught() {
        let exported = b"# real exported lock\nversion = 3\n";
        let prov = good_prov(exported); // hash recorded over `exported`
                                        // If the bytes actually exported differ from what the hash was recorded over
                                        // (a stale/swapped lock), the recompute-from-exported-bytes catches it.
        let swapped = b"# a DIFFERENT lock swapped in\nversion = 3\n";
        assert!(matches!(
            verify_in_container_provenance(&prov, swapped),
            Err(LockError::HashMismatch { .. })
        ));
        // and a recorded hash that simply lies also fails
        let mut lying = good_prov(exported);
        lying.lock_blake3_hex = "f".repeat(64);
        assert!(matches!(
            verify_in_container_provenance(&lying, exported),
            Err(LockError::HashMismatch { .. })
        ));
    }

    #[test]
    fn recompute_matches_the_frozen_domain_rule() {
        // the lock hash rule is BLAKE3(CARGO_LOCK_TAG ‖ bytes), the same one the
        // Stage-6 assembler uses.
        let bytes = b"version = 3\n";
        let expected = super::super::to_hex(&prefixed(&CARGO_LOCK_TAG, bytes));
        assert_eq!(recompute_lock_hash(bytes), expected);
    }
}

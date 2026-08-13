//! Candidate `Cargo.lock` provenance — the COMMITTED lock is the source of truth; the
//! in-container generated lock is an independent execution CHECK.
//!
//! The committed `candidates/<cand>/Cargo.lock` is the authoritative source of truth. The
//! authoritative run resolves a FRESH lock with `cargo generate-lockfile` INSIDE the pinned
//! builder image and must find it BYTE-IDENTICAL to the committed lock. A lock is accepted
//! only when: its provenance proves `origin = generated-in-container`, bound to
//! `(candidate, arch, container_digest, source_commit, command_log)`; the recorded
//! GENERATED-lock BLAKE3 is RECOMPUTED from the exported (generated) bytes and matches; the
//! recorded COMMITTED-lock BLAKE3 is RECOMPUTED from the committed bytes and matches; and the
//! two locks are BYTE-IDENTICAL (equal domain-separated BLAKE3). A host-originated lock, a
//! missing binding field, a hash that does not match its bytes, or ANY generated-vs-committed
//! drift is refused — and the committed lock is never rewritten. Off-venue the container run
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
    /// The CLAIMED domain-separated hash of the in-container GENERATED lock. Never
    /// trusted; recomputed from the exported (generated) bytes and must match.
    pub lock_blake3_hex: String,
    /// The CLAIMED domain-separated hash of the COMMITTED source-of-truth lock
    /// (`candidates/<cand>/Cargo.lock`). Never trusted; recomputed from the committed
    /// bytes and must both match AND equal the generated-lock hash (byte-identical).
    pub committed_lock_blake3_hex: String,
}

/// The accepted, fully-bound lock identity. Only produced after in-container provenance,
/// the recomputed-from-exported-bytes generated hash, the recomputed-from-committed-bytes
/// committed hash, and generated==committed byte equality all check out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockBinding {
    pub candidate: String,
    pub arch: String,
    pub container_digest: String,
    pub source_commit: String,
    pub command_log_blake3_hex: String,
    /// `BLAKE3(CARGO_LOCK_TAG ‖ bytes)` — necessarily equal for the generated and the
    /// committed lock (they are byte-identical).
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
    /// A recorded lock hash does not equal `BLAKE3(tag ‖ bytes)` for its bytes.
    HashMismatch {
        which: &'static str,
        recorded: String,
        recomputed: String,
    },
    /// The recorded committed-lock hash is empty / not 64-hex.
    BadCommittedLock,
    /// The generated in-container lock is not byte-identical to the committed
    /// source-of-truth lock (their domain-separated BLAKE3 differ). The committed
    /// lock is authoritative and is never rewritten; any drift refuses.
    CommittedGeneratedMismatch {
        committed: String,
        generated: String,
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
                which,
                recorded,
                recomputed,
            } => write!(
                f,
                "{which} lock hash recorded {recorded} != recomputed-from-bytes {recomputed}"
            ),
            LockError::BadCommittedLock => {
                write!(
                    f,
                    "committed source-of-truth lock hash is empty / not 64-hex"
                )
            }
            LockError::CommittedGeneratedMismatch {
                committed,
                generated,
            } => write!(
                f,
                "generated in-container lock ({generated}) != committed source-of-truth lock \
                 ({committed}); the committed lock is authoritative and is never rewritten"
            ),
            LockError::Missing(field) => {
                write!(f, "required lock-provenance field {field} is empty")
            }
        }
    }
}

impl std::error::Error for LockError {}

/// The domain-separated lock hash rule, recomputed from bytes:
/// `BLAKE3(CARGO_LOCK_TAG ‖ bytes)`. Identical to the Stage-6 assembler's rule, so
/// the resolver and the assembler agree on one identity.
pub fn recompute_lock_hash(bytes: &[u8]) -> String {
    super::to_hex(&prefixed(&CARGO_LOCK_TAG, bytes))
}

/// True iff a full, non-synthetic `sha256:<64hex>` builder-image digest.
fn is_real_container_digest(d: &str) -> bool {
    match d.strip_prefix("sha256:") {
        Some(hex) => is_hex64(hex) && !super::is_synthetic(d),
        None => false,
    }
}

/// Accept a candidate lock ONLY when its provenance proves it was generated in the pinned
/// container, its recorded generated hash equals `BLAKE3(tag ‖ generated_bytes)`, its
/// recorded committed hash equals `BLAKE3(tag ‖ committed_bytes)`, and the generated lock
/// is BYTE-IDENTICAL to the committed source-of-truth lock. Any host origin, missing field,
/// hash that does not match its bytes, or generated-vs-committed drift is refused. The
/// committed lock is authoritative and is never rewritten.
pub fn verify_in_container_provenance(
    prov: &LockProvenance,
    generated_bytes: &[u8],
    committed_bytes: &[u8],
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
    // (4) Recompute the GENERATED lock hash FROM THE EXPORTED BYTES — never trust the
    //     recorded value. A swapped / stale generated lock produces a mismatch here.
    let gen_recomputed = recompute_lock_hash(generated_bytes);
    if gen_recomputed != prov.lock_blake3_hex {
        return Err(LockError::HashMismatch {
            which: "generated",
            recorded: prov.lock_blake3_hex.clone(),
            recomputed: gen_recomputed,
        });
    }
    // (5) The committed source-of-truth hash must be present + recompute from the
    //     committed bytes (never trust the recorded value).
    if !is_hex64(&prov.committed_lock_blake3_hex) {
        return Err(LockError::BadCommittedLock);
    }
    let committed_recomputed = recompute_lock_hash(committed_bytes);
    if committed_recomputed != prov.committed_lock_blake3_hex {
        return Err(LockError::HashMismatch {
            which: "committed",
            recorded: prov.committed_lock_blake3_hex.clone(),
            recomputed: committed_recomputed,
        });
    }
    // (6) The generated lock MUST be byte-identical to the committed source-of-truth.
    //     Equal domain-separated BLAKE3 over the respective bytes ⟺ identical bytes.
    if gen_recomputed != committed_recomputed {
        return Err(LockError::CommittedGeneratedMismatch {
            committed: committed_recomputed,
            generated: gen_recomputed,
        });
    }
    Ok(LockBinding {
        candidate: prov.candidate.clone(),
        arch: prov.arch.clone(),
        container_digest: prov.container_digest.clone(),
        source_commit: prov.source_commit.clone(),
        command_log_blake3_hex: prov.command_log_blake3_hex.clone(),
        lock_blake3_hex: gen_recomputed,
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

    /// Provenance for a run whose committed and generated locks are BYTE-IDENTICAL
    /// (the authoritative, accepted case).
    fn good_prov(bytes: &[u8]) -> LockProvenance {
        LockProvenance {
            candidate: "Sp1".into(),
            arch: "X86_64".into(),
            origin: IN_CONTAINER_ORIGIN.into(),
            container_digest: real_digest("builder-sp1-x86_64"),
            source_commit: "a".repeat(40),
            command_log_blake3_hex: super::super::to_hex(
                blake3::hash(b"cargo generate-lockfile").as_bytes(),
            ),
            lock_blake3_hex: recompute_lock_hash(bytes),
            committed_lock_blake3_hex: recompute_lock_hash(bytes),
        }
    }

    #[test]
    fn accepts_when_generated_is_byte_identical_to_committed() {
        let lock = b"# in-container Cargo.lock\nversion = 3\n";
        let binding = verify_in_container_provenance(&good_prov(lock), lock, lock).unwrap();
        assert_eq!(binding.candidate, "Sp1");
        assert_eq!(binding.lock_blake3_hex, recompute_lock_hash(lock));
    }

    #[test]
    fn rejects_generated_vs_committed_byte_difference() {
        // The committed source-of-truth lock and a DIFFERENT freshly-generated lock.
        let committed = b"# committed source-of-truth\nversion = 3\n";
        let generated = b"# a DIFFERENT generated lock\nversion = 3\n";
        let mut prov = good_prov(committed);
        // provenance honestly records each side's hash, but they differ -> refused
        prov.lock_blake3_hex = recompute_lock_hash(generated);
        prov.committed_lock_blake3_hex = recompute_lock_hash(committed);
        assert!(matches!(
            verify_in_container_provenance(&prov, generated, committed),
            Err(LockError::CommittedGeneratedMismatch { .. })
        ));
    }

    #[test]
    fn rejects_altered_generated_lock() {
        let lock = b"# real lock\nversion = 3\n";
        let prov = good_prov(lock); // hashes recorded over `lock`
        let swapped = b"# a swapped-in generated lock\nversion = 3\n";
        // generated bytes differ from what the generated hash was recorded over
        let e = verify_in_container_provenance(&prov, swapped, lock).unwrap_err();
        assert!(matches!(
            e,
            LockError::HashMismatch {
                which: "generated",
                ..
            }
        ));
    }

    #[test]
    fn rejects_altered_committed_lock() {
        let lock = b"# real lock\nversion = 3\n";
        let prov = good_prov(lock); // committed hash recorded over `lock`
        let altered = b"# the committed lock was altered on disk\nversion = 3\n";
        // committed bytes differ from what the committed hash was recorded over
        let e = verify_in_container_provenance(&prov, lock, altered).unwrap_err();
        assert!(matches!(
            e,
            LockError::HashMismatch {
                which: "committed",
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_committed_hash() {
        let lock = b"version = 3\n";
        let mut prov = good_prov(lock);
        prov.committed_lock_blake3_hex = String::new();
        assert!(matches!(
            verify_in_container_provenance(&prov, lock, lock),
            Err(LockError::BadCommittedLock)
        ));
    }

    #[test]
    fn rejects_host_originated_lock() {
        let lock = b"host lock";
        let mut prov = good_prov(lock);
        prov.origin = "host-path:/home/dev/candidates/sp1/Cargo.lock".into();
        assert!(matches!(
            verify_in_container_provenance(&prov, lock, lock),
            Err(LockError::HostOriginated { .. })
        ));
        prov.origin = "host".into();
        assert!(matches!(
            verify_in_container_provenance(&prov, lock, lock),
            Err(LockError::HostOriginated { .. })
        ));
    }

    #[test]
    fn rejects_synthetic_or_truncated_container_digest() {
        let lock = b"lock";
        let mut prov = good_prov(lock);
        prov.container_digest = format!("{}://x", super::super::TEST_ONLY_SENTINEL);
        assert!(matches!(
            verify_in_container_provenance(&prov, lock, lock),
            Err(LockError::BadContainerDigest { .. })
        ));
        prov.container_digest = "sha256:deadbeef".into();
        assert!(matches!(
            verify_in_container_provenance(&prov, lock, lock),
            Err(LockError::BadContainerDigest { .. })
        ));
        prov.container_digest = "a".repeat(64);
        assert!(matches!(
            verify_in_container_provenance(&prov, lock, lock),
            Err(LockError::BadContainerDigest { .. })
        ));
    }

    #[test]
    fn recompute_is_over_bytes_so_a_lying_recorded_hash_fails() {
        let lock = b"# real exported lock\nversion = 3\n";
        let mut lying = good_prov(lock);
        lying.lock_blake3_hex = "f".repeat(64);
        assert!(matches!(
            verify_in_container_provenance(&lying, lock, lock),
            Err(LockError::HashMismatch {
                which: "generated",
                ..
            })
        ));
    }

    #[test]
    fn recompute_matches_the_frozen_domain_rule() {
        let bytes = b"version = 3\n";
        let expected = super::super::to_hex(&prefixed(&CARGO_LOCK_TAG, bytes));
        assert_eq!(recompute_lock_hash(bytes), expected);
    }
}

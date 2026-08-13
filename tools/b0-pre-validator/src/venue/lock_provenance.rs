//! Candidate `Cargo.lock` provenance — the COMMITTED lock is the dependency-selection AUTHORITY.
//!
//! After a candidate `Cargo.lock` is committed it is the exact, frozen dependency graph. The
//! authoritative venue does NOT re-resolve it: it copies the committed lock into the isolated
//! candidate workspace inside the pinned builder image and MATERIALIZES that exact graph under
//! Cargo LOCKED semantics (`cargo metadata --locked`, `cargo vendor --locked`). It must never run
//! `cargo generate-lockfile`, update the lock, or run any unlocked command that could select a
//! newer semver-compatible release from a moving registry. The committed lock is read-only and is
//! required byte-identical before and after every Cargo operation.
//!
//! A candidate lock is accepted only when its provenance proves: `origin =
//! committed-source-of-truth`, bound to the authenticated builder image + clean source commit; the
//! recorded committed-lock SHA-256 AND domain-separated BLAKE3 both RECOMPUTE from the committed
//! bytes; the POST-run SHA-256 equals the PRE-run SHA-256 (Cargo did not rewrite the authority); and
//! the locked-command log, materialized-closure identity, and vendored-input identity are present.
//! A host-originated lock, a mutated committed lock, a hash that does not match its bytes, or a
//! missing binding field is refused. This is NOT a `cargo generate-lockfile` result compared against
//! a moving registry — any such reselection is a defect, never authoritative provenance.

use super::is_hex64;
use crate::hashing::prefixed;
use crate::tags::CARGO_LOCK_TAG;

/// The ONE accepted candidate-lock origin: the committed source-of-truth lock, materialized under
/// Cargo LOCKED semantics inside the pinned builder image. Anything else (a host lock, or a
/// reselected `cargo generate-lockfile` result) is refused.
pub const COMMITTED_SOURCE_ORIGIN: &str = "committed-source-of-truth";

/// The recorded provenance the resolver attaches to a materialized committed candidate lock.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockProvenance {
    pub candidate: String,
    pub arch: String,
    /// Must be [`COMMITTED_SOURCE_ORIGIN`]. A host origin, or any "generated"/"reselected" origin,
    /// is refused: the committed lock is the authority and is materialized, never re-resolved.
    pub origin: String,
    /// The full `sha256:<64hex>` digest of the builder image the committed lock was materialized
    /// inside — binds the run to the exact authenticated container.
    pub container_digest: String,
    /// The clean source commit resolved against (40- or 64-hex).
    pub source_commit: String,
    /// SHA-256 (bare 64-hex) of the COMMITTED source-of-truth lock, recorded BEFORE any Cargo ran.
    /// Never trusted: recomputed from the committed bytes and must match.
    pub committed_lock_sha256_hex: String,
    /// Domain-separated BLAKE3 (bare 64-hex) of the committed lock (`BLAKE3(CARGO_LOCK_TAG ‖
    /// bytes)`), recorded before Cargo. Never trusted: recomputed from the committed bytes.
    pub committed_lock_blake3_hex: String,
    /// SHA-256 (bare 64-hex) of the lock AFTER every locked Cargo operation. Must equal
    /// `committed_lock_sha256_hex` — proof that no Cargo command rewrote the authority.
    pub post_lock_sha256_hex: String,
    /// BLAKE3 (bare 64-hex) of the exact `cargo … --locked` command log the run executed (the
    /// locked metadata/vendor commands; a run that used an unlocked command is refused upstream).
    pub locked_command_log_blake3_hex: String,
    /// Domain-separated BLAKE3 (bare 64-hex) identity of the MATERIALIZED package set / target
    /// closure produced under `--locked` (nodes = the exact locked package set).
    pub materialized_closure_blake3_hex: String,
    /// Domain-separated BLAKE3 (bare 64-hex) identity of the vendored input tree — the exact
    /// downloaded per-crate checksums, so a substituted / altered vendor tree is caught.
    pub vendor_inputs_blake3_hex: String,
}

/// The accepted, fully-bound candidate-lock identity. Produced only after committed-source origin,
/// the recomputed-from-committed-bytes SHA-256 + BLAKE3, and pre==post byte-equality all check out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockBinding {
    pub candidate: String,
    pub arch: String,
    pub container_digest: String,
    pub source_commit: String,
    pub locked_command_log_blake3_hex: String,
    /// `BLAKE3(CARGO_LOCK_TAG ‖ committed_bytes)` — the committed lock's domain-separated identity,
    /// which downstream (the notice manifest) binds to.
    pub lock_blake3_hex: String,
    pub materialized_closure_blake3_hex: String,
    pub vendor_inputs_blake3_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// The lock was not materialized from the committed source of truth (host origin, or a
    /// reselected `cargo generate-lockfile` result masquerading as authoritative).
    WrongOrigin { origin: String },
    /// The builder container digest is absent / not a full sha256 / synthetic.
    BadContainerDigest { digest: String },
    /// The source commit is not 40/64-hex.
    BadSourceCommit { commit: String },
    /// The locked-command log hash is not 64-hex.
    BadCommandLog,
    /// A recorded hash does not equal the recomputed value for its bytes.
    HashMismatch {
        which: &'static str,
        recorded: String,
        recomputed: String,
    },
    /// The lock was mutated during resolution: the post-run SHA-256 differs from the pre-run
    /// (committed) SHA-256 — Cargo rewrote the authority (e.g. an unlocked command updated it).
    LockMutatedDuringResolution { pre: String, post: String },
    /// The materialized-closure identity is empty / not 64-hex.
    BadClosureIdentity,
    /// The vendored-input identity is empty / not 64-hex.
    BadVendorInputs,
    /// A required field was empty.
    Missing(&'static str),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::WrongOrigin { origin } => write!(
                f,
                "candidate lock origin {origin:?} is not {COMMITTED_SOURCE_ORIGIN:?}: the committed \
                 lock is the selection authority and is materialized under --locked, never reselected"
            ),
            LockError::BadContainerDigest { digest } => {
                write!(f, "builder container digest invalid/synthetic: {digest:?}")
            }
            LockError::BadSourceCommit { commit } => write!(f, "source commit invalid: {commit:?}"),
            LockError::BadCommandLog => write!(f, "locked-command-log hash is not 64-hex"),
            LockError::HashMismatch {
                which,
                recorded,
                recomputed,
            } => write!(
                f,
                "{which} lock hash recorded {recorded} != recomputed-from-bytes {recomputed}"
            ),
            LockError::LockMutatedDuringResolution { pre, post } => write!(
                f,
                "committed lock was MUTATED during resolution: pre-run sha256 {pre} != post-run \
                 sha256 {post} (a Cargo command rewrote the authority; it must be materialized \
                 read-only under --locked)"
            ),
            LockError::BadClosureIdentity => {
                write!(f, "materialized-closure identity is empty / not 64-hex")
            }
            LockError::BadVendorInputs => write!(f, "vendored-input identity is empty / not 64-hex"),
            LockError::Missing(field) => {
                write!(f, "required lock-provenance field {field} is empty")
            }
        }
    }
}

impl std::error::Error for LockError {}

/// The domain-separated lock hash rule, recomputed from bytes: `BLAKE3(CARGO_LOCK_TAG ‖ bytes)`.
/// Identical to the Stage-6 assembler's rule, so the resolver and the assembler agree on one
/// identity.
pub fn recompute_lock_hash(bytes: &[u8]) -> String {
    super::to_hex(&prefixed(&CARGO_LOCK_TAG, bytes))
}

/// Plain SHA-256 (bare lowercase 64-hex) of the given bytes — the lock's content sha256 (matches
/// `sha256sum`), used for the pre/post byte-equality proof recorded by the resolver.
pub fn recompute_lock_sha256(bytes: &[u8]) -> String {
    super::sha256::hex_digest(bytes)
}

/// True iff a full, non-synthetic `sha256:<64hex>` builder-image digest.
fn is_real_container_digest(d: &str) -> bool {
    match d.strip_prefix("sha256:") {
        Some(hex) => is_hex64(hex) && !super::is_synthetic(d),
        None => false,
    }
}

/// Accept a candidate lock ONLY when its provenance proves the COMMITTED source-of-truth lock was
/// materialized in the pinned container under Cargo LOCKED semantics: `origin =
/// committed-source-of-truth`; the recorded committed SHA-256 and domain-separated BLAKE3 both
/// recompute from the committed bytes; the POST-run SHA-256 equals the PRE-run committed SHA-256
/// (Cargo did not rewrite it); and the locked-command / closure / vendor identities are present.
/// A wrong origin, mutated lock, hash-vs-bytes mismatch, or missing field is refused. This never
/// accepts a reselected `cargo generate-lockfile` graph — that is a defect, not authoritative.
pub fn verify_committed_source_lock(
    prov: &LockProvenance,
    committed_bytes: &[u8],
) -> Result<LockBinding, LockError> {
    if prov.candidate.trim().is_empty() {
        return Err(LockError::Missing("candidate"));
    }
    if prov.arch.trim().is_empty() {
        return Err(LockError::Missing("arch"));
    }
    // (1) Origin must be committed-source-of-truth (a host origin or a reselected lock is refused).
    if prov.origin != COMMITTED_SOURCE_ORIGIN {
        return Err(LockError::WrongOrigin {
            origin: prov.origin.clone(),
        });
    }
    // (2) Bind to the exact authenticated builder container (real, non-synthetic sha256).
    if !is_real_container_digest(&prov.container_digest) {
        return Err(LockError::BadContainerDigest {
            digest: prov.container_digest.clone(),
        });
    }
    // (3) Clean source commit + real locked-command-log hash.
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
    if !is_hex64(&prov.locked_command_log_blake3_hex) {
        return Err(LockError::BadCommandLog);
    }
    // (4) Recompute the committed lock's SHA-256 + domain-separated BLAKE3 FROM THE COMMITTED BYTES
    //     — never trust the recorded values.
    let sha_recomputed = recompute_lock_sha256(committed_bytes);
    if !is_hex64(&prov.committed_lock_sha256_hex) {
        return Err(LockError::HashMismatch {
            which: "committed-sha256",
            recorded: prov.committed_lock_sha256_hex.clone(),
            recomputed: sha_recomputed,
        });
    }
    if sha_recomputed != prov.committed_lock_sha256_hex {
        return Err(LockError::HashMismatch {
            which: "committed-sha256",
            recorded: prov.committed_lock_sha256_hex.clone(),
            recomputed: sha_recomputed,
        });
    }
    let b3_recomputed = recompute_lock_hash(committed_bytes);
    if b3_recomputed != prov.committed_lock_blake3_hex {
        return Err(LockError::HashMismatch {
            which: "committed-blake3",
            recorded: prov.committed_lock_blake3_hex.clone(),
            recomputed: b3_recomputed,
        });
    }
    // (5) Pre/post byte-equality: the POST-run sha256 must equal the committed (pre-run) sha256 —
    //     no Cargo command rewrote the authority.
    if !is_hex64(&prov.post_lock_sha256_hex) {
        return Err(LockError::LockMutatedDuringResolution {
            pre: sha_recomputed.clone(),
            post: prov.post_lock_sha256_hex.clone(),
        });
    }
    if prov.post_lock_sha256_hex != sha_recomputed {
        return Err(LockError::LockMutatedDuringResolution {
            pre: sha_recomputed,
            post: prov.post_lock_sha256_hex.clone(),
        });
    }
    // (6) Materialized-closure + vendored-input identities must be present (64-hex).
    if !is_hex64(&prov.materialized_closure_blake3_hex) {
        return Err(LockError::BadClosureIdentity);
    }
    if !is_hex64(&prov.vendor_inputs_blake3_hex) {
        return Err(LockError::BadVendorInputs);
    }
    Ok(LockBinding {
        candidate: prov.candidate.clone(),
        arch: prov.arch.clone(),
        container_digest: prov.container_digest.clone(),
        source_commit: prov.source_commit.clone(),
        locked_command_log_blake3_hex: prov.locked_command_log_blake3_hex.clone(),
        lock_blake3_hex: b3_recomputed,
        materialized_closure_blake3_hex: prov.materialized_closure_blake3_hex.clone(),
        vendor_inputs_blake3_hex: prov.vendor_inputs_blake3_hex.clone(),
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

    /// Provenance for an authoritative run that materialized the committed lock under --locked.
    fn good_prov(bytes: &[u8]) -> LockProvenance {
        LockProvenance {
            candidate: "Risc0".into(),
            arch: "X86_64".into(),
            origin: COMMITTED_SOURCE_ORIGIN.into(),
            container_digest: real_digest("builder-risc0-x86_64"),
            source_commit: "a".repeat(40),
            committed_lock_sha256_hex: recompute_lock_sha256(bytes),
            committed_lock_blake3_hex: recompute_lock_hash(bytes),
            post_lock_sha256_hex: recompute_lock_sha256(bytes),
            locked_command_log_blake3_hex: super::super::to_hex(
                blake3::hash(b"cargo metadata --locked; cargo vendor --locked").as_bytes(),
            ),
            materialized_closure_blake3_hex: super::super::to_hex(
                blake3::hash(b"closure").as_bytes(),
            ),
            vendor_inputs_blake3_hex: super::super::to_hex(blake3::hash(b"vendor").as_bytes()),
        }
    }

    #[test]
    fn accepts_materialized_committed_lock() {
        let lock = b"# committed Cargo.lock\nversion = 3\n";
        let binding = verify_committed_source_lock(&good_prov(lock), lock).unwrap();
        assert_eq!(binding.candidate, "Risc0");
        assert_eq!(binding.lock_blake3_hex, recompute_lock_hash(lock));
    }

    #[test]
    fn rejects_reselected_or_host_origin() {
        let lock = b"version = 3\n";
        for bad in [
            "generated-in-container",
            "host-path:/home/dev/candidates/risc0/Cargo.lock",
            "host",
        ] {
            let mut prov = good_prov(lock);
            prov.origin = bad.into();
            assert!(matches!(
                verify_committed_source_lock(&prov, lock),
                Err(LockError::WrongOrigin { .. })
            ));
        }
    }

    #[test]
    fn rejects_lock_mutated_during_resolution() {
        // The committed lock's post-run sha256 differs from its pre-run sha256 -> Cargo rewrote it.
        let lock = b"# committed\nversion = 3\n";
        let mut prov = good_prov(lock);
        prov.post_lock_sha256_hex = recompute_lock_sha256(b"# mutated\nversion = 3\n");
        assert!(matches!(
            verify_committed_source_lock(&prov, lock),
            Err(LockError::LockMutatedDuringResolution { .. })
        ));
    }

    #[test]
    fn rejects_altered_committed_lock_vs_recorded_hash() {
        let lock = b"# real committed lock\nversion = 3\n";
        let prov = good_prov(lock); // hashes recorded over `lock`
        let altered = b"# the committed lock was altered on disk\nversion = 3\n";
        let e = verify_committed_source_lock(&prov, altered).unwrap_err();
        assert!(matches!(e, LockError::HashMismatch { .. }));
    }

    #[test]
    fn recompute_is_over_bytes_so_a_lying_recorded_hash_fails() {
        let lock = b"# real committed lock\nversion = 3\n";
        let mut lying = good_prov(lock);
        lying.committed_lock_blake3_hex = "f".repeat(64);
        assert!(matches!(
            verify_committed_source_lock(&lying, lock),
            Err(LockError::HashMismatch {
                which: "committed-blake3",
                ..
            })
        ));
    }

    #[test]
    fn rejects_synthetic_or_truncated_container_digest() {
        let lock = b"lock";
        let mut prov = good_prov(lock);
        prov.container_digest = format!("{}://x", super::super::TEST_ONLY_SENTINEL);
        assert!(matches!(
            verify_committed_source_lock(&prov, lock),
            Err(LockError::BadContainerDigest { .. })
        ));
        prov.container_digest = "sha256:deadbeef".into();
        assert!(matches!(
            verify_committed_source_lock(&prov, lock),
            Err(LockError::BadContainerDigest { .. })
        ));
    }

    #[test]
    fn rejects_missing_closure_or_vendor_identity() {
        let lock = b"version = 3\n";
        let mut p1 = good_prov(lock);
        p1.materialized_closure_blake3_hex = String::new();
        assert!(matches!(
            verify_committed_source_lock(&p1, lock),
            Err(LockError::BadClosureIdentity)
        ));
        let mut p2 = good_prov(lock);
        p2.vendor_inputs_blake3_hex = "xyz".into();
        assert!(matches!(
            verify_committed_source_lock(&p2, lock),
            Err(LockError::BadVendorInputs)
        ));
    }

    #[test]
    fn recompute_matches_the_frozen_domain_rule() {
        let bytes = b"version = 3\n";
        let expected = super::super::to_hex(&prefixed(&CARGO_LOCK_TAG, bytes));
        assert_eq!(recompute_lock_hash(bytes), expected);
    }
}

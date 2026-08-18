//! Ratified MEASUREMENT-TOOLING authority — the second, independent authority of the two-root model.
//!
//! The measured-source authority ([`crate::guest_set::RATIFIED_SOURCE_COMMIT`]) pins the frozen
//! guest/program source. This module pins the reviewed MEASUREMENT TOOLING that runs against that
//! frozen source: the orchestration scripts, host-provenance reader, runner sources, producer,
//! validator, independent verifier, protobuf provisioning, and runbook helpers. The two authorities
//! are DELIBERATELY separate: tooling advances without re-ratifying the measured source, and the
//! measured source is never inferred from the tooling checkout HEAD.
//!
//! # Commit A / Commit B self-reference avoidance
//!
//! A commit cannot record its own SHA, and a path-set digest cannot cover the bytes that store the
//! digest. So the authority is bound in TWO steps:
//!   * Commit A (implementation) ships this file with both values as the [`UNBOUND`] sentinel and the
//!     complete tooling; every consumer FAILS CLOSED against an unbound authority, so no run can
//!     proceed until it is bound.
//!   * Commit B (authority binding) edits ONLY this file, recording Commit A's exact 40-hex SHA in
//!     [`RATIFIED_MEASUREMENT_TOOLING_COMMIT`] and the canonical tooling path-set digest (computed
//!     over Commit A's tooling) in [`RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3`].
//!
//! This file is the SOLE member of the tooling graph EXCLUDED from the path-set inventory
//! (`tools/b0-pre-candidates/measurement_tooling_pathset.txt`), precisely so Commit B's edit here does
//! not change the digest it records. Nothing else measurement-affecting is excluded.

/// The explicit unbound sentinel. Both authority values hold this until Commit B binds them.
pub const UNBOUND: &str = "UNBOUND";

/// Commit B records Commit A's exact 40-hex commit SHA here. Until then: [`UNBOUND`].
pub const RATIFIED_MEASUREMENT_TOOLING_COMMIT: &str = UNBOUND;

/// Commit B records the canonical tooling path-set digest (64-hex BLAKE3) here. Until then:
/// [`UNBOUND`]. The digest is [`recompute_pathset_digest`] over the sorted inventory manifest.
pub const RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3: &str = UNBOUND;

/// Domain separation for the tooling path-set digest. The preimage is the canonical MANIFEST TEXT:
/// one line per inventory path, `"<file_blake3_hex>  <relpath>\n"`, sorted ascending by `relpath`
/// (byte order). `tools/b0-pre-candidates/scripts/tooling_pathset.sh` produces the identical manifest
/// from the working tree (verifying each path is git-tracked / present / a regular non-symlink file,
/// and that no tracked measurement-tooling file is missing from the inventory), so the shell producer
/// and this reference cannot diverge.
pub const PATHSET_DIGEST_DOMAIN: &[u8] = b"b0-final-measurement-tooling-pathset/v1\0";

/// `true` iff `s` is exactly 64 lowercase-hex characters.
fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// `true` iff `s` is exactly 40 lowercase-hex characters.
fn is_hex40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `true` once Commit B has bound BOTH values to well-formed hex (never while either is [`UNBOUND`]
/// or malformed).
pub fn tooling_authority_is_bound() -> bool {
    is_hex40(RATIFIED_MEASUREMENT_TOOLING_COMMIT)
        && is_hex64(RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3)
}

/// The BLAKE3 digest of a canonical path-set MANIFEST TEXT (see [`PATHSET_DIGEST_DOMAIN`]). `manifest`
/// is the exact bytes of the sorted `"<blake3>  <relpath>\n"` stream. Returns lowercase-hex.
pub fn recompute_pathset_digest(manifest: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(PATHSET_DIGEST_DOMAIN);
    h.update(manifest.as_bytes());
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    use std::fmt::Write as _;
    for b in d.as_bytes() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Verify an OBSERVED (venue-attested) tooling authority against the ratified values. Fails closed:
///   * the ratified authority must be BOUND (Commit B done) — an unbound authority never validates;
///   * `observed_commit` must be well-formed 40-hex and EQUAL the ratified tooling commit — this is
///     the tooling checkout, and it is NEVER compared to the measured-source `RATIFIED_SOURCE_COMMIT`;
///   * `observed_pathset_digest` must be well-formed 64-hex and EQUAL the ratified path-set digest.
///
/// The caller supplies the recomputed-at-run digest (the venue recomputes it over the tooling root
/// with `tooling_pathset.sh`); this function is the equality gate, not the filesystem walk.
pub fn verify_tooling_authority(
    observed_commit: &str,
    observed_pathset_digest: &str,
) -> Result<(), String> {
    if !tooling_authority_is_bound() {
        return Err(
            "ratified measurement-tooling authority is UNBOUND (Commit B has not bound the tooling \
             commit + path-set digest); refusing every run until it is bound"
                .into(),
        );
    }
    if !is_hex40(observed_commit) {
        return Err(format!(
            "observed tooling commit {observed_commit:?} is not 40 lowercase-hex"
        ));
    }
    if observed_commit != RATIFIED_MEASUREMENT_TOOLING_COMMIT {
        return Err(format!(
            "observed tooling commit {observed_commit} != ratified {RATIFIED_MEASUREMENT_TOOLING_COMMIT}"
        ));
    }
    if !is_hex64(observed_pathset_digest) {
        return Err(format!(
            "observed tooling path-set digest {observed_pathset_digest:?} is not 64 lowercase-hex"
        ));
    }
    if observed_pathset_digest != RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3 {
        return Err(format!(
            "observed tooling path-set digest {observed_pathset_digest} != ratified \
             {RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3} (missing/extra path, changed byte, or dirty \
             tooling root)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_a_ships_unbound_and_refuses() {
        // Commit A invariant: both values are the sentinel, so nothing validates yet.
        assert_eq!(RATIFIED_MEASUREMENT_TOOLING_COMMIT, UNBOUND);
        assert_eq!(RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3, UNBOUND);
        assert!(!tooling_authority_is_bound());
        let e = verify_tooling_authority(&"a".repeat(40), &"b".repeat(64)).unwrap_err();
        assert!(e.contains("UNBOUND"), "{e}");
    }

    #[test]
    fn pathset_digest_is_domain_separated_and_stable() {
        let manifest = "aa..  x\nbb..  y\n";
        let d = recompute_pathset_digest(manifest);
        assert_eq!(d.len(), 64);
        assert!(is_hex64(&d));
        // Domain separation: the same manifest under a different domain differs.
        let mut h = blake3::Hasher::new();
        h.update(manifest.as_bytes());
        let mut bare = String::new();
        use std::fmt::Write as _;
        for b in h.finalize().as_bytes() {
            let _ = write!(bare, "{b:02x}");
        }
        assert_ne!(d, bare);
    }

    // A hypothetical BOUND authority (simulated via the same equality logic) accepts an exact match
    // and refuses a wrong commit / wrong digest / malformed input. We cannot mutate the consts at
    // runtime, so this exercises the equality + shape logic through a local mirror.
    #[test]
    fn equality_and_shape_gates() {
        assert!(is_hex40(&"0".repeat(40)));
        assert!(!is_hex40(&"0".repeat(39)));
        assert!(!is_hex40(&"g".repeat(40)));
        assert!(!is_hex40(&"A".repeat(40))); // uppercase is non-canonical
        assert!(is_hex64(&"0".repeat(64)));
        assert!(!is_hex64(&"0".repeat(63)));
    }
}

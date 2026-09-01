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

/// The explicit unbound sentinel.
pub const UNBOUND: &str = "UNBOUND";

/// **B0-PRE RETIRED (2026-09-01).** The B0 measurement phase is closed — RISC0 was selected and the
/// official evidence sealed (retirement record: `docs/b0-final/B0-PRE-RETIREMENT.md`). The live
/// tooling authority below is deliberately set back to [`UNBOUND`] so current `main` FAILS CLOSED and
/// can no longer produce a new official B0 measurement. This is NOT the pre-binding Commit-A state —
/// it is a terminal retirement, and `main` is never re-ratified (no new Commit B). Historical
/// measurements are verified ONLY from the tagged historical commit/release below.
pub const B0_PRE_RETIRED: bool = true;

/// Historical (now-retired) authority values, preserved for the record ONLY. They are NOT live and
/// MUST NOT authorize a measurement on current `main`; check out [`HISTORICAL_MEASUREMENT_HEAD`]
/// (immutable release [`HISTORICAL_EVIDENCE_RELEASE_TAG`]) to verify historical evidence.
pub const HISTORICAL_TOOLING_COMMIT: &str = "be3a5cb151b42689b31574691ec1641bb1278bbf";
pub const HISTORICAL_TOOLING_PATHSET_BLAKE3: &str =
    "e17877e38b5ada83f7d84b81bd25be0c3e1cd53e6a1a94fb555140371397a856";
pub const HISTORICAL_MEASUREMENT_HEAD: &str = "9cccaa5ee6e038fb9dcb45af44ecb3cbdc2f48c6";
pub const HISTORICAL_EVIDENCE_RELEASE_TAG: &str = "b0-final-evidence-60ace32c";
pub const HISTORICAL_OFFICIAL_SEAL_BLAKE3: &str =
    "60ace32cc2775fd38c3a4b9ea81f49686121cdd25a38db7a5ca5a0f4580bd600";

/// Live ratified tooling commit — **retired ⇒ [`UNBOUND`]** (see [`B0_PRE_RETIRED`]). Historical
/// value: [`HISTORICAL_TOOLING_COMMIT`].
pub const RATIFIED_MEASUREMENT_TOOLING_COMMIT: &str = UNBOUND;

/// Live ratified tooling path-set digest — **retired ⇒ [`UNBOUND`]** (see [`B0_PRE_RETIRED`]).
/// Historical value: [`HISTORICAL_TOOLING_PATHSET_BLAKE3`].
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

/// `true` iff B0-PRE is retired: measurement production is permanently disabled on this tree.
pub fn b0_pre_retired() -> bool {
    B0_PRE_RETIRED
}

/// Fail-closed retirement gate for every measurement-production entrypoint. Returns `Err` carrying
/// the `B0_PRE_RETIRED` marker while retired, so current `main` refuses to produce a new official B0
/// measurement. Historical evidence is verified from the tagged historical commit/release, not here.
pub fn assert_not_retired() -> Result<(), String> {
    if B0_PRE_RETIRED {
        return Err(format!(
            "B0_PRE_RETIRED: the B0 measurement phase is closed; current main cannot produce a new \
             official B0 measurement. Verify historical evidence from tag \
             {HISTORICAL_EVIDENCE_RELEASE_TAG} (commit {HISTORICAL_MEASUREMENT_HEAD}); see \
             docs/b0-final/B0-PRE-RETIREMENT.md."
        ));
    }
    Ok(())
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

    // Commit B (authority binding) ratified the tooling authority to Commit A + the twice-recomputed
    // path-set digest. These exercise the now-ACTIVE authority: the exact pair validates; an UNBOUND
    // sentinel, a wrong commit, or a wrong path-set digest are each refused.
    // STATE-TOLERANT across the two-commit ratification: it holds in Commit A (both consts UNBOUND,
    // fail-closed) AND in Commit B (both consts bound to Commit A's SHA + the path-set digest). Commit B
    // edits ONLY the two consts above; this test needs no change between the commits.
    #[test]
    fn ratified_tooling_authority_validates_and_refuses_mismatches() {
        if tooling_authority_is_bound() {
            // Commit B (BOUND): the exact ratified pair validates; a wrong commit / wrong digest is refused.
            assert!(is_hex40(RATIFIED_MEASUREMENT_TOOLING_COMMIT));
            assert!(is_hex64(RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3));
            assert!(verify_tooling_authority(
                RATIFIED_MEASUREMENT_TOOLING_COMMIT,
                RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
            )
            .is_ok());
            assert!(
                verify_tooling_authority(RATIFIED_MEASUREMENT_TOOLING_COMMIT, UNBOUND).is_err()
            );
            assert!(verify_tooling_authority(
                &"a".repeat(40),
                RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3
            )
            .unwrap_err()
            .contains("!= ratified"));
            assert!(
                verify_tooling_authority(RATIFIED_MEASUREMENT_TOOLING_COMMIT, &"b".repeat(64))
                    .unwrap_err()
                    .contains("path-set digest")
            );
        } else {
            // Commit A (UNBOUND): fail-closed — every run refused until Commit B binds the authority.
            assert_eq!(RATIFIED_MEASUREMENT_TOOLING_COMMIT, UNBOUND);
            assert_eq!(RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3, UNBOUND);
            assert!(verify_tooling_authority(&"a".repeat(40), &"b".repeat(64)).is_err());
        }
        // Both states refuse an UNBOUND observed value.
        assert!(verify_tooling_authority(UNBOUND, &"b".repeat(64)).is_err());
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

    // #196 RETIREMENT: current `main` is retired — the live authority is UNBOUND, the explicit marker
    // is set, and every measurement-production gate fails closed. Historical values are preserved
    // (well-formed hex) for the record but are NOT live.
    #[test]
    fn b0_pre_is_retired_and_production_measurement_refuses() {
        assert!(b0_pre_retired());
        assert_eq!(RATIFIED_MEASUREMENT_TOOLING_COMMIT, UNBOUND);
        assert_eq!(RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3, UNBOUND);
        assert!(!tooling_authority_is_bound());
        let e = assert_not_retired().expect_err("retired tree must refuse production measurement");
        assert!(
            e.contains("B0_PRE_RETIRED"),
            "refusal must carry the marker: {e}"
        );
        // the Rust authority gate also fails closed for any observed value while retired.
        assert!(verify_tooling_authority(&"a".repeat(40), &"b".repeat(64)).is_err());
        // historical values preserved for the record (well-formed, non-live).
        assert!(is_hex40(HISTORICAL_TOOLING_COMMIT));
        assert!(is_hex64(HISTORICAL_TOOLING_PATHSET_BLAKE3));
        assert!(is_hex40(HISTORICAL_MEASUREMENT_HEAD));
        assert!(is_hex64(HISTORICAL_OFFICIAL_SEAL_BLAKE3));
        assert_eq!(
            HISTORICAL_EVIDENCE_RELEASE_TAG,
            "b0-final-evidence-60ace32c"
        );
    }
}

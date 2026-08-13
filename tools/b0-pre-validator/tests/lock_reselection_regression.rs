//! Regression for the committed-lock reselection defect (owner ruling).
//!
//! Commit A's venue validation exposed that an authoritative venue which re-ran an UNCONSTRAINED
//! `cargo generate-lockfile` selected `http-body-util 0.1.5` from a moving registry, while the
//! committed candidate graph pins `http-body-util 0.1.4` (checksum e9f41fd6…). The committed
//! `Cargo.lock` is the dependency-selection AUTHORITY: the venue materializes THAT exact graph under
//! Cargo `--locked` and NEVER reselects.
//!
//! This test proves, over the REAL committed candidate locks (RISC0 + SP1):
//!   - the committed `http-body-util 0.1.4` graph, materialized as the committed source of truth,
//!     is ACCEPTED by `verify_committed_source_lock`; and
//!   - a `0.1.5` "unlocked drift" is REFUSED from BOTH directions —
//!       (a) an on-disk committed lock silently swapped to 0.1.5, and
//!       (b) a defective venue that recorded provenance over the reselected 0.1.5 lock —
//!     each fails with `HashMismatch`, because the recorded committed SHA-256 / BLAKE3 no longer
//!     recompute from the bytes verify is asked to bind.
//!
//! No Docker / builder image is needed: the reselection is modeled as the exact byte edit
//! `version = "0.1.4"` -> `version = "0.1.5"` inside the `http-body-util` stanza.

use b0_pre_validator::venue::lock_provenance::{
    recompute_lock_hash, recompute_lock_sha256, verify_committed_source_lock, LockError,
    LockProvenance, COMMITTED_SOURCE_ORIGIN,
};

fn committed_lock(candidate: &str) -> Vec<u8> {
    let p = format!(
        "{}/../b0-pre-candidates/candidates/{candidate}/Cargo.lock",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("read committed lock {p}: {e}"))
}

/// Model an UNCONSTRAINED reselection: the committed `http-body-util 0.1.4` stanza becomes `0.1.5`.
/// Panics if the committed lock no longer pins 0.1.4 — that is itself a meaningful regression signal.
fn reselect_http_body_util_0_1_5(bytes: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("Cargo.lock is UTF-8");
    let name_at = text
        .find("name = \"http-body-util\"")
        .expect("committed lock must pin http-body-util");
    let ver_rel = text[name_at..]
        .find("version = \"0.1.4\"")
        .expect("http-body-util must be pinned to 0.1.4 in the committed graph");
    let ver_at = name_at + ver_rel;
    let mut out = text.to_string();
    out.replace_range(ver_at..ver_at + "version = \"0.1.4\"".len(), "version = \"0.1.5\"");
    assert_ne!(out.as_bytes(), bytes, "reselection must change the bytes");
    out.into_bytes()
}

fn real_container_digest(label: &str) -> String {
    // A real, non-synthetic sha256:<64hex> builder-image digest shape.
    format!("sha256:{}", recompute_lock_sha256(label.as_bytes()))
}

/// A faithful committed-source-of-truth provenance recorded over `bytes` (the committed lock the
/// venue materialized under --locked): committed sha256/blake3 and post==pre are all over `bytes`.
fn provenance_over(candidate_schema: &str, bytes: &[u8]) -> LockProvenance {
    let sha = recompute_lock_sha256(bytes);
    LockProvenance {
        candidate: candidate_schema.to_string(),
        arch: "X86_64".to_string(),
        origin: COMMITTED_SOURCE_ORIGIN.to_string(),
        container_digest: real_container_digest(&format!("builder-{candidate_schema}-x86_64")),
        source_commit: "a".repeat(40),
        committed_lock_sha256_hex: sha.clone(),
        committed_lock_blake3_hex: recompute_lock_hash(bytes),
        post_lock_sha256_hex: sha,
        locked_command_log_blake3_hex: recompute_lock_sha256(b"cargo vendor --locked; cargo metadata --locked"),
        materialized_closure_blake3_hex: recompute_lock_sha256(b"materialized-closure"),
        vendor_inputs_blake3_hex: recompute_lock_sha256(b"vendor-inputs"),
    }
}

fn run_for(candidate: &str, candidate_schema: &str) {
    let committed = committed_lock(candidate);
    assert!(
        std::str::from_utf8(&committed).unwrap().contains("version = \"0.1.4\""),
        "{candidate} committed lock must pin http-body-util 0.1.4"
    );

    // (1) The committed 0.1.4 graph, materialized as the committed source of truth, is ACCEPTED.
    let good = provenance_over(candidate_schema, &committed);
    let binding = verify_committed_source_lock(&good, &committed)
        .unwrap_or_else(|e| panic!("{candidate}: committed 0.1.4 lock must verify: {e}"));
    assert_eq!(binding.lock_blake3_hex, recompute_lock_hash(&committed));
    assert_eq!(binding.candidate, candidate_schema);

    let reselected = reselect_http_body_util_0_1_5(&committed);

    // (2a) On-disk committed lock silently swapped to 0.1.5, provenance still over the true 0.1.4
    //      bytes: verify is asked to bind the 0.1.5 bytes and REFUSES (recorded hashes are over
    //      0.1.4).
    let e = verify_committed_source_lock(&good, &reselected).unwrap_err();
    assert!(
        matches!(e, LockError::HashMismatch { .. }),
        "{candidate}: a 0.1.5-swapped committed lock must be refused, got {e:?}"
    );

    // (2b) A DEFECTIVE venue recorded provenance over the reselected 0.1.5 lock, but the committed
    //      authority is still 0.1.4: verify against the committed bytes REFUSES (the reselected
    //      hashes do not recompute from the committed 0.1.4 bytes).
    let drifted = provenance_over(candidate_schema, &reselected);
    let e = verify_committed_source_lock(&drifted, &committed).unwrap_err();
    assert!(
        matches!(e, LockError::HashMismatch { .. }),
        "{candidate}: provenance recorded over the reselected 0.1.5 lock must be refused against the committed 0.1.4 authority, got {e:?}"
    );

    // (2c) Even a self-consistent reselected provenance+bytes pair (the venue regenerated AND
    //      recorded over 0.1.5) is not the committed authority: its committed sha256 differs from the
    //      real committed lock's sha256, so downstream binding to the committed lock cannot match.
    assert_ne!(
        drifted.committed_lock_sha256_hex, good.committed_lock_sha256_hex,
        "{candidate}: the 0.1.5 reselection must have a different committed sha256 than 0.1.4"
    );
}

#[test]
fn risc0_committed_0_1_4_passes_and_0_1_5_reselection_is_refused() {
    run_for("risc0", "Risc0");
}

#[test]
fn sp1_committed_0_1_4_passes_and_0_1_5_reselection_is_refused() {
    run_for("sp1", "Sp1");
}

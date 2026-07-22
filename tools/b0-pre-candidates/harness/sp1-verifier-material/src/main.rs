//! SP1 verifier-material extractor (venue-only).
//!
//! NOT_YET_REPRODUCED off-venue: this binary compiles and runs only where
//! `sp1-verifier = 6.3.1` is present (the pinned container). It emits a
//! `VerifierMaterialManifestV1` for the SP1 candidate by READING the immutable
//! Groth16 verifying key bytes directly from the pinned crate — no bytes are
//! hardcoded, inferred, or fabricated.
//!
//! The single immutable non-code artifact the SP1 Groth16 terminal verifier
//! consumes is `sp1_verifier::GROTH16_VK_BYTES` (canonical role `groth16_vk`).
//! `tests/contract.rs` proves, executably, that `Groth16Verifier::verify`
//! consumes exactly that material and that no other omitted immutable blob is
//! required.
//!
//! Identity is NOT authoritative from any ad-hoc extractor hash. The raw entries
//! are fed straight through the SHARED canonical primitive `b0_pre_vmat`
//! (`sort_entries` + `identity`) — the exact same code the reference validator's
//! `VerifierMaterialManifestV1::{encode,identity}` calls and its passing tests
//! cover. `manifest_identity_blake3 = BLAKE3(b0_pre_vmat::encode(..))` is the only
//! value a Stage-1 bundle may present as `manifest_hash_hex`. This crate contains
//! NO hand-rolled wire replica; the former ad-hoc body hash survives ONLY as a
//! clearly-labelled non-canonical diagnostic that must never be used as identity.

use std::process::ExitCode;

use b0_pre_vmat::{Entry, CANDIDATE_SP1, REQUIRED_STAMPS, ROLE_GROTH16_VK};

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Build and print the canonical manifest, propagating every fallible-codec
/// rejection instead of `expect`-ing on the codec path. Any codec error means the
/// extractor emits NO manifest and the caller sees a non-zero exit.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    // READ the immutable Groth16 vk bytes from the pinned crate.
    let vk: &[u8] = sp1_verifier::GROTH16_VK_BYTES.as_ref();
    let entry_digest = blake3::hash(vk);

    // SP1 contains exactly one canonical role: groth16_vk. `canonical_label`
    // returns `None` only for an unknown role; groth16_vk is defined, so we map a
    // (here-impossible) miss into a codec-shaped error rather than unwrapping.
    let label = b0_pre_vmat::canonical_label(ROLE_GROTH16_VK).ok_or(
        b0_pre_vmat::VmatError::UnknownRole {
            role: ROLE_GROTH16_VK,
        },
    )?;
    let byte_len = u64::try_from(vk.len()).map_err(|_| b0_pre_vmat::VmatError::Overflow)?;
    let mut entries = vec![Entry {
        role: ROLE_GROTH16_VK,
        label,
        byte_len,
        hash: *entry_digest.as_bytes(),
    }];

    // Canonical order + identity from the SHARED primitive. `manifest_identity` ==
    // BLAKE3(VerifierMaterialManifestV1::encode()) — the only valid manifest_hash_hex.
    // The strict canonical gate is applied before hashing so a non-canonical set
    // fails closed here.
    b0_pre_vmat::sort_entries(&mut entries);
    b0_pre_vmat::ensure_canonical(CANDIDATE_SP1, &entries)?;
    let total = b0_pre_vmat::total_bytes(&entries)?;
    let manifest_identity = b0_pre_vmat::identity(CANDIDATE_SP1, &entries)?;

    // Non-canonical diagnostic ONLY (the former ad-hoc body hash): explicitly NOT
    // the manifest identity, retained for debugging cross-checks. Distinct body
    // shape by construction, so it can never be confused with the canonical bytes.
    let mut diag = Vec::new();
    diag.extend_from_slice(b"Sp1\0");
    diag.extend_from_slice(b"groth16_vk\0");
    diag.extend_from_slice(&byte_len.to_le_bytes());
    diag.extend_from_slice(entry_digest.as_bytes());
    let mut dh = blake3::Hasher::new();
    dh.update(&b0_pre_vmat::VERIFIER_MATERIAL_TAG);
    dh.update(&diag);
    let noncanonical_diagnostic = dh.finalize();

    let json_entries: Vec<_> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "role": e.label,
                "label": e.label,
                "byte_length": e.byte_len,
                "blake3": hex(&e.hash),
            })
        })
        .collect();

    let manifest = serde_json::json!({
        "stamp": REQUIRED_STAMPS,
        "candidate_id": "Sp1",
        "manifest_schema": "VerifierMaterialManifestV1",
        "entries": json_entries,
        "total_bytes": total,
        "manifest_identity_blake3": hex(&manifest_identity),
        "noncanonical_diagnostic_blake3": hex(noncanonical_diagnostic.as_bytes()),
        "domain": b0_pre_vmat::VERIFIER_MATERIAL_TAG_ASCII,
        "note": "bytes read from sp1_verifier::GROTH16_VK_BYTES; not fabricated. \
                 manifest_identity_blake3 = BLAKE3(b0_pre_vmat::encode(..)), the shared canonical \
                 encoder the validator also uses; noncanonical_diagnostic_blake3 is NOT an identity \
                 and must never be used as manifest_hash_hex.",
    });
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("INELIGIBLE: SP1 verifier-material extraction failed closed: {e}");
            ExitCode::FAILURE
        }
    }
}

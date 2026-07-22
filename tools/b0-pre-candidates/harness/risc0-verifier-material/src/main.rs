//! RISC Zero verifier-material extractor (venue-only, native x86_64).
//!
//! NOT_YET_REPRODUCED off-venue: compiles/runs only where `risc0-zkvm = 3.0.5`
//! and `risc0-groth16 = 3.0.4` are present on a native x86_64 builder. It emits a
//! `VerifierMaterialManifestV1` for the RISC Zero candidate by READING the
//! immutable material that the `Receipt::verify(image_id)` -> `InnerReceipt::Groth16`
//! path consumes, directly from the pinned `Groth16ReceiptVerifierParameters`.
//! No bytes are hardcoded, inferred, duplicated, or fabricated.
//!
//! The four canonical roles that path consumes, in canonical `(role, label)`
//! order (role discriminant ascending): `groth16_vk`, `control_root`,
//! `control_id`, `verifier_params`. Each label is the lowercase role name.
//! `tests/contract.rs` proves genuine verification + rejects mutation of each
//! required component, the image id, the journal, and the seal; if the pinned
//! path cannot reproducibly produce/verify the Groth16 receipt, the run records
//! an evidence-backed INELIGIBLE finding rather than emit partial material.
//!
//! Identity is NOT authoritative from any ad-hoc hash: the raw entries are fed
//! straight through the SHARED canonical primitive `b0_pre_vmat`
//! (`sort_entries` + `identity`) — the exact same code the reference validator's
//! `VerifierMaterialManifestV1::{encode,identity}` calls and its passing tests
//! cover. `manifest_identity_blake3 = BLAKE3(b0_pre_vmat::encode(..))` is the only
//! value a Stage-1 bundle may present as `manifest_hash_hex`. This crate contains
//! NO hand-rolled wire replica.
//!
//! NOTE: exact symbol/field names from the 3.0.5 API are confirmed in the venue
//! (where the crate is present). This extractor reads them from the crate; if a
//! name differs it must be corrected there — never replaced by a literal.

use std::process::ExitCode;

use b0_pre_vmat::{
    Entry, CANDIDATE_RISC0, REQUIRED_STAMPS, ROLE_CONTROL_ID, ROLE_CONTROL_ROOT, ROLE_GROTH16_VK,
    ROLE_VERIFIER_PARAMS,
};

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// One immutable material blob read from the pinned crate, before hashing. Its
/// canonical label is minted by the shared primitive from the role.
struct RawMaterial {
    role: u8,
    bytes: Vec<u8>,
}

/// Read the immutable material from the pinned Groth16 receipt verifier
/// parameters. Every value is read from the crate; nothing is synthesized. The
/// shared primitive imposes the canonical `(role, label)` order at encode time,
/// so the read order here is not load-bearing.
fn extract_entries() -> Vec<RawMaterial> {
    use risc0_zkvm::Groth16ReceiptVerifierParameters;
    let p = Groth16ReceiptVerifierParameters::default();

    // The Groth16 verifying key bytes actually used by the verify path.
    let groth16_vk = p.verifying_key.to_bytes();
    // control_root and bn254 control id are pinned digests for this version.
    let control_root = p.control_root.as_bytes().to_vec();
    let control_id = p.bn254_control_id.as_bytes().to_vec();
    // The overall verifier-parameters digest bound into Receipt::verify.
    let verifier_params = risc0_zkvm::sha::Digestible::digest(&p).as_bytes().to_vec();

    vec![
        RawMaterial {
            role: ROLE_GROTH16_VK,
            bytes: groth16_vk,
        },
        RawMaterial {
            role: ROLE_CONTROL_ROOT,
            bytes: control_root,
        },
        RawMaterial {
            role: ROLE_CONTROL_ID,
            bytes: control_id,
        },
        RawMaterial {
            role: ROLE_VERIFIER_PARAMS,
            bytes: verifier_params,
        },
    ]
}

/// Build and print the canonical manifest, propagating every fallible-codec
/// rejection instead of `expect`-ing on the codec path. Any codec error (or an
/// empty material blob) means NO manifest is emitted and the caller sees a
/// non-zero exit — an evidence-backed INELIGIBLE, never partial material.
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let raw = extract_entries();
    if !raw.iter().all(|e| !e.bytes.is_empty()) {
        return Err(
            "INELIGIBLE: an immutable verifier-material entry extracted empty; \
             do not emit partial material"
                .into(),
        );
    }

    // Build the shared canonical entries: label minted from the role, digest over
    // the read bytes. No hand-rolled encoding — sorting + identity + total all come
    // from `b0_pre_vmat`.
    let digests: Vec<[u8; 32]> = raw
        .iter()
        .map(|e| *blake3::hash(&e.bytes).as_bytes())
        .collect();
    let mut entries: Vec<Entry> = Vec::with_capacity(raw.len());
    for (e, d) in raw.iter().zip(&digests) {
        let label = b0_pre_vmat::canonical_label(e.role)
            .ok_or(b0_pre_vmat::VmatError::UnknownRole { role: e.role })?;
        let byte_len =
            u64::try_from(e.bytes.len()).map_err(|_| b0_pre_vmat::VmatError::Overflow)?;
        entries.push(Entry {
            role: e.role,
            label,
            byte_len,
            hash: *d,
        });
    }
    b0_pre_vmat::sort_entries(&mut entries);
    // Strict canonical gate before hashing: canonical labels, ascending order, no
    // duplicate role. A non-canonical set fails closed here.
    b0_pre_vmat::ensure_canonical(CANDIDATE_RISC0, &entries)?;
    let total = b0_pre_vmat::total_bytes(&entries)?;
    let manifest_identity = b0_pre_vmat::identity(CANDIDATE_RISC0, &entries)?;

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
        "candidate_id": "Risc0",
        "manifest_schema": "VerifierMaterialManifestV1",
        "entries": json_entries,
        "total_bytes": total,
        "manifest_identity_blake3": hex(&manifest_identity),
        "domain": b0_pre_vmat::VERIFIER_MATERIAL_TAG_ASCII,
        "note": "bytes read from risc0 Groth16ReceiptVerifierParameters; not fabricated. Entries \
                 are placed in canonical (role, label) order by b0_pre_vmat::sort_entries; \
                 manifest_identity_blake3 = BLAKE3(b0_pre_vmat::encode(..)), the shared canonical \
                 encoder the validator also uses, and is the only valid manifest_hash_hex.",
    });
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("INELIGIBLE: RISC Zero verifier-material extraction failed closed: {e}");
            ExitCode::FAILURE
        }
    }
}

//! RISC Zero verifier-material extractor (venue-only, native x86_64).
//!
//! NOT_YET_REPRODUCED off-venue: compiles/runs only where `risc0-zkvm = 3.0.5`
//! and `risc0-groth16 = 3.0.4` are present on a native x86_64 builder. It emits a
//! `VerifierMaterialManifestV1` for the RISC Zero candidate by READING the
//! immutable material that the `Receipt::verify(image_id)` -> `InnerReceipt::Groth16`
//! path consumes, directly from the pinned `Groth16ReceiptVerifierParameters`.
//! No bytes are hardcoded, inferred, duplicated, or fabricated.
//!
//! Only roles actually consumed by that path are included:
//!   control_root, groth16_vk, control_id, verifier_params.
//! `tests/contract.rs` proves genuine verification + rejects mutation of each
//! required component, the image id, the journal, and the seal; if the pinned
//! path cannot reproducibly produce/verify the Groth16 receipt, the run records
//! an evidence-backed INELIGIBLE finding rather than emit partial material.
//!
//! NOTE: exact symbol/field names from the 3.0.5 API are confirmed in the venue
//! (where the crate is present). This extractor reads them from the crate; if a
//! name differs it must be corrected there — never replaced by a literal.

const VMAT_TAG_ASCII: &str = "SUMCHAIN/B0PRE/VMAT/v1"; // == validator tags::VERIFIER_MATERIAL_TAG

fn vmat_tag32() -> [u8; 32] {
    let mut t = [0u8; 32];
    let b = VMAT_TAG_ASCII.as_bytes();
    t[..b.len()].copy_from_slice(b);
    t
}
fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

struct Entry {
    role: &'static str,
    label: String,
    bytes: Vec<u8>,
}

/// Read the immutable material from the pinned Groth16 receipt verifier
/// parameters. Every value is read from the crate; nothing is synthesized.
fn extract_entries() -> Vec<Entry> {
    use risc0_zkvm::Groth16ReceiptVerifierParameters;
    let p = Groth16ReceiptVerifierParameters::default();

    // control_root and bn254 control id are pinned digests for this version.
    let control_root = p.control_root.as_bytes().to_vec();
    let control_id = p.bn254_control_id.as_bytes().to_vec();
    // The Groth16 verifying key bytes actually used by the verify path.
    let groth16_vk = p.verifying_key.to_bytes();
    // The overall verifier-parameters digest bound into Receipt::verify.
    let verifier_params = risc0_zkvm::sha::Digestible::digest(&p).as_bytes().to_vec();

    vec![
        Entry {
            role: "control_root",
            label: "CONTROL_ROOT".into(),
            bytes: control_root,
        },
        Entry {
            role: "groth16_vk",
            label: "GROTH16_VERIFYING_KEY".into(),
            bytes: groth16_vk,
        },
        Entry {
            role: "control_id",
            label: "BN254_CONTROL_ID".into(),
            bytes: control_id,
        },
        Entry {
            role: "verifier_params",
            label: "VERIFIER_PARAMETERS_DIGEST".into(),
            bytes: verifier_params,
        },
    ]
}

fn main() {
    let entries = extract_entries();
    assert!(
        entries.iter().all(|e| !e.bytes.is_empty()),
        "INELIGIBLE: an immutable verifier-material entry extracted empty; do not emit partial material"
    );

    let mut body = Vec::new();
    body.extend_from_slice(b"Risc0\0");
    let mut json_entries = Vec::new();
    let mut total = 0u64;
    for e in &entries {
        let d = blake3::hash(&e.bytes);
        body.extend_from_slice(e.role.as_bytes());
        body.push(0);
        body.extend_from_slice(e.label.as_bytes());
        body.push(0);
        body.extend_from_slice(&(e.bytes.len() as u64).to_le_bytes());
        body.extend_from_slice(d.as_bytes());
        total += e.bytes.len() as u64;
        json_entries.push(serde_json::json!({
            "role": e.role,
            "label": e.label,
            "byte_length": e.bytes.len(),
            "blake3": hex(d.as_bytes()),
        }));
    }
    let mut h = blake3::Hasher::new();
    h.update(&vmat_tag32());
    h.update(&body);
    let identity = h.finalize();

    let manifest = serde_json::json!({
        "stamp": ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0"],
        "candidate_id": "Risc0",
        "manifest_schema": "VerifierMaterialManifestV1",
        "entries": json_entries,
        "total_bytes": total,
        "manifest_identity_blake3": hex(identity.as_bytes()),
        "domain": VMAT_TAG_ASCII,
        "note": "bytes read from risc0 Groth16ReceiptVerifierParameters; not fabricated",
    });
    println!("{}", serde_json::to_string_pretty(&manifest).unwrap());
}

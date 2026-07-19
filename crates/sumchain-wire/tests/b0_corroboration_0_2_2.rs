//! sumchain-wire 0.2.2 — b0 corroboration vectors (test-only).
//!
//! Loads `fixtures/wire-0-2-2-b0-corroboration.json` (two b0 encodings that were
//! not previously frozen: a full multi-chunk `ObjectCommitmentV1` and a one-slot
//! `OutputManifestV1`) and asserts the production `b0` types re-encode to those
//! EXACT bytes. The fixture bytes were produced by BOTH independent frozen b0
//! implementations (`tools/b0-pre-validator` and `tools/b0-pre-independent`),
//! which agree byte-for-byte; see the fixture's `_provenance` block.
//!
//! This is TEST CORROBORATION ONLY: it is not the B0 protocol artifact, changes
//! no B0 protocol hash rule, and asserts no semantic protocol change.

use sumchain_wire::b0::enums::{ObjectKind, SlotKind};
use sumchain_wire::b0::manifest::{OutputManifestV1, SlotDescriptorV1};
use sumchain_wire::b0::merkle;
use sumchain_wire::b0::object_commitment::ObjectCommitmentV1;

const V: &str = include_str!("fixtures/wire-0-2-2-b0-corroboration.json");

fn fixture() -> serde_json::Value {
    serde_json::from_str(V).expect("parse corroboration fixture json")
}
fn jstr(j: &serde_json::Value, path: &[&str]) -> String {
    let mut c = j;
    for k in path {
        c = &c[*k];
    }
    c.as_str().expect("string node").to_string()
}
fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// Byte-identical to the two tools' `multichunk_buf` (2*CHUNK+7 bytes).
fn multichunk_buf() -> Vec<u8> {
    let n = 2 * merkle::CHUNK + 7;
    let mut buf = vec![0u8; n];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i as u64 * 31 + 7) & 0xff) as u8;
    }
    buf
}

#[test]
fn multichunk_object_commitment_reencodes_to_fixture_bytes() {
    let j = fixture();
    let want = unhex(&jstr(&j, &["object_commitment_multichunk", "bytes"]));

    // (a) Reconstruct from inputs: the production commit() must yield these bytes.
    let oc = ObjectCommitmentV1::commit(ObjectKind::Model, &multichunk_buf()).unwrap();
    assert!(oc.chunk_count() > 1, "vector must be genuinely multi-chunk");
    assert_eq!(oc.chunk_count(), 3);
    assert_eq!(oc.byte_len(), 2 * merkle::CHUNK as u64 + 7);
    assert_eq!(oc.encode(), want, "commit(...) must equal the agreed bytes");
    assert_eq!(
        hex::encode(oc.identity()),
        jstr(&j, &["object_commitment_multichunk", "identity"])
    );

    // (b) Round-trip: decode the exact bytes and re-encode.
    let decoded = ObjectCommitmentV1::decode_exact(&want).unwrap();
    assert_eq!(decoded.encode(), want);
    assert_eq!(decoded, oc);
}

#[test]
fn one_slot_output_manifest_reencodes_to_fixture_bytes() {
    let j = fixture();
    let want = unhex(&jstr(&j, &["one_slot_output_manifest", "bytes"]));

    // (a) Reconstruct from inputs.
    let om = OutputManifestV1 {
        slots: vec![SlotDescriptorV1 {
            slot_kind: SlotKind::ResidualStream,
            slot_index: 7,
            commitment: ObjectCommitmentV1::commit(ObjectKind::ResidualState, b"g").unwrap(),
        }],
    };
    assert_eq!(om.slots.len(), 1, "vector must be a one-slot manifest");
    assert_eq!(om.try_encode().unwrap(), want, "manifest must equal the agreed bytes");
    assert_eq!(
        hex::encode(om.try_commitment().unwrap().identity()),
        jstr(&j, &["one_slot_output_manifest", "commitment_identity"])
    );

    // (b) Round-trip: decode the exact bytes and re-encode.
    let decoded = OutputManifestV1::decode_exact(&want).unwrap();
    assert_eq!(decoded.try_encode().unwrap(), want);
    assert_eq!(decoded, om);
}

/// Mechanically re-verify the fixture's declared provenance digest: recompute
/// `sha256( oc_bytes || manifest_bytes )` from the byte fields and assert it
/// equals the stored `_provenance.sha256` — so the digest is not merely stored,
/// it is checked against the actual bytes on every test run.
#[test]
fn provenance_sha256_recomputes() {
    use sha2::{Digest, Sha256};
    let j = fixture();
    let oc = unhex(&jstr(&j, &["object_commitment_multichunk", "bytes"]));
    let mf = unhex(&jstr(&j, &["one_slot_output_manifest", "bytes"]));
    let mut h = Sha256::new();
    h.update(&oc);
    h.update(&mf);
    let recomputed = hex::encode(h.finalize());
    let declared = jstr(&j, &["_provenance", "sha256"]);
    assert_eq!(
        recomputed, declared,
        "declared provenance sha256 does not match sha256(oc_bytes || manifest_bytes)"
    );
}

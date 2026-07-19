//! Emit the two NEW corroboration vectors for the sumchain-wire 0.2.2 patch:
//!   * a full multi-chunk `ObjectCommitmentV1` (chunk_count > 1), and
//!   * a one-slot `OutputManifestV1`.
//!
//! This only ADDS input cases; it reuses the frozen reference encoders unchanged
//! (`schema::object`, `schema::manifest`, `golden::multichunk_buf`). Prints
//! `key hex` lines to stdout so the output can be diffed byte-for-byte against
//! the independent crate's matching emitter. NOT wired into the workspace or the
//! committed golden fixtures.

use b0_pre_validator::enums::{ObjectKind, SlotKind};
use b0_pre_validator::golden;
use b0_pre_validator::schema::manifest::{OutputManifestV1, SlotDescriptorV1};
use b0_pre_validator::schema::object::ObjectCommitmentV1;

fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn one_slot_output_manifest() -> OutputManifestV1 {
    OutputManifestV1 {
        slots: vec![SlotDescriptorV1 {
            slot_kind: SlotKind::ResidualStream,
            slot_index: 7,
            commitment: ObjectCommitmentV1::commit(ObjectKind::ResidualState, golden::G),
        }],
    }
}

fn main() {
    // Vector 1: full multi-chunk ObjectCommitmentV1 (2*CHUNK+7 => chunk_count 3).
    let oc = ObjectCommitmentV1::commit(ObjectKind::Model, &golden::multichunk_buf());
    println!("oc_multichunk_bytes {}", hx(&oc.encode()));
    println!("oc_multichunk_identity {}", hx(&oc.identity()));

    // Vector 2: one-slot OutputManifestV1.
    let om = one_slot_output_manifest();
    println!("one_slot_manifest_bytes {}", hx(&om.encode()));
    println!(
        "one_slot_manifest_commitment_identity {}",
        hx(&om.commitment().identity())
    );
}

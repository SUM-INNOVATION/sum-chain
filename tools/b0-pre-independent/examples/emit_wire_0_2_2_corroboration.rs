//! Independent emitter for the two NEW sumchain-wire 0.2.2 corroboration vectors.
//!
//! Reproduces, with the independent (distinct) encoders in `enc`, the same two
//! inputs the reference emitter builds:
//!   * a full multi-chunk `ObjectCommitmentV1` (chunk_count > 1), and
//!   * a one-slot output manifest.
//!
//! Adds only input cases; the `enc` encoders are unchanged. Prints `key hex`
//! lines to stdout, byte-for-byte comparable with the reference emitter's output.

use b0_pre_independent::enc::{self, Slot};
use b0_pre_independent::merkle;

const G: &[u8] = b"g";

fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

/// Byte-identical to the reference `golden::multichunk_buf()`.
fn multichunk_buf() -> Vec<u8> {
    let n = 2 * merkle::CHUNK + 7;
    let mut buf = vec![0u8; n];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i as u64 * 31 + 7) & 0xff) as u8;
    }
    buf
}

fn one_slot() -> Vec<Slot> {
    vec![Slot {
        kind: enc::S_RESIDUAL_STREAM,
        index: 7,
        commitment: enc::object_commitment(enc::K_RESIDUAL_STATE, G),
    }]
}

fn main() {
    // Vector 1: full multi-chunk ObjectCommitmentV1.
    let buf = multichunk_buf();
    let oc = enc::object_commitment(enc::K_MODEL, &buf);
    println!("oc_multichunk_bytes {}", hx(&oc));
    println!(
        "oc_multichunk_identity {}",
        hx(&enc::oc_identity(enc::K_MODEL, &buf))
    );

    // Vector 2: one-slot output manifest.
    let slots = one_slot();
    println!(
        "one_slot_manifest_bytes {}",
        hx(&enc::output_manifest(&slots))
    );
    println!(
        "one_slot_manifest_commitment_identity {}",
        hx(&enc::output_manifest_commitment_identity(&slots))
    );
}

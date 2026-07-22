//! B0-PRE independent cross-checker (sum-chain #123, stage 1).
//!
//! A deliberately separate, from-scratch implementation of the deterministic
//! B0-PRE artifacts — Merkle roots, object commitments, derived input,
//! manifests, and the statement/template bytes and their hashes. It shares no
//! executor code with `b0-pre-validator`; the golden cross-check test requires
//! the two crates to agree byte-for-byte via a shared fixture file.
//!
//! Constants (tags, discriminants, fixed scalars) are documented values shared
//! with the reference; the *encoding and hashing* here are independent. This
//! crate performs no proving, toolchain download, or measurement.

#![forbid(unsafe_code)]

pub mod closure;
pub mod enc;
pub mod exp;
pub mod fixed;
pub mod harness;
pub mod merkle;
pub mod rd;
pub mod tags;
pub mod transformer;
pub mod workload;

/// The frozen B0-PRE protocol revision this crate cross-checks. Bumped v10 -> v11
/// with the canonical Stage-1 preregistration hardening (#123); kept in lockstep
/// with `b0-pre-validator`'s `SPEC_VERSION`.
pub const SPEC_VERSION: &str = "b0-pre/v11";

/// `BLAKE3(prefix ‖ data)`.
pub fn prefixed(prefix: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prefix);
    h.update(data);
    h.finalize().into()
}

/// `BLAKE3(data)`.
pub fn plain(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

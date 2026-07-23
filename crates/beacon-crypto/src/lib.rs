//! # SUM Chain Beacon Crypto (BR1 / issue #127) — DEV/TEST ONLY
//!
//! A **narrow internal adapter** over BLS12-381 for the BR1 randomness beacon's
//! DKG + threshold-BLS constructions. This crate exists so that the executable
//! crypto for issue #127 can be exercised and pinned by deterministic test
//! vectors **without** exposing the raw pairing-library types to the rest of the
//! codebase, and **without** wiring anything into consensus.
//!
//! ## Status: NOT ACTIVATED, NOT CONSENSUS
//!
//! Per `BR1-BEACON-SECURITY-SPEC-DRAFT.md`, only two elements are owner-RATIFIED:
//! `G_enc = BLS12-381 G1` and the K-rotate key lifecycle. The ECIES/DLEQ/threshold
//! construction implemented here is **reviewer-approved PROPOSED**, not adopted.
//! The domain-separation strings ([`DST_DLEQ`]) and preimage layouts are PROPOSED
//! (owner decisions, not frozen consensus bytes). This crate:
//!
//! * is a workspace **leaf** — no production crate depends on it;
//! * confines the `blstrs`/`blst` dependency entirely behind the [`bls`] adapter;
//! * defines **no** activation heights, wire ordinals (owned by #125), or protocol
//!   `.hash`es; and
//! * is intended for development, review, and deterministic vectors only.
//!
//! ## Implementation selection (Phase 1)
//!
//! The adapter is built on **`blstrs`** (the Rust binding over supranational
//! `blst`), selected over the pure-Rust `bls12_381` (zkcrypto) crate on the
//! combined security + portability evidence: `blst` carries an NCC Group audit
//! and ongoing Galois formal verification, conforms to IETF BLS Signature V6 +
//! RFC 9380 hash-to-curve, ships hand-optimised assembly for **both** x86_64 and
//! aarch64 (our two required targets) plus a portable C fallback, and is deployed
//! in production (Filecoin, Ethereum-consensus tooling). `bls12_381` is explicitly
//! *unaudited* and offers RFC 9380 hash-to-curve only behind an `experimental`
//! feature. See the PR description for the full comparison table.
//!
//! **This selection is scoped to THIS `publish = false` validation leaf only.**
//! It does NOT select the production consensus BLS implementation, and it does
//! NOT claim this integration is audited — only that upstream `blst` carries the
//! audit history cited above. Production BLS selection and any audit of the
//! integrated code remain open owner decisions.
//!
//! ## Adapter surface
//!
//! Everything crossing the crate boundary is an opaque wrapper — the raw `blstrs`
//! types (`G1Affine`, `G2Affine`, `Scalar`, `Gt`, …) never appear in a public
//! signature. See [`bls`].

pub mod bls;

mod hash_to_scalar;

#[cfg(test)]
mod vectors;

pub use bls::{
    combine, dleq_prove, dleq_verify, pop_verify, verify, verify_partial, DleqContext, DleqProof,
    G1Point, PartialSignature, Pop, PublicKey, SecretScalar, Signature, DST_DLEQ, DST_POP, DST_SIG,
    G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, SCALAR_SIZE, THRESHOLD_T,
};

use thiserror::Error;

/// Errors surfaced by the beacon-crypto adapter. Point/scalar decode failures are
/// split so that the deterministic vectors can assert the *reason* for rejection.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BeaconCryptoError {
    /// Bytes did not decode to a canonical on-curve point in the prime-order
    /// subgroup (covers non-canonical encodings, off-curve points, and
    /// cofactor/small-subgroup points — all rejected by the checked decode).
    #[error("point failed canonical/on-curve/subgroup validation")]
    InvalidPoint,

    /// The point decoded but is the identity (point at infinity), which is
    /// rejected for every beacon element per spec §2.2/§2.3/§5.6.
    #[error("point at infinity (identity) rejected")]
    PointAtInfinity,

    /// A scalar encoding was not canonical (integer >= r).
    #[error("non-canonical scalar (>= r)")]
    NonCanonicalScalar,

    /// A fixed-width buffer had the wrong length.
    #[error("invalid byte length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// Fewer than [`THRESHOLD_T`] distinct partial signatures were supplied to
    /// the exactly-`T` Lagrange combine.
    #[error("insufficient partials for threshold: need {need}, got {got}")]
    InsufficientPartials { need: usize, got: usize },

    /// Two partials shared the same evaluation point `x_j`, so Lagrange
    /// interpolation is undefined.
    #[error("duplicate evaluation point x = {0}")]
    DuplicateEvaluationPoint(u64),
}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, BeaconCryptoError>;

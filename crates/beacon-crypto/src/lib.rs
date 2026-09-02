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
//! Per `BR1-BEACON-SECURITY-SPEC-DRAFT.md` (RATIFIED v1, owner decision
//! 2026-09-01, #127), the BR1 construction implemented here is the **v1
//! specification**: the profile `f=1,c=1,T=2,Q_dkg=3,n=5`, the GJKR/Pedersen +
//! Feldman DKG, threshold-BLS combine, the ECIES suite (BLS12-381 G1 / HKDF-
//! SHA-256 / ChaCha20-Poly1305, §8), the DLEQ construction + tag
//! ([`DST_DLEQ`] `OMNINODE-DKG-DLEQ:v1:`, §5.3), and the beacon GENESIS/ROUND/OUT
//! domain tags + preimage layouts (§12.1) are all **RATIFIED v1 consensus
//! bytes** (§15 decision table rows 22–26, 17–19). Open magnitudes only (e.g.
//! `MARGIN`) remain governance-deferred. Even so, this crate stays **NOT
//! ACTIVATED**: it is gate-closed, wires nothing into consensus execution, and
//! activation additionally requires an independent cryptographic audit. This
//! crate:
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
pub mod ecies;

mod hash_to_scalar;

#[cfg(test)]
mod vectors;

pub use bls::{
    aggregate_g1, combine, commitment_poly_eval, dleq_prove, dleq_verify, eval_share_le,
    feldman_check, pop_verify, verify, verify_partial, DleqContext, DleqProof, G1Point,
    PartialSignature, Pop, PublicKey, SecretScalar, Signature, DST_DLEQ, DST_POP, DST_SIG,
    G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, SCALAR_SIZE, THRESHOLD_T,
};
pub use ecies::{
    ecies_open, ecies_seal, EciesContext, ECIES_AEAD_KEY_LABEL, ECIES_AEAD_NONCE_LABEL,
    ECIES_CTX_DST, ECIES_CT_LEN, ECIES_HKDF_SALT, ECIES_PLAINTEXT_LEN,
};

use thiserror::Error;

/// Errors surfaced by the beacon-crypto adapter. Point/scalar decode failures are
/// split so that the deterministic vectors can assert the *reason* for rejection.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
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

    /// An AEAD (ChaCha20-Poly1305) open failed — a bad tag, a wrong key/nonce, or
    /// tampered ciphertext (spec §8, §6.1: during adjudication this is conclusive
    /// dealer misconduct, `DISQUALIFY(i)`).
    #[error("AEAD open failed (bad tag / wrong key / tampered ciphertext)")]
    AeadOpenFailed,

    /// A G1 aggregation (e.g. `PK_E = Σ C_{i,0}` or `vk_j = Σ …`) had no inputs, or
    /// summed to the identity — a degenerate group/verification key, rejected per
    /// the §2.2 infinity rule.
    #[error("G1 aggregation empty or summed to identity")]
    DegenerateAggregate,
}

/// Crate result alias.
pub type Result<T> = core::result::Result<T, BeaconCryptoError>;

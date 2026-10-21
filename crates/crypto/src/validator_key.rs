//! The per-key validator construction rules, enforced at genesis (VS-5,
//! ratified 2026-10-21).
//!
//! A validator key is accepted only if its 32 bytes decode to an Ed25519
//! curve point, are that point's canonical encoding, and the point is not of
//! small order. A small-order key is unsafe even under protocol v1. Block
//! signatures are checked with the non-strict `verify`, under which such a key
//! admits signatures made without its private key. With the identity point,
//! one signature verifies every message.
//!
//! These are the per-key rules the dormant finality foundations apply to an
//! authenticated validator set (`AuthenticatedValidatorSet`, #338). This is
//! the copy the active genesis path uses, because nothing may depend on the
//! dormant crate yet. `finality-foundations/tests/validator_key_rules.rs`
//! checks that the two give the same verdict on every case. The set rules
//! (count and duplicates) are applied by the caller.

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

/// The per-key construction rule a validator key fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ValidatorKeyRule {
    #[error("does not decode to an Ed25519 curve point")]
    Undecodable,
    #[error("is not the canonical encoding of its curve point")]
    NonCanonical,
    #[error("is a small-order point")]
    SmallOrder,
}

/// Check one validator key against the per-key rules, in order: decode,
/// canonical encoding, small order.
pub fn check_validator_key(bytes: &[u8; 32]) -> Result<(), ValidatorKeyRule> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| ValidatorKeyRule::Undecodable)?;
    if key.to_edwards().compress().to_bytes() != *bytes {
        return Err(ValidatorKeyRule::NonCanonical);
    }
    if key.is_weak() {
        return Err(ValidatorKeyRule::SmallOrder);
    }
    Ok(())
}

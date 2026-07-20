//! Sponsored public-key registration — Ed25519 verification for the SRC-201
//! messaging `RegisterPublicKeySponsoredV1` operation (sum-chain issue #145).
//!
//! The **wire types** (the payload struct, the canonical domain tag, and the
//! signing-preimage builder) live in the `sumchain-wire` leaf crate and are
//! re-exported through `sumchain_primitives::messaging`. That leaf is
//! deliberately ed25519-free — encoding is separated from cryptographic
//! verification.
//!
//! This module keeps the piece that must stay ABOVE the leaf: the strict
//! Ed25519 verification of the registrant's inner signature over the canonical
//! preimage. It mirrors [`crate::inference_attestation::verify_attestation_v2_signature`]:
//! `verify_strict` (which rejects signature malleability and small-order points)
//! and a distinct error for a malformed public key vs. a bad signature so the
//! executor can surface the right receipt code.

use sumchain_wire::messaging::{
    sponsored_register_v1_signing_preimage, RegisterPublicKeySponsoredV1Data,
};
use sumchain_wire::Address;

/// Why a `RegisterPublicKeySponsoredV1` registrant authorization failed
/// cryptographic verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SponsoredRegisterError {
    /// `registrant_public_key` is not a canonical Ed25519 verifying key.
    InvalidPublicKey,
    /// The signature did not strictly verify over the canonical preimage.
    InvalidSignature,
}

/// Strictly verify a registrant's inner authorization for
/// `RegisterPublicKeySponsoredV1` (issue #145).
///
/// Rebuilds the exact canonical preimage
/// (`SPONSORED_REGISTER_V1_TAG || chain_id.to_le_bytes() || sponsor_address ||
/// registrant_public_key`) and verifies `registrant_signature` against
/// `registrant_public_key` with `verify_strict`. The registrant address is
/// ALWAYS derived from `registrant_public_key` by the caller — never supplied.
///
/// The `sponsor_address` (the outer `tx.from`) is bound into the preimage, so a
/// signature produced for one sponsor cannot be replayed under another
/// (sponsor substitution) and a signature produced on one chain cannot be
/// replayed on another (`chain_id`). Parsing the public key first distinguishes
/// [`SponsoredRegisterError::InvalidPublicKey`] (→ a malformed-key receipt code)
/// from [`SponsoredRegisterError::InvalidSignature`].
pub fn verify_sponsored_registration_v1(
    data: &RegisterPublicKeySponsoredV1Data,
    chain_id: u64,
    sponsor_address: &Address,
) -> Result<(), SponsoredRegisterError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&data.registrant_public_key)
        .map_err(|_| SponsoredRegisterError::InvalidPublicKey)?;
    let preimage = sponsored_register_v1_signing_preimage(
        chain_id,
        sponsor_address,
        &data.registrant_public_key,
    );
    let signature = ed25519_dalek::Signature::from_bytes(&data.registrant_signature);
    verifying_key
        .verify_strict(&preimage, &signature)
        .map_err(|_| SponsoredRegisterError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn valid_data(
        registrant: &SigningKey,
        chain_id: u64,
        sponsor: &Address,
    ) -> RegisterPublicKeySponsoredV1Data {
        let registrant_public_key = registrant.verifying_key().to_bytes();
        let preimage =
            sponsored_register_v1_signing_preimage(chain_id, sponsor, &registrant_public_key);
        let sig = registrant.sign(&preimage);
        RegisterPublicKeySponsoredV1Data {
            registrant_public_key,
            registrant_signature: sig.to_bytes(),
        }
    }

    #[test]
    fn valid_registrant_signature_verifies() {
        let registrant = signing_key(1);
        let sponsor = Address::new([9u8; 20]);
        let d = valid_data(&registrant, 7, &sponsor);
        assert_eq!(verify_sponsored_registration_v1(&d, 7, &sponsor), Ok(()));
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let registrant = signing_key(1);
        let sponsor = Address::new([9u8; 20]);
        let d = valid_data(&registrant, 7, &sponsor);
        assert_eq!(
            verify_sponsored_registration_v1(&d, 8, &sponsor),
            Err(SponsoredRegisterError::InvalidSignature)
        );
    }

    #[test]
    fn sponsor_substitution_rejected() {
        let registrant = signing_key(1);
        let sponsor = Address::new([9u8; 20]);
        let other_sponsor = Address::new([10u8; 20]);
        let d = valid_data(&registrant, 7, &sponsor);
        assert_eq!(
            verify_sponsored_registration_v1(&d, 7, &other_sponsor),
            Err(SponsoredRegisterError::InvalidSignature)
        );
    }

    #[test]
    fn public_key_substitution_rejected() {
        let registrant = signing_key(1);
        let attacker = signing_key(2);
        let sponsor = Address::new([9u8; 20]);
        let mut d = valid_data(&registrant, 7, &sponsor);
        // Swap in a different public key while keeping the original signature.
        d.registrant_public_key = attacker.verifying_key().to_bytes();
        assert_eq!(
            verify_sponsored_registration_v1(&d, 7, &sponsor),
            Err(SponsoredRegisterError::InvalidSignature)
        );
    }

    #[test]
    fn malformed_public_key_rejected() {
        let registrant = signing_key(1);
        let sponsor = Address::new([9u8; 20]);
        let mut d = valid_data(&registrant, 7, &sponsor);
        // `[0x02; 32]` is a y-coordinate with no valid curve point, so
        // `VerifyingKey::from_bytes` rejects it before any signature work —
        // exercising the distinct InvalidPublicKey branch (→ receipt code 393).
        d.registrant_public_key = [0x02; 32];
        assert_eq!(
            verify_sponsored_registration_v1(&d, 7, &sponsor),
            Err(SponsoredRegisterError::InvalidPublicKey)
        );
    }
}

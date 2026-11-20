//! Sponsored messaging — Ed25519 verification of the inner signatures the
//! SRC-201 sponsored operations carry: the `RegisterPublicKeySponsoredV1`
//! registrant authorization (sum-chain issue #145) and the version-2 sender
//! envelope of a sponsored `SendMessage`.
//!
//! The **wire types** (the payload structs, the canonical domain tags, and the
//! signing-preimage builders) live in the `sumchain-wire` leaf crate and are
//! re-exported through `sumchain_primitives::messaging`. That leaf is
//! deliberately ed25519-free — encoding is separated from cryptographic
//! verification.
//!
//! This module keeps the piece that must stay ABOVE the leaf: the strict
//! Ed25519 verification of each inner signature over its canonical preimage.
//! It mirrors [`crate::inference_attestation::verify_attestation_v2_signature`]:
//! `verify_strict` (which rejects signature malleability and small-order points)
//! and a distinct error for a malformed public key vs. a bad signature so the
//! executor can surface the right receipt code.

use sumchain_wire::messaging::{
    sponsored_register_v1_signing_preimage, sponsored_send_v2_signing_preimage,
    RegisterPublicKeySponsoredV1Data, SponsoredMessage,
};
use sumchain_wire::Address;

/// Why a sponsored `SendMessage` sender envelope failed cryptographic
/// verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SponsoredEnvelopeError {
    /// `sender_pubkey` is not a canonical Ed25519 verifying key.
    InvalidPublicKey,
    /// The signature did not strictly verify over the version-2 preimage.
    InvalidSignature,
}

/// Strictly verify the version-2 sender envelope of a sponsored `SendMessage`.
///
/// Rebuilds the exact canonical preimage
/// ([`sponsored_send_v2_signing_preimage`]: the tag, `chain_id`, the sender
/// key, the recipient hash, the message hash, the nonce, the expiry and the
/// amount, fixed-width big-endian) and verifies `m.signature` against
/// `m.sender_pubkey` with `verify_strict`, the rule the ratified E1 path and
/// the other inner-signature checks use: canonical encodings only, no
/// small-order components. The sender address is ALWAYS derived from
/// `sender_pubkey` by the caller — never supplied.
///
/// This checks the signature only. Whether the nonce is the sender's current
/// messaging nonce, whether the expiry has passed, and whether an amount is
/// allowed are rules of the executor, judged against state.
pub fn verify_sponsored_send_v2(
    m: &SponsoredMessage,
    chain_id: u64,
) -> Result<(), SponsoredEnvelopeError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&m.sender_pubkey)
        .map_err(|_| SponsoredEnvelopeError::InvalidPublicKey)?;
    let preimage = sponsored_send_v2_signing_preimage(chain_id, m);
    let signature = ed25519_dalek::Signature::from_bytes(&m.signature);
    verifying_key
        .verify_strict(&preimage, &signature)
        .map_err(|_| SponsoredEnvelopeError::InvalidSignature)
}

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

    // ── the version-2 sender envelope ───────────────────────────────────────

    const CHAIN: u64 = 1;

    /// A fixed envelope naming `sender`'s key, unsigned.
    fn envelope(sender: &SigningKey) -> SponsoredMessage {
        SponsoredMessage {
            message_data: b"golden message bytes".to_vec(),
            recipient_hash: [0x33; 32],
            signature: [0u8; 64],
            sender_pubkey: sender.verifying_key().to_bytes(),
            nonce: 5,
            expiry: 1_760_000_000,
            koppa_amount: None,
        }
    }

    /// `m`, signed by `signer` over the version-2 preimage for `chain_id`.
    fn signed_v2(mut m: SponsoredMessage, signer: &SigningKey, chain_id: u64) -> SponsoredMessage {
        let preimage = sponsored_send_v2_signing_preimage(chain_id, &m);
        m.signature = signer.sign(&preimage).to_bytes();
        m
    }

    #[test]
    fn a_v2_envelope_signed_by_the_named_sender_verifies() {
        let sender = signing_key(0x11);
        let m = signed_v2(envelope(&sender), &sender, CHAIN);
        assert_eq!(verify_sponsored_send_v2(&m, CHAIN), Ok(()));
    }

    /// GOLDEN: the deterministic Ed25519 signature of the fixed envelope by the
    /// fixed key, so a client implementation can check its own signing bytes.
    #[test]
    fn the_v2_golden_vector_is_frozen() {
        let sender = signing_key(0x11);
        let m = signed_v2(envelope(&sender), &sender, CHAIN);
        assert_eq!(
            hex::encode(m.sender_pubkey),
            "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
        );
        assert_eq!(
            hex::encode(sponsored_send_v2_signing_preimage(CHAIN, &m)),
            "53554d434841494e2f5352432d3230312f53454e442d53504f4e534f5245442f7632\
             0000000000000001\
             d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737\
             3333333333333333333333333333333333333333333333333333333333333333\
             7f619a2ba30b7c11fbd40834191b2a3f2037274605f0e9e54366138307bd07ea\
             0000000000000005\
             0000000068e77800\
             00000000000000000000000000000000"
        );
        assert_eq!(
            hex::encode(m.signature),
            "89a0ef1a88a012e89e78110d2bb142ca0bcc172381083abecea01f3532d35b1c\
             0aca2307e65b51a41bd675a923c35dea40d0947d548c0e31bcee831acf9ea30c"
        );
        assert_eq!(verify_sponsored_send_v2(&m, CHAIN), Ok(()));
    }

    /// Each bound field, changed after signing, is refused: the chain, the
    /// recipient, the message bytes, the nonce, the expiry and the amount; so
    /// is a signature by another key, and the all-zero signature.
    #[test]
    fn a_v2_envelope_is_refused_when_any_bound_field_changes() {
        let sender = signing_key(0x11);
        let other = signing_key(0x12);
        let good = signed_v2(envelope(&sender), &sender, CHAIN);

        assert_eq!(
            verify_sponsored_send_v2(&good, CHAIN + 1),
            Err(SponsoredEnvelopeError::InvalidSignature),
            "another chain"
        );
        type Change = fn(&mut SponsoredMessage);
        let variants: [(&str, Change); 6] = [
            ("recipient", |m| m.recipient_hash[0] ^= 1),
            ("content", |m| m.message_data[0] ^= 1),
            ("nonce", |m| m.nonce += 1),
            ("expiry", |m| m.expiry += 1),
            ("amount", |m| m.koppa_amount = Some(1)),
            ("signature", |m| m.signature = [0u8; 64]),
        ];
        for (label, change) in variants {
            let mut m = good.clone();
            change(&mut m);
            assert_eq!(
                verify_sponsored_send_v2(&m, CHAIN),
                Err(SponsoredEnvelopeError::InvalidSignature),
                "{label}"
            );
        }
        let by_other_key = signed_v2(envelope(&sender), &other, CHAIN);
        assert_eq!(
            verify_sponsored_send_v2(&by_other_key, CHAIN),
            Err(SponsoredEnvelopeError::InvalidSignature),
            "signed by a key that is not the named sender's"
        );
        // The sender key swapped for another after signing: the signature no
        // longer verifies under the key the envelope names.
        let mut swapped = good.clone();
        swapped.sender_pubkey = other.verifying_key().to_bytes();
        assert_eq!(
            verify_sponsored_send_v2(&swapped, CHAIN),
            Err(SponsoredEnvelopeError::InvalidSignature),
            "another sender key"
        );
    }

    /// A signature over the relay's string form (the pre-gate preimage) is not
    /// a version-2 signature.
    #[test]
    fn a_signature_over_the_string_form_is_refused() {
        let sender = signing_key(0x11);
        let mut m = envelope(&sender);
        let string_form = format!(
            "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
            m.nonce,
            m.expiry,
            hex::encode(m.recipient_hash),
            hex::encode(blake3::hash(&m.message_data).as_bytes())
        );
        m.signature = sender.sign(string_form.as_bytes()).to_bytes();
        assert_eq!(
            verify_sponsored_send_v2(&m, CHAIN),
            Err(SponsoredEnvelopeError::InvalidSignature)
        );
    }

    #[test]
    fn a_malformed_sender_key_is_a_distinct_refusal() {
        let sender = signing_key(0x11);
        let mut m = signed_v2(envelope(&sender), &sender, CHAIN);
        m.sender_pubkey = [0x02; 32];
        assert_eq!(
            verify_sponsored_send_v2(&m, CHAIN),
            Err(SponsoredEnvelopeError::InvalidPublicKey)
        );
    }
}

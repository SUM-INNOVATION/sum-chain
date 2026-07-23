//! Deterministic test vectors for the BR1 beacon crypto (issue #127).
//!
//! Every input is a **fixed** byte seed — no clock, no RNG — so these vectors are
//! reproducible across runs and architectures. They exercise the public adapter
//! surface plus the in-crate `test_support` helpers (needed only to *craft*
//! adversarial inputs such as a non-subgroup point).
//!
//! Coverage:
//!   * positive round-trips: G1/G2 encode↔decode, sign/verify, PoP, partial
//!     verify, exactly-T Lagrange combine (with subset-independence + equals the
//!     direct group signature), DLEQ prove/verify, proof (de)serialisation.
//!   * negatives: malformed point, point at infinity, non-subgroup point, wrong
//!     message, wrong key, non-canonical scalar, DLEQ tamper, combine misuse.

use crate::bls::test_support::{
    g1_identity_compressed, g1_mul, is_on_curve_but_not_subgroup, non_subgroup_g1_compressed,
    poly_eval_deg1_le,
};
use crate::bls::{
    combine, dleq_prove, dleq_verify, pop_verify, verify, verify_partial, DleqContext, DleqProof,
    G1Point, PartialSignature, PublicKey, SecretScalar, Signature, G1_COMPRESSED_SIZE,
    G2_COMPRESSED_SIZE, SCALAR_SIZE,
};
use crate::BeaconCryptoError;

/// A fixed, canonical (`< r`) 32-byte little-endian scalar seed derived from a
/// tag. Byte 31 (most-significant in LE) is forced to 0 so the value is well
/// below `r ≈ 2^255`, guaranteeing canonicalness without a modular reduction.
fn seed(tag: u8) -> [u8; SCALAR_SIZE] {
    let mut b = [0u8; SCALAR_SIZE];
    for (i, out) in b.iter_mut().enumerate() {
        *out = tag.wrapping_add(i as u8).wrapping_mul(7).wrapping_add(1);
    }
    b[SCALAR_SIZE - 1] = 0; // keep < r
    b
}

const MSG: &[u8] = b"BR1 beacon round 0x2a preimage (dev/test, not consensus)";
const WRONG_MSG: &[u8] = b"BR1 beacon round 0x2b preimage (dev/test, not consensus)";

// ---------------------------------------------------------------------------
// Positive: BLS sign / verify / PoP
// ---------------------------------------------------------------------------

#[test]
fn vec_sign_verify_and_pop_roundtrip() {
    let sk = SecretScalar::from_bytes_le(&seed(0x11)).unwrap();
    let pk = sk.public_key();

    let sig = sk.sign(MSG);
    assert!(verify(&pk, MSG, &sig), "honest signature must verify");

    let pop = sk.pop_prove();
    assert!(pop_verify(&pk, &pop), "honest PoP must verify");

    // Signature encode/decode round-trip (96-byte compressed G2).
    let sig_bytes = sig.to_compressed();
    assert_eq!(sig_bytes.len(), G2_COMPRESSED_SIZE);
    let sig2 = Signature::from_compressed(&sig_bytes).unwrap();
    assert_eq!(sig, sig2);

    println!(
        "KAT pk(g1^sk seed0x11) = {}",
        hex::encode(pk.to_compressed())
    );
    println!("KAT sig(MSG)           = {}", hex::encode(sig_bytes));
}

// ---------------------------------------------------------------------------
// Positive: G1 canonical encode/decode round-trips
// ---------------------------------------------------------------------------

#[test]
fn vec_g1_encode_decode_roundtrip() {
    let g = G1Point::generator();
    let bytes = g.to_compressed();
    assert_eq!(bytes.len(), G1_COMPRESSED_SIZE);
    let g2 = G1Point::from_compressed(&bytes).unwrap();
    assert_eq!(g, g2);

    // A derived public key round-trips through both G1 wrappers.
    let pk = SecretScalar::from_bytes_le(&seed(0x77))
        .unwrap()
        .public_key();
    let pk_bytes = pk.to_compressed();
    let pk2 = PublicKey::from_compressed(&pk_bytes).unwrap();
    assert_eq!(pk, pk2);
}

// ---------------------------------------------------------------------------
// Positive: partial verify + exactly-T Lagrange combine
// ---------------------------------------------------------------------------

/// Build a degree-1 (T=2) sharing: group secret `a0`, coefficient `a1`, shares at
/// x = 1,2,3, and the group key `PK_E = g1^{a0}`.
struct Sharing {
    group_sk: SecretScalar,
    pk_e: PublicKey,
    shares: Vec<(u64, SecretScalar, PublicKey)>, // (x_j, sk_j, vk_j)
}

fn build_sharing() -> Sharing {
    let a0 = seed(0x11);
    let a1 = seed(0x22);
    let group_sk = SecretScalar::from_bytes_le(&a0).unwrap();
    let pk_e = group_sk.public_key();

    let mut shares = Vec::new();
    for x in [1u64, 2, 3] {
        let sk_bytes = poly_eval_deg1_le(&a0, &a1, x);
        let sk_j = SecretScalar::from_bytes_le(&sk_bytes).unwrap();
        let vk_j = sk_j.public_key();
        shares.push((x, sk_j, vk_j));
    }
    Sharing {
        group_sk,
        pk_e,
        shares,
    }
}

#[test]
fn vec_partial_verify_positive() {
    let s = build_sharing();
    for (x, sk_j, vk_j) in &s.shares {
        let partial = PartialSignature::new(*x, sk_j.sign(MSG));
        assert!(
            verify_partial(vk_j, MSG, &partial),
            "partial at x={x} must verify under its vk_j"
        );
    }
}

#[test]
fn vec_combine_exactly_t_equals_group_signature_and_is_subset_independent() {
    let s = build_sharing();

    // Direct group signature H(m)^{a0}.
    let group_sig = s.group_sk.sign(MSG);

    let partial = |idx: usize| {
        let (x, sk_j, _vk) = &s.shares[idx];
        PartialSignature::new(*x, sk_j.sign(MSG))
    };
    let p1 = partial(0); // x=1
    let p2 = partial(1); // x=2
    let p3 = partial(2); // x=3

    let c_12 = combine(&[p1, p2]).unwrap();
    let c_23 = combine(&[p2, p3]).unwrap();
    let c_13 = combine(&[p1, p3]).unwrap();

    // Every T-subset reconstructs the same group signature (subset independence).
    assert_eq!(c_12, c_23);
    assert_eq!(c_12, c_13);
    assert_eq!(
        c_12, group_sig,
        "combined signature must equal the direct group signature H(m)^a0"
    );

    // And it verifies under PK_E.
    assert!(verify(&s.pk_e, MSG, &c_12));

    // Order independence: unsorted input yields the identical canonical result.
    let c_21 = combine(&[p2, p1]).unwrap();
    assert_eq!(c_12, c_21, "combine sorts ascending by x_j (canonical)");

    // Extra partial beyond T is ignored (exactly-T selects first T after sort).
    let c_123 = combine(&[p1, p2, p3]).unwrap();
    assert_eq!(c_12, c_123, "exactly-T selects the first T (x=1,2)");

    println!(
        "KAT PK_E              = {}",
        hex::encode(s.pk_e.to_compressed())
    );
    println!(
        "KAT combined group sig= {}",
        hex::encode(c_12.to_compressed())
    );
}

// ---------------------------------------------------------------------------
// Positive: DLEQ prove / verify + proof (de)serialisation
// ---------------------------------------------------------------------------

fn dleq_ctx() -> DleqContext {
    DleqContext {
        chain_id: b"sumchain-dev".to_vec(),
        epoch: 7,
        dealer_index: 2,
        recipient_index: 4,
    }
}

/// Build a valid DLEQ statement (h, EK=h^ek, R=h^r, D=R^ek) + witness ek + nonce.
fn build_dleq_statement() -> (
    G1Point,
    G1Point,
    G1Point,
    G1Point,
    SecretScalar,
    [u8; SCALAR_SIZE],
) {
    let h = G1Point::generator();
    let ek = SecretScalar::from_bytes_le(&seed(0x33)).unwrap();
    let r = SecretScalar::from_bytes_le(&seed(0x44)).unwrap();
    let ek_pt = ek.public_g1(); // EK = h^ek
    let r_pt = r.public_g1(); // R  = h^r
    let d_pt = g1_mul(&r_pt, &ek); // D  = R^ek
    let nonce = seed(0x55);
    (h, ek_pt, r_pt, d_pt, ek, nonce)
}

#[test]
fn vec_dleq_prove_verify_positive_and_proof_roundtrip() {
    let ctx = dleq_ctx();
    let (h, ek_pt, r_pt, d_pt, ek, nonce) = build_dleq_statement();

    let proof = dleq_prove(&ctx, &h, &ek_pt, &r_pt, &d_pt, &ek, &nonce).unwrap();
    assert!(
        dleq_verify(&ctx, &h, &ek_pt, &r_pt, &d_pt, &proof),
        "honest DLEQ proof must verify"
    );

    // Proof (de)serialise round-trip (c_le || z_le = 64 bytes).
    let bytes = proof.to_bytes();
    assert_eq!(bytes.len(), 2 * SCALAR_SIZE);
    let proof2 = DleqProof::from_bytes(&bytes).unwrap();
    assert_eq!(proof, proof2);
    assert!(dleq_verify(&ctx, &h, &ek_pt, &r_pt, &d_pt, &proof2));

    println!("KAT DLEQ proof (c||z) = {}", hex::encode(bytes));
}

// ---------------------------------------------------------------------------
// Negative: malformed point, point at infinity, non-subgroup point
// ---------------------------------------------------------------------------

#[test]
fn vec_neg_malformed_point_rejected() {
    let bytes = [0xFFu8; G1_COMPRESSED_SIZE];
    assert_eq!(
        G1Point::from_compressed(&bytes),
        Err(BeaconCryptoError::InvalidPoint)
    );
    assert_eq!(
        PublicKey::from_compressed(&bytes).unwrap_err(),
        BeaconCryptoError::InvalidPoint
    );
}

#[test]
fn vec_neg_point_at_infinity_rejected() {
    let bytes = g1_identity_compressed();
    assert_eq!(
        G1Point::from_compressed(&bytes),
        Err(BeaconCryptoError::PointAtInfinity)
    );
    assert_eq!(
        PublicKey::from_compressed(&bytes).unwrap_err(),
        BeaconCryptoError::PointAtInfinity
    );
}

#[test]
fn vec_neg_non_subgroup_point_rejected() {
    let bytes = non_subgroup_g1_compressed();
    // Sanity: the crafted bytes really are on-curve but outside the subgroup.
    assert!(
        is_on_curve_but_not_subgroup(&bytes),
        "test input must be on-curve and NOT torsion-free"
    );
    // The checked decode (mandatory subgroup check, spec §2.2) rejects it.
    assert_eq!(
        G1Point::from_compressed(&bytes),
        Err(BeaconCryptoError::InvalidPoint)
    );
    println!("KAT non-subgroup G1   = {}", hex::encode(bytes));
}

// ---------------------------------------------------------------------------
// Negative: wrong message, wrong key
// ---------------------------------------------------------------------------

#[test]
fn vec_neg_wrong_message_and_wrong_key() {
    let s = build_sharing();
    let group_sig = s.group_sk.sign(MSG);

    // Wrong message: signature over MSG must NOT verify against WRONG_MSG.
    assert!(
        !verify(&s.pk_e, WRONG_MSG, &group_sig),
        "wrong message rejected"
    );

    // Wrong key: valid group signature must NOT verify under a per-share vk.
    let (_x1, _sk1, vk1) = &s.shares[0];
    assert!(!verify(vk1, MSG, &group_sig), "wrong key rejected");

    // Partial under the wrong vk is rejected.
    let p1 = PartialSignature::new(s.shares[0].0, s.shares[0].1.sign(MSG));
    let (_x2, _sk2, vk2) = &s.shares[1];
    assert!(
        !verify_partial(vk2, MSG, &p1),
        "partial x=1 must not verify under vk_2"
    );
    // ...and the same partial against the wrong message is rejected.
    assert!(!verify_partial(&s.shares[0].2, WRONG_MSG, &p1));

    // PoP under the wrong key is rejected.
    let sk = SecretScalar::from_bytes_le(&seed(0x11)).unwrap();
    let pop = sk.pop_prove();
    let other_pk = SecretScalar::from_bytes_le(&seed(0x99))
        .unwrap()
        .public_key();
    assert!(!pop_verify(&other_pk, &pop), "PoP under wrong key rejected");
}

// ---------------------------------------------------------------------------
// Negative: DLEQ wrong witness / wrong D / tampered proof
// ---------------------------------------------------------------------------

#[test]
fn vec_neg_dleq_wrong_statement_and_tamper() {
    let ctx = dleq_ctx();
    let (h, ek_pt, r_pt, d_pt, ek, nonce) = build_dleq_statement();
    let proof = dleq_prove(&ctx, &h, &ek_pt, &r_pt, &d_pt, &ek, &nonce).unwrap();

    // Wrong D: D' = R^{ek'} for a different secret breaks the equality.
    let ek_other = SecretScalar::from_bytes_le(&seed(0x66)).unwrap();
    let d_wrong = g1_mul(&r_pt, &ek_other);
    assert!(
        !dleq_verify(&ctx, &h, &ek_pt, &r_pt, &d_wrong, &proof),
        "DLEQ must reject a D that is not R^ek"
    );

    // Wrong witness: prove with ek' but publish EK = h^ek -> unverifiable.
    let bad_proof = dleq_prove(&ctx, &h, &ek_pt, &r_pt, &d_pt, &ek_other, &nonce).unwrap();
    assert!(
        !dleq_verify(&ctx, &h, &ek_pt, &r_pt, &d_pt, &bad_proof),
        "DLEQ with wrong witness must not verify"
    );

    // Wrong context: a proof is bound to (chain_id, epoch, i, j); replay fails.
    let mut ctx2 = ctx.clone();
    ctx2.epoch = 8;
    assert!(
        !dleq_verify(&ctx2, &h, &ek_pt, &r_pt, &d_pt, &proof),
        "DLEQ proof must not replay across epochs"
    );

    // Tampered proof bytes: flip one bit of z -> verification fails.
    let mut bytes = proof.to_bytes();
    bytes[SCALAR_SIZE] ^= 0x01;
    if let Ok(tampered) = DleqProof::from_bytes(&bytes) {
        assert!(!dleq_verify(&ctx, &h, &ek_pt, &r_pt, &d_pt, &tampered));
    }
}

// ---------------------------------------------------------------------------
// Negative: non-canonical scalar rejection (spec §5.6)
// ---------------------------------------------------------------------------

#[test]
fn vec_neg_non_canonical_scalar_rejected() {
    // Secret scalar >= r is rejected. (SecretScalar has no Debug impl by design,
    // so match on the error rather than unwrap the Ok value.)
    assert!(matches!(
        SecretScalar::from_bytes_le(&[0xFFu8; SCALAR_SIZE]),
        Err(BeaconCryptoError::NonCanonicalScalar)
    ));
    // DLEQ proof with a non-canonical component is rejected at decode.
    assert_eq!(
        DleqProof::from_bytes(&[0xFFu8; 2 * SCALAR_SIZE]).unwrap_err(),
        BeaconCryptoError::NonCanonicalScalar
    );
    // Non-canonical DLEQ nonce is rejected by the prover.
    let ctx = dleq_ctx();
    let (h, ek_pt, r_pt, d_pt, ek, _nonce) = build_dleq_statement();
    assert_eq!(
        dleq_prove(&ctx, &h, &ek_pt, &r_pt, &d_pt, &ek, &[0xFFu8; SCALAR_SIZE]).unwrap_err(),
        BeaconCryptoError::NonCanonicalScalar
    );
}

// ---------------------------------------------------------------------------
// Negative: exactly-T combine misuse
// ---------------------------------------------------------------------------

#[test]
fn vec_neg_combine_misuse() {
    let s = build_sharing();
    let p1 = PartialSignature::new(s.shares[0].0, s.shares[0].1.sign(MSG));

    // Fewer than T partials.
    assert_eq!(
        combine(&[p1]).unwrap_err(),
        BeaconCryptoError::InsufficientPartials { need: 2, got: 1 }
    );

    // Duplicate evaluation point.
    let dup = PartialSignature::new(s.shares[0].0, s.shares[0].1.sign(MSG));
    assert_eq!(
        combine(&[p1, dup]).unwrap_err(),
        BeaconCryptoError::DuplicateEvaluationPoint(1)
    );
}

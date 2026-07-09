//! Fixture: `omninode_buildClaimInferenceReward` signed-submit assembly.
//!
//! Locks the exact client flow the RPC builder + offline signer follow, end to
//! end, with a deterministic Ed25519 seed so the bytes are reproducible:
//!
//! 1. builder output `unsigned_tx` = `bincode(TransactionV2)` (hex);
//! 2. `signing_hash` = `TransactionV2::signing_hash()`;
//! 3. `signature`    = Ed25519 `sign(signing_hash.as_bytes())`;
//! 4. submit raw tx  = `bincode(SignedTransaction { inner: TxInner::V2(tx),
//!    signature, public_key })` (hex), via `SignedTransaction::new_v2(...).to_hex()`;
//! 5. `SignedTransaction::from_hex(raw)` round-trips to an identical value.
//!
//! There is NO raw concatenation anywhere: both `unsigned_tx` and the submit hex
//! are bincode encodings of the whole struct. See the module doc-comments below.

use sumchain_crypto::{sign, verify, KeyPair, Signature};
use sumchain_primitives::inference_settlement::{
    ClaimInferenceRewardRequest, InferenceSettlementOperation, InferenceSettlementTxData,
};
use sumchain_primitives::{
    Address, SignedTransaction, TransactionV2, TxInner, TxPayload, TxType,
};

/// Deterministic 32-byte Ed25519 seed (fixture stability). Real clients use a
/// real keystore; the assembly is identical.
const SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

/// Build the exact `TransactionV2` the `omninode_buildClaimInferenceReward` RPC
/// builder assembles: `TxPayload::InferenceSettlement(ClaimReward { session_id })`.
fn claim_tx(from: Address) -> TransactionV2 {
    let op = InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest {
        session_id: "omni-session-fixture-1".to_string(),
    });
    TransactionV2 {
        chain_id: 1,
        from,
        fee: 1_000,
        nonce: 7,
        payload: TxPayload::InferenceSettlement(InferenceSettlementTxData { operation: op }),
    }
}

#[test]
fn claim_reward_signed_submit_round_trips() {
    // Deterministic signer from the fixed seed.
    let kp = KeyPair::from_bytes(SEED);
    let from = Address::from_public_key(kp.public_key().as_bytes());

    // Fixed claim payload → TransactionV2 (what the builder assembles).
    let tx = claim_tx(from);
    assert_eq!(tx.tx_type(), TxType::InferenceSettlement, "claim is an InferenceSettlement tx");

    // (1) builder `unsigned_tx` == bincode(TransactionV2). `to_bytes()` IS the
    // bincode encoding, so the two must be byte-identical (no raw concat).
    let unsigned_tx = tx.to_bytes();
    assert_eq!(
        unsigned_tx,
        bincode::serialize(&tx).unwrap(),
        "unsigned_tx must be bincode(TransactionV2), not a hand-rolled layout"
    );

    // (2) signing hash over the canonical tx bytes.
    let signing_hash = tx.signing_hash();

    // (3) Ed25519 signature over the signing hash bytes.
    let signature: Signature = sign(signing_hash.as_bytes(), kp.private_key());
    assert!(
        verify(signing_hash.as_bytes(), &signature, kp.public_key()).is_ok(),
        "signature must verify against the signing hash"
    );

    // (4) submit hex = bincode(SignedTransaction { inner: V2(tx), signature, public_key }).
    let signed = SignedTransaction::new_v2(
        tx.clone(),
        signature.to_bytes(),
        *kp.public_key().as_bytes(),
    );
    let raw_tx = signed.to_hex();
    // The submit hex is the bincode of the WHOLE SignedTransaction, not the
    // unsigned bytes with a signature appended.
    assert_eq!(
        raw_tx,
        hex::encode(bincode::serialize(&signed).unwrap()),
        "submit hex must be bincode(SignedTransaction), no raw concat"
    );
    assert_ne!(
        raw_tx,
        hex::encode({
            // The naive-but-WRONG "unsigned || signature" concat must differ.
            let mut v = unsigned_tx.clone();
            v.extend_from_slice(&signature.to_bytes());
            v
        }),
        "submit hex must NOT be unsigned_tx concatenated with the signature"
    );

    // (5) round-trip: from_hex(raw) reproduces the identical SignedTransaction,
    // and the recovered inner tx / signing hash / signature all match.
    let recovered = SignedTransaction::from_hex(&raw_tx).expect("from_hex round-trips");
    assert_eq!(recovered, signed, "SignedTransaction must round-trip through hex");
    assert_eq!(recovered.signature, signature.to_bytes());
    assert_eq!(recovered.public_key, *kp.public_key().as_bytes());
    match &recovered.inner {
        TxInner::V2(inner_tx) => {
            assert_eq!(inner_tx, &tx, "inner V2 tx must be identical after round-trip");
            assert_eq!(inner_tx.signing_hash(), signing_hash, "signing hash stable after round-trip");
            assert!(
                verify(inner_tx.signing_hash().as_bytes(), &signature, kp.public_key()).is_ok(),
                "recovered tx's signature still verifies",
            );
        }
        TxInner::Legacy(_) => panic!("expected a V2 inner transaction"),
    }
}

/// Determinism guard: the same seed + same payload yields byte-identical raw tx.
#[test]
fn claim_reward_assembly_is_deterministic() {
    let build = || {
        let kp = KeyPair::from_bytes(SEED);
        let tx = claim_tx(Address::from_public_key(kp.public_key().as_bytes()));
        let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
        SignedTransaction::new_v2(tx, sig.to_bytes(), *kp.public_key().as_bytes()).to_hex()
    };
    assert_eq!(build(), build(), "assembly must be deterministic for a fixed seed + payload");
}

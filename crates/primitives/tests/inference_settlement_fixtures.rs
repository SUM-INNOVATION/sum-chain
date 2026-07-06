//! Wire-fixture lock for OmniNode Inference Settlement (issue #61).
//!
//! Locks the append-only `TxType`/`TxPayload` variant index (24) and bincode
//! round-trips for every settlement operation, so any accidental reorder or
//! wire-shape drift surfaces as a red test.

use sumchain_primitives::inference_settlement::*;
use sumchain_primitives::{Address, TxPayload, TxType};

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

#[test]
fn txtype_variant_index_is_frozen_at_24() {
    assert_eq!(TxType::InferenceSettlement as u8, 24);
    assert_eq!(TxType::from_byte(24), Some(TxType::InferenceSettlement));
}

#[test]
fn txpayload_bincode_tag_is_24() {
    let payload = TxPayload::InferenceSettlement(InferenceSettlementTxData {
        operation: InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest {
            session_id: "s".to_string(),
        }),
    });
    let bytes = bincode::serialize(&payload).unwrap();
    // bincode encodes the enum variant index as a u32 LE prefix.
    assert_eq!(&bytes[..4], &[24, 0, 0, 0], "TxPayload::InferenceSettlement ordinal must be 24");
}

#[test]
fn all_operations_bincode_round_trip() {
    let ops = vec![
        InferenceSettlementOperation::OpenSession(OpenInferenceSessionRequest {
            session_id: "sess-1".to_string(),
            reward_per_verifier: 1_000_000,
            max_verifiers: 3,
            dispute_window_blocks: 100,
            expires_at_height: 5_000,
            deposit: 3_000_000,
        }),
        InferenceSettlementOperation::FundSession(FundInferenceSessionRequest {
            session_id: "sess-1".to_string(),
            amount: 1_000_000,
        }),
        InferenceSettlementOperation::ClaimReward(ClaimInferenceRewardRequest {
            session_id: "sess-1".to_string(),
        }),
        InferenceSettlementOperation::OpenDispute(OpenInferenceDisputeRequest {
            session_id: "sess-1".to_string(),
            verifier: addr(0xAB),
            evidence_commitment: [7u8; 32],
        }),
        InferenceSettlementOperation::ResolveDispute(ResolveInferenceDisputeRequest {
            session_id: "sess-1".to_string(),
            verifier: addr(0xAB),
            allow_claim: false,
            approvals: vec![],
        }),
        InferenceSettlementOperation::RefundSession(RefundInferenceSessionRequest {
            session_id: "sess-1".to_string(),
        }),
    ];
    for op in ops {
        let data = InferenceSettlementTxData { operation: op.clone() };
        let bytes = bincode::serialize(&data).unwrap();
        let back: InferenceSettlementTxData = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.operation, op);
    }
}

#[test]
fn records_bincode_round_trip() {
    let session = InferenceSession {
        session_id: "sess-1".to_string(),
        funder: addr(0x01),
        reward_per_verifier: 1_000_000,
        max_verifiers: 3,
        remaining_escrow: 3_000_000,
        claims_count: 0,
        dispute_window_blocks: 100,
        status: InferenceSessionStatus::Open,
        created_at_height: 10,
        expires_at_height: 5_000,
    };
    let claim = InferenceClaim {
        session_id: "sess-1".to_string(),
        verifier: addr(0xAB),
        amount: 1_000_000,
        claimed_at_height: 200,
        status: InferenceClaimStatus::Paid,
    };
    let dispute = InferenceDispute {
        session_id: "sess-1".to_string(),
        verifier: addr(0xAB),
        opener: addr(0x01),
        evidence_commitment: [7u8; 32],
        status: InferenceDisputeStatus::ResolvedDenyClaim,
        opened_at_height: 150,
        resolved_at_height: Some(180),
        allow_claim: false,
    };
    assert_eq!(
        bincode::deserialize::<InferenceSession>(&bincode::serialize(&session).unwrap()).unwrap(),
        session
    );
    assert_eq!(
        bincode::deserialize::<InferenceClaim>(&bincode::serialize(&claim).unwrap()).unwrap(),
        claim
    );
    assert_eq!(
        bincode::deserialize::<InferenceDispute>(&bincode::serialize(&dispute).unwrap()).unwrap(),
        dispute
    );
}

#[test]
fn keys_are_domain_separated_and_stable_shape() {
    // Session key is 32 bytes; entry key is 36 bytes = 16-byte prefix + 20-byte addr.
    let sk = session_key("sess-1");
    let ek = settlement_entry_key("sess-1", &addr(0xAB));
    assert_eq!(sk.len(), 32);
    assert_eq!(ek.len(), 36);
    assert_eq!(&ek[..SESSION_PREFIX_BYTES], &session_prefix("sess-1"));
    assert_eq!(&ek[SESSION_PREFIX_BYTES..], addr(0xAB).as_bytes());
    // Distinct sessions ⇒ distinct prefixes/keys.
    assert_ne!(session_key("sess-1"), session_key("sess-2"));
    assert_ne!(session_prefix("sess-1"), session_prefix("sess-2"));
}

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
            consistency: None,
            bond_requirement: None,
        }),
        // A second OpenSession that opts into consistency, to lock its round-trip.
        InferenceSettlementOperation::OpenSession(OpenInferenceSessionRequest {
            session_id: "sess-c".to_string(),
            reward_per_verifier: 1_000_000,
            max_verifiers: 5,
            dispute_window_blocks: 100,
            expires_at_height: 5_000,
            deposit: 3_000_000,
            consistency: Some(InferenceConsistencyConfig { min_matching_verifiers: 3, threshold_bps: 6000 }),
            bond_requirement: Some(InferenceVerifierBondRequirement { min_bond: 5_000_000, slash_bps_on_denied_dispute: 2500 }),
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
        // ── Verifier bonding ops (issue #78), appended variants ──
        InferenceSettlementOperation::RegisterVerifier(RegisterVerifierRequest { bond: 5_000_000 }),
        InferenceSettlementOperation::AddVerifierBond(AddVerifierBondRequest { amount: 1_000_000 }),
        InferenceSettlementOperation::BeginVerifierUnbond,
        InferenceSettlementOperation::WithdrawVerifierBond,
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
        consistency: Some(InferenceConsistencyConfig { min_matching_verifiers: 2, threshold_bps: 0 }),
        bond_requirement: None,
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

// ── Consistency mode (issue #77) — append-only / default-safe ────────────────

#[test]
fn open_request_without_consistency_defaults_to_none() {
    // A pre-#77 JSON payload (no `consistency` key) must decode as `None` so old
    // clients / stored request shapes keep v1 behavior.
    let json = r#"{
        "session_id": "s",
        "reward_per_verifier": 1000000,
        "max_verifiers": 3,
        "dispute_window_blocks": 100,
        "expires_at_height": 5000,
        "deposit": 3000000
    }"#;
    let req: OpenInferenceSessionRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.consistency, None);
}

#[test]
fn session_without_consistency_defaults_to_none() {
    // Same for the stored `InferenceSession` record shape. Build a value, drop the
    // `consistency` key (simulating a pre-#77 record), and confirm it decodes as
    // `None`. Format-agnostic about the `funder` Address encoding.
    let session = InferenceSession {
        session_id: "s".to_string(),
        funder: addr(0x01),
        reward_per_verifier: 1_000_000,
        max_verifiers: 3,
        remaining_escrow: 3_000_000,
        claims_count: 0,
        dispute_window_blocks: 100,
        status: InferenceSessionStatus::Open,
        created_at_height: 10,
        expires_at_height: 5_000,
        consistency: Some(InferenceConsistencyConfig { min_matching_verifiers: 2, threshold_bps: 0 }),
        bond_requirement: None,
    };
    let mut value = serde_json::to_value(&session).unwrap();
    value.as_object_mut().unwrap().remove("consistency");
    let decoded: InferenceSession = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.consistency, None);
}

#[test]
fn consistency_config_round_trips() {
    let cfg = InferenceConsistencyConfig { min_matching_verifiers: 3, threshold_bps: 6667 };
    let back: InferenceConsistencyConfig =
        bincode::deserialize(&bincode::serialize(&cfg).unwrap()).unwrap();
    assert_eq!(back, cfg);
}

// ── Verifier bonding (issue #78) — append-only / default-safe ────────────────

#[test]
fn open_request_without_bond_defaults_to_none() {
    // A pre-#78 JSON payload (no `bond_requirement`) decodes as `None`.
    let json = r#"{
        "session_id": "s",
        "reward_per_verifier": 1000000,
        "max_verifiers": 3,
        "dispute_window_blocks": 100,
        "expires_at_height": 5000,
        "deposit": 3000000
    }"#;
    let req: OpenInferenceSessionRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.bond_requirement, None);
    assert_eq!(req.consistency, None);
}

#[test]
fn verifier_record_and_requirement_round_trip() {
    let rec = InferenceVerifierRecord {
        verifier: addr(0x0C),
        bond: 5_000_000,
        status: InferenceVerifierStatus::Unbonding,
        registered_at_height: 10,
        unbonding_started_height: Some(50),
        unlock_height: Some(250),
    };
    assert_eq!(
        bincode::deserialize::<InferenceVerifierRecord>(&bincode::serialize(&rec).unwrap()).unwrap(),
        rec
    );
    let req = InferenceVerifierBondRequirement { min_bond: 5_000_000, slash_bps_on_denied_dispute: 2500 };
    assert_eq!(
        bincode::deserialize::<InferenceVerifierBondRequirement>(&bincode::serialize(&req).unwrap()).unwrap(),
        req
    );
}

#[test]
fn verifier_status_byte_round_trips() {
    for s in [
        InferenceVerifierStatus::Active,
        InferenceVerifierStatus::Unbonding,
        InferenceVerifierStatus::Withdrawn,
    ] {
        assert_eq!(InferenceVerifierStatus::from_byte(s as u8), Some(s));
    }
    assert_eq!(InferenceVerifierStatus::from_byte(9), None);
}

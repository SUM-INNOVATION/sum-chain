//! Wire/tag safety fixtures for governance v1 (issue #50, Phase 1).
//!
//! These lock the append-only positioning of the new `TxType::Governance` and
//! `TxPayload::Governance` so a later refactor that reorders variants — which
//! would silently re-decode every historical transaction as a different
//! operation — fails CI. bincode encodes a data-enum variant as a u32
//! little-endian tag by declaration ordinal.

use sumchain_primitives::governance::{GovernanceOperation, GovernanceTxData};
use sumchain_primitives::transaction::{TxPayload, TxType};
use sumchain_primitives::Address;

fn gov_payload() -> TxPayload {
    TxPayload::Governance(GovernanceTxData {
        operation: GovernanceOperation::CreateProposal,
        data: vec![],
    })
}

fn variant_tag(payload: &TxPayload) -> u32 {
    let bytes = bincode::serialize(payload).expect("payload encodes");
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[test]
fn tx_type_governance_ordinal_locked() {
    assert_eq!(TxType::Governance as u8, 23);
    assert_eq!(TxType::from_byte(23), Some(TxType::Governance));
    // The previous last discriminant (Education = 22) is unchanged.
    assert_eq!(TxType::Education as u8, 22);
    assert_eq!(TxType::from_byte(22), Some(TxType::Education));
    // 24 is not yet assigned.
    assert_eq!(TxType::from_byte(24), None);
}

#[test]
fn tx_payload_governance_variant_index_locked() {
    // Governance is appended at declaration ordinal 23 (Education = 22).
    // Any reorder above it silently re-numbers historical txs.
    assert_eq!(
        variant_tag(&gov_payload()),
        23,
        "TxPayload::Governance bincode variant tag must be 23 (declaration \
         ordinal, immediately after Education at 22)."
    );
}

#[test]
fn tx_payload_existing_variants_unmoved() {
    // Appending Governance must not renumber any existing variant.
    let transfer = TxPayload::Transfer {
        to: Address::ZERO,
        amount: 0,
    };
    assert_eq!(variant_tag(&transfer), 0, "TxPayload::Transfer must remain bincode tag 0");
    // Governance sits immediately above the prior last variant.
    assert!(
        variant_tag(&gov_payload()) > 22,
        "Governance must be strictly above the pre-existing variants"
    );
}

#[test]
fn governance_txdata_bincode_round_trip() {
    let data = GovernanceTxData {
        operation: GovernanceOperation::CastVote,
        data: vec![1, 2, 3],
    };
    let bytes = bincode::serialize(&data).expect("encodes");
    let back: GovernanceTxData = bincode::deserialize(&bytes).expect("decodes");
    assert_eq!(data, back);
    assert_eq!(GovernanceOperation::from_u8(2), Some(GovernanceOperation::CastVote));
}

// ───────────────────── v1 data-model round-trips (P2) ────────────────────────

use sumchain_primitives::governance::{
    ExecutionKind, ExternalRef, GovAsset, GovAssetKind, GovAssetStatus, GovProposal,
    GovProposalClass, GovProposalStatus, GovVote, VoteChoice, WeightRule,
};

fn round_trip<T>(v: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let bytes = bincode::serialize(v).expect("encodes");
    let back: T = bincode::deserialize(&bytes).expect("decodes");
    assert_eq!(v, &back);
}

#[test]
fn gov_asset_round_trip() {
    round_trip(&GovAsset {
        asset: GovAssetKind::Src20Token([7u8; 32]),
        create_threshold: 1_000,
        vote_weight_rule: WeightRule::Linear,
        status: GovAssetStatus::Enabled,
        effective_height: 42,
    });
}

#[test]
fn gov_proposal_round_trip() {
    round_trip(&GovProposal {
        id: [1u8; 32],
        proposer: Address::new([2u8; 20]),
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/pr/1".into(), content_hash: [3u8; 32] },
        asset: GovAssetKind::Src20Token([7u8; 32]),
        voting_start_height: 100,
        status: GovProposalStatus::Created,
        created_at: 1000,
        created_at_height: 100,
        expires_at: 2000,
    });
}

#[test]
fn gov_vote_round_trip() {
    round_trip(&GovVote {
        proposal_id: [1u8; 32],
        voter: Address::new([9u8; 20]),
        weight: 500,
        choice: VoteChoice::Yes,
        cast_at_height: 101,
    });
}

#[test]
fn gov_enum_discriminants_stable() {
    // Lock the on-wire enum ordering (from_u8 must match repr).
    assert_eq!(GovProposalClass::from_u8(8), Some(GovProposalClass::TreasurySpend));
    assert_eq!(GovProposalStatus::from_u8(0), Some(GovProposalStatus::Created));
    assert_eq!(GovProposalStatus::from_u8(8), Some(GovProposalStatus::Cancelled));
    assert_eq!(VoteChoice::from_u8(2), Some(VoteChoice::Abstain));
    assert_eq!(GovProposalClass::from_u8(9), None);
}

// ───────────────────── P3a: params + request structs + id ────────────────────

use sumchain_primitives::governance::{
    generate_proposal_id, CancelProposalRequest, CastVoteRequest, CreateProposalRequest,
    ExecuteProposalRequest, GovernanceParams, RegisterAssetRequest,
};

#[test]
fn governance_params_round_trip() {
    round_trip(&GovernanceParams {
        council: Address::new([0xC0; 20]),
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 16,
    });
}

#[test]
fn operation_request_structs_round_trip() {
    round_trip(&RegisterAssetRequest { token_id: [7u8; 32], create_threshold: 1_000, effective_height: 42 });
    round_trip(&CreateProposalRequest {
        asset: GovAssetKind::Src20Token([7u8; 32]),
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/pr/1".into(), content_hash: [3u8; 32] },
    });
    round_trip(&CastVoteRequest { proposal_id: [1u8; 32], choice: VoteChoice::Yes });
    round_trip(&ExecuteProposalRequest { proposal_id: [1u8; 32] });
    round_trip(&CancelProposalRequest { proposal_id: [1u8; 32] });
}

#[test]
fn proposal_id_is_deterministic_and_input_sensitive() {
    let proposer = Address::new([2u8; 20]);
    let asset = GovAssetKind::Src20Token([7u8; 32]);
    let ch = [9u8; 32];
    let id = generate_proposal_id(&proposer, &asset, &ch, 100, 1);
    // Deterministic for identical inputs.
    assert_eq!(id, generate_proposal_id(&proposer, &asset, &ch, 100, 1));
    assert_ne!(id, [0u8; 32]);
    // Sensitive to each input (nonce, height, content hash).
    assert_ne!(id, generate_proposal_id(&proposer, &asset, &ch, 100, 2));
    assert_ne!(id, generate_proposal_id(&proposer, &asset, &ch, 101, 1));
    assert_ne!(id, generate_proposal_id(&proposer, &asset, &[8u8; 32], 100, 1));
}

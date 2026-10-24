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
    // 24 is InferenceSettlement (issue #61, appended after Governance); 25 is
    // InferenceAttestationV2 (issue #79, sponsored attestation); 26 is Supply
    // (800B supply correction / service grants); 27 is ComputePool (#130, filled
    // in place); 28/29 are the beacon families (#125).
    assert_eq!(TxType::from_byte(24), Some(TxType::InferenceSettlement));
    assert_eq!(TxType::from_byte(25), Some(TxType::InferenceAttestationV2));
    assert_eq!(TxType::from_byte(26), Some(TxType::Supply));
    assert_eq!(TxType::from_byte(27), Some(TxType::ComputePool));
    assert_eq!(TxType::from_byte(28), Some(TxType::BeaconSetup));
    assert_eq!(TxType::from_byte(29), Some(TxType::BeaconSigning));
    assert_eq!(TxType::from_byte(30), None);
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

/// C5 registry ingress (#242, PROPOSED) is dormant and UNWIRED: operations 8
/// and 9 are not `GovernanceOperation` variants. A governance transaction
/// naming either is refused at decode with the same error an unknown operation
/// always produced (an enum of exactly eight variants), and a block holding
/// one is rejected whole, exactly as on the base this proposal started from.
/// Adding the variants is the separately authorized activation change.
#[test]
fn governance_operations_8_and_9_do_not_decode() {
    use sumchain_primitives::block::Block;
    use sumchain_primitives::{Hash, SignedTransaction, TransactionV2};

    assert_eq!(GovernanceOperation::from_u8(7), Some(GovernanceOperation::CastEquityVote));
    for n in [8u8, 9, 10, 255] {
        assert_eq!(GovernanceOperation::from_u8(n), None);
    }

    // A real governance transaction (operation 7) in a real block, then the
    // same bytes with only the operation index changed.
    let data = vec![0xC5u8; 5];
    let payload = TxPayload::Governance(GovernanceTxData {
        operation: GovernanceOperation::CastEquityVote,
        data: data.clone(),
    });
    let payload_bytes = bincode::serialize(&payload).unwrap();
    let tx = SignedTransaction::new_v2(
        TransactionV2 {
            chain_id: 4242,
            from: Address::ZERO,
            fee: 1,
            nonce: 0,
            payload,
        },
        [0x11; 64],
        [0x22; 32],
    );
    let mut block = Block::genesis(Hash::ZERO, [0x33; 32], 1);
    block.transactions.push(tx.clone());
    let tx_bytes = tx.to_bytes();
    let block_bytes = block.to_bytes();
    assert!(SignedTransaction::from_bytes(&tx_bytes).is_ok());
    assert!(Block::from_bytes(&block_bytes).is_ok());

    // `TxPayload::Governance` tag ‖ operation index ‖ data length ‖ data.
    let marker: Vec<u8> = [
        &23u32.to_le_bytes()[..],
        &7u32.to_le_bytes(),
        &(data.len() as u64).to_le_bytes(),
        &data,
    ]
    .concat();
    let with_op = |bytes: &[u8], op: u32| -> Vec<u8> {
        let at = bytes
            .windows(marker.len())
            .position(|w| w == marker.as_slice())
            .expect("the governance payload is in the encoding");
        assert_eq!(
            bytes.windows(marker.len()).filter(|w| *w == marker.as_slice()).count(),
            1
        );
        let mut out = bytes.to_vec();
        out[at + 4..at + 8].copy_from_slice(&op.to_le_bytes());
        out
    };

    for op in [8u32, 9] {
        let expected =
            format!("invalid value: integer `{op}`, expected variant index 0 <= i < 8");
        // The bare payload, the signed transaction and the block all refuse,
        // each with the unknown-variant error.
        let payload_err = bincode::deserialize::<TxPayload>(&with_op(&payload_bytes, op)).unwrap_err();
        assert_eq!(payload_err.to_string(), expected, "payload, op {op}");
        let tx_err = SignedTransaction::from_bytes(&with_op(&tx_bytes, op)).unwrap_err();
        assert_eq!(tx_err.to_string(), expected, "transaction, op {op}");
        let block_err = Block::from_bytes(&with_op(&block_bytes, op)).unwrap_err();
        assert_eq!(block_err.to_string(), expected, "block, op {op}");
        // The same class as an index that was never assigned.
        assert_eq!(
            SignedTransaction::from_bytes(&with_op(&tx_bytes, 10)).unwrap_err().to_string(),
            "invalid value: integer `10`, expected variant index 0 <= i < 8"
        );
        assert!(matches!(*tx_err, bincode::ErrorKind::Custom(_)));
        assert!(matches!(*block_err, bincode::ErrorKind::Custom(_)));
    }
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
        bond: 500,
        bond_state: sumchain_primitives::governance::BondState::Escrowed,
        treasury_beneficiary: Some(Address::new([0xB0; 20])),
        treasury_amount: Some(1_000),
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
    // Monetary-policy classes (800B correction), appended: 9/10/11; 12 free.
    assert_eq!(GovProposalClass::from_u8(9), Some(GovProposalClass::ReserveReleaseEcosystem));
    assert_eq!(GovProposalClass::from_u8(10), Some(GovProposalClass::ReserveReleaseGovernance));
    assert_eq!(GovProposalClass::from_u8(11), Some(GovProposalClass::MonetaryPolicyMint));
    assert_eq!(GovProposalClass::from_u8(12), None);
}

// ───────────────────── P3a: params + request structs + id ────────────────────

use sumchain_primitives::governance::{
    generate_proposal_id, CancelProposalRequest, CastVoteRequest, CreateProposalRequest,
    ExecuteProposalRequest, GovernanceParams, RegisterAssetRequest,
};

#[test]
fn governance_params_round_trip() {
    round_trip(&GovernanceParams {
        validator_authority_threshold_bps: 6_667,
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 16,
        proposal_bond: 500,
        treasury: Some(Address::new([0xD0; 20])),
        min_koppa_for_eligibility: 1_000,
    });
}

#[test]
fn operation_request_structs_round_trip() {
    round_trip(&RegisterAssetRequest { token_id: [7u8; 32], create_threshold: 1_000, effective_height: 42, approvals: vec![] });
    round_trip(&CreateProposalRequest {
        asset: GovAssetKind::Src20Token([7u8; 32]),
        class: GovProposalClass::TreasurySpend,
        execution_kind: ExecutionKind::OnChain,
        external_ref: ExternalRef { url: "https://x/pr/1".into(), content_hash: [3u8; 32] },
        treasury_beneficiary: Some(Address::new([0xB1; 20])),
        treasury_amount: Some(2_500),
    });
    round_trip(&CastVoteRequest { proposal_id: [1u8; 32], choice: VoteChoice::Yes });
    round_trip(&ExecuteProposalRequest { proposal_id: [1u8; 32] });
    round_trip(&CancelProposalRequest { proposal_id: [1u8; 32], approvals: vec![] });
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

// ───────────────────── Governance v2 (#91 native, #92 equity) ─────────────────

use sumchain_primitives::governance::{
    equity_vote_signing_bytes, CastEquityVoteRequest, RegisterEquityClassRequest,
    RegisterQualifyingAssetRequest,
};

#[test]
fn gov_v2_asset_kind_and_weight_rule_round_trip() {
    round_trip(&GovAsset {
        asset: GovAssetKind::NativeEligibility,
        create_threshold: 0,
        vote_weight_rule: WeightRule::OneAddressOneVote,
        status: GovAssetStatus::Enabled,
        effective_height: 1,
    });
    round_trip(&GovAsset {
        asset: GovAssetKind::EquityClass([0xEC; 32]),
        create_threshold: 100,
        vote_weight_rule: WeightRule::SharesTimesVotesPerShare,
        status: GovAssetStatus::Enabled,
        effective_height: 5,
    });
}

#[test]
fn gov_v2_request_structs_round_trip() {
    round_trip(&RegisterQualifyingAssetRequest {
        token_id: [7u8; 32],
        min_balance: 50,
        effective_height: 10,
        approvals: vec![],
    });
    round_trip(&RegisterEquityClassRequest {
        class_id: [0xEC; 32],
        create_threshold: 100,
        effective_height: 10,
        approvals: vec![],
    });
    round_trip(&CastEquityVoteRequest {
        proposal_id: [1u8; 32],
        holder_commitment: [2u8; 32],
        shares: 1234,
        merkle_path: vec![[3u8; 32], [4u8; 32]],
        controller_pubkey: [5u8; 32],
        controller_sig: [6u8; 64],
        choice: VoteChoice::Yes,
    });
}

#[test]
fn gov_v2_proposal_id_variants_distinct() {
    let proposer = Address::new([2u8; 20]);
    let ch = [9u8; 32];
    let src20 = generate_proposal_id(&proposer, &GovAssetKind::Src20Token([7u8; 32]), &ch, 100, 1);
    let native = generate_proposal_id(&proposer, &GovAssetKind::NativeEligibility, &ch, 100, 1);
    let equity = generate_proposal_id(&proposer, &GovAssetKind::EquityClass([7u8; 32]), &ch, 100, 1);
    assert_ne!(src20, native);
    assert_ne!(src20, equity);
    assert_ne!(native, equity);
}

#[test]
fn equity_vote_signing_bytes_bind_all_fields() {
    let a = equity_vote_signing_bytes(1, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 10, &Address::new([5u8; 20]));
    // Deterministic.
    assert_eq!(a, equity_vote_signing_bytes(1, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 10, &Address::new([5u8; 20])));
    // Sensitive to every field.
    assert_ne!(a, equity_vote_signing_bytes(2, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 10, &Address::new([5u8; 20])));
    assert_ne!(a, equity_vote_signing_bytes(1, &[9u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 10, &Address::new([5u8; 20])));
    assert_ne!(a, equity_vote_signing_bytes(1, &[1u8; 32], &[9u8; 32], &[3u8; 32], &[4u8; 32], 10, &Address::new([5u8; 20])));
    assert_ne!(a, equity_vote_signing_bytes(1, &[1u8; 32], &[2u8; 32], &[9u8; 32], &[4u8; 32], 10, &Address::new([5u8; 20])));
    assert_ne!(a, equity_vote_signing_bytes(1, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[9u8; 32], 10, &Address::new([5u8; 20])));
    assert_ne!(a, equity_vote_signing_bytes(1, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 99, &Address::new([5u8; 20])));
    assert_ne!(a, equity_vote_signing_bytes(1, &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], 10, &Address::new([9u8; 20])));
}

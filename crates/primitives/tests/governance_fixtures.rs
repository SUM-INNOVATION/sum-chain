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

//! Append-only GOLDEN VECTORS for the C1 pool ids RATIFIED on 2026-10-16
//! (G1-1..G1-3): `offer_bond_id`, `reservation_id`, `entitlement_id`, and the
//! `EntitlementKind` map with its occurrence rule.
//!
//! The `*_HEX` constants are copied byte for byte from the ratified proposal's
//! `vectors.json` (`docs/proposals/c1-pool-id-kdfs/`, sum-chain 6fde77fa), whose
//! values two independent generators reproduced. Each vector pins three things:
//!  * the **layout**: the preimage rebuilt here field by field from the tag
//!    constant and little-endian integers equals the frozen preimage;
//!  * the **hash**: BLAKE3 of that preimage equals the frozen output;
//!  * the **implementation**: the production function reproduces the output.
//!
//! Append-only: never edit an existing constant; only add new ones.
//!
//! **Architecture independence is structural**: every field is fixed-width and
//! explicitly little-endian, so these vectors are identical on x86_64 and
//! aarch64, and CI runs this suite on both.
//!
//! `job_id` and `unit_id` are frozen and unchanged; they appear here only as
//! inputs, via their own frozen KATs. `legacy_session_id_hash` is deferred.

use sumchain_wire::b0::codec::DecodeError;
use sumchain_wire::compute_pool_graph::*;
use sumchain_wire::registry_wire::{GRAPH_DEFINITION_TAG, TOKENIZER_ID_TAG, VK_ID_TAG};
use sumchain_wire::Address;

// ── Frozen tags. ─────────────────────────────────────────────────────────────
const OFFERBOND_TAG_HEX: &str = "53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a";
const RESERVATION_TAG_HEX: &str = "53554d434841494e2f504f4f4c2f5245534552564154494f4e2f76310a";
const ENTITLEMENT_TAG_HEX: &str = "53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a";

// ── Frozen vectors (inputs: the frozen job/unit KAT inputs, offer_seq 7,
//    generation 1; byte-order vectors use distinct bytes in every position). ──

// offer_bond_id/base (63-byte preimage)
const OFFER_BASE_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a01000000000000000102030405060708090a0b0c0d0e0f10111213140700000000000000";
const OFFER_BASE_HEX: &str = "98fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8debea7a1a4ea";

// offer_bond_id/chain_id_2 (63-byte preimage)
const OFFER_CHAIN_2_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a02000000000000000102030405060708090a0b0c0d0e0f10111213140700000000000000";
const OFFER_CHAIN_2_HEX: &str = "85181c227b1f434961fdbdb1f9a3050871b04c3592149c7c7175d09245d78851";

// offer_bond_id/byte_order (63-byte preimage)
const OFFER_BYTE_ORDER_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a0102030405060708ffffffffffffffffffffffffffffffffffffffff8877665544332211";
const OFFER_BYTE_ORDER_HEX: &str =
    "5826d4c3a89fd1374b06f69b10a9531300786cee60f07a2e73ad1e815cde071e";

// reservation_id/base (133-byte preimage)
const RESERVATION_BASE_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f5245534552564154494f4e2f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662010000000000000098fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8debea7a1a4ea";
const RESERVATION_BASE_HEX: &str =
    "1b251c9b56949e5b383b618003331f50b19acd98234ca7d73adef5fc66624c4f";

// entitlement_id/accept_reimb (106-byte preimage)
const ENT_ACCEPT_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266201000000000000000000000000";
const ENT_ACCEPT_HEX: &str = "7377c94d7668f3347e779acac43a4110951ee9c8423468c3172b6605d302da27";

// entitlement_id/reassign_reimb_occurrence_2 (106-byte preimage)
const ENT_REASSIGN_OCC_2_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266201000000000000000102000000";
const ENT_REASSIGN_OCC_2_HEX: &str =
    "f0fc9e68ce981ce200d82502657b195179ba8bee94dc16d82fca4b149aac23c9";

// entitlement_id/reprovision_reimb (106-byte preimage)
const ENT_REPROVISION_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266201000000000000000200000000";
const ENT_REPROVISION_HEX: &str =
    "11d1849a4a75b45140cb801fe3d33ffac1d40a2680ebf1d164c1018b23de7b89";

// entitlement_id/reassign_reimb_byte_order (106-byte preimage)
const ENT_REASSIGN_BYTE_ORDER_PREIMAGE_HEX: &str =
    "53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266208070605040302010104030201";
const ENT_REASSIGN_BYTE_ORDER_HEX: &str =
    "66d885ec3397304cd5bf211e784aa73277d0aeb98baec256c3372f9a80d9105f";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn h32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

/// The frozen §K KAT requester, `0x01..0x14`; also the offer sender here.
fn kat_sender() -> Address {
    let mut a = [0u8; 20];
    for (i, b) in a.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    Address::new(a)
}

/// The frozen `job_id` KAT: chain 1, requester `0x01..0x14`, nonce 7, salt 0xAA.
fn kat_job() -> [u8; 32] {
    job_id(1, &kat_sender(), 7, &[0xAA; 32])
}

/// The frozen `unit_id` KAT: unit 0 of [`kat_job`].
fn kat_unit() -> [u8; 32] {
    unit_id(&kat_job(), 0)
}

/// Pin one vector: field-by-field preimage == frozen preimage (layout),
/// BLAKE3(preimage) == frozen output (hash), production fn == output (impl).
fn pin(built: Vec<u8>, preimage_hex: &str, preimage_len: usize, derived: [u8; 32], out_hex: &str) {
    assert_eq!(built.len(), preimage_len, "preimage length");
    assert_eq!(
        hex::encode(&built),
        preimage_hex,
        "frozen preimage layout changed"
    );
    assert_eq!(
        hex::encode(blake3::hash(&built).as_bytes()),
        out_hex,
        "BLAKE3 of the frozen preimage"
    );
    assert_eq!(hex::encode(derived), out_hex, "derivation changed");
}

fn offer_preimage(chain_id: u64, sender: &Address, offer_seq: u64) -> Vec<u8> {
    let mut p = POOL_OFFERBOND_TAG.to_vec();
    p.extend_from_slice(&chain_id.to_le_bytes());
    p.extend_from_slice(sender.as_bytes());
    p.extend_from_slice(&offer_seq.to_le_bytes());
    p
}

fn entitlement_preimage(gen: u64, kind: u8, occurrence: u32) -> Vec<u8> {
    let mut p = POOL_ENTITLEMENT_TAG.to_vec();
    p.extend_from_slice(&kat_job());
    p.extend_from_slice(&kat_unit());
    p.extend_from_slice(&gen.to_le_bytes());
    p.push(kind);
    p.extend_from_slice(&occurrence.to_le_bytes());
    p
}

// ── Inputs and tags. ─────────────────────────────────────────────────────────

#[test]
fn inputs_are_the_frozen_job_and_unit_kats() {
    assert_eq!(
        hex::encode(kat_job()),
        "8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82"
    );
    assert_eq!(
        hex::encode(kat_unit()),
        "3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662"
    );
}

#[test]
fn tags_are_the_ratified_bytes() {
    for (tag, hex_, len) in [
        (POOL_OFFERBOND_TAG, OFFERBOND_TAG_HEX, 27),
        (POOL_RESERVATION_TAG, RESERVATION_TAG_HEX, 29),
        (POOL_ENTITLEMENT_TAG, ENTITLEMENT_TAG_HEX, 29),
    ] {
        assert_eq!(hex::encode(tag), hex_);
        assert_eq!(tag.len(), len);
        assert!(tag.is_ascii());
        assert_eq!(*tag.last().unwrap(), b'\n', "POOL family is \\n-terminated");
        assert_eq!(tag.iter().filter(|&&b| b == b'\n').count(), 1);
    }
}

/// No tag of the POOL or REGISTRY families equals or prefixes another, so no
/// preimage of one id can be read as a preimage of another.
#[test]
fn every_pool_and_registry_tag_is_prefix_free() {
    let tags: [&[u8]; 9] = [
        POOL_JOB_TAG,
        POOL_UNIT_TAG,
        POOL_GRAPHDEF_TAG,
        POOL_OFFERBOND_TAG,
        POOL_RESERVATION_TAG,
        POOL_ENTITLEMENT_TAG,
        VK_ID_TAG,
        TOKENIZER_ID_TAG,
        GRAPH_DEFINITION_TAG,
    ];
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert!(!b.starts_with(a), "{a:?} prefixes {b:?}");
            }
        }
    }
}

// ── offer_bond_id. ───────────────────────────────────────────────────────────

#[test]
fn golden_offer_bond_id_base() {
    pin(
        offer_preimage(1, &kat_sender(), 7),
        OFFER_BASE_PREIMAGE_HEX,
        63,
        offer_bond_id(1, &kat_sender(), 7),
        OFFER_BASE_HEX,
    );
}

#[test]
fn golden_offer_bond_id_chain_id_2() {
    pin(
        offer_preimage(2, &kat_sender(), 7),
        OFFER_CHAIN_2_PREIMAGE_HEX,
        63,
        offer_bond_id(2, &kat_sender(), 7),
        OFFER_CHAIN_2_HEX,
    );
}

#[test]
fn golden_offer_bond_id_byte_order() {
    let sender = Address::new([0xFF; 20]);
    let (chain_id, seq) = (0x0807_0605_0403_0201, 0x1122_3344_5566_7788);
    pin(
        offer_preimage(chain_id, &sender, seq),
        OFFER_BYTE_ORDER_PREIMAGE_HEX,
        63,
        offer_bond_id(chain_id, &sender, seq),
        OFFER_BYTE_ORDER_HEX,
    );
}

/// The chain id separates offer ids: the two preimages differ only in the
/// `chain_id` field (offset 27, 8 bytes), and the ids differ.
#[test]
fn chain_id_separates_offer_bond_ids() {
    let (a, b) = (
        unhex(OFFER_BASE_PREIMAGE_HEX),
        unhex(OFFER_CHAIN_2_PREIMAGE_HEX),
    );
    let differing: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert!(differing.iter().all(|i| (27..35).contains(i)));
    assert_ne!(OFFER_BASE_HEX, OFFER_CHAIN_2_HEX);
}

// ── reservation_id. ──────────────────────────────────────────────────────────

#[test]
fn golden_reservation_id_base() {
    let offer = offer_bond_id(1, &kat_sender(), 7);
    assert_eq!(offer, h32(OFFER_BASE_HEX));
    let mut p = POOL_RESERVATION_TAG.to_vec();
    p.extend_from_slice(&kat_job());
    p.extend_from_slice(&kat_unit());
    p.extend_from_slice(&1u64.to_le_bytes());
    p.extend_from_slice(&offer);
    pin(
        p,
        RESERVATION_BASE_PREIMAGE_HEX,
        133,
        reservation_id(&kat_job(), &kat_unit(), 1, &offer),
        RESERVATION_BASE_HEX,
    );
}

// ── entitlement_id. ──────────────────────────────────────────────────────────

fn ent(gen: u64, kind: EntitlementKind, occurrence: u32) -> [u8; 32] {
    entitlement_id(&kat_job(), &kat_unit(), gen, kind, occurrence).expect("derives")
}

#[test]
fn golden_entitlement_id_accept_reimb() {
    pin(
        entitlement_preimage(1, 0, 0),
        ENT_ACCEPT_PREIMAGE_HEX,
        106,
        ent(1, EntitlementKind::AcceptReimb, 0),
        ENT_ACCEPT_HEX,
    );
}

#[test]
fn golden_entitlement_id_reassign_reimb_occurrence_2() {
    pin(
        entitlement_preimage(1, 1, 2),
        ENT_REASSIGN_OCC_2_PREIMAGE_HEX,
        106,
        ent(1, EntitlementKind::ReassignReimb, 2),
        ENT_REASSIGN_OCC_2_HEX,
    );
}

#[test]
fn golden_entitlement_id_reprovision_reimb() {
    pin(
        entitlement_preimage(1, 2, 0),
        ENT_REPROVISION_PREIMAGE_HEX,
        106,
        ent(1, EntitlementKind::ReprovisionReimb, 0),
        ENT_REPROVISION_HEX,
    );
}

#[test]
fn golden_entitlement_id_reassign_reimb_byte_order() {
    let (gen, occ) = (0x0102_0304_0506_0708, 0x0102_0304);
    pin(
        entitlement_preimage(gen, 1, occ),
        ENT_REASSIGN_BYTE_ORDER_PREIMAGE_HEX,
        106,
        ent(gen, EntitlementKind::ReassignReimb, occ),
        ENT_REASSIGN_BYTE_ORDER_HEX,
    );
}

/// The id names the event: equal inputs give equal ids (so a second payment
/// of one event collides), and each counted ReassignReimb occurrence is a
/// distinct id.
#[test]
fn entitlement_ids_name_events() {
    assert_eq!(
        ent(1, EntitlementKind::AcceptReimb, 0),
        ent(1, EntitlementKind::AcceptReimb, 0)
    );
    let reassigns: Vec<[u8; 32]> = (0..4)
        .map(|o| ent(1, EntitlementKind::ReassignReimb, o))
        .collect();
    for (i, a) in reassigns.iter().enumerate() {
        for b in &reassigns[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_ne!(
        ent(1, EntitlementKind::AcceptReimb, 0),
        ent(2, EntitlementKind::AcceptReimb, 0),
        "generation separates work items"
    );
}

// ── The kind map and the occurrence rule. ────────────────────────────────────

#[test]
fn entitlement_kind_map_is_frozen() {
    for (kind, v) in [
        (EntitlementKind::AcceptReimb, 0u8),
        (EntitlementKind::ReassignReimb, 1),
        (EntitlementKind::ReprovisionReimb, 2),
    ] {
        assert_eq!(kind.to_u8(), v);
        assert_eq!(EntitlementKind::from_u8(v), Ok(kind));
    }
    assert!(EntitlementKind::ReassignReimb.is_repeatable());
    assert!(!EntitlementKind::AcceptReimb.is_repeatable());
    assert!(!EntitlementKind::ReprovisionReimb.is_repeatable());
}

/// Refused: kinds 3 and 255 (the ratified examples) and every value between.
#[test]
fn reserved_entitlement_kinds_are_refused() {
    for v in 3..=255u8 {
        assert_eq!(
            EntitlementKind::from_u8(v),
            Err(DecodeError::ReservedEnum {
                name: "EntitlementKind",
                value: v as u64
            })
        );
    }
}

/// Refused: a nonzero occurrence for a one-time kind (the ratified examples,
/// occurrence 1, and the extreme).
#[test]
fn one_time_kinds_refuse_a_nonzero_occurrence() {
    for kind in [
        EntitlementKind::AcceptReimb,
        EntitlementKind::ReprovisionReimb,
    ] {
        for occ in [1u32, 2, u32::MAX] {
            assert!(matches!(
                entitlement_id(&kat_job(), &kat_unit(), 1, kind, occ),
                Err(DecodeError::BadFixedScalar { value, .. }) if value == occ as u64
            ));
        }
    }
    assert!(entitlement_id(
        &kat_job(),
        &kat_unit(),
        1,
        EntitlementKind::ReassignReimb,
        u32::MAX
    )
    .is_ok());
}

//! Append-only GOLDEN FIXTURES + ordinal-stability tests for the BR1 randomness
//! beacon (#125), frozen by owner OPTION B (2026-07).
//!
//! These pin the byte-stable surface the owner ratified as FROZEN:
//!  * the five carrier encodings (`schema_version = 1`);
//!  * the `0xBE01..=0xBE05` beacon op sub-tags;
//!  * the two-slot **phase** allocation `TxType::BeaconSetup = 28` /
//!    `BeaconSigning = 29` and their `from_byte` mapping (27 stays C1-reserved);
//!  * the `TxPayload` bincode encoding of a beacon transaction (the appended
//!    declaration ordinals 27/28, and the frozen carrier bytes embedded verbatim).
//!
//! The `*_HEX` constants below were emitted once by the carriers' own `try_encode`
//! / `to_bytes`; the production encoders MUST reproduce them byte-for-byte forever
//! (append-only — never edit an existing constant; only add new ones).

use sumchain_wire::beacon_wire::*;
use sumchain_wire::transaction::{BeaconTxData, TransactionV2, TxPayload, TxType};
use sumchain_wire::Address;

// ── Frozen carrier encodings (schema_version = 1). ─────────────────────────────
const KEY_HEX: &str = "52424b31763100010008070605040302012a00000000000000802121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
const DEAL_HEX: &str = "444b444c763100010007000000000000000900000000000000010000000300000002000000804141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141804242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242805151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060606060";
const COMPLAINT_HEX: &str = "444b435076310001000b000000000000000d00000000000000020000000400000080717171717171717171717171717171717171717171717171717171717171717171717171717171717171717171717180727272727272727272727272727272727272727272727272727272727272727272727272727272727272727272727201010101010101010101010101010101010101010101010101010101010101000202020202020202020202020202020202020202020202020202020202020200";
const PARTIAL_HEX: &str = "42505254763100010011100f0e0d0c0b0a0700000000000000050000000000000003000000808181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181";
const FINALIZE_HEX: &str = "42464e4c7631000100998877665544332208000000000000000600000000000000808282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282828282020000000000000001000000";

// ── Frozen TxPayload/TransactionV2 bincode (registration; appended ordinals). ──
const TX_SETUP_HEX: &str = "08070605040302011111111111111111111111111111111111111111e803000000000000000000000000000007000000000000001b000000a90000000000000052424b31763100010008070605040302012a00000000000000802121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
const TX_SIGNING_HEX: &str = "11100f0e0d0c0b0a1111111111111111111111111111111111111111e803000000000000000000000000000007000000000000001c000000850000000000000042505254763100010011100f0e0d0c0b0a0700000000000000050000000000000003000000808181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181818181";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn g1(b: u8) -> [u8; G1_LEN] {
    let mut p = [b; G1_LEN];
    p[0] = 0x80;
    p
}
fn g2(b: u8) -> [u8; G2_LEN] {
    let mut p = [b; G2_LEN];
    p[0] = 0x80;
    p
}
fn sc(b: u8) -> [u8; SCALAR_LEN] {
    let mut s = [b; SCALAR_LEN];
    s[SCALAR_LEN - 1] = 0x00;
    s
}

fn key() -> RegisterBeaconKeyV1 {
    RegisterBeaconKeyV1 {
        chain_id: 0x0102_0304_0506_0708,
        epoch: 42,
        ek_j: g1(0x21),
        pop: [0x33; POP_LEN],
    }
}
fn deal() -> DkgDealV1 {
    DkgDealV1 {
        chain_id: 7,
        epoch: 9,
        dealer_i: 1,
        recipient_j: 3,
        commitments: vec![g1(0x41), g1(0x42)],
        r_ij: g1(0x51),
        ct_ij: [0x60; CT_LEN],
    }
}
fn complaint() -> DkgComplaintV1 {
    DkgComplaintV1 {
        chain_id: 11,
        epoch: 13,
        i: 2,
        j: 4,
        r_ij: g1(0x71),
        d_ij: g1(0x72),
        dleq_c: sc(0x01),
        dleq_z: sc(0x02),
    }
}
fn partial() -> BeaconPartialV1 {
    BeaconPartialV1 {
        chain_id: 0x0A0B_0C0D_0E0F_1011,
        epoch: 7,
        round: 5,
        j: 3,
        sigma_j: g2(0x81),
    }
}
fn finalize() -> BeaconFinalizeV1 {
    BeaconFinalizeV1 {
        chain_id: 0x2233_4455_6677_8899,
        epoch: 8,
        round: 6,
        sigma_r: g2(0x82),
        witness: vec![0, 1],
    }
}

// ── (1) Carrier golden: encode == frozen hex, decode round-trips. ──────────────
#[test]
fn carrier_bytes_are_frozen_and_roundtrip() {
    assert_eq!(hex::encode(key().try_encode().unwrap()), KEY_HEX);
    assert_eq!(hex::encode(deal().try_encode().unwrap()), DEAL_HEX);
    assert_eq!(
        hex::encode(complaint().try_encode().unwrap()),
        COMPLAINT_HEX
    );
    assert_eq!(hex::encode(partial().try_encode().unwrap()), PARTIAL_HEX);
    assert_eq!(hex::encode(finalize().try_encode().unwrap()), FINALIZE_HEX);

    assert_eq!(
        RegisterBeaconKeyV1::decode_exact(&unhex(KEY_HEX)).unwrap(),
        key()
    );
    assert_eq!(DkgDealV1::decode_exact(&unhex(DEAL_HEX)).unwrap(), deal());
    assert_eq!(
        DkgComplaintV1::decode_exact(&unhex(COMPLAINT_HEX)).unwrap(),
        complaint()
    );
    assert_eq!(
        BeaconPartialV1::decode_exact(&unhex(PARTIAL_HEX)).unwrap(),
        partial()
    );
    assert_eq!(
        BeaconFinalizeV1::decode_exact(&unhex(FINALIZE_HEX)).unwrap(),
        finalize()
    );
}

// ── (2) BeaconOperation dispatch golden: same bytes, decode by magic. ──────────
#[test]
fn beacon_operation_dispatch_golden() {
    // A BeaconOperation encodes exactly the wrapped carrier's frozen bytes.
    let op = BeaconOperation::BeaconFinalize(finalize());
    assert_eq!(hex::encode(op.try_encode().unwrap()), FINALIZE_HEX);
    // Every carrier's frozen bytes dispatch back to the right BeaconOperation.
    for (hexstr, want) in [
        (KEY_HEX, BeaconWireOp::RegisterBeaconKey),
        (DEAL_HEX, BeaconWireOp::DkgDeal),
        (COMPLAINT_HEX, BeaconWireOp::DkgComplaint),
        (PARTIAL_HEX, BeaconWireOp::BeaconPartial),
        (FINALIZE_HEX, BeaconWireOp::BeaconFinalize),
    ] {
        let decoded = BeaconOperation::decode_exact(&unhex(hexstr)).unwrap();
        assert_eq!(decoded.wire_op(), want);
        assert_eq!(hex::encode(decoded.try_encode().unwrap()), hexstr);
    }
}

// ── (3) Op sub-tag ordinals are FROZEN (0xBE01..=0xBE05). ──────────────────────
#[test]
fn op_subtags_are_frozen() {
    assert_eq!(BeaconWireOp::RegisterBeaconKey.to_repr(), 0xBE01);
    assert_eq!(BeaconWireOp::DkgDeal.to_repr(), 0xBE02);
    assert_eq!(BeaconWireOp::DkgComplaint.to_repr(), 0xBE03);
    assert_eq!(BeaconWireOp::BeaconPartial.to_repr(), 0xBE04);
    assert_eq!(BeaconWireOp::BeaconFinalize.to_repr(), 0xBE05);
    // Round-trip through the namespaced decoder.
    for &op in BeaconWireOp::ALL {
        assert_eq!(BeaconWireOp::from_repr(op.to_repr()).unwrap(), op);
    }
}

// ── (4) Top-level TxType ordinals are FROZEN; 27 stays C1-reserved. ────────────
#[test]
fn txtype_ordinals_are_frozen_and_stable() {
    // Discriminants never change.
    assert_eq!(TxType::BeaconSetup as u8, 28);
    assert_eq!(TxType::BeaconSigning as u8, 29);
    // from_byte mapping: 27 unregistered (C1), 28/29 the beacon phases.
    assert_eq!(TxType::from_byte(27), None);
    assert_eq!(TxType::from_byte(28), Some(TxType::BeaconSetup));
    assert_eq!(TxType::from_byte(29), Some(TxType::BeaconSigning));
    // The phase→ordinal split reported by the ops matches the frozen slots.
    assert_eq!(BeaconWireOp::RegisterBeaconKey.top_level_txtype(), 28);
    assert_eq!(BeaconWireOp::DkgDeal.top_level_txtype(), 28);
    assert_eq!(BeaconWireOp::DkgComplaint.top_level_txtype(), 28);
    assert_eq!(BeaconWireOp::BeaconPartial.top_level_txtype(), 29);
    assert_eq!(BeaconWireOp::BeaconFinalize.top_level_txtype(), 29);
}

// ── (5) TxPayload bincode golden: appended ordinals + embedded frozen bytes. ───
#[test]
fn txpayload_beacon_bincode_is_frozen_and_roundtrips() {
    let setup_op = BeaconOperation::RegisterBeaconKey(key());
    let tx_setup = TransactionV2 {
        chain_id: 0x0102_0304_0506_0708,
        from: Address::new([0x11; 20]),
        fee: 1000,
        nonce: 7,
        payload: TxPayload::BeaconSetup(BeaconTxData::from_operation(&setup_op).unwrap()),
    };
    assert_eq!(hex::encode(tx_setup.to_bytes()), TX_SETUP_HEX);
    let back = TransactionV2::from_bytes(&unhex(TX_SETUP_HEX)).unwrap();
    assert_eq!(back, tx_setup);
    assert_eq!(back.tx_type(), TxType::BeaconSetup);
    assert_eq!(back.tx_type() as u8, 28);

    let signing = TransactionV2 {
        chain_id: 0x0A0B_0C0D_0E0F_1011,
        from: Address::new([0x11; 20]),
        fee: 1000,
        nonce: 7,
        payload: TxPayload::BeaconSigning(
            BeaconTxData::from_operation(&BeaconOperation::BeaconPartial(partial())).unwrap(),
        ),
    };
    assert_eq!(hex::encode(signing.to_bytes()), TX_SIGNING_HEX);
    let back2 = TransactionV2::from_bytes(&unhex(TX_SIGNING_HEX)).unwrap();
    assert_eq!(back2, signing);
    assert_eq!(back2.tx_type(), TxType::BeaconSigning);
    assert_eq!(back2.tx_type() as u8, 29);

    // The outer bincode enum tag (declaration ordinal) sits right after
    // chain_id(u64=8) + from(20) + fee(Balance=u128=16) + nonce(u64=8) = offset
    // 52, as a u32_le. The beacon variants are APPENDED after Supply, so their
    // tags are 27 and 28 — exactly the C1 gap below their TxType discriminants
    // (28/29). Freezing this guards against any reorder that would shift the
    // beacon bytes.
    const TAG_OFFSET: usize = 8 + 20 + 16 + 8;
    let setup_bytes = unhex(TX_SETUP_HEX);
    let tag_setup = u32::from_le_bytes(setup_bytes[TAG_OFFSET..TAG_OFFSET + 4].try_into().unwrap());
    assert_eq!(
        tag_setup, 27,
        "BeaconSetup declaration ordinal must stay 27"
    );
    let signing_bytes = unhex(TX_SIGNING_HEX);
    let tag_signing = u32::from_le_bytes(
        signing_bytes[TAG_OFFSET..TAG_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        tag_signing, 28,
        "BeaconSigning declaration ordinal must stay 28"
    );

    // The frozen carrier bytes are embedded verbatim after an 8-byte length prefix.
    assert!(hex::encode(&setup_bytes).contains(KEY_HEX));
    assert!(hex::encode(&signing_bytes).contains(PARTIAL_HEX));

    // The wrapped payload decodes back to the right beacon operation.
    if let TxPayload::BeaconSetup(d) = &back.payload {
        assert_eq!(d.decode_operation().unwrap(), setup_op);
    } else {
        panic!("expected BeaconSetup payload");
    }
}

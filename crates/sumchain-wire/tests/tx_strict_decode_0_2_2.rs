//! sumchain-wire 0.2.2 — strict trailing-byte rejection for the two remaining
//! primary tx decode entry points (`TransactionV2::from_bytes`, legacy
//! `Transaction::from_bytes`) plus proof that `MessageHeader::from_bytes` stays
//! PERMISSIVE by design.
//!
//! This test lives inside the published wire crate (packaged via the
//! `tests/**/*.rs` include glob) so the crate is self-verifying on crates.io.
//!
//! Structure:
//!   (a) byte-lock: pin the canonical hex the UNCHANGED encoder emits for one
//!       legacy `Transaction`, one `TransactionV2` transfer, and one
//!       `SignedTransaction`; assert `to_bytes() == frozen hex` and that
//!       `from_bytes(frozen)` round-trips. Proves 0.2.2 changed zero bytes on
//!       the accepted canonical byte set.
//!   (b) negatives: a valid encoding + trailing byte(s) is now REJECTED for
//!       `TransactionV2` and `Transaction` (the only behavioral delta).
//!   (c) positive: a 72-byte `MessageHeader` followed by body bytes still
//!       parses and equals the header (locks the permissive prefix parse).

use sumchain_wire::{
    Address, ContentType, MessageFlags, MessageHeader, SignedTransaction, Transaction,
    TransactionV2, SRC201_HEADER_SIZE, SRC201_MAGIC, SRC201_VERSION,
};

// ── Frozen canonical hex (identical to the pre-0.2.2 encoder output; the same
//    bytes locked by crates/primitives/tests/wire_golden_fixtures.rs). ─────────
const LEGACY_TX_HEX: &str = "010000000000000011111111111111111111111111111111111111112222222222222222222222222222222222222222e80300000000000000000000000000000a0000000000000000000000000000000700000000000000";
const V2_TX_HEX: &str = "010000000000000011111111111111111111111111111111111111110a0000000000000000000000000000000700000000000000000000002222222222222222222222222222222222222222e8030000000000000000000000000000";
const SIGNED_LEGACY_HEX: &str = "00000000010000000000000011111111111111111111111111111111111111112222222222222222222222222222222222222222e80300000000000000000000000000000a0000000000000000000000000000000700000000000000ababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

const SIG: [u8; 64] = [0xAB; 64];
const PK: [u8; 32] = [0xCD; 32];

fn sample_legacy() -> Transaction {
    Transaction::new(1, Address::new([0x11; 20]), Address::new([0x22; 20]), 1000, 10, 7)
}
fn sample_v2() -> TransactionV2 {
    TransactionV2::transfer(1, Address::new([0x11; 20]), Address::new([0x22; 20]), 1000, 10, 7)
}
fn sample_signed() -> SignedTransaction {
    SignedTransaction::new(sample_legacy(), SIG, PK)
}

// ── (a) Byte-lock: encoder output is byte-identical + canonical decodes. ──────

#[test]
fn legacy_transaction_bytes_are_frozen_and_round_trip() {
    let lt = sample_legacy();
    assert_eq!(hex::encode(lt.to_bytes()), LEGACY_TX_HEX);
    let decoded = Transaction::from_bytes(&hex::decode(LEGACY_TX_HEX).unwrap()).unwrap();
    assert_eq!(decoded, lt);
}

#[test]
fn transaction_v2_bytes_are_frozen_and_round_trip() {
    let vt = sample_v2();
    assert_eq!(hex::encode(vt.to_bytes()), V2_TX_HEX);
    let decoded = TransactionV2::from_bytes(&hex::decode(V2_TX_HEX).unwrap()).unwrap();
    assert_eq!(decoded, vt);
}

#[test]
fn signed_transaction_bytes_are_frozen_and_round_trip() {
    let st = sample_signed();
    assert_eq!(hex::encode(st.to_bytes()), SIGNED_LEGACY_HEX);
    let decoded = SignedTransaction::from_bytes(&hex::decode(SIGNED_LEGACY_HEX).unwrap()).unwrap();
    assert_eq!(decoded, st);
}

// ── (b) Negatives: trailing bytes now REJECTED for the two hardened types. ────

#[test]
fn transaction_v2_from_bytes_rejects_trailing_byte() {
    let good = sample_v2().to_bytes();
    assert!(TransactionV2::from_bytes(&good).is_ok()); // canonical still accepted

    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(TransactionV2::from_bytes(&trailing).is_err()); // +1 trailing byte rejected

    let mut arb = good.clone();
    arb.extend_from_slice(&[0xDE, 0xAD]);
    assert!(TransactionV2::from_bytes(&arb).is_err()); // arbitrary trailing rejected

    let mut dbl = good.clone();
    dbl.extend_from_slice(&good);
    assert!(TransactionV2::from_bytes(&dbl).is_err()); // prefix + 2nd full tx rejected

    assert!(TransactionV2::from_bytes(&good[..good.len() - 1]).is_err()); // truncation still rejected
}

#[test]
fn legacy_transaction_from_bytes_rejects_trailing_byte() {
    let good = sample_legacy().to_bytes();
    assert!(Transaction::from_bytes(&good).is_ok()); // canonical still accepted

    let mut trailing = good.clone();
    trailing.push(0xFF);
    assert!(Transaction::from_bytes(&trailing).is_err()); // +1 trailing byte rejected

    let mut arb = good.clone();
    arb.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(Transaction::from_bytes(&arb).is_err()); // arbitrary trailing rejected

    assert!(Transaction::from_bytes(&good[..good.len() - 1]).is_err()); // truncation still rejected
}

// ── (c) Positive: MessageHeader stays PERMISSIVE (prefix parse; body follows). ─

fn sample_header() -> MessageHeader {
    MessageHeader {
        magic: SRC201_MAGIC,
        version: SRC201_VERSION,
        flags: MessageFlags::encrypted(),
        content_type: ContentType::TextPlain,
        attachment_count: 0,
        recipient_hash: [1u8; 32],
        ephemeral_pubkey: [2u8; 32],
    }
}

#[test]
fn message_header_from_bytes_still_accepts_trailing_body_bytes() {
    let header = sample_header();
    let mut framed = header.to_bytes().to_vec(); // exactly the 72-byte header
    assert_eq!(framed.len(), SRC201_HEADER_SIZE);
    framed.extend_from_slice(&[0xAB; 40]); // simulated body (nonce/ciphertext/tag in real frames)

    let parsed =
        MessageHeader::from_bytes(&framed).expect("header prefix must parse with body appended");
    // The trailing body is intentionally ignored by the fixed-size prefix parse.
    assert_eq!(parsed, header);
}

//! Byte-identical parity between the removed `ethers` implementation and the
//! `ethabi` one (#206).
//!
//! Every expected value here was **captured from the ethers implementation
//! before it was deleted**, by encoding through `ethers::abi` on the
//! pre-migration tree. They are committed baseline vectors, not values derived
//! from the new code, so they are an independent oracle: if the migration moved
//! one byte of a selector, calldata, address, integer or array encoding, a test
//! below fails.
//!
//! Why byte-identity is structural rather than lucky: `ethers::abi` **was**
//! `ethabi`. Keeping the same signatures keeps the same keccak preimages, so the
//! selectors and topic hashes cannot drift.
//!
//! Scope note: the bridge performs **no Ethereum signing**. Its provider is
//! read-only, and the "signatures" in `BridgeConfig` are SUM validator
//! signatures, not secp256k1 ones. The parity surface is therefore ABI encoding,
//! event topics, address/integer conversion, and decode rejection.

use ethabi::ethereum_types::{H160, H256, U256};
use ethabi::{ParamType, Token};
use sumchain_bridge::ethereum::abi;
use sumchain_bridge::EthAddress;

// ── Committed baseline vectors, captured from ethers ────────────────────────
const SEL_DEPOSIT: &str = "26b3293f";
const SEL_WITHDRAW: &str = "b26a434e";
const SEL_PAUSED: &str = "5c975abb";
const SEL_TOTAL_LOCKED: &str = "d8fb9337";

const TOPIC0_DEPOSIT: &str =
    "76bb911c362d5b1feb3058bc7dc9354703e4b6eb9c61cc845f73da880cf62f61";
const TOPIC0_WITHDRAWAL: &str =
    "2717ead6b9200dd235aad468c9809ea400fe33ac69b5bfaa6d3e90fc922b6398";

/// `deposit(0x1111…11, 1e18, 0xABAB…AB)` — full encoded payload.
const CALL_DEPOSIT: &str = "26b3293f\
0000000000000000000000001111111111111111111111111111111111111111\
0000000000000000000000000000000000000000000000000de0b6b3a7640000\
abababababababababababababababababababababababababababababababab";

fn token_addr() -> H160 {
    H160::from_slice(&[0x11u8; 20])
}

#[test]
fn function_selectors_are_unchanged() {
    assert_eq!(hex::encode(abi::deposit().short_signature()), SEL_DEPOSIT);
    assert_eq!(hex::encode(abi::withdraw().short_signature()), SEL_WITHDRAW);
    assert_eq!(hex::encode(abi::paused().short_signature()), SEL_PAUSED);
    assert_eq!(
        hex::encode(abi::total_locked().short_signature()),
        SEL_TOTAL_LOCKED
    );
}

#[test]
fn event_topic0_hashes_are_unchanged() {
    assert_eq!(hex::encode(abi::deposit_event().signature()), TOPIC0_DEPOSIT);
    assert_eq!(
        hex::encode(abi::withdrawal_event().signature()),
        TOPIC0_WITHDRAWAL
    );
}

/// The whole encoded payload, not just the selector — wrong argument packing
/// would still produce a correct selector.
#[test]
fn deposit_calldata_is_byte_identical() {
    let data = abi::deposit()
        .encode_input(&[
            Token::Address(token_addr()),
            Token::Uint(U256::from(1_000_000_000_000_000_000u128)),
            Token::FixedBytes(H256::from([0xAB; 32]).as_bytes().to_vec()),
        ])
        .expect("encodes");
    assert_eq!(hex::encode(&data), CALL_DEPOSIT);
}

/// `bytes[]` is the only dynamic argument in the ABI, and dynamic encoding is
/// where an ABI port is most likely to drift: it carries an offset, a length,
/// then per-element offset/length/padded-data. Pinned explicitly.
#[test]
fn withdraw_dynamic_array_encoding_is_correct() {
    let data = abi::withdraw()
        .encode_input(&[
            Token::Address(token_addr()),
            Token::Uint(U256::from(255u64)),
            Token::Address(H160::from_slice(&[0x22u8; 20])),
            Token::Array(vec![
                Token::Bytes(vec![0xAA, 0xBB]),
                Token::Bytes(vec![0xCC]),
            ]),
        ])
        .expect("encodes");
    let hexed = hex::encode(&data);

    assert!(hexed.starts_with(SEL_WITHDRAW), "selector changed");
    // head: token, amount, recipient, then the offset to the array (0x80 = 128).
    assert!(
        hexed.contains("00000000000000000000000000000000000000000000000000000000000000ff"),
        "uint256 255 not encoded big-endian padded"
    );
    assert!(
        hexed.contains("0000000000000000000000000000000000000000000000000000000000000080"),
        "dynamic array head offset missing"
    );
    // array length 2, then element bytes right-padded in 32-byte words.
    assert!(hexed.contains("aabb0000"), "element 0 payload missing/mispadded");
    assert!(hexed.contains("cc0000"), "element 1 payload missing/mispadded");

    // And it round-trips back to the same tokens.
    let back = abi::withdraw()
        .decode_input(&data[4..])
        .expect("decodes its own encoding");
    assert_eq!(back.len(), 4);
    assert_eq!(back[3], Token::Array(vec![
        Token::Bytes(vec![0xAA, 0xBB]),
        Token::Bytes(vec![0xCC]),
    ]));
}

/// Address conversion must reinterpret the same 20 bytes in both directions.
#[test]
fn address_conversion_round_trips_byte_for_byte() {
    let raw = [
        0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x01, 0x02, 0x03, 0x04, 0x05,
    ];
    let eth = EthAddress::from_bytes(raw);
    let h: H160 = eth.into();
    assert_eq!(h.0, raw, "EthAddress -> H160 moved bytes");
    let back: EthAddress = h.into();
    assert_eq!(back, eth, "round trip is not lossless");
}

#[test]
fn zero_address_is_preserved() {
    let h: H160 = EthAddress::ZERO.into();
    assert_eq!(h, H160::zero());
    let back: EthAddress = h.into();
    assert_eq!(back, EthAddress::ZERO);
}

/// Integer encoding is big-endian, left-padded to 32 bytes, at both extremes.
#[test]
fn integer_encoding_is_unchanged_at_the_boundaries() {
    let enc = |v: U256| {
        hex::encode(ethabi::encode(&[Token::Uint(v)]))
    };
    assert_eq!(
        enc(U256::zero()),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        enc(U256::from(1u8)),
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(
        enc(U256::from(1_000_000_000_000_000_000u128)),
        "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
    );
    assert_eq!(
        enc(U256::max_value()),
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    // Decimal/hex rendering, as ethers produced it for 1e18.
    let amount = U256::from(1_000_000_000_000_000_000u128);
    assert_eq!(amount.to_string(), "1000000000000000000");
    assert_eq!(format!("{amount:x}"), "de0b6b3a7640000");
}

// ── Malformed-input rejection ───────────────────────────────────────────────
//
// A decoder that accepts truncated or over-long input is how a malformed log or
// return value becomes silent corruption. Each case must be REFUSED.

#[test]
fn truncated_calldata_is_refused() {
    let full = hex::decode(CALL_DEPOSIT).unwrap();
    let body = &full[4..];
    for cut in [1usize, 8, 31, 32, 64] {
        let short = &body[..body.len() - cut];
        assert!(
            abi::deposit().decode_input(short).is_err(),
            "truncated by {cut} byte(s) was accepted"
        );
    }
}

#[test]
fn empty_input_for_a_function_with_arguments_is_refused() {
    assert!(abi::deposit().decode_input(&[]).is_err());
    assert!(abi::total_locked().decode_input(&[]).is_err());
}

#[test]
fn a_wrong_shaped_dynamic_array_is_refused() {
    // Array head offset points past the end of the payload.
    let mut bad = vec![0u8; 32];
    bad[31] = 0xFF; // offset 255 into a 32-byte buffer
    assert!(
        ethabi::decode(&[ParamType::Array(Box::new(ParamType::Bytes))], &bad).is_err(),
        "out-of-range dynamic offset was accepted"
    );
}

#[test]
fn decoding_the_wrong_type_does_not_silently_succeed() {
    // 32 bytes of 0xFF is a valid uint256 but not a valid `bool`.
    let ones = [0xFFu8; 32];
    assert!(ethabi::decode(&[ParamType::Bool], &ones).is_err());
}

/// The selector must be BOUND to the input signature, so a future edit that
/// changes a parameter type cannot keep the frozen selector constants above
/// silently valid.
///
/// Asserted by construction rather than against `Function::signature()`, whose
/// ethabi rendering appends return types (`paused():(bool)`) and is a display
/// form, not the canonical ABI signature the selector hashes.
#[test]
fn selector_is_bound_to_the_input_signature() {
    use ethabi::{Function, Param, StateMutability};

    // Same name, one parameter type changed: the selector MUST move.
    let tampered = Function {
        name: "deposit".into(),
        inputs: vec![
            Param { name: "token".into(), kind: ParamType::Address, internal_type: None },
            // uint256 -> uint128
            Param { name: "amount".into(), kind: ParamType::Uint(128), internal_type: None },
            Param { name: "sumRecipient".into(), kind: ParamType::FixedBytes(32), internal_type: None },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    assert_ne!(
        hex::encode(tampered.short_signature()),
        SEL_DEPOSIT,
        "changing a parameter type did not change the selector"
    );

    // Same name, one parameter dropped: also must move.
    let dropped = Function {
        name: "deposit".into(),
        inputs: vec![
            Param { name: "token".into(), kind: ParamType::Address, internal_type: None },
            Param { name: "amount".into(), kind: ParamType::Uint(256), internal_type: None },
        ],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::Payable,
    };
    assert_ne!(hex::encode(dropped.short_signature()), SEL_DEPOSIT);

    // Return types must NOT affect the selector (they are not hashed).
    let mut with_outputs = abi::deposit();
    with_outputs.outputs = vec![Param {
        name: "".into(),
        kind: ParamType::Bool,
        internal_type: None,
    }];
    assert_eq!(
        hex::encode(with_outputs.short_signature()),
        SEL_DEPOSIT,
        "outputs must not participate in the selector"
    );
}

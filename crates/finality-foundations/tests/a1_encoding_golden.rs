//! Golden vectors and boundary tests for G2 byte group A1, RATIFIED
//! 2026-10-17: D0 (little-endian in objects and preimages, big-endian only in
//! database keys), D4 (`u32` rounds, `round ≤ 2^20`) and D2 (no explicit
//! validator count in a certificate).
//!
//! APPEND-ONLY: never change an existing vector; add new ones below. The
//! workspace tests run on x86_64 and aarch64, so every vector is checked on
//! both architectures.
//!
//! The composite records and keys below are SYNTHETIC field sequences that
//! pin byte order and strictness. They are not the layout of any vote,
//! certificate, signer state, evidence, manifest, hint or database key; those
//! layouts are unratified.

use sumchain_finality_foundations::certificate::{
    check_signers, quorum, SignerSetError, ValidatorSetResolver,
};
use sumchain_finality_foundations::encoding::{
    DecodeError, KeyReader, KeyWriter, LeReader, LeWriter, Round, RoundOutOfRange, MAX_ROUND,
};
use sumchain_finality_foundations::Digest;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- D0: byte order ------------------------------------------------------

#[test]
fn d0_object_integers_are_little_endian() {
    let mut w = LeWriter::new();
    w.u16(0x0102).u32(0x0102_0304).u64(0x0102_0304_0506_0708);
    assert_eq!(hex(&w.into_bytes()), "0201040302010807060504030201");
}

#[test]
fn d0_key_integers_are_big_endian() {
    let mut w = KeyWriter::new();
    w.u16(0x0102).u32(0x0102_0304).u64(0x0102_0304_0506_0708);
    assert_eq!(hex(&w.into_bytes()), "0102010203040102030405060708");
}

#[test]
fn d0_the_two_orders_differ_for_the_same_value() {
    let mut le = LeWriter::new();
    le.u64(7);
    let mut be = KeyWriter::new();
    be.u64(7);
    assert_eq!(hex(&le.into_bytes()), "0700000000000000");
    assert_eq!(hex(&be.into_bytes()), "0000000000000007");
}

#[test]
fn d0_big_endian_keys_sort_numerically() {
    let key = |h: u64| {
        let mut w = KeyWriter::new();
        w.u64(h);
        w.into_bytes()
    };
    let heights = [0u64, 1, 255, 256, 65_535, 65_536, 1 << 32, u64::MAX];
    for pair in heights.windows(2) {
        assert!(key(pair[0]) < key(pair[1]), "{} vs {}", pair[0], pair[1]);
    }
    // Little-endian would not sort: 256 encodes below 255.
    let le = |h: u64| h.to_le_bytes().to_vec();
    assert!(le(256) < le(255));
}

#[test]
fn d0_round_trip_of_a_synthetic_le_record() {
    // SYNTHETIC: schema u16 = 1, height u64 = 7, round u32 = 3, flag = 1,
    // a 4-byte absent group. Not an object layout.
    let vector = concat!("0100", "0700000000000000", "03000000", "01", "00000000");
    let mut w = LeWriter::new();
    w.u16(1)
        .u64(7)
        .round(Round::new(3).unwrap())
        .flag(true)
        .zeros(4);
    let bytes = w.into_bytes();
    assert_eq!(hex(&bytes), vector);

    let mut r = LeReader::new(&bytes);
    assert_eq!(r.u16().unwrap(), 1);
    assert_eq!(r.u64().unwrap(), 7);
    assert_eq!(r.round().unwrap().get(), 3);
    assert!(r.flag().unwrap());
    r.zeros(4).unwrap();
    r.finish().unwrap();
}

#[test]
fn d0_round_trip_of_a_synthetic_key() {
    // SYNTHETIC: u64 = 7, u32 = 3, u8 = 2, u16 = 1, 4 bytes 0xaa. Not a key layout.
    let mut w = KeyWriter::new();
    w.u64(7)
        .round(Round::new(3).unwrap())
        .u8(2)
        .u16(1)
        .bytes(&[0xaa; 4]);
    let bytes = w.into_bytes();
    assert_eq!(
        hex(&bytes),
        concat!("0000000000000007", "00000003", "02", "0001", "aaaaaaaa")
    );

    let mut r = KeyReader::new(&bytes);
    assert_eq!(r.u64().unwrap(), 7);
    assert_eq!(r.round().unwrap().get(), 3);
    assert_eq!(r.u8().unwrap(), 2);
    assert_eq!(r.u16().unwrap(), 1);
    assert_eq!(r.array::<4>().unwrap(), [0xaa; 4]);
    r.finish().unwrap();
}

// ---- Strict decoding ------------------------------------------------------

#[test]
fn strict_truncation_is_refused() {
    let bytes = unhex("0807060504030201");
    for cut in 0..bytes.len() {
        let mut r = LeReader::new(&bytes[..cut]);
        assert_eq!(
            r.u64(),
            Err(DecodeError::Truncated {
                needed: 8,
                remaining: cut
            })
        );
        let mut k = KeyReader::new(&bytes[..cut]);
        assert!(matches!(k.u64(), Err(DecodeError::Truncated { .. })));
    }
}

#[test]
fn strict_trailing_bytes_are_refused() {
    let bytes = unhex("07000000000000000000");
    let mut r = LeReader::new(&bytes);
    assert_eq!(r.u64().unwrap(), 7);
    assert_eq!(r.finish(), Err(DecodeError::Trailing(2)));

    let mut k = KeyReader::new(&bytes);
    k.u64().unwrap();
    assert_eq!(k.finish(), Err(DecodeError::Trailing(2)));
}

#[test]
fn strict_flag_bytes_are_zero_or_one() {
    for b in 0u8..=255 {
        let r = LeReader::new(&[b]).flag();
        match b {
            0 => assert_eq!(r, Ok(false)),
            1 => assert_eq!(r, Ok(true)),
            _ => assert_eq!(r, Err(DecodeError::BadFlag(b))),
        }
    }
}

#[test]
fn strict_absent_groups_are_all_zero() {
    LeReader::new(&[0; 32]).zeros(32).unwrap();
    for i in 0..32 {
        let mut g = [0u8; 32];
        g[i] = 1;
        assert_eq!(
            LeReader::new(&g).zeros(32),
            Err(DecodeError::NonZeroAbsentGroup(32))
        );
    }
    assert!(matches!(
        LeReader::new(&[0; 31]).zeros(32),
        Err(DecodeError::Truncated { .. })
    ));
}

// ---- D4: rounds ------------------------------------------------------------

#[test]
fn d4_cap_is_two_to_the_twentieth() {
    assert_eq!(MAX_ROUND, 1_048_576);
    assert_eq!(Round::MAX.get(), 1 << 20);
    assert_eq!(Round::ZERO.get(), 0);
}

#[test]
fn d4_construction_boundaries() {
    assert_eq!(Round::new(0).unwrap().get(), 0);
    assert_eq!(Round::new(MAX_ROUND).unwrap(), Round::MAX);
    assert_eq!(
        Round::new(MAX_ROUND + 1),
        Err(RoundOutOfRange(MAX_ROUND + 1))
    );
    assert_eq!(Round::new(u32::MAX), Err(RoundOutOfRange(u32::MAX)));
    assert_eq!(Round::try_from(MAX_ROUND - 1).unwrap().get(), MAX_ROUND - 1);
    assert_eq!(Round::MAX.next(), None);
    assert_eq!(Round::new(MAX_ROUND - 1).unwrap().next(), Some(Round::MAX));
    assert_eq!(u32::from(Round::new(9).unwrap()), 9);
}

#[test]
fn d4_round_encodings() {
    // (value, little-endian object bytes, big-endian key bytes)
    let vectors = [
        (0u32, "00000000", "00000000"),
        (1, "01000000", "00000001"),
        (MAX_ROUND, "00001000", "00100000"),
    ];
    for (v, le, be) in vectors {
        let r = Round::new(v).unwrap();
        let mut w = LeWriter::new();
        w.round(r);
        assert_eq!(hex(&w.into_bytes()), le, "LE {v}");
        let mut k = KeyWriter::new();
        k.round(r);
        assert_eq!(hex(&k.into_bytes()), be, "BE {v}");
        assert_eq!(LeReader::new(&unhex(le)).round().unwrap(), r);
        assert_eq!(KeyReader::new(&unhex(be)).round().unwrap(), r);
    }
}

#[test]
fn d4_decode_refuses_rounds_above_the_cap() {
    // 2^20 + 1 and u32::MAX, in both byte orders.
    let refused = [
        (MAX_ROUND + 1, "01001000", "00100001"),
        (u32::MAX, "ffffffff", "ffffffff"),
    ];
    for (v, le, be) in refused {
        assert_eq!(
            LeReader::new(&unhex(le)).round(),
            Err(DecodeError::Round(RoundOutOfRange(v)))
        );
        assert_eq!(
            KeyReader::new(&unhex(be)).round(),
            Err(DecodeError::Round(RoundOutOfRange(v)))
        );
    }
}

// ---- D2: signer count implied by the validator-set commitment ---------------

struct Sets(Vec<(Digest, u16)>);

impl ValidatorSetResolver for Sets {
    fn validator_count(&self, commitment: &Digest) -> Option<u16> {
        self.0
            .iter()
            .find(|(c, _)| c == commitment)
            .map(|(_, n)| *n)
    }
}

const SET2: Digest = [0x02; 32];
const SET4: Digest = [0x04; 32];
const EMPTY: Digest = [0x00; 32];
const UNKNOWN: Digest = [0xff; 32];

fn sets() -> Sets {
    Sets(vec![(SET2, 2), (SET4, 4), (EMPTY, 0)])
}

#[test]
fn d2_quorum_table() {
    let expected = [
        (1u16, 1u16),
        (2, 2),
        (3, 3),
        (4, 3),
        (5, 4),
        (6, 5),
        (7, 5),
        (100, 67),
    ];
    for (n, q) in expected {
        assert_eq!(quorum(n), q, "n = {n}");
    }
    assert_eq!(quorum(u16::MAX), 43_691);
}

#[test]
fn d2_count_comes_from_the_named_set() {
    let s = sets();
    let two = check_signers(&SET2, &[0, 1], &s).unwrap();
    assert_eq!(two.validator_count(), 2);
    assert_eq!(two.indices(), &[0, 1]);
    // The same entries check against a different n under another commitment.
    assert_eq!(
        check_signers(&SET4, &[0, 1], &s),
        Err(SignerSetError::BelowQuorum {
            k: 2,
            quorum: 3,
            n: 4
        })
    );
    assert_eq!(
        check_signers(&SET4, &[0, 1, 3], &s)
            .unwrap()
            .validator_count(),
        4
    );
    assert_eq!(
        check_signers(&SET4, &[0, 1, 2, 3], &s)
            .unwrap()
            .indices()
            .len(),
        4
    );
}

#[test]
fn d2_refusals() {
    let s = sets();
    assert_eq!(
        check_signers(&UNKNOWN, &[0, 1], &s),
        Err(SignerSetError::UnknownValidatorSet)
    );
    assert_eq!(
        check_signers(&EMPTY, &[], &s),
        Err(SignerSetError::EmptyValidatorSet)
    );
    // k > n
    assert_eq!(
        check_signers(&SET2, &[0, 1, 2], &s),
        Err(SignerSetError::AboveSetSize { k: 3, n: 2 })
    );
    // k < q(n): q(4) = 3
    assert_eq!(
        check_signers(&SET4, &[0, 3], &s),
        Err(SignerSetError::BelowQuorum {
            k: 2,
            quorum: 3,
            n: 4
        })
    );
    // index out of range
    assert_eq!(
        check_signers(&SET4, &[0, 1, 4], &s),
        Err(SignerSetError::IndexOutOfRange { index: 4, n: 4 })
    );
    // duplicate
    assert_eq!(
        check_signers(&SET4, &[0, 1, 1], &s),
        Err(SignerSetError::NotStrictlyAscending {
            previous: 1,
            index: 1
        })
    );
    // descending
    assert_eq!(
        check_signers(&SET4, &[0, 2, 1], &s),
        Err(SignerSetError::NotStrictlyAscending {
            previous: 2,
            index: 1
        })
    );
}

#[test]
fn d2_quorum_matches_the_bootstrap_membership_quorum() {
    use sumchain_finality_foundations::bootstrap::Membership;
    for n in 1u16..=200 {
        let m = Membership {
            members: vec![vec![0u8; 32]; usize::from(n)],
            commitment: [0u8; 32],
        };
        assert_eq!(usize::from(quorum(n)), m.quorum(), "n = {n}");
    }
}

//! BR1 beacon — DRAFT domain / ciphersuite / transcript-layout vectors
//! (issue #127; see `docs/design/BR1-BEACON-SECURITY-SPEC-DRAFT.md`).
//!
//! DRAFT SPEC-TRACK VECTORS ONLY — NOT CONSENSUS. This file adds **no** BLS/pairing
//! code and does **not** implement or activate any consensus cryptography. It
//! recomputes, with the in-tree `blake3` / `sha2` crates, byte strings and byte
//! layouts and asserts them against constants derived **independently** (Python
//! `hashlib` for SHA-256; the `b3sum` CLI for BLAKE3). Matching two independent
//! implementations is the point — a self-referential "assert what we just
//! computed" check would prove nothing.
//!
//! The vectors fall in TWO classes:
//!
//! NORMATIVE (bytes fixed by an external standard):
//!   T-1  the three BLS ciphersuite / RFC 9380 hash-to-curve identifier strings
//!        (exact ASCII, length, SHA-256 fingerprint). Authorities:
//!        draft-irtf-cfrg-bls-signature-05 (2022-06-16) §4/§3.3 for the two
//!        `BLS_SIG_…_POP_` / `BLS_POP_…_POP_` strings; RFC 9380 (2023-08) §8.8.2
//!        for `BLS12381G2_XMD:SHA-256_SSWU_RO_`.
//!   T-2  little-endian u64 encoding (a standard integer encoding).
//!
//! PROPOSED — OWNER DECISION, NOT ADOPTED (a concrete #127 proposal checked for
//! self-consistency; these are **NOT frozen consensus bytes**):
//!   T-3  PROPOSED genesis-seed preimage layout + its BLAKE3 digest (synthetic in).
//!   T-4  PROPOSED round-message + OUT preimage layout + BLAKE3 digest (synthetic).
//!   T-5  PROPOSED domain-tag prefix-freeness (no proposed tag is a prefix of
//!        another). The beacon/DLEQ/ECIES tag strings are owner decisions (spec
//!        §12.1) that have not been adopted.
//!
//! WHAT IS NOT LOCKED (bytes undetermined — see spec §14.2): RFC 9380 point-level
//! hash-to-curve vectors and BLS sign/verify/PoP vectors (need a BLS12-381
//! implementation not in this crate); DLEQ transcript bytes and ECIES ciphertext
//! bytes (OPEN primitive choices); W1b tx ordinals and #125-owned encodings;
//! activation heights / MARGIN. None of those are asserted here.
//!
//! IMPORTANT: the T-3 / T-4 tags and layouts are PROPOSED owner decisions, not
//! consensus; their inputs (`chain_id`, `genesis_params_hash`, compressed points)
//! are **explicitly synthetic**. They check a proposed concatenation ORDER and
//! field WIDTHS, not any adopted or live-chain value. They must never be read as
//! the real chain's genesis seed or beacon output.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// NORMATIVE ciphersuite / hash-to-curve identifier strings (standard-fixed).
// See spec §2.1.
// ---------------------------------------------------------------------------

const CS_SIGN: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const CS_POP: &str = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const CS_H2C: &str = "BLS12381G2_XMD:SHA-256_SSWU_RO_";

// ---------------------------------------------------------------------------
// PROPOSED domain-separation tags — OWNER DECISIONS, NOT ADOPTED. These are a
// concrete #127 proposal (spec §12.1, §5.3, §8); they are NOT ratified consensus
// strings. The T-3/T-4/T-5 checks below validate self-consistency of the
// proposal, not any adopted byte layout.
// ---------------------------------------------------------------------------

const TAG_GENESIS: &[u8] = b"OMNINODE-BEACON-GENESIS:v1:";
const TAG_ROUND: &[u8] = b"OMNINODE-BEACON-ROUND:v1:";
const TAG_OUT: &[u8] = b"OMNINODE-BEACON-OUT:v1:";
const TAG_DLEQ: &[u8] = b"OMNINODE-DKG-DLEQ:v1:";
const TAG_ECIES_KEY: &[u8] = b"OMNINODE-DKG-ECIES:v1:key";
const TAG_ECIES_AAD: &[u8] = b"OMNINODE-DKG-ECIES:v1:aad";

fn sha256_hex(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

fn blake3_hex(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

// ---------------------------------------------------------------------------
// T-1 (NORMATIVE) — ciphersuite / hash-to-curve identifier strings.
//   Authorities pinned per string:
//     CS_SIGN, CS_POP : draft-irtf-cfrg-bls-signature-05 (2022-06-16),
//                       §4 Ciphersuites (POP variant, `..._POP_`); PoP §3.3.
//     CS_H2C          : RFC 9380 (2023-08, final), §8.8.2 "BLS12-381 G2" suite.
//   Expected hex + SHA-256 independently computed with Python hashlib.
// ---------------------------------------------------------------------------
#[test]
fn t1_ciphersuite_identifier_bytes() {
    // (string, expected_len, expected_ascii_hex, expected_sha256_hex)
    let cases = [
        (
            CS_SIGN,
            43usize,
            "424c535f5349475f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f",
            "0075dd56b0bab673a13ae85bc7cb54f280ca9149b5cdda11ddd7f9354fb2abf1",
        ),
        (
            CS_POP,
            43,
            "424c535f504f505f424c53313233383147325f584d443a5348412d3235365f535357555f524f5f504f505f",
            "6006a4acdfca2ebb06493170a6a187d3dfb8e8f0b4f6f4360f1beb7e8d13167c",
        ),
        (
            CS_H2C,
            31,
            "424c53313233383147325f584d443a5348412d3235365f535357555f524f5f",
            "55bc7f259ec0129d21b98bce804afb0e5cb029601795fd2f0c9b4581b049f3e2",
        ),
    ];
    for (s, len, ascii_hex, sha) in cases {
        let b = s.as_bytes();
        assert_eq!(b.len(), len, "length mismatch for {s}");
        assert_eq!(hex::encode(b), ascii_hex, "ASCII hex mismatch for {s}");
        assert_eq!(sha256_hex(b), sha, "SHA-256 fingerprint mismatch for {s}");
    }

    // Cross-check the fixed structural substrings that make these the POP scheme
    // over G2 with the RFC 9380 SSWU_RO_ map (guards against silent edits).
    assert!(CS_SIGN.starts_with("BLS_SIG_"));
    assert!(CS_POP.starts_with("BLS_POP_"));
    assert!(CS_SIGN.ends_with("_SSWU_RO_POP_"));
    assert!(CS_POP.ends_with("_SSWU_RO_POP_"));
    assert!(CS_H2C.ends_with("_SSWU_RO_"));
    assert!(CS_SIGN.contains("BLS12381G2_XMD:SHA-256"));
}

// ---------------------------------------------------------------------------
// T-2 (NORMATIVE) — little-endian u64 encoding (a standard integer encoding).
//   (Its *placement* in the beacon message layout, by contrast, is PROPOSED —
//   see T-4.)
// ---------------------------------------------------------------------------
#[test]
fn t2_u64_le_encoding() {
    let cases: [(u64, &str); 5] = [
        (1, "0100000000000000"),
        (3, "0300000000000000"),
        (7, "0700000000000000"),
        (256, "0001000000000000"),
        (u64::MAX, "ffffffffffffffff"),
    ];
    for (v, expect) in cases {
        assert_eq!(hex::encode(v.to_le_bytes()), expect, "u64_le({v})");
    }
}

// ---------------------------------------------------------------------------
// Synthetic (ILLUSTRATIVE, NOT LIVE) inputs for the PROPOSED T-3 / T-4 layouts.
// They exercise a PROPOSED (owner decision, not adopted) concatenation order +
// field widths only. Real chain_id / genesis_params_hash / points are
// deployment-owned (chain_id encoding: #125/W1b).
// ---------------------------------------------------------------------------
const SYN_CHAIN_ID: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
const SYN_GENESIS_PARAMS_HASH: [u8; 32] = [0x11; 32];
const SYN_EPOCH: u64 = 7;
const SYN_ROUND: u64 = 3;
const SYN_SIGMA_PREV: [u8; 96] = [0x22; 96]; // stand-in compressed G2
const SYN_SIGMA_R: [u8; 96] = [0x33; 96]; // stand-in compressed G2

// ---------------------------------------------------------------------------
// T-3 (PROPOSED — owner decision, NOT adopted) — genesis seed preimage layout +
//   BLAKE3 digest. NOT frozen consensus bytes; validates a PROPOSED construction.
//   Sigma_0_seed = blake3( TAG_GENESIS || chain_id || genesis_params_hash )
//   Expected preimage hex + BLAKE3 digest independently computed (Python concat
//   + `b3sum`); inputs synthetic.
// ---------------------------------------------------------------------------
#[test]
fn t3_proposed_genesis_seed_layout() {
    let mut pre = Vec::new();
    pre.extend_from_slice(TAG_GENESIS);
    pre.extend_from_slice(&SYN_CHAIN_ID);
    pre.extend_from_slice(&SYN_GENESIS_PARAMS_HASH);

    assert_eq!(pre.len(), 63, "genesis preimage length");
    assert_eq!(
        hex::encode(&pre),
        "4f4d4e494e4f44452d424541434f4e2d47454e455349533a76313aaabbccdd\
1111111111111111111111111111111111111111111111111111111111111111",
        "PROPOSED genesis preimage layout (order/widths) mismatch"
    );
    // BLAKE3 digest cross-checked against the independent `b3sum` implementation.
    // PROPOSED, synthetic inputs — NOT a consensus value.
    assert_eq!(
        blake3_hex(&pre),
        "c4e8a81a8b3cc11b6e03fb6b48d1b88322bad4d598c912194f0f2e62b6e04481",
        "PROPOSED genesis seed BLAKE3 digest (synthetic inputs) mismatch"
    );
}

// ---------------------------------------------------------------------------
// T-4 (PROPOSED — owner decision, NOT adopted) — round message + OUT preimage
//   layouts + BLAKE3 digests. NOT frozen consensus bytes.
//   m_r      = TAG_ROUND || chain_id || u64_le(epoch) || u64_le(round) || compress(Sigma_prev)
//   beacon_r = blake3( TAG_OUT || chain_id || u64_le(epoch) || u64_le(round) || compress(Sigma_r) )
// ---------------------------------------------------------------------------
#[test]
fn t4_proposed_round_message_and_output_layout() {
    // Round signing message m_r (this is the message hashed to G2 at sign time;
    // its digest here just fingerprints the byte layout, it is not the signature).
    let mut mr = Vec::new();
    mr.extend_from_slice(TAG_ROUND);
    mr.extend_from_slice(&SYN_CHAIN_ID);
    mr.extend_from_slice(&SYN_EPOCH.to_le_bytes());
    mr.extend_from_slice(&SYN_ROUND.to_le_bytes());
    mr.extend_from_slice(&SYN_SIGMA_PREV);
    assert_eq!(mr.len(), 141, "m_r preimage length");
    assert_eq!(
        blake3_hex(&mr),
        "b0cc26af2ef05c05b096570b8a274cf5cad9b802c4cf2b8a6fef7b07b16bcf83",
        "PROPOSED m_r layout BLAKE3 fingerprint (synthetic) mismatch"
    );

    // Beacon OUT preimage + digest.
    let mut out = Vec::new();
    out.extend_from_slice(TAG_OUT);
    out.extend_from_slice(&SYN_CHAIN_ID);
    out.extend_from_slice(&SYN_EPOCH.to_le_bytes());
    out.extend_from_slice(&SYN_ROUND.to_le_bytes());
    out.extend_from_slice(&SYN_SIGMA_R);
    assert_eq!(out.len(), 139, "OUT preimage length");
    assert_eq!(
        blake3_hex(&out),
        "71ccc107238dd193b1397214570098f238c433e1b2a2ddaadbeff8598b1d8073",
        "PROPOSED beacon OUT BLAKE3 digest (synthetic) mismatch"
    );

    // Chaining sensitivity: flipping one byte of Sigma_prev changes m_r's digest
    // (demonstrates the chained-round dependency; acceptance criterion (d)).
    let mut mr2 = mr.clone();
    let last = mr2.len() - 1;
    mr2[last] ^= 0x01;
    assert_ne!(
        blake3_hex(&mr),
        blake3_hex(&mr2),
        "changing prev Sigma must change the round message digest"
    );
}

// ---------------------------------------------------------------------------
// T-5 (PROPOSED — owner decision, NOT adopted) — domain-tag prefix-freeness.
//   Every PROPOSED tag is used as a prefix before variable-length data; if one
//   tag were a prefix of another, two distinct domains could produce colliding
//   preimages. Assert pairwise: distinct and neither a prefix of the other.
//   (spec §12.1, §5.3, §8) The tag strings themselves are NOT adopted consensus.
// ---------------------------------------------------------------------------
#[test]
fn t5_proposed_domain_tags_prefix_free() {
    let tags: [&[u8]; 6] = [
        TAG_GENESIS,
        TAG_ROUND,
        TAG_OUT,
        TAG_DLEQ,
        TAG_ECIES_KEY,
        TAG_ECIES_AAD,
    ];
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i == j {
                continue;
            }
            assert_ne!(a, b, "duplicate domain tag at {i},{j}");
            assert!(
                !b.starts_with(a),
                "domain tag {i} is a prefix of {j} — domain separation broken"
            );
        }
    }
}

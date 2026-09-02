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
//! RATIFIED v1 layout (owner decision 2026-09-01, #127; spec banner + §15
//! decision table rows 17–19, 22–26). These lock the ratified concatenation
//! ORDER + field WIDTHS over fixture inputs; the byte-exact real-signature
//! beacon_output KAT is in `crates/beacon-runtime/src/wire.rs`
//! (`tests::beacon_output_kat_ratified_v1`):
//!   T-3  genesis-seed preimage layout + its BLAKE3 digest (fixture inputs).
//!   T-4  round-message + OUT preimage layout + BLAKE3 digest (fixture inputs).
//!   T-5  domain-tag prefix-freeness (no tag is a prefix of another). All six
//!        tags — beacon GENESIS/ROUND/OUT, DLEQ, and the two ECIES tags — are
//!        RATIFIED v1 consensus bytes (spec §12.1, §5.3, §8).
//!
//! WHAT IS NOT ASSERTED HERE (this crate carries no BLS/pairing code): the RFC 9380
//! point-level hash-to-curve vectors and the BLS sign/verify/PoP/partial/combine
//! vectors now live — byte-exact and cross-architecture — in `sumchain-beacon-crypto`
//! (`vectors.rs`), and the ECIES ciphertext + `(key, nonce)` KATs in its `ecies.rs`;
//! DLEQ transcript bytes, W1b tx ordinals and #125-owned encodings, and activation
//! heights / MARGIN remain out of scope for this file.
//!
//! IMPORTANT: the T-3 / T-4 tags and layouts are RATIFIED v1 consensus bytes, but
//! their INPUTS here (`chain_id`, `genesis_params_hash`, the compressed-point
//! slot) are fixture placeholders, not live-chain values — these checks lock the
//! ratified concatenation ORDER + field WIDTHS, and must never be read as the real
//! chain's genesis seed or beacon output. The real byte-exact output over a valid
//! G2 signature is KAT-locked in `beacon-runtime` `wire.rs`.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// NORMATIVE ciphersuite / hash-to-curve identifier strings (standard-fixed).
// See spec §2.1.
// ---------------------------------------------------------------------------

const CS_SIGN: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const CS_POP: &str = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const CS_H2C: &str = "BLS12381G2_XMD:SHA-256_SSWU_RO_";

// ---------------------------------------------------------------------------
// Domain-separation tags. The two ECIES tags are RATIFIED v1 (#127 owner ruling):
// they are the exact namespace strings implemented in `sumchain-beacon-crypto`
// (`ecies.rs` `ECIES_CTX_DST` / `ECIES_HKDF_SALT`) — the HKDF-SHA-256 +
// ChaCha20-Poly1305 suite. The superseded single-tag `:key`/`:aad` design is
// GONE. The AEAD key/nonce are HKDF-Expand outputs under the info-labels
// `aead-key` / `aead-nonce` appended AFTER the whole canonical context, so those
// labels are suffixes, not standalone domain prefixes, and are not in this set.
//
// The beacon genesis/round/out and DLEQ tags below are RATIFIED v1 consensus
// bytes (spec §12.1, §5.3): the T-3/T-4 checks validate the ratified concatenation
// ORDER and field WIDTHS over fixture inputs (not any live-chain byte value); the
// real-signature byte-exact output lives in beacon-runtime wire.rs.
// ---------------------------------------------------------------------------

const TAG_GENESIS: &[u8] = b"OMNINODE-BEACON-GENESIS:v1:";
const TAG_ROUND: &[u8] = b"OMNINODE-BEACON-ROUND:v1:";
const TAG_OUT: &[u8] = b"OMNINODE-BEACON-OUT:v1:";
const TAG_DLEQ: &[u8] = b"OMNINODE-DKG-DLEQ:v1:";
// RATIFIED v1 — must byte-match `sumchain-beacon-crypto::ecies` (drift is a bug).
const TAG_ECIES_CTX: &[u8] = b"OMNINODE-DKG-ECIES:v1:ctx";
const TAG_ECIES_HKDF_SALT: &[u8] = b"OMNINODE-DKG-ECIES:v1:hkdf-salt";

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
//   (Its *placement* in the beacon message layout is RATIFIED v1 — see T-4.)
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
// Fixture inputs for the RATIFIED v1 T-3 / T-4 layout checks. These exercise the
// ratified concatenation ORDER + field WIDTHS (u64_le chain_id/epoch/round + a
// 96-byte compressed-G2 slot). The chain_id/genesis_params_hash values and the
// compressed-point slot are fixture placeholders, NOT live-chain values; the
// byte-exact vector over a REAL G2 signature is KAT-locked in
// `crates/beacon-runtime/src/wire.rs` (`tests::beacon_output_kat_ratified_v1`).
// This crate carries no BLS code, so it cannot mint a real point here — it locks
// the layout, wire.rs locks the real bytes.
// ---------------------------------------------------------------------------
const SYN_CHAIN_ID: u64 = 0xAABB_CCDD; // u64_le, matching the ratified layout
const SYN_GENESIS_PARAMS_HASH: [u8; 32] = [0x11; 32];
const SYN_EPOCH: u64 = 7;
const SYN_ROUND: u64 = 3;
const SYN_SIGMA_PREV: [u8; 96] = [0x22; 96]; // compressed-G2 slot placeholder
const SYN_SIGMA_R: [u8; 96] = [0x33; 96]; // compressed-G2 slot placeholder

// ---------------------------------------------------------------------------
// T-3 (RATIFIED v1 layout, §12.1) — genesis seed preimage layout + BLAKE3 digest
//   over fixture inputs. Locks the ratified concatenation ORDER + field WIDTHS:
//   Sigma_0_seed = blake3( TAG_GENESIS || u64_le(chain_id) || genesis_params_hash )
//   — matching `beacon_runtime::wire::genesis_seed`. The digest is over fixture
//   inputs (NOT a live genesis seed); the real byte-exact authority is wire.rs.
// ---------------------------------------------------------------------------
#[test]
fn t3_genesis_seed_layout_ratified_v1() {
    let mut pre = Vec::new();
    pre.extend_from_slice(TAG_GENESIS);
    pre.extend_from_slice(&SYN_CHAIN_ID.to_le_bytes());
    pre.extend_from_slice(&SYN_GENESIS_PARAMS_HASH);

    assert_eq!(pre.len(), 67, "genesis preimage length (27 tag + 8 u64_le + 32)");
    assert_eq!(
        hex::encode(&pre),
        "4f4d4e494e4f44452d424541434f4e2d47454e455349533a76313addccbbaa000000001111111111111111111111111111111111111111111111111111111111111111",
        "genesis preimage layout (order/widths) mismatch"
    );
    assert_eq!(
        blake3_hex(&pre),
        "478071a41e9880e12b300aa6b7dfdcc51c02a4dff45f4b65c300c770bf1dca50",
        "genesis seed BLAKE3 digest (fixture inputs) mismatch"
    );
}

// ---------------------------------------------------------------------------
// T-4 (RATIFIED v1 layout, §12.1) — round message + OUT preimage layouts + BLAKE3
//   digests over fixture inputs. Locks the ratified ORDER + WIDTHS:
//   m_r      = TAG_ROUND || u64_le(chain_id) || u64_le(epoch) || u64_le(round) || compress(Sigma_prev)
//   beacon_r = blake3( TAG_OUT || u64_le(chain_id) || u64_le(epoch) || u64_le(round) || compress(Sigma_r) )
//   — matching `beacon_runtime::wire::{round_message, beacon_output}`. The
//   compressed-point slot is a fixture placeholder; the byte-exact real-signature
//   beacon_output KAT is in wire.rs (`tests::beacon_output_kat_ratified_v1`).
// ---------------------------------------------------------------------------
#[test]
fn t4_round_message_and_output_layout_ratified_v1() {
    // Round signing message m_r (this is the message hashed to G2 at sign time;
    // its digest here just fingerprints the byte layout, it is not the signature).
    let mut mr = Vec::new();
    mr.extend_from_slice(TAG_ROUND);
    mr.extend_from_slice(&SYN_CHAIN_ID.to_le_bytes());
    mr.extend_from_slice(&SYN_EPOCH.to_le_bytes());
    mr.extend_from_slice(&SYN_ROUND.to_le_bytes());
    mr.extend_from_slice(&SYN_SIGMA_PREV);
    assert_eq!(mr.len(), 145, "m_r preimage length (25 tag + 8+8+8 + 96)");
    assert_eq!(
        blake3_hex(&mr),
        "ccb2dec163335002f27baf715b09e03b0457a5cdf17763800dcba257a64b60dc",
        "m_r layout BLAKE3 fingerprint (fixture) mismatch"
    );

    // Beacon OUT preimage + digest.
    let mut out = Vec::new();
    out.extend_from_slice(TAG_OUT);
    out.extend_from_slice(&SYN_CHAIN_ID.to_le_bytes());
    out.extend_from_slice(&SYN_EPOCH.to_le_bytes());
    out.extend_from_slice(&SYN_ROUND.to_le_bytes());
    out.extend_from_slice(&SYN_SIGMA_R);
    assert_eq!(out.len(), 143, "OUT preimage length (23 tag + 8+8+8 + 96)");
    assert_eq!(
        blake3_hex(&out),
        "35b49a430c62f3f6b9ad576bfcd2adbac1e2ee82fed06a312f3f89cdbaecdee6",
        "beacon OUT BLAKE3 digest (fixture) mismatch"
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
// T-5 (RATIFIED v1, §12.1/§5.3/§8) — domain-tag prefix-freeness.
//   Every tag is used as a prefix before variable-length data; if one tag were a
//   prefix of another, two distinct domains could produce colliding preimages.
//   Assert pairwise: distinct and neither a prefix of the other. All six tags
//   are RATIFIED v1 consensus bytes.
// ---------------------------------------------------------------------------
#[test]
fn t5_domain_tags_prefix_free_ratified_v1() {
    let tags: [&[u8]; 6] = [
        TAG_GENESIS,
        TAG_ROUND,
        TAG_OUT,
        TAG_DLEQ,
        TAG_ECIES_CTX,
        TAG_ECIES_HKDF_SALT,
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

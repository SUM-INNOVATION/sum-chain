//! Raw residual / KV / token byte encoders (and strict decoders) from the frozen
//! B0-PRE workload.
//!
//! The reference `workload.rs` also builds full transformer fixtures — deriving a
//! model by BLAKE3-XOF, running the frozen transformer, and assembling
//! statements/manifests. Those pull in the transformer / exp / protocol machinery
//! that is out of scope for this pure-encoding leaf, so only the residual-stream,
//! KV-cache, and token-sequence **raw-byte** encoders (and their little-endian
//! inverses) are reproduced here, byte-for-byte identical to the reference:
//!  * residual state  = `i16` little-endian, 2 bytes per lane (16 bytes for `[i16; 8]`)
//!  * KV state        = per `(key, value)` pair: i16-LE key ‖ i16-LE value (32 bytes/pair)
//!  * token sequence  = `u32` little-endian, 4 bytes per token
//!
//! The ENCODERS are byte-identical to the reference. The DECODERS are strict and
//! panic-free: they reject a short slice, an odd/partial trailing element, and
//! (for KV state) more than the frozen `MAX_SEQ` pairs, returning a
//! [`DecodeError`] rather than silently discarding a remainder or panicking on a
//! too-short slice.

use crate::b0::codec::DecodeError;
use crate::b0::consts::MAX_SEQ;

/// A single KV-cache `(key, value)` pair: eight `i16` key lanes, eight value lanes.
pub type KvPair = ([i16; 8], [i16; 8]);

// ---- encoders (byte-identical to the reference) ----

/// Encode `i16` lanes little-endian (2 bytes each).
pub fn i16_bytes(a: &[i16]) -> Vec<u8> {
    a.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Raw residual-stream bytes: the eight lanes little-endian (16 bytes).
pub fn residual_state_bytes(residual: &[i16; 8]) -> Vec<u8> {
    i16_bytes(residual)
}

/// Raw KV-cache bytes: each `(key, value)` pair as i16-LE key ‖ i16-LE value.
pub fn kv_state_bytes(pairs: &[KvPair]) -> Vec<u8> {
    pairs
        .iter()
        .flat_map(|(k, v)| [i16_bytes(k), i16_bytes(v)].concat())
        .collect()
}

/// Raw token-sequence bytes: each token as `u32` little-endian (4 bytes).
pub fn token_seq_bytes(tokens: &[u32]) -> Vec<u8> {
    tokens.iter().flat_map(|t| t.to_le_bytes()).collect()
}

// ---- strict, panic-free decoders ----

/// Convert an exactly-8-lane slice into `[i16; 8]` without slicing or panicking.
fn to_arr8(v: &[i16], ctx: &'static str) -> Result<[i16; 8], DecodeError> {
    <[i16; 8]>::try_from(v).map_err(|_| DecodeError::BadValue { ctx })
}

/// Strict little-endian `i16` decode: requires an even byte length. A trailing
/// odd byte is rejected, never silently dropped.
pub fn decode_i16s(bytes: &[u8]) -> Result<Vec<i16>, DecodeError> {
    if bytes.len() % 2 != 0 {
        return Err(DecodeError::BadValue {
            ctx: "workload.i16s.odd_len",
        });
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect())
}

/// Strict residual-stream decode: requires EXACTLY 16 bytes.
pub fn decode_residual_state(bytes: &[u8]) -> Result<[i16; 8], DecodeError> {
    if bytes.len() < 16 {
        return Err(DecodeError::Truncated {
            needed: 16,
            remaining: bytes.len(),
            ctx: "workload.residual",
        });
    }
    if bytes.len() > 16 {
        return Err(DecodeError::LengthExceedsMax {
            ctx: "workload.residual",
            len: bytes.len() as u64,
            max: 16,
        });
    }
    to_arr8(&decode_i16s(bytes)?, "workload.residual")
}

/// Strict KV-cache decode: requires `len % 32 == 0` and at most `MAX_SEQ` pairs.
pub fn decode_kv_state(bytes: &[u8]) -> Result<Vec<KvPair>, DecodeError> {
    if bytes.len() % 32 != 0 {
        return Err(DecodeError::BadValue {
            ctx: "workload.kv.len_not_multiple_of_32",
        });
    }
    let pairs = bytes.len() / 32;
    if pairs as u64 > MAX_SEQ as u64 {
        return Err(DecodeError::LengthExceedsMax {
            ctx: "workload.kv.pairs",
            len: pairs as u64,
            max: MAX_SEQ as u64,
        });
    }
    let mut out = Vec::with_capacity(pairs);
    for c in bytes.chunks_exact(32) {
        // c is exactly 32 bytes (chunks_exact), so these sub-slices never panic.
        let k = to_arr8(&decode_i16s(&c[0..16])?, "workload.kv.key")?;
        let v = to_arr8(&decode_i16s(&c[16..32])?, "workload.kv.value")?;
        out.push((k, v));
    }
    Ok(out)
}

/// Strict token-sequence decode: requires `len % 4 == 0`.
pub fn decode_token_seq(bytes: &[u8]) -> Result<Vec<u32>, DecodeError> {
    if bytes.len() % 4 != 0 {
        return Err(DecodeError::BadValue {
            ctx: "workload.token_seq.len_not_multiple_of_4",
        });
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residual_encode_decode_roundtrip_is_16_bytes() {
        let r = [1i16, -2, 3, -4, 5, -6, 7, -8];
        let b = residual_state_bytes(&r);
        assert_eq!(b.len(), 16);
        assert_eq!(decode_residual_state(&b).unwrap(), r);
    }

    #[test]
    fn residual_rejects_wrong_lengths() {
        for len in [0usize, 1, 15] {
            assert!(
                matches!(
                    decode_residual_state(&vec![0u8; len]),
                    Err(DecodeError::Truncated { .. })
                ),
                "len {len} must be Truncated"
            );
        }
        assert!(matches!(
            decode_residual_state(&[0u8; 17]),
            Err(DecodeError::LengthExceedsMax { .. })
        ));
    }

    #[test]
    fn kv_encode_decode_roundtrip_and_length() {
        let pairs = vec![
            (
                [1i16, 2, 3, 4, 5, 6, 7, 8],
                [9i16, 10, 11, 12, 13, 14, 15, 16],
            ),
            (
                [-1i16, -2, -3, -4, -5, -6, -7, -8],
                [100i16, 200, 300, 400, 500, 600, 700, 800],
            ),
        ];
        let b = kv_state_bytes(&pairs);
        assert_eq!(b.len(), 32 * pairs.len());
        assert_eq!(decode_kv_state(&b).unwrap(), pairs);
    }

    #[test]
    fn kv_rejects_non_multiple_of_32() {
        for len in [31usize, 33] {
            assert!(
                matches!(
                    decode_kv_state(&vec![0u8; len]),
                    Err(DecodeError::BadValue { .. })
                ),
                "len {len} must be BadValue"
            );
        }
    }

    #[test]
    fn kv_enforces_max_seq_pairs() {
        // exactly MAX_SEQ pairs is accepted; MAX_SEQ + 1 pairs is rejected.
        let ok = vec![0u8; 32 * MAX_SEQ as usize];
        assert_eq!(decode_kv_state(&ok).unwrap().len(), MAX_SEQ as usize);
        let over = vec![0u8; 32 * (MAX_SEQ as usize + 1)];
        assert!(matches!(
            decode_kv_state(&over),
            Err(DecodeError::LengthExceedsMax { .. })
        ));
    }

    #[test]
    fn tokens_encode_decode_roundtrip_and_reject_non_multiple_of_4() {
        let t = vec![0u32, 7, 15, 12345];
        let b = token_seq_bytes(&t);
        assert_eq!(b.len(), 4 * t.len());
        assert_eq!(decode_token_seq(&b).unwrap(), t);
        for len in [1usize, 3, 5] {
            assert!(
                matches!(
                    decode_token_seq(&vec![0u8; len]),
                    Err(DecodeError::BadValue { .. })
                ),
                "len {len} must be BadValue"
            );
        }
    }

    #[test]
    fn i16s_rejects_odd_length() {
        assert!(matches!(
            decode_i16s(&[0u8; 3]),
            Err(DecodeError::BadValue { .. })
        ));
        assert_eq!(decode_i16s(&[1, 0, 2, 0]).unwrap(), vec![1i16, 2]);
    }
}

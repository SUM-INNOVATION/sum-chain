//! INDEPENDENT second-source recompute of the `b0_pre_spec_hash`.
//!
//! The reference validator owns the typed protocol model; the spec hash it commits is
//! `BLAKE3(SPEC_PREFIX ‖ canonicalize(serde_json_string_of_artifact))`, where the canonicalizer
//! (validator `json::canonicalize`) is: strict parse, byte-sorted object keys, minimal integers
//! re-emitted verbatim, only `"` and `\` escaped in strings (`/` literal), printable ASCII only, no
//! insignificant whitespace, no trailing newline, `null` forbidden.
//!
//! This module mirrors EXACTLY that canonicalization subset over `serde_json::Value` (the crate enables
//! `arbitrary_precision`, so numbers round-trip verbatim) and BLAKE3s `SPEC_PREFIX ‖ canonical` with the
//! crate's own BLAKE3. Feeding it the committed `b0-pre-protocol-v1.json` must reproduce the ratified
//! spec hash — a genuine "both implementations recompute the spec hash" corroboration.

use serde_json::Value;

/// Domain-separation prefix for the spec hash — MUST equal the reference `tags::SPEC_PREFIX`.
pub const SPEC_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/SPEC/v1\n";

/// Canonicalize the committed pretty JSON to the FROZEN canonical byte form and BLAKE3
/// `SPEC_PREFIX ‖ canonical`. Byte-identical canonicalization to the reference is the whole point.
pub fn recompute_spec_hash_from_artifact_json(
    committed_pretty_json: &[u8],
) -> Result<[u8; 32], String> {
    let v: Value = serde_json::from_slice(committed_pretty_json)
        .map_err(|e| format!("independent: protocol artifact parse: {e}"))?;
    let mut canonical = Vec::new();
    write_canonical(&v, &mut canonical)?;
    Ok(crate::prefixed(SPEC_PREFIX, &canonical))
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match v {
        Value::Null => Err("independent: protocol canonicalize: null forbidden".into()),
        Value::Bool(b) => {
            out.extend_from_slice(if *b { b"true" } else { b"false" });
            Ok(())
        }
        Value::Number(n) => {
            // `arbitrary_precision` keeps the exact literal; the strict form is a minimal integer, so
            // re-emit verbatim (identical to the reference).
            out.extend_from_slice(n.to_string().as_bytes());
            Ok(())
        }
        Value::String(s) => write_canonical_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(e, out)?;
            }
            out.push(b']');
            Ok(())
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical_string(k, out)?;
                out.push(b':');
                write_canonical(&m[*k], out)?;
            }
            out.push(b'}');
            Ok(())
        }
    }
}

fn write_canonical_string(s: &str, out: &mut Vec<u8>) -> Result<(), String> {
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x20..=0x7E => out.push(b),
            _ => {
                return Err(
                    "independent: protocol canonicalize: control/non-ASCII in string".into(),
                )
            }
        }
    }
    out.push(b'"');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::malformed_corpus_report::to_hex;

    const ARTIFACT: &str = include_str!("../../../docs/b0-pre/protocol/b0-pre-protocol-v1.json");
    const SIDECAR: &str =
        include_str!("../../../docs/b0-pre/protocol/b0-pre-protocol-v1.json.hash");
    /// The real, owner-ratified `b0_pre_spec_hash`.
    const REAL_SPEC_HASH: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";

    #[test]
    fn independent_recompute_reproduces_the_real_spec_hash() {
        let h = recompute_spec_hash_from_artifact_json(ARTIFACT.as_bytes())
            .expect("committed artifact canonicalizes + hashes");
        assert_eq!(
            to_hex(&h),
            REAL_SPEC_HASH,
            "independent spec-hash recompute"
        );
        assert_eq!(
            to_hex(&h),
            SIDECAR.trim(),
            "recompute must equal the committed .json.hash sidecar"
        );
    }

    #[test]
    fn spec_prefix_is_the_frozen_tag() {
        assert_eq!(SPEC_PREFIX, b"SUMCHAIN/B0-PRE/SPEC/v1\n");
        assert_eq!(*SPEC_PREFIX.last().unwrap(), b'\n');
    }
}

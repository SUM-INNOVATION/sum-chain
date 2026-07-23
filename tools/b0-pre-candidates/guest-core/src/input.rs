//! Guest-input envelope — the framing that packs the ONE public statement plus
//! its private witness objects into the single byte blob a zkVM guest reads.
//!
//! # Why this envelope exists (and why it is guest-local, not consensus)
//!
//! The frozen B0-PRE wire family (`sumchain-wire::b0`) freezes the *statement*
//! and every *witness object* (model, residual, KV, token prefix, input
//! manifest) as canonical byte structures, and freezes the guest's public output
//! (`computation_statement_hash`). It does NOT freeze an OUTER container that
//! concatenates a statement with its witnesses for `stdin.write_slice` — the
//! prover just hands the guest one opaque blob. That outer framing is therefore
//! an UNFROZEN, guest-LOCAL I/O concern: it never enters the guest's committed
//! output (the journal is derived only from the re-canonicalized statement), so a
//! different framing changes no consensus value. It is defined here explicitly —
//! self-domained, strict, length-checked — rather than left implicit.
//!
//! Layout (all integers little-endian, via the frozen `sumchain-wire` codec):
//! ```text
//!   GUEST_INPUT_TAG[32]  = pad32("SUMCHAIN/R0/GUESTIN/v1")
//!   schema_version u16   = 1
//!   statement_len  u32   = 996 (R0ComputationStatementV2::LEN)
//!   statement_bytes[996]
//!   witness_count  u16
//!   repeat witness_count:
//!     witness_kind u8    (strict enum; unknown/duplicate rejected)
//!     witness_len  u32   (bounded by MAX_WITNESS_BYTES)
//!     witness_bytes[witness_len]
//! ```
//! Decoding rejects a bad tag, a non-1 version, a wrong statement length, an
//! unknown or duplicate witness kind, an over-length witness, truncation, and
//! trailing bytes — the same discipline as the frozen structures.

use sumchain_wire::b0::codec::{DecodeError, Reader, Writer};
use sumchain_wire::b0::statement::R0ComputationStatementV2;
use sumchain_wire::b0::tags::pad32;

/// 32-byte domain tag for the guest-input envelope (guest-local, not a consensus
/// wire type — it never enters the committed journal).
pub const GUEST_INPUT_TAG: [u8; 32] = pad32(b"SUMCHAIN/R0/GUESTIN/v1");
/// Envelope schema version.
pub const SCHEMA_VERSION: u16 = 1;
/// Upper bound on any single witness object (defensive allocation cap decoded
/// BEFORE the statement's own `max_state_bytes` is trusted; the semantic layer
/// then re-checks the true frozen `max_state_bytes`).
pub const MAX_WITNESS_BYTES: u32 = 65_536;
/// Upper bound on the number of witness slots (the two statements use ≤ 5).
pub const MAX_WITNESSES: u16 = 8;

/// The private witness objects a guest may carry, keyed by a strict 1-byte tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessKind {
    /// Canonical 1334-byte model bytes.
    Model = 1,
    /// Raw residual-stream bytes (`[i16; 8]` LE) — TLG input residual / SelectToken final residual.
    Residual = 2,
    /// Raw prior KV-cache bytes (TLG only).
    PriorKv = 3,
    /// Raw token-prefix bytes (`u32` LE per token).
    TokenPrefix = 4,
    /// Canonical `InputManifestV1` bytes.
    InputManifest = 5,
}

impl WitnessKind {
    fn from_u8(v: u8) -> Result<Self, DecodeError> {
        Ok(match v {
            1 => WitnessKind::Model,
            2 => WitnessKind::Residual,
            3 => WitnessKind::PriorKv,
            4 => WitnessKind::TokenPrefix,
            5 => WitnessKind::InputManifest,
            _ => {
                return Err(DecodeError::BadEnum {
                    name: "GuestInput.witness_kind",
                    value: v as u64,
                })
            }
        })
    }
    fn to_u8(self) -> u8 {
        self as u8
    }
}

/// A decoded guest-input envelope: the public statement bytes + up to five named
/// witness byte-slots. Present/absent witnesses are validated by the semantic
/// layer against the statement's `unit_kind`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuestInput {
    /// The exact 996 statement bytes as received (decode confirms canonicality).
    pub statement: Vec<u8>,
    pub model: Option<Vec<u8>>,
    pub residual: Option<Vec<u8>>,
    pub prior_kv: Option<Vec<u8>>,
    pub token_prefix: Option<Vec<u8>>,
    pub input_manifest: Option<Vec<u8>>,
}

impl GuestInput {
    /// Encode the canonical envelope. Used by the golden-input emitter/tests; the
    /// order of witness slots is fixed ascending by `WitnessKind`, so a given set
    /// of objects has exactly one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&GUEST_INPUT_TAG);
        w.u16(SCHEMA_VERSION);
        w.u32(self.statement.len() as u32);
        w.bytes(&self.statement);
        let slots: Vec<(WitnessKind, &Vec<u8>)> = [
            (WitnessKind::Model, self.model.as_ref()),
            (WitnessKind::Residual, self.residual.as_ref()),
            (WitnessKind::PriorKv, self.prior_kv.as_ref()),
            (WitnessKind::TokenPrefix, self.token_prefix.as_ref()),
            (WitnessKind::InputManifest, self.input_manifest.as_ref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|b| (k, b)))
        .collect();
        w.u16(slots.len() as u16);
        for (k, b) in slots {
            w.u8(k.to_u8());
            w.u32(b.len() as u32);
            w.bytes(b);
        }
        w.into_bytes()
    }

    /// Strictly decode an envelope, consuming exactly `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let tag = r.read_array::<32>("GuestInput.tag")?;
        if tag != GUEST_INPUT_TAG {
            return Err(DecodeError::BadTag { ctx: "GuestInput" });
        }
        let sv = r.read_u16("GuestInput.schema_version")?;
        if sv != SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "GuestInput.schema_version",
                value: sv as u64,
            });
        }
        let stmt_len = r.read_u32("GuestInput.statement_len")?;
        if stmt_len as usize != R0ComputationStatementV2::LEN {
            return Err(DecodeError::BadValue {
                ctx: "GuestInput.statement_len",
            });
        }
        let statement = r
            .read_bytes(stmt_len as usize, "GuestInput.statement")?
            .to_vec();

        let count = r.read_u16("GuestInput.witness_count")?;
        if count > MAX_WITNESSES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "GuestInput.witness_count",
                count: count as u64,
                max: MAX_WITNESSES as u64,
            });
        }
        let mut out = GuestInput {
            statement,
            ..Default::default()
        };
        for _ in 0..count {
            let kind = WitnessKind::from_u8(r.read_u8("GuestInput.witness_kind")?)?;
            let len = r.read_u32("GuestInput.witness_len")?;
            if len > MAX_WITNESS_BYTES {
                return Err(DecodeError::LengthExceedsMax {
                    ctx: "GuestInput.witness_len",
                    len: len as u64,
                    max: MAX_WITNESS_BYTES as u64,
                });
            }
            let body = r
                .read_bytes(len as usize, "GuestInput.witness_body")?
                .to_vec();
            let slot = match kind {
                WitnessKind::Model => &mut out.model,
                WitnessKind::Residual => &mut out.residual,
                WitnessKind::PriorKv => &mut out.prior_kv,
                WitnessKind::TokenPrefix => &mut out.token_prefix,
                WitnessKind::InputManifest => &mut out.input_manifest,
            };
            if slot.is_some() {
                return Err(DecodeError::DuplicateEntry {
                    ctx: "GuestInput.witness_kind",
                });
            }
            *slot = Some(body);
        }
        r.finish("GuestInput")?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GuestInput {
        GuestInput {
            statement: vec![7u8; R0ComputationStatementV2::LEN],
            model: Some(vec![1u8; 10]),
            residual: Some(vec![2u8; 16]),
            token_prefix: Some(vec![3u8; 4]),
            input_manifest: Some(vec![4u8; 20]),
            prior_kv: None,
        }
    }

    #[test]
    fn roundtrips_in_canonical_slot_order() {
        let g = sample();
        let bytes = g.encode();
        assert_eq!(GuestInput::decode(&bytes).unwrap(), g);
    }

    #[test]
    fn bad_tag_version_length_rejected() {
        let mut bytes = sample().encode();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            GuestInput::decode(&bytes),
            Err(DecodeError::BadTag { .. })
        ));
        let mut bytes = sample().encode();
        bytes[32..34].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            GuestInput::decode(&bytes),
            Err(DecodeError::BadFixedScalar { .. })
        ));
        let mut bytes = sample().encode();
        bytes[34..38].copy_from_slice(&995u32.to_le_bytes());
        assert!(matches!(
            GuestInput::decode(&bytes),
            Err(DecodeError::BadValue {
                ctx: "GuestInput.statement_len"
            })
        ));
    }

    #[test]
    fn trailing_and_truncation_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(matches!(
            GuestInput::decode(&bytes),
            Err(DecodeError::TrailingBytes { .. })
        ));
        let bytes = sample().encode();
        assert!(matches!(
            GuestInput::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
    }

    #[test]
    fn unknown_and_duplicate_witness_rejected() {
        // duplicate model slot
        let mut w = Writer::new();
        w.tag(&GUEST_INPUT_TAG);
        w.u16(SCHEMA_VERSION);
        w.u32(R0ComputationStatementV2::LEN as u32);
        w.bytes(&vec![0u8; R0ComputationStatementV2::LEN]);
        w.u16(2);
        w.u8(WitnessKind::Model.to_u8());
        w.u32(1);
        w.u8(9);
        w.u8(WitnessKind::Model.to_u8());
        w.u32(1);
        w.u8(9);
        assert!(matches!(
            GuestInput::decode(&w.into_bytes()),
            Err(DecodeError::DuplicateEntry { .. })
        ));

        // unknown witness kind 99
        let mut w = Writer::new();
        w.tag(&GUEST_INPUT_TAG);
        w.u16(SCHEMA_VERSION);
        w.u32(R0ComputationStatementV2::LEN as u32);
        w.bytes(&vec![0u8; R0ComputationStatementV2::LEN]);
        w.u16(1);
        w.u8(99);
        w.u32(0);
        assert!(matches!(
            GuestInput::decode(&w.into_bytes()),
            Err(DecodeError::BadEnum { .. })
        ));
    }
}

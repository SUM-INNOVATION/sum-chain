//! `PartialComputeProofV1` — 137 bytes.
//!
//! A strict, self-domained partial-compute proof binding. Layout:
//! `magic b"PCPFv1\0"[7] · schema_version u16 · computation_statement_hash[32] ·
//! b0_pre_spec_hash[32] · r0_guest_set_hash[32] · proof_artifact_digest[32]`.
//!
//! Decoders reject a bad magic, a non-1 schema version, truncation, and trailing
//! bytes — the same discipline as the frozen B0-PRE structures.

use crate::b0::codec::{DecodeError, Reader, Writer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialComputeProofV1 {
    pub computation_statement_hash: [u8; 32],
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub proof_artifact_digest: [u8; 32],
}

impl PartialComputeProofV1 {
    /// Seven-byte structure magic: `P C P F v 1 NUL`.
    pub const MAGIC: [u8; 7] = *b"PCPFv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    /// Documented total; asserted against the encoder-derived length in tests.
    pub const LEN: usize = 137;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.bytes(&self.computation_statement_hash);
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.bytes(&self.proof_artifact_digest);
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("PartialComputeProofV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag {
                ctx: "PartialComputeProofV1",
            });
        }
        let sv = r.read_u16("PartialComputeProofV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "PartialComputeProofV1.schema_version",
                value: sv as u64,
            });
        }
        let computation_statement_hash =
            r.read_array::<32>("PartialComputeProofV1.computation_statement_hash")?;
        let b0_pre_spec_hash = r.read_array::<32>("PartialComputeProofV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("PartialComputeProofV1.r0_guest_set_hash")?;
        let proof_artifact_digest =
            r.read_array::<32>("PartialComputeProofV1.proof_artifact_digest")?;
        Ok(Self {
            computation_statement_hash,
            b0_pre_spec_hash,
            r0_guest_set_hash,
            proof_artifact_digest,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("PartialComputeProofV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PartialComputeProofV1 {
        PartialComputeProofV1 {
            computation_statement_hash: [1; 32],
            b0_pre_spec_hash: [2; 32],
            r0_guest_set_hash: [3; 32],
            proof_artifact_digest: [4; 32],
        }
    }

    #[test]
    fn encoded_length_is_137() {
        assert_eq!(sample().encode().len(), 137);
        assert_eq!(sample().encode().len(), PartialComputeProofV1::LEN);
    }

    #[test]
    fn roundtrips() {
        let p = sample();
        assert_eq!(PartialComputeProofV1::decode_exact(&p.encode()).unwrap(), p);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = sample().encode();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            PartialComputeProofV1::decode_exact(&bytes),
            Err(DecodeError::BadTag { .. })
        ));
    }

    #[test]
    fn bad_version_rejected() {
        let mut bytes = sample().encode();
        bytes[7..9].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            PartialComputeProofV1::decode_exact(&bytes),
            Err(DecodeError::BadFixedScalar {
                ctx: "PartialComputeProofV1.schema_version",
                ..
            })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let bytes = sample().encode();
        assert!(matches!(
            PartialComputeProofV1::decode_exact(&bytes[..136]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            PartialComputeProofV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}

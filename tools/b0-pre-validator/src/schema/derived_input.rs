//! `DerivedInputV1` — 350 bytes (plan §8).

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::tags::{DERIVED_INPUT_TAG, RESEARCH_CHAIN_TAG};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedInputV1 {
    pub job_id: [u8; 32],
    pub session_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub generation_index: u32,
    pub model_id: [u8; 32],
    pub model_commitment_identity: [u8; 32],
    pub layer_start: u32,
    pub layer_end: u32,
    pub prior_residual_commitment_identity: [u8; 32],
    pub prior_kv_commitment_identity: [u8; 32],
    pub token_prefix_commitment_identity: [u8; 32],
    pub position: u32,
    pub sequence_length: u32,
}

impl DerivedInputV1 {
    pub const LEN: usize = 350;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&DERIVED_INPUT_TAG);
        w.u16(consts::SCHEMA_VERSION);
        w.tag(&RESEARCH_CHAIN_TAG);
        w.bytes(&self.job_id);
        w.bytes(&self.session_id);
        w.bytes(&self.unit_id);
        w.u32(self.generation_index);
        w.bytes(&self.model_id);
        w.bytes(&self.model_commitment_identity);
        w.u32(self.layer_start);
        w.u32(self.layer_end);
        w.bytes(&self.prior_residual_commitment_identity);
        w.bytes(&self.prior_kv_commitment_identity);
        w.bytes(&self.token_prefix_commitment_identity);
        w.u32(self.position);
        w.u32(self.sequence_length);
        w.u16(consts::FIXED_POINT_VERSION);
        w.u16(consts::ALGORITHM_VERSION);
        w.u32(consts::WORKLOAD_ARCH_ID);
        w.into_bytes()
    }

    pub fn identity(&self) -> [u8; 32] {
        blake3::hash(&self.encode()).into()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("DerivedInputV1.tag")?;
        if tag != DERIVED_INPUT_TAG {
            return Err(DecodeError::BadTag {
                ctx: "DerivedInputV1",
            });
        }
        let sv = r.read_u16("DerivedInputV1.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DerivedInputV1.schema_version",
                value: sv as u64,
            });
        }
        let rcd = r.read_array::<32>("DerivedInputV1.research_chain_domain")?;
        if rcd != RESEARCH_CHAIN_TAG {
            return Err(DecodeError::BadTag {
                ctx: "DerivedInputV1.research_chain_domain",
            });
        }
        let job_id = r.read_array::<32>("DerivedInputV1.job_id")?;
        let session_id = r.read_array::<32>("DerivedInputV1.session_id")?;
        let unit_id = r.read_array::<32>("DerivedInputV1.unit_id")?;
        let generation_index = r.read_u32("DerivedInputV1.generation_index")?;
        let model_id = r.read_array::<32>("DerivedInputV1.model_id")?;
        let model_commitment_identity =
            r.read_array::<32>("DerivedInputV1.model_commitment_identity")?;
        let layer_start = r.read_u32("DerivedInputV1.layer_start")?;
        let layer_end = r.read_u32("DerivedInputV1.layer_end")?;
        let prior_residual_commitment_identity =
            r.read_array::<32>("DerivedInputV1.prior_residual_commitment_identity")?;
        let prior_kv_commitment_identity =
            r.read_array::<32>("DerivedInputV1.prior_kv_commitment_identity")?;
        let token_prefix_commitment_identity =
            r.read_array::<32>("DerivedInputV1.token_prefix_commitment_identity")?;
        let position = r.read_u32("DerivedInputV1.position")?;
        let sequence_length = r.read_u32("DerivedInputV1.sequence_length")?;
        let fpv = r.read_u16("DerivedInputV1.fixed_point_version")?;
        if fpv != consts::FIXED_POINT_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DerivedInputV1.fixed_point_version",
                value: fpv as u64,
            });
        }
        let av = r.read_u16("DerivedInputV1.algorithm_version")?;
        if av != consts::ALGORITHM_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DerivedInputV1.algorithm_version",
                value: av as u64,
            });
        }
        let wai = r.read_u32("DerivedInputV1.workload_arch_id")?;
        if wai != consts::WORKLOAD_ARCH_ID {
            return Err(DecodeError::BadFixedScalar {
                ctx: "DerivedInputV1.workload_arch_id",
                value: wai as u64,
            });
        }
        Ok(Self {
            job_id,
            session_id,
            unit_id,
            generation_index,
            model_id,
            model_commitment_identity,
            layer_start,
            layer_end,
            prior_residual_commitment_identity,
            prior_kv_commitment_identity,
            token_prefix_commitment_identity,
            position,
            sequence_length,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("DerivedInputV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DerivedInputV1 {
        DerivedInputV1 {
            job_id: [1; 32],
            session_id: [2; 32],
            unit_id: [3; 32],
            generation_index: 7,
            model_id: [4; 32],
            model_commitment_identity: [5; 32],
            layer_start: 0,
            layer_end: 1,
            prior_residual_commitment_identity: [6; 32],
            prior_kv_commitment_identity: [7; 32],
            token_prefix_commitment_identity: [8; 32],
            position: 7,
            sequence_length: 8,
        }
    }

    #[test]
    fn encoded_length_is_350() {
        assert_eq!(sample().encode().len(), 350);
    }

    #[test]
    fn roundtrips() {
        let d = sample();
        assert_eq!(DerivedInputV1::decode_exact(&d.encode()).unwrap(), d);
    }

    #[test]
    fn wrong_fixed_scalar_rejected() {
        let mut bytes = sample().encode();
        // workload_arch_id at offset 346..350
        bytes[346..350].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            DerivedInputV1::decode_exact(&bytes),
            Err(DecodeError::BadFixedScalar {
                ctx: "DerivedInputV1.workload_arch_id",
                ..
            })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let bytes = sample().encode();
        assert!(matches!(
            DerivedInputV1::decode_exact(&bytes[..349]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            DerivedInputV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}

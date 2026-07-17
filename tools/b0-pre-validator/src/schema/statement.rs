//! `R0ComputationStatementV2` — 996 bytes — plus the zero-hash
//! `OfficialStatementTemplateV2` and deterministic final materialization
//! (plan §8/§22).
//!
//! The structural decoder validates the tag, the fixed scalars (§2), the
//! embedded commitments' object kinds, and enum discriminants. It does **not**
//! enforce the §9/§20 semantic equations or the frozen dimensions — those are a
//! separate official-workload validation layer, so a general decoder still
//! accepts schema-valid (selection-ineligible) alternatives.

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::enums::{ObjectKind, UnitKind};
use crate::hashing;
use crate::schema::object::ObjectCommitmentV1;
use crate::tags::{RESEARCH_CHAIN_TAG, STATEMENT_TAG, STMT_TEMPLATE_PREFIX};

fn expect_u8(r: &mut Reader, expected: u8, ctx: &'static str) -> Result<(), DecodeError> {
    let v = r.read_u8(ctx)?;
    if v != expected {
        return Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        });
    }
    Ok(())
}
fn expect_u16(r: &mut Reader, expected: u16, ctx: &'static str) -> Result<(), DecodeError> {
    let v = r.read_u16(ctx)?;
    if v != expected {
        return Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        });
    }
    Ok(())
}
fn expect_u32(r: &mut Reader, expected: u32, ctx: &'static str) -> Result<(), DecodeError> {
    let v = r.read_u32(ctx)?;
    if v != expected {
        return Err(DecodeError::BadFixedScalar {
            ctx,
            value: v as u64,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R0ComputationStatementV2 {
    pub b0_pre_spec_hash: [u8; 32],
    pub job_id: [u8; 32],
    pub session_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub unit_kind: UnitKind,
    pub unit_index: u32,
    pub generation_index: u32,
    pub model_id: [u8; 32],
    pub model_commitment: ObjectCommitmentV1,
    pub tokenizer_id: [u8; 32],
    pub head_dim: u16,
    pub ffn_dim: u16,
    pub layer_start: u32,
    pub layer_end: u32,
    pub vocab_size: u32,
    pub d_model: u32,
    pub n_heads: u32,
    pub derived_input_commitment: ObjectCommitmentV1,
    pub prior_residual_stream: ObjectCommitmentV1,
    pub prior_kv_cache: ObjectCommitmentV1,
    pub token_prefix: ObjectCommitmentV1,
    pub input_manifest: ObjectCommitmentV1,
    pub sequence_length: u32,
    pub position: u32,
    pub output_manifest: ObjectCommitmentV1,
    pub selected_token: u32,
    pub updated_token_seq_commitment: ObjectCommitmentV1,
    pub eos_flag: u8,
    pub max_cycles: u64,
    pub max_d_model: u32,
    pub max_seq_len: u32,
    pub max_output_tokens: u32,
    pub max_manifest_slots: u32,
    pub max_state_bytes: u64,
}

impl R0ComputationStatementV2 {
    pub const LEN: usize = 996;
    /// Offset of the `b0_pre_spec_hash` field (the only bytes that differ
    /// between a template and its materialized final).
    pub const SPEC_HASH_RANGE: std::ops::Range<usize> = 34..66;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&STATEMENT_TAG);
        w.u16(consts::SCHEMA_VERSION);
        w.bytes(&self.b0_pre_spec_hash);
        w.tag(&RESEARCH_CHAIN_TAG);
        w.bytes(&self.job_id);
        w.bytes(&self.session_id);
        w.bytes(&self.unit_id);
        w.u16(self.unit_kind.to_repr());
        w.u32(self.unit_index);
        w.u32(self.generation_index);
        w.bytes(&self.model_id);
        w.bytes(&self.model_commitment.encode());
        w.bytes(&self.tokenizer_id);
        w.u32(consts::WEIGHT_SCHEDULE_VERSION);
        w.u8(consts::FIXED_POINT_SCALE_LOG2);
        w.u16(consts::FIXED_POINT_VERSION);
        w.u32(consts::WORKLOAD_ARCH_ID);
        w.u16(consts::ALGORITHM_VERSION);
        w.u16(consts::SOFTMAX_VARIANT_ID);
        w.u16(self.head_dim);
        w.u16(self.ffn_dim);
        w.u16(consts::TOKEN_INPUT_SCHEME_ID);
        w.u32(self.layer_start);
        w.u32(self.layer_end);
        w.u32(self.vocab_size);
        w.u32(self.d_model);
        w.u32(self.n_heads);
        w.bytes(&self.derived_input_commitment.encode());
        w.bytes(&self.prior_residual_stream.encode());
        w.bytes(&self.prior_kv_cache.encode());
        w.bytes(&self.token_prefix.encode());
        w.bytes(&self.input_manifest.encode());
        w.u32(self.sequence_length);
        w.u32(self.position);
        w.u16(consts::OUTPUT_MANIFEST_SCHEMA_VERSION);
        w.bytes(&self.output_manifest.encode());
        w.u32(self.selected_token);
        w.bytes(&self.updated_token_seq_commitment.encode());
        w.u8(self.eos_flag);
        w.u64(self.max_cycles);
        w.u32(self.max_d_model);
        w.u32(self.max_seq_len);
        w.u32(self.max_output_tokens);
        w.u32(self.max_manifest_slots);
        w.u64(self.max_state_bytes);
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("R0ComputationStatementV2.tag")?;
        if tag != STATEMENT_TAG {
            return Err(DecodeError::BadTag {
                ctx: "R0ComputationStatementV2",
            });
        }
        expect_u16(r, consts::SCHEMA_VERSION, "statement.schema_version")?;
        let b0_pre_spec_hash = r.read_array::<32>("statement.b0_pre_spec_hash")?;
        let rcd = r.read_array::<32>("statement.research_chain_domain")?;
        if rcd != RESEARCH_CHAIN_TAG {
            return Err(DecodeError::BadTag {
                ctx: "statement.research_chain_domain",
            });
        }
        let job_id = r.read_array::<32>("statement.job_id")?;
        let session_id = r.read_array::<32>("statement.session_id")?;
        let unit_id = r.read_array::<32>("statement.unit_id")?;
        let unit_kind = UnitKind::from_repr(r.read_u16("statement.unit_kind")?)?;
        let unit_index = r.read_u32("statement.unit_index")?;
        let generation_index = r.read_u32("statement.generation_index")?;
        let model_id = r.read_array::<32>("statement.model_id")?;
        let model_commitment = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::Model,
            "statement.model_commitment",
        )?;
        let tokenizer_id = r.read_array::<32>("statement.tokenizer_id")?;
        expect_u32(
            r,
            consts::WEIGHT_SCHEDULE_VERSION,
            "statement.weight_schedule_version",
        )?;
        expect_u8(
            r,
            consts::FIXED_POINT_SCALE_LOG2,
            "statement.fixed_point_scale_log2",
        )?;
        expect_u16(
            r,
            consts::FIXED_POINT_VERSION,
            "statement.fixed_point_version",
        )?;
        expect_u32(r, consts::WORKLOAD_ARCH_ID, "statement.workload_arch_id")?;
        expect_u16(r, consts::ALGORITHM_VERSION, "statement.algorithm_version")?;
        expect_u16(
            r,
            consts::SOFTMAX_VARIANT_ID,
            "statement.softmax_variant_id",
        )?;
        let head_dim = r.read_u16("statement.head_dim")?;
        let ffn_dim = r.read_u16("statement.ffn_dim")?;
        expect_u16(
            r,
            consts::TOKEN_INPUT_SCHEME_ID,
            "statement.token_input_scheme_id",
        )?;
        let layer_start = r.read_u32("statement.layer_start")?;
        let layer_end = r.read_u32("statement.layer_end")?;
        let vocab_size = r.read_u32("statement.vocab_size")?;
        let d_model = r.read_u32("statement.d_model")?;
        let n_heads = r.read_u32("statement.n_heads")?;
        let derived_input_commitment = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::DerivedInput,
            "statement.derived_input_commitment",
        )?;
        let prior_residual_stream = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::PriorResidual,
            "statement.prior_residual_stream",
        )?;
        let prior_kv_cache = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::PriorKv,
            "statement.prior_kv_cache",
        )?;
        let token_prefix = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::TokenPrefix,
            "statement.token_prefix",
        )?;
        let input_manifest = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::InputManifest,
            "statement.input_manifest",
        )?;
        let sequence_length = r.read_u32("statement.sequence_length")?;
        let position = r.read_u32("statement.position")?;
        expect_u16(
            r,
            consts::OUTPUT_MANIFEST_SCHEMA_VERSION,
            "statement.output_manifest_schema_version",
        )?;
        let output_manifest = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::OutputManifest,
            "statement.output_manifest",
        )?;
        let selected_token = r.read_u32("statement.selected_token")?;
        let updated_token_seq_commitment = ObjectCommitmentV1::decode_expecting(
            r,
            ObjectKind::TokenSeq,
            "statement.updated_token_seq_commitment",
        )?;
        let eos_flag = r.read_u8("statement.eos_flag")?;
        let max_cycles = r.read_u64("statement.max_cycles")?;
        let max_d_model = r.read_u32("statement.max_d_model")?;
        let max_seq_len = r.read_u32("statement.max_seq_len")?;
        let max_output_tokens = r.read_u32("statement.max_output_tokens")?;
        let max_manifest_slots = r.read_u32("statement.max_manifest_slots")?;
        let max_state_bytes = r.read_u64("statement.max_state_bytes")?;

        Ok(Self {
            b0_pre_spec_hash,
            job_id,
            session_id,
            unit_id,
            unit_kind,
            unit_index,
            generation_index,
            model_id,
            model_commitment,
            tokenizer_id,
            head_dim,
            ffn_dim,
            layer_start,
            layer_end,
            vocab_size,
            d_model,
            n_heads,
            derived_input_commitment,
            prior_residual_stream,
            prior_kv_cache,
            token_prefix,
            input_manifest,
            sequence_length,
            position,
            output_manifest,
            selected_token,
            updated_token_seq_commitment,
            eos_flag,
            max_cycles,
            max_d_model,
            max_seq_len,
            max_output_tokens,
            max_manifest_slots,
            max_state_bytes,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("R0ComputationStatementV2")?;
        Ok(v)
    }

    /// `computation_statement_hash = BLAKE3(final_996_bytes)` (§17).
    pub fn computation_statement_hash(final_bytes: &[u8]) -> [u8; 32] {
        hashing::plain(final_bytes)
    }
}

/// A zero-hash statement template: the 996-byte statement with
/// `b0_pre_spec_hash` all zero. Used as the spec-hash preimage input so the
/// spec hash never references bytes that contain it (§22-B).
pub fn template_bytes(mut statement: R0ComputationStatementV2) -> Vec<u8> {
    statement.b0_pre_spec_hash = [0u8; 32];
    statement.encode()
}

/// `template_hash = BLAKE3(STMT_TEMPLATE ‖ template_996_bytes)` (§17).
pub fn template_hash(template: &[u8]) -> [u8; 32] {
    hashing::prefixed(STMT_TEMPLATE_PREFIX, template)
}

/// Materialize the final statement from a template by writing `spec_hash` into
/// bytes 34..66 and changing nothing else (§22-C).
pub fn materialize_final(template: &[u8], spec_hash: &[u8; 32]) -> Result<Vec<u8>, DecodeError> {
    if template.len() != R0ComputationStatementV2::LEN {
        return Err(DecodeError::BadValue {
            ctx: "materialize_final.template_len",
        });
    }
    let mut out = template.to_vec();
    out[R0ComputationStatementV2::SPEC_HASH_RANGE].copy_from_slice(spec_hash);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::ObjectKind;

    fn oc(kind: ObjectKind) -> ObjectCommitmentV1 {
        ObjectCommitmentV1::commit(kind, b"payload")
    }

    fn sample() -> R0ComputationStatementV2 {
        R0ComputationStatementV2 {
            b0_pre_spec_hash: [0xAB; 32],
            job_id: [1; 32],
            session_id: [2; 32],
            unit_id: [3; 32],
            unit_kind: UnitKind::TransformerLayerGroup,
            unit_index: 14,
            generation_index: 7,
            model_id: [4; 32],
            model_commitment: oc(ObjectKind::Model),
            tokenizer_id: [5; 32],
            head_dim: 4,
            ffn_dim: 16,
            layer_start: 0,
            layer_end: 1,
            vocab_size: 16,
            d_model: 8,
            n_heads: 2,
            derived_input_commitment: oc(ObjectKind::DerivedInput),
            prior_residual_stream: oc(ObjectKind::PriorResidual),
            prior_kv_cache: oc(ObjectKind::PriorKv),
            token_prefix: oc(ObjectKind::TokenPrefix),
            input_manifest: oc(ObjectKind::InputManifest),
            sequence_length: 8,
            position: 7,
            output_manifest: oc(ObjectKind::OutputManifest),
            selected_token: u32::MAX,
            updated_token_seq_commitment: oc(ObjectKind::TokenSeq),
            eos_flag: 0,
            max_cycles: 0,
            max_d_model: 8,
            max_seq_len: 8,
            max_output_tokens: 8,
            max_manifest_slots: 3,
            max_state_bytes: 2761,
        }
    }

    #[test]
    fn encoded_length_is_996() {
        assert_eq!(sample().encode().len(), 996);
    }

    #[test]
    fn roundtrips() {
        let s = sample();
        assert_eq!(
            R0ComputationStatementV2::decode_exact(&s.encode()).unwrap(),
            s
        );
    }

    #[test]
    fn template_has_zero_spec_hash_field() {
        let t = template_bytes(sample());
        assert_eq!(t.len(), 996);
        assert!(t[34..66].iter().all(|&b| b == 0));
    }

    #[test]
    fn materialize_differs_only_in_spec_hash_bytes() {
        let t = template_bytes(sample());
        let spec = [0x9Cu8; 32];
        let final_bytes = materialize_final(&t, &spec).unwrap();
        assert_eq!(final_bytes.len(), 996);
        // exactly bytes 34..66 differ, and they equal the spec hash
        for i in 0..996 {
            if (34..66).contains(&i) {
                assert_eq!(final_bytes[i], spec[i - 34]);
            } else {
                assert_eq!(
                    final_bytes[i], t[i],
                    "byte {i} changed outside spec-hash range"
                );
            }
        }
        // and the statement hash tracks the spec hash
        let h1 = R0ComputationStatementV2::computation_statement_hash(&final_bytes);
        let other = materialize_final(&t, &[0x11u8; 32]).unwrap();
        let h2 = R0ComputationStatementV2::computation_statement_hash(&other);
        assert_ne!(h1, h2);
    }

    #[test]
    fn changing_any_template_byte_changes_template_hash() {
        let t = template_bytes(sample());
        let base = template_hash(&t);
        let mut m = t.clone();
        m[500] ^= 0x01;
        assert_ne!(template_hash(&m), base);
    }

    #[test]
    fn fixed_scalar_rejected() {
        let mut bytes = sample().encode();
        // fixed_point_scale_log2 at offset 352 must be 8
        bytes[352] = 9;
        assert!(matches!(
            R0ComputationStatementV2::decode_exact(&bytes),
            Err(DecodeError::BadFixedScalar {
                ctx: "statement.fixed_point_scale_log2",
                ..
            })
        ));
    }

    #[test]
    fn embedded_commitment_kind_mismatch_rejected() {
        let mut s = sample();
        // put a TokenSeq commitment where a Model commitment is required
        s.model_commitment = oc(ObjectKind::TokenSeq);
        assert!(matches!(
            R0ComputationStatementV2::decode_exact(&s.encode()),
            Err(DecodeError::Inconsistent {
                ctx: "statement.model_commitment"
            })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let bytes = sample().encode();
        assert!(matches!(
            R0ComputationStatementV2::decode_exact(&bytes[..995]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            R0ComputationStatementV2::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}

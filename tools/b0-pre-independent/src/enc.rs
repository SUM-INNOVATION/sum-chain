//! Independent encoders for the spec-hash pipeline. Bytes are built directly
//! (no shared writer abstraction) to keep the implementation distinct from the
//! reference. Object-kind discriminants and fixed scalars are documented values.

use crate::merkle;
use crate::tags;

// Object-kind discriminants (documented; plan §2).
pub const K_MODEL: u16 = 1;
pub const K_TOKEN_PREFIX: u16 = 3;
pub const K_INPUT_MANIFEST: u16 = 4;
pub const K_OUTPUT_MANIFEST: u16 = 5;
pub const K_RESIDUAL_STATE: u16 = 6;
pub const K_KV_STATE: u16 = 7;
pub const K_DERIVED_INPUT: u16 = 9;
pub const K_TOKEN_SEQ: u16 = 10;
pub const K_PRIOR_RESIDUAL: u16 = 11;
pub const K_PRIOR_KV: u16 = 12;

// Slot-kind / input-slot-kind discriminants.
pub const S_RESIDUAL_STREAM: u8 = 0;
pub const S_KV_CACHE: u8 = 1;
pub const IS_PRIOR_RESIDUAL: u8 = 0;
pub const IS_PRIOR_KV: u8 = 1;
pub const IS_TOKEN_PREFIX: u8 = 2;

// Fixed scalars.
const SCHEMA_VERSION: u16 = 1;
const WEIGHT_SCHEDULE_VERSION: u32 = 0;
const FIXED_POINT_SCALE_LOG2: u8 = 8;
const FIXED_POINT_VERSION: u16 = 1;
const WORKLOAD_ARCH_ID: u32 = 0x5230_0001;
const ALGORITHM_VERSION: u16 = 1;
const SOFTMAX_VARIANT_ID: u16 = 1;
const TOKEN_INPUT_SCHEME_ID: u16 = 1;
const OUTPUT_MANIFEST_SCHEMA_VERSION: u16 = 1;
const UNIT_KIND_TLG: u16 = 0;

fn identity(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).into()
}

pub fn object_commitment(kind: u16, data: &[u8]) -> Vec<u8> {
    let byte_len = data.len() as u64;
    let (cc, root) = if data.is_empty() {
        (0u32, [0u8; 32])
    } else {
        (merkle::chunk_count(byte_len), merkle::root(data))
    };
    let mut b = Vec::with_capacity(80);
    b.extend_from_slice(&tags::OBJECT);
    b.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    b.extend_from_slice(&kind.to_le_bytes());
    b.extend_from_slice(&byte_len.to_le_bytes());
    b.extend_from_slice(&cc.to_le_bytes());
    b.extend_from_slice(&root);
    b
}

pub fn object_commitment_empty(kind: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(80);
    b.extend_from_slice(&tags::OBJECT);
    b.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    b.extend_from_slice(&kind.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&[0u8; 32]);
    b
}

pub fn oc_identity(kind: u16, data: &[u8]) -> [u8; 32] {
    identity(&object_commitment(kind, data))
}

#[derive(Clone)]
pub struct Di {
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

pub fn derived_input(d: &Di) -> Vec<u8> {
    let mut b = Vec::with_capacity(350);
    b.extend_from_slice(&tags::DERIVED_INPUT);
    b.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    b.extend_from_slice(&tags::RESEARCH_CHAIN);
    b.extend_from_slice(&d.job_id);
    b.extend_from_slice(&d.session_id);
    b.extend_from_slice(&d.unit_id);
    b.extend_from_slice(&d.generation_index.to_le_bytes());
    b.extend_from_slice(&d.model_id);
    b.extend_from_slice(&d.model_commitment_identity);
    b.extend_from_slice(&d.layer_start.to_le_bytes());
    b.extend_from_slice(&d.layer_end.to_le_bytes());
    b.extend_from_slice(&d.prior_residual_commitment_identity);
    b.extend_from_slice(&d.prior_kv_commitment_identity);
    b.extend_from_slice(&d.token_prefix_commitment_identity);
    b.extend_from_slice(&d.position.to_le_bytes());
    b.extend_from_slice(&d.sequence_length.to_le_bytes());
    b.extend_from_slice(&FIXED_POINT_VERSION.to_le_bytes());
    b.extend_from_slice(&ALGORITHM_VERSION.to_le_bytes());
    b.extend_from_slice(&WORKLOAD_ARCH_ID.to_le_bytes());
    b
}

/// A manifest slot: (kind byte, slot_index, 80-byte commitment).
pub struct Slot {
    pub kind: u8,
    pub index: u32,
    pub commitment: Vec<u8>,
}

fn manifest(tag: &[u8; 32], slots: &[Slot]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(tag);
    b.extend_from_slice(&SCHEMA_VERSION.to_le_bytes()); // version
    b.extend_from_slice(&(slots.len() as u32).to_le_bytes());
    for s in slots {
        b.push(s.kind);
        b.extend_from_slice(&s.index.to_le_bytes());
        b.extend_from_slice(&s.commitment);
    }
    b
}

pub fn output_manifest(slots: &[Slot]) -> Vec<u8> {
    manifest(&tags::OUTPUT_MANIFEST, slots)
}
pub fn input_manifest(slots: &[Slot]) -> Vec<u8> {
    manifest(&tags::INPUT_MANIFEST, slots)
}
pub fn output_manifest_commitment_identity(slots: &[Slot]) -> [u8; 32] {
    oc_identity(K_OUTPUT_MANIFEST, &output_manifest(slots))
}
pub fn input_manifest_commitment_identity(slots: &[Slot]) -> [u8; 32] {
    oc_identity(K_INPUT_MANIFEST, &input_manifest(slots))
}

/// The statement fields the golden pipeline needs (embedded commitments passed
/// as their 80-byte encodings).
pub struct St {
    pub b0_pre_spec_hash: [u8; 32],
    pub job_id: [u8; 32],
    pub session_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub unit_kind: u16,
    pub unit_index: u32,
    pub generation_index: u32,
    pub model_id: [u8; 32],
    pub model_commitment: Vec<u8>,
    pub tokenizer_id: [u8; 32],
    pub head_dim: u16,
    pub ffn_dim: u16,
    pub layer_start: u32,
    pub layer_end: u32,
    pub vocab_size: u32,
    pub d_model: u32,
    pub n_heads: u32,
    pub derived_input_commitment: Vec<u8>,
    pub prior_residual_stream: Vec<u8>,
    pub prior_kv_cache: Vec<u8>,
    pub token_prefix: Vec<u8>,
    pub input_manifest: Vec<u8>,
    pub sequence_length: u32,
    pub position: u32,
    pub output_manifest: Vec<u8>,
    pub selected_token: u32,
    pub updated_token_seq_commitment: Vec<u8>,
    pub eos_flag: u8,
    pub max_cycles: u64,
    pub max_d_model: u32,
    pub max_seq_len: u32,
    pub max_output_tokens: u32,
    pub max_manifest_slots: u32,
    pub max_state_bytes: u64,
}

pub fn statement(s: &St) -> Vec<u8> {
    let mut b = Vec::with_capacity(996);
    b.extend_from_slice(&tags::STATEMENT);
    b.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    b.extend_from_slice(&s.b0_pre_spec_hash);
    b.extend_from_slice(&tags::RESEARCH_CHAIN);
    b.extend_from_slice(&s.job_id);
    b.extend_from_slice(&s.session_id);
    b.extend_from_slice(&s.unit_id);
    b.extend_from_slice(&s.unit_kind.to_le_bytes());
    b.extend_from_slice(&s.unit_index.to_le_bytes());
    b.extend_from_slice(&s.generation_index.to_le_bytes());
    b.extend_from_slice(&s.model_id);
    b.extend_from_slice(&s.model_commitment);
    b.extend_from_slice(&s.tokenizer_id);
    b.extend_from_slice(&WEIGHT_SCHEDULE_VERSION.to_le_bytes());
    b.push(FIXED_POINT_SCALE_LOG2);
    b.extend_from_slice(&FIXED_POINT_VERSION.to_le_bytes());
    b.extend_from_slice(&WORKLOAD_ARCH_ID.to_le_bytes());
    b.extend_from_slice(&ALGORITHM_VERSION.to_le_bytes());
    b.extend_from_slice(&SOFTMAX_VARIANT_ID.to_le_bytes());
    b.extend_from_slice(&s.head_dim.to_le_bytes());
    b.extend_from_slice(&s.ffn_dim.to_le_bytes());
    b.extend_from_slice(&TOKEN_INPUT_SCHEME_ID.to_le_bytes());
    b.extend_from_slice(&s.layer_start.to_le_bytes());
    b.extend_from_slice(&s.layer_end.to_le_bytes());
    b.extend_from_slice(&s.vocab_size.to_le_bytes());
    b.extend_from_slice(&s.d_model.to_le_bytes());
    b.extend_from_slice(&s.n_heads.to_le_bytes());
    b.extend_from_slice(&s.derived_input_commitment);
    b.extend_from_slice(&s.prior_residual_stream);
    b.extend_from_slice(&s.prior_kv_cache);
    b.extend_from_slice(&s.token_prefix);
    b.extend_from_slice(&s.input_manifest);
    b.extend_from_slice(&s.sequence_length.to_le_bytes());
    b.extend_from_slice(&s.position.to_le_bytes());
    b.extend_from_slice(&OUTPUT_MANIFEST_SCHEMA_VERSION.to_le_bytes());
    b.extend_from_slice(&s.output_manifest);
    b.extend_from_slice(&s.selected_token.to_le_bytes());
    b.extend_from_slice(&s.updated_token_seq_commitment);
    b.push(s.eos_flag);
    b.extend_from_slice(&s.max_cycles.to_le_bytes());
    b.extend_from_slice(&s.max_d_model.to_le_bytes());
    b.extend_from_slice(&s.max_seq_len.to_le_bytes());
    b.extend_from_slice(&s.max_output_tokens.to_le_bytes());
    b.extend_from_slice(&s.max_manifest_slots.to_le_bytes());
    b.extend_from_slice(&s.max_state_bytes.to_le_bytes());
    b
}

pub fn template_hash(template: &[u8]) -> [u8; 32] {
    crate::prefixed(tags::STMT_TEMPLATE_PREFIX, template)
}

pub fn materialize_final(template: &[u8], spec_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = template.to_vec();
    out[34..66].copy_from_slice(spec_hash);
    out
}

pub fn computation_statement_hash(final_bytes: &[u8]) -> [u8; 32] {
    crate::plain(final_bytes)
}

/// Convenience: the `unit_kind` discriminant for a TransformerLayerGroup.
pub const fn unit_kind_tlg() -> u16 {
    UNIT_KIND_TLG
}

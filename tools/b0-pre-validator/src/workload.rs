//! Deterministic workload fixtures + the witness→statement binding contract
//! (plan §7/§9/§10/§21). Integer-only; no floating point.
//!
//! A workload case derives a model and inputs by BLAKE3-XOF, executes the frozen
//! transformer, and builds every `ObjectCommitmentV1`, `DerivedInputV1`, the
//! input/output manifests, and the `R0ComputationStatementV2` (template form).
//! `verify_tlg` / `verify_select` are the guest-side contract: authenticate every
//! private witness byte against the public statement, re-execute, recompute all
//! outputs, and reject on any mismatch. Timings/weights are synthetic TEST_ONLY
//! data and are not part of `b0_pre_spec_hash`.

use crate::consts;
use crate::enums::{InputSlotKind, ObjectKind, SlotKind, UnitKind};
use crate::exp;
use crate::schema::derived_input::DerivedInputV1;
use crate::schema::manifest::{
    InputManifestV1, InputSlotDescriptorV1, OutputManifestV1, SlotDescriptorV1,
};
use crate::schema::object::ObjectCommitmentV1;
use crate::schema::statement::{self, R0ComputationStatementV2};
use crate::transformer::{self, Model};

const FIXTURE_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/FIXTURE/v1\0";
const DATA_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/DATA/v1\0";

/// The per-workload fixture seed: `BLAKE3(FIXTURE_PREFIX ‖ name)`.
pub fn seed_of(name: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(FIXTURE_PREFIX);
    h.update(name);
    h.finalize().into()
}
fn stream(seed: &[u8; 32], label: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(seed);
    h.update(DATA_PREFIX);
    h.update(label);
    let mut xof = h.finalize_xof();
    let mut buf = vec![0u8; out_len];
    xof.fill(&mut buf);
    buf
}
fn i16s(bytes: &[u8]) -> Vec<i16> {
    bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}
fn i16_bytes(a: &[i16]) -> Vec<u8> {
    a.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn arr8(v: &[i16]) -> [i16; 8] {
    let mut a = [0i16; 8];
    a.copy_from_slice(&v[..8]);
    a
}
fn id(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(seed);
    h.update(label);
    h.finalize().into()
}

/// Derive the model tensors by per-tensor BLAKE3-XOF.
pub fn derive_model(seed: &[u8; 32]) -> Model {
    let g = |label: &[u8], n: usize| i16s(&stream(seed, label, n * 2));
    let m88 = |label: &[u8]| {
        let v = i16s(&stream(seed, label, 128));
        let mut m = [[0i16; 8]; 8];
        for i in 0..8 {
            for j in 0..8 {
                m[i][j] = v[i * 8 + j];
            }
        }
        m
    };
    let m816 = |label: &[u8]| {
        let v = i16s(&stream(seed, label, 256));
        let mut m = [[0i16; 16]; 8];
        for i in 0..8 {
            for j in 0..16 {
                m[i][j] = v[i * 16 + j];
            }
        }
        m
    };
    let m168 = |label: &[u8]| {
        let v = i16s(&stream(seed, label, 256));
        let mut m = [[0i16; 8]; 16];
        for i in 0..16 {
            for j in 0..8 {
                m[i][j] = v[i * 8 + j];
            }
        }
        m
    };
    Model {
        attn_gamma: arr8(&g(b"model/attn_norm_gamma", 8)),
        wq: m88(b"model/wq"),
        wk: m88(b"model/wk"),
        wv: m88(b"model/wv"),
        wo: m88(b"model/wo"),
        ffn_gamma: arr8(&g(b"model/ffn_norm_gamma", 8)),
        w1: m816(b"model/w1"),
        w2: m168(b"model/w2"),
        final_gamma: arr8(&g(b"model/final_norm_gamma", 8)),
        lmhead: m816(b"model/lmhead"),
    }
}

fn parse_kv(bytes: &[u8]) -> Vec<([i16; 8], [i16; 8])> {
    bytes
        .chunks_exact(32)
        .map(|c| (arr8(&i16s(&c[0..16])), arr8(&i16s(&c[16..32]))))
        .collect()
}

fn tokenizer_id() -> [u8; 32] {
    blake3::hash(b"SUMCHAIN/R0/TOKCTX/external-pretokenized-u32/v1").into()
}

/// A fully-built TransformerLayerGroup workload case.
pub struct TlgCase {
    pub position: u32,
    pub model: Vec<u8>,
    pub prior_residual: Vec<u8>,
    pub prior_kv: Vec<u8>,
    pub token_prefix: Vec<u8>,
    pub input_manifest: Vec<u8>,
    pub statement: R0ComputationStatementV2,
    pub output_residual: Vec<u8>,
    pub output_kv: Vec<u8>,
}

pub fn build_tlg(name: &[u8], position: u32) -> TlgCase {
    let table = exp::table_cached();
    let seed = seed_of(name);
    let model = derive_model(&seed);
    let model_bytes = model.encode();

    let seq_len = position + 1;
    let input_residual = arr8(&i16s(&stream(&seed, b"tlg/input_residual", 16)));
    let prior_residual = i16_bytes(&input_residual);
    let prior_kv = stream(&seed, b"tlg/prior_kv", 32 * position as usize);
    let tok_raw = stream(&seed, b"tlg/token_prefix", 4 * seq_len as usize);
    let tokens: Vec<u32> = tok_raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) % 16)
        .collect();
    let token_prefix: Vec<u8> = tokens.iter().flat_map(|t| t.to_le_bytes()).collect();

    let prior = parse_kv(&prior_kv);
    let (out_res, cur) = transformer::layer_group(table, &model, &input_residual, &prior).unwrap();
    let output_residual = i16_bytes(&out_res);
    let mut full_kv = prior.clone();
    full_kv.push(cur);
    let output_kv: Vec<u8> = full_kv
        .iter()
        .flat_map(|(k, v)| [i16_bytes(k), i16_bytes(v)].concat())
        .collect();

    // commitments
    let oc = |k, b: &[u8]| ObjectCommitmentV1::commit(k, b);
    let model_commitment = oc(ObjectKind::Model, &model_bytes);
    let prior_residual_c = oc(ObjectKind::PriorResidual, &prior_residual);
    let prior_kv_c = if position == 0 {
        ObjectCommitmentV1::empty(ObjectKind::PriorKv)
    } else {
        oc(ObjectKind::PriorKv, &prior_kv)
    };
    let token_prefix_c = oc(ObjectKind::TokenPrefix, &token_prefix);

    let input_manifest_struct = InputManifestV1 {
        slots: vec![
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorResidual,
                slot_index: 0,
                commitment: prior_residual_c.clone(),
            },
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorKv,
                slot_index: 0,
                commitment: prior_kv_c.clone(),
            },
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::TokenPrefix,
                slot_index: 0,
                commitment: token_prefix_c.clone(),
            },
        ],
    };
    let input_manifest = input_manifest_struct.encode();
    let input_manifest_c = input_manifest_struct.commitment();

    let di = DerivedInputV1 {
        job_id: id(&seed, b"job"),
        session_id: id(&seed, b"session"),
        unit_id: id(&seed, b"unit/tlg"),
        generation_index: position,
        model_id: model.model_id(),
        model_commitment_identity: model_commitment.identity(),
        layer_start: 0,
        layer_end: 1,
        prior_residual_commitment_identity: prior_residual_c.identity(),
        prior_kv_commitment_identity: prior_kv_c.identity(),
        token_prefix_commitment_identity: token_prefix_c.identity(),
        position,
        sequence_length: seq_len,
    };
    let derived_input_c = oc(ObjectKind::DerivedInput, &di.encode());

    let output_residual_c = oc(ObjectKind::ResidualState, &output_residual);
    let output_kv_c = oc(ObjectKind::KvState, &output_kv);
    let output_manifest_struct = OutputManifestV1 {
        slots: vec![
            SlotDescriptorV1 {
                slot_kind: SlotKind::ResidualStream,
                slot_index: position,
                commitment: output_residual_c.clone(),
            },
            SlotDescriptorV1 {
                slot_kind: SlotKind::KvCache,
                slot_index: position,
                commitment: output_kv_c.clone(),
            },
        ],
    };
    let output_manifest_c = output_manifest_struct.commitment();
    let updated_token_seq_c = oc(ObjectKind::TokenSeq, &token_prefix);

    let statement = R0ComputationStatementV2 {
        b0_pre_spec_hash: [0; 32],
        job_id: di.job_id,
        session_id: di.session_id,
        unit_id: di.unit_id,
        unit_kind: UnitKind::TransformerLayerGroup,
        unit_index: 2 * position,
        generation_index: position,
        model_id: model.model_id(),
        model_commitment,
        tokenizer_id: tokenizer_id(),
        head_dim: consts::HEAD_DIM,
        ffn_dim: consts::FFN_DIM,
        layer_start: 0,
        layer_end: 1,
        vocab_size: consts::VOCAB_SIZE,
        d_model: consts::D_MODEL,
        n_heads: consts::N_HEADS,
        derived_input_commitment: derived_input_c,
        prior_residual_stream: prior_residual_c,
        prior_kv_cache: prior_kv_c,
        token_prefix: token_prefix_c,
        input_manifest: input_manifest_c,
        sequence_length: seq_len,
        position,
        output_manifest: output_manifest_c,
        selected_token: u32::MAX,
        updated_token_seq_commitment: updated_token_seq_c,
        eos_flag: 0,
        max_cycles: 0,
        max_d_model: 8,
        max_seq_len: 8,
        max_output_tokens: 8,
        max_manifest_slots: 3,
        max_state_bytes: consts::MAX_STATE_BYTES,
    };

    TlgCase {
        position,
        model: model_bytes,
        prior_residual,
        prior_kv,
        token_prefix,
        input_manifest,
        statement,
        output_residual,
        output_kv,
    }
}

/// The §10 witness→statement contract for a TransformerLayerGroup. `witness`
/// bytes are private; `statement` is public. Returns Ok only if every private
/// input authenticates and every recomputed public output matches.
pub fn verify_tlg(case: &TlgCase) -> Result<(), &'static str> {
    let table = exp::table_cached();
    let s = &case.statement;

    // frozen constants / bounds
    if (s.d_model, s.n_heads, s.head_dim, s.ffn_dim, s.vocab_size) != (8, 2, 4, 16, 16) {
        return Err("frozen dims");
    }
    if (
        s.max_d_model,
        s.max_seq_len,
        s.max_output_tokens,
        s.max_manifest_slots,
        s.max_state_bytes,
        s.max_cycles,
    ) != (8, 8, 8, 3, consts::MAX_STATE_BYTES, 0)
    {
        return Err("frozen bounds");
    }
    if s.layer_start != 0 || s.layer_end != 1 || s.unit_kind != UnitKind::TransformerLayerGroup {
        return Err("unit sentinels");
    }
    if s.position != case.position || s.sequence_length != case.position + 1 {
        return Err("position/length");
    }

    // authenticate model
    let model = Model::decode(&case.model).map_err(|_| "model decode")?;
    if ObjectCommitmentV1::commit(ObjectKind::Model, &case.model) != s.model_commitment {
        return Err("model commitment");
    }
    if model.model_id() != s.model_id {
        return Err("model id");
    }
    // authenticate inputs
    if ObjectCommitmentV1::commit(ObjectKind::PriorResidual, &case.prior_residual)
        != s.prior_residual_stream
    {
        return Err("prior residual");
    }
    let expect_kv = if case.position == 0 {
        ObjectCommitmentV1::empty(ObjectKind::PriorKv)
    } else {
        ObjectCommitmentV1::commit(ObjectKind::PriorKv, &case.prior_kv)
    };
    if expect_kv != s.prior_kv_cache {
        return Err("prior kv");
    }
    if ObjectCommitmentV1::commit(ObjectKind::TokenPrefix, &case.token_prefix) != s.token_prefix {
        return Err("token prefix");
    }
    if case.prior_kv.len() != 32 * case.position as usize {
        return Err("kv shape");
    }
    if case.token_prefix.len() != 4 * (case.position as usize + 1) {
        return Err("token count");
    }

    // input manifest slots must bind the embedded commitments
    let im =
        InputManifestV1::decode_exact(&case.input_manifest).map_err(|_| "input manifest decode")?;
    if im.slots.len() != 3
        || im.slots[0].commitment != s.prior_residual_stream
        || im.slots[1].commitment != s.prior_kv_cache
        || im.slots[2].commitment != s.token_prefix
    {
        return Err("input manifest slots");
    }
    if ObjectCommitmentV1::commit(ObjectKind::InputManifest, &case.input_manifest)
        != s.input_manifest
    {
        return Err("input manifest commitment");
    }

    // reconstruct + authenticate derived input
    let di = DerivedInputV1 {
        job_id: s.job_id,
        session_id: s.session_id,
        unit_id: s.unit_id,
        generation_index: s.generation_index,
        model_id: s.model_id,
        model_commitment_identity: s.model_commitment.identity(),
        layer_start: 0,
        layer_end: 1,
        prior_residual_commitment_identity: s.prior_residual_stream.identity(),
        prior_kv_commitment_identity: s.prior_kv_cache.identity(),
        token_prefix_commitment_identity: s.token_prefix.identity(),
        position: s.position,
        sequence_length: s.sequence_length,
    };
    if ObjectCommitmentV1::commit(ObjectKind::DerivedInput, &di.encode())
        != s.derived_input_commitment
    {
        return Err("derived input");
    }

    // checked max_state_bytes before trusting outputs
    let state: u64 = [
        case.model.len(),
        case.prior_residual.len(),
        case.prior_kv.len(),
        case.token_prefix.len(),
        case.input_manifest.len(),
        di.encode().len(),
        case.output_residual.len(),
        case.output_kv.len(),
    ]
    .iter()
    .map(|&x| x as u64)
    .sum::<u64>()
        + 208
        + case.token_prefix.len() as u64; // output manifest + updated token seq
    if state > s.max_state_bytes {
        return Err("max_state_bytes");
    }

    // execute and recompute outputs
    let input_residual = arr8(&i16s(&case.prior_residual));
    let prior = parse_kv(&case.prior_kv);
    let (out_res, cur) =
        transformer::layer_group(table, &model, &input_residual, &prior).map_err(|_| "exec")?;
    let out_res_bytes = i16_bytes(&out_res);
    let mut full = prior;
    full.push(cur);
    let out_kv_bytes: Vec<u8> = full
        .iter()
        .flat_map(|(k, v)| [i16_bytes(k), i16_bytes(v)].concat())
        .collect();

    let output_residual_c = ObjectCommitmentV1::commit(ObjectKind::ResidualState, &out_res_bytes);
    let output_kv_c = ObjectCommitmentV1::commit(ObjectKind::KvState, &out_kv_bytes);
    let om = OutputManifestV1 {
        slots: vec![
            SlotDescriptorV1 {
                slot_kind: SlotKind::ResidualStream,
                slot_index: s.position,
                commitment: output_residual_c,
            },
            SlotDescriptorV1 {
                slot_kind: SlotKind::KvCache,
                slot_index: s.position,
                commitment: output_kv_c,
            },
        ],
    };
    if om.commitment() != s.output_manifest {
        return Err("output manifest");
    }
    // sentinels
    if s.selected_token != u32::MAX || s.eos_flag != 0 {
        return Err("tlg sentinels");
    }
    if ObjectCommitmentV1::commit(ObjectKind::TokenSeq, &case.token_prefix)
        != s.updated_token_seq_commitment
    {
        return Err("updated token seq");
    }
    Ok(())
}

/// Statement/template bytes for the case (spec-hash field zero → template).
pub fn tlg_template(case: &TlgCase) -> Vec<u8> {
    statement::template_bytes(case.statement.clone())
}

/// A fully-built SelectToken workload case.
pub struct SelectCase {
    pub position: u32,
    pub model: Vec<u8>,
    pub final_residual: Vec<u8>,
    pub token_prefix: Vec<u8>,
    pub input_manifest: Vec<u8>,
    pub statement: R0ComputationStatementV2,
    pub selected: u32,
    pub eos: u8,
}

pub fn build_select(name: &[u8], position: u32) -> SelectCase {
    let seed = seed_of(name);
    let model = derive_model(&seed);
    let model_bytes = model.encode();
    let seq_len = position + 1; // sequence_length < MAX_SEQ enforced by caller
    let final_residual_arr = arr8(&i16s(&stream(&seed, b"select/final_residual", 16)));
    let final_residual = i16_bytes(&final_residual_arr);
    let tok_raw = stream(&seed, b"select/token_prefix", 4 * seq_len as usize);
    let tokens: Vec<u32> = tok_raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) % 16)
        .collect();
    let token_prefix: Vec<u8> = tokens.iter().flat_map(|t| t.to_le_bytes()).collect();

    let (selected, eos) = transformer::select_token(&model, &final_residual_arr);
    let mut updated: Vec<u32> = tokens.clone();
    updated.push(selected);
    let updated_bytes: Vec<u8> = updated.iter().flat_map(|t| t.to_le_bytes()).collect();

    let oc = |k, b: &[u8]| ObjectCommitmentV1::commit(k, b);
    let model_commitment = oc(ObjectKind::Model, &model_bytes);
    let final_residual_c = oc(ObjectKind::PriorResidual, &final_residual);
    let token_prefix_c = oc(ObjectKind::TokenPrefix, &token_prefix);
    let prior_kv_c = ObjectCommitmentV1::empty(ObjectKind::PriorKv);

    let input_manifest_struct = InputManifestV1 {
        slots: vec![
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorResidual,
                slot_index: 0,
                commitment: final_residual_c.clone(),
            },
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::TokenPrefix,
                slot_index: 0,
                commitment: token_prefix_c.clone(),
            },
        ],
    };
    let input_manifest = input_manifest_struct.encode();
    let input_manifest_c = input_manifest_struct.commitment();

    let di = DerivedInputV1 {
        job_id: id(&seed, b"job"),
        session_id: id(&seed, b"session"),
        unit_id: id(&seed, b"unit/select-token"),
        generation_index: position,
        model_id: model.model_id(),
        model_commitment_identity: model_commitment.identity(),
        layer_start: u32::MAX,
        layer_end: u32::MAX,
        prior_residual_commitment_identity: final_residual_c.identity(),
        prior_kv_commitment_identity: prior_kv_c.identity(),
        token_prefix_commitment_identity: token_prefix_c.identity(),
        position,
        sequence_length: seq_len,
    };
    let derived_input_c = oc(ObjectKind::DerivedInput, &di.encode());
    let output_manifest_c = OutputManifestV1 { slots: vec![] }.commitment();
    let updated_token_seq_c = oc(ObjectKind::TokenSeq, &updated_bytes);

    let statement = R0ComputationStatementV2 {
        b0_pre_spec_hash: [0; 32],
        job_id: di.job_id,
        session_id: di.session_id,
        unit_id: di.unit_id,
        unit_kind: UnitKind::SelectToken,
        unit_index: 2 * position + 1,
        generation_index: position,
        model_id: model.model_id(),
        model_commitment,
        tokenizer_id: tokenizer_id(),
        head_dim: consts::HEAD_DIM,
        ffn_dim: consts::FFN_DIM,
        layer_start: u32::MAX,
        layer_end: u32::MAX,
        vocab_size: consts::VOCAB_SIZE,
        d_model: consts::D_MODEL,
        n_heads: consts::N_HEADS,
        derived_input_commitment: derived_input_c,
        prior_residual_stream: final_residual_c,
        prior_kv_cache: prior_kv_c,
        token_prefix: token_prefix_c,
        input_manifest: input_manifest_c,
        sequence_length: seq_len,
        position,
        output_manifest: output_manifest_c,
        selected_token: selected,
        updated_token_seq_commitment: updated_token_seq_c,
        eos_flag: eos,
        max_cycles: 0,
        max_d_model: 8,
        max_seq_len: 8,
        max_output_tokens: 8,
        max_manifest_slots: 3,
        max_state_bytes: consts::MAX_STATE_BYTES,
    };
    SelectCase {
        position,
        model: model_bytes,
        final_residual,
        token_prefix,
        input_manifest,
        statement,
        selected,
        eos,
    }
}

/// The §10 witness→statement contract for SelectToken.
pub fn verify_select(case: &SelectCase) -> Result<(), &'static str> {
    let s = &case.statement;
    if s.unit_kind != UnitKind::SelectToken || s.layer_start != u32::MAX || s.layer_end != u32::MAX
    {
        return Err("select sentinels");
    }
    if s.prior_kv_cache != ObjectCommitmentV1::empty(ObjectKind::PriorKv) {
        return Err("prior kv must be empty");
    }
    if s.token_prefix.byte_len == 0 {
        return Err("empty prefix");
    }
    if s.sequence_length >= 8 {
        return Err("sequence overflow");
    }
    let model = Model::decode(&case.model).map_err(|_| "model decode")?;
    if ObjectCommitmentV1::commit(ObjectKind::Model, &case.model) != s.model_commitment
        || model.model_id() != s.model_id
    {
        return Err("model");
    }
    if ObjectCommitmentV1::commit(ObjectKind::PriorResidual, &case.final_residual)
        != s.prior_residual_stream
    {
        return Err("final residual");
    }
    if ObjectCommitmentV1::commit(ObjectKind::TokenPrefix, &case.token_prefix) != s.token_prefix {
        return Err("token prefix");
    }
    let im = InputManifestV1::decode_exact(&case.input_manifest).map_err(|_| "im decode")?;
    if im.slots.len() != 2
        || im.slots[0].commitment != s.prior_residual_stream
        || im.slots[1].commitment != s.token_prefix
    {
        return Err("input manifest slots");
    }
    if ObjectCommitmentV1::commit(ObjectKind::InputManifest, &case.input_manifest)
        != s.input_manifest
    {
        return Err("input manifest commitment");
    }
    if (OutputManifestV1 { slots: vec![] }).commitment() != s.output_manifest {
        return Err("output manifest must be empty");
    }
    // execute + recompute selection
    let fr = arr8(&i16s(&case.final_residual));
    let (selected, eos) = transformer::select_token(&model, &fr);
    if selected != s.selected_token || eos != s.eos_flag {
        return Err("selection");
    }
    if selected >= s.vocab_size {
        return Err("selected out of range");
    }
    if (selected == s.vocab_size - 1) as u8 != s.eos_flag {
        return Err("eos flag");
    }
    // updated token sequence = prefix ‖ selected
    let mut updated = case.token_prefix.clone();
    updated.extend_from_slice(&selected.to_le_bytes());
    if ObjectCommitmentV1::commit(ObjectKind::TokenSeq, &updated) != s.updated_token_seq_commitment
    {
        return Err("updated token seq");
    }
    Ok(())
}

pub fn select_template(case: &SelectCase) -> Vec<u8> {
    statement::template_bytes(case.statement.clone())
}

/// Ordered canonical artifacts of a TransformerLayerGroup case, for
/// byte-for-byte cross-implementation locking.
pub fn tlg_artifacts(case: &TlgCase) -> Vec<(&'static str, Vec<u8>)> {
    let s = &case.statement;
    let di = DerivedInputV1 {
        job_id: s.job_id,
        session_id: s.session_id,
        unit_id: s.unit_id,
        generation_index: s.generation_index,
        model_id: s.model_id,
        model_commitment_identity: s.model_commitment.identity(),
        layer_start: 0,
        layer_end: 1,
        prior_residual_commitment_identity: s.prior_residual_stream.identity(),
        prior_kv_commitment_identity: s.prior_kv_cache.identity(),
        token_prefix_commitment_identity: s.token_prefix.identity(),
        position: s.position,
        sequence_length: s.sequence_length,
    };
    let out_res_c = ObjectCommitmentV1::commit(ObjectKind::ResidualState, &case.output_residual);
    let out_kv_c = ObjectCommitmentV1::commit(ObjectKind::KvState, &case.output_kv);
    let om = OutputManifestV1 {
        slots: vec![
            SlotDescriptorV1 {
                slot_kind: SlotKind::ResidualStream,
                slot_index: s.position,
                commitment: out_res_c.clone(),
            },
            SlotDescriptorV1 {
                slot_kind: SlotKind::KvCache,
                slot_index: s.position,
                commitment: out_kv_c.clone(),
            },
        ],
    };
    vec![
        ("model", case.model.clone()),
        ("model_id", s.model_id.to_vec()),
        ("prior_residual", case.prior_residual.clone()),
        ("prior_kv", case.prior_kv.clone()),
        ("token_prefix", case.token_prefix.clone()),
        ("input_manifest", case.input_manifest.clone()),
        ("derived_input", di.encode()),
        ("output_residual", case.output_residual.clone()),
        ("output_kv", case.output_kv.clone()),
        ("output_manifest", om.encode()),
        ("c_model", s.model_commitment.encode()),
        ("c_prior_residual", s.prior_residual_stream.encode()),
        ("c_prior_kv", s.prior_kv_cache.encode()),
        ("c_token_prefix", s.token_prefix.encode()),
        ("c_input_manifest", s.input_manifest.encode()),
        ("c_derived_input", s.derived_input_commitment.encode()),
        ("c_output_residual", out_res_c.encode()),
        ("c_output_kv", out_kv_c.encode()),
        ("c_output_manifest", s.output_manifest.encode()),
        (
            "c_updated_token_seq",
            s.updated_token_seq_commitment.encode(),
        ),
        ("statement_template", statement::template_bytes(s.clone())),
    ]
}

/// Ordered canonical artifacts of a SelectToken case.
pub fn select_artifacts(case: &SelectCase) -> Vec<(&'static str, Vec<u8>)> {
    let s = &case.statement;
    let di = DerivedInputV1 {
        job_id: s.job_id,
        session_id: s.session_id,
        unit_id: s.unit_id,
        generation_index: s.generation_index,
        model_id: s.model_id,
        model_commitment_identity: s.model_commitment.identity(),
        layer_start: u32::MAX,
        layer_end: u32::MAX,
        prior_residual_commitment_identity: s.prior_residual_stream.identity(),
        prior_kv_commitment_identity: s.prior_kv_cache.identity(),
        token_prefix_commitment_identity: s.token_prefix.identity(),
        position: s.position,
        sequence_length: s.sequence_length,
    };
    let mut updated = case.token_prefix.clone();
    updated.extend_from_slice(&case.selected.to_le_bytes());
    let empty_om = OutputManifestV1 { slots: vec![] };
    vec![
        ("model", case.model.clone()),
        ("model_id", s.model_id.to_vec()),
        ("final_residual", case.final_residual.clone()),
        ("token_prefix", case.token_prefix.clone()),
        ("input_manifest", case.input_manifest.clone()),
        ("derived_input", di.encode()),
        ("updated_token_seq", updated),
        ("output_manifest", empty_om.encode()),
        ("selected_token", case.selected.to_le_bytes().to_vec()),
        ("eos_flag", vec![case.eos]),
        ("c_model", s.model_commitment.encode()),
        ("c_final_residual", s.prior_residual_stream.encode()),
        ("c_prior_kv_empty", s.prior_kv_cache.encode()),
        ("c_token_prefix", s.token_prefix.encode()),
        ("c_input_manifest", s.input_manifest.encode()),
        ("c_derived_input", s.derived_input_commitment.encode()),
        ("c_output_manifest_empty", s.output_manifest.encode()),
        (
            "c_updated_token_seq",
            s.updated_token_seq_commitment.encode(),
        ),
        ("statement_template", statement::template_bytes(s.clone())),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlg_case_verifies_at_several_positions() {
        for pos in [0u32, 1, 2, 7] {
            let case = build_tlg(b"official-workload-v1", pos);
            assert_eq!(verify_tlg(&case), Ok(()), "position {pos}");
        }
    }

    #[test]
    fn witness_and_public_mutations_all_reject() {
        let base = build_tlg(b"official-workload-v1", 3);
        assert_eq!(verify_tlg(&base), Ok(()));

        type M = Box<dyn Fn(&TlgCase) -> TlgCase>;
        let clone = |c: &TlgCase| TlgCase {
            position: c.position,
            model: c.model.clone(),
            prior_residual: c.prior_residual.clone(),
            prior_kv: c.prior_kv.clone(),
            token_prefix: c.token_prefix.clone(),
            input_manifest: c.input_manifest.clone(),
            statement: c.statement.clone(),
            output_residual: c.output_residual.clone(),
            output_kv: c.output_kv.clone(),
        };
        let cases: Vec<(&str, M)> = vec![
            // private witness byte classes
            (
                "model_magic",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.model[8] ^= 1;
                        x
                    }
                }),
            ),
            (
                "model_norm_gamma",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.model[6] ^= 1;
                        x
                    }
                }),
            ),
            (
                "model_tensor_byte",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.model[500] ^= 1;
                        x
                    }
                }),
            ),
            (
                "residual_byte",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.prior_residual[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "kv_byte",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.prior_kv[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "token_byte",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.token_prefix[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "input_manifest_descriptor",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.input_manifest[40] ^= 1;
                        x
                    }
                }),
            ),
            // public statement fields
            (
                "public_model_commitment",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.model_commitment.merkle_root[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "public_prior_kv",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.prior_kv_cache.merkle_root[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "public_output_manifest",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.output_manifest.merkle_root[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "public_selected_token",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.selected_token = 5;
                        x
                    }
                }),
            ),
            (
                "public_eos",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.eos_flag = 1;
                        x
                    }
                }),
            ),
            (
                "public_updated_token_seq",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.updated_token_seq_commitment.merkle_root[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "public_position",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.position ^= 1;
                        x
                    }
                }),
            ),
            (
                "public_derived_input",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.derived_input_commitment.merkle_root[0] ^= 1;
                        x
                    }
                }),
            ),
            (
                "public_max_state_bytes",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.max_state_bytes = 10;
                        x
                    }
                }),
            ),
            (
                "ffn_gamma",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.model[534] ^= 1;
                        x
                    }
                }),
            ),
            (
                "final_gamma",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.model[1062] ^= 1;
                        x
                    }
                }),
            ),
            (
                "prior_v_byte",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.prior_kv[16] ^= 1;
                        x
                    }
                }),
            ),
            (
                "trailing_witness",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.model.push(0);
                        x
                    }
                }),
            ),
            (
                "public_dims",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.d_model = 9;
                        x
                    }
                }),
            ),
            (
                "public_unit_kind",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.unit_kind = UnitKind::SelectToken;
                        x
                    }
                }),
            ),
            (
                "public_sequence_length",
                Box::new({
                    let c = clone;
                    move |x| {
                        let mut x = c(x);
                        x.statement.sequence_length = 3;
                        x
                    }
                }),
            ),
        ];
        for (name, mutate) in &cases {
            assert!(
                verify_tlg(&mutate(&base)).is_err(),
                "case `{name}` must reject"
            );
        }
    }

    #[test]
    fn select_case_verifies_and_mutations_reject() {
        let base = build_select(b"official-workload-v1", 6); // seq_len 7 < MAX_SEQ
        assert_eq!(verify_select(&base), Ok(()));

        let cl = |c: &SelectCase| SelectCase {
            position: c.position,
            model: c.model.clone(),
            final_residual: c.final_residual.clone(),
            token_prefix: c.token_prefix.clone(),
            input_manifest: c.input_manifest.clone(),
            statement: c.statement.clone(),
            selected: c.selected,
            eos: c.eos,
        };
        type M = Box<dyn Fn(&SelectCase) -> SelectCase>;
        let cases: Vec<(&str, M)> = vec![
            (
                "model_byte",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.model[500] ^= 1;
                    x
                }),
            ),
            (
                "final_residual_byte",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.final_residual[0] ^= 1;
                    x
                }),
            ),
            (
                "token_byte",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.token_prefix[0] ^= 1;
                    x
                }),
            ),
            (
                "input_manifest_byte",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.input_manifest[40] ^= 1;
                    x
                }),
            ),
            (
                "public_selected",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.statement.selected_token ^= 1;
                    x
                }),
            ),
            (
                "public_eos",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.statement.eos_flag ^= 1;
                    x
                }),
            ),
            (
                "public_updated_seq",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.statement.updated_token_seq_commitment.merkle_root[0] ^= 1;
                    x
                }),
            ),
            (
                "prior_kv_not_empty",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.statement.prior_kv_cache =
                        ObjectCommitmentV1::commit(ObjectKind::PriorKv, b"x");
                    x
                }),
            ),
            (
                "nonempty_output_manifest",
                Box::new(move |x| {
                    let mut x = cl(x);
                    x.statement.output_manifest.merkle_root[0] ^= 1;
                    x
                }),
            ),
        ];
        for (name, mutate) in &cases {
            assert!(
                verify_select(&mutate(&base)).is_err(),
                "select `{name}` must reject"
            );
        }
    }
}

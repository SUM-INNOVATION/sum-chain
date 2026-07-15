//! Independent workload fixtures + witness→statement contract (plan §7/§9/§10/§21).
//! From-scratch mirror of the reference: same BLAKE3-XOF derivation and frozen
//! executor, its own `enc` encoders, and its own witness recomputation. Shares no
//! code with the reference (separate crate). Integer-only. TEST_ONLY synthetic data.
//!
//! Both TransformerLayerGroup and SelectToken are generated and verified here
//! independently; the byte-lock test asserts byte-for-byte agreement with the
//! reference on the two canonical official statements.

use crate::enc;
use crate::transformer::{self, Model};

const FIXTURE_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/FIXTURE/v1\0";
const DATA_PREFIX: &[u8] = b"SUMCHAIN/B0-PRE/DATA/v1\0";

fn seed_of(name: &[u8]) -> [u8; 32] {
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
fn tokenizer_id() -> [u8; 32] {
    blake3::hash(b"SUMCHAIN/R0/TOKCTX/external-pretokenized-u32/v1").into()
}

pub fn derive_model(seed: &[u8; 32]) -> Model {
    let g = |label: &[u8]| i16s(&stream(seed, label, 16));
    let m88 = |label: &[u8]| {
        let v = i16s(&stream(seed, label, 128));
        let mut m = [[0i16; 8]; 8];
        for (i, row) in m.iter_mut().enumerate() {
            for (j, x) in row.iter_mut().enumerate() {
                *x = v[i * 8 + j];
            }
        }
        m
    };
    let m816 = |label: &[u8]| {
        let v = i16s(&stream(seed, label, 256));
        let mut m = [[0i16; 16]; 8];
        for (i, row) in m.iter_mut().enumerate() {
            for (j, x) in row.iter_mut().enumerate() {
                *x = v[i * 16 + j];
            }
        }
        m
    };
    let m168 = |label: &[u8]| {
        let v = i16s(&stream(seed, label, 256));
        let mut m = [[0i16; 8]; 16];
        for (i, row) in m.iter_mut().enumerate() {
            for (j, x) in row.iter_mut().enumerate() {
                *x = v[i * 8 + j];
            }
        }
        m
    };
    Model {
        attn_gamma: arr8(&g(b"model/attn_norm_gamma")),
        wq: m88(b"model/wq"),
        wk: m88(b"model/wk"),
        wv: m88(b"model/wv"),
        wo: m88(b"model/wo"),
        ffn_gamma: arr8(&g(b"model/ffn_norm_gamma")),
        w1: m816(b"model/w1"),
        w2: m168(b"model/w2"),
        final_gamma: arr8(&g(b"model/final_norm_gamma")),
        lmhead: m816(b"model/lmhead"),
    }
}

fn parse_kv(bytes: &[u8]) -> Vec<([i16; 8], [i16; 8])> {
    bytes
        .chunks_exact(32)
        .map(|c| (arr8(&i16s(&c[0..16])), arr8(&i16s(&c[16..32]))))
        .collect()
}
fn slot(kind: u8, index: u32, commitment: Vec<u8>) -> enc::Slot {
    enc::Slot {
        kind,
        index,
        commitment,
    }
}
fn oc(kind: u16, data: &[u8]) -> Vec<u8> {
    enc::object_commitment(kind, data)
}

// ---------------- TransformerLayerGroup ----------------

pub struct TlgCase {
    pub position: u32,
    pub sequence_length: u32,
    pub job_id: [u8; 32],
    pub session_id: [u8; 32],
    pub unit_id: [u8; 32],
    pub model: Vec<u8>,
    pub prior_residual: Vec<u8>,
    pub prior_kv: Vec<u8>,
    pub token_prefix: Vec<u8>,
    pub input_manifest: Vec<u8>,
    pub derived_input: Vec<u8>,
    pub output_residual: Vec<u8>,
    pub output_kv: Vec<u8>,
    pub output_manifest: Vec<u8>,
    pub model_commitment: Vec<u8>,
    pub prior_residual_c: Vec<u8>,
    pub prior_kv_c: Vec<u8>,
    pub token_prefix_c: Vec<u8>,
    pub input_manifest_c: Vec<u8>,
    pub derived_input_c: Vec<u8>,
    pub output_residual_c: Vec<u8>,
    pub output_kv_c: Vec<u8>,
    pub output_manifest_c: Vec<u8>,
    pub updated_token_seq_c: Vec<u8>,
    pub model_id: [u8; 32],
    pub template: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn tlg_di(
    seed: &[u8; 32],
    model_id: [u8; 32],
    position: u32,
    seq_len: u32,
    model_c: &[u8],
    prc: &[u8],
    pkc: &[u8],
    tpc: &[u8],
) -> enc::Di {
    enc::Di {
        job_id: id(seed, b"job"),
        session_id: id(seed, b"session"),
        unit_id: id(seed, b"unit/tlg"),
        generation_index: position,
        model_id,
        model_commitment_identity: crate::plain(model_c),
        layer_start: 0,
        layer_end: 1,
        prior_residual_commitment_identity: crate::plain(prc),
        prior_kv_commitment_identity: crate::plain(pkc),
        token_prefix_commitment_identity: crate::plain(tpc),
        position,
        sequence_length: seq_len,
    }
}

pub fn build_tlg(name: &[u8], position: u32) -> TlgCase {
    let table = crate::exp::table_cached();
    let seed = seed_of(name);
    let model = derive_model(&seed);
    let model_bytes = model.encode();
    let model_id = model.model_id();
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
    let mut full = prior.clone();
    full.push(cur);
    let output_kv: Vec<u8> = full
        .iter()
        .flat_map(|(k, v)| [i16_bytes(k), i16_bytes(v)].concat())
        .collect();

    let model_commitment = oc(enc::K_MODEL, &model_bytes);
    let prior_residual_c = oc(enc::K_PRIOR_RESIDUAL, &prior_residual);
    let prior_kv_c = if position == 0 {
        enc::object_commitment_empty(enc::K_PRIOR_KV)
    } else {
        oc(enc::K_PRIOR_KV, &prior_kv)
    };
    let token_prefix_c = oc(enc::K_TOKEN_PREFIX, &token_prefix);
    let input_manifest = enc::input_manifest(&[
        slot(enc::IS_PRIOR_RESIDUAL, 0, prior_residual_c.clone()),
        slot(enc::IS_PRIOR_KV, 0, prior_kv_c.clone()),
        slot(enc::IS_TOKEN_PREFIX, 0, token_prefix_c.clone()),
    ]);
    let input_manifest_c = oc(enc::K_INPUT_MANIFEST, &input_manifest);
    let di = tlg_di(
        &seed,
        model_id,
        position,
        seq_len,
        &model_commitment,
        &prior_residual_c,
        &prior_kv_c,
        &token_prefix_c,
    );
    let derived_input = enc::derived_input(&di);
    let derived_input_c = oc(enc::K_DERIVED_INPUT, &derived_input);
    let output_residual_c = oc(enc::K_RESIDUAL_STATE, &output_residual);
    let output_kv_c = oc(enc::K_KV_STATE, &output_kv);
    let output_manifest = enc::output_manifest(&[
        slot(enc::S_RESIDUAL_STREAM, position, output_residual_c.clone()),
        slot(enc::S_KV_CACHE, position, output_kv_c.clone()),
    ]);
    let output_manifest_c = oc(enc::K_OUTPUT_MANIFEST, &output_manifest);
    let updated_token_seq_c = oc(enc::K_TOKEN_SEQ, &token_prefix);

    let st = tlg_statement(
        &di,
        model_id,
        position,
        seq_len,
        &model_commitment,
        &derived_input_c,
        &prior_residual_c,
        &prior_kv_c,
        &token_prefix_c,
        &input_manifest_c,
        &output_manifest_c,
        &updated_token_seq_c,
    );
    let template = enc::statement(&st);

    TlgCase {
        position,
        sequence_length: seq_len,
        job_id: di.job_id,
        session_id: di.session_id,
        unit_id: di.unit_id,
        model: model_bytes,
        prior_residual,
        prior_kv,
        token_prefix,
        input_manifest,
        derived_input,
        output_residual,
        output_kv,
        output_manifest,
        model_commitment,
        prior_residual_c,
        prior_kv_c,
        token_prefix_c,
        input_manifest_c,
        derived_input_c,
        output_residual_c,
        output_kv_c,
        output_manifest_c,
        updated_token_seq_c,
        model_id,
        template,
    }
}

#[allow(clippy::too_many_arguments)]
fn tlg_statement(
    di: &enc::Di,
    model_id: [u8; 32],
    position: u32,
    seq_len: u32,
    model_c: &[u8],
    derived_c: &[u8],
    prc: &[u8],
    pkc: &[u8],
    tpc: &[u8],
    imc: &[u8],
    omc: &[u8],
    utsc: &[u8],
) -> enc::St {
    enc::St {
        b0_pre_spec_hash: [0; 32],
        job_id: di.job_id,
        session_id: di.session_id,
        unit_id: di.unit_id,
        unit_kind: 0,
        unit_index: 2 * position,
        generation_index: position,
        model_id,
        model_commitment: model_c.to_vec(),
        tokenizer_id: tokenizer_id(),
        head_dim: 4,
        ffn_dim: 16,
        layer_start: 0,
        layer_end: 1,
        vocab_size: 16,
        d_model: 8,
        n_heads: 2,
        derived_input_commitment: derived_c.to_vec(),
        prior_residual_stream: prc.to_vec(),
        prior_kv_cache: pkc.to_vec(),
        token_prefix: tpc.to_vec(),
        input_manifest: imc.to_vec(),
        sequence_length: seq_len,
        position,
        output_manifest: omc.to_vec(),
        selected_token: u32::MAX,
        updated_token_seq_commitment: utsc.to_vec(),
        eos_flag: 0,
        max_cycles: 0,
        max_d_model: 8,
        max_seq_len: 8,
        max_output_tokens: 8,
        max_manifest_slots: 3,
        max_state_bytes: 2761,
    }
}

/// Witness→statement contract: authenticate every private input against the
/// public commitments, execute, recompute outputs, reconstruct the derived
/// input and the full statement template, and reject on any mismatch.
pub fn verify_tlg(case: &TlgCase) -> Result<(), &'static str> {
    let table = crate::exp::table_cached();
    let model = Model::decode(&case.model).map_err(|_| "model decode")?;
    // 1. authenticate witness
    if oc(enc::K_MODEL, &case.model) != case.model_commitment {
        return Err("model commitment");
    }
    if model.model_id() != case.model_id {
        return Err("model id");
    }
    if oc(enc::K_PRIOR_RESIDUAL, &case.prior_residual) != case.prior_residual_c {
        return Err("prior residual");
    }
    let expect_kv = if case.position == 0 {
        enc::object_commitment_empty(enc::K_PRIOR_KV)
    } else {
        oc(enc::K_PRIOR_KV, &case.prior_kv)
    };
    if expect_kv != case.prior_kv_c {
        return Err("prior kv");
    }
    if oc(enc::K_TOKEN_PREFIX, &case.token_prefix) != case.token_prefix_c {
        return Err("token prefix");
    }
    if case.prior_kv.len() != 32 * case.position as usize {
        return Err("kv shape");
    }
    if case.token_prefix.len() != 4 * (case.position as usize + 1) {
        return Err("token count");
    }
    if oc(enc::K_INPUT_MANIFEST, &case.input_manifest) != case.input_manifest_c {
        return Err("input manifest");
    }
    // 2. reconstruct derived input from the case's public ids + commitments
    let di = enc::Di {
        job_id: case.job_id,
        session_id: case.session_id,
        unit_id: case.unit_id,
        generation_index: case.position,
        model_id: case.model_id,
        model_commitment_identity: crate::plain(&case.model_commitment),
        layer_start: 0,
        layer_end: 1,
        prior_residual_commitment_identity: crate::plain(&case.prior_residual_c),
        prior_kv_commitment_identity: crate::plain(&case.prior_kv_c),
        token_prefix_commitment_identity: crate::plain(&case.token_prefix_c),
        position: case.position,
        sequence_length: case.sequence_length,
    };
    if enc::derived_input(&di) != case.derived_input {
        return Err("derived input bytes");
    }
    if oc(enc::K_DERIVED_INPUT, &case.derived_input) != case.derived_input_c {
        return Err("derived input commitment");
    }
    // 3. execute + recompute outputs
    let input_residual = arr8(&i16s(&case.prior_residual));
    let prior = parse_kv(&case.prior_kv);
    let (out_res, cur) =
        transformer::layer_group(table, &model, &input_residual, &prior).map_err(|_| "exec")?;
    let mut full = prior;
    full.push(cur);
    let out_kv: Vec<u8> = full
        .iter()
        .flat_map(|(k, v)| [i16_bytes(k), i16_bytes(v)].concat())
        .collect();
    let orc = oc(enc::K_RESIDUAL_STATE, &i16_bytes(&out_res));
    let okc = oc(enc::K_KV_STATE, &out_kv);
    if orc != case.output_residual_c || okc != case.output_kv_c {
        return Err("output state");
    }
    let om = enc::output_manifest(&[
        slot(enc::S_RESIDUAL_STREAM, case.position, orc),
        slot(enc::S_KV_CACHE, case.position, okc),
    ]);
    if oc(enc::K_OUTPUT_MANIFEST, &om) != case.output_manifest_c {
        return Err("output manifest");
    }
    if oc(enc::K_TOKEN_SEQ, &case.token_prefix) != case.updated_token_seq_c {
        return Err("updated token seq");
    }
    // 4. rebuild the full statement template from the public commitments + frozen
    //    constants and compare byte-for-byte (catches any public scalar mutation).
    let st = tlg_statement(
        &di,
        case.model_id,
        case.position,
        case.sequence_length,
        &case.model_commitment,
        &case.derived_input_c,
        &case.prior_residual_c,
        &case.prior_kv_c,
        &case.token_prefix_c,
        &case.input_manifest_c,
        &case.output_manifest_c,
        &case.updated_token_seq_c,
    );
    if enc::statement(&st) != case.template {
        return Err("statement template");
    }
    Ok(())
}

pub fn tlg_template_hash(case: &TlgCase) -> [u8; 32] {
    enc::template_hash(&case.template)
}

pub fn tlg_artifacts(case: &TlgCase) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("model", case.model.clone()),
        ("model_id", case.model_id.to_vec()),
        ("prior_residual", case.prior_residual.clone()),
        ("prior_kv", case.prior_kv.clone()),
        ("token_prefix", case.token_prefix.clone()),
        ("input_manifest", case.input_manifest.clone()),
        ("derived_input", case.derived_input.clone()),
        ("output_residual", case.output_residual.clone()),
        ("output_kv", case.output_kv.clone()),
        ("output_manifest", case.output_manifest.clone()),
        ("c_model", case.model_commitment.clone()),
        ("c_prior_residual", case.prior_residual_c.clone()),
        ("c_prior_kv", case.prior_kv_c.clone()),
        ("c_token_prefix", case.token_prefix_c.clone()),
        ("c_input_manifest", case.input_manifest_c.clone()),
        ("c_derived_input", case.derived_input_c.clone()),
        ("c_output_residual", case.output_residual_c.clone()),
        ("c_output_kv", case.output_kv_c.clone()),
        ("c_output_manifest", case.output_manifest_c.clone()),
        ("c_updated_token_seq", case.updated_token_seq_c.clone()),
        ("statement_template", case.template.clone()),
    ]
}

// ---------------- SelectToken ----------------

pub struct SelectCase {
    pub position: u32,
    pub sequence_length: u32,
    pub model: Vec<u8>,
    pub final_residual: Vec<u8>,
    pub token_prefix: Vec<u8>,
    pub input_manifest: Vec<u8>,
    pub derived_input: Vec<u8>,
    pub updated_token_seq: Vec<u8>,
    pub output_manifest: Vec<u8>,
    pub model_commitment: Vec<u8>,
    pub final_residual_c: Vec<u8>,
    pub prior_kv_c: Vec<u8>,
    pub token_prefix_c: Vec<u8>,
    pub input_manifest_c: Vec<u8>,
    pub derived_input_c: Vec<u8>,
    pub output_manifest_c: Vec<u8>,
    pub updated_token_seq_c: Vec<u8>,
    pub selected: u32,
    pub eos: u8,
    pub model_id: [u8; 32],
    pub template: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn select_statement(
    seed: &[u8; 32],
    model_id: [u8; 32],
    position: u32,
    seq_len: u32,
    selected: u32,
    eos: u8,
    model_c: &[u8],
    derived_c: &[u8],
    frc: &[u8],
    pkc: &[u8],
    tpc: &[u8],
    imc: &[u8],
    omc: &[u8],
    utsc: &[u8],
) -> enc::St {
    enc::St {
        b0_pre_spec_hash: [0; 32],
        job_id: id(seed, b"job"),
        session_id: id(seed, b"session"),
        unit_id: id(seed, b"unit/select-token"),
        unit_kind: 1,
        unit_index: 2 * position + 1,
        generation_index: position,
        model_id,
        model_commitment: model_c.to_vec(),
        tokenizer_id: tokenizer_id(),
        head_dim: 4,
        ffn_dim: 16,
        layer_start: u32::MAX,
        layer_end: u32::MAX,
        vocab_size: 16,
        d_model: 8,
        n_heads: 2,
        derived_input_commitment: derived_c.to_vec(),
        prior_residual_stream: frc.to_vec(),
        prior_kv_cache: pkc.to_vec(),
        token_prefix: tpc.to_vec(),
        input_manifest: imc.to_vec(),
        sequence_length: seq_len,
        position,
        output_manifest: omc.to_vec(),
        selected_token: selected,
        updated_token_seq_commitment: utsc.to_vec(),
        eos_flag: eos,
        max_cycles: 0,
        max_d_model: 8,
        max_seq_len: 8,
        max_output_tokens: 8,
        max_manifest_slots: 3,
        max_state_bytes: 2761,
    }
}

pub fn build_select(name: &[u8], position: u32) -> SelectCase {
    let seed = seed_of(name);
    let model = derive_model(&seed);
    let model_bytes = model.encode();
    let model_id = model.model_id();
    let seq_len = position + 1;
    let fr = arr8(&i16s(&stream(&seed, b"select/final_residual", 16)));
    let final_residual = i16_bytes(&fr);
    let tok_raw = stream(&seed, b"select/token_prefix", 4 * seq_len as usize);
    let tokens: Vec<u32> = tok_raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) % 16)
        .collect();
    let token_prefix: Vec<u8> = tokens.iter().flat_map(|t| t.to_le_bytes()).collect();
    let (selected, eos) = transformer::select_token(&model, &fr);
    let mut updated = tokens.clone();
    updated.push(selected);
    let updated_token_seq: Vec<u8> = updated.iter().flat_map(|t| t.to_le_bytes()).collect();

    let model_commitment = oc(enc::K_MODEL, &model_bytes);
    let final_residual_c = oc(enc::K_PRIOR_RESIDUAL, &final_residual);
    let token_prefix_c = oc(enc::K_TOKEN_PREFIX, &token_prefix);
    let prior_kv_c = enc::object_commitment_empty(enc::K_PRIOR_KV);
    let input_manifest = enc::input_manifest(&[
        slot(enc::IS_PRIOR_RESIDUAL, 0, final_residual_c.clone()),
        slot(enc::IS_TOKEN_PREFIX, 0, token_prefix_c.clone()),
    ]);
    let input_manifest_c = oc(enc::K_INPUT_MANIFEST, &input_manifest);
    let di = enc::Di {
        job_id: id(&seed, b"job"),
        session_id: id(&seed, b"session"),
        unit_id: id(&seed, b"unit/select-token"),
        generation_index: position,
        model_id,
        model_commitment_identity: crate::plain(&model_commitment),
        layer_start: u32::MAX,
        layer_end: u32::MAX,
        prior_residual_commitment_identity: crate::plain(&final_residual_c),
        prior_kv_commitment_identity: crate::plain(&prior_kv_c),
        token_prefix_commitment_identity: crate::plain(&token_prefix_c),
        position,
        sequence_length: seq_len,
    };
    let derived_input = enc::derived_input(&di);
    let derived_input_c = oc(enc::K_DERIVED_INPUT, &derived_input);
    let output_manifest = enc::output_manifest(&[]);
    let output_manifest_c = oc(enc::K_OUTPUT_MANIFEST, &output_manifest);
    let updated_token_seq_c = oc(enc::K_TOKEN_SEQ, &updated_token_seq);

    let st = select_statement(
        &seed,
        model_id,
        position,
        seq_len,
        selected,
        eos,
        &model_commitment,
        &derived_input_c,
        &final_residual_c,
        &prior_kv_c,
        &token_prefix_c,
        &input_manifest_c,
        &output_manifest_c,
        &updated_token_seq_c,
    );
    let template = enc::statement(&st);

    SelectCase {
        position,
        sequence_length: seq_len,
        model: model_bytes,
        final_residual,
        token_prefix,
        input_manifest,
        derived_input,
        updated_token_seq,
        output_manifest,
        model_commitment,
        final_residual_c,
        prior_kv_c,
        token_prefix_c,
        input_manifest_c,
        derived_input_c,
        output_manifest_c,
        updated_token_seq_c,
        selected,
        eos,
        model_id,
        template,
    }
}

pub fn verify_select(case: &SelectCase) -> Result<(), &'static str> {
    let model = Model::decode(&case.model).map_err(|_| "model decode")?;
    if oc(enc::K_MODEL, &case.model) != case.model_commitment || model.model_id() != case.model_id {
        return Err("model");
    }
    if oc(enc::K_PRIOR_RESIDUAL, &case.final_residual) != case.final_residual_c {
        return Err("final residual");
    }
    if oc(enc::K_TOKEN_PREFIX, &case.token_prefix) != case.token_prefix_c {
        return Err("token prefix");
    }
    if case.prior_kv_c != enc::object_commitment_empty(enc::K_PRIOR_KV) {
        return Err("prior kv must be empty");
    }
    if case.token_prefix.is_empty() {
        return Err("empty prefix");
    }
    if case.sequence_length >= 8 {
        return Err("sequence overflow");
    }
    if oc(enc::K_INPUT_MANIFEST, &case.input_manifest) != case.input_manifest_c {
        return Err("input manifest");
    }
    if oc(enc::K_OUTPUT_MANIFEST, &enc::output_manifest(&[])) != case.output_manifest_c {
        return Err("output manifest must be empty");
    }
    // execute + recompute selection
    let fr = arr8(&i16s(&case.final_residual));
    let (selected, eos) = transformer::select_token(&model, &fr);
    if selected != case.selected || eos != case.eos {
        return Err("selection");
    }
    if selected >= 16 {
        return Err("selected out of range");
    }
    if ((selected == 15) as u8) != case.eos {
        return Err("eos flag");
    }
    let mut updated = case.token_prefix.clone();
    updated.extend_from_slice(&selected.to_le_bytes());
    if updated != case.updated_token_seq
        || oc(enc::K_TOKEN_SEQ, &updated) != case.updated_token_seq_c
    {
        return Err("updated token seq");
    }
    Ok(())
}

pub fn select_template_hash(case: &SelectCase) -> [u8; 32] {
    enc::template_hash(&case.template)
}

pub fn select_artifacts(case: &SelectCase) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("model", case.model.clone()),
        ("model_id", case.model_id.to_vec()),
        ("final_residual", case.final_residual.clone()),
        ("token_prefix", case.token_prefix.clone()),
        ("input_manifest", case.input_manifest.clone()),
        ("derived_input", case.derived_input.clone()),
        ("updated_token_seq", case.updated_token_seq.clone()),
        ("output_manifest", case.output_manifest.clone()),
        ("selected_token", case.selected.to_le_bytes().to_vec()),
        ("eos_flag", vec![case.eos]),
        ("c_model", case.model_commitment.clone()),
        ("c_final_residual", case.final_residual_c.clone()),
        ("c_prior_kv_empty", case.prior_kv_c.clone()),
        ("c_token_prefix", case.token_prefix_c.clone()),
        ("c_input_manifest", case.input_manifest_c.clone()),
        ("c_derived_input", case.derived_input_c.clone()),
        ("c_output_manifest_empty", case.output_manifest_c.clone()),
        ("c_updated_token_seq", case.updated_token_seq_c.clone()),
        ("statement_template", case.template.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlg_and_select_verify_and_mutations_reject() {
        for pos in [0u32, 1, 2, 7] {
            assert_eq!(
                verify_tlg(&build_tlg(b"official-workload-v1", pos)),
                Ok(()),
                "tlg {pos}"
            );
        }
        assert_eq!(
            verify_select(&build_select(b"official-workload-v1", 6)),
            Ok(())
        );

        // TLG mutation matrix (equalized with the reference)
        let base = build_tlg(b"official-workload-v1", 3);
        type Mt = Box<dyn Fn(&TlgCase) -> TlgCase>;
        let cl = |_c: &TlgCase| build_tlg(b"official-workload-v1", 3);
        let tlg: Vec<(&str, Mt)> = vec![
            (
                "model_tensor_byte",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.model[500] ^= 1;
                    x
                }),
            ),
            (
                "attn_gamma",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.model[6] ^= 1;
                    x
                }),
            ),
            (
                "ffn_gamma",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.model[534] ^= 1;
                    x
                }),
            ),
            (
                "final_gamma",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.model[1062] ^= 1;
                    x
                }),
            ),
            (
                "prior_residual_byte",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.prior_residual[0] ^= 1;
                    x
                }),
            ),
            (
                "prior_k_byte",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.prior_kv[0] ^= 1;
                    x
                }),
            ),
            (
                "prior_v_byte",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.prior_kv[16] ^= 1;
                    x
                }),
            ),
            (
                "token_byte",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.token_prefix[0] ^= 1;
                    x
                }),
            ),
            (
                "input_manifest_descriptor",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.input_manifest[40] ^= 1;
                    x
                }),
            ),
            (
                "c_model",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.model_commitment[48] ^= 1;
                    x
                }),
            ),
            (
                "c_prior_kv",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.prior_kv_c[48] ^= 1;
                    x
                }),
            ),
            (
                "c_token_prefix",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.token_prefix_c[48] ^= 1;
                    x
                }),
            ),
            (
                "c_input_manifest",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.input_manifest_c[48] ^= 1;
                    x
                }),
            ),
            (
                "c_derived_input",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.derived_input_c[48] ^= 1;
                    x
                }),
            ),
            (
                "c_output_manifest",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.output_manifest_c[48] ^= 1;
                    x
                }),
            ),
            (
                "c_updated_seq",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.updated_token_seq_c[48] ^= 1;
                    x
                }),
            ),
            (
                "template_position",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.template[793] ^= 1;
                    x
                }),
            ),
            (
                "template_seq_len",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.template[789] ^= 1;
                    x
                }),
            ),
            (
                "template_dim",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.template[381] ^= 1;
                    x
                }),
            ),
            (
                "template_bound",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.template[988] ^= 1;
                    x
                }),
            ),
            (
                "template_unit_kind",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.template[194] ^= 1;
                    x
                }),
            ),
            (
                "template_selected",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.template[879] ^= 1;
                    x
                }),
            ),
            (
                "template_eos",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.template[963] ^= 1;
                    x
                }),
            ),
            (
                "trailing_byte",
                Box::new(move |c| {
                    let mut x = cl(c);
                    x.model.push(0);
                    x
                }),
            ),
        ];
        for (n, m) in &tlg {
            assert!(verify_tlg(&m(&base)).is_err(), "tlg `{n}` must reject");
        }

        // SelectToken mutation matrix
        let sbase = build_select(b"official-workload-v1", 6);
        type Ms = Box<dyn Fn(&SelectCase) -> SelectCase>;
        let cs = |_c: &SelectCase| build_select(b"official-workload-v1", 6);
        let sel: Vec<(&str, Ms)> = vec![
            (
                "model_byte",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.model[500] ^= 1;
                    x
                }),
            ),
            (
                "final_residual_byte",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.final_residual[0] ^= 1;
                    x
                }),
            ),
            (
                "token_byte",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.token_prefix[0] ^= 1;
                    x
                }),
            ),
            (
                "input_manifest_byte",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.input_manifest[40] ^= 1;
                    x
                }),
            ),
            (
                "c_final_residual",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.final_residual_c[48] ^= 1;
                    x
                }),
            ),
            (
                "selected",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.selected ^= 1;
                    x
                }),
            ),
            (
                "eos",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.eos ^= 1;
                    x
                }),
            ),
            (
                "updated_seq_c",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.updated_token_seq_c[48] ^= 1;
                    x
                }),
            ),
            (
                "prior_kv_not_empty",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.prior_kv_c = oc(enc::K_PRIOR_KV, b"x");
                    x
                }),
            ),
            (
                "output_manifest_not_empty",
                Box::new(move |c| {
                    let mut x = cs(c);
                    x.output_manifest_c = oc(enc::K_OUTPUT_MANIFEST, b"x");
                    x
                }),
            ),
        ];
        for (n, m) in &sel {
            assert!(
                verify_select(&m(&sbase)).is_err(),
                "select `{n}` must reject"
            );
        }
    }
}

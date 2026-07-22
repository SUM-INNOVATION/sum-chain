//! The §10 witness→statement contract, guest form: authenticate every private
//! witness byte against the ONE public statement, re-execute the frozen
//! transformer, recompute every public output, and reject on any mismatch.
//!
//! This is the byte-driven counterpart of the frozen reference
//! `b0-pre-validator::workload::{verify_tlg, verify_select}` (which the reference
//! documents as "the guest-side contract"). It differs only in that it consumes
//! the decoded [`GuestInput`] witness bytes and the statement's own `position`
//! rather than a host-built `TlgCase`/`SelectCase`; the semantic checks are the
//! same. Every wire structure is decoded through the FROZEN `sumchain-wire::b0`
//! types — there is no mirror.

use sumchain_wire::b0::consts;
use sumchain_wire::b0::derived_input::DerivedInputV1;
use sumchain_wire::b0::enums::{InputSlotKind, ObjectKind, SlotKind, UnitKind};
use sumchain_wire::b0::manifest::{InputManifestV1, OutputManifestV1, SlotDescriptorV1};
use sumchain_wire::b0::object_commitment::ObjectCommitmentV1;
use sumchain_wire::b0::statement::R0ComputationStatementV2;

use crate::input::GuestInput;
use crate::transformer::{self, Model};
use crate::GuestError;

fn sem(reason: &'static str) -> GuestError {
    GuestError::Semantic(reason)
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
fn arr8(v: &[i16]) -> Result<[i16; 8], GuestError> {
    <[i16; 8]>::try_from(v).map_err(|_| sem("residual shape"))
}
fn parse_kv(bytes: &[u8]) -> Result<Vec<transformer::Kv>, GuestError> {
    if bytes.len() % 32 != 0 {
        return Err(sem("kv shape"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for c in bytes.chunks_exact(32) {
        out.push((arr8(&i16s(&c[0..16]))?, arr8(&i16s(&c[16..32]))?));
    }
    Ok(out)
}

/// The frozen tokenizer-context id (§7). Constant, self-derived — not a measured
/// or venue value.
fn tokenizer_id() -> [u8; 32] {
    blake3::hash(b"SUMCHAIN/R0/TOKCTX/external-pretokenized-u32/v1").into()
}

fn commit(kind: ObjectKind, data: &[u8]) -> Result<ObjectCommitmentV1, GuestError> {
    ObjectCommitmentV1::commit(kind, data).map_err(GuestError::Decode)
}

/// Decode the statement, dispatch on its `unit_kind`, verify the witness→statement
/// contract, and return the guest's ONLY committed output: the
/// `computation_statement_hash` over the re-canonicalized 996 statement bytes.
pub fn verify_and_journal(input: &GuestInput) -> Result<[u8; 32], GuestError> {
    let statement = R0ComputationStatementV2::decode_exact(&input.statement)?;
    match statement.unit_kind {
        UnitKind::TransformerLayerGroup => verify_tlg(&statement, input)?,
        UnitKind::SelectToken => verify_select(&statement, input)?,
    }
    // The single public journal: BLAKE3 of the validated canonical statement.
    // `try_identity` re-validates + re-encodes, so the hash is over canonical
    // bytes and equals `computation_statement_hash` (§17).
    statement.try_identity().map_err(GuestError::Decode)
}

fn require<'a>(w: &'a Option<Vec<u8>>, name: &'static str) -> Result<&'a [u8], GuestError> {
    w.as_deref().ok_or(GuestError::Semantic(name))
}
fn forbid(w: &Option<Vec<u8>>, name: &'static str) -> Result<(), GuestError> {
    if w.is_some() {
        return Err(GuestError::Semantic(name));
    }
    Ok(())
}

fn verify_tlg(s: &R0ComputationStatementV2, input: &GuestInput) -> Result<(), GuestError> {
    let model_bytes = require(&input.model, "missing model")?;
    let prior_residual = require(&input.residual, "missing residual")?;
    let prior_kv = require(&input.prior_kv, "missing prior_kv")?;
    let token_prefix = require(&input.token_prefix, "missing token_prefix")?;
    let input_manifest = require(&input.input_manifest, "missing input_manifest")?;

    // frozen constants / bounds
    if (s.d_model, s.n_heads, s.head_dim, s.ffn_dim, s.vocab_size) != (8, 2, 4, 16, 16) {
        return Err(sem("frozen dims"));
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
        return Err(sem("frozen bounds"));
    }
    if s.layer_start != 0 || s.layer_end != 1 || s.unit_kind != UnitKind::TransformerLayerGroup {
        return Err(sem("unit sentinels"));
    }
    if s.tokenizer_id != tokenizer_id() {
        return Err(sem("tokenizer id"));
    }
    let position = s.position;
    if s.sequence_length != position + 1 {
        return Err(sem("position/length"));
    }
    if (position as usize) >= transformer::MAX_SEQ {
        return Err(sem("sequence overflow"));
    }

    // authenticate model
    let model = Model::decode(model_bytes).map_err(|_| sem("model decode"))?;
    if commit(ObjectKind::Model, model_bytes)? != s.model_commitment {
        return Err(sem("model commitment"));
    }
    if model.model_id() != s.model_id {
        return Err(sem("model id"));
    }
    // authenticate inputs
    if commit(ObjectKind::PriorResidual, prior_residual)? != s.prior_residual_stream {
        return Err(sem("prior residual"));
    }
    let expect_kv = if position == 0 {
        ObjectCommitmentV1::empty(ObjectKind::PriorKv)
    } else {
        commit(ObjectKind::PriorKv, prior_kv)?
    };
    if expect_kv != s.prior_kv_cache {
        return Err(sem("prior kv"));
    }
    if commit(ObjectKind::TokenPrefix, token_prefix)? != s.token_prefix {
        return Err(sem("token prefix"));
    }
    if prior_kv.len() != 32 * position as usize {
        return Err(sem("kv shape"));
    }
    if token_prefix.len() != 4 * (position as usize + 1) {
        return Err(sem("token count"));
    }

    // input manifest slots must bind the embedded commitments
    let im =
        InputManifestV1::decode_exact(input_manifest).map_err(|_| sem("input manifest decode"))?;
    if im.slots.len() != 3
        || im.slots[0].commitment != s.prior_residual_stream
        || im.slots[1].commitment != s.prior_kv_cache
        || im.slots[2].commitment != s.token_prefix
    {
        return Err(sem("input manifest slots"));
    }
    if commit(ObjectKind::InputManifest, input_manifest)? != s.input_manifest {
        return Err(sem("input manifest commitment"));
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
    let di_bytes = di.encode();
    if commit(ObjectKind::DerivedInput, &di_bytes)? != s.derived_input_commitment {
        return Err(sem("derived input"));
    }

    // execute and recompute outputs
    let input_residual = arr8(&i16s(prior_residual))?;
    if prior_residual.len() != 16 {
        return Err(sem("residual shape"));
    }
    let prior = parse_kv(prior_kv)?;
    let (out_res, cur) =
        transformer::layer_group(crate::exp::table(), &model, &input_residual, &prior)
            .map_err(|_| sem("exec"))?;
    let out_res_bytes = i16_bytes(&out_res);
    let mut full = prior;
    full.push(cur);
    let out_kv_bytes: Vec<u8> = full
        .iter()
        .flat_map(|(k, v)| [i16_bytes(k), i16_bytes(v)].concat())
        .collect();

    // checked max_state_bytes before trusting the recomputed outputs
    let state: u64 = [
        model_bytes.len(),
        prior_residual.len(),
        prior_kv.len(),
        token_prefix.len(),
        input_manifest.len(),
        di_bytes.len(),
        out_res_bytes.len(),
        out_kv_bytes.len(),
    ]
    .iter()
    .map(|&x| x as u64)
    .sum::<u64>()
        + 208
        + token_prefix.len() as u64; // output manifest + updated token seq
    if state > s.max_state_bytes {
        return Err(sem("max_state_bytes"));
    }

    let output_residual_c = commit(ObjectKind::ResidualState, &out_res_bytes)?;
    let output_kv_c = commit(ObjectKind::KvState, &out_kv_bytes)?;
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
    if om.try_commitment().map_err(GuestError::Decode)? != s.output_manifest {
        return Err(sem("output manifest"));
    }
    // sentinels
    if s.selected_token != u32::MAX || s.eos_flag != 0 {
        return Err(sem("tlg sentinels"));
    }
    if commit(ObjectKind::TokenSeq, token_prefix)? != s.updated_token_seq_commitment {
        return Err(sem("updated token seq"));
    }
    Ok(())
}

fn verify_select(s: &R0ComputationStatementV2, input: &GuestInput) -> Result<(), GuestError> {
    let model_bytes = require(&input.model, "missing model")?;
    let final_residual = require(&input.residual, "missing residual")?;
    let token_prefix = require(&input.token_prefix, "missing token_prefix")?;
    let input_manifest = require(&input.input_manifest, "missing input_manifest")?;
    forbid(&input.prior_kv, "unexpected prior_kv")?;

    // frozen constants / bounds (same table as TLG)
    if (s.d_model, s.n_heads, s.head_dim, s.ffn_dim, s.vocab_size) != (8, 2, 4, 16, 16) {
        return Err(sem("frozen dims"));
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
        return Err(sem("frozen bounds"));
    }
    if s.unit_kind != UnitKind::SelectToken || s.layer_start != u32::MAX || s.layer_end != u32::MAX
    {
        return Err(sem("select sentinels"));
    }
    if s.tokenizer_id != tokenizer_id() {
        return Err(sem("tokenizer id"));
    }
    if s.prior_kv_cache != ObjectCommitmentV1::empty(ObjectKind::PriorKv) {
        return Err(sem("prior kv must be empty"));
    }
    if s.token_prefix.byte_len() == 0 {
        return Err(sem("empty prefix"));
    }
    if s.sequence_length >= 8 {
        return Err(sem("sequence overflow"));
    }
    if s.sequence_length != s.position + 1 {
        return Err(sem("position/length"));
    }

    let model = Model::decode(model_bytes).map_err(|_| sem("model decode"))?;
    if commit(ObjectKind::Model, model_bytes)? != s.model_commitment
        || model.model_id() != s.model_id
    {
        return Err(sem("model"));
    }
    if final_residual.len() != 16 {
        return Err(sem("residual shape"));
    }
    if commit(ObjectKind::PriorResidual, final_residual)? != s.prior_residual_stream {
        return Err(sem("final residual"));
    }
    if commit(ObjectKind::TokenPrefix, token_prefix)? != s.token_prefix {
        return Err(sem("token prefix"));
    }
    if token_prefix.len() != 4 * s.sequence_length as usize {
        return Err(sem("token count"));
    }
    let im = InputManifestV1::decode_exact(input_manifest).map_err(|_| sem("im decode"))?;
    if im.slots.len() != 2
        || im.slots[0].slot_kind != InputSlotKind::PriorResidual
        || im.slots[1].slot_kind != InputSlotKind::TokenPrefix
        || im.slots[0].commitment != s.prior_residual_stream
        || im.slots[1].commitment != s.token_prefix
    {
        return Err(sem("input manifest slots"));
    }
    if commit(ObjectKind::InputManifest, input_manifest)? != s.input_manifest {
        return Err(sem("input manifest commitment"));
    }

    // reconstruct + authenticate derived input (SelectToken uses u32::MAX layers)
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
    if commit(ObjectKind::DerivedInput, &di.encode())? != s.derived_input_commitment {
        return Err(sem("derived input"));
    }

    // output manifest must be the canonical empty manifest
    if (OutputManifestV1 { slots: vec![] })
        .try_commitment()
        .map_err(GuestError::Decode)?
        != s.output_manifest
    {
        return Err(sem("output manifest must be empty"));
    }

    // execute + recompute selection
    let fr = arr8(&i16s(final_residual))?;
    let (selected, eos) = transformer::select_token(&model, &fr);
    if selected != s.selected_token || eos != s.eos_flag {
        return Err(sem("selection"));
    }
    if selected >= s.vocab_size {
        return Err(sem("selected out of range"));
    }
    if (selected == s.vocab_size - 1) as u8 != s.eos_flag {
        return Err(sem("eos flag"));
    }
    // updated token sequence = prefix ‖ selected
    let mut updated = token_prefix.to_vec();
    updated.extend_from_slice(&selected.to_le_bytes());
    if commit(ObjectKind::TokenSeq, &updated)? != s.updated_token_seq_commitment {
        return Err(sem("updated token seq"));
    }
    Ok(())
}

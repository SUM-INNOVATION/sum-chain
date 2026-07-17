//! Cross-check: the independent pipeline must reproduce, byte-for-byte, the
//! golden vectors emitted by `b0-pre-validator` (shared fixture file). No
//! dependency edge to the reference crate — only the fixture is shared.

use b0_pre_independent::enc::{self, Di, Slot, St};
use b0_pre_independent::merkle;

const VECTORS: &str = include_str!("../../../docs/b0-pre/fixtures/encoding-golden/vectors.json");

const G: &[u8] = b"g";
const SPEC_HASH: [u8; 32] = [0x9c; 32];

fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn get<'a>(v: &'a serde_json::Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str().unwrap_or_else(|| panic!("missing {:?}", path))
}

fn di() -> Di {
    Di {
        job_id: [0x11; 32],
        session_id: [0x22; 32],
        unit_id: [0x33; 32],
        generation_index: 7,
        model_id: [0x44; 32],
        model_commitment_identity: [0x55; 32],
        layer_start: 0,
        layer_end: 1,
        prior_residual_commitment_identity: [0x66; 32],
        prior_kv_commitment_identity: [0x77; 32],
        token_prefix_commitment_identity: [0x88; 32],
        position: 7,
        sequence_length: 8,
    }
}

fn output_slots() -> Vec<Slot> {
    vec![
        Slot {
            kind: enc::S_RESIDUAL_STREAM,
            index: 7,
            commitment: enc::object_commitment(enc::K_RESIDUAL_STATE, G),
        },
        Slot {
            kind: enc::S_KV_CACHE,
            index: 7,
            commitment: enc::object_commitment(enc::K_KV_STATE, G),
        },
    ]
}

fn input_slots() -> Vec<Slot> {
    vec![
        Slot {
            kind: enc::IS_PRIOR_RESIDUAL,
            index: 0,
            commitment: enc::object_commitment(enc::K_PRIOR_RESIDUAL, G),
        },
        Slot {
            kind: enc::IS_PRIOR_KV,
            index: 0,
            commitment: enc::object_commitment(enc::K_PRIOR_KV, G),
        },
        Slot {
            kind: enc::IS_TOKEN_PREFIX,
            index: 0,
            commitment: enc::object_commitment(enc::K_TOKEN_PREFIX, G),
        },
    ]
}

fn statement_template() -> Vec<u8> {
    let oc = |k| enc::object_commitment(k, G);
    let st = St {
        b0_pre_spec_hash: [0; 32],
        job_id: [0x11; 32],
        session_id: [0x22; 32],
        unit_id: [0x33; 32],
        unit_kind: enc::unit_kind_tlg(),
        unit_index: 14,
        generation_index: 7,
        model_id: [0x44; 32],
        model_commitment: oc(enc::K_MODEL),
        tokenizer_id: [0x55; 32],
        head_dim: 4,
        ffn_dim: 16,
        layer_start: 0,
        layer_end: 1,
        vocab_size: 16,
        d_model: 8,
        n_heads: 2,
        derived_input_commitment: oc(enc::K_DERIVED_INPUT),
        prior_residual_stream: oc(enc::K_PRIOR_RESIDUAL),
        prior_kv_cache: oc(enc::K_PRIOR_KV),
        token_prefix: oc(enc::K_TOKEN_PREFIX),
        input_manifest: oc(enc::K_INPUT_MANIFEST),
        sequence_length: 8,
        position: 7,
        output_manifest: oc(enc::K_OUTPUT_MANIFEST),
        selected_token: u32::MAX,
        updated_token_seq_commitment: oc(enc::K_TOKEN_SEQ),
        eos_flag: 0,
        max_cycles: 0,
        max_d_model: 8,
        max_seq_len: 8,
        max_output_tokens: 8,
        max_manifest_slots: 3,
        max_state_bytes: 2761,
    };
    enc::statement(&st)
}

#[test]
fn independent_pipeline_matches_golden_vectors() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();

    // object commitment
    let oc = enc::object_commitment(enc::K_MODEL, b"golden-model");
    assert_eq!(
        hx(&oc),
        get(&v, &["object_commitment_model_golden", "bytes"])
    );
    assert_eq!(
        hx(&b0_pre_independent::plain(&oc)),
        get(&v, &["object_commitment_model_golden", "identity"])
    );

    // empty prior-kv
    let ek = enc::object_commitment_empty(enc::K_PRIOR_KV);
    assert_eq!(hx(&ek), get(&v, &["empty_prior_kv", "bytes"]));
    assert_eq!(
        hx(&b0_pre_independent::plain(&ek)),
        get(&v, &["empty_prior_kv", "identity"])
    );

    // merkle multichunk
    let n = 2 * merkle::CHUNK + 7;
    let mut buf = vec![0u8; n];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i as u64 * 31 + 7) & 0xff) as u8;
    }
    assert_eq!(
        hx(&merkle::root(&buf)),
        get(&v, &["merkle_multichunk_root"])
    );

    // derived input
    let di_bytes = enc::derived_input(&di());
    assert_eq!(hx(&di_bytes), get(&v, &["derived_input", "bytes"]));
    assert_eq!(
        hx(&b0_pre_independent::plain(&di_bytes)),
        get(&v, &["derived_input", "identity"])
    );

    // manifests
    assert_eq!(
        hx(&enc::output_manifest(&output_slots())),
        get(&v, &["output_manifest_2slot", "bytes"])
    );
    assert_eq!(
        hx(&enc::output_manifest_commitment_identity(&output_slots())),
        get(&v, &["output_manifest_2slot", "commitment_identity"])
    );
    assert_eq!(
        hx(&enc::input_manifest(&input_slots())),
        get(&v, &["input_manifest_3slot", "bytes"])
    );
    assert_eq!(
        hx(&enc::input_manifest_commitment_identity(&input_slots())),
        get(&v, &["input_manifest_3slot", "commitment_identity"])
    );

    // statement template + final
    let template = statement_template();
    assert_eq!(hx(&template), get(&v, &["statement_template", "bytes"]));
    assert_eq!(
        hx(&enc::template_hash(&template)),
        get(&v, &["statement_template", "template_hash"])
    );

    let final_bytes = enc::materialize_final(&template, &SPEC_HASH);
    assert_eq!(hx(&final_bytes), get(&v, &["statement_final", "bytes"]));
    assert_eq!(
        hx(&enc::computation_statement_hash(&final_bytes)),
        get(&v, &["statement_final", "computation_statement_hash"])
    );
    assert_eq!(hx(&SPEC_HASH), get(&v, &["statement_final", "spec_hash"]));
}

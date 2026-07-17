//! Wave 2A golden tests for the production `b0` wire types.
//!
//! Two kinds of byte-equality are proven here:
//!  1. Against the committed **frozen fixtures** in
//!     `docs/b0-pre/fixtures/closure-golden/vectors.json` — the same vectors the
//!     B0-PRE reference and independent crates agree on: the verifier-material
//!     manifest identity and re-encode, and the empty allowlist's guest-set hash
//!     and re-encode.
//!  2. Against the **frozen reference encoder** — the `*_HEX` constants below were
//!     emitted by a throwaway binary that path-depends on `b0-pre-validator` and
//!     encodes the SAME fixed instances reproduced here (`fixed_*`). The
//!     production `encode()` must equal them byte-for-byte. That binary is scratch
//!     only; it is never added to the repo or the workspace.
//!
//! Plus strict-decoder negatives and the pure cross-binding checks for the two
//! new proof types (`PartialComputeProofV1`, `ProductionProofEnvelopeV1`).

use sumchain_wire::b0::allowlist::{BuilderArch, GuestProgramAllowlistV1, GuestProgramEntryV1};
use sumchain_wire::b0::codec::DecodeError;
use sumchain_wire::b0::derived_input::DerivedInputV1;
use sumchain_wire::b0::enums::{
    Arch, Candidate, InputSlotKind, ObjectKind, SlotKind, UnitKind, VerifierMaterialRole,
};
use sumchain_wire::b0::manifest::{
    InputManifestV1, InputSlotDescriptorV1, OutputManifestV1, SlotDescriptorV1,
};
use sumchain_wire::b0::object_commitment::ObjectCommitmentV1;
use sumchain_wire::b0::partial_proof::PartialComputeProofV1;
use sumchain_wire::b0::proof_envelope::{
    allowlist_membership, shared_binding_ok, MembershipError, ProductionProofEnvelopeV1,
};
use sumchain_wire::b0::statement::R0ComputationStatementV2;
use sumchain_wire::b0::tags;
use sumchain_wire::b0::verifier_material::{VerifierMaterialEntry, VerifierMaterialManifestV1};
use sumchain_wire::b0::workload;

// Crate-local copy of the frozen closure-golden vectors so the published crate is
// self-contained (byte-identical to docs/b0-pre/fixtures/closure-golden/vectors.json).
const V: &str = include_str!("fixtures/closure-golden-vectors.json");

// Frozen reference-encoder hex for the fixed instances built in `fixed_*` below.
const OBJECT_COMMITMENT_HEX: &str = "53554d434841494e2f52302f4f424a4543542f763100000000000000000000000100010017000000000000000100000004e4ef17c5602584d46b89e3ab1fd929173fb747d587fece3d4eedbe0de013f0";
const OUTPUT_MANIFEST_HEX: &str = "53554d434841494e2f52302f4d414e49464553542f7631000000000000000000010002000000000500000053554d434841494e2f52302f4f424a4543542f7631000000000000000000000001000600190000000000000001000000cea792f0d72bf681fce93b32c968117dd8c4259fcfd5b3b6c726cb1984f4d893010500000053554d434841494e2f52302f4f424a4543542f7631000000000000000000000001000700130000000000000001000000d4a46282ed2345300bef031d1b5b82e0ae401cda463fe04b67b05a502aaa05b5";
const INPUT_MANIFEST_HEX: &str = "53554d434841494e2f52302f494e4d414e49464553542f763100000000000000010003000000000000000053554d434841494e2f52302f4f424a4543542f7631000000000000000000000001000b001f0000000000000001000000f1348055cf36a53c9a9754c81626a509622a645baaef36205abe4017d0d946c4010000000053554d434841494e2f52302f4f424a4543542f7631000000000000000000000001000c00190000000000000001000000b235cdcc6db75afc5ced869afa8f7c50ada48f4861f817d72bfb8e9fa57625be020000000053554d434841494e2f52302f4f424a4543542f76310000000000000000000000010003001d00000000000000010000000dac6ad054ea49d8959ede1c9733106d3606cfb22d5abd29c7762a5c92ccfb4a";
const DERIVED_INPUT_HEX: &str = "53554d434841494e2f52302f4445524956494e2f763100000000000000000000010053554d434841494e2f52302f52434841494e2f763100000000000000000000001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330700000044444444444444444444444444444444444444444444444444444444444444445555555555555555555555555555555555555555555555555555555555555555000000000100000066666666666666666666666666666666666666666666666666666666666666667777777777777777777777777777777777777777777777777777777777777777888888888888888888888888888888888888888888888888888888888888888807000000080000000100010001003052";
const STATEMENT_HEX: &str = "53554d434841494e2f52302f53544154454d454e542f763200000000000000000100abababababababababababababababababababababababababababababababab53554d434841494e2f52302f52434841494e2f7631000000000000000000000001010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030300000e00000007000000040404040404040404040404040404040404040404040404040404040404040453554d434841494e2f52302f4f424a4543542f76310000000000000000000000010001001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e890505050505050505050505050505050505050505050505050505050505050505000000000801000100305201000100040010000100000000000100000010000000080000000200000053554d434841494e2f52302f4f424a4543542f76310000000000000000000000010009001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e8953554d434841494e2f52302f4f424a4543542f7631000000000000000000000001000b001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e8953554d434841494e2f52302f4f424a4543542f7631000000000000000000000001000c001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e8953554d434841494e2f52302f4f424a4543542f76310000000000000000000000010003001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e8953554d434841494e2f52302f4f424a4543542f76310000000000000000000000010004001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e890800000007000000010053554d434841494e2f52302f4f424a4543542f76310000000000000000000000010005001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e89ffffffff53554d434841494e2f52302f4f424a4543542f7631000000000000000000000001000a001d00000000000000010000000d796df45f1e5afed1179c0f151e2eb28c9ffc08cc8e538fb71c9a177b062e8900000000000000000008000000080000000800000003000000c90a000000000000";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}
fn hx(b: &[u8]) -> String {
    hex::encode(b)
}
fn fixture() -> serde_json::Value {
    serde_json::from_str(V).expect("parse fixture json")
}
fn jstr(j: &serde_json::Value, path: &[&str]) -> String {
    let mut c = j;
    for k in path {
        c = &c[*k];
    }
    c.as_str().expect("string node").to_string()
}

// ---- fixed instances; MUST match the refgen binary field-for-field ----
// The commits below are all valid, so `commit(...).unwrap()` yields exactly the
// bytes the (previously infallible) reference encoder produced — the frozen
// reference hex above is therefore unchanged.
fn commit_oc(kind: ObjectKind, data: &[u8]) -> ObjectCommitmentV1 {
    ObjectCommitmentV1::commit(kind, data).unwrap()
}
fn fixed_object() -> ObjectCommitmentV1 {
    commit_oc(ObjectKind::Model, b"wave2a-refgen/object/v1")
}
fn fixed_output_manifest() -> OutputManifestV1 {
    OutputManifestV1 {
        slots: vec![
            SlotDescriptorV1 {
                slot_kind: SlotKind::ResidualStream,
                slot_index: 5,
                commitment: commit_oc(ObjectKind::ResidualState, b"wave2a-refgen/residual/v1"),
            },
            SlotDescriptorV1 {
                slot_kind: SlotKind::KvCache,
                slot_index: 5,
                commitment: commit_oc(ObjectKind::KvState, b"wave2a-refgen/kv/v1"),
            },
        ],
    }
}
fn fixed_input_manifest() -> InputManifestV1 {
    InputManifestV1 {
        slots: vec![
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorResidual,
                slot_index: 0,
                commitment: commit_oc(
                    ObjectKind::PriorResidual,
                    b"wave2a-refgen/prior-residual/v1",
                ),
            },
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::PriorKv,
                slot_index: 0,
                commitment: commit_oc(ObjectKind::PriorKv, b"wave2a-refgen/prior-kv/v1"),
            },
            InputSlotDescriptorV1 {
                slot_kind: InputSlotKind::TokenPrefix,
                slot_index: 0,
                commitment: commit_oc(ObjectKind::TokenPrefix, b"wave2a-refgen/token-prefix/v1"),
            },
        ],
    }
}
fn fixed_derived_input() -> DerivedInputV1 {
    DerivedInputV1 {
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
fn fixed_statement() -> R0ComputationStatementV2 {
    let oc = |kind| commit_oc(kind, b"wave2a-refgen/stmt-payload/v1");
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

// ---------- 1. verifier material (fixture byte-equality) ----------
#[test]
fn verifier_material_identity_and_reencode_match_fixture() {
    let j = fixture();
    let bytes = unhex(&jstr(&j, &["valid", "verifier_material", "bytes"]));
    let vm = VerifierMaterialManifestV1::decode_exact(&bytes).unwrap();
    assert_eq!(
        hx(&vm.try_identity().unwrap()),
        jstr(&j, &["valid", "verifier_material", "identity"])
    );
    assert_eq!(vm.verifier_material_bytes().unwrap(), 292);
    assert_eq!(
        vm.try_encode().unwrap(),
        bytes,
        "re-encode must be byte-identical"
    );
}

// ---------- 2. empty allowlist (fixture byte-equality) ----------
#[test]
fn allowlist_empty_guest_set_hash_and_reencode_match_fixture() {
    let j = fixture();
    let bytes = unhex(&jstr(&j, &["valid", "allowlist_empty", "bytes"]));
    let al = GuestProgramAllowlistV1::decode_exact(&bytes).unwrap();
    assert!(al.entries.is_empty());
    assert_eq!(
        hx(&al.try_guest_set_hash().unwrap()),
        jstr(&j, &["valid", "allowlist_empty", "guest_set_hash"])
    );
    assert_eq!(
        al.try_encode().unwrap(),
        bytes,
        "re-encode must be byte-identical"
    );
}

// ---------- 3. frozen structs: length + reference bytes + round-trip ----------
#[test]
fn frozen_structs_match_reference_bytes_and_roundtrip() {
    // ObjectCommitmentV1 — 80
    let obj = fixed_object();
    let obj_b = obj.encode();
    assert_eq!(obj_b.len(), 80);
    assert_eq!(hx(&obj_b), OBJECT_COMMITMENT_HEX);
    assert_eq!(ObjectCommitmentV1::decode_exact(&obj_b).unwrap(), obj);

    // OutputManifestV1 — 38 + 85n
    let om = fixed_output_manifest();
    let om_b = om.try_encode().unwrap();
    assert_eq!(om_b.len(), 38 + 2 * 85);
    assert_eq!(hx(&om_b), OUTPUT_MANIFEST_HEX);
    assert_eq!(OutputManifestV1::decode_exact(&om_b).unwrap(), om);

    // InputManifestV1 — 38 + 85n
    let im = fixed_input_manifest();
    let im_b = im.try_encode().unwrap();
    assert_eq!(im_b.len(), 38 + 3 * 85);
    assert_eq!(hx(&im_b), INPUT_MANIFEST_HEX);
    assert_eq!(InputManifestV1::decode_exact(&im_b).unwrap(), im);

    // DerivedInputV1 — 350
    let di = fixed_derived_input();
    let di_b = di.encode();
    assert_eq!(di_b.len(), 350);
    assert_eq!(hx(&di_b), DERIVED_INPUT_HEX);
    assert_eq!(DerivedInputV1::decode_exact(&di_b).unwrap(), di);

    // R0ComputationStatementV2 — 996
    let st = fixed_statement();
    let st_b = st.try_encode().unwrap();
    assert_eq!(st_b.len(), 996);
    assert_eq!(hx(&st_b), STATEMENT_HEX);
    assert_eq!(R0ComputationStatementV2::decode_exact(&st_b).unwrap(), st);
}

#[test]
fn workload_raw_encoders_lengths_and_strict_roundtrip() {
    let residual = [1i16, -2, 3, -4, 5, -6, 7, -8];
    let rb = workload::residual_state_bytes(&residual);
    assert_eq!(rb.len(), 16);
    assert_eq!(workload::decode_residual_state(&rb).unwrap(), residual);

    let pairs = vec![
        (
            [1i16, 2, 3, 4, 5, 6, 7, 8],
            [9i16, 10, 11, 12, 13, 14, 15, 16],
        ),
        (
            [-1i16, -2, -3, -4, -5, -6, -7, -8],
            [100i16, 200, 300, 400, 500, 600, 700, 800],
        ),
    ];
    let kvb = workload::kv_state_bytes(&pairs);
    assert_eq!(kvb.len(), 32 * pairs.len());
    assert_eq!(workload::decode_kv_state(&kvb).unwrap(), pairs);

    let tokens = vec![0u32, 7, 15, 12345];
    let tb = workload::token_seq_bytes(&tokens);
    assert_eq!(tb.len(), 4 * tokens.len());
    assert_eq!(workload::decode_token_seq(&tb).unwrap(), tokens);

    // the strict decoders reject malformed raw byte strings (no silent truncation)
    assert!(workload::decode_residual_state(&[0u8; 15]).is_err());
    assert!(workload::decode_kv_state(&[0u8; 33]).is_err());
    assert!(workload::decode_token_seq(&[0u8; 5]).is_err());
}

// ---------- 4. production envelope field-map from the research envelope ----------
#[test]
fn production_envelope_maps_from_research_envelope_head() {
    let j = fixture();
    let e = unhex(&jstr(&j, &["valid", "envelope", "bytes"]));
    // documented research-envelope offsets (see envelope.rs encode order)
    assert_eq!(&e[0..32], &tags::ENVELOPE_TAG[..], "envelope domain tag");
    let a32 = |lo: usize| -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(&e[lo..lo + 32]);
        o
    };
    let candidate = Candidate::from_repr(u16::from_le_bytes([e[34], e[35]])).unwrap();
    let candidate_dep_lock_hash = a32(36);
    let guest_program_id = a32(68);
    let verifier_material_manifest_hash = a32(100);
    let computation_statement_hash = a32(132);
    let b0_pre_spec_hash = a32(164);
    let r0_guest_set_hash = a32(196);
    // research `proof_hash` at offset 267 (after arch_run_provenance[228..260],
    // arch u8[260], sample_kind u8[261], iteration_index u32[262..266],
    // ProofRefKind u8[266]) is the artifact digest.
    let proof_artifact_digest = a32(267);

    let env = ProductionProofEnvelopeV1 {
        candidate,
        candidate_dep_lock_hash,
        guest_program_id,
        verifier_material_manifest_hash,
        computation_statement_hash,
        b0_pre_spec_hash,
        r0_guest_set_hash,
        proof_artifact_digest,
    };
    let enc = env.encode();
    assert_eq!(enc.len(), 235);
    assert_eq!(ProductionProofEnvelopeV1::decode_exact(&enc).unwrap(), env);

    // its four shared hashes equal the research envelope's
    assert_eq!(env.computation_statement_hash, computation_statement_hash);
    assert_eq!(env.b0_pre_spec_hash, b0_pre_spec_hash);
    assert_eq!(env.r0_guest_set_hash, r0_guest_set_hash);
    assert_eq!(env.proof_artifact_digest, proof_artifact_digest);

    // a partial proof sharing those four hashes binds
    let partial = PartialComputeProofV1 {
        computation_statement_hash,
        b0_pre_spec_hash,
        r0_guest_set_hash,
        proof_artifact_digest,
    };
    assert_eq!(partial.encode().len(), 137);
    assert!(shared_binding_ok(&env, &partial));
}

// ---------- 5. strict-negatives + adversarial + binding + membership ----------
fn sample_partial() -> PartialComputeProofV1 {
    PartialComputeProofV1 {
        computation_statement_hash: [0xc5; 32],
        b0_pre_spec_hash: [0x5b; 32],
        r0_guest_set_hash: [0x65; 32],
        proof_artifact_digest: [0xd1; 32],
    }
}
fn sample_env() -> ProductionProofEnvelopeV1 {
    ProductionProofEnvelopeV1 {
        candidate: Candidate::Risc0,
        candidate_dep_lock_hash: [0x0d; 32],
        guest_program_id: [0x09; 32],
        verifier_material_manifest_hash: [0x06; 32],
        computation_statement_hash: [0xc5; 32],
        b0_pre_spec_hash: [0x5b; 32],
        r0_guest_set_hash: [0x65; 32],
        proof_artifact_digest: [0xd1; 32],
    }
}

#[test]
fn partial_proof_strict_negatives() {
    let p = sample_partial();
    // wrong magic
    let mut b = p.encode();
    b[0] ^= 0xFF;
    assert!(matches!(
        PartialComputeProofV1::decode_exact(&b),
        Err(DecodeError::BadTag { .. })
    ));
    // wrong version
    let mut b = p.encode();
    b[7..9].copy_from_slice(&9u16.to_le_bytes());
    assert!(matches!(
        PartialComputeProofV1::decode_exact(&b),
        Err(DecodeError::BadFixedScalar { .. })
    ));
    // truncation
    let b = p.encode();
    assert!(matches!(
        PartialComputeProofV1::decode_exact(&b[..136]),
        Err(DecodeError::Truncated { .. })
    ));
    // trailing byte
    let mut b = p.encode();
    b.push(0);
    assert!(matches!(
        PartialComputeProofV1::decode_exact(&b),
        Err(DecodeError::TrailingBytes { .. })
    ));
}

#[test]
fn production_envelope_strict_negatives() {
    let e = sample_env();
    // wrong magic
    let mut b = e.encode();
    b[0] ^= 0xFF;
    assert!(matches!(
        ProductionProofEnvelopeV1::decode_exact(&b),
        Err(DecodeError::BadTag { .. })
    ));
    // wrong version
    let mut b = e.encode();
    b[7..9].copy_from_slice(&5u16.to_le_bytes());
    assert!(matches!(
        ProductionProofEnvelopeV1::decode_exact(&b),
        Err(DecodeError::BadFixedScalar { .. })
    ));
    // unknown candidate discriminant
    let mut b = e.encode();
    b[9..11].copy_from_slice(&7u16.to_le_bytes());
    assert!(matches!(
        ProductionProofEnvelopeV1::decode_exact(&b),
        Err(DecodeError::BadEnum {
            name: "Candidate",
            ..
        })
    ));
    // truncation
    let b = e.encode();
    assert!(matches!(
        ProductionProofEnvelopeV1::decode_exact(&b[..234]),
        Err(DecodeError::Truncated { .. })
    ));
    // trailing byte
    let mut b = e.encode();
    b.push(0);
    assert!(matches!(
        ProductionProofEnvelopeV1::decode_exact(&b),
        Err(DecodeError::TrailingBytes { .. })
    ));
}

#[test]
fn shared_binding_flips_each_shared_hash() {
    let env = sample_env();
    let partial = PartialComputeProofV1 {
        computation_statement_hash: env.computation_statement_hash,
        b0_pre_spec_hash: env.b0_pre_spec_hash,
        r0_guest_set_hash: env.r0_guest_set_hash,
        proof_artifact_digest: env.proof_artifact_digest,
    };
    assert!(shared_binding_ok(&env, &partial));

    let mut a = partial.clone();
    a.computation_statement_hash[0] ^= 1;
    assert!(!shared_binding_ok(&env, &a));
    let mut b = partial.clone();
    b.b0_pre_spec_hash[0] ^= 1;
    assert!(!shared_binding_ok(&env, &b));
    let mut c = partial.clone();
    c.r0_guest_set_hash[0] ^= 1;
    assert!(!shared_binding_ok(&env, &c));
    let mut d = partial.clone();
    d.proof_artifact_digest[0] ^= 1;
    assert!(!shared_binding_ok(&env, &d));
}

fn matching_entry() -> GuestProgramEntryV1 {
    GuestProgramEntryV1 {
        candidate: Candidate::Sp1,
        b0_pre_spec_hash: [0x5b; 32],
        guest_source_tree_hash: [0x02; 32],
        candidate_dep_lock_hash: [0x0d; 32],
        arches: vec![BuilderArch {
            arch: Arch::X86_64,
            builder_container_digest: [0xaa; 32],
        }],
        guest_image_hash: [0x04; 32],
        program_id: [0x09; 32],
        verifier_material_manifest_hash: [0x06; 32],
        build_command_hash: [0x07; 32],
        reproducible: true,
    }
}
fn env_for(entry: &GuestProgramEntryV1, guest_set_hash: [u8; 32]) -> ProductionProofEnvelopeV1 {
    ProductionProofEnvelopeV1 {
        candidate: entry.candidate,
        candidate_dep_lock_hash: entry.candidate_dep_lock_hash,
        guest_program_id: entry.program_id,
        verifier_material_manifest_hash: entry.verifier_material_manifest_hash,
        computation_statement_hash: [0xc5; 32],
        b0_pre_spec_hash: entry.b0_pre_spec_hash,
        r0_guest_set_hash: guest_set_hash,
        proof_artifact_digest: [0xd1; 32],
    }
}

#[test]
fn allowlist_membership_ok_and_each_field_mismatch() {
    let entry = matching_entry();
    let allowlist = GuestProgramAllowlistV1 {
        entries: vec![entry.clone()],
    };
    let gsh = allowlist.try_guest_set_hash().unwrap();
    let env = env_for(&entry, gsh);

    // happy path
    assert_eq!(
        allowlist_membership(&env, &allowlist),
        Ok(&allowlist.entries[0])
    );

    // (a) guest-set mismatch
    let mut e = env.clone();
    e.r0_guest_set_hash[0] ^= 1;
    assert_eq!(
        allowlist_membership(&e, &allowlist),
        Err(MembershipError::GuestSetMismatch)
    );

    // candidate mismatch -> NoSuchCandidate (Sp1-only allowlist)
    let mut e = env.clone();
    e.candidate = Candidate::Risc0;
    assert_eq!(
        allowlist_membership(&e, &allowlist),
        Err(MembershipError::NoSuchCandidate)
    );

    // candidate_dep_lock_hash
    let mut e = env.clone();
    e.candidate_dep_lock_hash[0] ^= 1;
    assert_eq!(
        allowlist_membership(&e, &allowlist),
        Err(MembershipError::DepLockMismatch)
    );

    // program_id
    let mut e = env.clone();
    e.guest_program_id[0] ^= 1;
    assert_eq!(
        allowlist_membership(&e, &allowlist),
        Err(MembershipError::ProgramIdMismatch)
    );

    // verifier_material_manifest_hash
    let mut e = env.clone();
    e.verifier_material_manifest_hash[0] ^= 1;
    assert_eq!(
        allowlist_membership(&e, &allowlist),
        Err(MembershipError::VerifierMaterialMismatch)
    );

    // b0_pre_spec_hash
    let mut e = env.clone();
    e.b0_pre_spec_hash[0] ^= 1;
    assert_eq!(
        allowlist_membership(&e, &allowlist),
        Err(MembershipError::SpecHashMismatch)
    );

    // reproducible = false (recompute guest-set hash for the mutated entry)
    let mut entry_np = entry.clone();
    entry_np.reproducible = false;
    let allowlist_np = GuestProgramAllowlistV1 {
        entries: vec![entry_np.clone()],
    };
    let gsh_np = allowlist_np.try_guest_set_hash().unwrap();
    let env_np = env_for(&entry_np, gsh_np);
    assert_eq!(
        allowlist_membership(&env_np, &allowlist_np),
        Err(MembershipError::NotReproducible)
    );
}

// ---------- API-surface audit ----------
// Enumerates every new `b0` public type and exercises the classification in the
// `b0` module docs: an invariant-free type encodes infallibly and round-trips; a
// type that can represent invalid state exposes ONLY a fallible canonical route
// (its raw `encode` is private) and that route fails closed on an invalid value.
#[test]
fn api_surface_audit() {
    // --- invariant-free: infallible encode is sound (round-trips) ---
    // ObjectCommitmentV1: invalid state is UNREPRESENTABLE (private fields).
    let oc = ObjectCommitmentV1::commit(ObjectKind::Model, b"x").unwrap();
    assert_eq!(ObjectCommitmentV1::decode_exact(&oc.encode()).unwrap(), oc);
    // DerivedInputV1: no field-driven invariant.
    let di = fixed_derived_input();
    assert_eq!(DerivedInputV1::decode_exact(&di.encode()).unwrap(), di);
    // PartialComputeProofV1 / ProductionProofEnvelopeV1: typed enum + free hashes.
    let p = sample_partial();
    assert_eq!(PartialComputeProofV1::decode_exact(&p.encode()).unwrap(), p);
    let en = sample_env();
    assert_eq!(
        ProductionProofEnvelopeV1::decode_exact(&en.encode()).unwrap(),
        en
    );

    // --- violable: the ONLY canonical route is fallible and fails closed ---
    // OutputManifestV1: descending slot kind.
    let om = OutputManifestV1 {
        slots: vec![
            SlotDescriptorV1 {
                slot_kind: SlotKind::KvCache,
                slot_index: 0,
                commitment: commit_oc(ObjectKind::KvState, b"k"),
            },
            SlotDescriptorV1 {
                slot_kind: SlotKind::ResidualStream,
                slot_index: 0,
                commitment: commit_oc(ObjectKind::ResidualState, b"r"),
            },
        ],
    };
    assert!(om.try_encode().is_err() && om.try_commitment().is_err());

    // InputManifestV1: slot-kind ↔ object-kind mismatch.
    let im = InputManifestV1 {
        slots: vec![InputSlotDescriptorV1 {
            slot_kind: InputSlotKind::PriorResidual,
            slot_index: 0,
            commitment: commit_oc(ObjectKind::KvState, b"k"),
        }],
    };
    assert!(im.try_encode().is_err());

    // R0ComputationStatementV2: valid-but-wrong-kind embedded commitment.
    let mut st = fixed_statement();
    st.model_commitment = commit_oc(ObjectKind::TokenSeq, b"x");
    assert!(st.try_encode().is_err() && st.try_identity().is_err());

    // VerifierMaterialManifestV1: empty label.
    let vm = VerifierMaterialManifestV1 {
        candidate: Candidate::Sp1,
        entries: vec![VerifierMaterialEntry {
            label: String::new(),
            role: VerifierMaterialRole::Groth16Vk,
            byte_len: 1,
            hash: [0; 32],
        }],
    };
    assert!(vm.try_encode().is_err() && vm.try_identity().is_err());

    // GuestProgramAllowlistV1 / GuestProgramEntryV1: empty arch list.
    let al = GuestProgramAllowlistV1 {
        entries: vec![GuestProgramEntryV1 {
            arches: vec![],
            ..matching_entry()
        }],
    };
    assert!(al.try_encode().is_err() && al.try_guest_set_hash().is_err());
}

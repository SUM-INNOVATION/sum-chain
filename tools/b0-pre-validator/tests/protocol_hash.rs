//! Canonical protocol-hash preimage: golden vectors, finalization gating,
//! mutation sensitivity, committed-identity locks, and strict validation of
//! every committed JSON fixture. The final `b0_pre_spec_hash` is intentionally
//! NOT written while implementation-produced fields are absent.

use b0_pre_validator::protocol::{self, B0PreProtocolV1};
use b0_pre_validator::{
    canonical_protocol_json, protocol_hash, protocol_hash_preimage, workload, ProtocolHashError,
};

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/protocol/hash-golden.json"
));
const EXP_TABLE_HASH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/exp/exp_table_q16.json.hash"
));
const EXP_CERT_HASH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/b0-pre/exp/exp_table_certificate.json.hash"
));

fn hx(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
fn golden_vectors_reproduced_from_test_artifact() {
    let g: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
    let p = protocol::test_only_finalizable_artifact();
    assert!(p.is_finalizable());
    assert!(p.semantic_violations().is_empty());

    let canon = canonical_protocol_json(&p).unwrap();
    let preimage = protocol_hash_preimage(&p).unwrap();
    let hash = protocol_hash(&p).unwrap();

    assert_eq!(
        canon.len() as u64,
        g["canonical_json_len"].as_u64().unwrap()
    );
    assert_eq!(
        hx(blake3::hash(&canon).as_bytes()),
        g["canonical_json_blake3"].as_str().unwrap()
    );
    assert_eq!(preimage.len() as u64, g["preimage_len"].as_u64().unwrap());
    assert_eq!(hx(&hash), g["preimage_blake3"].as_str().unwrap());
}

#[test]
fn frozen_artifact_hash_is_blocked() {
    let p = B0PreProtocolV1::frozen();
    assert_eq!(
        protocol_hash(&p),
        Err(ProtocolHashError::NotFinalizable(p.pending_inputs.absent()))
    );
    assert!(matches!(
        protocol_hash_preimage(&p),
        Err(ProtocolHashError::NotFinalizable(_))
    ));
}

#[test]
fn removing_any_placeholder_reblocks_finalization() {
    // start finalizable, drop each of the three Stage-1 categories -> blocked
    for i in 0..3 {
        let mut p = protocol::test_only_finalizable_artifact();
        match i {
            0 => p.pending_inputs.candidate_container_digests = None,
            1 => p.pending_inputs.cargo_lock_hashes = None,
            _ => p.pending_inputs.verifier_material_manifests = None,
        }
        assert!(!p.is_finalizable());
        assert!(matches!(
            protocol_hash_preimage(&p),
            Err(ProtocolHashError::SemanticViolations(_))
                | Err(ProtocolHashError::NotFinalizable(_))
        ));
    }
}

#[test]
fn placeholder_values_never_leak_into_a_blocked_preimage() {
    // the frozen artifact cannot produce a preimage at all, so its (absent)
    // Stage-1 bytes can never appear in a finalized preimage.
    let frozen = B0PreProtocolV1::frozen();
    assert!(protocol_hash_preimage(&frozen).is_err());

    // a finalized preimage carries the resolved Stage-1 digest bytes ...
    let p = protocol::test_only_finalizable_artifact();
    let pre = protocol_hash_preimage(&p).unwrap();
    assert!(String::from_utf8(pre.clone())
        .unwrap()
        .contains(&"21".repeat(32)));

    // ... but the pending_inputs object has ONLY the three Stage-1 categories as
    // data fields — no guest-closure field can carry a value into the preimage.
    // (The lifecycle section documents guest closure in prose; that is expected
    // and is not a data field.)
    let json = &pre[b0_pre_validator::tags::SPEC_PREFIX.len()..];
    let v: serde_json::Value = serde_json::from_slice(json).unwrap();
    let keys: Vec<&str> = v["pending_inputs"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "candidate_container_digests",
            "cargo_lock_hashes",
            "verifier_material_manifests"
        ]
    );
}

#[test]
fn field_number_and_array_order_mutations_change_the_preimage() {
    let base = protocol_hash_preimage(&protocol::test_only_finalizable_artifact()).unwrap();

    // string mutation
    let mut a = protocol::test_only_finalizable_artifact();
    a.transformer.rmsnorm_rule.push('!');
    assert_ne!(protocol_hash_preimage(&a).unwrap(), base);

    // number mutation
    let mut b = protocol::test_only_finalizable_artifact();
    b.exp_table.max_terms += 1;
    assert_ne!(protocol_hash_preimage(&b).unwrap(), base);

    // array-order mutation (canonical JSON preserves array order)
    let mut c = protocol::test_only_finalizable_artifact();
    c.versions.swap(0, 1);
    assert_ne!(protocol_hash_preimage(&c).unwrap(), base);
}

#[test]
fn committed_identities_match_crate_and_files() {
    // exp table + certificate hashes: constant == committed .hash file
    assert_eq!(protocol::EXP_TABLE_HASH_HEX, EXP_TABLE_HASH.trim());
    assert_eq!(protocol::EXP_CERT_HASH_HEX, EXP_CERT_HASH.trim());

    // official statement template hashes + model id: constant == fresh recompute
    let tlg = workload::build_tlg(b"official-workload-v1", 7);
    let sel = workload::build_select(b"official-workload-v1", 6);
    let tlg_hash = hx(&b0_pre_validator::schema::statement::template_hash(
        &workload::tlg_template(&tlg),
    ));
    let sel_hash = hx(&b0_pre_validator::schema::statement::template_hash(
        &workload::select_template(&sel),
    ));
    assert_eq!(protocol::OFFICIAL_TLG_TEMPLATE_HASH_HEX, tlg_hash);
    assert_eq!(protocol::OFFICIAL_SELECT_TEMPLATE_HASH_HEX, sel_hash);

    let seed = workload::seed_of(b"official-workload-v1");
    assert_eq!(
        protocol::OFFICIAL_MODEL_ID_HEX,
        hx(&workload::derive_model(&seed).model_id())
    );

    // and the frozen artifact embeds exactly those identities
    let p = B0PreProtocolV1::frozen();
    assert_eq!(p.exp_table.table_hash_hex, EXP_TABLE_HASH.trim());
    assert_eq!(p.exp_table.certificate_hash_hex, EXP_CERT_HASH.trim());
    assert_eq!(
        p.official_statements.model_id_hex,
        protocol::OFFICIAL_MODEL_ID_HEX
    );
}

#[test]
fn every_committed_json_fixture_strict_parses() {
    // The JSON *Schema* is deliberately excluded: schemars output is standard
    // JSON Schema (e.g. `"minimum": 0.0`) and is not B0-PRE strict-canonical. It
    // is byte-locked by tests/protocol_schema.rs and drives jsonschema
    // validation instead. Every B0-PRE *data* document must strict-parse.
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/b0-pre");
    let fixtures = [
        "protocol/b0-pre-protocol-v1.json",
        "protocol/hash-golden.json",
        "exp/exp_table_q16.json",
        "exp/exp_table_certificate.json",
        "fixtures/encoding-golden/vectors.json",
        "fixtures/closure-golden/vectors.json",
        "fixtures/evidence-harness/spec.json",
        "fixtures/workload/official.json",
    ];
    for f in fixtures {
        let bytes = std::fs::read(format!("{base}/{f}")).unwrap_or_else(|_| panic!("read {f}"));
        b0_pre_validator::json::parse_strict(&bytes)
            .unwrap_or_else(|e| panic!("{f} failed strict parse: {e:?}"));
    }
}

//! Independent cross-lock of the normative protocol artifact.
//!
//! The reference validator owns the typed model / schema / hash machinery
//! (schemars + jsonschema live only there, by design). This crate has no schema
//! tooling, but it *does* independently re-derive the deterministic identities
//! the artifact embeds — model id, both official statement template hashes, and
//! the exp-table hash — and asserts the committed artifact matches, byte for
//! byte on the hex. It also confirms the artifact is not finalized (no
//! fabricated implementation-produced fields have leaked in).

use b0_pre_independent::workload;

const ARTIFACT: &str = include_str!("../../../docs/b0-pre/protocol/b0-pre-protocol-v1.json");
const EXP_TABLE_HASH: &str = include_str!("../../../docs/b0-pre/exp/exp_table_q16.json.hash");

fn hx(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn stmt<'a>(art: &'a serde_json::Value, unit_kind: &str) -> &'a serde_json::Value {
    art["official_statements"]["statements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["unit_kind"] == unit_kind)
        .unwrap_or_else(|| panic!("missing official statement {unit_kind}"))
}

#[test]
fn artifact_identities_match_independent_derivation() {
    let art: serde_json::Value = serde_json::from_str(ARTIFACT).unwrap();

    let tlg = workload::build_tlg(b"official-workload-v1", 7);
    let sel = workload::build_select(b"official-workload-v1", 6);

    // model id
    assert_eq!(
        art["official_statements"]["model_id_hex"].as_str().unwrap(),
        hx(&tlg.model_id),
        "artifact model_id disagrees with independent derivation"
    );

    // both official statement template hashes
    assert_eq!(
        stmt(&art, "TransformerLayerGroup")["template_hash_hex"]
            .as_str()
            .unwrap(),
        hx(&workload::tlg_template_hash(&tlg)),
    );
    assert_eq!(
        stmt(&art, "SelectToken")["template_hash_hex"]
            .as_str()
            .unwrap(),
        hx(&workload::select_template_hash(&sel)),
    );

    // exp-table hash: artifact value == committed .hash file
    assert_eq!(
        art["exp_table"]["table_hash_hex"].as_str().unwrap(),
        EXP_TABLE_HASH.trim(),
    );
}

#[test]
fn artifact_is_not_finalized_and_carries_no_fabricated_fields() {
    let art: serde_json::Value = serde_json::from_str(ARTIFACT).unwrap();
    assert_eq!(art["finalization"]["state"], "not_finalizable");
    // every implementation-produced field is absent (pending_inputs is empty)
    assert_eq!(
        art["pending_inputs"].as_object().unwrap().len(),
        0,
        "no implementation-produced field may be present until it truly exists"
    );
    assert_eq!(
        art["finalization"]["blocked_on"].as_array().unwrap().len(),
        3,
        "exactly three Stage-1 categories block finalization"
    );
    // guest closure must not appear as a Stage-1 pending input anywhere
    let dump = serde_json::to_string(&art["pending_inputs"]).unwrap();
    assert!(!dump.contains("r0_guest_set_hash"));
    assert!(!dump.contains("guest_program_identities"));
}

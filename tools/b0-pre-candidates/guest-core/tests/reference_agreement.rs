//! Golden cross-check against the frozen official workload fixture.
//!
//! `docs/b0-pre/fixtures/workload/official.json` is the committed, frozen
//! witness+statement data for the two official statements, produced by the
//! reference transformer in `b0-pre-validator`. This test packs that exact data
//! into the guest-input envelope, runs the OFFICIAL guest core, and asserts:
//!  * the guest ACCEPTS both statements (the baked transformer/exp/fixed logic
//!    reproduces the committed output commitments — any drift makes a recomputed
//!    output commitment mismatch and the guest reject), and
//!  * the committed journal equals `computation_statement_hash` over the frozen
//!    statement template bytes.
//!
//! Runs locally with NO prover toolchain — it is the evidence that the guest
//! semantics match the frozen reference byte-for-byte.

use b0_pre_guest_core::{run, GuestInput};
use sumchain_wire::b0::hashing;

const OFFICIAL: &str = include_str!("../../../../docs/b0-pre/fixtures/workload/official.json");

fn hexbytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn field(v: &serde_json::Value, case: &str, key: &str) -> Vec<u8> {
    hexbytes(
        v[case][key]
            .as_str()
            .unwrap_or_else(|| panic!("{case}.{key} missing")),
    )
}

#[test]
fn official_tlg_and_select_are_accepted_and_journal_matches() {
    let v: serde_json::Value = serde_json::from_str(OFFICIAL).unwrap();
    assert_eq!(v["fixture_name"].as_str().unwrap(), "official-workload-v1");

    // --- TransformerLayerGroup ---
    let tlg_stmt = field(&v, "tlg", "statement_template");
    let tlg = GuestInput {
        statement: tlg_stmt.clone(),
        model: Some(field(&v, "tlg", "model")),
        residual: Some(field(&v, "tlg", "prior_residual")),
        prior_kv: Some(field(&v, "tlg", "prior_kv")),
        token_prefix: Some(field(&v, "tlg", "token_prefix")),
        input_manifest: Some(field(&v, "tlg", "input_manifest")),
    };
    let tlg_journal = run(&tlg.encode()).expect("official TLG must be accepted");
    assert_eq!(
        tlg_journal,
        hashing::plain(&tlg_stmt),
        "TLG journal must be computation_statement_hash of the template"
    );

    // --- SelectToken ---
    let sel_stmt = field(&v, "select", "statement_template");
    let sel = GuestInput {
        statement: sel_stmt.clone(),
        model: Some(field(&v, "select", "model")),
        residual: Some(field(&v, "select", "final_residual")),
        prior_kv: None,
        token_prefix: Some(field(&v, "select", "token_prefix")),
        input_manifest: Some(field(&v, "select", "input_manifest")),
    };
    let sel_journal = run(&sel.encode()).expect("official SelectToken must be accepted");
    assert_eq!(sel_journal, hashing::plain(&sel_stmt));

    // the two official statements are distinct
    assert_ne!(tlg_journal, sel_journal);

    // SelectToken's committed public selected_token is 2, eos 0 (fixture) — the
    // guest recomputed and bound them; a wrong recomputation could not have been
    // accepted above. Cross-check the fixture's own recorded selection is 2.
    assert_eq!(field(&v, "select", "selected_token"), 2u32.to_le_bytes());
    assert_eq!(field(&v, "select", "eos_flag"), vec![0u8]);
}

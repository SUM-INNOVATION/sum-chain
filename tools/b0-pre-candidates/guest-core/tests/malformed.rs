//! Deterministic-rejection matrix over the official fixture.
//!
//! Starting from the accepted official TLG and SelectToken inputs, every
//! adversarial mutation — a tampered witness byte, a tampered public statement
//! field, a wrong statement kind, a missing/extra witness, a corrupted envelope,
//! trailing bytes — must make the guest return `Err` (a zkVM abort). No prover
//! toolchain is needed.

use b0_pre_guest_core::{run, GuestError, GuestInput};

const OFFICIAL: &str = include_str!("../../../../docs/b0-pre/fixtures/workload/official.json");

fn hexbytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn f(v: &serde_json::Value, case: &str, key: &str) -> Vec<u8> {
    hexbytes(v[case][key].as_str().unwrap())
}

fn tlg_input(v: &serde_json::Value) -> GuestInput {
    GuestInput {
        statement: f(v, "tlg", "statement_template"),
        model: Some(f(v, "tlg", "model")),
        residual: Some(f(v, "tlg", "prior_residual")),
        prior_kv: Some(f(v, "tlg", "prior_kv")),
        token_prefix: Some(f(v, "tlg", "token_prefix")),
        input_manifest: Some(f(v, "tlg", "input_manifest")),
    }
}
fn select_input(v: &serde_json::Value) -> GuestInput {
    GuestInput {
        statement: f(v, "select", "statement_template"),
        model: Some(f(v, "select", "model")),
        residual: Some(f(v, "select", "final_residual")),
        prior_kv: None,
        token_prefix: Some(f(v, "select", "token_prefix")),
        input_manifest: Some(f(v, "select", "input_manifest")),
    }
}

fn rejects(g: &GuestInput) -> bool {
    run(&g.encode()).is_err()
}

/// A named input mutation.
type Mut = Box<dyn Fn(&mut GuestInput)>;

#[test]
fn tlg_mutations_all_reject() {
    let v: serde_json::Value = serde_json::from_str(OFFICIAL).unwrap();
    let base = tlg_input(&v);
    assert!(run(&base.encode()).is_ok());

    let cases: Vec<(&str, Mut)> = vec![
        // private witness bytes
        (
            "model_tensor_byte",
            Box::new(|g| g.model.as_mut().unwrap()[500] ^= 1),
        ),
        (
            "model_magic",
            Box::new(|g| g.model.as_mut().unwrap()[0] ^= 1),
        ),
        (
            "residual_byte",
            Box::new(|g| g.residual.as_mut().unwrap()[0] ^= 1),
        ),
        (
            "prior_kv_byte",
            Box::new(|g| g.prior_kv.as_mut().unwrap()[0] ^= 1),
        ),
        (
            "token_byte",
            Box::new(|g| g.token_prefix.as_mut().unwrap()[0] ^= 1),
        ),
        (
            "input_manifest_byte",
            Box::new(|g| g.input_manifest.as_mut().unwrap()[40] ^= 1),
        ),
        (
            "trailing_witness_byte",
            Box::new(|g| g.model.as_mut().unwrap().push(0)),
        ),
        // missing / extra witnesses
        ("drop_model", Box::new(|g| g.model = None)),
        ("drop_prior_kv", Box::new(|g| g.prior_kv = None)),
        ("drop_token_prefix", Box::new(|g| g.token_prefix = None)),
        ("drop_input_manifest", Box::new(|g| g.input_manifest = None)),
    ];
    for (name, mutate) in &cases {
        let mut g = base.clone();
        mutate(&mut g);
        assert!(rejects(&g), "TLG case `{name}` must reject");
    }

    // A statement-byte mutation (flip a byte in the public 996-byte statement)
    // must reject: it either breaks strict decode or unbinds a commitment.
    for off in [2usize, 100, 400, 900] {
        let mut g = base.clone();
        g.statement[off] ^= 1;
        assert!(rejects(&g), "TLG statement byte {off} flip must reject");
    }
}

#[test]
fn select_mutations_all_reject() {
    let v: serde_json::Value = serde_json::from_str(OFFICIAL).unwrap();
    let base = select_input(&v);
    assert!(run(&base.encode()).is_ok());

    let cases: Vec<(&str, Mut)> = vec![
        (
            "model_byte",
            Box::new(|g| g.model.as_mut().unwrap()[500] ^= 1),
        ),
        (
            "final_residual_byte",
            Box::new(|g| g.residual.as_mut().unwrap()[0] ^= 1),
        ),
        (
            "token_byte",
            Box::new(|g| g.token_prefix.as_mut().unwrap()[0] ^= 1),
        ),
        (
            "input_manifest_byte",
            Box::new(|g| g.input_manifest.as_mut().unwrap()[40] ^= 1),
        ),
        (
            "unexpected_prior_kv",
            Box::new(|g| g.prior_kv = Some(vec![0u8; 32])),
        ),
        ("drop_model", Box::new(|g| g.model = None)),
        ("drop_residual", Box::new(|g| g.residual = None)),
    ];
    for (name, mutate) in &cases {
        let mut g = base.clone();
        mutate(&mut g);
        assert!(rejects(&g), "SelectToken case `{name}` must reject");
    }
    for off in [2usize, 100, 400, 900] {
        let mut g = base.clone();
        g.statement[off] ^= 1;
        assert!(
            rejects(&g),
            "SelectToken statement byte {off} flip must reject"
        );
    }
}

#[test]
fn wrong_statement_kind_and_swapped_witnesses_reject() {
    let v: serde_json::Value = serde_json::from_str(OFFICIAL).unwrap();
    // Feed the TLG statement with SelectToken witnesses (no prior_kv) and vice
    // versa: the unit_kind dispatch + witness-set checks must reject both.
    let tlg_stmt = f(&v, "tlg", "statement_template");
    let sel_stmt = f(&v, "select", "statement_template");

    let mut cross = select_input(&v);
    cross.statement = tlg_stmt; // TLG statement, SelectToken witnesses
    assert!(
        rejects(&cross),
        "TLG statement with select witnesses must reject"
    );

    let mut cross2 = tlg_input(&v);
    cross2.statement = sel_stmt; // SelectToken statement, TLG witnesses
    assert!(
        rejects(&cross2),
        "select statement with TLG witnesses must reject"
    );
}

#[test]
fn corrupt_envelope_rejects() {
    let v: serde_json::Value = serde_json::from_str(OFFICIAL).unwrap();
    let bytes = tlg_input(&v).encode();

    // bad tag
    let mut b = bytes.clone();
    b[0] ^= 0xFF;
    assert!(matches!(run(&b), Err(GuestError::Decode(_))));
    // trailing byte
    let mut b = bytes.clone();
    b.push(0);
    assert!(matches!(run(&b), Err(GuestError::Decode(_))));
    // truncated
    assert!(run(&bytes[..bytes.len() - 3]).is_err());
    // empty
    assert!(run(&[]).is_err());
}

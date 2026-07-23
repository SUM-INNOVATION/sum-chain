//! Emit the two canonical guest-input blobs for the official B0-PRE workload.
//!
//! Reads the frozen `docs/b0-pre/fixtures/workload/official.json`, packs each of
//! the two official statements (TransformerLayerGroup, SelectToken) plus its
//! witnesses into the guest-input envelope, and writes:
//!   <out_dir>/tlg.guestin.bin
//!   <out_dir>/select.guestin.bin
//!
//! These are DETERMINISTIC INPUT bytes only — never a proof. The venue passes one
//! as `PROVER_GUEST_INPUT` to `prove_fixture.sh` so the official guest has the
//! statement+witnesses to prove. The blobs carry no proof, receipt, program id,
//! or measured value.
//!
//! Usage: cargo run --example emit_official_guest_input -- <official.json> <out_dir>

use std::fs;
use std::path::Path;

use b0_pre_guest_core::{run, GuestInput};

fn hexbytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
fn field(v: &serde_json::Value, case: &str, key: &str) -> Vec<u8> {
    hexbytes(
        v[case][key]
            .as_str()
            .unwrap_or_else(|| panic!("{case}.{key} missing")),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let official = args
        .get(1)
        .expect("usage: emit_official_guest_input <official.json> <out_dir>");
    let out_dir = args
        .get(2)
        .expect("usage: emit_official_guest_input <official.json> <out_dir>");
    let raw = fs::read_to_string(official).expect("read official.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse official.json");

    let tlg = GuestInput {
        statement: field(&v, "tlg", "statement_template"),
        model: Some(field(&v, "tlg", "model")),
        residual: Some(field(&v, "tlg", "prior_residual")),
        prior_kv: Some(field(&v, "tlg", "prior_kv")),
        token_prefix: Some(field(&v, "tlg", "token_prefix")),
        input_manifest: Some(field(&v, "tlg", "input_manifest")),
    };
    let select = GuestInput {
        statement: field(&v, "select", "statement_template"),
        model: Some(field(&v, "select", "model")),
        residual: Some(field(&v, "select", "final_residual")),
        prior_kv: None,
        token_prefix: Some(field(&v, "select", "token_prefix")),
        input_manifest: Some(field(&v, "select", "input_manifest")),
    };

    // Self-check: the guest core must ACCEPT each emitted blob before we write it,
    // so a malformed input can never be handed to the prover.
    let tlg_bytes = tlg.encode();
    let sel_bytes = select.encode();
    let tlg_j = run(&tlg_bytes).expect("official TLG input must be accepted by the guest core");
    let sel_j =
        run(&sel_bytes).expect("official SelectToken input must be accepted by the guest core");

    fs::create_dir_all(out_dir).expect("mkdir out_dir");
    fs::write(Path::new(out_dir).join("tlg.guestin.bin"), &tlg_bytes).expect("write tlg");
    fs::write(Path::new(out_dir).join("select.guestin.bin"), &sel_bytes).expect("write select");

    let hx = |b: &[u8]| {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    };
    eprintln!(
        "tlg.guestin.bin    bytes={} journal={}",
        tlg_bytes.len(),
        hx(&tlg_j)
    );
    eprintln!(
        "select.guestin.bin bytes={} journal={}",
        sel_bytes.len(),
        hx(&sel_j)
    );
    eprintln!("NOTE: input bytes only — no proof/receipt/program-id/measurement.");
}

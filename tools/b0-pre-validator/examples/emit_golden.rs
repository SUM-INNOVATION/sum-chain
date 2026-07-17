//! Emit the encoding golden vectors used to cross-check `b0-pre-independent`.
//!
//! Run with `cargo run --example emit_golden`; it writes
//! `docs/b0-pre/fixtures/encoding-golden/vectors.json`. Both tool crates
//! recompute these vectors from the same documented inputs (`golden` module here,
//! a separate copy in the independent crate) and assert byte-for-byte agreement.

use std::fs;
use std::path::Path;

use b0_pre_validator::enums::ObjectKind;
use b0_pre_validator::golden;
use b0_pre_validator::merkle;
use b0_pre_validator::schema::object::ObjectCommitmentV1;
use b0_pre_validator::schema::statement::{self, R0ComputationStatementV2};

fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn main() {
    let oc = ObjectCommitmentV1::commit(ObjectKind::Model, golden::GOLDEN_MODEL);
    let empty_kv = ObjectCommitmentV1::empty(ObjectKind::PriorKv);
    let root = merkle::merkle_root(&golden::multichunk_buf());
    let di = golden::derived_input();
    let om = golden::output_manifest();
    let im = golden::input_manifest();
    let template = statement::template_bytes(golden::statement());
    let template_hash = statement::template_hash(&template);
    let final_bytes = statement::materialize_final(&template, &golden::SPEC_HASH).unwrap();
    let stmt_hash = R0ComputationStatementV2::computation_statement_hash(&final_bytes);

    let json = format!(
        concat!(
            "{{\n",
            "  \"object_commitment_model_golden\": {{\"bytes\":\"{}\",\"identity\":\"{}\"}},\n",
            "  \"empty_prior_kv\": {{\"bytes\":\"{}\",\"identity\":\"{}\"}},\n",
            "  \"merkle_multichunk_root\": \"{}\",\n",
            "  \"derived_input\": {{\"bytes\":\"{}\",\"identity\":\"{}\"}},\n",
            "  \"output_manifest_2slot\": {{\"bytes\":\"{}\",\"commitment_identity\":\"{}\"}},\n",
            "  \"input_manifest_3slot\": {{\"bytes\":\"{}\",\"commitment_identity\":\"{}\"}},\n",
            "  \"statement_template\": {{\"bytes\":\"{}\",\"template_hash\":\"{}\"}},\n",
            "  \"statement_final\": {{\"spec_hash\":\"{}\",\"bytes\":\"{}\",\"computation_statement_hash\":\"{}\"}}\n",
            "}}\n"
        ),
        hx(&oc.encode()),
        hx(&oc.identity()),
        hx(&empty_kv.encode()),
        hx(&empty_kv.identity()),
        hx(&root),
        hx(&di.encode()),
        hx(&di.identity()),
        hx(&om.encode()),
        hx(&om.commitment().identity()),
        hx(&im.encode()),
        hx(&im.commitment().identity()),
        hx(&template),
        hx(&template_hash),
        hx(&golden::SPEC_HASH),
        hx(&final_bytes),
        hx(&stmt_hash),
    );

    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/fixtures/encoding-golden");
    fs::create_dir_all(&dir).expect("create fixture dir");
    fs::write(dir.join("vectors.json"), json).expect("write vectors.json");
    eprintln!("wrote {}", dir.join("vectors.json").display());
}

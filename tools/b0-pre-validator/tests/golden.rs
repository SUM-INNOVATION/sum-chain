//! Regression lock: the reference pipeline must still reproduce the committed
//! golden vectors. Guards against any accidental change to the encoders that
//! would alter canonical bytes or hashes.

use b0_pre_validator::enums::ObjectKind;
use b0_pre_validator::golden;
use b0_pre_validator::merkle;
use b0_pre_validator::schema::object::ObjectCommitmentV1;
use b0_pre_validator::schema::statement::{self, R0ComputationStatementV2};

const VECTORS: &str = include_str!("../../../docs/b0-pre/fixtures/encoding-golden/vectors.json");

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

#[test]
fn reference_pipeline_matches_committed_golden() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();

    let oc = ObjectCommitmentV1::commit(ObjectKind::Model, golden::GOLDEN_MODEL);
    assert_eq!(
        hx(&oc.encode()),
        get(&v, &["object_commitment_model_golden", "bytes"])
    );
    assert_eq!(
        hx(&oc.identity()),
        get(&v, &["object_commitment_model_golden", "identity"])
    );

    let ek = ObjectCommitmentV1::empty(ObjectKind::PriorKv);
    assert_eq!(hx(&ek.encode()), get(&v, &["empty_prior_kv", "bytes"]));
    assert_eq!(hx(&ek.identity()), get(&v, &["empty_prior_kv", "identity"]));

    assert_eq!(
        hx(&merkle::merkle_root(&golden::multichunk_buf())),
        get(&v, &["merkle_multichunk_root"])
    );

    let di = golden::derived_input();
    assert_eq!(hx(&di.encode()), get(&v, &["derived_input", "bytes"]));
    assert_eq!(hx(&di.identity()), get(&v, &["derived_input", "identity"]));

    let om = golden::output_manifest();
    assert_eq!(
        hx(&om.encode()),
        get(&v, &["output_manifest_2slot", "bytes"])
    );
    assert_eq!(
        hx(&om.commitment().identity()),
        get(&v, &["output_manifest_2slot", "commitment_identity"])
    );

    let im = golden::input_manifest();
    assert_eq!(
        hx(&im.encode()),
        get(&v, &["input_manifest_3slot", "bytes"])
    );
    assert_eq!(
        hx(&im.commitment().identity()),
        get(&v, &["input_manifest_3slot", "commitment_identity"])
    );

    let template = statement::template_bytes(golden::statement());
    assert_eq!(hx(&template), get(&v, &["statement_template", "bytes"]));
    assert_eq!(
        hx(&statement::template_hash(&template)),
        get(&v, &["statement_template", "template_hash"])
    );

    let final_bytes = statement::materialize_final(&template, &golden::SPEC_HASH).unwrap();
    assert_eq!(hx(&final_bytes), get(&v, &["statement_final", "bytes"]));
    assert_eq!(
        hx(&R0ComputationStatementV2::computation_statement_hash(
            &final_bytes
        )),
        get(&v, &["statement_final", "computation_statement_hash"])
    );
}

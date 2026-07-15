//! The reference reproduces every canonical byte of the two official statements
//! and the witness contract accepts them.

use b0_pre_validator::workload;

const OFFICIAL: &str = include_str!("../../../docs/b0-pre/fixtures/workload/official.json");

fn hx(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[test]
fn reference_official_statements_byte_locked() {
    let j: serde_json::Value = serde_json::from_str(OFFICIAL).unwrap();
    assert!(j["label"].as_str().unwrap().contains("canonical official"));

    let tlg = workload::build_tlg(b"official-workload-v1", 7);
    let sel = workload::build_select(b"official-workload-v1", 6);

    for (k, v) in workload::tlg_artifacts(&tlg) {
        assert_eq!(
            hx(&v),
            j["tlg"][k].as_str().unwrap(),
            "tlg.{k} byte mismatch"
        );
    }
    for (k, v) in workload::select_artifacts(&sel) {
        assert_eq!(
            hx(&v),
            j["select"][k].as_str().unwrap(),
            "select.{k} byte mismatch"
        );
    }

    assert_eq!(workload::verify_tlg(&tlg), Ok(()));
    assert_eq!(workload::verify_select(&sel), Ok(()));
}

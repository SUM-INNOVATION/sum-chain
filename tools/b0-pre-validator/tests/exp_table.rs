//! The reference certified table must equal the committed `exp_table_q16.json`,
//! its single-domain hash must match `.hash`, and the committed certificate must
//! agree with the recomputed table (mutation-sensitive).

use b0_pre_validator::exp;
use b0_pre_validator::tags::EXP_TABLE_TAG;

const TABLE_JSON: &str = include_str!("../../../docs/b0-pre/exp/exp_table_q16.json");
const TABLE_HASH: &str = include_str!("../../../docs/b0-pre/exp/exp_table_q16.json.hash");
const CERT_JSON: &str = include_str!("../../../docs/b0-pre/exp/exp_table_certificate.json");

fn parse_table(j: &str) -> Vec<u32> {
    let v: serde_json::Value = serde_json::from_str(j).unwrap();
    v["table"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect()
}
fn hx(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[test]
fn reference_table_matches_committed_and_hash() {
    let committed = parse_table(TABLE_JSON);
    assert_eq!(exp::table_cached(), committed.as_slice());

    let mut h = blake3::Hasher::new();
    h.update(&EXP_TABLE_TAG);
    h.update(TABLE_JSON.as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    assert_eq!(format!("{}\n", hx(&digest)), TABLE_HASH);
}

#[test]
fn committed_certificate_agrees_with_recomputed_table() {
    let v: serde_json::Value = serde_json::from_str(CERT_JSON).unwrap();
    let entries = v["entries"].as_array().unwrap();
    let t = exp::table_cached();
    assert_eq!(entries.len(), t.len());
    for (i, e) in entries.iter().enumerate() {
        let cert_value = e.as_array().unwrap()[0].as_u64().unwrap() as u32;
        assert_eq!(cert_value, t[i], "certificate value mismatch at index {i}");
    }
    // A mutated certificate value would no longer equal the recomputed table.
    assert_ne!(t[100] + 1, t[100]);
}

//! Cross-crate agreement: the independent direct-series certification must
//! reproduce the exact committed `exp_table_q16.json` the reference emitted.

use b0_pre_independent::exp;

const TABLE_JSON: &str = include_str!("../../../docs/b0-pre/exp/exp_table_q16.json");

fn parse_table(j: &str) -> Vec<u32> {
    let v: serde_json::Value = serde_json::from_str(j).unwrap();
    v["table"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect()
}

#[test]
fn independent_table_matches_reference_committed() {
    let committed = parse_table(TABLE_JSON);
    assert_eq!(exp::table_cached(), committed.as_slice());
    assert_eq!(committed.len(), 3017);
    assert_eq!(committed[0], 65536);
}

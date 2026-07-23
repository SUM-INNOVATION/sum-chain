//! Bind the baked-in [`EXP_TABLE`] to the committed frozen artifact.
//!
//! The guest cannot run the bignum certifier, so it carries the certified values
//! as a constant. This test proves those constants ARE the committed frozen
//! table by (a) reproducing the committed single-domain hash
//! `BLAKE3(EXP_TABLE_TAG ‖ json_bytes)` == `exp_table_q16.json.hash`, and
//! (b) checking every value in the committed JSON equals the baked constant. Any
//! drift from `docs/b0-pre/exp/exp_table_q16.json` fails here — locally, without
//! any prover toolchain.

use b0_pre_guest_core::exp::{EXP_TABLE, SCALE_BITS, TABLE_LEN, Z_MAX};
use sumchain_wire::b0::hashing;
use sumchain_wire::b0::tags::EXP_TABLE_TAG;

const TABLE_JSON: &str = include_str!("../../../../docs/b0-pre/exp/exp_table_q16.json");
const TABLE_HASH: &str = include_str!("../../../../docs/b0-pre/exp/exp_table_q16.json.hash");

fn hx(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[test]
fn baked_table_reproduces_committed_hash_and_values() {
    // (a) single-domain hash of the committed JSON bytes == committed .hash
    let digest = hashing::prefixed(&EXP_TABLE_TAG, TABLE_JSON.as_bytes());
    assert_eq!(format!("{}\n", hx(&digest)), TABLE_HASH);

    // (b) every committed value equals the baked constant
    let v: serde_json::Value = serde_json::from_str(TABLE_JSON).unwrap();
    assert_eq!(v["z_max"].as_u64().unwrap() as u32, Z_MAX);
    assert_eq!(v["scale_bits"].as_u64().unwrap() as u32, SCALE_BITS);
    let committed: Vec<u32> = v["table"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect();
    assert_eq!(committed.len(), TABLE_LEN);
    assert_eq!(committed.as_slice(), &EXP_TABLE[..]);
}

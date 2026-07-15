//! Emit the committed exp-table artifacts: `exp_table_q16.json` (+ `.hash`) and
//! `exp_table_certificate.json` (+ `.hash`), using the single-domain hash rule
//! `BLAKE3(tag ‖ file_bytes)`. Both tool crates recompute the table and assert
//! it matches these committed bytes.

use std::fs;
use std::path::Path;

use b0_pre_validator::exp;
use b0_pre_validator::tags::{EXP_CERT_TAG, EXP_TABLE_TAG};

fn hx(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn write_with_hash(dir: &Path, name: &str, tag: &[u8; 32], body: &str) {
    let path = dir.join(name);
    fs::write(&path, body).expect("write body");
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(body.as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    fs::write(
        dir.join(format!("{name}.hash")),
        format!("{}\n", hx(&digest)),
    )
    .expect("write hash");
    eprintln!("{name}: {}", hx(&digest));
}

fn main() {
    let (table, certs) = exp::generate();

    // exp_table_q16.json : {"z_max":3016,"scale_bits":16,"table":[...]}
    let values = table
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let table_json = format!(
        "{{\"z_max\":{},\"scale_bits\":{},\"table\":[{}]}}\n",
        exp::Z_MAX,
        exp::SCALE_BITS,
        values
    );

    // exp_table_certificate.json : per-entry [value, range_reduction, terms]
    let entries = certs
        .iter()
        .map(|c| format!("[{},{},{}]", c.value, c.range_reduction, c.terms))
        .collect::<Vec<_>>()
        .join(",");
    let cert_json = format!(
        "{{\"z_max\":{},\"scale_bits\":{},\"max_terms\":{},\"entries\":[{}]}}\n",
        exp::Z_MAX,
        exp::SCALE_BITS,
        exp::MAX_TERMS,
        entries
    );

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/exp");
    fs::create_dir_all(&dir).expect("mkdir");
    write_with_hash(&dir, "exp_table_q16.json", &EXP_TABLE_TAG, &table_json);
    write_with_hash(
        &dir,
        "exp_table_certificate.json",
        &EXP_CERT_TAG,
        &cert_json,
    );

    let max_terms = certs.iter().map(|c| c.terms).max().unwrap();
    let max_r = certs.iter().map(|c| c.range_reduction).max().unwrap();
    eprintln!(
        "entries={} table[0]={} table[3016]={} max_terms={} max_range_reduction={}",
        table.len(),
        table[0],
        table[3016],
        max_terms,
        max_r
    );
}

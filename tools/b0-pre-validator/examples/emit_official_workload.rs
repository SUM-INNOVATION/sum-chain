//! Emit the two canonical official B0-PRE workload statements — the
//! TransformerLayerGroup at position 7 and the SelectToken at position 6 (plan
//! §20) — with every canonical artifact as hex, so BOTH tool crates lock them
//! byte-for-byte. NON_SELECTION generation / TEST_ONLY weights.

use std::fs;
use std::path::Path;

use b0_pre_validator::workload;

fn hx(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn artifacts_json(arts: &[(&'static str, Vec<u8>)]) -> String {
    arts.iter()
        .map(|(k, v)| format!("    \"{}\": \"{}\"", k, hx(v)))
        .collect::<Vec<_>>()
        .join(",\n")
}

fn main() {
    let name: &[u8] = b"official-workload-v1";
    let tlg = workload::build_tlg(name, 7);
    let sel = workload::build_select(name, 6);
    assert_eq!(workload::verify_tlg(&tlg), Ok(()));
    assert_eq!(workload::verify_select(&sel), Ok(()));

    let tlg_arts = workload::tlg_artifacts(&tlg);
    let sel_arts = workload::select_artifacts(&sel);

    let json = format!(
        "{{\n  \"label\": \"the two canonical official B0-PRE workload statements (NON_SELECTION generation, TEST_ONLY weights)\",\n  \"fixture_name\": \"official-workload-v1\",\n  \"tlg_position\": 7,\n  \"select_position\": 6,\n  \"tlg\": {{\n{}\n  }},\n  \"select\": {{\n{}\n  }}\n}}\n",
        artifacts_json(&tlg_arts),
        artifacts_json(&sel_arts),
    );

    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/fixtures/workload");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("official.json"), json).expect("write");

    eprintln!("tlg statement bytes: {}", tlg.statement.encode().len());
    eprintln!("select statement bytes: {}", sel.statement.encode().len());
    for (k, v) in &tlg_arts {
        if *k == "statement_template" || *k == "model_id" {
            eprintln!("tlg.{k} = {}", hx(v));
        }
    }
    for (k, v) in &sel_arts {
        if *k == "statement_template" {
            eprintln!("select.{k} = {}", hx(v));
        }
    }
}

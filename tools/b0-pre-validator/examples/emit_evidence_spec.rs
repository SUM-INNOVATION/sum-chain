//! Emit the compact evidence-harness spec fixture (NON_SELECTION / TEST_ONLY):
//! a seed plus the reference's computed result-set hash and aggregates. Both
//! crates generate the full evidence grid from the seed and assert they match.

use std::fs;
use std::path::Path;

use b0_pre_validator::harness;

fn hx(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn main() {
    let ev = harness::generate();
    let r = harness::verify_evidence(&ev).expect("valid");
    eprintln!("result_set_hash={}", hx(&r.result_set_hash));
    eprintln!(
        "p99={} max_pb={} vmat={} vrss={} qual={}",
        r.worst_arch_p99_verify_ns,
        r.max_proof_bytes,
        r.verifier_material_bytes,
        r.worst_arch_verifier_rss_bytes,
        r.qualification
    );

    let json = format!(
        concat!(
            "{{\n",
            "  \"label\": \"{}\",\n",
            "  \"seed\": \"{}\",\n",
            "  \"expected\": {{\n",
            "    \"result_set_hash\": \"{}\",\n",
            "    \"worst_arch_p99_verify_ns\": {},\n",
            "    \"max_proof_bytes\": {},\n",
            "    \"verifier_material_bytes\": {},\n",
            "    \"worst_arch_verifier_rss_bytes\": {},\n",
            "    \"qualification\": {},\n",
            "    \"measured_proofs\": 40,\n",
            "    \"verify_samples\": 4000\n",
            "  }}\n",
            "}}\n"
        ),
        harness::NON_SELECTION_LABEL,
        hx(&harness::SEED),
        hx(&r.result_set_hash),
        r.worst_arch_p99_verify_ns,
        r.max_proof_bytes,
        r.verifier_material_bytes,
        r.worst_arch_verifier_rss_bytes,
        r.qualification,
    );
    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/fixtures/evidence-harness");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("spec.json"), json).expect("write");
    eprintln!("wrote {}", dir.join("spec.json").display());
}

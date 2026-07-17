//! Print the independent crate's computed evidence-harness values, for direct
//! comparison against the reference (they must be byte-identical).

use b0_pre_independent::harness;

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
}

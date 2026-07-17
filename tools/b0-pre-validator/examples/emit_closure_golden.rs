//! Emit the R0-closure golden: valid canonical bytes for each selection-relevant
//! format plus adversarial mutations that must be rejected. Both tool crates load
//! this shared fixture and must agree on identities/aggregates and reject every
//! mutation. Writes `docs/b0-pre/fixtures/closure-golden/vectors.json`.

use std::fs;
use std::path::Path;

use b0_pre_validator::golden;

fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn main() {
    // --- valid ---
    let vm = golden::official_verifier_material();
    let env = golden::official_envelope();
    let prov = golden::official_provenance_proving();
    let allow = golden::official_allowlist_empty();
    let sample = golden::official_sample();
    let rss = golden::official_rss();
    let rs = golden::official_result_set();

    // --- adversarial mutations ---
    let mut rs_wrong_count = golden::official_result_set();
    rs_wrong_count.completeness.measured_proof_count = 39;

    let mut rs_missing = golden::official_result_set();
    rs_missing.measured_proofs.pop();

    let mut rs_qual = golden::official_result_set();
    rs_qual.failure_codes = vec![3];

    let mut rs_unsorted_prov = golden::official_result_set();
    rs_unsorted_prov.arch_provenance.swap(0, 2);

    // verifier material: unsorted and duplicate entries
    use b0_pre_validator::enums::{Candidate, VerifierMaterialRole};
    use b0_pre_validator::schema::verifier_material::{
        VerifierMaterialEntry, VerifierMaterialManifestV1,
    };
    let vm_unsorted = VerifierMaterialManifestV1 {
        candidate: Candidate::Risc0,
        entries: vec![
            VerifierMaterialEntry {
                label: "b".into(),
                role: VerifierMaterialRole::ControlRoot,
                byte_len: 1,
                hash: [1; 32],
            },
            VerifierMaterialEntry {
                label: "a".into(),
                role: VerifierMaterialRole::Groth16Vk,
                byte_len: 1,
                hash: [2; 32],
            },
        ],
    };
    let vm_dup = VerifierMaterialManifestV1 {
        candidate: Candidate::Sp1,
        entries: vec![
            VerifierMaterialEntry {
                label: "x".into(),
                role: VerifierMaterialRole::Groth16Vk,
                byte_len: 1,
                hash: [1; 32],
            },
            VerifierMaterialEntry {
                label: "x".into(),
                role: VerifierMaterialRole::Groth16Vk,
                byte_len: 1,
                hash: [1; 32],
            },
        ],
    };

    let mut prov_weak = golden::official_provenance_proving();
    prov_weak.physical_core_count = 8;

    let mut prov_gov = golden::official_provenance_proving();
    prov_gov.governor = "powersave".into();

    let mut env_bad_gs = golden::official_envelope();
    env_bad_gs.r0_guest_set_hash[0] ^= 0x01;

    let json = format!(
        concat!(
            "{{\n",
            "  \"valid\": {{\n",
            "    \"verifier_material\": {{\"bytes\":\"{}\",\"identity\":\"{}\",\"verifier_material_bytes\":{}}},\n",
            "    \"envelope\": {{\"bytes\":\"{}\"}},\n",
            "    \"provenance\": {{\"bytes\":\"{}\",\"hash\":\"{}\"}},\n",
            "    \"allowlist_empty\": {{\"bytes\":\"{}\",\"guest_set_hash\":\"{}\"}},\n",
            "    \"sample\": {{\"bytes\":\"{}\"}},\n",
            "    \"rss\": {{\"bytes\":\"{}\"}},\n",
            "    \"result_set\": {{\"bytes\":\"{}\",\"hash\":\"{}\"}}\n",
            "  }},\n",
            "  \"reject\": {{\n",
            "    \"rs_wrong_count\": \"{}\",\n",
            "    \"rs_missing_proof\": \"{}\",\n",
            "    \"rs_qualified_with_failures\": \"{}\",\n",
            "    \"rs_unsorted_provenance\": \"{}\",\n",
            "    \"vm_unsorted\": \"{}\",\n",
            "    \"vm_dup\": \"{}\",\n",
            "    \"prov_underpowered\": \"{}\",\n",
            "    \"prov_bad_governor\": \"{}\",\n",
            "    \"env_wrong_guest_set\": \"{}\"\n",
            "  }}\n",
            "}}\n"
        ),
        hx(&vm.encode()),
        hx(&vm.identity()),
        vm.verifier_material_bytes().unwrap(),
        hx(&env.encode()),
        hx(&prov.encode()),
        hx(&prov.provenance_hash()),
        hx(&allow.encode()),
        hx(&allow.guest_set_hash()),
        hx(&sample.encode()),
        hx(&rss.encode()),
        hx(&rs.encode()),
        hx(&rs.result_set_hash()),
        hx(&rs_wrong_count.encode()),
        hx(&rs_missing.encode()),
        hx(&rs_qual.encode()),
        hx(&rs_unsorted_prov.encode()),
        hx(&vm_unsorted.encode()),
        hx(&vm_dup.encode()),
        hx(&prov_weak.encode()),
        hx(&prov_gov.encode()),
        hx(&env_bad_gs.encode()),
    );

    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/b0-pre/fixtures/closure-golden");
    fs::create_dir_all(&dir).expect("create fixture dir");
    fs::write(dir.join("vectors.json"), json).expect("write vectors.json");
    eprintln!("wrote {}", dir.join("vectors.json").display());
}

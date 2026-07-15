//! Independent closure cross-check: parse the shared closure fixture with the
//! independent decoders, recompute every selection-relevant identity/hash and
//! aggregate, and reject every adversarial mutation.

use b0_pre_independent::closure::{
    decode_allowlist, decode_env, decode_prov, decode_result_set, decode_rss, decode_sample,
    decode_vm, envelope_binds, provenance_eligible, provenance_hash, validate_completeness,
    Allowlist, ResultSet, Vm,
};

const V: &str = include_str!("../../../docs/b0-pre/fixtures/closure-golden/vectors.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hx(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[test]
fn independent_closure_agrees_on_valid_and_rejects_mutations() {
    let j: serde_json::Value = serde_json::from_str(V).unwrap();
    let val = &j["valid"];
    let s = |p: &[&str]| -> String {
        let mut c = &j;
        for k in p {
            c = &c[*k];
        }
        c.as_str().unwrap().to_string()
    };

    // --- verifier material: identity + verifier_material_bytes ---
    let vm_bytes = unhex(&s(&["valid", "verifier_material", "bytes"]));
    let vm = decode_vm(&vm_bytes).unwrap();
    assert_eq!(
        hx(&Vm::identity(&vm_bytes)),
        s(&["valid", "verifier_material", "identity"])
    );
    assert_eq!(
        vm.verifier_material_bytes().unwrap(),
        val["verifier_material"]["verifier_material_bytes"]
            .as_u64()
            .unwrap()
    );

    // --- result set: hash + completeness ---
    let rs_bytes = unhex(&s(&["valid", "result_set", "bytes"]));
    let rs = decode_result_set(&rs_bytes).unwrap();
    assert_eq!(
        hx(&ResultSet::result_set_hash(&rs_bytes)),
        s(&["valid", "result_set", "hash"])
    );
    assert_eq!(validate_completeness(&rs), Ok(()));

    // --- envelope binds the result set ---
    let env = decode_env(&unhex(&s(&["valid", "envelope", "bytes"]))).unwrap();
    assert_eq!(envelope_binds(&env, &rs), Ok(()));

    // --- provenance: hash + eligibility ---
    let pv_bytes = unhex(&s(&["valid", "provenance", "bytes"]));
    let pv = decode_prov(&pv_bytes).unwrap();
    assert_eq!(
        hx(&provenance_hash(&pv_bytes)),
        s(&["valid", "provenance", "hash"])
    );
    assert_eq!(provenance_eligible(&pv), Ok(()));

    // --- allowlist (empty): guest-set hash ---
    let al_bytes = unhex(&s(&["valid", "allowlist_empty", "bytes"]));
    let al = decode_allowlist(&al_bytes).unwrap();
    assert!(al.entries.is_empty());
    assert_eq!(
        hx(&Allowlist::guest_set_hash(&al_bytes)),
        s(&["valid", "allowlist_empty", "guest_set_hash"])
    );

    // --- sample + rss decode cleanly ---
    decode_sample(&unhex(&s(&["valid", "sample", "bytes"]))).unwrap();
    decode_rss(&unhex(&s(&["valid", "rss", "bytes"]))).unwrap();

    // --- adversarial mutations: every one must be rejected ---
    let rej = |k: &str| unhex(&s(&["reject", k]));

    for k in [
        "rs_wrong_count",
        "rs_missing_proof",
        "rs_qualified_with_failures",
        "rs_unsorted_provenance",
    ] {
        let rejected = match decode_result_set(&rej(k)) {
            Err(_) => true,
            Ok(r) => validate_completeness(&r).is_err(),
        };
        assert!(rejected, "{k} must be rejected");
    }
    for k in ["vm_unsorted", "vm_dup"] {
        assert!(
            decode_vm(&rej(k)).is_err(),
            "{k} must be rejected at decode"
        );
    }
    for k in ["prov_underpowered", "prov_bad_governor"] {
        let rejected = match decode_prov(&rej(k)) {
            Err(_) => true,
            Ok(p) => provenance_eligible(&p).is_err(),
        };
        assert!(rejected, "{k} must be rejected");
    }
    {
        let rejected = match decode_env(&rej("env_wrong_guest_set")) {
            Err(_) => true,
            Ok(e) => envelope_binds(&e, &rs).is_err(),
        };
        assert!(rejected, "env_wrong_guest_set must be rejected");
    }
}

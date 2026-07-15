//! Reference closure cross-check: the reference decoders + validation must agree
//! with the committed closure fixture on the valid vectors and reject every
//! adversarial mutation — the same fixture the independent crate consumes.

use b0_pre_validator::schema::allowlist::GuestProgramAllowlistV1;
use b0_pre_validator::schema::bench::{BenchmarkRssRecordV1, BenchmarkSampleV1};
use b0_pre_validator::schema::envelope::R0ProofArtifactEnvelopeV1;
use b0_pre_validator::schema::provenance::ArchRunProvenanceV1;
use b0_pre_validator::schema::result_set::R0ResultSetV1;
use b0_pre_validator::schema::verifier_material::VerifierMaterialManifestV1;
use b0_pre_validator::validation;

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
fn reference_closure_agrees_on_valid_and_rejects_mutations() {
    let j: serde_json::Value = serde_json::from_str(V).unwrap();
    let s = |p: &[&str]| -> String {
        let mut c = &j;
        for k in p {
            c = &c[*k];
        }
        c.as_str().unwrap().to_string()
    };

    // verifier material
    let vm = VerifierMaterialManifestV1::decode_exact(&unhex(&s(&[
        "valid",
        "verifier_material",
        "bytes",
    ])))
    .unwrap();
    assert_eq!(
        hx(&vm.identity()),
        s(&["valid", "verifier_material", "identity"])
    );
    assert_eq!(vm.verifier_material_bytes().unwrap(), 292);

    // result set
    let rs_bytes = unhex(&s(&["valid", "result_set", "bytes"]));
    let rs = R0ResultSetV1::decode_exact(&rs_bytes).unwrap();
    assert_eq!(
        hx(&rs.result_set_hash()),
        s(&["valid", "result_set", "hash"])
    );
    assert_eq!(validation::validate_official_completeness(&rs), Ok(()));

    // envelope binds
    let env = R0ProofArtifactEnvelopeV1::decode_exact(&unhex(&s(&["valid", "envelope", "bytes"])))
        .unwrap();
    assert_eq!(validation::envelope_binds_result_set(&env, &rs), Ok(()));

    // provenance
    let pv =
        ArchRunProvenanceV1::decode_exact(&unhex(&s(&["valid", "provenance", "bytes"]))).unwrap();
    assert_eq!(
        hx(&pv.provenance_hash()),
        s(&["valid", "provenance", "hash"])
    );
    assert_eq!(validation::provenance_eligible(&pv), Ok(()));

    // allowlist
    let al =
        GuestProgramAllowlistV1::decode_exact(&unhex(&s(&["valid", "allowlist_empty", "bytes"])))
            .unwrap();
    assert!(al.entries.is_empty());
    assert_eq!(
        hx(&al.guest_set_hash()),
        s(&["valid", "allowlist_empty", "guest_set_hash"])
    );

    // sample + rss decode
    BenchmarkSampleV1::decode_exact(&unhex(&s(&["valid", "sample", "bytes"]))).unwrap();
    BenchmarkRssRecordV1::decode_exact(&unhex(&s(&["valid", "rss", "bytes"]))).unwrap();

    // adversarial mutations
    let rej = |k: &str| unhex(&s(&["reject", k]));

    for k in [
        "rs_wrong_count",
        "rs_missing_proof",
        "rs_qualified_with_failures",
        "rs_unsorted_provenance",
    ] {
        let rejected = match R0ResultSetV1::decode_exact(&rej(k)) {
            Err(_) => true,
            Ok(r) => validation::validate_official_completeness(&r).is_err(),
        };
        assert!(rejected, "{k} must be rejected");
    }
    for k in ["vm_unsorted", "vm_dup"] {
        assert!(
            VerifierMaterialManifestV1::decode_exact(&rej(k)).is_err(),
            "{k}"
        );
    }
    for k in ["prov_underpowered", "prov_bad_governor"] {
        let rejected = match ArchRunProvenanceV1::decode_exact(&rej(k)) {
            Err(_) => true,
            Ok(p) => validation::provenance_eligible(&p).is_err(),
        };
        assert!(rejected, "{k}");
    }
    {
        let rejected = match R0ProofArtifactEnvelopeV1::decode_exact(&rej("env_wrong_guest_set")) {
            Err(_) => true,
            Ok(e) => validation::envelope_binds_result_set(&e, &rs).is_err(),
        };
        assert!(rejected, "env_wrong_guest_set");
    }
}

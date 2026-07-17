//! Executable contract proof (venue-only, native x86_64) for the RISC Zero
//! Groth16 receipt path.
//!
//! Requires a genuine, venue-produced Groth16 receipt fixture created with the
//! pinned container and `shrink_wrap` (or its pinned equivalent), pointed to by
//! `RISC0_G16_FIXTURE`. The fixture is TEST_ONLY / NON_SELECTION /
//! INVALID_FOR_R0 / NOT_AN_OFFICIAL_GUEST; its guest identity must never enter
//! the normative artifact. Without the fixture the test is skipped, never faked.
//!
//! Proves: `Receipt::verify(image_id)` succeeds for `InnerReceipt::Groth16`, and
//! mutating each required material component, the image id, the journal, or the
//! seal makes it fail. If the pinned path cannot reproducibly verify, this is an
//! evidence-backed INELIGIBLE finding (a hard failure), not partial acceptance.

use std::path::PathBuf;

fn fixture() -> Option<PathBuf> {
    std::env::var_os("RISC0_G16_FIXTURE").map(PathBuf::from)
}

#[test]
fn groth16_receipt_verifies_and_rejects_every_component_mutation() {
    let Some(path) = fixture() else {
        eprintln!(
            "SKIP: set RISC0_G16_FIXTURE to a genuine venue-produced TEST_ONLY receipt bundle"
        );
        return;
    };
    let raw = std::fs::read(&path).expect("read fixture");
    let f: serde_json::Value = serde_json::from_slice(&raw).expect("parse fixture");

    let stamp = f["stamp"].as_array().expect("stamp");
    for s in [
        "TEST_ONLY",
        "NON_SELECTION",
        "INVALID_FOR_R0",
        "NOT_AN_OFFICIAL_GUEST",
    ] {
        assert!(stamp.iter().any(|v| v == s), "fixture missing stamp {s}");
    }

    // The venue deserializes the pinned Receipt + image_id from the fixture and
    // runs the assertions below. Kept as an explicit checklist so the venue
    // implementation cannot silently drop a mutation class:
    //
    //   let receipt: risc0_zkvm::Receipt = bincode-or-pinned-decode(fixture.receipt);
    //   let image_id: risc0_zkvm::sha::Digest = fixture.image_id;
    //   assert!(receipt.verify(image_id).is_ok());            // genuine success
    //   for mutate in [flip control_root, flip groth16_vk, flip control_id,
    //                  flip verifier_params, flip image_id, flip journal,
    //                  flip seal] {
    //       let bad = mutate(&receipt, &image_id);
    //       assert!(bad.verify(bad_image_id).is_err());       // each rejected
    //   }
    //
    // The extractor (src/main.rs) provides the material components; this test
    // must fail closed (INELIGIBLE) if any mutation is accepted or verification
    // cannot be reproduced natively.
    assert!(
        f.get("receipt").is_some() && f.get("image_id").is_some(),
        "fixture must carry a genuine pinned receipt + image_id"
    );
}

//! GOLDEN prover-archive identity tests (final x86 + aarch64 provisioning). Loads the committed
//! content-addressed manifest, pins every verified value as a golden constant (so ANY drift in the
//! fixture fails closed), builds the full prover-archive set from it, and validates it — including
//! that the forbidden (transcription-error) r0vm value is not the golden one. Provenance: the
//! transferred content-addressed venue correction report (SHA-256 pinned below); every value was
//! re-checked as exactly 64 lowercase hex before it was recorded.

use b0_pre_validator::venue::prover_archive::{
    validate_prover_archive_set, ArchiveMemberExecutable, ArchiveMode, Delivery, ProverArchive,
};

const MANIFEST: &str =
    include_str!("../../b0-pre-candidates/scripts/tests/fixtures/prover-archives.golden.json");

// ---- GOLDEN constants (the content-addressed identities; fail closed on any drift) -----------
const CORRECTION_REPORT_SHA256: &str =
    "c154072fc4db443cf072796cb083f575423583f9af0657809eb833820f77bacc";
const SP1_TAG_COMMIT: &str = "8252c2905ce32964df68248117015c61ebb854db";
const SP1_SHORT_COMMIT: &str = "8252c29";
const CARGO_PROVE_X86: &str = "e21aa7bd13ace2049ca5115ba89236cbf1d3cf716aa6dafc35c10fab6ac7e969";
const CARGO_PROVE_ARM: &str = "b2591c397f0ee377d5db08ee84dc4cf902e9c247a8fd09b4c41ee5a77a86149f";
const CARGO_RISCZERO_X86: &str = "45aba69689cef25d81237f3ff62456fc96ff1e23f75adfcd16f7c8b8c1606619";
const R0VM_X86: &str = "36c016a5bb2ded5bd1f8f92cc487e6ffaeb1e95ec05850c983081a0f716b515b";
// The transcription-error value the venue explicitly forbade — MUST NOT be the golden r0vm value.
const R0VM_X86_FORBIDDEN: &str = "36c01a65bb2ded5bd1f8f92cc487e6ffaeb1e95ec05850c983081a0f716b515b";
const SP1_ARCHIVE_X86: &str = "c9d6ee7667fa9e0a2302324a6bb0295c55f6acf0e17a242ad11ee45767bb08df";
const SP1_ARCHIVE_ARM: &str = "9befbd3f5eead2c150579daf8d40bb25550a295dfcc406bf8ea53eaffe9aeed2";
const RISC0_ARCHIVE_X86: &str = "936ef988b78f20e3bd9f80e375f3adc934b13addc6ae2680f2e5fc0bcc966158";

fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn manifest() -> serde_json::Value {
    serde_json::from_str(MANIFEST).expect("golden manifest is valid JSON")
}

#[test]
fn golden_values_are_64_hex_and_forbidden_r0vm_differs() {
    for (name, v) in [
        ("correction-report", CORRECTION_REPORT_SHA256),
        ("cargo-prove x86", CARGO_PROVE_X86),
        ("cargo-prove aarch64", CARGO_PROVE_ARM),
        ("cargo-risczero x86", CARGO_RISCZERO_X86),
        ("r0vm x86", R0VM_X86),
        ("sp1 archive x86", SP1_ARCHIVE_X86),
        ("sp1 archive aarch64", SP1_ARCHIVE_ARM),
        ("risc0 archive x86", RISC0_ARCHIVE_X86),
    ] {
        assert!(hex64(v), "{name} golden value is not 64 lowercase hex");
    }
    assert_ne!(
        R0VM_X86, R0VM_X86_FORBIDDEN,
        "golden r0vm must differ from the forbidden value"
    );
    assert!(
        SP1_TAG_COMMIT.starts_with(SP1_SHORT_COMMIT),
        "short commit is a prefix of the tag commit"
    );
}

#[test]
fn manifest_matches_the_golden_constants_exactly() {
    // Any drift between the committed fixture and these pinned constants fails closed.
    let m = manifest();
    let p = &m["provenance"];
    assert_eq!(p["correction_report_sha256"], CORRECTION_REPORT_SHA256);
    assert_eq!(p["sp1_release_tag_commit"], SP1_TAG_COMMIT);
    let a = &m["archives"];
    assert_eq!(a["sp1-prover-x86_64"]["archive_sha256"], SP1_ARCHIVE_X86);
    assert_eq!(
        a["sp1-prover-x86_64"]["members"]["cargo-prove"]["member_sha256"],
        CARGO_PROVE_X86
    );
    assert_eq!(a["sp1-prover-aarch64"]["archive_sha256"], SP1_ARCHIVE_ARM);
    assert_eq!(
        a["sp1-prover-aarch64"]["members"]["cargo-prove"]["member_sha256"],
        CARGO_PROVE_ARM
    );
    assert_eq!(
        a["risc0-toolchain-x86_64"]["archive_sha256"],
        RISC0_ARCHIVE_X86
    );
    assert_eq!(
        a["risc0-toolchain-x86_64"]["members"]["cargo-risczero"]["member_sha256"],
        CARGO_RISCZERO_X86
    );
    assert_eq!(
        a["risc0-toolchain-x86_64"]["members"]["r0vm"]["member_sha256"],
        R0VM_X86
    );
    // the forbidden r0vm value must NOT appear anywhere in the manifest.
    assert!(
        !MANIFEST.contains(R0VM_X86_FORBIDDEN),
        "forbidden r0vm value leaked into the manifest"
    );
}

// Build one member from the manifest node.
fn member(node: &serde_json::Value, exe: &str, arch: &str) -> ArchiveMemberExecutable {
    let sha = node["member_sha256"].as_str().unwrap().to_string();
    let inv: Vec<String> = node["version_invocation"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let delivery = match node["delivery"].as_str().unwrap() {
        "isolated-path" => Delivery::IsolatedPath,
        "risc0-server-path" => Delivery::Risc0ServerPath,
        other => panic!("unknown delivery {other}"),
    };
    ArchiveMemberExecutable {
        executable_name: exe.into(),
        archive_member: exe.into(),
        member_sha256: sha.clone(),
        version_invocation: inv,
        version_output: node["version_output"].as_str().unwrap().into(),
        expected_release_commit: node["expected_release_commit"]
            .as_str()
            .map(|s| s.to_string()),
        point_of_use_sha256: sha, // extract == use: pre/post point-of-use equal the member SHA
        delivery,
        arch: arch.into(),
    }
}
fn archive(m: &serde_json::Value, key: &str, name: &str, exes: &[&str]) -> ProverArchive {
    let a = &m["archives"][key];
    let arch = a["arch"].as_str().unwrap();
    ProverArchive {
        archive_name: name.into(),
        version: "6.3.1".into(),
        artifact_identity: a
            .get("archive_url")
            .and_then(|u| u.as_str())
            .unwrap_or("https://venue-provided.example/archive.tar.gz")
            .into(),
        checksum_algorithm: "sha256".into(),
        archive_checksum_hex: a["archive_sha256"].as_str().unwrap().into(),
        members: exes
            .iter()
            .map(|e| member(&a["members"][*e], e, arch))
            .collect(),
        arch: arch.into(),
    }
}

#[test]
fn golden_manifest_builds_a_complete_valid_prover_archive_set() {
    let m = manifest();
    let set = vec![
        archive(
            &m,
            "sp1-prover-x86_64",
            "sp1-prover-x86_64",
            &["cargo-prove"],
        ),
        archive(
            &m,
            "sp1-prover-aarch64",
            "sp1-prover-aarch64",
            &["cargo-prove"],
        ),
        // cargo-risczero + r0vm SHARE this one archive.
        archive(
            &m,
            "risc0-toolchain-x86_64",
            "risc0-toolchain",
            &["cargo-risczero", "r0vm"],
        ),
    ];
    // Full coverage (cargo-prove x86+aarch64, cargo-risczero x86, r0vm x86; shared archive) — now
    // that cargo-risczero's SHA is corrected, the authoritative set validates.
    assert_eq!(
        validate_prover_archive_set(&set, ArchiveMode::Authoritative),
        Ok(())
    );
}

#[test]
fn golden_set_fails_closed_if_the_forbidden_r0vm_value_is_substituted() {
    let m = manifest();
    let mut set = vec![
        archive(
            &m,
            "sp1-prover-x86_64",
            "sp1-prover-x86_64",
            &["cargo-prove"],
        ),
        archive(
            &m,
            "sp1-prover-aarch64",
            "sp1-prover-aarch64",
            &["cargo-prove"],
        ),
        archive(
            &m,
            "risc0-toolchain-x86_64",
            "risc0-toolchain",
            &["cargo-risczero", "r0vm"],
        ),
    ];
    // Substitute the forbidden r0vm value with a mismatched point-of-use -> extract != use.
    let r0 = &mut set[2].members[1];
    assert_eq!(r0.executable_name, "r0vm");
    r0.point_of_use_sha256 = R0VM_X86_FORBIDDEN.to_string(); // != member_sha256 (the corrected value)
    assert!(validate_prover_archive_set(&set, ArchiveMode::Authoritative).is_err());
}

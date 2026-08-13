//! Regression for the committed-lock reselection defect AND the provenance-artifact-verification
//! hardening (owner rulings).
//!
//! Two contracts, exercised over the REAL committed RISC0 + SP1 locks:
//!
//! 1. **Reselection** — the committed `http-body-util 0.1.4` graph verifies; a `0.1.5` unlocked
//!    drift is refused from both directions.
//! 2. **Artifact recomputation** — the three provenance identities
//!    (`locked_command_log_blake3_hex`, `vendor_inputs_blake3_hex`, `materialized_closure_blake3_hex`)
//!    are RECOMPUTED from the supplied canonical artifacts. A well-formed FALSE 64-hex value, a
//!    mutated closure / inventory / command argv / exit status, a command missing `--locked`, an
//!    injected `generate-lockfile`, a reordered / duplicated vendor entry, a missing artifact, and a
//!    cross-candidate artifact swap are all refused. A caller-supplied hash without its bytes cannot
//!    pass.

use b0_pre_validator::venue::lock_artifacts::{self as la, ArtifactError};
use b0_pre_validator::venue::lock_provenance::{
    recompute_lock_hash, recompute_lock_sha256, verify_committed_source_lock, LockArtifacts,
    LockError, LockProvenance, COMMITTED_SOURCE_ORIGIN,
};
use serde_json::json;

const ARCH: &str = "X86_64";

fn committed_lock(candidate: &str) -> Vec<u8> {
    let p = format!(
        "{}/../b0-pre-candidates/candidates/{candidate}/Cargo.lock",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("read committed lock {p}: {e}"))
}

fn hex(label: &str) -> String {
    recompute_lock_sha256(label.as_bytes())
}

fn real_container_digest(label: &str) -> String {
    format!("sha256:{}", recompute_lock_sha256(label.as_bytes()))
}

fn command_log_bytes(schema_cand: &str, digest: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": la::COMMAND_LOG_SCHEMA,
        "candidate": schema_cand, "arch": ARCH, "builder_container_digest": digest,
        "commands": [
            {"op":"vendor","argv":["cargo","vendor","--locked","--versioned-dirs","/tmp/v"],
             "cwd":"/work/c","target":"","exit_status":0},
            {"op":"metadata","argv":["cargo","metadata","--locked","--filter-platform",
             "x86_64-unknown-linux-gnu","--format-version","1"],
             "cwd":"/work/c","target":"x86_64-unknown-linux-gnu","exit_status":0}
        ]
    }))
    .unwrap()
}

fn vendor_inventory_bytes(schema_cand: &str) -> Vec<u8> {
    // Two registry entries in strictly canonical (name, version, source, path) order.
    let src = "registry+https://github.com/rust-lang/crates.io-index";
    serde_json::to_vec(&json!({
        "schema": la::VENDOR_INVENTORY_SCHEMA,
        "candidate": schema_cand, "arch": ARCH,
        "entries": [
            {"name":"http-body-util","version":"0.1.4","source":src,
             "checksum": hex("hbu-cksum"),
             "path":"http-body-util-0.1.4/src/lib.rs","size":10u64,"sha256": hex("hbu-lib")},
            {"name":"http-body-util","version":"0.1.4","source":src,
             "checksum": hex("hbu-cksum"),
             "path":"http-body-util-0.1.4/src/util.rs","size":20u64,"sha256": hex("hbu-util")}
        ]
    }))
    .unwrap()
}

fn closure_bytes(schema_cand: &str, lock_b3: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1u16, "candidate": schema_cand, "arch": ARCH,
        "venue_targets": ["x86_64-unknown-linux-gnu"], "features": [],
        "lock_blake3_hex": lock_b3, "stage2_graph_blake3_hex": lock_b3,
        "roots": [], "nodes": []
    }))
    .unwrap()
}

struct Bundle {
    prov: LockProvenance,
    committed: Vec<u8>,
    cmdlog: Vec<u8>,
    inv: Vec<u8>,
    closure: Vec<u8>,
}
impl Bundle {
    fn artifacts(&self) -> LockArtifacts {
        LockArtifacts {
            command_log: &self.cmdlog,
            vendor_inventory: &self.inv,
            closure: &self.closure,
        }
    }
    fn verify(&self) -> Result<(), LockError> {
        verify_committed_source_lock(&self.prov, &self.committed, &self.artifacts()).map(|_| ())
    }
}

/// A fully-consistent authoritative bundle: provenance whose three artifact identities RECOMPUTE
/// from the accompanying canonical artifacts, over the real committed lock.
fn good_bundle(candidate: &str, schema_cand: &str) -> Bundle {
    let committed = committed_lock(candidate);
    let digest = real_container_digest(&format!("builder-{candidate}-x86_64"));
    let cmdlog = command_log_bytes(schema_cand, &digest);
    let inv = vendor_inventory_bytes(schema_cand);
    let lock_b3 = recompute_lock_hash(&committed);
    let closure = closure_bytes(schema_cand, &lock_b3);
    let sha = recompute_lock_sha256(&committed);
    let prov = LockProvenance {
        candidate: schema_cand.to_string(),
        arch: ARCH.to_string(),
        origin: COMMITTED_SOURCE_ORIGIN.to_string(),
        container_digest: digest,
        source_commit: "a".repeat(40),
        committed_lock_sha256_hex: sha.clone(),
        committed_lock_blake3_hex: lock_b3,
        post_lock_sha256_hex: sha,
        locked_command_log_blake3_hex: la::recompute_command_log_hash(&cmdlog),
        materialized_closure_blake3_hex: la::recompute_materialized_closure_hash(&closure),
        vendor_inputs_blake3_hex: la::recompute_vendor_inventory_hash(&inv),
    };
    Bundle {
        prov,
        committed,
        cmdlog,
        inv,
        closure,
    }
}

fn reselect_http_body_util_0_1_5(bytes: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("Cargo.lock is UTF-8");
    let name_at = text
        .find("name = \"http-body-util\"")
        .expect("committed lock must pin http-body-util");
    let ver_rel = text[name_at..]
        .find("version = \"0.1.4\"")
        .expect("http-body-util must be pinned to 0.1.4 in the committed graph");
    let ver_at = name_at + ver_rel;
    let mut out = text.to_string();
    out.replace_range(
        ver_at..ver_at + "version = \"0.1.4\"".len(),
        "version = \"0.1.5\"",
    );
    assert_ne!(out.as_bytes(), bytes, "reselection must change the bytes");
    out.into_bytes()
}

fn is_artifact_hash_mismatch(e: &LockError, which: &str) -> bool {
    matches!(e, LockError::Artifact(ArtifactError::HashMismatch { which: w, .. }) if *w == which)
}

// ---------------------------------------------------------------------------------------------
// Contract 1: reselection
// ---------------------------------------------------------------------------------------------
fn reselection_case(candidate: &str, schema_cand: &str) {
    let mut b = good_bundle(candidate, schema_cand);
    assert!(
        std::str::from_utf8(&b.committed)
            .unwrap()
            .contains("version = \"0.1.4\""),
        "{candidate} committed lock must pin http-body-util 0.1.4"
    );

    // (1) committed 0.1.4 graph verifies.
    b.verify()
        .unwrap_or_else(|e| panic!("{candidate}: committed 0.1.4 lock must verify: {e}"));

    let reselected = reselect_http_body_util_0_1_5(&b.committed);

    // (2a) on-disk committed lock silently swapped to 0.1.5, provenance over the true 0.1.4 bytes.
    let mut swapped = good_bundle(candidate, schema_cand);
    swapped.committed = reselected.clone();
    assert!(
        matches!(swapped.verify(), Err(LockError::HashMismatch { .. })),
        "{candidate}: a 0.1.5-swapped committed lock must be refused"
    );

    // (2b) a defective venue recorded provenance over the reselected 0.1.5 lock; the committed
    //      authority is still 0.1.4.
    let sha5 = recompute_lock_sha256(&reselected);
    b.prov.committed_lock_sha256_hex = sha5.clone();
    b.prov.committed_lock_blake3_hex = recompute_lock_hash(&reselected);
    b.prov.post_lock_sha256_hex = sha5;
    assert!(
        matches!(b.verify(), Err(LockError::HashMismatch { .. })),
        "{candidate}: provenance over the 0.1.5 reselection must be refused vs the committed 0.1.4"
    );
}

#[test]
fn risc0_reselection_contract() {
    reselection_case("risc0", "Risc0");
}
#[test]
fn sp1_reselection_contract() {
    reselection_case("sp1", "Sp1");
}

// ---------------------------------------------------------------------------------------------
// Contract 2: artifact recomputation + structural/semantic validation
// ---------------------------------------------------------------------------------------------
fn artifact_contract(candidate: &str, schema_cand: &str) {
    // positive: recomputation of all three passes.
    good_bundle(candidate, schema_cand).verify().unwrap();

    // well-formed FALSE 64-hex for each provenance field (no artifact recomputes to it).
    for field in ["cmdlog", "vendor", "closure"] {
        let mut b = good_bundle(candidate, schema_cand);
        let bogus = hex("well-formed-but-false");
        match field {
            "cmdlog" => b.prov.locked_command_log_blake3_hex = bogus,
            "vendor" => b.prov.vendor_inputs_blake3_hex = bogus,
            _ => b.prov.materialized_closure_blake3_hex = bogus,
        }
        let e = b.verify().unwrap_err();
        assert!(
            matches!(e, LockError::Artifact(ArtifactError::HashMismatch { .. })),
            "{candidate}/{field}: a well-formed false hash must be refused, got {e:?}"
        );
    }

    // mutated closure bytes (provenance hash unchanged) -> recompute mismatch.
    {
        let mut b = good_bundle(candidate, schema_cand);
        b.closure = closure_bytes(schema_cand, &recompute_lock_hash(&b.committed))
            .iter()
            .cloned()
            .chain(std::iter::once(b' '))
            .collect();
        assert!(is_artifact_hash_mismatch(
            &b.verify().unwrap_err(),
            "materialized-closure"
        ));
    }

    // mutated vendor-inventory entry (provenance hash unchanged) -> recompute mismatch.
    {
        let mut b = good_bundle(candidate, schema_cand);
        let mut v: serde_json::Value = serde_json::from_slice(&b.inv).unwrap();
        v["entries"][0]["size"] = json!(9999u64);
        b.inv = serde_json::to_vec(&v).unwrap();
        assert!(is_artifact_hash_mismatch(
            &b.verify().unwrap_err(),
            "vendor-inventory"
        ));
    }

    // reordered vendor entries WITH the provenance hash updated to match -> structural refusal.
    {
        let mut b = good_bundle(candidate, schema_cand);
        let mut v: serde_json::Value = serde_json::from_slice(&b.inv).unwrap();
        let arr = v["entries"].as_array_mut().unwrap();
        arr.reverse();
        b.inv = serde_json::to_vec(&v).unwrap();
        b.prov.vendor_inputs_blake3_hex = la::recompute_vendor_inventory_hash(&b.inv);
        assert!(matches!(
            b.verify().unwrap_err(),
            LockError::Artifact(ArtifactError::Vendor { .. })
        ));
    }

    // duplicated vendor entry WITH the hash updated -> structural refusal.
    {
        let mut b = good_bundle(candidate, schema_cand);
        let mut v: serde_json::Value = serde_json::from_slice(&b.inv).unwrap();
        let first = v["entries"][0].clone();
        v["entries"].as_array_mut().unwrap().insert(1, first);
        b.inv = serde_json::to_vec(&v).unwrap();
        b.prov.vendor_inputs_blake3_hex = la::recompute_vendor_inventory_hash(&b.inv);
        assert!(matches!(
            b.verify().unwrap_err(),
            LockError::Artifact(ArtifactError::Vendor { .. })
        ));
    }

    // missing/extra vendor entry (hash NOT updated) -> recompute mismatch.
    {
        let mut b = good_bundle(candidate, schema_cand);
        let mut v: serde_json::Value = serde_json::from_slice(&b.inv).unwrap();
        v["entries"].as_array_mut().unwrap().pop();
        b.inv = serde_json::to_vec(&v).unwrap();
        assert!(is_artifact_hash_mismatch(
            &b.verify().unwrap_err(),
            "vendor-inventory"
        ));
    }

    // command: nonzero exit / missing --locked / injected generate-lockfile — each recorded with a
    // MATCHING hash so the SEMANTIC check is what refuses.
    let digest = real_container_digest(&format!("builder-{candidate}-x86_64"));
    let bad_logs = [
        json!({"schema": la::COMMAND_LOG_SCHEMA,"candidate":schema_cand,"arch":ARCH,
            "builder_container_digest":digest,
            "commands":[{"op":"vendor","argv":["cargo","vendor","--locked"],"cwd":"/w","target":"","exit_status":1},
                        {"op":"metadata","argv":["cargo","metadata","--locked","--filter-platform","t","--format-version","1"],"cwd":"/w","target":"t","exit_status":0}]}),
        json!({"schema": la::COMMAND_LOG_SCHEMA,"candidate":schema_cand,"arch":ARCH,
            "builder_container_digest":digest,
            "commands":[{"op":"vendor","argv":["cargo","vendor","--versioned-dirs","/tmp/v"],"cwd":"/w","target":"","exit_status":0},
                        {"op":"metadata","argv":["cargo","metadata","--locked","--filter-platform","t","--format-version","1"],"cwd":"/w","target":"t","exit_status":0}]}),
        json!({"schema": la::COMMAND_LOG_SCHEMA,"candidate":schema_cand,"arch":ARCH,
            "builder_container_digest":digest,
            "commands":[{"op":"vendor","argv":["cargo","generate-lockfile"],"cwd":"/w","target":"","exit_status":0},
                        {"op":"metadata","argv":["cargo","metadata","--locked","--filter-platform","t","--format-version","1"],"cwd":"/w","target":"t","exit_status":0}]}),
    ];
    for bad in bad_logs {
        let mut b = good_bundle(candidate, schema_cand);
        b.cmdlog = serde_json::to_vec(&bad).unwrap();
        b.prov.locked_command_log_blake3_hex = la::recompute_command_log_hash(&b.cmdlog);
        assert!(
            matches!(
                b.verify().unwrap_err(),
                LockError::Artifact(ArtifactError::Command { .. })
            ),
            "{candidate}: a semantically-invalid command log must be refused"
        );
    }

    // missing artifact (empty bytes) -> recompute mismatch, for each of the three.
    for which in ["cmdlog", "vendor", "closure"] {
        let mut b = good_bundle(candidate, schema_cand);
        match which {
            "cmdlog" => b.cmdlog = Vec::new(),
            "vendor" => b.inv = Vec::new(),
            _ => b.closure = Vec::new(),
        }
        assert!(
            matches!(
                b.verify().unwrap_err(),
                LockError::Artifact(ArtifactError::HashMismatch { .. })
            ),
            "{candidate}: a missing/empty {which} artifact must be refused"
        );
    }

    // cross-candidate artifact swap: a command log bound to the OTHER candidate, recorded with a
    // matching hash, is refused by the candidate binding.
    {
        let other = if schema_cand == "Risc0" {
            "Sp1"
        } else {
            "Risc0"
        };
        let mut b = good_bundle(candidate, schema_cand);
        b.cmdlog = command_log_bytes(other, &b.prov.container_digest);
        b.prov.locked_command_log_blake3_hex = la::recompute_command_log_hash(&b.cmdlog);
        assert!(matches!(
            b.verify().unwrap_err(),
            LockError::Artifact(ArtifactError::Binding { .. })
        ));
    }

    // closure not lock-bound (bound to a different lock) with a matching hash -> refused.
    {
        let mut b = good_bundle(candidate, schema_cand);
        b.closure = closure_bytes(schema_cand, &hex("some-other-lock"));
        b.prov.materialized_closure_blake3_hex =
            la::recompute_materialized_closure_hash(&b.closure);
        assert!(matches!(
            b.verify().unwrap_err(),
            LockError::Artifact(ArtifactError::ClosureLockBinding { .. })
        ));
    }
}

#[test]
fn risc0_artifact_contract() {
    artifact_contract("risc0", "Risc0");
}
#[test]
fn sp1_artifact_contract() {
    artifact_contract("sp1", "Sp1");
}

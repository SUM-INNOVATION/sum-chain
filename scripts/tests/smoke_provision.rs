//! Issue #119 smoke-provisioning integration tests.
//!
//! These assert the provisioning invariants WITHOUT booting a node (fast,
//! deterministic, always run in CI): (a) the runnable genesis's `validators`
//! array holds exactly one entry equal to the generated validator key, and
//! (b) every bootstrap role address is present and funded (> 0) in the runtime
//! genesis. They also lock in chain id 1337, the dormant compute-pool/beacon
//! gates, output containment (everything under the given output dir), teardown,
//! and the second-run-from-a-clean-dir guarantee.
//!
//! The full boot / block-production / chain_id-over-RPC / teardown / repeat loop
//! is exercised by `deploy/smoke-e2e-harness.sh`, which actually runs the node.

use std::collections::HashMap;

use sumchain_genesis::Genesis;
use sumchain_scripts::{
    provision_smoke, DEVNET_CHAIN_ID, ROLE_ALLOC, SMOKE_GENESIS_FILE, SMOKE_ROLE_NAMES,
};

/// Provision once and assert every #119 smoke acceptance invariant on the
/// materialized genesis + key files.
#[test]
fn smoke_provision_produces_valid_single_validator_genesis() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path();

    let artifacts = provision_smoke(out, 1).expect("smoke provisioning must succeed");

    // Every artifact path is contained under the output dir — smoke never
    // writes anywhere else (in particular, never a tracked repo path).
    assert!(artifacts.genesis_path.starts_with(out));
    assert!(artifacts.manifest_path.starts_with(out));
    assert!(artifacts.validator_key_path.starts_with(out));
    for role in &artifacts.roles {
        assert!(role.key_path.starts_with(out));
    }

    // The runnable genesis basename is NOT a tracked genesis name.
    assert_eq!(
        artifacts.genesis_path.file_name().unwrap(),
        SMOKE_GENESIS_FILE
    );
    assert_ne!(SMOKE_GENESIS_FILE, "local_genesis.json");

    // Load through the authoritative loader (this also runs Genesis::validate,
    // which is fail-closed on the compute-pool/beacon gates).
    let genesis =
        Genesis::from_file(&artifacts.genesis_path).expect("runnable genesis must load + validate");

    // (chain id) 1337.
    assert_eq!(genesis.chain_id, DEVNET_CHAIN_ID);
    assert_eq!(genesis.chain_id, 1337);

    // (a) validators holds EXACTLY ONE entry, equal to the generated validator.
    assert_eq!(
        genesis.validators.len(),
        1,
        "smoke genesis must have exactly one validator"
    );
    assert_eq!(genesis.validators[0], artifacts.validator_pubkey_b58);

    // Dormant gates stay None.
    assert!(genesis.params.compute_pool_enabled_from_height.is_none());
    assert!(genesis.params.beacon_enabled_from_height.is_none());

    // (b) every bootstrap role (+ the validator) is present and funded > 0.
    let expected_roles: usize = SMOKE_ROLE_NAMES.len();
    assert_eq!(artifacts.roles.len(), expected_roles);

    let funded = |addr: &str, alloc: &HashMap<String, u128>| -> bool {
        alloc.get(addr).copied().unwrap_or(0) > 0
    };
    assert!(
        funded(&artifacts.validator_address_b58, &genesis.alloc),
        "validator address must be funded in alloc"
    );
    for role in &artifacts.roles {
        assert!(
            funded(&role.address_b58, &genesis.alloc),
            "role {} ({}) must be funded > 0 in alloc",
            role.name,
            role.address_b58
        );
        assert_eq!(genesis.alloc[&role.address_b58], ROLE_ALLOC);
    }

    // The exact #119 role set is present.
    let role_names: Vec<&str> = artifacts.roles.iter().map(|r| r.name.as_str()).collect();
    for expected in SMOKE_ROLE_NAMES {
        assert!(
            role_names.contains(expected),
            "missing required funded role: {expected}"
        );
    }

    // Every private key file + the manifest exist on disk.
    assert!(artifacts.validator_key_path.is_file());
    for role in &artifacts.roles {
        assert!(
            role.key_path.is_file(),
            "missing key file for {}",
            role.name
        );
    }
    assert!(artifacts.manifest_path.is_file());

    // Manifest carries only public identifiers + the dormant gate states.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["chain_id"], 1337);
    assert!(manifest["gates"]["compute_pool_enabled_from_height"].is_null());
    assert!(manifest["gates"]["beacon_enabled_from_height"].is_null());
}

/// Teardown + second-run evidence at the provisioning layer: removing the
/// runtime dir deterministically clears it, and a fresh provisioning into a new
/// clean directory succeeds again with a fresh (distinct) validator key.
#[test]
fn smoke_provision_teardown_and_second_run() {
    let first_validator;
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().to_path_buf();
        let a = provision_smoke(&out, 1).expect("first run");
        first_validator = a.validator_pubkey_b58.clone();
        assert!(a.genesis_path.is_file());
        // `dir` drops here -> the runtime dir is removed deterministically.
        drop(dir);
        assert!(!out.exists(), "runtime dir must be gone after teardown");
    }

    // Second run from a brand-new clean directory succeeds.
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let b = provision_smoke(dir2.path(), 1).expect("second run must succeed");
    assert!(b.genesis_path.is_file());
    // Ephemeral keys -> a different validator each run.
    assert_ne!(b.validator_pubkey_b58, first_validator);
}

/// Smoke mode is single-validator by definition: any other count is rejected
/// (it points at the deferred ecosystem mode), and nothing is emitted.
#[test]
fn smoke_provision_rejects_multi_validator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = provision_smoke(dir.path(), 3).expect_err("multi-validator smoke must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("single-validator"), "unexpected error: {msg}");
    // Nothing was written (no genesis) when the count is rejected up front.
    assert!(!dir.path().join(SMOKE_GENESIS_FILE).exists());
}

/// Private-key files are written owner-only (`0600`) on Unix, regardless of the
/// host umask — a private key must never be world/group-readable.
#[cfg(unix)]
#[test]
fn smoke_private_keys_are_owner_only_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let a = provision_smoke(dir.path(), 1).expect("provision");
    let check = |p: &std::path::Path| {
        let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} must be 0600, got {mode:o}", p.display());
    };
    check(&a.validator_key_path);
    for role in &a.roles {
        check(&role.key_path);
    }
}

/// A non-empty / pre-populated output dir is rejected, and the pre-existing
/// artifact is NOT overwritten (fail rather than clobber).
#[test]
fn smoke_rejects_non_empty_output_and_never_overwrites() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("genesis.json"), b"PRE-EXISTING").unwrap();
    let err = provision_smoke(dir.path(), 1).expect_err("non-empty output dir must be rejected");
    let msg = format!("{err:#}").to_lowercase();
    assert!(msg.contains("empty"), "unexpected error: {msg}");
    // The pre-existing file is byte-untouched.
    assert_eq!(
        std::fs::read_to_string(dir.path().join("genesis.json")).unwrap(),
        "PRE-EXISTING"
    );
}

/// A pre-existing (symlinked) `keys/` is rejected rather than written into.
#[cfg(unix)]
#[test]
fn smoke_rejects_pre_existing_symlinked_keys_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let elsewhere = tempfile::tempdir().expect("target");
    std::os::unix::fs::symlink(elsewhere.path(), dir.path().join("keys")).unwrap();
    let err = provision_smoke(dir.path(), 1).expect_err("symlinked keys/ must be rejected");
    // Rejected before any key is written into the symlink target.
    let _ = format!("{err:#}");
    assert!(
        std::fs::read_dir(elsewhere.path())
            .unwrap()
            .next()
            .is_none(),
        "nothing must be written through the keys/ symlink"
    );
}

/// An output dir that resolves INSIDE the repository is rejected even when empty
/// — smoke output must live in an ephemeral dir outside the tree.
#[test]
fn smoke_rejects_output_dir_inside_repository() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root");
    // Prefer the gitignored target/ so the transient dir never shows in git status.
    let target = repo_root.join("target");
    let parent = if target.is_dir() {
        target
    } else {
        repo_root.to_path_buf()
    };
    let inside = tempfile::tempdir_in(&parent).expect("tempdir inside repo");
    let err = provision_smoke(inside.path(), 1).expect_err("inside-repo output must be rejected");
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains("outside") || msg.contains("repository"),
        "unexpected error: {msg}"
    );
    assert!(!inside.path().join(SMOKE_GENESIS_FILE).exists());
}

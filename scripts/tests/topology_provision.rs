//! Issue #118 synthetic-topology provisioning tests.
//!
//! SYNTHETIC TEST TOPOLOGY: every key here is a throwaway key generated into a
//! temporary directory for the duration of one test. Nothing in this file
//! describes, proposes or changes a production validator set.
//!
//! These assert the provisioning invariants WITHOUT booting a node: the
//! runnable genesis lists exactly the generated validators in order, it is
//! consensus only (compute-pool and beacon gates `None`, their parameter
//! surfaces absent), chain id 1337, every identity is funded, every validator
//! owns round-robin slots, and the mode refuses fewer than five validators and
//! any output location other than an outside directory or the ignored
//! `<repo>/devnet`. Booting the five validators and checking that each one
//! proposes is `deploy/topology-e2e-harness.sh`, run in CI.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use sumchain_genesis::Genesis;
use sumchain_primitives::proposer::round_robin_proposer;
use sumchain_scripts::{
    provision_topology, DEVNET_CHAIN_ID, DEVNET_GITIGNORE_LINE, DEVNET_RUNTIME_DIR, GENESIS_FILE,
    ROLE_ALLOC, SMOKE_ROLE_NAMES, TOPOLOGY_DEFAULT_VALIDATORS, TOPOLOGY_MAX_VALIDATORS,
    TOPOLOGY_MIN_VALIDATORS,
};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
}

fn is_empty_dir(p: &Path) -> bool {
    std::fs::read_dir(p).expect("read dir").next().is_none()
}

// The local upper bound never undercuts the floor.
const _: () = assert!(TOPOLOGY_MAX_VALIDATORS >= TOPOLOGY_MIN_VALIDATORS);

/// The default topology is five validators, the floor #118 and #126 require.
#[test]
fn default_topology_is_the_five_validator_minimum() {
    assert_eq!(TOPOLOGY_DEFAULT_VALIDATORS, 5);
    assert_eq!(TOPOLOGY_MIN_VALIDATORS, 5);
}

/// Provision the default topology and assert every invariant on the
/// materialized genesis, key files and manifest.
#[test]
fn topology_provision_produces_a_consensus_only_five_validator_genesis() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path();
    let a = provision_topology(out, TOPOLOGY_DEFAULT_VALIDATORS).expect("provision");

    // Containment: every artifact is under the output dir, and the output dir
    // holds exactly genesis.json, manifest.json and keys/.
    assert!(a.genesis_path.starts_with(out));
    assert!(a.manifest_path.starts_with(out));
    assert_eq!(a.genesis_path.file_name().unwrap(), GENESIS_FILE);
    let top: BTreeSet<String> = std::fs::read_dir(out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        top,
        ["genesis.json", "keys", "manifest.json"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    );
    let key_files: BTreeSet<String> = std::fs::read_dir(out.join("keys"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    let mut expected_keys: BTreeSet<String> =
        (1..=5).map(|i| format!("validator{i}.json")).collect();
    expected_keys.extend(SMOKE_ROLE_NAMES.iter().map(|r| format!("{r}.json")));
    assert_eq!(key_files, expected_keys);

    // Authoritative loader (runs Genesis::validate).
    let g = Genesis::from_file(&a.genesis_path).expect("runnable genesis must load + validate");
    assert_eq!(g.chain_id, DEVNET_CHAIN_ID);
    assert_eq!(g.chain_id, 1337);

    // Exactly the generated validators, in order, all distinct.
    assert_eq!(g.validators.len(), 5);
    let generated: Vec<String> = a.validators.iter().map(|v| v.pubkey_b58.clone()).collect();
    assert_eq!(g.validators, generated);
    assert_eq!(g.validators.iter().collect::<BTreeSet<_>>().len(), 5);
    for (i, v) in a.validators.iter().enumerate() {
        assert_eq!(v.name, format!("validator{}", i + 1));
        assert!(v.key_path.starts_with(out.join("keys")));
    }

    // Consensus only: both pool/beacon gates and their parameter surfaces absent.
    let p = &g.params;
    assert!(p.compute_pool_enabled_from_height.is_none());
    assert!(p.beacon_enabled_from_height.is_none());
    assert!(p.compute_pool_params.is_none());
    assert!(p.beacon_params.is_none());
    assert!(p.beacon_schedule.is_none());

    // alloc funds exactly the validators + the six roles, each with ROLE_ALLOC.
    let mut want: HashMap<String, u128> = HashMap::new();
    for v in &a.validators {
        want.insert(v.address_b58.clone(), ROLE_ALLOC);
    }
    for r in &a.roles {
        want.insert(r.address_b58.clone(), ROLE_ALLOC);
    }
    assert_eq!(want.len(), 5 + SMOKE_ROLE_NAMES.len());
    assert_eq!(g.alloc, want);

    // The hex form the harness compares block proposers against is the same key.
    let pubkeys = g.validator_pubkeys().expect("validator pubkeys");
    for (v, pk) in a.validators.iter().zip(&pubkeys) {
        let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(v.pubkey_hex, hex, "{}", v.name);
    }

    // Round-robin: validator i owns every height h with h % 5 == i, so each of
    // the five proposes exactly once in every window of five heights.
    for h in 0..50u64 {
        assert_eq!(
            round_robin_proposer(h, &pubkeys).unwrap(),
            pubkeys[(h % 5) as usize]
        );
    }
    for start in 0..20u64 {
        let owners: BTreeSet<[u8; 32]> = (start..start + 5)
            .map(|h| round_robin_proposer(h, &pubkeys).unwrap())
            .collect();
        assert_eq!(owners.len(), 5, "window starting at {start}");
    }

    // Manifest: public identities only, synthetic marker, dormant gates.
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&a.manifest_path).unwrap()).unwrap();
    assert_eq!(m["mode"], "topology");
    assert_eq!(m["synthetic_test_topology"], true);
    assert_eq!(m["chain_id"], 1337);
    assert_eq!(m["validator_count"], 5);
    let mv = m["validators"].as_array().unwrap();
    assert_eq!(mv.len(), 5);
    for (i, (entry, v)) in mv.iter().zip(&a.validators).enumerate() {
        assert_eq!(entry["index"], i);
        assert_eq!(entry["pubkey"], v.pubkey_b58.as_str());
        assert_eq!(entry["pubkey_hex"], v.pubkey_hex.as_str());
        assert_eq!(entry["key_file"], format!("keys/validator{}.json", i + 1));
    }
    assert!(m["gates"]["compute_pool_enabled_from_height"].is_null());
    assert!(m["gates"]["beacon_enabled_from_height"].is_null());
    let text = std::fs::read_to_string(&a.manifest_path).unwrap();
    for v in &a.validators {
        let secret = std::fs::read_to_string(&v.key_path).unwrap();
        assert!(
            !text.contains(secret.trim()),
            "manifest must not carry a private key"
        );
    }
}

/// Private-key files are written owner-only (`0600`) on Unix.
#[cfg(unix)]
#[test]
fn topology_private_keys_are_owner_only_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let a = provision_topology(dir.path(), 5).expect("provision");
    let paths = a
        .validators
        .iter()
        .map(|v| v.key_path.clone())
        .chain(a.roles.iter().map(|r| r.key_path.clone()));
    for p in paths {
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} must be 0600, got {mode:o}", p.display());
    }
}

/// Fewer than five validators is refused (the < 5 adversarial case of #118),
/// and so is a count above the local bound; nothing is written either way.
#[test]
fn topology_refuses_counts_outside_the_bounds_and_writes_nothing() {
    for n in [0, 1, 2, 3, 4, TOPOLOGY_MAX_VALIDATORS + 1] {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = provision_topology(dir.path(), n).expect_err("count must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("topology mode needs"), "n={n}: {msg}");
        assert!(is_empty_dir(dir.path()), "n={n}: nothing may be written");
    }
}

/// A larger synthetic topology works the same way (e.g. a 7-validator set).
#[test]
fn topology_accepts_a_larger_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = provision_topology(dir.path(), 7).expect("provision 7");
    let g = Genesis::from_file(&a.genesis_path).expect("load");
    assert_eq!(g.validators.len(), 7);
    assert_eq!(a.validators.last().unwrap().name, "validator7");
}

/// A non-empty output dir is rejected and the pre-existing file is untouched.
#[test]
fn topology_rejects_non_empty_output_and_never_overwrites() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("genesis.json"), b"PRE-EXISTING").unwrap();
    let err = provision_topology(dir.path(), 5).expect_err("non-empty must be rejected");
    assert!(format!("{err:#}").to_lowercase().contains("empty"));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("genesis.json")).unwrap(),
        "PRE-EXISTING"
    );
}

/// An output dir that does not exist is refused (no implicit creation).
#[test]
fn topology_refuses_a_missing_output_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("absent");
    let err = provision_topology(&missing, 5).expect_err("missing dir must be refused");
    assert!(format!("{err:#}").contains("must exist"));
    assert!(!missing.exists());
}

/// A directory inside the repository other than `<repo>/devnet` is refused,
/// even when empty. The in-repository exception is exactly `devnet/`.
#[test]
fn topology_rejects_in_repository_dirs_other_than_devnet() {
    let root = repo_root();
    // Prefer the gitignored target/ so the transient dir never shows in git status.
    let target = root.join("target");
    let parent = if target.is_dir() {
        target
    } else {
        root.to_path_buf()
    };
    let inside = tempfile::tempdir_in(&parent).expect("tempdir inside repo");
    let err = provision_topology(inside.path(), 5).expect_err("must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("OUTSIDE the repository"),
        "unexpected error: {msg}"
    );
    assert!(is_empty_dir(inside.path()));
}

/// The ignored runtime directory the compose file reads is in `.gitignore`,
/// exactly as the provisioner requires before it writes there.
#[test]
fn gitignore_ignores_the_devnet_runtime_directory() {
    let gi = std::fs::read_to_string(repo_root().join(".gitignore")).expect(".gitignore");
    assert_eq!(DEVNET_GITIGNORE_LINE, format!("/{DEVNET_RUNTIME_DIR}/"));
    assert!(
        gi.lines().any(|l| l.trim() == DEVNET_GITIGNORE_LINE),
        ".gitignore must ignore {DEVNET_GITIGNORE_LINE}"
    );
    assert!(
        !gi.lines()
            .any(|l| l.trim().starts_with('!') && l.contains(DEVNET_RUNTIME_DIR)),
        ".gitignore must not re-include anything under devnet/"
    );
}

//! `sumchain-scripts` — devnet provisioning library.
//!
//! # Issue #119 — bootstrap ephemeral keys + a runnable genesis
//!
//! This crate owns the *smoke-mode* devnet provisioner: it generates ephemeral
//! keypairs and materializes a runnable genesis **into an explicit output
//! directory** on the current dormant [`ChainParams`] (chain id `1337`). It
//! never reads or overwrites any tracked genesis file — the caller (a test or
//! the `deploy/smoke-e2e-harness.sh` harness) points `output_dir` at a `mktemp`
//! directory *outside* the repository, so the git worktree stays clean.
//!
//! Two provisioning modes are exposed to the binary:
//!
//! * **smoke** ([`provision_smoke`]) — *exactly one* validator plus all funded
//!   roles required by #119 scope (three archives, one verifier, one client,
//!   one funder). Implementable now on the dormant schema; the compute-pool and
//!   beacon activation gates stay `None`.
//! * **ecosystem** ([`ECOSYSTEM_DEFERRED_MSG`]) — the five-validator pool. It is
//!   **deferred** and hard-fails: its prerequisites (a ≥5-validator template,
//!   the `n_min` validator-floor field, `ComputePoolParams`, `BeaconParams`) do
//!   not exist yet. A passing smoke run does NOT constitute the ecosystem.
//!
//! The legacy three-validator "local testnet" behaviour lives in the binary
//! (`setup_local_testnet.rs`) and is unchanged; this library is only the new
//! #119 surface.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

/// The selected devnet chain id. `1337` is the devnet configuration value; there
/// is no running ecosystem devnet. Production chain id `1` is never produced
/// here.
pub const DEVNET_CHAIN_ID: u64 = 1337;

/// Per-role genesis allocation, in base units (1 Koppa = 1e9 base units).
/// Every funded role receives this positive balance so the acceptance-criteria
/// "balance > 0" holds for the validator and every bootstrap role.
pub const ROLE_ALLOC: u128 = 1_000_000_000_000_000_000; // 1e18 base units

/// The non-validator funded roles a smoke devnet must bootstrap (issue #119
/// scope): three archives, one verifier, one client, one funder.
pub const SMOKE_ROLE_NAMES: &[&str] = &[
    "archive1", "archive2", "archive3", "verifier", "client", "funder",
];

/// Basename of the runnable genesis written by smoke mode. Deliberately NOT
/// `local_genesis.json` (a tracked file) — smoke mode never writes a tracked
/// genesis name.
pub const SMOKE_GENESIS_FILE: &str = "genesis.json";

/// Explicit, actionable message emitted when `ecosystem` mode is selected while
/// its prerequisites are absent. Naming the blockers keeps the deferral honest
/// (the five-validator pool is tracked separately and is never satisfied by a
/// smoke run).
pub const ECOSYSTEM_DEFERRED_MSG: &str = "\
ecosystem mode is DEFERRED and cannot generate anything yet.

The five-validator pool devnet requires prerequisites that do not exist on the
current schema:
  - #118's full (>= 5-validator) genesis template file (absent)
  - the `n_min` validator-floor field (absent)
  - `ComputePoolParams` — the compute-pool typed parameter surface
    (blocked on B0 #123 + C1 #130; the `compute_pool_enabled_from_height`
    gate is fail-closed until it exists)
  - `BeaconParams` — the threshold-BLS beacon typed parameter surface
    (blocked on BR1 #127; the `beacon_enabled_from_height` gate is
    fail-closed until it exists)

A passing smoke run does NOT constitute the five-validator pool ecosystem.
Ecosystem completion is tracked separately. Use `--mode smoke` for the
single-validator devnet that is implementable today.";

/// A generated, funded role: its name, its base58 address, and the path its
/// private key was written to (inside `output_dir/keys`).
#[derive(Debug, Clone)]
pub struct RoleKey {
    /// Role name, e.g. `archive1`, `verifier`, `client`, `funder`.
    pub name: String,
    /// base58 account address (public identifier).
    pub address_b58: String,
    /// Path to the JSON private-key file (32-byte array), inside `output_dir`.
    pub key_path: PathBuf,
}

/// Everything a smoke provisioning produced. All paths live under `output_dir`.
#[derive(Debug, Clone)]
pub struct SmokeArtifacts {
    /// The output directory every artifact was written under.
    pub output_dir: PathBuf,
    /// The runnable genesis path (`output_dir/genesis.json`).
    pub genesis_path: PathBuf,
    /// base58 validator public key — the sole entry in `genesis.validators`.
    pub validator_pubkey_b58: String,
    /// base58 validator address (also funded in `alloc`).
    pub validator_address_b58: String,
    /// Path to the validator private key (`output_dir/keys/validator.json`).
    pub validator_key_path: PathBuf,
    /// The funded non-validator roles (three archives, verifier, client, funder).
    pub roles: Vec<RoleKey>,
    /// Public manifest path (`output_dir/manifest.json`).
    pub manifest_path: PathBuf,
}

/// Write a keypair's 32-byte private key as the JSON array shape the node reads
/// (`sumchain run --validator-key`, `keygen`, `transfer` all parse `[u8; 32]`).
///
/// Fail-closed: uses **create-new** semantics (never overwrites an existing key
/// file) and sets **owner-only `0600`** permissions on Unix so a private key is
/// never left world/group-readable regardless of the host umask.
fn write_private_key(path: &Path, kp: &KeyPair) -> Result<()> {
    use std::io::Write;
    let json = serde_json::to_string_pretty(kp.private_key().as_bytes())
        .context("serialize private key")?;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| {
        format!(
            "create private key file {} (create-new; refusing to overwrite an existing key)",
            path.display()
        )
    })?;
    f.write_all(json.as_bytes())
        .with_context(|| format!("write private key to {}", path.display()))?;
    f.flush()
        .with_context(|| format!("flush private key {}", path.display()))?;
    // Normalize to exactly 0600 on Unix (defensive against a permissive umask
    // narrowing the create mode differently across platforms).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    Ok(())
}

/// Write a **public** (non-secret) artifact with **create-new** semantics: the
/// open fails closed if the path already exists, so the empty-directory
/// precondition cannot be defeated by a check/write race — no emitted artifact
/// is ever overwritten. Normal (umask) permissions; genesis/manifest are public.
fn write_new_public_file(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "create {} (create-new; refusing to overwrite an existing artifact)",
                path.display()
            )
        })?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    f.flush()
        .with_context(|| format!("flush {}", path.display()))?;
    Ok(())
}

/// Fail-closed validation of a smoke `--output-dir` **before** anything is
/// written. The directory must (1) resolve OUTSIDE this repository, (2) already
/// exist and be EMPTY, and (3) contain no pre-existing/symlinked `keys/`. Any
/// violation is an error — the provisioner never overwrites an existing
/// artifact and never writes inside the repo tree.
fn validate_smoke_output_dir(output_dir: &Path) -> Result<()> {
    // Must already exist as a real directory (caller creates it with `mktemp -d`).
    let meta = fs::symlink_metadata(output_dir).with_context(|| {
        format!(
            "smoke --output-dir {} must exist (create it with `mktemp -d`)",
            output_dir.display()
        )
    })?;
    if !meta.is_dir() {
        bail!(
            "smoke --output-dir {} must be a directory (not a file/symlink)",
            output_dir.display()
        );
    }

    // (1) Must resolve OUTSIDE the repository. Repo root = parent of this crate's
    // compile-time manifest dir (`<repo>/scripts`).
    let resolved = output_dir
        .canonicalize()
        .with_context(|| format!("canonicalize --output-dir {}", output_dir.display()))?;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("locate repository root")?
        .canonicalize()
        .context("canonicalize repository root")?;
    if resolved == repo_root || resolved.starts_with(&repo_root) {
        bail!(
            "smoke --output-dir must resolve OUTSIDE the repository \
             (got {}, repo root {}); use an ephemeral `mktemp -d` directory",
            resolved.display(),
            repo_root.display()
        );
    }

    // (2) Must be empty before provisioning — never overwrite existing artifacts.
    if fs::read_dir(output_dir)
        .with_context(|| format!("read --output-dir {}", output_dir.display()))?
        .next()
        .is_some()
    {
        bail!(
            "smoke --output-dir {} must be EMPTY before provisioning \
             (refusing to overwrite genesis.json / manifest.json / keys)",
            output_dir.display()
        );
    }

    // (3) No pre-existing/symlinked `keys/` (implied by empty, but explicit).
    if output_dir.join("keys").symlink_metadata().is_ok() {
        bail!(
            "smoke output {}/keys already exists (possibly a symlink); refusing to write into it",
            output_dir.display()
        );
    }
    Ok(())
}

/// Provision a **smoke** devnet into `output_dir`.
///
/// Generates exactly one validator plus the #119 funded roles, builds a runnable
/// genesis on the dormant [`ChainParams`] (compute-pool + beacon gates `None`,
/// chain id [`DEVNET_CHAIN_ID`]), funds every role in `alloc` (balance > 0),
/// validates the genesis through the authoritative loader path, and writes:
///
/// * `output_dir/keys/validator.json` + one file per role,
/// * `output_dir/genesis.json` (the runnable genesis; only public identifiers),
/// * `output_dir/manifest.json` (public role → address map + gate states).
///
/// `validator_count` must be `1` — smoke mode is single-validator by definition;
/// multi-validator provisioning is the deferred ecosystem mode.
///
/// This function writes **only** under `output_dir`. It never reads #118's
/// template and never touches a tracked genesis file.
pub fn provision_smoke(output_dir: &Path, validator_count: usize) -> Result<SmokeArtifacts> {
    if validator_count != 1 {
        bail!(
            "smoke mode is single-validator by definition (got --validator-count {validator_count}). \
             A multi-validator pool is the deferred ecosystem mode; use --mode ecosystem to see \
             its blockers, or --validator-count 1."
        );
    }

    // Defensive guard: smoke must never emit a tracked genesis basename.
    debug_assert_eq!(SMOKE_GENESIS_FILE, "genesis.json");

    // Fail-closed: outside-repo, empty, no pre-existing/symlinked keys/ — checked
    // before anything is written, so we never overwrite an existing artifact.
    validate_smoke_output_dir(output_dir)?;

    let keys_dir = output_dir.join("keys");
    fs::create_dir(&keys_dir).with_context(|| {
        format!(
            "create keys dir {} (must not already exist)",
            keys_dir.display()
        )
    })?;

    // ── one validator ──────────────────────────────────────────────────────
    let validator = KeyPair::generate();
    let validator_pubkey_b58 = validator.public_key().to_base58();
    let validator_address_b58 = validator.address().to_base58();
    let validator_key_path = keys_dir.join("validator.json");
    write_private_key(&validator_key_path, &validator)?;

    // ── all funded roles ───────────────────────────────────────────────────
    // alloc funds the validator address AND every role, so every one has
    // balance > 0 straight from genesis (no live node needed to fund).
    let mut alloc: HashMap<String, u128> = HashMap::new();
    alloc.insert(validator_address_b58.clone(), ROLE_ALLOC);

    let mut roles = Vec::with_capacity(SMOKE_ROLE_NAMES.len());
    for &name in SMOKE_ROLE_NAMES {
        let kp = KeyPair::generate();
        let address_b58 = kp.address().to_base58();
        let key_path = keys_dir.join(format!("{name}.json"));
        write_private_key(&key_path, &kp)?;
        alloc.insert(address_b58.clone(), ROLE_ALLOC);
        roles.push(RoleKey {
            name: name.to_string(),
            address_b58,
            key_path,
        });
    }

    // ── runnable genesis on the dormant ChainParams ─────────────────────────
    // `with_v2_enabled()` activates SNIP V2 from genesis (so the funded archive
    // roles have a live storage subprotocol) while leaving every other gate at
    // its production-safe default — crucially compute_pool + beacon = None.
    let params = ChainParams::with_v2_enabled();
    debug_assert!(params.compute_pool_enabled_from_height.is_none());
    debug_assert!(params.beacon_enabled_from_height.is_none());

    let genesis_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let genesis = Genesis::new(
        DEVNET_CHAIN_ID,
        genesis_time,
        vec![validator_pubkey_b58.clone()],
        alloc,
        params,
    );
    // Fail-closed loader check: rejects any opened compute-pool/beacon gate and
    // validates every validator key + alloc address.
    genesis
        .validate()
        .context("generated smoke genesis failed validation")?;

    let genesis_path = output_dir.join(SMOKE_GENESIS_FILE);
    let genesis_json = genesis.to_json().context("serialize runnable genesis")?;
    write_new_public_file(&genesis_path, &genesis_json)
        .with_context(|| format!("write runnable genesis to {}", genesis_path.display()))?;

    // ── public manifest (no private material) ───────────────────────────────
    let manifest_path = output_dir.join("manifest.json");
    let manifest = serde_json::json!({
        "mode": "smoke",
        "chain_id": DEVNET_CHAIN_ID,
        "genesis_file": SMOKE_GENESIS_FILE,
        "validator": {
            "pubkey": validator_pubkey_b58,
            "address": validator_address_b58,
            "key_file": "keys/validator.json",
        },
        "roles": roles
            .iter()
            .map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "address": r.address_b58,
                    "key_file": format!("keys/{}.json", r.name),
                })
            })
            .collect::<Vec<_>>(),
        "gates": {
            "compute_pool_enabled_from_height": serde_json::Value::Null,
            "beacon_enabled_from_height": serde_json::Value::Null,
        },
    });
    let manifest_json = serde_json::to_string_pretty(&manifest).context("serialize manifest")?;
    write_new_public_file(&manifest_path, &manifest_json)
        .with_context(|| format!("write manifest to {}", manifest_path.display()))?;

    Ok(SmokeArtifacts {
        output_dir: output_dir.to_path_buf(),
        genesis_path,
        validator_pubkey_b58,
        validator_address_b58,
        validator_key_path,
        roles,
        manifest_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public-artifact writer is create-new: a second write to an existing
    /// path fails closed and leaves the existing bytes untouched (defeats the
    /// check/write race on genesis.json / manifest.json).
    #[test]
    fn write_new_public_file_refuses_existing_and_preserves_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("artifact.json");
        write_new_public_file(&p, "FIRST").expect("first write must succeed");
        assert_eq!(fs::read_to_string(&p).unwrap(), "FIRST");
        let err = write_new_public_file(&p, "SECOND")
            .expect_err("create-new must refuse an existing artifact");
        let _ = format!("{err:#}");
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            "FIRST",
            "existing artifact bytes must be unchanged"
        );
    }
}

//! `sumchain-scripts` — devnet provisioning library.
//!
//! # Issue #119 — bootstrap ephemeral keys + a runnable genesis
//!
//! This crate owns the devnet provisioner: it generates ephemeral keypairs and
//! materializes a runnable genesis **into an explicit output directory** on the
//! current dormant [`ChainParams`] (chain id `1337`). It never reads or
//! overwrites any tracked genesis file, and every artifact it writes lives under
//! the output directory, so the git worktree stays clean.
//!
//! Three provisioning modes are exposed to the binary:
//!
//! * **smoke** ([`provision_smoke`]) — *exactly one* validator plus all funded
//!   roles required by #119 scope (three archives, one verifier, one client,
//!   one funder). The output directory must resolve outside the repository
//!   (the caller, a test or `deploy/smoke-e2e-harness.sh`, uses `mktemp -d`).
//!   The compute-pool and beacon activation gates stay `None`.
//! * **topology** ([`provision_topology`]) — issue #118's runtime-path contract:
//!   a **synthetic test topology** of `>= 5` validators (default 5, the #126
//!   product minimum) plus the same funded roles, on the same dormant
//!   `ChainParams`. Consensus only: the compute-pool and beacon gates stay
//!   `None` and their parameter surfaces stay absent. This is what
//!   `deploy/snip-local-mirror.yaml` runs. Every validator key is a throwaway
//!   key generated on the machine that runs the provisioner; nothing here
//!   describes, proposes or changes any production validator set. The output
//!   directory may resolve outside the repository, or be exactly the ignored
//!   runtime directory `<repo>/devnet` ([`DEVNET_RUNTIME_DIR`]) that the compose
//!   file reads.
//!
//!   Its genesis is described, for review, by the tracked placeholder template
//!   [`TOPOLOGY_TEMPLATE`]: [`substitute_template`] fills it, the loader refuses
//!   it until then, and `tests/topology_template.rs` checks that it describes
//!   exactly what this mode provisions. [`check_topology_shape`] is the one
//!   shape rule both satisfy.
//! * **ecosystem** ([`ECOSYSTEM_DEFERRED_MSG`]) — the five-validator *pool*
//!   devnet. It is **deferred** and hard-fails: its genesis template needs
//!   values that are not ratified and gates the loader refuses. A passing smoke
//!   or topology run does NOT constitute the ecosystem.
//!
//! The legacy three-validator "local testnet" behaviour lives in the binary
//! (`setup_local_testnet.rs`) and is unchanged; this library is only the
//! #118/#119 surface.

use std::collections::{BTreeMap, BTreeSet};
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

/// The non-validator funded roles every devnet mode bootstraps (issue #119
/// scope): three archives, one verifier, one client, one funder.
pub const SMOKE_ROLE_NAMES: &[&str] = &[
    "archive1", "archive2", "archive3", "verifier", "client", "funder",
];

/// Basename of the runnable genesis written by every devnet mode. Deliberately
/// NOT `local_genesis.json` (a tracked file) — no devnet mode writes a tracked
/// genesis name.
pub const GENESIS_FILE: &str = "genesis.json";

/// Basename of the runnable genesis written by smoke mode (see [`GENESIS_FILE`]).
pub const SMOKE_GENESIS_FILE: &str = GENESIS_FILE;

/// The repository-relative runtime directory issue #118 assigns to the
/// generated devnet. `deploy/snip-local-mirror.yaml` bind-mounts
/// `../devnet/genesis.json` and `../devnet/keys/validator<i>.json` from it, and
/// `.gitignore` ignores it (`/devnet/`).
///
/// It is the ONLY path inside the repository a provisioner may write to, only
/// in topology mode, and only while `.gitignore` still ignores it — see
/// [`provision_topology`].
pub const DEVNET_RUNTIME_DIR: &str = "devnet";

/// The `.gitignore` line that must be present before the in-repository
/// exception for [`DEVNET_RUNTIME_DIR`] is honoured.
pub const DEVNET_GITIGNORE_LINE: &str = "/devnet/";

/// Validator count `topology` mode provisions when none is given: the number of
/// validator services `deploy/snip-local-mirror.yaml` runs.
pub const TOPOLOGY_DEFAULT_VALIDATORS: usize = 5;

/// Fewest validators `topology` mode accepts: issue #118 requires a `>= 5`
/// validator devnet, which is #126's product minimum for the DKG-creation phase
/// (`n >= 3f + 1 + c` with `f = 1`, `c = 1`).
///
/// This is a floor on a SYNTHETIC test topology. It is not the beacon `n_min`
/// field (which does not exist), not a ratified validator floor, and not a
/// statement about any production validator set.
pub const TOPOLOGY_MIN_VALIDATORS: usize = 5;

/// Most validators `topology` mode accepts. A local resource bound (one
/// container per validator on one host), not a protocol value; it exists so a
/// typo cannot generate thousands of key files.
pub const TOPOLOGY_MAX_VALIDATORS: usize = 16;

/// The tracked, repository-relative placeholder template that describes the
/// topology genesis for review (issue #118). It is a TEMPLATE, never a runnable
/// genesis: its `DEVNET_*` strings are placeholders the loader refuses until
/// [`substitute_template`] replaces them. Consensus only, like everything
/// [`provision_topology`] writes; it is not the pool or beacon ecosystem
/// genesis.
pub const TOPOLOGY_TEMPLATE: &str = "genesis/snip-mirror-genesis.template.json";

/// Every placeholder in a template starts with this prefix and is otherwise
/// upper-case ASCII letters, digits and underscores.
pub const TEMPLATE_PLACEHOLDER_PREFIX: &str = "DEVNET_";

/// Explicit, actionable message emitted when `ecosystem` mode is selected while
/// its prerequisites are absent. Naming the blockers keeps the deferral honest
/// (the five-validator pool is tracked separately and is never satisfied by a
/// smoke or topology run).
pub const ECOSYSTEM_DEFERRED_MSG: &str = "\
ecosystem mode is DEFERRED and cannot generate anything yet.

The five-validator pool devnet needs #118's pool and beacon fields in the
genesis template (genesis/snip-mirror-genesis.template.json). That template
is consensus only today: it holds the synthetic five-validator topology,
and its pool and beacon fields are absent because they are not ratified:
  - bond values (B_offer, B_commit, D_beacon, B_check) and reimbursement
    amounts
  - re-provision and reassignment bounds, and the retention values
    (#129)
  - the beacon DKG windows and the VK/program/tokenizer/model registry
    contents
  - the beacon `n_min` validator-floor field, which `BeaconParamsConfig`
    does not have
and its gates are refused: the genesis loader rejects any value, including
0, for `compute_pool_enabled_from_height` and `beacon_enabled_from_height`.

A passing smoke or topology run does NOT constitute the five-validator pool
ecosystem; ecosystem completion is tracked separately. Available today:
`--mode smoke` (one validator) and `--mode topology` (a synthetic >= 5
validator, consensus-only devnet with both gates None, which
deploy/snip-local-mirror.yaml runs).";

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

/// A generated, funded validator identity. Throwaway: generated fresh on every
/// run, never committed.
#[derive(Debug, Clone)]
pub struct ValidatorKey {
    /// Key-file stem: `validator` (smoke) or `validator<i>`, 1-based (topology).
    pub name: String,
    /// base58 public key, exactly as listed in `genesis.validators`.
    pub pubkey_b58: String,
    /// The same public key as lowercase hex, the form block headers carry
    /// (`get_block_by_height` reports `proposer` in it).
    pub pubkey_hex: String,
    /// base58 account address (also funded in `alloc`).
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

/// Everything a topology provisioning produced. All paths live under
/// `output_dir`.
#[derive(Debug, Clone)]
pub struct TopologyArtifacts {
    /// The output directory every artifact was written under.
    pub output_dir: PathBuf,
    /// The runnable genesis path (`output_dir/genesis.json`).
    pub genesis_path: PathBuf,
    /// The validators, in `genesis.validators` order: `validators[i]` proposes
    /// every height `h` with `h % n == i` under round-robin.
    pub validators: Vec<ValidatorKey>,
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

/// Where a provisioning mode may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputPolicy {
    /// Outside the repository only. Smoke mode (#119), unchanged.
    OutsideRepository,
    /// Outside the repository, or exactly the ignored `<repo>/devnet` runtime
    /// directory. Topology mode (#118).
    OutsideRepositoryOrDevnet,
}

/// True when `.gitignore` text ignores the devnet runtime directory: it holds
/// the exact line [`DEVNET_GITIGNORE_LINE`] and no negation that could
/// re-include anything under it.
fn gitignore_ignores_devnet(gitignore: &str) -> bool {
    let lines: Vec<&str> = gitignore.lines().map(str::trim).collect();
    let ignored = lines.contains(&DEVNET_GITIGNORE_LINE);
    let reincluded = lines
        .iter()
        .any(|l| l.starts_with('!') && l.contains(DEVNET_RUNTIME_DIR));
    ignored && !reincluded
}

/// Decide whether the canonical output directory `resolved` is an acceptable
/// location under `policy`. `repo_root` is canonical too; `gitignore` is the
/// text of `<repo_root>/.gitignore`, `None` when it could not be read.
///
/// The rule the in-repository exception keeps: no provisioner write can modify
/// a tracked file or show up in `git status`. Smoke mode meets it by writing
/// outside the tree only. Topology mode may also write into exactly
/// `<repo>/devnet` — the path #118 assigns to the generated devnet, and the
/// only one `deploy/snip-local-mirror.yaml` reads — and only while
/// `.gitignore` ignores it, so the exception cannot outlive the ignore rule.
/// Any other path inside the repository (the root, `genesis/`, `target/`, a
/// subdirectory of `devnet/`) is still refused, as are a non-empty directory
/// and a symlink, by [`validate_output_dir`].
fn check_output_location(
    resolved: &Path,
    repo_root: &Path,
    gitignore: Option<&str>,
    policy: OutputPolicy,
    mode: &str,
) -> Result<()> {
    if !(resolved == repo_root || resolved.starts_with(repo_root)) {
        return Ok(());
    }
    match policy {
        OutputPolicy::OutsideRepository => bail!(
            "{mode} --output-dir must resolve OUTSIDE the repository \
             (got {}, repo root {}); use an ephemeral `mktemp -d` directory",
            resolved.display(),
            repo_root.display()
        ),
        OutputPolicy::OutsideRepositoryOrDevnet => {
            let devnet = repo_root.join(DEVNET_RUNTIME_DIR);
            if resolved != devnet {
                bail!(
                    "{mode} --output-dir must resolve OUTSIDE the repository, or be exactly the \
                     ignored runtime directory {} (got {}); use `mktemp -d` or `mkdir -m 0700 {}`",
                    devnet.display(),
                    resolved.display(),
                    DEVNET_RUNTIME_DIR
                );
            }
            if !gitignore.is_some_and(gitignore_ignores_devnet) {
                bail!(
                    "{mode} --output-dir {} is inside the repository and {}/.gitignore does not \
                     ignore it (expected the line `{}` and no negation under it); refusing to \
                     write keys or a genesis where git could track them",
                    resolved.display(),
                    repo_root.display(),
                    DEVNET_GITIGNORE_LINE
                );
            }
            Ok(())
        }
    }
}

/// Fail-closed validation of an `--output-dir` **before** anything is written.
/// The directory must (1) already exist as a real directory (not a symlink),
/// (2) be an acceptable location under `policy` ([`check_output_location`]),
/// (3) be EMPTY, and (4) contain no pre-existing/symlinked `keys/`. Any
/// violation is an error — the provisioner never overwrites an existing
/// artifact.
fn validate_output_dir(output_dir: &Path, policy: OutputPolicy, mode: &str) -> Result<()> {
    let create_hint = match policy {
        OutputPolicy::OutsideRepository => "create it with `mktemp -d`",
        OutputPolicy::OutsideRepositoryOrDevnet => {
            "create it with `mktemp -d`, or `mkdir -m 0700 devnet` at the repository root"
        }
    };
    // Must already exist as a real directory (caller creates it).
    let meta = fs::symlink_metadata(output_dir).with_context(|| {
        format!(
            "{mode} --output-dir {} must exist ({create_hint})",
            output_dir.display()
        )
    })?;
    if !meta.is_dir() {
        bail!(
            "{mode} --output-dir {} must be a directory (not a file/symlink)",
            output_dir.display()
        );
    }

    // Location. Repo root = parent of this crate's compile-time manifest dir
    // (`<repo>/scripts`).
    let resolved = output_dir
        .canonicalize()
        .with_context(|| format!("canonicalize --output-dir {}", output_dir.display()))?;
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("locate repository root")?
        .canonicalize()
        .context("canonicalize repository root")?;
    let gitignore = fs::read_to_string(repo_root.join(".gitignore")).ok();
    check_output_location(&resolved, &repo_root, gitignore.as_deref(), policy, mode)?;

    // Must be empty before provisioning — never overwrite existing artifacts.
    if fs::read_dir(output_dir)
        .with_context(|| format!("read --output-dir {}", output_dir.display()))?
        .next()
        .is_some()
    {
        bail!(
            "{mode} --output-dir {} must be EMPTY before provisioning \
             (refusing to overwrite genesis.json / manifest.json / keys)",
            output_dir.display()
        );
    }

    // No pre-existing/symlinked `keys/` (implied by empty, but explicit).
    if output_dir.join("keys").symlink_metadata().is_ok() {
        bail!(
            "{mode} output {}/keys already exists (possibly a symlink); refusing to write into it",
            output_dir.display()
        );
    }
    Ok(())
}

/// Create `output_dir/keys` (it must not exist yet).
fn create_keys_dir(output_dir: &Path) -> Result<PathBuf> {
    let keys_dir = output_dir.join("keys");
    fs::create_dir(&keys_dir).with_context(|| {
        format!(
            "create keys dir {} (must not already exist)",
            keys_dir.display()
        )
    })?;
    Ok(keys_dir)
}

/// Generate one validator keypair per name, writing each private key to
/// `keys_dir/<name>.json` (create-new, `0600`).
fn generate_validators(keys_dir: &Path, names: &[String]) -> Result<Vec<ValidatorKey>> {
    names
        .iter()
        .map(|name| {
            let kp = KeyPair::generate();
            let key_path = keys_dir.join(format!("{name}.json"));
            write_private_key(&key_path, &kp)?;
            Ok(ValidatorKey {
                name: name.clone(),
                pubkey_b58: kp.public_key().to_base58(),
                pubkey_hex: kp.public_key().to_hex(),
                address_b58: kp.address().to_base58(),
                key_path,
            })
        })
        .collect()
}

/// Generate the #119 funded roles ([`SMOKE_ROLE_NAMES`]), writing each private
/// key to `keys_dir/<role>.json` (create-new, `0600`).
fn generate_roles(keys_dir: &Path) -> Result<Vec<RoleKey>> {
    SMOKE_ROLE_NAMES
        .iter()
        .map(|&name| {
            let kp = KeyPair::generate();
            let key_path = keys_dir.join(format!("{name}.json"));
            write_private_key(&key_path, &kp)?;
            Ok(RoleKey {
                name: name.to_string(),
                address_b58: kp.address().to_base58(),
                key_path,
            })
        })
        .collect()
}

/// Build the runnable genesis every devnet mode shares — the single
/// genesis-building path (#119: no second independent implementation).
///
/// `validators` in the given order (round-robin proposer order); `alloc` funds
/// every validator address and every role with [`ROLE_ALLOC`], so each has
/// balance > 0 straight from genesis. Duplicate accounts are refused rather
/// than overwritten (#276). Validated through the authoritative loader check
/// before it is returned.
fn build_dormant_genesis(
    validators: &[ValidatorKey],
    roles: &[RoleKey],
    mode: &str,
) -> Result<Genesis> {
    let alloc_entries: Vec<(String, u128)> = validators
        .iter()
        .map(|v| (v.address_b58.clone(), ROLE_ALLOC))
        .chain(roles.iter().map(|r| (r.address_b58.clone(), ROLE_ALLOC)))
        .collect();

    // `with_v2_enabled()` activates SNIP V2 from genesis (so the funded archive
    // roles have a live storage subprotocol) while leaving every other gate at
    // its production-safe default — crucially compute_pool + beacon = None, with
    // their parameter surfaces absent. Checked, not assumed: a devnet genesis is
    // consensus only.
    //
    // No staking section, like every shipped genesis and the legacy local mode:
    // protocol v1 membership is the static validator list, and the executor's
    // staking defaults apply (`genesis/tests/protocol_v1_staking.rs` requires
    // every shipped genesis, including the topology template, to omit it).
    let mut params = ChainParams::with_v2_enabled();
    params.staking = None;
    if params.compute_pool_enabled_from_height.is_some()
        || params.beacon_enabled_from_height.is_some()
        || params.compute_pool_params.is_some()
        || params.beacon_params.is_some()
        || params.beacon_schedule.is_some()
    {
        bail!("{mode} genesis must leave the compute-pool and beacon gates and parameters absent");
    }

    let genesis_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let alloc = sumchain_genesis::alloc_from_entries(alloc_entries)
        .with_context(|| format!("{mode} genesis allocations"))?;

    let genesis = Genesis::new(
        DEVNET_CHAIN_ID,
        genesis_time,
        validators.iter().map(|v| v.pubkey_b58.clone()).collect(),
        alloc,
        params,
    );
    // Fail-closed loader check: rejects any opened compute-pool/beacon gate and
    // validates every validator key + alloc address.
    genesis
        .validate()
        .with_context(|| format!("generated {mode} genesis failed validation"))?;
    Ok(genesis)
}

/// Serialize `genesis` to `output_dir/genesis.json` (create-new).
fn write_genesis(output_dir: &Path, genesis: &Genesis) -> Result<PathBuf> {
    let genesis_path = output_dir.join(GENESIS_FILE);
    let genesis_json = genesis.to_json().context("serialize runnable genesis")?;
    write_new_public_file(&genesis_path, &genesis_json)
        .with_context(|| format!("write runnable genesis to {}", genesis_path.display()))?;
    Ok(genesis_path)
}

/// The public role list a manifest carries (no private material).
fn roles_manifest(roles: &[RoleKey]) -> Vec<serde_json::Value> {
    roles
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "address": r.address_b58,
                "key_file": format!("keys/{}.json", r.name),
            })
        })
        .collect()
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
/// the synthetic multi-validator devnet is [`provision_topology`], and the pool
/// is the deferred ecosystem mode.
///
/// This function writes **only** under `output_dir`, which must resolve outside
/// the repository. It never reads #118's template and never touches a tracked
/// genesis file.
pub fn provision_smoke(output_dir: &Path, validator_count: usize) -> Result<SmokeArtifacts> {
    if validator_count != 1 {
        bail!(
            "smoke mode is single-validator by definition (got --validator-count {validator_count}). \
             A multi-validator pool is the deferred ecosystem mode; use --mode ecosystem to see \
             its blockers, --mode topology for the synthetic consensus-only multi-validator \
             devnet, or --validator-count 1."
        );
    }

    // Fail-closed: outside-repo, empty, no pre-existing/symlinked keys/ — checked
    // before anything is written, so we never overwrite an existing artifact.
    validate_output_dir(output_dir, OutputPolicy::OutsideRepository, "smoke")?;

    let keys_dir = create_keys_dir(output_dir)?;
    let mut validators = generate_validators(&keys_dir, &["validator".to_string()])?;
    let roles = generate_roles(&keys_dir)?;
    let genesis = build_dormant_genesis(&validators, &roles, "smoke")?;
    let genesis_path = write_genesis(output_dir, &genesis)?;
    let validator = validators.remove(0);

    // ── public manifest (no private material) ───────────────────────────────
    let manifest_path = output_dir.join("manifest.json");
    let manifest = serde_json::json!({
        "mode": "smoke",
        "chain_id": DEVNET_CHAIN_ID,
        "genesis_file": SMOKE_GENESIS_FILE,
        "validator": {
            "pubkey": validator.pubkey_b58,
            "address": validator.address_b58,
            "key_file": "keys/validator.json",
        },
        "roles": roles_manifest(&roles),
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
        validator_pubkey_b58: validator.pubkey_b58,
        validator_address_b58: validator.address_b58,
        validator_key_path: validator.key_path,
        roles,
        manifest_path,
    })
}

/// Provision a **synthetic test topology** of `validator_count` validators into
/// `output_dir` (issue #118's runtime-path contract).
///
/// SYNTHETIC: every validator key is a throwaway key generated here, for a
/// local or CI devnet. This never describes, proposes or changes a production
/// validator set.
///
/// Generates `validator_count` validators (`validator1` .. `validatorN`, in
/// genesis and therefore round-robin order) plus the #119 funded roles, builds
/// the runnable genesis through the same path as smoke mode (consensus only:
/// compute-pool and beacon gates `None`, their parameters absent; chain id
/// [`DEVNET_CHAIN_ID`]), and writes:
///
/// * `output_dir/keys/validator<i>.json` + one file per role (each `0600`),
/// * `output_dir/genesis.json` (the runnable genesis; only public identifiers),
/// * `output_dir/manifest.json` (public identities + gate states).
///
/// `validator_count` must lie in
/// [`TOPOLOGY_MIN_VALIDATORS`]`..=`[`TOPOLOGY_MAX_VALIDATORS`].
///
/// `output_dir` must exist, be empty, and resolve outside the repository or be
/// exactly the ignored `<repo>/devnet` ([`DEVNET_RUNTIME_DIR`]) — the directory
/// `deploy/snip-local-mirror.yaml` reads. Nothing is written anywhere else, and
/// no tracked genesis file is read or written.
pub fn provision_topology(output_dir: &Path, validator_count: usize) -> Result<TopologyArtifacts> {
    if !(TOPOLOGY_MIN_VALIDATORS..=TOPOLOGY_MAX_VALIDATORS).contains(&validator_count) {
        bail!(
            "topology mode needs {TOPOLOGY_MIN_VALIDATORS}..={TOPOLOGY_MAX_VALIDATORS} validators \
             (got --validator-count {validator_count}). Issue #118 requires a >= 5-validator devnet \
             (#126's product minimum); deploy/snip-local-mirror.yaml runs exactly \
             {TOPOLOGY_DEFAULT_VALIDATORS}. Use --mode smoke for a single validator."
        );
    }

    validate_output_dir(
        output_dir,
        OutputPolicy::OutsideRepositoryOrDevnet,
        "topology",
    )?;

    let keys_dir = create_keys_dir(output_dir)?;
    let names: Vec<String> = (1..=validator_count)
        .map(|i| format!("validator{i}"))
        .collect();
    let validators = generate_validators(&keys_dir, &names)?;
    let roles = generate_roles(&keys_dir)?;
    let genesis = build_dormant_genesis(&validators, &roles, "topology")?;
    check_topology_shape(&genesis).context("generated topology genesis")?;
    let genesis_path = write_genesis(output_dir, &genesis)?;

    // ── public manifest (no private material) ───────────────────────────────
    let manifest_path = output_dir.join("manifest.json");
    let manifest = serde_json::json!({
        "mode": "topology",
        "synthetic_test_topology": true,
        "notice": "Synthetic test topology with throwaway keys for a local or CI devnet; \
                   not a production validator set.",
        "chain_id": DEVNET_CHAIN_ID,
        "genesis_file": GENESIS_FILE,
        "validator_count": validators.len(),
        "validators": validators
            .iter()
            .enumerate()
            .map(|(index, v)| {
                serde_json::json!({
                    "name": v.name,
                    "index": index,
                    "pubkey": v.pubkey_b58,
                    "pubkey_hex": v.pubkey_hex,
                    "address": v.address_b58,
                    "key_file": format!("keys/{}.json", v.name),
                })
            })
            .collect::<Vec<_>>(),
        "roles": roles_manifest(&roles),
        "gates": {
            "compute_pool_enabled_from_height": serde_json::Value::Null,
            "beacon_enabled_from_height": serde_json::Value::Null,
        },
    });
    let manifest_json = serde_json::to_string_pretty(&manifest).context("serialize manifest")?;
    write_new_public_file(&manifest_path, &manifest_json)
        .with_context(|| format!("write manifest to {}", manifest_path.display()))?;

    Ok(TopologyArtifacts {
        output_dir: output_dir.to_path_buf(),
        genesis_path,
        validators,
        roles,
        manifest_path,
    })
}

/// The topology shape issue #118 asks of a devnet genesis, and nothing more:
/// chain id [`DEVNET_CHAIN_ID`], at least [`TOPOLOGY_MIN_VALIDATORS`] distinct
/// validators, every validator funded, and consensus only.
///
/// "Consensus only" is checked, not assumed: the compute-pool and beacon gates
/// must be `None` and their parameter surfaces absent. Issue #118's checklist
/// asks for both gates at `Some(0)`; the loader refuses either gate at any
/// value, including 0, and their parameters are not ratified, so a topology
/// genesis that opened them would be wrong twice over. Activating either one is
/// a separate, owner-authorized change, not something a devnet genesis may
/// assume.
pub fn check_topology_shape(genesis: &Genesis) -> Result<()> {
    if genesis.chain_id != DEVNET_CHAIN_ID {
        bail!(
            "topology genesis has chain id {}, not the devnet's {DEVNET_CHAIN_ID}",
            genesis.chain_id
        );
    }
    let n = genesis.validators.len();
    if n < TOPOLOGY_MIN_VALIDATORS {
        bail!(
            "topology genesis lists {n} validators; issue #118 requires at least \
             {TOPOLOGY_MIN_VALIDATORS} (#126's product minimum)"
        );
    }
    let distinct: BTreeSet<&String> = genesis.validators.iter().collect();
    if distinct.len() != n {
        bail!("topology genesis lists a validator more than once");
    }
    for (i, v) in genesis.validators.iter().enumerate() {
        let key = sumchain_crypto::PublicKey::from_base58(v)
            .with_context(|| format!("topology validator {i} is not a public key"))?;
        let address = key.address().to_base58();
        if genesis.alloc.get(&address).copied().unwrap_or(0) == 0 {
            bail!("topology validator {i} is not funded at genesis");
        }
    }
    let p = &genesis.params;
    if p.compute_pool_enabled_from_height.is_some()
        || p.beacon_enabled_from_height.is_some()
        || p.compute_pool_params.is_some()
        || p.beacon_params.is_some()
        || p.beacon_schedule.is_some()
    {
        bail!(
            "topology genesis must leave the compute-pool and beacon gates and parameters \
             absent: it is consensus only, and neither feature is activated by a devnet genesis"
        );
    }
    Ok(())
}

/// Fill a placeholder template: every JSON string (value or object key) equal
/// to a key of `values` becomes that value, and the result is returned as JSON
/// text for the genesis loader.
///
/// Fail closed in both directions: a placeholder left in the template with no
/// value, and a value whose placeholder does not appear, are both refused, so a
/// template and its caller cannot drift apart silently. A placeholder is any
/// string starting with [`TEMPLATE_PLACEHOLDER_PREFIX`] made only of upper-case
/// ASCII letters, digits and underscores.
pub fn substitute_template(template: &str, values: &BTreeMap<String, String>) -> Result<String> {
    fn is_placeholder(s: &str) -> bool {
        s.len() > TEMPLATE_PLACEHOLDER_PREFIX.len()
            && s.starts_with(TEMPLATE_PLACEHOLDER_PREFIX)
            && s.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    }
    fn fill(
        s: &str,
        values: &BTreeMap<String, String>,
        used: &mut BTreeSet<String>,
        missing: &mut BTreeSet<String>,
    ) -> Option<String> {
        if let Some(real) = values.get(s) {
            used.insert(s.to_string());
            Some(real.clone())
        } else {
            if is_placeholder(s) {
                missing.insert(s.to_string());
            }
            None
        }
    }
    fn walk(
        v: &mut serde_json::Value,
        values: &BTreeMap<String, String>,
        used: &mut BTreeSet<String>,
        missing: &mut BTreeSet<String>,
    ) {
        match v {
            serde_json::Value::String(s) => {
                if let Some(real) = fill(s, values, used, missing) {
                    *s = real;
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, values, used, missing);
                }
            }
            serde_json::Value::Object(map) => {
                let entries: Vec<(String, serde_json::Value)> =
                    std::mem::take(map).into_iter().collect();
                for (k, mut child) in entries {
                    let k = fill(&k, values, used, missing).unwrap_or(k);
                    walk(&mut child, values, used, missing);
                    map.insert(k, child);
                }
            }
            _ => {}
        }
    }
    let mut doc: serde_json::Value =
        serde_json::from_str(template).context("template is not JSON")?;
    let mut used = BTreeSet::new();
    let mut missing = BTreeSet::new();
    walk(&mut doc, values, &mut used, &mut missing);
    if !missing.is_empty() {
        bail!("template placeholders with no value: {missing:?}");
    }
    let unused: Vec<&String> = values.keys().filter(|k| !used.contains(*k)).collect();
    if !unused.is_empty() {
        bail!("values for placeholders the template does not contain: {unused:?}");
    }
    serde_json::to_string_pretty(&doc).context("serialize substituted template")
}

/// The values a provisioned topology gives [`TOPOLOGY_TEMPLATE`]'s
/// placeholders: `DEVNET_VALIDATOR<i>_PUBKEY` and `DEVNET_VALIDATOR<i>_ADDRESS`
/// for each validator in order (from 1), and `DEVNET_<ROLE>_ADDRESS` for each
/// funded role.
pub fn topology_template_values(artifacts: &TopologyArtifacts) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for (i, v) in artifacts.validators.iter().enumerate() {
        let n = i + 1;
        values.insert(format!("DEVNET_VALIDATOR{n}_PUBKEY"), v.pubkey_b58.clone());
        values.insert(
            format!("DEVNET_VALIDATOR{n}_ADDRESS"),
            v.address_b58.clone(),
        );
    }
    for r in &artifacts.roles {
        values.insert(
            format!("DEVNET_{}_ADDRESS", r.name.to_ascii_uppercase()),
            r.address_b58.clone(),
        );
    }
    values
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

    const IGNORES: &str = "/target/\n/keys/\n/devnet/\n";

    fn location(
        resolved: &Path,
        root: &Path,
        gitignore: Option<&str>,
        policy: OutputPolicy,
    ) -> Result<()> {
        check_output_location(resolved, root, gitignore, policy, "test")
    }

    /// Outside the repository is acceptable under both policies.
    #[test]
    fn outside_the_repository_is_accepted_by_both_policies() {
        let root = Path::new("/r/repo");
        for policy in [
            OutputPolicy::OutsideRepository,
            OutputPolicy::OutsideRepositoryOrDevnet,
        ] {
            location(Path::new("/tmp/x"), root, Some(IGNORES), policy).expect("outside");
            // A sibling whose name merely starts with the repo's is outside.
            location(Path::new("/r/repo-devnet"), root, None, policy).expect("sibling");
        }
    }

    /// Smoke's rule is unchanged: nothing inside the repository, `devnet`
    /// included.
    #[test]
    fn smoke_policy_refuses_every_in_repository_path_including_devnet() {
        let root = Path::new("/r/repo");
        for p in [
            "/r/repo",
            "/r/repo/devnet",
            "/r/repo/target/t",
            "/r/repo/genesis",
        ] {
            let err = location(
                Path::new(p),
                root,
                Some(IGNORES),
                OutputPolicy::OutsideRepository,
            )
            .expect_err(p);
            assert!(
                format!("{err:#}").contains("OUTSIDE the repository"),
                "{p}: {err:#}"
            );
        }
    }

    /// Topology may write into exactly `<repo>/devnet` while it is ignored —
    /// and nowhere else inside the repository.
    #[test]
    fn topology_policy_allows_only_the_ignored_devnet_directory() {
        let root = Path::new("/r/repo");
        let policy = OutputPolicy::OutsideRepositoryOrDevnet;
        location(Path::new("/r/repo/devnet"), root, Some(IGNORES), policy)
            .expect("the ignored devnet runtime directory");
        for p in [
            "/r/repo",
            "/r/repo/devnet/sub",
            "/r/repo/devnet2",
            "/r/repo/genesis",
            "/r/repo/keys",
            "/r/repo/target/t",
            "/r/repo/deploy/devnet",
        ] {
            let err = location(Path::new(p), root, Some(IGNORES), policy).expect_err(p);
            assert!(
                format!("{err:#}").contains("OUTSIDE the repository"),
                "{p}: {err:#}"
            );
        }
    }

    /// The exception does not outlive the ignore rule: without the exact
    /// `/devnet/` line, or with a negation re-including part of it, or with no
    /// readable `.gitignore`, `<repo>/devnet` is refused.
    #[test]
    fn topology_devnet_exception_requires_the_gitignore_rule() {
        let root = Path::new("/r/repo");
        let devnet = Path::new("/r/repo/devnet");
        let policy = OutputPolicy::OutsideRepositoryOrDevnet;
        for gi in [
            Some("/target/\n/keys/\n"),
            Some("devnet\n"),
            Some("/devnet/*\n"),
            Some("/devnet/\n!/devnet/genesis.json\n"),
            None,
        ] {
            let err = location(devnet, root, gi, policy).expect_err("must refuse");
            assert!(
                format!("{err:#}").contains("does not ignore it"),
                "{gi:?}: {err:#}"
            );
        }
    }
}

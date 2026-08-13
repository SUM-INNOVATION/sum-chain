//! `b0-pre-host-provenance` — emit ONE measurement `ProvFacts` record for a
//! (candidate-arch, role), read from the real host. Host/cgroup facts come from the
//! unit-tested [`b0_pre_host_provenance::read_host_facts`]; git state (source commit +
//! dirty tree) is read live from the repo; the raw-environment capture is hashed from
//! the live host facts + kernel cmdline. NOTHING is hard-coded or defaulted.
//!
//! Usage:
//!   b0-pre-host-provenance <arch> <role> \
//!     --root <fs-root=/> --repo <git-repo> \
//!     --builder-digest <sha256:...> --harness-source-hash <blake3-hex> [--out <file>]

use std::path::Path;
use std::process::{Command, ExitCode};

use b0_pre_host_provenance::read_host_facts;

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn git_state(repo: &Path) -> Result<(String, bool), String> {
    let head = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("run git rev-parse: {e}"))?;
    if !head.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&head.stderr).trim()
        ));
    }
    let commit = String::from_utf8_lossy(&head.stdout).trim().to_string();
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("git returned a non-canonical HEAD: {commit:?}"));
    }
    let status = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["status", "--porcelain"])
        .output()
        .map_err(|e| format!("run git status: {e}"))?;
    if !status.status.success() {
        return Err("git status --porcelain failed".into());
    }
    let dirty = !String::from_utf8_lossy(&status.stdout).trim().is_empty();
    Ok((commit, dirty))
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    let arch = args.get(1).ok_or("usage: <arch> <role> [flags]")?.clone();
    let role = args.get(2).ok_or("usage: <arch> <role> [flags]")?.clone();
    match arch.as_str() {
        "x86_64" | "aarch64" => {}
        other => return Err(format!("arch must be x86_64|aarch64 (got {other})")),
    }
    let root = arg(&args, "--root").unwrap_or_else(|| "/".into());
    let repo = arg(&args, "--repo").ok_or("--repo <git-repo> is required")?;
    let builder_digest = arg(&args, "--builder-digest").ok_or("--builder-digest is required")?;
    let harness_source_hash =
        arg(&args, "--harness-source-hash").ok_or("--harness-source-hash is required")?;
    if harness_source_hash.len() != 64
        || !harness_source_hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("--harness-source-hash must be 64 hex chars (blake3)".into());
    }

    let root = Path::new(&root);
    let facts = read_host_facts(root)?;
    let (source_commit, dirty_tree_flag) = git_state(Path::new(&repo))?;

    // Raw-environment capture: a REAL, deterministic snapshot of the measured host —
    // the canonical host facts plus the kernel cmdline — hashed with BLAKE3. Fail-closed
    // if the cmdline is unreadable (no synthetic capture).
    let cmdline = std::fs::read(root.join("proc/cmdline"))
        .map_err(|e| format!("read proc/cmdline for environment capture: {e}"))?;
    let mut h = blake3::Hasher::new();
    h.update(format!("{facts:?}").as_bytes());
    h.update(b"\n");
    h.update(&cmdline);
    let raw_environment_capture_hash = hex(h.finalize().as_bytes());

    let record = serde_json::json!({
        "arch": arch,
        "role": role,
        "source_commit": source_commit,
        "dirty_tree_flag": dirty_tree_flag,
        "builder_container_digest": builder_digest,
        "host_os": facts.host_os,
        "kernel": facts.kernel,
        "cpu_vendor": facts.cpu_vendor,
        "cpu_model": facts.cpu_model,
        "physical_core_count": facts.physical_core_count,
        "logical_cpu_count": facts.logical_cpu_count,
        "total_ram_bytes": facts.total_ram_bytes,
        "configured_cpuset_core_limit": facts.configured_cpuset_core_limit,
        "configured_memory_limit_bytes": facts.configured_memory_limit_bytes,
        "dvfs": facts.dvfs,
        "clock_source": facts.clock_source,
        "cgroup_version": facts.cgroup_version,
        "cgroup_scope_label": facts.cgroup_scope_label,
        "benchmark_harness_source_hash": harness_source_hash,
        "raw_environment_capture_hash": raw_environment_capture_hash,
    });
    let out = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
    if let Some(path) = arg(&args, "--out") {
        std::fs::write(&path, &out).map_err(|e| format!("write {path}: {e}"))?;
    }
    Ok(out)
}

fn main() -> ExitCode {
    match run() {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("INELIGIBLE: host-provenance read failed closed: {e}");
            ExitCode::FAILURE
        }
    }
}

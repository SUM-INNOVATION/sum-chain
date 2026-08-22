//! Real host/cgroup provenance READER for the B0-FINAL measurement producer.
//!
//! Every field the measurement [`ProvFacts`] record carries about the host is READ
//! here from the live `/proc`, `/sys`, and cgroup filesystems — never assumed,
//! defaulted, or hard-coded. The filesystem root is a parameter (`--root`, default
//! `/`) so the exact parsing + fail-closed behaviour is unit-tested off-venue against
//! crafted trees; the venue runs it against the real root.
//!
//! Fail-closed discipline: a missing or ambiguous source is an ERROR, not a default.
//! A turbo state that cannot be determined, a non-uniform governor, an unreadable
//! cpuset, or an absent memory limit all REFUSE — because an unverifiable provenance
//! value must never silently enter authoritative measurement evidence.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

// ============== benchmark-harness source inventory (verifier-material causal closure) =============
//
// `benchmark_harness_source_hash` is the domain-separated BLAKE3 of a CANONICAL, EXPLICIT inventory of
// the exact benchmark-harness source inputs — the causal closure that determines the verifier material
// — computed from the CLEAN tooling root. It is NEVER a caller-supplied 64-hex value, and it is NOT the
// runner binary hash (that is separately attested).
//
// Included = both verifier-material harness crates (Cargo.toml + src + tests), the shared `b0-pre-vmat`
// canonical primitive (Cargo.toml + committed Cargo.lock + src), and `extract_material.sh` whose bytes
// bind the lock + builder that produce the material. EXCLUDED, deliberately: the measurement RUNNER
// sources (`b0-pre-measure-*`) — already bound independently by the tooling path-set authority AND each
// runner attestation's `production_binary_blake3`; and `b0-pre-vmat/.gitignore` (not a build input).
// The set is an EXPLICIT git pathspec list, never a recursive directory hash.
pub const HARNESS_SOURCE_DOMAIN: &[u8] = b"b0-final-benchmark-harness-source/v1\0";

const HARNESS_SOURCE_GLOBS: &[&str] = &[
    "tools/b0-pre-candidates/harness/sp1-verifier-material/Cargo.toml",
    "tools/b0-pre-candidates/harness/sp1-verifier-material/src/*.rs",
    "tools/b0-pre-candidates/harness/sp1-verifier-material/tests/*.rs",
    "tools/b0-pre-candidates/harness/risc0-verifier-material/Cargo.toml",
    "tools/b0-pre-candidates/harness/risc0-verifier-material/src/*.rs",
    "tools/b0-pre-candidates/harness/risc0-verifier-material/tests/*.rs",
    "tools/b0-pre-vmat/Cargo.toml",
    "tools/b0-pre-vmat/Cargo.lock",
    "tools/b0-pre-vmat/src/*.rs",
    "tools/b0-pre-candidates/scripts/extract_material.sh",
];
// Directories whose ENTIRE tracked contents (minus the documented exclude) MUST be covered by the
// globs — so a new harness file fails closed until it is explicitly listed.
const HARNESS_SOURCE_DIRS: &[&str] = &["tools/b0-pre-candidates/harness/", "tools/b0-pre-vmat/"];
const HARNESS_SOURCE_EXCLUDE: &[&str] = &["tools/b0-pre-vmat/.gitignore"];

fn git_lines(root: &Path, args: &[&str]) -> Result<Vec<String>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| format!("run git {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect())
}

/// Compute the canonical benchmark-harness source manifest + its domain-separated BLAKE3 digest from
/// the CLEAN tooling root. Fail-closed: git unavailable, an untracked helper under the harness dirs, a
/// tracked harness file not covered by the explicit globs, a symlink / non-regular git mode, or an
/// unreadable file all REFUSE. The manifest is the retained preimage — one canonical line per input,
/// `"<blake3_hex> <git_mode> <size>  <relpath>\n"`, LC_ALL=C sorted by relpath.
pub fn harness_source_inventory(tooling_root: &Path) -> Result<(String, [u8; 32]), String> {
    // No untracked helper may be smuggled under the harness dirs.
    let mut others = vec!["ls-files", "--others", "--exclude-standard", "--"];
    others.extend(HARNESS_SOURCE_DIRS);
    if let Some(u) = git_lines(tooling_root, &others)?
        .iter()
        .find(|s| !s.is_empty())
    {
        return Err(format!("untracked file under harness source dirs: {u}"));
    }
    // Canonical inventory: tracked files matched by the explicit globs ("<mode> <obj> <stage>\t<path>").
    let mut ls = vec!["ls-files", "-s", "--"];
    ls.extend(HARNESS_SOURCE_GLOBS);
    let mut modes: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for line in git_lines(tooling_root, &ls)? {
        if line.is_empty() {
            continue;
        }
        let (meta, path) = line
            .split_once('\t')
            .ok_or_else(|| format!("git ls-files -s line has no tab: {line:?}"))?;
        let mode = meta
            .split_whitespace()
            .next()
            .ok_or_else(|| format!("git ls-files -s line has no mode: {line:?}"))?;
        if mode != "100644" && mode != "100755" {
            return Err(format!(
                "harness source {path} has non-regular git mode {mode}"
            ));
        }
        modes.insert(path.to_string(), mode.to_string());
    }
    if modes.is_empty() {
        return Err("harness source inventory is empty (globs matched nothing)".into());
    }
    // Completeness: every tracked file under the harness DIRS (minus the documented exclude) must be
    // covered, so a new harness file fails closed until listed.
    let mut dir_ls = vec!["ls-files", "--"];
    dir_ls.extend(HARNESS_SOURCE_DIRS);
    for p in git_lines(tooling_root, &dir_ls)? {
        if p.is_empty() || HARNESS_SOURCE_EXCLUDE.contains(&p.as_str()) {
            continue;
        }
        if !modes.contains_key(&p) {
            return Err(format!(
                "tracked harness file absent from the canonical inventory globs (list it or exclude it): {p}"
            ));
        }
    }
    // BTreeMap already yields relpaths in ASCII byte order (LC_ALL=C).
    let mut manifest = String::new();
    for (rel, mode) in &modes {
        let abs = tooling_root.join(rel);
        let meta = std::fs::symlink_metadata(&abs).map_err(|e| format!("stat {rel}: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!("harness source {rel} is a symlink (refused)"));
        }
        let bytes = std::fs::read(&abs).map_err(|e| format!("read {rel}: {e}"))?;
        let bh = hex_lower(blake3::hash(&bytes).as_bytes());
        use std::fmt::Write as _;
        let _ = writeln!(manifest, "{bh} {mode} {}  {rel}", bytes.len());
    }
    let digest = recompute_harness_source_digest(&manifest);
    Ok((manifest, digest))
}

/// Domain-separated BLAKE3 of a canonical harness-source manifest preimage — the value BOTH verifiers
/// recompute from the retained manifest bytes (mirrors the tooling-path-set digest formula, distinct
/// domain).
pub fn recompute_harness_source_digest(manifest: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(HARNESS_SOURCE_DOMAIN);
    h.update(manifest.as_bytes());
    *h.finalize().as_bytes()
}

/// Host facts read purely from the filesystem root (everything except git state, which
/// the binary resolves separately, and the caller-supplied build/role/arch identities).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    pub host_os: String,
    pub kernel: String,
    pub cpu_vendor: String,
    pub cpu_model: String,
    pub physical_core_count: u32,
    pub logical_cpu_count: u32,
    pub total_ram_bytes: u64,
    /// The canonical effective CPU count. When the process leaf cgroup does not expose the cpuset
    /// controller, this is the INHERITED effective set resolved from the nearest ancestor (never a
    /// default-to-all-host-CPUs). The source + raw + inherited-flag below bind exactly where it came
    /// from so eligibility can independently recompute and verify the ancestor relationship.
    pub configured_cpuset_core_limit: u32,
    /// The cgroup path (cgroup-root-relative, e.g. `/user.slice`) the effective cpuset was READ from:
    /// the process leaf itself when leaf-observed, else the nearest ancestor that exposes it.
    pub cpuset_source_cgroup_path: String,
    /// The RAW `cpuset.cpus.effective` string (e.g. `0-3,7`) read from the source cgroup — bound so a
    /// verifier recomputes `configured_cpuset_core_limit` from it and refuses any raw/count mismatch.
    pub cpuset_raw: String,
    /// false = the value was observed at the process leaf; true = it was INHERITED from an ancestor
    /// because the leaf did not expose a readable nonempty `cpuset.cpus.effective`.
    pub cpuset_inherited: bool,
    /// The CANONICAL nearest-first probe chain from the process leaf (order 0) up to AND INCLUDING
    /// the selected source, one entry per visited cgroup with its observation state + stat/double-read
    /// evidence. The verifier recomputes "nearest ancestor" from this — never from a leaf/source pair.
    pub cpuset_probe_chain: Vec<CpusetProbeEntry>,
    pub configured_memory_limit_bytes: u64,
    pub dvfs: DvfsState,
    pub clock_source: String,
    pub cgroup_version: u8,
    pub cgroup_scope_label: String,
}

fn read_trimmed(p: &Path) -> Result<String, String> {
    let s = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    Ok(s.trim().to_string())
}

fn read_trimmed_at(root: &Path, rel: &str) -> Result<String, String> {
    read_trimmed(&root.join(rel.trim_start_matches('/')))
}

/// Parse a Linux cpu-list ("0-3,7,9-10") into the count of listed CPUs. Fail-closed on
/// any malformed token — an unreadable cpuset must never be silently treated as "all".
pub fn count_cpu_list(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty cpu list".into());
    }
    let mut total: u32 = 0;
    for tok in s.split(',') {
        let tok = tok.trim();
        if let Some((a, b)) = tok.split_once('-') {
            let lo: u32 = a
                .trim()
                .parse()
                .map_err(|_| format!("bad cpu range lo: {tok}"))?;
            let hi: u32 = b
                .trim()
                .parse()
                .map_err(|_| format!("bad cpu range hi: {tok}"))?;
            if hi < lo {
                return Err(format!("inverted cpu range: {tok}"));
            }
            total += hi - lo + 1;
        } else {
            tok.parse::<u32>()
                .map_err(|_| format!("bad cpu index: {tok}"))?;
            total += 1;
        }
    }
    Ok(total)
}

fn parse_meminfo_total_bytes(text: &str) -> Result<u64, String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .trim()
                .strip_suffix("kB")
                .unwrap_or(rest.trim())
                .trim()
                .parse()
                .map_err(|_| format!("bad MemTotal: {line}"))?;
            return kb
                .checked_mul(1024)
                .ok_or_else(|| "MemTotal overflow".to_string());
        }
    }
    Err("MemTotal not found in meminfo".into())
}

/// vendor + model from `/proc/cpuinfo`. x86 exposes `vendor_id` + `model name`; ARM
/// exposes `CPU implementer` + `CPU part`. Refuse if neither pairing is present.
fn parse_cpuinfo_identity(text: &str) -> Result<(String, String), String> {
    let field = |keys: &[&str]| -> Option<String> {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                if keys.iter().any(|want| k == *want) {
                    let v = v.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        None
    };
    let vendor = field(&["vendor_id", "CPU implementer"]);
    let model = field(&["model name", "CPU part"]);
    match (vendor, model) {
        (Some(vendor), Some(model)) => Ok((vendor, model)),
        _ => Err("cpuinfo lacks a vendor/model identity (vendor_id+model name or CPU implementer+CPU part)".into()),
    }
}

/// logical count = number of `cpuN` topology dirs; physical = unique
/// (physical_package_id, core_id) pairs. Both are exposed on x86 and ARM under
/// `/sys/devices/system/cpu`. Refuse if the topology is absent (never guess).
fn read_core_counts(root: &Path) -> Result<(u32, u32), String> {
    let base = root.join("sys/devices/system/cpu");
    let mut logical: u32 = 0;
    let mut pairs: Vec<(String, String)> = Vec::new();
    let entries = std::fs::read_dir(&base).map_err(|e| format!("read {}: {e}", base.display()))?;
    for ent in entries {
        let ent = ent.map_err(|e| e.to_string())?;
        let name = ent.file_name().to_string_lossy().to_string();
        let is_cpu = name
            .strip_prefix("cpu")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !is_cpu {
            continue;
        }
        logical += 1;
        let topo = ent.path().join("topology");
        let core_id = read_trimmed(&topo.join("core_id"))
            .map_err(|_| format!("missing topology/core_id for {name}"))?;
        let pkg_id = read_trimmed(&topo.join("physical_package_id"))
            .map_err(|_| format!("missing topology/physical_package_id for {name}"))?;
        let pair = (pkg_id, core_id);
        if !pairs.contains(&pair) {
            pairs.push(pair);
        }
    }
    if logical == 0 {
        return Err("no cpuN topology dirs found".into());
    }
    Ok((pairs.len() as u32, logical))
}

/// Turbo state: `intel_pstate/no_turbo` (1 => disabled) takes precedence, else
/// `cpufreq/boost` (0 => disabled). Neither present => REFUSE (undeterminable).
fn read_turbo_enabled(root: &Path) -> Result<bool, String> {
    let no_turbo = root.join("sys/devices/system/cpu/intel_pstate/no_turbo");
    if no_turbo.exists() {
        return match read_trimmed(&no_turbo)?.as_str() {
            "1" => Ok(false),
            "0" => Ok(true),
            other => Err(format!("unexpected intel_pstate/no_turbo value: {other}")),
        };
    }
    let boost = root.join("sys/devices/system/cpu/cpufreq/boost");
    if boost.exists() {
        return match read_trimmed(&boost)?.as_str() {
            "0" => Ok(false),
            "1" => Ok(true),
            other => Err(format!("unexpected cpufreq/boost value: {other}")),
        };
    }
    Err("cannot determine turbo state (no intel_pstate/no_turbo nor cpufreq/boost); refusing to assume".into())
}

/// Governor read from every `cpuN/cpufreq/scaling_governor`; must be present and
/// UNIFORM across all CPUs, else refuse (a mixed governor is not a measurable state).
fn read_uniform_governor(root: &Path) -> Result<String, String> {
    let base = root.join("sys/devices/system/cpu");
    let mut governor: Option<String> = None;
    let entries = std::fs::read_dir(&base).map_err(|e| format!("read {}: {e}", base.display()))?;
    let mut seen = 0u32;
    for ent in entries {
        let ent = ent.map_err(|e| e.to_string())?;
        let name = ent.file_name().to_string_lossy().to_string();
        let is_cpu = name
            .strip_prefix("cpu")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !is_cpu {
            continue;
        }
        let g = read_trimmed(&ent.path().join("cpufreq/scaling_governor"))
            .map_err(|_| format!("missing cpufreq/scaling_governor for {name}"))?;
        seen += 1;
        match &governor {
            None => governor = Some(g),
            Some(prev) if *prev != g => return Err(format!("non-uniform governor: {prev} vs {g}")),
            _ => {}
        }
    }
    if seen == 0 {
        return Err("no per-cpu scaling_governor found".into());
    }
    governor.ok_or_else(|| "governor unset".into())
}

/// The process's own cgroup path (v2 line `0::<path>`, or the first v1 line's path).
fn read_cgroup_scope(root: &Path) -> Result<String, String> {
    let text = read_trimmed_at(root, "proc/self/cgroup")?;
    // Prefer the unified v2 line "0::/path".
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(rest.trim().to_string());
        }
    }
    // v1: "<hier>:<controllers>:/path" — take the first entry's path.
    if let Some(first) = text.lines().next() {
        let parts: Vec<&str> = first.splitn(3, ':').collect();
        if parts.len() == 3 && !parts[2].is_empty() {
            return Ok(parts[2].trim().to_string());
        }
    }
    Err(format!(
        "cannot parse cgroup scope from proc/self/cgroup: {text:?}"
    ))
}

/// cgroup dir for the process under `/sys/fs/cgroup` (+ scope for v2).
fn cgroup_dir(root: &Path, version: u8, scope: &str, v1_controller: &str) -> PathBuf {
    let base = root.join("sys/fs/cgroup");
    if version == 2 {
        base.join(scope.trim_start_matches('/'))
    } else {
        base.join(v1_controller).join(scope.trim_start_matches('/'))
    }
}

fn read_memory_limit(root: &Path, version: u8, scope: &str, total_ram: u64) -> Result<u64, String> {
    if version == 2 {
        let p = cgroup_dir(root, 2, scope, "").join("memory.max");
        let v = read_trimmed(&p)?;
        if v == "max" {
            return Ok(total_ram);
        }
        v.parse::<u64>().map_err(|_| format!("bad memory.max: {v}"))
    } else {
        let p = cgroup_dir(root, 1, scope, "memory").join("memory.limit_in_bytes");
        let v = read_trimmed(&p)?;
        let n: u64 = v
            .parse()
            .map_err(|_| format!("bad memory.limit_in_bytes: {v}"))?;
        // v1 encodes "unlimited" as a near-u64::MAX sentinel; clamp to real RAM.
        Ok(if n >= (u64::MAX / 4096) * 4096 || n > total_ram {
            total_ram
        } else {
            n
        })
    }
}

/// The effective-cpuset file name for a cgroup version (v2 exposes the kernel-computed
/// `cpuset.cpus.effective`; v1 exposes `cpuset.cpus` under the cpuset controller mount).
fn cpuset_effective_file(version: u8) -> &'static str {
    if version == 2 {
        "cpuset.cpus.effective"
    } else {
        "cpuset.cpus"
    }
}

/// The CANONICAL ancestor chain of a cgroup scope path, NEAREST-FIRST: the leaf itself, then each
/// parent, down to the hierarchy root `/`. Refuses a non-canonical path (`.`/`..` component) so a
/// crafted scope can never traverse out of the cgroup root.
fn cgroup_ancestor_chain(scope: &str) -> Result<Vec<String>, String> {
    if !scope.starts_with('/') {
        return Err(format!("cgroup scope is not absolute: {scope:?}"));
    }
    let mut comps: Vec<&str> = Vec::new();
    for c in scope.split('/') {
        if c.is_empty() {
            continue; // leading / trailing / doubled slash
        }
        if c == "." || c == ".." {
            return Err(format!("non-canonical cgroup scope component in {scope:?}"));
        }
        comps.push(c);
    }
    let mut chain = Vec::with_capacity(comps.len() + 1);
    for i in (0..=comps.len()).rev() {
        chain.push(if i == 0 {
            "/".to_string()
        } else {
            format!("/{}", comps[..i].join("/"))
        });
    }
    Ok(chain)
}

/// True iff `ancestor` is the same cgroup as `leaf` or a canonical ancestor of it. Both are
/// cgroup-root-relative absolute paths (`/`, `/user.slice`, `/user.slice/session.scope`). This is
/// the exact relationship the eligibility check (validator + independent verifier) recomputes.
pub fn cgroup_path_is_ancestor_or_self(ancestor: &str, leaf: &str) -> bool {
    if ancestor == leaf || ancestor == "/" {
        return true;
    }
    matches!(leaf.strip_prefix(ancestor), Some(rest) if rest.starts_with('/'))
}

/// The RETAINED `cpuset.cpus.effective` state at one probed cgroup. Only these three states are ever
/// retained (they are the states that allow ascent or select a source). A read error, a malformed
/// value, a symlink, or a non-regular/ambiguous file is NEVER retained — it fails the resolution
/// immediately (a read error is not an inheritable "absence").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CpusetState {
    /// The effective-cpuset file does not exist at this cgroup (the leaf tmux-scope case) — ascend.
    Absent,
    /// The file exists and is empty — ascend.
    ReadableEmpty,
    /// The file exists and holds a nonempty, canonically-valid CPU set — the selected source.
    ReadableNonempty,
}

/// One complete authenticated observation of the effective-cpuset file at a cgroup: its state, raw
/// bytes (when readable), and the file-identity stat facts needed to detect replacement between the
/// two reads of a single entry. `read_error_class` is only ever set on the failure diagnostic (a
/// read error fails immediately), so it is `None` in every RETAINED observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpusetObservation {
    pub state: CpusetState,
    pub raw: Option<String>,
    /// "absent" | "regular" | "symlink" | "other".
    pub file_type: String,
    pub is_symlink: bool,
    pub dev: Option<u64>,
    pub inode: Option<u64>,
    pub size: Option<u64>,
    pub mtime_secs: Option<i64>,
    pub mtime_nanos: Option<i64>,
    pub read_error_class: Option<String>,
}

/// One entry of the canonical nearest-first probe chain. Retains TWO complete observations that MUST
/// be equal — detecting the leaf or an ancestor changing state during resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpusetProbeEntry {
    /// Canonical cgroup-root-relative path of this probed cgroup (never a host-absolute path).
    pub cgroup_path: String,
    /// Position in the ancestor chain: 0 = the process leaf, 1 = its immediate parent, ...
    pub order: u32,
    pub first: CpusetObservation,
    pub second: CpusetObservation,
}

/// A resolved effective cpuset bound to exactly where it was read, plus the canonical probe chain.
struct CpusetResolution {
    count: u32,
    source_cgroup_path: String,
    raw: String,
    inherited: bool,
    probe_chain: Vec<CpusetProbeEntry>,
}

/// Take ONE complete observation of the effective-cpuset file at a cgroup. Fail-closed (never a
/// retained observation) on: a stat error other than not-found, a symlink, a non-regular file, a
/// read error (permission/I/O), or a malformed nonempty CPU set. Absent and readable-empty are
/// benign (ascendable) states; a canonically-valid nonempty set is a source.
fn observe_cpuset(root: &Path, version: u8, cg: &str) -> Result<CpusetObservation, String> {
    use std::os::unix::fs::MetadataExt;
    let v1_controller = if version == 2 { "" } else { "cpuset" };
    let path = cgroup_dir(root, version, cg, v1_controller).join(cpuset_effective_file(version));
    let mut o = CpusetObservation {
        state: CpusetState::Absent,
        raw: None,
        file_type: "absent".to_string(),
        is_symlink: false,
        dev: None,
        inode: None,
        size: None,
        mtime_secs: None,
        mtime_nanos: None,
        read_error_class: None,
    };
    let lmeta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(o), // absent -> ascendable
        Err(e) => {
            return Err(format!(
                "cpuset stat error at {} ({:?})",
                path.display(),
                e.kind()
            ))
        }
    };
    let ft = lmeta.file_type();
    o.dev = Some(lmeta.dev());
    o.inode = Some(lmeta.ino());
    o.size = Some(lmeta.size());
    o.mtime_secs = Some(lmeta.mtime());
    o.mtime_nanos = Some(lmeta.mtime_nsec());
    if ft.is_symlink() {
        o.is_symlink = true;
        o.file_type = "symlink".to_string();
        return Err(format!(
            "cpuset source is a symlink (refused): {}",
            path.display()
        ));
    }
    if !ft.is_file() {
        o.file_type = "other".to_string();
        return Err(format!(
            "cpuset source is not a regular file (ambiguous, refused): {}",
            path.display()
        ));
    }
    o.file_type = "regular".to_string();
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let t = s.trim();
            if t.is_empty() {
                o.state = CpusetState::ReadableEmpty;
                o.raw = Some(String::new());
            } else {
                // A malformed / invalid CPU syntax FAILS immediately (never ascend past it).
                count_cpu_list(t)?;
                o.state = CpusetState::ReadableNonempty;
                o.raw = Some(t.to_string());
            }
        }
        // A read error is NOT an inheritable absence — fail immediately.
        Err(e) => {
            return Err(format!(
                "cpuset read error at {} ({:?})",
                path.display(),
                e.kind()
            ))
        }
    }
    Ok(o)
}

/// Probe one cgroup with TWO complete observations and require they are equal (state + raw + file
/// identity), detecting a replacement / state change during resolution.
fn probe_cpuset_entry(
    root: &Path,
    version: u8,
    cg: &str,
    order: u32,
) -> Result<CpusetProbeEntry, String> {
    let first = observe_cpuset(root, version, cg)?;
    let second = observe_cpuset(root, version, cg)?;
    if first != second {
        return Err(format!(
            "cpuset observation at {cg:?} changed between reads (first != second)"
        ));
    }
    Ok(CpusetProbeEntry {
        cgroup_path: cg.to_string(),
        order,
        first,
        second,
    })
}

/// Resolve the effective cpuset for the process leaf cgroup, building the CANONICAL nearest-first
/// probe chain (the live reader verifies live ancestry + observations; the producer binds the
/// retained evidence). Read the leaf first; if it does not expose a readable nonempty effective
/// cpuset (the x86 systemd case, where the leaf tmux scope lacks the cpuset controller), walk ONLY
/// the canonical ancestor chain and take the NEAREST cgroup with a stable readable-nonempty valid CPU
/// set. Entries before the source are stable-absent or stable-readable-empty only; the chain stops
/// AT the source (no entries after it). Never search siblings; never default to all host CPUs.
fn resolve_cpuset(root: &Path, version: u8, leaf_scope: &str) -> Result<CpusetResolution, String> {
    let file = cpuset_effective_file(version);
    let chain = cgroup_ancestor_chain(leaf_scope)?;
    let mut probe_chain: Vec<CpusetProbeEntry> = Vec::new();
    for (idx, cg) in chain.iter().enumerate() {
        let entry = probe_cpuset_entry(root, version, cg, idx as u32)?;
        match entry.first.state {
            CpusetState::ReadableNonempty => {
                // The FIRST readable-nonempty entry is the selected source; the chain stops here.
                let raw = entry.first.raw.clone().expect("nonempty carries raw");
                let count = count_cpu_list(&raw)?;
                probe_chain.push(entry);
                return Ok(CpusetResolution {
                    count,
                    source_cgroup_path: cg.clone(),
                    raw,
                    inherited: idx != 0, // idx 0 is the leaf; anything above it is inherited
                    probe_chain,
                });
            }
            // Stable absent / readable-empty -> record and ascend. (Errors already failed above.)
            CpusetState::Absent | CpusetState::ReadableEmpty => probe_chain.push(entry),
        }
    }
    Err(format!(
        "no cgroup in the canonical ancestor chain of {leaf_scope:?} exposes a readable nonempty {file}"
    ))
}

/// Read every host fact from `root`. Fail-closed on any unreadable/ambiguous source.
pub fn read_host_facts(root: &Path) -> Result<HostFacts, String> {
    let host_os = read_trimmed_at(root, "proc/sys/kernel/ostype")?;
    let kernel = read_trimmed_at(root, "proc/sys/kernel/osrelease")?;

    let cpuinfo = read_trimmed_at(root, "proc/cpuinfo")?;
    let (cpu_vendor, cpu_model) = parse_cpuinfo_identity(&cpuinfo)?;
    let (physical_core_count, logical_cpu_count) = read_core_counts(root)?;

    let meminfo = std::fs::read_to_string(root.join("proc/meminfo"))
        .map_err(|e| format!("read proc/meminfo: {e}"))?;
    let total_ram_bytes = parse_meminfo_total_bytes(&meminfo)?;

    let dvfs = read_dvfs_state(root)?;
    let clock_source = read_trimmed_at(
        root,
        "sys/devices/system/clocksource/clocksource0/current_clocksource",
    )?;

    let cgroup_version = if root.join("sys/fs/cgroup/cgroup.controllers").exists() {
        2
    } else {
        1
    };
    let cgroup_scope_label = read_cgroup_scope(root)?;
    // The leaf scope must be canonical (no `.`/`..` component) BEFORE any cgroup path is joined, so
    // neither the memory nor the cpuset resolution can traverse out of the cgroup root.
    cgroup_ancestor_chain(&cgroup_scope_label)?;
    let configured_memory_limit_bytes =
        read_memory_limit(root, cgroup_version, &cgroup_scope_label, total_ram_bytes)?;
    // Resolve the effective cpuset with inheritance: leaf-observed when the process leaf exposes it,
    // else the nearest canonical ancestor. Bind the source path + raw + inherited flag so eligibility
    // can independently recompute the count and verify the ancestor relationship.
    let cpuset = resolve_cpuset(root, cgroup_version, &cgroup_scope_label)?;
    // Defence in depth: the recorded source must be a real ancestor of (or equal to) the leaf.
    if !cgroup_path_is_ancestor_or_self(&cpuset.source_cgroup_path, &cgroup_scope_label) {
        return Err(format!(
            "resolved cpuset source {:?} is not an ancestor of the process leaf {:?}",
            cpuset.source_cgroup_path, cgroup_scope_label
        ));
    }

    Ok(HostFacts {
        host_os,
        kernel,
        cpu_vendor,
        cpu_model,
        physical_core_count,
        logical_cpu_count,
        total_ram_bytes,
        configured_cpuset_core_limit: cpuset.count,
        cpuset_source_cgroup_path: cpuset.source_cgroup_path,
        cpuset_raw: cpuset.raw,
        cpuset_inherited: cpuset.inherited,
        cpuset_probe_chain: cpuset.probe_chain,
        configured_memory_limit_bytes,
        dvfs,
        clock_source,
        cgroup_version,
        cgroup_scope_label,
    })
}

// ============================ DVFS provenance state (turbo/governor) ============================
//
// Two SEMANTICALLY-DISTINCT states. `Observable` is the ORDINARY state: the standard turbo +
// per-CPU governor control surfaces are present and read directly (an OBSERVED DVFS, e.g. turbo
// disabled + performance governor). `HypervisorManagedUnobservable` is a DISTINCT state — NEVER
// encoded as `turbo=false` / `performance` — for a host that exposes NO DVFS control surface at
// all because a hypervisor owns DVFS (observed only on native aarch64 under the ratified
// Microsoft/Azure venue). It carries STRUCTURED evidence positively proving that case. A
// partially-observable or contradictory host is REFUSED (fail closed), never mapped into either
// state.

/// A lowercase-hex encoding of bytes (bare, no prefix).
fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DvfsState {
    /// The ordinary, directly-observed DVFS state (turbo + uniform governor read from sysfs).
    Observable {
        turbo_enabled: bool,
        governor: String,
    },
    /// DVFS is owned by the hypervisor and NO control surface is observable (native aarch64 +
    /// Microsoft venue). Carries structured proof; never means `turbo=false`/`performance`.
    HypervisorManagedUnobservable(HypervisorManagedDvfsEvidence),
}

/// STRUCTURED (never free-form) evidence for [`DvfsState::HypervisorManagedUnobservable`]. Every
/// field is a positively-recorded observation used for eligibility; `raw_evidence_blake3` binds
/// ALL of them so the eligibility decision is over exactly the recorded observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypervisorManagedDvfsEvidence {
    /// The native CPU architecture PROVEN from `/proc/cpuinfo` (never the caller's `--arch`).
    pub cpu_arch: String,
    /// The `/proc/cpuinfo` CPU implementer/part identity that proves the arch.
    pub cpu_identity: String,
    /// The positively-observed virtualization vendor (must be `microsoft`).
    pub virtualization: String,
    /// Where the virtualization vendor was observed (`path=value`).
    pub virtualization_source: String,
    /// Each DVFS control surface CONFIRMED ABSENT (sorted, exact repo-relative sysfs paths).
    pub absent_controls: Vec<String>,
    /// `BLAKE3(domain ‖ canonical(all fields above))` — binds every observation used for eligibility.
    pub raw_evidence_blake3: String,
}

/// Positively observe Microsoft (Azure) virtualization via DMI. Returns `(vendor, source)` only
/// when the DMI system vendor is exactly `Microsoft Corporation`.
fn microsoft_virtualization(root: &Path) -> Option<(String, String)> {
    let v = read_trimmed_at(root, "sys/class/dmi/id/sys_vendor")
        .ok()
        .filter(|s| !s.is_empty())?;
    if v == "Microsoft Corporation" {
        Some((
            "microsoft".to_string(),
            format!("/sys/class/dmi/id/sys_vendor={v}"),
        ))
    } else {
        None
    }
}

/// Prove native aarch64 from `/proc/cpuinfo`: ARM exposes `CPU implementer` + `CPU part` and NO
/// x86 `vendor_id` / `model name`. Returns the identity string, or `None` if not provably aarch64.
fn native_aarch64_identity(root: &Path) -> Option<String> {
    let text = read_trimmed_at(root, "proc/cpuinfo").ok()?;
    let field = |k: &str| -> Option<String> {
        text.lines().find_map(|l| {
            l.split_once(':')
                .and_then(|(a, b)| (a.trim() == k).then(|| b.trim().to_string()))
        })
    };
    // x86 markers disqualify (must be UNAMBIGUOUSLY aarch64).
    if field("vendor_id").is_some() || field("model name").is_some() {
        return None;
    }
    let implementer = field("CPU implementer")?;
    let part = field("CPU part")?;
    Some(format!("CPU implementer={implementer} CPU part={part}"))
}

/// The DVFS control surfaces, partitioned into (present, absent). The host is "unobservable" ONLY
/// when EVERY surface is absent; any present surface while turbo/governor are not fully readable is
/// partial/contradictory (refused).
fn dvfs_control_surfaces(root: &Path) -> (Vec<String>, Vec<String>) {
    let base = "sys/devices/system/cpu";
    let mut present = Vec::new();
    let mut absent = Vec::new();
    let mut check = |rel: String, exists: bool| {
        if exists {
            present.push(rel);
        } else {
            absent.push(rel);
        }
    };
    check(
        format!("{base}/intel_pstate/no_turbo"),
        root.join(format!("{base}/intel_pstate/no_turbo")).exists(),
    );
    check(
        format!("{base}/cpufreq/boost"),
        root.join(format!("{base}/cpufreq/boost")).exists(),
    );
    // Any per-CPU `cpuN/cpufreq/scaling_governor`.
    let any_governor = std::fs::read_dir(root.join(base))
        .ok()
        .map(|it| {
            it.flatten().any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.strip_prefix("cpu")
                    .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
                    && e.path().join("cpufreq/scaling_governor").exists()
            })
        })
        .unwrap_or(false);
    check(
        format!("{base}/cpuN/cpufreq/scaling_governor"),
        any_governor,
    );
    // A usable cpufreq driver/control surface (cpu0's cpufreq dir).
    check(
        format!("{base}/cpu0/cpufreq"),
        root.join(format!("{base}/cpu0/cpufreq")).exists(),
    );
    (present, absent)
}

/// Determine the host DVFS provenance state, fail-closed. Fully observable → [`DvfsState::Observable`]
/// (byte-for-byte the current turbo/governor behaviour). Otherwise the ONLY accepted non-observable
/// state is [`DvfsState::HypervisorManagedUnobservable`], and ONLY when EVERY control surface is
/// absent AND the host is provably native aarch64 under positively-observed Microsoft virtualization;
/// a partially-observable / contradictory / wrong-arch / wrong-hypervisor host is refused.
pub fn read_dvfs_state(root: &Path) -> Result<DvfsState, String> {
    // Fully OBSERVABLE (ordinary): both standard controls read directly.
    if let (Ok(turbo_enabled), Ok(governor)) =
        (read_turbo_enabled(root), read_uniform_governor(root))
    {
        return Ok(DvfsState::Observable {
            turbo_enabled,
            governor,
        });
    }
    // Not fully observable. Any control surface present here means partial/contradictory evidence.
    let (present, mut absent) = dvfs_control_surfaces(root);
    if !present.is_empty() {
        return Err(format!(
            "DVFS partially observable / contradictory: control surface(s) present but turbo/governor \
             not fully readable: {present:?}; refusing (neither observable nor hypervisor-unobservable)"
        ));
    }
    // EVERY control surface is absent — the sanctioned unobservable case requires PROVEN native
    // aarch64 + POSITIVELY-observed Microsoft virtualization.
    let cpu_identity = native_aarch64_identity(root).ok_or_else(|| {
        "hypervisor-unobservable DVFS requires PROVEN native aarch64 (cpuinfo CPU implementer/part, \
         no x86 markers); refusing"
            .to_string()
    })?;
    let (virtualization, virtualization_source) =
        microsoft_virtualization(root).ok_or_else(|| {
            "hypervisor-unobservable DVFS requires POSITIVELY-observed Microsoft virtualization \
         (/sys/class/dmi/id/sys_vendor=Microsoft Corporation); refusing"
                .to_string()
        })?;
    absent.sort();
    let canonical = format!(
        "b0-final-dvfs-unobservable/v1|arch=aarch64|id={cpu_identity}|virt={virtualization}|\
         virt_src={virtualization_source}|absent={}",
        absent.join(",")
    );
    let mut h = blake3::Hasher::new();
    h.update(b"b0-final-dvfs-unobservable-evidence/v1\0");
    h.update(canonical.as_bytes());
    let raw_evidence_blake3 = hex_lower(h.finalize().as_bytes());
    Ok(DvfsState::HypervisorManagedUnobservable(
        HypervisorManagedDvfsEvidence {
            cpu_arch: "aarch64".to_string(),
            cpu_identity,
            virtualization,
            virtualization_source,
            absent_controls: absent,
            raw_evidence_blake3,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_list_counts() {
        assert_eq!(count_cpu_list("0-3").unwrap(), 4);
        assert_eq!(count_cpu_list("0-3,7,9-10").unwrap(), 7);
        assert_eq!(count_cpu_list("5").unwrap(), 1);
        assert!(count_cpu_list("").is_err());
        assert!(count_cpu_list("3-1").is_err());
        assert!(count_cpu_list("x").is_err());
    }

    #[test]
    fn meminfo_total() {
        assert_eq!(
            parse_meminfo_total_bytes("MemTotal:   32768 kB\nMemFree: 1 kB").unwrap(),
            32768 * 1024
        );
        assert!(parse_meminfo_total_bytes("MemFree: 1 kB").is_err());
    }

    #[test]
    fn cpuinfo_identity_both_arches() {
        let x86 = "processor: 0\nvendor_id: GenuineIntel\nmodel name: Xeon\n";
        assert_eq!(
            parse_cpuinfo_identity(x86).unwrap(),
            ("GenuineIntel".into(), "Xeon".into())
        );
        let arm = "processor: 0\nCPU implementer: 0x41\nCPU part: 0xd0c\n";
        assert_eq!(
            parse_cpuinfo_identity(arm).unwrap(),
            ("0x41".into(), "0xd0c".into())
        );
        assert!(parse_cpuinfo_identity("processor: 0\n").is_err());
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    fn tree(files: &[(&str, &str)]) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "b0-dvfs-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for (p, body) in files {
            let f = base.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, body).unwrap();
        }
        base
    }

    const ARM_CPUINFO: &str =
        "processor\t: 0\nBogoMIPS\t: 50.00\nCPU implementer\t: 0x41\nCPU part\t: 0xd0c\n";
    const X86_CPUINFO: &str = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Xeon\n";

    // Observable (ordinary) x86: standard controls present + read directly -> exact current behaviour.
    #[test]
    fn observable_x86_disabled_turbo_is_ordinary_state() {
        let root = tree(&[
            ("proc/cpuinfo", X86_CPUINFO),
            ("sys/devices/system/cpu/intel_pstate/no_turbo", "1\n"),
            (
                "sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                "performance\n",
            ),
        ]);
        match read_dvfs_state(&root).unwrap() {
            DvfsState::Observable {
                turbo_enabled,
                governor,
            } => {
                assert!(!turbo_enabled);
                assert_eq!(governor, "performance");
            }
            other => panic!("expected Observable, got {other:?}"),
        }
    }

    // Native aarch64 + Microsoft venue + EVERY control surface absent -> the distinct unobservable
    // state, with bound structured evidence. NEVER turbo=false/performance. Deterministic.
    #[test]
    fn azure_aarch64_all_absent_is_hypervisor_unobservable_with_bound_evidence() {
        let files: &[(&str, &str)] = &[
            ("proc/cpuinfo", ARM_CPUINFO),
            ("sys/class/dmi/id/sys_vendor", "Microsoft Corporation\n"),
        ];
        let root = tree(files);
        let st = read_dvfs_state(&root).unwrap();
        let ev = match &st {
            DvfsState::HypervisorManagedUnobservable(e) => e,
            other => panic!("expected HypervisorManagedUnobservable, got {other:?}"),
        };
        assert_eq!(ev.cpu_arch, "aarch64");
        assert_eq!(ev.virtualization, "microsoft");
        assert!(ev
            .absent_controls
            .iter()
            .any(|c| c.contains("intel_pstate/no_turbo")));
        assert!(ev
            .absent_controls
            .iter()
            .any(|c| c.contains("scaling_governor")));
        assert_eq!(ev.raw_evidence_blake3.len(), 64);
        assert!(!matches!(st, DvfsState::Observable { .. }));
        // identical observations -> identical bound evidence hash
        match read_dvfs_state(&tree(files)).unwrap() {
            DvfsState::HypervisorManagedUnobservable(e2) => {
                assert_eq!(e2.raw_evidence_blake3, ev.raw_evidence_blake3)
            }
            _ => unreachable!(),
        }
    }

    // x86 with no control surfaces is NOT the sanctioned case (must be PROVEN native aarch64).
    #[test]
    fn x86_all_absent_is_refused_not_unobservable() {
        let root = tree(&[
            ("proc/cpuinfo", X86_CPUINFO),
            ("sys/class/dmi/id/sys_vendor", "Microsoft Corporation\n"),
        ]);
        assert!(read_dvfs_state(&root).is_err());
    }

    // aarch64 with no controls but NOT Microsoft virtualization -> refused (wrong hypervisor).
    #[test]
    fn aarch64_all_absent_but_not_microsoft_is_refused() {
        let root = tree(&[
            ("proc/cpuinfo", ARM_CPUINFO),
            ("sys/class/dmi/id/sys_vendor", "QEMU\n"),
        ]);
        assert!(read_dvfs_state(&root).is_err());
        // and with NO dmi vendor at all
        let root2 = tree(&[("proc/cpuinfo", ARM_CPUINFO)]);
        assert!(read_dvfs_state(&root2).is_err());
    }

    // aarch64 + Microsoft but a PARTIAL control surface present -> contradictory -> refused.
    #[test]
    fn aarch64_microsoft_but_partial_control_present_is_refused() {
        let boost = tree(&[
            ("proc/cpuinfo", ARM_CPUINFO),
            ("sys/class/dmi/id/sys_vendor", "Microsoft Corporation\n"),
            ("sys/devices/system/cpu/cpufreq/boost", "1\n"),
        ]);
        assert!(read_dvfs_state(&boost).is_err());
        let gov = tree(&[
            ("proc/cpuinfo", ARM_CPUINFO),
            ("sys/class/dmi/id/sys_vendor", "Microsoft Corporation\n"),
            (
                "sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                "performance\n",
            ),
        ]);
        assert!(read_dvfs_state(&gov).is_err());
    }
}

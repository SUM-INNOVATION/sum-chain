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

use serde::{Deserialize, Serialize};

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
    pub configured_cpuset_core_limit: u32,
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

fn read_cpuset_limit(root: &Path, version: u8, scope: &str, logical: u32) -> Result<u32, String> {
    let path = if version == 2 {
        cgroup_dir(root, 2, scope, "").join("cpuset.cpus.effective")
    } else {
        cgroup_dir(root, 1, scope, "cpuset").join("cpuset.cpus")
    };
    match read_trimmed(&path) {
        Ok(s) if !s.is_empty() => count_cpu_list(&s),
        // An empty v2 cpuset.cpus.effective is only valid when it means "inherit all";
        // a MISSING file is a refusal, not "all".
        Ok(_) if version == 2 => Ok(logical),
        Ok(_) => Err(format!("empty cpuset at {}", path.display())),
        Err(e) => Err(e),
    }
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
    let configured_memory_limit_bytes =
        read_memory_limit(root, cgroup_version, &cgroup_scope_label, total_ram_bytes)?;
    let configured_cpuset_core_limit =
        read_cpuset_limit(root, cgroup_version, &cgroup_scope_label, logical_cpu_count)?;

    Ok(HostFacts {
        host_os,
        kernel,
        cpu_vendor,
        cpu_model,
        physical_core_count,
        logical_cpu_count,
        total_ram_bytes,
        configured_cpuset_core_limit,
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

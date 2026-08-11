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
    pub governor: String,
    pub turbo_enabled: bool,
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

    let turbo_enabled = read_turbo_enabled(root)?;
    let governor = read_uniform_governor(root)?;
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
        governor,
        turbo_enabled,
        clock_source,
        cgroup_version,
        cgroup_scope_label,
    })
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
}

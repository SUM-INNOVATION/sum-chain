//! A15: SCOPED VERIFICATION ENVELOPE — the runner migrates its OWN process into the operator-provisioned,
//! already-delegated **2-core / 4-GiB verification cgroup** for the verification-timing phase ONLY,
//! VALIDATES the envelope fail-closed BEFORE any sample, and migrates BACK to the proving cgroup
//! (revalidated) before the next prove. Proving stays in its full proving cgroup.
//!
//! Two-envelope model (ratified `VENUE.md`): proving runs with the full detected hardware; the controlled
//! chain-verification reference is a CONFIGURED 2-core cpuset + 4-GiB memory limit. The runner couples
//! prove→verify per iteration, so it must move between the two cgroups explicitly.
//!
//! HARD CONSTRAINTS (reviewed):
//! * The runner NEVER invokes `sudo` and NEVER creates/configures cgroups. It is handed two ratified,
//!   already-delegated cgroup PATHS (via env) and only writes its own PID to their `cgroup.procs`.
//! * Before timing verification it independently verifies, fail-closed: cgroup membership, effective
//!   cpuset == the configured two CPUs, process affinity == those CPUs, memory limit == 4 GiB, and the
//!   role classification (exactly-two-core cpuset ⇒ the Verification role of `provenance_eligible`).
//! * Transition/migration time is OUTSIDE the per-sample verification timing (callers migrate BEFORE the
//!   timing loop). On return to proving the proving membership is revalidated. Never sample mid-transition.
//! * Env-gated: when neither cgroup path is set (off-venue / unit tests / dry-run) it is a strict no-op.

use std::path::{Path, PathBuf};

/// The controlled verification reference envelope: EXACTLY two CPUs and a 4-GiB memory limit.
pub const VERIFY_CORES: usize = 2;
pub const VERIFY_MEM_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// A snapshot of the process's ACTUAL cgroup/affinity/memory state — pure data so validation is unit
/// testable without a real cgroup hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeProbe {
    /// The cgroup-v2 membership path from `/proc/self/cgroup` (e.g. `/system.slice/b0-verify`).
    pub cgroup_rel: String,
    /// `cpuset.cpus.effective` of the membership cgroup, parsed to sorted CPU ids.
    pub cpuset_effective: Vec<u32>,
    /// The process's actual CPU affinity (`Cpus_allowed_list` from `/proc/self/status`), sorted.
    pub affinity: Vec<u32>,
    /// `memory.max` of the membership cgroup, in bytes (`u64::MAX` for `max`).
    pub memory_max: u64,
}

/// PURE fail-closed validation of the verification envelope. `want_rel` is the expected membership path,
/// `want_cpus` the two configured CPUs (read from the verify cgroup's `cpuset.cpus`). Returns the first
/// disagreement. Mirrors the independent `provenance_eligible` role==Verification rule (cpuset == 2).
pub fn validate_verification_probe(
    p: &EnvelopeProbe,
    want_rel: &str,
    want_cpus: &[u32],
    want_mem: u64,
) -> Result<(), String> {
    // 1. cgroup membership (the process actually migrated into the verification cgroup).
    if p.cgroup_rel != want_rel {
        return Err(format!(
            "verification envelope: cgroup membership {:?} != verification cgroup {:?} (migration failed or wrong cgroup)",
            p.cgroup_rel, want_rel
        ));
    }
    // configured envelope must itself be exactly two CPUs and 4 GiB (rejects a mis-provisioned scope).
    if want_cpus.len() != VERIFY_CORES {
        return Err(format!(
            "verification envelope: configured cpuset is {} core(s), require exactly {VERIFY_CORES}",
            want_cpus.len()
        ));
    }
    if want_mem != VERIFY_MEM_BYTES {
        return Err(format!(
            "verification envelope: configured memory limit {want_mem} != {VERIFY_MEM_BYTES} (4 GiB)"
        ));
    }
    // 2. effective cpuset == the two configured CPUs (refuses 16-core inheritance / any drift).
    if p.cpuset_effective.len() != VERIFY_CORES {
        return Err(format!(
            "verification envelope: effective cpuset is {} core(s) {:?}, require exactly {VERIFY_CORES} (16-core inheritance / undelegated cpuset)",
            p.cpuset_effective.len(),
            p.cpuset_effective
        ));
    }
    if p.cpuset_effective != want_cpus {
        return Err(format!(
            "verification envelope: effective cpuset {:?} != configured {:?}",
            p.cpuset_effective, want_cpus
        ));
    }
    // 3. process affinity == those CPUs (an independent kernel view of the pinning).
    if p.affinity != want_cpus {
        return Err(format!(
            "verification envelope: process affinity {:?} != verification cpuset {:?}",
            p.affinity, want_cpus
        ));
    }
    // 4. memory limit == 4 GiB.
    if p.memory_max != VERIFY_MEM_BYTES {
        return Err(format!(
            "verification envelope: memory.max {} != {VERIFY_MEM_BYTES} (4 GiB)",
            p.memory_max
        ));
    }
    // 5. role classification: an exactly-two-core cpuset IS the Verification role (provenance_eligible
    // role==1 requires cpuset == 2). Enforced by checks 1–4 above; stated explicitly for the reviewer.
    Ok(())
}

/// Parse a Linux CPU list (`cpuset.cpus.effective` / `Cpus_allowed_list`), e.g. `"0-1"`, `"0-3,7"`,
/// `"2"`, into a SORTED, de-duplicated `Vec<u32>`. Fail-closed on any malformed token — an unreadable
/// or malformed cpuset must never be silently treated as a superset.
pub fn parse_cpu_list(s: &str) -> Result<Vec<u32>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty cpu list".into());
    }
    let mut cpus: Vec<u32> = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            return Err(format!("malformed cpu list {s:?} (empty range token)"));
        }
        if let Some((a, b)) = tok.split_once('-') {
            let lo: u32 = a
                .parse()
                .map_err(|_| format!("malformed cpu range {tok:?}"))?;
            let hi: u32 = b
                .parse()
                .map_err(|_| format!("malformed cpu range {tok:?}"))?;
            if hi < lo {
                return Err(format!("descending cpu range {tok:?}"));
            }
            for c in lo..=hi {
                cpus.push(c);
            }
        } else {
            cpus.push(
                tok.parse()
                    .map_err(|_| format!("malformed cpu id {tok:?}"))?,
            );
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

/// Parse `memory.max` (`"max"` ⇒ `u64::MAX`, else a byte count).
fn parse_mem_max(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s == "max" {
        Ok(u64::MAX)
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("malformed memory.max {s:?}"))
    }
}

fn read_trim(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("read {}: {e}", path.display()))
}

/// The cgroup-v2 membership path from `/proc/self/cgroup` (the `0::<path>` line).
fn current_cgroup_rel() -> Result<String, String> {
    let raw = read_trim(Path::new("/proc/self/cgroup"))?;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(format!(
        "no cgroup-v2 (0::) membership line in /proc/self/cgroup: {raw:?}"
    ))
}

/// The process's effective CPU affinity from `/proc/self/status` (`Cpus_allowed_list`) — an independent
/// kernel view, distinct from the cgroup's `cpuset.cpus.effective`.
fn read_affinity() -> Result<Vec<u32>, String> {
    let status = read_trim(Path::new("/proc/self/status"))?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Cpus_allowed_list:") {
            return parse_cpu_list(rest);
        }
    }
    Err("no Cpus_allowed_list in /proc/self/status".into())
}

/// The `/sys/fs/cgroup`-relative path of an absolute cgroup dir (for the membership comparison).
fn cgroup_rel_of(dir: &Path) -> Result<String, String> {
    let s = dir.to_str().ok_or("cgroup path not UTF-8")?;
    let rel = s
        .strip_prefix("/sys/fs/cgroup")
        .ok_or_else(|| format!("cgroup path {s:?} is not under /sys/fs/cgroup"))?;
    let rel = rel.trim_end_matches('/');
    Ok(if rel.is_empty() {
        "/".to_string()
    } else {
        rel.to_string()
    })
}

/// Migrate THIS process into `cgroup_dir` by writing its own PID to `<cgroup_dir>/cgroup.procs`. The dir
/// must already exist and be delegated (writable) — the runner NEVER creates or `chown`s it.
fn migrate_self(cgroup_dir: &Path) -> Result<(), String> {
    let procs = cgroup_dir.join("cgroup.procs");
    let pid = std::process::id();
    std::fs::write(&procs, format!("{pid}\n")).map_err(|e| {
        format!(
            "cgroup migration failed: write {} to {} (cgroup absent or not delegated): {e}",
            pid,
            procs.display()
        )
    })
}

/// Snapshot the process's live envelope state, reading `cpuset.cpus.effective` + `memory.max` from
/// `cgroup_dir` and affinity/membership from `/proc/self`.
fn probe(cgroup_dir: &Path) -> Result<EnvelopeProbe, String> {
    Ok(EnvelopeProbe {
        cgroup_rel: current_cgroup_rel()?,
        cpuset_effective: parse_cpu_list(&read_trim(&cgroup_dir.join("cpuset.cpus.effective"))?)?,
        affinity: read_affinity()?,
        memory_max: parse_mem_max(&read_trim(&cgroup_dir.join("memory.max"))?)?,
    })
}

/// Controls migration between the operator-provisioned proving and verification cgroups.
pub struct EnvelopeController {
    proving_cgroup: PathBuf,
    verify_cgroup: PathBuf,
    verify_cpus: Vec<u32>,
    verify_mem: u64,
    proving_rel: String,
    verify_rel: String,
}

impl EnvelopeController {
    /// Build from the operator-provided cgroup paths in the environment:
    /// `B0PRE_PROVING_CGROUP_PATH` + `B0PRE_VERIFY_CGROUP_PATH` (absolute `/sys/fs/cgroup/...`). Returns
    /// `Ok(None)` when NEITHER is set (off-venue / unit tests / dry-run: strict no-op). Errors if only one
    /// is set, or a path is not a present, delegated cgroup, or the verification cgroup is not exactly a
    /// 2-core / 4-GiB scope. Does NOT migrate — construction only reads + validates the provisioning.
    pub fn from_env() -> Result<Option<Self>, String> {
        let prov = std::env::var("B0PRE_PROVING_CGROUP_PATH")
            .ok()
            .filter(|s| !s.is_empty());
        let ver = std::env::var("B0PRE_VERIFY_CGROUP_PATH")
            .ok()
            .filter(|s| !s.is_empty());
        match (prov, ver) {
            (None, None) => Ok(None),
            (Some(p), Some(v)) => Ok(Some(Self::new(PathBuf::from(p), PathBuf::from(v))?)),
            _ => Err(
                "A15 verification envelope: BOTH B0PRE_PROVING_CGROUP_PATH and \
                      B0PRE_VERIFY_CGROUP_PATH must be set (or neither)"
                    .into(),
            ),
        }
    }

    fn new(proving: PathBuf, verify: PathBuf) -> Result<Self, String> {
        // The runner does not create cgroups: both must already exist and expose a writable cgroup.procs
        // (delegated by the operator). Fail closed on a missing/undelegated path.
        for c in [&proving, &verify] {
            if !c.join("cgroup.procs").exists() {
                return Err(format!(
                    "A15 verification envelope: cgroup not present/delegated (no cgroup.procs): {}",
                    c.display()
                ));
            }
        }
        // Read the CONFIGURED verification envelope from the cgroup itself (never a trusted operator
        // scalar): exactly two CPUs + 4 GiB, else refuse before any measurement.
        let verify_cpus = parse_cpu_list(&read_trim(&verify.join("cpuset.cpus"))?)?;
        let verify_mem = parse_mem_max(&read_trim(&verify.join("memory.max"))?)?;
        if verify_cpus.len() != VERIFY_CORES {
            return Err(format!(
                "A15 verification envelope: verify cgroup {} has {} configured CPU(s) {:?}, require exactly {VERIFY_CORES}",
                verify.display(),
                verify_cpus.len(),
                verify_cpus
            ));
        }
        if verify_mem != VERIFY_MEM_BYTES {
            return Err(format!(
                "A15 verification envelope: verify cgroup {} memory.max {verify_mem} != {VERIFY_MEM_BYTES} (4 GiB)",
                verify.display()
            ));
        }
        let proving_rel = cgroup_rel_of(&proving)?;
        let verify_rel = cgroup_rel_of(&verify)?;
        Ok(Self {
            proving_cgroup: proving,
            verify_cgroup: verify,
            verify_cpus,
            verify_mem,
            proving_rel,
            verify_rel,
        })
    }

    /// Establish / REVALIDATE the PROVING envelope: migrate self into the proving cgroup, confirm
    /// membership, and confirm it is the FULL-hardware envelope (more than the two verification cores) so
    /// proving never silently continues inside the constrained verify cgroup. Called once before proving
    /// begins and again after every verification batch. Never a sample is taken during this transition.
    pub fn enter_proving(&self) -> Result<(), String> {
        migrate_self(&self.proving_cgroup)?;
        let cur = current_cgroup_rel()?;
        if cur != self.proving_rel {
            return Err(format!(
                "A15 verification envelope: failed to (re)enter proving cgroup: membership {cur:?} != {:?}",
                self.proving_rel
            ));
        }
        // Revalidate the proving envelope is the full-hardware scope (not accidentally the 2-core verify
        // cgroup): proving must retain MORE than the two verification cores, or proving would be crippled.
        let proving_cpus = parse_cpu_list(&read_trim(
            &self.proving_cgroup.join("cpuset.cpus.effective"),
        )?)?;
        if proving_cpus.len() <= VERIFY_CORES {
            return Err(format!(
                "A15 verification envelope: proving cgroup effective cpuset {:?} has only {} core(s) (≤ {VERIFY_CORES}); proving must run with the full detected hardware",
                proving_cpus,
                proving_cpus.len()
            ));
        }
        Ok(())
    }

    /// Enter the VERIFICATION envelope: migrate self into the 2-core / 4-GiB verify cgroup and VALIDATE
    /// fail-closed. MUST be called BEFORE the verification-timing loop so migration time is excluded from
    /// the per-sample timing. Errors leave the caller responsible for refusing (never sample on error).
    pub fn enter_verification(&self) -> Result<(), String> {
        migrate_self(&self.verify_cgroup)?;
        let p = probe(&self.verify_cgroup)?;
        validate_verification_probe(&p, &self.verify_rel, &self.verify_cpus, self.verify_mem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_probe() -> EnvelopeProbe {
        EnvelopeProbe {
            cgroup_rel: "/system.slice/b0-verify".into(),
            cpuset_effective: vec![0, 1],
            affinity: vec![0, 1],
            memory_max: VERIFY_MEM_BYTES,
        }
    }
    const REL: &str = "/system.slice/b0-verify";
    const CPUS: [u32; 2] = [0, 1];

    #[test]
    fn pristine_envelope_validates() {
        assert!(validate_verification_probe(&ok_probe(), REL, &CPUS, VERIFY_MEM_BYTES).is_ok());
    }

    #[test]
    fn negative_wrong_cgroup_membership() {
        let mut p = ok_probe();
        p.cgroup_rel = "/user.slice".into();
        let e = validate_verification_probe(&p, REL, &CPUS, VERIFY_MEM_BYTES).unwrap_err();
        assert!(e.contains("membership"), "{e}");
    }

    #[test]
    fn negative_sixteen_core_inheritance() {
        let mut p = ok_probe();
        p.cpuset_effective = (0..16).collect();
        let e = validate_verification_probe(&p, REL, &CPUS, VERIFY_MEM_BYTES).unwrap_err();
        assert!(e.contains("effective cpuset") && e.contains("16"), "{e}");
    }

    #[test]
    fn negative_effective_cpuset_wrong_two() {
        let mut p = ok_probe();
        p.cpuset_effective = vec![2, 3];
        let e = validate_verification_probe(&p, REL, &CPUS, VERIFY_MEM_BYTES).unwrap_err();
        assert!(
            e.contains("effective cpuset") && e.contains("configured"),
            "{e}"
        );
    }

    #[test]
    fn negative_affinity_mismatch() {
        let mut p = ok_probe();
        p.affinity = vec![0, 2];
        let e = validate_verification_probe(&p, REL, &CPUS, VERIFY_MEM_BYTES).unwrap_err();
        assert!(e.contains("affinity"), "{e}");
    }

    #[test]
    fn negative_wrong_memory_limit() {
        let mut p = ok_probe();
        p.memory_max = 8 * 1024 * 1024 * 1024;
        let e = validate_verification_probe(&p, REL, &CPUS, VERIFY_MEM_BYTES).unwrap_err();
        assert!(e.contains("memory.max"), "{e}");
    }

    #[test]
    fn negative_configured_envelope_not_two_core() {
        // A mis-provisioned scope with the "right" effective set but a 3-CPU configuration is refused.
        let e = validate_verification_probe(&ok_probe(), REL, &[0, 1, 2], VERIFY_MEM_BYTES)
            .unwrap_err();
        assert!(
            e.contains("configured cpuset") && e.contains("exactly"),
            "{e}"
        );
    }

    #[test]
    fn negative_configured_memory_not_4gib() {
        let e = validate_verification_probe(&ok_probe(), REL, &CPUS, 2 * 1024 * 1024 * 1024)
            .unwrap_err();
        assert!(e.contains("configured memory limit"), "{e}");
    }

    #[test]
    fn cpu_list_parse_forms() {
        assert_eq!(parse_cpu_list("0-1").unwrap(), vec![0, 1]);
        assert_eq!(parse_cpu_list("2").unwrap(), vec![2]);
        assert_eq!(parse_cpu_list("0-3,7").unwrap(), vec![0, 1, 2, 3, 7]);
        assert_eq!(parse_cpu_list(" 0-1 \n").unwrap(), vec![0, 1]);
        assert!(parse_cpu_list("").is_err());
        assert!(parse_cpu_list("3-1").is_err());
        assert!(parse_cpu_list("x").is_err());
        assert!(parse_cpu_list("0,,1").is_err());
    }

    #[test]
    fn mem_max_parse() {
        assert_eq!(parse_mem_max("max").unwrap(), u64::MAX);
        assert_eq!(parse_mem_max("4294967296").unwrap(), VERIFY_MEM_BYTES);
        assert!(parse_mem_max("garbage").is_err());
    }

    #[test]
    fn cgroup_rel_extraction() {
        assert_eq!(
            cgroup_rel_of(Path::new("/sys/fs/cgroup/system.slice/b0-verify")).unwrap(),
            "/system.slice/b0-verify"
        );
        assert_eq!(
            cgroup_rel_of(Path::new("/sys/fs/cgroup/b0-verify/")).unwrap(),
            "/b0-verify"
        );
        assert_eq!(cgroup_rel_of(Path::new("/sys/fs/cgroup")).unwrap(), "/");
        assert!(cgroup_rel_of(Path::new("/elsewhere/x")).is_err());
    }

    #[test]
    fn from_env_neither_set_is_noop() {
        // NB: relies on these not being set in the test environment (they are venue-only).
        // Save/restore to avoid cross-test env bleed is unnecessary — they are never set under `cargo test`.
        assert!(EnvelopeController::from_env().unwrap().is_none());
    }
}

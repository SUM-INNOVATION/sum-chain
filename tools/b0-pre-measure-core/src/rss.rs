//! Peak-RSS capture, split by execution locus per the reviewer's correction:
//!
//! * **Proving** runs the heavy backend INSIDE a Docker container, so its peak memory
//!   is read from that container's dedicated cgroup (`memory.peak` v2 /
//!   `memory.max_usage_in_bytes` v1) and bound to the cgroup identity. `getrusage` on
//!   the runner would miss the container, so it is NEVER used for proving RSS.
//! * **Native verification** (RISC0 `receipt.verify`) runs in-process with no proving
//!   container, so `getrusage(RUSAGE_SELF).ru_maxrss` is the correct source there.
//!
//! Both fail closed: an unavailable cgroup peak is an error, never a substituted value.

use std::path::Path;

fn read_u64(p: &Path) -> Result<u64, String> {
    let s = std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    let s = s.trim();
    s.parse::<u64>()
        .map_err(|_| format!("{} is not a u64: {s:?}", p.display()))
}

/// The dedicated proving cgroup's identity (its path) — bound into evidence so the RSS
/// figure is attributable to exactly this cgroup.
pub fn cgroup_identity(cgroup_dir: &Path) -> String {
    cgroup_dir.to_string_lossy().into_owned()
}

/// Peak memory of the proving CONTAINER's cgroup. Fail-closed if no peak file exists —
/// the review requires this be measured from the container, not the runner.
pub fn container_peak_rss_bytes(cgroup_dir: &Path) -> Result<u64, String> {
    let v2 = cgroup_dir.join("memory.peak");
    if v2.exists() {
        return read_u64(&v2);
    }
    let v1 = cgroup_dir.join("memory.max_usage_in_bytes");
    if v1.exists() {
        return read_u64(&v1);
    }
    Err(format!(
        "proving-container cgroup peak unavailable under {} (no memory.peak / memory.max_usage_in_bytes); refusing to substitute a value",
        cgroup_dir.display()
    ))
}

/// Peak RSS of the current (native) process via `getrusage`. Correct ONLY for a native
/// verification with no proving container. Linux reports KiB, macOS/BSD report bytes.
pub fn native_peak_rss_bytes() -> Result<u64, String> {
    // SAFETY: getrusage writes a fully-initialized rusage into the zeroed struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return Err("getrusage(RUSAGE_SELF) failed".into());
    }
    let maxrss = usage.ru_maxrss as u64;
    #[cfg(target_os = "linux")]
    {
        Ok(maxrss.saturating_mul(1024))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(maxrss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(name: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!("b0rss-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }

    #[test]
    fn v2_peak_is_read() {
        let t = tmp("v2");
        std::fs::write(t.0.join("memory.peak"), "4831838208\n").unwrap();
        assert_eq!(container_peak_rss_bytes(&t.0).unwrap(), 4831838208);
    }

    #[test]
    fn v1_peak_is_read() {
        let t = tmp("v1");
        std::fs::write(t.0.join("memory.max_usage_in_bytes"), "2147483648").unwrap();
        assert_eq!(container_peak_rss_bytes(&t.0).unwrap(), 2147483648);
    }

    #[test]
    fn missing_peak_refuses_no_substitute() {
        let t = tmp("none");
        let e = container_peak_rss_bytes(&t.0).unwrap_err();
        assert!(e.contains("refusing to substitute"), "{e}");
    }

    #[test]
    fn native_rss_is_positive() {
        // Touch some memory so ru_maxrss is meaningfully nonzero.
        let v = vec![7u8; 4 * 1024 * 1024];
        assert!(native_peak_rss_bytes().unwrap() > 0);
        assert_eq!(v[0], 7);
    }
}

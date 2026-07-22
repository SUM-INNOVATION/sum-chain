//! Fail-closed durable file materialization for the Stage-1 ingest output.
//!
//! Extracted from the `stage1-ingest` binary so its fail-closed / durability
//! behavior is unit-testable: create-new temp, write + flush + fsync, atomic
//! rename, parent-directory fsync, and temp cleanup on any failure. No error is
//! ever swallowed with `.ok()`.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Durably materialize `body` at `out` via a FRESH sibling temp:
///   1. create the temp with `create_new(true)` — a stale/leftover temp is
///      REFUSED, never clobbered;
///   2. write + flush + `sync_all` the temp, removing it on ANY failure;
///   3. rename the temp onto `out` (atomic on the same filesystem), removing the
///      temp on failure;
///   4. fsync the parent directory so the rename entry itself is durable.
///
/// Every I/O error propagates (no `.ok()`), so a write reported as complete is
/// actually durable — this is never an fsync-free rename described as durable. On
/// the parent-directory fsync (step 4), a failure on a platform that SUPPORTS
/// directory fsync propagates AND the (now non-durable) `out` is removed, so no
/// path leaves a half-durable file behind; platforms that do not support directory
/// fsync take the explicit, documented [`fsync_parent_dir`] fallback instead of a
/// silently-swallowed `let _ = d.sync_all()`.
pub fn write_durably(tmp: &Path, out: &Path, body: &[u8]) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
        .map_err(|e| format!("create_new temp {} (stale temp?): {e}", tmp.display()))?;
    // write + flush + fsync the file contents; clean up the temp on failure.
    let flushed = (|| -> std::io::Result<()> {
        f.write_all(body)?;
        f.flush()?;
        f.sync_all()
    })();
    if let Err(e) = flushed {
        let _ = std::fs::remove_file(tmp);
        return Err(format!("write/flush/sync temp {}: {e}", tmp.display()));
    }
    drop(f);
    // Atomic rename into place; clean up the temp on failure.
    if let Err(e) = std::fs::rename(tmp, out) {
        let _ = std::fs::remove_file(tmp);
        return Err(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            out.display()
        ));
    }
    // Parent-directory fsync so the rename's directory entry is durable. On a
    // supported platform any error PROPAGATES (never swallowed); we then remove the
    // now-unconfirmed `out`. If that cleanup ALSO fails, the output may still exist,
    // so a COMPOUND error names both failures — an error must never claim nothing
    // remains when a non-durable `out` may still be on disk.
    if let Err(e) = fsync_parent_dir(out) {
        return Err(cleanup_unconfirmed_output(out, e));
    }
    Ok(())
}

/// After the parent-directory fsync FAILS, the just-renamed `out` is no longer
/// known to be durable, so it is removed. Returns the bare fsync error when removal
/// succeeds; otherwise returns a COMPOUND error naming BOTH the fsync failure and
/// the cleanup failure — because on a removal failure the output may still exist and
/// must never be trusted as durable. The removal error is NOT swallowed with
/// `let _ =`.
fn cleanup_unconfirmed_output(out: &Path, fsync_err: String) -> String {
    match std::fs::remove_file(out) {
        Ok(()) => fsync_err,
        Err(rm) => format!(
            "{fsync_err}; AND cleanup of the now-unconfirmed output {} also failed: {rm} \
             — the output may still exist and must NOT be trusted as durable",
            out.display()
        ),
    }
}

/// The parent directory of `out` (or `.` when `out` has no non-empty parent).
fn parent_dir(out: &Path) -> PathBuf {
    match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// fsync the parent directory so a rename entry is durable, on platforms where a
/// directory file descriptor can be fsync'd (Linux, Android, the BSDs, illumos /
/// Solaris). Every open / `sync_all` error PROPAGATES — nothing is swallowed.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "solaris",
))]
fn fsync_parent_dir(out: &Path) -> Result<(), String> {
    let dir = parent_dir(out);
    let d = std::fs::File::open(&dir)
        .map_err(|e| format!("open parent dir {} for fsync: {e}", dir.display()))?;
    d.sync_all()
        .map_err(|e| format!("fsync parent dir {}: {e}", dir.display()))?;
    Ok(())
}

/// Explicit, documented platform-specific fallback: on platforms where a directory
/// file descriptor cannot be fsync'd (e.g. macOS, where `File::sync_all` issues
/// `F_FULLFSYNC`, which is unsupported on a directory, and Windows, which has no
/// directory-fsync primitive), the rename entry's durability is left to the
/// filesystem. This is deliberately NOT a swallowed error: the code never *attempts*
/// a directory fsync it knows will fail, and the file contents themselves were
/// already strictly fsync'd in [`write_durably`] before the rename.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "solaris",
)))]
fn fsync_parent_dir(out: &Path) -> Result<(), String> {
    // No directory-fsync primitive on this platform; do not pretend otherwise.
    let _dir = parent_dir(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "b0pre-durable-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn durable_write_creates_out_with_content() {
        let dir = tmpdir();
        let out = dir.join("artifact.json");
        let tmp = dir.join("artifact.tmp.1");
        write_durably(&tmp, &out, b"hello\n").expect("durable write");
        assert_eq!(std::fs::read(&out).unwrap(), b"hello\n");
        assert!(!tmp.exists(), "temp must be gone after a successful rename");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_temp_is_refused_not_clobbered() {
        let dir = tmpdir();
        let out = dir.join("artifact.json");
        let tmp = dir.join("artifact.tmp.stale");
        // a leftover temp from a previous crashed run
        std::fs::write(&tmp, b"leftover").unwrap();
        let r = write_durably(&tmp, &out, b"new\n");
        assert!(r.is_err(), "create_new must refuse an existing temp");
        // the stale temp is left untouched (not clobbered) and no out is produced
        assert_eq!(std::fs::read(&tmp).unwrap(), b"leftover");
        assert!(!out.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cleanup_after_failed_parent_fsync_returns_bare_error_when_removal_succeeds() {
        // The parent-dir fsync failed but the now-unconfirmed `out` is removable, so
        // the reported error is exactly the fsync error (nothing remains behind).
        let dir = tmpdir();
        let out = dir.join("unconfirmed.json");
        std::fs::write(&out, b"non-durable").unwrap();
        let msg = cleanup_unconfirmed_output(&out, "fsync parent dir X: boom".into());
        assert_eq!(msg, "fsync parent dir X: boom");
        assert!(!out.exists(), "removable out must be cleaned up");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cleanup_after_failed_parent_fsync_returns_compound_error_when_removal_also_fails() {
        // The parent-dir fsync failed AND the output cannot be removed (here `out` is
        // a directory, so `remove_file` fails): the error must name BOTH failures and
        // must warn the output may still exist — never a bare fsync error implying
        // nothing remains.
        let dir = tmpdir();
        let out = dir.join("stubborn-output");
        std::fs::create_dir(&out).unwrap(); // remove_file on a dir fails
        let msg = cleanup_unconfirmed_output(&out, "fsync parent dir Y: boom".into());
        assert!(
            msg.contains("fsync parent dir Y: boom"),
            "keeps the fsync failure"
        );
        assert!(
            msg.contains("also failed"),
            "names the cleanup failure too: {msg}"
        );
        assert!(
            msg.contains("may still exist"),
            "warns the output may still exist: {msg}"
        );
        assert!(out.exists(), "the un-removable output is still present");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rename_failure_cleans_up_the_temp() {
        let dir = tmpdir();
        // out lives under a NON-existent directory, so the rename fails.
        let out = dir.join("missing-subdir").join("artifact.json");
        let tmp = dir.join("artifact.tmp.2");
        let r = write_durably(&tmp, &out, b"data\n");
        assert!(r.is_err(), "rename into a missing directory must fail");
        assert!(!tmp.exists(), "temp must be removed after a failed rename");
        assert!(!out.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}

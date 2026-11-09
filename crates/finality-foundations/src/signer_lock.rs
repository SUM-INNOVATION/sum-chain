//! Exclusive ownership of a signer directory (G2-b, ratified 2026-10-16: "the
//! signer holds an exclusive lock, so one signer process exists per key"),
//! for the store over a real directory ([`crate::signer_file::StdSignerDir`]).
//!
//! [`DirLock`] takes an advisory `flock(LOCK_EX | LOCK_NB)` on the signer
//! directory itself and holds it through an open descriptor for the guard's
//! life:
//!
//! * it adds no file: the directory holds exactly the file set adopted with
//!   B6 (owner, 2026-11-09), so no lock file is named, created or cleaned up;
//! * the kernel releases it when the holder exits, however it exits, so a
//!   killed signer never leaves a stale lock behind;
//! * it belongs to the open file description, so a second acquisition in the
//!   same process is refused exactly as one from another process is, and
//!   closing another descriptor of the directory (the store's directory
//!   fsync opens and closes one) does not release it.
//!
//! It is advisory: it excludes every holder that asks for it, and every
//! signer opened through [`DirLock`] asks. It cannot see a copy of the key
//! used from another directory or another host (the "one signer per key"
//! operating requirement, ratification packet §7). Unix only; elsewhere
//! acquisition fails, so opening and initialization fail closed.
//!
//! Dormant: no node path opens a signer.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::signer::{ExclusiveOwnership, OwnershipError};

/// The exclusive lock of one signer directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirLock {
    path: PathBuf,
}

impl DirLock {
    /// The lock of the directory at `path`. Nothing is opened until
    /// [`ExclusiveOwnership::try_acquire`].
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The locked directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Holds the directory's lock until dropped.
#[derive(Debug)]
pub struct DirLockGuard {
    _dir: File,
}

impl ExclusiveOwnership for DirLock {
    type Guard = DirLockGuard;

    /// Refuses when the directory is missing (it is never created here) or
    /// when any other guard for it is alive, in this process or another.
    fn try_acquire(&self) -> Result<DirLockGuard, OwnershipError> {
        let refuse = |why: String| {
            OwnershipError(format!(
                "cannot lock the signer directory {}: {why}",
                self.path.display()
            ))
        };
        let dir = File::open(&self.path).map_err(|e| refuse(e.to_string()))?;
        let is_dir = dir.metadata().map_err(|e| refuse(e.to_string()))?.is_dir();
        if !is_dir {
            return Err(refuse("not a directory".into()));
        }
        lock_exclusive(&dir).map_err(refuse)?;
        Ok(DirLockGuard { _dir: dir })
    }
}

#[cfg(unix)]
fn lock_exclusive(dir: &File) -> Result<(), String> {
    use rustix::fs::{flock, FlockOperation};
    use rustix::io::Errno;
    loop {
        match flock(dir, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(Errno::INTR) => {}
            // EWOULDBLOCK and EAGAIN are one value on Linux and macOS; both
            // are named in case a platform separates them.
            Err(e) if e == Errno::WOULDBLOCK || e == Errno::AGAIN => {
                return Err("another signer holds it (in another process or in this one)".into())
            }
            Err(e) => return Err(std::io::Error::from(e).to_string()),
        }
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_dir: &File) -> Result<(), String> {
    Err("directory locking is not supported on this platform".into())
}

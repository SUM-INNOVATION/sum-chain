//! Canonical, deterministic content digest of a checked-out directory tree (policy A: the
//! pinned RustSec advisory-database checkout). It is the value Stage-2 evidence records and
//! the importer re-verifies so two operators materializing the SAME pinned commit compute
//! the SAME digest and any tampering fails closed.
//!
//! Digest = `BLAKE3(ADVDB_CHECKOUT_TAG ‖ u64_le(entry_count) ‖ Σ canonical(entry))` over
//! EVERY entry under the root (a top-level `.git` directory is excluded — the digest is over
//! the working-tree CONTENT, not git metadata), sorted by relative-path bytes (bytewise /
//! C-locale). Each entry canonically encodes:
//!   * relative path (length-prefixed bytes);
//!   * type: `d` dir | `f` regular | `l` symlink;
//!   * regular files: a git-style mode (`0o644`/`0o755`, exec bit only — reproducible across
//!     umask) + BLAKE3 of the file bytes;
//!   * symlinks: the target (length-prefixed bytes);
//!   * dirs: nothing beyond the path + type.
//!
//! Fails closed on: an unsupported file type (fifo/socket/device/…); a duplicate relative
//! path; or a traversal attempt (a `..`/absolute/NUL component in any relative path, or an
//! absolute / `..`-containing symlink target). Independently reproducible: re-checkout the
//! commit, re-run — same digest.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

use crate::tags::ADVDB_CHECKOUT_TAG;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckoutDigestError {
    Io {
        path: String,
        detail: String,
    },
    /// A path component was `..`, absolute, empty, or contained a NUL (traversal / non-canonical).
    UnsafePath {
        path: String,
    },
    /// A symlink target was absolute or contained a `..` component (could escape the tree).
    UnsafeSymlinkTarget {
        path: String,
        target: String,
    },
    /// A filesystem entry was neither a regular file, a symlink, nor a directory.
    UnsupportedType {
        path: String,
    },
    /// Two entries resolved to the same relative path.
    DuplicatePath {
        path: String,
    },
    /// A symlink target was not valid UTF-8 (cannot be canonically recorded).
    NonUtf8Target {
        path: String,
    },
}

impl std::fmt::Display for CheckoutDigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckoutDigestError::Io { path, detail } => write!(f, "io error at {path:?}: {detail}"),
            CheckoutDigestError::UnsafePath { path } => {
                write!(
                    f,
                    "unsafe/non-canonical relative path (traversal): {path:?}"
                )
            }
            CheckoutDigestError::UnsafeSymlinkTarget { path, target } => write!(
                f,
                "symlink {path:?} has an unsafe target {target:?} (absolute or contains `..`)"
            ),
            CheckoutDigestError::UnsupportedType { path } => {
                write!(
                    f,
                    "unsupported file type at {path:?} (not regular/symlink/dir)"
                )
            }
            CheckoutDigestError::DuplicatePath { path } => {
                write!(f, "duplicate relative path in checkout: {path:?}")
            }
            CheckoutDigestError::NonUtf8Target { path } => {
                write!(f, "symlink target at {path:?} is not valid UTF-8")
            }
        }
    }
}

impl std::error::Error for CheckoutDigestError {}

enum EntryKind {
    Dir,
    File { git_mode: u16, content: [u8; 32] },
    Symlink { target: String },
}

/// True iff `rel` is a safe canonical relative path (no `..`, no absolute prefix, no empty
/// or NUL component). `.` (CurDir) is not expected from a walk and is rejected.
fn rel_path_is_safe(rel: &Path) -> bool {
    let mut any = false;
    for c in rel.components() {
        match c {
            Component::Normal(s) => {
                if s.is_empty() || s.to_string_lossy().contains('\0') {
                    return false;
                }
                any = true;
            }
            // RootDir/Prefix (absolute), ParentDir (`..`), CurDir (`.`) are all rejected.
            _ => return false,
        }
    }
    any
}

fn symlink_target_is_safe(target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    !target.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    })
}

fn walk(
    root: &Path,
    rel: &Path,
    out: &mut BTreeMap<Vec<u8>, EntryKind>,
) -> Result<(), CheckoutDigestError> {
    let abs = root.join(rel);
    let rd = std::fs::read_dir(&abs).map_err(|e| CheckoutDigestError::Io {
        path: abs.display().to_string(),
        detail: e.to_string(),
    })?;
    for ent in rd {
        let ent = ent.map_err(|e| CheckoutDigestError::Io {
            path: abs.display().to_string(),
            detail: e.to_string(),
        })?;
        let name = ent.file_name();
        let child_rel = rel.join(&name);
        // Exclude a top-level `.git` directory (git metadata is not working-tree content).
        if rel.as_os_str().is_empty() && name == std::ffi::OsStr::new(".git") {
            continue;
        }
        if !rel_path_is_safe(&child_rel) {
            return Err(CheckoutDigestError::UnsafePath {
                path: child_rel.display().to_string(),
            });
        }
        let key = child_rel.to_string_lossy().into_owned().into_bytes();
        let child_abs = root.join(&child_rel);
        let md = std::fs::symlink_metadata(&child_abs).map_err(|e| CheckoutDigestError::Io {
            path: child_abs.display().to_string(),
            detail: e.to_string(),
        })?;
        let ft = md.file_type();
        let kind = if ft.is_symlink() {
            let target = std::fs::read_link(&child_abs).map_err(|e| CheckoutDigestError::Io {
                path: child_abs.display().to_string(),
                detail: e.to_string(),
            })?;
            if !symlink_target_is_safe(&target) {
                return Err(CheckoutDigestError::UnsafeSymlinkTarget {
                    path: child_rel.display().to_string(),
                    target: target.display().to_string(),
                });
            }
            let target = target
                .to_str()
                .ok_or_else(|| CheckoutDigestError::NonUtf8Target {
                    path: child_rel.display().to_string(),
                })?;
            EntryKind::Symlink {
                target: target.to_string(),
            }
        } else if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_file() {
            let bytes = std::fs::read(&child_abs).map_err(|e| CheckoutDigestError::Io {
                path: child_abs.display().to_string(),
                detail: e.to_string(),
            })?;
            let exec = md.permissions().mode() & 0o111 != 0;
            EntryKind::File {
                git_mode: if exec { 0o755 } else { 0o644 },
                content: *blake3::hash(&bytes).as_bytes(),
            }
        } else {
            return Err(CheckoutDigestError::UnsupportedType {
                path: child_rel.display().to_string(),
            });
        };
        if out.insert(key.clone(), kind).is_some() {
            return Err(CheckoutDigestError::DuplicatePath {
                path: String::from_utf8_lossy(&key).into_owned(),
            });
        }
        if matches!(out.get(&key), Some(EntryKind::Dir)) {
            walk(root, &child_rel, out)?;
        }
    }
    Ok(())
}

/// Compute the canonical checkout-content digest (bare 64-hex) of the tree at `root`.
pub fn canonical_checkout_digest(root: &Path) -> Result<String, CheckoutDigestError> {
    // BTreeMap keyed by the raw relative-path bytes -> deterministic bytewise (C-locale) order.
    let mut entries: BTreeMap<Vec<u8>, EntryKind> = BTreeMap::new();
    walk(root, Path::new(""), &mut entries)?;

    let mut h = blake3::Hasher::new();
    h.update(&ADVDB_CHECKOUT_TAG);
    h.update(&(entries.len() as u64).to_le_bytes());
    for (rel, kind) in &entries {
        h.update(&(rel.len() as u64).to_le_bytes());
        h.update(rel);
        match kind {
            EntryKind::Dir => h.update(b"d"),
            EntryKind::File { git_mode, content } => {
                h.update(b"f");
                h.update(&git_mode.to_le_bytes());
                h.update(content)
            }
            EntryKind::Symlink { target } => {
                h.update(b"l");
                h.update(&(target.len() as u64).to_le_bytes());
                h.update(target.as_bytes())
            }
        };
    }
    Ok(super::to_hex(h.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "b0pre-ckdigest-{}-{}-{}",
            tag,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn write(p: &Path, b: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(b).unwrap();
    }

    fn sample(root: &Path) {
        write(&root.join("RUSTSEC/2020-0001.md"), b"advisory one\n");
        write(
            &root.join("crates/foo/RUSTSEC-0002.toml"),
            b"[advisory]\nid=2\n",
        );
        write(&root.join("README.md"), b"db\n");
    }

    #[test]
    fn deterministic_and_independently_reproducible() {
        let a = tmpdir("a");
        let b = tmpdir("b");
        sample(&a);
        sample(&b);
        let da = canonical_checkout_digest(&a).unwrap();
        let db = canonical_checkout_digest(&b).unwrap();
        assert_eq!(
            da, db,
            "identical content in two locations -> identical digest"
        );
        assert_eq!(da.len(), 64);
        // Re-run on the same tree reproduces the digest.
        assert_eq!(canonical_checkout_digest(&a).unwrap(), da);
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn content_change_changes_digest() {
        let a = tmpdir("c1");
        let b = tmpdir("c2");
        sample(&a);
        sample(&b);
        write(&b.join("README.md"), b"db TAMPERED\n");
        assert_ne!(
            canonical_checkout_digest(&a).unwrap(),
            canonical_checkout_digest(&b).unwrap(),
            "a one-byte content change must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn exec_bit_change_changes_digest() {
        let a = tmpdir("m1");
        write(&a.join("x.sh"), b"#!/bin/sh\n");
        let before = canonical_checkout_digest(&a).unwrap();
        std::fs::set_permissions(a.join("x.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let after = canonical_checkout_digest(&a).unwrap();
        assert_ne!(
            before, after,
            "flipping the exec bit must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn a_top_level_git_dir_is_excluded() {
        let a = tmpdir("g1");
        let b = tmpdir("g2");
        sample(&a);
        sample(&b);
        // b additionally has a .git with volatile content; digests must still match.
        write(&b.join(".git/HEAD"), b"ref: refs/heads/main\n");
        write(&b.join(".git/objects/ab/cdef"), b"\x00volatile\x01");
        assert_eq!(
            canonical_checkout_digest(&a).unwrap(),
            canonical_checkout_digest(&b).unwrap(),
            "a top-level .git dir must not affect the content digest"
        );
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn unsupported_file_type_is_rejected() {
        let a = tmpdir("fifo");
        let fifo = a.join("pipe");
        // mkfifo via libc-free path: use `mkfifo` if available, else skip the assertion.
        let ok = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            assert!(matches!(
                canonical_checkout_digest(&a),
                Err(CheckoutDigestError::UnsupportedType { .. })
            ));
        }
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn absolute_symlink_target_is_rejected() {
        let a = tmpdir("sl1");
        write(&a.join("real.txt"), b"x");
        std::os::unix::fs::symlink("/etc/passwd", a.join("evil")).unwrap();
        assert!(matches!(
            canonical_checkout_digest(&a),
            Err(CheckoutDigestError::UnsafeSymlinkTarget { .. })
        ));
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn parent_traversal_symlink_target_is_rejected() {
        let a = tmpdir("sl2");
        write(&a.join("real.txt"), b"x");
        std::os::unix::fs::symlink("../../outside", a.join("escape")).unwrap();
        assert!(matches!(
            canonical_checkout_digest(&a),
            Err(CheckoutDigestError::UnsafeSymlinkTarget { .. })
        ));
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn a_safe_relative_symlink_is_accepted_and_bound() {
        let a = tmpdir("sl3");
        write(&a.join("real.txt"), b"x");
        std::os::unix::fs::symlink("real.txt", a.join("alias")).unwrap();
        let d1 = canonical_checkout_digest(&a).unwrap();
        // Repointing the symlink to a different (safe) target changes the digest.
        write(&a.join("other.txt"), b"y");
        std::fs::remove_file(a.join("alias")).unwrap();
        std::os::unix::fs::symlink("other.txt", a.join("alias")).unwrap();
        assert_ne!(d1, canonical_checkout_digest(&a).unwrap());
        std::fs::remove_dir_all(&a).ok();
    }

    // ---- Frozen GOLDEN VECTOR + mutation matrix + independent-reference agreement -----

    /// The exact fixed tree whose digest is frozen below (and cross-checked by the
    /// independent Python reference `scripts/advdb_digest_ref.py`).
    fn golden_tree(root: &Path) {
        write(&root.join("RUSTSEC-2020-0001.md"), b"advisory one\n");
        write(
            &root.join("crates/foo/RUSTSEC-0002.toml"),
            b"[advisory]\nid=2\n",
        );
        write(&root.join("README.md"), b"db\n");
        for p in [
            "RUSTSEC-2020-0001.md",
            "crates/foo/RUSTSEC-0002.toml",
            "README.md",
        ] {
            std::fs::set_permissions(root.join(p), std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    /// FROZEN golden digest of `golden_tree` (ADVDB/v1 format). A change here is a
    /// deliberate format-version bump, never an accident.
    const GOLDEN: &str = "c8a6834f7a5bb1ae61e8f5f78c4770a8d357669cc084f8450442a348573f7c0a";

    #[test]
    fn golden_vector_is_frozen() {
        let a = tmpdir("golden");
        golden_tree(&a);
        assert_eq!(
            canonical_checkout_digest(&a).unwrap(),
            GOLDEN,
            "the ADVDB/v1 canonical digest of the golden tree must be frozen"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn extra_file_changes_digest() {
        let a = tmpdir("extra");
        golden_tree(&a);
        assert_eq!(canonical_checkout_digest(&a).unwrap(), GOLDEN);
        write(&a.join("crates/foo/EXTRA.toml"), b"x\n");
        assert_ne!(
            canonical_checkout_digest(&a).unwrap(),
            GOLDEN,
            "an added file must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn missing_file_changes_digest() {
        let a = tmpdir("missing");
        golden_tree(&a);
        std::fs::remove_file(a.join("README.md")).unwrap();
        assert_ne!(
            canonical_checkout_digest(&a).unwrap(),
            GOLDEN,
            "a removed file must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    /// The genuinely independent Python + b3sum reference (`scripts/advdb_digest_ref.py`)
    /// must reproduce the Rust digest bit-for-bit on the golden tree. Skips (does not fail)
    /// only if python3/b3sum are unavailable, so the agreement is enforced wherever both
    /// exist (CI has both).
    #[test]
    fn independent_reference_reproduces_the_digest() {
        let have = |b: &str| {
            std::process::Command::new(b)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if !have("python3") || !have("b3sum") {
            eprintln!("SKIP: python3/b3sum unavailable; independent-reference agreement not run");
            return;
        }
        let a = tmpdir("ref");
        golden_tree(&a);
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/advdb_digest_ref.py");
        let out = std::process::Command::new("python3")
            .arg(&script)
            .arg(&a)
            .output()
            .expect("run independent reference");
        assert!(
            out.status.success(),
            "reference failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let ref_digest = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_eq!(
            ref_digest, GOLDEN,
            "independent reference must reproduce the frozen golden digest"
        );
        assert_eq!(
            ref_digest,
            canonical_checkout_digest(&a).unwrap(),
            "independent reference must equal the Rust implementation"
        );
        std::fs::remove_dir_all(&a).ok();
    }
}

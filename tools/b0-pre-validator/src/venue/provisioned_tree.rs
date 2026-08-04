//! Canonical, deterministic content digest of an extracted PROVISIONING tree
//! (`PROVISIONED_TREE/v1`). A provisioning tree is a fully-known set of extracted
//! bytes — a proving circuit's runtime tree, a guest-toolchain tree, or a prover
//! backend/data tree — that a v4 pin binds so two venues (and two architectures)
//! materializing the SAME approved content compute the SAME digest and any
//! tampering fails closed.
//!
//! This module is INDEPENDENT of the ADVDB checkout digest ([`super::checkout_digest`])
//! and never changes its behavior or golden vectors. It shares the same
//! ambiguity-resistant serialization *shape* (so both are auditable the same way)
//! but under a DISTINCT domain tag and with ONE deliberate semantic difference:
//!
//!   * ADVDB excludes a top-level `.git` (it digests a git working tree's CONTENT).
//!   * PROVISIONED_TREE excludes NOTHING — an extracted archive is fully-known
//!     content, so a stray `.git` (or any other entry) is bound, not silently
//!     dropped. A tree that differs only by a top-level `.git` gets a DIFFERENT
//!     PROVISIONED_TREE digest.
//!
//! Digest = `BLAKE3(PROVISIONED_TREE_TAG ‖ u64_le(entry_count) ‖ Σ canonical(entry))`
//! over EVERY entry under the root, sorted by relative-path bytes (bytewise /
//! C-locale). Each entry canonically encodes:
//!   * relative path (length-prefixed bytes);
//!   * type: `d` dir | `f` regular | `l` symlink;
//!   * regular files: a git-style mode (`0o644`/`0o755`, exec bit only —
//!     reproducible across umask) + BLAKE3 of the file bytes;
//!   * symlinks: the target (length-prefixed bytes);
//!   * dirs: nothing beyond the path + type.
//!
//! Fails closed on: an unsupported file type (fifo/socket/device/…); a duplicate
//! relative path; or a traversal attempt (a `..`/absolute/NUL component in any
//! relative path, or an absolute / `..`-containing symlink target). Independently
//! reproducible: re-extract the archive, re-run — same digest. A byte-identical
//! Python reference (`scripts/provisioned_tree_ref.py`) re-derives the spec and is
//! required to agree.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

use crate::tags::PROVISIONED_TREE_TAG;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionedTreeError {
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

impl std::fmt::Display for ProvisionedTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionedTreeError::Io { path, detail } => {
                write!(f, "io error at {path:?}: {detail}")
            }
            ProvisionedTreeError::UnsafePath { path } => {
                write!(f, "unsafe/non-canonical relative path (traversal): {path:?}")
            }
            ProvisionedTreeError::UnsafeSymlinkTarget { path, target } => write!(
                f,
                "symlink {path:?} has an unsafe target {target:?} (absolute or contains `..`)"
            ),
            ProvisionedTreeError::UnsupportedType { path } => {
                write!(f, "unsupported file type at {path:?} (not regular/symlink/dir)")
            }
            ProvisionedTreeError::DuplicatePath { path } => {
                write!(f, "duplicate relative path in provisioning tree: {path:?}")
            }
            ProvisionedTreeError::NonUtf8Target { path } => {
                write!(f, "symlink target at {path:?} is not valid UTF-8")
            }
        }
    }
}

impl std::error::Error for ProvisionedTreeError {}

/// One canonical tree entry as recorded in the digest and in the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
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
) -> Result<(), ProvisionedTreeError> {
    let abs = root.join(rel);
    let rd = std::fs::read_dir(&abs).map_err(|e| ProvisionedTreeError::Io {
        path: abs.display().to_string(),
        detail: e.to_string(),
    })?;
    for ent in rd {
        let ent = ent.map_err(|e| ProvisionedTreeError::Io {
            path: abs.display().to_string(),
            detail: e.to_string(),
        })?;
        let name = ent.file_name();
        let child_rel = rel.join(&name);
        // NOTE: unlike ADVDB, PROVISIONED_TREE excludes NOTHING — every entry is bound.
        if !rel_path_is_safe(&child_rel) {
            return Err(ProvisionedTreeError::UnsafePath {
                path: child_rel.display().to_string(),
            });
        }
        let key = child_rel.to_string_lossy().into_owned().into_bytes();
        let child_abs = root.join(&child_rel);
        let md = std::fs::symlink_metadata(&child_abs).map_err(|e| ProvisionedTreeError::Io {
            path: child_abs.display().to_string(),
            detail: e.to_string(),
        })?;
        let ft = md.file_type();
        let kind = if ft.is_symlink() {
            let target = std::fs::read_link(&child_abs).map_err(|e| ProvisionedTreeError::Io {
                path: child_abs.display().to_string(),
                detail: e.to_string(),
            })?;
            if !symlink_target_is_safe(&target) {
                return Err(ProvisionedTreeError::UnsafeSymlinkTarget {
                    path: child_rel.display().to_string(),
                    target: target.display().to_string(),
                });
            }
            let target = target
                .to_str()
                .ok_or_else(|| ProvisionedTreeError::NonUtf8Target {
                    path: child_rel.display().to_string(),
                })?;
            EntryKind::Symlink {
                target: target.to_string(),
            }
        } else if ft.is_dir() {
            EntryKind::Dir
        } else if ft.is_file() {
            let bytes = std::fs::read(&child_abs).map_err(|e| ProvisionedTreeError::Io {
                path: child_abs.display().to_string(),
                detail: e.to_string(),
            })?;
            let exec = md.permissions().mode() & 0o111 != 0;
            EntryKind::File {
                git_mode: if exec { 0o755 } else { 0o644 },
                content: *blake3::hash(&bytes).as_bytes(),
            }
        } else {
            return Err(ProvisionedTreeError::UnsupportedType {
                path: child_rel.display().to_string(),
            });
        };
        if out.insert(key.clone(), kind).is_some() {
            return Err(ProvisionedTreeError::DuplicatePath {
                path: String::from_utf8_lossy(&key).into_owned(),
            });
        }
        if matches!(out.get(&key), Some(EntryKind::Dir)) {
            walk(root, &child_rel, out)?;
        }
    }
    Ok(())
}

/// Collect the canonical inventory (relpath -> kind) of the tree at `root`, keyed by raw
/// relative-path bytes so iteration is deterministic bytewise (C-locale) order. This is the
/// exact set of entries the digest is computed over; a caller can also render it as an
/// auditable member inventory.
pub fn collect_inventory(root: &Path) -> Result<BTreeMap<Vec<u8>, EntryKind>, ProvisionedTreeError> {
    let mut entries: BTreeMap<Vec<u8>, EntryKind> = BTreeMap::new();
    walk(root, Path::new(""), &mut entries)?;
    Ok(entries)
}

/// Fold a collected inventory into the canonical `PROVISIONED_TREE/v1` digest bytes. Split out
/// so a caller that already has the inventory (e.g. after an archive-member reconciliation)
/// digests the SAME bytes the walker would.
pub fn digest_inventory(entries: &BTreeMap<Vec<u8>, EntryKind>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&PROVISIONED_TREE_TAG);
    h.update(&(entries.len() as u64).to_le_bytes());
    for (rel, kind) in entries {
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
    *h.finalize().as_bytes()
}

/// Compute the canonical `PROVISIONED_TREE/v1` content digest (bare 64-hex) of the tree at
/// `root`. Excludes nothing; fails closed on unsupported types / duplicate paths / traversal.
pub fn provisioned_tree_digest(root: &Path) -> Result<String, ProvisionedTreeError> {
    let entries = collect_inventory(root)?;
    Ok(super::to_hex(&digest_inventory(&entries)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "b0pre-provtree-{}-{}-{}",
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
        write(&root.join("bin/cargo-prove"), b"ELF...\n");
        std::fs::set_permissions(root.join("bin/cargo-prove"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        write(&root.join("lib/rustlib/components"), b"rust-std\n");
        write(&root.join("version"), b"succinct-1.94.0-64bit\n");
    }

    #[test]
    fn deterministic_and_independently_reproducible() {
        let a = tmpdir("a");
        let b = tmpdir("b");
        sample(&a);
        sample(&b);
        let da = provisioned_tree_digest(&a).unwrap();
        let db = provisioned_tree_digest(&b).unwrap();
        assert_eq!(da, db, "identical content in two locations -> identical digest");
        assert_eq!(da.len(), 64);
        assert_eq!(provisioned_tree_digest(&a).unwrap(), da);
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn distinct_domain_from_advdb() {
        // The SAME tree digested by ADVDB and by PROVISIONED_TREE must differ: the domain
        // tags are distinct, so a provisioning-tree digest can never be read as, or collide
        // with, an ADVDB checkout digest.
        let a = tmpdir("dom");
        sample(&a);
        let prov = provisioned_tree_digest(&a).unwrap();
        let advdb = super::super::checkout_digest::canonical_checkout_digest(&a).unwrap();
        assert_ne!(prov, advdb, "domain separation: PROVTREE != ADVDB for the same tree");
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn top_level_git_is_bound_not_excluded() {
        // The KEY semantic difference from ADVDB: PROVISIONED_TREE excludes nothing, so a tree
        // that differs only by a top-level `.git` entry gets a DIFFERENT digest. (ADVDB would
        // treat these two trees as equal.)
        let a = tmpdir("git-a");
        let b = tmpdir("git-b");
        sample(&a);
        sample(&b);
        write(&b.join(".git/HEAD"), b"ref: refs/heads/main\n");
        assert_ne!(
            provisioned_tree_digest(&a).unwrap(),
            provisioned_tree_digest(&b).unwrap(),
            "PROVISIONED_TREE must bind a top-level .git (no exclusion)"
        );
        // And ADVDB (unchanged) still excludes it — proving we did not alter ADVDB behavior.
        assert_eq!(
            super::super::checkout_digest::canonical_checkout_digest(&a).unwrap(),
            super::super::checkout_digest::canonical_checkout_digest(&b).unwrap(),
            "ADVDB behavior is unchanged: it still excludes a top-level .git"
        );
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn content_change_changes_digest() {
        let a = tmpdir("c1");
        let b = tmpdir("c2");
        sample(&a);
        sample(&b);
        write(&b.join("version"), b"succinct-9.99.9-64bit\n");
        assert_ne!(
            provisioned_tree_digest(&a).unwrap(),
            provisioned_tree_digest(&b).unwrap(),
            "a one-byte content change must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn exec_bit_change_changes_digest() {
        let a = tmpdir("m1");
        write(&a.join("x"), b"binary\n");
        let before = provisioned_tree_digest(&a).unwrap();
        std::fs::set_permissions(a.join("x"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let after = provisioned_tree_digest(&a).unwrap();
        assert_ne!(before, after, "flipping the exec bit must change the digest");
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn unsupported_file_type_is_rejected() {
        let a = tmpdir("fifo");
        let fifo = a.join("pipe");
        let ok = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            assert!(matches!(
                provisioned_tree_digest(&a),
                Err(ProvisionedTreeError::UnsupportedType { .. })
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
            provisioned_tree_digest(&a),
            Err(ProvisionedTreeError::UnsafeSymlinkTarget { .. })
        ));
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn parent_traversal_symlink_target_is_rejected() {
        let a = tmpdir("sl2");
        write(&a.join("real.txt"), b"x");
        std::os::unix::fs::symlink("../../outside", a.join("escape")).unwrap();
        assert!(matches!(
            provisioned_tree_digest(&a),
            Err(ProvisionedTreeError::UnsafeSymlinkTarget { .. })
        ));
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn a_safe_relative_symlink_is_accepted_and_bound() {
        let a = tmpdir("sl3");
        write(&a.join("real.txt"), b"x");
        std::os::unix::fs::symlink("real.txt", a.join("alias")).unwrap();
        let d1 = provisioned_tree_digest(&a).unwrap();
        write(&a.join("other.txt"), b"y");
        std::fs::remove_file(a.join("alias")).unwrap();
        std::os::unix::fs::symlink("other.txt", a.join("alias")).unwrap();
        assert_ne!(d1, provisioned_tree_digest(&a).unwrap());
        std::fs::remove_dir_all(&a).ok();
    }

    // ---- Frozen GOLDEN VECTOR + adversarial matrix + independent-reference agreement -----

    /// The exact fixed tree whose digest is frozen below (and cross-checked by the independent
    /// Python reference `scripts/provisioned_tree_ref.py`). Deliberately exercises: an exec-bit
    /// file, a plain file, a nested dir, and a safe relative symlink.
    fn golden_tree(root: &Path) {
        write(&root.join("bin/prover"), b"#!/bin/sh\nexec prover\n");
        std::fs::set_permissions(root.join("bin/prover"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        write(&root.join("lib/data.bin"), b"\x00\x01\x02circuit\x03\x04");
        write(&root.join("VERSION"), b"v6.1.0\n");
        for p in ["lib/data.bin", "VERSION"] {
            std::fs::set_permissions(root.join(p), std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::os::unix::fs::symlink("bin/prover", root.join("prover-latest")).unwrap();
    }

    #[test]
    fn domain_tag_is_frozen() {
        // The exact provisioned-tree domain tag is FROZEN. A change here is a deliberate
        // format-version bump, never an accident (it would invalidate every v4 pin).
        let n = crate::tags::ascii_len(&PROVISIONED_TREE_TAG);
        assert_eq!(
            &PROVISIONED_TREE_TAG[..n],
            b"SUMCHAIN/B0PRE/PROVTREE/v1",
            "PROVISIONED_TREE domain tag must be exactly SUMCHAIN/B0PRE/PROVTREE/v1"
        );
        assert!(crate::tags::well_padded(&PROVISIONED_TREE_TAG));
    }

    /// FROZEN golden digest of `golden_tree` (PROVISIONED_TREE/v1 format). A change here is a
    /// deliberate format-version bump, never an accident. Kept in lock-step with the Python
    /// reference and the shell golden vector `scripts/tests/provisioned_tree_vectors.test.sh`.
    const GOLDEN: &str = "2cf78171daeb42d4b5a004ffb1d7aa8b341ef1c18a7cd684a8f5a61548fe89af";

    #[test]
    fn golden_vector_is_frozen() {
        let a = tmpdir("golden");
        golden_tree(&a);
        assert_eq!(
            provisioned_tree_digest(&a).unwrap(),
            GOLDEN,
            "the PROVISIONED_TREE/v1 canonical digest of the golden tree must be frozen"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn extra_file_changes_digest() {
        let a = tmpdir("extra");
        golden_tree(&a);
        assert_eq!(provisioned_tree_digest(&a).unwrap(), GOLDEN);
        write(&a.join("lib/EXTRA.bin"), b"x\n");
        assert_ne!(
            provisioned_tree_digest(&a).unwrap(),
            GOLDEN,
            "an added file must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn missing_file_changes_digest() {
        let a = tmpdir("missing");
        golden_tree(&a);
        std::fs::remove_file(a.join("VERSION")).unwrap();
        assert_ne!(
            provisioned_tree_digest(&a).unwrap(),
            GOLDEN,
            "a removed file must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    #[test]
    fn moved_file_changes_digest() {
        // Same bytes, different path — the path is bound, so the digest changes.
        let a = tmpdir("moved");
        golden_tree(&a);
        std::fs::rename(a.join("VERSION"), a.join("lib/VERSION")).unwrap();
        assert_ne!(
            provisioned_tree_digest(&a).unwrap(),
            GOLDEN,
            "moving a file to a different path must change the digest"
        );
        std::fs::remove_dir_all(&a).ok();
    }

    /// The genuinely independent Python + b3sum reference (`scripts/provisioned_tree_ref.py`)
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
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("scripts/provisioned_tree_ref.py");
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
            provisioned_tree_digest(&a).unwrap(),
            "independent reference must equal the Rust implementation"
        );
        std::fs::remove_dir_all(&a).ok();
    }
}

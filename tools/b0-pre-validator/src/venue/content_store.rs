//! A digest-addressed venue **content store** for the multi-GB Stage-5 provisioning inputs
//! (the SP1 Groth16 circuit runtime tree, guest-toolchain trees, immutable data artifacts).
//!
//! Motivation: those artifacts are gigabytes and MUST NOT be baked into candidate images or
//! referenced by machine-specific paths in the portable pin proposal. Instead the proposal
//! carries only a **digest**; the venue resolves that digest to a local path in this store and
//! **re-hashes the bytes before use**, then mounts them **read-only** into the restricted
//! host-side prover container. A store miss, a traversal attempt, or any hash drift fails
//! closed — a resolved path is only ever handed out after its content re-hashes to the digest
//! that addressed it.
//!
//! Two object kinds, each under a versioned, digest-named path:
//!   * **trees**  → `<store>/trees/provtree-v1/<64hex>/…`  addressed by [`provisioned_tree`]
//!                  (`PROVISIONED_TREE/v1`); re-verified by recomputing that digest.
//!   * **blobs**  → `<store>/blobs/sha256/<64hex>`          addressed by SHA-256; re-verified
//!                  by recomputing SHA-256.
//!
//! The store never mutates a stored object in place: `put_*` is content-addressed, so a second
//! put of the same bytes lands at the same path and is verified equal, never overwritten with
//! unverified content. The digest is validated as exactly 64 lowercase-hex BEFORE it is used
//! as a path component, so a crafted digest can never escape the store root.

use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use super::provisioned_tree::{provisioned_tree_digest, ProvisionedTreeError};
use super::{is_hex64, sha256, to_hex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentStoreError {
    Io {
        path: String,
        detail: String,
    },
    /// The digest was not exactly 64 lowercase-hex (rejected before any path use).
    BadDigest {
        digest: String,
    },
    /// The addressed object is not present in the store.
    Missing {
        kind: &'static str,
        digest: String,
    },
    /// The stored bytes re-hashed to a value other than the digest that addressed them.
    IntegrityMismatch {
        kind: &'static str,
        expected: String,
        got: String,
    },
    /// A tree could not be digested (unsafe member, traversal, unsupported type, …).
    Tree(ProvisionedTreeError),
}

impl std::fmt::Display for ContentStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentStoreError::Io { path, detail } => write!(f, "io error at {path:?}: {detail}"),
            ContentStoreError::BadDigest { digest } => {
                write!(f, "not a bare 64-lowercase-hex digest (refused before path use): {digest:?}")
            }
            ContentStoreError::Missing { kind, digest } => {
                write!(f, "{kind} object {digest} is not present in the content store")
            }
            ContentStoreError::IntegrityMismatch { kind, expected, got } => write!(
                f,
                "{kind} content-store integrity mismatch: addressed by {expected} but re-hashed to {got}"
            ),
            ContentStoreError::Tree(e) => write!(f, "tree digest error: {e}"),
        }
    }
}

impl std::error::Error for ContentStoreError {}

impl From<ProvisionedTreeError> for ContentStoreError {
    fn from(e: ProvisionedTreeError) -> Self {
        ContentStoreError::Tree(e)
    }
}

fn io<E: std::fmt::Display>(path: &Path, e: E) -> ContentStoreError {
    ContentStoreError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// Validate a digest is exactly 64 lowercase-hex — the ONLY values allowed as a path component.
fn checked_digest(digest: &str) -> Result<&str, ContentStoreError> {
    if is_hex64(digest) {
        Ok(digest)
    } else {
        Err(ContentStoreError::BadDigest {
            digest: digest.to_string(),
        })
    }
}

fn trees_dir(store: &Path) -> PathBuf {
    store.join("trees").join("provtree-v1")
}
fn blobs_dir(store: &Path) -> PathBuf {
    store.join("blobs").join("sha256")
}

/// Recursively copy `src` into `dst`, preserving exactly what `PROVISIONED_TREE/v1` binds:
/// file bytes, the exec bit, directory structure, and symlink targets. Refuses anything the
/// digest cannot represent (unsupported types are surfaced by the subsequent re-digest).
fn copy_tree(src: &Path, dst: &Path) -> Result<(), ContentStoreError> {
    std::fs::create_dir_all(dst).map_err(|e| io(dst, e))?;
    for ent in std::fs::read_dir(src).map_err(|e| io(src, e))? {
        let ent = ent.map_err(|e| io(src, e))?;
        let from = ent.path();
        let to = dst.join(ent.file_name());
        let md = std::fs::symlink_metadata(&from).map_err(|e| io(&from, e))?;
        let ft = md.file_type();
        if ft.is_symlink() {
            let target = std::fs::read_link(&from).map_err(|e| io(&from, e))?;
            std::os::unix::fs::symlink(&target, &to).map_err(|e| io(&to, e))?;
        } else if ft.is_dir() {
            copy_tree(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to).map_err(|e| io(&from, e))?;
            let exec = md.permissions().mode() & 0o111 != 0;
            std::fs::set_permissions(
                &to,
                std::fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }),
            )
            .map_err(|e| io(&to, e))?;
        } else {
            // Unsupported type; the re-digest of the destination would fail closed anyway, but
            // refuse here so nothing partial is stored.
            return Err(ContentStoreError::Tree(
                ProvisionedTreeError::UnsupportedType {
                    path: from.display().to_string(),
                },
            ));
        }
    }
    Ok(())
}

/// Store the tree at `src` under its `PROVISIONED_TREE/v1` digest. Returns the digest. If the
/// tree is already present, verifies the existing copy re-digests correctly (never overwrites).
pub fn put_tree(store: &Path, src: &Path) -> Result<String, ContentStoreError> {
    let digest = provisioned_tree_digest(src)?;
    let dest = trees_dir(store).join(&digest);
    if dest.exists() {
        // Idempotent: confirm the existing object still addresses to `digest`.
        let have = provisioned_tree_digest(&dest)?;
        if have != digest {
            return Err(ContentStoreError::IntegrityMismatch {
                kind: "tree",
                expected: digest,
                got: have,
            });
        }
        return Ok(digest);
    }
    std::fs::create_dir_all(trees_dir(store)).map_err(|e| io(&trees_dir(store), e))?;
    // Stage into a temp dir, verify, then atomically rename into place.
    let staging = trees_dir(store).join(format!(".staging-{}-{}", std::process::id(), digest));
    if staging.exists() {
        std::fs::remove_dir_all(&staging).ok();
    }
    copy_tree(src, &staging)?;
    let staged = provisioned_tree_digest(&staging)?;
    if staged != digest {
        std::fs::remove_dir_all(&staging).ok();
        return Err(ContentStoreError::IntegrityMismatch {
            kind: "tree",
            expected: digest,
            got: staged,
        });
    }
    std::fs::rename(&staging, &dest).map_err(|e| io(&dest, e))?;
    Ok(digest)
}

/// Resolve a tree digest to its read-only path, RE-HASHING the stored bytes first. The returned
/// path is safe to bind-mount read-only. Fails closed on bad digest / miss / any drift.
pub fn resolve_tree(store: &Path, digest: &str) -> Result<PathBuf, ContentStoreError> {
    let digest = checked_digest(digest)?;
    let path = trees_dir(store).join(digest);
    if !path.is_dir() {
        return Err(ContentStoreError::Missing {
            kind: "tree",
            digest: digest.to_string(),
        });
    }
    let have = provisioned_tree_digest(&path)?;
    if have != digest {
        return Err(ContentStoreError::IntegrityMismatch {
            kind: "tree",
            expected: digest.to_string(),
            got: have,
        });
    }
    Ok(path)
}

/// Store a blob file under its SHA-256. Returns the hex digest.
pub fn put_blob(store: &Path, src: &Path) -> Result<String, ContentStoreError> {
    let bytes = std::fs::read(src).map_err(|e| io(src, e))?;
    let digest = to_hex(&sha256::digest(&bytes));
    let dest = blobs_dir(store).join(&digest);
    if dest.exists() {
        let have = to_hex(&sha256::digest(
            &std::fs::read(&dest).map_err(|e| io(&dest, e))?,
        ));
        if have != digest {
            return Err(ContentStoreError::IntegrityMismatch {
                kind: "blob",
                expected: digest,
                got: have,
            });
        }
        return Ok(digest);
    }
    std::fs::create_dir_all(blobs_dir(store)).map_err(|e| io(&blobs_dir(store), e))?;
    let tmp = blobs_dir(store).join(format!(".staging-{}-{}", std::process::id(), digest));
    std::fs::write(&tmp, &bytes).map_err(|e| io(&tmp, e))?;
    std::fs::rename(&tmp, &dest).map_err(|e| io(&dest, e))?;
    Ok(digest)
}

/// Resolve a blob digest to its read-only path, RE-HASHING first. Fails closed on bad digest /
/// miss / drift.
pub fn resolve_blob(store: &Path, digest: &str) -> Result<PathBuf, ContentStoreError> {
    let digest = checked_digest(digest)?;
    let path = blobs_dir(store).join(digest);
    if !path.is_file() {
        return Err(ContentStoreError::Missing {
            kind: "blob",
            digest: digest.to_string(),
        });
    }
    let have = to_hex(&sha256::digest(
        &std::fs::read(&path).map_err(|e| io(&path, e))?,
    ));
    if have != digest {
        return Err(ContentStoreError::IntegrityMismatch {
            kind: "blob",
            expected: digest.to_string(),
            got: have,
        });
    }
    Ok(path)
}

/// True iff `p` is a syntactically safe store-relative path (no `..`/absolute/prefix). Used to
/// reject a caller-supplied relative locator before it is joined onto a resolved tree root.
pub fn is_safe_relpath(p: &Path) -> bool {
    let mut any = false;
    for c in p.components() {
        match c {
            Component::Normal(_) => any = true,
            _ => return false,
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "b0pre-cstore-{}-{}-{}",
            tag,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    fn write(p: &Path, b: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::File::create(p).unwrap().write_all(b).unwrap();
    }
    fn sample(root: &Path) {
        write(&root.join("bin/prover"), b"#!/bin/sh\nexec prover\n");
        std::fs::set_permissions(
            root.join("bin/prover"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        write(&root.join("lib/data.bin"), b"\x00\x01\x02circuit\x03\x04");
        write(&root.join("VERSION"), b"v6.1.0\n");
    }

    #[test]
    fn tree_roundtrip_preserves_digest() {
        let store = tmp("store");
        let src = tmp("src");
        sample(&src);
        let want = provisioned_tree_digest(&src).unwrap();
        let put = put_tree(&store, &src).unwrap();
        assert_eq!(put, want, "put returns the provisioned-tree digest");
        let resolved = resolve_tree(&store, &want).unwrap();
        assert_eq!(
            provisioned_tree_digest(&resolved).unwrap(),
            want,
            "re-hash on resolve matches"
        );
        std::fs::remove_dir_all(&store).ok();
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn put_is_idempotent() {
        let store = tmp("idem");
        let src = tmp("idemsrc");
        sample(&src);
        let a = put_tree(&store, &src).unwrap();
        let b = put_tree(&store, &src).unwrap();
        assert_eq!(a, b);
        std::fs::remove_dir_all(&store).ok();
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn resolve_missing_fails_closed() {
        let store = tmp("miss");
        let bogus = "0".repeat(64);
        assert!(matches!(
            resolve_tree(&store, &bogus),
            Err(ContentStoreError::Missing { .. })
        ));
        assert!(matches!(
            resolve_blob(&store, &bogus),
            Err(ContentStoreError::Missing { .. })
        ));
        std::fs::remove_dir_all(&store).ok();
    }

    #[test]
    fn bad_digest_is_refused_before_path_use() {
        let store = tmp("baddig");
        // Traversal attempt + non-hex: must be refused by the digest check, never touch the FS.
        for d in [
            "../../etc",
            "../escape",
            "not-hex",
            "ABCDEF",
            &"g".repeat(64),
            &"0".repeat(63),
        ] {
            assert!(
                matches!(
                    resolve_tree(&store, d),
                    Err(ContentStoreError::BadDigest { .. })
                ),
                "tree {d}"
            );
            assert!(
                matches!(
                    resolve_blob(&store, d),
                    Err(ContentStoreError::BadDigest { .. })
                ),
                "blob {d}"
            );
        }
        std::fs::remove_dir_all(&store).ok();
    }

    #[test]
    fn tampered_tree_fails_closed_on_resolve() {
        let store = tmp("tamper");
        let src = tmp("tampersrc");
        sample(&src);
        let d = put_tree(&store, &src).unwrap();
        // Tamper with the stored bytes under the digest-named dir.
        write(&trees_dir(&store).join(&d).join("VERSION"), b"TAMPERED\n");
        assert!(matches!(
            resolve_tree(&store, &d),
            Err(ContentStoreError::IntegrityMismatch { .. })
        ));
        std::fs::remove_dir_all(&store).ok();
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn blob_roundtrip_and_tamper() {
        let store = tmp("blob");
        let f = tmp("blobsrc").join("a.bin");
        write(&f, b"hello circuit bytes");
        let d = put_blob(&store, &f).unwrap();
        let r = resolve_blob(&store, &d).unwrap();
        assert_eq!(std::fs::read(&r).unwrap(), b"hello circuit bytes");
        // Tamper.
        write(&blobs_dir(&store).join(&d), b"different");
        assert!(matches!(
            resolve_blob(&store, &d),
            Err(ContentStoreError::IntegrityMismatch { .. })
        ));
        std::fs::remove_dir_all(&store).ok();
    }

    #[test]
    fn exec_bit_is_preserved_across_store() {
        let store = tmp("exec");
        let src = tmp("execsrc");
        write(&src.join("run"), b"binary");
        std::fs::set_permissions(src.join("run"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let d = put_tree(&store, &src).unwrap();
        let r = resolve_tree(&store, &d).unwrap();
        let mode = std::fs::metadata(r.join("run"))
            .unwrap()
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "exec bit preserved so the digest matches"
        );
        std::fs::remove_dir_all(&store).ok();
        std::fs::remove_dir_all(&src).ok();
    }

    #[test]
    fn safe_relpath_rejects_traversal() {
        assert!(is_safe_relpath(Path::new("groth16_pk.bin")));
        assert!(is_safe_relpath(Path::new("a/b/c")));
        assert!(!is_safe_relpath(Path::new("../x")));
        assert!(!is_safe_relpath(Path::new("/abs")));
        assert!(!is_safe_relpath(Path::new("")));
    }
}

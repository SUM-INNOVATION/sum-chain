//! Blocker 5: parse an exported OCI image layout and record its TRUE manifest
//! identity.
//!
//! The prior producer recorded `sha256(exported_oci.tar)` as if it were the image
//! digest. It is not: the OCI **manifest content address** is the `digest` the
//! layout's `index.json` binds to the image manifest blob — independent of how the
//! layout is serialized (tar member order, gzip, timestamps). This module reads the
//! layout on disk, extracts that manifest digest + its platform descriptor, and
//! (using the dependency-free [`super::sha256`]) re-verifies the referenced blob's
//! content address, so the recorded identity is the real one, not a tar hash.
//!
//! On-venue `build_container.sh` calls the `stage-oci-manifest` bin over the layout
//! Docker exports. Off-venue this module is unit-tested against a hand-built sample
//! layout; the raw exported-tar hash is kept ONLY as a separate `*_hex` raw-artifact
//! field, never as the manifest identity.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{is_hex64, sha256};

/// The OCI platform descriptor recorded alongside the manifest identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    pub variant: Option<String>,
}

/// The extracted manifest identity: the content-addressed manifest digest, its
/// media type, and (when present) the platform it targets. This — not any tar hash
/// — is the OCI image identity recorded into Stage-1 evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestIdentity {
    pub digest: String,
    pub media_type: String,
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciError {
    LayoutMarker(String),
    Parse(String),
    /// A descriptor digest was not a full `sha256:<64hex>`.
    BadDigest(String),
    NoManifests,
    /// No index manifest targeted the requested architecture.
    PlatformNotFound {
        arch: String,
    },
    /// More than one index manifest targeted the requested architecture.
    AmbiguousPlatform {
        arch: String,
    },
    /// The manifest blob named by the descriptor digest is absent from the layout.
    BlobMissing {
        digest: String,
    },
    /// The blob at `blobs/sha256/<hex>` does not hash to its own name — the layout
    /// is not content-addressed / has been tampered with.
    ContentAddressMismatch {
        digest: String,
        actual: String,
    },
    /// The image the runtime loaded/reported does NOT resolve to the recorded
    /// manifest digest — the running image is not the exact verified image.
    RuntimeIdentityMismatch {
        recorded: String,
        runtime: String,
    },
    Io(String),
}

impl std::fmt::Display for OciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OciError::LayoutMarker(m) => write!(f, "oci-layout marker invalid: {m}"),
            OciError::Parse(e) => write!(f, "index.json parse failed: {e}"),
            OciError::BadDigest(d) => write!(f, "descriptor digest is not sha256:<64hex>: {d:?}"),
            OciError::NoManifests => write!(f, "index.json lists no manifests"),
            OciError::PlatformNotFound { arch } => {
                write!(f, "no image manifest targets architecture {arch:?}")
            }
            OciError::AmbiguousPlatform { arch } => {
                write!(f, "more than one image manifest targets architecture {arch:?}")
            }
            OciError::BlobMissing { digest } => write!(f, "manifest blob {digest} absent from layout"),
            OciError::ContentAddressMismatch { digest, actual } => write!(
                f,
                "manifest blob content address mismatch: index claims {digest} but blob hashes to sha256:{actual}"
            ),
            OciError::RuntimeIdentityMismatch { recorded, runtime } => write!(
                f,
                "runtime image identity {runtime} does not resolve to the recorded manifest digest {recorded}"
            ),
            OciError::Io(e) => write!(f, "layout io error: {e}"),
        }
    }
}

impl std::error::Error for OciError {}

#[derive(Deserialize)]
struct LayoutMarkerFile {
    #[serde(rename = "imageLayoutVersion")]
    image_layout_version: String,
}

// The OCI descriptor / index shapes carry many optional fields (annotations,
// urls, ...); parse tolerantly (no deny_unknown_fields) but validate what we use.
#[derive(Deserialize)]
struct IndexFile {
    manifests: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    #[serde(default)]
    platform: Option<PlatformJson>,
}

#[derive(Deserialize)]
struct PlatformJson {
    architecture: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    variant: Option<String>,
}

/// Validate the `oci-layout` marker bytes (`imageLayoutVersion == "1.0.0"`).
pub fn parse_layout_marker(bytes: &[u8]) -> Result<(), OciError> {
    let m: LayoutMarkerFile =
        serde_json::from_slice(bytes).map_err(|e| OciError::LayoutMarker(e.to_string()))?;
    if m.image_layout_version != "1.0.0" {
        return Err(OciError::LayoutMarker(format!(
            "unsupported imageLayoutVersion {:?}",
            m.image_layout_version
        )));
    }
    Ok(())
}

/// Require a full `sha256:<64hex>` descriptor digest.
fn require_sha256_digest(d: &str) -> Result<(), OciError> {
    match d.strip_prefix("sha256:") {
        Some(hex) if is_hex64(hex) => Ok(()),
        _ => Err(OciError::BadDigest(d.to_string())),
    }
}

/// Parse `index.json` into its manifest descriptors, validating every digest is a
/// full sha256 content address.
pub fn parse_index(index_json: &[u8]) -> Result<Vec<ManifestIdentity>, OciError> {
    let idx: IndexFile =
        serde_json::from_slice(index_json).map_err(|e| OciError::Parse(e.to_string()))?;
    if idx.manifests.is_empty() {
        return Err(OciError::NoManifests);
    }
    let mut out = Vec::with_capacity(idx.manifests.len());
    for d in idx.manifests {
        require_sha256_digest(&d.digest)?;
        out.push(ManifestIdentity {
            digest: d.digest,
            media_type: d.media_type,
            platform: d.platform.map(|p| Platform {
                architecture: p.architecture,
                os: p.os,
                variant: p.variant,
            }),
        });
    }
    Ok(out)
}

/// Select the single index manifest targeting `oci_arch` (`amd64` / `arm64`). A
/// single-manifest index with no platform descriptor is returned as-is. Zero or
/// more than one match is a hard failure — the recorded identity must be
/// unambiguous.
pub fn select_by_arch(
    manifests: &[ManifestIdentity],
    oci_arch: &str,
) -> Result<ManifestIdentity, OciError> {
    if manifests.len() == 1 && manifests[0].platform.is_none() {
        return Ok(manifests[0].clone());
    }
    let mut hits = manifests
        .iter()
        .filter(|m| m.platform.as_ref().map(|p| p.architecture.as_str()) == Some(oci_arch));
    let first = hits.next().ok_or(OciError::PlatformNotFound {
        arch: oci_arch.to_string(),
    })?;
    if hits.next().is_some() {
        return Err(OciError::AmbiguousPlatform {
            arch: oci_arch.to_string(),
        });
    }
    Ok(first.clone())
}

/// The on-disk path of a blob named by a `sha256:<hex>` digest.
fn blob_path(layout_root: &Path, digest: &str) -> Result<PathBuf, OciError> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| OciError::BadDigest(digest.to_string()))?;
    Ok(layout_root.join("blobs").join("sha256").join(hex))
}

/// Re-verify a manifest blob's content address: read `blobs/sha256/<hex>` and
/// require its SHA-256 to equal `<hex>`. This is the real content-addressing
/// integrity check — it proves the recorded manifest identity is the hash of the
/// actual manifest bytes, not a claim.
pub fn verify_blob_content_address(layout_root: &Path, digest: &str) -> Result<(), OciError> {
    let path = blob_path(layout_root, digest)?;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OciError::BlobMissing {
                digest: digest.to_string(),
            })
        }
        Err(e) => return Err(OciError::Io(e.to_string())),
    };
    let actual = sha256::hex_digest(&bytes);
    let want = digest.strip_prefix("sha256:").unwrap_or(digest);
    if actual != want {
        return Err(OciError::ContentAddressMismatch {
            digest: digest.to_string(),
            actual,
        });
    }
    Ok(())
}

/// Full extraction over a layout root: validate the marker, parse the index, select
/// the manifest for `oci_arch`, and re-verify its blob content address. Returns the
/// TRUE manifest identity (digest + media type + platform), never a tar hash.
pub fn extract_manifest_identity(
    layout_root: &Path,
    oci_arch: &str,
) -> Result<ManifestIdentity, OciError> {
    let marker =
        std::fs::read(layout_root.join("oci-layout")).map_err(|e| OciError::Io(e.to_string()))?;
    parse_layout_marker(&marker)?;
    let index =
        std::fs::read(layout_root.join("index.json")).map_err(|e| OciError::Io(e.to_string()))?;
    let manifests = parse_index(&index)?;
    let selected = select_by_arch(&manifests, oci_arch)?;
    verify_blob_content_address(layout_root, &selected.digest)?;
    Ok(selected)
}

/// Blocker 2: prove the image the runtime loaded is the exact verified image.
///
/// `build_container.sh` exports the OCI layout as `type=oci,dest=<tar>`; before any
/// lock-gen / audit / extractor / fixture can run INSIDE that image, the tar is
/// loaded into the runtime and the runtime's reported image identity must resolve
/// to `recorded` — the manifest digest [`extract_manifest_identity`] parsed from
/// the exported layout. This is the digest-equality check that makes
/// `oci:local/b0pre-<candidate>-<arch>` an image that provably IS the verified one,
/// not an invented reference. Both sides must be full non-synthetic `sha256:<64hex>`
/// digests, and they must be equal; anything else fails closed.
///
/// The load/run itself is venue-gated (no Docker off-venue); this equality decision
/// is pure and unit-tested.
pub fn verify_runtime_image_identity(
    recorded: &str,
    runtime_reported: &str,
) -> Result<String, OciError> {
    require_sha256_digest(recorded)?;
    require_sha256_digest(runtime_reported)?;
    if super::is_synthetic(recorded) || super::is_synthetic(runtime_reported) {
        return Err(OciError::BadDigest(if super::is_synthetic(recorded) {
            recorded.to_string()
        } else {
            runtime_reported.to_string()
        }));
    }
    if recorded != runtime_reported {
        return Err(OciError::RuntimeIdentityMismatch {
            recorded: recorded.to_string(),
            runtime: runtime_reported.to_string(),
        });
    }
    Ok(recorded.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmpdir() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "b0pre-oci-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(d.join("blobs").join("sha256")).unwrap();
        d
    }

    /// Write a manifest blob into the layout and return its true content address.
    fn write_blob(root: &Path, contents: &[u8]) -> String {
        let hex = sha256::hex_digest(contents);
        std::fs::write(root.join("blobs").join("sha256").join(&hex), contents).unwrap();
        format!("sha256:{hex}")
    }

    fn write_marker(root: &Path) {
        std::fs::write(
            root.join("oci-layout"),
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
    }

    #[test]
    fn extracts_true_manifest_digest_not_a_tar_hash() {
        let root = tmpdir();
        write_marker(&root);
        // A realistic (arbitrary) manifest blob; its content address is what the
        // index binds to. Crucially this is INDEPENDENT of how the layout is tarred.
        let manifest_blob = br#"{"schemaVersion":2,"config":{},"layers":[]}"#;
        let digest = write_blob(&root, manifest_blob);
        let index = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
                "manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json",
                "digest":"{digest}","size":{},"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#,
            manifest_blob.len()
        );
        std::fs::write(root.join("index.json"), index.as_bytes()).unwrap();

        let id = extract_manifest_identity(&root, "amd64").unwrap();
        assert_eq!(
            id.digest, digest,
            "identity is the manifest content address"
        );
        assert_eq!(id.platform.as_ref().unwrap().architecture, "amd64");
        assert_eq!(id.platform.as_ref().unwrap().os, "linux");

        // The manifest identity is the hash of the MANIFEST bytes...
        assert_eq!(
            id.digest,
            format!("sha256:{}", sha256::hex_digest(manifest_blob))
        );
        // ...and is NOT the hash of the index.json serialization (a "tar-shaped"
        // wrapper), demonstrating the fix's core distinction.
        let index_hash = format!("sha256:{}", sha256::hex_digest(index.as_bytes()));
        assert_ne!(id.digest, index_hash);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn selects_the_requested_arch_from_a_multi_platform_index() {
        let root = tmpdir();
        write_marker(&root);
        let amd = write_blob(&root, b"amd64-manifest-bytes");
        let arm = write_blob(&root, b"arm64-manifest-bytes");
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[
                {{"mediaType":"m","digest":"{amd}","size":1,"platform":{{"architecture":"amd64","os":"linux"}}}},
                {{"mediaType":"m","digest":"{arm}","size":1,"platform":{{"architecture":"arm64","os":"linux"}}}}
            ]}}"#
        );
        std::fs::write(root.join("index.json"), index.as_bytes()).unwrap();
        assert_eq!(
            extract_manifest_identity(&root, "amd64").unwrap().digest,
            amd
        );
        assert_eq!(
            extract_manifest_identity(&root, "arm64").unwrap().digest,
            arm
        );
        // an unrequested platform fails closed
        assert!(matches!(
            extract_manifest_identity(&root, "s390x"),
            Err(OciError::PlatformNotFound { .. })
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn tampered_blob_fails_content_address_check() {
        let root = tmpdir();
        write_marker(&root);
        // index claims a digest, but the stored blob's bytes differ -> mismatch.
        let claimed = format!("sha256:{}", sha256::hex_digest(b"the-real-manifest"));
        let hex = claimed.strip_prefix("sha256:").unwrap();
        std::fs::write(
            root.join("blobs").join("sha256").join(hex),
            b"TAMPERED-manifest-bytes",
        )
        .unwrap();
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"m","digest":"{claimed}","size":1,
                "platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#
        );
        std::fs::write(root.join("index.json"), index.as_bytes()).unwrap();
        assert!(matches!(
            extract_manifest_identity(&root, "amd64"),
            Err(OciError::ContentAddressMismatch { .. })
        ));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn missing_blob_and_bad_digest_fail_closed() {
        // referenced blob absent
        let root = tmpdir();
        write_marker(&root);
        let index = r#"{"schemaVersion":2,"manifests":[{"mediaType":"m",
            "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size":1,"platform":{"architecture":"amd64","os":"linux"}}]}"#;
        std::fs::write(root.join("index.json"), index).unwrap();
        assert!(matches!(
            extract_manifest_identity(&root, "amd64"),
            Err(OciError::BlobMissing { .. })
        ));
        std::fs::remove_dir_all(&root).ok();

        // a truncated / non-sha256 digest is rejected at parse time
        assert!(matches!(
            parse_index(br#"{"manifests":[{"digest":"sha256:deadbeef"}]}"#),
            Err(OciError::BadDigest(_))
        ));
        // a bad layout marker is rejected
        assert!(matches!(
            parse_layout_marker(br#"{"imageLayoutVersion":"9.9.9"}"#),
            Err(OciError::LayoutMarker(_))
        ));
    }

    #[test]
    fn runtime_image_identity_must_equal_the_recorded_manifest_digest() {
        let recorded = format!("sha256:{}", sha256::hex_digest(b"the-verified-image"));
        // the runtime loaded the exact same image -> resolves.
        assert_eq!(
            verify_runtime_image_identity(&recorded, &recorded).unwrap(),
            recorded
        );
        // the runtime is running a DIFFERENT image -> refused (no invented ref rides).
        let other = format!("sha256:{}", sha256::hex_digest(b"a-different-image"));
        assert!(matches!(
            verify_runtime_image_identity(&recorded, &other),
            Err(OciError::RuntimeIdentityMismatch { .. })
        ));
        // a truncated / synthetic runtime digest is refused before the equality test.
        assert!(matches!(
            verify_runtime_image_identity(&recorded, "sha256:deadbeef"),
            Err(OciError::BadDigest(_))
        ));
        assert!(matches!(
            verify_runtime_image_identity(&recorded, "sha256:TEST_ONLY_SYNTHETIC"),
            Err(OciError::BadDigest(_))
        ));
    }
}

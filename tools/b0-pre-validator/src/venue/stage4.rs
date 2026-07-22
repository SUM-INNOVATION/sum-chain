//! Blocker 3: Stage-4 verifier-material extraction runs INSIDE the verified builder
//! image, and RISC Zero extraction is x86_64-enforced at BOTH boundaries.
//!
//! `produce_arch` used to run `cargo run --manifest-path harness/...` on the HOST.
//! The authoritative path instead runs the extractor inside the exact verified
//! builder image (fails closed off-venue). Independent of where it runs, RISC Zero
//! Groth16 verifier-material extraction (`stark2snark`/`shrink_wrap`) MUST be native
//! x86_64 (VENUE.md §2): both the HOST kernel arch (`uname -m`) AND the CONTAINER
//! platform descriptor must be x86_64/amd64. Emulated (QEMU/Rosetta/buildx) results
//! are ineligible. This module owns that boundary decision and binds the extractor
//! output to the container it ran in; it is unit-tested off-venue.

use super::is_hex64;

/// Which extractor a Stage-4 run drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extractor {
    Sp1,
    Risc0,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage4Error {
    UnknownArch {
        which: &'static str,
        arch: String,
    },
    /// A build/extract host arch differed from the target arch (emulated).
    NonNativeHost {
        target: String,
        host: String,
    },
    /// The container platform differed from the target arch.
    NonNativeContainer {
        target: String,
        container: String,
    },
    /// RISC Zero extraction was attempted on a non-x86_64 host boundary.
    Risc0HostNotX86 {
        host: String,
    },
    /// RISC Zero extraction was attempted inside a non-x86_64 container boundary.
    Risc0ContainerNotX86 {
        container: String,
    },
    /// The extractor output was not bound to the builder image it ran in.
    BadContainerDigest {
        digest: String,
    },
    /// The extractor output hash was malformed.
    BadOutputHash,
}

impl std::fmt::Display for Stage4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stage4Error::UnknownArch { which, arch } => {
                write!(f, "{which} arch {arch:?} is not x86_64/amd64 or aarch64/arm64")
            }
            Stage4Error::NonNativeHost { target, host } => write!(
                f,
                "Stage-4 target {target} ran on host arch {host} (emulation is ineligible)"
            ),
            Stage4Error::NonNativeContainer { target, container } => write!(
                f,
                "Stage-4 target {target} ran in a {container} container (cross-platform ineligible)"
            ),
            Stage4Error::Risc0HostNotX86 { host } => write!(
                f,
                "RISC Zero extraction requires a native x86_64 host; host is {host} (VENUE.md §2)"
            ),
            Stage4Error::Risc0ContainerNotX86 { container } => write!(
                f,
                "RISC Zero extraction requires an x86_64 container; container platform is {container} (VENUE.md §2)"
            ),
            Stage4Error::BadContainerDigest { digest } => {
                write!(f, "Stage-4 output builder digest invalid: {digest:?}")
            }
            Stage4Error::BadOutputHash => write!(f, "Stage-4 output hash is not bare 64-hex"),
        }
    }
}

impl std::error::Error for Stage4Error {}

/// Normalize an arch spelling to `x86_64` / `aarch64`, or `None` if unrecognized.
fn norm_arch(a: &str) -> Option<&'static str> {
    match a {
        "x86_64" | "amd64" | "X86_64" => Some("x86_64"),
        "aarch64" | "arm64" | "Aarch64" => Some("aarch64"),
        _ => None,
    }
}

/// Enforce the Stage-4 architecture boundaries for one extractor run. The host
/// kernel arch and the container platform must both equal the target arch (no
/// emulation / cross-platform), and RISC Zero additionally requires that target
/// arch to be x86_64 at BOTH the host and container boundaries. Returns the
/// normalized target arch on success; fails closed otherwise.
pub fn enforce_stage4_arch(
    extractor: Extractor,
    target_arch: &str,
    host_arch: &str,
    container_arch: &str,
) -> Result<&'static str, Stage4Error> {
    let target = norm_arch(target_arch).ok_or_else(|| Stage4Error::UnknownArch {
        which: "target",
        arch: target_arch.to_string(),
    })?;
    let host = norm_arch(host_arch).ok_or_else(|| Stage4Error::UnknownArch {
        which: "host",
        arch: host_arch.to_string(),
    })?;
    let container = norm_arch(container_arch).ok_or_else(|| Stage4Error::UnknownArch {
        which: "container",
        arch: container_arch.to_string(),
    })?;
    // No emulation: host and container must both match the target.
    if host != target {
        return Err(Stage4Error::NonNativeHost {
            target: target.to_string(),
            host: host.to_string(),
        });
    }
    if container != target {
        return Err(Stage4Error::NonNativeContainer {
            target: target.to_string(),
            container: container.to_string(),
        });
    }
    // RISC Zero is x86_64-only at BOTH boundaries.
    if matches!(extractor, Extractor::Risc0) {
        if host != "x86_64" {
            return Err(Stage4Error::Risc0HostNotX86 {
                host: host.to_string(),
            });
        }
        if container != "x86_64" {
            return Err(Stage4Error::Risc0ContainerNotX86 {
                container: container.to_string(),
            });
        }
    }
    Ok(target)
}

/// Bind a Stage-4 extractor output to the exact builder image it ran inside: the
/// arch boundary must hold AND the output must carry the builder `sha256:<64hex>`
/// digest and a bare-64-hex output hash. This is the anti-forgery binding that makes
/// the extractor JSON evidence from a specific verified image, not a free-floating
/// file.
pub fn bind_extractor_output(
    extractor: Extractor,
    target_arch: &str,
    host_arch: &str,
    container_arch: &str,
    builder_digest: &str,
    output_blake3_hex: &str,
) -> Result<&'static str, Stage4Error> {
    let target = enforce_stage4_arch(extractor, target_arch, host_arch, container_arch)?;
    match builder_digest.strip_prefix("sha256:") {
        Some(hex) if is_hex64(hex) && !super::is_synthetic(builder_digest) => {}
        _ => {
            return Err(Stage4Error::BadContainerDigest {
                digest: builder_digest.to_string(),
            })
        }
    }
    if !is_hex64(output_blake3_hex) {
        return Err(Stage4Error::BadOutputHash);
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sp1_extraction_is_native_on_either_arch() {
        assert_eq!(
            enforce_stage4_arch(Extractor::Sp1, "x86_64", "x86_64", "amd64"),
            Ok("x86_64")
        );
        assert_eq!(
            enforce_stage4_arch(Extractor::Sp1, "aarch64", "aarch64", "arm64"),
            Ok("aarch64")
        );
    }

    #[test]
    fn risc0_extraction_requires_x86_64_at_both_boundaries() {
        // native x86_64 both sides -> ok.
        assert_eq!(
            enforce_stage4_arch(Extractor::Risc0, "x86_64", "x86_64", "amd64"),
            Ok("x86_64")
        );
        // targeting aarch64 for RISC Zero is refused (host not x86 even if native).
        assert!(matches!(
            enforce_stage4_arch(Extractor::Risc0, "aarch64", "aarch64", "arm64"),
            Err(Stage4Error::Risc0HostNotX86 { .. })
        ));
    }

    #[test]
    fn an_emulated_host_is_refused() {
        // x86_64 target built on an arm host (Rosetta/QEMU) -> not native.
        assert!(matches!(
            enforce_stage4_arch(Extractor::Sp1, "x86_64", "aarch64", "amd64"),
            Err(Stage4Error::NonNativeHost { .. })
        ));
    }

    #[test]
    fn a_cross_platform_container_is_refused() {
        // native x86 host but the container is an arm64 platform (buildx cross) -> refused.
        assert!(matches!(
            enforce_stage4_arch(Extractor::Sp1, "x86_64", "x86_64", "arm64"),
            Err(Stage4Error::NonNativeContainer { .. })
        ));
    }

    #[test]
    fn risc0_on_an_x86_host_but_emulated_arm_container_is_refused() {
        // A RISC Zero run that is x86 at the host but ran in an emulated arm64
        // container is refused before the x86 container check even matters.
        assert!(matches!(
            enforce_stage4_arch(Extractor::Risc0, "x86_64", "x86_64", "arm64"),
            Err(Stage4Error::NonNativeContainer { .. })
        ));
    }

    #[test]
    fn binding_requires_a_real_builder_digest_and_output_hash() {
        let d = format!("sha256:{}", super::super::sha256::hex_digest(b"builder"));
        let h = super::super::to_hex(blake3::hash(b"out").as_bytes());
        assert_eq!(
            bind_extractor_output(Extractor::Sp1, "x86_64", "x86_64", "amd64", &d, &h),
            Ok("x86_64")
        );
        // synthetic builder digest -> refused.
        assert!(matches!(
            bind_extractor_output(
                Extractor::Sp1,
                "x86_64",
                "x86_64",
                "amd64",
                "TEST_ONLY_SYNTHETIC://x",
                &h
            ),
            Err(Stage4Error::BadContainerDigest { .. })
        ));
        // bad output hash -> refused.
        assert!(matches!(
            bind_extractor_output(Extractor::Sp1, "x86_64", "x86_64", "amd64", &d, "nope"),
            Err(Stage4Error::BadOutputHash)
        ));
    }
}

//! `HostToolchainAttestationV1` — the venue-produced authority binding the NATIVE per-arch cargo/rustc
//! the runner was built with (x86 1.90.0 / ARM 1.88.0). Parsed from the retained JSON
//! `lib.sh:b0_host_toolchain_attestation` emits; its VENUE-INDEPENDENT content `address` is recomputed
//! here and required to equal both the record's own `address` and the address `RunnerAttestationV1`
//! binds. Host-specific paths + file counts are recorded for provenance but DELIBERATELY excluded from
//! the address (so the identity is reproducible across venues).
//!
//! Address preimage MIRRORS lib.sh EXACTLY (NUL-joined, UTF-8, SHA-256):
//!   domain \0 arch \0 requested_toolchain \0 cargo_version_verbose \0 rustc_vV
//!   \0 cargo_sha256 \0 cargo_blake3 \0 rustc_sha256 \0 rustc_blake3 \0 sysroot_address

use serde::Deserialize;

pub const HOST_TOOLCHAIN_SCHEMA: &str = "b0-final-runner-host-toolchain/v1";

#[derive(Debug, Clone, Deserialize)]
pub struct HostToolchainAttestationV1 {
    pub schema: String,
    pub arch: String,
    pub requested_toolchain: String,
    pub cargo_version_verbose: String,
    /// `rustc -vV` verbatim. The JSON key is `rustc_vV` (lib.sh).
    #[serde(rename = "rustc_vV")]
    pub rustc_vv: String,
    pub cargo_sha256: String,
    pub cargo_blake3: String,
    pub rustc_sha256: String,
    pub rustc_blake3: String,
    pub sysroot_address: String,
    pub address: String,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex32(s: &str) -> Result<[u8; 32], String> {
    if !is_hex64(s) {
        return Err(format!(
            "host-toolchain address {s:?} is not 64 lowercase-hex"
        ));
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

impl HostToolchainAttestationV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("host-toolchain JSON parse: {e}"))
    }

    pub fn recompute_address(&self) -> String {
        let pre = [
            HOST_TOOLCHAIN_SCHEMA,
            &self.arch,
            &self.requested_toolchain,
            &self.cargo_version_verbose,
            &self.rustc_vv,
            &self.cargo_sha256,
            &self.cargo_blake3,
            &self.rustc_sha256,
            &self.rustc_blake3,
            &self.sysroot_address,
        ]
        .join("\0");
        crate::venue::sha256::hex_digest(pre.as_bytes())
    }

    /// Verify the record matches the expected arch + ratified per-arch toolchain and recomputes to its
    /// own address. Returns the 32-byte address. `expect_toolchain` is the ratified per-arch pin
    /// (x86_64→"1.90.0", aarch64→"1.88.0"); pass `None` to skip that check (e.g. structural tests).
    pub fn verify(
        &self,
        expect_arch: &str,
        expect_toolchain: Option<&str>,
    ) -> Result<[u8; 32], String> {
        if self.schema != HOST_TOOLCHAIN_SCHEMA {
            return Err(format!(
                "host-toolchain schema {:?} != {HOST_TOOLCHAIN_SCHEMA}",
                self.schema
            ));
        }
        if self.arch != expect_arch {
            return Err(format!(
                "host-toolchain arch {:?} != expected {expect_arch:?}",
                self.arch
            ));
        }
        if let Some(tc) = expect_toolchain {
            if self.requested_toolchain != tc {
                return Err(format!(
                    "host-toolchain requested_toolchain {:?} != ratified {tc:?}",
                    self.requested_toolchain
                ));
            }
        }
        for (name, v) in [
            ("cargo_sha256", &self.cargo_sha256),
            ("cargo_blake3", &self.cargo_blake3),
            ("rustc_sha256", &self.rustc_sha256),
            ("rustc_blake3", &self.rustc_blake3),
            ("sysroot_address", &self.sysroot_address),
        ] {
            if !is_hex64(v) {
                return Err(format!("host-toolchain {name} not 64-hex"));
            }
        }
        let recomputed = self.recompute_address();
        if recomputed != self.address {
            return Err(format!(
                "host-toolchain recomputed address {recomputed} != recorded {}",
                self.address
            ));
        }
        hex32(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(arch: &str, tc: &str) -> HostToolchainAttestationV1 {
        let mut d = HostToolchainAttestationV1 {
            schema: HOST_TOOLCHAIN_SCHEMA.into(),
            arch: arch.into(),
            requested_toolchain: tc.into(),
            cargo_version_verbose: "cargo 1.90.0 (840b83a10 2025-07-30)".into(),
            rustc_vv: "rustc 1.90.0 (1159e78c4 2025-09-14)".into(),
            cargo_sha256: "1".repeat(64),
            cargo_blake3: "2".repeat(64),
            rustc_sha256: "3".repeat(64),
            rustc_blake3: "4".repeat(64),
            sysroot_address: "5".repeat(64),
            address: String::new(),
        };
        d.address = d.recompute_address();
        d
    }

    #[test]
    fn recompute_verifies_and_binds_arch_toolchain() {
        let d = rec("x86_64", "1.90.0");
        assert_eq!(d.recompute_address(), d.address);
        assert!(d.verify("x86_64", Some("1.90.0")).is_ok());
        assert!(d.verify("aarch64", Some("1.90.0")).is_err()); // wrong arch
        assert!(d.verify("x86_64", Some("1.88.0")).is_err()); // wrong toolchain pin
    }

    #[test]
    fn tamper_identity_field_breaks_address() {
        let base = rec("aarch64", "1.88.0");
        let a0 = base.address.clone();
        let mut t = rec("aarch64", "1.88.0");
        t.rustc_sha256 = "9".repeat(64);
        assert_ne!(t.recompute_address(), a0);
        let mut t2 = rec("aarch64", "1.88.0");
        t2.address = "0".repeat(64);
        assert!(t2.verify("aarch64", Some("1.88.0")).is_err());
    }
}

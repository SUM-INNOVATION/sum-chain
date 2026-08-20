//! `ProtocAuthorityV1` — the venue-produced NATIVE protoc authority (SP1 only; RISC0 needs no protoc).
//! Binds the protoc version + executable SHA-256/BLAKE3 and the committed protobuf-include-authority
//! content address. Parsed from the retained JSON `lib.sh:b0_protoc_authority` emits; its
//! venue-independent `address` is recomputed here and required to equal both the record's own `address`
//! and the address `RunnerAttestationV1` binds.
//!
//! Address preimage MIRRORS lib.sh EXACTLY (NUL-joined, UTF-8, SHA-256):
//!   domain \0 candidate \0 arch \0 protoc_version \0 protoc_sha256 \0 protoc_blake3 \0 include_address

use serde::Deserialize;

pub const PROTOC_AUTHORITY_SCHEMA: &str = "b0-final-runner-protoc-authority/v1";
/// The exact protoc version the venue must report.
pub const RATIFIED_PROTOC_VERSION: &str = "libprotoc 3.21.12";

#[derive(Debug, Clone, Deserialize)]
pub struct ProtocAuthorityV1 {
    pub schema: String,
    pub candidate: String,
    pub arch: String,
    pub protoc_version: String,
    pub protoc_sha256: String,
    pub protoc_blake3: String,
    pub include_address: String,
    pub include_file_count: u64,
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
            "protoc-authority address {s:?} is not 64 lowercase-hex"
        ));
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

impl ProtocAuthorityV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("protoc-authority JSON parse: {e}"))
    }

    pub fn recompute_address(&self) -> String {
        let pre = [
            PROTOC_AUTHORITY_SCHEMA,
            &self.candidate,
            &self.arch,
            &self.protoc_version,
            &self.protoc_sha256,
            &self.protoc_blake3,
            &self.include_address,
        ]
        .join("\0");
        crate::venue::sha256::hex_digest(pre.as_bytes())
    }

    pub fn verify(&self, expect_candidate: &str, expect_arch: &str) -> Result<[u8; 32], String> {
        if self.schema != PROTOC_AUTHORITY_SCHEMA {
            return Err(format!(
                "protoc-authority schema {:?} != {PROTOC_AUTHORITY_SCHEMA}",
                self.schema
            ));
        }
        if self.candidate != expect_candidate {
            return Err(format!(
                "protoc-authority candidate {:?} != {expect_candidate:?}",
                self.candidate
            ));
        }
        if self.arch != expect_arch {
            return Err(format!(
                "protoc-authority arch {:?} != {expect_arch:?}",
                self.arch
            ));
        }
        if self.protoc_version != RATIFIED_PROTOC_VERSION {
            return Err(format!(
                "protoc-authority version {:?} != ratified {RATIFIED_PROTOC_VERSION:?}",
                self.protoc_version
            ));
        }
        if self.include_file_count == 0 {
            return Err("protoc-authority include tree is empty".into());
        }
        for (name, v) in [
            ("protoc_sha256", &self.protoc_sha256),
            ("protoc_blake3", &self.protoc_blake3),
            ("include_address", &self.include_address),
        ] {
            if !is_hex64(v) {
                return Err(format!("protoc-authority {name} not 64-hex"));
            }
        }
        let recomputed = self.recompute_address();
        if recomputed != self.address {
            return Err(format!(
                "protoc-authority recomputed address {recomputed} != recorded {}",
                self.address
            ));
        }
        hex32(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> ProtocAuthorityV1 {
        let mut d = ProtocAuthorityV1 {
            schema: PROTOC_AUTHORITY_SCHEMA.into(),
            candidate: "sp1".into(),
            arch: "aarch64".into(),
            protoc_version: RATIFIED_PROTOC_VERSION.into(),
            protoc_sha256: "1".repeat(64),
            protoc_blake3: "2".repeat(64),
            include_address: "3".repeat(64),
            include_file_count: 1,
            address: String::new(),
        };
        d.address = d.recompute_address();
        d
    }

    #[test]
    fn recompute_verifies() {
        let d = rec();
        assert!(d.verify("sp1", "aarch64").is_ok());
        assert!(d.verify("risc0", "aarch64").is_err()); // wrong candidate
    }

    #[test]
    fn refuses_wrong_version_empty_include_and_tamper() {
        let mut d = rec();
        d.protoc_version = "libprotoc 4.0.0".into();
        d.address = d.recompute_address();
        assert!(d.verify("sp1", "aarch64").is_err());
        let mut e = rec();
        e.include_file_count = 0;
        assert!(e.verify("sp1", "aarch64").is_err());
        let mut f = rec();
        f.protoc_sha256 = "9".repeat(64); // address no longer matches
        assert!(f.verify("sp1", "aarch64").is_err());
    }
}

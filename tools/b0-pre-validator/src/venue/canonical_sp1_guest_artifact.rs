//! `CanonicalSp1GuestArtifactV1` — the ONE canonical SP1 zkVM guest ELF, built once on the ratified
//! x86_64 authority and distributed VERBATIM to every proving architecture. SP1's per-arch succinct
//! cross-compiler does not emit a byte-identical guest across build hosts, so the grid's shared-program
//! requirement is met by sealing a single ELF here and having every arch consume THESE bytes — no
//! architecture may `cargo prove build` the official guest.
//!
//! Address (venue-authority family): SHA-256 over a NUL-joined UTF-8 preimage, mirrored EXACTLY by the
//! producer `scripts/produce_canonical_sp1_guest.sh`. The verifier decodes from scratch, recomputes the
//! address, and recomputes every identity derivable from the retained ELF bytes (size, sha256, blake3,
//! guest_image_hash) — `program_id` (the SP1 verifying-key hash) is bound by equality (only the real SP1
//! SDK can derive it; the consuming runner recomputes it from the same retained ELF).

use serde::{Deserialize, Serialize};

pub const CANONICAL_SP1_GUEST_ARTIFACT_SCHEMA: &str = "b0-final-canonical-sp1-guest-artifact/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildLeg {
    pub elf_sha256: String,
    pub elf_blake3: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DoubleBuildProof {
    pub byte_identical: bool,
    pub cmp_ok: bool,
    pub sha256_equal: bool,
    pub blake3_equal: bool,
    pub wallclock_separated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CanonicalSp1GuestArtifactV1 {
    pub schema: String,
    pub candidate: String,
    pub canonical_build_arch: String,
    pub measured_source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub staged_context_blake3: String,
    pub guest_lock_sha256: String,
    pub guest_lock_blake3: String,
    pub dependency_seed_address: String,
    pub vendor_config_sha256: String,
    pub builder_image_id: String,
    pub builder_config_digest: String,
    pub builder_platform: String,
    pub sp1_toolchain_identity: String,
    pub build_argv: String,
    pub build_env_address: String,
    pub command_log_address: String,
    pub build_a: BuildLeg,
    pub build_b: BuildLeg,
    pub double_build_proof: DoubleBuildProof,
    pub elf_size: u64,
    pub elf_sha256: String,
    pub elf_blake3: String,
    pub program_id: String,
    pub guest_image_hash: String,
    pub address: String,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_hex40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex32(s: &str) -> Result<[u8; 32], String> {
    if !is_hex64(s) {
        return Err(format!(
            "canonical-sp1-guest address {s:?} is not 64 lowercase-hex"
        ));
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] =
            u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn blake3_hex(bytes: &[u8]) -> String {
    let d = blake3::hash(bytes);
    let mut s = String::with_capacity(64);
    use std::fmt::Write as _;
    for b in d.as_bytes() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl CanonicalSp1GuestArtifactV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("canonical-sp1-guest JSON parse: {e}"))
    }

    /// SHA-256 over the NUL-joined preimage — MUST match the producer's python byte-for-byte.
    pub fn recompute_address(&self) -> String {
        let pre = [
            self.schema.as_str(),
            self.candidate.as_str(),
            self.canonical_build_arch.as_str(),
            self.measured_source_commit.as_str(),
            self.tooling_commit.as_str(),
            self.tooling_pathset_blake3.as_str(),
            self.staged_context_blake3.as_str(),
            self.guest_lock_sha256.as_str(),
            self.guest_lock_blake3.as_str(),
            self.dependency_seed_address.as_str(),
            self.vendor_config_sha256.as_str(),
            self.builder_image_id.as_str(),
            self.builder_config_digest.as_str(),
            self.builder_platform.as_str(),
            self.sp1_toolchain_identity.as_str(),
            self.build_argv.as_str(),
            self.build_env_address.as_str(),
            self.command_log_address.as_str(),
            self.build_a.elf_sha256.as_str(),
            self.build_b.elf_sha256.as_str(),
        ]
        .join("\0");
        let size = self.elf_size.to_string();
        let tail = [
            size.as_str(),
            self.elf_sha256.as_str(),
            self.elf_blake3.as_str(),
            self.program_id.as_str(),
            self.guest_image_hash.as_str(),
        ]
        .join("\0");
        let full = format!("{pre}\0{tail}");
        crate::venue::sha256::hex_digest(full.as_bytes())
    }

    /// Shape + double-build proof + address self-consistency. Does NOT need the ELF bytes.
    pub fn verify(&self, expect_measured_commit: &str) -> Result<[u8; 32], String> {
        if self.schema != CANONICAL_SP1_GUEST_ARTIFACT_SCHEMA {
            return Err(format!(
                "canonical-sp1-guest schema {:?} != {CANONICAL_SP1_GUEST_ARTIFACT_SCHEMA}",
                self.schema
            ));
        }
        if self.candidate != "sp1" {
            return Err(format!(
                "canonical-sp1-guest candidate {:?} != sp1",
                self.candidate
            ));
        }
        if self.canonical_build_arch != "x86_64" {
            return Err(format!(
                "canonical guest authority arch {:?} != x86_64 (canonical build authority is x86_64 only)",
                self.canonical_build_arch
            ));
        }
        if self.builder_platform != "linux/amd64" {
            return Err(format!(
                "canonical guest builder platform {:?} != linux/amd64",
                self.builder_platform
            ));
        }
        if !is_hex40(&self.measured_source_commit)
            || self.measured_source_commit != expect_measured_commit
        {
            return Err(format!(
                "canonical guest measured_source_commit {} != ratified {expect_measured_commit}",
                self.measured_source_commit
            ));
        }
        // double-build proof: every gate true, and BOTH legs equal the sealed ELF.
        let p = &self.double_build_proof;
        if !(p.byte_identical
            && p.cmp_ok
            && p.sha256_equal
            && p.blake3_equal
            && p.wallclock_separated)
        {
            return Err(
                "canonical guest double-build proof is incomplete / not reproducible".into(),
            );
        }
        if self.build_a.elf_sha256 != self.elf_sha256 || self.build_b.elf_sha256 != self.elf_sha256
        {
            return Err(
                "canonical guest A/B double-build proof does not match the sealed ELF sha256"
                    .into(),
            );
        }
        if self.build_a.elf_blake3 != self.elf_blake3 || self.build_b.elf_blake3 != self.elf_blake3
        {
            return Err(
                "canonical guest A/B double-build proof does not match the sealed ELF blake3"
                    .into(),
            );
        }
        for (name, v) in [
            ("tooling_pathset_blake3", &self.tooling_pathset_blake3),
            ("guest_lock_sha256", &self.guest_lock_sha256),
            ("guest_lock_blake3", &self.guest_lock_blake3),
            ("dependency_seed_address", &self.dependency_seed_address),
            ("vendor_config_sha256", &self.vendor_config_sha256),
            ("sp1_toolchain_identity", &self.sp1_toolchain_identity),
            ("build_env_address", &self.build_env_address),
            ("command_log_address", &self.command_log_address),
            ("elf_sha256", &self.elf_sha256),
            ("elf_blake3", &self.elf_blake3),
            ("program_id", &self.program_id),
            ("guest_image_hash", &self.guest_image_hash),
        ] {
            if !is_hex64(v) {
                return Err(format!("canonical-sp1-guest {name} not 64-hex"));
            }
        }
        if !is_hex40(&self.tooling_commit) {
            return Err("canonical-sp1-guest tooling_commit not 40-hex".into());
        }
        let recomputed = self.recompute_address();
        if recomputed != self.address {
            return Err(format!(
                "canonical-sp1-guest recomputed address {recomputed} != recorded {}",
                self.address
            ));
        }
        hex32(&self.address)
    }

    /// Recompute EVERY identity derivable from the retained ELF bytes and require equality with the
    /// sealed manifest. `program_id` (SP1 vkey hash) is NOT re-derivable here (no SP1 SDK) — it is bound
    /// by equality where the consuming runner recomputes it from these same bytes.
    pub fn verify_elf(&self, elf: &[u8]) -> Result<(), String> {
        if elf.len() as u64 != self.elf_size {
            return Err(format!(
                "canonical guest ELF size {} != sealed {}",
                elf.len(),
                self.elf_size
            ));
        }
        let sha = crate::venue::sha256::hex_digest(elf);
        if sha != self.elf_sha256 {
            return Err("canonical guest ELF sha256 mismatch (bytes changed)".into());
        }
        let bl = blake3_hex(elf);
        if bl != self.elf_blake3 {
            return Err("canonical guest ELF blake3 mismatch (bytes changed)".into());
        }
        if bl != self.guest_image_hash {
            return Err("canonical guest guest_image_hash != blake3(ELF)".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art() -> CanonicalSp1GuestArtifactV1 {
        let mut a = CanonicalSp1GuestArtifactV1 {
            schema: CANONICAL_SP1_GUEST_ARTIFACT_SCHEMA.into(),
            candidate: "sp1".into(),
            canonical_build_arch: "x86_64".into(),
            measured_source_commit: "5".repeat(40),
            tooling_commit: "a".repeat(40),
            tooling_pathset_blake3: "1".repeat(64),
            staged_context_blake3: String::new(),
            guest_lock_sha256: "2".repeat(64),
            guest_lock_blake3: "3".repeat(64),
            dependency_seed_address: "4".repeat(64),
            vendor_config_sha256: "5".repeat(64),
            builder_image_id: "db450e1a".into(),
            builder_config_digest: "db450e1a".into(),
            builder_platform: "linux/amd64".into(),
            sp1_toolchain_identity: "6".repeat(64),
            build_argv: "cargo prove build --locked --offline".into(),
            build_env_address: "7".repeat(64),
            command_log_address: "8".repeat(64),
            build_a: BuildLeg {
                elf_sha256: "9".repeat(64),
                elf_blake3: "a".repeat(64),
            },
            build_b: BuildLeg {
                elf_sha256: "9".repeat(64),
                elf_blake3: "a".repeat(64),
            },
            double_build_proof: DoubleBuildProof {
                byte_identical: true,
                cmp_ok: true,
                sha256_equal: true,
                blake3_equal: true,
                wallclock_separated: true,
            },
            elf_size: 3,
            elf_sha256: "9".repeat(64),
            elf_blake3: "a".repeat(64),
            program_id: "b".repeat(64),
            guest_image_hash: "a".repeat(64),
            address: String::new(),
        };
        a.address = a.recompute_address();
        a
    }

    #[test]
    fn recompute_verifies_and_rejects_tamper() {
        let a = art();
        assert!(a.verify(&"5".repeat(40)).is_ok());
        // wrong measured commit
        assert!(a.verify(&"6".repeat(40)).is_err());
        // tamper a field without updating address
        let mut t = art();
        t.program_id = "c".repeat(64);
        assert!(t.verify(&"5".repeat(40)).is_err());
    }

    #[test]
    fn rejects_bad_double_build_and_arch() {
        let mut a = art();
        a.double_build_proof.byte_identical = false;
        a.address = a.recompute_address();
        assert!(a.verify(&"5".repeat(40)).is_err());
        let mut b = art();
        b.canonical_build_arch = "aarch64".into();
        b.address = b.recompute_address();
        assert!(b.verify(&"5".repeat(40)).is_err());
        // A/B leg disagreeing with sealed ELF
        let mut c = art();
        c.build_b.elf_sha256 = "e".repeat(64);
        c.address = c.recompute_address();
        assert!(c.verify(&"5".repeat(40)).is_err());
    }

    #[test]
    fn verify_elf_recomputes_from_bytes() {
        // build an artifact whose hashes match real bytes
        let elf = b"canonical-elf-bytes";
        let sha = crate::venue::sha256::hex_digest(elf);
        let bl = blake3_hex(elf);
        let mut a = art();
        a.elf_size = elf.len() as u64;
        a.elf_sha256 = sha.clone();
        a.elf_blake3 = bl.clone();
        a.guest_image_hash = bl.clone();
        a.build_a.elf_sha256 = sha.clone();
        a.build_b.elf_sha256 = sha.clone();
        a.build_a.elf_blake3 = bl.clone();
        a.build_b.elf_blake3 = bl.clone();
        a.address = a.recompute_address();
        assert!(a.verify(&"5".repeat(40)).is_ok());
        assert!(a.verify_elf(elf).is_ok());
        // a changed ELF (even 1 byte) is refused
        assert!(a.verify_elf(b"canonical-elf-byteX").is_err());
    }
}

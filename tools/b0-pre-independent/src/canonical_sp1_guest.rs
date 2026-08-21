//! INDEPENDENT re-decode of `CanonicalSp1GuestArtifactV1` — the second, from-scratch verifier of the
//! ONE canonical SP1 guest ELF that is built on the x86 authority and distributed to every proving
//! arch. This crate shares NO code with `b0-pre-validator`: it carries its OWN dependency-free SHA-256
//! (the artifact address is SHA-256 over a NUL-joined preimage) so that agreement between the two
//! verifiers is genuine independent corroboration, not a shared bug. It recomputes the artifact address
//! and every identity derivable from the retained ELF bytes (size, sha256, blake3, guest_image_hash);
//! `program_id` (the SP1 verifying-key hash) is bound by equality, as only the SP1 SDK can derive it.

use serde::Deserialize;

// ---- own SHA-256 (FIPS 180-4), independent of the reference crate's copy ----------------------
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = H0;
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let b = i * 4;
            *word = u32::from_be_bytes([block[b], block[b + 1], block[b + 2], block[b + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (dst, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *dst = dst.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    use std::fmt::Write as _;
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}
fn sha256_hex(data: &[u8]) -> String {
    to_hex(&sha256(data))
}
fn blake3_hex(data: &[u8]) -> String {
    to_hex(crate::plain(data).as_slice()) // crate::plain = BLAKE3(data)
}

pub const CANONICAL_SP1_GUEST_ARTIFACT_SCHEMA: &str = "b0-final-canonical-sp1-guest-artifact/v1";

#[derive(Debug, Clone, Deserialize)]
struct Leg {
    elf_sha256: String,
    elf_blake3: String,
}
#[derive(Debug, Clone, Deserialize)]
struct Proof {
    byte_identical: bool,
    cmp_ok: bool,
    sha256_equal: bool,
    blake3_equal: bool,
    wallclock_separated: bool,
}
#[derive(Debug, Clone, Deserialize)]
pub struct CanonicalSp1GuestArtifact {
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
    build_a: Leg,
    build_b: Leg,
    double_build_proof: Proof,
    pub elf_size: u64,
    pub elf_sha256: String,
    pub elf_blake3: String,
    pub program_id: String,
    pub guest_image_hash: String,
    pub address: String,
}

impl CanonicalSp1GuestArtifact {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("canonical-sp1-guest JSON parse: {e}"))
    }

    /// Independent SHA-256 recompute over the SAME NUL-joined preimage the producer used.
    pub fn recompute_address(&self) -> String {
        let parts = [
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
        ];
        let size = self.elf_size.to_string();
        let tail = [
            size.as_str(),
            self.elf_sha256.as_str(),
            self.elf_blake3.as_str(),
            self.program_id.as_str(),
            self.guest_image_hash.as_str(),
        ];
        let pre = format!("{}\0{}", parts.join("\0"), tail.join("\0"));
        sha256_hex(pre.as_bytes())
    }

    /// From-scratch verification: shape, double-build proof, and address self-consistency.
    pub fn verify(&self, expect_measured_commit: &str) -> Result<(), String> {
        if self.schema != CANONICAL_SP1_GUEST_ARTIFACT_SCHEMA {
            return Err("independent: wrong canonical-sp1-guest schema".into());
        }
        if self.candidate != "sp1" || self.canonical_build_arch != "x86_64" {
            return Err("independent: canonical guest must be sp1 / x86_64 authority".into());
        }
        if self.builder_platform != "linux/amd64" {
            return Err("independent: canonical guest builder platform != linux/amd64".into());
        }
        if self.measured_source_commit != expect_measured_commit {
            return Err("independent: canonical guest measured_source_commit mismatch".into());
        }
        let p = &self.double_build_proof;
        if !(p.byte_identical
            && p.cmp_ok
            && p.sha256_equal
            && p.blake3_equal
            && p.wallclock_separated)
        {
            return Err("independent: canonical guest double-build proof incomplete".into());
        }
        if self.build_a.elf_sha256 != self.elf_sha256
            || self.build_b.elf_sha256 != self.elf_sha256
            || self.build_a.elf_blake3 != self.elf_blake3
            || self.build_b.elf_blake3 != self.elf_blake3
        {
            return Err("independent: A/B double-build proof does not match sealed ELF".into());
        }
        if self.recompute_address() != self.address {
            return Err("independent: canonical guest address recompute mismatch".into());
        }
        Ok(())
    }

    /// Recompute every identity derivable from the retained ELF bytes and require equality.
    pub fn verify_elf(&self, elf: &[u8]) -> Result<(), String> {
        if elf.len() as u64 != self.elf_size {
            return Err("independent: canonical guest ELF size mismatch".into());
        }
        if sha256_hex(elf) != self.elf_sha256 {
            return Err("independent: canonical guest ELF sha256 mismatch".into());
        }
        let bl = blake3_hex(elf);
        if bl != self.elf_blake3 || bl != self.guest_image_hash {
            return Err(
                "independent: canonical guest ELF blake3 / guest_image_hash mismatch".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_sha256_matches_fips_vectors() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn independent_recompute_of_real_artifact() {
        // The SAME real fixture the reference verifier cross-checks: independent decode + address
        // recompute must reach the identical value (genuine second-source corroboration).
        let bytes = include_bytes!("../tests/fixtures/real_canonical_sp1_guest.json");
        let a = CanonicalSp1GuestArtifact::from_json(bytes).expect("parse");
        assert_eq!(
            a.recompute_address(),
            a.address,
            "independent SHA-256 preimage drift"
        );
        a.verify("507281e21e95a6a98e3480e25e12d1baab586e07")
            .expect("verify");
    }
}

//! INDEPENDENT re-decode of `MalformedCorpusReportV1` — the second, from-scratch verifier of the
//! retained malformed-corpus evidence. Shares NO code with `b0-pre-validator`: it carries its OWN
//! SHA-256 (the report address is SHA-256 over a NUL-joined preimage) so agreement with the reference
//! verifier is genuine second-source corroboration. Recomputes the address + every member's BLAKE3 from
//! the retained bytes, and refuses count/order/duplicate/byte-mismatch/ill-formed-or-mismatched-class.

use serde::Deserialize;

pub const MALFORMED_CORPUS_REPORT_SCHEMA: &str = "b0-final-malformed-corpus-report/v1";
pub const MALFORMED_CORPUS_DOMAIN: &str = "b0-final-malformed-corpus/v1";
pub const DECODE_VARIANT_COUNT: u16 = 12;
pub const SEMANTIC_REASON_COUNT: u16 = 40;

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
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
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
pub(crate) fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    use std::fmt::Write as _;
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RefusalClass {
    pub kind: String,
    pub code: u16,
}
impl RefusalClass {
    fn is_well_formed(&self) -> bool {
        match self.kind.as_str() {
            "decode" => self.code < DECODE_VARIANT_COUNT,
            "semantic" => self.code < SEMANTIC_REASON_COUNT,
            _ => false,
        }
    }
    fn canon(&self) -> String {
        format!("{}:{}", self.kind, self.code)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorpusMember {
    pub index: u32,
    pub statement_kind: String,
    pub name: String,
    pub member_bytes_hex: String,
    pub member_blake3: String,
    pub member_len: u32,
    pub expected_class: RefusalClass,
    pub actual_class: RefusalClass,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MalformedCorpusReport {
    pub schema: String,
    pub corpus_domain: String,
    pub b0_pre_spec_hash: String,
    pub measured_source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub member_count: u32,
    pub members: Vec<CorpusMember>,
    pub address: String,
}

fn is_hex_of(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl MalformedCorpusReport {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("independent: malformed-corpus parse: {e}"))
    }

    /// Independent SHA-256 recompute over the SAME NUL-joined preimage the generator + reference use.
    pub fn recompute_address(&self) -> String {
        let mut parts: Vec<String> = vec![
            self.schema.clone(),
            self.corpus_domain.clone(),
            self.b0_pre_spec_hash.clone(),
            self.measured_source_commit.clone(),
            self.tooling_commit.clone(),
            self.tooling_pathset_blake3.clone(),
            self.member_count.to_string(),
        ];
        for m in &self.members {
            parts.push(m.index.to_string());
            parts.push(m.statement_kind.clone());
            parts.push(m.member_blake3.clone());
            parts.push(m.member_len.to_string());
            parts.push(m.expected_class.canon());
            parts.push(m.actual_class.canon());
        }
        to_hex(&sha256(parts.join("\0").as_bytes()))
    }

    /// From-scratch structural verification (mirrors the reference verifier). Returns the 32-byte
    /// address on success.
    pub fn verify(
        &self,
        expect_measured_commit: &str,
        expect_spec_hash: &str,
    ) -> Result<[u8; 32], String> {
        if self.schema != MALFORMED_CORPUS_REPORT_SCHEMA {
            return Err("independent: malformed-corpus wrong schema".into());
        }
        if self.corpus_domain != MALFORMED_CORPUS_DOMAIN {
            return Err("independent: malformed-corpus wrong domain".into());
        }
        if self.b0_pre_spec_hash != expect_spec_hash {
            return Err("independent: malformed-corpus spec mismatch".into());
        }
        if self.measured_source_commit != expect_measured_commit {
            return Err("independent: malformed-corpus measured commit mismatch".into());
        }
        if !is_hex_of(&self.tooling_commit, 40) || !is_hex_of(&self.tooling_pathset_blake3, 64) {
            return Err("independent: malformed-corpus tooling identity not hex".into());
        }
        if self.member_count as usize != self.members.len() || self.members.is_empty() {
            return Err("independent: malformed-corpus count/empty".into());
        }
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (i, m) in self.members.iter().enumerate() {
            if m.index as usize != i {
                return Err(format!(
                    "independent: malformed-corpus member {i} out of order"
                ));
            }
            if m.statement_kind != "tlg" && m.statement_kind != "select" {
                return Err(format!(
                    "independent: malformed-corpus member {i} bad statement_kind"
                ));
            }
            if !is_hex_of(&m.member_blake3, 64) || !seen.insert(m.member_blake3.as_str()) {
                return Err(format!(
                    "independent: malformed-corpus member {i} blake3 bad/duplicate"
                ));
            }
            let bytes = decode_hex(&m.member_bytes_hex)
                .ok_or_else(|| format!("independent: malformed-corpus member {i} bytes not hex"))?;
            if bytes.len() as u32 != m.member_len {
                return Err(format!(
                    "independent: malformed-corpus member {i} len mismatch"
                ));
            }
            if to_hex(crate::plain(&bytes).as_slice()) != m.member_blake3 {
                return Err(format!(
                    "independent: malformed-corpus member {i} bytes != member_blake3"
                ));
            }
            if !m.expected_class.is_well_formed() || !m.actual_class.is_well_formed() {
                return Err(format!(
                    "independent: malformed-corpus member {i} ill-formed class"
                ));
            }
            if m.expected_class != m.actual_class {
                return Err(format!(
                    "independent: malformed-corpus member {i} wrong-error-class"
                ));
            }
        }
        if self.recompute_address() != self.address {
            return Err("independent: malformed-corpus address recompute mismatch".into());
        }
        let d = decode_hex(&self.address).ok_or("independent: malformed-corpus address not hex")?;
        if d.len() != 32 {
            return Err("independent: malformed-corpus address not 32 bytes".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn own_sha256_matches_fips_vectors() {
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

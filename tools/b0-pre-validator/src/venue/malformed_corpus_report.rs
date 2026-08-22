//! `MalformedCorpusReportV1` — the retained, content-addressed evidence that a fixed, ORDERED corpus
//! of malformed guest inputs was run through the REAL guest boundary (`b0_pre_guest_core::run`, the
//! candidate-neutral statement decoder+verifier) and each member was REFUSED with the exact stable
//! `GuestError` class expected for it. This report REPLACES the former caller-supplied
//! `malformed_corpus_result_hash`: the measurement producer receives the retained report and derives
//! the 32-byte result hash from it (never an operator value).
//!
//! Address = domain-separated SHA-256 over a canonical NUL-joined preimage (mirrors
//! `CanonicalSp1GuestArtifactV1`), computed here with the validator's own dependency-free SHA-256 and,
//! independently, by `b0-pre-independent` with its own SHA-256 — so agreement is genuine second-source
//! corroboration. The exact ordered member BYTES are retained in the report (hex), BLAKE3-indexed, so a
//! missing / reordered / altered / extra member moves the address, and a wrong expected refusal class
//! (or a member whose recorded outcome disagrees with the recorded expectation) is refused.

use serde::{Deserialize, Serialize};

pub const MALFORMED_CORPUS_REPORT_SCHEMA: &str = "b0-final-malformed-corpus-report/v1";
/// The generator/version domain: the frozen identity of the corpus construction procedure. Both the
/// generator and the report bind it, so a report from a different corpus procedure never validates.
pub const MALFORMED_CORPUS_DOMAIN: &str = "b0-final-malformed-corpus/v1";

/// The number of DEFINED `DecodeError` variant discriminants (0..=11), so `decode` codes are bounded.
pub const DECODE_VARIANT_COUNT: u16 = 12;
/// The number of DEFINED frozen semantic reason codes — the length of the generator's canonical
/// `SEMANTIC_REASONS` table (`tools/b0-pre-malformed-corpus`). A report may only carry `semantic` codes
/// in `0..SEMANTIC_REASON_COUNT`; the generator maps each `GuestError::Semantic(&'static str)` prose
/// reason to its stable code and FAILS on any unmapped reason, so an unknown reason never reaches a
/// report. This constant is the append-only table length (bump both together when a reason is added).
pub const SEMANTIC_REASON_COUNT: u16 = 40;

/// One stable `GuestError` class as an EXPLICIT PROTOCOL CODE — never Display text nor a prose reason
/// string. `kind="decode"` carries the frozen `DecodeError` variant discriminant (`0..DECODE_VARIANT_COUNT`);
/// `kind="semantic"` carries the stable semantic-reason code (`0..SEMANTIC_REASON_COUNT`) assigned by the
/// generator's canonical reason→code table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RefusalClass {
    pub kind: String,
    pub code: u16,
}

impl RefusalClass {
    /// Well-formed iff `decode` with a defined variant code, or `semantic` with a defined reason code.
    fn is_well_formed(&self) -> bool {
        match self.kind.as_str() {
            "decode" => self.code < DECODE_VARIANT_COUNT,
            "semantic" => self.code < SEMANTIC_REASON_COUNT,
            _ => false,
        }
    }
    /// Canonical class string for the address preimage (`decode:<code>` | `semantic:<code>`).
    fn canon(&self) -> String {
        format!("{}:{}", self.kind, self.code)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorpusMember {
    pub index: u32,
    /// Which official statement the member mutates: `"tlg"` | `"select"`.
    pub statement_kind: String,
    /// Human label of the mutation (documentation only; NOT in the address preimage).
    pub name: String,
    /// The exact malformed member bytes (hex) that were run through the guest boundary.
    pub member_bytes_hex: String,
    /// BLAKE3 of the member bytes (in the address preimage; the bytes above must reproduce it).
    pub member_blake3: String,
    pub member_len: u32,
    /// The stable refusal class this member is REQUIRED to produce.
    pub expected_class: RefusalClass,
    /// The stable refusal class the generator OBSERVED from `guest_core::run` (must equal expected).
    pub actual_class: RefusalClass,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MalformedCorpusReportV1 {
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

impl MalformedCorpusReportV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("malformed-corpus-report JSON parse: {e}"))
    }

    /// Domain-separated SHA-256 over the canonical NUL-joined preimage (validator's own SHA-256).
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
        crate::venue::sha256::hex_digest(parts.join("\0").as_bytes())
    }

    /// Full structural verification against the ratified measured source. Fail-closed on schema/domain,
    /// spec/commit shape, count/order, duplicate members, byte↔blake3↔len disagreement, ill-formed or
    /// mismatched (expected≠actual) refusal class, or an address recompute mismatch.
    pub fn verify(
        &self,
        expect_measured_commit: &str,
        expect_spec_hash: &str,
    ) -> Result<[u8; 32], String> {
        if self.schema != MALFORMED_CORPUS_REPORT_SCHEMA {
            return Err("malformed-corpus: wrong schema".into());
        }
        if self.corpus_domain != MALFORMED_CORPUS_DOMAIN {
            return Err("malformed-corpus: wrong corpus domain".into());
        }
        if self.b0_pre_spec_hash != expect_spec_hash {
            return Err("malformed-corpus: spec hash mismatch".into());
        }
        if self.measured_source_commit != expect_measured_commit {
            return Err("malformed-corpus: measured source commit mismatch".into());
        }
        if self.tooling_commit.len() != 40 || !is_hex_of(&self.tooling_commit, 40) {
            return Err("malformed-corpus: tooling_commit not 40-hex".into());
        }
        if !is_hex_of(&self.tooling_pathset_blake3, 64) {
            return Err("malformed-corpus: tooling_pathset_blake3 not 64-hex".into());
        }
        if self.member_count as usize != self.members.len() {
            return Err("malformed-corpus: member_count != members.len()".into());
        }
        if self.members.is_empty() {
            return Err("malformed-corpus: empty corpus".into());
        }
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (i, m) in self.members.iter().enumerate() {
            if m.index as usize != i {
                return Err(format!(
                    "malformed-corpus: member {i} out of order (index {})",
                    m.index
                ));
            }
            if m.statement_kind != "tlg" && m.statement_kind != "select" {
                return Err(format!("malformed-corpus: member {i} bad statement_kind"));
            }
            if !is_hex_of(&m.member_blake3, 64) {
                return Err(format!(
                    "malformed-corpus: member {i} member_blake3 not 64-hex"
                ));
            }
            if !seen.insert(m.member_blake3.as_str()) {
                return Err(format!(
                    "malformed-corpus: duplicate member {}",
                    m.member_blake3
                ));
            }
            let bytes = decode_hex(&m.member_bytes_hex)
                .ok_or_else(|| format!("malformed-corpus: member {i} member_bytes_hex not hex"))?;
            if bytes.len() as u32 != m.member_len {
                return Err(format!("malformed-corpus: member {i} member_len mismatch"));
            }
            if crate::venue::to_hex(blake3::hash(&bytes).as_bytes()) != m.member_blake3 {
                return Err(format!(
                    "malformed-corpus: member {i} bytes do not reproduce member_blake3"
                ));
            }
            if !m.expected_class.is_well_formed() || !m.actual_class.is_well_formed() {
                return Err(format!(
                    "malformed-corpus: member {i} ill-formed refusal class"
                ));
            }
            if m.expected_class != m.actual_class {
                return Err(format!(
                    "malformed-corpus: member {i} observed refusal class != expected (wrong-error-class)"
                ));
            }
        }
        if self.recompute_address() != self.address {
            return Err("malformed-corpus: address recompute mismatch".into());
        }
        let mut out = [0u8; 32];
        let d = hex_to_32(&self.address).ok_or("malformed-corpus: address not 32 bytes")?;
        out.copy_from_slice(&d);
        Ok(out)
    }
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
fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let v = decode_hex(s)?;
    if v.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEASURED: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";
    const SPEC: &str = "201cfcb80e94a5a7845dc3380cde32171d40f325ae2bacde9547f3c0da3c4df3";
    const REPORT_JSON: &str = include_str!(
        "../../../../docs/b0-pre/fixtures/measurement-input-authority/malformed-corpus-report.v1.json"
    );

    fn report() -> MalformedCorpusReportV1 {
        MalformedCorpusReportV1::from_json(REPORT_JSON.as_bytes()).expect("draft report parses")
    }
    fn reparse(r: &MalformedCorpusReportV1) -> Result<[u8; 32], String> {
        let bytes = serde_json::to_vec(r).unwrap();
        MalformedCorpusReportV1::from_json(&bytes)?.verify(MEASURED, SPEC)
    }

    #[test]
    fn draft_report_verifies() {
        report()
            .verify(MEASURED, SPEC)
            .expect("draft 32-member report verifies");
    }

    #[test]
    fn wrong_error_class_refused() {
        // A member whose recorded observed class disagrees with its required expected class is a
        // wrong-error-class result — refused (this is what a silently-changed guest reason would look
        // like). Change expected only, so expected != actual before the address self-check.
        let mut r = report();
        r.members[0].expected_class.code ^= 1;
        let e = reparse(&r).expect_err("wrong error class refused");
        assert!(
            e.contains("wrong-error-class") || e.contains("address recompute"),
            "{e}"
        );
    }

    #[test]
    fn reordered_members_refused() {
        let mut r = report();
        r.members.swap(0, 1);
        let e = reparse(&r).expect_err("reordered members refused");
        assert!(
            e.contains("out of order") || e.contains("address recompute"),
            "{e}"
        );
    }

    #[test]
    fn duplicate_member_refused() {
        let mut r = report();
        let m0 = r.members[0].clone();
        r.members[1] = m0; // duplicate blake3 with a matching count
        let e = reparse(&r).expect_err("duplicate member refused");
        assert!(
            e.contains("duplicate member") || e.contains("out of order"),
            "{e}"
        );
    }

    #[test]
    fn extra_member_count_mismatch_refused() {
        let mut r = report();
        let m0 = r.members[0].clone();
        r.members.push(m0); // members.len() now != member_count
        let e = reparse(&r).expect_err("extra member refused");
        assert!(
            e.contains("member_count") || e.contains("out of order"),
            "{e}"
        );
    }

    #[test]
    fn tampered_member_bytes_refused() {
        // Flip a byte of a member's retained hex → it no longer reproduces member_blake3.
        let mut r = report();
        let h = r.members[0].member_bytes_hex.clone();
        let mut chars: Vec<char> = h.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        r.members[0].member_bytes_hex = chars.into_iter().collect();
        let e = reparse(&r).expect_err("tampered member bytes refused");
        assert!(
            e.contains("reproduce member_blake3") || e.contains("member_len"),
            "{e}"
        );
    }

    #[test]
    fn wrong_measured_or_spec_refused() {
        assert!(report().verify("0".repeat(40).as_str(), SPEC).is_err());
        assert!(report().verify(MEASURED, "0".repeat(64).as_str()).is_err());
    }
}

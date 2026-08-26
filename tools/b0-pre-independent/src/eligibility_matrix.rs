//! INDEPENDENT re-decode of `EligibilityMatrixV1` — the second, from-scratch verifier of the retained,
//! content-addressed DECLARATION of the reviewed two-cell measurement model. Shares NO code with
//! `b0-pre-validator`: it recomputes the record address with the independent crate's OWN SHA-256 (the
//! same copy the report/inventory addresses use) over the IDENTICAL FROZEN NUL-joined preimage, so
//! agreement with the reference verifier is genuine second-source corroboration.
//!
//! The record distinguishes three concepts:
//!   * IDENTITY eligibility — the Phase-1 guest identities in the shared guest set: Sp1/x86_64,
//!     Sp1/aarch64, Risc0/x86_64 (exactly three).
//!   * native TERMINAL-MEASUREMENT eligibility — the cells that can produce a real terminal proof on
//!     native hardware: Sp1/x86_64, Risc0/x86_64 (exactly two).
//!   * explicitly UNSUPPORTED terminal proofs: Sp1/aarch64 terminal Groth16 (no first-party arm64
//!     gnark backend) and Risc0/aarch64 (RISC Zero receipt path is x86_64-only).

use serde::Deserialize;

use crate::malformed_corpus_report::{sha256, to_hex};

pub const ELIGIBILITY_MATRIX_SCHEMA: &str = "b0-final-eligibility-matrix/v1";

/// The canonical (candidate, arch) row order — FROZEN. Any decode whose rows are not exactly this set
/// in this order is refused (no missing / extra / reordered / duplicate rows).
pub const CANONICAL_ROWS: [(&str, &str); 4] = [
    ("Sp1", "x86_64"),
    ("Sp1", "aarch64"),
    ("Risc0", "x86_64"),
    ("Risc0", "aarch64"),
];

/// The single ratified two-cell model — the authority for which cells may be measured.
fn ratified_native_measurement_eligible(candidate: &str, arch: &str) -> bool {
    matches!((candidate, arch), ("Sp1", "x86_64") | ("Risc0", "x86_64"))
}
fn ratified_identity_eligible(candidate: &str, arch: &str) -> bool {
    matches!(
        (candidate, arch),
        ("Sp1", "x86_64") | ("Sp1", "aarch64") | ("Risc0", "x86_64")
    )
}

#[derive(Debug, Clone, Deserialize)]
pub struct EligibilityEntry {
    pub candidate: String,
    pub arch: String,
    pub identity_eligible: bool,
    pub native_measurement_eligible: bool,
    pub unsupported: bool,
    pub reason_code: String,
    pub backend: String,
    pub backend_version: String,
    pub arch_manifest_evidence: String,
    pub governing_authority: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EligibilityMatrix {
    pub schema: String,
    pub b0_pre_spec_hash: String,
    pub entries: Vec<EligibilityEntry>,
    pub address: String,
}

fn is_hex_of(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl EligibilityMatrix {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes)
            .map_err(|e| format!("independent: eligibility-matrix parse: {e}"))
    }

    /// FROZEN NUL-joined preimage → the crate's OWN SHA-256. Rows are joined in `entries` order (which
    /// `verify` requires to equal [`CANONICAL_ROWS`]), each row flattened field-by-field. Byte-identical
    /// to the reference `EligibilityMatrixV1::recompute_address`.
    pub fn recompute_address(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(3 + self.entries.len() * 10);
        parts.push(self.schema.clone());
        parts.push(self.b0_pre_spec_hash.clone());
        parts.push(self.entries.len().to_string());
        for e in &self.entries {
            parts.push(e.candidate.clone());
            parts.push(e.arch.clone());
            parts.push(e.identity_eligible.to_string());
            parts.push(e.native_measurement_eligible.to_string());
            parts.push(e.unsupported.to_string());
            parts.push(e.reason_code.clone());
            parts.push(e.backend.clone());
            parts.push(e.backend_version.clone());
            parts.push(e.arch_manifest_evidence.clone());
            parts.push(e.governing_authority.clone());
        }
        to_hex(&sha256(parts.join("\0").as_bytes()))
    }

    /// Shape + the EXACT ratified two-cell model + self-consistency + address recompute. Returns the
    /// 32-byte address on success.
    pub fn verify(&self, expect_spec_hash: &str) -> Result<[u8; 32], String> {
        if self.schema != ELIGIBILITY_MATRIX_SCHEMA {
            return Err("independent: eligibility-matrix wrong schema".into());
        }
        if self.b0_pre_spec_hash != expect_spec_hash {
            return Err("independent: eligibility-matrix spec hash mismatch".into());
        }
        if self.entries.len() != CANONICAL_ROWS.len() {
            return Err(format!(
                "independent: eligibility-matrix expected exactly {} rows, got {}",
                CANONICAL_ROWS.len(),
                self.entries.len()
            ));
        }
        for (i, (c, a)) in CANONICAL_ROWS.iter().enumerate() {
            let e = &self.entries[i];
            if e.candidate != *c || e.arch != *a {
                return Err(format!(
                    "independent: eligibility-matrix row {i} is {}/{}, expected {c}/{a} (missing/extra/reordered)",
                    e.candidate, e.arch
                ));
            }
            if e.identity_eligible != ratified_identity_eligible(c, a) {
                return Err(format!(
                    "independent: eligibility-matrix {c}/{a} identity_eligible != ratified"
                ));
            }
            if e.native_measurement_eligible != ratified_native_measurement_eligible(c, a) {
                return Err(format!(
                    "independent: eligibility-matrix {c}/{a} native_measurement_eligible != ratified"
                ));
            }
            // A cell is unsupported iff it is not natively measurement-eligible.
            if e.unsupported == e.native_measurement_eligible {
                return Err(format!(
                    "independent: eligibility-matrix {c}/{a} unsupported must be the negation of native_measurement_eligible"
                ));
            }
            // Every unsupported row carries a reason code + governing authority + arch-manifest
            // evidence; every supported row must carry an empty reason code.
            if e.unsupported {
                if e.reason_code.is_empty()
                    || e.governing_authority.is_empty()
                    || e.arch_manifest_evidence.is_empty()
                {
                    return Err(format!(
                        "independent: eligibility-matrix unsupported {c}/{a} missing reason_code/governing_authority/arch_manifest_evidence"
                    ));
                }
            } else if !e.reason_code.is_empty() {
                return Err(format!(
                    "independent: eligibility-matrix supported {c}/{a} must have empty reason_code"
                ));
            }
            // A measurement-eligible cell must also be identity-eligible.
            if e.native_measurement_eligible && !e.identity_eligible {
                return Err(format!(
                    "independent: eligibility-matrix {c}/{a} measurement-eligible but not identity-eligible"
                ));
            }
        }
        if !is_hex_of(&self.address, 64) {
            return Err("independent: eligibility-matrix address not 64-hex".into());
        }
        if self.recompute_address() != self.address {
            return Err("independent: eligibility-matrix address recompute mismatch".into());
        }
        decode_hex32(&self.address)
            .ok_or_else(|| "independent: eligibility-matrix address not 32 bytes".into())
    }

    /// The two natively-measurable cells, in canonical order.
    pub fn measurement_cells(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|e| e.native_measurement_eligible)
            .map(|e| (e.candidate.clone(), e.arch.clone()))
            .collect()
    }
    /// The unsupported (candidate, arch) set, in canonical order.
    pub fn unsupported_cells(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|e| e.unsupported)
            .map(|e| (e.candidate.clone(), e.arch.clone()))
            .collect()
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";
    const ELIG_JSON: &str = include_str!(
        "../../../docs/b0-pre/fixtures/measurement-input-authority/eligibility-matrix.v1.json"
    );
    // Ground truth: the address the reference validator committed for spec e933e732.
    const EXPECT_ADDR: &str = "2a2804b0b6057cdae47b0aaed733f1b94ef7d2894888a73bc3cbcc3949363fe1";

    fn elig() -> EligibilityMatrix {
        EligibilityMatrix::from_json(ELIG_JSON.as_bytes())
            .expect("committed eligibility record parses")
    }

    // Independent second-source corroboration: the from-scratch SHA-256 recompute of the canonical
    // record reproduces the exact address the reference validator committed.
    #[test]
    fn independent_recompute_matches_committed_address() {
        let m = elig();
        assert_eq!(
            m.recompute_address(),
            EXPECT_ADDR,
            "independent SHA-256 recompute"
        );
        assert_eq!(m.address, EXPECT_ADDR, "committed address field");
        let addr = m
            .verify(SPEC)
            .expect("committed record verifies against the spec");
        assert_eq!(to_hex(&addr), EXPECT_ADDR);
    }

    #[test]
    fn independent_two_cell_model_cross_checks() {
        let m = elig();
        assert_eq!(
            m.measurement_cells(),
            vec![
                ("Sp1".to_string(), "x86_64".to_string()),
                ("Risc0".to_string(), "x86_64".to_string())
            ]
        );
        assert_eq!(
            m.unsupported_cells(),
            vec![
                ("Sp1".to_string(), "aarch64".to_string()),
                ("Risc0".to_string(), "aarch64".to_string())
            ]
        );
    }

    #[test]
    fn independent_wrong_spec_refused() {
        assert!(elig().verify(&"0".repeat(64)).is_err());
    }
}

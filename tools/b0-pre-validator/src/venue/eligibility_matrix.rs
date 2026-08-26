//! `EligibilityMatrixV1` — the retained, content-addressed DECLARATION of the two-cell measurement model.
//!
//! It distinguishes three concepts that were previously conflated:
//!   * IDENTITY eligibility — the Phase-1 guest identities that form the shared guest set:
//!     Sp1/x86_64, Sp1/aarch64, Risc0/x86_64 (exactly three).
//!   * native TERMINAL-MEASUREMENT eligibility — the cells that can produce a real terminal proof on
//!     native hardware: Sp1/x86_64, Risc0/x86_64 (exactly two).
//!   * explicitly UNSUPPORTED terminal proofs (ratified fail-closed): Sp1/aarch64 terminal Groth16
//!     (no first-party linux/arm64 gnark backend) and Risc0/aarch64 (RISC Zero receipt path is x86_64-only).
//!
//! The SP1/aarch64 *identity* is eligible and stays in the guest set, but is NEVER a measurement or proof.
//! The record carries, per (candidate,arch): the three eligibility booleans, a reason code, the backend +
//! version, the architecture-manifest evidence, and the governing authority. Its address is SHA-256 over a
//! FROZEN NUL-joined preimage (the validator's own SHA-256 here; the independent crate recomputes with its
//! own SHA-256 — genuine second-source corroboration). It is bound into the MeasurementInputAuthorityV1 (by
//! address) and travels in the measurement container so both verifiers decode + recompute it.

use serde::{Deserialize, Serialize};

pub const ELIGIBILITY_MATRIX_SCHEMA: &str = "b0-final-eligibility-matrix/v1";

/// One (candidate, arch) eligibility row.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EligibilityEntry {
    pub candidate: String,
    pub arch: String,
    pub identity_eligible: bool,
    pub native_measurement_eligible: bool,
    pub unsupported: bool,
    /// Stable machine reason code (empty iff supported). E.g. `sp1-aarch64-groth16-no-arm-backend`.
    pub reason_code: String,
    /// Terminal proving backend for this cell (e.g. `sp1-recursion-gnark-ffi/docker`, `risc0-groth16`).
    pub backend: String,
    /// Backend version identity (e.g. `sp1-gnark:v6.1.0`, `risc0-zkvm:3.0.5`).
    pub backend_version: String,
    /// Architecture-manifest evidence: for an unsupported arm cell, the proof that no native backend
    /// exists (e.g. the amd64-only OCI image index digest). Empty for supported cells.
    pub arch_manifest_evidence: String,
    /// Governing authority for this row (the ratified evidence/decision that fixes it).
    pub governing_authority: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EligibilityMatrixV1 {
    pub schema: String,
    pub b0_pre_spec_hash: String,
    pub entries: Vec<EligibilityEntry>,
    pub address: String,
}

/// The canonical (candidate, arch) row order — FROZEN. Any decode whose rows are not exactly this
/// set in this order is refused (no missing / extra / reordered / duplicate rows).
pub const CANONICAL_ROWS: [(&str, &str); 4] = [
    ("Sp1", "x86_64"),
    ("Sp1", "aarch64"),
    ("Risc0", "x86_64"),
    ("Risc0", "aarch64"),
];

/// The single ratified two-cell model. `native_measurement_eligible` here is the authority for which
/// cells may be measured; it MUST agree with [`crate::measurement::native_eligible`].
pub fn ratified_native_measurement_eligible(candidate: &str, arch: &str) -> bool {
    matches!((candidate, arch), ("Sp1", "x86_64") | ("Risc0", "x86_64"))
}
fn ratified_identity_eligible(candidate: &str, arch: &str) -> bool {
    matches!(
        (candidate, arch),
        ("Sp1", "x86_64") | ("Sp1", "aarch64") | ("Risc0", "x86_64")
    )
}

fn is_hex_of(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl EligibilityMatrixV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("eligibility-matrix parse: {e}"))
    }

    /// FROZEN NUL-joined preimage → validator's own SHA-256. Rows are joined in `entries` order (which
    /// `verify` requires to equal [`CANONICAL_ROWS`]), each row flattened field-by-field.
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
        crate::venue::sha256::hex_digest(parts.join("\0").as_bytes())
    }

    /// Shape + the EXACT ratified two-cell model + self-consistency + address recompute. Returns the
    /// 32-byte address on success.
    pub fn verify(&self, expect_spec_hash: &str) -> Result<[u8; 32], String> {
        if self.schema != ELIGIBILITY_MATRIX_SCHEMA {
            return Err("eligibility-matrix: wrong schema".into());
        }
        if self.b0_pre_spec_hash != expect_spec_hash {
            return Err("eligibility-matrix: spec hash mismatch".into());
        }
        if self.entries.len() != CANONICAL_ROWS.len() {
            return Err(format!(
                "eligibility-matrix: expected exactly {} rows, got {}",
                CANONICAL_ROWS.len(),
                self.entries.len()
            ));
        }
        for (i, (c, a)) in CANONICAL_ROWS.iter().enumerate() {
            let e = &self.entries[i];
            if e.candidate != *c || e.arch != *a {
                return Err(format!(
                    "eligibility-matrix: row {i} is {}/{}, expected {c}/{a} (missing/extra/reordered)",
                    e.candidate, e.arch
                ));
            }
            // The exact ratified model.
            if e.identity_eligible != ratified_identity_eligible(c, a) {
                return Err(format!(
                    "eligibility-matrix: {c}/{a} identity_eligible != ratified"
                ));
            }
            if e.native_measurement_eligible != ratified_native_measurement_eligible(c, a) {
                return Err(format!(
                    "eligibility-matrix: {c}/{a} native_measurement_eligible != ratified"
                ));
            }
            // A cell is unsupported iff it is not natively measurement-eligible.
            if e.unsupported == e.native_measurement_eligible {
                return Err(format!(
                    "eligibility-matrix: {c}/{a} unsupported must be the negation of native_measurement_eligible"
                ));
            }
            // Every unsupported row must carry a reason code + governing authority + arch-manifest
            // evidence; every supported row must carry an empty reason code (no spurious unsupported claim).
            if e.unsupported {
                if e.reason_code.is_empty()
                    || e.governing_authority.is_empty()
                    || e.arch_manifest_evidence.is_empty()
                {
                    return Err(format!(
                        "eligibility-matrix: unsupported {c}/{a} missing reason_code/governing_authority/arch_manifest_evidence"
                    ));
                }
            } else if !e.reason_code.is_empty() {
                return Err(format!(
                    "eligibility-matrix: supported {c}/{a} must have empty reason_code"
                ));
            }
            // A measurement-eligible cell must also be identity-eligible.
            if e.native_measurement_eligible && !e.identity_eligible {
                return Err(format!(
                    "eligibility-matrix: {c}/{a} measurement-eligible but not identity-eligible"
                ));
            }
        }
        // Cross-bind to the code path that actually gates proving: the record's measurement eligibility
        // MUST equal `measurement::native_eligible` for every (candidate,arch) — the declaration and the
        // enforcement can never drift.
        use crate::enums::{Arch, Candidate};
        for (c, a) in CANONICAL_ROWS.iter() {
            let cand = match *c {
                "Sp1" => Candidate::Sp1,
                "Risc0" => Candidate::Risc0,
                _ => continue,
            };
            let arch = match *a {
                "x86_64" => Arch::X86_64,
                "aarch64" => Arch::Aarch64,
                _ => continue,
            };
            if crate::measurement::native_eligible(cand, arch)
                != ratified_native_measurement_eligible(c, a)
            {
                return Err(format!(
                    "eligibility-matrix: {c}/{a} native_eligible() disagrees with the ratified matrix"
                ));
            }
        }
        if !is_hex_of(&self.address, 64) {
            return Err("eligibility-matrix: address not 64-hex".into());
        }
        if self.recompute_address() != self.address {
            return Err("eligibility-matrix: address recompute mismatch".into());
        }
        decode_hex32(&self.address).ok_or_else(|| "eligibility-matrix: address not 32 bytes".into())
    }

    /// Convenience: the two natively-measurable cells, in canonical order.
    pub fn measurement_cells(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|e| e.native_measurement_eligible)
            .map(|e| (e.candidate.clone(), e.arch.clone()))
            .collect()
    }
    /// Convenience: the unsupported (candidate,arch) set, in canonical order.
    pub fn unsupported_cells(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|e| e.unsupported)
            .map(|e| (e.candidate.clone(), e.arch.clone()))
            .collect()
    }

    /// The ONE canonical ratified eligibility record, self-addressed and bound to `spec_hash`. This is
    /// the sole authoritative constructor — the producer, `--dry-run`, and the committed-fixture
    /// emitter all build the record through it, so the declaration can never be hand-authored.
    pub fn canonical(spec_hash: &str) -> Self {
        let mk = |c: &str,
                  a: &str,
                  id: bool,
                  meas: bool,
                  reason: &str,
                  backend: &str,
                  ver: &str,
                  evid: &str,
                  auth: &str| EligibilityEntry {
            candidate: c.into(),
            arch: a.into(),
            identity_eligible: id,
            native_measurement_eligible: meas,
            unsupported: !meas,
            reason_code: reason.into(),
            backend: backend.into(),
            backend_version: ver.into(),
            arch_manifest_evidence: evid.into(),
            governing_authority: auth.into(),
        };
        let mut m =
            EligibilityMatrixV1 {
                schema: ELIGIBILITY_MATRIX_SCHEMA.into(),
                b0_pre_spec_hash: spec_hash.into(),
                entries: vec![
                mk(
                    "Sp1", "x86_64", true, true, "", "sp1-recursion-gnark-ffi/docker",
                    "sp1-gnark:v6.1.0", "", "",
                ),
                mk(
                    "Sp1", "aarch64", true, false, "sp1-aarch64-groth16-no-arm-backend",
                    "sp1-recursion-gnark-ffi/docker", "sp1-gnark:v6.1.0",
                    "oci-index sha256:e1a1cd62 publishes only linux/amd64; no linux/arm64 manifest",
                    "arm-sp1-stage5 no-arm-gnark-evidence (CONFIRMED); B0-FINAL eligibility matrix",
                ),
                mk(
                    "Risc0", "x86_64", true, true, "", "risc0-groth16", "risc0-zkvm:3.0.5", "", "",
                ),
                mk(
                    "Risc0", "aarch64", false, false, "risc0-aarch64-x86-only", "risc0-groth16",
                    "risc0-zkvm:3.0.5",
                    "RISC Zero r0vm/cargo-risczero published x86_64-only (VENUE section 2)",
                    "B0-FINAL eligibility matrix; VENUE.md section 2",
                ),
            ],
                address: String::new(),
            };
        m.address = m.recompute_address();
        m
    }

    /// Canonical JSON serialization (stable field order via the struct definition).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("EligibilityMatrixV1 serializes")
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

    fn canonical_matrix() -> EligibilityMatrixV1 {
        EligibilityMatrixV1::canonical(crate::guest_set::MERGED_SPEC_HASH_HEX)
    }

    #[test]
    fn canonical_matrix_verifies_and_matches_native_eligible() {
        let m = canonical_matrix();
        assert!(m.verify(crate::guest_set::MERGED_SPEC_HASH_HEX).is_ok());
        assert_eq!(
            m.measurement_cells(),
            vec![
                ("Sp1".into(), "x86_64".into()),
                ("Risc0".into(), "x86_64".into())
            ]
        );
        assert_eq!(
            m.unsupported_cells(),
            vec![
                ("Sp1".into(), "aarch64".into()),
                ("Risc0".into(), "aarch64".into())
            ]
        );
    }

    #[test]
    fn a_fabricated_sp1_aarch64_measurement_claim_is_refused() {
        // Flip SP1/aarch64 to measurement-eligible (a fabricated ARM measurement) → refused.
        let mut m = canonical_matrix();
        m.entries[1].native_measurement_eligible = true;
        m.entries[1].unsupported = false;
        m.entries[1].reason_code = String::new();
        m.address = m.recompute_address();
        assert!(m.verify(crate::guest_set::MERGED_SPEC_HASH_HEX).is_err());
    }

    #[test]
    fn missing_unsupported_reason_is_refused() {
        let mut m = canonical_matrix();
        m.entries[1].reason_code = String::new();
        m.address = m.recompute_address();
        assert!(m.verify(crate::guest_set::MERGED_SPEC_HASH_HEX).is_err());
    }

    #[test]
    fn reordered_or_extra_rows_refused() {
        let mut m = canonical_matrix();
        m.entries.swap(0, 2);
        m.address = m.recompute_address();
        assert!(m.verify(crate::guest_set::MERGED_SPEC_HASH_HEX).is_err());
    }

    #[test]
    fn tampered_address_refused() {
        let mut m = canonical_matrix();
        m.address = "0".repeat(64);
        assert!(m.verify(crate::guest_set::MERGED_SPEC_HASH_HEX).is_err());
    }
}

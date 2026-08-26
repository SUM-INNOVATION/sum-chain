//! `MeasurementInputAuthorityV1` — the UNIFIER that binds every derived measurement input under one
//! retained, content-addressed authority, REPLACING the three former caller-supplied hashes
//! (`RSS_CONTEXT_HASH`, `MALFORMED_CORPUS_RESULT_HASH`, `HARNESS_SOURCE_HASH`).
//!
//! It binds, by INDEPENDENTLY RECOMPUTED ADDRESS (never a duplicated caller value):
//!   * the benchmark-harness source inventory address — BLAKE3(domain‖retained manifest bytes);
//!   * the malformed-corpus report address — SHA-256 over the retained report's canonical preimage;
//!   * the RSS statement-binding POLICY (a frozen tag; the per-cell binding itself is enforced
//!     structurally in `verify_evidence`, never a hash);
//!
//! plus the spec/workload identity and the measured-source + tooling identity. The retained inventory
//! and report BYTES travel in the measurement container (VEC6); both verifiers recompute the two
//! sub-addresses from those bytes and require the authority to bind exactly them. The authority's own
//! address is SHA-256 over a NUL-joined preimage (validator's own SHA-256 here, the independent crate's
//! own SHA-256 there — genuine second-source corroboration).

use serde::{Deserialize, Serialize};

pub const MEASUREMENT_INPUT_AUTHORITY_SCHEMA: &str = "b0-final-measurement-input-authority/v1";
/// The one recognised RSS statement-binding policy: every RSS record binds the statement of the cell it
/// measures (enforced in `verify_evidence`). The authority records the POLICY, not a value.
pub const RSS_STATEMENT_BINDING_POLICY: &str = "per-cell-statement/v1";
/// Domain for the harness-source inventory digest — MUST equal
/// `b0_pre_host_provenance::HARNESS_SOURCE_DOMAIN` so this recompute matches the provenance reader.
pub const HARNESS_SOURCE_DOMAIN: &[u8] = b"b0-final-benchmark-harness-source/v1\0";

/// The repository's established non-authoritative sentinel tooling commit — the value the synthetic /
/// dry-run assembly paths and the committed TEST_ONLY authority fixtures bind. It can NEVER be a real
/// ratified tooling commit, so production (the pre-grid `--verify-authority` gate) refuses an authority
/// bound to it: a TEST_ONLY encoding/verification vector must never be usable as official grid authority.
pub const TEST_ONLY_TOOLING_COMMIT_SENTINEL: &str = "1234567890abcdef1234567890abcdef12345678";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MeasurementInputAuthorityV1 {
    pub schema: String,
    pub b0_pre_spec_hash: String,
    pub measured_source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub harness_source_inventory_address: String,
    pub malformed_corpus_report_address: String,
    pub rss_statement_binding_policy: String,
    /// Address of the retained eligibility/unsupported matrix (`EligibilityMatrixV1`) — the reviewed
    /// two-cell measurement model (3 identities, 2 native-measurement cells, the exact unsupported
    /// set). Bound here so the authority ties the package to the ratified eligibility policy; both
    /// verifiers recompute it from the retained eligibility-record bytes in `verify_binds`.
    pub eligibility_matrix_address: String,
    pub address: String,
}

fn is_hex_of(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl MeasurementInputAuthorityV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("measurement-input-authority parse: {e}"))
    }

    /// Domain-separated SHA-256 over the canonical NUL-joined preimage (validator's own SHA-256).
    pub fn recompute_address(&self) -> String {
        let parts = [
            self.schema.as_str(),
            self.b0_pre_spec_hash.as_str(),
            self.measured_source_commit.as_str(),
            self.tooling_commit.as_str(),
            self.tooling_pathset_blake3.as_str(),
            self.harness_source_inventory_address.as_str(),
            self.malformed_corpus_report_address.as_str(),
            self.rss_statement_binding_policy.as_str(),
            self.eligibility_matrix_address.as_str(),
        ];
        crate::venue::sha256::hex_digest(parts.join("\0").as_bytes())
    }

    /// Shape + self-consistency of the authority (not yet tied to retained bytes — see `verify_binds`).
    pub fn verify(
        &self,
        expect_measured_commit: &str,
        expect_spec_hash: &str,
    ) -> Result<[u8; 32], String> {
        if self.schema != MEASUREMENT_INPUT_AUTHORITY_SCHEMA {
            return Err("measurement-input-authority: wrong schema".into());
        }
        if self.b0_pre_spec_hash != expect_spec_hash {
            return Err("measurement-input-authority: spec hash mismatch".into());
        }
        if self.measured_source_commit != expect_measured_commit {
            return Err("measurement-input-authority: measured source commit mismatch".into());
        }
        if !is_hex_of(&self.tooling_commit, 40) {
            return Err("measurement-input-authority: tooling_commit not 40-hex".into());
        }
        for (nm, v) in [
            ("tooling_pathset_blake3", &self.tooling_pathset_blake3),
            (
                "harness_source_inventory_address",
                &self.harness_source_inventory_address,
            ),
            (
                "malformed_corpus_report_address",
                &self.malformed_corpus_report_address,
            ),
            (
                "eligibility_matrix_address",
                &self.eligibility_matrix_address,
            ),
        ] {
            if !is_hex_of(v, 64) {
                return Err(format!("measurement-input-authority: {nm} not 64-hex"));
            }
        }
        if self.rss_statement_binding_policy != RSS_STATEMENT_BINDING_POLICY {
            return Err(
                "measurement-input-authority: unrecognised RSS statement-binding policy".into(),
            );
        }
        if self.recompute_address() != self.address {
            return Err("measurement-input-authority: address recompute mismatch".into());
        }
        let d = decode_hex32(&self.address)
            .ok_or("measurement-input-authority: address not 32 bytes")?;
        Ok(d)
    }

    /// Tie the authority to the RETAINED bytes it binds: recompute the harness-source inventory address
    /// (BLAKE3 domain-sep over the retained manifest) and the malformed-corpus report address (the
    /// retained report's own full verification), and require the authority to bind EXACTLY those. Both
    /// sub-artifacts are also fully verified against the ratified measured source + spec.
    pub fn verify_binds(
        &self,
        harness_inventory_manifest: &[u8],
        malformed_report_json: &[u8],
        eligibility_record_json: &[u8],
        expect_measured_commit: &str,
        expect_spec_hash: &str,
    ) -> Result<(), String> {
        // harness-source inventory: BLAKE3(domain ‖ manifest bytes), mirroring the provenance reader.
        let mut h = blake3::Hasher::new();
        h.update(HARNESS_SOURCE_DOMAIN);
        h.update(harness_inventory_manifest);
        let inv_addr = crate::venue::to_hex(h.finalize().as_bytes());
        if inv_addr != self.harness_source_inventory_address {
            return Err(
                "measurement-input-authority: harness inventory address != retained manifest"
                    .into(),
            );
        }
        // malformed-corpus report: full structural verification of the retained bytes → its address.
        let report = crate::venue::malformed_corpus_report::MalformedCorpusReportV1::from_json(
            malformed_report_json,
        )?;
        let report_addr = report.verify(expect_measured_commit, expect_spec_hash)?;
        if crate::venue::to_hex(&report_addr) != self.malformed_corpus_report_address {
            return Err("measurement-input-authority: report address != retained report".into());
        }
        // eligibility/unsupported matrix: independently DECODE the retained record and RECOMPUTE its
        // address (the two-cell model: 3 identities, 2 native-measurement cells, exact unsupported
        // set). The authority must bind EXACTLY that address — a fabricated/edited eligibility record,
        // or one whose model disagrees with `native_eligible`, is refused by `verify()` here.
        let elig = crate::venue::eligibility_matrix::EligibilityMatrixV1::from_json(
            eligibility_record_json,
        )?;
        let elig_addr = elig.verify(expect_spec_hash)?;
        if crate::venue::to_hex(&elig_addr) != self.eligibility_matrix_address {
            return Err(
                "measurement-input-authority: eligibility-matrix address != retained record".into(),
            );
        }
        Ok(())
    }

    /// Tie the authority's tooling identity to the RATIFIED measurement tooling. A structurally valid,
    /// internally self-consistent authority whose tooling commit/path-set is NOT the ratified one is a
    /// STALE package (bound to superseded tooling) and is refused — this is the fail-fast pre-grid check
    /// that prevents a valid OLD authority from being reused after source edits change the tooling.
    pub fn verify_tooling_ratified(
        &self,
        ratified_commit: &str,
        ratified_pathset_blake3: &str,
    ) -> Result<(), String> {
        // A committed TEST_ONLY authority fixture is bound to the non-authoritative sentinel tooling
        // commit. Refuse it EXPLICITLY in production even if the ratified tooling were ever misconfigured
        // to the sentinel — a mechanics-only test vector is never official grid authority.
        if self.tooling_commit == TEST_ONLY_TOOLING_COMMIT_SENTINEL {
            return Err(
                "authority bound to the TEST_ONLY sentinel tooling commit; refused in production \
                 (this is a mechanics-only test vector, never official grid authority)"
                    .into(),
            );
        }
        if self.tooling_commit != ratified_commit {
            return Err(format!(
                "authority tooling_commit {} != ratified measurement-tooling commit {ratified_commit} (stale authority package)",
                self.tooling_commit
            ));
        }
        if self.tooling_pathset_blake3 != ratified_pathset_blake3 {
            return Err(format!(
                "authority tooling_pathset_blake3 {} != ratified {ratified_pathset_blake3} (stale authority package)",
                self.tooling_pathset_blake3
            ));
        }
        Ok(())
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut a = [0u8; 32];
    for (i, b) in a.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEASURED: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";
    const SPEC: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";
    const MIA_JSON: &str = include_str!(
        "../../../../docs/b0-pre/fixtures/measurement-input-authority/measurement-input-authority.v1.json"
    );
    const REPORT_JSON: &str = include_str!(
        "../../../../docs/b0-pre/fixtures/measurement-input-authority/malformed-corpus-report.v1.json"
    );
    const INVENTORY: &str = include_str!(
        "../../../../docs/b0-pre/fixtures/measurement-input-authority/harness-source-inventory.txt"
    );

    fn mia() -> MeasurementInputAuthorityV1 {
        MeasurementInputAuthorityV1::from_json(MIA_JSON.as_bytes()).expect("draft MIA parses")
    }
    // The canonical two-cell eligibility record for this spec — its address is what the draft MIA binds.
    fn elig() -> String {
        crate::venue::eligibility_matrix::EligibilityMatrixV1::canonical(SPEC).to_json()
    }

    #[test]
    fn draft_authority_verifies_and_binds_its_retained_bytes() {
        let m = mia();
        m.verify(MEASURED, SPEC).expect("shape/self-consistency");
        m.verify_binds(
            INVENTORY.as_bytes(),
            REPORT_JSON.as_bytes(),
            elig().as_bytes(),
            MEASURED,
            SPEC,
        )
        .expect("binds the retained inventory + report");
    }

    #[test]
    fn swapped_inventory_and_report_bytes_refused() {
        // Feeding the report bytes where the inventory manifest is expected (and vice versa) must fail:
        // neither recomputed address equals what the authority binds.
        let m = mia();
        let e = m
            .verify_binds(
                REPORT_JSON.as_bytes(),
                INVENTORY.as_bytes(),
                elig().as_bytes(),
                MEASURED,
                SPEC,
            )
            .expect_err("swapped retained bytes must be refused");
        assert!(
            e.contains("inventory address") || e.contains("report"),
            "{e}"
        );
    }

    #[test]
    fn mutually_edited_report_binding_refused() {
        // A self-consistently RE-ADDRESSED authority that binds a DIFFERENT report address than the
        // retained report bytes hash to: verify() passes (internally consistent) but verify_binds()
        // refuses (retained report address != bound address). Guards the "mutually-edited facts" case.
        let mut m = mia();
        m.malformed_corpus_report_address = "f".repeat(64);
        m.address = m.recompute_address();
        m.verify(MEASURED, SPEC)
            .expect("re-addressed MIA is internally consistent");
        let e = m
            .verify_binds(
                INVENTORY.as_bytes(),
                REPORT_JSON.as_bytes(),
                elig().as_bytes(),
                MEASURED,
                SPEC,
            )
            .expect_err("bound report address != retained report must be refused");
        assert!(e.contains("report address != retained report"), "{e}");
    }

    #[test]
    fn mutually_edited_inventory_binding_refused() {
        let mut m = mia();
        m.harness_source_inventory_address = "a".repeat(64);
        m.address = m.recompute_address();
        m.verify(MEASURED, SPEC)
            .expect("re-addressed MIA is internally consistent");
        let e = m
            .verify_binds(
                INVENTORY.as_bytes(),
                REPORT_JSON.as_bytes(),
                elig().as_bytes(),
                MEASURED,
                SPEC,
            )
            .expect_err("bound inventory address != retained manifest must be refused");
        assert!(
            e.contains("harness inventory address != retained manifest"),
            "{e}"
        );
    }

    #[test]
    fn wrong_measured_or_spec_refused() {
        let m = mia();
        assert!(m.verify("0".repeat(40).as_str(), SPEC).is_err());
        assert!(m.verify(MEASURED, "0".repeat(64).as_str()).is_err());
    }

    #[test]
    fn tampered_address_refused() {
        let mut m = mia();
        // flip the last nibble of the self address.
        let mut a: Vec<char> = m.address.chars().collect();
        let last = a.len() - 1;
        a[last] = if a[last] == '0' { '1' } else { '0' };
        m.address = a.into_iter().collect();
        let e = m
            .verify(MEASURED, SPEC)
            .expect_err("tampered address refused");
        assert!(e.contains("address recompute mismatch"), "{e}");
    }

    #[test]
    fn unknown_rss_policy_refused() {
        let mut m = mia();
        m.rss_statement_binding_policy = "last-write-wins/v0".into();
        m.address = m.recompute_address();
        let e = m
            .verify(MEASURED, SPEC)
            .expect_err("unknown RSS policy refused");
        assert!(e.contains("RSS statement-binding policy"), "{e}");
    }

    #[test]
    fn test_only_sentinel_authority_refused_in_production() {
        use crate::tooling_authority::{
            RATIFIED_MEASUREMENT_TOOLING_COMMIT, RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
        };
        // The committed fixture is a TEST_ONLY vector bound to the non-authoritative sentinel tooling
        // commit. Its encoding/verification mechanics are sound (verify + verify_binds pass), but the
        // production tooling tie REFUSES it — a mechanics-only vector is never official grid authority.
        let m = mia();
        assert_eq!(m.tooling_commit, TEST_ONLY_TOOLING_COMMIT_SENTINEL);
        m.verify(MEASURED, SPEC)
            .expect("mechanics: shape/self-consistency ok");
        let e = m
            .verify_tooling_ratified(
                RATIFIED_MEASUREMENT_TOOLING_COMMIT,
                RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
            )
            .expect_err("TEST_ONLY sentinel must be refused in production");
        assert!(e.contains("TEST_ONLY sentinel"), "{e}");
    }

    #[test]
    fn tooling_tie_accepts_ratified_and_refuses_stale() {
        use crate::tooling_authority::{
            RATIFIED_MEASUREMENT_TOOLING_COMMIT, RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
        };
        // Re-address a copy of the fixture to bind the REAL ratified tooling → accepted (mechanism).
        let mut ok = mia();
        ok.tooling_commit = RATIFIED_MEASUREMENT_TOOLING_COMMIT.into();
        ok.tooling_pathset_blake3 = RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3.into();
        ok.address = ok.recompute_address();
        ok.verify_tooling_ratified(
            RATIFIED_MEASUREMENT_TOOLING_COMMIT,
            RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
        )
        .expect("an authority bound to the ratified tooling is accepted");

        // A valid, non-sentinel, non-ratified tooling commit is a STALE package — refused at the tie.
        let mut stale = mia();
        stale.tooling_commit = "abcdefabcdefabcdefabcdefabcdefabcdefabcd".into();
        stale.address = stale.recompute_address();
        stale
            .verify(MEASURED, SPEC)
            .expect("stale authority is internally consistent");
        let e = stale
            .verify_tooling_ratified(
                RATIFIED_MEASUREMENT_TOOLING_COMMIT,
                RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
            )
            .expect_err("stale tooling commit must be refused");
        assert!(e.contains("stale authority package"), "{e}");

        // Likewise a valid, non-ratified path-set (with the ratified, non-sentinel commit).
        let mut stale_ps = mia();
        stale_ps.tooling_commit = RATIFIED_MEASUREMENT_TOOLING_COMMIT.into();
        stale_ps.tooling_pathset_blake3 = "0".repeat(64);
        stale_ps.address = stale_ps.recompute_address();
        let e = stale_ps
            .verify_tooling_ratified(
                RATIFIED_MEASUREMENT_TOOLING_COMMIT,
                RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3,
            )
            .expect_err("stale tooling path-set must be refused");
        assert!(e.contains("stale authority package"), "{e}");
    }
}

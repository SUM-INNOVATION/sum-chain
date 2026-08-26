//! INDEPENDENT re-decode of `MeasurementInputAuthorityV1` — the second, from-scratch verifier of the
//! unifying measurement-input authority. Shares NO code with `b0-pre-validator`: it recomputes the
//! authority address with the independent crate's OWN SHA-256 (via the malformed-corpus module) and the
//! harness-inventory address with the crate's OWN BLAKE3 (`crate::plain`), and re-verifies the retained
//! malformed-corpus report from scratch — so agreement with the reference verifier is genuine
//! corroboration. The authority binds the two sub-artifacts by their independently recomputed ADDRESS
//! (never a duplicated caller hash) plus the RSS statement-binding policy.

use serde::Deserialize;

use crate::malformed_corpus_report::{sha256, to_hex, MalformedCorpusReport};

pub const MEASUREMENT_INPUT_AUTHORITY_SCHEMA: &str = "b0-final-measurement-input-authority/v1";
pub const RSS_STATEMENT_BINDING_POLICY: &str = "per-cell-statement/v1";
pub const HARNESS_SOURCE_DOMAIN: &[u8] = b"b0-final-benchmark-harness-source/v1\0";

#[derive(Debug, Clone, Deserialize)]
pub struct MeasurementInputAuthority {
    pub schema: String,
    pub b0_pre_spec_hash: String,
    pub measured_source_commit: String,
    pub tooling_commit: String,
    pub tooling_pathset_blake3: String,
    pub harness_source_inventory_address: String,
    pub malformed_corpus_report_address: String,
    pub rss_statement_binding_policy: String,
    /// Address of the retained eligibility/unsupported matrix (`EligibilityMatrix`) — the reviewed
    /// two-cell measurement model (3 identities, 2 native-measurement cells, the exact unsupported
    /// set). Bound here so the authority ties the package to the ratified eligibility policy;
    /// `verify_binds` recomputes it from the retained eligibility-record bytes with the crate's OWN
    /// SHA-256.
    pub eligibility_matrix_address: String,
    pub address: String,
}

fn is_hex_of(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl MeasurementInputAuthority {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("independent: MIA parse: {e}"))
    }

    /// Independent SHA-256 recompute over the SAME NUL-joined preimage the reference uses.
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
        to_hex(&sha256(parts.join("\0").as_bytes()))
    }

    pub fn verify(
        &self,
        expect_measured_commit: &str,
        expect_spec_hash: &str,
    ) -> Result<[u8; 32], String> {
        if self.schema != MEASUREMENT_INPUT_AUTHORITY_SCHEMA {
            return Err("independent: MIA wrong schema".into());
        }
        if self.b0_pre_spec_hash != expect_spec_hash {
            return Err("independent: MIA spec mismatch".into());
        }
        if self.measured_source_commit != expect_measured_commit {
            return Err("independent: MIA measured commit mismatch".into());
        }
        if !is_hex_of(&self.tooling_commit, 40) {
            return Err("independent: MIA tooling_commit not 40-hex".into());
        }
        for v in [
            &self.tooling_pathset_blake3,
            &self.harness_source_inventory_address,
            &self.malformed_corpus_report_address,
            &self.eligibility_matrix_address,
        ] {
            if !is_hex_of(v, 64) {
                return Err("independent: MIA bound address not 64-hex".into());
            }
        }
        if self.rss_statement_binding_policy != RSS_STATEMENT_BINDING_POLICY {
            return Err("independent: MIA unrecognised RSS policy".into());
        }
        if self.recompute_address() != self.address {
            return Err("independent: MIA address recompute mismatch".into());
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&self.address[i * 2..i * 2 + 2], 16)
                .map_err(|_| "independent: MIA address not hex")?;
        }
        Ok(out)
    }

    /// Tie the authority to the RETAINED bytes: recompute the harness-inventory address (own BLAKE3
    /// domain-sep) and the malformed-corpus report address (from-scratch report verification), and
    /// require the authority to bind exactly those.
    pub fn verify_binds(
        &self,
        harness_inventory_manifest: &[u8],
        malformed_report_json: &[u8],
        eligibility_record_json: &[u8],
        expect_measured_commit: &str,
        expect_spec_hash: &str,
    ) -> Result<(), String> {
        let mut pre = HARNESS_SOURCE_DOMAIN.to_vec();
        pre.extend_from_slice(harness_inventory_manifest);
        if to_hex(crate::plain(&pre).as_slice()) != self.harness_source_inventory_address {
            return Err("independent: MIA harness inventory address != retained manifest".into());
        }
        let report = MalformedCorpusReport::from_json(malformed_report_json)?;
        let report_addr = report.verify(expect_measured_commit, expect_spec_hash)?;
        if to_hex(&report_addr) != self.malformed_corpus_report_address {
            return Err("independent: MIA report address != retained report".into());
        }
        // eligibility/unsupported matrix: independently DECODE the retained record and RECOMPUTE its
        // address with the crate's OWN SHA-256 (the two-cell model: 3 identities, 2 native-measurement
        // cells, exact unsupported set). The authority must bind EXACTLY that address — a fabricated /
        // edited eligibility record, or one whose model disagrees with the ratified matrix, is refused.
        let elig =
            crate::eligibility_matrix::EligibilityMatrix::from_json(eligibility_record_json)?;
        let elig_addr = elig.verify(expect_spec_hash)?;
        if to_hex(&elig_addr) != self.eligibility_matrix_address {
            return Err("independent: MIA eligibility-matrix address != retained record".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEASURED: &str = "507281e21e95a6a98e3480e25e12d1baab586e07";
    const SPEC: &str = "e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2";
    const MIA_JSON: &str = include_str!(
        "../../../docs/b0-pre/fixtures/measurement-input-authority/measurement-input-authority.v1.json"
    );
    const REPORT_JSON: &str = include_str!(
        "../../../docs/b0-pre/fixtures/measurement-input-authority/malformed-corpus-report.v1.json"
    );
    const INVENTORY: &str = include_str!(
        "../../../docs/b0-pre/fixtures/measurement-input-authority/harness-source-inventory.txt"
    );
    // The committed two-cell eligibility record whose independently recomputed address the draft MIA binds.
    const ELIG_JSON: &str = include_str!(
        "../../../docs/b0-pre/fixtures/measurement-input-authority/eligibility-matrix.v1.json"
    );

    fn mia() -> MeasurementInputAuthority {
        MeasurementInputAuthority::from_json(MIA_JSON.as_bytes()).expect("draft MIA parses")
    }

    // Independent second-source corroboration: the from-scratch verifier accepts exactly the same
    // draft authority + retained bytes the reference verifier accepts.
    #[test]
    fn independent_authority_verifies_and_binds() {
        let m = mia();
        m.verify(MEASURED, SPEC).expect("shape/self-consistency");
        m.verify_binds(
            INVENTORY.as_bytes(),
            REPORT_JSON.as_bytes(),
            ELIG_JSON.as_bytes(),
            MEASURED,
            SPEC,
        )
        .expect("binds retained bytes");
    }

    #[test]
    fn independent_swapped_bytes_refused() {
        let m = mia();
        assert!(m
            .verify_binds(
                REPORT_JSON.as_bytes(),
                INVENTORY.as_bytes(),
                ELIG_JSON.as_bytes(),
                MEASURED,
                SPEC
            )
            .is_err());
    }

    #[test]
    fn independent_mutually_edited_report_refused() {
        let mut m = mia();
        m.malformed_corpus_report_address = "f".repeat(64);
        m.address = m.recompute_address();
        m.verify(MEASURED, SPEC)
            .expect("re-addressed MIA internally consistent");
        let e = m
            .verify_binds(
                INVENTORY.as_bytes(),
                REPORT_JSON.as_bytes(),
                ELIG_JSON.as_bytes(),
                MEASURED,
                SPEC,
            )
            .expect_err("bound report != retained report refused");
        assert!(e.contains("report address != retained report"), "{e}");
    }

    #[test]
    fn independent_mutually_edited_eligibility_refused() {
        // A self-consistently re-addressed MIA that binds a DIFFERENT eligibility address than the
        // retained record hashes to: verify() passes but verify_binds() refuses.
        let mut m = mia();
        m.eligibility_matrix_address = "a".repeat(64);
        m.address = m.recompute_address();
        m.verify(MEASURED, SPEC)
            .expect("re-addressed MIA internally consistent");
        let e = m
            .verify_binds(
                INVENTORY.as_bytes(),
                REPORT_JSON.as_bytes(),
                ELIG_JSON.as_bytes(),
                MEASURED,
                SPEC,
            )
            .expect_err("bound eligibility != retained record refused");
        assert!(e.contains("eligibility-matrix address"), "{e}");
    }

    #[test]
    fn independent_tampered_address_refused() {
        let mut m = mia();
        let mut a: Vec<char> = m.address.chars().collect();
        let last = a.len() - 1;
        a[last] = if a[last] == '0' { '1' } else { '0' };
        m.address = a.into_iter().collect();
        assert!(m.verify(MEASURED, SPEC).is_err());
    }

    #[test]
    fn independent_unknown_rss_policy_refused() {
        let mut m = mia();
        m.rss_statement_binding_policy = "last-write-wins/v0".into();
        m.address = m.recompute_address();
        assert!(m.verify(MEASURED, SPEC).is_err());
    }
}

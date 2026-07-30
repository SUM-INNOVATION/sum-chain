//! Strengthened Option A: the TWO distinct outputs of a first-class TEST_ONLY smoke.
//!
//! A first-class smoke drives the REAL candidate seams (build → lock → Stage-2 audit → material
//! → Stage-5 proof/verification → assemble → seal → import) but must NEVER emit authoritative
//! evidence. It therefore produces two SEPARATE, clearly-named outputs:
//!
//!  1. [`SmokeExecutionAttestation`] — the REAL, checksum-verified prover/verifier executables
//!     that actually ran: exact `--version`, point-of-use SHA-256, candidate / arch / container
//!     digest, the clean PR-head source SHA, and a CAUSAL binding (the Stage-5 output each binary
//!     produced). It is stored ONLY as TEST_ONLY smoke evidence and is NEVER a
//!     [`super::tool_install::ToolBindingRecord`] — authoritative readers do not accept it.
//!  2. The sealed TEST_ONLY bundle — uses the existing unmistakably-synthetic Stage-5b identity
//!     sentinel, preserving the `TEST_ONLY ⇒ synthetic identity` invariant and staying
//!     permanently non-finalizable.
//!
//! Smoke success REQUIRES the attestation to AGREE with the actual Stage-5 execution BEFORE the
//! synthetic sentinel identity is substituted into the sealed bundle; the substitution is
//! EXPLICIT and LOGGED, never silent ([`plan_synthetic_substitution`]).
//!
//! Source authority: a smoke run binds a distinct [`SmokeSourceBinding`] under its own domain tag
//! ([`crate::tags::SMOKE_SOURCE_TAG`]) whose classification can ONLY be TEST_ONLY / NON_SELECTION.
//! The classification + PR-head are inside the sealed hash, so editing either after sealing breaks
//! it, and an authoritative reader rejects the record outright ([`SmokeSourceBinding`] is not an
//! authoritative source identity, and [`SmokeClass`] has no authoritative variant). There is NO
//! env-var bypass and NO reuse of an authoritative runnable-ref sidecar.

use super::{is_hex64, is_synthetic};
use crate::hashing::prefixed;
use crate::tags::{SMOKE_ATTEST_TAG, SMOKE_SOURCE_TAG};

/// A smoke classification — NEVER authoritative. The enum has NO authoritative variant, so a
/// record edited to claim `AUTHORITATIVE_STAGE1` fails to deserialize; an authoritative reader
/// can never be handed a smoke record that decodes as authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SmokeClass {
    #[serde(rename = "TEST_ONLY")]
    TestOnly,
    #[serde(rename = "NON_SELECTION")]
    NonSelection,
}

impl SmokeClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            SmokeClass::TestOnly => "TEST_ONLY",
            SmokeClass::NonSelection => "NON_SELECTION",
        }
    }
}

pub const SMOKE_SCHEMA_VERSION: u16 = 1;

/// One REAL executable that actually ran during the smoke (a prover/verifier/audit binary).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeExecutable {
    /// The executable name as invoked (`cargo-prove`, `cargo-risczero`, `r0vm`, `cargo-audit`).
    pub executable_name: String,
    /// The exact `--version` output.
    pub version_output: String,
    /// SHA-256 (bare 64-hex) of the DOWNLOADED artifact bytes, verified against the ratified
    /// source pin before install.
    pub checksum_verified_hex: String,
    /// SHA-256 (bare 64-hex) recomputed at the POINT OF USE — the binary that ACTUALLY ran.
    pub point_of_use_sha256: String,
    /// CAUSAL binding (bare 64-hex BLAKE3): a Stage-5 output artifact this exact binary produced.
    /// This is what lets the smoke prove the ATTESTED binaries are the ones that ran, before the
    /// synthetic sentinel identity is substituted into the sealed bundle.
    pub produced_output_blake3: String,
}

/// Output (1): the real execution attestation. TEST_ONLY smoke evidence ONLY — never an
/// authoritative tool-binding record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeExecutionAttestation {
    pub schema_version: u16,
    /// Always a smoke class — the type cannot express an authoritative classification.
    pub classification: SmokeClass,
    pub candidate: String,
    pub arch: String,
    /// The builder-image `sha256:<64hex>` digest the binaries ran inside.
    pub container_digest: String,
    /// The exact clean PR-head SHA (40 lowercase hex) the smoke ran against.
    pub source_pr_head: String,
    /// The real executables that ran (>= 1).
    pub executables: Vec<SmokeExecutable>,
}

/// Output source-authority: the distinct smoke SOURCE binding. Its own domain tag; an
/// authoritative reader rejects it, and its classification + source are in the sealed hash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeSourceBinding {
    pub schema_version: u16,
    pub classification: SmokeClass,
    /// The exact clean PR-head SHA (40 lowercase hex). Never satisfies `RATIFIED_SOURCE_COMMIT`:
    /// authoritative gates require a DISTINCT ratified value, and this record is not the type
    /// they read.
    pub source_pr_head: String,
    /// Free-text note (kept out of the sealed identity math but part of the JSON record).
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmokeError {
    Missing(&'static str),
    BadHash(&'static str),
    BadArch {
        arch: String,
    },
    BadContainerDigest {
        digest: String,
    },
    BadPrHead {
        got: String,
    },
    UnknownCandidate {
        candidate: String,
    },
    NotTestOnly,
    /// A supposedly-synthetic sentinel handed to the substitution was NOT unmistakably synthetic.
    SentinelNotSynthetic,
    /// The attestation carried a REAL executable whose causal output is not among the observed
    /// Stage-5 outputs — the attested binary is not the one that ran.
    AttestationDisagrees {
        executable: String,
    },
    /// No executables were attested.
    NoExecutables,
}

impl std::fmt::Display for SmokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmokeError::Missing(x) => write!(f, "smoke record field {x} is absent (fails closed)"),
            SmokeError::BadHash(x) => write!(f, "smoke record {x} is not bare 64-hex"),
            SmokeError::BadArch { arch } => write!(f, "smoke arch must be x86_64|aarch64 (got {arch:?})"),
            SmokeError::BadContainerDigest { digest } => {
                write!(f, "smoke container_digest invalid (need sha256:<64hex>): {digest:?}")
            }
            SmokeError::BadPrHead { got } => {
                write!(f, "smoke source_pr_head must be 40 lowercase hex: {got:?}")
            }
            SmokeError::UnknownCandidate { candidate } => {
                write!(f, "smoke candidate must be Sp1|Risc0 (got {candidate:?})")
            }
            SmokeError::NotTestOnly => write!(
                f,
                "smoke record classification must be TEST_ONLY / NON_SELECTION (never authoritative)"
            ),
            SmokeError::SentinelNotSynthetic => write!(
                f,
                "substitution sentinel is not unmistakably synthetic; a smoke bundle must carry the \
                 TEST_ONLY_SYNTHETIC sentinel identity"
            ),
            SmokeError::AttestationDisagrees { executable } => write!(
                f,
                "smoke attestation disagrees with the actual Stage-5 execution for {executable:?}: \
                 its causal output is not among the observed outputs — the attested binary did not run"
            ),
            SmokeError::NoExecutables => write!(f, "smoke attestation names no executables"),
        }
    }
}

impl std::error::Error for SmokeError {}

fn is_pr_head(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn check_container_digest(d: &str) -> Result<(), SmokeError> {
    match d.strip_prefix("sha256:") {
        Some(hex) if is_hex64(hex) => Ok(()),
        _ => Err(SmokeError::BadContainerDigest {
            digest: d.to_string(),
        }),
    }
}

impl SmokeExecutable {
    fn validate(&self) -> Result<(), SmokeError> {
        if self.executable_name.trim().is_empty() {
            return Err(SmokeError::Missing("executable_name"));
        }
        if self.version_output.trim().is_empty() {
            return Err(SmokeError::Missing("version_output"));
        }
        for (field, v) in [
            ("checksum_verified_hex", &self.checksum_verified_hex),
            ("point_of_use_sha256", &self.point_of_use_sha256),
            ("produced_output_blake3", &self.produced_output_blake3),
        ] {
            if v.trim().is_empty() {
                return Err(SmokeError::Missing(match field {
                    "checksum_verified_hex" => "checksum_verified_hex",
                    "point_of_use_sha256" => "point_of_use_sha256",
                    _ => "produced_output_blake3",
                }));
            }
            if !is_hex64(v) {
                return Err(SmokeError::BadHash(match field {
                    "checksum_verified_hex" => "checksum_verified_hex",
                    "point_of_use_sha256" => "point_of_use_sha256",
                    _ => "produced_output_blake3",
                }));
            }
        }
        Ok(())
    }
}

impl SmokeExecutionAttestation {
    /// Validate the attestation. Every field is MANDATORY; the classification can only be a smoke
    /// class (the type has no authoritative variant); it is never a tool-binding record.
    pub fn validate(&self) -> Result<(), SmokeError> {
        if self.schema_version != SMOKE_SCHEMA_VERSION {
            return Err(SmokeError::Missing("schema_version"));
        }
        // classification is a SmokeClass by type; be explicit that authoritative is impossible.
        match self.classification {
            SmokeClass::TestOnly | SmokeClass::NonSelection => {}
        }
        if self.candidate != "Sp1" && self.candidate != "Risc0" {
            return Err(SmokeError::UnknownCandidate {
                candidate: self.candidate.clone(),
            });
        }
        match self.arch.as_str() {
            "x86_64" | "aarch64" => {}
            other => {
                return Err(SmokeError::BadArch {
                    arch: other.to_string(),
                })
            }
        }
        check_container_digest(&self.container_digest)?;
        if !is_pr_head(&self.source_pr_head) {
            return Err(SmokeError::BadPrHead {
                got: self.source_pr_head.clone(),
            });
        }
        if self.executables.is_empty() {
            return Err(SmokeError::NoExecutables);
        }
        for e in &self.executables {
            e.validate()?;
        }
        Ok(())
    }

    /// Domain-separated identity of the attestation (never mistaken for an authoritative tool
    /// binding, which uses a different domain).
    pub fn attestation_hash(&self) -> String {
        let mut pre: Vec<u8> = Vec::new();
        pre.extend_from_slice(self.classification.as_str().as_bytes());
        pre.push(0);
        pre.extend_from_slice(self.candidate.as_bytes());
        pre.push(0);
        pre.extend_from_slice(self.arch.as_bytes());
        pre.push(0);
        pre.extend_from_slice(self.container_digest.as_bytes());
        pre.push(0);
        pre.extend_from_slice(self.source_pr_head.as_bytes());
        pre.push(0);
        for e in &self.executables {
            for field in [
                e.executable_name.as_str(),
                e.version_output.as_str(),
                e.checksum_verified_hex.as_str(),
                e.point_of_use_sha256.as_str(),
                e.produced_output_blake3.as_str(),
            ] {
                pre.extend_from_slice(&(field.len() as u64).to_le_bytes());
                pre.extend_from_slice(field.as_bytes());
            }
        }
        super::to_hex(&prefixed(&SMOKE_ATTEST_TAG, &pre))
    }
}

impl SmokeSourceBinding {
    /// Validate: a smoke source binding is only ever TEST_ONLY / NON_SELECTION with a clean
    /// PR-head. It is NOT an authoritative source identity and can never satisfy a ratified gate.
    pub fn validate(&self) -> Result<(), SmokeError> {
        if self.schema_version != SMOKE_SCHEMA_VERSION {
            return Err(SmokeError::Missing("schema_version"));
        }
        match self.classification {
            SmokeClass::TestOnly | SmokeClass::NonSelection => {}
        }
        if !is_pr_head(&self.source_pr_head) {
            return Err(SmokeError::BadPrHead {
                got: self.source_pr_head.clone(),
            });
        }
        Ok(())
    }

    /// The sealed identity of the smoke source binding, bound into the bundle's sealed hashes.
    /// The classification AND the PR-head are INSIDE this hash under a smoke-only domain tag, so
    /// editing either after sealing breaks the hash, and no authoritative source domain can
    /// reproduce it.
    pub fn sealed_hash(&self) -> String {
        let mut pre: Vec<u8> = Vec::new();
        pre.extend_from_slice(&self.schema_version.to_le_bytes());
        let cls = self.classification.as_str();
        pre.extend_from_slice(&(cls.len() as u64).to_le_bytes());
        pre.extend_from_slice(cls.as_bytes());
        pre.extend_from_slice(&(self.source_pr_head.len() as u64).to_le_bytes());
        pre.extend_from_slice(self.source_pr_head.as_bytes());
        super::to_hex(&prefixed(&SMOKE_SOURCE_TAG, &pre))
    }
}

/// The EXPLICIT, LOGGED record of substituting the synthetic sentinel identity for the real one
/// in the sealed TEST_ONLY bundle. Returned only after the attestation AGREES with the actual
/// Stage-5 execution — the substitution is never silent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SubstitutionLog {
    pub reason: String,
    /// The real executables (name + point-of-use hash) the smoke actually ran, preserved in the
    /// ATTESTATION (not the sealed bundle).
    pub real_executables: Vec<(String, String)>,
    /// The unmistakably-synthetic sentinel identity written into the sealed bundle instead.
    pub synthetic_sentinel: String,
    /// The attestation identity that was verified to agree before substitution.
    pub attestation_hash: String,
}

/// Verify the attestation AGREES with the actual Stage-5 execution, then return an EXPLICIT,
/// LOGGED plan to substitute the unmistakably-synthetic sentinel identity into the sealed bundle.
/// Fails closed if the attestation is missing/malformed, if any attested executable's causal
/// output is not among the observed Stage-5 outputs (disagreement), or if the sentinel is not
/// unmistakably synthetic. The substitution is NEVER performed silently: callers must record the
/// returned [`SubstitutionLog`].
pub fn plan_synthetic_substitution(
    attest: &SmokeExecutionAttestation,
    observed_stage5_output_blake3: &[String],
    synthetic_sentinel: &str,
) -> Result<SubstitutionLog, SmokeError> {
    attest.validate()?;
    if !is_synthetic(synthetic_sentinel) {
        return Err(SmokeError::SentinelNotSynthetic);
    }
    // Agreement: every attested binary's causal output MUST be among the actually-observed
    // Stage-5 outputs. A missing/mismatched attestation fails the smoke here (never a silent skip).
    for e in &attest.executables {
        if !observed_stage5_output_blake3
            .iter()
            .any(|o| o == &e.produced_output_blake3)
        {
            return Err(SmokeError::AttestationDisagrees {
                executable: e.executable_name.clone(),
            });
        }
    }
    Ok(SubstitutionLog {
        reason: "smoke: real executable identities verified to have produced the Stage-5 outputs; \
                 substituting the unmistakably-synthetic Stage-5b sentinel into the sealed TEST_ONLY \
                 bundle to preserve TEST_ONLY ⇒ synthetic (bundle stays permanently non-finalizable)"
            .to_string(),
        real_executables: attest
            .executables
            .iter()
            .map(|e| (e.executable_name.clone(), e.point_of_use_sha256.clone()))
            .collect(),
        synthetic_sentinel: synthetic_sentinel.to_string(),
        attestation_hash: attest.attestation_hash(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::venue::sha256;

    const SENT: &str = super::super::TEST_ONLY_SENTINEL;

    fn h(s: &str) -> String {
        sha256::hex_digest(s.as_bytes())
    }
    fn bh(s: &str) -> String {
        super::super::to_hex(blake3::hash(s.as_bytes()).as_bytes())
    }

    fn exe(name: &str, out: &str) -> SmokeExecutable {
        SmokeExecutable {
            executable_name: name.into(),
            version_output: format!("{name} 1.2.3"),
            checksum_verified_hex: h(&format!("{name}-download")),
            point_of_use_sha256: h(&format!("{name}-installed")),
            produced_output_blake3: bh(out),
        }
    }

    fn attest() -> SmokeExecutionAttestation {
        SmokeExecutionAttestation {
            schema_version: SMOKE_SCHEMA_VERSION,
            classification: SmokeClass::TestOnly,
            candidate: "Sp1".into(),
            arch: "x86_64".into(),
            container_digest: format!("sha256:{}", h("builder")),
            source_pr_head: "a".repeat(40),
            executables: vec![
                exe("cargo-prove", "stage5-out-1"),
                exe("r0vm", "stage5-out-2"),
            ],
        }
    }

    fn src() -> SmokeSourceBinding {
        SmokeSourceBinding {
            schema_version: SMOKE_SCHEMA_VERSION,
            classification: SmokeClass::TestOnly,
            source_pr_head: "a".repeat(40),
            note: "TEST_ONLY smoke".into(),
        }
    }

    #[test]
    fn attestation_validates_and_hashes() {
        let a = attest();
        assert_eq!(a.validate(), Ok(()));
        assert!(is_hex64(&a.attestation_hash()));
    }

    #[test]
    fn attestation_fails_closed_on_absent_causal_output() {
        let mut a = attest();
        a.executables[0].produced_output_blake3 = String::new();
        assert_eq!(
            a.validate(),
            Err(SmokeError::Missing("produced_output_blake3"))
        );
    }

    #[test]
    fn attestation_rejects_bad_pr_head_and_container() {
        let mut a = attest();
        a.source_pr_head = "A".repeat(40); // uppercase
        assert!(matches!(a.validate(), Err(SmokeError::BadPrHead { .. })));
        let mut b = attest();
        b.container_digest = "deadbeef".into();
        assert!(matches!(
            b.validate(),
            Err(SmokeError::BadContainerDigest { .. })
        ));
    }

    // NEGATIVE #5: missing/mismatched real execution attestation fails the smoke.
    #[test]
    fn substitution_requires_attestation_to_agree_with_execution() {
        let a = attest();
        // observed outputs match both attested causal outputs -> substitution planned + logged.
        let observed = vec![bh("stage5-out-1"), bh("stage5-out-2")];
        let log = plan_synthetic_substitution(&a, &observed, &format!("{SENT}:sp1-verifier"))
            .expect("agreement");
        assert!(log.synthetic_sentinel.contains(SENT));
        assert_eq!(log.real_executables.len(), 2);
        assert_eq!(log.attestation_hash, a.attestation_hash());

        // a MISSING observed output for one attested binary -> disagreement -> fails closed.
        let partial = vec![bh("stage5-out-1")];
        assert!(matches!(
            plan_synthetic_substitution(&a, &partial, &format!("{SENT}:sp1-verifier")),
            Err(SmokeError::AttestationDisagrees { .. })
        ));
        // an empty observed set -> fails closed (no silent success).
        assert!(matches!(
            plan_synthetic_substitution(&a, &[], &format!("{SENT}:sp1-verifier")),
            Err(SmokeError::AttestationDisagrees { .. })
        ));
    }

    // The substitution sentinel MUST be unmistakably synthetic (never a real identity).
    #[test]
    fn substitution_refuses_a_nonsynthetic_sentinel() {
        let a = attest();
        let observed = vec![bh("stage5-out-1"), bh("stage5-out-2")];
        assert_eq!(
            plan_synthetic_substitution(&a, &observed, "https://real.example/sp1-verifier"),
            Err(SmokeError::SentinelNotSynthetic)
        );
    }

    #[test]
    fn source_binding_validates() {
        assert_eq!(src().validate(), Ok(()));
    }

    // NEGATIVE #4: changing classification or source after sealing breaks the sealed hash.
    #[test]
    fn editing_classification_or_source_breaks_the_sealed_hash() {
        let base = src().sealed_hash();
        let mut c = src();
        c.classification = SmokeClass::NonSelection;
        assert_ne!(
            c.sealed_hash(),
            base,
            "classification is inside the sealed hash"
        );
        let mut s = src();
        s.source_pr_head = "b".repeat(40);
        assert_ne!(
            s.sealed_hash(),
            base,
            "source PR-head is inside the sealed hash"
        );
    }

    // NEGATIVE #3 (part): a smoke source binding cannot be edited into an authoritative one — the
    // enum has no authoritative variant, so the JSON simply fails to deserialize.
    #[test]
    fn smoke_class_has_no_authoritative_variant() {
        let json = serde_json::to_string(&src()).unwrap();
        let flipped = json.replace("\"TEST_ONLY\"", "\"AUTHORITATIVE_STAGE1\"");
        assert!(
            serde_json::from_str::<SmokeSourceBinding>(&flipped).is_err(),
            "editing the classification string to authoritative must fail to decode"
        );
        // and an unknown field is rejected (deny_unknown_fields).
        let extra = json.replace("\"note\"", "\"bogus\":1,\"note\"");
        assert!(serde_json::from_str::<SmokeSourceBinding>(&extra).is_err());
    }

    #[test]
    fn attestation_round_trips_and_rejects_unknown_fields() {
        let a = attest();
        let s = serde_json::to_string(&a).unwrap();
        let back: SmokeExecutionAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
        let bad = s.replace("\"executables\"", "\"bogus\":1,\"executables\"");
        assert!(serde_json::from_str::<SmokeExecutionAttestation>(&bad).is_err());
    }

    // NEGATIVE #3: the authoritative reader (build_finalizable_artifact / the Stage-1 ingest
    // gate) REJECTS a smoke source binding AND a smoke execution attestation — neither is a
    // Stage-1 result bundle, so authoritative ingest can never mint an artifact from smoke
    // evidence, even before the classification enum forbids an authoritative value.
    #[test]
    fn authoritative_reader_rejects_smoke_records() {
        use crate::schema::stage1_bundle::build_finalizable_artifact;
        let src_json = serde_json::to_vec(&src()).unwrap();
        assert!(
            build_finalizable_artifact(&src_json).is_err(),
            "authoritative ingest must reject a smoke SOURCE binding"
        );
        let att_json = serde_json::to_vec(&attest()).unwrap();
        assert!(
            build_finalizable_artifact(&att_json).is_err(),
            "authoritative ingest must reject a smoke execution ATTESTATION"
        );
        // and a smoke attestation is NOT interchangeable with a ToolBindingRecord: its
        // deny_unknown_fields shape rejects the authoritative tool-binding fields.
        let as_tool = serde_json::to_string(&attest()).unwrap().replace(
            "\"executables\"",
            "\"installed_binary_sha256_hex\":\"x\",\"executables\"",
        );
        assert!(serde_json::from_str::<SmokeExecutionAttestation>(&as_tool).is_err());
    }
}

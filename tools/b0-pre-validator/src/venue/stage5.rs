//! Blocker 4: a real, required Stage-5 verifier-fixture + mutation result.
//!
//! Stage 5 runs the pinned terminal verifier over a candidate's real fixture and a
//! full suite of REQUIRED mutation cases, asserting the verifier REJECTS every
//! mutation. A well-formed JSON claim is not evidence: the result carries the
//! fixture / raw-artifact hashes, the verifier identity, EVERY required mutation
//! case with its expected-and-actual rejection, the tool / container / source
//! identities the run was bound to, and an overall pass that is DERIVED here from
//! the individual cases — never trusted from the input.
//!
//! The real fixture execution is venue-gated (it runs the pinned verifier inside
//! the verified builder image and fails closed off-venue). This module owns the
//! typed result + the pass derivation + the completeness gate, all unit-tested
//! off-venue against real-shaped inputs (and adversarial ones).

use serde::{Deserialize, Serialize};

use super::is_hex64;

/// The mutation cases every candidate's Stage-5 run MUST exercise. Each names a
/// distinct corruption the pinned verifier must reject; a result missing any of
/// them (or carrying an unknown extra) is incomplete and refused. These are the
/// verifier-authenticity mutations that make a Stage-5 pass meaningful.
pub const REQUIRED_MUTATION_CASES: &[&str] = &[
    "flip_public_input_bit",
    "truncate_proof",
    "swap_verifier_material",
    "corrupt_terminal_claim",
    "zero_fill_receipt",
];

/// One mutation case: the corruption that was applied, whether the verifier was
/// EXPECTED to reject it (always true — a mutation must be rejected), and whether
/// it ACTUALLY did. A case whose `actual_rejected` disagrees with
/// `expected_rejected` is a Stage-5 failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5MutationCase {
    pub name: String,
    /// A mutation must be rejected, so this is always `true`; a case declaring
    /// `false` is malformed (a mutation the run did not expect to reject).
    pub expected_rejected: bool,
    /// Whether the pinned verifier actually rejected the mutated input.
    pub actual_rejected: bool,
}

/// A hashed fixture / raw-artifact input to the Stage-5 run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5FixtureHash {
    pub label: String,
    /// Bare 64-hex BLAKE3 of the fixture / raw-artifact bytes.
    pub blake3_hex: String,
    pub byte_len: u64,
}

/// The current Stage-5 result schema version.
///
/// v1 (unversioned, or `schema_version` == 1) bound `tool_identity_hex` — the SHA-256 of
/// a downloaded+installed proof-tool CLI binary — as the Stage-5 tool identity. That was
/// a FALSE causal claim: the Stage-5 fixtures + mutation rejections are produced by the
/// pinned verifier SDK *library* compiled inside the verified image, which the installed
/// CLI binary never runs. v2 instead binds the VERIFIER THAT ACTUALLY RAN — the exact
/// executed runner binary, its resolved dependency lock, and its SDK name/version — so
/// the attribution is causal. v1 remains decodable only to be REFUSED: it is INELIGIBLE
/// for authoritative evidence because its attribution is insufficient.
pub const STAGE5_SCHEMA_VERSION: u16 = 2;

/// The strict Stage-5 result for one candidate on one architecture (schema v2).
///
/// Authority for "which verifier produced this" comes EXCLUSIVELY from the hash-backed
/// `verifier_executed_binary_sha256` / `verifier_sdk_lock_blake3` / `verifier_sdk_name` /
/// `verifier_sdk_version` fields bound to the `container_digest` it ran inside and the
/// `command_log_blake3_hex` of the exact commands. `verifier_identity` is a DESCRIPTIVE
/// label only and is never trusted as identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5Result {
    /// REQUIRED schema version. Only [`STAGE5_SCHEMA_VERSION`] is eligible for
    /// authoritative evidence; an absent/older version is refused by [`Self::validate`].
    pub schema_version: u16,
    pub candidate: String,
    pub arch: String,
    /// The fixture + raw-artifact hashes the verifier consumed (at least one).
    pub fixture_hashes: Vec<Stage5FixtureHash>,
    /// A DESCRIPTIVE label only (e.g. "sp1-verifier terminal Groth16"). Authority comes
    /// EXCLUSIVELY from the hash-backed verifier_* fields below; this string is never
    /// trusted as identity and may not stand in for the executed binary + dependency set.
    pub verifier_identity: String,
    /// EVERY required mutation case, each with expected-and-actual rejection.
    pub mutation_cases: Vec<Stage5MutationCase>,
    /// SHA-256 (bare 64-hex) of the EXACT verifier-runner executable that was located and
    /// executed directly (not an unbound `cargo run`) to produce this result.
    pub verifier_executed_binary_sha256: String,
    /// BLAKE3 (bare 64-hex) of the verifier runner's resolved, in-container dependency
    /// lock — the transitive graph that pinned the verifier SDK bytes actually compiled.
    pub verifier_sdk_lock_blake3: String,
    /// The pinned verifier SDK crate name (e.g. `sp1-verifier`).
    pub verifier_sdk_name: String,
    /// The pinned verifier SDK version (e.g. `6.3.1`).
    pub verifier_sdk_version: String,
    /// The builder-image `sha256:<64hex>` digest the verifier ran inside.
    pub container_digest: String,
    /// The clean source commit (40/64-hex).
    pub source_commit: String,
    /// Bound to the exact in-container commands that ran the verifier + mutations
    /// (bare 64-hex BLAKE3 of the command log).
    pub command_log_blake3_hex: String,
    /// OPTIONAL upstream proof-producer tool identity (bare 64-hex) — set ONLY when the
    /// tool that produced the proof being verified is CAUSALLY established (authenticated
    /// delivery + rehash-at-point-of-use + that exact binary executed). It is separate
    /// upstream provenance and NEVER a substitute for the verifier identity above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_producer_tool_identity: Option<String>,
    /// The OVERALL pass. Validation requires it to equal the value DERIVED from the
    /// individual cases (all required present, each rejected); a lying `true` is
    /// refused.
    pub overall_pass: bool,
}

/// Peek the `schema_version` of a raw Stage-5 record WITHOUT a strict decode, so the
/// importer can reject an inadequate v1 (or unversioned) record with a clear trust error
/// instead of a generic parse failure. Returns 0 when the field is absent or unparseable.
pub fn peek_stage5_schema_version(raw: &[u8]) -> u16 {
    #[derive(Deserialize)]
    struct V {
        #[serde(default)]
        schema_version: u16,
    }
    serde_json::from_slice::<V>(raw)
        .map(|v| v.schema_version)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage5Error {
    Missing(&'static str),
    /// The record's `schema_version` is not the authoritative-eligible
    /// [`STAGE5_SCHEMA_VERSION`] (e.g. an inadequate v1 record whose attribution binds a
    /// non-causal installed CLI instead of the executed verifier).
    UnsupportedSchemaVersion {
        got: u16,
    },
    UnknownCandidate {
        candidate: String,
    },
    UnknownArch {
        arch: String,
    },
    /// A required mutation case was absent.
    MissingCase {
        name: String,
    },
    /// A mutation case appeared more than once.
    DuplicateCase {
        name: String,
    },
    /// A case not in [`REQUIRED_MUTATION_CASES`] was present.
    UnknownCase {
        name: String,
    },
    /// A case declared `expected_rejected != true` (a mutation must be rejected).
    NonRejectingExpectation {
        name: String,
    },
    /// A case the verifier did NOT reject (`actual_rejected == false`).
    MutationNotRejected {
        name: String,
    },
    /// A hash field was not bare 64-hex.
    BadHash(&'static str),
    /// The recorded `overall_pass` disagreed with the derived value.
    OverallPassMismatch {
        recorded: bool,
        derived: bool,
    },
    /// A fixture hash was malformed / empty.
    BadFixture(String),
}

impl std::fmt::Display for Stage5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stage5Error::Missing(field) => write!(f, "required Stage-5 field {field} is empty"),
            Stage5Error::UnsupportedSchemaVersion { got } => write!(
                f,
                "Stage-5 schema_version {got} is not the authoritative-eligible v{} \
                 (a v1/unversioned record binds a non-causal installed CLI, not the \
                 executed verifier, and is refused for authoritative evidence)",
                STAGE5_SCHEMA_VERSION
            ),
            Stage5Error::UnknownCandidate { candidate } => {
                write!(f, "unknown candidate {candidate:?}")
            }
            Stage5Error::UnknownArch { arch } => write!(f, "unknown architecture {arch:?}"),
            Stage5Error::MissingCase { name } => {
                write!(f, "required mutation case {name:?} is absent")
            }
            Stage5Error::DuplicateCase { name } => write!(f, "mutation case {name:?} is duplicated"),
            Stage5Error::UnknownCase { name } => {
                write!(f, "unknown mutation case {name:?} (not a required case)")
            }
            Stage5Error::NonRejectingExpectation { name } => write!(
                f,
                "mutation case {name:?} must expect rejection (expected_rejected=true)"
            ),
            Stage5Error::MutationNotRejected { name } => write!(
                f,
                "mutation case {name:?} was NOT rejected by the verifier (actual_rejected=false)"
            ),
            Stage5Error::BadHash(field) => write!(f, "Stage-5 {field} is not bare 64-hex"),
            Stage5Error::OverallPassMismatch { recorded, derived } => write!(
                f,
                "overall_pass recorded {recorded} != derived {derived} (a Stage-5 pass is derived from the cases)"
            ),
            Stage5Error::BadFixture(m) => write!(f, "Stage-5 fixture hash invalid: {m}"),
        }
    }
}

impl std::error::Error for Stage5Error {}

fn known_candidate(c: &str) -> bool {
    c == "Sp1" || c == "Risc0"
}

fn known_arch(a: &str) -> bool {
    a == "X86_64" || a == "Aarch64"
}

impl Stage5Result {
    /// Derive the overall pass from the individual cases: every required case must
    /// be present exactly once, expect rejection, and have actually been rejected.
    /// Returns `Ok(())` only when the derivation itself is a pass. This is the ONE
    /// place a Stage-5 pass is decided; `validate` compares the recorded flag to it.
    pub fn derive_pass(&self) -> Result<(), Stage5Error> {
        // exactly the required set, each once, no unknown extras.
        let mut seen: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for c in &self.mutation_cases {
            if !REQUIRED_MUTATION_CASES.contains(&c.name.as_str()) {
                return Err(Stage5Error::UnknownCase {
                    name: c.name.clone(),
                });
            }
            *seen.entry(c.name.as_str()).or_insert(0) += 1;
        }
        for req in REQUIRED_MUTATION_CASES {
            match seen.get(req) {
                None => {
                    return Err(Stage5Error::MissingCase {
                        name: (*req).to_string(),
                    })
                }
                Some(n) if *n > 1 => {
                    return Err(Stage5Error::DuplicateCase {
                        name: (*req).to_string(),
                    })
                }
                Some(_) => {}
            }
        }
        // every case must expect rejection and have been rejected.
        for c in &self.mutation_cases {
            if !c.expected_rejected {
                return Err(Stage5Error::NonRejectingExpectation {
                    name: c.name.clone(),
                });
            }
            if !c.actual_rejected {
                return Err(Stage5Error::MutationNotRejected {
                    name: c.name.clone(),
                });
            }
        }
        Ok(())
    }

    /// Strictly validate the result: known candidate/arch, well-formed fixture +
    /// identity hashes, the full required mutation suite all rejected, and a
    /// recorded `overall_pass` that EQUALS the derived pass. Any deviation fails
    /// closed. The container-digest / source-commit binding shape is checked here;
    /// binding those to the manifest is done by the evidence-bundle importer.
    pub fn validate(&self) -> Result<(), Stage5Error> {
        // Only the current schema version is eligible; an inadequate v1/unversioned
        // record is refused BEFORE any other check (its attribution is non-causal).
        if self.schema_version != STAGE5_SCHEMA_VERSION {
            return Err(Stage5Error::UnsupportedSchemaVersion {
                got: self.schema_version,
            });
        }
        if !known_candidate(&self.candidate) {
            return Err(Stage5Error::UnknownCandidate {
                candidate: self.candidate.clone(),
            });
        }
        if !known_arch(&self.arch) {
            return Err(Stage5Error::UnknownArch {
                arch: self.arch.clone(),
            });
        }
        // `verifier_identity` is a descriptive label; require it be non-empty but it is
        // NOT the authority — the hash-backed fields below are.
        if self.verifier_identity.trim().is_empty() {
            return Err(Stage5Error::Missing("verifier_identity"));
        }
        // The CAUSAL verifier identity: the executed binary + its dependency lock, plus a
        // non-empty SDK name/version. These are what bind "the verifier that actually ran".
        if !is_hex64(&self.verifier_executed_binary_sha256) {
            return Err(Stage5Error::BadHash("verifier_executed_binary_sha256"));
        }
        if !is_hex64(&self.verifier_sdk_lock_blake3) {
            return Err(Stage5Error::BadHash("verifier_sdk_lock_blake3"));
        }
        if self.verifier_sdk_name.trim().is_empty() {
            return Err(Stage5Error::Missing("verifier_sdk_name"));
        }
        if self.verifier_sdk_version.trim().is_empty() {
            return Err(Stage5Error::Missing("verifier_sdk_version"));
        }
        // The optional upstream proof-producer identity, when present, must be a bare
        // 64-hex identity (it is separate provenance, never the verifier authority).
        if let Some(p) = &self.proof_producer_tool_identity {
            if !is_hex64(p) {
                return Err(Stage5Error::BadHash("proof_producer_tool_identity"));
            }
        }
        if self.source_commit.trim().is_empty() {
            return Err(Stage5Error::Missing("source_commit"));
        }
        if !is_hex64(&self.command_log_blake3_hex) {
            return Err(Stage5Error::BadHash("command_log_blake3_hex"));
        }
        // container digest must be a full sha256:<64hex>.
        match self.container_digest.strip_prefix("sha256:") {
            Some(hex) if is_hex64(hex) => {}
            _ => return Err(Stage5Error::BadHash("container_digest")),
        }
        if self.fixture_hashes.is_empty() {
            return Err(Stage5Error::BadFixture(
                "at least one fixture is required".into(),
            ));
        }
        for fx in &self.fixture_hashes {
            if fx.label.trim().is_empty() {
                return Err(Stage5Error::BadFixture("empty fixture label".into()));
            }
            if !is_hex64(&fx.blake3_hex) {
                return Err(Stage5Error::BadFixture(format!(
                    "fixture {:?} hash is not bare 64-hex",
                    fx.label
                )));
            }
            if fx.byte_len == 0 {
                return Err(Stage5Error::BadFixture(format!(
                    "fixture {:?} has zero length",
                    fx.label
                )));
            }
        }
        // Derive the pass and require the recorded flag to match it.
        let derived_pass = self.derive_pass().is_ok();
        if self.overall_pass != derived_pass {
            return Err(Stage5Error::OverallPassMismatch {
                recorded: self.overall_pass,
                derived: derived_pass,
            });
        }
        // A validated Stage-5 result must be a genuine pass (the derivation held).
        self.derive_pass()
    }
}

// ---- Raw fixture/mutation execution -> typed, bound Stage-5 evidence ---------

/// Binding inputs the venue holds for the Stage-5 record. The fixture hashes are
/// computed HERE from raw artifact bytes, the mutation outcomes come from the ACTUAL
/// verifier runs, `overall_pass` is DERIVED (never supplied), and the command-log hash
/// is computed here from the raw log.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5BindParams {
    pub candidate: String,
    pub arch: String,
    /// Descriptive label only (see [`Stage5Result::verifier_identity`]).
    pub verifier_identity: String,
    /// SHA-256 (bare 64-hex) of the exact executed verifier-runner binary.
    pub verifier_executed_binary_sha256: String,
    /// BLAKE3 (bare 64-hex) of the verifier runner's resolved dependency lock.
    pub verifier_sdk_lock_blake3: String,
    pub verifier_sdk_name: String,
    pub verifier_sdk_version: String,
    pub container_digest: String,
    pub source_commit: String,
    /// Optional upstream proof-producer identity (bare 64-hex), only when causally bound.
    #[serde(default)]
    pub proof_producer_tool_identity: Option<String>,
}

/// One raw fixture/receipt/material artifact the verifier consumed: a label and the
/// path to its bytes (hashed here, not trusted).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5FixtureInput {
    pub label: String,
    pub path: String,
}

/// The observed outcome of ONE mutation case from the actual verifier run.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5MutationOutcome {
    pub name: String,
    /// Whether the pinned verifier ACTUALLY rejected the mutated input.
    pub actual_rejected: bool,
}

impl Stage5Result {
    /// Build a typed, bound Stage-5 result from GENUINE execution outcomes: fixture
    /// hashes computed from the raw artifact bytes, each mutation case carrying the
    /// ACTUAL observed rejection, `overall_pass` DERIVED from the individual results (a
    /// supplied pass is never accepted), and the command-log hash computed here. The
    /// result is fully validated, so it is emitted ONLY when the run genuinely passed
    /// (every required mutation present and rejected, fixtures well-formed).
    pub fn generate(
        params: &Stage5BindParams,
        fixtures: &[(String, Vec<u8>)],
        mutations: &[Stage5MutationOutcome],
        command_log_bytes: &[u8],
    ) -> Result<Stage5Result, Stage5Error> {
        let fixture_hashes = fixtures
            .iter()
            .map(|(label, bytes)| Stage5FixtureHash {
                label: label.clone(),
                blake3_hex: super::to_hex(blake3::hash(bytes).as_bytes()),
                byte_len: bytes.len() as u64,
            })
            .collect();
        let mutation_cases = mutations
            .iter()
            .map(|m| Stage5MutationCase {
                name: m.name.clone(),
                expected_rejected: true, // a mutation must be rejected
                actual_rejected: m.actual_rejected,
            })
            .collect();
        let mut result = Stage5Result {
            schema_version: STAGE5_SCHEMA_VERSION,
            candidate: params.candidate.clone(),
            arch: params.arch.clone(),
            fixture_hashes,
            verifier_identity: params.verifier_identity.clone(),
            mutation_cases,
            verifier_executed_binary_sha256: params.verifier_executed_binary_sha256.clone(),
            verifier_sdk_lock_blake3: params.verifier_sdk_lock_blake3.clone(),
            verifier_sdk_name: params.verifier_sdk_name.clone(),
            verifier_sdk_version: params.verifier_sdk_version.clone(),
            container_digest: params.container_digest.clone(),
            source_commit: params.source_commit.clone(),
            command_log_blake3_hex: super::to_hex(blake3::hash(command_log_bytes).as_bytes()),
            proof_producer_tool_identity: params.proof_producer_tool_identity.clone(),
            overall_pass: false,
        };
        // DERIVE the overall pass from the individual results; never read a supplied one.
        result.overall_pass = result.derive_pass().is_ok();
        // validate() re-derives + requires a genuine pass, so a failing run yields Err.
        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(label: &str) -> String {
        super::super::to_hex(blake3::hash(label.as_bytes()).as_bytes())
    }

    fn full_case(name: &str) -> Stage5MutationCase {
        Stage5MutationCase {
            name: name.into(),
            expected_rejected: true,
            actual_rejected: true,
        }
    }

    fn good_result(candidate: &str, arch: &str) -> Stage5Result {
        Stage5Result {
            schema_version: STAGE5_SCHEMA_VERSION,
            candidate: candidate.into(),
            arch: arch.into(),
            fixture_hashes: vec![Stage5FixtureHash {
                label: "terminal-proof".into(),
                blake3_hex: h("fixture"),
                byte_len: 1234,
            }],
            verifier_identity: "sp1-verifier terminal Groth16 (descriptive)".into(),
            mutation_cases: REQUIRED_MUTATION_CASES
                .iter()
                .map(|n| full_case(n))
                .collect(),
            verifier_executed_binary_sha256: h("runner-binary"),
            verifier_sdk_lock_blake3: h("runner-lock"),
            verifier_sdk_name: "sp1-verifier".into(),
            verifier_sdk_version: "6.3.1".into(),
            container_digest: format!("sha256:{}", h("container")),
            source_commit: "a".repeat(40),
            command_log_blake3_hex: h("stage5-cmd"),
            proof_producer_tool_identity: None,
            overall_pass: true,
        }
    }

    #[test]
    fn complete_all_rejected_result_passes() {
        let r = good_result("Sp1", "X86_64");
        assert_eq!(r.validate(), Ok(()));
        assert!(r.overall_pass);
    }

    #[test]
    fn a_missing_required_case_is_incomplete() {
        let mut r = good_result("Risc0", "X86_64");
        r.mutation_cases.pop(); // drop one required case
                                // overall_pass must then be false, and a claimed true is caught.
        r.overall_pass = false;
        assert!(matches!(
            r.derive_pass(),
            Err(Stage5Error::MissingCase { .. })
        ));
        // if it still claims pass, validation catches the mismatch.
        r.overall_pass = true;
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::OverallPassMismatch { .. })
        ));
    }

    #[test]
    fn a_non_rejected_mutation_fails_closed() {
        let mut r = good_result("Sp1", "Aarch64");
        // the verifier accepted a mutation (actual_rejected=false) -> not a pass.
        r.mutation_cases[0].actual_rejected = false;
        r.overall_pass = false;
        assert!(matches!(
            r.derive_pass(),
            Err(Stage5Error::MutationNotRejected { .. })
        ));
        // claiming pass anyway is caught.
        r.overall_pass = true;
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::OverallPassMismatch { .. })
        ));
    }

    #[test]
    fn an_unknown_extra_case_is_rejected() {
        let mut r = good_result("Sp1", "X86_64");
        r.mutation_cases.push(full_case("not_a_required_case"));
        assert!(matches!(
            r.derive_pass(),
            Err(Stage5Error::UnknownCase { .. })
        ));
    }

    #[test]
    fn a_duplicated_case_is_rejected() {
        let mut r = good_result("Sp1", "X86_64");
        r.mutation_cases.push(full_case(REQUIRED_MUTATION_CASES[0]));
        assert!(matches!(
            r.derive_pass(),
            Err(Stage5Error::DuplicateCase { .. })
        ));
    }

    #[test]
    fn a_lying_overall_pass_true_over_a_failing_suite_is_refused() {
        let mut r = good_result("Sp1", "X86_64");
        r.mutation_cases[2].actual_rejected = false; // one mutation not rejected
        r.overall_pass = true; // but the result LIES that it passed
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::OverallPassMismatch {
                recorded: true,
                derived: false
            })
        ));
    }

    #[test]
    fn malformed_identities_and_hashes_are_rejected() {
        let mut r = good_result("Sp1", "X86_64");
        r.verifier_executed_binary_sha256 = "not-hex".into();
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::BadHash("verifier_executed_binary_sha256"))
        ));
        let mut r2 = good_result("Sp1", "X86_64");
        r2.container_digest = "deadbeef".into();
        assert!(matches!(
            r2.validate(),
            Err(Stage5Error::BadHash("container_digest"))
        ));
        let mut r3 = good_result("Sp1", "X86_64");
        r3.candidate = "Nope".into();
        assert!(matches!(
            r3.validate(),
            Err(Stage5Error::UnknownCandidate { .. })
        ));
    }

    #[test]
    fn v1_or_unversioned_schema_is_ineligible_for_authoritative() {
        // A v1 record (schema_version != current) is refused BEFORE any other check —
        // its non-causal installed-CLI attribution is insufficient for authoritative use.
        let mut r = good_result("Sp1", "X86_64");
        r.schema_version = 1;
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::UnsupportedSchemaVersion { got: 1 })
        ));
        let mut r0 = good_result("Sp1", "X86_64");
        r0.schema_version = 0;
        assert!(matches!(
            r0.validate(),
            Err(Stage5Error::UnsupportedSchemaVersion { got: 0 })
        ));
    }

    #[test]
    fn missing_causal_verifier_bindings_are_rejected() {
        let mut r = good_result("Sp1", "X86_64");
        r.verifier_sdk_lock_blake3 = "xyz".into();
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::BadHash("verifier_sdk_lock_blake3"))
        ));
        let mut r2 = good_result("Sp1", "X86_64");
        r2.verifier_sdk_name = "  ".into();
        assert!(matches!(
            r2.validate(),
            Err(Stage5Error::Missing("verifier_sdk_name"))
        ));
        let mut r3 = good_result("Sp1", "X86_64");
        r3.verifier_sdk_version = "".into();
        assert!(matches!(
            r3.validate(),
            Err(Stage5Error::Missing("verifier_sdk_version"))
        ));
    }

    #[test]
    fn optional_proof_producer_identity_when_present_must_be_hex64() {
        let mut r = good_result("Sp1", "X86_64");
        r.proof_producer_tool_identity = Some("not-hex".into());
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::BadHash("proof_producer_tool_identity"))
        ));
        // A well-formed optional identity is accepted (it is separate provenance).
        r.proof_producer_tool_identity = Some(h("prover-cli"));
        assert!(r.validate().is_ok());
    }

    #[test]
    fn peek_schema_version_reads_v1_and_v2_and_junk() {
        let v2 = serde_json::to_vec(&good_result("Sp1", "X86_64")).unwrap();
        assert_eq!(peek_stage5_schema_version(&v2), STAGE5_SCHEMA_VERSION);
        // A v1-shaped record (no schema_version) peeks as 0 -> importer treats as ineligible.
        assert_eq!(
            peek_stage5_schema_version(br#"{"candidate":"Sp1","tool_identity_hex":"x"}"#),
            0
        );
        assert_eq!(peek_stage5_schema_version(b"not json"), 0);
    }

    // ---- raw execution outcomes → typed, bound generation -----------------

    fn s5_bind() -> Stage5BindParams {
        Stage5BindParams {
            candidate: "Sp1".into(),
            arch: "X86_64".into(),
            verifier_identity: "sp1-verifier terminal Groth16 (descriptive)".into(),
            verifier_executed_binary_sha256: h("runner-binary"),
            verifier_sdk_lock_blake3: h("runner-lock"),
            verifier_sdk_name: "sp1-verifier".into(),
            verifier_sdk_version: "6.3.1".into(),
            container_digest: format!("sha256:{}", h("container")),
            source_commit: "a".repeat(40),
            proof_producer_tool_identity: None,
        }
    }
    fn all_rejected() -> Vec<Stage5MutationOutcome> {
        REQUIRED_MUTATION_CASES
            .iter()
            .map(|n| Stage5MutationOutcome {
                name: (*n).into(),
                actual_rejected: true,
            })
            .collect()
    }

    #[test]
    fn stage5_generate_derives_pass_from_genuine_outcomes() {
        let fixtures = vec![("terminal-proof".to_string(), b"receipt-bytes".to_vec())];
        let log = b"docker run ... verify + mutate\n".to_vec();
        let res = Stage5Result::generate(&s5_bind(), &fixtures, &all_rejected(), &log)
            .expect("a genuine pass generates a result");
        assert!(res.overall_pass, "overall_pass is DERIVED true");
        assert_eq!(res.mutation_cases.len(), REQUIRED_MUTATION_CASES.len());
        assert!(res.mutation_cases.iter().all(|c| c.expected_rejected));
        // fixture hash + command-log hash are computed HERE from the raw bytes.
        assert_eq!(
            res.fixture_hashes[0].blake3_hex,
            super::super::to_hex(blake3::hash(b"receipt-bytes").as_bytes())
        );
        assert_eq!(
            res.fixture_hashes[0].byte_len,
            b"receipt-bytes".len() as u64
        );
        assert_eq!(
            res.command_log_blake3_hex,
            super::super::to_hex(blake3::hash(&log).as_bytes())
        );
        assert!(res.validate().is_ok());
    }

    #[test]
    fn stage5_generate_refuses_a_non_rejecting_mutation() {
        // the verifier FAILED to reject one mutation -> the run did not pass -> no record
        // is ever emitted with a lying `overall_pass`.
        let mut outcomes = all_rejected();
        outcomes[0].actual_rejected = false;
        let err = Stage5Result::generate(
            &s5_bind(),
            &[("f".into(), b"x".to_vec())],
            &outcomes,
            b"log",
        )
        .unwrap_err();
        assert!(matches!(err, Stage5Error::MutationNotRejected { .. }));
    }

    #[test]
    fn stage5_generate_refuses_a_missing_required_case() {
        let short: Vec<_> = all_rejected()
            .into_iter()
            .take(REQUIRED_MUTATION_CASES.len() - 1)
            .collect();
        let err =
            Stage5Result::generate(&s5_bind(), &[("f".into(), b"x".to_vec())], &short, b"log")
                .unwrap_err();
        assert!(matches!(err, Stage5Error::MissingCase { .. }));
    }
}

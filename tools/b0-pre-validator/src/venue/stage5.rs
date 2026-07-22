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

/// The strict Stage-5 result for one candidate on one architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5Result {
    pub candidate: String,
    pub arch: String,
    /// The fixture + raw-artifact hashes the verifier consumed (at least one).
    pub fixture_hashes: Vec<Stage5FixtureHash>,
    /// The pinned terminal-verifier identity (e.g. its binary / image identity).
    pub verifier_identity: String,
    /// EVERY required mutation case, each with expected-and-actual rejection.
    pub mutation_cases: Vec<Stage5MutationCase>,
    /// The verified proof-tool identity the run was bound to (bare 64-hex, e.g.
    /// the installed-binary hash from the tool binding).
    pub tool_identity_hex: String,
    /// The builder-image `sha256:<64hex>` digest the fixtures ran inside.
    pub container_digest: String,
    /// The clean source commit (40/64-hex).
    pub source_commit: String,
    /// The OVERALL pass. Validation requires it to equal the value DERIVED from the
    /// individual cases (all required present, each rejected); a lying `true` is
    /// refused.
    pub overall_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage5Error {
    Missing(&'static str),
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
        if self.verifier_identity.trim().is_empty() {
            return Err(Stage5Error::Missing("verifier_identity"));
        }
        if !is_hex64(&self.tool_identity_hex) {
            return Err(Stage5Error::BadHash("tool_identity_hex"));
        }
        if self.source_commit.trim().is_empty() {
            return Err(Stage5Error::Missing("source_commit"));
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
            candidate: candidate.into(),
            arch: arch.into(),
            fixture_hashes: vec![Stage5FixtureHash {
                label: "terminal-proof".into(),
                blake3_hex: h("fixture"),
                byte_len: 1234,
            }],
            verifier_identity: "pinned-terminal-verifier@1".into(),
            mutation_cases: REQUIRED_MUTATION_CASES
                .iter()
                .map(|n| full_case(n))
                .collect(),
            tool_identity_hex: h("tool"),
            container_digest: format!("sha256:{}", h("container")),
            source_commit: "a".repeat(40),
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
        r.tool_identity_hex = "not-hex".into();
        assert!(matches!(
            r.validate(),
            Err(Stage5Error::BadHash("tool_identity_hex"))
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
}

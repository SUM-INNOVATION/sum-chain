//! Stage-2 license policy: standards-based SPDX expression evaluation.
//!
//! Replaces the invalid byte-exact string match (`allowed_licenses.contains(&lic)`). The old match
//! produced 75 SP1 / 69 RISC Zero disallowed-license findings (SMOKE-BLOCKED-004); of those, 55 SP1
//! / 49 RISC Zero were FALSE POSITIVES — valid SPDX expressions rejected purely on operand ORDER,
//! `/`-vs-`OR`, extra `OR` alternatives, `AND`, or `WITH` — cleared by correct evaluation alone,
//! and the remaining 20 per graph were GENUINE gaps needing exactly the two owner-approved atoms
//! (`Unicode-3.0`, `CDLA-Permissive-2.0`). Uses the maintained `spdx` crate (pinned `=0.13.4`,
//! default-features off — expression parsing only, no license-text corpus).
//!
//! The policy is a set of permitted SPDX license IDENTIFIERS (atoms) plus explicitly-permitted
//! `WITH` exception pairs, DERIVED from the venue allow-list entries (`run_authoritative.sh`
//! `STAGE2_ALLOWED_LICENSES`). Deriving from the existing entries keeps the venue policy string
//! and the Stage-2 record field UNCHANGED and makes the permitted set provably identical to
//! today's — every current entry still self-allows (`allow_list_entries_all_self_allow`). Adding a
//! new atom later is a one-line, obvious edit to that list.
//!
//! Acceptance is spec-correct SPDX evaluation over the permitted set: `OR` = at least one branch
//! permitted, `AND` = every branch permitted, `WITH` = the license AND its exception both
//! explicitly permitted (the exception is never discarded). Ordering never changes the verdict.
//! FAIL-CLOSED: a parse error, an unknown identifier, a deprecated/imprecise id, a `LicenseRef-*`
//! or non-SPDX addition, and a package with no license expression are all DENIED. Authoritative and
//! TEST_ONLY apply the identical policy.

use spdx::{Expression, ParseMode};
use std::collections::BTreeSet;

/// The venue Stage-2 license allow-list — the SINGLE canonical source of truth. The shell producer
/// `run_authoritative.sh` (`STAGE2_ALLOWED_LICENSES`) MUST mirror this verbatim (enforced by the
/// `stage2_allowed_licenses_mirrors_run_authoritative` anti-drift test), and Stage-2 fixtures/tests
/// derive their policy from it, so the same policy cannot diverge across producer, validator,
/// fixtures, and import. Entries are acceptable SPDX license expressions; the permitted atom set is
/// the union of the identifiers they name (see [`LicensePolicy::from_allow_list`]).
///
/// Owner-approved additions per the SMOKE-BLOCKED-004 ruling (2026-07-31): `Unicode-3.0` and
/// `CDLA-Permissive-2.0` — the only two atoms required by the authentic SP1 + RISC Zero graphs.
/// Their distribution obligations are recorded in docs/b0-pre/venue/THIRD-PARTY-LICENSES.md.
pub const STAGE2_ALLOWED_LICENSES: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "MIT OR Apache-2.0",
    "Apache-2.0 OR MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
    "Apache-2.0 WITH LLVM-exception",
    "MPL-2.0",
    "Zlib",
    "CC0-1.0",
    "Unlicense",
    // owner-approved 2026-07-31 (SMOKE-BLOCKED-004): required by the authentic graphs.
    "Unicode-3.0",
    "CDLA-Permissive-2.0",
];

/// Strict SPDX parsing EXCEPT the crate's Cargo pre-2.0 legacy `/`-as-`OR` compatibility — the sole
/// relaxation. Deprecated ids, unknown ids, imprecise names, and postfix-`+` all remain rejected.
/// SPDX tokens never contain `/`, so this is a narrow, documented legacy-Cargo accommodation, not a
/// global string rewrite (cargo emitted `MIT/Apache-2.0` for `MIT OR Apache-2.0` before Rust 2021).
const MODE: ParseMode = ParseMode {
    allow_deprecated: false,
    allow_unknown: false,
    allow_imprecise_license_names: false,
    allow_postfix_plus_on_gpl: false,
    allow_slash_as_or_operator: true,
};

/// The permitted SPDX atoms + `WITH` exception pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicensePolicy {
    atoms: BTreeSet<String>,
    exceptions: BTreeSet<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// An allow-list entry is not a parseable SPDX expression — a policy misconfiguration.
    UnparsableAllowEntry(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::UnparsableAllowEntry(e) => {
                write!(
                    f,
                    "license allow-list entry is not a valid SPDX expression: {e:?}"
                )
            }
        }
    }
}
impl std::error::Error for PolicyError {}

impl LicensePolicy {
    /// Derive the atomic policy from the venue allow-list entries: each entry contributes the SPDX
    /// identifiers (and `WITH` exceptions) it names to the permitted set. An unparsable entry fails
    /// closed (`PolicyError`). The result permits exactly what the current list allows.
    pub fn from_allow_list(allow: &[&str]) -> Result<Self, PolicyError> {
        let mut atoms = BTreeSet::new();
        let mut exceptions = BTreeSet::new();
        for entry in allow {
            let ex = Expression::parse_mode(entry, MODE)
                .map_err(|_| PolicyError::UnparsableAllowEntry((*entry).to_string()))?;
            for r in ex.requirements() {
                if let Some(id) = r.req.license.id() {
                    atoms.insert(id.name.to_string());
                    if let Some(add) = &r.req.addition {
                        if let Some(exc) = add.id() {
                            exceptions.insert((id.name.to_string(), exc.name.to_string()));
                        }
                    }
                }
            }
        }
        Ok(Self { atoms, exceptions })
    }

    /// True iff the crate `license` expression is satisfiable under the permitted atoms/exceptions.
    /// Fail-closed on parse error / unknown id / `LicenseRef` / non-SPDX addition.
    pub fn allows_expression(&self, expr: &str) -> bool {
        match Expression::parse_mode(expr, MODE) {
            Err(_) => false,
            Ok(ex) => ex.evaluate(|req| match req.license.id() {
                None => false, // LicenseRef-* / non-SPDX license -> deny
                Some(id) => {
                    let atom_ok = self.atoms.contains(id.name);
                    match &req.addition {
                        None => atom_ok,
                        Some(add) => match add.id() {
                            // WITH: require BOTH the license atom AND the exact exception pair.
                            Some(exc) => {
                                atom_ok
                                    && self
                                        .exceptions
                                        .contains(&(id.name.to_string(), exc.name.to_string()))
                            }
                            None => false, // non-SPDX addition (ref) -> deny
                        },
                    }
                }
            }),
        }
    }

    pub fn atoms(&self) -> &BTreeSet<String> {
        &self.atoms
    }
    pub fn exceptions(&self) -> &BTreeSet<(String, String)> {
        &self.exceptions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical venue allow-list (single source of truth).
    use super::STAGE2_ALLOWED_LICENSES as ALLOW;
    fn policy() -> LicensePolicy {
        LicensePolicy::from_allow_list(ALLOW).expect("canonical allow-list parses")
    }

    #[test]
    fn derives_the_expected_atoms_and_exception() {
        let p = policy();
        let want: BTreeSet<String> = [
            "MIT",
            "Apache-2.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Unicode-DFS-2016",
            "MPL-2.0",
            "Zlib",
            "CC0-1.0",
            "Unlicense",
            "Unicode-3.0",
            "CDLA-Permissive-2.0",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(p.atoms(), &want);
        assert_eq!(
            p.exceptions(),
            &[("Apache-2.0".to_string(), "LLVM-exception".to_string())]
                .into_iter()
                .collect()
        );
    }

    /// Equivalence guard: every current allow-list entry still self-allows under the derived
    /// policy, so the atomic representation permits exactly today's set (no silent widen/narrow).
    #[test]
    fn allow_list_entries_all_self_allow() {
        let p = policy();
        for entry in ALLOW {
            assert!(
                p.allows_expression(entry),
                "allow-list entry must self-allow: {entry}"
            );
        }
    }

    #[test]
    fn single_allowed_and_denied_atoms() {
        let p = policy();
        assert!(p.allows_expression("MIT"));
        assert!(p.allows_expression("Apache-2.0"));
        assert!(!p.allows_expression("GPL-3.0-only")); // known SPDX id, not permitted
        assert!(!p.allows_expression("AGPL-3.0-only")); // known, not permitted
    }

    #[test]
    fn owner_approved_atoms_are_accepted() {
        let p = policy();
        // SMOKE-BLOCKED-004 ruling: exactly these two were added.
        assert!(p.allows_expression("Unicode-3.0"));
        assert!(p.allows_expression("CDLA-Permissive-2.0"));
        assert!(p.allows_expression("(MIT OR Apache-2.0) AND Unicode-3.0")); // unicode-ident
    }

    #[test]
    fn or_semantics_any_allowed_branch_accepts_all_denied_rejects() {
        let p = policy();
        assert!(p.allows_expression("Apache-2.0 OR ISC OR MIT"));
        assert!(p.allows_expression("MIT OR Apache-2.0 OR LGPL-2.1-or-later")); // LGPL branch unused
        assert!(!p.allows_expression("GPL-3.0-only OR LGPL-2.1-or-later")); // no allowed branch
    }

    #[test]
    fn and_semantics_requires_every_branch() {
        let p = policy();
        assert!(p.allows_expression("Apache-2.0 AND ISC")); // both permitted (ring)
        assert!(p.allows_expression("MIT AND BSD-3-Clause")); // both permitted (matchit)
        assert!(!p.allows_expression("(MIT OR Apache-2.0) AND GPL-3.0-only")); // GPL branch denied
        assert!(!p.allows_expression("MIT AND GPL-3.0-only"));
    }

    #[test]
    fn with_requires_the_explicit_license_exception_pair() {
        let p = policy();
        assert!(p.allows_expression("Apache-2.0 WITH LLVM-exception"));
        // permitted license, but a DIFFERENT (unpermitted) exception -> deny; the exception is
        // never discarded.
        assert!(!p.allows_expression("Apache-2.0 WITH GCC-exception-3.1"));
        // an exception on an unpermitted license -> deny.
        assert!(!p.allows_expression("GPL-3.0-only WITH GCC-exception-3.1"));
    }

    #[test]
    fn legacy_cargo_slash_is_or() {
        let p = policy();
        assert!(p.allows_expression("MIT/Apache-2.0"));
        assert!(p.allows_expression("Apache-2.0/MIT"));
        assert!(p.allows_expression("Apache-2.0 / MIT"));
    }

    #[test]
    fn ordering_does_not_change_the_verdict() {
        let p = policy();
        assert_eq!(
            p.allows_expression("MIT OR Apache-2.0"),
            p.allows_expression("Apache-2.0 OR MIT")
        );
        assert_eq!(
            p.allows_expression("Apache-2.0 OR ISC OR MIT"),
            p.allows_expression("MIT OR Apache-2.0 OR ISC")
        );
    }

    #[test]
    fn parentheses_and_precedence_are_preserved() {
        let p = policy();
        // (allowed OR denied) AND allowed -> allowed
        assert!(p.allows_expression("(MIT OR GPL-3.0-only) AND Apache-2.0"));
        // allowed OR (denied AND denied) -> allowed (the left OR branch)
        assert!(p.allows_expression("MIT OR (GPL-3.0-only AND LGPL-2.1-or-later)"));
        // (denied AND allowed) -> denied
        assert!(!p.allows_expression("GPL-3.0-only AND MIT"));
    }

    #[test]
    fn fail_closed_on_licenseref_unknown_and_malformed() {
        let p = policy();
        assert!(!p.allows_expression("LicenseRef-Proprietary")); // LicenseRef -> deny
        assert!(!p.allows_expression("DocumentRef-x:LicenseRef-y"));
        assert!(!p.allows_expression("NotAnSpdxId")); // unknown -> parse error -> deny
        assert!(!p.allows_expression("MIT OR")); // malformed -> deny
        assert!(!p.allows_expression("")); // empty -> deny
        assert!(!p.allows_expression("MIT AND")); // malformed -> deny
    }

    #[test]
    fn no_substring_or_prefix_acceptance() {
        let p = policy();
        // a denied id that merely CONTAINS an allowed id as a substring is still denied.
        assert!(!p.allows_expression("MITnotreal"));
        assert!(!p.allows_expression("Apache-2.0-only")); // not a real id
    }

    /// A deny-all misconfiguration (bad allow entry) fails closed rather than silently widening.
    #[test]
    fn unparsable_allow_entry_is_a_policy_error() {
        assert!(matches!(
            LicensePolicy::from_allow_list(&["MIT", "not a license"]),
            Err(PolicyError::UnparsableAllowEntry(_))
        ));
    }

    /// Anti-drift: the shell producer's `STAGE2_ALLOWED_LICENSES` must equal the canonical Rust
    /// const VERBATIM (order + values), so the license policy cannot diverge between the producer
    /// (`run_authoritative.sh`) and the validator/fixtures/import.
    #[test]
    fn stage2_allowed_licenses_mirrors_run_authoritative() {
        let sh = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../b0-pre-candidates/scripts/run_authoritative.sh"
        ))
        .expect("read run_authoritative.sh");
        let line = sh
            .lines()
            .find(|l| l.trim_start().starts_with("STAGE2_ALLOWED_LICENSES="))
            .expect("STAGE2_ALLOWED_LICENSES assignment present");
        let json = line
            .split_once('\'')
            .and_then(|(_, r)| r.rsplit_once('\'').map(|(j, _)| j))
            .expect("single-quoted JSON array");
        let shell: Vec<String> =
            serde_json::from_str(json).expect("shell allow-list is valid JSON");
        let canon: Vec<String> = STAGE2_ALLOWED_LICENSES
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            shell, canon,
            "run_authoritative.sh STAGE2_ALLOWED_LICENSES must mirror the canonical Rust const"
        );
    }
}

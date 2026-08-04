//! Blocker 4, Stage 2: an actual resolved-graph audit.
//!
//! Stage 2 is a real authoritative stage, not a comment. It audits the
//! container-resolved dependency graph (dependency / source / advisory / license)
//! and emits fatal-vs-recorded classifications as machine-readable output that
//! Stage 6 requires before it proceeds. The policy is exactly VENUE.md §5:
//!
//!   * FATAL (candidate ineligible): the selected proof-stack release is not the
//!     pinned stable version; an unexpected git/path source on a proof-stack crate;
//!     duplicate INCOMPATIBLE proof-stack versions; an unresolved security advisory;
//!     a license outside the allow-list.
//!   * RECORDED (not auto-fatal): transitive prerelease crates (SP1's Plonky3 `p3-*`
//!     stack resolves to prereleases; expected, enumerated, not fatal by itself).
//!
//! The audit runs against a resolved graph; the resolution itself happens in the
//! container (fails closed off-venue). This classification core is unit-tested here.

use std::collections::BTreeMap;

/// The pinned SELECTED proof-stack releases (VENUE.md §5 / `run_authoritative.sh`).
/// A selected proof-stack crate resolving to any other version is fatal.
///
/// These are the crates each candidate's manifests DIRECTLY declare (`candidates/<c>/host` deps
/// and build-deps, and `candidates/<c>/guest` deps), by their EXACT published names. SP1 publishes
/// no crate named bare `sp1`; its stack is `sp1-sdk`, `sp1-verifier`, `sp1-build` (host) and
/// `sp1-zkvm` (guest), and RISC Zero's is `risc0-zkvm`, `risc0-groth16`, `risc0-build` (host) and
/// `risc0-zkvm-platform` (guest). This list is exactly the union of [`required_pins_for`] over the
/// candidates (asserted by the `proof_stack_pins_are_the_union_of_required_pins...` test), so the
/// version-check list and the coverage list never drift.
pub const PROOF_STACK_PINS: &[(&str, &str)] = &[
    ("sp1-sdk", "6.3.1"),
    ("sp1-verifier", "6.3.1"),
    ("sp1-build", "6.3.1"),
    ("sp1-zkvm", "6.3.1"),
    ("risc0-zkvm", "3.0.5"),
    ("risc0-groth16", "3.0.4"),
    ("risc0-build", "3.0.5"),
    ("risc0-zkvm-platform", "2.2.3"),
];

/// The crate-name prefixes that identify proof-stack crates for the source rule.
const PROOF_STACK_PREFIXES: &[&str] = &["sp1", "risc0"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Registry,
    Git,
    Path,
}

/// One resolved crate node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrateNode {
    pub name: String,
    pub version: String,
    pub source: Source,
    /// SPDX-ish license id, or `None` if unresolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

/// A security advisory affecting a crate in the graph.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub crate_name: String,
    pub id: String,
    /// True if patched/mitigated in the resolved graph.
    pub resolved: bool,
}

/// A STRUCTURED, reviewed advisory exception. NOT a bare `--ignore`: a specific advisory in a
/// specific candidate's proof-stack graph, accepted because the vulnerable code path is not
/// reachable in this execution mode. Every field is required and validated; the advisory is still
/// RECORDED as an `accepted_exception` finding (never hidden, never "0 vulnerabilities"), and the
/// cargo-audit `--ignore` argv is built FROM these fields as their execution representation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryException {
    /// The candidate this exception is scoped to (e.g. "Risc0"). NEVER "Sp1".
    pub candidate: String,
    /// The bound SDK pin, `"<crate>=<version>"` (e.g. "risc0-zkvm=3.0.5"); must be resolved
    /// at that exact version in the graph, else the exception is stale (fail closed).
    pub sdk: String,
    /// `RUSTSEC-YYYY-NNNN`.
    pub advisory_id: String,
    /// The EXACT affected crate + version; a different version does NOT match (fail closed).
    pub affected_crate: String,
    pub affected_version: String,
    /// BLAKE3 (bare 64-hex) of the frozen reachability-evidence document this exception rests on.
    pub source_feature_graph_hash: String,
    /// Why the finding is accepted and its applicability to THIS execution mode.
    pub justification: String,
    pub applicability: String,
    /// The policy version that approved this exception.
    pub approving_policy_version: String,
    /// The conditions that invalidate this exception and force re-review.
    pub review_trigger: String,
}

/// A structured advisory-exception policy (the committed authority). Trusted code builds the
/// cargo-audit `--ignore` argv from this; the acceptance decision lives here, not in a flag string.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryExceptionPolicy {
    pub policy_version: String,
    /// Optional human-facing classification/notes (recorded, format only — not authority).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default)]
    pub exceptions: Vec<AdvisoryException>,
}

/// Why an advisory-exception policy is refused (all fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionPolicyError {
    /// An exception scoped to SP1 (or any candidate that must stay exception-free).
    ExceptionForForbiddenCandidate { advisory_id: String, candidate: String },
    /// The exception's candidate does not match the audit's candidate.
    CandidateMismatch { advisory_id: String, expected: String, got: String },
    /// A required field is empty.
    MissingField { advisory_id: String, field: &'static str },
    /// `advisory_id` is not a well-formed RUSTSEC id.
    BadAdvisoryId { advisory_id: String },
    /// Two exceptions bind the same (advisory, crate, version).
    Duplicate { advisory_id: String, crate_name: String, version: String },
    /// The bound (crate, version) is NOT present in the resolved graph (stale binding).
    StaleBinding { advisory_id: String, crate_name: String, version: String },
    /// The bound SDK pin is not present at that exact version in the graph.
    SdkMismatch { advisory_id: String, sdk: String },
}

impl std::fmt::Display for ExceptionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExceptionPolicyError::ExceptionForForbiddenCandidate { advisory_id, candidate } =>
                write!(f, "advisory exception {advisory_id} is scoped to forbidden candidate {candidate} (must stay exception-free)"),
            ExceptionPolicyError::CandidateMismatch { advisory_id, expected, got } =>
                write!(f, "advisory exception {advisory_id} candidate {got} != audit candidate {expected}"),
            ExceptionPolicyError::MissingField { advisory_id, field } =>
                write!(f, "advisory exception {advisory_id} missing required field {field}"),
            ExceptionPolicyError::BadAdvisoryId { advisory_id } =>
                write!(f, "advisory exception has malformed advisory id {advisory_id:?}"),
            ExceptionPolicyError::Duplicate { advisory_id, crate_name, version } =>
                write!(f, "duplicate advisory exception {advisory_id} for {crate_name} {version}"),
            ExceptionPolicyError::StaleBinding { advisory_id, crate_name, version } =>
                write!(f, "advisory exception {advisory_id} binds {crate_name} {version} which is ABSENT from the resolved graph (stale)"),
            ExceptionPolicyError::SdkMismatch { advisory_id, sdk } =>
                write!(f, "advisory exception {advisory_id} bound SDK {sdk} is not resolved at that version in the graph"),
        }
    }
}

/// Forbidden exception candidates: SP1 must pass Stage 2 with zero findings and carry NO exception.
const EXCEPTION_FORBIDDEN_CANDIDATES: &[&str] = &["Sp1"];

fn advisory_id_ok(id: &str) -> bool {
    // RUSTSEC-YYYY-NNNN  (8 + 4 + 1 + 4 = 17 chars)
    let b = id.as_bytes();
    id.len() == 17
        && id.starts_with("RUSTSEC-")
        && b[12] == b'-'
        && b[8..12].iter().all(u8::is_ascii_digit)
        && b[13..17].iter().all(u8::is_ascii_digit)
}

/// Validate + scope the exception policy to `candidate`, against the resolved `nodes`. Rejects
/// (fail closed) any forbidden-candidate exception, malformed id, missing field, duplicate, stale
/// (crate,version) binding, or SDK-pin mismatch. Returns the candidate-scoped exceptions to apply.
pub fn scope_and_validate_exceptions<'a>(
    candidate: &str,
    exceptions: &'a [AdvisoryException],
    nodes: &[CrateNode],
) -> Result<Vec<&'a AdvisoryException>, ExceptionPolicyError> {
    use std::collections::BTreeSet;
    // GLOBAL guards over the WHOLE policy (not just the scoped subset): a forbidden-candidate
    // exception, a malformed id, a missing field, or a duplicate is rejected regardless of which
    // candidate is being audited — so a bad exception can never sit latent in the policy.
    let mut seen: BTreeSet<(&str, &str, &str)> = BTreeSet::new();
    for e in exceptions {
        if EXCEPTION_FORBIDDEN_CANDIDATES.contains(&e.candidate.as_str()) {
            return Err(ExceptionPolicyError::ExceptionForForbiddenCandidate {
                advisory_id: e.advisory_id.clone(),
                candidate: e.candidate.clone(),
            });
        }
        if !advisory_id_ok(&e.advisory_id) {
            return Err(ExceptionPolicyError::BadAdvisoryId { advisory_id: e.advisory_id.clone() });
        }
        for (field, val) in [
            ("candidate", &e.candidate), ("sdk", &e.sdk),
            ("affected_crate", &e.affected_crate), ("affected_version", &e.affected_version),
            ("source_feature_graph_hash", &e.source_feature_graph_hash),
            ("justification", &e.justification), ("applicability", &e.applicability),
            ("approving_policy_version", &e.approving_policy_version),
            ("review_trigger", &e.review_trigger),
        ] {
            if val.trim().is_empty() {
                return Err(ExceptionPolicyError::MissingField { advisory_id: e.advisory_id.clone(), field });
            }
        }
        if !seen.insert((&e.advisory_id, &e.affected_crate, &e.affected_version)) {
            return Err(ExceptionPolicyError::Duplicate {
                advisory_id: e.advisory_id.clone(),
                crate_name: e.affected_crate.clone(),
                version: e.affected_version.clone(),
            });
        }
    }
    // Scope to THIS candidate + bind each scoped exception to the resolved graph.
    let mut scoped = Vec::new();
    for e in exceptions.iter().filter(|e| e.candidate == candidate) {
        if !nodes.iter().any(|n| n.name == e.affected_crate && n.version == e.affected_version) {
            return Err(ExceptionPolicyError::StaleBinding {
                advisory_id: e.advisory_id.clone(),
                crate_name: e.affected_crate.clone(),
                version: e.affected_version.clone(),
            });
        }
        let (sdk_name, sdk_ver) = e.sdk.split_once('=').ok_or_else(|| ExceptionPolicyError::SdkMismatch {
            advisory_id: e.advisory_id.clone(), sdk: e.sdk.clone(),
        })?;
        if !nodes.iter().any(|n| n.name == sdk_name && n.version == sdk_ver) {
            return Err(ExceptionPolicyError::SdkMismatch { advisory_id: e.advisory_id.clone(), sdk: e.sdk.clone() });
        }
        scoped.push(e);
    }
    Ok(scoped)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Candidate ineligible — any fatal finding fails Stage 2 closed.
    Fatal(FatalKind),
    /// Recorded for audit, not auto-fatal.
    Recorded(RecordedKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatalKind {
    WrongPinnedVersion {
        crate_name: String,
        found: String,
        expected: String,
    },
    UnexpectedSource {
        crate_name: String,
        source: Source,
    },
    DuplicateIncompatible {
        crate_name: String,
        versions: Vec<String>,
    },
    UnresolvedAdvisory {
        crate_name: String,
        id: String,
    },
    DisallowedLicense {
        crate_name: String,
        license: String,
    },
    UnlicensedCrate {
        crate_name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedKind {
    Prerelease { crate_name: String, version: String },
    /// A security advisory ACCEPTED under a structured, reviewed exception (see
    /// [`AdvisoryException`]). It is STILL recorded as a finding — the audit never reports
    /// "0 vulnerabilities" — but it is not auto-fatal.
    AcceptedAdvisoryException {
        crate_name: String,
        version: String,
        advisory_id: String,
        policy_version: String,
    },
}

/// The machine-readable Stage-2 audit report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// Stage 2 passes iff there is NO fatal finding.
    pub fn is_fatal(&self) -> bool {
        self.findings.iter().any(|f| matches!(f, Finding::Fatal(_)))
    }

    pub fn fatal_findings(&self) -> impl Iterator<Item = &FatalKind> {
        self.findings.iter().filter_map(|f| match f {
            Finding::Fatal(k) => Some(k),
            _ => None,
        })
    }

    pub fn recorded_findings(&self) -> impl Iterator<Item = &RecordedKind> {
        self.findings.iter().filter_map(|f| match f {
            Finding::Recorded(k) => Some(k),
            _ => None,
        })
    }

    /// A stable machine-readable JSON string (the artifact Stage 6 requires).
    pub fn to_json(&self) -> String {
        let fatal: Vec<serde_json::Value> = self
            .fatal_findings()
            .map(|k| match k {
                FatalKind::WrongPinnedVersion { crate_name, found, expected } => serde_json::json!({
                    "kind": "wrong_pinned_version", "crate": crate_name, "found": found, "expected": expected
                }),
                FatalKind::UnexpectedSource { crate_name, source } => serde_json::json!({
                    "kind": "unexpected_source", "crate": crate_name, "source": format!("{source:?}")
                }),
                FatalKind::DuplicateIncompatible { crate_name, versions } => serde_json::json!({
                    "kind": "duplicate_incompatible", "crate": crate_name, "versions": versions
                }),
                FatalKind::UnresolvedAdvisory { crate_name, id } => serde_json::json!({
                    "kind": "unresolved_advisory", "crate": crate_name, "id": id
                }),
                FatalKind::DisallowedLicense { crate_name, license } => serde_json::json!({
                    "kind": "disallowed_license", "crate": crate_name, "license": license
                }),
                FatalKind::UnlicensedCrate { crate_name } => serde_json::json!({
                    "kind": "unlicensed_crate", "crate": crate_name
                }),
            })
            .collect();
        let recorded: Vec<serde_json::Value> = self
            .recorded_findings()
            .map(|k| match k {
                RecordedKind::Prerelease {
                    crate_name,
                    version,
                } => serde_json::json!({
                    "kind": "prerelease", "crate": crate_name, "version": version
                }),
                RecordedKind::AcceptedAdvisoryException {
                    crate_name,
                    version,
                    advisory_id,
                    policy_version,
                } => serde_json::json!({
                    "kind": "accepted_exception", "crate": crate_name, "version": version,
                    "advisory": advisory_id, "policy_version": policy_version
                }),
            })
            .collect();
        serde_json::json!({
            "stage": "stage2-graph-audit",
            "fatal": self.is_fatal(),
            "fatal_findings": fatal,
            "recorded_findings": recorded,
        })
        .to_string()
    }
}

/// True iff `name` is a proof-stack crate (for the git/path source rule).
fn is_proof_stack(name: &str) -> bool {
    PROOF_STACK_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// A true SemVer prerelease: a `-` immediately after `MAJOR.MINOR.PATCH`, before any
/// `+build` metadata (so `0.11.0+wasi-...` is NOT flagged).
fn is_prerelease(version: &str) -> bool {
    let core = version.split('+').next().unwrap_or(version);
    match core.find('-') {
        Some(idx) => core[..idx].split('.').filter(|s| !s.is_empty()).count() == 3,
        None => false,
    }
}

/// The MAJOR component of a version (for incompatible-duplicate detection).
fn major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

/// Audit a resolved graph against the frozen policy, producing the machine-readable
/// report. `allowed_licenses` is the license allow-list.
pub fn audit_graph(
    nodes: &[CrateNode],
    advisories: &[Advisory],
    allowed_licenses: &[&str],
    exceptions: &[&AdvisoryException],
) -> AuditReport {
    let mut findings = Vec::new();

    // Build the SPDX policy from the allow-list ONCE. A misconfigured (unparsable) allow-list
    // yields None -> every license expression is DENIED (fail closed), never silently widened.
    let policy = super::license_policy::LicensePolicy::from_allow_list(allowed_licenses).ok();

    // (1) selected proof-stack pins: a pinned crate present in the graph must be at
    //     its exact pinned version.
    for (name, expected) in PROOF_STACK_PINS {
        for n in nodes.iter().filter(|n| n.name == *name) {
            if n.version != *expected {
                findings.push(Finding::Fatal(FatalKind::WrongPinnedVersion {
                    crate_name: n.name.clone(),
                    found: n.version.clone(),
                    expected: (*expected).to_string(),
                }));
            }
        }
    }

    // (2) source rule: a proof-stack crate from git/path is fatal; license + advisory
    //     + prerelease pass below.
    for n in nodes {
        if is_proof_stack(&n.name) && n.source != Source::Registry {
            findings.push(Finding::Fatal(FatalKind::UnexpectedSource {
                crate_name: n.name.clone(),
                source: n.source,
            }));
        }
        // license policy: standards-based SPDX evaluation (NOT a byte-exact string match). A
        // license-file-only package (no expression) and any expression not satisfiable under the
        // permitted atoms/exceptions both fail closed.
        match &n.license {
            None => findings.push(Finding::Fatal(FatalKind::UnlicensedCrate {
                crate_name: n.name.clone(),
            })),
            Some(lic)
                if !policy
                    .as_ref()
                    .map(|p| p.allows_expression(lic))
                    .unwrap_or(false) =>
            {
                findings.push(Finding::Fatal(FatalKind::DisallowedLicense {
                    crate_name: n.name.clone(),
                    license: lic.clone(),
                }));
            }
            Some(_) => {}
        }
        // recorded prereleases
        if is_prerelease(&n.version) {
            findings.push(Finding::Recorded(RecordedKind::Prerelease {
                crate_name: n.name.clone(),
                version: n.version.clone(),
            }));
        }
    }

    // (3) duplicate INCOMPATIBLE proof-stack versions (same crate, >1 major).
    let mut by_name: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for n in nodes {
        if is_proof_stack(&n.name) {
            by_name.entry(&n.name).or_default().push(&n.version);
        }
    }
    for (name, versions) in by_name {
        let mut majors: Vec<&str> = versions.iter().map(|v| major(v)).collect();
        majors.sort_unstable();
        majors.dedup();
        if majors.len() > 1 {
            let mut vs: Vec<String> = versions.iter().map(|s| s.to_string()).collect();
            vs.sort();
            vs.dedup();
            findings.push(Finding::Fatal(FatalKind::DuplicateIncompatible {
                crate_name: name.to_string(),
                versions: vs,
            }));
        }
    }

    // (4) unresolved advisories. Each is FATAL unless a structured, reviewed exception (already
    //     scoped + validated + graph-bound by the caller) matches it EXACTLY by advisory id, crate,
    //     and the crate's RESOLVED version in this graph. A matching exception downgrades it to a
    //     RECORDED accepted_exception (still reported); anything else — a new advisory, a different
    //     affected version, a different crate — has no match and stays FATAL (fail closed).
    for a in advisories {
        if !a.resolved {
            let resolved_versions: Vec<&str> = nodes
                .iter()
                .filter(|n| n.name == a.crate_name)
                .map(|n| n.version.as_str())
                .collect();
            let matched = exceptions.iter().find(|e| {
                e.advisory_id == a.id
                    && e.affected_crate == a.crate_name
                    && resolved_versions.contains(&e.affected_version.as_str())
            });
            match matched {
                Some(e) => findings.push(Finding::Recorded(RecordedKind::AcceptedAdvisoryException {
                    crate_name: a.crate_name.clone(),
                    version: e.affected_version.clone(),
                    advisory_id: a.id.clone(),
                    policy_version: e.approving_policy_version.clone(),
                })),
                None => findings.push(Finding::Fatal(FatalKind::UnresolvedAdvisory {
                    crate_name: a.crate_name.clone(),
                    id: a.id.clone(),
                })),
            }
        }
    }

    AuditReport { findings }
}

// ---- Blocker 5: in-image graph derivation + required-crate coverage --------

/// The candidate-specific pinned crates Stage 2 must find in the resolved graph,
/// each exactly once at its pinned version. A graph missing any of them is
/// INCOMPLETE (the proof-stack was not actually resolved) and is rejected — a
/// pass over an empty/incomplete graph is meaningless.
///
/// Each candidate's proof-stack coverage set is the crates its own manifests DIRECTLY declare, by
/// EXACT published name + pinned version (VENUE.md §5 / `candidates/<c>/{host,guest}/Cargo.toml`).
/// SP1's set is `sp1-sdk`, `sp1-verifier`, `sp1-build` (host) and `sp1-zkvm` (guest); RISC Zero's is
/// `risc0-zkvm`, `risc0-groth16`, `risc0-build` (host) and `risc0-zkvm-platform` (guest). There is NO
/// crate literally named `sp1`, so a completeness gate demanding one is unsatisfiable by any correct
/// SP1 graph. These mirror [`PROOF_STACK_PINS`] (their union), not a second policy.
pub fn required_pins_for(candidate: &str) -> Option<&'static [(&'static str, &'static str)]> {
    const SP1: &[(&str, &str)] = &[
        ("sp1-sdk", "6.3.1"),
        ("sp1-verifier", "6.3.1"),
        ("sp1-build", "6.3.1"),
        ("sp1-zkvm", "6.3.1"),
    ];
    const RISC0: &[(&str, &str)] = &[
        ("risc0-zkvm", "3.0.5"),
        ("risc0-groth16", "3.0.4"),
        ("risc0-build", "3.0.5"),
        ("risc0-zkvm-platform", "2.2.3"),
    ];
    match candidate {
        "Sp1" => Some(SP1),
        "Risc0" => Some(RISC0),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphCoverageError {
    UnknownCandidate {
        candidate: String,
    },
    /// The resolved graph was empty — the proof stack was never resolved.
    EmptyGraph,
    /// A required pinned crate was absent from the graph.
    RequiredCrateAbsent {
        crate_name: String,
        version: String,
    },
    /// A required pinned crate appeared more than once at its pinned version.
    RequiredCrateDuplicated {
        crate_name: String,
        version: String,
    },
}

impl std::fmt::Display for GraphCoverageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphCoverageError::UnknownCandidate { candidate } => {
                write!(f, "unknown candidate {candidate:?}")
            }
            GraphCoverageError::EmptyGraph => {
                write!(f, "resolved graph is empty; the proof stack was not resolved in-container")
            }
            GraphCoverageError::RequiredCrateAbsent { crate_name, version } => write!(
                f,
                "required candidate crate {crate_name} = {version} is absent from the resolved graph"
            ),
            GraphCoverageError::RequiredCrateDuplicated { crate_name, version } => write!(
                f,
                "required candidate crate {crate_name} = {version} appears more than once"
            ),
        }
    }
}

impl std::error::Error for GraphCoverageError {}

/// Require every candidate-specific pinned crate to be present EXACTLY ONCE at its
/// pinned version, and reject an empty graph. This is the completeness gate that
/// stops Stage 2 passing when the proof-stack crates are simply absent.
pub fn require_candidate_pins(
    nodes: &[CrateNode],
    candidate: &str,
) -> Result<(), GraphCoverageError> {
    let required = required_pins_for(candidate).ok_or(GraphCoverageError::UnknownCandidate {
        candidate: candidate.to_string(),
    })?;
    if nodes.is_empty() {
        return Err(GraphCoverageError::EmptyGraph);
    }
    for (name, version) in required {
        let count = nodes
            .iter()
            .filter(|n| n.name == *name && n.version == *version)
            .count();
        match count {
            0 => {
                return Err(GraphCoverageError::RequiredCrateAbsent {
                    crate_name: (*name).to_string(),
                    version: (*version).to_string(),
                })
            }
            1 => {}
            _ => {
                return Err(GraphCoverageError::RequiredCrateDuplicated {
                    crate_name: (*name).to_string(),
                    version: (*version).to_string(),
                })
            }
        }
    }
    Ok(())
}

/// The current Stage-2 audit-record schema version.
///
/// v1 (unversioned) recorded a FREE-TEXT `advisory_db_snapshot` ("git rev / date") and no
/// executed-cargo-audit identity — insufficient to reproduce or verify the scan. v2 binds
/// the advisory database by immutable git commit + tree + a canonical content digest, binds
/// the exact cargo-audit executable + version used, and records STRUCTURED audit-policy
/// fields (never a free-form command). v1 remains decodable for historical inspection but is
/// INELIGIBLE for new authoritative evidence; unknown versions fail closed.
pub const STAGE2_SCHEMA_VERSION: u16 = 2;

/// Structured, non-executable Stage-2 audit policy (policy A). Trusted code constructs the
/// actual `cargo audit` argv from these; the command log records the exact argv that ran.
/// Storing a free-form command string as authority would invite command-injection and
/// semantic drift, so it is deliberately NOT a field here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPolicy {
    /// Whether the advisory DB may be updated during the audit. MUST be `false` (forbidden).
    pub database_update_allowed: bool,
    /// Whether a stale (pinned) snapshot is permitted. MUST be `true`.
    pub stale_snapshot_permitted: bool,
    /// Output format. MUST be `"json"`.
    pub output_format: String,
    /// How the DB is provided. MUST be `"runtime-read-only-mount"` (a runtime-controlled,
    /// read-only checkout — never a build-time-baked or writable path).
    pub database_source: String,
}

/// The pinned advisory database identity (policy A): immutable VCS identity (commit + tree)
/// AND the canonical materialized-checkout content digest (see `checkout_digest`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryDbIdentity {
    /// Upstream VCS commit (40-hex).
    pub commit: String,
    /// Upstream VCS tree (40-hex) at that commit.
    pub git_tree: String,
    /// Canonical BLAKE3 (bare 64-hex) of the materialized read-only checkout content.
    pub content_blake3: String,
}

/// The bound Stage-2 audit record (schema v2): the in-container-DERIVED resolved graph +
/// advisories + license allow-list, bound to the resolved lock hash, the builder container
/// digest, the clean source commit, the architecture, the EXACT cargo-audit executable +
/// version, the pinned advisory-DB identity, and the structured audit policy. Stage 6 (via
/// the evidence bundle) REQUIRES this — not a bare externally-supplied graph.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2AuditRecord {
    /// REQUIRED schema version. Only [`STAGE2_SCHEMA_VERSION`] is authoritative-eligible.
    pub schema_version: u16,
    pub candidate: String,
    pub arch: String,
    /// Bound to the resolved candidate lock hash (bare 64-hex BLAKE3).
    pub lock_blake3_hex: String,
    /// Bound to the builder-image `sha256:<64hex>` digest the graph was resolved in.
    pub container_digest: String,
    pub source_commit: String,
    /// Bound to the exact in-container commands that produced the graph + audit
    /// (bare 64-hex BLAKE3 of the command log). A record whose graph was produced by
    /// a different command sequence than the one hashed here is not this evidence.
    pub command_log_blake3_hex: String,
    /// Descriptive audit-tool label (e.g. `cargo-metadata 1.x + cargo-audit 0.y`). Authority
    /// is the hash-backed cargo-audit fields below, not this string.
    pub audit_tool_identity: String,
    /// The exact cargo-audit version the invocation self-reported. VENUE EVIDENCE (recorded
    /// from `cargo audit --version` at the venue), bound to the ratified crate/version pin.
    pub cargo_audit_version: String,
    /// SHA-256 (bare 64-hex) of the exact cargo-audit executable that ran the scan. This is
    /// VENUE EVIDENCE, NOT an owner-ratified source pin: the ratified inputs are the crate +
    /// version + crate checksum + packaged-lock checksum + Rust toolchain + build environment
    /// (see PIN-PROPOSAL.md §6). This hash is recorded at the venue, re-checked at the point of
    /// use, and MUST be independently reproduced by a second same-architecture operator; if the
    /// two same-arch builds do not reproduce, the executable identity is NOT blessed — an
    /// immutable first-party binary or a stronger build-provenance model is required instead.
    pub cargo_audit_executable_sha256: String,
    /// The pinned advisory-DB identity the scan ran against (commit + tree + content digest).
    pub advisory_db: AdvisoryDbIdentity,
    /// The structured, non-executable audit policy the scan enforced.
    pub audit_policy: AuditPolicy,
    pub allowed_licenses: Vec<String>,
    /// The DERIVED-in-container resolved graph (dependency/source/license nodes).
    pub nodes: Vec<CrateNode>,
    pub advisories: Vec<Advisory>,
    /// The structured, reviewed advisory exceptions APPLIED to this candidate's audit (each
    /// scoped to `candidate`, graph-bound, and RECORDED as an accepted_exception finding). Empty
    /// for a candidate with no accepted advisories (e.g. SP1, which must stay exception-free).
    #[serde(default)]
    pub advisory_exceptions: Vec<AdvisoryException>,
}

/// Peek a raw Stage-2 record's `schema_version` without a strict decode, so the importer can
/// reject an inadequate v1/unversioned record with a clear trust error (0 if absent).
pub fn peek_stage2_schema_version(raw: &[u8]) -> u16 {
    #[derive(serde::Deserialize)]
    struct V {
        #[serde(default)]
        schema_version: u16,
    }
    serde_json::from_slice::<V>(raw)
        .map(|v| v.schema_version)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage2RecordError {
    /// The record's `schema_version` is not [`STAGE2_SCHEMA_VERSION`] (e.g. an inadequate v1
    /// record with a free-text advisory-DB snapshot and no executed-cargo-audit identity).
    UnsupportedSchemaVersion {
        got: u16,
    },
    UnknownCandidate {
        candidate: String,
    },
    UnknownArch {
        arch: String,
    },
    Missing(&'static str),
    BadHash(&'static str),
    /// A structured audit-policy field held a disallowed value.
    BadPolicy(&'static str),
    /// A structured advisory-exception policy was invalid (forbidden candidate, stale binding,
    /// version/SDK mismatch, missing field, duplicate, or an out-of-scope exception on the record).
    BadExceptionPolicy(String),
    BadContainerDigest {
        digest: String,
    },
    /// A fatal audit finding (wrong pin, bad source, advisory, license, ...).
    FatalAudit {
        count: usize,
    },
    /// The required-crate coverage failed (empty/incomplete graph).
    Coverage(GraphCoverageError),
    /// Raw `cargo metadata` / `cargo audit` output could not be parsed.
    Parse(String),
}

impl std::fmt::Display for Stage2RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stage2RecordError::UnknownCandidate { candidate } => {
                write!(f, "unknown candidate {candidate:?}")
            }
            Stage2RecordError::UnknownArch { arch } => write!(f, "unknown architecture {arch:?}"),
            Stage2RecordError::UnsupportedSchemaVersion { got } => write!(
                f,
                "Stage-2 schema_version {got} is not the authoritative-eligible v{} \
                 (a v1/unversioned record's free-text advisory-DB snapshot + missing \
                 executed-cargo-audit identity are insufficient and are refused)",
                STAGE2_SCHEMA_VERSION
            ),
            Stage2RecordError::Missing(field) => write!(f, "Stage-2 record field {field} is empty"),
            Stage2RecordError::BadHash(field) => {
                write!(f, "Stage-2 record {field} is not bare 64-hex")
            }
            Stage2RecordError::BadExceptionPolicy(msg) => {
                write!(f, "Stage-2 advisory-exception policy refused: {msg}")
            }
            Stage2RecordError::BadPolicy(field) => {
                write!(f, "Stage-2 audit policy {field} holds a disallowed value")
            }
            Stage2RecordError::BadContainerDigest { digest } => {
                write!(f, "Stage-2 record container_digest invalid: {digest:?}")
            }
            Stage2RecordError::FatalAudit { count } => {
                write!(
                    f,
                    "Stage-2 graph audit is FATAL ({count} finding(s)); candidate ineligible"
                )
            }
            Stage2RecordError::Coverage(e) => {
                write!(f, "Stage-2 required-crate coverage failed: {e}")
            }
            Stage2RecordError::Parse(e) => {
                write!(f, "Stage-2 raw-output parse failed: {e}")
            }
        }
    }
}

impl std::error::Error for Stage2RecordError {}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Stage2AuditRecord {
    /// Validate the record: known candidate/arch, well-formed non-synthetic
    /// bindings, a NON-FATAL audit over the derived graph, and the required-crate
    /// coverage (rejecting an empty/incomplete graph). Returns the audit report so
    /// the caller can retain the recorded prereleases. Binding the lock hash /
    /// container digest to the resolved lock is done by the evidence-bundle importer.
    pub fn validate(&self) -> Result<AuditReport, Stage2RecordError> {
        // Only the current schema version is authoritative-eligible; an inadequate v1
        // record is refused before any other check.
        if self.schema_version != STAGE2_SCHEMA_VERSION {
            return Err(Stage2RecordError::UnsupportedSchemaVersion {
                got: self.schema_version,
            });
        }
        if required_pins_for(&self.candidate).is_none() {
            return Err(Stage2RecordError::UnknownCandidate {
                candidate: self.candidate.clone(),
            });
        }
        if self.arch != "X86_64" && self.arch != "Aarch64" {
            return Err(Stage2RecordError::UnknownArch {
                arch: self.arch.clone(),
            });
        }
        if !is_hex64(&self.lock_blake3_hex) {
            return Err(Stage2RecordError::BadHash("lock_blake3_hex"));
        }
        match self.container_digest.strip_prefix("sha256:") {
            Some(hex) if is_hex64(hex) && !super::is_synthetic(&self.container_digest) => {}
            _ => {
                return Err(Stage2RecordError::BadContainerDigest {
                    digest: self.container_digest.clone(),
                })
            }
        }
        if self.source_commit.trim().is_empty() {
            return Err(Stage2RecordError::Missing("source_commit"));
        }
        if !is_hex64(&self.command_log_blake3_hex) {
            return Err(Stage2RecordError::BadHash("command_log_blake3_hex"));
        }
        if self.audit_tool_identity.trim().is_empty() {
            return Err(Stage2RecordError::Missing("audit_tool_identity"));
        }
        // The EXACT executed cargo-audit identity (authority; the label above is descriptive).
        if self.cargo_audit_version.trim().is_empty() {
            return Err(Stage2RecordError::Missing("cargo_audit_version"));
        }
        if !is_hex64(&self.cargo_audit_executable_sha256) {
            return Err(Stage2RecordError::BadHash("cargo_audit_executable_sha256"));
        }
        // The pinned advisory-DB identity: commit + tree (40-hex) + canonical content digest.
        if !is_hex40(&self.advisory_db.commit) {
            return Err(Stage2RecordError::BadHash("advisory_db.commit"));
        }
        if !is_hex40(&self.advisory_db.git_tree) {
            return Err(Stage2RecordError::BadHash("advisory_db.git_tree"));
        }
        if !is_hex64(&self.advisory_db.content_blake3) {
            return Err(Stage2RecordError::BadHash("advisory_db.content_blake3"));
        }
        // The structured policy invariants (policy A): DB update forbidden, stale permitted,
        // JSON output, runtime-controlled read-only DB source. A free-form command is never
        // stored; trusted code builds the argv and the command log records what actually ran.
        if self.audit_policy.database_update_allowed {
            return Err(Stage2RecordError::BadPolicy(
                "database_update_allowed (must be false)",
            ));
        }
        if !self.audit_policy.stale_snapshot_permitted {
            return Err(Stage2RecordError::BadPolicy(
                "stale_snapshot_permitted (must be true)",
            ));
        }
        if self.audit_policy.output_format != "json" {
            return Err(Stage2RecordError::BadPolicy(
                "output_format (must be \"json\")",
            ));
        }
        if self.audit_policy.database_source != "runtime-read-only-mount" {
            return Err(Stage2RecordError::BadPolicy(
                "database_source (must be \"runtime-read-only-mount\")",
            ));
        }
        // required-crate coverage (rejects empty/incomplete graphs).
        require_candidate_pins(&self.nodes, &self.candidate)
            .map_err(Stage2RecordError::Coverage)?;
        // Re-validate + re-scope the recorded advisory exceptions against THIS record's candidate +
        // resolved graph (a tampered record — e.g. an exception moved onto SP1, a stale binding, a
        // wrong version — is rejected here at import time, not just at generation).
        let scoped = scope_and_validate_exceptions(&self.candidate, &self.advisory_exceptions, &self.nodes)
            .map_err(|e| Stage2RecordError::BadExceptionPolicy(e.to_string()))?;
        // Every recorded exception must have been in-scope for this candidate (none dropped by the
        // scope filter): a record must not carry an exception it did not actually apply.
        if scoped.len() != self.advisory_exceptions.len() {
            return Err(Stage2RecordError::BadExceptionPolicy(
                "record carries advisory exceptions not scoped to its own candidate".to_string(),
            ));
        }
        // the audit itself must not be fatal (advisories matched by a scoped exception are recorded,
        // not fatal; any other advisory stays fatal).
        let allowed: Vec<&str> = self.allowed_licenses.iter().map(String::as_str).collect();
        let report = audit_graph(&self.nodes, &self.advisories, &allowed, &scoped);
        if report.is_fatal() {
            return Err(Stage2RecordError::FatalAudit {
                count: report.fatal_findings().count(),
            });
        }
        Ok(report)
    }
}

// ---- Raw-command-output → typed, bound Stage-2 evidence ----------------------

/// The binding inputs the venue already holds for the Stage-2 record — everything
/// except the graph/advisories (parsed here from raw output) and the command-log hash
/// (computed here from the raw command log, never supplied).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2BindParams {
    pub candidate: String,
    pub arch: String,
    pub container_digest: String,
    pub lock_blake3_hex: String,
    pub source_commit: String,
    pub audit_tool_identity: String,
    pub cargo_audit_version: String,
    pub cargo_audit_executable_sha256: String,
    pub advisory_db: AdvisoryDbIdentity,
    pub audit_policy: AuditPolicy,
    pub allowed_licenses: Vec<String>,
}

// Focused views over raw `cargo metadata --format-version 1` / `cargo audit --json`
// output; the real outputs carry far more fields, all ignored here.
#[derive(serde::Deserialize)]
struct RawMetadata {
    packages: Vec<RawPackage>,
}
#[derive(serde::Deserialize)]
struct RawPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    license: Option<String>,
}
#[derive(serde::Deserialize)]
struct RawAudit {
    vulnerabilities: RawVulns,
}
#[derive(serde::Deserialize)]
struct RawVulns {
    #[serde(default)]
    list: Vec<RawVuln>,
}
#[derive(serde::Deserialize)]
struct RawVuln {
    advisory: RawAdvisory,
}
#[derive(serde::Deserialize)]
struct RawAdvisory {
    id: String,
    package: String,
}

/// Parse the resolved dependency graph from raw `cargo metadata --format-version 1`
/// output into typed [`CrateNode`]s. `source: null` is a path/workspace crate; a
/// `registry+` / `git+` source maps to the corresponding [`Source`] (an unrecognized
/// source is treated as non-registry so the source gate scrutinizes it).
pub fn parse_cargo_metadata(raw: &str) -> Result<Vec<CrateNode>, String> {
    let meta: RawMetadata =
        serde_json::from_str(raw).map_err(|e| format!("cargo metadata parse failed: {e}"))?;
    Ok(meta
        .packages
        .into_iter()
        .map(|p| {
            let source = match p.source.as_deref() {
                None => Source::Path,
                Some(s) if s.starts_with("registry+") => Source::Registry,
                Some(s) if s.starts_with("git+") => Source::Git,
                Some(_) => Source::Git,
            };
            CrateNode {
                name: p.name,
                version: p.version,
                source,
                license: p.license,
            }
        })
        .collect())
}

/// Parse active security advisories from raw `cargo audit --json` output. Every entry
/// in `vulnerabilities.list` affects the resolved graph, so it is recorded as an
/// UNRESOLVED advisory (`resolved: false`) and the audit gate then treats it as fatal.
pub fn parse_cargo_audit(raw: &str) -> Result<Vec<Advisory>, String> {
    let audit: RawAudit =
        serde_json::from_str(raw).map_err(|e| format!("cargo audit parse failed: {e}"))?;
    Ok(audit
        .vulnerabilities
        .list
        .into_iter()
        .map(|v| Advisory {
            crate_name: v.advisory.package,
            id: v.advisory.id,
            resolved: false,
        })
        .collect())
}

impl Stage2AuditRecord {
    /// Build a typed, bound Stage-2 record DIRECTLY from raw in-container command
    /// output: the graph from `cargo metadata`, the advisories from `cargo audit`, and
    /// the command-log hash computed HERE from the raw command log (never supplied).
    /// The result is fully validated (non-fatal audit + required-crate coverage) before
    /// it is returned, so a fatal graph never becomes a record.
    pub fn generate(
        params: &Stage2BindParams,
        cargo_metadata_raw: &str,
        cargo_audit_raw: &str,
        command_log_bytes: &[u8],
        exception_policy: &AdvisoryExceptionPolicy,
    ) -> Result<Stage2AuditRecord, Stage2RecordError> {
        let nodes = parse_cargo_metadata(cargo_metadata_raw).map_err(Stage2RecordError::Parse)?;
        let advisories = parse_cargo_audit(cargo_audit_raw).map_err(Stage2RecordError::Parse)?;
        // Scope + validate the committed exception policy to THIS candidate against the resolved
        // graph (fail closed on a forbidden-candidate/malformed/duplicate/stale/mismatched
        // exception), then RECORD exactly the applied set — the same reviewed policy is used for
        // TEST_ONLY and authoritative evaluation (this generator is the single shared path).
        let advisory_exceptions: Vec<AdvisoryException> =
            scope_and_validate_exceptions(&params.candidate, &exception_policy.exceptions, &nodes)
                .map_err(|e| Stage2RecordError::BadExceptionPolicy(e.to_string()))?
                .into_iter()
                .cloned()
                .collect();
        let record = Stage2AuditRecord {
            schema_version: STAGE2_SCHEMA_VERSION,
            candidate: params.candidate.clone(),
            arch: params.arch.clone(),
            lock_blake3_hex: params.lock_blake3_hex.clone(),
            container_digest: params.container_digest.clone(),
            source_commit: params.source_commit.clone(),
            command_log_blake3_hex: super::to_hex(blake3::hash(command_log_bytes).as_bytes()),
            audit_tool_identity: params.audit_tool_identity.clone(),
            cargo_audit_version: params.cargo_audit_version.clone(),
            cargo_audit_executable_sha256: params.cargo_audit_executable_sha256.clone(),
            advisory_db: params.advisory_db.clone(),
            audit_policy: params.audit_policy.clone(),
            allowed_licenses: params.allowed_licenses.clone(),
            nodes,
            advisories,
            advisory_exceptions,
        };
        record.validate()?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(name: &str, version: &str, source: Source, license: &str) -> CrateNode {
        CrateNode {
            name: name.into(),
            version: version.into(),
            source,
            license: Some(license.into()),
        }
    }

    const ALLOWED: &[&str] = &["MIT", "Apache-2.0", "MIT OR Apache-2.0", "BSD-3-Clause"];

    fn find_mut<'a>(g: &'a mut [CrateNode], name: &str) -> &'a mut CrateNode {
        g.iter_mut()
            .find(|c| c.name == name)
            .expect("node present in fixture")
    }

    /// A clean graph: the real per-candidate proof-stack crates at their pins, registry
    /// sources, allowed licenses, and the expected p3-* prereleases (recorded, not fatal).
    fn clean_graph() -> Vec<CrateNode> {
        vec![
            n("sp1-sdk", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
            n(
                "sp1-verifier",
                "6.3.1",
                Source::Registry,
                "MIT OR Apache-2.0",
            ),
            n("sp1-build", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
            n("sp1-zkvm", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
            n("risc0-zkvm", "3.0.5", Source::Registry, "Apache-2.0"),
            n("risc0-groth16", "3.0.4", Source::Registry, "Apache-2.0"),
            n("risc0-build", "3.0.5", Source::Registry, "Apache-2.0"),
            n(
                "risc0-zkvm-platform",
                "2.2.3",
                Source::Registry,
                "Apache-2.0",
            ),
            n("p3-field", "0.1.0-alpha.1", Source::Registry, "MIT"),
            n("p3-matrix", "0.1.0-beta", Source::Registry, "MIT"),
            n("serde", "1.0.200", Source::Registry, "MIT OR Apache-2.0"),
        ]
    }

    #[test]
    fn clean_graph_has_no_fatal_and_records_prereleases() {
        let r = audit_graph(&clean_graph(), &[], ALLOWED, &[]);
        assert!(
            !r.is_fatal(),
            "clean graph must not be fatal: {:?}",
            r.findings
        );
        let pre: Vec<_> = r.recorded_findings().collect();
        assert_eq!(pre.len(), 2, "the two p3-* prereleases are recorded");
        // machine-readable output reports fatal=false.
        assert!(r.to_json().contains("\"fatal\":false"));
    }

    #[test]
    fn wrong_pinned_version_is_fatal() {
        let mut g = clean_graph();
        find_mut(&mut g, "sp1-sdk").version = "6.3.0".into(); // a pinned crate off its pin
        let r = audit_graph(&g, &[], ALLOWED, &[]);
        assert!(r.is_fatal());
        assert!(r
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::WrongPinnedVersion { .. })));
    }

    #[test]
    fn git_or_path_source_on_proof_stack_is_fatal() {
        let mut g = clean_graph();
        find_mut(&mut g, "sp1-verifier").source = Source::Git; // a proof-stack crate from git
        let r = audit_graph(&g, &[], ALLOWED, &[]);
        assert!(r
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::UnexpectedSource { .. })));
    }

    #[test]
    fn unresolved_advisory_is_fatal_resolved_is_not() {
        let g = clean_graph();
        let unresolved = [Advisory {
            crate_name: "serde".into(),
            id: "RUSTSEC-0000-0000".into(),
            resolved: false,
        }];
        assert!(audit_graph(&g, &unresolved, ALLOWED, &[]).is_fatal());
        let resolved = [Advisory {
            crate_name: "serde".into(),
            id: "RUSTSEC-0000-0000".into(),
            resolved: true,
        }];
        assert!(!audit_graph(&g, &resolved, ALLOWED, &[]).is_fatal());
    }

    #[test]
    fn disallowed_or_missing_license_is_fatal() {
        let mut g = clean_graph();
        find_mut(&mut g, "serde").license = Some("GPL-3.0".into());
        assert!(audit_graph(&g, &[], ALLOWED, &[])
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::DisallowedLicense { .. })));
        find_mut(&mut g, "serde").license = None;
        assert!(audit_graph(&g, &[], ALLOWED, &[])
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::UnlicensedCrate { .. })));
    }

    #[test]
    fn duplicate_incompatible_proof_stack_versions_are_fatal() {
        let mut g = clean_graph();
        // a second, incompatible risc0-zkvm major in the graph.
        g.push(n("risc0-zkvm", "2.0.0", Source::Registry, "Apache-2.0"));
        let r = audit_graph(&g, &[], ALLOWED, &[]);
        assert!(r
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::DuplicateIncompatible { .. })));
    }

    #[test]
    fn prerelease_detection_ignores_build_metadata() {
        assert!(is_prerelease("0.1.0-alpha"));
        assert!(is_prerelease("1.2.3-rc.1"));
        assert!(!is_prerelease("0.11.0+wasi-snapshot"));
        assert!(!is_prerelease("1.0.200"));
    }

    // ---- Blocker 5: required-crate coverage + bound Stage-2 record ----------

    /// A realistic resolved SP1 6.3.1 graph: the four candidate-declared crates that MUST be
    /// covered (sp1-sdk/sp1-verifier/sp1-build/sp1-zkvm), plus transitive `sp1-*` crates that
    /// resolve alongside them but are not individually pinned, plus a recorded prerelease dep and
    /// an unrelated crate. There is deliberately NO crate literally named `sp1`.
    fn sp1_graph() -> Vec<CrateNode> {
        vec![
            n("sp1-sdk", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
            n(
                "sp1-verifier",
                "6.3.1",
                Source::Registry,
                "MIT OR Apache-2.0",
            ),
            n("sp1-build", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
            n("sp1-zkvm", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
            n(
                "sp1-core-machine",
                "6.3.1",
                Source::Registry,
                "MIT OR Apache-2.0",
            ),
            n(
                "sp1-primitives",
                "6.3.1",
                Source::Registry,
                "MIT OR Apache-2.0",
            ),
            n("p3-field", "0.1.0-alpha.1", Source::Registry, "MIT"),
            n("serde", "1.0.200", Source::Registry, "MIT OR Apache-2.0"),
        ]
    }

    fn risc0_graph() -> Vec<CrateNode> {
        vec![
            n("risc0-zkvm", "3.0.5", Source::Registry, "Apache-2.0"),
            n("risc0-build", "3.0.5", Source::Registry, "Apache-2.0"),
            n("risc0-groth16", "3.0.4", Source::Registry, "Apache-2.0"),
            n(
                "risc0-zkvm-platform",
                "2.2.3",
                Source::Registry,
                "Apache-2.0",
            ),
            n("serde", "1.0.200", Source::Registry, "MIT OR Apache-2.0"),
        ]
    }

    #[test]
    fn required_pins_present_exactly_once_passes_coverage() {
        assert_eq!(require_candidate_pins(&sp1_graph(), "Sp1"), Ok(()));
        assert_eq!(require_candidate_pins(&risc0_graph(), "Risc0"), Ok(()));
    }

    #[test]
    fn an_empty_graph_is_rejected() {
        assert_eq!(
            require_candidate_pins(&[], "Sp1"),
            Err(GraphCoverageError::EmptyGraph)
        );
    }

    #[test]
    fn a_missing_required_crate_is_rejected() {
        // drop risc0-groth16 -> incomplete graph.
        let g: Vec<CrateNode> = risc0_graph()
            .into_iter()
            .filter(|c| c.name != "risc0-groth16")
            .collect();
        assert!(matches!(
            require_candidate_pins(&g, "Risc0"),
            Err(GraphCoverageError::RequiredCrateAbsent { .. })
        ));
        // a graph with unrelated crates but no proof stack is likewise incomplete.
        let unrelated = vec![n("serde", "1.0.200", Source::Registry, "MIT")];
        assert!(matches!(
            require_candidate_pins(&unrelated, "Sp1"),
            Err(GraphCoverageError::RequiredCrateAbsent { .. })
        ));
    }

    // ---- SMOKE-BLOCKED-003 regression: the required-crate NAMES must be crates SP1 publishes ----

    /// REGRESSION for SMOKE-BLOCKED-003: SP1 6.3.1 publishes NO crate literally named `sp1` (its
    /// crates are all `sp1-*`), so the old `("sp1","6.3.1")` completeness pin was unsatisfiable by
    /// every correct SP1 graph and deterministically failed Stage 2. The contract now requires the
    /// four candidate-declared crates, and a realistic SP1 graph (which never contains bare `sp1`)
    /// is ACCEPTED.
    #[test]
    fn realistic_sp1_6_3_1_graph_without_a_bare_sp1_crate_is_accepted() {
        let g = sp1_graph();
        assert!(
            g.iter().all(|c| c.name != "sp1"),
            "a real SP1 graph contains no bare `sp1` crate"
        );
        assert!(g
            .iter()
            .any(|c| c.name == "sp1-sdk" && c.version == "6.3.1"));
        assert_eq!(require_candidate_pins(&g, "Sp1"), Ok(()));
        // the impossible historical requirement (a crate literally named `sp1`) must not return.
        assert!(
            required_pins_for("Sp1")
                .unwrap()
                .iter()
                .all(|(n, _)| *n != "sp1"),
            "no required SP1 crate may be the nonexistent bare `sp1`"
        );
    }

    /// PROOF_STACK_PINS (the version-check list) is EXACTLY the union of `required_pins_for` (the
    /// coverage list) over the candidates, and every required crate is a real `<stack>-<component>`
    /// name — never a bare stack name. This is the invariant whose absence let the bare-`sp1` bug
    /// live in two places at once.
    #[test]
    fn proof_stack_pins_are_the_union_of_required_pins_and_name_real_crates() {
        use std::collections::BTreeSet;
        let mut union: BTreeSet<(&str, &str)> = BTreeSet::new();
        for cand in ["Sp1", "Risc0"] {
            for (nm, v) in required_pins_for(cand).unwrap() {
                assert!(
                    *nm != "sp1" && *nm != "risc0",
                    "required crate {nm} is a bare stack name that no candidate publishes"
                );
                assert!(
                    nm.starts_with("sp1-") || nm.starts_with("risc0-"),
                    "required crate {nm} is not a real proof-stack crate name"
                );
                union.insert((nm, v));
            }
        }
        let pins: BTreeSet<(&str, &str)> =
            PROOF_STACK_PINS.iter().map(|(nm, v)| (*nm, *v)).collect();
        assert_eq!(
            pins, union,
            "PROOF_STACK_PINS must equal the union of required_pins_for over candidates"
        );
        assert!(required_pins_for("Nope").is_none());
    }

    /// The completeness gate fails closed on every way a required crate can be absent/wrong — for
    /// SP1 AND RISC Zero — and a cross-candidate graph cannot satisfy the other candidate.
    #[test]
    fn coverage_fails_closed_on_missing_wrong_version_duplicate_renamed_and_cross_candidate() {
        // missing: drop sp1-verifier.
        let mut g = sp1_graph();
        g.retain(|c| c.name != "sp1-verifier");
        assert!(matches!(
            require_candidate_pins(&g, "Sp1"),
            Err(GraphCoverageError::RequiredCrateAbsent { crate_name, .. }) if crate_name == "sp1-verifier"
        ));
        // wrong version: sp1-build resolved at 6.3.0 (present-at-pin count is 0).
        let mut g = sp1_graph();
        find_mut(&mut g, "sp1-build").version = "6.3.0".into();
        assert!(matches!(
            require_candidate_pins(&g, "Sp1"),
            Err(GraphCoverageError::RequiredCrateAbsent { crate_name, version })
                if crate_name == "sp1-build" && version == "6.3.1"
        ));
        // duplicated at the pinned version: two sp1-sdk 6.3.1.
        let mut g = sp1_graph();
        g.push(n("sp1-sdk", "6.3.1", Source::Registry, "MIT OR Apache-2.0"));
        assert!(matches!(
            require_candidate_pins(&g, "Sp1"),
            Err(GraphCoverageError::RequiredCrateDuplicated { crate_name, .. }) if crate_name == "sp1-sdk"
        ));
        // renamed: the historical bare `sp1` present does NOT cover the real sp1-zkvm requirement.
        let mut g = sp1_graph();
        g.retain(|c| c.name != "sp1-zkvm");
        g.push(n("sp1", "6.3.1", Source::Registry, "MIT OR Apache-2.0"));
        assert!(matches!(
            require_candidate_pins(&g, "Sp1"),
            Err(GraphCoverageError::RequiredCrateAbsent { crate_name, .. }) if crate_name == "sp1-zkvm"
        ));
        // cross-candidate: neither candidate's graph satisfies the other's coverage.
        assert!(matches!(
            require_candidate_pins(&sp1_graph(), "Risc0"),
            Err(GraphCoverageError::RequiredCrateAbsent { .. })
        ));
        assert!(matches!(
            require_candidate_pins(&risc0_graph(), "Sp1"),
            Err(GraphCoverageError::RequiredCrateAbsent { .. })
        ));
    }

    /// Unrelated `sp1-*` / `risc0-*` packages (not the required set) cannot accidentally satisfy
    /// coverage — the match is exact `(name, version)`, never a prefix / substring / version-only.
    #[test]
    fn unrelated_stack_prefixed_crates_do_not_satisfy_coverage() {
        let sp1_soup = vec![
            n(
                "sp1-core-machine",
                "6.3.1",
                Source::Registry,
                "MIT OR Apache-2.0",
            ),
            n(
                "sp1-primitives",
                "6.3.1",
                Source::Registry,
                "MIT OR Apache-2.0",
            ),
            n(
                "sp1-recursion-executor",
                "6.3.1",
                Source::Registry,
                "MIT OR Apache-2.0",
            ),
        ];
        assert!(matches!(
            require_candidate_pins(&sp1_soup, "Sp1"),
            Err(GraphCoverageError::RequiredCrateAbsent { .. })
        ));
        let risc0_soup = vec![
            n("risc0-binfmt", "3.0.5", Source::Registry, "Apache-2.0"),
            n(
                "risc0-circuit-rv32im",
                "3.0.5",
                Source::Registry,
                "Apache-2.0",
            ),
        ];
        assert!(matches!(
            require_candidate_pins(&risc0_soup, "Risc0"),
            Err(GraphCoverageError::RequiredCrateAbsent { .. })
        ));
    }

    /// RISC Zero's correct graph is accepted; a wrong RISC Zero version fails closed — equivalent
    /// negative coverage to SP1.
    #[test]
    fn risc0_correct_graph_accepted_wrong_version_fails_closed() {
        assert_eq!(require_candidate_pins(&risc0_graph(), "Risc0"), Ok(()));
        let mut g = risc0_graph();
        find_mut(&mut g, "risc0-zkvm-platform").version = "2.2.1".into();
        assert!(matches!(
            require_candidate_pins(&g, "Risc0"),
            Err(GraphCoverageError::RequiredCrateAbsent { crate_name, .. }) if crate_name == "risc0-zkvm-platform"
        ));
    }

    fn t_advdb() -> AdvisoryDbIdentity {
        AdvisoryDbIdentity {
            commit: "ab".repeat(20),
            git_tree: "cd".repeat(20),
            content_blake3: "ef".repeat(32),
        }
    }
    fn t_policy() -> AuditPolicy {
        AuditPolicy {
            database_update_allowed: false,
            stale_snapshot_permitted: true,
            output_format: "json".into(),
            database_source: "runtime-read-only-mount".into(),
        }
    }

    fn sp1_record() -> Stage2AuditRecord {
        Stage2AuditRecord {
            schema_version: STAGE2_SCHEMA_VERSION,
            candidate: "Sp1".into(),
            arch: "X86_64".into(),
            lock_blake3_hex: super::super::to_hex(blake3::hash(b"sp1-lock").as_bytes()),
            container_digest: format!(
                "sha256:{}",
                super::super::sha256::hex_digest(b"builder-sp1")
            ),
            source_commit: "a".repeat(40),
            command_log_blake3_hex: super::super::to_hex(
                blake3::hash(b"sp1-stage2-cmd").as_bytes(),
            ),
            audit_tool_identity: "cargo-metadata 1.0 + cargo-audit 0.22.2".into(),
            cargo_audit_version: "0.22.2".into(),
            cargo_audit_executable_sha256: "ca".repeat(32),
            advisory_db: t_advdb(),
            audit_policy: t_policy(),
            allowed_licenses: ["MIT", "Apache-2.0", "MIT OR Apache-2.0"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            nodes: sp1_graph(),
            advisories: vec![],
            advisory_exceptions: vec![],
        }
    }

    #[test]
    fn bound_stage2_record_validates_and_records_prereleases() {
        let rec = sp1_record();
        let report = rec.validate().expect("clean Stage-2 record");
        assert_eq!(report.recorded_findings().count(), 1); // the p3-* prerelease
    }

    // ---- structured advisory-exception subsystem (RISC0 rsa + tracing-subscriber) ----------
    const RSA_ADV: &str = "RUSTSEC-2023-0071";
    const TRC_ADV: &str = "RUSTSEC-2025-0055";

    fn ex(candidate: &str, adv: &str, crate_name: &str, ver: &str) -> AdvisoryException {
        AdvisoryException {
            candidate: candidate.into(),
            sdk: "risc0-zkvm=3.0.5".into(),
            advisory_id: adv.into(),
            affected_crate: crate_name.into(),
            affected_version: ver.into(),
            source_feature_graph_hash: "ab".repeat(32),
            justification: "compiled host tooling; vulnerable path not reachable in this mode".into(),
            applicability: "compiled-unreachable-in-this-execution-mode".into(),
            approving_policy_version: "test.1".into(),
            review_trigger: "any SDK/crate-version/feature-set/runner/lockfile/execution-mode change".into(),
        }
    }
    fn risc0_graph_with_advisory_crates() -> Vec<CrateNode> {
        vec![
            n("risc0-zkvm", "3.0.5", Source::Registry, "Apache-2.0"),
            n("risc0-groth16", "3.0.4", Source::Registry, "Apache-2.0"),
            n("risc0-build", "3.0.5", Source::Registry, "Apache-2.0"),
            n("risc0-zkvm-platform", "2.2.3", Source::Registry, "Apache-2.0"),
            n("rsa", "0.9.10", Source::Registry, "MIT OR Apache-2.0"),
            n("tracing-subscriber", "0.2.25", Source::Registry, "MIT"),
        ]
    }
    fn adv(crate_name: &str, id: &str) -> Advisory {
        Advisory { crate_name: crate_name.into(), id: id.into(), resolved: false }
    }
    fn risc0_advisories() -> Vec<Advisory> {
        vec![adv("rsa", RSA_ADV), adv("tracing-subscriber", TRC_ADV)]
    }
    fn valid_exceptions() -> Vec<AdvisoryException> {
        vec![
            ex("Risc0", RSA_ADV, "rsa", "0.9.10"),
            ex("Risc0", TRC_ADV, "tracing-subscriber", "0.2.25"),
        ]
    }

    #[test]
    fn accepted_exceptions_are_recorded_findings_never_zero_vulns_and_not_fatal() {
        let nodes = risc0_graph_with_advisory_crates();
        let exc = valid_exceptions();
        let scoped = scope_and_validate_exceptions("Risc0", &exc, &nodes)
            .expect("valid policy");
        assert_eq!(scoped.len(), 2);
        let report = audit_graph(&nodes, &risc0_advisories(), ALLOWED, &scoped);
        assert!(!report.is_fatal(), "accepted exceptions must not be fatal");
        let accepted = report
            .recorded_findings()
            .filter(|k| matches!(k, RecordedKind::AcceptedAdvisoryException { .. }))
            .count();
        // NEVER "0 vulnerabilities": both advisories are RECORDED as accepted_exception findings.
        assert_eq!(accepted, 2);
    }

    #[test]
    fn exception_cannot_mask_a_different_affected_version() {
        // policy accepts rsa 0.9.10; the graph now resolves rsa 0.9.11 (un-reviewed) -> stale/fatal.
        let mut nodes = risc0_graph_with_advisory_crates();
        find_mut(&mut nodes, "rsa").version = "0.9.11".into();
        assert!(matches!(
            scope_and_validate_exceptions("Risc0", &valid_exceptions(), &nodes),
            Err(ExceptionPolicyError::StaleBinding { .. })
        ));
    }

    #[test]
    fn exception_for_sp1_fails_closed() {
        let nodes = risc0_graph_with_advisory_crates();
        let exc = vec![ex("Sp1", RSA_ADV, "rsa", "0.9.10")];
        assert!(matches!(
            scope_and_validate_exceptions("Risc0", &exc, &nodes),
            Err(ExceptionPolicyError::ExceptionForForbiddenCandidate { .. })
        ));
        // And Risc0-scoped exceptions never scope INTO an SP1 audit.
        let sp1exc = valid_exceptions();
        let sp1graph = sp1_graph();
        let sp1_scoped = scope_and_validate_exceptions("Sp1", &sp1exc, &sp1graph)
            .expect("risc0 exceptions simply do not apply to SP1");
        assert!(sp1_scoped.is_empty());
    }

    #[test]
    fn exception_cannot_mask_a_new_unlisted_advisory() {
        let nodes = risc0_graph_with_advisory_crates();
        let exc = valid_exceptions();
        let scoped = scope_and_validate_exceptions("Risc0", &exc, &nodes).unwrap();
        let mut advs = risc0_advisories();
        advs.push(adv("rsa", "RUSTSEC-2099-9999")); // a NEW, unlisted advisory
        let report = audit_graph(&nodes, &advs, ALLOWED, &scoped);
        assert!(report.is_fatal(), "a newly reachable/unlisted advisory must stay fatal");
    }

    #[test]
    fn exception_with_stale_crate_binding_is_refused() {
        let mut nodes = risc0_graph_with_advisory_crates();
        nodes.retain(|c| c.name != "rsa"); // rsa resolved away
        assert!(matches!(
            scope_and_validate_exceptions("Risc0", &valid_exceptions(), &nodes),
            Err(ExceptionPolicyError::StaleBinding { .. })
        ));
    }

    #[test]
    fn duplicate_exception_is_refused() {
        let nodes = risc0_graph_with_advisory_crates();
        let mut exc = valid_exceptions();
        exc.push(ex("Risc0", RSA_ADV, "rsa", "0.9.10"));
        assert!(matches!(
            scope_and_validate_exceptions("Risc0", &exc, &nodes),
            Err(ExceptionPolicyError::Duplicate { .. })
        ));
    }

    #[test]
    fn exception_missing_justification_is_refused() {
        let nodes = risc0_graph_with_advisory_crates();
        let mut e = ex("Risc0", RSA_ADV, "rsa", "0.9.10");
        e.justification = "   ".into();
        assert!(matches!(
            scope_and_validate_exceptions("Risc0", std::slice::from_ref(&e), &nodes),
            Err(ExceptionPolicyError::MissingField { field: "justification", .. })
        ));
    }

    #[test]
    fn exception_with_wrong_sdk_binding_is_refused() {
        let mut nodes = risc0_graph_with_advisory_crates();
        find_mut(&mut nodes, "risc0-zkvm").version = "3.0.6".into();
        assert!(matches!(
            scope_and_validate_exceptions("Risc0", &valid_exceptions(), &nodes),
            Err(ExceptionPolicyError::SdkMismatch { .. })
        ));
    }

    #[test]
    fn a_record_with_an_out_of_scope_exception_is_rejected() {
        // A tampered record: an SP1 record carrying a Risc0 exception must fail closed at validate.
        let mut rec = sp1_record();
        rec.advisory_exceptions = vec![ex("Risc0", RSA_ADV, "rsa", "0.9.10")];
        assert!(matches!(
            rec.validate(),
            Err(Stage2RecordError::BadExceptionPolicy(_))
        ));
    }

    #[test]
    fn bound_stage2_record_rejects_incomplete_graph() {
        let mut rec = sp1_record();
        rec.nodes.retain(|c| c.name != "sp1-sdk"); // remove a required pinned crate
        assert!(matches!(
            rec.validate(),
            Err(Stage2RecordError::Coverage(
                GraphCoverageError::RequiredCrateAbsent { .. }
            ))
        ));
    }

    #[test]
    fn bound_stage2_record_rejects_fatal_audit() {
        let mut rec = sp1_record();
        find_mut(&mut rec.nodes, "sp1-sdk").version = "6.3.0".into(); // off its pin -> fatal AND missing pin
        assert!(rec.validate().is_err());
        // isolate the fatal-audit path: keep the pin present but add a git proof-stack.
        let mut rec2 = sp1_record();
        rec2.nodes
            .push(n("sp1-recursion", "6.3.1", Source::Git, "MIT"));
        assert!(matches!(
            rec2.validate(),
            Err(Stage2RecordError::FatalAudit { .. })
        ));
    }

    #[test]
    fn bound_stage2_record_rejects_synthetic_container_and_missing_snapshot() {
        let mut rec = sp1_record();
        rec.container_digest = format!("sha256:{}", "0".repeat(64));
        // all-zero is not synthetic-marked but is caught elsewhere; use a sentinel.
        rec.container_digest = format!("{}://x", "TEST_ONLY_SYNTHETIC");
        assert!(matches!(
            rec.validate(),
            Err(Stage2RecordError::BadContainerDigest { .. })
        ));
        // v2: a policy that permits DB update (moving DB) is refused.
        let mut rec2 = sp1_record();
        rec2.audit_policy.database_update_allowed = true;
        assert!(matches!(
            rec2.validate(),
            Err(Stage2RecordError::BadPolicy(
                "database_update_allowed (must be false)"
            ))
        ));
        // v2: a malformed advisory-DB commit is refused.
        let mut rec3 = sp1_record();
        rec3.advisory_db.commit = "nothex".into();
        assert!(matches!(
            rec3.validate(),
            Err(Stage2RecordError::BadHash("advisory_db.commit"))
        ));
        // v1 (unversioned) is ineligible for authoritative evidence.
        let mut rec4 = sp1_record();
        rec4.schema_version = 1;
        assert!(matches!(
            rec4.validate(),
            Err(Stage2RecordError::UnsupportedSchemaVersion { got: 1 })
        ));
    }

    // ---- raw-output → typed generation ------------------------------------

    fn sp1_bind() -> Stage2BindParams {
        Stage2BindParams {
            candidate: "Sp1".into(),
            arch: "X86_64".into(),
            container_digest: format!(
                "sha256:{}",
                super::super::sha256::hex_digest(b"builder-sp1")
            ),
            lock_blake3_hex: super::super::to_hex(blake3::hash(b"sp1-lock").as_bytes()),
            source_commit: "a".repeat(40),
            audit_tool_identity: "cargo-metadata 1.0 + cargo-audit 0.22.2".into(),
            cargo_audit_version: "0.22.2".into(),
            cargo_audit_executable_sha256: "ca".repeat(32),
            advisory_db: t_advdb(),
            audit_policy: t_policy(),
            allowed_licenses: ["MIT", "Apache-2.0", "MIT OR Apache-2.0"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    // Source/license-mapping fixture: a registry pin, a git dep, and a workspace/path
    // member (source null, license null) — exercises all three `Source` variants.
    const META_MIXED: &str = r#"{
      "packages": [
        {"name":"sp1-sdk","version":"6.3.1","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT OR Apache-2.0"},
        {"name":"somegit","version":"0.1.0","source":"git+https://github.com/x/y#abc","license":"MIT"},
        {"name":"b0-pre-candidate-sp1-host","version":"0.0.0","source":null,"license":null}
      ],
      "workspace_members": [], "resolve": null
    }"#;
    // Audit-valid fixture (mirrors the known-good sp1_graph): the four required SP1 crates at
    // their pins, plus a prerelease and an unrelated crate; all registry + licensed.
    const META_VALID: &str = r#"{
      "packages": [
        {"name":"sp1-sdk","version":"6.3.1","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT OR Apache-2.0"},
        {"name":"sp1-verifier","version":"6.3.1","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT OR Apache-2.0"},
        {"name":"sp1-build","version":"6.3.1","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT OR Apache-2.0"},
        {"name":"sp1-zkvm","version":"6.3.1","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT OR Apache-2.0"},
        {"name":"p3-field","version":"0.1.0-alpha.1","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT"},
        {"name":"serde","version":"1.0.200","source":"registry+https://github.com/rust-lang/crates.io-index","license":"MIT OR Apache-2.0"}
      ], "workspace_members": [], "resolve": null
    }"#;
    const NO_VULNS: &str = r#"{"vulnerabilities":{"found":false,"count":0,"list":[]}}"#;

    #[test]
    fn parse_cargo_metadata_maps_sources_and_licenses() {
        let nodes = parse_cargo_metadata(META_MIXED).expect("parse");
        assert_eq!(nodes.len(), 3);
        let sp1 = nodes.iter().find(|n| n.name == "sp1-sdk").unwrap();
        assert_eq!(sp1.source, Source::Registry);
        assert_eq!(sp1.license.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(
            nodes.iter().find(|n| n.name == "somegit").unwrap().source,
            Source::Git
        );
        // source: null -> Path (workspace/local); license null -> None.
        let local = nodes
            .iter()
            .find(|n| n.name == "b0-pre-candidate-sp1-host")
            .unwrap();
        assert_eq!(local.source, Source::Path);
        assert!(local.license.is_none());
    }

    #[test]
    fn parse_cargo_audit_extracts_active_advisories() {
        let raw = r#"{"vulnerabilities":{"found":true,"count":1,"list":[
            {"advisory":{"id":"RUSTSEC-2024-0001","package":"badcrate"}}]}}"#;
        let advs = parse_cargo_audit(raw).expect("parse");
        assert_eq!(advs.len(), 1);
        assert_eq!(advs[0].crate_name, "badcrate");
        assert_eq!(advs[0].id, "RUSTSEC-2024-0001");
        assert!(
            !advs[0].resolved,
            "a listed advisory affects the graph -> unresolved"
        );
        assert!(parse_cargo_audit(NO_VULNS).unwrap().is_empty());
    }

    #[test]
    fn stage2_generate_builds_a_valid_bound_record_from_raw_output() {
        let log = b"docker run ... cargo metadata --locked && cargo audit --json\n";
        let rec = Stage2AuditRecord::generate(&sp1_bind(), META_VALID, NO_VULNS, log, &AdvisoryExceptionPolicy::default())
            .expect("valid graph generates a record");
        assert_eq!(rec.candidate, "Sp1");
        assert_eq!(rec.nodes.len(), 6);
        assert!(rec.advisories.is_empty());
        // the command-log hash is DERIVED here from the raw log, not supplied.
        assert_eq!(
            rec.command_log_blake3_hex,
            super::super::to_hex(blake3::hash(log).as_bytes())
        );
        // and it re-validates (the generator never emits a record that fails validation).
        assert!(rec.validate().is_ok());
    }

    #[test]
    fn stage2_generate_rejects_a_fatal_graph() {
        // sp1 (present at its pin, so coverage passes) carries a disallowed license ->
        // fatal audit -> no record is emitted.
        let bad = META_VALID.replacen("MIT OR Apache-2.0", "GPL-3.0-only", 1);
        let err = Stage2AuditRecord::generate(&sp1_bind(), &bad, NO_VULNS, b"log", &AdvisoryExceptionPolicy::default()).unwrap_err();
        assert!(matches!(err, Stage2RecordError::FatalAudit { .. }));
        // and a wrong pin is rejected too, at the coverage gate (before the audit).
        let wrong = META_VALID.replace("\"6.3.1\"", "\"6.3.0\"");
        assert!(matches!(
            Stage2AuditRecord::generate(&sp1_bind(), &wrong, NO_VULNS, b"log", &AdvisoryExceptionPolicy::default()).unwrap_err(),
            Stage2RecordError::Coverage(_)
        ));
    }

    #[test]
    fn stage2_generate_rejects_an_unresolved_advisory() {
        let vuln = r#"{"vulnerabilities":{"found":true,"count":1,"list":[
            {"advisory":{"id":"RUSTSEC-2024-0002","package":"sp1-sdk"}}]}}"#;
        let err = Stage2AuditRecord::generate(&sp1_bind(), META_VALID, vuln, b"log", &AdvisoryExceptionPolicy::default()).unwrap_err();
        assert!(matches!(err, Stage2RecordError::FatalAudit { .. }));
    }
}

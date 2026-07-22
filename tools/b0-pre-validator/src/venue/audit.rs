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
pub const PROOF_STACK_PINS: &[(&str, &str)] = &[
    ("sp1", "6.3.1"),
    ("risc0-zkvm", "3.0.5"),
    ("risc0-build", "3.0.5"),
    ("risc0-groth16", "3.0.4"),
    ("risc0-zkvm-platform", "2.2.2"),
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
) -> AuditReport {
    let mut findings = Vec::new();

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
        // license allow-list
        match &n.license {
            None => findings.push(Finding::Fatal(FatalKind::UnlicensedCrate {
                crate_name: n.name.clone(),
            })),
            Some(lic) if !allowed_licenses.contains(&lic.as_str()) => {
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

    // (4) unresolved advisories.
    for a in advisories {
        if !a.resolved {
            findings.push(Finding::Fatal(FatalKind::UnresolvedAdvisory {
                crate_name: a.crate_name.clone(),
                id: a.id.clone(),
            }));
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
/// SP1's requirement is the `sp1` crate at 6.3.1; RISC Zero's is its four pinned
/// crates (VENUE.md §5). These mirror [`PROOF_STACK_PINS`], not a second policy.
pub fn required_pins_for(candidate: &str) -> Option<&'static [(&'static str, &'static str)]> {
    const SP1: &[(&str, &str)] = &[("sp1", "6.3.1")];
    const RISC0: &[(&str, &str)] = &[
        ("risc0-zkvm", "3.0.5"),
        ("risc0-build", "3.0.5"),
        ("risc0-groth16", "3.0.4"),
        ("risc0-zkvm-platform", "2.2.2"),
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

/// The bound Stage-2 audit record: the in-container-DERIVED resolved graph +
/// advisories + license allow-list, bound to the resolved lock hash, the builder
/// container digest, the clean source commit, the architecture, and the exact
/// audit-tool identity / advisory-DB snapshot. Stage 6 (via the evidence bundle)
/// REQUIRES this — not a bare externally-supplied graph.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stage2AuditRecord {
    pub candidate: String,
    pub arch: String,
    /// Bound to the resolved candidate lock hash (bare 64-hex BLAKE3).
    pub lock_blake3_hex: String,
    /// Bound to the builder-image `sha256:<64hex>` digest the graph was resolved in.
    pub container_digest: String,
    pub source_commit: String,
    /// The exact audit-tool identity (e.g. `cargo-metadata 1.x + cargo-audit 0.y`).
    pub audit_tool_identity: String,
    /// The advisory-DB snapshot the scan ran against (git rev / date).
    pub advisory_db_snapshot: String,
    pub allowed_licenses: Vec<String>,
    /// The DERIVED-in-container resolved graph (dependency/source/license nodes).
    pub nodes: Vec<CrateNode>,
    pub advisories: Vec<Advisory>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage2RecordError {
    UnknownCandidate {
        candidate: String,
    },
    UnknownArch {
        arch: String,
    },
    Missing(&'static str),
    BadHash(&'static str),
    BadContainerDigest {
        digest: String,
    },
    /// A fatal audit finding (wrong pin, bad source, advisory, license, ...).
    FatalAudit {
        count: usize,
    },
    /// The required-crate coverage failed (empty/incomplete graph).
    Coverage(GraphCoverageError),
}

impl std::fmt::Display for Stage2RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stage2RecordError::UnknownCandidate { candidate } => {
                write!(f, "unknown candidate {candidate:?}")
            }
            Stage2RecordError::UnknownArch { arch } => write!(f, "unknown architecture {arch:?}"),
            Stage2RecordError::Missing(field) => write!(f, "Stage-2 record field {field} is empty"),
            Stage2RecordError::BadHash(field) => {
                write!(f, "Stage-2 record {field} is not bare 64-hex")
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
        }
    }
}

impl std::error::Error for Stage2RecordError {}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
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
        if self.audit_tool_identity.trim().is_empty() {
            return Err(Stage2RecordError::Missing("audit_tool_identity"));
        }
        if self.advisory_db_snapshot.trim().is_empty() {
            return Err(Stage2RecordError::Missing("advisory_db_snapshot"));
        }
        // required-crate coverage (rejects empty/incomplete graphs).
        require_candidate_pins(&self.nodes, &self.candidate)
            .map_err(Stage2RecordError::Coverage)?;
        // the audit itself must not be fatal.
        let allowed: Vec<&str> = self.allowed_licenses.iter().map(String::as_str).collect();
        let report = audit_graph(&self.nodes, &self.advisories, &allowed);
        if report.is_fatal() {
            return Err(Stage2RecordError::FatalAudit {
                count: report.fatal_findings().count(),
            });
        }
        Ok(report)
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

    /// A clean graph: correct pins, registry sources, allowed licenses, and the
    /// expected p3-* prereleases (recorded, not fatal).
    fn clean_graph() -> Vec<CrateNode> {
        vec![
            n("sp1", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
            n("risc0-zkvm", "3.0.5", Source::Registry, "Apache-2.0"),
            n("risc0-groth16", "3.0.4", Source::Registry, "Apache-2.0"),
            n(
                "risc0-zkvm-platform",
                "2.2.2",
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
        let r = audit_graph(&clean_graph(), &[], ALLOWED);
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
        g[0].version = "6.3.0".into(); // sp1 not at its pin
        let r = audit_graph(&g, &[], ALLOWED);
        assert!(r.is_fatal());
        assert!(r
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::WrongPinnedVersion { .. })));
    }

    #[test]
    fn git_or_path_source_on_proof_stack_is_fatal() {
        let mut g = clean_graph();
        g[1].source = Source::Git; // risc0-zkvm from git
        let r = audit_graph(&g, &[], ALLOWED);
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
        assert!(audit_graph(&g, &unresolved, ALLOWED).is_fatal());
        let resolved = [Advisory {
            crate_name: "serde".into(),
            id: "RUSTSEC-0000-0000".into(),
            resolved: true,
        }];
        assert!(!audit_graph(&g, &resolved, ALLOWED).is_fatal());
    }

    #[test]
    fn disallowed_or_missing_license_is_fatal() {
        let mut g = clean_graph();
        g[6].license = Some("GPL-3.0".into());
        assert!(audit_graph(&g, &[], ALLOWED)
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::DisallowedLicense { .. })));
        g[6].license = None;
        assert!(audit_graph(&g, &[], ALLOWED)
            .fatal_findings()
            .any(|k| matches!(k, FatalKind::UnlicensedCrate { .. })));
    }

    #[test]
    fn duplicate_incompatible_proof_stack_versions_are_fatal() {
        let mut g = clean_graph();
        // a second, incompatible risc0-zkvm major in the graph.
        g.push(n("risc0-zkvm", "2.0.0", Source::Registry, "Apache-2.0"));
        let r = audit_graph(&g, &[], ALLOWED);
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

    fn sp1_graph() -> Vec<CrateNode> {
        vec![
            n("sp1", "6.3.1", Source::Registry, "MIT OR Apache-2.0"),
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
                "2.2.2",
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

    fn sp1_record() -> Stage2AuditRecord {
        Stage2AuditRecord {
            candidate: "Sp1".into(),
            arch: "X86_64".into(),
            lock_blake3_hex: super::super::to_hex(blake3::hash(b"sp1-lock").as_bytes()),
            container_digest: format!(
                "sha256:{}",
                super::super::sha256::hex_digest(b"builder-sp1")
            ),
            source_commit: "a".repeat(40),
            audit_tool_identity: "cargo-metadata 1.0 + cargo-audit 0.21".into(),
            advisory_db_snapshot: "rustsec-db@2026-07-01".into(),
            allowed_licenses: ["MIT", "Apache-2.0", "MIT OR Apache-2.0"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            nodes: sp1_graph(),
            advisories: vec![],
        }
    }

    #[test]
    fn bound_stage2_record_validates_and_records_prereleases() {
        let rec = sp1_record();
        let report = rec.validate().expect("clean Stage-2 record");
        assert_eq!(report.recorded_findings().count(), 1); // the p3-* prerelease
    }

    #[test]
    fn bound_stage2_record_rejects_incomplete_graph() {
        let mut rec = sp1_record();
        rec.nodes.retain(|c| c.name != "sp1"); // remove the pinned crate
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
        rec.nodes[0].version = "6.3.0".into(); // sp1 off its pin -> fatal AND missing pin
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
        let mut rec2 = sp1_record();
        rec2.advisory_db_snapshot = "  ".into();
        assert!(matches!(
            rec2.validate(),
            Err(Stage2RecordError::Missing("advisory_db_snapshot"))
        ));
    }
}

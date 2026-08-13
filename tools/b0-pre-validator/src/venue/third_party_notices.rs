//! Third-party license NOTICE packaging for the B0-PRE candidate artifacts (compliance).
//!
//! Each candidate's sealed evidence bundle must CARRY the copyright/permission notices and license
//! texts of every third-party crate its resolved dependency graph redistributes (see
//! `docs/b0-pre/venue/THIRD-PARTY-LICENSES.md`). This module is the reproducible, fail-closed
//! generator + verifier:
//!
//!   * INPUT  — the candidate's sealed `Cargo.lock` (the EXACT resolved graph; already bound into
//!              the bundle) + a materialized crate-source root (`cargo vendor`), so the notices come
//!              from the crates' OWN license files, not a canonical-text guess.
//!   * OUTPUT — a deterministic `ThirdPartyNotices` manifest: for EVERY third-party package in the
//!              lock, its FULL identity (name, version, `source`, and registry `checksum`), its
//!              declared SPDX expression, and the verbatim text (+ SHA-256, + crate-relative path)
//!              of every license/copyright/notice file the crate ships. A package is third-party iff
//!              it carries a `source` (registry OR git — both are redistributed); only a package with
//!              NO source (a path/workspace member) is first-party and carries no obligation.
//!   * GATE   — FAIL CLOSED at every ambiguity: a licensed package that ships no collectable notice
//!              file (and no readable `license-file`) refuses generation; an unreadable / non-UTF-8 /
//!              symlinked / escaping notice file refuses; two packages that collapse to one vendor
//!              directory refuse; a duplicate package identity refuses. Verification re-derives the
//!              full third-party set (and the first-party set) from the lock and rejects any missing,
//!              extra, duplicate, unsorted, checksum-mismatched, empty, or text-vs-SHA-mismatched
//!              record. Nothing is fabricated, deduplicated, or defaulted.
//!
//! The manifest is content-addressed (BLAKE3, domain-separated) and bound to the lock hash, so the
//! sealed bundle + the import gate can require it, byte-for-byte, before an artifact finalizes.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

/// Domain tag for the notice-manifest content hash (kept distinct from every other B0-PRE hash).
pub const NOTICES_TAG: &str = "SUMCHAIN/B0PRE/THIRDPARTYNOTICES/v1";

pub const NOTICES_SCHEMA_VERSION: u16 = 1;

/// The license/copyright/notice file basenames a crate may ship, matched case-insensitively. A
/// crate satisfies the notice obligation by shipping at least one of these (or a readable
/// `license-file`); the FULL verbatim text of every match is captured. `AUTHORS` and `PATENTS` are
/// deliberately NOT here: a contributors list or a bare patent grant is not a license text, so a
/// crate shipping only those must still fail closed for its license.
fn is_notice_filename(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    const EXACT: &[&str] = &["NOTICE", "COPYRIGHT"];
    if EXACT
        .iter()
        .any(|e| n == *e || n.starts_with(&format!("{e}.")))
    {
        return true;
    }
    n.starts_with("LICENSE")
        || n.starts_with("LICENCE")
        || n.starts_with("COPYING")
        || n.starts_with("UNLICENSE")
}

/// True iff `rel` is a safe canonical relative path: at least one component, and every component is
/// a plain `Normal` name with no NUL — no absolute prefix / root, no `..`, no `.`, no empty. Mirrors
/// `checkout_digest::rel_path_is_safe`, the project's established traversal guard.
fn rel_path_is_safe(rel: &Path) -> bool {
    let mut any = false;
    for c in rel.components() {
        match c {
            Component::Normal(s) => {
                match s.to_str() {
                    Some(x) if !x.contains('\0') => {}
                    _ => return false,
                }
                any = true;
            }
            // RootDir/Prefix (absolute), ParentDir (`..`), CurDir (`.`) are all rejected.
            _ => return false,
        }
    }
    any
}

/// Normalize a crate-relative notice path for use as a stable key + record: forward slashes, no
/// leading `./`. (The vendored sources are Linux paths, so components are already `/`-separated.)
fn normalize_rel(rel: &str) -> String {
    rel.trim().trim_start_matches("./").replace('\\', "/")
}

/// One collected notice file: its crate-relative path, verbatim UTF-8 text, and the SHA-256 of the
/// exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeFile {
    /// The file's path RELATIVE to the crate root (e.g. `LICENSE-MIT`, `licenses/APACHE`), forward-
    /// slashed and normalized. Preserved (not collapsed to a basename) so distinct files never merge.
    pub path: String,
    pub sha256: String,
    pub text: String,
}

/// Where an entry's notice texts came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeSource {
    /// Collected from the vendored crate's OWN license/notice files.
    CrateFile,
    /// The crate ships no license file; the texts come from the owner-ratified per-family upstream
    /// notice map (`map_family` names the covering family).
    RatifiedMap,
    /// The crate is in the resolved lock but is NOT compiled for any venue build target (a
    /// platform-gated dependency, e.g. a macOS/Windows-only crate), so the produced artifact never
    /// redistributes it and it carries no notice. `venue_targets` records the targets checked.
    NotRedistributed,
}

/// One third-party package's notice record, carrying its FULL lock identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeEntry {
    pub name: String,
    pub version: String,
    /// The package's exact `source` string from the lock (`registry+…` or `git+…`). Every entry is
    /// third-party, so this is always present; it is part of the package identity, so a
    /// source-swapped manifest is rejected.
    pub source: String,
    /// The registry `checksum` from the lock (present for registry packages, absent for git). Bound
    /// so a manifest cannot claim a different resolved artifact than the lock pins.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub checksum: Option<String>,
    /// The crate's declared SPDX license expression (from its `Cargo.toml` `license`), empty when it
    /// declares only a `license-file`.
    pub spdx: String,
    /// Whether `notices` were collected from the crate's own files or supplied by the ratified map.
    pub notice_source: NoticeSource,
    /// The ratified-map family id that supplied the texts (present iff `notice_source` is
    /// `ratified-map`), so audit can trace a map-sourced notice to its ratified upstream provenance.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub map_family: Option<String>,
    /// Every notice/license/copyright file for the crate, sorted by `path`, paths unique. Non-empty.
    pub notices: Vec<NoticeFile>,
}

/// The per-candidate third-party notice manifest bound into the sealed bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThirdPartyNotices {
    pub schema_version: u16,
    pub candidate: String,
    pub arch: String,
    /// The domain-separated candidate-lock hash this notice set is bound to (bare 64-hex BLAKE3),
    /// so a notice set generated for a different graph cannot satisfy the gate.
    pub lock_blake3_hex: String,
    /// The first-party (path/workspace, source-less) package names deliberately excluded, sorted +
    /// unique. Recomputed and compared exactly on verify.
    pub first_party: Vec<String>,
    /// The ratified per-family notice-map `policy_version` applied during generation, present iff at
    /// least one entry has `notice_source == ratified-map`. Records WHICH ratified map covered the
    /// no-file crates (a full re-verification against the committed map is a producer/CI step).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ratified_map_version: Option<String>,
    /// The venue build target triples the notice set was scoped to (e.g. `x86_64-unknown-linux-gnu`,
    /// `aarch64-unknown-linux-gnu`). Non-empty iff any entry is `not-redistributed`; a crate not
    /// compiled for ANY of these targets carries no notice. Empty = full-lock coverage (no scoping).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub venue_targets: Vec<String>,
    /// Every third-party package's collected notices, sorted by (name, version, source), unique.
    pub entries: Vec<NoticeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoticeError {
    LockParse(String),
    /// A crate source directory expected from the lock is absent in the vendor root.
    MissingSource {
        name: String,
        version: String,
    },
    /// A notice or `license-file` path is unsafe (absolute / traversal / escapes the crate dir),
    /// is a symlink or non-regular file, or is unreadable / not UTF-8.
    BadNoticeFile {
        name: String,
        version: String,
        detail: String,
    },
    /// Two DISTINCT packages collapse to the same `<name>-<version>` vendor directory (their notices
    /// cannot be disambiguated from the vendored layout).
    AmbiguousVendorDir {
        name: String,
        version: String,
    },
    /// The lock (or manifest) carries the same package identity twice.
    DuplicatePackage {
        name: String,
        version: String,
        source: String,
    },
    /// The verified manifest does not match the lock's third-party / first-party set, or a record is
    /// empty / mis-hashed / mis-bound / duplicated / unsorted.
    Mismatch(String),
    BadHash(&'static str),
    /// The ratified per-family notice map is malformed.
    BadMap(String),
    /// A crate ships no license file AND no ratified-map family covers it — fail closed.
    UncoveredByMap {
        name: String,
        version: String,
        spdx: String,
    },
    /// A no-file crate's declared SPDX does not exactly match its covering ratified-map family's.
    MapSpdxMismatch {
        name: String,
        version: String,
        declared: String,
        family: String,
        family_spdx: String,
    },
    /// A crate is covered only by a CANONICAL-fallback family (upstream ships no license text) that
    /// the owner has NOT individually approved — fail closed.
    CanonicalNotApproved {
        name: String,
        version: String,
        family: String,
    },
    /// The sealed target-closure record is malformed or not bound to the lock / Stage-2 graph.
    BadClosure(String),
    /// A notice entry's redistribution classification does not match the recomputed target closure.
    ClassificationMismatch {
        name: String,
        version: String,
        detail: String,
    },
    /// A FETCHED-UPSTREAM family covers this crate NAME, but the EXACT package identity
    /// `(name, version, source)` or the published archive checksum does not match the family's
    /// binding. Such a family is NEVER a wildcard: it applies only to the one exact package it was
    /// fetched for; another version/source or a same-name package fails closed.
    FetchedUpstreamIdentityMismatch {
        name: String,
        version: String,
        family: String,
        detail: String,
    },
}

impl std::fmt::Display for NoticeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoticeError::LockParse(e) => write!(f, "Cargo.lock parse failed: {e}"),
            NoticeError::MissingSource { name, version } => {
                write!(f, "crate source absent from vendor root: {name} {version}")
            }
            NoticeError::BadNoticeFile {
                name,
                version,
                detail,
            } => write!(f, "bad notice file for {name} {version}: {detail}"),
            NoticeError::AmbiguousVendorDir { name, version } => write!(
                f,
                "two distinct packages collapse to vendor dir {name}-{version}; cannot disambiguate notices — fail closed"
            ),
            NoticeError::DuplicatePackage {
                name,
                version,
                source,
            } => write!(f, "duplicate package identity {name} {version} [{source}]"),
            NoticeError::Mismatch(e) => write!(f, "third-party notice manifest mismatch: {e}"),
            NoticeError::BadHash(field) => {
                write!(f, "third-party notice field {field} is not bare 64-hex")
            }
            NoticeError::BadMap(e) => write!(f, "ratified notice map invalid: {e}"),
            NoticeError::UncoveredByMap {
                name,
                version,
                spdx,
            } => write!(
                f,
                "{name} {version} (license {spdx:?}) ships no license file and no ratified-map family covers it — fail closed"
            ),
            NoticeError::MapSpdxMismatch {
                name,
                version,
                declared,
                family,
                family_spdx,
            } => write!(
                f,
                "{name} {version} declares {declared:?} but ratified-map family {family:?} asserts {family_spdx:?}"
            ),
            NoticeError::CanonicalNotApproved {
                name,
                version,
                family,
            } => write!(
                f,
                "{name} {version} is covered only by CANONICAL-fallback family {family:?} which the owner has not individually approved — fail closed"
            ),
            NoticeError::BadClosure(e) => write!(f, "target-closure record invalid: {e}"),
            NoticeError::ClassificationMismatch {
                name,
                version,
                detail,
            } => write!(
                f,
                "{name} {version} redistribution classification does not match the target closure: {detail}"
            ),
            NoticeError::FetchedUpstreamIdentityMismatch {
                name,
                version,
                family,
                detail,
            } => write!(
                f,
                "{name} {version} does not match the exact package identity bound by fetched-upstream family {family:?} (not a wildcard): {detail}"
            ),
        }
    }
}
impl std::error::Error for NoticeError {}

/// The per-crate attestation REQUIRED when a family's notice text is not the crate's own license
/// file. Every kind records the exhaustive search and requires INDIVIDUAL owner approval; without
/// approval the generator fails closed. No copyright is ever synthesized — the crate's declared
/// metadata authors are recorded verbatim for reference only, never injected into the license text.
///
/// `kind` categorizes WHY the fallback is used and what text is carried:
///   * `apache-or-branch`   — the crate's SPDX offers Apache-2.0 as an OR alternative; the canonical
///                            Apache-2.0 body is carried (no upstream NOTICE file, confirmed).
///   * `fork-lineage`       — the crate is a fork whose upstream dropped the license; the PARENT
///                            project's REAL license text (with its copyright) is carried.
///   * `mit-risk-acceptance`— an un-removable, un-bumpable transitive dependency declares MIT but
///                            ships no copyright notice anywhere; the owner explicitly ACCEPTS the
///                            documented risk and carries the canonical MIT body. `risk_acceptance`
///                            states the acceptance; `crates_io_owners` records the authoritative
///                            crates.io ownership verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAttestation {
    /// The attestation kind (see the type doc): `apache-or-branch` | `fork-lineage` |
    /// `mit-risk-acceptance`.
    pub kind: String,
    /// The exhaustive search performed (published tag/commit, repository history, parent workspace,
    /// README, source headers, crates.io) and its negative result.
    pub search_log: String,
    /// The source `repository` and the exact commit the text/search is bound to (for `fork-lineage`,
    /// the PARENT repository; empty if the repo is unreachable — recorded as such in `search_log`).
    pub repository: String,
    pub repository_commit: String,
    /// The crate's declared SPDX expression (must equal the family `spdx`).
    pub declared_spdx: String,
    /// The crate's `authors` recorded VERBATIM from its `Cargo.toml` (reference only; never placed
    /// into the license text).
    pub metadata_authors: Vec<String>,
    /// The authoritative crates.io owners recorded VERBATIM (reference only). Present for
    /// `mit-risk-acceptance`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub crates_io_owners: Vec<String>,
    /// The SPDX license id(s) whose body is carried (e.g. `MIT`, `Apache-2.0`). For `fork-lineage`
    /// the body is the parent's real file rather than a canonical template.
    pub canonical_spdx_ids: Vec<String>,
    /// SHA-256 of each body carried, matching the family `notices` shas (sorted).
    pub canonical_text_sha256: Vec<String>,
    /// The explicit owner risk-acceptance statement. Required (non-empty) for `mit-risk-acceptance`.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub risk_acceptance: String,
    /// INDIVIDUAL owner approval that this fallback satisfies the obligation for this crate. The
    /// generator fails closed on any attested family that is not approved.
    pub owner_approved: bool,
}

/// One ratified upstream-notice family: a set of crate NAMES that share one upstream license text,
/// with the exact SPDX the covered crates must declare and the pinned notice text(s).
/// For a FETCHED-UPSTREAM family — the notice text IS the crate's OWN license, fetched from
/// the upstream repository at an EXACT commit because the PUBLISHED crate ships no license file.
/// The loader verifies crate/version/source identity, the upstream commit (a 40-hex commit,
/// NEVER a tag) + its resolution authority, and the published crate's absence of license files;
/// the exact license bytes/hashes are verified via the family `notices` (sha-true). Mutually
/// exclusive with `attestation` (there is no canonical fallback and no synthesized copyright).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchedUpstream {
    pub crate_name: String,
    pub crate_version: String,
    /// The exact Cargo source, e.g. `registry+https://github.com/rust-lang/crates.io-index`.
    pub crate_source: String,
    /// SHA-256 of the exact published `.crate` whose absence-of-license was determined.
    pub published_crate_sha256: String,
    /// The PUBLISHED crate ships NO license file (that is why the upstream text is fetched).
    pub published_license_files_absent: bool,
    pub repository: String,
    /// The EXACT upstream commit the license bytes were fetched at (40-hex; NEVER a tag).
    pub commit: String,
    /// How the commit was resolved (e.g. `.cargo_vcs_info.json`).
    pub commit_authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeFamily {
    /// Stable family id (e.g. `succinct-sp1`, `plonky3-succinct`, `arkworks`).
    pub id: String,
    /// The EXACT SPDX expression the covered crates must declare (a version whose license changed
    /// no longer matches, so it fails closed until the map is updated).
    pub spdx: String,
    /// Human-auditable upstream provenance for the texts (repo URL @ commit / file paths).
    pub upstream_provenance: String,
    /// The crate NAMES this family covers (version-independent; the `spdx` match is the guard).
    pub covers: Vec<String>,
    /// The pinned notice text(s), sorted by `path`, paths unique, each `sha256` matching its `text`.
    pub notices: Vec<NoticeFile>,
    /// Present iff this family supplies the CANONICAL SPDX body because upstream ships no license
    /// text. Requires individual owner approval; a family WITH real upstream texts omits it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attestation: Option<CanonicalAttestation>,
    /// Present iff this is a fetched-upstream family whose notice texts ARE the crate's own
    /// license files, fetched from upstream at an exact commit (the published crate ships none).
    /// Mutually exclusive with `attestation`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fetched_upstream: Option<FetchedUpstream>,
}

impl NoticeFamily {
    /// True iff this family may be USED by the generator: a real-upstream family always; a canonical
    /// (attested) family only when the owner has individually approved it.
    fn is_usable(&self) -> bool {
        match &self.attestation {
            None => true,
            Some(a) => a.owner_approved,
        }
    }
}

/// The owner-ratified per-family upstream notice map: for crates that declare an SPDX license but
/// ship no license file, the real upstream license text (fetched once, pinned by hash) to carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RatifiedNoticeMap {
    pub policy_version: String,
    #[serde(default)]
    pub note: String,
    pub families: Vec<NoticeFamily>,
}

impl RatifiedNoticeMap {
    /// Parse + fully validate a ratified notice map: non-empty version, unique family ids, each
    /// family non-empty + notices sha-true and strictly sorted-unique by path, and NO crate name
    /// covered by two families (an ambiguous mapping).
    pub fn load(json: &str) -> Result<Self, NoticeError> {
        let m: RatifiedNoticeMap =
            serde_json::from_str(json).map_err(|e| NoticeError::BadMap(format!("parse: {e}")))?;
        if m.policy_version.trim().is_empty() {
            return Err(NoticeError::BadMap("empty policy_version".into()));
        }
        let mut ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut covered: BTreeMap<&str, &str> = BTreeMap::new();
        for fam in &m.families {
            if fam.id.trim().is_empty() {
                return Err(NoticeError::BadMap("empty family id".into()));
            }
            if !ids.insert(fam.id.as_str()) {
                return Err(NoticeError::BadMap(format!(
                    "duplicate family id {}",
                    fam.id
                )));
            }
            if fam.spdx.trim().is_empty() {
                return Err(NoticeError::BadMap(format!(
                    "family {} has empty spdx",
                    fam.id
                )));
            }
            if fam.covers.is_empty() {
                return Err(NoticeError::BadMap(format!(
                    "family {} covers nothing",
                    fam.id
                )));
            }
            if fam.notices.is_empty() {
                return Err(NoticeError::BadMap(format!(
                    "family {} has no notices",
                    fam.id
                )));
            }
            let mut prev: Option<&str> = None;
            for nf in &fam.notices {
                if let Some(p) = prev {
                    if p >= nf.path.as_str() {
                        return Err(NoticeError::BadMap(format!(
                            "family {} notices not strictly sorted/unique by path",
                            fam.id
                        )));
                    }
                }
                prev = Some(nf.path.as_str());
                if nf.sha256 != sha256_hex(nf.text.as_bytes()) {
                    return Err(NoticeError::BadMap(format!(
                        "family {} notice {} sha256 does not match text",
                        fam.id, nf.path
                    )));
                }
            }
            for c in &fam.covers {
                if let Some(other) = covered.insert(c.as_str(), fam.id.as_str()) {
                    return Err(NoticeError::BadMap(format!(
                        "crate {c} covered by two families ({other} and {})",
                        fam.id
                    )));
                }
            }
            // A FETCHED-UPSTREAM family (real upstream license text): verify the structured
            // provenance is exact + well-formed and mutually exclusive with a canonical
            // attestation. A nonexistent-tag substitution (commit not 40-hex), a missing crate
            // identity, a non-64-hex published-crate sha, or a claim that the published crate DID
            // ship a license all fail closed here.
            if let Some(fu) = &fam.fetched_upstream {
                if fam.attestation.is_some() {
                    return Err(NoticeError::BadMap(format!(
                        "family {} has both fetched_upstream and a canonical attestation",
                        fam.id
                    )));
                }
                if fu.crate_name.trim().is_empty()
                    || fu.crate_version.trim().is_empty()
                    || fu.crate_source.trim().is_empty()
                    || fu.repository.trim().is_empty()
                    || fu.commit_authority.trim().is_empty()
                {
                    return Err(NoticeError::BadMap(format!(
                        "family {} fetched_upstream has an empty required field",
                        fam.id
                    )));
                }
                if !fam.covers.iter().any(|c| c == &fu.crate_name) {
                    return Err(NoticeError::BadMap(format!(
                        "family {} fetched_upstream crate {:?} is not in covers",
                        fam.id, fu.crate_name
                    )));
                }
                let is_hex64 = |s: &str| {
                    s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                };
                if !is_hex64(&fu.published_crate_sha256) {
                    return Err(NoticeError::BadMap(format!(
                        "family {} fetched_upstream published_crate_sha256 is not 64-hex",
                        fam.id
                    )));
                }
                if !fu.published_license_files_absent {
                    return Err(NoticeError::BadMap(format!(
                        "family {} fetched_upstream must record the published crate ships no license file",
                        fam.id
                    )));
                }
                // The upstream commit MUST be an exact 40-hex commit — NEVER a tag.
                let commit_ok = fu.commit.len() == 40
                    && fu
                        .commit
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
                if !commit_ok {
                    return Err(NoticeError::BadMap(format!(
                        "family {} fetched_upstream commit {:?} is not a 40-hex commit (tags are refused)",
                        fam.id, fu.commit
                    )));
                }
            }
            // A canonical (attested) family: validate the attestation is complete + self-consistent.
            if let Some(a) = &fam.attestation {
                const KINDS: &[&str] = &["apache-or-branch", "fork-lineage", "mit-risk-acceptance"];
                if !KINDS.contains(&a.kind.as_str()) {
                    return Err(NoticeError::BadMap(format!(
                        "family {} attestation kind {:?} is not one of {KINDS:?}",
                        fam.id, a.kind
                    )));
                }
                if a.kind == "mit-risk-acceptance"
                    && (a.risk_acceptance.trim().is_empty() || a.crates_io_owners.is_empty())
                {
                    return Err(NoticeError::BadMap(format!(
                        "family {} mit-risk-acceptance requires a non-empty risk_acceptance + crates_io_owners",
                        fam.id
                    )));
                }
                if a.search_log.trim().is_empty() {
                    return Err(NoticeError::BadMap(format!(
                        "family {} attestation has empty search_log",
                        fam.id
                    )));
                }
                if a.declared_spdx != fam.spdx {
                    return Err(NoticeError::BadMap(format!(
                        "family {} attestation declared_spdx != family spdx",
                        fam.id
                    )));
                }
                if a.canonical_spdx_ids.is_empty() {
                    return Err(NoticeError::BadMap(format!(
                        "family {} attestation has no canonical_spdx_ids",
                        fam.id
                    )));
                }
                // the attestation's canonical hashes must equal the family notices' shas (sorted).
                let mut want: Vec<&str> = fam.notices.iter().map(|n| n.sha256.as_str()).collect();
                want.sort_unstable();
                let mut got: Vec<&str> =
                    a.canonical_text_sha256.iter().map(String::as_str).collect();
                got.sort_unstable();
                if want != got {
                    return Err(NoticeError::BadMap(format!(
                        "family {} attestation canonical_text_sha256 != family notice shas",
                        fam.id
                    )));
                }
            }
        }
        Ok(m)
    }

    /// The family covering crate `name`, if any.
    fn family_for(&self, name: &str) -> Option<&NoticeFamily> {
        self.families
            .iter()
            .find(|f| f.covers.iter().any(|c| c == name))
    }
}

impl ThirdPartyNotices {
    /// Full ratification binding (a producer/CI step): every `ratified-map` entry must name a family
    /// that exists in `map`, covers the crate, asserts the entry's SPDX, and whose pinned notices are
    /// BYTE-EXACT the entry's — so a sealed manifest cannot claim map provenance for texts the
    /// ratified map does not contain. Also requires `ratified_map_version` to equal the map's version.
    pub fn verify_map_sources(&self, map: &RatifiedNoticeMap) -> Result<(), NoticeError> {
        let uses_map = self
            .entries
            .iter()
            .any(|e| e.notice_source == NoticeSource::RatifiedMap);
        if uses_map && self.ratified_map_version.as_deref() != Some(map.policy_version.as_str()) {
            return Err(NoticeError::Mismatch(format!(
                "ratified_map_version {:?} != map policy_version {:?}",
                self.ratified_map_version, map.policy_version
            )));
        }
        for e in &self.entries {
            if e.notice_source != NoticeSource::RatifiedMap {
                continue;
            }
            let fam_id = e.map_family.as_deref().ok_or_else(|| {
                NoticeError::Mismatch(format!("map entry {} {} missing family", e.name, e.version))
            })?;
            let fam = map
                .families
                .iter()
                .find(|f| f.id == fam_id)
                .ok_or_else(|| {
                    NoticeError::Mismatch(format!(
                        "map entry {} {} names unknown family {fam_id}",
                        e.name, e.version
                    ))
                })?;
            if !fam.covers.iter().any(|c| c == &e.name) {
                return Err(NoticeError::Mismatch(format!(
                    "family {fam_id} does not cover {}",
                    e.name
                )));
            }
            if fam.spdx != e.spdx {
                return Err(NoticeError::Mismatch(format!(
                    "family {fam_id} spdx != entry {} spdx",
                    e.name
                )));
            }
            if fam.notices != e.notices {
                return Err(NoticeError::Mismatch(format!(
                    "map entry {} {} notices are not byte-exact the ratified family {fam_id}",
                    e.name, e.version
                )));
            }
        }
        Ok(())
    }

    /// Independently verify every entry's redistribution CLASSIFICATION against a recomputed target
    /// closure — the `not-redistributed` marking is NEVER trusted from the producer. Validates +
    /// binds the sealed closure (lock hash + Stage-2 graph identity + candidate/arch/targets),
    /// requires the closure's third-party node set to EQUAL the lock's third-party set (so no locked
    /// crate can be hidden), recomputes the normal-dependency closure by pure graph reachability, and
    /// requires: a third-party package IN the closure is `crate-file`/`ratified-map`; a package NOT
    /// in the closure is `not-redistributed`. Full package identity (name, version, source) is used
    /// throughout, so multiple versions cannot be conflated.
    pub fn verify_classification(
        &self,
        closure: &TargetClosure,
        lock: &str,
        lock_blake3_hex: &str,
        stage2_graph_blake3_hex: &str,
    ) -> Result<(), NoticeError> {
        closure.validate(lock_blake3_hex, stage2_graph_blake3_hex)?;
        if closure.candidate != self.candidate {
            return Err(NoticeError::BadClosure(format!(
                "closure candidate {:?} != manifest candidate {:?}",
                closure.candidate, self.candidate
            )));
        }
        if closure.arch != self.arch {
            return Err(NoticeError::BadClosure(
                "closure arch != manifest arch".into(),
            ));
        }
        if closure.venue_targets != self.venue_targets {
            return Err(NoticeError::BadClosure(
                "closure venue_targets != manifest venue_targets".into(),
            ));
        }
        // The closure's third-party node set must EQUAL the lock's third-party set — a closure that
        // omits (or adds) a locked crate cannot silently reclassify it.
        let packages = sorted_unique_packages(lock)?;
        let lock_tp: std::collections::BTreeSet<(String, String, String)> = packages
            .iter()
            .filter(|p| !p.is_first_party())
            .map(|p| {
                (
                    p.name.clone(),
                    p.version.clone(),
                    p.source.clone().unwrap_or_default(),
                )
            })
            .collect();
        let closure_tp: std::collections::BTreeSet<(String, String, String)> = closure
            .nodes
            .iter()
            .filter(|n| !n.source.is_empty())
            .map(|n| (n.name.clone(), n.version.clone(), n.source.clone()))
            .collect();
        if lock_tp != closure_tp {
            return Err(NoticeError::BadClosure(
                "closure third-party node set != lock third-party set".into(),
            ));
        }
        let redist = closure.redistributed();
        let by_id: BTreeMap<(&str, &str, &str), &NoticeEntry> = self
            .entries
            .iter()
            .map(|e| ((e.name.as_str(), e.version.as_str(), e.source.as_str()), e))
            .collect();
        for id in &lock_tp {
            let key = (id.0.as_str(), id.1.as_str(), id.2.as_str());
            let e = by_id
                .get(&key)
                .ok_or_else(|| NoticeError::ClassificationMismatch {
                    name: id.0.clone(),
                    version: id.1.clone(),
                    detail: "no notice entry for lock package".into(),
                })?;
            let in_closure = redist.contains(id);
            match e.notice_source {
                NoticeSource::NotRedistributed if in_closure => {
                    return Err(NoticeError::ClassificationMismatch {
                        name: id.0.clone(),
                        version: id.1.clone(),
                        detail: "marked not-redistributed but IS in the normal closure".into(),
                    })
                }
                NoticeSource::CrateFile | NoticeSource::RatifiedMap if !in_closure => {
                    return Err(NoticeError::ClassificationMismatch {
                        name: id.0.clone(),
                        version: id.1.clone(),
                        detail: "carries a notice but is NOT in the normal closure (should be not-redistributed)".into(),
                    })
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// The canonical package-identity key: name + version + source (empty source = path/first-party).
fn pkgid(name: &str, version: &str, source: &str) -> String {
    // Unit-separator delimited so it is unambiguous even if a name/version contained a space.
    format!("{name}\u{1f}{version}\u{1f}{source}")
}

/// One node of the sealed platform-resolved NORMAL-dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureNode {
    pub name: String,
    pub version: String,
    /// The lock `source` (empty for path/workspace/first-party members).
    pub source: String,
    /// The registry checksum, when present (bound so a node cannot be swapped for another artifact).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub checksum: Option<String>,
    /// The `pkgid` strings this node normal-depends on (build/dev edges excluded; already platform-
    /// filtered by `cargo metadata --filter-platform` for the venue targets).
    pub normal_deps: Vec<String>,
}

impl ClosureNode {
    fn id(&self) -> String {
        pkgid(&self.name, &self.version, &self.source)
    }
}

/// The sealed, deterministic **target-closure record**: the platform-resolved NORMAL-dependency
/// graph over the venue build target(s), so `import-bundle` can INDEPENDENTLY recompute which lock
/// crates the produced artifact actually redistributes and require every notice entry's
/// `crate-file` / `ratified-map` / `not-redistributed` classification to match — the classification
/// is never trusted from the producer. Bound to the candidate, arch, target triples, feature set,
/// the `Cargo.lock` hash, and the Stage-2 graph identity so target/feature/graph drift is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetClosure {
    pub schema_version: u16,
    pub candidate: String,
    pub arch: String,
    /// The venue build target triples the closure was resolved for (union taken over these).
    pub venue_targets: Vec<String>,
    /// The feature flags the resolution used (empty = default features), bound for drift detection.
    #[serde(default)]
    pub features: Vec<String>,
    /// The domain-separated candidate-lock hash (== the Stage-2 record's `lock_blake3_hex`).
    pub lock_blake3_hex: String,
    /// The Stage-2 graph identity this closure is bound to (== the Stage-2 record's
    /// `command_log_blake3_hex`), so the closure is tied to the audited resolve graph.
    pub stage2_graph_blake3_hex: String,
    /// The workspace root member `pkgid`s (first-party); redistribution is the normal closure of these.
    pub roots: Vec<String>,
    /// Every package node in the platform-resolved graph.
    pub nodes: Vec<ClosureNode>,
}

pub const TARGET_CLOSURE_SCHEMA_VERSION: u16 = 1;

impl TargetClosure {
    /// Validate internal consistency + the required bindings (lock hash + Stage-2 graph identity).
    pub fn validate(
        &self,
        lock_blake3_hex: &str,
        stage2_graph_blake3_hex: &str,
    ) -> Result<(), NoticeError> {
        if self.schema_version != TARGET_CLOSURE_SCHEMA_VERSION {
            return Err(NoticeError::BadClosure(format!(
                "schema_version {}",
                self.schema_version
            )));
        }
        if !super::is_hex64(&self.lock_blake3_hex) {
            return Err(NoticeError::BadHash("closure lock_blake3_hex"));
        }
        if self.lock_blake3_hex != lock_blake3_hex {
            return Err(NoticeError::BadClosure(
                "lock_blake3_hex not bound to this lock".into(),
            ));
        }
        if self.stage2_graph_blake3_hex != stage2_graph_blake3_hex {
            return Err(NoticeError::BadClosure(
                "stage2_graph_blake3_hex not bound to the Stage-2 graph".into(),
            ));
        }
        if self.venue_targets.is_empty() {
            return Err(NoticeError::BadClosure("empty venue_targets".into()));
        }
        // unique node identities; every edge + root references an existing node.
        let mut ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for n in &self.nodes {
            if !ids.insert(n.id()) {
                return Err(NoticeError::BadClosure(format!(
                    "duplicate closure node {} {} [{}]",
                    n.name, n.version, n.source
                )));
            }
        }
        for n in &self.nodes {
            for d in &n.normal_deps {
                if !ids.contains(d) {
                    return Err(NoticeError::BadClosure(format!(
                        "closure node {} references unknown dep",
                        n.name
                    )));
                }
            }
        }
        for r in &self.roots {
            if !ids.contains(r) {
                return Err(NoticeError::BadClosure("closure root is not a node".into()));
            }
        }
        if self.roots.is_empty() {
            return Err(NoticeError::BadClosure("no roots".into()));
        }
        Ok(())
    }

    /// Recompute the THIRD-PARTY redistributed set: the normal-dependency closure of the roots,
    /// keeping only nodes that carry a `source` (registry/git). Pure graph reachability over the
    /// sealed normal edges — no producer-asserted membership is trusted.
    pub fn redistributed(&self) -> std::collections::BTreeSet<(String, String, String)> {
        let by_id: BTreeMap<String, &ClosureNode> =
            self.nodes.iter().map(|n| (n.id(), n)).collect();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut stack: Vec<String> = self.roots.clone();
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(n) = by_id.get(&id) {
                for d in &n.normal_deps {
                    if !seen.contains(d) {
                        stack.push(d.clone());
                    }
                }
            }
        }
        // third-party (source non-empty) reached nodes
        self.nodes
            .iter()
            .filter(|n| !n.source.is_empty() && seen.contains(&n.id()))
            .map(|n| (n.name.clone(), n.version.clone(), n.source.clone()))
            .collect()
    }
}

/// A `[[package]]` row from `Cargo.lock` with the fields that fix its identity.
#[derive(Debug, Clone)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    /// `None` = path/workspace (first-party); `Some("registry+…")` / `Some("git+…")` = third-party.
    pub source: Option<String>,
    /// The registry `checksum`, when present (registry packages carry one; git/path do not).
    pub checksum: Option<String>,
}

impl LockPackage {
    pub fn is_registry(&self) -> bool {
        self.source
            .as_deref()
            .map(|s| s.starts_with("registry+"))
            .unwrap_or(false)
    }
    /// First-party iff it carries NO source (a path/workspace member). Registry AND git packages are
    /// third-party (redistributed).
    pub fn is_first_party(&self) -> bool {
        self.source.is_none()
    }
    /// The full identity used for coverage/sorting: (name, version, source). First-party packages
    /// have `source == ""` here (they are tracked separately, by name).
    fn identity(&self) -> (&str, &str, &str) {
        (
            self.name.as_str(),
            self.version.as_str(),
            self.source.as_deref().unwrap_or(""),
        )
    }
    /// The `cargo vendor --versioned-dirs` directory name for this package.
    fn vendor_dir_name(&self) -> String {
        format!("{}-{}", self.name, self.version)
    }
}

/// Minimal, dependency-free `Cargo.lock` package parser (name/version/source/checksum). The lock is
/// a TOML array of `[[package]]` tables; we read just the four identity fields, so no toml crate is
/// pulled and the parse is trivially auditable.
pub fn parse_lock_packages(lock: &str) -> Result<Vec<LockPackage>, NoticeError> {
    let mut out = Vec::new();
    // (name, version, source, checksum)
    type Cur = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let mut cur: Option<Cur> = None;
    let flush = |cur: &mut Option<Cur>, out: &mut Vec<LockPackage>| -> Result<(), NoticeError> {
        if let Some((name, version, source, checksum)) = cur.take() {
            let name = name.ok_or_else(|| NoticeError::LockParse("package without name".into()))?;
            let version = version
                .ok_or_else(|| NoticeError::LockParse(format!("package {name} without version")))?;
            out.push(LockPackage {
                name,
                version,
                source,
                checksum,
            });
        }
        Ok(())
    };
    for line in lock.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(&mut cur, &mut out)?;
            cur = Some((None, None, None, None));
            continue;
        }
        if let Some(c) = cur.as_mut() {
            if let Some(v) = t.strip_prefix("name = ") {
                c.0 = Some(unquote(v));
            } else if let Some(v) = t.strip_prefix("version = ") {
                c.1 = Some(unquote(v));
            } else if let Some(v) = t.strip_prefix("source = ") {
                c.2 = Some(unquote(v));
            } else if let Some(v) = t.strip_prefix("checksum = ") {
                c.3 = Some(unquote(v));
            }
        }
    }
    flush(&mut cur, &mut out)?;
    Ok(out)
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    super::sha256::hex_digest(bytes)
}

/// Parse a `key = "value"` TOML string field from a single line, tolerant of the whitespace around
/// `=` (canonical vendored `Cargo.toml` uses `key = "v"`, but do not depend on it). Returns the
/// unquoted value only when `key` is the exact bare key (so `license` never matches `license-file`).
fn toml_string_value(line: &str, key: &str) -> Option<String> {
    let rest = line.trim().strip_prefix(key)?;
    let rest = rest.trim_start().strip_prefix('=')?;
    let rest = rest.trim();
    if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
        Some(unquote(rest))
    } else {
        None
    }
}

/// Read the crate's declared SPDX `license` (and `license-file`) from its vendored `Cargo.toml`,
/// with a trivial line scanner (avoids a toml dependency; the fields are single-line strings).
fn read_license_fields(cargo_toml: &str) -> (Option<String>, Option<String>) {
    let (mut lic, mut licf) = (None, None);
    let mut in_package = false;
    for line in cargo_toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_package = t == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        // `license-file` first: `license` is a prefix of it, though the exact-`=` guard already
        // prevents a false match.
        if let Some(v) = toml_string_value(t, "license-file") {
            licf = Some(v);
        } else if let Some(v) = toml_string_value(t, "license") {
            lic = Some(v);
        }
    }
    (lic, licf)
}

/// Insert a collected notice file keyed by its crate-relative path, failing closed on a CONFLICTING
/// duplicate (same path, different bytes) — identical re-collections (e.g. a `license-file` that
/// points at a file the directory scan already captured) are idempotent.
fn insert_notice(
    p: &LockPackage,
    files: &mut BTreeMap<String, NoticeFile>,
    nf: NoticeFile,
) -> Result<(), NoticeError> {
    if let Some(existing) = files.get(&nf.path) {
        if existing.sha256 != nf.sha256 {
            return Err(NoticeError::BadNoticeFile {
                name: p.name.clone(),
                version: p.version.clone(),
                detail: format!("conflicting duplicate notice path {}", nf.path),
            });
        }
        return Ok(());
    }
    files.insert(nf.path.clone(), nf);
    Ok(())
}

/// Read a regular notice file at `abs` (already confirmed a non-symlink regular file), returning its
/// verbatim UTF-8 text — fail closed on read error or non-UTF-8.
fn read_notice_text(p: &LockPackage, abs: &Path, rel: &str) -> Result<NoticeFile, NoticeError> {
    let bytes = std::fs::read(abs).map_err(|e| NoticeError::BadNoticeFile {
        name: p.name.clone(),
        version: p.version.clone(),
        detail: format!("unreadable notice {rel}: {e}"),
    })?;
    let text = String::from_utf8(bytes.clone()).map_err(|_| NoticeError::BadNoticeFile {
        name: p.name.clone(),
        version: p.version.clone(),
        detail: format!("notice {rel} is not UTF-8"),
    })?;
    Ok(NoticeFile {
        path: normalize_rel(rel),
        sha256: sha256_hex(&bytes),
        text,
    })
}

/// Collect every notice file the crate at `crate_dir` ships. Every matching candidate is either
/// collected or fails closed (no silent skips): a symlink or non-regular notice-named entry, an
/// unreadable / non-UTF-8 file, or a `read_dir` failure all refuse. A `license-file` is additionally
/// bounded to the canonical crate directory (no absolute / traversal / symlink escape).
fn collect_crate_notices(
    p: &LockPackage,
    crate_dir: &Path,
) -> Result<(String, Vec<NoticeFile>), NoticeError> {
    let cargo_toml_path = crate_dir.join("Cargo.toml");
    let cargo_toml =
        std::fs::read_to_string(&cargo_toml_path).map_err(|_| NoticeError::MissingSource {
            name: p.name.clone(),
            version: p.version.clone(),
        })?;
    let (spdx, license_file) = read_license_fields(&cargo_toml);

    let crate_canon = crate_dir
        .canonicalize()
        .map_err(|e| NoticeError::BadNoticeFile {
            name: p.name.clone(),
            version: p.version.clone(),
            detail: format!("cannot canonicalize crate dir: {e}"),
        })?;

    let mut files: BTreeMap<String, NoticeFile> = BTreeMap::new();

    // (1) every notice-named entry in the crate root — collected or fail closed, never skipped.
    let rd = std::fs::read_dir(crate_dir).map_err(|e| NoticeError::BadNoticeFile {
        name: p.name.clone(),
        version: p.version.clone(),
        detail: format!("cannot read crate dir: {e}"),
    })?;
    for ent in rd {
        let ent = ent.map_err(|e| NoticeError::BadNoticeFile {
            name: p.name.clone(),
            version: p.version.clone(),
            detail: format!("directory entry error: {e}"),
        })?;
        let fname = ent.file_name().to_string_lossy().to_string();
        if !is_notice_filename(&fname) {
            continue;
        }
        let ft = ent.file_type().map_err(|e| NoticeError::BadNoticeFile {
            name: p.name.clone(),
            version: p.version.clone(),
            detail: format!("cannot stat notice-named entry {fname}: {e}"),
        })?;
        if ft.is_dir() {
            // A directory named like a license file is not a notice file; ignore it explicitly.
            continue;
        }
        if ft.is_symlink() || !ft.is_file() {
            return Err(NoticeError::BadNoticeFile {
                name: p.name.clone(),
                version: p.version.clone(),
                detail: format!("notice-named entry {fname} is a symlink or non-regular file"),
            });
        }
        let nf = read_notice_text(p, &ent.path(), &fname)?;
        insert_notice(p, &mut files, nf)?;
    }

    // (2) an explicit `license-file` (may point into a subdirectory) — bounded to the crate dir.
    if let Some(rel) = license_file.as_deref().filter(|s| !s.is_empty()) {
        let rel_path = Path::new(rel);
        if !rel_path_is_safe(rel_path) {
            return Err(NoticeError::BadNoticeFile {
                name: p.name.clone(),
                version: p.version.clone(),
                detail: format!("unsafe license-file path (absolute/traversal): {rel}"),
            });
        }
        let abs = crate_dir.join(rel_path);
        let md = std::fs::symlink_metadata(&abs).map_err(|e| NoticeError::BadNoticeFile {
            name: p.name.clone(),
            version: p.version.clone(),
            detail: format!("unreadable license-file {rel}: {e}"),
        })?;
        if md.file_type().is_symlink() || !md.is_file() {
            return Err(NoticeError::BadNoticeFile {
                name: p.name.clone(),
                version: p.version.clone(),
                detail: format!("license-file {rel} is a symlink or non-regular file"),
            });
        }
        // Canonicalize + require containment beneath the canonical crate dir (defeats symlinked
        // intermediate directories too).
        let abs_canon = abs.canonicalize().map_err(|e| NoticeError::BadNoticeFile {
            name: p.name.clone(),
            version: p.version.clone(),
            detail: format!("cannot canonicalize license-file {rel}: {e}"),
        })?;
        if !abs_canon.starts_with(&crate_canon) {
            return Err(NoticeError::BadNoticeFile {
                name: p.name.clone(),
                version: p.version.clone(),
                detail: format!("license-file {rel} escapes the crate directory"),
            });
        }
        let nf = read_notice_text(p, &abs, rel)?;
        insert_notice(p, &mut files, nf)?;
    }

    let spdx = spdx.unwrap_or_default();
    // BTreeMap iteration is already sorted by path; collect in that canonical order. The result may
    // be EMPTY (the crate ships no license file) — the caller then consults the ratified map, and
    // fails closed only if no family covers the crate.
    Ok((spdx, files.into_values().collect()))
}

/// Sort key over full identity + reject a duplicate identity or an ambiguous vendor-dir collision.
/// Returns the packages sorted by (name, version, source).
fn sorted_unique_packages(lock: &str) -> Result<Vec<LockPackage>, NoticeError> {
    let mut packages = parse_lock_packages(lock)?;
    packages.sort_by(|a, b| a.identity().cmp(&b.identity()));
    // Reject a duplicated FULL identity (a malformed lock).
    for w in packages.windows(2) {
        if w[0].identity() == w[1].identity() {
            return Err(NoticeError::DuplicatePackage {
                name: w[0].name.clone(),
                version: w[0].version.clone(),
                source: w[0].source.clone().unwrap_or_default(),
            });
        }
    }
    // Reject two DISTINCT third-party identities that map to one vendor directory.
    let mut by_dir: BTreeMap<String, (&str, &str, &str)> = BTreeMap::new();
    for p in packages.iter().filter(|p| !p.is_first_party()) {
        let dir = p.vendor_dir_name();
        match by_dir.get(&dir) {
            Some(prev) if *prev != p.identity() => {
                return Err(NoticeError::AmbiguousVendorDir {
                    name: p.name.clone(),
                    version: p.version.clone(),
                });
            }
            _ => {
                by_dir.insert(dir, p.identity());
            }
        }
    }
    Ok(packages)
}

/// The sorted-unique first-party (source-less) package names.
fn first_party_names(packages: &[LockPackage]) -> Vec<String> {
    let mut v: Vec<String> = packages
        .iter()
        .filter(|p| p.is_first_party())
        .map(|p| p.name.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Generate the per-candidate third-party notice manifest from the sealed lock + a vendored source
/// root, consulting the owner-ratified per-family notice `map` for crates that ship no license file.
/// Fails closed on any uncollectable-and-unmapped / SPDX-mismatched / ambiguous / duplicate package.
#[allow(clippy::too_many_arguments)]
pub fn generate(
    candidate: &str,
    arch: &str,
    lock_blake3_hex: &str,
    lock: &str,
    vendor_root: &Path,
    map: Option<&RatifiedNoticeMap>,
    closure: Option<&TargetClosure>,
) -> Result<ThirdPartyNotices, NoticeError> {
    if !super::is_hex64(lock_blake3_hex) {
        return Err(NoticeError::BadHash("lock_blake3_hex"));
    }
    let packages = sorted_unique_packages(lock)?;
    let first_party = first_party_names(&packages);
    // Full-identity redistributed set recomputed from the sealed closure (empty when unscoped).
    let redist_set = closure.map(|c| c.redistributed());
    let venue_targets: Vec<String> = closure.map(|c| c.venue_targets.clone()).unwrap_or_default();

    let mut entries = Vec::new();
    let mut used_map = false;
    let mut any_not_redistributed = false;
    for p in packages.iter().filter(|p| !p.is_first_party()) {
        // Target-scoping: a crate not in the normal-dependency closure for any venue target is not
        // redistributed by the produced artifact, so it carries no notice (records SPDX for audit).
        // Full package identity (name, version, source) — versions are never conflated.
        if let Some(redist) = &redist_set {
            let id = (
                p.name.clone(),
                p.version.clone(),
                p.source.clone().unwrap_or_default(),
            );
            if !redist.contains(&id) {
                let spdx = std::fs::read_to_string(
                    vendor_root.join(p.vendor_dir_name()).join("Cargo.toml"),
                )
                .ok()
                .map(|t| read_license_fields(&t).0.unwrap_or_default())
                .unwrap_or_default();
                any_not_redistributed = true;
                entries.push(NoticeEntry {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    source: p.source.clone().unwrap_or_default(),
                    checksum: p.checksum.clone(),
                    spdx,
                    notice_source: NoticeSource::NotRedistributed,
                    map_family: None,
                    notices: Vec::new(),
                });
                continue;
            }
        }
        let crate_dir = vendor_root.join(p.vendor_dir_name());
        if !crate_dir.is_dir() {
            return Err(NoticeError::MissingSource {
                name: p.name.clone(),
                version: p.version.clone(),
            });
        }
        let (spdx, notices) = collect_crate_notices(p, &crate_dir)?;
        let (notice_source, map_family, notices) = if !notices.is_empty() {
            (NoticeSource::CrateFile, None, notices)
        } else {
            // The crate ships no license file: consult the ratified map (fail closed if uncovered).
            let fam = map.and_then(|m| m.family_for(&p.name)).ok_or_else(|| {
                NoticeError::UncoveredByMap {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    spdx: if spdx.is_empty() {
                        "<none>".into()
                    } else {
                        spdx.clone()
                    },
                }
            })?;
            // A canonical (attested) family may be used ONLY when the owner has individually approved it.
            if !fam.is_usable() {
                return Err(NoticeError::CanonicalNotApproved {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    family: fam.id.clone(),
                });
            }
            if fam.spdx != spdx {
                return Err(NoticeError::MapSpdxMismatch {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    declared: spdx.clone(),
                    family: fam.id.clone(),
                    family_spdx: fam.spdx.clone(),
                });
            }
            // Step 2: a FETCHED-UPSTREAM family binds an EXACT (name, version, source) package
            // identity + the published archive checksum. It is NEVER a wildcard: it applies ONLY to
            // that one exact package. A different version/source, or a same-name package with a
            // different checksum, fails closed here (the family does not cover it).
            if let Some(fu) = &fam.fetched_upstream {
                let src = p.source.as_deref().unwrap_or("");
                let ck = p.checksum.as_deref().unwrap_or("");
                if fu.crate_name != p.name
                    || fu.crate_version != p.version
                    || fu.crate_source != src
                    || fu.published_crate_sha256 != ck
                {
                    return Err(NoticeError::FetchedUpstreamIdentityMismatch {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        family: fam.id.clone(),
                        detail: format!(
                            "family binds ({}, {}, {}) checksum {}; package is ({}, {}, {}) checksum {}",
                            fu.crate_name,
                            fu.crate_version,
                            fu.crate_source,
                            fu.published_crate_sha256,
                            p.name,
                            p.version,
                            src,
                            ck
                        ),
                    });
                }
            }
            used_map = true;
            (
                NoticeSource::RatifiedMap,
                Some(fam.id.clone()),
                fam.notices.clone(),
            )
        };
        entries.push(NoticeEntry {
            name: p.name.clone(),
            version: p.version.clone(),
            source: p.source.clone().unwrap_or_default(),
            checksum: p.checksum.clone(),
            spdx,
            notice_source,
            map_family,
            notices,
        });
    }
    // `packages` is already sorted by identity, so `entries` is too.
    Ok(ThirdPartyNotices {
        schema_version: NOTICES_SCHEMA_VERSION,
        candidate: candidate.to_string(),
        arch: arch.to_string(),
        lock_blake3_hex: lock_blake3_hex.to_string(),
        first_party,
        ratified_map_version: if used_map {
            map.map(|m| m.policy_version.clone())
        } else {
            None
        },
        // Record the scope targets whenever a closure was applied (even if nothing was excluded),
        // so the sealed manifest always matches the sealed closure it is verified against.
        venue_targets: if closure.is_some() {
            venue_targets.clone()
        } else {
            let _ = any_not_redistributed;
            Vec::new()
        },
        entries,
    })
}

impl NoticeEntry {
    fn identity(&self) -> (&str, &str, &str) {
        (
            self.name.as_str(),
            self.version.as_str(),
            self.source.as_str(),
        )
    }
}

impl ThirdPartyNotices {
    /// The domain-separated content hash of the canonical JSON (bare 64-hex BLAKE3).
    pub fn content_blake3(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("serialize notices");
        let mut h = blake3::Hasher::new();
        h.update(NOTICES_TAG.as_bytes());
        h.update(&[0u8]);
        h.update(&canonical);
        super::to_hex(h.finalize().as_bytes())
    }

    /// Verify this manifest is well-formed, bound to `lock`, and COVERS EXACTLY the lock's
    /// third-party set (by FULL identity) with its first-party set recomputed and matched — no
    /// missing, extra, duplicate, unsorted, checksum-mismatched, empty, or text-vs-SHA-mismatched
    /// record (fail closed).
    pub fn verify_against_lock(
        &self,
        lock_blake3_hex: &str,
        lock: &str,
    ) -> Result<(), NoticeError> {
        if self.schema_version != NOTICES_SCHEMA_VERSION {
            return Err(NoticeError::Mismatch(format!(
                "schema_version {}",
                self.schema_version
            )));
        }
        if !super::is_hex64(&self.lock_blake3_hex) {
            return Err(NoticeError::BadHash("lock_blake3_hex"));
        }
        if self.lock_blake3_hex != lock_blake3_hex {
            return Err(NoticeError::Mismatch(
                "lock_blake3_hex not bound to this lock".into(),
            ));
        }

        let packages = sorted_unique_packages(lock)?;

        // Expected third-party identities -> checksum, from the lock.
        let expected: BTreeMap<(&str, &str, &str), Option<&str>> = packages
            .iter()
            .filter(|p| !p.is_first_party())
            .map(|p| (p.identity(), p.checksum.as_deref()))
            .collect();

        // First-party set must match exactly (recomputed, not trusted).
        if self.first_party != first_party_names(&packages) {
            return Err(NoticeError::Mismatch(
                "first_party set does not match the lock's path packages".into(),
            ));
        }

        // Manifest entries: unique, sorted, fully-identified, checksum-bound, non-empty, hash-true.
        let mut seen: std::collections::BTreeSet<(&str, &str, &str)> =
            std::collections::BTreeSet::new();
        let mut prev: Option<(&str, &str, &str)> = None;
        let mut any_map = false;
        let mut any_not_redistributed = false;
        for e in &self.entries {
            let id = e.identity();
            if let Some(pv) = prev {
                if pv >= id {
                    return Err(NoticeError::Mismatch(format!(
                        "entries not strictly sorted at {} {} [{}]",
                        e.name, e.version, e.source
                    )));
                }
            }
            prev = Some(id);
            if !seen.insert(id) {
                return Err(NoticeError::Mismatch(format!(
                    "duplicate entry {} {} [{}]",
                    e.name, e.version, e.source
                )));
            }
            match expected.get(&id) {
                None => {
                    return Err(NoticeError::Mismatch(format!(
                        "extra notice entry {} {} [{}] not in lock",
                        e.name, e.version, e.source
                    )))
                }
                Some(expected_ck) => {
                    if e.checksum.as_deref() != *expected_ck {
                        return Err(NoticeError::Mismatch(format!(
                            "checksum mismatch for {} {} [{}]",
                            e.name, e.version, e.source
                        )));
                    }
                }
            }
            // Provenance self-consistency per source.
            match e.notice_source {
                NoticeSource::CrateFile => {
                    if e.map_family.is_some() {
                        return Err(NoticeError::Mismatch(format!(
                            "crate-file entry {} {} carries a map_family",
                            e.name, e.version
                        )));
                    }
                }
                NoticeSource::RatifiedMap => {
                    if e.map_family.as_deref().map(str::is_empty).unwrap_or(true) {
                        return Err(NoticeError::Mismatch(format!(
                            "ratified-map entry {} {} missing map_family",
                            e.name, e.version
                        )));
                    }
                    any_map = true;
                }
                NoticeSource::NotRedistributed => {
                    if e.map_family.is_some() {
                        return Err(NoticeError::Mismatch(format!(
                            "not-redistributed entry {} {} carries a map_family",
                            e.name, e.version
                        )));
                    }
                    if !e.notices.is_empty() {
                        return Err(NoticeError::Mismatch(format!(
                            "not-redistributed entry {} {} carries notices",
                            e.name, e.version
                        )));
                    }
                    any_not_redistributed = true;
                }
            }
            // Redistributed entries (crate-file / ratified-map) must carry non-empty, hash-true,
            // strictly-sorted notices; not-redistributed entries carry none (checked above).
            if e.notice_source != NoticeSource::NotRedistributed {
                if e.notices.is_empty() {
                    return Err(NoticeError::Mismatch(format!(
                        "empty notice set for {} {} [{}]",
                        e.name, e.version, e.source
                    )));
                }
                let mut prev_path: Option<&str> = None;
                for nf in &e.notices {
                    if let Some(pp) = prev_path {
                        if pp >= nf.path.as_str() {
                            return Err(NoticeError::Mismatch(format!(
                                "notice paths not strictly sorted/unique for {} {}: {}",
                                e.name, e.version, nf.path
                            )));
                        }
                    }
                    prev_path = Some(nf.path.as_str());
                    if nf.sha256 != sha256_hex(nf.text.as_bytes()) {
                        return Err(NoticeError::Mismatch(format!(
                            "notice text/sha mismatch for {} {} file {}",
                            e.name, e.version, nf.path
                        )));
                    }
                }
            }
        }
        // Every expected third-party identity must be covered.
        for id in expected.keys() {
            if !seen.contains(id) {
                return Err(NoticeError::Mismatch(format!(
                    "missing notice entry {} {} [{}]",
                    id.0, id.1, id.2
                )));
            }
        }
        // `ratified_map_version` presence must match whether any entry is map-sourced.
        let has_version = self
            .ratified_map_version
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if any_map != has_version {
            return Err(NoticeError::Mismatch(
                "ratified_map_version presence does not match map-sourced entries".into(),
            ));
        }
        // Any not-redistributed entry requires the venue_targets it was scoped against.
        if any_not_redistributed && self.venue_targets.is_empty() {
            return Err(NoticeError::Mismatch(
                "not-redistributed entries present but venue_targets is empty".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "b0pre-notices-{}-{}-{}",
            tag,
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    fn vendor_crate(
        root: &Path,
        name: &str,
        version: &str,
        cargo_toml: &str,
        files: &[(&str, &str)],
    ) {
        let d = root.join(format!("{name}-{version}"));
        std::fs::create_dir_all(&d).unwrap();
        write(&d, "Cargo.toml", cargo_toml);
        for (f, body) in files {
            let p = d.join(f);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, body).unwrap();
        }
    }

    const REG: &str = "registry+https://github.com/rust-lang/crates.io-index";

    const LOCK: &str = r#"
[[package]]
name = "b0-pre-candidate-risc0-guest"
version = "0.0.0"

[[package]]
name = "mit-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "dual-crate"
version = "2.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"
"#;

    fn setup_vendor(tag: &str) -> (PathBuf, String) {
        let root = tmp(tag);
        vendor_crate(
            &root,
            "mit-crate",
            "1.0.0",
            "[package]\nname = \"mit-crate\"\nlicense = \"MIT\"\n",
            &[("LICENSE.md", "MIT License\nCopyright (c) 2020 Someone\n")],
        );
        vendor_crate(
            &root,
            "dual-crate",
            "2.1.0",
            "[package]\nname = \"dual-crate\"\nlicense = \"MIT OR Apache-2.0\"\n",
            &[
                ("LICENSE-MIT", "MIT ...\nCopyright (c) 2021 Dual\n"),
                ("LICENSE-APACHE", "Apache License 2.0 ...\n"),
            ],
        );
        (root, "cd".repeat(32))
    }

    #[test]
    fn generates_full_third_party_coverage_and_skips_first_party() {
        let (root, lh) = setup_vendor("cov");
        let n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).expect("generate");
        assert_eq!(n.first_party, vec!["b0-pre-candidate-risc0-guest"]);
        assert_eq!(n.entries.len(), 2);
        let dual = n.entries.iter().find(|e| e.name == "dual-crate").unwrap();
        assert_eq!(dual.notices.len(), 2); // both LICENSE-MIT and LICENSE-APACHE captured
        assert_eq!(dual.source, REG);
        assert_eq!(dual.checksum.as_deref(), Some("bbbb"));
        // notice paths preserved + sorted
        assert_eq!(dual.notices[0].path, "LICENSE-APACHE");
        assert_eq!(dual.notices[1].path, "LICENSE-MIT");
        n.verify_against_lock(&lh, LOCK).expect("verify");
    }

    #[test]
    fn uncollectable_license_fails_closed() {
        let root = tmp("uncollectable");
        vendor_crate(
            &root,
            "mit-crate",
            "1.0.0",
            "[package]\nname = \"mit-crate\"\nlicense = \"MIT\"\n",
            &[("src.rs", "// code")],
        );
        vendor_crate(
            &root,
            "dual-crate",
            "2.1.0",
            "[package]\nname=\"dual-crate\"\nlicense=\"MIT\"\n",
            &[("LICENSE", "x")],
        );
        // no license file + no ratified map covering it -> fail closed
        assert!(matches!(
            generate("Risc0", "X86_64", &"cd".repeat(32), LOCK, &root, None, None),
            Err(NoticeError::UncoveredByMap { .. })
        ));
    }

    #[test]
    fn fetched_upstream_family_matches_exact_identity_and_rejects_others() {
        let commit = "4a8cdb44891ed57b8ff5a023b6bec7137c48708f";
        let ck = "10d60334b3b2e7c9d91ef8150abfb6fa4c1c39ebbcf4a81c2e346aad939fee3e";
        let mit = "MIT License text\n";
        let apache = "Apache-2.0 License text\n";
        let map_json = serde_json::json!({
            "policy_version": "t",
            "families": [{
                "id": "knurling-defmt-parser",
                "spdx": "MIT OR Apache-2.0",
                "upstream_provenance": format!("https://github.com/knurling-rs/defmt @ {commit}"),
                "covers": ["defmt-parser"],
                "notices": [
                    {"path": "LICENSE-APACHE", "sha256": sha256_hex(apache.as_bytes()), "text": apache},
                    {"path": "LICENSE-MIT", "sha256": sha256_hex(mit.as_bytes()), "text": mit},
                ],
                "fetched_upstream": {
                    "crate_name": "defmt-parser", "crate_version": "1.0.0", "crate_source": REG,
                    "published_crate_sha256": ck, "published_license_files_absent": true,
                    "repository": "https://github.com/knurling-rs/defmt",
                    "commit": commit, "commit_authority": ".cargo_vcs_info.json",
                },
            }],
        })
        .to_string();
        let map = RatifiedNoticeMap::load(&map_json).expect("defmt map loads");
        let lh = "cd".repeat(32);
        let defmt_toml = "[package]\nname = \"defmt-parser\"\nlicense = \"MIT OR Apache-2.0\"\n";
        let lock = format!(
            "\n[[package]]\nname = \"b0-pre-candidate-risc0-guest\"\nversion = \"0.0.0\"\n\n\
             [[package]]\nname = \"defmt-parser\"\nversion = \"1.0.0\"\nsource = \"{REG}\"\n\
             checksum = \"{ck}\"\n"
        );

        // EXACT (name, version, source, checksum) -> resolves through the fetched-upstream family.
        let root = tmp("defmt-ok");
        vendor_crate(
            &root,
            "defmt-parser",
            "1.0.0",
            defmt_toml,
            &[("src/lib.rs", "// no license")],
        );
        let n = generate("Risc0", "X86_64", &lh, &lock, &root, Some(&map), None).expect("generate");
        let e = n
            .entries
            .iter()
            .find(|e| e.name == "defmt-parser")
            .expect("defmt-parser entry");
        assert_eq!(e.map_family.as_deref(), Some("knurling-defmt-parser"));
        assert_eq!(e.notices.len(), 2);

        // WRONG VERSION (same name+source) -> the family is NOT a wildcard -> fail closed.
        let lock_v2 = lock.replace("version = \"1.0.0\"", "version = \"2.0.0\"");
        let root2 = tmp("defmt-v2");
        vendor_crate(
            &root2,
            "defmt-parser",
            "2.0.0",
            defmt_toml,
            &[("src/lib.rs", "// no license")],
        );
        assert!(matches!(
            generate("Risc0", "X86_64", &lh, &lock_v2, &root2, Some(&map), None),
            Err(NoticeError::FetchedUpstreamIdentityMismatch { .. })
        ));

        // WRONG CHECKSUM (same name/version/source, e.g. a same-name substitute) -> fail closed.
        let lock_ck = lock.replace(ck, &"0".repeat(64));
        assert!(matches!(
            generate("Risc0", "X86_64", &lh, &lock_ck, &root, Some(&map), None),
            Err(NoticeError::FetchedUpstreamIdentityMismatch { .. })
        ));
    }

    #[test]
    fn verify_rejects_missing_extra_altered_and_source_swap() {
        let (root, lh) = setup_vendor("altered");
        let mut n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).unwrap();
        assert!(n.verify_against_lock(&"ab".repeat(32), LOCK).is_err()); // wrong lock binding
                                                                         // altered text without updating sha
        n.entries[0].notices[0].text.push_str("TAMPER");
        assert!(matches!(
            n.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
        // source swap: same name+version, different source -> extra/mismatch
        let (root2, lh2) = setup_vendor("swap");
        let mut n2 = generate("Risc0", "X86_64", &lh2, LOCK, &root2, None, None).unwrap();
        n2.entries[0].source = "git+https://example.invalid/x".into();
        assert!(matches!(
            n2.verify_against_lock(&lh2, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
        // extra entry not in lock
        let (root3, lh3) = setup_vendor("extra");
        let mut n3 = generate("Risc0", "X86_64", &lh3, LOCK, &root3, None, None).unwrap();
        n3.entries.push(NoticeEntry {
            name: "ghost".into(),
            version: "9.9.9".into(),
            source: REG.into(),
            checksum: Some("ffff".into()),
            spdx: "MIT".into(),
            notice_source: NoticeSource::CrateFile,
            map_family: None,
            notices: vec![NoticeFile {
                path: "LICENSE".into(),
                sha256: sha256_hex(b"x"),
                text: "x".into(),
            }],
        });
        assert!(matches!(
            n3.verify_against_lock(&lh3, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
    }

    #[test]
    fn verify_rejects_checksum_swap_and_duplicate_and_unsorted() {
        let (root, lh) = setup_vendor("ck");
        // checksum swap
        let mut n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).unwrap();
        n.entries[0].checksum = Some("dead".into());
        assert!(matches!(
            n.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
        // duplicate entry
        let mut n2 = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).unwrap();
        let dup = n2.entries[0].clone();
        n2.entries.push(dup);
        assert!(matches!(
            n2.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
        // unsorted entries
        let mut n3 = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).unwrap();
        n3.entries.reverse();
        assert!(matches!(
            n3.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
    }

    #[test]
    fn verify_rejects_first_party_tampering() {
        let (root, lh) = setup_vendor("fp");
        let mut n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).unwrap();
        n.first_party.push("smuggled".into());
        assert!(matches!(
            n.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
        // dropping the real first-party entry also fails
        let mut n2 = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).unwrap();
        n2.first_party.clear();
        assert!(matches!(
            n2.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
    }

    #[test]
    fn missing_vendor_source_fails_closed() {
        let root = tmp("missing-src");
        vendor_crate(
            &root,
            "mit-crate",
            "1.0.0",
            "[package]\nname=\"mit-crate\"\nlicense=\"MIT\"\n",
            &[("LICENSE", "x")],
        );
        // dual-crate source absent
        assert!(matches!(
            generate("Risc0", "X86_64", &"cd".repeat(32), LOCK, &root, None, None),
            Err(NoticeError::MissingSource { .. })
        ));
    }

    #[test]
    fn absolute_and_traversal_license_file_are_rejected() {
        for bad in ["/etc/passwd", "../escape", "../../x", "sub/../../x"] {
            let root = tmp("licfile-escape");
            vendor_crate(
                &root,
                "mit-crate",
                "1.0.0",
                &format!("[package]\nname=\"mit-crate\"\nlicense-file=\"{bad}\"\n"),
                &[("placeholder", "x")],
            );
            vendor_crate(
                &root,
                "dual-crate",
                "2.1.0",
                "[package]\nname=\"dual-crate\"\nlicense=\"MIT\"\n",
                &[("LICENSE", "x")],
            );
            let e = generate("Risc0", "X86_64", &"cd".repeat(32), LOCK, &root, None, None);
            assert!(
                matches!(e, Err(NoticeError::BadNoticeFile { .. })),
                "expected reject for license-file {bad:?}, got {e:?}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn symlink_license_file_and_notice_are_rejected() {
        use std::os::unix::fs::symlink;
        // symlinked license-file target
        let root = tmp("symlink-licfile");
        let cd = root.join("mit-crate-1.0.0");
        std::fs::create_dir_all(&cd).unwrap();
        write(
            &cd,
            "Cargo.toml",
            "[package]\nname=\"mit-crate\"\nlicense-file=\"LINK\"\n",
        );
        symlink("/etc/passwd", cd.join("LINK")).unwrap();
        vendor_crate(
            &root,
            "dual-crate",
            "2.1.0",
            "[package]\nname=\"dual-crate\"\nlicense=\"MIT\"\n",
            &[("LICENSE", "x")],
        );
        assert!(matches!(
            generate("Risc0", "X86_64", &"cd".repeat(32), LOCK, &root, None, None),
            Err(NoticeError::BadNoticeFile { .. })
        ));

        // symlinked notice-named entry in the crate root
        let root2 = tmp("symlink-notice");
        let cd2 = root2.join("mit-crate-1.0.0");
        std::fs::create_dir_all(&cd2).unwrap();
        write(
            &cd2,
            "Cargo.toml",
            "[package]\nname=\"mit-crate\"\nlicense=\"MIT\"\n",
        );
        symlink("/etc/hosts", cd2.join("LICENSE")).unwrap();
        vendor_crate(
            &root2,
            "dual-crate",
            "2.1.0",
            "[package]\nname=\"dual-crate\"\nlicense=\"MIT\"\n",
            &[("LICENSE", "x")],
        );
        assert!(matches!(
            generate(
                "Risc0",
                "X86_64",
                &"cd".repeat(32),
                LOCK,
                &root2,
                None,
                None
            ),
            Err(NoticeError::BadNoticeFile { .. })
        ));
    }

    #[test]
    fn subdir_license_file_is_collected_with_relative_path() {
        let root = tmp("subdir-licfile");
        vendor_crate(
            &root,
            "mit-crate",
            "1.0.0",
            "[package]\nname=\"mit-crate\"\nlicense-file=\"licenses/COPYING\"\n",
            &[("licenses/COPYING", "custom license text")],
        );
        vendor_crate(
            &root,
            "dual-crate",
            "2.1.0",
            "[package]\nname=\"dual-crate\"\nlicense=\"MIT\"\n",
            &[("LICENSE", "x")],
        );
        let n = generate("Risc0", "X86_64", &"cd".repeat(32), LOCK, &root, None, None).unwrap();
        let mc = n.entries.iter().find(|e| e.name == "mit-crate").unwrap();
        assert_eq!(mc.notices[0].path, "licenses/COPYING");
    }

    #[test]
    #[cfg(unix)]
    fn non_utf8_notice_fails_closed() {
        let root = tmp("nonutf8");
        let cd = root.join("mit-crate-1.0.0");
        std::fs::create_dir_all(&cd).unwrap();
        write(
            &cd,
            "Cargo.toml",
            "[package]\nname=\"mit-crate\"\nlicense=\"MIT\"\n",
        );
        std::fs::write(cd.join("LICENSE"), [0xff, 0xfe, 0x00, 0x9f]).unwrap();
        vendor_crate(
            &root,
            "dual-crate",
            "2.1.0",
            "[package]\nname=\"dual-crate\"\nlicense=\"MIT\"\n",
            &[("LICENSE", "x")],
        );
        assert!(matches!(
            generate("Risc0", "X86_64", &"cd".repeat(32), LOCK, &root, None, None),
            Err(NoticeError::BadNoticeFile { .. })
        ));
    }

    #[test]
    fn duplicate_lock_identity_and_ambiguous_vendor_dir_fail_closed() {
        // duplicate FULL identity in the lock
        let dup_lock = format!(
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"{REG}\"\nchecksum = \"11\"\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"{REG}\"\nchecksum = \"11\"\n"
        );
        let root = tmp("duplock");
        vendor_crate(
            &root,
            "a",
            "1.0.0",
            "[package]\nname=\"a\"\nlicense=\"MIT\"\n",
            &[("LICENSE", "x")],
        );
        assert!(matches!(
            generate(
                "Sp1",
                "X86_64",
                &"cd".repeat(32),
                &dup_lock,
                &root,
                None,
                None
            ),
            Err(NoticeError::DuplicatePackage { .. })
        ));

        // two DISTINCT sources -> one vendor dir
        let amb_lock = format!(
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"{REG}\"\nchecksum = \"11\"\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = \"git+https://example.invalid/a\"\n"
        );
        assert!(matches!(
            generate(
                "Sp1",
                "X86_64",
                &"cd".repeat(32),
                &amb_lock,
                &root,
                None,
                None
            ),
            Err(NoticeError::AmbiguousVendorDir { .. })
        ));
    }

    fn sample_map() -> RatifiedNoticeMap {
        let text = "Custom upstream MIT text\nCopyright (c) 2024 Upstream\n";
        let map = serde_json::json!({
            "policy_version": "2026-08-04.test",
            "note": "test map",
            "families": [{
                "id": "fam-mit",
                "spdx": "MIT",
                "upstream_provenance": "https://example.invalid/repo @ deadbeef LICENSE",
                "covers": ["nolicense-crate"],
                "notices": [{"path": "LICENSE-MIT", "sha256": sha256_hex(text.as_bytes()), "text": text}],
            }],
        });
        RatifiedNoticeMap::load(&map.to_string()).expect("map loads")
    }

    const LOCK_NOFILE: &str = r#"
[[package]]
name = "first-party-guest"
version = "0.0.0"

[[package]]
name = "nolicense-crate"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeee"
"#;

    #[test]
    fn ratified_map_supplies_notices_for_no_file_crate() {
        let root = tmp("map-hit");
        // crate declares MIT but ships NO license file
        vendor_crate(
            &root,
            "nolicense-crate",
            "3.0.0",
            "[package]\nname=\"nolicense-crate\"\nlicense=\"MIT\"\n",
            &[("src.rs", "// code")],
        );
        let map = sample_map();
        let n = generate(
            "Sp1",
            "X86_64",
            &"cd".repeat(32),
            LOCK_NOFILE,
            &root,
            Some(&map),
            None,
        )
        .unwrap();
        assert_eq!(n.entries.len(), 1);
        let e = &n.entries[0];
        assert_eq!(e.notice_source, NoticeSource::RatifiedMap);
        assert_eq!(e.map_family.as_deref(), Some("fam-mit"));
        assert_eq!(e.notices[0].path, "LICENSE-MIT");
        assert_eq!(n.ratified_map_version.as_deref(), Some("2026-08-04.test"));
        n.verify_against_lock(&"cd".repeat(32), LOCK_NOFILE)
            .expect("verify");
    }

    #[test]
    fn no_file_crate_without_map_or_coverage_fails_closed() {
        let root = tmp("map-miss");
        vendor_crate(
            &root,
            "nolicense-crate",
            "3.0.0",
            "[package]\nname=\"nolicense-crate\"\nlicense=\"MIT\"\n",
            &[("src.rs", "// code")],
        );
        // no map at all -> uncovered
        assert!(matches!(
            generate(
                "Sp1",
                "X86_64",
                &"cd".repeat(32),
                LOCK_NOFILE,
                &root,
                None,
                None
            ),
            Err(NoticeError::UncoveredByMap { .. })
        ));
        // a map that does not cover this crate -> uncovered
        let other = serde_json::json!({
            "policy_version":"v","families":[{"id":"x","spdx":"MIT","upstream_provenance":"p",
            "covers":["someone-else"],"notices":[{"path":"L","sha256":sha256_hex(b"t"),"text":"t"}]}]
        });
        let m = RatifiedNoticeMap::load(&other.to_string()).unwrap();
        assert!(matches!(
            generate(
                "Sp1",
                "X86_64",
                &"cd".repeat(32),
                LOCK_NOFILE,
                &root,
                Some(&m),
                None,
            ),
            Err(NoticeError::UncoveredByMap { .. })
        ));
    }

    #[test]
    fn map_spdx_mismatch_fails_closed() {
        let root = tmp("map-spdx");
        vendor_crate(
            &root,
            "nolicense-crate",
            "3.0.0",
            "[package]\nname=\"nolicense-crate\"\nlicense=\"Apache-2.0\"\n", // declares Apache, family is MIT
            &[("src.rs", "// code")],
        );
        let map = sample_map();
        assert!(matches!(
            generate(
                "Sp1",
                "X86_64",
                &"cd".repeat(32),
                LOCK_NOFILE,
                &root,
                Some(&map),
                None,
            ),
            Err(NoticeError::MapSpdxMismatch { .. })
        ));
    }

    #[test]
    fn map_loader_rejects_bad_sha_dup_family_and_dup_coverage() {
        // bad text sha
        let bad = serde_json::json!({"policy_version":"v","families":[{"id":"a","spdx":"MIT",
            "upstream_provenance":"p","covers":["c"],"notices":[{"path":"L","sha256":"00","text":"t"}]}]});
        assert!(matches!(
            RatifiedNoticeMap::load(&bad.to_string()),
            Err(NoticeError::BadMap(_))
        ));
        // duplicate family id
        let dupid = serde_json::json!({"policy_version":"v","families":[
            {"id":"a","spdx":"MIT","upstream_provenance":"p","covers":["c"],"notices":[{"path":"L","sha256":sha256_hex(b"t"),"text":"t"}]},
            {"id":"a","spdx":"MIT","upstream_provenance":"p","covers":["d"],"notices":[{"path":"L","sha256":sha256_hex(b"t"),"text":"t"}]}]});
        assert!(matches!(
            RatifiedNoticeMap::load(&dupid.to_string()),
            Err(NoticeError::BadMap(_))
        ));
        // crate covered by two families
        let dupcov = serde_json::json!({"policy_version":"v","families":[
            {"id":"a","spdx":"MIT","upstream_provenance":"p","covers":["c"],"notices":[{"path":"L","sha256":sha256_hex(b"t"),"text":"t"}]},
            {"id":"b","spdx":"MIT","upstream_provenance":"p","covers":["c"],"notices":[{"path":"L","sha256":sha256_hex(b"t"),"text":"t"}]}]});
        assert!(matches!(
            RatifiedNoticeMap::load(&dupcov.to_string()),
            Err(NoticeError::BadMap(_))
        ));
    }

    fn canonical_map(approved: bool) -> RatifiedNoticeMap {
        let body = "MIT License\n\nStandard MIT body without a synthesized copyright.\n";
        let s = sha256_hex(body.as_bytes());
        let map = serde_json::json!({
            "policy_version": "2026-08-04.canon",
            "families": [{
                "id": "canon-nolicense",
                "spdx": "MIT",
                "upstream_provenance": "CANONICAL SPDX text (upstream ships no license file)",
                "covers": ["nolicense-crate"],
                "notices": [{"path": "LICENSE-MIT.canonical", "sha256": s, "text": body}],
                "attestation": {
                    "kind": "mit-risk-acceptance",
                    "search_log": "checked published tag v3.0.0 @abc123, repository history, parent workspace, README, source headers, crates.io — no license text found",
                    "repository": "https://example.invalid/nolicense",
                    "repository_commit": "abc123",
                    "declared_spdx": "MIT",
                    "metadata_authors": ["Someone <a@b.invalid>"],
                    "crates_io_owners": ["someone"],
                    "canonical_spdx_ids": ["MIT"],
                    "canonical_text_sha256": [s],
                    "risk_acceptance": "un-removable transitive dep; MIT declared, no upstream copyright notice; risk accepted.",
                    "owner_approved": approved,
                },
            }],
        });
        RatifiedNoticeMap::load(&map.to_string()).expect("canonical map loads")
    }

    #[test]
    fn canonical_family_requires_individual_owner_approval() {
        let root = tmp("canon");
        vendor_crate(
            &root,
            "nolicense-crate",
            "3.0.0",
            "[package]\nname=\"nolicense-crate\"\nlicense=\"MIT\"\n",
            &[("src.rs", "// code")],
        );
        // unapproved canonical family -> fail closed
        let unapproved = canonical_map(false);
        assert!(matches!(
            generate(
                "Sp1",
                "X86_64",
                &"cd".repeat(32),
                LOCK_NOFILE,
                &root,
                Some(&unapproved),
                None,
            ),
            Err(NoticeError::CanonicalNotApproved { .. })
        ));
        // approved -> generates, records ratified-map provenance
        let approved = canonical_map(true);
        let n = generate(
            "Sp1",
            "X86_64",
            &"cd".repeat(32),
            LOCK_NOFILE,
            &root,
            Some(&approved),
            None,
        )
        .unwrap();
        assert_eq!(n.entries[0].notice_source, NoticeSource::RatifiedMap);
        assert_eq!(n.entries[0].map_family.as_deref(), Some("canon-nolicense"));
        n.verify_against_lock(&"cd".repeat(32), LOCK_NOFILE)
            .unwrap();
        n.verify_map_sources(&approved).unwrap();
    }

    const S2G: &str = "ab"; // stage2 graph hash prefix (repeated in tests)

    // A closure over LOCK where dual-crate is a normal dep of the root (redistributed) and mit-crate
    // is NOT reached (not-redistributed).
    fn scope_closure(lh: &str) -> TargetClosure {
        let root = ClosureNode {
            name: "b0-pre-candidate-risc0-guest".into(),
            version: "0.0.0".into(),
            source: String::new(),
            checksum: None,
            normal_deps: vec![pkgid("dual-crate", "2.1.0", REG)],
        };
        let dual = ClosureNode {
            name: "dual-crate".into(),
            version: "2.1.0".into(),
            source: REG.into(),
            checksum: Some("bbbb".into()),
            normal_deps: vec![],
        };
        let mit = ClosureNode {
            name: "mit-crate".into(),
            version: "1.0.0".into(),
            source: REG.into(),
            checksum: Some("aaaa".into()),
            normal_deps: vec![],
        };
        TargetClosure {
            schema_version: TARGET_CLOSURE_SCHEMA_VERSION,
            candidate: "Risc0".into(),
            arch: "X86_64".into(),
            venue_targets: vec!["x86_64-unknown-linux-gnu".into()],
            features: vec![],
            lock_blake3_hex: lh.to_string(),
            stage2_graph_blake3_hex: S2G.repeat(32),
            roots: vec![pkgid("b0-pre-candidate-risc0-guest", "0.0.0", "")],
            nodes: vec![root, dual, mit],
        }
    }

    #[test]
    fn target_scoping_marks_out_of_closure_crate_not_redistributed() {
        let (root, lh) = setup_vendor("scope");
        let cl = scope_closure(&lh);
        let n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, Some(&cl)).unwrap();
        let mc = n.entries.iter().find(|e| e.name == "mit-crate").unwrap();
        assert_eq!(mc.notice_source, NoticeSource::NotRedistributed);
        assert!(mc.notices.is_empty());
        let dc = n.entries.iter().find(|e| e.name == "dual-crate").unwrap();
        assert_eq!(dc.notice_source, NoticeSource::CrateFile);
        assert_eq!(
            n.venue_targets,
            vec!["x86_64-unknown-linux-gnu".to_string()]
        );
        n.verify_against_lock(&lh, LOCK).unwrap();
        // the INDEPENDENT classification check against the recomputed closure passes
        n.verify_classification(&cl, LOCK, &lh, &S2G.repeat(32))
            .unwrap();
    }

    #[test]
    fn classification_check_is_fail_closed() {
        let (root, lh) = setup_vendor("cls");
        let cl = scope_closure(&lh);
        let n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, Some(&cl)).unwrap();
        let s2 = S2G.repeat(32);
        // (a) relabel a REDISTRIBUTED crate (dual-crate) as not-redistributed -> rejected
        let mut bad = n.clone();
        {
            let e = bad
                .entries
                .iter_mut()
                .find(|e| e.name == "dual-crate")
                .unwrap();
            e.notice_source = NoticeSource::NotRedistributed;
            e.notices.clear();
            e.map_family = None;
        }
        assert!(matches!(
            bad.verify_classification(&cl, LOCK, &lh, &s2),
            Err(NoticeError::ClassificationMismatch { .. })
        ));
        // (b) closure not bound to the lock -> rejected
        assert!(matches!(
            n.verify_classification(&cl, LOCK, &"ff".repeat(32), &s2),
            Err(NoticeError::BadClosure(_))
        ));
        // (c) stage2-graph drift -> rejected
        assert!(matches!(
            n.verify_classification(&cl, LOCK, &lh, &"cd".repeat(32)),
            Err(NoticeError::BadClosure(_))
        ));
        // (d) venue_targets drift -> rejected
        let mut cl2 = cl.clone();
        cl2.venue_targets = vec!["aarch64-unknown-linux-gnu".into()];
        assert!(matches!(
            n.verify_classification(&cl2, LOCK, &lh, &s2),
            Err(NoticeError::BadClosure(_))
        ));
        // (e) closure omits a locked third-party crate (drop mit-crate node) -> rejected
        let mut cl3 = cl.clone();
        cl3.nodes.retain(|nd| nd.name != "mit-crate");
        assert!(matches!(
            n.verify_classification(&cl3, LOCK, &lh, &s2),
            Err(NoticeError::BadClosure(_))
        ));
        // (f) same name, different version must not be conflated: a closure node with the wrong
        // version leaves the real identity uncovered -> rejected
        let mut cl4 = cl.clone();
        cl4.nodes
            .iter_mut()
            .find(|nd| nd.name == "mit-crate")
            .unwrap()
            .version = "9.9.9".into();
        assert!(matches!(
            n.verify_classification(&cl4, LOCK, &lh, &s2),
            Err(NoticeError::BadClosure(_))
        ));
    }

    #[test]
    fn not_redistributed_provenance_selfconsistency() {
        let (root, lh) = setup_vendor("nr");
        let cl = scope_closure(&lh);
        let n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, Some(&cl)).unwrap();
        // a not-redistributed entry may not carry notices
        let mut bad = n.clone();
        bad.entries
            .iter_mut()
            .find(|e| e.name == "mit-crate")
            .unwrap()
            .notices = vec![NoticeFile {
            path: "L".into(),
            sha256: sha256_hex(b"x"),
            text: "x".into(),
        }];
        assert!(matches!(
            bad.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
        // not-redistributed present but venue_targets emptied
        let mut bad2 = n.clone();
        bad2.venue_targets.clear();
        assert!(matches!(
            bad2.verify_against_lock(&lh, LOCK),
            Err(NoticeError::Mismatch(_))
        ));
    }

    #[test]
    fn loader_rejects_bad_attestation() {
        // canonical_text_sha256 not matching the notice sha
        let bad = serde_json::json!({
            "policy_version": "v",
            "families": [{
                "id": "c", "spdx": "MIT", "upstream_provenance": "CANONICAL",
                "covers": ["x"],
                "notices": [{"path": "L", "sha256": sha256_hex(b"real"), "text": "real"}],
                "attestation": {
                    "kind": "apache-or-branch",
                    "search_log": "searched", "repository": "r", "repository_commit": "c",
                    "declared_spdx": "MIT", "metadata_authors": [], "canonical_spdx_ids": ["MIT"],
                    "canonical_text_sha256": [sha256_hex(b"WRONG")], "owner_approved": true,
                },
            }],
        });
        assert!(matches!(
            RatifiedNoticeMap::load(&bad.to_string()),
            Err(NoticeError::BadMap(_))
        ));
    }

    #[test]
    fn verify_rejects_provenance_inconsistency() {
        let root = tmp("prov");
        vendor_crate(
            &root,
            "nolicense-crate",
            "3.0.0",
            "[package]\nname=\"nolicense-crate\"\nlicense=\"MIT\"\n",
            &[("src.rs", "// code")],
        );
        let map = sample_map();
        // crate-file entry must not carry a map_family
        let mut n = generate(
            "Sp1",
            "X86_64",
            &"cd".repeat(32),
            LOCK_NOFILE,
            &root,
            Some(&map),
            None,
        )
        .unwrap();
        n.entries[0].notice_source = NoticeSource::CrateFile;
        assert!(matches!(
            n.verify_against_lock(&"cd".repeat(32), LOCK_NOFILE),
            Err(NoticeError::Mismatch(_))
        ));
        // map-sourced entries require ratified_map_version
        let mut n2 = generate(
            "Sp1",
            "X86_64",
            &"cd".repeat(32),
            LOCK_NOFILE,
            &root,
            Some(&map),
            None,
        )
        .unwrap();
        n2.ratified_map_version = None;
        assert!(matches!(
            n2.verify_against_lock(&"cd".repeat(32), LOCK_NOFILE),
            Err(NoticeError::Mismatch(_))
        ));
    }

    #[test]
    fn content_hash_is_domain_separated_and_stable() {
        let (root, lh) = setup_vendor("hash-a");
        let n = generate("Risc0", "X86_64", &lh, LOCK, &root, None, None).unwrap();
        let h1 = n.content_blake3();
        assert!(super::super::is_hex64(&h1));
        let (root2, _) = setup_vendor("hash-b");
        let n2 = generate("Risc0", "X86_64", &lh, LOCK, &root2, None, None).unwrap();
        assert_eq!(h1, n2.content_blake3());
    }
}

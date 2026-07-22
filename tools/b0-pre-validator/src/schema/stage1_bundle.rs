//! Strict, versioned Stage-1 result bundle (`b0-pre-stage1-result-bundle-v1`).
//!
//! This is the machine-readable bundle `run_authoritative.sh` emits after
//! resolving the three B0-PRE Stage-1 categories inside the pinned container
//! venue, and that this validator re-checks INDEPENDENTLY before any insertion.
//! Acceptance is all-or-nothing: `run_authoritative.sh` Stage 6-7 invokes the
//! `stage1-ingest` binary ([`build_finalizable_artifact`]) as the SINGLE
//! insertion gate (there is no loose host-side JSON parsing). Every category
//! array must be present, non-empty, exactly complete, `all_reproducible ===
//! true`, and carry NO guest-closure field anywhere. A single failure keeps the
//! artifact `not_finalizable`.
//!
//! Every object forbids unknown members (`deny_unknown_fields` /
//! `additionalProperties:false`). Guest closure (`r0_guest_set_hash`,
//! `guest_program_identities`, `guest_program_id`, `populated_allowlist`) is
//! post-spec-hash and MUST NOT appear; the exact reject-list from
//! `run_authoritative.sh` is enforced both structurally (unknown-field rejection)
//! and by a raw-text scan identical to the shell guard.
//!
//! The verifier-material manifests carry their raw entries; identity is derived
//! ONLY by feeding them through the canonical
//! [`VerifierMaterialManifestV1`](super::verifier_material::VerifierMaterialManifestV1)
//! constructor/encoder — `manifest_hash_hex` must equal
//! `BLAKE3(VerifierMaterialManifestV1::encode())`, and the per-candidate
//! `total_bytes` must equal that candidate's own Σ `byte_len`. An ad-hoc
//! extractor hash can never stand in for the canonical identity.

use std::collections::BTreeSet;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::codec::DecodeError;
use crate::enums::{Candidate, VerifierMaterialRole};
use crate::protocol::{
    B0PreProtocolV1, ContainerDigest, LockHash, PendingInputs, VerifierMaterialManifestRef,
    ARCH_NAMES, CANDIDATE_NAMES, CONTAINER_ROLES,
};
use crate::schema::verifier_material::{VerifierMaterialEntry, VerifierMaterialManifestV1};
use crate::tags;

/// The frozen bundle kind + schema version.
pub const BUNDLE_KIND: &str = "b0-pre-stage1-result-bundle-v1";
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// The unmistakable synthetic sentinel every TEST_ONLY / NON_SELECTION tool
/// identity MUST carry (in both `artifact_identity` and `install_entrypoint`), so
/// synthetic tool metadata can never be mistaken for — or substituted as —
/// real venue-selected installer evidence. Authoritative validation REJECTS any
/// tool identity carrying it; TEST_ONLY validation REQUIRES it.
pub const TEST_ONLY_TOOL_SENTINEL: &str = "TEST_ONLY_SYNTHETIC";

/// The checksum algorithms an authoritative tool-identity may name, paired with
/// the exact lowercase-hex length their digest must occupy. A checksum whose hex
/// length disagrees with its named algorithm is rejected (no truncation, no
/// over-long value).
const ALLOWED_CHECKSUM_ALGOS: &[(&str, usize)] = &[
    ("sha256", 64),
    ("sha384", 96),
    ("sha512", 128),
    ("blake3", 64),
];

/// The Stage-1 bundle classification, bound into the schema and REQUIRED. Only
/// `AUTHORITATIVE_STAGE1` may reach `stage1-ingest` / `build_finalizable_artifact`;
/// `TEST_ONLY` and `NON_SELECTION` are rejected there (they carry synthetic tool
/// identities and never resolve the real Stage-1 categories). There is no
/// shippable command that mints an `AUTHORITATIVE_STAGE1` bundle from synthetic
/// data.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq, Debug)]
pub enum BundleClassification {
    #[serde(rename = "AUTHORITATIVE_STAGE1")]
    AuthoritativeStage1,
    #[serde(rename = "TEST_ONLY")]
    TestOnly,
    #[serde(rename = "NON_SELECTION")]
    NonSelection,
}

impl BundleClassification {
    /// Only the authoritative classification may build a finalizable artifact.
    pub fn is_authoritative(self) -> bool {
        matches!(self, BundleClassification::AuthoritativeStage1)
    }

    fn as_str(self) -> &'static str {
        match self {
            BundleClassification::AuthoritativeStage1 => "AUTHORITATIVE_STAGE1",
            BundleClassification::TestOnly => "TEST_ONLY",
            BundleClassification::NonSelection => "NON_SELECTION",
        }
    }
}

/// Guest-closure field names that are post-spec-hash and must never appear in a
/// Stage-1 bundle. The exact reject-list from `run_authoritative.sh` (~:75).
pub const FORBIDDEN_GUEST_CLOSURE_KEYS: [&str; 4] = [
    "r0_guest_set_hash",
    "guest_program_identities",
    "guest_program_id",
    "populated_allowlist",
];

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Stage1ResultBundleV1 {
    pub schema_version: u32,
    pub bundle_kind: String,
    /// REQUIRED classification. Only `AUTHORITATIVE_STAGE1` can build a finalizable
    /// artifact; `TEST_ONLY` / `NON_SELECTION` are rejected by authoritative ingest.
    pub classification: BundleClassification,
    /// True only when every category is two-build reproducible; a bundle with
    /// this false is refused (partial insertion is never allowed).
    pub all_reproducible: bool,
    pub candidate_container_digests: Vec<ContainerDigestEntry>,
    pub cargo_lock_hashes: Vec<LockHashEntry>,
    pub verifier_material_manifests: Vec<VerifierMaterialManifestEntry>,
    pub native_build_provenance: Vec<NativeBuildProvenance>,
    /// Exact Rust / SP1 / RISC Zero tool identities, one entry per candidate,
    /// cross-checked against the frozen pins. In the authoritative venue path this
    /// is read from real toolchain evidence; if absent the run fails closed.
    pub tool_identities: Vec<ToolIdentityEntry>,
    pub reproducibility: ReproducibilityEvidence,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerDigestEntry {
    pub candidate: String,
    /// `base` or `builder`. The two roles carry DIFFERENT kinds of evidence
    /// (Blocker 6): a `base` entry is an IMMUTABLE INPUT resolved by pull-by-digest,
    /// while a `builder` entry is the two-clean-build image. Validation binds each
    /// role's identity to its own source so builder evidence can never be relabelled
    /// as base evidence.
    pub role: String,
    pub arch: String,
    /// The agreed immutable OCI manifest identity, as a FULL `sha256:<64hex>`
    /// digest (matching `lib.sh` `require_full_sha256_digest`, `VENUE.md`, the
    /// Dockerfiles, and `BASE_DIGEST`). It is NOT trusted on its own: validation
    /// requires it to equal both paired build digests below AND, per role, to equal
    /// `base_image_digest` (base = the pinned pull-by-digest identity) or
    /// `builder_oci_digest` (builder = the built image). The `sha256:` prefix
    /// carries the algorithm identity and is never stripped, and it is the REAL OCI
    /// manifest content address (parsed from the exported layout's `index.json`),
    /// never a hash of the exported tar serialization.
    pub image_digest: String,
    /// The two build digests, each a full `sha256:<64hex>`. For a `builder` entry
    /// these are two INDEPENDENT clean-OCI builds (independent empty cache scopes);
    /// `two_builds_match` is DERIVED by comparing them (`build1 == build2`), never a
    /// supplied boolean, and a divergence fails closed. For a `base` entry they are
    /// the pinned base digest resolved by pull-by-digest (an immutable input is not
    /// re-built, so both equal `base_image_digest`).
    pub image_digest_build1: String,
    pub image_digest_build2: String,
    /// The base image (OCI ref + its pinned `sha256:<64hex>` digest). For a `base`
    /// entry this IS the entry's own immutable-input identity.
    pub base_image_ref: String,
    pub base_image_digest: String,
    /// The builder OCI image identity (ref + its `sha256:<64hex>` manifest digest,
    /// parsed from the exported OCI layout). For a `builder` entry this IS the
    /// entry's own built-image identity.
    pub builder_oci_ref: String,
    pub builder_oci_digest: String,
    /// The clean source commit the build was produced from (git object id, hex).
    pub source_commit_hex: String,
    /// BLAKE3 of the command log and of the relevant raw output, so the evidence
    /// carries HOW the identity was produced. For a `builder` entry this is the
    /// two-clean-build command/output; for a `base` entry it is the GENUINE
    /// pull-by-digest base-resolution command/output — never a copy of the builder's
    /// build evidence.
    pub build_command_log_blake3_hex: String,
    pub raw_build_output_blake3_hex: String,
    pub domain_ascii: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct LockHashEntry {
    pub candidate: String,
    pub blake3_hex: String,
    pub domain_ascii: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct VerifierMaterialManifestEntry {
    pub candidate: String,
    /// The extractor's self-labelling stamps. The real fixture-acceptance path
    /// requires ALL of `b0_pre_vmat::REQUIRED_STAMPS` (TEST_ONLY, NON_SELECTION,
    /// INVALID_FOR_R0, NOT_AN_OFFICIAL_GUEST) BEFORE this manifest is inserted; a
    /// three-stamp manifest is rejected. This is the same gate the extractor
    /// contract tests apply, sourced from the shared crate — not a second copy.
    pub stamp: Vec<String>,
    pub entries: Vec<VerifierMaterialEntryJson>,
    pub total_bytes: u64,
    /// Must equal `BLAKE3(VerifierMaterialManifestV1::encode())` of the canonical
    /// manifest reconstructed from `entries`. No ad-hoc extractor hash is valid.
    pub manifest_hash_hex: String,
    pub domain_ascii: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct VerifierMaterialEntryJson {
    /// Canonical lowercase role name (`groth16_vk`, `control_root`, ...).
    pub role: String,
    /// The single canonical label, which must equal the role name.
    pub label: String,
    pub byte_len: u64,
    pub blake3_hex: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct NativeBuildProvenance {
    pub candidate: String,
    pub arch: String,
    /// The architecture of the host the build actually ran on. `native_arch` is
    /// DERIVED from `host_arch == arch`; a build whose host does not match the
    /// target arch is a cross-compile and is refused.
    pub host_arch: String,
    /// Asserted native flag; validation requires it to equal the DERIVED
    /// `host_arch == arch`, so a mislabelled cross-compile cannot claim native.
    pub native_arch: bool,
    /// Asserted two-build reproducibility; validation requires it to equal the
    /// value DERIVED from the paired container-digest comparison for this
    /// `(candidate, arch)`, so a supplied boolean can never override the digests.
    pub two_build_reproducible: bool,
}

/// Exact tool identities for one candidate: the container Rust toolchain plus the
/// pinned proof-stack tool versions, cross-checked against the frozen pins.
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentityEntry {
    pub candidate: String,
    /// The candidate-container Rust toolchain (e.g. `1.88.0`).
    pub rust_version: String,
    /// The proof-stack tool versions this candidate pins (name → version).
    pub proof_tools: Vec<ToolVersion>,
}

/// The complete preregistered identity of one proof tool. A version string alone
/// does NOT preregister the executable bytes, so every field below is required and,
/// in authoritative mode, must be present and non-synthetic (fail-closed).
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ToolVersion {
    pub name: String,
    pub version: String,
    /// The immutable artifact identity or URL that pins the executable bytes (e.g.
    /// a release URL, an OCI/content digest reference, or a crate content id).
    pub artifact_identity: String,
    /// The checksum algorithm covering `checksum_hex` (`sha256`/`sha384`/`sha512`/
    /// `blake3`); the hex length must match the named algorithm.
    pub checksum_algorithm: String,
    /// The FULL checksum of the artifact bytes, lowercase hex.
    pub checksum_hex: String,
    /// The installation command / entrypoint identity that installs or invokes the
    /// tool (e.g. the pinned installer command or cargo dependency spec).
    pub install_entrypoint: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct ReproducibilityEvidence {
    pub all_container_digests_two_build_reproducible: bool,
    pub in_container_lock_resolution: bool,
    pub verifier_material_reproduced: bool,
}

/// Why a Stage-1 bundle was refused. Any variant keeps the artifact
/// `not_finalizable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage1BundleError {
    /// A post-spec-hash guest-closure field name appeared anywhere in the bytes.
    ForbiddenGuestClosure(&'static str),
    /// Strict JSON parse failed (unknown field, wrong type, malformed).
    Parse(String),
    /// A coverage / count / uniqueness / domain / reproducibility rule failed.
    Rule(String),
    /// A manifest's raw entries are not canonical (label, order, or coverage).
    ManifestNonCanonical(DecodeError),
    /// `manifest_hash_hex` is not `BLAKE3(VerifierMaterialManifestV1::encode())` —
    /// an ad-hoc extractor identity was offered and is refused.
    ManifestIdentityMismatch { candidate: String },
    /// `total_bytes` does not equal this candidate's own Σ `byte_len`.
    ManifestTotalMismatch { candidate: String },
    /// A verifier-material fixture's stamp set was not EXACTLY the four mandatory
    /// stamps, each once (missing / duplicate / unknown-extra); it is refused
    /// before insertion. The exact-set policy is owned by `b0-pre-vmat`.
    FixtureStampSet {
        candidate: String,
        reason: b0_pre_vmat::StampSetError,
    },
    /// A proof-tool identity failed the authoritative completeness rule (absent /
    /// synthetic / malformed artifact identity, checksum algorithm, or checksum), or
    /// a TEST_ONLY tool identity was not unmistakably synthetic.
    ToolIdentity(String),
    /// The bundle carries a non-authoritative classification (`TEST_ONLY` /
    /// `NON_SELECTION`) and can never build a finalizable artifact. This is the
    /// security boundary that keeps synthetic-input bundles out of finalization.
    NonAuthoritativeClassification(BundleClassification),
}

impl fmt::Display for Stage1BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stage1BundleError::ForbiddenGuestClosure(k) => {
                write!(f, "forbidden post-spec guest-closure field present: {k}")
            }
            Stage1BundleError::Parse(e) => write!(f, "strict parse failed: {e}"),
            Stage1BundleError::Rule(m) => write!(f, "completeness rule failed: {m}"),
            Stage1BundleError::ManifestNonCanonical(e) => {
                write!(f, "verifier-material manifest not canonical: {e}")
            }
            Stage1BundleError::ManifestIdentityMismatch { candidate } => write!(
                f,
                "manifest_hash_hex for {candidate} is not the canonical BLAKE3(encode) identity"
            ),
            Stage1BundleError::ManifestTotalMismatch { candidate } => write!(
                f,
                "total_bytes for {candidate} does not equal its own Sum(byte_len)"
            ),
            Stage1BundleError::FixtureStampSet { candidate, reason } => write!(
                f,
                "verifier-material fixture for {candidate} has an invalid stamp set: {reason}"
            ),
            Stage1BundleError::ToolIdentity(m) => write!(f, "tool-identity rule failed: {m}"),
            Stage1BundleError::NonAuthoritativeClassification(c) => write!(
                f,
                "bundle classification {} may not build a finalizable artifact; \
                 only AUTHORITATIVE_STAGE1 reaches authoritative ingest",
                c.as_str()
            ),
        }
    }
}

impl std::error::Error for Stage1BundleError {}

fn rule(m: impl Into<String>) -> Stage1BundleError {
    Stage1BundleError::Rule(m.into())
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Stage1BundleError> {
    if !is_hex64(s) {
        return Err(rule("expected 64 lowercase-hex characters"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| Stage1BundleError::Parse(e.to_string()))?;
    }
    Ok(out)
}

fn candidate_from_name(name: &str) -> Result<Candidate, Stage1BundleError> {
    match name {
        "Sp1" => Ok(Candidate::Sp1),
        "Risc0" => Ok(Candidate::Risc0),
        other => Err(rule(format!("unknown candidate {other:?}"))),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn ascii_of(tag: &[u8; 32]) -> String {
    let n = tags::ascii_len(tag);
    String::from_utf8_lossy(&tag[..n]).into_owned()
}

/// The candidate-container Rust toolchain the tool identities must report. Mirrors
/// `protocol::CANDIDATE_CONTAINER_RUST` — NOT invented here.
pub(crate) const EXPECTED_CANDIDATE_RUST: &str = crate::protocol::CANDIDATE_CONTAINER_RUST;
/// The pinned proof-stack tool versions, mirroring the `=x.y.z` pins in the venue
/// extractor `Cargo.toml`s and `run_authoritative.sh` (VENUE.md audit policy).
/// These are cross-checked, never fabricated: an authoritative bundle must report
/// exactly these, and the TEST_ONLY simulation reuses the same frozen pins.
pub(crate) const EXPECTED_SP1_VERIFIER: &str = "6.3.1";
pub(crate) const EXPECTED_RISC0_ZKVM: &str = "3.0.5";
pub(crate) const EXPECTED_RISC0_GROTH16: &str = "3.0.4";

/// A small explicit blocklist of well-known placeholder digests that are 64-hex
/// yet obviously not a real image/artifact identity.
const PLACEHOLDER_DIGESTS: &[&str] = &[
    // SHA-256 of the empty input (a build that produced nothing).
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    // BLAKE3 of the empty input.
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
];

/// The ONE coherent OCI/base/builder manifest-identity representation: a FULL
/// `sha256:<64hex>` digest (matching `lib.sh` `require_full_sha256_digest`,
/// `VENUE.md`, the Dockerfiles, and `BASE_DIGEST`). The `sha256:` prefix carries
/// the algorithm identity and is never stripped. Rejects: a missing / non-`sha256:`
/// algorithm prefix; uppercase or non-hex characters; a truncated / over-long hex
/// body; the all-zero value; an all-identical-byte value; and any known
/// placeholder pattern. Raw BLAKE3/SHA-256 fields (named `*_hex`) keep the bare
/// 64-hex form via [`check_nonplaceholder_hex64`]; only OCI manifest identities
/// carry the `sha256:` prefix.
fn check_oci_digest(ctx: &str, s: &str) -> Result<(), Stage1BundleError> {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return Err(rule(format!(
            "{ctx}: OCI digest must be a full 'sha256:<64hex>' identity (algorithm prefix required, \
             never a bare hex string or another algorithm)"
        )));
    };
    if !is_hex64(hex) {
        return Err(rule(format!(
            "{ctx}: sha256 digest body must be exactly 64 lowercase-hex characters (no uppercase, \
             no truncation)"
        )));
    }
    if is_placeholder_hex(hex) {
        return Err(rule(format!(
            "{ctx}: digest is a placeholder / all-zero / all-identical value"
        )));
    }
    Ok(())
}

/// True iff a 64-lowercase-hex string is an obvious placeholder: all-zero, every
/// byte identical (covers `00..`, `ff..`, `2121..`, ...), or on the explicit
/// blocklist. Assumes `s` already passed [`is_hex64`].
fn is_placeholder_hex(s: &str) -> bool {
    let b = s.as_bytes();
    // Every byte identical => every 2-hex pair identical.
    if b.chunks(2).all(|c| c == &b[0..2]) {
        return true;
    }
    PLACEHOLDER_DIGESTS.contains(&s)
}

/// A non-container hex identity (BLAKE3 lock / command-log / raw-output hash): 64
/// lowercase hex and not a placeholder. Reuses the same fail-closed placeholder
/// rule so a synthetic-looking all-zero hash cannot slip through.
fn check_nonplaceholder_hex64(ctx: &str, s: &str) -> Result<(), Stage1BundleError> {
    if !is_hex64(s) {
        return Err(rule(format!("{ctx}: must be 64 lowercase hex")));
    }
    if is_placeholder_hex(s) {
        return Err(rule(format!("{ctx}: is a placeholder / all-zero value")));
    }
    Ok(())
}

/// A clean-source git commit: 40- or 64-char lowercase hex (sha1 or sha256 object
/// id), never all-zero / placeholder. An empty or `0000..` commit is refused.
fn check_source_commit(ctx: &str, s: &str) -> Result<(), Stage1BundleError> {
    let ok_len = s.len() == 40 || s.len() == 64;
    let ok_hex = s
        .bytes()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !(ok_len && ok_hex) {
        return Err(rule(format!(
            "{ctx}: source_commit must be 40- or 64-char lowercase hex"
        )));
    }
    if s.bytes().all(|c| c == b'0') {
        return Err(rule(format!("{ctx}: source_commit must not be all-zero")));
    }
    Ok(())
}

/// A non-empty OCI reference identity (base image ref / builder ref). Missing
/// identities are refused.
fn check_ref(ctx: &str, s: &str) -> Result<(), Stage1BundleError> {
    if s.trim().is_empty() {
        return Err(rule(format!("{ctx}: identity reference must not be empty")));
    }
    Ok(())
}

/// A reported tool version string: non-empty and version-like (digits / dots /
/// `-` / `+` / alnum), never a placeholder token.
fn check_version(ctx: &str, s: &str) -> Result<(), Stage1BundleError> {
    let bad = s.trim().is_empty()
        || matches!(
            s.to_ascii_uppercase().as_str(),
            "UNKNOWN" | "TODO" | "TBD" | "NONE" | "PLACEHOLDER" | "N/A"
        )
        || !s.bytes().any(|c| c.is_ascii_digit());
    if bad {
        return Err(rule(format!(
            "{ctx}: tool version {s:?} is empty / a placeholder / not version-like"
        )));
    }
    Ok(())
}

fn tool_ident(m: impl Into<String>) -> Stage1BundleError {
    Stage1BundleError::ToolIdentity(m.into())
}

/// True iff `s` carries the unmistakable synthetic marker (the sentinel token, or
/// an obviously-synthetic scheme). Used to REJECT synthetic values in authoritative
/// mode and to REQUIRE them in TEST_ONLY mode.
fn is_synthetic_marker(s: &str) -> bool {
    let up = s.to_ascii_uppercase();
    up.contains(TEST_ONLY_TOOL_SENTINEL) || up.contains("SYNTHETIC") || up.contains("TEST_ONLY")
}

/// Fully validate one proof tool's preregistered identity in AUTHORITATIVE mode:
/// name, artifact identity/URL, checksum algorithm, and a full checksum of the
/// matching length must all be present, non-placeholder, and NOT synthetic. A
/// version string alone never preregisters the bytes; this is the fail-closed gate.
fn check_tool_identity_authoritative(ctx: &str, tv: &ToolVersion) -> Result<(), Stage1BundleError> {
    if tv.name.trim().is_empty() {
        return Err(tool_ident(format!("{ctx}: tool name is empty")));
    }
    // artifact identity / URL: present, not a placeholder token, not synthetic.
    let ai = tv.artifact_identity.trim();
    if ai.is_empty() {
        return Err(tool_ident(format!(
            "{ctx} {}: artifact_identity (immutable identity or URL) is absent",
            tv.name
        )));
    }
    if is_synthetic_marker(ai) {
        return Err(tool_ident(format!(
            "{ctx} {}: artifact_identity is synthetic; authoritative mode requires real \
             venue-selected installer metadata",
            tv.name
        )));
    }
    // checksum algorithm + full checksum of the matching hex length.
    let algo = tv.checksum_algorithm.trim();
    let Some((_, want_len)) = ALLOWED_CHECKSUM_ALGOS.iter().find(|(a, _)| *a == algo) else {
        return Err(tool_ident(format!(
            "{ctx} {}: checksum_algorithm {:?} is absent or not an allowed algorithm",
            tv.name, tv.checksum_algorithm
        )));
    };
    let cs = &tv.checksum_hex;
    let hex_ok = cs.len() == *want_len
        && cs
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if !hex_ok {
        return Err(tool_ident(format!(
            "{ctx} {}: checksum_hex must be exactly {want_len} lowercase-hex characters for {algo}",
            tv.name
        )));
    }
    if is_synthetic_marker(cs) || cs.bytes().all(|b| b == cs.as_bytes()[0]) {
        return Err(tool_ident(format!(
            "{ctx} {}: checksum_hex is a placeholder / synthetic value",
            tv.name
        )));
    }
    // installation command / entrypoint identity: present and not synthetic.
    let ie = tv.install_entrypoint.trim();
    if ie.is_empty() {
        return Err(tool_ident(format!(
            "{ctx} {}: install_entrypoint identity is absent",
            tv.name
        )));
    }
    if is_synthetic_marker(ie) {
        return Err(tool_ident(format!(
            "{ctx} {}: install_entrypoint is synthetic; authoritative mode requires real \
             venue-selected installer metadata",
            tv.name
        )));
    }
    Ok(())
}

/// Validate one proof tool's identity in TEST_ONLY mode: it MUST be unmistakably
/// synthetic (both artifact_identity and install_entrypoint carry the sentinel), so
/// a synthetic value can never be silently substituted for real venue metadata.
fn check_tool_identity_test_only(ctx: &str, tv: &ToolVersion) -> Result<(), Stage1BundleError> {
    if tv.name.trim().is_empty() {
        return Err(tool_ident(format!("{ctx}: tool name is empty")));
    }
    if !is_synthetic_marker(&tv.artifact_identity) || !is_synthetic_marker(&tv.install_entrypoint) {
        return Err(tool_ident(format!(
            "{ctx} {}: a TEST_ONLY tool identity must be unmistakably synthetic (carry the \
             {TEST_ONLY_TOOL_SENTINEL} sentinel in artifact_identity AND install_entrypoint)",
            tv.name
        )));
    }
    // still require a well-formed checksum shape so the schema stays honest.
    let algo = tv.checksum_algorithm.trim();
    let Some((_, want_len)) = ALLOWED_CHECKSUM_ALGOS.iter().find(|(a, _)| *a == algo) else {
        return Err(tool_ident(format!(
            "{ctx} {}: checksum_algorithm {:?} is not an allowed algorithm",
            tv.name, tv.checksum_algorithm
        )));
    };
    if tv.checksum_hex.len() != *want_len
        || !tv
            .checksum_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(tool_ident(format!(
            "{ctx} {}: checksum_hex must be {want_len} lowercase-hex characters for {algo}",
            tv.name
        )));
    }
    Ok(())
}

impl Stage1ResultBundleV1 {
    /// Strict-parse and fully validate a bundle from its raw bytes. This is the
    /// single insertion gate: it succeeds ONLY when the bundle is complete,
    /// reproducible, canonical, and free of any guest-closure field.
    pub fn decode_and_validate(raw: &[u8]) -> Result<Self, Stage1BundleError> {
        // (1) raw-text guard, identical to run_authoritative.sh: the reject-list
        // must not appear ANYWHERE in the bytes (even inside a string value).
        let text = std::str::from_utf8(raw)
            .map_err(|e| Stage1BundleError::Parse(format!("not utf-8: {e}")))?;
        for k in FORBIDDEN_GUEST_CLOSURE_KEYS {
            if text.contains(k) {
                return Err(Stage1BundleError::ForbiddenGuestClosure(k));
            }
        }
        // (2) strict structural parse (deny_unknown_fields rejects any extra key,
        // which also structurally rejects a top-level guest-closure member).
        let bundle: Self =
            serde_json::from_slice(raw).map_err(|e| Stage1BundleError::Parse(e.to_string()))?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Full completeness validation of an already-parsed bundle.
    pub fn validate(&self) -> Result<(), Stage1BundleError> {
        if self.schema_version != BUNDLE_SCHEMA_VERSION {
            return Err(rule(format!(
                "schema_version must be {BUNDLE_SCHEMA_VERSION}, got {}",
                self.schema_version
            )));
        }
        if self.bundle_kind != BUNDLE_KIND {
            return Err(rule(format!("bundle_kind must be {BUNDLE_KIND:?}")));
        }
        if !self.all_reproducible {
            return Err(rule("all_reproducible must be true (no partial insertion)"));
        }
        if !(self
            .reproducibility
            .all_container_digests_two_build_reproducible
            && self.reproducibility.in_container_lock_resolution
            && self.reproducibility.verifier_material_reproduced)
        {
            return Err(rule("every reproducibility flag must be true"));
        }

        self.validate_containers()?;
        self.validate_locks()?;
        self.validate_manifests()?;
        self.validate_native_build_provenance()?;
        self.validate_tool_identities()?;
        Ok(())
    }

    fn validate_containers(&self) -> Result<(), Stage1BundleError> {
        let container_tag = ascii_of(&tags::CONTAINER_TAG);
        // required 2 candidates x 2 roles x 2 arches, each exactly once.
        let mut required: BTreeSet<(&str, &str, &str)> = BTreeSet::new();
        for c in CANDIDATE_NAMES {
            for role in CONTAINER_ROLES {
                for arch in ARCH_NAMES {
                    required.insert((c, role, arch));
                }
            }
        }
        let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
        // Correction 3 provenance-matches-tuple: every container tuple of one
        // candidate must share a single clean source commit.
        let mut candidate_commit: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for cd in &self.candidate_container_digests {
            if !CANDIDATE_NAMES.contains(&cd.candidate.as_str()) {
                return Err(rule(format!(
                    "container: unknown candidate {:?}",
                    cd.candidate
                )));
            }
            if !CONTAINER_ROLES.contains(&cd.role.as_str()) {
                return Err(rule(format!("container: unknown role {:?}", cd.role)));
            }
            if !ARCH_NAMES.contains(&cd.arch.as_str()) {
                return Err(rule(format!("container: unknown arch {:?}", cd.arch)));
            }
            if cd.domain_ascii != container_tag {
                return Err(rule("container: domain_ascii must be the CONTAINER tag"));
            }
            let ctx = format!("container ({}, {}, {})", cd.candidate, cd.role, cd.arch);
            // Correction 4 + Blocker 2: coherent OCI manifest-identity rule on EVERY
            // OCI digest field — a full `sha256:<64hex>` (algorithm prefix required),
            // no uppercase/truncation, no placeholder/all-zero. Raw `*_hex` fields
            // (command-log, raw-output) keep the bare-64-hex form below.
            check_oci_digest(&format!("{ctx} image_digest"), &cd.image_digest)?;
            check_oci_digest(&format!("{ctx} build1"), &cd.image_digest_build1)?;
            check_oci_digest(&format!("{ctx} build2"), &cd.image_digest_build2)?;
            check_oci_digest(&format!("{ctx} base_image_digest"), &cd.base_image_digest)?;
            check_oci_digest(&format!("{ctx} builder_oci_digest"), &cd.builder_oci_digest)?;
            // Correction 3: DERIVE two_builds_match from the paired digests here;
            // a supplied boolean is never trusted. Divergence => not reproducible.
            if cd.image_digest_build1 != cd.image_digest_build2 {
                return Err(rule(format!(
                    "{ctx}: the two clean OCI build digests diverge; not two-build reproducible"
                )));
            }
            // ...and the agreed digest must equal the reproduced build digest.
            if cd.image_digest != cd.image_digest_build1 {
                return Err(rule(format!(
                    "{ctx}: image_digest must equal the reproduced build digest"
                )));
            }
            // Blocker 6: bind each role's manifest identity to its own truthful
            // source, so builder evidence can never be relabelled as base evidence.
            // A `base` entry models an IMMUTABLE INPUT pulled by digest: its manifest
            // identity IS the pinned base digest (`base_image_digest`), not a
            // separately-built image. A `builder` entry's identity IS the builder
            // image it was built into (`builder_oci_digest`). Its base-resolution
            // provenance (command-log / raw-output) is distinct base evidence, not a
            // copy of the builder build.
            match cd.role.as_str() {
                "base" if cd.image_digest != cd.base_image_digest => {
                    return Err(rule(format!(
                        "{ctx}: a base entry is an immutable input; its image_digest must equal \
                         base_image_digest (the pinned pull-by-digest identity, not a rebuilt image)"
                    )));
                }
                "builder" if cd.image_digest != cd.builder_oci_digest => {
                    return Err(rule(format!(
                        "{ctx}: a builder entry's image_digest must equal builder_oci_digest \
                         (its built image identity)"
                    )));
                }
                _ => {}
            }
            // Correction 3+4: base and builder identities must be present.
            check_ref(&format!("{ctx} base_image_ref"), &cd.base_image_ref)?;
            check_ref(&format!("{ctx} builder_oci_ref"), &cd.builder_oci_ref)?;
            // Correction 3: clean source commit + command-log / raw-output hashes.
            check_source_commit(&format!("{ctx} source_commit"), &cd.source_commit_hex)?;
            check_nonplaceholder_hex64(
                &format!("{ctx} build_command_log_blake3"),
                &cd.build_command_log_blake3_hex,
            )?;
            check_nonplaceholder_hex64(
                &format!("{ctx} raw_build_output_blake3"),
                &cd.raw_build_output_blake3_hex,
            )?;
            // Provenance-matches-tuple: one clean source commit per candidate.
            match candidate_commit.get(&cd.candidate) {
                Some(prev) if *prev != cd.source_commit_hex => {
                    return Err(rule(format!(
                        "container: candidate {} has inconsistent source commits across tuples",
                        cd.candidate
                    )));
                }
                _ => {
                    candidate_commit.insert(cd.candidate.clone(), cd.source_commit_hex.clone());
                }
            }
            let key = (cd.candidate.clone(), cd.role.clone(), cd.arch.clone());
            if !seen.insert(key) {
                return Err(rule(format!(
                    "container: duplicate tuple ({}, {}, {})",
                    cd.candidate, cd.role, cd.arch
                )));
            }
        }
        let present: BTreeSet<(&str, &str, &str)> = seen
            .iter()
            .map(|(c, r, a)| (c.as_str(), r.as_str(), a.as_str()))
            .collect();
        if let Some(m) = required.difference(&present).next() {
            return Err(rule(format!(
                "container: missing tuple ({}, {}, {})",
                m.0, m.1, m.2
            )));
        }
        if self.candidate_container_digests.len() != 8 {
            return Err(rule(format!(
                "container: exactly 8 digests required (2x2x2), got {}",
                self.candidate_container_digests.len()
            )));
        }
        Ok(())
    }

    fn validate_locks(&self) -> Result<(), Stage1BundleError> {
        let lock_tag = ascii_of(&tags::CARGO_LOCK_TAG);
        let mut cands: BTreeSet<&str> = BTreeSet::new();
        for lk in &self.cargo_lock_hashes {
            if !CANDIDATE_NAMES.contains(&lk.candidate.as_str()) {
                return Err(rule(format!("lock: unknown candidate {:?}", lk.candidate)));
            }
            if lk.domain_ascii != lock_tag {
                return Err(rule("lock: domain_ascii must be the CARGO_LOCK tag"));
            }
            if !is_hex64(&lk.blake3_hex) {
                return Err(rule("lock: blake3_hex must be 64 lowercase hex"));
            }
            if !cands.insert(lk.candidate.as_str()) {
                return Err(rule(format!("lock: duplicate candidate {}", lk.candidate)));
            }
        }
        if self.cargo_lock_hashes.len() != 2 {
            return Err(rule(format!(
                "lock: exactly 2 lock hashes required (one per candidate), got {}",
                self.cargo_lock_hashes.len()
            )));
        }
        Ok(())
    }

    fn validate_manifests(&self) -> Result<(), Stage1BundleError> {
        let vmat_tag = ascii_of(&tags::VERIFIER_MATERIAL_TAG);
        let mut cands: BTreeSet<&str> = BTreeSet::new();
        for m in &self.verifier_material_manifests {
            // Validate the candidate name early (the reconstruction below re-parses
            // it); a bad name is rejected regardless of the other fields.
            candidate_from_name(&m.candidate)?;
            // Correction 5: EXACT fixture-acceptance stamp gate — the four stamps,
            // each present once, with NO missing / duplicate / unknown-extra stamp.
            // The exact-set policy is owned by the shared crate; this is the real
            // insertion boundary (stricter than the extractor contract tests'
            // `all_required_stamps_present`, which tolerates extras).
            b0_pre_vmat::check_exact_stamp_set(&m.stamp).map_err(|reason| {
                Stage1BundleError::FixtureStampSet {
                    candidate: m.candidate.clone(),
                    reason,
                }
            })?;
            if m.domain_ascii != vmat_tag {
                return Err(rule("manifest: domain_ascii must be the VMAT tag"));
            }
            if !is_hex64(&m.manifest_hash_hex) {
                return Err(rule("manifest: manifest_hash_hex must be 64 lowercase hex"));
            }
            // Reconstruct the canonical manifest from the raw entries (preserving
            // input order so a mis-ordered bundle is rejected) and assert canonical
            // coverage: SP1 => only groth16_vk; RISC0 => all four, canonically
            // labelled and strictly ordered.
            let vmm = reconstruct_canonical_manifest(m)?;
            vmm.validate_canonical()
                .map_err(Stage1BundleError::ManifestNonCanonical)?;
            // Canonical bridge: only BLAKE3(encode) is the identity. The fallible
            // codec propagates any structural rejection instead of panicking.
            let identity = vmm
                .identity()
                .map_err(Stage1BundleError::ManifestNonCanonical)?;
            if hex(&identity) != m.manifest_hash_hex {
                return Err(Stage1BundleError::ManifestIdentityMismatch {
                    candidate: m.candidate.clone(),
                });
            }
            // Per-candidate total equals this candidate's own Σ byte_len.
            let total = vmm
                .verifier_material_bytes()
                .map_err(Stage1BundleError::ManifestNonCanonical)?;
            if total != m.total_bytes {
                return Err(Stage1BundleError::ManifestTotalMismatch {
                    candidate: m.candidate.clone(),
                });
            }
            if !cands.insert(m.candidate.as_str()) {
                return Err(rule(format!(
                    "manifest: duplicate candidate {}",
                    m.candidate
                )));
            }
        }
        if self.verifier_material_manifests.len() != 2 {
            return Err(rule(format!(
                "manifest: exactly 2 manifests required (one per candidate), got {}",
                self.verifier_material_manifests.len()
            )));
        }
        Ok(())
    }

    fn validate_native_build_provenance(&self) -> Result<(), Stage1BundleError> {
        // Exactly one native build per (candidate, arch) = 4, each native and
        // two-build reproducible.
        let mut required: BTreeSet<(&str, &str)> = BTreeSet::new();
        for c in CANDIDATE_NAMES {
            for arch in ARCH_NAMES {
                required.insert((c, arch));
            }
        }
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for p in &self.native_build_provenance {
            if !CANDIDATE_NAMES.contains(&p.candidate.as_str()) {
                return Err(rule(format!(
                    "provenance: unknown candidate {:?}",
                    p.candidate
                )));
            }
            if !ARCH_NAMES.contains(&p.arch.as_str()) {
                return Err(rule(format!("provenance: unknown arch {:?}", p.arch)));
            }
            if !ARCH_NAMES.contains(&p.host_arch.as_str()) {
                return Err(rule(format!(
                    "provenance: unknown host_arch {:?}",
                    p.host_arch
                )));
            }
            // Correction 3: DERIVE native from the host-architecture evidence; a
            // build whose host arch differs from the target arch is a cross-compile.
            let derived_native = p.host_arch == p.arch;
            if !derived_native {
                return Err(rule(format!(
                    "provenance: {} on {} ran on host_arch {} (cross-compiled, not native)",
                    p.candidate, p.arch, p.host_arch
                )));
            }
            if p.native_arch != derived_native {
                return Err(rule(format!(
                    "provenance: {} on {} native_arch flag disagrees with host_arch evidence",
                    p.candidate, p.arch
                )));
            }
            // Correction 3: DERIVE two-build reproducibility from THIS candidate/
            // arch's paired container digests; the supplied boolean must equal it.
            let derived_repro = {
                let tuples: Vec<&ContainerDigestEntry> = self
                    .candidate_container_digests
                    .iter()
                    .filter(|c| c.candidate == p.candidate && c.arch == p.arch)
                    .collect();
                !tuples.is_empty()
                    && tuples
                        .iter()
                        .all(|c| c.image_digest_build1 == c.image_digest_build2)
            };
            if p.two_build_reproducible != derived_repro {
                return Err(rule(format!(
                    "provenance: {} on {} two_build_reproducible flag disagrees with the paired \
                     container-digest comparison",
                    p.candidate, p.arch
                )));
            }
            if !derived_repro {
                return Err(rule(format!(
                    "provenance: {} on {} is not two-build reproducible",
                    p.candidate, p.arch
                )));
            }
            if !seen.insert((p.candidate.clone(), p.arch.clone())) {
                return Err(rule(format!(
                    "provenance: duplicate ({}, {})",
                    p.candidate, p.arch
                )));
            }
        }
        let present: BTreeSet<(&str, &str)> =
            seen.iter().map(|(c, a)| (c.as_str(), a.as_str())).collect();
        if let Some(m) = required.difference(&present).next() {
            return Err(rule(format!(
                "provenance: missing native build ({}, {})",
                m.0, m.1
            )));
        }
        if self.native_build_provenance.len() != 4 {
            return Err(rule(format!(
                "provenance: exactly 4 native builds required (2 candidates x 2 arches), got {}",
                self.native_build_provenance.len()
            )));
        }
        Ok(())
    }

    /// Correction 3: the exact Rust / SP1 / RISC Zero tool identities, one entry
    /// per candidate, cross-checked against the FROZEN pins (never fabricated —
    /// they mirror the values already pinned in the venue extractor `Cargo.toml`s,
    /// `run_authoritative.sh`, and `protocol::CANDIDATE_CONTAINER_RUST`). A missing
    /// or mismatched tool version fails the bundle closed.
    fn validate_tool_identities(&self) -> Result<(), Stage1BundleError> {
        let mut cands: BTreeSet<&str> = BTreeSet::new();
        for t in &self.tool_identities {
            if !CANDIDATE_NAMES.contains(&t.candidate.as_str()) {
                return Err(rule(format!(
                    "tool_identities: unknown candidate {:?}",
                    t.candidate
                )));
            }
            check_version("tool_identities.rust_version", &t.rust_version)?;
            if t.rust_version != EXPECTED_CANDIDATE_RUST {
                return Err(rule(format!(
                    "tool_identities: {} rust_version {:?} != frozen {EXPECTED_CANDIDATE_RUST:?}",
                    t.candidate, t.rust_version
                )));
            }
            let expected: &[(&str, &str)] = match t.candidate.as_str() {
                "Sp1" => &[("sp1-verifier", EXPECTED_SP1_VERIFIER)],
                "Risc0" => &[
                    ("risc0-zkvm", EXPECTED_RISC0_ZKVM),
                    ("risc0-groth16", EXPECTED_RISC0_GROTH16),
                ],
                other => {
                    return Err(rule(format!(
                        "tool_identities: unknown candidate {other:?}"
                    )))
                }
            };
            if t.proof_tools.len() != expected.len() {
                return Err(rule(format!(
                    "tool_identities: {} must report exactly {} proof tool(s), got {}",
                    t.candidate,
                    expected.len(),
                    t.proof_tools.len()
                )));
            }
            let mut names: BTreeSet<&str> = BTreeSet::new();
            for pt in &t.proof_tools {
                if !names.insert(pt.name.as_str()) {
                    return Err(rule(format!(
                        "tool_identities: {} duplicate proof tool {:?}",
                        t.candidate, pt.name
                    )));
                }
            }
            for (name, ver) in expected {
                let pt = t
                    .proof_tools
                    .iter()
                    .find(|pt| pt.name == *name)
                    .ok_or_else(|| {
                        rule(format!(
                            "tool_identities: {} missing pinned proof tool {name:?}",
                            t.candidate
                        ))
                    })?;
                check_version("tool_identities.proof_tool", &pt.version)?;
                if pt.version != *ver {
                    return Err(rule(format!(
                        "tool_identities: {} {name} version {:?} != frozen pin {ver:?}",
                        t.candidate, pt.version
                    )));
                }
                // Blocker 3: a version string does not preregister the executable
                // bytes. AUTHORITATIVE requires a complete, non-synthetic identity
                // (artifact identity/URL + checksum algorithm + full checksum +
                // install entrypoint), fail-closed on absent/synthetic values;
                // TEST_ONLY / NON_SELECTION require the identity be unmistakably
                // synthetic so it can never substitute for real venue metadata.
                let ctx = format!("tool_identities[{}]", t.candidate);
                if self.classification.is_authoritative() {
                    check_tool_identity_authoritative(&ctx, pt)?;
                } else {
                    check_tool_identity_test_only(&ctx, pt)?;
                }
            }
            if !cands.insert(t.candidate.as_str()) {
                return Err(rule(format!(
                    "tool_identities: duplicate candidate {}",
                    t.candidate
                )));
            }
        }
        if self.tool_identities.len() != 2 {
            return Err(rule(format!(
                "tool_identities: exactly 2 entries required (one per candidate), got {}",
                self.tool_identities.len()
            )));
        }
        Ok(())
    }

    /// Convert a fully-validated bundle into the complete Stage-1
    /// `pending_inputs` replacement. Each verifier-material ref carries the
    /// CANONICAL identity + total recomputed from the reconstructed manifest (both
    /// were already checked equal to the bundle's self-report in `validate`), so no
    /// self-reported value stands unchecked.
    fn to_pending_inputs(&self) -> Result<PendingInputs, Stage1BundleError> {
        let containers = self
            .candidate_container_digests
            .iter()
            .map(|cd| ContainerDigest {
                candidate: cd.candidate.clone(),
                role: cd.role.clone(),
                arch: cd.arch.clone(),
                image_digest: cd.image_digest.clone(),
                domain_ascii: cd.domain_ascii.clone(),
            })
            .collect();
        let locks = self
            .cargo_lock_hashes
            .iter()
            .map(|lk| LockHash {
                name: lk.candidate.clone(),
                blake3_hex: lk.blake3_hex.clone(),
                domain_ascii: lk.domain_ascii.clone(),
            })
            .collect();
        let mut manifests = Vec::with_capacity(self.verifier_material_manifests.len());
        for m in &self.verifier_material_manifests {
            let vmm = reconstruct_canonical_manifest(m)?;
            let total = vmm
                .verifier_material_bytes()
                .map_err(Stage1BundleError::ManifestNonCanonical)?;
            let identity = vmm
                .identity()
                .map_err(Stage1BundleError::ManifestNonCanonical)?;
            manifests.push(VerifierMaterialManifestRef {
                candidate: m.candidate.clone(),
                manifest_hash_hex: hex(&identity),
                total_bytes: total,
                domain_ascii: m.domain_ascii.clone(),
            });
        }
        Ok(PendingInputs {
            candidate_container_digests: Some(containers),
            cargo_lock_hashes: Some(locks),
            verifier_material_manifests: Some(manifests),
        })
    }
}

/// Reconstruct the canonical `VerifierMaterialManifestV1` from a bundle entry's
/// raw JSON entries, in the input order given (so `validate_canonical` can reject
/// a mis-ordered bundle). Rejects any non-canonical role label or label/role
/// mismatch — it never normalizes the supplied representation.
fn reconstruct_canonical_manifest(
    m: &VerifierMaterialManifestEntry,
) -> Result<VerifierMaterialManifestV1, Stage1BundleError> {
    let candidate = candidate_from_name(&m.candidate)?;
    let mut entries = Vec::with_capacity(m.entries.len());
    for je in &m.entries {
        let role = VerifierMaterialRole::from_canonical_label(&je.role)
            .map_err(Stage1BundleError::ManifestNonCanonical)?;
        if je.label != role.canonical_label() {
            return Err(Stage1BundleError::ManifestNonCanonical(
                DecodeError::BadValue {
                    ctx: "Stage1.manifest.label_not_canonical",
                },
            ));
        }
        entries.push(VerifierMaterialEntry {
            label: je.label.clone(),
            role,
            byte_len: je.byte_len,
            hash: parse_hex32(&je.blake3_hex)?,
        });
    }
    Ok(VerifierMaterialManifestV1 { candidate, entries })
}

/// The full authoritative Stage-1 ingest pipeline, IN MEMORY:
///
///   raw bundle bytes
///     -> forbidden guest-closure text scan  (reject)
///     -> strict `deny_unknown_fields` decode (any unknown field -> reject)
///     -> schema/version + exact coverage + provenance/reproducibility validation
///     -> canonical verifier-material reconstruction + identity + total + the
///        four-stamp fixture gate
///     -> complete `pending_inputs` replacement
///     -> regenerated `finalizable` artifact
///     -> semantic re-validation of the whole artifact.
///
/// Returns the finalizable artifact ONLY when EVERY check passes; any failure
/// returns `Err` and yields NO artifact (all-or-nothing — a malformed bundle can
/// never reach insertion). This function NEVER touches the filesystem and NEVER
/// computes or persists the real `b0_pre_spec_hash`; the caller atomically writes
/// the returned artifact to a temp target only after this succeeds.
pub fn build_finalizable_artifact(raw: &[u8]) -> Result<B0PreProtocolV1, Stage1BundleError> {
    let bundle = Stage1ResultBundleV1::decode_and_validate(raw)?;
    // Blocker 4 security boundary: TEST_ONLY / NON_SELECTION bundles are fully
    // validated above but can NEVER reach finalization. A synthetic-input bundle
    // has no path to a finalizable artifact.
    if !bundle.classification.is_authoritative() {
        return Err(Stage1BundleError::NonAuthoritativeClassification(
            bundle.classification,
        ));
    }
    let pending = bundle.to_pending_inputs()?;

    let mut p = B0PreProtocolV1::frozen();
    p.pending_inputs = pending;
    p.finalization.state = "finalizable".into();
    p.finalization.blocked_on = Vec::new();

    // Re-validate the WHOLE reconstructed artifact (coverage/uniqueness/domain
    // cross-fields), independently of the bundle checks above.
    let viol = p.semantic_violations();
    if !viol.is_empty() {
        return Err(rule(format!(
            "reconstructed artifact failed semantic validation: {viol:?}"
        )));
    }
    if !p.is_finalizable() {
        return Err(rule("reconstructed artifact is not finalizable"));
    }
    Ok(p)
}

/// The explicitly test-only validation path (Blocker 4): strict decode + the FULL
/// semantic validation ([`Stage1ResultBundleV1::validate`]) of a NON-authoritative
/// bundle (`TEST_ONLY` / `NON_SELECTION`), returning its validated classification.
/// It proves the whole pipeline accepts the bundle's shape / coverage /
/// reproducibility / canonical manifests, yet by construction it CANNOT emit a
/// finalizable artifact: it refuses an `AUTHORITATIVE_STAGE1` bundle (that must go
/// through `stage1-ingest`), and it never regenerates or writes any artifact. This
/// is the local e2e path for exercising assembly + validation of a TEST_ONLY bundle
/// without any route to finalization.
pub fn validate_test_only_bundle(raw: &[u8]) -> Result<BundleClassification, Stage1BundleError> {
    let bundle = Stage1ResultBundleV1::decode_and_validate(raw)?;
    if bundle.classification.is_authoritative() {
        return Err(rule(
            "validate-test-only refuses an AUTHORITATIVE_STAGE1 bundle; \
             an authoritative bundle must go through stage1-ingest",
        ));
    }
    Ok(bundle.classification)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RISC Zero verifier-material total these TEST_ONLY fixtures happen to
    /// carry (256 + 32 + 32 + 32). It is SYNTHETIC per-fixture data — NEVER a
    /// protocol constant, candidate requirement, qualification limit,
    /// preregistered expected result, or venue acceptance condition. An
    /// authoritative RISC Zero bundle may carry ANY positive, internally-consistent
    /// total; it is checked ONLY against its own canonical manifest, never against
    /// this number (see `authoritative_risc0_may_carry_any_total_checked_against_own_manifest`).
    const TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL: u64 = 256 + 32 + 32 + 32;

    /// A deterministic, NON-placeholder 64-hex digest from a label (BLAKE3), so
    /// TEST_ONLY fixtures never trip the placeholder / all-identical-byte guards.
    fn syn(label: &str) -> String {
        hex(blake3::hash(label.as_bytes()).as_bytes())
    }

    /// A reproducible TEST_ONLY container entry: the two build digests agree and
    /// equal the image digest, identities are present, and per-candidate the source
    /// commit is stable across tuples.
    /// A full OCI manifest digest for a fixture: `sha256:<64hex>` (non-placeholder).
    fn oci(label: &str) -> String {
        format!("sha256:{}", syn(label))
    }

    fn container(candidate: &str, role: &str, arch: &str, b: u8) -> ContainerDigestEntry {
        let base_image_digest = oci(&format!("base-{candidate}-{arch}"));
        let builder_oci_digest = oci(&format!("builder-{candidate}-{arch}"));
        // Blocker 6: the base entry's identity IS the pinned base digest (immutable
        // input); the builder entry's identity IS the builder image digest.
        let img = match role {
            "base" => base_image_digest.clone(),
            "builder" => builder_oci_digest.clone(),
            _ => oci(&format!("image-{candidate}-{role}-{arch}-{b}")),
        };
        ContainerDigestEntry {
            candidate: candidate.into(),
            role: role.into(),
            arch: arch.into(),
            image_digest: img.clone(),
            image_digest_build1: img.clone(),
            image_digest_build2: img,
            base_image_ref: format!("registry.test/{candidate}/base:pinned"),
            base_image_digest,
            builder_oci_ref: format!("registry.test/{candidate}/builder:pinned"),
            builder_oci_digest,
            source_commit_hex: syn(&format!("commit-{candidate}"))[..40].to_string(),
            // distinct base-resolution vs builder-build evidence (never a copy).
            build_command_log_blake3_hex: syn(&format!("cmdlog-{candidate}-{role}-{arch}-{b}")),
            raw_build_output_blake3_hex: syn(&format!("rawout-{candidate}-{role}-{arch}-{b}")),
            domain_ascii: ascii_of(&tags::CONTAINER_TAG),
        }
    }

    /// A complete AUTHORITATIVE proof-tool identity fixture: pinned version plus a
    /// well-formed, NON-synthetic artifact identity / checksum / entrypoint. These
    /// are test-fixture values (not real installer metadata), used only to exercise
    /// the accept-path logic in-code — never written to the committed artifact and
    /// never mintable by a shippable synthetic-input command.
    fn tool(name: &str, version: &str) -> ToolVersion {
        ToolVersion {
            name: name.into(),
            version: version.into(),
            artifact_identity: format!("https://fixtures.invalid/{name}-{version}.tar"),
            checksum_algorithm: "sha256".into(),
            checksum_hex: syn(&format!("artifact-{name}-{version}")),
            install_entrypoint: format!("cargo:{name}@{version}"),
        }
    }

    /// AUTHORITATIVE tool identities: the pinned versions cross-checked against the
    /// frozen pins, with complete non-synthetic identity fields.
    fn tool_ids() -> Vec<ToolIdentityEntry> {
        vec![
            ToolIdentityEntry {
                candidate: "Sp1".into(),
                rust_version: EXPECTED_CANDIDATE_RUST.into(),
                proof_tools: vec![tool("sp1-verifier", EXPECTED_SP1_VERIFIER)],
            },
            ToolIdentityEntry {
                candidate: "Risc0".into(),
                rust_version: EXPECTED_CANDIDATE_RUST.into(),
                proof_tools: vec![
                    tool("risc0-zkvm", EXPECTED_RISC0_ZKVM),
                    tool("risc0-groth16", EXPECTED_RISC0_GROTH16),
                ],
            },
        ]
    }

    fn manifest_entry_json(m: &VerifierMaterialManifestV1) -> VerifierMaterialManifestEntry {
        VerifierMaterialManifestEntry {
            candidate: match m.candidate {
                Candidate::Sp1 => "Sp1".into(),
                Candidate::Risc0 => "Risc0".into(),
            },
            stamp: b0_pre_vmat::REQUIRED_STAMPS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            entries: m
                .entries
                .iter()
                .map(|e| VerifierMaterialEntryJson {
                    role: e.role.canonical_label().to_string(),
                    label: e.label.clone(),
                    byte_len: e.byte_len,
                    blake3_hex: hex(&e.hash),
                })
                .collect(),
            total_bytes: m.verifier_material_bytes().unwrap(),
            manifest_hash_hex: hex(&m.identity().unwrap()),
            domain_ascii: ascii_of(&tags::VERIFIER_MATERIAL_TAG),
        }
    }

    fn sp1_manifest() -> VerifierMaterialManifestV1 {
        VerifierMaterialManifestV1::from_canonical(
            Candidate::Sp1,
            [(VerifierMaterialRole::Groth16Vk, 292, [0x71; 32])],
        )
    }
    fn risc0_manifest() -> VerifierMaterialManifestV1 {
        VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [
                (VerifierMaterialRole::Groth16Vk, 256, [0x72; 32]),
                (VerifierMaterialRole::ControlRoot, 32, [0x73; 32]),
                (VerifierMaterialRole::ControlId, 32, [0x74; 32]),
                (VerifierMaterialRole::VerifierParams, 32, [0x75; 32]),
            ],
        )
    }

    /// A fully-valid bundle: exactly 8 containers, 2 locks, 2 canonical manifests,
    /// 4 native builds, all reproducible, no guest closure.
    pub(super) fn valid_bundle() -> Stage1ResultBundleV1 {
        let lock = |candidate: &str, b: u8| LockHashEntry {
            candidate: candidate.into(),
            blake3_hex: hex(&[b; 32]),
            domain_ascii: ascii_of(&tags::CARGO_LOCK_TAG),
        };
        let prov = |candidate: &str, arch: &str| NativeBuildProvenance {
            candidate: candidate.into(),
            arch: arch.into(),
            host_arch: arch.into(),
            native_arch: true,
            two_build_reproducible: true,
        };
        Stage1ResultBundleV1 {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_kind: BUNDLE_KIND.into(),
            classification: BundleClassification::AuthoritativeStage1,
            all_reproducible: true,
            candidate_container_digests: vec![
                container("Sp1", "base", "X86_64", 0x21),
                container("Sp1", "base", "Aarch64", 0x22),
                container("Sp1", "builder", "X86_64", 0x23),
                container("Sp1", "builder", "Aarch64", 0x24),
                container("Risc0", "base", "X86_64", 0x25),
                container("Risc0", "base", "Aarch64", 0x26),
                container("Risc0", "builder", "X86_64", 0x27),
                container("Risc0", "builder", "Aarch64", 0x28),
            ],
            cargo_lock_hashes: vec![lock("Sp1", 0x33), lock("Risc0", 0x34)],
            verifier_material_manifests: vec![
                manifest_entry_json(&sp1_manifest()),
                manifest_entry_json(&risc0_manifest()),
            ],
            native_build_provenance: vec![
                prov("Sp1", "X86_64"),
                prov("Sp1", "Aarch64"),
                prov("Risc0", "X86_64"),
                prov("Risc0", "Aarch64"),
            ],
            tool_identities: tool_ids(),
            reproducibility: ReproducibilityEvidence {
                all_container_digests_two_build_reproducible: true,
                in_container_lock_resolution: true,
                verifier_material_reproduced: true,
            },
        }
    }

    fn raw(b: &Stage1ResultBundleV1) -> Vec<u8> {
        serde_json::to_vec(b).unwrap()
    }

    #[test]
    fn valid_bundle_accepts_and_totals_are_per_candidate() {
        let b = valid_bundle();
        assert_eq!(b.validate(), Ok(()));
        let parsed = Stage1ResultBundleV1::decode_and_validate(&raw(&b)).unwrap();
        assert_eq!(parsed, b);
        // per-candidate totals: SP1 = 292, RISC0 = its own synthetic Σ, never a
        // shared constant.
        assert_eq!(parsed.verifier_material_manifests[0].total_bytes, 292);
        assert_eq!(
            parsed.verifier_material_manifests[1].total_bytes,
            TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL
        );
    }

    #[test]
    fn authoritative_risc0_may_carry_any_total_checked_against_own_manifest() {
        // Item 4: 352 is not authoritative and not a gate. A RISC Zero bundle whose
        // four roles carry ARBITRARY positive venue-derived byte lengths (summing
        // to something that is NOT the synthetic 352) is accepted, because the
        // total is validated ONLY against that bundle's own canonical manifest.
        let arbitrary = VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [
                (VerifierMaterialRole::Groth16Vk, 999, [0xa1; 32]),
                (VerifierMaterialRole::ControlRoot, 111, [0xa2; 32]),
                (VerifierMaterialRole::ControlId, 222, [0xa3; 32]),
                (VerifierMaterialRole::VerifierParams, 333, [0xa4; 32]),
            ],
        );
        let own_total = arbitrary.verifier_material_bytes().unwrap();
        assert_eq!(own_total, 999 + 111 + 222 + 333);
        assert_ne!(own_total, TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL);

        let mut b = valid_bundle();
        b.verifier_material_manifests[1] = manifest_entry_json(&arbitrary);
        assert_eq!(
            b.validate(),
            Ok(()),
            "an internally-consistent RISC0 total other than 352 must be accepted"
        );

        // and the pipeline builds a finalizable artifact carrying that own total
        let artifact = build_finalizable_artifact(&raw(&b)).expect("valid");
        let risc0 = artifact
            .pending_inputs
            .verifier_material_manifests
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.candidate == "Risc0")
            .unwrap();
        assert_eq!(risc0.total_bytes, own_total);
    }

    #[test]
    fn empty_arrays_are_rejected() {
        let mut b = valid_bundle();
        b.candidate_container_digests.clear();
        assert!(matches!(b.validate(), Err(Stage1BundleError::Rule(_))));
        let mut b = valid_bundle();
        b.cargo_lock_hashes.clear();
        assert!(matches!(b.validate(), Err(Stage1BundleError::Rule(_))));
        let mut b = valid_bundle();
        b.verifier_material_manifests.clear();
        assert!(matches!(b.validate(), Err(Stage1BundleError::Rule(_))));
    }

    #[test]
    fn incomplete_missing_and_extra_container_coverage_rejected() {
        // missing one tuple (7 entries)
        let mut b = valid_bundle();
        b.candidate_container_digests.pop();
        assert!(b.validate().is_err());
        // duplicate a tuple (still 8, but coverage wrong)
        let mut b = valid_bundle();
        b.candidate_container_digests[7] = b.candidate_container_digests[0].clone();
        assert!(b.validate().is_err());
        // extra tuple (9 entries)
        let mut b = valid_bundle();
        b.candidate_container_digests
            .push(container("Sp1", "base", "X86_64", 0x99));
        assert!(b.validate().is_err());
        // unknown arch
        let mut b = valid_bundle();
        b.candidate_container_digests[0].arch = "riscv".into();
        assert!(b.validate().is_err());
    }

    #[test]
    fn lock_and_manifest_must_be_two_per_candidate() {
        let mut b = valid_bundle();
        b.cargo_lock_hashes[1].candidate = "Sp1".into(); // both Sp1 -> dup + missing Risc0
        assert!(b.validate().is_err());
        let mut b = valid_bundle();
        b.verifier_material_manifests.pop();
        assert!(b.validate().is_err());
    }

    #[test]
    fn ad_hoc_extractor_identity_is_never_accepted_as_manifest_hash() {
        // Substitute the OLD ad-hoc extractor identity (BLAKE3(TAG || custom body))
        // for the canonical manifest_hash_hex. It must be rejected: only
        // BLAKE3(VerifierMaterialManifestV1::encode()) is valid.
        let m = sp1_manifest();
        let mut adhoc = blake3::Hasher::new();
        adhoc.update(&tags::VERIFIER_MATERIAL_TAG);
        adhoc.update(b"Sp1\0groth16_vk\0"); // a non-canonical body, like the extractor's
        let adhoc_hex = hex(adhoc.finalize().as_bytes());
        assert_ne!(adhoc_hex, hex(&m.identity().unwrap()));

        let mut b = valid_bundle();
        b.verifier_material_manifests[0].manifest_hash_hex = adhoc_hex;
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ManifestIdentityMismatch { .. })
        ));
    }

    #[test]
    fn falsified_total_bytes_rejected() {
        let mut b = valid_bundle();
        b.verifier_material_manifests[1].total_bytes = 292; // RISC0 claiming SP1's 292
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ManifestTotalMismatch { .. })
        ));
    }

    #[test]
    fn noncanonical_labels_order_and_coverage_rejected() {
        // uppercase legacy label
        let mut b = valid_bundle();
        b.verifier_material_manifests[0].entries[0].label = "GROTH16_VK_BYTES".into();
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ManifestNonCanonical(_))
        ));
        // RISC0 missing a role (wrong coverage)
        let mut b = valid_bundle();
        b.verifier_material_manifests[1].entries.pop();
        assert!(b.validate().is_err());
        // RISC0 entries out of canonical order
        let mut b = valid_bundle();
        b.verifier_material_manifests[1].entries.swap(0, 1);
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ManifestNonCanonical(_))
        ));
    }

    #[test]
    fn stage1_labels_must_already_be_canonical_never_normalized() {
        // Item 5: the Stage-1 DECODER requires the supplied representation to be
        // ALREADY canonical — it never silently normalizes an attacker-supplied
        // label before validation. Every deviation below is REJECTED, not repaired.
        type Mut = fn(&mut Stage1ResultBundleV1);
        let cases: &[(&str, Mut)] = &[
            // uppercase legacy label (role field still canonical) -> label/role mismatch
            ("uppercase_label", |b| {
                b.verifier_material_manifests[0].entries[0].label = "GROTH16_VK_BYTES".into();
            }),
            // uppercase role string -> not a canonical role label
            ("uppercase_role", |b| {
                b.verifier_material_manifests[0].entries[0].role = "GROTH16_VK".into();
            }),
            // an alias / abbreviation for the role -> rejected, not resolved
            ("aliased_role", |b| {
                b.verifier_material_manifests[0].entries[0].role = "groth16".into();
                b.verifier_material_manifests[0].entries[0].label = "groth16".into();
            }),
            // role/label mismatch: a valid role paired with another role's label
            ("label_role_mismatch", |b| {
                b.verifier_material_manifests[1].entries[0].label = "control_root".into();
            }),
            // duplicate role/label (verifier_params overwritten with a 2nd groth16_vk)
            ("duplicate_role", |b| {
                b.verifier_material_manifests[1].entries[3].role = "groth16_vk".into();
                b.verifier_material_manifests[1].entries[3].label = "groth16_vk".into();
            }),
            // an unexpected role for the candidate (SP1 carrying a control_root)
            ("unexpected_role_for_candidate", |b| {
                b.verifier_material_manifests[0]
                    .entries
                    .push(VerifierMaterialEntryJson {
                        role: "control_root".into(),
                        label: "control_root".into(),
                        byte_len: 32,
                        blake3_hex: hex(&[0u8; 32]),
                    });
            }),
            // wrong candidate-role set: SP1 given RISC Zero's four-role coverage
            ("wrong_candidate_role_set", |b| {
                b.verifier_material_manifests[0].entries =
                    b.verifier_material_manifests[1].entries.clone();
            }),
            // missing a required role (RISC0 drops verifier_params)
            ("missing_required_role", |b| {
                b.verifier_material_manifests[1].entries.pop();
            }),
            // noncanonical ordering of an otherwise-correct set
            ("noncanonical_order", |b| {
                b.verifier_material_manifests[1].entries.swap(0, 2);
            }),
        ];
        for (name, mutate) in cases {
            let mut b = valid_bundle();
            mutate(&mut b);
            assert!(
                b.validate().is_err(),
                "case `{name}` must be rejected, never normalized"
            );
        }

        // And prove non-normalization concretely: an uppercase role is NOT accepted
        // as if it had been lowercased.
        let mut b = valid_bundle();
        b.verifier_material_manifests[0].entries[0].role = "GROTH16_VK".into();
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ManifestNonCanonical(_))
        ));
        // the byte-identical canonical spelling still validates, confirming only the
        // representation (not the value) was the reason for rejection.
        let ok = valid_bundle();
        assert_eq!(ok.validate(), Ok(()));
    }

    #[test]
    fn exact_stamp_set_enforced_before_insertion() {
        // Correction 5: the real fixture-acceptance path (bundle validation)
        // requires EXACTLY the four stamps, each once. Dropping ANY one stamp from
        // EITHER candidate's manifest is rejected before insertion...
        for cand_idx in 0..2 {
            for omit in b0_pre_vmat::REQUIRED_STAMPS {
                let mut b = valid_bundle();
                b.verifier_material_manifests[cand_idx].stamp = b0_pre_vmat::REQUIRED_STAMPS
                    .iter()
                    .filter(|s| **s != omit)
                    .map(|s| s.to_string())
                    .collect();
                assert!(
                    matches!(
                        b.validate(),
                        Err(Stage1BundleError::FixtureStampSet { reason: b0_pre_vmat::StampSetError::Missing(m), .. }) if m == omit
                    ),
                    "candidate {cand_idx} omitting {omit} must fail before insertion"
                );
            }
        }
        // ...an empty stamp array is rejected...
        let mut b = valid_bundle();
        b.verifier_material_manifests[0].stamp.clear();
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::FixtureStampSet {
                reason: b0_pre_vmat::StampSetError::Missing(_),
                ..
            })
        ));
        // ...a DUPLICATE stamp is rejected (each stamp must appear once)...
        let mut b = valid_bundle();
        b.verifier_material_manifests[0]
            .stamp
            .push("TEST_ONLY".into());
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::FixtureStampSet {
                reason: b0_pre_vmat::StampSetError::Duplicate(_),
                ..
            })
        ));
        // ...and an UNKNOWN-EXTRA stamp is rejected, even with all four present.
        let mut b = valid_bundle();
        b.verifier_material_manifests[1]
            .stamp
            .push("EXTRA_UNKNOWN".into());
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::FixtureStampSet {
                reason: b0_pre_vmat::StampSetError::Unknown(_),
                ..
            })
        ));
    }

    #[test]
    fn all_reproducible_and_flags_must_be_true() {
        let mut b = valid_bundle();
        b.all_reproducible = false;
        assert!(b.validate().is_err());
        let mut b = valid_bundle();
        b.reproducibility.verifier_material_reproduced = false;
        assert!(b.validate().is_err());
        let mut b = valid_bundle();
        b.native_build_provenance[0].native_arch = false;
        assert!(b.validate().is_err());
    }

    #[test]
    fn guest_closure_fields_are_rejected_structurally_and_by_text_scan() {
        // raw-text scan: the reject-list substring anywhere fails, even in a value
        for k in FORBIDDEN_GUEST_CLOSURE_KEYS {
            let injected = format!(r#"{{"bundle_kind":"{BUNDLE_KIND}","note":"{k}"}}"#);
            assert!(matches!(
                Stage1ResultBundleV1::decode_and_validate(injected.as_bytes()),
                Err(Stage1BundleError::ForbiddenGuestClosure(_))
            ));
        }
        // structural: an unknown top-level member is rejected by deny_unknown_fields
        let mut v = serde_json::to_value(valid_bundle()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra_key".into(), serde_json::json!(1));
        assert!(matches!(
            Stage1ResultBundleV1::decode_and_validate(v.to_string().as_bytes()),
            Err(Stage1BundleError::Parse(_))
        ));
    }

    // ---- Item 2: the full ingest pipeline (build_finalizable_artifact) ----

    #[test]
    fn valid_test_only_bundle_builds_a_finalizable_artifact_without_a_real_hash() {
        let artifact = build_finalizable_artifact(&raw(&valid_bundle())).expect("valid bundle");
        // A finalizable, semantically-consistent artifact was reconstructed IN
        // MEMORY. Its blocked_on is empty and pending inputs are the exact three
        // Stage-1 categories, with per-candidate totals (292 / 352).
        assert!(artifact.is_finalizable());
        assert!(artifact.semantic_violations().is_empty());
        assert_eq!(artifact.finalization.state, "finalizable");
        assert!(artifact.finalization.blocked_on.is_empty());
        let refs = artifact
            .pending_inputs
            .verifier_material_manifests
            .as_ref()
            .unwrap();
        let sp1 = refs.iter().find(|m| m.candidate == "Sp1").unwrap();
        let risc0 = refs.iter().find(|m| m.candidate == "Risc0").unwrap();
        assert_eq!(sp1.total_bytes, 292);
        assert_eq!(risc0.total_bytes, TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL);
        // The in-memory TEST_ONLY artifact CAN produce a synthetic preimage, but
        // this pipeline never writes it and the caller writes only the artifact.
        assert!(crate::protocol_hash(&artifact).is_ok());
    }

    #[test]
    fn every_pipeline_failure_is_all_or_nothing() {
        // Each malformed bundle must make the WHOLE pipeline refuse (no artifact),
        // so a bad bundle can never reach insertion.
        type BundleMut = Box<dyn Fn(&mut Stage1ResultBundleV1)>;
        let cases: Vec<(&str, BundleMut)> = vec![
            (
                "missing_container_tuple",
                Box::new(|b: &mut Stage1ResultBundleV1| {
                    b.candidate_container_digests.pop();
                }),
            ),
            (
                "duplicate_container_tuple",
                Box::new(|b: &mut Stage1ResultBundleV1| {
                    b.candidate_container_digests[7] = b.candidate_container_digests[0].clone();
                }),
            ),
            (
                "extra_container_tuple",
                Box::new(|b: &mut Stage1ResultBundleV1| {
                    b.candidate_container_digests
                        .push(container("Sp1", "base", "X86_64", 0x99));
                }),
            ),
            (
                "not_all_reproducible",
                Box::new(|b: &mut Stage1ResultBundleV1| {
                    b.all_reproducible = false;
                }),
            ),
            (
                "falsified_total",
                Box::new(|b: &mut Stage1ResultBundleV1| {
                    b.verifier_material_manifests[1].total_bytes = 292;
                }),
            ),
            (
                "noncanonical_label",
                Box::new(|b: &mut Stage1ResultBundleV1| {
                    b.verifier_material_manifests[0].entries[0].label = "GROTH16_VK_BYTES".into();
                }),
            ),
            (
                "three_stamp_fixture",
                Box::new(|b: &mut Stage1ResultBundleV1| {
                    b.verifier_material_manifests[0].stamp.pop();
                }),
            ),
        ];
        for (name, mutate) in cases {
            let mut b = valid_bundle();
            mutate(&mut b);
            assert!(
                build_finalizable_artifact(&raw(&b)).is_err(),
                "case `{name}` must refuse insertion"
            );
        }
    }

    #[test]
    fn malformed_bundle_never_reaches_insertion() {
        // Not even a parseable structure survives: unknown field, forbidden guest
        // field, and non-JSON all refuse before any artifact is built.
        let mut v = serde_json::to_value(valid_bundle()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("surprise".into(), serde_json::json!(true));
        assert!(build_finalizable_artifact(v.to_string().as_bytes()).is_err());

        let injected = format!(r#"{{"bundle_kind":"{BUNDLE_KIND}","x":"r0_guest_set_hash"}}"#);
        assert!(matches!(
            build_finalizable_artifact(injected.as_bytes()),
            Err(Stage1BundleError::ForbiddenGuestClosure(_))
        ));

        assert!(build_finalizable_artifact(b"not json at all").is_err());
    }

    // ---- Blocker 2: coherent OCI digest representation (sha256:<64hex>) ----

    #[test]
    fn oci_digest_rule_rejects_bare_uppercase_truncated_and_wrong_algo() {
        let set = |b: &mut Stage1ResultBundleV1, v: &str| {
            b.candidate_container_digests[0].image_digest = v.into();
            b.candidate_container_digests[0].image_digest_build1 = v.into();
            b.candidate_container_digests[0].image_digest_build2 = v.into();
        };
        // BARE 64-hex (missing the required sha256: prefix) is now rejected — this
        // is the reverted freeze: the OCI representation MUST carry the algorithm.
        let mut b = valid_bundle();
        set(&mut b, &syn("bare"));
        assert!(
            b.validate().is_err(),
            "bare 64-hex must be rejected for OCI"
        );
        // uppercase hex body
        let mut b = valid_bundle();
        set(&mut b, &format!("sha256:{}", syn("x").to_uppercase()));
        assert!(b.validate().is_err());
        // truncated (63-char body)
        let mut b = valid_bundle();
        set(&mut b, &format!("sha256:{}", &syn("y")[..63]));
        assert!(b.validate().is_err());
        // a different algorithm prefix is not accepted implicitly
        let mut b = valid_bundle();
        set(&mut b, &format!("sha512:{}", syn("z")));
        assert!(b.validate().is_err());
        // the coherent full sha256:<64hex> form validates
        let ok = valid_bundle();
        assert_eq!(ok.validate(), Ok(()));
    }

    #[test]
    fn oci_digest_rule_rejects_placeholders() {
        for body in [
            "0".repeat(64),                                                            // all-zero
            "2".repeat(64), // all-identical
            "f".repeat(64), // all-0xff
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(), // blocklist
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(), // sha256("")
        ] {
            let ph = format!("sha256:{body}");
            let mut b = valid_bundle();
            b.candidate_container_digests[0].image_digest = ph.clone();
            b.candidate_container_digests[0].image_digest_build1 = ph.clone();
            b.candidate_container_digests[0].image_digest_build2 = ph.clone();
            assert!(b.validate().is_err(), "placeholder {ph} must be rejected");
        }
    }

    // ---- Correction 3: derived reproducibility cross-checks ----

    #[test]
    fn paired_build_digests_are_compared_by_the_validator_itself() {
        // build1 != build2 => the validator DERIVES non-reproducibility and refuses,
        // regardless of any supplied boolean.
        let mut b = valid_bundle();
        b.candidate_container_digests[0].image_digest_build2 = oci("divergent");
        // keep the (untrusted) reproducibility booleans "true" to prove they are
        // not what the decision rests on.
        assert!(b.all_reproducible);
        assert!(b.validate().is_err());
    }

    #[test]
    fn agreed_digest_must_equal_the_reproduced_build_digest() {
        let mut b = valid_bundle();
        // build1 == build2 but the agreed image_digest is a third value.
        b.candidate_container_digests[0].image_digest = oci("third-value");
        assert!(b.validate().is_err());
    }

    #[test]
    fn base_entry_is_an_immutable_input_bound_to_base_digest() {
        // Blocker 6: a base entry's identity IS the pinned base digest. If its
        // image_digest (and paired builds) is any OTHER real digest — e.g. a
        // relabelled builder image — the base-immutable-input rule refuses it.
        let mut b = valid_bundle();
        let base = &mut b.candidate_container_digests[0]; // Sp1/base/X86_64
        assert_eq!(base.role, "base");
        let other = oci("some-rebuilt-image-not-the-pinned-base");
        base.image_digest = other.clone();
        base.image_digest_build1 = other.clone();
        base.image_digest_build2 = other;
        // build1==build2 and image_digest==build1 both hold, so the ONLY failing rule
        // is the base-immutable-input binding.
        let err = b.validate().unwrap_err();
        assert!(
            matches!(&err, Stage1BundleError::Rule(m) if m.contains("immutable input")),
            "expected the base-immutable-input rule, got {err}"
        );
    }

    #[test]
    fn builder_entry_identity_must_equal_its_builder_image() {
        // Blocker 6: a builder entry's identity IS its builder image digest. A builder
        // entry whose image_digest is some unrelated real digest is refused.
        let mut b = valid_bundle();
        // index 2 = Sp1/builder/X86_64
        let builder = &mut b.candidate_container_digests[2];
        assert_eq!(builder.role, "builder");
        let other = oci("an-image-that-is-not-the-recorded-builder");
        builder.image_digest = other.clone();
        builder.image_digest_build1 = other.clone();
        builder.image_digest_build2 = other;
        let err = b.validate().unwrap_err();
        assert!(
            matches!(&err, Stage1BundleError::Rule(m) if m.contains("builder_oci_digest")),
            "expected the builder-identity rule, got {err}"
        );
    }

    #[test]
    fn missing_base_or_builder_identity_is_rejected() {
        let mut b = valid_bundle();
        b.candidate_container_digests[0].base_image_ref = "  ".into();
        assert!(b.validate().is_err());
        let mut b = valid_bundle();
        b.candidate_container_digests[0].builder_oci_ref = String::new();
        assert!(b.validate().is_err());
    }

    #[test]
    fn bad_source_commit_and_inconsistent_per_candidate_commit_rejected() {
        // all-zero source commit
        let mut b = valid_bundle();
        b.candidate_container_digests[0].source_commit_hex = "0".repeat(40);
        assert!(b.validate().is_err());
        // two tuples of the SAME candidate carrying different commits (provenance
        // does not match the candidate)
        let mut b = valid_bundle();
        b.candidate_container_digests[0].source_commit_hex = syn("other-commit")[..40].to_string();
        assert!(b.validate().is_err());
    }

    #[test]
    fn non_native_host_arch_and_inconsistent_flags_rejected() {
        // cross-compiled: host_arch != arch
        let mut b = valid_bundle();
        b.native_build_provenance[0].host_arch = "Aarch64".into();
        b.native_build_provenance[0].arch = "X86_64".into();
        assert!(b.validate().is_err());
        // native_arch flag lies (host_arch == arch but native_arch=false)
        let mut b = valid_bundle();
        b.native_build_provenance[0].native_arch = false;
        assert!(b.validate().is_err());
        // two_build_reproducible flag lies (digests match but it claims false)
        let mut b = valid_bundle();
        b.native_build_provenance[0].two_build_reproducible = false;
        assert!(b.validate().is_err());
    }

    // ---- Correction 3: tool identities cross-checked against frozen pins ----

    #[test]
    fn tool_identities_must_match_frozen_pins_and_be_complete() {
        // wrong rust version
        let mut b = valid_bundle();
        b.tool_identities[0].rust_version = "1.87.0".into();
        assert!(b.validate().is_err());
        // wrong proof-tool version
        let mut b = valid_bundle();
        b.tool_identities[0].proof_tools[0].version = "6.3.0".into();
        assert!(b.validate().is_err());
        // missing an entry
        let mut b = valid_bundle();
        b.tool_identities.pop();
        assert!(b.validate().is_err());
        // extra unexpected proof tool for the candidate
        let mut b = valid_bundle();
        b.tool_identities[0]
            .proof_tools
            .push(tool("surprise", "1.0.0"));
        assert!(b.validate().is_err());
        // placeholder version string
        let mut b = valid_bundle();
        b.tool_identities[0].proof_tools[0].version = "TODO".into();
        assert!(b.validate().is_err());
    }

    // ---- Blocker 3: complete tool identity (fail-closed in authoritative mode) ----

    #[test]
    fn authoritative_tool_identity_rejects_absent_or_synthetic_fields() {
        // absent artifact identity
        let mut b = valid_bundle();
        b.tool_identities[0].proof_tools[0].artifact_identity = "  ".into();
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ToolIdentity(_))
        ));
        // synthetic artifact identity may never stand in for real metadata
        let mut b = valid_bundle();
        b.tool_identities[0].proof_tools[0].artifact_identity =
            format!("{TEST_ONLY_TOOL_SENTINEL}://sp1");
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ToolIdentity(_))
        ));
        // absent / unknown checksum algorithm
        let mut b = valid_bundle();
        b.tool_identities[0].proof_tools[0].checksum_algorithm = String::new();
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ToolIdentity(_))
        ));
        // checksum length disagrees with the named algorithm (sha256 wants 64 hex)
        let mut b = valid_bundle();
        b.tool_identities[0].proof_tools[0].checksum_hex = "abcd".into();
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ToolIdentity(_))
        ));
        // absent install entrypoint
        let mut b = valid_bundle();
        b.tool_identities[0].proof_tools[0].install_entrypoint = String::new();
        assert!(matches!(
            b.validate(),
            Err(Stage1BundleError::ToolIdentity(_))
        ));
    }

    #[test]
    fn valid_bundle_with_full_reproducibility_evidence_still_accepts() {
        // sanity: the extended, cross-checked valid_bundle still passes end to end.
        let b = valid_bundle();
        assert_eq!(b.validate(), Ok(()));
        assert!(build_finalizable_artifact(&raw(&b)).is_ok());
    }

    // ---- Blocker 4: classification gate keeps synthetic bundles out ----

    #[test]
    fn non_authoritative_classification_never_finalizes() {
        // A structurally-complete bundle re-classified TEST_ONLY / NON_SELECTION
        // still validates (with synthetic tool identities) but can NEVER build a
        // finalizable artifact.
        for class in [
            BundleClassification::TestOnly,
            BundleClassification::NonSelection,
        ] {
            let mut b = valid_bundle();
            b.classification = class;
            // switch the tool identities to their unmistakably-synthetic form so the
            // non-authoritative validation accepts them.
            for t in &mut b.tool_identities {
                for pt in &mut t.proof_tools {
                    pt.artifact_identity = format!("{TEST_ONLY_TOOL_SENTINEL}://{}", pt.name);
                    pt.install_entrypoint = format!("{TEST_ONLY_TOOL_SENTINEL}:{}", pt.name);
                }
            }
            assert_eq!(b.validate(), Ok(()), "{class:?} bundle must still validate");
            // ...yet authoritative ingest refuses it outright.
            assert!(matches!(
                build_finalizable_artifact(&raw(&b)),
                Err(Stage1BundleError::NonAuthoritativeClassification(_))
            ));
            // ...and the explicit test-only path accepts it but yields NO artifact.
            assert_eq!(validate_test_only_bundle(&raw(&b)), Ok(class));
        }
        // conversely, an authoritative bundle is refused by the test-only path.
        assert!(matches!(
            validate_test_only_bundle(&raw(&valid_bundle())),
            Err(Stage1BundleError::Rule(_))
        ));
    }
}

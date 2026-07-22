//! Canonical `VerifierMaterialManifestV1` primitives, shared by the B0-PRE
//! reference validator (`b0-pre-validator`) and the two venue verifier-material
//! extractors (`harness/{sp1,risc0}-verifier-material`).
//!
//! This crate is the SINGLE canonical implementation of:
//!   * role-label construction ([`canonical_label`] / [`role_from_canonical_label`]),
//!   * entry sorting (the frozen `(role, label)` order — [`sort_entries`]),
//!   * canonical encoding ([`encode`]),
//!   * total-byte computation ([`total_bytes`]),
//!   * manifest identity ([`identity`] `= BLAKE3(encode)`),
//!   * and the four TEST_ONLY fixture stamps ([`REQUIRED_STAMPS`]).
//!
//! The extractors no longer hand-roll a wire replica; they call this. The
//! validator's `VerifierMaterialManifestV1::{encode,identity,verifier_material_bytes}`
//! and `from_canonical` delegate here too, so the validator's passing tests
//! cover the exact same bytes the extractors emit — this crate is the bridge, not
//! a mirror.
//!
//! Tool-only, workspace-excluded, blake3-only. No production, guest, or candidate
//! crate depends on it.

#![forbid(unsafe_code)]

/// Zero-pad an ASCII tag to 32 bytes at compile time (identical rule to the
/// validator `tags::pad32`). Panics (const) if longer than 32 bytes.
pub const fn pad32(s: &[u8]) -> [u8; 32] {
    assert!(s.len() <= 32, "structured domain tag exceeds 32 bytes");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < s.len() {
        out[i] = s[i];
        i += 1;
    }
    out
}

/// Frozen verifier-material manifest schema version (== validator
/// `consts::SCHEMA_VERSION`).
pub const SCHEMA_VERSION: u16 = 1;

/// Candidate wire discriminants (== validator `Candidate::to_repr()`).
pub const CANDIDATE_SP1: u16 = 1;
pub const CANDIDATE_RISC0: u16 = 2;

/// Verifier-material role wire discriminants (== validator
/// `VerifierMaterialRole::to_repr()`).
pub const ROLE_GROTH16_VK: u8 = 0;
pub const ROLE_CONTROL_ROOT: u8 = 1;
pub const ROLE_CONTROL_ID: u8 = 2;
pub const ROLE_VERIFIER_PARAMS: u8 = 3;

/// The frozen verifier-material domain tag as its unpadded ASCII string. The one
/// source of the `domain` string the extractors emit.
pub const VERIFIER_MATERIAL_TAG_ASCII: &str = "SUMCHAIN/B0PRE/VMAT/v1";

/// The frozen 32-byte verifier-material domain tag, ASCII zero-padded (==
/// validator `tags::VERIFIER_MATERIAL_TAG`). It is the leading field of the
/// canonical encoding, present exactly once, self-domaining the identity.
pub const VERIFIER_MATERIAL_TAG: [u8; 32] = pad32(VERIFIER_MATERIAL_TAG_ASCII.as_bytes());

/// The four stamps every TEST_ONLY / NON_SELECTION verifier-material fixture must
/// carry so it can never be mistaken for official evidence. The real
/// fixture-acceptance path (validator bundle validation) and the extractor
/// contract tests both require ALL four — a three-stamp fixture is rejected.
pub const REQUIRED_STAMPS: [&str; 4] = [
    "TEST_ONLY",
    "NON_SELECTION",
    "INVALID_FOR_R0",
    "NOT_AN_OFFICIAL_GUEST",
];

/// The single canonical label for a role: the lowercase role name. `None` for an
/// unknown discriminant.
pub const fn canonical_label(role: u8) -> Option<&'static str> {
    match role {
        ROLE_GROTH16_VK => Some("groth16_vk"),
        ROLE_CONTROL_ROOT => Some("control_root"),
        ROLE_CONTROL_ID => Some("control_id"),
        ROLE_VERIFIER_PARAMS => Some("verifier_params"),
        _ => None,
    }
}

/// Parse a canonical lowercase role label back to its role discriminant,
/// rejecting any non-canonical (uppercase / aliased) spelling. `None` = reject.
pub fn role_from_canonical_label(label: &str) -> Option<u8> {
    match label {
        "groth16_vk" => Some(ROLE_GROTH16_VK),
        "control_root" => Some(ROLE_CONTROL_ROOT),
        "control_id" => Some(ROLE_CONTROL_ID),
        "verifier_params" => Some(ROLE_VERIFIER_PARAMS),
        _ => None,
    }
}

/// The stamps from [`REQUIRED_STAMPS`] that are absent from `present`, in canonical
/// order. Empty = every required stamp is present.
pub fn missing_stamps<S: AsRef<str>>(present: &[S]) -> Vec<&'static str> {
    REQUIRED_STAMPS
        .iter()
        .copied()
        .filter(|req| !present.iter().any(|p| p.as_ref() == *req))
        .collect()
}

/// True iff every required stamp is present (order and extras irrelevant).
pub fn all_required_stamps_present<S: AsRef<str>>(present: &[S]) -> bool {
    missing_stamps(present).is_empty()
}

/// A precise reason a stamp set is not EXACTLY the four required stamps, each
/// present once. Owned by this crate so the exact-set policy lives in one place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StampSetError {
    /// A required stamp is absent.
    Missing(&'static str),
    /// A stamp appeared more than once.
    Duplicate(String),
    /// A stamp outside [`REQUIRED_STAMPS`] appeared.
    Unknown(String),
}

impl core::fmt::Display for StampSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StampSetError::Missing(s) => write!(f, "missing required stamp {s}"),
            StampSetError::Duplicate(s) => write!(f, "duplicate stamp {s}"),
            StampSetError::Unknown(s) => write!(f, "unknown stamp {s}"),
        }
    }
}

impl std::error::Error for StampSetError {}

/// Enforce the EXACT authority-boundary stamp policy: the four [`REQUIRED_STAMPS`],
/// each present exactly once — no missing stamp, no duplicate, and no
/// unknown-extra. [`all_required_stamps_present`] (used by the extractor contract
/// tests) tolerates extras and ordering; this stricter policy is what the Stage-1
/// insertion boundary applies. The reason is returned in a stable order: an
/// unknown or duplicated stamp is reported as encountered, then any missing
/// required stamp in canonical order.
pub fn check_exact_stamp_set<S: AsRef<str>>(present: &[S]) -> Result<(), StampSetError> {
    let mut seen: Vec<&str> = Vec::new();
    for s in present {
        let s = s.as_ref();
        if !REQUIRED_STAMPS.contains(&s) {
            return Err(StampSetError::Unknown(s.to_string()));
        }
        if seen.contains(&s) {
            return Err(StampSetError::Duplicate(s.to_string()));
        }
        seen.push(s);
    }
    for req in REQUIRED_STAMPS {
        if !seen.contains(&req) {
            return Err(StampSetError::Missing(req));
        }
    }
    Ok(())
}

/// Maximum canonical label byte length. A label longer than this is rejected by
/// [`encode`] (and mirrors the validator decoder's `MAX_LABEL_LEN`). Chosen so
/// every canonical role label (`verifier_params`, the longest, is 15 bytes) fits
/// with wide margin while any adversarial over-long label fails closed.
pub const MAX_LABEL_LEN: usize = 64;
/// Maximum number of manifest entries. The largest real coverage (RISC Zero's
/// four roles) is 4; anything beyond this is rejected. Mirrors the validator
/// decoder's `MAX_ENTRIES`.
pub const MAX_ENTRIES: usize = 64;

/// Every way the canonical codec can refuse to encode / canonicalize a manifest.
/// The codec is fail-closed: it returns one of these rather than silently
/// truncating a length, hashing an oversized/invalid manifest, or panicking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmatError {
    /// The candidate discriminant is not a defined value (1 = SP1, 2 = RISC0).
    UnknownCandidate { candidate: u16 },
    /// A role discriminant has no canonical label (not 0..=3).
    UnknownRole { role: u8 },
    /// A label was empty (a canonical manifest never carries an empty label).
    EmptyLabel,
    /// A label contained a non-printable / non-ASCII byte, so it cannot round-trip
    /// through the ASCII-only wire form.
    NonAsciiLabel,
    /// A label exceeded [`MAX_LABEL_LEN`] (or would not fit the `u16` length
    /// prefix) — the lossy `as u16` cast is replaced by this checked rejection.
    LabelTooLong { len: usize, max: usize },
    /// The entry count exceeded [`MAX_ENTRIES`] (or would not fit the `u32` count
    /// prefix) — the lossy `as u32` cast is replaced by this checked rejection.
    TooManyEntries { count: usize, max: usize },
    /// A label did not equal its role's single canonical label (only surfaced by
    /// [`ensure_canonical`]; [`encode`] preserves a supplied non-canonical-cased
    /// label so the byte decoder can still observe and reject it).
    NonCanonicalLabel { role: u8 },
    /// Two entries carried the same `(role, label)` (only surfaced by
    /// [`ensure_canonical`]).
    DuplicateRole { role: u8 },
    /// Entries were not in strictly ascending `(role, label)` order (only surfaced
    /// by [`ensure_canonical`]).
    NonCanonicalOrder,
    /// Summing `byte_len` overflowed `u64`.
    Overflow,
}

impl core::fmt::Display for VmatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VmatError::UnknownCandidate { candidate } => {
                write!(f, "unknown candidate discriminant {candidate}")
            }
            VmatError::UnknownRole { role } => write!(f, "unknown verifier-material role {role}"),
            VmatError::EmptyLabel => write!(f, "empty verifier-material label"),
            VmatError::NonAsciiLabel => write!(f, "non-ASCII verifier-material label"),
            VmatError::LabelTooLong { len, max } => {
                write!(f, "label length {len} exceeds max {max}")
            }
            VmatError::TooManyEntries { count, max } => {
                write!(f, "entry count {count} exceeds max {max}")
            }
            VmatError::NonCanonicalLabel { role } => {
                write!(f, "label is not the canonical label for role {role}")
            }
            VmatError::DuplicateRole { role } => write!(f, "duplicate entry for role {role}"),
            VmatError::NonCanonicalOrder => write!(f, "entries are not in canonical order"),
            VmatError::Overflow => write!(f, "byte_len sum overflowed u64"),
        }
    }
}

impl std::error::Error for VmatError {}

/// True iff `candidate` is one of the two defined candidate discriminants.
const fn candidate_defined(candidate: u16) -> bool {
    candidate == CANDIDATE_SP1 || candidate == CANDIDATE_RISC0
}

/// One raw verifier-material entry, in `(role, label, byte_len, hash)` form.
/// `label` is borrowed so both an owned `String` (validator) and a `&'static str`
/// (extractor) map in without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub role: u8,
    pub label: &'a str,
    pub byte_len: u64,
    pub hash: [u8; 32],
}

/// The frozen canonical order: ascending `(role discriminant, label bytes)`. The
/// ONE sort rule; both the validator's `from_canonical` and the extractors call
/// it, so "arbitrary input order" always collapses to the same canonical bytes.
pub fn sort_entries(entries: &mut [Entry<'_>]) {
    entries.sort_by(|a, b| (a.role, a.label.as_bytes()).cmp(&(b.role, b.label.as_bytes())));
}

/// Canonical wire encoding of a manifest, in the entry order GIVEN (no implicit
/// sort — the validator's byte decoder must be able to observe a deliberately
/// mis-ordered manifest and reject it, so encoding preserves order; callers that
/// want canonical bytes call [`sort_entries`] first).
///
/// Fail-closed: rejects an unknown candidate/role discriminant, an empty /
/// non-ASCII / over-long label, and an over-large entry count, with CHECKED
/// `u16` / `u32` length conversions replacing the former lossy `as` casts, so no
/// truncated length or invalid manifest can ever be hashed. It deliberately does
/// NOT reject a non-canonically-cased label or a mis-ordering — those remain the
/// byte decoder's job (see [`ensure_canonical`] for the strict canonical gate).
///
/// Layout (all integers little-endian):
/// `tag ‖ u16 schema_version ‖ u16 candidate ‖ u32 count ‖`
/// then for each entry `u16 label_len ‖ label ‖ u8 role ‖ u64 byte_len ‖ 32B hash`.
pub fn encode(candidate: u16, entries: &[Entry<'_>]) -> Result<Vec<u8>, VmatError> {
    if !candidate_defined(candidate) {
        return Err(VmatError::UnknownCandidate { candidate });
    }
    // Checked count conversion: never a lossy `as u32`, and bounded by MAX_ENTRIES.
    if entries.len() > MAX_ENTRIES {
        return Err(VmatError::TooManyEntries {
            count: entries.len(),
            max: MAX_ENTRIES,
        });
    }
    let count = u32::try_from(entries.len()).map_err(|_| VmatError::TooManyEntries {
        count: entries.len(),
        max: MAX_ENTRIES,
    })?;

    let mut w = Vec::new();
    w.extend_from_slice(&VERIFIER_MATERIAL_TAG);
    w.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    w.extend_from_slice(&candidate.to_le_bytes());
    w.extend_from_slice(&count.to_le_bytes());
    for e in entries {
        if canonical_label(e.role).is_none() {
            return Err(VmatError::UnknownRole { role: e.role });
        }
        if e.label.is_empty() {
            return Err(VmatError::EmptyLabel);
        }
        if !e.label.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(VmatError::NonAsciiLabel);
        }
        if e.label.len() > MAX_LABEL_LEN {
            return Err(VmatError::LabelTooLong {
                len: e.label.len(),
                max: MAX_LABEL_LEN,
            });
        }
        // Checked label-length conversion: never a lossy `as u16`.
        let label_len = u16::try_from(e.label.len()).map_err(|_| VmatError::LabelTooLong {
            len: e.label.len(),
            max: MAX_LABEL_LEN,
        })?;
        w.extend_from_slice(&label_len.to_le_bytes());
        w.extend_from_slice(e.label.as_bytes());
        w.push(e.role);
        w.extend_from_slice(&e.byte_len.to_le_bytes());
        w.extend_from_slice(&e.hash);
    }
    Ok(w)
}

/// Manifest identity `= BLAKE3(encode(candidate, entries))`. Self-domained by the
/// leading tag; this is the ONLY value a Stage-1 bundle may present as
/// `manifest_hash_hex`. Propagates every [`encode`] rejection, so an invalid
/// manifest yields NO identity rather than a hash of truncated bytes.
pub fn identity(candidate: u16, entries: &[Entry<'_>]) -> Result<[u8; 32], VmatError> {
    Ok(blake3::hash(&encode(candidate, entries)?).into())
}

/// `Σ byte_len`, with arithmetic overflow rejected.
pub fn total_bytes(entries: &[Entry<'_>]) -> Result<u64, VmatError> {
    let mut total: u64 = 0;
    for e in entries {
        total = total.checked_add(e.byte_len).ok_or(VmatError::Overflow)?;
    }
    Ok(total)
}

/// The strict canonical gate on top of the byte layout: every entry must carry a
/// defined role's single canonical label, entries must be strictly ascending in
/// `(role, label)` with no duplicate role, the count must be within
/// [`MAX_ENTRIES`], and the candidate must be defined. This is where a
/// non-canonically-cased label, a duplicate role, or a mis-ordering is rejected;
/// the reference validator's `validate_canonical` delegates here so the policy
/// lives in exactly one place. It does NOT enforce per-candidate role coverage
/// (which roles a given candidate must carry) — that candidate→role-set policy
/// stays with the validator.
pub fn ensure_canonical(candidate: u16, entries: &[Entry<'_>]) -> Result<(), VmatError> {
    if !candidate_defined(candidate) {
        return Err(VmatError::UnknownCandidate { candidate });
    }
    if entries.len() > MAX_ENTRIES {
        return Err(VmatError::TooManyEntries {
            count: entries.len(),
            max: MAX_ENTRIES,
        });
    }
    let mut prev: Option<(u8, &str)> = None;
    for e in entries {
        let canon = canonical_label(e.role).ok_or(VmatError::UnknownRole { role: e.role })?;
        if e.label != canon {
            return Err(VmatError::NonCanonicalLabel { role: e.role });
        }
        let key = (e.role, e.label);
        if let Some(p) = prev {
            if key == p {
                return Err(VmatError::DuplicateRole { role: e.role });
            }
            if key < p {
                return Err(VmatError::NonCanonicalOrder);
            }
        }
        prev = Some(key);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(role: u8, len: u64, h: u8) -> Entry<'static> {
        Entry {
            role,
            label: canonical_label(role).unwrap(),
            byte_len: len,
            hash: [h; 32],
        }
    }

    #[test]
    fn tag_matches_frozen_ascii() {
        assert_eq!(&VERIFIER_MATERIAL_TAG[..22], b"SUMCHAIN/B0PRE/VMAT/v1");
        assert_eq!(VERIFIER_MATERIAL_TAG_ASCII, "SUMCHAIN/B0PRE/VMAT/v1");
        assert_eq!(
            VERIFIER_MATERIAL_TAG_ASCII.as_bytes(),
            &VERIFIER_MATERIAL_TAG[..VERIFIER_MATERIAL_TAG_ASCII.len()]
        );
        assert!(VERIFIER_MATERIAL_TAG[22..].iter().all(|&b| b == 0));
    }

    #[test]
    fn labels_roundtrip_and_reject_noncanonical() {
        for r in [
            ROLE_GROTH16_VK,
            ROLE_CONTROL_ROOT,
            ROLE_CONTROL_ID,
            ROLE_VERIFIER_PARAMS,
        ] {
            let l = canonical_label(r).unwrap();
            assert_eq!(role_from_canonical_label(l), Some(r));
        }
        assert_eq!(canonical_label(4), None);
        // uppercase legacy / aliased spellings are NOT canonical labels
        assert_eq!(role_from_canonical_label("GROTH16_VK_BYTES"), None);
        assert_eq!(role_from_canonical_label("groth16"), None);
        assert_eq!(role_from_canonical_label("Groth16Vk"), None);
    }

    #[test]
    fn sort_is_frozen_role_then_label() {
        let mut v = vec![
            e(ROLE_VERIFIER_PARAMS, 4, 3),
            e(ROLE_GROTH16_VK, 1, 0),
            e(ROLE_CONTROL_ID, 3, 2),
            e(ROLE_CONTROL_ROOT, 2, 1),
        ];
        sort_entries(&mut v);
        let roles: Vec<u8> = v.iter().map(|x| x.role).collect();
        assert_eq!(
            roles,
            [
                ROLE_GROTH16_VK,
                ROLE_CONTROL_ROOT,
                ROLE_CONTROL_ID,
                ROLE_VERIFIER_PARAMS
            ]
        );
    }

    #[test]
    fn encode_layout_is_byte_stable_golden() {
        // A frozen golden byte vector pins the wire format so it cannot drift.
        let entries = [e(ROLE_GROTH16_VK, 292, 7)];
        let bytes = encode(CANDIDATE_SP1, &entries).unwrap();
        // tag(32) + sv(2) + cand(2) + count(4) + [label_len(2)+"groth16_vk"(10)
        //   + role(1) + byte_len(8) + hash(32)]
        assert_eq!(bytes.len(), 32 + 2 + 2 + 4 + (2 + 10 + 1 + 8 + 32));
        assert_eq!(&bytes[..22], b"SUMCHAIN/B0PRE/VMAT/v1");
        assert_eq!(&bytes[32..34], &SCHEMA_VERSION.to_le_bytes());
        assert_eq!(&bytes[34..36], &CANDIDATE_SP1.to_le_bytes());
        assert_eq!(&bytes[36..40], &1u32.to_le_bytes());
        assert_eq!(&bytes[40..42], &10u16.to_le_bytes());
        assert_eq!(&bytes[42..52], b"groth16_vk");
        assert_eq!(bytes[52], ROLE_GROTH16_VK);
        assert_eq!(&bytes[53..61], &292u64.to_le_bytes());
        assert_eq!(&bytes[61..93], &[7u8; 32]);
        // identity == BLAKE3(encode)
        let want: [u8; 32] = blake3::hash(&bytes).into();
        assert_eq!(identity(CANDIDATE_SP1, &entries).unwrap(), want);
    }

    #[test]
    fn total_bytes_sums_and_rejects_overflow() {
        let v = [e(ROLE_GROTH16_VK, 256, 0), e(ROLE_CONTROL_ROOT, 96, 1)];
        assert_eq!(total_bytes(&v), Ok(352));
        let big = [e(ROLE_GROTH16_VK, u64::MAX, 0), e(ROLE_CONTROL_ROOT, 1, 1)];
        assert_eq!(total_bytes(&big), Err(VmatError::Overflow));
    }

    // ---- Correction 1: adversarial boundary tests for EVERY codec rejection ----

    /// Build an entry with an arbitrary (possibly non-canonical) label so the
    /// boundary conditions can be exercised directly.
    fn raw(role: u8, label: &'static str, len: u64) -> Entry<'static> {
        Entry {
            role,
            label,
            byte_len: len,
            hash: [role; 32],
        }
    }

    #[test]
    fn encode_rejects_unknown_candidate() {
        let entries = [e(ROLE_GROTH16_VK, 1, 0)];
        assert_eq!(
            encode(0, &entries),
            Err(VmatError::UnknownCandidate { candidate: 0 })
        );
        assert_eq!(
            encode(3, &entries),
            Err(VmatError::UnknownCandidate { candidate: 3 })
        );
        // identity propagates the same rejection (no hash of an invalid manifest)
        assert_eq!(
            identity(0, &entries),
            Err(VmatError::UnknownCandidate { candidate: 0 })
        );
    }

    #[test]
    fn encode_rejects_unknown_role() {
        let entries = [raw(9, "groth16_vk", 1)];
        assert_eq!(
            encode(CANDIDATE_SP1, &entries),
            Err(VmatError::UnknownRole { role: 9 })
        );
    }

    #[test]
    fn encode_rejects_empty_and_non_ascii_labels() {
        assert_eq!(
            encode(CANDIDATE_SP1, &[raw(ROLE_GROTH16_VK, "", 1)]),
            Err(VmatError::EmptyLabel)
        );
        // a non-printable byte inside the label
        assert_eq!(
            encode(CANDIDATE_SP1, &[raw(ROLE_GROTH16_VK, "groth16\u{7f}", 1)]),
            Err(VmatError::NonAsciiLabel)
        );
        // a non-ASCII (multibyte) label
        assert_eq!(
            encode(CANDIDATE_SP1, &[raw(ROLE_GROTH16_VK, "grothé", 1)]),
            Err(VmatError::NonAsciiLabel)
        );
    }

    #[test]
    fn encode_rejects_oversized_label_via_checked_conversion() {
        let long: &'static str = Box::leak(("a".repeat(MAX_LABEL_LEN + 1)).into_boxed_str());
        assert_eq!(
            encode(CANDIDATE_SP1, &[raw(ROLE_GROTH16_VK, long, 1)]),
            Err(VmatError::LabelTooLong {
                len: MAX_LABEL_LEN + 1,
                max: MAX_LABEL_LEN,
            })
        );
    }

    #[test]
    fn encode_rejects_too_many_entries() {
        let entries: Vec<Entry> = (0..=MAX_ENTRIES)
            .map(|_| e(ROLE_GROTH16_VK, 1, 0))
            .collect();
        assert_eq!(
            encode(CANDIDATE_SP1, &entries),
            Err(VmatError::TooManyEntries {
                count: MAX_ENTRIES + 1,
                max: MAX_ENTRIES,
            })
        );
    }

    #[test]
    fn ensure_canonical_accepts_the_two_real_coverages() {
        // SP1: single groth16_vk.
        assert_eq!(
            ensure_canonical(CANDIDATE_SP1, &[e(ROLE_GROTH16_VK, 292, 0)]),
            Ok(())
        );
        // RISC0: four roles in ascending order.
        let mut v = vec![
            e(ROLE_GROTH16_VK, 256, 0),
            e(ROLE_CONTROL_ROOT, 32, 1),
            e(ROLE_CONTROL_ID, 32, 2),
            e(ROLE_VERIFIER_PARAMS, 32, 3),
        ];
        sort_entries(&mut v);
        assert_eq!(ensure_canonical(CANDIDATE_RISC0, &v), Ok(()));
    }

    #[test]
    fn ensure_canonical_rejects_noncanonical_label_dup_and_order() {
        // a non-canonically-cased label (encode still accepts it; the strict gate
        // does not)
        assert_eq!(
            ensure_canonical(CANDIDATE_SP1, &[raw(ROLE_GROTH16_VK, "GROTH16_VK", 1)]),
            Err(VmatError::NonCanonicalLabel {
                role: ROLE_GROTH16_VK
            })
        );
        // ...and encode DOES accept that same non-canonical label (order/label-case
        // are the decoder's job, not the byte encoder's).
        assert!(encode(CANDIDATE_SP1, &[raw(ROLE_GROTH16_VK, "GROTH16_VK", 1)]).is_ok());
        // duplicate role
        assert_eq!(
            ensure_canonical(
                CANDIDATE_RISC0,
                &[e(ROLE_GROTH16_VK, 1, 0), e(ROLE_GROTH16_VK, 1, 0)]
            ),
            Err(VmatError::DuplicateRole {
                role: ROLE_GROTH16_VK
            })
        );
        // descending / mis-ordered
        assert_eq!(
            ensure_canonical(
                CANDIDATE_RISC0,
                &[e(ROLE_CONTROL_ROOT, 1, 1), e(ROLE_GROTH16_VK, 1, 0)]
            ),
            Err(VmatError::NonCanonicalOrder)
        );
        // unknown role / candidate
        assert_eq!(
            ensure_canonical(CANDIDATE_SP1, &[raw(9, "x", 1)]),
            Err(VmatError::UnknownRole { role: 9 })
        );
        assert_eq!(
            ensure_canonical(7, &[e(ROLE_GROTH16_VK, 1, 0)]),
            Err(VmatError::UnknownCandidate { candidate: 7 })
        );
    }

    #[test]
    fn stamp_policy_requires_all_four() {
        assert!(all_required_stamps_present(&REQUIRED_STAMPS));
        let three = ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0"];
        assert!(!all_required_stamps_present(&three));
        assert_eq!(missing_stamps(&three), vec!["NOT_AN_OFFICIAL_GUEST"]);
        // order and extra stamps are irrelevant; all four must be present
        let scrambled = [
            "NOT_AN_OFFICIAL_GUEST",
            "extra",
            "INVALID_FOR_R0",
            "TEST_ONLY",
            "NON_SELECTION",
        ];
        assert!(all_required_stamps_present(&scrambled));
    }

    #[test]
    fn exact_stamp_set_requires_the_four_each_once_no_extra() {
        // exactly the four, in any order -> accepted
        assert_eq!(check_exact_stamp_set(&REQUIRED_STAMPS), Ok(()));
        assert_eq!(
            check_exact_stamp_set(&[
                "NOT_AN_OFFICIAL_GUEST",
                "TEST_ONLY",
                "INVALID_FOR_R0",
                "NON_SELECTION",
            ]),
            Ok(())
        );
        // missing one
        assert_eq!(
            check_exact_stamp_set(&["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0"]),
            Err(StampSetError::Missing("NOT_AN_OFFICIAL_GUEST"))
        );
        // duplicate
        assert_eq!(
            check_exact_stamp_set(&[
                "TEST_ONLY",
                "TEST_ONLY",
                "NON_SELECTION",
                "INVALID_FOR_R0",
                "NOT_AN_OFFICIAL_GUEST",
            ]),
            Err(StampSetError::Duplicate("TEST_ONLY".into()))
        );
        // unknown-extra (all four present, but a fifth unknown stamp) -> rejected,
        // unlike `all_required_stamps_present` which tolerates extras.
        let with_extra = [
            "TEST_ONLY",
            "NON_SELECTION",
            "INVALID_FOR_R0",
            "NOT_AN_OFFICIAL_GUEST",
            "SOMETHING_ELSE",
        ];
        assert!(all_required_stamps_present(&with_extra));
        assert_eq!(
            check_exact_stamp_set(&with_extra),
            Err(StampSetError::Unknown("SOMETHING_ELSE".into()))
        );
        // empty
        assert_eq!(
            check_exact_stamp_set::<&str>(&[]),
            Err(StampSetError::Missing("TEST_ONLY"))
        );
    }
}

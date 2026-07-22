//! `VerifierMaterialManifestV1` — variable (plan §8/§12).
//!
//! Entries are sorted by `(role, label)`, duplicates rejected;
//! `verifier_material_bytes = Σ byte_len`.
//!
//! **Identity (single self-domain, approved rule):** the canonical encoding
//! already begins with the exact 32-byte `VERIFIER_MATERIAL` tag, so
//!
//! ```text
//! verifier_material_manifest_hash = BLAKE3(canonical_encode(manifest))
//! ```
//!
//! The tag is the domain prefix, present exactly once at offset 0. The earlier
//! prose that prepended `VERIFIER_MATERIAL` a *second* time was a mistake and is
//! superseded: there is no double prefix anywhere. This is the identity bound by
//! the envelope, benchmark records, allowlist entries, result set, and `.hash`.

use crate::codec::{DecodeError, Reader};
use crate::consts;
use crate::enums::{Candidate, VerifierMaterialRole};
use crate::tags::VERIFIER_MATERIAL_TAG;

/// Sourced from the shared canonical primitive so the decoder maxima and the
/// encoder maxima can never drift apart.
pub const MAX_LABEL_LEN: u32 = b0_pre_vmat::MAX_LABEL_LEN as u32;
pub const MAX_ENTRIES: u32 = b0_pre_vmat::MAX_ENTRIES as u32;

/// Map a shared-codec [`b0_pre_vmat::VmatError`] into this crate's `DecodeError`,
/// so a fallible-codec rejection propagates with a precise context instead of a
/// panic. This is the ONE place the two error taxonomies meet.
pub(crate) fn vmat_to_decode(e: b0_pre_vmat::VmatError) -> DecodeError {
    use b0_pre_vmat::VmatError as V;
    match e {
        V::UnknownCandidate { candidate } => DecodeError::BadEnum {
            name: "Candidate",
            value: candidate as u64,
        },
        V::UnknownRole { role } => DecodeError::BadEnum {
            name: "VerifierMaterialRole",
            value: role as u64,
        },
        V::EmptyLabel => DecodeError::BadValue {
            ctx: "VerifierMaterialManifestV1.label_empty",
        },
        V::NonAsciiLabel => DecodeError::BadValue {
            ctx: "VerifierMaterialManifestV1.label_ascii",
        },
        V::LabelTooLong { len, max } => DecodeError::LengthExceedsMax {
            ctx: "VerifierMaterialManifestV1.label",
            len: len as u64,
            max: max as u64,
        },
        V::TooManyEntries { count, max } => DecodeError::CountExceedsMax {
            ctx: "VerifierMaterialManifestV1.entry_count",
            count: count as u64,
            max: max as u64,
        },
        V::NonCanonicalLabel { .. } => DecodeError::BadValue {
            ctx: "VerifierMaterialManifestV1.canonical_label",
        },
        V::DuplicateRole { .. } => DecodeError::DuplicateEntry {
            ctx: "VerifierMaterialManifestV1.entries",
        },
        V::NonCanonicalOrder => DecodeError::NonCanonicalOrder {
            ctx: "VerifierMaterialManifestV1.entries",
        },
        V::Overflow => DecodeError::Inconsistent {
            ctx: "verifier_material_bytes.overflow",
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierMaterialEntry {
    pub label: String,
    pub role: VerifierMaterialRole,
    pub byte_len: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierMaterialManifestV1 {
    pub candidate: Candidate,
    pub entries: Vec<VerifierMaterialEntry>,
}

/// The canonical role set a candidate's verifier-material manifest must contain,
/// in ascending `role` order. SP1 consumes only the Groth16 verifying key; RISC
/// Zero's Groth16 receipt path consumes all four. This is the authoritative
/// per-candidate coverage the canonical bridge and the Stage-1 bundle enforce.
pub fn required_roles(candidate: Candidate) -> &'static [VerifierMaterialRole] {
    match candidate {
        Candidate::Sp1 => &[VerifierMaterialRole::Groth16Vk],
        Candidate::Risc0 => &[
            VerifierMaterialRole::Groth16Vk,
            VerifierMaterialRole::ControlRoot,
            VerifierMaterialRole::ControlId,
            VerifierMaterialRole::VerifierParams,
        ],
    }
}

impl VerifierMaterialEntry {
    /// Build one entry with its single canonical label (`role.canonical_label()`).
    /// The only place a verifier-material label is minted for the canonical path.
    pub fn canonical(role: VerifierMaterialRole, byte_len: u64, hash: [u8; 32]) -> Self {
        Self {
            label: role.canonical_label().to_string(),
            role,
            byte_len,
            hash,
        }
    }
}

impl VerifierMaterialManifestV1 {
    /// Build a canonical manifest from raw `(role, byte_len, hash)` triples: assign
    /// each entry its canonical label and sort into the frozen `(role, label)`
    /// order. This is the single constructor the extractors and Stage-1 bundle
    /// feed their raw entries through, so `identity()` is the only manifest hash.
    pub fn from_canonical(
        candidate: Candidate,
        raw: impl IntoIterator<Item = (VerifierMaterialRole, u64, [u8; 32])>,
    ) -> Self {
        // Mint canonical labels and sort via the SHARED canonical primitive so the
        // label + ordering rule is identical to the one the extractors call.
        let mut shared: Vec<b0_pre_vmat::Entry<'static>> = raw
            .into_iter()
            .map(|(role, byte_len, hash)| b0_pre_vmat::Entry {
                role: role.to_repr(),
                label: b0_pre_vmat::canonical_label(role.to_repr())
                    .expect("every VerifierMaterialRole has a canonical label"),
                byte_len,
                hash,
            })
            .collect();
        b0_pre_vmat::sort_entries(&mut shared);
        let entries = shared
            .into_iter()
            .map(|e| VerifierMaterialEntry {
                label: e.label.to_string(),
                role: VerifierMaterialRole::from_repr(e.role)
                    .expect("shared entry carries a valid role discriminant"),
                byte_len: e.byte_len,
                hash: e.hash,
            })
            .collect();
        Self { candidate, entries }
    }

    /// This manifest's entries in the shared `(role, label, byte_len, hash)` form,
    /// borrowing the owned labels — the single bridge into the canonical
    /// primitive for `encode` / `identity` / `verifier_material_bytes`.
    fn shared_entries(&self) -> Vec<b0_pre_vmat::Entry<'_>> {
        self.entries
            .iter()
            .map(|e| b0_pre_vmat::Entry {
                role: e.role.to_repr(),
                label: e.label.as_str(),
                byte_len: e.byte_len,
                hash: e.hash,
            })
            .collect()
    }

    /// Assert this manifest is on the canonical verifier-material path: every entry
    /// carries its canonical label, entries are the exact `required_roles`
    /// coverage for the candidate (no missing / extra / duplicate role), and they
    /// are in canonical order. This is the extra gate the canonical bridge and the
    /// Stage-1 bundle apply on top of `decode` (which alone still accepts the
    /// synthetic legacy harness labels).
    pub fn validate_canonical(&self) -> Result<(), DecodeError> {
        // Strict canonical gate delegated to the SHARED primitive: canonical
        // labels, strictly-ascending `(role, label)` order, no duplicate role,
        // bounded count, valid role/candidate discriminants. The policy lives in
        // exactly one place (b0-pre-vmat), not a second copy here.
        b0_pre_vmat::ensure_canonical(self.candidate.to_repr(), &self.shared_entries())
            .map_err(vmat_to_decode)?;
        // Per-candidate coverage policy (which roles this candidate must carry, in
        // canonical order): the shared gate proves order/labels/uniqueness, this
        // proves the exact required role set.
        let want = required_roles(self.candidate);
        if self.entries.len() != want.len() {
            return Err(DecodeError::Inconsistent {
                ctx: "VerifierMaterialManifestV1.canonical_role_count",
            });
        }
        for (e, expect_role) in self.entries.iter().zip(want.iter()) {
            if e.role != *expect_role {
                return Err(DecodeError::Inconsistent {
                    ctx: "VerifierMaterialManifestV1.canonical_role_set",
                });
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        // Byte-exact canonical encoding, produced by the SHARED primitive (not a
        // local Writer copy). Entry order is preserved so a mis-ordered manifest
        // still encodes mis-ordered and the byte `decode` below rejects it. The
        // fallible codec propagates every structural rejection (checked length
        // conversions, oversized label/count, invalid role/candidate, empty /
        // non-ASCII label) instead of panicking.
        b0_pre_vmat::encode(self.candidate.to_repr(), &self.shared_entries())
            .map_err(vmat_to_decode)
    }

    /// Manifest identity (== its `.hash`), self-domained via the leading tag:
    /// `BLAKE3(canonical_encode(self))`, with no second prefix. Propagates codec
    /// rejections, so an invalid manifest yields NO identity.
    pub fn identity(&self) -> Result<[u8; 32], DecodeError> {
        b0_pre_vmat::identity(self.candidate.to_repr(), &self.shared_entries())
            .map_err(vmat_to_decode)
    }

    /// The normative name for the same value, as bound by consumers.
    pub fn verifier_material_manifest_hash(&self) -> Result<[u8; 32], DecodeError> {
        self.identity()
    }

    /// `verifier_material_bytes = Σ byte_len`, with overflow rejected. Computed by
    /// the SHARED primitive.
    pub fn verifier_material_bytes(&self) -> Result<u64, DecodeError> {
        b0_pre_vmat::total_bytes(&self.shared_entries()).map_err(vmat_to_decode)
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("VerifierMaterialManifestV1.tag")?;
        if tag != VERIFIER_MATERIAL_TAG {
            return Err(DecodeError::BadTag {
                ctx: "VerifierMaterialManifestV1",
            });
        }
        let sv = r.read_u16("VerifierMaterialManifestV1.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "VerifierMaterialManifestV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate =
            Candidate::from_repr(r.read_u16("VerifierMaterialManifestV1.candidate_id")?)?;
        let count = r.read_u32("VerifierMaterialManifestV1.entry_count")?;
        if count > MAX_ENTRIES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "VerifierMaterialManifestV1.entry_count",
                count: count as u64,
                max: MAX_ENTRIES as u64,
            });
        }
        let mut entries = Vec::with_capacity(count as usize);
        let mut prev: Option<(u8, Vec<u8>)> = None;
        for _ in 0..count {
            let label = r.read_ascii_str(MAX_LABEL_LEN, "VerifierMaterialManifestV1.label")?;
            if label.is_empty() {
                return Err(DecodeError::BadValue {
                    ctx: "VerifierMaterialManifestV1.label_empty",
                });
            }
            let role =
                VerifierMaterialRole::from_repr(r.read_u8("VerifierMaterialManifestV1.role")?)?;
            let byte_len = r.read_u64("VerifierMaterialManifestV1.byte_len")?;
            let hash = r.read_array::<32>("VerifierMaterialManifestV1.hash")?;
            let key = (role.to_repr(), label.as_bytes().to_vec());
            if let Some(p) = &prev {
                if *p == key {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "VerifierMaterialManifestV1.entries",
                    });
                }
                if key < *p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "VerifierMaterialManifestV1.entries",
                    });
                }
            }
            prev = Some(key);
            entries.push(VerifierMaterialEntry {
                label,
                role,
                byte_len,
                hash,
            });
        }
        Ok(Self { candidate, entries })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("VerifierMaterialManifestV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TEST_ONLY synthetic RISC Zero material total used in these unit fixtures
    /// (256 + 32 + 32 + 32). NOT a protocol constant, requirement, limit, or venue
    /// acceptance condition — a manifest is only ever checked against its own Σ.
    const TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL: u64 = 256 + 32 + 32 + 32;

    fn e(label: &str, role: VerifierMaterialRole, len: u64) -> VerifierMaterialEntry {
        VerifierMaterialEntry {
            label: label.to_string(),
            role,
            byte_len: len,
            hash: [role.to_repr(); 32],
        }
    }

    /// Secondary cross-implementation evidence (NOT the production bridge — the
    /// bridge is the shared `b0_pre_vmat` crate both this validator and the
    /// extractors call). The extractors build raw `(role_repr, label, len, hash)`
    /// entries and feed them, out of order, straight to `b0_pre_vmat::{sort_entries,
    /// identity}`. This proves that raw-repr path lands byte-for-byte on the same
    /// identity as this crate's typed `from_canonical` + `identity()`, so an
    /// extractor's `manifest_identity_blake3` equals `identity()`.
    fn extractor_raw_identity(candidate: u16, raw: &[(u8, &str, u64, [u8; 32])]) -> [u8; 32] {
        let mut es: Vec<b0_pre_vmat::Entry> = raw
            .iter()
            .map(|&(role, label, byte_len, hash)| b0_pre_vmat::Entry {
                role,
                label,
                byte_len,
                hash,
            })
            .collect();
        b0_pre_vmat::sort_entries(&mut es);
        b0_pre_vmat::identity(candidate, &es).expect("canonical test entries encode")
    }

    #[test]
    fn extractor_raw_path_matches_typed_canonical_identity() {
        // SP1: single groth16_vk.
        let sp1 = VerifierMaterialManifestV1::from_canonical(
            Candidate::Sp1,
            [(VerifierMaterialRole::Groth16Vk, 292, [7u8; 32])],
        );
        assert_eq!(
            sp1.identity().unwrap(),
            extractor_raw_identity(
                Candidate::Sp1.to_repr(),
                &[(b0_pre_vmat::ROLE_GROTH16_VK, "groth16_vk", 292, [7u8; 32])],
            )
        );

        // RISC0: four canonical roles supplied out of order to the raw path, which
        // sorts to the same canonical bytes and identity.
        let risc0 = VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [
                (VerifierMaterialRole::Groth16Vk, 256, [0u8; 32]),
                (VerifierMaterialRole::ControlRoot, 32, [1u8; 32]),
                (VerifierMaterialRole::ControlId, 32, [2u8; 32]),
                (VerifierMaterialRole::VerifierParams, 32, [3u8; 32]),
            ],
        );
        assert_eq!(
            risc0.identity().unwrap(),
            extractor_raw_identity(
                Candidate::Risc0.to_repr(),
                &[
                    (
                        b0_pre_vmat::ROLE_VERIFIER_PARAMS,
                        "verifier_params",
                        32,
                        [3u8; 32]
                    ),
                    (
                        b0_pre_vmat::ROLE_CONTROL_ROOT,
                        "control_root",
                        32,
                        [1u8; 32]
                    ),
                    (b0_pre_vmat::ROLE_GROTH16_VK, "groth16_vk", 256, [0u8; 32]),
                    (b0_pre_vmat::ROLE_CONTROL_ID, "control_id", 32, [2u8; 32]),
                ],
            )
        );
    }

    #[test]
    fn shared_reprs_and_tag_agree_with_validator_frozen_constants() {
        // The shared crate mirrors the frozen scalars; a test binds them so they
        // cannot drift apart.
        assert_eq!(b0_pre_vmat::SCHEMA_VERSION, consts::SCHEMA_VERSION);
        assert_eq!(b0_pre_vmat::VERIFIER_MATERIAL_TAG, VERIFIER_MATERIAL_TAG);
        assert_eq!(b0_pre_vmat::CANDIDATE_SP1, Candidate::Sp1.to_repr());
        assert_eq!(b0_pre_vmat::CANDIDATE_RISC0, Candidate::Risc0.to_repr());
        assert_eq!(
            b0_pre_vmat::ROLE_GROTH16_VK,
            VerifierMaterialRole::Groth16Vk.to_repr()
        );
        assert_eq!(
            b0_pre_vmat::ROLE_VERIFIER_PARAMS,
            VerifierMaterialRole::VerifierParams.to_repr()
        );
        for r in VerifierMaterialRole::ALL {
            assert_eq!(
                b0_pre_vmat::canonical_label(r.to_repr()),
                Some(r.canonical_label())
            );
        }
    }

    #[test]
    fn sp1_single_entry_roundtrips_and_sums() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        assert_eq!(
            VerifierMaterialManifestV1::decode_exact(&m.encode().unwrap()).unwrap(),
            m
        );
        assert_eq!(m.verifier_material_bytes().unwrap(), 292);
    }

    #[test]
    fn risc0_four_roles_sorted_roundtrip_and_sum() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Risc0,
            entries: vec![
                e("groth16_vk", VerifierMaterialRole::Groth16Vk, 10),
                e("control_root", VerifierMaterialRole::ControlRoot, 20),
                e("control_id", VerifierMaterialRole::ControlId, 30),
                e("verifier_params", VerifierMaterialRole::VerifierParams, 40),
            ],
        };
        // encoded in role order 0,1,2,3 which is already ascending
        assert_eq!(
            VerifierMaterialManifestV1::decode_exact(&m.encode().unwrap()).unwrap(),
            m
        );
        assert_eq!(m.verifier_material_bytes().unwrap(), 100);
    }

    #[test]
    fn out_of_order_entries_rejected() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Risc0,
            entries: vec![
                e("control_root", VerifierMaterialRole::ControlRoot, 20),
                e("groth16_vk", VerifierMaterialRole::Groth16Vk, 10), // role 0 after role 1
            ],
        };
        assert!(matches!(
            VerifierMaterialManifestV1::decode_exact(&m.encode().unwrap()),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn duplicate_role_label_rejected() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![
                e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 1),
                e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 2),
            ],
        };
        assert!(matches!(
            VerifierMaterialManifestV1::decode_exact(&m.encode().unwrap()),
            Err(DecodeError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn identity_is_stable_and_sensitive() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        let id = m.identity().unwrap();
        assert_eq!(id, crate::hashing::plain(&m.encode().unwrap()));
        let mut m2 = m.clone();
        m2.entries[0].byte_len = 293;
        assert_ne!(m2.identity().unwrap(), id);
    }

    #[test]
    fn identity_is_single_self_domain_not_double_prefixed() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        let enc = m.encode().unwrap();
        // the approved single rule
        assert_eq!(m.identity().unwrap(), crate::hashing::plain(&enc));
        assert_eq!(
            m.verifier_material_manifest_hash().unwrap(),
            m.identity().unwrap()
        );
        // and explicitly NOT the superseded double-prefixed form
        assert_ne!(
            m.identity().unwrap(),
            crate::hashing::prefixed(&VERIFIER_MATERIAL_TAG, &enc)
        );
    }

    #[test]
    fn from_canonical_assigns_lowercase_labels_and_sorts() {
        // deliberately supply RISC0 roles out of order; the constructor sorts them
        // into the frozen (role, label) order and labels them lowercase.
        let m = VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [
                (VerifierMaterialRole::VerifierParams, 32, [3u8; 32]),
                (VerifierMaterialRole::ControlRoot, 32, [1u8; 32]),
                (VerifierMaterialRole::Groth16Vk, 256, [0u8; 32]),
                (VerifierMaterialRole::ControlId, 32, [2u8; 32]),
            ],
        );
        let labels: Vec<&str> = m.entries.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "groth16_vk",
                "control_root",
                "control_id",
                "verifier_params"
            ]
        );
        // canonical, roundtrips through the byte decoder, and passes the extra gate
        assert_eq!(
            VerifierMaterialManifestV1::decode_exact(&m.encode().unwrap()).unwrap(),
            m
        );
        assert_eq!(m.validate_canonical(), Ok(()));
        assert_eq!(
            m.verifier_material_bytes().unwrap(),
            TEST_ONLY_SYNTHETIC_RISC0_MATERIAL_TOTAL
        );
    }

    #[test]
    fn sp1_canonical_is_single_groth16_vk() {
        let m = VerifierMaterialManifestV1::from_canonical(
            Candidate::Sp1,
            [(VerifierMaterialRole::Groth16Vk, 292, [9u8; 32])],
        );
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].label, "groth16_vk");
        assert_eq!(m.validate_canonical(), Ok(()));
    }

    #[test]
    fn validate_canonical_rejects_wrong_coverage_and_noncanonical_labels() {
        // RISC0 with only one role -> wrong coverage
        let short = VerifierMaterialManifestV1::from_canonical(
            Candidate::Risc0,
            [(VerifierMaterialRole::Groth16Vk, 256, [0u8; 32])],
        );
        assert!(short.validate_canonical().is_err());

        // SP1 with an extra role -> wrong coverage
        let extra = VerifierMaterialManifestV1::from_canonical(
            Candidate::Sp1,
            [
                (VerifierMaterialRole::Groth16Vk, 292, [0u8; 32]),
                (VerifierMaterialRole::ControlRoot, 32, [1u8; 32]),
            ],
        );
        assert!(extra.validate_canonical().is_err());

        // canonical roles but a legacy uppercase label -> rejected
        let mut bad_label = VerifierMaterialManifestV1::from_canonical(
            Candidate::Sp1,
            [(VerifierMaterialRole::Groth16Vk, 292, [0u8; 32])],
        );
        bad_label.entries[0].label = "GROTH16_VK_BYTES".into();
        assert!(matches!(
            bad_label.validate_canonical(),
            Err(DecodeError::BadValue { .. })
        ));
    }

    #[test]
    fn identity_changes_with_every_selection_relevant_field() {
        let base = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        let id = base.identity().unwrap();

        let mut a = base.clone();
        a.candidate = Candidate::Risc0;
        assert_ne!(a.identity().unwrap(), id, "candidate_id");

        let mut b = base.clone();
        b.entries[0].role = VerifierMaterialRole::ControlRoot;
        assert_ne!(b.identity().unwrap(), id, "role");

        let mut c = base.clone();
        c.entries[0].label = "OTHER_LABEL".into();
        assert_ne!(c.identity().unwrap(), id, "label");

        let mut d = base.clone();
        d.entries[0].byte_len += 1;
        assert_ne!(d.identity().unwrap(), id, "byte_len");

        let mut f = base.clone();
        f.entries[0].hash[0] ^= 0x01;
        assert_ne!(f.identity().unwrap(), id, "digest");
    }
}

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

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::enums::{Candidate, VerifierMaterialRole};
use crate::tags::VERIFIER_MATERIAL_TAG;

pub const MAX_LABEL_LEN: u32 = 64;
pub const MAX_ENTRIES: u32 = 64;

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

impl VerifierMaterialManifestV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&VERIFIER_MATERIAL_TAG);
        w.u16(consts::SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            w.u16(e.label.len() as u16);
            w.bytes(e.label.as_bytes());
            w.u8(e.role.to_repr());
            w.u64(e.byte_len);
            w.bytes(&e.hash);
        }
        w.into_bytes()
    }

    /// Manifest identity (== its `.hash`), self-domained via the leading tag:
    /// `BLAKE3(canonical_encode(self))`, with no second prefix.
    pub fn identity(&self) -> [u8; 32] {
        crate::hashing::plain(&self.encode())
    }

    /// The normative name for the same value, as bound by consumers.
    pub fn verifier_material_manifest_hash(&self) -> [u8; 32] {
        self.identity()
    }

    /// `verifier_material_bytes = Σ byte_len`, with overflow rejected.
    pub fn verifier_material_bytes(&self) -> Result<u64, DecodeError> {
        let mut total: u64 = 0;
        for e in &self.entries {
            total = total
                .checked_add(e.byte_len)
                .ok_or(DecodeError::Inconsistent {
                    ctx: "verifier_material_bytes.overflow",
                })?;
        }
        Ok(total)
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

    fn e(label: &str, role: VerifierMaterialRole, len: u64) -> VerifierMaterialEntry {
        VerifierMaterialEntry {
            label: label.to_string(),
            role,
            byte_len: len,
            hash: [role.to_repr(); 32],
        }
    }

    #[test]
    fn sp1_single_entry_roundtrips_and_sums() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        assert_eq!(
            VerifierMaterialManifestV1::decode_exact(&m.encode()).unwrap(),
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
            VerifierMaterialManifestV1::decode_exact(&m.encode()).unwrap(),
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
            VerifierMaterialManifestV1::decode_exact(&m.encode()),
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
            VerifierMaterialManifestV1::decode_exact(&m.encode()),
            Err(DecodeError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn identity_is_stable_and_sensitive() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        let id = m.identity();
        assert_eq!(id, crate::hashing::plain(&m.encode()));
        let mut m2 = m.clone();
        m2.entries[0].byte_len = 293;
        assert_ne!(m2.identity(), id);
    }

    #[test]
    fn identity_is_single_self_domain_not_double_prefixed() {
        let m = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        let enc = m.encode();
        // the approved single rule
        assert_eq!(m.identity(), crate::hashing::plain(&enc));
        assert_eq!(m.verifier_material_manifest_hash(), m.identity());
        // and explicitly NOT the superseded double-prefixed form
        assert_ne!(
            m.identity(),
            crate::hashing::prefixed(&VERIFIER_MATERIAL_TAG, &enc)
        );
    }

    #[test]
    fn identity_changes_with_every_selection_relevant_field() {
        let base = VerifierMaterialManifestV1 {
            candidate: Candidate::Sp1,
            entries: vec![e("GROTH16_VK_BYTES", VerifierMaterialRole::Groth16Vk, 292)],
        };
        let id = base.identity();

        let mut a = base.clone();
        a.candidate = Candidate::Risc0;
        assert_ne!(a.identity(), id, "candidate_id");

        let mut b = base.clone();
        b.entries[0].role = VerifierMaterialRole::ControlRoot;
        assert_ne!(b.identity(), id, "role");

        let mut c = base.clone();
        c.entries[0].label = "OTHER_LABEL".into();
        assert_ne!(c.identity(), id, "label");

        let mut d = base.clone();
        d.entries[0].byte_len += 1;
        assert_ne!(d.identity(), id, "byte_len");

        let mut f = base.clone();
        f.entries[0].hash[0] ^= 0x01;
        assert_ne!(f.identity(), id, "digest");
    }
}

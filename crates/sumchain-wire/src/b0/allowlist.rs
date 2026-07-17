//! `GuestProgramAllowlistV1` + `GuestProgramEntryV1` — variable (plan §8/§22).
//!
//! Entry fixed part is 228 bytes; each architecture builder adds 33
//! (`arch u8 ‖ digest[32]`), so a two-arch entry is 294. Entries are ascending
//! by `candidate_id` (dedup), and per-entry architectures ascending (dedup).
//! `r0_guest_set_hash = BLAKE3(GUESTSET ‖ canonical_allowlist_bytes)`. The
//! stage-1 allowlist is empty (`entry_count = 0`).

use crate::b0::codec::{DecodeError, Reader, Writer};
use crate::b0::consts;
use crate::b0::enums::{Arch, Candidate};
use crate::b0::hashing;
use crate::b0::tags::GUESTSET_PREFIX;

pub const ENTRY_FIXED_LEN: usize = 228;
pub const ARCH_ENTRY_LEN: usize = 33;
pub const MAX_ENTRIES: u32 = 64;
pub const MAX_ARCHES: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuilderArch {
    pub arch: Arch,
    pub builder_container_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestProgramEntryV1 {
    pub candidate: Candidate,
    pub b0_pre_spec_hash: [u8; 32],
    pub guest_source_tree_hash: [u8; 32],
    pub candidate_dep_lock_hash: [u8; 32],
    pub arches: Vec<BuilderArch>,
    pub guest_image_hash: [u8; 32],
    pub program_id: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub build_command_hash: [u8; 32],
    pub reproducible: bool,
}

impl GuestProgramEntryV1 {
    fn encode_into(&self, w: &mut Writer) {
        w.u16(self.candidate.to_repr());
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.guest_source_tree_hash);
        w.bytes(&self.candidate_dep_lock_hash);
        w.u8(self.arches.len() as u8);
        for a in &self.arches {
            w.u8(a.arch.to_repr());
            w.bytes(&a.builder_container_digest);
        }
        w.bytes(&self.guest_image_hash);
        w.bytes(&self.program_id);
        w.bytes(&self.verifier_material_manifest_hash);
        w.bytes(&self.build_command_hash);
        w.u8(if self.reproducible { 1 } else { 0 });
    }

    /// Validate the per-entry frozen invariants: an architecture list of
    /// `1..=MAX_ARCHES` (which proves the count fits its `u8` wire field) that is
    /// strictly ascending by arch discriminant and free of duplicates. All other
    /// fields are fixed-width arrays or a `bool`, always valid.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.arches.is_empty() || self.arches.len() as u64 > MAX_ARCHES as u64 {
            return Err(DecodeError::CountExceedsMax {
                ctx: "GuestProgramEntryV1.arch_count",
                count: self.arches.len() as u64,
                max: MAX_ARCHES as u64,
            });
        }
        let mut prev: Option<u8> = None;
        for a in &self.arches {
            let r = a.arch.to_repr();
            if let Some(p) = prev {
                if r == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "GuestProgramEntryV1.arches",
                    });
                }
                if r < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "GuestProgramEntryV1.arches",
                    });
                }
            }
            prev = Some(r);
        }
        Ok(())
    }

    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let candidate = Candidate::from_repr(r.read_u16("GuestProgramEntryV1.candidate_id")?)?;
        let b0_pre_spec_hash = r.read_array::<32>("GuestProgramEntryV1.b0_pre_spec_hash")?;
        let guest_source_tree_hash =
            r.read_array::<32>("GuestProgramEntryV1.guest_source_tree_hash")?;
        let candidate_dep_lock_hash =
            r.read_array::<32>("GuestProgramEntryV1.candidate_dep_lock_hash")?;
        let arch_count = r.read_u8("GuestProgramEntryV1.arch_count")?;
        if arch_count == 0 || arch_count > MAX_ARCHES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "GuestProgramEntryV1.arch_count",
                count: arch_count as u64,
                max: MAX_ARCHES as u64,
            });
        }
        let mut arches = Vec::with_capacity(arch_count as usize);
        let mut prev_arch: Option<u8> = None;
        for _ in 0..arch_count {
            let arch = Arch::from_repr(r.read_u8("GuestProgramEntryV1.arch")?)?;
            let digest = r.read_array::<32>("GuestProgramEntryV1.builder_container_digest")?;
            if let Some(p) = prev_arch {
                if arch.to_repr() == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "GuestProgramEntryV1.arches",
                    });
                }
                if arch.to_repr() < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "GuestProgramEntryV1.arches",
                    });
                }
            }
            prev_arch = Some(arch.to_repr());
            arches.push(BuilderArch {
                arch,
                builder_container_digest: digest,
            });
        }
        let guest_image_hash = r.read_array::<32>("GuestProgramEntryV1.guest_image_hash")?;
        let program_id = r.read_array::<32>("GuestProgramEntryV1.program_id")?;
        let verifier_material_manifest_hash =
            r.read_array::<32>("GuestProgramEntryV1.verifier_material_manifest_hash")?;
        let build_command_hash = r.read_array::<32>("GuestProgramEntryV1.build_command_hash")?;
        let reproducible = match r.read_u8("GuestProgramEntryV1.reproducible")? {
            0 => false,
            1 => true,
            v => {
                return Err(DecodeError::BadFixedScalar {
                    ctx: "GuestProgramEntryV1.reproducible",
                    value: v as u64,
                })
            }
        };
        Ok(Self {
            candidate,
            b0_pre_spec_hash,
            guest_source_tree_hash,
            candidate_dep_lock_hash,
            arches,
            guest_image_hash,
            program_id,
            verifier_material_manifest_hash,
            build_command_hash,
            reproducible,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestProgramAllowlistV1 {
    pub entries: Vec<GuestProgramEntryV1>,
}

impl GuestProgramAllowlistV1 {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(consts::SCHEMA_VERSION);
        w.u32(self.entries.len() as u32);
        for e in &self.entries {
            e.encode_into(&mut w);
        }
        w.into_bytes()
    }

    /// Validate the frozen invariants the decoder enforces: the entry-count cap
    /// (which proves the count fits its `u32` wire field), each entry's own
    /// [`GuestProgramEntryV1::validate`], and entries strictly ascending by
    /// candidate discriminant and unique. A struct from `decode_exact` is valid by
    /// construction, so `decode → try_encode` round-trips.
    pub fn validate(&self) -> Result<(), DecodeError> {
        if self.entries.len() as u64 > MAX_ENTRIES as u64 {
            return Err(DecodeError::CountExceedsMax {
                ctx: "GuestProgramAllowlistV1.entry_count",
                count: self.entries.len() as u64,
                max: MAX_ENTRIES as u64,
            });
        }
        let mut prev: Option<u16> = None;
        for e in &self.entries {
            e.validate()?;
            let key = e.candidate.to_repr();
            if let Some(p) = prev {
                if key == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "GuestProgramAllowlistV1.entries",
                    });
                }
                if key < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "GuestProgramAllowlistV1.entries",
                    });
                }
            }
            prev = Some(key);
        }
        Ok(())
    }

    /// `validate()` then encode: the only public way to obtain canonical bytes,
    /// so no public method emits or hashes a structure the decoder would reject.
    pub fn try_encode(&self) -> Result<Vec<u8>, DecodeError> {
        self.validate()?;
        Ok(self.encode())
    }

    /// `r0_guest_set_hash = BLAKE3(GUESTSET ‖ canonical_allowlist_bytes)`.
    /// Fallible so it never hashes a structure the decoder would reject.
    pub fn try_guest_set_hash(&self) -> Result<[u8; 32], DecodeError> {
        Ok(hashing::prefixed(GUESTSET_PREFIX, &self.try_encode()?))
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let sv = r.read_u16("GuestProgramAllowlistV1.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "GuestProgramAllowlistV1.schema_version",
                value: sv as u64,
            });
        }
        let count = r.read_u32("GuestProgramAllowlistV1.entry_count")?;
        if count > MAX_ENTRIES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "GuestProgramAllowlistV1.entry_count",
                count: count as u64,
                max: MAX_ENTRIES as u64,
            });
        }
        let mut entries = Vec::with_capacity(count as usize);
        let mut prev: Option<u16> = None;
        for _ in 0..count {
            let e = GuestProgramEntryV1::decode(r)?;
            let key = e.candidate.to_repr();
            if let Some(p) = prev {
                if key == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "GuestProgramAllowlistV1.entries",
                    });
                }
                if key < p {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "GuestProgramAllowlistV1.entries",
                    });
                }
            }
            prev = Some(key);
            entries.push(e);
        }
        Ok(Self { entries })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("GuestProgramAllowlistV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(c: Candidate, arches: Vec<Arch>) -> GuestProgramEntryV1 {
        GuestProgramEntryV1 {
            candidate: c,
            b0_pre_spec_hash: [1; 32],
            guest_source_tree_hash: [2; 32],
            candidate_dep_lock_hash: [3; 32],
            arches: arches
                .into_iter()
                .map(|a| BuilderArch {
                    arch: a,
                    builder_container_digest: [a.to_repr(); 32],
                })
                .collect(),
            guest_image_hash: [4; 32],
            program_id: [5; 32],
            verifier_material_manifest_hash: [6; 32],
            build_command_hash: [7; 32],
            reproducible: true,
        }
    }

    #[test]
    fn empty_allowlist_is_valid_stage1() {
        let a = GuestProgramAllowlistV1 { entries: vec![] };
        assert_eq!(a.encode().len(), 6); // schema_version(2) + count(4)
        assert_eq!(
            GuestProgramAllowlistV1::decode_exact(&a.encode()).unwrap(),
            a
        );
        // hash is defined and stable
        assert_eq!(
            a.try_guest_set_hash().unwrap(),
            hashing::prefixed(GUESTSET_PREFIX, &a.encode())
        );
    }

    #[test]
    fn two_arch_entry_is_294_bytes() {
        let mut w = Writer::new();
        entry(Candidate::Sp1, vec![Arch::X86_64, Arch::Aarch64]).encode_into(&mut w);
        assert_eq!(w.len(), 228 + 2 * 33); // 294
    }

    #[test]
    fn two_candidate_allowlist_roundtrips() {
        let a = GuestProgramAllowlistV1 {
            entries: vec![
                entry(Candidate::Sp1, vec![Arch::X86_64, Arch::Aarch64]),
                entry(Candidate::Risc0, vec![Arch::X86_64, Arch::Aarch64]),
            ],
        };
        assert_eq!(
            GuestProgramAllowlistV1::decode_exact(&a.encode()).unwrap(),
            a
        );
    }

    #[test]
    fn descending_candidate_rejected() {
        let a = GuestProgramAllowlistV1 {
            entries: vec![
                entry(Candidate::Risc0, vec![Arch::X86_64]),
                entry(Candidate::Sp1, vec![Arch::X86_64]),
            ],
        };
        assert!(matches!(
            GuestProgramAllowlistV1::decode_exact(&a.encode()),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn descending_arch_within_entry_rejected() {
        let a = GuestProgramAllowlistV1 {
            entries: vec![entry(Candidate::Sp1, vec![Arch::Aarch64, Arch::X86_64])],
        };
        assert!(matches!(
            GuestProgramAllowlistV1::decode_exact(&a.encode()),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn bad_reproducible_byte_rejected() {
        let a = GuestProgramAllowlistV1 {
            entries: vec![entry(Candidate::Sp1, vec![Arch::X86_64])],
        };
        let mut bytes = a.encode();
        *bytes.last_mut().unwrap() = 2; // reproducible must be 0/1
        assert!(matches!(
            GuestProgramAllowlistV1::decode_exact(&bytes),
            Err(DecodeError::BadFixedScalar {
                ctx: "GuestProgramEntryV1.reproducible",
                ..
            })
        ));
    }

    // ---- Design B: the construction/encoding path also fails closed ----

    #[test]
    fn try_guest_set_hash_ok_for_valid() {
        let a = GuestProgramAllowlistV1 {
            entries: vec![
                entry(Candidate::Sp1, vec![Arch::X86_64, Arch::Aarch64]),
                entry(Candidate::Risc0, vec![Arch::X86_64]),
            ],
        };
        assert!(a.validate().is_ok());
        assert_eq!(
            a.try_guest_set_hash().unwrap(),
            hashing::prefixed(GUESTSET_PREFIX, &a.try_encode().unwrap())
        );
    }

    #[test]
    fn try_encode_rejects_descending_candidate() {
        let a = GuestProgramAllowlistV1 {
            entries: vec![
                entry(Candidate::Risc0, vec![Arch::X86_64]),
                entry(Candidate::Sp1, vec![Arch::X86_64]),
            ],
        };
        assert!(matches!(
            a.try_encode(),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
        assert!(matches!(
            a.try_guest_set_hash(),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn try_encode_rejects_duplicate_candidate() {
        let a = GuestProgramAllowlistV1 {
            entries: vec![
                entry(Candidate::Sp1, vec![Arch::X86_64]),
                entry(Candidate::Sp1, vec![Arch::X86_64]),
            ],
        };
        assert!(matches!(
            a.try_encode(),
            Err(DecodeError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn entry_validate_enforces_arch_rule() {
        // descending arches within an entry
        assert!(matches!(
            entry(Candidate::Sp1, vec![Arch::Aarch64, Arch::X86_64]).validate(),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
        // duplicate arches
        assert!(matches!(
            entry(Candidate::Sp1, vec![Arch::X86_64, Arch::X86_64]).validate(),
            Err(DecodeError::DuplicateEntry { .. })
        ));
        // zero arches
        assert!(matches!(
            entry(Candidate::Sp1, vec![]).validate(),
            Err(DecodeError::CountExceedsMax { .. })
        ));
        // a valid single-arch entry passes
        assert!(entry(Candidate::Sp1, vec![Arch::X86_64]).validate().is_ok());
    }

    #[test]
    fn try_encode_rejects_over_cap() {
        // MAX_ENTRIES + 1 entries: the entry-count cap fires first (candidate has
        // only two variants, so this can never be a valid ascending list anyway).
        let entries: Vec<_> = (0..(MAX_ENTRIES + 1))
            .map(|_| entry(Candidate::Sp1, vec![Arch::X86_64]))
            .collect();
        let a = GuestProgramAllowlistV1 { entries };
        assert!(matches!(
            a.try_encode(),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }
}

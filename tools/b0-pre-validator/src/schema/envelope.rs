//! `R0ProofArtifactEnvelopeV1` — fixed head 266, max 3,503 bytes (plan §8/§22).
//!
//! Binds both closure hashes (`b0_pre_spec_hash`, `r0_guest_set_hash`), the
//! provenance hash, and — explicitly — `arch`, `sample_kind`, and
//! `iteration_index`, so a proof cannot be reused across architecture or
//! iteration just because its `proof_hash` matches.

use crate::codec::{DecodeError, Reader, Writer};
use crate::consts;
use crate::enums::{Arch, Candidate, ProofRefKind, SampleKind};
use crate::tags::ENVELOPE_TAG;

pub const HEAD_LEN: usize = 266;
pub const MAX_ARTIFACT_HASHES: u32 = 32;
pub const MAX_LABEL_LEN: u32 = 64;
pub const MAX_LEN: usize = 3503;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactHash {
    pub label: String,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R0ProofArtifactEnvelopeV1 {
    pub candidate: Candidate,
    pub candidate_dep_lock_hash: [u8; 32],
    pub guest_program_id: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub computation_statement_hash: [u8; 32],
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub arch_run_provenance: [u8; 32],
    pub arch: Arch,
    pub sample_kind: SampleKind,
    pub iteration_index: u32,
    pub proof_hash: [u8; 32],
    pub artifact_hashes: Vec<ArtifactHash>,
}

impl R0ProofArtifactEnvelopeV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.tag(&ENVELOPE_TAG);
        w.u16(consts::SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.bytes(&self.candidate_dep_lock_hash);
        w.bytes(&self.guest_program_id);
        w.bytes(&self.verifier_material_manifest_hash);
        w.bytes(&self.computation_statement_hash);
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.bytes(&self.arch_run_provenance);
        w.u8(self.arch.to_repr());
        w.u8(self.sample_kind.to_repr());
        w.u32(self.iteration_index);
        // ProofRef (ContentDigest only)
        w.u8(ProofRefKind::ContentDigest.to_repr());
        w.bytes(&self.proof_hash);
        // artifact hashes
        w.u32(self.artifact_hashes.len() as u32);
        for a in &self.artifact_hashes {
            w.u32(a.label.len() as u32);
            w.bytes(a.label.as_bytes());
            w.bytes(&a.hash);
        }
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let tag = r.read_array::<32>("envelope.tag")?;
        if tag != ENVELOPE_TAG {
            return Err(DecodeError::BadTag { ctx: "envelope" });
        }
        let sv = r.read_u16("envelope.schema_version")?;
        if sv != consts::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "envelope.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("envelope.candidate_id")?)?;
        let candidate_dep_lock_hash = r.read_array::<32>("envelope.candidate_dep_lock_hash")?;
        let guest_program_id = r.read_array::<32>("envelope.guest_program_id")?;
        let verifier_material_manifest_hash =
            r.read_array::<32>("envelope.verifier_material_manifest_hash")?;
        let computation_statement_hash =
            r.read_array::<32>("envelope.computation_statement_hash")?;
        let b0_pre_spec_hash = r.read_array::<32>("envelope.b0_pre_spec_hash")?;
        let r0_guest_set_hash = r.read_array::<32>("envelope.r0_guest_set_hash")?;
        let arch_run_provenance = r.read_array::<32>("envelope.arch_run_provenance")?;
        let arch = Arch::from_repr(r.read_u8("envelope.arch")?)?;
        let sample_kind = SampleKind::from_repr(r.read_u8("envelope.sample_kind")?)?;
        let iteration_index = r.read_u32("envelope.iteration_index")?;
        let _proof_ref_kind = ProofRefKind::from_repr(r.read_u8("envelope.proof_ref_kind")?)?;
        let proof_hash = r.read_array::<32>("envelope.proof_hash")?;

        let count = r.read_u32("envelope.artifact_count")?;
        if count > MAX_ARTIFACT_HASHES {
            return Err(DecodeError::CountExceedsMax {
                ctx: "envelope.artifact_count",
                count: count as u64,
                max: MAX_ARTIFACT_HASHES as u64,
            });
        }
        let mut artifact_hashes = Vec::with_capacity(count as usize);
        let mut prev_label: Option<Vec<u8>> = None;
        for _ in 0..count {
            let label_len = r.read_u32("envelope.label_len")?;
            if label_len == 0 || label_len > MAX_LABEL_LEN {
                return Err(DecodeError::LengthExceedsMax {
                    ctx: "envelope.label_len",
                    len: label_len as u64,
                    max: MAX_LABEL_LEN as u64,
                });
            }
            let label_bytes = r.read_bytes(label_len as usize, "envelope.label")?.to_vec();
            if !label_bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                return Err(DecodeError::BadValue {
                    ctx: "envelope.label_ascii",
                });
            }
            if let Some(p) = &prev_label {
                if &label_bytes == p {
                    return Err(DecodeError::DuplicateEntry {
                        ctx: "envelope.artifact_hashes",
                    });
                }
                if label_bytes.as_slice() < p.as_slice() {
                    return Err(DecodeError::NonCanonicalOrder {
                        ctx: "envelope.artifact_hashes",
                    });
                }
            }
            prev_label = Some(label_bytes.clone());
            let hash = r.read_array::<32>("envelope.artifact_hash")?;
            // label is validated ASCII, safe to build a String
            let label = String::from_utf8(label_bytes).expect("ascii");
            artifact_hashes.push(ArtifactHash { label, hash });
        }

        Ok(Self {
            candidate,
            candidate_dep_lock_hash,
            guest_program_id,
            verifier_material_manifest_hash,
            computation_statement_hash,
            b0_pre_spec_hash,
            r0_guest_set_hash,
            arch_run_provenance,
            arch,
            sample_kind,
            iteration_index,
            proof_hash,
            artifact_hashes,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("R0ProofArtifactEnvelopeV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(artifacts: Vec<ArtifactHash>) -> R0ProofArtifactEnvelopeV1 {
        R0ProofArtifactEnvelopeV1 {
            candidate: Candidate::Sp1,
            candidate_dep_lock_hash: [1; 32],
            guest_program_id: [2; 32],
            verifier_material_manifest_hash: [3; 32],
            computation_statement_hash: [4; 32],
            b0_pre_spec_hash: [5; 32],
            r0_guest_set_hash: [6; 32],
            arch_run_provenance: [7; 32],
            arch: Arch::X86_64,
            sample_kind: SampleKind::Measured,
            iteration_index: 3,
            proof_hash: [8; 32],
            artifact_hashes: artifacts,
        }
    }

    fn ah(label: &str, b: u8) -> ArtifactHash {
        ArtifactHash {
            label: label.to_string(),
            hash: [b; 32],
        }
    }

    #[test]
    fn head_len_is_266_and_min_envelope() {
        let e = sample(vec![]);
        // head(266) + ProofRef(33) + count(4) = 303 with no artifacts
        assert_eq!(e.encode().len(), 266 + 33 + 4);
    }

    #[test]
    fn max_len_is_3503() {
        let arts: Vec<ArtifactHash> = (0..32)
            .map(|i| ArtifactHash {
                label: format!("{:064}", i),
                hash: [i as u8; 32],
            })
            .collect();
        let e = sample(arts);
        assert_eq!(e.encode().len(), 3503);
        assert_eq!(
            R0ProofArtifactEnvelopeV1::decode_exact(&e.encode()).unwrap(),
            e
        );
    }

    #[test]
    fn roundtrips_with_sorted_artifacts() {
        let e = sample(vec![ah("aaa", 1), ah("bbb", 2), ah("ccc", 3)]);
        assert_eq!(
            R0ProofArtifactEnvelopeV1::decode_exact(&e.encode()).unwrap(),
            e
        );
    }

    #[test]
    fn unsorted_artifacts_rejected() {
        let e = sample(vec![ah("bbb", 2), ah("aaa", 1)]);
        assert!(matches!(
            R0ProofArtifactEnvelopeV1::decode_exact(&e.encode()),
            Err(DecodeError::NonCanonicalOrder { .. })
        ));
    }

    #[test]
    fn duplicate_artifact_label_rejected() {
        let e = sample(vec![ah("dup", 1), ah("dup", 2)]);
        assert!(matches!(
            R0ProofArtifactEnvelopeV1::decode_exact(&e.encode()),
            Err(DecodeError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn artifact_count_over_max_rejected() {
        let mut e = sample(vec![]);
        let bytes = {
            e.artifact_hashes = vec![];
            let mut b = e.encode();
            // overwrite the count field (at offset 299) with 33
            b[299..303].copy_from_slice(&33u32.to_le_bytes());
            b
        };
        assert!(matches!(
            R0ProofArtifactEnvelopeV1::decode_exact(&bytes),
            Err(DecodeError::CountExceedsMax { .. })
        ));
    }

    #[test]
    fn bad_proof_ref_kind_rejected() {
        let e = sample(vec![]);
        let mut bytes = e.encode();
        bytes[266] = 2; // ProofRefKind at offset 266 must be 1 (ContentDigest)
        assert!(matches!(
            R0ProofArtifactEnvelopeV1::decode_exact(&bytes),
            Err(DecodeError::BadEnum {
                name: "ProofRefKind",
                ..
            })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let e = sample(vec![]);
        let bytes = e.encode();
        assert!(matches!(
            R0ProofArtifactEnvelopeV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            R0ProofArtifactEnvelopeV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}

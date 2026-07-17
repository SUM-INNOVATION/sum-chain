//! `ProductionProofEnvelopeV1` — 235 bytes — plus pure cross-binding checks.
//!
//! Layout: `magic b"PPEVv1\0"[7] · schema_version u16 · candidate u16 ·
//! candidate_dep_lock_hash[32] · guest_program_id[32] ·
//! verifier_material_manifest_hash[32] · computation_statement_hash[32] ·
//! b0_pre_spec_hash[32] · r0_guest_set_hash[32] · proof_artifact_digest[32]`.
//!
//! The `candidate` discriminant decodes through the frozen [`Candidate`] enum
//! (Sp1=1, Risc0=2), so an unknown value is rejected. Strict decoding rejects a
//! bad magic, a non-1 schema version, truncation, and trailing bytes.

use crate::b0::allowlist::{GuestProgramAllowlistV1, GuestProgramEntryV1};
use crate::b0::codec::{DecodeError, Reader, Writer};
use crate::b0::enums::Candidate;
use crate::b0::partial_proof::PartialComputeProofV1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionProofEnvelopeV1 {
    pub candidate: Candidate,
    pub candidate_dep_lock_hash: [u8; 32],
    pub guest_program_id: [u8; 32],
    pub verifier_material_manifest_hash: [u8; 32],
    pub computation_statement_hash: [u8; 32],
    pub b0_pre_spec_hash: [u8; 32],
    pub r0_guest_set_hash: [u8; 32],
    pub proof_artifact_digest: [u8; 32],
}

impl ProductionProofEnvelopeV1 {
    /// Seven-byte structure magic: `P P E V v 1 NUL`.
    pub const MAGIC: [u8; 7] = *b"PPEVv1\0";
    pub const SCHEMA_VERSION: u16 = 1;
    /// Documented total; asserted against the encoder-derived length in tests.
    pub const LEN: usize = 235;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&Self::MAGIC);
        w.u16(Self::SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.bytes(&self.candidate_dep_lock_hash);
        w.bytes(&self.guest_program_id);
        w.bytes(&self.verifier_material_manifest_hash);
        w.bytes(&self.computation_statement_hash);
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.r0_guest_set_hash);
        w.bytes(&self.proof_artifact_digest);
        w.into_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let magic = r.read_array::<7>("ProductionProofEnvelopeV1.magic")?;
        if magic != Self::MAGIC {
            return Err(DecodeError::BadTag {
                ctx: "ProductionProofEnvelopeV1",
            });
        }
        let sv = r.read_u16("ProductionProofEnvelopeV1.schema_version")?;
        if sv != Self::SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "ProductionProofEnvelopeV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("ProductionProofEnvelopeV1.candidate")?)?;
        let candidate_dep_lock_hash =
            r.read_array::<32>("ProductionProofEnvelopeV1.candidate_dep_lock_hash")?;
        let guest_program_id = r.read_array::<32>("ProductionProofEnvelopeV1.guest_program_id")?;
        let verifier_material_manifest_hash =
            r.read_array::<32>("ProductionProofEnvelopeV1.verifier_material_manifest_hash")?;
        let computation_statement_hash =
            r.read_array::<32>("ProductionProofEnvelopeV1.computation_statement_hash")?;
        let b0_pre_spec_hash = r.read_array::<32>("ProductionProofEnvelopeV1.b0_pre_spec_hash")?;
        let r0_guest_set_hash =
            r.read_array::<32>("ProductionProofEnvelopeV1.r0_guest_set_hash")?;
        let proof_artifact_digest =
            r.read_array::<32>("ProductionProofEnvelopeV1.proof_artifact_digest")?;
        Ok(Self {
            candidate,
            candidate_dep_lock_hash,
            guest_program_id,
            verifier_material_manifest_hash,
            computation_statement_hash,
            b0_pre_spec_hash,
            r0_guest_set_hash,
            proof_artifact_digest,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("ProductionProofEnvelopeV1")?;
        Ok(v)
    }
}

/// True iff `env` and `partial` agree on all four shared consensus hashes:
/// `computation_statement_hash`, `b0_pre_spec_hash`, `r0_guest_set_hash`, and
/// `proof_artifact_digest`.
pub fn shared_binding_ok(env: &ProductionProofEnvelopeV1, partial: &PartialComputeProofV1) -> bool {
    env.computation_statement_hash == partial.computation_statement_hash
        && env.b0_pre_spec_hash == partial.b0_pre_spec_hash
        && env.r0_guest_set_hash == partial.r0_guest_set_hash
        && env.proof_artifact_digest == partial.proof_artifact_digest
}

/// Ways an envelope can fail to match an allowlist entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipError {
    /// The allowlist's `guest_set_hash()` did not equal `env.r0_guest_set_hash`.
    GuestSetMismatch,
    /// No entry carried `env.candidate`.
    NoSuchCandidate,
    /// The entry's `candidate_dep_lock_hash` disagreed with the envelope's.
    DepLockMismatch,
    /// The entry's `program_id` did not equal `env.guest_program_id`.
    ProgramIdMismatch,
    /// The entry's `verifier_material_manifest_hash` disagreed with the envelope's.
    VerifierMaterialMismatch,
    /// The entry's `b0_pre_spec_hash` disagreed with the envelope's.
    SpecHashMismatch,
    /// The entry is not marked reproducible.
    NotReproducible,
}

/// Locate and validate the allowlist entry an envelope claims membership in.
///
/// Checks, in order: (a) the allowlist's guest-set hash binds the envelope's
/// `r0_guest_set_hash` (`GuestSetMismatch`); (b) an entry exists for
/// `env.candidate` (`NoSuchCandidate`); then, each with its own error, that the
/// entry's `candidate_dep_lock_hash`, `program_id`,
/// `verifier_material_manifest_hash`, and `b0_pre_spec_hash` equal the envelope's
/// and that the entry is `reproducible`.
///
/// This is a pure byte/field check. The registry `Active` / `activation_height`
/// status of the guest set is a **caller responsibility** and is not evaluated
/// here.
pub fn allowlist_membership<'a>(
    env: &ProductionProofEnvelopeV1,
    allowlist: &'a GuestProgramAllowlistV1,
) -> Result<&'a GuestProgramEntryV1, MembershipError> {
    // A malformed allowlist has no well-defined guest-set hash, so it cannot
    // legitimately authorize any envelope: treat that as a guest-set mismatch.
    match allowlist.try_guest_set_hash() {
        Ok(h) if h == env.r0_guest_set_hash => {}
        _ => return Err(MembershipError::GuestSetMismatch),
    }
    let entry = allowlist
        .entries
        .iter()
        .find(|e| e.candidate == env.candidate)
        .ok_or(MembershipError::NoSuchCandidate)?;
    if entry.candidate_dep_lock_hash != env.candidate_dep_lock_hash {
        return Err(MembershipError::DepLockMismatch);
    }
    if entry.program_id != env.guest_program_id {
        return Err(MembershipError::ProgramIdMismatch);
    }
    if entry.verifier_material_manifest_hash != env.verifier_material_manifest_hash {
        return Err(MembershipError::VerifierMaterialMismatch);
    }
    if entry.b0_pre_spec_hash != env.b0_pre_spec_hash {
        return Err(MembershipError::SpecHashMismatch);
    }
    if !entry.reproducible {
        return Err(MembershipError::NotReproducible);
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProductionProofEnvelopeV1 {
        ProductionProofEnvelopeV1 {
            candidate: Candidate::Sp1,
            candidate_dep_lock_hash: [1; 32],
            guest_program_id: [2; 32],
            verifier_material_manifest_hash: [3; 32],
            computation_statement_hash: [4; 32],
            b0_pre_spec_hash: [5; 32],
            r0_guest_set_hash: [6; 32],
            proof_artifact_digest: [7; 32],
        }
    }

    #[test]
    fn encoded_length_is_235() {
        assert_eq!(sample().encode().len(), 235);
        assert_eq!(sample().encode().len(), ProductionProofEnvelopeV1::LEN);
    }

    #[test]
    fn roundtrips() {
        let e = sample();
        assert_eq!(
            ProductionProofEnvelopeV1::decode_exact(&e.encode()).unwrap(),
            e
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = sample().encode();
        bytes[0] ^= 0xFF;
        assert!(matches!(
            ProductionProofEnvelopeV1::decode_exact(&bytes),
            Err(DecodeError::BadTag { .. })
        ));
    }

    #[test]
    fn unknown_candidate_rejected() {
        let mut bytes = sample().encode();
        // candidate u16 at offset 9..11 (7 magic + 2 version)
        bytes[9..11].copy_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            ProductionProofEnvelopeV1::decode_exact(&bytes),
            Err(DecodeError::BadEnum {
                name: "Candidate",
                ..
            })
        ));
    }

    #[test]
    fn truncation_and_trailing_rejected() {
        let bytes = sample().encode();
        assert!(matches!(
            ProductionProofEnvelopeV1::decode_exact(&bytes[..234]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            ProductionProofEnvelopeV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }
}

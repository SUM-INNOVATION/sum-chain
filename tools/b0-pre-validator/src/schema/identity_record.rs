//! `Phase1IdentityRecordV1` — the RETAINED, independently-addressed Phase-1 guest-identity record.
//!
//! Runner continuity is not sufficient when it compares two fields inside the SAME producer-set
//! runner attestation — a mutually-edited attestation stays internally consistent. This artifact is
//! the authentic Phase-1 record retained as a mandatory package member with its own domain-separated
//! [`Phase1IdentityRecordV1::hash`], which the runner attestation binds
//! (`RunnerAttestationV1.phase1_identity_record_blake3`). At sealed import the validator and the
//! independent verifier decode it from scratch, recompute its address, require it equals the bound
//! attestation field, enforce the EXACT identity set, and require
//! `production_binary_blake3 == phase1_production_binary_blake3 == runner_blake3` plus the same
//! candidate/arch/measured-source/tooling/spec — so a substituted or non-reproducible runner binary
//! is refused against an INDEPENDENT anchor, not a copied hash claim.
//!
//! It carries ONLY the continuity-relevant subset of the Phase-1 `GuestIdentityRecord`; it is NEVER
//! added to `GuestProgramAllowlistV1` or the arch-neutral guest identity (`r0_guest_set_hash`).

use crate::codec::{DecodeError, Reader, Writer};
use crate::enums::{Arch, Candidate};

pub const PHASE1_IDENTITY_SCHEMA_VERSION: u16 = 1;
/// 32-byte kind tag (leads the canonical bytes; a foreign record can never masquerade).
pub const PHASE1_IDENTITY_KIND: &[u8; 32] = b"b0-final-phase1-identity-rec-v1\0";
/// Domain separation for [`Phase1IdentityRecordV1::hash`].
pub const PHASE1_IDENTITY_PREFIX: &[u8] = b"b0-final-phase1-identity-record/v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase1IdentityRecordV1 {
    pub candidate: Candidate,
    pub arch: Arch,
    pub source_commit: String,          // 40-hex (measured source)
    pub tooling_commit: String,         // 40-hex
    pub tooling_pathset_blake3: String, // 64-hex
    pub b0_pre_spec_hash: [u8; 32],
    /// The compiled runner binary that emitted the Phase-1 guest identity.
    pub production_binary_blake3: [u8; 32],
}

fn w_hexstr(w: &mut Writer, s: &str) {
    w.u8(s.len() as u8);
    w.bytes(s.as_bytes());
}
fn r_hexstr(r: &mut Reader, n: usize, ctx: &'static str) -> Result<String, DecodeError> {
    let len = r.read_u8(ctx)? as usize;
    if len != n {
        return Err(DecodeError::BadValue { ctx });
    }
    let b = r.read_bytes(len, ctx)?;
    if !b
        .iter()
        .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(DecodeError::BadValue { ctx });
    }
    Ok(String::from_utf8(b.to_vec()).expect("ascii-hex"))
}

impl Phase1IdentityRecordV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(PHASE1_IDENTITY_KIND);
        w.u16(PHASE1_IDENTITY_SCHEMA_VERSION);
        w.u16(self.candidate.to_repr());
        w.u8(self.arch.to_repr());
        w_hexstr(&mut w, &self.source_commit);
        w_hexstr(&mut w, &self.tooling_commit);
        w_hexstr(&mut w, &self.tooling_pathset_blake3);
        w.bytes(&self.b0_pre_spec_hash);
        w.bytes(&self.production_binary_blake3);
        w.into_bytes()
    }

    /// The domain-separated artifact address bound by `RunnerAttestationV1.phase1_identity_record_blake3`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(PHASE1_IDENTITY_PREFIX);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    pub fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        let kind = r.read_array::<32>("Phase1IdentityRecordV1.kind")?;
        if &kind != PHASE1_IDENTITY_KIND {
            return Err(DecodeError::BadTag {
                ctx: "Phase1IdentityRecordV1.kind",
            });
        }
        let sv = r.read_u16("Phase1IdentityRecordV1.schema_version")?;
        if sv != PHASE1_IDENTITY_SCHEMA_VERSION {
            return Err(DecodeError::BadFixedScalar {
                ctx: "Phase1IdentityRecordV1.schema_version",
                value: sv as u64,
            });
        }
        let candidate = Candidate::from_repr(r.read_u16("Phase1IdentityRecordV1.candidate")?)?;
        let arch = Arch::from_repr(r.read_u8("Phase1IdentityRecordV1.arch")?)?;
        let source_commit = r_hexstr(r, 40, "Phase1IdentityRecordV1.source_commit")?;
        let tooling_commit = r_hexstr(r, 40, "Phase1IdentityRecordV1.tooling_commit")?;
        let tooling_pathset_blake3 =
            r_hexstr(r, 64, "Phase1IdentityRecordV1.tooling_pathset_blake3")?;
        let b0_pre_spec_hash = r.read_array::<32>("Phase1IdentityRecordV1.b0_pre_spec_hash")?;
        let production_binary_blake3 =
            r.read_array::<32>("Phase1IdentityRecordV1.production_binary_blake3")?;
        Ok(Self {
            candidate,
            arch,
            source_commit,
            tooling_commit,
            tooling_pathset_blake3,
            b0_pre_spec_hash,
            production_binary_blake3,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let v = Self::decode(&mut r)?;
        r.finish("Phase1IdentityRecordV1")?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Phase1IdentityRecordV1 {
        Phase1IdentityRecordV1 {
            candidate: Candidate::Sp1,
            arch: Arch::X86_64,
            source_commit: "5".repeat(40),
            tooling_commit: "1".repeat(40),
            tooling_pathset_blake3: "7".repeat(64),
            b0_pre_spec_hash: [2; 32],
            production_binary_blake3: [3; 32],
        }
    }

    #[test]
    fn roundtrips_and_hash_domain_separated() {
        let a = sample();
        assert_eq!(
            Phase1IdentityRecordV1::decode_exact(&a.encode()).unwrap(),
            a
        );
        assert_ne!(a.hash(), *blake3::hash(&a.encode()).as_bytes());
    }

    #[test]
    fn foreign_kind_truncation_trailing_rejected() {
        let bytes = sample().encode();
        let mut bad = bytes.clone();
        bad[0] ^= 0xff;
        assert!(matches!(
            Phase1IdentityRecordV1::decode_exact(&bad),
            Err(DecodeError::BadTag { .. })
        ));
        assert!(matches!(
            Phase1IdentityRecordV1::decode_exact(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated { .. })
        ));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(
            Phase1IdentityRecordV1::decode_exact(&long),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn non_hex_field_rejected() {
        let mut a = sample();
        a.source_commit = "z".repeat(40);
        assert!(matches!(
            Phase1IdentityRecordV1::decode_exact(&a.encode()),
            Err(DecodeError::BadValue { .. })
        ));
    }
}

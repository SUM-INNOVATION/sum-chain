//! G2 evidence records (group A3, D5), ADOPTED by the owner on 2026-11-09
//! (decision ledger, "2026-11-09 owner ADOPTION addendum", B3: "adopt the
//! evidence records and first-valid-record rule, using versioned META keys
//! rather than a new column family. No penalties are introduced."). DORMANT.
//!
//! # `EquivocationEvidenceV1`: 363 bytes, independent of `n`
//!
//! | Offset | Width | Field | Rule |
//! |---|---|---|---|
//! | 0 | 7 | [`EVIDENCE_MAGIC`] `FEVDv1\0` | exact |
//! | 7 | 2 | `schema` u16 LE | 1 |
//! | 9 | 113 | vote A body | a ratified `FinalityVoteV1` body ([`crate::vote`]) |
//! | 122 | 64 | vote A signature | E1 over `D_VOTE ‖ A body` |
//! | 186 | 113 | vote B body | as A |
//! | 299 | 64 | vote B signature | E1 over `D_VOTE ‖ B body` |
//!
//! * **One slot.** Both bodies name the same consensus-config commitment,
//!   height, round, vote type, validator-set commitment and validator index.
//! * **One encoding.** `A.block_id < B.block_id` bytewise. Identical blocks
//!   and the reverse order are refused, so a pair of votes has exactly one
//!   record. The nil `block_id` is all zero, so nil against non-nil is a
//!   conflict, with the nil vote first.
//! * **Identical bodies are a duplicate, never evidence.** Two signature
//!   bytes over one body (V-4 counting: [`crate::vote::VoteTally`] reports
//!   `Duplicate`) name one block, and are refused here as identical blocks.
//! * **Both votes verify** ([`verify_evidence`]) exactly as a vote is checked
//!   before it counts ([`crate::vote::verify`]): the node's own commitment
//!   and authenticated set for the height, the index below `n`, and the
//!   signature under E1.
//!
//! # `UpgradeConflictEvidenceV1`: `573 + 66·(k_a + k_b)` bytes
//!
//! | Offset | Width | Field | Rule |
//! |---|---|---|---|
//! | 0 | 7 | [`UPGRADE_CONFLICT_MAGIC`] `UCEVv1\0` | exact |
//! | 7 | 2 | `schema` u16 LE | 1 |
//! | 9 | 4 | `len_a` u32 LE | `= 278 + 66·k_a` |
//! | 13 | `len_a` | manifest A | complete A4 bytes, signatures included |
//! | 13 + `len_a` | 4 | `len_b` u32 LE | `= 278 + 66·k_b` |
//! | 17 + `len_a` | `len_b` | manifest B | complete A4 bytes |
//!
//! At `n = 2` with both signers (`k = 2` each) the record is 837 bytes.
//!
//! The manifest (A4: its layout, M1–M5 and its domains, owner item B4) is
//! **not adopted**. This module reads one manifest field, the signer count
//! `k` (u16 LE at offset [`MANIFEST_SIGNER_COUNT_OFFSET`]), because the
//! record's adopted length rule names it, and treats every other manifest
//! byte as opaque. Validity beyond that framing is decided through an
//! injected [`ManifestVerifier`], which has no implementation here: both
//! manifests fully verify, they name the same `sequence`, and
//! `digest(A) < digest(B)`. Equal digests are refused, since two signer
//! subsets of one body share a digest and are never a conflict. Only full
//! manifest bytes make this record; a hint never does. The record's consumer,
//! the G2-c conflict halt, lands with B4.
//!
//! # Storage (D5) and penalties
//!
//! No key is composed here. `sumchain-storage` (`evidence_meta`) keeps the
//! first valid record per slot, (height, round, type, index) for votes and
//! `sequence` for upgrade conflicts, under versioned keys in the existing
//! `meta` column family. No penalty is attached: nothing here slashes, jails,
//! tombstones or changes stake, and these records feed nothing into the
//! staking `SubmitEvidence` transaction.
//!
//! Nothing calls this module from a node path. Both required CI jobs (x86_64
//! and aarch64) check it against the byte-review draft's fixed vectors.

use thiserror::Error;

use crate::encoding::{DecodeError, LeReader, LeWriter};
use crate::vote::{
    self, Equivocation, FinalityVoteV1, SignedFinalityVoteV1, VoteContext, VoteDecodeError,
    VoteVerifyError, BODY_LEN, SIGNATURE_LEN,
};
use crate::Digest;

/// Which of a record's two members an error is about: the first (A) or the
/// second (B) in the record's canonical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Member {
    First,
    Second,
}

// ---------------------------------------------------------------------------
// EquivocationEvidenceV1
// ---------------------------------------------------------------------------

/// The equivocation record's magic, `FEVDv1\0` (7 bytes).
pub const EVIDENCE_MAGIC: [u8; 7] = *b"FEVDv1\0";
/// The only accepted equivocation-record `schema`.
pub const EVIDENCE_SCHEMA: u16 = 1;
/// Length of an equivocation record: magic, schema, then two votes, each a
/// 113-byte body and a 64-byte signature.
pub const EVIDENCE_LEN: usize = EVIDENCE_MAGIC.len() + 2 + 2 * (BODY_LEN + SIGNATURE_LEN);

const _: () = assert!(EVIDENCE_LEN == 363);

/// Two votes that cannot form one equivocation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidencePairError {
    #[error(
        "the votes are for different slots (commitment, height, round, type, \
         validator-set commitment or index differ)"
    )]
    DifferentSlots,
    #[error(
        "both votes name one block_id: with one slot their bodies are identical, \
         which is a duplicate, never evidence"
    )]
    IdenticalBlocks,
    #[error("block_id A is above block_id B: not the canonical order")]
    NonCanonicalOrder,
}

/// Why equivocation-record bytes were refused before any context check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidenceDecodeError {
    #[error("length {actual} is not exactly {}", EVIDENCE_LEN)]
    Length { actual: usize },
    #[error("the record magic is not FEVDv1\\0")]
    Magic,
    #[error("schema {0} is not 1")]
    Schema(u16),
    #[error("vote {member:?}: {error}")]
    Vote {
        member: Member,
        error: VoteDecodeError,
    },
    #[error(transparent)]
    Pair(#[from] EvidencePairError),
}

/// Why a decoded equivocation record was refused by its context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("vote {member:?}: {error}")]
pub struct EvidenceVerifyError {
    pub member: Member,
    pub error: VoteVerifyError,
}

/// Why equivocation-record bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EvidenceError {
    #[error(transparent)]
    Decode(#[from] EvidenceDecodeError),
    #[error(transparent)]
    Verify(#[from] EvidenceVerifyError),
}

/// A decoded `EquivocationEvidenceV1`: two votes for one slot with different
/// `block_id`s, in canonical order. `schema` is not a field: it is always 1.
/// Every value of this type encodes; [`verify_evidence`] checks the
/// signatures and the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EquivocationEvidenceV1 {
    first: SignedFinalityVoteV1,
    second: SignedFinalityVoteV1,
}

fn same_slot(a: &FinalityVoteV1, b: &FinalityVoteV1) -> bool {
    a.consensus_config_commitment == b.consensus_config_commitment
        && a.height == b.height
        && a.round == b.round
        && a.vote_type == b.vote_type
        && a.validator_set_commitment == b.validator_set_commitment
        && a.validator_index == b.validator_index
}

fn read_vote(
    r: &mut LeReader<'_>,
    member: Member,
) -> Result<SignedFinalityVoteV1, EvidenceDecodeError> {
    let fixed = "the length was checked before the votes are read";
    let vote = FinalityVoteV1::decode_body(r.bytes(BODY_LEN).expect(fixed))
        .map_err(|error| EvidenceDecodeError::Vote { member, error })?;
    Ok(SignedFinalityVoteV1 {
        vote,
        signature: r.array().expect(fixed),
    })
}

impl EquivocationEvidenceV1 {
    /// The record for two votes, in either order. Refused when they are for
    /// different slots or name one `block_id`.
    pub fn new(
        x: SignedFinalityVoteV1,
        y: SignedFinalityVoteV1,
    ) -> Result<EquivocationEvidenceV1, EvidencePairError> {
        if !same_slot(&x.vote, &y.vote) {
            return Err(EvidencePairError::DifferentSlots);
        }
        match x.vote.block_id.cmp(&y.vote.block_id) {
            std::cmp::Ordering::Less => Ok(EquivocationEvidenceV1 {
                first: x,
                second: y,
            }),
            std::cmp::Ordering::Greater => Ok(EquivocationEvidenceV1 {
                first: y,
                second: x,
            }),
            std::cmp::Ordering::Equal => Err(EvidencePairError::IdenticalBlocks),
        }
    }

    /// The record for an equivocation a [`crate::vote::VoteTally`] reported.
    pub fn from_equivocation(
        equivocation: &Equivocation,
    ) -> Result<EquivocationEvidenceV1, EvidencePairError> {
        EquivocationEvidenceV1::new(equivocation.counted, equivocation.conflicting)
    }

    /// Vote A: the lower `block_id` (nil, if either is).
    pub fn first(&self) -> &SignedFinalityVoteV1 {
        &self.first
    }

    /// Vote B: the higher `block_id`.
    pub fn second(&self) -> &SignedFinalityVoteV1 {
        &self.second
    }

    /// The 363-byte record.
    pub fn encode(&self) -> [u8; EVIDENCE_LEN] {
        let mut w = LeWriter::new();
        w.bytes(&EVIDENCE_MAGIC).u16(EVIDENCE_SCHEMA);
        for signed in [&self.first, &self.second] {
            w.bytes(&signed.vote.body()).bytes(&signed.signature);
        }
        w.into_bytes()
            .try_into()
            .expect("the record layout is exactly 363 bytes")
    }

    /// Strict decode. In order: exactly 363 bytes (so trailing bytes are
    /// refused); magic; schema; each body as a vote body is decoded (schema,
    /// vote type, round cap); one slot; `A.block_id < B.block_id`.
    pub fn decode(bytes: &[u8]) -> Result<EquivocationEvidenceV1, EvidenceDecodeError> {
        if bytes.len() != EVIDENCE_LEN {
            return Err(EvidenceDecodeError::Length {
                actual: bytes.len(),
            });
        }
        let fixed = "the length was checked above";
        let mut r = LeReader::new(bytes);
        if r.array::<7>().expect(fixed) != EVIDENCE_MAGIC {
            return Err(EvidenceDecodeError::Magic);
        }
        let schema = r.u16().expect(fixed);
        if schema != EVIDENCE_SCHEMA {
            return Err(EvidenceDecodeError::Schema(schema));
        }
        let first = read_vote(&mut r, Member::First)?;
        let second = read_vote(&mut r, Member::Second)?;
        r.finish().expect(fixed);
        if !same_slot(&first.vote, &second.vote) {
            return Err(EvidencePairError::DifferentSlots.into());
        }
        match first.vote.block_id.cmp(&second.vote.block_id) {
            std::cmp::Ordering::Less => Ok(EquivocationEvidenceV1 { first, second }),
            std::cmp::Ordering::Equal => Err(EvidencePairError::IdenticalBlocks.into()),
            std::cmp::Ordering::Greater => Err(EvidencePairError::NonCanonicalOrder.into()),
        }
    }
}

/// An equivocation record whose two votes both passed [`vote::verify`]. Only
/// [`verify_evidence`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedEvidence {
    evidence: EquivocationEvidenceV1,
}

impl VerifiedEvidence {
    pub fn evidence(&self) -> &EquivocationEvidenceV1 {
        &self.evidence
    }
}

/// Check both votes of `evidence` against the node's own `context` for their
/// height, as a vote is checked before it counts ([`vote::verify`]): vote A,
/// then vote B. The first failure refuses the record.
pub fn verify_evidence(
    evidence: &EquivocationEvidenceV1,
    context: &dyn VoteContext,
) -> Result<VerifiedEvidence, EvidenceVerifyError> {
    for (member, signed) in [
        (Member::First, &evidence.first),
        (Member::Second, &evidence.second),
    ] {
        vote::verify(signed, context).map_err(|error| EvidenceVerifyError { member, error })?;
    }
    Ok(VerifiedEvidence {
        evidence: *evidence,
    })
}

/// Decode equivocation-record bytes, then [`verify_evidence`].
pub fn decode_and_verify_evidence(
    bytes: &[u8],
    context: &dyn VoteContext,
) -> Result<VerifiedEvidence, EvidenceError> {
    let evidence = EquivocationEvidenceV1::decode(bytes)?;
    Ok(verify_evidence(&evidence, context)?)
}

// ---------------------------------------------------------------------------
// UpgradeConflictEvidenceV1
// ---------------------------------------------------------------------------

/// The upgrade-conflict record's magic, `UCEVv1\0` (7 bytes).
pub const UPGRADE_CONFLICT_MAGIC: [u8; 7] = *b"UCEVv1\0";
/// The only accepted upgrade-conflict-record `schema`.
pub const UPGRADE_CONFLICT_SCHEMA: u16 = 1;
/// The record's own bytes: magic, schema, `len_a` and `len_b`.
pub const UPGRADE_CONFLICT_FRAME_LEN: usize = UPGRADE_CONFLICT_MAGIC.len() + 2 + 4 + 4;
/// A manifest's length without its signer entries, as the record's length
/// rule counts it: the 276-byte body and the signer count `k`.
pub const MANIFEST_FIXED_LEN: usize = 278;
/// One manifest signer entry: `validator_index u16 ‖ signature[64]`.
pub const MANIFEST_ENTRY_LEN: usize = 2 + SIGNATURE_LEN;
/// Where a manifest carries its signer count `k` (u16 LE). The only manifest
/// field this module reads.
pub const MANIFEST_SIGNER_COUNT_OFFSET: usize = MANIFEST_FIXED_LEN - 2;

/// The length a manifest with `k` signers must have, `278 + 66·k`.
pub const fn manifest_len(k: u16) -> usize {
    MANIFEST_FIXED_LEN + MANIFEST_ENTRY_LEN * k as usize
}

/// The exact length of an upgrade-conflict record whose manifests have `k_a`
/// and `k_b` signers, `573 + 66·(k_a + k_b)`.
pub const fn upgrade_conflict_len(k_a: u16, k_b: u16) -> usize {
    UPGRADE_CONFLICT_FRAME_LEN + manifest_len(k_a) + manifest_len(k_b)
}

const _: () = assert!(upgrade_conflict_len(0, 0) == 573 && upgrade_conflict_len(2, 2) == 837);

/// Why upgrade-conflict-record bytes were refused before any manifest is
/// verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UpgradeConflictDecodeError {
    /// Too short for the field being read, or bytes after manifest B.
    #[error(transparent)]
    Framing(#[from] DecodeError),
    #[error("the record magic is not UCEVv1\\0")]
    Magic,
    #[error("schema {0} is not 1")]
    Schema(u16),
    #[error("manifest {member:?} is {actual} bytes, not 278 + 66 × its signer count")]
    ManifestLength { member: Member, actual: usize },
}

/// Why a manifest verifier refused a manifest. Free text: the verifier owns
/// the manifest encoding (A4), so this module cannot classify its reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct ManifestRefusal(pub String);

/// What a fully verified manifest is identified by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestIdentity {
    pub sequence: u64,
    /// The manifest digest, over its body without signatures.
    pub digest: Digest,
}

/// Full A4 verification of one manifest's complete bytes against the node's
/// own chain identity and the set that authenticates the manifest's sequence:
/// strict decoding, quorum and every signature under E1.
///
/// Injected, with no implementation in this crate: A4 (B4) is not adopted. An
/// implementation refuses everything A4 refuses, so two manifests it accepts
/// share the chain identity and the authenticating set the record requires.
pub trait ManifestVerifier {
    fn verify(&self, manifest: &[u8]) -> Result<ManifestIdentity, ManifestRefusal>;
}

/// Why an upgrade-conflict record was refused by its manifests.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpgradeConflictVerifyError {
    #[error("manifest {member:?} does not verify: {reason}")]
    ManifestRefused {
        member: Member,
        reason: ManifestRefusal,
    },
    #[error("the manifests are for sequences {first} and {second}, not one")]
    DifferentSequences { first: u64, second: u64 },
    #[error("the manifests share a digest: one body, never a conflict")]
    SameDigest,
    #[error("digest A is above digest B: not the canonical order")]
    NonCanonicalOrder,
}

/// Why upgrade-conflict-record bytes, or two manifests, were refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpgradeConflictError {
    #[error(transparent)]
    Decode(#[from] UpgradeConflictDecodeError),
    #[error(transparent)]
    Verify(#[from] UpgradeConflictVerifyError),
}

/// A decoded `UpgradeConflictEvidenceV1`. Each manifest's length matches its
/// signer count, so every value of this type encodes;
/// [`verify_upgrade_conflict`] checks everything else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpgradeConflictEvidenceV1 {
    first: Vec<u8>,
    second: Vec<u8>,
}

fn check_manifest_frame(manifest: &[u8], member: Member) -> Result<(), UpgradeConflictDecodeError> {
    let declared = manifest
        .get(MANIFEST_SIGNER_COUNT_OFFSET..MANIFEST_FIXED_LEN)
        .map(|k| manifest_len(u16::from_le_bytes([k[0], k[1]])));
    if declared != Some(manifest.len()) {
        return Err(UpgradeConflictDecodeError::ManifestLength {
            member,
            actual: manifest.len(),
        });
    }
    Ok(())
}

fn verify_manifest(
    verifier: &dyn ManifestVerifier,
    manifest: &[u8],
    member: Member,
) -> Result<ManifestIdentity, UpgradeConflictVerifyError> {
    verifier
        .verify(manifest)
        .map_err(|reason| UpgradeConflictVerifyError::ManifestRefused { member, reason })
}

impl UpgradeConflictEvidenceV1 {
    /// The record for two conflicting manifests, in either order: both
    /// verify, they name one sequence and their digests differ. Ordered by
    /// digest. A framing or verification refusal names `x` as
    /// [`Member::First`] and `y` as [`Member::Second`].
    pub fn from_manifests(
        x: &[u8],
        y: &[u8],
        verifier: &dyn ManifestVerifier,
    ) -> Result<VerifiedUpgradeConflict, UpgradeConflictError> {
        check_manifest_frame(x, Member::First)?;
        check_manifest_frame(y, Member::Second)?;
        let ix = verify_manifest(verifier, x, Member::First)?;
        let iy = verify_manifest(verifier, y, Member::Second)?;
        let ((first, a), (second, b)) = if ix.digest <= iy.digest {
            ((x, ix), (y, iy))
        } else {
            ((y, iy), (x, ix))
        };
        let evidence = UpgradeConflictEvidenceV1 {
            first: first.to_vec(),
            second: second.to_vec(),
        };
        Ok(check_pair(evidence, a, b)?)
    }

    /// Manifest A: the lower digest.
    pub fn first(&self) -> &[u8] {
        &self.first
    }

    /// Manifest B: the higher digest.
    pub fn second(&self) -> &[u8] {
        &self.second
    }

    /// The `573 + 66·(k_a + k_b)`-byte record.
    pub fn encode(&self) -> Vec<u8> {
        let len = |m: &[u8]| u32::try_from(m.len()).expect("a framed manifest is below 2^23 bytes");
        let mut w = LeWriter::new();
        w.bytes(&UPGRADE_CONFLICT_MAGIC)
            .u16(UPGRADE_CONFLICT_SCHEMA)
            .u32(len(&self.first))
            .bytes(&self.first)
            .u32(len(&self.second))
            .bytes(&self.second);
        w.into_bytes()
    }

    /// Strict decode of the framing. In order: magic; schema; `len_a` and
    /// manifest A, which must be `278 + 66·k_a` bytes for its own signer
    /// count; `len_b` and manifest B, likewise; no trailing bytes. A length
    /// that runs past the input is refused before anything is copied.
    pub fn decode(bytes: &[u8]) -> Result<UpgradeConflictEvidenceV1, UpgradeConflictDecodeError> {
        let mut r = LeReader::new(bytes);
        if r.array::<7>()? != UPGRADE_CONFLICT_MAGIC {
            return Err(UpgradeConflictDecodeError::Magic);
        }
        let schema = r.u16()?;
        if schema != UPGRADE_CONFLICT_SCHEMA {
            return Err(UpgradeConflictDecodeError::Schema(schema));
        }
        let mut manifest = |member| {
            let len = usize::try_from(r.u32()?).expect("u32 fits usize on supported targets");
            let manifest = r.bytes(len)?;
            check_manifest_frame(manifest, member)?;
            Ok::<_, UpgradeConflictDecodeError>(manifest)
        };
        let first = manifest(Member::First)?.to_vec();
        let second = manifest(Member::Second)?.to_vec();
        r.finish()?;
        Ok(UpgradeConflictEvidenceV1 { first, second })
    }
}

/// An upgrade-conflict record whose manifests both verified, name one
/// sequence and are in strictly ascending digest order. Only
/// [`verify_upgrade_conflict`] and
/// [`UpgradeConflictEvidenceV1::from_manifests`] make one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpgradeConflict {
    evidence: UpgradeConflictEvidenceV1,
    sequence: u64,
    digests: [Digest; 2],
}

impl VerifiedUpgradeConflict {
    pub fn evidence(&self) -> &UpgradeConflictEvidenceV1 {
        &self.evidence
    }
    /// The sequence both manifests name: the record's D5 slot.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// The digests of manifests A and B, strictly ascending.
    pub fn digests(&self) -> &[Digest; 2] {
        &self.digests
    }
}

fn check_pair(
    evidence: UpgradeConflictEvidenceV1,
    a: ManifestIdentity,
    b: ManifestIdentity,
) -> Result<VerifiedUpgradeConflict, UpgradeConflictVerifyError> {
    if a.sequence != b.sequence {
        return Err(UpgradeConflictVerifyError::DifferentSequences {
            first: a.sequence,
            second: b.sequence,
        });
    }
    match a.digest.cmp(&b.digest) {
        std::cmp::Ordering::Less => Ok(VerifiedUpgradeConflict {
            evidence,
            sequence: a.sequence,
            digests: [a.digest, b.digest],
        }),
        std::cmp::Ordering::Equal => Err(UpgradeConflictVerifyError::SameDigest),
        std::cmp::Ordering::Greater => Err(UpgradeConflictVerifyError::NonCanonicalOrder),
    }
}

/// Verify both manifests of `evidence` with `verifier` (A, then B), then
/// check that they name one sequence and that `digest(A) < digest(B)`.
pub fn verify_upgrade_conflict(
    evidence: &UpgradeConflictEvidenceV1,
    verifier: &dyn ManifestVerifier,
) -> Result<VerifiedUpgradeConflict, UpgradeConflictVerifyError> {
    let a = verify_manifest(verifier, &evidence.first, Member::First)?;
    let b = verify_manifest(verifier, &evidence.second, Member::Second)?;
    check_pair(evidence.clone(), a, b)
}

/// Decode upgrade-conflict-record bytes, then [`verify_upgrade_conflict`].
pub fn decode_and_verify_upgrade_conflict(
    bytes: &[u8],
    verifier: &dyn ManifestVerifier,
) -> Result<VerifiedUpgradeConflict, UpgradeConflictError> {
    let evidence = UpgradeConflictEvidenceV1::decode(bytes)?;
    Ok(verify_upgrade_conflict(&evidence, verifier)?)
}

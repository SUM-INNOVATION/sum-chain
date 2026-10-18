//! G2 finality vote `FinalityVoteV1` (group V), RATIFIED 2026-10-17 with
//! choices V-1 to V-6. DORMANT.
//!
//! Ratified format (`docs/proposals/g2-byte-review/README.md` §3):
//!
//! | Body offset | Preimage offset | Width | Field | Encoding | Rule |
//! |---|---|---|---|---|---|
//! | — | 0 | 26 | [`D_VOTE`] | domain | exact; preimage only, never on the wire |
//! | 0 | 26 | 32 | `consensus_config_commitment` | bytes | the effective commitment at `height` |
//! | 32 | 58 | 2 | `schema` | u16 LE | 1 |
//! | 34 | 60 | 8 | `height` | u64 LE | |
//! | 42 | 68 | 32 | `block_id` | bytes | all zero = nil (V-3) |
//! | 74 | 100 | 4 | `round` | u32 LE | `≤ 2^20` (D4) |
//! | 78 | 104 | 1 | `vote_type` | u8 | 1 prevote, 2 precommit; anything else refused |
//! | 79 | 105 | 32 | `validator_set_commitment` | bytes | the set authenticated for `height` (V-4) |
//! | 111 | 137 | 2 | `validator_index` | u16 LE | `< n` |
//!
//! * **Body:** 113 bytes, in the order above (V-1).
//! * **Signature preimage:** 139 bytes, `D_VOTE ‖ body`, signed with Ed25519
//!   in RFC 8032 pure mode (no prehash, no context). Nothing is hashed first.
//! * **Wire:** 184 bytes, `FVOTv1\0 ‖ body ‖ signature` (V-5).
//! * **Verification (E1):** `ed25519_dalek::VerifyingKey::verify_strict`:
//!   canonical `S < ℓ`, `R` and `A` not of small order, cofactorless equation
//!   compared by encoding. The `legacy_compatibility` feature, which would
//!   weaken the `S` check, must stay disabled (`tests/vote_v1.rs` checks both
//!   the behaviour and the manifests).
//! * **Validator keys (V-6):** refused at set construction when their encoding
//!   is not canonical or the point is of small order, alongside the duplicate
//!   refusal. The set size is at most `u16::MAX`: every index then fits the
//!   `u16` field, and `n` fits the `u16` count the certificate rules (D2)
//!   already use.
//! * **Vote type and signer step (V-2):** `step = vote_type + 1`, so prevote
//!   1 → step 2 and precommit 2 → step 3; a proposal is step 1 and has no vote
//!   type ([`VoteType::step`], [`step_number`]).
//!
//! # Context checks, in order
//!
//! A decoded vote counts only after [`verify`] checks, against the caller's
//! [`VoteContext`] for the vote's height:
//!
//! 1. `consensus_config_commitment` equals the node's effective commitment;
//! 2. `validator_set_commitment` equals the authenticated set's (under G2-d,
//!    the static genesis order);
//! 3. `validator_index < n`, with `n` from the authenticated set, never from
//!    the vote;
//! 4. the signature verifies under E1 against the set's key at that index.
//!
//! # Counting
//!
//! [`VoteTally`] counts at most one vote per (commitment, height, round, type,
//! validator-set commitment, index). A second vote with an identical body is a
//! duplicate, even when its signature bytes differ. A second vote with a
//! different `block_id` is equivocation (nil against non-nil counts), and is
//! not counted. A nil precommit never counts toward a certificate:
//! [`VoteTally::certificate_signers`] refuses an all-zero `block_id`.
//!
//! # Not here
//!
//! * How the validator-set commitment is computed (draft §2): the caller
//!   supplies the commitment of the set it authenticated.
//! * The certificate layout, evidence layout (A3) and signer state (A2). The
//!   durable signer does not yet decode its payload as a vote; binding it is a
//!   follow-up once A2 is ratified.
//! * Any signing, wiring, transport or activation. No node path calls this
//!   module.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::certificate::{self, CertificateSigners, SignerSetError, ValidatorSetResolver};
use crate::encoding::{LeReader, LeWriter, Round, RoundOutOfRange};
use crate::signer::Step;
use crate::Digest;

/// The vote's signature domain, `SUMCHAIN/FINALITY/VOTE/v1\0` (26 bytes).
pub const D_VOTE: [u8; 26] = *b"SUMCHAIN/FINALITY/VOTE/v1\0";
/// The vote's wire magic, `FVOTv1\0` (7 bytes).
pub const VOTE_MAGIC: [u8; 7] = *b"FVOTv1\0";
/// The only accepted `schema`.
pub const VOTE_SCHEMA: u16 = 1;
/// Length of the vote body.
pub const BODY_LEN: usize = 113;
/// Length of the signature preimage, `D_VOTE ‖ body`.
pub const PREIMAGE_LEN: usize = D_VOTE.len() + BODY_LEN;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;
/// Length of the wire form, `FVOTv1\0 ‖ body ‖ signature`.
pub const WIRE_LEN: usize = VOTE_MAGIC.len() + BODY_LEN + SIGNATURE_LEN;
/// The nil `block_id` (V-3).
pub const NIL_BLOCK_ID: Digest = [0; 32];
/// The largest validator set: `n` and every index fit a `u16`.
pub const MAX_VALIDATORS: usize = u16::MAX as usize;

const _: () = assert!(PREIMAGE_LEN == 139 && WIRE_LEN == 184);

/// The vote type byte: 1 prevote, 2 precommit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoteType {
    Prevote,
    Precommit,
}

impl VoteType {
    /// The wire byte.
    pub const fn code(self) -> u8 {
        match self {
            VoteType::Prevote => 1,
            VoteType::Precommit => 2,
        }
    }

    /// The vote type for a wire byte; `None` for anything but 1 or 2.
    pub const fn from_code(code: u8) -> Option<VoteType> {
        match code {
            1 => Some(VoteType::Prevote),
            2 => Some(VoteType::Precommit),
            _ => None,
        }
    }

    /// The signer step this vote type is signed at (V-2).
    pub const fn step(self) -> Step {
        match self {
            VoteType::Prevote => Step::Prevote,
            VoteType::Precommit => Step::Precommit,
        }
    }
}

/// The ratified step number (V-2): proposal 1, prevote 2, precommit 3. For a
/// vote, `step_number(vote_type.step()) == vote_type.code() + 1`.
pub const fn step_number(step: Step) -> u8 {
    match step {
        Step::Propose => 1,
        Step::Prevote => 2,
        Step::Precommit => 3,
    }
}

/// A decoded vote body. `schema` is not a field: it is always 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FinalityVoteV1 {
    pub consensus_config_commitment: Digest,
    pub height: u64,
    pub block_id: Digest,
    pub round: Round,
    pub vote_type: VoteType,
    pub validator_set_commitment: Digest,
    pub validator_index: u16,
}

/// Why a vote's bytes were refused before any context check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VoteDecodeError {
    #[error("length {actual} is not exactly {expected}")]
    Length { expected: usize, actual: usize },
    #[error("the wire magic is not FVOTv1\\0")]
    Magic,
    #[error("schema {0} is not 1")]
    Schema(u16),
    #[error("vote_type {0:#04x} is neither 1 (prevote) nor 2 (precommit)")]
    VoteType(u8),
    #[error(transparent)]
    Round(#[from] RoundOutOfRange),
}

impl FinalityVoteV1 {
    /// Whether this is a nil vote (all-zero `block_id`, V-3).
    pub fn is_nil(&self) -> bool {
        self.block_id == NIL_BLOCK_ID
    }

    /// The 113-byte body.
    pub fn body(&self) -> [u8; BODY_LEN] {
        let mut w = LeWriter::new();
        w.bytes(&self.consensus_config_commitment)
            .u16(VOTE_SCHEMA)
            .u64(self.height)
            .bytes(&self.block_id)
            .round(self.round)
            .u8(self.vote_type.code())
            .bytes(&self.validator_set_commitment)
            .u16(self.validator_index);
        w.into_bytes()
            .try_into()
            .expect("the body layout is exactly 113 bytes")
    }

    /// The 139-byte signature preimage, `D_VOTE ‖ body`.
    pub fn preimage(&self) -> [u8; PREIMAGE_LEN] {
        let mut out = [0u8; PREIMAGE_LEN];
        out[..D_VOTE.len()].copy_from_slice(&D_VOTE);
        out[D_VOTE.len()..].copy_from_slice(&self.body());
        out
    }

    /// Strict decode of a body: exactly 113 bytes, `schema` 1, `vote_type` 1
    /// or 2, `round ≤ 2^20`.
    pub fn decode_body(bytes: &[u8]) -> Result<FinalityVoteV1, VoteDecodeError> {
        if bytes.len() != BODY_LEN {
            return Err(VoteDecodeError::Length {
                expected: BODY_LEN,
                actual: bytes.len(),
            });
        }
        let mut r = LeReader::new(bytes);
        let fixed = "the length was checked above";
        let consensus_config_commitment = r.array().expect(fixed);
        let schema = r.u16().expect(fixed);
        if schema != VOTE_SCHEMA {
            return Err(VoteDecodeError::Schema(schema));
        }
        let height = r.u64().expect(fixed);
        let block_id = r.array().expect(fixed);
        let round = Round::new(r.u32().expect(fixed))?;
        let code = r.u8().expect(fixed);
        let vote_type = VoteType::from_code(code).ok_or(VoteDecodeError::VoteType(code))?;
        let validator_set_commitment = r.array().expect(fixed);
        let validator_index = r.u16().expect(fixed);
        r.finish().expect(fixed);
        Ok(FinalityVoteV1 {
            consensus_config_commitment,
            height,
            block_id,
            round,
            vote_type,
            validator_set_commitment,
            validator_index,
        })
    }
}

/// A decoded vote and its signature bytes. Decoding checks the format only;
/// [`verify`] checks the context and the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignedFinalityVoteV1 {
    pub vote: FinalityVoteV1,
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedFinalityVoteV1 {
    /// The 184-byte wire form.
    pub fn to_wire(&self) -> [u8; WIRE_LEN] {
        let mut out = [0u8; WIRE_LEN];
        out[..VOTE_MAGIC.len()].copy_from_slice(&VOTE_MAGIC);
        out[VOTE_MAGIC.len()..VOTE_MAGIC.len() + BODY_LEN].copy_from_slice(&self.vote.body());
        out[VOTE_MAGIC.len() + BODY_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// Strict decode of the wire form: exactly 184 bytes, the exact magic,
    /// then the body rules. Trailing bytes are refused by the length check.
    pub fn from_wire(bytes: &[u8]) -> Result<SignedFinalityVoteV1, VoteDecodeError> {
        if bytes.len() != WIRE_LEN {
            return Err(VoteDecodeError::Length {
                expected: WIRE_LEN,
                actual: bytes.len(),
            });
        }
        let (magic, rest) = bytes.split_at(VOTE_MAGIC.len());
        if magic != VOTE_MAGIC {
            return Err(VoteDecodeError::Magic);
        }
        let (body, signature) = rest.split_at(BODY_LEN);
        Ok(SignedFinalityVoteV1 {
            vote: FinalityVoteV1::decode_body(body)?,
            signature: signature.try_into().expect("the length was checked above"),
        })
    }
}

/// E1: strict Ed25519 verification of `message` (pure mode) under `key`.
pub fn verify_e1(key: &VerifyingKey, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    key.verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// Why a validator set was refused at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ValidatorSetError {
    #[error("the validator set is empty")]
    Empty,
    #[error("{n} validators exceeds the u16 capacity {}", MAX_VALIDATORS)]
    TooMany { n: usize },
    #[error("validator key {index} does not decode to a curve point")]
    Undecodable { index: u16 },
    #[error("validator key {index} is not the canonical encoding of its point")]
    NonCanonical { index: u16 },
    #[error("validator key {index} is a point of small order")]
    SmallOrder { index: u16 },
    #[error("validator keys {first} and {second} are the same key")]
    Duplicate { first: u16, second: u16 },
}

/// The validator set authenticated for a height, in authenticated order, with
/// the commitment that names it. Under G2-d that is the static genesis order
/// (ConsensusConfig field `0x0003 validators`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedValidatorSet {
    commitment: Digest,
    keys: Vec<VerifyingKey>,
}

impl AuthenticatedValidatorSet {
    /// A set from its commitment and its keys in authenticated order. Refused:
    /// an empty set, more than `u16::MAX` keys, a key that does not decode, is
    /// not canonically encoded or is of small order (V-6), and a duplicate.
    pub fn new(
        commitment: Digest,
        keys: &[[u8; 32]],
    ) -> Result<AuthenticatedValidatorSet, ValidatorSetError> {
        if keys.is_empty() {
            return Err(ValidatorSetError::Empty);
        }
        if keys.len() > MAX_VALIDATORS {
            return Err(ValidatorSetError::TooMany { n: keys.len() });
        }
        let mut seen: BTreeMap<[u8; 32], u16> = BTreeMap::new();
        let mut decoded = Vec::with_capacity(keys.len());
        for (i, bytes) in keys.iter().enumerate() {
            let index = u16::try_from(i).expect("the size was checked above");
            let key = VerifyingKey::from_bytes(bytes)
                .map_err(|_| ValidatorSetError::Undecodable { index })?;
            if key.to_edwards().compress().to_bytes() != *bytes {
                return Err(ValidatorSetError::NonCanonical { index });
            }
            if key.is_weak() {
                return Err(ValidatorSetError::SmallOrder { index });
            }
            if let Some(&first) = seen.get(bytes) {
                return Err(ValidatorSetError::Duplicate {
                    first,
                    second: index,
                });
            }
            seen.insert(*bytes, index);
            decoded.push(key);
        }
        Ok(AuthenticatedValidatorSet {
            commitment,
            keys: decoded,
        })
    }

    /// The commitment that names this set.
    pub fn commitment(&self) -> &Digest {
        &self.commitment
    }

    /// The number of validators `n`.
    pub fn len(&self) -> u16 {
        u16::try_from(self.keys.len()).expect("the size was checked at construction")
    }

    /// Always false: an empty set is refused at construction.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The key at `index` in authenticated order.
    pub fn key(&self, index: u16) -> Option<&VerifyingKey> {
        self.keys.get(usize::from(index))
    }
}

impl ValidatorSetResolver for AuthenticatedValidatorSet {
    fn validator_count(&self, commitment: &Digest) -> Option<u16> {
        (commitment == &self.commitment).then(|| self.len())
    }
}

/// What the verifier knows for a height. Both values are the node's own,
/// never taken from the vote.
pub trait VoteContext {
    /// The node's effective consensus-config commitment at `height`.
    fn consensus_config_commitment(&self, height: u64) -> Option<Digest>;
    /// The validator set authenticated for `height`.
    fn validator_set(&self, height: u64) -> Option<&AuthenticatedValidatorSet>;
}

/// Why a decoded vote was refused by its context or its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VoteVerifyError {
    #[error("no consensus-config commitment is known for height {height}")]
    NoConfigCommitment { height: u64 },
    #[error("the consensus-config commitment is not this node's for the vote's height")]
    ConfigCommitmentMismatch,
    #[error("no validator set is authenticated for height {height}")]
    NoValidatorSet { height: u64 },
    #[error("the validator-set commitment is not the authenticated set's")]
    ValidatorSetCommitmentMismatch,
    #[error("validator index {index} is not below the set size {n}")]
    IndexOutOfRange { index: u16, n: u16 },
    #[error("the signature does not verify under E1")]
    Signature,
}

/// Why wire bytes were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VoteError {
    #[error(transparent)]
    Decode(#[from] VoteDecodeError),
    #[error(transparent)]
    Verify(#[from] VoteVerifyError),
}

/// A vote that passed every context check and E1. Only [`verify`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedVote {
    signed: SignedFinalityVoteV1,
}

impl VerifiedVote {
    pub fn signed(&self) -> &SignedFinalityVoteV1 {
        &self.signed
    }
    pub fn vote(&self) -> &FinalityVoteV1 {
        &self.signed.vote
    }
}

/// Check a decoded vote against `context` and verify its signature (E1).
pub fn verify(
    signed: &SignedFinalityVoteV1,
    context: &dyn VoteContext,
) -> Result<VerifiedVote, VoteVerifyError> {
    let vote = &signed.vote;
    let height = vote.height;
    let commitment = context
        .consensus_config_commitment(height)
        .ok_or(VoteVerifyError::NoConfigCommitment { height })?;
    if vote.consensus_config_commitment != commitment {
        return Err(VoteVerifyError::ConfigCommitmentMismatch);
    }
    let set = context
        .validator_set(height)
        .ok_or(VoteVerifyError::NoValidatorSet { height })?;
    if vote.validator_set_commitment != *set.commitment() {
        return Err(VoteVerifyError::ValidatorSetCommitmentMismatch);
    }
    let n = set.len();
    let key = set
        .key(vote.validator_index)
        .ok_or(VoteVerifyError::IndexOutOfRange {
            index: vote.validator_index,
            n,
        })?;
    if !verify_e1(key, &vote.preimage(), &signed.signature) {
        return Err(VoteVerifyError::Signature);
    }
    Ok(VerifiedVote { signed: *signed })
}

/// Decode wire bytes, then [`verify`].
pub fn decode_and_verify(
    wire: &[u8],
    context: &dyn VoteContext,
) -> Result<VerifiedVote, VoteError> {
    let signed = SignedFinalityVoteV1::from_wire(wire)?;
    Ok(verify(&signed, context)?)
}

/// The slot a vote occupies: at most one vote counts per slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Slot {
    consensus_config_commitment: Digest,
    height: u64,
    round: Round,
    vote_type: VoteType,
    validator_index: u16,
}

impl Slot {
    fn of(vote: &FinalityVoteV1) -> Slot {
        Slot {
            consensus_config_commitment: vote.consensus_config_commitment,
            height: vote.height,
            round: vote.round,
            vote_type: vote.vote_type,
            validator_index: vote.validator_index,
        }
    }
}

/// Two valid votes for one slot with different `block_id`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Equivocation {
    /// The vote already counted for the slot.
    pub counted: SignedFinalityVoteV1,
    /// The conflicting vote, which is not counted.
    pub conflicting: SignedFinalityVoteV1,
}

/// The result of adding a verified vote to a tally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TallyOutcome {
    /// The first vote for its slot: it counts.
    Counted,
    /// The slot already holds this body (signature bytes may differ): not
    /// counted again.
    Duplicate,
    /// The slot holds a vote for another `block_id`: not counted.
    Equivocation(Box<Equivocation>),
}

/// Why a tally refused a vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TallyError {
    #[error("the vote names another validator set than this tally's")]
    OtherValidatorSet,
}

/// Why no certificate can be formed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CertificateRefusal {
    #[error("a certificate is never formed for the nil block_id")]
    Nil,
    #[error(transparent)]
    Signers(#[from] SignerSetError),
}

/// Counted votes for one validator set.
#[derive(Debug, Clone)]
pub struct VoteTally {
    validator_set_commitment: Digest,
    n: u16,
    slots: BTreeMap<Slot, SignedFinalityVoteV1>,
}

impl VoteTally {
    /// An empty tally for `set`.
    pub fn new(set: &AuthenticatedValidatorSet) -> VoteTally {
        VoteTally {
            validator_set_commitment: *set.commitment(),
            n: set.len(),
            slots: BTreeMap::new(),
        }
    }

    /// Add a verified vote.
    pub fn insert(&mut self, vote: &VerifiedVote) -> Result<TallyOutcome, TallyError> {
        let signed = vote.signed();
        if signed.vote.validator_set_commitment != self.validator_set_commitment {
            return Err(TallyError::OtherValidatorSet);
        }
        let slot = Slot::of(&signed.vote);
        match self.slots.get(&slot) {
            None => {
                self.slots.insert(slot, *signed);
                Ok(TallyOutcome::Counted)
            }
            Some(counted) if counted.vote == signed.vote => Ok(TallyOutcome::Duplicate),
            Some(counted) => Ok(TallyOutcome::Equivocation(Box::new(Equivocation {
                counted: *counted,
                conflicting: *signed,
            }))),
        }
    }

    /// Indices, ascending, of the counted votes of `vote_type` for `block_id`
    /// (nil included) at (`consensus_config_commitment`, `height`, `round`).
    pub fn counted_indices(
        &self,
        consensus_config_commitment: &Digest,
        height: u64,
        round: Round,
        vote_type: VoteType,
        block_id: &Digest,
    ) -> Vec<u16> {
        let indices: BTreeSet<u16> = self
            .slots
            .iter()
            .filter(|(slot, signed)| {
                slot.consensus_config_commitment == *consensus_config_commitment
                    && slot.height == height
                    && slot.round == round
                    && slot.vote_type == vote_type
                    && signed.vote.block_id == *block_id
            })
            .map(|(slot, _)| slot.validator_index)
            .collect();
        indices.into_iter().collect()
    }

    /// The signers of a certificate for `block_id`: the counted precommits for
    /// it, checked against the quorum of this set (D2). Refused for the nil
    /// `block_id`, whatever the number of nil precommits.
    pub fn certificate_signers(
        &self,
        consensus_config_commitment: &Digest,
        height: u64,
        round: Round,
        block_id: &Digest,
    ) -> Result<CertificateSigners, CertificateRefusal> {
        if *block_id == NIL_BLOCK_ID {
            return Err(CertificateRefusal::Nil);
        }
        let indices = self.counted_indices(
            consensus_config_commitment,
            height,
            round,
            VoteType::Precommit,
            block_id,
        );
        Ok(certificate::check_signers(
            &self.validator_set_commitment,
            &indices,
            &TallySet(self),
        )?)
    }
}

struct TallySet<'a>(&'a VoteTally);

impl ValidatorSetResolver for TallySet<'_> {
    fn validator_count(&self, commitment: &Digest) -> Option<u16> {
        (commitment == &self.0.validator_set_commitment).then_some(self.0.n)
    }
}

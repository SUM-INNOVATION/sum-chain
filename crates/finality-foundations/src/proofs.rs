//! PROPOSED, UNRATIFIED: the consensus proofs the signer verifies itself.
//!
//! * [`PolkaProofV1`]: a prevote quorum for (height, round, block), the
//!   justification V left opaque. It is the ratified `FinalityCertificateV1`
//!   layout with its own magic `FPOLv1\0` and PREVOTE entries; every entry
//!   signs the ratified `FinalityVoteV1` preimage with `vote_type = 1`, so the
//!   signatures are exactly the gossiped prevotes and no new signing domain
//!   exists. The bytes are not ratified.
//! * [`ConsensusProofs`]: the signer's [`PolkaVerifier`] over a node's
//!   [`VoteContext`]. It verifies a [`PolkaProofV1`] for a lock change and a
//!   ratified [`FinalityCertificateV1`] for a height advancement, each against
//!   the set authenticated for the height the proof names. Nothing the
//!   consensus core says is trusted.
//!
//! Dormant: nothing calls this module.

use thiserror::Error;

use crate::certificate::{
    certificate_len, check_signers, quorum, verify_certificate, CertificateEntry,
    CertificateSigners, FinalityCertificateV1, SignerSetError, CERT_ENTRY_LEN, CERT_HEADER_LEN,
    MAX_VALIDATORS,
};
use crate::encoding::{LeReader, LeWriter, Round, RoundOutOfRange};
use crate::signer::{Certified, PolkaVerifier};
use crate::vote::{verify_e1, FinalityVoteV1, VoteContext, VoteType, NIL_BLOCK_ID};
use crate::Digest;

/// UNRATIFIED: the prevote-quorum wire magic, `FPOLv1\0` (`46504f4c763100`).
pub const POLKA_MAGIC: [u8; 7] = *b"FPOLv1\0";
/// UNRATIFIED: the only accepted schema.
pub const POLKA_SCHEMA: u16 = 1;
/// Fixed header through the signer count `k` (as the certificate).
pub const POLKA_HEADER_LEN: usize = CERT_HEADER_LEN;
/// One entry: `validator_index u16 ‖ prevote signature[64]`.
pub const POLKA_ENTRY_LEN: usize = CERT_ENTRY_LEN;
/// The largest valid proof: `k = n = 65,535`, 4,325,429 bytes.
pub const MAX_POLKA_LEN: usize = polka_proof_len(MAX_VALIDATORS);

/// `119 + 66·k`, the same as a certificate with `k` signers.
pub const fn polka_proof_len(k: u16) -> usize {
    certificate_len(k)
}

/// A decoded prevote quorum. Decoding guarantees a non-nil block, a valid
/// round, at most 65,535 entries in strictly ascending index order; the rest
/// is checked by [`verify_polka_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolkaProofV1 {
    pub consensus_config_commitment: Digest,
    pub height: u64,
    pub block_id: Digest,
    pub round: Round,
    pub validator_set_commitment: Digest,
    pub entries: Vec<CertificateEntry>,
}

/// Why prevote-quorum bytes were refused before any context check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PolkaDecodeError {
    #[error("length {actual} is shorter than the 119-byte header")]
    ShortHeader { actual: usize },
    #[error("the wire magic is not FPOLv1\\0")]
    Magic,
    #[error("schema {0} is not 1")]
    Schema(u16),
    #[error("length {actual} is not 119 + 66 × {k} = {expected}")]
    Length {
        k: u16,
        expected: usize,
        actual: usize,
    },
    #[error(transparent)]
    Round(#[from] RoundOutOfRange),
    #[error("a prevote quorum for the nil block_id justifies nothing")]
    NilBlock,
    #[error("signer index {index} does not follow {previous} in strictly ascending order")]
    NotStrictlyAscending { previous: u16, index: u16 },
}

/// Why a proof could not be encoded (it would not decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PolkaEncodeError {
    #[error("{k} entries exceeds the u16 signer count")]
    TooManyEntries { k: usize },
    #[error("a prevote quorum for the nil block_id justifies nothing")]
    NilBlock,
    #[error("signer index {index} does not follow {previous} in strictly ascending order")]
    NotStrictlyAscending { previous: u16, index: u16 },
}

/// Why a decoded proof was refused for the request it should justify.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolkaVerifyError {
    #[error("the proof names height {named}, not {expected}")]
    HeightMismatch { named: u64, expected: u64 },
    #[error("the proof names round {named}, not {expected}")]
    RoundMismatch { named: u32, expected: u32 },
    #[error("the proof names another block than the value being signed")]
    BlockMismatch,
    #[error("no consensus-config commitment is known for height {height}")]
    NoConfigCommitment { height: u64 },
    #[error("the consensus-config commitment is not this node's for the height")]
    ConfigCommitmentMismatch,
    #[error("no validator set is authenticated for height {height}")]
    NoValidatorSet { height: u64 },
    #[error("the validator-set commitment is not the authenticated set's")]
    ValidatorSetCommitmentMismatch,
    #[error(transparent)]
    Signers(#[from] SignerSetError),
    #[error("the PREVOTE signature of validator {index} does not verify under E1")]
    Signature { index: u16 },
}

/// Why prevote-quorum bytes were refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolkaError {
    #[error(transparent)]
    Decode(#[from] PolkaDecodeError),
    #[error(transparent)]
    Verify(#[from] PolkaVerifyError),
}

impl PolkaProofV1 {
    /// The signer indices, in entry order.
    pub fn indices(&self) -> Vec<u16> {
        self.entries.iter().map(|e| e.validator_index).collect()
    }

    /// The PREVOTE entry `validator_index` signs: the proof's fields with
    /// `vote_type = 1`.
    pub fn prevote(&self, validator_index: u16) -> FinalityVoteV1 {
        FinalityVoteV1 {
            consensus_config_commitment: self.consensus_config_commitment,
            height: self.height,
            block_id: self.block_id,
            round: self.round,
            vote_type: VoteType::Prevote,
            validator_set_commitment: self.validator_set_commitment,
            validator_index,
        }
    }

    /// The `119 + 66·k`-byte wire form.
    pub fn encode(&self) -> Result<Vec<u8>, PolkaEncodeError> {
        let k =
            u16::try_from(self.entries.len()).map_err(|_| PolkaEncodeError::TooManyEntries {
                k: self.entries.len(),
            })?;
        if self.block_id == NIL_BLOCK_ID {
            return Err(PolkaEncodeError::NilBlock);
        }
        for pair in self.entries.windows(2) {
            if pair[1].validator_index <= pair[0].validator_index {
                return Err(PolkaEncodeError::NotStrictlyAscending {
                    previous: pair[0].validator_index,
                    index: pair[1].validator_index,
                });
            }
        }
        let mut w = LeWriter::new();
        w.bytes(&POLKA_MAGIC)
            .u16(POLKA_SCHEMA)
            .bytes(&self.consensus_config_commitment)
            .u64(self.height)
            .bytes(&self.block_id)
            .round(self.round)
            .bytes(&self.validator_set_commitment)
            .u16(k);
        for e in &self.entries {
            w.u16(e.validator_index).bytes(&e.signature);
        }
        let out = w.into_bytes();
        debug_assert_eq!(out.len(), polka_proof_len(k));
        Ok(out)
    }

    /// Strict decode, in this order: header present; magic; schema; total
    /// length exactly `119 + 66·k` (checked before anything is allocated for
    /// the entries); round `≤ 2^20`; non-nil block; strictly ascending
    /// indices.
    pub fn decode(bytes: &[u8]) -> Result<PolkaProofV1, PolkaDecodeError> {
        if bytes.len() < POLKA_HEADER_LEN {
            return Err(PolkaDecodeError::ShortHeader {
                actual: bytes.len(),
            });
        }
        let fixed = "the header length was checked above";
        let mut r = LeReader::new(bytes);
        if r.array::<7>().expect(fixed) != POLKA_MAGIC {
            return Err(PolkaDecodeError::Magic);
        }
        let schema = r.u16().expect(fixed);
        if schema != POLKA_SCHEMA {
            return Err(PolkaDecodeError::Schema(schema));
        }
        let consensus_config_commitment = r.array().expect(fixed);
        let height = r.u64().expect(fixed);
        let block_id: Digest = r.array().expect(fixed);
        let round_raw = r.u32().expect(fixed);
        let validator_set_commitment = r.array().expect(fixed);
        let k = r.u16().expect(fixed);
        let expected = polka_proof_len(k);
        if bytes.len() != expected {
            return Err(PolkaDecodeError::Length {
                k,
                expected,
                actual: bytes.len(),
            });
        }
        let round = Round::new(round_raw)?;
        if block_id == NIL_BLOCK_ID {
            return Err(PolkaDecodeError::NilBlock);
        }
        let exact = "the total length was checked above";
        let mut entries = Vec::with_capacity(usize::from(k));
        let mut previous: Option<u16> = None;
        for _ in 0..k {
            let validator_index = r.u16().expect(exact);
            if let Some(p) = previous {
                if validator_index <= p {
                    return Err(PolkaDecodeError::NotStrictlyAscending {
                        previous: p,
                        index: validator_index,
                    });
                }
            }
            previous = Some(validator_index);
            entries.push(CertificateEntry {
                validator_index,
                signature: r.array().expect(exact),
            });
        }
        r.finish().expect(exact);
        Ok(PolkaProofV1 {
            consensus_config_commitment,
            height,
            block_id,
            round,
            validator_set_commitment,
            entries,
        })
    }
}

/// Check `proof` as the quorum justifying a vote for `block_id` at
/// (`height`, `round`), in this order: it names exactly that height, round
/// and block; its config commitment is the node's at `height`; its
/// validator-set commitment is the authenticated set's for `height`; the
/// signer indices pass [`check_signers`]; every reconstructed PREVOTE verifies
/// under E1. The first failure refuses the whole proof.
pub fn verify_polka_proof(
    proof: &PolkaProofV1,
    height: u64,
    round: u32,
    block_id: &Digest,
    context: &dyn VoteContext,
) -> Result<CertificateSigners, PolkaVerifyError> {
    if proof.height != height {
        return Err(PolkaVerifyError::HeightMismatch {
            named: proof.height,
            expected: height,
        });
    }
    if proof.round.get() != round {
        return Err(PolkaVerifyError::RoundMismatch {
            named: proof.round.get(),
            expected: round,
        });
    }
    if proof.block_id != *block_id {
        return Err(PolkaVerifyError::BlockMismatch);
    }
    let commitment = context
        .consensus_config_commitment(height)
        .ok_or(PolkaVerifyError::NoConfigCommitment { height })?;
    if proof.consensus_config_commitment != commitment {
        return Err(PolkaVerifyError::ConfigCommitmentMismatch);
    }
    let set = context
        .validator_set(height)
        .ok_or(PolkaVerifyError::NoValidatorSet { height })?;
    if proof.validator_set_commitment != *set.commitment() {
        return Err(PolkaVerifyError::ValidatorSetCommitmentMismatch);
    }
    let signers = check_signers(&proof.validator_set_commitment, &proof.indices(), set)?;
    for e in &proof.entries {
        let key = set
            .key(e.validator_index)
            .expect("check_signers refused every index outside the set");
        if !verify_e1(
            key,
            &proof.prevote(e.validator_index).preimage(),
            &e.signature,
        ) {
            return Err(PolkaVerifyError::Signature {
                index: e.validator_index,
            });
        }
    }
    Ok(signers)
}

/// Decode, then [`verify_polka_proof`].
pub fn decode_and_verify_polka_proof(
    bytes: &[u8],
    height: u64,
    round: u32,
    block_id: &Digest,
    context: &dyn VoteContext,
) -> Result<CertificateSigners, PolkaError> {
    let proof = PolkaProofV1::decode(bytes)?;
    Ok(verify_polka_proof(
        &proof, height, round, block_id, context,
    )?)
}

/// The signer's own proof verifier over a node's authenticated context.
///
/// * Lock change: `evidence` must be a [`PolkaProofV1`] for exactly the
///   request's (height, polka round, value).
/// * Height advancement: `proof` must be a ratified [`FinalityCertificateV1`]
///   that verifies for the (height, block) it names against the set
///   authenticated for that height; the result is that (height, block).
pub struct ConsensusProofs<C> {
    context: C,
}

impl<C: VoteContext> ConsensusProofs<C> {
    pub fn new(context: C) -> Self {
        Self { context }
    }
}

impl<C: VoteContext> PolkaVerifier for ConsensusProofs<C> {
    fn verify_polka(
        &self,
        height: u64,
        round: u32,
        value: &Digest,
        evidence: &[u8],
    ) -> Result<(), String> {
        decode_and_verify_polka_proof(evidence, height, round, value, &self.context)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn verify_finality(&self, proof: &[u8]) -> Result<Certified, String> {
        let cert = FinalityCertificateV1::decode(proof).map_err(|e| e.to_string())?;
        verify_certificate(&cert, cert.height, &cert.block_id, &self.context)
            .map_err(|e| e.to_string())?;
        Ok(Certified {
            height: cert.height,
            block_id: cert.block_id,
        })
    }

    /// The accepted prevote quorum trimmed to its `q(n)` lowest-index
    /// entries, returned only if the trimmed proof still verifies.
    fn retained_polka(
        &self,
        height: u64,
        round: u32,
        value: &Digest,
        evidence: &[u8],
    ) -> Option<Vec<u8>> {
        let mut proof = PolkaProofV1::decode(evidence).ok()?;
        let n = self.context.validator_set(height)?.len();
        proof.entries.truncate(usize::from(quorum(n)));
        let bytes = proof.encode().ok()?;
        decode_and_verify_polka_proof(&bytes, height, round, value, &self.context).ok()?;
        Some(bytes)
    }

    /// The accepted finality certificate trimmed the same way.
    fn retained_finality(&self, proof: &[u8]) -> Option<Vec<u8>> {
        let mut cert = FinalityCertificateV1::decode(proof).ok()?;
        let n = self.context.validator_set(cert.height)?.len();
        cert.entries.truncate(usize::from(quorum(n)));
        let bytes = cert.encode().ok()?;
        let again = FinalityCertificateV1::decode(&bytes).ok()?;
        verify_certificate(&again, again.height, &again.block_id, &self.context).ok()?;
        Some(bytes)
    }
}

//! G2 finality certificate. DORMANT.
//!
//! * **D2** (group A1, RATIFIED 2026-10-17): a certificate carries no
//!   explicit validator count. `n` is implied by the validator-set commitment
//!   the certificate names, which the verifier must resolve anyway.
//!   [`check_signers`] checks signer indices against that `n`:
//!   * the commitment must resolve to a known set whose count passes
//!     [`checked_validator_count`] (`1 ≤ n ≤ 65,535`);
//!   * `q(n) ≤ k ≤ n`, with quorum `q(n) = ⌊2n/3⌋ + 1`;
//!   * every index is `< n`, and the indices are strictly ascending (so a
//!     duplicate is refused).
//! * **C** (RATIFIED 2026-10-19): the wire encoding and validity of
//!   [`FinalityCertificateV1`], `119 + 66·k` bytes:
//!
//! | Offset | Width | Field | Encoding | Rule |
//! |---|---|---|---|---|
//! | 0 | 7 | [`CERT_MAGIC`] `FCRTv1\0` | bytes | exact |
//! | 7 | 2 | `schema` | u16 LE | 1 |
//! | 9 | 32 | `consensus_config_commitment` | bytes | the node's effective commitment at `height` |
//! | 41 | 8 | `height` | u64 LE | the height being committed |
//! | 49 | 32 | `block_id` | bytes | never all zero (a certificate never commits nil) |
//! | 81 | 4 | `round` | u32 LE | `≤ 2^20` (D4) |
//! | 85 | 32 | `validator_set_commitment` | bytes | the set authenticated for `height`; implies `n` (D2) |
//! | 117 | 2 | `k` | u16 LE | `q(n) ≤ k ≤ n` |
//! | 119 | 66·k | `k × (validator_index u16 LE ‖ signature[64])` | entries | indices `< n`, strictly ascending |
//!
//!   Entry `i`'s signature is a ratified `FinalityVoteV1` PRECOMMIT signature:
//!   the verifier reconstructs the vote from the certificate's fields with
//!   `vote_type = 2` and the entry's index, and checks the 139-byte preimage
//!   under E1 (`verify_strict`). There is no certificate-specific domain.
//!   **Any** invalid entry refuses the whole certificate; nothing is trimmed.
//!
//! [`FinalityCertificateV1::decode`] checks the total length against
//! `119 + 66·k` from the header before it allocates anything for the
//! entries, so a header that declares more signers than the input holds is
//! refused without allocation.
//!
//! Sizes depend on `k`, not `n` (the quorum minimum and the all-signers size
//! differ): see [`certificate_len`].
//!
//! # Not here (not decided)
//!
//! Storage: no column family, key, finalized pointer or migration. The
//! certified-commit seam (#292) is untouched; how a certificate is stored is a
//! separate decision. How a validator-set commitment is computed and how a
//! set is resolved from it are injected ([`ValidatorSetResolver`],
//! [`VoteContext`]). Nothing calls this module from a node path.

use thiserror::Error;

use crate::encoding::{LeReader, LeWriter, Round, RoundOutOfRange};
use crate::vote::{verify_e1, FinalityVoteV1, VoteContext, VoteType, NIL_BLOCK_ID, SIGNATURE_LEN};
use crate::Digest;

/// The largest validator count `n`: `n` and every signer index fit a `u16`
/// (owner, 2026-10-18, for this dormant protocol version). Every place that
/// represents a validator count as a `u16` checks it with
/// [`checked_validator_count`].
pub const MAX_VALIDATORS: u16 = u16::MAX;

/// Why a validator count is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ValidatorCountError {
    #[error("a validator set is never empty")]
    Empty,
    #[error("{n} validators exceeds the cap {}", MAX_VALIDATORS)]
    TooMany { n: usize },
}

/// The one check of a validator count: `1 ≤ n ≤ MAX_VALIDATORS`, returned as
/// the `u16` the encodings carry.
pub const fn checked_validator_count(n: usize) -> Result<u16, ValidatorCountError> {
    if n == 0 {
        Err(ValidatorCountError::Empty)
    } else if n > MAX_VALIDATORS as usize {
        Err(ValidatorCountError::TooMany { n })
    } else {
        Ok(n as u16)
    }
}

/// Resolves a validator-set commitment to the size `n` of the set it names.
pub trait ValidatorSetResolver {
    /// `None` when the commitment names no known set.
    fn validator_count(&self, commitment: &Digest) -> Option<u16>;
}

/// Signatures needed from a set of `n`: `⌊2n/3⌋ + 1`, the least count
/// strictly greater than two-thirds of `n`. Computed in `u32`, so it cannot
/// overflow; `quorum(65_535) = 43_691`.
pub const fn quorum(n: u16) -> u16 {
    (n as u32 * 2 / 3 + 1) as u16
}

/// A certificate's signer entries, checked against the resolved set (D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSigners {
    n: u16,
    indices: Vec<u16>,
}

impl CertificateSigners {
    /// The validator count implied by the commitment.
    pub fn validator_count(&self) -> u16 {
        self.n
    }
    /// The signer indices, strictly ascending.
    pub fn indices(&self) -> &[u16] {
        &self.indices
    }
}

/// Why a certificate's signer entries were refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignerSetError {
    #[error("the validator-set commitment names no known set")]
    UnknownValidatorSet,
    #[error("the validator-set commitment names an empty set")]
    EmptyValidatorSet,
    #[error("{k} signers is below the quorum {quorum} of {n}")]
    BelowQuorum { k: usize, quorum: u16, n: u16 },
    #[error("{k} signers exceeds the set size {n}")]
    AboveSetSize { k: usize, n: u16 },
    #[error("signer index {index} is not below the set size {n}")]
    IndexOutOfRange { index: u16, n: u16 },
    #[error("signer index {index} does not follow {previous} in strictly ascending order")]
    NotStrictlyAscending { previous: u16, index: u16 },
}

/// Check signer `indices` against the set `commitment` names (D2).
pub fn check_signers(
    commitment: &Digest,
    indices: &[u16],
    resolver: &dyn ValidatorSetResolver,
) -> Result<CertificateSigners, SignerSetError> {
    let n = resolver
        .validator_count(commitment)
        .ok_or(SignerSetError::UnknownValidatorSet)?;
    // A `u16` count never exceeds the cap, so the only refusal here is empty.
    let n =
        checked_validator_count(usize::from(n)).map_err(|_| SignerSetError::EmptyValidatorSet)?;
    let k = indices.len();
    if k > usize::from(n) {
        return Err(SignerSetError::AboveSetSize { k, n });
    }
    let q = quorum(n);
    if k < usize::from(q) {
        return Err(SignerSetError::BelowQuorum { k, quorum: q, n });
    }
    let mut previous: Option<u16> = None;
    for &index in indices {
        if index >= n {
            return Err(SignerSetError::IndexOutOfRange { index, n });
        }
        if let Some(p) = previous {
            if index <= p {
                return Err(SignerSetError::NotStrictlyAscending { previous: p, index });
            }
        }
        previous = Some(index);
    }
    Ok(CertificateSigners {
        n,
        indices: indices.to_vec(),
    })
}

/// The certificate's wire magic, `FCRTv1\0` (7 bytes).
pub const CERT_MAGIC: [u8; 7] = *b"FCRTv1\0";
/// The only accepted certificate `schema`.
pub const CERT_SCHEMA: u16 = 1;
/// Length of the fixed header, through the signer count `k`.
pub const CERT_HEADER_LEN: usize = 119;
/// Length of one signer entry: `validator_index u16 ‖ signature[64]`.
pub const CERT_ENTRY_LEN: usize = 2 + SIGNATURE_LEN;
/// The largest valid certificate: `k = n = 65,535`.
pub const MAX_CERT_LEN: usize = certificate_len(MAX_VALIDATORS);

/// The exact length of a certificate with `k` signers, `119 + 66·k`. It
/// depends on `k`, not `n`: for `n = 4` the quorum minimum `k = 3` is 317
/// bytes and the all-signers `k = 4` is 383 bytes.
pub const fn certificate_len(k: u16) -> usize {
    CERT_HEADER_LEN + CERT_ENTRY_LEN * k as usize
}

/// One signer entry: the signer's index in the authenticated set and its
/// PRECOMMIT signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateEntry {
    pub validator_index: u16,
    pub signature: [u8; SIGNATURE_LEN],
}

/// A decoded `FinalityCertificateV1`. `schema` is not a field: it is always 1.
/// Decoding guarantees a non-nil `block_id`, a valid round, at most
/// [`MAX_VALIDATORS`] entries and strictly ascending indices; everything that
/// needs the authenticated set is checked by [`verify_certificate`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FinalityCertificateV1 {
    pub consensus_config_commitment: Digest,
    pub height: u64,
    pub block_id: Digest,
    pub round: Round,
    pub validator_set_commitment: Digest,
    pub entries: Vec<CertificateEntry>,
}

/// Why certificate bytes were refused before any context check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CertificateDecodeError {
    #[error("length {actual} is shorter than the {}-byte header", CERT_HEADER_LEN)]
    ShortHeader { actual: usize },
    #[error("the wire magic is not FCRTv1\\0")]
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
    #[error("a certificate never commits the nil block_id")]
    NilBlock,
    #[error("signer index {index} does not follow {previous} in strictly ascending order")]
    NotStrictlyAscending { previous: u16, index: u16 },
}

/// Why a certificate could not be encoded (it would not decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CertificateEncodeError {
    #[error("{k} entries exceeds the u16 signer count")]
    TooManyEntries { k: usize },
    #[error("a certificate never commits the nil block_id")]
    NilBlock,
    #[error("signer index {index} does not follow {previous} in strictly ascending order")]
    NotStrictlyAscending { previous: u16, index: u16 },
}

fn check_ascending(entries: &[CertificateEntry]) -> Result<(), (u16, u16)> {
    for pair in entries.windows(2) {
        let (previous, index) = (pair[0].validator_index, pair[1].validator_index);
        if index <= previous {
            return Err((previous, index));
        }
    }
    Ok(())
}

impl FinalityCertificateV1 {
    /// The number of signers `k`.
    pub fn signer_count(&self) -> usize {
        self.entries.len()
    }

    /// The signer indices, in entry order.
    pub fn indices(&self) -> Vec<u16> {
        self.entries.iter().map(|e| e.validator_index).collect()
    }

    /// The PRECOMMIT vote entry `validator_index` signs: the certificate's
    /// fields with `vote_type = 2`.
    pub fn precommit(&self, validator_index: u16) -> FinalityVoteV1 {
        FinalityVoteV1 {
            consensus_config_commitment: self.consensus_config_commitment,
            height: self.height,
            block_id: self.block_id,
            round: self.round,
            vote_type: VoteType::Precommit,
            validator_set_commitment: self.validator_set_commitment,
            validator_index,
        }
    }

    /// The `119 + 66·k`-byte wire form. Refused when it would not decode:
    /// more than 65,535 entries, a nil `block_id`, or indices that are not
    /// strictly ascending.
    pub fn encode(&self) -> Result<Vec<u8>, CertificateEncodeError> {
        let k = u16::try_from(self.entries.len()).map_err(|_| {
            CertificateEncodeError::TooManyEntries {
                k: self.entries.len(),
            }
        })?;
        if self.block_id == NIL_BLOCK_ID {
            return Err(CertificateEncodeError::NilBlock);
        }
        check_ascending(&self.entries).map_err(|(previous, index)| {
            CertificateEncodeError::NotStrictlyAscending { previous, index }
        })?;
        let mut w = LeWriter::new();
        w.bytes(&CERT_MAGIC)
            .u16(CERT_SCHEMA)
            .bytes(&self.consensus_config_commitment)
            .u64(self.height)
            .bytes(&self.block_id)
            .round(self.round)
            .bytes(&self.validator_set_commitment)
            .u16(k);
        for entry in &self.entries {
            w.u16(entry.validator_index).bytes(&entry.signature);
        }
        let out = w.into_bytes();
        debug_assert_eq!(out.len(), certificate_len(k));
        Ok(out)
    }

    /// Strict decode. In order: the header is present; magic; schema; the
    /// total length is exactly `119 + 66·k` for the header's `k` (checked
    /// before anything is allocated for the entries, so trailing bytes and a
    /// header that over-declares `k` are refused here); round `≤ 2^20`;
    /// non-nil `block_id`; strictly ascending indices.
    pub fn decode(bytes: &[u8]) -> Result<FinalityCertificateV1, CertificateDecodeError> {
        if bytes.len() < CERT_HEADER_LEN {
            return Err(CertificateDecodeError::ShortHeader {
                actual: bytes.len(),
            });
        }
        let fixed = "the header length was checked above";
        let mut r = LeReader::new(bytes);
        if r.array::<7>().expect(fixed) != CERT_MAGIC {
            return Err(CertificateDecodeError::Magic);
        }
        let schema = r.u16().expect(fixed);
        if schema != CERT_SCHEMA {
            return Err(CertificateDecodeError::Schema(schema));
        }
        let consensus_config_commitment = r.array().expect(fixed);
        let height = r.u64().expect(fixed);
        let block_id: Digest = r.array().expect(fixed);
        let round_raw = r.u32().expect(fixed);
        let validator_set_commitment = r.array().expect(fixed);
        let k = r.u16().expect(fixed);
        let expected = certificate_len(k);
        if bytes.len() != expected {
            return Err(CertificateDecodeError::Length {
                k,
                expected,
                actual: bytes.len(),
            });
        }
        let round = Round::new(round_raw)?;
        if block_id == NIL_BLOCK_ID {
            return Err(CertificateDecodeError::NilBlock);
        }
        let exact = "the total length was checked above";
        let mut entries = Vec::with_capacity(usize::from(k));
        let mut previous: Option<u16> = None;
        for _ in 0..k {
            let validator_index = r.u16().expect(exact);
            if let Some(p) = previous {
                if validator_index <= p {
                    return Err(CertificateDecodeError::NotStrictlyAscending {
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
        Ok(FinalityCertificateV1 {
            consensus_config_commitment,
            height,
            block_id,
            round,
            validator_set_commitment,
            entries,
        })
    }
}

/// Why a certificate was refused by its context or its signatures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CertificateVerifyError {
    #[error("the certificate names height {named}, not the committed height {committed}")]
    HeightMismatch { named: u64, committed: u64 },
    #[error("the certificate names another block_id than the one being committed")]
    BlockMismatch,
    #[error("a certificate never commits the nil block_id")]
    NilBlock,
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
    #[error("the PRECOMMIT signature of validator {index} does not verify under E1")]
    Signature { index: u16 },
}

/// Why certificate bytes were refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CertificateError {
    #[error(transparent)]
    Decode(#[from] CertificateDecodeError),
    #[error(transparent)]
    Verify(#[from] CertificateVerifyError),
}

/// A certificate that passed every check. Only [`verify_certificate`] makes
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCertificate {
    certificate: FinalityCertificateV1,
    signers: CertificateSigners,
}

impl VerifiedCertificate {
    pub fn certificate(&self) -> &FinalityCertificateV1 {
        &self.certificate
    }
    pub fn signers(&self) -> &CertificateSigners {
        &self.signers
    }
}

/// Check `certificate` for committing (`height`, `block_id`) against the
/// node's own `context`, then verify every entry. In order:
///
/// 1. it names exactly `height` and `block_id`, and `block_id` is not nil;
/// 2. its `consensus_config_commitment` is the node's effective one at
///    `height`;
/// 3. its `validator_set_commitment` is the set authenticated for `height`,
///    which gives `n`;
/// 4. the signer indices pass [`check_signers`] (`q(n) ≤ k ≤ n`, every index
///    `< n`, strictly ascending), before any signature is checked;
/// 5. every entry's reconstructed PRECOMMIT verifies under E1 against the
///    set's key at its index. The first failure refuses the whole
///    certificate.
pub fn verify_certificate(
    certificate: &FinalityCertificateV1,
    height: u64,
    block_id: &Digest,
    context: &dyn VoteContext,
) -> Result<VerifiedCertificate, CertificateVerifyError> {
    if certificate.height != height {
        return Err(CertificateVerifyError::HeightMismatch {
            named: certificate.height,
            committed: height,
        });
    }
    if certificate.block_id != *block_id {
        return Err(CertificateVerifyError::BlockMismatch);
    }
    if certificate.block_id == NIL_BLOCK_ID {
        return Err(CertificateVerifyError::NilBlock);
    }
    let commitment = context
        .consensus_config_commitment(height)
        .ok_or(CertificateVerifyError::NoConfigCommitment { height })?;
    if certificate.consensus_config_commitment != commitment {
        return Err(CertificateVerifyError::ConfigCommitmentMismatch);
    }
    let set = context
        .validator_set(height)
        .ok_or(CertificateVerifyError::NoValidatorSet { height })?;
    if certificate.validator_set_commitment != *set.commitment() {
        return Err(CertificateVerifyError::ValidatorSetCommitmentMismatch);
    }
    let signers = check_signers(
        &certificate.validator_set_commitment,
        &certificate.indices(),
        set,
    )?;
    for entry in &certificate.entries {
        let index = entry.validator_index;
        let key = set
            .key(index)
            .expect("check_signers refused every index outside the set");
        let preimage = certificate.precommit(index).preimage();
        if !verify_e1(key, &preimage, &entry.signature) {
            return Err(CertificateVerifyError::Signature { index });
        }
    }
    Ok(VerifiedCertificate {
        certificate: certificate.clone(),
        signers,
    })
}

/// Decode certificate bytes, then [`verify_certificate`].
pub fn decode_and_verify_certificate(
    bytes: &[u8],
    height: u64,
    block_id: &Digest,
    context: &dyn VoteContext,
) -> Result<VerifiedCertificate, CertificateError> {
    let certificate = FinalityCertificateV1::decode(bytes)?;
    Ok(verify_certificate(&certificate, height, block_id, context)?)
}

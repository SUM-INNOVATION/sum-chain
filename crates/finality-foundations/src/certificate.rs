//! G2 group A1 rule D2, RATIFIED 2026-10-17: a certificate carries no
//! explicit validator count. DORMANT.
//!
//! The count `n` is implied by the validator-set commitment the certificate
//! names, which the verifier must resolve anyway. This module checks a
//! certificate's signer entries against the `n` of the resolved set:
//!
//! * the commitment must resolve to a known, non-empty set;
//! * `q(n) ≤ k ≤ n`, with quorum `q(n) = ⌊2n/3⌋ + 1`;
//! * every index is `< n`, and the indices are strictly ascending (so a
//!   duplicate is refused).
//!
//! # Not here (unratified)
//!
//! The certificate's byte layout (field order, offsets, the entry encoding,
//! signature verification over the vote preimage) is not frozen: this works
//! on already-decoded signer indices. How a commitment is computed and how a
//! set is resolved from it are injected through [`ValidatorSetResolver`].

use thiserror::Error;

use crate::Digest;

/// Resolves a validator-set commitment to the size `n` of the set it names.
pub trait ValidatorSetResolver {
    /// `None` when the commitment names no known set.
    fn validator_count(&self, commitment: &Digest) -> Option<u16>;
}

/// Signatures needed from a set of `n`: `⌊2n/3⌋ + 1`.
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
    if n == 0 {
        return Err(SignerSetError::EmptyValidatorSet);
    }
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

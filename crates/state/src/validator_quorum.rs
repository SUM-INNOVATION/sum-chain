//! Validator-quorum authorization for governance + inference settlement.
//!
//! Privileged actions (governance `RegisterAsset` / validator-cancel, settlement
//! `ResolveDispute`) are authorized by a quorum of the **active PoA validator
//! set for the block being executed** — the pubkeys are threaded in from the
//! consensus layer (see `BlockExecutor::execute_block`), never read from
//! `StakingStore`/`ValidatorSetStore`. This keeps authorization on exactly the
//! same set that produces/validates the block.
//!
//! Fail-closed by construction: an empty validator set or an out-of-range
//! threshold is an error (never "quorum satisfied").

use std::collections::HashSet;

use sumchain_primitives::validator_authority::{required_approvals, ValidatorApproval};

/// Why a validator-quorum check failed. Executors map this to their own numeric
/// receipt codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumError {
    /// `threshold_bps` not in `1..=10000`.
    InvalidThreshold,
    /// No active validators supplied — cannot authorize anything (fail closed).
    EmptyValidatorSet,
    /// An approval's pubkey is not in the active validator set.
    NonValidatorApproval,
    /// The same validator pubkey approved more than once.
    DuplicateApproval,
    /// An approval signature did not verify over the action's signing bytes.
    InvalidSignature,
    /// Fewer distinct valid validator approvals than the quorum requires.
    ThresholdNotMet { required: u32, got: u32 },
}

/// Verify that `approvals` form a valid validator quorum over `signing_bytes`,
/// evaluated against the supplied active PoA validator set.
///
/// Rules (all fail-closed):
/// - `threshold_bps` must be `1..=10000`.
/// - the active set must be non-empty.
/// - every approval pubkey must be in the active set (else reject).
/// - duplicate approver pubkeys reject.
/// - every signature must verify (Ed25519) over `signing_bytes` (else reject).
/// - distinct valid approvals must be `>= ceil(active_count * threshold_bps / 10000)`.
///
/// `tx.from` is irrelevant here — authority comes solely from the approvals.
pub fn verify_validator_quorum(
    approvals: &[ValidatorApproval],
    signing_bytes: &[u8],
    active_validator_pubkeys: &[[u8; 32]],
    threshold_bps: u16,
) -> Result<(), QuorumError> {
    if !(1..=10000).contains(&threshold_bps) {
        return Err(QuorumError::InvalidThreshold);
    }
    let active_count = active_validator_pubkeys.len() as u32;
    if active_count == 0 {
        return Err(QuorumError::EmptyValidatorSet);
    }
    let required = required_approvals(active_count, threshold_bps);

    let active: HashSet<[u8; 32]> = active_validator_pubkeys.iter().copied().collect();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut valid: u32 = 0;
    for ap in approvals {
        if !active.contains(&ap.pubkey) {
            return Err(QuorumError::NonValidatorApproval);
        }
        if !seen.insert(ap.pubkey) {
            return Err(QuorumError::DuplicateApproval);
        }
        sumchain_crypto::verify_bytes(signing_bytes, &ap.signature, &ap.pubkey)
            .map_err(|_| QuorumError::InvalidSignature)?;
        valid += 1;
    }
    if valid < required {
        return Err(QuorumError::ThresholdNotMet { required, got: valid });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::{sign, KeyPair};

    fn approve(kp: &KeyPair, msg: &[u8]) -> ValidatorApproval {
        ValidatorApproval {
            pubkey: *kp.public_key().as_bytes(),
            signature: sign(msg, kp.private_key()).to_bytes(),
        }
    }

    #[test]
    fn empty_set_fails_closed() {
        let msg = b"action";
        assert_eq!(
            verify_validator_quorum(&[], msg, &[], 5000),
            Err(QuorumError::EmptyValidatorSet)
        );
    }

    #[test]
    fn invalid_threshold_rejected() {
        let v = [[1u8; 32]];
        assert_eq!(
            verify_validator_quorum(&[], b"m", &v, 0),
            Err(QuorumError::InvalidThreshold)
        );
        assert_eq!(
            verify_validator_quorum(&[], b"m", &v, 10001),
            Err(QuorumError::InvalidThreshold)
        );
    }

    #[test]
    fn two_validator_thresholds() {
        let msg = b"the-action-bytes";
        let v1 = KeyPair::generate();
        let v2 = KeyPair::generate();
        let set = [*v1.public_key().as_bytes(), *v2.public_key().as_bytes()];

        // 5000 → requires 1: one approval passes.
        assert!(verify_validator_quorum(&[approve(&v1, msg)], msg, &set, 5000).is_ok());
        // 6667 → requires 2: one approval fails, two pass.
        assert_eq!(
            verify_validator_quorum(&[approve(&v1, msg)], msg, &set, 6667),
            Err(QuorumError::ThresholdNotMet { required: 2, got: 1 })
        );
        assert!(
            verify_validator_quorum(&[approve(&v1, msg), approve(&v2, msg)], msg, &set, 6667).is_ok()
        );
        // 10000 → all validators.
        assert!(
            verify_validator_quorum(&[approve(&v1, msg), approve(&v2, msg)], msg, &set, 10000)
                .is_ok()
        );
    }

    #[test]
    fn non_validator_and_duplicate_and_bad_sig_rejected() {
        let msg = b"m";
        let v1 = KeyPair::generate();
        let outsider = KeyPair::generate();
        let set = [*v1.public_key().as_bytes()];

        // non-validator pubkey
        assert_eq!(
            verify_validator_quorum(&[approve(&outsider, msg)], msg, &set, 5000),
            Err(QuorumError::NonValidatorApproval)
        );
        // duplicate approver
        assert_eq!(
            verify_validator_quorum(&[approve(&v1, msg), approve(&v1, msg)], msg, &set, 5000),
            Err(QuorumError::DuplicateApproval)
        );
        // malformed / wrong-message signature
        let mut bad = approve(&v1, b"different-message");
        assert_eq!(
            verify_validator_quorum(std::slice::from_ref(&bad), msg, &set, 5000),
            Err(QuorumError::InvalidSignature)
        );
        bad.signature = [0u8; 64];
        assert_eq!(
            verify_validator_quorum(&[bad], msg, &set, 5000),
            Err(QuorumError::InvalidSignature)
        );
    }
}

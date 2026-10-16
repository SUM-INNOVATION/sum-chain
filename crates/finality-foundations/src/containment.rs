//! G2-d (ratified 2026-10-16): no dynamic membership before certified
//! finality.
//!
//! Protocol v1 keeps the static genesis membership. This guard refuses any
//! membership transition while certified finality is not active. It does not
//! authorize dynamic membership once certified finality is active: lifting
//! the protocol-v1 containment still needs its own reviewed change, and
//! nothing in this crate implements a membership transition.

use thiserror::Error;

use crate::Digest;

/// A membership change was attempted while certified finality is inactive.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("membership change refused: dynamic membership needs certified finality (G2-d)")]
pub struct DynamicMembershipBeforeCertifiedFinality {
    pub current: Digest,
    pub proposed: Digest,
}

/// Refuse a change from `current` to `proposed` (membership commitments)
/// unless certified finality is active. An unchanged set is always allowed.
pub fn check_membership_transition(
    current: &Digest,
    proposed: &Digest,
    certified_finality_active: bool,
) -> Result<(), DynamicMembershipBeforeCertifiedFinality> {
    if current == proposed || certified_finality_active {
        Ok(())
    } else {
        Err(DynamicMembershipBeforeCertifiedFinality {
            current: *current,
            proposed: *proposed,
        })
    }
}

//! DORMANT (#270): fork choice and rollback never cross certified finality.
//!
//! #270 requires that "fork choice and the rollback command cannot cross
//! finality". Under G2-a (ratified 2026-10-16) a block is final once its
//! certificate is committed, in the same durable batch as the block, through
//! the certified-commit seam; [`crate::certified_meta`] stores the resulting
//! finalized pointer under `finality/finalized/v1`. This module is the pure
//! check a reorg or a rollback must pass against that pointer:
//!
//! * a reorg whose fork point is below the certified height, or at it on a
//!   different block, is refused;
//! * a reorg that would unwind the certified block or anything below it is
//!   refused;
//! * a rollback whose target is below the certified height, or at it on a
//!   different block, is refused;
//! * a stored pointer that cannot be read or decoded is refused (fail-closed),
//!   never treated as "no finality".
//!
//! The check relies on one invariant the seam already guarantees and
//! [`crate::certified_meta::recover_v1`] re-verifies at start-up: the certified
//! block is on the canonical chain. So a branch forking at or above the
//! certified height, on the certified block itself when at it, contains the
//! certified block.
//!
//! It is DORMANT: nothing calls it. The reorg planner and the operator
//! rollback command still use the legacy local-depth `finalized_height`
//! (`crates/consensus/src/reorg.rs`), and certified finality is inactive.
//! Wiring this check into them is a separate, authorized change, which must
//! also decide how the legacy rollback pull-back of `finalized_height` is
//! retired. It defines no key, family, encoding or value: the pointer key and
//! its encoding are [`crate::certified_meta`]'s.

use std::fmt;

use sumchain_primitives::{BlockHeight, Hash};

use crate::certified_meta::{decode_pointer, FINALIZED_POINTER_KEY};
use crate::db::{cf, Database};

/// The certified finalized block a reorg or rollback must not cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertifiedBlock {
    pub height: BlockHeight,
    pub hash: Hash,
}

/// Why a reorg or rollback was refused against certified finality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossingRefusal {
    /// The stored pointer could not be read or decoded. Fail-closed.
    UnreadablePointer(String),
    /// The reorg forks below the certified height.
    ForkBelowCertified {
        fork_height: BlockHeight,
        certified: CertifiedBlock,
    },
    /// The reorg forks at the certified height on a different block.
    ForkReplacesCertified {
        fork_hash: Hash,
        certified: CertifiedBlock,
    },
    /// The reorg would unwind the certified block or a block below it.
    UnwindsCertified {
        height: BlockHeight,
        certified: CertifiedBlock,
    },
    /// The rollback target is below the certified height.
    RollbackBelowCertified {
        target_height: BlockHeight,
        certified: CertifiedBlock,
    },
    /// The rollback target is at the certified height on a different block.
    RollbackReplacesCertified {
        target_hash: Hash,
        certified: CertifiedBlock,
    },
}

impl fmt::Display for CrossingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreadablePointer(e) => write!(
                f,
                "the certified finalized pointer cannot be read ({e}); refusing rather than \
                 treating finality as absent"
            ),
            Self::ForkBelowCertified {
                fork_height,
                certified,
            } => write!(
                f,
                "the branch forks at block {fork_height}, below the certified block {}; \
                 certified history cannot be abandoned",
                certified.height
            ),
            Self::ForkReplacesCertified { certified, .. } => write!(
                f,
                "the branch forks at height {} on a block other than the certified one; \
                 certified history cannot be replaced",
                certified.height
            ),
            Self::UnwindsCertified { height, certified } => write!(
                f,
                "the switch would unwind block {height}, at or below the certified block {}",
                certified.height
            ),
            Self::RollbackBelowCertified {
                target_height,
                certified,
            } => write!(
                f,
                "rollback target {target_height} is below the certified block {}; certified \
                 finality cannot be rolled back",
                certified.height
            ),
            Self::RollbackReplacesCertified { certified, .. } => write!(
                f,
                "rollback target at height {} is not the certified block",
                certified.height
            ),
        }
    }
}

impl std::error::Error for CrossingRefusal {}

/// The certified finalized block recorded under `finality/finalized/v1`, if
/// any. `Ok(None)` only when the key is absent. Any read or decode failure is
/// an error, never "no finality".
pub fn certified_block(db: &Database) -> Result<Option<CertifiedBlock>, CrossingRefusal> {
    let bytes = db
        .get(cf::META, FINALIZED_POINTER_KEY)
        .map_err(|e| CrossingRefusal::UnreadablePointer(e.to_string()))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let pointer = decode_pointer(&bytes).map_err(CrossingRefusal::UnreadablePointer)?;
    Ok(Some(CertifiedBlock {
        height: pointer.height,
        hash: pointer.hash,
    }))
}

/// Refuse a reorg that crosses certified finality.
///
/// `fork_height` / `fork_hash` name the common ancestor the switch keeps, and
/// `unwound` every block the switch abandons, as (height, hash), in any order.
/// With no certified block nothing is refused here.
pub fn refuse_reorg_crossing(
    certified: Option<&CertifiedBlock>,
    fork_height: BlockHeight,
    fork_hash: &Hash,
    unwound: impl IntoIterator<Item = (BlockHeight, Hash)>,
) -> Result<(), CrossingRefusal> {
    let Some(c) = certified else {
        return Ok(());
    };
    if fork_height < c.height {
        return Err(CrossingRefusal::ForkBelowCertified {
            fork_height,
            certified: *c,
        });
    }
    if fork_height == c.height && *fork_hash != c.hash {
        return Err(CrossingRefusal::ForkReplacesCertified {
            fork_hash: *fork_hash,
            certified: *c,
        });
    }
    for (height, _) in unwound {
        if height <= c.height {
            return Err(CrossingRefusal::UnwindsCertified {
                height,
                certified: *c,
            });
        }
    }
    Ok(())
}

/// Refuse an operator rollback that crosses certified finality: the target
/// must be the certified block or a block above it.
pub fn refuse_rollback_crossing(
    certified: Option<&CertifiedBlock>,
    target_height: BlockHeight,
    target_hash: &Hash,
) -> Result<(), CrossingRefusal> {
    let Some(c) = certified else {
        return Ok(());
    };
    if target_height < c.height {
        return Err(CrossingRefusal::RollbackBelowCertified {
            target_height,
            certified: *c,
        });
    }
    if target_height == c.height && *target_hash != c.hash {
        return Err(CrossingRefusal::RollbackReplacesCertified {
            target_hash: *target_hash,
            certified: *c,
        });
    }
    Ok(())
}

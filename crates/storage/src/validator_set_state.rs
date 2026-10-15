//! Validator-set state rows: a DORMANT seam for #266 that keeps membership as
//! ordinary application state, over [`crate::validator_set_record`].
//!
//! Nothing reads or writes membership through this module. No crate outside
//! storage and no other module of this crate names it, and
//! `tests/validator_set_record_dormant.rs` fails if that changes. Membership is
//! still the static genesis list (protocol v1, #272); the legacy
//! `ValidatorSetStore`, its epoch-keyed rows and the startup refusal of any
//! stored legacy row are unchanged.
//!
//! # What it provides
//!
//! Membership written the way every other piece of application state is: by
//! block execution, through the [`ExecutionView`] it is handed, into the
//! candidate's overlay. Publication, rollback and reorg are then the chain's
//! ordinary machinery, not code of this module's:
//!
//! | id | obligation | how it holds | tests in `tests/validator_set_state.rs` |
//! |----|------------|--------------|-----------------------------------------|
//! | S1 | A row lands only when its block is published, in the same batch as the block, and never otherwise. | The only write path takes an [`ExecutionView`]; there is no impl that makes one from a [`Database`]. `AcceptedCandidate::publish` commits the overlay in one batch; a dropped or refused candidate commits nothing. | `s1_*` |
//! | S2 | Undoing a block restores the rows it wrote exactly: a new row is removed, a replaced row gets its prior bytes back. | The generic application journal captures every overlay pre-image, for every family, with no list to fall behind (`crate::journal`). Nothing here unwinds anything. | `s2_*` |
//! | S3 | Competing blocks never share a row: each executes on its own overlay and, on a replacement branch, over the reconstructed fork parent; adopting the branch makes its rows canonical in the one adoption batch. | `crate::branch` and `crate::candidate::build_adoption_batch`, from the same journals. | `s3_*` |
//! | S4 | Every read fails closed: a row that is missing when required, present when absent, corrupt, of another version or for another key is an error, never "no set". | [`read`]. | `s4_*` |
//! | S5 | A write states what it replaces: [`stage_insert`] refuses an occupied key, [`stage_replace`] a missing one, and both refuse an undecodable row instead of overwriting it. A refused write stages nothing. | Every check runs before the one staged write. | `s5_*` |
//! | S6 | Rows stay in their own namespace. A row outside another subsystem's key range is invisible to that subsystem's reads and scans, and a layout that lands on another subsystem's row fails closed instead of overwriting it. | Disjointness is the layout's obligation (see [`ValidatorSetLayout`]); a collision is caught by S5's decode-before-write. | `s6_*` |
//!
//! # What is deliberately NOT decided here
//!
//! * **What a key means, and which blocks write one.** The caller passes the
//!   key with every row. No epoch length, boundary rule or transition rule is
//!   read, and nothing relates a key to a height.
//! * **Effective height.** Nothing maps a height to the set that validates it.
//!   There is no "current set", no ancestry walk and no resolution function.
//! * **Authenticated history.** Rows are uncommitted application state, like
//!   the staking rows: nothing folds them into a state root or a header, so a
//!   node holding a different set is detected only when it disagrees about a
//!   proposer. Folding them is a separate, gated change.
//! * **Finality.** Nothing here checks any block against a finalized height.
//! * **Where rows live.** The column family and key come from an injected
//!   [`ValidatorSetLayout`], which has no production implementation. No
//!   family is added and no key is reserved. Every family the database opens
//!   is journalled, so any existing family gives S2 and S3.
//! * **Write-set accounting.** A staged row charges the block's write-set
//!   ceiling like any other execution write.
//! * **The transition function.** Whoever builds the row chose its members.

use crate::db::Database;
use crate::exec_view::ExecutionView;
use crate::validator_set_record::{ValidatorSetRecord, ValidatorSetRecordError};
use crate::StorageError;

/// Where the row for `key` is stored.
///
/// Injected so that this seam freezes no column family or key. The family
/// must already exist (this seam adds none), and two different keys must map
/// to two different locations.
///
/// A production layout must also keep rows out of every other subsystem's
/// namespace:
///
/// * its keys must be disjoint from every key another subsystem writes in the
///   family, and from every range another subsystem scans. In `STATE` that is
///   the `acct` prefix, which the account readers and the account-root digest
///   scan with RocksDB's prefix overrun and bound by the prefix;
/// * it must not use a family that a committed digest scans in full (today
///   `COMPUTE_POOL_STATE` and `BEACON_STATE`), or its rows would change the
///   state root.
///
/// A layout that lands on another subsystem's row fails closed at write time
/// (the row does not decode, so nothing is overwritten), but disjointness
/// itself is the layout's obligation, checked where a production layout is
/// chosen.
pub trait ValidatorSetLayout {
    fn row_location(&self, key: u64) -> (&'static str, Vec<u8>);
}

/// Whether a row must exist under a key.
///
/// Decided by the caller's transition rule, which is not decided yet. The seam
/// only enforces it: without it, "no set was written here" and "the set written
/// here is lost" are the same absent row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// A row must exist.
    Required,
    /// A row must not exist.
    Absent,
}

/// State rows can be read from.
///
/// [`ExecutionView`] reads see the block's own earlier writes, then the branch
/// layer or committed state beneath it. [`Database`] reads see committed state
/// only: the canonical head's post-state.
pub trait RowSource {
    fn get_row(&self, cf: &str, key: &[u8]) -> crate::Result<Option<Vec<u8>>>;
}

impl RowSource for ExecutionView<'_, '_> {
    fn get_row(&self, cf: &str, key: &[u8]) -> crate::Result<Option<Vec<u8>>> {
        self.get(cf, key)
    }
}

impl RowSource for Database {
    fn get_row(&self, cf: &str, key: &[u8]) -> crate::Result<Option<Vec<u8>>> {
        self.get(cf, key)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("validator-set state: {0}")]
    Storage(#[from] StorageError),
    #[error("a validator-set row is required under key {key} and none is stored")]
    Missing { key: u64 },
    #[error("no validator-set row is expected under key {key}, but one is stored")]
    Unexpected { key: u64 },
    #[error("the validator-set row stored under key {key} is refused: {source}")]
    Record {
        key: u64,
        source: ValidatorSetRecordError,
    },
    #[error("a validator-set row is already stored under key {key}; refusing to replace it")]
    Occupied { key: u64 },
}

/// Read the row under `key`, refusing anything [`Presence`] does not allow.
///
/// `Ok(None)` only for [`Presence::Absent`] with nothing stored. A row that does
/// not decode, or decodes as another key's, is an error under either presence.
pub fn read<S>(
    rows: &S,
    layout: &(impl ValidatorSetLayout + ?Sized),
    key: u64,
    presence: Presence,
) -> Result<Option<ValidatorSetRecord>, StateError>
where
    S: RowSource + ?Sized,
{
    let (cf, row_key) = layout.row_location(key);
    match (presence, rows.get_row(cf, &row_key)?) {
        (Presence::Absent, None) => Ok(None),
        (Presence::Absent, Some(_)) => Err(StateError::Unexpected { key }),
        (Presence::Required, None) => Err(StateError::Missing { key }),
        (Presence::Required, Some(bytes)) => decode(&bytes, key).map(Some),
    }
}

/// Stage `record` under its key, where no row is stored yet.
///
/// Refuses an occupied key, including one holding the identical row: a block
/// writes a key once, and a second write of it is a transition-rule error,
/// not a no-op. An undecodable row under the key is reported as such rather
/// than overwritten.
pub fn stage_insert(
    view: &mut ExecutionView<'_, '_>,
    layout: &(impl ValidatorSetLayout + ?Sized),
    record: &ValidatorSetRecord,
) -> Result<(), StateError> {
    let key = record.key();
    let (cf, row_key) = layout.row_location(key);
    if let Some(bytes) = view.get(cf, &row_key)? {
        decode(&bytes, key)?;
        return Err(StateError::Occupied { key });
    }
    view.put(cf, &row_key, &record.encode())?;
    Ok(())
}

/// Stage `record` over the row already stored under its key, and return the
/// row it replaces.
///
/// Refuses a missing key and an undecodable stored row: what is replaced must
/// be a row this binary can read, so the journal's pre-image is one too.
pub fn stage_replace(
    view: &mut ExecutionView<'_, '_>,
    layout: &(impl ValidatorSetLayout + ?Sized),
    record: &ValidatorSetRecord,
) -> Result<ValidatorSetRecord, StateError> {
    let key = record.key();
    let replaced = read(&*view, layout, key, Presence::Required)?
        .expect("a required read returns a row or an error");
    let (cf, row_key) = layout.row_location(key);
    view.put(cf, &row_key, &record.encode())?;
    Ok(replaced)
}

fn decode(bytes: &[u8], key: u64) -> Result<ValidatorSetRecord, StateError> {
    ValidatorSetRecord::decode_for(bytes, key).map_err(|source| StateError::Record { key, source })
}

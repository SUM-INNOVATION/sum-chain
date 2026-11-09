//! Evidence records (G2 A3) in versioned keys of the EXISTING `meta` column
//! family, keeping the first valid record per slot (D5). DORMANT.
//!
//! Adopted by the owner on 2026-11-09 (decision ledger, "2026-11-09 owner
//! ADOPTION addendum", B3): "adopt the evidence records and
//! first-valid-record rule, using versioned META keys rather than a new
//! column family. No penalties are introduced."
//!
//! # Keys and values (all in `cf::META`; no new column family)
//!
//! | Record | Key | Value |
//! |---|---|---|
//! | vote equivocation | [`EQUIVOCATION_KEY_PREFIX`] `finality/evidence/v1/` ‖ height u64 **BE** ‖ round u32 **BE** ‖ vote type u8 ‖ validator index u16 **BE**, 36 bytes | the 363-byte `EquivocationEvidenceV1`, opaque here |
//! | upgrade conflict | [`UPGRADE_CONFLICT_KEY_PREFIX`] `upgrade/conflict/v1/` ‖ sequence u64 **BE**, 28 bytes | the `UpgradeConflictEvidenceV1` bytes, opaque here |
//!
//! * The 15 bytes after the equivocation prefix are the adopted slot key
//!   ([`EquivocationSlot::slot_bytes`]), unchanged. The draft made them the
//!   whole key of a new `finality_evidence` column family. The prefix is
//!   named after that family, as the certificate prefix `finality/cert/v1/`
//!   was after `finality_certificates` ([`crate::certified_meta`]); the name
//!   is this layout's proposal.
//! * The upgrade-conflict key is the adopted 28-byte META key as drafted.
//!
//! Integers are big-endian only in keys, so rows sort by height, round, type
//! and index, or by sequence (A1, D0). The two prefixes are prefix-free with
//! each other and with every other META key, including the certified layout's
//! `finality/cert/v1/` and `finality/finalized/v1`: the certified-crossing
//! guard and its start-up audit never read these rows.
//!
//! # Why `meta` and not a new column family
//!
//! As for the certificate rows: a binary that does not name a column family
//! cannot open a volume on which a newer binary created that family, and the
//! deployed 0.2.0-era binary treats the resulting open error as corruption and
//! auto-repairs the volume to empty (see `Database::repair`). Keys in an
//! existing family carry no such hazard: an older binary opens the volume and
//! never reads them.
//!
//! # D5: the first valid record per slot is kept
//!
//! [`record_equivocation`] and [`record_upgrade_conflict`]:
//! 1. verify the record with the injected verifier, which also names its
//!    slot, so an invalid record is refused and never takes a slot;
//! 2. write it only if its slot is empty ([`Insert::Stored`]). Otherwise the
//!    stored record is kept unchanged, whatever the new one is
//!    ([`Insert::SlotHeld`]).
//!
//! Repeated or spammed records therefore cost at most one row per slot, and
//! a stored record is never overwritten. The slot read and the write run
//! under one process-wide lock, so two writers cannot both find a slot empty.
//!
//! # Writes, reorgs and rollback
//!
//! Each record is committed alone, in one synced batch (`commit_durable`),
//! never through a block's execution view, so no application journal records
//! it. A reorg, a block revert and the `rollback` command restore state from
//! each unwound block's journal and otherwise touch only block, index, head
//! and legacy finality records, so they leave these rows as they were:
//! evidence is a fact about signed messages, not chain state, and no unwind
//! removes or resurrects it. Nothing here deletes or rewrites a row.
//!
//! # No penalty; dormant
//!
//! Nothing reads these rows to slash, jail, tombstone or change stake. They
//! are unrelated to the staking `SubmitEvidence` transaction, which is
//! unchanged. Nothing outside this module and its tests names these keys or
//! calls this module, and `tests/evidence_meta_v1.rs` fails if a production
//! source does. Nothing consumes the records until certified finality runs
//! (the upgrade-conflict record's consumer lands with the authorization
//! manifest). There is no production verifier: the codecs are
//! `sumchain-finality-foundations`' `evidence`, on which no workspace crate
//! may depend yet, so the verifiers are injected, as the certificate verifier
//! is ([`crate::certified::CertificateVerifier`]).

use std::fmt;
use std::sync::{Mutex, PoisonError};

use crate::db::{cf, Database};
use crate::StorageError;

/// Prefix of every vote-equivocation key in `cf::META`.
pub const EQUIVOCATION_KEY_PREFIX: &[u8] = b"finality/evidence/v1/";
/// Length of the adopted slot key: height u64 ‖ round u32 ‖ type u8 ‖ index
/// u16.
pub const EQUIVOCATION_SLOT_LEN: usize = 8 + 4 + 1 + 2;
/// Length of a vote-equivocation key: prefix ‖ slot key.
pub const EQUIVOCATION_KEY_LEN: usize = EQUIVOCATION_KEY_PREFIX.len() + EQUIVOCATION_SLOT_LEN;
/// Prefix of every upgrade-conflict key in `cf::META`.
pub const UPGRADE_CONFLICT_KEY_PREFIX: &[u8] = b"upgrade/conflict/v1/";
/// Length of an upgrade-conflict key: prefix ‖ sequence u64.
pub const UPGRADE_CONFLICT_KEY_LEN: usize = UPGRADE_CONFLICT_KEY_PREFIX.len() + 8;

const _: () = assert!(EQUIVOCATION_SLOT_LEN == 15);
const _: () = assert!(EQUIVOCATION_KEY_LEN == 36 && UPGRADE_CONFLICT_KEY_LEN == 28);

/// The slot of a vote equivocation (D5): at most one record per (height,
/// round, vote type, validator index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EquivocationSlot {
    pub height: u64,
    pub round: u32,
    pub vote_type: u8,
    pub validator_index: u16,
}

impl EquivocationSlot {
    /// The adopted 15-byte slot key: height u64 BE ‖ round u32 BE ‖ type u8 ‖
    /// index u16 BE.
    pub fn slot_bytes(&self) -> [u8; EQUIVOCATION_SLOT_LEN] {
        let mut out = [0u8; EQUIVOCATION_SLOT_LEN];
        out[..8].copy_from_slice(&self.height.to_be_bytes());
        out[8..12].copy_from_slice(&self.round.to_be_bytes());
        out[12] = self.vote_type;
        out[13..].copy_from_slice(&self.validator_index.to_be_bytes());
        out
    }

    /// The slot's `cf::META` key: prefix ‖ slot key.
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(EQUIVOCATION_KEY_LEN);
        key.extend_from_slice(EQUIVOCATION_KEY_PREFIX);
        key.extend_from_slice(&self.slot_bytes());
        key
    }
}

/// Strict parse of a vote-equivocation key: the exact prefix and exactly 15
/// more bytes. Anything else is `None`.
pub fn parse_equivocation_key(key: &[u8]) -> Option<EquivocationSlot> {
    if key.len() != EQUIVOCATION_KEY_LEN || !key.starts_with(EQUIVOCATION_KEY_PREFIX) {
        return None;
    }
    let slot = &key[EQUIVOCATION_KEY_PREFIX.len()..];
    Some(EquivocationSlot {
        height: u64::from_be_bytes(slot[..8].try_into().expect("8 bytes")),
        round: u32::from_be_bytes(slot[8..12].try_into().expect("4 bytes")),
        vote_type: slot[12],
        validator_index: u16::from_be_bytes(slot[13..].try_into().expect("2 bytes")),
    })
}

/// The upgrade-conflict key for `sequence`.
pub fn upgrade_conflict_key(sequence: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(UPGRADE_CONFLICT_KEY_LEN);
    key.extend_from_slice(UPGRADE_CONFLICT_KEY_PREFIX);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

/// Strict parse of an upgrade-conflict key: the exact prefix and exactly 8
/// more bytes. Anything else is `None`.
pub fn parse_upgrade_conflict_key(key: &[u8]) -> Option<u64> {
    if key.len() != UPGRADE_CONFLICT_KEY_LEN || !key.starts_with(UPGRADE_CONFLICT_KEY_PREFIX) {
        return None;
    }
    let sequence = &key[UPGRADE_CONFLICT_KEY_PREFIX.len()..];
    Some(u64::from_be_bytes(sequence.try_into().expect("8 bytes")))
}

/// Why a verifier refused a record. Free text: the verifier owns the
/// encoding, so this module cannot classify its reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRefusal(pub String);

impl fmt::Display for EvidenceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Checks that opaque bytes are a valid vote-equivocation record and names
/// the slot it occupies.
///
/// Must refuse anything that is not a complete, valid `EquivocationEvidenceV1`
/// for this node (strict decoding, one slot, canonical order, both votes
/// verified). The store does not parse the bytes.
pub trait EquivocationVerifier {
    fn verify(&self, record: &[u8]) -> Result<EquivocationSlot, EvidenceRefusal>;
}

/// Checks that opaque bytes are a valid upgrade-conflict record and names the
/// sequence it occupies.
///
/// Must refuse anything that is not a complete, valid
/// `UpgradeConflictEvidenceV1` for this node (strict framing, both manifests
/// fully verified, one sequence, ascending digests). The store does not parse
/// the bytes.
pub trait UpgradeConflictVerifier {
    fn verify(&self, record: &[u8]) -> Result<u64, EvidenceRefusal>;
}

/// What happened to a valid record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    /// The slot was empty: this is now its record.
    Stored,
    /// The slot already holds a record, which is kept unchanged; nothing was
    /// written. `identical` says whether the presented record is the same
    /// bytes.
    SlotHeld { identical: bool },
}

/// A rule of this layout a stored row breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceViolation {
    /// A key under either prefix does not parse exactly.
    MalformedKey(Vec<u8>),
    /// The verifier refuses the stored record.
    Refused {
        key: Vec<u8>,
        reason: EvidenceRefusal,
    },
    /// The stored record is valid for another slot than its key names.
    WrongSlot { key: Vec<u8> },
}

/// Every way this module refuses. None of them writes anything.
#[derive(Debug)]
pub enum EvidenceError {
    Storage(StorageError),
    /// The verifier refused the presented record.
    Refused(EvidenceRefusal),
    /// A stored row breaks the layout ([`audit_evidence`] only).
    Violation(EvidenceViolation),
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {e}"),
            Self::Refused(r) => write!(f, "evidence refused: {r}"),
            Self::Violation(v) => write!(f, "evidence layout v1: {v:?}"),
        }
    }
}

impl std::error::Error for EvidenceError {}

impl From<StorageError> for EvidenceError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

/// Serializes every slot read and write of this module in the process.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Write `record` under `key` unless the key already holds one (D5).
fn insert_first(db: &Database, key: &[u8], record: &[u8]) -> Result<Insert, StorageError> {
    // The guarded value is `()`, so a panic elsewhere leaves nothing to repair.
    let _guard = WRITE_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(stored) = db.get(cf::META, key)? {
        return Ok(Insert::SlotHeld {
            identical: stored == record,
        });
    }
    let mut batch = db.batch();
    batch.put(cf::META, key, record)?;
    batch.commit_durable()?;
    Ok(Insert::Stored)
}

/// Keep `record` if it is valid and the first for its slot (D5).
///
/// The verifier runs first, so an invalid record is reported as refused and
/// never as a held slot. A valid record is written in its own synced batch
/// when its slot is empty; otherwise nothing is written.
pub fn record_equivocation(
    db: &Database,
    verifier: &dyn EquivocationVerifier,
    record: &[u8],
) -> Result<Insert, EvidenceError> {
    let slot = verifier.verify(record).map_err(EvidenceError::Refused)?;
    Ok(insert_first(db, &slot.key(), record)?)
}

/// Keep `record` if it is valid and the first for its sequence (D5). As
/// [`record_equivocation`].
pub fn record_upgrade_conflict(
    db: &Database,
    verifier: &dyn UpgradeConflictVerifier,
    record: &[u8],
) -> Result<Insert, EvidenceError> {
    let sequence = verifier.verify(record).map_err(EvidenceError::Refused)?;
    Ok(insert_first(db, &upgrade_conflict_key(sequence), record)?)
}

/// The record stored for `slot`, as stored. [`audit_evidence`] re-verifies.
pub fn equivocation_record(
    db: &Database,
    slot: &EquivocationSlot,
) -> Result<Option<Vec<u8>>, StorageError> {
    db.get(cf::META, &slot.key())
}

/// The record stored for `sequence`, as stored. [`audit_evidence`]
/// re-verifies.
pub fn upgrade_conflict_record(
    db: &Database,
    sequence: u64,
) -> Result<Option<Vec<u8>>, StorageError> {
    db.get(cf::META, &upgrade_conflict_key(sequence))
}

/// What an audit found when every rule held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceAudit {
    pub equivocations: u64,
    pub upgrade_conflicts: u64,
}

fn violation<T>(v: EvidenceViolation) -> Result<T, EvidenceError> {
    Err(EvidenceError::Violation(v))
}

/// Check every stored record against this layout. Read-only.
///
/// Every key under either prefix must parse exactly, and its record must
/// verify for exactly the slot (or sequence) the key names. Verifies every
/// record, so its cost is one verification per row: an explicit audit, not a
/// per-open check.
pub fn audit_evidence(
    db: &Database,
    equivocation: &dyn EquivocationVerifier,
    upgrade_conflict: &dyn UpgradeConflictVerifier,
) -> Result<EvidenceAudit, EvidenceError> {
    let mut audit = EvidenceAudit {
        equivocations: 0,
        upgrade_conflicts: 0,
    };
    for entry in db.prefix_iter_checked(cf::META, EQUIVOCATION_KEY_PREFIX)? {
        let (key, value) = entry?;
        if !key.starts_with(EQUIVOCATION_KEY_PREFIX) {
            break;
        }
        let Some(slot) = parse_equivocation_key(&key) else {
            return violation(EvidenceViolation::MalformedKey(key.to_vec()));
        };
        match equivocation.verify(&value) {
            Err(reason) => {
                return violation(EvidenceViolation::Refused {
                    key: key.to_vec(),
                    reason,
                })
            }
            Ok(named) if named != slot => {
                return violation(EvidenceViolation::WrongSlot { key: key.to_vec() })
            }
            Ok(_) => audit.equivocations += 1,
        }
    }
    for entry in db.prefix_iter_checked(cf::META, UPGRADE_CONFLICT_KEY_PREFIX)? {
        let (key, value) = entry?;
        if !key.starts_with(UPGRADE_CONFLICT_KEY_PREFIX) {
            break;
        }
        let Some(sequence) = parse_upgrade_conflict_key(&key) else {
            return violation(EvidenceViolation::MalformedKey(key.to_vec()));
        };
        match upgrade_conflict.verify(&value) {
            Err(reason) => {
                return violation(EvidenceViolation::Refused {
                    key: key.to_vec(),
                    reason,
                })
            }
            Ok(named) if named != sequence => {
                return violation(EvidenceViolation::WrongSlot { key: key.to_vec() })
            }
            Ok(_) => audit.upgrade_conflicts += 1,
        }
    }
    Ok(audit)
}

//! Durable signer safety core (G2-b, ratified 2026-10-16).
//!
//! The ratified rule: signer state is made durable before any signature is
//! released; one owner at a time; state exists only after an explicit
//! initialization; missing or corrupt state means refusing to sign.
//!
//! [`DurableSigner`] enforces that over three injected traits:
//!
//! * [`SignerStore`]: loads and atomically persists one [`SignerRecord`].
//!   `persist` may return `Ok` only once the record is durable (data and
//!   directory entry fsynced). This crate defines no on-disk encoding; the
//!   record's bytes are part of the unratified signer-state layout.
//! * [`ExclusiveOwnership`]: one owner per key. The guard is held for the
//!   signer's whole life.
//! * [`SigningKey`] and [`PolkaVerifier`]: the key, and the check of a
//!   quorum-of-prevotes justification. The justification bytes are unratified;
//!   no production verifier exists.
//!
//! # Signing order
//!
//! For every new signature: check the refusal rules, compute the signature,
//! persist a record that contains it, and return it only if the persist
//! succeeded. If the persist fails, nothing is released and the signer is
//! poisoned until it is reopened from durable state, because the durable
//! record may then be either the old or the new one.
//!
//! # Refusal rules
//!
//! Positions are ordered by (height, round, step) with
//! `Propose < Prevote < Precommit`.
//!
//! * A position at or below the initialization floor, or below the last
//!   signed position, is refused.
//! * At the last signed position, the identical request returns the stored
//!   signature (no new signature is made); any other request is refused as
//!   equivocation.
//! * Lock (Tendermint, per height):
//!   - a non-nil precommit for `v` in round `r` needs a verified polka for `v`
//!     in round `r`, and locks on `(r, v)`;
//!   - while locked on `(r_l, v_l)`, a non-nil prevote for `v != v_l` in round
//!     `r` needs a verified polka for `v` in a round `p` with `r_l <= p < r`;
//!   - nil prevotes and nil precommits are allowed and leave the lock as is;
//!   - the lock applies only to its own height and is dropped at the next.
//!
//! # Limits of what this core can check
//!
//! * The payload bytes are opaque. Until the vote codec is ratified the signer
//!   trusts the caller's declared position and value to match the payload.
//!   With a codec it would decode them instead.
//! * Restoring an old copy of the state is detected only against external
//!   evidence: [`DurableSigner::open`] takes the highest position at which this
//!   key's signature is known to exist (for example in certificates on the
//!   canonical chain), and refuses state whose high-water mark is below it.
//!   Without such evidence a restored copy is indistinguishable from the real
//!   one; the operator rule "never restore signer state from a backup" covers
//!   that case.
//! * Durability across power loss depends on the store honouring the fsync
//!   contract; the tests here exercise process-level faults only.

use thiserror::Error;

use crate::Digest;

/// Step of a signed consensus message, in protocol order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
}

/// What a signature is bound to. Ordered by height, then round, then step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignPosition {
    pub height: u64,
    pub round: u32,
    pub step: Step,
}

/// The value a message signs for: a block (by digest) or nil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteValue {
    Nil,
    Block(Digest),
}

/// A claimed quorum of prevotes for the request's value in `polka_round`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Justification {
    pub polka_round: u32,
    /// Opaque; checked only by the injected [`PolkaVerifier`].
    pub evidence: Vec<u8>,
}

/// One request to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub position: SignPosition,
    pub value: VoteValue,
    /// The exact bytes to sign. Their encoding is unratified; the caller's
    /// codec must make them bind `position` and `value`.
    pub payload: Vec<u8>,
    pub justification: Option<Justification>,
}

/// The last signature this key released (or is about to release).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastSigned {
    pub position: SignPosition,
    pub value: VoteValue,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A Tendermint lock: this key precommitted `value` in `round` at `height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lock {
    pub height: u64,
    pub round: u32,
    pub value: Digest,
}

/// Everything the signer persists. Its byte encoding is NOT defined here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerRecord {
    /// Identifies the key this state belongs to (caller-defined digest).
    pub key_id: Digest,
    /// Incremented by every persist.
    pub sequence: u64,
    /// Set at initialization: positions at or below it are refused.
    pub floor: Option<SignPosition>,
    pub last: Option<LastSigned>,
    pub lock: Option<Lock>,
}

impl SignerRecord {
    /// The highest position this record forbids signing at or below.
    pub fn high_water(&self) -> Option<SignPosition> {
        let last = self.last.as_ref().map(|l| l.position);
        match (self.floor, last) {
            (Some(f), Some(l)) => Some(f.max(l)),
            (f, l) => f.or(l),
        }
    }

    /// Internal consistency of a loaded record. Anything else is corruption.
    fn check_consistent(&self) -> Result<(), &'static str> {
        if let (Some(floor), Some(last)) = (self.floor, self.last.as_ref()) {
            if last.position <= floor {
                return Err("last signed position is at or below the floor");
            }
        }
        if let Some(lock) = self.lock {
            let Some(last) = self.last.as_ref() else {
                return Err("a lock exists without any signed message");
            };
            let lock_pos = SignPosition {
                height: lock.height,
                round: lock.round,
                step: Step::Precommit,
            };
            if lock_pos > last.position {
                return Err("the lock is above the last signed position");
            }
            if last.position.height != lock.height {
                return Err("the lock belongs to an earlier height");
            }
        }
        if let Some(last) = self.last.as_ref() {
            if last.position.step == Step::Propose && last.value == VoteValue::Nil {
                return Err("a nil proposal was recorded");
            }
        }
        Ok(())
    }
}

/// A store failure, as reported by the store.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct StoreError(pub String);

/// Durable storage for one [`SignerRecord`].
pub trait SignerStore {
    /// `Ok(None)` if no record exists; `Err` if one exists but cannot be read.
    fn load(&mut self) -> Result<Option<SignerRecord>, StoreError>;

    /// Atomically replace the record. Must return `Ok` only once the new record
    /// is durable. On `Err` the durable record may be the old or the new one.
    fn persist(&mut self, record: &SignerRecord) -> Result<(), StoreError>;
}

/// Another owner holds the key, or ownership could not be established.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct OwnershipError(pub String);

/// Exclusive ownership of a signing key (for example an exclusive file lock).
pub trait ExclusiveOwnership {
    /// Released when dropped.
    type Guard;
    /// Must fail while any other guard for the same key is alive.
    fn try_acquire(&self) -> Result<Self::Guard, OwnershipError>;
}

/// The private key.
pub trait SigningKey {
    /// The digest that ties a [`SignerRecord`] to this key.
    fn key_id(&self) -> Digest;
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
}

/// Checks a quorum-of-prevotes justification. No production implementation
/// exists: the evidence encoding is unratified.
pub trait PolkaVerifier {
    fn verify_polka(
        &self,
        height: u64,
        round: u32,
        value: &Digest,
        evidence: &[u8],
    ) -> Result<(), String>;
}

/// Why the signer refused to open, initialize or sign.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignerError {
    #[error("signer state already exists; initialization refused")]
    AlreadyInitialized,
    #[error("no signer state: refusing to sign until explicitly initialized")]
    NotInitialized,
    #[error("signer state is unreadable or inconsistent: {0}")]
    Corrupt(String),
    #[error("signer state belongs to a different key")]
    KeyMismatch,
    #[error(
        "signer state is stale: high-water {recorded:?} is below known signature at {evidence:?}"
    )]
    StaleState {
        recorded: Option<SignPosition>,
        evidence: SignPosition,
    },
    #[error("signing key is owned elsewhere: {0}")]
    OwnershipHeld(String),
    #[error("a previous persist failed; reopen from durable state")]
    Poisoned,
    #[error("persist failed; no signature released: {0}")]
    PersistFailed(String),
    #[error("position {requested:?} is not above {high_water:?}")]
    Regression {
        requested: SignPosition,
        high_water: SignPosition,
    },
    #[error("a different message was already signed at {0:?}")]
    Equivocation(SignPosition),
    #[error("locked on {0:?}; no valid justification to vote otherwise")]
    LockedOnOtherValue(Lock),
    #[error("a non-nil precommit needs a polka justification in its own round")]
    MissingJustification,
    #[error("justification refused: {0}")]
    InvalidJustification(String),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
}

/// The signer. Holds the ownership guard for its whole life.
pub struct DurableSigner<S, K, P, G> {
    store: S,
    key: K,
    polka: P,
    _ownership: G,
    record: SignerRecord,
    poisoned: bool,
}

/// Explicit initialization: creates the first record, and refuses if any
/// record exists or the store cannot be read. `floor` must be at or above any
/// position this key may already have signed.
pub fn initialize<S: SignerStore>(
    store: &mut S,
    key_id: Digest,
    floor: Option<SignPosition>,
) -> Result<(), SignerError> {
    match store.load() {
        Ok(None) => {}
        Ok(Some(_)) => return Err(SignerError::AlreadyInitialized),
        Err(e) => return Err(SignerError::Corrupt(e.0)),
    }
    let record = SignerRecord {
        key_id,
        sequence: 0,
        floor,
        last: None,
        lock: None,
    };
    store
        .persist(&record)
        .map_err(|e| SignerError::PersistFailed(e.0))
}

impl<S, K, P, G> DurableSigner<S, K, P, G>
where
    S: SignerStore,
    K: SigningKey,
    P: PolkaVerifier,
{
    /// Acquire ownership, then load existing state. Never creates state.
    ///
    /// `evidence_floor` is the highest position at which a signature by this
    /// key is known to exist outside the signer; state whose high-water mark
    /// is below it is refused as stale.
    pub fn open<L>(
        ownership: &L,
        mut store: S,
        key: K,
        polka: P,
        evidence_floor: Option<SignPosition>,
    ) -> Result<Self, SignerError>
    where
        L: ExclusiveOwnership<Guard = G>,
    {
        let guard = ownership
            .try_acquire()
            .map_err(|e| SignerError::OwnershipHeld(e.0))?;
        let record = match store.load() {
            Ok(Some(r)) => r,
            Ok(None) => return Err(SignerError::NotInitialized),
            Err(e) => return Err(SignerError::Corrupt(e.0)),
        };
        record
            .check_consistent()
            .map_err(|m| SignerError::Corrupt(m.to_string()))?;
        if record.key_id != key.key_id() {
            return Err(SignerError::KeyMismatch);
        }
        if let Some(evidence) = evidence_floor {
            let recorded = record.high_water();
            if recorded.is_none_or(|hw| hw < evidence) {
                return Err(SignerError::StaleState { recorded, evidence });
            }
        }
        Ok(Self {
            store,
            key,
            polka,
            _ownership: guard,
            record,
            poisoned: false,
        })
    }

    /// The state as last made durable by this signer.
    pub fn record(&self) -> &SignerRecord {
        &self.record
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Sign `req`, or refuse. A returned signature is always durable first.
    pub fn sign(&mut self, req: &SignRequest) -> Result<Vec<u8>, SignerError> {
        if self.poisoned {
            return Err(SignerError::Poisoned);
        }
        if req.position.step == Step::Propose && req.value == VoteValue::Nil {
            return Err(SignerError::InvalidRequest("a proposal must name a block"));
        }
        if let Some(floor) = self.record.floor {
            if req.position <= floor {
                return Err(SignerError::Regression {
                    requested: req.position,
                    high_water: floor,
                });
            }
        }
        if let Some(last) = self.record.last.as_ref() {
            if req.position < last.position {
                return Err(SignerError::Regression {
                    requested: req.position,
                    high_water: last.position,
                });
            }
            if req.position == last.position {
                return if last.value == req.value && last.payload == req.payload {
                    // Already durable: hand back the same bytes, sign nothing new.
                    Ok(last.signature.clone())
                } else {
                    Err(SignerError::Equivocation(req.position))
                };
            }
        }

        let lock_here = self.record.lock.filter(|l| l.height == req.position.height);
        let mut next_lock = lock_here;
        match (req.position.step, req.value) {
            (Step::Prevote, VoteValue::Block(v)) => {
                if let Some(lock) = lock_here {
                    if lock.value != v {
                        let j = req
                            .justification
                            .as_ref()
                            .ok_or(SignerError::LockedOnOtherValue(lock))?;
                        if !(lock.round <= j.polka_round && j.polka_round < req.position.round) {
                            return Err(SignerError::LockedOnOtherValue(lock));
                        }
                        self.polka
                            .verify_polka(req.position.height, j.polka_round, &v, &j.evidence)
                            .map_err(SignerError::InvalidJustification)?;
                    }
                }
            }
            (Step::Precommit, VoteValue::Block(v)) => {
                let j = req
                    .justification
                    .as_ref()
                    .ok_or(SignerError::MissingJustification)?;
                if j.polka_round != req.position.round {
                    return Err(SignerError::MissingJustification);
                }
                self.polka
                    .verify_polka(req.position.height, j.polka_round, &v, &j.evidence)
                    .map_err(SignerError::InvalidJustification)?;
                next_lock = Some(Lock {
                    height: req.position.height,
                    round: req.position.round,
                    value: v,
                });
            }
            (Step::Prevote | Step::Precommit, VoteValue::Nil) | (Step::Propose, _) => {}
        }

        let sequence = self
            .record
            .sequence
            .checked_add(1)
            .ok_or(SignerError::InvalidRequest("signer sequence exhausted"))?;
        let signature = self.key.sign(&req.payload);
        let next = SignerRecord {
            key_id: self.record.key_id,
            sequence,
            floor: self.record.floor,
            last: Some(LastSigned {
                position: req.position,
                value: req.value,
                payload: req.payload.clone(),
                signature: signature.clone(),
            }),
            lock: next_lock,
        };
        match self.store.persist(&next) {
            Ok(()) => {
                self.record = next;
                Ok(signature)
            }
            Err(e) => {
                self.poisoned = true;
                Err(SignerError::PersistFailed(e.0))
            }
        }
    }
}

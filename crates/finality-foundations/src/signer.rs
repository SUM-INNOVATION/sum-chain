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
//! * Height (PROPOSED, unratified): the signer works at one height at a time.
//!   Before any certified height it is the floor's next height, or else the
//!   height of the first signature; after [`DurableSigner::advance`] it is the
//!   certified height + 1. A request above the working height is refused: a
//!   caller asking for a higher height never by itself discards the lock or
//!   the last signature. Only `advance`, with a finality proof the signer
//!   verifies itself, moves to a higher height; it raises the floor past the
//!   proven height and only then discards the old height's lock and last
//!   signature.
//! * Lock (Tendermint, per height):
//!   - a non-nil precommit for `v` in round `r` needs a verified polka for `v`
//!     in round `r`, and locks on `(r, v)`;
//!   - while locked on `(r_l, v_l)`, a non-nil prevote for `v != v_l` in round
//!     `r` needs a verified polka for `v` in a round `p` with `r_l <= p < r`;
//!   - nil prevotes and nil precommits are allowed and leave the lock as is;
//!   - the lock applies only to its own height; it is discarded only by
//!     `advance` past that height.
//!
//! # Limits of what this core can check
//!
//! * The payload bytes are opaque: the signer trusts the caller's declared
//!   position and value to match the payload. The vote format is now ratified
//!   ([`crate::vote`]); decoding the payload as exactly `D_VOTE ‖ body` and
//!   binding it to the requested position and value is a follow-up together
//!   with the signer-state layout (A2, unratified).
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

/// The bytes a stored signature covers, as the store keeps them.
///
/// A record built by [`DurableSigner::sign`] always holds the full bytes. A
/// store whose encoding keeps only a digest (the proposed file layout in
/// [`crate::signer_file`]) loads [`SignBytes::Digest`] and must then answer
/// [`SignerStore::sign_bytes_digest`], so that an identical request can still
/// be recognised after a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignBytes {
    Full(Vec<u8>),
    Digest(Digest),
}

/// The last signature this key released (or is about to release).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastSigned {
    pub position: SignPosition,
    pub value: VoteValue,
    pub payload: SignBytes,
    pub signature: Vec<u8>,
}

/// A Tendermint lock: this key precommitted `value` in `round` at `height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lock {
    pub height: u64,
    pub round: u32,
    pub value: Digest,
}

/// The highest height this signer holds a verified finality proof for, and
/// the block that proof commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certified {
    pub height: u64,
    pub block_id: Digest,
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
    /// Set by [`DurableSigner::advance`]: the floor is then the whole of
    /// `certified.height` and below.
    pub certified: Option<Certified>,
}

/// The floor position that covers every position at heights `≤ height`.
pub fn whole_height_floor(height: u64) -> SignPosition {
    SignPosition {
        height,
        round: crate::encoding::MAX_ROUND,
        step: Step::Precommit,
    }
}

impl SignerRecord {
    /// The only height this record may sign at, if one is fixed yet: the
    /// certified height + 1; else the first height above the floor; else the
    /// height of the last signature. `None` only before anything is signed,
    /// certified or floored.
    pub fn working_height(&self) -> Option<u64> {
        if let Some(c) = self.certified {
            return c.height.checked_add(1);
        }
        if let Some(f) = self.floor {
            let next = if f.round == crate::encoding::MAX_ROUND && f.step == Step::Precommit {
                f.height.checked_add(1)
            } else {
                Some(f.height)
            };
            return next;
        }
        self.last.as_ref().map(|l| l.position.height)
    }

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
            if let Some(w) = self.working_height() {
                if last.position.height != w {
                    return Err("the last signature is not at the working height");
                }
            }
        }
        if let Some(c) = self.certified {
            if self.floor != Some(whole_height_floor(c.height)) {
                return Err("a certified height without its floor");
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

    /// The digest under which this store records `sign_bytes`, for stores that
    /// load [`SignBytes::Digest`]. `None` (the default) means the store keeps
    /// full bytes; a loaded digest is then never matched, which refuses an
    /// identical request as equivocation rather than guessing.
    fn sign_bytes_digest(&self, _sign_bytes: &[u8]) -> Option<Digest> {
        None
    }
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

    /// Verify a finality proof (PROPOSED: a `FinalityCertificateV1` checked
    /// against the node's authenticated set for the height it names) and
    /// return the (height, block) it proves final. The default refuses every
    /// proof, so a signer without a finality verifier can never leave its
    /// working height.
    fn verify_finality(&self, _proof: &[u8]) -> Result<Certified, String> {
        Err("no finality-proof verifier is configured".into())
    }
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
    #[error("height {requested} is above the working height {working}; advance with a finality proof first")]
    HeightNotCertified { requested: u64, working: u64 },
    #[error("finality proof refused: {0}")]
    InvalidFinalityProof(String),
    #[error("finality proof for height {proof} is not above the certified history (working height {working})")]
    StaleFinalityProof { proof: u64, working: u64 },
    #[error("two verified finality proofs name different blocks at height {0}; the signer stops")]
    ConflictingFinality(u64),
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

/// [`initialize`] while holding the key's exclusive ownership, so that two
/// initializations (or an initialization racing a running signer) cannot
/// interleave. The guard is released on return.
pub fn initialize_exclusive<S: SignerStore, L: ExclusiveOwnership>(
    ownership: &L,
    store: &mut S,
    key_id: Digest,
    floor: Option<SignPosition>,
) -> Result<(), SignerError> {
    let _guard = ownership
        .try_acquire()
        .map_err(|e| SignerError::OwnershipHeld(e.0))?;
    initialize(store, key_id, floor)
}

/// Explicit initialization: creates the first record, and refuses if any
/// record exists or the store cannot be read. `floor` must be at or above any
/// position this key may already have signed. It does not take the ownership
/// lock itself; [`initialize_exclusive`] does.
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
        certified: None,
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

    /// Leave the working height (PROPOSED, unratified). `proof` must convince
    /// the signer's own verifier ([`PolkaVerifier::verify_finality`]) that a
    /// height `H` is final; the caller's word is never enough.
    ///
    /// * `H` at or above the working height: the floor is raised to cover
    ///   every position at heights `≤ H`, the last signature and the lock
    ///   (both at a height `≤ H`) are discarded, and the record is persisted
    ///   before anything is signed at `H + 1`.
    /// * `H` equal to the certified height: nothing changes if the block is
    ///   the same; a different block means two verified finality proofs
    ///   conflict, and the signer refuses everything until it is reopened.
    /// * `H` below the working height otherwise: refused as stale; nothing
    ///   changes.
    pub fn advance(&mut self, proof: &[u8]) -> Result<Certified, SignerError> {
        if self.poisoned {
            return Err(SignerError::Poisoned);
        }
        let proven = self
            .polka
            .verify_finality(proof)
            .map_err(SignerError::InvalidFinalityProof)?;
        if proven.height == u64::MAX {
            return Err(SignerError::InvalidFinalityProof(
                "a finality proof for the last representable height".into(),
            ));
        }
        if let Some(c) = self.record.certified {
            if proven.height == c.height {
                if proven.block_id != c.block_id {
                    self.poisoned = true;
                    return Err(SignerError::ConflictingFinality(proven.height));
                }
                return Ok(c);
            }
        }
        if let Some(working) = self.record.working_height() {
            if proven.height < working {
                return Err(SignerError::StaleFinalityProof {
                    proof: proven.height,
                    working,
                });
            }
        }
        let sequence = self
            .record
            .sequence
            .checked_add(1)
            .ok_or(SignerError::InvalidRequest("signer sequence exhausted"))?;
        let next = SignerRecord {
            key_id: self.record.key_id,
            sequence,
            floor: Some(whole_height_floor(proven.height)),
            last: None,
            lock: None,
            certified: Some(proven),
        };
        match self.store.persist(&next) {
            Ok(()) => {
                self.record = next;
                Ok(proven)
            }
            Err(e) => {
                self.poisoned = true;
                Err(SignerError::PersistFailed(e.0))
            }
        }
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
                let same_bytes = match &last.payload {
                    SignBytes::Full(bytes) => *bytes == req.payload,
                    SignBytes::Digest(d) => self
                        .store
                        .sign_bytes_digest(&req.payload)
                        .is_some_and(|x| x == *d),
                };
                return if last.value == req.value && same_bytes {
                    // Already durable: hand back the same bytes, sign nothing new.
                    Ok(last.signature.clone())
                } else {
                    Err(SignerError::Equivocation(req.position))
                };
            }
        }

        if let Some(working) = self.record.working_height() {
            if req.position.height > working {
                return Err(SignerError::HeightNotCertified {
                    requested: req.position.height,
                    working,
                });
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
                payload: SignBytes::Full(req.payload.clone()),
                signature: signature.clone(),
            }),
            lock: next_lock,
            certified: self.record.certified,
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

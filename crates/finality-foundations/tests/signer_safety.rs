//! G2-b (ratified 2026-10-16): durable signer state before signature release,
//! exclusive ownership, explicit initialization and fail-closed recovery.
//!
//! The store, ownership lock and polka evidence below are test doubles. The
//! payload bytes are synthetic and are not a proposal for any vote encoding.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ed25519_dalek::{Signer as _, Verifier as _};
use sumchain_finality_foundations::signer::{
    initialize, Certified, DurableSigner, ExclusiveOwnership, Justification, Lock, OwnershipError,
    PolkaVerifier, SignBytes, SignPosition, SignRequest, SignerError, SignerRecord, SignerStore,
    SigningKey, Step, StoreError, VoteValue,
};
use sumchain_finality_foundations::Digest;

// ── test doubles ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// The next persist fails and writes nothing.
    FailBeforeWrite,
    /// The next persist writes the record durably, then reports failure (a
    /// crash or fsync error after the write).
    FailAfterWrite,
    /// Every load fails.
    LoadCorrupt,
}

type Events = Rc<RefCell<Vec<&'static str>>>;

struct DiskInner {
    record: Option<SignerRecord>,
    fault: Fault,
    persists: usize,
}

#[derive(Clone)]
struct Disk(Rc<RefCell<DiskInner>>, Events);

impl Disk {
    fn new(events: &Events) -> Self {
        Disk(
            Rc::new(RefCell::new(DiskInner {
                record: None,
                fault: Fault::None,
                persists: 0,
            })),
            events.clone(),
        )
    }
    fn record(&self) -> Option<SignerRecord> {
        self.0.borrow().record.clone()
    }
    fn set_record(&self, r: Option<SignerRecord>) {
        self.0.borrow_mut().record = r;
    }
    fn fault(&self, f: Fault) {
        self.0.borrow_mut().fault = f;
    }
    fn persists(&self) -> usize {
        self.0.borrow().persists
    }
    fn store(&self) -> MemStore {
        MemStore(self.clone())
    }
}

struct MemStore(Disk);

impl SignerStore for MemStore {
    fn load(&mut self) -> Result<Option<SignerRecord>, StoreError> {
        let d = self.0 .0.borrow();
        if d.fault == Fault::LoadCorrupt {
            return Err(StoreError("checksum mismatch".into()));
        }
        Ok(d.record.clone())
    }

    fn persist(&mut self, record: &SignerRecord) -> Result<(), StoreError> {
        let mut d = self.0 .0.borrow_mut();
        match d.fault {
            Fault::FailBeforeWrite => {
                d.fault = Fault::None;
                Err(StoreError("write failed".into()))
            }
            Fault::FailAfterWrite => {
                d.fault = Fault::None;
                d.record = Some(record.clone());
                Err(StoreError("fsync reported an error after the write".into()))
            }
            Fault::None | Fault::LoadCorrupt => {
                d.record = Some(record.clone());
                d.persists += 1;
                self.0 .1.borrow_mut().push("persist");
                Ok(())
            }
        }
    }
}

#[derive(Clone, Default)]
struct MemOwnership(Rc<Cell<bool>>);

struct MemGuard(Rc<Cell<bool>>);

impl Drop for MemGuard {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl ExclusiveOwnership for MemOwnership {
    type Guard = MemGuard;
    fn try_acquire(&self) -> Result<MemGuard, OwnershipError> {
        if self.0.get() {
            Err(OwnershipError("another signer holds this key".into()))
        } else {
            self.0.set(true);
            Ok(MemGuard(self.0.clone()))
        }
    }
}

struct EdKey {
    sk: ed25519_dalek::SigningKey,
    uses: Rc<Cell<usize>>,
    events: Events,
}

impl SigningKey for EdKey {
    fn key_id(&self) -> Digest {
        self.sk.verifying_key().to_bytes()
    }
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.uses.set(self.uses.get() + 1);
        self.events.borrow_mut().push("sign");
        self.sk.sign(payload).to_bytes().to_vec()
    }
}

/// Accepts evidence equal to `polka ‖ height ‖ round ‖ value`, nothing else.
struct TestPolka;

fn polka_evidence(height: u64, round: u32, value: &Digest) -> Vec<u8> {
    let mut e = b"polka".to_vec();
    e.extend_from_slice(&height.to_le_bytes());
    e.extend_from_slice(&round.to_le_bytes());
    e.extend_from_slice(value);
    e
}

impl PolkaVerifier for TestPolka {
    fn verify_polka(
        &self,
        height: u64,
        round: u32,
        value: &Digest,
        evidence: &[u8],
    ) -> Result<(), String> {
        if evidence == polka_evidence(height, round, value) {
            Ok(())
        } else {
            Err("not a quorum of prevotes".into())
        }
    }
    fn verify_finality(&self, proof: &[u8]) -> Result<Certified, String> {
        // Accepts `final ‖ height LE ‖ block`, nothing else.
        match proof.strip_prefix(b"final".as_slice()) {
            Some(rest) if rest.len() == 40 => Ok(Certified {
                height: u64::from_le_bytes(rest[..8].try_into().unwrap()),
                block_id: rest[8..].try_into().unwrap(),
            }),
            _ => Err("not a finality proof".into()),
        }
    }
}

fn finality(height: u64, block: &Digest) -> Vec<u8> {
    let mut p = b"final".to_vec();
    p.extend_from_slice(&height.to_le_bytes());
    p.extend_from_slice(block);
    p
}

type TestSigner = DurableSigner<MemStore, EdKey, TestPolka, MemGuard>;

struct Rig {
    disk: Disk,
    owner: MemOwnership,
    seed: [u8; 32],
    uses: Rc<Cell<usize>>,
    events: Events,
}

impl Rig {
    fn new() -> Self {
        let events: Events = Rc::default();
        Rig {
            disk: Disk::new(&events),
            owner: MemOwnership::default(),
            seed: [7u8; 32],
            uses: Rc::default(),
            events,
        }
    }
    fn key(&self) -> EdKey {
        EdKey {
            sk: ed25519_dalek::SigningKey::from_bytes(&self.seed),
            uses: self.uses.clone(),
            events: self.events.clone(),
        }
    }
    fn key_id(&self) -> Digest {
        self.key().key_id()
    }
    fn init(&self) {
        initialize(&mut self.disk.store(), self.key_id(), None).unwrap();
    }
    fn open(&self, evidence: Option<SignPosition>) -> Result<TestSigner, SignerError> {
        DurableSigner::open(
            &self.owner,
            self.disk.store(),
            self.key(),
            TestPolka,
            evidence,
        )
    }
}

fn pos(height: u64, round: u32, step: Step) -> SignPosition {
    SignPosition {
        height,
        round,
        step,
    }
}

const A: Digest = [0xA1; 32];
const B: Digest = [0xB2; 32];

fn req(height: u64, round: u32, step: Step, value: VoteValue, tag: &str) -> SignRequest {
    SignRequest {
        position: pos(height, round, step),
        value,
        payload: format!("{height}/{round}/{step:?}/{value:?}/{tag}").into_bytes(),
        justification: None,
    }
}

fn justified(mut r: SignRequest, polka_round: u32, value: &Digest) -> SignRequest {
    r.justification = Some(Justification {
        polka_round,
        evidence: polka_evidence(r.position.height, polka_round, value),
    });
    r
}

// ── explicit initialization and fail-closed recovery ────────────────────────

#[test]
fn g2b_open_never_creates_state() {
    let rig = Rig::new();
    assert!(matches!(rig.open(None), Err(SignerError::NotInitialized)));
    assert_eq!(rig.disk.record(), None, "open must not create state");
    assert_eq!(rig.disk.persists(), 0);
    // The failed open released ownership.
    rig.init();
    assert!(rig.open(None).is_ok());
}

#[test]
fn g2b_initialization_is_explicit_and_happens_once() {
    let rig = Rig::new();
    rig.init();
    let first = rig.disk.record().unwrap();
    assert_eq!(first.sequence, 0);
    assert_eq!(first.last, None);
    assert_eq!(
        initialize(&mut rig.disk.store(), rig.key_id(), None),
        Err(SignerError::AlreadyInitialized)
    );
    assert_eq!(
        rig.disk.record(),
        Some(first),
        "a refused init writes nothing"
    );

    let corrupt = Rig::new();
    corrupt.disk.fault(Fault::LoadCorrupt);
    assert!(matches!(
        initialize(&mut corrupt.disk.store(), corrupt.key_id(), None),
        Err(SignerError::Corrupt(_))
    ));
}

#[test]
fn g2b_state_missing_after_initialization_fails_closed() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    s.sign(&req(5, 0, Step::Prevote, VoteValue::Block(A), "x"))
        .unwrap();
    drop(s);

    rig.disk.set_record(None); // the state file is lost
    assert!(matches!(rig.open(None), Err(SignerError::NotInitialized)));

    // Re-initializing without a floor is caught by external evidence of the
    // signature already released at (5, 0, Prevote).
    rig.init();
    assert!(matches!(
        rig.open(Some(pos(5, 0, Step::Prevote))),
        Err(SignerError::StaleState { .. })
    ));

    // Re-initializing with a floor at or above anything possibly signed is
    // safe: nothing at or below the floor can be signed again.
    rig.disk.set_record(None);
    initialize(
        &mut rig.disk.store(),
        rig.key_id(),
        Some(pos(5, 0, Step::Precommit)),
    )
    .unwrap();
    let mut s = rig.open(Some(pos(5, 0, Step::Prevote))).unwrap();
    assert!(matches!(
        s.sign(&req(5, 0, Step::Prevote, VoteValue::Block(B), "y")),
        Err(SignerError::Regression { .. })
    ));
    assert!(s
        .sign(&req(5, 1, Step::Prevote, VoteValue::Nil, "z"))
        .is_ok());
}

#[test]
fn g2b_corrupt_or_inconsistent_state_fails_closed() {
    let rig = Rig::new();
    rig.init();
    rig.disk.fault(Fault::LoadCorrupt);
    assert!(matches!(rig.open(None), Err(SignerError::Corrupt(_))));

    let rig = Rig::new();
    rig.disk.set_record(Some(SignerRecord {
        key_id: rig.key_id(),
        sequence: 3,
        floor: None,
        last: None,
        lock: Some(Lock {
            height: 1,
            round: 0,
            value: A,
        }),
        certified: None,
        lock_proof: None,
        halt: None,
    }));
    assert!(matches!(rig.open(None), Err(SignerError::Corrupt(_))));
}

#[test]
fn g2b_state_of_another_key_is_refused() {
    let rig = Rig::new();
    initialize(&mut rig.disk.store(), [9u8; 32], None).unwrap();
    assert!(matches!(rig.open(None), Err(SignerError::KeyMismatch)));
}

// ── durability before release ───────────────────────────────────────────────

#[test]
fn g2b_signature_is_durable_before_it_is_released() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    rig.events.borrow_mut().clear();
    let r = req(1, 0, Step::Prevote, VoteValue::Block(A), "x");
    let sig = s.sign(&r).unwrap();
    rig.events.borrow_mut().push("release");
    assert_eq!(*rig.events.borrow(), vec!["sign", "persist", "release"]);
    let durable = rig.disk.record().unwrap().last.unwrap();
    assert_eq!(durable.signature, sig);
    assert_eq!(durable.payload, SignBytes::Full(r.payload.clone()));

    let vk = ed25519_dalek::SigningKey::from_bytes(&rig.seed).verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
    vk.verify(&r.payload, &sig).unwrap();
}

#[test]
fn g2b_failed_persist_releases_nothing_and_poisons_the_signer() {
    let rig = Rig::new();
    rig.init();
    let before = rig.disk.record();
    let mut s = rig.open(None).unwrap();
    rig.disk.fault(Fault::FailBeforeWrite);
    let r = req(1, 0, Step::Prevote, VoteValue::Block(A), "x");
    assert!(matches!(s.sign(&r), Err(SignerError::PersistFailed(_))));
    assert_eq!(rig.disk.record(), before, "nothing became durable");
    assert!(s.is_poisoned());
    assert_eq!(s.sign(&r), Err(SignerError::Poisoned));
    assert_eq!(
        s.sign(&req(2, 0, Step::Prevote, VoteValue::Nil, "y")),
        Err(SignerError::Poisoned)
    );
    drop(s);

    // Reopening from durable state recovers.
    let mut s = rig.open(None).unwrap();
    assert!(s.sign(&r).is_ok());
}

#[test]
fn g2b_crash_after_persist_before_release_cannot_equivocate() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    rig.disk.fault(Fault::FailAfterWrite);
    let r = req(4, 2, Step::Precommit, VoteValue::Block(A), "x");
    let r = justified(r, 2, &A);
    assert!(matches!(s.sign(&r), Err(SignerError::PersistFailed(_))));
    let durable = rig.disk.record().unwrap();
    let stored = durable.last.clone().unwrap().signature;
    drop(s);

    let uses = rig.uses.get();
    let mut s = rig.open(None).unwrap();
    // The same message gets the stored bytes back; no new signature is made.
    assert_eq!(s.sign(&r).unwrap(), stored);
    assert_eq!(rig.uses.get(), uses);
    // Anything else at that position is equivocation.
    let other = justified(req(4, 2, Step::Precommit, VoteValue::Block(B), "y"), 2, &B);
    assert_eq!(
        s.sign(&other),
        Err(SignerError::Equivocation(pos(4, 2, Step::Precommit)))
    );
    // The lock taken by the persisted precommit survived the crash.
    assert_eq!(
        s.record().lock,
        Some(Lock {
            height: 4,
            round: 2,
            value: A
        })
    );
}

// ── refusal rules ───────────────────────────────────────────────────────────

#[test]
fn g2b_same_position_returns_stored_signature_or_refuses() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    let r = req(3, 1, Step::Prevote, VoteValue::Block(A), "x");
    let first = s.sign(&r).unwrap();
    let persists = rig.disk.persists();
    let uses = rig.uses.get();
    assert_eq!(s.sign(&r).unwrap(), first);
    assert_eq!((rig.disk.persists(), rig.uses.get()), (persists, uses));

    let mut other_payload = r.clone();
    other_payload.payload.push(0);
    assert_eq!(
        s.sign(&other_payload),
        Err(SignerError::Equivocation(r.position))
    );
    let other_value = req(3, 1, Step::Prevote, VoteValue::Block(B), "x");
    assert_eq!(
        s.sign(&other_value),
        Err(SignerError::Equivocation(r.position))
    );
    let nil = req(3, 1, Step::Prevote, VoteValue::Nil, "x");
    assert_eq!(s.sign(&nil), Err(SignerError::Equivocation(r.position)));
}

#[test]
fn g2b_positions_below_the_last_signed_are_refused() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    s.sign(&req(10, 3, Step::Prevote, VoteValue::Nil, "x"))
        .unwrap();
    for (h, r, step) in [
        (9, 9, Step::Precommit),
        (10, 2, Step::Precommit),
        (10, 3, Step::Propose),
    ] {
        assert!(matches!(
            s.sign(&req(h, r, step, VoteValue::Block(A), "y")),
            Err(SignerError::Regression { .. })
        ));
    }
    assert!(s
        .sign(&req(10, 3, Step::Precommit, VoteValue::Nil, "z"))
        .is_ok());
}

#[test]
fn g2b_nil_proposal_is_refused() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    assert!(matches!(
        s.sign(&req(1, 0, Step::Propose, VoteValue::Nil, "x")),
        Err(SignerError::InvalidRequest(_))
    ));
}

// ── exclusive ownership ─────────────────────────────────────────────────────

#[test]
fn g2b_second_owner_is_refused() {
    let rig = Rig::new();
    rig.init();
    let s1 = rig.open(None).unwrap();
    assert!(matches!(rig.open(None), Err(SignerError::OwnershipHeld(_))));
    drop(s1);
    assert!(rig.open(None).is_ok());
}

// ── restore from old state ──────────────────────────────────────────────────

#[test]
fn g2b_restored_old_state_is_refused_against_external_evidence() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    s.sign(&req(7, 0, Step::Prevote, VoteValue::Block(A), "x"))
        .unwrap();
    let backup = rig.disk.record();
    s.sign(&justified(
        req(7, 0, Step::Precommit, VoteValue::Block(A), "x"),
        0,
        &A,
    ))
    .unwrap();
    drop(s);

    rig.disk.set_record(backup); // an operator restores the older copy
    assert!(matches!(
        rig.open(Some(pos(7, 0, Step::Precommit))),
        Err(SignerError::StaleState { .. })
    ));
}

/// The limit stated in the module docs: without external evidence a restored
/// copy cannot be told apart, which is why restoring signer state is an
/// operator prohibition and `open` takes an evidence floor.
#[test]
fn g2b_restored_old_state_is_undetectable_without_external_evidence() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    s.sign(&req(7, 0, Step::Prevote, VoteValue::Block(A), "x"))
        .unwrap();
    let backup = rig.disk.record();
    s.sign(&req(7, 0, Step::Precommit, VoteValue::Nil, "x"))
        .unwrap();
    drop(s);
    rig.disk.set_record(backup);
    let mut s = rig.open(None).unwrap();
    assert!(s
        .sign(&req(7, 0, Step::Precommit, VoteValue::Nil, "different"))
        .is_ok());
}

// ── lock rules ──────────────────────────────────────────────────────────────

#[test]
fn g2b_precommit_needs_a_polka_in_its_own_round_and_locks() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    let bare = req(2, 1, Step::Precommit, VoteValue::Block(A), "x");
    assert_eq!(s.sign(&bare), Err(SignerError::MissingJustification));
    assert_eq!(
        s.sign(&justified(bare.clone(), 0, &A)),
        Err(SignerError::MissingJustification)
    );
    let mut forged = justified(bare.clone(), 1, &A);
    forged.justification.as_mut().unwrap().evidence.push(1);
    assert!(matches!(
        s.sign(&forged),
        Err(SignerError::InvalidJustification(_))
    ));
    assert!(matches!(
        s.sign(&justified(bare.clone(), 1, &B)),
        Err(SignerError::InvalidJustification(_))
    ));
    assert_eq!(
        rig.disk.record().unwrap().sequence,
        0,
        "refusals write nothing"
    );

    s.sign(&justified(bare, 1, &A)).unwrap();
    assert_eq!(
        rig.disk.record().unwrap().lock,
        Some(Lock {
            height: 2,
            round: 1,
            value: A
        })
    );
}

#[test]
fn g2b_lock_refuses_prevotes_for_other_values_without_a_later_polka() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    s.sign(&justified(
        req(2, 2, Step::Precommit, VoteValue::Block(A), "x"),
        2,
        &A,
    ))
    .unwrap();
    let lock = Lock {
        height: 2,
        round: 2,
        value: A,
    };

    let other = req(2, 5, Step::Prevote, VoteValue::Block(B), "y");
    assert_eq!(s.sign(&other), Err(SignerError::LockedOnOtherValue(lock)));
    // Polka older than the lock: refused.
    assert_eq!(
        s.sign(&justified(other.clone(), 1, &B)),
        Err(SignerError::LockedOnOtherValue(lock))
    );
    // Polka not before the prevote's round: refused.
    assert_eq!(
        s.sign(&justified(other.clone(), 5, &B)),
        Err(SignerError::LockedOnOtherValue(lock))
    );
    // Polka in [lock round, prevote round): allowed.
    s.sign(&justified(other, 3, &B)).unwrap();
}

#[test]
fn g2b_locked_value_and_nil_votes_need_no_justification() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    s.sign(&justified(
        req(2, 0, Step::Precommit, VoteValue::Block(A), "x"),
        0,
        &A,
    ))
    .unwrap();
    let lock = rig.disk.record().unwrap().lock;
    s.sign(&req(2, 1, Step::Prevote, VoteValue::Block(A), "y"))
        .unwrap();
    s.sign(&req(2, 1, Step::Precommit, VoteValue::Nil, "y"))
        .unwrap();
    s.sign(&req(2, 2, Step::Prevote, VoteValue::Nil, "z"))
        .unwrap();
    assert_eq!(
        rig.disk.record().unwrap().lock,
        lock,
        "nil votes keep the lock"
    );
}

#[test]
fn g2b_lock_is_discarded_only_by_a_verified_finality_proof() {
    let rig = Rig::new();
    rig.init();
    let mut s = rig.open(None).unwrap();
    s.sign(&justified(
        req(2, 0, Step::Precommit, VoteValue::Block(A), "x"),
        0,
        &A,
    ))
    .unwrap();
    // Asking for a higher height does not move the signer.
    assert_eq!(
        s.sign(&req(3, 0, Step::Prevote, VoteValue::Block(B), "y")),
        Err(SignerError::HeightNotCertified {
            requested: 3,
            working: 2
        })
    );
    assert!(matches!(
        s.advance(b"no proof"),
        Err(SignerError::InvalidFinalityProof(_))
    ));
    assert_eq!(
        rig.disk.record().unwrap().lock.map(|l| l.value),
        Some(A),
        "the lock survives every refused request"
    );
    // A verified proof for height 2 moves the signer to height 3.
    s.advance(&finality(2, &A)).unwrap();
    assert_eq!(rig.disk.record().unwrap().lock, None);
    s.sign(&req(3, 0, Step::Prevote, VoteValue::Block(B), "y"))
        .unwrap();
    assert!(matches!(
        s.sign(&req(2, 5, Step::Prevote, VoteValue::Nil, "late")),
        Err(SignerError::Regression { .. })
    ));
}

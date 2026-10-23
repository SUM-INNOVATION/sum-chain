//! Signer persistence (the 413-byte record adopted by the owner, 2026-10-22 (decision ledger, as enumerated there); dormant, no node wiring; other elements PROPOSED): the recovery
//! invariants and the crash-point matrix, over the file-backed store in
//! `signer_file` and the ratified G2-b signer core; on Unix, round trips
//! through a real directory, including a conflict halt and its recovery.
//!
//! The disk below is a model: each file has volatile and durable contents,
//! the directory has volatile and durable entries, and a simulated crash
//! drops everything not yet synced. Real power-loss behaviour is not tested.
//! Keys, payloads and values are synthetic.

use std::rc::Rc;

use ed25519_dalek::{Signer as _, Verifier as _};
use sumchain_finality_foundations::encoding::MAX_ROUND;
use sumchain_finality_foundations::signer::{
    initialize_exclusive, Certified, DurableSigner, Justification, Lock, SignBytes, SignPosition,
    SignRequest, SignerError, SignerRecord, SignerStore, SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{
    conflict_file_name, floor_below_height, offset, proof_file_name, sign_bytes_digest, Classified,
    FileSignerStore, Identity, IoError, MirrorStore, RecoveryReceipt, SignerState, StateError,
    StateLast, StdSignerDir, CHECKSUMMED_LEN, D_SIGNER, HALT_SET, STATE_FILE, STATE_LEN, TEMP_FILE,
};
use sumchain_finality_foundations::Digest;

mod common;
use common::*;

struct EdKey(ed25519_dalek::SigningKey);
impl SigningKey for EdKey {
    fn key_id(&self) -> Digest {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.0.sign(payload).to_bytes().to_vec()
    }
}

type Store = FileSignerStore<SimDir, SimMirror, B3>;
type Signer = DurableSigner<Store, EdKey, TestPolka, MemGuard>;

const CHAIN: u64 = 4242;
const GENESIS: Digest = [0x11; 32];
const SEED: [u8; 32] = [7u8; 32];
const FLOOR: u64 = 7;
const A: Digest = [0xA1; 32];
const B: Digest = [0xB2; 32];

struct Rig {
    disk: Disk,
    owner: MemOwnership,
    seed: [u8; 32],
    chain: u64,
    genesis: Digest,
}

impl Rig {
    fn new() -> Self {
        Rig {
            disk: Rc::default(),
            owner: MemOwnership::default(),
            seed: SEED,
            chain: CHAIN,
            genesis: GENESIS,
        }
    }
    fn store(&self) -> Store {
        FileSignerStore::new(
            SimDir(self.disk.clone()),
            SimMirror(self.disk.clone()),
            B3,
            self.chain,
            self.genesis,
        )
    }
    fn key(&self) -> EdKey {
        EdKey(ed25519_dalek::SigningKey::from_bytes(&self.seed))
    }
    fn pubkey(&self) -> Digest {
        self.key().key_id()
    }
    fn init(&self) -> Result<(), SignerError> {
        initialize_exclusive(
            &self.owner,
            &mut self.store(),
            self.pubkey(),
            floor_below_height(FLOOR),
        )
    }
    fn open(&self) -> Result<Signer, SignerError> {
        DurableSigner::open(&self.owner, self.store(), self.key(), TestPolka, None)
    }
    /// Fail (or crash at) the `n`-th mutating operation from now.
    fn arm(&self, n: usize, mode: Mode) {
        let mut m = self.disk.borrow_mut();
        m.ops = 0;
        m.log.clear();
        m.plan = Some((n, mode));
    }
    fn recover(&self, mode: Mode) {
        match mode {
            Mode::Error | Mode::EffectThenError => self.disk.borrow_mut().restart(),
            _ => self.disk.borrow_mut().reboot(),
        }
    }
    fn file(&self, name: &str) -> Option<Vec<u8>> {
        let m = self.disk.borrow();
        m.dir_vol.get(name).map(|&i| m.inodes[i].vol.clone())
    }
    fn durable_file(&self, name: &str) -> Option<Vec<u8>> {
        let m = self.disk.borrow();
        m.dir_dur.get(name).map(|&i| m.inodes[i].dur.clone())
    }
    fn mirror(&self) -> Option<Vec<u8>> {
        self.disk.borrow().mirror_vol.clone()
    }
    fn set_file(&self, name: &str, bytes: Vec<u8>) {
        let mut m = self.disk.borrow_mut();
        m.inodes.push(Inode {
            vol: bytes.clone(),
            dur: bytes,
        });
        let id = m.inodes.len() - 1;
        m.dir_vol.insert(name.to_string(), id);
        m.dir_dur.insert(name.to_string(), id);
    }
    fn remove_file(&self, name: &str) {
        let mut m = self.disk.borrow_mut();
        m.dir_vol.remove(name);
        m.dir_dur.remove(name);
    }
    fn set_mirror(&self, bytes: Option<Vec<u8>>) {
        let mut m = self.disk.borrow_mut();
        m.mirror_vol = bytes.clone();
        m.mirror_dur = bytes;
    }
    fn identity(&self) -> Identity {
        Identity {
            chain_id: self.chain,
            genesis_block_hash: self.genesis,
            signer_pubkey: self.pubkey(),
        }
    }
}

fn pos(height: u64, round: u32, step: Step) -> SignPosition {
    SignPosition {
        height,
        round,
        step,
    }
}

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

fn prevote(h: u64, r: u32, v: Digest) -> SignRequest {
    req(h, r, Step::Prevote, VoteValue::Block(v), "x")
}
fn precommit(h: u64, r: u32, v: Digest) -> SignRequest {
    justified(req(h, r, Step::Precommit, VoteValue::Block(v), "x"), r, &v)
}

fn verify(rig: &Rig, payload: &[u8], sig: &[u8]) {
    let vk = ed25519_dalek::SigningKey::from_bytes(&rig.seed).verifying_key();
    vk.verify(payload, &ed25519_dalek::Signature::from_slice(sig).unwrap())
        .unwrap();
}

/// Recompute the checksum over mutated bytes (to test semantic checks).
fn reseal(mut b: Vec<u8>) -> Vec<u8> {
    let mut pre = D_SIGNER.to_vec();
    pre.extend_from_slice(&b[..CHECKSUMMED_LEN]);
    let sum: Digest = blake3::hash(&pre).into();
    b[CHECKSUMMED_LEN..STATE_LEN].copy_from_slice(&sum);
    b
}

type Expect = fn(&StateError) -> bool;
type Mutate = fn(&mut SignerState);
type MutateDyn = dyn Fn(&mut SignerState);

fn decode(b: &[u8]) -> Result<(SignerState, Digest), StateError> {
    SignerState::decode(b, &B3)
}

/// A fresh rig, initialized at floor 7, with `setup` signed without faults.
#[derive(Clone)]
enum Act {
    Sign(SignRequest),
    Advance(Vec<u8>),
}

/// A fresh rig, initialized at floor 7, with `acts` performed without faults.
fn prepared_acts(acts: &[Act]) -> Rig {
    let rig = Rig::new();
    rig.init().unwrap();
    let mut s = rig.open().unwrap();
    for a in acts {
        match a {
            Act::Sign(r) => {
                s.sign(r).unwrap();
            }
            Act::Advance(p) => {
                s.advance(p).unwrap();
            }
        }
    }
    rig
}

fn prepared(setup: &[SignRequest]) -> Rig {
    let rig = Rig::new();
    rig.init().unwrap();
    let mut s = rig.open().unwrap();
    for r in setup {
        s.sign(r).unwrap();
    }
    rig
}

fn record_now(rig: &Rig) -> SignerRecord {
    rig.open().unwrap().record().clone()
}

// ── crash-point matrix ──────────────────────────────────────────────────────

struct Transition {
    name: &'static str,
    setup: Vec<Act>,
    request: SignRequest,
    lock_after: Option<Lock>,
}

fn transitions() -> Vec<Transition> {
    let locked = vec![Act::Sign(prevote(7, 0, A)), Act::Sign(precommit(7, 0, A))];
    let lock_a = Lock {
        height: 7,
        round: 0,
        value: A,
    };
    vec![
        Transition {
            name: "first sign",
            setup: vec![],
            request: prevote(7, 0, A),
            lock_after: None,
        },
        Transition {
            name: "lock",
            setup: vec![Act::Sign(prevote(7, 0, A))],
            request: precommit(7, 0, A),
            lock_after: Some(lock_a),
        },
        Transition {
            name: "relock at a higher round",
            setup: locked.clone(),
            request: precommit(7, 1, B),
            lock_after: Some(Lock {
                height: 7,
                round: 1,
                value: B,
            }),
        },
        Transition {
            name: "prevote another value with a later polka (lock kept)",
            setup: locked.clone(),
            request: justified(req(7, 2, Step::Prevote, VoteValue::Block(B), "x"), 1, &B),
            lock_after: Some(lock_a),
        },
        Transition {
            name: "first sign at the next height, after a verified advancement",
            setup: [locked, vec![Act::Advance(finality(7, &A))]].concat(),
            request: prevote(8, 0, B),
            lock_after: None,
        },
    ]
}

/// One fault at persist step `op` (0 write temp, 1 sync temp, 2 rename,
/// 3 sync dir, 4 mirror) in `mode`, then recovery, then the invariants.
fn run_sign_case(t: &Transition, op: usize, mode: Mode) {
    let ctx = format!("{} / op {op} / {mode:?}", t.name);
    let rig = prepared_acts(&t.setup);
    let before = record_now(&rig);
    let c = before.sequence;

    let mut s = rig.open().unwrap();
    rig.arm(op, mode);
    let res = s.sign(&t.request);
    assert!(res.is_err(), "{ctx}: a failed persist must not release");
    assert!(s.is_poisoned(), "{ctx}: signer must poison");
    drop(s);
    rig.recover(mode);

    // A single fault never bricks the signer.
    let mut s = rig
        .open()
        .unwrap_or_else(|e| panic!("{ctx}: reopen refused: {e}"));
    let rec = s.record().clone();
    assert!(
        rec.sequence == c || rec.sequence == c + 1,
        "{ctx}: counter {}",
        rec.sequence
    );
    if rec.sequence == c + 1 {
        let last = rec.last.as_ref().unwrap();
        assert_eq!(last.position, t.request.position, "{ctx}");
        assert_eq!(rec.lock, t.lock_after, "{ctx}: lock after the transition");
    } else {
        assert_eq!(
            rec.last,
            before.last.clone().map(|mut l| {
                if let SignBytes::Full(b) = &l.payload {
                    l.payload = SignBytes::Digest(sign_bytes_digest(&B3, b));
                }
                l
            }),
            "{ctx}"
        );
        assert_eq!(rec.lock, before.lock, "{ctx}: lock before the transition");
    }
    // Never a lost lock at the current height.
    if let (Some(old), Some(last)) = (before.lock, rec.last.as_ref()) {
        if last.position.height == old.height {
            let now = rec.lock.unwrap_or_else(|| panic!("{ctx}: lock lost"));
            assert!(now.round >= old.round, "{ctx}: lock went back");
        }
    }

    // No conflicting signature: a different message at the same position is
    // refused once the state names one, and the identical one is re-released.
    let mut other = t.request.clone();
    other.payload.extend_from_slice(b"/conflict");
    if rec.sequence == c + 1 {
        assert_eq!(
            s.sign(&other),
            Err(SignerError::Equivocation(t.request.position)),
            "{ctx}"
        );
    }
    let sig = s
        .sign(&t.request)
        .unwrap_or_else(|e| panic!("{ctx}: identical request: {e}"));
    verify(&rig, &t.request.payload, &sig);
    assert_eq!(
        s.sign(&other),
        Err(SignerError::Equivocation(t.request.position)),
        "{ctx}"
    );
    drop(s);

    // A power loss afterwards loses nothing that was released or repaired.
    rig.disk.borrow_mut().reboot();
    let s = rig
        .open()
        .unwrap_or_else(|e| panic!("{ctx}: refused after a later power loss: {e}"));
    assert_eq!(s.record().sequence, c + 1, "{ctx}");
    assert_eq!(s.record().lock, t.lock_after, "{ctx}");
}

#[test]
fn crash_point_matrix_for_every_signing_transition() {
    let mut cases = 0;
    for t in transitions() {
        for op in 0..5 {
            for mode in MODES {
                run_sign_case(&t, op, mode);
                cases += 1;
            }
        }
        // Released, then power loss: the signature is durable.
        let rig = prepared_acts(&t.setup);
        let mut s = rig.open().unwrap();
        let sig = s.sign(&t.request).unwrap();
        drop(s);
        rig.disk.borrow_mut().reboot();
        let mut s = rig.open().unwrap();
        assert_eq!(s.record().lock, t.lock_after, "{}", t.name);
        assert_eq!(s.sign(&t.request).unwrap(), sig, "{}", t.name);
        cases += 1;
    }
    assert_eq!(cases, 5 * 5 * 5 + 5);
}

/// Height advancement: a fault at every persistence step of `advance`, from
/// a state locked at height 7. Recovery yields either the old state (still
/// at height 7, lock and last intact) or the new one (height 8, certified
/// (7, A), nothing left of height 7). Never a state at height 8 without the
/// proof, and never height 7 without its lock.
#[test]
fn crash_point_matrix_for_height_advancement() {
    let lock_a = Lock {
        height: 7,
        round: 0,
        value: A,
    };
    let mut cases = 0;
    for op in 0..5 {
        for mode in MODES {
            let ctx = format!("advance / op {op} / {mode:?}");
            let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
            let c = record_now(&rig).sequence;
            let mut s = rig.open().unwrap();
            rig.arm(op, mode);
            assert!(s.advance(&finality(7, &A)).is_err(), "{ctx}");
            assert!(s.is_poisoned(), "{ctx}");
            drop(s);
            rig.recover(mode);

            let mut s = rig
                .open()
                .unwrap_or_else(|e| panic!("{ctx}: reopen refused: {e}"));
            let rec = s.record().clone();
            if rec.sequence == c + 1 {
                assert_eq!(rec.lock, None, "{ctx}");
                assert_eq!(rec.last, None, "{ctx}");
                assert_eq!(
                    rec.certified,
                    Some(Certified {
                        height: 7,
                        block_id: A
                    }),
                    "{ctx}"
                );
                assert_eq!(rec.working_height(), Some(8), "{ctx}");
            } else {
                assert_eq!(rec.sequence, c, "{ctx}");
                assert_eq!(rec.lock, Some(lock_a), "{ctx}: the lock survives");
                assert_eq!(rec.working_height(), Some(7), "{ctx}");
                assert_eq!(
                    s.sign(&prevote(8, 0, B)),
                    Err(SignerError::HeightNotCertified {
                        requested: 8,
                        working: 7
                    }),
                    "{ctx}"
                );
                s.advance(&finality(7, &A))
                    .unwrap_or_else(|e| panic!("{ctx}: retry advance: {e}"));
            }
            s.sign(&prevote(8, 0, B)).unwrap();
            assert!(
                matches!(
                    s.sign(&prevote(7, 3, A)),
                    Err(SignerError::Regression { .. })
                ),
                "{ctx}: height 7 is closed"
            );
            drop(s);
            rig.disk.borrow_mut().reboot();
            let s = rig
                .open()
                .unwrap_or_else(|e| panic!("{ctx}: refused after a later power loss: {e}"));
            assert_eq!(s.record().working_height(), Some(8), "{ctx}");
            assert_eq!(
                s.record().last.as_ref().map(|l| l.position),
                Some(pos(8, 0, Step::Prevote)),
                "{ctx}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 25);
}

/// Across several heights: a request for a higher height never moves the
/// signer; only a verified proof does, and stale or conflicting proofs
/// change nothing on disk.
#[test]
fn multi_height_sequence_with_refused_and_accepted_proofs() {
    let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
    let mut s = rig.open().unwrap();
    // No proof, a forged proof, a proof for a lower height: nothing moves.
    assert!(matches!(
        s.sign(&prevote(8, 0, B)),
        Err(SignerError::HeightNotCertified {
            requested: 8,
            working: 7
        })
    ));
    assert!(matches!(
        s.advance(b"forged"),
        Err(SignerError::InvalidFinalityProof(_))
    ));
    assert!(matches!(
        s.advance(&finality(6, &B)),
        Err(SignerError::StaleFinalityProof {
            proof: 6,
            working: 7
        })
    ));
    assert_eq!(s.record().lock.map(|l| l.height), Some(7));
    // Height 7 → 8.
    s.advance(&finality(7, &A)).unwrap();
    s.sign(&prevote(8, 0, B)).unwrap();
    s.sign(&precommit(8, 0, B)).unwrap();
    // Catch-up: a proof for height 11 moves straight to 12.
    s.advance(&finality(11, &A)).unwrap();
    assert_eq!(s.record().working_height(), Some(12));
    assert_eq!(s.record().lock, None);
    // The same certified height again is a no-op; a stale one is refused.
    rig.arm(0, Mode::Error);
    assert_eq!(
        s.advance(&finality(11, &A)).unwrap(),
        Certified {
            height: 11,
            block_id: A
        }
    );
    assert!(matches!(
        s.advance(&finality(9, &B)),
        Err(SignerError::StaleFinalityProof { .. })
    ));
    assert!(rig.disk.borrow().log.is_empty(), "nothing written");
    // A second verified proof for height 11 naming another block: the halt is
    // persisted (RATIFIED), and the signer refuses everything from now on.
    rig.arm(usize::MAX, Mode::Error);
    assert_eq!(
        s.advance(&finality(11, &B)),
        Err(SignerError::ConflictingFinality(11))
    );
    assert!(s.is_halted());
    assert!(!rig.disk.borrow().log.is_empty(), "the halt was written");
    assert_eq!(s.sign(&prevote(12, 0, A)), Err(SignerError::Halted));
    assert_eq!(s.advance(&finality(12, &A)), Err(SignerError::Halted));
    drop(s);
    rig.disk.borrow_mut().reboot();
    let s = rig.open().unwrap();
    assert!(s.is_halted(), "the halt survives a power loss");
    assert_eq!(
        s.record().certified,
        Some(Certified {
            height: 11,
            block_id: A
        })
    );
}

#[test]
fn crash_point_matrix_for_initialization() {
    for op in 0..5 {
        for mode in MODES {
            let ctx = format!("init / op {op} / {mode:?}");
            let rig = Rig::new();
            rig.arm(op, mode);
            assert!(rig.init().is_err(), "{ctx}");
            rig.recover(mode);
            match rig.open() {
                Err(SignerError::NotInitialized) => {
                    rig.init()
                        .unwrap_or_else(|e| panic!("{ctx}: retry init: {e}"));
                    assert_eq!(rig.open().unwrap().record().sequence, 0, "{ctx}");
                }
                Ok(s) => assert_eq!(s.record().sequence, 0, "{ctx}"),
                Err(e) => panic!("{ctx}: refused: {e}"),
            }
            rig.disk.borrow_mut().reboot();
            let mut s = rig
                .open()
                .unwrap_or_else(|e| panic!("{ctx}: refused after a later power loss: {e}"));
            s.sign(&prevote(7, 0, A)).unwrap();
        }
    }
}

#[test]
fn identical_resign_survives_restart_and_power_loss_without_writing() {
    let rig = prepared(&[prevote(7, 0, A)]);
    let mut s = rig.open().unwrap();
    rig.arm(0, Mode::Error); // any write would fail
    let first = s.sign(&prevote(7, 0, A)).unwrap();
    assert!(
        rig.disk.borrow().log.is_empty(),
        "re-release writes nothing"
    );
    drop(s);
    rig.disk.borrow_mut().reboot();
    let mut s = rig.open().unwrap();
    assert_eq!(s.sign(&prevote(7, 0, A)).unwrap(), first);
    assert!(matches!(
        s.sign(&req(7, 0, Step::Prevote, VoteValue::Block(A), "other")),
        Err(SignerError::Equivocation(_))
    ));
}

/// Leave the state file one persist ahead of the mirror: P1 complete, P2 failed.
fn one_ahead(rig: &Rig, r: &SignRequest) {
    let mut s = rig.open().unwrap();
    rig.arm(4, Mode::Error);
    assert!(s.sign(r).is_err());
    drop(s);
    rig.disk.borrow_mut().restart();
}

#[test]
fn crash_points_during_mirror_repair() {
    for op in 0..3 {
        for mode in MODES {
            let ctx = format!("repair / op {op} / {mode:?}");
            let rig = prepared(&[prevote(7, 0, A)]);
            one_ahead(&rig, &precommit(7, 0, A));
            rig.arm(op, mode);
            assert!(rig.open().is_err(), "{ctx}");
            rig.recover(mode);
            let s = rig.open().unwrap_or_else(|e| panic!("{ctx}: {e}"));
            assert_eq!(s.record().sequence, 2, "{ctx}");
            assert_eq!(
                s.record().lock,
                Some(Lock {
                    height: 7,
                    round: 0,
                    value: A
                }),
                "{ctx}"
            );
        }
    }
}

#[test]
fn crash_points_while_removing_a_leftover_temp_file() {
    for op in 0..2 {
        for mode in MODES {
            let ctx = format!("temp removal / op {op} / {mode:?}");
            let rig = prepared(&[prevote(7, 0, A)]);
            rig.set_file(TEMP_FILE, b"partial".to_vec());
            rig.arm(op, mode);
            assert!(rig.open().is_err(), "{ctx}");
            rig.recover(mode);
            let s = rig.open().unwrap_or_else(|e| panic!("{ctx}: {e}"));
            assert_eq!(s.record().sequence, 1, "{ctx}");
            assert!(rig.file(TEMP_FILE).is_none(), "{ctx}");
        }
    }
}

// ── I1 persistence before release; I9 file protocol ─────────────────────────

#[test]
fn i1_i9_release_follows_temp_write_sync_rename_dir_sync_and_mirror() {
    let rig = prepared(&[]);
    let mut s = rig.open().unwrap();
    rig.arm(usize::MAX, Mode::Error);
    s.sign(&prevote(7, 0, A)).unwrap();
    assert_eq!(
        rig.disk.borrow().log,
        vec![
            Op::WriteNew,
            Op::SyncFile,
            Op::Rename,
            Op::SyncDir,
            Op::Mirror
        ]
    );
    let durable = rig.durable_file(STATE_FILE).unwrap();
    assert_eq!(Some(durable.clone()), rig.disk.borrow().mirror_dur.clone());
    assert_eq!(decode(&durable).unwrap().0.counter, 1);
    assert!(rig.durable_file(TEMP_FILE).is_none());
}

// ── I2 complete mirror comparison ───────────────────────────────────────────

fn state_now(rig: &Rig) -> (SignerState, Digest) {
    decode(&rig.file(STATE_FILE).unwrap()).unwrap()
}

#[test]
fn i2_same_counter_requires_byte_identical_mirror() {
    // Each mirror below has the same counter, height, round and step as the
    // state file, so the draft-1 mirror tuple (counter ‖ height ‖ round ‖ step)
    // would have called it consistent.
    let mutations: Vec<(&str, Mutate, &str)> = vec![
        (
            "signature",
            |m| m.last.as_mut().unwrap().signature[0] ^= 1,
            "differ at the same counter",
        ),
        (
            "sign-bytes digest",
            |m| m.last.as_mut().unwrap().sign_bytes_digest[0] ^= 1,
            "differ at the same counter",
        ),
        (
            "predecessor",
            |m| m.prev_checksum[0] ^= 1,
            "differ at the same counter",
        ),
        (
            "certified block",
            |m| m.certified_block_id = B,
            "differ at the same counter",
        ),
    ];
    for (what, mutate, expect) in mutations {
        let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
        let (mut m, _) = state_now(&rig);
        mutate(&mut m);
        rig.set_mirror(Some(m.encode(&B3).unwrap().to_vec()));
        assert!(
            matches!(rig.open(), Err(SignerError::Corrupt(ref msg)) if msg.contains(expect)),
            "{what}"
        );
    }
    // A mirror whose lock group was cleared is not even a valid record.
    let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
    let mut m = rig.mirror().unwrap();
    m[offset::LOCK_STATE..offset::PREV].fill(0);
    rig.set_mirror(Some(reseal(m)));
    assert!(
        matches!(rig.open(), Err(SignerError::Corrupt(msg)) if msg.contains("without its own lock"))
    );
}

// ── I3 exact one-ahead repair; I8 counter overflow ──────────────────────────

#[test]
fn i3_one_ahead_repair_happens_only_for_the_exact_successor() {
    let rig = prepared(&[prevote(7, 0, A)]);
    one_ahead(&rig, &precommit(7, 0, A));
    let mut st = rig.store();
    assert!(st.load().unwrap().is_some());
    assert_eq!(st.classified(), Some(Classified::AdvancedMirror));
    assert_eq!(rig.file(STATE_FILE), rig.mirror());

    // Wrong predecessor checksum.
    let rig = prepared(&[prevote(7, 0, A)]);
    one_ahead(&rig, &precommit(7, 0, A));
    let (mut st, _) = state_now(&rig);
    st.prev_checksum = [9; 32];
    rig.set_file(STATE_FILE, st.encode(&B3).unwrap().to_vec());
    assert!(matches!(rig.open(), Err(SignerError::Corrupt(m)) if m.contains("predecessor")));

    // Position did not increase.
    let rig = prepared(&[prevote(7, 0, A)]);
    let (m_state, m_sum) = state_now(&rig);
    let mut f = m_state.clone();
    f.counter += 1;
    f.prev_checksum = m_sum;
    f.last.as_mut().unwrap().signature[0] ^= 1;
    rig.set_file(STATE_FILE, f.encode(&B3).unwrap().to_vec());
    assert!(matches!(rig.open(), Err(SignerError::Corrupt(m)) if m.contains("did not increase")));

    // Two ahead, and behind.
    for delta in [2i64, -1] {
        let rig = prepared(&[prevote(7, 0, A)]);
        let (mut f, _) = state_now(&rig);
        f.counter = (f.counter as i64 + delta) as u64;
        if f.counter == 0 {
            f.last = None;
            f.prev_checksum = [0; 32];
        }
        rig.set_file(STATE_FILE, f.encode(&B3).unwrap().to_vec());
        assert!(rig.open().is_err(), "delta {delta}");
    }

    // Mirror missing for a state that has signed.
    let rig = prepared(&[prevote(7, 0, A)]);
    rig.set_mirror(None);
    assert!(matches!(rig.open(), Err(SignerError::Corrupt(m)) if m.contains("mirror missing")));
}

#[test]
fn i3_repair_makes_the_state_file_durable_before_writing_the_mirror() {
    // P1's directory sync fails: the rename is visible but not durable.
    let rig = prepared(&[prevote(7, 0, A)]);
    let mut s = rig.open().unwrap();
    rig.arm(3, Mode::Error);
    assert!(s.sign(&precommit(7, 0, A)).is_err());
    drop(s);
    rig.disk.borrow_mut().restart();
    // Reopen repairs the mirror from the (visible) newer state file...
    let mut s = rig.open().unwrap();
    assert_eq!(s.record().sequence, 2);
    let sig = s.sign(&precommit(7, 0, A)).unwrap();
    drop(s);
    // ...and a power loss right after must not leave the mirror ahead of the
    // state file (which would refuse every later open).
    rig.disk.borrow_mut().reboot();
    let mut s = rig
        .open()
        .expect("state file was made durable before the repair");
    assert_eq!(s.sign(&precommit(7, 0, A)).unwrap(), sig);
}

#[test]
fn i8_counter_overflow_refuses_without_signing_or_writing() {
    let rig = prepared(&[prevote(7, 0, A)]);
    let (mut st, _) = state_now(&rig);
    st.counter = u64::MAX;
    let bytes = st.encode(&B3).unwrap().to_vec();
    rig.set_file(STATE_FILE, bytes.clone());
    rig.set_mirror(Some(bytes));
    let mut s = rig.open().unwrap();
    rig.arm(0, Mode::Error);
    assert_eq!(
        s.sign(&prevote(7, 1, A)),
        Err(SignerError::InvalidRequest("signer sequence exhausted"))
    );
    assert!(rig.disk.borrow().log.is_empty());

    // A mirror at u64::MAX with a fresh state file is a rollback, not a wrap.
    let rig = prepared(&[]);
    let (mut m, _) = state_now(&rig);
    m.counter = u64::MAX;
    m.last = Some(StateLast {
        position: pos(7, 0, Step::Prevote),
        value: VoteValue::Block(A),
        sign_bytes_digest: [3; 32],
        signature: [4; 64],
    });
    m.prev_checksum = [5; 32];
    rig.set_mirror(Some(m.encode(&B3).unwrap().to_vec()));
    assert!(matches!(rig.open(), Err(SignerError::Corrupt(msg)) if msg.contains("behind")));
}

// ── I4 no lost lock ─────────────────────────────────────────────────────────

#[test]
fn i4_a_one_ahead_state_that_loses_or_rewrites_a_lock_is_refused() {
    let lock_a = Lock {
        height: 7,
        round: 0,
        value: A,
    };
    let cases: Vec<(&str, Box<MutateDyn>)> = vec![
        ("dropped within its height", Box::new(|f| f.lock = None)),
        (
            "changed without its precommit",
            Box::new(|f| {
                f.lock = Some(Lock {
                    height: 7,
                    round: 0,
                    value: B,
                })
            }),
        ),
    ];
    for (what, mutate) in cases {
        let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
        let (m, m_sum) = state_now(&rig);
        assert_eq!(m.lock, Some(lock_a));
        let mut f = m.clone();
        f.counter += 1;
        f.prev_checksum = m_sum;
        f.last = Some(StateLast {
            position: pos(7, 1, Step::Prevote),
            value: VoteValue::Nil,
            sign_bytes_digest: [3; 32],
            signature: [4; 64],
        });
        mutate(&mut f);
        rig.set_file(STATE_FILE, f.encode(&B3).unwrap().to_vec());
        let err = rig
            .open()
            .err()
            .unwrap_or_else(|| panic!("{what}: accepted"));
        assert!(matches!(err, SignerError::Corrupt(_)), "{what}: {err}");
    }

    // Locked on (7, 1, A): a relock needs its own precommit at a higher round.
    let rig = prepared(&[prevote(7, 0, A), precommit(7, 1, A)]);
    let (m, m_sum) = state_now(&rig);
    let mut f = m.clone();
    f.counter += 1;
    f.prev_checksum = m_sum;
    f.last = Some(StateLast {
        position: pos(7, 2, Step::Precommit),
        value: VoteValue::Block(B),
        sign_bytes_digest: [3; 32],
        signature: [4; 64],
    });
    f.lock = Some(Lock {
        height: 7,
        round: 2,
        value: B,
    });
    let ok = m.check_successor(&m_sum, &f);
    assert!(ok.is_ok(), "{ok:?}");
    // The same round, another value, after a prevote: no precommit made it.
    f.last = Some(StateLast {
        position: pos(7, 2, Step::Prevote),
        value: VoteValue::Nil,
        sign_bytes_digest: [3; 32],
        signature: [4; 64],
    });
    f.lock = Some(Lock {
        height: 7,
        round: 1,
        value: B,
    });
    assert_eq!(
        m.check_successor(&m_sum, &f),
        Err(StateError::NotSuccessor(
            "the lock changed without a new precommit"
        ))
    );
    // An older round's lock in place of the current one.
    f.lock = Some(Lock {
        height: 7,
        round: 0,
        value: A,
    });
    assert!(m.check_successor(&m_sum, &f).is_err());
}

#[test]
fn i4_the_store_refuses_to_persist_a_transition_that_drops_a_lock() {
    let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
    let mut store = rig.store();
    let rec = store.load().unwrap().unwrap();
    let mut next = rec.clone();
    next.sequence += 1;
    next.lock = None;
    next.last = Some(sumchain_finality_foundations::signer::LastSigned {
        position: pos(7, 1, Step::Prevote),
        value: VoteValue::Nil,
        payload: SignBytes::Full(b"p".to_vec()),
        signature: vec![1; 64],
    });
    let err = store.persist(&next).unwrap_err();
    assert!(
        err.0.contains("dropped without a finality proof"),
        "{}",
        err.0
    );
    assert!(rig.file(TEMP_FILE).is_none(), "nothing written");
}

// ── I5 no conflicting signature across restarts ─────────────────────────────

#[test]
fn i5_after_reopen_only_the_identical_message_is_released_at_a_signed_position() {
    let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
    let mut s = rig.open().unwrap();
    let r = precommit(7, 0, A);
    let sig = s.sign(&r).unwrap();
    verify(&rig, &r.payload, &sig);
    let mut other = r.clone();
    other.payload.push(0);
    assert_eq!(s.sign(&other), Err(SignerError::Equivocation(r.position)));
    let mut nil = req(7, 0, Step::Precommit, VoteValue::Nil, "x");
    nil.payload = r.payload.clone();
    assert_eq!(s.sign(&nil), Err(SignerError::Equivocation(r.position)));
}

// ── I6 canonical absence; I7 record consistency; strict decoding ────────────

#[test]
fn i6_i7_strict_decoding_refuses_each_field_class() {
    let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
    let good = rig.file(STATE_FILE).unwrap();
    let fresh = {
        let r = Rig::new();
        r.init().unwrap();
        r.file(STATE_FILE).unwrap()
    };
    let set = |mut b: Vec<u8>, at: usize, bytes: &[u8]| {
        b[at..at + bytes.len()].copy_from_slice(bytes);
        reseal(b)
    };
    use offset as o;
    let advanced = {
        let r = prepared_acts(&[Act::Sign(prevote(7, 0, A)), Act::Advance(finality(7, &A))]);
        r.file(STATE_FILE).unwrap()
    };
    let cases: Vec<(&'static str, Vec<u8>, Expect)> = vec![
        (
            "checksum",
            {
                let mut b = good.clone();
                b[o::LAST_HEIGHT] ^= 1;
                b
            },
            |e| *e == StateError::Checksum,
        ),
        ("short", good[..STATE_LEN - 1].to_vec(), |e| {
            matches!(e, StateError::Length(412))
        }),
        ("long", [good.clone(), vec![0]].concat(), |e| {
            matches!(e, StateError::Length(414))
        }),
        ("magic", set(good.clone(), 0, b"FSGNv2\0"), |e| {
            *e == StateError::Magic
        }),
        ("schema", set(good.clone(), 7, &2u16.to_le_bytes()), |e| {
            *e == StateError::Schema(2)
        }),
        ("last flag", set(good.clone(), o::LAST_PRESENT, &[2]), |e| {
            matches!(e, StateError::Flag(_))
        }),
        (
            "lock_state 2 (no longer defined)",
            set(good.clone(), o::LOCK_STATE, &[2]),
            |e| matches!(e, StateError::Flag("lock_state")),
        ),
        ("halt flag 2", set(good.clone(), o::HALT, &[2]), |e| {
            matches!(e, StateError::Flag("halt"))
        }),
        (
            "halted at counter 0",
            set(fresh.clone(), o::HALT, &[1]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "halted while locked",
            set(good.clone(), o::HALT, &[1]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "absent last not zero",
            set(fresh.clone(), o::LAST_HEIGHT, &[1]),
            |e| matches!(e, StateError::NonCanonicalAbsent(_)),
        ),
        (
            "absent lock not zero",
            set(fresh.clone(), o::HALT - 1, &[1]),
            |e| matches!(e, StateError::NonCanonicalAbsent(_)),
        ),
        ("step 0", set(good.clone(), o::LAST_STEP, &[0]), |e| {
            *e == StateError::Step(0)
        }),
        ("step 4", set(good.clone(), o::LAST_STEP, &[4]), |e| {
            *e == StateError::Step(4)
        }),
        (
            "last round",
            set(good.clone(), o::LAST_ROUND, &(MAX_ROUND + 1).to_le_bytes()),
            |e| matches!(e, StateError::Round("last", _)),
        ),
        (
            "lock round",
            set(good.clone(), o::LOCK_ROUND, &(MAX_ROUND + 1).to_le_bytes()),
            |e| matches!(e, StateError::Round("lock", _)),
        ),
        (
            "below floor",
            set(good.clone(), o::FLOOR, &8u64.to_le_bytes()),
            |e| matches!(e, StateError::BelowFloor(_)),
        ),
        (
            "above the working height",
            set(good.clone(), o::FLOOR, &6u64.to_le_bytes()),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "certified block at counter 0",
            set(fresh.clone(), o::CERTIFIED, &A),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "certified block without a floor",
            {
                let b = set(advanced.clone(), o::FLOOR, &0u64.to_le_bytes());
                set(b, o::CERTIFIED, &A)
            },
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "neither a signature nor a certified height above counter 0",
            set(advanced.clone(), o::CERTIFIED, &[0; 32]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "counter 0 with a signature",
            set(good.clone(), o::COUNTER, &0u64.to_le_bytes()),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "predecessor zero above counter 0",
            set(good.clone(), o::PREV, &[0; 32]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "predecessor at counter 0",
            set(fresh.clone(), o::PREV, &[1; 32]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "lock without a signature",
            {
                let b = set(fresh.clone(), o::LOCK_STATE, &[1]);
                let b = set(b, o::LOCK_HEIGHT, &7u64.to_le_bytes());
                set(b, o::LOCK_VALUE, &A)
            },
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "lock at another height",
            set(good.clone(), o::LOCK_HEIGHT, &6u64.to_le_bytes()),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "lock above the last signature",
            set(good.clone(), o::LOCK_ROUND, &1u32.to_le_bytes()),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "locking precommit names another value",
            set(good.clone(), o::LOCK_VALUE, &B),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "lock on nil",
            set(good.clone(), o::LOCK_VALUE, &[0; 32]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "nil proposal",
            {
                let b = set(good.clone(), o::LOCK_STATE, &[0; 45]);
                let b = set(b, o::LAST_STEP, &[1]);
                set(b, o::LAST_VALUE, &[0; 32])
            },
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "zero sign-bytes digest",
            set(good.clone(), o::LAST_DIGEST, &[0; 32]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "lock_state 3",
            set(good.clone(), o::LOCK_STATE, &[3]),
            |e| matches!(e, StateError::Flag(_)),
        ),
        (
            "a retained proof without a lock",
            set(advanced.clone(), o::PROOF, &[7; 32]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
        (
            "a proof at counter 0",
            set(fresh.clone(), o::PROOF, &[7; 32]),
            |e| matches!(e, StateError::Inconsistent(_)),
        ),
    ];
    let n = cases.len();
    for (what, bytes, expect) in cases {
        let err = decode(&bytes)
            .err()
            .unwrap_or_else(|| panic!("{what}: accepted"));
        assert!(expect(&err), "{what}: {err}");
        // And the store refuses to open on it.
        let r = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
        r.set_file(STATE_FILE, bytes);
        assert!(matches!(r.open(), Err(SignerError::Corrupt(_))), "{what}");
    }
    assert_eq!(n, 34);
}

// ── I10 identity; missing and corrupt files; ownership; floor ───────────────

#[test]
fn i10_identity_mismatches_are_refused() {
    let rig = prepared(&[prevote(7, 0, A)]);
    let mut other_chain = Rig::new();
    other_chain.disk = rig.disk.clone();
    other_chain.chain = CHAIN + 1;
    assert!(matches!(other_chain.open(), Err(SignerError::Corrupt(m)) if m.contains("chain id")));

    let mut other_genesis = Rig::new();
    other_genesis.disk = rig.disk.clone();
    other_genesis.genesis = [0x22; 32];
    assert!(matches!(other_genesis.open(), Err(SignerError::Corrupt(m)) if m.contains("genesis")));

    let mut other_key = Rig::new();
    other_key.disk = rig.disk.clone();
    other_key.seed = [8u8; 32];
    assert!(matches!(other_key.open(), Err(SignerError::KeyMismatch)));

    // Mirror for another key.
    let (mut m, _) = state_now(&rig);
    m.identity.signer_pubkey = [0x33; 32];
    rig.set_mirror(Some(m.encode(&B3).unwrap().to_vec()));
    assert!(
        matches!(rig.open(), Err(SignerError::Corrupt(msg)) if msg.contains("different identities"))
    );
}

#[test]
fn missing_or_corrupt_files_fail_closed() {
    let rig = prepared(&[prevote(7, 0, A)]);
    rig.remove_file(STATE_FILE);
    assert!(matches!(rig.open(), Err(SignerError::Corrupt(m)) if m.contains("state file missing")));
    assert!(
        matches!(rig.init(), Err(SignerError::Corrupt(_))),
        "init refuses too"
    );

    let rig = prepared(&[prevote(7, 0, A)]);
    let mut m = rig.mirror().unwrap();
    m[200] ^= 1;
    rig.set_mirror(Some(m));
    assert!(
        matches!(rig.open(), Err(SignerError::Corrupt(msg)) if msg.contains("mirror: checksum"))
    );

    let rig = prepared(&[prevote(7, 0, A)]);
    rig.set_file(STATE_FILE, Vec::new());
    assert!(matches!(rig.open(), Err(SignerError::Corrupt(msg)) if msg.contains("length 0")));
}

#[test]
fn interrupted_initialization_is_completed_only_when_pristine() {
    let rig = Rig::new();
    rig.arm(4, Mode::CrashBefore);
    assert!(rig.init().is_err());
    rig.disk.borrow_mut().reboot();
    let mut st = rig.store();
    let rec = st.load().unwrap().unwrap();
    assert_eq!(st.classified(), Some(Classified::CompletedInitialization));
    assert_eq!(rec.sequence, 0);
    assert_eq!(rig.file(STATE_FILE), rig.mirror());
    assert!(matches!(rig.init(), Err(SignerError::AlreadyInitialized)));
}

#[test]
fn leftover_temp_file_is_removed_and_never_trusted() {
    let rig = prepared(&[prevote(7, 0, A)]);
    // A complete, valid, newer state left in the temp file is still ignored.
    let (m, m_sum) = state_now(&rig);
    let mut t = m.clone();
    t.counter += 1;
    t.prev_checksum = m_sum;
    t.last.as_mut().unwrap().position = pos(7, 1, Step::Prevote);
    rig.set_file(TEMP_FILE, t.encode(&B3).unwrap().to_vec());
    let mut st = rig.store();
    let rec = st.load().unwrap().unwrap();
    assert!(st.removed_temp());
    assert_eq!(rec.sequence, 1);
    assert!(rig.file(TEMP_FILE).is_none());
}

#[test]
fn ownership_covers_initialization_and_signing() {
    let rig = Rig::new();
    rig.init().unwrap();
    let s = rig.open().unwrap();
    assert!(matches!(rig.init(), Err(SignerError::OwnershipHeld(_))));
    assert!(matches!(rig.open(), Err(SignerError::OwnershipHeld(_))));
    drop(s);
    assert!(rig.open().is_ok());
}

#[test]
fn floor_height_refuses_lower_heights_and_allows_its_own() {
    let rig = prepared(&[]);
    let mut s = rig.open().unwrap();
    assert!(matches!(
        s.sign(&prevote(6, 0, A)),
        Err(SignerError::Regression { .. })
    ));
    s.sign(&prevote(7, 0, A)).unwrap();
    assert_eq!(state_now(&rig).0.floor_height, FLOOR);
}

#[test]
fn round_trip_and_digest_only_storage() {
    let rig = prepared(&[prevote(7, 0, A), precommit(7, 0, A)]);
    let bytes = rig.file(STATE_FILE).unwrap();
    let (st, sum) = decode(&bytes).unwrap();
    assert_eq!(st.encode(&B3).unwrap().to_vec(), bytes);
    assert_eq!(&bytes[offset::CHECKSUM..], &sum);
    let rec = record_now(&rig);
    let last = rec.last.unwrap();
    assert_eq!(
        last.payload,
        SignBytes::Digest(sign_bytes_digest(&B3, &precommit(7, 0, A).payload))
    );
    assert_eq!(st.identity, rig.identity());
}

// ── the real file system ────────────────────────────────────────────────────

struct FileMirror(std::path::PathBuf);
impl MirrorStore for FileMirror {
    fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        match std::fs::read(&self.0) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(IoError(e.to_string())),
        }
    }
    fn write_synced(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&self.0).map_err(|e| IoError(e.to_string()))?;
        f.write_all(bytes).map_err(|e| IoError(e.to_string()))?;
        f.sync_all().map_err(|e| IoError(e.to_string()))
    }
}

#[cfg(unix)]
#[test]
fn std_directory_round_trip() {
    let base = std::env::temp_dir().join(format!(
        "sumchain-signer-file-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let dir = base.join("finality");
    std::fs::create_dir_all(&dir).unwrap();
    let mirror = base.join("mirror.bin");
    let owner = MemOwnership::default();
    let key = || EdKey(ed25519_dalek::SigningKey::from_bytes(&SEED));
    let store = || {
        FileSignerStore::new(
            StdSignerDir::new(dir.clone()),
            FileMirror(mirror.clone()),
            B3,
            CHAIN,
            GENESIS,
        )
    };
    initialize_exclusive(
        &owner,
        &mut store(),
        key().key_id(),
        floor_below_height(FLOOR),
    )
    .unwrap();
    let r = prevote(7, 0, A);
    let sig = {
        let mut s = DurableSigner::open(&owner, store(), key(), TestPolka, None).unwrap();
        s.sign(&r).unwrap()
    };
    assert_eq!(
        std::fs::read(dir.join(STATE_FILE)).unwrap(),
        std::fs::read(&mirror).unwrap()
    );
    assert!(!dir.join(TEMP_FILE).exists());
    let mut s = DurableSigner::open(&owner, store(), key(), TestPolka, None).unwrap();
    assert_eq!(s.sign(&r).unwrap(), sig);
    drop(s);
    std::fs::remove_dir_all(&base).unwrap();
}

/// A conflict halt and its recovery through a real directory: the halt byte
/// on disk in both copies, the retained evidence, the archive with its
/// receipt and no temp files left, the evidence file removed at the next
/// open, signing above the resume height, and initialization refused while
/// the archive exists.
#[cfg(unix)]
#[test]
fn std_directory_conflict_halt_and_recovery() {
    let base = std::env::temp_dir().join(format!(
        "sumchain-signer-recovery-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let dir = base.join("finality");
    std::fs::create_dir_all(&dir).unwrap();
    let mirror = base.join("mirror.bin");
    let owner = MemOwnership::default();
    let key = || EdKey(ed25519_dalek::SigningKey::from_bytes(&SEED));
    let store = || {
        FileSignerStore::new(
            StdSignerDir::new(dir.clone()),
            FileMirror(mirror.clone()),
            B3,
            CHAIN,
            GENESIS,
        )
    };
    let open = || DurableSigner::open(&owner, store(), key(), RetainingPolka, None);
    initialize_exclusive(
        &owner,
        &mut store(),
        key().key_id(),
        floor_below_height(FLOOR),
    )
    .unwrap();
    {
        let mut s = open().unwrap();
        s.sign(&prevote(7, 0, A)).unwrap();
        s.advance(&finality(7, &A)).unwrap();
        s.sign(&prevote(8, 0, A)).unwrap();
        assert_eq!(
            s.advance(&finality(7, &B)),
            Err(SignerError::ConflictingFinality(7))
        );
    }
    let state = std::fs::read(dir.join(STATE_FILE)).unwrap();
    assert_eq!(state.len(), STATE_LEN);
    assert_eq!(
        (state[offset::HALT], state[offset::LOCK_STATE]),
        (HALT_SET, 0)
    );
    assert_eq!(
        std::fs::read(&mirror).unwrap(),
        state,
        "the halt is in both copies"
    );
    let (halted, _) = SignerState::decode(&state, &B3).unwrap();
    let evidence = dir.join(proof_file_name(&halted.proof_digest));
    assert_eq!(std::fs::read(&evidence).unwrap(), finality(7, &B));

    let mut s = open().unwrap();
    assert!(s.is_halted());
    assert_eq!(s.sign(&prevote(8, 1, A)), Err(SignerError::Halted));
    assert_eq!(
        s.recover_after_conflict(&ChainPoint(9, A), &finality(9, &A), None),
        Ok(Certified {
            height: 9,
            block_id: A
        })
    );
    drop(s);
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    for suffix in ["state", "evidence", "resume", "receipt"] {
        assert!(names.contains(&conflict_file_name(7, suffix)), "{suffix}");
    }
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "{names:?}");
    let receipt = RecoveryReceipt::decode(
        &std::fs::read(dir.join(conflict_file_name(7, "receipt"))).unwrap(),
        &B3,
    )
    .unwrap();
    assert_eq!(
        (
            receipt.conflict_height,
            receipt.resume_height,
            receipt.resume_block
        ),
        (7, 9, A)
    );
    assert_eq!(
        std::fs::read(dir.join(conflict_file_name(7, "state"))).unwrap(),
        state,
        "the archived record is the halted one"
    );

    let mut s = open().unwrap();
    assert!(!s.is_halted());
    assert!(
        !evidence.exists(),
        "the unreferenced evidence file is removed at open"
    );
    assert_eq!(s.record().working_height(), Some(10));
    assert!(matches!(
        s.sign(&prevote(9, 0, A)),
        Err(SignerError::Regression { .. })
    ));
    s.sign(&prevote(10, 0, A)).unwrap();
    drop(s);
    assert_eq!(
        std::fs::read(dir.join(STATE_FILE)).unwrap(),
        std::fs::read(&mirror).unwrap()
    );

    std::fs::remove_file(dir.join(STATE_FILE)).unwrap();
    std::fs::remove_file(&mirror).unwrap();
    assert!(matches!(
        initialize_exclusive(
            &owner,
            &mut store(),
            key().key_id(),
            floor_below_height(FLOOR)
        ),
        Err(SignerError::Corrupt(_))
    ));
    std::fs::remove_dir_all(&base).unwrap();
}

/// Requests outside the ratified V ranges are refused before anything else:
/// nothing is written and the signer stays usable. Without the round bound,
/// a round above 2^20 at a closed height would sit above the whole-height
/// floor `(H, 2^20, precommit)`.
#[test]
fn requests_outside_the_v_ranges_are_refused_without_writing() {
    let rig = prepared(&[prevote(7, 0, A)]);
    let mut s = rig.open().unwrap();
    s.advance(&finality(7, &A)).unwrap();
    rig.arm(usize::MAX, Mode::Error);
    for (q, why) in [
        (
            req(7, MAX_ROUND + 1, Step::Prevote, VoteValue::Block(A), "x"),
            "a round above the maximum",
        ),
        (
            req(8, MAX_ROUND + 1, Step::Prevote, VoteValue::Block(A), "x"),
            "a round above the maximum",
        ),
        (
            req(8, 0, Step::Prevote, VoteValue::Block([0; 32]), "x"),
            "a zero block id",
        ),
    ] {
        assert_eq!(s.sign(&q), Err(SignerError::InvalidRequest(why)));
    }
    assert_eq!(rig.disk.borrow().ops, 0, "nothing written");
    s.sign(&prevote(8, 0, A)).expect("not poisoned");
}

/// Initialized without a floor, the working height is the first signed
/// one. A one-ahead "advancement" whose floor does not close that height is
/// not an exact successor: the repair refuses it.
#[test]
fn a_one_ahead_advancement_must_close_every_signed_height() {
    let rig = Rig::new();
    initialize_exclusive(&rig.owner, &mut rig.store(), rig.pubkey(), None).unwrap();
    rig.open().unwrap().sign(&prevote(7, 0, A)).unwrap();
    let (m_state, m_sum) = state_now(&rig);
    assert_eq!(m_state.floor_height, 0);
    let advanced = |floor_height: u64| {
        let mut f = m_state.clone();
        f.counter += 1;
        f.prev_checksum = m_sum;
        f.floor_height = floor_height;
        f.certified_block_id = B;
        f.last = None;
        f.encode(&B3).unwrap().to_vec()
    };
    for floor_height in [3u64, 7] {
        rig.set_file(STATE_FILE, advanced(floor_height));
        assert!(
            matches!(rig.open(), Err(SignerError::Corrupt(m)) if m.contains("above the last signed height")),
            "floor height {floor_height}"
        );
    }
    rig.set_file(STATE_FILE, advanced(8));
    let s = rig.open().unwrap();
    assert_eq!(s.store().classified(), Some(Classified::AdvancedMirror));
    assert_eq!(s.record().working_height(), Some(8));
}

/// The store writes an initial record only after a load that found no
/// state: never over existing state, and never after a failed load.
#[test]
fn initialization_needs_a_load_that_found_nothing() {
    let rig = prepared(&[prevote(7, 0, A)]);
    let before = (rig.file(STATE_FILE), rig.mirror());
    let record = SignerRecord {
        key_id: rig.pubkey(),
        sequence: 0,
        floor: floor_below_height(FLOOR),
        last: None,
        lock: None,
        certified: None,
        lock_proof: None,
        halt: None,
    };
    let mut st = rig.store();
    assert!(st.persist(&record).is_err(), "no load");
    rig.set_mirror(Some(vec![0; 7]));
    assert!(st.load().is_err());
    assert!(st.persist(&record).is_err(), "a failed load");
    rig.set_mirror(before.1.clone());
    assert_eq!(
        (rig.file(STATE_FILE), rig.mirror()),
        before,
        "nothing overwritten"
    );
}

/// A directory holding an earlier signer's conflict archive or retained
/// proofs is never initialized over, and an interrupted initialization never
/// completes beside them: the halt or its evidence would be lost.
#[test]
fn initialization_never_runs_over_an_earlier_signers_files() {
    for name in [
        proof_file_name(&[0x11; 32]),
        "proof.tmp".to_string(),
        conflict_file_name(7, "receipt"),
        conflict_file_name(7, "state.tmp"),
    ] {
        let rig = Rig::new();
        rig.set_file(&name, b"x".to_vec());
        assert!(
            matches!(rig.init(), Err(SignerError::Corrupt(m)) if m.contains("earlier signer")),
            "{name}"
        );
        assert_eq!(rig.file(&name), Some(b"x".to_vec()), "{name} is kept");
        assert_eq!(rig.file(STATE_FILE), None);

        let rig = Rig::new();
        rig.init().unwrap();
        rig.set_mirror(None);
        rig.set_file(&name, b"x".to_vec());
        assert!(
            matches!(rig.open(), Err(SignerError::Corrupt(m)) if m.contains("earlier signer")),
            "R0 beside {name}"
        );
        assert_eq!(rig.mirror(), None, "R0 did not complete");
    }
}

/// The two-conflict sequence on a real directory: both completed archives
/// and receipts are on disk after the second recovery, the first is
/// byte-identical to what the first recovery wrote, and orphan proof files
/// are removed at open without touching either archive.
#[cfg(unix)]
#[test]
fn std_directory_two_conflicts_keep_both_archives() {
    let base = std::env::temp_dir().join(format!(
        "sumchain-signer-two-conflicts-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let dir = base.join("finality");
    std::fs::create_dir_all(&dir).unwrap();
    let mirror = base.join("mirror.bin");
    let owner = MemOwnership::default();
    let key = || EdKey(ed25519_dalek::SigningKey::from_bytes(&SEED));
    let store = || {
        FileSignerStore::new(
            StdSignerDir::new(dir.clone()),
            FileMirror(mirror.clone()),
            B3,
            CHAIN,
            GENESIS,
        )
    };
    let open = || DurableSigner::open(&owner, store(), key(), RetainingPolka, None);
    let read = |name: String| std::fs::read(dir.join(name)).unwrap();
    let archive =
        |h: u64| ["state", "evidence", "resume", "receipt"].map(|x| read(conflict_file_name(h, x)));
    initialize_exclusive(
        &owner,
        &mut store(),
        key().key_id(),
        floor_below_height(FLOOR),
    )
    .unwrap();
    {
        let mut s = open().unwrap();
        s.sign(&prevote(7, 0, A)).unwrap();
        s.advance(&finality(7, &A)).unwrap();
        assert_eq!(
            s.advance(&finality(7, &B)),
            Err(SignerError::ConflictingFinality(7))
        );
        s.recover_after_conflict(&ChainPoint(9, A), &finality(9, &A), None)
            .unwrap();
        s.sign(&prevote(10, 0, A)).unwrap();
    }
    let first = archive(7);
    {
        let mut s = open().unwrap();
        assert_eq!(
            s.advance(&finality(9, &B)),
            Err(SignerError::ConflictingFinality(9))
        );
        s.recover_after_conflict(&ChainPoint(11, A), &finality(11, &A), None)
            .unwrap();
    }
    std::fs::write(dir.join(proof_file_name(&[0x77; 32])), b"orphan").unwrap();
    std::fs::write(dir.join("proof.tmp"), b"orphan").unwrap();
    let mut s = open().unwrap();
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(!names.iter().any(|n| n.starts_with("proof")), "{names:?}");
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "{names:?}");
    assert_eq!(archive(7), first, "the first archive is byte-identical");
    let second = archive(9);
    for (receipt, want) in [(&first[3], (7, 9)), (&second[3], (9, 11))] {
        let r = RecoveryReceipt::decode(receipt, &B3).unwrap();
        assert_eq!((r.conflict_height, r.resume_height), want);
    }
    assert_eq!(second[1], finality(9, &B));
    s.sign(&prevote(12, 0, A)).unwrap();
    drop(s);
    std::fs::remove_dir_all(&base).unwrap();
}

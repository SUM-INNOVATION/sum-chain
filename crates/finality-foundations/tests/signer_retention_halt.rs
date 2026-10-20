//! The retained lock proof and the persisted conflict halt (semantics
//! RATIFIED 2026-10-20; the 413-byte layout, the side files and the conflict
//! archive UNRATIFIED),
//! over the file-backed store and the disk model in `common`.
//!
//! * KAT vectors for the 413-byte `SignerStateV1` proposal (separate halt flag).
//! * Crash matrices across the proof, state and mirror writes for a first
//!   lock, a relock, a lock-keeping prevote, an advancement and a halt.
//! * Orphan, missing and corrupt proof files; a forged justification.
//! * The halt across crashes; the operator's recovery with verified evidence,
//!   with a fault at each of its writes, and its refusals.
//!
//! Keys, payloads and proofs are synthetic.

use std::rc::Rc;

use ed25519_dalek::Signer as _;
use serde_json::{json, Value};
use sumchain_finality_foundations::signer::{
    initialize_exclusive, Certified, DurableSigner, Justification, Lock, SignPosition, SignRequest,
    SignerError, SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{
    floor_below_height, offset, proof_digest, proof_file_name, FileSignerStore, ProofStatus,
    SignerState, HALT_SET, MAX_RETAINED_PROOF_LEN, STATE_FILE, STATE_LEN,
};
use sumchain_finality_foundations::Digest;

mod common;
use common::*;

const CHAIN: u64 = 4242;
const GENESIS: Digest = [0x11; 32];
const SEED: [u8; 32] = [7u8; 32];
const A: Digest = [0xA1; 32];
const B: Digest = [0xB2; 32];

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
type Signer = DurableSigner<Store, EdKey, RetainingPolka, MemGuard>;

struct Rig {
    disk: Disk,
    owner: MemOwnership,
}

impl Rig {
    fn new() -> Rig {
        let rig = Rig {
            disk: Rc::default(),
            owner: MemOwnership::default(),
        };
        initialize_exclusive(
            &rig.owner,
            &mut rig.store(),
            rig.key().key_id(),
            floor_below_height(7),
        )
        .unwrap();
        rig
    }
    fn store(&self) -> Store {
        FileSignerStore::new(
            SimDir(self.disk.clone()),
            SimMirror(self.disk.clone()),
            B3,
            CHAIN,
            GENESIS,
        )
    }
    fn key(&self) -> EdKey {
        EdKey(ed25519_dalek::SigningKey::from_bytes(&SEED))
    }
    fn open(&self) -> Result<Signer, SignerError> {
        DurableSigner::open(&self.owner, self.store(), self.key(), RetainingPolka, None)
    }
    fn arm(&self, n: usize, mode: Mode) {
        let mut m = self.disk.borrow_mut();
        m.ops = 0;
        m.log.clear();
        m.plan = Some((n, mode));
    }
    fn ops(&self) -> usize {
        self.disk.borrow().ops
    }
    fn recover(&self, mode: Mode) {
        match mode {
            Mode::Error | Mode::EffectThenError => self.disk.borrow_mut().restart(),
            _ => self.disk.borrow_mut().reboot(),
        }
    }
    fn files(&self) -> Vec<String> {
        self.disk.borrow().dir_vol.keys().cloned().collect()
    }
    fn proof_files(&self) -> Vec<String> {
        self.files()
            .into_iter()
            .filter(|n| n.starts_with("proof"))
            .collect()
    }
    fn file(&self, name: &str) -> Option<Vec<u8>> {
        let m = self.disk.borrow();
        m.dir_vol.get(name).map(|&i| m.inodes[i].vol.clone())
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
}

fn pos(h: u64, r: u32, step: Step) -> SignPosition {
    SignPosition {
        height: h,
        round: r,
        step,
    }
}

fn req(h: u64, r: u32, step: Step, value: VoteValue, tag: &str) -> SignRequest {
    SignRequest {
        position: pos(h, r, step),
        value,
        payload: format!("{h}/{r}/{step:?}/{value:?}/{tag}").into_bytes(),
        justification: None,
    }
}

fn prevote(h: u64, r: u32, v: Digest) -> SignRequest {
    req(h, r, Step::Prevote, VoteValue::Block(v), "x")
}

fn precommit(h: u64, r: u32, v: Digest) -> SignRequest {
    let mut q = req(h, r, Step::Precommit, VoteValue::Block(v), "x");
    q.justification = Some(Justification {
        polka_round: r,
        evidence: polka_evidence(h, r, &v),
    });
    q
}

#[derive(Clone)]
enum Act {
    Sign(SignRequest),
    Advance(Vec<u8>),
}

fn run(s: &mut Signer, a: &Act) -> Result<(), SignerError> {
    match a {
        Act::Sign(q) => s.sign(q).map(|_| ()),
        Act::Advance(p) => s.advance(p).map(|_| ()),
    }
}

fn prepared(acts: &[Act]) -> Rig {
    let rig = Rig::new();
    let mut s = rig.open().unwrap();
    for a in acts {
        run(&mut s, a).unwrap();
    }
    rig
}

fn state_bytes(rig: &Rig) -> Vec<u8> {
    rig.file(STATE_FILE).unwrap()
}

fn decoded(rig: &Rig) -> SignerState {
    SignerState::decode(&state_bytes(rig), &B3).unwrap().0
}

/// After a successful open: the referenced proof is present (never degraded
/// by a crash) and it is the only proof file.
fn assert_proofs_settled(rig: &Rig, s: &Signer, ctx: &str) {
    let st = decoded(rig);
    let expected: Vec<String> = if st.proof_digest == [0; 32] {
        vec![]
    } else {
        vec![proof_file_name(&st.proof_digest)]
    };
    assert_eq!(rig.proof_files(), expected, "{ctx}: proof files");
    let want = if st.proof_digest == [0; 32] {
        ProofStatus::NotReferenced
    } else {
        ProofStatus::Present
    };
    assert_eq!(s.store().proof_status(), want, "{ctx}: proof status");
}

// ── KAT vectors: the 413-byte proposal ──────────────────────────────────────

const STATE_VECTORS: &str = include_str!("vectors/signer_state_413.json");

fn kat_states() -> Vec<(&'static str, Vec<Act>)> {
    vec![
        ("initialized, working height 7", vec![]),
        (
            "locked at (7, 0) on A, proof retained",
            vec![Act::Sign(prevote(7, 0, A)), Act::Sign(precommit(7, 0, A))],
        ),
        (
            "advanced: height 7 certified with A, working height 8",
            vec![
                Act::Sign(prevote(7, 0, A)),
                Act::Sign(precommit(7, 0, A)),
                Act::Advance(finality(7, &A)),
            ],
        ),
        (
            "halted: height 7 certified with A, conflicting proof names B",
            vec![
                Act::Sign(prevote(7, 0, A)),
                Act::Sign(precommit(7, 0, A)),
                Act::Advance(finality(7, &A)),
                Act::Advance(finality(7, &B)),
            ],
        ),
    ]
}

fn state_kat_json() -> Value {
    let vectors: Vec<Value> = kat_states()
        .into_iter()
        .map(|(name, acts)| {
            let rig = Rig::new();
            let mut s = rig.open().unwrap();
            for a in &acts {
                let _ = run(&mut s, a);
            }
            let bytes = state_bytes(&rig);
            let st = decoded(&rig);
            let proof = (st.proof_digest != [0; 32])
                .then(|| hex::encode(rig.file(&proof_file_name(&st.proof_digest)).unwrap()));
            json!({
                "name": name,
                "length": bytes.len(),
                "hex": hex::encode(&bytes),
                "proof_file": st.proof_digest.ne(&[0; 32]).then(|| proof_file_name(&st.proof_digest)),
                "proof_hex": proof,
            })
        })
        .collect();
    json!({
        "title": "SignerStateV1 413-byte proposal (separate halt flag): known-answer vectors",
        "status": "UNRATIFIED PROPOSAL. SYNTHETIC: test Ed25519 seed [0x07;32]; chain id 4242; genesis 11…; synthetic payloads and proofs; hash BLAKE3-256.",
        "vectors": vectors,
    })
}

/// Regenerate: `SUMCHAIN_WRITE_SIGNER_STATE_VECTORS=1 cargo test ...`.
#[test]
fn signer_state_413_kat_vectors_match_and_decode() {
    let generated = state_kat_json();
    if std::env::var_os("SUMCHAIN_WRITE_SIGNER_STATE_VECTORS").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/signer_state_413.json"
        );
        std::fs::write(
            path,
            serde_json::to_string_pretty(&generated).unwrap() + "\n",
        )
        .unwrap();
    }
    let committed: Value = serde_json::from_str(STATE_VECTORS).expect("vectors are JSON");
    assert_eq!(
        committed, generated,
        "the committed vectors are what the code produces"
    );
    for v in committed["vectors"].as_array().unwrap() {
        let bytes = hex::decode(v["hex"].as_str().unwrap()).unwrap();
        assert_eq!(bytes.len(), STATE_LEN);
        let (st, _) = SignerState::decode(&bytes, &B3).unwrap();
        assert_eq!(st.encode(&B3).unwrap().to_vec(), bytes, "canonical");
        if let Some(p) = v["proof_hex"].as_str() {
            assert_eq!(proof_digest(&B3, &hex::decode(p).unwrap()), st.proof_digest);
        }
    }
    let halted = hex::decode(committed["vectors"][3]["hex"].as_str().unwrap()).unwrap();
    assert_eq!(halted[offset::HALT], HALT_SET);
    assert_eq!(halted[offset::LOCK_STATE], 0, "lock_state is 0 or 1 only");
    assert_eq!(MAX_RETAINED_PROOF_LEN, 2_883_725);
}

// ── crash matrices across proof, state and mirror writes ────────────────────

struct Transition {
    name: &'static str,
    setup: Vec<Act>,
    action: Act,
}

fn transitions() -> Vec<Transition> {
    let locked = vec![Act::Sign(prevote(7, 0, A)), Act::Sign(precommit(7, 0, A))];
    vec![
        Transition {
            name: "first lock (P0 writes its proof)",
            setup: vec![Act::Sign(prevote(7, 0, A))],
            action: Act::Sign(precommit(7, 0, A)),
        },
        Transition {
            name: "relock (a new proof; the old one becomes an orphan)",
            setup: locked.clone(),
            action: Act::Sign(precommit(7, 1, B)),
        },
        Transition {
            name: "prevote keeping the lock (the proof is carried)",
            setup: locked.clone(),
            action: Act::Sign(prevote(7, 1, A)),
        },
        Transition {
            name: "advancement (the lock and its proof are discarded)",
            setup: locked.clone(),
            action: Act::Advance(finality(7, &A)),
        },
        Transition {
            name: "halt (P0 writes the evidence)",
            setup: [locked, vec![Act::Advance(finality(7, &A))]].concat(),
            action: Act::Advance(finality(7, &B)),
        },
    ]
}

#[test]
fn crash_matrix_across_proof_state_and_mirror_writes() {
    let mut cases = 0;
    for t in transitions() {
        // The fault-free run: its write count and its outcome.
        let rig = prepared(&t.setup);
        let before = decoded(&rig);
        let mut s = rig.open().unwrap();
        rig.arm(usize::MAX, Mode::Error);
        let ok = run(&mut s, &t.action);
        let writes = rig.ops();
        drop(s);
        let after = decoded(&rig);
        let halt = matches!(t.action, Act::Advance(ref p) if p == &finality(7, &B));
        assert!(
            ok.is_ok() || (halt && ok == Err(SignerError::ConflictingFinality(7))),
            "{}: {ok:?}",
            t.name
        );
        assert!(writes >= 5, "{}", t.name);

        for k in 0..writes {
            for mode in MODES {
                let ctx = format!("{} / write {k} / {mode:?}", t.name);
                let rig = prepared(&t.setup);
                let mut s = rig.open().unwrap();
                rig.arm(k, mode);
                let res = run(&mut s, &t.action);
                assert!(
                    res.is_err(),
                    "{ctx}: nothing is released when a write fails"
                );
                drop(s);
                rig.recover(mode);

                let s = rig
                    .open()
                    .unwrap_or_else(|e| panic!("{ctx}: reopen refused: {e}"));
                let now = decoded(&rig);
                assert!(
                    now == before || now == after,
                    "{ctx}: neither the old nor the new state"
                );
                assert_proofs_settled(&rig, &s, &ctx);
                if halt {
                    assert_eq!(s.is_halted(), now == after, "{ctx}");
                }
                drop(s);
                // A later power loss changes nothing.
                rig.disk.borrow_mut().reboot();
                let s = rig
                    .open()
                    .unwrap_or_else(|e| panic!("{ctx}: refused after power loss: {e}"));
                assert_eq!(decoded(&rig), now, "{ctx}");
                assert_proofs_settled(&rig, &s, &ctx);
                cases += 1;
            }
        }
    }
    assert!(cases >= 5 * 5 * 5, "{cases}");
}

// ── proof files: orphans, missing, corrupt, forged ──────────────────────────

#[test]
fn orphan_proof_files_are_removed_at_open() {
    let rig = prepared(&[Act::Sign(prevote(7, 0, A)), Act::Sign(precommit(7, 0, A))]);
    let referenced = proof_file_name(&decoded(&rig).proof_digest);
    rig.set_file("proof.tmp", b"partial".to_vec());
    rig.set_file(&proof_file_name(&[9; 32]), b"stale".to_vec());
    let s = rig.open().unwrap();
    assert_eq!(rig.proof_files(), vec![referenced]);
    assert_eq!(s.store().removed_orphans().len(), 2);
    assert_eq!(s.store().proof_status(), ProofStatus::Present);
}

#[test]
fn missing_or_corrupt_proof_opens_degraded_and_keeps_the_lock() {
    for corrupt in [false, true] {
        let rig = prepared(&[Act::Sign(prevote(7, 0, A)), Act::Sign(precommit(7, 0, A))]);
        let name = proof_file_name(&decoded(&rig).proof_digest);
        if corrupt {
            let mut b = rig.file(&name).unwrap();
            b[0] ^= 1;
            rig.set_file(&name, b);
        } else {
            rig.remove_file(&name);
        }
        let mut s = rig.open().unwrap();
        let want = if corrupt {
            ProofStatus::Corrupt
        } else {
            ProofStatus::Missing
        };
        assert_eq!(s.store().proof_status(), want);
        assert_eq!(
            rig.file(&name).is_some(),
            corrupt,
            "a corrupt proof is kept as found"
        );
        // The lock is still enforced from the state.
        assert!(matches!(
            s.sign(&prevote(7, 1, B)),
            Err(SignerError::LockedOnOtherValue(_))
        ));
        // A relock with a verified quorum retains a new proof.
        s.sign(&precommit(7, 1, B)).unwrap();
        drop(s);
        let s = rig.open().unwrap();
        assert_eq!(s.store().proof_status(), ProofStatus::Present);
        assert_proofs_settled(&rig, &s, "after relock");
    }
}

#[test]
fn nothing_is_released_on_a_justification_that_fails_verification() {
    let rig = prepared(&[Act::Sign(prevote(7, 0, A))]);
    let mut s = rig.open().unwrap();
    rig.arm(usize::MAX, Mode::Error);
    let mut forged = precommit(7, 0, A);
    forged.justification.as_mut().unwrap().evidence.push(0);
    assert!(matches!(
        s.sign(&forged),
        Err(SignerError::InvalidJustification(_))
    ));
    assert_eq!(rig.ops(), 0, "nothing written");
    assert!(rig.proof_files().is_empty());
}

// ── the halt ────────────────────────────────────────────────────────────────

#[test]
fn halt_is_persisted_first_and_survives_every_crash_and_restart() {
    let rig = prepared(&[
        Act::Sign(prevote(7, 0, A)),
        Act::Sign(precommit(7, 0, A)),
        Act::Advance(finality(7, &A)),
        Act::Sign(prevote(8, 0, B)),
    ]);
    let mut s = rig.open().unwrap();
    assert_eq!(
        s.advance(&finality(7, &B)),
        Err(SignerError::ConflictingFinality(7))
    );
    let st = decoded(&rig);
    assert!(st.halted);
    assert_eq!(
        (st.floor_height, st.certified_block_id, st.lock),
        (8, A, None)
    );
    assert_eq!(
        st.last.as_ref().map(|l| l.position),
        Some(pos(8, 0, Step::Prevote)),
        "last kept as evidence"
    );
    assert_eq!(
        rig.file(&proof_file_name(&st.proof_digest)),
        Some(finality(7, &B)),
        "evidence kept"
    );
    for i in 0..3 {
        drop(s);
        if i % 2 == 0 {
            rig.disk.borrow_mut().reboot();
        } else {
            rig.disk.borrow_mut().restart();
        }
        s = rig.open().unwrap();
        assert!(s.is_halted());
        assert_eq!(s.sign(&prevote(8, 1, B)), Err(SignerError::Halted));
        assert_eq!(
            s.sign(&prevote(8, 0, B)),
            Err(SignerError::Halted),
            "not even an identical re-release"
        );
        assert_eq!(s.advance(&finality(8, &A)), Err(SignerError::Halted));
    }
    // The halt cannot be removed by deleting one copy: either copy alone
    // refuses to open.
    drop(s);
    let mirror = rig.disk.borrow().mirror_vol.clone();
    rig.disk.borrow_mut().mirror_vol = None;
    rig.disk.borrow_mut().mirror_dur = None;
    assert!(matches!(rig.open(), Err(SignerError::Corrupt(_))));
    rig.disk.borrow_mut().mirror_vol = mirror.clone();
    rig.disk.borrow_mut().mirror_dur = mirror;
    assert!(rig.open().unwrap().is_halted());
}

/// (what, followed, resume certificate, supplied evidence).
type RecoveryCase = (&'static str, Certified, Vec<u8>, Option<Vec<u8>>);

fn at(height: u64, block_id: Digest) -> Certified {
    Certified { height, block_id }
}

fn halted_rig() -> Rig {
    let rig = prepared(&[
        Act::Sign(prevote(7, 0, A)),
        Act::Sign(precommit(7, 0, A)),
        Act::Advance(finality(7, &A)),
        Act::Sign(prevote(8, 0, B)),
    ]);
    let mut s = rig.open().unwrap();
    assert_eq!(
        s.advance(&finality(7, &B)),
        Err(SignerError::ConflictingFinality(7))
    );
    rig
}

/// The conflict was at height 7 (certified A, conflicting B); the halted
/// working height is 8, where the key signed a prevote.
fn conflict_files(rig: &Rig) -> Vec<String> {
    rig.files()
        .into_iter()
        .filter(|n| n.starts_with("conflict-"))
        .collect()
}

#[test]
fn recovery_needs_verified_evidence_at_or_above_the_halted_height() {
    let rig = halted_rig();
    let mut s = rig.open().unwrap();
    // Never automatic: an advancement does not recover.
    assert_eq!(s.advance(&finality(9, &A)), Err(SignerError::Halted));
    rig.arm(usize::MAX, Mode::Error);
    // Refused without writing anything.
    let refused: Vec<RecoveryCase> = vec![
        (
            "forged resume certificate",
            at(9, A),
            b"forged".to_vec(),
            None,
        ),
        (
            "resume at the conflict height",
            at(7, A),
            finality(7, &A),
            None,
        ),
        ("resume at a lower height", at(5, A), finality(5, &A), None),
        ("the other fork's block", at(9, A), finality(9, &B), None),
        (
            "another height than the followed one",
            at(10, A),
            finality(9, &A),
            None,
        ),
        (
            "evidence naming the certified block",
            at(9, A),
            finality(9, &A),
            Some(finality(7, &A)),
        ),
        (
            "evidence for another height",
            at(9, A),
            finality(9, &A),
            Some(finality(6, &B)),
        ),
        (
            "forged evidence",
            at(9, A),
            finality(9, &A),
            Some(b"forged".to_vec()),
        ),
    ];
    for (what, followed, resume, evidence) in refused {
        let r = s.recover_after_conflict(followed, &resume, evidence.as_deref());
        assert!(r.is_err(), "{what}: {r:?}");
        assert!(s.is_halted(), "{what}");
        assert_eq!(rig.ops(), 0, "{what}: nothing written");
    }
    assert!(matches!(
        s.recover_after_conflict(at(7, A), &finality(7, &A), None),
        Err(SignerError::RecoveryTooLow {
            resume: 7,
            working: 8
        })
    ));
    assert!(matches!(
        s.recover_after_conflict(at(9, A), &finality(9, &B), None),
        Err(SignerError::RecoveryWrongFork { .. })
    ));
    // A verified certificate at or above the halted working height recovers.
    assert_eq!(
        s.recover_after_conflict(at(9, A), &finality(9, &A), None)
            .unwrap(),
        Certified {
            height: 9,
            block_id: A
        }
    );
    assert!(!s.is_halted());
    assert_eq!(s.record().working_height(), Some(10));
    for (h, r) in [(8, 1), (9, 0)] {
        assert!(
            matches!(
                s.sign(&prevote(h, r, A)),
                Err(SignerError::Regression { .. })
            ),
            "height {h} is closed"
        );
    }
    s.sign(&prevote(10, 0, A)).unwrap();
    drop(s);
    let s = rig.open().unwrap();
    assert_eq!(
        conflict_files(&rig),
        vec![
            "conflict-7.evidence".to_string(),
            "conflict-7.receipt".to_string(),
            "conflict-7.resume".to_string(),
            "conflict-7.state".to_string(),
        ],
        "the conflict archive is retained"
    );
    assert_eq!(rig.file("conflict-7.evidence"), Some(finality(7, &B)));
    assert_proofs_settled(&rig, &s, "after recovery");
    // A state that is not halted has nothing to recover from.
    let other = prepared(&[Act::Sign(prevote(7, 0, A))]);
    let mut o = other.open().unwrap();
    assert_eq!(
        o.recover_after_conflict(at(9, A), &finality(9, &A), None),
        Err(SignerError::NotHalted)
    );
}

#[test]
fn recovery_without_retained_evidence_needs_it_supplied() {
    let rig = halted_rig();
    let evidence_file = proof_file_name(&decoded(&rig).proof_digest);
    rig.remove_file(&evidence_file);
    let mut s = rig.open().unwrap();
    assert_eq!(
        s.store().proof_status(),
        ProofStatus::Missing,
        "degraded, still halted"
    );
    assert!(s.is_halted());
    assert!(matches!(
        s.recover_after_conflict(at(9, A), &finality(9, &A), None),
        Err(SignerError::RecoveryArchive(m)) if m.contains("supply it")
    ));
    assert!(s.is_halted());
    s.recover_after_conflict(at(9, A), &finality(9, &A), Some(&finality(7, &B)))
        .unwrap();
    assert_eq!(rig.file("conflict-7.evidence"), Some(finality(7, &B)));
}

#[test]
fn a_recovered_state_without_its_archive_is_refused() {
    let rig = halted_rig();
    let mut s = rig.open().unwrap();
    // Fail the mirror write: the recovered state file is one ahead of the
    // halted mirror.
    let writes_before_mirror = {
        let probe = halted_rig();
        let mut p = probe.open().unwrap();
        probe.arm(usize::MAX, Mode::Error);
        p.recover_after_conflict(at(9, A), &finality(9, &A), None)
            .unwrap();
        probe.ops()
    };
    rig.arm(writes_before_mirror - 1, Mode::Error);
    assert!(s
        .recover_after_conflict(at(9, A), &finality(9, &A), None)
        .is_err());
    drop(s);
    rig.disk.borrow_mut().restart();
    // With the archive, the repair completes.
    let probe_receipt = rig.file("conflict-7.receipt").unwrap();
    rig.remove_file("conflict-7.receipt");
    assert!(
        matches!(rig.open(), Err(SignerError::Corrupt(m)) if m.contains("recovery archive")),
        "no receipt, no recovery"
    );
    rig.set_file("conflict-7.receipt", probe_receipt);
    let s = rig.open().unwrap();
    assert!(!s.is_halted());
    assert_eq!(s.record().working_height(), Some(10));
}

#[test]
fn initialization_refuses_while_a_conflict_archive_exists() {
    let rig = halted_rig();
    let key = rig.key().key_id();
    let mut s = rig.open().unwrap();
    s.recover_after_conflict(at(9, A), &finality(9, &A), None)
        .unwrap();
    drop(s);
    // Wipe the state and the mirror: initializing now could choose any floor,
    // clearing the conflict's history without evidence.
    rig.remove_file(STATE_FILE);
    rig.disk.borrow_mut().mirror_vol = None;
    rig.disk.borrow_mut().mirror_dur = None;
    assert!(matches!(
        initialize_exclusive(&rig.owner, &mut rig.store(), key, floor_below_height(5)),
        Err(SignerError::Corrupt(_))
    ));
}

#[test]
fn crash_matrix_for_recovery_after_a_conflict() {
    let rig = halted_rig();
    let halted = decoded(&rig);
    let mut s = rig.open().unwrap();
    rig.arm(usize::MAX, Mode::Error);
    s.recover_after_conflict(at(9, A), &finality(9, &A), None)
        .unwrap();
    let writes = rig.ops();
    drop(s);
    let recovered = decoded(&rig);
    assert!(writes >= 4 * 4 + 5, "{writes}");
    let mut cases = 0;
    for k in 0..writes {
        for mode in MODES {
            let ctx = format!("recovery / write {k} / {mode:?}");
            let rig = halted_rig();
            let mut s = rig.open().unwrap();
            rig.arm(k, mode);
            assert!(
                s.recover_after_conflict(at(9, A), &finality(9, &A), None)
                    .is_err(),
                "{ctx}"
            );
            drop(s);
            rig.recover(mode);
            let mut s = rig
                .open()
                .unwrap_or_else(|e| panic!("{ctx}: reopen refused: {e}"));
            let now = decoded(&rig);
            assert!(
                now == halted || now == recovered,
                "{ctx}: neither halted nor recovered"
            );
            assert_eq!(s.is_halted(), now == halted, "{ctx}");
            if now == halted {
                // Still halted: nothing signs; running the recovery again completes it.
                assert_eq!(
                    s.sign(&prevote(10, 0, A)),
                    Err(SignerError::Halted),
                    "{ctx}"
                );
                s.recover_after_conflict(at(9, A), &finality(9, &A), None)
                    .unwrap_or_else(|e| panic!("{ctx}: resume: {e}"));
            }
            s.sign(&prevote(10, 0, A)).unwrap();
            drop(s);
            rig.disk.borrow_mut().reboot();
            let s = rig
                .open()
                .unwrap_or_else(|e| panic!("{ctx}: after power loss: {e}"));
            assert!(!s.is_halted(), "{ctx}");
            assert_eq!(s.record().working_height(), Some(10), "{ctx}");
            cases += 1;
        }
    }
    assert_eq!(cases, writes * 5);
}

// ── multi-height with retained proofs ───────────────────────────────────────

#[test]
fn multi_height_sequence_keeps_exactly_the_current_proof() {
    let rig = Rig::new();
    let mut s = rig.open().unwrap();
    s.sign(&prevote(7, 0, A)).unwrap();
    s.sign(&precommit(7, 0, A)).unwrap();
    let p1 = rig.proof_files();
    assert_eq!(p1.len(), 1);
    s.sign(&precommit(7, 1, B)).unwrap();
    assert_eq!(
        rig.proof_files().len(),
        2,
        "the old proof waits for the next write"
    );
    s.advance(&finality(7, &B)).unwrap();
    assert_eq!(rig.proof_files().len(), 1, "G removed the first proof");
    s.sign(&prevote(8, 0, A)).unwrap();
    assert!(
        rig.proof_files().is_empty(),
        "G removed the second; the lock is gone"
    );
    s.sign(&precommit(8, 0, A)).unwrap();
    assert_eq!(rig.proof_files().len(), 1);
    drop(s);
    rig.disk.borrow_mut().reboot();
    let s = rig.open().unwrap();
    assert_proofs_settled(&rig, &s, "after reboot");
    assert_eq!(
        s.record().lock,
        Some(Lock {
            height: 8,
            round: 0,
            value: A
        })
    );
    assert_eq!(
        s.record().certified,
        Some(Certified {
            height: 7,
            block_id: B
        })
    );
}

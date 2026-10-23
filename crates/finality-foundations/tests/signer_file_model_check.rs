//! Signer persistence (the 413-byte record adopted by the owner, 2026-10-22 (decision ledger, as enumerated there); dormant, no node wiring; other elements PROPOSED): a bounded,
//! explicit-state model check of the recovery protocol, of proof-gated
//! height advancement, of the persisted conflict halt (its own flag in the
//! record) and of the operator's recovery from it.
//!
//! The system is the ratified G2-b signer core over the file-backed
//! store and the disk model in `common` (volatile and durable file data,
//! volatile and durable directory entries, a durable synced mirror). From an
//! empty disk, a breadth-first search enumerates every reachable state under:
//!
//! * initialization, open and every request of a fixed alphabet over heights
//!   7 to 10 (lock, relock, conflicting bytes, conflicting values,
//!   justified and unjustified lock-changing prevotes, nil precommit, votes
//!   at the next heights);
//! * every height advancement of a fixed proof alphabet, verified by an
//!   oracle that answers valid or invalid: valid proofs for heights 7 and 8,
//!   a second valid proof for height 7 naming another block (two verified
//!   proofs in conflict), a stale proof for height 6, and a forged one;
//! * in a halted state, every recovery of a fixed alphabet: valid resume
//!   proofs for heights 8 and 9 naming the followed block (with the retained
//!   conflict evidence, or with evidence supplied: either block at height 7,
//!   so one of the two is refused), and the refusals: too low (height 7),
//!   the other fork's block, forged;
//! * at every mutating operation of each action, each of five faults: error,
//!   effect-then-error, crash before, crash after, and crash after with the
//!   directory entries persisted; a crash then loses everything unsynced;
//! * repeated faults, including faults during recovery, up to `K` per path.
//!
//! In every reachable state it asserts:
//!
//! * **I1:** a released signature is in the durable state file and the
//!   durable mirror;
//! * **I4:** no lock at the current height is older than the latest issued
//!   lock, and the state never falls below an issued position. *Issued*
//!   means released or durably persisted: a durable signature can still be
//!   released by the identical request, and is indistinguishable from a
//!   message sent and lost;
//! * **I4b:** an issued non-nil vote never departs from the latest issued
//!   lock without the justification the lock rules require, and a non-nil
//!   precommit is never issued without a polka in its round;
//! * **I5:** no two different messages are ever issued at one position;
//! * **H1:** nothing is issued at a height above the first (7) unless a
//!   valid proof for the height below or higher was presented, and nothing
//!   is issued at or below a height the durable state has certified;
//! * **H2:** the signer leaves a height that holds an issued lock only with a
//!   valid proof for that height or higher;
//! * **H3:** a forged proof never changes the state, and the block certified
//!   for a height never changes;
//! * **HALT1:** while halted nothing is issued, and the halt (the record's
//!   own flag) is never lost except by a recovery REC1 allows; **HALT2:** a
//!   halt needs two valid proofs naming different blocks at its height;
//! * **REC1:** a halt ends only by a recovery with a valid resume proof that
//!   names the followed block at a height above the conflict height, and a
//!   recovery returns only once it is durable; an allowed recovery is never
//!   refused without a fault;
//! * **REC2:** after a recovery, nothing is issued at or below its resume
//!   height (so nothing at or below the conflict height or the halted
//!   working height);
//! * **PR2:** at every open, the referenced proof verifies for the purpose
//!   and context the record gives it (the lock's quorum, or a finality proof
//!   for another block at the conflict height);
//! * **REC3:** a recovered signer's conflict archive is durable: the halted
//!   record, the conflicting evidence (a valid proof naming another block at
//!   the conflict height), the resume certificate and the receipt naming the
//!   resume height;
//! * **liveness of recovery:** no fault sequence leaves a state that refuses
//!   to open.
//!
//! Assumptions: one process; ownership is the lock trait; the oracle is sound
//! (a "valid" answer means a real certificate exists); the operator's
//! `followed` block is what the node's chain holds; the disk model's
//! durability rules; no whole-directory rollback; no cloned keys.
//!
//! Signatures here are a keyed hash, not Ed25519: the properties are about
//! what is released and persisted, not about signature validity.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::rc::Rc;

use sumchain_finality_foundations::signer::{
    initialize_exclusive, DurableSigner, Justification, PolkaVerifier, RetainedProofCheck,
    SignPosition, SignRequest, SignerError, SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{
    conflict_file_name, floor_below_height, proof_file_name, sign_bytes_digest, Classified,
    FileSignerStore, ProofStatus, RecoveryReceipt, SignerState, STATE_FILE,
};
use sumchain_finality_foundations::Digest;

mod common;
use common::*;

const CHAIN: u64 = 4242;
const GENESIS: Digest = [0x11; 32];
const KEY_ID: Digest = [0x5A; 32];
const A: Digest = [0xA1; 32];
const B: Digest = [0xB2; 32];

struct HashKey;
impl SigningKey for HashKey {
    fn key_id(&self) -> Digest {
        KEY_ID
    }
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(b"model-check-key");
        h.update(payload);
        let mut out = vec![0u8; 64];
        h.finalize_xof().fill(&mut out);
        out
    }
}

type Store = FileSignerStore<SimDir, SimMirror, B3>;
type Signer = DurableSigner<Store, HashKey, RetainingPolka, MemGuard>;

fn store(disk: &Disk) -> Store {
    FileSignerStore::new(
        SimDir(disk.clone()),
        SimMirror(disk.clone()),
        B3,
        CHAIN,
        GENESIS,
    )
}

fn open(disk: &Disk, owner: &MemOwnership) -> Result<Signer, SignerError> {
    DurableSigner::open(owner, store(disk), HashKey, RetainingPolka, None)
}

fn pos(height: u64, round: u32, step: Step) -> SignPosition {
    SignPosition {
        height,
        round,
        step,
    }
}

fn req(
    h: u64,
    r: u32,
    step: Step,
    value: VoteValue,
    tag: &str,
    polka: Option<(u32, Digest)>,
) -> SignRequest {
    SignRequest {
        position: pos(h, r, step),
        value,
        payload: format!("{h}/{r}/{step:?}/{value:?}/{tag}").into_bytes(),
        justification: polka.map(|(p, v)| Justification {
            polka_round: p,
            evidence: polka_evidence(h, p, &v),
        }),
    }
}

/// The request alphabet: fifteen requests over twelve positions, exercising
/// every lock rule; height 10 is reachable only by a recovery.
fn alphabet() -> Vec<SignRequest> {
    use Step::{Precommit, Prevote};
    use VoteValue::{Block, Nil};
    vec![
        req(7, 0, Prevote, Block(A), "x", None),
        req(7, 0, Prevote, Block(A), "other bytes", None),
        req(7, 0, Precommit, Block(A), "x", Some((0, A))),
        req(7, 0, Precommit, Block(B), "x", Some((0, B))),
        req(7, 1, Prevote, Block(B), "x", Some((0, B))),
        req(7, 1, Prevote, Block(B), "unjustified", None),
        req(7, 1, Precommit, Block(B), "x", Some((1, B))),
        req(7, 2, Prevote, Block(A), "unjustified", None),
        req(7, 2, Prevote, Block(B), "x", None),
        req(7, 2, Precommit, Nil, "x", None),
        req(8, 0, Prevote, Block(B), "x", None),
        req(8, 0, Precommit, Block(B), "x", Some((0, B))),
        req(8, 1, Prevote, Block(A), "unjustified", None),
        req(9, 0, Prevote, Block(A), "x", None),
        req(10, 0, Prevote, Block(A), "x", None),
    ]
}

/// The proof alphabet, with the oracle's verdict: `Some((height, block))` for
/// a valid proof, `None` for a forged one.
/// A proof and the oracle's verdict on it.
type OracleProof = (Vec<u8>, Option<(u64, Digest)>);

/// A recovery: the followed block, the resume proof, supplied evidence, and
/// the oracle's verdict on the resume proof.
type OracleRecovery = (ChainPoint, Vec<u8>, Option<Vec<u8>>, Option<(u64, Digest)>);

fn recoveries() -> Vec<OracleRecovery> {
    let at = ChainPoint;
    vec![
        (at(9, A), finality(9, &A), None, Some((9, A))),
        (at(8, B), finality(8, &B), None, Some((8, B))),
        // Supplied evidence: allowed only when it names the block not
        // certified at the conflict height.
        (
            at(9, A),
            finality(9, &A),
            Some(finality(7, &B)),
            Some((9, A)),
        ),
        (
            at(9, A),
            finality(9, &A),
            Some(finality(7, &A)),
            Some((9, A)),
        ),
        // Refused: too low (the conflict height), the other fork's block,
        // forged.
        (at(7, A), finality(7, &A), None, Some((7, A))),
        (at(9, A), finality(9, &B), None, Some((9, B))),
        (
            at(9, A),
            b"forged finality for height 9".to_vec(),
            None,
            None,
        ),
    ]
}

fn proofs() -> Vec<OracleProof> {
    vec![
        (finality(7, &A), Some((7, A))),
        (finality(7, &B), Some((7, B))),
        (finality(8, &B), Some((8, B))),
        (finality(6, &A), Some((6, A))),
        (b"forged finality for height 7".to_vec(), None),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Status {
    /// No signer state: the next action is initialization.
    Uninitialized,
    /// The process is down (or poisoned): the next action is an open.
    Closed,
    /// A healthy signer is running.
    Open,
}

/// What has happened so far, for the safety assertions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
struct Ghost {
    /// Every message issued, by position: released, or durably persisted
    /// (a durable signature can be released later by the identical request,
    /// and is indistinguishable from a message sent and lost).
    issued: BTreeMap<SignPosition, (VoteValue, Digest)>,
    /// Positions actually released.
    released: BTreeMap<SignPosition, Digest>,
    /// The highest height a valid proof was presented for.
    valid_proof_max: Option<u64>,
    /// Every valid (height, block) proof presented.
    valid_proofs: BTreeSet<(u64, Digest)>,
    /// The signer is halted: a halt was persisted (observed durable, or
    /// returned) and has not ended since.
    halted: bool,
    /// The height of the latest persisted conflict.
    conflict: Option<u64>,
    /// The recoveries the rules allow, as (resume height, block): a valid
    /// resume proof naming the followed block above the conflict height.
    allowed_recoveries: BTreeSet<(u64, Digest)>,
    /// The resume height of the latest completed recovery.
    resumed: Option<u64>,
    /// Every (height, block) a durable state has certified.
    certified: BTreeMap<u64, Digest>,
}

impl Ghost {
    /// The highest issued lock: the latest non-nil precommit.
    fn lock_floor(&self) -> Option<(u64, u32, Digest)> {
        self.issued
            .iter()
            .filter(|(p, _)| p.step == Step::Precommit)
            .filter_map(|(p, (v, _))| match v {
                VoteValue::Block(b) => Some((p.height, p.round, *b)),
                VoteValue::Nil => None,
            })
            .next_back()
    }
}

#[derive(Clone)]
struct Node {
    model: Model,
    status: Status,
    ghost: Ghost,
    faults: u32,
}

/// The model with only reachable inodes, renumbered: equal content, equal key.
fn compact(m: &Model) -> Model {
    let mut ids: Vec<usize> = Vec::new();
    for &i in m.dir_vol.values().chain(m.dir_dur.values()) {
        if !ids.contains(&i) {
            ids.push(i);
        }
    }
    let remap = |i: usize| ids.iter().position(|&x| x == i).expect("reachable");
    Model {
        inodes: ids.iter().map(|&i| m.inodes[i].clone()).collect(),
        dir_vol: m
            .dir_vol
            .iter()
            .map(|(k, &v)| (k.clone(), remap(v)))
            .collect(),
        dir_dur: m
            .dir_dur
            .iter()
            .map(|(k, &v)| (k.clone(), remap(v)))
            .collect(),
        mirror_vol: m.mirror_vol.clone(),
        mirror_dur: m.mirror_dur.clone(),
        ..Model::default()
    }
}

fn model_key(m: &Model) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = |b: &[u8]| {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    };
    for (k, v) in &m.dir_vol {
        bytes(k.as_bytes());
        bytes(&[*v as u8]);
    }
    bytes(b"|");
    for (k, v) in &m.dir_dur {
        bytes(k.as_bytes());
        bytes(&[*v as u8]);
    }
    bytes(b"|");
    for i in &m.inodes {
        bytes(&i.vol);
        bytes(&i.dur);
    }
    bytes(m.mirror_vol.as_deref().unwrap_or(b"-"));
    bytes(m.mirror_dur.as_deref().unwrap_or(b"-"));
    out
}

/// The state's identity: a BLAKE3-256 digest of the canonical disk, the
/// status and the history. (Assumption: no collision among the states
/// visited; the digests are only used to remember what was seen.)
fn node_key(n: &Node) -> [u8; 32] {
    let mut k = model_key(&n.model);
    k.extend_from_slice(format!("{:?}|{:?}", n.status, n.ghost).as_bytes());
    blake3::hash(&k).into()
}

/// The state file a process would read now (the volatile view).
fn durable_or_visible_state(m: &Model) -> Option<SignerState> {
    let id = *m.dir_vol.get(STATE_FILE)?;
    SignerState::decode(&m.inodes[id].vol, &B3)
        .ok()
        .map(|(s, _)| s)
}

fn durable_state(m: &Model) -> Option<SignerState> {
    let id = *m.dir_dur.get(STATE_FILE)?;
    SignerState::decode(&m.inodes[id].dur, &B3)
        .ok()
        .map(|(s, _)| s)
}

/// I4 and H2 on an open signer: never below an issued position; at the
/// height of the latest issued lock, never an older lock; above it, only with
/// a valid proof for that height or higher.
fn check_open(n: &Node, s: &Signer, disk: &Disk, violations: &mut Vec<String>) {
    let rec = s.record();
    // HALT1: a persisted halt is never lost.
    if n.ghost.halted && !s.is_halted() {
        violations.push("HALT1: the persisted halt was lost".into());
    }
    // PR1: no fault ever leaves the referenced proof missing or corrupt, and
    // no unreferenced proof file survives an open.
    match s.store().proof_status() {
        ProofStatus::Missing | ProofStatus::Corrupt => violations.push(format!(
            "PR1: the referenced proof is {:?} after faults",
            s.store().proof_status()
        )),
        _ => {}
    }
    // PR2: the signer's own check of the referenced proof, for its purpose.
    match s.retained_proof_check() {
        RetainedProofCheck::NotReferenced | RetainedProofCheck::Verified => {}
        other => violations.push(format!("PR2: the retained proof check is {other:?}")),
    }
    let referenced = durable_or_visible_state(&disk.borrow()).map(|st| st.proof_digest);
    let keep = referenced
        .filter(|d| *d != [0; 32])
        .map(|d| proof_file_name(&d));
    for name in disk.borrow().dir_vol.keys() {
        if name.starts_with("proof") && Some(name) != keep.as_ref() {
            violations.push(format!("PR1: unreferenced proof file {name} after open"));
        }
    }
    if s.store().classified() != Some(Classified::Consistent) {
        violations.push(format!(
            "an open state needed a repair: {:?}",
            s.store().classified()
        ));
    }
    if n.ghost.halted {
        return;
    }
    if let (Some(r), Some(h)) = (n.ghost.resumed, n.ghost.conflict) {
        check_archive(n, &disk.borrow(), h, r, violations);
    }
    let hw = rec.high_water();
    if let Some(&issued_max) = n.ghost.issued.keys().next_back() {
        if hw.is_none_or(|p| p < issued_max) {
            violations.push(format!("I4: state {hw:?} below issued {issued_max:?}"));
        }
    }
    if let Some((h, r, _)) = n.ghost.lock_floor() {
        match rec.working_height() {
            Some(w) if w == h => match rec.lock {
                Some(l) if l.height == h && l.round >= r => {}
                other => violations.push(format!(
                    "I4: lock {other:?} at height {h}, issued lock round {r}"
                )),
            },
            Some(w) if w > h => {
                if n.ghost.valid_proof_max.is_none_or(|v| v < h) {
                    violations.push(format!(
                        "H2: left height {h} (lock round {r}) for {w} without a valid proof"
                    ));
                }
            }
            other => violations.push(format!(
                "I4: working height {other:?} below the issued lock height {h}"
            )),
        }
    }
}

/// REC3: the conflict archive of a recovery is durable and names it.
fn check_archive(n: &Node, m: &Model, h: u64, r: u64, violations: &mut Vec<String>) {
    let durable = |suffix: &str| -> Option<Vec<u8>> {
        let name = conflict_file_name(h, suffix);
        let (&d, &v) = (m.dir_dur.get(&name)?, m.dir_vol.get(&name)?);
        (d == v && m.inodes[d].dur == m.inodes[d].vol && !m.inodes[d].dur.is_empty())
            .then(|| m.inodes[d].dur.clone())
    };
    let files = ["state", "evidence", "resume", "receipt"].map(durable);
    let [Some(_), Some(evidence), Some(_), Some(receipt)] = files else {
        violations.push(format!("REC3: the archive for height {h} is not durable"));
        return;
    };
    match RecoveryReceipt::decode(&receipt, &B3) {
        Ok(rc) if rc.conflict_height == h && rc.resume_height == r => {}
        other => violations.push(format!(
            "REC3: the receipt does not name the recovery: {other:?}"
        )),
    }
    let certified = n.ghost.certified.get(&h).copied();
    match RetainingPolka.verify_finality(&evidence) {
        Ok(c) if c.height == h && Some(c.block_id) != certified => {}
        other => violations.push(format!(
            "REC3: the archived evidence is not a conflict: {other:?}"
        )),
    }
}

/// I5 and I4b when `q` becomes issued (released, or durably persisted).
fn issue(n: &mut Node, q: &SignRequest, violations: &mut Vec<String>) {
    let p = q.position;
    if n.ghost.halted {
        violations.push(format!("HALT1: issued {p:?} after the halt"));
    }
    if n.ghost.resumed.is_some_and(|r| p.height <= r) {
        violations.push(format!(
            "REC2: issued {p:?} at or below the resume height {:?}",
            n.ghost.resumed
        ));
    }
    let d = sign_bytes_digest(&B3, &q.payload);
    if p.height > 7 && n.ghost.valid_proof_max.is_none_or(|v| v < p.height - 1) {
        violations.push(format!(
            "H1: issued at height {} without a valid proof for {}",
            p.height,
            p.height - 1
        ));
    }
    if let Some((&ch, _)) = n.ghost.certified.iter().next_back() {
        if p.height <= ch {
            violations.push(format!(
                "H1: issued at height {} at or below the certified height {ch}",
                p.height
            ));
        }
    }
    if let Some((v, dd)) = n.ghost.issued.get(&p) {
        if *v != q.value || *dd != d {
            violations.push(format!("I5: two different messages issued at {p:?}"));
        }
        return;
    }
    if let (Some((lh, lr, lv)), VoteValue::Block(v)) = (n.ghost.lock_floor(), q.value) {
        if lh == p.height && p.round > lr && v != lv {
            let ok = match (p.step, q.justification.as_ref()) {
                (Step::Prevote, Some(j)) => lr <= j.polka_round && j.polka_round < p.round,
                (Step::Precommit, Some(j)) => j.polka_round == p.round,
                _ => false,
            };
            if !ok {
                violations.push(format!(
                    "I4b: {p:?} departs from the issued lock at round {lr} without justification"
                ));
            }
        }
    }
    if p.step == Step::Precommit
        && q.value != VoteValue::Nil
        && q.justification
            .as_ref()
            .is_none_or(|j| j.polka_round != p.round)
    {
        violations.push(format!(
            "I4b: non-nil precommit {p:?} issued without a polka in its round"
        ));
    }
    n.ghost.issued.insert(p, (q.value, d));
}

/// After an action: a signature that has become durable (by the action, or
/// by a repair completing an interrupted one) becomes issued. It is matched to
/// the request that produced it; a durable signature no request produced is a
/// violation.
fn observe_durable(n: &mut Node, alphabet: &[SignRequest], violations: &mut Vec<String>) {
    let Some(s) = durable_state(&n.model) else {
        return;
    };
    if s.halted {
        let h = s.floor_height - 1;
        let conflicting = n
            .ghost
            .valid_proofs
            .iter()
            .any(|&(ph, b)| ph == h && b != s.certified_block_id);
        if !(conflicting && n.ghost.valid_proofs.contains(&(h, s.certified_block_id))) {
            violations.push(format!(
                "HALT2: halted at height {h} without two valid conflicting proofs"
            ));
        }
        n.ghost.halted = true;
        n.ghost.conflict = Some(h);
    } else if n.ghost.halted {
        // The halt ended: only by an allowed recovery.
        let r = s.floor_height - 1;
        if !n
            .ghost
            .allowed_recoveries
            .contains(&(r, s.certified_block_id))
        {
            violations.push(format!(
                "REC1: the halt ended without an allowed recovery (resume at {r})"
            ));
        }
        n.ghost.halted = false;
        n.ghost.resumed = Some(r);
    }
    if s.certified_block_id != [0; 32] {
        let h = s.floor_height - 1;
        match n.ghost.certified.get(&h) {
            Some(b) if *b != s.certified_block_id => {
                violations.push(format!("H3: the block certified for height {h} changed"))
            }
            _ => {
                n.ghost.certified.insert(h, s.certified_block_id);
            }
        }
    }
    let Some(last) = s.last.as_ref() else {
        return;
    };
    if n.ghost
        .issued
        .get(&last.position)
        .is_some_and(|(v, d)| *v == last.value && *d == last.sign_bytes_digest)
    {
        return;
    }
    match alphabet.iter().find(|q| {
        q.position == last.position
            && q.value == last.value
            && sign_bytes_digest(&B3, &q.payload) == last.sign_bytes_digest
    }) {
        Some(q) => issue(n, q, violations),
        None => violations.push(format!(
            "durable signature at {:?} matches no request",
            last.position
        )),
    }
}

/// I1 on a release: in the durable state file and the durable mirror.
fn check_release(n: &mut Node, q: &SignRequest, violations: &mut Vec<String>) {
    let p = q.position;
    let d = sign_bytes_digest(&B3, &q.payload);
    match durable_state(&n.model) {
        Some(s)
            if s.last
                .as_ref()
                .is_some_and(|l| l.position == p && l.sign_bytes_digest == d) => {}
        other => violations.push(format!(
            "I1: released {p:?} not in the durable state file ({:?})",
            other.map(|s| s.counter)
        )),
    }
    let fid = n.model.dir_dur.get(STATE_FILE).copied();
    if fid.map(|i| n.model.inodes[i].dur.clone()) != n.model.mirror_dur {
        violations.push(format!(
            "I1: durable mirror differs from the durable state file after releasing {p:?}"
        ));
    }
    issue(n, q, violations);
    n.ghost.released.insert(p, d);
}

fn recover(disk: &Disk, mode: Mode) {
    match mode {
        Mode::Error | Mode::EffectThenError => disk.borrow_mut().restart(),
        _ => disk.borrow_mut().reboot(),
    }
}

fn arm(disk: &Disk, plan: Option<(usize, Mode)>) {
    let mut m = disk.borrow_mut();
    m.ops = 0;
    m.log.clear();
    m.plan = plan;
}

fn fresh(model: &Model) -> Disk {
    Rc::new(RefCell::new(model.clone()))
}

struct Report {
    states: usize,
    transitions: usize,
    max_depth: usize,
    released: usize,
    issued: usize,
    /// The highest working height an open signer reached.
    max_height: u64,
    /// Accepted advancements seen (open states whose height is above 7).
    advanced_states: usize,
    /// Open states whose signer is halted.
    halted_states: usize,
    /// Open states whose signer recovered from a halt.
    recovered_states: usize,
    /// Open states halted again after a recovery on their path.
    rehalted_states: usize,
    /// With [`Config::collect_image`]: the canonical keys of the visited states.
    image: HashSet<[u8; 32]>,
    violations: Vec<String>,
}

#[derive(Clone)]
enum Action {
    Init,
    Open,
    Sign(SignRequest),
    /// A height advancement, with the oracle's verdict on the proof.
    Advance(Vec<u8>, Option<(u64, Digest)>),
    /// The operator's recovery from a halt (see [`recoveries`]).
    Recover(OracleRecovery),
}

/// Run `action` from `node` under `plan`; return the successor (if any) and
/// the number of mutating operations the fault-free run performed.
fn act(
    node: &Node,
    action: &Action,
    plan: Option<(usize, Mode)>,
    alphabet: &[SignRequest],
    v: &mut Vec<String>,
) -> Option<(Node, usize)> {
    let disk = fresh(&node.model);
    let owner = MemOwnership::default();
    let res: Result<Status, SignerError> = match action {
        Action::Init => {
            arm(&disk, plan);
            let mut st = store(&disk);
            initialize_exclusive(&owner, &mut st, KEY_ID, floor_below_height(7))
                .map(|()| Status::Closed)
        }
        Action::Open => {
            arm(&disk, plan);
            open(&disk, &owner).map(|_| Status::Open)
        }
        Action::Sign(q) => {
            // An open state reopens without any write, so the plan counts the
            // signing's own operations.
            let mut s = match open(&disk, &owner) {
                Ok(s) => s,
                Err(e) => {
                    v.push(format!("an open state does not reopen: {e}"));
                    return None;
                }
            };
            arm(&disk, plan);
            s.sign(q).map(|_| Status::Open)
        }
        Action::Advance(proof, _) => {
            let mut s = match open(&disk, &owner) {
                Ok(s) => s,
                Err(e) => {
                    v.push(format!("an open state does not reopen: {e}"));
                    return None;
                }
            };
            arm(&disk, plan);
            s.advance(proof).map(|_| Status::Open)
        }
        Action::Recover((followed, proof, evidence, _)) => {
            let mut s = match open(&disk, &owner) {
                Ok(s) => s,
                Err(e) => {
                    v.push(format!("an open state does not reopen: {e}"));
                    return None;
                }
            };
            arm(&disk, plan);
            s.recover_after_conflict(followed, proof, evidence.as_deref())
                .map(|_| Status::Open)
        }
    };
    let ops = disk.borrow().ops;
    let fired = plan.is_some_and(|(k, _)| k < ops);
    let mut next = Node {
        model: Model::default(),
        status: node.status,
        ghost: node.ghost.clone(),
        faults: node.faults + u32::from(fired),
    };
    if let Action::Advance(_, verdict) = action {
        if let (Ok(_), None) = (&res, verdict) {
            v.push("H3: a forged proof was accepted".into());
            return None;
        }
        if let Some((h, b)) = verdict {
            if next.ghost.valid_proof_max.is_none_or(|m| m < *h) {
                next.ghost.valid_proof_max = Some(*h);
            }
            next.ghost.valid_proofs.insert((*h, *b));
        }
    }
    let mut recovery_allowed = false;
    if let Action::Recover((followed, _, evidence, verdict)) = action {
        if let (Ok(_), None) = (&res, verdict) {
            v.push("REC1: a forged resume proof was accepted".into());
            return None;
        }
        if let Some((h, b)) = verdict {
            if next.ghost.valid_proof_max.is_none_or(|m| m < *h) {
                next.ghost.valid_proof_max = Some(*h);
            }
            next.ghost.valid_proofs.insert((*h, *b));
            let conflict = next.ghost.conflict;
            let evidence_ok = evidence.as_ref().is_none_or(|e| {
                let c = RetainingPolka.verify_finality(e);
                c.is_ok_and(|c| {
                    Some(c.height) == conflict
                        && next.ghost.certified.get(&c.height) != Some(&c.block_id)
                })
            });
            recovery_allowed = (*h, *b) == (followed.0, followed.1)
                && conflict.is_some_and(|c| *h > c)
                && evidence_ok;
            if recovery_allowed {
                next.ghost.allowed_recoveries.insert((*h, *b));
            }
        }
    }
    let succeeded = res.is_ok();
    match (res, fired) {
        (Ok(status), false) => next.status = status,
        (Ok(_), true) => {
            v.push(format!(
                "I1: {:?} action released although a write failed",
                node.status
            ));
            return None;
        }
        (Err(_), true) => {
            recover(&disk, plan.expect("fired").1);
            next.status = Status::Closed;
        }
        (Err(e), false) => match (action, e) {
            // The store refused a transition the core produced: a core bug
            // caught only by the store's defensive check.
            (Action::Sign(q), SignerError::PersistFailed(m)) => {
                v.push(format!(
                    "I4: store refused the core's transition at {:?}: {m}",
                    q.position
                ));
                return None;
            }
            (Action::Advance(..), SignerError::PersistFailed(m)) => {
                v.push(format!("H3: store refused the core's advancement: {m}"));
                return None;
            }
            (Action::Recover(..), e) if recovery_allowed => {
                v.push(format!("REC1: an allowed recovery was refused: {e}"));
                return None;
            }
            // The halt is persisted and returned as this error.
            (Action::Advance(..), SignerError::ConflictingFinality(h)) => {
                let blocks = next
                    .ghost
                    .valid_proofs
                    .iter()
                    .filter(|(ph, _)| *ph == h)
                    .count();
                if blocks < 2 {
                    v.push(format!(
                        "HALT2: halted at height {h} without two valid proofs"
                    ));
                }
                next.ghost.halted = true;
                next.ghost.conflict = Some(h);
                next.status = Status::Open;
            }
            // A refused request, advancement or recovery changes nothing.
            (Action::Sign(_) | Action::Advance(..) | Action::Recover(..), _) => {
                if ops != 0 {
                    v.push("H3: a refused action wrote to disk".into());
                }
                return None;
            }
            (Action::Open, SignerError::NotInitialized) => next.status = Status::Uninitialized,
            (_, e) => {
                v.push(format!(
                    "liveness: {:?} refused without a fault: {e}",
                    node.status
                ));
                return None;
            }
        },
    }
    next.model = compact(&disk.borrow());
    let q = match action {
        Action::Sign(q) => Some(q),
        _ => None,
    };
    if let (Some(q), Status::Open, false) = (q, next.status, fired) {
        check_release(&mut next, q, v);
    } else {
        observe_durable(&mut next, alphabet, v);
    }
    if let (Action::Advance(_, Some((h, b))), Status::Open, false, true) =
        (action, next.status, fired, succeeded)
    {
        // Durable before the advance returns.
        match durable_state(&next.model) {
            Some(st) if st.certified_block_id == *b && st.floor_height == h + 1 => {}
            Some(st) if st.floor_height > h + 1 => {} // an equal-or-higher height was already certified
            other => v.push(format!(
                "H1: advancement to {} returned before it was durable ({:?})",
                h + 1,
                other.map(|s| s.floor_height)
            )),
        }
    }
    if let (Action::Recover((_, _, _, Some((h, b)))), Status::Open, false, true) =
        (action, next.status, fired, succeeded)
    {
        match durable_state(&next.model) {
            Some(st) if !st.halted && st.certified_block_id == *b && st.floor_height == h + 1 => {}
            other => v.push(format!(
                "REC1: recovery to {h} returned before it was durable ({:?})",
                other.map(|s| (s.halted, s.floor_height))
            )),
        }
        if next.ghost.halted || next.ghost.resumed != Some(*h) {
            v.push("REC1: a returned recovery was not observed durable".into());
        }
    }
    Some((next, ops))
}

/// Explore every state reachable with at most `max_faults` faults per path.
/// DIAGNOSTIC: a one-line description of a state's archive debris.
fn diag_category(n: &Node) -> String {
    let m = &n.model;
    let tag = |b: &[u8]| -> String {
        if b.is_empty() {
            "0".into()
        } else if b.starts_with(b"final") && b.len() == 45 {
            format!("f{}{:02x}", b[5], b[13])
        } else if b.len() == 185 {
            format!("r{}", b[49])
        } else if b.len() == 413 {
            "st".into()
        } else {
            format!("?{}", b.len())
        }
    };
    let files: Vec<String> = m
        .dir_vol
        .iter()
        .filter(|(k, _)| k.starts_with("conflict-"))
        .map(|(k, &i)| {
            let d = m.dir_dur.get(k) == Some(&i) && m.inodes[i].dur == m.inodes[i].vol;
            format!(
                "{}={}{}",
                k.split_once('.').map_or(k.as_str(), |x| x.1),
                tag(&m.inodes[i].vol),
                if d { "" } else { "~" }
            )
        })
        .collect();
    format!(
        "{:?} h={} r={:?} [{}]",
        n.status,
        u8::from(n.ghost.halted),
        n.ghost.resumed,
        files.join(",")
    )
}

/// ABSTRACTION (used only where a run names it): in a state whose state
/// file (volatile and durable) and mirror (volatile and durable) are one
/// identical **halted** record, remove every `conflict-*` file.
///
/// Why this is exact for the signer and the store: in such a state no
/// recovery has reached P1, so the files are debris of interrupted archive
/// attempts. The store reads `conflict-*` files only (a) in
/// `recovery_archive_ok`, from `persist` of a recovery, after the same call's
/// `archive_conflict` rewrote all four (truncate, rename, sync), or from the
/// R1 repair of a recovered state file, which exists only after such a
/// complete rewrite and is never canonicalised (its volatile state file is
/// not halted); and (b) in `load` when the state file and mirror are both
/// absent, which never happens once initialized (nothing removes the state
/// file). No property reads them in a halted state (REC3 reads the archive
/// of a recovered state only). The claim is checked, not assumed, by
/// `debris_canonicalisation_is_exact_up_to_two_faults`, which compares the
/// canonical image of the exact reachable set with the canonicalised one.
fn canonicalise_debris(m: &mut Model) {
    let halted = |b: &[u8]| SignerState::decode(b, &B3).is_ok_and(|(st, _)| st.halted);
    let consistent_halt = match (m.dir_vol.get(STATE_FILE), m.dir_dur.get(STATE_FILE)) {
        (Some(&v), Some(&d)) => {
            let bytes = &m.inodes[v].vol;
            halted(bytes)
                && m.inodes[d].dur == *bytes
                && m.mirror_vol.as_deref() == Some(bytes.as_slice())
                && m.mirror_dur.as_deref() == Some(bytes.as_slice())
        }
        _ => false,
    };
    if consistent_halt {
        m.dir_vol.retain(|k, _| !k.starts_with("conflict-"));
        m.dir_dur.retain(|k, _| !k.starts_with("conflict-"));
        *m = compact(m);
    }
}

/// What a run explores.
struct Config<'a> {
    max_faults: u32,
    recoveries: &'a [OracleRecovery],
    /// Stop after this many states (diagnostics only).
    max_states: Option<usize>,
    /// Apply [`canonicalise_debris`] to every state.
    canonical_debris: bool,
    /// Collect the key of every visited state after [`canonicalise_debris`].
    collect_image: bool,
}

impl Config<'_> {
    fn exact(max_faults: u32, recoveries: &[OracleRecovery]) -> Config<'_> {
        Config {
            max_faults,
            recoveries,
            max_states: None,
            canonical_debris: false,
            collect_image: false,
        }
    }
}

fn explore_with(c: &Config) -> Report {
    let (max_faults, recovery_alphabet, max_states) = (c.max_faults, c.recoveries, c.max_states);
    let mut image: HashSet<[u8; 32]> = HashSet::new();
    let diag = std::env::var_os("SUMCHAIN_MC_DIAG").is_some();
    let mut hist: HashMap<String, usize> = HashMap::new();
    let t0 = std::time::Instant::now();
    let alphabet = alphabet();
    let start = Node {
        model: Model::default(),
        status: Status::Uninitialized,
        ghost: Ghost::default(),
        faults: 0,
    };
    // Key -> fewest faults it was reached with.
    let mut seen: HashMap<[u8; 32], u32> = HashMap::new();
    let mut queue: VecDeque<(Node, usize)> = VecDeque::new();
    seen.insert(node_key(&start), 0);
    queue.push_back((start, 0));
    let mut report = Report {
        states: 0,
        transitions: 0,
        max_depth: 0,
        released: 0,
        issued: 0,
        max_height: 0,
        advanced_states: 0,
        halted_states: 0,
        recovered_states: 0,
        rehalted_states: 0,
        image: HashSet::new(),
        violations: Vec::new(),
    };

    // Breadth-first for a fault bound (so the fewest-faults rule is exact);
    // depth-first without one, which keeps the frontier small. Either way
    // every reachable state is visited once.
    let depth_first = max_faults == u32::MAX;
    while let Some((node, depth)) = if depth_first {
        queue.pop_back()
    } else {
        queue.pop_front()
    } {
        report.states += 1;
        if c.collect_image {
            let mut canon = node.clone();
            canonicalise_debris(&mut canon.model);
            image.insert(node_key(&canon));
        }
        if diag {
            *hist.entry(diag_category(&node)).or_default() += 1;
            if report.states % 200_000 == 0 {
                eprintln!("diag: {} states, {:?}", report.states, t0.elapsed());
            }
        }
        if max_states.is_some_and(|c| report.states >= c) {
            eprintln!("diag: stopped at the state cap {}", report.states);
            break;
        }
        report.max_depth = report.max_depth.max(depth);
        report.released = report.released.max(node.ghost.released.len());
        report.issued = report.issued.max(node.ghost.issued.len());
        let mut v: Vec<String> = Vec::new();
        let actions: Vec<Action> = match node.status {
            Status::Uninitialized => vec![Action::Init],
            Status::Closed => vec![Action::Open],
            Status::Open => {
                // I4 on the running signer (an open of this disk, no repair).
                let disk = fresh(&node.model);
                arm(&disk, None);
                let mut halted = false;
                match open(&disk, &MemOwnership::default()) {
                    Ok(s) => {
                        check_open(&node, &s, &disk, &mut v);
                        halted = s.is_halted();
                        if halted {
                            report.halted_states += 1;
                            if node.ghost.resumed.is_some() {
                                report.rehalted_states += 1;
                            }
                        } else if node.ghost.resumed.is_some() {
                            report.recovered_states += 1;
                        }
                        let w = s.record().working_height().unwrap_or(0);
                        report.max_height = report.max_height.max(w);
                        if w > 7 {
                            report.advanced_states += 1;
                        }
                    }
                    Err(e) => v.push(format!("an open state does not reopen: {e}")),
                }
                alphabet
                    .iter()
                    .cloned()
                    .map(Action::Sign)
                    .chain(proofs().into_iter().map(|(p, v)| Action::Advance(p, v)))
                    .chain(
                        recovery_alphabet
                            .iter()
                            .filter(|_| halted)
                            .cloned()
                            .map(Action::Recover),
                    )
                    .collect()
            }
        };
        let mut successors: Vec<Node> = Vec::new();
        for a in &actions {
            // Fault-free first; then a fault at each operation it performed.
            let Some((n0, ops)) = act(&node, a, None, &alphabet, &mut v) else {
                continue;
            };
            successors.push(n0);
            for k in 0..ops {
                for mode in MODES {
                    if let Some((n1, _)) = act(&node, a, Some((k, mode)), &alphabet, &mut v) {
                        successors.push(n1);
                    }
                }
            }
        }
        report.violations.extend(v);
        for mut s in successors {
            report.transitions += 1;
            if s.faults > max_faults {
                continue;
            }
            if c.canonical_debris {
                canonicalise_debris(&mut s.model);
            }
            let key = node_key(&s);
            // Without a bound the fault count is irrelevant: a state seen once
            // is done.
            if seen
                .get(&key)
                .is_some_and(|&f| depth_first || f <= s.faults)
            {
                continue;
            }
            seen.insert(key, s.faults);
            queue.push_back((s, depth + 1));
        }
        if report.violations.len() > 20 {
            break;
        }
    }
    report.image = image;
    if diag {
        let mut h: Vec<(String, usize)> = hist.into_iter().collect();
        h.sort_by(|a, b| b.1.cmp(&a.1));
        eprintln!(
            "diag: {} categories; {} states in {:?}; top:",
            h.len(),
            report.states,
            t0.elapsed()
        );
        for (c, n) in h.iter().take(30) {
            eprintln!("diag: {n:>9} {c}");
        }
    }
    report
}

/// DIAGNOSTIC: `SUMCHAIN_MC_K` (default 1), `SUMCHAIN_MC_MAX_STATES`
/// (default 3,000,000), `SUMCHAIN_MC_RECOVERIES` (comma-separated indices
/// into [`recoveries`]; empty: none; unset: all), `SUMCHAIN_MC_DIAG=1`.
#[test]
#[ignore]
fn model_check_diagnostics() {
    let env = |k: &str| std::env::var(k).ok();
    let k: u32 = env("SUMCHAIN_MC_K").map_or(1, |v| v.parse().unwrap());
    let cap: usize = env("SUMCHAIN_MC_MAX_STATES").map_or(3_000_000, |v| v.parse().unwrap());
    let all = recoveries();
    let set: Vec<OracleRecovery> = match env("SUMCHAIN_MC_RECOVERIES") {
        None => all,
        Some(v) if v.is_empty() => Vec::new(),
        Some(v) => v
            .split(',')
            .map(|i| all[i.parse::<usize>().unwrap()].clone())
            .collect(),
    };
    let t0 = std::time::Instant::now();
    let r = explore_with(&Config {
        max_states: Some(cap),
        canonical_debris: env("SUMCHAIN_MC_CANONICAL").is_some(),
        ..Config::exact(k, &set)
    });
    println!(
        "diag K={k} recoveries={}: {} states ({} halted, {} recovered, {} halted again after a recovery; up to height {}), {} transitions, depth {}, {} violations, {:?}",
        set.len(),
        r.states,
        r.halted_states,
        r.recovered_states,
        r.rehalted_states,
        r.max_height,
        r.transitions,
        r.max_depth,
        r.violations.len(),
        t0.elapsed()
    );
}

fn run(max_faults: u32) -> Report {
    run_with(&Config::exact(max_faults, &recoveries()))
}

fn run_with(c: &Config) -> Report {
    let t0 = std::time::Instant::now();
    let r = explore_with(c);
    println!(
        "model check K={}{}: {} states ({} at a height above 7, up to height {}; {} halted, {} recovered, {} halted again after a recovery), {} transitions, depth {}, up to {} released / {} issued messages, {} violations, {:?}",
        if c.max_faults == u32::MAX { "unbounded".to_string() } else { c.max_faults.to_string() },
        if c.canonical_debris { " (archive debris canonicalised)" } else { "" },
        r.states,
        r.advanced_states,
        r.max_height,
        r.halted_states,
        r.recovered_states,
        r.rehalted_states,
        r.transitions,
        r.max_depth,
        r.released,
        r.issued,
        r.violations.len(),
        t0.elapsed()
    );
    assert!(r.violations.is_empty(), "violations: {:#?}", r.violations);
    assert_eq!(
        r.rehalted_states, 0,
        "no proof here can halt a recovered signer"
    );
    r
}

/// Bounds of every run: heights 7–10 (initial working height 7), rounds 0–2
/// at height 7, 0–1 at height 8, 0 at heights 9 and 10; 15 signing requests,
/// 5 proofs and, in halted states, 7 recoveries; five fault modes at every
/// write; `K` faults per path.
#[test]
fn model_check_without_faults() {
    let r = run(0);
    assert!(
        r.states > 100,
        "the search reached too little: {}",
        r.states
    );
    assert!(
        r.max_height >= 9,
        "heights 8 and 9 were reached by advancement"
    );
    assert!(
        r.halted_states > 0,
        "a conflicting pair of proofs halted the signer"
    );
    assert!(r.recovered_states > 0, "a halted signer recovered");
    assert!(r.max_height >= 10, "height 10 was reached by recovery");
}

/// Release build; run with
/// `cargo test --release -p sumchain-finality-foundations --test signer_file_model_check -- --ignored --nocapture`.
#[test]
#[ignore]
fn model_check_up_to_one_fault_per_path() {
    let r = run(1);
    assert!(r.max_height >= 9);
    assert!(
        r.released >= 9,
        "messages at several heights were released on one path"
    );
}

/// Slow in a debug build; run with
/// `cargo test --release -p sumchain-finality-foundations --test signer_file_model_check -- --ignored --nocapture`.
#[test]
#[ignore]
fn model_check_up_to_two_faults_per_path() {
    run(2);
}

#[test]
#[ignore]
fn model_check_up_to_three_faults_per_path() {
    run(3);
}

/// No bound on faults per path: the whole reachable state space under any
/// sequence of faults, **with archive debris canonicalised**
/// ([`canonicalise_debris`]; exactness checked up to two faults by
/// `debris_canonicalisation_is_exact_up_to_two_faults`). The key excludes the
/// fault count, so the search ends when no new disk/signer/history state is
/// reachable.
#[test]
#[ignore]
fn model_check_with_unbounded_faults() {
    run_with(&Config {
        canonical_debris: true,
        ..Config::exact(u32::MAX, &recoveries())
    });
}

/// The abstraction used by the unbounded run is exact up to two faults per
/// path: the canonical image of the exact reachable set equals the set the
/// canonicalised search reaches, and neither search finds a violation.
/// Release build; slow.
#[test]
#[ignore]
fn debris_canonicalisation_is_exact_up_to_two_faults() {
    let all = recoveries();
    // `SUMCHAIN_MC_CROSSCHECK_MAX_K` limits the bounds (diagnostics); default 2.
    let max_k: u32 =
        std::env::var("SUMCHAIN_MC_CROSSCHECK_MAX_K").map_or(2, |v| v.parse().unwrap());
    for k in (1..=2).filter(|&k| k <= max_k) {
        let exact = explore_with(&Config {
            collect_image: true,
            ..Config::exact(k, &all)
        });
        let canon = explore_with(&Config {
            collect_image: true,
            canonical_debris: true,
            ..Config::exact(k, &all)
        });
        println!(
            "cross-check K={k}: exact search {} states, {} after canonicalisation; canonicalised search {} states ({} distinct); violations {} / {}",
            exact.states,
            exact.image.len(),
            canon.states,
            canon.image.len(),
            exact.violations.len(),
            canon.violations.len()
        );
        assert!(exact.violations.is_empty(), "{:#?}", exact.violations);
        assert!(canon.violations.is_empty(), "{:#?}", canon.violations);
        assert!(
            exact.image == canon.image,
            "K={k}: the canonicalisation is not exact ({} vs {} states)",
            exact.image.len(),
            canon.image.len()
        );
    }
}

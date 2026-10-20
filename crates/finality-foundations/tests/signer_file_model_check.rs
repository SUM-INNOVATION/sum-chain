//! PROPOSED signer persistence (A2 draft 3, UNRATIFIED): a bounded,
//! explicit-state model check of the recovery protocol and of proof-gated
//! height advancement.
//!
//! The system is the ratified G2-b signer core over the proposed file-backed
//! store and the disk model in `common` (volatile and durable file data,
//! volatile and durable directory entries, a durable synced mirror). From an
//! empty disk, a breadth-first search enumerates every reachable state under:
//!
//! * initialization, open and every request of a fixed alphabet over heights
//!   7, 8 and 9 (lock, relock, conflicting bytes, conflicting values,
//!   justified and unjustified lock-changing prevotes, nil precommit, votes
//!   at the next heights);
//! * every height advancement of a fixed proof alphabet, verified by an
//!   oracle that answers valid or invalid: valid proofs for heights 7 and 8,
//!   a second valid proof for height 7 naming another block (two verified
//!   proofs in conflict), a stale proof for height 6, and a forged one;
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
//! * **liveness of recovery:** no fault sequence leaves a state that refuses
//!   to open.
//!
//! Assumptions: one process; ownership is the lock trait; the oracle is sound
//! (a "valid" answer means a real certificate exists); the disk model's
//! durability rules; no whole-directory rollback; no cloned keys.
//!
//! Signatures here are a keyed hash, not Ed25519: the properties are about
//! what is released and persisted, not about signature validity.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::rc::Rc;

use sumchain_finality_foundations::signer::{
    initialize_exclusive, DurableSigner, Justification, SignPosition, SignRequest, SignerError,
    SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{
    floor_below_height, sign_bytes_digest, FileSignerStore, SignerState, STATE_FILE,
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
type Signer = DurableSigner<Store, HashKey, TestPolka, MemGuard>;

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
    DurableSigner::open(owner, store(disk), HashKey, TestPolka, None)
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

/// The request alphabet: eleven requests over seven positions, exercising
/// every lock rule.
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
    ]
}

/// The proof alphabet, with the oracle's verdict: `Some((height, block))` for
/// a valid proof, `None` for a forged one.
fn proofs() -> Vec<(Vec<u8>, Option<(u64, Digest)>)> {
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

fn durable_state(m: &Model) -> Option<SignerState> {
    let id = *m.dir_dur.get(STATE_FILE)?;
    SignerState::decode(&m.inodes[id].dur, &B3)
        .ok()
        .map(|(s, _)| s)
}

/// I4 and H2 on an open signer: never below an issued position; at the
/// height of the latest issued lock, never an older lock; above it, only with
/// a valid proof for that height or higher.
fn check_open(n: &Node, s: &Signer, violations: &mut Vec<String>) {
    let rec = s.record();
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

/// I5 and I4b when `q` becomes issued (released, or durably persisted).
fn issue(n: &mut Node, q: &SignRequest, violations: &mut Vec<String>) {
    let p = q.position;
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
    violations: Vec<String>,
}

#[derive(Clone)]
enum Action {
    Init,
    Open,
    Sign(SignRequest),
    /// A height advancement, with the oracle's verdict on the proof.
    Advance(Vec<u8>, Option<(u64, Digest)>),
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
        if let Some((h, _)) = verdict {
            if next.ghost.valid_proof_max.is_none_or(|m| m < *h) {
                next.ghost.valid_proof_max = Some(*h);
            }
        }
    }
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
            // A refused request or advancement changes nothing.
            (Action::Sign(_) | Action::Advance(..), _) => {
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
    if let (Action::Advance(_, Some((h, b))), Status::Open, false) = (action, next.status, fired) {
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
    Some((next, ops))
}

/// Explore every state reachable with at most `max_faults` faults per path.
fn explore(max_faults: u32) -> Report {
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
        violations: Vec::new(),
    };

    while let Some((node, depth)) = queue.pop_front() {
        report.states += 1;
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
                match open(&disk, &MemOwnership::default()) {
                    Ok(s) => {
                        if disk.borrow().ops != 0 {
                            v.push("an open state needed a repair".into());
                        }
                        check_open(&node, &s, &mut v);
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
        for s in successors {
            report.transitions += 1;
            if s.faults > max_faults {
                continue;
            }
            let key = node_key(&s);
            if seen.get(&key).is_some_and(|&f| f <= s.faults) {
                continue;
            }
            seen.insert(key, s.faults);
            queue.push_back((s, depth + 1));
        }
        if report.violations.len() > 20 {
            break;
        }
    }
    report
}

fn run(max_faults: u32) -> Report {
    let r = explore(max_faults);
    println!(
        "model check K={}: {} states ({} at a height above 7, up to height {}), {} transitions, depth {}, up to {} released / {} issued messages, {} violations",
        if max_faults == u32::MAX { "unbounded".to_string() } else { max_faults.to_string() },
        r.states,
        r.advanced_states,
        r.max_height,
        r.transitions,
        r.max_depth,
        r.released,
        r.issued,
        r.violations.len()
    );
    assert!(r.violations.is_empty(), "violations: {:#?}", r.violations);
    r
}

/// Bounds of every run: heights 7–9 (initial working height 7), rounds 0–2 at
/// height 7, 0–1 at height 8, 0 at height 9; 14 signing requests and 5
/// proofs; five fault modes at every write; `K` faults per path.
#[test]
fn model_check_up_to_one_fault_per_path() {
    let r = run(1);
    assert!(
        r.states > 1000,
        "the search reached too little: {}",
        r.states
    );
    assert!(
        r.max_height >= 9,
        "heights 8 and 9 were reached by advancement"
    );
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
/// sequence of faults. The key excludes the fault count, so the search ends
/// when no new disk/signer/history state is reachable.
#[test]
#[ignore]
fn model_check_with_unbounded_faults() {
    run(u32::MAX);
}

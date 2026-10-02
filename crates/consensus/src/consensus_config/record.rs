//! The persisted baseline, its append-only transition history, the startup
//! comparison and the stopped-node acknowledgement.
//!
//! # Keys (`cf::META`)
//!
//! ```text
//! consensus_config/v1/record                 the current baseline
//! consensus_config/v1/transition/<seq:u64 BE>  one per accepted change, seq from 1
//! ```
//!
//! # Record
//!
//! ```text
//! record_version:u16 = 1 ‖ status:u8 ‖ baseline_height:u64
//!   ‖ initial_commitment[32] ‖ transition_count:u64 ‖ commitment[32]
//!   ‖ encoding_len:u32 ‖ encoding
//! ```
//!
//! # Transition
//!
//! ```text
//! transition_version:u16 = 1 ‖ seq:u64 ‖ kind:u8 ‖ at_height:u64
//!   ‖ old_commitment[32] ‖ new_commitment[32]
//!   ‖ changed_count:u16 ‖ changed_id:u16*
//!   ‖ old_encoding_len:u32 ‖ old_encoding
//! ```
//!
//! Integers little-endian. The record and the transition that produced it are
//! always written in ONE durable batch, so the history and the baseline cannot
//! disagree after a crash, and every start re-verifies that they agree: the
//! transitions form an unbroken chain from `initial_commitment` to
//! `commitment`, each carrying the encoding it replaced. Nothing in this module
//! deletes a transition.

use sumchain_genesis::Genesis;
use sumchain_primitives::Hash;
use sumchain_storage::{cf, Database};

use super::codec::{commitment_of, ConsensusConfig, FieldChange};
use super::fields::{build, is_gate, is_identity_or_rule, recorded_gates};
use super::ConfigError;

/// Where the baseline lives.
pub const RECORD_KEY: &[u8] = b"consensus_config/v1/record";

/// Prefix of every transition entry.
pub const TRANSITION_PREFIX: &[u8] = b"consensus_config/v1/transition/";

const RECORD_VERSION: u16 = 1;
const TRANSITION_VERSION: u16 = 1;

/// Upper bound on the transition history a start will walk. Each entry carries
/// the encoding it replaced (a few KiB), so this bounds a start's memory as
/// well. A history this long is not an operator's; it is a damaged database.
const MAX_TRANSITIONS: u64 = 10_000;

/// What the stored baseline is.
///
/// One status exists. It is a number rather than an implicit fact so that a
/// later release, which binds the commitment to an authenticated network
/// agreement, has a value to move to and a reader of an old record cannot
/// mistake it for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineStatus {
    /// What THIS node computed from its own genesis and binary. It describes
    /// what the node runs. It is not evidence that any other node runs the same
    /// thing, and nothing in this release treats it as such.
    UnverifiedLocalBaseline,
}

impl BaselineStatus {
    fn code(self) -> u8 {
        match self {
            BaselineStatus::UnverifiedLocalBaseline => 1,
        }
    }
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(BaselineStatus::UnverifiedLocalBaseline),
            _ => None,
        }
    }
    /// The label the logs and the RPC use.
    pub fn label(self) -> &'static str {
        match self {
            BaselineStatus::UnverifiedLocalBaseline => "unverified-local-baseline",
        }
    }
}

/// Why a transition was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionKind {
    /// Only activation heights of gates still ahead of the chain changed, which
    /// the existing gate rule permits. Recorded automatically at start.
    GateReschedule,
    /// An operator acknowledged the change with the stopped-node command, naming
    /// both commitments.
    OperatorAcknowledged,
}

impl TransitionKind {
    fn code(self) -> u8 {
        match self {
            TransitionKind::GateReschedule => 1,
            TransitionKind::OperatorAcknowledged => 2,
        }
    }
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(TransitionKind::GateReschedule),
            2 => Some(TransitionKind::OperatorAcknowledged),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            TransitionKind::GateReschedule => "gate-reschedule",
            TransitionKind::OperatorAcknowledged => "operator-acknowledged",
        }
    }
}

/// The stored baseline, decoded and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineRecord {
    pub status: BaselineStatus,
    /// Chain height when this database first recorded a baseline.
    pub baseline_height: u64,
    /// The commitment recorded then.
    pub initial_commitment: Hash,
    /// Number of transitions since.
    pub transition_count: u64,
    /// The current commitment.
    pub commitment: Hash,
    /// The configuration it commits to.
    pub config: ConsensusConfig,
}

/// One entry of the transition history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub seq: u64,
    pub kind: TransitionKind,
    pub at_height: u64,
    pub old_commitment: Hash,
    pub new_commitment: Hash,
    pub changed_ids: Vec<u16>,
    pub old_encoding: Vec<u8>,
}

/// What the startup check did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupOutcome {
    /// No baseline existed; one was recorded.
    Initialized {
        commitment: Hash,
        baseline_height: u64,
    },
    /// The configuration matches the baseline exactly.
    Unchanged { commitment: Hash },
    /// Only future gates moved; the change was recorded as a transition.
    GatesRescheduled {
        from: Hash,
        to: Hash,
        changes: Vec<FieldChange>,
    },
}

/// What an acknowledgement did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledged {
    pub seq: u64,
    pub from: Hash,
    pub to: Hash,
    pub changes: Vec<FieldChange>,
}

/// Read and verify the stored baseline, or `None` if this database has never
/// recorded one.
///
/// "Never recorded" means the key is absent. A key that is present and fails
/// any check — framing, schema, commitment, or the transition chain — is an
/// error, never `None`: treating a damaged record as a first start would
/// replace the one record that can show the rules changed.
pub fn read_record(db: &Database) -> Result<Option<BaselineRecord>, ConfigError> {
    let raw = match db.get(cf::META, RECORD_KEY).map_err(|e| {
        ConfigError::Storage(format!("reading the consensus configuration record: {e}"))
    })? {
        None => return Ok(None),
        Some(raw) => raw,
    };
    let record = decode_record(&raw)?;
    verify_history(db, &record)?;
    Ok(Some(record))
}

/// Read the transition history, oldest first, verified against the record.
pub fn read_transitions(db: &Database) -> Result<Vec<Transition>, ConfigError> {
    match read_record(db)? {
        None => Ok(Vec::new()),
        Some(record) => verify_history(db, &record),
    }
}

/// The startup comparison. Runs after the genesis and activation-height checks
/// and before anything that processes a block exists.
///
/// * No baseline: compute, record it as an unverified local baseline at
///   `current_height`, continue. A write failure refuses startup.
/// * Exact match: continue.
/// * Only gates still ahead of the chain changed, as the existing gate rule
///   permits: record a [`TransitionKind::GateReschedule`] transition, continue.
/// * A gate the chain has passed changed: refuse. No acknowledgement can permit
///   this.
/// * Anything else changed: refuse, with the field-level difference and both
///   commitments, naming the acknowledgement command.
pub fn check_at_startup(
    db: &Database,
    genesis: &Genesis,
    current_height: u64,
) -> Result<StartupOutcome, ConfigError> {
    let now = build(genesis)?;
    let now_commitment = now.commitment();

    let Some(record) = read_record(db)? else {
        write_initial(db, &now, current_height)?;
        return Ok(StartupOutcome::Initialized {
            commitment: now_commitment,
            baseline_height: current_height,
        });
    };

    if record.commitment == now_commitment {
        return Ok(StartupOutcome::Unchanged {
            commitment: now_commitment,
        });
    }

    let changes = record.config.diff(&now);
    refuse_retroactive_gates(genesis, &record.config, &changes, current_height)?;

    let non_gate: Vec<&FieldChange> = changes.iter().filter(|c| !is_gate(c.id)).collect();
    if !non_gate.is_empty() {
        return Err(ConfigError::Refused(format!(
            "the consensus configuration this node computes differs from the baseline \
             recorded in its database in {} field(s) that are not future activation \
             heights: {}. Recorded commitment {}, computed commitment {}. If this change \
             is the intended result of a coordinated binary or genesis change, stop the \
             node and run `sumchain acknowledge-consensus-config --old {} --new {}`; \
             otherwise restore the previous binary or genesis.json. The acknowledgement \
             is local: it records that this operator accepted the change, it does not \
             make any other node agree.",
            non_gate.len(),
            join(&non_gate),
            record.commitment,
            now_commitment,
            record.commitment,
            now_commitment,
        )));
    }

    append_transition(
        db,
        &record,
        &now,
        TransitionKind::GateReschedule,
        current_height,
        &changes,
    )?;
    Ok(StartupOutcome::GatesRescheduled {
        from: record.commitment,
        to: now_commitment,
        changes,
    })
}

/// The stopped-node acknowledgement.
///
/// The caller holds the database open, which holds RocksDB's exclusive lock: a
/// running node and this command cannot both have it. `genesis` must already
/// have passed the same validation a node start performs.
///
/// Accepts only when ALL of these hold:
/// * a baseline exists and verifies;
/// * `expected_old` is exactly the recorded commitment;
/// * `expected_new` is exactly the commitment of the configuration THIS binary
///   computes from `genesis`, and differs from the old one;
/// * no gate the chain has passed changed (the existing gate rule);
/// * neither the chain identity nor a consensus rule code changed — those are
///   a different chain or a protocol upgrade, which a local acknowledgement
///   cannot authorize.
pub fn acknowledge(
    db: &Database,
    genesis: &Genesis,
    current_height: u64,
    expected_old: Hash,
    expected_new: Hash,
) -> Result<Acknowledged, ConfigError> {
    let record = read_record(db)?.ok_or_else(|| {
        ConfigError::Refused(
            "this database has no consensus configuration baseline, so there is nothing \
             to acknowledge; the next node start records one"
                .to_string(),
        )
    })?;
    if record.commitment != expected_old {
        return Err(ConfigError::Refused(format!(
            "--old {expected_old} is not the recorded commitment {}",
            record.commitment
        )));
    }
    let now = build(genesis)?;
    let now_commitment = now.commitment();
    if now_commitment != expected_new {
        return Err(ConfigError::Refused(format!(
            "--new {expected_new} is not the commitment this binary computes from this \
             genesis, {now_commitment}"
        )));
    }
    if now_commitment == record.commitment {
        return Err(ConfigError::Refused(
            "the computed configuration already matches the baseline; nothing to acknowledge"
                .to_string(),
        ));
    }

    let changes = record.config.diff(&now);
    refuse_retroactive_gates(genesis, &record.config, &changes, current_height)?;
    let protected: Vec<&FieldChange> = changes
        .iter()
        .filter(|c| is_identity_or_rule(c.id))
        .collect();
    if !protected.is_empty() {
        return Err(ConfigError::Refused(format!(
            "the change touches the chain identity or a consensus rule code: {}. That is \
             a different chain or a protocol upgrade, and a local acknowledgement cannot \
             authorize either",
            join(&protected)
        )));
    }

    let seq = append_transition(
        db,
        &record,
        &now,
        TransitionKind::OperatorAcknowledged,
        current_height,
        &changes,
    )?;
    Ok(Acknowledged {
        seq,
        from: record.commitment,
        to: now_commitment,
        changes,
    })
}

fn refuse_retroactive_gates(
    genesis: &Genesis,
    recorded: &ConsensusConfig,
    changes: &[FieldChange],
    current_height: u64,
) -> Result<(), ConfigError> {
    if !changes.iter().any(|c| is_gate(c.id)) {
        return Ok(());
    }
    // The existing rule, applied to the heights THIS record holds. Normally the
    // activation-height check has already refused these; repeating it against
    // this record keeps the two from drifting apart and covers a database whose
    // activation record was removed.
    let refused: Vec<String> = genesis
        .params
        .activation_changes(&recorded_gates(recorded), current_height)
        .into_iter()
        .filter(|c| !c.is_permitted())
        .map(|c| c.to_string())
        .collect();
    if refused.is_empty() {
        return Ok(());
    }
    Err(ConfigError::Refused(format!(
        "activation heights changed for gates this chain has already passed at height \
         {current_height}: {}. No acknowledgement can permit this; restore the previous \
         genesis.json or re-sync from genesis",
        refused.join("; ")
    )))
}

fn join(changes: &[&FieldChange]) -> String {
    changes
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

fn write_initial(db: &Database, config: &ConsensusConfig, height: u64) -> Result<(), ConfigError> {
    let commitment = config.commitment();
    let record = BaselineRecord {
        status: BaselineStatus::UnverifiedLocalBaseline,
        baseline_height: height,
        initial_commitment: commitment,
        transition_count: 0,
        commitment,
        config: config.clone(),
    };
    let mut batch = db.batch();
    batch
        .put(cf::META, RECORD_KEY, &encode_record(&record))
        .map_err(|e| ConfigError::Storage(format!("staging the baseline: {e}")))?;
    batch.commit_durable().map_err(|e| {
        ConfigError::Storage(format!(
            "recording the consensus configuration baseline failed ({e}); refusing to \
             start without it"
        ))
    })
}

fn append_transition(
    db: &Database,
    record: &BaselineRecord,
    now: &ConsensusConfig,
    kind: TransitionKind,
    at_height: u64,
    changes: &[FieldChange],
) -> Result<u64, ConfigError> {
    let seq = record.transition_count + 1;
    let transition = Transition {
        seq,
        kind,
        at_height,
        old_commitment: record.commitment,
        new_commitment: now.commitment(),
        changed_ids: changes.iter().map(|c| c.id).collect(),
        old_encoding: record.config.encode(),
    };
    let next = BaselineRecord {
        status: record.status,
        baseline_height: record.baseline_height,
        initial_commitment: record.initial_commitment,
        transition_count: seq,
        commitment: now.commitment(),
        config: now.clone(),
    };
    let mut batch = db.batch();
    batch
        .put(
            cf::META,
            &transition_key(seq),
            &encode_transition(&transition),
        )
        .and_then(|_| batch.put(cf::META, RECORD_KEY, &encode_record(&next)))
        .map_err(|e| ConfigError::Storage(format!("staging the transition: {e}")))?;
    batch.commit_durable().map_err(|e| {
        ConfigError::Storage(format!(
            "recording consensus configuration transition {seq}: {e}"
        ))
    })?;
    Ok(seq)
}

fn transition_key(seq: u64) -> Vec<u8> {
    let mut k = TRANSITION_PREFIX.to_vec();
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Verify the transition chain behind `record` and return it.
fn verify_history(db: &Database, record: &BaselineRecord) -> Result<Vec<Transition>, ConfigError> {
    let corrupt = |why: String| ConfigError::RecordCorrupt(why);
    if record.transition_count > MAX_TRANSITIONS {
        return Err(corrupt(format!(
            "record claims {} transitions, above the {MAX_TRANSITIONS} bound",
            record.transition_count
        )));
    }

    // Every key under the prefix, so an entry beyond the recorded count — a
    // history the record does not account for — is caught rather than ignored.
    let mut stored = Vec::new();
    for entry in db
        .prefix_iter_checked(cf::META, TRANSITION_PREFIX)
        .map_err(|e| ConfigError::Storage(format!("scanning transitions: {e}")))?
    {
        let (key, value) =
            entry.map_err(|e| ConfigError::Storage(format!("reading a transition: {e}")))?;
        if !key.starts_with(TRANSITION_PREFIX) {
            break;
        }
        if stored.len() as u64 >= MAX_TRANSITIONS {
            return Err(corrupt("transition history exceeds its bound".to_string()));
        }
        stored.push((key.to_vec(), value.to_vec()));
    }
    if stored.len() as u64 != record.transition_count {
        return Err(corrupt(format!(
            "record names {} transition(s), database holds {}",
            record.transition_count,
            stored.len()
        )));
    }

    let mut out = Vec::with_capacity(stored.len());
    let mut expected_old = record.initial_commitment;
    for (i, (key, value)) in stored.iter().enumerate() {
        let seq = i as u64 + 1;
        if key.as_slice() != transition_key(seq).as_slice() {
            return Err(corrupt(format!("transition {seq} is missing or misplaced")));
        }
        let t = decode_transition(value)?;
        if t.seq != seq {
            return Err(corrupt(format!(
                "transition stored at {seq} names itself {}",
                t.seq
            )));
        }
        if t.old_commitment != expected_old {
            return Err(corrupt(format!(
                "transition {seq} starts from {} but the history reached {expected_old}",
                t.old_commitment
            )));
        }
        if commitment_of(&t.old_encoding) != t.old_commitment {
            return Err(corrupt(format!(
                "transition {seq} carries an encoding that does not match its commitment"
            )));
        }
        expected_old = t.new_commitment;
        out.push(t);
    }
    if expected_old != record.commitment {
        return Err(corrupt(format!(
            "the transition history ends at {expected_old} but the record holds {}",
            record.commitment
        )));
    }
    Ok(out)
}

fn encode_record(r: &BaselineRecord) -> Vec<u8> {
    let encoding = r.config.encode();
    let mut out = Vec::with_capacity(96 + encoding.len());
    out.extend_from_slice(&RECORD_VERSION.to_le_bytes());
    out.push(r.status.code());
    out.extend_from_slice(&r.baseline_height.to_le_bytes());
    out.extend_from_slice(r.initial_commitment.as_bytes());
    out.extend_from_slice(&r.transition_count.to_le_bytes());
    out.extend_from_slice(r.commitment.as_bytes());
    out.extend_from_slice(&(encoding.len() as u32).to_le_bytes());
    out.extend_from_slice(&encoding);
    out
}

fn decode_record(raw: &[u8]) -> Result<BaselineRecord, ConfigError> {
    let mut r = Cursor::new(raw);
    let version = r.u16()?;
    if version != RECORD_VERSION {
        return Err(ConfigError::RecordCorrupt(format!(
            "record version {version} is not one this binary reads; it may have been \
             written by a newer binary"
        )));
    }
    let status = BaselineStatus::from_code(r.u8()?)
        .ok_or_else(|| ConfigError::RecordCorrupt("unknown baseline status".to_string()))?;
    let baseline_height = r.u64()?;
    let initial_commitment = r.hash()?;
    let transition_count = r.u64()?;
    let commitment = r.hash()?;
    let len = r.u32()? as usize;
    let encoding = r.take(len)?;
    r.finish()?;
    let config = ConsensusConfig::decode(encoding).map_err(|e| match e {
        ConfigError::UnknownSchema(s) => ConfigError::RecordCorrupt(format!(
            "the baseline uses configuration schema {s}, which this binary does not \
             implement; it was written by a newer binary"
        )),
        other => ConfigError::RecordCorrupt(format!("the baseline encoding is invalid: {other}")),
    })?;
    if commitment_of(encoding) != commitment {
        return Err(ConfigError::RecordCorrupt(
            "the baseline encoding does not match its recorded commitment".to_string(),
        ));
    }
    if transition_count == 0 && initial_commitment != commitment {
        return Err(ConfigError::RecordCorrupt(
            "no transitions recorded, yet the commitment moved from its initial value".to_string(),
        ));
    }
    Ok(BaselineRecord {
        status,
        baseline_height,
        initial_commitment,
        transition_count,
        commitment,
        config,
    })
}

fn encode_transition(t: &Transition) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + t.old_encoding.len());
    out.extend_from_slice(&TRANSITION_VERSION.to_le_bytes());
    out.extend_from_slice(&t.seq.to_le_bytes());
    out.push(t.kind.code());
    out.extend_from_slice(&t.at_height.to_le_bytes());
    out.extend_from_slice(t.old_commitment.as_bytes());
    out.extend_from_slice(t.new_commitment.as_bytes());
    out.extend_from_slice(&(t.changed_ids.len() as u16).to_le_bytes());
    for id in &t.changed_ids {
        out.extend_from_slice(&id.to_le_bytes());
    }
    out.extend_from_slice(&(t.old_encoding.len() as u32).to_le_bytes());
    out.extend_from_slice(&t.old_encoding);
    out
}

fn decode_transition(raw: &[u8]) -> Result<Transition, ConfigError> {
    let mut r = Cursor::new(raw);
    let version = r.u16()?;
    if version != TRANSITION_VERSION {
        return Err(ConfigError::RecordCorrupt(format!(
            "transition version {version} is not one this binary reads"
        )));
    }
    let seq = r.u64()?;
    let kind = TransitionKind::from_code(r.u8()?)
        .ok_or_else(|| ConfigError::RecordCorrupt("unknown transition kind".to_string()))?;
    let at_height = r.u64()?;
    let old_commitment = r.hash()?;
    let new_commitment = r.hash()?;
    let n = r.u16()? as usize;
    let mut changed_ids = Vec::with_capacity(n);
    for _ in 0..n {
        changed_ids.push(r.u16()?);
    }
    let len = r.u32()? as usize;
    let old_encoding = r.take(len)?.to_vec();
    r.finish()?;
    Ok(Transition {
        seq,
        kind,
        at_height,
        old_commitment,
        new_commitment,
        changed_ids,
        old_encoding,
    })
}

struct Cursor<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ConfigError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.raw.len())
            .ok_or_else(|| ConfigError::RecordCorrupt("truncated record".to_string()))?;
        let out = &self.raw[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, ConfigError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ConfigError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, ConfigError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, ConfigError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn hash(&mut self) -> Result<Hash, ConfigError> {
        let b: [u8; 32] = self.take(32)?.try_into().expect("32 bytes");
        Ok(Hash::from(b))
    }
    fn finish(&self) -> Result<(), ConfigError> {
        if self.pos == self.raw.len() {
            Ok(())
        } else {
            Err(ConfigError::RecordCorrupt(format!(
                "{} trailing byte(s) in a stored record",
                self.raw.len() - self.pos
            )))
        }
    }
}

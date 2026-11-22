//! The persisted baseline, its append-only transition history, the startup
//! comparison, the stopped-node acknowledgement and the stopped-node schema
//! transition.
//!
//! # Keys (`cf::META`)
//!
//! ```text
//! consensus_config/v1/record                 the current baseline
//! consensus_config/v1/transition/<seq:u64 BE>  one per accepted change, seq from 1
//! ```
//!
//! The `v1` in the keys names this record LAYOUT, not the configuration
//! schema: a record of any schema is stored under the same key, and the schema
//! is the one its encoding declares.
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
//! deletes a transition, with one exception: [`revert_schema_transition`]
//! removes the schema transition it undoes, and only on a node whose chain
//! has not moved past the height the move was made at.
//!
//! # Schemas
//!
//! The record and transition layouts are unchanged by a new configuration
//! schema. A binary refuses a record whose encoding declares a schema it does
//! not read (see [`super::schema::SchemaPolicy`]) — the same refusal an
//! older binary applies to a newer record. Every comparison is made in the
//! schema the record holds. Moving the record to a newer schema is
//! [`acknowledge_schema_transition`]: a stopped-node command naming both
//! commitments, recorded as a [`TransitionKind::SchemaTransition`] that keeps
//! the old encoding, never an implicit re-encoding at start.
//!
//! # Before the first start after a move
//!
//! A binary that does not read the newer schema refuses the moved record. A
//! move that has to be abandoned before the node runs on it — the window is
//! aborted after the move and before the first normal start — is undone with
//! [`revert_schema_transition`], a stopped-node command naming both
//! commitments. It writes back exactly the record the move replaced, which the
//! transition kept, and removes that transition: the configuration rows are
//! then byte for byte what they were before the move. It is refused unless the
//! last transition is that move, into the schema this binary writes, no normal
//! start has been attempted since ([`super::start_marker`]: the marker every
//! start writes first is absent, or predates the move), and the chain is still
//! exactly at the height the move was made at, with no block above it. It
//! touches no block, no state and no row outside the configuration record and
//! that one transition, so it rewinds nothing. Once a normal start has been
//! attempted on the moved record — whether it then ran, imported nothing or was
//! refused by a later check — recovery is forward only: a binary that reads the
//! newer schema. The marker, not the chain height, is what decides that, so a
//! later rewind to the move's height does not reopen the revert.

use sumchain_genesis::Genesis;
use sumchain_primitives::Hash;
use sumchain_storage::schema::BlockStore;
use sumchain_storage::{cf, Database};

use super::codec::{commitment_of, ConsensusConfig, FieldChange};
use super::fields::{compute, is_gate, is_identity_or_rule, recorded_gates};
use super::schema::{Schema, SchemaPolicy, PRODUCTION};
use super::start_marker::{read_start_marker, RecordState, StartMarker};
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
    /// An operator moved the record to a later schema with the stopped-node
    /// schema transition, naming both commitments. The rules are unchanged:
    /// the new configuration is the old one with every added field absent.
    /// `changed_ids` lists the added fields.
    SchemaTransition,
}

impl TransitionKind {
    fn code(self) -> u8 {
        match self {
            TransitionKind::GateReschedule => 1,
            TransitionKind::OperatorAcknowledged => 2,
            TransitionKind::SchemaTransition => 3,
        }
    }
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(TransitionKind::GateReschedule),
            2 => Some(TransitionKind::OperatorAcknowledged),
            3 => Some(TransitionKind::SchemaTransition),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            TransitionKind::GateReschedule => "gate-reschedule",
            TransitionKind::OperatorAcknowledged => "operator-acknowledged",
            TransitionKind::SchemaTransition => "schema-transition",
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

/// What a schema transition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaTransitioned {
    pub seq: u64,
    pub from_schema: u16,
    pub to_schema: u16,
    pub from: Hash,
    pub to: Hash,
    /// The fields the new schema adds, all recorded absent.
    pub added: Vec<u16>,
}

/// A pre-start revert of a schema transition this binary could perform on
/// this database ([`pending_schema_revert`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSchemaRevert {
    /// The transition that would be removed: the record's last.
    pub seq: u64,
    /// The chain height the move was made at, and still is.
    pub at_height: u64,
    /// The chain head now: the block at `at_height`.
    pub head_hash: Option<Hash>,
    /// The start marker this database holds, which predates the move (a
    /// marker written at or after it refuses the revert).
    pub start_marker: Option<StartMarker>,
    /// The schema the record holds now.
    pub from_schema: u16,
    /// The schema the move came from, which the revert restores.
    pub to_schema: u16,
    /// The recorded commitment: `--old`.
    pub old: Hash,
    /// The commitment the move replaced, which the revert restores: `--new`.
    pub new: Hash,
}

/// What a pre-start revert did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaReverted {
    /// The transition removed.
    pub seq: u64,
    pub at_height: u64,
    pub from_schema: u16,
    pub to_schema: u16,
    pub from: Hash,
    pub to: Hash,
}

/// A schema transition this binary could perform on this database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSchemaTransition {
    pub from_schema: u16,
    pub to_schema: u16,
    /// The recorded commitment: `--old`.
    pub old: Hash,
    /// The commitment of the record carried into the new schema: `--new`.
    pub new: Hash,
}

/// Read and verify the stored baseline, or `None` if this database has never
/// recorded one.
///
/// "Never recorded" means the key is absent. A key that is present and fails
/// any check — framing, schema, commitment, or the transition chain — is an
/// error, never `None`: treating a damaged record as a first start would
/// replace the one record that can show the rules changed.
pub fn read_record(db: &Database) -> Result<Option<BaselineRecord>, ConfigError> {
    read_record_with(db, &PRODUCTION)
}

/// [`read_record`] under `policy`.
pub fn read_record_with(
    db: &Database,
    policy: &SchemaPolicy,
) -> Result<Option<BaselineRecord>, ConfigError> {
    let raw = match db.get(cf::META, RECORD_KEY).map_err(|e| {
        ConfigError::Storage(format!("reading the consensus configuration record: {e}"))
    })? {
        None => return Ok(None),
        Some(raw) => raw,
    };
    let record = decode_record(&raw, policy)?;
    verify_history(db, &record, policy)?;
    Ok(Some(record))
}

/// Read the transition history, oldest first, verified against the record.
pub fn read_transitions(db: &Database) -> Result<Vec<Transition>, ConfigError> {
    read_transitions_with(db, &PRODUCTION)
}

/// [`read_transitions`] under `policy`.
pub fn read_transitions_with(
    db: &Database,
    policy: &SchemaPolicy,
) -> Result<Vec<Transition>, ConfigError> {
    match read_record_with(db, policy)? {
        None => Ok(Vec::new()),
        Some(record) => verify_history(db, &record, policy),
    }
}

/// The configuration this binary computes from `genesis`, in `schema`.
///
/// A non-absent value of a field `schema` does not have is a refusal: the
/// record cannot describe that rule. When `policy` writes a schema that has
/// the field, the refusal names the schema transition; when even that schema
/// cannot express it, moving the record would not help, and the refusal says
/// the field must stay absent.
fn computed_in(
    genesis: &Genesis,
    policy: &SchemaPolicy,
    schema: &'static Schema,
    record: Option<&BaselineRecord>,
) -> Result<ConsensusConfig, ConfigError> {
    let values = compute(genesis, policy)?;
    let writable = !matches!(
        ConsensusConfig::project(values.clone(), policy.knows, policy.writes),
        Err(ConfigError::BeyondSchema { .. })
    );
    ConsensusConfig::project(values, policy.knows, schema).map_err(|e| match e {
        ConfigError::BeyondSchema { schema: n, fields } => {
            let how = match (record, pending_schema_transition_for(record, policy)) {
                (Some(r), Some(p)) if writable => format!(
                    "This database records schema {n}; this binary can move it to \
                     schema {to}. Stop the node and run `sumchain \
                     acknowledge-consensus-config-schema --old {old} --new {new}` (it \
                     re-encodes the recorded rules and changes none), then start again; \
                     or restore the previous genesis.json",
                    to = p.to_schema,
                    old = r.commitment,
                    new = p.new,
                ),
                _ => format!(
                    "This binary records schema {w} and can register those fields but \
                     not activate them; they must stay absent",
                    w = policy.writes.number
                ),
            };
            ConfigError::Refused(format!(
                "the genesis sets {fields}, which schema {n} cannot express. {how}"
            ))
        }
        other => other,
    })
}

/// The schema transition `policy` could perform on `record`, an already read
/// and verified record ([`read_record_with`]), if any. Lets a caller that has
/// just read the record avoid reading and verifying it again; the answer is
/// that of [`pending_schema_transition_with`] over the same database.
pub fn pending_schema_transition_for(
    record: Option<&BaselineRecord>,
    policy: &SchemaPolicy,
) -> Option<PendingSchemaTransition> {
    let r = record?;
    let from = r.config.schema();
    if std::ptr::eq(from, policy.writes) || !policy.writes.extends(from) {
        return None;
    }
    let to = r.config.extend_to(policy.writes).ok()?;
    Some(PendingSchemaTransition {
        from_schema: from.number,
        to_schema: policy.writes.number,
        old: r.commitment,
        new: to.commitment(),
    })
}

/// The schema transition this binary could perform on this database, if any:
/// its record is of an older schema than the one this binary writes.
pub fn pending_schema_transition(
    db: &Database,
) -> Result<Option<PendingSchemaTransition>, ConfigError> {
    pending_schema_transition_with(db, &PRODUCTION)
}

/// [`pending_schema_transition`] under `policy`.
pub fn pending_schema_transition_with(
    db: &Database,
    policy: &SchemaPolicy,
) -> Result<Option<PendingSchemaTransition>, ConfigError> {
    Ok(pending_schema_transition_for(
        read_record_with(db, policy)?.as_ref(),
        policy,
    ))
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
///
/// Every comparison is made in the schema the record holds. A stored record of
/// an older schema than this binary writes is compared as it stands and never
/// re-encoded here; a value that only the newer schema can express refuses,
/// naming [`acknowledge_schema_transition`].
pub fn check_at_startup(
    db: &Database,
    genesis: &Genesis,
    current_height: u64,
) -> Result<StartupOutcome, ConfigError> {
    check_at_startup_with(db, genesis, current_height, &PRODUCTION)
}

/// [`check_at_startup`] under `policy`.
pub fn check_at_startup_with(
    db: &Database,
    genesis: &Genesis,
    current_height: u64,
    policy: &SchemaPolicy,
) -> Result<StartupOutcome, ConfigError> {
    let Some(record) = read_record_with(db, policy)? else {
        // A fresh baseline is recorded in the schema this binary writes.
        let now = computed_in(genesis, policy, policy.writes, None)?;
        let now_commitment = now.commitment();
        write_initial(db, &now, current_height)?;
        return Ok(StartupOutcome::Initialized {
            commitment: now_commitment,
            baseline_height: current_height,
        });
    };
    let now = computed_in(genesis, policy, record.config.schema(), Some(&record))?;
    let now_commitment = now.commitment();

    if record.commitment == now_commitment {
        return Ok(StartupOutcome::Unchanged {
            commitment: now_commitment,
        });
    }

    let changes = record.config.diff(&now)?;
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
///
/// The change is acknowledged in the schema the record holds; moving the
/// record to another schema is [`acknowledge_schema_transition`] and is never
/// combined with a change of rules.
pub fn acknowledge(
    db: &Database,
    genesis: &Genesis,
    current_height: u64,
    expected_old: Hash,
    expected_new: Hash,
) -> Result<Acknowledged, ConfigError> {
    acknowledge_with(
        db,
        genesis,
        current_height,
        expected_old,
        expected_new,
        &PRODUCTION,
    )
}

/// [`acknowledge`] under `policy`.
pub fn acknowledge_with(
    db: &Database,
    genesis: &Genesis,
    current_height: u64,
    expected_old: Hash,
    expected_new: Hash,
    policy: &SchemaPolicy,
) -> Result<Acknowledged, ConfigError> {
    let record = read_record_with(db, policy)?.ok_or_else(|| {
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
    let now = computed_in(genesis, policy, record.config.schema(), Some(&record))?;
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

    let changes = record.config.diff(&now)?;
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

/// The stopped-node schema transition: move the recorded baseline to the
/// schema this binary writes.
///
/// It changes the representation of the recorded rules, never the rules: the
/// new configuration is the recorded one with every field the newer schema
/// adds recorded absent, which by the schema rule is the behaviour the node
/// already runs. It consults neither the genesis nor the binary's own
/// configuration; the next start compares those against the moved record as
/// it compares them against any record.
///
/// Like [`acknowledge`], the caller holds the database open, which holds
/// RocksDB's exclusive lock, so a running node and this command cannot both
/// have it. Accepts only when ALL of these hold:
/// * a baseline exists and verifies, history included;
/// * its schema is older than the one this binary writes, and that schema
///   extends it;
/// * `expected_old` is exactly the recorded commitment;
/// * `expected_new` is exactly the commitment of the recorded configuration
///   carried into the newer schema.
///
/// The new record and a [`TransitionKind::SchemaTransition`] carrying the old
/// encoding are written in ONE durable batch. The old encoding is kept for
/// good: the history still shows every schema-1 configuration this node held.
///
/// This is a LOCAL acknowledgement. It authorizes nothing on the network and
/// activates no rule.
pub fn acknowledge_schema_transition(
    db: &Database,
    current_height: u64,
    expected_old: Hash,
    expected_new: Hash,
) -> Result<SchemaTransitioned, ConfigError> {
    acknowledge_schema_transition_with(db, current_height, expected_old, expected_new, &PRODUCTION)
}

/// [`acknowledge_schema_transition`] under `policy`.
pub fn acknowledge_schema_transition_with(
    db: &Database,
    current_height: u64,
    expected_old: Hash,
    expected_new: Hash,
    policy: &SchemaPolicy,
) -> Result<SchemaTransitioned, ConfigError> {
    let record = read_record_with(db, policy)?.ok_or_else(|| {
        ConfigError::Refused(
            "this database has no consensus configuration baseline, so there is no \
             schema to move from; the next node start records one in schema the binary \
             writes"
                .to_string(),
        )
    })?;
    let from = record.config.schema();
    let to = policy.writes;
    if std::ptr::eq(from, to) {
        return Err(ConfigError::Refused(format!(
            "the baseline is already recorded in schema {}, the schema this binary \
             writes; there is no schema transition to make",
            from.number
        )));
    }
    if !to.extends(from) {
        return Err(ConfigError::Refused(format!(
            "this binary writes schema {}, which does not extend the recorded schema {}",
            to.number, from.number
        )));
    }
    if record.commitment != expected_old {
        return Err(ConfigError::Refused(format!(
            "--old {expected_old} is not the recorded commitment {}",
            record.commitment
        )));
    }
    let moved = record.config.extend_to(to)?;
    let moved_commitment = moved.commitment();
    if moved_commitment != expected_new {
        return Err(ConfigError::Refused(format!(
            "--new {expected_new} is not the commitment of the recorded configuration \
             in schema {}, {moved_commitment}",
            to.number
        )));
    }
    let added: Vec<u16> = to.added_since(from).iter().map(|s| s.id).collect();
    let seq = write_transition(
        db,
        &record,
        &moved,
        TransitionKind::SchemaTransition,
        current_height,
        added.clone(),
    )?;
    Ok(SchemaTransitioned {
        seq,
        from_schema: from.number,
        to_schema: to.number,
        from: record.commitment,
        to: moved_commitment,
        added,
    })
}

/// The pre-start revert this binary could perform on this database: undo the
/// schema transition it made, while the chain has not moved past the height
/// the move was made at. A refusal says why none is available.
pub fn pending_schema_revert(db: &Database) -> Result<PendingSchemaRevert, ConfigError> {
    pending_schema_revert_with(db, &PRODUCTION)
}

/// [`pending_schema_revert`] under `policy`.
pub fn pending_schema_revert_with(
    db: &Database,
    policy: &SchemaPolicy,
) -> Result<PendingSchemaRevert, ConfigError> {
    plan_schema_revert(db, policy).map(|(pending, _, _)| pending)
}

/// The stopped-node, pre-start revert of a schema transition: write back the
/// record the move replaced, and remove the move's transition.
///
/// It exists for one moment of a coordinated upgrade: the move has been made
/// on a stopped node, and the upgrade is abandoned before the node first runs
/// on the moved record. A binary that does not read the newer schema refuses
/// that record; this restores the one it accepted, byte for byte.
///
/// Like [`acknowledge_schema_transition`], the caller holds the database open,
/// which holds RocksDB's exclusive lock, so a running node and this command
/// cannot both have it. Accepts only when ALL of these hold:
/// * a baseline exists and verifies, history included;
/// * its last transition is a [`TransitionKind::SchemaTransition`] into the
///   schema this binary writes, from a schema this binary reads, and the
///   record is exactly that transition's old configuration carried into the
///   newer schema;
/// * no normal start has been attempted since the move: the start marker
///   ([`super::start_marker`]) is absent, or was written at an earlier
///   transition count and names the commitment the history holds there. A
///   marker written at the move's own count means a node started on the moved
///   record, imported or not, refused or not; any marker this binary cannot
///   read, or that disagrees with the history, is an uncertain state. Both
///   refuse;
/// * the chain's head is exactly the height the move was made at, and the
///   block-height index holds nothing above it;
/// * `expected_old` is exactly the recorded commitment, and `expected_new`
///   exactly the commitment the move replaced.
///
/// The restored record and the removal of the transition are written in ONE
/// durable batch: a crash leaves either the moved database or the reverted
/// one. Nothing else is read for writing or written: no block, no state, no
/// activation record, and not the start marker. Once a normal start has been
/// attempted, the only recovery is forward, with a binary that reads the newer
/// schema; a later rewind of the chain does not reopen the revert.
///
/// This is a LOCAL operation. It authorizes nothing on the network.
pub fn revert_schema_transition(
    db: &Database,
    expected_old: Hash,
    expected_new: Hash,
) -> Result<SchemaReverted, ConfigError> {
    revert_schema_transition_with(db, expected_old, expected_new, &PRODUCTION)
}

/// [`revert_schema_transition`] under `policy`.
pub fn revert_schema_transition_with(
    db: &Database,
    expected_old: Hash,
    expected_new: Hash,
    policy: &SchemaPolicy,
) -> Result<SchemaReverted, ConfigError> {
    let (pending, record, restored) = plan_schema_revert(db, policy)?;
    if pending.old != expected_old {
        return Err(ConfigError::Refused(format!(
            "--old {expected_old} is not the recorded commitment {}",
            pending.old
        )));
    }
    if pending.new != expected_new {
        return Err(ConfigError::Refused(format!(
            "--new {expected_new} is not the commitment the schema transition replaced, {}",
            pending.new
        )));
    }
    let previous = BaselineRecord {
        status: record.status,
        baseline_height: record.baseline_height,
        initial_commitment: record.initial_commitment,
        transition_count: pending.seq - 1,
        commitment: pending.new,
        config: restored,
    };
    let mut batch = db.batch();
    batch
        .delete(cf::META, &transition_key(pending.seq))
        .and_then(|_| batch.put(cf::META, RECORD_KEY, &encode_record(&previous)))
        .map_err(|e| ConfigError::Storage(format!("staging the schema revert: {e}")))?;
    #[cfg(feature = "failpoints")]
    crate::branch_switch::failpoints::barrier(
        crate::branch_switch::failpoints::Failpoint::SchemaRevertBeforeCommit,
    );
    batch.commit_durable().map_err(|e| {
        ConfigError::Storage(format!(
            "reverting consensus configuration transition {}: {e}",
            pending.seq
        ))
    })?;
    #[cfg(feature = "failpoints")]
    crate::branch_switch::failpoints::barrier(
        crate::branch_switch::failpoints::Failpoint::SchemaRevertAfterCommit,
    );
    // Read back what was written: it must verify, history included, and be
    // the record the move replaced.
    let back = read_record_with(db, policy)?.ok_or_else(|| {
        ConfigError::RecordCorrupt("the reverted record did not read back".to_string())
    })?;
    if back != previous {
        return Err(ConfigError::RecordCorrupt(
            "the reverted record read back differently".to_string(),
        ));
    }
    Ok(SchemaReverted {
        seq: pending.seq,
        at_height: pending.at_height,
        from_schema: pending.from_schema,
        to_schema: pending.to_schema,
        from: pending.old,
        to: pending.new,
    })
}

/// Everything [`revert_schema_transition_with`] checks before it writes: the
/// revert, the verified record, and the configuration it restores.
fn plan_schema_revert(
    db: &Database,
    policy: &SchemaPolicy,
) -> Result<(PendingSchemaRevert, BaselineRecord, ConsensusConfig), ConfigError> {
    let refused = |why: String| ConfigError::Refused(why);
    let record = read_record_with(db, policy)?.ok_or_else(|| {
        refused(
            "this database has no consensus configuration baseline, so there is no schema \
             transition to revert"
                .to_string(),
        )
    })?;
    let history = verify_history(db, &record, policy)?;
    let Some(last) = history.last() else {
        return Err(refused(
            "this database has recorded no transition, so there is no schema transition to \
             revert"
                .to_string(),
        ));
    };
    if last.kind != TransitionKind::SchemaTransition {
        return Err(refused(format!(
            "the last recorded transition ({}) is a {}, not a schema transition; only a \
             schema transition the node has not run on can be reverted",
            last.seq,
            last.kind.label()
        )));
    }
    let now = record.config.schema();
    if !std::ptr::eq(now, policy.writes) {
        return Err(refused(format!(
            "the record holds schema {}, and this binary writes schema {}; it reverts only \
             its own schema transition",
            now.number, policy.writes.number
        )));
    }
    let restored = ConsensusConfig::decode_with(&last.old_encoding, policy.reads)
        .map_err(|e| ConfigError::RecordCorrupt(format!("the kept encoding: {e}")))?;
    if std::ptr::eq(restored.schema(), now)
        || restored.encode() != last.old_encoding
        || restored.commitment() != last.old_commitment
        || restored.extend_to(now)? != record.config
    {
        return Err(ConfigError::RecordCorrupt(format!(
            "schema transition {} is not exactly the re-encoding of the configuration it \
             kept",
            last.seq
        )));
    }
    // The start marker decides "has run on the moved record". Read first, so
    // that a started node is refused as such even when its chain position
    // happens to equal the move's.
    let uncertain = |why: String| {
        refused(format!(
            "uncertain migration state: {why}. The revert needs a start marker that is \
             absent or that this history accounts for; recovery is forward only, with a \
             binary that reads the newer schema"
        ))
    };
    let marker = match read_start_marker(db) {
        Ok(m) => m,
        Err(ConfigError::RecordCorrupt(why)) => return Err(uncertain(why)),
        Err(e) => return Err(e),
    };
    if let Some(m) = &marker {
        match m.record {
            RecordState::Present {
                transition_count: count,
                commitment,
            } => {
                if count > record.transition_count {
                    return Err(uncertain(format!(
                        "the start marker (attempt {}) names transition count {count}, above \
                         the record's {}",
                        m.attempt, record.transition_count
                    )));
                }
                let expected = if count == 0 {
                    record.initial_commitment
                } else {
                    history[count as usize - 1].new_commitment
                };
                if commitment != expected {
                    return Err(uncertain(format!(
                        "the start marker (attempt {}) names commitment {commitment} at \
                         transition count {count}, but the history holds {expected} there",
                        m.attempt
                    )));
                }
                if count == last.seq {
                    return Err(refused(format!(
                        "a normal start was attempted on the moved record (start marker: \
                         attempt {}, at transition count {count}, commitment {commitment}, \
                         head {}); recovery is forward only, with a binary that reads the \
                         newer schema",
                        m.attempt,
                        match m.head {
                            Some((h, hash)) => format!("{h} {hash}"),
                            None => "none".to_string(),
                        }
                    )));
                }
                // count < seq: a start before the move, on the record it replaced.
            }
            RecordState::Absent => {
                return Err(uncertain(format!(
                    "a normal start (attempt {}) was made while no configuration record \
                     existed",
                    m.attempt
                )));
            }
            RecordState::Unreadable => {
                return Err(uncertain(format!(
                    "a normal start (attempt {}) was made while the configuration record \
                     was unreadable",
                    m.attempt
                )));
            }
        }
    }
    let blocks = BlockStore::new(db);
    let head = blocks
        .get_latest_height()
        .map_err(|e| ConfigError::Storage(format!("reading the chain head: {e}")))?
        .unwrap_or(0);
    if head != last.at_height {
        return Err(refused(format!(
            "the schema transition was made at height {} and the chain is now at height \
             {head}. {}",
            last.at_height,
            if head > last.at_height {
                "Blocks above the move's height exist: this node has run on the moved record, \
                 and recovery is forward only, with a binary that reads the newer schema"
            } else {
                "The chain is below the move's height; the revert does not follow a rewind \
                 (a rewind to exactly the move's height after a start is refused by the \
                 start marker above)"
            }
        )));
    }
    let head_hash = blocks
        .get_latest_hash()
        .map_err(|e| ConfigError::Storage(format!("reading the chain head: {e}")))?;
    let above = (last.at_height.saturating_add(1)).to_be_bytes();
    if let Some(entry) = db
        .iter_checked_from(cf::BLOCK_HEIGHT, Some(&above))
        .map_err(|e| ConfigError::Storage(format!("scanning the block-height index: {e}")))?
        .next()
    {
        let (key, _) = entry
            .map_err(|e| ConfigError::Storage(format!("scanning the block-height index: {e}")))?;
        let at = <[u8; 8]>::try_from(&key[..])
            .map(|b| u64::from_be_bytes(b).to_string())
            .unwrap_or_else(|_| format!("an unparseable {}-byte key", key.len()));
        return Err(refused(format!(
            "the block-height index holds a block at {at}, above the move's height {}: this \
             node has run on the moved record, and recovery is forward only, with a binary \
             that reads the newer schema",
            last.at_height
        )));
    }
    Ok((
        PendingSchemaRevert {
            seq: last.seq,
            at_height: last.at_height,
            head_hash,
            start_marker: marker,
            from_schema: now.number,
            to_schema: restored.schema().number,
            old: record.commitment,
            new: last.old_commitment,
        },
        record,
        restored,
    ))
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
    write_transition(
        db,
        record,
        now,
        kind,
        at_height,
        changes.iter().map(|c| c.id).collect(),
    )
}

fn write_transition(
    db: &Database,
    record: &BaselineRecord,
    now: &ConsensusConfig,
    kind: TransitionKind,
    at_height: u64,
    changed_ids: Vec<u16>,
) -> Result<u64, ConfigError> {
    let seq = record.transition_count + 1;
    let transition = Transition {
        seq,
        kind,
        at_height,
        old_commitment: record.commitment,
        new_commitment: now.commitment(),
        changed_ids,
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
    #[cfg(feature = "failpoints")]
    if kind == TransitionKind::SchemaTransition {
        crate::branch_switch::failpoints::barrier(
            crate::branch_switch::failpoints::Failpoint::SchemaTransitionBeforeCommit,
        );
    }
    batch.commit_durable().map_err(|e| {
        ConfigError::Storage(format!(
            "recording consensus configuration transition {seq}: {e}"
        ))
    })?;
    #[cfg(feature = "failpoints")]
    if kind == TransitionKind::SchemaTransition {
        crate::branch_switch::failpoints::barrier(
            crate::branch_switch::failpoints::Failpoint::SchemaTransitionAfterCommit,
        );
    }
    Ok(seq)
}

fn transition_key(seq: u64) -> Vec<u8> {
    let mut k = TRANSITION_PREFIX.to_vec();
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Verify the transition chain behind `record` and return it.
fn verify_history(
    db: &Database,
    record: &BaselineRecord,
    policy: &SchemaPolicy,
) -> Result<Vec<Transition>, ConfigError> {
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
        if t.kind == TransitionKind::SchemaTransition {
            verify_schema_transition(&t, policy).map_err(corrupt)?;
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

/// A schema transition must be exactly the re-encoding of its old
/// configuration into a later schema this binary reads: same rules, every
/// added field absent, the added ids listed.
fn verify_schema_transition(t: &Transition, policy: &SchemaPolicy) -> Result<(), String> {
    let seq = t.seq;
    let old = ConsensusConfig::decode_with(&t.old_encoding, policy.reads)
        .map_err(|e| format!("schema transition {seq} carries an unreadable encoding: {e}"))?;
    for to in policy.reads {
        if std::ptr::eq(*to, old.schema()) || !to.extends(old.schema()) {
            continue;
        }
        let Ok(moved) = old.extend_to(to) else {
            continue;
        };
        if moved.commitment() == t.new_commitment {
            let added: Vec<u16> = to.added_since(old.schema()).iter().map(|s| s.id).collect();
            if added != t.changed_ids {
                return Err(format!(
                    "schema transition {seq} lists fields other than those schema {} adds",
                    to.number
                ));
            }
            return Ok(());
        }
    }
    Err(format!(
        "schema transition {seq} does not re-encode its schema-{} configuration into a \
         schema this binary reads",
        old.schema().number
    ))
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

fn decode_record(raw: &[u8], policy: &SchemaPolicy) -> Result<BaselineRecord, ConfigError> {
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
    let config = ConsensusConfig::decode_with(encoding, policy.reads).map_err(|e| match e {
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

// ── migration provenance, for the maintenance commands ──────────────────────

/// What a database says about its own migration history: the start marker and
/// every consensus-configuration row (the record and its transitions), as the
/// raw bytes stored. `rollback` and `restore` read it before and after they
/// run, and refuse when it cannot be established or when they would change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub marker: Option<StartMarker>,
    /// Every `consensus_config/` row of `cf::META`, in key order, and the
    /// start-marker row if present.
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Read and verify the migration provenance of `db`. An unreadable start
/// marker or an unreadable configuration record is an error: the provenance
/// cannot be established, and a command that rewrites the database must refuse.
pub fn migration_provenance(db: &Database) -> Result<Provenance, ConfigError> {
    let marker = read_start_marker(db)?;
    read_record(db)?;
    let mut rows = Vec::new();
    for entry in db
        .prefix_iter_checked(cf::META, b"consensus_config/")
        .map_err(|e| ConfigError::Storage(format!("scanning the configuration rows: {e}")))?
    {
        let (key, value) =
            entry.map_err(|e| ConfigError::Storage(format!("reading a configuration row: {e}")))?;
        if !key.starts_with(b"consensus_config/") {
            break;
        }
        rows.push((key.to_vec(), value.to_vec()));
    }
    if let Some(raw) = db
        .get(cf::META, super::start_marker::START_MARKER_KEY)
        .map_err(|e| ConfigError::Storage(format!("reading the start marker: {e}")))?
    {
        rows.push((super::start_marker::START_MARKER_KEY.to_vec(), raw));
    }
    Ok(Provenance { marker, rows })
}

/// Whether restoring a database with provenance `backup` over one with
/// provenance `current` keeps the protection the current database holds:
/// the configuration record and its history are identical, and a start marker
/// the current database holds is held by the backup at the same record state
/// (the same transition count and commitment, which is what the pre-start
/// revert decides on; the attempt count and head may differ). A backup without
/// that is one taken before the move or before the start it would erase, and
/// restoring it would reopen a closed abort window.
pub fn restore_preserves_provenance(
    current: &Provenance,
    backup: &Provenance,
) -> Result<(), String> {
    fn config(p: &Provenance) -> Vec<&(Vec<u8>, Vec<u8>)> {
        p.rows
            .iter()
            .filter(|(k, _)| k.starts_with(b"consensus_config/"))
            .collect()
    }
    if config(current) != config(backup) {
        return Err(
            "the backup's consensus-configuration record or history differs from the existing \
             database's; restoring it would change the migration provenance"
                .to_string(),
        );
    }
    match (&current.marker, &backup.marker) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(
            "the existing database holds a start marker and the backup holds none; restoring \
             it would clear the record that a normal start was attempted"
                .to_string(),
        ),
        (Some(c), Some(b)) if c.record != b.record => Err(format!(
            "the existing database's start marker names record state {:?} and the backup's \
             names {:?}; restoring it would change what the start marker protects",
            c.record, b.record
        )),
        (Some(_), Some(_)) => Ok(()),
    }
}

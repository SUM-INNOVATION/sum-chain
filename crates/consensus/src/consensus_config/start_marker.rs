//! The start marker: the first logical write of every normal node start.
//!
//! # Why it exists
//!
//! The stopped-node schema move ([`super::record::acknowledge_schema_transition`])
//! can be undone by the pre-start revert
//! ([`super::record::revert_schema_transition`]) only while the node has not
//! run on the moved record. "Has not run" is decided by this marker, not by the
//! chain height: a normal start rewrites local rows before it processes any
//! block (the activation record, the messaging backfill, a fresh baseline), and
//! a start can be refused by a later check after some of those writes. So the
//! abort window closes at the first normal start ATTEMPT, whatever that start
//! then did, and it closes on this evidence alone.
//!
//! # What a normal start does
//!
//! Immediately after the database is opened, before the journal format check,
//! the messaging backfill, the activation-height check, the configuration
//! baseline, genesis initialization and the node key, the node writes this
//! marker in ONE durable batch ([`record_start`]). If that write fails the
//! start refuses, and nothing else has been written. Every later refusal
//! leaves the marker behind, which is the point.
//!
//! # What the marker holds
//!
//! ```text
//! version:u16 = 1 ‖ attempt:u64
//!   ‖ record_state:u8 ‖ transition_count:u64 ‖ commitment[32]
//!   ‖ head_state:u8 ‖ head_height:u64 ‖ head_hash[32]
//! ```
//!
//! Integers little-endian. `attempt` counts normal starts on this database.
//! The record fields are the configuration record's transition count and
//! commitment as read at the attempt (`record_state` 0: no record, 1: present,
//! 2: unreadable; the count and commitment are zero unless present). The head
//! fields are the chain head at the attempt (`head_state` 0: none, 1: present).
//!
//! Binding the marker to the record's state, not to its presence, is what lets
//! a later schema move be reverted before ITS first start: a marker written at
//! transition count `c` says a node ran on the record as it was after `c`
//! transitions, so a schema transition with sequence number `> c` was never
//! run on, and one with sequence number `== c` was.
//!
//! # What never writes it
//!
//! Every read-only command (`--version`, the two `--show`s,
//! `check-finality-record`, `inspect-v2-rows`, `info`,
//! `export-registered-keys`), the move, the revert and the field-level
//! acknowledgement. The revert neither writes nor deletes it: it is an
//! unrelated record, and on the revert's own path it is absent or predates
//! the move.

use sumchain_primitives::Hash;
use sumchain_storage::schema::BlockStore;
use sumchain_storage::{cf, Database};

use super::record::read_record;
use super::ConfigError;

/// Where the marker lives (`cf::META`). Outside the configuration record and
/// transition keys.
pub const START_MARKER_KEY: &[u8] = b"node/start-marker/v1";

const MARKER_VERSION: u16 = 1;
const MARKER_LEN: usize = 2 + 8 + 1 + 8 + 32 + 1 + 8 + 32;

/// The configuration record as the start found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    /// No record was recorded: a fresh database.
    Absent,
    /// A record that decoded and verified, with its transition count and
    /// commitment.
    Present {
        transition_count: u64,
        commitment: Hash,
    },
    /// A record was present and did not decode or verify.
    Unreadable,
}

/// One normal start, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartMarker {
    /// How many normal starts this database has seen, this one included.
    pub attempt: u64,
    pub record: RecordState,
    /// The chain head at the attempt, `(height, hash)`, if any block existed.
    pub head: Option<(u64, Hash)>,
}

impl StartMarker {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MARKER_LEN);
        out.extend_from_slice(&MARKER_VERSION.to_le_bytes());
        out.extend_from_slice(&self.attempt.to_le_bytes());
        let (state, count, commitment) = match self.record {
            RecordState::Absent => (0u8, 0u64, Hash::default()),
            RecordState::Present {
                transition_count,
                commitment,
            } => (1, transition_count, commitment),
            RecordState::Unreadable => (2, 0, Hash::default()),
        };
        out.push(state);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(commitment.as_bytes());
        match self.head {
            None => {
                out.push(0);
                out.extend_from_slice(&0u64.to_le_bytes());
                out.extend_from_slice(Hash::default().as_bytes());
            }
            Some((height, hash)) => {
                out.push(1);
                out.extend_from_slice(&height.to_le_bytes());
                out.extend_from_slice(hash.as_bytes());
            }
        }
        debug_assert_eq!(out.len(), MARKER_LEN);
        out
    }

    fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 2 {
            return Err("truncated".to_string());
        }
        let version = u16::from_le_bytes([raw[0], raw[1]]);
        if version != MARKER_VERSION {
            return Err(format!(
                "version {version} is not one this binary reads; it may have been written by \
                 a newer binary"
            ));
        }
        if raw.len() != MARKER_LEN {
            return Err(format!("{} bytes, expected {MARKER_LEN}", raw.len()));
        }
        let u64_at = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().expect("8 bytes"));
        let hash_at =
            |at: usize| Hash::from(<[u8; 32]>::try_from(&raw[at..at + 32]).expect("32 bytes"));
        let attempt = u64_at(2);
        let record = match raw[10] {
            0 => RecordState::Absent,
            1 => RecordState::Present {
                transition_count: u64_at(11),
                commitment: hash_at(19),
            },
            2 => RecordState::Unreadable,
            other => return Err(format!("unknown record state {other}")),
        };
        let head = match raw[51] {
            0 => None,
            1 => Some((u64_at(52), hash_at(60))),
            other => return Err(format!("unknown head state {other}")),
        };
        Ok(StartMarker {
            attempt,
            record,
            head,
        })
    }
}

/// The marker this database holds, if any. An unreadable marker is an error,
/// never `None`: the revert treats it as an uncertain state and refuses, and a
/// start refuses rather than overwrite what it cannot read.
pub fn read_start_marker(db: &Database) -> Result<Option<StartMarker>, ConfigError> {
    let raw = db
        .get(cf::META, START_MARKER_KEY)
        .map_err(|e| ConfigError::Storage(format!("reading the start marker: {e}")))?;
    match raw {
        None => Ok(None),
        Some(raw) => StartMarker::decode(&raw).map(Some).map_err(|why| {
            ConfigError::RecordCorrupt(format!("the start marker is unreadable: {why}"))
        }),
    }
}

/// Record a normal start: the first logical write of `Node::with_rpc_config`,
/// immediately after the database is opened.
///
/// Reads the previous marker (its attempt count), the configuration record and
/// the chain head, and writes the new marker in one durable batch. Returns the
/// marker written. An error means nothing was written, and the start must
/// refuse: an unreadable previous marker (one this binary cannot read), or a
/// failed write.
pub fn record_start(db: &Database) -> Result<StartMarker, ConfigError> {
    let attempt = read_start_marker(db)?.map_or(1, |m| m.attempt.saturating_add(1));
    let record = match read_record(db) {
        Ok(None) => RecordState::Absent,
        Ok(Some(r)) => RecordState::Present {
            transition_count: r.transition_count,
            commitment: r.commitment,
        },
        Err(_) => RecordState::Unreadable,
    };
    let blocks = BlockStore::new(db);
    let head = match (
        blocks
            .get_latest_height()
            .map_err(|e| ConfigError::Storage(format!("reading the chain head: {e}")))?,
        blocks
            .get_latest_hash()
            .map_err(|e| ConfigError::Storage(format!("reading the chain head: {e}")))?,
    ) {
        (Some(height), Some(hash)) => Some((height, hash)),
        _ => None,
    };
    let marker = StartMarker {
        attempt,
        record,
        head,
    };
    let mut batch = db.batch();
    batch
        .put(cf::META, START_MARKER_KEY, &marker.encode())
        .map_err(|e| ConfigError::Storage(format!("staging the start marker: {e}")))?;
    #[cfg(feature = "failpoints")]
    {
        use crate::branch_switch::failpoints::{barrier, hit, Failpoint};
        barrier(Failpoint::StartMarkerBeforeCommit);
        if hit(Failpoint::StartMarkerCommitFails) {
            return Err(ConfigError::Storage(
                "injected failure: the start marker's commit failed".to_string(),
            ));
        }
    }
    batch
        .commit_durable()
        .map_err(|e| ConfigError::Storage(format!("recording the start marker: {e}")))?;
    #[cfg(feature = "failpoints")]
    crate::branch_switch::failpoints::barrier(
        crate::branch_switch::failpoints::Failpoint::StartMarkerAfterCommit,
    );
    Ok(marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_round_trips_and_refuses_what_it_did_not_write() {
        let h = Hash::hash(b"x");
        for marker in [
            StartMarker {
                attempt: 1,
                record: RecordState::Absent,
                head: None,
            },
            StartMarker {
                attempt: 7,
                record: RecordState::Present {
                    transition_count: 2,
                    commitment: h,
                },
                head: Some((99, h)),
            },
            StartMarker {
                attempt: u64::MAX,
                record: RecordState::Unreadable,
                head: Some((0, Hash::default())),
            },
        ] {
            let bytes = marker.encode();
            assert_eq!(bytes.len(), MARKER_LEN);
            assert_eq!(StartMarker::decode(&bytes).unwrap(), marker);
            let mut longer = bytes.clone();
            longer.push(0);
            assert!(StartMarker::decode(&longer).is_err(), "trailing byte");
            assert!(
                StartMarker::decode(&bytes[..bytes.len() - 1]).is_err(),
                "truncated"
            );
            let mut newer = bytes.clone();
            newer[0] = 2;
            assert!(StartMarker::decode(&newer)
                .unwrap_err()
                .contains("newer binary"));
            let mut state = bytes.clone();
            state[10] = 9;
            assert!(StartMarker::decode(&state).is_err(), "unknown record state");
        }
        assert!(StartMarker::decode(&[]).is_err());
    }
}

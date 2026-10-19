//! PROPOSED, UNRATIFIED: a file-backed [`SignerStore`] for the G2-b signer.
//!
//! This is a dormant prototype of the signer-state layout and recovery rules
//! under review (group A2, revision 2 of the draft). Nothing calls it, the
//! byte layout is not frozen, and it exists so that every crash point of the
//! persistence protocol can be tested against the real encoding.
//!
//! # Layout: 348 bytes (draft 1 was 284)
//!
//! | Offset | Width | Field |
//! |---|---|---|
//! | 0 | 7 | magic `FSGNv1\0` |
//! | 7 | 2 | schema u16 LE = 1 |
//! | 9 | 8 | counter u64 LE |
//! | 17 | 8 | chain_id u64 LE |
//! | 25 | 32 | genesis_block_hash |
//! | 57 | 32 | signer_pubkey |
//! | 89 | 8 | floor_height u64 LE |
//! | 97 | 1 | last_present (0 or 1) |
//! | 98 | 8 | last_height u64 LE |
//! | 106 | 4 | last_round u32 LE |
//! | 110 | 1 | last_step (1 proposal, 2 prevote, 3 precommit) |
//! | 111 | 32 | last_value (block id; all zero = nil) **new** |
//! | 143 | 32 | last_sign_bytes_digest = H(`D_SIGNBYTES` ‖ sign bytes) |
//! | 175 | 64 | last_signature |
//! | 239 | 1 | lock_present (0 or 1) |
//! | 240 | 8 | lock_height u64 LE |
//! | 248 | 4 | lock_round u32 LE |
//! | 252 | 32 | lock_value |
//! | 284 | 32 | prev_checksum (checksum of the record this one replaced) **new** |
//! | 316 | 32 | checksum = H(`D_SIGNER` ‖ bytes[0..316]) |
//!
//! The mirror (kept in the node database, written with a synced WAL) is a
//! byte-identical copy of the last fully persisted state, so equal counters
//! are compared over every byte, and a one-ahead state can be checked as the
//! exact successor of the mirrored one.
//!
//! The hash function is injected ([`StateHasher`]); the draft proposes
//! BLAKE3-256.
//!
//! # Persistence protocol
//!
//! * **P1:** write `signer.v1.tmp`, fsync it, rename it over `signer.v1`,
//!   fsync the directory.
//! * **P2:** write the mirror, durably.
//! * The store returns `Ok` only after both; the signer releases only after
//!   `Ok`.
//!
//! # Recovery at open
//!
//! See [`FileSignerStore::load`]: a leftover temp file is removed; then the
//! state file and the mirror are classified, and only two repairs exist:
//! completing an interrupted initialization, and advancing a mirror that is
//! exactly one persist behind. Both first make the state file durable.
//!
//! # Limits
//!
//! * Restoring the state file and the mirror together (a whole data-directory
//!   rollback) is undetectable here; only external evidence of a newer
//!   signature catches it.
//! * Two signers holding cloned keys, each with its own state, are
//!   undetectable here.
//! * The crash model tested is process crashes plus a simulated loss of
//!   unsynced writes; real power-loss durability is untested.

use std::path::PathBuf;

use thiserror::Error;

use crate::encoding::MAX_ROUND;
use crate::signer::{
    LastSigned, Lock, SignBytes, SignPosition, SignerRecord, SignerStore, Step, StoreError,
    VoteValue,
};
use crate::Digest;

/// Checksum domain.
pub const D_SIGNER: &[u8; 28] = b"SUMCHAIN/FINALITY/SIGNER/v1\0";
/// Sign-bytes digest domain.
pub const D_SIGNBYTES: &[u8; 31] = b"SUMCHAIN/FINALITY/SIGNBYTES/v1\0";
/// Magic.
pub const MAGIC: &[u8; 7] = b"FSGNv1\0";
/// Schema.
pub const SCHEMA: u16 = 1;
/// Length of an encoded state.
pub const STATE_LEN: usize = 348;
/// Bytes covered by the checksum.
pub const CHECKSUMMED_LEN: usize = 316;
/// The state file.
pub const STATE_FILE: &str = "signer.v1";
/// The temporary file renamed over [`STATE_FILE`].
pub const TEMP_FILE: &str = "signer.v1.tmp";

const ZERO: Digest = [0u8; 32];

/// The hash used for the checksum and the sign-bytes digest.
pub trait StateHasher {
    fn hash(&self, data: &[u8]) -> Digest;
}

/// Who this state belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub chain_id: u64,
    pub genesis_block_hash: Digest,
    pub signer_pubkey: Digest,
}

/// The last released (or about to be released) signature, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLast {
    pub position: SignPosition,
    pub value: VoteValue,
    pub sign_bytes_digest: Digest,
    pub signature: [u8; 64],
}

/// A decoded signer state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerState {
    pub counter: u64,
    pub identity: Identity,
    /// Heights below this are never signed. 0: no floor.
    pub floor_height: u64,
    pub last: Option<StateLast>,
    pub lock: Option<Lock>,
    pub prev_checksum: Digest,
}

/// Why bytes were refused as a state, or a transition as a successor.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    #[error("length {0}, expected 348")]
    Length(usize),
    #[error("bad magic")]
    Magic,
    #[error("unknown schema {0}")]
    Schema(u16),
    #[error("checksum mismatch")]
    Checksum,
    #[error("{0} is not 0 or 1")]
    Flag(&'static str),
    #[error("absent {0} is not all zero")]
    NonCanonicalAbsent(&'static str),
    #[error("step byte {0} is not 1, 2 or 3")]
    Step(u8),
    #[error("{0} round {1} exceeds 2^20")]
    Round(&'static str, u32),
    #[error("{0} is below the floor")]
    BelowFloor(&'static str),
    #[error("inconsistent: {0}")]
    Inconsistent(&'static str),
    #[error("not the successor: {0}")]
    NotSuccessor(&'static str),
    #[error("identity mismatch: {0}")]
    Identity(&'static str),
    #[error("record not representable: {0}")]
    Unrepresentable(&'static str),
}

fn step_byte(step: Step) -> u8 {
    match step {
        Step::Propose => 1,
        Step::Prevote => 2,
        Step::Precommit => 3,
    }
}

fn byte_step(b: u8) -> Result<Step, StateError> {
    match b {
        1 => Ok(Step::Propose),
        2 => Ok(Step::Prevote),
        3 => Ok(Step::Precommit),
        other => Err(StateError::Step(other)),
    }
}

fn value_bytes(v: VoteValue) -> Result<Digest, StateError> {
    match v {
        VoteValue::Nil => Ok(ZERO),
        VoteValue::Block(d) if d == ZERO => Err(StateError::Unrepresentable(
            "a block id of all zero means nil",
        )),
        VoteValue::Block(d) => Ok(d),
    }
}

fn bytes_value(d: Digest) -> VoteValue {
    if d == ZERO {
        VoteValue::Nil
    } else {
        VoteValue::Block(d)
    }
}

/// The core's floor position for a floor height: every position below height
/// `floor_height` is refused, signing at `floor_height` itself is allowed.
pub fn floor_below_height(floor_height: u64) -> Option<SignPosition> {
    floor_height.checked_sub(1).map(|h| SignPosition {
        height: h,
        round: MAX_ROUND,
        step: Step::Precommit,
    })
}

fn height_of_floor(floor: Option<SignPosition>) -> Result<u64, StateError> {
    match floor {
        None => Ok(0),
        Some(p) if p.round == MAX_ROUND && p.step == Step::Precommit => p
            .height
            .checked_add(1)
            .ok_or(StateError::Unrepresentable("floor height overflows")),
        Some(_) => Err(StateError::Unrepresentable(
            "the floor must cover whole heights (use floor_below_height)",
        )),
    }
}

fn lock_position(lock: &Lock) -> SignPosition {
    SignPosition {
        height: lock.height,
        round: lock.round,
        step: Step::Precommit,
    }
}

impl SignerState {
    /// Rules every single record must satisfy (canonical absence, last/lock
    /// consistency, bounds). Decoding applies them; so does persisting.
    pub fn check(&self) -> Result<(), StateError> {
        if self.counter == 0 {
            if self.last.is_some() || self.lock.is_some() {
                return Err(StateError::Inconsistent(
                    "counter 0 (just initialized) with a signature or lock",
                ));
            }
            if self.prev_checksum != ZERO {
                return Err(StateError::Inconsistent(
                    "counter 0 with a predecessor checksum",
                ));
            }
            return Ok(());
        }
        if self.prev_checksum == ZERO {
            return Err(StateError::Inconsistent(
                "counter above 0 without a predecessor checksum",
            ));
        }
        let Some(last) = self.last.as_ref() else {
            return Err(StateError::Inconsistent(
                "counter above 0 without a signature (every persist after init signs)",
            ));
        };
        if last.position.round > MAX_ROUND {
            return Err(StateError::Round("last", last.position.round));
        }
        if last.position.height < self.floor_height {
            return Err(StateError::BelowFloor("last signature"));
        }
        if last.position.step == Step::Propose && last.value == VoteValue::Nil {
            return Err(StateError::Inconsistent("a nil proposal was recorded"));
        }
        if last.sign_bytes_digest == ZERO {
            return Err(StateError::Inconsistent("a zero sign-bytes digest"));
        }
        if let Some(lock) = self.lock.as_ref() {
            if lock.value == ZERO {
                return Err(StateError::Inconsistent("a lock on the nil value"));
            }
            if lock.round > MAX_ROUND {
                return Err(StateError::Round("lock", lock.round));
            }
            if lock.height != last.position.height {
                return Err(StateError::Inconsistent(
                    "the lock is not at the last signature's height",
                ));
            }
            let lp = lock_position(lock);
            if lp > last.position {
                return Err(StateError::Inconsistent(
                    "the lock is above the last signature",
                ));
            }
            if lp == last.position && last.value != VoteValue::Block(lock.value) {
                return Err(StateError::Inconsistent(
                    "the locking precommit names another value",
                ));
            }
        }
        if let (Step::Precommit, VoteValue::Block(v)) = (last.position.step, last.value) {
            let own = Lock {
                height: last.position.height,
                round: last.position.round,
                value: v,
            };
            if self.lock != Some(own) {
                return Err(StateError::Inconsistent(
                    "a non-nil precommit is recorded without its own lock",
                ));
            }
        }
        Ok(())
    }

    /// Encode, computing the checksum. Refuses a record that fails
    /// [`SignerState::check`].
    pub fn encode<H: StateHasher>(&self, hasher: &H) -> Result<[u8; STATE_LEN], StateError> {
        self.check()?;
        let mut b = [0u8; STATE_LEN];
        b[0..7].copy_from_slice(MAGIC);
        b[7..9].copy_from_slice(&SCHEMA.to_le_bytes());
        b[9..17].copy_from_slice(&self.counter.to_le_bytes());
        b[17..25].copy_from_slice(&self.identity.chain_id.to_le_bytes());
        b[25..57].copy_from_slice(&self.identity.genesis_block_hash);
        b[57..89].copy_from_slice(&self.identity.signer_pubkey);
        b[89..97].copy_from_slice(&self.floor_height.to_le_bytes());
        if let Some(last) = self.last.as_ref() {
            b[97] = 1;
            b[98..106].copy_from_slice(&last.position.height.to_le_bytes());
            b[106..110].copy_from_slice(&last.position.round.to_le_bytes());
            b[110] = step_byte(last.position.step);
            b[111..143].copy_from_slice(&value_bytes(last.value)?);
            b[143..175].copy_from_slice(&last.sign_bytes_digest);
            b[175..239].copy_from_slice(&last.signature);
        }
        if let Some(lock) = self.lock.as_ref() {
            b[239] = 1;
            b[240..248].copy_from_slice(&lock.height.to_le_bytes());
            b[248..252].copy_from_slice(&lock.round.to_le_bytes());
            b[252..284].copy_from_slice(&lock.value);
        }
        b[284..316].copy_from_slice(&self.prev_checksum);
        let sum = checksum(hasher, &b[..CHECKSUMMED_LEN]);
        b[316..348].copy_from_slice(&sum);
        Ok(b)
    }

    /// Strict decode. Returns the state and its checksum.
    pub fn decode<H: StateHasher>(
        bytes: &[u8],
        hasher: &H,
    ) -> Result<(SignerState, Digest), StateError> {
        if bytes.len() != STATE_LEN {
            return Err(StateError::Length(bytes.len()));
        }
        if &bytes[0..7] != MAGIC {
            return Err(StateError::Magic);
        }
        let schema = u16::from_le_bytes([bytes[7], bytes[8]]);
        if schema != SCHEMA {
            return Err(StateError::Schema(schema));
        }
        let stored: Digest = bytes[316..348].try_into().expect("32 bytes");
        if checksum(hasher, &bytes[..CHECKSUMMED_LEN]) != stored {
            return Err(StateError::Checksum);
        }
        let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().expect("8"));
        let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().expect("4"));
        let d_at = |o: usize| -> Digest { bytes[o..o + 32].try_into().expect("32") };
        let identity = Identity {
            chain_id: u64_at(17),
            genesis_block_hash: d_at(25),
            signer_pubkey: d_at(57),
        };
        let last = match bytes[97] {
            0 => {
                if bytes[98..239].iter().any(|&x| x != 0) {
                    return Err(StateError::NonCanonicalAbsent("last signature"));
                }
                None
            }
            1 => {
                let step = byte_step(bytes[110])?;
                let round = u32_at(106);
                if round > MAX_ROUND {
                    return Err(StateError::Round("last", round));
                }
                Some(StateLast {
                    position: SignPosition {
                        height: u64_at(98),
                        round,
                        step,
                    },
                    value: bytes_value(d_at(111)),
                    sign_bytes_digest: d_at(143),
                    signature: bytes[175..239].try_into().expect("64"),
                })
            }
            _ => return Err(StateError::Flag("last_present")),
        };
        let lock = match bytes[239] {
            0 => {
                if bytes[240..284].iter().any(|&x| x != 0) {
                    return Err(StateError::NonCanonicalAbsent("lock"));
                }
                None
            }
            1 => {
                let round = u32_at(248);
                if round > MAX_ROUND {
                    return Err(StateError::Round("lock", round));
                }
                Some(Lock {
                    height: u64_at(240),
                    round,
                    value: d_at(252),
                })
            }
            _ => return Err(StateError::Flag("lock_present")),
        };
        let state = SignerState {
            counter: u64_at(9),
            identity,
            floor_height: u64_at(89),
            last,
            lock,
            prev_checksum: d_at(284),
        };
        state.check()?;
        Ok((state, stored))
    }

    /// Whether `next` is exactly one persist after `self` (whose checksum is
    /// `self_checksum`), under the signer's rules. Used to allow a one-ahead
    /// mirror repair and to refuse persisting an invalid transition.
    pub fn check_successor(
        &self,
        self_checksum: &Digest,
        next: &SignerState,
    ) -> Result<(), StateError> {
        next.check()?;
        if next.identity != self.identity {
            return Err(StateError::NotSuccessor("identity changed"));
        }
        if next.floor_height != self.floor_height {
            return Err(StateError::NotSuccessor("floor changed"));
        }
        if self.counter.checked_add(1) != Some(next.counter) {
            return Err(StateError::NotSuccessor("counter is not exactly one ahead"));
        }
        if next.prev_checksum != *self_checksum {
            return Err(StateError::NotSuccessor(
                "predecessor checksum does not name the previous state",
            ));
        }
        let Some(n_last) = next.last.as_ref() else {
            return Err(StateError::NotSuccessor("no new signature"));
        };
        if let Some(p_last) = self.last.as_ref() {
            if n_last.position <= p_last.position {
                return Err(StateError::NotSuccessor(
                    "the signed position did not increase",
                ));
            }
        }
        let new_lock_from_last = |lock: &Lock| {
            n_last.position == lock_position(lock) && n_last.value == VoteValue::Block(lock.value)
        };
        match (self.lock.as_ref(), next.lock.as_ref()) {
            (None, None) => {}
            (None, Some(n)) => {
                if !new_lock_from_last(n) {
                    return Err(StateError::NotSuccessor(
                        "a lock appeared without its precommit",
                    ));
                }
            }
            (Some(p), None) => {
                if n_last.position.height <= p.height {
                    return Err(StateError::NotSuccessor(
                        "the lock was dropped within its height",
                    ));
                }
            }
            (Some(p), Some(n)) => {
                if n != p {
                    if !new_lock_from_last(n) {
                        return Err(StateError::NotSuccessor(
                            "the lock changed without a new precommit",
                        ));
                    }
                    if n.height == p.height && n.round <= p.round {
                        return Err(StateError::NotSuccessor("relock is not at a higher round"));
                    }
                }
            }
        }
        Ok(())
    }

    fn from_record<H: StateHasher>(
        record: &SignerRecord,
        identity: Identity,
        prev_checksum: Digest,
        hasher: &H,
    ) -> Result<SignerState, StateError> {
        if record.key_id != identity.signer_pubkey {
            return Err(StateError::Identity("record key is not the signer key"));
        }
        let last = match record.last.as_ref() {
            None => None,
            Some(l) => Some(StateLast {
                position: l.position,
                value: l.value,
                sign_bytes_digest: match &l.payload {
                    SignBytes::Full(b) => sign_bytes_digest(hasher, b),
                    SignBytes::Digest(d) => *d,
                },
                signature: l
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| StateError::Unrepresentable("signature is not 64 bytes"))?,
            }),
        };
        Ok(SignerState {
            counter: record.sequence,
            identity,
            floor_height: height_of_floor(record.floor)?,
            last,
            lock: record.lock,
            prev_checksum,
        })
    }

    fn to_record(&self) -> SignerRecord {
        SignerRecord {
            key_id: self.identity.signer_pubkey,
            sequence: self.counter,
            floor: floor_below_height(self.floor_height),
            last: self.last.as_ref().map(|l| LastSigned {
                position: l.position,
                value: l.value,
                payload: SignBytes::Digest(l.sign_bytes_digest),
                signature: l.signature.to_vec(),
            }),
            lock: self.lock,
        }
    }
}

fn checksum<H: StateHasher>(hasher: &H, covered: &[u8]) -> Digest {
    let mut pre = Vec::with_capacity(D_SIGNER.len() + covered.len());
    pre.extend_from_slice(D_SIGNER);
    pre.extend_from_slice(covered);
    hasher.hash(&pre)
}

/// `H(D_SIGNBYTES ‖ sign_bytes)`.
pub fn sign_bytes_digest<H: StateHasher>(hasher: &H, sign_bytes: &[u8]) -> Digest {
    let mut pre = Vec::with_capacity(D_SIGNBYTES.len() + sign_bytes.len());
    pre.extend_from_slice(D_SIGNBYTES);
    pre.extend_from_slice(sign_bytes);
    hasher.hash(&pre)
}

/// A file-system operation failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct IoError(pub String);

/// The signer's directory (`<data_dir>/finality/`). Injected so every step
/// can fail in tests.
pub trait SignerDir {
    /// `Ok(None)` if the file does not exist.
    fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, IoError>;
    /// Create or truncate `name` and write `bytes` (not yet durable).
    fn write_new(&mut self, name: &str, bytes: &[u8]) -> Result<(), IoError>;
    /// Make `name`'s data durable.
    fn sync_file(&mut self, name: &str) -> Result<(), IoError>;
    /// Atomically replace `to` with `from` (not yet durable).
    fn rename(&mut self, from: &str, to: &str) -> Result<(), IoError>;
    /// Make the directory's entries durable.
    fn sync_dir(&mut self) -> Result<(), IoError>;
    /// Remove `name`; absent is not an error.
    fn remove(&mut self, name: &str) -> Result<(), IoError>;
}

/// The mirror record in the node database (`finality/signer-mirror/v1`).
pub trait MirrorStore {
    fn read(&mut self) -> Result<Option<Vec<u8>>, IoError>;
    /// Returns `Ok` only once the bytes are durable (synced WAL write).
    fn write_synced(&mut self, bytes: &[u8]) -> Result<(), IoError>;
}

/// How the last [`FileSignerStore::load`] classified the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classified {
    /// Neither the state file nor the mirror exists.
    Uninitialized,
    /// State file and mirror are byte-identical.
    Consistent,
    /// R0: an initialization stopped after the state file (counter 0) and
    /// before the mirror; completed.
    CompletedInitialization,
    /// R1: the mirror was exactly one persist behind; advanced.
    AdvancedMirror,
}

/// The proposed file-backed store. One per signer; reopen by creating a new
/// one over the same directory and mirror.
pub struct FileSignerStore<D, M, H> {
    dir: D,
    mirror: M,
    hasher: H,
    chain_id: u64,
    genesis_block_hash: Digest,
    current: Option<(SignerState, Digest)>,
    classified: Option<Classified>,
    removed_temp: bool,
}

impl<D: SignerDir, M: MirrorStore, H: StateHasher> FileSignerStore<D, M, H> {
    pub fn new(dir: D, mirror: M, hasher: H, chain_id: u64, genesis_block_hash: Digest) -> Self {
        Self {
            dir,
            mirror,
            hasher,
            chain_id,
            genesis_block_hash,
            current: None,
            classified: None,
            removed_temp: false,
        }
    }

    /// How the last load classified the state.
    pub fn classified(&self) -> Option<Classified> {
        self.classified
    }

    /// Whether the last load removed a leftover temp file.
    pub fn removed_temp(&self) -> bool {
        self.removed_temp
    }

    fn decode_checked(
        &self,
        what: &'static str,
        bytes: &[u8],
    ) -> Result<(SignerState, Digest), StoreError> {
        let (state, sum) = SignerState::decode(bytes, &self.hasher)
            .map_err(|e| StoreError(format!("{what}: {e}")))?;
        if state.identity.chain_id != self.chain_id {
            return Err(StoreError(format!(
                "{what}: {}",
                StateError::Identity("chain id")
            )));
        }
        if state.identity.genesis_block_hash != self.genesis_block_hash {
            return Err(StoreError(format!(
                "{what}: {}",
                StateError::Identity("genesis block hash")
            )));
        }
        Ok((state, sum))
    }

    /// Make the state file durable before a repair writes the mirror from it,
    /// so the mirror can never get ahead of the durable state file.
    fn make_state_durable(&mut self) -> Result<(), StoreError> {
        self.dir
            .sync_file(STATE_FILE)
            .map_err(|e| StoreError(format!("repair: sync state file: {e}")))?;
        self.dir
            .sync_dir()
            .map_err(|e| StoreError(format!("repair: sync directory: {e}")))
    }

    fn io(step: &str, e: IoError) -> StoreError {
        StoreError(format!("{step}: {e}"))
    }
}

impl<D: SignerDir, M: MirrorStore, H: StateHasher> SignerStore for FileSignerStore<D, M, H> {
    /// Classify the durable state. Refusals are `Err`; the only repairs are R0
    /// and R1 ([`Classified`]).
    fn load(&mut self) -> Result<Option<SignerRecord>, StoreError> {
        self.current = None;
        self.classified = None;
        self.removed_temp = false;
        if self
            .dir
            .read(TEMP_FILE)
            .map_err(|e| Self::io("read temp file", e))?
            .is_some()
        {
            // Never renamed, so never authoritative, and its signature was never
            // released (release follows P2).
            self.dir
                .remove(TEMP_FILE)
                .map_err(|e| Self::io("remove temp file", e))?;
            self.dir
                .sync_dir()
                .map_err(|e| Self::io("sync directory", e))?;
            self.removed_temp = true;
        }
        let file = self
            .dir
            .read(STATE_FILE)
            .map_err(|e| Self::io("read state file", e))?;
        let mirror = self.mirror.read().map_err(|e| Self::io("read mirror", e))?;
        match (file, mirror) {
            (None, None) => {
                self.classified = Some(Classified::Uninitialized);
                Ok(None)
            }
            (None, Some(_)) => Err(StoreError(
                "state file missing while the mirror exists".into(),
            )),
            (Some(f), None) => {
                let (fs, fsum) = self.decode_checked("state file", &f)?;
                if fs.counter != 0 {
                    return Err(StoreError(
                        "mirror missing for a state that has signed".into(),
                    ));
                }
                self.make_state_durable()?;
                self.mirror
                    .write_synced(&f)
                    .map_err(|e| Self::io("repair: write mirror", e))?;
                self.classified = Some(Classified::CompletedInitialization);
                let record = fs.to_record();
                self.current = Some((fs, fsum));
                Ok(Some(record))
            }
            (Some(f), Some(m)) => {
                let (fs, fsum) = self.decode_checked("state file", &f)?;
                let (ms, msum) = self.decode_checked("mirror", &m)?;
                if fs.identity != ms.identity || fs.floor_height != ms.floor_height {
                    return Err(StoreError(
                        "state file and mirror name different identities or floors".into(),
                    ));
                }
                if fs.counter == ms.counter {
                    if f != m {
                        return Err(StoreError(
                            "state file and mirror differ at the same counter".into(),
                        ));
                    }
                    self.classified = Some(Classified::Consistent);
                } else if ms.counter.checked_add(1) == Some(fs.counter) {
                    ms.check_successor(&msum, &fs)
                        .map_err(|e| StoreError(format!("one-ahead state file: {e}")))?;
                    self.make_state_durable()?;
                    self.mirror
                        .write_synced(&f)
                        .map_err(|e| Self::io("repair: write mirror", e))?;
                    self.classified = Some(Classified::AdvancedMirror);
                } else if fs.counter < ms.counter {
                    return Err(StoreError(
                        "state file is behind the mirror (rolled back)".into(),
                    ));
                } else {
                    return Err(StoreError(
                        "state file is more than one persist ahead of the mirror".into(),
                    ));
                }
                let record = fs.to_record();
                self.current = Some((fs, fsum));
                Ok(Some(record))
            }
        }
    }

    /// P1 then P2; `Ok` only after both. Refuses to write a record that is not
    /// the exact successor of the current one.
    fn persist(&mut self, record: &SignerRecord) -> Result<(), StoreError> {
        let identity = Identity {
            chain_id: self.chain_id,
            genesis_block_hash: self.genesis_block_hash,
            signer_pubkey: record.key_id,
        };
        let prev = match (&self.current, record.sequence) {
            (None, 0) => ZERO,
            (Some(_), 0) => {
                return Err(StoreError("initialization over existing state".into()));
            }
            (None, _) => return Err(StoreError("no current state to succeed".into())),
            (Some((_, sum)), _) => *sum,
        };
        let next = SignerState::from_record(record, identity, prev, &self.hasher)
            .map_err(|e| StoreError(format!("encode: {e}")))?;
        if let Some((cur, sum)) = &self.current {
            cur.check_successor(sum, &next)
                .map_err(|e| StoreError(format!("refused transition: {e}")))?;
        }
        let bytes = next
            .encode(&self.hasher)
            .map_err(|e| StoreError(format!("encode: {e}")))?;
        self.dir
            .write_new(TEMP_FILE, &bytes)
            .map_err(|e| Self::io("P1 write temp file", e))?;
        self.dir
            .sync_file(TEMP_FILE)
            .map_err(|e| Self::io("P1 sync temp file", e))?;
        self.dir
            .rename(TEMP_FILE, STATE_FILE)
            .map_err(|e| Self::io("P1 rename", e))?;
        self.dir
            .sync_dir()
            .map_err(|e| Self::io("P1 sync directory", e))?;
        self.mirror
            .write_synced(&bytes)
            .map_err(|e| Self::io("P2 write mirror", e))?;
        let sum: Digest = bytes[316..348].try_into().expect("32 bytes");
        self.current = Some((next, sum));
        Ok(())
    }

    fn sign_bytes_digest(&self, sign_bytes: &[u8]) -> Option<Digest> {
        Some(sign_bytes_digest(&self.hasher, sign_bytes))
    }
}

/// [`SignerDir`] over a real directory. Directory sync is supported on Unix
/// only; elsewhere it fails, so persisting fails closed.
pub struct StdSignerDir {
    path: PathBuf,
}

impl StdSignerDir {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

fn io_err(e: std::io::Error) -> IoError {
    IoError(e.to_string())
}

impl SignerDir for StdSignerDir {
    fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, IoError> {
        match std::fs::read(self.path.join(name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(e)),
        }
    }

    fn write_new(&mut self, name: &str, bytes: &[u8]) -> Result<(), IoError> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.path.join(name))
            .map_err(io_err)?;
        f.write_all(bytes).map_err(io_err)
    }

    fn sync_file(&mut self, name: &str) -> Result<(), IoError> {
        std::fs::File::open(self.path.join(name))
            .and_then(|f| f.sync_all())
            .map_err(io_err)
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), IoError> {
        std::fs::rename(self.path.join(from), self.path.join(to)).map_err(io_err)
    }

    #[cfg(unix)]
    fn sync_dir(&mut self) -> Result<(), IoError> {
        std::fs::File::open(&self.path)
            .and_then(|d| d.sync_all())
            .map_err(io_err)
    }

    #[cfg(not(unix))]
    fn sync_dir(&mut self) -> Result<(), IoError> {
        Err(IoError(
            "directory sync is not supported on this platform".into(),
        ))
    }

    fn remove(&mut self, name: &str) -> Result<(), IoError> {
        match std::fs::remove_file(self.path.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(e)),
        }
    }
}

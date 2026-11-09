//! The durable finality signer (G2-b) over this node's data directory: the
//! signer wiring of #350 (#270 bullet 3) that the owner's adoption of B6
//! (2026-11-09) unlocked.
//!
//! # DORMANT
//!
//! This binary produces no finality vote. `run` never calls into this module
//! and no node path opens a signer: the finality crate's dormancy guard
//! (`crates/finality-foundations/tests/dormant.rs`, narrowed to this wiring
//! with the owner's authorization, 2026-11-09) fails if one starts to, and
//! `tests/signer_run_dormant.rs` runs a producing validator and finds no
//! signer state created and none signed. Only the operator commands
//! `sumchain signer init` and `sumchain signer status` reach it, and neither
//! signs anything. A signer opened here ([`open`]) could not change a lock or
//! leave its working height either: its proof verifier ([`NoProofVerifier`])
//! refuses every proof.
//!
//! # What is wired
//!
//! | Piece | Here | Decided |
//! |---|---|---|
//! | state files | `<data_dir>/finality/` ([`SIGNER_DIR`]) over `StdSignerDir`: `signer.v1`, `signer.v1.tmp`, `proof.tmp`, `proof-<hex>.v1`, `conflict-H.*` | file names B6 (2026-11-09); archive names 2026-10-23; the directory, owner 2026-11-09 |
//! | mirror | `meta` key `finality/signer-mirror/v1` (named in storage), a synced write ([`DbMirror`]) | B6; adapter and key kept as they are, owner 2026-11-09 |
//! | persistence | G/P0/P1/P2, as `FileSignerStore` implements it | B6 |
//! | hash | BLAKE3-256 (`Blake3StateHasher`) | 2026-10-22 |
//! | exclusive ownership | `flock` on the state directory (`DirLock`) | G2-b |
//! | identity | `chain_id` from the genesis file and the genesis block hash, checked against the database's block at height 0 ([`SignerIdentity::of`]) | the 413-byte record binds both (2026-10-22) |
//! | key | initialization takes the validator's PUBLIC key only; a signing path loads the private key ([`ValidatorKey`]) and [`open`] refuses it, before anything is written, unless its public key is the one initialized; signatures are pure Ed25519 | owner 2026-11-09; VS-1/3/4: votes are signed by the genesis validator keys |
//! | chain | [`CanonicalChain`]: the canonical stored block hash at each height (`Block::hash()` for the current block format), for recovery "against the node's chain" | owner 2026-11-09; no new header or proposal envelope is adopted |
//! | database | `signer init` opens only an existing, compatible database ([`Database::open_existing`]) and creates nothing in it but the mirror record | owner 2026-11-09 |
//!
//! # Not here: each waits on a decision still PROPOSED
//!
//! * The production proof verifier (`proofs::ConsensusProofs` over a
//!   `VoteContext`) needs the configuration commitment a vote carries: E-def.
//! * Anything that asks the signer for a signature: the round engine, the
//!   proposer rule and the proposal envelope (ENGINE, PROP, HDR), and
//!   certificate production (#350 item 1).
//! * The evidence floor at open (the highest position this key is known to
//!   have signed, read from stored certificates): no certificate is stored.
//! * A chain view that, from H_F, holds certified blocks only: H_F and how it
//!   is set (ACT, #352).
//! * Whether a validator with no initialized signer refuses to start or only
//!   warns once H_F is set (an activation-plan choice).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sumchain_crypto::{KeyPair, PublicKey};
use sumchain_finality_foundations::signer::{
    initialize_exclusive, ChainView, DurableSigner, PolkaVerifier, SignerError, SignerRecord,
    SignerStore, SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{
    floor_below_height, Blake3StateHasher, Classified, FileSignerStore, IoError, MirrorStore,
    ProofStatus, SignerDir, StdSignerDir,
};
use sumchain_finality_foundations::signer_lock::{DirLock, DirLockGuard};
use sumchain_finality_foundations::Digest;
use sumchain_genesis::Genesis;
use sumchain_storage::certified_meta::SIGNER_MIRROR_KEY;
use sumchain_storage::{cf, BlockStore, Database};

/// The signer's directory under the data directory: the `<data_dir>/finality/`
/// that `SignerDir` names (adopted by the owner, 2026-11-09).
pub const SIGNER_DIR: &str = "finality";

/// `<data_dir>/finality`.
pub fn signer_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(SIGNER_DIR)
}

/// Who a signer state belongs to, besides its key: the chain identifier the
/// node runs with and the hash of the genesis block it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerIdentity {
    pub chain_id: u64,
    pub genesis_block_hash: Digest,
}

impl SignerIdentity {
    /// The identity of the chain `db` holds under `genesis`: refused unless
    /// the database's block at height 0 is the genesis block `genesis` builds.
    pub fn of(genesis: &Genesis, db: &Database) -> Result<Self> {
        let built = genesis
            .create_genesis_block()
            .context("building the genesis block from the genesis file")?
            .hash();
        let held = BlockStore::new(db)
            .get_hash_by_height(0)
            .context("reading the data directory's genesis block")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the data directory holds no chain: no block at height 0 (a node writes \
                     its genesis block when it first starts)"
                )
            })?;
        if held != built {
            anyhow::bail!(
                "the data directory's genesis block is {held}, but the genesis file builds \
                 {built}: they are different chains"
            );
        }
        Ok(Self {
            chain_id: genesis.chain_id,
            genesis_block_hash: *built.as_bytes(),
        })
    }
}

/// The mirror: the 413-byte state in `meta` under `finality/signer-mirror/v1`,
/// written with a synced WAL write (the persistence protocol's P2).
pub struct DbMirror {
    db: Arc<Database>,
}

impl DbMirror {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

impl MirrorStore for DbMirror {
    fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        self.db
            .get(cf::META, SIGNER_MIRROR_KEY)
            .map_err(|e| IoError(e.to_string()))
    }

    fn write_synced(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        let mut batch = self.db.batch();
        batch
            .put(cf::META, SIGNER_MIRROR_KEY, bytes)
            .map_err(|e| IoError(e.to_string()))?;
        batch.commit_durable().map_err(|e| IoError(e.to_string()))
    }
}

/// The node's chain for the signer: the canonical stored block hash at each
/// height, from the height index; for the current block format it is
/// `Block::hash()` (owner, 2026-11-09; this adopts no new header or proposal
/// envelope). A height the node does not hold, or cannot read, is `None`,
/// which a recovery treats as "not this block".
#[cfg_attr(not(test), allow(dead_code))] // dormant: no node path recovers a signer
pub struct CanonicalChain {
    db: Arc<Database>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl CanonicalChain {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

impl ChainView for CanonicalChain {
    fn block_at(&self, height: u64) -> Option<Digest> {
        BlockStore::new(&self.db)
            .get_hash_by_height(height)
            .ok()
            .flatten()
            .map(|hash| *hash.as_bytes())
    }
}

/// The validator's private key, loaded for signing: the record's
/// `signer_pubkey` is its Ed25519 public key, and a signature is pure Ed25519
/// over the sign bytes. [`open`] refuses it unless that public key is the one
/// the state was initialized for.
#[cfg_attr(not(test), allow(dead_code))] // dormant: no node path opens a signer
pub struct ValidatorKey(pub KeyPair);

impl SigningKey for ValidatorKey {
    fn key_id(&self) -> Digest {
        *self.0.public_key().as_bytes()
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        sumchain_crypto::sign(payload, self.0.private_key())
            .to_bytes()
            .to_vec()
    }
}

/// The proof verifier this binary has: none. A prevote quorum (a lock
/// change) and a finality proof (a height advancement or a recovery) are
/// checked against the configuration commitment a vote carries, which is not
/// decided (E-def), so every one is refused.
#[cfg_attr(not(test), allow(dead_code))] // dormant: no node path opens a signer
pub struct NoProofVerifier;

impl PolkaVerifier for NoProofVerifier {
    fn verify_polka(
        &self,
        _height: u64,
        _round: u32,
        _value: &Digest,
        _evidence: &[u8],
    ) -> Result<(), String> {
        Err("this binary verifies no prevote quorum (certified finality is not active)".into())
    }
    // `verify_finality` keeps the default, which refuses every proof.
}

/// The store over this node's data directory and database.
pub type NodeSignerStore = FileSignerStore<StdSignerDir, DbMirror, Blake3StateHasher>;

/// A signer opened over this node's data directory.
#[cfg_attr(not(test), allow(dead_code))] // dormant: no node path opens a signer
pub type NodeSigner = DurableSigner<NodeSignerStore, ValidatorKey, NoProofVerifier, DirLockGuard>;

/// The store over `<data_dir>/finality` and the mirror in `db`.
pub fn store(data_dir: &Path, db: Arc<Database>, id: SignerIdentity) -> NodeSignerStore {
    FileSignerStore::new(
        StdSignerDir::new(signer_dir(data_dir)),
        DbMirror::new(db),
        Blake3StateHasher,
        id.chain_id,
        id.genesis_block_hash,
    )
}

/// The exclusive lock of `<data_dir>/finality`.
pub fn ownership(data_dir: &Path) -> DirLock {
    DirLock::new(signer_dir(data_dir))
}

/// Explicit initialization (G2-b) of the signer for the key `signer_pubkey`:
/// creates `<data_dir>/finality` if needed, then the first state, durably,
/// under the directory's lock. `floor_height`: the first height the signer
/// may sign at. Refused (B6) when any state exists, when the mirror exists
/// without the state file, or when the directory holds an earlier signer's
/// proof or conflict files; a directory created here is removed again on a
/// refusal.
pub fn initialize(
    data_dir: &Path,
    db: Arc<Database>,
    id: SignerIdentity,
    signer_pubkey: Digest,
    floor_height: Option<u64>,
) -> Result<(), SignerError> {
    let dir = signer_dir(data_dir);
    let created = !dir.exists();
    if created {
        std::fs::create_dir(&dir)
            .and_then(|()| sync_dir(data_dir))
            .map_err(|e| SignerError::PersistFailed(format!("creating {}: {e}", dir.display())))?;
    }
    let result = initialize_exclusive(
        &ownership(data_dir),
        &mut store(data_dir, db, id),
        signer_pubkey,
        floor_height.and_then(floor_below_height),
    );
    if result.is_err() && created {
        // Only an empty directory is removed: a refusal wrote nothing in it.
        let _ = std::fs::remove_dir(&dir);
    }
    result
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "directory sync is not supported on this platform",
    ))
}

/// Open this node's signer with the private key `key`. First the key: unless
/// its public key is the one the state was initialized for, the open is
/// refused (`KeyMismatch`) before anything is locked, repaired or written.
/// Then the lock and the durable state. Never creates state: a missing
/// directory or state file is `NotInitialized` (or `Corrupt` when the mirror
/// exists without it).
///
/// DORMANT: no node path calls this; only tests do.
#[cfg_attr(not(test), allow(dead_code))]
pub fn open(
    data_dir: &Path,
    db: Arc<Database>,
    id: SignerIdentity,
    key: KeyPair,
) -> Result<NodeSigner, SignerError> {
    if !signer_dir(data_dir).is_dir() {
        let mirror = DbMirror::new(db)
            .read()
            .map_err(|e| SignerError::Corrupt(e.0))?;
        return Err(match mirror {
            None => SignerError::NotInitialized,
            Some(_) => SignerError::Corrupt(
                "the signer directory is missing while the mirror exists".into(),
            ),
        });
    }
    check_signing_key(data_dir, &db, id, &key)?;
    DurableSigner::open(
        &ownership(data_dir),
        store(data_dir, db, id),
        ValidatorKey(key),
        NoProofVerifier,
        None,
    )
}

/// The check every signing path makes when it loads the private key: the
/// state, as the next open would load it (on a copy, so nothing is written),
/// must have been initialized for this key's public key.
#[cfg_attr(not(test), allow(dead_code))] // dormant: no node path opens a signer
fn check_signing_key(
    data_dir: &Path,
    db: &Database,
    id: SignerIdentity,
    key: &KeyPair,
) -> Result<(), SignerError> {
    let s = status(data_dir, db, id).map_err(|e| SignerError::Corrupt(format!("{e:#}")))?;
    match (s.verdict, s.record) {
        (StatusVerdict::NotInitialized, _) => Err(SignerError::NotInitialized),
        (StatusVerdict::Refused(why), _) => Err(SignerError::Corrupt(why)),
        (StatusVerdict::Opens, Some(r)) if r.key_id == *key.public_key().as_bytes() => Ok(()),
        (StatusVerdict::Opens, Some(_)) => Err(SignerError::KeyMismatch),
        (StatusVerdict::Opens, None) => Err(SignerError::Corrupt("no record loaded".into())),
    }
}

// ── status: the store's load, run on a copy ─────────────────────────────────

/// A copy of the signer directory in memory. `status` runs the store's load
/// on it, so the repairs and cleanups a real open would make change only the
/// copy.
struct CopyDir(BTreeMap<String, Result<Vec<u8>, String>>);

impl CopyDir {
    /// Every entry of `dir` (none when it is missing). An entry that cannot be
    /// read as a file is kept as an error, as reading it would fail.
    fn of(dir: &Path) -> Result<Self> {
        let mut files = BTreeMap::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self(files)),
            Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
            if let Some(name) = entry.file_name().to_str() {
                files.insert(
                    name.to_string(),
                    std::fs::read(entry.path()).map_err(|e| e.to_string()),
                );
            }
        }
        Ok(Self(files))
    }
}

impl SignerDir for CopyDir {
    fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, IoError> {
        match self.0.get(name) {
            None => Ok(None),
            Some(Ok(bytes)) => Ok(Some(bytes.clone())),
            Some(Err(e)) => Err(IoError(e.clone())),
        }
    }
    fn write_new(&mut self, name: &str, bytes: &[u8]) -> Result<(), IoError> {
        self.0.insert(name.to_string(), Ok(bytes.to_vec()));
        Ok(())
    }
    fn sync_file(&mut self, _name: &str) -> Result<(), IoError> {
        Ok(())
    }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), IoError> {
        let entry = self
            .0
            .remove(from)
            .ok_or_else(|| IoError(format!("{from}: not found")))?;
        self.0.insert(to.to_string(), entry);
        Ok(())
    }
    fn sync_dir(&mut self) -> Result<(), IoError> {
        Ok(())
    }
    fn remove(&mut self, name: &str) -> Result<(), IoError> {
        self.0.remove(name);
        Ok(())
    }
    fn list(&mut self) -> Result<Vec<String>, IoError> {
        Ok(self.0.keys().cloned().collect())
    }
}

/// A copy of the mirror in memory.
struct CopyMirror(Option<Vec<u8>>);

impl MirrorStore for CopyMirror {
    fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        Ok(self.0.clone())
    }
    fn write_synced(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        self.0 = Some(bytes.to_vec());
        Ok(())
    }
}

/// What the next open of the signer would find.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusVerdict {
    /// Neither a state file nor a mirror: `signer init` has not run.
    NotInitialized,
    /// The store loads a state (perhaps after a repair it reports).
    Opens,
    /// The store refuses the state: missing, corrupt, rolled back or another
    /// chain's.
    Refused(String),
}

/// `signer status`: what the store's load makes of the signer's files and
/// mirror. Nothing is locked, repaired, removed or written.
#[derive(Debug, Clone)]
pub struct SignerStatus {
    pub verdict: StatusVerdict,
    pub record: Option<SignerRecord>,
    pub classified: Option<Classified>,
    pub proof_status: ProofStatus,
    pub removes_temp: bool,
    pub removes_orphans: Vec<String>,
}

/// The status of the signer in `data_dir` against `db` (which may be opened
/// read-only) and the identity `id`.
pub fn status(data_dir: &Path, db: &Database, id: SignerIdentity) -> Result<SignerStatus> {
    let dir = CopyDir::of(&signer_dir(data_dir))?;
    let mirror = CopyMirror(
        db.get(cf::META, SIGNER_MIRROR_KEY)
            .context("reading the signer mirror")?,
    );
    let mut copy = FileSignerStore::new(
        dir,
        mirror,
        Blake3StateHasher,
        id.chain_id,
        id.genesis_block_hash,
    );
    let (verdict, record) = match copy.load() {
        Ok(None) => (StatusVerdict::NotInitialized, None),
        Ok(Some(record)) => (StatusVerdict::Opens, Some(record)),
        Err(e) => (StatusVerdict::Refused(e.0), None),
    };
    Ok(SignerStatus {
        verdict,
        record,
        classified: copy.classified(),
        proof_status: copy.proof_status(),
        removes_temp: copy.removed_temp(),
        removes_orphans: copy.removed_orphans().to_vec(),
    })
}

// ── the operator commands ───────────────────────────────────────────────────

/// `sumchain signer …`
#[derive(clap::Args)]
pub struct SignerArgs {
    #[command(subcommand)]
    pub command: SignerCommand,
}

#[derive(clap::Subcommand)]
pub enum SignerCommand {
    /// Create this validator's finality-signer state, once, on a STOPPED node.
    ///
    /// G2-b: the state exists only after this explicit initialization. It
    /// needs the validator's PUBLIC key only; a signing path loads the private
    /// key later and refuses it unless it matches. It writes
    /// `<data-dir>/finality/signer.v1` and the mirror record in the node
    /// database, both durably, and nothing else: it opens only an existing,
    /// compatible database and creates no column family (prepare an older
    /// database first). It refuses when any signer state already exists, when
    /// the directory holds an earlier signer's proof or conflict files, when
    /// another process holds the signer directory or the node database, and
    /// when --genesis is not the chain the data directory holds.
    ///
    /// DORMANT: this binary produces no finality votes, so nothing uses the
    /// state until a release that does. Never restore it from a backup and
    /// never use one key from two signers.
    Init {
        /// Data directory of the stopped node
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Genesis file the node runs with
        #[arg(short, long)]
        genesis: PathBuf,

        /// The validator's public key, base58 (as in the genesis file)
        #[arg(long)]
        validator_pubkey: String,

        /// The first height this signer may sign at; it refuses every lower
        /// height. Without it no height is fixed until the first signature.
        #[arg(long)]
        floor_height: Option<u64>,
    },

    /// Show the finality-signer state of a data directory, and write nothing.
    ///
    /// Runs the signer store's load on a copy of the state directory and the
    /// mirror (the database is opened read-only): it reports what the next
    /// open would find, including any repair or cleanup that open would make.
    /// Exits 0 when the state opens, 2 when it is refused, 3 when no state has
    /// been initialized.
    Status {
        /// Data directory
        #[arg(short, long, default_value = "data")]
        data_dir: PathBuf,

        /// Genesis file the node runs with
        #[arg(short, long)]
        genesis: PathBuf,
    },
}

/// Run a `signer` command; returns the process exit code.
pub fn run_cli(args: SignerArgs) -> Result<i32> {
    match args.command {
        SignerCommand::Init {
            data_dir,
            genesis,
            validator_pubkey,
            floor_height,
        } => init_command(&data_dir, &genesis, &validator_pubkey, floor_height).map(|()| 0),
        SignerCommand::Status { data_dir, genesis } => status_command(&data_dir, &genesis),
    }
}

fn load_genesis(path: &Path) -> Result<Genesis> {
    Genesis::from_file(path).with_context(|| format!("failed to load genesis from {path:?}"))
}

fn is_genesis_validator(genesis: &Genesis, key: &Digest) -> bool {
    genesis
        .validator_pubkeys()
        .is_ok_and(|keys| keys.contains(key))
}

fn print_identity(dir: &Path, id: &SignerIdentity) {
    println!("Signer directory: {}", dir.display());
    println!(
        "Identity:         chain id {}, genesis block {}",
        id.chain_id,
        hex::encode(id.genesis_block_hash)
    );
}

fn init_command(
    data_dir: &Path,
    genesis_path: &Path,
    validator_pubkey: &str,
    floor_height: Option<u64>,
) -> Result<()> {
    let genesis = load_genesis(genesis_path)?;
    let key = PublicKey::from_base58(validator_pubkey)
        .with_context(|| format!("--validator-pubkey {validator_pubkey:?} is not a public key"))?;
    if !data_dir.is_dir() {
        anyhow::bail!("no data directory at {data_dir:?}; nothing was initialized or created");
    }
    // Read-write, for the mirror record; never created, and no column family
    // is created in it.
    let db = Database::open_existing(data_dir).with_context(|| {
        format!(
            "cannot open the node database in {data_dir:?} as it is (stop the node first; \
             prepare an older database first)"
        )
    })?;
    let db = Arc::new(db);
    let id = SignerIdentity::of(&genesis, &db)?;
    let pubkey = *key.as_bytes();
    initialize(data_dir, db, id, pubkey, floor_height)
        .context("the finality signer was not initialized")?;

    print_identity(&signer_dir(data_dir), &id);
    println!(
        "Key:              {} ({})",
        key.to_base58(),
        if is_genesis_validator(&genesis, &pubkey) {
            "a genesis validator"
        } else {
            "NOT a genesis validator: its votes would not count"
        }
    );
    match floor_height.filter(|h| *h > 0) {
        Some(h) => println!("Floor:            nothing below height {h} is signed"),
        None => println!("Floor:            none; the first signature fixes the working height"),
    }
    println!("Result: INITIALIZED");
    println!("This binary produces no finality votes; nothing uses this state yet.");
    Ok(())
}

fn status_command(data_dir: &Path, genesis_path: &Path) -> Result<i32> {
    let genesis = load_genesis(genesis_path)?;
    if !data_dir.is_dir() {
        anyhow::bail!("no data directory at {data_dir:?}; nothing was checked or created");
    }
    let db = Database::open_read_only(data_dir)
        .with_context(|| format!("cannot open {data_dir:?} read-only"))?;
    let id = SignerIdentity::of(&genesis, &db)?;
    let s = status(data_dir, &db, id)?;

    print_identity(&signer_dir(data_dir), &id);
    println!("                  (read-only: nothing was locked, repaired or written)");
    let code = match &s.verdict {
        StatusVerdict::NotInitialized => {
            println!("State:            not initialized (no state file and no mirror)");
            println!("Result: NOT_INITIALIZED");
            3
        }
        StatusVerdict::Refused(why) => {
            println!("State:            refused: {why}");
            println!("  An open of this signer refuses it, so it would release no vote.");
            println!("Result: REFUSED");
            2
        }
        StatusVerdict::Opens => {
            print_record(&genesis, &s);
            println!("Result: OPENS");
            0
        }
    };
    println!("This binary produces no finality votes; nothing uses this state yet.");
    Ok(code)
}

fn print_record(genesis: &Genesis, s: &SignerStatus) {
    let state = match s.classified {
        Some(Classified::CompletedInitialization) => {
            "initialized; the next open completes the interrupted initialization (R0)"
        }
        Some(Classified::AdvancedMirror) => {
            "the mirror is one persist behind; the next open advances it (R1)"
        }
        _ => "the state file and the mirror agree",
    };
    println!("State:            {state}");
    let Some(r) = s.record.as_ref() else {
        return;
    };
    println!(
        "Key:              {} ({})",
        PublicKey::from_bytes(r.key_id).to_base58(),
        if is_genesis_validator(genesis, &r.key_id) {
            "a genesis validator"
        } else {
            "NOT a genesis validator"
        }
    );
    println!("Persists:         {}", r.sequence);
    match r.working_height() {
        Some(h) => println!("Working height:   {h}"),
        None => println!("Working height:   none fixed yet"),
    }
    match r.last.as_ref() {
        Some(l) => println!(
            "Last signature:   height {}, round {}, {}, {}",
            l.position.height,
            l.position.round,
            step_name(l.position.step),
            value_name(&l.value)
        ),
        None => println!("Last signature:   none"),
    }
    match r.lock {
        Some(l) => println!(
            "Lock:             height {}, round {}, block {}",
            l.height,
            l.round,
            hex::encode(l.value)
        ),
        None => println!("Lock:             none"),
    }
    match r.certified {
        Some(c) => println!(
            "Certified:        height {}, block {}",
            c.height,
            hex::encode(c.block_id)
        ),
        None => println!("Certified:        none"),
    }
    match r.halt.as_ref() {
        Some(h) => println!(
            "Halted:           YES, conflicting finality at height {}; only operator recovery \
             with verified evidence ends it",
            h.height
        ),
        None => println!("Halted:           no"),
    }
    let proof = match s.proof_status {
        ProofStatus::NotReferenced => "none referenced",
        ProofStatus::Present => "present",
        ProofStatus::Missing => "MISSING (degraded: the lock or halt is still enforced)",
        ProofStatus::Corrupt => "CORRUPT (degraded: the lock or halt is still enforced)",
    };
    println!("Retained proof:   {proof}");
    if s.removes_temp {
        println!("Next open:        removes a leftover signer.v1.tmp");
    }
    if !s.removes_orphans.is_empty() {
        println!(
            "Next open:        removes unreferenced proof files {}",
            s.removes_orphans.join(", ")
        );
    }
}

fn step_name(step: Step) -> &'static str {
    match step {
        Step::Propose => "proposal",
        Step::Prevote => "prevote",
        Step::Precommit => "precommit",
    }
}

fn value_name(value: &VoteValue) -> String {
    match value {
        VoteValue::Nil => "nil".to_string(),
        VoteValue::Block(d) => format!("block {}", hex::encode(d)),
    }
}

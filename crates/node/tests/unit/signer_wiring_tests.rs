//! The durable finality signer wired over a node's data directory (#350,
//! #270 bullet 3; B6, adopted 2026-11-09): `crate::finality_signer`.
//!
//! * Dormancy: a node that starts and imports blocks never touches the
//!   signer's files or mirror, whatever state they are in; a missing or
//!   corrupt state still imports blocks, and the signer then refuses to open,
//!   so no vote can be released. (Which code may name the signer is the
//!   finality crate's dormancy guard; `tests/signer_run_dormant.rs` runs a
//!   producing validator.)
//! * The database is opened only as it is: no column family is created.
//! * A signing path's private key must match the initialized public key, and
//!   a mismatch is refused before anything is written.
//! * The chain view, the identity, initialization and its refusals, and the
//!   refusals at open.
//! * Real processes: SIGKILL at every persist step of initialization,
//!   signing, a lock, a relock and an advancement, then a restart, never
//!   yields two different messages signed at one position; and a second
//!   process is refused while one holds the signer.
//!
//! Proofs, payloads and blocks are synthetic: the proof verifier here
//! accepts only the synthetic forms below, because the production verifier
//! waits on E-def. Only process crashes are tested, not power loss.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_finality_foundations::signer::{
    initialize_exclusive, Certified, ChainView, DurableSigner, ExclusiveOwnership, Justification,
    PolkaVerifier, SignPosition, SignRequest, SignerError, SigningKey, Step, VoteValue,
};
use sumchain_finality_foundations::signer_file::{
    floor_below_height, Blake3StateHasher, FileSignerStore, IoError, MirrorStore, SignerDir,
    SignerState, StdSignerDir, STATE_FILE,
};
use sumchain_finality_foundations::Digest;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Block, Hash};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::certified_meta::SIGNER_MIRROR_KEY;
use sumchain_storage::{cf, BlockStore, Database};

use super::Node;
use crate::finality_signer::{
    self, initialize, open, ownership, signer_dir, status, store, CanonicalChain, DbMirror,
    SignerIdentity, StatusVerdict, ValidatorKey,
};

const CHAIN_ID: u64 = 7;
const FLOOR: u64 = 5;
const A: Digest = [0xA1; 32];
const B: Digest = [0xB2; 32];
const C: Digest = [0xC3; 32];

fn validator() -> KeyPair {
    KeyPair::from_bytes([41u8; 32])
}

fn pubkey() -> Digest {
    *validator().public_key().as_bytes()
}

fn genesis_with(chain_id: u64, genesis_time: u64) -> Genesis {
    Genesis::new(
        chain_id,
        genesis_time,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams {
            finality_depth: 2,
            ..ChainParams::default()
        },
    )
}

fn genesis() -> Genesis {
    genesis_with(CHAIN_ID, 1_734_624_000_000)
}

fn engine(db: &Arc<Database>, key: Option<KeyPair>) -> PoAEngine {
    let g = genesis();
    PoAEngine::new(
        db.clone(),
        Arc::new(StateManager::new(db.clone(), g.chain_id)),
        Arc::new(Mempool::new(MempoolConfig::default())),
        &g,
        key,
    )
    .unwrap()
}

/// A stopped node's data directory holding genesis only.
fn chain_at_genesis(dir: &Path) {
    let db = Arc::new(Database::open_default(dir).unwrap());
    engine(&db, None).init_genesis(&genesis()).unwrap();
}

/// `n` blocks produced on top of genesis in `dir`; every handle is closed on
/// return.
fn produced(dir: &Path, n: u64) -> Vec<Block> {
    let db = Arc::new(Database::open_default(dir).unwrap());
    let e = engine(&db, Some(validator()));
    let genesis_block = e.init_genesis(&genesis()).unwrap();
    let rt = runtime();
    let mut blocks = vec![genesis_block];
    for _ in 0..n {
        blocks.push(rt.block_on(e.propose_block(Vec::new())).unwrap());
    }
    blocks
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn identity(db: &Database) -> SignerIdentity {
    SignerIdentity::of(&genesis(), db).unwrap()
}

/// Every file of the signer directory with its contents (none when the
/// directory is missing).
fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    match std::fs::read_dir(signer_dir(dir)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => panic!("{e}"),
        Ok(entries) => entries
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect(),
    }
}

fn mirror(db: &Database) -> Option<Vec<u8>> {
    db.get(cf::META, SIGNER_MIRROR_KEY).unwrap()
}

fn position(height: u64, round: u32, step: Step) -> SignPosition {
    SignPosition {
        height,
        round,
        step,
    }
}

fn request(height: u64, round: u32, step: Step, value: Digest) -> SignRequest {
    SignRequest {
        position: position(height, round, step),
        value: VoteValue::Block(value),
        payload: format!("{height}/{round}/{step:?}/{}", hex::encode(&value[..4])).into_bytes(),
        justification: None,
    }
}

fn justified(mut r: SignRequest, polka_round: u32, value: &Digest) -> SignRequest {
    r.justification = Some(Justification {
        polka_round,
        evidence: polka(r.position.height, polka_round, value),
    });
    r
}

fn prevote(h: u64, r: u32, v: Digest) -> SignRequest {
    request(h, r, Step::Prevote, v)
}

fn precommit(h: u64, r: u32, v: Digest) -> SignRequest {
    justified(request(h, r, Step::Precommit, v), r, &v)
}

fn polka(height: u64, round: u32, value: &Digest) -> Vec<u8> {
    [
        b"polka".as_slice(),
        &height.to_le_bytes(),
        &round.to_le_bytes(),
        value,
    ]
    .concat()
}

fn finality(height: u64, block: &Digest) -> Vec<u8> {
    [b"final".as_slice(), &height.to_le_bytes(), block].concat()
}

/// A verifier of the synthetic proofs above, retaining what it accepts (as
/// `ConsensusProofs` retains real ones), so a lock writes its proof file
/// (P0) and a relock or an advancement leaves one to remove (G).
struct TestProofs;

impl PolkaVerifier for TestProofs {
    fn verify_polka(
        &self,
        height: u64,
        round: u32,
        value: &Digest,
        e: &[u8],
    ) -> Result<(), String> {
        (e == polka(height, round, value))
            .then_some(())
            .ok_or_else(|| "not a quorum of prevotes".into())
    }
    fn verify_finality(&self, proof: &[u8]) -> Result<Certified, String> {
        match proof.strip_prefix(b"final".as_slice()) {
            Some(rest) if rest.len() == 40 => Ok(Certified {
                height: u64::from_le_bytes(rest[..8].try_into().unwrap()),
                block_id: rest[8..].try_into().unwrap(),
            }),
            _ => Err("not a finality proof".into()),
        }
    }
    fn retained_polka(&self, h: u64, r: u32, v: &Digest, e: &[u8]) -> Option<Vec<u8>> {
        self.verify_polka(h, r, v, e).ok()?;
        Some(e.to_vec())
    }
    fn retained_finality(&self, proof: &[u8]) -> Option<Vec<u8>> {
        self.verify_finality(proof).ok()?;
        Some(proof.to_vec())
    }
}

fn verify_signature(payload: &[u8], signature: &[u8]) {
    sumchain_crypto::signature::verify_bytes_strict(
        payload,
        signature.try_into().expect("64 bytes"),
        &pubkey(),
    )
    .expect("a pure Ed25519 signature by the validator key");
}

// ── dormancy ────────────────────────────────────────────────────────────────
//
// Which code may name the signer, and what it may do, is enforced by the
// finality crate's dormancy guard (`crates/finality-foundations/tests/
// dormant.rs`); `tests/signer_run_dormant.rs` runs a producing validator.
// These are the behaviour beside them.

/// The signer module opens the node database only as it is: `signer init`
/// through `Database::open_existing` (no column family is ever created) and
/// `signer status` read-only. No other way of opening it appears there.
#[test]
fn the_signer_opens_the_database_only_as_it_is() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/finality_signer.rs"
    ))
    .unwrap();
    let opens: Vec<&str> = src
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .flat_map(|l| l.match_indices("Database::").map(move |(i, _)| &l[i..]))
        .filter(|call| call.starts_with("Database::open"))
        .map(|call| &call[..call.find('(').unwrap_or(call.len())])
        .collect();
    assert_eq!(
        opens,
        ["Database::open_existing", "Database::open_read_only"],
        "every database open in the signer module"
    );
}

/// A node that starts and imports blocks, as a validator with its key,
/// never touches the signer: with no signer it creates neither the directory
/// nor the mirror; with an initialized, corrupt or half-present one, every
/// file and the mirror are left byte for byte. Missing or corrupt state does
/// not stop the import, and the signer then refuses to open: no vote could be
/// released.
#[test]
fn a_node_imports_blocks_without_touching_the_signer_in_any_state() {
    #[derive(Debug, Clone, Copy)]
    enum Setup {
        None,
        Initialized,
        CorruptStateFile,
        MirrorWithoutStateFile,
    }
    let source = tempfile::TempDir::new().unwrap();
    let blocks = produced(source.path(), 4);
    let rt = runtime();

    for setup in [
        Setup::None,
        Setup::Initialized,
        Setup::CorruptStateFile,
        Setup::MirrorWithoutStateFile,
    ] {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("node");
        chain_at_genesis(&dir);
        {
            let db = Arc::new(Database::open_default(&dir).unwrap());
            let id = identity(&db);
            if !matches!(setup, Setup::None) {
                initialize(&dir, db.clone(), id, pubkey(), Some(FLOOR)).unwrap();
            }
            match setup {
                Setup::CorruptStateFile => {
                    let path = signer_dir(&dir).join(STATE_FILE);
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes[100] ^= 1;
                    std::fs::write(&path, bytes).unwrap();
                }
                Setup::MirrorWithoutStateFile => {
                    std::fs::remove_file(signer_dir(&dir).join(STATE_FILE)).unwrap();
                }
                Setup::None | Setup::Initialized => {}
            }
        }
        let before_files = files(&dir);
        let before_mirror = mirror(&Database::open_read_only(&dir).unwrap());

        {
            let node = Node::with_rpc_config(
                dir.clone(),
                genesis(),
                Some(validator()),
                sumchain_p2p::NetworkConfig::default(),
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                sumchain_rpc::RpcAuthConfig::disabled(),
                sumchain_rpc::RateLimitConfig::disabled(),
                crate::config::ConsensusSettings::default(),
            )
            .expect("the node starts");
            node.init_chain().expect("the chain loads");
            for b in &blocks[1..] {
                rt.block_on(node.consensus.import_block(b.clone()))
                    .unwrap_or_else(|e| panic!("{setup:?}: import of {}: {e}", b.height()));
            }
            assert_eq!(node.consensus.current_height(), 4, "{setup:?}");
            assert_eq!(files(&dir), before_files, "{setup:?}: the signer's files");
            assert_eq!(mirror(&node.db), before_mirror, "{setup:?}: the mirror");
        }

        let db = Arc::new(Database::open_default(&dir).unwrap());
        let id = identity(&db);
        let opened = open(&dir, db.clone(), id, validator()).map(|_| ());
        match setup {
            Setup::None => {
                assert!(!signer_dir(&dir).exists(), "no directory is created");
                assert_eq!(mirror(&db), None, "and no mirror");
                assert_eq!(opened, Err(SignerError::NotInitialized));
            }
            Setup::Initialized => assert_eq!(opened, Ok(())),
            Setup::CorruptStateFile | Setup::MirrorWithoutStateFile => {
                assert!(
                    matches!(opened, Err(SignerError::Corrupt(_))),
                    "{setup:?}: {opened:?}"
                );
            }
        }
    }
}

// ── the chain view and the identity ─────────────────────────────────────────

#[test]
fn the_chain_view_is_the_canonical_height_index() {
    let tmp = tempfile::TempDir::new().unwrap();
    let blocks = produced(tmp.path(), 4);
    let db = Arc::new(Database::open_default(tmp.path()).unwrap());
    let chain = CanonicalChain::new(db.clone());
    let store = BlockStore::new(&db);
    for b in &blocks {
        let h = b.height();
        assert_eq!(chain.block_at(h), Some(*b.hash().as_bytes()), "height {h}");
        assert_eq!(
            store.get_by_height(h).unwrap().unwrap().hash(),
            b.hash(),
            "the produced block is the canonical one"
        );
    }
    for h in [5, 6, u64::MAX] {
        assert_eq!(chain.block_at(h), None, "the node holds no block at {h}");
    }
    // A branch switch rewrites the index; the view reads it at each call.
    let other = Hash::hash(b"another block at height 4");
    db.put(cf::BLOCK_HEIGHT, &4u64.to_be_bytes(), other.as_bytes())
        .unwrap();
    assert_eq!(chain.block_at(4), Some(*other.as_bytes()));
    // An index entry that is not a hash is not a block.
    db.put(cf::BLOCK_HEIGHT, &3u64.to_be_bytes(), b"short")
        .unwrap();
    assert_eq!(chain.block_at(3), None);
}

#[test]
fn the_identity_is_the_genesis_files_chain_over_the_databases_genesis_block() {
    let tmp = tempfile::TempDir::new().unwrap();
    let blocks = produced(tmp.path(), 1);
    let db = Database::open_default(tmp.path()).unwrap();
    assert_eq!(
        SignerIdentity::of(&genesis(), &db).unwrap(),
        SignerIdentity {
            chain_id: CHAIN_ID,
            genesis_block_hash: *blocks[0].hash().as_bytes(),
        }
    );
    // The chain id is not an input of the genesis block: another one is
    // accepted here and refused by the state it does not match (below).
    assert_eq!(
        SignerIdentity::of(&genesis_with(CHAIN_ID + 1, 1_734_624_000_000), &db)
            .unwrap()
            .chain_id,
        CHAIN_ID + 1
    );
    let other = SignerIdentity::of(&genesis_with(CHAIN_ID, 1_734_624_000_001), &db)
        .unwrap_err()
        .to_string();
    assert!(other.contains("different chains"), "{other}");

    let empty = tempfile::TempDir::new().unwrap();
    let db = Database::open_default(empty.path()).unwrap();
    let none = SignerIdentity::of(&genesis(), &db).unwrap_err().to_string();
    assert!(none.contains("no block at height 0"), "{none}");
}

// ── initialization ──────────────────────────────────────────────────────────

#[test]
fn initialization_writes_the_state_file_and_its_mirror_once() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("node");
    chain_at_genesis(&dir);
    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);
    initialize(&dir, db.clone(), id, pubkey(), Some(FLOOR)).unwrap();

    let written = files(&dir);
    assert_eq!(
        written.keys().map(String::as_str).collect::<Vec<_>>(),
        [STATE_FILE],
        "exactly the state file: no temp file, no lock file"
    );
    let bytes = &written[STATE_FILE];
    assert_eq!(
        mirror(&db).as_ref(),
        Some(bytes),
        "the mirror is the same bytes"
    );
    let (state, _) = SignerState::decode(bytes, &Blake3StateHasher).unwrap();
    assert_eq!(state.counter, 0);
    assert_eq!(state.identity.chain_id, CHAIN_ID);
    assert_eq!(state.identity.genesis_block_hash, id.genesis_block_hash);
    assert_eq!(state.identity.signer_pubkey, pubkey());
    assert_eq!(state.floor_height, FLOOR);
    assert!(state.last.is_none() && state.lock.is_none() && !state.halted);

    assert_eq!(
        initialize(&dir, db.clone(), id, pubkey(), None),
        Err(SignerError::AlreadyInitialized)
    );
    let other_key = *KeyPair::from_bytes([42u8; 32]).public_key().as_bytes();
    assert_eq!(
        initialize(&dir, db.clone(), id, other_key, None),
        Err(SignerError::AlreadyInitialized),
        "one state per directory, whatever the key"
    );
    assert_eq!(files(&dir), written);
    assert_eq!(mirror(&db).as_ref(), Some(bytes));
}

/// The initialization refusals (B6), each writing nothing.
#[test]
fn initialization_refusals_write_nothing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("node");
    chain_at_genesis(&dir);
    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);

    // The mirror without the state file: the directory created for the
    // attempt is removed again.
    db.put(cf::META, SIGNER_MIRROR_KEY, &[1u8; 413]).unwrap();
    let refused = initialize(&dir, db.clone(), id, pubkey(), None);
    assert!(
        matches!(refused, Err(SignerError::Corrupt(ref m)) if m.contains("mirror")),
        "{refused:?}"
    );
    assert!(!signer_dir(&dir).exists());
    db.delete(cf::META, SIGNER_MIRROR_KEY).unwrap();

    // An earlier signer's retained proof or conflict archive.
    std::fs::create_dir(signer_dir(&dir)).unwrap();
    for name in [
        "conflict-9.receipt",
        &format!("proof-{}.v1", "ab".repeat(32)),
    ] {
        std::fs::write(signer_dir(&dir).join(name), b"earlier").unwrap();
        let before = files(&dir);
        let refused = initialize(&dir, db.clone(), id, pubkey(), None);
        assert!(
            matches!(refused, Err(SignerError::Corrupt(ref m)) if m.contains("earlier signer")),
            "{name}: {refused:?}"
        );
        assert_eq!(files(&dir), before, "{name}");
        assert_eq!(mirror(&db), None, "{name}");
        std::fs::remove_file(signer_dir(&dir).join(name)).unwrap();
    }

    // Another holder of the directory.
    let held = ownership(&dir).try_acquire().unwrap();
    assert!(matches!(
        initialize(&dir, db.clone(), id, pubkey(), None),
        Err(SignerError::OwnershipHeld(_))
    ));
    assert!(files(&dir).is_empty() && mirror(&db).is_none());
    drop(held);

    // A state made for another chain is not this chain's: refused, not
    // overwritten.
    let foreign = SignerIdentity {
        chain_id: CHAIN_ID + 1,
        ..id
    };
    initialize(&dir, db.clone(), foreign, pubkey(), None).unwrap();
    let before = (files(&dir), mirror(&db));
    let refused = initialize(&dir, db.clone(), id, pubkey(), None);
    assert!(
        matches!(refused, Err(SignerError::Corrupt(ref m)) if m.contains("identity mismatch")),
        "{refused:?}"
    );
    assert_eq!((files(&dir), mirror(&db)), before);
}

// ── open ────────────────────────────────────────────────────────────────────

/// The signer refuses to open, and so releases nothing, on a missing,
/// corrupt, foreign or rolled-back state.
#[test]
fn open_refuses_missing_corrupt_foreign_or_rolled_back_state() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("node");
    chain_at_genesis(&dir);
    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);
    let opened = |id: SignerIdentity, key: KeyPair| open(&dir, db.clone(), id, key).map(|_| ());

    assert_eq!(opened(id, validator()), Err(SignerError::NotInitialized));
    std::fs::create_dir(signer_dir(&dir)).unwrap();
    assert_eq!(opened(id, validator()), Err(SignerError::NotInitialized));

    initialize(&dir, db.clone(), id, pubkey(), Some(FLOOR)).unwrap();
    let initialized = files(&dir)[STATE_FILE].clone();
    assert_eq!(opened(id, validator()), Ok(()));

    // Another key, another chain id, another genesis block.
    assert_eq!(
        opened(id, KeyPair::from_bytes([42u8; 32])),
        Err(SignerError::KeyMismatch)
    );
    for other in [
        SignerIdentity {
            chain_id: CHAIN_ID + 1,
            ..id
        },
        SignerIdentity {
            genesis_block_hash: [0x99; 32],
            ..id
        },
    ] {
        let refused = opened(other, validator());
        assert!(
            matches!(refused, Err(SignerError::Corrupt(ref m)) if m.contains("identity mismatch")),
            "{refused:?}"
        );
    }

    // Two persists ahead of a mirror restored from before them: rolled back.
    {
        let mut s = open(&dir, db.clone(), id, validator()).unwrap();
        s.sign(&prevote(FLOOR, 0, A)).unwrap();
        s.sign(&prevote(FLOOR, 1, A)).unwrap();
    }
    let advanced = mirror(&db).unwrap();
    db.put(cf::META, SIGNER_MIRROR_KEY, &initialized).unwrap();
    let refused = opened(id, validator());
    assert!(
        matches!(refused, Err(SignerError::Corrupt(ref m)) if m.contains("more than one persist")),
        "{refused:?}"
    );
    db.put(cf::META, SIGNER_MIRROR_KEY, &advanced).unwrap();
    assert_eq!(opened(id, validator()), Ok(()));

    // A corrupt state file; then no state file while the mirror exists.
    let path = signer_dir(&dir).join(STATE_FILE);
    let good = std::fs::read(&path).unwrap();
    let mut bad = good.clone();
    bad[200] ^= 0x40;
    std::fs::write(&path, &bad).unwrap();
    assert!(matches!(
        opened(id, validator()),
        Err(SignerError::Corrupt(_))
    ));
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        opened(id, validator()),
        Err(SignerError::Corrupt(_))
    ));
    std::fs::remove_dir_all(signer_dir(&dir)).unwrap();
    let refused = opened(id, validator());
    assert!(
        matches!(refused, Err(SignerError::Corrupt(ref m)) if m.contains("directory is missing")),
        "{refused:?}"
    );
}

/// The node's signer signs with the validator key, pure Ed25519, only after
/// both copies are durable; with no proof verifier in this binary it changes
/// no lock and leaves no height, and those refusals write nothing.
#[test]
fn the_node_signer_signs_with_the_validator_key_and_verifies_no_proof() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("node");
    chain_at_genesis(&dir);
    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);
    initialize(&dir, db.clone(), id, pubkey(), Some(FLOOR)).unwrap();
    let mut s = open(&dir, db.clone(), id, validator()).unwrap();
    assert_eq!(ValidatorKey(validator()).key_id(), pubkey());

    let r = prevote(FLOOR, 0, A);
    let sig = s.sign(&r).unwrap();
    verify_signature(&r.payload, &sig);
    assert_eq!(Some(&files(&dir)[STATE_FILE]), mirror(&db).as_ref());

    let before = (files(&dir), mirror(&db));
    assert!(matches!(
        s.sign(&precommit(FLOOR, 0, A)),
        Err(SignerError::InvalidJustification(_))
    ));
    assert!(matches!(
        s.advance(&finality(FLOOR, &A)),
        Err(SignerError::InvalidFinalityProof(_))
    ));
    assert_eq!(
        (files(&dir), mirror(&db)),
        before,
        "the refusals wrote nothing"
    );
    assert_eq!(
        s.sign(&r).unwrap(),
        sig,
        "the identical request, the same bytes"
    );
}

/// Initialization takes the public key only; the private key is loaded when
/// a signer is opened, and it must be the initialized one. Another key is
/// refused before anything is locked, repaired or written, even when the
/// next open would repair (a leftover temp file, a mirror one persist
/// behind); the right key then opens, and the open makes those repairs.
#[test]
fn a_private_key_other_than_the_initialized_one_is_refused_before_any_write() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("node");
    chain_at_genesis(&dir);
    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);
    initialize(&dir, db.clone(), id, pubkey(), Some(FLOOR)).unwrap();
    let initialized = files(&dir)[STATE_FILE].clone();
    {
        let mut s = open(&dir, db.clone(), id, validator()).unwrap();
        s.sign(&prevote(FLOOR, 0, A)).unwrap();
    }
    db.put(cf::META, SIGNER_MIRROR_KEY, &initialized).unwrap();
    std::fs::write(signer_dir(&dir).join("signer.v1.tmp"), b"debris").unwrap();
    let before = (files(&dir), mirror(&db));

    let other = KeyPair::from_bytes([42u8; 32]);
    assert_eq!(
        open(&dir, db.clone(), id, other).map(|_| ()),
        Err(SignerError::KeyMismatch)
    );
    assert_eq!((files(&dir), mirror(&db)), before, "nothing was written");
    assert!(
        ownership(&dir).try_acquire().is_ok(),
        "nor is the lock left held"
    );

    let mut s = open(&dir, db.clone(), id, validator()).expect("the initialized key opens");
    assert!(!signer_dir(&dir).join("signer.v1.tmp").exists(), "repaired");
    assert_eq!(Some(&files(&dir)[STATE_FILE]), mirror(&db).as_ref());
    let r = prevote(FLOOR, 0, A);
    verify_signature(&r.payload, &s.sign(&r).unwrap());
}

// ── status ──────────────────────────────────────────────────────────────────

/// `status` reports what the next open finds, including its repairs, and
/// writes nothing: every file and the mirror are left as they were.
#[test]
fn status_reports_and_writes_nothing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("node");
    chain_at_genesis(&dir);
    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);
    let unchanged = |db: &Database, f: &dyn Fn() -> finality_signer::SignerStatus| {
        let before = (files(&dir), mirror(db));
        let s = f();
        assert_eq!((files(&dir), mirror(db)), before, "status wrote nothing");
        s
    };

    let s = unchanged(&db, &|| status(&dir, &db, id).unwrap());
    assert_eq!(s.verdict, StatusVerdict::NotInitialized);

    initialize(&dir, db.clone(), id, pubkey(), Some(FLOOR)).unwrap();
    {
        let mut s = open(&dir, db.clone(), id, validator()).unwrap();
        s.sign(&prevote(FLOOR, 0, A)).unwrap();
    }
    let s = unchanged(&db, &|| status(&dir, &db, id).unwrap());
    assert_eq!(s.verdict, StatusVerdict::Opens);
    let record = s.record.unwrap();
    assert_eq!(record.key_id, pubkey());
    assert_eq!(record.working_height(), Some(FLOOR));
    assert_eq!(
        record.last.unwrap().position,
        position(FLOOR, 0, Step::Prevote)
    );

    // A leftover temp file and a mirror one persist behind: the next open
    // repairs; status only says so.
    let state = files(&dir)[STATE_FILE].clone();
    std::fs::write(signer_dir(&dir).join("signer.v1.tmp"), b"debris").unwrap();
    {
        let mut s = open(&dir, db.clone(), id, validator()).unwrap();
        s.sign(&prevote(FLOOR, 1, A)).unwrap();
    }
    db.put(cf::META, SIGNER_MIRROR_KEY, &state).unwrap();
    std::fs::write(signer_dir(&dir).join("signer.v1.tmp"), b"debris").unwrap();
    let s = unchanged(&db, &|| status(&dir, &db, id).unwrap());
    assert_eq!(s.verdict, StatusVerdict::Opens);
    assert_eq!(
        s.classified,
        Some(sumchain_finality_foundations::signer_file::Classified::AdvancedMirror)
    );
    assert!(s.removes_temp);

    // Another chain's view of the same files: refused.
    let s = unchanged(&db, &|| {
        status(
            &dir,
            &db,
            SignerIdentity {
                chain_id: CHAIN_ID + 1,
                ..id
            },
        )
        .unwrap()
    });
    assert!(
        matches!(s.verdict, StatusVerdict::Refused(ref m) if m.contains("identity mismatch")),
        "{:?}",
        s.verdict
    );
}

// ── real processes ──────────────────────────────────────────────────────────

const CHILD_DIR_ENV: &str = "SUMCHAIN_SIGNER_CHILD_DIR";
const CHILD_AT_ENV: &str = "SUMCHAIN_SIGNER_CHILD_AT";
const CHILD_MARKER_ENV: &str = "SUMCHAIN_SIGNER_CHILD_MARKER";
const CHILD_SENT_ENV: &str = "SUMCHAIN_SIGNER_CHILD_SENT";

#[derive(Clone)]
enum Act {
    Sign(SignRequest),
    Advance(Vec<u8>),
}

/// Initialization (before this), then: a prevote; a precommit that locks
/// (P0 writes its proof); a prevote for another value justified past the
/// lock; a precommit that relocks (a new proof; the old one is left for G);
/// an advancement (G removes the old proof; the lock and its proof go); a
/// prevote and a locking precommit at the next height.
fn script() -> Vec<Act> {
    vec![
        Act::Sign(prevote(FLOOR, 0, A)),
        Act::Sign(precommit(FLOOR, 0, A)),
        Act::Sign(justified(prevote(FLOOR, 2, B), 1, &B)),
        Act::Sign(precommit(FLOOR, 2, B)),
        Act::Advance(finality(FLOOR, &B)),
        Act::Sign(prevote(FLOOR + 1, 0, C)),
        Act::Sign(precommit(FLOOR + 1, 0, C)),
    ]
}

/// Counts the steps of the store's writes; at step `at` it announces itself
/// and parks, for the parent to SIGKILL.
struct Barrier {
    at: Option<usize>,
    count: Cell<usize>,
    marker: PathBuf,
}

impl Barrier {
    fn point(&self) {
        let n = self.count.get();
        self.count.set(n + 1);
        if self.at == Some(n) {
            std::fs::write(&self.marker, n.to_string()).unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }
}

/// The real directory, with a barrier before every write, sync, rename and
/// removal.
struct BarrierDir(StdSignerDir, Rc<Barrier>);

impl SignerDir for BarrierDir {
    fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, IoError> {
        self.0.read(name)
    }
    fn write_new(&mut self, name: &str, bytes: &[u8]) -> Result<(), IoError> {
        self.1.point();
        self.0.write_new(name, bytes)
    }
    fn sync_file(&mut self, name: &str) -> Result<(), IoError> {
        self.1.point();
        self.0.sync_file(name)
    }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), IoError> {
        self.1.point();
        self.0.rename(from, to)
    }
    fn sync_dir(&mut self) -> Result<(), IoError> {
        self.1.point();
        self.0.sync_dir()
    }
    fn remove(&mut self, name: &str) -> Result<(), IoError> {
        self.1.point();
        self.0.remove(name)
    }
    fn list(&mut self) -> Result<Vec<String>, IoError> {
        self.0.list()
    }
}

/// The node-database mirror, with a barrier before its synced write.
struct BarrierMirror(DbMirror, Rc<Barrier>);

impl MirrorStore for BarrierMirror {
    fn read(&mut self) -> Result<Option<Vec<u8>>, IoError> {
        self.0.read()
    }
    fn write_synced(&mut self, bytes: &[u8]) -> Result<(), IoError> {
        self.1.point();
        self.0.write_synced(bytes)
    }
}

/// Initialize, open and run the script over `dir`, recording each released
/// signature in `sent` (one line: position, payload, signature) after a
/// barrier of its own. Returns the number of barrier steps.
fn run_script(dir: &Path, at: Option<usize>, marker: &Path, sent: &Path) -> usize {
    use std::io::Write as _;
    let barrier = Rc::new(Barrier {
        at,
        count: Cell::new(0),
        marker: marker.to_path_buf(),
    });
    let db = Arc::new(Database::open_default(dir).unwrap());
    let id = identity(&db);
    let store = || {
        FileSignerStore::new(
            BarrierDir(StdSignerDir::new(signer_dir(dir)), barrier.clone()),
            BarrierMirror(DbMirror::new(db.clone()), barrier.clone()),
            Blake3StateHasher,
            id.chain_id,
            id.genesis_block_hash,
        )
    };
    initialize_exclusive(
        &ownership(dir),
        &mut store(),
        pubkey(),
        floor_below_height(FLOOR),
    )
    .unwrap();
    let mut s = DurableSigner::open(
        &ownership(dir),
        store(),
        ValidatorKey(validator()),
        TestProofs,
        None,
    )
    .unwrap();
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sent)
        .unwrap();
    for act in script() {
        match act {
            Act::Sign(r) => {
                let sig = s.sign(&r).unwrap();
                // Durable, not yet sent.
                barrier.point();
                let p = r.position;
                writeln!(
                    log,
                    "{} {} {:?} {} {}",
                    p.height,
                    p.round,
                    p.step,
                    hex::encode(&r.payload),
                    hex::encode(&sig)
                )
                .unwrap();
            }
            Act::Advance(proof) => {
                s.advance(&proof).unwrap();
            }
        }
    }
    barrier.count.get()
}

fn read_sent(sent: &Path) -> Vec<(SignPosition, Vec<u8>, Vec<u8>)> {
    let text = std::fs::read_to_string(sent).unwrap_or_default();
    text.lines()
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let step = match f[2] {
                "Propose" => Step::Propose,
                "Prevote" => Step::Prevote,
                "Precommit" => Step::Precommit,
                other => panic!("step {other}"),
            };
            (
                position(f[0].parse().unwrap(), f[1].parse().unwrap(), step),
                hex::decode(f[3]).unwrap(),
                hex::decode(f[4]).unwrap(),
            )
        })
        .collect()
}

/// A fresh node directory at genesis with an empty signer directory.
fn fresh(tmp: &Path) -> PathBuf {
    let dir = tmp.join("node");
    chain_at_genesis(&dir);
    std::fs::create_dir(signer_dir(&dir)).unwrap();
    dir
}

fn spawn_child(test: &str, envs: &[(&str, &Path)], marker: &Path) -> std::process::Child {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", test, "--nocapture", "--test-threads", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn the child");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            panic!(
                "the child exited ({status}) before its barrier:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "the child never reached its barrier"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child
}

/// SIGKILL at every step the store takes, through initialization, three
/// signatures, a lock, a relock, an advancement and the next height, then a
/// restart on the same directory and database. The restarted signer opens
/// (or finds nothing initialized, when nothing was released), and asked for
/// a different message and then the script's own at every position, it never
/// signs a second message at a position where one was signed before or
/// after the crash.
#[cfg(unix)]
#[test]
fn sigkill_at_every_persist_step_never_signs_two_messages_at_one_position() {
    let dry = tempfile::TempDir::new().unwrap();
    let steps = run_script(
        &fresh(dry.path()),
        None,
        &dry.path().join("unused"),
        &dry.path().join("sent"),
    );
    assert!(
        steps > 40,
        "{steps} steps: the script exercises P0, P1, P2 and G"
    );

    for at in 0..steps {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = fresh(tmp.path());
        let marker = tmp.path().join("at-barrier");
        let sent_path = tmp.path().join("sent");
        let at_file = tmp.path().join("at");
        std::fs::write(&at_file, at.to_string()).unwrap();
        let mut child = spawn_child(
            "node::signer_wiring_tests::crash_child",
            &[
                (CHILD_DIR_ENV, &dir),
                (CHILD_AT_ENV, &at_file),
                (CHILD_MARKER_ENV, &marker),
                (CHILD_SENT_ENV, &sent_path),
            ],
            &marker,
        );
        child.kill().expect("SIGKILL the child");
        assert!(
            !child.wait().unwrap().success(),
            "step {at}: killed, not exited"
        );

        let sent = read_sent(&sent_path);
        let db = Arc::new(Database::open_default(&dir).unwrap());
        let id = identity(&db);
        let reopen = || {
            DurableSigner::open(
                &ownership(&dir),
                store(&dir, db.clone(), id),
                ValidatorKey(validator()),
                TestProofs,
                None,
            )
        };
        let mut s = match reopen() {
            Ok(s) => s,
            Err(SignerError::NotInitialized) => {
                assert!(sent.is_empty(), "step {at}: released, then uninitialized");
                initialize(&dir, db.clone(), id, pubkey(), Some(FLOOR)).unwrap();
                reopen().unwrap()
            }
            Err(e) => panic!("step {at}: the state does not open after the crash: {e}"),
        };

        let mut signed: BTreeMap<SignPosition, BTreeSet<Vec<u8>>> = BTreeMap::new();
        for (p, payload, sig) in &sent {
            verify_signature(payload, sig);
            signed.entry(*p).or_default().insert(payload.clone());
        }
        for act in script() {
            match act {
                Act::Sign(r) => {
                    let mut other = r.clone();
                    other.payload = [b"other:".as_slice(), &r.payload].concat();
                    for req in [other, r] {
                        if let Ok(sig) = s.sign(&req) {
                            verify_signature(&req.payload, &sig);
                            signed.entry(req.position).or_default().insert(req.payload);
                        }
                    }
                }
                Act::Advance(proof) => {
                    let _ = s.advance(&proof);
                }
            }
        }
        for (p, payloads) in &signed {
            assert_eq!(
                payloads.len(),
                1,
                "step {at}: two different messages signed at {p:?}"
            );
        }
        drop(s);
        assert_eq!(
            Some(&files(&dir)[STATE_FILE]),
            mirror(&db).as_ref(),
            "step {at}: both copies agree after the restart"
        );
    }
}

/// The child half: inert in an ordinary run.
#[test]
fn crash_child() {
    let Ok(dir) = std::env::var(CHILD_DIR_ENV) else {
        return;
    };
    let path = |k: &str| PathBuf::from(std::env::var(k).unwrap());
    let at: usize = std::fs::read_to_string(path(CHILD_AT_ENV))
        .unwrap()
        .parse()
        .unwrap();
    run_script(
        Path::new(&dir),
        Some(at),
        &path(CHILD_MARKER_ENV),
        &path(CHILD_SENT_ENV),
    );
    panic!("the child finished without reaching step {at}");
}

/// A real second process: while one holds the node's signer, another cannot
/// take the signer directory or the node database, and `status` still reads
/// the state; once the holder is SIGKILLed, the signer opens and returns the
/// released signature for the same request, and refuses another message at
/// that position.
#[cfg(unix)]
#[test]
fn a_second_process_is_refused_while_one_holds_the_signer() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("node");
    chain_at_genesis(&dir);
    {
        let db = Arc::new(Database::open_default(&dir).unwrap());
        let id = identity(&db);
        initialize(&dir, db, id, pubkey(), Some(FLOOR)).unwrap();
    }
    let marker = tmp.path().join("released");
    let mut child = spawn_child(
        "node::signer_wiring_tests::holder_child",
        &[(CHILD_DIR_ENV, &dir), (CHILD_MARKER_ENV, &marker)],
        &marker,
    );
    let released = std::fs::read(&marker).unwrap();

    assert!(
        ownership(&dir).try_acquire().is_err(),
        "the directory is held"
    );
    assert!(
        Database::open_default(&dir).is_err(),
        "and so is the node database"
    );
    {
        let db = Database::open_read_only(&dir).unwrap();
        let s = status(&dir, &db, identity(&db)).unwrap();
        assert_eq!(s.verdict, StatusVerdict::Opens);
        assert_eq!(
            s.record.unwrap().last.unwrap().position,
            position(FLOOR, 0, Step::Prevote)
        );
    }

    child.kill().expect("SIGKILL the child");
    assert!(!child.wait().unwrap().success(), "killed, not exited");

    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);
    let mut s = open(&dir, db, id, validator()).expect("free once the holder is gone");
    let r = prevote(FLOOR, 0, A);
    assert_eq!(s.sign(&r).unwrap(), released);
    let mut other = r.clone();
    other.payload = b"another message".to_vec();
    assert_eq!(
        s.sign(&other).unwrap_err(),
        SignerError::Equivocation(r.position)
    );
}

/// The holder half: opens the node's signer, signs one prevote, announces
/// the released signature and holds the signer until killed. Inert in an
/// ordinary run.
#[test]
fn holder_child() {
    let Ok(dir) = std::env::var(CHILD_DIR_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let marker = PathBuf::from(std::env::var(CHILD_MARKER_ENV).unwrap());
    let db = Arc::new(Database::open_default(&dir).unwrap());
    let id = identity(&db);
    let mut s = open(&dir, db, id, validator()).unwrap();
    let sig = s.sign(&prevote(FLOOR, 0, A)).unwrap();
    let tmp = marker.with_extension("tmp");
    std::fs::write(&tmp, &sig).unwrap();
    std::fs::rename(&tmp, &marker).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

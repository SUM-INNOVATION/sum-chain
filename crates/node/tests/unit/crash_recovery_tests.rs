//! Chain-switch recovery after a REAL process crash (#269).
//!
//! The parent test prepares a node's data directory: a canonical chain, and a
//! longer replacement branch whose interior is archived. It then re-runs THIS
//! test binary as a child process, restricted to [`crash_child`], which boots
//! the node through the production constructor (`Node::with_rpc_config` +
//! `init_chain`) and imports the replacement's tip through the production
//! import path. A crash barrier compiled into the consensus engine (the
//! `failpoints` feature, enabled only for this crate's tests) stops the child at
//! a chosen point and announces it; the parent then kills the child with
//! SIGKILL — no unwinding, no destructors, no flush.
//!
//! The parent restarts the node through the same production path and checks:
//!
//! * the database is EXACTLY the complete old chain or EXACTLY the complete new
//!   chain, across every column family (archive rows of blocks the node merely
//!   saw excepted, and checked exactly);
//! * the head, the height index, the parent links and the journals describe one
//!   unbroken chain — no shortened chain, no index above the head;
//! * the in-memory head and accumulator match the database;
//! * the next block imports on top of the recovered head.
//!
//! Durability: the database uses RocksDB's write-ahead log with default write
//! options (`sync = false`). A killed PROCESS loses nothing the WAL holds,
//! because the WAL is in the kernel's page cache; that is what this proves. It
//! proves nothing about POWER LOSS, which can drop un-synced WAL bytes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sumchain_consensus::branch_switch::failpoints::{Failpoint, BARRIER_AT_ENV, BARRIER_FILE_ENV};
use sumchain_consensus::{ConsensusEngine, ConsensusQuery, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Block, BlockHeader, Hash, SignedTransaction, Transaction};
use sumchain_state::{BlockExecutor, Mempool, MempoolConfig, StateManager};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::{cf, BlockStore, Database};

use super::Node;

const CHAIN_ID: u64 = 1;
const CHILD_DIR_ENV: &str = "SUMCHAIN_CRASH_CHILD_DIR";
const CHILD_TIP_ENV: &str = "SUMCHAIN_CRASH_CHILD_TIP";

fn key(i: u8) -> KeyPair {
    KeyPair::from_bytes([i; 32])
}

fn pk(k: &KeyPair) -> [u8; 32] {
    *k.public_key().as_bytes()
}

fn genesis() -> Genesis {
    let params = ChainParams {
        application_journal_enabled_from_height: Some(1),
        finality_depth: 1_000_000,
        ..ChainParams::with_contracts_enabled()
    };
    let mut alloc = HashMap::new();
    for i in [1u8, 2, 0x61, 0x62, 0x63] {
        alloc.insert(key(i).address().to_base58(), 1_000_000_000u128);
    }
    Genesis::new(
        CHAIN_ID,
        0,
        vec![
            key(1).public_key().to_base58(),
            key(2).public_key().to_base58(),
        ],
        alloc,
        params,
    )
}

fn transfer(from: &KeyPair, to: &KeyPair, amount: u128, nonce: u64) -> SignedTransaction {
    let tx = Transaction::new(CHAIN_ID, from.address(), to.address(), amount, 10, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), pk(from))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Boot through the production constructor and chain load.
fn boot(dir: &Path) -> Node {
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let node = Node::with_rpc_config(
        dir.to_path_buf(),
        genesis(),
        None,
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    )
    .expect("the node boots");
    node.init_chain().expect("the chain loads");
    node
}

/// Produces blocks off-node with real execution.
struct Builder {
    _dir: tempfile::TempDir,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    validators: Vec<[u8; 32]>,
    head: Block,
    salt: u64,
}

impl Builder {
    fn new(salt: u64) -> Self {
        let g = genesis();
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
        let engine = PoAEngine::new(
            db.clone(),
            state.clone(),
            Arc::new(Mempool::new(MempoolConfig::default())),
            &g,
            None,
        )
        .unwrap();
        let head = engine.init_genesis(&g).unwrap();
        drop(engine);
        Self {
            _dir: dir,
            executor: BlockExecutor::new(state.clone(), db, g.params.clone()),
            state,
            validators: g.validator_pubkeys().unwrap(),
            head,
            salt,
        }
    }

    fn follow(&mut self, b: &Block) {
        let exec = self
            .executor
            .execute_block(b, self.state.state_root(), &self.validators)
            .unwrap();
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_imported(b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
    }

    fn produce(&mut self, txs: Vec<SignedTransaction>) -> Block {
        let height = self.head.height() + 1;
        let want = self.validators[(height % 2) as usize];
        let signer = [key(1), key(2)]
            .into_iter()
            .find(|k| pk(k) == want)
            .unwrap();
        let mut b = Block::new(
            BlockHeader::new(
                self.head.hash(),
                height,
                self.head.header.timestamp + 10 + self.salt,
                Hash::ZERO,
                Hash::ZERO,
                want,
            ),
            txs,
        );
        b.header.tx_root = b.compute_tx_root();
        let exec = self
            .executor
            .execute_block(&b, self.state.state_root(), &self.validators)
            .unwrap();
        b.header.state_root = exec.computed_root();
        let s = sign(b.header.signing_hash().as_bytes(), signer.private_key());
        b.header.set_signature(*s.as_bytes());
        let (executed, _, _) = exec.into_parts();
        let accepted = executed.accept_produced(&b).unwrap();
        let acc = accepted.accumulator();
        accepted.publish().unwrap();
        self.state.set_state_root(acc);
        self.head = b.clone();
        b
    }
}

struct Chains {
    prefix: Vec<Block>,
    canonical: Vec<Block>,
    branch: Vec<Block>,
    canonical_next: Block,
    branch_next: Block,
}

/// Two shared blocks, then three canonical blocks (alice pays bob) against four
/// replacement blocks (alice pays carol), plus the next block of each.
fn chains() -> Chains {
    let (alice, bob, carol) = (key(0x61), key(0x62), key(0x63));
    let mut a = Builder::new(0);
    let mut b = Builder::new(1);
    let prefix: Vec<Block> = (0..2)
        .map(|i| {
            let blk = a.produce(vec![transfer(&alice, &bob, 1, i)]);
            b.follow(&blk);
            blk
        })
        .collect();
    let canonical: Vec<Block> = (0..3)
        .map(|i| a.produce(vec![transfer(&alice, &bob, 100 + i as u128, 2 + i)]))
        .collect();
    let branch: Vec<Block> = (0..4)
        .map(|i| b.produce(vec![transfer(&alice, &carol, 500 + i as u128, 2 + i)]))
        .collect();
    let canonical_next = a.produce(vec![transfer(&alice, &bob, 9, 5)]);
    let branch_next = b.produce(vec![transfer(&alice, &carol, 9, 6)]);
    Chains {
        prefix,
        canonical,
        branch,
        canonical_next,
        branch_next,
    }
}

type Rows = BTreeMap<(String, Vec<u8>), Vec<u8>>;

fn rows(db: &Database) -> Rows {
    let mut out = BTreeMap::new();
    for cf_name in ALL_CFS {
        for entry in db.iter_checked_from(cf_name, None).unwrap() {
            let (k, v) = entry.unwrap();
            out.insert((cf_name.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

fn archive_keys(blocks: &[Block]) -> BTreeSet<(String, Vec<u8>)> {
    let mut out = BTreeSet::new();
    for b in blocks {
        out.insert((cf::BLOCKS.to_string(), b.hash().as_bytes().to_vec()));
        for tx in &b.transactions {
            out.insert((cf::TRANSACTIONS.to_string(), tx.hash().as_bytes().to_vec()));
        }
    }
    out
}

fn without(mut r: Rows, keys: &BTreeSet<(String, Vec<u8>)>) -> Rows {
    for k in keys {
        r.remove(k);
    }
    r
}

fn archive(db: &Database, b: &Block) {
    db.put(cf::BLOCKS, b.hash().as_bytes(), &b.to_bytes())
        .unwrap();
    for tx in &b.transactions {
        db.put(cf::TRANSACTIONS, tx.hash().as_bytes(), &tx.to_bytes())
            .unwrap();
    }
}

/// The head, height index, parent links and journals describe ONE unbroken
/// chain from genesis to the head, with nothing indexed above it.
fn assert_unbroken_chain(db: &Database, expected: &[Block]) {
    let store = BlockStore::new(db);
    let head = store.get_latest().unwrap().unwrap();
    assert_eq!(
        &head,
        expected.last().unwrap(),
        "the head is the expected tip"
    );
    let mut child = head.clone();
    for blk in expected.iter().rev().skip(1) {
        assert_eq!(
            child.header.parent_hash,
            blk.hash(),
            "parent link at {}",
            child.height()
        );
        child = blk.clone();
    }
    for blk in expected {
        assert_eq!(
            store.get_by_height(blk.height()).unwrap().map(|b| b.hash()),
            Some(blk.hash()),
            "height index at {}",
            blk.height()
        );
        let jkey = sumchain_storage::schema::journal_key(blk.height(), &blk.hash());
        assert!(
            db.get(cf::APPLICATION_JOURNAL, &jkey).unwrap().is_some(),
            "journal for canonical block {}",
            blk.height()
        );
    }
    let indexed_heights: Vec<u64> = db
        .iter_checked_from(cf::BLOCK_HEIGHT, None)
        .unwrap()
        .map(|e| {
            let (k, _) = e.unwrap();
            let mut h = [0u8; 8];
            h.copy_from_slice(&k[..8]);
            u64::from_be_bytes(h)
        })
        .collect();
    assert_eq!(
        indexed_heights.iter().max().copied(),
        Some(head.height()),
        "nothing is indexed above the head"
    );
    let journals = db
        .iter_checked_from(cf::APPLICATION_JOURNAL, None)
        .unwrap()
        .count();
    assert_eq!(
        journals,
        expected.len(),
        "a journal for every canonical block and no other"
    );
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    OldChain,
    NewChain,
}

/// Prepare, crash at `fp`, restart, verify.
fn crash_and_recover(fp: Failpoint, expect: Expect) {
    let c = chains();
    let rt = runtime();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("node");

    // ── prepare: canonical chain, archived replacement interior ────────────
    let before = {
        let node = boot(&dir);
        for b in c.prefix.iter().chain(&c.canonical) {
            rt.block_on(node.consensus.import_block(b.clone())).unwrap();
        }
        for b in &c.branch[..c.branch.len() - 1] {
            archive(&node.db, b);
        }
        rows(&node.db)
    };
    let tip_file = tmp.path().join("tip.bin");
    std::fs::write(&tip_file, c.branch.last().unwrap().to_bytes()).unwrap();
    let marker = tmp.path().join("at-barrier");

    // ── the child: production boot, production import, parked at `fp` ──────
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "node::crash_recovery_tests::crash_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_DIR_ENV, &dir)
        .env(CHILD_TIP_ENV, &tip_file)
        .env(BARRIER_AT_ENV, fp.name())
        .env(BARRIER_FILE_ENV, &marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child");
    let deadline = Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            panic!(
                "the child exited ({status}) before reaching barrier {}:\n{}\n{}",
                fp.name(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(
            Instant::now() < deadline,
            "the child never reached {}",
            fp.name()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill().expect("SIGKILL the child"); // SIGKILL on unix
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "the child must have been killed, not exited"
    );

    // ── restart through the production path, and verify ───────────────────
    let node = boot(&dir);
    let tip = c.branch.last().unwrap();
    match expect {
        Expect::OldChain => {
            let expected: Vec<Block> = c.prefix.iter().chain(&c.canonical).cloned().collect();
            assert_unbroken_chain(&node.db, &expected);
            // Every row as it was, except the tip's own archive row, which the
            // child wrote before validating.
            let tip_archive = archive_keys(std::slice::from_ref(tip));
            assert_eq!(
                without(rows(&node.db), &tip_archive),
                without(before, &tip_archive)
            );
        }
        Expect::NewChain => {
            let expected: Vec<Block> = c.prefix.iter().chain(&c.branch).cloned().collect();
            assert_unbroken_chain(&node.db, &expected);
            let reference_dir = tmp.path().join("winner");
            let winner = boot(&reference_dir);
            for b in &expected {
                rt.block_on(winner.consensus.import_block(b.clone()))
                    .unwrap();
            }
            let abandoned = archive_keys(&c.canonical);
            assert_eq!(
                without(rows(&node.db), &abandoned),
                rows(&winner.db),
                "the recovered database is exactly the winner's"
            );
        }
    }
    let head = BlockStore::new(&node.db).get_latest().unwrap().unwrap();
    assert_eq!(
        node.consensus.best_block_hash(),
        head.hash(),
        "memory matches the database"
    );
    assert_eq!(node.state.state_root(), head.header.state_root);

    // The next block imports on top of the recovered head.
    let next = match expect {
        Expect::OldChain => &c.canonical_next,
        Expect::NewChain => &c.branch_next,
    };
    rt.block_on(node.consensus.import_block(next.clone()))
        .expect("the next block extends the recovered chain");
    assert_eq!(node.consensus.best_block_hash(), next.hash());
}

/// The child half. Inert in an ordinary test run: it does anything only when
/// the parent started this binary with the crash environment.
#[test]
fn crash_child() {
    let Ok(dir) = std::env::var(CHILD_DIR_ENV) else {
        return;
    };
    let tip_file = std::env::var(CHILD_TIP_ENV).expect("tip file");
    let tip = Block::from_bytes(&std::fs::read(tip_file).unwrap()).unwrap();
    let node = boot(Path::new(&PathBuf::from(dir)));
    let result = runtime().block_on(node.consensus.import_block(tip));
    // Reaching here means the barrier was not hit; the parent reports it.
    panic!("the child finished the import without reaching its barrier: {result:?}");
}

#[test]
fn a_crash_after_validation_before_adoption_recovers_the_old_chain() {
    crash_and_recover(Failpoint::AfterValidation, Expect::OldChain);
}

#[test]
fn a_crash_immediately_before_the_batch_write_recovers_the_old_chain() {
    crash_and_recover(Failpoint::CrashBeforeCommit, Expect::OldChain);
}

#[test]
fn a_crash_immediately_after_the_commit_recovers_the_new_chain() {
    crash_and_recover(Failpoint::CrashAfterCommit, Expect::NewChain);
}

#[test]
fn a_crash_during_post_commit_reconciliation_recovers_the_new_chain() {
    crash_and_recover(Failpoint::MidReconcile, Expect::NewChain);
}

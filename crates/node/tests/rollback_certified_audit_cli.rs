//! `sumchain rollback` through the real binary runs the certified-finality
//! start-up audit (#341, #350) before it plans anything.
//!
//! The rollback is checked against the certified block, and that check trusts
//! the stored pointer only once `certified_guard::audit_at_start` has passed.
//! This binary verifies no certificate, so a database holding a certified
//! record is refused and left as it was; one holding none rolls back exactly as
//! before. The certified records here are synthetic.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Block, SignedTransaction, Transaction};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::certified_meta::{certificate_key, FINALIZED_POINTER_KEY};
use sumchain_storage::db::ALL_CFS;
use sumchain_storage::{cf, BlockStore, Database};

const CHAIN_ID: u64 = 1;

fn validator() -> KeyPair {
    KeyPair::from_bytes([71u8; 32])
}

fn alice() -> KeyPair {
    KeyPair::from_bytes([72u8; 32])
}

fn transfer(nonce: u64) -> SignedTransaction {
    let from = alice();
    let to = KeyPair::from_bytes([73u8; 32]).address();
    let tx = Transaction::new(CHAIN_ID, from.address(), to, 1_000, 1_000_000, nonce);
    let sig = sign(tx.signing_hash().as_bytes(), from.private_key());
    SignedTransaction::new(tx, *sig.as_bytes(), *from.public_key().as_bytes())
}

/// A data directory holding genesis and three produced blocks.
async fn chain(dir: &Path) -> Vec<Block> {
    let g = Genesis::new(
        CHAIN_ID,
        1_734_624_000_000,
        vec![validator().public_key().to_base58()],
        HashMap::from([(alice().address().to_base58(), 10_000_000_000u128)]),
        ChainParams::default(),
    );
    let db = Arc::new(Database::open_default(dir).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let engine = PoAEngine::new(
        db.clone(),
        state,
        Arc::new(Mempool::new(MempoolConfig::default())),
        &g,
        Some(validator()),
    )
    .unwrap();
    let mut blocks = vec![engine.init_genesis(&g).unwrap()];
    for n in 0..3 {
        blocks.push(engine.propose_block(vec![transfer(n)]).await.unwrap());
    }
    assert_eq!(blocks.last().unwrap().height(), 3);
    blocks
}

type Rows = BTreeMap<(String, Vec<u8>), Vec<u8>>;

fn rows(dir: &Path) -> Rows {
    let db = Database::open_default(dir).unwrap();
    let mut out = BTreeMap::new();
    for cf_name in ALL_CFS {
        for entry in db.iter_checked_from(cf_name, None).unwrap() {
            let (k, v) = entry.unwrap();
            out.insert((cf_name.to_string(), k.into_vec()), v.into_vec());
        }
    }
    out
}

/// `sumchain rollback --to-height 1 --yes` on `dir`, to completion.
fn rollback(dir: &Path) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args([
            "rollback",
            "--data-dir",
            dir.to_str().unwrap(),
            "--to-height",
            "1",
            "--yes",
        ])
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("`sumchain rollback` did not finish");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[tokio::test]
async fn a_rollback_on_a_database_with_no_certified_record_runs_as_before() {
    let dir = tempfile::TempDir::new().unwrap();
    let blocks = chain(dir.path()).await;
    let (ok, text) = rollback(dir.path());
    assert!(ok, "the rollback must run:\n{text}");
    let db = Database::open_default(dir.path()).unwrap();
    assert_eq!(
        BlockStore::new(&db).get_latest_hash().unwrap(),
        Some(blocks[1].hash())
    );
}

#[tokio::test]
async fn a_rollback_on_a_database_with_a_certified_record_is_refused_by_the_audit() {
    let dir = tempfile::TempDir::new().unwrap();
    let blocks = chain(dir.path()).await;
    let head = blocks.last().unwrap();
    {
        let db = Database::open_default(dir.path()).unwrap();
        let mut pointer = head.height().to_le_bytes().to_vec();
        pointer.extend_from_slice(head.hash().as_bytes());
        db.put(cf::META, FINALIZED_POINTER_KEY, &pointer).unwrap();
        db.put(
            cf::META,
            &certificate_key(head.height(), &head.hash()),
            b"synthetic",
        )
        .unwrap();
    }
    let before = rows(dir.path());
    let (ok, text) = rollback(dir.path());
    assert!(!ok, "the rollback must be refused:\n{text}");
    assert!(
        text.contains("refusing to roll back")
            && text.contains("did not pass the start-up audit")
            && text.contains("no finality-certificate verifier"),
        "the refusal must come from the start-up audit:\n{text}"
    );
    assert_eq!(rows(dir.path()), before, "a refused rollback wrote");
}

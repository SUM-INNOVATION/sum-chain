//! `sumchain signer init` and `sumchain signer status` (#350, B6), through the
//! real binary, on a stopped node's data directory.
//!
//! `init` takes the validator's public key only, and creates the signer
//! state once: `<data-dir>/finality/signer.v1` and its mirror in the node
//! database, byte-identical. It refuses a second time, another chain's
//! genesis file, a database in use, a missing directory, a malformed key and
//! a secret key file, creating nothing. `status` reports what the next open would find, exits 0
//! (opens), 2 (refused) or 3 (not initialized), and writes nothing: every
//! test digests the whole data directory (names, lengths, modification times
//! and contents) around it. This binary produces no finality votes.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use sumchain_consensus::PoAEngine;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Hash;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::certified_meta::SIGNER_MIRROR_KEY;
use sumchain_storage::{cf, Database};

fn validator() -> KeyPair {
    KeyPair::from_bytes([43u8; 32])
}

fn genesis_at(genesis_time: u64) -> Genesis {
    Genesis::new(
        11,
        genesis_time,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams::default(),
    )
}

fn genesis() -> Genesis {
    genesis_at(1_734_624_000_000)
}

/// A stopped node: `<tmp>/data` holding genesis, and `<tmp>/genesis.json`.
struct Stopped {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    genesis: PathBuf,
}

/// The validator's public key as `signer init` takes it.
fn pubkey() -> String {
    validator().public_key().to_base58()
}

fn stopped() -> Stopped {
    let tmp = tempfile::TempDir::new().unwrap();
    let data = tmp.path().join("data");
    {
        let g = genesis();
        let db = Arc::new(Database::open_default(&data).unwrap());
        PoAEngine::new(
            db.clone(),
            Arc::new(StateManager::new(db.clone(), g.chain_id)),
            Arc::new(Mempool::new(MempoolConfig::default())),
            &g,
            None,
        )
        .unwrap()
        .init_genesis(&g)
        .unwrap();
    }
    let genesis_file = tmp.path().join("genesis.json");
    genesis().to_file(&genesis_file).unwrap();
    Stopped {
        data,
        genesis: genesis_file,
        _tmp: tmp,
    }
}

fn signer(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .arg("signer")
        .args(args)
        .output()
        .expect("running the node binary")
}

fn init(n: &Stopped, genesis: &Path, extra: &[&str]) -> Output {
    let key = pubkey();
    let mut args = vec![
        "init",
        "--data-dir",
        n.data.to_str().unwrap(),
        "--genesis",
        genesis.to_str().unwrap(),
        "--validator-pubkey",
        &key,
    ];
    args.extend_from_slice(extra);
    signer(&args)
}

fn status(n: &Stopped) -> Output {
    signer(&[
        "status",
        "--data-dir",
        n.data.to_str().unwrap(),
        "--genesis",
        n.genesis.to_str().unwrap(),
    ])
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Every entry under `dir`: length, modification time and the hash of its
/// contents (directories: zero and none).
type Tree = BTreeMap<String, (u64, std::time::SystemTime, Option<Hash>)>;

fn tree(dir: &Path) -> Tree {
    fn walk(root: &Path, at: &Path, out: &mut Tree) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let meta = std::fs::metadata(&path).unwrap();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if meta.is_dir() {
                out.insert(rel, (0, meta.modified().unwrap(), None));
                walk(root, &path, out);
            } else {
                let contents = std::fs::read(&path).unwrap();
                out.insert(
                    rel,
                    (
                        meta.len(),
                        meta.modified().unwrap(),
                        Some(Hash::hash(&contents)),
                    ),
                );
            }
        }
    }
    let mut out = Tree::new();
    walk(dir, dir, &mut out);
    out
}

/// The signer directory's entries of a tree.
fn signer_files_of(t: &Tree) -> Tree {
    t.iter()
        .filter(|(k, _)| k.starts_with("finality"))
        .map(|(k, v)| (k.clone(), *v))
        .collect()
}

fn signer_files(data: &Path) -> Tree {
    signer_files_of(&tree(data))
}

fn mirror(data: &Path) -> Option<Vec<u8>> {
    Database::open_read_only(data)
        .unwrap()
        .get(cf::META, SIGNER_MIRROR_KEY)
        .unwrap()
}

#[test]
fn init_once_then_status_reads_it_and_writes_nothing() {
    let n = stopped();

    let before = tree(&n.data);
    let out = status(&n);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert!(
        text(&out).contains("Result: NOT_INITIALIZED"),
        "{}",
        text(&out)
    );
    assert_eq!(tree(&n.data), before, "status wrote nothing");

    let out = init(&n, &n.genesis, &["--floor-height", "5"]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("Result: INITIALIZED"), "{t}");
    assert!(t.contains("a genesis validator"), "{t}");
    assert!(t.contains("nothing below height 5 is signed"), "{t}");
    let state = std::fs::read(n.data.join("finality").join("signer.v1")).unwrap();
    assert_eq!(state.len(), 413);
    assert_eq!(
        mirror(&n.data),
        Some(state.clone()),
        "the mirror is the same bytes"
    );

    let before = tree(&n.data);
    let out = status(&n);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("Result: OPENS"), "{t}");
    assert!(t.contains("Working height:   5"), "{t}");
    assert!(t.contains("Last signature:   none"), "{t}");
    assert!(t.contains(&validator().public_key().to_base58()), "{t}");
    assert!(t.contains("produces no finality votes"), "{t}");
    assert_eq!(tree(&n.data), before, "status wrote nothing");

    // A refused init opens the database read-write, which rewrites RocksDB's
    // own files; the signer's files and the mirror are left as they were.
    let out = init(&n, &n.genesis, &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("already exists"), "{}", text(&out));
    assert_eq!(signer_files(&n.data), signer_files_of(&before));
    assert_eq!(mirror(&n.data), Some(state));
}

#[test]
fn status_refuses_a_damaged_state_and_writes_nothing() {
    let n = stopped();
    assert!(init(&n, &n.genesis, &[]).status.success());
    let path = n.data.join("finality").join("signer.v1");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[30] ^= 1;
    std::fs::write(&path, &bytes).unwrap();

    let before = tree(&n.data);
    let out = status(&n);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("Result: REFUSED"), "{t}");
    assert!(t.contains("checksum"), "{t}");
    assert_eq!(tree(&n.data), before, "status wrote nothing");
}

#[test]
fn init_refuses_another_chain_a_database_in_use_and_a_missing_directory() {
    let n = stopped();

    let other = n.genesis.with_file_name("other.json");
    genesis_at(1_734_624_000_001).to_file(&other).unwrap();
    let out = init(&n, &other, &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("different chains"), "{}", text(&out));
    assert!(!n.data.join("finality").exists());

    {
        let _running = Database::open_default(&n.data).unwrap();
        let out = init(&n, &n.genesis, &[]);
        assert!(!out.status.success());
        assert!(text(&out).contains("stop the node first"), "{}", text(&out));
        assert!(!n.data.join("finality").exists());
    }
    assert_eq!(mirror(&n.data), None);
    assert!(signer_files(&n.data).is_empty());

    let missing = n.data.with_file_name("absent");
    let out = signer(&[
        "init",
        "--data-dir",
        missing.to_str().unwrap(),
        "--genesis",
        n.genesis.to_str().unwrap(),
        "--validator-pubkey",
        &pubkey(),
    ]);
    assert!(!out.status.success());
    assert!(text(&out).contains("no data directory"), "{}", text(&out));
    assert!(!missing.exists(), "nothing was created");

    // A data directory without a node database: none is created.
    let empty = n.data.with_file_name("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = signer(&[
        "init",
        "--data-dir",
        empty.to_str().unwrap(),
        "--genesis",
        n.genesis.to_str().unwrap(),
        "--validator-pubkey",
        &pubkey(),
    ]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("cannot open the node database"),
        "{}",
        text(&out)
    );
    assert_eq!(
        std::fs::read_dir(&empty).unwrap().count(),
        0,
        "nothing created"
    );
}

/// Only the public key: a malformed one is refused, and so is a secret key
/// file (the command has no such argument). Nothing is created either way.
#[test]
fn init_takes_the_public_key_only() {
    let n = stopped();
    let secret = n.data.with_file_name("validator.key");
    std::fs::write(
        &secret,
        serde_json::to_string(validator().private_key().as_bytes()).unwrap(),
    )
    .unwrap();
    for args in [
        vec!["--validator-pubkey", "not-a-key"],
        vec!["--validator-pubkey", "3yZe7d"],
        vec!["--validator-key", secret.to_str().unwrap()],
    ] {
        let mut all = vec![
            "init",
            "--data-dir",
            n.data.to_str().unwrap(),
            "--genesis",
            n.genesis.to_str().unwrap(),
        ];
        all.extend_from_slice(&args);
        let out = signer(&all);
        assert!(!out.status.success(), "{args:?}: {}", text(&out));
        assert!(signer_files(&n.data).is_empty(), "{args:?}");
        assert_eq!(mirror(&n.data), None, "{args:?}");
    }

    // Another key than the genesis validator's is initialized, and reported.
    let other = KeyPair::from_bytes([44u8; 32]).public_key().to_base58();
    let out = signer(&[
        "init",
        "--data-dir",
        n.data.to_str().unwrap(),
        "--genesis",
        n.genesis.to_str().unwrap(),
        "--validator-pubkey",
        &other,
    ]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("NOT a genesis validator"),
        "{}",
        text(&out)
    );
}

//! #268 through the real binary: a genesis with a field the loader does not
//! define is refused when it is parsed, which is before a data directory is
//! created, before the database is opened and before the consensus-
//! configuration record is read or written. An existing database is left
//! byte-for-byte as it was.
//!
//! `sumchain run` parses the genesis (`Genesis::from_file`) before it calls
//! `Node::with_rpc_config`, whose first disk access is creating the data
//! directory; `init` and `acknowledge-consensus-config` also parse it before
//! opening the database.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

fn valid_genesis() -> Value {
    let validator = KeyPair::from_bytes([61u8; 32]);
    let account = KeyPair::from_bytes([62u8; 32]).address();
    let g = Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([(account.to_base58(), 5u128)]),
        ChainParams::default(),
    );
    serde_json::from_str(&g.to_json().unwrap()).unwrap()
}

/// The valid genesis with `field` added to `params` (or to the document when
/// `in_params` is false).
fn with_unknown(field: &str, in_params: bool) -> Value {
    let mut v = valid_genesis();
    let target = if in_params { &mut v["params"] } else { &mut v };
    target
        .as_object_mut()
        .unwrap()
        .insert(field.to_string(), json!(100));
    v
}

/// A loopback-only node configuration, so that a `run` that is wrongly not
/// refused binds nothing outside this host and finds no peers.
fn loopback_config(dir: &Path) -> PathBuf {
    let file = dir.join("node.toml");
    std::fs::write(
        &file,
        "[consensus]\nengine = \"poa\"\n\
         [network]\nlisten_addr = \"/ip4/127.0.0.1/tcp/0\"\nmdns = false\n\
         [rpc]\naddr = \"127.0.0.1:0\"\n\
         [health]\naddr = \"127.0.0.1:0\"\n",
    )
    .unwrap();
    file
}

fn write(dir: &Path, name: &str, v: &Value) -> PathBuf {
    let file = dir.join(name);
    std::fs::write(&file, serde_json::to_string_pretty(v).unwrap()).unwrap();
    file
}

/// Run the binary to completion. A refusal exits at once; a command that is
/// still running after the deadline was not refused, and is killed.
fn sumchain(args: &[&str]) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sumchain"))
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "`sumchain {}` kept running: it was not refused",
                args.join(" ")
            );
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

/// Every file under `dir` with its length and content hash.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (u64, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<PathBuf, (u64, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                let bytes = std::fs::read(&p).unwrap();
                out.insert(
                    p.strip_prefix(root).unwrap().to_path_buf(),
                    (
                        bytes.len() as u64,
                        sumchain_primitives::Hash::hash(&bytes).to_string(),
                    ),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn assert_refused_naming(args: &[&str], field: &str) {
    let (ok, text) = sumchain(args);
    assert!(!ok, "`sumchain {}` must fail:\n{text}", args.join(" "));
    assert!(
        text.contains(&format!("unknown field `{field}`")),
        "`sumchain {}` must name `{field}`:\n{text}",
        args.join(" ")
    );
}

#[test]
fn run_and_init_refuse_an_unknown_field_before_creating_anything() {
    let dir = tempfile::TempDir::new().unwrap();
    for (field, in_params) in [
        ("beacon_enabled_from_heigth", true),
        ("contracts_enabled_from_height", false),
    ] {
        let file = write(dir.path(), "genesis.json", &with_unknown(field, in_params));
        let data = dir.path().join("data");
        let config = loopback_config(dir.path());
        for cmd in [
            vec!["run", "--config", config.to_str().unwrap()],
            vec!["init"],
        ] {
            let mut args = cmd.clone();
            args.extend([
                "--genesis",
                file.to_str().unwrap(),
                "--data-dir",
                data.to_str().unwrap(),
            ]);
            assert_refused_naming(&args, field);
            assert!(
                !data.exists(),
                "`sumchain {}` created a data directory before refusing",
                cmd[0]
            );
        }
    }
}

#[test]
fn an_existing_database_is_not_opened_or_modified() {
    let dir = tempfile::TempDir::new().unwrap();
    let data = dir.path().join("data");
    let good = write(dir.path(), "good.json", &valid_genesis());
    let (ok, text) = sumchain(&[
        "init",
        "--genesis",
        good.to_str().unwrap(),
        "--data-dir",
        data.to_str().unwrap(),
    ]);
    assert!(ok, "the valid genesis initializes:\n{text}");
    let before = snapshot(&data);
    assert!(!before.is_empty());

    let field = "max_txs_per_blok";
    let bad = write(dir.path(), "bad.json", &with_unknown(field, true));
    let bad = bad.to_str().unwrap();
    let data_arg = data.to_str().unwrap();
    let commitment = format!("0x{}", "00".repeat(32));
    let config = loopback_config(dir.path());
    for args in [
        vec![
            "run",
            "--config",
            config.to_str().unwrap(),
            "--genesis",
            bad,
            "--data-dir",
            data_arg,
        ],
        vec!["init", "--genesis", bad, "--data-dir", data_arg],
        vec![
            "acknowledge-consensus-config",
            "--genesis",
            bad,
            "--data-dir",
            data_arg,
            "--old",
            &commitment,
            "--new",
            &commitment,
            "--yes",
        ],
    ] {
        assert_refused_naming(&args, field);
        assert_eq!(
            snapshot(&data),
            before,
            "`sumchain {}` changed the database before refusing",
            args.join(" ")
        );
    }
}

//! Issue #353: several nodes on one host.
//!
//! Every `sumchain run` binds three listeners: JSON-RPC (`--rpc-addr`), P2P
//! (`--p2p-addr`) and the health/readiness server, which defaults to
//! `0.0.0.0:8546` and is bound whether or not anything probes it. Before
//! `--health-addr` existed it could only be moved with a config file, so the
//! local three-validator recipe failed as written: validator 2's JSON-RPC
//! (`127.0.0.1:8546`) and every node's health server wanted the same port.
//!
//! * The README recipe and the commands `setup-local-testnet` prints give
//!   every listener of every node its own address.
//! * `--health-addr` overrides the config file's `[health] addr`.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sumchain");

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/crates/node ; the workspace root is two up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

// ── The local-testnet recipes ────────────────────────────────────────────────

/// One listener of one node: `(ip, port)`, with where it came from.
#[derive(Debug, Clone)]
struct Listener {
    node: String,
    flag: &'static str,
    ip: String,
    port: u16,
}

fn split_host_port(s: &str) -> (String, u16) {
    let (ip, port) = s.rsplit_once(':').unwrap_or_else(|| panic!("no port in {s:?}"));
    (ip.to_string(), port.parse().unwrap_or_else(|_| panic!("bad port in {s:?}")))
}

/// The listeners one `sumchain run` command binds, given its arguments.
/// Flags it does not pass take the node's defaults (`config.rs`).
fn listeners(node: &str, args: &[String]) -> Vec<Listener> {
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .map(|i| args.get(i + 1).unwrap_or_else(|| panic!("{node}: {flag} without a value")).clone())
    };
    let mut out = Vec::new();
    let (ip, port) = split_host_port(&value("--rpc-addr").unwrap_or_else(|| "127.0.0.1:8545".into()));
    out.push(Listener { node: node.into(), flag: "--rpc-addr", ip, port });
    let (ip, port) =
        split_host_port(&value("--health-addr").unwrap_or_else(|| "0.0.0.0:8546".into()));
    out.push(Listener { node: node.into(), flag: "--health-addr", ip, port });
    if let Some(p2p) = value("--p2p-addr") {
        // /ip4/<ip>/tcp/<port>
        let parts: Vec<&str> = p2p.split('/').collect();
        assert!(
            parts.len() >= 5 && parts[1] == "ip4" && parts[3] == "tcp",
            "{node}: unexpected --p2p-addr {p2p:?}"
        );
        out.push(Listener {
            node: node.into(),
            flag: "--p2p-addr",
            ip: parts[2].to_string(),
            port: parts[4].parse().expect("p2p port"),
        });
    }
    out
}

/// Two TCP listeners on one host collide when they share a port and one of
/// them is the wildcard address or both are the same address.
fn collide(a: &Listener, b: &Listener) -> bool {
    a.port == b.port && (a.ip == b.ip || a.ip == "0.0.0.0" || b.ip == "0.0.0.0")
}

fn assert_no_collisions(source: &str, nodes: &[(String, Vec<String>)]) {
    assert!(
        nodes.len() >= 4,
        "{source}: expected three validators and a full node, found {}",
        nodes.len()
    );
    let all: Vec<Listener> = nodes.iter().flat_map(|(n, a)| listeners(n, a)).collect();
    let mut clashes = Vec::new();
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            if collide(a, b) {
                clashes.push(format!(
                    "{} {} {}:{} and {} {} {}:{}",
                    a.node, a.flag, a.ip, a.port, b.node, b.flag, b.ip, b.port
                ));
            }
        }
    }
    assert!(clashes.is_empty(), "{source}: listeners collide:\n{}", clashes.join("\n"));
}

/// Arguments of a shell command written over continuation lines.
fn shell_words(command: &str) -> Vec<String> {
    command
        .replace("\\\n", " ")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// The `sumchain run` commands of the README's local-testnet recipe: every
/// fenced block from "### 2. Start Validator Nodes" up to "### 4.".
fn readme_recipe() -> Vec<(String, Vec<String>)> {
    let text = fs::read_to_string(workspace_root().join("README.md")).unwrap();
    let start = text.find("### 2. Start Validator Nodes").expect("recipe start");
    let end = start + text[start..].find("### 4.").expect("recipe end");
    let section = &text[start..end];
    let mut nodes = Vec::new();
    for block in section.split("```").skip(1).step_by(2) {
        if !block.contains("sumchain -- run") {
            continue;
        }
        let args = shell_words(block.trim_start_matches("bash"));
        let name = args
            .iter()
            .position(|a| a == "--data-dir")
            .map(|i| args[i + 1].clone())
            .expect("--data-dir names the node");
        nodes.push((name, args));
    }
    nodes
}

/// The commands `setup-local-testnet` (local mode) prints, read from its
/// `println!` lines.
fn setup_script_recipe() -> Vec<(String, Vec<String>)> {
    let text =
        fs::read_to_string(workspace_root().join("scripts/src/setup_local_testnet.rs")).unwrap();
    let start = text.find("To start the testnet, run:").expect("printed recipe");
    let mut printed = String::new();
    for line in text[start..].lines().skip(1) {
        let line = line.trim();
        if line.starts_with("Ok(())") {
            break;
        }
        if let Some(lit) = line
            .strip_prefix("println!(\"")
            .and_then(|l| l.strip_suffix("\");"))
        {
            printed.push_str(&lit.replace("\\\\", "\\"));
        }
        printed.push('\n');
    }
    printed
        .split("  # Terminal")
        .skip(1)
        .map(|cmd| {
            let args = shell_words(cmd);
            let name = args
                .iter()
                .position(|a| a == "--data-dir")
                .map(|i| args[i + 1].clone())
                .expect("--data-dir names the node");
            (name, args)
        })
        .collect()
}

#[test]
fn readme_local_testnet_recipe_binds_distinct_addresses() {
    assert_no_collisions("README.md", &readme_recipe());
}

#[test]
fn setup_local_testnet_prints_commands_that_bind_distinct_addresses() {
    assert_no_collisions("scripts/src/setup_local_testnet.rs", &setup_script_recipe());
}

#[test]
fn the_collision_rule_catches_the_issue_353_recipe() {
    // The recipe as it stood: validator 2's RPC on 8546 and every node's
    // health server on the default 0.0.0.0:8546.
    let v1 = listeners("v1", &shell_words("--rpc-addr 127.0.0.1:8545"));
    let v2 = listeners("v2", &shell_words("--rpc-addr 127.0.0.1:8546"));
    assert!(v1.iter().any(|a| v2.iter().any(|b| collide(a, b))));
}

// ── `--health-addr` on the real binary ───────────────────────────────────────

struct Node {
    _dir: tempfile::TempDir,
    log: PathBuf,
    child: Child,
}

impl Node {
    fn log_text(&self) -> String {
        let mut s = String::new();
        if let Ok(mut f) = fs::File::open(&self.log) {
            let _ = f.read_to_string(&mut s);
        }
        s
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A one-validator NONPRODUCTION devnet (chain id 1337, a key the binary
/// generates into a temp directory) whose config file names `health` as its
/// health address, started with `extra` arguments.
fn start(health: &str, extra: &[&str]) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let key = p.join("fixture-validator.json");
    let out = Command::new(BIN)
        .args(["keygen", "--output"])
        .arg(&key)
        .output()
        .unwrap();
    assert!(out.status.success(), "keygen failed: {out:?}");
    let pk = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Public key: ").map(str::to_owned))
        .expect("keygen prints the public key");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    fs::write(
        p.join("genesis.json"),
        format!(
            r#"{{"chain_id":1337,"genesis_time":{now},"validators":["{pk}"],"alloc":{{}},
 "params":{{"block_time_ms":1000,"max_block_bytes":1000000,"max_txs_per_block":1000,"min_fee":1}}}}"#
        ),
    )
    .unwrap();
    // Port 0 everywhere: the kernel picks a free port when the node binds.
    fs::write(
        p.join("node.toml"),
        format!(
            r#"[node]
genesis = "{g}"
data_dir = "{d}"
validator_key = "{k}"
[consensus]
engine = "poa"
[network]
listen_addr = "/ip4/127.0.0.1/tcp/0"
mdns = false
[rpc]
addr = "127.0.0.1:0"
[health]
addr = "{health}"
[logging]
level = "info"
json = false
"#,
            g = p.join("genesis.json").display(),
            d = p.join("data").display(),
            k = key.display(),
        ),
    )
    .unwrap();
    let log = p.join("node.log");
    let f = fs::File::create(&log).unwrap();
    let child = Command::new(BIN)
        .args(["run", "--config"])
        .arg(p.join("node.toml"))
        .args(extra)
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap();
    Node { _dir: dir, log, child }
}

/// Wait for `needle` in the log, or for the process to exit.
fn wait_for(node: &mut Node, needle: &str, within: Duration) -> bool {
    let t = Instant::now();
    while t.elapsed() < within {
        if node.log_text().contains(needle) {
            return true;
        }
        if node.child.try_wait().unwrap().is_some() {
            return node.log_text().contains(needle);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

#[test]
fn health_addr_flag_overrides_the_config_file() {
    // The config file's health address is unusable on its own ...
    let mut refused = start("not-an-address", &[]);
    assert!(
        wait_for(&mut refused, "Invalid health address", Duration::from_secs(60)),
        "the config's health address was not the one in force:\n{}",
        refused.log_text()
    );
    let st = refused.child.wait().unwrap();
    assert!(!st.success(), "a node with no usable health address started");

    // ... and `--health-addr` replaces it.
    let mut node = start("not-an-address", &["--health-addr", "127.0.0.1:0"]);
    assert!(
        wait_for(&mut node, "Health server listening on 127.0.0.1:0", Duration::from_secs(60)),
        "--health-addr did not take effect:\n{}",
        node.log_text()
    );
    assert!(
        wait_for(&mut node, "Produced block", Duration::from_secs(60)),
        "the node did not run with --health-addr:\n{}",
        node.log_text()
    );
}

//! Swarm roster display (#309 item 3) through the wallet's real output paths: the
//! `sumchain-wallet` binary runs against a stub JSON-RPC server that answers from fixtures
//! and records every request. Each command runs with a roster and without one.
//!
//! Nothing is submitted: `transfer` stops at its confirmation prompt (there is no terminal,
//! so the prompt answers no), and the stub has no send method.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sumchain_primitives::Address;

fn addr(n: u8) -> Address {
    let mut b = [0u8; 20];
    b[0] = 0x5a;
    b[19] = n;
    Address::new(b)
}

/// A stub JSON-RPC server on 127.0.0.1: answers `method` from `fixtures` (an unknown method
/// gets a JSON-RPC error) and records every request body.
struct Stub {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Stub {
    fn start(fixtures: Vec<(&'static str, Value)>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let seen = Arc::clone(&seen);
                let fixtures = fixtures.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(conn.try_clone().unwrap());
                    loop {
                        let mut len = None;
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            let line = line.trim_end();
                            if line.is_empty() {
                                break;
                            }
                            if let Some(v) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                len = v.trim().parse::<usize>().ok();
                            }
                        }
                        let mut body = vec![0u8; len.unwrap_or(0)];
                        reader.read_exact(&mut body).unwrap();
                        let req: Value = serde_json::from_slice(&body).unwrap();
                        seen.lock().unwrap().push(req.clone());
                        let method = req["method"].as_str().unwrap_or_default();
                        let reply = match fixtures.iter().find(|(m, _)| *m == method) {
                            Some((_, result)) => {
                                json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
                            }
                            None => json!({"jsonrpc": "2.0", "id": req["id"],
                                       "error": {"code": -32601, "message": format!("stub: no {method}")}}),
                        };
                        let out = reply.to_string();
                        let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        out.len(),
                        out
                    );
                        if conn.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Stub { url, requests }
    }

    fn methods(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r["method"].as_str().unwrap_or_default().to_string())
            .collect()
    }
}

struct Run {
    out: String,
}

/// Run the wallet with `args`, with `--swarm-roster <roster>` when given. No terminal: stdin is null.
fn wallet(roster: Option<&PathBuf>, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sumchain-wallet"));
    cmd.arg("--no-color");
    if let Some(r) = roster {
        cmd.arg("--swarm-roster").arg(r);
    }
    let o = cmd
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run the wallet");
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    Run { out }
}

struct Fixture {
    dir: PathBuf,
    roster: PathBuf,
    member: Address,
    other: Address,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!(
            "sumchain-wallet-roster-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (member, other) = (addr(1), addr(2));
        let roster = dir.join("roster.txt");
        std::fs::write(
            &roster,
            format!("# test roster\n{}\n", member.to_raddress()),
        )
        .unwrap();
        Fixture {
            dir,
            roster,
            member,
            other,
        }
    }

    /// A throwaway unencrypted key (a JSON array of 32 bytes), so no password prompt.
    fn key(&self) -> PathBuf {
        let p = self.dir.join("key.json");
        std::fs::write(&p, serde_json::to_string(&vec![7u8; 32]).unwrap()).unwrap();
        p
    }

    /// With the roster the member shows only in the `r0` form; the other account only plain.
    /// Without it, both show only plain.
    fn check(&self, with: &Run, without: &Run, label: &str) {
        let (m, o) = (self.member.to_base58(), self.other.to_base58());
        let (mr, or) = (self.member.to_raddress(), self.other.to_raddress());
        assert!(
            with.out.contains(&mr),
            "{label}: member not shown as r0 with the roster:\n{}",
            with.out
        );
        assert!(
            !with.out.replace(&mr, "").contains(&m),
            "{label}: member also shown plain with the roster:\n{}",
            with.out
        );
        assert!(
            with.out.contains(&o) && !with.out.contains(&or),
            "{label}: other account must stay plain:\n{}",
            with.out
        );
        assert!(
            without.out.contains(&m),
            "{label}: member must be plain without a roster:\n{}",
            without.out
        );
        assert!(
            !without.out.contains(&mr) && !without.out.contains(&or),
            "{label}: no r0 without a roster:\n{}",
            without.out
        );
    }

    /// As [`Fixture::check`], for output that shows addresses only in their short form (first 8 and
    /// last 6 characters of the shown text).
    fn check_short(&self, with: &Run, without: &Run, label: &str) {
        let short = |s: &str| format!("{}...{}", &s[..8], &s[s.len() - 6..]);
        let (m, o) = (self.member.to_base58(), self.other.to_base58());
        let mr = self.member.to_raddress();
        assert!(
            with.out.contains(&short(&mr)),
            "{label}: member short form not r0 with the roster:\n{}",
            with.out
        );
        assert!(
            !with.out.contains(&short(&m)),
            "{label}: member short form plain with the roster:\n{}",
            with.out
        );
        assert!(
            with.out.contains(&short(&o)),
            "{label}: other account's short form must stay plain:\n{}",
            with.out
        );
        assert!(
            without.out.contains(&short(&m)) && !without.out.contains(&short(&mr)),
            "{label}: default short forms:\n{}",
            without.out
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tx_info(hash: &str, from: &Address, to: &Address) -> Value {
    json!({"hash": hash, "from": from.to_base58(), "to": to.to_base58(), "amount": "1000000000", "fee": "1000",
           "nonce": 3, "chain_id": 1, "signature": "00", "block_height": 10, "status": "success",
           "tx_type": "transfer", "action": null, "asset_ref": null, "asset_kind": null})
}

fn delegation(delegator: &Address, validator: &Address) -> Value {
    json!({"delegator": delegator.to_base58(), "validator_address": validator.to_base58(),
           "validator_pubkey": "pk-validator", "amount": "5000000000", "pending_rewards": "0", "delegated_at": 42})
}

#[test]
fn transaction_details_and_pending_rows() {
    let f = Fixture::new("tx");
    let hash = format!("0x{}", "ab".repeat(32));
    let stub = Stub::start(vec![
        ("get_transaction", tx_info(&hash, &f.member, &f.other)),
        (
            "get_pending_transactions",
            json!([tx_info(&hash, &f.member, &f.other)]),
        ),
    ]);
    let args = ["tx", "--rpc", &stub.url, "--hash", &hash];
    let (with, without) = (wallet(Some(&f.roster), &args), wallet(None, &args));
    f.check(&with, &without, "tx");
    assert!(
        with.out.contains(&hash) && without.out.contains(&hash),
        "the hash is printed unchanged"
    );
    let args = ["pending", "--rpc", &stub.url];
    f.check_short(
        &wallet(Some(&f.roster), &args),
        &wallet(None, &args),
        "pending",
    );
}

#[test]
fn block_proposer_and_validator_list() {
    let f = Fixture::new("block");
    let stub = Stub::start(vec![
        (
            "get_block_by_height",
            json!({"hash": format!("0x{}", "cd".repeat(32)), "height": 9, "parent_hash": "0x00",
            "timestamp": 1, "tx_root": "0x01", "state_root": "0x02", "proposer": f.member.to_base58(), "tx_count": 0, "transactions": []}),
        ),
        (
            "get_validators",
            json!({"validators": [
            {"public_key": "pk-member", "address": f.member.to_base58(), "is_current_proposer": true},
            {"public_key": "pk-other", "address": f.other.to_base58(), "is_current_proposer": false}],
            "current_height": 9, "current_proposer_index": 0}),
        ),
    ]);
    let block = ["block", "--rpc", &stub.url, "--height", "9"];
    let with = wallet(Some(&f.roster), &block);
    assert!(
        with.out.contains(&f.member.to_raddress()),
        "proposer shown as r0:\n{}",
        with.out
    );
    assert!(!wallet(None, &block).out.contains(&f.member.to_raddress()));
    let args = ["validators", "--rpc", &stub.url];
    let (with, without) = (wallet(Some(&f.roster), &args), wallet(None, &args));
    f.check(&with, &without, "validators");
    assert!(
        with.out.contains("pk-member") && with.out.contains("pk-other"),
        "public keys printed unchanged"
    );
}

#[test]
fn nft_owners_creators_approved_and_royalty_recipients() {
    let f = Fixture::new("nft");
    let stub = Stub::start(vec![
        (
            "nft_getCollection",
            json!({"collection_id": "c1", "name": "C", "symbol": "C", "description": "",
            "owner": f.member.to_base58(), "max_supply": 0, "total_supply": 1, "transferable": true, "burnable": false,
            "metadata_updatable": false, "royalty_bps": 250, "royalty_recipient": f.other.to_base58(), "base_uri": null,
            "created_at": 1}),
        ),
        (
            "nft_getToken",
            json!({"collection_id": "c1", "token_id": 1, "owner": f.member.to_base58(),
            "creator": f.other.to_base58(), "metadata": "", "is_document": false, "uri_type": "none", "uri_value": null,
            "approved": f.member.to_base58(), "locked": false, "transfer_count": 0, "minted_at": 1}),
        ),
        (
            "nft_getTokensByOwner",
            json!({"owner": f.member.to_base58(), "count": 1,
            "tokens": [{"collection_id": "c1", "token_id": 1}]}),
        ),
    ]);
    let args = ["nft-collection", "--rpc", &stub.url, "--id", "c1"];
    f.check(
        &wallet(Some(&f.roster), &args),
        &wallet(None, &args),
        "nft-collection (owner, royalty recipient)",
    );
    let args = [
        "nft-token",
        "--rpc",
        &stub.url,
        "--collection",
        "c1",
        "--token-id",
        "1",
    ];
    f.check(
        &wallet(Some(&f.roster), &args),
        &wallet(None, &args),
        "nft-token (owner, creator, approved)",
    );
    let m = f.member.to_base58();
    let args = ["nft-list", "--rpc", &stub.url, "--owner", &m];
    let with = wallet(Some(&f.roster), &args);
    assert!(
        with.out.contains(&f.member.to_raddress())
            && !with.out.replace(&f.member.to_raddress(), "").contains(&m),
        "nft-list owner:\n{}",
        with.out
    );
    // The RPC input is passed as typed: the plain form here, never rewritten to r0.
    let sent: Vec<Value> = stub
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["method"] == "nft_getTokensByOwner")
        .cloned()
        .collect();
    assert!(
        !sent.is_empty()
            && sent
                .iter()
                .all(|r| r["params"].to_string().contains(&m)
                    && !r["params"].to_string().contains("r0"))
    );
}

#[test]
fn delegators_and_validator_addresses() {
    let f = Fixture::new("delegation");
    let stub = Stub::start(vec![
        ("delegation_getDelegation", delegation(&f.member, &f.other)),
        (
            "delegation_getDelegationsByDelegator",
            json!([delegation(&f.member, &f.other)]),
        ),
        (
            "delegation_getDelegationsByValidator",
            json!([delegation(&f.member, &f.other)]),
        ),
        (
            "delegation_getDelegatorSummary",
            json!({"delegator": f.member.to_base58(), "total_delegated": "5000000000",
            "total_pending_rewards": "0", "total_unbonding": "0", "delegation_count": 1, "unbonding_count": 0}),
        ),
    ]);
    let (m, o) = (f.member.to_base58(), f.other.to_base58());
    let args = [
        "delegation",
        "--rpc",
        &stub.url,
        "--delegator",
        &m,
        "--validator",
        &o,
    ];
    let (with, without) = (wallet(Some(&f.roster), &args), wallet(None, &args));
    assert!(
        with.out.contains(&f.member.to_raddress())
            && !without.out.contains(&f.member.to_raddress()),
        "delegation delegator:\n{}",
        with.out
    );
    assert!(
        with.out.contains("pk-validator"),
        "validator public key printed unchanged"
    );
    let args = ["delegator-summary", "--rpc", &stub.url, "--delegator", &m];
    let with = wallet(Some(&f.roster), &args);
    assert!(
        with.out.contains(&f.member.to_raddress()),
        "delegator summary:\n{}",
        with.out
    );
    let args = ["delegations", "--rpc", &stub.url, "--delegator", &m];
    let (with, without) = (wallet(Some(&f.roster), &args), wallet(None, &args));
    // The header names the delegator (a member) and each row the validator (not a member), short.
    f.check_short(&with, &without, "delegations");
    let args = [
        "validator-delegations",
        "--rpc",
        &stub.url,
        "--validator",
        &o,
    ];
    let with = wallet(Some(&f.roster), &args);
    let short = |s: &str| format!("{}...{}", &s[..8], &s[s.len() - 6..]);
    assert!(
        with.out.contains(&short(&f.member.to_raddress())),
        "validator-delegations delegator rows:\n{}",
        with.out
    );
}

#[test]
fn transfer_confirmation_and_offline_signing() {
    let f = Fixture::new("transfer");
    let key = f.key();
    let key = key.to_str().unwrap();
    // The roster names the signing account and the recipient's other form is plain.
    let ks_addr = {
        let probe = wallet(None, &["address", "--key", key]);
        probe
            .out
            .lines()
            .map(str::trim)
            .find_map(|l| Address::from_base58(l.rsplit(' ').next()?).ok())
            .expect("address printed")
    };
    std::fs::write(
        &f.roster,
        format!("{}\n{}\n", ks_addr.to_raddress(), f.member.to_base58()),
    )
    .unwrap();
    let stub = Stub::start(vec![
        ("get_nonce", json!(3)),
        ("get_balance", json!("100000000000")),
    ]);
    let m = f.member.to_base58();
    let args = [
        "transfer",
        "--key",
        key,
        "--rpc",
        &stub.url,
        "--to",
        &m,
        "--amount",
        "1",
        "--fee",
        "0.001",
        "--chain-id",
        "1",
    ];
    let (with, without) = (wallet(Some(&f.roster), &args), wallet(None, &args));
    for (run, label) in [(&with, "with"), (&without, "without")] {
        assert!(
            run.out.contains("Transfer cancelled."),
            "{label}: the transfer must stop at the prompt:\n{}",
            run.out
        );
    }
    assert!(
        with.out.contains(&ks_addr.to_raddress()) && with.out.contains(&f.member.to_raddress()),
        "transfer confirmation:\n{}",
        with.out
    );
    assert!(
        !without.out.contains(&ks_addr.to_raddress()) && without.out.contains(&ks_addr.to_base58()),
        "default transfer confirmation:\n{}",
        without.out
    );
    // Nothing was sent; the nonce and balance queries carry the plain address.
    let methods = stub.methods();
    assert!(
        methods
            .iter()
            .all(|m| m == "get_nonce" || m == "get_balance"),
        "only queries were made: {methods:?}"
    );
    for r in stub.requests.lock().unwrap().iter() {
        assert!(
            r["params"].to_string().contains(&ks_addr.to_base58())
                && !r["params"].to_string().contains("r0"),
            "RPC input: {r}"
        );
    }

    // Offline signing: the summary shows the r0 forms; the hash and the raw transaction are identical
    // with and without the roster, and for a recipient given in either form.
    let sign = |roster: Option<&PathBuf>, to: &str| {
        wallet(
            roster,
            &[
                "sign-tx",
                "--key",
                key,
                "--to",
                to,
                "--amount",
                "1",
                "--fee",
                "0.001",
                "--nonce",
                "3",
                "--chain-id",
                "1",
            ],
        )
    };
    let field = |run: &Run, name: &str| {
        run.out
            .lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix(&format!("{name}: "))
                    .map(str::to_string)
            })
            .unwrap_or_else(|| panic!("{name} missing:\n{}", run.out))
    };
    let (a, b, c) = (
        sign(Some(&f.roster), &m),
        sign(None, &m),
        sign(Some(&f.roster), &f.member.to_raddress()),
    );
    assert!(
        a.out.contains(&ks_addr.to_raddress()) && a.out.contains(&f.member.to_raddress()),
        "sign-tx summary:\n{}",
        a.out
    );
    assert!(
        !b.out.contains(&f.member.to_raddress()),
        "sign-tx default summary:\n{}",
        b.out
    );
    for name in ["Hash", "Raw TX"] {
        assert_eq!(
            field(&a, name),
            field(&b, name),
            "{name} must not depend on the roster"
        );
        assert_eq!(
            field(&a, name),
            field(&c, name),
            "{name} must not depend on the recipient's form"
        );
    }
}

#[test]
fn nft_owner_contract_call_events_and_gas_estimate() {
    let f = Fixture::new("contract");
    let topic = format!("0x{}", "11".repeat(32));
    let stub = Stub::start(vec![
        ("nft_ownerOf", json!(f.member.to_base58())),
        (
            "contract_call",
            json!({"tx_hash": null, "return_data": "0x01", "gas_used": 21000, "success": true,
            "error": null, "events": [
                {"contract": f.member.to_base58(), "topics": [topic], "data": "0xff"},
                {"contract": f.other.to_base58(), "topics": [], "data": ""}]}),
        ),
        (
            "contract_estimateGas",
            json!({"gas_estimate": 50000, "gas_price": "1", "total_cost": "50000"}),
        ),
    ]);
    let (m, o, mr) = (
        f.member.to_base58(),
        f.other.to_base58(),
        f.member.to_raddress(),
    );
    let only_r0 = |run: &Run, label: &str| {
        assert!(
            run.out.contains(&mr) && !run.out.replace(&mr, "").contains(&m),
            "{label}: member must show only as r0:\n{}",
            run.out
        );
    };
    let only_plain = |run: &Run, label: &str| {
        assert!(
            run.out.contains(&m) && !run.out.contains("r0"),
            "{label}: default output must be plain:\n{}",
            run.out
        );
    };

    // nft-owner: the owner, coloured after the roster is applied.
    let args = [
        "nft-owner",
        "--rpc",
        &stub.url,
        "--collection",
        "c1",
        "--token-id",
        "1",
    ];
    only_r0(&wallet(Some(&f.roster), &args), "nft-owner");
    only_plain(&wallet(None, &args), "nft-owner");

    // contract-call: the contract field and each event's contract address; topics and data unchanged.
    let args = [
        "contract-call",
        "--rpc",
        &stub.url,
        "--contract",
        &m,
        "--method",
        "get",
        "--from",
        &o,
    ];
    let (with, without) = (wallet(Some(&f.roster), &args), wallet(None, &args));
    f.check(
        &with,
        &without,
        "contract-call (contract field, event addresses)",
    );
    assert!(
        with.out.contains(&format!("Contract: {mr}"))
            && with.out.contains(&format!("Contract: {o}")),
        "event rows:\n{}",
        with.out
    );
    assert!(
        with.out.contains(&topic) && without.out.contains(&topic),
        "topics printed unchanged"
    );

    // contract-estimate-gas: the contract field.
    let args = [
        "contract-estimate-gas",
        "--rpc",
        &stub.url,
        "--contract",
        &m,
        "--method",
        "get",
    ];
    only_r0(&wallet(Some(&f.roster), &args), "contract-estimate-gas");
    only_plain(&wallet(None, &args), "contract-estimate-gas");

    // RPC inputs go out as given (plain here), never rewritten to r0; and a contract given in the r0 form is
    // passed on in that form.
    let sent = stub.requests.lock().unwrap().clone();
    for r in sent
        .iter()
        .filter(|r| r["method"] == "contract_call" || r["method"] == "contract_estimateGas")
    {
        let p = r["params"].to_string();
        assert!(
            p.contains(&m) && !p.contains("r0"),
            "RPC input rewritten: {r}"
        );
    }
    let _ = wallet(
        Some(&f.roster),
        &[
            "contract-estimate-gas",
            "--rpc",
            &stub.url,
            "--contract",
            &mr,
            "--method",
            "get",
        ],
    );
    let last = stub.requests.lock().unwrap().last().cloned().unwrap();
    assert!(
        last["params"].to_string().contains(&mr),
        "an r0 contract argument is passed as given: {last}"
    );
    // Only queries were made.
    assert!(stub.methods().iter().all(|x| [
        "nft_ownerOf",
        "contract_call",
        "contract_estimateGas"
    ]
    .contains(&x.as_str())));
}

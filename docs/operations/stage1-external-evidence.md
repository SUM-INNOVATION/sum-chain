# Stage 1: external evidence, what was measured and what could not be

Round: Stage 1 rollout preparation, track 3. Tree: `8954b0d0ace726ab9491cac8a7757f11158c3d1a`
(merged `origin/main`), branch `rollout/r3-evidence`. Date of every reading:
2026-09-23 (UTC).

**Nothing in this file is a production measurement unless it says so and names
the command, the timestamp and the endpoint it came from.** Fixture results are
labelled NONPRODUCTION. No devnet, fixture or estimate stands in for a
production number anywhere below.

What this machine can reach: the public JSON-RPC `https://rpc.sumchain.io`
(behind Cloudflare, `server: cloudflare`) and GitHub read-only. What it cannot:
`kubectl`, `gcloud`, `aws`, `az`, `doctl` and `docker` are all `not found`;
`~/.kube` and `~/.ssh/config` do not exist; no production database or snapshot
is on this machine.

Each section separates **(a) verified**, **(b) inferred** and **(c) unresolved**.

---

## 1. Production `cf::STATE` physical-row count: NOT MEASURED, access missing

The procedure is `docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md` §1.5 (and
Sequence step 0 of `docs/operations/ACCOUNT-ROOT-ACTIVATION.md`).

### What the procedure requires

| | |
|---|---|
| quantity | rows in `cf::STATE` under `ACCOUNT_KEY_PREFIX`, counted by `account_row_count` (`crates/state/src/account_root.rs`) — not accounts holding value |
| database identity | a node running a binary built from this tree, opened against **the production data directory** (a production validator after the upgrade, or a node restored from a production snapshot) |
| command, form A | start that node and read its startup line `Account rows: N (warn at 250000, act at 500000)` (`crates/node/src/node.rs`) |
| command, form B | `curl -s http://<that node>:8545/ -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"chain_getSyncCapability","params":[]}'` → `.result.account_rows` |
| recorded with it | chain height, UTC timestamp, node identity (hostname or validator key, and the binary identity), data-directory identity (absolute path; executed-from-genesis or restored, and the snapshot height) |
| validity | head within `finality_depth` (6) of the public head; two independent nodes, agreeing once adjusted for height |
| acceptance | `N < 250,000` ACCEPT; `250,000 ≤ N < 500,000` ACCEPT with tracking; `500,000 ≤ N < 2,000,000` DO NOT SCHEDULE on this evidence; `N ≥ 2,000,000` REFUSE. `N < 18` means the instrument was pointed at the wrong database |

### Attempt

```
$ date -u; curl -sS https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"chain_getSyncCapability","params":[]}'
2026-09-23T19:24:36Z  {"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}
2026-09-23T19:31:05Z  {"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":1}
```

`chain_getActivationStatus` answers the same (`-32601`, 19:24:36Z). The public
endpoint runs a binary older than this tree and cannot serve form B. For
reference only, not a row count: `chain_getBlockHeight` returned
`{"height":13241209}` at 19:24:36Z and `{"height":13241469}` at 19:31:05Z.

### The exact missing access

From the committed manifests (`deploy/kubernetes/statefulset-validator-{1,2,3}.yaml`,
`deploy/kubernetes/configmap.yaml`). These are the COMMITTED manifests; whether
production matches them is part of what is missing.

| needed | value per the manifests |
|---|---|
| cluster credentials | a kubeconfig for the production cluster (none on this machine) |
| namespace | `sumchain` |
| pod name pattern | `sumchain-validator-<n>-0` (three single-replica StatefulSets `sumchain-validator-1..3`) |
| DB path | `/data`: volume `data` (a `volumeClaimTemplate`, PVC `data-sumchain-validator-<n>-0`) mounted at `/data`, and `node.toml` `data_dir = "/data"` |
| RBAC | `get`/`list` on `pods`, `create` on `pods/exec` and `get` on `pods/log` in `sumchain` (form A reads the startup log; form B needs `pods/portforward` or in-cluster RPC access on port 8545) |
| or, instead | a production snapshot (`sumchain backup` output) and a host with this tree's binary to restore it on — plus that snapshot's height |

And the precondition: form B only works **after** a validator runs this tree's
binary, i.e. after Stage 1 itself. Form A works against a restored snapshot.

**(a) verified** the public RPC cannot serve the count (twice, timestamps above);
no access path exists from this machine. **(b) inferred** the pod/DB identity
above, from committed manifests only. **(c) unresolved** the number itself.
`account_root_enabled_from_height` stays unset.

---

## 2. OC-3 and SC-8

### OC-3: tree `T` NOT identified

What was searched (all read-only):

* `git log --all -S'raw reorg'` and `-S'7 operator'`: the phrase first enters
  the repository in `25d3ae5a86132907882b63abb2798c15da8287f6`
  ("docs: repair the blocker inventory and correct three claims it got wrong"),
  **as a withdrawal**: "An earlier summary of mine claimed roughly thirteen …
  That count could not be reproduced." The commit's parent, and the tree it says
  it was checked against, is `b6f4f6ada25a14b5438823658c615e5053de7c1d`.
* `git log --all --grep` for `thirteen` / `out-of-consensus`: nothing records
  the original claim's tree. The other "thirteen" hits are unrelated
  (`e293b03`, "thirteen families" = the thirteen `MESSAGING_*` column families).
* `git log --all -S MESSAGING -- crates/state/src/state.rs crates/state/src/snapshot.rs crates/consensus …`:
  the only hit, `5fd6619`, adds **tests** under `crates/consensus/tests/`. No
  committed tree in this clone's 73 refs had a non-test `MESSAGING` reference in
  the snapshot or reorg paths the "1 snapshot, 3 raw reorg" names.
* GitHub, read-only: `gh search issues/prs "raw reorg"`, `"seven operator"`,
  `"MESSAGING_ write sites"` → nothing relevant; `gh issue view 253` (left OPEN,
  untouched) does not mention it.

**Conclusion:** the count came from an uncommitted session summary. `T` is not
recoverable from the repository or its issues, so the reproducer was **not run
against `T`**.

What would identify it: the transcript or working copy of the session that
produced the "earlier summary" (before 2026-09-17 19:24 -0700), or its
enumeration with file:line, together with `git -C <T> rev-parse HEAD`.

**Supplementary, NOT `T`, closes nothing.** To test the reproducer itself, it was
run against the one tree the record names, `b6f4f6a…`, in a temporary worktree
(`/Users/0x1e0/worktrees/sum-chain/oc3-candidate-b6f4f6a`, removed afterwards),
compiled with `rustc --edition 2021 --test` and `CARGO_MANIFEST_DIR` pointed at
that tree (the file is `std`-only):

```
running 2 tests
thread 'the_non_test_callers_of_a_messaging_write_are_exactly_the_two_audited_rows' panicked at …:200:5:
the method-set derivation must find the writers this row is about; it found ["add_contact", "backfill_indexes", …, "unblock_sender"]
test the_scan_can_see_a_caller_it_is_not_expecting ... ok
test result: FAILED. 1 passed; 1 failed
```

**This is a defect in the reproducer (reported, not fixed).** Its precondition
assert requires `seed_registry_at_genesis`, which only exists from `fdc077e1`
(2026-09-18). On ANY tree older than that, which includes every tree a
2026-09-17 count could have been taken against, the test panics before its
`assert_eq!` and **never prints the enumeration**. That is a fourth outcome
that step 5 of the reproducer does not list. Re-run with only that one conjunct
removed (scratch copy, not committed), the same tree gives
`left: {"crates/node/src/main.rs": ["set_public_key"], "crates/node/src/node.rs": ["backfill_indexes"]}`:
two callers at `b6f4f6a`, the same as the audit's recount. As a control, the
unmodified file passes 2/2 at `8954b0d` under the same `rustc` harness.

### SC-8: NOT settled, deployed configuration not observable

The reproducer asks for the **deployed** operator RPC configuration. Findings:

* **(a) verified, committed configuration:** `deploy/kubernetes/configmap.yaml`
  sets `[rpc] addr = "0.0.0.0:8545"`, and `deploy/kubernetes/service.yaml`
  defines `sumchain-rpc` as `type: LoadBalancer` selecting every validator pod.
  As committed, validator RPC is exposed publicly. The in-code default is
  loopback (`crates/node/src/config.rs`), and the manifests override it.
* **(a) verified, live:** `https://rpc.sumchain.io` answers unauthenticated
  JSON-RPC from this machine through Cloudflare (19:24:36Z). It runs the OLDER
  binary, so it is not the release RPC surface SC-8 asks about.
* **(c) unresolved:** whether that endpoint's origin is a validator or a
  separate RPC node, and whether production uses the committed manifests.
  Missing: `kubectl -n sumchain get svc,ingress -o yaml`, the deployed
  `sumchain-config` ConfigMap's `node.toml` `[rpc] addr`, and the Cloudflare
  origin / tunnel configuration for `rpc.sumchain.io`.

---

## 3. Stage 1 telemetry path, verified at `8954b0d`

| claim | verdict | evidence |
|---|---|---|
| `sumchain_tx_execution_errors_total` has exactly one production call site | **VERIFIED** | `grep -rn 'tx_error_metrics::record'`: `crates/state/src/executor.rs:3696` (under `if screening.is_none()`) and `crates/rpc/src/metrics.rs:672`, which is inside `#[cfg(test)]` (module opens at `:559`). No re-export of `record`. Pinned by `exactly_one_non_test_call_site_builds_a_receipt` |
| label set is exactly `{subsystem, code}` from a closed table | **VERIFIED** | `TX_EXECUTION_ERROR_LABEL_NAMES = &["subsystem","code"]`; labels are `&'static str` from `SUBSYSTEMS`/`FAILURE_SERIES`/`STATUS_SERIES`; unknown codes go to one `unknown/unallocated` series; counters are a fixed `[AtomicU64; SERIES_COUNT]` with no insert path |
| per-process, resets on restart | **VERIFIED by reading, not by test** | `static COUNTS: [AtomicU64; SERIES_COUNT] = [const { AtomicU64::new(0) }; …]`; nothing loads or persists it. No test restarts a process to show it |
| handshake success is `info!`, refusal is `warn!` | **VERIFIED** | `crates/node/src/node.rs:913-917` `info!(peer, digest, "compatibility handshake accepted: …")`; `:919-926` `warn!("REFUSING peer {}: …")`; also `crates/p2p/src/peer_compat.rs:195` `warn!` |
| `wave1-monitor.sh` compares deltas over a common window, not raw totals | **FALSE for `agree`** (see below) | `cmd_agree` diffs raw `samples` output; only its closing text *advises* comparing deltas. `cmd_delta` is single-node against its own baseline |

Tests run (`cargo test`, this worktree, 2026-09-23):

```
cargo test -p sumchain-state --test wave1_execution_error_signal
     Running tests/wave1_execution_error_signal.rs
running 15 tests
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p sumchain-primitives tx_error_metrics
     Running unittests src/lib.rs
running 8 tests
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 13 filtered out

cargo test -p sumchain-rpc --lib metrics
     Running unittests src/lib.rs
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 147 filtered out
```

### Two defects in `wave1-monitor.sh`, reported, NOT fixed (outside this round's remit)

NONPRODUCTION fixture `/metrics` text, served through a `curl` shim:

1. **`agree` compares raw totals.** Validator A `nft/2 = 105` (100 before a
   restart, 5 since), validator B `nft/2 = 5` (restarted). Same refusals over the
   common window. Result: `DISAGREE … fork in progress`, exit 1. §4.1 item 6 of
   `activation-rollout-evidence.md` makes this a HALT condition, so any
   uneven restart produces a false halt. That is the safe direction, but it is
   noisy and it trains operators to ignore the signal.
2. **`delta` hides refusals across a restart.** Baseline `nft 2 100`; the node
   restarts; 3 refusals follow, so `now = 3`. Result: `delta -97` and
   **"Nothing moved"**, exit 0. The test is `[[ $d -gt 0 ]]`, and a negative
   delta after a reset reads as quiet. That is a false negative in the unsafe
   direction. Fix direction (not applied): treat `now < baseline` as a counter
   reset and report `now` as the lower bound on refusals, or refuse to compute
   the delta.

---

## 4. Rollout evidence collector: dry-run, defects, fix

Collector: `docs/operations/activation-rollout-evidence.md` §1.1 `rollout-record.sh`
plus the §1.1/§1.2 aggregation. Harness: `kubectl` and `curl` shims that serve
NONPRODUCTION fixtures and emulate the image filesystem as the `Dockerfile`
defines it (only `/usr/local/bin/sumchain` exists). The fixtures are generated by
`tools/lane-b/rollout-check-test.py`.

### 4.1 The committed collector (before)

| fixture (NONPRODUCTION) | expected | actual, committed collector |
|---|---|---|
| complete N=2 | pass, with a binary sha | exit 0, **`binary_sha256:` EMPTY**. `sha256sum: /usr/local/bin/sumchain-node: No such file or directory` on stderr. The `$(…)` inside `echo` does not trip `set -e`, so the script continues |
| missing handshake line (v2 never logged v1) | FAIL | exit 0, no verdict. The grep printed 1 line instead of 2, and nothing counts them |
| incompatibility refusal | FAIL | exit 0, no verdict. The refusal line is printed and nothing fails on it |
| validator on a different digest | FAIL | exit 0, no verdict. `uniq -c` shows `1 protocol_digest` twice, which only a reader would notice |
| empty log | FAIL | exit 0, no verdict |

Defects:

* **D1, wrong binary path** (also reported by track 1): `sha256sum /usr/local/bin/sumchain-node`
  at §1 row 1 and in `rollout-record.sh`. The image installs
  `/usr/local/bin/sumchain` (`Dockerfile:92` `COPY --from=builder /build/target/release/sumchain /usr/local/bin/`,
  `ENTRYPOINT ["sumchain"]`; `crates/node/Cargo.toml` `[[bin]] name = "sumchain"`).
  Correction to the report that came in: the script does **not** abort on this
  line. It records an **empty** `binary_sha256` and exits 0, which is worse.
  The same wrong name was the program invoked in §2.2 (`sumchain-node backup|restore|info|run`).
* **D2, no enforcement**: nothing requires N·(N−1) handshakes, zero refusals,
  digest agreement or the presence of any record. Every rule was a sentence for
  a human to apply, so silence passed.
* **D3, no attribution**: a success line names a libp2p peer ID, and the record
  did not capture each validator's own peer ID. A per-pair check was impossible.
* **D4, window**: `kubectl logs --since=1h` misses handshakes made when peers
  connected more than an hour earlier, and the startup peer-ID line.
* **D5, namespace**: `kubectl` without `-n sumchain`, while the manifests put
  the pods in namespace `sumchain`.

### 4.2 The fix (this branch)

* `docs/operations/activation-rollout-evidence.md`: hashes `/usr/local/bin/sumchain`;
  the §2.2 commands invoke `sumchain`; `rollout-record.sh` takes an output
  directory, uses `-n "$NS"` (default `sumchain`), saves the whole current-container
  log to `<pod>.log`, records `local_peer_id` (from `Local peer ID:`) and
  `telemetry: OK`, and hands the decision to the checker instead of `uniq -c`.
  The row now says the binary's identity is its file hash. The binary cannot
  report its commit (`option_env!("GIT_HASH")` is unset in every build, so it
  logs `Commit: unknown`). The procedure did not rely on the binary reporting
  its commit before this change, and it does not now.
* `tools/lane-b/rollout-check.py` (new): exits 0 only if every rule holds;
  **absent is failure** for every record, field, log and handshake.
* `tools/lane-b/rollout-check-test.py` (new): derives the binary path from the
  Dockerfile (runtime-stage `ENTRYPOINT` name + its `COPY` destination) and
  fails if the document hashes or invokes anything else. It then runs the
  document's own `rollout-record.sh`, extracted verbatim, through the shims and
  into the checker for every case.

Run against the COMMITTED document (`git show 8954b0d:docs/operations/activation-rollout-evidence.md`):

```
binary path derived from Dockerfile: /usr/local/bin/sumchain; document hashes ['/usr/local/bin/sumchain-node']
  FAIL complete N=2   expected exit 0, got 1
```

### 4.3 Dry-run after the fix (NONPRODUCTION fixtures)

`python3 tools/lane-b/rollout-check-test.py`:

| fixture | expected | actual | reason printed |
|---|---|---|---|
| complete N=2 | exit 0 | **exit 0** | `2/2 handshakes, 0 refusals` |
| complete N=3 | exit 0 | **exit 0** | `6/6 handshakes, 0 refusals` |
| missing handshake line | exit 1 | **exit 1** | `MISSING HANDSHAKE` |
| incompatibility refusal | exit 1 | **exit 1** | `INCOMPATIBILITY REFUSAL` |
| validator on a different protocol digest | exit 1 | **exit 1** | `DIGEST DISAGREEMENT` |
| activation digest differs, no refusal | exit 1 | **exit 1** | `DIGEST DISAGREEMENT on activation_digest` |
| empty log | exit 1 | **exit 1** | `MISSING HANDSHAKE` |
| missing validator record | exit 1 | **exit 1** | `MISSING RECORD` |
| missing log file | exit 1 | **exit 1** | `MISSING LOG` |
| wrong binary sha | exit 1 | **exit 1** | `BINARY MISMATCH` |
| missing `binary_sha256` field | exit 1 | **exit 1** | `MISSING FIELD binary_sha256` |
| gates set at stage 1 | exit 1 | **exit 1** | `gates_set is 3` |
| wrong chain id | exit 1 | **exit 1** | `CHAIN ID MISMATCH` |
| empty evidence directory | exit 1 | **exit 1** | `MISSING RECORD` |

```
ROLLOUT CHECK BATTERY OK: 14 cases, binary path matches the Dockerfile.
```

### 4.4 Found in the same document, reported, NOT changed

* §3 loops over `validator-1-0 validator-2-0 validator-3-0` with no namespace.
  The manifests name them `sumchain-validator-<n>-0` in namespace `sumchain`.
  It also hashes ConfigMap `sumchain-genesis`, which no manifest defines; the
  genesis is key `genesis.json` of ConfigMap `sumchain-config`. Both fail closed
  (the hashes come back empty or different, and `test` fails), but they will
  stop the rollout for the wrong reason.
* `get_peers` always returns `[]`: `RpcServer::with_peer_info` has no caller, so
  the `peers:` line the committed script printed was always `0`. It is dropped
  from the record because it was never evidence.
* The StatefulSets set `RUST_LOG=info,sumchain=debug`. **(b) inferred:** the
  debug volume shortens how long the handshake and peer-ID lines survive
  kubelet log rotation. If they rotate out, the check fails; nobody may fill
  the gap by hand.

---

## 5. Symbolic Stage 2 proposal, reviewed without heights

```
$ python3 tools/lane-b/activation-proposal.py
ACTIVATION PROPOSAL OK: 39 scheduled remediation gates + peer_protocol_declaration_required_from_height, {'1': 24, '2a': 4, '2b': 8, '2c': 2, '3': 1}, every height UNSET-PENDING-OWNER-AUTHORIZATION, 2 gates and 2 gateless audit rows held unset.
```

| requirement | verdict | where |
|---|---|---|
| peer-protocol enforcement ≥ 48 h before Wave 1 | **stated as the acceptance criterion, not machine-checked** | `derivation_rule.peer_protocol` and Wave 1 `prerequisites[0]` ("STRICTLY BELOW … at least 48 hours"). `ChainParams::validate` enforces only the looser load rule (`≤` earliest open remediation gate). `peer_protocol_enforcement.rs` 8/8 pass. The heights are symbolic, so nothing numeric can be checked until Stage 2 |
| Wave 1 keeps its full lead after recalculation, no compression | **VERIFIED** | `derivation_rule.lead_time_rule`; offsets 14/28/42/56/70 days pinned by `WAVE_OFFSET_DAYS`, and the script fails if the committed artifact differs from what it rebuilds |
| R5 `healthcare_authorization` ≤ R30 `healthcare_consent_subject_signature` | **VERIFIED, and enforced at load** | both in Wave 1 (a shared height satisfies it); `ChainParams::validate`, `crates/genesis/src/lib.rs:3177-3191`, refuses `(None, Some)` and `auth > grant`; tests `a_healthcare_authorization_gate_later_than_the_consent_grant_gate_is_refused`, `the_consent_grant_gate_cannot_open_over_a_closed_healthcare_authorization`, `the_legal_healthcare_consent_orderings_are_admitted` 3/3 pass |
| R2, account-root, OC-3, SC-8 unset | **VERIFIED** | `must_remain_unset`: `docclass_stake_escrow_enabled_from_height` (R2), `account_root_enabled_from_height` (N3), rows OC-3 and SC-8 (gateless; `no_gate_exists_for` derives it). The script fails if either field appears in a wave |

No height was inserted anywhere. `genesis.json` is untouched.

**One inaccuracy found, reported and not changed:** activation-rollout-evidence.md
§5 step 5 says `activation-proposal.py` "will then FAIL" once heights are
written into `genesis.json`. The script never reads `genesis.json`: it reads the
packet, the audit, `crates/genesis/src/lib.rs` and the artifact. It fails only
on a height written into the artifact. stage2-procedure.md §4.4 states the
correct expectation.

---

## 6. Summary

**(a) Verified**
* The public RPC cannot serve the row count (`-32601`, 2026-09-23T19:24:36Z and 19:31:05Z).
* No kube, cloud, SSH or docker access exists on this machine.
* The OC-3 count originates in an uncommitted summary. No ref or issue records `T`.
* The OC-3 reproducer cannot print its enumeration on any tree before `fdc077e1`.
* Telemetry: one production call site, a closed two-label set, per-process `static` atomics, `info!` success and `warn!` refusal. 15 + 8 + 7 tests pass.
* `wave1-monitor.sh agree` compares raw totals, and `delta` reports "Nothing moved" across a counter reset.
* The collector defects D1–D5 were demonstrated on fixtures and fixed. The 14-case battery passes.
* Proposal: lead times pinned, R5 ≤ R30 enforced at load, the four held rows unset.

**(b) Inferred**
* Production pod, namespace and DB-path identity, from the committed manifests.
* That `rpc.sumchain.io` fronts an older-binary node of chain 1. Its origin is unknown.
* Log-rotation risk to the handshake evidence under `sumchain=debug`.

**(c) Unresolved**
* The production `cf::STATE` row count. It needs production cluster access or a production snapshot.
* OC-3 tree `T`.
* SC-8 deployed RPC exposure.
* The 48 h peer-gate margin, which can only be checked once Stage 2 heights exist.
* The two `wave1-monitor.sh` defects, which need their own change.

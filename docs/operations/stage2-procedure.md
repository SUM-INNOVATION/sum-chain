# Stage 2: the activation-configuration branch and PR (procedure only)

**This is a procedure, not an authorization.** No branch, PR, height or genesis
edit was created while writing it. Stage 2 starts only when the repository owner
authorizes recalculation in writing **and** every precondition in §1 holds.
Until then `docs/lane-a/ACTIVATION-PROPOSAL.json` stays symbolic and
`genesis.json` stays exactly as committed.

Source of the rules: `docs/operations/activation-rollout-evidence.md` §§1–5,
`docs/lane-a/ACTIVATION-PROPOSAL.json` (`derivation_rule`, `waves`,
`must_remain_unset`), and `docs/lane-a/ACTIVATION-DECISION-PACKET.md` §0.7 (load
rules) and §0.9 (deployment).

---

## 1. Preconditions: all of them, or do not start

1. **Stage 1 rollout evidence is complete for EVERY validator.** For each one,
   `rollout-record.sh` (activation-rollout-evidence.md §1.1) has produced
   `<pod>.record` and `<pod>.log`, and on that directory
   ```bash
   python3 tools/lane-b/rollout-check.py \
     --validators <N> \
     --expected-binary-sha256 <binary_sha256 from the release record> \
     --expected-commit <40-hex release commit> \
     --expected-image-digest <sha256:... registry digest from the release record> \
     --expected-chain-id <chain id> \
     --expected-validator <64-hex public key of validator 1> \
     --expected-validator <64-hex public key of validator 2> \
     --expected-genesis-sha256 <sha256 of the PRODUCTION genesis bytes> \
     <evidence-dir>
   ```
   exits 0 and prints `STAGE 1 ROLLOUT EVIDENCE COMPLETE: N validators …
   N·(N−1)/N·(N−1) handshakes, 0 refusals`. Anything else means Stage 1 is not
   complete, and nothing below starts.
2. `tools/lane-b/wave1-monitor.sh verify <metrics-url>` passes on every validator.
3. The owner has authorized recalculation, in writing, naming the validator set
   the rate is to be measured against.
4. The owner has decided how the rows the audit holds **UNDETERMINED** are
   treated. Stage 2 does not settle them and must not claim to: OC-3 (tree `T`),
   SC-8 (deployed RPC exposure), and the production `cf::STATE` row count
   (account-root). See `docs/operations/stage1-external-evidence.md`.
5. The evidence directory from (1) is kept and is attached to, or referenced
   by, the PR.

## 2. Branch

| | |
|---|---|
| name | `activation/stage2-heights` |
| base | `origin/main` **at the moment of recalculation**, which must contain the Stage 1 release commit whose binary sha256 is the `--expected-binary-sha256` above |
| contents | `genesis.json` heights, plus nothing else except the record of how they were derived (the PR body). No source change and no tooling change. Do not edit `ACTIVATION-PROPOSAL.json`: it stays symbolic, and `activation-proposal.py` must still pass on the branch (§4.4) |

```bash
git fetch origin
git switch -c activation/stage2-heights origin/main
git rev-parse HEAD            # record: the recalculation base
```

## 3. Recalculate the heights (activation-rollout-evidence.md §5)

**3.1 Head and rate, measured and not remembered.**

```bash
# H: the head on a healthy validator, with a UTC timestamp.
date -u +%Y-%m-%dT%H:%M:%SZ
curl -fsS -X POST http://<validator>:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getActivationStatus","params":[]}' \
  | jq '{current_height, digest, protocol_digest, chain_id}'
```

`BLOCKS_PER_DAY`: read `current_height` twice, **at least 24 hours apart,
against the CURRENT validator set**, and divide the difference by the elapsed
days. The previous 57,524 blocks/day was measured against a two-validator set
and is not a constant. A reading of a few minutes, or one taken from any other
network, is not this measurement.

**3.2 Offsets, exactly as committed.** For each wave `w`, with `days` from
`ACTIVATION-PROPOSAL.json` `waves[].offset_from_recalculation_head.days`:

```
height(w) = H + days(w) * BLOCKS_PER_DAY        days = 14 / 28 / 42 / 56 / 70
```

Every gate in a wave takes that wave's height. **The days are not shortened**
(`derivation_rule.lead_time_rule`). If time was lost, the schedule moves later.

**3.3 The peer gate.** `peer_protocol_declaration_required_from_height` goes
**strictly below** the Wave 1 height by **at least 48 hours of blocks**:

```
peer_gate <= height(1) - 2 * BLOCKS_PER_DAY
peer_gate >  H                                   (every height above the head)
```

The load rule only requires `peer_gate ≤ earliest open remediation gate`. The
48 hours is the acceptance criterion, and the PR must show the arithmetic.

**3.4 Held unset. They must not appear in the genesis with a value:**
`docclass_stake_escrow_enabled_from_height` (R2),
`account_root_enabled_from_height` (N3), and the out-of-band
`application_journal_enabled_from_height` (N2). OC-3 and SC-8 have no gate.

**3.5 Pairs.** R5 `healthcare_authorization_enabled_from_height` ≤ R30
`healthcare_consent_subject_signature_enabled_from_height`. Both are in Wave 1,
so they share a height; `ChainParams::validate` refuses the other order.

**3.6 Write them into `genesis.json`** (the root runtime genesis, not
`genesis/mainnet_genesis.json`), identically for every validator.

## 4. Validation that must run, and pass, before the PR is opened

```bash
# 4.1 The committed bytes are the bytes under review (§2.1).
sha256sum genesis.json
git show HEAD:genesis.json | sha256sum          # identical after committing

# 4.2 ChainParams::validate and the gate invariants.
cargo test -p sumchain-genesis
cargo test -p sumchain-genesis --test peer_protocol_enforcement
cargo test -p sumchain-state --test remediation_gates
cargo test -p sumchain-state --test runtime_activation

# 4.3 The restart path against a POPULATED database, loopback-only (§2.2).
#     Pass: the log carries "Genesis activation digest … N gates set: …".
#     Fail: "chain activation parameters are unsound: …".
sumchain backup  --data-dir /data --output <backup-dir>
sumchain restore --backup <backup-dir> --data-dir <scratch-dir>
sumchain info    --data-dir <scratch-dir>                # height MUST be > 0
sumchain run --data-dir <scratch-dir> --genesis ./genesis.json \
  --p2p-addr 127.0.0.1:0 --rpc-addr 127.0.0.1:18545 --log-level debug
curl -fsS -X POST http://127.0.0.1:18545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getActivationStatus","params":[]}' | jq
#     gates[] carries exactly the heights written in §3, and no held field is set.

# 4.4 The symbolic artifact is untouched and still passes.
python3 tools/lane-b/activation-proposal.py
```

`activation-proposal.py` reads the packet, the audit, `crates/genesis/src/lib.rs`
and the artifact, **not `genesis.json`**. So it must still pass on this branch.
It fails only if someone writes a height into the artifact, and that is the
mistake it exists to catch. (activation-rollout-evidence.md §5 step 5 says it
"will then FAIL" once heights are in `genesis.json`. That is inaccurate, and
it is recorded in stage1-external-evidence.md.)

## 5. What the PR body must contain

1. The owner's authorization: a link or quote, with its date.
2. The Stage 1 evidence: the `rollout-check.py` command line, its full output,
   and where the evidence directory is kept. The expected binary sha256 and
   which release artifact it is the hash of.
3. `H`, with its UTC timestamp and the validator it was read from.
4. The two `current_height` readings behind `BLOCKS_PER_DAY`, with timestamps,
   the elapsed time and the validator set.
5. The table: wave → `days` → `H + days × BLOCKS_PER_DAY` → height, and the
   peer-gate arithmetic showing `height(1) − peer_gate ≥ 2 × BLOCKS_PER_DAY`.
6. The list of fields held unset (§3.4), and a statement that OC-3, SC-8 and the
   account-root row count remain as recorded, unsettled by this PR.
7. The outputs of §4.1–4.3 (hashes, test summary lines, and the restart log's
   `Genesis activation digest …` line).
8. The deployment plan from activation-rollout-evidence.md §3 and §4:
   byte-identical genesis on every validator and in the ConfigMap, rolling
   restarts one validator at a time, and the abort rule. **Stop before the peer
   gate if any validator misses the rollout. Compressing the lead is not an
   option.**

## 6. After merge (not part of the PR)

Deploy per activation-rollout-evidence.md §3: the same genesis bytes in the
commit, in every pod and in the ConfigMap. Before the peer-gate height, none of
the §4.1 stop conditions may hold on any validator. `rollout-check.py` is the
Stage 1 gate and requires `gates_set: 0`, so it is not the post-deploy check.
After the deploy, the checks are §3's byte identity and §4.1's digest agreement.

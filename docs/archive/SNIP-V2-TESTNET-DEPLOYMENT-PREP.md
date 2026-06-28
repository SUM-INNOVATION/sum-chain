# SNIP V2 Integration Plan — Phase 2 Closed

> **Archived / historical.** Kept for history; for current truth see [docs/tokens.md](../tokens.md) and [docs/policy-accounts-and-contracts.md](../policy-accounts-and-contracts.md).

**Status:** **CLOSED 2026-04-30.** All three Phase 2 deliverables shipped + verified by real smoke test (not just YAML validation). Hosted testnet deferred to Phase 2.x. Mainnet V2 is a separate track.
**Constraints that drove this scope:**
- **No hosted testnet capacity right now.** No 24/7 chain we can put a public RPC in front of.
- **2 validator machines available, not 3.** Anything that assumes 3 validators (current `deploy/kubernetes/` and prior compose) needs to drop to 2 — and 2-validator PoA has worse liveness than 3.
- **Mainnet-only is on the table** as an alternative for SNIP integration testing. That's a different release process (V2 chain upgrade) with real-Koppa stakes; out of scope for Phase 2 close.

Together these mean: **the original Phase 2 plan ("hosted testnet endpoint + end-to-end SNIP-client tests") is not feasible right now.** This doc is the recalibrated Phase 2 close.

---

## What changed in v3 (vs v1/v2)

v1/v2 of this doc described a 3-validator hosted testnet with Cloudflare TLS, k8s manifests, an Ingress, and 6 decisions to make. That was wrong on first principles — none of the infrastructure ($, machines, capacity) exists for it right now. v3:

- **Drops the 6 hosted-testnet decisions.** None of them mattered because the host doesn't exist.
- **Promotes "SNIP runs the chain locally" to the primary delivery path.** docker-compose, fixed in the deploy patches, is the handoff vehicle.
- **Defers hosted testnet** to Phase 2.x ("when capacity arrives"), with the deploy artifacts now correct so it's a turn-key affair when capacity does arrive.
- **Calls out mainnet-V2 testing** as a separate, much larger track requiring a chain upgrade. Not Phase 2.

---

## Reality check: what's now actually delivered

| Artifact | State | What it gives SNIP |
|---|---|---|
| 45 SNIP V2 integration tests through real block production | ✅ Done — `cargo test -p sumchain-integration-tests` passes | End-to-end coverage of every Phase 1 op (Register/Accept/Activate/Abandon/Add/Update/Remove + RPC backends) on a real PoA chain. |
| docker-compose.yaml | ✅ Fixed (`run` subcommand, real path mounts) | SNIP can spin up a 3-validator + fullnode chain locally with `docker-compose up -d --build`. |
| k8s manifests (configmap + statefulset variants) | ✅ Fixed (correct CLI, schema-valid TOML, per-validator StatefulSet split) | Ready when hosted capacity arrives. Not deployed today. |
| Dockerfile | ✅ Fixed (toolchain pin to 1.85, curl for health probe, `run` in CMD) | Image actually builds and survives health checks. |
| Existing keys + genesis | ✅ Already in repo (`keys/validator{1,2,3}.json`, `genesis/local_genesis.json`) | Compose mounts these directly. No key generation needed. |

Together: **SNIP can run a full V2-aware chain locally and exercise every V2 op against it today.** The local mirror, RPC cheatsheet, and `chain_getChainParams` are all shipped and smoke-tested.

---

## Phase 2 close — three deliverables shipped

### 1. SNIP-friendly single-validator compose preset
**Status: SHIPPED.** [deploy/snip-local-mirror.yaml](../../deploy/snip-local-mirror.yaml) + `genesis/snip-mirror-genesis.json`.

- One validator service exposing RPC on `localhost:8545`. No fullnode, no Prometheus/Grafana.
- Mounts `keys/validator1.json` + **`genesis/snip-mirror-genesis.json`** (single-validator genesis with `chain_id = 31337` — Hardhat-style devnet ID, distinct from `local_genesis.json`'s 1337 and from any plausible mainnet).
- Doc header explicitly: "**NOT production-like. NOT fault-tolerant.**" — single-validator outage halts block production.
- Verified by real smoke test (see §verification below). Block height advances 1→4 in 6s at 2s blocks.

Note: an early version pointed at `genesis/local_genesis.json`, which has 3 validators. With only one container running, PoA round-robin can't make progress through heights assigned to the absent validators. The shipped preset uses a single-validator genesis instead.

### 2. SNIP-V2 RPC cheatsheet
**Status: SHIPPED.** [SNIP-V2-RPC-CHEATSHEET.md](../rpc/SNIP-V2-RPC-CHEATSHEET.md).

Top-of-doc "Important behaviors that have bitten people" covers:
- `SignedTransaction::hash()` is the receipt key, NOT `signing_hash()` — with the wrong-vs-right code example.
- `assigned_count: Option<u32>` is JSON `null` for files above `MAX_ASSIGNED_COUNT_CHUNK_COUNT` (16,384 chunks); clients compute locally via `assigned_archives_presorted` — recipe + pointer to plan Appendix C conformance vectors.
- Mainnet integration is read-only unless separately approved (V2 not live on mainnet).

Plus tx submission shape, finality polling pattern, full file-lifecycle ASCII diagram, stable paginated coverage polling, RPC reference, receipt-code table (22, 30–35), and a smoke-test snippet.

### 3. `chain_getChainParams` RPC
**Status: SHIPPED.** Method on [crates/rpc/src/api.rs](../../crates/rpc/src/api.rs); server impl reads from the live `self.chain_params` plumbed into `RpcServer` during Phase 1b — explicitly **not** `ChainParams::default()`, with an inline comment locking that contract.

- New `ChainParamsInfo` wire type at [crates/rpc/src/types.rs](../../crates/rpc/src/types.rs) — flat JSON, no nested `staking`/`messaging`/`docclass`.
- Two JSON-shape tests (`chain_params_info_json_shape` + `chain_params_info_round_trip`).
- Smoke-tested end-to-end: returns live values from a running node, including all six SNIP V2 params.

---

## Deferred: hosted testnet (Phase 2.x — when capacity arrives)

The deploy artifacts are now correct, so a hosted testnet becomes a reasonable next step the moment ops has machines and budget. The deferred path:

1. **2-validator testnet on the 2 available machines** (when "available" means "available for 24/7 chain use," which they aren't right now).
   - Use [statefulset-validator-1.yaml](../../deploy/kubernetes/statefulset-validator-1.yaml) and [-2.yaml](../../deploy/kubernetes/statefulset-validator-2.yaml). Drop -3.
   - **Liveness caveat**: PoA round-robin with 2 validators stalls every other block if one is down (vs every third with 3 validators). The chain doesn't fork or corrupt — it just freezes until the missing proposer returns. SNIP testing is interrupted, not destroyed.
   - For a testnet that's tolerable. For mainnet it would not be — argues for ≥3 validators on mainnet whenever it ships.
2. **Cloudflare-fronted hostname** + IP rate-limit (Decision #2 from v2 of this doc) when there's a domain to point at.
3. **A fresh `snip-testnet-genesis.json`** generated at deploy time (Decision #3 from v2).

None of this is in scope for closing Phase 2 right now.

---

## Mainnet V2 testing (separate track — not Phase 2)

If "mainnet testing only" is the path eventually taken, that's not a Phase 2 close — it's a separate, larger initiative:

1. **V2 chain upgrade**: deploy V2 schemas + RPCs to mainnet. Either:
   - A scheduled hard fork (V1 nodes stop accepting V2-shaped txs at a known height; V2 nodes accept both). Requires governance ratification.
   - A soft activation (V2 ops exist on chain but no policy enforces them until a future flag flip). Less risky but still needs all validators to upgrade.
2. **SNIP integration on mainnet**: real-Koppa file deposits, real-Koppa fees, real PoR slashing risk to archive nodes. Substantially higher stakes than testnet integration.
3. **Operational readiness**: monitoring, runbooks, on-call rotation, archive-node operator coordination. None exist today for V2 specifically.

This is a separate track with its own plan, scope, and timeline. **Not a Phase 2 deliverable.** Flagging it here so it doesn't accidentally get folded into the Phase 2 close.

---

## What's actually in the repo (unchanged from v2 of this doc — reference)

The v2 doc's status table (CLI fixes, config keys, validator-key handling, etc.) is now historical — the deploy-fix patches landed in this round addressed all the bugs it described. Current state:

- [docker-compose.yaml](../../docker-compose.yaml) — 3-validator + fullnode + Prometheus/Grafana, all CLI/path issues fixed.
- [deploy/kubernetes/statefulset.yaml](../../deploy/kubernetes/statefulset.yaml) — deprecated 3-replica layout, retained as reference, CLI fixed.
- [deploy/kubernetes/statefulset-validator-{1,2,3}.yaml](../../deploy/kubernetes/statefulset-validator-1.yaml) — per-validator split (use 1+2 only on a 2-machine deploy).
- [deploy/kubernetes/configmap.yaml](../../deploy/kubernetes/configmap.yaml) — schema-valid TOML against `crates/node/src/config.rs`.
- [Dockerfile](../../Dockerfile) — toolchain pinned to 1.85, curl present, CMD uses `run` subcommand.

All YAML parses cleanly. All chain-side tests pass: `cargo test -p sumchain-state --lib` → 63, `cargo test -p sumchain-rpc --lib` → **44** (Phase 2 added 2 ChainParamsInfo JSON-shape tests), `cargo test -p sumchain-integration-tests --lib` → 45. `cargo check --workspace` → clean.

---

## Verification (real smoke test, not just YAML validation)

Built the binary natively (`cargo build --bin sumchain`), ran with the preset's exact CLI args + the new single-validator genesis, curled the live RPC:

```
chain_id                                       → 31337
chain_getChainParams                           → live ChainParamsInfo with V2 fields
chain_getBlockHeight (latest, t0)              → height: 1
chain_getBlockHeight (latest, t+6s)            → height: 4   (advancing at 2s/block)
chain_getBlockHeight (finalized)               → height: 1   (= 4 − finality_depth=3)
sumchain_consensus::poa producer log           → "Created block ... at height 4"
```

The smoke test caught a real issue along the way: an earlier preset pointed at the 3-validator `local_genesis.json`, but PoA round-robin needs every validator in the set to actively produce. Block height stuck at 0 until the preset was switched to the single-validator `snip-mirror-genesis.json`. SNIP would have hit this on first run; the smoke test caught it first.

---

## Deferred — explicitly NOT in Phase 2

These are real future work tracks, called out so they don't get accidentally folded into Phase 2's closeout:

- **Hosted testnet → Phase 2.x.** When ops has machines + budget, the now-correct deploy artifacts ([statefulset-validator-{1,2,3}.yaml](../../deploy/kubernetes), Cloudflare-fronted hostname, fresh `snip-testnet-genesis.json`) become a turn-key affair. With the established constraint of 2 machines, recommended layout is `statefulset-validator-1.yaml + -2.yaml` only (skip -3) — with the explicit caveat that 2-validator PoA stalls every other block on a single-validator outage.
- **Mainnet V2 testing → separate track.** Requires a chain upgrade (hard fork or soft activation), real-Koppa stakes for SNIP integration, and operational readiness work (monitoring, runbooks, on-call, archive-node operator coordination). Out of Phase 2 scope; will need its own plan, governance ratification, and timeline. SNIP integration on mainnet is **read-only** until that lands.

---

## Phase 2 closed

All deliverables shipped. SNIP can run a full V2-aware chain locally today via `docker-compose -f deploy/snip-local-mirror.yaml up -d --build`, integrate against the documented RPC contracts via [SNIP-V2-RPC-CHEATSHEET.md](../rpc/SNIP-V2-RPC-CHEATSHEET.md), and pin chain values via `chain_getChainParams` rather than baking in defaults.

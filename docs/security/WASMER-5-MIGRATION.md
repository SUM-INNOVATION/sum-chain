# Wasmer 4.4 → 5.0.6 migration (issue #203)

Coordinated migration of the consensus WASM execution engine from Wasmer 4.4 to
**5.0.6**, resolving RustSec **RUSTSEC-2026-0235** (rkyv 0.7 OOB read) and treated
as a **hard mainnet-release blocker**, not an ordinary dependency bump.

Contract execution stays **dormant** throughout: production genesis keeps
`contracts_enabled_from_height = None`, and this migration does not change that.

## Why 5.0.6 and not 7.x — the licensing constraint

#203 originally scoped a bump to Wasmer 7. Investigation found that **Wasmer
relicensed the Singlepass compiler from MIT to Business Source License 1.1
(BUSL-1.1) starting at v6.0.0**:

| Crate | ≤ 5.0.6 | ≥ 6.0.0 |
|---|---|---|
| `wasmer`, `wasmer-compiler`, `wasmer-types`, `wasmer-vm` | MIT | MIT |
| **`wasmer-compiler-singlepass`** (the deterministic backend consensus needs) | **MIT** | **BUSL-1.1** |

BUSL-1.1 **Additional Use Grant**: *production use requires being a Wasmer Sponsor
(or an entity within a Sponsor's network).* **Change Date**: four years after each
version's publication, then it converts to **MPL-2.0**. BUSL is source-available,
not permissive, so `cargo deny` correctly rejects it (`unlicensed`) and it is not
on the license allow-list.

**5.0.6 is the last MIT Singlepass release**, and — critically — it **still fixes
the security advisory**: `wasmer-compiler` 5.0.0 already depends on `rkyv ^0.8.8`,
which resolves to **rkyv 0.8.18** (≥ 0.8.17, the fixed version). So 5.0.6 achieves
the true #203 goal (clear RUSTSEC-2026-0235) while keeping the engine MIT and
avoiding the BUSL production-use restriction entirely.

The owner ratified this path over accepting BUSL / sponsoring Wasmer / switching
to the optimizing Cranelift backend (which would require re-proving determinism).

The version is pinned **exactly** (`=5.0.6`) in the workspace `Cargo.toml` so a
routine bump cannot cross into a BUSL 6.x release; the license allow-list (no BUSL
entry) is the backstop.

## What changed

| Area | Before | After |
|---|---|---|
| `wasmer`, `wasmer-compiler-singlepass` | `4.2` (`4.4.0` locked) | `=5.0.6` |
| `rkyv` (transitive, wasmer-internal) | `0.7.46` (vulnerable) | `0.8.18` (≥ 0.8.17, fixed) |
| Workspace MSRV | `1.88.0` | **`1.88.0` (unchanged)** — 5.0.6 MSRV is 1.81 |
| License of the WASM backend | MIT | **MIT** (unchanged; explicitly NOT BUSL) |

**No MSRV bump** and **no toolchain churn**: 5.0.6 requires only Rust 1.81, well
below the workspace's 1.88. The frozen b0-pre tools (1.85-pinned, workspace-
excluded) are untouched.

## API port

The Store/Module/Instance/FunctionEnv/imports/Memory context API is materially the
same as 4.x. One structural improvement is retained from the engine work: the
executor holds the `Engine` (Send+Sync) and clones a fresh, short-lived `Store`
inside each **synchronous** deploy/call rather than holding one long-term. This
keeps `ContractExecutor` `Send`, is behavior-neutral (each call already built a
fresh `Instance`, and the determinism golden is byte-identical), and is defensive
against future engine versions whose `Store` is `!Send`.

## Consensus-equivalence gates (executable)

All gates run in the normal `cargo test` path and CI.

1. **Old-vs-new determinism vectors** —
   `crates/sumc-runtime/tests/wasmer_determinism_vectors.rs`. A fixed WASM corpus
   is captured on the **pre-migration 4.4** engine as an ordered golden of the
   consensus-visible surface — per case: `(phase, success, gas_used, return-bytes,
   outcome CLASSIFICATION, sorted state-transition journal)`. After the bump, the
   **same test reproduces the golden byte-for-byte**. Covered: storage write
   (state transition), absent read, normal return bytes, three traps (unreachable
   / div-by-zero / OOB memory → `revert`, gas = call-base, empty journal), and
   `MethodNotFound`. Any divergence in state, gas, returns, traps, or error
   classification fails the build — a consensus-visible engine change to
   **escalate**, never to silently re-bless. Golden values are engine-/arch-
   independent by construction, so both CI arches assert the identical golden.
   *(Deferred to a cost/depth-tuned follow-up: OutOfGas via host-call exhaustion
   and StackOverflow via deep recursion — gas here is app-level, so pure-compute
   loops are unmetered and native stack-trap depth is engine-config-dependent.)*

2. **Persisted-state compatibility** —
   `contract_storage_persistence::storage_survives_restart` deploys, writes state,
   drops the executor, **reopens the database, builds a fresh executor**, and reads
   the state back. Contract code/metadata persist via serde/bincode (engine-
   independent); the golden additionally pins the exact `(cf_kind, key)` of every
   committed mutation.

3. **Rollback / reorg** — `sumchain-state`'s `contract_reorg_and_root.rs` and
   `contract_activation_gate.rs` exercise contract state rollback across reorgs and
   the dormant activation gate.

4. **Mixed-version refusal** —
   `crates/sumc-runtime/tests/engine_version_guard.rs` +
   `sumc_runtime::{ENGINE_IDENTITY, verify_engine}`. `ENGINE_IDENTITY` moves from
   `wasmer-singlepass-4` to `wasmer-singlepass-5`. `verify_engine(expected)`
   refuses (`RuntimeError::EngineVersionMismatch`) when the caller's expected
   identity differs from this binary's. Node-local mechanism; see the open
   decision below.

## Cross-platform CI

Runtime targets are Linux x86_64 and Linux aarch64 — both existing CI lanes.
Windows is intentionally not a target (validators run Linux).

## Open decision deferred to owner ratification (NOT implemented here)

**Network-wide engine-version enforcement.** `verify_engine` is a node-local
guard. Binding `expected` to a network-agreed value — a ratified
`ChainParams`/genesis field so every validator enforces the same engine identity
before contracts activate — is a **consensus-policy decision** and is intentionally
not wired into `ChainParams`/wire here, consistent with keeping execution dormant
and not inventing consensus policy.

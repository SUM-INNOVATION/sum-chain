# Wasmer 4.x → 7.4 migration (issue #203)

Coordinated migration of the consensus WASM execution engine from Wasmer 4.4 to
7.4, resolving RustSec **RUSTSEC-2026-0235** (rkyv 0.7 OOB read) and treated as a
**hard mainnet-release blocker**, not an ordinary dependency bump.

Contract execution stays **dormant** throughout: production genesis keeps
`contracts_enabled_from_height = None`, and this migration does not change that.
The migration is gated by executable equivalence/compatibility tests that must
pass before contracts are ever activated.

## What changed

| Area | Before | After |
|---|---|---|
| `wasmer`, `wasmer-compiler-singlepass` | `4.2` (`4.4.0` locked) | `7.4` (`7.4.0` locked) |
| `rkyv` (transitive, wasmer-internal) | `0.7.46` (vulnerable) | `0.8.18` (≥ 0.8.17, fixed) |
| Workspace MSRV (`rust-toolchain.toml`) | `1.88.0` | `1.95.0` |
| Frozen b0-pre tools | `1.85.0` (pinned in `b0-pre.yml`) | `1.85.0` (**unchanged**; workspace-excluded) |
| Public embedding API in `sumc-runtime` | `Store::new(Singlepass)` | `Store::new(EngineBuilder::new(Singlepass).engine().into())` |

The API delta is **one line**. Wasmer 7's multi-backend refactor means a compiler
config no longer converts directly into an `Engine`; it goes through the sys
`EngineBuilder`. The context API used everywhere else in the executor
(`FunctionEnv`/`FunctionEnvMut`, `Function::new_typed_with_env`, `imports!`,
`Memory::view(...).read/write`, `get_typed_function`, `TypedFunction::call`,
`RuntimeError`) is unchanged from 4.x to 7.4. The **Singlepass** backend is
retained (deterministic, no optimizing-compiler nondeterminism).

## MSRV 1.95 transition evidence

- Wasmer/`wasmer-compiler-singlepass` **7.3+ declare `rust-version = 1.95`**
  (verified from the crates.io index; 7.2 needed 1.93, 7.1 needed 1.91). 7.4 is
  the first line that pairs the rkyv-0.8 fix with a released, installable MSRV.
- `rust-toolchain.toml` is the **single source of truth**: `rust-ci.yml` installs
  the pinned channel from it (no hardcoded version in the workflow), so this bump
  propagates to both CI lanes automatically.
- The **frozen b0-pre measurement toolchain is untouched**. Those tools are
  workspace-excluded (`exclude = ["tools"]`) and pinned to 1.85 via
  `RUSTUP_TOOLCHAIN` in `b0-pre.yml`; the workspace MSRV bump does not reach them.
- Full workspace builds and tests under 1.95 (see gates below).

## Consensus-equivalence gates (executable)

All gates run in the normal `cargo test` path and CI.

1. **Old-vs-new determinism vectors** —
   `crates/sumc-runtime/tests/wasmer_determinism_vectors.rs`.
   A fixed WASM corpus is captured on the **pre-migration 4.4** engine as an
   ordered golden of the consensus-visible surface — per case: `(phase, success,
   gas_used, return-bytes, outcome CLASSIFICATION, sorted state-transition
   journal)`. After the bump, the **same test on 7.4 reproduces the golden
   byte-for-byte**. Covered classes: storage write (state transition), absent
   read, normal return bytes, three traps (unreachable / div-by-zero / OOB
   memory → `revert`, gas = call-base, empty journal), and `MethodNotFound`.
   Any divergence in state, gas, returns, traps, or error classification fails
   the build — a consensus-visible engine change to **escalate**, never to
   silently re-bless. The golden values are engine-/arch-independent by
   construction (app-metered gas, program-deterministic returns, semantic trap
   classes, cf+key journal), so both CI arches assert the identical golden.
   *(Deferred to a cost/depth-tuned follow-up: OutOfGas via host-call exhaustion
   and StackOverflow via deep recursion — gas here is app-level, so pure-compute
   loops are unmetered and native stack-trap depth is engine-config-dependent.)*

2. **Persisted-state compatibility** —
   `contract_storage_persistence.rs::storage_survives_restart` deploys, writes
   state, drops the executor, **reopens the database, builds a fresh executor**,
   and reads the state back — all under 7.4. Contract code and metadata persist
   via serde/bincode (engine-independent); the determinism golden additionally
   pins the exact `(cf_kind, key)` of every committed mutation.

3. **Rollback / reorg** — `sumchain-state`'s `contract_reorg_and_root.rs` and
   `contract_activation_gate.rs` exercise contract state rollback across reorgs
   and the dormant activation gate; the entire `sumchain-state` suite (191 lib +
   integration tests) passes under 7.4.

4. **Mixed-version refusal** —
   `crates/sumc-runtime/tests/engine_version_guard.rs` +
   `sumc_runtime::{ENGINE_IDENTITY, verify_engine}`.
   `ENGINE_IDENTITY` moves from `wasmer-singlepass-4` to `wasmer-singlepass-7`.
   `verify_engine(expected)` refuses (`RuntimeError::EngineVersionMismatch`) when
   the caller's expected identity differs from this binary's. This is the
   node-local **mechanism**; see the open decision below for the network binding.

## Cross-platform CI

The runtime targets are Linux x86_64 and Linux aarch64 — both already CI lanes
(`build-test-clippy`, `build-test-clippy-aarch64`), both now on 1.95 via
`rust-toolchain.toml`. **Windows is intentionally not a target**: Wasmer 7 drops
Windows support for the Sys (compilers) backend, and validators do not run on
Windows.

## Open decision deferred to owner ratification (NOT implemented here)

**Network-wide engine-version enforcement.** `verify_engine` is a node-local
guard. Binding `expected` to a *network-agreed* value — so every validator
enforces the same engine identity before contracts activate, and a divergent
node halts instead of forking — requires a **consensus-policy decision**: where
the canonical engine identity lives (e.g. a ratified `ChainParams`/genesis field)
and how it is upgraded. That is intentionally **not** wired into `ChainParams`
or the wire format here, consistent with keeping execution dormant and not
inventing consensus policy. The determinism golden already proves 4.4 ≡ 7.4 for
the covered corpus, so the specific 4→7 transition is safe; the genesis binding
is the general, future-proof enforcement and is left for ratification.

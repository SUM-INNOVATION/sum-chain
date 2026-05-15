# OmniNode `InferenceAttestation` — Activation Readiness

Chain-side readiness package for any future devnet/mainnet decision to enable the OmniNode `InferenceAttestation` subprotocol. **This document does not set or propose an activation height for any environment.** It records what has shipped, what must be verified before any environment is activated, and the procedure / rollback / monitoring shape an operator should expect to follow.

For the frozen v1 protocol contract (wire format, dispatch behavior, RPC surface, status semantics), see [`INFERENCE-ATTESTATION.md`](INFERENCE-ATTESTATION.md). This doc is operational; that one is the contract.

## Current status (2026-05-14)

- InferenceAttestation v1 merged to `main` (PR [#1](https://github.com/SUM-INNOVATION/sum-chain/pull/1), merge commit `5a8548b6`).
- `chain_getChainParams.omninode_enabled_from_height` merged to `main` (PR [#2](https://github.com/SUM-INNOVATION/sum-chain/pull/2), merge commit `d83e45a4`).
- Local mirror branch `snip-local-mirror-omninode` is activated from genesis with `omninode_enabled_from_height: 0`.
- OmniNode Stage 7b live validation passed on the activated local mirror.
- OmniNode Stage 5.2 staleness/retry work is client-local and requires no SUM Chain change.
- Production / mainnet default: `omninode_enabled_from_height: None` (dormant). No environment has an activation height set.

## Explicit non-goals

- No mainnet (or any other environment) activation height is proposed in this document.
- No new tx status; the 4-state status model (`submitted` / `included` / `finalized` / `unknown`) is not expanded. In particular, no `Dropped` state.
- No tx wire format change, no executor behavior change, no mempool behavior change, no RPC method addition or signature change.

## Pre-activation gates

Before any environment is activated, every item below must be checked. The list is ordered roughly from "easiest to verify" to "needs human sign-off."

1. **CI green on `main` at the candidate validator-binary commit.** Workspace build, clippy, fmt, and the full test suite must be green.
2. **Validator binaries confirmed at or after `d83e45a4`** on every validator in the target environment. PR #2 introduced the `chain_getChainParams` field that the adapter relies on; a validator running PR #1 only would underreport chain params to clients.
3. **`chain_getChainParams.omninode_enabled_from_height` reachable** from the target environment's RPC endpoint and reporting the expected pre-activation value (`null` when disabled).
4. **OmniNode adapter pinned to a known-tested SUM Chain revision:**
   - `d83e45a4` for full adapter / RPC alignment (includes both the wire-format types and `chain_getChainParams.omninode_enabled_from_height`).
   - `5a8548b6` is sufficient **only** for `sumchain-primitives` wire-type vendoring (the RPC field from PR #2 is not yet present at that rev).
5. **OmniNode Stage 5.2 client-local retry / staleness work shipped and verified** on the adapter side.
6. **Target-environment smoke test passed** against the deployed binaries:
   - `chain_getChainParams` returns the expected `omninode_enabled_from_height` value.
   - At least one happy-path attestation tx flows `submitted` → `included` → `finalized` via `sum_getInferenceAttestationStatus`.
   - One duplicate `(session_id, verifier_address)` submission is rejected at mempool admission with `DuplicateInferenceAttestation` (no receipt, no fee).
7. **Eng director sign-off + validator ops sign-off** recorded against the candidate binary commit and the proposed activation height.

## Local-mirror verification record

| Field | Value |
|---|---|
| Branch | `snip-local-mirror-omninode` |
| Tip SHA | `b586ff3f96e3f6f1a97d051910166d6b68b7100d` |
| `chain_id` | `31337` |
| `omninode_enabled_from_height` | `0` |
| OmniNode Stage 7b live validation | passed |

The local-mirror preset is the only environment in which OmniNode is currently active. It is a disposable single-validator devnet; nothing about its passing state implies readiness for any other environment.

## Future activation procedure

Generic template — no environment-specific values are filled in.

1. **Build and deploy the validator binary** built from the candidate `main` commit (at or after `d83e45a4`) to every validator in the target environment.
2. **Verify every validator** reports the same commit (via the binary's version endpoint) and reports the expected pre-activation chain params via `chain_getChainParams`. Do not proceed if any validator is behind.
3. **Choose a future activation height `H`.** `H` must be strictly greater than every validator's current head, with enough lead time for the chain-params overlay change to propagate through that environment's params-update mechanism and for clients to update.
4. **Apply the chain-params overlay** setting `omninode_enabled_from_height: H` to every validator's genesis/params source per the environment's params-update mechanism. Confirm the value via `chain_getChainParams` from each validator.
5. **Restart validators** if required by that environment's params-update mechanism.
6. **From block `H` onward, monitor** the metrics listed in [Post-activation monitoring](#post-activation-monitoring).

This procedure assumes the environment's params-update mechanism already exists. Defining or modifying that mechanism is out of scope here.

## Rollback / abort guidance

Two distinct cases, and they behave very differently.

**Case A — before height `H` is finalized.** Remove `omninode_enabled_from_height` from the params overlay (or set it to a later height) and propagate the change as in step 4 above. No state has been written to `INFERENCE_ATTESTATIONS`, no fees collected, no nonces advanced. The abort is effectively free.

**Case B — after height `H` is finalized and at least one attestation has been accepted.** Accepted attestations cannot be retroactively erased: `INFERENCE_ATTESTATIONS` rows are part of chain state, and the associated fee deductions / nonce increments are part of the finalized history. Disabling **future** admission would require an operational decision:

- The current chain has no built-in "deactivate" gate — `omninode_enabled_from_height` enables activation but is not consulted after the point of activation by every code path. Verify the runtime behavior in the target binary before relying on a "set to far-future height" rollback.
- Adding a clean deactivation gate (or a per-height "deny new submissions" semantic) would be a new protocol change, not covered by this readiness package.

For any post-activation incident severe enough that admission must stop, the immediate lever is operational (validator-side rate-limit, RPC-layer drop, or coordinated binary downgrade), not protocol.

## Post-activation monitoring

Recommended metrics. Reasonable starting points; tune thresholds against observed baseline.

- **Status counters via `sum_getInferenceAttestationStatus`** over a rolling window:
  - `submitted`: in flight in mempool
  - `included`: in a block but not yet finalized
  - `finalized`: at or past `chain_getChainParams.finality_depth`
  - `unknown`: no receipt and not in mempool (evicted, never seen, or non-OmniNode tx hash submitted by mistake)
- **Executor failure-code counters** (per the protocol doc's §"Failure codes"):
  - `Failed(50)` (pre-activation) — should be `0` after activation. Non-zero means a tx slipped past admission, which would be a bug.
  - `Failed(51)` (duplicate `(session_id, verifier)`) — should track the expected duplicate rate; spikes indicate client-side retry storms or an OmniNode-side bug.
  - `Failed(52)` (invalid inner signature) — should be `0` on healthy clients; non-zero indicates client signing-key drift or a malformed adapter.
  - `Failed(53)` (sender/verifier mismatch) — should be `0` by construction (caught by outer validation); non-zero is a bug.
- **Mempool admission duplicate rejection rate** (`StateError::DuplicateInferenceAttestation`).
- **Column family size and growth:** `INFERENCE_ATTESTATIONS` and `INFERENCE_ATTESTATIONS_BY_SESSION`.
- **RPC error rate** on the three read-only OmniNode methods: `sum_getInferenceAttestation`, `sum_listInferenceAttestations`, `sum_getInferenceAttestationStatus`.
- **OmniNode adapter retry / error logs** (client side). Pair with chain-side status counters to distinguish "client gave up too early" from "chain dropped the tx."

## References

- Protocol contract: [`INFERENCE-ATTESTATION.md`](INFERENCE-ATTESTATION.md)
- Wire format + executor + mempool + RPC: PR [#1](https://github.com/SUM-INNOVATION/sum-chain/pull/1) (merge `5a8548b6`)
- `chain_getChainParams.omninode_enabled_from_height`: PR [#2](https://github.com/SUM-INNOVATION/sum-chain/pull/2) (merge `d83e45a4`)
- Local-mirror activation: branch `snip-local-mirror-omninode` tip `b586ff3f`
- Activation gate source of truth: [`crates/genesis/src/lib.rs:137`](../../crates/genesis/src/lib.rs#L137)
- Wire-shape source of truth: [`crates/rpc/src/types.rs`](../../crates/rpc/src/types.rs) (`ChainParamsInfo.omninode_enabled_from_height`)

# SRC-817/818 Education — Activation Readiness

Chain-side readiness package for any future decision to activate the
SRC-817 Course Catalog / SRC-818 Course Offering education suite on a
live network. **This document sets no activation height and edits no
runtime genesis.** It records what shipped, the gates that must pass
(education adds *hard legal/privacy gates* beyond the OmniNode model),
the production runtime-genesis procedure, the per-validator verification
checklist, rollback, and post-activation monitoring.

Companion contract: read [`SRC-81X-EDUCATION-VALIDATION.md`](../SRC-81X-EDUCATION-VALIDATION.md)
(dev runbook) and the Phase 0 specs ([`SRC-817.md`](../SRC-817.md),
[`SRC-818.md`](../SRC-818.md), [`SRC-81X-EDUCATION-SUITE.md`](../SRC-81X-EDUCATION-SUITE.md)).

## Current status (2026-05-18)

- Phases 0–5 merged to `main`: specs (PRs #5–#7), wire types (#8),
  storage/executor/activation gate + Policy B (#9), mempool admission
  (#10), read-only RPC (#11), local/dev e2e validation (#12).
- `chain_getChainParams` exposes `education_enabled_from_height`
  (added by this phase) so activation state is **directly verifiable**
  per validator — not inferred.
- **Mainnet/testnet dormant.** No runtime `genesis.json` carries
  `education_enabled_from_height` → `#[serde(default)] → None` →
  education txs rejected (`EducationNotActivated` at admission /
  `Failed(70)` at executor). No height chosen.

## Explicit non-goals (this phase)

- No activation height chosen or scheduled.
- No edit to any validator's runtime `genesis.json`.
- No mainnet/testnet activation.
- No wire / fee-nonce / executor / mempool / CF / RPC-write change.
  (The only code change is the additive read-only `ChainParamsInfo`
  field above.)

## Deployment model — read this first

**Production validators boot from the root runtime `genesis.json` on
each validator host. `genesis/mainnet_genesis.json` is a placeholder
TEMPLATE and is NOT used in production** (it now carries a `_comment`
banner saying so). Any activation edit applies to **each validator's
runtime `genesis.json`**, and those files must end **byte-identical**.

## Pre-activation gates

All must pass, in writing, before any height is proposed. Education's
legal/privacy gates are **hard blockers** (stricter than OmniNode).

### A. Code gates
- [ ] Activation-candidate commit identified; CI green on it.
- [ ] Both validators run binaries built from **that exact commit**
      (commit hash recorded per validator).

### B. Dev-validation gates
- [ ] Phase 5 e2e green on the candidate:
      `cargo test -p sumchain-integration-tests education`.
- [ ] Dev runbook ([`SRC-81X-EDUCATION-VALIDATION.md`](../SRC-81X-EDUCATION-VALIDATION.md))
      executed against an education-enabled dev node.

### C. Legal / privacy gates (HARD — activation blocked until signed)
- [ ] **FERPA / privacy sign-off** recorded (named approver + date).
- [ ] No raw student-address indexing — evidenced by the Phase 5
      raw-CF scan (no 20-byte student-address pattern in any `edu_*`
      key/value).
- [ ] No raw grades / submissions / answer keys / PII on-chain **or**
      in any RPC response (commitments + SNIP refs + institutional
      base58 only; students only as `student_commitment`).
- [ ] **Retention / erasure policy** accepted (how SNIP-side coursework
      is retained/erased; on-chain holds only commitments/receipts).
- [ ] **Sponsor/institution `tx.from` model** accepted (the public
      sender is the sponsor/relayer/LMS service account, never the
      student; student pays nothing).
- [ ] **SNIP access-policy enforcement smoke** passed (access policies
      on `ManagedSnipRef`s enforced by the SNIP layer; no plaintext or
      decryption material on-chain/RPC).

### D. Product / operator gates
- [ ] ≥1 registered SRC-81X institution / sponsor operationally ready.
- [ ] LMS adapter ready (submits via sponsor `tx.from`).
- [ ] SNIP content/access workflow verified end to end.
- [ ] RPC / explorer / SDK consumers notified of the new
      `src817_*`/`src818_*` reads + `chain_getChainParams` field.
- [ ] Rollback plan reviewed (before-H and after-H, below).

### E. Ops gates
- [ ] Both validators enumerated; coordinated maintenance window
      scheduled (avoid weekends/off-hours).
- [ ] Runtime-`genesis.json` byte-identical procedure rehearsed on a
      dev node.

## Dev verification record

| Item | Value |
|---|---|
| Phase 5 e2e | `cargo test -p sumchain-integration-tests education` → 4 passed |
| Privacy CF scan | no raw student-address pattern in any `edu_*` CF key/value |
| Policy B | sponsor pays Σfees; semantic failure still charged; student never charged |
| Phase 3 admission | committed-dup → `DuplicateEducationRecord`; ineligible → `InvalidEducationTransaction` |
| RPC reads | all 12 `src817_*`/`src818_*` paths verified (present/missing/bounded) |

## Future activation procedure (documented; NOT executed here)

Only after a **separate written approval** that chooses a height `H`:

1. Confirm both validators run the approved candidate binary commit.
2. On **each** validator, edit the **root runtime `genesis.json`**
   `params` to add exactly: `"education_enabled_from_height": <H>`.
   (Do **not** edit `genesis/mainnet_genesis.json` — it is a template.)
3. On **each** validator: `sha256sum genesis.json`. The hashes **must
   be byte-identical**. If they differ, **abort** — fix and re-compare
   before any restart.
4. Coordinated restart of **both** validators within one window.
5. Run the verification checklist below on **both** validators.
6. From block `H` onward, run post-activation monitoring.

**Choosing `H` (when later approved):** `H` strictly greater than the
current head with lead time for coordination + consumer updates;
ETA ≈ `(H − head) × block_time_ms / 1000` seconds (runtime
`block_time_ms = 3000`); schedule the crossing in-hours, not
weekends/off-hours.

## Per-validator verification checklist

Run on **every** validator. `RPC` = `curl -s -XPOST -H 'content-type:
application/json' localhost:8545 -d '{"jsonrpc":"2.0","id":1,"method":"<m>","params":[]}'`.

| Check | Command | Expected |
|---|---|---|
| Binary/commit identity | `sumchain --version` + recorded git commit | identical on both; = approved candidate |
| Runtime genesis hash | `sha256sum genesis.json` | **byte-identical across both validators** |
| Activation param | `RPC chain_getChainParams` → `.education_enabled_from_height` | `null` pre-activation; `<H>` after the runtime-genesis edit + restart |
| Latest height | `RPC chain_getBlockHeight` (latest) | advancing on both |
| Finalized height | `RPC chain_getBlockHeight` (finalized) | lagging latest by `finality_depth = 6` |
| Block production post-restart | observe height across both | new blocks within ~`block_time_ms` |
| Pre-H behavior | dev probe education tx | rejected `EducationNotActivated`/`Failed(70)` while head < H |
| Post-H behavior | dev probe education tx at/after H | admitted / `Success` |

## Rollback / abort guidance

- **Before block `H` is finalized:** revert the `genesis.json` edit on
  **both** validators (back to the byte-identical no-key form),
  re-`sha256` compare, coordinated restart. No education state exists →
  clean abort.
- **After `H` + the first education tx is finalized:** education CFs
  hold committed records (catalog/offering/receipt/grade commitments);
  these **cannot be un-written**. There is **no in-protocol
  "deactivate"**. Stopping further education activity is an operational
  action (deploy a re-gated binary, or a coordinated halt + decision).
  Plan the maintenance window accordingly; treat post-H as effectively
  one-way.

## Post-activation monitoring

- `chain_getChainParams.education_enabled_from_height` stays `<H>` and
  identical on all validators (config-drift alarm).
- Education tx mix: `Success` vs `Failed(70..=84)` rates; sustained
  `Failed(70)` post-H ⇒ a validator didn't pick up the edit.
- Mempool admission rejections: `EducationNotActivated` /
  `DuplicateEducationRecord` / `InvalidEducationTransaction` trends.
- Policy B sanity: sponsors (not students) bearing fees; nonce/fee
  advance on success and on charged semantic failures.
- Privacy invariant spot-check: periodic `edu_*` CF scan confirms no
  raw student-address pattern; RPC responses expose commitments/refs
  only.
- SNIP-side: access-policy enforcement + retention/erasure operating
  per the accepted policy.
- Block production / finality unaffected on both validators.

## References

- Specs: [`SRC-817.md`](../SRC-817.md), [`SRC-818.md`](../SRC-818.md),
  [`SRC-81X-EDUCATION-SUITE.md`](../SRC-81X-EDUCATION-SUITE.md)
- Dev runbook: [`SRC-81X-EDUCATION-VALIDATION.md`](../SRC-81X-EDUCATION-VALIDATION.md)
- Phase PRs: #5–#7 (specs), #8 (wire), #9 (storage/executor/Policy B),
  #10 (mempool admission), #11 (read-only RPC), #12 (dev e2e),
  this phase (activation readiness + `chain_getChainParams` field)
- Precedent: [`INFERENCE-ATTESTATION-ACTIVATION.md`](INFERENCE-ATTESTATION-ACTIVATION.md)
  (OmniNode model; education adds hard legal/privacy gates above it)

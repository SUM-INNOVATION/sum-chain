# SRC-817/818 Education Suite — Phase 5 Local/Dev Validation Runbook

> **Scope:** local/dev validation only. Education is enabled from
> genesis **only** in `genesis/local_genesis.json` and the local
> generator `scripts/src/setup_local_testnet.rs`. `mainnet_genesis.json`
> and `testnet_genesis.json` are **untouched** — production stays
> dormant (`education_enabled_from_height` defaults to `None`). This
> document does **not** propose any mainnet/testnet activation.

## 1. What Phase 5 validates

The automated end-to-end test
(`crates/integration-tests/src/education_e2e_tests.rs`) drives the full
SRC-817/818 stack through **real PoA block production** with the
education gate open, then asserts privacy, Policy B fee/nonce, Phase 3
mempool admission, executor-authoritativeness, and every Phase 4
read path. The live JSON-RPC socket path is the manual procedure in §4.

## 2. Activation (local/dev only)

- `genesis/local_genesis.json` → `params.education_enabled_from_height = 0`
  (beside `v2_enabled_from_height: 0`).
- `scripts/src/setup_local_testnet.rs` → `education_enabled_from_height: Some(0)`.
- Production-safe invariant (asserted by `genesis_activation_local_only`):
  `mainnet_genesis.json` / `testnet_genesis.json` contain **no**
  `education_enabled_from_height` key → `#[serde(default)]` resolves to
  `None` → dormant.

## 3. Automated validation — commands

Run with the pinned toolchain (`rust-toolchain.toml` = 1.85.0):

```
cargo test -p sumchain-integration-tests education
cargo test -p sumchain-rpc --lib
cargo test -p sumchain-state --test education_dispatch
cargo test -p sumchain-state --test education_mempool
cargo test -p sumchain-state --test inference_attestation_mempool
cargo test -p sumchain-primitives --test education_fixtures
cargo check --workspace
```

Expected: `education` → 4 e2e tests pass
(`education_full_e2e_flow_with_privacy_and_policy_b`,
`education_semantic_failure_is_charged_policy_b`,
`education_phase3_admission_and_executor_authoritative`,
`genesis_activation_local_only`); all regression suites green.

> **If you see `could not find native static library 'rocksdb'`:** the
> `librocksdb-sys` build cache was wiped (e.g. a disk cleanup). Run
> `cargo clean -p librocksdb-sys` then re-run. This is **not** a
> toolchain problem (1.85.0 is correct) and not unfixable.

## 4. Manual live-node validation (optional)

Boot a local node on the education-enabled genesis and query the Phase 4
read-only RPC over plain HTTP JSON-RPC (`localhost:8545`):

```
sumchain run --genesis genesis/local_genesis.json --data-dir /tmp/edu-dev --rpc-addr 0.0.0.0:8545
```

Submit the LMS flow with your tooling (`sum_sendRawTransaction` with
`TxPayload::Education` ops — sponsor/relayer signs `tx.from`, never the
student), then read back. All ids/commitments are `0x`+64-hex; the
`student_commitment` is the only student identifier.

```
curl -s -XPOST -H 'content-type: application/json' localhost:8545 \
  --data '{"jsonrpc":"2.0","id":1,"method":"src817_getCatalogEntry","params":["0x<catalog_id>"]}'
```

The 12 read methods to exercise (each returns hex/commitment/base58
only — never raw grade/submission/answer-key/PII/SNIP plaintext):

| Method | Params |
|---|---|
| `src817_getCatalogEntry` | `[catalog_id]` |
| `src817_getCatalogContent` | `[catalog_id]` |
| `src817_listCatalogsByInstitution` | `[institution_id, limit?]` |
| `src817_listCatalogsByCode` | `[department, course_code, limit?]` |
| `src818_getOffering` | `[offering_id]` |
| `src818_listOfferingsByCatalog` | `[catalog_id, limit?]` |
| `src818_listAssessments` | `[offering_id, limit?]` |
| `src818_getAssessment` | `[offering_id, assessment_id]` |
| `src818_getEnrollmentLink` | `[offering_id, student_commitment]` |
| `src818_getSubmissionReceipt` | `[offering_id, assessment_id, student_commitment, attempt]` |
| `src818_listSubmissionsByStudentCommitment` | `[student_commitment, limit?]` |
| `src818_getGradeRecord` | `[offering_id, assessment_id, student_commitment]` |

`limit` defaults to and is capped at `MAX_EDU_LIST_LIMIT = 256`.

## 5. Privacy checklist (asserted automatically)

- No raw 20-byte student-address pattern in **any** `edu_*` CF key or
  value (scan over all education CFs).
- Student appears only as a 32-byte `student_commitment`; `owner` /
  `submitter` / `grader` are sponsor/institution base58 addresses,
  distinct from the student.
- Submission is a **receipt** (`submission_commitment` + `ManagedSnipRef`)
  — coursework stays in SNIP; no work bytes on chain.
- No raw grade (commitment only), no answer-key plaintext (commitment
  only), no SNIP plaintext / decryption material in any response.

## 6. Policy / authority checklist (asserted automatically)

- **Policy B:** success → fee charged + nonce advanced; semantic
  failure after activation (e.g. duplicate catalog `Failed(81)`) →
  **still** fee charged + nonce advanced; pre-semantic
  (gate/malformed/insufficient) → free.
- **Sponsor pays, student never:** sponsor balance decreases by exactly
  Σ(success-tx fees); the student has no account and is never charged.
- **Phase 3 admission:** committed-duplicate → `DuplicateEducationRecord`;
  ineligible (not-enrolled) → `InvalidEducationTransaction`;
  non-education tx unaffected.
- **Executor authoritative:** a mempool without the admission ctx still
  has the executor reject a committed duplicate with `Failed(81)`.

## 7. Non-goals

No mainnet/testnet activation. No protocol wire / executor semantics /
fee-nonce / mempool / CF / RPC-write changes. No raw student-address
indexing. No SNIP plaintext exposure.

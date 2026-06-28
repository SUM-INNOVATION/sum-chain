# sumchain-wallet

Command-line wallet for SUM Chain — key management and transaction signing.
Native currency: Koppa (Ϙ).

## Purpose

A CLI tool for generating/storing keys and constructing, signing, and submitting
transactions against a SUM Chain node's RPC.

## Entry points

- `sumchain-wallet` binary (`cargo run -p sumchain-wallet -- …`).
- `keystore` — key storage/loading; `tx` — transaction build/sign/submit;
  `currency` — Koppa/base-unit conversion; `display` — output formatting.

## Not for

- Library/server use — this is an end-user CLI, not a stable embedding API. For
  programmatic access use `sumc-sdk` (Rust) or `sdk/typescript`.
- Custodial key management — keys are handled locally for developer/operator use.

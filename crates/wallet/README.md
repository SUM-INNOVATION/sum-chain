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

## Swarm roster (display only)

`--swarm-roster <FILE>` (a global option) names a file of accounts whose addresses the wallet prints in the agent form
`r0…` (#309), wherever it prints an account address: balances and transfers, transaction details and pending rows,
blocks and validators, NFT owners, creators, approvals and royalty recipients, contracts, delegators and their validators,
archive and storage accounts, NFT owner lookups, contract call results (the contract and each event's contract),
gas estimates, and messaging senders and contacts. Every other address prints as before. Public keys,
hashes, raw transactions and the addresses sent to the RPC are never rewritten.

- **Source:** the file is the roster's only source; the chain has no swarm registry yet.
- **Default:** without the option there is no roster, and every address prints in the plain form.
- **Format:** entries are separated by newlines, commas or whitespace, and `#` starts a comment. Each entry is a plain,
  `r0` or hex address. An entry that is not an address stops the wallet with an error naming its line.
- **Display only:** `r0` is a text form of the same address and grants nothing. The roster is read only when printing;
  no signature, fee, permission or consensus rule reads it. A transfer to `r0…` is byte-for-byte the transaction to the
  plain form (tested).
- **Input:** address arguments also accept the `r0` form, so a printed address can be pasted back.

## Not for

- Library/server use — this is an end-user CLI, not a stable embedding API. For
  programmatic access use `sumc-sdk` (Rust) or `sdk/typescript`.
- Custodial key management — keys are handled locally for developer/operator use.

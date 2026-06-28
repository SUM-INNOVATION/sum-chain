# sumchain-token

SRC-20: SUM Chain's native fungible token standard (similar to ERC-20).

## Purpose

Defines the on-chain types and transaction payloads for creating and managing
fungible tokens. Execution of these operations lives in the state executor; this
crate is the type/standard definition.

## Main modules

- `token` — `Token`, `TokenConfig`, `TokenId`, `TokenInfo`.
- `transaction` — `TokenOperation` / `TokenAction` / `TokenTxData` (the on-chain
  `TxPayload::Token`).
- `error` — `TokenError`, `Result`.

## Public interfaces

`Token`, `TokenConfig`, `TokenId`, `TokenInfo`, `TokenOperation`, `TokenAction`,
`TokenTxData`, `TokenError`.

User-facing usage (RPC reads, write flow) is documented in
[`docs/tokens.md`](../../docs/tokens.md).

## Not for

- NFTs / non-fungible assets — use `sumchain-nft` (SUM-721).
- Execution logic — see `sumchain-state`.

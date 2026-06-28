# sumchain-nft

SUM-721: SUM Chain's native NFT standard for certified documents and digital
assets (ERC-721-compatible, with issuer verification).

## Purpose

Defines on-chain types and transaction payloads for NFT collections, tokens,
metadata, and issuer registration. Execution lives in the state executor; this
crate is the type/standard definition.

## Main modules

- `collection` — `Collection`, `CollectionConfig`, `CollectionId`.
- `token` — `Token`, `TokenId`, `TokenUri`.
- `metadata` — token metadata types.
- `registry` — issuer registration (`RegisteredIssuer`, `IssuerStatus`,
  `IssuerOrgType`, `RegistryOperation`).
- `transaction` — `NftTransaction` / `NftAction` (the on-chain `TxPayload::Nft`).
- `error` — `NftError`, `Result`.

## Public interfaces

`Collection`, `Token`, metadata types, `RegisteredIssuer` and registry types,
`NftTransaction`/`NftAction`, `NftError`.

User-facing usage is documented in [`docs/tokens.md`](../../docs/tokens.md).

## Not for

- Fungible tokens — use `sumchain-token` (SRC-20).
- Execution logic — see `sumchain-state`.

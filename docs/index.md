# SUM Chain Documentation Index

Entry point for SUM Chain documentation. This index is the map; the canonical
"how do I actually use X" docs are linked first, deep specs and operational docs
below.

## Start here (canonical, code-verified)

- **[Token types & token families](./tokens.md)** — every token/token-family
  type, what's usable via public RPC today, and copy-paste `curl` examples.
- **[Policy accounts & contracts](./policy-accounts-and-contracts.md)** — what
  works, what is stubbed/partial, and why.
- **[RPC API reference](./api-reference.md)** — full JSON-RPC method list.

## Status legend

Every canonical doc and Status block uses this schema:

```
> Status:             code-backed | partial | spec-only | unavailable
> Last verified:      <date>
> Code references:    <file[:line] ...>
> Public RPC support: yes (<methods>) | no (<reason>)
```

- **code-backed** — types + executor + a wired RPC handler all exist.
- **partial** — some of {types, executor, RPC} exist; gaps called out.
- **spec-only** — design document; no corresponding code path.
- **unavailable** — declared but non-functional (e.g. stubbed handler).

## Mainnet activation gates

Read-only publication sanity check against the public endpoint
`https://rpc.sumchain.io` (`chain_getChainParams`), `chain_id: 1`, verified
2026-06-27. These are activation-gate values (stable), not the live chain head:

| Subprotocol gate | Mainnet value | Meaning |
|---|---|---|
| `v2_enabled_from_height` | `5200000` | V2 storage **active** |
| `omninode_enabled_from_height` | `6000000` | OmniNode inference attestation **active** |
| `education_enabled_from_height` | `null` | Education writes **dormant** (reads still work) |

Token / NFT / messaging / docclass / employment families have **no activation
gate** — they are always available when the node binary is running.

## Map of other docs

- **Architecture:** [bft-consensus](./bft-consensus.md) ·
  [bft-integration](./bft-integration.md) ·
  [security-overview](./security-overview.md) ·
  [economic-model](./economic-model.md) ·
  [performance-guide](./performance-guide.md)
- **Subprotocols:** [SUBPROTOCOLS/](./SUBPROTOCOLS/) (inference attestation,
  education activation)
- **Standards / specs (design depth):** the `docs/SRC-*.md` family +
  [SUM-721](./SUM-721.md). The canonical [tokens](./tokens.md) doc summarizes
  which of these are code-backed vs design-only.
- **Status / operational:** [production-checklist](./production-checklist.md) ·
  [policy-accounts-implementation-status](./policy-accounts-implementation-status.md)

> Several one-off documents at the repo root (academic-credentials, SUMallet,
> SUMail, web-wallet, SNIP-V2, SRC-81X guides) are integration handoffs or
> historical/design-only specs and may contain dated activation claims. Treat
> the canonical docs above as current truth.

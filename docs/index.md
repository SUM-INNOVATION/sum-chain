# SUM Chain Documentation Index

Entry point for SUM Chain documentation. This index is the map; the canonical
"how do I actually use X" docs are linked first, deep specs and operational docs
below.

## Start here (canonical usage docs)

- **[Token types & token families](./tokens.md)** — current public usage for
  every token/token-family type, with copy-paste `curl` examples.
- **[Policy accounts & contracts](./policy-accounts-and-contracts.md)** — current
  supported policy-account and contract usage.
- **[RPC API reference](./rpc/api-reference.md)** — full JSON-RPC method list.

## Status legend

Every canonical doc and Status block uses this schema:

```
> Status:             code-backed | spec-only | historical
> Last verified:      <date>
> Code references:    <file[:line] ...>
> Public RPC support: <current supported commands, or how writes are submitted>
```

- **code-backed** — current supported usage backed by types + executor + RPC.
- **spec-only** — design document; not a usage guide.
- **historical** — archived; superseded by a canonical usage doc above.

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

- **Architecture:** [bft-consensus](./architecture/bft-consensus.md) ·
  [bft-integration](./architecture/bft-integration.md) ·
  [security-overview](./architecture/security-overview.md) ·
  [economic-model](./architecture/economic-model.md) ·
  [performance-guide](./architecture/performance-guide.md)
- **Subprotocols:** [subprotocols/](./subprotocols/) (inference attestation,
  education activation)
- **Design specs (non-token):** [specs/](./specs/) (SNIP V2 storage plan;
  [Governance v1](./specs/GOVERNANCE-V1.md) design spec).
  Token-family usage is in [tokens.md](./tokens.md).
- **Operational:** [operator-guide](./operator-guide.md), [production-checklist](./operations/production-checklist.md)

> Integration handoffs and historical/design-only specs live under
> `docs/integrations/`, `docs/specs/`, and `docs/archive/`. Current usage is in
> the canonical usage docs above.

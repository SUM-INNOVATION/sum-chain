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

Deployed-genesis activation gates for `chain_id: 1`, verified at **height
8,716,604 · 2026-07-06** (deployed commit `21de231d`, both validators). These
are activation-gate values (stable), not the live chain head. `v2`, `omninode`,
and `education` gates are also observable live via
`chain_getChainParams`; the other five 8,900,000 gates are verified from the
deployed genesis (not exposed over RPC):

| Subprotocol gate | Mainnet value | Meaning |
|---|---|---|
| `v2_enabled_from_height` | `5200000` | V2 storage **active** (height > gate) |
| `omninode_enabled_from_height` | `6000000` | OmniNode inference **attestation active** (height > gate) |
| `education_enabled_from_height` | `8900000` | Education (SRC-817/818) deployed and code-backed; gate **set to 8,900,000 — active at that height** (≈2026-07-12). Reads work now regardless of the gate. |
| `contracts_enabled_from_height` | `8900000` | WASM smart contracts deployed and code-backed; gate **set to 8,900,000 — active at that height** (≈2026-07-12) |
| `governance_enabled_from_height` | `8900000` | Governance v1 deployed and code-backed; gate **set to 8,900,000 — active at that height** (≈2026-07-12). The `ChainParams.governance` params object is also configured (`validator_authority_threshold_bps 6667`, quorum, pass threshold, voting period, snapshot bound). Admin/council authority is **validator-quorum** controlled — no single council address. |
| `archive_unbonding_enabled_from_height` | `8900000` | Archive-node unbonding withdrawal **implemented**; gate **set to 8,900,000 — active at that height** (≈2026-07-12) (issue #20) |
| `archive_reassignment_enabled_from_height` | `8900000` | Archive-node chunk reassignment **implemented**; gate **set to 8,900,000 — active at that height** (≈2026-07-12) (issue #62) |
| `inference_settlement_enabled_from_height` | `8900000` | OmniNode inference settlement **implemented**; gate **set to 8,900,000 — active at that height** (≈2026-07-12) (issue #61; separate from attestation, which is already active). Dispute resolution is validator-quorum controlled via `inference_settlement_dispute_threshold_bps` (6667). |
| `omninode_sponsored_attestation_enabled_from_height` | `9200000` | Sponsored inference attestation (v2 envelope, code-backed, issue #79; a payer/sponsor may submit an attestation, but it stays verifier-keyed for dedup/storage/settlement). **Deployed and activation-gated at height 9,200,000.** Separate from base attestation, which is already active. |
| `por_assignment_targeting_enabled_from_height` | `9200000` | Assignment-targeted PoR challenge selection (issue #81 Phase 1). **Deployed and activation-gated at height 9,200,000.** A separate extension of base PoR / SNIP V2, which is already active. |
| `assignment_aware_por_scheduler_enabled_from_height` | `9200000` | Assignment-aware bounded PoR challenge scheduler (issue #81 Phase 2). **Deployed and activation-gated at height 9,200,000.** A separate extension of base PoR / SNIP V2. |
| `inference_settlement_consistency_enabled_from_height` | `9200000` | Consistency/plurality settlement mode (code-backed, issue #77; opt-in claim rule layered on settlement). **Deployed and activation-gated at height 9,200,000.** A separate extension of base inference settlement, which is already active at 8,900,000. |
| `inference_verifier_bonding_enabled_from_height` | `9200000` | Verifier bonding + slashing (code-backed, issue #78; opt-in per-session bond requirement, slash only on a validator-quorum denied dispute, burned to the zero address). **Deployed and activation-gated at height 9,200,000.** A separate extension of base inference settlement. |
| `service_grants_enabled_from_height` | `9200000` | ProtocolReserve service-grant claiming (validator / archive / compute bootstrap and milestone grants). **Deployed and activation-gated at height 9,200,000; not usable before that height.** |
| `monetary_policy_enabled_from_height` | `9200000` | Reserve release + `MonetaryPolicyMint`, native-Koppa consensus governance at 6667 bps. **Deployed and activation-gated at height 9,200,000; not usable before that height.** |

The 8,900,000-cohort rows are **deployed and code-backed; the activation gate is
set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)**. They
auto-activate when the chain crosses 8,900,000; no further operator action is
required beyond the coordinated genesis that set the gate. OmniNode inference
**attestation** is already active; inference **settlement** (escrow-funded
rewards/refunds) is a separate subprotocol whose gate is set to 8,900,000.

### Post-supply cohort — gate set to 9,200,000

The final seven gates in the table above form a separate **post-supply cohort**,
added to runtime genesis after the 8,900,000 batch and **set to activate together
at height 9,200,000**. They are deployed and code-backed today, not `null`, not
dormant, and not "ungated" — they are activation-gated at 9,200,000 and remain
inert only until the live chain reaches that height, at which point they
auto-activate with no redeploy. Each is a strict extension of an already-active
base subprotocol: sponsored attestation extends base attestation; assignment
targeting and the assignment-aware scheduler extend base PoR / SNIP V2;
consistency and verifier bonding extend base inference settlement (active at
8,900,000). Service grants and monetary policy (reserve release / mint) are
**not usable before height 9,200,000**.

`chain_getChainParams` does not expose every one of these seven gates, so the
**runtime genesis is the source of truth** for their activation height. The
website hard-codes the operator-verified constant `9,200,000` intentionally for
exactly this reason, and derives each gate's active/pending status from the live
block height — so the UI auto-flips to active the moment the chain crosses
9,200,000, and never reports these gates as `null`, dormant, or ungated.

Token / NFT / messaging / docclass / employment families have **no activation
gate** — they are always available when the node binary is running.

## Map of other docs

- **Architecture:** [bft-consensus](./architecture/bft-consensus.md) ·
  [bft-integration](./architecture/bft-integration.md) ·
  [security-overview](./architecture/security-overview.md) ·
  [economic-model](./architecture/economic-model.md) ·
  [performance-guide](./architecture/performance-guide.md)
- **Subprotocols:** [subprotocols/](./subprotocols/) —
  [inference attestation](./subprotocols/INFERENCE-ATTESTATION.md) (active),
  [inference settlement](./subprotocols/inference-settlement.md) (implemented; gate set to 8,900,000, issue #61),
  education activation.
- **Design specs (non-token):** [specs/](./specs/) (SNIP V2 storage plan, incl.
  §5.4 [archive reassignment](./specs/SNIP-V2-CHAIN-PLAN.md) (implemented; gate set to 8,900,000, issue #62);
  [assignment-aware PoR scheduling](./specs/snip-assignment-aware-por-scheduling.md) (deployed and **activation-gated at height 9,200,000**, issue #81 — post-supply extension of base PoR);
  [Governance v1](./specs/GOVERNANCE-V1.md) design spec).
  Archive-node unbonding withdrawal (implemented; gate set to 8,900,000, issue #20) and reassignment are
  separate landed storage mechanics — see the RPC cheatsheet. Token-family usage
  is in [tokens.md](./tokens.md).
- **Operational:** [operator-guide](./operator-guide.md), [production-checklist](./operations/production-checklist.md)
- **Process:** [GOVERNANCE.md](../GOVERNANCE.md) (on-chain governance model; gate set to 8,900,000) ·
  [RELEASE.md](../RELEASE.md) (how approved changes are released)

## Conventions

**Filenames.** New docs use lowercase kebab-case (e.g. `snip-v2-reassignment.md`).
Existing UPPERCASE-KEBAB filenames (e.g. `SNIP-V2-CHAIN-PLAN.md`) are legacy and
kept as-is — they are not mass-renamed.

**Locations.**
- **Current usage guides** live at the docs root and under `docs/rpc/`,
  `docs/operations/`, and `docs/subprotocols/`.
- **Design specs** (non-token) live under `docs/specs/`.
- **Historical handoffs and superseded / point-in-time docs** live under
  `docs/archive/`, each carrying an "Archived / historical" banner. Current
  usage is always in the canonical usage docs above.

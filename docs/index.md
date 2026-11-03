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
| `omninode_sponsored_attestation_enabled_from_height` | `null` (live) | Sponsored inference attestation (v2 envelope, code-backed, issue #79; a payer/sponsor may submit an attestation, but it stays verifier-keyed for dedup/storage/settlement). **Not set on mainnet:** the public `chain_getChainParams` reports `null` and `chain_getConsensusConfig` reports the field absent (live read 2026-11-03), so sponsored attestation is **not active**. 9,200,000 is the height #113 states as intended; it is not the live configuration, and setting it is a separate coordinated configuration change. Separate from base attestation, which is already active. |
| `por_assignment_targeting_enabled_from_height` | absent (live) | Assignment-targeted PoR challenge selection (code-backed, issue #81 Phase 1). **Not set on mainnet:** `chain_getChainParams` does not expose this gate, and `chain_getConsensusConfig` reports it absent (live read 2026-11-03), so targeting is **not active**. 9,200,000 is the height #113 states as intended; it is not the live configuration, and setting it is a separate coordinated configuration change. A separate extension of base PoR / SNIP V2, which is already active. |
| `assignment_aware_por_scheduler_enabled_from_height` | absent (live) | Assignment-aware bounded PoR challenge scheduler (code-backed, issue #81 Phase 2). **Not set on mainnet:** `chain_getChainParams` does not expose this gate, and `chain_getConsensusConfig` reports it absent (live read 2026-11-03), so the scheduler is **not active**. 9,200,000 is the height #113 states as intended; it is not the live configuration, and setting it is a separate coordinated configuration change. A separate extension of base PoR / SNIP V2. |
| `inference_settlement_consistency_enabled_from_height` | `null` (live) | Consistency/plurality settlement mode (code-backed, issue #77; opt-in claim rule layered on settlement). **Not set on mainnet:** the public `chain_getChainParams` (served by the deployed binary, which exposes this gate since #122) reports `null` (read 2026-10-16, recorded on #135), so the mode is **not active**. 9,200,000 is the height #113 states as intended; it is not the live configuration, and setting it is a separate configuration change. A separate extension of base inference settlement, which is active at 8,900,000. |
| `inference_verifier_bonding_enabled_from_height` | `null` (live) | Verifier bonding + slashing (code-backed, issue #78; opt-in per-session bond requirement, slash only on a validator-quorum denied dispute, burned to the zero address). **Not set on mainnet:** the public `chain_getChainParams` (served by the deployed binary, which exposes this gate since #122) reports `null` (read 2026-10-16, recorded on #135), so bonding is **not active**. 9,200,000 is the height #113 states as intended, not the live configuration. A separate extension of base inference settlement. |
| `service_grants_enabled_from_height` | `null` (live) | ProtocolReserve service-grant claiming (validator / archive / compute bootstrap and milestone grants). **Not set on mainnet:** the public `chain_getChainParams` reports `null` and `chain_getConsensusConfig` reports the field absent (live read 2026-11-03), so grant claiming is **not active**. 9,200,000 is the height #113 states as intended; it is not the live configuration, and setting it is a separate coordinated configuration change. |
| `monetary_policy_enabled_from_height` | `null` (live) | Reserve release + `MonetaryPolicyMint`, native-Koppa consensus governance at 6667 bps. **Not set on mainnet:** the public `chain_getChainParams` reports `null` and `chain_getConsensusConfig` reports the field absent (live read 2026-11-03), so reserve release and minting are **not active**. 9,200,000 is the height #113 states as intended; it is not the live configuration, and setting it is a separate coordinated configuration change. |

The 8,900,000-cohort rows are **deployed and code-backed; the activation gate is
set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)**. They
auto-activate when the chain crosses 8,900,000; no further operator action is
required beyond the coordinated genesis that set the gate. OmniNode inference
**attestation** is already active; inference **settlement** (escrow-funded
rewards/refunds) is a separate subprotocol whose gate is set to 8,900,000.

### Post-supply cohort — not set on mainnet (9,200,000 intended)

The final seven gates in the table above form a separate **post-supply cohort**.
All seven are code-backed, and **none of them is set on mainnet.** A live read
of the public RPC on 2026-11-03 (chain head ≈15,569,863) found
`chain_getChainParams` reporting `null` for every one of the seven it exposes,
and `chain_getConsensusConfig` reporting all seven absent, so **none of these
features is active**: sponsored attestation, assignment targeting, the
assignment-aware scheduler, consistency mode, verifier bonding, service-grant
claiming and reserve release / monetary-policy mint. 9,200,000 is the height #113
states as intended; it is not the live configuration, and setting it is a
separate coordinated configuration change. Five of the seven are strict
extensions of an already-active base subprotocol: sponsored attestation extends
base attestation; assignment targeting and the assignment-aware scheduler extend
base PoR / SNIP V2; consistency and verifier bonding extend base inference
settlement (active at 8,900,000). Service grants and monetary policy (reserve
release / mint) are **not usable** while their gates are unset.

**What the public RPC exposes.** On the live chain, `chain_getChainParams`
exposes five of the seven (sponsored attestation, consistency, verifier bonding,
`service_grants` and `monetary_policy`) and reports `null` for all five, so for
those five the live RPC, not this page, is the source of truth. It does not
expose assignment targeting or the assignment-aware scheduler;
`chain_getConsensusConfig` reports both absent. The website
(`website/src/lib/chainStatus.ts`) reads each of the seven gates by name from
these two methods: a gate shows active only when it is set and the live head
has reached it, an unset gate shows "not set", and an unreadable RPC shows
"status unavailable". 9,200,000 appears there only as the height #113 states as
intended.

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
  [assignment-aware PoR scheduling](./specs/snip-assignment-aware-por-scheduling.md) (implemented, issue #81 — post-supply extension of base PoR; its gates are **not set on mainnet**, so it is not active; 9,200,000 is the height #113 states as intended);
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

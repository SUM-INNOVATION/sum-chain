# SUM Chain Governance

How decisions about SUM Chain are made and recorded. This describes the
**implemented** on-chain governance v1 protocol and the record-first model it
follows. The protocol design spec is
[docs/specs/GOVERNANCE-V1.md](docs/specs/GOVERNANCE-V1.md); the public RPC
surface is documented in [docs/tokens.md](docs/tokens.md); how approved
decisions are carried out is in [RELEASE.md](RELEASE.md).

## Dormant by default

On-chain governance ships **inert**. It does nothing until a coordinated
validator activation sets **both** the activation gate
(`governance_enabled_from_height`) and the network parameters
(`ChainParams.governance`). Neither is set on mainnet, so governance
transactions are rejected until a network enables them. Activation is a
validator-coordinated, byte-identical runtime-genesis change — see
[RELEASE.md](RELEASE.md) and
[docs/operations/production-checklist.md](docs/operations/production-checklist.md).

No final token id, `create_threshold`, quorum, pass threshold, proposal bond,
voting period, or activation height is fixed here; those are set per activation.

## Record-first model

The authoritative governance decision is the **on-chain approval record**.
Governance **records** that a proposal passed; it does **not** force validators
to upgrade and does **not** mutate chain parameters, the validator set, or
consensus. Approved code, release, genesis, or validator changes are carried out
off-chain (GitHub PR / release build / coordinated validator rollout) as
described in [RELEASE.md](RELEASE.md). Validators always remain in control of
which binary and genesis they run.

## Who governs

- **Token-holder governance.** Holders of a single allowlisted SRC-20 governance
  token create proposals and vote. Voting power is a **balance snapshot frozen
  at proposal creation** (transfers after the snapshot do not change weight;
  live balances are never used during voting). A token is eligible only if it is
  fixed-supply / non-mintable.
- **Validator-quorum admin authority.** Governance admin/council authority is
  **validator-quorum controlled** — there is **no single council address**
  anymore. A threshold of the **active PoA validator set** must sign
  (Ed25519, domain-separated, chain_id-bound) to administer the governance asset
  registry, exercise emergency/security authority, or cancel a live proposal.
  Threshold is configured in basis points
  (`GovernanceParams.validator_authority_threshold_bps`): required approvals =
  `ceil(active_validator_count * threshold_bps / 10000)`. Non-signing validators
  count in the denominator; a validator that does not sign abstains, and the
  action only executes if enough approvals are submitted — this is threshold
  authorization, not yes/no voting. For the current 2-validator network, `6667`
  requires both validators; `10000` requires all validators. The governance
  `treasury` remains a governed payout address that on-chain treasury payouts
  draw from.

There is no foundation and no other committee. These two authorities are the
whole model.

## Proposal lifecycle

1. **Create** — the proposer's snapshot power must meet the asset's
   `create_threshold`. When a deposit bond is configured, it is escrowed to a
   canonical governance escrow address at creation (the proposer must cover
   `fee + bond`).
2. **Vote** — holders cast Yes / No / Abstain, weighted by the frozen snapshot.
3. **Tally** — after the voting window, the result is one of **Recorded**,
   **Executed**, **Rejected**, **QuorumNotMet**, or **Expired**, by quorum and
   pass-threshold over the snapshot.
4. **Cancel** — the proposer may self-cancel their own proposal (no approvals
   needed) while it is still open (Created/Voting); a **validator-quorum**
   cancel (threshold of the active validator set) may also cancel a live
   proposal.

Every proposal links to the off-chain artifact it authorizes (a GitHub PR /
release / doc: URL + content hash), so a proposal id maps to a real change.

**Deposit bond.** Returned to the proposer on a good-faith outcome (Recorded /
Executed / Rejected) or a proposer cancel; burned on spam / low turnout
(QuorumNotMet / Expired) or a validator-quorum cancel.

## Execution model

Approval is **record-only** for every proposal class except one:

- **Record-only** — repository/process, RPC-surface, token/economic, genesis /
  config / validator, activation-height, consensus / wire / storage migration,
  and package-publishing proposals. Approval is an authoritative record; the
  change is carried out off-chain per [RELEASE.md](RELEASE.md). Economic-class
  proposals should reference
  [docs/architecture/economic-model.md](docs/architecture/economic-model.md).
- **On-chain** — a passed `TreasurySpend` proposal marked `OnChain` performs a
  single **native-Koppa transfer** from the configured governance treasury
  (`GovernanceParams.treasury`, a dedicated governance-owned payout address) to
  the beneficiary and amount fixed at creation,
  then moves to **Executed**. An underfunded treasury fails cleanly and leaves
  the proposal live. This is the **only** on-chain auto-execution path; every
  other `OnChain` proposal is rejected. No chain parameter, validator, or
  consensus state is ever changed.

## What governance cannot do

- It cannot force a validator to upgrade its binary or genesis.
- It cannot mutate chain parameters, the validator set, or consensus on-chain.
- It cannot move funds except the single `TreasurySpend` native payout above.

## Emergency & security

Suspected vulnerabilities follow [SECURITY.md](SECURITY.md) — report privately,
not via a public issue or proposal. Emergency/security authority (including a
validator-quorum cancel of a live proposal) is validator-quorum controlled — a
threshold of the active validator set — as a backstop.

## Related documents

- [docs/specs/GOVERNANCE-V1.md](docs/specs/GOVERNANCE-V1.md) — protocol design spec.
- [docs/tokens.md](docs/tokens.md) — governance RPC surface (dormant).
- [RELEASE.md](RELEASE.md) — how approved decisions are released.
- [docs/operations/production-checklist.md](docs/operations/production-checklist.md) — activation & rollout operations.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how changes are proposed and reviewed.
- [SECURITY.md](SECURITY.md) — vulnerability reporting.

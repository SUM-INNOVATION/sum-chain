# SUM Chain Governance

How decisions about SUM Chain are made and recorded. This describes the
**implemented** on-chain governance v1 protocol and the record-first model it
follows. The protocol design spec is
[docs/specs/GOVERNANCE-V1.md](docs/specs/GOVERNANCE-V1.md); the public RPC
surface is documented in [docs/tokens.md](docs/tokens.md); how approved
decisions are carried out is in [RELEASE.md](RELEASE.md).

## Deployed; gate set to height 8,900,000

On-chain governance is **deployed and code-backed**. On mainnet **both** the
activation gate (`governance_enabled_from_height`) and the network parameters
(`ChainParams.governance`) are configured in the deployed genesis: the gate is
**set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)**
(live height 8,716,604 · 2026-07-06). Until the chain crosses 8,900,000,
governance transactions are still rejected; the subprotocol auto-activates at
that height with no further operator action. The gate was set via a
validator-coordinated, byte-identical runtime-genesis change — see
[RELEASE.md](RELEASE.md) and
[docs/operations/production-checklist.md](docs/operations/production-checklist.md).

The configured `ChainParams.governance` params object includes
`validator_authority_threshold_bps 6667`, quorum, pass threshold, voting period,
and the snapshot bound. No governance token id is registered until a
validator-quorum `RegisterAsset` action after activation.

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

## Governance v2 — additional voting modes (shipped)

Two token-holder voting modes ship alongside SRC-20 snapshot voting. Both reuse
the same frozen-snapshot lifecycle, quorum, and bond mechanics; they differ only
in how the electorate and per-voter weight are derived. Validator-quorum
authority (used to register the eligibility sources) stays entirely separate
from the public vote.

- **Native-Koppa 1-address-1-vote (#91).** Validator-quorum
  `RegisterQualifyingAsset` allowlists an SRC-20 whose holders (balance ≥ that
  asset's `min_balance`) are eligible. At **proposal creation**, the electorate
  is frozen: every holder of an effective qualifying SRC-20 whose native Koppa
  balance is ≥ `GovernanceParams.min_koppa_for_eligibility` at creation height,
  deduped, each with **weight 1** (bounded by `max_snapshot_holders`).
  Non-allowlisted or self-minted tokens confer nothing; NFTs/credentials are not
  qualifying (only an SRC-20 `token_id` registry exists). Native proposals pass
  at a fixed **6667 bps** of (yes+no); quorum uses `quorum_bps` over the frozen
  electorate size. Votes reuse the standard cast-vote path.
- **SRC-833 controller-attested equity vote (#92).** Validator-quorum
  `RegisterEquityClass` registers a voting equity share class
  (`votes_per_share > 0`) as a governance asset. At proposal creation the class's
  **chain-derived** `EQUITY_BALANCES` Merkle root is computed on-chain and frozen
  to the proposal. A voter proves `(holder_commitment, shares)` under that root
  and submits the class **controller's** Ed25519 attestation over the vote;
  weight = `shares × votes_per_share`. Each `(proposal, holder_commitment)` may
  vote once. The chain never stores or returns a holder→balance table — only the
  root and parameters are readable (`gov_getEquityClassVoting`).

## Policy-Account token administration (shipped)

A Policy Account can now execute, on behalf of its own address, exactly five
SRC-20 token-admin operations via an approved proposal: **Pause, Unpause,
AddMinter, RemoveMinter, TransferOwnership** (#90). The wrapped token op runs as
`sender = policy_account.address`. Any other token op (e.g. Mint/Transfer) and
all NFT/Staking/Governance/Deploy/Call actions remain fail-closed; only native
transfer and these five ops execute. A failing wrapped op leaves **no** partial
token state and does **not** advance the policy nonce, so the proposal can be
retried.

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

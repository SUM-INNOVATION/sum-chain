# Governance v1 — SRC-20 Holder Governance (Design Spec)

> **Status:** code-backed and deployed; activation gate `governance_enabled_from_height` **set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)** (height 8,716,604 · 2026-07-06)
> **Umbrella:** issue #31 · **Implementation:** #50 · **Process docs:** #51
> This document specifies the protocol. On mainnet the gate and the
> `ChainParams.governance` params object are configured in the deployed genesis;
> governance auto-activates when the chain crosses height 8,900,000.

## 1. Goal

On-chain governance where **token-type holders** create proposals and vote. The
primary v1 right is a **single allowlisted SRC-20 governance token**, held in a
maintainer-gated **governance asset registry**. Approval is recorded on-chain;
execution of code/release/validator/consensus changes remains off-chain
(record-first).

## 2. Scope of v1 (approved rulings)

| Decision | v1 ruling |
|---|---|
| Voting source | **SRC-20 governance token** (allowlisted `TokenId`) |
| Staked Koppa | **Not in v1** (future optional) |
| Native raw balance | Excluded (plutocracy/vote-buying) |
| Asset model | **Single** approved governance asset (not multi-asset) |
| Private/sensitive SRC families (Healthcare, Legal, Finance subjects, private credentials) | **Excluded** as voting sources |
| Equity SRC-83X governance | **Separate**; no bridge in v1 |
| Snapshot | `TOKEN_BALANCES` prefix scan by `token_id` + `gov_snapshots` CF, frozen at voting-start |
| Ballot privacy | **Public votes** in v1 (commit-reveal is future) |
| Governance token supply | **Fixed-supply / non-mintable** (`!mintable`) required before eligibility |
| Validator binding | Governance **records approval**; it does not force validator upgrades or mutate chain params/consensus |

## 3. Governance asset registry

An on-chain, **validator-quorum-administered** allowlist of governance-eligible
assets. Governance admin/council authority is validator-quorum controlled; there
is **no single council address**.

```
GovAsset {
  asset:            GovAssetKind,   // v1: Src20Token(TokenId)
  create_threshold: u128,           // min snapshot power to CREATE a proposal
  vote_weight_rule: WeightRule,     // v1: Linear (weight = snapshot balance)
  status:           Enabled | Disabled,
  effective_height: BlockHeight,    // when this eligibility takes effect
}
```

- `GovAssetKind` in v1 is `Src20Token(TokenId)` only. `StakedKoppa` and other
  classes are reserved for a future, separately-approved revision.
- The registry starts **empty**. The first (single) asset is added by a
  validator-quorum `RegisterAsset` action after activation (a threshold of the
  active validator set must sign).
- **Eligibility rule:** a token may be listed only if it is fixed-supply /
  non-mintable (`!mintable`). This prevents inflating voting power by minting.
  SRC-20 exposes no on-chain operation to freeze or renounce mint authority
  (`mintable` is immutable after creation, and `pause` only halts transfers), so
  `!mintable` is the sole v1 eligibility rule — a "frozen mint authority"
  state does not exist on-chain and is not accepted.
- Registry changes (list/enable/disable) are **validator-quorum** actions (a
  threshold of the active validator set signs), not open votes, in v1.

## 4. Voting power & snapshot

`TOKEN_BALANCES` is keyed **`token_id ‖ owner`**, so all holders of a governance
token are directly enumerable with a prefix scan
(`db.prefix_iter(TOKEN_BALANCES, token_id)`). No separate reverse index is
needed. v1 therefore:

- freezes eligible balances via a **`TOKEN_BALANCES` prefix scan by `token_id`**
  into a **`gov_snapshots` CF** (`gov_snapshots[proposal_id][holder] = weight`)
  at the **voting-start** height; and
- bounds the snapshot with a **maximum holder count** (constant or config): if a
  governance token's holder set exceeds the bound, proposal creation /
  voting-start fails cleanly rather than doing unbounded block work.

Voting reads the frozen snapshot; **live balances are never used during voting**,
so transfers after the snapshot do not change weight. For v1,
`voting_start_height = proposal.created_at_height` (snapshot at creation; no
delayed voting window).

## 5. Proposal & vote lifecycle

```
Created  (proposer snapshot power ≥ create_threshold; deposit bond posted)
  → Voting     [snapshot eligible balances @ voting-start → gov_snapshots]
  → tally      (quorum + pass threshold over snapshot power)
  → { Passed | Rejected | QuorumNotMet }
  → { Executed(on-chain: treasury payout) | Recorded(off-chain + external_ref) | Expired }
Cancel: self-cancel by proposer (no approvals); or validator-quorum cancel (emergency).
```

- **Deposit bond**: `GovernanceParams.proposal_bond` (native Koppa; `0` = off).
  Escrowed to a canonical keyless governance escrow address at creation (the
  proposer must cover `fee + bond`); **returned** to the proposer on a good-faith
  terminal state (Recorded / Executed / Rejected) or a proposer cancel, and
  **burned** to `Address::ZERO` on spam / low turnout (QuorumNotMet / Expired) or
  a validator-quorum cancel.
- **`external_ref`**: every proposal links to the GitHub PR / release / doc it
  authorizes (URL + content hash), so proposal IDs map to real artifacts.
- **`execution_kind`**: `OnChain` (treasury spend only) or `RecordOnly`.
- **Cancel**: the proposer may self-cancel their own proposal with no approvals;
  a **validator-quorum** cancel (a threshold of the active validator set,
  configured by `GovernanceParams.validator_authority_threshold_bps`) may also
  cancel a live proposal while Created/Voting, via the `gov_buildCancelProposal`
  builder (which accepts an optional `approvals` list of validator signatures).

## 6. Proposal classes → execution model

| Class | v1 execution |
|---|---|
| Routine repo/process | RecordOnly |
| Public RPC surface change | RecordOnly |
| Token / economic change | RecordOnly (+ economic-model revision) |
| Genesis / config / validator change | RecordOnly (validator-coordinated) |
| Activation-height change | RecordOnly → byte-identical runtime-genesis edit + rollout |
| Consensus / wire / storage migration | RecordOnly (binary rollout) |
| Package publishing | RecordOnly (off-chain) |
| Emergency / security | Validator-quorum fast-path (threshold of the active validator set) |
| Treasury spend (dedicated governance treasury) | **On-chain**: a passed `TreasurySpend` + `OnChain` proposal pays a single native-Koppa amount from `GovernanceParams.treasury` to its beneficiary and moves to `Executed` — the only auto-exec path in v1 |

Treasury execution is deliberately minimal: exactly one native-Koppa transfer,
`TreasurySpend`-class only, from a dedicated governance-owned `treasury` address
(a governed payout address, funded to be governed) to a beneficiary and
amount fixed at proposal creation. Insufficient treasury balance fails cleanly
(`312`) and leaves the proposal live; every other `OnChain` class fails `310`.
No on-chain chain-param / validator / consensus mutation exists or is performed,
so nothing else auto-executes — a passed proposal is an authoritative approval
record, never a forced validator upgrade.

## 7. Validator-quorum admin authority

Governance admin/council authority is **validator-quorum controlled**; there is
**no single council address**. A threshold of the **active PoA validator set**
must sign (Ed25519, domain-separated, chain_id-bound) to exercise admin
authority:
- administers the governance asset registry (`RegisterAsset`),
- holds emergency/security authority, including a validator-quorum **cancel** of
  a live proposal (bond burned) — the proposer can still self-cancel their own
  proposal with no approvals,
- the dedicated `treasury` address (a governed payout address) is what
  `TreasurySpend` payouts draw from.

**Threshold is configured in basis points**
(`GovernanceParams.validator_authority_threshold_bps: u16`): required approvals =
`ceil(active_validator_count * threshold_bps / 10000)`. **Non-signing validators
count in the denominator; a validator that does not sign abstains, and the
action only executes if enough approvals are submitted** — this is threshold
authorization, not yes/no voting. For the current 2-validator network, `5000`
→ 1 signature, and `5001`, `6667`, or `10000` → 2 signatures: `6667` requires
both validators; `10000` requires all validators. `tx.from` is only the fee
payer / submitter — not the authority.

On-chain treasury payouts execute through governance's own `ExecuteProposal`
path (§6), from the dedicated `treasury` address. Token-holder governance (this
spec) is **separate** but a passed token-holder proposal can **authorize** a
validator-quorum admin action.

## 8. Activation & migration

Gated by `governance_enabled_from_height: Option<u64>` (fresh-chain default
`None`), mirroring the OmniNode / education / v2 deploy pattern. On mainnet this
gate is **set to height 8,900,000 — active once the chain reaches it
(≈2026-07-12)** and the `ChainParams.governance` params object is configured in
the deployed genesis, so governance auto-activates when the chain crosses that
height. Validators deploy the binary; the gate was set via a coordinated,
byte-identical runtime-genesis edit. Governance never bypasses validator control.

## 9. Storage / RPC surface (for the implementation issue)

- **CFs:** `gov_registry`, `gov_proposals`, `gov_votes`, `gov_snapshots`,
  `gov_proposal_index`. Snapshots are built by a `TOKEN_BALANCES` prefix scan
  (§4), so no reverse holder-index CF is required.
- **Tx:** new `TxPayload::Governance` (separate from equity `GovernanceAction`).
- **RPC (builder pattern):** writes `gov_buildCreateProposal`,
  `gov_buildCastVote`, `gov_buildExecuteProposal`, `gov_buildCancelProposal`;
  reads `gov_getProposal`, `gov_listProposals`, `gov_listActiveProposals`,
  `gov_getTally`, `gov_getVote`, `gov_getVotingPower`, `gov_listEligibleAssets`.

Detailed types and tests are defined in the implementation issue (#50).

## 10. Security & privacy

- **Sensitive-holder leakage:** public governance draws power only from the
  allowlisted SRC-20 governance token; private/sensitive SRC families are never
  voting sources.
- **Mint-based capture:** fixed-supply / non-mintable (`!mintable`) eligibility rule (§3).
- **Vote-buying / balance moves:** voting-start snapshot (§4).
- **Validator coercion:** record-first; governance does not force upgrades (§6, §8).
- **Spam:** create-threshold + deposit bond + rate limits.
- **Low turnout / capture:** quorum + validator-quorum emergency backstop.
- **Ballot privacy:** public votes in v1; commit-reveal is a future option.

## 11. TBD parameters (resolved before/at implementation, not in this spec)

| Parameter | Status |
|---|---|
| First eligible governance `TokenId` | TBD |
| Proposal `create_threshold` | TBD |
| Quorum (% of snapshot power) | TBD |
| Pass threshold (%) | TBD |
| Validator admin authority threshold | Configurable via `GovernanceParams.validator_authority_threshold_bps` (basis points of the active validator set; `6667` requires both of a 2-validator network, `10000` requires all); value TBD per activation |
| Deposit bond amount | Configurable via `GovernanceParams.proposal_bond` (`0` = off); value TBD per activation |
| Governance `treasury` address | Configurable via `GovernanceParams.treasury` (`None` = no on-chain treasury execution); value TBD per activation |
| Voting period (blocks) | TBD |
| Proposal expiry (if unexecuted) | TBD |

## 12. Out of scope for v1

Staked-Koppa voting, multi-asset weighted voting, commit-reveal ballots,
Equity-governance bridging, on-chain consensus/param mutation, and any
auto-execution beyond the single-native-transfer `TreasurySpend` payout (§6).
`GOVERNANCE.md` / `RELEASE.md` are produced under #51 after the protocol (#50)
is implemented.

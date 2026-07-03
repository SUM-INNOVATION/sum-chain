# Governance v1 — SRC-20 Holder Governance (Design Spec)

> **Status:** code-backed, dormant (implemented behind an activation gate; not yet activated on mainnet)
> **Umbrella:** issue #31 · **Implementation:** #50 · **Process docs:** #51
> This document specifies the protocol. It is not an active mainnet surface;
> governance ships dormant behind an activation gate and is enabled only by a
> coordinated validator rollout.

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

An on-chain, **council-administered** allowlist of governance-eligible assets.

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
- The registry starts **empty**. The first (single) asset is added by the
  Policy Account council after activation.
- **Eligibility rule:** a token may be listed only if it is fixed-supply /
  non-mintable (`!mintable`). This prevents inflating voting power by minting.
  SRC-20 exposes no on-chain operation to freeze or renounce mint authority
  (`mintable` is immutable after creation, and `pause` only halts transfers), so
  `!mintable` is the sole v1 eligibility rule — a "council-frozen mint authority"
  state does not exist on-chain and is not accepted.
- Registry changes (list/enable/disable) are **council** actions (Policy
  Account), not open votes, in v1.

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
  → { Executed(on-chain: treasury via council) | Recorded(off-chain + external_ref) | Expired }
Cancel: by proposer before Voting; by council (emergency).
```

- **Deposit bond**: `GovernanceParams.proposal_bond` (native Koppa; `0` = off).
  Escrowed to a canonical keyless governance escrow address at creation (the
  proposer must cover `fee + bond`); **returned** to the proposer on a good-faith
  terminal state (Recorded / Executed / Rejected) or a proposer cancel, and
  **burned** to `Address::ZERO` on spam / low turnout (QuorumNotMet / Expired) or
  a council cancel.
- **`external_ref`**: every proposal links to the GitHub PR / release / doc it
  authorizes (URL + content hash), so proposal IDs map to real artifacts.
- **`execution_kind`**: `OnChain` (treasury spend only) or `RecordOnly`.
- **Cancel**: by the proposer or the council (`GovernanceParams.council`) while
  Created/Voting, via the `gov_buildCancelProposal` builder.

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
| Emergency / security | Policy Account council fast-path |
| Treasury spend (dedicated governance treasury) | **On-chain**: a passed `TreasurySpend` + `OnChain` proposal pays a single native-Koppa amount from `GovernanceParams.treasury` to its beneficiary and moves to `Executed` — the only auto-exec path in v1 |

Treasury execution is deliberately minimal: exactly one native-Koppa transfer,
`TreasurySpend`-class only, from a dedicated governance-owned `treasury` address
(funded to be governed; **not** the council Policy Account) to a beneficiary and
amount fixed at proposal creation. Insufficient treasury balance fails cleanly
(`312`) and leaves the proposal live; every other `OnChain` class fails `310`.
No on-chain chain-param / validator / consensus mutation exists or is performed,
so nothing else auto-executes — a passed proposal is an authoritative approval
record, never a forced validator upgrade.

## 7. Policy Account council

The `GovernanceParams.council` address (a Policy Account weighted-multisig) is
the **council**:
- administers the governance asset registry (`RegisterAsset`),
- holds emergency/security authority, including **cancelling** a live proposal
  (bond burned),
- funds and owns the dedicated `treasury` address that `TreasurySpend` payouts
  draw from.

On-chain treasury payouts execute through governance's own `ExecuteProposal`
path (§6), from the dedicated `treasury` address — not from the council Policy
Account itself. Token-holder governance (this spec) is **separate** but a passed
token-holder proposal can **authorize** a council action.

## 8. Activation & migration

Ships dormant behind `governance_enabled_from_height: Option<u64>` (default
`None`), mirroring the OmniNode / education / v2 dormant-deploy pattern.
Validators deploy the binary; activation is a coordinated, byte-identical
runtime-genesis edit. Governance never bypasses validator control.

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
- **Low turnout / capture:** quorum + council emergency backstop.
- **Ballot privacy:** public votes in v1; commit-reveal is a future option.

## 11. TBD parameters (resolved before/at implementation, not in this spec)

| Parameter | Status |
|---|---|
| First eligible governance `TokenId` | TBD |
| Proposal `create_threshold` | TBD |
| Quorum (% of snapshot power) | TBD |
| Pass threshold (%) | TBD |
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

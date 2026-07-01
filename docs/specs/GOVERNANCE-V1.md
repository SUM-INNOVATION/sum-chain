# Governance v1 — SRC-20 Holder Governance (Design Spec)

> **Status:** design spec (approved direction; not yet implemented)
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
| Snapshot | Governance reverse holder index + `gov_snapshots` CF, frozen at voting-start |
| Ballot privacy | **Public votes** in v1 (commit-reveal is future) |
| Governance token supply | **Fixed-supply / non-mintable or council-frozen mint authority** required before eligibility |
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
  non-mintable, or its mint authority is council-frozen, before listing. This
  prevents inflating voting power by minting.
- Registry changes (list/enable/disable) are **council** actions (Policy
  Account), not open votes, in v1.

## 4. Voting power & snapshot

The current `TOKEN_HOLDER_INDEX` is `owner → token_ids` and balances are
current-state (no history), so a naive "read all holders at height H" is not
supported. v1 therefore adds:

- a **governance-only reverse holder index** (`token_id → holders`), maintained
  only for registry-listed tokens; and
- a **`gov_snapshots` CF** that freezes eligible balances
  (`gov_snapshots[proposal_id][holder] = weight`) at the **voting-start** height.

Voting reads the frozen snapshot; **live balances are never used during voting**,
so transfers after the snapshot do not change weight. Snapshotting at
voting-start (not proposal creation) is intentional.

## 5. Proposal & vote lifecycle

```
Created  (proposer snapshot power ≥ create_threshold; deposit bond posted)
  → Voting     [snapshot eligible balances @ voting-start → gov_snapshots]
  → tally      (quorum + pass threshold over snapshot power)
  → { Passed | Rejected | QuorumNotMet }
  → { Executed(on-chain: treasury via council) | Recorded(off-chain + external_ref) | Expired }
Cancel: by proposer before Voting; by council (emergency).
```

- **Deposit bond**: returned on good-faith proposals; burned on spam / quorum
  failure (amount TBD).
- **`external_ref`**: every proposal links to the GitHub PR / release / doc it
  authorizes (URL + content hash), so proposal IDs map to real artifacts.
- **`execution_kind`**: `OnChain` (treasury only) or `RecordOnly`.

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
| Treasury spend (council-held Policy Account) | **On-chain** via the council's `ExecuteProposal` — the only auto-exec path in v1 |

No on-chain chain-param/consensus mutation exists today, so nothing in those
classes auto-executes. A passed proposal is an authoritative approval record,
never a forced validator upgrade.

## 7. Policy Account council

The existing Policy Account weighted-multisig is the **council**:
- administers the governance asset registry,
- holds emergency/security authority,
- executes on-chain **treasury** actions via `ExecuteProposal`.

Token-holder governance (this spec) is **separate** but a passed token-holder
proposal can **authorize** a council action.

## 8. Activation & migration

Ships dormant behind `governance_enabled_from_height: Option<u64>` (default
`None`), mirroring the OmniNode / education / v2 dormant-deploy pattern.
Validators deploy the binary; activation is a coordinated, byte-identical
runtime-genesis edit. Governance never bypasses validator control.

## 9. Storage / RPC surface (for the implementation issue)

- **CFs:** `gov_registry`, `gov_proposals`, `gov_votes`, `gov_snapshots`,
  `gov_proposal_index`, `gov_token_holder_index` (governance-eligible tokens only).
- **Tx:** new `TxPayload::Governance` (separate from equity `GovernanceAction`).
- **RPC (builder pattern):** writes `gov_buildCreateProposal`,
  `gov_buildCastVote`, `gov_buildExecuteProposal`; reads `gov_getProposal`,
  `gov_listProposals`, `gov_listActiveProposals`, `gov_getTally`, `gov_getVote`,
  `gov_getVotingPower`, `gov_listEligibleAssets`.

Detailed types and tests are defined in the implementation issue (#50).

## 10. Security & privacy

- **Sensitive-holder leakage:** public governance draws power only from the
  allowlisted SRC-20 governance token; private/sensitive SRC families are never
  voting sources.
- **Mint-based capture:** fixed-supply / frozen-mint eligibility rule (§3).
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
| Deposit bond amount | TBD |
| Voting period (blocks) | TBD |
| Proposal expiry (if unexecuted) | TBD |

## 12. Out of scope for v1

Staked-Koppa voting, multi-asset weighted voting, commit-reveal ballots,
Equity-governance bridging, on-chain consensus/param mutation, and any
auto-execution beyond council-scoped treasury actions. `GOVERNANCE.md` /
`RELEASE.md` are produced under #51 after the protocol (#50) is implemented.

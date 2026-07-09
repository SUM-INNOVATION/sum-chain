# OmniNode Inference Settlement (issue #61)

> **Status:** code-backed and **implemented**; deployed on mainnet with
> `inference_settlement_enabled_from_height` **set to height 8,900,000 — active
> once the chain reaches it (≈2026-07-12)** (height 8,716,604 · 2026-07-06). It
> auto-activates when the chain crosses 8,900,000; no further operator action is
> required.

Escrow-funded reward settlement for OmniNode inference verifiers, **keyed by the
existing immutable [`InferenceAttestation`](INFERENCE-ATTESTATION.md) records** by
`(session_id, verifier_address)`. Settlement is a **separate subprotocol**: it
reads attestations and moves escrowed Koppa, but never changes the attestation
wire format, storage, or records.

## What v1 is (and is not)

- **No inflation.** Payouts are supply-conserving: a funder is debited when a
  session is opened/funded, verifiers are credited when they claim, and any
  remainder is refunded to the funder on close. Nothing is minted. (Mirrors the
  storage `fee_pool` pattern; fixed 800B supply is unchanged — see
  [economic-model.md](../architecture/economic-model.md).)
- **Bond slashing is opt-in and gated (issue #78).** Base v1 has no bond; a
  session may require a verifier bond and slash it **only** on a validator-quorum
  denied dispute. Slashing is supply-conserving (burned to `Address::ZERO`, never
  minted) — see **Verifier bonding and slashing** below. Sessions without a bond
  requirement keep the v1 levers: **reward denial**, **claim withholding**,
  **escrow refund**, and **dispute records**.
- **Attestation v1 is untouched.** `InferenceAttestationDigest`,
  `InferenceAttestationTxData`, and the attestation column families are read-only
  from settlement's perspective and are never mutated.

## Model

A session is opened and funded by a **funder** (the requester/payer), who sets a
fixed `reward_per_verifier`, a `max_verifiers` cap, a `dispute_window_blocks`, and
an `expires_at_height`. Escrow is tracked as `remaining_escrow` in the session
record. **`expires_at_height` must be at or after the minimum claim-maturity
window** — `created_at_height + finality_depth + dispute_window_blocks` — so a
session can never expire before an attestation submitted at open time could
mature; otherwise `OpenSession` is rejected.

A **verifier** who produced an attestation for that session may **self-claim** the
fixed reward once the claim is *mature*. **No claim can be paid until the
attestation is finalized AND the dispute window has elapsed**, i.e. not before:

```
attestation.included_at_height + finality_depth + dispute_window_blocks
```

Each verifier can claim once, up to `max_verifiers`, while escrow remains.

### Consistency / plurality mode (issue #77, v1.1 — gated, opt-in)

A session may optionally require **agreement among verifiers** before a claim
qualifies. This is **deterministic agreement over the on-chain commitments** — it
compares the verifiers' *full attestation digest tuples*, `(model_hash,
manifest_root, response_hash, proof_root)`. It is **not** a judgement of the AI
output's semantic correctness, and involves **no zkML or on-chain re-execution**.

A funder opts in at `OpenSession` by supplying a consistency config:

- `min_matching_verifiers` (`u32`, `>= 1`, `<= max_verifiers`) — primary,
  always-active rule: the claimant's exact-tuple group must reach at least this
  many verifiers.
- `threshold_bps` (`u16`, `0`–`10000`, `0` = disabled) — optional proportional
  rule measured against the **fixed, funder-declared `max_verifiers`** (never the
  live attestation count, which would be gameable): the group must also satisfy
  `matching_count * 10000 >= max_verifiers * threshold_bps`.

Both active constraints must hold. The group is always evaluated against the
**claimant's own tuple**, so a verifier with a divergent digest can never ride
another group's plurality. Only attestations that are **finalized** at claim
height (`included + finality_depth`) and **not** blocked by an open/denied dispute
count toward the group — a premature or disputed attestation lends no weight.

Consistency mode is gated by
`inference_settlement_consistency_enabled_from_height`. A session that requests a
consistency config while the gate is closed is rejected `Failed(361)`; an invalid
config is rejected `Failed(363)`. A matured claim whose group is too small is
rejected `Failed(362)`. Sessions with **no** consistency config are unaffected —
v1 single-attestation claim behavior is unchanged.

### Verifier bonding and slashing (issue #78, gated, opt-in)

By default settlement is **optimistic / lazy-approved**: once a verifier's
attestation clears finality + the dispute window, satisfies the session's
consistency rule (if any), and no dispute is upheld against it, the verifier may
claim — no one has to actively approve each honest claim. **A dispute is the
overwrite mechanism**: it can block a pending claim during the window, and
validator-quorum resolution either lets the claim proceed or denies it.

**consistency decides eligibility; dispute resolution decides punishment.** A
consistency-plurality failure only blocks reward eligibility (`Failed(362)`) — it
never slashes. Slashing happens **only** through an explicit adjudication path: a
validator-quorum `ResolveDispute(allow_claim = false)` on a session that carries a
bond requirement.

A funder opts a session into bonding by supplying a `bond_requirement` at
`OpenSession`:

- `min_bond` (`u128`, `> 0`) — a verifier must hold an `Active` bond of at least
  this much to claim the session.
- `slash_bps_on_denied_dispute` (`u16`, `0`–`10000`, `0` = no slashing) — on a
  denied dispute the target's bond is reduced by
  `min(bond, bond * slash_bps / 10000)`.

**Verifier bond registry.** Verifiers manage their own bond (sender = verifier):

- `RegisterVerifier { bond }` — locks native Koppa as bond (accounting-in-record,
  like session escrow). A `Withdrawn` record may be re-registered with a fresh
  bond; an `Active`/`Unbonding` record is rejected (`366`).
- `AddVerifierBond { amount }` — top up an `Active` bond.
- `BeginVerifierUnbond` — start the
  `inference_verifier_unbonding_period_blocks` delay (status → `Unbonding`).
- `WithdrawVerifierBond` — after the unlock height, return the remaining bond
  (possibly reduced by slashes during unbonding) and mark `Withdrawn`.

**Claim gating (bond-required sessions), in order:** no record → `367`; status not
`Active` → `368`; bond `< min_bond` → `370`. Sessions **without** a
`bond_requirement` are entirely unaffected — no registration, no slashing.

**Slashing is supply-conserving and auditable.** No Koppa is minted; a slash moves
the amount from the verifier's bond record to `Address::ZERO` (the same burn sink
governance uses for forfeited proposal bonds). A denied dispute against a verifier
with **no or zero** bond slashes zero — the reward denial still stands, and there
is no mint or underflow. An `Unbonding` verifier is still slashable; only *claiming*
requires `Active` status. This is **agreement-and-adjudication economics — it does
not prove semantic AI correctness and performs no on-chain zkML verification.**

The funder may **refund** the remaining escrow once the session is closable
(expired or fully claimed) and no dispute is left unresolved. **A refund can never
bypass a pending claim**: even at/after expiry, `RefundSession` is rejected while
any verifier that attested for the session is still within its maturity window and
has neither claimed nor been denied by a dispute. Only once every such claim has
matured (or been claimed/denied) can the remaining escrow be refunded.

## Disputes (record-only, validator-quorum resolution)

Disputes are **record-only** — the chain cannot verify inference correctness. A
dispute is raised by the funder during the dispute window against a specific
verifier and carries only an opaque `evidence_commitment` (a hash; **no plaintext
evidence on chain**). It **withholds** that verifier's claim until resolved.

Inference-settlement dispute resolution is **validator-quorum controlled** —
there is **no personal resolver key**, so the funder is never both accuser and
judge. `ResolveDispute` requires a threshold of the **active PoA validator set**
to sign (Ed25519, domain-separated, chain_id-bound). **Threshold is configured in
basis points** (`inference_settlement_dispute_threshold_bps: Option<u16>`):
required approvals = `ceil(active_validator_count * threshold_bps / 10000)`.
**Non-signing validators count in the denominator; a validator that does not sign
abstains, and the action only executes if enough approvals are submitted** — this
is threshold authorization, not yes/no voting. For the current 2-validator
network, `5000` → 1 signature, and `6667` requires both validators; `10000`
requires all validators. `tx.from` is only the fee payer / submitter — not the
authority. A resolution either **allows** the claim to proceed or **denies** it
(the verifier's reward is withheld; escrow stays refundable to the funder).

**Disputes require `inference_settlement_dispute_threshold_bps` to be set.** When
it is `None` (the default), disputes are **disabled**: both `OpenDispute` and
`ResolveDispute` are rejected with `Failed(353)` — there is no way to open a
dispute that could deadlock a claim with no resolution path. `OpenDispute` itself
needs no approvals (it only requires the dispute threshold to be configured);
approvals are required only for `ResolveDispute`. **Escrow / fund / claim / refund
all still work normally when the threshold is `None`** — only the dispute
mechanism is off. Configuring the dispute threshold is a separate, coordinated
decision from enabling settlement.

## Activation & chain parameters

Ships dormant behind:

- `inference_settlement_enabled_from_height: Option<u64>` (default `None`) — gate.
- `inference_settlement_max_dispute_window_blocks: u64` — ceiling on a session's dispute window.
- `inference_settlement_max_session_duration_blocks: u64` — ceiling on escrow lock-up.
- `inference_settlement_dispute_threshold_bps: Option<u16>` (default `None`) — validator-quorum threshold (basis points of the active validator set) that must sign `ResolveDispute`; disputes disabled when unset (`None`). **On mainnet this is set to `6667`** (both validators of the current 2-validator net must sign).
- `inference_settlement_consistency_enabled_from_height: Option<u64>` (default `None`) — consistency/plurality mode gate (issue #77). When unset or unreached, a session cannot opt into a consistency rule (`Failed(361)`); single-verifier v1 claims are unaffected. Not part of the mainnet 8,900,000 cohort — an operator sets a height to activate it.
- `inference_verifier_bonding_enabled_from_height: Option<u64>` (default `None`) — verifier bonding + slashing gate (issue #78). When unset or unreached, bond-registry ops and bond-requiring `OpenSession` fail `Failed(364)`; sessions without a bond requirement are unaffected. Not part of the 8,900,000 cohort.
- `inference_verifier_unbonding_period_blocks: u64` (default ~201,600 ≈ 7 days) — delay between `BeginVerifierUnbond` and a permitted `WithdrawVerifierBond`.

Below the gate, all settlement operations are rejected with `Failed(350)` (no
fee, no state change). Attestation recording is unaffected either way.

## Transactions (`TxPayload::InferenceSettlement`, wire index 24)

| Operation | Who | Effect |
|---|---|---|
| `OpenSession` | funder | Create + fund a session; debits the deposit. |
| `FundSession` | funder | Top up `remaining_escrow`. |
| `ClaimReward` | verifier (self) | Pay the fixed reward after maturity; one per verifier. |
| `OpenDispute` | funder | Record a dispute (during window) that withholds a verifier's claim. Requires the dispute threshold to be configured; no approvals. |
| `ResolveDispute` | validator quorum | Allow or deny the disputed claim; requires a threshold of the active validator set to sign (approvals). |
| `RefundSession` | funder | Refund remaining escrow once closable. |

## RPC (read-only + unsigned builders, no keys)

- `omninode_getInferenceSession(session_id)`
- `omninode_getInferenceClaims(session_id)`
- `omninode_getInferenceDisputes(session_id)`
- `omninode_getClaimableReward(session_id, verifier)` — eligibility, amount, unlock height, and (for consistency sessions) the consistency evaluation `{ required_min, threshold_bps, max_verifiers, matching_count, satisfied }`.
- `omninode_getInferenceConsistency(session_id)` — the session's rule plus attestations grouped by the full digest tuple, with per-group `verifier_count` and currently-`eligible_count` (finalized + undisputed).
- `omninode_getVerifier(verifier)` — a verifier's bond record: `bond`, `status` (`Active`/`Unbonding`/`Withdrawn`), and unbonding timers (issue #78). `null` if never registered.
- `omninode_build{Open|Fund}InferenceSession`, `omninode_buildClaimInferenceReward`, `omninode_build{Open|Resolve}InferenceDispute`, `omninode_buildRefundInferenceSession` — return an unsigned `TransactionV2` (hex) + signing hash. `omninode_buildOpenInferenceSession` accepts optional `consistency` `{ min_matching_verifiers, threshold_bps }` and `bond_requirement` `{ min_bond, slash_bps_on_denied_dispute }` configs. `omninode_buildResolveInferenceDispute` accepts an optional `approvals` list of validator signatures (validator-quorum authorization).
- `omninode_build{RegisterVerifier, AddVerifierBond, BeginVerifierUnbond, WithdrawVerifierBond}` — verifier bond-registry builders (issue #78).

### Signed-submission wire format (no raw concatenation)

The builder → sign → submit flow is entirely bincode-of-struct at both stages;
nothing is hand-concatenated:

1. **Builder output.** A builder returns `unsigned_tx` = `bincode(TransactionV2)`
   (hex, `0x`-prefixed) plus `signing_hash` = `TransactionV2::signing_hash()`.
   For a claim, the tx is `TxPayload::InferenceSettlement(InferenceSettlementTxData
   { operation: ClaimReward { session_id } })`.
2. **Sign offline.** `signature = Ed25519.sign(signing_hash.as_bytes())` with the
   verifier's key. No key ever reaches the RPC.
3. **Submit hex.** The raw tx submitted to `sum_sendRawTransaction` is
   `bincode(SignedTransaction { inner: TxInner::V2(tx), signature, public_key })`
   (hex), i.e. `SignedTransaction::new_v2(tx, signature, public_key).to_hex()`.
   This is **not** `unsigned_tx` with the signature appended — it is the bincode
   encoding of the whole `SignedTransaction`, and `SignedTransaction::from_hex`
   round-trips it exactly. See the fixture
   `crates/crypto/tests/omninode_claim_assembly.rs`.

## Receipt codes (isolated 350-block)

`350` not enabled · `351` malformed/unsupported op · `352` session not found/duplicate ·
`353` unauthorized (insufficient validator approvals, or dispute threshold not configured) · `354` invalid session terms
(incl. expiry before finality + dispute window) · `355` insufficient escrow/deposit ·
`356` attestation not found · `357` claim not mature (needs finality_depth + dispute window) ·
`358` duplicate claim/dispute · `359` unresolved/denied dispute blocks settlement ·
`360` refund not available (not closable, or a claim is still within its maturity window) ·
`361` consistency mode not enabled at this height · `362` insufficient verifier consistency for claim ·
`363` invalid consistency configuration ·
`364` verifier bonding not enabled at this height · `365` invalid bond amount/requirement config ·
`366` verifier already registered · `367` verifier not registered ·
`368` verifier not active (unbonding/withdrawn) · `369` verifier unbonding not yet mature ·
`370` insufficient verifier bond for claim.

## Privacy

Only commitments/metadata are on chain, exactly as for attestations — no prompts or
responses. Settlement adds public funder addresses, reward amounts, and claim/dispute
status. Dispute evidence is an opaque commitment, never plaintext.

## Shipped since v1

- Sponsored attestation (`sender ≠ verifier`) — **shipped** as the append-only
  `InferenceAttestationV2` envelope (issue #79), gated by
  `omninode_sponsored_attestation_enabled_from_height`. The verifier remains the
  attestation identity and the settlement reward recipient; only who pays to
  submit changes. Additive sponsor metadata (issue #95) is queryable via
  `sum_getInferenceAttestationSponsor`. See
  [`INFERENCE-ATTESTATION.md`](./INFERENCE-ATTESTATION.md) §11a.

> Consistency/plurality reward mode shipped in v1.1 (issue #77, gated by
> `inference_settlement_consistency_enabled_from_height`) — see **Consistency /
> plurality mode** above. Verifier bonding + slashing shipped in issue #78 (gated
> by `inference_verifier_bonding_enabled_from_height`) — see **Verifier bonding
> and slashing** above.

> This subprotocol is **deployed and code-backed on mainnet** with
> `inference_settlement_enabled_from_height` set to height 8,900,000 (active
> ≈2026-07-12) and `inference_settlement_dispute_threshold_bps` set to `6667`
> (both validators of the 2-validator net must sign `ResolveDispute`). It
> auto-activates when the chain crosses 8,900,000. The consistency gate is
> **not** part of that cohort and remains unset until an operator configures it.

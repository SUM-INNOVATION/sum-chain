# OmniNode Inference Settlement (issue #61)

> **Status:** code-backed, **dormant** (implemented behind an activation gate;
> not activated on mainnet). Activation is a coordinated validator upgrade that
> sets `inference_settlement_enabled_from_height`.

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
- **No bond slashing in v1.** There is no on-chain verifier bond, so there is
  nothing to slash. v1's economic levers are **reward denial**, **claim
  withholding**, **escrow refund**, and **dispute records**. Bond slashing is a
  future (v2) feature that requires a verifier-bond registry.
- **Attestation v1 is untouched.** `InferenceAttestationDigest`,
  `InferenceAttestationTxData`, and the attestation column families are read-only
  from settlement's perspective and are never mutated.

## Model

A session is opened and funded by a **funder** (the requester/payer), who sets a
fixed `reward_per_verifier`, a `max_verifiers` cap, a `dispute_window_blocks`, and
an `expires_at_height`. Escrow is tracked as `remaining_escrow` in the session
record.

A **verifier** who produced an attestation for that session may **self-claim** the
fixed reward once the claim is *mature* — after the attestation is finalized and
the dispute window has elapsed (`attestation.included_at_height +
dispute_window_blocks`). Each verifier can claim once, up to `max_verifiers`,
while escrow remains.

The funder may **refund** the remaining escrow once the session is closable
(expired or fully claimed) and no dispute is left unresolved.

## Disputes (record-only, neutral resolver)

Disputes are **record-only** — the chain cannot verify inference correctness. A
dispute is raised by the funder during the dispute window against a specific
verifier and carries only an opaque `evidence_commitment` (a hash; **no plaintext
evidence on chain**). It **withholds** that verifier's claim until resolved.

Resolution is performed by a **neutral configured resolver**
(`inference_settlement_dispute_resolver`) — deliberately *not* the funder, so the
funder is never both accuser and judge. Only that resolver may `ResolveDispute`. A
resolution either **allows** the claim to proceed or **denies** it (the verifier's
reward is withheld; escrow stays refundable to the funder).

**Disputes require `inference_settlement_dispute_resolver` to be set.** When it is
`None` (the default), both `OpenDispute` and `ResolveDispute` are rejected with
`Failed(353)` — disputes are simply unavailable, and there is no way to open a
dispute that could deadlock a claim with no resolution path. **Escrow / fund /
claim / refund all still work normally when the resolver is `None`** — only the
dispute mechanism is off. Configuring a resolver is a separate, coordinated
decision from enabling settlement.

## Activation & chain parameters

Ships dormant behind:

- `inference_settlement_enabled_from_height: Option<u64>` (default `None`) — gate.
- `inference_settlement_max_dispute_window_blocks: u64` — ceiling on a session's dispute window.
- `inference_settlement_max_session_duration_blocks: u64` — ceiling on escrow lock-up.
- `inference_settlement_dispute_resolver: Option<Address>` (default `None`) — neutral dispute resolver; disputes disabled when unset.

Below the gate, all settlement operations are rejected with `Failed(350)` (no
fee, no state change). Attestation recording is unaffected either way.

## Transactions (`TxPayload::InferenceSettlement`, wire index 24)

| Operation | Who | Effect |
|---|---|---|
| `OpenSession` | funder | Create + fund a session; debits the deposit. |
| `FundSession` | funder | Top up `remaining_escrow`. |
| `ClaimReward` | verifier (self) | Pay the fixed reward after maturity; one per verifier. |
| `OpenDispute` | funder | Record a dispute (during window) that withholds a verifier's claim. Requires a configured resolver. |
| `ResolveDispute` | resolver | Allow or deny the disputed claim. |
| `RefundSession` | funder | Refund remaining escrow once closable. |

## RPC (read-only + unsigned builders, no keys)

- `omninode_getInferenceSession(session_id)`
- `omninode_getInferenceClaims(session_id)`
- `omninode_getInferenceDisputes(session_id)`
- `omninode_getClaimableReward(session_id, verifier)` — eligibility, amount, unlock height.
- `omninode_build{Open|Fund}InferenceSession`, `omninode_buildClaimInferenceReward`, `omninode_build{Open|Resolve}InferenceDispute`, `omninode_buildRefundInferenceSession` — return an unsigned `TransactionV2` (hex) + signing hash.

## Receipt codes (isolated 350-block)

`350` not enabled · `351` malformed/unsupported op · `352` session not found/duplicate ·
`353` unauthorized · `354` invalid session terms · `355` insufficient escrow/deposit ·
`356` attestation not found/not finalized · `357` dispute window not elapsed (claim not mature) ·
`358` duplicate claim/dispute · `359` unresolved/denied dispute blocks settlement ·
`360` refund not available yet.

## Privacy

Only commitments/metadata are on chain, exactly as for attestations — no prompts or
responses. Settlement adds public funder addresses, reward amounts, and claim/dispute
status. Dispute evidence is an opaque commitment, never plaintext.

## Not in v1 (future)

- Verifier-bond registry and **bond slashing** (v2).
- Consistency/plurality reward mode (reward only verifiers whose digest matches the
  session plurality) — objectively checkable on chain; a candidate v1.1/v2 addition.
- Sponsored attestation (`sender ≠ verifier`) — requires `InferenceAttestationV2`.

> This subprotocol is **not active on mainnet**; it is dormant until an operator
> configures `inference_settlement_enabled_from_height`.

# BR1 — Scalar-Share DKG + Chained Threshold-BLS Beacon (Security Design DRAFT)

> # ⚠ DRAFT — NOT CONSENSUS
> **This is a security-DESIGN draft, not an adopted specification.** With one
> exception (below), nothing here is ratified, adopted reference behavior, or
> consensus-normative. In particular, **the beacon domain-separation strings and
> message/preimage layouts (§12, §5, §8) are OWNER DECISIONS that have NOT been
> adopted** — they are PROPOSED constructions pending owner ratification, not
> frozen consensus bytes. Only items fixed by an external standard (the BLS
> ciphersuite draft, RFC 9380, SHA-256, BLAKE3, little-endian integer encoding)
> are treated as normative here.
>
> **RATIFIED EXCEPTION — key-lifecycle direction (owner decision, 2026-07).** The
> owner has **ratified the K-rotate encryption-key lifecycle** as the **normative
> key-management direction** (§11, §16.1): genuinely fresh per-epoch encryption
> keys, keyed by `(chain_id, validator, epoch)`, registered-before-cutoff,
> epoch-scoped decryption, bounded retention then secure erase, with cross-epoch
> reuse / static-key fallback / master-secret derivation **forbidden**. This is
> the ONLY ratified element. It fixes the *direction and rules* only — it does
> **not** ratify any exact CF encoding, W1b ordinal, receipt integer, or timing
> magnitude, all of which remain OPEN. Everything else in this document
> (DLEQ, complaint, threshold, carrier, encodings, W1b, audit) stays DRAFT — NOT
> CONSENSUS.

> **Status:** DRAFT SECURITY-DESIGN — not adopted, not ratified, not implemented,
> not activated. This document proposes constructions, threat model, and security
> goals for the BR1 randomness beacon (issue #127). It is an **activation
> blocker**: an independent cryptographic audit of the on-chain DKG, complaint
> adjudication, and threshold combine must pass before any implementation is
> activated (`beacon_enabled_from_height = None` until then).
> **Umbrella:** issue #127 (BR1) · **Depends:** #126 (VT1, n ≥ 5), #125 (W1b wire),
> #123 (B0). · **Reference implementations cited (not vendored here):**
> `celo-threshold-bls-rs`, `blst`, `arkworks`.
>
> This is an IMPLEMENTER's design draft authored for a separate reviewer. It treats
> as **normative** only what an external standard fixes; everything the #127 issue
> body describes about beacon tags / message layout / DLEQ / ECIES is **PROPOSED
> (owner decision, not adopted)**, and every remaining primitive choice is marked
> **OPEN** in the decision table (§15). Where two constructions differ in *security*
> (not merely engineering), the dispute is escalated for owner adjudication (§16).
> Nothing here asserts activation heights, W1b transaction ordinals, #125-owned
> on-chain operation encodings, or any protocol `.hash`.

---

## 0. Scope, non-goals, and prohibitions

**In scope (this document).** Precise definitions, equations, transcripts, domain
separation, threat model, and security goals for: (a) the scalar-share
drand/GJKR/Pedersen "New-DKG" over BLS12-381; (b) the threshold-BLS partial /
combine; (c) the chained beacon; (d) per-phase topology; (e) Option-1 liveness;
(f) objective-only penalties; (g) reorg atomicity. Plus machine-checkable test
vectors (§14): normative ones for the parts fixed by an external standard, and
clearly-labelled **PROPOSED** ones for the #127 beacon tags / preimage layouts.

**Out of scope / non-goals.** Consuming the beacon (C1); pool logic; any
consensus-enforced mempool inclusion (explicitly rejected — Option 1). No
production key generation, no live signing, no wire encodings (owned by #125/W1b),
no activation constants.

**Hard prohibitions honoured here.** No activation, no production deployment, no
cloud provisioning, no authoritative evidence, no protocol `.hash`, no fabricated
constants. Test vectors assert bytes **only** where either (a) an external standard
(RFC 9380, the BLS ciphersuite draft, SHA-256, BLAKE3, LE integer encoding)
determines them exactly — these are **normative**; or (b) a #127 **PROPOSED** tag /
preimage layout is checked as a proposed (not consensus) construction — these are
labelled **PROPOSED** and are explicitly **not** frozen consensus bytes. Everything
else is marked non-normative / TODO.

---

## 1. Notation, groups, and system parameters

### 1.1 Curve and fields

BLS12-381 (as standardised for `blst`/RFC 9380):

| Symbol | Meaning |
|---|---|
| `F_r` | scalar field, prime order `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| `G1` | subgroup of order `r` in `E(F_q)`; generator `g1` (RFC 9380 fixed generator) |
| `G2` | subgroup of order `r` in `E'(F_{q^2})`; generator `g2` |
| `G_T` | target group; pairing `e : G1 × G2 → G_T` |
| `H_{G2}` | hash-to-curve into `G2` (RFC 9380 suite `BLS12381G2_XMD:SHA-256_SSWU_RO_`) |

**Group placement (minimal-pubkey-size / "G1 public keys, G2 signatures").**
Verification keys and Feldman commitments live in `G1`; signatures live in `G2`.
This is the `blst` / draft-irtf-cfrg-bls-signature "minimal-pubkey-size"
placement and matches the issue's `C_{i,k} = g1^{a_{i,k}}` (commitments in G1) and
`sigma_j = H_{G2}(m_r)^{sk_j}` (signatures in G2).

### 1.2 Fault and threshold parameters (specified in #127; pending adoption)

| Symbol | Value | Meaning |
|---|---|---|
| `f` | `1` | Byzantine faults tolerated |
| `c` | `1` | additional crash slack |
| `T` | `f + 1 = 2` | **reconstruction threshold** (partials needed to combine; polynomial degree `= T − 1 = 1`) |
| `Q_dkg` | `2f + 1 = 3` | **QUAL / qualification size** (minimum qualified dealers for DKG success) |
| `n_crypto` | `2f + c + 1 = 4` | crypto minimum for beacon signing |
| `n_product` | `3f + 1 + c = 5` | product predicate; the topology guard enforces `n ≥ 5` |

`T` and `Q_dkg` are **distinct axes** — see §7. `T` bounds forgery/reconstruction;
`Q_dkg` bounds how many dealers must qualify for the group key to exist.

### 1.3 Indices and identifiers

- Participants are addressed by a 0-based array index `j ∈ {0, …, n−1}` drawn from
  the epoch **membership snapshot** (`beacon_getMembershipSnapshot(epoch)`), whose
  ordering is canonical (see §4.1).
- The **scalar evaluation point** for participant `j` is `x_j = (j + 1) mod r`
  (§3). Never `0`.

---

## 2. Ciphersuites, subgroup & infinity checks, PoP, partial verification

### 2.1 Ciphersuite identifiers (normative — fixed by the BLS ciphersuite draft)

The proof-of-possession (POP) scheme, minimal-pubkey-size (G1 public keys, G2
signatures). **Authority revision pinned per string** so a reviewer can check each
against the cited document:

| Use | ASCII identifier / DST | Authority (exact revision, primary-source-verified) |
|---|---|---|
| Signing (CoreSign / partial signatures) | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` | `draft-irtf-cfrg-bls-signature-05` (**16 June 2022**), §4.2.3 "Proof of possession" ciphersuite; `CoreSign` §2.6. Hash-to-curve component per RFC 9380. |
| Proof of possession | `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` | `draft-irtf-cfrg-bls-signature-05` (**16 June 2022**), §3.3 `PopProve`/`PopVerify` (§3.3.2/§3.3.3); §4.2.3 POP ciphersuite. |
| Hash-to-curve suite | `BLS12381G2_XMD:SHA-256_SSWU_RO_` | **RFC 9380** (**August 2023**, final), §8.8.2 "BLS12-381 G2" suite (`expand_message_xmd` §5.3.1 with SHA-256, `hash_to_field` §5.2, map SSWU, RO encoding). |

Notes for the reviewer (all citations checked against the primary IETF sources on
2026-07-21): the hash-to-curve suite id `BLS12381G2_XMD:SHA-256_SSWU_RO_` is the
RFC 9380 §8.8.2 registered suite (RFC 9380, August 2023). The two
`BLS_SIG_…_POP_` / `BLS_POP_…_POP_` strings are the
draft-irtf-cfrg-bls-signature-**05** (16 June 2022) proof-of-possession
ciphersuite ids (§4.2.3), minimal-pubkey-size placement (G1 public keys, G2
signatures). The `draft-irtf-cfrg-bls-signature` series has since advanced to
**-07 (6 July 2026)**; the ciphersuite strings and the `KeyValidate`/`PopProve`/
`PopVerify`/`CoreSign` constructions are stable across -05…-07, and -05 is the
revision the cited reference implementations (`blst`, `celo-threshold-bls-rs`,
Ethereum consensus) deploy — so the pin remains -05 with the -07 pointer noted.
The signing DST used inside `hash_to_point` for CoreSign is the signing
ciphersuite string above; the PoP DST is the PoP string above. These byte strings
are asserted in the vector test (§14, `T-1`, which are the standard-fixed /
**normative** vectors).

### 2.2 Subgroup and point-at-infinity checks (normative)

Every group element deserialised from untrusted bytes (a deal commitment, a
registered verification key, a partial signature, a combined signature, a PoP)
MUST pass, **before any use**:

1. **On-curve** decode (reject non-canonical encodings; enforce the compression
   / sign conventions of the ZCash/`blst` serialisation).
2. **Subgroup membership**: the point is in the order-`r` subgroup
   (`blst_p1_in_g1` / `blst_p2_in_g2`; equivalently `KeyValidate`'s subgroup
   check). Points on the curve but outside the prime-order subgroup are rejected
   — this blocks small-subgroup / cofactor attacks.
3. **Infinity rejection where it would trivialise a check**:
   - a registered verification key equal to the identity `O_{G1}` is rejected
     (`KeyValidate` rejects the identity — otherwise `e(O, ·) = 1` verifies
     everything);
   - a partial signature or a combined signature equal to `O_{G2}` is rejected;
   - a Feldman commitment coefficient `C_{i,0} = O_{G1}` (dealer contributes a
     zero constant term) is rejected at deal-validation time.

Rationale: the identity element makes pairing checks degenerate and enables
rogue-key / zero-share griefing. `KeyValidate` (draft-irtf-cfrg-bls-signature §2.5)
is the canonical composite of on-curve + subgroup + non-identity.

### 2.3 Proof of Possession (normative construction)

Each node registering a beacon verification key `vk = g1^{sk}` (via the
`RegisterBeaconKeyV1` operation, encoding owned by #125) MUST attach a PoP:

```
PopProve(sk):
    pk   = g1^{sk}                                  # in G1
    Q    = H_{G2}(serialize(pk); DST = BLS_POP_…POP_)   # hash the pubkey bytes
    pop  = Q^{sk}                                    # in G2
    return pop

PopVerify(pk, pop):
    require KeyValidate(pk)                          # §2.2
    require pop ∈ G2 and pop ≠ O_{G2}
    Q = H_{G2}(serialize(pk); DST = BLS_POP_…POP_)
    return  e(g1, pop) == e(pk, Q)
```

PoP binds the key to knowledge of `sk`, preventing registration of a key whose
secret the registrant does not hold (defence against rogue-key attacks in any
context where verification keys are summed).

### 2.4 Partial-signature verification (normative)

For round message `m_r` (§12), participant `j`'s partial is
`sigma_j = H_{G2}(m_r; DST = BLS_SIG_…POP_)^{sk_j}`. Its per-participant
verification key is

```
vk_j = Σ_{i ∈ QUAL} Σ_{k=0}^{T−1} [x_j^k] · C_{i,k}          (in G1)
```

where `[x_j^k]` is scalar multiplication by `x_j^k mod r` and `x_j = j + 1`
(§3). The partial verifies iff

```
e(g1, sigma_j) == e(vk_j, H_{G2}(m_r))
```

with `sigma_j` first passing the §2.2 subgroup + infinity checks. Exactly **one
pairing product** per partial-verify (the two pairings are checked as a single
multi-pairing `e(g1, sigma_j) · e(−vk_j, H(m_r)) == 1`).

---

## 3. Share evaluation at `index + 1` (why the `+1`, and the domain)

Dealer `i` samples a degree-`(T−1)` polynomial over `F_r`:

```
f_i(x) = a_{i,0} + a_{i,1}·x + … + a_{i,T−1}·x^{T−1}          (a_{i,k} ∈ F_r)
```

with commitments `C_{i,k} = g1^{a_{i,k}}`. The **secret contribution** of dealer
`i` is `a_{i,0} = f_i(0)`. The share dealt to participant `j` is
`s_{ij} = f_i(x_j)`.

**Why `x_j = j + 1`, never `x_j = j`.** Evaluating the sharing polynomial at
`x = 0` returns the secret constant term `a_{i,0}` directly. If any participant's
evaluation point were `0`, that participant would receive the dealer's secret in
the clear, collapsing the DKG. The map from the 0-based membership index `j` to a
**nonzero** scalar is therefore `x_j = (j + 1) mod r`. With `n ≪ r` (here `n = 5`
against a ~255-bit `r`), `j + 1` is never `0` and all `x_j` are distinct nonzero
field elements. This matches the `celo-threshold-bls-rs` convention of 1-based
share ids (`id = index + 1`).

**Domain.** The evaluation domain is `F_r^{*}` (nonzero scalars). Canonical: the
membership snapshot fixes the index order; the scalar is `j + 1` reduced mod `r`;
Lagrange interpolation (§4) treats `{x_j}` as distinct nonzero nodes and
reconstructs at the evaluation point `0` (the secret).

---

## 4. QUAL aggregation and EXACTLY-T sorted Lagrange combination

### 4.1 Canonical ordering

Two orderings are fixed and used consistently:

- **Membership order** — the order of participants in
  `beacon_getMembershipSnapshot(epoch)`; defines `j` and thus `x_j = j + 1`.
- **QUAL order** — `QUAL ⊆ {dealers}` sorted ascending by membership index `j`.
  All sums over `QUAL` (below) are evaluated in this canonical order so the group
  key and per-node verification keys are byte-reproducible across implementations.

### 4.2 QUAL set and aggregation

`QUAL` is the set of dealers **not disqualified** by adjudicated complaints
(§6). The DKG **succeeds iff `|QUAL| ≥ Q_dkg = 2f + 1`**; otherwise it enters
**safe halt** (§ Option-1, no key is produced). On success:

```
group public key   PK_E = Σ_{i ∈ QUAL} C_{i,0}                       (G1)
participant share  sk_j = Σ_{i ∈ QUAL} s_{ij}          (scalar in F_r)
participant vk     vk_j = Σ_{i ∈ QUAL} Σ_{k} [x_j^k] · C_{i,k}        (G1)
```

`sk_j` is a **native scalar** BLS signing share (the whole point of BR1: an
aggregatable-PVSS / Ferveo DKG would yield *group-element* shares that cannot be
used as a BLS exponent). Consistency: `vk_j = g1^{sk_j}` and
`PK_E = g1^{sk}` with `sk = Σ_{i∈QUAL} a_{i,0}` the (never-reconstructed) group
secret. `PK_E` is fixed **per epoch**; each round produces exactly one output
under it.

### 4.3 EXACTLY-T sorted Lagrange combine (in G2)

Given a set `S` of *verified* partials (each having passed §2.4), the combiner:

1. discards any partial that fails §2.4 (invalid partials must never enter the
   interpolation — one bad partial corrupts the result);
2. sorts the valid contributors ascending by `x_j`;
3. selects **exactly `T`** of them — the first `T` in that order
   (`|selection| = T`, not `≥ T`);
4. computes Lagrange coefficients at the interpolation point `0`:

```
λ_k = Π_{l ∈ selection, l ≠ k}  x_l / (x_l − x_k)      (mod r)
Σ   = Σ_{k ∈ selection}  [λ_k] · sigma_k                (in G2)
```

**Why exactly `T` and canonical.** Threshold BLS gives a *unique* group signature
`Σ = H_{G2}(m_r)^{sk}` for **any** valid `T`-subset (interpolation recovers the
same `sk` in the exponent), so the *value* is subset-independent when all selected
partials are valid. Fixing "exactly `T`, canonically sorted" is required for two
operational reasons, not for the value's correctness:

- **Determinism / reproducibility.** The on-chain combine artifact and any
  witness must be byte-identical across honest combiners and across architectures
  (acceptance criterion: "pairing verify bit-identical cross-arch"). A canonical
  exactly-`T` selection removes the free choice of subset.
- **DoS / cost bound.** Rejecting `> T` inputs caps combine cost at one Lagrange
  interpolation over `T` points and prevents a malicious combiner from padding the
  set with (possibly invalid) extras.

The combined `Σ` is re-verified as an ordinary signature under `PK_E`:
`e(g1, Σ) == e(PK_E, H_{G2}(m_r))`.

---

## 5. DLEQ (Chaum-Pedersen equality-of-discrete-logs) — full construction

A complaint (§6) makes decryption **publicly verifiable** without the complainant
revealing their static decryption key. The complainant reveals the ECDH shared
secret and proves, in zero knowledge, that it was computed with the *same* secret
key that their registered encryption key commits to.

### 5.1 Group and generators

The DLEQ is over the ECIES key group `G_enc` with fixed generator `h`
(see §8 for the choice of `G_enc`; the DLEQ construction below is written
group-generically and is identical whichever `G_enc` is ratified). Write
group operations multiplicatively; scalars are mod the group order `ρ` of
`G_enc`.

### 5.2 Statement proved

Public inputs: `(h, EK_j, R_{ij}, D_{ij})` where
- `EK_j = h^{ek_j}` is participant `j`'s registered encryption key,
- `R_{ij} = h^{r_{ij}}` is the dealer's ephemeral carrier for the `(i, j)`
  ciphertext (published in the deal),
- `D_{ij}` is the value the complainant *claims* is the ECDH secret
  `R_{ij}^{ek_j}`.

The DLEQ proves the **statement**:

```
∃ ek_j :  EK_j = h^{ek_j}  ∧  D_{ij} = R_{ij}^{ek_j}
```

i.e. `log_h(EK_j) = log_{R_{ij}}(D_{ij})`. This certifies that `D_{ij}` is the
unique ECDH secret for the published carrier and the registered key, so anyone can
derive the symmetric key from `D_{ij}` (§8.3) and decrypt the on-chain ciphertext
deterministically.

### 5.3 Transcript layout and domain separation

Let `DST_DLEQ = "OMNINODE-DKG-DLEQ:v1:"` (a #127 **PROPOSED** domain tag — owner
decision, not adopted; the **serialisation and hash-to-scalar** are OPEN — see
§15, decision-table #22/#23). All group
elements are serialised with the canonical compressed encoding of `G_enc`. The
Fiat-Shamir challenge binds every public input and both commitments:

```
transcript(A1, A2) =
    DST_DLEQ
  ‖ chain_id
  ‖ u64_le(epoch)
  ‖ u32_le(dealer_index i)
  ‖ u32_le(recipient_index j)
  ‖ serialize(h)
  ‖ serialize(EK_j)
  ‖ serialize(R_{ij})
  ‖ serialize(D_{ij})
  ‖ serialize(A1)
  ‖ serialize(A2)

c = HashToScalar(transcript(A1, A2))  mod ρ
```

`HashToScalar` is RFC 9380 `hash_to_field(msg, 1)` with `expand_message_xmd`
(SHA-256) and `DST = DST_DLEQ`, reduced mod `ρ` (RECOMMENDED; OPEN — §15).
Binding `chain_id`, `epoch`, `i`, `j` prevents cross-context replay of a proof.

### 5.4 Prover (complainant, holds `ek_j`)

```
1. sample  k  ←$ scalars mod ρ           (fresh, from a CSPRNG)
2. A1 = h^{k}
   A2 = R_{ij}^{k}
3. c  = HashToScalar(transcript(A1, A2))
4. z  = k + c · ek_j   (mod ρ)
5. output complaint = { i, j, R_{ij}, D_{ij}, proof = (c, z) }
```

`(c, z)` is the compact form; the equivalent `(A1, A2, z)` form is acceptable and
recomputes `c` on both sides.

### 5.5 Verifier (on-chain, deterministic)

```
1. require  EK_j, R_{ij}, D_{ij}, h  pass §2.2-style subgroup/infinity checks in G_enc
2. A1' = h^{z} · EK_j^{−c}
   A2' = R_{ij}^{z} · D_{ij}^{−c}
3. c'  = HashToScalar(transcript(A1', A2'))
4. accept iff  c' == c
```

Soundness: a prover without `ek_j` s.t. both equations hold can only pass with
negligible probability (special-soundness of Chaum-Pedersen). Zero-knowledge:
`k` blinds `ek_j`, so the proof reveals nothing about `ek_j` beyond the asserted
equality. **The static key `ek_j` itself is never revealed** — only `D_{ij}`, the
single per-`(i,j)` ECDH secret, is disclosed (leakage accounting: §9).

---

## 6. Complaint evidence, deterministic adjudication, dealer response, false-accuser policy

### 6.1 Deterministic adjudication — NO count / majority rule

Adjudication is a **pure function of on-chain data**; there is no vote and no
threshold-of-accusers. Given a `DkgComplaintV1{ i, j, R_{ij}, D_{ij}, dleq }`
against dealer `i`'s deal to recipient `j`, the chain executes deterministically:

```
adjudicate(complaint, deal_i):
    if not DLEQ_verify(h, EK_j, R_{ij}, D_{ij}, dleq):         # §5.5
        return REJECT_COMPLAINT_MALFORMED   # complaint invalid → no effect on i
    key   = KDF(D_{ij}, aad)                                   # §8.3
    s_ij  = AEAD_open(key, nonce, ct_{ij}, aad)                # deterministic decrypt
    if AEAD_open failed:
        return DISQUALIFY(i)                # ciphertext undecryptable under the
                                            # proven secret ⇒ dealer misbehaved
    feldman_ok = ( g1^{s_ij} == Π_{k=0}^{T−1} C_{i,k}^{ (x_j^k mod r) } )   # §6.2
    if feldman_ok:
        return SLASH_FALSE_ACCUSER(j)       # share was valid ⇒ complaint is false
    else:
        return DISQUALIFY_AND_SLASH(i)      # share invalid ⇒ dealer disqualified
```

Every branch is a deterministic re-computation. The outcome is identical for every
honest validator; there is no "how many complained" input. This is the issue's
"evidence-based complaints (no count/majority)".

### 6.2 Feldman check

The recipient (and, on complaint, every validator) verifies a decrypted scalar
share against the public commitments:

```
g1^{s_ij}  ==  Π_{k=0}^{T−1}  C_{i,k}^{ (x_j^k mod r) }        (in G1)
```

A share failing this check is invalid; if it was *encrypted* correctly (decrypts
cleanly) but is inconsistent with the commitments, the dealer is culpable.

### 6.3 Dealer response and the adjudication ordering

The complaint reveals `D_{ij}` via the recipient's key. A dealer accused falsely
(or wishing to pre-empt a griefing recipient) MAY respond by revealing the
**carrier secret** `r_{ij}` with a Schnorr/DLEQ proof that `R_{ij} = h^{r_{ij}}`;
the chain then independently recomputes `D_{ij}' = EK_j^{r_{ij}}` and decrypts,
closing the "carrier gap" (§9) from the dealer's side. Because both the
complainant's path (via `ek_j`) and the dealer's path (via `r_{ij}`) recompute the
**same** `D_{ij}` and then run the **same** deterministic decrypt+Feldman check,
the adjudication result is independent of which party supplied the reveal — there
is a single deterministic verdict, not a dispute to be voted on.

### 6.4 False-accuser policy (objective, symmetric)

- Valid dealing proven good ⇒ **the complainant is slashed** (`SLASH_FALSE_ACCUSER`)
  and the dealer stays in `QUAL`.
- Invalid dealing proven bad ⇒ **the dealer is disqualified and slashed**; no
  penalty to the complainant.
- A malformed complaint (DLEQ fails) has **no effect on the dealer** and MAY be
  charged to the complainant as spam (fee-only), never as a share-culpability
  slash.

All penalties are **objective misconduct only** (invalid dealing proven by
complaint; conflicting deals; conflicting partials; invalid signed PoP;
false accusation proven by re-decryption). **Absence is never penalised** (§
Option-1). This is a strict superset of the issue's "penalties objective-only …
never absence".

---

## 7. Threshold assumptions: explicit `T` vs `Q` separation

Two thresholds are frequently conflated; BR1 keeps them **orthogonal**:

| | `T` (reconstruction threshold) | `Q_dkg` (QUAL / qualification size) |
|---|---|---|
| Value | `f + 1 = 2` | `2f + 1 = 3` |
| Governs | how many **partial signatures** interpolate the group signature; equivalently the **degree** of each dealer polynomial (`deg = T − 1`) | how many **dealers** must be non-disqualified for the group key to exist at all |
| Security role | unforgeability: an adversary with `< T` shares cannot sign; liveness: `≥ T` honest online signers can produce the beacon | robustness: `≥ 2f + 1` qualified dealers guarantees `> f` honest contributions to `PK_E`, so no `f`-sized Byzantine dealer coalition controls the group secret |
| Failure mode | `< T` valid partials in a round ⇒ that round safe-halts (no output) | `|QUAL| < 2f + 1` ⇒ the **whole DKG** safe-halts (no `PK_E`) |

Independence matters: one can have `|QUAL| = 3` (DKG succeeded) yet still fail a
*round* because fewer than `T = 2` participants submitted valid partials in that
round's window. Conversely `T` is a property of the sharing polynomials fixed at
DKG time and does not change if extra dealers qualify. The topology guard binds
`n ≥ 5` so that, tolerating `f = 1` Byzantine and `c = 1` crash, at least
`2f + 1 = 3` dealers can qualify and at least `T = 2` signers remain online.

---

## 8. ECIES for scalar shares — group, KDF, AEAD, nonce, AAD, binding, goals

The DKG deal `DkgDealV1` carries, for each recipient `j`, an ECIES ciphertext of
the **scalar** share `s_{ij} ∈ F_r`.

### 8.1 Group `G_enc` (choice is OPEN — see §15/§16)

`G_enc` is the group in which encryption keys `EK_j = h^{ek_j}` live, generator
`h`, order `ρ`. Two ratifiable instantiations (both give equivalent
confidentiality/integrity; they differ in audit surface and performance, not in
the security *goal*):

- **(E-A) Reuse BLS12-381 `G1`** — `h = g1`, `ρ = r`. Single curve for the whole
  subsystem; DLEQ over G1; keys ~48 B compressed. Reference: `celo-threshold-bls-rs`
  encrypts shares to keys in the scheme's public-key group.
- **(E-B) Independent Curve25519 / Ristretto255** — `h` the Ristretto basepoint,
  `ρ` the Ristretto group order. Smaller/faster; reuses the curve already in the
  SRC-201 stack (`crates/crypto/src/messaging.rs`); adds a *second* curve to the
  audit surface, and DLEQ (§5) runs over Ristretto.

Whichever is ratified, the ECIES/DLEQ construction is structurally identical.

### 8.2 KDF, AEAD, nonce, AAD (RECOMMENDED construction; exact primitives OPEN)

Following the pattern already in-tree for SRC-201
(`blake3::derive_key(context, dh) → XChaCha20-Poly1305 with header-as-AAD`):

```
per recipient j, dealer i:
    r_{ij}  ←$ scalars mod ρ                # fresh ephemeral per (i,j)
    R_{ij}  = h^{r_{ij}}                     # carrier, published in the deal
    D_{ij}  = EK_j^{r_{ij}}                  # ECDH secret ( = R_{ij}^{ek_j} )
    key     = KDF(context, serialize(D_{ij}))          # §8.3
    aad     = ECIES_AAD(i, j, epoch, chain_id, R_{ij}) # §8.4  (transcript binding)
    nonce   = fixed 96/192-bit zero nonce  OR  KDF-derived        # §8.5
    ct_{ij} = AEAD_seal(key, nonce, aad, LE_bytes(s_{ij}))        # 32-byte scalar plaintext
```

- **KDF** — `blake3::derive_key(context = "OMNINODE-DKG-ECIES:v1:key", D_ij_bytes)`
  → 32-byte key (RECOMMENDED, matches repo). Alternative: HKDF-SHA-256. **OPEN.**
- **AEAD** — XChaCha20-Poly1305 (RECOMMENDED, matches repo) or AES-256-GCM.
  **OPEN.** Provides confidentiality + integrity of the ciphertext.
- **Plaintext** — the 32-byte canonical little-endian encoding of the scalar
  `s_{ij}` (fixed length; no length side channel).

### 8.3 Symmetric key derivation

`key = KDF(context, serialize(D_{ij}))`. Because the ephemeral `r_{ij}` is fresh
per `(i, j)`, `D_{ij}` (hence `key`) is unique per ciphertext; nonce reuse across
messages is therefore not a hazard even with a fixed nonce.

### 8.4 Associated data and transcript binding

`aad` MUST bind the ciphertext to its context so a ciphertext cannot be replayed
into another `(dealer, recipient, epoch, chain)` slot or re-paired with a
different carrier:

```
ECIES_AAD = "OMNINODE-DKG-ECIES:v1:aad"
          ‖ chain_id
          ‖ u64_le(epoch)
          ‖ u32_le(i) ‖ u32_le(j)
          ‖ serialize(R_{ij})
```

Binding `R_{ij}` into the AAD ties the AEAD tag to the exact carrier used in the
DLEQ statement (§5.2), so complaint adjudication (§6.1) verifies over the same
transcript the sender authenticated.

### 8.5 Nonce derivation

Because `key` is unique per ciphertext (§8.3), a **fixed all-zero nonce** is
sound (RECOMMENDED, minimises bytes on-chain). A KDF-derived nonce
(`nonce = KDF(context_nonce, D_{ij})[..N]`) is an equally-sound alternative.
**OPEN** which is ratified; both avoid catastrophic nonce reuse.

### 8.6 Security goals — what IS and IS NOT guaranteed

**Guaranteed:**
- **Confidentiality** of each scalar share `s_{ij}` against everyone except the
  intended recipient `j` **and** the dealer `i` (the dealer trivially knows the
  share it created — this is not a leak).
- **Integrity / ciphertext authenticity** — the AEAD tag plus AAD binding prevents
  undetected tampering, truncation, or cross-context replay of a ciphertext.
- **Public verifiability of decryption** on complaint — via the DLEQ (§5), any
  party can reproduce the decryption without the recipient's static key.

**NOT guaranteed (explicit non-goals):**
- **No forward secrecy** from the ECIES layer with static recipient keys: an
  attacker who later compromises `ek_j` can decrypt every share ever dealt to `j`
  whose ciphertext is still on-chain (transcripts are permanent state). Forward
  secrecy exists only across **epochs**, and only if nodes actually rotate their
  static encryption key each epoch (§11, §16 — flagged decision).
- **No sender anonymity / no metadata privacy** — dealer, recipient, epoch, and
  carrier are all public (they are consensus inputs).
- **No protection against the dealer** learning/altering its own share (out of
  scope — the dealer authored it; misbehaviour is caught by Feldman + complaint,
  not by encryption).
- **No post-quantum security** (BLS12-381 / discrete-log ECIES).

---

## 9. The dealer `r_{ij}` reveal / carrier gap

**The gap.** The deal publishes the **carrier** `R_{ij} = h^{r_{ij}}` but never the
dealer's ephemeral secret `r_{ij}`. Decryption capability is split:

- the **recipient** can derive `D_{ij} = R_{ij}^{ek_j}` (uses `ek_j`);
- the **dealer** can derive `D_{ij} = EK_j^{r_{ij}}` (uses `r_{ij}`);
- **no third party** can derive `D_{ij}` from public data alone (CDH).

So on the public ledger there is a *gap* between what is carried (`R_{ij}`) and
what is needed to reconstruct `D_{ij}` (either secret). Adjudication (§6) closes
the gap **only** when one of the two secret-holders authenticates a reveal:

- complainant reveals `D_{ij}` + DLEQ over `ek_j` (§5); or
- dealer reveals `r_{ij}` + Schnorr/DLEQ over the carrier (§6.3).

**Consequences (leakage accounting).**
- A reveal exposes exactly **one** per-`(i, j)` ECDH secret and hence exactly one
  dealer-to-recipient share `s_{ij}` — **not** `ek_j`, **not** `r_{ij}` for other
  recipients (each `(i, j)` uses a fresh `r_{ij}`), and **not** the recipient's
  final share `sk_j = Σ_{i∈QUAL} s_{ij}`.
- Security therefore requires the count of exposed *individual dealer shares of a
  single dealer's polynomial* to stay `< T` to keep that dealer's `a_{i,0}` hidden,
  and — more importantly — the group secret `sk` is a **sum over QUAL** of dealer
  constant terms, so exposing shares of one dealer's polynomial never by itself
  reveals `sk`. An adversary must expose `≥ T` shares of the *summed* secret across
  a common set of recipients, which the complaint path does not produce (it exposes
  per-dealer contributions, one at a time, each already authored by a possibly
  honest dealer). The safe design invariant: **treat every adjudicated reveal as a
  disclosed share and require that the number of shares of `sk_j` disclosable this
  way stays below `T`.**
- The gap is *asymmetric* in griefing terms: a recipient can force a public verdict
  unilaterally (DLEQ), whereas a falsely-accused dealer must *choose* to reveal
  `r_{ij}` (thereby publishing that one share) to clear itself. The dealer's clean
  alternative is to have dealt correctly in the first place — a correct share always
  adjudicates as `SLASH_FALSE_ACCUSER(j)` once the complainant's own DLEQ-authenticated
  `D_{ij}` is used, so an honest dealer need not reveal `r_{ij}` at all; the
  `r_{ij}` path exists only for a dealer who wants to pre-empt or who disputes the
  complainant's `D_{ij}` (which the DLEQ already pins).

---

## 10. Reorg-related disclosure / leakage

All DKG/beacon column families are **revertible state**. A reorg that abandons
fork-A and adopts fork-B reverts fork-A's transcripts, keys, and outputs; fork-B
may legitimately carry different deals and therefore a **different** group key and
a **different** beacon (acceptance criterion (e)). This is not a fault — it is the
defined behaviour of a chain without hard finality.

**What a reorg can expose.** Only data that was *already public on the abandoned
fork*:
1. **Partial signatures** that honest nodes broadcast / posted on fork-A, each over
   fork-A's specific round message `m_r^A` (which embeds `compress(Sigma_prev^A)`).
2. **The abandoned fork's beacon output** value(s) `Σ^A` / `beacon^A`.

**What a reorg does NOT expose.** Share plaintexts are **never** on-chain (only
ECIES ciphertexts are), so reverting transcripts leaks **no shares**; `sk_j` and
`sk` are never materialised on-chain in any fork.

**Why the exposed data is harmless — mitigations.**
- **Domain-separated chaining (§12).** `m_r = … ‖ compress(Sigma_prev)`. A partial
  or output produced on fork-A is bound to fork-A's history; on fork-B the message
  differs (`Sigma_prev^B ≠ Sigma_prev^A`), so fork-A partials/outputs neither verify
  nor combine there. Threshold-BLS partials over *different* messages do not
  combine into a forgery.
- **Fresh DKG per epoch.** Group keys are not carried across epochs; a reorg that
  crosses an epoch boundary re-runs the DKG.
- **Consume-after boundary (§12.3).** A beacon output may be *consumed* only after
  it is buried by `finality_depth (6) + MARGIN`. An output that a reorg could
  revert is therefore never consumed, so a "reveal-then-revert" observation cannot
  have influenced any consumer — withholding buys **delay, not bias**.
- **No hard finality assumed.** The design never claims identical-across-reorg
  outputs (a superseded design); it claims *internally-deterministic-per-history*
  outputs with atomic revert.

The only genuine adversary gain from a reorg is **timing**: an adversary who
observes `Σ^A` before it is buried, dislikes it, and can muster enough
reorg power, may replace fork-A with a fork-B that (re-running DKG or a later
round) yields a different `Σ^B`. This is a **grinding-by-reorg / withholding**
concern, bounded by (i) the consume-after boundary (nothing downstream consumed
`Σ^A`), and (ii) the cost of reorging past `finality_depth + MARGIN` blocks under
the chain's longest-chain rule. BR1 reduces beacon bias to **the chain's own
reorg-resistance** — it does not add hard finality.

---

## 11. Encryption-key lifecycle — K-rotate (RATIFIED normative direction)

> **RATIFIED (owner decision, 2026-07).** This section states the **normative**
> encryption-key lifecycle. It is the ONE ratified element of this DRAFT; it fixes
> the *direction and rules* only. Exact CF encodings, the `RegisterBeaconKeyV1`
> wire encoding (owned by #125/W1b), receipt integers, and timing *magnitudes*
> (`MARGIN`, exact complaint-deadline duration) remain **OPEN** and are NOT fixed
> here. The rest of the document stays DRAFT — NOT CONSENSUS.

**Why rotation is mandatory (the threat this closes).** DKG transcripts — the
ECIES ciphertexts `ct_{ij}` and carriers `R_{ij}` — are **permanent on-chain
state**. A *static* encryption key would therefore have **no forward secrecy**: a
single future compromise of `ek_j` decrypts *every* share ever dealt to `j`, and
compromising `≥ T` participants' static keys in a common QUAL/epoch reconstructs
that epoch's group secret **retroactively**. K-rotate bounds any key compromise to
a single epoch. (K-static is REJECTED; see §16.1.)

### 11.1 Normative lifecycle rules (RATIFIED)

Every validator MUST observe all of the following:

1. **Fresh per epoch.** Each validator generates a **genuinely fresh** encryption
   keypair for every epoch (fresh entropy from a CSPRNG).
2. **Key identity.** A key's identity is the triple `(chain_id, validator_identity,
   epoch)`. Transcripts, complaints, and the key column family are scoped by this
   triple (exact CF encoding OPEN).
3. **Register-before-cutoff.** The **next** epoch's public key MUST be registered
   and authenticated on-chain **before that epoch's DKG deal cutoff**; deals for an
   epoch reference only keys already committed for that epoch.
4. **Epoch-scoped decryption.** A key MAY decrypt **only** ciphertexts belonging to
   its designated epoch. Using an epoch key to decrypt another epoch's ciphertext
   is a protocol violation.
5. **Bounded retention.** The private key MUST be retained through **that epoch's
   complaint deadline PLUS its finality/reorg margin** — i.e. at least until
   `max(complaint_deadline, last_referencing_block + finality_depth(6) + MARGIN)`
   (magnitudes OPEN) — so late complaints and reorg replay can still be adjudicated
   (§11.3).
6. **Secure retirement.** When that bounded window ends, the private key MUST be
   **securely zeroised** (best-effort; see §11.4 limitations).
7. **No reuse / no static fallback.** Cross-epoch key reuse and any fallback to a
   long-lived static key are **FORBIDDEN**.
8. **No master-secret derivation.** Epoch keys MUST **not** be derived from a
   single persistent master secret (a KDF chain, an HD-wallet tree, etc.) —
   compromise of the master would defeat historical forward secrecy, re-introducing
   exactly the K-static weakness. Each epoch key is independent fresh randomness.
9. **Missing/invalid next-epoch key ⇒ deterministic exclusion or safe-halt.** A
   validator that fails to register a valid next-epoch key before the cutoff is
   **deterministically excluded** from that epoch's membership, or the ratified
   **SAFE-HALT** path is taken if too few valid keys remain (`< 2f+1` prospective
   dealers). **Never** a static-key fallback.

### 11.2 Key lifecycle state machine

```
   generate ──▶ register ──▶ activate ──▶ retain ──▶ retire ──▶ zeroize
   (fresh       (publish     (epoch e     (hold      (window    (best-effort
    entropy,     next-epoch   is current;  private    ends:      secure
    (chain_id,   pubkey       decrypt      key        stop       erase;
    validator,   BEFORE e's   ONLY epoch   through    accepting  §11.4
    epoch)       deal cutoff) e ciphertx)  complaint  new use)   limits)
                                           + reorg
                                           margin)
```

- **generate** — fresh keypair for epoch `e`; never derived from a master secret
  (rule 8).
- **register** — `RegisterBeaconKeyV1` (encoding #125-owned) publishes the epoch-`e`
  public key with PoP/authentication, **before** epoch `e`'s deal cutoff (rule 3).
- **activate** — epoch `e` is current; the key decrypts only epoch-`e` ciphertexts
  (rule 4).
- **retain** — after epoch `e` closes, the private key is held for the bounded
  window (rule 5) so complaints/reorgs remain adjudicable (§11.3).
- **retire** — window ends; the key accepts no further use.
- **zeroize** — best-effort secure erasure (rule 6; limits §11.4).

Failure edge (rule 9): if `register` does not complete with a valid key before the
cutoff, the validator transitions to **excluded** for that epoch (or the group
takes the SAFE-HALT path) — there is no transition back to a prior/static key.

### 11.3 Safety during the bounded retention window

The retention window (rule 5) exists precisely so that the three time-sensitive
on-chain processes remain sound while a key is still decryptable:

- **Complaint safety.** A complaint against an epoch-`e` deal (§6) may arrive up to
  the epoch-`e` complaint deadline. Adjudication re-derives the ECDH secret and
  re-decrypts; the epoch-`e` key (or, on the dealer side, `r_{ij}`) must still exist
  to let honest parties reproduce the decryption. Retiring before the complaint
  deadline would strand valid complaints.
- **Finality safety.** An epoch-`e` transcript is only settled once buried by
  `finality_depth(6) + MARGIN` (magnitudes OPEN). Retaining until then ensures a key
  is available for any adjudication that can still be triggered on a not-yet-final
  block.
- **Reorg safety.** A reorg (§10) can revert and re-present epoch-`e` deals on the
  replacement history. While within the reorg margin, the epoch key must remain
  available so the re-presented deals can be decrypted/adjudicated identically.
  After the window (past the reorg margin), the transcript can no longer be revived,
  so the key is safe to destroy. Forward secrecy is thus achieved **as early as
  soundness allows** — not one block sooner (which would break adjudication), not
  later (which would erode the benefit).

Because the group secret is a *sum over QUAL*, forward-secrecy loss for `< T`
participants of an epoch does not by itself reveal that epoch's `sk` — a defence in
depth on top of per-epoch rotation.

### 11.4 Secure-deletion limitations (best-effort, residual-copy risk)

`zeroize` (rule 6) is **best-effort**, not a guarantee. A validator's operational
security posture MUST account for residual copies that in-process zeroization
cannot reach:

- **Memory copies** — the key may have been copied by the allocator, by `Vec`
  re-allocation/growth, by move semantics, or by intermediate buffers; only the
  final live copy is zeroized. Use `Zeroizing<_>` wrappers and avoid cloning secret
  material.
- **Swap / paging** — the OS may have paged the key to swap/backing store. Mitigate
  with `mlock`/`munlock` (locked, unswappable pages) or an encrypted swap device.
- **Crash dumps / core dumps** — a crash may serialise process memory (including the
  key) to a core dump. Disable core dumps for the validator process
  (`RLIMIT_CORE = 0`) or ensure dumps are encrypted and access-controlled.
- **Backups / snapshots** — VM snapshots, hibernation images, or filesystem backups
  taken while a key is resident capture it outside the process's control; retention
  policies must treat such artifacts as key material.
- **Hardware remanence / DMA** — cold-boot remanence and DMA-capable peripherals can
  read RAM; HSM/enclave custody removes the key from general-purpose RAM entirely
  and is RECOMMENDED for validators.

Consequence: K-rotate delivers forward secrecy **against on-chain-only adversaries**
(who see permanent transcripts but not host memory) with high assurance, and
against host-compromise adversaries only to the extent the operator controls the
residual-copy surface above. This limitation is inherent to software key handling
and is documented, not eliminated.

---

## 12. Beacon chaining domains and the consume-after boundary

### 12.1 Domain-separated messages (PROPOSED — owner decision, NOT adopted)

> **PROPOSED, not consensus.** The tag strings (`GENESIS`/`ROUND`/`OUT`), the
> concatenation order, and the field widths below are #127 **owner decisions that
> have not been ratified**. They are presented as a concrete, self-consistent
> proposal for review, **not** as frozen consensus bytes. Only the underlying
> primitives — BLAKE3, SHA-256, and little-endian integer encoding — are
> standard-fixed; the *layout that uses them* is proposed.

```
genesis seed:   Sigma_0_seed = blake3( "OMNINODE-BEACON-GENESIS:v1:"
                                        ‖ chain_id ‖ genesis_params_hash )

round message:  m_r = "OMNINODE-BEACON-ROUND:v1:"
                      ‖ chain_id
                      ‖ u64_le(epoch)
                      ‖ u64_le(round)
                      ‖ compress(Sigma_prev)          # Sigma_{r−1}, or the genesis
                                                        # seed for the first round

beacon output:  beacon_r = blake3( "OMNINODE-BEACON-OUT:v1:"
                                    ‖ chain_id ‖ u64_le(epoch) ‖ u64_le(round)
                                    ‖ compress(Sigma_r) )
```

The three tags (`GENESIS`, `ROUND`, `OUT`) are **distinct domain-separation
prefixes** so a genesis seed, a signing message, and a hashed output can never
collide or be substituted for one another. Binding `chain_id`, `epoch`, `round`
prevents cross-chain, cross-epoch, and cross-round replay of any partial or
output. Chaining `compress(Sigma_prev)` into each `m_r` makes round `r`'s message —
and therefore its unique signature `Sigma_r = H_{G2}(m_r)^{sk}` — depend on the
entire prior beacon history; changing any prior `Sigma` changes every subsequent
output (acceptance criterion (d)). Encodings: `u64_le` = little-endian 8-byte;
`compress(·)` = canonical compressed G2 point (`blst` serialisation).

### 12.2 Uniqueness

For fixed `PK_E` and `m_r`, `Sigma_r = H_{G2}(m_r)^{sk}` is the **unique** valid
group signature (BLS signatures are unique / deterministic — no signer randomness),
so `beacon_r` is a deterministic function of history. "Exactly one `PK_E` per
epoch, exactly one output per `(epoch, round)`."

### 12.3 Consume-after boundary (PROPOSED requirement — owner decision, not adopted)

A beacon output `Sigma_r` / `beacon_r` MUST NOT be **consumed** by any downstream
protocol (C1 and beyond) until the block that carried its combine is buried by at
least

```
finality_depth (= 6)  +  MARGIN
```

confirmations (`MARGIN` is an OPEN, non-negative safety constant — §15; it is
**not** an activation height). Rationale: below this depth the output is
reorg-revertible (§10); consuming it early would let a withholding/reorg adversary
influence a consumer by reveal-then-revert. Above the boundary, an output is
practically irreversible under the longest-chain rule, so consumption cannot be
retroactively biased. The boundary converts withholding into **delay, not bias**.

---

## 13. Threat model and consolidated security goals

**Adversary.** Static (per-epoch) Byzantine corruption of up to `f = 1` participant
plus `c = 1` crash, with full view of all on-chain data (ciphertexts, carriers,
commitments, partials, outputs), able to schedule message delivery within windows
and — for §10 — able to attempt reorgs subject to the chain's longest-chain rule.
No compromise of honest nodes' private keys (except as studied in §11).

**Goals.**
1. **Unbiasability under `T`-of-`n`.** With `< T` corrupted signers, the adversary
   cannot compute a round output before honest signers do, and cannot bias it;
   withholding yields **delay, not bias** (bounded by §12.3).
2. **Unforgeability.** Without `≥ T` valid shares the adversary cannot produce a
   partial that verifies under an honest `vk_j`, nor a combined `Σ` under `PK_E`
   (threshold BLS + §2 checks).
3. **Robust DKG.** With `|QUAL| ≥ 2f + 1`, `> f` honest dealers contribute to
   `PK_E`; a size-`f` Byzantine dealer set cannot fix the group secret; every
   Byzantine deal is either caught by Feldman at the recipient or by a
   DLEQ-authenticated complaint on-chain.
4. **Objective accountability.** Only proven misconduct is slashed; absence is
   never confiscated (§6.4, Option-1).
5. **Reorg atomicity, no leakage.** DKG/beacon state reverts atomically with the
   fork; no share plaintext is ever on-chain; exposed partials/outputs are bound to
   their fork's history and useless elsewhere (§10).
6. **Liveness is an assumption, not a rule (Option-1).** Deal and complaint
   inclusion are an explicit liveness assumption, **not** consensus-enforced.
   Window expiry or `|QUAL| < 2f + 1` ⇒ **safe halt** (no seed, no biased fallback,
   compute-assignment-only halt; requester cancel/refund; VT1 repair + fresh DKG).
   No omission slashing.

**Residual risks (documented, not eliminated).** (a) Reorg/withholding grinding
bounded only by chain reorg-resistance (§10); (b) forward-secrecy loss under static
encryption keys (§11, §16); (c) leakage accounting on adjudicated reveals (§9); (d)
no PQ security; (e) DKG availability depends on the Option-1 liveness assumption.

---

## 14. Test vectors

Vectors live in `crates/crypto/tests/br1_beacon_vectors.rs` (this worktree) and are
run with `cargo test -p sumchain-crypto`, using only crates already in-tree
(`blake3`, `sha2`, `hex`). No BLS/pairing code is added by this track. The vectors
fall in **two classes**:

- **NORMATIVE** (`T-1`, `T-2`) — bytes fixed by an external standard.
- **PROPOSED** (`T-3`, `T-4`, `T-5`) — checks of #127 **owner-decision**
  constructions (beacon tags + preimage layouts). These are **NOT frozen consensus
  bytes**; they validate a self-consistent proposal pending owner ratification.

### 14.1 Vectors present (machine-checked here)

| ID | Class | What is asserted | Basis |
|---|---|---|---|
| `T-1` | **NORMATIVE** | Exact ASCII bytes + length + SHA-256 fingerprint of the three ciphersuite / hash-to-curve identifier strings (§2.1) | BLS ciphersuite draft-05 + RFC 9380 |
| `T-2` | **NORMATIVE** | `u64_le` little-endian encoding of representative values (§12) | LE integer encoding (standard) |
| `T-3` | **PROPOSED** | **Proposed** genesis-seed preimage layout + its BLAKE3 digest, from **explicitly synthetic** `chain_id`/`genesis_params_hash` (§12.1) | #127 owner-decision tag/layout (values synthetic) |
| `T-4` | **PROPOSED** | **Proposed** round-message `m_r` + `OUT` preimage layout + BLAKE3 digests, from synthetic components (§12.1) | #127 owner-decision tags/layout (values synthetic) |
| `T-5` | **PROPOSED** | Proposed domain tags are pairwise distinct and prefix-free (GENESIS/ROUND/OUT/DLEQ/ECIES) (§12.1, §5.3, §8) | #127 owner-decision tags |

`T-3`/`T-4` check a **PROPOSED** construction and byte order (concatenation order,
LE widths, tag placement) using clearly-labelled synthetic inputs. They are **not**
consensus bytes and **not** normative — the tags and layout are owner decisions
(§12.1) that have not been adopted; the synthetic digests additionally depend on
real deployment `chain_id`/`genesis_params_hash` and must never be read as the live
chain's genesis seed. Only the underlying BLAKE3/LE primitives are standard-fixed.

### 14.2 Topics with NO byte-exact vectors (bytes undetermined)

| Topic | Why no asserted bytes |
|---|---|
| RFC 9380 hash-to-curve `G2` point outputs; ciphersuite sign/verify + PoP point vectors | Require a BLS12-381 implementation (`blst`/`arkworks`) not in this crate; authoritative vectors are RFC 9380 §8.8.2 and draft-irtf-cfrg-bls-signature Appendix — to be wired in when the `blst` layer lands. Adding a pairing dependency is out of scope for a spec/vectors track. |
| DLEQ transcript / challenge bytes (§5) | Fiat-Shamir serialisation + hash-to-scalar are **OPEN** (§15); asserting bytes now would invent unratified constants. |
| ECIES ciphertext bytes (§8) | KDF/AEAD/nonce primitives are **OPEN** (§15). |
| W1b transaction ordinals (28/29) and on-chain operation encodings | Owned by #125/W1b; not this track's to fix. |
| Activation heights, `MARGIN` | Prohibited / OPEN. |

---

## 15. Normative vs non-normative decision table

`N` = normative here (fixed by an **external standard** or by an established
reference construction — GJKR New-DKG / threshold-BLS / celo). `P` = **PROPOSED
(owner decision, NOT adopted)** — a concrete #127 proposal for review, not ratified
consensus. `O` = open decision (recommended value given; ratify before
implementation). `X` = owned by another issue / prohibited to fix here.

> The beacon domain strings and message/preimage layouts are `P` (owner decisions,
> not adopted). They were classified as owner decisions in earlier #127 analysis;
> only the primitives they are built from (BLAKE3, SHA-256, LE encoding, the BLS
> ciphersuite / RFC 9380 strings) are `N`.

| # | Item | Status | Fixed by / owner | Value / recommendation |
|---|---|---|---|---|
| 1 | Curve BLS12-381, `F_r`, `G1`/`G2`/`G_T`, pairing | **N** | RFC 9380 / `blst` | as §1.1 |
| 2 | Group placement (G1 keys, G2 sigs) | **N** | BLS draft-05 ciphersuite | minimal-pubkey-size |
| 3 | Signing ciphersuite `BLS_SIG_…SSWU_RO_POP_` | **N** | BLS draft-05 | §2.1 |
| 4 | PoP ciphersuite `BLS_POP_…SSWU_RO_POP_` | **N** | BLS draft-05 | §2.1 |
| 5 | Hash-to-curve suite `BLS12381G2_XMD:SHA-256_SSWU_RO_` | **N** | RFC 9380 | §2.1 |
| 6 | Subgroup + infinity / `KeyValidate` checks | **N** | BLS draft-05 §2.5 | §2.2 (mandatory) |
| 7 | PoP construction | **N** | BLS draft-05 §3.3 | §2.3 |
| 8 | Partial-sig verify equation | **N** | threshold BLS | §2.4 |
| 9 | Share eval point `x_j = j + 1`; domain `F_r^*` | **N** | #127 + celo convention | §3 |
| 10 | Feldman check equation | **N** | Feldman VSS | §6.2 |
| 11 | QUAL = non-disqualified; success iff `|QUAL| ≥ 2f+1` | **N** | #127 | §4.2 |
| 12 | `PK_E`, `sk_j`, `vk_j` aggregation over sorted QUAL | **N** | #127 | §4.2 |
| 13 | Exactly-`T` sorted Lagrange combine (canonical) | **N** | #127 + threshold BLS | §4.3 |
| 14 | `f=1, c=1, T=2, Q_dkg=3`; `n_crypto≥4`, `n_product≥5` | **N** | #127 | §1.2 |
| 15 | Deterministic complaint adjudication (no count/majority) | **N** | #127 | §6.1 |
| 16 | Objective-only penalties; absence never slashed | **N** | #127 | §6.4 |
| 17 | Beacon tags GENESIS/ROUND/OUT + chaining layout | **P — owner decision, not adopted** | #127 owner decision | §12.1 (PROPOSED) |
| 18 | `u64_le`/`compress(·)` primitives **N**; their placement in the beacon layout **P** | **N** primitives / **P** layout | LE + blst (primitives); #127 owner decision (layout) | §12.1 |
| 19 | BLAKE3 / SHA-256 algorithms **N**; the *choice to use* BLAKE3 for beacon seed/output **P** | **N** algorithms / **P** beacon use | BLAKE3, RFC 9380 (algorithms); #127 owner decision (beacon use) | §12.1 / §2.1 |
| 20 | Consume-after `≥ finality_depth(6) + MARGIN` | **P** (rule) / `MARGIN` **O** | #127 owner decision (rule); `MARGIN` open | §12.3 |
| 21 | DLEQ statement + prover/verifier equations | **N** | Chaum-Pedersen | §5.2, §5.4, §5.5 |
| 22 | DLEQ Fiat-Shamir serialisation + `HashToScalar` | **O** | ratify | RFC 9380 `hash_to_field` w/ `DST_DLEQ` (§5.3) |
| 23 | DLEQ domain tag string `OMNINODE-DKG-DLEQ:v1:` | **P — owner decision, not adopted** | #127 tag proposal | §5.3 |
| 24 | ECIES group `G_enc` (E-A G1 vs E-B Ristretto) | **O** (engineering) | ratify | see §8.1, §16-note |
| 25 | ECIES KDF (BLAKE3-derive-key vs HKDF-SHA-256) | **O** | ratify | BLAKE3-derive-key (repo pattern) |
| 26 | ECIES AEAD (XChaCha20-Poly1305 vs AES-256-GCM) | **O** | ratify | XChaCha20-Poly1305 (repo pattern) |
| 27 | ECIES nonce (fixed-zero vs KDF-derived) | **O** | ratify | fixed-zero (unique key per ct) |
| 28 | ECIES AAD transcript binding fields | **N** (security goal: MUST bind i,j,epoch,chain,R) / tag strings + exact bytes **P** | #127 security goal (binding); #127 tag proposal (`OMNINODE-DKG-ECIES:v1:*`) | §8.4 |
| 29 | Encryption-key lifetime (static long-lived vs per-epoch rotated) | **RATIFIED — K-rotate (owner decision, 2026-07); normative rules in §11** | owner-ratified | §11, §16.1 |
| 30 | W1b tx ordinals 28/29; on-chain op encodings | **X** | #125 / W1b | reference only |
| 31 | Activation height `beacon_enabled_from_height` | **X** | ops / #127 gate | `None` until audit passes |
| 32 | Reorg-atomic revertible CFs; no-leak; no hard finality | **N** | #127 | §10 |

---

## 16. Open decisions escalated for owner adjudication

Per the track rule, human adjudication is requested **only** where two valid
constructions differ in *security* (not merely engineering). One such item was
escalated — the encryption-key lifetime (§16.1) — and has now been **RESOLVED** by
owner ratification of K-rotate; it is retained below as a decision record. One
adjacent item is noted as engineering-only. **No security dispute remains open.**

### 16.1 RESOLVED — encryption-key lifetime (decision-table #29): K-rotate RATIFIED

> **RATIFIED (owner decision, 2026-07): K-rotate.** The encryption-key lifecycle
> dispute is DECIDED. The normative rules are stated in §11 (lifecycle state machine
> §11.2, secure-deletion limits §11.4); this section records the decision and why the
> rejected alternative was rejected. This is the ONE ratified element of the draft; it
> ratifies no exact CF encoding, W1b ordinal, receipt integer, or timing magnitude
> (those remain OPEN).

Two ratifiable designs with **materially different security** (forward secrecy) were
weighed; the owner ratified **K-rotate**:

- **(K-rotate) — RATIFIED. Per-epoch ephemeral `ek_j` with mandatory rotation,
  epoch-scoped decryption, bounded retention, then secure erase.**
  Each node registers a **fresh** encryption key `ek_j` for each epoch, identified by
  `(chain_id, validator, epoch)` (§11), registered/authenticated **before** that
  epoch's DKG deal cutoff. The corresponding **private** key is **bound to that
  epoch**, may decrypt **only** that epoch's ciphertexts, and is **retained only
  through that epoch's complaint window PLUS the reorg/finality window** (so a late
  complaint or a reorg that re-exposes the epoch's deals can still be decrypted /
  adjudicated), and is then **securely erased (zeroized)**.
  - *Forward secrecy:* a later single-key compromise exposes **at most one epoch's**
    shares; matches the issue's stated "per-epoch key rotation (forward secrecy)".
  - *Retention rule (must be spelled out):* the private key MUST live at least until
    `max(complaint_window_end, block_of_last_referencing_deal + finality_depth(6) +
    MARGIN)`, then be zeroized. Erasing earlier breaks complaint adjudication /
    reorg replay; erasing later erodes the forward-secrecy benefit.
  - *Model changes this forces (owner must weigh):*
    1. **Registration/state model** — a **per-epoch key-registration** step
       (`RegisterBeaconKeyV1` per epoch, not once per node), with a key-rotation
       **ordering requirement**: the new `ek_j` must be registered and on-chain
       **before** that epoch's deals reference it.
    2. **Complaint / CF schema** — the complaint path and the key column family must
       be **keyed by `(node, epoch)`** rather than by `node` alone, so the correct
       epoch key is selected during adjudication; transcripts/keys become
       epoch-scoped state.
    3. **Liveness** — the per-epoch registration falls inside the Option-1 window
       (one more step that can time out → safe halt); more key churn / state.

- **(K-static) — REJECTED ALTERNATIVE. Long-lived static `ek_j`, reused across
  epochs.**
  - *Pro:* operationally simplest; no per-epoch registration; smaller state;
    `node`-keyed CF.
  - *Con (why rejected):* **no forward secrecy.** DKG transcripts are permanent
    on-chain, so a **single future compromise** of `ek_j` decrypts **all historical
    shares** ever dealt to `j`; compromising `≥ T` nodes' static keys in a common
    epoch **reconstructs that epoch's group secret retroactively** (§11). The threat
    model would have to assume encryption keys are *never* compromised for the life
    of the chain — an unacceptably strong assumption for a randomness beacon.

**Decision (owner, 2026-07).** The two designs give *different confidentiality
guarantees against key compromise* — a genuine security-property difference, not a
performance tradeoff. The issue text simultaneously implies static registered
encryption keys (`enc_pk` in a CF, `RegisterBeaconKeyV1`) **and** claims "per-epoch
key rotation (forward secrecy)"; these are only mutually consistent under
**(K-rotate)**, which the owner has **ratified**. Cross-epoch reuse, static-key
fallback, and deriving all epoch keys from a persistent master secret are FORBIDDEN;
a missing/invalid next-epoch key ⇒ deterministic exclusion or the ratified safe-halt
path. The normative rules are in §11. The exact retention magnitude (`finality_depth`,
`MARGIN`) and CF encoding remain OPEN — this decision fixes the direction and rules,
not those bytes/magnitudes.

### 16.2 Engineering-only note — ECIES curve choice (decision-table #24)

**(E-A) reuse BLS12-381 G1** vs **(E-B) independent Ristretto255** give
*equivalent* confidentiality/integrity; they differ in audit surface (one curve vs
two) and performance, **not** in security goal. This is flagged as an engineering
decision for the implementers/auditors, **not** escalated as a security dispute.
Recommendation: **(E-B)** if minimising bytes/latency and reusing the audited
SRC-201 curve stack is preferred; **(E-A)** if a single-curve audit surface is
preferred. Either is acceptable.

---

## 17. References

- **RFC 9380** (2023-08, final) — *Hashing to Elliptic Curves* (suite `BLS12381G2_XMD:SHA-256_SSWU_RO_`, §8.8.2; `expand_message_xmd` §5.3.1; `hash_to_field` §5.2).
- **draft-irtf-cfrg-bls-signature-05** (2022-06-16) — *BLS Signatures* (POP scheme ciphersuites §4; `KeyValidate` §2.5; `PopProve`/`PopVerify` §3.3; `CoreSign`/`CoreVerify` §2).
- Chaum & Pedersen (1992) — *Wallet Databases with Observers* (DLEQ / equality of discrete logs).
- Gennaro, Jarecki, Krawczyk, Rabin — *Secure Distributed Key Generation for Discrete-Log Based Cryptosystems* (GJKR "New-DKG").
- Feldman (1987) — *A Practical Scheme for Non-interactive Verifiable Secret Sharing*.
- `celo-threshold-bls-rs` — reference scalar-share DKG + threshold BLS (cited, not vendored).
- `blst` — BLS12-381 primitives (serialisation, subgroup checks).
- In-tree precedent: `crates/crypto/src/messaging.rs` (SRC-201 ECIES pattern:
  `blake3::derive_key` + XChaCha20-Poly1305 + header-as-AAD; low-order-point rejection).

---

*End of BR1 beacon security-design DRAFT. Refs #127. DRAFT — NOT CONSENSUS: no
implementation, no activation, no adopted/ratified beacon layout. The K-rotate
key-lifecycle direction (§11, §16.1) is RATIFIED (owner decision, 2026-07); beacon
domain strings/layouts and all other constructions remain PROPOSED pending owner
ratification.*

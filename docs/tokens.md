# Token Types & Token Families

Canonical reference for every token and token-family type on SUM Chain: what
each is, whether it is usable today, the exact public RPC methods, and
copy-paste `curl` examples against the public endpoint `https://rpc.sumchain.io`.

> Status:             code-backed (per-family status below)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/transaction.rs, crates/state/src/*_executor.rs, crates/rpc/src/api.rs, crates/rpc/src/server.rs
> Public RPC support: per family (see each section)

Every method shown here is a current, supported public RPC method (declared in
`crates/rpc/src/api.rs` with a working handler in `crates/rpc/src/server.rs`).
State-changing operations use signed transactions through the generic endpoint
(see [Submitting writes](#submitting-writes)).

## How to call

All examples are JSON-RPC 2.0 over HTTP POST:

```bash
curl -s https://rpc.sumchain.io \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"sum_blockNumber","params":[]}'
```

Placeholders like `<token_id>`, `<owner_addr>` are inputs you supply; they are
not real values.

## Activation state

| Family | Activation gate | Mainnet state |
|---|---|---|
| Token, NFT, Messaging, DocClass, Employment | none | always available |
| Education (SRC-817/818) | `education_enabled_from_height` | reads available; **writes dormant** (`null` on mainnet) |

(Gate values are observable live via `chain_getChainParams`.)

## Submitting writes

There is **no per-family write RPC**. Every state-changing token operation is a
signed transaction submitted through the generic endpoint:

```bash
curl -s https://rpc.sumchain.io \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"sum_sendRawTransaction","params":["<hex_signed_tx>"]}'
```

`<hex_signed_tx>` is a hex-encoded signed `SignedTransaction` whose payload is
the relevant `TxPayload` variant (e.g. `Token`, `Nft`, `Education`, `Tax`).
Construct and sign it with the SDK; this doc does not invent a write API.

---

## Native token — SUM-20 (fungible)

> Status:             code-backed
> Last verified:      2026-06-27
> Code references:    crates/token/src/, crates/state/src/token_executor.rs, crates/rpc/src/server.rs
> Public RPC support: yes (token_getToken, token_balanceOf, token_totalSupply, token_allowance, token_exists, token_getTokensByOwner)

Fungible tokens. Write flow: `TxPayload::Token` (operations include Create,
Mint, Burn, Transfer, Approve, TransferFrom) via [sum_sendRawTransaction](#submitting-writes).

Read examples:

```bash
# Balance of an owner for a token
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"token_balanceOf","params":["<token_id>","<owner_addr>"]}'

# Total supply
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"token_totalSupply","params":["<token_id>"]}'

# Token metadata
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"token_getToken","params":["<token_id>"]}'
```

## NFT — SUM-721

> Status:             code-backed
> Last verified:      2026-06-27
> Code references:    crates/nft/src/, crates/state/src/nft_executor.rs, crates/rpc/src/server.rs
> Public RPC support: yes (nft_getCollection, nft_getToken, nft_getTokensByOwner, nft_getTokensInCollection, nft_balanceOf, nft_ownerOf, nft_tokenExists)

Native NFTs and certified documents. Write flow: `TxPayload::Nft` (CreateCollection,
Mint, Transfer, Burn, …) via [sum_sendRawTransaction](#submitting-writes).

```bash
# Owner of a specific token (token_id is a number, not a string)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"nft_ownerOf","params":["<collection_id>",1]}'

# How many NFTs an address holds
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"nft_balanceOf","params":["<owner_addr>"]}'
```

## Messaging — SRC-201

> Status:             code-backed
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/messaging.rs, crates/state/src/messaging_executor.rs, crates/rpc/src/server.rs
> Public RPC support: yes (messaging_getConfig, messaging_getQuota, messaging_getInboxFilter, messaging_getMessages, messaging_getMessageByTxHash, messaging_getMessagesInBlock, messaging_getMessageData, messaging_getPendingPayment, messaging_getTrustStake, messaging_getSpamScore, messaging_isContact, messaging_isBlocked)

On-chain encrypted messaging with anti-spam/trust-stake. Write flow:
`TxPayload::Messaging` (SendMessage, StakeForTrust, AddContact, BlockSender, …)
via [sum_sendRawTransaction](#submitting-writes).

```bash
# Messaging quota for an address
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"messaging_getQuota","params":["<address>"]}'
```

## DocClass / academic credentials — SRC-80X/81X

> Status:             code-backed (no activation gate — always available)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/docclass.rs, crates/state/src/docclass_executor.rs, crates/rpc/src/server.rs
> Public RPC support: yes (docclass_getCredential, docclass_isCredentialValid, docclass_getCredentialsBySubject, docclass_getIssuer, docclass_getIssuers, docclass_canIssue, … )

Privacy-preserving document/credential class system (academic credentials,
issuers, identities). Write flow: `TxPayload::DocClass` (RegisterIssuer,
IssueCredential, RevokeCredential, …) via [sum_sendRawTransaction](#submitting-writes).

```bash
# Fetch a credential by id
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"docclass_getCredential","params":["<credential_id>"]}'

# Is a credential currently valid (not revoked/expired)?
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"docclass_isCredentialValid","params":["<credential_id>"]}'
```

## Education / LMS — SRC-817/818

> Status:             code-backed; writes gated (dormant on mainnet)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/education.rs, crates/state/src/education_executor.rs, crates/rpc/src/server.rs
> Public RPC support: yes for reads (src817_*, src818_*); writes require the activation gate

Course catalogs (SRC-817) and course offerings with assessments/grades
(SRC-818). Write flow: `TxPayload::Education` via
[sum_sendRawTransaction](#submitting-writes), **gated by
`education_enabled_from_height`** — `null` (not yet enabled) on mainnet. Read
RPCs are available regardless of the gate.

```bash
# Course catalog entry
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"src817_getCatalogEntry","params":["<catalog_id>"]}'

# Course offering
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"src818_getOffering","params":["<offering_id>"]}'
```

## Employment / HR — SRC-88X

> Status:             code-backed
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/employment.rs, crates/state/src/employment_executor.rs, crates/rpc/src/server.rs
> Public RPC support: yes (employment_getCredential, employment_verifyEmployment, employment_getSummary, employment_getIncomeAttestation, … )

Employment credentials and income attestations. Write flow:
`TxPayload::Employment` via [sum_sendRawTransaction](#submitting-writes).

```bash
# Employment credential by id
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"employment_getCredential","params":["<employment_id>"]}'
```

## Write-only families — Tax, Equity, Agreement, Legal, Property, Healthcare, Finance

> Status:             code-backed (write flow)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/{tax,equity,agreement,legal,property,healthcare,finance}.rs, crates/state/src/{tax,equity,agreement,legal,property,healthcare,finance}_executor.rs
> Public RPC support: writes via sum_sendRawTransaction

Each of these families has a `TxPayload` variant and a wired executor.

| Family | SRC | TxPayload variant |
|---|---|---|
| Tax / compliance | 82X | `Tax` |
| Business / equity | 83X | `Equity` |
| Agreement / IP | 84X | `Agreement` |
| Legal process | 85X | `Legal` |
| Property / insurance | 86X | `Property` |
| Healthcare | 87X | `Healthcare` |
| Finance / banking | 89X | `Finance` |

> Public read examples are not published for this family. State-changing
> operations use signed transactions through
> [`sum_sendRawTransaction`](#submitting-writes).

For these families, generic block/transaction reads (`sum_getTransaction`,
`sum_getReceipt`, block queries) cover the transactions that carried the writes.

---

## Standards & privacy model

Token families map to SUM standards: **SUM-20** (fungible token), **SUM-721**
(NFT), **SRC-201** (messaging), **SRC-80X/81X** (document/credential class incl.
academic credentials), **SRC-817/818** (education catalog/offering), **SRC-82X**
(tax), **SRC-83X** (equity), **SRC-84X** (agreement), **SRC-85X** (legal),
**SRC-86X** (property), **SRC-87X** (healthcare), **SRC-88X** (employment),
**SRC-89X** (finance).

Privacy model for the document/credential families (DocClass, Education,
Employment, and the SRC-82X–89X families):

- **No PII on-chain.** Records store only BLAKE3 commitments and optional
  references to encrypted off-chain payloads — never names, IDs, emails, raw
  grades/courses, or other personal data.
- **Schema allowlist.** Credential metadata is validated against an attribute
  allowlist; disallowed PII-bearing fields are rejected at consensus.
- **Commitment canonicalization.** Commitments use BLAKE3 with domain separation
  (e.g. `SRC-810-COURSES-v1`) over canonical JSON (sorted keys, no whitespace),
  so independent parties derive identical commitments.
- **Pseudonymous subjects.** Identity is a scoped commitment / pseudonymous
  address, not a real-world identifier.

## Source-of-truth pointers

- Transaction variants: `crates/primitives/src/transaction.rs` (`TxType`, `TxPayload`).
- Per-family executors: `crates/state/src/<family>_executor.rs`.
- RPC surface: `crates/rpc/src/api.rs` (declarations) + `crates/rpc/src/server.rs` (handlers).

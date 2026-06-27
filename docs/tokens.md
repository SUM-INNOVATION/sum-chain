# Token Types & Token Families

Canonical reference for every token and token-family type on SUM Chain: what
each is, whether it is usable today, the exact public RPC methods, and
copy-paste `curl` examples against the public endpoint `https://rpc.sumchain.io`.

> Status:             code-backed (per-family status below)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/transaction.rs, crates/state/src/*_executor.rs, crates/rpc/src/api.rs, crates/rpc/src/server.rs
> Public RPC support: per family (see each section)

Every method shown here is declared in `crates/rpc/src/api.rs`. A method is only
described as usable when it also has a **working** handler in
`crates/rpc/src/server.rs`; declared-but-stubbed methods are called out
explicitly per family (see Messaging). Families with no read RPC are flagged too.
No write API is invented: on-chain writes go through the generic
signed-transaction endpoint (see [Submitting writes](#submitting-writes)).

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

> Status:             partial (working executor; some declared read RPCs are stubbed)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/messaging.rs, crates/state/src/messaging_executor.rs, crates/rpc/src/server.rs
> Public RPC support: partial. Working reads include messaging_getConfig, messaging_getQuota, messaging_getInboxFilter, messaging_getMessages, messaging_getMessageByTxHash, messaging_getMessagesInBlock, messaging_getMessageData, messaging_getPendingPayment, messaging_getTrustStake, messaging_getSpamScore, messaging_isContact, messaging_isBlocked. Known non-functional declared methods: messaging_getSentMessages and messaging_getPendingPayments return "not yet implemented".

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
`education_enabled_from_height`** — `null` (dormant) on mainnet, so education
writes are rejected there today. Read RPCs work regardless of the gate.

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

> Status:             partial (types + executor, no read RPC)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/{tax,equity,agreement,legal,property,healthcare,finance}.rs, crates/state/src/{tax,equity,agreement,legal,property,healthcare,finance}_executor.rs
> Public RPC support: no family-specific read RPC

Each of these families has a `TxPayload` variant and a wired executor, but **no
family-specific public read RPC method** is defined.

| Family | SRC | TxPayload variant |
|---|---|---|
| Tax / compliance | 82X | `Tax` |
| Business / equity | 83X | `Equity` |
| Agreement / IP | 84X | `Agreement` |
| Legal process | 85X | `Legal` |
| Property / insurance | 86X | `Property` |
| Healthcare | 87X | `Healthcare` |
| Finance / banking | 89X | `Finance` |

> No family-specific public read RPC exists in this repo for this family.
> Writes, where supported by the transaction type, are submitted through the
> generic signed transaction endpoint
> [`sum_sendRawTransaction`](#submitting-writes).

To inspect state for these families today, use generic block/transaction reads
(`sum_getTransaction`, `sum_getReceipt`, block queries) on the transactions that
carried the writes.

---

## Source-of-truth pointers

- Transaction variants: `crates/primitives/src/transaction.rs` (`TxType`, `TxPayload`).
- Per-family executors: `crates/state/src/<family>_executor.rs`.
- RPC surface: `crates/rpc/src/api.rs` (declarations) + `crates/rpc/src/server.rs` (handlers).
- Deep per-family specs: the `docs/SRC-*.md` family and [SUM-721](./SUM-721.md).

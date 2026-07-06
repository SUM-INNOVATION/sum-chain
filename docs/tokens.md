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
| Governance (on-chain v1) | `governance_enabled_from_height` **and** `ChainParams.governance` | code-backed; **dormant** (both unset on mainnet) |

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
> Public RPC support: yes (token_getToken, token_balanceOf, token_totalSupply, token_allowance, token_exists, token_getTokensByOwner, token_getMinters)

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

# Minters of a token (owner + registered minters) — token-scoped
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"token_getMinters","params":["<token_id>"]}'
```

`token_getMinters` is **token-scoped**: it returns the owner and registered
minters for one token id. There is intentionally no address→tokens ("everything
this address can mint") lookup — see the note in
[api-reference.md](rpc/api-reference.md#token_getminters).

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
> Last verified:      2026-06-29
> Code references:    crates/primitives/src/messaging.rs, crates/state/src/messaging_executor.rs, crates/rpc/src/server.rs
> Public RPC support: yes (messaging_getConfig, messaging_getQuota, messaging_getInboxFilter, messaging_getMessages, messaging_getSentMessages, messaging_getMessageByTxHash, messaging_getMessagesInBlock, messaging_getMessageData, messaging_getPendingPayment, messaging_getPendingPayments, messaging_getTrustStake, messaging_getSpamScore, messaging_isContact, messaging_isBlocked)

On-chain encrypted messaging with anti-spam/trust-stake. Write flow:
`TxPayload::Messaging` (SendMessage, StakeForTrust, AddContact, BlockSender, …)
via [sum_sendRawTransaction](#submitting-writes).

```bash
# Messaging quota for an address
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"messaging_getQuota","params":["<address>"]}'

# Messages sent by an address (paginated: limit default 100, max 1000; offset)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"messaging_getSentMessages","params":["<sender_address>",100,0]}'

# Pending escrow payments addressed to a recipient
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"messaging_getPendingPayments","params":["<recipient_address>"]}'
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

## Tax — SRC-82X (registry reads)

> Status:             code-backed
> Last verified:      2026-06-30
> Code references:    crates/primitives/src/tax.rs, crates/storage/src/tax_store.rs, crates/rpc/src/server.rs
> Public RPC support: yes for registry reads (tax_getClaimType, tax_listClaimTypes, tax_getIssuer, tax_getActiveIssuers, tax_getIssuersByClass, tax_getPolicy, tax_listPolicies)

Public read access to the SRC-82X tax-compliance registries: claim-type
definitions, authorized issuers, and policy templates. Hashes are returned as
opaque `0x` values. Writes are signed `TxPayload::Tax` transactions via
[sum_sendRawTransaction](#submitting-writes).

```bash
# Claim-type registry: one entry, or all
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tax_getClaimType","params":["tax.filed.return"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tax_listClaimTypes","params":[]}'

# Issuers: by address, active only, or by class (e.g. "TaxAuthority")
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tax_getIssuer","params":["<issuer_address>"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tax_getActiveIssuers","params":[]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tax_getIssuersByClass","params":["TaxAuthority"]}'

# Policies: by id, or all
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tax_getPolicy","params":["0x<policy_id_hex>"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tax_listPolicies","params":[]}'
```

---

## Equity — SRC-83X (registry reads)

> Status:             code-backed
> Last verified:      2026-06-30
> Code references:    crates/primitives/src/equity.rs, crates/storage/src/equity_store.rs, crates/rpc/src/server.rs
> Public RPC support: yes for registry reads (equity_getEntity, equity_getActiveEntities, equity_getEntitiesByOrgType, equity_getEntitiesByController, equity_getShareClass, equity_getActiveShareClasses, equity_getShareClassesByIssuer, equity_getControllerConfig)

Public read access to the SRC-83X equity registries: entity profiles, share
classes, and class-level controller config. Commitments and rights/metadata
references are returned as opaque `0x` hashes. Writes are signed
`TxPayload::Equity` transactions via [sum_sendRawTransaction](#submitting-writes).

```bash
# Entities: by subject id (hex), active only, by org type, or by controller
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getEntity","params":["0x<subject_id_hex>"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getActiveEntities","params":[]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getEntitiesByOrgType","params":["Corporation"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getEntitiesByController","params":["<controller_address>"]}'

# Share classes: by class id (hex), active only, or by issuer entity (hex)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getShareClass","params":["0x<class_id_hex>"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getActiveShareClasses","params":[]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getShareClassesByIssuer","params":["0x<issuer_subject_hex>"]}'

# Class-level controller config by class id (hex)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"equity_getControllerConfig","params":["0x<class_id_hex>"]}'
```

---

## Agreement — SRC-84X (executor-link registry reads)

> Status:             code-backed
> Last verified:      2026-06-30
> Code references:    crates/primitives/src/agreement.rs, crates/storage/src/agreement_store.rs, crates/rpc/src/server.rs
> Public RPC support: yes for executor-link registry reads (agreement_getExecutorLink, agreement_getExecutorLinksByAgreement, agreement_getExecutorLinksByExecutor, agreement_getActiveExecutorLinks)

Public read access to SRC-846 agreement executor links — the executor/automation
bindings for an agreement. Ids and commitments are returned as opaque `0x`
hashes; `executor_contract` is a contract address. Writes are signed
`TxPayload::Agreement` transactions via [sum_sendRawTransaction](#submitting-writes).

```bash
# Executor link by link id (hex)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"agreement_getExecutorLink","params":["0x<link_id_hex>"]}'
# Links bound to an agreement (hex)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"agreement_getExecutorLinksByAgreement","params":["0x<agreement_id_hex>"]}'
# Links for an executor contract address
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"agreement_getExecutorLinksByExecutor","params":["<executor_address>"]}'
# Active executor links
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"agreement_getActiveExecutorLinks","params":[]}'
```

---

## Property — SRC-86X (asset registry reads)

> Status:             code-backed
> Last verified:      2026-06-30
> Code references:    crates/primitives/src/property.rs, crates/storage/src/property_store.rs, crates/rpc/src/server.rs
> Public RPC support: yes for asset-anchor registry reads (property_getAsset, property_getActiveAssets, property_getAssetsByJurisdiction)

Public read access to SRC-861 asset anchors — the property/asset identity
registry. Ids and commitments are returned as opaque `0x` hashes;
`issuer_address` is the registrant address. Writes are signed
`TxPayload::Property` transactions via [sum_sendRawTransaction](#submitting-writes).

```bash
# Asset anchor by asset id (hex)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"property_getAsset","params":["0x<asset_id_hex>"]}'
# Active asset anchors
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"property_getActiveAssets","params":[]}'
# Asset anchors registered in a jurisdiction (e.g. "US-CA-LA")
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"property_getAssetsByJurisdiction","params":["US-CA-LA"]}'
```

---

## Finance — SRC-89X (issuer registry reads)

> Status:             code-backed
> Last verified:      2026-06-30
> Code references:    crates/primitives/src/finance.rs, crates/storage/src/finance_store.rs, crates/rpc/src/server.rs
> Public RPC support: yes for issuer registry reads (finance_getIssuer, finance_getActiveIssuers, finance_getIssuersByJurisdiction)

Public read access to SRC-891 finance issuer profiles — financial institution
and utility issuer registrations. `issuer_address` is the institution address;
`issuer_commitment` and `policy_id` are opaque `0x` hashes. These records carry
no subject/customer data. Writes are signed `TxPayload::Finance` transactions
via [sum_sendRawTransaction](#submitting-writes).

```bash
# Issuer profile by issuer address
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"finance_getIssuer","params":["<issuer_address>"]}'
# Active issuer profiles
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"finance_getActiveIssuers","params":[]}'
# Issuer profiles registered in a jurisdiction (e.g. "US")
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"finance_getIssuersByJurisdiction","params":["US"]}'
```

---

## Legal — SRC-85X (case-anchor registry reads)

> Status:             code-backed
> Last verified:      2026-06-30
> Code references:    crates/primitives/src/legal.rs, crates/storage/src/legal_store.rs, crates/rpc/src/server.rs
> Public RPC support: yes for case-anchor registry reads (legal_getCase, legal_getActiveCases, legal_getCasesByJurisdiction)

Public read access to SRC-851 case/docket anchors. Ids and commitments are
returned as opaque `0x` hashes; `issuer_address` is the court/agency address.
`legal_getActiveCases` returns **open case anchors (Filed/Active)**. Sealed
cases are never returned by any of these reads. Writes are signed
`TxPayload::Legal` transactions via [sum_sendRawTransaction](#submitting-writes).

```bash
# Case anchor by case id (hex); returns null for sealed cases
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"legal_getCase","params":["0x<case_id_hex>"]}'
# Open (Filed/Active) case anchors
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"legal_getActiveCases","params":[]}'
# Case anchors registered in a jurisdiction (e.g. "US-NY-SDNY"); sealed excluded
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"legal_getCasesByJurisdiction","params":["US-NY-SDNY"]}'
```

---

## Healthcare — SRC-871 (institutional provider registry reads)

> Status:             code-backed
> Last verified:      2026-07-01
> Code references:    crates/primitives/src/healthcare.rs, crates/storage/src/healthcare_store.rs, crates/rpc/src/server.rs
> Public RPC support: yes for institutional provider registry reads (healthcare_getInstitutionalProvider, healthcare_getActiveInstitutionalProviders)

Public read access to SRC-871 provider profiles, restricted to institutional
(organizational) providers — hospitals, health insurers, clinics, pharmacies,
and laboratories. Ids and commitments are returned as opaque `0x` hashes;
`issuer_address` is the registrant address. Writes are signed
`TxPayload::Healthcare` transactions via [sum_sendRawTransaction](#submitting-writes).

```bash
# Institutional provider by provider id (hex); null for non-institutional providers
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"healthcare_getInstitutionalProvider","params":["0x<provider_id_hex>"]}'
# Active institutional providers
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"healthcare_getActiveInstitutionalProviders","params":[]}'
```

---

## Governance — on-chain v1 (dormant)

> Status:             code-backed; dormant (not enabled on mainnet)
> Last verified:      2026-07-02
> Code references:    docs/specs/GOVERNANCE-V1.md, crates/primitives/src/governance.rs, crates/state/src/governance_executor.rs, crates/storage/src/governance_store.rs, crates/rpc/src/server.rs
> Public RPC support: builders (gov_buildCreateProposal, gov_buildCastVote, gov_buildExecuteProposal, gov_buildCancelProposal) + reads (gov_getProposal, gov_listProposals, gov_listActiveProposals, gov_getTally, gov_getVote, gov_getVotingPower, gov_listEligibleAssets)

On-chain token-holder governance v1: holders of an allowlisted SRC-20 governance
token create proposals and vote using a balance snapshot frozen at proposal
creation; execution is record-only (approval is recorded on-chain and carried
out off-chain). Full design: [docs/specs/GOVERNANCE-V1.md](specs/GOVERNANCE-V1.md).

**Dormant by default.** Governance is inert unless **both** are configured via a
coordinated validator upgrade: the activation gate `governance_enabled_from_height`
**and** the `ChainParams.governance` parameters (`validator_authority_threshold_bps`,
quorum, pass threshold, voting period, snapshot bound). Admin/council authority is
**validator-quorum controlled** — there is **no single council address**; a
threshold of the active validator set signs. Neither is set on mainnet, so governance
transactions are rejected and the reads below return empty/`null` until a network
enables and populates governance. No mainnet token id, quorum, threshold, bond,
or period values are published here.

When a non-zero deposit bond is configured, creating a proposal escrows the bond
(the proposer must cover `fee + bond`); it is returned to the proposer on a
good-faith outcome or proposer cancel, and burned on spam / quorum failure or a
validator-quorum cancel. A proposal may be self-cancelled by its proposer (no
approvals), or cancelled by a **validator-quorum** (a threshold of the active
validator set) while Created/Voting via `gov_buildCancelProposal` — which accepts
an optional `approvals` list of validator signatures. The `gov_getProposal` response
surfaces the `bond` amount and `bond_state` (`Escrowed`/`Returned`/`Burned`).

Execution is record-only except for a single treasury-spend path: when a
governance `treasury` address is configured, a passed `TreasurySpend` proposal
built with `execution_kind:"OnChain"` plus a `treasury_beneficiary` and
`treasury_amount` pays that native-Koppa amount from the treasury to the
beneficiary and moves to `Executed`. Every other `OnChain` class is rejected;
no chain-parameter, validator, or consensus state is ever changed. When present,
`gov_getProposal` surfaces `treasury_beneficiary` and `treasury_amount`.

### Reads (safe to call; empty/`null` until configured & populated)

```bash
# Registered governance assets (empty until an asset is registered)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_listEligibleAssets","params":[]}'
# All proposals, and only those currently in voting
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_listProposals","params":[]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_listActiveProposals","params":[]}'
# A proposal by id (hex); null if absent
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_getProposal","params":["0x<proposal_id_hex>"]}'
# Tally from the frozen snapshot + cast votes (quorum/pass are null when params are unset)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_getTally","params":["0x<proposal_id_hex>"]}'
# A voter's vote, and a holder's frozen snapshot voting power (null if absent)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_getVote","params":["0x<proposal_id_hex>","<voter_address>"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_getVotingPower","params":["0x<proposal_id_hex>","<holder_address>"]}'
```

### Builders (return unsigned tx material; sign locally, submit via `sum_sendRawTransaction`)

The `gov_build*` methods accept **no private keys**. Each returns an unsigned
`TransactionV2` (hex) plus a `signing_hash`; the client signs the hash locally
and broadcasts via [sum_sendRawTransaction](#submitting-writes). The resulting
transactions only take effect once governance is enabled.

```bash
# Unsigned create-proposal tx (the proposal id is discovered post-inclusion via gov_listProposals)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_buildCreateProposal","params":[{"from":"<address>","token_id":"0x<token_id_hex>","class":"RoutineProcess","execution_kind":"RecordOnly","external_ref_url":"https://example/pr/1","external_ref_content_hash":"0x<content_hash_hex>"}]}'
# Unsigned cast-vote tx
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_buildCastVote","params":[{"from":"<address>","proposal_id":"0x<proposal_id_hex>","choice":"Yes"}]}'
# Unsigned execute-proposal tx
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_buildExecuteProposal","params":[{"from":"<address>","proposal_id":"0x<proposal_id_hex>"}]}'
# Unsigned cancel-proposal tx (proposer self-cancel, or validator-quorum via optional approvals; while Created/Voting)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"gov_buildCancelProposal","params":[{"from":"<address>","proposal_id":"0x<proposal_id_hex>"}]}'
```

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

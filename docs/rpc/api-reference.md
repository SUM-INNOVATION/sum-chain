# SUM Chain API Reference

SUM Chain exposes a JSON-RPC API for interacting with the blockchain. The native currency is **Koppa (Ϙ)** with 9 decimal places.

This reference lists SUM Chain's **current supported public** JSON-RPC methods. For token-family usage with copy-paste examples, see [docs/tokens.md](../tokens.md).

## Connection

Default endpoint: `http://localhost:8545`

All requests use JSON-RPC 2.0 format:

```json
{
    "jsonrpc": "2.0",
    "method": "method_name",
    "params": [...],
    "id": 1
}
```

## Currency

| Name | Symbol | Decimals | Base Unit |
|------|--------|----------|-----------|
| Koppa | Ϙ | 9 | 1 Koppa = 1,000,000,000 base units |

All amounts in the API are represented in base units (smallest denomination).

Examples:
- `1 Ϙ` = `1000000000` base units
- `0.5 Ϙ` = `500000000` base units
- `0.001 Ϙ` = `1000000` base units

## Methods

### Chain Methods

#### `chain_id`

Returns the chain ID.

**Parameters:** None

**Returns:** `integer` - Chain ID

---

#### `get_latest_block`

Returns the latest block.

**Parameters:** None

**Returns:** Block object

| Field | Type | Description |
|-------|------|-------------|
| `height` | integer | Block height |
| `hash` | string | Block hash (hex) |
| `parent_hash` | string | Parent block hash |
| `timestamp` | integer | Unix timestamp (ms) |
| `state_root` | string | State root hash |
| `tx_root` | string | Transaction root hash |
| `proposer` | string | Proposer address (base58) |
| `tx_count` | integer | Transaction count |
| `transactions` | array | Transaction hashes |

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"get_latest_block","id":1}'
```

---

#### `get_block_by_height`

Returns block information by height.

**Parameters:**
1. `height` (integer) - Block height

**Returns:** Block object or `null`

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"get_block_by_height","params":[100],"id":1}'
```

---

#### `get_block_by_hash`

Returns block information by hash.

**Parameters:**
1. `hash` (string) - Block hash (hex)

**Returns:** Block object or `null`

---

#### `get_blocks`

Returns multiple blocks in a range.

**Parameters:**
1. `start_height` (integer) - Start height
2. `end_height` (integer) - End height

**Returns:** Array of block objects

---

### Account Methods

#### `get_balance`

Returns the account balance in base units.

**Parameters:**
1. `address` (string) - Account address (base58 or hex)

**Returns:** `string` - Balance in base units

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"get_balance","params":["SUM1abc..."],"id":1}'
```

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": "1500000000"
}
```

This represents `1.5 Ϙ` (1,500,000,000 base units).

---

#### `get_nonce`

Returns the account nonce (transaction count).

**Parameters:**
1. `address` (string) - Account address

**Returns:** `integer` - Current nonce

---

#### `get_account`

Returns full account information.

**Parameters:**
1. `address` (string) - Account address

**Returns:** Account object

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Account address |
| `balance` | string | Balance in base units |
| `nonce` | integer | Current nonce |

---

### Transaction Methods

#### `send_raw_transaction`

Broadcasts a signed transaction.

**Parameters:**
1. `raw_tx` (string) - Hex-encoded signed transaction

**Returns:** Object with transaction hash

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | string | Transaction hash (hex) |

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"send_raw_transaction","params":["0x..."],"id":1}'
```

---

#### `get_transaction`

Returns transaction details by hash.

**Parameters:**
1. `tx_hash` (string) - Transaction hash (hex)

**Returns:** Transaction object or `null`

| Field | Type | Description |
|-------|------|-------------|
| `hash` | string | Transaction hash |
| `from` | string | Sender address |
| `to` | string | Recipient address |
| `amount` | string | Amount in base units |
| `fee` | string | Fee in base units |
| `nonce` | integer | Sender nonce |
| `chain_id` | integer | Chain ID |
| `block_height` | integer | Block height (if confirmed) |
| `status` | string | "pending", "success", or "failed" |
| `tx_type` | string | Domain/type machine token derived from the payload at read time (e.g. `"Transfer"`, `"Token"`, `"StorageMetadataV2"`, `"Governance"`). |
| `action` | string \| null | Inner-operation machine token when present (e.g. `"Mint"`, `"CastVote"`, `"RegisterFilePendingV2"`), else `null`. |
| `asset_ref` | string \| null | Hex asset reference taken directly from the payload (SRC-20 `token_id` / NFT `collection_id`), else `null`. Never inferred. |
| `asset_kind` | string \| null | Coarse asset class: `"native"`, `"src20"`, `"nft"`, or `null`. |

> **`tx_type` / `action` / `asset_ref` / `asset_kind` are additive, read-time
> semantic labels.** They are computed from the already-public transaction
> payload when the response is built — nothing is persisted, and no
> classification is inferred beyond what the payload proves. The same four fields
> appear on transaction-history entries (`sum_getTransactionsByAddress` and
> friends). Older clients that ignore them are unaffected. Consumers map these
> stable machine tokens to human labels (see the `@sumchain/sdk`
> `classifyTransaction` helper).

---

#### `get_receipt`

Returns transaction receipt (for confirmed transactions).

**Parameters:**
1. `tx_hash` (string) - Transaction hash

**Returns:** Receipt object or `null`

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | string | Transaction hash |
| `block_height` | integer | Block height |
| `tx_index` | integer | Index in block |
| `status` | string | "success" or "failed" |
| `fee_paid` | string | Actual fee paid |

---

#### `get_pending_transactions`

Returns pending transactions in the mempool.

**Parameters:** None

**Returns:** Array of transaction objects

---

#### `pending_tx_count`

Returns number of pending transactions.

**Parameters:** None

**Returns:** `integer` - Mempool size

---

### Validator Methods

#### `get_validators`

Returns the current validator set.

**Parameters:** None

**Returns:** Validator set info

| Field | Type | Description |
|-------|------|-------------|
| `validators` | array | Validator list |
| `current_height` | integer | Current block height |
| `current_proposer_index` | integer | Current proposer index |

Each validator object:

| Field | Type | Description |
|-------|------|-------------|
| `address` | string | Validator address |
| `public_key` | string | Validator public key |
| `is_current_proposer` | boolean | Is current proposer |

---

#### `get_finality`

Returns finality information.

**Parameters:** None

**Returns:** Finality object

---

#### `is_block_finalized`

Checks if a block is finalized.

**Parameters:**
1. `height` (integer) - Block height

**Returns:** `boolean` - Is finalized

---

### P2P Methods

#### `get_peers`

Returns connected peers.

**Parameters:** None

**Returns:** Object with peer info

| Field | Type | Description |
|-------|------|-------------|
| `peer_count` | integer | Number of peers |
| `peers` | array | Peer details |

---

#### `get_p2p_stats`

Returns P2P network statistics.

**Parameters:** None

**Returns:** P2P stats object

---

### Health Methods

#### `health`

Returns basic health check.

**Parameters:** None

**Returns:** Health object

---

#### `node_info`

Returns detailed node information.

**Parameters:** None

**Returns:** Node info object

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Node version |
| `chain_id` | string | Chain ID |
| `peer_id` | string | Local peer ID |
| `is_validator` | boolean | Running as validator |
| `current_height` | integer | Current block height |
| `peer_count` | integer | Connected peers |
| `mempool_size` | integer | Pending transactions |
| `uptime_seconds` | integer | Node uptime |

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"node_info","id":1}'
```

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "version": "0.1.0",
        "chain_id": "sumchain-1",
        "peer_id": "12D3KooW...",
        "is_validator": true,
        "current_height": 420,
        "peer_count": 7,
        "mempool_size": 0,
        "uptime_seconds": 19122
    }
}
```

---

#### `get_metrics`

Returns Prometheus-format metrics.

**Parameters:** None

**Returns:** Metrics object (JSON)

---

### SUM Chain Native Methods (sum_* prefix)

These methods use the SUM Chain branded prefix for brand consistency. They return the same data as the generic methods.

#### `sum_blockNumber`

Returns the current block number as an integer.

**Parameters:** None

**Returns:** `integer` - Block height

---

#### `sum_getLatestBlock`

Alias for `get_latest_block`. Returns the latest block.

---

#### `sum_getBlockByHeight`

Alias for `get_block_by_height`. Returns block by height.

**Parameters:**
1. `height` (integer) - Block height

---

#### `sum_getBalance`

Alias for `get_balance`. Returns account balance in base units.

**Parameters:**
1. `address` (string) - Account address

**Returns:** `string` - Balance in base units

---

#### `sum_getNonce`

Alias for `get_nonce`. Returns account nonce.

**Parameters:**
1. `address` (string) - Account address

---

#### `sum_sendRawTransaction`

Alias for `send_raw_transaction`. Broadcasts a signed transaction.

**Parameters:**
1. `raw_tx` (string) - Hex-encoded signed transaction

---

#### `sum_getTransaction`

Alias for `get_transaction`. Returns transaction by hash.

**Parameters:**
1. `tx_hash` (string) - Transaction hash

---

#### `sum_getReceipt`

Alias for `get_receipt`. Returns transaction receipt.

**Parameters:**
1. `tx_hash` (string) - Transaction hash

---

#### `sum_getPendingTransactions`

Alias for `get_pending_transactions`. Returns pending transactions.

---

#### `sum_getValidators`

Alias for `get_validators`. Returns validator set.

---

### Ethereum-Compatible Methods (eth_* prefix)

For wallet compatibility (MetaMask, etc.), these Ethereum-style methods are supported:

#### `eth_blockNumber`

Returns the current block number in hex format.

**Parameters:** None

**Returns:** `string` - Hex-encoded block number (e.g., `"0x1a4"`)

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}'
```

---

#### `eth_getBalance`

Returns account balance in hex format.

**Parameters:**
1. `address` (string) - Account address
2. `block` (string) - Block number or "latest" (optional)

**Returns:** `string` - Hex-encoded balance

---

### NFT (SUM-721) Methods

#### `nft_getCollection`

Returns NFT collection information.

**Parameters:**
1. `collection_id` (string) - Collection ID (hex)

**Returns:** Collection object or `null`

| Field | Type | Description |
|-------|------|-------------|
| `collection_id` | string | Collection ID |
| `name` | string | Collection name |
| `symbol` | string | Collection symbol |
| `description` | string | Description |
| `owner` | string | Owner address |
| `max_supply` | integer | Maximum supply |
| `total_supply` | integer | Current supply |
| `transferable` | boolean | Can be transferred |
| `burnable` | boolean | Can be burned |

---

#### `nft_getToken`

Returns NFT token information.

**Parameters:**
1. `collection_id` (string) - Collection ID
2. `token_id` (integer) - Token ID

**Returns:** Token object or `null`

| Field | Type | Description |
|-------|------|-------------|
| `collection_id` | string | Collection ID |
| `token_id` | integer | Token ID |
| `owner` | string | Owner address |
| `creator` | string | Creator address |
| `metadata` | string | Token metadata |
| `minted_at` | integer | Mint timestamp |

---

#### `nft_getTokensByOwner`

Returns all NFTs owned by an address.

**Parameters:**
1. `owner` (string) - Owner address

**Returns:** Owner tokens object

| Field | Type | Description |
|-------|------|-------------|
| `owner` | string | Owner address |
| `count` | integer | Number of NFTs |
| `tokens` | array | Token references |

---

#### `nft_balanceOf`

Returns NFT count for an address.

**Parameters:**
1. `owner` (string) - Owner address

**Returns:** `integer` - Number of NFTs owned

---

#### `nft_ownerOf`

Returns owner of a specific NFT.

**Parameters:**
1. `collection_id` (string) - Collection ID
2. `token_id` (integer) - Token ID

**Returns:** `string` - Owner address or `null`

---

#### `nft_tokenExists`

Checks if an NFT exists.

**Parameters:**
1. `collection_id` (string) - Collection ID
2. `token_id` (integer) - Token ID

**Returns:** `boolean` - Exists

---

#### `nft_getTokensInCollection`

Returns all token IDs in a collection.

**Parameters:**
1. `collection_id` (string) - Collection ID

**Returns:** Array of token IDs

---

### SRC-20 Token Methods

SUM Chain's native fungible token standard, similar to ERC-20.

#### `token_getToken`

Returns SRC-20 token information by ID.

**Parameters:**
1. `token_id` (string) - Token ID (hex)

**Returns:** Token object or `null`

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string | Token ID (hex) |
| `name` | string | Token name |
| `symbol` | string | Token symbol |
| `decimals` | integer | Decimal places |
| `owner` | string | Owner address |
| `total_supply` | string | Current total supply |
| `max_supply` | string | Maximum supply (0 = unlimited) |
| `mintable` | boolean | Can mint new tokens |
| `burnable` | boolean | Can burn tokens |
| `pausable` | boolean | Can pause transfers |
| `paused` | boolean | Currently paused |
| `created_at` | integer | Creation timestamp (ms) |
| `created_at_block` | integer | Creation block height |

---

#### `token_balanceOf`

Returns SRC-20 token balance for an address.

**Parameters:**
1. `token_id` (string) - Token ID (hex)
2. `owner` (string) - Owner address

**Returns:** `string` - Balance in base units

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"token_balanceOf","params":["0x1234...","SUM1abc..."],"id":1}'
```

---

#### `token_getTokensByOwner`

Returns all SRC-20 tokens held by an address.

**Parameters:**
1. `owner` (string) - Owner address

**Returns:** Token holdings object

| Field | Type | Description |
|-------|------|-------------|
| `owner` | string | Owner address |
| `count` | integer | Number of different tokens |
| `tokens` | array | List of token balances |

Each token balance:

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string | Token ID (hex) |
| `symbol` | string | Token symbol |
| `decimals` | integer | Decimal places |
| `balance` | string | Balance in base units |

---

#### `token_allowance`

Returns SRC-20 token allowance for a spender.

**Parameters:**
1. `token_id` (string) - Token ID (hex)
2. `owner` (string) - Token owner address
3. `spender` (string) - Spender address

**Returns:** `string` - Allowance in base units

---

#### `token_totalSupply`

Returns total supply of an SRC-20 token.

**Parameters:**
1. `token_id` (string) - Token ID (hex)

**Returns:** `string` - Total supply in base units

---

#### `token_exists`

Checks if an SRC-20 token exists.

**Parameters:**
1. `token_id` (string) - Token ID (hex)

**Returns:** `boolean` - Exists

---

#### `token_getMinters`

Returns the registered minters of a single SRC-20 token. **Token-scoped**: it
answers "who may mint *this* token", read from the token's public config.

**Parameters:**
1. `token_id` (string) - Token ID (hex)

**Returns:** Object or `null` (token not found)

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | string | Token ID (hex) |
| `owner` | string | Token owner (implicit minter) |
| `minters` | string[] | Explicitly-registered minter addresses |

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"token_getMinters","params":["0x1234..."],"id":1}'
```

> **Not exposed (by design).** There is intentionally **no** address→tokens
> lookup — no "everything this address can mint" endpoint — and no maintained
> minter reverse index. Minter data is only queryable **per token id** (a token
> already in view), never as an address-wide minter profile; that broader
> address-profiling surface is out of scope and deferred to a future
> privacy/observability-reviewed change. Minters are read live from token config,
> so removals are reflected immediately.

---

## Subprotocol RPC surface

Read-only queries and unsigned-tx builders for the storage (SNIP V2) and OmniNode
subprotocols. Method signatures and field semantics are documented in the
subprotocol docs linked below; this is the discovery index. Several of these
belong to subprotocols whose activation gate is **set to height 8,900,000 —
active once the chain reaches it (≈2026-07-12)** (see the
[activation-gate table](../index.md#mainnet-activation-gates)) — the RPC methods
respond now, but the underlying write ops are rejected until the chain crosses
the gate.

### SNIP V2 storage (`storage_*`)

Detailed shapes: [SNIP-V2-RPC-CHEATSHEET.md](SNIP-V2-RPC-CHEATSHEET.md).

| Method | Notes |
|---|---|
| `storage_getFileInfoV2(merkle_root, offset?, limit?)` | Full V2 file row + paginated access list. |
| `storage_getPushableFilesV2(offset?, limit?)` | Pending+Active files (archive warm-cache). |
| `storage_getAssignmentCoverageV2(merkle_root, missing_offset?, missing_limit?)` | Coverage progress; **epoch-aware/aggregate** since issue #62. |
| `storage_getActiveNodesAtHeight(height)` | Active-archive snapshot at `assignment_height`. |
| `storage_getArchiveUnbonding(operator_address)` | Pending archive-node unbonding record, or `null` (issue #20; implemented, gate set to 8,900,000). |
| `storage_buildReassignChunksV2({from, merkle_root, fee?})` | **No-key** unsigned-tx builder for owner-triggered `ReassignChunksV2` (issue #80). Returns `{unsigned_tx, signing_hash, from, nonce, fee, chain_id}`; no signing/execution/authorization — executor stays authoritative. For non-Rust clients; the Rust CLI wallet builds locally. |
| `storage_getNodeRecord`, `storage_getAccessList`, `storage_getActiveChallenges`, `storage_getFundedFiles` | Node/ACL/challenge/funded-file reads. |

Archive-node **withdrawal** (issue #20) and **reassignment** (issue #62) are
implemented; their gates `archive_unbonding_enabled_from_height` /
`archive_reassignment_enabled_from_height` are **set to height 8,900,000 —
active once the chain reaches it (≈2026-07-12)**.

### OmniNode inference attestation (`sum_*InferenceAttestation*`) — active

| Method | Notes |
|---|---|
| `sum_getInferenceAttestation(session_id, verifier_address)` | One attestation record. |
| `sum_listInferenceAttestations(session_id)` | Every verifier for a session. |
| `sum_getInferenceAttestationStatus(tx_hash)` | Chain-side status of an attestation tx. |
| `sum_buildSponsoredInferenceAttestation(request)` | Build an unsigned **sponsored** (v2) attestation tx (issue #79): a payer/sponsor submits on a verifier's behalf. No keys; the sponsor signs offline. The attestation stays verifier-keyed for dedup, storage, and settlement. |

### OmniNode inference settlement (`omninode_*`) — gate set to 8,900,000 (issue #61)

Escrow-funded rewards keyed by attestations; implemented, with
`inference_settlement_enabled_from_height` **set to height 8,900,000 — active
once the chain reaches it (≈2026-07-12)**. Full model:
[inference-settlement.md](../subprotocols/inference-settlement.md). No bond
slashing in v1 (reward denial / claim withholding / escrow refund only).

| Method | Kind |
|---|---|
| `omninode_getInferenceSession(session_id)` | read |
| `omninode_getInferenceClaims(session_id)` | read |
| `omninode_getInferenceDisputes(session_id)` | read |
| `omninode_getClaimableReward(session_id, verifier)` | read |
| `omninode_getInferenceConsistency(session_id)` | read — attestations grouped by full digest tuple (issue #77 consistency mode) |
| `omninode_getVerifier(verifier)` | read — verifier bond record: bond, status, unbonding timers (issue #78) |
| `omninode_buildOpenInferenceSession` / `buildFundInferenceSession` / `buildClaimInferenceReward` / `buildOpenInferenceDispute` / `buildResolveInferenceDispute` / `buildRefundInferenceSession` | unsigned-tx builders (no keys). `buildOpenInferenceSession` accepts optional `consistency` (issue #77) and `bond_requirement` (issue #78) configs. Dispute resolution is validator-quorum controlled (no personal resolver key); `buildResolveInferenceDispute` accepts an optional `approvals` list of validator signatures. |
| `omninode_buildRegisterVerifier` / `buildAddVerifierBond` / `buildBeginVerifierUnbond` / `buildWithdrawVerifierBond` | verifier bond-registry builders (no keys, issue #78). Bond is native Koppa; slashing on a denied dispute burns to the zero address. |

### On-chain governance (`gov_*`) — gate set to 8,900,000

Token-holder governance behind `governance_enabled_from_height`. All writes go
through **no-key unsigned-tx builders** (client signs `signing_hash`, broadcasts
via `sum_sendRawTransaction`); reads expose governance data only. Full model:
[GOVERNANCE.md](../../GOVERNANCE.md). Validator-quorum authority (register paths)
is separate from public token-holder voting.

| Method | Kind |
|---|---|
| `gov_buildCreateProposal` / `gov_buildCastVote` / `gov_buildExecuteProposal` / `gov_buildCancelProposal` | unsigned-tx builders (no keys). SRC-20 snapshot voting (weight = frozen balance). |
| `gov_getProposal(id)` / `gov_listProposals` / `gov_listActiveProposals` / `gov_getTally(id)` / `gov_getVote(id, voter)` / `gov_getVotingPower(id, holder)` / `gov_listEligibleAssets` | reads |
| `gov_buildRegisterQualifyingAsset` | **Governance v2 (#91)** unsigned builder — validator-quorum registers an SRC-20 whose holders (balance ≥ `min_balance`) join the native-Koppa 1-address-1-vote electorate. |
| `gov_buildCastNativeVote` | **Governance v2 (#91)** unsigned builder — cast a native-eligibility vote (weight = 1 per eligible address; reuses the CastVote payload). |
| `gov_getNativeEligibility(proposal_id, address)` → `bool` | **Governance v2 (#91)** read — whether an address is in a native proposal's frozen eligibility snapshot. |
| `gov_listQualifyingAssets` | **Governance v2 (#91)** read — the native qualifying-SRC-20 registry (`token_id`, `min_balance`, `effective_height`). |
| `gov_buildRegisterEquityClass` | **Governance v2 (#92)** unsigned builder — validator-quorum registers an SRC-833 equity share class as a governance asset (weight = `shares × votes_per_share`). |
| `gov_buildCastEquityVote` | **Governance v2 (#92)** unsigned builder — controller-attested equity vote carrying `holder_commitment` / `shares` / `merkle_path` / `controller_pubkey` / `controller_sig` as **data** (no keys). |
| `gov_getEquityClassVoting(class_id)` → `{ balances_root, votes_per_share, voting }` | **Governance v2 (#92)** read — chain-derived balances root + params only; **never** a holder→balance table. |

### No-key unsigned-tx family builders (issue #89)

One builder per family, each taking a tagged operation request `{from, fee?, nonce?, chain_id?, <envelope ids>, op}`. **No-key** — no private keys, no signing, no submit, no execution, no authorization: the builder only assembles an unsigned `TransactionV2`. All return the shared shape `{unsigned_tx, signing_hash, from, nonce, fee, chain_id}`. `nonce`/`chain_id` are fetched from state when omitted. The client signs `signing_hash` locally and broadcasts via `sum_sendRawTransaction`; the executor stays authoritative for all authority/gate/lifecycle checks.

| Method | Notes |
|---|---|
| `token_buildTransaction({from, token_id?, op, ...})` | **No-key** SRC-20 builder. `op` (tagged): `create`, `mint`, `burn`, `transfer`, `approve`, `transfer_from`, `pause`, `unpause`, `transfer_ownership`, `add_minter`, `remove_minter`. `token_id` (hex) omitted for `create`. Decodes to `TxPayload::Token`. |
| `nft_buildTransaction({from, collection_id, token_id, op, ...})` | **No-key** SUM-721 builder. `op` (tagged): `create_collection`, `mint`, `mint_document`, `batch_mint`, `transfer`, `approve`, `burn`, `update_metadata`, `transfer_collection_ownership`, `update_collection_config`, `lock_token`, `unlock_token`. (`set_approval_for_all` is intentionally unsupported.) Decodes to `TxPayload::Nft`. |
| `staking_buildTransaction({from, op, ...})` | **No-key** staking builder covering all 11 ops: `create_validator`, `add_stake`, `unstake`, `update_validator`, `unjail`, `claim_rewards`, `delegate`, `undelegate`, `claim_delegation_rewards`, `withdraw_unbonded`, plus `submit_double_sign_evidence` / `submit_downtime_evidence`. Decodes to `TxPayload::Staking`. |
| `nodeRegistry_buildTransaction({from, op, ...})` | **No-key** node-registry builder: `register {role, stake}`, `begin_unstake {amount}`, `withdraw_unbonded`, `register_encryption_key {encryption_pubkey}`. `register_encryption_key` decodes to `TxPayload::NodeRegistryV2`, the rest to `TxPayload::NodeRegistry`. (`update_status` is privileged/internal and intentionally unsupported.) |

---

## REST Endpoints

### Health Checks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Full health status (JSON) |
| `/health/live` | GET | Liveness probe (200 OK) |
| `/health/ready` | GET | Readiness probe (200/503) |

### Metrics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | Prometheus metrics |

---

## Error Codes

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Invalid JSON-RPC request |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid parameters |
| -32603 | Internal error | Internal JSON-RPC error |
| -32000 | Server error | Generic server error |
| -32001 | Transaction rejected | Transaction validation failed |
| -32002 | Insufficient funds | Balance too low |
| -32003 | Nonce too low | Nonce already used |
| -32004 | Nonce too high | Nonce gap detected |

---

## Rate Limiting

Default rate limits (configurable):

| Endpoint | Limit |
|----------|-------|
| Read methods | 100 req/s |
| Write methods | 10 req/s |
| Subscriptions | 5 per connection |

---

## CLI Examples

### Using the Wallet CLI

```bash
# Check balance
sumchain-wallet balance --address SUM1abc... --rpc http://localhost:8545

# Transfer tokens (1.5 Koppa)
sumchain-wallet transfer \
    --key wallet.key \
    --to SUM1abc... \
    --amount 1.5 \
    --fee 0.001 \
    --chain-id 1

# Get block
sumchain-wallet block --height 100

# Check node status
sumchain-wallet status
```

### Using curl

```bash
# Get node info
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"node_info","id":1}'

# Get balance
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"get_balance","params":["SUM1abc..."],"id":1}'

# Get block number (Ethereum-compatible)
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}'

# Send transaction
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"send_raw_transaction","params":["0x..."],"id":1}'
```

---

## SDK Support

### TypeScript

Published package: **`@sumchain/sdk@0.2.3`** (current). Install with
`npm install @sumchain/sdk`.

```typescript
import { Provider } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');

// Get node info
const info = await provider.getHealth();
console.log(`Height: ${info.current_height}, Peers: ${info.peer_count}`);

// Get balance (returns BigInt in base units)
const balance = await provider.getBalance('SUM1abc...');
console.log(`Balance: ${Number(balance) / 1_000_000_000} Ϙ`);

// Get block number (Ethereum-compatible)
const blockNumber = await provider.getBlockNumber();

// Get latest block
const block = await provider.getLatestBlock();

// Wait for transaction
const receipt = await provider.waitForReceipt(txHash);
```

### Python

```python
import requests

def rpc_call(method, params=None):
    response = requests.post('http://localhost:8545', json={
        'jsonrpc': '2.0',
        'method': method,
        'params': params or [],
        'id': 1
    })
    return response.json()['result']

# Get node info
info = rpc_call('node_info')
print(f"Height: {info['current_height']}, Version: {info['version']}")

# Get balance
balance = int(rpc_call('get_balance', ['SUM1abc...']))
print(f'Balance: {balance / 1_000_000_000} Ϙ')

# Get block number (Ethereum-compatible, returns hex)
block_hex = rpc_call('eth_blockNumber')
block_number = int(block_hex, 16)
```

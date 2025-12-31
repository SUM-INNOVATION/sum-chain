# SUM Chain API Reference

SUM Chain exposes a JSON-RPC API for interacting with the blockchain. The native currency is **Koppa (Ϙ)** with 9 decimal places.

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

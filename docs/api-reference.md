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

#### `sum_blockNumber`

Returns the current block height.

**Parameters:** None

**Returns:** `string` - Hex-encoded block number

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"sum_blockNumber","id":1}'
```

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": "0x1a4"
}
```

---

#### `sum_getBlockByHeight`

Returns block information by height.

**Parameters:**
1. `height` (integer) - Block height

**Returns:** Block object or `null`

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
    -d '{"jsonrpc":"2.0","method":"sum_getBlockByHeight","params":[100],"id":1}'
```

---

#### `sum_getLatestBlock`

Returns the latest block.

**Parameters:** None

**Returns:** Block object (same as `sum_getBlockByHeight`)

---

### Account Methods

#### `sum_getBalance`

Returns the account balance in base units.

**Parameters:**
1. `address` (string) - Account address (base58 or hex)

**Returns:** `string` - Balance in base units

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"sum_getBalance","params":["5Hq8...]","id":1}'
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

#### `sum_getNonce`

Returns the account nonce (transaction count).

**Parameters:**
1. `address` (string) - Account address

**Returns:** `integer` - Current nonce

---

### Transaction Methods

#### `sum_sendRawTransaction`

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
    -d '{"jsonrpc":"2.0","method":"sum_sendRawTransaction","params":["0x..."],"id":1}'
```

---

#### `sum_getTransaction`

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

#### `sum_getReceipt`

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

#### `sum_getPendingTransactions`

Returns pending transactions in the mempool.

**Parameters:** None

**Returns:** Array of transaction objects

---

### Validator Methods

#### `sum_getValidators`

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

### P2P Methods

#### `p2p_peers`

Returns connected peers.

**Parameters:** None

**Returns:** Object with peer info

| Field | Type | Description |
|-------|------|-------------|
| `peer_count` | integer | Number of peers |
| `peers` | array | Peer details |

---

#### `p2p_localPeerId`

Returns the local peer ID.

**Parameters:** None

**Returns:** `string` - Local peer ID

---

### Health Methods

#### `health`

Returns node health status.

**Parameters:** None

**Returns:** Health object

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | "healthy" or "unhealthy" |
| `chain_id` | integer | Chain ID |
| `height` | integer | Current block height |
| `peer_count` | integer | Connected peers |
| `is_validator` | boolean | Running as validator |
| `is_synced` | boolean | Fully synced |

**Example:**
```bash
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"health","id":1}'
```

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "status": "healthy",
        "chain_id": 1,
        "height": 420,
        "peer_count": 5,
        "is_validator": true,
        "is_synced": true
    }
}
```

---

### Ethereum-Compatible Methods

For wallet compatibility, these Ethereum-style methods are supported:

#### `eth_blockNumber`

Alias for `sum_blockNumber`.

---

#### `eth_chainId`

Returns the chain ID in hex format.

**Returns:** `string` - Hex-encoded chain ID

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

## WebSocket Support

WebSocket connections are supported on the same port for subscriptions:

```javascript
const ws = new WebSocket('ws://localhost:8545');

// Subscribe to new blocks
ws.send(JSON.stringify({
    jsonrpc: '2.0',
    method: 'subscribe',
    params: ['newBlocks'],
    id: 1
}));

// Subscribe to pending transactions
ws.send(JSON.stringify({
    jsonrpc: '2.0',
    method: 'subscribe',
    params: ['pendingTransactions'],
    id: 2
}));
```

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
sumchain-wallet balance --address 5Hq8... --rpc http://localhost:8545

# Transfer tokens (1.5 Koppa)
sumchain-wallet transfer \
    --key wallet.key \
    --to 5Hq8... \
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
# Get balance
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"sum_getBalance","params":["5Hq8..."],"id":1}'

# Send transaction
curl -X POST http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"sum_sendRawTransaction","params":["0x..."],"id":1}'
```

---

## SDK Support

### JavaScript/TypeScript

```typescript
import { JsonRpcProvider } from 'sumchain-sdk';

const provider = new JsonRpcProvider('http://localhost:8545');

// Get balance (returns BigInt in base units)
const balance = await provider.getBalance('5Hq8...');
console.log(`Balance: ${balance / 1_000_000_000n} Ϙ`);

// Send transaction
const txHash = await provider.sendTransaction(signedTx);
```

### Rust

```rust
use sumchain_rpc::api::SumChainApiClient;
use jsonrpsee::http_client::HttpClientBuilder;

let client = HttpClientBuilder::default()
    .build("http://localhost:8545")?;

let balance = client.get_balance("5Hq8...".to_string()).await?;
```

### Python

```python
import requests

def get_balance(address):
    response = requests.post('http://localhost:8545', json={
        'jsonrpc': '2.0',
        'method': 'sum_getBalance',
        'params': [address],
        'id': 1
    })
    return int(response.json()['result'])

# Convert to Koppa
balance_koppa = get_balance('5Hq8...') / 1_000_000_000
print(f'Balance: {balance_koppa} Ϙ')
```

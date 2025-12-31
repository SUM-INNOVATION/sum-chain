# SUM Chain

A Layer-1 blockchain built entirely in Rust (stable toolchain). No C/C++, Python, Go, JS/TS, or Solidity.

**Native Currency:** Koppa (Ϙ) with 9 decimal places

## Features

- **Proof of Authority (PoA) Consensus**: Round-robin validator rotation with deterministic block production
- **Blake3 Hashing**: Fast, modern cryptographic hash function (reference impl is Rust)
- **Ed25519 Signatures**: Secure digital signatures for transactions and blocks
- **Account-Based State Model**: Simple balance and nonce tracking
- **Koppa Currency**: Native token with symbol Ϙ (1 Koppa = 1,000,000,000 base units)
- **libp2p Networking**: Gossipsub for transaction/block propagation, mDNS for local discovery
- **JSON-RPC API**: HTTP server for chain queries and transaction submission
- **RocksDB Storage**: Persistent key-value storage for blocks and state
- **Enhanced CLI Wallet**: Colored output, human-readable amounts, interactive confirmations

## Architecture

```
sum-chain/
├── crates/
│   ├── primitives/     # Core types: Hash, Address, Block, Transaction
│   ├── crypto/         # Ed25519 keys/signatures, Blake3 hashing
│   ├── storage/        # RocksDB persistence layer
│   ├── genesis/        # Genesis configuration
│   ├── state/          # Account state, transaction execution, mempool
│   ├── consensus/      # PoA consensus engine
│   ├── p2p/            # libp2p networking
│   ├── rpc/            # JSON-RPC server
│   ├── node/           # Full node binary
│   └── wallet/         # CLI wallet
├── scripts/            # Setup scripts (Rust)
├── configs/            # Node configuration files
└── genesis/            # Genesis file templates
```

## Requirements

- Rust stable toolchain (1.70+)
- RocksDB (installed via cargo, no separate installation needed)

## Build

```bash
# Build all crates
cargo build --release

# Run tests
cargo test --all
```

## Quick Start: Local Testnet

### 1. Generate Keys and Genesis

```bash
# Run the setup script to generate validator keys and genesis
cargo run --bin setup-local-testnet
```

This creates:
- `keys/validator1.json`, `keys/validator2.json`, `keys/validator3.json` - Validator private keys
- `keys/test_account.json` - Test account for sending transactions
- `genesis/local_genesis.json` - Genesis file with validators and prefunded accounts

### 2. Start Validator Nodes

Open 3 terminals and start each validator:

**Terminal 1 - Validator 1:**
```bash
cargo run --release --bin sumchain -- run \
  --genesis genesis/local_genesis.json \
  --data-dir data/validator1 \
  --validator-key keys/validator1.json \
  --p2p-addr /ip4/0.0.0.0/tcp/30301 \
  --rpc-addr 127.0.0.1:8545
```

**Terminal 2 - Validator 2:**
```bash
cargo run --release --bin sumchain -- run \
  --genesis genesis/local_genesis.json \
  --data-dir data/validator2 \
  --validator-key keys/validator2.json \
  --p2p-addr /ip4/0.0.0.0/tcp/30302 \
  --rpc-addr 127.0.0.1:8546 \
  --bootnodes /ip4/127.0.0.1/tcp/30301
```

**Terminal 3 - Validator 3:**
```bash
cargo run --release --bin sumchain -- run \
  --genesis genesis/local_genesis.json \
  --data-dir data/validator3 \
  --validator-key keys/validator3.json \
  --p2p-addr /ip4/0.0.0.0/tcp/30303 \
  --rpc-addr 127.0.0.1:8547 \
  --bootnodes /ip4/127.0.0.1/tcp/30301
```

### 3. Start a Full Node (Optional)

```bash
cargo run --release --bin sumchain -- run \
  --genesis genesis/local_genesis.json \
  --data-dir data/fullnode \
  --p2p-addr /ip4/0.0.0.0/tcp/30304 \
  --rpc-addr 127.0.0.1:8548 \
  --bootnodes /ip4/127.0.0.1/tcp/30301
```

### 4. Query the Chain

```bash
# Check node info
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"node_info","params":[],"id":1}'

# Get latest block
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_latest_block","params":[],"id":1}'

# Get block number (Ethereum-compatible, returns hex)
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Get balance (replace ADDRESS with actual address)
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"get_balance","params":["ADDRESS"],"id":1}'
```

### 5. Send a Transaction

Using the enhanced wallet CLI with Koppa (Ϙ) amounts:

```bash
# Check balance (displays in Koppa)
cargo run --bin sumchain-wallet -- balance \
  --rpc http://127.0.0.1:8545 \
  --address YOUR_ADDRESS

# Example output:
# Address: 5HqX...
# Balance: 100 Ϙ

# Transfer Koppa tokens (interactive with confirmation)
cargo run --bin sumchain-wallet -- transfer \
  --key keys/test_account.json \
  --rpc http://127.0.0.1:8545 \
  --to RECIPIENT_ADDRESS \
  --amount 1.5 \
  --fee 0.001 \
  --chain-id 1337

# Skip confirmation with -y flag
cargo run --bin sumchain-wallet -- transfer \
  --key keys/test_account.json \
  --to RECIPIENT_ADDRESS \
  --amount 10 \
  --chain-id 1337 \
  -y
```

Or sign offline and broadcast separately:

```bash
# Sign a transaction offline (amounts in Koppa)
cargo run --bin sumchain-wallet -- sign-tx \
  --key keys/test_account.json \
  --to RECIPIENT_ADDRESS \
  --amount 1.5 \
  --fee 0.001 \
  --nonce 0 \
  --chain-id 1337

# Send the raw transaction
cargo run --bin sumchain-wallet -- send \
  --rpc http://127.0.0.1:8545 \
  --raw RAW_TX_HEX
```

## RPC API

**All amounts in the RPC API are returned in base units.**

To convert:
- From Koppa to base units: multiply by 1,000,000,000
- From base units to Koppa: divide by 1,000,000,000

Example: A balance of `"1500000000"` = 1.5 Ϙ

For detailed API documentation, see [docs/api-reference.md](docs/api-reference.md).

### Chain & Block Methods

| Generic Method | SUM Native | ETH Compatible | Description |
|---------------|------------|----------------|-------------|
| `chain_id` | - | - | Get chain ID |
| `get_latest_block` | `sum_getLatestBlock` | - | Get the latest block |
| `get_block_by_height` | `sum_getBlockByHeight` | - | Get block by height |
| `get_block_by_hash` | - | - | Get block by hash |
| `get_blocks` | - | - | Get multiple blocks in a range |
| - | `sum_blockNumber` | `eth_blockNumber` | Get current block height |

### Account Methods

| Generic Method | SUM Native | ETH Compatible | Description |
|---------------|------------|----------------|-------------|
| `get_balance` | `sum_getBalance` | `eth_getBalance` | Get account balance |
| `get_nonce` | `sum_getNonce` | - | Get account nonce |
| `get_account` | - | - | Get full account info |

### Transaction Methods

| Generic Method | SUM Native | Description |
|---------------|------------|-------------|
| `send_raw_transaction` | `sum_sendRawTransaction` | Submit a signed transaction |
| `get_transaction` | `sum_getTransaction` | Get transaction by hash |
| `get_receipt` | `sum_getReceipt` | Get transaction receipt |
| `get_pending_transactions` | `sum_getPendingTransactions` | Get all pending transactions |
| `pending_tx_count` | - | Get mempool size |

### Validator Methods

| Generic Method | SUM Native | Description |
|---------------|------------|-------------|
| `get_validators` | `sum_getValidators` | Get current validator set |
| `get_finality` | - | Get finality information |
| `is_block_finalized` | - | Check if block is finalized |

### P2P & Network Methods
| Method | Description |
|--------|-------------|
| `get_peers` | Get connected peer information |
| `get_p2p_stats` | Get P2P network statistics |

### Health & Monitoring Methods
| Method | Description |
|--------|-------------|
| `health` | Health check with node status |
| `node_info` | Get node version, peer info, etc. |
| `get_metrics` | Get node metrics (Prometheus format) |

### NFT (SUM-721) Methods
| Method | Description |
|--------|-------------|
| `nft_getCollection` | Get NFT collection by ID |
| `nft_getToken` | Get NFT token by collection and token ID |
| `nft_getTokensByOwner` | Get all NFTs owned by address |
| `nft_balanceOf` | Get NFT count for address |
| `nft_ownerOf` | Get owner of specific NFT |
| `nft_tokenExists` | Check if NFT exists |
| `nft_getTokensInCollection` | Get all token IDs in collection |

**Note:** All methods have three naming styles:
- **Generic** (`get_balance`): Standard snake_case, recommended for most use cases
- **SUM Native** (`sum_getBalance`): Branded methods with `sum_` prefix
- **ETH Compatible** (`eth_getBalance`): Ethereum-style for wallet compatibility (hex responses)

## Wallet CLI

The enhanced wallet CLI now supports human-readable Koppa (Ϙ) amounts with colored output:

| Command | Description | Example |
|---------|-------------|---------|
| `info` | Show wallet info and version | `sumchain-wallet info` |
| `keygen` | Generate new encrypted keypair | `sumchain-wallet keygen -o wallet.key` |
| `address` | Show address for a key | `sumchain-wallet address -k wallet.key` |
| `pubkey` | Show public key | `sumchain-wallet pubkey -k wallet.key` |
| `balance` | Query account balance (in Ϙ) | `sumchain-wallet balance --address ADDR` |
| `nonce` | Query account nonce | `sumchain-wallet nonce --address ADDR` |
| `transfer` | Transfer Koppa with confirmation | `sumchain-wallet transfer -k key --to ADDR --amount 1.5` |
| `sign-tx` | Sign a transaction offline | `sumchain-wallet sign-tx -k key --to ADDR --amount 1.5 --fee 0.001` |
| `send` | Broadcast a signed transaction | `sumchain-wallet send --raw TX_HEX` |
| `tx` | Get transaction details | `sumchain-wallet tx --hash TX_HASH` |
| `receipt` | Get transaction receipt | `sumchain-wallet receipt --hash TX_HASH` |
| `block` | Get block by height | `sumchain-wallet block --height 100` |
| `block-number` | Get current block height | `sumchain-wallet block-number` |
| `validators` | Get validator set | `sumchain-wallet validators` |
| `pending` | Get pending transactions | `sumchain-wallet pending` |
| `status` | Get node health status | `sumchain-wallet status` |

**Features:**
- Human-readable amounts (e.g., `1.5 Ϙ` instead of `1500000000`)
- Colored output for better readability
- Interactive confirmation prompts for transfers
- Balance checking before transfers
- Support for both base58 and hex addresses
- `--no-color` flag for scripts/CI

## Configuration

### Genesis Format

```json
{
  "chain_id": 1337,
  "genesis_time": 1700000000000,
  "validators": [
    "VALIDATOR1_PUBKEY_BASE58",
    "VALIDATOR2_PUBKEY_BASE58"
  ],
  "alloc": {
    "ADDRESS_BASE58": 1000000000000000000
  },
  "params": {
    "block_time_ms": 2000,
    "max_block_bytes": 1000000,
    "max_txs_per_block": 1000,
    "min_fee": 1000000
  }
}
```

**Note:** All amounts in genesis are in base units. For example:
- `1000000000` = 1 Ϙ
- `1500000000` = 1.5 Ϙ
- `1000000000000` = 1,000 Ϙ
- `min_fee: 1000000` = 0.001 Ϙ minimum fee

### Node Configuration

```json
{
  "name": "node-name",
  "data_dir": "data/node",
  "listen_addr": "/ip4/0.0.0.0/tcp/30303",
  "bootnodes": ["/ip4/127.0.0.1/tcp/30301"],
  "is_validator": true,
  "validator_key_path": "keys/validator.json",
  "rpc_addr": "127.0.0.1:8545",
  "rpc_enabled": true,
  "log_level": "info"
}
```

## Transaction Format

```
Transaction:
- chain_id: u64
- from: Address (20 bytes)
- to: Address (20 bytes)
- amount: u128 (in base units, 1 Ϙ = 1,000,000,000)
- fee: u128 (in base units)
- nonce: u64

SignedTransaction:
- tx: Transaction
- signature: [u8; 64] (Ed25519)
- public_key: [u8; 32] (Ed25519)
```

**Koppa Currency:**
- Symbol: Ϙ (Greek letter Koppa)
- Decimals: 9
- Base unit: 1 Koppa = 1,000,000,000 base units
- Example amounts:
  - Transfer 1.5 Ϙ: `amount = 1500000000`
  - Fee 0.001 Ϙ: `fee = 1000000`

## Consensus: Proof of Authority

- Validators are defined in genesis
- Round-robin proposer selection: `proposer = validators[height % validator_count]`
- Block time: configurable (default 2 seconds)
- Fork choice: longest chain, with hash tiebreaker

## Security Considerations

- All cryptography uses audited Rust crates (ed25519-dalek, blake3)
- Deterministic serialization with bincode
- Nonce-based replay protection
- Chain ID for cross-chain replay protection
- Encrypted wallet keystores (Argon2 + AES-256-GCM)

## Production Features

### Completed

- **Koppa Currency**: Native token with Ϙ symbol, 9 decimals, human-readable formatting
- **Enhanced CLI Wallet**: Colored output, interactive confirmations, balance checks
- **TOML Configuration**: File-based configuration with CLI overrides
- **Health Check Endpoints**: `/health` (liveness) and `/ready` (readiness) HTTP endpoints
- **Prometheus Metrics**: `/metrics` endpoint with full node metrics in Prometheus format
- **Database Recovery**: Auto-repair on corruption, integrity checks, manual repair command
- **Backup/Snapshot Support**: CLI commands for backup, restore, list backups, and compaction
- **State Snapshot Sync**: Fast sync from snapshots without replaying all blocks
- **Block Synchronization**: Full sync from genesis for new nodes
- **Peer Management**: Connection limits, peer scoring/reputation, exponential backoff, RPC peer info
- **Transaction Rebroadcasting**: Automatic retry for pending transactions
- **Graceful Shutdown**: Clean termination with database flush
- **Finality Tracking**: Block finality after 2/3 validator confirmations
- **Rate Limiting**: Per-IP request rate limiting for RPC
- **API Authentication**: Optional API key authentication for RPC
- **Integration Tests**: 16 end-to-end tests for multi-node scenarios
- **Docker/Kubernetes**: Container images and orchestration manifests
- **Monitoring Dashboard**: Grafana dashboards for validators
- **Documentation**: Operator guide and complete API reference

### Node CLI Commands

| Command | Description |
|---------|-------------|
| `run` | Start a full node |
| `gen-config` | Generate example configuration file |
| `backup` | Create a database backup |
| `restore` | Restore from a backup |
| `list-backups` | List available backups |
| `compact` | Compact the database |

## Phase 2 Roadmap

### Proof of Stake (PoS)
- Stake delegation
- Validator rewards and slashing
- Economic finality

### Light Clients
- Merkle proofs for state verification
- Header-only sync
- Light client protocol

### Smart Contracts (Optional)
- WASM-based VM
- Contract deployment and execution
- Gas metering

### Bridging / IBC
- Cross-chain communication
- Asset transfers
- Relayer infrastructure

## License

MIT

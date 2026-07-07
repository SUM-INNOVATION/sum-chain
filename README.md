# SUM Chain

![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2021-orange)
![Toolchain](https://img.shields.io/badge/toolchain-1.85.0-orange)
![SNIP](https://img.shields.io/badge/SNIP-V2%20active-green)
![OmniNode](https://img.shields.io/badge/OmniNode-InferenceAttestation%20v1%20active-purple)

A Layer-1 blockchain built entirely in Rust (stable toolchain). No C/C++, Python, Go, JS/TS, or Solidity.

**Native Currency:** Koppa (Ϙ) with 9 decimal places

## Project Process

- [Governance](GOVERNANCE.md) — code-backed governance v1 is deployed and code-backed; its activation gate `governance_enabled_from_height` is **set to height 8,900,000** — active once the chain reaches it (≈2026-07-12). Admin/council authority is **validator-quorum** controlled (a quorum of the active PoA validator set), not a single council address. Design spec: [docs/specs/GOVERNANCE-V1.md](docs/specs/GOVERNANCE-V1.md).
- [Release process](RELEASE.md) — record-first release and rollout process.
- [Security](SECURITY.md) — private vulnerability reporting.
- [Contributing](CONTRIBUTING.md) — PR and review policy.

**Protocol status (live mainnet, height 8,716,604 · 2026-07-06):** SNIP V2 storage and OmniNode `InferenceAttestation` v1 are **active** (gates already reached). Governance v1, WASM smart contracts, Education (SRC-817/818), archive unbonding (#20), archive reassignment (#62), and inference settlement (#61) are **deployed and code-backed; their activation gate is set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)**.

## Features

- **Proof of Authority (PoA) Consensus**: Round-robin validator rotation with deterministic block production
- **Blake3 Hashing**: Fast, modern cryptographic hash function (reference impl is Rust)
- **Ed25519 Signatures**: Secure digital signatures for transactions and blocks
- **Account-Based State Model**: Simple balance and nonce tracking
- **Koppa Currency**: Native token with symbol Ϙ (1 Koppa = 1,000,000,000 base units)
- **SUM-721 NFTs**: Native NFT standard for digital assets and certified documents
- **SRC-20 Tokens**: Native fungible token standard (ERC-20 compatible interface)
- **Staking & Delegation**: Validator staking, delegation rewards, and slashing
- **WASM Smart Contracts**: Contract deployment and execution via sumc-runtime
- **Policy Accounts**: Consensus-level multi-sig group governance
- **On-chain Encrypted Messaging**: SRC-201 standard using X25519 + XChaCha20-Poly1305
- **SRC-80X through SRC-89X Document Token Families**: DocClass, Tax, Equity, Agreement, Legal, Property, Healthcare, Employment, Finance
- **SNIP V2 Storage Protocol**: Decentralized file storage with on-chain metadata. Pending → Active → Abandoned lifecycle, ed25519 X25519-derived encryption keys, archive-node staking + replication assignment, fee pools, and per-block PoR challenges. Activation gated by `v2_enabled_from_height`. See `crates/state/src/storage_metadata.rs` and `docs/SNIP-V2.md` (where present)
- **Dynamic Validator Sets**: Epoch-based, stake-weighted validator selection
- **libp2p Networking**: Gossipsub for transaction/block propagation, mDNS for local discovery
- **JSON-RPC API**: HTTP server for chain queries and transaction submission (ETH + SUM compatible)
- **RocksDB Storage**: Persistent key-value storage for blocks and state
- **Enhanced CLI Wallet**: Colored output, human-readable amounts, interactive confirmations

## Subprotocols

| Name | Status | Location | Purpose |
|---|---|---|---|
| SRC-201 Messaging (a.k.a. SNIP V1) | Production (mainnet) | `crates/primitives/src/messaging.rs`, `crates/state/src/messaging_executor.rs` | On-chain encrypted messaging (X25519 + XChaCha20-Poly1305). Supports sender-paid and sponsored submission. |
| SNIP V2 Storage Protocol | Production behind `v2_enabled_from_height` activation gate | `crates/state/src/storage_metadata.rs`, `crates/state/src/inference_attestations.rs` (forthcoming) | Decentralized file storage with chain-side metadata: Pending/Active/Abandoned lifecycle, encryption-key registry, archive-node staking, PoR challenges. Genesis param controls activation. |
| OmniNode `InferenceAttestation` | v1 merged on `main` (PR [#1](https://github.com/SUM-INNOVATION/sum-chain/pull/1) — wire format, executor, mempool, RPC, docs; PR [#2](https://github.com/SUM-INNOVATION/sum-chain/pull/2) — `chain_getChainParams.omninode_enabled_from_height`). Active on mainnet (`omninode_enabled_from_height = 6,000,000`, live params verified at height 8,716,604 · 2026-07-06); fresh-chain genesis default `None`. Activation readiness: [`docs/subprotocols/INFERENCE-ATTESTATION-ACTIVATION.md`](docs/subprotocols/INFERENCE-ATTESTATION-ACTIVATION.md). | Spec: [`docs/subprotocols/INFERENCE-ATTESTATION.md`](docs/subprotocols/INFERENCE-ATTESTATION.md). Code: `crates/primitives/src/inference_attestation.rs`, `crates/state/src/inference_attestation_executor.rs`, `crates/state/src/mempool.rs` (`InferenceAttestationAdmission`), `crates/node/src/node.rs` (admission wiring), `crates/rpc/src/api.rs` + `server.rs` (RPC methods), fixtures in `crates/primitives/tests/fixtures/` | Verifier-signed digests attesting to off-chain inference outputs. Inner Stage 6 signature (`omninode.inference_attestation.v1` domain) verified at chain side; outer chain signing semantics unchanged. Activation gated by `omninode_enabled_from_height` (mainnet active at `6,000,000`; fresh-chain default `None`). Mempool admission enforces activation gate + in-flight duplicate + permanent CF duplicate. Read-only RPC: `sum_getInferenceAttestation`, `sum_listInferenceAttestations`, `sum_getInferenceAttestationStatus`. Full protocol contract in the linked doc. |
| SNIP V2 archive-node withdrawal + reassignment | Code-backed and **implemented**; gates `archive_unbonding_enabled_from_height` [#20] and `archive_reassignment_enabled_from_height` [#62] are **set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)** (height 8,716,604 · 2026-07-06). | Code: `crates/state/src/node_registry.rs`, `crates/state/src/storage_metadata.rs`; RPC in `crates/rpc/src/api.rs` + `server.rs`. RPC cheatsheet: [`docs/rpc/SNIP-V2-RPC-CHEATSHEET.md`](docs/rpc/SNIP-V2-RPC-CHEATSHEET.md); design §5.4 in [`docs/specs/SNIP-V2-CHAIN-PLAN.md`](docs/specs/SNIP-V2-CHAIN-PLAN.md). | Two separate landed mechanics. **#20**: full-exit archive-node stake unbonding (`BeginUnstake`/`WithdrawUnbonded`, `Unbonding`/`Withdrawn` node states, `storage_getArchiveUnbonding`, wallet `archive-begin-unstake`/`archive-withdraw`/`archive-unbonding`). **#62**: deterministic chunk reassignment (`ReassignChunksV2`, epoch-aware attestation CFs with epoch-0 bitmaps untouched, epoch-aware/aggregate `storage_getAssignmentCoverageV2`). Both implemented; each takes effect once the chain crosses gate height 8,900,000. |
| OmniNode Inference Settlement (v1) | Code-backed and **implemented**; gate `inference_settlement_enabled_from_height` is **set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)** (height 8,716,604 · 2026-07-06). Separate from attestation, which is already active. | Spec: [`docs/subprotocols/inference-settlement.md`](docs/subprotocols/inference-settlement.md). Code: `crates/primitives/src/inference_settlement.rs`, `crates/state/src/inference_settlement_executor.rs`, RPC `omninode_*` in `crates/rpc/`. | Escrow-funded verifier rewards keyed by the immutable `(session_id, verifier)` attestations. Supply-conserving — no mint/inflation. Levers are **reward denial / claim withholding / escrow refund**; **no bond slashing in v1** (no verifier bond exists). Claim maturity = attestation inclusion + `finality_depth` + `dispute_window_blocks`; refunds cannot bypass pending immature claims. Dispute resolution is **validator-quorum** controlled via `inference_settlement_dispute_threshold_bps` (a threshold of the active validator set signs `ResolveDispute`; no single resolver key). Attestation v1 untouched. Issue #61. |
| SRC-817/818 Education (Course Catalog + Offering) | Phases 0–6 merged on `main`. Deployed and code-backed; `education_enabled_from_height` is **set to height 8,900,000 — active once the chain reaches it (≈2026-07-12)** (height 8,716,604 · 2026-07-06). Activation readiness: [`docs/subprotocols/EDUCATION-ACTIVATION.md`](docs/subprotocols/EDUCATION-ACTIVATION.md). | Usage: [`docs/tokens.md`](docs/tokens.md) (Education). Code: `crates/primitives/src/education.rs`, `crates/state/src/education_executor.rs`, `crates/state/src/mempool.rs` (`EducationAdmission`), `crates/rpc/` (`src817_*`/`src818_*` read-only RPC). | LMS catalog/offering/assessment/enrollment/submission-receipt/grade. Activation gated by `education_enabled_from_height` (set to 8,900,000 on mainnet). Privacy-first: students only as scoped `student_commitment`; sponsor/institution `tx.from` (never the student); no raw grades/submissions/answer-keys/PII on-chain or RPC. Policy B fee/nonce. Read-only RPC only (reads work regardless of the gate). |

## Local Development

For SNIP V2 client integration without spinning up a full 3-validator local testnet, the chain ships a self-bootstrapping single-validator Docker preset on the `snip-local-mirror-preset` branch:

```bash
git checkout snip-local-mirror-preset
docker-compose -f deploy/snip-local-mirror.yaml up -d --build
curl -X POST -H 'Content-Type: application/json' \
     --data '{"jsonrpc":"2.0","id":1,"method":"chain_id","params":[]}' \
     http://localhost:8545
# → {"jsonrpc":"2.0","result":31337,"id":1}
```

Generates a fresh disposable validator key on first boot, renders genesis from a committed template (`genesis/snip-mirror-genesis.template.json`), and exposes RPC on `localhost:8545`. `docker-compose down -v` wipes everything; `stop` / `start` preserves the chain. SNIP-side test addresses can be pre-funded via a mounted `extra-alloc.json` overlay before the first `up`.

## Architecture

```
sum-chain/
├── crates/
│   ├── bridge/             # Cross-chain bridging
│   ├── consensus/          # PoA consensus engine
│   ├── crypto/             # Ed25519 keys/signatures, Blake3 hashing
│   ├── genesis/            # Genesis configuration
│   ├── integration-tests/  # End-to-end multi-node tests
│   ├── nft/                # SUM-721 NFT standard
│   ├── node/               # Full node binary
│   ├── p2p/                # libp2p networking
│   ├── primitives/         # Core types: Hash, Address, Block, Transaction
│   ├── rpc/                # JSON-RPC server
│   ├── state/              # Account state, transaction execution, mempool
│   ├── storage/            # RocksDB persistence layer
│   ├── sumc-runtime/       # WASM smart contract runtime
│   ├── sumc-sdk/           # SDK for building on SUM Chain
│   ├── sumc-sdk-macros/    # Procedural macros for sumc-sdk
│   ├── token/              # SRC-20 fungible token standard
│   └── wallet/             # CLI wallet
├── sdk/
│   └── typescript/         # TypeScript SDK
├── explorer/               # Block explorer (React)
├── scripts/                # Setup scripts (Rust)
├── configs/                # Node configuration files
└── genesis/                # Genesis file templates
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

## Run a node (join the live network)

For most operators, "running a node" means **joining an already-running network**
(a shared testnet or mainnet) — not creating a new chain. You do that with the
network's own `config.toml` and `genesis.json` plus at least one bootnode:

```bash
sumchain run \
  --config config.toml \
  --genesis genesis.json \
  --bootnodes /ip4/<PUBLIC_IP>/tcp/9933/p2p/<PEER_ID>
```

- **`config.toml`** is the canonical node config (TOML). Its defaults expose
  JSON-RPC on `127.0.0.1:8545` and P2P on `/ip4/0.0.0.0/tcp/9933`.
- **`genesis.json`** is the network's runtime genesis. Every node on a network
  must run a **byte-identical** `genesis.json`. **Do not edit genesis to join** —
  obtain the exact file from the operators; a mismatched genesis will not sync.
- **`config.toml` and `genesis.json` are network-specific and obtained
  out-of-band** from the operator team / a secure channel. They are **not** the
  local templates in this repo — in particular, `genesis/local_genesis.json` is
  only for a throwaway local network (see
  [Starting a new local network](#starting-a-new-local-network-local-development-only)).

### Bootnodes

The sample `config.toml` ships `bootnodes = []` on purpose — no real peer
addresses live in source control, and `mdns` only discovers peers on the same
LAN. To join across hosts you must supply at least one **bootnode**, obtained
out-of-band. **Real bootnode IPs / peer-ids must never be committed.** A bootnode
multiaddr is a placeholder of the form:

```
/ip4/<PUBLIC_IP>/tcp/9933/p2p/<PEER_ID>
```

Supply it with the CLI/systemd `--bootnodes` flag (shown above); that override
takes precedence over `config.toml`, so it keeps working even if a later deploy
resets the tracked sample config back to `bootnodes = []`. (You *may* instead set
`bootnodes` in a host-local `config.toml` and protect it with
`git update-index --skip-worktree config.toml`, but that does not survive a hard
reset — prefer `--bootnodes`.)

> **Running a full node does not make you a validator.** Syncing the chain and
> producing blocks are different roles — see
> [Becoming a validator](#becoming-a-validator).

## Becoming a validator

Supplying a bootnode lets your node **sync** as a full node. That is **not** the
same as becoming a **block-producing validator**. Under the current PoA
consensus, block production requires your validator public key to be in the
**active validator set**, which is coordinated separately by the operator team
(via genesis / the validator-set process) — a node does not become a producer
just by joining the network.

If you are approved to run a validator, **generate your own validator key** (never
reuse another node's key) and run with it once your key is in the active set:

```bash
sumchain keygen --output keys/validator.json
sumchain run --config config.toml --genesis genesis.json \
  --bootnodes /ip4/<PUBLIC_IP>/tcp/9933/p2p/<PEER_ID> \
  --validator-key keys/validator.json
```

## Starting a new local network (local development only)

**Local development only.** The steps below **bootstrap a brand-new, throwaway
network from scratch** on one machine — they generate their own validator keys
and a local `genesis/local_genesis.json`, and wire nodes together over loopback.
This is for development and testing. **It is not how you join the live network**
(see [Run a node](#run-a-node-join-the-live-network)); never use
`genesis/local_genesis.json` or loopback bootnodes to reach a shared testnet or
mainnet.

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

### 3. Start a Local Full Node (Optional)

This joins the **local** testnet created above (local genesis, loopback bootnode).
To sync a **shared testnet or mainnet** instead, see
[Run a node (join the live network)](#run-a-node-join-the-live-network) — that
uses the network-provided `config.toml` / `genesis.json` and an out-of-band
bootnode, not the local paths below.

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

## Documentation

Start at **[docs/index.md](docs/index.md)**. Canonical usage docs:
- **[docs/tokens.md](docs/tokens.md)** — token types & token families (the single token-family usage doc).
- **[docs/policy-accounts-and-contracts.md](docs/policy-accounts-and-contracts.md)** — policy accounts & contracts.
- **[docs/rpc/api-reference.md](docs/rpc/api-reference.md)** — JSON-RPC reference.

Project process & policy: **[GOVERNANCE.md](GOVERNANCE.md)** (on-chain governance
model; activation gate set to height 8,900,000) · **[RELEASE.md](RELEASE.md)** (how
approved changes are released) · **[CONTRIBUTING.md](CONTRIBUTING.md)** · **[SECURITY.md](SECURITY.md)**.

## TypeScript SDK

The published TypeScript SDK is **`@sumchain/sdk@0.2.3`** (current):

```bash
npm install @sumchain/sdk
```

```typescript
import { Provider } from '@sumchain/sdk';
const provider = new Provider('http://localhost:8545');
```

## RPC API

**All amounts in the RPC API are returned in base units.**

To convert:
- From Koppa to base units: multiply by 1,000,000,000
- From base units to Koppa: divide by 1,000,000,000

Example: A balance of `"1500000000"` = 1.5 Ϙ

For detailed API documentation, see [docs/rpc/api-reference.md](docs/rpc/api-reference.md).

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

### SRC-20 Token Methods
| Method | Description |
|--------|-------------|
| `token_getToken` | Get SRC-20 token info by ID |
| `token_balanceOf` | Get token balance for address |
| `token_getTokensByOwner` | Get all tokens held by address |
| `token_allowance` | Get spending allowance |
| `token_totalSupply` | Get token total supply |
| `token_exists` | Check if token exists |

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

**V2 Transaction Payload Types:**

V2 transactions support 16 payload types: Transfer, NFT (SUM-721), Token (SRC-20), ContractDeploy, ContractCall, Staking, Messaging (SRC-201), DocClass (SRC-80X/81X), Tax (SRC-82X), Equity (SRC-83X), Agreement (SRC-84X), Legal (SRC-85X), Property (SRC-86X), Healthcare (SRC-87X), Employment (SRC-88X), Finance (SRC-89X), PolicyAccount.

## Consensus: Proof of Authority

- Validators are defined in genesis
- PoA with round-robin OR stake-weighted proposer selection (configurable)
- Dynamic validator sets with epoch-based recalculation
- Block time: configurable (default 2 seconds)
- Fork choice: longest chain, with hash tiebreaker
- Finality: depth-based (default 6 blocks)
- BFT module exists but is not yet production-ready

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
- **Finality Tracking**: Depth-based block finality (default 6 confirmations)
- **Staking & Delegation**: Validator staking, delegation, reward claiming
- **WASM Smart Contracts**: Contract deployment and execution
- **Policy Accounts**: Consensus-level multi-sig group governance
- **Encrypted Messaging**: SRC-201 on-chain encrypted messaging
- **Document Token Families**: SRC-80X through SRC-89X industry-specific standards
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

### Light Clients
- Merkle proofs for state verification
- Header-only sync
- Light client protocol

### Bridging / IBC
- Cross-chain communication
- Asset transfers
- Relayer infrastructure

### Archive/Storage Nodes
- Full historical state retention
- Dedicated storage node role

### BFT Consensus (experimental roadmap)
- Production consensus today is **PoA with depth-based finality**. BFT remains experimental roadmap work.
- Roadmap: harden the existing BFT module for production use

### OmniNode `InferenceAttestation` Subprotocol
- Verifier-signed digests attesting to off-chain inference outputs, recorded on-chain by reference
- Inner signature uses OmniNode-defined Stage 6 domain (`omninode.inference_attestation.v1`); chain re-verifies bit-for-bit against the same signing input — no double-signing, no chain-side crypto changes
- New `TxPayload::InferenceAttestation` variant (bincode tag `21`, `TxType` discriminant `21`); outer `SignedTransaction` shape unchanged
- Activation gated by `omninode_enabled_from_height: Option<u64>` chain param (fresh-chain default `None`; **mainnet active at `6,000,000`**, live-verified 2026-07-02); same dormant-deploy pattern SNIP V2 uses
- Permanent `(session_id, verifier)` dedup at mempool admission via dedicated `INFERENCE_ATTESTATIONS` CF — required because executor duplicate failure returns `fee_paid: 0` and does not advance nonce
- **v1 merged on `main`:** PR [#1](https://github.com/SUM-INNOVATION/sum-chain/pull/1) (merge commit `5a8548b6`) shipped wire format + parity gate, executor + storage + activation gate, mempool admission, production wiring + read-only RPC, and the frozen v1 protocol doc. PR [#2](https://github.com/SUM-INNOVATION/sum-chain/pull/2) (merge commit `d83e45a4`) appended `omninode_enabled_from_height` to `chain_getChainParams` so adapters can read the activation gate at runtime.
- **Frozen v1 protocol contract:** [`docs/subprotocols/INFERENCE-ATTESTATION.md`](docs/subprotocols/INFERENCE-ATTESTATION.md). Submit path, digest wire format (bincode 1.3 + `DOMAIN_TAG`), address & signature encoding, executor dispatch + failure codes 50–53, permanent duplicate policy, mempool admission behavior, three read-only RPC methods with curl recipes, 4-state status semantics + payload-type guard, finality via `chain_getChainParams.finality_depth`, and explicit v1 exclusions (typed-sugar RPC, sponsored submission, dropped-state tracking, CF pruning, BLS aggregation, etc.).
- **Activation readiness:** [`docs/subprotocols/INFERENCE-ATTESTATION-ACTIVATION.md`](docs/subprotocols/INFERENCE-ATTESTATION-ACTIVATION.md). Pre-activation gates (CI green, validator-binary commit at or after `d83e45a4`, adapter pinned, Stage 5.2 shipped, target-environment smoke, eng director + validator ops sign-off), local-mirror verification record, generic activation procedure, rollback distinction (before vs. after height `H` is finalized), post-activation metrics. Production mainnet default remains dormant (`omninode_enabled_from_height: None`) — no activation height is proposed.

**Last Updated**: 2026-07-06 (deployed status refresh at height 8,716,604; commit `21de231d` on both validators; 8.9M-cohort gates set to height 8,900,000)

## License

This project is licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

# SUM Chain Security Overview

This document provides a comprehensive overview of SUM Chain's security architecture, threat model, and security practices for external auditors and security researchers.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Cryptographic Primitives](#cryptographic-primitives)
3. [Consensus Security](#consensus-security)
4. [Network Security](#network-security)
5. [Transaction Security](#transaction-security)
6. [State Machine Security](#state-machine-security)
7. [Storage Security](#storage-security)
8. [RPC Security](#rpc-security)
9. [Threat Model](#threat-model)
10. [Known Limitations](#known-limitations)
11. [Security Practices](#security-practices)
12. [Bug Bounty Program](#bug-bounty-program)

## Architecture Overview

SUM Chain is a Proof of Authority (PoA) blockchain written entirely in Rust:

```
┌─────────────────────────────────────────────────────────┐
│                      Application Layer                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │   RPC    │  │  Wallet  │  │ Explorer │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
└───────┼─────────────┼─────────────┼──────────────────────┘
        │             │             │
┌───────┼─────────────┼─────────────┼──────────────────────┐
│       ▼             ▼             ▼    Node Layer        │
│  ┌──────────────────────────────────────────────┐       │
│  │           JSON-RPC API Server                 │       │
│  └──────────────┬───────────────────────────────┘       │
│                 │                                         │
│  ┌──────────────┴───────────────────────────────┐       │
│  │           Transaction Mempool                 │       │
│  └──────────────┬───────────────────────────────┘       │
│                 │                                         │
│  ┌──────────────┴───────────────────────────────┐       │
│  │           PoA Consensus Engine                │       │
│  └──────────────┬───────────────────────────────┘       │
│                 │                                         │
│  ┌──────────────┴───────────────────────────────┐       │
│  │           State Machine & Execution           │       │
│  └──────────────┬───────────────────────────────┘       │
│                 │                                         │
│  ┌──────────────┴───────────────────────────────┐       │
│  │           RocksDB Storage Layer               │       │
│  └──────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────┐
│                  Network Layer (libp2p)                  │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐        │
│  │ Gossipsub  │  │   mDNS     │  │Request-Resp│        │
│  └────────────┘  └────────────┘  └────────────┘        │
└─────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### Hashing: Blake3

**Library**: `blake3` v1.5.x
**Usage**: Block hashes, transaction hashes, state roots

**Security Properties**:
- 256-bit output
- Based on BLAKE2 and Bao
- Faster than SHA-256 and SHA-3
- Resistant to length-extension attacks

**Code Location**: `crates/crypto/src/hash.rs`

### Digital Signatures: Ed25519

**Library**: `ed25519-dalek` v2.1.x
**Usage**: Transaction signatures, block signatures

**Security Properties**:
- 128-bit security level
- Deterministic signatures
- Small signature size (64 bytes)
- Fast verification

**Code Location**: [`crates/crypto/src/lib.rs`](../../crates/crypto/src/lib.rs)

**Key Generation**:
```rust
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

let keypair = SigningKey::generate(&mut OsRng);
```

### Key Derivation: Argon2id

**Library**: `argon2` v0.5.x
**Usage**: Wallet key encryption

**Parameters**:
- Memory: 64 MB
- Iterations: 3
- Parallelism: 4
- Salt: 16 bytes (random)

**Code Location**: [`crates/wallet/src/keystore.rs`](../../crates/wallet/src/keystore.rs)

### Encryption: AES-256-GCM

**Library**: `aes-gcm` v0.10.x
**Usage**: Wallet keystore encryption

**Security Properties**:
- 256-bit key
- Authenticated encryption
- 96-bit nonce (random)
- 128-bit authentication tag

## Consensus Security

### Proof of Authority (PoA)

**Model**: Round-robin validator rotation (default) or stake-weighted proposer selection

**Security Assumptions**:
1. Validator honesty: Majority of validators are honest
2. Network synchrony: Bounded message delays
3. No key compromise: Validator keys remain secret

**Proposer Selection**:
```rust
// Round-robin (default)
let proposer_index = block_height % validator_count;
let proposer = validators[proposer_index];

// Stake-weighted (alternative)
// Proposer selected proportionally to staked amount
```

**Attack Resistance**:
- ✅ Sybil attacks: Only authorized validators can propose
- ✅ Long-range attacks: Finality checkpoints prevent deep reorgs
- ✅ Nothing-at-stake: Validators don't have incentive to double-sign
- ⚠️ 51% attack: Majority of validators can censor/reorg
- ⚠️ Validator collusion: Coordinated validators can halt chain

### Finality

**Mechanism**: Depth-based confirmations

**Parameters**:
- Finality depth: 6 blocks (configurable)
- A block at height H is finalized when chain reaches height H + finality_depth

**Code Location**: [`crates/consensus/src/poa.rs`](../../crates/consensus/src/poa.rs)

## Network Security

### P2P Layer: libp2p

**Transport**: TCP with Noise encryption
**Multiplexing**: Yamux
**Discovery**: mDNS (local), Bootstrap nodes (global)

**Security Features**:
1. **Peer ID Authentication**: Ed25519-based peer IDs
2. **Encrypted Connections**: Noise protocol framework
3. **Peer Reputation**: Connection scoring and banning
4. **Rate Limiting**: Connection and message rate limits

**Code Location**: [`crates/p2p/src/network.rs`](../../crates/p2p/src/network.rs)

### Gossipsub

**Topics**:
- `sumchain/tx/1` - Transaction propagation
- `sumchain/block/1` - Block propagation
- `sumchain/bft/proposal/1` - BFT proposals (experimental)
- `sumchain/bft/prevote/1` - BFT prevotes (experimental)
- `sumchain/bft/precommit/1` - BFT precommits (experimental)

**Protection Mechanisms**:
- Message deduplication
- Peer scoring
- Flood control

### Attack Mitigations

| Attack Type | Mitigation |
|-------------|------------|
| Eclipse Attack | Multiple bootstrap nodes, peer diversity |
| Sybil Attack | Peer reputation, connection limits |
| DDoS | Rate limiting, connection backoff |
| Message Flooding | Message size limits, peer scoring |

## Transaction Security

### Transaction Format

```rust
// V1 Transaction
pub struct Transaction {
    pub chain_id: u64,      // Replay protection
    pub from: Address,      // Sender (derived from signature)
    pub to: Address,        // Recipient
    pub amount: u128,       // Amount in base units
    pub fee: u128,          // Transaction fee
    pub nonce: u64,         // Nonce for ordering
}
```

**Note**: V2 transactions also include a `payload` field supporting 16 different payload types (Transfer, NFT, Token, Staking, Contract, Messaging, DocClass, etc.).

### Security Features

1. **Replay Protection**
   - Chain ID prevents cross-chain replay
   - Nonce prevents same-chain replay

2. **Signature Verification**
   ```rust
   fn verify_transaction(tx: &SignedTransaction) -> bool {
       let signing_hash = tx.tx.signing_hash();
       verify_signature(&tx.public_key, signing_hash.as_bytes(), &tx.signature)
   }
   ```

3. **Balance Checks**
   ```rust
   if account.balance < tx.amount + tx.fee {
       return Err(InsufficientFunds);
   }
   ```

4. **Nonce Validation**
   ```rust
   if tx.nonce != account.nonce {
       return Err(InvalidNonce);
   }
   ```

**Code Location**: [`crates/primitives/src/transaction.rs`](../../crates/primitives/src/transaction.rs)

### Mempool Security

**Limits**:
- Per-sender limit: 100 pending transactions
- Global limit: 10,000 transactions
- Expiration time: 1 hour
- Minimum fee: 0.001 Ϙ (configurable)

**Code Location**: [`crates/state/src/mempool.rs`](../../crates/state/src/mempool.rs)

## State Machine Security

### Account Model

```rust
pub struct AccountState {
    pub balance: Balance,  // u128
    pub nonce: u64,        // Transaction counter
}
```

### State Transitions

All state transitions are deterministic and validated:

```rust
fn execute_transaction(state: &mut State, tx: &SignedTransaction) -> Result<Receipt> {
    // 1. Verify signature
    if !tx.verify_signer() {
        return Err(InvalidSignature);
    }

    // 2. Check nonce
    if tx.tx.nonce != state.get_nonce(&tx.tx.from)? {
        return Err(InvalidNonce);
    }

    // 3. Check balance
    let sender_balance = state.get_balance(&tx.tx.from)?;
    if sender_balance < tx.tx.amount + tx.tx.fee {
        return Err(InsufficientFunds);
    }

    // 4. Execute transfer
    state.sub_balance(&tx.tx.from, tx.tx.amount + tx.tx.fee)?;
    state.add_balance(&tx.tx.to, tx.tx.amount)?;
    state.increment_nonce(&tx.tx.from)?;

    // 5. Award fee to proposer
    state.add_balance(&proposer, tx.tx.fee)?;

    Ok(receipt)
}
```

**Overflow Protection**: All arithmetic operations use checked math

**Code Location**: [`crates/state/src/executor.rs`](../../crates/state/src/executor.rs)

## Storage Security

### RocksDB Configuration

**Checksums**: Enabled on all reads
**Compression**: Snappy
**Backups**: Incremental with verification

**Security Features**:
- Atomic writes
- Crash recovery
- Corruption detection
- Integrity checks

**Code Location**: [`crates/storage/src/db.rs`](../../crates/storage/src/db.rs)

### Data Integrity

1. **Block Hashes**: Each block contains parent hash
2. **State Root**: Merkle root of account states
3. **Transaction Root**: Merkle root of block transactions

## RPC Security

### Authentication

**API Key Authentication** (optional):
```toml
[rpc]
api_key_enabled = true
api_keys = ["secret_key_1", "secret_key_2"]
```

### Rate Limiting

**Default Limits**:
- Read methods: 100 req/s per IP
- Write methods: 10 req/s per IP
- Burst allowance: 2x sustained rate

### CORS

**Configuration**:
```toml
[rpc]
cors_origins = ["https://app.sumchain.io"]
```

**Code Location**: [`crates/rpc/src/server.rs`](../../crates/rpc/src/server.rs)

## Threat Model

### In-Scope Threats

| Threat | Impact | Likelihood | Mitigation |
|--------|--------|------------|------------|
| Validator Key Compromise | High | Low | HSM storage, key rotation |
| Double Spending | High | Low | Nonce validation, finality |
| Transaction Replay | High | Low | Chain ID, nonce |
| Network Partitioning | Medium | Medium | Multiple bootstrap nodes |
| DDoS on Validators | Medium | Medium | Rate limiting, peer banning |
| Front-running | Medium | Medium | Fair ordering (future) |
| MEV Extraction | Low | High | Not applicable (PoA) |

### Out-of-Scope Threats

- Physical access to validator infrastructure
- Compromise of underlying OS/hardware
- Social engineering of validators
- Legal/regulatory attacks
- Quantum computing attacks (post-quantum crypto planned for Phase 2)

## Known Limitations

### Current Version (v0.1.0)

1. **No Formal Verification**
   - Code is not formally verified
   - Extensive testing and audits planned

2. **Limited DoS Protection**
   - Basic rate limiting only
   - Advanced DDoS mitigation planned

3. **No Light Clients**
   - All nodes are full nodes
   - Light client protocol planned

4. **BFT Consensus (Experimental)**
   - Experimental BFT module exists but `propose_block()` returns `NotImplemented`
   - PoA is the production consensus

## Security Practices

### Development

- **Memory Safety**: Rust's ownership system prevents most memory vulnerabilities
- **No Unsafe Code**: Zero `unsafe` blocks in core logic
- **Dependency Auditing**: All dependencies reviewed and audited
- **Fuzzing**: Critical components fuzzed (planned)
- **Static Analysis**: Clippy and rustfmt in CI

### Testing

- **Unit Tests**: 136 tests across all crates
- **Integration Tests**: 16 end-to-end scenarios
- **Property Testing**: QuickCheck for invariants (planned)
- **Code Coverage**: Target 80%+ (currently: TBD)

### Deployment

- **Least Privilege**: Nodes run as non-root user
- **Sandboxing**: Systemd sandboxing enabled
- **Encrypted Keys**: All private keys encrypted at rest
- **Secure Boot**: Verified boot chain (recommended)

## Bug Bounty Program

**Status**: To be announced

**Scope**:
- Consensus vulnerabilities
- Transaction validation bypass
- Double-spending
- Network attacks
- Cryptographic issues

**Rewards**:
- Critical: Up to 50,000 Ϙ
- High: Up to 10,000 Ϙ
- Medium: Up to 2,000 Ϙ
- Low: Up to 500 Ϙ

**Disclosure**: Coordinated disclosure with 90-day embargo

## Audit Checklist

For external auditors, please review:

- [ ] Cryptographic primitive usage
- [ ] Signature verification logic
- [ ] Transaction validation and execution
- [ ] State transition correctness
- [ ] Consensus algorithm implementation
- [ ] Network protocol security
- [ ] RPC endpoint authentication and authorization
- [ ] Input validation across all interfaces
- [ ] Overflow/underflow protection
- [ ] Denial of service vectors
- [ ] Storage integrity mechanisms
- [ ] Key management practices
- [ ] Dependencies security

## References

- [API Reference](../rpc/api-reference.md)
- Consensus Specification
- [Cryptography Documentation](../../crates/crypto/README.md)

## Contact

**Security Issues**: security@sumchain.io (PGP key available)
**Audit Inquiries**: audit@sumchain.io
**General Questions**: tech@sumchain.io

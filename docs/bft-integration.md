# BFT Consensus Integration Guide

This guide explains how to integrate BFT consensus into a running SUM Chain network.

## Overview

The BFT consensus implementation provides:

- **Immediate finality**: Blocks are final once committed (no confirmations needed)
- **Byzantine fault tolerance**: Tolerates up to 1/3 malicious validators
- **Safety guarantees**: Never commits conflicting blocks
- **Liveness**: Always makes progress with >2/3 honest validators

## Architecture

### Network Layer Integration

BFT consensus uses three gossipsub topics for message propagation:

```rust
pub const BFT_PROPOSALS: &str = "sumchain/bft/proposal/1";
pub const BFT_PREVOTES: &str = "sumchain/bft/prevote/1";
pub const BFT_PRECOMMITS: &str = "sumchain/bft/precommit/1";
```

### Message Flow

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│Validator │         │Validator │         │Validator │
│    A     │         │    B     │         │    C     │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                    │
     │  1. Proposal       │                    │
     ├───────────────────>│                    │
     ├────────────────────┴───────────────────>│
     │                    │                    │
     │  2. Prevote        │  2. Prevote        │
     │<───────────────────┤<───────────────────┤
     │                    │                    │
     │  3. Precommit      │  3. Precommit      │
     │<───────────────────┤<───────────────────┤
     │                    │                    │
     │  4. Commit Block (when >2/3 reached)    │
     └────────────────────┴────────────────────┘
```

## Using BFT in Your Node

### 1. Import BFT Module

```rust
use sumchain_consensus::bft::{
    BftEngine, Proposal, Vote, VoteType, View, ConsensusState,
};
use sumchain_p2p::{NetworkCommand, NetworkEvent};
```

### 2. Initialize BFT Engine

```rust
// Load validator set from genesis
let genesis = Genesis::load("./genesis/mainnet_genesis.json")?;
let validators: Vec<PublicKey> = genesis.validators.iter()
    .map(|addr| addr_to_pubkey(addr))
    .collect();

// Create BFT engine
let bft_engine = BftEngine::new(validators, keypair.clone());
```

### 3. Handle Network Events

```rust
// Subscribe to network events
let mut events = network.subscribe();

while let Ok(event) = events.recv().await {
    match event {
        NetworkEvent::BftProposalReceived(data) => {
            if let Ok(proposal) = Proposal::from_bytes(&data) {
                handle_proposal(proposal).await?;
            }
        }

        NetworkEvent::BftPrevoteReceived(data) => {
            if let Ok(vote) = Vote::from_bytes(&data) {
                if vote.vote_type == VoteType::Prevote {
                    handle_prevote(vote).await?;
                }
            }
        }

        NetworkEvent::BftPrecommitReceived(data) => {
            if let Ok(vote) = Vote::from_bytes(&data) {
                if vote.vote_type == VoteType::Precommit {
                    handle_precommit(vote).await?;
                }
            }
        }

        _ => {}
    }
}
```

### 4. Proposal Phase

```rust
async fn propose_block(
    bft: &BftEngine,
    network: &NetworkService,
    view: View,
) -> Result<()> {
    // Check if we're the leader
    if !bft.is_leader(&view) {
        return Ok(());
    }

    // Create block from mempool
    let block = build_block_from_mempool()?;

    // Create proposal
    let proposal = bft.create_proposal(view, block, None)?;

    // Broadcast proposal
    let data = proposal.to_bytes();
    network.command_sender()
        .send(NetworkCommand::BroadcastBftProposal(data))
        .await?;

    // Vote for our own proposal
    let prevote = bft.create_prevote(view, Some(proposal.block.hash()))?;
    let vote_data = prevote.to_bytes();
    network.command_sender()
        .send(NetworkCommand::BroadcastBftPrevote(vote_data))
        .await?;

    Ok(())
}
```

### 5. Prevote Phase

```rust
async fn handle_proposal(
    bft: &BftEngine,
    network: &NetworkService,
    proposal: Proposal,
) -> Result<()> {
    // Verify proposal signature
    let leader = bft.get_leader(&proposal.view);
    if !proposal.verify(&leader) {
        return Err(ConsensusError::InvalidVote("Invalid proposal signature".into()));
    }

    // Validate block
    let valid = validate_block(&proposal.block)?;

    // Create prevote
    let block_hash = if valid {
        Some(proposal.block.hash())
    } else {
        None // Nil vote
    };

    let prevote = bft.create_prevote(proposal.view, block_hash)?;

    // Broadcast prevote
    let data = prevote.to_bytes();
    network.command_sender()
        .send(NetworkCommand::BroadcastBftPrevote(data))
        .await?;

    Ok(())
}
```

### 6. Precommit Phase

```rust
async fn handle_prevote(
    bft: &BftEngine,
    network: &NetworkService,
    vote: Vote,
) -> Result<()> {
    // Add vote to vote set
    let has_quorum = bft.add_prevote(vote)?;

    if !has_quorum {
        return Ok(());
    }

    // Get block with >2/3 prevotes
    let view = vote.view;
    if let Some(block_hash) = bft.get_prevote_quorum(&view) {
        // Create precommit
        let precommit = bft.create_precommit(view, Some(block_hash))?;

        // Broadcast precommit
        let data = precommit.to_bytes();
        network.command_sender()
            .send(NetworkCommand::BroadcastBftPrecommit(data))
            .await?;
    } else {
        // No quorum, send nil precommit
        let precommit = bft.create_precommit(view, None)?;
        let data = precommit.to_bytes();
        network.command_sender()
            .send(NetworkCommand::BroadcastBftPrecommit(data))
            .await?;
    }

    Ok(())
}
```

### 7. Commit Phase

```rust
async fn handle_precommit(
    bft: &BftEngine,
    storage: &Storage,
    vote: Vote,
) -> Result<()> {
    // Add precommit to vote set
    let has_quorum = bft.add_precommit(vote)?;

    if !has_quorum {
        return Ok(());
    }

    // Get block with >2/3 precommits
    let view = vote.view;
    if let Some(block_hash) = bft.get_precommit_quorum(&view) {
        // Get the block (should be in cache from proposal)
        let block = get_block_from_cache(&block_hash)?;

        // Execute and commit block
        execute_block(&block)?;
        storage.commit_block(block)?;

        // Move to next height
        bft.move_to_next_height();

        // Start new round as potential proposer
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            propose_block(bft, network, bft.current_view()).await
        });
    }

    Ok(())
}
```

### 8. Timeout Handling

```rust
async fn run_timeouts(bft: &BftEngine) {
    let timeout_config = TimeoutConfig::default();

    loop {
        let view = bft.current_view();
        let step = bft.current_step();

        // Calculate timeout for current step/round
        let timeout_ms = timeout_config.timeout_for(step, view.round);

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(timeout_ms)) => {
                // Timeout expired, move to next round
                warn!("Timeout in round {}, moving to round {}", view.round, view.round + 1);
                bft.move_to_next_round();

                // Propose if we're the new leader
                if bft.is_leader(&bft.current_view()) {
                    propose_block(bft, network, bft.current_view()).await?;
                }
            }

            _ = bft.wait_for_step_change() => {
                // Step changed, recalculate timeout
                continue;
            }
        }
    }
}
```

## Configuration

Update your node configuration file (see [configs/bft-config.toml](../configs/bft-config.toml)):

```toml
[consensus]
engine = "bft"

[consensus.bft]
propose_timeout_ms = 3000
prevote_timeout_ms = 1000
precommit_timeout_ms = 1000
timeout_multiplier = 1.5
```

## Network Upgrade

### Coordinated Upgrade (Recommended)

1. **Announce upgrade height**:
   ```
   Network will upgrade to BFT consensus at height 10000
   ```

2. **All validators upgrade software**:
   ```bash
   # Stop node
   systemctl stop sumchain-validator

   # Update binary
   cp sumchain-node-v2.0.0 /usr/local/bin/sumchain-node

   # Update config
   sed -i 's/engine = "poa"/engine = "bft"/' /etc/sumchain/config.toml

   # Restart node
   systemctl start sumchain-validator
   ```

3. **Automatic activation at height 10000**:
   - Node switches to BFT when height 10000 is reached
   - First BFT round begins at height 10001

### Genesis Network (New Chain)

For new chains, set BFT in genesis configuration:

```json
{
  "chain_id": 1,
  "consensus": {
    "engine": "bft",
    "bft_config": {
      "propose_timeout_ms": 3000,
      "prevote_timeout_ms": 1000,
      "precommit_timeout_ms": 1000
    }
  },
  "validators": [...]
}
```

## Monitoring

### Key Metrics

Monitor these metrics to ensure BFT is functioning correctly:

```prometheus
# Rounds per block (should be 1-2 on average)
sumchain_bft_rounds_histogram

# Vote participation rate (should be ~100%)
sumchain_bft_vote_participation_ratio

# Round timeouts (should be low)
sumchain_bft_round_timeouts_total

# Consensus time per block
sumchain_bft_consensus_duration_seconds
```

### Logs

```bash
# View BFT consensus logs
journalctl -u sumchain-validator -f | grep BFT

# Example output:
INFO  Quorum of prevotes reached, height=1234, round=0, block=0x1a2b3c...
INFO  Quorum of precommits reached, height=1234, round=0
INFO  Block finalized, height=1234, hash=0x1a2b3c...
```

## Testing

### Local Testnet

Run a 4-validator BFT network locally:

```bash
# Terminal 1: Validator 1 (proposer for height 1)
./target/release/sumchain-node \
  --config configs/bft-config.toml \
  --validator-key keys/validator1.pem \
  --data-dir ./data/validator1

# Terminal 2: Validator 2
./target/release/sumchain-node \
  --config configs/bft-config.toml \
  --validator-key keys/validator2.pem \
  --data-dir ./data/validator2 \
  --port 9934

# Terminal 3: Validator 3
./target/release/sumchain-node \
  --config configs/bft-config.toml \
  --validator-key keys/validator3.pem \
  --data-dir ./data/validator3 \
  --port 9935

# Terminal 4: Validator 4
./target/release/sumchain-node \
  --config configs/bft-config.toml \
  --validator-key keys/validator4.pem \
  --data-dir ./data/validator4 \
  --port 9936
```

### Byzantine Behavior Testing

Test BFT fault tolerance by simulating Byzantine validators:

```bash
# Kill 1 validator (network should continue)
kill $(pidof sumchain-node | awk '{print $1}')

# Network continues with 3/4 validators (75% > 66%)

# Kill another validator (network should halt)
kill $(pidof sumchain-node | awk '{print $1}')

# Network halts with 2/4 validators (50% < 66%)
```

## Troubleshooting

### Blocks Not Finalizing

**Symptoms**: Chain height not increasing

**Causes**:
- <2/3 validators online
- Network partition
- Clock skew between validators

**Solutions**:
```bash
# Check validator count
curl -X POST http://localhost:8545 \
  -d '{"jsonrpc":"2.0","method":"sum_getValidators","id":1}'

# Check NTP sync
timedatectl status

# Check peer connectivity
curl -X POST http://localhost:8545 \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","id":1}'
```

### High Round Numbers

**Symptoms**: Blocks finalize but after many rounds (round > 5)

**Causes**:
- High network latency
- Overloaded validators
- Byzantine validators proposing invalid blocks

**Solutions**:
```bash
# Increase timeouts
# In config.toml:
propose_timeout_ms = 5000  # Increase from 3000
prevote_timeout_ms = 2000  # Increase from 1000

# Check validator resource usage
top -p $(pidof sumchain-node)

# Check network latency to peers
ping <peer-ip>
```

### Vote Signature Failures

**Symptoms**: "Invalid vote signature" errors in logs

**Causes**:
- Validator key mismatch
- Corrupted vote messages
- Man-in-the-middle attacks

**Solutions**:
```bash
# Verify validator public key
./sumchain-node show-pubkey --key validator.pem

# Check validator is in genesis set
grep <pubkey> genesis.json

# Enable P2P encryption (if not already)
# In config.toml:
[network]
enable_tls = true
```

## Performance Tuning

### Network Optimization

```toml
[network]
# Increase mesh size for faster gossip
mesh_n = 4
mesh_n_high = 8

# Reduce gossip interval
heartbeat_interval_ms = 500
```

### Timeout Tuning

```toml
[consensus.bft]
# Low-latency networks (local/datacenter)
propose_timeout_ms = 1000
prevote_timeout_ms = 500
precommit_timeout_ms = 500

# High-latency networks (global)
propose_timeout_ms = 5000
prevote_timeout_ms = 2000
precommit_timeout_ms = 2000
```

### Validator Count

- **4 validators**: Minimum (can tolerate 1 Byzantine)
- **7 validators**: Recommended (can tolerate 2 Byzantine)
- **13-21 validators**: Optimal balance
- **>21 validators**: High overhead, consider sharding

## Security Best Practices

1. **Key Management**:
   - Use HSM for validator keys in production
   - Never share private keys between validators
   - Rotate keys periodically with coordinated update

2. **Network Security**:
   - Enable TLS/Noise encryption for P2P
   - Use firewall to restrict P2P to known validators
   - DDoS protection for validator nodes

3. **Monitoring**:
   - 24/7 monitoring with alerts
   - Log aggregation and analysis
   - Automated incident response

4. **Validator Operations**:
   - Run validators in different datacenters
   - Separate network infrastructure
   - Independent operators for decentralization

## Further Reading

- [BFT Consensus Algorithm](./bft-consensus.md) - Detailed algorithm specification
- [Tendermint Paper](https://arxiv.org/abs/1807.04938) - Original research
- [Byzantine Generals Problem](https://lamport.azurewebsites.net/pubs/byz.pdf) - Foundational paper

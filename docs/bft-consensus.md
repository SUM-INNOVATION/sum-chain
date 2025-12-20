# Byzantine Fault Tolerant (BFT) Consensus

SUM Chain implements a Tendermint-style BFT consensus algorithm that provides:
- **Immediate Finality**: Blocks are final once committed (no confirmations needed)
- **Byzantine Fault Tolerance**: Tolerates up to 1/3 malicious validators
- **Safety**: Never commits conflicting blocks
- **Liveness**: Always makes progress (with >2/3 honest validators)

## Overview

BFT consensus replaces the simple round-robin Proof of Authority (PoA) with a voting-based system that achieves stronger security guarantees.

### Key Differences from PoA

| Feature | PoA | BFT |
|---------|-----|-----|
| Finality | Probabilistic (2+ confirmations) | Immediate (0 confirmations) |
| Byzantine Tolerance | None (assumes all honest) | Up to 1/3 malicious |
| Validator Selection | Round-robin | Leader rotation |
| Fork Choice | Longest chain | Vote-based |
| Network Overhead | Low | Medium (votes + proposals) |

## Architecture

### Consensus Rounds

Each block height proceeds through consensus rounds until a block is committed:

```
Height H, Round R:
  1. PROPOSE:   Leader proposes block
  2. PREVOTE:   Validators vote on proposal
  3. PRECOMMIT: Validators commit if >2/3 prevoted
  4. COMMIT:    Block committed if >2/3 precommitted
```

If a round times out (no consensus), validators move to Round R+1 with a new leader.

### State Machine

```
┌─────────┐
│ PROPOSE │ ──> Wait for proposal or timeout
└────┬────┘
     │ Proposal received / Timeout
     ▼
┌─────────┐
│ PREVOTE │ ──> Validators vote on proposal
└────┬────┘
     │ >2/3 prevotes
     ▼
┌──────────┐
│PRECOMMIT │ ──> Validators commit to proposal
└────┬─────┘
     │ >2/3 precommits
     ▼
┌────────┐
│ COMMIT │ ──> Block finalized, move to next height
└────────┘
```

### Voting

Two types of votes:

1. **Prevote** - "I agree this block is valid"
2. **Precommit** - "I commit to this block"

Votes include:
- View (height + round)
- Vote type (prevote/precommit)
- Block hash (or nil)
- Signature

### Quorum Rules

- **Byzantine Quorum**: >2/3 of validators (67% + 1)
- **Example with 4 validators**: Need 3 votes (75%)
- **Example with 7 validators**: Need 5 votes (71%)

## Safety Properties

### Locked Blocks

Once a validator prevotes for a block in round R, it cannot prevote for a different block in rounds R+1, R+2, etc. at the same height.

This prevents equivocation and ensures safety.

### Valid Blocks

A block becomes "valid" when it receives >2/3 prevotes. Validators can only precommit for valid blocks.

## Liveness Properties

### Timeouts

Each step has a timeout that increases exponentially with round number:

```
timeout(step, round) = base_timeout * 1.5^round
```

Default timeouts:
- Propose: 3 seconds
- Prevote: 1 second
- Precommit: 1 second

### Round Incrementing

Validators move to the next round if:
- Proposal timeout expires
- >1/3 validators timeout (network partition detection)
- Any validator moves to round R+1 (helps synchronize)

## Leader Selection

Leaders rotate based on view:

```rust
leader = validators[(height + round) % validator_count]
```

This ensures:
- Fairness: All validators get turns
- Liveness: Byzantine leaders are eventually skipped
- Simplicity: Deterministic, no randomness needed

## Message Types

### Proposal

```rust
struct Proposal {
    view: View,             // Height + round
    block: Block,           // Proposed block
    valid_round: Option<Round>, // POL round if applicable
    signature: Signature,   // Leader signature
}
```

### Vote

```rust
struct Vote {
    view: View,             // Height + round
    vote_type: VoteType,    // Prevote or Precommit
    block_hash: Option<Hash>, // Block hash or nil
    validator: PublicKey,
    signature: Signature,
}
```

## Consensus Algorithm (Simplified)

```
function consensus(height):
    round = 0
    while true:
        // PROPOSE
        if is_leader(height, round):
            propose_block(height, round)
        wait_for_proposal(timeout)

        // PREVOTE
        if valid_proposal_received():
            broadcast_prevote(block_hash)
        else:
            broadcast_prevote(nil)

        // PRECOMMIT
        if received_2/3_prevotes(block_hash):
            valid_block = block_hash
            broadcast_precommit(block_hash)
        else if received_2/3_prevotes(nil):
            broadcast_precommit(nil)

        // COMMIT
        if received_2/3_precommits(block_hash):
            commit_block(block_hash)
            return

        // TIMEOUT
        if timeout():
            round++
```

## Attack Resistance

### Double Spending

**Attack**: Submit conflicting transactions to different validators.

**Defense**: BFT ensures all honest validators commit the same block. Conflicting blocks cannot both get >2/3 votes.

### Long-Range Attack

**Attack**: Create a fork from genesis with a different history.

**Defense**: Immediate finality means committed blocks are final. Cannot revert finalized blocks.

### Censorship

**Attack**: Byzantine leader refuses to include certain transactions.

**Defense**: Round timeouts cause leader rotation. Honest leaders will eventually include the transactions.

### Network Partition

**Attack**: Split network into two partitions.

**Defense**: Neither partition can achieve >2/3 quorum. Network heals when partition resolves.

## Performance Characteristics

### Throughput

- Block time: ~3-5 seconds (configurable)
- Rounds per block: 1-2 average (more if Byzantine validators)
- Network overhead: O(n²) vote messages per block

### Scalability

Optimal validator count: **4-21 validators**

- Too few (<4): Limited fault tolerance
- Too many (>21): High network overhead

For larger networks, consider:
- Hierarchical consensus
- Validator delegation
- Sharding

## Migration from PoA to BFT

### Configuration

Update node configuration to use BFT:

```toml
[consensus]
engine = "bft"  # Change from "poa"

[consensus.bft]
# Timeout configuration (optional)
propose_timeout_ms = 3000
prevote_timeout_ms = 1000
precommit_timeout_ms = 1000
timeout_multiplier = 1.5
```

### Network Upgrade

Coordinated upgrade process:

1. **Announce upgrade** at target block height
2. **Validators upgrade** software before target height
3. **Activate BFT** at target height automatically
4. **Monitor consensus** to ensure smooth transition

### Compatibility

BFT and PoA nodes **cannot** coexist on the same network. All validators must upgrade together.

## Monitoring BFT Consensus

### Metrics

Monitor these Prometheus metrics:

```
# Consensus rounds per block (should be ~1-2)
sum chain_bft_rounds_per_block

# Vote participation rate (should be ~100%)
sumchain_bft_vote_participation_ratio

# Round timeouts (should be low)
sumchain_bft_round_timeouts_total

# Consensus time per block
sumchain_bft_consensus_duration_seconds
```

### Health Checks

```bash
# Check consensus is progressing
curl http://localhost:8545 \
  -d '{"jsonrpc":"2.0","method":"sum_getBlockNumber","id":1}'

# Check validator participation
curl http://localhost:8545 \
  -d '{"jsonrpc":"2.0","method":"sum_getValidators","id":1}'
```

### Logs

Watch for these log messages:

```
INFO  Quorum of prevotes reached
INFO  Quorum of precommits reached
INFO  Block finalized
WARN  Round timeout, moving to next round
ERROR Invalid vote signature
```

## Troubleshooting

### Blocks Not Finalizing

**Symptoms**: Height not increasing

**Possible Causes**:
- <2/3 validators online
- Network partition
- Clock skew

**Solutions**:
- Check validator connectivity
- Verify NTP synchronization
- Review firewall rules

### Frequent Round Timeouts

**Symptoms**: High round numbers before consensus

**Possible Causes**:
- High network latency
- Byzantine leaders
- Overloaded validators

**Solutions**:
- Increase timeout values
- Check network quality
- Monitor validator resources

### Vote Signature Failures

**Symptoms**: "Invalid vote signature" errors

**Possible Causes**:
- Validator key mismatch
- Clock skew causing replay
- Network corruption

**Solutions**:
- Verify validator keys
- Check NTP sync
- Inspect network packets

## Security Considerations

### Validator Key Management

- **Never share** validator private keys
- **Use HSM** for production validators
- **Rotate keys** periodically (requires network coordination)
- **Backup safely** with encryption

### Network Security

- **TLS/Noise** encryption for P2P
- **DDoS protection** for validator nodes
- **Rate limiting** on vote processing
- **Signature verification** for all votes

### Operational Security

- **Monitor 24/7** with alerting
- **Incident response** plan documented
- **Regular drills** for network upgrades
- **Security audits** before mainnet

## Further Reading

- [Tendermint Specification](https://arxiv.org/abs/1807.04938)
- [The latest gossip on BFT consensus](https://arxiv.org/abs/1807.04938)
- [Hotstuff: BFT Consensus](https://arxiv.org/abs/1803.05069)
- [Byzantine Generals Problem](https://lamport.azurewebsites.net/pubs/byz.pdf)

## Future Enhancements

Planned improvements:

- [ ] Proposer-based timestamps (BFT Time)
- [ ] Evidence handling for misbehavior
- [ ] Light client support with proofs
- [ ] Parallel prevote aggregation
- [ ] Optimistic fast path (1 round when no Byzantine validators)
- [ ] Vote extensions for app-level data

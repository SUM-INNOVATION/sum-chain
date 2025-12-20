# BFT Integration TODO

## Status: In Progress

We've created the BFT consensus engine but need to integrate it into the node. Here's what's needed:

## Completed ✅

1. **BFT Core Implementation**
   - ✅ BFT types (View, Round, VoteType)
   - ✅ Vote and VoteSet with quorum logic
   - ✅ Proposal creation and verification
   - ✅ BftEngine struct
   - ✅ P2P message types (NetworkEvent/NetworkCommand)
   - ✅ Config structure (ConsensusSettings, BftSettings)

## In Progress 🔄

2. **Node Integration** (CURRENT STEP)
   - ✅ Config support for consensus type selection
   - 🔄 Make Node support both PoA and BFT
   - ⏸️ Wire BFT messages to consensus engine
   - ⏸️ Implement block proposal logic
   - ⏸️ Implement vote handling

## Remaining Tasks ⏸️

### 3. Consensus Engine Abstraction

**Problem**: Node is currently hardcoded to use `Arc<PoAEngine>`. Need to support both PoA and BFT.

**Solution Options**:

**Option A: Enum Wrapper** (Recommended - Simpler)
```rust
pub enum ConsensusEngineType {
    Poa(Arc<PoAEngine>),
    Bft(Arc<BftEngine>),
}

impl ConsensusEngineType {
    pub fn propose_block(&self, ...) -> Result<Block> {
        match self {
            Self::Poa(engine) => engine.propose_block(...),
            Self::Bft(engine) => engine.propose_block(...),
        }
    }
}
```

**Option B: Trait Object** (Cleaner but more work)
```rust
// Both PoAEngine and BftEngine implement ConsensusEngine trait
consensus: Arc<dyn ConsensusEngine>
```

### 4. BFT Message Handling

Need to add to `Node::run()`:

```rust
// In event loop
NetworkEvent::BftProposalReceived(data) => {
    let proposal = Proposal::from_bytes(&data)?;
    handle_bft_proposal(proposal).await?;
}

NetworkEvent::BftPrevoteReceived(data) => {
    let vote = Vote::from_bytes(&data)?;
    if vote.vote_type == VoteType::Prevote {
        handle_bft_prevote(vote).await?;
    }
}

NetworkEvent::BftPrecommitReceived(data) => {
    let vote = Vote::from_bytes(&data)?;
    if vote.vote_type == VoteType::Precommit {
        handle_bft_precommit(vote).await?;
    }
}
```

### 5. BFT Block Production

```rust
async fn bft_consensus_loop(
    bft: Arc<BftEngine>,
    network: Arc<NetworkService>,
    state: Arc<StateManager>,
) {
    loop {
        let view = bft.current_view();

        // If we're the leader, propose
        if bft.is_leader(&view) {
            let block = build_block_from_mempool()?;
            let proposal = bft.create_proposal(view, block, None)?;

            // Broadcast proposal
            network.send(NetworkCommand::BroadcastBftProposal(
                proposal.to_bytes()
            )).await?;
        }

        // Wait for proposal or timeout
        tokio::select! {
            proposal = wait_for_proposal() => {
                handle_proposal(proposal).await?;
            }
            _ = timeout(view) => {
                bft.move_to_next_round();
            }
        }
    }
}
```

### 6. Integration Points

**Files to modify**:

1. `crates/node/src/node.rs`
   - Change `consensus: Arc<PoAEngine>` to enum/trait
   - Add BFT message handlers
   - Add BFT consensus loop

2. `crates/consensus/src/lib.rs`
   - Ensure ConsensusEngine trait is implemented by both
   - Add common interface methods

3. `crates/node/src/main.rs`
   - Read consensus type from config
   - Instantiate correct engine

## Quick Win: Test with PoA First

**To test the node RIGHT NOW**:

1. Keep existing PoA code as-is
2. Build and run with PoA:
   ```bash
   cargo build --release
   ./target/release/sumchain-node run --config config.toml
   ```

3. This will work immediately with existing code

4. Then integrate BFT in parallel

## Estimated Time

- **Option A (Enum)**: 2-4 hours
- **Option B (Trait)**: 4-6 hours
- **Testing**: 2-4 hours
- **Total**: 6-12 hours of focused work

## Next Step

**DECISION NEEDED**:
- Launch with PoA immediately (works now)
- OR spend 1-2 days integrating BFT first

**My recommendation**:
1. Test current node with PoA (today)
2. Order hardware (today)
3. Integrate BFT while hardware ships (this week)
4. Deploy with BFT when hardware arrives (next week)

This de-risks the hardware purchase and gives you working software sooner.

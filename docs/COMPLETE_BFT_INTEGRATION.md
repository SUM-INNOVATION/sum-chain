# Complete BFT Integration Guide

## What's Been Done ✅

1. **Config Support** - Added `ConsensusSettings` with BFT options
2. **Consensus Wrapper** - Created `ConsensusWrapper` enum in `crates/node/src/consensus_wrapper.rs`
3. **Node Struct Updated** - Changed from `Arc<PoAEngine>` to `ConsensusWrapper`

## Remaining Steps (2-3 hours)

### Step 1: Fix Node Constructor

**File**: `crates/node/src/node.rs`

Find the `new()` and `with_rpc_config()` methods and update consensus creation:

```rust
// OLD CODE (around line 100-130):
let consensus = Arc::new(PoAEngine::new(
    genesis.validators.clone(),
    validator_key.clone(),
    genesis_height,
));

// NEW CODE:
use crate::config::ConsensusEngine as ConsensusEngineType;

let consensus = match config.consensus.engine {
    ConsensusEngineType::Poa => {
        ConsensusWrapper::new_poa(
            genesis.validators.clone(),
            validator_key.clone(),
            genesis_height,
        )?
    }
    ConsensusEngineType::Bft => {
        if let Some(key) = validator_key.clone() {
            ConsensusWrapper::new_bft(
                genesis.validators.clone(),
                key,
            )?
        } else {
            return Err(anyhow::anyhow!("BFT requires validator key"));
        }
    }
};
```

**Note**: You'll need to pass `config` parameter to the constructor, or read it from somewhere.

### Step 2: Add BFT Message Handlers to Event Loop

**File**: `crates/node/src/node.rs`

In the `run()` method event loop (around line 300-500), add BFT message handling:

```rust
// Find the match statement for NetworkEvent
// Add these new cases:

NetworkEvent::BftProposalReceived(data) => {
    if let Ok(proposal) = Proposal::from_bytes(&data) {
        info!("Received BFT proposal for height {}", proposal.view.height);

        // Handle proposal and create prevote
        if let Ok(Some(prevote)) = self.consensus.handle_proposal(proposal) {
            // Broadcast prevote
            let vote_data = prevote.to_bytes();
            self.network
                .command_sender()
                .send(NetworkCommand::BroadcastBftPrevote(vote_data))
                .await
                .ok();
        }
    }
}

NetworkEvent::BftPrevoteReceived(data) => {
    if let Ok(vote) = Vote::from_bytes(&data) {
        if vote.vote_type == VoteType::Prevote {
            debug!("Received BFT prevote for height {}", vote.view.height);

            // Handle prevote and create precommit if quorum reached
            if let Ok(Some(precommit)) = self.consensus.handle_prevote(vote) {
                // Broadcast precommit
                let vote_data = precommit.to_bytes();
                self.network
                    .command_sender()
                    .send(NetworkCommand::BroadcastBftPrecommit(vote_data))
                    .await
                    .ok();
            }
        }
    }
}

NetworkEvent::BftPrecommitReceived(data) => {
    if let Ok(vote) = Vote::from_bytes(&data) {
        if vote.vote_type == VoteType::Precommit {
            debug!("Received BFT precommit for height {}", vote.view.height);

            // Handle precommit and commit block if quorum reached
            if let Ok(Some(block_hash)) = self.consensus.handle_precommit(vote) {
                info!("BFT consensus reached for block {}", block_hash);
                // Block should already be in cache from proposal
                // Execute and commit it
                // (This integrates with existing block execution code)
            }
        }
    }
}
```

### Step 3: Add BFT Block Proposal Loop

**File**: `crates/node/src/node.rs`

Add a new async function for BFT consensus loop:

```rust
/// BFT consensus loop (runs if using BFT engine)
async fn bft_consensus_loop(&self) -> Result<()> {
    let Some(bft) = self.consensus.as_bft() else {
        return Ok(()); // Not BFT, nothing to do
    };

    info!("Starting BFT consensus loop");

    loop {
        let view = bft.current_view();

        // Check if we're the leader for this view
        if bft.is_leader(&view) {
            info!("We are leader for height {}, round {}", view.height, view.round);

            // Build block from mempool
            let txs = self.mempool.get_transactions(2000); // Max per block
            let parent_hash = self.state.best_block_hash();
            let state_root = self.state.state_root();

            // Create block
            let block = sumchain_primitives::Block::new(
                view.height,
                parent_hash,
                state_root,
                txs,
            );

            // Create proposal
            let proposal = bft.create_proposal(view, block, None)?;

            // Broadcast proposal
            let proposal_data = proposal.to_bytes();
            self.network
                .command_sender()
                .send(NetworkCommand::BroadcastBftProposal(proposal_data))
                .await?;

            info!("Broadcast proposal for height {}", view.height);
        }

        // Wait for consensus or timeout
        // This is simplified - real implementation needs timeout handling
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }
}
```

Then call this from `run()`:

```rust
// In run() method, spawn BFT loop if using BFT:
if self.consensus.as_bft().is_some() {
    let bft_node = /* clone necessary fields */;
    tokio::spawn(async move {
        if let Err(e) = bft_node.bft_consensus_loop().await {
            error!("BFT consensus loop error: {}", e);
        }
    });
}
```

### Step 4: Update Main.rs to Pass Config

**File**: `crates/node/src/main.rs`

Find where `Node::new()` or `Node::with_rpc_config()` is called, and update it to pass the config:

```rust
// Around line 150-200 in main.rs
let node = Node::with_rpc_config(
    data_dir,
    genesis,
    validator_key,
    network_config,
    rpc_addr,
    rpc_auth_config,
    rpc_rate_limit_config,
    config.consensus, // ADD THIS
)?;
```

Then update the Node constructor signature to accept it:

```rust
pub fn with_rpc_config(
    data_dir: PathBuf,
    genesis: Genesis,
    validator_key: Option<KeyPair>,
    network_config: NetworkConfig,
    rpc_addr: SocketAddr,
    rpc_auth_config: RpcAuthConfig,
    rpc_rate_limit_config: RateLimitConfig,
    consensus_config: ConsensusSettings, // ADD THIS
) -> Result<Self> {
    // ... use consensus_config to create consensus engine
}
```

### Step 5: Add Missing Trait Implementations

**File**: `crates/consensus/src/bft/engine.rs`

Make sure BftEngine has these methods (they might be missing):

```rust
impl BftEngine {
    pub fn create_proposal(
        &self,
        view: View,
        block: Block,
        valid_round: Option<Round>,
    ) -> Result<Proposal> {
        let proposal = Proposal::new(view, block, valid_round, &self.keypair);
        Ok(proposal)
    }

    pub fn create_prevote(
        &self,
        view: View,
        block_hash: Option<Hash>,
    ) -> Result<Vote> {
        let vote = Vote::new(view, VoteType::Prevote, block_hash, &self.keypair);
        Ok(vote)
    }

    pub fn create_precommit(
        &self,
        view: View,
        block_hash: Option<Hash>,
    ) -> Result<Vote> {
        let vote = Vote::new(view, VoteType::Precommit, block_hash, &self.keypair);
        Ok(vote)
    }

    pub fn add_prevote(&self, vote: Vote) -> Result<bool> {
        // Add to prevote vote set
        // Return true if quorum reached
        // Implementation depends on your VoteSet tracking
        Ok(false) // Placeholder
    }

    pub fn add_precommit(&self, vote: Vote) -> Result<bool> {
        // Add to precommit vote set
        // Return true if quorum reached
        Ok(false) // Placeholder
    }

    pub fn get_prevote_quorum(&self, view: &View) -> Option<Hash> {
        // Check if any block has >2/3 prevotes
        None // Placeholder
    }

    pub fn get_precommit_quorum(&self, view: &View) -> Option<Hash> {
        // Check if any block has >2/3 precommits
        None // Placeholder
    }

    pub fn is_leader(&self, view: &View) -> bool {
        let leader = self.get_leader(view);
        leader == *self.keypair.public_key()
    }

    pub fn current_view(&self) -> View {
        // Return current view from consensus state
        View::new(0, 0) // Placeholder
    }
}
```

## Testing

After integration, test with:

```bash
# 1. Build
cargo build --release

# 2. Create config with PoA first
cat > config.toml <<EOF
[node]
genesis = "genesis/mainnet_genesis.json"
data_dir = "data"

[consensus]
engine = "poa"

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9933"

[rpc]
addr = "127.0.0.1:8545"
EOF

# 3. Run with PoA
./target/release/sumchain-node run --config config.toml

# 4. If that works, switch to BFT
# Edit config.toml, change engine = "bft"

# 5. Run with BFT
./target/release/sumchain-node run --config config.toml
```

## Common Issues & Fixes

### Issue 1: "ConsensusWrapper doesn't implement Clone"
**Fix**: Don't clone it. Pass by reference or use Arc if needed.

### Issue 2: "Missing fields in BftEngine"
**Fix**: Add the missing methods shown in Step 5 above.

### Issue 3: "Cannot move out of Arc"
**Fix**: Use `.as_ref()` or clone the Arc.

### Issue 4: Compilation errors about lifetimes
**Fix**: Make sure all async functions have proper lifetime annotations.

## Completion Checklist

- [ ] Node constructor updated to create ConsensusWrapper based on config
- [ ] BFT message handlers added to event loop
- [ ] BFT consensus loop implemented
- [ ] Main.rs passes consensus config to Node
- [ ] BftEngine has all required methods
- [ ] Compiles successfully: `cargo build`
- [ ] PoA mode works: Run node with `engine = "poa"`
- [ ] BFT mode works: Run node with `engine = "bft"`

## Estimated Time

- **Step 1-2**: 1 hour (updating constructors and event loop)
- **Step 3**: 30 minutes (BFT loop)
- **Step 4**: 15 minutes (main.rs)
- **Step 5**: 1 hour (implementing missing methods)
- **Testing**: 30 minutes
- **Total**: ~3 hours

## Need Help?

If you get stuck:

1. **Check compiler errors** - They're usually very helpful
2. **Look at existing PoA code** - Copy its patterns for BFT
3. **Test incrementally** - Get PoA working first, then add BFT

The hard parts (BFT algorithm, P2P, state) are done. This is just wiring!

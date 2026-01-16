# Validator Setup Guide

This guide walks you through setting up a SUM Chain validator node.

## Prerequisites

- Rust toolchain (1.70+)
- 8GB RAM minimum
- 100GB disk space
- Stable internet connection
- Open port 9933 for P2P networking

## Step 1: Install Rust (if not already installed)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Restart shell or run:
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

## Step 2: Clone and Build the Node

```bash
# Clone the repository
git clone https://github.com/SUM-INNOVATION/sum-chain.git
cd sum-chain

# Build release version (optimized)
cargo build --release

# This will take 5-10 minutes on first build
# Binary will be at: ./target/release/sumchain-node
```

## Step 3: Create Working Directory

```bash
# Create validator working directory
mkdir -p ~/sumchain
cd ~/sumchain

# Create keys subdirectory
mkdir -p keys
```

## Step 4: Generate Validator Key

Each validator needs a unique Ed25519 keypair:

```bash
# Generate validator key (replace N with your validator number: 1, 2, etc.)
../sum-chain/target/release/sumchain-node keygen --output keys/validatorN.json

# This creates a file with your validator keypair (array format):
# [93, 85, 141, 250, ...]  # 64 bytes representing the keypair

# View your public key (base58 format)
../sum-chain/target/release/sumchain-node keygen --show-public keys/validatorN.json
# Output: 7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy
```

**IMPORTANT**:
- Back up `keys/validatorN.json` securely
- Never share your private key
- If you lose this file, you lose validator access
- Use a paper backup for critical validators

## Step 5: Collect Public Keys

Send your **public key** (base58 format) to coordinate with other validators for genesis configuration.

Example public keys:
- Validator 1: `GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8`
- Validator 2: `7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy`

## Step 6: Create Genesis File

Create `~/sumchain/genesis.json` with all validator public keys:

```json
{
  "chain_id": 1,
  "genesis_time": 1734624000000,
  "validators": [
    "GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8",
    "7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy"
  ],
  "params": {
    "block_time": 3000,
    "max_block_size": 5000000,
    "min_fee": 1000000
  },
  "alloc": {
    "FOUNDATION_ADDRESS": "400000000000000000000",
    "ECOSYSTEM_FUND": "160000000000000000000",
    "TEAM_VESTING": "120000000000000000000",
    "COMMUNITY_REWARDS": "80000000000000000000",
    "LIQUIDITY_POOL": "40000000000000000000"
  }
}
```

**CRITICAL**: All validators must use the **exact same genesis file**.

## Step 7: Create Node Configuration

Create `~/sumchain/config.toml`:

### Validator 1 Configuration

```toml
[node]
# Path to genesis file
genesis = "genesis.json"

# Data directory (blockchain data, state, etc.)
data_dir = "data"

# Validator key file (relative to working directory)
validator_key = "keys/validator1.json"

[network]
# P2P listen address
listen_addr = "/ip4/0.0.0.0/tcp/9933"

# Bootstrap nodes (other validators)
# Add after getting peer IDs from other validators
bootnodes = [
    "/ip4/OTHER_VALIDATOR_IP/tcp/9933/p2p/OTHER_VALIDATOR_PEER_ID"
]

# Enable mDNS for local network discovery
mdns = true

[rpc]
# JSON-RPC server address
addr = "127.0.0.1:8545"
```

### Validator 2 Configuration

```toml
[node]
genesis = "genesis.json"
data_dir = "data"
validator_key = "keys/validator2.json"

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9933"
bootnodes = [
    "/ip4/VALIDATOR1_IP/tcp/9933/p2p/VALIDATOR1_PEER_ID"
]
mdns = true

[rpc]
# Use different port if running multiple validators on same network
addr = "127.0.0.1:9944"
```

## Step 8: Get Your Peer ID

Start the node once to get your P2P peer ID:

```bash
cd ~/sumchain
../sum-chain/target/release/sumchain-node run --config config.toml
```

Look for a log line like:
```
Local peer ID: 12D3KooWGbbD8JBcVHR1Ps7TMwcQTbk1pWc7dJfuNk9BP9h4jkbG
```

Your full P2P multiaddress will be:
```
/ip4/YOUR_IP/tcp/9933/p2p/12D3KooWGbbD8JBcVHR1Ps7TMwcQTbk1pWc7dJfuNk9BP9h4jkbG
```

**Share this address** with other validators. Stop the node (Ctrl+C) for now.

## Step 9: Update Bootnodes

Once you have P2P addresses from other validators, update your `config.toml`:

```toml
[network]
listen_addr = "/ip4/0.0.0.0/tcp/9933"
bootnodes = [
    "/ip4/100.124.197.122/tcp/9933/p2p/12D3KooWGbbD8JBcVHR1Ps7TMwcQTbk1pWc7dJfuNk9BP9h4jkbG"
]
mdns = true
```

## Step 10: Set Up systemd Service (Linux)

Create `/etc/systemd/system/sumchain.service`:

```ini
[Unit]
Description=SUM Chain Validator Node
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/sumchain
ExecStart=/home/YOUR_USERNAME/sum-chain/target/release/sumchain-node run --config config.toml
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sumchain
sudo systemctl start sumchain

# View logs
sudo journalctl -u sumchain -f
```

## Step 11: Verify It's Working

Check the logs for healthy operation:

```bash
# View recent logs
journalctl -u sumchain -n 50 --no-pager

# Follow logs in real-time
sudo journalctl -u sumchain -f
```

### Healthy Validator Logs

```
INFO sumchain::node: Starting node
INFO sumchain_network::p2p: Local peer ID: 12D3KooWGbbD8JBcVHR1Ps7TMwcQTbk1pWc7dJfuNk9BP9h4jkbG
INFO sumchain_network::p2p: Peer connected: 12D3KooW...
INFO sumchain_consensus::poa: Block producer started with 3000ms block time
INFO sumchain_consensus::poa: Our turn to propose block 497004
INFO sumchain_state::executor: Block 497004 executed, new state root: 0xf172...
INFO sumchain_consensus::poa: Created block 0x1ea7... at height 497004 with 0 txs
INFO sumchain_consensus::poa: Finality checkpoint: height 496998 (current: 497004, depth: 6)
INFO sumchain::node: Produced block 0x1ea7... at height 497004
```

### RPC Health Check

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sum_blockNumber","params":[],"id":1}'

# Response: {"jsonrpc":"2.0","id":1,"result":497004}
```

## Updating the Node

When updates are available:

```bash
# Pull latest changes
cd ~/sum-chain
git pull origin main

# Rebuild
source ~/.cargo/env
cargo build --release

# Restart the service
sudo systemctl restart sumchain

# Verify new version is running
sudo journalctl -u sumchain -n 20 --no-pager
```

## Copying Database Between Validators

If a new validator needs to sync from an existing one:

```bash
# On source validator, stop the service
sudo systemctl stop sumchain

# Copy the data directory to the new validator
rsync -avz --progress ~/sumchain/data/ user@new-validator:~/sumchain/data/

# IMPORTANT: Remove node.key from the copied data so new validator generates its own peer ID
ssh user@new-validator "rm ~/sumchain/data/node.key"

# Restart source validator
sudo systemctl start sumchain

# Start new validator
ssh user@new-validator "sudo systemctl start sumchain"
```

## Troubleshooting

### "State root mismatch" Error

This occurs when validators are running different code versions:

```
WARN sumchain::node: Failed to import block: Invalid block: State root mismatch: expected 0xdc9f..., got 0x9e38...
```

**Solution**: Ensure all validators are running the same binary version. Update and restart the out-of-sync validator.

### "Parent block not found" During Sync

This can happen when syncing from genesis with blocks arriving out of order:

```
WARN sumchain::node: Failed to import block: Parent block not found
```

**Solution**: Copy the database from a synced validator (see "Copying Database Between Validators" above).

### Validator Not Producing Blocks

Check that:
1. The correct validator key is configured in `config.toml`
2. The key path is relative to the working directory
3. The public key matches what's in genesis.json

```bash
# Verify key configuration
cat ~/sumchain/config.toml | grep validator_key
# Should show: validator_key = "keys/validator1.json"

# Verify key file exists
ls -la ~/sumchain/keys/validator1.json
```

### "No peers connected"

1. Check firewall allows port 9933
2. Verify bootnode addresses are correct
3. Check network connectivity to other validators

```bash
# Test connectivity to other validator
nc -zv 100.124.197.122 9933
```

### Service Won't Start

Check for configuration errors:

```bash
# Test config manually
cd ~/sumchain
../sum-chain/target/release/sumchain-node run --config config.toml

# Check systemd logs for errors
sudo journalctl -u sumchain -n 100 --no-pager
```

## File Permissions

Secure your validator key:

```bash
chmod 600 ~/sumchain/keys/validator*.json
chmod 700 ~/sumchain/keys
```

## Backup Checklist

Critical files to backup:

1. **Validator key**: `~/sumchain/keys/validatorN.json` - CRITICAL
2. **Configuration**: `~/sumchain/config.toml`
3. **Genesis file**: `~/sumchain/genesis.json`

```bash
# Create encrypted backup
tar czf - ~/sumchain/keys ~/sumchain/config.toml ~/sumchain/genesis.json | \
  gpg --symmetric --cipher-algo AES256 > validator-backup-$(date +%Y%m%d).tar.gz.gpg
```

## Network Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Chain ID | 1 | Mainnet chain identifier |
| Block Time | 3 seconds | Target block production time |
| Min Fee | 1,000,000 base units | Minimum transaction fee |
| P2P Port | 9933 | Default P2P networking port |
| RPC Port | 8545 | Default JSON-RPC port |
| Finality Depth | 6 blocks | Blocks until finality checkpoint |

## Current Validators

| Validator | Public Key | IP (Tailscale) |
|-----------|------------|----------------|
| Validator 1 | `GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8` | 100.124.197.122 |
| Validator 2 | `7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy` | 100.84.189.95 |

## Support

If your validator experiences issues:
1. Check logs for error messages
2. Verify all validators are on the same code version
3. Ensure network connectivity between validators
4. Coordinate with other validators before making changes

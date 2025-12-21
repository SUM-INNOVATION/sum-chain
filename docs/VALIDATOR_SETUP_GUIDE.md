# Validator Setup Guide

This guide walks you through setting up a SUM Chain validator node on your computer.

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

## Step 2: Build the Node

```bash
# Navigate to project directory
cd /Users/1mle0wang/Library/Mobile\ Documents/com~apple~CloudDocs/sum-chain

# Build release version (optimized)
cargo build --release

# This will take 5-10 minutes on first build
# Binary will be at: ./target/release/sumchain-node
```

## Step 3: Generate Validator Key

Each validator needs a unique Ed25519 keypair:

```bash
# Generate validator key
./target/release/sumchain-node keygen --output validator-key.json

# This creates a file with your validator keypair:
# {
#   "public_key": "0x1234...",  // Your validator public key
#   "secret_key": "0xabcd..."   // Keep this SECRET!
# }
```

**⚠️ IMPORTANT**:
- Back up `validator-key.json` securely
- Never share your secret key
- If you lose this file, you lose validator access

## Step 4: Share Your Public Key

Send your **public key** (from validator-key.json) to coordinate with other validators for genesis configuration.

You'll need:
1. Your public key: `0x1234...`
2. Delaware friend's public key
3. China friend's public key

## Step 5: Create Genesis File

Once you have all 3 validator public keys, create the genesis file:

```bash
# Edit genesis/mainnet_genesis.json
nano genesis/mainnet_genesis.json
```

Update the validators array with all 3 public keys:

```json
{
  "chain_id": 1,
  "genesis_time": 1734624000000,
  "validators": [
    "YOUR_PUBLIC_KEY_HERE",
    "DELAWARE_PUBLIC_KEY_HERE",
    "CHINA_PUBLIC_KEY_HERE"
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

**Share this genesis file** with Delaware and China validators - all 3 nodes must use the **exact same genesis**.

## Step 6: Create Node Configuration

Create your node config file:

```bash
# Create config file
cat > config.toml <<EOF
[node]
# Path to genesis file
genesis = "genesis/mainnet_genesis.json"

# Data directory (blockchain data, state, etc.)
data_dir = "data"

# Validator key file
validator_key = "validator-key.json"

[consensus]
# Use BFT consensus (Byzantine Fault Tolerant)
engine = "bft"

[consensus.bft]
# Block proposal timeout (milliseconds)
propose_timeout_ms = 3000

# Prevote timeout
prevote_timeout_ms = 1000

# Precommit timeout
precommit_timeout_ms = 1000

# Timeout multiplier per round
timeout_multiplier = 1.5

[network]
# P2P listen address
listen_addr = "/ip4/0.0.0.0/tcp/9933"

# Bootstrap nodes (other validators)
# You'll add these after getting their addresses
bootnodes = []

# Maximum connections
max_inbound = 50
max_outbound = 10

[rpc]
# JSON-RPC server address
addr = "127.0.0.1:8545"

# Enable authentication (recommended for production)
# auth_token = "your-secret-rpc-token"

[logging]
# Log level: trace, debug, info, warn, error
level = "info"
EOF
```

## Step 7: Get Your P2P Address

Start the node once to get your P2P address:

```bash
./target/release/sumchain-node run --config config.toml
```

Look for a log line like:
```
Local peer ID: 12D3KooWAbc123...
Listening on: /ip4/192.168.1.100/tcp/9933/p2p/12D3KooWAbc123...
```

**Your full P2P address** is something like:
```
/ip4/YOUR_PUBLIC_IP/tcp/9933/p2p/12D3KooWAbc123...
```

**Share this address** with Delaware and China validators.

Stop the node (Ctrl+C) for now.

## Step 8: Configure Port Forwarding

To allow other validators to connect to you:

**On your router**:
1. Log into router admin panel (usually 192.168.1.1)
2. Find "Port Forwarding" section
3. Add rule:
   - External Port: 9933
   - Internal Port: 9933
   - Internal IP: Your computer's local IP
   - Protocol: TCP

**Get your public IP**:
```bash
curl ifconfig.me
```

## Step 9: Update Bootnodes

Once you have P2P addresses from Delaware and China validators, update your config:

```bash
nano config.toml
```

Update the bootnodes section:
```toml
[network]
# ... other settings ...

bootnodes = [
    "/ip4/DELAWARE_PUBLIC_IP/tcp/9933/p2p/DELAWARE_PEER_ID",
    "/ip4/CHINA_PUBLIC_IP/tcp/9933/p2p/CHINA_PEER_ID",
]
```

## Step 10: Start Your Validator

```bash
# Start the validator node
./target/release/sumchain-node run --config config.toml

# You should see:
# - "Starting node"
# - "BFT consensus active"
# - "Peer connected: 12D3..." (when other validators connect)
# - "Received BFT proposal for height X"
# - "BFT consensus reached for block Y"
```

## Step 11: Verify It's Working

Open another terminal and check the RPC:

```bash
# Check node status
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sum_blockNumber",
    "params": [],
    "id": 1
  }'

# Should return current block height:
# {"jsonrpc":"2.0","id":1,"result":"0x123"}
```

## Monitoring Your Validator

### Check logs
```bash
# Watch logs in real-time
tail -f logs/validator.log  # if you configured log_file

# Or just watch the console output
```

### Key metrics to watch:
- **Peer count**: Should be 2 (Delaware + China)
- **Block height**: Should increase every 3-5 seconds
- **Consensus participation**: Look for "Received BFT prevote/precommit" logs
- **Quorum reached**: "BFT consensus reached for block" logs

### Common log patterns:

**Healthy validator**:
```
INFO Starting node
INFO BFT consensus active
INFO Peer connected: 12D3KooW... (Delaware)
INFO Peer connected: 12D3KooW... (China)
INFO Received BFT proposal for height 1
INFO Received BFT prevote for height 1
INFO BFT consensus reached for block 0xabc...
INFO Block finalized: height=1, hash=0xabc...
```

**Issues to watch for**:
```
WARN Peer disconnected: 12D3KooW...  # Network issue
ERROR Failed to import block: ...     # Sync issue
WARN Sync request failed: ...         # Connectivity issue
```

## Firewall Configuration

### macOS
```bash
# Allow incoming connections on port 9933
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/sumchain-node
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /path/to/sumchain-node
```

### Linux (ufw)
```bash
sudo ufw allow 9933/tcp
sudo ufw enable
```

## Running as a Service (Recommended)

### macOS (launchd)

Create `~/Library/LaunchAgents/com.sumchain.validator.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sumchain.validator</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/sumchain-node</string>
        <string>run</string>
        <string>--config</string>
        <string>/path/to/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/path/to/logs/validator.log</string>
    <key>StandardErrorPath</key>
    <string>/path/to/logs/validator-error.log</string>
</dict>
</plist>
```

Start the service:
```bash
launchctl load ~/Library/LaunchAgents/com.sumchain.validator.plist
launchctl start com.sumchain.validator
```

## Backup and Recovery

### What to backup:
1. **validator-key.json** - Your validator identity (CRITICAL)
2. **config.toml** - Node configuration
3. **genesis/mainnet_genesis.json** - Genesis file
4. **data/** directory - Blockchain data (optional, can resync)

### How to backup:
```bash
# Create backup directory
mkdir -p ~/sumchain-backups

# Backup critical files
cp validator-key.json ~/sumchain-backups/
cp config.toml ~/sumchain-backups/
cp genesis/mainnet_genesis.json ~/sumchain-backups/

# Compress and encrypt (recommended)
tar czf ~/sumchain-backups/validator-backup-$(date +%Y%m%d).tar.gz \
    validator-key.json config.toml genesis/mainnet_genesis.json

# Store this backup in a secure location (USB drive, cloud backup, etc.)
```

## Troubleshooting

### "Failed to bind to port 9933"
- Port already in use
- Run: `lsof -i :9933` to find what's using it
- Kill the process or use a different port

### "No peers connected"
- Check firewall settings
- Verify port forwarding is correct
- Confirm bootnodes addresses are correct
- Check your public IP hasn't changed

### "BFT consensus not reaching quorum"
- Need at least 2 out of 3 validators online
- Check network connectivity to other validators
- Verify all validators have the same genesis file
- Check time synchronization (NTP)

### "Out of disk space"
- Default data directory can grow large
- Monitor disk usage: `du -sh data/`
- Consider pruning or larger disk

## Next Steps

Once your validator is running:
1. ✅ Monitor for 24 hours to ensure stability
2. ✅ Coordinate with Delaware and China validators
3. ✅ Set up automated backups
4. ✅ Configure monitoring/alerting
5. ✅ Document your setup for disaster recovery

## Support Checklist

- [ ] Rust installed and working
- [ ] Node compiled successfully
- [ ] Validator key generated and backed up
- [ ] Genesis file created with all 3 validators
- [ ] Config file created
- [ ] Port 9933 forwarded on router
- [ ] P2P address shared with other validators
- [ ] Bootnodes configured
- [ ] Node started and running
- [ ] Connected to 2 peers (Delaware + China)
- [ ] Participating in BFT consensus
- [ ] Blocks being finalized

## Emergency Contacts

Keep contact info for other validators:
- Delaware validator: [Contact info]
- China validator: [Contact info]

If your validator goes down, notify them ASAP so they know the network is operating with reduced capacity.

---

**You're now running a SUM Chain validator node!** 🎉

The network can tolerate 1 out of 3 validators being down (BFT requires 2f+1 for 3 validators, where f=0), so uptime is critical. Aim for 99.9% uptime.

---

## Security Best Practices

### Validator Key Security
1. **Never commit validator-key.json to git**
2. **Use file permissions**: `chmod 600 validator-key.json`
3. **Consider HSM** for production deployments
4. **Rotate keys** if compromise is suspected

### Network Security
1. **Use a firewall** - only allow port 9933 for P2P
2. **Disable RPC** on public interface (use 127.0.0.1)
3. **Use VPN** between validators for additional security
4. **Enable RPC authentication** in production

### Operational Security
1. **Monitor** node logs for anomalies
2. **Alert** on peer disconnections
3. **Regular backups** of validator key
4. **Test recovery** procedures periodically

## Using the Wallet CLI

The wallet CLI can interact with your running node:

```bash
# Build the wallet
cargo build --release --bin sumchain-wallet

# Check node health
./target/release/sumchain-wallet status --rpc http://127.0.0.1:8545

# Generate a new address
./target/release/sumchain-wallet generate --password "your-password"

# Check balance
./target/release/sumchain-wallet balance --address SUM1abc... --rpc http://127.0.0.1:8545

# Send transaction
./target/release/sumchain-wallet send \
  --from wallet.json \
  --to SUM1xyz... \
  --amount 1000000000 \
  --rpc http://127.0.0.1:8545

# NFT Commands (SUM-721)
./target/release/sumchain-wallet nft-collection --id 0x... --rpc http://127.0.0.1:8545
./target/release/sumchain-wallet nft-token --collection 0x... --token-id 1
./target/release/sumchain-wallet nft-list --owner SUM1abc...
./target/release/sumchain-wallet nft-balance --owner SUM1abc...
```

## Network Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Chain ID | 1 | Mainnet chain identifier |
| Block Time | 3 seconds | Target block production time |
| Min Fee | 1,000,000 Milli | Minimum transaction fee |
| Total Supply | 800M SUM | Maximum token supply |
| Validators | 3 | Initial validator count |
| BFT Threshold | 2/3 | Required votes for consensus |

## Glossary

- **Validator**: A node that participates in block production and consensus
- **BFT**: Byzantine Fault Tolerant consensus algorithm
- **Quorum**: Minimum number of validators needed to finalize a block (2/3)
- **Peer ID**: Unique identifier for a node in the P2P network
- **Genesis**: The first block and initial state of the blockchain
- **Finality**: When a block cannot be reverted (immediate in BFT)

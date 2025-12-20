# SUM Chain Operator Guide

This guide covers deploying and operating SUM Chain validator nodes in production.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running a Validator](#running-a-validator)
5. [Monitoring](#monitoring)
6. [Backup and Recovery](#backup-and-recovery)
7. [Upgrading](#upgrading)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 100 GB SSD | 500+ GB NVMe SSD |
| Network | 100 Mbps | 1 Gbps |

### Software Requirements

- Linux (Ubuntu 22.04+ recommended) or macOS
- Rust 1.75+ (for building from source)
- Docker 24+ (for containerized deployment)
- Kubernetes 1.28+ (for orchestrated deployment)

## Installation

### From Source

```bash
# Clone repository
git clone https://github.com/sumchain/sum-chain.git
cd sum-chain

# Build release binary
cargo build --release

# Binary will be at target/release/sumchain-node
```

### Using Docker

```bash
# Build image
docker build -t sumchain:latest .

# Or pull from registry (when available)
docker pull sumchain/sumchain:latest
```

### Using Docker Compose (Development/Testing)

```bash
# Start 3-node validator network with monitoring
docker-compose up -d

# View logs
docker-compose logs -f

# Stop network
docker-compose down -v
```

## Configuration

### Node Configuration File

Create a configuration file at `/etc/sumchain/node.toml`:

```toml
# Network identity
chain_id = 1

# Data directory
data_dir = "/var/lib/sumchain"

# P2P networking
[p2p]
listen_address = "/ip4/0.0.0.0/tcp/30303"
external_address = "/ip4/<PUBLIC_IP>/tcp/30303"
bootstrap_nodes = [
    "/ip4/bootstrap1.sumchain.io/tcp/30303/p2p/<PEER_ID>",
    "/ip4/bootstrap2.sumchain.io/tcp/30303/p2p/<PEER_ID>"
]

# RPC server
[rpc]
enabled = true
listen_address = "0.0.0.0:8545"
cors_origins = ["*"]

# Metrics
[metrics]
enabled = true
listen_address = "0.0.0.0:9090"

# Consensus
[consensus]
block_time_ms = 3000
finality_threshold = 2

# Logging
[logging]
level = "info"
format = "json"
```

### Validator Key Management

Generate validator keys securely:

```bash
# Generate encrypted keystore
sumchain-wallet keygen --output /etc/sumchain/validator.key

# View validator address
sumchain-wallet address --key /etc/sumchain/validator.key
```

**Security Best Practices:**
- Store keys on encrypted filesystem
- Use hardware security modules (HSM) in production
- Never share private keys
- Backup keys securely offline

## Running a Validator

### Systemd Service

Create `/etc/systemd/system/sumchain.service`:

```ini
[Unit]
Description=SUM Chain Validator Node
After=network.target

[Service]
Type=simple
User=sumchain
Group=sumchain
ExecStart=/usr/local/bin/sumchain-node \
    --config /etc/sumchain/node.toml \
    --validator \
    --validator-key /etc/sumchain/validator.key
Restart=always
RestartSec=10
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sumchain

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable sumchain
sudo systemctl start sumchain
sudo journalctl -u sumchain -f
```

### Docker

```bash
docker run -d \
    --name sumchain-validator \
    -v /var/lib/sumchain:/data \
    -v /etc/sumchain:/config:ro \
    -p 30303:30303 \
    -p 8545:8545 \
    -p 9090:9090 \
    sumchain:latest \
    --config /config/node.toml \
    --validator
```

### Kubernetes

Apply manifests:

```bash
kubectl apply -f deploy/kubernetes/
```

See `deploy/kubernetes/` for full manifests including:
- Namespace
- ConfigMap
- StatefulSet
- Service
- ServiceMonitor (for Prometheus Operator)

## Monitoring

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health/live` | Liveness probe |
| `GET /health/ready` | Readiness probe |
| `GET /health` | Full health status |

### Prometheus Metrics

Metrics are exposed at `http://localhost:9090/metrics`:

| Metric | Description |
|--------|-------------|
| `sumchain_block_height` | Current block height |
| `sumchain_block_time_seconds` | Block production time |
| `sumchain_peer_count` | Connected peer count |
| `sumchain_mempool_size` | Pending transactions |
| `sumchain_consensus_round` | Current consensus round |

### Grafana Dashboard

Import the dashboard from `deploy/monitoring/grafana/dashboards/sumchain-overview.json`.

The dashboard provides:
- Block production metrics
- Consensus participation
- P2P network health
- Resource utilization

### Alerting

Recommended alerts:

```yaml
groups:
  - name: sumchain
    rules:
      - alert: NodeDown
        expr: up{job="sumchain-validators"} == 0
        for: 1m
        annotations:
          summary: "SUM Chain validator is down"

      - alert: BlockProductionStalled
        expr: increase(sumchain_block_height[5m]) == 0
        for: 5m
        annotations:
          summary: "No new blocks in 5 minutes"

      - alert: LowPeerCount
        expr: sumchain_peer_count < 2
        for: 5m
        annotations:
          summary: "Validator has fewer than 2 peers"
```

## Backup and Recovery

### Regular Backups

```bash
# Stop node (or use online backup if supported)
systemctl stop sumchain

# Backup data directory
tar -czf sumchain-backup-$(date +%Y%m%d).tar.gz /var/lib/sumchain

# Restart node
systemctl start sumchain
```

### State Snapshots

SUM Chain supports state snapshots for fast sync:

```bash
# Create snapshot (while node is running)
sumchain-node snapshot create --output /backups/snapshot-latest.bin

# Restore from snapshot on new node
sumchain-node snapshot restore --input /backups/snapshot-latest.bin
```

### Disaster Recovery

1. Provision new server
2. Install SUM Chain
3. Restore validator key from secure backup
4. Either:
   - Restore from snapshot (fast, minutes)
   - Full sync from genesis (slow, hours/days)
5. Start validator

## Upgrading

### Rolling Upgrade (Recommended)

For validator sets, upgrade one validator at a time:

1. Stop validator
2. Backup data directory
3. Upgrade binary/image
4. Start validator
5. Verify healthy before proceeding to next

### Kubernetes Rolling Update

```bash
# Update image tag
kubectl set image statefulset/sumchain-validator \
    sumchain=sumchain:v1.2.0 \
    -n sumchain

# Monitor rollout
kubectl rollout status statefulset/sumchain-validator -n sumchain
```

## Troubleshooting

### Node Not Syncing

1. Check peer connections:
   ```bash
   curl http://localhost:8545/health | jq .peer_count
   ```

2. Verify bootstrap nodes are reachable:
   ```bash
   nc -zv bootstrap1.sumchain.io 30303
   ```

3. Check firewall rules allow P2P port (30303)

### Consensus Issues

1. Verify validator key is loaded:
   ```bash
   curl http://localhost:8545/health | jq .is_validator
   ```

2. Check consensus participation in logs:
   ```bash
   journalctl -u sumchain | grep -i consensus
   ```

3. Ensure clock is synchronized:
   ```bash
   timedatectl status
   ```

### High Memory Usage

1. Check mempool size:
   ```bash
   curl http://localhost:8545 \
       -H "Content-Type: application/json" \
       -d '{"jsonrpc":"2.0","method":"txpool_content","id":1}' | jq
   ```

2. Consider adjusting mempool limits in config

### RPC Connection Issues

1. Verify RPC is enabled and listening:
   ```bash
   netstat -tlnp | grep 8545
   ```

2. Check CORS configuration if accessing from browser

3. Verify TLS/SSL if using HTTPS

### Log Analysis

Enable debug logging temporarily:

```bash
RUST_LOG=debug sumchain-node --config /etc/sumchain/node.toml
```

Key log patterns to watch:
- `block_imported` - Successful block import
- `consensus_vote` - Consensus participation
- `peer_connected` - P2P connections
- `transaction_added` - Mempool activity

## Support

- Documentation: https://docs.sumchain.io
- GitHub Issues: https://github.com/sumchain/sum-chain/issues
- Discord: https://discord.gg/sumchain

# Bootstrap Node Setup Guide

Bootstrap nodes are critical infrastructure for SUM Chain network peer discovery. They provide initial connection points for new nodes joining the network.

## Overview

Bootstrap nodes serve as initial entry points for P2P network discovery. They:
- Run 24/7 with high availability
- Accept connections from all peers
- Advertise their addresses via DNS
- Do not participate in consensus (non-validator nodes)
- Maintain connections to validators and other bootstrap nodes

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 50 GB SSD | 200+ GB SSD |
| Network | 100 Mbps | 1 Gbps |
| Uptime | 99% | 99.9%+ |

## Network Requirements

### Firewall Configuration

```bash
# Allow P2P connections
ufw allow 30303/tcp

# Allow RPC (optional, for monitoring only)
ufw allow 8545/tcp from <MONITORING_IP>

# Allow metrics
ufw allow 9090/tcp from <PROMETHEUS_IP>
```

### DNS Configuration

Bootstrap nodes should have stable DNS records:

```
boot1.sumchain.io    A    <IP_ADDRESS>
boot2.sumchain.io    A    <IP_ADDRESS>
boot3.sumchain.io    A    <IP_ADDRESS>
```

## Installation

### Using Docker

```bash
# Pull image
docker pull sumchain/sumchain:latest

# Run bootstrap node
docker run -d \
    --name sumchain-bootstrap \
    --restart always \
    -p 30303:30303 \
    -p 8545:8545 \
    -p 9090:9090 \
    -v /var/lib/sumchain:/data \
    sumchain/sumchain:latest \
    --config /config/bootstrap.toml
```

### Using Systemd

Create `/etc/sumchain/bootstrap.toml`:

```toml
chain_id = 1
data_dir = "/var/lib/sumchain"

[p2p]
listen_address = "/ip4/0.0.0.0/tcp/30303"
external_address = "/dns4/boot1.sumchain.io/tcp/30303"
max_peers = 200
bootstrap_nodes = [
    "/dns4/boot2.sumchain.io/tcp/30303/p2p/<PEER_ID_2>",
    "/dns4/boot3.sumchain.io/tcp/30303/p2p/<PEER_ID_3>"
]

[rpc]
enabled = true
listen_address = "127.0.0.1:8545"
cors_origins = []

[metrics]
enabled = true
listen_address = "0.0.0.0:9090"

[logging]
level = "info"
format = "json"
```

Create `/etc/systemd/system/sumchain-bootstrap.service`:

```ini
[Unit]
Description=SUM Chain Bootstrap Node
After=network.target

[Service]
Type=simple
User=sumchain
Group=sumchain
ExecStart=/usr/local/bin/sumchain-node \
    --config /etc/sumchain/bootstrap.toml \
    --genesis /etc/sumchain/mainnet_genesis.json
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
sudo systemctl enable sumchain-bootstrap
sudo systemctl start sumchain-bootstrap
sudo journalctl -u sumchain-bootstrap -f
```

## Configuration

### Key Configuration Parameters

```toml
[p2p]
# Maximum number of peers (bootstrap nodes should accept more)
max_peers = 200

# Enable mDNS for local discovery
mdns_enabled = true

# Connection limits
max_incoming_connections = 150
max_outgoing_connections = 50

# Keep-alive settings
connection_idle_timeout_ms = 300000  # 5 minutes
ping_interval_ms = 30000  # 30 seconds
```

### External Address

Bootstrap nodes MUST advertise their external address correctly:

```toml
external_address = "/dns4/boot1.sumchain.io/tcp/30303"
# Or with IP:
# external_address = "/ip4/<PUBLIC_IP>/tcp/30303"
```

To find your peer ID:

```bash
# After starting the node
curl http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"p2p_localPeerId","id":1}' | jq -r .result
```

## Monitoring

### Health Checks

```bash
# Liveness check
curl http://localhost:8545/health/live

# Readiness check
curl http://localhost:8545/health/ready

# Full health status
curl http://localhost:8545/health | jq
```

### Metrics

Monitor these key metrics:

```bash
# Peer count (should be close to max_peers)
curl http://localhost:9090/metrics | grep sumchain_peer_count

# Connection rate
curl http://localhost:9090/metrics | grep sumchain_p2p_connections_total

# Bandwidth usage
curl http://localhost:9090/metrics | grep sumchain_p2p_bytes
```

### Prometheus Configuration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'sumchain-bootstrap'
    static_configs:
      - targets:
          - 'boot1.sumchain.io:9090'
          - 'boot2.sumchain.io:9090'
          - 'boot3.sumchain.io:9090'
```

### Alerting Rules

```yaml
groups:
  - name: bootstrap_nodes
    rules:
      - alert: BootstrapNodeDown
        expr: up{job="sumchain-bootstrap"} == 0
        for: 2m
        annotations:
          summary: "Bootstrap node {{ $labels.instance }} is down"

      - alert: LowPeerCount
        expr: sumchain_peer_count{job="sumchain-bootstrap"} < 10
        for: 5m
        annotations:
          summary: "Bootstrap node has low peer count: {{ $value }}"

      - alert: HighConnectionRate
        expr: rate(sumchain_p2p_connections_total[1m]) > 100
        for: 5m
        annotations:
          summary: "High connection rate may indicate attack"
```

## Maintenance

### Log Rotation

Configure log rotation to prevent disk fill:

```bash
# /etc/logrotate.d/sumchain-bootstrap
/var/log/sumchain/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 sumchain sumchain
    sharedscripts
    postrotate
        systemctl reload sumchain-bootstrap > /dev/null 2>&1 || true
    endscript
}
```

### Database Maintenance

```bash
# Compact database monthly
sumchain-node compact --data-dir /var/lib/sumchain

# Check database size
du -sh /var/lib/sumchain
```

### Updates

```bash
# Backup before updating
systemctl stop sumchain-bootstrap
tar -czf backup-$(date +%Y%m%d).tar.gz /var/lib/sumchain

# Update binary
wget https://github.com/sumchain/sum-chain/releases/download/v1.1.0/sumchain-node
chmod +x sumchain-node
mv sumchain-node /usr/local/bin/

# Restart
systemctl start sumchain-bootstrap
journalctl -u sumchain-bootstrap -f
```

## Security

### DDoS Protection

1. **Rate Limiting**: Configure connection rate limits

```toml
[p2p]
max_connection_rate_per_ip = 10  # connections per second
connection_backoff_base_ms = 1000
connection_backoff_max_ms = 60000
```

2. **IP Filtering**: Block abusive IPs

```bash
# Block specific IP
ufw deny from <ABUSIVE_IP>

# Use fail2ban for automatic blocking
apt-get install fail2ban
```

3. **Resource Limits**

```toml
[p2p]
max_message_size_bytes = 1048576  # 1 MB
max_pending_connections = 100
```

### Network Security

1. **TLS/SSL**: Bootstrap nodes should support TLS

```toml
[p2p]
tls_enabled = true
tls_cert = "/etc/sumchain/tls/cert.pem"
tls_key = "/etc/sumchain/tls/key.pem"
```

2. **Regular Security Audits**
   - Monthly dependency updates
   - Quarterly security reviews
   - Annual penetration testing

## Troubleshooting

### Low Peer Count

```bash
# Check external address is advertised correctly
curl http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"p2p_peers","id":1}' | jq

# Verify firewall
nc -zv <PUBLIC_IP> 30303

# Check DNS resolution
dig boot1.sumchain.io
```

### High CPU/Memory Usage

```bash
# Check peer count
curl http://localhost:9090/metrics | grep sumchain_peer_count

# Reduce max_peers if needed
# Edit /etc/sumchain/bootstrap.toml
max_peers = 100

# Restart
systemctl restart sumchain-bootstrap
```

### Connection Refused

```bash
# Verify node is listening
netstat -tlnp | grep 30303

# Check logs
journalctl -u sumchain-bootstrap --since "10 minutes ago"

# Verify configuration
sumchain-node --config /etc/sumchain/bootstrap.toml --check-config
```

## Best Practices

1. **Geographic Distribution**: Run bootstrap nodes in different regions
2. **Provider Diversity**: Use different hosting providers
3. **Redundancy**: Maintain at least 3 bootstrap nodes
4. **Monitoring**: Set up comprehensive monitoring and alerts
5. **Automation**: Use infrastructure-as-code (Terraform, Ansible)
6. **Documentation**: Keep runbooks updated
7. **Communication**: Maintain operator communication channel
8. **Backups**: Regular backups of configuration and data

## Mainnet Bootstrap Nodes

| Node | Domain | Location | Operator |
|------|--------|----------|----------|
| Bootstrap 1 | boot1.sumchain.io | US East | SUM Foundation |
| Bootstrap 2 | boot2.sumchain.io | EU West | SUM Foundation |
| Bootstrap 3 | boot3.sumchain.io | Asia Pacific | SUM Foundation |

## Testnet Bootstrap Nodes

| Node | Domain | Location |
|------|--------|----------|
| Testnet Bootstrap 1 | testnet-boot1.sumchain.io | US East |
| Testnet Bootstrap 2 | testnet-boot2.sumchain.io | EU West |

## Contact

- **Bootstrap Node Issues**: bootstrap@sumchain.io
- **Emergency**: Call validator emergency hotline

# SUM Chain Quick Start Guide

## What is SUM Chain?

**SUM Chain** is a high-performance blockchain designed for **global peer-to-peer cash transactions**. Think Bitcoin, but optimized for everyday purchases with instant finality and ultra-low fees.

### Key Features

- **Native Currency**: Koppa (Ϙ)
- **Total Supply**: 800 billion Ϙ (~100 Ϙ per person globally)
- **Transaction Fee**: 0.001 Ϙ (essentially negligible)
- **Block Time**: 3-5 seconds
- **Finality**: Immediate (BFT consensus)
- **Throughput**: 1000+ transactions per second

## For Users

### Getting Started

1. **Install Wallet**
   ```bash
   cargo install sumchain-wallet
   ```

2. **Create Account**
   ```bash
   sumchain-wallet new
   # Your address: 0x1a2b3c4d...
   # IMPORTANT: Save your seed phrase!
   ```

3. **Receive Koppa**
   - Share your address with sender
   - Funds arrive in 3-5 seconds
   - No confirmations needed!

4. **Send Koppa**
   ```bash
   sumchain-wallet transfer \
     --to 0x5e6f7g8h... \
     --amount 10.5 \
     --fee 0.001
   ```

### Example Transactions

**Buy coffee (5 Ϙ)**:
```bash
sumchain-wallet transfer \
  --to COFFEE_SHOP_ADDRESS \
  --amount 5 \
  --fee 0.001
```

**Split dinner bill (25 Ϙ each)**:
```bash
sumchain-wallet transfer --to FRIEND1 --amount 25 --fee 0.001
sumchain-wallet transfer --to FRIEND2 --amount 25 --fee 0.001
sumchain-wallet transfer --to FRIEND3 --amount 25 --fee 0.001
```

**International remittance (500 Ϙ)**:
```bash
sumchain-wallet transfer \
  --to FAMILY_ADDRESS \
  --amount 500 \
  --fee 0.001
# Arrives in 3 seconds! Traditional banks take 3-5 days.
```

## For Developers

### TypeScript/JavaScript

1. **Install SDK**
   ```bash
   npm install @sumchain/sdk
   ```

2. **Connect to Network**
   ```typescript
   import { Provider } from '@sumchain/sdk';

   const provider = new Provider('https://mainnet.sumchain.org');

   // Get current block
   const height = await provider.getBlockNumber();
   console.log(`Current height: ${height}`);

   // Check balance
   const balance = await provider.getBalance('0x1a2b3c...');
   console.log(`Balance: ${formatKoppa(balance)}`);
   ```

3. **Build DApp**
   ```typescript
   // Transfer Koppa
   const tx = await provider.sendTransaction({
     from: wallet.address,
     to: '0x5e6f7g8h...',
     amount: parseKoppa('10.5'), // 10.5 Ϙ
     fee: parseKoppa('0.001'),
     nonce: await provider.getNonce(wallet.address),
   });

   // Wait for confirmation (3-5 seconds)
   const receipt = await provider.waitForReceipt(tx.hash);
   console.log(`Success! Block: ${receipt.block_height}`);
   ```

### Smart Contract Development

SUM Chain currently focuses on **simple value transfers** for peer-to-peer cash. Smart contract support is planned for a future upgrade.

**Current capabilities**:
- Native token transfers
- Multi-signature wallets (coming soon)
- Atomic swaps (coming soon)

## For Validators

### Minimum Requirements

- **CPU**: 8 cores
- **RAM**: 16 GB
- **Disk**: 500 GB NVMe SSD
- **Network**: 1 Gbps
- **OS**: Linux (Ubuntu 22.04+ recommended)

### Setup Validator

1. **Install Node**
   ```bash
   curl -sSL https://get.sumchain.org | sh
   ```

2. **Generate Keys**
   ```bash
   sumchain-node keygen --output validator-key.pem
   # Public key: 0xaabbccdd...
   # (Share with SUM Chain foundation to be added to validator set)
   ```

3. **Configure Node**
   ```toml
   # config.toml
   [node]
   node_type = "validator"
   validator_key_file = "./validator-key.pem"
   chain_id = 1

   [consensus]
   engine = "bft"

   [network]
   listen_addr = "0.0.0.0"
   listen_port = 9933
   bootnodes = [
     "/ip4/10.0.1.10/tcp/9933/p2p/12D3KooW...",
     "/ip4/10.0.1.11/tcp/9933/p2p/12D3KooW..."
   ]
   ```

4. **Start Validator**
   ```bash
   sumchain-node --config config.toml
   ```

5. **Monitor**
   - Prometheus metrics: http://localhost:9615/metrics
   - Logs: journalctl -u sumchain-validator -f

### Validator Rewards

Initial validators receive allocations from the **Community Rewards pool** (80B Ϙ total):
- 5 validators: 8B Ϙ each
- Distributed over 4 years

Future validator economics determined by community governance.

## For Merchants

### Accept Koppa Payments

1. **Generate Payment Address**
   ```bash
   sumchain-wallet new --label "Store Cash Register"
   ```

2. **Display QR Code**
   ```bash
   sumchain-wallet qr 0xYOUR_ADDRESS
   # Customer scans and sends payment
   ```

3. **Monitor Payments**
   ```typescript
   const provider = new Provider('https://mainnet.sumchain.org');

   // Subscribe to new transactions
   provider.subscribe('transactions', (tx) => {
     if (tx.to === YOUR_ADDRESS) {
       console.log(`Received ${formatKoppa(tx.amount)} from ${tx.from}`);
       // Payment received! Ship order.
     }
   });
   ```

4. **Instant Finality**
   - No waiting for confirmations
   - Payment is final in 3-5 seconds
   - No chargebacks!

### Payment Flow Example

```
Customer → Scans QR → Wallet App → Broadcast TX → 3 seconds → Confirmed!
                                                              ↓
                                         Merchant notification
                                         "Payment received: 25 Ϙ"
```

## Network Information

### Mainnet

- **Chain ID**: 1
- **Genesis**: December 20, 2025 00:00:00 UTC
- **RPC Endpoint**: https://mainnet.sumchain.org (TBD)
- **Explorer**: https://explorer.sumchain.org (TBD)

### Testnet

- **Chain ID**: 9999
- **RPC Endpoint**: https://testnet.sumchain.org (TBD)
- **Faucet**: https://faucet.sumchain.org (TBD)

## Economics at a Glance

### Supply & Distribution

- **Total Supply**: 800,000,000,000 Ϙ (800 billion)
- **Per Person**: ~100 Ϙ (for 8 billion people)
- **Initial Circulating**: ~680 billion Ϙ (120B locked in vesting)

| Allocation | Amount | % |
|------------|--------|---|
| Foundation | 400B Ϙ | 50% |
| Ecosystem | 160B Ϙ | 20% |
| Team (vesting) | 120B Ϙ | 15% |
| Community | 80B Ϙ | 10% |
| Liquidity | 40B Ϙ | 5% |

### Transaction Economics

- **Fee**: 0.001 Ϙ per transaction (flat, not percentage)
- **Fee destination**: Burned (deflationary)
- **Daily burn** (at capacity): 86,400 Ϙ/day

### Value Examples

If 1 Ϙ = $1 USD:
- Coffee: $5 → 5 Ϙ
- Lunch: $12 → 12 Ϙ
- Weekly groceries: $100 → 100 Ϙ
- Transaction fee: $0.001 (0.1¢)

## Use Cases

### ✅ What SUM Chain is Great For

- **Everyday purchases**: Coffee, groceries, dining
- **Peer-to-peer transfers**: Split bills, gifts, allowances
- **Remittances**: Send money globally in seconds
- **Micropayments**: Content tips, donations
- **Cross-border commerce**: No currency exchange delays
- **Unbanked access**: No bank account required

### ❌ What SUM Chain is NOT For (Currently)

- **Complex smart contracts**: Use Ethereum
- **NFTs**: Use Solana or Polygon
- **DeFi protocols**: Use Ethereum or BSC
- **Store of value hoarding**: Use Bitcoin

**SUM Chain's focus**: Simple, fast, cheap peer-to-peer cash for everyday use.

## Performance Benchmarks

| Metric | Value |
|--------|-------|
| Transactions per second | 1,000-2,500 |
| Block time | 3-5 seconds |
| Finality | Immediate |
| Transaction latency | <5 seconds |
| Fee cost | 0.001 Ϙ |
| Daily capacity | 86.4M transactions |

### Comparison

| Chain | TPS | Finality | Fee |
|-------|-----|----------|-----|
| **SUM Chain** | 1000+ | 3-5s | 0.001 Ϙ |
| Bitcoin | 7 | 60 min | $1-50 |
| Ethereum | 30 | 12 min | $1-100 |
| Visa | 65,000 | 2-3 days | 2-3% |

## Resources

### Documentation
- [Production Checklist](production-checklist.md)
- [Economic Model](economic-model.md)
- [BFT Consensus](bft-consensus.md)
- [Security Overview](security-overview.md)
- [Performance Guide](performance-guide.md)

### SDK & Tools
- [TypeScript SDK](../sdk/typescript/README.md)
- [Block Explorer](../explorer/README.md)
- [CLI Wallet](../README.md#wallet-usage)

### Community
- Discord: TBD
- Twitter: TBD
- GitHub: https://github.com/sumchain/sumchain
- Forum: TBD

## FAQ

### Is SUM Chain decentralized?

Yes! SUM Chain uses **Byzantine Fault Tolerant (BFT) consensus** with:
- 5+ validators distributed globally
- Open validator participation (governance)
- No single point of control

### How is this different from Bitcoin?

| Feature | Bitcoin | SUM Chain |
|---------|---------|-----------|
| Purpose | Store of value | Daily transactions |
| Supply | 21 million | 800 billion |
| Block time | 10 minutes | 3-5 seconds |
| Finality | ~60 minutes | Immediate |
| Fee | $1-50 | ~$0.001 |
| TPS | ~7 | 1000+ |

**Bitcoin** = Digital gold, long-term savings
**SUM Chain** = Digital cash, everyday spending

### Why 800 billion supply?

Designed for **8+ billion people globally**:
- ~100 Ϙ per person
- Whole number pricing (5 Ϙ coffee, not 0.00005)
- Psychological comfort with holdings
- Room for growth and adoption

See [Economic Model](economic-model.md) for detailed analysis.

### Is my transaction really instant?

**Yes!** BFT consensus provides:
- 3-5 second block time
- **Immediate finality** (no confirmations needed)
- No risk of transaction reversal

Unlike Bitcoin (60 min) or Ethereum (12 min), SUM Chain transactions are **final immediately**.

### What if I lose my keys?

**Keys are unrecoverable** - this is the tradeoff for decentralization.

**Best practices**:
- Write down seed phrase on paper
- Store in safe/secure location
- Consider multi-signature for large amounts
- Test recovery process with small amount

### Can I run a validator?

Currently, the validator set is limited to maintain performance. Future expansion via community governance.

**To apply**:
1. Meet hardware requirements
2. Demonstrate technical expertise
3. Apply to SUM Chain Foundation
4. Community vote for approval

### Where can I buy Koppa?

**Post-mainnet launch**:
- DEX liquidity pools (Uniswap-style)
- Centralized exchanges (TBD)
- Direct P2P transactions

**Price discovery**: Market-driven from genesis.

---

**Ready to get started?** Join the future of peer-to-peer cash!

**Questions?** Open an issue on [GitHub](https://github.com/sumchain/sumchain) or join our Discord (TBD).

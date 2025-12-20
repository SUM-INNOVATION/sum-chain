# Mainnet Genesis Configuration

This document describes the SUM Chain mainnet genesis configuration and launch parameters.

## Network Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Chain ID | 1 | Mainnet chain identifier |
| Genesis Time | 2025-12-20 00:00:00 UTC | Network launch timestamp |
| Block Time | 3000 ms | 3 seconds per block |
| Max Block Size | 2 MB | Maximum block size in bytes |
| Max Transactions | 2000 | Maximum transactions per block |
| Minimum Fee | 0.001 Ϙ | Minimum transaction fee (1,000,000 base units) |

## Total Supply

**800,000,000,000 Ϙ (800 billion Koppa)**

### Supply Design for Global P2P Cash

SUM Chain is designed as a **global peer-to-peer cash system** for Earth's 8+ billion people. The supply is intentionally large to ensure:

- **Psychological pricing**: Whole number amounts for everyday transactions
- **Per-capita allocation**: ~100 Ϙ per person globally if evenly distributed
- **Micro-transactions**: Support for small payments without fractional decimals
- **Divisibility**: 9 decimals provide precision down to 0.000000001 Ϙ when needed

**Daily transaction capacity**: With 1000+ TPS and 3-second blocks:
- 86,400,000 transactions per day
- ~10 transactions per person per day (for 8B people at full adoption)

## Token Distribution

| Allocation | Amount (Ϙ) | Percentage | Address Placeholder |
|------------|-----------|------------|---------------------|
| Foundation Reserve | 400,000,000,000 | 50% | `FOUNDATION_ADDRESS_PLACEHOLDER` |
| Ecosystem Fund | 160,000,000,000 | 20% | `ECOSYSTEM_FUND_PLACEHOLDER` |
| Team (Vesting) | 120,000,000,000 | 15% | `TEAM_VESTING_PLACEHOLDER` |
| Community Rewards | 80,000,000,000 | 10% | `COMMUNITY_REWARDS_PLACEHOLDER` |
| Liquidity Pool | 40,000,000,000 | 5% | `LIQUIDITY_POOL_PLACEHOLDER` |
| **TOTAL** | **800,000,000,000** | **100%** | |

### Allocation Details

1. **Foundation Reserve (50%)**
   - Long-term protocol development
   - Network operations and maintenance
   - Strategic partnerships
   - Emergency reserve fund

2. **Ecosystem Fund (20%)**
   - Developer grants
   - Infrastructure incentives
   - DApp funding
   - Public goods funding

3. **Team Vesting (15%)**
   - 4-year linear vesting
   - 1-year cliff
   - Core team and advisors

4. **Community Rewards (10%)**
   - Validator rewards
   - Bug bounties
   - Community contests
   - Early adopter incentives

5. **Liquidity Pool (5%)**
   - DEX liquidity
   - Market making
   - Initial exchange listings

## Initial Validator Set

The mainnet will launch with 5 geographically distributed validators:

| Validator | Location | Organization |
|-----------|----------|--------------|
| Validator 1 | North America | TBD |
| Validator 2 | Europe | TBD |
| Validator 3 | Asia | TBD |
| Validator 4 | South America | TBD |
| Validator 5 | Oceania | TBD |

**Selection Criteria:**
- Technical expertise and infrastructure
- Geographic distribution
- Reputation and track record
- Commitment to network decentralization

## Vesting Schedule

### Team Allocation (120,000,000,000 Ϙ)

| Period | Unlock | Cumulative |
|--------|--------|------------|
| Month 0-12 | 0 Ϙ (Cliff) | 0% |
| Month 13 | 2,500,000,000 Ϙ | 2.08% |
| Month 14-48 | 2,500,000,000 Ϙ/month | 100% at Month 48 |

**Vesting Formula:** After 1-year cliff, linear unlock of 2.5 billion Ϙ per month over remaining 36 months

### Foundation & Ecosystem

No hard vesting requirements, but governed by:
- Multi-signature wallet (3-of-5)
- On-chain transparency
- Community oversight through governance proposals

## Genesis File Generation

Before mainnet launch, replace all placeholders:

```bash
# 1. Generate validator keys
for i in {1..5}; do
    sumchain-wallet keygen --output validator$i.key
    sumchain-wallet pubkey --key validator$i.key > validator$i.pub
done

# 2. Generate allocation addresses
sumchain-wallet keygen --output foundation.key
sumchain-wallet keygen --output ecosystem.key
sumchain-wallet keygen --output team.key
sumchain-wallet keygen --output community.key
sumchain-wallet keygen --output liquidity.key

# 3. Extract addresses
sumchain-wallet address --key foundation.key > addresses/foundation.txt
sumchain-wallet address --key ecosystem.key > addresses/ecosystem.txt
sumchain-wallet address --key team.key > addresses/team.txt
sumchain-wallet address --key community.key > addresses/community.txt
sumchain-wallet address --key liquidity.key > addresses/liquidity.txt

# 4. Update genesis file with real values
# Replace placeholders in mainnet_genesis.json
```

## Security Considerations

### Key Management

1. **Validator Keys**
   - Generated on air-gapped machines
   - Stored in hardware security modules (HSM)
   - Backup encrypted and stored in multiple secure locations
   - Key ceremony with witnesses

2. **Allocation Keys**
   - Multi-signature wallets for Foundation and Ecosystem
   - Hardware wallet storage
   - Distributed key holders
   - Regular security audits

### Launch Checklist

- [ ] All validator infrastructure provisioned and tested
- [ ] Validator keys generated securely
- [ ] Allocation addresses generated and verified
- [ ] Genesis file reviewed by all validators
- [ ] Bootstrap nodes configured and tested
- [ ] Monitoring infrastructure deployed
- [ ] Incident response plan documented
- [ ] Communication channels established
- [ ] Block explorer ready
- [ ] RPC endpoints load tested
- [ ] Security audit completed
- [ ] Backup and disaster recovery tested

## Network Bootstrapping

### Bootstrap Nodes

Operators will run at least 3 bootstrap nodes for peer discovery:

```toml
# Bootstrap node 1
external_address = "/dns4/boot1.sumchain.io/tcp/30303"

# Bootstrap node 2
external_address = "/dns4/boot2.sumchain.io/tcp/30303"

# Bootstrap node 3
external_address = "/dns4/boot3.sumchain.io/tcp/30303"
```

### Launch Sequence

1. **T-24h**: Final genesis file distribution to validators
2. **T-2h**: Validators start nodes in sync-only mode
3. **T-30m**: Final connectivity checks
4. **T-15m**: Validators switch to consensus mode
5. **T-0**: Genesis time reached, block production begins
6. **T+1h**: Public RPC endpoints enabled
7. **T+24h**: Full network health assessment

## Post-Launch

### First 7 Days

- 24/7 monitoring of all validators
- Daily validator coordination calls
- Immediate response to any issues
- Public status updates every 6 hours

### First 30 Days

- Weekly network health reports
- Community AMA sessions
- Validator performance review
- Initial governance proposals

### First 90 Days

- Ecosystem fund first disbursements
- Community rewards program launch
- Exchange listing preparations
- Network upgrade planning

## Governance

Initial governance will be conducted through:
- Validator consensus (for protocol upgrades)
- Foundation oversight (for fund allocations)
- Community feedback (via Discord, forums)

Long-term: On-chain governance to be implemented in Phase 2.

## Contact

- **Technical Issues**: tech@sumchain.io
- **Validator Support**: validators@sumchain.io
- **General Inquiries**: hello@sumchain.io
- **Emergency Hotline**: TBD

## References

- [Operator Guide](../docs/operator-guide.md)
- [API Reference](../docs/api-reference.md)
- [Security Audit Report](../docs/security-audit.md) (TBD)

# SUM Chain Economic Model

This document explains the economic design of SUM Chain and the Koppa (Ϙ) currency.

## Design Philosophy

SUM Chain is designed as **global peer-to-peer electronic cash** for everyday transactions worldwide. The economic model prioritizes:

1. **Global accessibility**: Supply sized for 8+ billion people
2. **Psychological simplicity**: Whole number amounts for common purchases
3. **Low barriers**: Minimal fees and fast finality
4. **Long-term sustainability**: Predictable supply with no inflation

## Total Supply

### 800,000,000,000 Ϙ (800 Billion Koppa)

**Fixed supply** - No inflation, no mining rewards, all tokens minted at genesis.

### Why 800 Billion?

With Earth's population at 8+ billion people:

- **~100 Ϙ per person** if evenly distributed globally
- Enables **whole number pricing** for everyday items
- Supports **psychological comfort** - people prefer owning "100 Ϙ" vs "0.00001 BTC"

### Comparison to Other Cryptocurrencies

| Currency | Total Supply | Supply per Person (8B) | Typical Transaction |
|----------|--------------|------------------------|---------------------|
| **Koppa (Ϙ)** | 800 billion | ~100 Ϙ | 5-50 Ϙ |
| Bitcoin (BTC) | 21 million | 0.002625 BTC | 0.0001-0.001 BTC |
| Ethereum (ETH) | ~120 million | 0.015 ETH | 0.01-0.1 ETH |
| Dogecoin (DOGE) | ~140 billion | ~17.5 DOGE | 10-100 DOGE |

**Koppa provides the sweet spot**: Large enough for whole numbers, small enough to feel valuable.

## Use Cases & Pricing Examples

### Coffee Shop
- **Espresso**: 3 Ϙ
- **Latte**: 5 Ϙ
- **Sandwich**: 8 Ϙ

### Grocery Store
- **Milk (1L)**: 2 Ϙ
- **Bread**: 3 Ϙ
- **Weekly groceries**: 50-100 Ϙ

### Services
- **Haircut**: 15 Ϙ
- **Movie ticket**: 10 Ϙ
- **Monthly phone bill**: 40 Ϙ

### Peer-to-Peer Transfers
- **Send to friend**: 10 Ϙ
- **Split dinner bill**: 25 Ϙ each
- **International remittance**: 200 Ϙ

**Transaction fee**: 0.001 Ϙ (essentially negligible)

## Transaction Capacity

### Current Performance

- **Throughput**: 1,000+ TPS sustained
- **Block time**: 3-5 seconds
- **Finality**: Depth-based (6 block confirmations, PoA consensus)

### Daily Capacity

```
1,000 TPS × 86,400 seconds/day = 86,400,000 transactions per day
```

### Global Scale

At full adoption (8 billion people):

```
86.4M tx/day ÷ 8B people = ~10.8 transactions per person per day
```

**This supports**:
- Morning coffee purchase
- Lunch payment
- Afternoon snack
- Dinner with friends
- Online shopping
- Bill payments
- P2P transfers
- Subscription services
- Transportation
- Miscellaneous purchases

### Comparison to Traditional Systems

| System | Peak TPS | Daily Capacity | Notes |
|--------|----------|----------------|-------|
| **SUM Chain** | 1,000-2,500 | 86-216M tx/day | ~18s finality (6 blocks) |
| Visa | ~65,000 | 5.6B tx/day | 150M actual average |
| Mastercard | ~50,000 | 4.3B tx/day | Settlement in days |
| Bitcoin | ~7 | 600K tx/day | 60 min finality |
| Ethereum | ~30 | 2.6M tx/day | 12 min finality |

**SUM Chain is positioned** between current crypto (too slow) and credit cards (centralized), optimized for global P2P cash.

## Fee Economics

### Transaction Fees

**Minimum fee**: `min_fee` is a chain parameter. On live mainnet it is **1,000 base units = 0.000001 Ϙ** (verified 2026-07-02 at height 8,183,329 via `chain_getChainParams`). `0.001 Ϙ` is a typical, comfortable fee used in the worked examples below, not the protocol minimum.

The illustrative fiat figures below are hypothetical (no exchange rate is implied or endorsed):
- **If 1 Ϙ = $1**: a 0.001 Ϙ fee is $0.001 (0.1¢).
- **If 1 Ϙ = $10**: a 0.001 Ϙ fee is $0.01 (1¢).
- **If 1 Ϙ = $0.10**: a 0.001 Ϙ fee is $0.0001 (0.01¢).

### Fee Distribution

Transaction fees are **paid to the block proposer** — the validator who creates the block. This directly incentivizes validators to participate in block production and maintain network uptime.

- All fees from transactions included in a block go to the proposing validator
- Fee revenue scales with network usage, aligning validator incentives with network growth
- No fees are burned; the total supply is only reduced by lost/inaccessible coins

### Validator Economics

Validators **earn transaction fees** from every block they propose. The block proposer receives all fees collected in their block. Additional funding sources include:

- **Genesis allocation**: Validators funded from Community Rewards pool (40B Ϙ)
- **Network grants**: Foundation provides operational support
- **Delegation distributions**: Staking rewards claimable by delegators

**Rationale**: Paying fees to validators creates a sustainable economic incentive for block production without requiring inflation or new token issuance.

## Token Distribution & Governance

### Allocation Breakdown

| Pool | Amount (Ϙ) | % | Purpose |
|------|-----------|---|---------|
| Foundation | 400B | 50% | Long-term development, operations |
| Ecosystem | 160B | 20% | Grants, infrastructure, DApps |
| Team | 120B | 15% | Core team (4-year vesting) |
| Community | 80B | 10% | Validators, bug bounties, rewards |
| Liquidity | 40B | 5% | DEX liquidity, exchanges |

### Foundation Reserve (400B Ϙ)

**Purpose**: Long-term sustainability of the protocol

**Governance**: 3-of-5 multisig with transparent on-chain activity

**Use cases**:
- Protocol upgrades and development
- Security audits and bug bounties
- Emergency network support
- Strategic partnerships
- Research & development
- Public goods funding

### Ecosystem Fund (160B Ϙ)

**Purpose**: Bootstrap the SUM Chain ecosystem

**Distribution**:
- **Developer grants**: 80B Ϙ (50%)
- **Infrastructure**: 40B Ϙ (25%)
- **DApp funding**: 32B Ϙ (20%)
- **Public goods**: 8B Ϙ (5%)

**Grant examples**:
- Wallet development: 1-10B Ϙ
- DEX deployment: 5-20B Ϙ
- Payment processors: 2-15B Ϙ
- Open-source tooling: 0.5-5B Ϙ

### Team Vesting (120B Ϙ)

**Vesting schedule**:
- **Cliff**: 12 months (0 tokens)
- **Linear**: 36 months after cliff
- **Monthly unlock**: 2.5B Ϙ/month

**Rationale**: Aligns team incentives with long-term success, prevents dumping.

### Community Rewards (80B Ϙ)

**Purpose**: Incentivize network participation

**Allocation**:
- **Validator operations**: 40B Ϙ (50%)
- **Bug bounty program**: 20B Ϙ (25%)
- **Community contests**: 12B Ϙ (15%)
- **Early adopters**: 8B Ϙ (10%)

**Validator rewards**:
- 5 initial validators: 8B Ϙ each
- Future validators: Community governance

**Bug bounties**:
- Critical: Up to 50,000 Ϙ
- High: Up to 10,000 Ϙ
- Medium: Up to 2,000 Ϙ
- Low: Up to 500 Ϙ

### Liquidity Pool (40B Ϙ)

**Purpose**: Bootstrap trading and price discovery

**Allocation**:
- **DEX liquidity**: 24B Ϙ (60%)
- **Market making**: 12B Ϙ (30%)
- **Exchange listings**: 4B Ϙ (10%)

**DEX pairs**:
- Ϙ/USDC: 10B Ϙ
- Ϙ/ETH: 8B Ϙ
- Ϙ/BTC: 6B Ϙ

## Comparison: SUM Chain vs Traditional Finance

### Traditional Banking

**Bank transfer**:
- Fee: $15-50 international, $0-5 domestic
- Time: 1-5 business days
- Finality: 2-3 days settlement
- Access: Requires bank account, ID, credit check

**SUM Chain transfer**:
- Fee: 0.001 Ϙ (~$0.001-0.01)
- Time: 3-5 seconds
- Finality: ~18 seconds (6 block confirmations)
- Access: Just need internet connection

### Credit Cards

**Credit card payment**:
- Fee: 2-3% for merchant
- Time: Instant authorization, 2-3 days settlement
- Finality: 60+ days (chargebacks)
- Access: Requires credit history

**SUM Chain payment**:
- Fee: 0.001 Ϙ for both parties
- Time: 3-5 seconds
- Finality: ~18 seconds (no chargebacks)
- Access: No credit check needed

### Remittances (e.g., Western Union)

**Traditional remittance**:
- Fee: 5-10% of amount
- Time: Minutes to days
- Exchange rate markup: 3-5%
- Total cost: 8-15% typically

**SUM Chain remittance**:
- Fee: 0.001 Ϙ (flat, not percentage)
- Time: 3-5 seconds
- Exchange rate: Market rate (DEX)
- Total cost: <0.1% typically

## Price Discovery & Valuation

### Market Cap Scenarios

| Price per Ϙ | Market Cap | Comparable To |
|-------------|------------|---------------|
| $0.01 | $8 billion | Small cap crypto |
| $0.10 | $80 billion | Top 20 crypto |
| $1.00 | $800 billion | Top 5 crypto |
| $10.00 | $8 trillion | Gold market cap |

### Realistic Adoption Scenarios

**Conservative (Year 1)**:
- 1 million active users
- 100,000 daily transactions
- Price: $0.01-0.05 per Ϙ
- Use case: Crypto enthusiasts, early adopters

**Moderate (Year 3)**:
- 50 million active users
- 5 million daily transactions
- Price: $0.10-0.50 per Ϙ
- Use case: Regional adoption, some merchants

**Optimistic (Year 5)**:
- 500 million active users
- 50 million daily transactions
- Price: $1.00-5.00 per Ϙ
- Use case: Global adoption, mainstream use

**Mass Adoption (Year 10+)**:
- 1+ billion active users
- 100+ million daily transactions
- Price: $5.00-50.00 per Ϙ
- Use case: Primary global currency

### Velocity Considerations

Unlike store-of-value coins (Bitcoin), Koppa is designed for **high velocity**:

```
Velocity = Transaction Volume / Money Supply

Target: 1-10 transactions per token per year
Bitcoin velocity: ~1-2 transactions per year
Cash velocity: ~5-7 transactions per year
```

**Higher velocity means**:
- Lower price per transaction volume
- Better suited for commerce
- Less speculation, more usage

## Deflationary Mechanics

### Validator Fee Revenue

All transaction fees are paid to block proposers (validators), not burned:

```
At full capacity (86.4M tx/day):
- Daily fee revenue: 86,400 Ϙ
- Yearly fee revenue: 31,536,000 Ϙ
- Split among validators based on blocks proposed
```

**Fee-based validator compensation** ensures:
- Sustainable validator incentives without inflation
- Revenue scales with network adoption
- No new tokens need to be minted

### Lost Coins

Estimated lost coins over time:
- Year 1: ~0.1% (800M Ϙ)
- Year 5: ~0.5% (4B Ϙ)
- Year 10: ~1% (8B Ϙ)
- Year 50: ~5% (40B Ϙ)

**Lost coins are the only deflationary pressure** on the fixed supply, slowly creating scarcity over time.

## Monetary Policy

### No Inflation

- **Zero new issuance**: All 800B Ϙ minted at genesis
- **No mining**: PoA consensus, no block rewards
- **Staking rewards**: Available via delegation distributions (manual claim)
- **Subprotocol rewards are escrow/fee-funded, never minted**: storage PoR
  payouts (from per-file `fee_pool`) and OmniNode
  [inference settlement](../subprotocols/inference-settlement.md) rewards (from a
  funder's per-session escrow) are supply-conserving — a party is debited up
  front and the same Koppa is later credited or refunded. No subprotocol issues
  new tokens.

### Predictable Supply

Circulating supply is **always decreasing** due to:
1. Lost coins
2. Locked vesting (120B Ϙ locked for 4 years)

**Launch circulating supply**: ~680B Ϙ (800B - 120B vesting)

### Long-term Sustainability

**Concerns**: "Won't fees be too low to sustain validators?"

**Solutions**:
1. **Transaction fees**: Block proposers earn all fees from their blocks
2. **Foundation grants**: Operational support from 400B Ϙ reserve
3. **Fee market**: If network congested, fees increase naturally
4. **Value appreciation**: As Ϙ price rises, 0.001 Ϙ fee becomes more valuable

**Example**: If 1 Ϙ = $10, then 0.001 Ϙ = $0.01 per transaction
- At 86.4M tx/day: $864,000/day in fees
- Split among 5 validators: $173,000/day per validator
- Yearly per validator: $63M

## Conclusion

SUM Chain's economic model is designed for **global peer-to-peer cash**:

✅ **800 billion supply**: Sized for 8+ billion people
✅ **Whole number pricing**: Psychological comfort
✅ **Ultra-low fees**: 0.001 Ϙ per transaction
✅ **Depth-based finality**: PoA consensus (6 block confirmations)
✅ **High capacity**: 86.4M+ transactions per day
✅ **Mild deflation**: Lost coins reduce supply over time
✅ **Fixed supply**: No inflation, predictable scarcity

**Target use case**: Replace cash and payment processors for everyday transactions worldwide.

**Value proposition**: Faster, cheaper, and more accessible than traditional finance, while maintaining simplicity and psychological comfort that other cryptocurrencies lack.

---

**Document Version**: 3.0
**Last Updated**: March 2026
**Next Review**: Q3 2026

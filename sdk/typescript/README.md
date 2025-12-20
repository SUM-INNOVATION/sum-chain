# SUM Chain TypeScript SDK

Official TypeScript/JavaScript SDK for interacting with SUM Chain.

**Native Currency:** Koppa (Ϙ) with 9 decimal places

## Installation

```bash
npm install @sumchain/sdk
```

Or with yarn:

```bash
yarn add @sumchain/sdk
```

## Quick Start

```typescript
import { Provider, koppaToBaseUnits, formatKoppa } from '@sumchain/sdk';

// Connect to a node
const provider = new Provider('http://localhost:8545');

// Get account balance
const balance = await provider.getBalance('5HqX...');
console.log(formatKoppa(balance)); // "100 Ϙ"

// Get current block
const block = await provider.getLatestBlock();
console.log(`Block #${block.height}`);

// Get block height
const height = await provider.getBlockNumber();
console.log(`Current height: ${height}`);
```

## Currency Conversion

The SDK provides utilities for working with Koppa (Ϙ) amounts:

```typescript
import { koppaToBaseUnits, baseUnitsToKoppa, formatKoppa } from '@sumchain/sdk';

// Convert Koppa to base units
const baseUnits = koppaToBaseUnits("1.5");  // 1500000000n
const baseUnits2 = koppaToBaseUnits(1.5);    // 1500000000n

// Convert base units to Koppa
const koppa = baseUnitsToKoppa(1500000000n); // "1.5"

// Format for display
const formatted = formatKoppa(1500000000n);  // "1.5 Ϙ"
```

## API Reference

### Provider

#### Constructor

```typescript
const provider = new Provider('http://localhost:8545');

// Or with options
const provider = new Provider({
  url: 'http://localhost:8545',
  timeout: 30000,
  headers: {
    'Authorization': 'Bearer token'
  }
});
```

#### Methods

##### getBlockNumber()

Get the current block height.

```typescript
const height = await provider.getBlockNumber();
console.log(height); // 1234
```

##### getBlockByHeight(height)

Get block information by height.

```typescript
const block = await provider.getBlockByHeight(100);
if (block) {
  console.log(`Block #${block.height}`);
  console.log(`Hash: ${block.hash}`);
  console.log(`Transactions: ${block.tx_count}`);
}
```

##### getLatestBlock()

Get the latest block.

```typescript
const block = await provider.getLatestBlock();
console.log(`Latest block: #${block.height}`);
```

##### getBalance(address)

Get account balance in base units.

```typescript
const balance = await provider.getBalance('5HqX...');
console.log(formatKoppa(balance)); // "100 Ϙ"
```

##### getNonce(address)

Get account nonce (transaction count).

```typescript
const nonce = await provider.getNonce('5HqX...');
console.log(`Nonce: ${nonce}`);
```

##### sendRawTransaction(rawTx)

Broadcast a signed transaction.

```typescript
const txHash = await provider.sendRawTransaction('0x...');
console.log(`Transaction sent: ${txHash}`);
```

##### getTransaction(txHash)

Get transaction details.

```typescript
const tx = await provider.getTransaction('0x...');
if (tx) {
  console.log(`From: ${tx.from}`);
  console.log(`To: ${tx.to}`);
  console.log(`Amount: ${formatKoppa(tx.amount)}`);
  console.log(`Fee: ${formatKoppa(tx.fee)}`);
  console.log(`Status: ${tx.status}`);
}
```

##### getReceipt(txHash)

Get transaction receipt.

```typescript
const receipt = await provider.getReceipt('0x...');
if (receipt) {
  console.log(`Block: ${receipt.block_height}`);
  console.log(`Status: ${receipt.status}`);
  console.log(`Fee Paid: ${formatKoppa(receipt.fee_paid)}`);
}
```

##### getPendingTransactions()

Get pending transactions in mempool.

```typescript
const pending = await provider.getPendingTransactions();
console.log(`Pending: ${pending.length} transactions`);
```

##### getValidators()

Get current validator set.

```typescript
const validators = await provider.getValidators();
console.log(`Validators: ${validators.validators.length}`);
console.log(`Current proposer: ${validators.current_proposer_index}`);
```

##### getHealth()

Get node health status.

```typescript
const health = await provider.getHealth();
console.log(`Status: ${health.status}`);
console.log(`Chain ID: ${health.chain_id}`);
console.log(`Height: ${health.height}`);
console.log(`Peers: ${health.peer_count}`);
console.log(`Synced: ${health.is_synced}`);
```

##### getChainId()

Get chain ID.

```typescript
const chainId = await provider.getChainId();
console.log(`Chain ID: ${chainId}`);
```

##### waitForReceipt(txHash, timeout?, interval?)

Wait for transaction to be included in a block.

```typescript
const receipt = await provider.waitForReceipt(txHash, 60000);
console.log(`Transaction confirmed in block ${receipt.block_height}`);
```

##### waitForConfirmation(txHash, confirmations?, timeout?)

Wait for specified number of block confirmations.

```typescript
const receipt = await provider.waitForConfirmation(txHash, 3);
console.log(`Transaction has 3 confirmations`);
```

## Utility Functions

### koppaToBaseUnits(koppa)

Convert Koppa amount to base units.

```typescript
koppaToBaseUnits("1.5")    // 1500000000n
koppaToBaseUnits(1.5)      // 1500000000n
koppaToBaseUnits("0.001")  // 1000000n
```

### baseUnitsToKoppa(baseUnits)

Convert base units to Koppa.

```typescript
baseUnitsToKoppa(1500000000n)  // "1.5"
baseUnitsToKoppa("1000000000")  // "1"
baseUnitsToKoppa(1000000n)      // "0.001"
```

### formatKoppa(baseUnits)

Format base units with Koppa symbol.

```typescript
formatKoppa(1500000000n)      // "1.5 Ϙ"
formatKoppa("1000000000000")  // "1,000 Ϙ"
```

### formatNumber(value)

Format number with comma separators.

```typescript
formatNumber("1000")      // "1,000"
formatNumber("1000.5")    // "1,000.5"
formatNumber(1234567.89)  // "1,234,567.89"
```

### isValidAddress(address)

Validate address format.

```typescript
isValidAddress("5HqX...")  // true
isValidAddress("0x...")    // true
isValidAddress("invalid")  // false
```

### isValidHash(hash)

Validate transaction/block hash format.

```typescript
isValidHash("0x1234...")  // true
isValidHash("invalid")     // false
```

## Constants

```typescript
import {
  KOPPA_UNIT,      // 1000000000n
  KOPPA_SYMBOL,    // "Ϙ"
  KOPPA_NAME,      // "Koppa"
  KOPPA_DECIMALS   // 9
} from '@sumchain/sdk';
```

## Examples

### Query Account Information

```typescript
import { Provider, formatKoppa } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');
const address = '5HqX...';

// Get balance
const balance = await provider.getBalance(address);
console.log(`Balance: ${formatKoppa(balance)}`);

// Get nonce
const nonce = await provider.getNonce(address);
console.log(`Nonce: ${nonce}`);
```

### Monitor New Blocks

```typescript
import { Provider } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');

async function monitorBlocks() {
  let lastHeight = await provider.getBlockNumber();

  setInterval(async () => {
    const currentHeight = await provider.getBlockNumber();

    if (currentHeight > lastHeight) {
      const block = await provider.getBlockByHeight(currentHeight);
      console.log(`New block #${block.height}`);
      console.log(`  Hash: ${block.hash}`);
      console.log(`  Transactions: ${block.tx_count}`);
      lastHeight = currentHeight;
    }
  }, 3000); // Poll every 3 seconds
}

monitorBlocks();
```

### Send Transaction and Wait for Confirmation

```typescript
import { Provider } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');

// Sign transaction offline (using wallet CLI or other tool)
const signedTx = '0x...';

// Send transaction
const txHash = await provider.sendRawTransaction(signedTx);
console.log(`Transaction sent: ${txHash}`);

// Wait for receipt
const receipt = await provider.waitForReceipt(txHash);
console.log(`Confirmed in block ${receipt.block_height}`);
console.log(`Status: ${receipt.status}`);

// Or wait for multiple confirmations
const finalReceipt = await provider.waitForConfirmation(txHash, 3);
console.log(`Transaction has 3 confirmations`);
```

### Check Node Health

```typescript
import { Provider } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');

const health = await provider.getHealth();

if (health.status === 'healthy' && health.is_synced) {
  console.log('Node is healthy and synced');
  console.log(`Height: ${health.height}`);
  console.log(`Peers: ${health.peer_count}`);
} else {
  console.log('Node is not ready');
}
```

### List Validators

```typescript
import { Provider } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');

const validatorSet = await provider.getValidators();

console.log(`Validators at height ${validatorSet.current_height}:`);
validatorSet.validators.forEach((v, i) => {
  const marker = v.is_current_proposer ? ' ← current proposer' : '';
  console.log(`[${i}] ${v.address}${marker}`);
});
```

## TypeScript Support

The SDK is written in TypeScript and includes full type definitions:

```typescript
import type {
  BlockInfo,
  TransactionInfo,
  TransactionReceipt,
  ValidatorSetInfo,
  HealthResponse
} from '@sumchain/sdk';

const block: BlockInfo = await provider.getLatestBlock();
const tx: TransactionInfo | null = await provider.getTransaction(txHash);
```

## Error Handling

```typescript
import { Provider } from '@sumchain/sdk';

const provider = new Provider('http://localhost:8545');

try {
  const balance = await provider.getBalance(address);
  console.log(formatKoppa(balance));
} catch (error) {
  if (error instanceof Error) {
    console.error(`Error: ${error.message}`);
  }
}
```

## Browser Support

The SDK works in both Node.js and browser environments. For browsers, you may need to polyfill `fetch` for older browsers.

```html
<script type="module">
  import { Provider, formatKoppa } from 'https://cdn.skypack.dev/@sumchain/sdk';

  const provider = new Provider('http://localhost:8545');
  const balance = await provider.getBalance('5HqX...');
  console.log(formatKoppa(balance));
</script>
```

## License

MIT

## Links

- [SUM Chain Repository](https://github.com/sumchain/sum-chain)
- [API Documentation](https://docs.sumchain.io/api)
- [Operator Guide](https://docs.sumchain.io/operator-guide)

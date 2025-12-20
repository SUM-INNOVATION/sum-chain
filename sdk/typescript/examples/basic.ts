/**
 * Basic example of using the SUM Chain TypeScript SDK
 */

import { Provider, formatKoppa, koppaToBaseUnits } from '../src';

async function main() {
  // Connect to local node
  const provider = new Provider('http://localhost:8545');

  console.log('=== SUM Chain SDK Example ===\n');

  // 1. Check node health
  console.log('1. Checking node health...');
  const health = await provider.getHealth();
  console.log(`   Status: ${health.status}`);
  console.log(`   Chain ID: ${health.chain_id}`);
  console.log(`   Height: ${health.height}`);
  console.log(`   Peers: ${health.peer_count}`);
  console.log(`   Synced: ${health.is_synced}\n`);

  // 2. Get latest block
  console.log('2. Getting latest block...');
  const block = await provider.getLatestBlock();
  console.log(`   Block #${block.height}`);
  console.log(`   Hash: ${block.hash}`);
  console.log(`   Transactions: ${block.tx_count}`);
  console.log(`   Proposer: ${block.proposer}\n`);

  // 3. Get validators
  console.log('3. Getting validators...');
  const validators = await provider.getValidators();
  console.log(`   Total validators: ${validators.validators.length}`);
  console.log(`   Current proposer index: ${validators.current_proposer_index}`);
  validators.validators.forEach((v, i) => {
    const marker = v.is_current_proposer ? ' ← current proposer' : '';
    console.log(`   [${i}] ${v.address}${marker}`);
  });
  console.log();

  // 4. Query account balance
  const testAddress = 'YOUR_ADDRESS_HERE';
  if (testAddress !== 'YOUR_ADDRESS_HERE') {
    console.log('4. Getting account balance...');
    const balance = await provider.getBalance(testAddress);
    console.log(`   Address: ${testAddress}`);
    console.log(`   Balance: ${formatKoppa(balance)}`);
    console.log(`   Raw: ${balance} base units\n`);

    const nonce = await provider.getNonce(testAddress);
    console.log(`   Nonce: ${nonce}\n`);
  } else {
    console.log('4. Skipping balance query (set testAddress first)\n');
  }

  // 5. Get pending transactions
  console.log('5. Getting pending transactions...');
  const pending = await provider.getPendingTransactions();
  console.log(`   Pending: ${pending.length} transactions`);
  if (pending.length > 0) {
    pending.slice(0, 3).forEach((tx) => {
      console.log(`   - ${tx.hash.slice(0, 16)}...`);
      console.log(`     ${tx.from.slice(0, 16)}... → ${tx.to.slice(0, 16)}...`);
      console.log(`     Amount: ${formatKoppa(tx.amount)}, Fee: ${formatKoppa(tx.fee)}`);
    });
  }
  console.log();

  // 6. Currency conversion examples
  console.log('6. Currency conversion examples...');
  const amounts = ['1', '1.5', '0.001', '1000'];
  amounts.forEach((amt) => {
    const baseUnits = koppaToBaseUnits(amt);
    const formatted = formatKoppa(baseUnits);
    console.log(`   ${amt} Koppa = ${baseUnits} base units = ${formatted}`);
  });
}

main().catch(console.error);

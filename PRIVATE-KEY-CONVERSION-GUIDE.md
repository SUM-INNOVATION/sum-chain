# Private Key Conversion Guide

Convert your SUM Chain wallet private key to hex format for SDK usage.

---

## Quick Reference

Your wallet stores private keys in **encrypted format**. SDKs typically need them in **hex format** (`0x...`).

**Formats**:
- **Encrypted keystore** (JSON file): Argon2 + AES-256-GCM encrypted
- **Raw array** (JSON file): `[1,2,3,...]` (32 numbers)
- **Hex format** (SDK): `0x1234567890abcdef...` (64 hex characters)

---

## Method 1: Using the Export Script (Recommended)

### Step 1: Add Binary to Cargo.toml

Edit `Cargo.toml` in the workspace root and add to `[workspace]` section:

```toml
[[bin]]
name = "export_private_key"
path = "scripts/export_private_key.rs"
```

### Step 2: Build and Run

```bash
cd /Users/1mle0wang/Library/Mobile\ Documents/com~apple~CloudDocs/sum-chain

# Build the export tool
cargo build --release --bin export_private_key

# Export your private key
./target/release/export_private_key --key keys/sum-hypothesis-institute.json
```

### Step 3: Enter Password

```
🔐 Enter keystore password: [your password]
✅ Successfully decrypted private key

🔑 Private Key (hex format):
0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

⚠️  WARNING: Keep this private key secure!
   Never share it or commit it to version control.
   Anyone with this key has full access to your account.
```

**Copy the `0x...` value** - this is your hex-formatted private key.

---

## Method 2: Manual Conversion (Raw Array Format)

If your keystore is in raw array format (unencrypted dev key):

### Input Format

```json
[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]
```

### Conversion (JavaScript/Node.js)

```javascript
const fs = require('fs');

// Read the array from file
const keyArray = JSON.parse(fs.readFileSync('keys/your-key.json', 'utf8'));

// Convert to hex
const hexKey = '0x' + Buffer.from(keyArray).toString('hex');

console.log('Private Key (hex):', hexKey);
```

### Conversion (Python)

```python
import json

# Read the array from file
with open('keys/your-key.json') as f:
    key_array = json.load(f)

# Convert to hex
hex_key = '0x' + bytes(key_array).hex()

print('Private Key (hex):', hex_key)
```

---

## Method 3: Manual Decryption (Encrypted Keystore)

If you need to decrypt manually without the export script:

### Encrypted Keystore Format

```json
{
  "version": 1,
  "public_key": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
  "address": "3yZe7d1hKWF2Fq8N9Zu4Qv6qR8mT5pL7",
  "salt": "1234567890abcdef...",
  "nonce": "fedcba9876543210...",
  "ciphertext": "abcdef1234567890..."
}
```

### Decryption Steps (Node.js)

```javascript
const crypto = require('crypto');
const argon2 = require('argon2');
const { decrypt } = require('crypto');

async function decryptKeystore(keystorePath, password) {
  const fs = require('fs');
  const keystore = JSON.parse(fs.readFileSync(keystorePath, 'utf8'));

  // Decode hex values
  const salt = Buffer.from(keystore.salt, 'hex');
  const nonce = Buffer.from(keystore.nonce, 'hex');
  const ciphertext = Buffer.from(keystore.ciphertext, 'hex');

  // Derive key using Argon2
  const key = await argon2.hash(password, {
    salt,
    raw: true,
    hashLength: 32,
    type: argon2.argon2id
  });

  // Decrypt using AES-256-GCM
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  const authTag = ciphertext.slice(-16); // Last 16 bytes are auth tag
  const encrypted = ciphertext.slice(0, -16);

  decipher.setAuthTag(authTag);

  let privateKey = decipher.update(encrypted);
  privateKey = Buffer.concat([privateKey, decipher.final()]);

  return '0x' + privateKey.toString('hex');
}

// Usage
decryptKeystore('keys/sum-hypothesis-institute.json', 'your-password')
  .then(hexKey => console.log('Private Key:', hexKey))
  .catch(err => console.error('Decryption failed:', err));
```

---

## Security Best Practices

### 1. Never Expose Private Keys

**NEVER**:
- ❌ Commit private keys to version control
- ❌ Share private keys in chat/email
- ❌ Store private keys in plain text files
- ❌ Include private keys in screenshots
- ❌ Log private keys to console in production

**ALWAYS**:
- ✅ Use environment variables for SDK keys
- ✅ Encrypt keystores with strong passwords
- ✅ Use hardware wallets for high-value accounts
- ✅ Keep backups in secure, encrypted storage

### 2. Environment Variables

When using the hex key in your SDK:

```bash
# .env file (add to .gitignore!)
PRIVATE_KEY=0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

```javascript
// Load from environment
require('dotenv').config();
const privateKey = process.env.PRIVATE_KEY;

// Use in SDK
const signer = new Wallet(privateKey, provider);
```

### 3. .gitignore

Ensure your `.gitignore` includes:

```gitignore
# Private keys and keystores
*.key
*.pem
keys/
.env
.env.local

# Wallet files
wallet.json
keystore.json
*-keystore.json
```

---

## Verification

After conversion, verify the address matches:

### Using the Wallet Tool

```bash
# Get address from keystore (for comparison)
./target/release/sumchain-wallet address --key keys/sum-hypothesis-institute.json
```

### Using SDK (JavaScript)

```javascript
const { Wallet } = require('ethers');

const privateKey = '0x1234567890abcdef...';
const wallet = new Wallet(privateKey);

console.log('Address:', wallet.address);
// Should match the address from your keystore
```

### Using SDK (Python)

```python
from eth_account import Account

private_key = '0x1234567890abcdef...'
account = Account.from_key(private_key)

print('Address:', account.address)
# Should match the address from your keystore
```

---

## Troubleshooting

### Error: "Invalid private key length"

**Cause**: Private key is not exactly 32 bytes (64 hex characters without `0x`)

**Fix**: Ensure conversion preserves all 32 bytes:
```javascript
// Correct: 64 hex chars
'0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'

// Wrong: Missing characters
'0x1234567890abcdef...'
```

### Error: "Decryption failed - incorrect password"

**Cause**: Wrong password or corrupted keystore

**Fix**:
1. Double-check password (case-sensitive)
2. Verify keystore file is not corrupted
3. Restore from backup if needed

### Error: "Address mismatch"

**Cause**: Different key derivation or address format

**Fix**:
- SUM Chain uses **Ed25519** + **BLAKE3** for addresses
- Ethereum uses **secp256k1** + **Keccak-256**
- **They are NOT compatible** - use SUM Chain's address format (base58 or hex)

### Hex Format Issues

**Problem**: SDK expects `0x` prefix

```javascript
// Correct
const privateKey = '0x1234567890abcdef...';

// Wrong - missing 0x prefix
const privateKey = '1234567890abcdef...';

// Fix
const privateKey = '0x' + rawHex;
```

---

## Format Comparison

| Format | Example | Use Case |
|--------|---------|----------|
| **Encrypted Keystore** | `{"version":1,"ciphertext":"..."}` | Secure storage, wallet files |
| **Raw Array** | `[1,2,3,4,...]` | Dev keys, testing (NOT secure) |
| **Hex String** | `0x1234567890abcdef...` | SDK integration, API calls |
| **Base58** | `5FHneW46xGXgs5...` | Public keys, human-readable |

---

## Example: Using with TypeScript SDK

```typescript
import { Wallet, providers } from 'ethers';

// Load from environment variable
const privateKey = process.env.PRIVATE_KEY!;

// Create provider
const provider = new providers.JsonRpcProvider('https://rpc.sum-chain.xyz');

// Create signer from private key
const signer = new Wallet(privateKey, provider);

console.log('Address:', signer.address);

// Sign and send transaction
const tx = await signer.sendTransaction({
  to: '0xRecipientAddress',
  value: ethers.utils.parseEther('1.0'), // 1 Ϙ
  gasLimit: 21000,
});

console.log('Transaction hash:', tx.hash);
await tx.wait();
console.log('Transaction confirmed!');
```

---

## Next Steps

After converting your private key:

1. **Store securely**: Use environment variables, never hardcode
2. **Test on testnet**: Verify SDK integration works before mainnet
3. **Monitor usage**: Set up logging for transaction activity
4. **Rotate keys**: Generate new keys periodically for security
5. **Backup**: Keep encrypted backups in multiple locations

---

## Summary

1. Use `export_private_key` script for easiest conversion
2. Alternatively convert manually if you have raw array format
3. Store hex key in environment variable
4. Verify address matches before using in production
5. **NEVER expose private keys** in code or logs

---

**Document Version**: 1.0
**Date**: 2026-02-01
**Status**: Production Guide
**Security Level**: CRITICAL - Handle with Care

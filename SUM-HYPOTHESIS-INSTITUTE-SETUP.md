# SUM Hypothesis Institute Technology - Setup Guide

**Institution**: SUM Hypothesis Institute Technology
**Purpose**: Register as university issuer for academic credentials (SRC-810/811/812)
**Date**: 2026-02-01

---

## Part 1: Generate Key Pair

### Step 1: Build the Wallet Tool

```bash
cd /Users/1mle0wang/Library/Mobile\ Documents/com~apple~CloudDocs/sum-chain

# Build wallet binary
cargo build --release --bin sumchain-wallet
```

### Step 2: Create Keys Directory

```bash
mkdir -p keys
```

### Step 3: Generate Keypair

```bash
# Generate encrypted keystore for SUM Hypothesis Institute
./target/release/sumchain-wallet keygen --output keys/sum-hypothesis-institute.json
```

**You will be prompted**:
```
Enter password to encrypt keystore: [Enter a strong password]
```

**Output**: Creates `keys/sum-hypothesis-institute.json` with encrypted keypair

**IMPORTANT**:
- **Save the password securely** - you'll need it to sign transactions
- **Backup the keystore file** - this is your only access to the institution's account

### Step 4: Get the Address

```bash
# View the institution's address
./target/release/sumchain-wallet address --key keys/sum-hypothesis-institute.json
```

**Expected output**:
```
Address: 0x1234567890abcdef1234567890abcdef12345678
```

**Save this address** - you'll need it for funding and registration.

---

## Part 2: Fund the Institution Account

### Required Funding

| Purpose | Amount | Notes |
|---------|--------|-------|
| **Issuer Stake** | 1000 Ϙ | Required to register as credential issuer |
| **Transaction Fees** | ~10 Ϙ | For registration transaction and initial credentials |
| **Total** | **~1010 Ϙ** | Minimum recommended funding |

**Note**: Stake is locked while registered as issuer but can be withdrawn if you unregister.

### Funding Options

#### Option A: Transfer from Existing Account

If you have an existing funded account on the chain:

```bash
# Using wallet tool (from funded account)
./target/release/sumchain-wallet sign-tx \
  --key keys/your-funded-account.json \
  --to 0x[SUM-HYPOTHESIS-ADDRESS] \
  --amount "1010 Ϙ" \
  --fee "0.001 Ϙ" \
  --nonce [YOUR_NONCE] \
  --chain-id 1

# Then broadcast the signed transaction to the network
```

#### Option B: Genesis Allocation (If Bootstrapping)

If you're setting up a new chain or have access to genesis configuration:

Edit `genesis.json`:
```json
{
  "balances": {
    "0x[SUM-HYPOTHESIS-ADDRESS]": "1010000000000000"  // 1010 Ϙ in base units
  }
}
```

#### Option C: Request from Chain Operator

Contact the chain operator to transfer funds from the treasury or validator account.

### Verify Balance

```bash
# Check balance via RPC
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_getBalance",
    "params": ["0x[SUM-HYPOTHESIS-ADDRESS]", "latest"],
    "id": 1
  }'
```

**Expected response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "0x38d7ea4c68000"  // Hex value = 1010 Ϙ in base units
}
```

---

## Part 3: Register as University Issuer

### Step 1: Prepare Registration Data

Create a JSON file with issuer details: `sum-hypothesis-registration.json`

```json
{
  "address": "0x[SUM-HYPOTHESIS-ADDRESS]",
  "name": "SUM Hypothesis Institute Technology",
  "issuer_type": "Educational",
  "jurisdictions": ["US", "US-CA"],
  "authorized_subcodes": [810, 811, 812],
  "keys": [
    {
      "key_id": "sum-hypothesis-2025-primary",
      "public_key": "[PUBLIC_KEY_BASE58]",
      "algorithm": "Ed25519",
      "valid_from": 1735689600,
      "valid_until": 0,
      "status": "Active"
    }
  ],
  "registered_at": 1735689600,
  "updated_at": 1735689600,
  "status": "Active",
  "stake_amount": "1000000000000000",
  "metadata": "{\"university_type\":\"technology_institute\",\"accreditation\":\"WASC\",\"website\":\"https://sum-hypothesis.edu\"}"
}
```

**Field Explanations**:

| Field | Value | Description |
|-------|-------|-------------|
| `address` | From Step 4 above | Institution's blockchain address |
| `name` | `"SUM Hypothesis Institute Technology"` | Official institution name |
| `issuer_type` | `"Educational"` | Must be "Educational" for universities |
| `jurisdictions` | `["US", "US-CA"]` | ISO 3166 codes for US and California |
| `authorized_subcodes` | `[810, 811, 812]` | 810=Transcript, 811=Diploma, 812=Enrollment |
| `keys[0].public_key` | Get from wallet | Base58-encoded public key |
| `stake_amount` | `"1000000000000000"` | 1000 Ϙ in base units (10^15) |
| `metadata` | JSON string | Optional institutional details |

### Step 2: Get Public Key

```bash
# Get public key in base58 format
./target/release/sumchain-wallet pubkey --key keys/sum-hypothesis-institute.json
```

**Output**:
```
Public Key: 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
```

**Copy this value** and paste into `keys[0].public_key` in the JSON above.

### Step 3: Serialize Registration Data

You need to convert the JSON to bincode format (the chain uses bincode for DocClassIssuer).

**Option A: Use Rust Script**

Create `scripts/register_issuer.rs`:

```rust
use sumchain_primitives::{
    Address, DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType,
    DocSubcode, IssuerKey, IssuerKeyStatus, Timestamp, Balance,
};

fn main() {
    let issuer_address = Address::from_base58("0x[SUM-HYPOTHESIS-ADDRESS]").unwrap();
    let public_key = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"; // From Step 2

    let issuer = DocClassIssuer {
        address: issuer_address,
        name: "SUM Hypothesis Institute Technology".to_string(),
        issuer_type: DocClassIssuerType::Educational,
        jurisdictions: vec!["US".to_string(), "US-CA".to_string()],
        authorized_subcodes: vec![
            DocSubcode::AcademicTranscript,
            DocSubcode::AcademicDiploma,
            DocSubcode::EnrollmentVerification,
        ],
        keys: vec![IssuerKey {
            key_id: "sum-hypothesis-2025-primary".to_string(),
            public_key: public_key.to_string(),
            algorithm: "Ed25519".to_string(),
            valid_from: 1735689600,
            valid_until: 0, // No expiry
            status: IssuerKeyStatus::Active,
        }],
        registered_at: 1735689600,
        updated_at: 1735689600,
        status: DocClassIssuerStatus::Active,
        stake_amount: 1_000_000_000_000_000, // 1000 Ϙ
        metadata: Some(r#"{"university_type":"technology_institute","accreditation":"WASC","website":"https://sum-hypothesis.edu"}"#.to_string()),
    };

    // Serialize to bincode
    let encoded = bincode::serialize(&issuer).unwrap();

    // Print as hex for transaction
    println!("Encoded issuer data (hex):");
    println!("{}", hex::encode(&encoded));

    // Save to file
    std::fs::write("sum-hypothesis-issuer.bin", &encoded).unwrap();
    println!("\nSaved to: sum-hypothesis-issuer.bin");
}
```

**Run**:
```bash
cargo run --bin register_issuer
```

**Output**: Hex-encoded bincode data

**Option B: Use Python with cbor2**

If you prefer Python (approximate, may need adjustment):

```python
import cbor2
import json

# Load JSON
with open('sum-hypothesis-registration.json') as f:
    data = json.load(f)

# Encode to CBOR (similar to bincode)
encoded = cbor2.dumps(data)

# Save to file
with open('sum-hypothesis-issuer.bin', 'wb') as f:
    f.write(encoded)

# Print hex
print("Hex:", encoded.hex())
```

### Step 4: Submit Registration Transaction

**Via RPC** (requires implementing custom RPC method):

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_registerIssuer",
    "params": [{
      "issuer_data": "0x[HEX_FROM_STEP_3]",
      "from": "0x[SUM-HYPOTHESIS-ADDRESS]",
      "fee": "1000000000",
      "nonce": 0
    }],
    "id": 1
  }'
```

**Via Direct Transaction** (manual construction):

```rust
use sumchain_primitives::{Transaction, TxPayload, DocClassTxData, DocClassOperation};

let tx_data = DocClassTxData {
    operation: DocClassOperation::RegisterIssuer,
    data: encoded_issuer_data, // From Step 3
};

let tx = Transaction {
    sender: issuer_address,
    nonce: 0,
    fee: 1_000_000_000, // 0.001 Ϙ transaction fee
    payload: TxPayload::DocClass(tx_data),
};

// Sign with institution's private key
let signed_tx = keypair.sign_transaction(&tx);

// Broadcast to network
```

### Step 5: Verify Registration

```bash
# Check if issuer is registered
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_getIssuer",
    "params": ["0x[SUM-HYPOTHESIS-ADDRESS]"],
    "id": 1
  }'
```

**Expected response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "0x[SUM-HYPOTHESIS-ADDRESS]",
    "name": "SUM Hypothesis Institute Technology",
    "issuer_type": "Educational",
    "status": "Active",
    "authorized_subcodes": [810, 811, 812],
    "stake_amount": "1000000000000000"
  }
}
```

---

## Part 4: Issue Your First Credential

Once registered, you can issue academic credentials.

### Example: Issue Academic Transcript (SRC-810)

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "docclass_issueAcademicCredential",
    "params": [{
      "subcode": 810,
      "subject": "0x[STUDENT_ADDRESS]",
      "content_commitment": "0x[32_BYTE_HASH]",
      "metadata": {
        "title": "Academic Transcript",
        "credential_type": "transcript",
        "issue_date": "2025-05-15",
        "attributes": [
          {"name": "academic_year", "value": "2024-2025"},
          {"name": "semester", "value": "Fall"},
          {"name": "courses_commitment", "value": "blake3:a7f2c9..."},
          {"name": "grades_commitment", "value": "blake3:1234..."},
          {"name": "student_commitment", "value": "blake3:5678..."},
          {"name": "pdf_cid", "value": "bafybeig..."}
        ]
      },
      "issued_at": 1735689600,
      "valid_from": 1735689600,
      "expires_at": 0,
      "payload_hint": "bafybeig...json",
      "issuer_signature": "0x[64_BYTE_SIG]",
      "issuer_key_id": "sum-hypothesis-2025-primary"
    }],
    "id": 1
  }'
```

**IMPORTANT**: Credentials must comply with schema validation rules (see [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md))

---

## Security Best Practices

### Key Management

1. **Store keystore file securely**
   - Use encrypted storage (e.g., encrypted USB drive, hardware security module)
   - Never commit to version control

2. **Strong password**
   - Use 20+ character passphrase
   - Store password in password manager
   - Use different password than any other system

3. **Backup strategy**
   - Keep 2-3 encrypted copies in different physical locations
   - Test recovery process periodically

4. **Key rotation**
   - Generate new key annually
   - Add new key to `keys[]` array before removing old key
   - Update credential signatures to use new key

### Operational Security

1. **Transaction signing**
   - Always verify transaction details before signing
   - Use offline signing for high-value transactions
   - Keep signing machine isolated from network when possible

2. **Monitoring**
   - Monitor issuer account balance
   - Watch for unauthorized credential issuance
   - Set up alerts for unusual activity

3. **Access control**
   - Limit who has access to keystore file and password
   - Use multi-signature for high-stakes operations
   - Implement internal approval process for credential issuance

---

## Troubleshooting

### "Insufficient balance" error

**Cause**: Account doesn't have enough Ϙ to cover stake + fees

**Fix**: Fund account with at least 1010 Ϙ (1000 stake + 10 buffer for fees)

### "Already registered" error

**Cause**: Address has already registered as issuer

**Fix**: Use `docclass_updateIssuer` to modify existing registration instead

### "Incorrect password" error

**Cause**: Wrong password when loading keystore

**Fix**: Verify password, check for typos, restore from backup if password lost

### "Issuer not authorized" when issuing credential

**Cause**: Issuer not registered for this subcode or jurisdiction

**Fix**: Update issuer registration to include required subcodes and jurisdictions

### Schema validation failures

**Cause**: Credential contains disallowed PII fields

**Fix**: Use commitments instead of raw data, follow [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md) guidelines

---

## Summary Checklist

- [ ] Build wallet binary
- [ ] Generate keypair for SUM Hypothesis Institute
- [ ] Save keystore file and password securely
- [ ] Get institution address
- [ ] Fund account with 1010 Ϙ
- [ ] Verify balance received
- [ ] Get public key in base58 format
- [ ] Prepare registration JSON
- [ ] Serialize to bincode format
- [ ] Submit registration transaction
- [ ] Verify registration successful
- [ ] Issue test credential to verify setup

---

## Next Steps

After successful registration:

1. **Read documentation**:
   - [VERIFICATION-TEAM-SUMMARY.md](VERIFICATION-TEAM-SUMMARY.md) - Credential issuance guide
   - [SRC-81X-COMMITMENT-CANONICALIZATION.md](SRC-81X-COMMITMENT-CANONICALIZATION.md) - Hashing rules
   - [DEPLOYMENT-GUIDE.md](DEPLOYMENT-GUIDE.md) - Chain deployment info

2. **Implement credential issuance**:
   - Build commitment generation (BLAKE3 hashing)
   - Set up IPFS for payload storage
   - Implement encryption if needed (X25519Aes256Gcm recommended)
   - Create client-side validation

3. **Test on staging/testnet** (if available):
   - Issue test credentials
   - Verify commitments
   - Test revocation/supersede flow

4. **Go to production**:
   - Issue real credentials after block 385,000 (schema validation active)
   - Monitor for schema validation errors
   - Provide student verification interface

---

## Contact

**Issues during setup**:
- Check logs for detailed error messages
- Review troubleshooting section above
- Contact chain operator team

**Post-registration support**:
- Credential issuance questions: See VERIFICATION-TEAM-SUMMARY.md
- Schema validation errors: See allowlists in documentation
- Technical issues: File in chain repository

---

**Document Version**: 1.0
**Date**: 2026-02-01
**Status**: Production Guide
**Institution**: SUM Hypothesis Institute Technology

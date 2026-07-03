# Web Wallet RPC Implementation Guide

> **Archived / historical.** Point-in-time backend integration handoff (2026-02).
> Kept for history; for current RPC usage see
> [docs/rpc/api-reference.md](../rpc/api-reference.md) and
> [docs/rpc/SNIP-V2-RPC-CHEATSHEET.md](../rpc/SNIP-V2-RPC-CHEATSHEET.md).

**For Blockchain Backend Team**

This document provides ready-to-paste implementation code for the three RPC endpoints required by the web wallet.

---

## Overview

The web wallet needs these three endpoints to be fully functional:

1. **`sum_sendRawTransaction`** - Submit signed transactions
2. **`pub_key_get`** - Retrieve recipient public keys for encryption
3. **`messaging_submitMessage`** - Submit encrypted messages

---

## 1. sum_sendRawTransaction

### Add to api.rs

```rust
#[method(name = "sum_sendRawTransaction")]
async fn sum_send_raw_transaction(
    &self,
    raw_tx_hex: String,
) -> Result<SendRawTransactionResponse, ErrorObjectOwned>;
```

### Add to types.rs

```rust
/// Response for sum_sendRawTransaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRawTransactionResponse {
    /// Transaction hash (hex-encoded)
    pub tx_hash: String,
}
```

### Add to server.rs

```rust
async fn sum_send_raw_transaction(
    &self,
    raw_tx_hex: String,
) -> std::result::Result<SendRawTransactionResponse, ErrorObjectOwned> {
    use sumchain_primitives::{Transaction, SignedTransaction};
    use sumchain_crypto::PublicKey;
    use blake3;

    // Remove 0x prefix if present
    let hex_str = raw_tx_hex.strip_prefix("0x").unwrap_or(&raw_tx_hex);

    // Decode hex to bytes
    let raw_bytes = hex::decode(hex_str).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Invalid hex encoding: {}", e),
            None::<()>,
        )
    })?;

    // Expected format: 192 bytes
    // - 1 byte: version
    // - 91 bytes: unsigned transaction
    // - 64 bytes: signature
    // - 32 bytes: public key
    // - 4 bytes: network magic
    if raw_bytes.len() != 192 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("Invalid transaction length: expected 192 bytes, got {}", raw_bytes.len()),
            None::<()>,
        ));
    }

    // Parse version
    let version = raw_bytes[0];
    if version != 1 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("Unsupported transaction version: {}", version),
            None::<()>,
        ));
    }

    // Extract components
    let unsigned_tx_bytes = &raw_bytes[1..92];
    let signature_bytes = &raw_bytes[92..156];
    let public_key_bytes = &raw_bytes[156..188];
    let network_magic_bytes = &raw_bytes[188..192];

    // Verify network magic (0x01020304 for mainnet, adjust as needed)
    let expected_network_magic = self.network_magic();
    let network_magic = u32::from_le_bytes(network_magic_bytes.try_into().unwrap());
    if network_magic != expected_network_magic {
        return Err(ErrorObjectOwned::owned(
            -32603,
            format!("Invalid network magic: expected 0x{:08x}, got 0x{:08x}",
                    expected_network_magic, network_magic),
            None::<()>,
        ));
    }

    // Parse public key
    let public_key = PublicKey::from_bytes(public_key_bytes).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Invalid public key: {}", e),
            None::<()>,
        )
    })?;

    // Derive sender address from public key
    let sender_address = public_key.to_address();

    // Parse signature
    let signature = ed25519_dalek::Signature::from_bytes(signature_bytes.try_into().unwrap());

    // Verify signature
    use ed25519_dalek::Verifier;
    let public_key_ed = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
        .map_err(|e| {
            ErrorObjectOwned::owned(
                -32602,
                format!("Invalid Ed25519 public key: {}", e),
                None::<()>,
            )
        })?;

    public_key_ed.verify(unsigned_tx_bytes, &signature).map_err(|_| {
        ErrorObjectOwned::owned(
            -32603,
            "Invalid signature",
            None::<()>,
        )
    })?;

    // Deserialize unsigned transaction
    let unsigned_tx: Transaction = bincode::deserialize(unsigned_tx_bytes).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Failed to deserialize transaction: {}", e),
            None::<()>,
        )
    })?;

    // Validate sender address matches transaction
    if unsigned_tx.sender != sender_address {
        return Err(ErrorObjectOwned::owned(
            -32603,
            "Sender address does not match public key",
            None::<()>,
        ));
    }

    // Get sender's current balance and nonce
    let account_store = self.db.account_store();
    let account = account_store.get(&sender_address).map_err(|e| {
        ErrorObjectOwned::owned(
            -32603,
            format!("Failed to fetch sender account: {}", e),
            None::<()>,
        )
    })?;

    let current_balance = account.as_ref().map(|a| a.balance).unwrap_or(0);
    let current_nonce = account.as_ref().map(|a| a.nonce).unwrap_or(0);

    // Validate nonce (must be exactly current_nonce)
    if unsigned_tx.nonce != current_nonce {
        return Err(ErrorObjectOwned::owned(
            -32603,
            format!("Invalid nonce: expected {}, got {}", current_nonce, unsigned_tx.nonce),
            None::<()>,
        ));
    }

    // Calculate total cost
    let total_cost = unsigned_tx.operation.calculate_cost() + unsigned_tx.fee;

    // Validate balance
    if current_balance < total_cost {
        return Err(ErrorObjectOwned::owned(
            -32603,
            format!("Insufficient balance: have {} Koppa, need {} Koppa",
                    current_balance, total_cost),
            None::<()>,
        ));
    }

    // Create signed transaction
    let signed_tx = SignedTransaction {
        transaction: unsigned_tx.clone(),
        signature: signature_bytes.to_vec(),
        public_key: public_key_bytes.to_vec(),
    };

    // Calculate transaction hash
    let tx_hash_bytes = blake3::hash(&raw_bytes[..188]); // Hash everything except network magic
    let tx_hash = format!("0x{}", hex::encode(tx_hash_bytes.as_bytes()));

    // Submit to mempool
    let mempool = self.mempool();
    mempool.add_transaction(signed_tx.clone()).map_err(|e| {
        ErrorObjectOwned::owned(
            -32603,
            format!("Failed to add transaction to mempool: {}", e),
            None::<()>,
        )
    })?;

    // Broadcast to network
    self.broadcast_transaction(signed_tx).await;

    info!("Transaction submitted: {} from {}", tx_hash, sender_address);

    Ok(SendRawTransactionResponse { tx_hash })
}
```

---

## 2. pub_key_get

### Add to api.rs

```rust
#[method(name = "pub_key_get")]
async fn pub_key_get(
    &self,
    address: String,
) -> Result<String, ErrorObjectOwned>;
```

### Add to server.rs

```rust
async fn pub_key_get(
    &self,
    address: String,
) -> std::result::Result<String, ErrorObjectOwned> {
    use sumchain_primitives::Address;

    // Parse address
    let addr = Address::from_base58(&address).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Invalid address format: {}", e),
            None::<()>,
        )
    })?;

    // Get account from state
    let account_store = self.db.account_store();
    let account = account_store.get(&addr).map_err(|e| {
        ErrorObjectOwned::owned(
            -32603,
            format!("Failed to fetch account: {}", e),
            None::<()>,
        )
    })?;

    // Check if account exists
    let account = account.ok_or_else(|| {
        ErrorObjectOwned::owned(
            -32001,
            format!("Account not found: {}", address),
            None::<()>,
        )
    })?;

    // Check if public key is registered
    let x25519_public_key = account.x25519_public_key.ok_or_else(|| {
        ErrorObjectOwned::owned(
            -32001,
            "Recipient has not registered their public key on-chain",
            None::<()>,
        )
    })?;

    // Return hex-encoded public key
    Ok(format!("0x{}", hex::encode(&x25519_public_key)))
}
```

---

## 3. messaging_submitMessage

### Add to api.rs

```rust
#[method(name = "messaging_submitMessage")]
async fn messaging_submit_message(
    &self,
    request: SubmitMessageRequest,
) -> Result<SubmitMessageResponse, ErrorObjectOwned>;
```

### Add to types.rs

```rust
/// Request to submit an encrypted message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitMessageRequest {
    /// Encrypted message data (hex)
    pub encrypted_data: String,
    /// Recipient hash (BLAKE3 hash of recipient address, hex)
    pub recipient_hash: String,
    /// Signature of encrypted data (hex)
    pub signature: String,
    /// Sender address (base58)
    pub sender_address: String,
}

/// Response for message submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitMessageResponse {
    /// Transaction hash (hex)
    pub tx_hash: String,
}
```

### Add to server.rs

```rust
async fn messaging_submit_message(
    &self,
    request: SubmitMessageRequest,
) -> std::result::Result<SubmitMessageResponse, ErrorObjectOwned> {
    use sumchain_primitives::{Address, Transaction, Operation};
    use sumchain_crypto::PublicKey;
    use blake3;

    // Parse sender address
    let sender_address = Address::from_base58(&request.sender_address).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Invalid sender address: {}", e),
            None::<()>,
        )
    })?;

    // Decode encrypted data
    let encrypted_data_hex = request.encrypted_data.strip_prefix("0x").unwrap_or(&request.encrypted_data);
    let encrypted_data = hex::decode(encrypted_data_hex).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Invalid encrypted data hex: {}", e),
            None::<()>,
        )
    })?;

    // Decode recipient hash
    let recipient_hash_hex = request.recipient_hash.strip_prefix("0x").unwrap_or(&request.recipient_hash);
    let recipient_hash = hex::decode(recipient_hash_hex).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Invalid recipient hash hex: {}", e),
            None::<()>,
        )
    })?;

    if recipient_hash.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("Invalid recipient hash length: expected 32 bytes, got {}", recipient_hash.len()),
            None::<()>,
        ));
    }

    // Decode signature
    let signature_hex = request.signature.strip_prefix("0x").unwrap_or(&request.signature);
    let signature_bytes = hex::decode(signature_hex).map_err(|e| {
        ErrorObjectOwned::owned(
            -32602,
            format!("Invalid signature hex: {}", e),
            None::<()>,
        )
    })?;

    if signature_bytes.len() != 64 {
        return Err(ErrorObjectOwned::owned(
            -32602,
            format!("Invalid signature length: expected 64 bytes, got {}", signature_bytes.len()),
            None::<()>,
        ));
    }

    // Get sender's account to retrieve public key
    let account_store = self.db.account_store();
    let account = account_store.get(&sender_address).map_err(|e| {
        ErrorObjectOwned::owned(
            -32603,
            format!("Failed to fetch sender account: {}", e),
            None::<()>,
        )
    })?;

    let account = account.ok_or_else(|| {
        ErrorObjectOwned::owned(
            -32001,
            format!("Sender account not found: {}", request.sender_address),
            None::<()>,
        )
    })?;

    let sender_public_key_bytes = account.public_key.ok_or_else(|| {
        ErrorObjectOwned::owned(
            -32603,
            "Sender public key not found in account state",
            None::<()>,
        )
    })?;

    // Verify signature
    use ed25519_dalek::Verifier;
    let signature = ed25519_dalek::Signature::from_bytes(signature_bytes.as_slice().try_into().unwrap());
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(sender_public_key_bytes.as_slice().try_into().unwrap())
        .map_err(|e| {
            ErrorObjectOwned::owned(
                -32603,
                format!("Invalid sender public key: {}", e),
                None::<()>,
            )
        })?;

    public_key.verify(&encrypted_data, &signature).map_err(|_| {
        ErrorObjectOwned::owned(
            -32603,
            "Invalid signature: signature does not match encrypted data",
            None::<()>,
        )
    })?;

    // Create message operation
    let message_op = Operation::SendMessage {
        recipient_hash: recipient_hash.try_into().unwrap(),
        encrypted_data: encrypted_data.clone(),
    };

    // Get current nonce
    let current_nonce = account.nonce;

    // Create transaction
    let tx = Transaction {
        sender: sender_address,
        nonce: current_nonce,
        operation: message_op,
        fee: 1_000_000, // 0.001 Ϙ
    };

    // Calculate transaction cost
    let total_cost = tx.operation.calculate_cost() + tx.fee;

    // Validate balance
    if account.balance < total_cost {
        return Err(ErrorObjectOwned::owned(
            -32603,
            format!("Insufficient balance: have {} Koppa, need {} Koppa",
                    account.balance, total_cost),
            None::<()>,
        ));
    }

    // Sign transaction (server-side signing for messages)
    let tx_bytes = bincode::serialize(&tx).map_err(|e| {
        ErrorObjectOwned::owned(
            -32603,
            format!("Failed to serialize transaction: {}", e),
            None::<()>,
        )
    })?;

    // For messages, we use the provided signature
    let signed_tx = SignedTransaction {
        transaction: tx.clone(),
        signature: signature_bytes,
        public_key: sender_public_key_bytes,
    };

    // Calculate transaction hash
    let tx_hash_bytes = blake3::hash(&tx_bytes);
    let tx_hash = format!("0x{}", hex::encode(tx_hash_bytes.as_bytes()));

    // Submit to mempool
    let mempool = self.mempool();
    mempool.add_transaction(signed_tx.clone()).map_err(|e| {
        ErrorObjectOwned::owned(
            -32603,
            format!("Failed to add transaction to mempool: {}", e),
            None::<()>,
        )
    })?;

    // Broadcast to network
    self.broadcast_transaction(signed_tx).await;

    // Store message in message index for recipient retrieval
    let message_store = self.db.message_store();
    message_store.store_message(
        &recipient_hash.try_into().unwrap(),
        &encrypted_data,
        &sender_address,
        tx_hash_bytes.as_bytes(),
    ).map_err(|e| {
        ErrorObjectOwned::owned(
            -32603,
            format!("Failed to store message: {}", e),
            None::<()>,
        )
    })?;

    info!("Message submitted: {} from {} to recipient hash {}",
          tx_hash, request.sender_address, request.recipient_hash);

    Ok(SubmitMessageResponse { tx_hash })
}
```

---

## Error Codes Reference

| Code | Meaning | When to Use |
|------|---------|-------------|
| -32600 | Invalid Request | Malformed JSON-RPC request |
| -32601 | Method not found | RPC method doesn't exist |
| -32602 | Invalid params | Parameter format/type wrong |
| -32603 | Internal error | Server-side processing error |
| -32001 | Not found | Account/resource doesn't exist |
| -32000 | Custom error | Domain-specific errors |

---

## Testing

### Test sum_sendRawTransaction

```bash
# Build a test transaction first (use web wallet or CLI tool)
# Then submit it:

curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sum_sendRawTransaction",
    "params": ["0x01000000..."],
    "id": 1
  }'
```

**Expected Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tx_hash": "0x1a2b3c4d5e6f..."
  },
  "id": 1
}
```

### Test pub_key_get

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "pub_key_get",
    "params": ["MMwxCo6U35xubBLi6N3ouktKiT7FM2gFE"],
    "id": 2
  }'
```

**Expected Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
  "id": 2
}
```

### Test messaging_submitMessage

```bash
curl -X POST https://rpc.sum-chain.xyz \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "messaging_submitMessage",
    "params": {
      "encrypted_data": "0x53524332010000...",
      "recipient_hash": "0xaabbccdd...",
      "signature": "0x1122334455...",
      "sender_address": "GHij6789..."
    },
    "id": 3
  }'
```

**Expected Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tx_hash": "0x9z8y7x6w5v4u..."
  },
  "id": 3
}
```

---

## Integration Checklist

- [ ] Add RPC method signatures to `api.rs`
- [ ] Add request/response types to `types.rs`
- [ ] Implement handlers in `server.rs`
- [ ] Add `sum_sendRawTransaction` - validate signatures, check balance/nonce
- [ ] Add `pub_key_get` - retrieve X25519 public keys from accounts
- [ ] Add `messaging_submitMessage` - store encrypted messages
- [ ] Test with curl commands above
- [ ] Test with web wallet integration
- [ ] Deploy to production RPC endpoint

---

## Additional Notes

### Transaction Format (192 bytes)

```
[0]       : version (1 byte) = 0x01
[1..92]   : unsigned transaction (91 bytes, bincode)
[92..156] : signature (64 bytes, Ed25519)
[156..188]: public key (32 bytes, Ed25519)
[188..192]: network magic (4 bytes, little-endian u32)
```

### Network Magic Values

- **Mainnet**: `0x01020304`
- **Testnet**: `0x05060708`

Update `self.network_magic()` to return the correct value for your network.

---

**Document Version**: 1.0
**Date**: 2026-02-03
**Status**: Ready for Implementation
**Priority**: Critical for Web Wallet Launch

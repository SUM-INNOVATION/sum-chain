//! SRC-201 Messaging Cryptography
//!
//! Provides encryption and decryption for SRC-201 on-chain messages.
//! Uses X25519-XChaCha20-Poly1305 with explicit AAD for authenticated encryption.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use sumchain_primitives::{
    Address, ContentType, Hash, MessageFlags, MessageHeader, SRC201_HEADER_SIZE, SRC201_KDF_CONTEXT,
    SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};

use crate::CryptoError;

/// Result type for messaging operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Decrypted message content
#[derive(Debug, Clone)]
pub struct DecryptedMessage {
    /// Recipient address (from decrypted payload)
    pub recipient_address: Address,
    /// Recipient's Ed25519 public key
    pub recipient_pubkey: [u8; 32],
    /// Message content
    pub content: Vec<u8>,
    /// Content type
    pub content_type: ContentType,
    /// Message flags
    pub flags: MessageFlags,
    /// Reply-to message ID (if present)
    pub reply_to: Option<Hash>,
    /// Sender-provided timestamp (if present)
    pub timestamp: Option<u64>,
}

/// Convert Ed25519 public key to X25519 public key
///
/// Uses the birational map from Edwards to Montgomery form:
/// u = (1 + y) / (1 - y) mod p
pub fn ed25519_pk_to_x25519(ed_pk: &[u8; 32]) -> Result<[u8; 32]> {
    // Parse as compressed Edwards point
    let compressed = CompressedEdwardsY(*ed_pk);
    let edwards_point = compressed
        .decompress()
        .ok_or(CryptoError::InvalidPublicKey)?;

    // Convert to Montgomery form
    let montgomery = edwards_point.to_montgomery();
    Ok(montgomery.to_bytes())
}

/// Convert Ed25519 private key (seed) to X25519 private key
///
/// Ed25519 internally expands the 32-byte seed to 64 bytes using SHA-512,
/// then takes the first 32 bytes and clamps them to form the scalar.
/// For X25519, we need the same clamped bytes (not reduced mod group order).
pub fn ed25519_sk_to_x25519(ed_seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Sha512, Digest};

    // Hash the seed with SHA-512 (same as Ed25519 key expansion)
    let hash = Sha512::digest(ed_seed);

    // Take the first 32 bytes and clamp them for X25519
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);

    // Apply X25519/Ed25519 clamping
    output[0] &= 248;   // Clear the lowest 3 bits
    output[31] &= 127;  // Clear the highest bit
    output[31] |= 64;   // Set the second-highest bit

    output
}

/// Perform X25519 Diffie-Hellman key exchange
pub fn x25519_ecdh(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let secret = X25519Secret::from(*private_key);
    let their_public = X25519PublicKey::from(*public_key);
    *secret.diffie_hellman(&their_public).as_bytes()
}

/// Derive a key using BLAKE3 keyed derivation
pub fn blake3_derive_key(context: &str, input: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, input)
}

/// Compute recipient hash for message discovery
pub fn recipient_hash(address: &Address) -> [u8; 32] {
    *blake3::hash(address.as_bytes()).as_bytes()
}

/// Encrypt a message for a recipient
///
/// # Arguments
/// * `sender_ed_sk` - Sender's Ed25519 private key (seed)
/// * `recipient_ed_pk` - Recipient's Ed25519 public key
/// * `recipient_address` - Recipient's address
/// * `content` - Message content
/// * `content_type` - Content MIME type
/// * `flags` - Message flags (encrypted flag will be set automatically)
/// * `reply_to` - Optional parent message hash
/// * `timestamp` - Optional sender-provided timestamp
pub fn encrypt_message(
    sender_ed_sk: &[u8; 32],
    recipient_ed_pk: &[u8; 32],
    recipient_address: &Address,
    content: &[u8],
    content_type: ContentType,
    mut flags: MessageFlags,
    reply_to: Option<Hash>,
    timestamp: Option<u64>,
) -> Result<Vec<u8>> {
    // 1. Generate ephemeral X25519 keypair
    let mut ephemeral_private = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_private);
    let ephemeral_secret = X25519Secret::from(ephemeral_private);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // 2. Convert recipient Ed25519 key to X25519
    let recipient_x25519 = ed25519_pk_to_x25519(recipient_ed_pk)?;
    let recipient_x25519_pk = X25519PublicKey::from(recipient_x25519);

    // 3. ECDH to get shared secret
    let shared_point = ephemeral_secret.diffie_hellman(&recipient_x25519_pk);

    // 4. Derive message key
    let message_key = blake3_derive_key(SRC201_KDF_CONTEXT, shared_point.as_bytes());

    // 5. Build plaintext (recipient address + recipient pubkey + content)
    let mut plaintext = Vec::with_capacity(32 + 32 + content.len());
    plaintext.extend_from_slice(recipient_address.as_bytes());
    plaintext.extend_from_slice(recipient_ed_pk);
    plaintext.extend_from_slice(content);

    // 6. Build header (this becomes AAD)
    flags.set(MessageFlags::ENCRYPTED);
    if reply_to.is_some() {
        flags.set(MessageFlags::HAS_REPLY_TO);
    }
    if timestamp.is_some() {
        flags.set(MessageFlags::HAS_TIMESTAMP);
    }

    let rec_hash = recipient_hash(recipient_address);

    let header = MessageHeader {
        magic: SRC201_MAGIC,
        version: SRC201_VERSION,
        flags,
        content_type,
        attachment_count: 0,
        recipient_hash: rec_hash,
        ephemeral_pubkey: *ephemeral_public.as_bytes(),
    };
    let header_bytes = header.to_bytes();

    // 7. Generate random nonce
    let mut nonce_bytes = [0u8; SRC201_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // 8. Encrypt with AEAD (header as AAD)
    let cipher = XChaCha20Poly1305::new_from_slice(&message_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;

    let payload = Payload {
        msg: &plaintext,
        aad: &header_bytes,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::InvalidSignature)?;

    // 9. Assemble message
    // Header (72) + nonce (24) + payload_len (2) + ciphertext (includes 16-byte tag) + optional fields
    let payload_len = (ciphertext.len() - SRC201_TAG_SIZE) as u16;

    let mut message = Vec::with_capacity(
        SRC201_HEADER_SIZE + SRC201_NONCE_SIZE + 2 + ciphertext.len() + 32 + 8,
    );
    message.extend_from_slice(&header_bytes);
    message.extend_from_slice(&nonce_bytes);
    message.extend_from_slice(&payload_len.to_be_bytes());
    message.extend_from_slice(&ciphertext);

    // Optional fields
    if let Some(ref reply) = reply_to {
        message.extend_from_slice(reply.as_bytes());
    }
    if let Some(ts) = timestamp {
        message.extend_from_slice(&ts.to_be_bytes());
    }

    // 10. Zeroize sensitive data
    ephemeral_private.zeroize();

    Ok(message)
}

/// Decrypt a message
///
/// Returns None if this message is not intended for the given recipient.
///
/// # Arguments
/// * `recipient_ed_sk` - Recipient's Ed25519 private key (seed)
/// * `recipient_address` - Recipient's address (for verification)
/// * `message` - Encoded SRC-201 message
pub fn decrypt_message(
    recipient_ed_sk: &[u8; 32],
    recipient_address: &Address,
    message: &[u8],
) -> Result<Option<DecryptedMessage>> {
    // 1. Parse header
    let header = MessageHeader::from_bytes(message).ok_or(CryptoError::InvalidSignature)?;

    // 2. Check if this message is for us (fast reject)
    let my_hash = recipient_hash(recipient_address);
    if header.recipient_hash != my_hash {
        return Ok(None);
    }

    if !header.flags.is_encrypted() {
        return Err(CryptoError::InvalidSignature);
    }

    // 3. Extract nonce and ciphertext
    if message.len() < SRC201_HEADER_SIZE + SRC201_NONCE_SIZE + 2 {
        return Err(CryptoError::InvalidSignature);
    }

    let nonce_start = SRC201_HEADER_SIZE;
    let nonce_bytes: [u8; 24] = message[nonce_start..nonce_start + 24]
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;

    let payload_len = u16::from_be_bytes([
        message[nonce_start + 24],
        message[nonce_start + 25],
    ]) as usize;

    let ciphertext_start = nonce_start + 26;
    let ciphertext_end = ciphertext_start + payload_len + SRC201_TAG_SIZE;

    if message.len() < ciphertext_end {
        return Err(CryptoError::InvalidSignature);
    }

    let ciphertext = &message[ciphertext_start..ciphertext_end];

    // 4. Convert our Ed25519 key to X25519
    let my_x25519_private = ed25519_sk_to_x25519(recipient_ed_sk);
    let my_x25519_secret = X25519Secret::from(my_x25519_private);

    // 5. Parse sender's ephemeral public key
    let ephemeral_public = X25519PublicKey::from(header.ephemeral_pubkey);

    // 6. ECDH to recover shared secret
    let shared_point = my_x25519_secret.diffie_hellman(&ephemeral_public);

    // 7. Derive message key
    let message_key = blake3_derive_key(SRC201_KDF_CONTEXT, shared_point.as_bytes());

    // 8. Decrypt with AEAD
    let header_bytes = header.to_bytes();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(&message_key)
        .map_err(|_| CryptoError::InvalidPrivateKey)?;

    let payload = Payload {
        msg: ciphertext,
        aad: &header_bytes,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::VerificationFailed)?;

    // 9. Parse plaintext
    if plaintext.len() < 64 {
        return Err(CryptoError::InvalidSignature);
    }

    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&plaintext[0..20]);
    let decrypted_recipient = Address::new(addr_bytes);

    // Verify recipient matches
    if decrypted_recipient != *recipient_address {
        return Err(CryptoError::VerificationFailed);
    }

    let mut recipient_pubkey = [0u8; 32];
    recipient_pubkey.copy_from_slice(&plaintext[20..52]);

    let content = plaintext[52..].to_vec();

    // 10. Parse optional fields
    let mut offset = ciphertext_end;
    let reply_to = if header.flags.has_reply_to() && message.len() >= offset + 32 {
        let hash = Hash::from_slice(&message[offset..offset + 32])
            .ok();
        offset += 32;
        hash
    } else {
        None
    };

    let timestamp = if header.flags.has_timestamp() && message.len() >= offset + 8 {
        let ts = u64::from_be_bytes(
            message[offset..offset + 8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        Some(ts)
    } else {
        None
    };

    Ok(Some(DecryptedMessage {
        recipient_address: decrypted_recipient,
        recipient_pubkey,
        content,
        content_type: header.content_type,
        flags: header.flags,
        reply_to,
        timestamp,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn test_ed25519_to_x25519_conversion() {
        let kp = KeyPair::generate();
        let x25519_pk = ed25519_pk_to_x25519(kp.public_key().as_bytes()).unwrap();

        // X25519 public key should be 32 bytes
        assert_eq!(x25519_pk.len(), 32);

        // Should be deterministic
        let x25519_pk2 = ed25519_pk_to_x25519(kp.public_key().as_bytes()).unwrap();
        assert_eq!(x25519_pk, x25519_pk2);

        // The X25519 public key derived from the Ed25519 public key
        // should match the X25519 public key derived from the X25519 private key
        // (which was derived from the Ed25519 private key)
        let x25519_sk = ed25519_sk_to_x25519(kp.private_key().as_bytes());
        let x25519_sk_secret = X25519Secret::from(x25519_sk);
        let x25519_pk_from_sk = X25519PublicKey::from(&x25519_sk_secret);

        // These should match!
        assert_eq!(x25519_pk, *x25519_pk_from_sk.as_bytes(),
            "X25519 pk from ed25519 pk birational map should match X25519 pk from ed25519 sk");
    }

    #[test]
    fn test_ecdh_shared_secret() {
        let alice_private = [1u8; 32];
        let bob_private = [2u8; 32];

        let alice_secret = X25519Secret::from(alice_private);
        let bob_secret = X25519Secret::from(bob_private);

        let alice_public = X25519PublicKey::from(&alice_secret);
        let bob_public = X25519PublicKey::from(&bob_secret);

        let alice_shared = x25519_ecdh(&alice_private, bob_public.as_bytes());
        let bob_shared = x25519_ecdh(&bob_private, alice_public.as_bytes());

        // Both parties should derive the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_recipient_hash() {
        let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();
        let hash = recipient_hash(&addr);

        // Hash should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Should be deterministic
        let hash2 = recipient_hash(&addr);
        assert_eq!(hash, hash2);

        // Different address should give different hash
        let addr2 = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();
        let hash3 = recipient_hash(&addr2);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_message_encrypt_decrypt_roundtrip() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let content = b"Hello, SRC-201!";
        let content_type = ContentType::TextPlain;
        let flags = MessageFlags::new();

        // Encrypt
        let encrypted = encrypt_message(
            sender.private_key().as_bytes(),
            recipient.public_key().as_bytes(),
            &recipient.address(),
            content,
            content_type,
            flags,
            None,
            None,
        )
        .unwrap();

        // Verify magic bytes
        assert_eq!(&encrypted[0..4], &SRC201_MAGIC);

        // Decrypt
        let decrypted = decrypt_message(
            recipient.private_key().as_bytes(),
            &recipient.address(),
            &encrypted,
        )
        .unwrap()
        .unwrap();

        assert_eq!(decrypted.content, content);
        assert_eq!(decrypted.content_type, ContentType::TextPlain);
        assert!(decrypted.flags.is_encrypted());
    }

    #[test]
    fn test_message_with_reply_to_and_timestamp() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let content = b"Reply message";
        let reply_to = Hash::hash(b"parent message");
        let timestamp = 1704067200u64; // 2024-01-01 00:00:00 UTC

        let encrypted = encrypt_message(
            sender.private_key().as_bytes(),
            recipient.public_key().as_bytes(),
            &recipient.address(),
            content,
            ContentType::TextPlain,
            MessageFlags::new(),
            Some(reply_to),
            Some(timestamp),
        )
        .unwrap();

        let decrypted = decrypt_message(
            recipient.private_key().as_bytes(),
            &recipient.address(),
            &encrypted,
        )
        .unwrap()
        .unwrap();

        assert_eq!(decrypted.content, content);
        assert!(decrypted.flags.has_reply_to());
        assert!(decrypted.flags.has_timestamp());
        assert_eq!(decrypted.reply_to, Some(reply_to));
        assert_eq!(decrypted.timestamp, Some(timestamp));
    }

    #[test]
    fn test_wrong_recipient_returns_none() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        let wrong_recipient = KeyPair::generate();

        let content = b"Secret message";

        let encrypted = encrypt_message(
            sender.private_key().as_bytes(),
            recipient.public_key().as_bytes(),
            &recipient.address(),
            content,
            ContentType::TextPlain,
            MessageFlags::new(),
            None,
            None,
        )
        .unwrap();

        // Wrong recipient should get None (message not for them)
        let result = decrypt_message(
            wrong_recipient.private_key().as_bytes(),
            &wrong_recipient.address(),
            &encrypted,
        )
        .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_tampered_message_fails() {
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let content = b"Original message";

        let mut encrypted = encrypt_message(
            sender.private_key().as_bytes(),
            recipient.public_key().as_bytes(),
            &recipient.address(),
            content,
            ContentType::TextPlain,
            MessageFlags::new(),
            None,
            None,
        )
        .unwrap();

        // Tamper with the flags byte (offset 5)
        encrypted[5] ^= 0xFF;

        // Decryption should fail due to AAD mismatch
        let result = decrypt_message(
            recipient.private_key().as_bytes(),
            &recipient.address(),
            &encrypted,
        );

        assert!(result.is_err());
    }
}

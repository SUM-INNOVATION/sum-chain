//! Encrypted keystore management.
//!
//! Uses Argon2 for key derivation and AES-256-GCM for encryption.

use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sumchain_crypto::{KeyPair, PublicKey};
use sumchain_primitives::Address;
use zeroize::Zeroize;

/// Encrypted keystore format
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    /// Version
    pub version: u32,
    /// Public key (not encrypted)
    pub public_key: String,
    /// Address (not encrypted)
    pub address: String,
    /// Argon2 salt (hex)
    pub salt: String,
    /// AES-GCM nonce (hex)
    pub nonce: String,
    /// Encrypted private key (hex)
    pub ciphertext: String,
}

/// Loaded keystore with decrypted key
pub struct Keystore {
    keypair: KeyPair,
}

impl Keystore {
    /// Generate a new keystore
    pub fn generate(_password: &str) -> Result<Self> {
        let keypair = KeyPair::generate();
        Ok(Self { keypair })
    }

    /// Load from file (supports both encrypted and raw formats)
    pub fn load(path: &Path, password: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read keystore from {:?}", path))?;

        // Try to load as raw key bytes first (for unencrypted dev keys)
        if let Ok(raw_bytes) = serde_json::from_str::<Vec<u8>>(&contents) {
            if raw_bytes.len() == 32 {
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&raw_bytes);
                let keypair = KeyPair::from_bytes(key_array);
                return Ok(Self { keypair });
            }
        }

        // Otherwise load as encrypted keystore
        let encrypted: EncryptedKeystore = serde_json::from_str(&contents)
            .context("Failed to parse keystore JSON")?;

        // Decode hex values
        let salt = hex::decode(&encrypted.salt).context("Invalid salt")?;
        let nonce = hex::decode(&encrypted.nonce).context("Invalid nonce")?;
        let ciphertext = hex::decode(&encrypted.ciphertext).context("Invalid ciphertext")?;

        // Derive key from password
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

        // Decrypt private key
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Cipher creation failed: {}", e))?;

        let nonce = Nonce::from_slice(&nonce);
        let private_key_bytes = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("Decryption failed - incorrect password?"))?;

        // Zeroize the derived key
        key.zeroize();

        // Create keypair
        if private_key_bytes.len() != 32 {
            anyhow::bail!("Invalid private key length");
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&private_key_bytes);
        let keypair = KeyPair::from_bytes(key_array);
        key_array.zeroize();

        // Verify public key matches
        if keypair.public_key().to_base58() != encrypted.public_key {
            anyhow::bail!("Public key mismatch - keystore may be corrupted");
        }

        Ok(Self { keypair })
    }

    /// Save to encrypted file
    pub fn save(&self, path: &Path) -> Result<()> {
        let password = rpassword::prompt_password("Enter password to encrypt keystore: ")?;

        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Derive key from password
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

        // Encrypt private key
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Cipher creation failed: {}", e))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, self.keypair.private_key().as_bytes().as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Zeroize the derived key
        key.zeroize();

        // Create encrypted keystore
        let encrypted = EncryptedKeystore {
            version: 1,
            public_key: self.keypair.public_key().to_base58(),
            address: self.keypair.address().to_base58(),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
        };

        // Write to file
        let contents = serde_json::to_string_pretty(&encrypted)?;
        std::fs::write(path, contents)?;

        Ok(())
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        self.keypair.public_key()
    }

    /// Get the address
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get the keypair (for signing)
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_keystore_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.json");

        // Generate and save with explicit password handling
        let keystore = Keystore::generate("testpassword123").unwrap();
        let pubkey = keystore.public_key().to_base58();

        // Manual save without prompt for testing
        let mut salt = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into("testpassword123".as_bytes(), &salt, &mut key)
            .unwrap();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, keystore.keypair().private_key().as_bytes().as_ref())
            .unwrap();

        let encrypted = EncryptedKeystore {
            version: 1,
            public_key: keystore.public_key().to_base58(),
            address: keystore.address().to_base58(),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
        };

        std::fs::write(&path, serde_json::to_string_pretty(&encrypted).unwrap()).unwrap();

        // Load
        let loaded = Keystore::load(&path, "testpassword123").unwrap();
        assert_eq!(loaded.public_key().to_base58(), pubkey);
    }
}

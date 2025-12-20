//! Node key management for persistent peer identity.
//!
//! Handles loading and saving of libp2p Ed25519 keypairs.

use std::fs;
use std::path::Path;

use libp2p::identity::Keypair;
use tracing::{info, warn};

use crate::{P2pError, Result};

/// Load or generate a node keypair
///
/// If the key file exists, loads it. Otherwise generates a new key and saves it.
pub fn load_or_generate_keypair(key_path: Option<&Path>) -> Result<Keypair> {
    match key_path {
        Some(path) => {
            if path.exists() {
                load_keypair(path)
            } else {
                let keypair = generate_and_save_keypair(path)?;
                Ok(keypair)
            }
        }
        None => {
            // No path specified, generate ephemeral key
            info!("No node key file specified, generating ephemeral keypair");
            Ok(Keypair::generate_ed25519())
        }
    }
}

/// Load an existing keypair from file
pub fn load_keypair(path: &Path) -> Result<Keypair> {
    let bytes = fs::read(path).map_err(|e| {
        P2pError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to read node key from {:?}: {}", path, e),
        ))
    })?;

    // Try to decode as raw Ed25519 secret key (32 bytes)
    if bytes.len() == 32 {
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&bytes);
        let keypair = Keypair::ed25519_from_bytes(secret_bytes).map_err(|e| {
            P2pError::Transport(format!("Failed to decode Ed25519 key: {}", e))
        })?;
        info!("Loaded node key from {:?}", path);
        return Ok(keypair);
    }

    // Try to decode as protobuf-encoded keypair
    let keypair = Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
        P2pError::Transport(format!(
            "Failed to decode node key from {:?}: {}. Expected 32-byte Ed25519 secret or protobuf encoding.",
            path, e
        ))
    })?;

    info!("Loaded node key from {:?}", path);
    Ok(keypair)
}

/// Generate a new keypair and save it to file
pub fn generate_and_save_keypair(path: &Path) -> Result<Keypair> {
    let keypair = Keypair::generate_ed25519();

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                P2pError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to create directory {:?}: {}", parent, e),
                ))
            })?;
        }
    }

    // Save as raw Ed25519 secret key (32 bytes) for simplicity
    let secret = keypair
        .clone()
        .try_into_ed25519()
        .map_err(|_| P2pError::Transport("Expected Ed25519 keypair".to_string()))?;

    let secret_key = secret.secret();
    let secret_bytes = secret_key.as_ref();
    fs::write(path, secret_bytes).map_err(|e| {
        P2pError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to write node key to {:?}: {}", path, e),
        ))
    })?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600); // Owner read/write only
        fs::set_permissions(path, perms)?;
    }

    info!("Generated and saved new node key to {:?}", path);
    warn!("⚠️  Back up your node key file! Loss means a new peer identity.");

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_load_keypair() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("node.key");

        // Generate new key
        let keypair1 = generate_and_save_keypair(&key_path).unwrap();
        let peer_id1 = PeerId::from(keypair1.public());

        // Load existing key
        let keypair2 = load_keypair(&key_path).unwrap();
        let peer_id2 = PeerId::from(keypair2.public());

        // Should have same peer ID
        assert_eq!(peer_id1, peer_id2);
    }

    #[test]
    fn test_load_or_generate_creates_new() {
        let dir = TempDir::new().unwrap();
        let key_path = dir.path().join("new_node.key");

        assert!(!key_path.exists());

        let keypair = load_or_generate_keypair(Some(&key_path)).unwrap();
        let peer_id = PeerId::from(keypair.public());

        assert!(key_path.exists());

        // Load again and verify same ID
        let keypair2 = load_or_generate_keypair(Some(&key_path)).unwrap();
        assert_eq!(peer_id, PeerId::from(keypair2.public()));
    }

    #[test]
    fn test_ephemeral_key_when_no_path() {
        let keypair1 = load_or_generate_keypair(None).unwrap();
        let keypair2 = load_or_generate_keypair(None).unwrap();

        // Different keys each time
        assert_ne!(
            PeerId::from(keypair1.public()),
            PeerId::from(keypair2.public())
        );
    }
}

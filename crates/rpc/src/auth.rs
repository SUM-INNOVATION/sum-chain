//! RPC authentication middleware.
//!
//! Provides API key authentication for the JSON-RPC server.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// RPC authentication configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RpcAuthConfig {
    /// Enable authentication (if false, all requests are allowed)
    #[serde(default)]
    pub enabled: bool,

    /// Valid API keys (if empty and enabled, no requests are allowed)
    #[serde(default)]
    pub api_keys: Vec<String>,

    /// Methods that don't require authentication (e.g., health checks)
    #[serde(default)]
    pub public_methods: Vec<String>,
}

impl RpcAuthConfig {
    /// Create config with authentication disabled
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            api_keys: Vec::new(),
            public_methods: Vec::new(),
        }
    }

    /// Create config with a single API key
    pub fn with_api_key(api_key: String) -> Self {
        Self {
            enabled: true,
            api_keys: vec![api_key],
            public_methods: default_public_methods(),
        }
    }

    /// Create config with multiple API keys
    pub fn with_api_keys(api_keys: Vec<String>) -> Self {
        Self {
            enabled: true,
            api_keys,
            public_methods: default_public_methods(),
        }
    }
}

/// Default methods that don't require authentication
fn default_public_methods() -> Vec<String> {
    vec![
        "health".to_string(),
        "chain_id".to_string(),
        "eth_blockNumber".to_string(),
    ]
}

/// API key validator
#[derive(Debug, Clone)]
pub struct ApiKeyValidator {
    enabled: bool,
    valid_keys: Arc<RwLock<HashSet<String>>>,
    public_methods: HashSet<String>,
}

impl ApiKeyValidator {
    /// Create a new validator from config
    pub fn new(config: &RpcAuthConfig) -> Self {
        let valid_keys: HashSet<String> = config.api_keys.iter().cloned().collect();
        let public_methods: HashSet<String> = config.public_methods.iter().cloned().collect();

        Self {
            enabled: config.enabled,
            valid_keys: Arc::new(RwLock::new(valid_keys)),
            public_methods,
        }
    }

    /// Check if authentication is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Validate an API key
    pub fn validate_key(&self, api_key: &str) -> bool {
        if !self.enabled {
            return true;
        }
        self.valid_keys.read().contains(api_key)
    }

    /// Check if a method is public (doesn't require auth)
    pub fn is_public_method(&self, method: &str) -> bool {
        self.public_methods.contains(method)
    }

    /// Add a new API key at runtime
    pub fn add_key(&self, api_key: String) {
        self.valid_keys.write().insert(api_key);
    }

    /// Remove an API key at runtime
    pub fn remove_key(&self, api_key: &str) {
        self.valid_keys.write().remove(api_key);
    }

    /// Validate a request
    /// Returns Ok(()) if authorized, Err with message if not
    pub fn authorize(&self, method: &str, api_key: Option<&str>) -> std::result::Result<(), String> {
        // If auth is disabled, allow all
        if !self.enabled {
            return Ok(());
        }

        // If method is public, allow without key
        if self.is_public_method(method) {
            return Ok(());
        }

        // Require valid API key
        match api_key {
            Some(key) if self.validate_key(key) => Ok(()),
            Some(_) => Err("Invalid API key".to_string()),
            None => Err("API key required. Use X-API-Key header or ?api_key= query param".to_string()),
        }
    }
}

/// Generate a random API key
pub fn generate_api_key() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_auth() {
        let config = RpcAuthConfig::disabled();
        let validator = ApiKeyValidator::new(&config);

        assert!(!validator.is_enabled());
        assert!(validator.authorize("send_raw_transaction", None).is_ok());
    }

    #[test]
    fn test_enabled_auth() {
        let config = RpcAuthConfig::with_api_key("test-key-123".to_string());
        let validator = ApiKeyValidator::new(&config);

        assert!(validator.is_enabled());

        // Public method works without key
        assert!(validator.authorize("health", None).is_ok());

        // Private method requires key
        assert!(validator.authorize("send_raw_transaction", None).is_err());

        // Valid key works
        assert!(validator.authorize("send_raw_transaction", Some("test-key-123")).is_ok());

        // Invalid key fails
        assert!(validator.authorize("send_raw_transaction", Some("wrong-key")).is_err());
    }

    #[test]
    fn test_runtime_key_management() {
        let config = RpcAuthConfig::with_api_key("initial-key".to_string());
        let validator = ApiKeyValidator::new(&config);

        // Initial key works
        assert!(validator.validate_key("initial-key"));

        // Add new key
        validator.add_key("new-key".to_string());
        assert!(validator.validate_key("new-key"));

        // Remove key
        validator.remove_key("initial-key");
        assert!(!validator.validate_key("initial-key"));
    }

    #[test]
    fn test_generate_api_key() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();

        // Keys should be 64 hex chars (32 bytes)
        assert_eq!(key1.len(), 64);
        assert_eq!(key2.len(), 64);

        // Keys should be unique
        assert_ne!(key1, key2);
    }
}

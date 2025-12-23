//! Security Feature Tests
//!
//! Tests for NFT security features:
//! - Per-byte storage pricing (prevents state bloat attacks)
//! - Issuer registry (prevents unauthorized document minting)

use std::sync::Arc;

use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_nft::collection::CollectionConfig;
use sumchain_primitives::{Address, NftOperation, NftTxData};
use sumchain_state::{NftExecutor, StateManager};
use sumchain_storage::{Database, IssuerData, IssuerStore, NftStore};
use tempfile::TempDir;

/// Helper to generate key bytes for tests
fn generate_key_bytes() -> [u8; 32] {
    *KeyPair::generate().private_key().as_bytes()
}

/// Security test node
struct SecurityTestNode {
    db: Arc<Database>,
    state: Arc<StateManager>,
    nft_executor: NftExecutor,
    validator_key_bytes: [u8; 32],
    params: ChainParams,
    chain_id: u64,
    #[allow(dead_code)]
    data_dir: TempDir,
}

impl SecurityTestNode {
    fn new(validator_key_bytes: [u8; 32], chain_id: u64) -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let db = Arc::new(Database::open_default(data_dir.path()).expect("Failed to open database"));
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        let params = ChainParams::default();
        let nft_executor = NftExecutor::new(db.clone(), params.clone());

        // Create validator key from bytes
        let validator_key = KeyPair::from_bytes(validator_key_bytes);

        // Fund the validator generously
        state
            .put_account(
                &validator_key.address(),
                &sumchain_storage::schema::AccountState {
                    balance: 1_000_000_000_000_000, // 1M Koppa
                    nonce: 0,
                },
            )
            .expect("Failed to fund validator");

        Self {
            db,
            state,
            nft_executor,
            validator_key_bytes,
            params,
            chain_id,
            data_dir,
        }
    }

    fn validator_key(&self) -> KeyPair {
        KeyPair::from_bytes(self.validator_key_bytes)
    }

    fn validator_address(&self) -> Address {
        self.validator_key().address()
    }

    fn nft_store(&self) -> NftStore<'_> {
        NftStore::new(&self.db)
    }

    fn issuer_store(&self) -> IssuerStore<'_> {
        IssuerStore::new(&self.db)
    }

    /// Register an issuer in the registry
    fn register_issuer(&self, address: &Address, name: &str, domain: &str) -> Result<(), String> {
        let issuer_store = self.issuer_store();
        let issuer_data = IssuerData {
            address: *address,
            name: name.to_string(),
            domain: domain.to_string(),
            org_type: 0, // Educational
            country_code: "US".to_string(),
            status: 0, // Active
            allowed_doc_types: vec![], // All types
            registered_at: 1000,
            updated_at: 1000,
            expires_at: 0, // No expiry
            metadata: None,
        };

        issuer_store
            .put_issuer(address, &issuer_data)
            .map_err(|e| format!("Failed to register issuer: {}", e))
    }

    /// Create a collection for testing
    fn create_collection(&self, config: CollectionConfig) -> Result<[u8; 32], String> {
        let store = self.nft_store();
        let sender = self.validator_address();

        #[derive(serde::Serialize)]
        struct CreateData {
            name: String,
            symbol: String,
            description: String,
            config: CollectionConfig,
            base_uri: Option<String>,
        }

        let create_data = CreateData {
            name: "Test Collection".to_string(),
            symbol: "TEST".to_string(),
            description: "Test".to_string(),
            config,
            base_uri: None,
        };

        let nft_data = NftTxData {
            operation: NftOperation::CreateCollection,
            collection_id: [0u8; 32],
            token_id: 0,
            data: bincode::serialize(&create_data).unwrap(),
        };

        let result = self
            .nft_executor
            .execute(
                &sender,
                &nft_data,
                &self.state,
                &sender,
                self.params.min_fee,
            )
            .map_err(|e| format!("Failed to create collection: {}", e))?;

        if result.success {
            Ok(result.collection_id.expect("Missing collection ID"))
        } else {
            Err(result.error.unwrap_or_else(|| "Unknown error".to_string()))
        }
    }

    /// Attempt to mint a token with specific fee and metadata size
    fn mint_token_with_fee(
        &self,
        collection_id: &[u8; 32],
        metadata_size: usize,
        fee: u128,
        is_document: bool,
    ) -> Result<u64, String> {
        let store = self.nft_store();
        let sender = self.validator_address();

        #[derive(serde::Serialize)]
        struct MintData {
            to: Address,
            metadata: Vec<u8>,
            uri_type: String,
            uri_value: Option<String>,
        }

        let mint_data = MintData {
            to: sender,
            metadata: vec![0u8; metadata_size],
            uri_type: "onchain".to_string(),
            uri_value: None,
        };

        let nft_data = NftTxData {
            operation: if is_document {
                NftOperation::MintDocument
            } else {
                NftOperation::Mint
            },
            collection_id: *collection_id,
            token_id: 0,
            data: bincode::serialize(&mint_data).unwrap(),
        };

        let result = self
            .nft_executor
            .execute(&sender, &nft_data, &self.state, &sender, fee)
            .map_err(|e| format!("Failed to mint token: {}", e))?;

        if result.success {
            Ok(result.token_id.expect("Missing token ID"))
        } else {
            Err(result.error.unwrap_or_else(|| "Unknown error".to_string()))
        }
    }
}

// ============================================================================
// Per-byte Storage Pricing Tests
// ============================================================================

#[test]
fn test_storage_fee_calculation() {
    let params = ChainParams::default();

    // Test fee calculation
    let fee_0 = params.calculate_nft_storage_fee(0);
    let fee_100 = params.calculate_nft_storage_fee(100);
    let fee_1000 = params.calculate_nft_storage_fee(1000);

    // Fee should be min_fee + (bytes * storage_fee_per_byte)
    assert_eq!(fee_0, params.min_fee);
    assert_eq!(fee_100, params.min_fee + 100 * params.storage_fee_per_byte);
    assert_eq!(fee_1000, params.min_fee + 1000 * params.storage_fee_per_byte);

    // Larger metadata = higher fee
    assert!(fee_100 > fee_0);
    assert!(fee_1000 > fee_100);
}

#[test]
fn test_metadata_size_validation() {
    let params = ChainParams::default();

    // Default max is 16KB
    assert!(params.validate_metadata_size(0));
    assert!(params.validate_metadata_size(1000));
    assert!(params.validate_metadata_size(16384)); // Exactly 16KB
    assert!(!params.validate_metadata_size(16385)); // Over limit
    assert!(!params.validate_metadata_size(100_000)); // Way over limit
}

#[test]
fn test_mint_with_insufficient_fee_fails() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    // Create a collection
    let collection_id = node.create_collection(CollectionConfig::default()).unwrap();

    // Calculate required fee for 1000 bytes of metadata
    let metadata_size = 1000;
    let required_fee = node.params.calculate_nft_storage_fee(metadata_size);

    // Try to mint with insufficient fee (below minimum)
    let result = node.mint_token_with_fee(&collection_id, metadata_size, required_fee - 1, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Insufficient storage fee"));
}

#[test]
fn test_mint_with_sufficient_fee_succeeds() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    // Create a collection
    let collection_id = node.create_collection(CollectionConfig::default()).unwrap();

    // Calculate required fee for 1000 bytes of metadata
    let metadata_size = 1000;
    let required_fee = node.params.calculate_nft_storage_fee(metadata_size);

    // Mint with exact required fee
    let result = node.mint_token_with_fee(&collection_id, metadata_size, required_fee, false);
    assert!(result.is_ok());

    // Mint with more than required fee
    let result2 = node.mint_token_with_fee(&collection_id, metadata_size, required_fee * 2, false);
    assert!(result2.is_ok());
}

#[test]
fn test_mint_with_oversized_metadata_fails() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    // Create a collection
    let collection_id = node.create_collection(CollectionConfig::default()).unwrap();

    // Try to mint with oversized metadata (> 16KB default)
    let oversized = 20_000; // 20KB
    let fee = node.params.calculate_nft_storage_fee(oversized);

    let result = node.mint_token_with_fee(&collection_id, oversized, fee, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Metadata too large"));
}

// ============================================================================
// Issuer Registry Tests
// ============================================================================

#[test]
fn test_document_mint_by_unregistered_issuer_fails() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    // Create a certified document collection
    let mut config = CollectionConfig::certified_document();
    config.royalty_recipient = node.validator_address();
    let collection_id = node.create_collection(config).unwrap();

    // Try to mint a document WITHOUT being registered as an issuer
    let metadata_size = 100;
    let fee = node.params.calculate_nft_storage_fee(metadata_size) * 2; // More than enough

    let result = node.mint_token_with_fee(&collection_id, metadata_size, fee, true);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not a registered document issuer"));
}

#[test]
fn test_document_mint_by_registered_issuer_succeeds() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    // Register the validator as an issuer
    let validator_addr = node.validator_address();
    node.register_issuer(&validator_addr, "Test University", "test.edu")
        .unwrap();

    // Create a certified document collection
    let mut config = CollectionConfig::certified_document();
    config.royalty_recipient = validator_addr;
    let collection_id = node.create_collection(config).unwrap();

    // Now minting a document should succeed
    let metadata_size = 100;
    let fee = node.params.calculate_nft_storage_fee(metadata_size) * 2;

    let result = node.mint_token_with_fee(&collection_id, metadata_size, fee, true);
    assert!(result.is_ok());
}

#[test]
fn test_regular_mint_does_not_require_issuer_registration() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    // Create a regular (non-document) collection
    let collection_id = node.create_collection(CollectionConfig::default()).unwrap();

    // Minting regular NFTs should NOT require issuer registration
    let metadata_size = 100;
    let fee = node.params.calculate_nft_storage_fee(metadata_size) * 2;

    let result = node.mint_token_with_fee(&collection_id, metadata_size, fee, false);
    assert!(result.is_ok());
}

#[test]
fn test_issuer_store_operations() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    let issuer_store = node.issuer_store();
    let addr = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

    // Initially not registered
    assert!(!issuer_store.is_registered(&addr).unwrap());
    assert!(!issuer_store.can_mint_documents(&addr, None, 1000).unwrap());

    // Register issuer
    let issuer_data = IssuerData {
        address: addr,
        name: "Test Issuer".to_string(),
        domain: "test.org".to_string(),
        org_type: 0,
        country_code: "US".to_string(),
        status: 0, // Active
        allowed_doc_types: vec!["degree".to_string()],
        registered_at: 1000,
        updated_at: 1000,
        expires_at: 0,
        metadata: None,
    };

    issuer_store.put_issuer(&addr, &issuer_data).unwrap();

    // Now registered
    assert!(issuer_store.is_registered(&addr).unwrap());
    assert!(issuer_store.can_mint_documents(&addr, None, 1000).unwrap());
    assert!(issuer_store.can_mint_documents(&addr, Some("degree"), 1000).unwrap());
    assert!(!issuer_store.can_mint_documents(&addr, Some("license"), 1000).unwrap());
}

#[test]
fn test_suspended_issuer_cannot_mint() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    let issuer_store = node.issuer_store();
    let addr = Address::from_hex("0x0000000000000000000000000000000000000002").unwrap();

    // Register a suspended issuer
    let issuer_data = IssuerData {
        address: addr,
        name: "Suspended Issuer".to_string(),
        domain: "suspended.org".to_string(),
        org_type: 0,
        country_code: "US".to_string(),
        status: 1, // Suspended
        allowed_doc_types: vec![],
        registered_at: 1000,
        updated_at: 1000,
        expires_at: 0,
        metadata: None,
    };

    issuer_store.put_issuer(&addr, &issuer_data).unwrap();

    // Suspended issuer cannot mint
    assert!(issuer_store.is_registered(&addr).unwrap());
    assert!(!issuer_store.can_mint_documents(&addr, None, 1000).unwrap());
}

#[test]
fn test_expired_issuer_cannot_mint() {
    let key_bytes = generate_key_bytes();
    let node = SecurityTestNode::new(key_bytes, 1);

    let issuer_store = node.issuer_store();
    let addr = Address::from_hex("0x0000000000000000000000000000000000000003").unwrap();

    // Register an expired issuer
    let issuer_data = IssuerData {
        address: addr,
        name: "Expired Issuer".to_string(),
        domain: "expired.org".to_string(),
        org_type: 0,
        country_code: "US".to_string(),
        status: 0, // Active
        allowed_doc_types: vec![],
        registered_at: 1000,
        updated_at: 1000,
        expires_at: 5000, // Expired at 5000
        metadata: None,
    };

    issuer_store.put_issuer(&addr, &issuer_data).unwrap();

    // Before expiry - can mint
    assert!(issuer_store.can_mint_documents(&addr, None, 4000).unwrap());

    // After expiry - cannot mint
    assert!(!issuer_store.can_mint_documents(&addr, None, 6000).unwrap());
}

//! NFT (SUM-721) Integration Tests
//!
//! Tests for NFT collection creation, minting, transfers, and document certification.

use std::sync::Arc;

use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_nft::collection::CollectionConfig;
use sumchain_primitives::{Address, NftOperation, NftTxData};
use sumchain_state::{NftExecutor, StateManager};
use sumchain_storage::candidate::CandidateExecution;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::Database;
use tempfile::TempDir;

/// Helper to generate key bytes for tests
fn generate_key_bytes() -> [u8; 32] {
    *KeyPair::generate().private_key().as_bytes()
}

/// NFT test node with direct access to NFT executor
struct NftTestNode {
    db: Arc<Database>,
    state: Arc<StateManager>,
    params: ChainParams,
    validator_key_bytes: [u8; 32],
    #[allow(dead_code)]
    chain_id: u64,
    #[allow(dead_code)]
    data_dir: TempDir,
}

impl NftTestNode {
    fn new(validator_key_bytes: [u8; 32], chain_id: u64) -> Self {
        let data_dir = TempDir::new().expect("Failed to create temp dir");
        let db = Arc::new(Database::open_default(data_dir.path()).expect("Failed to open database"));
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        let params = ChainParams::default();

        // Create validator key from bytes
        let validator_key = KeyPair::from_bytes(validator_key_bytes);

        // Fund the validator
        sumchain_storage::StateStore::new(&db).put_account(
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
            params,
            validator_key_bytes,
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

    /// One candidate for one block.
    ///
    /// The executor stages into the block's candidate now, so these fixtures
    /// open one and thread it through every operation in the scenario. A fresh
    /// candidate per operation would be a fresh block per operation: the mint
    /// would not see the collection the create staged. Nothing here is ever
    /// published — the subject is NFT semantics, not canonical state — so the
    /// assertions read the candidate back through `NftExecutor::v_*`.
    fn candidate(&self) -> CandidateExecution<'_> {
        CandidateExecution::new(&self.db, 1 << 30)
    }

    /// Create collection with given config
    fn create_collection(
        &self,
        view: &mut ExecutionView<'_, '_>,
        name: &str,
        symbol: &str,
        config: CollectionConfig,
    ) -> Result<[u8; 32], String> {
        #[derive(serde::Serialize)]
        struct CreateCollectionData {
            name: String,
            symbol: String,
            description: String,
            config: CollectionConfig,
            base_uri: Option<String>,
        }

        let data = CreateCollectionData {
            name: name.to_string(),
            symbol: symbol.to_string(),
            description: format!("Test collection: {}", name),
            config,
            base_uri: None,
        };

        let serialized = bincode::serialize(&data).expect("Failed to serialize");

        let nft_data = NftTxData {
            collection_id: [0u8; 32], // Not used for creation
            token_id: 0,
            operation: NftOperation::CreateCollection,
            data: serialized,
        };

        let result = NftExecutor::execute(
            view,
            &self.params,
            &self.validator_address(),
            &nft_data,
            &Address::ZERO,
            0,
            1000000000, // block_timestamp
            0,          // block_height: the gate is dormant, so any height behaves alike
        )
        .map_err(|e| e.to_string())?;

        if result.success {
            Ok(result.collection_id.unwrap())
        } else {
            Err(result.error.unwrap_or("Unknown error".to_string()))
        }
    }

    /// Mint a token in a collection
    fn mint_token(
        &self,
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        to: Address,
        metadata: &[u8],
    ) -> Result<u64, String> {
        #[derive(serde::Serialize)]
        struct MintData {
            to: Address,
            metadata: Vec<u8>,
            uri_type: String,
            uri_value: Option<String>,
        }

        let data = MintData {
            to,
            metadata: metadata.to_vec(),
            uri_type: "onchain".to_string(),
            uri_value: None,
        };

        let serialized = bincode::serialize(&data).expect("Failed to serialize");

        let nft_data = NftTxData {
            collection_id: *collection_id,
            token_id: 0,
            operation: NftOperation::Mint,
            data: serialized,
        };

        // Calculate the required storage fee for the metadata
        let storage_fee = self.params.calculate_nft_storage_fee(metadata.len());

        let result = NftExecutor::execute(
            view,
            &self.params,
            &self.validator_address(),
            &nft_data,
            &Address::ZERO,
            storage_fee,
            1000000000, // block_timestamp
            0,          // block_height: the gate is dormant, so any height behaves alike
        )
        .map_err(|e| e.to_string())?;

        if result.success {
            Ok(result.token_id.unwrap())
        } else {
            Err(result.error.unwrap_or("Unknown error".to_string()))
        }
    }

    /// Transfer a token
    fn transfer_token(
        &self,
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
        to: Address,
    ) -> Result<(), String> {
        #[derive(serde::Serialize)]
        struct TransferData {
            to: Address,
        }

        let data = TransferData { to };
        let serialized = bincode::serialize(&data).expect("Failed to serialize");

        let nft_data = NftTxData {
            collection_id: *collection_id,
            token_id,
            operation: NftOperation::Transfer,
            data: serialized,
        };

        let result = NftExecutor::execute(
            view,
            &self.params,
            &self.validator_address(),
            &nft_data,
            &Address::ZERO,
            0,
            1000000000, // block_timestamp
            0,          // block_height: the gate is dormant, so any height behaves alike
        )
        .map_err(|e| e.to_string())?;

        if result.success {
            Ok(())
        } else {
            Err(result.error.unwrap_or("Unknown error".to_string()))
        }
    }

    /// Burn a token
    fn burn_token(
        &self,
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<(), String> {
        let nft_data = NftTxData {
            collection_id: *collection_id,
            token_id,
            operation: NftOperation::Burn,
            data: vec![],
        };

        let result = NftExecutor::execute(
            view,
            &self.params,
            &self.validator_address(),
            &nft_data,
            &Address::ZERO,
            0,
            1000000000, // block_timestamp
            0,          // block_height: the gate is dormant, so any height behaves alike
        )
        .map_err(|e| e.to_string())?;

        if result.success {
            Ok(())
        } else {
            Err(result.error.unwrap_or("Unknown error".to_string()))
        }
    }
}

// ============================================================================
// Collection Tests
// ============================================================================

#[test]
fn test_create_collection_default_config() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let collection_id = node
        .create_collection(
            &mut view,
            "Test Collection",
            "TEST",
            CollectionConfig::default(),
        )
        .expect("Should create collection");

    // Verify collection exists
    let collection = NftExecutor::v_get_collection(&view, &collection_id)
        .expect("Should query")
        .expect("Collection exists");

    assert_eq!(collection.name, "Test Collection");
    assert_eq!(collection.symbol, "TEST");
    assert_eq!(collection.owner, node.validator_address());
    assert_eq!(collection.total_supply, 0);
    assert_eq!(collection.next_token_id, 1);
}

#[test]
fn test_create_certified_document_collection() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    // Create non-transferable, non-burnable collection for documents
    let config = CollectionConfig::certified_document();
    let collection_id = node
        .create_collection(&mut view, "University Degrees", "DEGREE", config)
        .expect("Should create collection");

    let collection = NftExecutor::v_get_collection(&view, &collection_id)
        .expect("Should query")
        .expect("Collection exists");

    assert_eq!(collection.name, "University Degrees");
    assert!(!collection.transferable); // Documents cannot be transferred
    assert!(!collection.burnable); // Documents cannot be burned
    assert!(collection.owner_only_minting); // Only owner can mint
}

#[test]
fn test_create_collectible_collection() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    // Create transferable collection with royalties
    let mut config = CollectionConfig::collectible();
    config.royalty_recipient = node.validator_address(); // Set royalty recipient
    let collection_id = node
        .create_collection(&mut view, "Art Collection", "ART", config)
        .expect("Should create collection");

    let collection = NftExecutor::v_get_collection(&view, &collection_id)
        .expect("Should query")
        .expect("Collection exists");

    assert!(collection.transferable);
    assert!(collection.burnable);
    assert_eq!(collection.royalty_bps, 250); // 2.5% royalty
}

// ============================================================================
// Minting Tests
// ============================================================================

#[test]
fn test_mint_single_token() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let collection_id = node
        .create_collection(&mut view, "Test", "TST", CollectionConfig::default())
        .expect("Should create collection");

    let metadata = b"{'name': 'Token #1', 'description': 'First token'}";
    let token_id = node
        .mint_token(
            &mut view,
            &collection_id,
            node.validator_address(),
            metadata,
        )
        .expect("Should mint token");

    assert_eq!(token_id, 1);

    // Verify token
    let token = NftExecutor::v_get_token(&view, &collection_id, token_id)
        .expect("Should query")
        .expect("Token exists");

    assert_eq!(token.owner, node.validator_address());
    assert_eq!(token.creator, node.validator_address());
    assert!(!token.is_document);
    assert!(!token.locked);

    // Verify collection supply updated
    let collection = NftExecutor::v_get_collection(&view, &collection_id)
        .expect("Should query")
        .expect("Collection exists");

    assert_eq!(collection.total_supply, 1);
    assert_eq!(collection.next_token_id, 2);
}

#[test]
fn test_mint_multiple_tokens() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let collection_id = node
        .create_collection(&mut view, "Multi", "MULTI", CollectionConfig::default())
        .expect("Should create collection");

    // Mint 5 tokens. Each one reads the `next_token_id` the previous one wrote,
    // so this only counts up through the candidate.
    for i in 1..=5 {
        let metadata = format!("{{'name': 'Token #{}'}}", i).into_bytes();
        let token_id = node
            .mint_token(
                &mut view,
                &collection_id,
                node.validator_address(),
                &metadata,
            )
            .expect("Should mint token");
        assert_eq!(token_id, i);
    }

    // Verify collection
    let collection = NftExecutor::v_get_collection(&view, &collection_id)
        .expect("Should query")
        .expect("Collection exists");

    assert_eq!(collection.total_supply, 5);
    assert_eq!(collection.next_token_id, 6);

    // Verify owner tokens
    let tokens =
        NftExecutor::v_get_owner_tokens(&view, &node.validator_address()).expect("Should query");
    assert_eq!(tokens.len(), 5);
}

#[test]
fn test_mint_to_different_address() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let recipient = KeyPair::generate();
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let collection_id = node
        .create_collection(&mut view, "Gift", "GIFT", CollectionConfig::default())
        .expect("Should create collection");

    let token_id = node
        .mint_token(
            &mut view,
            &collection_id,
            recipient.address(),
            b"gift token",
        )
        .expect("Should mint token");

    // Verify ownership
    let token = NftExecutor::v_get_token(&view, &collection_id, token_id)
        .expect("Should query")
        .expect("Token exists");

    assert_eq!(token.owner, recipient.address());
    assert_eq!(token.creator, node.validator_address()); // Creator is still minter

    // Check owner index
    let recipient_tokens =
        NftExecutor::v_get_owner_tokens(&view, &recipient.address()).expect("Should query");
    assert_eq!(recipient_tokens.len(), 1);
    assert_eq!(recipient_tokens[0].0.as_slice(), collection_id.as_slice());
    assert_eq!(recipient_tokens[0].1, token_id);
}

// ============================================================================
// Transfer Tests
// ============================================================================

#[test]
fn test_transfer_token() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let recipient = KeyPair::generate();
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let config = CollectionConfig {
        transferable: true,
        ..Default::default()
    };
    let collection_id = node
        .create_collection(&mut view, "Transfer", "XFER", config)
        .expect("Should create collection");

    let token_id = node
        .mint_token(
            &mut view,
            &collection_id,
            node.validator_address(),
            b"transferable",
        )
        .expect("Should mint token");

    // Transfer to recipient
    node.transfer_token(&mut view, &collection_id, token_id, recipient.address())
        .expect("Should transfer");

    // Verify new ownership
    let token = NftExecutor::v_get_token(&view, &collection_id, token_id)
        .expect("Should query")
        .expect("Token exists");

    assert_eq!(token.owner, recipient.address());
    assert_eq!(token.transfer_count, 1);

    // Verify owner indices updated
    let validator_tokens =
        NftExecutor::v_get_owner_tokens(&view, &node.validator_address()).expect("Should query");
    assert_eq!(validator_tokens.len(), 0);

    let recipient_tokens =
        NftExecutor::v_get_owner_tokens(&view, &recipient.address()).expect("Should query");
    assert_eq!(recipient_tokens.len(), 1);
}

#[test]
fn test_transfer_non_transferable_fails() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let recipient = KeyPair::generate();
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    // Create non-transferable collection
    let config = CollectionConfig {
        transferable: false,
        ..Default::default()
    };
    let collection_id = node
        .create_collection(&mut view, "Soulbound", "SOUL", config)
        .expect("Should create collection");

    let token_id = node
        .mint_token(
            &mut view,
            &collection_id,
            node.validator_address(),
            b"soulbound",
        )
        .expect("Should mint token");

    // Transfer should fail
    let result = node.transfer_token(&mut view, &collection_id, token_id, recipient.address());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not allow transfers"));
}

// ============================================================================
// Burn Tests
// ============================================================================

#[test]
fn test_burn_token() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let config = CollectionConfig {
        burnable: true,
        ..Default::default()
    };
    let collection_id = node
        .create_collection(&mut view, "Burnable", "BURN", config)
        .expect("Should create collection");

    let token_id = node
        .mint_token(
            &mut view,
            &collection_id,
            node.validator_address(),
            b"to be burned",
        )
        .expect("Should mint token");

    // Burn token
    node.burn_token(&mut view, &collection_id, token_id)
        .expect("Should burn");

    // Verify token is gone
    let token = NftExecutor::v_get_token(&view, &collection_id, token_id).expect("Should query");
    assert!(token.is_none());

    // Supply should NOT decrease (we track total minted, not current supply)
    // But owner index should be updated
    let owner_tokens =
        NftExecutor::v_get_owner_tokens(&view, &node.validator_address()).expect("Should query");
    assert_eq!(owner_tokens.len(), 0);
}

#[test]
fn test_burn_non_burnable_fails() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let config = CollectionConfig {
        burnable: false,
        ..Default::default()
    };
    let collection_id = node
        .create_collection(&mut view, "Permanent", "PERM", config)
        .expect("Should create collection");

    let token_id = node
        .mint_token(
            &mut view,
            &collection_id,
            node.validator_address(),
            b"permanent",
        )
        .expect("Should mint token");

    let result = node.burn_token(&mut view, &collection_id, token_id);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not allow burns"));
}

// ============================================================================
// Max Supply Tests
// ============================================================================

#[test]
fn test_max_supply_enforcement() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let config = CollectionConfig {
        max_supply: 3,
        ..Default::default()
    };
    let collection_id = node
        .create_collection(&mut view, "Limited", "LTD", config)
        .expect("Should create collection");

    // Mint up to max
    for i in 1..=3 {
        let token_id = node
            .mint_token(
                &mut view,
                &collection_id,
                node.validator_address(),
                b"limited",
            )
            .expect("Should mint token");
        assert_eq!(token_id, i);
    }

    // Next mint should fail. The supply guard reads the candidate: against
    // committed state every mint above would have seen total_supply 0.
    let result = node.mint_token(
        &mut view,
        &collection_id,
        node.validator_address(),
        b"overflow",
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Max supply reached"));
}

// ============================================================================
// Query Tests
// ============================================================================

#[test]
fn test_owner_token_count() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    // Create multiple collections and tokens
    let col1 = node
        .create_collection(&mut view, "Col1", "C1", CollectionConfig::default())
        .expect("Should create");
    let col2 = node
        .create_collection(&mut view, "Col2", "C2", CollectionConfig::default())
        .expect("Should create");

    // Mint tokens in both collections
    node.mint_token(&mut view, &col1, node.validator_address(), b"c1t1")
        .expect("Should mint");
    node.mint_token(&mut view, &col1, node.validator_address(), b"c1t2")
        .expect("Should mint");
    node.mint_token(&mut view, &col2, node.validator_address(), b"c2t1")
        .expect("Should mint");

    let count = NftExecutor::v_get_owner_tokens(&view, &node.validator_address())
        .expect("Should query")
        .len() as u64;

    assert_eq!(count, 3);
}

#[test]
fn test_collection_token_list() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let collection_id = node
        .create_collection(&mut view, "Multi", "M", CollectionConfig::default())
        .expect("Should create");

    for _ in 0..5 {
        node.mint_token(
            &mut view,
            &collection_id,
            node.validator_address(),
            b"token",
        )
        .expect("Should mint");
    }

    let tokens = NftExecutor::v_get_collection_tokens(&view, &collection_id).expect("Should query");

    assert_eq!(tokens.len(), 5);
    assert_eq!(tokens, vec![1, 2, 3, 4, 5]);
}

#[test]
fn test_token_exists() {
    let validator_bytes = generate_key_bytes();
    let node = NftTestNode::new(validator_bytes, 1);
    let mut candidate = node.candidate();
    let mut view = candidate.view();

    let collection_id = node
        .create_collection(&mut view, "Exists", "EX", CollectionConfig::default())
        .expect("Should create");

    let token_id = node
        .mint_token(
            &mut view,
            &collection_id,
            node.validator_address(),
            b"exists",
        )
        .expect("Should mint");

    assert!(NftExecutor::v_token_exists(&view, &collection_id, token_id).expect("Should query"));
    assert!(!NftExecutor::v_token_exists(&view, &collection_id, 999).expect("Should query"));
    assert!(!NftExecutor::v_token_exists(&view, &[0u8; 32], 1).expect("Should query"));
}

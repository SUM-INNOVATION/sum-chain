//! Unique-allocation genesis files keep their identity across #276.
//!
//! Every value below was computed by the loader BEFORE #276 (main at
//! 2483a7b1) from the committed genesis fixtures. The canonical allocation
//! path must reproduce each exactly: the genesis block hash, the genesis state
//! root (also what state initialization returns), the activation digest, the
//! protocol digest, and the balances written by initialization.
//!
//! The activation and protocol digests are the exception, by design: both
//! cover EVERY gate `ChainParams` declares, dormant ones included, so adding a
//! gate moves them for every genesis. Their pins were recomputed when
//! `credential_schema_validation_enabled_from_height` (#277) and
//! `contract_error_rollback_enabled_from_height` (#279) were declared; the
//! block hash, state root and balances are unchanged.

use std::sync::Arc;

use sumchain_genesis::Genesis;
use sumchain_primitives::Hash;
use sumchain_state::StateManager;
use sumchain_storage::{Database, StateStore};

struct Pin {
    file: &'static str,
    block: &'static str,
    root: &'static str,
    activation: &'static str,
    protocol: &'static str,
    /// BLAKE3 over (address ‖ stored balance, big-endian) in address order,
    /// read back after `init_from_genesis`.
    balances: &'static str,
}

const PINS: &[Pin] = &[
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-1v.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0x0e5916f9e08b645ce9513a26b8f993208c74b19fd62c6428c36b2682d0949806",
        protocol: "0xc917ef380b34a8c9aee0827c8d52ae8de8f847b6279a27682fafcad778aa54cc",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        block: "0xf92241d3986ae1c5a30ef34e61dbec5e851ee289404e3276792dd0a27cf3083c",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0x8670618ce42fd597fa4bf4256d861c0da08e74882f464a7ca4daa12923f951f5",
        protocol: "0x36250f98fa5fc725b728ac98a7c88a145c0657b79de38237e1ca17d33fcbaaf1",
        balances: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0x3902fb74eb293b19386acae6f04489a29bd8255e1df8b93291e2f12ee5a85901",
        protocol: "0xd7c607370a39ed0e5c3da04fc1333f231b0084f1e89a7f39a6b41ae905c389b5",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0x30e46b9a6c8d22add9fd901672a8e5afbe59314c64484e328e1cebf42ea4c965",
        protocol: "0x48598656f58585f4a9b9905b75e416a5a5ca2e9f974ceee735dad17d6bb20f9f",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "genesis.json",
        block: "0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6",
        root: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
        activation: "0x2e2f20241e896411a3d6098d026c8e79c40cd44d3494fceeb86bc4fcfff75a7e",
        protocol: "0x29e6980adb2995cf9d9898e7d5ac3302d626a4cf13c1f9bb5e5802057337bf77",
        balances: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
    },
    Pin {
        file: "genesis/local_genesis.json",
        block: "0xe5e3fccc545ef9b0f29fb4204d4e79da04d47661e89eaebe23352abba269e1b4",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0x0fbccce75c5d12dcbbeae92604d26d69a847edfceed1adf95d33860dbaf0a37c",
        protocol: "0xc6970393bbbdea324f283497bcde21db31b159aa23cbf459975c2ce75004c53b",
        balances: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
    },
];

#[test]
fn committed_genesis_fixtures_keep_their_pre_276_identity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for pin in PINS {
        let g = Genesis::from_file(root.join(pin.file)).unwrap();
        assert_eq!(
            g.create_genesis_block().unwrap().hash().to_string(),
            pin.block,
            "{}",
            pin.file
        );
        assert_eq!(
            g.compute_state_root().unwrap().to_string(),
            pin.root,
            "{}",
            pin.file
        );
        assert_eq!(
            g.activation_digest().unwrap().to_string(),
            pin.activation,
            "{}",
            pin.file
        );
        assert_eq!(
            sumchain_state::protocol_digest::protocol_digest(&g)
                .unwrap()
                .to_string(),
            pin.protocol,
            "{}",
            pin.file
        );

        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let init = StateManager::new(db.clone(), g.chain_id)
            .init_from_genesis(&g)
            .unwrap();
        assert_eq!(init.to_string(), pin.root, "{}", pin.file);
        let store = StateStore::new(&db);
        let mut bytes = Vec::new();
        for (address, balance) in g.canonical_alloc().unwrap() {
            let stored = store.get_account(&address).unwrap().balance;
            assert_eq!(stored, balance, "{}", pin.file);
            bytes.extend_from_slice(address.as_bytes());
            bytes.extend_from_slice(&stored.to_be_bytes());
        }
        assert_eq!(Hash::hash(&bytes).to_string(), pin.balances, "{}", pin.file);
    }
}

/// The two network templates hold placeholder validator keys and are refused
/// for that, before and after #276, with the same error.
#[test]
fn placeholder_templates_are_refused_as_before() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for f in [
        "genesis/mainnet_genesis.json",
        "genesis/testnet_genesis.json",
    ] {
        let err = Genesis::from_file(root.join(f)).unwrap_err().to_string();
        assert!(
            err.starts_with("Invalid validator public key"),
            "{f}: {err}"
        );
    }
}

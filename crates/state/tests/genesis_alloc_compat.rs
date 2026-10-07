//! Unique-allocation genesis files keep their identity across #276.
//!
//! Every value below was computed by the loader BEFORE #276 (main at
//! 2483a7b1) from the committed genesis fixtures. The canonical allocation
//! path must reproduce each exactly: the genesis block hash, the genesis state
//! root (also what state initialization returns), the activation digest, the
//! protocol digest, and the balances written by initialization.
//!
//! The activation and protocol digests fold every `ChainParams` gate by name,
//! dormant ones included, so they were re-pinned when
//! `credential_schema_validation_enabled_from_height` (#277) was declared. The
//! block hash, state root and balances are unchanged by that.

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
        activation: "0xa345505c82e00ab8b0e57b08f7b2d22caaa68a64d63d70e086200e3b8755a444",
        protocol: "0x8c1b91ed6981848e14b020b1af417d5efcec9e8f602996950ab756def539f8fd",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        block: "0xf92241d3986ae1c5a30ef34e61dbec5e851ee289404e3276792dd0a27cf3083c",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0x5ff71ea21b9ea8776b3431208f8e19cd9ea8f85b651c5fa3df09d8d54ca5d8df",
        protocol: "0x615a748a8ce0f78397cfeb9095b7b5b01536722ee1ad3e00cfc53b893599c649",
        balances: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0xfbe2f166c5a562c49c5ad8ca4b9be3cda11b67536c92a498c96b53a1dd0fc654",
        protocol: "0xef4764303a4feb06f5eb3829fb1e68c1385ec6cef1058a511120fa5f50fc6e4a",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0xb6cff25d47f0f4fa9538fd160b66ddfd5f598773b79e8040024c5901601a22e2",
        protocol: "0xe1397e1375d9ab738e747d451acafc408ba64b196a6e2b321ec61aa778f82199",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "genesis.json",
        block: "0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6",
        root: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
        activation: "0x162560a43f0e043743f5ef981669cf1a9eb6b6b3f9845c7e9d0749fa88af5073",
        protocol: "0x7cb30cafb9d5d2f9876473a464e27bbc69e41e82fdd4e9b6df3def831a211bad",
        balances: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
    },
    Pin {
        file: "genesis/local_genesis.json",
        block: "0xe5e3fccc545ef9b0f29fb4204d4e79da04d47661e89eaebe23352abba269e1b4",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0x30d2b01e3416b22ee1a347d17c12640413b6b1c5f32b2006eeaf676b4857e2e3",
        protocol: "0x303944be1f40c992838b1fc9edef4834f491b7583a76e47f57c52f93609a2868",
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

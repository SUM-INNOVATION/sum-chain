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
//! gate moves them for every genesis. Their pins were recomputed, from the
//! combined tree, when `credential_schema_validation_enabled_from_height`
//! (#277), `contract_error_rollback_enabled_from_height` (#279),
//! `messaging_timestamp_units_enabled_from_height` (#278),
//! `contract_metering_enabled_from_height` (#279),
//! `node_registry_update_status_unsupported_enabled_from_height` and
//! `archive_unbonding_own_challenges_enabled_from_height` (#369, draft schema
//! 4) were declared; the block hash,
//! state root and balances -- what #276 could have changed -- are the pre-#276
//! values.

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
        activation: "0x198e8932230b5abe96532ea720615e5639adfbb0c257e3711080fb8b894a05a9",
        protocol: "0xacda2e0fc4ebcd6c48b4f194f47fef77db9baa3abcb4d5345837169ca213ed6a",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        block: "0xf92241d3986ae1c5a30ef34e61dbec5e851ee289404e3276792dd0a27cf3083c",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0x0550dd95836b4a968c491ea930759ff4293e408e762687c2133bc3e70a9d1c7b",
        protocol: "0xd0f1add431e6a54a3bc86f6f2097a8c02c3143abfd9be46f9bf5d876c158474f",
        balances: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0x5568e892f95d7defd2efc103e2c737baf8f8e59ac0bdc8e9bfedb05870239411",
        protocol: "0x2493ace1e9b2b06392e9a942a9524a4377f53769cec445b124cf8ed5616d376a",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0xd3748559c7bf9d096ce872463408e199153c3cca93f90cb6b2529b07e0f7c050",
        protocol: "0xaa56abeb3182f68e75028a6a30ab0209120a36fe0d65018e2f8b29b61027e399",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "genesis.json",
        block: "0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6",
        root: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
        activation: "0xe15146209ee16771c57a76ebf426042fe0bc6571b89302ced2038039a39cc406",
        protocol: "0x58d683b129008ad345ac3c2afb4af11207b27f1741be576d1a1e79ba1a8014d5",
        balances: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
    },
    Pin {
        file: "genesis/local_genesis.json",
        block: "0xe5e3fccc545ef9b0f29fb4204d4e79da04d47661e89eaebe23352abba269e1b4",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0xefa957d79b1b2efb71b9fa40e68db41604a265d9d8982b45454e722ee3661965",
        protocol: "0x289958178a07cff864257324a5c00d0cdf80777e423dc572d707f4d0f6b40449",
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

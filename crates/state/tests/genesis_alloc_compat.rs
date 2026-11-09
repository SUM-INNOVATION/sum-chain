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
//! `node_registry_update_status_unsupported_enabled_from_height`,
//! `archive_unbonding_own_challenges_enabled_from_height` (#369, draft schema
//! 4), `por_attested_targets_enabled_from_height` (draft schema 4),
//! `strict_transaction_signatures_enabled_from_height` and
//! `staking_submit_evidence_unsupported_enabled_from_height` (draft schema 4)
//! were declared; the block hash,
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
        activation: "0x610bc2a344c832edb8c274755c2d6270d0837ca37700cbbb2f0fb5aef01ede82",
        protocol: "0xe77c2d7674eb4aedd5105a75020e97df0a0fbd44a10336080fea48ffbc551486",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        block: "0xf92241d3986ae1c5a30ef34e61dbec5e851ee289404e3276792dd0a27cf3083c",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0x371335c39ea55447b2c177c4fc53d16272df793a06078adad0b5f8e4d5e14ad0",
        protocol: "0x24d7973cba2070fa1845c759fdab486545c79be0bee8ce991b8cb0f002f120f7",
        balances: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0xe7ea0fa4d550bb88edfa1d1d687e0fb8ebedc2a4cb48ef736dae165f68f4d9f7",
        protocol: "0xb5c716feae5d44a20bdad39c9b1a598133b6479f9c48e9371a2d288bd6e4fc9f",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0x5eac12707180460d39255c23475a6d28ff22e75c73f8fc3472104e32d56495c9",
        protocol: "0x242c0d699eedfee02a375f339716194ab8a79ffe2adb041bf04566d6e156ebc5",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "genesis.json",
        block: "0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6",
        root: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
        activation: "0x0a8552ee5202a3fd902b32584f9f817d58f255e1c59c2ef7cfd8da3fa9843dac",
        protocol: "0x45dfd6d87a229278d62a0d561b8c26036b7103fc4a21bb9b938b8fd0cfdb6e1b",
        balances: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
    },
    Pin {
        file: "genesis/local_genesis.json",
        block: "0xe5e3fccc545ef9b0f29fb4204d4e79da04d47661e89eaebe23352abba269e1b4",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0x49253578c49a7831ae0f1e5b6fe83584a4f2b6c91d98cdd968cfeaf3e0c84964",
        protocol: "0x76a049968cc6652459ea455750f22857275c14ba44ce4803536627241b176a28",
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

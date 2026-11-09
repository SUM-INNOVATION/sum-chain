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
//! 4), `por_attested_targets_enabled_from_height` (draft schema 4) and
//! `strict_transaction_signatures_enabled_from_height` (draft schema 4,
//! proposed) were declared; the block hash,
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
        activation: "0xbb69c31aa6efabfa67b85907941c3b1cc000b740f1869a7f21d715fd806f8ba3",
        protocol: "0x58f1f687ec3df5413bfc3e7bb8001c31f05d8516669b0a8ecc0891639a11ccfb",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        block: "0xf92241d3986ae1c5a30ef34e61dbec5e851ee289404e3276792dd0a27cf3083c",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0xdaa99dde2df7c2e67c33027b101ad95b71d182616926dcafd8cd1110eb5ba0ab",
        protocol: "0x145478b78bd2a3a1c010be18d562cad5765e1807921409c5c18c1529a0e0ce54",
        balances: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0x5f360b976a2c9454c822d838f3c7cae1b6727dab5c6ea4d8b832e4aef4d702f4",
        protocol: "0xf42039eb3c8d993d458d6c468eeb3d726582db51fc9854f88cc276336d11ab84",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        root: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
        activation: "0x616bfa4c539d8bf0e49ed69d8a0c47c2cfa0640f5fdd6e44920916ed3d42b07f",
        protocol: "0x0438420e2c7cc80993807ed5bcc1712bc59a6f97dea027019a7cff18f285c7b6",
        balances: "0xe2711f5e07574ca1371c938f6f04482f52bddaa1f1b8e3aa94f269487440d584",
    },
    Pin {
        file: "genesis.json",
        block: "0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6",
        root: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
        activation: "0x389b6ab8be937a0dcd0e52829d6f1c271d151aade1192383c0f491b50be702c7",
        protocol: "0x049580f835f24d1bbd70cf2f4fbef99997a97b9a12006c1abab031175eaea3e5",
        balances: "0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2",
    },
    Pin {
        file: "genesis/local_genesis.json",
        block: "0xe5e3fccc545ef9b0f29fb4204d4e79da04d47661e89eaebe23352abba269e1b4",
        root: "0xac9a93d885f55fc964b027871e22a59932e1082af03b1b73ac5457297572055a",
        activation: "0xe963c852288bfa225af5ec562675220da0eccd7877593ebe52a7c25b8b19a79d",
        protocol: "0xcc1c1927e9ee5adb79e9cab160ad7849978d4e843489bc4678185252011eeb4b",
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

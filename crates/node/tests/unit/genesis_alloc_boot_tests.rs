//! #276 through the real boot: a genesis allocating one account twice is
//! refused before a data directory or database exists.

use std::collections::HashMap;
use std::net::SocketAddr;

use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};

use super::Node;

#[test]
fn a_duplicate_allocation_is_refused_before_the_database_exists() {
    let validator = KeyPair::from_bytes([41u8; 32]);
    let account = KeyPair::from_bytes([42u8; 32]).address();
    let genesis = Genesis::new(
        1,
        1_734_624_000_000,
        vec![validator.public_key().to_base58()],
        HashMap::from([
            (account.to_base58(), 1_000u128),
            (hex::encode(account.as_bytes()), 1_000u128),
        ]),
        ChainParams::default(),
    );
    let parent = tempfile::TempDir::new().unwrap();
    let data_dir = parent.path().join("data");
    let rpc: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let health: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let err = Node::with_rpc_config(
        data_dir.clone(),
        genesis,
        None,
        sumchain_p2p::NetworkConfig::default(),
        rpc,
        health,
        sumchain_rpc::RpcAuthConfig::disabled(),
        sumchain_rpc::RateLimitConfig::disabled(),
        crate::config::ConsensusSettings::default(),
    )
    .err()
    .expect("a duplicate allocation must refuse startup");
    assert!(
        format!("{err:#}").contains("Duplicate genesis allocation"),
        "{err:#}"
    );
    assert!(
        !data_dir.exists(),
        "the data directory was created before the refusal"
    );
}

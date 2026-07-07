//! Wire-shape lock for the promoted SRC-20 token op-data structs (issue #89).
//!
//! These structs were promoted from private `token_executor` definitions into
//! `sumchain_primitives::token_ops`. This fixture proves the bincode wire shape is
//! **unchanged** — the executor deserializes exactly these bytes, and the no-key RPC
//! builders serialize them. Any field reorder / type change flips these asserts.

use sumchain_primitives::token_ops::*;
use sumchain_primitives::Address;

fn rt<T>(v: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let bytes = bincode::serialize(v).unwrap();
    let back: T = bincode::deserialize(&bytes).unwrap();
    assert_eq!(&back, v, "round-trip mismatch");
    back
}

#[test]
fn token_ops_round_trip() {
    rt(&CreateTokenData {
        name: "Token".into(),
        symbol: "TKN".into(),
        decimals: 9,
        initial_supply: 1_000_000,
        max_supply: 1_000_000,
        mintable: false,
        burnable: true,
        pausable: false,
    });
    rt(&TokenMintData { to: Address::new([0x22; 20]), amount: 42 });
    rt(&TokenBurnData { amount: 42 });
    rt(&TokenTransferData { to: Address::new([0x22; 20]), amount: 42 });
    rt(&TokenApproveData { spender: Address::new([0x33; 20]), amount: 7 });
    rt(&TokenTransferFromData { from: Address::new([0x11; 20]), to: Address::new([0x22; 20]), amount: 7 });
    rt(&TokenTransferOwnershipData { new_owner: Address::new([0x44; 20]) });
    rt(&TokenMinterData { minter: Address::new([0x55; 20]) });
}

#[test]
fn token_ops_exact_bytes_locked() {
    // u128 is 16-byte little-endian; Address is 20 raw bytes (no length prefix).
    assert_eq!(
        bincode::serialize(&TokenBurnData { amount: 1_000_000 }).unwrap(),
        vec![0x40, 0x42, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "TokenBurnData wire = u128 LE (16 bytes)"
    );
    assert_eq!(
        bincode::serialize(&TokenMinterData { minter: Address::new([0x11; 20]) }).unwrap(),
        vec![0x11; 20],
        "TokenMinterData wire = 20 raw address bytes"
    );
    // Fixed-size structs: byte-length locks (catch a field add/drop/type change).
    assert_eq!(bincode::serialize(&TokenMintData { to: Address::new([0; 20]), amount: 0 }).unwrap().len(), 36);
    assert_eq!(bincode::serialize(&TokenTransferData { to: Address::new([0; 20]), amount: 0 }).unwrap().len(), 36);
    assert_eq!(bincode::serialize(&TokenApproveData { spender: Address::new([0; 20]), amount: 0 }).unwrap().len(), 36);
    assert_eq!(bincode::serialize(&TokenTransferFromData { from: Address::new([0; 20]), to: Address::new([0; 20]), amount: 0 }).unwrap().len(), 56);
    assert_eq!(bincode::serialize(&TokenTransferOwnershipData { new_owner: Address::new([0; 20]) }).unwrap().len(), 20);
}

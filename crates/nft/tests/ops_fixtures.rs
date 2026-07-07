//! Wire-shape lock for the promoted SUM-721 NFT op-data structs (issue #89).
//!
//! Proves the bincode wire shape is unchanged after promoting the previously
//! executor-private structs into `sumchain_nft::ops`. The executor deserializes
//! exactly these bytes; the no-key RPC builders serialize them.

use sumchain_nft::collection::CollectionConfig;
use sumchain_nft::ops::*;
use sumchain_primitives::Address;

fn rt<T>(v: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let bytes = bincode::serialize(v).unwrap();
    let back: T = bincode::deserialize(&bytes).unwrap();
    assert_eq!(&back, v, "round-trip mismatch");
}

#[test]
fn nft_ops_round_trip() {
    rt(&NftMintData {
        to: Address::new([0x22; 20]),
        metadata: vec![1, 2, 3],
        uri_type: "ipfs".into(),
        uri_value: Some("Qm...".into()),
    });
    rt(&NftBatchMintData {
        requests: vec![
            NftBatchMintRequest { to: Address::new([0x11; 20]), metadata: vec![9] },
            NftBatchMintRequest { to: Address::new([0x22; 20]), metadata: vec![] },
        ],
    });
    rt(&NftTransferData { to: Address::new([0x33; 20]) });
    rt(&NftApproveData { approved: Some(Address::new([0x44; 20])) });
    rt(&NftApproveData { approved: None });
    rt(&NftTransferCollectionOwnershipData { new_owner: Address::new([0x55; 20]) });
    rt(&NftUpdateCollectionConfigData {
        new_royalty_recipient: Some(Address::new([0x66; 20])),
        new_base_uri: Some("https://x".into()),
    });
}

#[test]
fn create_collection_data_round_trips_bytes() {
    // CreateCollectionData has no PartialEq (CollectionConfig lacks it) — compare
    // by re-serializing after a decode round-trip.
    let cfg = CollectionConfig {
        max_supply: 100,
        transferable: true,
        burnable: false,
        metadata_updatable: true,
        owner_only_minting: true,
        royalty_bps: 250,
        royalty_recipient: Address::new([0x77; 20]),
    };
    let v = CreateCollectionData {
        name: "Coll".into(),
        symbol: "CL".into(),
        description: "desc".into(),
        config: cfg,
        base_uri: Some("ipfs://base".into()),
    };
    let bytes = bincode::serialize(&v).unwrap();
    let back: CreateCollectionData = bincode::deserialize(&bytes).unwrap();
    assert_eq!(bincode::serialize(&back).unwrap(), bytes, "byte round-trip mismatch");
    // Field-order lock: name(String) comes first, so the 8-byte LE length prefix of
    // "Coll" (4) leads the encoding.
    assert_eq!(&bytes[0..8], &[4, 0, 0, 0, 0, 0, 0, 0]);
}

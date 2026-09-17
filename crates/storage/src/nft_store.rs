//! SUM-721 NFT key layout and codecs, shared by both sides.
//!
//! One builder per row and one codec per value, called by the committed
//! [`crate::schema::NftStore`] / [`crate::schema::IssuerStore`] below and by the
//! candidate surface in `sumchain_state::nft_view`. Neither side restates a key
//! or a codec.
//!
//! Three things here are easy to get wrong, and are why these are extracted
//! rather than written out on each side:
//!
//!   * The token key is the only COMPOSITE key in the subsystem: a 32-byte
//!     collection id followed by the token id as eight BIG-endian bytes, forty
//!     bytes in all. Collections, the collection index and the owner index are
//!     all bare keys, and the owner index's is twenty bytes, not thirty-two.
//!   * The two index VALUES are accumulating lists, not presence markers, and
//!     they are accumulating lists of DIFFERENT shapes: the owner index holds
//!     `Vec<(Vec<u8>, u64)>` — the collection id as a length-prefixed byte
//!     vector, not as a fixed array — and the collection index holds
//!     `Vec<u64>`. Appending either is a read-modify-write, and on the
//!     candidate side it has to read the candidate or a second token in one
//!     block overwrites the first one's list with a single-element one.
//!   * Removal is asymmetric and deliberately reproduced: emptying an owner's
//!     list DELETES the row, and emptying a collection's list WRITES an empty
//!     list. A block that burns the last token of an owner and the last token
//!     of a collection leaves one absent key and one present empty one.

use sumchain_primitives::Address;

use crate::schema::{IssuerData, NftCollectionData, NftTokenData};
use crate::{Result, StorageError};

/// One entry of the owner index: the collection id as a byte vector, and the
/// token id.
///
/// The `Vec<u8>` half is what the committed store has always encoded — bincode
/// writes a length prefix for it and would not for a `[u8; 32]`, so the row
/// layout depends on this type and not merely on its contents.
pub type OwnerTokenEntry = (Vec<u8>, u64);

/// Collections are keyed by the bare 32-byte collection id.
pub fn collection_key(collection_id: &[u8; 32]) -> &[u8] {
    collection_id
}

/// Tokens are keyed by collection id followed by the token id, big-endian.
///
/// Forty bytes. Big-endian is what makes a prefix scan of one collection's
/// tokens come back in token-id order, so the byte order is part of the row
/// layout and not an implementation detail.
pub fn token_key(collection_id: &[u8; 32], token_id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(collection_id);
    key.extend_from_slice(&token_id.to_be_bytes());
    key
}

/// The owner index is keyed by the owner ADDRESS — twenty bytes, not
/// thirty-two.
pub fn owner_index_key(owner: &Address) -> &[u8] {
    owner.as_bytes()
}

/// The collection index is keyed by the bare 32-byte collection id, the same
/// key as the collection row itself in a different family.
pub fn collection_index_key(collection_id: &[u8; 32]) -> &[u8] {
    collection_id
}

/// Issuer registrations are keyed by the issuer ADDRESS.
pub fn issuer_key(address: &Address) -> &[u8] {
    address.as_bytes()
}

pub fn encode_collection(c: &NftCollectionData) -> Result<Vec<u8>> {
    bincode::serialize(c).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_collection(bytes: &[u8]) -> Result<NftCollectionData> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_token(t: &NftTokenData) -> Result<Vec<u8>> {
    bincode::serialize(t).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_token(bytes: &[u8]) -> Result<NftTokenData> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_owner_tokens(tokens: &[OwnerTokenEntry]) -> Result<Vec<u8>> {
    bincode::serialize(tokens).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_owner_tokens(bytes: &[u8]) -> Result<Vec<OwnerTokenEntry>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_collection_tokens(tokens: &[u64]) -> Result<Vec<u8>> {
    bincode::serialize(tokens).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_collection_tokens(bytes: &[u8]) -> Result<Vec<u64>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn encode_issuer(i: &IssuerData) -> Result<Vec<u8>> {
    bincode::serialize(i).map_err(|e| StorageError::Serialization(e.to_string()))
}

pub fn decode_issuer(bytes: &[u8]) -> Result<IssuerData> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}

//! SUM-721 NFTs, as this block's candidate sees them.
//!
//! The committed twins in `sumchain_storage::schema` (`NftStore`,
//! `IssuerStore`) stay for the RPC server, which answers about the canonical
//! chain.
//!
//! ## Why the reads move with the writes
//!
//! NFTs are OWNERSHIP state, and every guard in the subsystem is a read of the
//! row it is about to write.
//!
//! `execute_transfer` reads the token, checks `token.owner == sender` (or that
//! the sender is the single approved address), and then writes a new owner. If
//! that read went to committed state, the check would answer about the row the
//! BLOCK started with. Two consequences, both consensus-relevant:
//!
//!   * A chain of transfers cannot form. `mint -> A`, `A -> B`, `B -> C` in one
//!     block: the second transfer would find `A` still recorded as owner and
//!     refuse `B`'s transaction.
//!   * Worse in the other direction, `A` could transfer the SAME token twice in
//!     one block — to `B` and then to `C` — because the second read would still
//!     show `A` as owner. The token would land on `C` while `B`'s transaction
//!     also reported success, and both owner-index lists would be written from
//!     the same stale base.
//!
//! The same shape runs through the whole unit. `execute_approve`,
//! `execute_lock_token` and `execute_unlock_token` read the token, change one
//! field and write it back. `execute_mint` reads the collection for
//! `next_token_id` and `total_supply` and writes both back, so two mints in one
//! block must chain or they mint the same token id twice. `execute_burn`
//! decrements `total_supply` read-modify-write. And both indexes are
//! accumulating lists appended by read-modify-write, so a second token for one
//! owner in one block would otherwise overwrite the first one's list with a
//! single-element one.
//!
//! ## What these reproduce exactly, from the shared halves
//!
//! * The key layout: collections and the collection index keyed by a bare
//!   32-byte id, tokens by the 40-byte composite, the owner index by a 20-byte
//!   ADDRESS.
//! * The two index VALUES as accumulating lists of different shapes, each with
//!   its own dedup rule, and the REMOVAL asymmetry — an emptied owner list
//!   deletes its row, an emptied collection list writes an empty one.
//! * `v_add_to_owner_index` and `v_add_to_collection_index` write even when the
//!   entry is already present, rewriting an identical list. The committed twins
//!   do, unlike the agreement indexes, and a skipped write is a different
//!   candidate.
//! * `v_transfer_token` writes the token row only `if let Some(..)`, and
//!   updates both owner lists regardless. Reproduced rather than tightened:
//!   making an absent token an error there would change which transactions are
//!   valid.

use sumchain_primitives::Address;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::nft_store::{
    collection_index_key, collection_key, decode_collection, decode_collection_tokens,
    decode_issuer, decode_owner_tokens, decode_token, encode_collection, encode_collection_tokens,
    encode_owner_tokens, encode_token, issuer_key, owner_index_key, token_key, OwnerTokenEntry,
};
use sumchain_storage::{IssuerData, NftCollectionData, NftTokenData};

use crate::nft_executor::NftExecutor;
use crate::{Result, StateError};

impl NftExecutor {
    // ── Collections ─────────────────────────────────────────────────────────

    pub fn v_put_collection(
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        data: &NftCollectionData,
    ) -> Result<()> {
        let bytes = encode_collection(data).map_err(StateError::Storage)?;
        view.put(cf::NFT_COLLECTIONS, collection_key(collection_id), &bytes)
            .map_err(StateError::Storage)
    }

    pub fn v_get_collection(
        view: &ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
    ) -> Result<Option<NftCollectionData>> {
        match view
            .get(cf::NFT_COLLECTIONS, collection_key(collection_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(
                decode_collection(&bytes).map_err(StateError::Storage)?,
            )),
            None => Ok(None),
        }
    }

    pub fn v_collection_exists(
        view: &ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
    ) -> Result<bool> {
        view.contains(cf::NFT_COLLECTIONS, collection_key(collection_id))
            .map_err(StateError::Storage)
    }

    // ── Tokens ──────────────────────────────────────────────────────────────

    pub fn v_put_token(
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &NftTokenData,
    ) -> Result<()> {
        let key = token_key(collection_id, token_id);
        let bytes = encode_token(data).map_err(StateError::Storage)?;
        view.put(cf::NFT_TOKENS, &key, &bytes)
            .map_err(StateError::Storage)
    }

    pub fn v_get_token(
        view: &ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<Option<NftTokenData>> {
        let key = token_key(collection_id, token_id);
        match view
            .get(cf::NFT_TOKENS, &key)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_token(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_token_exists(
        view: &ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<bool> {
        let key = token_key(collection_id, token_id);
        view.contains(cf::NFT_TOKENS, &key)
            .map_err(StateError::Storage)
    }

    pub fn v_delete_token(
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let key = token_key(collection_id, token_id);
        view.delete(cf::NFT_TOKENS, &key)
            .map_err(StateError::Storage)
    }

    // ── The owner index ─────────────────────────────────────────────────────

    pub fn v_get_owner_tokens(
        view: &ExecutionView<'_, '_>,
        owner: &Address,
    ) -> Result<Vec<OwnerTokenEntry>> {
        match view
            .get(cf::NFT_OWNER_INDEX, owner_index_key(owner))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_owner_tokens(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    /// Append, then write — even when the entry was already there.
    ///
    /// The committed twin writes unconditionally, so a re-add rewrites an
    /// identical list rather than skipping. Skipping would stage one fewer row
    /// and a different overlay byte count.
    pub fn v_add_to_owner_index(
        view: &mut ExecutionView<'_, '_>,
        owner: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let mut tokens = Self::v_get_owner_tokens(view, owner)?;

        let entry = (collection_id.to_vec(), token_id);
        if !tokens
            .iter()
            .any(|(c, t)| c == collection_id && *t == token_id)
        {
            tokens.push(entry);
        }

        let bytes = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
        view.put(cf::NFT_OWNER_INDEX, owner_index_key(owner), &bytes)
            .map_err(StateError::Storage)
    }

    /// Remove, and DELETE the row when the list empties.
    ///
    /// The asymmetry with the collection index is inherited: that one writes an
    /// empty list instead. Both are reproduced exactly.
    pub fn v_remove_from_owner_index(
        view: &mut ExecutionView<'_, '_>,
        owner: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let mut tokens = Self::v_get_owner_tokens(view, owner)?;
        tokens.retain(|(c, t)| !(c.as_slice() == collection_id && *t == token_id));

        if tokens.is_empty() {
            view.delete(cf::NFT_OWNER_INDEX, owner_index_key(owner))
                .map_err(StateError::Storage)?;
        } else {
            let bytes = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
            view.put(cf::NFT_OWNER_INDEX, owner_index_key(owner), &bytes)
                .map_err(StateError::Storage)?;
        }
        Ok(())
    }

    // ── The collection index ────────────────────────────────────────────────

    pub fn v_get_collection_tokens(
        view: &ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
    ) -> Result<Vec<u64>> {
        match view
            .get(
                cf::NFT_COLLECTION_INDEX,
                collection_index_key(collection_id),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_collection_tokens(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    pub fn v_add_to_collection_index(
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let mut tokens = Self::v_get_collection_tokens(view, collection_id)?;
        if !tokens.contains(&token_id) {
            tokens.push(token_id);
        }

        let bytes = encode_collection_tokens(&tokens).map_err(StateError::Storage)?;
        view.put(
            cf::NFT_COLLECTION_INDEX,
            collection_index_key(collection_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Emptying this list WRITES an empty list; it does not delete the row.
    pub fn v_remove_from_collection_index(
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<()> {
        let mut tokens = Self::v_get_collection_tokens(view, collection_id)?;
        tokens.retain(|t| *t != token_id);

        let bytes = encode_collection_tokens(&tokens).map_err(StateError::Storage)?;
        view.put(
            cf::NFT_COLLECTION_INDEX,
            collection_index_key(collection_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    // ── The two mirror-pair compounds ───────────────────────────────────────

    /// Token row, then `from`'s list, then `to`'s list — that order.
    ///
    /// The three writes are one ownership move: the row says who holds the
    /// token and the two lists say what each address holds, and a block that
    /// staged one without the others would leave the candidate disagreeing with
    /// itself.
    pub fn v_transfer_token(
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
        from: &Address,
        to: &Address,
    ) -> Result<()> {
        if let Some(mut token) = Self::v_get_token(view, collection_id, token_id)? {
            token.owner = *to;
            token.approved = None;
            token.transfer_count += 1;
            Self::v_put_token(view, collection_id, token_id, &token)?;
        }

        Self::v_remove_from_owner_index(view, from, collection_id, token_id)?;
        Self::v_add_to_owner_index(view, to, collection_id, token_id)?;

        Ok(())
    }

    /// Delete the token, drop it from both indexes, then decrement supply.
    ///
    /// The supply decrement is `saturating_sub`, and the collection is re-read
    /// here rather than passed in — so a burn that follows a mint in the same
    /// block decrements the supply the mint wrote, not the one the block
    /// started with.
    pub fn v_burn_token(
        view: &mut ExecutionView<'_, '_>,
        collection_id: &[u8; 32],
        token_id: u64,
        owner: &Address,
    ) -> Result<()> {
        Self::v_delete_token(view, collection_id, token_id)?;

        Self::v_remove_from_owner_index(view, owner, collection_id, token_id)?;
        Self::v_remove_from_collection_index(view, collection_id, token_id)?;

        if let Some(mut collection) = Self::v_get_collection(view, collection_id)? {
            collection.total_supply = collection.total_supply.saturating_sub(1);
            Self::v_put_collection(view, collection_id, &collection)?;
        }

        Ok(())
    }

    // ── The issuer registry, read-only from execution ───────────────────────
    //
    // `ISSUER_REGISTRY` has no writer anywhere in block execution — issuers are
    // seeded out of band — so this family contributes no manifest row. The READ
    // moves anyway: a read left on the committed handle is a read that would
    // not see a candidate write if one ever arrived, and leaving one behind is
    // how the next subsystem inherits a half-migrated path.

    pub fn v_get_issuer(
        view: &ExecutionView<'_, '_>,
        address: &Address,
    ) -> Result<Option<IssuerData>> {
        match view
            .get(cf::ISSUER_REGISTRY, issuer_key(address))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(Some(decode_issuer(&bytes).map_err(StateError::Storage)?)),
            None => Ok(None),
        }
    }

    pub fn v_can_mint_documents(
        view: &ExecutionView<'_, '_>,
        address: &Address,
        doc_type: Option<&str>,
        current_time: u64,
    ) -> Result<bool> {
        match Self::v_get_issuer(view, address)? {
            Some(issuer) => {
                if let Some(dtype) = doc_type {
                    Ok(issuer.can_mint_doc_type(dtype, current_time))
                } else {
                    Ok(issuer.can_mint(current_time))
                }
            }
            None => Ok(false),
        }
    }
}

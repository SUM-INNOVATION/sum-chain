//! SRC-20 tokens, as this block's candidate sees them.
//!
//! Unused on purpose. This is preparation: the surface the token executor will
//! route through exists and is tested, but nothing calls it yet. The routing
//! commit moves governance, token and equity together, because their same-block
//! dependencies run across each other — governance reads token balances to set
//! a create-threshold and scans `cf::TOKEN_BALANCES` to freeze a vote snapshot,
//! so a token migration that landed on its own would leave governance reading
//! committed balances the same block had already staged.
//!
//! Splitting the surfaces from the routing is safe in a way splitting the
//! routing is not: adding a function nobody calls changes no behaviour, and it
//! lets the routing commit be read as what it is — a change of caller, not a
//! change of semantics.
//!
//! ## What these must reproduce exactly
//!
//! * The key layout, from the shared builders in `TokenStore`.
//! * The amount encoding: a bare 16-byte big-endian `u128`, never bincode.
//! * Absence. `set_balance(0)` DELETES the row and drops the holder-index
//!   entry; it does not store a zero. A candidate that stored one would leave a
//!   row where the chain has none, and an abandoned block's rollback would
//!   restore the wrong shape.
//!
//! All three are pinned by `crates/storage/tests/gte_codec_parity.rs` on the
//! committed side and by `token_view` cases here on the candidate side.

use sumchain_primitives::Address;
use sumchain_storage::cf;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::schema::{
    decode_holder_tokens, decode_src20_token, decode_token_amount, encode_holder_tokens,
    encode_src20_token, encode_token_amount, Src20TokenData, TokenStore,
};

use crate::token_executor::TokenExecutor;
use crate::{Result, StateError};

impl TokenExecutor {
    // ── Token metadata ──────────────────────────────────────────────────────

    /// A token as the candidate sees it, including one created by an earlier
    /// transaction of the same block.
    pub fn v_get_token(
        view: &ExecutionView<'_, '_>,
        token_id: &[u8; 32],
    ) -> Result<Option<Src20TokenData>> {
        match view.get(cf::TOKENS, token_id).map_err(StateError::Storage)? {
            Some(bytes) => Ok(Some(decode_src20_token(&bytes)?)),
            None => Ok(None),
        }
    }

    pub fn v_put_token(
        view: &mut ExecutionView<'_, '_>,
        token_id: &[u8; 32],
        data: &Src20TokenData,
    ) -> Result<()> {
        view.put(cf::TOKENS, token_id, &encode_src20_token(data)?)
            .map_err(StateError::Storage)
    }

    pub fn v_token_exists(view: &ExecutionView<'_, '_>, token_id: &[u8; 32]) -> Result<bool> {
        view.contains(cf::TOKENS, token_id)
            .map_err(StateError::Storage)
    }

    // ── Balances ────────────────────────────────────────────────────────────

    /// An absent balance row reads as 0, matching the committed store. Zero is
    /// the ABSENCE of a row here, not a stored value, which is why this is the
    /// one family where "absent" and "present and zero" are the same thing.
    pub fn v_get_balance(
        view: &ExecutionView<'_, '_>,
        token_id: &[u8; 32],
        owner: &Address,
    ) -> Result<u128> {
        let key = TokenStore::balance_key(token_id, owner);
        match view.get(cf::TOKEN_BALANCES, &key).map_err(StateError::Storage)? {
            Some(bytes) => Ok(decode_token_amount(&bytes)?),
            None => Ok(0),
        }
    }

    /// Stage a balance AND its holder-index entry, deleting both at zero.
    pub fn v_set_balance(
        view: &mut ExecutionView<'_, '_>,
        token_id: &[u8; 32],
        owner: &Address,
        balance: u128,
    ) -> Result<()> {
        let key = TokenStore::balance_key(token_id, owner);
        if balance == 0 {
            view.delete(cf::TOKEN_BALANCES, &key)
                .map_err(StateError::Storage)?;
            Self::v_remove_from_holder_index(view, owner, token_id)
        } else {
            view.put(cf::TOKEN_BALANCES, &key, &encode_token_amount(balance))
                .map_err(StateError::Storage)?;
            Self::v_add_to_holder_index(view, owner, token_id)
        }
    }

    // ── Allowances ──────────────────────────────────────────────────────────

    pub fn v_get_allowance(
        view: &ExecutionView<'_, '_>,
        token_id: &[u8; 32],
        owner: &Address,
        spender: &Address,
    ) -> Result<u128> {
        let key = TokenStore::allowance_key(token_id, owner, spender);
        match view
            .get(cf::TOKEN_ALLOWANCES, &key)
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_token_amount(&bytes)?),
            None => Ok(0),
        }
    }

    pub fn v_set_allowance(
        view: &mut ExecutionView<'_, '_>,
        token_id: &[u8; 32],
        owner: &Address,
        spender: &Address,
        allowance: u128,
    ) -> Result<()> {
        let key = TokenStore::allowance_key(token_id, owner, spender);
        if allowance == 0 {
            view.delete(cf::TOKEN_ALLOWANCES, &key)
                .map_err(StateError::Storage)
        } else {
            view.put(cf::TOKEN_ALLOWANCES, &key, &encode_token_amount(allowance))
                .map_err(StateError::Storage)
        }
    }

    // ── The holder index, which is part of the balance ──────────────────────

    pub fn v_get_holder_tokens(
        view: &ExecutionView<'_, '_>,
        owner: &Address,
    ) -> Result<Vec<Vec<u8>>> {
        match view
            .get(cf::TOKEN_HOLDER_INDEX, owner.as_bytes())
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_holder_tokens(&bytes)?),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_holder_index(
        view: &mut ExecutionView<'_, '_>,
        owner: &Address,
        token_id: &[u8; 32],
    ) -> Result<()> {
        let mut tokens = Self::v_get_holder_tokens(view, owner)?;
        if !tokens.iter().any(|t| t == token_id) {
            tokens.push(token_id.to_vec());
            let bytes = encode_holder_tokens(&tokens)?;
            view.put(cf::TOKEN_HOLDER_INDEX, owner.as_bytes(), &bytes)
                .map_err(StateError::Storage)?;
        }
        Ok(())
    }

    fn v_remove_from_holder_index(
        view: &mut ExecutionView<'_, '_>,
        owner: &Address,
        token_id: &[u8; 32],
    ) -> Result<()> {
        let mut tokens = Self::v_get_holder_tokens(view, owner)?;
        tokens.retain(|t| t.as_slice() != token_id);
        // Empty DELETES the index row; it does not store an empty list. The
        // committed store does exactly this, and the difference is visible:
        // an empty list is a row, and a row is not the absence it replaced.
        if tokens.is_empty() {
            view.delete(cf::TOKEN_HOLDER_INDEX, owner.as_bytes())
                .map_err(StateError::Storage)?;
        } else {
            let bytes = encode_holder_tokens(&tokens)?;
            view.put(cf::TOKEN_HOLDER_INDEX, owner.as_bytes(), &bytes)
                .map_err(StateError::Storage)?;
        }
        Ok(())
    }
}

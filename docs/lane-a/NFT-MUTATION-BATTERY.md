# NFT routing: mutation battery

NOT DEPLOYABLE ON ITS OWN, like the rest of this lane.


Each mutation is applied to the tree that this commit contains, one at a time,
and the NAMED covering test is run. A kill requires that test to appear in
libtest's output AND to have failed. A mutation whose anchor does not resolve
exactly once aborts the whole run before anything is applied; one that does not
compile, and one whose covering test does not appear, are separate categories
that never count as kills. Restoration happens in a `finally` and on
SIGINT/SIGTERM, every restore is checked against the pre-run hash, and the run
is made with `CARGO_INCREMENTAL=0`.

Whole-tree text scanning for leftover replacements is diagnostic only. A
replacement is usable as a residue marker only if it does not already occur in
the pristine tree; 9 of these do occur there -- strings such as
`Ok(false)`, `Ok(())`, `.map_err(StateError::Storage)` and outright deletions --
so finding them proves nothing. The final evidence is 71 mutations total,
62 scanned specifically by text, and 9 covered by exact file
hashes alone. The authoritative residue check for all 71 is the pre/post
hash of every mutated file, printed at the end of this document.

## The one survivor, and what it cost

On the first pass E4 -- `mint writes the collection row first` -- SURVIVED.
Inserting a redundant `v_put_collection` before the token write is invisible to
a CONTENT comparison, because at that point in `execute_mint` the collection
struct still holds exactly the bytes the block started with: the row is
rewritten identically, and `families_changed`, which diffs committed against
staged, sees nothing.

Two things were wrong and both are fixed. E4 named the corrupt-row test as its
cover, which was never the right test for a write-ordering change; it is now
covered by `a_refusal_part_way_leaves_canonical_storage_untouched`. And that
test read staging with a merged point read, which cannot see an
identical-bytes rewrite; it now reads `ExecutionView::preimage`, which answers
"did THIS block write this key", and asserts the whole mint write order as a
chain of implications -- token, then owner index, then collection index, then
the collection row.

The three mutations that test covers (E2, E3, E4) were re-run against the
strengthened test. All three are killed. Nothing else was re-run, and no source
file changed between the two passes -- the pre-run hashes of the re-run match
the post-run hashes of the first pass, and both are printed below.


## Pre-run file hashes

```
  c1f2ba90b895f5a6e717071bed1b237b9f59e3445a35768927305d57fb1841c5  crates/state/src/nft_view.rs
  0ff9435bb63dee3593b1d245f87f8b03e8ad1a9456bacb797b700297af8dc999  crates/state/src/nft_executor.rs
  f1903f882024498bea7713b2859360df78947467f7f8a3a85e08457e8cdae07d  crates/state/src/executor.rs
  388fe9590d610480c60ce3d2247167cb23a8e488da885fd7b0507951abaeede1  crates/storage/src/nft_store.rs
  59e6836129e34472c3144be2cb7abb36f6cc04744a6b5a9b09383a18205b1ce5  crates/storage/src/schema.rs
```


## The 71 mutations


### `crates/state/src/nft_view.rs`


#### A1 collection read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `0b28769405f51dd5` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::NFT_COLLECTIONS, collection_key(collection_id))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes ... FAILED
```

#### A2 token read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_chain_of_transfers_in_one_block_reaches_the_last_owner` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `556a4badb5dfee6e` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::NFT_TOKENS, &key)
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test a_chain_of_transfers_in_one_block_reaches_the_last_owner ... FAILED
```

#### A3 owner index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `d9f54b62ed1cf2a2` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::NFT_OWNER_INDEX, owner_index_key(owner))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes ... FAILED
```

#### A4 collection index read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `77688da52b48d396` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::NFT_COLLECTION_INDEX,
                collection_index_key(collection_id),
            )
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes ... FAILED
```

#### A5 issuer read sees nothing

* occurrences checked before applying: **1** (expected 1)
* covering test: `no_block_writes_the_issuer_registry` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `e788561df5829f60` -> replacement `c832b86ec08ac5f2`
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::ISSUER_REGISTRY, issuer_key(address))
            .map_err(StateError::Storage)?
        {
```
Replacement:
```rust
        match None::<Vec<u8>> {
```
Printed by libtest while mutated:
```
test no_block_writes_the_issuer_registry ... FAILED
```

#### B1 collection exists is always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_collection_in_the_same_block_is_refused` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `5eab1ffbf2da3749` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::NFT_COLLECTIONS, collection_key(collection_id))
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test a_duplicate_collection_in_the_same_block_is_refused ... FAILED
```

#### B2 token exists is always false

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_existence_guards_read_the_candidate` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `9517676114675905` -> replacement `e3b3651260f4ca5a`
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::NFT_TOKENS, &key)
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(false)
```
Printed by libtest while mutated:
```
test the_existence_guards_read_the_candidate ... FAILED
```

#### C1 a corrupt collection reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `6585b9bd5838061f` -> replacement `8e36e29886c3b2b5`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_collection(&bytes).map_err(StateError::Storage)?,
            )),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_collection(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### C2 a corrupt token reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `551338ac24a117c0` -> replacement `d59d7437a91af8ca`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_token(&bytes).map_err(StateError::Storage)?)),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_token(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### C3 a corrupt owner index reads as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `78b83890fc9be9fe` -> replacement `8a9b824a18bdfb19`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_owner_tokens(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_owner_tokens(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### C4 a corrupt collection index reads as empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `a399a83a4d9efd9d` -> replacement `d411fbe7530ff4c4`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => decode_collection_tokens(&bytes).map_err(StateError::Storage),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_collection_tokens(&bytes).unwrap_or_default()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### C5 a corrupt issuer reads as absent

* occurrences checked before applying: **1** (expected 1)
* covering test: `corrupt_rows_error_through_dispatch_with_exactly_this_staged` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `6dd5bd164addf217` -> replacement `c2b21a8c8a41f4b0`
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_issuer(&bytes).map_err(StateError::Storage)?)),
```
Replacement:
```rust
            Some(bytes) => Ok(decode_issuer(&bytes).ok()),
```
Printed by libtest while mutated:
```
test corrupt_rows_error_through_dispatch_with_exactly_this_staged ... FAILED
```

#### D1 the collection write is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `b305ee96972fc92d` -> replacement `d681517540ef5e7d`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_collection(data).map_err(StateError::Storage)?;
        view.put(cf::NFT_COLLECTIONS, collection_key(collection_id), &bytes)
            .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = encode_collection(data).map_err(StateError::Storage)?;
        Ok(())
```
Printed by libtest while mutated:
```
test two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes ... FAILED
```

#### D2 the token write is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_chain_of_transfers_in_one_block_reaches_the_last_owner` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `6eefaee3c9bd9c22` -> replacement `6472edf75a5bd011`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_token(data).map_err(StateError::Storage)?;
        view.put(cf::NFT_TOKENS, &key, &bytes)
            .map_err(StateError::Storage)
```
Replacement:
```rust
        let _ = encode_token(data).map_err(StateError::Storage)?;
        Ok(())
```
Printed by libtest while mutated:
```
test a_chain_of_transfers_in_one_block_reaches_the_last_owner ... FAILED
```

#### D3 the token delete is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `f2773ce79e3147d4` -> replacement `b17e351a96d51a7c`
* verdict: **KILLED**

Anchor:
```rust
        view.delete(cf::NFT_TOKENS, &key)
            .map_err(StateError::Storage)
```
Replacement:
```rust
        Ok(())
```
Printed by libtest while mutated:
```
test a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together ... FAILED
```

#### D4 the owner index append is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `9b75638ba6162625` -> replacement `42f77d28329d5f71`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
        view.put(cf::NFT_OWNER_INDEX, owner_index_key(owner), &bytes)
            .map_err(StateError::Storage)
    }
```
Replacement:
```rust
        let _ = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
        Ok(())
    }
```
Printed by libtest while mutated:
```
test two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes ... FAILED
```

#### D5 the owner index delete-when-empty is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `burning_the_last_token_deletes_one_index_row_and_writes_the_other_empty` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `6327f76e913c4052` -> replacement `f7b3c7079d29f5e8`
* verdict: **KILLED**

Anchor:
```rust
        if tokens.is_empty() {
            view.delete(cf::NFT_OWNER_INDEX, owner_index_key(owner))
                .map_err(StateError::Storage)?;
        } else {
```
Replacement:
```rust
        if tokens.is_empty() {
        } else {
```
Printed by libtest while mutated:
```
test burning_the_last_token_deletes_one_index_row_and_writes_the_other_empty ... FAILED
```

#### D6 the owner index shrink-write is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `13de323662f00948` -> replacement `74372b444366099f`
* verdict: **KILLED**

Anchor:
```rust
            let bytes = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
            view.put(cf::NFT_OWNER_INDEX, owner_index_key(owner), &bytes)
                .map_err(StateError::Storage)?;
```
Replacement:
```rust
            let _ = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
```
Printed by libtest while mutated:
```
test a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together ... FAILED
```

#### D7 the collection index append is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `541e9b52e95d3bf6` -> replacement `cde01f7eea8e2f7d`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_collection_tokens(&tokens).map_err(StateError::Storage)?;
        view.put(
            cf::NFT_COLLECTION_INDEX,
            collection_index_key(collection_id),
            &bytes,
        )
        .map_err(StateError::Storage)
    }

    /// Emptying this list WRITES an empty list; it does not delete the row.
```
Replacement:
```rust
        let _ = encode_collection_tokens(&tokens).map_err(StateError::Storage)?;
        Ok(())
    }

    /// Emptying this list WRITES an empty list; it does not delete the row.
```
Printed by libtest while mutated:
```
test two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes ... FAILED
```

#### D8 the collection index shrink-write is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `59dfe1cdc6a081e7` -> replacement `337ef0786f3c09e2`
* verdict: **KILLED**

Anchor:
```rust
        let mut tokens = Self::v_get_collection_tokens(view, collection_id)?;
        tokens.retain(|t| *t != token_id);

        let bytes = encode_collection_tokens(&tokens).map_err(StateError::Storage)?;
```
Replacement:
```rust
        let mut tokens = Self::v_get_collection_tokens(view, collection_id)?;
        tokens.retain(|t| *t != token_id);
        return Ok(());
        #[allow(unreachable_code)]
        let bytes = encode_collection_tokens(&tokens).map_err(StateError::Storage)?;
```
Printed by libtest while mutated:
```
test a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together ... FAILED
```

#### D9 the supply decrement write is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `4bd4cb8fc5f48468` -> replacement `5108318e1cd6b284`
* verdict: **KILLED**

Anchor:
```rust
        if let Some(mut collection) = Self::v_get_collection(view, collection_id)? {
            collection.total_supply = collection.total_supply.saturating_sub(1);
            Self::v_put_collection(view, collection_id, &collection)?;
        }
```
Replacement:
```rust
        if let Some(mut collection) = Self::v_get_collection(view, collection_id)? {
            collection.total_supply = collection.total_supply.saturating_sub(1);
        }
```
Printed by libtest while mutated:
```
test a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together ... FAILED
```

#### D10 the transfer's token rewrite is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_chain_of_transfers_in_one_block_reaches_the_last_owner` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `76873f7c83d736f5` -> replacement `d710f068d3101821`
* verdict: **KILLED**

Anchor:
```rust
            token.transfer_count += 1;
            Self::v_put_token(view, collection_id, token_id, &token)?;
```
Replacement:
```rust
            token.transfer_count += 1;
```
Printed by libtest while mutated:
```
test a_chain_of_transfers_in_one_block_reaches_the_last_owner ... FAILED
```

#### E1 transfer updates the recipient list before the sender's

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_transfer_to_self_clears_the_approval_and_keeps_the_index_entry` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `7bc73065a12ace31` -> replacement `64204b797f002c02`
* verdict: **KILLED**

Anchor:
```rust
        Self::v_remove_from_owner_index(view, from, collection_id, token_id)?;
        Self::v_add_to_owner_index(view, to, collection_id, token_id)?;
```
Replacement:
```rust
        Self::v_add_to_owner_index(view, to, collection_id, token_id)?;
        Self::v_remove_from_owner_index(view, from, collection_id, token_id)?;
```
Printed by libtest while mutated:
```
test a_transfer_to_self_clears_the_approval_and_keeps_the_index_entry ... FAILED
```

#### H1 the candidate restates the token key little-endian

* occurrences checked before applying: **1** (expected 1)
* covering test: `published_nft_rows_survive_a_database_restart` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `682c0b1af505e0d7` -> replacement `3c99db7c23f96421`
* verdict: **KILLED**

Anchor:
```rust
        let key = token_key(collection_id, token_id);
        let bytes = encode_token(data).map_err(StateError::Storage)?;
```
Replacement:
```rust
        let mut key = collection_id.to_vec();
        key.extend_from_slice(&token_id.to_le_bytes());
        let bytes = encode_token(data).map_err(StateError::Storage)?;
```
Printed by libtest while mutated:
```
test published_nft_rows_survive_a_database_restart ... FAILED
```

#### H2 the candidate restates the owner index key truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `published_nft_rows_survive_a_database_restart` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `9b75638ba6162625` -> replacement `1ccf346c0873ca86`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
        view.put(cf::NFT_OWNER_INDEX, owner_index_key(owner), &bytes)
            .map_err(StateError::Storage)
    }
```
Replacement:
```rust
        let bytes = encode_owner_tokens(&tokens).map_err(StateError::Storage)?;
        view.put(cf::NFT_OWNER_INDEX, &owner.as_bytes()[..10], &bytes)
            .map_err(StateError::Storage)
    }
```
Printed by libtest while mutated:
```
test published_nft_rows_survive_a_database_restart ... FAILED
```

#### H3 the candidate restates the collection value codec

* occurrences checked before applying: **1** (expected 1)
* covering test: `published_nft_rows_survive_a_database_restart` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `b079d74b6195217c` -> replacement `4b0de67fef32e8d8`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_collection(data).map_err(StateError::Storage)?;
```
Replacement:
```rust
        let bytes = bincode::serialize(&(0u8, data))
            .map_err(|e| StateError::Storage(sumchain_storage::StorageError::Serialization(e.to_string())))?;
```
Printed by libtest while mutated:
```
test published_nft_rows_survive_a_database_restart ... FAILED
```

#### J19 an unregistered address may mint documents

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_unregistered_issuer_cannot_mint_a_document` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `6d5ffdb32f5a5301` -> replacement `746e7844570cd903`
* verdict: **KILLED**

Anchor:
```rust
            None => Ok(false),
        }
    }
}
```
Replacement:
```rust
            None => Ok(true),
        }
    }
}
```
Printed by libtest while mutated:
```
test an_unregistered_issuer_cannot_mint_a_document ... FAILED
```

#### L1 the owner index append stops reading the old list

* occurrences checked before applying: **1** (expected 1)
* covering test: `both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses` (`sumchain-state --test nft_index_allocation`)
* anchor sha256[:16] `34312040da20faae` -> replacement `fb751b66c58a4a6c`
* verdict: **KILLED**

Anchor:
```rust
        let mut tokens = Self::v_get_owner_tokens(view, owner)?;

        let entry = (collection_id.to_vec(), token_id);
```
Replacement:
```rust
        let mut tokens: Vec<OwnerTokenEntry> = Vec::new();

        let entry = (collection_id.to_vec(), token_id);
```
Printed by libtest while mutated:
```
test both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses ... FAILED
```

#### L2 the collection index append stops reading the old list

* occurrences checked before applying: **1** (expected 1)
* covering test: `both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses` (`sumchain-state --test nft_index_allocation`)
* anchor sha256[:16] `98599dfd7f1efca8` -> replacement `4b29438d71c70c71`
* verdict: **KILLED**

Anchor:
```rust
        let mut tokens = Self::v_get_collection_tokens(view, collection_id)?;
        if !tokens.contains(&token_id) {
```
Replacement:
```rust
        let mut tokens: Vec<u64> = Vec::new();
        if !tokens.contains(&token_id) {
```
Printed by libtest while mutated:
```
test both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses ... FAILED
```

### `crates/state/src/nft_executor.rs`


#### E2 mint writes the indexes before the token

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_refusal_part_way_leaves_canonical_storage_untouched` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `686bb5e1edd1ccbb` -> replacement `62964ebca692d88a`
* verdict: **KILLED   [scoped re-run, after the covering test was strengthened]**

Anchor:
```rust
        // Store token
        Self::v_put_token(view, collection_id, token_id, &token_data)?;

        // Update indices
        Self::v_add_to_owner_index(view, &mint_data.to, collection_id, token_id)?;
        Self::v_add_to_collection_index(view, collection_id, token_id)?;
```
Replacement:
```rust
        // Update indices
        Self::v_add_to_owner_index(view, &mint_data.to, collection_id, token_id)?;
        Self::v_add_to_collection_index(view, collection_id, token_id)?;

        // Store token
        Self::v_put_token(view, collection_id, token_id, &token_data)?;
```
Printed by libtest while mutated:
```
test a_refusal_part_way_leaves_canonical_storage_untouched ... FAILED
```

#### E3 mint writes the collection index before the owner index

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_refusal_part_way_leaves_canonical_storage_untouched` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `1fbc9552a23ec19e` -> replacement `6b6462f95b026b10`
* verdict: **KILLED   [scoped re-run, after the covering test was strengthened]**

Anchor:
```rust
        Self::v_add_to_owner_index(view, &mint_data.to, collection_id, token_id)?;
        Self::v_add_to_collection_index(view, collection_id, token_id)?;

        // Update collection
```
Replacement:
```rust
        Self::v_add_to_collection_index(view, collection_id, token_id)?;
        Self::v_add_to_owner_index(view, &mint_data.to, collection_id, token_id)?;

        // Update collection
```
Printed by libtest while mutated:
```
test a_refusal_part_way_leaves_canonical_storage_untouched ... FAILED
```

#### E4 mint writes the collection row first

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_refusal_part_way_leaves_canonical_storage_untouched` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `3a76950f9bfc8939` -> replacement `728a94f7d8535042`
* verdict: **KILLED   [scoped re-run, after the covering test was strengthened]**

Anchor:
```rust
        // Store token
        Self::v_put_token(view, collection_id, token_id, &token_data)?;
```
Replacement:
```rust
        Self::v_put_collection(view, collection_id, &collection)?;

        // Store token
        Self::v_put_token(view, collection_id, token_id, &token_data)?;
```
Printed by libtest while mutated:
```
test a_refusal_part_way_leaves_canonical_storage_untouched ... FAILED
```

#### J1 an absent collection becomes a failed receipt

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_transaction_naming_an_absent_collection_aborts_the_whole_block` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `20ddf367ba54c900` -> replacement `9fd6f21a9a5c743f`
* verdict: **KILLED**

Anchor:
```rust
        fee: Balance,
        block_timestamp: u64,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;
```
Replacement:
```rust
        fee: Balance,
        block_timestamp: u64,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let Some(mut collection) = Self::v_get_collection(view, collection_id)? else {
            return Ok(NftExecutionResult::failure(
                "Collection not found".to_string(),
            ));
        };
```
Printed by libtest while mutated:
```
test a_transaction_naming_an_absent_collection_aborts_the_whole_block ... FAILED
```

#### J2 an absent token becomes a failed receipt

* occurrences checked before applying: **1** (expected 1)
* covering test: `burning_a_token_and_then_using_it_in_one_block_aborts_the_block` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `ec91677a5ba7c268` -> replacement `f2f013feaeefea71`
* verdict: **KILLED**

Anchor:
```rust
        // Get token
        let token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership or approval
```
Replacement:
```rust
        // Get token
        let Some(token) = Self::v_get_token(view, collection_id, token_id)? else {
            return Ok(NftExecutionResult::failure("Token not found".to_string()));
        };

        // Check ownership or approval
```
Printed by libtest while mutated:
```
test burning_a_token_and_then_using_it_in_one_block_aborts_the_block ... FAILED
```

#### J3 an invalid config becomes a failed receipt

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_invalid_collection_config_aborts_the_whole_block` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `9362b1ca54acc163` -> replacement `589cab8fcb214f86`
* verdict: **KILLED**

Anchor:
```rust
        create_data
            .config
            .validate()
            .map_err(|e| StateError::BlockValidation(format!("Invalid config: {}", e)))?;
```
Replacement:
```rust
        if let Err(e) = create_data.config.validate() {
            return Ok(NftExecutionResult::failure(format!("Invalid config: {}", e)));
        }
```
Printed by libtest while mutated:
```
test an_invalid_collection_config_aborts_the_whole_block ... FAILED
```

#### J4 the fee is not charged before the guards

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_refused_nft_operation_has_already_charged_the_fee` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `7db1bb6e20f89ae8` -> replacement `ba97e4b8aa583c5f`
* verdict: **KILLED**

Anchor:
```rust
        // Deduct fee from sender
        Self::deduct_fee(view, sender, fee, proposer)?;
```
Replacement:
```rust
        // Deduct fee from sender
        if !matches!(nft_data.operation, NftOperation::Mint) {
            Self::deduct_fee(view, sender, fee, proposer)?;
        }
```
Printed by libtest while mutated:
```
test a_refused_nft_operation_has_already_charged_the_fee ... FAILED
```

#### J5 SetApprovalForAll reports success

* occurrences checked before applying: **1** (expected 1)
* covering test: `set_approval_for_all_charges_a_fee_and_does_nothing` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `a9d536481ed948f5` -> replacement `1ad81e868c06b822`
* verdict: **KILLED**

Anchor:
```rust
                Ok(NftExecutionResult::failure(
                    "SetApprovalForAll not yet implemented".to_string(),
                ))
```
Replacement:
```rust
                Ok(NftExecutionResult::success())
```
Printed by libtest while mutated:
```
test set_approval_for_all_charges_a_fee_and_does_nothing ... FAILED
```

#### J6 update_metadata gains a size limit

* occurrences checked before applying: **1** (expected 1)
* covering test: `update_metadata_accepts_any_size_and_charges_no_storage_fee` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `dea177b15ae8141a` -> replacement `1a5e8c52f465a8d4`
* verdict: **KILLED**

Anchor:
```rust
        // Update metadata
        token.metadata = data.to_vec();
```
Replacement:
```rust
        // Update metadata
        if data.len() > 16_384 {
            return Ok(NftExecutionResult::failure("Metadata too large".to_string()));
        }
        token.metadata = data.to_vec();
```
Printed by libtest while mutated:
```
test update_metadata_accepts_any_size_and_charges_no_storage_fee ... FAILED
```

#### J7 update_metadata drops the creator clause

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_creator_can_rewrite_metadata_of_a_token_it_no_longer_owns` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `bd065e9b9daf0643` -> replacement `441baf4f1399ffb6`
* verdict: **KILLED**

Anchor:
```rust
        if token.owner != *sender && token.creator != *sender {
```
Replacement:
```rust
        if token.owner != *sender {
```
Printed by libtest while mutated:
```
test the_creator_can_rewrite_metadata_of_a_token_it_no_longer_owns ... FAILED
```

#### J8 approve gains a lock check

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_locked_token_can_still_be_approved_and_rewritten` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `c48aa76f60217993` -> replacement `cc36b4ae93c23894`
* verdict: **KILLED**

Anchor:
```rust
        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        // Deserialize approval data
```
Replacement:
```rust
        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        if token.locked {
            return Ok(NftExecutionResult::failure("Token is locked".to_string()));
        }

        // Deserialize approval data
```
Printed by libtest while mutated:
```
test a_locked_token_can_still_be_approved_and_rewritten ... FAILED
```

#### J9 batch_mint gains a metadata size limit

* occurrences checked before applying: **1** (expected 1)
* covering test: `batch_mint_ignores_the_metadata_size_limit_and_the_storage_fee` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `9ad7f770773bf0bd` -> replacement `d52fae5927712625`
* verdict: **KILLED**

Anchor:
```rust
        let first_token_id = collection.next_token_id;

        for (i, request) in batch_data.requests.iter().enumerate() {
```
Replacement:
```rust
        let first_token_id = collection.next_token_id;

        if batch_data.requests.iter().any(|r| r.metadata.len() > 16_384) {
            return Ok(NftExecutionResult::failure("Metadata too large".to_string()));
        }

        for (i, request) in batch_data.requests.iter().enumerate() {
```
Printed by libtest while mutated:
```
test batch_mint_ignores_the_metadata_size_limit_and_the_storage_fee ... FAILED
```

#### J10 the collection id nonce is not the block timestamp

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_collection_in_the_same_block_is_refused` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `8321e7842e57a7ec` -> replacement `ba33f922a1b21759`
* verdict: **KILLED**

Anchor:
```rust
        let nonce = Self::now_ms(block_timestamp);
        let collection_id = CollectionId::new(sender, &create_data.name, nonce);
```
Replacement:
```rust
        let nonce = 0u64;
        let collection_id = CollectionId::new(sender, &create_data.name, nonce);
```
Printed by libtest while mutated:
```
test a_duplicate_collection_in_the_same_block_is_refused ... FAILED
```

#### J11 creation keeps a recipient on a zero royalty

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_royalty_recipient_can_be_set_on_a_collection_that_pays_no_royalty` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `766d23b740e9d7e7` -> replacement `3bb1cc813fe05880`
* verdict: **KILLED**

Anchor:
```rust
            royalty_recipient: if create_data.config.royalty_bps > 0 {
```
Replacement:
```rust
            royalty_recipient: if true {
```
Printed by libtest while mutated:
```
test a_royalty_recipient_can_be_set_on_a_collection_that_pays_no_royalty ... FAILED
```

#### J12 transfer drops the approval clause

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_approval_in_one_block_lets_the_approved_address_transfer_in_the_same_block` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `5893755600822752` -> replacement `1b1b7092407f7719`
* verdict: **KILLED**

Anchor:
```rust
        if !is_owner && !is_approved {
```
Replacement:
```rust
        if !is_owner {
```
Printed by libtest while mutated:
```
test an_approval_in_one_block_lets_the_approved_address_transfer_in_the_same_block ... FAILED
```

#### J13 transfer drops the ownership guard

* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_first_transfer_the_second_is_refused` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `5a6714d3bdf5af98` -> replacement `d05d68034beba41b`
* verdict: **KILLED**

Anchor:
```rust
        if !is_owner && !is_approved {
            return Ok(NftExecutionResult::failure(
                "Not owner or approved".to_string(),
            ));
        }
```
Replacement:
```rust
        if false {
            return Ok(NftExecutionResult::failure(
                "Not owner or approved".to_string(),
            ));
        }
```
Printed by libtest while mutated:
```
test without_the_first_transfer_the_second_is_refused ... FAILED
```

#### J14 transfer drops the lock guard

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_lock_in_one_block_stops_a_transfer_in_the_same_block` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `a11164e5fb210174` -> replacement `ac4581e6a37e7e4a`
* verdict: **KILLED**

Anchor:
```rust
        // Check if locked
        if token.locked {
            return Ok(NftExecutionResult::failure("Token is locked".to_string()));
        }

        // Deserialize recipient
```
Replacement:
```rust
        // Deserialize recipient
```
Printed by libtest while mutated:
```
test a_lock_in_one_block_stops_a_transfer_in_the_same_block ... FAILED
```

#### J15 the max supply guard is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `max_supply_is_reached_within_one_block` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `24ddc85e58992e1e` -> replacement `4ef6a0810416e38b`
* verdict: **KILLED**

Anchor:
```rust
        if collection.max_supply > 0 && collection.total_supply >= collection.max_supply {
```
Replacement:
```rust
        if false {
```
Printed by libtest while mutated:
```
test max_supply_is_reached_within_one_block ... FAILED
```

#### J16 next_token_id stops advancing

* occurrences checked before applying: **1** (expected 1)
* covering test: `two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `e199fdca8d522fb1` -> replacement `f56e68461bac0faa`
* verdict: **KILLED**

Anchor:
```rust
        collection.total_supply += 1;
        collection.next_token_id += 1;
```
Replacement:
```rust
        collection.total_supply += 1;
```
Printed by libtest while mutated:
```
test two_mints_in_one_block_get_distinct_ids_and_accumulate_in_both_indexes ... FAILED
```

#### J17 total_supply stops advancing

* occurrences checked before applying: **1** (expected 1)
* covering test: `max_supply_is_reached_within_one_block` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `cf890405befa4495` -> replacement `579e098a483c0f9e`
* verdict: **KILLED**

Anchor:
```rust
        collection.total_supply += 1;
        collection.next_token_id += 1;
        Self::v_put_collection(view, collection_id, &collection)?;
```
Replacement:
```rust
        collection.next_token_id += 1;
        Self::v_put_collection(view, collection_id, &collection)?;
```
Printed by libtest while mutated:
```
test max_supply_is_reached_within_one_block ... FAILED
```

#### J18 the issuer guard is dropped

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_unregistered_issuer_cannot_mint_a_document` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `946f00db9c3b07a6` -> replacement `14bbd07e0b4838cd`
* verdict: **KILLED**

Anchor:
```rust
            if !Self::v_can_mint_documents(view, sender, None, current_time)? {
```
Replacement:
```rust
            if false {
```
Printed by libtest while mutated:
```
test an_unregistered_issuer_cannot_mint_a_document ... FAILED
```

#### J20 approve gains a transferable check

* occurrences checked before applying: **1** (expected 1)
* covering test: `approve_never_reads_the_collection` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `e836ff97e8cf4417` -> replacement `9fd5b79fe2a84eaa`
* verdict: **KILLED**

Anchor:
```rust
        // Deserialize approval data
        // Shared wire struct (issue #89)
        let approve_data: NftApproveData = bincode::deserialize(data)
```
Replacement:
```rust
        // Deserialize approval data
        // Shared wire struct (issue #89)
        if !Self::v_get_collection(view, collection_id)?
            .map(|c| c.transferable)
            .unwrap_or(false)
        {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow transfers".to_string(),
            ));
        }
        let approve_data: NftApproveData = bincode::deserialize(data)
```
Printed by libtest while mutated:
```
test approve_never_reads_the_collection ... FAILED
```

#### J21 transfer pays the royalty

* occurrences checked before applying: **1** (expected 1)
* covering test: `royalties_are_recorded_and_never_paid` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `745159c29782f8e6` -> replacement `69625e4fd2bd01a4`
* verdict: **KILLED**

Anchor:
```rust
        // Execute transfer
        Self::v_transfer_token(
```
Replacement:
```rust
        // Execute transfer
        if collection.royalty_bps > 0 {
            StateManager::v_credit(view, &collection.royalty_recipient, 1)?;
        }
        Self::v_transfer_token(
```
Printed by libtest while mutated:
```
test royalties_are_recorded_and_never_paid ... FAILED
test was strengthened to read `ExecutionView::preimage`:
```

### `crates/storage/src/nft_store.rs`


#### F1 the collection key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_collection_row_is_bincode_at_the_collection_id_key` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `54c6e415e4753844` -> replacement `f8c12e944b719e92`
* verdict: **KILLED**

Anchor:
```rust
pub fn collection_key(collection_id: &[u8; 32]) -> &[u8] {
    collection_id
}
```
Replacement:
```rust
pub fn collection_key(collection_id: &[u8; 32]) -> &[u8] {
    &collection_id[..16]
}
```
Printed by libtest while mutated:
```
test a_collection_row_is_bincode_at_the_collection_id_key ... FAILED
```

#### F2 the token key is little-endian

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_token_row_is_bincode_at_the_forty_byte_big_endian_key` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `b28566d4f411db46` -> replacement `bcd779eaceb092a5`
* verdict: **KILLED**

Anchor:
```rust
    key.extend_from_slice(&token_id.to_be_bytes());
```
Replacement:
```rust
    key.extend_from_slice(&token_id.to_le_bytes());
```
Printed by libtest while mutated:
```
test a_token_row_is_bincode_at_the_forty_byte_big_endian_key ... FAILED
```

#### F3 the token key puts the id first

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_token_row_is_bincode_at_the_forty_byte_big_endian_key` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `04d27f577975d253` -> replacement `d37546e327c51f2b`
* verdict: **KILLED**

Anchor:
```rust
    key.extend_from_slice(collection_id);
    key.extend_from_slice(&token_id.to_be_bytes());
    key
```
Replacement:
```rust
    key.extend_from_slice(&token_id.to_be_bytes());
    key.extend_from_slice(collection_id);
    key
```
Printed by libtest while mutated:
```
test a_token_row_is_bincode_at_the_forty_byte_big_endian_key ... FAILED
```

#### F4 the owner index key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_owner_index_is_a_list_of_length_prefixed_collection_ids` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `8a21a2051ae2c4db` -> replacement `52c468c708d756e1`
* verdict: **KILLED**

Anchor:
```rust
pub fn owner_index_key(owner: &Address) -> &[u8] {
    owner.as_bytes()
}
```
Replacement:
```rust
pub fn owner_index_key(owner: &Address) -> &[u8] {
    &owner.as_bytes()[..10]
}
```
Printed by libtest while mutated:
```
test the_owner_index_is_a_list_of_length_prefixed_collection_ids ... FAILED
```

#### F5 the collection index key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_collection_index_is_a_bare_list_of_token_ids` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `4aa50f9cf95e2f99` -> replacement `1efecbd33d079a66`
* verdict: **KILLED**

Anchor:
```rust
pub fn collection_index_key(collection_id: &[u8; 32]) -> &[u8] {
    collection_id
}
```
Replacement:
```rust
pub fn collection_index_key(collection_id: &[u8; 32]) -> &[u8] {
    &collection_id[..16]
}
```
Printed by libtest while mutated:
```
test the_collection_index_is_a_bare_list_of_token_ids ... FAILED
```

#### F6 the issuer key is truncated

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_row_is_bincode_at_the_issuer_address_key` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `613062373f4b9486` -> replacement `e750902caaa4c58d`
* verdict: **KILLED**

Anchor:
```rust
pub fn issuer_key(address: &Address) -> &[u8] {
    address.as_bytes()
}
```
Replacement:
```rust
pub fn issuer_key(address: &Address) -> &[u8] {
    &address.as_bytes()[..10]
}
```
Printed by libtest while mutated:
```
test an_issuer_row_is_bincode_at_the_issuer_address_key ... FAILED
```

#### G1 the collection encoder prefixes a byte

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_collection_row_is_bincode_at_the_collection_id_key` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `819494dc38dde958` -> replacement `9e516180afbc6535`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_collection(c: &NftCollectionData) -> Result<Vec<u8>> {
    bincode::serialize(c).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_collection(c: &NftCollectionData) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, c)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_collection_row_is_bincode_at_the_collection_id_key ... FAILED
```

#### G2 the token encoder prefixes a byte

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_token_row_is_bincode_at_the_forty_byte_big_endian_key` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `d97d66dddc5a6061` -> replacement `d4e01d0d2dd74c93`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_token(t: &NftTokenData) -> Result<Vec<u8>> {
    bincode::serialize(t).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_token(t: &NftTokenData) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, t)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test a_token_row_is_bincode_at_the_forty_byte_big_endian_key ... FAILED
```

#### G3 the owner list encoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `both_indexes_append_in_insertion_order` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `95619059f82f5a2c` -> replacement `31113b079d96087c`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_owner_tokens(tokens: &[OwnerTokenEntry]) -> Result<Vec<u8>> {
    bincode::serialize(tokens).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_owner_tokens(tokens: &[OwnerTokenEntry]) -> Result<Vec<u8>> {
    let mut t = tokens.to_vec();
    t.reverse();
    bincode::serialize(&t).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test both_indexes_append_in_insertion_order ... FAILED
```

#### G4 the collection list encoder reverses the list

* occurrences checked before applying: **1** (expected 1)
* covering test: `both_indexes_append_in_insertion_order` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `3abda64d25a6c3a3` -> replacement `14cab39493692823`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_collection_tokens(tokens: &[u64]) -> Result<Vec<u8>> {
    bincode::serialize(tokens).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_collection_tokens(tokens: &[u64]) -> Result<Vec<u8>> {
    let mut t = tokens.to_vec();
    t.reverse();
    bincode::serialize(&t).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test both_indexes_append_in_insertion_order ... FAILED
```

#### G5 the issuer encoder prefixes a byte

* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_row_is_bincode_at_the_issuer_address_key` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `acb9928e9b99b92c` -> replacement `ad167022ec9a60d2`
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_issuer(i: &IssuerData) -> Result<Vec<u8>> {
    bincode::serialize(i).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn encode_issuer(i: &IssuerData) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, i)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Printed by libtest while mutated:
```
test an_issuer_row_is_bincode_at_the_issuer_address_key ... FAILED
```

#### G6 the owner list decoder swallows a malformed row

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `70c5e123482864a7` -> replacement `f6f98e9793fc5aa2`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_owner_tokens(bytes: &[u8]) -> Result<Vec<OwnerTokenEntry>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_owner_tokens(bytes: &[u8]) -> Result<Vec<OwnerTokenEntry>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

#### G7 the collection list decoder swallows a malformed row

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_malformed_row_is_an_error_from_every_decoding_reader` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `a5b150522288a609` -> replacement `c55f153ec8ad45c8`
* verdict: **KILLED**

Anchor:
```rust
pub fn decode_collection_tokens(bytes: &[u8]) -> Result<Vec<u64>> {
    bincode::deserialize(bytes).map_err(|e| StorageError::Serialization(e.to_string()))
}
```
Replacement:
```rust
pub fn decode_collection_tokens(bytes: &[u8]) -> Result<Vec<u64>> {
    Ok(bincode::deserialize(bytes).unwrap_or_default())
}
```
Printed by libtest while mutated:
```
test a_malformed_row_is_an_error_from_every_decoding_reader ... FAILED
```

### `crates/storage/src/schema.rs`


#### K1 the committed owner index duplicates an entry

* occurrences checked before applying: **1** (expected 1)
* covering test: `re_adding_an_entry_rewrites_an_identical_list_rather_than_duplicating_it` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `3ece4bbe01aca390` -> replacement `a121debc08d5c958`
* verdict: **KILLED**

Anchor:
```rust
        if !tokens.iter().any(|(c, t)| c == collection_id && *t == token_id) {
            tokens.push(entry);
        }
```
Replacement:
```rust
        tokens.push(entry);
```
Printed by libtest while mutated:
```
test re_adding_an_entry_rewrites_an_identical_list_rather_than_duplicating_it ... FAILED
```

#### K2 the committed owner index writes empty instead of deleting

* occurrences checked before applying: **1** (expected 1)
* covering test: `removal_is_asymmetric_between_the_two_indexes` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `07e4ca616ce32a41` -> replacement `e55ded4121b44b07`
* verdict: **KILLED**

Anchor:
```rust
        if tokens.is_empty() {
            self.db
                .delete(cf::NFT_OWNER_INDEX, owner_index_key(owner))?;
        } else {
```
Replacement:
```rust
        if false {
            self.db
                .delete(cf::NFT_OWNER_INDEX, owner_index_key(owner))?;
        } else {
```
Printed by libtest while mutated:
```
test removal_is_asymmetric_between_the_two_indexes ... FAILED
```

#### K3 the committed collection index deletes instead of writing empty

* occurrences checked before applying: **1** (expected 1)
* covering test: `removal_is_asymmetric_between_the_two_indexes` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `244346d33d39c10a` -> replacement `83b624f4987a03fd`
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_collection_tokens(&tokens)?;
        self.db.put(
            cf::NFT_COLLECTION_INDEX,
            collection_index_key(collection_id),
            &bytes,
        )
    }

    /// Get all token IDs in a collection
```
Replacement:
```rust
        let _ = encode_collection_tokens(&tokens)?;
        self.db
            .delete(cf::NFT_COLLECTION_INDEX, collection_index_key(collection_id))
    }

    /// Get all token IDs in a collection
```
Printed by libtest while mutated:
```
test removal_is_asymmetric_between_the_two_indexes ... FAILED
```

#### K4 the committed burn stops decrementing the supply

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_burn_deletes_the_token_and_decrements_the_supply` (`sumchain-storage --test nft_codec_parity`)
* anchor sha256[:16] `b7dfea4af776cf8c` -> replacement `74309eb5f4253ee4`
* verdict: **KILLED**

Anchor:
```rust
            collection.total_supply = collection.total_supply.saturating_sub(1);
```
Replacement:
```rust
            collection.total_supply = collection.total_supply;
```
Printed by libtest while mutated:
```
test a_burn_deletes_the_token_and_decrements_the_supply ... FAILED
```

### `crates/state/src/executor.rs`


#### I1 the live dispatch surface is not routed

* occurrences checked before applying: **1** (expected 1)
* covering test: `a_chain_of_transfers_in_one_block_reaches_the_last_owner` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `044a4068d82fbed2` -> replacement `b42299c013d51935`
* verdict: **KILLED**

Anchor:
```rust
                        let result = NftExecutor::execute(
                            view,
                            &self.params,
                            &v2_tx.from,
```
Replacement:
```rust
                        let result = NftExecutor::execute(
                            &mut sumchain_storage::candidate::CandidateExecution::new(
                                &self.db,
                                u64::MAX,
                            )
                            .view(),
                            &self.params,
                            &v2_tx.from,
```
Printed by libtest while mutated:
```
test a_chain_of_transfers_in_one_block_reaches_the_last_owner ... FAILED
```

#### I2 the v2 dispatch surface is not routed

* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_also_stages_nfts` (`sumchain-state --test nft_routing`)
* anchor sha256[:16] `55c5a0c60fd248de` -> replacement `c572d238a0d91801`
* verdict: **KILLED**

Anchor:
```rust
                let result = NftExecutor::execute(
                    view,
                    &self.params,
                    &tx.from,
```
Replacement:
```rust
                let result = NftExecutor::execute(
                    &mut sumchain_storage::candidate::CandidateExecution::new(
                        &self.db,
                        u64::MAX,
                    )
                    .view(),
                    &self.params,
                    &tx.from,
```
Printed by libtest while mutated:
```
test the_v2_dispatch_surface_also_stages_nfts ... FAILED
```

## Totals and post-run hashes

```
=== totals ===
  first pass:   killed 70, survived 1 (E4), declared 71, scored 71
  scoped re-run of the three mutations covered by
  `a_refusal_part_way_leaves_canonical_storage_untouched`, after that
  test was strengthened to read `ExecutionView::preimage`:
    E2 KILLED, E3 KILLED, E4 KILLED
  final:        killed 71, survived 0, declared 71, scored 71

=== post-run hashes (authoritative) ===
  MATCH   c1f2ba90b895f5a6e717071bed1b237b9f59e3445a35768927305d57fb1841c5  crates/state/src/nft_view.rs
  MATCH   0ff9435bb63dee3593b1d245f87f8b03e8ad1a9456bacb797b700297af8dc999  crates/state/src/nft_executor.rs
  MATCH   f1903f882024498bea7713b2859360df78947467f7f8a3a85e08457e8cdae07d  crates/state/src/executor.rs
  MATCH   388fe9590d610480c60ce3d2247167cb23a8e488da885fd7b0507951abaeede1  crates/storage/src/nft_store.rs
  MATCH   59e6836129e34472c3144be2cb7abb36f6cc04744a6b5a9b09383a18205b1ce5  crates/storage/src/schema.rs
  all five byte-identical to pre-run: True

=== anchors resolve exactly once again ===
  71/71
```


## Residue audit

```
=== 1. the five mutated files vs the pre-run backups ===
  MATCH  crates/state/src/nft_view.rs  c1f2ba90b895f5a6
  MATCH  crates/state/src/nft_executor.rs  0ff9435bb63dee35
  MATCH  crates/state/src/executor.rs  f1903f882024498b
  MATCH  crates/storage/src/nft_store.rs  388fe9590d610480
  MATCH  crates/storage/src/schema.rs  59e6836129e34472
  all five restored: True

=== 2. whole-crates scan, 62 specific replacements ===
  residue: NONE

  9 replacements are generic text (Ok(false) / Ok(()) / deletion)
  and are covered by check 1 only -- a text scan for them is meaningless.

=== 3. every anchor still resolves exactly once ===
  anchors resolving once: 71/71; not-once: []
```

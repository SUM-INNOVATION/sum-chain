//! Governance, token and equity: the committed store and the shared helpers
//! agree byte-for-byte.
//!
//! These three subsystems migrate to the execution view as one package, because
//! their same-block dependencies run across each other: governance reads token
//! balances for create-thresholds, scans `TOKEN_BALANCES` to freeze a vote
//! snapshot, and reads equity state to register a class. That routing is a
//! later commit. This one only makes the halves shareable — every key builder
//! and every codec the candidate side will call is the one the committed store
//! already calls — and pins that with tests.
//!
//! ## Why byte parity, and not a round-trip
//!
//! A round-trip test (`decode(encode(v)) == v`) passes for ANY self-consistent
//! codec. It would still pass if the candidate encoded a token balance as
//! bincode while the committed store wrote 16 big-endian bytes: each side reads
//! back what it wrote, and the two disagree only about rows the other produced —
//! which is exactly the case a candidate creates, and exactly the case no test
//! that owns both ends will construct.
//!
//! So these assert on BYTES: what the committed store actually left in the
//! column family, against what the shared helper produces for the same input.
//! A future edit that reintroduces a private codec inside a store fails here.
//!
//! ## The trap this package carries
//!
//! A token balance is a bare 16-byte big-endian `u128`. An equity balance is a
//! bincode `u64`. They are adjacent subsystems, migrating together, and they
//! encode "a balance" differently. A shared helper that normalised them would
//! round-trip perfectly and corrupt every row it touched, so both encodings are
//! pinned here explicitly, including their widths.
//!
//! ## Absence is not zero
//!
//! Token balances, token allowances and equity balances all DELETE the row at
//! zero rather than storing one. That is a byte-level fact about the family —
//! the difference between no row and a row of zeroes — and the candidate side
//! has to reproduce it or an abandoned block's rollback would restore the wrong
//! shape. Pinned below.

use sumchain_primitives::equity::{
    ControllerModel, EntityProfile, EntityStatus, OrgType,
};
use sumchain_primitives::Address;
use sumchain_storage::db::{cf, Database};
use sumchain_storage::equity_store::{
    decode_class_id_list, decode_equity_balance, encode_class_id_list, encode_equity_balance,
    encode_entity_profile, EntityProfileStore, EquityBalanceStore,
};
use sumchain_storage::governance_store::{
    asset_key, composite_key, decode_snapshot_weight, encode_snapshot_weight,
    equity_commitment_key, proposer_index_key, ser, GovStore, QualifyingAsset,
};
use sumchain_storage::schema::{
    decode_holder_tokens, decode_token_amount, encode_holder_tokens, encode_src20_token,
    encode_token_amount, Src20TokenData, TokenStore,
};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    (Database::open_default(dir.path()).expect("open"), dir)
}

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

fn token_data(owner: Address) -> Src20TokenData {
    Src20TokenData {
        name: "Parity".to_string(),
        symbol: "PAR".to_string(),
        decimals: 8,
        owner,
        total_supply: 1_000_000,
        max_supply: 0,
        mintable: true,
        burnable: true,
        pausable: false,
        paused: false,
        minters: vec![owner],
        created_at: 42,
        created_at_block: 7,
    }
}

// ── Keys are byte layouts, not opaque handles ────────────────────────────────

/// The token key builders lay out exactly what they claim.
///
/// These are concatenations, and the candidate side will build the same keys
/// from the same function. Pinning the layout means a change to it is a change
/// both sides take together, rather than one side silently addressing rows the
/// other cannot find.
#[test]
fn token_key_layouts_are_exact() {
    let t = [0xA1u8; 32];
    let owner = addr(0xB1);
    let spender = addr(0xC1);

    let bal = TokenStore::balance_key(&t, &owner);
    assert_eq!(bal.len(), 52, "token_id (32) || owner (20)");
    assert_eq!(&bal[..32], &t);
    assert_eq!(&bal[32..], owner.as_bytes());

    let allow = TokenStore::allowance_key(&t, &owner, &spender);
    assert_eq!(allow.len(), 72, "token_id (32) || owner (20) || spender (20)");
    assert_eq!(&allow[..32], &t);
    assert_eq!(&allow[32..52], owner.as_bytes());
    assert_eq!(&allow[52..], spender.as_bytes());

    // Distinct spenders must not collide onto one allowance row.
    assert_ne!(allow, TokenStore::allowance_key(&t, &owner, &addr(0xC2)));
}

/// The equity balance key is `class_id || holder_commitment`, fixed at 64.
#[test]
fn equity_balance_key_layout_is_exact() {
    let class = [0xE1u8; 32];
    let holder = [0xE2u8; 32];
    let k = EquityBalanceStore::make_key(&class, &holder);
    assert_eq!(k.len(), 64);
    assert_eq!(&k[..32], &class);
    assert_eq!(&k[32..], &holder);
    assert_ne!(k, EquityBalanceStore::make_key(&holder, &class), "order matters");
}

/// The governance key builders lay out what they claim, and the two composite
/// families do not collide with each other.
#[test]
fn governance_key_layouts_are_exact() {
    let pid = [0x11u8; 32];
    let voter = addr(0x22);
    let proposer = addr(0x33);

    let vote = composite_key(&pid, &voter);
    assert_eq!(vote.len(), 52, "proposal_id (32) || address (20)");
    assert_eq!(&vote[..32], &pid);
    assert_eq!(&vote[32..], voter.as_bytes());

    let idx = proposer_index_key(&proposer, &pid);
    assert_eq!(idx.len(), 52, "proposer (20) || proposal_id (32)");
    assert_eq!(&idx[..20], proposer.as_bytes());
    assert_eq!(&idx[20..], &pid);

    // Same two values, opposite order: the index must not alias a vote row.
    assert_ne!(vote, idx);

    // Asset keys distinguish their kinds.
    use sumchain_primitives::governance::GovAssetKind;
    assert_ne!(
        asset_key(&GovAssetKind::NativeEligibility),
        asset_key(&GovAssetKind::Src20Token([0x44; 32]))
    );
}

// ── The two balance encodings, which are NOT the same ────────────────────────

/// A token amount is sixteen big-endian bytes, and nothing else.
#[test]
fn a_token_amount_is_sixteen_big_endian_bytes() {
    assert_eq!(
        encode_token_amount(1),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        "big-endian: the high byte comes first"
    );
    assert_eq!(encode_token_amount(u128::MAX), [0xFF; 16]);
    assert_eq!(decode_token_amount(&encode_token_amount(1 << 100)).unwrap(), 1 << 100);

    // A bincode encoding of the same number is a different byte string. If the
    // candidate ever used one, every row it wrote would decode wrong here.
    let via_bincode = bincode::serialize(&1u128).unwrap();
    assert_ne!(
        via_bincode.as_slice(),
        encode_token_amount(1).as_slice(),
        "bincode and the stored form differ — they must not be interchanged"
    );

    // Short rows are corruption, not small numbers.
    assert!(decode_token_amount(&[0u8; 8]).is_err());
    assert!(decode_token_amount(&[]).is_err());
    assert!(decode_token_amount(&[0u8; 17]).is_err());
}

/// An equity balance is a bincode `u64` — deliberately not the token encoding.
#[test]
fn an_equity_balance_is_not_encoded_like_a_token_balance() {
    let n: u64 = 1;
    let equity = encode_equity_balance(&n).unwrap();
    assert_eq!(decode_equity_balance(&equity).unwrap(), 1);
    assert_ne!(
        equity.as_slice(),
        &encode_token_amount(1)[..],
        "equity and token balances encode differently; a shared helper that \
         normalised them would round-trip and still corrupt every row"
    );
    assert_eq!(equity.len(), 8, "bincode u64 is eight bytes here");
}

// ── Store bytes == helper bytes ──────────────────────────────────────────────

/// What `TokenStore` leaves in each column family is what the helpers produce.
#[test]
fn token_store_writes_exactly_what_the_helpers_encode() {
    let (db, _dir) = db();
    let store = TokenStore::new(&db);
    let t = [0x77u8; 32];
    let owner = addr(0x88);
    let spender = addr(0x99);
    let data = token_data(owner);

    store.put_token(&t, &data).unwrap();
    assert_eq!(
        db.get(cf::TOKENS, &t).unwrap().unwrap(),
        encode_src20_token(&data).unwrap(),
        "cf::TOKENS holds exactly encode_src20_token"
    );

    store.set_balance(&t, &owner, 12_345).unwrap();
    let key = TokenStore::balance_key(&t, &owner);
    assert_eq!(
        db.get(cf::TOKEN_BALANCES, &key).unwrap().unwrap(),
        encode_token_amount(12_345).to_vec(),
        "the balance row is at the shared key and holds the shared encoding"
    );

    store.set_allowance(&t, &owner, &spender, 999).unwrap();
    assert_eq!(
        db.get(cf::TOKEN_ALLOWANCES, &TokenStore::allowance_key(&t, &owner, &spender))
            .unwrap()
            .unwrap(),
        encode_token_amount(999).to_vec()
    );

    // The holder index is keyed by the owner's bytes and holds the shared list
    // encoding.
    let raw = db
        .get(cf::TOKEN_HOLDER_INDEX, owner.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(decode_holder_tokens(&raw).unwrap(), vec![t.to_vec()]);
    assert_eq!(raw, encode_holder_tokens(&vec![t.to_vec()]).unwrap());
}

/// What the equity stores leave in their families is what the helpers produce.
#[test]
fn equity_stores_write_exactly_what_the_helpers_encode() {
    let (db, _dir) = db();
    let class = [0x21u8; 32];
    let holder = [0x22u8; 32];

    EquityBalanceStore::new(&db)
        .set_balance(&class, &holder, 500)
        .unwrap();
    let key = EquityBalanceStore::make_key(&class, &holder);
    assert_eq!(
        db.get(cf::EQUITY_BALANCES, &key).unwrap().unwrap(),
        encode_equity_balance(&500).unwrap(),
        "the equity balance row holds the shared encoding, at the shared key"
    );
    let raw = db.get(cf::EQUITY_HOLDER_INDEX, &holder).unwrap().unwrap();
    assert_eq!(decode_class_id_list(&raw).unwrap(), vec![class]);
    assert_eq!(raw, encode_class_id_list(&vec![class]).unwrap());

    let profile = EntityProfile {
        subject_id: [0x31; 32],
        org_type: OrgType::Corporation,
        name_commitment: [0x32; 32],
        jurisdiction: Some("XX".to_string()),
        registration_commitment: Some([0x33; 32]),
        controller_model: ControllerModel::SingleSigner,
        controllers: vec![addr(0x34)],
        multisig_threshold: None,
        services: Vec::new(),
        metadata_hash: [0x35; 32],
        created_at: 1,
        updated_at: 2,
        status: EntityStatus::Active,
    };
    EntityProfileStore::new(&db).put(&profile).unwrap();
    assert_eq!(
        db.get(cf::EQUITY_ENTITIES, &profile.subject_id)
            .unwrap()
            .unwrap(),
        encode_entity_profile(&profile).unwrap()
    );
}

/// What `GovStore` leaves in its families is what the helpers produce.
#[test]
fn gov_store_writes_exactly_what_the_helpers_encode() {
    let (db, _dir) = db();
    let store = GovStore::new(&db);

    let qa = QualifyingAsset {
        token_id: [0x55; 32],
        min_balance: 10,
        effective_height: 3,
    };
    store.put_qualifying_asset(&qa).unwrap();
    assert_eq!(
        db.get(cf::GOV_QUALIFYING_ASSETS, &qa.token_id)
            .unwrap()
            .unwrap(),
        ser(&qa).unwrap(),
        "cf::GOV_QUALIFYING_ASSETS holds exactly the shared encoder's output"
    );
}

// ── Absence is not a zero row ────────────────────────────────────────────────

/// Zero deletes the row in all three balance-like families.
///
/// The candidate side has to reproduce this exactly. Storing a zero instead
/// would leave a row where the chain has none, and an abandoned block's
/// rollback would then restore the wrong shape — a row of zeroes is not the
/// absence it replaced.
#[test]
fn zero_removes_the_row_rather_than_storing_one() {
    let (db, _dir) = db();
    let t = [0x61u8; 32];
    let owner = addr(0x62);
    let spender = addr(0x63);
    let store = TokenStore::new(&db);

    store.set_balance(&t, &owner, 5).unwrap();
    store.set_allowance(&t, &owner, &spender, 5).unwrap();
    assert!(db
        .get(cf::TOKEN_BALANCES, &TokenStore::balance_key(&t, &owner))
        .unwrap()
        .is_some());

    store.set_balance(&t, &owner, 0).unwrap();
    store.set_allowance(&t, &owner, &spender, 0).unwrap();
    assert!(
        db.get(cf::TOKEN_BALANCES, &TokenStore::balance_key(&t, &owner))
            .unwrap()
            .is_none(),
        "a zero token balance is an ABSENT row, not a row of zeroes"
    );
    assert!(db
        .get(
            cf::TOKEN_ALLOWANCES,
            &TokenStore::allowance_key(&t, &owner, &spender)
        )
        .unwrap()
        .is_none());
    assert!(
        db.get(cf::TOKEN_HOLDER_INDEX, owner.as_bytes())
            .unwrap()
            .map(|b| decode_holder_tokens(&b).unwrap().is_empty())
            .unwrap_or(true),
        "and the holder index drops it too"
    );

    let class = [0x64u8; 32];
    let holder = [0x65u8; 32];
    let eq = EquityBalanceStore::new(&db);
    eq.set_balance(&class, &holder, 5).unwrap();
    eq.set_balance(&class, &holder, 0).unwrap();
    assert!(
        db.get(cf::EQUITY_BALANCES, &EquityBalanceStore::make_key(&class, &holder))
            .unwrap()
            .is_none(),
        "a zero equity balance is an ABSENT row too"
    );
}

// ── The third amount encoding ────────────────────────────────────────────────

/// A frozen snapshot weight is sixteen big-endian bytes, like a token amount
/// and unlike an equity balance.
///
/// This is the third `u128` big-endian amount in the package. It was missed
/// when the codecs were first catalogued, because a "snapshot weight" does not
/// read as a balance — which is precisely how an encoding drifts: not by
/// disagreement, but by not being recognised as the same kind of thing.
#[test]
fn a_snapshot_weight_is_sixteen_big_endian_bytes() {
    assert_eq!(
        encode_snapshot_weight(1),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(decode_snapshot_weight(&encode_snapshot_weight(u128::MAX)).unwrap(), u128::MAX);
    assert!(decode_snapshot_weight(&[0u8; 8]).is_err(), "a short row is corruption");

    // Same shape as a token amount, deliberately: both are bare big-endian
    // u128. An equity balance is not, and must not be confused with either.
    assert_eq!(
        encode_snapshot_weight(12_345).as_slice(),
        encode_token_amount(12_345).as_slice()
    );
}

/// `GovStore` writes snapshot weights and dedup keys through the shared halves.
#[test]
fn gov_store_snapshot_and_commitment_rows_match_the_helpers() {
    let (db, _dir) = db();
    let store = GovStore::new(&db);
    let pid = [0x71u8; 32];
    let holder = addr(0x72);

    store.put_snapshot(&pid, &holder, 4_242).unwrap();
    assert_eq!(
        db.get(cf::GOV_SNAPSHOTS, &composite_key(&pid, &holder))
            .unwrap()
            .unwrap(),
        encode_snapshot_weight(4_242).to_vec(),
        "the snapshot row is at the shared key and holds the shared encoding"
    );
    assert_eq!(store.get_snapshot(&pid, &holder).unwrap(), Some(4_242));

    let commitment = [0x73u8; 32];
    store.mark_equity_commitment_used(&pid, &commitment).unwrap();
    assert!(
        db.get(
            cf::GOV_EQUITY_USED_COMMITMENTS,
            &equity_commitment_key(&pid, &commitment)
        )
        .unwrap()
        .is_some(),
        "the dedup row is at the shared key"
    );

    let k = equity_commitment_key(&pid, &commitment);
    assert_eq!(k.len(), 64, "proposal_id (32) || holder_commitment (32)");
    assert_eq!(&k[..32], &pid);
    assert_eq!(&k[32..], &commitment);
}

/// `GovStore::scan_token_holders` reads TOKEN balances, and must read them with
/// the token decoder — governance holding its own copy is drift across a crate
/// boundary, which is harder to see than drift within one.
#[test]
fn gov_store_scans_token_balances_with_the_token_codec() {
    let (db, _dir) = db();
    let t = [0x81u8; 32];
    let holder = addr(0x82);
    TokenStore::new(&db).set_balance(&t, &holder, 7_000).unwrap();

    let found = GovStore::new(&db).scan_token_holders(&t, 10).unwrap();
    assert_eq!(found, vec![(holder, 7_000)], "the scan decodes what TokenStore wrote");
}

//! B9-a, pinned (#351): a validator created by a real `CreateValidator`
//! staking operation is stored under its zero-padded sender address
//! (`StakingExecutor::get_pubkey_from_address`), not under a signing key, and
//! the G5 selection the dormant wiring runs (`read_candidates_in` and
//! `select_members`) names exactly those padded keys.
//!
//! No padded key is the public key of the account that registered it. A set
//! selected from transaction-created validators could not sign a block, and
//! every beacon DKG over it would fail. This is why dynamic membership needs
//! the B9-a decision (the source of a staking validator's block-signing key)
//! before it can activate. When that decision is implemented, this test is
//! meant to change with it: it records today's behaviour, not a requirement.
//!
//! Library level, one candidate view, nothing published. Every value is a test
//! fixture.

use std::sync::Arc;

use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::{Address, CreateValidatorData, StakingOperation, StakingTxData};
use sumchain_state::staking_executor::StakingExecutor;
use sumchain_state::state::StateManager;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::schema::AccountState;
use sumchain_storage::validator_set_g5::{read_candidates_in, select_members, Selection};
use sumchain_storage::Database;

#[test]
fn a_transaction_created_validator_is_selected_under_a_key_nobody_can_sign_with() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let params = ChainParams::with_v2_enabled();
    // The default staking minimum (1e18 base units); `params.staking` is unset.
    let stake: u128 = 1_000_000_000_000_000_000;

    let mut overlay = ApplicationOverlay::new(&db, 1 << 24);
    let mut view = ExecutionView::new(&mut overlay);
    let keys: Vec<KeyPair> = (1u8..=5).map(|i| KeyPair::from_bytes([i; 32])).collect();
    let proposer = Address::new([0xEE; 20]);
    for k in &keys {
        let addr = k.address();
        StateManager::v_put_account(
            &mut view,
            &addr,
            &AccountState {
                balance: stake * 10,
                nonce: 0,
            },
        )
        .unwrap();
        let data = bincode::serialize(&CreateValidatorData {
            stake,
            commission_bps: 0,
            metadata: Vec::new(),
        })
        .unwrap();
        let r = StakingExecutor::execute(
            &mut view,
            &params,
            &addr,
            &StakingTxData::new(StakingOperation::CreateValidator, data),
            &proposer,
            0,
            1,
        )
        .unwrap();
        assert!(r.success, "CreateValidator for {addr}: {:?}", r.error);
    }

    let candidates = read_candidates_in(&view).unwrap();
    assert_eq!(candidates.len(), 5);
    // N_min 5 (ratified), max_validators 5, minimum stake 1, any anchor.
    let selection = select_members(&candidates, 1, 5, 5, &[[0xAA; 32]]).unwrap();
    let members = match &selection {
        Selection::Selected(m) => m.clone(),
        other => panic!("five eligible validators must be selected, got {other:?}"),
    };
    for k in &keys {
        let mut padded = [0u8; 32];
        padded[..20].copy_from_slice(k.address().as_bytes());
        assert!(members.contains(&padded), "the padded address is selected");
        assert!(
            !members.contains(k.public_key().as_bytes()),
            "the registering account's signing key is not"
        );
    }
}

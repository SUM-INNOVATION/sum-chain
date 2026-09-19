//! `subsystem_allocation_bound_enabled_from_height`: a payload-chosen string
//! stops becoming an unbounded column-family KEY.
//!
//! ACTIVATION-AUDIT row AL-7, plus the two instances of it the audit does not
//! name.
//!
//! # Why this is the same gate and not a new one
//!
//! `subsystem_allocation_bound_enabled_from_height` already states its rule as
//! "bound the input before building the value", and already covers DocClass and
//! NFT under it. AL-7 is that rule at the one place in the inventory where the
//! attacker's control reaches the KEY rather than the value: the raw UTF-8 of a
//! `jurisdiction_code` the sender writes into its own payload becomes the key
//! of an index family, with no width check anywhere ahead of the `put`. Its own
//! audit row says so — "the attacker chooses both the width of the key and the
//! number of distinct keys in the family — the only row in this class where
//! attacker control extends to the key space".
//!
//! The doc comment on that field already argues why a partial activation is
//! wrong: an attacker refused by one bound moves to the cheapest one still
//! open. That argument is what puts AL-7 here rather than behind a height of
//! its own, and it is also what puts the Legal and Finance instances here: they
//! are the same field name, in the same shape, written by the same kind of
//! creation arm, and closing Property alone would leave two identical vectors
//! at the same price.
//!
//! # What each pair shows
//!
//! One `#[test]` per family. Each runs the SAME creation transaction — a
//! `jurisdiction_code` one byte over the bound — against a fresh database
//! twice, once with `allocation_bound: false` (the release configuration, and
//! byte-for-byte the unremediated binary) and once with it true, and asserts
//! the two nodes disagree: the ungated node ADMITS the transaction and writes
//! the over-long key, the gated one refuses it with a failed receipt and writes
//! nothing.
//!
//! A code AT the bound is accepted on both sides, so what the gate refuses is
//! the over-long key and not the operation.
//!
//! Every pair is spelled `{ allocation_bound: …, ..CLOSED }`, never field by
//! field: a gate added to one of these structs later must leave the pair
//! differing in exactly one decision.

mod common;

use common::{fund, setup_with_params};
use sumchain_crypto::KeyPair;
use sumchain_genesis::ChainParams;
use sumchain_primitives::finance::{
    FinanceIssuerClass, FinanceIssuerProfile, FinanceIssuerStatus, FinanceOperation, FinanceTxData,
};
use sumchain_primitives::legal::{
    BenefitDetermination, BenefitStatus, BenefitType, CaseAnchor, CaseStatus, CaseType,
    LegalIssuerClass, LegalOperation, LegalTxData,
};
use sumchain_primitives::property::{
    AssetAnchor, AssetStatus, AssetType, PropertyIssuerClass, PropertyOperation, PropertyTxData,
};
use sumchain_primitives::{Address, Hash};
use sumchain_state::{
    FinanceExecutor, FinanceGates, LegalExecutor, LegalGates, PropertyExecutor, PropertyGates,
    MAX_INDEX_KEY_TEXT_BYTES,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;

fn params() -> ChainParams {
    ChainParams::with_v2_enabled()
}

/// A jurisdiction code exactly at the bound, and one byte past it.
fn at_bound() -> String {
    "J".repeat(MAX_INDEX_KEY_TEXT_BYTES)
}
fn over_bound() -> String {
    "J".repeat(MAX_INDEX_KEY_TEXT_BYTES + 1)
}

macro_rules! pair {
    ($g:ident) => {
        [
            $g::CLOSED,
            $g {
                allocation_bound: true,
                ..$g::CLOSED
            },
        ]
    };
}

/// The one claim every case makes.
fn assert_the_pair_disagrees(subsystem: &str, gate_open: bool, at: bool, over: bool) {
    assert!(
        at,
        "{subsystem}: a code exactly at the {MAX_INDEX_KEY_TEXT_BYTES}-byte bound must be \
         accepted on both sides — the gate refuses an over-long KEY, not the operation \
         (allocation_bound={gate_open})"
    );
    assert_eq!(
        over, !gate_open,
        "{subsystem}: a code one byte past the bound is ADMITTED below the gate, and the \
         over-long key is written; at the gate it is a failed receipt \
         (allocation_bound={gate_open})"
    );
}

// ── Property — AL-7 ─────────────────────────────────────────────────────────

#[test]
fn property_stops_keying_its_jurisdiction_index_by_an_unbounded_payload_string() {
    for gates in pair!(PropertyGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let anchor = |view: &mut ExecutionView<'_, '_>, id: u8, code: &str| {
            let asset = AssetAnchor {
                asset_id: [id; 32],
                asset_commitment: [id.wrapping_add(1); 32],
                asset_type: AssetType::SingleFamilyResidence,
                jurisdiction_code: code.to_string(),
                public_reference: None,
                policy_id: [12u8; 32],
                issuer_class: PropertyIssuerClass::LandRegistry,
                issuer_address: sender,
                status: AssetStatus::Active,
                created_at: 1000,
                updated_at: 1000,
                anchored_at_height: 1,
                related_assets: vec![],
                attachments: vec![],
            };
            PropertyExecutor::execute_with_gates(
                view,
                &sender,
                &PropertyTxData {
                    operation: PropertyOperation::AnchorAsset,
                    data: bincode::serialize(&asset).unwrap(),
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap()
            .success
        };

        let at = anchor(&mut view, 0x11, &at_bound());
        let over = anchor(&mut view, 0x22, &over_bound());
        assert_the_pair_disagrees("property", gates.allocation_bound, at, over);

        // The key itself, not only the receipt: below the gate the over-long
        // key is IN the family; at the gate it is not.
        let present = PropertyExecutor::v_get_jurisdiction_asset_ids(&view, &over_bound()).unwrap();
        assert_eq!(
            !present.is_empty(),
            !gates.allocation_bound,
            "property: the {}-byte key is written below the gate and absent at it",
            over_bound().len()
        );
    }
}

// ── Legal — the same defect, at two arms ────────────────────────────────────

#[test]
fn legal_stops_keying_its_jurisdiction_index_by_an_unbounded_payload_string() {
    for gates in pair!(LegalGates) {
        let (_state, db, _dir, _executor) = setup_with_params(params());
        let actor = KeyPair::generate();
        fund(&db, &actor, 100_000_000);
        let sender = actor.address();
        let proposer = Address::new([9; 20]);
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let run = |view: &mut ExecutionView<'_, '_>, op: LegalOperation, data: Vec<u8>| {
            LegalExecutor::execute_with_gates(
                view,
                &sender,
                &LegalTxData {
                    operation: op,
                    data,
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap()
            .success
        };

        let case = |id: u8, code: &str| CaseAnchor {
            case_id: [id; 32],
            case_commitment: [0xC1; 32],
            jurisdiction_code: code.to_string(),
            case_type: Some(CaseType::Civil),
            public_reference: None,
            policy_id: [0xC2; 32],
            issuer_class: LegalIssuerClass::LawFirm,
            issuer_address: sender,
            status: CaseStatus::Filed,
            created_at: 1_000,
            updated_at: 1_000,
            anchored_at_height: 1,
            related_cases: vec![],
        };
        let benefit = |id: u8, code: &str| BenefitDetermination {
            benefit_id: [id; 32],
            benefit_type: BenefitType::Medicare,
            jurisdiction_code: code.to_string(),
            status: BenefitStatus::Approved,
            determination_commitment: [0xB1; 32],
            subject_nullifier: [0xB2; 32],
            issuer_address: sender,
            issuer_class: LegalIssuerClass::GovernmentAgency,
            valid_from: 1_000,
            expiry: None,
            policy_id: [0xB3; 32],
            revocation_ref: None,
            created_at: 1_000,
            updated_at: 1_000,
            recorded_at_height: 1,
            supersedes: None,
        };

        let at = run(
            &mut view,
            LegalOperation::AnchorCase,
            bincode::serialize(&case(0x11, &at_bound())).unwrap(),
        );
        let over = run(
            &mut view,
            LegalOperation::AnchorCase,
            bincode::serialize(&case(0x22, &over_bound())).unwrap(),
        );
        assert_the_pair_disagrees("legal/AnchorCase", gates.allocation_bound, at, over);

        let at_b = run(
            &mut view,
            LegalOperation::DetermineBenefit,
            bincode::serialize(&benefit(0x33, &at_bound())).unwrap(),
        );
        let over_b = run(
            &mut view,
            LegalOperation::DetermineBenefit,
            bincode::serialize(&benefit(0x44, &over_bound())).unwrap(),
        );
        assert_the_pair_disagrees(
            "legal/DetermineBenefit",
            gates.allocation_bound,
            at_b,
            over_b,
        );
    }
}

// ── Finance — the same defect ───────────────────────────────────────────────

#[test]
fn finance_stops_keying_its_jurisdiction_index_by_an_unbounded_payload_string() {
    for gates in pair!(FinanceGates) {
        for (code, expect_at_bound) in [(at_bound(), true), (over_bound(), false)] {
            let (_state, db, _dir, _executor) = setup_with_params(params());
            let actor = KeyPair::generate();
            fund(&db, &actor, 100_000_000);
            let sender = actor.address();
            let proposer = Address::new([9; 20]);
            let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
            let mut view = ExecutionView::new(&mut overlay);

            // One issuer per address, so each half needs its own database.
            let issuer = FinanceIssuerProfile {
                issuer_address: sender,
                issuer_class: FinanceIssuerClass::RegulatedBank,
                issuer_commitment: [2u8; 32],
                jurisdiction_code: code.clone(),
                policy_id: [3u8; 32],
                status: FinanceIssuerStatus::Active,
                registered_at_height: 1,
                created_at: 1_000,
                updated_at: 1_000,
            };
            let ok = FinanceExecutor::execute_with_gates(
                &mut view,
                &sender,
                &FinanceTxData {
                    operation: FinanceOperation::RegisterIssuer,
                    data: bincode::serialize(&issuer).unwrap(),
                    recipient: Address::ZERO,
                },
                &proposer,
                100,
                1,
                1_000,
                0,
                Hash::ZERO,
                gates,
            )
            .unwrap()
            .success;

            if expect_at_bound {
                assert!(
                    ok,
                    "finance: a code exactly at the {MAX_INDEX_KEY_TEXT_BYTES}-byte bound is \
                     accepted on both sides (allocation_bound={})",
                    gates.allocation_bound
                );
            } else {
                assert_eq!(
                    ok, !gates.allocation_bound,
                    "finance: a code one byte past the bound registers below the gate and is \
                     refused at it (allocation_bound={})",
                    gates.allocation_bound
                );
            }
        }
    }
}

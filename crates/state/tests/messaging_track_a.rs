//! Exactly-once messaging accounting and authenticated sponsored payments,
//! under `messaging_sponsored_envelope_verification_enabled_from_height`
//! (`0x1048`) and `messaging_fee_nonce_accounting_enabled_from_height`
//! (`0x1049`).
//!
//! Every block here is executed and published through the real block path,
//! on a chain whose id is not 1 unless a case says otherwise. Every state
//! assertion compares rows in the account family and in every messaging
//! family, not roots: the root folds no messaging row, and account rows only
//! from the account-root gate.

mod track_a_support;

use sumchain_crypto::recipient_hash;
use sumchain_primitives::messaging::{
    BlockSenderData, ClaimPaymentData, ContactData, FundRegistryData, MessagingTxData,
    RegisterPublicKeyData, ReportSpamData, SendMessageData, SendMessageWithPaymentData,
    SetDailyQuotaData, SetInboxFilterData, SetMaxMessageSizeData, SetMinTrustStakeData,
    SetSponsorshipEnabledData, StakeForTrustData, UpdatePublicKeyData,
};
use sumchain_primitives::{Hash, InboxFilter, MessagingOperation, MessagingUnstakeData, TxStatus};
use sumchain_state::{StateError, TxFailureClass};
use sumchain_storage::cf;
use sumchain_storage::messaging_store::config_keys;
use track_a_support::*;

/// What the same transaction does with both gates absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Below {
    /// The block that carries it is not applicable (the business errors and
    /// undecodable payloads that the accounting gate turns into refusals).
    Aborts,
    /// A refusal that charges nothing and changes nothing (the refusals that
    /// already were refusals).
    Free,
    /// It executes under the earlier rule (a sponsored envelope whose
    /// version-2 signature or nonce is not read below the envelope gate).
    Executes,
}

/// One refusal: what is prepared after `setup()`, who signs what, and what the
/// same bytes do below both gates.
struct Case {
    label: &'static str,
    prepare: fn(&mut Chain),
    signer: fn() -> sumchain_crypto::KeyPair,
    data: fn(&Chain) -> MessagingTxData,
    below: Below,
}

fn nothing(_: &mut Chain) {}

fn malformed(operation: MessagingOperation) -> MessagingTxData {
    raw(operation, vec![0xFF; 3])
}

fn set_quota(c: &mut Chain, quota: u32) {
    let tx = c.tx(
        &admin(),
        op(
            MessagingOperation::SetDailyQuota,
            &SetDailyQuotaData { quota },
        ),
    );
    c.all_succeed(vec![tx]);
}

/// Dave has used his whole quota of one.
fn dave_over_quota(c: &mut Chain) {
    set_quota(c, 1);
    let tx = c.tx(&dave(), direct_to(&bob().address()));
    c.all_succeed(vec![tx]);
}

/// Alice stakes and reports dave once, which takes him to the high spam
/// threshold without stake.
fn dave_reported(c: &mut Chain) {
    let stake = c.tx(
        &alice(),
        op(
            MessagingOperation::StakeForTrust,
            &StakeForTrustData {
                amount: 200_000_000_000,
            },
        ),
    );
    c.all_succeed(vec![stake]);
    let report = c.tx(
        &alice(),
        op(
            MessagingOperation::ReportSpam,
            &ReportSpamData {
                message_id: Hash::hash(b"a message"),
                spammer: dave().address(),
            },
        ),
    );
    c.all_succeed(vec![report]);
}

fn bob_filter(c: &mut Chain, mode: InboxFilter) {
    let tx = c.tx(
        &bob(),
        op(
            MessagingOperation::SetInboxFilter,
            &SetInboxFilterData { mode },
        ),
    );
    c.all_succeed(vec![tx]);
}

fn bob_contacts_only(c: &mut Chain) {
    bob_filter(c, InboxFilter::ContactsOnly);
}

fn bob_staked_only(c: &mut Chain) {
    bob_filter(c, InboxFilter::StakedOnly);
}

fn bob_blocks_dave(c: &mut Chain) {
    let tx = c.tx(
        &bob(),
        op(
            MessagingOperation::BlockSender,
            &BlockSenderData {
                sender: dave().address(),
            },
        ),
    );
    c.all_succeed(vec![tx]);
}

fn small_messages(c: &mut Chain) {
    let tx = c.tx(
        &admin(),
        op(
            MessagingOperation::SetMaxMessageSize,
            &SetMaxMessageSizeData { size: 10 },
        ),
    );
    c.all_succeed(vec![tx]);
}

fn sponsorship_off(c: &mut Chain) {
    let tx = c.tx(
        &admin(),
        op(
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: false },
        ),
    );
    c.all_succeed(vec![tx]);
}

/// Alice pays bob 500, escrowed under the paying transaction's hash, which
/// is recorded in `c.mark`.
fn alice_pays_bob(c: &mut Chain) {
    let tx = c.tx(&alice(), payment_to(&bob().address(), 500));
    c.mark = tx.hash();
    c.all_succeed(vec![tx]);
}

fn claim(c: &Chain, claimer: &sumchain_crypto::KeyPair) -> MessagingTxData {
    op(
        MessagingOperation::ClaimPayment,
        &ClaimPaymentData {
            message_id: c.mark,
            recipient_address: claimer.address(),
        },
    )
}

fn direct_malformed_message(to: &sumchain_primitives::Address) -> MessagingTxData {
    op(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: vec![0u8; 16],
            recipient_hash: recipient_hash(to),
        },
    )
}

fn paid_malformed_message(to: &sumchain_primitives::Address) -> MessagingTxData {
    op(
        MessagingOperation::SendMessageWithPayment,
        &SendMessageWithPaymentData {
            message_data: vec![0u8; 16],
            recipient_hash: recipient_hash(to),
            koppa_amount: 1,
        },
    )
}

/// The refusals of every one of the eighteen generic messaging operations that
/// do not depend on an authenticated sponsored envelope: every undecodable
/// payload, every business check that used to make the block inapplicable,
/// and every refusal that already was one. One row per case, unformatted, so
/// the table reads as a table.
#[rustfmt::skip]
fn cases() -> Vec<Case> {
    use MessagingOperation as M;
    vec![
        // ── undecodable payloads, all eighteen operations ────────────────
        Case { label: "SendMessage, undecodable", prepare: nothing, signer: sponsor, data: |_| malformed(M::SendMessage), below: Below::Aborts },
        Case { label: "SendMessageDirect, undecodable", prepare: nothing, signer: dave, data: |_| malformed(M::SendMessageDirect), below: Below::Aborts },
        Case { label: "SendMessageWithPayment, undecodable", prepare: nothing, signer: dave, data: |_| malformed(M::SendMessageWithPayment), below: Below::Aborts },
        Case { label: "ClaimPayment, undecodable", prepare: nothing, signer: bob, data: |_| malformed(M::ClaimPayment), below: Below::Aborts },
        Case { label: "StakeForTrust, undecodable", prepare: nothing, signer: dave, data: |_| malformed(M::StakeForTrust), below: Below::Aborts },
        Case { label: "Unstake, undecodable", prepare: nothing, signer: dave, data: |_| malformed(M::Unstake), below: Below::Aborts },
        Case { label: "SetInboxFilter, undecodable", prepare: nothing, signer: bob, data: |_| malformed(M::SetInboxFilter), below: Below::Aborts },
        Case { label: "SetInboxFilter, an unknown mode", prepare: nothing, signer: bob, data: |_| raw(M::SetInboxFilter, 99u32.to_le_bytes().to_vec()), below: Below::Aborts },
        Case { label: "AddContact, undecodable", prepare: nothing, signer: bob, data: |_| malformed(M::AddContact), below: Below::Aborts },
        Case { label: "RemoveContact, undecodable", prepare: nothing, signer: bob, data: |_| malformed(M::RemoveContact), below: Below::Aborts },
        Case { label: "BlockSender, undecodable", prepare: nothing, signer: bob, data: |_| malformed(M::BlockSender), below: Below::Aborts },
        Case { label: "ReportSpam, undecodable", prepare: nothing, signer: alice, data: |_| malformed(M::ReportSpam), below: Below::Aborts },
        Case { label: "RegisterPublicKey, undecodable", prepare: nothing, signer: frank, data: |_| malformed(M::RegisterPublicKey), below: Below::Aborts },
        Case { label: "UpdatePublicKey, undecodable", prepare: nothing, signer: alice, data: |_| malformed(M::UpdatePublicKey), below: Below::Aborts },
        Case { label: "SetDailyQuota by the admin, undecodable", prepare: nothing, signer: admin, data: |_| malformed(M::SetDailyQuota), below: Below::Aborts },
        Case { label: "SetMaxMessageSize by the admin, undecodable", prepare: nothing, signer: admin, data: |_| malformed(M::SetMaxMessageSize), below: Below::Aborts },
        Case { label: "SetMinTrustStake by the admin, undecodable", prepare: nothing, signer: admin, data: |_| malformed(M::SetMinTrustStake), below: Below::Aborts },
        Case { label: "SetSponsorshipEnabled by the admin, undecodable", prepare: nothing, signer: admin, data: |_| malformed(M::SetSponsorshipEnabled), below: Below::Aborts },
        Case { label: "FundRegistry, undecodable", prepare: nothing, signer: alice, data: |_| malformed(M::FundRegistry), below: Below::Aborts },
        // ── business checks that used to make the block inapplicable ─────
        Case { label: "SendMessageDirect, over quota", prepare: dave_over_quota, signer: dave, data: |_| direct_to(&bob().address()), below: Below::Aborts },
        Case { label: "SendMessageWithPayment, over quota", prepare: dave_over_quota, signer: dave, data: |_| payment_to(&bob().address(), 5), below: Below::Aborts },
        Case { label: "SendMessageDirect, high spam score without stake", prepare: dave_reported, signer: dave, data: |_| direct_to(&bob().address()), below: Below::Aborts },
        Case { label: "SendMessageWithPayment, high spam score without stake", prepare: dave_reported, signer: dave, data: |_| payment_to(&bob().address(), 5), below: Below::Aborts },
        Case { label: "SendMessageDirect, sender blocked", prepare: bob_blocks_dave, signer: dave, data: |_| direct_to(&bob().address()), below: Below::Aborts },
        Case { label: "SendMessageWithPayment, sender blocked", prepare: bob_blocks_dave, signer: dave, data: |_| payment_to(&bob().address(), 5), below: Below::Aborts },
        Case { label: "SendMessageDirect, not in contacts", prepare: bob_contacts_only, signer: dave, data: |_| direct_to(&bob().address()), below: Below::Aborts },
        Case { label: "SendMessageWithPayment, not in contacts", prepare: bob_contacts_only, signer: dave, data: |_| payment_to(&bob().address(), 5), below: Below::Aborts },
        Case { label: "SendMessageDirect, recipient requires stake", prepare: bob_staked_only, signer: dave, data: |_| direct_to(&bob().address()), below: Below::Aborts },
        Case { label: "SendMessageWithPayment, recipient requires stake", prepare: bob_staked_only, signer: dave, data: |_| payment_to(&bob().address(), 5), below: Below::Aborts },
        Case { label: "StakeForTrust, unaffordable", prepare: nothing, signer: dave, data: |_| op(M::StakeForTrust, &StakeForTrustData { amount: FUNDS * 2 }), below: Below::Aborts },
        Case { label: "FundRegistry, unaffordable", prepare: nothing, signer: dave, data: |_| op(M::FundRegistry, &FundRegistryData { amount: FUNDS * 2 }), below: Below::Aborts },
        // ── refusals that already were refusals ──────────────────────────
        Case { label: "SendMessageDirect, not an SRC-201 message", prepare: nothing, signer: dave, data: |_| direct_malformed_message(&bob().address()), below: Below::Free },
        Case { label: "SendMessageDirect, too large", prepare: small_messages, signer: dave, data: |_| direct_to(&bob().address()), below: Below::Free },
        Case { label: "SendMessageWithPayment, not an SRC-201 message", prepare: nothing, signer: dave, data: |_| paid_malformed_message(&bob().address()), below: Below::Free },
        Case { label: "SendMessageWithPayment, too large", prepare: small_messages, signer: dave, data: |_| payment_to(&bob().address(), 5), below: Below::Free },
        Case { label: "SendMessageWithPayment, unaffordable", prepare: nothing, signer: dave, data: |_| payment_to(&bob().address(), FUNDS * 2), below: Below::Free },
        Case { label: "ClaimPayment, no pending payment", prepare: nothing, signer: bob, data: |c| claim(c, &bob()), below: Below::Free },
        Case { label: "ClaimPayment, not the recipient", prepare: alice_pays_bob, signer: dave, data: |c| claim(c, &dave()), below: Below::Free },
        Case { label: "ClaimPayment, claimer mismatch", prepare: alice_pays_bob, signer: dave, data: |c| claim(c, &bob()), below: Below::Free },
        Case { label: "StakeForTrust, zero", prepare: nothing, signer: dave, data: |_| op(M::StakeForTrust, &StakeForTrustData { amount: 0 }), below: Below::Free },
        Case { label: "Unstake, more than staked", prepare: nothing, signer: dave, data: |_| op(M::Unstake, &MessagingUnstakeData { amount: 1 }), below: Below::Free },
        Case { label: "ReportSpam, reporter without stake", prepare: nothing, signer: dave, data: |_| op(M::ReportSpam, &ReportSpamData { message_id: Hash::hash(b"m"), spammer: alice().address() }), below: Below::Free },
        Case { label: "RegisterPublicKey, a key that is not the sender's", prepare: nothing, signer: frank, data: |_| op(M::RegisterPublicKey, &RegisterPublicKeyData { public_key: *erin().public_key().as_bytes() }), below: Below::Free },
        Case { label: "RegisterPublicKey, already registered", prepare: nothing, signer: bob, data: |_| op(M::RegisterPublicKey, &RegisterPublicKeyData { public_key: *bob().public_key().as_bytes() }), below: Below::Free },
        Case { label: "UpdatePublicKey, none registered", prepare: nothing, signer: frank, data: |_| op(M::UpdatePublicKey, &UpdatePublicKeyData { new_public_key: *frank().public_key().as_bytes() }), below: Below::Free },
        Case { label: "UpdatePublicKey, a key that is not the sender's", prepare: nothing, signer: alice, data: |_| op(M::UpdatePublicKey, &UpdatePublicKeyData { new_public_key: *frank().public_key().as_bytes() }), below: Below::Free },
        Case { label: "SetDailyQuota by a non-admin", prepare: nothing, signer: dave, data: |_| op(M::SetDailyQuota, &SetDailyQuotaData { quota: 1 }), below: Below::Free },
        Case { label: "SetMaxMessageSize by a non-admin", prepare: nothing, signer: dave, data: |_| op(M::SetMaxMessageSize, &SetMaxMessageSizeData { size: 1 }), below: Below::Free },
        Case { label: "SetMinTrustStake by a non-admin", prepare: nothing, signer: dave, data: |_| op(M::SetMinTrustStake, &SetMinTrustStakeData { amount: 1 }), below: Below::Free },
        Case { label: "SetSponsorshipEnabled by a non-admin", prepare: nothing, signer: dave, data: |_| op(M::SetSponsorshipEnabled, &SetSponsorshipEnabledData { enabled: false }), below: Below::Free },
        Case { label: "FundRegistry, zero", prepare: nothing, signer: dave, data: |_| op(M::FundRegistry, &FundRegistryData { amount: 0 }), below: Below::Free },
        Case { label: "SendMessage, sponsorship disabled", prepare: sponsorship_off, signer: sponsor, data: |c| sponsored(&envelope(&carol(), &bob().address(), c.msg_nonce(&carol().address()), None)), below: Below::Free },
        Case { label: "SendMessage, naming an unregistered sender", prepare: nothing, signer: sponsor, data: |_| sponsored(&envelope(&frank(), &bob().address(), 0, None)), below: Below::Free },
        Case { label: "SendMessage, no version-2 signature", prepare: nothing, signer: sponsor, data: |_| sponsored(&envelope(&carol(), &bob().address(), 0, None)), below: Below::Executes },
        Case { label: "SendMessage, a nonce that is not the sender's", prepare: nothing, signer: sponsor, data: |c| sponsored(&c.v2(&carol(), &bob().address(), 5, None)), below: Below::Executes },
    ]
}

/// At both gates, every refusal in `cases()` takes `Failed(7)` with
/// the fee, debits the signer the fee once, credits the proposer once and
/// advances the signer's account nonce once; and every other row, in the
/// account family and in every messaging family, is byte-identical to before
/// the transaction. None of these refusals carries an authenticated
/// envelope, so no messaging nonce moves.
#[test]
fn at_both_gates_every_refusal_is_charged_once_and_changes_nothing_else() {
    let mut labels = std::collections::BTreeSet::new();
    for case in cases() {
        assert!(labels.insert(case.label), "duplicate case {}", case.label);
        let mut c = Chain::new(both(Some(1)));
        c.setup();
        (case.prepare)(&mut c);
        let signer = (case.signer)();
        let who = signer.address();
        let before = c.rows();
        let (balance, nonce, pool) = (c.balance(&who), c.nonce(&signer), c.balance(&proposer()));

        let tx = c.tx(&signer, (case.data)(&c));
        let r = c.one(tx);

        assert_eq!(
            (r.status, r.fee_paid),
            (TxStatus::Failed(7), FEE),
            "{}",
            case.label
        );
        assert_eq!(c.balance(&who), balance - FEE, "{}: one debit", case.label);
        assert_eq!(c.nonce(&signer), nonce + 1, "{}: one nonce", case.label);
        assert_eq!(
            c.balance(&proposer()),
            pool + FEE,
            "{}: one credit",
            case.label
        );
        let mut want = vec![account_key(&who), account_key(&proposer())];
        want.sort();
        assert_eq!(
            changed(&before, &c.rows()),
            want,
            "{}: nothing but the two account rows",
            case.label
        );
    }
    assert_eq!(labels.len(), 55);
}

/// With both gates absent, the same transactions give what they
/// always gave: the converted checks make the block inapplicable (at that
/// transaction, transiently), the refusals that were refusals charge nothing
/// and change nothing, and the envelopes the earlier rule accepts execute.
#[test]
fn below_both_gates_the_same_transactions_end_as_before() {
    for case in cases() {
        let mut c = Chain::new(both(None));
        c.setup();
        (case.prepare)(&mut c);
        let signer = (case.signer)();
        let before = c.rows();
        let height = c.height;
        let tx = c.tx(&signer, (case.data)(&c));
        match (case.below, c.block(vec![tx])) {
            (
                Below::Aborts,
                Err(StateError::BlockTransactionAborted {
                    tx_index, class, ..
                }),
            ) => {
                assert_eq!(
                    (tx_index, class),
                    (0, TxFailureClass::Transient),
                    "{}",
                    case.label
                );
                assert_eq!(c.height, height, "{}: not published", case.label);
                assert_eq!(c.rows(), before, "{}", case.label);
            }
            (Below::Free, Ok(r)) => {
                assert_eq!(
                    (r[0].status, r[0].fee_paid),
                    (TxStatus::Failed(7), 0),
                    "{}",
                    case.label
                );
                assert_eq!(c.rows(), before, "{}: nothing moves", case.label);
            }
            (Below::Executes, Ok(r)) => {
                assert_eq!(r[0].status, TxStatus::Success, "{}", case.label);
            }
            (want, got) => panic!("{}: expected {want:?}, got {got:?}", case.label),
        }
    }
}

/// The accounting gate at H: H-1 aborts an over-quota send, H and H+1 charge
/// it as a refusal and the block is published.
#[test]
fn the_conversion_starts_exactly_at_the_gate() {
    const H: u64 = 5;
    let mut c = Chain::new(both(Some(H)));
    c.setup();
    dave_over_quota(&mut c);
    while c.height + 1 < H - 1 {
        c.block(Vec::new()).unwrap();
    }
    assert_eq!(c.height + 1, H - 1);
    let tx = c.tx(&dave(), direct_to(&bob().address()));
    assert!(matches!(
        c.block(vec![tx]),
        Err(StateError::BlockTransactionAborted { .. })
    ));
    c.block(Vec::new()).unwrap();
    // The empty block took H-1; the next two are H and H+1.
    for h in [H, H + 1] {
        let tx = c.tx(&dave(), direct_to(&bob().address()));
        let r = c.block(vec![tx]).expect("published");
        assert_eq!(c.height, h);
        assert_eq!((r[0].status, r[0].fee_paid), (TxStatus::Failed(7), FEE));
    }
}

/// A storage failure inside a messaging operation stays a failure of
/// this node: a stored row that does not decode makes the block inapplicable
/// at that transaction, transiently, at and below the gates, and screening
/// records it as transient. Nothing is charged and nothing published.
#[test]
fn a_storage_failure_still_makes_the_block_inapplicable() {
    for gate in [Some(1), None] {
        // A daily-quota row of the wrong width.
        let mut c = Chain::new(both(gate));
        c.setup();
        c.db.put(cf::MESSAGING_CONFIG, config_keys::DAILY_QUOTA, &[1, 2, 3])
            .unwrap();
        let tx = c.tx(&dave(), direct_to(&bob().address()));
        let s = c.screen(vec![tx.clone()], 1 << 20);
        assert_eq!(s.refused(), &[(0, TxFailureClass::Transient)], "{gate:?}");
        let before = c.rows();
        match c.block(vec![tx]) {
            Err(StateError::BlockTransactionAborted {
                tx_index, class, ..
            }) => assert_eq!((tx_index, class), (0, TxFailureClass::Transient)),
            other => panic!("{gate:?}: {other:?}"),
        }
        assert_eq!(c.rows(), before);

        // A registry-admin row of the wrong width: it must halt, never fall
        // back to the configured admin.
        let mut c = Chain::new(both(gate));
        c.setup();
        c.db.put(cf::MESSAGING_CONFIG, config_keys::REGISTRY_ADMIN, &[7u8; 3])
            .unwrap();
        let tx = c.tx(
            &admin(),
            op(
                MessagingOperation::SetDailyQuota,
                &SetDailyQuotaData { quota: 9 },
            ),
        );
        assert!(
            matches!(
                c.block(vec![tx]),
                Err(StateError::BlockTransactionAborted { .. })
            ),
            "{gate:?}"
        );
    }
}

/// A block of 1,000 refusals: screening executes it once and records
/// no offender and no refusal bytes, so it fits any refusal budget; the
/// producing execution publishes it once, with 1,000 charged receipts.
#[test]
fn a_block_of_a_thousand_refusals_executes_once() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let first = c.nonce(&dave());
    let txs: Vec<_> = (first..first + 1_000)
        .map(|n| {
            c.tx_at(
                &dave(),
                n,
                op(
                    MessagingOperation::SetDailyQuota,
                    &SetDailyQuotaData { quota: 1 },
                ),
            )
        })
        .collect();
    let s = c.screen(txs.clone(), 0);
    assert!(s.refused().is_empty());
    assert_eq!((s.ceiling_cut(), s.charge_cut()), (None, None));
    assert_eq!(s.refusal_bytes(), 0);
    assert_eq!(s.screened(), 1_000);
    let balance = c.balance(&dave().address());
    let r = c.block(txs).expect("published");
    assert_eq!(r.len(), 1_000);
    assert!(r
        .iter()
        .all(|r| (r.status, r.fee_paid) == (TxStatus::Failed(7), FEE)));
    assert_eq!(c.balance(&dave().address()), balance - 1_000 * FEE);
    assert_eq!(c.nonce(&dave()), first + 1_000);
}

/// The contact and block operations keep their single refusal path (an
/// undecodable payload) and otherwise succeed, charged once, at both gates.
#[test]
fn the_operations_without_a_business_refusal_succeed_charged_once() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    for data in [
        op(
            MessagingOperation::AddContact,
            &ContactData {
                contact_hash: recipient_hash(&alice().address()),
            },
        ),
        op(
            MessagingOperation::RemoveContact,
            &ContactData {
                contact_hash: recipient_hash(&alice().address()),
            },
        ),
        op(
            MessagingOperation::BlockSender,
            &BlockSenderData {
                sender: dave().address(),
            },
        ),
        op(
            MessagingOperation::SetInboxFilter,
            &SetInboxFilterData {
                mode: InboxFilter::AcceptAll,
            },
        ),
    ] {
        let balance = c.balance(&bob().address());
        let r = c.one(c.tx(&bob(), data));
        assert_eq!((r.status, r.fee_paid), (TxStatus::Success, FEE));
        assert_eq!(c.balance(&bob().address()), balance - FEE);
    }
}

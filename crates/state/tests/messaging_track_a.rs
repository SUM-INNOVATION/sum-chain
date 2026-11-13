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

// ── the envelope nonce: spent on every included authenticated attempt ───────

/// The `cf::MESSAGING_SENDER_NONCES` key of `a`'s messaging nonce.
fn msg_nonce_key(a: &sumchain_primitives::Address) -> (String, Vec<u8>) {
    (
        cf::MESSAGING_SENDER_NONCES.to_string(),
        sumchain_storage::messaging_store::sender_nonce_key(a).to_vec(),
    )
}

/// `base()` with both gates at `h` and both clock gates open, so the rules
/// read whole seconds and an expiry can pass.
fn both_with_clock(h: Option<u64>) -> sumchain_genesis::ChainParams {
    let mut p = both(h);
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
    p.messaging_timestamp_units_enabled_from_height = Some(0);
    p
}

/// A refusal of an authenticated envelope: what is prepared, the envelope's
/// named sender, and the envelope (signed by that sender at its current
/// messaging nonce).
struct Authenticated {
    label: &'static str,
    params: fn() -> sumchain_genesis::ChainParams,
    prepare: fn(&mut Chain),
    sender: fn() -> sumchain_crypto::KeyPair,
    envelope: fn(&Chain) -> sumchain_primitives::SponsoredMessage,
}

/// `sender`'s envelope to bob at its current messaging nonce, signed.
fn current(c: &Chain, sender: &sumchain_crypto::KeyPair) -> sumchain_primitives::SponsoredMessage {
    c.v2(
        sender,
        &bob().address(),
        c.msg_nonce(&sender.address()),
        None,
    )
}

/// `current`, with `edit` applied before the signature.
fn current_edited(
    c: &Chain,
    sender: &sumchain_crypto::KeyPair,
    edit: impl Fn(&mut sumchain_primitives::SponsoredMessage),
) -> sumchain_primitives::SponsoredMessage {
    let mut m = envelope(
        sender,
        &bob().address(),
        c.msg_nonce(&sender.address()),
        None,
    );
    edit(&mut m);
    signed_v2(m, sender, c.chain_id)
}

fn both_at_1() -> sumchain_genesis::ChainParams {
    both(Some(1))
}

fn both_at_1_with_clock() -> sumchain_genesis::ChainParams {
    both_with_clock(Some(1))
}

#[rustfmt::skip]
fn authenticated_refusals() -> Vec<Authenticated> {
    vec![
        Authenticated { label: "sponsorship disabled", params: both_at_1, prepare: sponsorship_off, sender: carol, envelope: |c| current(c, &carol()) },
        Authenticated { label: "the sender is not registered", params: both_at_1, prepare: nothing, sender: frank, envelope: |c| current(c, &frank()) },
        Authenticated { label: "not an SRC-201 message", params: both_at_1, prepare: nothing, sender: carol, envelope: |c| current_edited(c, &carol(), |m| m.message_data = vec![0u8; 16]) },
        Authenticated { label: "too large", params: both_at_1, prepare: small_messages, sender: carol, envelope: |c| current(c, &carol()) },
        Authenticated { label: "expired", params: both_at_1_with_clock, prepare: nothing, sender: carol, envelope: |c| { let at = c.next_second(); current_edited(c, &carol(), |m| m.expiry = at - 1) } },
        Authenticated { label: "over quota", params: both_at_1, prepare: dave_over_quota, sender: dave, envelope: |c| current(c, &dave()) },
        Authenticated { label: "high spam score without stake", params: both_at_1, prepare: dave_reported, sender: dave, envelope: |c| current(c, &dave()) },
        Authenticated { label: "the sender is blocked", params: both_at_1, prepare: bob_blocks_dave, sender: dave, envelope: |c| current(c, &dave()) },
        Authenticated { label: "not in the recipient's contacts", params: both_at_1, prepare: bob_contacts_only, sender: dave, envelope: |c| current(c, &dave()) },
        Authenticated { label: "the recipient requires stake", params: both_at_1, prepare: bob_staked_only, sender: dave, envelope: |c| current(c, &dave()) },
    ]
}

/// At both gates, an authenticated envelope refused for any business
/// reason is charged to its relayer once and spends the named sender's
/// messaging nonce, once. Nothing else moves: not the sender's balance or
/// account nonce, not its daily count, no event.
#[test]
fn an_authenticated_refusal_spends_the_envelope_nonce_and_nothing_else() {
    for case in authenticated_refusals() {
        let mut c = Chain::new((case.params)());
        c.setup();
        (case.prepare)(&mut c);
        let sender = (case.sender)();
        let who = sender.address();
        let m = (case.envelope)(&c);
        let n = c.msg_nonce(&who);
        assert_eq!(m.nonce, n, "{}", case.label);
        let before = c.rows();
        let (sponsor_balance, sponsor_nonce) =
            (c.balance(&sponsor().address()), c.nonce(&sponsor()));
        let sender_account = (c.balance(&who), c.nonce(&sender));

        let r = c.one(c.tx(&sponsor(), sponsored(&m)));

        assert_eq!(
            (r.status, r.fee_paid),
            (TxStatus::Failed(7), FEE),
            "{}",
            case.label
        );
        assert_eq!(
            c.balance(&sponsor().address()),
            sponsor_balance - FEE,
            "{}",
            case.label
        );
        assert_eq!(c.nonce(&sponsor()), sponsor_nonce + 1, "{}", case.label);
        assert_eq!(
            c.msg_nonce(&who),
            n + 1,
            "{}: the nonce is spent",
            case.label
        );
        assert_eq!(
            (c.balance(&who), c.nonce(&sender)),
            sender_account,
            "{}",
            case.label
        );
        let mut want = vec![
            account_key(&sponsor().address()),
            account_key(&proposer()),
            msg_nonce_key(&who),
            (
                cf::MESSAGING_SENDER_NONCES.to_string(),
                sumchain_storage::messaging_store::envelope_outcome_key(&who, n),
            ),
        ];
        want.sort();
        assert_eq!(changed(&before, &c.rows()), want, "{}", case.label);

        // The same envelope again, through another relayer: its nonce is
        // spent, so it is refused before authentication and spends nothing.
        let before = c.rows();
        let r = c.one(c.tx(&erin(), sponsored(&m)));
        assert_eq!(
            (r.status, r.fee_paid),
            (TxStatus::Failed(7), FEE),
            "{}",
            case.label
        );
        assert_eq!(c.msg_nonce(&who), n + 1, "{}: no second effect", case.label);
        let mut want = vec![account_key(&erin().address()), account_key(&proposer())];
        want.sort();
        assert_eq!(changed(&before, &c.rows()), want, "{}", case.label);
    }
}

/// A refusal before authentication spends nothing of the named sender's:
/// an undecodable payload, a signature that does not verify (another key,
/// another chain, the string form, another domain's preimage, the outer
/// transaction's own signature), a key that is not a point, a nonce ahead of the sender's (a gap) or behind it (a replay).
#[test]
fn a_refusal_before_authentication_spends_nothing_of_the_sender() {
    use sumchain_crypto::sign;
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let ok = c.one(c.tx(&sponsor(), sponsored(&current(&c, &carol()))));
    assert_eq!(ok.status, TxStatus::Success);
    let carol_addr = carol().address();
    let n = c.msg_nonce(&carol_addr);
    assert_eq!(n, 1);
    let base = envelope(&carol(), &bob().address(), n, None);
    let string_form = {
        let mut m = base.clone();
        let preimage = format!(
            "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
            m.nonce,
            m.expiry,
            hex::encode(m.recipient_hash),
            hex::encode(blake3::hash(&m.message_data).as_bytes())
        );
        m.signature = *sign(preimage.as_bytes(), carol().private_key()).as_bytes();
        m
    };
    let registration_preimage = {
        let mut m = base.clone();
        let preimage = sumchain_primitives::sponsored_register_v1_signing_preimage(
            c.chain_id,
            &sponsor().address(),
            &m.sender_pubkey,
        );
        m.signature = *sign(&preimage, carol().private_key()).as_bytes();
        m
    };
    let outer_signature = {
        // carol's signature over a transaction's signing hash, presented as
        // an envelope signature.
        let tx = c.tx(&carol(), direct_to(&bob().address()));
        let mut m = base.clone();
        m.signature = tx.signature;
        m
    };
    let cases: Vec<(&str, MessagingTxData)> = vec![
        ("undecodable", malformed(MessagingOperation::SendMessage)),
        ("unsigned", sponsored(&base)),
        (
            "signed by another key",
            sponsored(&signed_v2(base.clone(), &dave(), c.chain_id)),
        ),
        (
            "signed for chain 1",
            sponsored(&signed_v2(base.clone(), &carol(), 1)),
        ),
        ("signed over the string form", sponsored(&string_form)),
        (
            "signed over a registration preimage",
            sponsored(&registration_preimage),
        ),
        (
            "the outer transaction's signature",
            sponsored(&outer_signature),
        ),
        (
            "a key that is not a curve point",
            sponsored(&{
                let mut m = base.clone();
                m.sender_pubkey = [0x02; 32];
                m
            }),
        ),
        (
            "a nonce ahead of the sender's (a gap)",
            sponsored(&c.v2(&carol(), &bob().address(), n + 1, None)),
        ),
        (
            "a nonce behind the sender's (a replay)",
            sponsored(&c.v2(&carol(), &bob().address(), n - 1, None)),
        ),
    ];
    for (label, data) in cases {
        let before = c.rows();
        let r = c.one(c.tx(&sponsor(), data));
        assert_eq!(
            (r.status, r.fee_paid),
            (TxStatus::Failed(7), FEE),
            "{label}"
        );
        assert_eq!(c.msg_nonce(&carol_addr), n, "{label}: nothing spent");
        let mut want = vec![account_key(&sponsor().address()), account_key(&proposer())];
        want.sort();
        assert_eq!(changed(&before, &c.rows()), want, "{label}");
    }
    // The sender's current envelope still executes.
    let r = c.one(c.tx(&erin(), sponsored(&current(&c, &carol()))));
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.msg_nonce(&carol_addr), n + 1);
}

/// Nonce gaps. Envelopes at n and n + 2 in one block: n executes, n + 2 is
/// refused unauthenticated and spends nothing; then n + 1 and the same n + 2
/// envelope, re-relayed, execute in order.
#[test]
fn a_nonce_gap_is_refused_without_spending_and_filled_later() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let carol_addr = carol().address();
    let e0 = c.v2(&carol(), &bob().address(), 0, None);
    let e1 = c.v2(&carol(), &bob().address(), 1, None);
    let e2 = c.v2(&carol(), &bob().address(), 2, None);
    let s = c.nonce(&sponsor());
    let r = c
        .block(vec![
            c.tx_at(&sponsor(), s, sponsored(&e0)),
            c.tx_at(&sponsor(), s + 1, sponsored(&e2)),
        ])
        .unwrap();
    assert_eq!(
        r.iter().map(|r| (r.status, r.fee_paid)).collect::<Vec<_>>(),
        vec![(TxStatus::Success, FEE), (TxStatus::Failed(7), FEE)]
    );
    assert_eq!(c.msg_nonce(&carol_addr), 1, "the gap spent nothing");
    let r = c
        .block(vec![
            c.tx_at(&sponsor(), s + 2, sponsored(&e1)),
            c.tx_at(&erin(), c.nonce(&erin()), sponsored(&e2)),
        ])
        .unwrap();
    assert!(r.iter().all(|r| r.status == TxStatus::Success), "{r:?}");
    assert_eq!(c.msg_nonce(&carol_addr), 3);
    assert_eq!(
        c.sent_by(&carol_addr).len(),
        2,
        "one event row per block below the index gate"
    );
}

/// A genuine cycle between two sponsors: sponsor relays carol's envelope 1
/// then dave's 0; erin relays dave's 1 then carol's 0. No block order keeps
/// both sponsors' account nonces and both senders' envelope nonces. In the
/// order of the account nonces the block is valid at both gates: exactly the
/// envelope that comes before its predecessor (carol's 1) is refused,
/// charged and spends nothing, and the other three execute. Re-relayed, it
/// then executes.
#[test]
fn a_genuine_cycle_between_two_sponsors_refuses_only_the_envelope_out_of_sequence() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let (s, e) = (c.nonce(&sponsor()), c.nonce(&erin()));
    let carol1 = c.v2(&carol(), &bob().address(), 1, None);
    let txs = vec![
        c.tx_at(&sponsor(), s, sponsored(&carol1)),
        c.tx_at(
            &sponsor(),
            s + 1,
            sponsored(&c.v2(&dave(), &bob().address(), 0, None)),
        ),
        c.tx_at(
            &erin(),
            e,
            sponsored(&c.v2(&dave(), &bob().address(), 1, None)),
        ),
        c.tx_at(
            &erin(),
            e + 1,
            sponsored(&c.v2(&carol(), &bob().address(), 0, None)),
        ),
    ];
    let screened = c.screen(txs.clone(), 1 << 20);
    assert!(screened.refused().is_empty());
    let r = c.block(txs).expect("a valid block");
    assert_eq!(
        r.iter().map(|r| (r.status, r.fee_paid)).collect::<Vec<_>>(),
        vec![
            (TxStatus::Failed(7), FEE),
            (TxStatus::Success, FEE),
            (TxStatus::Success, FEE),
            (TxStatus::Success, FEE),
        ]
    );
    assert_eq!((c.nonce(&sponsor()), c.nonce(&erin())), (s + 2, e + 2));
    assert_eq!(c.msg_nonce(&carol().address()), 1);
    assert_eq!(c.msg_nonce(&dave().address()), 2);
    let r = c.one(c.tx(&erin(), sponsored(&carol1)));
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.msg_nonce(&carol().address()), 2);
}

/// Unrelated sponsors. The same envelope through two sponsors in one block,
/// and in consecutive blocks: the first executes, the second is refused and
/// charged to its own sponsor, and the message is delivered once. Two
/// different envelopes signed at one nonce for two sponsors: block order
/// decides. A sponsor's refusal costs no other sponsor anything.
#[test]
fn unrelated_sponsors_each_pay_their_own_fee_and_the_envelope_executes_once() {
    // One block.
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let m = current(&c, &carol());
    let r = c
        .block(vec![
            c.tx(&sponsor(), sponsored(&m)),
            c.tx(&erin(), sponsored(&m)),
        ])
        .unwrap();
    assert_eq!(
        r.iter().map(|r| (r.status, r.fee_paid)).collect::<Vec<_>>(),
        vec![(TxStatus::Success, FEE), (TxStatus::Failed(7), FEE)]
    );
    assert_eq!(c.msg_nonce(&carol().address()), 1);
    assert_eq!(c.sent_by(&carol().address()).len(), 1);
    assert_eq!(c.balance(&sponsor().address()), FUNDS - FEE);
    assert_eq!(c.balance(&erin().address()), FUNDS - FEE);

    // Consecutive blocks.
    let m = current(&c, &carol());
    assert_eq!(
        c.one(c.tx(&erin(), sponsored(&m))).status,
        TxStatus::Success
    );
    let r = c.one(c.tx(&sponsor(), sponsored(&m)));
    assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(7), FEE));
    assert_eq!(c.msg_nonce(&carol().address()), 2);

    // Two different envelopes at one nonce: the first in block order wins.
    let n = c.msg_nonce(&carol().address());
    let to_bob = c.v2(&carol(), &bob().address(), n, None);
    let to_alice = c.v2(&carol(), &alice().address(), n, None);
    let r = c
        .block(vec![
            c.tx(&erin(), sponsored(&to_alice)),
            c.tx(&sponsor(), sponsored(&to_bob)),
        ])
        .unwrap();
    assert_eq!(
        r.iter().map(|r| r.status).collect::<Vec<_>>(),
        vec![TxStatus::Success, TxStatus::Failed(7)]
    );
    assert_eq!(c.msg_nonce(&carol().address()), n + 1);
}

/// One sponsor relays, at consecutive account nonces, dave's envelope
/// over quota, then carol's and alice's. The block is valid for the producer
/// (screening records no offender) and for the importer: dave's is refused,
/// charged and spends dave's nonce; carol's and alice's execute.
#[test]
fn one_senders_refusal_does_not_hold_the_sponsors_other_envelopes() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    dave_over_quota(&mut c);
    let s = c.nonce(&sponsor());
    let dave_n = c.msg_nonce(&dave().address());
    let txs = vec![
        c.tx_at(&sponsor(), s, sponsored(&current(&c, &dave()))),
        c.tx_at(&sponsor(), s + 1, sponsored(&current(&c, &carol()))),
        c.tx_at(&sponsor(), s + 2, sponsored(&current(&c, &alice()))),
    ];
    assert!(c.screen(txs.clone(), 1 << 20).refused().is_empty());
    let r = c.block(txs).expect("a valid block");
    assert_eq!(
        r.iter().map(|r| (r.status, r.fee_paid)).collect::<Vec<_>>(),
        vec![
            (TxStatus::Failed(7), FEE),
            (TxStatus::Success, FEE),
            (TxStatus::Success, FEE),
        ]
    );
    assert_eq!(c.msg_nonce(&dave().address()), dave_n + 1);
    assert_eq!(c.msg_nonce(&carol().address()), 1);
    assert_eq!(c.msg_nonce(&alice().address()), 1);
    assert_eq!(c.nonce(&sponsor()), s + 3);
}

/// The rule's gate. With both gates at H, an envelope refused because its
/// sender is not registered: below H (the earlier rule) the refusal is free
/// and moves no messaging nonce; at H and at H + 1 it is charged and spends
/// the nonce. Each gate alone (a configuration genesis refuses) does not
/// spend it: the envelope gate alone settles no refusal, and the accounting
/// gate alone authenticates no envelope.
#[test]
fn the_envelope_nonce_is_spent_from_the_gate() {
    const H: u64 = 3;
    let frank_addr = frank().address();
    let mut c = Chain::new(both(Some(H)));
    c.setup();
    assert_eq!(c.height + 1, H - 1);
    let r = c.one(c.tx(
        &sponsor(),
        sponsored(&envelope(&frank(), &bob().address(), 0, None)),
    ));
    assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(7), 0), "H-1");
    assert_eq!(c.msg_nonce(&frank_addr), 0, "H-1");
    for (height, n) in [(H, 0), (H + 1, 1)] {
        let r = c.one(c.tx(&sponsor(), sponsored(&current(&c, &frank()))));
        assert_eq!(c.height, height);
        assert_eq!(
            (r.status, r.fee_paid),
            (TxStatus::Failed(7), FEE),
            "{height}"
        );
        assert_eq!(c.msg_nonce(&frank_addr), n + 1, "{height}");
    }

    for (label, params) in [
        ("the envelope gate alone", gates(Some(1), None)),
        ("the accounting gate alone", gates(None, Some(1))),
    ] {
        let mut c = Chain::new(params);
        c.setup();
        let r = c.one(c.tx(&sponsor(), sponsored(&current(&c, &frank()))));
        assert_eq!(r.status, TxStatus::Failed(7), "{label}");
        assert_eq!(c.msg_nonce(&frank_addr), 0, "{label}");
    }
}

/// A spent envelope nonce is durable: after a restart the refused envelope
/// is still spent and the next one executes.
#[test]
fn a_spent_envelope_nonce_survives_a_restart() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    sponsorship_off(&mut c);
    let m = current(&c, &carol());
    assert_eq!(
        c.one(c.tx(&sponsor(), sponsored(&m))).status,
        TxStatus::Failed(7)
    );
    let mut c = c.restart();
    assert_eq!(c.msg_nonce(&carol().address()), 1);
    let tx = c.tx(
        &admin(),
        op(
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        ),
    );
    c.all_succeed(vec![tx]);
    let r = c.one(c.tx(&erin(), sponsored(&m)));
    assert_eq!(r.status, TxStatus::Failed(7), "spent before the restart");
    let r = c.one(c.tx(&erin(), sponsored(&current(&c, &carol()))));
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.msg_nonce(&carol().address()), 2);
}

/// The single-transaction arm (`execute_tx_v2`, which no block loop wraps)
/// spends a refused authenticated envelope's nonce as the loop does, and
/// keeps the fee charged before dispatch.
#[test]
fn the_single_transaction_arm_spends_a_refused_envelopes_nonce() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    sponsorship_off(&mut c);
    let tx = c.tx(&sponsor(), sponsored(&current(&c, &carol())));
    let v2 = match tx.inner() {
        sumchain_primitives::TxInner::V2(v2) => v2.clone(),
        _ => unreachable!("a version-2 transaction"),
    };
    let mut cand = sumchain_storage::candidate::CandidateExecution::new(&c.db, 1 << 30);
    let mut view = cand.view();
    let r = c
        .exec
        .execute_tx_v2(
            &mut view,
            &v2,
            &tx.signature,
            &tx.public_key,
            &proposer(),
            c.height + 1,
            T_MS,
            0,
        )
        .unwrap();
    assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(7), FEE));
    assert_eq!(
        sumchain_state::MessagingExecutor::v_get_sender_nonce(&view, &carol().address()).unwrap(),
        1
    );
    assert_eq!(
        sumchain_state::state::StateManager::v_get_balance(&view, &sponsor().address()).unwrap(),
        c.balance(&sponsor().address()) - FEE
    );
}

// ── payments: the named sender funds the existing escrow ────────────────────

/// The escrow row of the payment made by `tx`, if any.
fn escrow_of(
    c: &Chain,
    tx: &sumchain_primitives::SignedTransaction,
) -> Option<sumchain_primitives::PendingPayment> {
    c.store().get_pending_payment(&tx.hash()).unwrap()
}

/// The event `tx` stored, if any.
fn event_of(
    c: &Chain,
    sender: &sumchain_primitives::Address,
    tx: &sumchain_primitives::SignedTransaction,
) -> Option<sumchain_primitives::MessageEvent> {
    c.sent_by(sender)
        .into_iter()
        .find(|e| e.message_id == tx.hash())
}

/// Every balance, every escrowed amount, every stake and the sponsorship pool:
/// what no messaging operation may create or destroy.
fn total_value(c: &Chain) -> u128 {
    let balances: u128 = c.balances().iter().sum();
    let escrowed: u128 =
        c.db.iter(cf::MESSAGING_PENDING_PAYMENTS)
            .unwrap()
            .map(|(_, v)| {
                sumchain_storage::messaging_store::decode_pending_payment(&v)
                    .unwrap()
                    .amount
            })
            .sum();
    let staked: u128 = everyone()
        .iter()
        .map(|k| c.store().get_stake_balance(&k.address()).unwrap())
        .sum();
    balances + escrowed + staked + c.store().get_sponsorship_balance().unwrap()
}

/// At both gates a sponsored envelope with a positive amount is
/// a payment by the named sender: carol is debited the amount, the escrow row
/// and its recipient index are written (amount, `expiry = clock + 7 days`,
/// sender carol), the event reports the payment, the sponsor pays the fee
/// and nothing else, carol's account nonce is unchanged and her messaging
/// nonce moves once, and the proposer is credited the fee. Bob then claims:
/// he is credited the amount and charged his fee once, and both escrow rows
/// are gone. Value is conserved throughout.
#[test]
fn a_sponsored_payment_escrows_the_senders_amount_and_the_recipient_claims_it() {
    use sumchain_storage::messaging_store::{payment_index_key, pending_payment_key};
    let amount: u128 = 5_000;
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let total = total_value(&c);
    let (carol_addr, bob_addr, sponsor_addr) =
        (carol().address(), bob().address(), sponsor().address());
    let before = c.rows();
    let (carol_before, sponsor_before, pool_before) = (
        (c.balance(&carol_addr), c.nonce(&carol())),
        (c.balance(&sponsor_addr), c.nonce(&sponsor())),
        c.balance(&proposer()),
    );
    let m = c.v2(&carol(), &bob_addr, 0, Some(amount));
    let tx = c.tx(&sponsor(), sponsored(&m));
    let r = c.one(tx.clone());
    assert_eq!((r.status, r.fee_paid), (TxStatus::Success, FEE));
    assert_eq!(
        (c.balance(&carol_addr), c.nonce(&carol())),
        (carol_before.0 - amount, carol_before.1),
        "carol pays the amount, her account nonce stays"
    );
    assert_eq!(
        (c.balance(&sponsor_addr), c.nonce(&sponsor())),
        (sponsor_before.0 - FEE, sponsor_before.1 + 1),
        "the sponsor pays the fee only"
    );
    assert_eq!(c.balance(&proposer()), pool_before + FEE);
    assert_eq!(c.msg_nonce(&carol_addr), 1);
    let escrow = escrow_of(&c, &tx).expect("escrowed");
    assert_eq!(
        (
            escrow.amount,
            escrow.sender,
            escrow.recipient_hash,
            escrow.expiry
        ),
        (amount, carol_addr, recipient_hash(&bob_addr), 7 * 24 * 3600),
        "the clock reads zero while the clock gates are closed"
    );
    assert!(event_of(&c, &carol_addr, &tx).expect("event").has_payment);
    assert_eq!(total_value(&c), total, "conserved");
    let moved = changed(&before, &c.rows());
    for key in [
        account_key(&carol_addr),
        account_key(&sponsor_addr),
        account_key(&proposer()),
        (
            cf::MESSAGING_PENDING_PAYMENTS.to_string(),
            pending_payment_key(&tx.hash()).to_vec(),
        ),
        (
            cf::MESSAGING_PAYMENTS_BY_RECIPIENT.to_string(),
            payment_index_key(&recipient_hash(&bob_addr), &tx.hash()),
        ),
    ] {
        assert!(moved.contains(&key), "{key:?}");
    }

    // The recipient claims.
    let bob_before = c.balance(&bob_addr);
    let claim = c.tx(
        &bob(),
        op(
            MessagingOperation::ClaimPayment,
            &ClaimPaymentData {
                message_id: tx.hash(),
                recipient_address: bob_addr,
            },
        ),
    );
    let r = c.one(claim);
    assert_eq!((r.status, r.fee_paid), (TxStatus::Success, FEE));
    assert_eq!(c.balance(&bob_addr), bob_before + amount - FEE);
    assert!(escrow_of(&c, &tx).is_none());
    assert!(c
        .db
        .iter(cf::MESSAGING_PAYMENTS_BY_RECIPIENT)
        .unwrap()
        .next()
        .is_none());
    assert_eq!(total_value(&c), total, "conserved");
}

/// `Some(0)` and `None` sign the same preimage and mean the same thing:
/// no payment. A relayer that flips one into the other changes the
/// transaction's hash and nothing else: the rows are identical except the
/// rows keyed by that hash (the event's id).
#[test]
fn some_zero_and_none_are_the_same_envelope() {
    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }
    let run = |amount: Option<u128>| {
        let mut c = Chain::new(both(Some(1)));
        c.setup();
        let mut m = c.v2(&carol(), &bob().address(), 0, None);
        m.koppa_amount = amount;
        let tx = c.tx(&sponsor(), sponsored(&m));
        let hash = tx.hash();
        let r = c.one(tx);
        assert_eq!(r.status, TxStatus::Success, "{amount:?}");
        let ev = c.sent_by(&carol().address());
        assert_eq!(ev.len(), 1);
        assert!(!ev[0].has_payment, "{amount:?}");
        assert!(c
            .db
            .iter(cf::MESSAGING_PENDING_PAYMENTS)
            .unwrap()
            .next()
            .is_none());
        // Rows that carry the transaction's hash (the event's message id)
        // set aside, the two runs agree byte for byte.
        let mut rows = c.rows();
        let removed = rows.len();
        rows.retain(|(_, k), v| !contains(k, hash.as_bytes()) && !contains(v, hash.as_bytes()));
        assert!(rows.len() < removed, "the event rows name the transaction");
        (rows, c.balances(), ev[0].size)
    };
    assert_eq!(run(None), run(Some(0)));
}

/// A relayer that changes the amount after signing breaks the
/// signature: refused before authentication, nothing of carol's spent, the
/// relayer charged.
#[test]
fn a_relayer_cannot_change_the_amount() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    for (signed, sent) in [
        (None, Some(1)),
        (Some(5_000), Some(50_000)),
        (Some(5_000), None),
    ] {
        let mut m = c.v2(&carol(), &bob().address(), 0, signed);
        m.koppa_amount = sent;
        let carol_before = c.balance(&carol().address());
        let r = c.one(c.tx(&sponsor(), sponsored(&m)));
        assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(7), FEE));
        assert_eq!(c.balance(&carol().address()), carol_before);
        assert_eq!(c.msg_nonce(&carol().address()), 0);
    }
}

/// Set `kp`'s committed balance, keeping its account nonce.
fn set_balance(c: &Chain, kp: &sumchain_crypto::KeyPair, balance: u128) {
    sumchain_storage::StateStore::new(&c.db)
        .put_account(
            &kp.address(),
            &sumchain_storage::schema::AccountState {
                balance,
                nonce: c.nonce(kp),
            },
        )
        .unwrap();
}

/// An amount the sender cannot afford is refused after
/// authentication: the nonce is spent, no escrow, the sender's balance
/// unchanged, the sponsor charged the fee. Two payments at `n` and `n + 1` in
/// one block where the balance covers only the first: the first is escrowed,
/// the second refused and spent.
#[test]
fn an_unaffordable_payment_is_refused_and_spends_the_nonce() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    set_balance(&c, &carol(), 7_000);
    let tx = c.tx(
        &sponsor(),
        sponsored(&c.v2(&carol(), &bob().address(), 0, Some(7_001))),
    );
    let r = c.one(tx.clone());
    assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(7), FEE));
    assert_eq!(c.balance(&carol().address()), 7_000);
    assert_eq!(c.msg_nonce(&carol().address()), 1);
    assert!(escrow_of(&c, &tx).is_none());

    let s = c.nonce(&sponsor());
    let first = c.tx_at(
        &sponsor(),
        s,
        sponsored(&c.v2(&carol(), &bob().address(), 1, Some(4_000))),
    );
    let second = c.tx_at(
        &sponsor(),
        s + 1,
        sponsored(&c.v2(&carol(), &bob().address(), 2, Some(4_000))),
    );
    let r = c.block(vec![first.clone(), second.clone()]).unwrap();
    assert_eq!(
        r.iter().map(|r| (r.status, r.fee_paid)).collect::<Vec<_>>(),
        vec![(TxStatus::Success, FEE), (TxStatus::Failed(7), FEE)]
    );
    assert_eq!(c.balance(&carol().address()), 3_000);
    assert!(escrow_of(&c, &first).is_some());
    assert!(escrow_of(&c, &second).is_none());
    assert_eq!(c.msg_nonce(&carol().address()), 3);
}

/// Sender = sponsor: carol relays her own envelope. One fee, one
/// account nonce, one messaging nonce, the amount once. A balance of exactly
/// fee + amount succeeds and ends at zero; fee + amount - 1 is refused after
/// the fee is charged, the nonce spent, no escrow.
#[test]
fn a_sender_relaying_its_own_payment_is_charged_once() {
    let amount: u128 = 5_000;
    for (balance, ok) in [(FEE + amount, true), (FEE + amount - 1, false)] {
        let mut c = Chain::new(both(Some(1)));
        c.setup();
        set_balance(&c, &carol(), balance);
        let (nonce, pool) = (c.nonce(&carol()), c.balance(&proposer()));
        let tx = c.tx(
            &carol(),
            sponsored(&c.v2(&carol(), &bob().address(), 0, Some(amount))),
        );
        let r = c.one(tx.clone());
        assert_eq!(c.nonce(&carol()), nonce + 1, "{balance}: one account nonce");
        assert_eq!(
            c.msg_nonce(&carol().address()),
            1,
            "{balance}: one messaging nonce"
        );
        assert_eq!(c.balance(&proposer()), pool + FEE, "{balance}: one fee");
        if ok {
            assert_eq!((r.status, r.fee_paid), (TxStatus::Success, FEE));
            assert_eq!(c.balance(&carol().address()), 0);
            assert_eq!(escrow_of(&c, &tx).unwrap().amount, amount);
        } else {
            assert_eq!((r.status, r.fee_paid), (TxStatus::Failed(7), FEE));
            assert_eq!(c.balance(&carol().address()), balance - FEE);
            assert!(escrow_of(&c, &tx).is_none());
        }
    }
}

/// The named sender is the block's proposer: the relayer's fee is
/// credited to it before the payment is checked, so a sender holding
/// amount - fee pays; the relayer still pays only the fee.
#[test]
fn a_sender_that_proposes_the_block_is_credited_the_fee_first() {
    let amount: u128 = 5_000;
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    c.proposer_pk = *carol().public_key().as_bytes();
    set_balance(&c, &carol(), amount - FEE);
    let sponsor_before = c.balance(&sponsor().address());
    let tx = c.tx(
        &sponsor(),
        sponsored(&c.v2(&carol(), &bob().address(), 0, Some(amount))),
    );
    let r = c.one(tx.clone());
    assert_eq!((r.status, r.fee_paid), (TxStatus::Success, FEE));
    assert_eq!(c.balance(&carol().address()), 0);
    assert_eq!(c.balance(&sponsor().address()), sponsor_before - FEE);
    assert_eq!(escrow_of(&c, &tx).unwrap().amount, amount);
}

/// A third party includes a gossiped envelope first: the payment
/// executes once, its escrow and event keyed by the third party's
/// transaction; the relay's own copy is refused (nonce), charged to the
/// relay, and moves nothing of carol's.
#[test]
fn a_third_party_including_first_takes_the_escrow_id() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let m = c.v2(&carol(), &bob().address(), 0, Some(5_000));
    let third = c.tx(&erin(), sponsored(&m));
    let relay = c.tx(&sponsor(), sponsored(&m));
    let carol_before = c.balance(&carol().address());
    let r = c.block(vec![third.clone(), relay.clone()]).unwrap();
    assert_eq!(
        r.iter().map(|r| (r.status, r.fee_paid)).collect::<Vec<_>>(),
        vec![(TxStatus::Success, FEE), (TxStatus::Failed(7), FEE)]
    );
    assert_eq!(
        c.balance(&carol().address()),
        carol_before - 5_000,
        "paid once"
    );
    assert!(escrow_of(&c, &third).is_some());
    assert!(escrow_of(&c, &relay).is_none());
}

/// Payments across the gate. Both gates at H. Below H an envelope naming an amount
/// executes under the earlier rule, as before: no debit and no escrow.
/// At H and H + 1 it is a payment: debited and escrowed, the flag backed.
#[test]
fn a_payment_executes_from_the_gate_and_the_earlier_rule_below_it() {
    const H: u64 = 3;
    let mut c = Chain::new(both(Some(H)));
    c.setup();
    let carol_addr = carol().address();
    assert_eq!(c.height + 1, H - 1);
    let below = c.tx(
        &sponsor(),
        sponsored(&envelope(&carol(), &bob().address(), 0, Some(5_000))),
    );
    let balance = c.balance(&carol_addr);
    let r = c.one(below.clone());
    assert_eq!((r.status, r.fee_paid), (TxStatus::Success, FEE));
    assert_eq!(c.balance(&carol_addr), balance, "H-1: no debit");
    assert!(escrow_of(&c, &below).is_none(), "H-1: no escrow");
    assert!(
        event_of(&c, &carol_addr, &below).unwrap().has_payment,
        "H-1: the legacy flag"
    );
    for height in [H, H + 1] {
        let n = c.msg_nonce(&carol_addr);
        let tx = c.tx(
            &sponsor(),
            sponsored(&c.v2(&carol(), &bob().address(), n, Some(5_000))),
        );
        let balance = c.balance(&carol_addr);
        let r = c.one(tx.clone());
        assert_eq!(c.height, height);
        assert_eq!((r.status, r.fee_paid), (TxStatus::Success, FEE), "{height}");
        assert_eq!(c.balance(&carol_addr), balance - 5_000, "{height}");
        assert_eq!(escrow_of(&c, &tx).unwrap().amount, 5_000, "{height}");
        assert!(
            event_of(&c, &carol_addr, &tx).unwrap().has_payment,
            "{height}"
        );
    }
}

/// A second handle on the same key.
struct KeyPairOf;
impl KeyPairOf {
    fn same(kp: &sumchain_crypto::KeyPair) -> sumchain_crypto::KeyPair {
        sumchain_crypto::KeyPair::from_bytes(*kp.private_key().as_bytes())
    }
}

/// A small deterministic generator (SplitMix64), so the property test below
/// is reproducible from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Escrow conservation. Random sequences of sponsored envelopes (with
/// and without amounts, affordable or not, relayed by a third party or by the
/// sender itself, valid or with a bad signature or a stale nonce, sometimes
/// sent with sponsorship turned off) and claims of the escrows made, at both
/// gates, on chain 7. After every block: balances plus escrow plus stakes plus
/// the pool are unchanged; a relayer that is not the named sender lost
/// exactly its fees; a sender lost exactly what it paid into escrows that
/// executed (plus its own fees when it relayed); and no refused envelope
/// moved any value.
#[test]
fn value_is_conserved_and_a_sponsor_never_pays_value() {
    let senders: [fn() -> sumchain_crypto::KeyPair; 3] = [alice, carol, dave];
    let relayers: [fn() -> sumchain_crypto::KeyPair; 2] = [sponsor, erin];
    for seed in 1..=6u64 {
        let mut rng = Rng(seed);
        let mut c = Chain::new(both(Some(1)));
        c.setup();
        for kp in senders {
            set_balance(&c, &kp(), 20_000 + rng.below(10_000) as u128);
        }
        let total = total_value(&c);
        let mut escrows: Vec<sumchain_primitives::Hash> = Vec::new();
        for step in 0..40 {
            let pick = rng.below(10);
            if pick == 0 && !escrows.is_empty() {
                // bob claims an escrow
                let id = escrows.remove(rng.below(escrows.len() as u64) as usize);
                let r = c.one(c.tx(
                    &bob(),
                    op(
                        MessagingOperation::ClaimPayment,
                        &ClaimPaymentData {
                            message_id: id,
                            recipient_address: bob().address(),
                        },
                    ),
                ));
                assert_eq!(r.status, TxStatus::Success, "seed {seed} step {step}");
            } else if pick == 1 {
                // sponsorship toggled
                let enabled = !c.store().is_sponsorship_enabled().unwrap();
                let tx = c.tx(
                    &admin(),
                    op(
                        MessagingOperation::SetSponsorshipEnabled,
                        &SetSponsorshipEnabledData { enabled },
                    ),
                );
                c.all_succeed(vec![tx]);
            } else {
                let sender = &senders[rng.below(3) as usize]();
                let self_relay = rng.below(4) == 0;
                let relayer = if self_relay {
                    KeyPairOf::same(sender)
                } else {
                    relayers[rng.below(2) as usize]()
                };
                let amount = match rng.below(5) {
                    0 => None,
                    1 => Some(0),
                    2 => Some(1 + rng.below(3_000) as u128),
                    3 => Some(c.balance(&sender.address())),
                    _ => Some(50_000 + rng.below(50_000) as u128),
                };
                let mut n = c.msg_nonce(&sender.address());
                let corrupt = rng.below(8);
                if corrupt == 0 && n > 0 {
                    n -= 1; // a stale nonce
                }
                let mut m = c.v2(sender, &bob().address(), n, amount);
                if corrupt == 1 {
                    m.signature[0] ^= 1; // a bad signature
                }
                let tx = c.tx(&relayer, sponsored(&m));
                let paid_before = c.balance(&sender.address());
                let relayer_before = c.balance(&relayer.address());
                let r = c.one(tx.clone());
                let escrowed = escrow_of(&c, &tx).map(|e| e.amount).unwrap_or(0);
                if r.status == TxStatus::Success {
                    assert_eq!(escrowed, amount.unwrap_or(0), "seed {seed} step {step}");
                    if escrowed > 0 {
                        escrows.push(tx.hash());
                    }
                } else {
                    assert_eq!(
                        escrowed, 0,
                        "seed {seed} step {step}: a refusal moves no value"
                    );
                }
                // A relayer that cannot pay the fee takes `InsufficientBalance`
                // from transaction validation: free, and nothing moves.
                let fee = if r.status == TxStatus::InsufficientBalance {
                    0
                } else {
                    FEE
                };
                assert_eq!(r.fee_paid, fee, "seed {seed} step {step}");
                if self_relay {
                    assert_eq!(
                        c.balance(&sender.address()),
                        paid_before - fee - escrowed,
                        "seed {seed} step {step}: the fee once and the amount once"
                    );
                } else {
                    assert_eq!(
                        c.balance(&relayer.address()),
                        relayer_before - fee,
                        "seed {seed} step {step}: the relayer pays the fee only"
                    );
                    assert_eq!(
                        c.balance(&sender.address()),
                        paid_before - escrowed,
                        "seed {seed} step {step}: the sender pays exactly what was escrowed"
                    );
                }
            }
            assert_eq!(
                total_value(&c),
                total,
                "seed {seed} step {step}: value conserved"
            );
        }
    }
}

// ── envelope outcomes ───────────────────────────────────────────────────────

fn outcome(
    c: &Chain,
    sender: &sumchain_primitives::Address,
    nonce: u64,
) -> Option<sumchain_storage::messaging_store::EnvelopeOutcome> {
    c.store().get_envelope_outcome(sender, nonce).unwrap()
}

fn spent(
    tx: &sumchain_primitives::SignedTransaction,
    outcome_code: u32,
    escrowed_amount: u128,
) -> Option<sumchain_storage::messaging_store::EnvelopeOutcome> {
    Some(sumchain_storage::messaging_store::EnvelopeOutcome {
        tx_hash: tx.hash(),
        outcome_code,
        escrowed_amount,
    })
}

/// At both gates every spent envelope nonce has one outcome row naming
/// the transaction that spent it, its receipt code and what it escrowed: a
/// payment (0, the amount), a message without one (0, 0), a refusal after
/// authentication (7, 0). A refusal before authentication spends no nonce
/// and writes no row; a front-runner's transaction is the one recorded, and
/// the relay's later copy, refused, does not overwrite it. The committed
/// reader and the candidate reader agree, and the rows survive a restart.
#[test]
fn every_spent_envelope_nonce_records_what_spent_it() {
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let carol_addr = carol().address();
    let bob_addr = bob().address();

    let pay = c.tx(
        &sponsor(),
        sponsored(&c.v2(&carol(), &bob_addr, 0, Some(5_000))),
    );
    assert_eq!(c.one(pay.clone()).status, TxStatus::Success);
    assert_eq!(outcome(&c, &carol_addr, 0), spent(&pay, 0, 5_000));

    let plain = c.tx(&erin(), sponsored(&c.v2(&carol(), &bob_addr, 1, Some(0))));
    assert_eq!(c.one(plain.clone()).status, TxStatus::Success);
    assert_eq!(outcome(&c, &carol_addr, 1), spent(&plain, 0, 0));

    sponsorship_off(&mut c);
    let refused = c.tx(&sponsor(), sponsored(&c.v2(&carol(), &bob_addr, 2, None)));
    assert_eq!(c.one(refused.clone()).status, TxStatus::Failed(7));
    assert_eq!(outcome(&c, &carol_addr, 2), spent(&refused, 7, 0));

    let tampered = c.tx(
        &sponsor(),
        sponsored(&signed_v2(
            envelope(&carol(), &bob_addr, 3, None),
            &dave(),
            c.chain_id,
        )),
    );
    assert_eq!(c.one(tampered).status, TxStatus::Failed(7));
    assert_eq!(
        outcome(&c, &carol_addr, 3),
        None,
        "no authentication, no row"
    );

    let tx = c.tx(
        &admin(),
        op(
            MessagingOperation::SetSponsorshipEnabled,
            &SetSponsorshipEnabledData { enabled: true },
        ),
    );
    c.all_succeed(vec![tx]);
    let m = c.v2(&carol(), &bob_addr, 3, None);
    let front = c.tx(&erin(), sponsored(&m));
    let relay = c.tx(&sponsor(), sponsored(&m));
    let r = c.block(vec![front.clone(), relay]).unwrap();
    assert_eq!(
        r.iter().map(|r| r.status).collect::<Vec<_>>(),
        vec![TxStatus::Success, TxStatus::Failed(7)]
    );
    assert_eq!(
        outcome(&c, &carol_addr, 3),
        spent(&front, 0, 0),
        "the first includer"
    );

    {
        let mut cand = sumchain_storage::candidate::CandidateExecution::new(&c.db, 1 << 20);
        let view = cand.view();
        for n in 0..4 {
            assert_eq!(
                sumchain_state::MessagingExecutor::v_get_envelope_outcome(&view, &carol_addr, n)
                    .unwrap(),
                outcome(&c, &carol_addr, n),
                "{n}"
            );
        }
    }
    let c = c.restart();
    assert_eq!(
        outcome(&c, &carol_addr, 0),
        spent(&pay, 0, 5_000),
        "after a restart"
    );
    assert_eq!(
        outcome(&c, &carol_addr, 2),
        spent(&refused, 7, 0),
        "after a restart"
    );
}

/// No outcome row where no authenticated envelope spends a nonce: below both
/// gates, and with the accounting gate alone (no envelope is authenticated).
/// With the envelope gate alone a success spends the nonce and writes its
/// row; a refusal there spends nothing and writes none.
#[test]
fn outcome_rows_follow_the_envelope_gate() {
    for (label, params, success_row) in [
        ("both gates absent", both(None), false),
        ("the accounting gate alone", gates(None, Some(1)), false),
        ("the envelope gate alone", gates(Some(1), None), true),
    ] {
        let mut c = Chain::new(params);
        c.setup();
        let carol_addr = carol().address();
        let tx = c.tx(
            &sponsor(),
            sponsored(&c.v2(&carol(), &bob().address(), 0, None)),
        );
        assert_eq!(c.one(tx.clone()).status, TxStatus::Success, "{label}");
        let want = if success_row { spent(&tx, 0, 0) } else { None };
        assert_eq!(outcome(&c, &carol_addr, 0), want, "{label}");
        let frank_tx = c.tx(
            &sponsor(),
            sponsored(&c.v2(&frank(), &bob().address(), 0, None)),
        );
        assert_eq!(c.one(frank_tx).status, TxStatus::Failed(7), "{label}");
        assert_eq!(outcome(&c, &frank().address(), 0), None, "{label}");
    }
}

/// The outcome rows share `cf::MESSAGING_SENDER_NONCES` with the nonce rows
/// and can never be read as one: a nonce key is a bare 20-byte address, an
/// outcome key is 52 bytes behind its prefix.
#[test]
fn an_outcome_key_never_meets_a_nonce_key() {
    use sumchain_storage::messaging_store::{
        envelope_outcome_key, sender_nonce_key, ENVELOPE_OUTCOME_PREFIX,
    };
    for kp in everyone() {
        let a = kp.address();
        for n in [0, 1, u64::MAX] {
            let k = envelope_outcome_key(&a, n);
            assert_eq!(k.len(), 52);
            assert!(k.starts_with(ENVELOPE_OUTCOME_PREFIX));
            assert_ne!(k.as_slice(), sender_nonce_key(&a));
            assert_eq!(sender_nonce_key(&a).len(), 20);
        }
    }
    let mut c = Chain::new(both(Some(1)));
    c.setup();
    let tx = c.tx(
        &sponsor(),
        sponsored(&c.v2(&carol(), &bob().address(), 0, None)),
    );
    c.one(tx);
    assert_eq!(
        c.msg_nonce(&carol().address()),
        1,
        "the nonce row reads as before"
    );
}

// ── an expired claim refunds the sender, as a success, from the gate ────────

/// With the clock gates open an escrow expires seven days after
/// the block that made it. At both gates the recipient's claim after that is
/// a success whose effect is the refund: the sender is credited the amount,
/// both escrow rows are deleted, the claimer is charged the fee once and
/// receives nothing. Below both gates the same claim is a failed receipt,
/// uncharged, with the refund made, as before. Value is conserved either way.
#[test]
fn an_expired_claim_refunds_the_sender_as_a_success_from_the_gate() {
    for (gate, want) in [
        (Some(1), (TxStatus::Success, FEE)),
        (None, (TxStatus::Failed(7), 0)),
    ] {
        let mut c = Chain::new(both_with_clock(gate));
        c.setup();
        let pay = c.tx(&alice(), payment_to(&bob().address(), 500));
        c.all_succeed(vec![pay.clone()]);
        let total = total_value(&c);
        let expiry = escrow_of(&c, &pay).expect("escrowed").expiry;
        c.clock_offset_ms = 8 * 24 * 3600 * 1000;
        assert!(c.next_second() > expiry);
        let (alice_before, bob_before) =
            (c.balance(&alice().address()), c.balance(&bob().address()));
        let r = c.one(c.tx(
            &bob(),
            op(
                MessagingOperation::ClaimPayment,
                &ClaimPaymentData {
                    message_id: pay.hash(),
                    recipient_address: bob().address(),
                },
            ),
        ));
        assert_eq!((r.status, r.fee_paid), want, "{gate:?}");
        assert_eq!(
            c.balance(&alice().address()),
            alice_before + 500,
            "{gate:?}: refunded"
        );
        assert_eq!(c.balance(&bob().address()), bob_before - want.1, "{gate:?}");
        assert!(escrow_of(&c, &pay).is_none(), "{gate:?}");
        assert!(c
            .db
            .iter(cf::MESSAGING_PAYMENTS_BY_RECIPIENT)
            .unwrap()
            .next()
            .is_none());
        assert_eq!(total_value(&c), total, "{gate:?}: conserved");
    }
}

/// The accounting gate at H for expired claims: at H-1 a failed receipt with
/// the refund, at H and H+1 a charged success with the refund.
#[test]
fn the_refund_outcome_starts_exactly_at_the_gate() {
    const H: u64 = 4;
    let mut c = Chain::new(both_with_clock(Some(H)));
    c.setup();
    let n = c.nonce(&alice());
    let pays: Vec<_> = (0..3)
        .map(|i| {
            c.tx_at(
                &alice(),
                n + i,
                payment_to(&bob().address(), 100 + i as u128),
            )
        })
        .collect();
    c.all_succeed(pays.clone());
    c.clock_offset_ms = 8 * 24 * 3600 * 1000;
    for (pay, height) in pays.iter().zip([H - 1, H, H + 1]) {
        let alice_before = c.balance(&alice().address());
        let r = c.one(c.tx(
            &bob(),
            op(
                MessagingOperation::ClaimPayment,
                &ClaimPaymentData {
                    message_id: pay.hash(),
                    recipient_address: bob().address(),
                },
            ),
        ));
        assert_eq!(c.height, height);
        let want = if height < H {
            (TxStatus::Failed(7), 0)
        } else {
            (TxStatus::Success, FEE)
        };
        assert_eq!((r.status, r.fee_paid), want, "{height}");
        assert!(
            c.balance(&alice().address()) > alice_before,
            "{height}: refunded"
        );
        assert!(escrow_of(&c, pay).is_none(), "{height}");
    }
}

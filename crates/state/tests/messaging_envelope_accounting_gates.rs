//! The sponsored-envelope verification gate and the messaging fee-accounting
//! gate (proposed names, dormant).
//!
//! This file starts with the dormant pin: a twelve-block history of signed
//! messaging transactions covering every one of the eighteen generic messaging
//! operations, succeeding and refused, sponsored sends included, executed and
//! published through the real block path (`execute_block` -> `accept_produced`
//! -> `publish`) with every gate absent. Its state roots and receipts were
//! recorded with this file's first version, BEFORE either gate existed, and
//! are asserted
//! unchanged here: with the gates absent, and with them set above the history.

mod common;

use std::sync::Arc;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::messaging::{
    BlockSenderData, ClaimPaymentData, ContactData, ContentType, FundRegistryData, MessageFlags,
    MessageHeader, MessagingTxData, RegisterPublicKeyData, ReportSpamData, SendMessageData,
    SendMessageWithPaymentData, SetDailyQuotaData, SetInboxFilterData, SetMaxMessageSizeData,
    SetMinTrustStakeData, SetSponsorshipEnabledData, StakeForTrustData, UpdatePublicKeyData,
    SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, InboxFilter, MessagingOperation, MessagingUnstakeData,
    Receipt, SignedTransaction, SponsoredMessage, TransactionV2, TxPayload,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;

/// 2025-10-09T08:53:20Z, in milliseconds, as a proposer writes a timestamp.
const T_MS: u64 = 1_760_000_000_000;
const MINUTE_MS: u64 = 60_000;
const FEE: u128 = 100;
/// Enough for the trust-stake minimum (`DEFAULT_MIN_TRUST_STAKE`, 1e11) twice.
const FUNDS: u128 = 1_000_000_000_000_000;
/// An envelope expiry that never passes, in Unix seconds.
const NEVER: u64 = u64::MAX;
/// The proposer key every block names.
const PROPOSER_PK: [u8; 32] = [0x5B; 32];
/// Blocks in the pinned history, at heights 1..=BLOCKS.
const BLOCKS: u64 = 12;

fn key(seed: u8) -> KeyPair {
    KeyPair::from_bytes([seed; 32])
}
/// The messaging registry admin.
fn admin() -> KeyPair {
    key(0x61)
}
/// A registered sender who pays her own fees.
fn alice() -> KeyPair {
    key(0x62)
}
/// The recipient.
fn bob() -> KeyPair {
    key(0x63)
}
/// A registered sender whose messages are relayed.
fn carol() -> KeyPair {
    key(0x64)
}
/// Relays carol's envelopes and pays the outer fee.
fn sponsor() -> KeyPair {
    key(0x65)
}
/// Funded, registered nowhere, not the admin.
fn dave() -> KeyPair {
    key(0x66)
}
/// A second relayer.
fn erin() -> KeyPair {
    key(0x67)
}
/// Another funded account.
fn frank() -> KeyPair {
    key(0x68)
}
fn everyone() -> [KeyPair; 8] {
    [
        admin(),
        alice(),
        bob(),
        carol(),
        sponsor(),
        dave(),
        erin(),
        frank(),
    ]
}

/// Production's shape: V2 open, `admin` as the messaging registry admin, every
/// other gate closed (so the messaging clock reads zero).
fn base() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    p
}

fn valid_message(rh: [u8; 32]) -> Vec<u8> {
    let header = MessageHeader {
        magic: SRC201_MAGIC,
        version: SRC201_VERSION,
        flags: MessageFlags::encrypted(),
        content_type: ContentType::TextPlain,
        attachment_count: 0,
        recipient_hash: rh,
        ephemeral_pubkey: [2u8; 32],
    };
    let mut v = header.to_bytes().to_vec();
    v.extend_from_slice(&[0u8; SRC201_NONCE_SIZE]);
    v.extend_from_slice(&[0u8, 0u8]);
    v.extend_from_slice(&[0u8; SRC201_TAG_SIZE]);
    v
}

fn op(operation: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation,
        data: bincode::serialize(payload).unwrap(),
    }
}

fn raw(operation: MessagingOperation, data: Vec<u8>) -> MessagingTxData {
    MessagingTxData { operation, data }
}

/// `kp` signs a V2 messaging transaction carrying `data` at `nonce`.
fn signed_at(kp: &KeyPair, nonce: u64, data: MessagingTxData) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::Messaging(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// `kp` signs `data` at its committed account nonce. One transaction per
/// signer per block, so the committed nonce is the one the block expects.
fn signed(state: &StateManager, kp: &KeyPair, data: MessagingTxData) -> SignedTransaction {
    signed_at(kp, state.get_nonce(&kp.address()).unwrap(), data)
}

fn direct_to(to: &Address) -> MessagingTxData {
    let rh = recipient_hash(to);
    op(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: valid_message(rh),
            recipient_hash: rh,
        },
    )
}

/// A direct message whose bytes are not an SRC-201 message.
fn direct_malformed(to: &Address) -> MessagingTxData {
    op(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: vec![0u8; 16],
            recipient_hash: recipient_hash(to),
        },
    )
}

fn payment_to(to: &Address, amount: u128) -> MessagingTxData {
    let rh = recipient_hash(to);
    op(
        MessagingOperation::SendMessageWithPayment,
        &SendMessageWithPaymentData {
            message_data: valid_message(rh),
            recipient_hash: rh,
            koppa_amount: amount,
        },
    )
}

/// An envelope naming `sender` as the sender of a message to `to`, with the
/// signature `signature`.
fn envelope(
    sender: &KeyPair,
    to: &Address,
    nonce: u64,
    expiry: u64,
    koppa_amount: Option<u128>,
    signature: [u8; 64],
) -> SponsoredMessage {
    let rh = recipient_hash(to);
    SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature,
        sender_pubkey: *sender.public_key().as_bytes(),
        nonce,
        expiry,
        koppa_amount,
    }
}

fn sponsored(m: &SponsoredMessage) -> MessagingTxData {
    op(MessagingOperation::SendMessage, m)
}

fn register(kp: &KeyPair) -> MessagingTxData {
    op(
        MessagingOperation::RegisterPublicKey,
        &RegisterPublicKeyData {
            public_key: *kp.public_key().as_bytes(),
        },
    )
}

fn contact(operation: MessagingOperation, of: &KeyPair) -> MessagingTxData {
    op(
        operation,
        &ContactData {
            contact_hash: recipient_hash(&of.address()),
        },
    )
}

/// One block's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The block was executed and published: its root and receipts.
    pub published: Option<(Hash, Vec<Receipt>)>,
    /// The block was refused: the refusal.
    pub refused: Option<String>,
}

impl Outcome {
    /// The canonical text of this outcome, which the pins hash.
    fn line(&self, height: u64) -> String {
        match (&self.published, &self.refused) {
            (Some((root, receipts)), None) => {
                format!("{height} published root={root} receipts={receipts:?}")
            }
            (None, Some(e)) => format!("{height} refused {e}"),
            _ => unreachable!(),
        }
    }
}

/// The block at `height`: its transactions, one per signer. `payment` is the
/// paid message's id, set by block 4 and claimed by block 5.
fn block_at(height: u64, state: &StateManager, payment: &mut Hash) -> Vec<SignedTransaction> {
    let s = state;
    match height {
        // Quota of fifty; carol, alice and bob register; dave is not the admin.
        1 => vec![
            signed(
                s,
                &admin(),
                op(
                    MessagingOperation::SetDailyQuota,
                    &SetDailyQuotaData { quota: 50 },
                ),
            ),
            signed(s, &carol(), register(&carol())),
            signed(s, &alice(), register(&alice())),
            signed(
                s,
                &dave(),
                op(
                    MessagingOperation::SetDailyQuota,
                    &SetDailyQuotaData { quota: 1 },
                ),
            ),
            signed(s, &bob(), register(&bob())),
        ],
        // Sponsorship on; two direct messages; a malformed one; a second
        // registration of the same key.
        2 => vec![
            signed(
                s,
                &admin(),
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            signed(s, &alice(), direct_to(&bob().address())),
            signed(s, &dave(), direct_malformed(&bob().address())),
            signed(s, &carol(), direct_to(&bob().address())),
            signed(s, &bob(), register(&bob())),
        ],
        // Relayed envelopes naming carol, carrying no version-2 signature and
        // a nonce outside her sequence; one naming an unregistered sender; one
        // carrying an amount.
        3 => vec![
            signed(
                s,
                &sponsor(),
                sponsored(&envelope(
                    &carol(),
                    &bob().address(),
                    0,
                    NEVER,
                    None,
                    [0u8; 64],
                )),
            ),
            signed(
                s,
                &erin(),
                sponsored(&envelope(
                    &carol(),
                    &bob().address(),
                    7,
                    NEVER,
                    Some(5_000),
                    [0u8; 64],
                )),
            ),
            signed(
                s,
                &frank(),
                sponsored(&envelope(
                    &dave(),
                    &bob().address(),
                    0,
                    NEVER,
                    None,
                    [0u8; 64],
                )),
            ),
        ],
        // A paid message; one the sender cannot afford; a malformed one.
        4 => {
            let pay = signed(s, &alice(), payment_to(&bob().address(), 500));
            *payment = pay.hash();
            vec![
                pay,
                signed(s, &dave(), payment_to(&bob().address(), FUNDS * 2)),
                signed(
                    s,
                    &carol(),
                    op(
                        MessagingOperation::SendMessageWithPayment,
                        &SendMessageWithPaymentData {
                            message_data: vec![1u8; 16],
                            recipient_hash: recipient_hash(&bob().address()),
                            koppa_amount: 1,
                        },
                    ),
                ),
            ]
        }
        // Bob claims; dave claims nothing; alice stakes; carol stakes zero.
        5 => vec![
            signed(
                s,
                &bob(),
                op(
                    MessagingOperation::ClaimPayment,
                    &ClaimPaymentData {
                        message_id: *payment,
                        recipient_address: bob().address(),
                    },
                ),
            ),
            signed(
                s,
                &dave(),
                op(
                    MessagingOperation::ClaimPayment,
                    &ClaimPaymentData {
                        message_id: Hash::hash(b"no such payment"),
                        recipient_address: dave().address(),
                    },
                ),
            ),
            signed(
                s,
                &alice(),
                op(
                    MessagingOperation::StakeForTrust,
                    &StakeForTrustData {
                        amount: 200_000_000_000,
                    },
                ),
            ),
            signed(
                s,
                &carol(),
                op(
                    MessagingOperation::StakeForTrust,
                    &StakeForTrustData { amount: 0 },
                ),
            ),
        ],
        // Alice unstakes half; dave has nothing to unstake; bob goes
        // contacts-only; carol adds a contact.
        6 => vec![
            signed(
                s,
                &alice(),
                op(
                    MessagingOperation::Unstake,
                    &MessagingUnstakeData {
                        amount: 100_000_000_000,
                    },
                ),
            ),
            signed(
                s,
                &dave(),
                op(
                    MessagingOperation::Unstake,
                    &MessagingUnstakeData { amount: 1 },
                ),
            ),
            signed(
                s,
                &bob(),
                op(
                    MessagingOperation::SetInboxFilter,
                    &SetInboxFilterData {
                        mode: InboxFilter::ContactsOnly,
                    },
                ),
            ),
            signed(
                s,
                &carol(),
                contact(MessagingOperation::AddContact, &alice()),
            ),
        ],
        // Contacts and blocks; a report by a staked reporter and by an unstaked
        // one.
        7 => vec![
            signed(s, &bob(), contact(MessagingOperation::AddContact, &alice())),
            signed(
                s,
                &carol(),
                contact(MessagingOperation::RemoveContact, &alice()),
            ),
            signed(
                s,
                &alice(),
                op(
                    MessagingOperation::ReportSpam,
                    &ReportSpamData {
                        message_id: Hash::hash(b"a message"),
                        spammer: dave().address(),
                    },
                ),
            ),
            signed(
                s,
                &dave(),
                op(
                    MessagingOperation::ReportSpam,
                    &ReportSpamData {
                        message_id: Hash::hash(b"another message"),
                        spammer: alice().address(),
                    },
                ),
            ),
            signed(
                s,
                &frank(),
                op(
                    MessagingOperation::BlockSender,
                    &BlockSenderData {
                        sender: dave().address(),
                    },
                ),
            ),
        ],
        // Key updates, a size change, a contact removal.
        8 => vec![
            signed(
                s,
                &alice(),
                op(
                    MessagingOperation::UpdatePublicKey,
                    &UpdatePublicKeyData {
                        new_public_key: *alice().public_key().as_bytes(),
                    },
                ),
            ),
            signed(
                s,
                &dave(),
                op(
                    MessagingOperation::UpdatePublicKey,
                    &UpdatePublicKeyData {
                        new_public_key: *dave().public_key().as_bytes(),
                    },
                ),
            ),
            signed(
                s,
                &admin(),
                op(
                    MessagingOperation::SetMaxMessageSize,
                    &SetMaxMessageSizeData { size: 60_000 },
                ),
            ),
            signed(
                s,
                &bob(),
                contact(MessagingOperation::RemoveContact, &alice()),
            ),
        ],
        // The trust minimum; a size change by a non-admin; registry funding and
        // a zero funding; a block.
        9 => vec![
            signed(
                s,
                &admin(),
                op(
                    MessagingOperation::SetMinTrustStake,
                    &SetMinTrustStakeData {
                        amount: 50_000_000_000,
                    },
                ),
            ),
            signed(
                s,
                &dave(),
                op(
                    MessagingOperation::SetMaxMessageSize,
                    &SetMaxMessageSizeData { size: 1 },
                ),
            ),
            signed(
                s,
                &alice(),
                op(
                    MessagingOperation::FundRegistry,
                    &FundRegistryData { amount: 1_000 },
                ),
            ),
            signed(
                s,
                &carol(),
                op(
                    MessagingOperation::FundRegistry,
                    &FundRegistryData { amount: 0 },
                ),
            ),
            signed(
                s,
                &bob(),
                op(
                    MessagingOperation::BlockSender,
                    &BlockSenderData {
                        sender: dave().address(),
                    },
                ),
            ),
        ],
        // Two non-admin setters; the admin turns sponsorship off.
        10 => vec![
            signed(
                s,
                &dave(),
                op(
                    MessagingOperation::SetMinTrustStake,
                    &SetMinTrustStakeData { amount: 1 },
                ),
            ),
            signed(
                s,
                &frank(),
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: false },
                ),
            ),
            signed(
                s,
                &admin(),
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: false },
                ),
            ),
        ],
        // A relayed envelope with sponsorship off; alice's second message, to
        // frank, whose inbox accepts everyone.
        11 => vec![
            signed(
                s,
                &sponsor(),
                sponsored(&envelope(
                    &carol(),
                    &bob().address(),
                    2,
                    NEVER,
                    None,
                    [0u8; 64],
                )),
            ),
            signed(s, &alice(), direct_to(&frank().address())),
        ],
        // A payload that does not decode.
        12 => vec![signed(
            s,
            &alice(),
            raw(MessagingOperation::SetInboxFilter, vec![0xFF; 3]),
        )],
        _ => unreachable!(),
    }
}

/// Execute and, unless it is refused, publish one block, the way a proposer
/// does (see `common::publish_block_returning`), at timestamp `ts`.
fn execute(
    state: &Arc<StateManager>,
    executor: &BlockExecutor,
    height: u64,
    ts: u64,
    txs: Vec<SignedTransaction>,
) -> Outcome {
    let header = BlockHeader::new(Hash::ZERO, height, ts, Hash::ZERO, Hash::ZERO, PROPOSER_PK);
    let mut block = Block::new(header, txs);
    let exec = match executor.execute_block(&block, state.state_root(), &[]) {
        Ok(exec) => exec,
        Err(e) => {
            return Outcome {
                published: None,
                refused: Some(e.to_string()),
            }
        }
    };
    let root = exec.computed_root();
    block.header.state_root = root;
    let (executed, _state_diff, _contract_diff) = exec.into_parts();
    let receipts = executed.receipts().to_vec();
    let accepted = executed.accept_produced(&block).expect("accept_produced");
    let accumulator = accepted.accumulator();
    accepted.publish().expect("publish");
    state.set_state_root(accumulator);
    Outcome {
        published: Some((root, receipts)),
        refused: None,
    }
}

/// The whole history under `params`, one outcome per block.
fn history(params: ChainParams) -> Vec<Outcome> {
    let (state, db, _dir, executor) = setup_with_params(params);
    for kp in everyone() {
        fund(&db, &kp, FUNDS);
    }
    let mut payment = Hash::ZERO;
    (1..=BLOCKS)
        .map(|height| {
            let txs = block_at(height, &state, &mut payment);
            execute(&state, &executor, height, T_MS + height * MINUTE_MS, txs)
        })
        .collect()
}

/// Each block's outcome, hashed: what the pins hold.
fn digests(outcomes: &[Outcome]) -> Vec<String> {
    outcomes
        .iter()
        .zip(1u64..)
        .map(|(o, h)| Hash::hash(o.line(h).as_bytes()).to_string())
        .collect()
}

// ── pins from before either gate existed ────────────────────────────────────
//
// Produced by compiling everything above this line, unchanged, as a test of
// `sumchain-state` on that commit, with `print_pins` below printing
// `digests(&history(base()))`. Never edited by hand.

/// Every gate absent.
const PINNED: [&str; BLOCKS as usize] = [
    "0x48ad6904e23d18d14ded58712c42b0ca65d8e766df6a33d28e2b0a6a1b7c4b14",
    "0x059f515136f1ae6bce5434a0128ac39667de9cfc063d6fdf5706c3beaa3758a3",
    "0xff74744a7496fd31be415967ccfc00b84bb0754cb65d64379a1ea1e10c45566c",
    "0x1eba0d67cf43da73cc6c8a38fd4dd062c03a9ea29b0fba44e8060d1eedb35090",
    "0x29109484c431da88040bdcc5ef50524ecc36ede6a6121851e9198f7d4fbccbc8",
    "0x8a40e5d688c9b652fbfde543df79b7a8f21b5653c4914912830fb9fd14bb76fa",
    "0x52a5ae7497c26e6e32e3511ae19140f259391ee2e493c624a837f11d28ab0a83",
    "0x2831582f464bbefbd1c3f7e810aaa6e888908589c594b5369edf6703f0c5a794",
    "0x9ee8d17a760f6622a49e6a9c417980b0d3815875f502c0de28836924c0e08248",
    "0x8c76acaea4b2a52c0683817c78c4f949d52abe1b03b161c49755409210d75a6a",
    "0xfa3222d9b072df5fddea999fee7615ca2182b126725007f0c0a3b2b9ec664f3f",
    "0xb651bb27f3f6b7cc966dafd9f7d562669ec72f16264f1071c1f25b604ca1acc5",
];

#[test]
#[ignore = "reporting aid: prints the digests the pins hold"]
fn print_pins() {
    let outcomes = history(base());
    for (o, h) in outcomes.iter().zip(1u64..) {
        println!("{}", o.line(h));
    }
    for d in digests(&outcomes) {
        println!("    \"{d}\",");
    }
}

/// The fixture exercises what it says: every block but the last is published,
/// the last is refused, and the receipts cover every generic messaging
/// operation succeeding and, where the operation has a refusing path, refused.
#[test]
fn the_history_covers_every_operation_both_ways() {
    use sumchain_primitives::TxStatus;
    let outcomes = history(base());
    assert_eq!(outcomes.len(), BLOCKS as usize);
    for (o, h) in outcomes.iter().zip(1u64..) {
        if h == BLOCKS {
            assert!(o.refused.is_some(), "block {h} is the undecodable payload");
        } else {
            assert!(o.published.is_some(), "block {h}: {:?}", o.refused);
        }
    }
    let statuses: Vec<Vec<TxStatus>> = outcomes
        .iter()
        .filter_map(|o| o.published.as_ref())
        .map(|(_, r)| r.iter().map(|r| r.status.clone()).collect())
        .collect();
    let ok = TxStatus::Success;
    let no = TxStatus::Failed(7);
    assert_eq!(
        statuses,
        vec![
            vec![ok.clone(), ok.clone(), ok.clone(), no.clone(), ok.clone()],
            vec![ok.clone(), ok.clone(), no.clone(), ok.clone(), no.clone()],
            vec![ok.clone(), ok.clone(), no.clone()],
            vec![ok.clone(), no.clone(), no.clone()],
            vec![ok.clone(), no.clone(), ok.clone(), no.clone()],
            vec![ok.clone(), no.clone(), ok.clone(), ok.clone()],
            vec![ok.clone(), ok.clone(), ok.clone(), no.clone(), ok.clone()],
            vec![ok.clone(), no.clone(), ok.clone(), ok.clone()],
            vec![ok.clone(), no.clone(), ok.clone(), no.clone(), ok.clone()],
            vec![no.clone(), no.clone(), ok.clone()],
            vec![no.clone(), ok.clone()],
        ],
    );
}

/// With every gate absent, the history is the pinned one, block for block.
#[test]
fn with_every_gate_absent_the_history_is_pinned() {
    assert_eq!(digests(&history(base())), PINNED);
}

// ── the sponsored-envelope verification gate ────────────────────────────────

/// `base()` with the envelope gate at `h`.
fn with_envelope_gate(h: Option<u64>) -> ChainParams {
    let mut p = base();
    p.messaging_sponsored_envelope_verification_enabled_from_height = h;
    p
}

/// `base()` with both block-timestamp gates open from genesis, so the
/// messaging rules read whole seconds and an expiry can pass.
fn with_clock_open(mut p: ChainParams) -> ChainParams {
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
    p.messaging_timestamp_units_enabled_from_height = Some(0);
    p
}

/// `m`, signed by `signer` over the version-2 preimage for `chain_id`.
fn signed_v2(mut m: SponsoredMessage, signer: &KeyPair, chain_id: u64) -> SponsoredMessage {
    let preimage = sumchain_primitives::sponsored_send_v2_signing_preimage(chain_id, &m);
    m.signature = *sign(&preimage, signer.private_key()).as_bytes();
    m
}

/// `m`, signed by `signer` over the string form the relay checked before the
/// gate (`SUMCHAIN_SPONSORED_MSG:{nonce}:{expiry}:{recipient hex}:{data hash}`).
fn signed_v1(mut m: SponsoredMessage, signer: &KeyPair) -> SponsoredMessage {
    let preimage = format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        m.nonce,
        m.expiry,
        hex::encode(m.recipient_hash),
        hex::encode(blake3::hash(&m.message_data).as_bytes())
    );
    m.signature = *sign(preimage.as_bytes(), signer.private_key()).as_bytes();
    m
}

/// Carol's envelope to bob at `nonce`, unsigned, never expiring, no amount.
fn carol_to_bob(nonce: u64) -> SponsoredMessage {
    envelope(&carol(), &bob().address(), nonce, NEVER, None, [0u8; 64])
}

/// A chain under test, executed block by block through the producing path,
/// one block per call, at consecutive heights.
struct Chain {
    state: Arc<StateManager>,
    db: Arc<sumchain_storage::Database>,
    dir: tempfile::TempDir,
    exec: BlockExecutor,
    params: ChainParams,
    height: u64,
}

impl Chain {
    fn new(params: ChainParams) -> Self {
        let (state, db, dir, exec) = setup_with_params(params.clone());
        for kp in everyone() {
            fund(&db, &kp, FUNDS);
        }
        Self {
            state,
            db,
            dir,
            exec,
            params,
            height: 0,
        }
    }

    /// Execute and publish the next block. `Err` is the block's refusal; a
    /// refused block is not published and the height stays.
    fn block(&mut self, txs: Vec<SignedTransaction>) -> Result<Vec<Receipt>, String> {
        let height = self.height + 1;
        let ts = T_MS + height * MINUTE_MS;
        let o = execute(&self.state, &self.exec, height, ts, txs);
        match (o.published, o.refused) {
            (Some((_, receipts)), None) => {
                self.height = height;
                Ok(receipts)
            }
            (None, Some(e)) => Err(e),
            _ => unreachable!(),
        }
    }

    /// One transaction in one block; panics unless the block is published.
    fn one(&mut self, tx: SignedTransaction) -> Receipt {
        let mut r = self.block(vec![tx]).expect("block published");
        assert_eq!(r.len(), 1);
        r.remove(0)
    }

    /// The next block's timestamp, in the whole seconds the rules read with
    /// the clock gates open.
    fn next_second(&self) -> u64 {
        (T_MS + (self.height + 1) * MINUTE_MS) / 1000
    }

    fn nonce(&self, kp: &KeyPair) -> u64 {
        self.state.get_nonce(&kp.address()).unwrap()
    }
    fn balance(&self, a: &Address) -> u128 {
        self.state.get_balance(a).unwrap()
    }
    fn store(&self) -> sumchain_storage::MessagingStore<'_> {
        sumchain_storage::MessagingStore::new(&self.db)
    }
    fn msg_nonce(&self, a: &Address) -> u64 {
        self.store().get_sender_nonce(a).unwrap()
    }
    fn daily(&self, a: &Address, day: u32) -> u32 {
        self.store().get_daily_message_count(a, day).unwrap()
    }
    fn sent_by(&self, a: &Address) -> Vec<sumchain_primitives::MessageEvent> {
        self.store().get_messages_by_sender(a, 1000, 0).unwrap()
    }

    /// `kp` signs `data` at its committed account nonce.
    fn tx(&self, kp: &KeyPair, data: MessagingTxData) -> SignedTransaction {
        signed_at(kp, self.nonce(kp), data)
    }

    /// Block 1: the admin enables sponsorship; carol, alice and bob register.
    fn setup(&mut self) {
        let txs = vec![
            self.tx(
                &admin(),
                op(
                    MessagingOperation::SetSponsorshipEnabled,
                    &SetSponsorshipEnabledData { enabled: true },
                ),
            ),
            self.tx(&carol(), register(&carol())),
            self.tx(&alice(), register(&alice())),
            self.tx(&bob(), register(&bob())),
        ];
        let receipts = self.block(txs).expect("setup block");
        assert!(
            receipts
                .iter()
                .all(|r| r.status == sumchain_primitives::TxStatus::Success),
            "{receipts:?}"
        );
        assert!(self.store().is_sponsorship_enabled().unwrap());
    }

    /// Close every handle and reopen the database, as a restarted node does.
    fn restart(self) -> Self {
        let Chain {
            state,
            db,
            dir,
            exec,
            params,
            height,
        } = self;
        drop(exec);
        drop(state);
        drop(db);
        let (state, db, exec) = common::reopen(&dir, params.clone());
        Chain {
            state,
            db,
            dir,
            exec,
            params,
            height,
        }
    }
}

/// The pinned history again, with the envelope gate set ABOVE it: unchanged,
/// block for block.
#[test]
fn with_the_envelope_gate_above_the_history_it_is_pinned() {
    for h in [BLOCKS + 1, 1_000_000, u64::MAX] {
        assert_eq!(
            digests(&history(with_envelope_gate(Some(h)))),
            PINNED,
            "gate at {h}"
        );
    }
}

/// The envelope gate inside the history, at block 3, where the relayed
/// envelopes without a version-2 signature are: blocks 1 and 2 are the pinned
/// ones to the byte, and block 3 differs, every envelope in it refused.
#[test]
fn with_the_envelope_gate_inside_the_history_only_blocks_from_it_change() {
    use sumchain_primitives::TxStatus;
    let outcomes = history(with_envelope_gate(Some(3)));
    let d = digests(&outcomes);
    assert_eq!(d[..2], PINNED[..2], "below the gate: history");
    assert_ne!(d[2], PINNED[2], "at the gate: the envelope rule");
    let (_, receipts) = outcomes[2].published.as_ref().expect("published");
    assert_eq!(
        receipts
            .iter()
            .map(|r| r.status.clone())
            .collect::<Vec<_>>(),
        vec![
            TxStatus::Failed(7),
            TxStatus::Failed(7),
            TxStatus::Failed(7)
        ]
    );
}

/// The gate is closed below its height and open from it, and closed at every
/// height while absent.
#[test]
fn the_envelope_gate_opens_exactly_at_its_height() {
    use sumchain_state::MessagingExecutor;
    const H: u64 = 1_000;
    let set = with_envelope_gate(Some(H));
    assert!(!MessagingExecutor::sponsored_envelope_verification_gate_open(&set, 0));
    assert!(!MessagingExecutor::sponsored_envelope_verification_gate_open(&set, H - 1));
    assert!(MessagingExecutor::sponsored_envelope_verification_gate_open(&set, H));
    assert!(MessagingExecutor::sponsored_envelope_verification_gate_open(&set, H + 1));
    assert!(MessagingExecutor::sponsored_envelope_verification_gate_open(&set, u64::MAX));
    let absent = with_envelope_gate(None);
    for h in [0, 1, H - 1, H, H + 1, u64::MAX] {
        assert!(!MessagingExecutor::sponsored_envelope_verification_gate_open(&absent, h));
    }
}

/// At the gate, carol's version-2 envelope relayed by the sponsor is accepted
/// once: the event is stored under carol, reporting no payment, and her
/// messaging nonce and daily count move. The same envelope again is refused,
/// stores nothing and moves nothing; the next nonce is accepted.
#[test]
fn at_the_gate_a_v2_envelope_is_accepted_once_and_its_replay_refused() {
    use sumchain_primitives::TxStatus;
    let mut c = Chain::new(with_envelope_gate(Some(2)));
    c.setup();
    let carol_addr = carol().address();
    let first = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);

    let tx = c.tx(&sponsor(), sponsored(&first));
    let r = c.one(tx.clone());
    assert_eq!(r.status, TxStatus::Success);
    let events = c.sent_by(&carol_addr);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sender, carol_addr);
    assert_eq!(events[0].message_id, tx.hash());
    assert!(!events[0].has_payment);
    assert_eq!(c.msg_nonce(&carol_addr), 1);
    assert_eq!(c.daily(&carol_addr, 0), 1);

    // The identical envelope, relayed again by the same sponsor and by another.
    for (label, relayer) in [("the same sponsor", sponsor()), ("another relayer", erin())] {
        let r = c.one(c.tx(&relayer, sponsored(&first)));
        assert_eq!(r.status, TxStatus::Failed(7), "{label}");
        assert_eq!(c.sent_by(&carol_addr).len(), 1, "{label}");
        assert_eq!(c.msg_nonce(&carol_addr), 1, "{label}");
        assert_eq!(c.daily(&carol_addr, 0), 1, "{label}");
    }

    let second = signed_v2(carol_to_bob(1), &carol(), CHAIN_ID);
    let r = c.one(c.tx(&erin(), sponsored(&second)));
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.sent_by(&carol_addr).len(), 2);
    assert_eq!(c.msg_nonce(&carol_addr), 2);
}

/// At the gate, every bound field is checked: an envelope signed for another
/// chain, or whose recipient, content, nonce or amount differ from what was
/// signed, or carrying an amount at all, or signed by another key, with no
/// signature, over the pre-gate string form, by a small-order key the legacy
/// rule would accept, or naming an unregistered sender, is refused as an
/// ordinary failed operation that stores nothing and moves no counter. A
/// correct envelope then still passes.
#[test]
fn at_the_gate_every_bound_field_is_checked() {
    use sumchain_primitives::TxStatus;
    let mut c = Chain::new(with_envelope_gate(Some(2)));
    c.setup();
    let carol_addr = carol().address();

    let cases: Vec<(&str, SponsoredMessage, &str)> = vec![
        (
            "signed for another chain",
            signed_v2(carol_to_bob(0), &carol(), CHAIN_ID + 1),
            "Invalid sponsored message signature",
        ),
        (
            "recipient changed after signing",
            {
                let mut m = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);
                m.recipient_hash = recipient_hash(&alice().address());
                m
            },
            "Invalid sponsored message signature",
        ),
        (
            "content changed after signing",
            {
                let mut m = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);
                m.message_data = valid_message(recipient_hash(&alice().address()));
                m
            },
            "Invalid sponsored message signature",
        ),
        (
            "nonce changed after signing",
            {
                let mut m = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);
                m.nonce = 1;
                m
            },
            "Invalid sponsored message signature",
        ),
        (
            "expiry changed after signing",
            {
                let mut m = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);
                m.expiry = NEVER - 1;
                m
            },
            "Invalid sponsored message signature",
        ),
        (
            "amount changed after signing",
            {
                let mut m = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);
                m.koppa_amount = Some(5_000);
                m
            },
            "Sponsored message carries an amount",
        ),
        (
            "an amount, properly signed",
            signed_v2(
                envelope(&carol(), &bob().address(), 0, NEVER, Some(5_000), [0u8; 64]),
                &carol(),
                CHAIN_ID,
            ),
            "Sponsored message carries an amount",
        ),
        (
            "a nonce that is not the sender's current one",
            signed_v2(carol_to_bob(1), &carol(), CHAIN_ID),
            "Sponsored message nonce 1 is not the sender's current nonce 0",
        ),
        (
            "signed by another key",
            signed_v2(carol_to_bob(0), &dave(), CHAIN_ID),
            "Invalid sponsored message signature",
        ),
        (
            "no signature",
            carol_to_bob(0),
            "Invalid sponsored message signature",
        ),
        (
            "signed over the pre-gate string form",
            signed_v1(carol_to_bob(0), &carol()),
            "Invalid sponsored message signature",
        ),
        (
            "a sender key that is not a curve point",
            {
                let mut m = carol_to_bob(0);
                m.sender_pubkey = [0x02; 32];
                m
            },
            "Invalid sponsored message sender key",
        ),
        (
            "an unregistered sender, properly signed",
            signed_v2(
                envelope(&dave(), &bob().address(), 0, NEVER, None, [0u8; 64]),
                &dave(),
                CHAIN_ID,
            ),
            "Sender must register public key first",
        ),
    ];
    for (label, m, _why) in &cases {
        let r = c.one(c.tx(&sponsor(), sponsored(m)));
        assert_eq!(r.status, TxStatus::Failed(7), "{label}");
        assert!(c.sent_by(&carol_addr).is_empty(), "{label}: nothing stored");
        assert_eq!(c.msg_nonce(&carol_addr), 0, "{label}: nonce unmoved");
        assert_eq!(c.daily(&carol_addr, 0), 0, "{label}: quota unmoved");
        assert!(
            c.sent_by(&Address::from_public_key(&m.sender_pubkey))
                .is_empty(),
            "{label}: nothing stored under the named key"
        );
    }
    // The executor's reasons, read through the executor directly on the
    // candidate so the text is asserted as well as the receipt.
    {
        use sumchain_state::MessagingExecutor;
        let mut cand = common::candidate(&c.db);
        let mut view = cand.view();
        for (label, m, why) in &cases {
            let r = MessagingExecutor::execute(
                &mut view,
                &c.params,
                CHAIN_ID,
                &sponsor().address(),
                &sponsored(m),
                &Address::from_public_key(&PROPOSER_PK),
                FEE,
                c.height + 1,
                T_MS,
                0,
                Hash::hash(label.as_bytes()),
            )
            .unwrap();
            assert!(!r.success, "{label}");
            assert_eq!(r.error.as_deref(), Some(*why), "{label}");
        }
    }
    let r = c.one(c.tx(
        &sponsor(),
        sponsored(&signed_v2(carol_to_bob(0), &carol(), CHAIN_ID)),
    ));
    assert_eq!(
        r.status,
        TxStatus::Success,
        "a correct envelope still passes"
    );
    assert_eq!(c.msg_nonce(&carol_addr), 1);
}

/// With the clock gates open the expiry is compared against the block's
/// second: an envelope expiring the second before the block is refused, one
/// expiring at the block's second is accepted. With them closed the clock
/// reads zero and no expiry passes, as before.
#[test]
fn at_the_gate_the_expiry_is_checked_against_the_rule_clock() {
    use sumchain_primitives::TxStatus;
    let mut c = Chain::new(with_clock_open(with_envelope_gate(Some(2))));
    c.setup();
    let carol_addr = carol().address();
    let at = c.next_second();
    let stale = signed_v2(
        envelope(&carol(), &bob().address(), 0, at - 1, None, [0u8; 64]),
        &carol(),
        CHAIN_ID,
    );
    let r = c.one(c.tx(&sponsor(), sponsored(&stale)));
    assert_eq!(r.status, TxStatus::Failed(7));
    assert_eq!(c.msg_nonce(&carol_addr), 0);
    let at = c.next_second();
    let fresh = signed_v2(
        envelope(&carol(), &bob().address(), 0, at, None, [0u8; 64]),
        &carol(),
        CHAIN_ID,
    );
    let r = c.one(c.tx(&sponsor(), sponsored(&fresh)));
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.msg_nonce(&carol_addr), 1);

    let mut closed = Chain::new(with_envelope_gate(Some(2)));
    closed.setup();
    let r = closed.one(closed.tx(
        &sponsor(),
        sponsored(&signed_v2(
            envelope(&carol(), &bob().address(), 0, 1, None, [0u8; 64]),
            &carol(),
            CHAIN_ID,
        )),
    ));
    assert_eq!(r.status, TxStatus::Success, "the clock reads zero");
}

/// Below the gate an envelope executes under the earlier rule. At H-2 an
/// envelope without a version-2 signature, at a nonce outside the sender's
/// sequence, executes; at H-1 one signed over the string form executes; at H
/// the same two forms are refused and a version-2 envelope at the sender's
/// current nonce is accepted; at H+1 the next nonce is accepted and a second
/// use of an envelope is refused.
#[test]
fn below_the_gate_the_envelope_executes_as_before_and_from_it_the_rule_applies() {
    use sumchain_primitives::TxStatus;
    const H: u64 = 4;
    let mut c = Chain::new(with_envelope_gate(Some(H)));
    c.setup();
    let carol_addr = carol().address();

    // H-2
    let r = c.one(c.tx(&sponsor(), sponsored(&carol_to_bob(7))));
    assert_eq!((c.height, r.status), (H - 2, TxStatus::Success));
    assert_eq!(c.msg_nonce(&carol_addr), 1);
    // H-1
    let r = c.one(c.tx(&sponsor(), sponsored(&signed_v1(carol_to_bob(0), &carol()))));
    assert_eq!((c.height, r.status), (H - 1, TxStatus::Success));
    assert_eq!(c.msg_nonce(&carol_addr), 2);
    // H
    let receipts = c
        .block(vec![
            c.tx(&sponsor(), sponsored(&carol_to_bob(2))),
            c.tx(&erin(), sponsored(&signed_v1(carol_to_bob(2), &carol()))),
            c.tx(
                &frank(),
                sponsored(&signed_v2(carol_to_bob(2), &carol(), CHAIN_ID)),
            ),
        ])
        .unwrap();
    assert_eq!(c.height, H);
    assert_eq!(
        receipts
            .iter()
            .map(|r| r.status.clone())
            .collect::<Vec<_>>(),
        vec![TxStatus::Failed(7), TxStatus::Failed(7), TxStatus::Success]
    );
    assert_eq!(c.msg_nonce(&carol_addr), 3);
    // H+1
    let receipts = c
        .block(vec![
            c.tx(
                &sponsor(),
                sponsored(&signed_v2(carol_to_bob(3), &carol(), CHAIN_ID)),
            ),
            c.tx(
                &erin(),
                sponsored(&signed_v2(carol_to_bob(2), &carol(), CHAIN_ID)),
            ),
        ])
        .unwrap();
    assert_eq!(c.height, H + 1);
    assert_eq!(
        receipts
            .iter()
            .map(|r| r.status.clone())
            .collect::<Vec<_>>(),
        vec![TxStatus::Success, TxStatus::Failed(7)]
    );
    assert_eq!(c.msg_nonce(&carol_addr), 4);
    assert_eq!(c.sent_by(&carol_addr).len(), 4);
}

/// Two envelopes from one sender in one block: in nonce order both are
/// accepted, the second seeing the first's increment on the candidate. In the
/// other order the first is refused and the second accepted, and the refused
/// one is accepted in the next block, when its nonce has come up.
#[test]
fn two_envelopes_from_one_sender_in_one_block_follow_the_nonce_order() {
    use sumchain_primitives::TxStatus;
    let carol_addr = carol().address();
    let n0 = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);
    let n1 = signed_v2(carol_to_bob(1), &carol(), CHAIN_ID);

    let mut c = Chain::new(with_envelope_gate(Some(2)));
    c.setup();
    let receipts = c
        .block(vec![
            c.tx(&sponsor(), sponsored(&n0)),
            c.tx(&erin(), sponsored(&n1)),
        ])
        .unwrap();
    assert_eq!(
        receipts
            .iter()
            .map(|r| r.status.clone())
            .collect::<Vec<_>>(),
        vec![TxStatus::Success, TxStatus::Success]
    );
    assert_eq!(c.msg_nonce(&carol_addr), 2);
    assert_eq!(c.daily(&carol_addr, 0), 2);
    // Below `subsystem_tx_index_enabled_from_height` every event row of a
    // block is keyed by index 0, so the second event overwrites the first:
    // unchanged by this rule, and not what it decides.
    assert_eq!(c.sent_by(&carol_addr).len(), 1);

    let mut c = Chain::new(with_envelope_gate(Some(2)));
    c.setup();
    let receipts = c
        .block(vec![
            c.tx(&sponsor(), sponsored(&n1)),
            c.tx(&erin(), sponsored(&n0)),
        ])
        .unwrap();
    assert_eq!(
        receipts
            .iter()
            .map(|r| r.status.clone())
            .collect::<Vec<_>>(),
        vec![TxStatus::Failed(7), TxStatus::Success]
    );
    assert_eq!(c.msg_nonce(&carol_addr), 1);
    let r = c.one(c.tx(&sponsor(), sponsored(&n1)));
    assert_eq!(r.status, TxStatus::Success);
    assert_eq!(c.msg_nonce(&carol_addr), 2);
}

/// A restart keeps the accepted nonce: after the database is closed and
/// reopened, the replay is still refused and the next nonce accepted.
#[test]
fn a_restart_keeps_the_accepted_envelope_nonce() {
    use sumchain_primitives::TxStatus;
    let carol_addr = carol().address();
    let n0 = signed_v2(carol_to_bob(0), &carol(), CHAIN_ID);
    let n1 = signed_v2(carol_to_bob(1), &carol(), CHAIN_ID);
    let mut c = Chain::new(with_envelope_gate(Some(2)));
    c.setup();
    assert_eq!(
        c.one(c.tx(&sponsor(), sponsored(&n0))).status,
        TxStatus::Success
    );
    let mut c = c.restart();
    assert_eq!(c.msg_nonce(&carol_addr), 1);
    assert_eq!(
        c.one(c.tx(&erin(), sponsored(&n0))).status,
        TxStatus::Failed(7)
    );
    assert_eq!(
        c.one(c.tx(&sponsor(), sponsored(&n1))).status,
        TxStatus::Success
    );
    assert_eq!(c.msg_nonce(&carol_addr), 2);
}

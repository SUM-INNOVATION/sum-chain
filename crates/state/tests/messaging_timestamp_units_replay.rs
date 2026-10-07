//! #278: blocks executed below `messaging_timestamp_units_enabled_from_height`
//! are executed exactly as the code before the gate existed executes them.
//!
//! A fixed sequence of seven blocks of signed messaging transactions -- quota
//! configuration, sends, a paid message and its claim, sponsored messages --
//! runs through the real block path (`execute_block` -> `accept_produced` ->
//! `publish`), with real millisecond block timestamps that cross the 604.8 s
//! "defect" expiry window, a UTC day and a week. For every block the outcome
//! is recorded: the state root and every receipt, or the refusal of the block.
//!
//! The pinned outcomes below were produced by the same scenario on
//! `origin/main` at 8744d8612a072ad4c24229df2b844cedc6cb5a5a, which has no
//! units gate. They are pinned per block, in the two configurations main can
//! run: both gates closed (today's release configuration) and
//! `subsystem_block_timestamp_enabled_from_height` open (what main does once
//! that gate opens). This branch must reproduce them, to the byte, whenever
//! the units gate is unset or above the replayed heights; and with the units
//! gate inside the sequence it must reproduce every block below it and differ
//! from the block it opens at.

mod common;

use std::sync::Arc;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::messaging::{
    ClaimPaymentData, ContentType, MessageFlags, MessageHeader, MessagingTxData,
    RegisterPublicKeyData, SendMessageData, SendMessageWithPaymentData, SetDailyQuotaData,
    SetSponsorshipEnabledData, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Block, BlockHeader, Hash, MessagingOperation, Receipt, SignedTransaction, SponsoredMessage,
    TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;

/// 2025-10-09T08:53:20Z, in milliseconds.
const T_MS: u64 = 1_760_000_000_000;
const SECOND_MS: u64 = 1_000;
const MINUTE_MS: u64 = 60 * SECOND_MS;
const DAY_MS: u64 = 86_400 * SECOND_MS;
/// Blocks in the sequence, at heights 1..=BLOCKS.
const BLOCKS: u64 = 7;

fn admin() -> KeyPair {
    KeyPair::from_bytes([0x21; 32])
}
fn alice() -> KeyPair {
    KeyPair::from_bytes([0x22; 32])
}
fn bob() -> KeyPair {
    KeyPair::from_bytes([0x23; 32])
}
/// The real sender of the sponsored messages.
fn carol() -> KeyPair {
    KeyPair::from_bytes([0x24; 32])
}
fn sponsor() -> KeyPair {
    KeyPair::from_bytes([0x25; 32])
}

/// Both gates closed, `admin` as the messaging registry admin.
fn base() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        ..MessagingParams::default()
    });
    p
}

/// The block-timestamp gate open from genesis.
fn timestamp_open() -> ChainParams {
    let mut p = base();
    p.subsystem_block_timestamp_enabled_from_height = Some(0);
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

fn msg(op: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation: op,
        data: bincode::serialize(payload).unwrap(),
    }
}

/// `kp` signs `data` at its committed account nonce. One transaction per
/// signer per block, so the committed nonce is the one the block expects.
fn signed(state: &StateManager, kp: &KeyPair, data: MessagingTxData) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce: state.get_nonce(&kp.address()).unwrap(),
        payload: TxPayload::Messaging(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn direct_to_bob() -> MessagingTxData {
    let rh = recipient_hash(&bob().address());
    msg(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: valid_message(rh),
            recipient_hash: rh,
        },
    )
}

/// Carol's message to bob, relayed by the sponsor, expiring at `expiry`
/// (client-signed Unix seconds).
fn sponsored_by_carol(nonce: u64, expiry: u64) -> MessagingTxData {
    let rh = recipient_hash(&bob().address());
    msg(
        MessagingOperation::SendMessage,
        &SponsoredMessage {
            message_data: valid_message(rh),
            recipient_hash: rh,
            signature: [0u8; 64],
            sender_pubkey: *carol().public_key().as_bytes(),
            nonce,
            expiry,
            koppa_amount: None,
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

/// The block at `height`: its timestamp and transactions. `payment` is the
/// paid message's id, set by block 2 and claimed by block 5.
fn block_at(
    height: u64,
    state: &StateManager,
    payment: &mut Hash,
) -> (u64, Vec<SignedTransaction>) {
    match height {
        // Quota of two per day; carol registers the key her sponsored
        // messages name; alice's first message of the day.
        1 => (
            T_MS,
            vec![
                signed(
                    state,
                    &admin(),
                    msg(
                        MessagingOperation::SetDailyQuota,
                        &SetDailyQuotaData { quota: 2 },
                    ),
                ),
                signed(
                    state,
                    &carol(),
                    msg(
                        MessagingOperation::RegisterPublicKey,
                        &RegisterPublicKeyData {
                            public_key: *carol().public_key().as_bytes(),
                        },
                    ),
                ),
                signed(state, &alice(), direct_to_bob()),
            ],
        ),
        // Sponsorship on; alice's second message of the day carries a payment.
        2 => {
            let rh = recipient_hash(&bob().address());
            let pay = signed(
                state,
                &alice(),
                msg(
                    MessagingOperation::SendMessageWithPayment,
                    &SendMessageWithPaymentData {
                        message_data: valid_message(rh),
                        recipient_hash: rh,
                        koppa_amount: 500,
                    },
                ),
            );
            *payment = pay.hash();
            (
                T_MS + MINUTE_MS,
                vec![
                    signed(
                        state,
                        &admin(),
                        msg(
                            MessagingOperation::SetSponsorshipEnabled,
                            &SetSponsorshipEnabledData { enabled: true },
                        ),
                    ),
                    pay,
                ],
            )
        }
        // A sponsored message expiring an hour from now, in Unix seconds.
        3 => (
            T_MS + 2 * MINUTE_MS,
            vec![signed(
                state,
                &sponsor(),
                sponsored_by_carol(0, T_MS / 1000 + 3600),
            )],
        ),
        // Alice's third message, the same UTC day.
        4 => (
            T_MS + 3 * MINUTE_MS,
            vec![signed(state, &alice(), direct_to_bob())],
        ),
        // Bob claims, twelve minutes after the payment.
        5 => (
            T_MS + 13 * MINUTE_MS,
            vec![signed(
                state,
                &bob(),
                msg(
                    MessagingOperation::ClaimPayment,
                    &ClaimPaymentData {
                        message_id: *payment,
                        recipient_address: bob().address(),
                    },
                ),
            )],
        ),
        // Alice again, the next UTC day.
        6 => (
            T_MS + DAY_MS + SECOND_MS,
            vec![signed(state, &alice(), direct_to_bob())],
        ),
        // A week on, a sponsored message that expired at Unix second 1.
        7 => (
            T_MS + 8 * DAY_MS,
            vec![signed(state, &sponsor(), sponsored_by_carol(1, 1))],
        ),
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
    let header = BlockHeader::new(Hash::ZERO, height, ts, Hash::ZERO, Hash::ZERO, [0x77; 32]);
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

/// The whole sequence under `params`, one outcome per block.
fn replay(params: ChainParams) -> Vec<Outcome> {
    let (state, db, _dir, executor) = setup_with_params(params);
    for kp in [admin(), alice(), bob(), carol(), sponsor()] {
        fund(&db, &kp, 1_000_000_000);
    }
    let mut payment = Hash::ZERO;
    (1..=BLOCKS)
        .map(|height| {
            let (ts, txs) = block_at(height, &state, &mut payment);
            execute(&state, &executor, height, ts, txs)
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

// ── pins from origin/main 8744d8612a072ad4c24229df2b844cedc6cb5a5a ──────────
//
// Produced by compiling everything above this line, unchanged, as a test of
// `sumchain-state` on that commit, with one test printing `digests(&replay(..))`
// for `base()` and `timestamp_open()`. Never edited by hand.

/// Both gates closed.
const MAIN_DORMANT: [&str; BLOCKS as usize] = [
    "0x63959ffe20076c8b829b38a797c89e05877f5a92d3ac7acd4de5b3663fc20a55",
    "0x6eae0e58f232f11e7483e17eafd5f061368c06c5826c84740bcf6e604b1b1998",
    "0xfccb9018cc33bac39e8de77a1f72180e89eb959c22e52b81ae472f3f6fdc4f07",
    "0x961a03f50a13954a99cddbcf12ec6d00ec6eb905329417cbb72e51accda0cb8c",
    "0xee88bf59992e03cab86972153f6d434d20ff6494deaee28e5ee2adaa6a676916",
    "0xa51f6fdeb0ecb4c394fae17efc004829a999e0ba2977ce364b8a337701085bbe",
    "0x4da30077a425d527ad642a0c3d5793690a1f47355d36c0aed9df9653f0f13ab4",
];
/// `subsystem_block_timestamp_enabled_from_height = Some(0)`.
const MAIN_TIMESTAMP_OPEN: [&str; BLOCKS as usize] = [
    "0x63959ffe20076c8b829b38a797c89e05877f5a92d3ac7acd4de5b3663fc20a55",
    "0x6eae0e58f232f11e7483e17eafd5f061368c06c5826c84740bcf6e604b1b1998",
    "0x82e442cfcc196d171621b4f3b9a37c5e9854576885bc9dcb8d0371f3430402de",
    "0xd0033ba0dfa29f21add52cdcf109f4af89a81bfddbd9524e80589c18940c4b4b",
    "0x5c34563af373615601b351b43a2452ff4a9d08dcf20af19e8570f2f2e9c72f11",
    "0xdcf8351770c5edf813500f5dc221b3fd9b2ec915dcc2d4e4331b55aabc8fbe04",
    "0xf181f0874b3ff78dbc88ba22bcb3a80e27839c7fa59c383e9a00c504d253e358",
];

fn with_units(mut p: ChainParams, h: Option<u64>) -> ChainParams {
    p.messaging_timestamp_units_enabled_from_height = h;
    p
}

fn status(o: &Outcome) -> Vec<TxStatus> {
    o.published
        .as_ref()
        .map(|(_, r)| r.iter().map(|r| r.status.clone()).collect())
        .unwrap_or_default()
}

/// The fixture is sensitive: main itself executes the two configurations
/// differently (the defect is visible in main's own outcomes).
#[test]
fn the_main_pins_tell_the_configurations_apart() {
    assert_ne!(MAIN_DORMANT, MAIN_TIMESTAMP_OPEN);
}

/// Units gate unset, or set above every replayed height: both closed-gate
/// sequences are main's, block for block.
#[test]
fn below_the_units_gate_a_dormant_chain_replays_as_main() {
    for units in [None, Some(BLOCKS + 1), Some(1_000_000), Some(u64::MAX)] {
        assert_eq!(
            digests(&replay(with_units(base(), units))),
            MAIN_DORMANT,
            "units gate {units:?}"
        );
    }
}

/// The same with the block-timestamp gate open: main's (defective) outcomes,
/// reproduced exactly, because those blocks are history.
#[test]
fn below_the_units_gate_a_timestamp_open_chain_replays_as_main() {
    for units in [None, Some(BLOCKS + 1), Some(u64::MAX)] {
        assert_eq!(
            digests(&replay(with_units(timestamp_open(), units))),
            MAIN_TIMESTAMP_OPEN,
            "units gate {units:?}"
        );
    }
}

/// The units gate inside the sequence, at block 5: blocks 1-4 are main's to
/// the byte, and block 5 -- the claim twelve minutes after the payment, which
/// main refunds as expired -- now pays bob.
#[test]
fn activation_inside_the_sequence_changes_only_blocks_at_and_above_it() {
    let main_like = replay(timestamp_open());
    let activated = replay(with_units(timestamp_open(), Some(5)));
    let d = digests(&activated);
    assert_eq!(d[..4], MAIN_TIMESTAMP_OPEN[..4], "below the gate: history");
    assert_ne!(
        d[4], MAIN_TIMESTAMP_OPEN[4],
        "at the gate: the corrected rule"
    );
    assert_eq!(
        status(&main_like[4]),
        vec![TxStatus::Failed(7)],
        "main: expired"
    );
    assert_eq!(status(&activated[4]), vec![TxStatus::Success], "gate: paid");
}

/// Both gates open from genesis: the three corrected rules, at block level.
#[test]
fn with_both_gates_open_the_sequence_follows_seconds() {
    let o = replay(with_units(timestamp_open(), Some(0)));
    let defect = replay(timestamp_open());

    // Block 4, alice's third message of the day: main admits it (a new
    // 86.4 s "day"); corrected, the quota of two refuses the block.
    assert!(defect[3].published.is_some(), "{:?}", defect[3]);
    let refused = o[3].refused.as_deref().expect("quota refuses block 4");
    assert!(refused.contains("Daily quota exceeded"), "{refused}");

    // Block 3, a sponsored message an hour ahead in seconds: main finds it
    // already expired; corrected, it is accepted.
    assert_eq!(status(&defect[2]), vec![TxStatus::Failed(7)]);
    assert_eq!(status(&o[2]), vec![TxStatus::Success]);

    // Block 5, the claim twelve minutes on: paid.
    assert_eq!(status(&o[4]), vec![TxStatus::Success]);

    // Block 6, the next UTC day: the quota has reset.
    assert_eq!(status(&o[5]), vec![TxStatus::Success]);

    // Block 7, a sponsored message that expired at Unix second 1: refused.
    assert_eq!(status(&o[6]), vec![TxStatus::Failed(7)]);
}

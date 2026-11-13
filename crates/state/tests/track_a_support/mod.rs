//! Shared fixtures for the messaging accounting suites: a chain executed and published
//! block by block through the real block path, on a chain id of the test's
//! choosing, with every account and messaging row readable for comparison.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use sumchain_crypto::{recipient_hash, sign, KeyPair};
use sumchain_genesis::{ChainParams, MessagingParams};
use sumchain_primitives::messaging::{
    ContentType, MessageFlags, MessageHeader, MessagingTxData, SendMessageData,
    SendMessageWithPaymentData, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
use sumchain_primitives::{
    Address, Block, BlockHeader, Hash, MessagingOperation, Receipt, SignedTransaction,
    SponsoredMessage, TransactionV2, TxPayload,
};
use sumchain_state::executor::{BlockExecutor, ProposalScreening};
use sumchain_state::state::StateManager;
use sumchain_state::StateError;
use sumchain_storage::{cf, Database, MessagingStore};
use tempfile::TempDir;

/// 2025-10-09T08:53:20Z, in milliseconds, as a proposer writes a timestamp.
pub const T_MS: u64 = 1_760_000_000_000;
pub const MINUTE_MS: u64 = 60_000;
pub const FEE: u128 = 100;
/// Enough for the trust-stake minimum (`DEFAULT_MIN_TRUST_STAKE`, 1e11) many
/// times over.
pub const FUNDS: u128 = 1_000_000_000_000_000;
/// An envelope expiry that never passes, in Unix seconds.
pub const NEVER: u64 = u64::MAX;
/// The proposer key every block names.
pub const PROPOSER_PK: [u8; 32] = [0x5B; 32];
/// A chain other than 1: the default for these suites.
pub const CHAIN: u64 = 7;

pub fn key(seed: u8) -> KeyPair {
    KeyPair::from_bytes([seed; 32])
}
/// The messaging registry admin.
pub fn admin() -> KeyPair {
    key(0x61)
}
/// A registered sender who pays her own fees, staked by the setups that need it.
pub fn alice() -> KeyPair {
    key(0x62)
}
/// The recipient.
pub fn bob() -> KeyPair {
    key(0x63)
}
/// A registered sender whose messages are relayed.
pub fn carol() -> KeyPair {
    key(0x64)
}
/// Relays envelopes and pays the outer fee.
pub fn sponsor() -> KeyPair {
    key(0x65)
}
/// Funded, registered by the setups, never the admin.
pub fn dave() -> KeyPair {
    key(0x66)
}
/// A second relayer.
pub fn erin() -> KeyPair {
    key(0x67)
}
/// Another funded account, registered nowhere.
pub fn frank() -> KeyPair {
    key(0x68)
}
pub fn everyone() -> [KeyPair; 8] {
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
pub fn proposer() -> Address {
    Address::from_public_key(&PROPOSER_PK)
}

/// Production's shape: V2 open, `admin` the messaging registry admin, a
/// spam threshold that one report reaches, every other gate closed (so the
/// messaging clock reads zero).
pub fn base() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.messaging = Some(MessagingParams {
        registry_admin: Some(admin().address().to_base58()),
        spam_threshold: 3,
        high_spam_threshold: 5,
        ..MessagingParams::default()
    });
    p
}

/// `base()` with the envelope gate at `envelope` and the accounting gate at
/// `accounting`.
pub fn gates(envelope: Option<u64>, accounting: Option<u64>) -> ChainParams {
    let mut p = base();
    p.messaging_sponsored_envelope_verification_enabled_from_height = envelope;
    p.messaging_fee_nonce_accounting_enabled_from_height = accounting;
    p
}

/// `base()` with both gates at `h`: the only shape genesis admits.
pub fn both(h: Option<u64>) -> ChainParams {
    gates(h, h)
}

pub fn valid_message(rh: [u8; 32]) -> Vec<u8> {
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

pub fn op(operation: MessagingOperation, payload: &impl serde::Serialize) -> MessagingTxData {
    MessagingTxData {
        operation,
        data: bincode::serialize(payload).unwrap(),
    }
}

pub fn raw(operation: MessagingOperation, data: Vec<u8>) -> MessagingTxData {
    MessagingTxData { operation, data }
}

pub fn direct_to(to: &Address) -> MessagingTxData {
    let rh = recipient_hash(to);
    op(
        MessagingOperation::SendMessageDirect,
        &SendMessageData {
            message_data: valid_message(rh),
            recipient_hash: rh,
        },
    )
}

pub fn payment_to(to: &Address, amount: u128) -> MessagingTxData {
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

/// An envelope naming `sender` as the sender of a message to `to`, unsigned.
pub fn envelope(
    sender: &KeyPair,
    to: &Address,
    nonce: u64,
    koppa_amount: Option<u128>,
) -> SponsoredMessage {
    let rh = recipient_hash(to);
    SponsoredMessage {
        message_data: valid_message(rh),
        recipient_hash: rh,
        signature: [0u8; 64],
        sender_pubkey: *sender.public_key().as_bytes(),
        nonce,
        expiry: NEVER,
        koppa_amount,
    }
}

/// `m`, signed by `signer` over the version-2 preimage for `chain_id`.
pub fn signed_v2(mut m: SponsoredMessage, signer: &KeyPair, chain_id: u64) -> SponsoredMessage {
    let preimage = sumchain_primitives::sponsored_send_v2_signing_preimage(chain_id, &m);
    m.signature = *sign(&preimage, signer.private_key()).as_bytes();
    m
}

/// `sender`'s own version-2 envelope to `to` at `nonce`, for `chain_id`.
pub fn v2(
    sender: &KeyPair,
    to: &Address,
    nonce: u64,
    koppa_amount: Option<u128>,
    chain_id: u64,
) -> SponsoredMessage {
    signed_v2(envelope(sender, to, nonce, koppa_amount), sender, chain_id)
}

pub fn sponsored(m: &SponsoredMessage) -> MessagingTxData {
    op(MessagingOperation::SendMessage, m)
}

/// `kp` signs a V2 messaging transaction carrying `data` at `nonce`, with
/// `fee`, for `chain_id`.
pub fn signed_tx(
    kp: &KeyPair,
    chain_id: u64,
    nonce: u64,
    fee: u128,
    data: MessagingTxData,
) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id,
        from: kp.address(),
        fee,
        nonce,
        payload: TxPayload::Messaging(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

/// Every row of the account family and of every messaging family.
pub type Rows = BTreeMap<(String, Vec<u8>), Vec<u8>>;

pub const FAMILIES: &[&str] = &[
    cf::STATE,
    cf::MESSAGING_CONFIG,
    cf::MESSAGING_SENDER_NONCES,
    cf::MESSAGING_DAILY_COUNTS,
    cf::MESSAGING_STAKES,
    cf::MESSAGING_SPAM_SCORES,
    cf::MESSAGING_INBOX_FILTERS,
    cf::MESSAGING_CONTACTS,
    cf::MESSAGING_BLOCKED,
    cf::MESSAGING_PENDING_PAYMENTS,
    cf::MESSAGING_PAYMENTS_BY_RECIPIENT,
    cf::MESSAGING_EVENTS,
    cf::MESSAGING_SENDER_EVENTS,
    cf::MESSAGING_PUBLIC_KEYS,
];

/// The keys whose rows differ between `before` and `after` (added, removed
/// or rewritten), as `(family, key)`.
pub fn changed(before: &Rows, after: &Rows) -> Vec<(String, Vec<u8>)> {
    let mut keys: Vec<_> = before
        .keys()
        .chain(after.keys())
        .filter(|k| before.get(*k) != after.get(*k))
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// The `cf::STATE` key of `a`'s account row.
pub fn account_key(a: &Address) -> (String, Vec<u8>) {
    (
        cf::STATE.to_string(),
        sumchain_storage::StateStore::account_key(a),
    )
}

/// A chain under test, executed block by block through the producing path
/// (`execute_block` -> `accept_produced` -> `publish`), one block per call,
/// at consecutive heights.
pub struct Chain {
    pub state: Arc<StateManager>,
    pub db: Arc<Database>,
    pub dir: TempDir,
    pub exec: BlockExecutor,
    pub params: ChainParams,
    pub chain_id: u64,
    pub height: u64,
    /// A value a test's preparation records for later steps (for example a
    /// paying transaction's hash, which is its escrow's id).
    pub mark: Hash,
    /// The proposer key every later block names (`PROPOSER_PK` unless a test
    /// makes an account the proposer).
    pub proposer_pk: [u8; 32],
    /// Added to every later block's timestamp, so a test can move the clock
    /// past an expiry without producing a week of blocks.
    pub clock_offset_ms: u64,
}

impl Chain {
    pub fn new(params: ChainParams) -> Self {
        Self::on(params, CHAIN)
    }

    pub fn on(params: ChainParams, chain_id: u64) -> Self {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        let exec = BlockExecutor::new(state.clone(), db.clone(), params.clone());
        for kp in everyone() {
            sumchain_storage::StateStore::new(&db)
                .put_account(
                    &kp.address(),
                    &sumchain_storage::schema::AccountState {
                        balance: FUNDS,
                        nonce: 0,
                    },
                )
                .unwrap();
        }
        Self {
            state,
            db,
            dir,
            exec,
            params,
            chain_id,
            height: 0,
            mark: Hash::ZERO,
            proposer_pk: PROPOSER_PK,
            clock_offset_ms: 0,
        }
    }

    fn next_block(&self, txs: Vec<SignedTransaction>) -> Block {
        let height = self.height + 1;
        Block::new(
            BlockHeader::new(
                Hash::ZERO,
                height,
                T_MS + height * MINUTE_MS + self.clock_offset_ms,
                Hash::ZERO,
                Hash::ZERO,
                self.proposer_pk,
            ),
            txs,
        )
    }

    /// Execute and publish the next block. `Err` is the block's refusal; a
    /// refused block is not published and the height stays.
    pub fn block(&mut self, txs: Vec<SignedTransaction>) -> Result<Vec<Receipt>, StateError> {
        let mut block = self.next_block(txs);
        let exec = self
            .exec
            .execute_block(&block, self.state.state_root(), &[])?;
        block.header.state_root = exec.computed_root();
        let (executed, _, _) = exec.into_parts();
        let receipts = executed.receipts().to_vec();
        let accepted = executed.accept_produced(&block).expect("accept_produced");
        let acc = accepted.accumulator();
        accepted.publish().expect("publish");
        self.state.set_state_root(acc);
        self.height += 1;
        Ok(receipts)
    }

    /// One transaction in one block; panics unless the block is published.
    pub fn one(&mut self, tx: SignedTransaction) -> Receipt {
        let mut r = self.block(vec![tx]).expect("block published");
        assert_eq!(r.len(), 1);
        r.remove(0)
    }

    /// Screen the next block's proposal, as a proposer does.
    pub fn screen(&self, txs: Vec<SignedTransaction>, budget: u64) -> ProposalScreening {
        let block = self.next_block(txs);
        self.exec
            .screen_proposal(&block, self.state.state_root(), &[], budget)
            .unwrap()
    }

    /// The next block's timestamp, in the whole seconds the rules read with
    /// the clock gates open.
    pub fn next_second(&self) -> u64 {
        (T_MS + (self.height + 1) * MINUTE_MS + self.clock_offset_ms) / 1000
    }

    pub fn nonce(&self, kp: &KeyPair) -> u64 {
        self.state.get_nonce(&kp.address()).unwrap()
    }
    pub fn balance(&self, a: &Address) -> u128 {
        self.state.get_balance(a).unwrap()
    }
    pub fn store(&self) -> MessagingStore<'_> {
        MessagingStore::new(&self.db)
    }
    pub fn msg_nonce(&self, a: &Address) -> u64 {
        self.store().get_sender_nonce(a).unwrap()
    }
    pub fn sent_by(&self, a: &Address) -> Vec<sumchain_primitives::MessageEvent> {
        self.store().get_messages_by_sender(a, 1000, 0).unwrap()
    }

    /// `kp` signs `data` at its committed account nonce, for this chain.
    pub fn tx(&self, kp: &KeyPair, data: MessagingTxData) -> SignedTransaction {
        signed_tx(kp, self.chain_id, self.nonce(kp), FEE, data)
    }

    /// `kp` signs `data` at `nonce`, for this chain.
    pub fn tx_at(&self, kp: &KeyPair, nonce: u64, data: MessagingTxData) -> SignedTransaction {
        signed_tx(kp, self.chain_id, nonce, FEE, data)
    }

    /// `kp`'s own version-2 envelope to `to` at `nonce`, for this chain.
    pub fn v2(
        &self,
        kp: &KeyPair,
        to: &Address,
        nonce: u64,
        amount: Option<u128>,
    ) -> SponsoredMessage {
        v2(kp, to, nonce, amount, self.chain_id)
    }

    pub fn rows(&self) -> Rows {
        let mut out = BTreeMap::new();
        for family in FAMILIES {
            for (k, v) in self.db.iter(family).unwrap() {
                out.insert((family.to_string(), k.into_vec()), v.into_vec());
            }
        }
        out
    }

    /// Every account's balance, in a fixed order, the proposer last.
    pub fn balances(&self) -> Vec<u128> {
        everyone()
            .iter()
            .map(|k| self.balance(&k.address()))
            .chain(std::iter::once(self.balance(&proposer())))
            .collect()
    }

    /// Block 1: the admin enables sponsorship; alice, bob, carol and dave
    /// register. Every receipt must be a success.
    pub fn setup(&mut self) {
        use sumchain_primitives::messaging::{RegisterPublicKeyData, SetSponsorshipEnabledData};
        let mut txs = vec![self.tx(
            &admin(),
            op(
                MessagingOperation::SetSponsorshipEnabled,
                &SetSponsorshipEnabledData { enabled: true },
            ),
        )];
        for kp in [alice(), bob(), carol(), dave()] {
            txs.push(self.tx(
                &kp,
                op(
                    MessagingOperation::RegisterPublicKey,
                    &RegisterPublicKeyData {
                        public_key: *kp.public_key().as_bytes(),
                    },
                ),
            ));
        }
        let receipts = self.block(txs).expect("setup block");
        assert!(
            receipts
                .iter()
                .all(|r| r.status == sumchain_primitives::TxStatus::Success),
            "{receipts:?}"
        );
    }

    /// Close every handle and reopen the database, as a restarted node does.
    pub fn restart(self) -> Self {
        let Chain {
            state,
            db,
            dir,
            exec,
            params,
            chain_id,
            height,
            mark,
            proposer_pk,
            clock_offset_ms,
        } = self;
        let root = state.state_root();
        drop(exec);
        drop(state);
        drop(db);
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        state.set_state_root(root);
        let exec = BlockExecutor::new(state.clone(), db.clone(), params.clone());
        Chain {
            state,
            db,
            dir,
            exec,
            params,
            chain_id,
            height,
            mark,
            proposer_pk,
            clock_offset_ms,
        }
    }

    /// Execute `txs` in one block and assert every receipt is a success.
    pub fn all_succeed(&mut self, txs: Vec<SignedTransaction>) {
        let receipts = self.block(txs).expect("block published");
        assert!(
            receipts
                .iter()
                .all(|r| r.status == sumchain_primitives::TxStatus::Success),
            "{receipts:?}"
        );
    }
}

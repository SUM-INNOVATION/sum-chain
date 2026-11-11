//! Transaction mempool for SUM Chain.
//!
//! Stores pending transactions, sorted by fee for block inclusion.
//!
//! ## OmniNode `InferenceAttestation` admission
//!
//! When wired with [`InferenceAttestationAdmission`] (see
//! [`Mempool::with_inference_admission`]), the mempool enforces three
//! checks for any `TxPayload::InferenceAttestation` before insertion:
//!
//! 1. Activation gate: reject if the OmniNode subprotocol isn't enabled
//!    at the current block height.
//! 2. In-flight duplicate: reject if a tx with the same
//!    `(session_id, verifier_address)` pair is already in this mempool.
//! 3. Permanent duplicate: reject if the canonical
//!    `INFERENCE_ATTESTATIONS` CF already contains a finalized
//!    attestation for that pair.
//!
//! This is the load-bearing protection against zero-fee duplicate
//! griefing — the executor returns `Failed(51), fee_paid: 0` on
//! duplicate and does not advance nonce, so the only thing that
//! prevents replay-spam is rejection at admission. The Mempool is
//! intentionally subprotocol-agnostic by default
//! (`InferenceAttestationAdmission` is `Option`-al); production
//! deployments opt in via the builder.
//!
//! ## The node-local inclusion policy
//!
//! When wired with an [`InclusionPolicy`] (see
//! [`Mempool::with_inclusion_policy`]), the mempool judges every transaction
//! it admits, and every transaction it offers for a block, against the
//! canonical chain this node proposes on top of:
//!
//! 1. a transaction that already has a canonical receipt is not admitted and
//!    not carried again;
//! 2. a sponsored `SendMessage` envelope must carry a signature that verifies
//!    over the relay's preimage, by the key it names as the sender;
//! 3. that envelope must carry the sender's expected messaging nonce, and a
//!    candidate block carries each (sender, nonce) at most once, in order;
//! 4. with [`MessagingQuotaAdmission`] wired, that envelope's sender must have
//!    quota left for it, as the canonical chain counts its sends.
//!
//! Admission and selection are this node's own choices. Nothing here is a
//! consensus rule: a block built by a proposer that applies none of it is
//! validated, executed and imported exactly as before.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::RwLock;
use sumchain_crypto::verify_bytes_strict;
use sumchain_genesis::ChainParams;
use sumchain_primitives::inference_attestation::inference_attestation_key;
use sumchain_primitives::{
    Address, Balance, Hash, MessagingOperation, Nonce, SignedTransaction, SponsoredMessage,
    TxInner, TxPayload, TxStatus,
};
use sumchain_storage::{Database, MessagingStore, ReceiptStore};
use tracing::{debug, info, warn};

use crate::education_executor::{
    education_in_flight_key, parse_education, EducationExecutor, EduParsed,
};
use crate::inference_attestation_executor::InferenceAttestationExecutor;
use crate::messaging_executor::{MessagingExecutor, STAKED_SENDER_QUOTA_MULTIPLIER};
use crate::policy_account_executor::policy_account_operation_is_submittable;
use crate::{Result, StateError, StateManager};

/// Mempool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions
    pub max_size: usize,
    /// Maximum transactions per sender
    pub max_per_sender: usize,
    /// Minimum fee for acceptance
    pub min_fee: Balance,
    /// Transaction expiration time in seconds (0 = no expiration)
    pub tx_expiration_secs: u64,
    /// The largest ENCODED transaction this mempool will hold, in bytes
    /// (0 = no bound).
    ///
    /// Not a policy preference: a necessary condition for the transaction ever
    /// being includable at all. `BlockExecutor::validate_block` refuses any
    /// block whose serialized bytes exceed `ChainParams::max_block_bytes`, and
    /// a block containing this transaction is at least this many bytes. So a
    /// transaction above the limit cannot appear in ANY valid block, at any
    /// height, behind any other transaction — and that is knowable at
    /// submission, from the transaction alone, without executing anything.
    ///
    /// Set to `max_block_bytes` by the node. Deliberately the block limit and
    /// not something smaller: admission may reject only what is
    /// DETERMINISTICALLY impossible. A tighter figure would be this mempool's
    /// opinion about what a proposer ought to carry, and a transaction refused
    /// for an opinion is a transaction refused for a reason the next node
    /// disagrees with.
    pub max_tx_bytes: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10000,
            max_per_sender: 100,
            min_fee: 1,
            tx_expiration_secs: 3600, // 1 hour default
            // `ChainParams::default().max_block_bytes`, named through the
            // parameter rather than repeated as a literal, so the two cannot
            // drift apart. A node overrides it with its own genesis figure.
            max_tx_bytes: ChainParams::default().max_block_bytes,
        }
    }
}

/// Transaction entry in mempool
#[derive(Debug, Clone)]
struct TxEntry {
    tx: SignedTransaction,
    fee: Balance,
    #[allow(dead_code)]
    received_at: u64, // Timestamp - reserved for future eviction policy
}

/// Narrow context required for OmniNode `InferenceAttestation` admission.
///
/// Carries only what the admission hook needs: the storage executor that
/// owns the permanent CF, the chain params (for
/// `omninode_enabled_from_height`), and a reference to the current block
/// height. Production nodes construct this once at startup and pass it
/// to [`Mempool::with_inference_admission`]. Tests can construct it
/// directly with handle-grade dependencies (a `TempDir`-backed Database
/// and an `AtomicU64` for height).
///
/// The mempool stores this `Option`-ally so other tx variants admit
/// without any subprotocol coupling.
#[derive(Clone)]
pub struct InferenceAttestationAdmission {
    pub executor: Arc<InferenceAttestationExecutor>,
    pub params: Arc<ChainParams>,
    pub current_height: Arc<AtomicU64>,
}

/// SRC-817/818 Education suite admission context. Same shape and
/// lifecycle as [`InferenceAttestationAdmission`]: owns a read-only
/// `EducationExecutor` (Phase 2 CFs), the chain params (for
/// `education_enabled_from_height`), and the shared live chain-height
/// `Arc<AtomicU64>`. Stored `Option`-ally so non-education txs and
/// no-context paths (tests / consensus internal re-adds) are
/// unaffected. Admission is a narrow filter only — the Phase 2
/// executor remains authoritative (no fee/nonce/dispatch here).
#[derive(Clone)]
pub struct EducationAdmission {
    pub executor: Arc<EducationExecutor>,
    pub params: Arc<ChainParams>,
    pub current_height: Arc<AtomicU64>,
}

/// Node-local inclusion policy: what THIS node admits to its pool and carries
/// in the blocks it builds, judged against the canonical chain it builds on.
/// See [`Mempool::with_inclusion_policy`].
///
/// Three rules, and a fourth with [`MessagingQuotaAdmission`], every one of
/// them about this node's own choices:
///
/// 1. **Canonical inclusion is final.** A transaction whose hash already has
///    a receipt on the canonical chain is not admitted and not carried again.
///    `RECEIPTS[tx_hash]` is written only by canonical publication, removed by
///    `stage_deindex` when its block is unwound, and never written for a block
///    archived off the canonical chain — so "has a receipt" is exactly
///    "included on the canonical chain as this node records it", a transaction
///    seen only on an abandoned branch is NOT counted as included, and a
///    transaction unwound by a chain switch becomes includable again.
///
/// 2. **A sponsored `SendMessage` envelope is authenticated.** Its signature
///    must verify by the key it names as the sender, over the same preimage
///    the relay (`messaging_submitSponsored`) checks before it relays, under
///    strict Ed25519 verification (`verify_bytes_strict`, as every inner
///    signature this tree verifies). The signed string, the signature and the
///    key are exactly what the relay already requires, so a client the relay
///    accepts is accepted here unchanged; no other signing format is
///    recognised. The preimage covers the nonce, the expiry, the recipient
///    hash and the message hash, and nothing else.
///
/// 3. **A sponsored envelope carries the sender's expected messaging nonce.**
///    The named sender's messaging nonce is the count of its successful sends
///    as the canonical chain records it: at admission the envelope must
///    continue the sequence that runs from that committed nonce through this
///    node's pending envelopes for the sender; at selection, envelopes are
///    carried in nonce order per sender, each (sender, nonce) at most once per
///    candidate block, and an envelope the chain has moved past is evicted.
///    An envelope carried to a failed receipt leaves the committed nonce where
///    it was; the sender's later pending envelopes are then evicted too,
///    since nothing in the pool can bring them into sequence.
///
/// 4. **A sponsored envelope's sender has quota left for it** (only with
///    [`Mempool::with_messaging_quota_admission`]). At admission, an envelope
///    is refused when the sender it names has already used its effective
///    quota in the bucket the next block counts sends in, counting this
///    pool's envelopes already pending for that sender. Such an envelope
///    cannot be executed while the count stands — the executor refuses it
///    with an error, not a receipt — so the client is told now rather than
///    left waiting on an envelope no block can carry.
///
/// None of this decides what a block MEANS. A block built by a proposer
/// without this policy is validated, executed and imported as before. The
/// digest, census and closure guards, and the chain-switch and producer tests
/// (`consensus/tests/proposal_policy_{reorg,producer}.rs`), hold that fixed.
#[derive(Clone)]
pub struct InclusionPolicy {
    /// The canonical database this node builds on.
    pub db: Arc<Database>,
}

/// What the pool needs to judge a sponsored envelope against the quota of the
/// sender it names: the chain parameters, for the clock gates the quota bucket
/// is read through, and the live chain height. Same shape as
/// [`EducationAdmission`]. See [`Mempool::with_messaging_quota_admission`].
#[derive(Clone)]
pub struct MessagingQuotaAdmission {
    pub params: Arc<ChainParams>,
    pub current_height: Arc<AtomicU64>,
}

/// The relay's envelope preimage, with the recipient hash rendered as
/// `recipient_hex`:
///
/// ```text
/// SUMCHAIN_SPONSORED_MSG:{nonce}:{expiry}:{recipient hash hex}:{blake3(message_data) hex}
/// ```
///
/// The relay embeds the recipient hash as the client typed it (minus any
/// `0x`), so that one field's hex case is the client's; the data hash is
/// always lower-case.
fn relay_preimage(m: &SponsoredMessage, recipient_hex: &str) -> Vec<u8> {
    format!(
        "SUMCHAIN_SPONSORED_MSG:{}:{}:{}:{}",
        m.nonce,
        m.expiry,
        recipient_hex,
        hex::encode(blake3::hash(&m.message_data).as_bytes())
    )
    .into_bytes()
}

/// Whether `m.signature` verifies, by `m.sender_pubkey`, over the relay
/// preimage — under strict Ed25519 verification, with the recipient hash in
/// lower-case hex or, failing that, upper-case. Those are the two renderings a
/// client produces; a mixed-case rendering is not tried.
///
/// Strict verification accepts every signature a standard Ed25519
/// implementation produces from a seed-derived key; it differs from the
/// non-strict rule only on signatures no such implementation emits. It is a
/// node-local acceptance rule over an unchanged signed string and signature
/// format, and decides nothing about block validity.
pub fn sponsored_envelope_verifies(m: &SponsoredMessage) -> bool {
    let lower = hex::encode(m.recipient_hash);
    if verify_bytes_strict(&relay_preimage(m, &lower), &m.signature, &m.sender_pubkey).is_ok() {
        return true;
    }
    let upper = lower.to_uppercase();
    verify_bytes_strict(&relay_preimage(m, &upper), &m.signature, &m.sender_pubkey).is_ok()
}

/// A sponsored `SendMessage` envelope, as the inclusion policy sees it.
enum Envelope {
    /// Decodes, and its signature verifies: the sender it names and its nonce.
    Verified { sender: Address, nonce: u64 },
    /// Does not decode, or its signature does not verify. No block this node
    /// builds carries it.
    Unverified(String),
}

/// The decoded envelope of a sponsored `SendMessage`; `None` for every other
/// transaction.
fn sponsored_message(
    tx: &SignedTransaction,
) -> Option<std::result::Result<SponsoredMessage, String>> {
    let TxInner::V2(v2) = &tx.inner else {
        return None;
    };
    let TxPayload::Messaging(data) = &v2.payload else {
        return None;
    };
    if data.operation != MessagingOperation::SendMessage {
        return None;
    }
    Some(
        bincode::deserialize::<SponsoredMessage>(&data.data)
            .map_err(|e| format!("the envelope does not decode: {e}")),
    )
}

/// The envelope of a sponsored `SendMessage`, judged; `None` for every other
/// transaction.
fn sponsored_envelope(tx: &SignedTransaction) -> Option<Envelope> {
    let m = match sponsored_message(tx)? {
        Ok(m) => m,
        Err(why) => return Some(Envelope::Unverified(why)),
    };
    if !sponsored_envelope_verifies(&m) {
        return Some(Envelope::Unverified(
            "the envelope signature does not verify, by the named sender's key, over the relay \
             preimage"
                .to_string(),
        ));
    }
    Some(Envelope::Verified {
        sender: Address::from_public_key(&m.sender_pubkey),
        nonce: m.nonce,
    })
}

/// The (sender, nonce) a sponsored `SendMessage` envelope names, decoded only
/// — the key the pending-envelope index is kept under. `None` for every other
/// transaction and for an envelope that does not decode (which was never
/// admitted).
fn sponsored_identity(tx: &SignedTransaction) -> Option<(Address, u64)> {
    let m = sponsored_message(tx)?.ok()?;
    Some((Address::from_public_key(&m.sender_pubkey), m.nonce))
}

/// The sender a sponsored `SendMessage` envelope NAMES, decoded only (the
/// signature is not checked); `None` for every other transaction and for an
/// envelope that does not decode.
///
/// A relayed envelope is a transaction FROM the relaying account, at that
/// account's committed nonce, but executing it advances no account nonce: the
/// sequence it belongs to is the named sender's messaging nonce, which the
/// inclusion policy orders. A proposer that has to leave one out of a block
/// reads this to know which of the block's other transactions depend on it.
pub fn sponsored_envelope_sender(tx: &SignedTransaction) -> Option<Address> {
    sponsored_identity(tx).map(|(sender, _)| sender)
}

/// Transaction mempool
pub struct Mempool {
    /// All transactions by hash
    txs: RwLock<HashMap<Hash, TxEntry>>,
    /// Transactions by sender address
    by_sender: RwLock<HashMap<Address, HashSet<Hash>>>,
    /// Transactions sorted by fee (descending) for selection
    by_fee: RwLock<BTreeMap<(Balance, Hash), Hash>>,
    /// Configuration
    config: MempoolConfig,
    /// In-flight (session_id, verifier_address) keys mapped to tx hash.
    /// Same 32-byte BLAKE3-domain-separated key shape used by the
    /// `INFERENCE_ATTESTATIONS` CF; lets us point-lookup duplicates at
    /// admission and unlink the entry when the tx is removed.
    inference_in_flight: RwLock<HashMap<[u8; 32], Hash>>,
    /// Optional admission context. `None` in tests and in any code path
    /// that adds txs to the mempool without going through user submission
    /// (e.g. consensus re-adding txs from rejected blocks). Production
    /// node-startup wires this via [`Mempool::with_inference_admission`].
    inference_admission: Option<InferenceAttestationAdmission>,
    /// In-flight education dedup keys → tx hash. Same 32-byte
    /// length-safe key the admission path derives via
    /// [`education_in_flight_key`]; re-derived on `remove`/`clear` so
    /// cleanup can't desync from admission.
    education_in_flight: RwLock<HashMap<[u8; 32], Hash>>,
    /// Optional education admission context (parallels
    /// `inference_admission`).
    education_admission: Option<EducationAdmission>,
    /// Node-local policy: refuse `ContractDeploy`/`ContractCall`. Off by
    /// default. See [`Mempool::set_refuse_contract_transactions`].
    refuse_contract_transactions: AtomicBool,
    /// Optional inclusion policy context. `None` in tests and in paths that
    /// construct a bare pool; a production node wires it via
    /// [`Mempool::with_inclusion_policy`], and nothing below is enforced
    /// without it.
    inclusion_policy: Option<InclusionPolicy>,
    /// Pending sponsored envelopes, by the sender each names: nonce → the hash
    /// of the transaction carrying it. Stamped at admission after every other
    /// check and after insertion (or the insertion is backed out, when two
    /// copies of one (sender, nonce) were admitted concurrently), unstamped on
    /// `remove`, re-derived from the stored transaction so the two cannot
    /// desync.
    sponsored_in_flight: RwLock<HashMap<Address, BTreeMap<u64, Hash>>>,
    /// Optional quota context for sponsored envelopes (inclusion policy rule
    /// 4). Read against the inclusion policy's database, so it does nothing
    /// without one.
    messaging_quota_admission: Option<MessagingQuotaAdmission>,
}

/// Whether `tx` is a contract deploy or call.
fn is_contract_transaction(tx: &SignedTransaction) -> bool {
    matches!(
        &tx.inner,
        TxInner::V2(v2) if matches!(
            v2.payload,
            TxPayload::ContractDeploy(_) | TxPayload::ContractCall(_)
        )
    )
}

impl Mempool {
    /// Create a new mempool
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            txs: RwLock::new(HashMap::new()),
            by_sender: RwLock::new(HashMap::new()),
            by_fee: RwLock::new(BTreeMap::new()),
            config,
            inference_in_flight: RwLock::new(HashMap::new()),
            inference_admission: None,
            education_in_flight: RwLock::new(HashMap::new()),
            education_admission: None,
            refuse_contract_transactions: AtomicBool::new(false),
            inclusion_policy: None,
            sponsored_in_flight: RwLock::new(HashMap::new()),
            messaging_quota_admission: None,
        }
    }

    /// Builder: attach the node-local [`InclusionPolicy`]. Without it, no
    /// transaction is checked against the canonical chain and sponsored
    /// envelopes are admitted as before (tests, bare pools); a production node
    /// always attaches it.
    pub fn with_inclusion_policy(mut self, policy: InclusionPolicy) -> Self {
        self.inclusion_policy = Some(policy);
        self
    }

    /// Whether an [`InclusionPolicy`] is attached.
    pub fn has_inclusion_policy(&self) -> bool {
        self.inclusion_policy.is_some()
    }

    /// Builder: judge every sponsored `SendMessage` envelope against the quota
    /// of the sender it names, at admission — the inclusion policy's rule 4.
    /// It reads the policy's database, so without a wired [`InclusionPolicy`]
    /// it does nothing.
    ///
    /// Node-local, like the rest of the policy. A block that carries an
    /// over-quota envelope is refused by every node's execution exactly as
    /// before; what changes is that this node does not hold such an envelope
    /// and the relay's caller is told why.
    pub fn with_messaging_quota_admission(mut self, admission: MessagingQuotaAdmission) -> Self {
        self.messaging_quota_admission = Some(admission);
        self
    }

    /// Node-local policy: refuse contract deploys and calls.
    ///
    /// When on, `add` refuses them from every source (RPC submission, gossip,
    /// re-addition after a reorg), any already held are removed, and
    /// `select_for_block` never returns one. Returns how many were removed.
    ///
    /// Not a consensus rule. It decides what THIS node holds and proposes. A
    /// block from another proposer that carries a contract transaction is
    /// still executed and accepted.
    pub fn set_refuse_contract_transactions(&self, refuse: bool) -> usize {
        self.refuse_contract_transactions
            .store(refuse, Ordering::SeqCst);
        if !refuse {
            return 0;
        }
        let held: Vec<Hash> = self
            .txs
            .read()
            .iter()
            .filter(|(_, e)| is_contract_transaction(&e.tx))
            .map(|(h, _)| *h)
            .collect();
        held.iter().filter(|h| self.remove(h).is_some()).count()
    }

    /// Whether the node-local contract refusal is on.
    pub fn refuses_contract_transactions(&self) -> bool {
        self.refuse_contract_transactions.load(Ordering::SeqCst)
    }

    /// Builder: attach the OmniNode `InferenceAttestation` admission
    /// context. Without it, `InferenceAttestation` txs are still
    /// admitted by in-flight dedup but the activation gate and permanent
    /// CF dedup are skipped (which is what you want for tests and for
    /// consensus internal re-adds, but NEVER for production user
    /// submission).
    pub fn with_inference_admission(
        mut self,
        admission: InferenceAttestationAdmission,
    ) -> Self {
        self.inference_admission = Some(admission);
        self
    }

    /// Builder: attach the SRC-817/818 Education admission context.
    /// Without it, education txs are still in-flight-deduped but the
    /// activation gate and committed-CF/structural prechecks are
    /// skipped (tests / consensus internal re-adds), never for
    /// production user submission.
    pub fn with_education_admission(mut self, admission: EducationAdmission) -> Self {
        self.education_admission = Some(admission);
        self
    }

    /// Add a transaction to the mempool
    pub fn add(&self, tx: SignedTransaction) -> Result<Hash> {
        let hash = tx.hash();
        let sender = tx.sender();
        let fee = tx.fee();

        // Check if already exists
        if self.txs.read().contains_key(&hash) {
            return Err(StateError::TxAlreadyExists);
        }

        // OmniNode `InferenceAttestation` subprotocol-specific admission.
        // For any other payload variant this is a no-op. The returned
        // key (if any) is stamped into `inference_in_flight` AFTER all
        // other admission checks pass — see end of this method.
        let inference_key = self.check_inference_admission(&tx)?;
        // SRC-817/818 Education admission. No-op for any other payload
        // variant. Returned key (if any) is stamped into
        // `education_in_flight` AFTER all other admission checks pass.
        let education_key = self.check_education_admission(&tx)?;
        // BR1 beacon (#125) admission: deterministically reject beacon payloads
        // while the subprotocol is gate-closed (the default; fail-closed pending
        // #127). No-op for any non-beacon payload.
        self.check_beacon_admission(&tx)?;
        // C1/ComputePool (#130) admission: deterministically reject ComputePool
        // payloads while the subprotocol is gate-closed (the default; fail-closed
        // pending #130). No-op for any non-ComputePool payload.
        self.check_compute_pool_admission(&tx)?;
        // Permanently unincludable and permanently unexecutable shapes, refused
        // here rather than discovered at proposal. No-op for everything else.
        self.check_permanently_invalid_admission(&tx)?;
        // Node-local contract refusal (off by default).
        if self.refuses_contract_transactions() && is_contract_transaction(&tx) {
            return Err(StateError::ContractTransactionsRefused);
        }
        // The node-local inclusion policy: nothing already included on the
        // canonical chain, and only authenticated, in-sequence sponsored
        // envelopes. No-op without a wired policy. Before the size check, so a
        // refused transaction never evicts a held one. The returned key (if
        // any) is stamped into `sponsored_in_flight` AFTER insertion.
        let sponsored_key = self.check_inclusion_admission(&tx, &hash)?;

        // Check mempool size
        if self.txs.read().len() >= self.config.max_size {
            // Try to evict lowest fee tx
            if !self.try_evict_lowest_fee(fee) {
                return Err(StateError::MempoolFull);
            }
        }

        // Check per-sender limit
        {
            let by_sender = self.by_sender.read();
            if let Some(sender_txs) = by_sender.get(&sender) {
                if sender_txs.len() >= self.config.max_per_sender {
                    return Err(StateError::MempoolFull);
                }
            }
        }

        // Check minimum fee
        if fee < self.config.min_fee {
            return Err(StateError::FeeTooLow {
                minimum: self.config.min_fee,
                got: fee,
            });
        }

        // Add to all indexes
        let entry = TxEntry {
            tx,
            fee,
            received_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        };

        self.txs.write().insert(hash, entry);
        self.by_sender
            .write()
            .entry(sender)
            .or_insert_with(HashSet::new)
            .insert(hash);

        // Use negative fee for descending order in BTreeMap
        let fee_key = (Balance::MAX - fee, hash);
        self.by_fee.write().insert(fee_key, hash);

        // Stamp the in-flight key only after every other admission check
        // and index insertion has succeeded, so a partial admission path
        // can never leave a dangling in-flight entry behind.
        if let Some(key) = inference_key {
            self.inference_in_flight.write().insert(key, hash);
        }
        if let Some(key) = education_key {
            self.education_in_flight.write().insert(key, hash);
        }
        if let Some((sender, nonce)) = sponsored_key {
            let mut in_flight = self.sponsored_in_flight.write();
            let raced = in_flight
                .get(&sender)
                .and_then(|nonces| nonces.get(&nonce))
                .is_some_and(|other| *other != hash);
            if raced {
                // The admission check and this stamp are not one critical
                // section, so two copies of one (sender, nonce) admitted
                // concurrently both reach here. The copy stamped first stays;
                // this one is backed out, as the check would have refused it.
                drop(in_flight);
                self.remove(&hash);
                return Err(StateError::SponsoredEnvelopeRefused(format!(
                    "an envelope from this sender with nonce {nonce} is already pending"
                )));
            }
            in_flight.entry(sender).or_default().insert(nonce, hash);
        }

        debug!("Added tx {} to mempool (fee: {})", hash, fee);

        Ok(hash)
    }

    /// The pending envelopes of `sender` that nothing in this pool can bring
    /// into sequence: every one above `committed`, when no pending envelope
    /// other than `failed` carries `committed` itself.
    ///
    /// Read when an envelope is evicted for a receipt that is not a success:
    /// such a receipt left the sender's committed nonce where it was, so the
    /// sender's later envelopes wait for a value only a fresh submission can
    /// supply. Evicting them keeps the pool's sequence equal to what the chain
    /// expects, and a client that re-reads the sender's nonce and resends its
    /// run is admitted again in order.
    fn stranded_envelopes(&self, sender: &Address, committed: u64, failed: &Hash) -> Vec<Hash> {
        let in_flight = self.sponsored_in_flight.read();
        let Some(nonces) = in_flight.get(sender) else {
            return Vec::new();
        };
        if nonces
            .get(&committed)
            .is_some_and(|carrier| carrier != failed)
        {
            return Vec::new();
        }
        nonces
            .range(committed.saturating_add(1)..)
            .map(|(_, h)| *h)
            .collect()
    }

    /// Hashes to evict alongside `hash`, an envelope that has a canonical
    /// receipt: none when the receipt is a success (the sequence moved on), the
    /// sender's stranded envelopes when it is not.
    fn stranded_after_receipt(
        &self,
        policy: &InclusionPolicy,
        tx: &SignedTransaction,
        hash: &Hash,
    ) -> Vec<Hash> {
        let Some((sender, _)) = sponsored_identity(tx) else {
            return Vec::new();
        };
        let Ok(Some(receipt)) = ReceiptStore::new(&policy.db).get(hash) else {
            return Vec::new();
        };
        if receipt.status == TxStatus::Success {
            return Vec::new();
        }
        match MessagingStore::new(&policy.db).get_sender_nonce(&sender) {
            Ok(committed) => self.stranded_envelopes(&sender, committed, hash),
            Err(_) => Vec::new(),
        }
    }

    /// The inclusion policy at admission.
    ///
    /// `Ok(None)` when no policy is wired, and for any transaction that is not
    /// a sponsored `SendMessage` and passes the canonical-receipt check.
    /// `Ok(Some((sender, nonce)))` for a sponsored envelope that passes every
    /// check, to be stamped as pending after insertion.
    ///
    /// The expected nonce runs from the committed messaging nonce through the
    /// envelopes this pool already holds for the sender: with `k` pending, the
    /// next admissible nonce is `committed + k`, and any nonce in
    /// `committed..=committed + k` not already pending is accepted, so a gap
    /// left by an evicted envelope can be filled. A nonce below the committed
    /// value has been used; a nonce beyond `committed + k` skips a value no
    /// pending envelope carries.
    fn check_inclusion_admission(
        &self,
        tx: &SignedTransaction,
        hash: &Hash,
    ) -> Result<Option<(Address, u64)>> {
        let Some(policy) = &self.inclusion_policy else {
            return Ok(None);
        };
        if ReceiptStore::new(&policy.db).contains(hash)? {
            return Err(StateError::TransactionAlreadyIncluded);
        }
        match sponsored_envelope(tx) {
            None => Ok(None),
            Some(Envelope::Unverified(why)) => Err(StateError::SponsoredEnvelopeRefused(why)),
            Some(Envelope::Verified { sender, nonce }) => {
                let committed = MessagingStore::new(&policy.db).get_sender_nonce(&sender)?;
                let in_flight = self.sponsored_in_flight.read();
                let pending = in_flight.get(&sender);
                if nonce < committed {
                    return Err(StateError::SponsoredEnvelopeRefused(format!(
                        "envelope nonce {nonce} is below the sender's current messaging nonce \
                         {committed}"
                    )));
                }
                if pending.is_some_and(|p| p.contains_key(&nonce)) {
                    return Err(StateError::SponsoredEnvelopeRefused(format!(
                        "an envelope from this sender with nonce {nonce} is already pending"
                    )));
                }
                let pending_count = pending.map_or(0, |p| p.len() as u64);
                let expected = committed.saturating_add(pending_count);
                if nonce > expected {
                    return Err(StateError::SponsoredEnvelopeRefused(format!(
                        "envelope nonce {nonce} is ahead of the expected {expected} (the \
                         sender's current messaging nonce is {committed})"
                    )));
                }
                if let Some(why) = self.messaging_quota_refusal(policy, &sender, pending_count)? {
                    return Err(StateError::SponsoredEnvelopeRefused(why));
                }
                Ok(Some((sender, nonce)))
            }
        }
    }

    /// The inclusion policy's rule 4 at admission: `None` when `sender`, named
    /// by a verified envelope, has quota left for it after its `pending`
    /// envelopes already in this pool; otherwise why it has not. `None`
    /// without a [`MessagingQuotaAdmission`].
    ///
    /// The comparison is `check_rate_limit`'s — the bucket's committed count
    /// against the base quota, multiplied for a sender whose trust stake meets
    /// the minimum — with the pending envelopes added to the count, since each
    /// of them is carried before this one and counts when it succeeds.
    fn messaging_quota_refusal(
        &self,
        policy: &InclusionPolicy,
        sender: &Address,
        pending: u64,
    ) -> Result<Option<String>> {
        let Some(admission) = &self.messaging_quota_admission else {
            return Ok(None);
        };
        // The next block, and the bucket it counts sends in. Its timestamp is
        // not known yet; this node's own proposal stamps the wall clock, so the
        // wall clock is read. While the block-timestamp gate is closed the
        // bucket is the same for every block and the reading changes nothing.
        let height = admission
            .current_height
            .load(Ordering::Relaxed)
            .saturating_add(1);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let day = MessagingExecutor::quota_day(&admission.params, height, now_ms);
        let store = MessagingStore::new(&policy.db);
        let used = store.get_daily_message_count(sender, day)?;
        let base = store.get_daily_quota()?;
        let quota = if store.get_stake_balance(sender)? >= store.get_min_trust_stake()? {
            base.saturating_mul(STAKED_SENDER_QUOTA_MULTIPLIER)
        } else {
            base
        };
        if u64::from(used).saturating_add(pending) < u64::from(quota) {
            return Ok(None);
        }
        let also_pending = if pending > 0 {
            format!(", and {pending} more of its envelopes are already pending here")
        } else {
            String::new()
        };
        Ok(Some(format!(
            "the sender has used {used} of its {quota} messages in the current quota period\
             {also_pending}; no block can carry this envelope until the sender has quota again"
        )))
    }

    /// Run the three OmniNode `InferenceAttestation` admission checks.
    /// Returns `Ok(None)` for any non-InferenceAttestation payload (skip).
    /// Returns `Ok(Some(key))` if all checks pass and the caller should
    /// register `key` in `inference_in_flight` after final insertion.
    fn check_inference_admission(&self, tx: &SignedTransaction) -> Result<Option<[u8; 32]>> {
        let TxInner::V2(v2_tx) = &tx.inner else {
            return Ok(None);
        };
        let TxPayload::InferenceAttestation(att) = &v2_tx.payload else {
            return Ok(None);
        };

        // (1) Activation gate. Only enforced when an admission context
        // is wired; tests and consensus-internal re-adds construct the
        // mempool without one and skip.
        if let Some(ctx) = &self.inference_admission {
            let height = ctx.current_height.load(Ordering::Relaxed);
            let gate_open = matches!(
                ctx.params.omninode_enabled_from_height,
                Some(h) if height >= h
            );
            if !gate_open {
                return Err(StateError::OmniNodeNotActivated);
            }
        }

        // Same 32-byte BLAKE3-domain-separated key the CF uses, so the
        // in-flight set and the permanent CF are queried under
        // bit-identical keys — no encoding skew possible.
        let key = inference_attestation_key(&att.digest.session_id, &v2_tx.from);

        // (2) In-flight duplicate. Cheap point lookup in our own state.
        if self.inference_in_flight.read().contains_key(&key) {
            return Err(StateError::DuplicateInferenceAttestation);
        }

        // (3) Permanent CF dedup. Only enforced when an admission
        // context is wired (the executor handle lives there).
        if let Some(ctx) = &self.inference_admission {
            if ctx.executor.exists(&key)? {
                return Err(StateError::DuplicateInferenceAttestation);
            }
        }

        Ok(Some(key))
    }

    /// SRC-817/818 Education admission. `Ok(None)` for any
    /// non-education payload (skip — zero behavior change for other
    /// variants). `Ok(Some(key))` if all checks pass and the caller
    /// should register `key` in `education_in_flight` after final
    /// insertion. Admission produces NO receipts and NO state mutation;
    /// the Phase 2 executor remains authoritative. No submission
    /// time-window check here (admission has no canonical block
    /// timestamp — executor + Policy B handle the window).
    fn check_education_admission(
        &self,
        tx: &SignedTransaction,
    ) -> Result<Option<[u8; 32]>> {
        let TxInner::V2(v2_tx) = &tx.inner else {
            return Ok(None);
        };
        let TxPayload::Education(edu) = &v2_tx.payload else {
            return Ok(None);
        };

        // (1) Activation gate (only when an admission ctx is wired).
        if let Some(ctx) = &self.education_admission {
            let height = ctx.current_height.load(Ordering::Relaxed);
            let gate_open = matches!(
                ctx.params.education_enabled_from_height,
                Some(h) if height >= h
            );
            if !gate_open {
                return Err(StateError::EducationNotActivated);
            }
        }

        // (2) Decode/route (size + supported standard/op + bincode).
        let parsed = parse_education(edu).map_err(|code| {
            StateError::InvalidEducationTransaction(format!(
                "undecodable or unsupported education op (code {code})"
            ))
        })?;

        // (3) Derive the length-safe in-flight dedup key.
        let key = education_in_flight_key(&parsed);

        // (4) In-flight duplicate (cheap point lookup in our state).
        if self.education_in_flight.read().contains_key(&key) {
            return Err(StateError::DuplicateEducationRecord);
        }

        // (5) Committed-CF + structural cheap prechecks (only when ctx
        // wired; the executor read handle lives there). No window check.
        if let Some(ctx) = &self.education_admission {
            let ex = &ctx.executor;
            match &parsed {
                EduParsed::CreateCatalog(d) => {
                    if ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::CreateOffering(d) => {
                    if ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                    match ex.get_catalog(&d.catalog_id)? {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "CreateOffering: catalog not found".into(),
                            ))
                        }
                        Some(c) if c.status != 1 /* Active */ => {
                            return Err(StateError::InvalidEducationTransaction(
                                "CreateOffering: catalog not Active".into(),
                            ))
                        }
                        Some(_) => {}
                    }
                }
                EduParsed::PublishContent(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "PublishContent: offering not found".into(),
                        ));
                    }
                    if ex.content_exists(&d.offering_id, &d.content_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::AddAssessment(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "AddAssessment: offering not found".into(),
                        ));
                    }
                    if ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::LinkEnrollment(d) => {
                    match ex.get_offering(&d.offering_id)? {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "LinkEnrollment: offering not found".into(),
                            ))
                        }
                        Some(o) if o.status != 1 /* Active */ => {
                            return Err(StateError::InvalidEducationTransaction(
                                "LinkEnrollment: offering not Active".into(),
                            ))
                        }
                        Some(_) => {}
                    }
                    if ex
                        .enrollment_link_exists(&d.offering_id, &d.student_commitment)?
                    {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::Submit(d, is_exam) => {
                    let off = match ex.get_offering(&d.offering_id)? {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "Submit: offering not found".into(),
                            ))
                        }
                        Some(o) => o,
                    };
                    // Active (1) or EnrollmentClosed (2).
                    if off.status != 1 && off.status != 2 {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: offering not accepting submissions".into(),
                        ));
                    }
                    let a = match ex
                        .get_assessment(&d.offering_id, &d.assessment_id)?
                    {
                        None => {
                            return Err(StateError::InvalidEducationTransaction(
                                "Submit: assessment not found".into(),
                            ))
                        }
                        Some(a) => a,
                    };
                    let want_kind: u8 = if *is_exam { 1 } else { 0 };
                    if a.kind != want_kind {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: assessment kind mismatch".into(),
                        ));
                    }
                    if !ex.enrollment_link_exists(
                        &d.offering_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: student_commitment not enrolled".into(),
                        ));
                    }
                    if a.max_attempts != 0
                        && ex.committed_attempts(
                            &d.offering_id,
                            &d.assessment_id,
                            &d.student_commitment,
                        )? >= a.max_attempts
                    {
                        return Err(StateError::InvalidEducationTransaction(
                            "Submit: attempts exhausted".into(),
                        ));
                    }
                    if ex.submission_exists(
                        &d.offering_id,
                        &d.assessment_id,
                        &d.student_commitment,
                        d.attempt,
                    )? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::Grade(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "Grade: offering not found".into(),
                        ));
                    }
                    if !ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "Grade: assessment not found".into(),
                        ));
                    }
                    if !ex.enrollment_link_exists(
                        &d.offering_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::InvalidEducationTransaction(
                            "Grade: student_commitment not enrolled".into(),
                        ));
                    }
                    if ex.grade_finalized(
                        &d.offering_id,
                        &d.assessment_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                EduParsed::FinalizeGrade(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "FinalizeGrade: offering not found".into(),
                        ));
                    }
                    if !ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "FinalizeGrade: assessment not found".into(),
                        ));
                    }
                    if !ex.enrollment_link_exists(
                        &d.offering_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::InvalidEducationTransaction(
                            "FinalizeGrade: student_commitment not enrolled".into(),
                        ));
                    }
                    if ex.grade_finalized(
                        &d.offering_id,
                        &d.assessment_id,
                        &d.student_commitment,
                    )? {
                        return Err(StateError::DuplicateEducationRecord);
                    }
                }
                // Mutate/lifecycle ops: cheap existence only (executor
                // remains authoritative for state/auth).
                EduParsed::UpdateCatalog(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::PublishCatalogContent(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::DeprecateCatalog(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::ArchiveCatalog(d) => {
                    if !ex.catalog_exists(&d.catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::SupersedeCatalog(d) => {
                    if !ex.catalog_exists(&d.old_catalog_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "catalog not found".into(),
                        ));
                    }
                }
                EduParsed::UpdateOffering(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::UpdateAssessment(d) => {
                    if !ex.assessment_exists(&d.offering_id, &d.assessment_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "assessment not found".into(),
                        ));
                    }
                }
                EduParsed::OpenEnrollment(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::CloseEnrollment(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::FinalizeCourse(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::ArchiveOffering(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
                EduParsed::SuspendOrCancel(d) => {
                    if !ex.offering_exists(&d.offering_id)? {
                        return Err(StateError::InvalidEducationTransaction(
                            "offering not found".into(),
                        ));
                    }
                }
            }
        }

        Ok(Some(key))
    }

    /// BR1 randomness-beacon (#125) admission. `Ok(())` for any non-beacon
    /// payload (skip — zero behavior change for other variants). For a beacon
    /// payload (`BeaconSetup` / `BeaconSigning`), the subprotocol is **gate-closed**
    /// and fail-closed pending BR1 #127, so admission **deterministically rejects**
    /// with [`StateError::BeaconNotActivated`] — no beacon tx enters the mempool,
    /// no receipt, no state. The executor independently rejects any beacon tx that
    /// reaches execution (`crate::beacon_executor`), so both seams are closed.
    ///
    /// (When #127 makes `beacon_enabled_from_height` openable, this should consult
    /// the gate via a wired admission context, exactly like
    /// [`Self::check_inference_admission`] / [`Self::check_education_admission`];
    /// until then the fail-closed unconditional rejection is the correct dormant
    /// stance and needs no admission-context plumbing.)
    fn check_beacon_admission(&self, tx: &SignedTransaction) -> Result<()> {
        let TxInner::V2(v2_tx) = &tx.inner else {
            return Ok(());
        };
        match &v2_tx.payload {
            TxPayload::BeaconSetup(_) | TxPayload::BeaconSigning(_) => {
                Err(StateError::BeaconNotActivated)
            }
            _ => Ok(()),
        }
    }

    /// Refuse, at submission, what no block could ever carry or execute.
    ///
    /// # Why admission and not the proposer
    ///
    /// The proposer can now survive both of these — it identifies the offending
    /// transaction, drops it and produces a block anyway. But surviving is not
    /// free. Each refusal costs a whole speculative block execution, and the
    /// transaction is still in every peer's mempool, still gossiped, still at
    /// the front of every fee-ordered selection until some proposer pays to
    /// discover it again. Both of these facts are knowable from the
    /// transaction's own bytes, with no state read and no execution, so the
    /// cheap seam is the right one and the proposer's handling is the
    /// backstop.
    ///
    /// # The two shapes
    ///
    /// PERMANENTLY OVERSIZED. `validate_block` refuses any block whose
    /// serialized bytes exceed `max_block_bytes`, and a block carrying this
    /// transaction is at least as large as the transaction. So above
    /// [`MempoolConfig::max_tx_bytes`] there is no valid block, at any height,
    /// in any order, that could ever include it.
    ///
    /// PERMANENTLY UNEXECUTABLE. `PolicyAccountExecutor::execute` matches on
    /// the operation code and returns `StateError::InvalidOperation` for
    /// `ModifyMembership` and `ModifyPolicy` before reading any state: both are
    /// reachable only as the EFFECT of an `ExecuteProposal`, never as a
    /// submission. Directly submitted, they do not merely fail — they
    /// propagate out of `execute_block` and make the whole block unexecutable,
    /// which is how one of them, at one `min_fee`, used to halt a validator
    /// permanently.
    ///
    /// Nothing here rejects anything a state or a height could change its mind
    /// about. A gate that is closed today opens at a height; a row that is
    /// missing today is created by the next block; a balance that is short
    /// today is topped up. None of those are refused here, and refusing them
    /// here would be the mempool destroying transactions on a guess.
    fn check_permanently_invalid_admission(&self, tx: &SignedTransaction) -> Result<()> {
        if self.config.max_tx_bytes > 0 {
            let encoded = tx.to_bytes().len() as u64;
            if encoded > self.config.max_tx_bytes {
                return Err(StateError::TransactionPermanentlyUnincludable(format!(
                    "the transaction encodes to {encoded} bytes, and no block may \
                     exceed {} bytes, so no block can ever carry it",
                    self.config.max_tx_bytes
                )));
            }
        }

        let TxInner::V2(v2_tx) = &tx.inner else {
            return Ok(());
        };
        if let TxPayload::PolicyAccount(data) = &v2_tx.payload {
            // The executor's own list, read rather than restated — see
            // `policy_account_operation_is_submittable`.
            if !policy_account_operation_is_submittable(data.operation) {
                return Err(StateError::TransactionPermanentlyUnincludable(format!(
                    "PolicyAccount operation {:?} is reachable only as the effect of \
                     an ExecuteProposal and is refused on the operation code alone, \
                     before any state is read, so it can never succeed at any height",
                    data.operation
                )));
            }
        }
        Ok(())
    }

    /// C1/ComputePool (#130) admission. `Ok(())` for any non-ComputePool payload.
    /// For a `TxPayload::ComputePool`, the subprotocol is **gate-closed** and
    /// fail-closed pending #130, so admission **deterministically rejects** with
    /// [`StateError::ComputePoolNotActivated`] — no ComputePool tx enters the
    /// mempool, no receipt, no state. The executor independently rejects any
    /// ComputePool tx that reaches execution, so both seams are closed. (When
    /// `compute_pool_enabled_from_height` becomes openable this should consult the
    /// gate via a wired admission context, exactly like beacon/inference/education;
    /// until then the unconditional fail-closed rejection is the correct dormant
    /// stance.)
    fn check_compute_pool_admission(&self, tx: &SignedTransaction) -> Result<()> {
        let TxInner::V2(v2_tx) = &tx.inner else {
            return Ok(());
        };
        match &v2_tx.payload {
            TxPayload::ComputePool(_) => Err(StateError::ComputePoolNotActivated),
            _ => Ok(()),
        }
    }

    /// Remove a transaction from the mempool
    pub fn remove(&self, hash: &Hash) -> Option<SignedTransaction> {
        let entry = self.txs.write().remove(hash)?;
        let sender = entry.tx.sender();

        // Remove from by_sender index
        {
            let mut by_sender = self.by_sender.write();
            if let Some(sender_txs) = by_sender.get_mut(&sender) {
                sender_txs.remove(hash);
                if sender_txs.is_empty() {
                    by_sender.remove(&sender);
                }
            }
        }

        // Remove from by_fee index
        let fee_key = (Balance::MAX - entry.fee, *hash);
        self.by_fee.write().remove(&fee_key);

        // Clear in-flight key for InferenceAttestation txs. Re-derive
        // the key from the stored tx rather than maintaining a reverse
        // index, so the cleanup path can't desync from the admission
        // path. No-op for non-InferenceAttestation variants.
        if let TxInner::V2(v2_tx) = &entry.tx.inner {
            if let TxPayload::InferenceAttestation(att) = &v2_tx.payload {
                let key = inference_attestation_key(
                    &att.digest.session_id,
                    &v2_tx.from,
                );
                self.inference_in_flight.write().remove(&key);
            }
            // Education in-flight unlink. Re-derive the key from the
            // stored tx (no reverse index → cleanup can't desync from
            // admission). No-op for non-education variants and for
            // undecodable payloads (which never got admitted anyway).
            if let TxPayload::Education(edu) = &v2_tx.payload {
                if let Ok(parsed) = parse_education(edu) {
                    let key = education_in_flight_key(&parsed);
                    self.education_in_flight.write().remove(&key);
                }
            }
        }
        // Pending-envelope unlink, re-derived from the stored transaction.
        // No-op for everything but a sponsored `SendMessage`, and for a copy
        // that was never the stamped carrier of its (sender, nonce).
        if let Some((sender, nonce)) = sponsored_identity(&entry.tx) {
            let mut in_flight = self.sponsored_in_flight.write();
            if let Some(nonces) = in_flight.get_mut(&sender) {
                if nonces.get(&nonce) == Some(hash) {
                    nonces.remove(&nonce);
                }
                if nonces.is_empty() {
                    in_flight.remove(&sender);
                }
            }
        }

        debug!("Removed tx {} from mempool", hash);

        Some(entry.tx)
    }

    /// Remove multiple transactions (e.g., after block inclusion)
    pub fn remove_batch(&self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove(hash);
        }
    }

    /// Get a transaction by hash
    pub fn get(&self, hash: &Hash) -> Option<SignedTransaction> {
        self.txs.read().get(hash).map(|e| e.tx.clone())
    }

    /// Check if a transaction exists
    pub fn contains(&self, hash: &Hash) -> bool {
        self.txs.read().contains_key(hash)
    }

    /// Get transactions for a sender
    pub fn get_by_sender(&self, sender: &Address) -> Vec<SignedTransaction> {
        let by_sender = self.by_sender.read();
        let txs = self.txs.read();

        match by_sender.get(sender) {
            Some(hashes) => hashes
                .iter()
                .filter_map(|h| txs.get(h).map(|e| e.tx.clone()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get next nonce for a sender (current nonce + pending tx count)
    pub fn pending_nonce(&self, sender: &Address, current_nonce: Nonce) -> Nonce {
        let by_sender = self.by_sender.read();
        match by_sender.get(sender) {
            Some(hashes) => current_nonce + hashes.len() as u64,
            None => current_nonce,
        }
    }

    /// Select transactions for a new block (sorted by fee, highest first).
    ///
    /// Every candidate passes the inclusion policy again here, against the
    /// canonical chain as it stands NOW rather than as it stood at admission:
    /// a held transaction that another block has since included, and a held
    /// envelope whose sender's nonce has since moved past it, are evicted
    /// rather than offered. See [`Self::apply_inclusion_policy`].
    pub fn select_for_block(&self, max_count: usize) -> Vec<SignedTransaction> {
        let (carried, evict) = {
            let by_fee = self.by_fee.read();
            let txs = self.txs.read();
            let refuse_contracts = self.refuses_contract_transactions();
            // Nothing held can be a contract transaction while the refusal is
            // on (see `set_refuse_contract_transactions`); the filter is a
            // second line.
            let candidates = by_fee
                .values()
                .filter_map(|hash| txs.get(hash).map(|e| e.tx.clone()))
                .filter(move |tx| !(refuse_contracts && is_contract_transaction(tx)));
            self.screen_for_inclusion(candidates, max_count)
        };
        if !evict.is_empty() {
            info!(
                "Inclusion policy: evicting {} held transaction(s) the canonical chain has \
                 moved past",
                evict.len()
            );
            self.remove_batch(&evict);
        }
        carried
    }

    /// The transactions among `transactions`, in the order given, that this
    /// node carries in ONE block under its inclusion policy; the rest are left
    /// out, and those the canonical chain has moved past are evicted from the
    /// pool if held.
    ///
    /// The same screening [`Self::select_for_block`] applies, offered for a
    /// list that did not come from this pool (`PoAEngine::create_block` applies
    /// it to whatever it is handed). Without a wired policy only the in-block
    /// duplicate-hash rule applies.
    pub fn apply_inclusion_policy(
        &self,
        transactions: Vec<SignedTransaction>,
    ) -> Vec<SignedTransaction> {
        let max_count = transactions.len();
        let (carried, evict) = self.screen_for_inclusion(transactions.into_iter(), max_count);
        if !evict.is_empty() {
            self.remove_batch(&evict);
        }
        carried
    }

    /// Which of `candidates`, taken in order, go into one candidate block, and
    /// which the pool should evict as no longer includable.
    ///
    /// Per candidate, in order: a hash already carried in this block is
    /// skipped; a transaction with a canonical receipt is evicted; a sponsored
    /// envelope that does not verify is evicted; a verified envelope is
    /// carried only if its nonce is the next in its sender's sequence — the
    /// committed messaging nonce, plus one per envelope from that sender
    /// carried earlier in this block — so each (sender, nonce) is carried at
    /// most once and in order. An envelope below the committed nonce is
    /// evicted. One ahead of the sequence when first seen is deferred and
    /// carried after the pass if the sequence has reached it by then, so a
    /// sender's run of envelopes goes into one block whatever the fee order
    /// put them in; otherwise it waits for a later block. A storage read that
    /// fails leaves the transaction out of this block and in the pool.
    ///
    /// Stops once `max_count` transactions are carried.
    fn screen_for_inclusion(
        &self,
        candidates: impl Iterator<Item = SignedTransaction>,
        max_count: usize,
    ) -> (Vec<SignedTransaction>, Vec<Hash>) {
        let mut carried: Vec<SignedTransaction> = Vec::new();
        let mut evict: Vec<Hash> = Vec::new();
        let mut seen: HashSet<Hash> = HashSet::new();
        // Per named sender: (committed messaging nonce, next nonce this block
        // expects).
        let mut sequence: HashMap<Address, (u64, u64)> = HashMap::new();
        // Verified envelopes ahead of their sender's sequence when first seen.
        let mut deferred: Vec<(SignedTransaction, Address, u64)> = Vec::new();
        for tx in candidates {
            if carried.len() >= max_count {
                break;
            }
            let hash = tx.hash();
            if !seen.insert(hash) {
                continue;
            }
            let Some(policy) = &self.inclusion_policy else {
                carried.push(tx);
                continue;
            };
            match ReceiptStore::new(&policy.db).contains(&hash) {
                Ok(false) => {}
                Ok(true) => {
                    debug!(tx = %hash, "inclusion policy: already included on the canonical chain");
                    evict.push(hash);
                    evict.extend(self.stranded_after_receipt(policy, &tx, &hash));
                    continue;
                }
                Err(e) => {
                    warn!(
                        tx = %hash,
                        "inclusion policy: cannot read the receipt store; leaving this \
                         transaction out of this block: {e}"
                    );
                    continue;
                }
            }
            match sponsored_envelope(&tx) {
                None => carried.push(tx),
                Some(Envelope::Unverified(why)) => {
                    debug!(tx = %hash, "inclusion policy: {why}");
                    evict.push(hash);
                }
                Some(Envelope::Verified { sender, nonce }) => {
                    let (committed, next) = match sequence.get(&sender) {
                        Some(known) => *known,
                        None => match MessagingStore::new(&policy.db).get_sender_nonce(&sender) {
                            Ok(committed) => {
                                sequence.insert(sender, (committed, committed));
                                (committed, committed)
                            }
                            Err(e) => {
                                warn!(
                                    tx = %hash,
                                    "inclusion policy: cannot read the sender's messaging \
                                     nonce; leaving this envelope out of this block: {e}"
                                );
                                continue;
                            }
                        },
                    };
                    if nonce < committed {
                        debug!(
                            tx = %hash,
                            "inclusion policy: envelope nonce {nonce} is below the sender's \
                             messaging nonce {committed}"
                        );
                        evict.push(hash);
                        continue;
                    }
                    if nonce < next {
                        // This block already carries that nonce.
                        continue;
                    }
                    if nonce > next {
                        deferred.push((tx, sender, nonce));
                        continue;
                    }
                    sequence.insert(sender, (committed, next + 1));
                    carried.push(tx);
                }
            }
        }
        // Deferred envelopes, carried in sequence after everything else. Each
        // round carries every envelope the sequence has reached and stops when
        // a round carries nothing. Appending them moves them out of fee order,
        // which decides nothing: a sponsored `SendMessage` advances no account
        // nonce, so its position in the block has no bearing on any validity
        // rule.
        let mut progressed = true;
        while progressed && !deferred.is_empty() && carried.len() < max_count {
            progressed = false;
            let mut i = 0;
            while i < deferred.len() && carried.len() < max_count {
                let (_, sender, nonce) = &deferred[i];
                let Some(&(committed, next)) = sequence.get(sender) else {
                    i += 1;
                    continue;
                };
                if *nonce == next {
                    let sender = *sender;
                    let (tx, _, _) = deferred.remove(i);
                    sequence.insert(sender, (committed, next + 1));
                    carried.push(tx);
                    progressed = true;
                } else {
                    i += 1;
                }
            }
        }
        (carried, evict)
    }

    /// Get mempool size
    pub fn len(&self) -> usize {
        self.txs.read().len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.txs.read().is_empty()
    }

    /// Get all transactions in the mempool
    pub fn get_all(&self) -> Vec<SignedTransaction> {
        self.txs.read().values().map(|e| e.tx.clone()).collect()
    }

    /// Clear all transactions
    pub fn clear(&self) {
        self.txs.write().clear();
        self.by_sender.write().clear();
        self.by_fee.write().clear();
        self.inference_in_flight.write().clear();
        self.education_in_flight.write().clear();
        self.sponsored_in_flight.write().clear();
        info!("Mempool cleared");
    }

    /// Try to evict the lowest fee transaction to make room
    fn try_evict_lowest_fee(&self, new_fee: Balance) -> bool {
        let by_fee = self.by_fee.write();

        // Get lowest fee tx (last in BTreeMap since we use MAX - fee)
        if let Some((fee_key, hash)) = by_fee.iter().next_back().map(|(k, v)| (*k, *v)) {
            let lowest_fee = Balance::MAX - fee_key.0;

            if new_fee > lowest_fee {
                // New tx has higher fee, evict the old one
                drop(by_fee);
                self.remove(&hash);
                debug!("Evicted low-fee tx {} (fee: {})", hash, lowest_fee);
                return true;
            }
        }

        false
    }

    /// Revalidate all transactions against current state.
    ///
    /// With an inclusion policy wired, also drops what the canonical chain has
    /// moved past: a held transaction that now has a receipt, a sponsored
    /// envelope that does not verify, and one whose nonce is below its sender's
    /// committed messaging nonce. Called after a chain switch, when the
    /// canonical chain this pool was admitted against has changed.
    pub fn revalidate(&self, state: &StateManager, chain_id: u64) {
        let hashes: Vec<Hash> = self.txs.read().keys().cloned().collect();
        let mut to_remove = Vec::new();

        for hash in hashes {
            if let Some(tx) = self.get(&hash) {
                // Check basic validity
                if tx.chain_id() != chain_id {
                    to_remove.push(hash);
                    continue;
                }

                if let Some(policy) = &self.inclusion_policy {
                    if matches!(ReceiptStore::new(&policy.db).contains(&hash), Ok(true)) {
                        to_remove.push(hash);
                        to_remove.extend(self.stranded_after_receipt(policy, &tx, &hash));
                        continue;
                    }
                    match sponsored_envelope(&tx) {
                        Some(Envelope::Unverified(_)) => {
                            to_remove.push(hash);
                            continue;
                        }
                        Some(Envelope::Verified { sender, nonce }) => {
                            if let Ok(committed) =
                                MessagingStore::new(&policy.db).get_sender_nonce(&sender)
                            {
                                if nonce < committed {
                                    to_remove.push(hash);
                                    continue;
                                }
                            }
                        }
                        None => {}
                    }
                }

                // Check nonce
                let sender = tx.sender();
                if let Ok(current_nonce) = state.get_nonce(&sender) {
                    if tx.nonce() < current_nonce {
                        to_remove.push(hash);
                        continue;
                    }
                }

                // Check balance
                if let Ok(balance) = state.get_balance(&sender) {
                    let total_cost = tx.amount().saturating_add(tx.fee());
                    if balance < total_cost {
                        to_remove.push(hash);
                    }
                }
            }
        }

        if !to_remove.is_empty() {
            info!("Revalidation removing {} stale transactions", to_remove.len());
            self.remove_batch(&to_remove);
        }
    }

    /// Remove expired transactions from the mempool
    /// Returns the number of transactions removed
    pub fn expire_old_transactions(&self) -> usize {
        if self.config.tx_expiration_secs == 0 {
            return 0; // Expiration disabled
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let expiration_threshold = now.saturating_sub(self.config.tx_expiration_secs * 1000);

        let mut to_remove = Vec::new();

        {
            let txs = self.txs.read();
            for (hash, entry) in txs.iter() {
                if entry.received_at < expiration_threshold {
                    to_remove.push(*hash);
                }
            }
        }

        let count = to_remove.len();
        if count > 0 {
            info!("Expiring {} old transactions from mempool", count);
            self.remove_batch(&to_remove);
        }

        count
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let txs = self.txs.read();
        let by_sender = self.by_sender.read();

        let mut total_fees = 0u128;
        let mut oldest_tx_age_ms = 0u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        for entry in txs.values() {
            total_fees += entry.fee as u128;
            let age = now.saturating_sub(entry.received_at);
            if age > oldest_tx_age_ms {
                oldest_tx_age_ms = age;
            }
        }

        MempoolStats {
            size: txs.len(),
            unique_senders: by_sender.len(),
            total_fees,
            oldest_tx_age_secs: oldest_tx_age_ms / 1000,
            max_size: self.config.max_size,
        }
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Current number of transactions
    pub size: usize,
    /// Number of unique senders
    pub unique_senders: usize,
    /// Total fees of all transactions
    pub total_fees: u128,
    /// Age of the oldest transaction in seconds
    pub oldest_tx_age_secs: u64,
    /// Maximum mempool size
    pub max_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_crypto::{sign, KeyPair};
    use sumchain_primitives::Transaction;

    fn create_signed_tx(
        kp: &KeyPair,
        to: Address,
        amount: Balance,
        fee: Balance,
        nonce: u64,
    ) -> SignedTransaction {
        let tx = Transaction::new(1, kp.address(), to, amount, fee, nonce);
        let signing_hash = tx.signing_hash();
        let sig = sign(signing_hash.as_bytes(), kp.private_key());
        SignedTransaction::new(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
    }

    #[test]
    fn test_add_and_get() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        let hash = tx.hash();

        mempool.add(tx.clone()).unwrap();

        assert!(mempool.contains(&hash));
        assert_eq!(mempool.get(&hash), Some(tx));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);
        let hash = tx.hash();

        mempool.add(tx).unwrap();
        assert!(mempool.contains(&hash));

        mempool.remove(&hash);
        assert!(!mempool.contains(&hash));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_duplicate_rejection() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0);

        mempool.add(tx.clone()).unwrap();
        let result = mempool.add(tx);

        assert!(matches!(result, Err(StateError::TxAlreadyExists)));
    }

    #[test]
    fn beacon_tx_decodes_but_admission_rejects_while_gate_closed() {
        use sumchain_primitives::beacon_wire::{BeaconOperation, RegisterBeaconKeyV1, G1_LEN};
        use sumchain_primitives::{BeaconTxData, TransactionV2, TxType};

        // A well-formed beacon setup op, wrapped and signed as a V2 tx.
        let mut ek = [0x11u8; G1_LEN];
        ek[0] = 0x80; // compressed, non-infinity
        let op = BeaconOperation::RegisterBeaconKey(RegisterBeaconKeyV1 {
            chain_id: 1,
            epoch: 1,
            ek_j: ek,
            pop: [0x22; 96],
        });
        let kp = KeyPair::generate();
        let v2 = TransactionV2 {
            chain_id: 1,
            from: kp.address(),
            fee: 10,
            nonce: 0,
            payload: TxPayload::BeaconSetup(BeaconTxData::from_operation(&op).unwrap()),
        };
        let sig = sign(v2.signing_hash().as_bytes(), kp.private_key());
        let signed = SignedTransaction::new_v2(v2, *sig.as_bytes(), *kp.public_key().as_bytes());

        // (a) It DECODES on the normal consensus path: bytes round-trip and the
        // registered tx type is the beacon setup phase (28).
        let back = SignedTransaction::from_bytes(&signed.to_bytes()).unwrap();
        assert_eq!(back, signed);
        assert_eq!(back.tx_type(), TxType::BeaconSetup);
        assert_eq!(back.tx_type() as u8, 28);

        // (b) But mempool admission deterministically REJECTS it while the beacon
        // gate is closed (the default), and nothing enters the mempool.
        let mempool = Mempool::new(MempoolConfig::default());
        assert!(matches!(
            mempool.add(signed),
            Err(StateError::BeaconNotActivated)
        ));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_fee_sorting() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx1 = create_signed_tx(&sender, recipient.address(), 100, 5, 0);
        let tx2 = create_signed_tx(&sender, recipient.address(), 100, 20, 1);
        let tx3 = create_signed_tx(&sender, recipient.address(), 100, 10, 2);

        mempool.add(tx1).unwrap();
        mempool.add(tx2.clone()).unwrap();
        mempool.add(tx3).unwrap();

        let selected = mempool.select_for_block(1);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].fee(), 20); // Highest fee first
    }

    #[test]
    fn test_min_fee() {
        let config = MempoolConfig {
            min_fee: 100,
            ..Default::default()
        };
        let mempool = Mempool::new(config);
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();

        let tx = create_signed_tx(&sender, recipient.address(), 100, 10, 0); // Fee too low

        let result = mempool.add(tx);
        assert!(matches!(result, Err(StateError::FeeTooLow { .. })));
    }
}

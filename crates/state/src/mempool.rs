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
//! 2. a sponsored `SendMessage` envelope must carry a signature that verifies,
//!    by the key it names as the sender, in a form the next block accepts:
//!    the relay's string preimage, or (with [`InclusionGates`] wired) the
//!    version-2 envelope, which alone is accepted from the envelope
//!    verification gate on;
//! 3. that envelope must carry the sender's expected messaging nonce, and a
//!    candidate block carries each (sender, nonce) at most once, in order,
//!    in one order that also keeps every outer sender's account nonces, and
//!    offers no transaction above a gap in its account's nonces;
//! 4. with [`MessagingQuotaAdmission`] wired, that envelope's sender must have
//!    quota left for it, as the canonical chain counts its sends.
//!
//! Admission and selection are this node's own choices. Nothing here is a
//! consensus rule: a block built by a proposer that applies none of it is
//! validated, executed and imported exactly as before.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::RwLock;
use sumchain_crypto::verify_bytes_strict;
use sumchain_genesis::ChainParams;
use sumchain_primitives::inference_attestation::inference_attestation_key;
use sumchain_primitives::{
    verify_sponsored_send_v2, Address, Balance, Hash, MessagingOperation, Nonce, SignedTransaction,
    SponsoredMessage, TxInner, TxPayload, TxStatus,
};
use sumchain_storage::{Database, MessagingStore, ReceiptStore, StateStore};
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

/// Transaction-signature admission context: the chain params (for
/// `strict_transaction_signatures_enabled_from_height`) and the shared live
/// chain-height `Arc<AtomicU64>`, the same handle the other admission
/// contexts read.
///
/// With it, a transaction whose next-block inclusion height is at or above
/// the strict-signature gate is admitted only if its signature passes the
/// strict rule, which is the rule that block will apply. Below that height
/// admission checks no signature, exactly as before; block execution remains
/// authoritative on both sides. Stored `Option`-ally, like the other contexts.
#[derive(Clone)]
pub struct TransactionSignatureAdmission {
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
///    With [`InclusionGates`] wired the form is the one the next block
///    accepts, judged at its height (the chain tip plus one), as the relay
///    judges it: below
///    `messaging_sponsored_envelope_verification_enabled_from_height`, or
///    while it is unset, the string form above or the version-2 envelope
///    (a strict signature by the named sender over the version-2 preimage
///    for this chain, and no amount), which the executor below the gate also
///    executes; from the gate on, the version-2 envelope only, the one form
///    that block executes. Without it, the string form only, as before.
///
/// 3. **A sponsored envelope carries the sender's expected messaging nonce.**
///    The named sender's messaging nonce is the count of its successful sends
///    as the canonical chain records it: at admission the envelope must
///    continue the sequence that runs from that committed nonce through this
///    node's pending envelopes for the sender; at selection, envelopes are
///    carried in nonce order per sender, each (sender, nonce) at most once per
///    candidate block, and an envelope the chain has moved past is evicted.
///    The block's order keeps that sequence and every outer sender's account
///    nonces together (`in_combined_order`), from each account's committed
///    nonce: a transaction above a gap in its account's nonces that the block
///    does not fill is not offered, nor is anything that depends on it.
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

/// What the inclusion policy needs to judge a transaction by the rules of the
/// block it would land in, the next one: the chain parameters, for the
/// sponsored-envelope verification gate (which envelope forms that block
/// accepts) and the messaging fee-and-nonce accounting gate (whether a
/// relayed `SendMessage` advances its sponsor's account nonce there), the
/// chain id the version-2 envelope binds, and the live chain height. Same
/// shape as [`TransactionSignatureAdmission`]. See
/// [`Mempool::with_inclusion_gates`].
#[derive(Clone)]
pub struct InclusionGates {
    pub params: Arc<ChainParams>,
    pub chain_id: u64,
    pub current_height: Arc<AtomicU64>,
}

/// The sponsored-envelope forms a block accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnvelopeForms {
    /// No [`InclusionGates`] wired: the string form only, as before.
    StringForm,
    /// Below the envelope verification gate: the string form, or the
    /// version-2 envelope for `chain_id`, which the executor below the gate
    /// also executes and which stays valid if it lands at or above it.
    Either { chain_id: u64 },
    /// From the envelope verification gate on: the version-2 envelope for
    /// `chain_id` only.
    Version2 { chain_id: u64 },
}

/// The rules of the next block that the inclusion policy reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NextBlockRules {
    forms: EnvelopeForms,
    /// From the accounting gate on, executing any transaction advances its
    /// sender's account nonce; below it, see
    /// [`advances_nonce_below_accounting_gate`].
    accounting: bool,
}

impl NextBlockRules {
    /// The rules without [`InclusionGates`]: the string form only, and the
    /// account-nonce rule below the accounting gate.
    const UNGATED: Self = Self {
        forms: EnvelopeForms::StringForm,
        accounting: false,
    };
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

/// Why `m` is in no form `forms` accepts; `None` when it is in one.
fn envelope_form_refusal(m: &SponsoredMessage, forms: EnvelopeForms) -> Option<String> {
    const STRING_FORM: &str =
        "the envelope signature does not verify, by the named sender's key, over the relay \
         preimage";
    let version_2 = |chain_id: u64| -> Option<&'static str> {
        if verify_sponsored_send_v2(m, chain_id).is_err() {
            return Some(
                "the envelope signature does not verify, by the named sender's key, over the \
                 version-2 envelope preimage",
            );
        }
        if m.koppa_amount.is_some() {
            return Some("a version-2 envelope carries no amount");
        }
        None
    };
    match forms {
        EnvelopeForms::StringForm => {
            (!sponsored_envelope_verifies(m)).then(|| STRING_FORM.to_string())
        }
        EnvelopeForms::Either { chain_id } => {
            if sponsored_envelope_verifies(m) {
                return None;
            }
            version_2(chain_id).map(|why| format!("neither envelope form is accepted: {why}"))
        }
        EnvelopeForms::Version2 { chain_id } => version_2(chain_id).map(|why| {
            format!(
                "from the envelope verification gate only the version-2 envelope is accepted: \
                 {why}"
            )
        }),
    }
}

/// The envelope of a sponsored `SendMessage`, judged in the forms `forms`
/// accepts; `None` for every other transaction.
fn sponsored_envelope(tx: &SignedTransaction, forms: EnvelopeForms) -> Option<Envelope> {
    let m = match sponsored_message(tx)? {
        Ok(m) => m,
        Err(why) => return Some(Envelope::Unverified(why)),
    };
    if let Some(why) = envelope_form_refusal(&m, forms) {
        return Some(Envelope::Unverified(why));
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
/// A relayed envelope is a transaction FROM the relaying account. Below the
/// messaging fee-and-nonce accounting gate it is signed at that account's
/// committed nonce and executing it advances no account nonce; from that gate
/// on it advances the relaying account's nonce like any other transaction.
/// Either way it also belongs to the named sender's messaging-nonce sequence,
/// which the inclusion policy orders. A proposer that has to leave one out of a block
/// reads this to know which of the block's other transactions depend on it.
pub fn sponsored_envelope_sender(tx: &SignedTransaction) -> Option<Address> {
    sponsored_identity(tx).map(|(sender, _)| sender)
}

/// The hashes a pool evicted above a gap ([`GAP_HOLD_SELECTIONS`]), oldest
/// first, for [`Mempool::evicted_above_a_gap`]. In memory only, and never more
/// entries than the pool has places: the oldest is forgotten first.
#[derive(Debug, Default)]
struct EvictionHistory {
    order: VecDeque<Hash>,
    held: HashSet<Hash>,
}

impl EvictionHistory {
    /// Records `hash` (once), then forgets the oldest entries beyond `cap`.
    fn record(&mut self, hash: Hash, cap: usize) {
        if self.held.insert(hash) {
            self.order.push_back(hash);
        }
        while self.order.len() > cap {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.held.remove(&oldest);
                }
                None => break,
            }
        }
    }

    /// Forgets `hash`, if recorded.
    fn forget(&mut self, hash: &Hash) {
        if self.held.remove(hash) {
            self.order.retain(|h| h != hash);
        }
    }

    fn contains(&self, hash: &Hash) -> bool {
        self.held.contains(hash)
    }

    fn clear(&mut self) {
        self.order.clear();
        self.held.clear();
    }
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
    /// Optional transaction-signature admission context. `None` in tests and
    /// in any path that builds a mempool without it: admission then checks no
    /// signature, as before.
    signature_admission: Option<TransactionSignatureAdmission>,
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
    /// How many of each relaying account's pending transactions are stamped
    /// sponsored envelopes (counted against the sender they name instead).
    /// Kept with the stamp: incremented when an envelope is stamped, decremented
    /// when the stamped carrier is removed.
    relayed_envelopes: RwLock<HashMap<Address, usize>>,
    /// Optional next-block rules for the inclusion policy: which envelope
    /// forms it accepts, and whether a relayed `SendMessage` advances its
    /// sponsor's account nonce. Without it, the string form only and the
    /// account-nonce rule below the accounting gate, as before. See
    /// [`Mempool::with_inclusion_gates`].
    inclusion_gates: Option<InclusionGates>,
    /// Per held sponsored envelope, how many of this node's selections in a
    /// row, from the accounting gate on, have left it out only because its
    /// named sender's earlier envelope is missing or held with another
    /// account ([`CROSS_ACCOUNT_WAIT_SELECTIONS`]). Kept in memory only: a
    /// restarted node counts from nothing.
    cross_account_waits: RwLock<HashMap<Hash, u32>>,
    /// The envelopes the last selection carried out of their named sender's
    /// sequence after that many selections; the screen carries them so again
    /// when the producer applies the policy to the block it builds.
    released_envelopes: RwLock<HashSet<Hash>>,
    /// Per transaction held directly above a gap, how many blocks in a row
    /// have held it ([`GAP_HOLD_SELECTIONS`]). Kept in memory only.
    gap_holds: RwLock<HashMap<Hash, u32>>,
    /// Whether this node has selected since the last head it committed: the
    /// next head's block was then counted by that selection
    /// ([`Mempool::at_new_head`]).
    selected_since_head: AtomicBool,
    /// What this pool evicted above a gap and has not admitted since, at most
    /// `max_size` entries ([`Mempool::evicted_above_a_gap`]).
    gap_evictions: RwLock<EvictionHistory>,
}

/// Whether executing `tx` advances its sender's account nonce below
/// `messaging_fee_nonce_accounting_enabled_from_height`.
///
/// Below that gate a messaging operation advances it only when it charges for
/// itself: a direct send, a paid send, and a sponsored registration. Every
/// other transaction family advances it. (A transaction that is refused may
/// leave it where it was; that cannot be known in advance, and it is counted
/// as advancing.)
pub fn advances_nonce_below_accounting_gate(tx: &SignedTransaction) -> bool {
    match &tx.inner {
        TxInner::V2(v2) => match &v2.payload {
            TxPayload::Messaging(d) => matches!(
                d.operation,
                MessagingOperation::SendMessageDirect
                    | MessagingOperation::SendMessageWithPayment
                    | MessagingOperation::RegisterPublicKeySponsoredV1
            ),
            _ => true,
        },
        _ => true,
    }
}

/// Whether executing `tx` in a block advances its sender's account nonce:
/// every transaction does from the accounting gate on (`accounting`); below
/// it, see [`advances_nonce_below_accounting_gate`].
fn advances_nonce(tx: &SignedTransaction, accounting: bool) -> bool {
    accounting || advances_nonce_below_accounting_gate(tx)
}

/// A transaction's place in the two sequences [`in_combined_order`] keeps.
struct Sequenced {
    /// The account that signs it.
    outer: Address,
    /// Its account nonce, and whether executing it advances that nonce: at
    /// one nonce, a transaction that leaves the nonce where it is comes first.
    key: (Nonce, bool),
    /// For a sponsored envelope, the sender it names and its envelope nonce.
    envelope: Option<(Address, u64)>,
}

/// The transactions of [`in_combined_order`] still to be placed, by outer
/// sender and by named sender, and those ready to be placed.
struct CombinedOrder<'a> {
    seq: &'a [Sequenced],
    /// Per outer sender, the transactions left, by key then position.
    by_outer: HashMap<Address, BTreeSet<((Nonce, bool), usize)>>,
    /// Per named sender, the envelopes left, by envelope nonce then position.
    by_named: HashMap<Address, BTreeSet<(u64, usize)>>,
    left: Vec<bool>,
    /// Positions whose key is the lowest left for their outer sender and,
    /// for an envelope, whose envelope nonce is the lowest left for its
    /// named sender. A position stays ready until it is placed or left out:
    /// what is left only shrinks, so the lowest of a set only rises.
    ready: BTreeSet<usize>,
    /// The committed account nonce of each outer sender, where known
    /// ([`Self::with_committed`]).
    committed: HashMap<Address, Nonce>,
}

impl<'a> CombinedOrder<'a> {
    fn new(seq: &'a [Sequenced]) -> Self {
        let mut by_outer: HashMap<Address, BTreeSet<((Nonce, bool), usize)>> = HashMap::new();
        let mut by_named: HashMap<Address, BTreeSet<(u64, usize)>> = HashMap::new();
        for (i, t) in seq.iter().enumerate() {
            by_outer.entry(t.outer).or_default().insert((t.key, i));
            if let Some((named, nonce)) = t.envelope {
                by_named.entry(named).or_default().insert((nonce, i));
            }
        }
        let mut order = Self {
            seq,
            by_outer,
            by_named,
            left: vec![true; seq.len()],
            ready: BTreeSet::new(),
            committed: HashMap::new(),
        };
        for i in 0..seq.len() {
            order.mark_if_ready(i);
        }
        order
    }

    /// The order, knowing each outer sender's committed account nonce (where
    /// `committed` holds one): a transaction below it holds nothing of its
    /// account behind it ([`Self::leave_out`]).
    fn with_committed(mut self, committed: &HashMap<Address, Option<Nonce>>) -> Self {
        self.committed = committed
            .iter()
            .filter_map(|(account, nonce)| nonce.map(|n| (*account, n)))
            .collect();
        self
    }

    fn is_ready(&self, i: usize) -> bool {
        let t = &self.seq[i];
        let outer_head = self
            .by_outer
            .get(&t.outer)
            .and_then(|left| left.first())
            .is_some_and(|(key, _)| *key == t.key);
        let named_head = t.envelope.is_none_or(|(named, nonce)| {
            self.by_named
                .get(&named)
                .and_then(|left| left.first())
                .is_some_and(|(lowest, _)| *lowest == nonce)
        });
        outer_head && named_head
    }

    fn mark_if_ready(&mut self, i: usize) {
        if self.left[i] && self.is_ready(i) {
            self.ready.insert(i);
        }
    }

    /// Takes `i` out of what is left, and marks what that makes ready: the
    /// next key of its outer sender, when no transaction is left at its own,
    /// and the next envelope of its named sender.
    fn take(&mut self, i: usize) {
        let seq = self.seq;
        let t = &seq[i];
        self.left[i] = false;
        self.ready.remove(&i);
        let mut recheck = Vec::new();
        if let Some(left) = self.by_outer.get_mut(&t.outer) {
            left.remove(&(t.key, i));
            if let Some(&(head, _)) = left.first() {
                if head != t.key {
                    recheck.extend(
                        left.iter()
                            .take_while(|(key, _)| *key == head)
                            .map(|(_, j)| *j),
                    );
                }
            }
        }
        if let Some((named, nonce)) = t.envelope {
            if let Some(left) = self.by_named.get_mut(&named) {
                left.remove(&(nonce, i));
                recheck.extend(left.first().map(|(_, j)| *j));
            }
        }
        for j in recheck {
            self.mark_if_ready(j);
        }
    }

    /// Whether `i`'s key is the lowest left for its outer sender.
    fn is_outer_head(&self, i: usize) -> bool {
        let t = &self.seq[i];
        self.by_outer
            .get(&t.outer)
            .and_then(|left| left.first())
            .is_some_and(|(key, _)| *key == t.key)
    }

    /// The transaction left that `i`, left and not ready, waits on: behind
    /// the head of its outer sender's sequence, that head (the first of it,
    /// by position); at the head, its named sender's lowest envelope left.
    fn waits_on(&self, i: usize) -> Option<usize> {
        let t = &self.seq[i];
        let &(head, first) = self.by_outer.get(&t.outer)?.first()?;
        if head != t.key {
            return Some(first);
        }
        let (named, _) = t.envelope?;
        self.by_named.get(&named)?.first().map(|&(_, j)| j)
    }

    /// With nothing ready (and nothing above a nonce gap, which is left out
    /// first), every transaction left waits on another one left.
    /// Following those waits from the first transaction left, a position
    /// repeats, and the transactions from its first visit on are a cycle.
    /// The victim is the latest of them in `carried` that heads its outer
    /// sender's sequence: every cycle has one, since a transaction behind its
    /// outer sender's head waits on that head. A transaction that only waits
    /// on a cycle is not on it and is never the victim.
    fn cycle_victim(&self) -> Option<usize> {
        let start = self.left.iter().position(|&left| left)?;
        let mut step_of: HashMap<usize, usize> = HashMap::new();
        let mut path = Vec::new();
        let mut at = start;
        while !step_of.contains_key(&at) {
            step_of.insert(at, path.len());
            path.push(at);
            at = self.waits_on(at)?;
        }
        path[step_of[&at]..]
            .iter()
            .copied()
            .filter(|&j| self.is_outer_head(j))
            .max()
    }

    /// The positions whose account nonce no transaction in the block can
    /// reach: those of an outer sender above the first nonce, from its
    /// committed one, at which none of its transactions advances the nonce
    /// (all of them, when the committed nonce could not be read). Outer
    /// senders absent from `committed` are not checked.
    fn beyond_a_gap(&self, committed: &HashMap<Address, Option<Nonce>>) -> Vec<usize> {
        let mut out = Vec::new();
        for (outer, left) in &self.by_outer {
            let Some(known) = committed.get(outer) else {
                continue;
            };
            let Some(mut reach) = *known else {
                out.extend(left.iter().map(|(_, j)| *j));
                continue;
            };
            let advancing: BTreeSet<Nonce> = left
                .iter()
                .filter(|((_, advances), _)| *advances)
                .map(|((nonce, _), _)| *nonce)
                .collect();
            while advancing.contains(&reach) {
                reach += 1;
            }
            out.extend(
                left.iter()
                    .filter(|((nonce, _), _)| *nonce > reach)
                    .map(|(_, j)| *j),
            );
        }
        out.sort_unstable();
        out
    }

    /// Takes out, without placing them, the transactions left of `taken`'s
    /// own account at higher nonces, when `taken` (taken already) advances the
    /// nonce and is not below its account's committed nonce: none of them can
    /// follow a transaction that will not execute. Nothing of another account
    /// goes with them. Taking them out moves their named senders' sequences
    /// on, so those senders' later envelopes through other accounts are placed
    /// when their turn comes, as a broken run never takes another account's
    /// transactions.
    fn take_out_account_tail(&mut self, taken: usize) -> Vec<usize> {
        let seq = self.seq;
        let t = &seq[taken];
        let stale = self
            .committed
            .get(&t.outer)
            .is_some_and(|committed| t.key.0 < *committed);
        if !t.key.1 || stale {
            return Vec::new();
        }
        let tail: Vec<usize> = self
            .by_outer
            .get(&t.outer)
            .map(|left| {
                left.iter()
                    .filter(|((nonce, _), _)| *nonce > t.key.0)
                    .map(|(_, j)| *j)
                    .collect()
            })
            .unwrap_or_default();
        for &j in &tail {
            self.take(j);
        }
        tail
    }

    /// Leaves `victim` out, and every transaction left that depends on it, in
    /// turn: its outer sender's transactions at higher nonces when it
    /// advances the nonce (and is not below its account's committed nonce,
    /// where that is known: such a transaction can never take its nonce, and
    /// nothing waits on it), and its named sender's later envelopes.
    fn leave_out(&mut self, victim: usize) -> Vec<usize> {
        let seq = self.seq;
        let mut out = Vec::new();
        let mut work = vec![victim];
        while let Some(x) = work.pop() {
            if !self.left[x] {
                continue;
            }
            let t = &seq[x];
            let stale = self
                .committed
                .get(&t.outer)
                .is_some_and(|committed| t.key.0 < *committed);
            if t.key.1 && !stale {
                if let Some(left) = self.by_outer.get(&t.outer) {
                    work.extend(
                        left.iter()
                            .filter(|((nonce, _), _)| *nonce > t.key.0)
                            .map(|(_, j)| *j),
                    );
                }
            }
            if let Some((named, nonce)) = t.envelope {
                if let Some(left) = self.by_named.get(&named) {
                    work.extend(
                        left.iter()
                            .filter(|(later, _)| *later > nonce)
                            .map(|(_, j)| *j),
                    );
                }
            }
            self.take(x);
            out.push(x);
        }
        out
    }
}

/// How many of this node's selections a sponsored envelope may be left out,
/// from `messaging_fee_nonce_accounting_enabled_from_height` on, only because
/// its named sender's earlier envelope is not carried with it — that envelope
/// is not in the pool, or is held with another account (above that account's
/// nonce gap, or with a cycle's victim) — while every earlier transaction of
/// its own account is carried. At this many such selections in a row it is
/// carried at its place in its own account's sequence without the earlier
/// envelope, and takes its canonical refusal: from
/// `messaging_sponsored_envelope_verification_enabled_from_height` on a
/// charged failed receipt, its envelope nonce not being its sender's current
/// one; below that gate it executes out of its sender's sequence. Its
/// account's later transactions then follow it.
///
/// From the accounting gate on, each relayed envelope advances its sponsor's
/// account nonce, so an envelope held behind another account's transaction
/// holds its own sponsor's whole queue: without a bound, for as long as the
/// other account leaves its nonce unfilled or the sender does not re-send a
/// missing envelope. This bounds that wait (no queue is held indefinitely)
/// without restricting admission.
///
/// Why three: the selection right after a cycle's victim is evicted must not
/// offer what depends on it, and a gap that is about to be filled
/// (a sponsor's next relayed transaction, a sender's re-send) is given more
/// than one further selection to close before anything is refused; three
/// bounds every such wait at three of this node's proposals.
///
/// The count is of this node's own selections, so in blocks the bound is
/// about three times the number of validators that take turns. For a cycle,
/// the wait counts from the selection that finds the cycle and evicts its
/// victim, so the victim's sponsor has about two more of this node's
/// selections to refill the victim's nonce before the envelopes waiting on
/// it are carried to their charged refusals.
///
/// Only a hold is counted. An envelope left out only because the block is
/// full — its named sender's earlier envelope is in the pool, held by
/// nothing, below the block's limit — waits on room, not on another account:
/// it is not counted, and a later hold gets the whole bound.
///
/// A wait counts when another account's envelope is part of what it waits
/// on (missing from the pool, or relayed by another account and not
/// carried), even if an earlier envelope of its own account's, at a later
/// nonce, is too (a cycle within one sponsor held with another account's
/// hold): a valid, funded outer transaction is never stranded
/// solely by another account's envelope dependency; it reaches its charged
/// refusal within the bound. A wait only on its own account's later
/// envelopes (a cycle within one sponsor and nothing else) is not counted:
/// such a cycle loses a victim in the block. Nothing with a gap in its own
/// account's nonces below it is counted or released, and the executor's
/// checks are never skipped: an outer transaction that cannot pay takes an
/// uncharged `InsufficientBalance`.
///
/// What a premature carry costs: one fee, charged to the envelope's sponsor.
/// The named sender consumes nothing: an envelope whose nonce is not its
/// sender's current one fails before anything of the sender is touched, and
/// the sender's client signs the envelope again once its earlier envelope has
/// executed.
///
/// Node-local proposer selection only: block validity, execution and import
/// are unchanged, and below the accounting gate nothing is counted.
pub const CROSS_ACCOUNT_WAIT_SELECTIONS: u32 = 3;

/// How many blocks in a row a transaction may be held directly — above a gap
/// in its own account's nonces that no transaction in the pool fills, or a
/// sponsored envelope beyond its named sender's first missing envelope nonce
/// ([`Mempool::pool_holds`]) — before it is evicted from the pool. At every
/// height, and on every node: each block is counted once, by this node's
/// selection for it when this node proposes it ([`Mempool::select_for_block`])
/// and otherwise at the head this node commits for it
/// ([`Mempool::at_new_head`]: a block it imports, the new head of a chain
/// switch, counted once). A node that never proposes counts every block at
/// its head, so it evicts as a producer does. In blocks, whatever the number
/// of validators; [`CROSS_ACCOUNT_WAIT_SELECTIONS`] counts this node's own
/// proposals only.
///
/// Such a transaction cannot be carried until its gap is filled, and on main
/// it is offered into an uncharged `InvalidNonce` and deleted with the block.
/// Held without a bound it would keep its place in the pool for good, and
/// enough of them would keep honest transactions out of a full pool. At this
/// many blocks it is evicted instead: the pool's capacity is released,
/// nothing is charged, and its named sender's later envelopes that nothing in
/// the pool can bring into sequence any more are evicted with an envelope, as
/// main evicts them after a failed receipt — below the accounting gate. From
/// the gate on, those relayed by another account than the evicted envelope's
/// are not stranded: they stay, waiting on a missing envelope, and
/// [`CROSS_ACCOUNT_WAIT_SELECTIONS`] carries each to its charged refusal once
/// its own account's earlier transactions are carried. An envelope that this node counts
/// toward [`CROSS_ACCOUNT_WAIT_SELECTIONS`] (a released one keeps its count
/// until it leaves the pool) is neither evicted nor stranded here: that
/// bound governs it, and it is carried to its refusal. The transaction is
/// lost, as on main; the client re-sends. Unlike main, no receipt records it:
/// this node reports it `dropped` while its bounded eviction history keeps it
/// ([`Mempool::evicted_above_a_gap`]), a local observation only.
///
/// Why three: the same number as the bound on a wait on another account,
/// long enough for a gap about to be filled (the sponsor's next relayed
/// transaction, a sender's re-send) to close, short enough that what can
/// never be carried leaves within three blocks.
///
/// Node-local pool policy only: block validity, execution and import are
/// unchanged.
pub const GAP_HOLD_SELECTIONS: u32 = 3;

/// What [`in_combined_order`] leaves out of a block.
#[derive(Debug, Default, PartialEq, Eq)]
struct LeftOut {
    /// One transaction per cycle, to be evicted: no order can carry it with
    /// the transactions it waits on, and held it would hold them all back in
    /// every later block.
    victims: Vec<Hash>,
    /// The transactions that depend on a victim. They stay in the pool.
    dependents: Vec<Hash>,
    /// The transactions above a gap in their account's nonces that no
    /// transaction in the block fills, and those that depend on them. They
    /// stay in the pool until the gap is filled, or, held directly above it,
    /// for at most [`GAP_HOLD_SELECTIONS`] blocks.
    gapped: Vec<Hash>,
}

/// `carried`, in one order that keeps two sequences, and what is left out to
/// keep them.
///
/// - Each outer sender's transactions in ascending account nonce and, at one
///   nonce, those that leave the nonce where it is first
///   ([`advances_nonce`]): fee then hash alone would put a sender's `N+1`
///   before its `N` whenever their fees tie or invert, and the `N+1` would
///   take an `InvalidNonce` receipt in a block that could carry both; and
///   below the accounting gate a relayed `SendMessage` shares its sponsor's
///   nonce with whatever else the sponsor sends at it, and executes only
///   while that nonce is still the account's.
/// - Each named sender's envelopes in ascending envelope nonce, the sequence
///   the inclusion policy's screen carried them in.
///
/// Transactions are placed one at a time: of those whose key is the lowest
/// left for their outer sender and, for an envelope, whose envelope nonce is
/// the lowest left for its named sender, the one earliest in `carried` (the
/// fee order) goes next. An order that already keeps both sequences is
/// returned unchanged.
///
/// When one named sender's envelopes are carried by several sponsors the two
/// sequences can conflict in a cycle that no order keeps. Then a transaction
/// on the cycle is left out as its victim ([`CombinedOrder::cycle_victim`]),
/// with every transaction left that depends on it, in turn: its outer
/// sender's transactions at higher nonces when it advances the nonce, and its
/// named sender's later envelopes.
///
/// `committed` holds the committed account nonce of each outer sender
/// (`None` where it could not be read). A transaction whose account nonce no
/// transaction in the block can reach (the account's committed nonce, or one
/// at which it has a transaction that advances the nonce, is missing below
/// it) is left out first, before anything is placed, with every transaction
/// left that depends on it, in turn, as for a cycle's victim. It is not
/// evicted, and nothing that depends on it is offered into the gap, where it
/// would take an `InvalidNonce` receipt, or a refusal for an envelope out of
/// its named sender's sequence, and be deleted. All of an outer sender's
/// transactions are left out when its committed nonce could not be read.
/// Outer senders absent from `committed` are not checked: their lowest
/// transaction is taken as their next, as in a pool without an inclusion
/// policy.
fn in_combined_order(
    carried: Vec<SignedTransaction>,
    accounting: bool,
    committed: &HashMap<Address, Option<Nonce>>,
) -> (Vec<SignedTransaction>, LeftOut) {
    in_combined_order_releasing(carried, accounting, committed, &HashSet::new())
}

/// [`in_combined_order`], with the envelopes in `released` placed in their
/// own account's sequence only: their named sender's sequence does not hold
/// them, and nothing that leaves with their named sender's earlier envelopes
/// takes them ([`CROSS_ACCOUNT_WAIT_SELECTIONS`]).
fn in_combined_order_releasing(
    carried: Vec<SignedTransaction>,
    accounting: bool,
    committed: &HashMap<Address, Option<Nonce>>,
    released: &HashSet<Hash>,
) -> (Vec<SignedTransaction>, LeftOut) {
    let seq: Vec<Sequenced> = sequenced(&carried, accounting, released);
    let mut order = CombinedOrder::new(&seq).with_committed(committed);
    let mut placed = Vec::with_capacity(seq.len());
    let mut left_out = LeftOut::default();
    let mut remaining = seq.len();
    for gapped in order.beyond_a_gap(committed) {
        let out = order.leave_out(gapped);
        remaining -= out.len();
        left_out
            .gapped
            .extend(out.iter().map(|&x| carried[x].hash()));
    }
    while remaining > 0 {
        if let Some(i) = order.ready.pop_first() {
            order.take(i);
            placed.push(i);
            remaining -= 1;
            continue;
        }
        let Some(victim) = order.cycle_victim() else {
            break;
        };
        let out = order.leave_out(victim);
        remaining -= out.len();
        left_out.victims.push(carried[victim].hash());
        left_out.dependents.extend(
            out.iter()
                .filter(|&&x| x != victim)
                .map(|&x| carried[x].hash()),
        );
    }
    let mut carried: Vec<Option<SignedTransaction>> = carried.into_iter().map(Some).collect();
    let ordered = placed
        .into_iter()
        .filter_map(|i| carried[i].take())
        .collect();
    (ordered, left_out)
}

/// Each transaction's place in the two sequences, with the envelopes in
/// `released` taken out of their named sender's sequence.
fn sequenced(
    txs: &[SignedTransaction],
    accounting: bool,
    released: &HashSet<Hash>,
) -> Vec<Sequenced> {
    txs.iter()
        .map(|tx| Sequenced {
            outer: tx.sender(),
            key: (tx.nonce(), advances_nonce(tx, accounting)),
            envelope: if released.contains(&tx.hash()) {
                None
            } else {
                sponsored_identity(tx)
            },
        })
        .collect()
}

/// What [`Mempool::pool_holds`] holds back from the next block.
#[derive(Debug, Default)]
struct PoolHolds {
    /// The transactions held directly above a gap: above a gap in their own
    /// account's nonces, or an envelope beyond its named sender's first
    /// missing envelope nonce ([`GAP_HOLD_SELECTIONS`]). Not one held because
    /// its account's nonce could not be read.
    direct: HashSet<Hash>,
    /// Those, and every transaction that depends on one of them, in turn.
    held: HashSet<Hash>,
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
            signature_admission: None,
            refuse_contract_transactions: AtomicBool::new(false),
            inclusion_policy: None,
            sponsored_in_flight: RwLock::new(HashMap::new()),
            messaging_quota_admission: None,
            relayed_envelopes: RwLock::new(HashMap::new()),
            inclusion_gates: None,
            cross_account_waits: RwLock::new(HashMap::new()),
            released_envelopes: RwLock::new(HashSet::new()),
            gap_holds: RwLock::new(HashMap::new()),
            selected_since_head: AtomicBool::new(false),
            gap_evictions: RwLock::new(EvictionHistory::default()),
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

    /// Builder: judge sponsored envelopes, at admission, at selection and on
    /// revalidation, by the forms the next block accepts (the inclusion
    /// policy's rule 2), and order a selection by that block's account-nonce
    /// rule ([`Self::select_for_block`]). The forms refine the policy's rules,
    /// so without a wired [`InclusionPolicy`] only the order changes.
    ///
    /// Node-local, like the rest of the policy: it decides which envelopes
    /// this node holds and carries, never what a block means.
    pub fn with_inclusion_gates(mut self, gates: InclusionGates) -> Self {
        self.inclusion_gates = Some(gates);
        self
    }

    /// The rules of the next block, judged at its height (the live chain
    /// height plus one); [`NextBlockRules::UNGATED`] without
    /// [`InclusionGates`].
    fn next_block_rules(&self) -> NextBlockRules {
        let Some(gates) = &self.inclusion_gates else {
            return NextBlockRules::UNGATED;
        };
        self.block_rules(
            gates
                .current_height
                .load(Ordering::Relaxed)
                .saturating_add(1),
        )
    }

    /// The inclusion rules of the block at `height`.
    fn block_rules(&self, height: u64) -> NextBlockRules {
        let Some(gates) = &self.inclusion_gates else {
            return NextBlockRules::UNGATED;
        };
        let forms = if MessagingExecutor::sponsored_envelope_verification_gate_open(
            &gates.params,
            height,
        ) {
            EnvelopeForms::Version2 {
                chain_id: gates.chain_id,
            }
        } else {
            EnvelopeForms::Either {
                chain_id: gates.chain_id,
            }
        };
        NextBlockRules {
            forms,
            accounting: MessagingExecutor::fee_nonce_accounting_gate_open(&gates.params, height),
        }
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

    /// Builder: attach the transaction-signature admission context. Without
    /// it no signature is checked at admission, at any height.
    pub fn with_signature_admission(mut self, admission: TransactionSignatureAdmission) -> Self {
        self.signature_admission = Some(admission);
        self
    }

    /// The height a transaction admitted now would be included at: the block
    /// after the current chain tip. `None` without a signature admission
    /// context.
    pub fn signature_inclusion_height(&self) -> Option<u64> {
        self.signature_admission
            .as_ref()
            .map(|ctx| ctx.current_height.load(Ordering::Relaxed).saturating_add(1))
    }

    /// Transaction-signature admission. From the strict-signature gate's
    /// height on, judged at the transaction's inclusion height (the next
    /// block's, see [`Self::signature_inclusion_height`]), the signature must
    /// pass the strict rule that block will apply; a transaction it refuses
    /// would only ever be included as an `InvalidSignature` receipt. Below that
    /// height, and without a context, nothing is checked here, as before.
    fn check_signature_admission(&self, tx: &SignedTransaction) -> Result<()> {
        let (Some(ctx), Some(inclusion_height)) =
            (&self.signature_admission, self.signature_inclusion_height())
        else {
            return Ok(());
        };
        if !crate::tx_signature::strict_transaction_signatures_gate_open(
            &ctx.params,
            inclusion_height,
        ) {
            return Ok(());
        }
        crate::tx_signature::verify_transaction_signature(
            &ctx.params,
            inclusion_height,
            tx.signing_hash().as_bytes(),
            &tx.signature,
            &tx.public_key,
        )
        .map_err(|_| StateError::InvalidSignature)
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

        // The signature rule of the inclusion height, from the strict-signature
        // gate on. No-op below it and without a context.
        self.check_signature_admission(&tx)?;

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

        // Check per-sender limit.
        //
        // A sponsored envelope this node's policy admitted — its signature
        // verified, strictly, by the key of the sender it names — is held
        // against that NAMED sender, not the account that relays it: a relay
        // serves many senders, and each has its own allowance. Every other
        // transaction is held against its own account, not counting the
        // envelopes that account relays. Without a wired policy nothing is
        // stamped as an envelope, and every transaction counts against its own
        // account, as before. The pool-wide bound (`max_size`) is unchanged.
        {
            let held = match &sponsored_key {
                Some((named, _)) => self
                    .sponsored_in_flight
                    .read()
                    .get(named)
                    .map_or(0, |nonces| nonces.len()),
                None => {
                    let all = self
                        .by_sender
                        .read()
                        .get(&sender)
                        .map_or(0, |txs| txs.len());
                    let relayed = self
                        .relayed_envelopes
                        .read()
                        .get(&sender)
                        .copied()
                        .unwrap_or(0);
                    all.saturating_sub(relayed)
                }
            };
            if held >= self.config.max_per_sender {
                return Err(StateError::MempoolFull);
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
        if let Some((named, nonce)) = sponsored_key {
            let mut in_flight = self.sponsored_in_flight.write();
            let raced = in_flight
                .get(&named)
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
            in_flight.entry(named).or_default().insert(nonce, hash);
            // Lock order: `sponsored_in_flight`, then `relayed_envelopes`, as
            // in `remove`.
            *self.relayed_envelopes.write().entry(sender).or_default() += 1;
        }

        // Admitted again: no longer dropped here. Only a successful admission
        // clears it; a refused one leaves it.
        self.gap_evictions.write().forget(&hash);

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
        match sponsored_envelope(tx, self.next_block_rules().forms) {
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
                    let relay = entry.tx.sender();
                    let mut relayed = self.relayed_envelopes.write();
                    if let Some(n) = relayed.get_mut(&relay) {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            relayed.remove(&relay);
                        }
                    }
                }
                if nonces.is_empty() {
                    in_flight.remove(&sender);
                }
            }
        }

        self.cross_account_waits.write().remove(hash);
        self.released_envelopes.write().remove(hash);
        self.gap_holds.write().remove(hash);

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
    ///
    /// What is carried is returned in one order that keeps each outer
    /// sender's account nonces and each named sender's envelope nonces
    /// ([`in_combined_order`]), judged by the next block's account-nonce rule.
    /// Where the two conflict in a cycle, one transaction of the cycle is
    /// evicted and those that depend on it wait in the pool.
    ///
    /// With an inclusion policy wired, each outer sender's committed account
    /// nonce is read too, and a transaction above a gap in its account's
    /// nonces that the block does not fill is not offered: it waits in the
    /// pool, with what depends on it, until the gap is filled
    /// ([`in_combined_order`]), for at most [`GAP_HOLD_SELECTIONS`] blocks. A
    /// cycle's victim leaves such a gap behind it when it advances its
    /// account's nonce.
    ///
    /// What waits is decided over the whole pool before the pool is cut to
    /// `max_count` ([`Self::pool_holds`]): a transaction that waits never
    /// takes a place in the block from one that can be carried. The cut then
    /// takes what can be carried account by account and named sender by named
    /// sender ([`Self::within_the_block_limit`]): nothing enters it ahead of
    /// its account's or its named sender's predecessor, and nothing that
    /// depends on a transaction its account cannot pay for. Nothing waits
    /// without a bound: from the accounting gate an envelope that waits on
    /// another account is carried to its refusal after
    /// [`CROSS_ACCOUNT_WAIT_SELECTIONS`] selections, and at every height a
    /// transaction held above a gap is evicted after [`GAP_HOLD_SELECTIONS`]
    /// blocks (counted here for the block this selection is for, and at the
    /// head of every other block, [`Self::at_new_head`]).
    pub fn select_for_block(&self, max_count: usize) -> Vec<SignedTransaction> {
        let rules = self.next_block_rules();
        let mut pool = self.pool_in_fee_order();
        let committed = self.committed_account_nonces(pool.iter());
        let mut holds = self.pool_holds(&pool, rules.accounting, &committed);
        // From the accounting gate, an envelope that has waited on another
        // account for CROSS_ACCOUNT_WAIT_SELECTIONS selections is released
        // in this one: carried in its own account's sequence only.
        let released =
            self.released_cross_account_waits(rules.accounting, &pool, &holds, &committed);
        if !released.is_empty() {
            info!(
                "Inclusion policy: carrying {} envelope(s) that waited {} selections in a row \
                 on another account; each takes its refusal and its account's queue moves",
                released.len(),
                CROSS_ACCOUNT_WAIT_SELECTIONS
            );
        }
        // This selection counts the block it is for: a transaction held
        // directly for GAP_HOLD_SELECTIONS blocks in a row is evicted in it,
        // with what its eviction strands, unless the cross-account bound
        // governs it.
        self.selected_since_head.store(true, Ordering::SeqCst);
        let governed = self.governed_by_the_cross_account_bound(&released);
        let expired = self.expired_gap_holds(&holds, &governed);
        if !expired.is_empty() {
            let gone = self.evict_gap_holds(&pool, &expired, &governed, rules.accounting);
            info!(
                "Inclusion policy: evicting {} transaction(s) held {} blocks in a row above \
                 a gap in their account's or their named sender's nonces, and {} envelope(s) \
                 that nothing in the pool can bring into sequence any more",
                expired.len(),
                GAP_HOLD_SELECTIONS,
                gone.len() - expired.len()
            );
            pool.retain(|tx| !gone.contains(&tx.hash()));
        }
        if !released.is_empty() || !expired.is_empty() {
            holds = self.pool_holds_releasing(&pool, rules.accounting, &committed, &released);
        }
        self.count_gap_holds(&holds);
        *self.released_envelopes.write() = released.clone();
        if !holds.held.is_empty() {
            info!(
                "Inclusion policy: leaving {} transaction(s) above a gap in their account's \
                 or their named sender's nonces, or depending on one, for a later block",
                holds.held.len()
            );
        }
        // The block's limit is applied account by account and named sender by
        // named sender, never ahead of a predecessor (`within_the_block_limit`).
        let candidates = self.within_the_block_limit(
            pool.iter()
                .filter(|tx| !holds.held.contains(&tx.hash()))
                .cloned()
                .collect(),
            max_count,
            rules.accounting,
            &committed,
            &released,
        );
        let (carried, evict) =
            self.screen_for_inclusion(candidates.into_iter(), max_count, rules.forms);
        if !evict.is_empty() {
            info!(
                "Inclusion policy: evicting {} held transaction(s) the canonical chain has \
                 moved past",
                evict.len()
            );
            self.remove_batch(&evict);
        }
        let (ordered, left_out) = if released.is_empty() {
            in_combined_order(carried, rules.accounting, &committed)
        } else {
            in_combined_order_releasing(carried, rules.accounting, &committed, &released)
        };
        if !left_out.gapped.is_empty() {
            debug!(
                "Inclusion policy: leaving {} transaction(s) whose account's earlier nonce was \
                 cut from this block for a later block",
                left_out.gapped.len()
            );
        }
        if !left_out.victims.is_empty() {
            info!(
                "Inclusion policy: {} transaction(s) wait on each other in a cycle of account \
                 and envelope nonces; evicting {} and leaving {} for a later block",
                left_out.victims.len() + left_out.dependents.len(),
                left_out.victims.len(),
                left_out.dependents.len()
            );
            self.remove_batch(&left_out.victims);
        }
        self.count_cross_account_waits(
            rules.accounting,
            &pool,
            &ordered,
            &holds.held,
            &left_out,
            &evict,
            &released,
            &committed,
        );
        ordered
    }

    /// How many selections in a row `hash` has been counted as waiting on
    /// another account ([`CROSS_ACCOUNT_WAIT_SELECTIONS`]); 0 when it is not.
    pub fn cross_account_wait_count(&self, hash: &Hash) -> u32 {
        self.cross_account_waits
            .read()
            .get(hash)
            .copied()
            .unwrap_or(0)
    }

    /// How many blocks in a row `hash` has been held directly above a gap
    /// ([`GAP_HOLD_SELECTIONS`]); 0 when it is not.
    pub fn gap_hold_count(&self, hash: &Hash) -> u32 {
        self.gap_holds.read().get(hash).copied().unwrap_or(0)
    }

    /// Counts the block whose head this node has just committed toward
    /// [`GAP_HOLD_SELECTIONS`], unless this node's own selection counted it,
    /// and evicts what reaches the bound with it.
    ///
    /// The consensus engine calls this on every node after each head it
    /// commits, once the pool has dropped what that head's block carries: a
    /// block this node produced, a block it imported, the new head of a chain
    /// switch (once, after the switch's reconciliation). When this node has
    /// selected since the last head, that selection counted this block
    /// ([`Self::select_for_block`]) and nothing more is done; otherwise —
    /// always, on a node that never proposes — the pool is viewed as the next
    /// block's selection views it ([`Self::pool_holds`], under the rules of
    /// the block at `head + 1`) and counted as a selection counts it: what
    /// reaches the bound is evicted with no receipt, with its named sender's
    /// later envelopes that nothing left in the pool can bring into sequence
    /// ([`Self::stranded_envelopes`]), except an envelope the cross-account
    /// bound governs; then each transaction held directly has its count
    /// raised by one and every other count is dropped. Nothing is verified,
    /// charged or written; without an inclusion policy nothing happens.
    pub fn at_new_head(&self, head: u64) {
        if self.selected_since_head.swap(false, Ordering::SeqCst) {
            return;
        }
        if self.inclusion_policy.is_none() {
            return;
        }
        let rules = self.block_rules(head.saturating_add(1));
        let mut pool = self.pool_in_fee_order();
        let committed = self.committed_account_nonces(pool.iter());
        let released = self.released_envelopes.read().clone();
        let mut holds = self.pool_holds_releasing(&pool, rules.accounting, &committed, &released);
        let governed = self.governed_by_the_cross_account_bound(&released);
        let expired = self.expired_gap_holds(&holds, &governed);
        if !expired.is_empty() {
            let gone = self.evict_gap_holds(&pool, &expired, &governed, rules.accounting);
            info!(
                "Inclusion policy: at head {head}, evicting {} transaction(s) held {} blocks in \
                 a row above a gap in their account's or their named sender's nonces, and {} \
                 envelope(s) that nothing in the pool can bring into sequence any more",
                expired.len(),
                GAP_HOLD_SELECTIONS,
                gone.len() - expired.len()
            );
            pool.retain(|tx| !gone.contains(&tx.hash()));
            holds = self.pool_holds_releasing(&pool, rules.accounting, &committed, &released);
        }
        self.count_gap_holds(&holds);
    }

    /// Every transaction this pool holds, in fee order (as `by_fee` keeps it),
    /// without a contract transaction while this node refuses them.
    fn pool_in_fee_order(&self) -> Vec<SignedTransaction> {
        let by_fee = self.by_fee.read();
        let txs = self.txs.read();
        let refuse_contracts = self.refuses_contract_transactions();
        // Nothing held can be a contract transaction while the refusal is on
        // (see `set_refuse_contract_transactions`); the filter is a second
        // line.
        by_fee
            .values()
            .filter_map(|hash| txs.get(hash).map(|e| e.tx.clone()))
            .filter(|tx| !(refuse_contracts && is_contract_transaction(tx)))
            .collect()
    }

    /// The envelopes the cross-account bound governs, which the gap-hold
    /// bound neither evicts nor strands: those this node counts toward
    /// [`CROSS_ACCOUNT_WAIT_SELECTIONS`] (a released one keeps its count until
    /// it leaves the pool), and those `released` in this selection.
    fn governed_by_the_cross_account_bound(&self, released: &HashSet<Hash>) -> HashSet<Hash> {
        let mut governed: HashSet<Hash> = self
            .cross_account_waits
            .read()
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(hash, _)| *hash)
            .collect();
        governed.extend(released.iter().copied());
        governed
    }

    /// The transactions the pool view `holds` holds directly that were held
    /// directly in the `GAP_HOLD_SELECTIONS - 1` blocks before this one,
    /// other than those in `governed`.
    fn expired_gap_holds(&self, holds: &PoolHolds, governed: &HashSet<Hash>) -> Vec<Hash> {
        let counts = self.gap_holds.read();
        let mut expired: Vec<Hash> = holds
            .direct
            .iter()
            .filter(|hash| {
                !governed.contains(hash)
                    && counts.get(hash).copied().unwrap_or(0) + 1 >= GAP_HOLD_SELECTIONS
            })
            .copied()
            .collect();
        expired.sort();
        expired
    }

    /// Evicts `expired` from the pool and, for each envelope among them, its
    /// named sender's later envelopes that nothing left in the pool can bring
    /// into sequence ([`Self::stranded_envelopes`], as after a failed
    /// receipt), other than those in `governed` and, from the accounting gate
    /// (`accounting`), those relayed by another account than the evicted
    /// envelope's: those stay for the cross-account bound. Returns everything
    /// evicted.
    fn evict_gap_holds(
        &self,
        pool: &[SignedTransaction],
        expired: &[Hash],
        governed: &HashSet<Hash>,
        accounting: bool,
    ) -> HashSet<Hash> {
        let mut gone: HashSet<Hash> = expired.iter().copied().collect();
        if let Some(policy) = &self.inclusion_policy {
            let by_hash: HashMap<Hash, &SignedTransaction> =
                pool.iter().map(|tx| (tx.hash(), tx)).collect();
            let messaging = MessagingStore::new(&policy.db);
            for hash in expired {
                let Some(evicted) = by_hash.get(hash) else {
                    continue;
                };
                let Some((sender, _)) = sponsored_identity(evicted) else {
                    continue;
                };
                let relay = evicted.sender();
                if let Ok(committed) = messaging.get_sender_nonce(&sender) {
                    gone.extend(
                        self.stranded_envelopes(&sender, committed, hash)
                            .into_iter()
                            .filter(|stranded| !governed.contains(stranded))
                            .filter(|stranded| {
                                !accounting
                                    || by_hash.get(stranded).is_some_and(|tx| tx.sender() == relay)
                            }),
                    );
                }
            }
        }
        let mut evict: Vec<Hash> = gone.iter().copied().collect();
        evict.sort();
        self.remove_batch(&evict);
        let mut history = self.gap_evictions.write();
        for hash in &evict {
            history.record(*hash, self.config.max_size);
        }
        gone
    }

    /// Whether this node's pool evicted `hash` above a gap
    /// ([`GAP_HOLD_SELECTIONS`]), with no receipt, and has not admitted it
    /// since. The history is in memory only and holds at most as many entries
    /// as the pool has places (`max_size`), the oldest forgotten first; it is
    /// empty after a restart. Only a successful admission clears an entry.
    ///
    /// A local observation: another node may still hold the transaction, or
    /// carry it in a block. It is not proof that the transaction will not be
    /// delivered, and a client should not sign a new transaction for the same
    /// intent because of it alone: a canonical receipt, and the client's own
    /// check of what its intent needs (for an envelope, its sender's
    /// messaging nonce and whether the message executed), decide.
    pub fn evicted_above_a_gap(&self, hash: &Hash) -> bool {
        self.gap_evictions.read().contains(hash)
    }

    /// Counts a block for [`GAP_HOLD_SELECTIONS`]: each transaction the pool
    /// view `holds` holds directly has its count raised by one; every other
    /// count is dropped.
    fn count_gap_holds(&self, holds: &PoolHolds) {
        let mut counts = self.gap_holds.write();
        counts.retain(|hash, _| holds.direct.contains(hash));
        for hash in &holds.direct {
            *counts.entry(*hash).or_insert(0) += 1;
        }
    }

    /// The envelopes to release in this selection: from the accounting gate
    /// on, those that the pool view `holds` holds only because of another
    /// account ([`Self::waiting_on_another_account`], with everything not
    /// held taken as carried) and that were counted in the
    /// `CROSS_ACCOUNT_WAIT_SELECTIONS - 1` selections before this one.
    fn released_cross_account_waits(
        &self,
        accounting: bool,
        pool: &[SignedTransaction],
        holds: &PoolHolds,
        committed: &HashMap<Address, Option<Nonce>>,
    ) -> HashSet<Hash> {
        if !accounting {
            return HashSet::new();
        }
        let carriable: Vec<&SignedTransaction> = pool
            .iter()
            .filter(|tx| !holds.held.contains(&tx.hash()))
            .collect();
        let waiting = self.waiting_on_another_account(
            pool.iter().filter(|tx| holds.held.contains(&tx.hash())),
            carriable.iter().copied(),
            committed,
        );
        let counts = self.cross_account_waits.read();
        waiting
            .into_iter()
            .filter(|hash| {
                counts.get(hash).copied().unwrap_or(0) + 1 >= CROSS_ACCOUNT_WAIT_SELECTIONS
            })
            .collect()
    }

    /// Counts this selection for [`CROSS_ACCOUNT_WAIT_SELECTIONS`], from its
    /// final placement `ordered`: each envelope of the pool that is held —
    /// over the whole pool (`held`, [`Self::pool_holds`]) or with a cycle's
    /// victim (`left_out`'s dependents) — and waits only on another account,
    /// and each envelope `released` in it, has its count raised by one; every
    /// other count is dropped. An envelope left out only because the block is
    /// full waits on room, not on an account, and is not counted: a fee cut
    /// alone never releases it, and it must not carry a count into a later
    /// hold. A released envelope keeps its count until it leaves the pool, so
    /// that it is released again if the block that carries it is not made.
    /// Below the accounting gate, and without an inclusion policy, nothing is
    /// counted.
    #[allow(clippy::too_many_arguments)]
    fn count_cross_account_waits(
        &self,
        accounting: bool,
        pool: &[SignedTransaction],
        ordered: &[SignedTransaction],
        held: &HashSet<Hash>,
        left_out: &LeftOut,
        evicted: &[Hash],
        released: &HashSet<Hash>,
        committed: &HashMap<Address, Option<Nonce>>,
    ) {
        if !accounting || self.inclusion_policy.is_none() {
            self.cross_account_waits.write().clear();
            return;
        }
        let placed: HashSet<Hash> = ordered.iter().map(|tx| tx.hash()).collect();
        let gone: HashSet<Hash> = left_out
            .victims
            .iter()
            .chain(evicted.iter())
            .copied()
            .collect();
        let with_a_victim: HashSet<Hash> = left_out.dependents.iter().copied().collect();
        let waiting = self.waiting_on_another_account(
            pool.iter().filter(|tx| {
                let hash = tx.hash();
                !placed.contains(&hash)
                    && !gone.contains(&hash)
                    && (held.contains(&hash) || with_a_victim.contains(&hash))
            }),
            ordered.iter(),
            committed,
        );
        let counted: HashSet<Hash> = waiting.union(released).copied().collect();
        let mut counts = self.cross_account_waits.write();
        counts.retain(|hash, _| counted.contains(hash));
        for hash in counted {
            *counts.entry(hash).or_insert(0) += 1;
        }
    }

    /// The sponsored envelopes among `left` that wait only on another account
    /// when `carried` are the transactions carried: every earlier transaction
    /// of their own account is carried (the account's nonce, from its
    /// committed one through the carried transactions that advance it,
    /// reaches theirs), and among their named sender's envelopes from its
    /// committed messaging nonce up to theirs at least one that is not
    /// carried is missing from the pool or relayed by another account (others
    /// not carried may be relayed by their own account, at a later nonce: a
    /// cycle within one sponsor, held with another account's hold).
    fn waiting_on_another_account<'a>(
        &self,
        left: impl Iterator<Item = &'a SignedTransaction>,
        carried: impl Iterator<Item = &'a SignedTransaction>,
        committed: &HashMap<Address, Option<Nonce>>,
    ) -> HashSet<Hash> {
        let Some(policy) = &self.inclusion_policy else {
            return HashSet::new();
        };
        let mut carried_hashes: HashSet<Hash> = HashSet::new();
        let mut advancing: HashMap<Address, BTreeSet<Nonce>> = HashMap::new();
        for tx in carried {
            carried_hashes.insert(tx.hash());
            if advances_nonce(tx, true) {
                advancing.entry(tx.sender()).or_default().insert(tx.nonce());
            }
        }
        let reach = |account: &Address| -> Option<Nonce> {
            let mut n = (*committed.get(account)?)?;
            if let Some(nonces) = advancing.get(account) {
                while nonces.contains(&n) {
                    n += 1;
                }
            }
            Some(n)
        };
        let messaging = MessagingStore::new(&policy.db);
        let mut messaging_nonces: HashMap<Address, Option<u64>> = HashMap::new();
        let txs = self.txs.read();
        let in_flight = self.sponsored_in_flight.read();
        let mut waiting = HashSet::new();
        for tx in left {
            let Some((named, nonce)) = sponsored_identity(tx) else {
                continue;
            };
            let own = tx.sender();
            if reach(&own) != Some(tx.nonce()) {
                continue;
            }
            let from = *messaging_nonces
                .entry(named)
                .or_insert_with(|| messaging.get_sender_nonce(&named).ok());
            let Some(from) = from else {
                continue;
            };
            let pending = in_flight.get(&named);
            let mut by_another_account = false;
            for earlier in from..nonce {
                match pending.and_then(|nonces| nonces.get(&earlier)) {
                    None => by_another_account = true,
                    Some(carrier) if carried_hashes.contains(carrier) => {}
                    Some(carrier) => {
                        if !txs.get(carrier).is_some_and(|e| e.tx.sender() == own) {
                            by_another_account = true;
                        }
                    }
                }
            }
            if by_another_account {
                waiting.insert(tx.hash());
            }
        }
        waiting
    }

    /// The transactions of `candidates` (the pool less what it holds, in fee
    /// order) that go to the screen for a block of at most `max_count`, in fee
    /// order. Every one of them when they fit and each can pay for itself.
    ///
    /// They are taken one at a time as [`in_combined_order`] places them: of
    /// those whose key is the lowest left for their account and, for an
    /// envelope, whose envelope nonce is the lowest left for its named sender,
    /// the earliest in fee order. So nothing is taken ahead of its account's
    /// or its named sender's predecessor: a run is taken behind its cheapest
    /// transaction so far, and later transactions priced above the cut never
    /// take its places while their predecessor is below it, to be left out of
    /// the block after the cut.
    ///
    /// A transaction its account cannot pay for — by the executor's check
    /// before execution: the account's committed balance, less the amount and
    /// fee of what was taken before it from the account, plus the amounts
    /// transactions taken before it pay to the account, is below its own
    /// amount and fee — is still taken, and takes its uncharged
    /// `InsufficientBalance` receipt in the block, as on main. Its own
    /// account's later nonces are not taken when it advances the nonce
    /// ([`CombinedOrder::take_out_account_tail`]): they cannot follow it, and
    /// stay in the pool, where the next selection finds them above a gap.
    /// Nothing of another account is held back for it: its named sender's
    /// later envelopes through other accounts are taken when their turn comes,
    /// and take the outcome their envelope nonce meets (from
    /// `messaging_sponsored_envelope_verification_enabled_from_height` a
    /// refusal, charged from the accounting gate; below it they execute out
    /// of their sender's sequence, as on main), and their accounts' queues
    /// move: an unpayable envelope resent before every block cannot hold
    /// another relay's queue. An account whose balance cannot be
    /// read is not checked.
    ///
    /// When nothing is ready (a cycle of account and envelope nonces), the
    /// rest is taken in fee order, and the combined order deals with the cycle
    /// within the block as before.
    ///
    /// Without an inclusion policy (which cannot read state) the candidates
    /// are returned as they are, and the screen cuts them in fee order, as
    /// before.
    fn within_the_block_limit(
        &self,
        candidates: Vec<SignedTransaction>,
        max_count: usize,
        accounting: bool,
        committed: &HashMap<Address, Option<Nonce>>,
        released: &HashSet<Hash>,
    ) -> Vec<SignedTransaction> {
        if self.inclusion_policy.is_none() {
            return candidates;
        }
        let seq = sequenced(&candidates, accounting, released);
        let mut order = CombinedOrder::new(&seq).with_committed(committed);
        let mut spendable = self.committed_account_balances(candidates.iter());
        let mut taken: Vec<usize> = Vec::new();
        while taken.len() < max_count {
            let Some(i) = order.ready.pop_first() else {
                taken.extend(
                    (0..seq.len())
                        .filter(|&j| order.left[j])
                        .take(max_count - taken.len()),
                );
                break;
            };
            order.take(i);
            taken.push(i);
            let tx = &candidates[i];
            let cost = tx.amount().saturating_add(tx.fee());
            let Some(balance) = spendable.get_mut(&tx.sender()) else {
                continue;
            };
            if *balance < cost {
                order.take_out_account_tail(i);
                continue;
            }
            *balance -= cost;
            if let Some(to) = tx.recipient() {
                if let Some(credited) = spendable.get_mut(&to) {
                    *credited = credited.saturating_add(tx.amount());
                }
            }
        }
        taken.sort_unstable();
        let mut candidates: Vec<Option<SignedTransaction>> =
            candidates.into_iter().map(Some).collect();
        taken
            .into_iter()
            .filter_map(|i| candidates[i].take())
            .collect()
    }

    /// The committed balance of each account that signs one of `txs`, read
    /// through the inclusion policy's database; an account whose balance
    /// cannot be read is left out. Empty without a wired policy.
    fn committed_account_balances<'a>(
        &self,
        txs: impl Iterator<Item = &'a SignedTransaction>,
    ) -> HashMap<Address, Balance> {
        let Some(policy) = &self.inclusion_policy else {
            return HashMap::new();
        };
        let store = StateStore::new(&policy.db);
        let mut balances = HashMap::new();
        for tx in txs {
            let sender = tx.sender();
            if balances.contains_key(&sender) {
                continue;
            }
            match store.get_balance(&sender) {
                Ok(balance) => {
                    balances.insert(sender, balance);
                }
                Err(e) => warn!(
                    sender = %sender.to_base58(),
                    "inclusion policy: cannot read the account balance; not checking what \
                     the account can pay for in this block: {e}"
                ),
            }
        }
        balances
    }

    /// The committed account nonce of each account that signs one of
    /// `carried`, read through the inclusion policy's database, as the
    /// policy reads receipts and messaging nonces: the canonical chain as it
    /// stands now. `None` for an account whose nonce cannot be read, whose
    /// transactions then wait for a later block. Empty without a wired
    /// policy, and then no account's nonces are checked.
    fn committed_account_nonces<'a>(
        &self,
        carried: impl Iterator<Item = &'a SignedTransaction>,
    ) -> HashMap<Address, Option<Nonce>> {
        let Some(policy) = &self.inclusion_policy else {
            return HashMap::new();
        };
        let store = StateStore::new(&policy.db);
        let mut committed = HashMap::new();
        for tx in carried {
            let sender = tx.sender();
            committed
                .entry(sender)
                .or_insert_with(|| match store.get_nonce(&sender) {
                    Ok(nonce) => Some(nonce),
                    Err(e) => {
                        warn!(
                            sender = %sender.to_base58(),
                            "inclusion policy: cannot read the account nonce; leaving the \
                             account's transactions out of this block: {e}"
                        );
                        None
                    }
                });
        }
        committed
    }

    /// What of `pool` (the whole pool, in fee order) cannot be carried in the
    /// next block whatever else it carries, judged before the pool is cut to
    /// a block's size, so that none of it takes a place in the block.
    ///
    /// Held directly: a transaction above a gap in its own account's nonces
    /// that no transaction in the pool fills (as [`in_combined_order`] judges
    /// it, from `committed`), and a sponsored envelope beyond the first
    /// envelope nonce, from its named sender's committed messaging nonce, that
    /// no envelope in the pool carries (the screen would only defer it). Held
    /// in turn: every transaction that depends on one held, as for a cycle's
    /// victim ([`CombinedOrder::leave_out`]): its account's later nonces when
    /// it advances the nonce, and its named sender's later envelopes.
    ///
    /// Nothing is verified or evicted here; the screen still judges what is
    /// not held. Without an inclusion policy nothing is held.
    fn pool_holds(
        &self,
        pool: &[SignedTransaction],
        accounting: bool,
        committed: &HashMap<Address, Option<Nonce>>,
    ) -> PoolHolds {
        self.pool_holds_releasing(pool, accounting, committed, &HashSet::new())
    }

    /// [`Self::pool_holds`], with the envelopes in `released` out of their
    /// named sender's sequence: each is held only by its own account
    /// ([`CROSS_ACCOUNT_WAIT_SELECTIONS`]).
    fn pool_holds_releasing(
        &self,
        pool: &[SignedTransaction],
        accounting: bool,
        committed: &HashMap<Address, Option<Nonce>>,
        released: &HashSet<Hash>,
    ) -> PoolHolds {
        let Some(policy) = &self.inclusion_policy else {
            return PoolHolds::default();
        };
        let seq = sequenced(pool, accounting, released);
        let mut order = CombinedOrder::new(&seq).with_committed(committed);
        let account_gapped = order.beyond_a_gap(committed);
        let messaging = MessagingStore::new(&policy.db);
        let mut envelope_gapped = Vec::new();
        for (named, left) in &order.by_named {
            let Ok(from) = messaging.get_sender_nonce(named) else {
                continue;
            };
            let mut next = from;
            let mut gap = false;
            for &(nonce, j) in left {
                if nonce < from {
                    // Below the committed nonce: the screen evicts it.
                    continue;
                }
                if !gap && nonce == next {
                    next += 1;
                } else if nonce > next {
                    gap = true;
                }
                if gap {
                    envelope_gapped.push(j);
                }
            }
        }
        // An account whose nonce could not be read has every transaction
        // held, but none of them above a gap.
        let direct = account_gapped
            .iter()
            .filter(|&&j| matches!(committed.get(&pool[j].sender()), Some(Some(_))))
            .chain(envelope_gapped.iter())
            .map(|&j| pool[j].hash())
            .collect();
        let mut held = HashSet::new();
        for &j in account_gapped.iter().chain(envelope_gapped.iter()) {
            held.extend(order.leave_out(j).into_iter().map(|x| pool[x].hash()));
        }
        PoolHolds { direct, held }
    }

    /// The transactions among `transactions`, in the order given, that this
    /// node carries in ONE block under its inclusion policy; the rest are left
    /// out, and those the canonical chain has moved past are evicted from the
    /// pool if held.
    ///
    /// The same screening [`Self::select_for_block`] applies, offered for a
    /// list that did not come from this pool (`PoAEngine::create_block` applies
    /// it to whatever it is handed). Without a wired policy only the in-block
    /// duplicate-hash rule applies. The order given is kept, but for an
    /// envelope the screen defers; `select_for_block`'s own order already
    /// carries each named sender's envelopes in sequence, so the screen defers
    /// none of them.
    pub fn apply_inclusion_policy(
        &self,
        transactions: Vec<SignedTransaction>,
    ) -> Vec<SignedTransaction> {
        let max_count = transactions.len();
        let rules = self.next_block_rules();
        let (carried, evict) =
            self.screen_for_inclusion(transactions.into_iter(), max_count, rules.forms);
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
    /// envelope that does not verify in a form `forms` accepts is evicted; a
    /// verified envelope is carried only if its nonce is the next in its
    /// sender's sequence — the committed messaging nonce, plus one per
    /// envelope from that sender carried earlier in this block — so each
    /// (sender, nonce) is carried at most once and in order. An envelope
    /// below the committed nonce is evicted. One ahead of the sequence when
    /// first seen is deferred and carried after the pass if the sequence has
    /// reached it by then, so a sender's run of envelopes goes into one block
    /// whatever the fee order put them in; otherwise it waits for a later
    /// block — unless the last selection released it after it waited
    /// [`CROSS_ACCOUNT_WAIT_SELECTIONS`] selections on another account, when
    /// it is carried out of sequence. A storage read that fails leaves the
    /// transaction out of this block and in the pool.
    ///
    /// Stops once `max_count` transactions are carried.
    fn screen_for_inclusion(
        &self,
        candidates: impl Iterator<Item = SignedTransaction>,
        max_count: usize,
        forms: EnvelopeForms,
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
            match sponsored_envelope(&tx, forms) {
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
                        if self.released_envelopes.read().contains(&hash) {
                            // Released: carried out of its sender's sequence,
                            // which does not move for it.
                            carried.push(tx);
                        } else {
                            deferred.push((tx, sender, nonce));
                        }
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
        // and from the accounting gate on, when a relayed `SendMessage`
        // advances its sponsor's account nonce, behind that sponsor's later
        // nonces: `select_for_block` then places what is carried in one order
        // that keeps both sequences (`in_combined_order`).
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

    /// What `pick` returns for each held transaction, where it returns
    /// something. The transactions are read in place, none is cloned, and the
    /// pool's read lock is held only while `pick` runs over them: `pick` should
    /// be cheap, and leave any expensive check of what it returns to the caller.
    pub fn filter_map_held<T>(
        &self,
        mut pick: impl FnMut(&SignedTransaction) -> Option<T>,
    ) -> Vec<T> {
        self.txs
            .read()
            .values()
            .filter_map(|e| pick(&e.tx))
            .collect()
    }

    /// Clear all transactions
    pub fn clear(&self) {
        self.txs.write().clear();
        self.by_sender.write().clear();
        self.by_fee.write().clear();
        self.inference_in_flight.write().clear();
        self.education_in_flight.write().clear();
        self.sponsored_in_flight.write().clear();
        self.relayed_envelopes.write().clear();
        self.cross_account_waits.write().clear();
        self.released_envelopes.write().clear();
        self.gap_holds.write().clear();
        self.gap_evictions.write().clear();
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
        let forms = self.next_block_rules().forms;
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
                    match sponsored_envelope(&tx, forms) {
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

    /// One sender's transactions are carried in nonce order, whatever their
    /// fees; the set selected is still the highest-fee one. Of the
    /// transactions whose turn it is, the higher fee goes first.
    #[test]
    fn one_senders_transactions_are_selected_in_nonce_order() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let other = KeyPair::generate();
        let recipient = KeyPair::generate();

        // Fees invert the sender's nonce order: 2 pays most, 0 least.
        let n0 = create_signed_tx(&sender, recipient.address(), 1, 10, 0);
        let n1 = create_signed_tx(&sender, recipient.address(), 1, 20, 1);
        let n2 = create_signed_tx(&sender, recipient.address(), 1, 30, 2);
        // Another sender between them in the fee order.
        let o0 = create_signed_tx(&other, recipient.address(), 1, 25, 0);
        for tx in [&n0, &n1, &n2, &o0] {
            mempool.add(tx.clone()).unwrap();
        }

        let picked = mempool.select_for_block(10);
        // Fee order is n2 (30), o0 (25), n1 (20), n0 (10). The turn is o0's
        // and n0's; o0 pays more, then the sender's run follows.
        assert_eq!(
            picked.iter().map(|t| t.hash()).collect::<Vec<_>>(),
            vec![o0.hash(), n0.hash(), n1.hash(), n2.hash()]
        );
        // Each sender's own order, exactly: the sender's run in nonce order,
        // and the other sender's one transaction.
        let of = |who: &KeyPair| -> Vec<Hash> {
            picked
                .iter()
                .filter(|t| t.sender() == who.address())
                .map(|t| t.hash())
                .collect()
        };
        assert_eq!(of(&sender), vec![n0.hash(), n1.hash(), n2.hash()]);
        assert_eq!(of(&other), vec![o0.hash()]);

        // A cut keeps the highest-fee set and orders it: n2 and o0 are the top
        // two, and n2 is alone for its sender.
        let top = mempool.select_for_block(2);
        assert_eq!(
            top.iter().map(|t| t.hash()).collect::<Vec<_>>(),
            vec![n2.hash(), o0.hash()]
        );
    }

    /// At one nonce, a relayed `SendMessage` (which leaves its sponsor's nonce
    /// where it is below the accounting gate) is carried before a sponsored
    /// registration (which advances it), although the registration pays the
    /// higher fee; the next nonce follows both.
    #[test]
    fn at_one_nonce_a_transaction_that_leaves_the_nonce_comes_first() {
        use sumchain_primitives::{MessagingTxData, TransactionV2};
        let mempool = Mempool::new(MempoolConfig::default());
        let sponsor = KeyPair::generate();
        let messaging = |operation: MessagingOperation, fee: Balance, nonce: u64| {
            let tx = TransactionV2::messaging(
                1,
                sponsor.address(),
                fee,
                nonce,
                MessagingTxData {
                    operation,
                    data: vec![nonce as u8, fee as u8],
                },
            );
            let sig = sign(tx.signing_hash().as_bytes(), sponsor.private_key());
            SignedTransaction::new_v2(tx, *sig.as_bytes(), *sponsor.public_key().as_bytes())
        };
        let registration = messaging(MessagingOperation::RegisterPublicKeySponsoredV1, 30, 0);
        let relayed = messaging(MessagingOperation::SendMessage, 10, 0);
        let next = messaging(MessagingOperation::SendMessage, 20, 1);
        for tx in [&registration, &relayed, &next] {
            mempool.add(tx.clone()).unwrap();
        }
        assert!(advances_nonce_below_accounting_gate(&registration));
        assert!(!advances_nonce_below_accounting_gate(&relayed));

        let picked = mempool.select_for_block(10);
        assert_eq!(
            picked.iter().map(|t| t.hash()).collect::<Vec<_>>(),
            vec![relayed.hash(), registration.hash(), next.hash()]
        );
    }

    /// A relayed `SendMessage` from `relay` at account nonce `nonce`, naming
    /// `named` at envelope nonce `envelope_nonce`. Only the shape matters to
    /// the order: nothing is verified.
    fn relayed(
        relay: &KeyPair,
        nonce: u64,
        named: &KeyPair,
        envelope_nonce: u64,
    ) -> SignedTransaction {
        use sumchain_primitives::{MessagingTxData, TransactionV2};
        let m = SponsoredMessage {
            message_data: vec![envelope_nonce as u8],
            recipient_hash: [7u8; 32],
            signature: [0u8; 64],
            sender_pubkey: *named.public_key().as_bytes(),
            nonce: envelope_nonce,
            expiry: u64::MAX,
            koppa_amount: None,
        };
        let tx = TransactionV2::messaging(
            1,
            relay.address(),
            1_000,
            nonce,
            MessagingTxData {
                operation: MessagingOperation::SendMessage,
                data: bincode::serialize(&m).unwrap(),
            },
        );
        let sig = sign(tx.signing_hash().as_bytes(), relay.private_key());
        SignedTransaction::new_v2(tx, *sig.as_bytes(), *relay.public_key().as_bytes())
    }

    fn transfer_from(from: &KeyPair, nonce: u64) -> SignedTransaction {
        create_signed_tx(from, KeyPair::from_bytes([9u8; 32]).address(), 1, 10, nonce)
    }

    fn ids(txs: &[SignedTransaction]) -> Vec<Hash> {
        txs.iter().map(|t| t.hash()).collect()
    }

    /// [`super::in_combined_order`] with no committed account nonce known, as
    /// a pool without an inclusion policy orders: no account's nonces are
    /// checked for a gap.
    fn in_combined_order(
        carried: Vec<SignedTransaction>,
        accounting: bool,
    ) -> (Vec<SignedTransaction>, LeftOut) {
        super::in_combined_order(carried, accounting, &HashMap::new())
    }

    fn keys() -> (KeyPair, KeyPair, KeyPair, KeyPair, KeyPair) {
        (
            KeyPair::from_bytes([1u8; 32]),
            KeyPair::from_bytes([2u8; 32]),
            KeyPair::from_bytes([3u8; 32]),
            KeyPair::from_bytes([4u8; 32]),
            KeyPair::from_bytes([5u8; 32]),
        )
    }

    /// One named sender's envelopes through two sponsors. Ordered by account
    /// nonce alone, `r1`'s transfer at nonce 0 would take the first of
    /// `r1`'s two positions and push `s`'s envelope 0 behind envelope 1;
    /// the combined order keeps both sequences, and an order that already
    /// keeps them is returned unchanged.
    #[test]
    fn the_combined_order_keeps_account_and_envelope_nonces_across_sponsors() {
        let (r1, r2, s, _, _) = keys();
        let r1_s0 = relayed(&r1, 1, &s, 0);
        let r2_s1 = relayed(&r2, 0, &s, 1);
        let r1_transfer = transfer_from(&r1, 0);
        // As the screen carries them: `s`'s envelopes in sequence, the rest in
        // fee order.
        let carried = vec![r1_s0.clone(), r2_s1.clone(), r1_transfer.clone()];
        for accounting in [false, true] {
            let (ordered, left_out) = in_combined_order(carried.clone(), accounting);
            assert_eq!(
                ids(&ordered),
                ids(&[r1_transfer.clone(), r1_s0.clone(), r2_s1.clone()]),
                "accounting {accounting}"
            );
            assert_eq!(left_out, LeftOut::default());
            let (again, _) = in_combined_order(ordered.clone(), accounting);
            assert_eq!(ids(&again), ids(&ordered), "a kept order is unchanged");
        }
    }

    /// The screen appends an envelope it deferred after everything else. When
    /// that envelope is its sponsor's nonce 0, the combined order brings it
    /// back in front of the sponsor's nonce 1, after the envelope it waits
    /// on.
    #[test]
    fn a_deferred_envelope_returns_in_front_of_its_sponsors_later_nonce() {
        let (r1, r2, s, _, _) = keys();
        let r2_s0 = relayed(&r2, 0, &s, 0);
        let r1_transfer = transfer_from(&r1, 1);
        let r1_s1 = relayed(&r1, 0, &s, 1);
        let carried = vec![r2_s0.clone(), r1_transfer.clone(), r1_s1.clone()];
        for accounting in [false, true] {
            let (ordered, left_out) = in_combined_order(carried.clone(), accounting);
            assert_eq!(
                ids(&ordered),
                ids(&[r2_s0.clone(), r1_s1.clone(), r1_transfer.clone()]),
                "accounting {accounting}"
            );
            assert_eq!(left_out, LeftOut::default());
        }
    }

    /// From the accounting gate on, two sponsors whose envelopes for `s` and
    /// `t` cross wait on each other in a cycle: `r1`'s nonce 0 is `s`'s
    /// envelope 1, which waits on `r2`'s nonce 1, which waits on `r2`'s nonce
    /// 0, `t`'s envelope 1, which waits on `r1`'s nonce 1, which waits on
    /// `r1`'s nonce 0. No order carries any of them. The latest at the head of
    /// its sponsor's sequence is the victim, and the three that depend on it
    /// go with it; a third sponsor's transactions are carried. Below the gate
    /// the relay signs every envelope at the sponsor's committed nonce, they
    /// advance no nonce, and the same crossing is no cycle.
    #[test]
    fn a_cycle_of_account_and_envelope_nonces_is_left_out() {
        let (r1, r2, s, t, r3) = keys();
        let u = KeyPair::from_bytes([6u8; 32]);
        let r1_s1 = relayed(&r1, 0, &s, 1);
        let r1_t0 = relayed(&r1, 1, &t, 0);
        let r2_t1 = relayed(&r2, 0, &t, 1);
        let r2_s0 = relayed(&r2, 1, &s, 0);
        let r3_transfer = transfer_from(&r3, 0);
        let r3_u0 = relayed(&r3, 1, &u, 0);
        let carried = vec![
            r1_t0.clone(),
            r2_t1.clone(),
            r2_s0.clone(),
            r3_transfer.clone(),
            r3_u0.clone(),
            r1_s1.clone(),
        ];
        let (ordered, left_out) = in_combined_order(carried, true);
        assert_eq!(ids(&ordered), ids(&[r3_transfer.clone(), r3_u0.clone()]));
        assert_eq!(left_out.victims, vec![r1_s1.hash()]);
        let mut dependents = left_out.dependents.clone();
        dependents.sort();
        let mut expected = ids(&[r1_t0.clone(), r2_t1.clone(), r2_s0.clone()]);
        expected.sort();
        assert_eq!(dependents, expected);

        // Below the accounting gate, at the sponsors' shared nonce 0.
        let r1_s1 = relayed(&r1, 0, &s, 1);
        let r1_t0 = relayed(&r1, 0, &t, 0);
        let r2_t1 = relayed(&r2, 0, &t, 1);
        let r2_s0 = relayed(&r2, 0, &s, 0);
        let carried = vec![r1_t0.clone(), r2_t1.clone(), r2_s0.clone(), r1_s1.clone()];
        let (ordered, left_out) = in_combined_order(carried.clone(), false);
        assert_eq!(ids(&ordered), ids(&carried), "nothing to reorder");
        assert_eq!(left_out, LeftOut::default());
    }

    /// `select_for_block` evicts a cycle's victim, so the cycle does not hold
    /// its sponsors back in every later block, and keeps the transactions
    /// that depend on it in the pool.
    #[test]
    fn select_for_block_evicts_a_cycles_victim_and_keeps_what_depends_on_it() {
        let (r1, r2, s, t, r3) = keys();
        let params = ChainParams {
            messaging_fee_nonce_accounting_enabled_from_height: Some(1),
            ..ChainParams::default()
        };
        let mempool = Mempool::new(MempoolConfig::default()).with_inclusion_gates(InclusionGates {
            params: Arc::new(params),
            chain_id: 1,
            current_height: Arc::new(AtomicU64::new(0)),
        });
        let r1_s1 = relayed(&r1, 0, &s, 1);
        let r1_t0 = relayed(&r1, 1, &t, 0);
        let r2_t1 = relayed(&r2, 0, &t, 1);
        let r2_s0 = relayed(&r2, 1, &s, 0);
        let r3_transfer = transfer_from(&r3, 0);
        for tx in [&r1_s1, &r1_t0, &r2_t1, &r2_s0, &r3_transfer] {
            mempool.add(tx.clone()).unwrap();
        }
        assert_eq!(ids(&mempool.select_for_block(10)), vec![r3_transfer.hash()]);
        let cycle = [&r1_s1, &r1_t0, &r2_t1, &r2_s0];
        let evicted: Vec<Hash> = cycle
            .iter()
            .map(|tx| tx.hash())
            .filter(|h| !mempool.contains(h))
            .collect();
        assert_eq!(evicted.len(), 1, "one victim");
        assert!(
            evicted[0] == r1_s1.hash() || evicted[0] == r2_t1.hash(),
            "the victim heads its sponsor's sequence"
        );
        assert!(mempool.contains(&r3_transfer.hash()));
        // The cycle is gone: the three left are carried in an order that
        // keeps both sequences. (This pool has no inclusion policy, so it
        // cannot read the sponsors' committed nonces and does not see the gap
        // the victim left; with a policy wired the three wait for it to be
        // filled: `nothing_above_a_nonce_gap_is_offered`.)
        let next = mempool.select_for_block(10);
        assert_eq!(next.len(), 4);
        assert_eq!(mempool.len(), 4);
    }

    fn key(i: u8) -> KeyPair {
        KeyPair::from_bytes([i; 32])
    }

    fn sorted(mut hashes: Vec<Hash>) -> Vec<Hash> {
        hashes.sort();
        hashes
    }

    /// A cycle through `sponsors.len()` sponsors and as many named senders,
    /// from the accounting gate on: sponsor `k` relays sender `k`'s envelope
    /// 1 at its nonce 0 and sender `k + 1`'s envelope 0 at its nonce 1, so
    /// each sponsor's nonce 0 waits on the next sponsor's nonce 1, which waits
    /// on that sponsor's nonce 0. With one sponsor it is one sender's two
    /// envelopes relayed in the reverse order. Returns, per sponsor, its
    /// nonce 0 and nonce 1.
    fn cycle_through(
        sponsors: &[KeyPair],
        senders: &[KeyPair],
    ) -> Vec<(SignedTransaction, SignedTransaction)> {
        let n = sponsors.len();
        (0..n)
            .map(|k| {
                (
                    relayed(&sponsors[k], 0, &senders[k], 1),
                    relayed(&sponsors[k], 1, &senders[(k + 1) % n], 0),
                )
            })
            .collect()
    }

    /// `w` relays `u`'s envelope 2, last in the fee order: it waits on
    /// the cycle of `r1` and `r2` (through `u`'s envelope 1) but is not on
    /// it. The victim is a transaction of the cycle that heads its sponsor's
    /// sequence, the latest of those in the fee order; `w`'s envelope and the
    /// cycle's other three are left for a later block, not evicted.
    #[test]
    fn a_transaction_that_only_waits_on_a_cycle_is_not_its_victim() {
        let (r1, r2, u, v, w) = keys();
        let r2_u0 = relayed(&r2, 1, &u, 0);
        let r1_v0 = relayed(&r1, 1, &v, 0);
        let r1_u1 = relayed(&r1, 0, &u, 1);
        let r2_v1 = relayed(&r2, 0, &v, 1);
        let w_u2 = relayed(&w, 0, &u, 2);
        let carried = vec![
            r2_u0.clone(),
            r1_v0.clone(),
            r1_u1.clone(),
            r2_v1.clone(),
            w_u2.clone(),
        ];
        let (ordered, left_out) = in_combined_order(carried, true);
        assert!(ordered.is_empty());
        assert_eq!(left_out.victims, vec![r2_v1.hash()]);
        assert_eq!(
            sorted(left_out.dependents.clone()),
            sorted(ids(&[r2_u0, r1_v0, r1_u1, w_u2]))
        );
        assert!(left_out.gapped.is_empty());
    }

    /// The victim is a head on the cycle even when the latest cycle
    /// member in `carried` is not a head: here `r2`'s nonce 1, `u`'s envelope
    /// 0, comes last. (From the producer this order cannot arise: the screen
    /// carries every envelope after its named sender's earlier ones, so each
    /// non-head on a cycle comes before the head that waits on it; the head
    /// filter is pinned here, on the order alone.)
    #[test]
    fn the_victim_is_a_head_even_when_a_later_cycle_member_is_not() {
        let (r1, r2, u, v, _) = keys();
        let r1_u1 = relayed(&r1, 0, &u, 1);
        let r2_v1 = relayed(&r2, 0, &v, 1);
        let r1_v0 = relayed(&r1, 1, &v, 0);
        let r2_u0 = relayed(&r2, 1, &u, 0);
        let carried = vec![r1_u1.clone(), r2_v1.clone(), r1_v0.clone(), r2_u0.clone()];
        let (ordered, left_out) = in_combined_order(carried, true);
        assert!(ordered.is_empty());
        assert_eq!(left_out.victims, vec![r2_v1.hash()]);
        assert_eq!(
            sorted(left_out.dependents.clone()),
            sorted(ids(&[r1_u1, r1_v0, r2_u0]))
        );
    }

    /// Cycles through one, two, three and four sponsors (two, four,
    /// six and eight transactions; a cycle alternates a sponsor's head and a
    /// transaction behind one, so it has no odd length): exactly one victim,
    /// on the cycle and heading its sponsor's sequence, every other
    /// transaction of the cycle left for a later block, and an unrelated
    /// sponsor's transfer and relayed envelope carried in order.
    #[test]
    fn each_cycle_loses_one_victim_from_the_cycle() {
        let sponsors: Vec<KeyPair> = (10..14).map(key).collect();
        let senders: Vec<KeyPair> = (20..24).map(key).collect();
        let (unrelated, unrelated_user) = (key(30), key(31));
        for n in 1..=4 {
            let pairs = cycle_through(&sponsors[..n], &senders[..n]);
            let unrelated_transfer = transfer_from(&unrelated, 0);
            let unrelated_envelope = relayed(&unrelated, 1, &unrelated_user, 0);
            // Fee order: the nonce-1 transactions, then the unrelated pair,
            // then the nonce-0 heads.
            let mut carried: Vec<SignedTransaction> =
                pairs.iter().map(|(_, one)| one.clone()).collect();
            carried.push(unrelated_transfer.clone());
            carried.push(unrelated_envelope.clone());
            carried.extend(pairs.iter().map(|(zero, _)| zero.clone()));
            let (ordered, left_out) = in_combined_order(carried, true);
            assert_eq!(
                ids(&ordered),
                ids(&[unrelated_transfer.clone(), unrelated_envelope.clone()]),
                "{n} sponsor(s)"
            );
            // The latest head in the fee order is the last sponsor's nonce 0.
            assert_eq!(left_out.victims, vec![pairs[n - 1].0.hash()], "{n}");
            let rest: Vec<Hash> = pairs
                .iter()
                .flat_map(|(zero, one)| [zero.hash(), one.hash()])
                .filter(|h| *h != pairs[n - 1].0.hash())
                .collect();
            assert_eq!(sorted(left_out.dependents.clone()), sorted(rest), "{n}");
            assert!(left_out.gapped.is_empty(), "{n}");
        }
    }

    /// With the committed account nonces known, a transaction above a
    /// gap in its account's nonces is left out, not evicted, with what
    /// depends on it in turn. `r1`'s committed nonce is 0 and it holds only
    /// nonce 1, `v`'s envelope 0; `v`'s envelope 1 through `r2` waits on it
    /// and, from the accounting gate, `r2`'s nonce 1 on that. A third
    /// sponsor and an unrelated sender are carried. Below the gate the
    /// relayed envelopes advance no nonce, and the same three wait: `r1`'s
    /// envelope at nonce 1 has no transaction at nonce 0 to reach it, `v`'s
    /// envelope 1 waits on it, and `r2`'s envelope at nonce 1 is reached by
    /// nothing either; `r3`'s envelope at nonce 1 is reached by its transfer
    /// at nonce 0.
    #[test]
    fn nothing_above_a_nonce_gap_is_offered() {
        let (r1, r2, v, r3, x) = keys();
        let u = key(6);
        let r1_v0 = relayed(&r1, 1, &v, 0);
        let r2_v1 = relayed(&r2, 0, &v, 1);
        let r2_u0 = relayed(&r2, 1, &u, 0);
        let r3_transfer = transfer_from(&r3, 0);
        let r3_x0 = relayed(&r3, 1, &x, 0);
        let other = transfer_from(&key(7), 0);
        let carried = vec![
            r1_v0.clone(),
            r2_v1.clone(),
            r2_u0.clone(),
            r3_transfer.clone(),
            r3_x0.clone(),
            other.clone(),
        ];
        let committed: HashMap<Address, Option<Nonce>> = [&r1, &r2, &r3, &key(7)]
            .into_iter()
            .map(|k| (k.address(), Some(0)))
            .collect();

        for accounting in [true, false] {
            let (ordered, left_out) =
                super::in_combined_order(carried.clone(), accounting, &committed);
            assert_eq!(
                ids(&ordered),
                ids(&[r3_transfer.clone(), r3_x0.clone(), other.clone()]),
                "accounting {accounting}"
            );
            assert!(left_out.victims.is_empty(), "accounting {accounting}");
            assert!(left_out.dependents.is_empty(), "accounting {accounting}");
            assert_eq!(
                sorted(left_out.gapped.clone()),
                sorted(ids(&[r1_v0.clone(), r2_v1.clone(), r2_u0.clone()])),
                "accounting {accounting}"
            );
        }

        // Without the committed nonces nothing is checked, as before.
        let (ordered, left_out) = in_combined_order(carried, true);
        assert_eq!(ordered.len(), 6);
        assert_eq!(left_out, LeftOut::default());
    }

    /// A gap the block fills is no gap: `r1`'s transfer at its
    /// committed nonce 3 reaches its envelope at nonce 4 below the gate (and
    /// its envelope at 3 shares nonce 3, before the transfer). A transaction
    /// below the committed nonce is offered as before (it takes
    /// `InvalidNonce`). A sender whose committed nonce cannot be read waits,
    /// with what depends on it; one not in `committed` is not checked.
    #[test]
    fn a_gap_the_block_fills_is_no_gap() {
        let (r1, s, t, stale, unread) = keys();
        let unchecked = key(6);
        let r1_s0 = relayed(&r1, 3, &s, 0);
        let r1_transfer = transfer_from(&r1, 3);
        let r1_s1 = relayed(&r1, 4, &s, 1);
        let old = transfer_from(&stale, 1);
        let current = transfer_from(&stale, 2);
        let unread_t0 = relayed(&unread, 0, &t, 0);
        let r1_t1 = relayed(&r1, 4, &t, 1);
        let free = transfer_from(&unchecked, 9);
        let carried = vec![
            r1_s1.clone(),
            r1_transfer.clone(),
            r1_s0.clone(),
            current.clone(),
            old.clone(),
            unread_t0.clone(),
            r1_t1.clone(),
            free.clone(),
        ];
        let committed: HashMap<Address, Option<Nonce>> = [
            (r1.address(), Some(3)),
            (stale.address(), Some(2)),
            (unread.address(), None),
        ]
        .into_iter()
        .collect();
        let (ordered, left_out) = super::in_combined_order(carried, false, &committed);
        assert_eq!(
            ids(&ordered),
            ids(&[
                r1_s0.clone(),
                r1_transfer.clone(),
                r1_s1.clone(),
                old.clone(),
                current.clone(),
                free.clone()
            ])
        );
        assert_eq!(
            sorted(left_out.gapped.clone()),
            sorted(ids(&[unread_t0, r1_t1]))
        );
        assert!(left_out.victims.is_empty());
    }

    /// Gives `who` a committed balance in the policy pool's database, as a
    /// block would have.
    fn fund(mempool: &Mempool, who: &KeyPair) {
        let db = &mempool.inclusion_policy.as_ref().unwrap().db;
        StateStore::new(db)
            .put_account(
                &who.address(),
                &sumchain_storage::schema::AccountState {
                    balance: 1_000_000,
                    nonce: 0,
                },
            )
            .unwrap();
    }

    /// A pool wired with an inclusion policy over an empty database: every
    /// committed account and messaging nonce reads 0, and every balance 0.
    fn policy_pool() -> (Mempool, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        (
            Mempool::new(MempoolConfig::default()).with_inclusion_policy(InclusionPolicy { db }),
            dir,
        )
    }

    /// What waits is decided over the whole pool. `s`'s envelope 0 is missing
    /// from the pool, so `s`'s envelope 1, relayed by `r2` at its nonce 0, is
    /// held directly; `r2` also sends transfers at nonces 0, 1 and 2. `r1`
    /// holds transfers at nonces 1 and 2 and its envelope for `t` at nonce 3,
    /// with nothing at its committed nonce 0: all three are held, and so is
    /// `t`'s envelope 1 through `r3`, behind `t`'s envelope 0. Unrelated `x` is
    /// not held. From the accounting gate `s`'s envelope advances `r2`'s nonce,
    /// so `r2`'s transfers at nonces 1 and 2 are held with it; below the gate
    /// it advances nothing and they are not.
    #[test]
    fn what_waits_is_decided_over_the_whole_pool() {
        let (r1, r2, s, t, x) = keys();
        let r3 = key(6);
        let (pool_mempool, _dir) = policy_pool();
        let s1 = relayed(&r2, 0, &s, 1);
        let r2_transfers: Vec<SignedTransaction> = (0..3).map(|n| transfer_from(&r2, n)).collect();
        let r1_above: Vec<SignedTransaction> = (1..3).map(|n| transfer_from(&r1, n)).collect();
        let r1_t0 = relayed(&r1, 3, &t, 0);
        let r3_t1 = relayed(&r3, 0, &t, 1);
        let x0 = transfer_from(&x, 0);
        let mut pool = vec![s1.clone(), r1_t0.clone(), r3_t1.clone(), x0.clone()];
        pool.extend(r2_transfers.iter().cloned());
        pool.extend(r1_above.iter().cloned());
        let committed: HashMap<Address, Option<Nonce>> = [&r1, &r2, &r3, &x]
            .into_iter()
            .map(|k| (k.address(), Some(0)))
            .collect();
        let mut always: Vec<Hash> = ids(&r1_above);
        always.extend([s1.hash(), r1_t0.hash(), r3_t1.hash()]);

        let held = pool_mempool.pool_holds(&pool, true, &committed).held;
        let mut expected = always.clone();
        expected.extend(ids(&r2_transfers[1..]));
        assert_eq!(sorted(held.into_iter().collect()), sorted(expected));

        let held = pool_mempool.pool_holds(&pool, false, &committed).held;
        assert_eq!(sorted(held.into_iter().collect()), sorted(always));

        // Without a policy nothing is held.
        let bare = Mempool::new(MempoolConfig::default());
        assert!(bare.pool_holds(&pool, true, &committed).held.is_empty());
    }

    /// A transaction below its account's committed nonce can never take its
    /// nonce, so nothing of its account waits on it. `r1`'s committed nonce is
    /// 2; its envelope for `s` at nonce 1 is stale and is held (`s`'s envelope
    /// 0 is missing), and `r1`'s transfers at nonces 2 and 3 are not held with
    /// it, from the accounting gate (where the envelope would advance the
    /// nonce) as below it.
    #[test]
    fn a_transaction_below_its_committed_nonce_holds_nothing_behind_it() {
        let (r1, _, s, _, _) = keys();
        let (pool_mempool, _dir) = policy_pool();
        let stale = relayed(&r1, 1, &s, 1);
        let later = [transfer_from(&r1, 2), transfer_from(&r1, 3)];
        let pool = vec![stale.clone(), later[0].clone(), later[1].clone()];
        let committed: HashMap<Address, Option<Nonce>> =
            [(r1.address(), Some(2))].into_iter().collect();
        for accounting in [true, false] {
            let held = pool_mempool.pool_holds(&pool, accounting, &committed).held;
            assert_eq!(
                held.into_iter().collect::<Vec<_>>(),
                vec![stale.hash()],
                "accounting {accounting}"
            );
        }
    }

    /// The count toward [`GAP_HOLD_SELECTIONS`], selection by selection: `a`'s
    /// transfer at nonce 1 is above `a`'s gap (committed nonce 0) and counted
    /// once per selection; it restarts when the gap closes (`a`'s nonce 0
    /// joins the pool) and when the transaction leaves the pool; the
    /// transaction is evicted, with no other change to the pool, only at its
    /// `GAP_HOLD_SELECTIONS`-th selection in a row.
    #[test]
    fn the_gap_hold_count_restarts_when_the_gap_closes_or_the_transaction_leaves() {
        let (a, _, _, _, x) = keys();
        let (mempool, _dir) = policy_pool();
        // `a` can pay for its run, so the cut carries it once the gap closes.
        fund(&mempool, &a);
        let above = transfer_from(&a, 1);
        let fill = transfer_from(&a, 0);
        let other = transfer_from(&x, 0);
        mempool.add(above.clone()).unwrap();
        mempool.add(other.clone()).unwrap();
        let count = || mempool.gap_hold_count(&above.hash());
        for n in 1..GAP_HOLD_SELECTIONS {
            assert_eq!(ids(&mempool.select_for_block(10)), vec![other.hash()]);
            assert_eq!(count(), n);
        }
        // The gap closes: nothing above it, nothing counted.
        mempool.add(fill.clone()).unwrap();
        let offered = mempool.select_for_block(10);
        assert!(offered.iter().any(|t| t.hash() == above.hash()));
        assert_eq!(count(), 0);
        // It opens again: counted from 1.
        mempool.remove(&fill.hash());
        for n in 1..GAP_HOLD_SELECTIONS {
            mempool.select_for_block(10);
            assert!(mempool.contains(&above.hash()), "selection {n}");
            assert_eq!(count(), n);
        }
        // It leaves the pool and is admitted again: counted from 1.
        mempool.remove(&above.hash());
        assert_eq!(count(), 0);
        mempool.add(above.clone()).unwrap();
        for n in 1..GAP_HOLD_SELECTIONS {
            mempool.select_for_block(10);
            assert!(mempool.contains(&above.hash()), "selection {n}");
            assert_eq!(count(), n);
        }
        // The bound: evicted; the unrelated transaction stays.
        assert_eq!(ids(&mempool.select_for_block(10)), vec![other.hash()]);
        assert!(!mempool.contains(&above.hash()));
        assert_eq!(count(), 0);
        assert!(mempool.contains(&other.hash()));
        assert_eq!(mempool.len(), 1);
    }

    /// The count at heads, on a pool that does not select (a node that never
    /// proposes): `a`'s transfer above `a`'s gap is counted once per head and
    /// evicted at its `GAP_HOLD_SELECTIONS`-th, with nothing else touched;
    /// the count restarts when the gap closes and when it leaves the pool. A
    /// selection since the last head counts the block itself, and that head
    /// then counts nothing: one count per block.
    #[test]
    fn a_pool_that_does_not_select_counts_at_each_head() {
        let (a, _, _, _, x) = keys();
        let (mempool, _dir) = policy_pool();
        let above = transfer_from(&a, 1);
        let fill = transfer_from(&a, 0);
        let other = transfer_from(&x, 0);
        mempool.add(above.clone()).unwrap();
        mempool.add(other.clone()).unwrap();
        let count = || mempool.gap_hold_count(&above.hash());
        for head in 1..GAP_HOLD_SELECTIONS {
            mempool.at_new_head(u64::from(head));
            assert_eq!(count(), head);
        }
        // A selection counts the block: the third, which evicts it.
        mempool.select_for_block(10);
        assert!(!mempool.contains(&above.hash()), "evicted by the selection");
        assert_eq!(count(), 0);
        // Admitted again; a selection counts its block, and that block's
        // head counts nothing more.
        mempool.add(above.clone()).unwrap();
        mempool.select_for_block(10);
        assert_eq!(count(), 1);
        mempool.at_new_head(10);
        assert_eq!(count(), 1, "that head was counted by the selection");
        // The gap closes, then opens again: counted from nothing.
        mempool.add(fill.clone()).unwrap();
        mempool.at_new_head(11);
        assert_eq!(count(), 0);
        mempool.remove(&fill.hash());
        mempool.at_new_head(12);
        assert_eq!(count(), 1);
        // It leaves the pool and comes back: counted from nothing.
        mempool.remove(&above.hash());
        assert_eq!(count(), 0);
        mempool.add(above.clone()).unwrap();
        for head in 13..(13 + u64::from(GAP_HOLD_SELECTIONS) - 1) {
            mempool.at_new_head(head);
            assert!(mempool.contains(&above.hash()), "head {head}");
        }
        assert_eq!(count(), GAP_HOLD_SELECTIONS - 1);
        mempool.at_new_head(20);
        assert!(!mempool.contains(&above.hash()), "evicted at the bound");
        assert_eq!(count(), 0);
        assert!(mempool.contains(&other.hash()));
        assert_eq!(mempool.len(), 1);
    }

    /// The eviction history is first in, first out, and holds at most as many
    /// entries as the pool has places. A pool of 4 evicts four transactions
    /// above a gap, then four more: the first four are forgotten, the last
    /// four are remembered.
    #[test]
    fn the_eviction_history_forgets_the_oldest_beyond_the_pool_capacity() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let mempool = Mempool::new(MempoolConfig {
            max_size: 4,
            ..MempoolConfig::default()
        })
        .with_inclusion_policy(InclusionPolicy { db });
        let batch = |from: u8| -> Vec<SignedTransaction> {
            (from..from + 4)
                .map(|i| transfer_from(&key(i), 1))
                .collect()
        };
        let mut head = 0;
        let mut evict_all = |txs: &[SignedTransaction]| {
            for t in txs {
                mempool.add(t.clone()).unwrap();
            }
            for _ in 0..GAP_HOLD_SELECTIONS {
                head += 1;
                mempool.at_new_head(head);
            }
            assert!(txs.iter().all(|t| !mempool.contains(&t.hash())));
        };
        let first = batch(20);
        let second = batch(30);
        evict_all(&first);
        assert!(first.iter().all(|t| mempool.evicted_above_a_gap(&t.hash())));
        evict_all(&second);
        assert!(first
            .iter()
            .all(|t| !mempool.evicted_above_a_gap(&t.hash())));
        assert!(second
            .iter()
            .all(|t| mempool.evicted_above_a_gap(&t.hash())));
        mempool.clear();
        assert!(second
            .iter()
            .all(|t| !mempool.evicted_above_a_gap(&t.hash())));
    }

    /// Only a successful admission clears an eviction entry. A pool of 2
    /// evicts `g` above a gap; with the pool full at the same fee, admitting
    /// `g` again is refused and the entry stays; with a place free, `g` is
    /// admitted and the entry is gone.
    #[test]
    fn only_a_successful_admission_clears_an_eviction_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let mempool = Mempool::new(MempoolConfig {
            max_size: 2,
            ..MempoolConfig::default()
        })
        .with_inclusion_policy(InclusionPolicy { db });
        let g = transfer_from(&key(40), 1);
        mempool.add(g.clone()).unwrap();
        for head in 1..=u64::from(GAP_HOLD_SELECTIONS) {
            mempool.at_new_head(head);
        }
        assert!(!mempool.contains(&g.hash()));
        assert!(mempool.evicted_above_a_gap(&g.hash()));
        let fillers = [transfer_from(&key(41), 0), transfer_from(&key(42), 0)];
        for t in &fillers {
            mempool.add(t.clone()).unwrap();
        }
        assert!(matches!(
            mempool.add(g.clone()),
            Err(StateError::MempoolFull)
        ));
        assert!(
            mempool.evicted_above_a_gap(&g.hash()),
            "a refused admission"
        );
        mempool.remove(&fillers[0].hash());
        mempool.add(g.clone()).unwrap();
        assert!(!mempool.evicted_above_a_gap(&g.hash()), "admitted again");
    }

    /// An account whose nonce cannot be read has every transaction held, but
    /// none of them counted toward eviction as above a gap; an account above
    /// a gap has its transactions counted.
    #[test]
    fn an_unreadable_account_is_held_but_never_counted_as_above_a_gap() {
        let (r1, r2, _, _, _) = keys();
        let (pool_mempool, _dir) = policy_pool();
        let unread = [transfer_from(&r1, 0), transfer_from(&r1, 1)];
        let above = transfer_from(&r2, 1);
        let pool = vec![unread[0].clone(), unread[1].clone(), above.clone()];
        let committed: HashMap<Address, Option<Nonce>> =
            [(r1.address(), None), (r2.address(), Some(0))]
                .into_iter()
                .collect();
        for accounting in [true, false] {
            let holds = pool_mempool.pool_holds(&pool, accounting, &committed);
            let mut all = ids(&unread);
            all.push(above.hash());
            assert_eq!(sorted(holds.held.into_iter().collect()), sorted(all));
            assert_eq!(
                holds.direct.into_iter().collect::<Vec<_>>(),
                vec![above.hash()],
                "accounting {accounting}"
            );
        }
    }

    /// `filter_map_held` sees each held transaction once and returns what the
    /// closure picks.
    #[test]
    fn filter_map_held_returns_what_is_picked_from_each_held_transaction() {
        let mempool = Mempool::new(MempoolConfig::default());
        let sender = KeyPair::generate();
        let recipient = KeyPair::generate();
        for (fee, nonce) in [(10, 0), (20, 1), (30, 2)] {
            mempool
                .add(create_signed_tx(
                    &sender,
                    recipient.address(),
                    1,
                    fee,
                    nonce,
                ))
                .unwrap();
        }
        let mut seen = 0;
        let mut picked = mempool.filter_map_held(|tx| {
            seen += 1;
            (tx.fee() >= 20).then(|| tx.nonce())
        });
        picked.sort_unstable();
        assert_eq!(seen, 3);
        assert_eq!(picked, vec![1, 2]);
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

//! A reference client for a relayed message: what a client does when the
//! relay's outer transaction for its message does not deliver it.
//!
//! The relay wraps the user's signed envelope in a sponsor transaction (a
//! "wrapper"). A wrapper the chain refuses with `InvalidNonce` never executed:
//! it charged nothing and moved no messaging nonce. The client then decides
//! from the chain, never from what it remembers:
//!
//! 1. It looks for the exact envelope the user signed (sender key,
//!    recipient, message bytes, nonce, expiry and signature; the content
//!    alone would confuse two messages with the same text) among the
//!    transactions the canonical chain carried and executed successfully:
//!    first its own wrappers, then every block above the height that was
//!    final when the user signed (`get_finality` at signing), up to the tip,
//!    each transaction read through `messaging_getMessageData`, which answers
//!    from the stored transaction and its receipt and only for a relayed
//!    message that executed. Anchoring at the final height, not the signing
//!    height, matters: a chain switch whose fork lies below the signing height
//!    can adopt a block below it that carries the envelope (another relay's
//!    copy). A message carried by a wrapper the client did not request counts
//!    too. Found: delivered, stop; the intent is never sent again. The
//!    sender's message listing (`messaging_getSentMessages`) is not used: it
//!    returns the oldest 1,000 records only, and below the transaction-index
//!    gate it keeps one row per sender per block. (The reference client scans
//!    the whole range at every step; a real client keeps the height it has
//!    scanned to, and after a chain switch scans again from the fork point.)
//! 2. It reads the sender's committed messaging nonce
//!    (`messaging_getSenderNonce`). A nonce that moved is never taken as a
//!    delivery: only a message record is.
//! 3. Not delivered, and the envelope's nonce is the committed nonce: it asks
//!    the relay for a fresh wrapper of the same signed envelope.
//! 4. Not delivered, and the committed nonce moved past the envelope's: the
//!    envelope can never execute; the user must sign a new one at the
//!    committed nonce. The relay cannot.
//! 5. A string-form envelope the relay no longer takes (from the envelope
//!    verification height, version 2 only): the user must sign a version-2
//!    envelope. The relay cannot convert it.
//!
//! **An incomplete search is uncertain, never "not delivered".** A block in
//! the range that is not available, an RPC error, or a range that is not yet
//! final gives `Step::Uncertain` with the reason: the client neither asks the
//! user to sign again nor reports the message undeliverable, and checks again
//! at the next step. Outcomes 4 and 5, and an undeliverable report, are given
//! only once the condition behind them has held on a chain final through the
//! height at which it was first seen (until then: `Step::Uncertain`); asking
//! the relay for a fresh wrapper of the same signed envelope (3) is not held
//! back, since the chain executes a version-2 envelope at most once.
//!
//! A delivery is final once the block that carries it is final. Until then
//! the client checks it again at each step: a chain switch that unwinds that
//! block puts the intent back into the protocol, and a wrapper the switch
//! returned to the pool is waited for rather than duplicated.
//!
//! A wrapper still pending in the pool, or a relay asking to retry after the
//! next block, is waited for. A wrapper executed and refused in the block (a
//! status other than `success` and `invalid nonce`) ends the intent as
//! undeliverable with that status, unless step 4 or 5 applies.
//!
//! **What the client persists, and how.** The whole tracker (the envelope,
//! the tip and the final height at signing, the height of the first
//! submission, the wrapper requests made, a request in flight, the wrappers
//! obtained, the bound, the outcome) lives in the client's own store,
//! written to a temporary file that is synced, renamed over the old one,
//! and the directory synced, so a power loss leaves the last write or the
//! one before it. Before a wrapper request is sent the count is raised and
//! the request recorded as in flight; the wrapper's hash is recorded when it
//! comes back. The count is lowered again only on a definite refusal from
//! the relay (a JSON-RPC error saying the request was refused); any other
//! error leaves the request counted and in flight, since the relay may have
//! made a wrapper. A client restarted with a request in flight waits for a
//! block before asking again: by then the wrapper, if one was made, has
//! either executed (and the search finds it) or is still pending, and the
//! relay refuses a second wrapper of an envelope already pending (by its
//! nonce for a version-2 envelope, by the identical signed envelope for the
//! string form). Below the envelope gate a string-form envelope follows the
//! earlier rule, within the bound.
//!
//! Each store keeps its own bound: two devices holding the same intent can
//! together make twice the bound's requests. The relay's refusal of an
//! envelope already pending limits what the second device's requests cost.
//!
//! Retries are bounded: at most `max_wrappers` wrapper requests per intent.
//! Who pays: the sponsor pays the outer fee for each wrapper that executes,
//! succeeding or refused in the block (from the accounting height; below it
//! a relayed message is not charged); a wrapper refused with `InvalidNonce`
//! costs nothing; the client pays nothing. A version-2 envelope executes at
//! most once, whichever wrapper carries it, so the sponsor's cost per intent
//! is at most one fee per wrapper, and at most `max_wrappers` fees.
//!
//! Below the envelope verification height both forms follow the earlier
//! rule across a chain switch; the client's search (step 1) prevents its own
//! resend.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, SponsoredMessage};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::SubmitSponsoredMessageRequest;

/// The two envelope forms a user can have signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Form {
    /// The version-2 envelope: bound to the chain, the sender's messaging
    /// nonce, the expiry and the content.
    Version2,
    /// The string form the relay took before the envelope verification
    /// height.
    Legacy,
}

/// One message a user wants delivered: the envelope as the user signed it,
/// the chain tip's height when it was signed, and the height that was final
/// then. The search for it starts above the final height: a block at or
/// below it cannot be replaced, a block above it can.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    pub envelope: SponsoredMessage,
    pub form: Form,
    pub signed_at: u64,
    pub final_at_signing: u64,
}

impl Intent {
    /// `envelope`, signed now: the tip and the final height read from the
    /// chain (`get_latest_block`, `get_finality`).
    pub async fn signed_now(server: &RpcServer, envelope: SponsoredMessage, form: Form) -> Self {
        let signed_at = tip(server).await.expect("the chain tip");
        let final_at_signing = server
            .get_finality()
            .await
            .expect("the final height")
            .finalized_height;
        Self {
            envelope,
            form,
            signed_at,
            final_at_signing,
        }
    }

    pub fn sender(&self) -> Address {
        Address::from_public_key(&self.envelope.sender_pubkey)
    }
}

/// How an intent ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The canonical chain holds a transaction carrying exactly this signed
    /// envelope, executed successfully: the wrapper `tx_hash`.
    Delivered { tx_hash: String },
    /// The envelope can never execute; the user must sign a new one. Why.
    NeedsUserSignature(String),
    /// The client stopped without delivering it. Why.
    Undeliverable(String),
}

/// What one step of the protocol did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// A wrapper is still pending, a request is in flight, or the relay asked
    /// to retry later.
    Wait,
    /// The search was incomplete (a block not available, an RPC error, a
    /// range not yet final): whether the message was delivered is not known.
    /// Nothing is re-signed or reported lost; the client checks again.
    Uncertain(String),
    /// A fresh wrapper of the same envelope was obtained.
    Resubmitted(String),
    Done(Outcome),
}

/// One intent and the wrappers the client obtained for it: what a client
/// persists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tracker {
    pub intent: Intent,
    /// The wrapper requests made, counted before each request is sent.
    pub requests: usize,
    /// The tip's height when the last request was sent, while its result is
    /// not recorded.
    pub in_flight: Option<u64>,
    /// The chain tip's height when the first wrapper was obtained.
    pub first_submitted_at: Option<u64>,
    /// The wrappers' transaction hashes, in the order obtained.
    pub wrappers: Vec<String>,
    pub max_wrappers: usize,
    pub outcome: Option<Outcome>,
    /// The tip's height when a negative outcome's condition was first seen;
    /// the outcome is given once that height is final.
    pub negative_since: Option<u64>,
    /// Where this tracker is persisted; `None` keeps it in memory only.
    #[serde(skip)]
    pub store: Option<PathBuf>,
}

/// The bound the reference client uses.
pub const MAX_WRAPPERS: usize = 3;

/// The JSON-RPC code of `InvalidParams`, which the relay and
/// `messaging_getMessageData` use for a definite refusal.
const INVALID_PARAMS: i32 = -32602;
/// The JSON-RPC code of `TxRejected`: the pool or the relay refused the
/// transaction, which therefore does not exist.
const TX_REJECTED: i32 = -32002;
/// The JSON-RPC code of `NotFound`, which `get_latest_block` answers before
/// the first block.
const NOT_FOUND: i32 = -32001;

fn request(m: &SponsoredMessage) -> SubmitSponsoredMessageRequest {
    SubmitSponsoredMessageRequest {
        message_data: format!("0x{}", hex::encode(&m.message_data)),
        recipient_hash: format!("0x{}", hex::encode(m.recipient_hash)),
        signature: format!("0x{}", hex::encode(m.signature)),
        sender_pubkey: format!("0x{}", hex::encode(m.sender_pubkey)),
        nonce: m.nonce,
        expiry: m.expiry,
        koppa_amount: m.koppa_amount.map(|a| a.to_string()),
    }
}

fn strip(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// The chain tip's height: 0 before the first block.
async fn tip(server: &RpcServer) -> Result<u64, String> {
    match server.get_latest_block().await {
        Ok(b) => Ok(b.height),
        Err(e) if e.code() == NOT_FOUND => Ok(0),
        Err(e) => Err(format!("the chain tip could not be read: {}", e.message())),
    }
}

/// Whether a negative outcome can be given now.
#[derive(Clone, Copy)]
enum Settled {
    /// At once: it is about the request, not about a delivery.
    Now,
    /// Once the height at which its condition was first seen is final.
    Through { final_through: u64, tip: u64 },
}

/// What a search of the chain found.
enum Search {
    /// The wrapper that delivered the exact envelope.
    Delivered(String),
    /// Not found in a complete search up to `tip`; blocks up to
    /// `final_through` are final.
    NotFound { final_through: u64, tip: u64 },
    /// The search could not be completed. Why.
    Incomplete(String),
}

impl Tracker {
    pub fn new(intent: Intent) -> Self {
        Self {
            intent,
            requests: 0,
            in_flight: None,
            first_submitted_at: None,
            wrappers: Vec::new(),
            max_wrappers: MAX_WRAPPERS,
            outcome: None,
            negative_since: None,
            store: None,
        }
    }

    /// A tracker persisted at `path` from now on.
    pub fn persisted(intent: Intent, path: &Path) -> Self {
        let mut t = Self::new(intent);
        t.store = Some(path.to_path_buf());
        t.save();
        t
    }

    /// The tracker persisted at `path`, as a restarted client reads it back.
    pub fn load(path: &Path) -> Self {
        let mut t: Self = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        t.store = Some(path.to_path_buf());
        t
    }

    /// Writes the tracker durably: a temporary file, synced, renamed over the
    /// old one, and the directory synced.
    fn save(&self) {
        if let Some(path) = &self.store {
            let tmp = path.with_extension("tmp");
            {
                let mut f = std::fs::File::create(&tmp).unwrap();
                f.write_all(&serde_json::to_vec(self).unwrap()).unwrap();
                f.sync_all().unwrap();
            }
            std::fs::rename(&tmp, path).unwrap();
            let dir = path.parent().unwrap_or_else(|| Path::new("."));
            std::fs::File::open(dir).unwrap().sync_all().unwrap();
        }
    }

    /// The first request to the relay. A refusal here is about the request,
    /// not about a delivery, so its outcome is given at once.
    pub async fn submit(&mut self, server: &RpcServer) -> Step {
        self.ask_for_wrapper(server, Settled::Now).await
    }

    /// A first request after which the client stops before recording the
    /// result, as a client that crashes once the relay has answered: the
    /// request is counted and in flight, the wrapper's hash (returned here,
    /// for the test) is not recorded.
    pub async fn submit_then_crash(&mut self, server: &RpcServer) -> Option<String> {
        self.requests += 1;
        self.in_flight = Some(tip(server).await.unwrap());
        self.save();
        server
            .messaging_submit_sponsored(request(&self.intent.envelope))
            .await
            .ok()
            .map(|r| r.tx_hash)
    }

    /// Exactly this signed envelope, executed successfully on the canonical
    /// chain: first among the client's own wrappers, then among every
    /// transaction of every block above the height final at signing.
    async fn search(&self, server: &RpcServer) -> Search {
        let m = &self.intent.envelope;
        let delivers = |d: &sumchain_rpc::types::MessageDataInfo| {
            strip(&d.envelope_signature) == hex::encode(m.signature)
                && d.envelope_nonce == m.nonce
                && d.envelope_expiry == m.expiry
                && strip(&d.sender_pubkey) == hex::encode(m.sender_pubkey)
                && strip(&d.recipient_hash) == hex::encode(m.recipient_hash)
                && strip(&d.message_data) == hex::encode(&m.message_data)
        };
        // A transaction that is not a relayed message is refused with
        // `InvalidParams`: definitely not this intent. Any other error leaves
        // the search incomplete.
        let read = |h: String| async move {
            match server.messaging_get_message_data(h.clone()).await {
                Ok(Some(d)) => Ok(delivers(&d).then_some(h)),
                Ok(None) => Ok(None),
                Err(e) if e.code() == INVALID_PARAMS => Ok(None),
                Err(e) => Err(format!(
                    "transaction {h} could not be read: {}",
                    e.message()
                )),
            }
        };
        for h in &self.wrappers {
            match read(h.clone()).await {
                Ok(Some(found)) => return Search::Delivered(found),
                Ok(None) => {}
                Err(why) => return Search::Incomplete(why),
            }
        }
        let tip = match tip(server).await {
            Ok(t) => t,
            Err(why) => return Search::Incomplete(why),
        };
        let final_through = match server.get_finality().await {
            Ok(f) => f.finalized_height,
            Err(e) => {
                return Search::Incomplete(format!(
                    "the final height could not be read: {}",
                    e.message()
                ))
            }
        };
        for height in self.intent.final_at_signing.saturating_add(1)..=tip {
            let block = match server.get_block_by_height(height).await {
                Ok(Some(b)) => b,
                Ok(None) => return Search::Incomplete(format!("block {height} is not available")),
                Err(e) => {
                    return Search::Incomplete(format!(
                        "block {height} could not be read: {}",
                        e.message()
                    ))
                }
            };
            for h in block.transactions {
                match read(h).await {
                    Ok(Some(found)) => return Search::Delivered(found),
                    Ok(None) => {}
                    Err(why) => return Search::Incomplete(why),
                }
            }
        }
        Search::NotFound { final_through, tip }
    }

    async fn pending(&self, server: &RpcServer, h: &str) -> bool {
        server
            .sum_get_pending_transactions()
            .await
            .unwrap()
            .iter()
            .any(|t| strip(&t.hash) == strip(h))
    }

    /// A negative outcome: given once its condition has held on a chain final
    /// through the height at which it was first seen; until then uncertain,
    /// and checked again at the next step.
    fn negative(&mut self, settled: Settled, o: Outcome) -> Step {
        let (final_through, tip) = match settled {
            Settled::Now => return self.done(o),
            Settled::Through { final_through, tip } => (final_through, tip),
        };
        let since = *self.negative_since.get_or_insert(tip);
        self.save();
        if final_through >= since {
            self.done(o)
        } else {
            Step::Uncertain(format!(
                "not delivered in the blocks searched, but blocks {}..={tip} are not final \
                 yet; once block {since} is, the outcome would be {o:?}",
                final_through + 1
            ))
        }
    }

    async fn ask_for_wrapper(&mut self, server: &RpcServer, settled: Settled) -> Step {
        if self.requests >= self.max_wrappers {
            return self.negative(
                settled,
                Outcome::Undeliverable(format!(
                    "the retry bound ({} wrappers) is reached",
                    self.max_wrappers
                )),
            );
        }
        // Counted and recorded as in flight before the request is sent: a
        // restart after this point counts it, and knows a wrapper may exist.
        self.requests += 1;
        self.in_flight = Some(tip(server).await.unwrap_or(0));
        self.save();
        match server
            .messaging_submit_sponsored(request(&self.intent.envelope))
            .await
        {
            Ok(r) => {
                if self.first_submitted_at.is_none() {
                    self.first_submitted_at = self.in_flight;
                }
                self.in_flight = None;
                self.negative_since = None;
                self.wrappers.push(r.tx_hash.clone());
                self.save();
                Step::Resubmitted(r.tx_hash)
            }
            Err(e) if e.code() == INVALID_PARAMS || e.code() == TX_REJECTED => {
                // A definite refusal: no wrapper was made, nothing to count.
                self.requests -= 1;
                self.in_flight = None;
                self.save();
                let msg = e.message().to_string();
                if msg.contains("Retry after the next block") || msg.contains("already pending") {
                    // Later, or another wrapper of this envelope is pending.
                    Step::Wait
                } else if self.intent.form == Form::Legacy && msg.contains("version-2") {
                    self.negative(
                        settled,
                        Outcome::NeedsUserSignature(
                            "the relay takes only the version-2 envelope now; it cannot convert \
                             the string form, the user must sign a version-2 envelope"
                                .to_string(),
                        ),
                    )
                } else if msg.contains("already used") {
                    // The nonce was spent since the last read: decide again
                    // from the chain at the next step.
                    Step::Wait
                } else {
                    self.negative(
                        settled,
                        Outcome::Undeliverable(format!("the relay refused: {msg}")),
                    )
                }
            }
            // Not a definite refusal: the relay may have made a wrapper. The
            // request stays counted and in flight.
            Err(_) => Step::Wait,
        }
    }

    fn done(&mut self, o: Outcome) -> Step {
        self.outcome = Some(o.clone());
        self.save();
        Step::Done(o)
    }

    /// One step of the protocol, from what the canonical chain and the pool
    /// show now.
    pub async fn step(&mut self, server: &RpcServer) -> Step {
        match &self.outcome {
            // Checked again: a chain switch can unwind the block that
            // delivered it.
            Some(Outcome::Delivered { .. }) | None => {}
            Some(o) => return Step::Done(o.clone()),
        }
        // 1. Delivered: exactly this envelope, executed, anywhere searched.
        let (final_through, tip) = match self.search(server).await {
            Search::Delivered(tx_hash) => {
                self.negative_since = None;
                return self.done(Outcome::Delivered { tx_hash });
            }
            Search::Incomplete(why) => return Step::Uncertain(why),
            Search::NotFound { final_through, tip } => (final_through, tip),
        };
        if self.outcome.take().is_some() {
            self.save();
        }
        // A request in flight whose result was never recorded (a restart):
        // let a block pass, so its wrapper, if one was made, has executed or
        // is pending, before deciding.
        if let Some(sent_at) = self.in_flight {
            if tip <= sent_at {
                return Step::Wait;
            }
            self.in_flight = None;
            self.save();
        }
        // A wrapper still pending may yet deliver it.
        for h in &self.wrappers {
            if self.pending(server, h).await {
                return Step::Wait;
            }
        }
        // The last wrapper: none, `invalid nonce` (never executed), or gone
        // from the pool without a receipt (never executed either) lead to a
        // retry decision; any other status was executed and refused.
        let refused = match self.wrappers.last() {
            Some(h) => match server.sum_get_receipt(h.clone()).await {
                Ok(Some(r)) if r.status == "invalid nonce" => None,
                Ok(Some(r)) => Some(r.status),
                Ok(None) => None,
                Err(e) => {
                    return Step::Uncertain(format!(
                        "the receipt of {h} could not be read: {}",
                        e.message()
                    ))
                }
            },
            None => None,
        };
        // 2. The committed messaging nonce. Never read as a delivery.
        let committed = match server
            .messaging_get_sender_nonce(self.intent.sender().to_base58())
            .await
        {
            Ok(n) => n.nonce,
            Err(e) => {
                return Step::Uncertain(format!(
                    "the sender's messaging nonce could not be read: {}",
                    e.message()
                ))
            }
        };
        let settled = Settled::Through { final_through, tip };
        let n = self.intent.envelope.nonce;
        if self.intent.form == Form::Version2 && n < committed {
            // 4. Moved past without this message.
            return self.negative(
                settled,
                Outcome::NeedsUserSignature(format!(
                    "the sender's messaging nonce moved from {n} to {committed} without this \
                     message; the user must sign a new envelope at {committed}"
                )),
            );
        }
        if let Some(status) = refused {
            let o = if self.intent.form == Form::Legacy {
                Outcome::NeedsUserSignature(format!(
                    "the string-form envelope was refused in the block ({status}); the user \
                     must sign a version-2 envelope"
                ))
            } else {
                Outcome::Undeliverable(format!("refused in the block: {status}"))
            };
            return self.negative(settled, o);
        }
        if self.intent.form == Form::Version2 && n > committed {
            // An earlier envelope from this sender has not executed yet.
            return Step::Wait;
        }
        // 3 (and 5, when the relay refuses the string form).
        self.ask_for_wrapper(server, settled).await
    }
}

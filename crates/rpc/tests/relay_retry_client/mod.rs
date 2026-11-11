//! A reference client for a relayed message: what a client does when the
//! relay's outer transaction for its message does not deliver it.
//!
//! The relay wraps the user's signed envelope in a sponsor transaction (a
//! "wrapper"). A wrapper the chain refuses with `InvalidNonce` never executed:
//! it charged nothing and moved no messaging nonce. The client then decides
//! from the chain, never from what it remembers:
//!
//! 1. It looks for its intended message by content (sender key, recipient,
//!    message bytes) among the transactions the canonical chain carried since
//!    the user signed the envelope: every block from then to the tip, each
//!    transaction read through `messaging_getMessageData`, which answers from
//!    the stored transaction and its receipt and only for one that executed.
//!    A message carried by a wrapper the client did not request (another
//!    relay, another device, another sponsor's copy) counts too. Found:
//!    delivered, stop; the intent is never sent again. The sender's message
//!    listing (`messaging_getSentMessages`) is not used: it returns the oldest
//!    1,000 records only, and below the transaction-index gate it keeps one
//!    row per sender per block, so a delivery can be missing from it. (The
//!    reference client scans from the signing height at every step; a real
//!    client keeps the height it has scanned to, and after a chain switch
//!    scans again from the fork point.)
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
//! A delivery is final once the block that carries it is final. Until then the
//! client checks it again at each step: a chain switch that unwinds that
//! block puts the intent back into the protocol, and a wrapper the switch
//! returned to the pool is waited for rather than duplicated.
//!
//! A wrapper still pending in the pool, or a relay asking to retry after the
//! next block, is waited for. A wrapper executed and refused in the block (a
//! status other than `success` and `invalid nonce`) ends the intent as
//! undeliverable with that status, unless step 4 or 5 applies.
//!
//! The whole tracker (the envelope, the height it was signed at, the wrappers
//! obtained, the bound, the outcome) is what a client persists with the
//! intent: a client that forgot its wrappers after a restart would count its
//! retries from zero again. `Tracker` serializes for that.
//!
//! Retries are bounded: at most `max_wrappers` wrappers per intent. Who pays:
//! the sponsor pays the outer fee for each wrapper that executes, succeeding
//! or refused in the block (from the accounting height; below it a relayed
//! message is not charged); a wrapper refused with `InvalidNonce` costs
//! nothing; the client pays nothing. A version-2 envelope executes at most
//! once, whichever wrapper carries it, so the sponsor's cost per intent is at
//! most one fee per wrapper, and at most `max_wrappers` fees.
//!
//! Below the envelope verification height both forms follow the earlier
//! rule across a chain switch; the client's content check (step 1) prevents
//! its own resend.

#![allow(dead_code)]

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
/// and the chain tip's height when it was signed. No block at or below that
/// height can carry it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    pub envelope: SponsoredMessage,
    pub form: Form,
    pub signed_at: u64,
}

impl Intent {
    pub fn sender(&self) -> Address {
        Address::from_public_key(&self.envelope.sender_pubkey)
    }
}

/// How an intent ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The canonical chain holds a message record with this content, carried
    /// by the wrapper `tx_hash`.
    Delivered { tx_hash: String },
    /// The envelope can never execute; the user must sign a new one. Why.
    NeedsUserSignature(String),
    /// The client stopped without delivering it. Why.
    Undeliverable(String),
}

/// What one step of the protocol did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// A wrapper is still pending, or the relay asked to retry later.
    Wait,
    /// A fresh wrapper of the same envelope was obtained.
    Resubmitted(String),
    Done(Outcome),
}

/// One intent and the wrappers the client obtained for it: what a client
/// persists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tracker {
    pub intent: Intent,
    /// The wrappers' transaction hashes, in the order obtained.
    pub wrappers: Vec<String>,
    pub max_wrappers: usize,
    pub outcome: Option<Outcome>,
}

/// The bound the reference client uses.
pub const MAX_WRAPPERS: usize = 3;

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

impl Tracker {
    pub fn new(intent: Intent) -> Self {
        Self {
            intent,
            wrappers: Vec::new(),
            max_wrappers: MAX_WRAPPERS,
            outcome: None,
        }
    }

    /// The first request to the relay.
    pub async fn submit(&mut self, server: &RpcServer) -> Step {
        self.ask_for_wrapper(server).await
    }

    /// The wrapper whose execution delivered this intent's content on the
    /// canonical chain, if any: first among the wrappers this client
    /// obtained, then among every transaction carried since the envelope was
    /// signed. `messaging_getMessageData` answers from the stored transaction
    /// and its receipt, and only for a relayed message that executed; any
    /// other transaction is refused or answered with nothing, and is not this
    /// intent.
    async fn delivered_by(&self, server: &RpcServer) -> Option<String> {
        let m = &self.intent.envelope;
        let delivers = |d: &sumchain_rpc::types::MessageDataInfo| {
            strip(&d.sender_pubkey) == hex::encode(m.sender_pubkey)
                && strip(&d.recipient_hash) == hex::encode(m.recipient_hash)
                && strip(&d.message_data) == hex::encode(&m.message_data)
        };
        for h in &self.wrappers {
            if let Ok(Some(d)) = server.messaging_get_message_data(h.clone()).await {
                if delivers(&d) {
                    return Some(h.clone());
                }
            }
        }
        let tip = match server.get_latest_block().await {
            Ok(b) => b.height,
            Err(_) => return None,
        };
        for height in self.intent.signed_at.saturating_add(1)..=tip {
            let Some(block) = server.get_block_by_height(height).await.unwrap() else {
                continue;
            };
            for h in block.transactions {
                if let Ok(Some(d)) = server.messaging_get_message_data(h.clone()).await {
                    if delivers(&d) {
                        return Some(h);
                    }
                }
            }
        }
        None
    }

    async fn pending(&self, server: &RpcServer, h: &str) -> bool {
        server
            .sum_get_pending_transactions()
            .await
            .unwrap()
            .iter()
            .any(|t| strip(&t.hash) == strip(h))
    }

    async fn ask_for_wrapper(&mut self, server: &RpcServer) -> Step {
        if self.wrappers.len() >= self.max_wrappers {
            return self.done(Outcome::Undeliverable(format!(
                "the retry bound ({} wrappers) is reached",
                self.max_wrappers
            )));
        }
        match server
            .messaging_submit_sponsored(request(&self.intent.envelope))
            .await
        {
            Ok(r) => {
                self.wrappers.push(r.tx_hash.clone());
                Step::Resubmitted(r.tx_hash)
            }
            Err(e) => {
                let msg = e.message().to_string();
                if msg.contains("Retry after the next block") || msg.contains("already pending") {
                    // Later, or another wrapper of this envelope is pending.
                    Step::Wait
                } else if self.intent.form == Form::Legacy && msg.contains("version-2") {
                    self.done(Outcome::NeedsUserSignature(
                        "the relay takes only the version-2 envelope now; it cannot convert \
                         the string form, the user must sign a version-2 envelope"
                            .to_string(),
                    ))
                } else if msg.contains("already used") {
                    // The nonce was spent since the last read: decide again
                    // from the chain at the next step.
                    Step::Wait
                } else {
                    self.done(Outcome::Undeliverable(format!("the relay refused: {msg}")))
                }
            }
        }
    }

    fn done(&mut self, o: Outcome) -> Step {
        self.outcome = Some(o.clone());
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
        // 1. Delivered, by content, whichever wrapper carried it.
        if let Some(tx_hash) = self.delivered_by(server).await {
            return self.done(Outcome::Delivered { tx_hash });
        }
        self.outcome = None;
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
            Some(h) => match server.sum_get_receipt(h.clone()).await.unwrap() {
                Some(r) if r.status == "invalid nonce" => None,
                Some(r) => Some(r.status),
                None => None,
            },
            None => None,
        };
        // 2. The committed messaging nonce. Never read as a delivery.
        let committed = server
            .messaging_get_sender_nonce(self.intent.sender().to_base58())
            .await
            .unwrap()
            .nonce;
        let n = self.intent.envelope.nonce;
        if self.intent.form == Form::Version2 && n < committed {
            // 4. Moved past without this message.
            return self.done(Outcome::NeedsUserSignature(format!(
                "the sender's messaging nonce moved from {n} to {committed} without this \
                 message; the user must sign a new envelope at {committed}"
            )));
        }
        if let Some(status) = refused {
            return self.done(if self.intent.form == Form::Legacy {
                Outcome::NeedsUserSignature(format!(
                    "the string-form envelope was refused in the block ({status}); the user \
                     must sign a version-2 envelope"
                ))
            } else {
                Outcome::Undeliverable(format!("refused in the block: {status}"))
            });
        }
        if self.intent.form == Form::Version2 && n > committed {
            // An earlier envelope from this sender has not executed yet.
            return Step::Wait;
        }
        // 3 (and 5, when the relay refuses the string form).
        self.ask_for_wrapper(server).await
    }
}

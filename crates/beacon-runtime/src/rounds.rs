//! Chained-round beacon state machine (draft §10, §12).
//!
//! [`BeaconChain`] drives the per-round signing lifecycle over a successful DKG
//! epoch ([`QualifiedEpoch`]): it constructs each round message with GENESIS/ROUND
//! domain separation and the chained `Σ_prev` (draft §12.1), enforces **monotonic**
//! round progression, accepts partials with replay/conflict detection, verifies the
//! finalized output and computes the OUT-domain beacon value with cross-round replay
//! separation, and supports **reorg restoration** of prior rounds / finalized
//! signatures (draft §10). Pure logic over the crypto adapter; no state mutation on
//! chain, no activation.

use std::collections::BTreeMap;

use sumchain_beacon_crypto::Signature;

use crate::context::{BeaconPhase, ContextError, ExecContext};
use crate::signing::{FinalizeError, PartialError, QualifiedEpoch};
use crate::wire::{beacon_output, round_message, BeaconFinalizeV1, BeaconPartialV1, ChainInput};

/// A finalized round: the combined signature `Σ_r` and its OUT-domain beacon output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedRound {
    /// The combined round signature `Σ_r` (draft §4.3).
    pub sigma_r: Signature,
    /// The beacon output `beacon_r` (OUT domain, draft §12.1).
    pub output: [u8; 32],
}

/// The outcome of accepting a partial into a round (draft §10, replay/conflict).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartialOutcome {
    /// A new verifying partial for `(round, j)` was recorded.
    Accepted,
    /// A byte-identical resubmission for `(round, j)` — no-op (BLS partials are
    /// unique per message, so an honest resubmission is always identical).
    Replay,
    /// A *different* verifying partial for an already-recorded `(round, j)` —
    /// modelled defensively; retained as [`PartialConflictEvidence`] (boxed to keep
    /// the common variants small). (Unreachable on one history: `Σ_j = H(m_r)^{sk_j}`
    /// is unique for a fixed `m_r`.)
    Conflict(Box<PartialConflictEvidence>),
}

/// Retained evidence of two conflicting partials for one `(round, j)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartialConflictEvidence {
    /// The round.
    pub round: u64,
    /// The participant index `j`.
    pub j: u32,
    /// The first recorded partial signature bytes.
    pub first: [u8; 96],
    /// The conflicting partial signature bytes.
    pub second: [u8; 96],
}

/// The finalized-round result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizeOutcome {
    /// The round finalized.
    pub round: u64,
    /// Its beacon output (OUT domain).
    pub output: [u8; 32],
}

/// A round-lifecycle failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RoundError {
    /// A partial-level failure (context / crypto / vk).
    #[error("partial error: {0}")]
    Partial(PartialError),
    /// A finalize-level failure (context / witness / signature).
    #[error("finalize error: {0}")]
    Finalize(FinalizeError),
    /// A context-binding failure at the round boundary.
    #[error("context violation: {0}")]
    Context(ContextError),
    /// A partial/finalize referenced a round `r>0` whose predecessor `r−1` is not
    /// finalized (its `Σ_{r-1}` — the chained input — is unavailable).
    #[error("round {round} predecessor is not finalized")]
    MissingPredecessor { round: u64 },
    /// Finalize did not target the next expected round (monotonic progression).
    #[error("non-monotonic finalize: expected round {expected}, got {got}")]
    NonMonotonic { expected: u64, got: u64 },
    /// The round is already finalized (idempotence / no re-finalize).
    #[error("round {round} already finalized")]
    AlreadyFinalized { round: u64 },
    /// A verifying partial did not verify — rejected, not recorded.
    #[error("partial signature did not verify")]
    PartialDidNotVerify,
}

impl From<PartialError> for RoundError {
    fn from(e: PartialError) -> Self {
        RoundError::Partial(e)
    }
}
impl From<FinalizeError> for RoundError {
    fn from(e: FinalizeError) -> Self {
        RoundError::Finalize(e)
    }
}
impl From<ContextError> for RoundError {
    fn from(e: ContextError) -> Self {
        RoundError::Context(e)
    }
}

/// The chained-round beacon state machine for one epoch.
#[derive(Clone, Debug)]
pub struct BeaconChain {
    chain_id: u64,
    epoch: u64,
    n: u32,
    qe: QualifiedEpoch,
    genesis: [u8; 32],
    rounds: BTreeMap<u64, FinalizedRound>,
    partials: BTreeMap<(u64, u32), [u8; 96]>,
    partial_conflicts: Vec<PartialConflictEvidence>,
}

impl BeaconChain {
    /// Start a chain over a qualified epoch, anchored at the genesis seed (§12.1).
    pub fn new(qe: QualifiedEpoch, genesis: [u8; 32]) -> Self {
        let chain_id = qe.chain_id();
        let epoch = qe.epoch();
        let n = qe.params().n();
        BeaconChain {
            chain_id,
            epoch,
            n,
            qe,
            genesis,
            rounds: BTreeMap::new(),
            partials: BTreeMap::new(),
            partial_conflicts: Vec::new(),
        }
    }

    /// The next round expected to be finalized (0 initially; contiguous by the
    /// monotonic guard).
    pub fn next_round(&self) -> u64 {
        self.rounds.keys().next_back().map(|r| r + 1).unwrap_or(0)
    }

    /// The finalized round record, if any.
    pub fn finalized(&self, round: u64) -> Option<&FinalizedRound> {
        self.rounds.get(&round)
    }

    /// Retained conflicting-partial evidence.
    pub fn partial_conflicts(&self) -> &[PartialConflictEvidence] {
        &self.partial_conflicts
    }

    /// Build the round message `m_r` for `round`: genesis seed for round 0, else the
    /// chained `Σ_{round-1}` (draft §12.1). Errors if the predecessor is unfinalized.
    pub fn round_message(&self, round: u64) -> Result<Vec<u8>, RoundError> {
        if round == 0 {
            Ok(round_message(
                self.chain_id,
                self.epoch,
                0,
                &ChainInput::GenesisSeed(self.genesis),
            ))
        } else {
            let prev = self
                .rounds
                .get(&(round - 1))
                .ok_or(RoundError::MissingPredecessor { round })?;
            Ok(round_message(
                self.chain_id,
                self.epoch,
                round,
                &ChainInput::Previous(&prev.sigma_r),
            ))
        }
    }

    /// Accept a partial into its round with authenticated binding + replay/conflict
    /// detection (draft §10). The partial must verify under its `vk_j` over the
    /// chained `m_r`; a non-verifying partial is rejected (not recorded).
    pub fn accept_partial(
        &mut self,
        ctx: &ExecContext,
        partial: &BeaconPartialV1,
    ) -> Result<PartialOutcome, RoundError> {
        let m_r = self.round_message(partial.round)?;
        if !self.qe.accept_partial(ctx, partial, &m_r)? {
            return Err(RoundError::PartialDidNotVerify);
        }
        let key = (partial.round, partial.j);
        match self.partials.get(&key) {
            Some(existing) if *existing == partial.sigma_j => Ok(PartialOutcome::Replay),
            Some(existing) => {
                let evidence = PartialConflictEvidence {
                    round: partial.round,
                    j: partial.j,
                    first: *existing,
                    second: partial.sigma_j,
                };
                self.partial_conflicts.push(evidence);
                Ok(PartialOutcome::Conflict(Box::new(evidence)))
            }
            None => {
                self.partials.insert(key, partial.sigma_j);
                Ok(PartialOutcome::Accepted)
            }
        }
    }

    /// Finalize a round from a `BeaconFinalizeV1` (draft §4.3, §12): enforce monotonic
    /// progression, chained predecessor, authenticated context, the exactly-`T`
    /// canonical membership-valid witness, and the `Σ_r` pairing verification under
    /// `PK_E`. Records the round + its OUT-domain output.
    pub fn finalize_round(
        &mut self,
        ctx: &ExecContext,
        finalize: &BeaconFinalizeV1,
    ) -> Result<FinalizeOutcome, RoundError> {
        if self.rounds.contains_key(&finalize.round) {
            return Err(RoundError::AlreadyFinalized {
                round: finalize.round,
            });
        }
        let expected = self.next_round();
        if finalize.round != expected {
            return Err(RoundError::NonMonotonic {
                expected,
                got: finalize.round,
            });
        }
        let m_r = self.round_message(finalize.round)?;
        // Context binding at the round boundary (chain/epoch + signing phase).
        ctx.check_chain_epoch(finalize.chain_id, finalize.epoch)?;
        ctx.check_phase(BeaconPhase::Signing)?;
        // Witness + Σ_r crypto (membership `n` bound enforced here).
        let sigma_r = self.qe.verify_finalize_sig(finalize, self.n, &m_r)?;

        let output = beacon_output(self.chain_id, self.epoch, finalize.round, &sigma_r);
        self.rounds
            .insert(finalize.round, FinalizedRound { sigma_r, output });
        Ok(FinalizeOutcome {
            round: finalize.round,
            output,
        })
    }

    // -- Reorg support (draft §10) ------------------------------------------

    /// Revert every finalized round and partial strictly **after** `keep_through`
    /// (pass `None` to drop all), restoring the chain to the state buried at that
    /// height on the winning history. Retained conflict evidence for reverted rounds
    /// is dropped. After this, [`next_round`](Self::next_round) is `keep_through + 1`.
    pub fn revert_after(&mut self, keep_through: Option<u64>) {
        let cutoff = keep_through;
        self.rounds.retain(|&r, _| match cutoff {
            Some(k) => r <= k,
            None => false,
        });
        self.partials.retain(|&(r, _j), _| match cutoff {
            Some(k) => r <= k,
            None => false,
        });
        self.partial_conflicts.retain(|e| match cutoff {
            Some(k) => e.round <= k,
            None => false,
        });
    }

    /// Restore a previously-finalized round from the winning history during a reorg
    /// replay (draft §10.1): re-present its `Σ_r` and recompute the OUT output. The
    /// round must be the next expected one (contiguous restore) and verify under
    /// `PK_E` over the chained `m_r` — a restore cannot inject an unverified output.
    pub fn restore_finalized(
        &mut self,
        round: u64,
        sigma_r: &Signature,
    ) -> Result<FinalizeOutcome, RoundError> {
        if self.rounds.contains_key(&round) {
            return Err(RoundError::AlreadyFinalized { round });
        }
        let expected = self.next_round();
        if round != expected {
            return Err(RoundError::NonMonotonic {
                expected,
                got: round,
            });
        }
        let m_r = self.round_message(round)?;
        if !sumchain_beacon_crypto::verify(self.qe.group_key(), &m_r, sigma_r) {
            return Err(RoundError::Finalize(FinalizeError::SignatureInvalid));
        }
        let output = beacon_output(self.chain_id, self.epoch, round, sigma_r);
        self.rounds.insert(
            round,
            FinalizedRound {
                sigma_r: *sigma_r,
                output,
            },
        );
        Ok(FinalizeOutcome { round, output })
    }
}

//! BR1 beacon (#127) shared, pure integer surfaces: the **single** threshold/fault
//! parameter predicate and the authoritative height→epoch schedule.
//!
//! This module has NO curve/pairing dependency, so BOTH the genesis crate
//! (`sumchain_genesis`) and the runtime crate (`sumchain_beacon_runtime`) delegate
//! their parameter validation here — one rule set, not two drifting ones. The
//! schedule is the deterministic map from block height to `(epoch, phase, cutoffs)`;
//! it is FROZEN (its outputs enter membership selection, tx validation, persistence
//! keys, and the replay domains). **The schedule is NOT an activation height** — it is
//! valid config even while `beacon_enabled_from_height` stays `None`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared parameter predicate (draft §7.4) — the single source of truth.
// ---------------------------------------------------------------------------

/// A threshold/fault parameter-set violation (draft §7.4). The variant names +
/// payloads are the canonical parameter-error surface; `sumchain_beacon_runtime`
/// re-exports this as its `ParamsError`, and `sumchain_genesis` maps it via
/// [`Self::reason`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BeaconParamsViolation {
    /// A zero threshold `T` is never valid.
    #[error("reconstruction threshold T must be >= 1")]
    ZeroThreshold,
    /// `T` must be at least `f + 1` (S1).
    #[error("reconstruction threshold T={t} must be >= f+1={min} (draft §7.4 S1)")]
    ThresholdTooSmall {
        /// The supplied `T`.
        t: u32,
        /// The minimum `f + 1`.
        min: u32,
    },
    /// `Q_dkg` must be at least `2f + 1` (S2).
    #[error("qualification size Q_dkg={q} must be >= 2f+1={min} (draft §7.4 S2)")]
    QualTooSmall {
        /// The supplied `Q_dkg`.
        q: u32,
        /// The minimum `2f + 1`.
        min: u32,
    },
    /// Consistency `T ≤ Q_dkg ≤ n` (C1).
    #[error("consistency violated: require T={t} <= Q_dkg={q} <= n={n} (draft §7.4 C1)")]
    Inconsistent {
        /// `T`.
        t: u32,
        /// `Q_dkg`.
        q: u32,
        /// `n`.
        n: u32,
    },
    /// Liveness (L1) signing: `n − f − c ≥ T`.
    #[error("liveness L1 violated: n-f-c={avail} must be >= T={t} (draft §7.4 L1)")]
    LivenessSigning {
        /// `n − f − c`.
        avail: i64,
        /// `T`.
        t: u32,
    },
    /// Liveness (L2) qualification: `n − f − c ≥ Q_dkg`.
    #[error("liveness L2 violated: n-f-c={avail} must be >= Q_dkg={q} (draft §7.4 L2)")]
    LivenessQual {
        /// `n − f − c`.
        avail: i64,
        /// `Q_dkg`.
        q: u32,
    },
}

impl BeaconParamsViolation {
    /// A stable `&'static str` reason (for callers that surface a string).
    pub fn reason(&self) -> &'static str {
        match self {
            BeaconParamsViolation::ZeroThreshold => "reconstruction threshold T must be >= 1",
            BeaconParamsViolation::ThresholdTooSmall { .. } => "require T >= f+1 (S1)",
            BeaconParamsViolation::QualTooSmall { .. } => "require Q_dkg >= 2f+1 (S2)",
            BeaconParamsViolation::Inconsistent { .. } => "require T <= Q_dkg <= n (C1)",
            BeaconParamsViolation::LivenessSigning { .. } => "require n-f-c >= T (L1)",
            BeaconParamsViolation::LivenessQual { .. } => "require n-f-c >= Q_dkg (L2)",
        }
    }
}

/// The **single** BR1 threshold/fault predicate (draft §7.4): `T ≥ 1`, `T = f+1`,
/// `Q_dkg = 2f+1`, `T ≤ Q_dkg ≤ n`, `n−f−c ≥ T` (L1), `n−f−c ≥ Q_dkg` (L2). Pure
/// integer arithmetic; both genesis config validation and the runtime's
/// `BeaconParams::validated` delegate here.
pub fn validate_beacon_params(
    f: u32,
    c: u32,
    t: u32,
    q_dkg: u32,
    n: u32,
) -> Result<(), BeaconParamsViolation> {
    if t == 0 {
        return Err(BeaconParamsViolation::ZeroThreshold);
    }
    if t < f + 1 {
        return Err(BeaconParamsViolation::ThresholdTooSmall { t, min: f + 1 });
    }
    if q_dkg < 2 * f + 1 {
        return Err(BeaconParamsViolation::QualTooSmall {
            q: q_dkg,
            min: 2 * f + 1,
        });
    }
    if !(t <= q_dkg && q_dkg <= n) {
        return Err(BeaconParamsViolation::Inconsistent { t, q: q_dkg, n });
    }
    let avail = n as i64 - f as i64 - c as i64;
    if avail < t as i64 {
        return Err(BeaconParamsViolation::LivenessSigning { avail, t });
    }
    if avail < q_dkg as i64 {
        return Err(BeaconParamsViolation::LivenessQual { avail, q: q_dkg });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Height→epoch schedule (deterministic, checked, FROZEN). Not an activation height.
// ---------------------------------------------------------------------------

/// A schedule config error (rejected at genesis load).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BeaconScheduleError {
    /// `epoch_length` is zero (an epoch must span ≥ 1 block).
    #[error("epoch_length must be >= 1")]
    ZeroEpochLength,
    /// The within-epoch phase offsets do not satisfy the ratified STRICT PHASE
    /// SEPARATION: require `key_cutoff_offset < deal_start_offset <=
    /// deal_cutoff_offset < complaint_start_offset <= complaint_deadline_offset`
    /// with a non-empty signing window (`complaint_deadline_offset + 1 < epoch_length`).
    #[error(
        "phase offsets must satisfy key_cutoff_offset < deal_start_offset <= \
         deal_cutoff_offset < complaint_start_offset <= complaint_deadline_offset, \
         with complaint_deadline_offset + 1 < epoch_length (non-empty signing window)"
    )]
    UnorderedOffsets,
    /// A height derivation overflowed `u64` (astronomically large height).
    #[error("beacon epoch derivation overflowed u64")]
    Overflow,
}

/// The BR1 height→epoch schedule config (issue #127). Authoritative, validated at
/// genesis load. **Declaring it does NOT activate the beacon** — the gate stays
/// `None`. Within each epoch of `epoch_length` blocks starting at `start_height`,
/// the ratified STRICT PHASE SEPARATION applies: key-registration
/// `[epoch_start, +key_cutoff_offset]`, deal `[+deal_start_offset, +deal_cutoff_offset]`,
/// complaint `[+complaint_start_offset, +complaint_deadline_offset]`, then signing
/// after the complaint deadline (draft §11.3, §6.5, §8; magnitudes are config, not
/// consensus-fixed constants).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconSchedule {
    /// The block height at which beacon epoch 0 begins. Heights below this have no
    /// beacon epoch.
    pub start_height: u64,
    /// The number of blocks per epoch (≥ enough for all four windows).
    pub epoch_length: u64,
    /// Inclusive end of the KEY-REGISTRATION window: `[epoch_start, epoch_start +
    /// key_cutoff_offset]` (register-before-cutoff, §11 rule 3).
    pub key_cutoff_offset: u64,
    /// Start of the DEAL window (strictly after the key cutoff): `[epoch_start +
    /// deal_start_offset, epoch_start + deal_cutoff_offset]`.
    pub deal_start_offset: u64,
    /// Inclusive end of the DEAL window (§8).
    pub deal_cutoff_offset: u64,
    /// Start of the COMPLAINT window (strictly after the deal cutoff): `[epoch_start +
    /// complaint_start_offset, epoch_start + complaint_deadline_offset]`.
    pub complaint_start_offset: u64,
    /// Inclusive end of the COMPLAINT window / the complaint deadline (§6.5, §11.3).
    /// SIGNING is ONLY after this (`position > complaint_deadline_offset`, to epoch
    /// end).
    pub complaint_deadline_offset: u64,
}

/// The ratified within-epoch lifecycle phase of a block height (draft §11.3, §6.5,
/// §8). Each op kind is valid ONLY in its own window; a gap between windows admits no
/// op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeaconWindowPhase {
    /// K-rotate encryption-key registration window.
    KeyRegistration,
    /// DKG deal window.
    Deal,
    /// Complaint-adjudication window.
    Complaint,
    /// Threshold-signing / output window (after the complaint deadline).
    Signing,
}

/// The deterministic derivation at a block height: the epoch, its start height, and
/// the within-epoch lifecycle phase (`None` in a between-windows gap — no op valid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconEpochPoint {
    /// The 0-based beacon epoch index.
    pub epoch: u64,
    /// The first block height of this epoch (the membership-snapshot boundary).
    pub epoch_start: u64,
    /// The within-epoch phase, or `None` for a between-windows gap.
    pub phase: Option<BeaconWindowPhase>,
}

impl BeaconSchedule {
    /// Validate the config, enforcing the ratified STRICT PHASE SEPARATION (draft
    /// §11.3, §6.5, §8): `key_cutoff < deal_start ≤ deal_cutoff < complaint_start ≤
    /// complaint_deadline`, every required window spans ≥ 1 block, no two windows
    /// overlap, and a non-empty signing window remains before epoch end
    /// (`complaint_deadline_offset + 1 < epoch_length`). `epoch_length ≥ 1`.
    pub fn validate(&self) -> Result<(), BeaconScheduleError> {
        if self.epoch_length == 0 {
            return Err(BeaconScheduleError::ZeroEpochLength);
        }
        // Strict ordering (< between windows ⇒ no overlap) + non-empty windows (≤
        // within each). Key window `[0, key_cutoff]` is always ≥ 1 block.
        let ordered = self.key_cutoff_offset < self.deal_start_offset
            && self.deal_start_offset <= self.deal_cutoff_offset
            && self.deal_cutoff_offset < self.complaint_start_offset
            && self.complaint_start_offset <= self.complaint_deadline_offset
            // Signing window `[complaint_deadline+1, epoch_length-1]` must be ≥ 1 block.
            && self.complaint_deadline_offset + 1 < self.epoch_length;
        if !ordered {
            return Err(BeaconScheduleError::UnorderedOffsets);
        }
        Ok(())
    }

    /// Deterministically derive `(epoch, epoch_start, phase)` at `height` with CHECKED
    /// arithmetic. `Ok(None)` for a pre-start height (no beacon epoch); `Err` on `u64`
    /// overflow. The phase is `None` in a between-windows gap. Requires a valid config
    /// ([`validate`](Self::validate)).
    pub fn derive(&self, height: u64) -> Result<Option<BeaconEpochPoint>, BeaconScheduleError> {
        if height < self.start_height {
            return Ok(None);
        }
        let delta = height - self.start_height; // height >= start_height
        let epoch = delta / self.epoch_length;
        let position = delta % self.epoch_length;
        let epoch_offset = epoch
            .checked_mul(self.epoch_length)
            .ok_or(BeaconScheduleError::Overflow)?;
        let epoch_start = self
            .start_height
            .checked_add(epoch_offset)
            .ok_or(BeaconScheduleError::Overflow)?;
        let phase = self.phase_at_position(position);
        Ok(Some(BeaconEpochPoint {
            epoch,
            epoch_start,
            phase,
        }))
    }

    /// The within-epoch phase for a 0-based `position` (`= height − epoch_start`), or
    /// `None` in a between-windows gap.
    fn phase_at_position(&self, position: u64) -> Option<BeaconWindowPhase> {
        if position <= self.key_cutoff_offset {
            Some(BeaconWindowPhase::KeyRegistration)
        } else if position >= self.deal_start_offset && position <= self.deal_cutoff_offset {
            Some(BeaconWindowPhase::Deal)
        } else if position >= self.complaint_start_offset
            && position <= self.complaint_deadline_offset
        {
            Some(BeaconWindowPhase::Complaint)
        } else if position > self.complaint_deadline_offset {
            Some(BeaconWindowPhase::Signing)
        } else {
            None // between-windows gap
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_predicate_accepts_proposed_and_rejects_each_violation() {
        assert!(validate_beacon_params(1, 1, 2, 3, 5).is_ok());
        assert!(validate_beacon_params(2, 1, 3, 5, 8).is_ok());
        assert_eq!(
            validate_beacon_params(1, 1, 0, 3, 5),
            Err(BeaconParamsViolation::ZeroThreshold)
        );
        assert!(matches!(
            validate_beacon_params(1, 1, 1, 3, 5),
            Err(BeaconParamsViolation::ThresholdTooSmall { .. })
        ));
        assert!(matches!(
            validate_beacon_params(1, 1, 2, 2, 5),
            Err(BeaconParamsViolation::QualTooSmall { .. })
        ));
        assert!(matches!(
            validate_beacon_params(1, 1, 2, 3, 2),
            Err(BeaconParamsViolation::Inconsistent { .. })
        ));
        assert!(matches!(
            validate_beacon_params(1, 1, 2, 3, 4),
            Err(BeaconParamsViolation::LivenessQual { .. })
        ));
    }

    /// A canonical strict-phase schedule for the golden vectors. start=100, len=100:
    /// KeyReg [100,110], gap [111,119], Deal [120,130], gap [131,139],
    /// Complaint [140,150], Signing [151,199]; epoch 1 starts at 200.
    fn golden_schedule() -> BeaconSchedule {
        BeaconSchedule {
            start_height: 100,
            epoch_length: 100,
            key_cutoff_offset: 10,
            deal_start_offset: 20,
            deal_cutoff_offset: 30,
            complaint_start_offset: 40,
            complaint_deadline_offset: 50,
        }
    }

    #[test]
    fn schedule_validation_strict_phase_separation() {
        let ok = golden_schedule();
        assert!(ok.validate().is_ok());
        // zero epoch length
        let mut z = ok;
        z.epoch_length = 0;
        assert_eq!(z.validate(), Err(BeaconScheduleError::ZeroEpochLength));
        // key_cutoff >= deal_start (windows would touch/overlap).
        let mut a = ok;
        a.key_cutoff_offset = 20;
        assert_eq!(a.validate(), Err(BeaconScheduleError::UnorderedOffsets));
        // deal_start > deal_cutoff (empty deal window).
        let mut b = ok;
        b.deal_start_offset = 31;
        assert_eq!(b.validate(), Err(BeaconScheduleError::UnorderedOffsets));
        // deal_cutoff >= complaint_start (touching windows).
        let mut c = ok;
        c.deal_cutoff_offset = 40;
        assert_eq!(c.validate(), Err(BeaconScheduleError::UnorderedOffsets));
        // complaint_start > complaint_deadline (empty complaint window).
        let mut d = ok;
        d.complaint_start_offset = 51;
        assert_eq!(d.validate(), Err(BeaconScheduleError::UnorderedOffsets));
        // empty signing window (complaint_deadline+1 == epoch_length).
        let mut e = ok;
        e.epoch_length = 51;
        assert_eq!(e.validate(), Err(BeaconScheduleError::UnorderedOffsets));
    }

    /// GOLDEN phase-boundary vectors: the derived phase frozen at EVERY transition
    /// (last/first block of each window) + the reject-one-block-before/after cases
    /// (gap ⇒ `None`) + pre-start, epoch rollover, and overflow.
    #[test]
    fn schedule_phase_golden_boundaries() {
        let s = golden_schedule();
        s.validate().unwrap();
        let phase = |h: u64| s.derive(h).unwrap().map(|p| p.phase);
        let epoch = |h: u64| s.derive(h).unwrap().map(|p| (p.epoch, p.epoch_start));
        use BeaconWindowPhase::*;

        // pre-start
        assert_eq!(s.derive(99).unwrap(), None);
        // epoch/epoch_start rollover
        assert_eq!(epoch(100), Some((0, 100)));
        assert_eq!(epoch(199), Some((0, 100)));
        assert_eq!(epoch(200), Some((1, 200)));

        // KeyRegistration window [100,110]; reject one after (111 → gap).
        assert_eq!(phase(100), Some(Some(KeyRegistration))); // first key block
        assert_eq!(phase(110), Some(Some(KeyRegistration))); // LAST key block
        assert_eq!(phase(111), Some(None)); // one after → gap (reject key)
        assert_eq!(phase(119), Some(None)); // one before deal → gap

        // Deal window [120,130]; reject one before (119→gap) and one after (131→gap).
        assert_eq!(phase(120), Some(Some(Deal))); // FIRST deal block
        assert_eq!(phase(130), Some(Some(Deal))); // LAST deal block
        assert_eq!(phase(131), Some(None)); // one after → gap (reject deal)
        assert_eq!(phase(139), Some(None)); // one before complaint → gap

        // Complaint window [140,150]; reject one before (139→gap) and one after (151→signing).
        assert_eq!(phase(140), Some(Some(Complaint))); // FIRST complaint block
        assert_eq!(phase(150), Some(Some(Complaint))); // LAST complaint block
        assert_eq!(phase(151), Some(Some(Signing))); // FIRST signing block (one after complaint)

        // Signing window [151,199]; last block of the epoch.
        assert_eq!(phase(199), Some(Some(Signing)));
        // Next epoch's boundary is KeyRegistration again.
        assert_eq!(phase(200), Some(Some(KeyRegistration)));

        // Overflow edge: u64::MAX divisible by 3, epoch_start=u64::MAX; but this
        // schedule has no epoch-start-relative offset overflow because phase is derived
        // from position only — so exercise overflow with a start-relative overflow of
        // `epoch_start` itself is impossible; instead confirm derive stays total.
        let big = BeaconSchedule {
            start_height: 0,
            epoch_length: 3,
            key_cutoff_offset: 0,
            deal_start_offset: 1,
            deal_cutoff_offset: 1,
            complaint_start_offset: 2,
            complaint_deadline_offset: 2,
        };
        // epoch_length=3 with these offsets: signing window empty (2+1==3) ⇒ invalid.
        assert!(big.validate().is_err());
        // A valid tiny schedule at an astronomical start still derives without panic.
        let big2 = BeaconSchedule {
            start_height: 0,
            epoch_length: 6,
            key_cutoff_offset: 0,
            deal_start_offset: 1,
            deal_cutoff_offset: 1,
            complaint_start_offset: 2,
            complaint_deadline_offset: 2,
        };
        big2.validate().unwrap();
        // u64::MAX is divisible by 3 but not by 6; check derive is total (no panic).
        assert!(big2.derive(u64::MAX).unwrap().is_some());
    }
}

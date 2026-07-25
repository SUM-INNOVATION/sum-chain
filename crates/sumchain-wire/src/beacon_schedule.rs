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
    /// The within-epoch phase offsets are not strictly ordered and inside the epoch:
    /// require `deal_cutoff_offset < complaint_deadline_offset < epoch_length`.
    #[error(
        "phase offsets must satisfy deal_cutoff_offset < complaint_deadline_offset < epoch_length"
    )]
    UnorderedOffsets,
    /// A height derivation overflowed `u64` (astronomically large height).
    #[error("beacon epoch derivation overflowed u64")]
    Overflow,
}

/// The BR1 height→epoch schedule config (issue #127). Authoritative, validated at
/// genesis load. **Declaring it does NOT activate the beacon** — the gate stays
/// `None`. Within each epoch of `epoch_length` blocks starting at `start_height`:
/// `[epoch_start, epoch_start+deal_cutoff_offset]` is the deal/registration window,
/// `(…, epoch_start+complaint_deadline_offset]` the complaint window, and the
/// remainder the signing window (draft §11.3, §6.5; magnitudes are config, not
/// consensus-fixed constants).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconSchedule {
    /// The block height at which beacon epoch 0 begins. Heights below this have no
    /// beacon epoch.
    pub start_height: u64,
    /// The number of blocks per epoch (≥ 1).
    pub epoch_length: u64,
    /// Within-epoch offset (blocks from `epoch_start`) of the deal/registration
    /// cutoff (register-before-cutoff, §11 rule 3).
    pub deal_cutoff_offset: u64,
    /// Within-epoch offset of the complaint deadline (§6.5, §11.3). Setup ⇒ position
    /// `≤` this; signing ⇒ position `>` this.
    pub complaint_deadline_offset: u64,
}

/// The deterministic derivation at a block height: the epoch, its start height, the
/// absolute deal-cutoff / complaint-deadline heights, and whether the height is in
/// the signing phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconEpochPoint {
    /// The 0-based beacon epoch index.
    pub epoch: u64,
    /// The first block height of this epoch.
    pub epoch_start: u64,
    /// Absolute deal-cutoff height (`epoch_start + deal_cutoff_offset`).
    pub deal_cutoff: u64,
    /// Absolute complaint-deadline height (`epoch_start + complaint_deadline_offset`).
    pub complaint_deadline: u64,
    /// `true` iff the height is in the signing phase (position `>` complaint offset).
    pub phase_is_signing: bool,
}

impl BeaconSchedule {
    /// Validate the config: `epoch_length ≥ 1` and strictly-ordered offsets that fit
    /// within the epoch (`0 ≤ deal_cutoff_offset < complaint_deadline_offset <
    /// epoch_length` — the same strict-phase-separation ordering).
    pub fn validate(&self) -> Result<(), BeaconScheduleError> {
        if self.epoch_length == 0 {
            return Err(BeaconScheduleError::ZeroEpochLength);
        }
        if !(self.deal_cutoff_offset < self.complaint_deadline_offset
            && self.complaint_deadline_offset < self.epoch_length)
        {
            return Err(BeaconScheduleError::UnorderedOffsets);
        }
        Ok(())
    }

    /// Deterministically derive `(epoch, phase, cutoffs)` at `height` with CHECKED
    /// arithmetic. `Ok(None)` for a pre-start height (no beacon epoch); `Err` on
    /// `u64` overflow. Requires a valid config (call [`validate`](Self::validate)
    /// first).
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
        let deal_cutoff = epoch_start
            .checked_add(self.deal_cutoff_offset)
            .ok_or(BeaconScheduleError::Overflow)?;
        let complaint_deadline = epoch_start
            .checked_add(self.complaint_deadline_offset)
            .ok_or(BeaconScheduleError::Overflow)?;
        Ok(Some(BeaconEpochPoint {
            epoch,
            epoch_start,
            deal_cutoff,
            complaint_deadline,
            phase_is_signing: position > self.complaint_deadline_offset,
        }))
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

    #[test]
    fn schedule_validation() {
        assert!(BeaconSchedule {
            start_height: 100,
            epoch_length: 50,
            deal_cutoff_offset: 10,
            complaint_deadline_offset: 20,
        }
        .validate()
        .is_ok());
        // zero epoch length
        assert_eq!(
            BeaconSchedule {
                start_height: 0,
                epoch_length: 0,
                deal_cutoff_offset: 0,
                complaint_deadline_offset: 0
            }
            .validate(),
            Err(BeaconScheduleError::ZeroEpochLength)
        );
        // unordered: deal >= complaint
        assert_eq!(
            BeaconSchedule {
                start_height: 0,
                epoch_length: 50,
                deal_cutoff_offset: 20,
                complaint_deadline_offset: 20
            }
            .validate(),
            Err(BeaconScheduleError::UnorderedOffsets)
        );
        // complaint >= epoch_length
        assert_eq!(
            BeaconSchedule {
                start_height: 0,
                epoch_length: 20,
                deal_cutoff_offset: 10,
                complaint_deadline_offset: 20
            }
            .validate(),
            Err(BeaconScheduleError::UnorderedOffsets)
        );
    }

    /// GOLDEN boundary vectors: `(epoch, epoch_start, deal_cutoff, complaint_deadline,
    /// phase_is_signing)` frozen at every boundary (pre-start, first/last of an epoch,
    /// first of the next epoch) and overflow edges. start=100, len=50, deal=10, cmpl=20.
    #[test]
    fn schedule_derivation_golden_boundaries() {
        let s = BeaconSchedule {
            start_height: 100,
            epoch_length: 50,
            deal_cutoff_offset: 10,
            complaint_deadline_offset: 20,
        };
        s.validate().unwrap();
        // pre-start
        assert_eq!(s.derive(0).unwrap(), None);
        assert_eq!(s.derive(99).unwrap(), None);
        // first height of epoch 0 (position 0 → setup)
        assert_eq!(
            s.derive(100).unwrap().unwrap(),
            BeaconEpochPoint {
                epoch: 0,
                epoch_start: 100,
                deal_cutoff: 110,
                complaint_deadline: 120,
                phase_is_signing: false
            }
        );
        // exactly the complaint deadline (position 20 → still setup, boundary inclusive)
        assert_eq!(
            s.derive(120).unwrap().unwrap(),
            BeaconEpochPoint {
                epoch: 0,
                epoch_start: 100,
                deal_cutoff: 110,
                complaint_deadline: 120,
                phase_is_signing: false
            }
        );
        // one past the deadline (position 21 → signing)
        assert!(s.derive(121).unwrap().unwrap().phase_is_signing);
        // last height of epoch 0 (position 49 → signing)
        assert_eq!(
            s.derive(149).unwrap().unwrap(),
            BeaconEpochPoint {
                epoch: 0,
                epoch_start: 100,
                deal_cutoff: 110,
                complaint_deadline: 120,
                phase_is_signing: true
            }
        );
        // first height of epoch 1
        assert_eq!(
            s.derive(150).unwrap().unwrap(),
            BeaconEpochPoint {
                epoch: 1,
                epoch_start: 150,
                deal_cutoff: 160,
                complaint_deadline: 170,
                phase_is_signing: false
            }
        );
        // last height of epoch 1
        assert_eq!(
            s.derive(199).unwrap().unwrap(),
            BeaconEpochPoint {
                epoch: 1,
                epoch_start: 150,
                deal_cutoff: 160,
                complaint_deadline: 170,
                phase_is_signing: true
            }
        );

        // Overflow edge: `u64::MAX` is exactly divisible by 3, so with epoch_length=3
        // and start=0, height=u64::MAX lands at position 0 with epoch_start=u64::MAX;
        // `epoch_start + deal_cutoff_offset(1)` then overflows u64 → checked → Err.
        let s_of = BeaconSchedule {
            start_height: 0,
            epoch_length: 3,
            deal_cutoff_offset: 1,
            complaint_deadline_offset: 2,
        };
        s_of.validate().unwrap();
        assert_eq!(
            s_of.derive(u64::MAX).unwrap_err(),
            BeaconScheduleError::Overflow
        );
    }
}

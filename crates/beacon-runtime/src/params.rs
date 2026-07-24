//! Beacon threshold / fault parameters (draft §1.2, §7) — validated, not hardcoded.
//!
//! The runtime does **not** bake the proposed `f=1/c=1/T=2/Q=3/n≥5` profile in as
//! authoritative. Instead it accepts a [`BeaconParams`] object that MUST come from
//! authoritative chain configuration (genesis `BeaconParams`, which does not exist
//! yet — the beacon gate stays `None`, fail-closed in `ChainParams::validate`), and
//! it **enforces the ratified inequalities on construction** ([`BeaconParams::
//! validated`]), rejecting any inconsistent config. The proposed profile survives
//! only as a clearly-labelled test fixture ([`BeaconParams::proposed_default`]),
//! never as frozen protocol behavior.

/// A validated construction failure for a [`BeaconParams`] set (draft §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    /// A zero threshold `T` is never valid (degree `T−1` would be negative).
    #[error("reconstruction threshold T must be >= 1")]
    ZeroThreshold,
    /// `T` must be at least `f + 1` (draft §7.4 (S1) unforgeability).
    #[error("reconstruction threshold T={t} must be >= f+1={min} (draft §7.4 S1)")]
    ThresholdTooSmall { t: u32, min: u32 },
    /// `Q_dkg` must be at least `2f + 1` (draft §7.4 (S2) robust DKG).
    #[error("qualification size Q_dkg={q} must be >= 2f+1={min} (draft §7.4 S2)")]
    QualTooSmall { q: u32, min: u32 },
    /// Consistency `T ≤ Q_dkg ≤ n` (draft §7.4 (C1)).
    #[error("consistency violated: require T={t} <= Q_dkg={q} <= n={n} (draft §7.4 C1)")]
    Inconsistent { t: u32, q: u32, n: u32 },
    /// Liveness (L1) signing: `n − f − c ≥ T` (enough honest-online signers).
    #[error("liveness L1 violated: n-f-c={avail} must be >= T={t} (draft §7.4 L1)")]
    LivenessSigning { avail: i64, t: u32 },
    /// Liveness (L2) qualification: `n − f − c ≥ Q_dkg` (enough honest dealers).
    #[error("liveness L2 violated: n-f-c={avail} must be >= Q_dkg={q} (draft §7.4 L2)")]
    LivenessQual { avail: i64, q: u32 },
}

/// The validated threshold / fault parameters governing one beacon epoch
/// (draft §1.2, §7). Construct **only** via [`BeaconParams::validated`], which
/// enforces the ratified inequalities; the fields are read-only.
///
/// Two thresholds are orthogonal (draft §7): `t` (reconstruction — partials to
/// combine; polynomial degree `= t − 1`; each deal carries exactly `t` Feldman
/// commitments) and `q_dkg` (qualification — dealers that must qualify for the
/// group key to exist). `t ≤ q_dkg ≤ n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconParams {
    f: u32,
    c: u32,
    t: u32,
    q_dkg: u32,
    n: u32,
}

impl BeaconParams {
    /// Construct + **validate** a parameter set against the draft §7.4 inequalities:
    /// `T ≥ f+1`, `Q_dkg ≥ 2f+1`, `T ≤ Q_dkg ≤ n`, `n−f−c ≥ T` (L1), `n−f−c ≥ Q_dkg`
    /// (L2). Any violation returns a typed [`ParamsError`]; an invalid config can
    /// never be represented.
    pub fn validated(f: u32, c: u32, t: u32, q_dkg: u32, n: u32) -> Result<Self, ParamsError> {
        if t == 0 {
            return Err(ParamsError::ZeroThreshold);
        }
        if t < f + 1 {
            return Err(ParamsError::ThresholdTooSmall { t, min: f + 1 });
        }
        if q_dkg < 2 * f + 1 {
            return Err(ParamsError::QualTooSmall {
                q: q_dkg,
                min: 2 * f + 1,
            });
        }
        if !(t <= q_dkg && q_dkg <= n) {
            return Err(ParamsError::Inconsistent { t, q: q_dkg, n });
        }
        // Computed in i64 so an over-large f+c cannot underflow.
        let avail = n as i64 - f as i64 - c as i64;
        if avail < t as i64 {
            return Err(ParamsError::LivenessSigning { avail, t });
        }
        if avail < q_dkg as i64 {
            return Err(ParamsError::LivenessQual { avail, q: q_dkg });
        }
        Ok(BeaconParams { f, c, t, q_dkg, n })
    }

    /// Byzantine fault bound `f`.
    pub fn f(&self) -> u32 {
        self.f
    }
    /// Crash slack `c`.
    pub fn c(&self) -> u32 {
        self.c
    }
    /// Reconstruction threshold `T` (partials to combine; `= deg + 1`; commitment
    /// count per deal).
    pub fn t(&self) -> u32 {
        self.t
    }
    /// Qualification size `Q_dkg`.
    pub fn q_dkg(&self) -> u32 {
        self.q_dkg
    }
    /// Committee size `n` (membership-snapshot cardinality).
    pub fn n(&self) -> u32 {
        self.n
    }

    /// The draft §1.2 proposed profile (`f=1, c=1, T=2, Q_dkg=3, n=5`).
    /// **PROPOSED — NOT RATIFIED, TEST FIXTURE ONLY.** A convenience for tests and
    /// for the gate-closed lifecycle to have concrete thresholds; it is **never**
    /// frozen protocol behavior. Real activation supplies an owner-ratified
    /// `BeaconParams` from genesis (which does not exist yet).
    pub fn proposed_default() -> Self {
        Self::validated(1, 1, 2, 3, 5).expect("proposed profile is self-consistent")
    }
}

//! Beacon threshold / fault parameters (draft §1.2, §7) — validated, not hardcoded.
//!
//! The runtime does **not** bake the `f=1/c=1/T=2/Q=3/n=5` profile in as
//! authoritative, although that profile is RATIFIED v1 (owner decision
//! 2026-09-01, #127; spec banner). Instead it accepts a [`BeaconParams`] object
//! that MUST come from authoritative chain configuration (genesis `beacon_params`;
//! the beacon gate stays `None`, fail-closed in `ChainParams::validate`), and it
//! **enforces the ratified inequalities on construction**
//! ([`BeaconParams::validated`]), rejecting any inconsistent config. The profile
//! is also available as a clearly-labelled fixture
//! ([`BeaconParams::proposed_default`]), which is never the chain's source.

/// A validated construction failure for a [`BeaconParams`] set (draft §7.4). This is
/// the **shared** `sumchain_wire::beacon_schedule::BeaconParamsViolation` — the SAME
/// enum the genesis config validates against, so the two cannot drift (one rule set).
pub use sumchain_wire::beacon_schedule::BeaconParamsViolation as ParamsError;

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
    /// Construct + **validate** a parameter set. Delegates to the single shared
    /// predicate `sumchain_wire::beacon_schedule::validate_beacon_params` (draft §7.4:
    /// `T ≥ f+1`, `Q_dkg ≥ 2f+1`, `T ≤ Q_dkg ≤ n`, `n−f−c ≥ T` (L1), `n−f−c ≥ Q_dkg`
    /// (L2)) — the SAME rule the genesis config validates against, so an invalid
    /// config can never be represented and the two surfaces cannot drift.
    pub fn validated(f: u32, c: u32, t: u32, q_dkg: u32, n: u32) -> Result<Self, ParamsError> {
        sumchain_wire::beacon_schedule::validate_beacon_params(f, c, t, q_dkg, n)?;
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

    /// The draft §1.2 profile (`f=1, c=1, T=2, Q_dkg=3, n=5`), RATIFIED v1 (owner
    /// decision 2026-09-01, #127; spec banner, §15 row 14). **A FIXTURE, not the
    /// chain's source:** tests and the gate-closed seam use it for concrete
    /// thresholds. A chain's parameters come from genesis `beacon_params`,
    /// validated by the same predicate as [`BeaconParams::validated`].
    pub fn proposed_default() -> Self {
        Self::validated(1, 1, 2, 3, 5).expect("proposed profile is self-consistent")
    }
}

//! Beacon threshold / fault parameters (draft §1.2, §7).
//!
//! **PROPOSED — NOT RATIFIED.** The values here (`f = 1`, `c = 1`, `T = f+1 = 2`,
//! `Q_dkg = 2f+1 = 3`, `n ≥ 5`) are the draft §1.2 parameter set, which the draft
//! marks `PROPOSED — OWNER DECISION` (§7.4 rows #14/#37), **not** standard-fixed and
//! **not** adopted. They are expressed here as an explicit, overridable
//! [`BeaconParams`] so the gate-closed runtime has a concrete lifecycle to validate;
//! a real activation would supply an owner-ratified `BeaconParams` (which does not
//! yet exist — the beacon executor seam is fail-closed on exactly this, see the crate
//! docs). Nothing here defines an activation height.

/// The threshold / fault parameters governing one beacon epoch (draft §1.2, §7).
///
/// Two thresholds are kept **orthogonal** (draft §7): `t` (reconstruction — how many
/// partials interpolate the group signature; polynomial degree `= t − 1`) and
/// `q_dkg` (qualification — how many dealers must qualify for the group key to
/// exist). `t ≤ q_dkg ≤ n` (consistency, draft §7.4 (C1)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconParams {
    /// Byzantine faults tolerated `f` (draft §1.2).
    pub f: u32,
    /// Additional crash slack `c` (draft §1.2).
    pub c: u32,
    /// Reconstruction threshold `T = f + 1` — partials needed to combine; the dealer
    /// polynomial degree is `T − 1` and each deal carries `T` Feldman commitments.
    pub t: u32,
    /// QUAL / qualification size `Q_dkg = 2f + 1` — the minimum number of
    /// non-disqualified dealers for the DKG to succeed (else safe-halt, draft §4.2).
    pub q_dkg: u32,
    /// Product committee floor `n ≥ 3f + 1 + c = 5` — the topology guard (draft §1.2,
    /// §7.4 (L2), enforced elsewhere by the `n ≥ 5` guard). Recorded for the
    /// consistency checks; the runtime never invents a committee.
    pub n_min: u32,
}

impl BeaconParams {
    /// The draft §1.2 parameter set (`f=1, c=1, T=2, Q_dkg=3, n≥5`). **PROPOSED, not
    /// ratified** — see the module docs. Provided so tests and the gate-closed
    /// lifecycle have concrete thresholds; NOT an adopted constant.
    pub const PROPOSED_DEFAULT: BeaconParams = BeaconParams {
        f: 1,
        c: 1,
        t: 2,
        q_dkg: 3,
        n_min: 5,
    };

    /// Check the draft §7.4 inequalities hold for this parameter set:
    /// `T = f+1`, `Q_dkg = 2f+1`, and consistency `T ≤ Q_dkg ≤ n_min`.
    pub fn is_self_consistent(&self) -> bool {
        self.t == self.f + 1
            && self.q_dkg == 2 * self.f + 1
            && self.t <= self.q_dkg
            && self.q_dkg <= self.n_min
    }
}

impl Default for BeaconParams {
    fn default() -> Self {
        Self::PROPOSED_DEFAULT
    }
}

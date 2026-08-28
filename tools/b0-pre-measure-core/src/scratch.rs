//! Confine the prover's Docker scratch/output under the per-proof root.
//!
//! The proving firewall ([`docker_firewall.sh`]) permits a Docker *output* mount ONLY under the
//! fresh per-proof root it is handed as `B0PRE_PROOF_DIR`. The SP1 gnark Groth16 backend and the
//! RISC0 stark2snark backend both create their scratch/output through the process temp dir
//! (`std::env::temp_dir()`, i.e. `TMPDIR`) / a work dir (`RISC0_WORK_DIR`). Unless those point at
//! the per-proof root, the firewall (correctly) refuses the mount — e.g.
//! `FIREWALL-REFUSED: SP1 output mount not under per-proof root: /tmp/.tmpXXXX` — and proving fails
//! closed.
//!
//! `prove_fixture.sh` already routes the fixture path (`TMPDIR=$PROOF_DIR` for SP1;
//! `RISC0_WORK_DIR=$PROOF_DIR/r0-work` for RISC0). This module gives the MEASUREMENT runners the
//! same guarantee FROM RUST, independent of the caller's environment, so a future caller that
//! forgets the shell env cannot silently route scratch to `/tmp`. `measure_fragment.sh` sets the
//! same env as a belt; the two agree and are idempotent (an already-confined value is kept).
//!
//! [`confine_scratch_to_proof_root`] MUST be called at the very top of each runner `main()` —
//! BEFORE any Tokio runtime or worker thread exists — so the `set_var` calls are single-threaded
//! and sound. The gnark backend runs in-process (`tokio-rt-worker`), so a process-level `TMPDIR`
//! set here governs its `std::env::temp_dir()` just as the shell env would.

use crate::Candidate;
use std::path::Path;

/// One environment decision the confinement makes (or declines to make). Pure data so the routing
/// logic is unit-testable without mutating the process environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvDecision {
    /// The environment variable this decision concerns (`TMPDIR` or `RISC0_WORK_DIR`).
    pub var: &'static str,
    /// `Some(path)` => set `var` to this path (under the per-proof root); `None` => leave `var`
    /// unchanged because it already resolves under the per-proof root.
    pub set_to: Option<String>,
    /// Human-readable rationale (for the run log).
    pub reason: &'static str,
}

/// `true` iff `path` is the per-proof `root` or lies underneath it. Component-wise (so `/a/bc` is
/// NOT under `/a/b`). Both arguments are expected to be canonical absolute paths.
fn path_is_under(path: &str, root: &str) -> bool {
    Path::new(path).starts_with(Path::new(root))
}

/// PURE routing plan: given the per-proof `root` (canonical, or `None`/empty when no firewall root
/// is in the environment) and the current canonical values of `TMPDIR` / `RISC0_WORK_DIR`, decide
/// what must be set so the candidate's Docker scratch lands under the per-proof root.
///
/// * No per-proof root (off-venue / non-firewalled) → empty plan: leave the process env untouched.
/// * `TMPDIR` governs `std::env::temp_dir()`, which the in-process SP1 gnark FFI and measure-core
///   both use → always routed under the root (kept if already there).
/// * RISC0 additionally routes `RISC0_WORK_DIR` to `<root>/r0-work` (the stark2snark `/mnt` work
///   dir the firewall checks) — kept if already under the root.
pub fn plan_scratch_confinement(
    candidate: Candidate,
    proof_dir: Option<&str>,
    tmpdir: Option<&str>,
    risc0_work_dir: Option<&str>,
) -> Vec<EnvDecision> {
    let root = match proof_dir {
        Some(p) if !p.is_empty() => p,
        _ => return Vec::new(),
    };
    let under = |v: Option<&str>| matches!(v, Some(s) if !s.is_empty() && path_is_under(s, root));

    let mut plan = Vec::new();
    if under(tmpdir) {
        plan.push(EnvDecision {
            var: "TMPDIR",
            set_to: None,
            reason: "TMPDIR already resolves under the per-proof root",
        });
    } else {
        plan.push(EnvDecision {
            var: "TMPDIR",
            set_to: Some(root.to_string()),
            reason: "route the process temp dir (gnark scratch + measure-core) under the per-proof root",
        });
    }
    if candidate == Candidate::Risc0 {
        if under(risc0_work_dir) {
            plan.push(EnvDecision {
                var: "RISC0_WORK_DIR",
                set_to: None,
                reason: "RISC0_WORK_DIR already resolves under the per-proof root",
            });
        } else {
            plan.push(EnvDecision {
                var: "RISC0_WORK_DIR",
                set_to: Some(format!("{root}/r0-work")),
                reason: "route the RISC0 stark2snark work dir under the per-proof root",
            });
        }
    }
    plan
}

/// Best-effort canonical form of an existing env path (falls back to the raw value if the path does
/// not yet resolve — e.g. a not-yet-created `RISC0_WORK_DIR`, which then reads as "not under root").
fn canon_env(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|s| !s.is_empty()).map(|v| {
        std::fs::canonicalize(&v)
            .ok()
            .and_then(|c| c.to_str().map(str::to_string))
            .unwrap_or(v)
    })
}

/// Apply [`plan_scratch_confinement`] to the REAL process environment for `candidate`, reading
/// `B0PRE_PROOF_DIR` / `TMPDIR` / `RISC0_WORK_DIR`. No-op (returns an empty plan) when
/// `B0PRE_PROOF_DIR` is unset/empty, so off-venue and unit-test runs are unaffected. Fails closed if
/// `B0PRE_PROOF_DIR` is set but does not resolve, or a routed dir cannot be created.
///
/// MUST run before any thread/runtime is spawned (top of `main()`): it uses `std::env::set_var`.
pub fn confine_scratch_to_proof_root(candidate: Candidate) -> Result<Vec<EnvDecision>, String> {
    let proof_dir = match std::env::var("B0PRE_PROOF_DIR")
        .ok()
        .filter(|s| !s.is_empty())
    {
        None => return Ok(Vec::new()),
        Some(p) => std::fs::canonicalize(&p)
            .map_err(|e| format!("B0PRE_PROOF_DIR {p:?} does not resolve: {e}"))?
            .to_str()
            .ok_or("B0PRE_PROOF_DIR is not valid UTF-8")?
            .to_string(),
    };
    let tmpdir = canon_env("TMPDIR");
    let r0_work = canon_env("RISC0_WORK_DIR");
    let plan = plan_scratch_confinement(
        candidate,
        Some(&proof_dir),
        tmpdir.as_deref(),
        r0_work.as_deref(),
    );
    for d in &plan {
        if let Some(val) = &d.set_to {
            if d.var == "RISC0_WORK_DIR" {
                std::fs::create_dir_all(val)
                    .map_err(|e| format!("cannot create RISC0 work dir {val:?}: {e}"))?;
            }
            std::env::set_var(d.var, val);
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(var: &'static str, v: &str) -> EnvDecision {
        EnvDecision {
            var,
            set_to: Some(v.to_string()),
            reason: "",
        }
    }
    fn keep(var: &'static str) -> EnvDecision {
        EnvDecision {
            var,
            set_to: None,
            reason: "",
        }
    }
    // Compare ignoring the `reason` string (rationale is for the log, not the contract).
    fn same(plan: &[EnvDecision], want: &[EnvDecision]) -> bool {
        plan.len() == want.len()
            && plan
                .iter()
                .zip(want)
                .all(|(a, b)| a.var == b.var && a.set_to == b.set_to)
    }

    #[test]
    fn no_proof_root_is_a_noop_for_both_candidates() {
        // Off-venue / non-firewalled: never touch the environment.
        assert!(plan_scratch_confinement(Candidate::Sp1, None, Some("/tmp"), None).is_empty());
        assert!(plan_scratch_confinement(Candidate::Sp1, Some(""), Some("/tmp"), None).is_empty());
        assert!(plan_scratch_confinement(Candidate::Risc0, None, None, Some("/tmp/x")).is_empty());
    }

    #[test]
    fn sp1_routes_tmpdir_under_root_when_outside() {
        // The failure that bit the burn-in: TMPDIR at /tmp -> gnark output mount refused.
        let plan = plan_scratch_confinement(Candidate::Sp1, Some("/b0/proof"), Some("/tmp"), None);
        assert!(same(&plan, &[set("TMPDIR", "/b0/proof")]));
        // Unset TMPDIR is likewise routed.
        let plan = plan_scratch_confinement(Candidate::Sp1, Some("/b0/proof"), None, None);
        assert!(same(&plan, &[set("TMPDIR", "/b0/proof")]));
    }

    #[test]
    fn sp1_keeps_tmpdir_when_already_confined() {
        // The shell belt (measure_fragment.sh) may have already set TMPDIR=$PROOF_DIR.
        let plan =
            plan_scratch_confinement(Candidate::Sp1, Some("/b0/proof"), Some("/b0/proof"), None);
        assert!(same(&plan, &[keep("TMPDIR")]));
        let plan = plan_scratch_confinement(
            Candidate::Sp1,
            Some("/b0/proof"),
            Some("/b0/proof/sub"),
            None,
        );
        assert!(same(&plan, &[keep("TMPDIR")]));
    }

    #[test]
    fn risc0_routes_both_tmpdir_and_work_dir() {
        let plan =
            plan_scratch_confinement(Candidate::Risc0, Some("/b0/proof"), Some("/tmp"), None);
        assert!(same(
            &plan,
            &[
                set("TMPDIR", "/b0/proof"),
                set("RISC0_WORK_DIR", "/b0/proof/r0-work")
            ]
        ));
        // An already-confined RISC0_WORK_DIR is kept.
        let plan = plan_scratch_confinement(
            Candidate::Risc0,
            Some("/b0/proof"),
            Some("/b0/proof"),
            Some("/b0/proof/r0-work"),
        );
        assert!(same(&plan, &[keep("TMPDIR"), keep("RISC0_WORK_DIR")]));
    }

    #[test]
    fn sp1_never_touches_risc0_work_dir() {
        let plan = plan_scratch_confinement(
            Candidate::Sp1,
            Some("/b0/proof"),
            Some("/tmp"),
            Some("/tmp/leak"),
        );
        assert!(plan.iter().all(|d| d.var != "RISC0_WORK_DIR"));
    }

    #[test]
    fn under_is_component_wise() {
        assert!(path_is_under("/a/b/c", "/a/b"));
        assert!(path_is_under("/a/b", "/a/b"));
        assert!(!path_is_under("/a/bc", "/a/b")); // sibling prefix, NOT under
        assert!(!path_is_under("/tmp/.tmpXXXX", "/b0/proof"));
    }
}

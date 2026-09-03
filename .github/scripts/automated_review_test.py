#!/usr/bin/env python3
"""Unit tests for the pure decision core of the automated-review gate (#219).

Run: python3 .github/scripts/automated_review_test.py

Covers the scenarios the gate must get right: a fresh successful independent
review, new commits, rebases, stale results, changed heads, failed/pending/
missing checks, not-up-to-date branches, fork PRs, and workflow (gate-file)
tampering with and without a qualifying admin override.
"""

import unittest

from automated_review import Check, State, evaluate

HEAD = "a" * 40
OLD = "b" * 40
DESIGNATED = ("build-test-clippy", "build-test-clippy-aarch64", "supply-chain-audit")
GATE = (
    ".github/workflows/automated-review.yml",
    ".github/scripts/automated_review.py",
    ".github/automated-review.config.json",
)


def green_checks(head=HEAD):
    return tuple(Check(n, head, "completed", "success") for n in DESIGNATED)


def state(**over):
    base = dict(
        run_head_sha=HEAD,
        pr_head_sha=HEAD,
        base_up_to_date=True,
        checks=green_checks(),
        designated_checks=DESIGNATED,
        gate_paths=GATE,
        changed_files=("crates/foo/src/lib.rs",),
        admin_approved_current_head=False,
        is_fork=False,
    )
    base.update(over)
    return State(**base)


class TestAutomatedReview(unittest.TestCase):

    # --- the happy path: a fully-green ordinary PR needs no human ---------- #
    def test_successful_independent_review_passes(self):
        v = evaluate(state())
        self.assertTrue(v.ok, v.reasons)
        self.assertEqual(v.reasons, [])

    # --- current head only: new commits / rebases / changed heads ---------- #
    def test_new_commit_makes_prior_run_stale(self):
        # A run triggered for OLD, but the PR head advanced to HEAD.
        v = evaluate(state(run_head_sha=OLD, pr_head_sha=HEAD))
        self.assertFalse(v.ok)
        self.assertTrue(any("stale run" in r for r in v.reasons))

    def test_rebase_changes_head_and_invalidates_run(self):
        # A rebase is just a changed head; the run for the pre-rebase head fails.
        v = evaluate(state(run_head_sha=OLD, pr_head_sha=HEAD, checks=green_checks(HEAD)))
        self.assertFalse(v.ok)
        self.assertTrue(any("stale run" in r for r in v.reasons))

    def test_fresh_run_on_new_head_with_green_passes(self):
        # After the new commit, the fresh run (run==pr==HEAD) with green checks passes.
        v = evaluate(state(run_head_sha=HEAD, pr_head_sha=HEAD))
        self.assertTrue(v.ok, v.reasons)

    # --- stale results: success recorded against an older head must NOT count #
    def test_stale_success_on_old_head_does_not_satisfy(self):
        stale = tuple(Check(n, OLD, "completed", "success") for n in DESIGNATED)
        v = evaluate(state(checks=stale))  # checks are for OLD, pr head is HEAD
        self.assertFalse(v.ok)
        self.assertTrue(all(
            any(f"'{n}' is missing on the current head" in r for r in v.reasons)
            for n in DESIGNATED))

    # --- failed / pending / missing checks --------------------------------- #
    def test_failed_check_fails(self):
        bad = (Check("build-test-clippy", HEAD, "completed", "failure"),
               *green_checks()[1:])
        v = evaluate(state(checks=bad))
        self.assertFalse(v.ok)
        self.assertTrue(any("did not succeed (conclusion=failure)" in r for r in v.reasons))

    def test_pending_check_fails(self):
        pend = (Check("supply-chain-audit", HEAD, "in_progress", None),
                *green_checks()[:2])
        v = evaluate(state(checks=pend))
        self.assertFalse(v.ok)
        self.assertTrue(any("has not completed (status=in_progress)" in r for r in v.reasons))

    def test_missing_check_fails(self):
        v = evaluate(state(checks=green_checks()[:2]))  # supply-chain-audit absent
        self.assertFalse(v.ok)
        self.assertTrue(any("'supply-chain-audit' is missing" in r for r in v.reasons))

    def test_cancelled_check_fails(self):
        canc = (Check("build-test-clippy-aarch64", HEAD, "completed", "cancelled"),
                green_checks()[0], green_checks()[2])
        v = evaluate(state(checks=canc))
        self.assertFalse(v.ok)
        self.assertTrue(any("conclusion=cancelled" in r for r in v.reasons))

    # --- strict up-to-date -------------------------------------------------- #
    def test_not_up_to_date_fails(self):
        v = evaluate(state(base_up_to_date=False))
        self.assertFalse(v.ok)
        self.assertTrue(any("not up to date with base" in r for r in v.reasons))

    # --- self-weakening: gate-file changes need an admin approval ---------- #
    def test_gate_file_change_without_admin_approval_fails(self):
        v = evaluate(state(changed_files=(".github/workflows/automated-review.yml",)))
        self.assertFalse(v.ok)
        self.assertTrue(any("modifies governance gate file" in r for r in v.reasons))

    def test_gate_file_change_with_current_head_admin_approval_passes(self):
        v = evaluate(state(
            changed_files=(".github/scripts/automated_review.py",),
            admin_approved_current_head=True))
        self.assertTrue(v.ok, v.reasons)

    def test_gate_change_config_also_guarded(self):
        v = evaluate(state(changed_files=(".github/automated-review.config.json",)))
        self.assertFalse(v.ok)
        self.assertTrue(any("modifies governance gate file" in r for r in v.reasons))

    def test_non_gate_change_needs_no_human(self):
        v = evaluate(state(changed_files=("README.md", "crates/x/src/lib.rs")))
        self.assertTrue(v.ok, v.reasons)

    # --- fork PRs ----------------------------------------------------------- #
    def test_fork_pr_ordinary_green_passes(self):
        v = evaluate(state(is_fork=True))
        self.assertTrue(v.ok, v.reasons)

    def test_fork_pr_touching_gate_needs_admin(self):
        v = evaluate(state(
            is_fork=True,
            changed_files=(".github/workflows/automated-review.yml",)))
        self.assertFalse(v.ok)
        self.assertTrue(any("modifies governance gate file" in r for r in v.reasons))

    # --- multiple simultaneous failures are all reported ------------------- #
    def test_multiple_failures_all_reported(self):
        v = evaluate(state(
            run_head_sha=OLD,
            base_up_to_date=False,
            checks=(Check("build-test-clippy", HEAD, "completed", "failure"),),
            changed_files=(".github/workflows/automated-review.yml",)))
        self.assertFalse(v.ok)
        self.assertTrue(any("stale run" in r for r in v.reasons))
        self.assertTrue(any("not up to date" in r for r in v.reasons))
        self.assertTrue(any("did not succeed" in r for r in v.reasons))
        self.assertTrue(any("gate file" in r for r in v.reasons))


if __name__ == "__main__":
    unittest.main(verbosity=2)

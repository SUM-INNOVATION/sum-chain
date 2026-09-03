# Independent automated-review gate (#219)

Replaces the review-event-only `approval-policy` mechanism with a **mandatory
independent automated review** that always produces a verdict for the PR's
**current head**.

## The defect this fixes

`main` protection combines **strict "require branches up to date"**, a required
`approval-policy` check that ran **only on `pull_request_review`**, and
`enforce_admins: true`. Batch-merging approved PRs deadlocked:

1. The first approved PR merges → every other open PR becomes **BEHIND**.
2. Strict up-to-date forces an **update-branch**, creating a **new head SHA**.
3. No review event fires on that new head, so `approval-policy` never runs there
   → the required check reads **"Expected — waiting for status"** → merge refused.
4. A `workflow_dispatch` "recovery" run goes green but GitHub does **not** count a
   dispatched run toward a PR's required checks (verified: the REST merge still
   returns `Required status check 'approval-policy' is expected`).
5. `enforce_admins: true` → no admin bypass.

Net: every PR after the first needed a **fresh human exact-head approval** after
each update — the recurring toil this issue exists to remove. Worse, GitHub
re-associates an approval to a new head, so an "approved" head could be one no
human ever looked at.

## The replacement

`.github/workflows/automated-review.yml` runs on `pull_request`
(`opened`, `synchronize`, `reopened`, `ready_for_review`) and makes **its own job
success** the required check. The policy is a pure, unit-tested function in
`.github/scripts/automated_review.py`; the workflow is a thin gatherer.

It passes only when **all** hold (fail-closed; every failing clause is reported):

| # | Clause | Guards |
|---|---|---|
| 1 | The run's head SHA **equals the PR's current head** (re-read live) | new commits, rebases, changed heads, stale runs |
| 2 | The branch is **up to date** with base (`behind_by == 0`) | preserves strict up-to-date |
| 3 | Every **designated check** is `completed` + `success` **for the current head** (a success recorded against an older head does **not** count) | failed / pending / missing / stale results |
| 4 | If the diff touches a **gate file**, a qualifying **admin/maintainer approval on the current head** is required | workflow/config self-modification |

Ordinary PRs need **no human approval** — the automated review is the reviewer.
Human sign-off remains mandatory for exactly one class: **changing the gate
itself**.

Designated checks and gate paths live in `.github/automated-review.config.json`
(itself a gate path, so widening it needs an admin approval).

### Never "Expected" because the branch moved

`synchronize` fires on every push/update-branch, so a new head always gets a
fresh run and a fresh verdict. Concurrency is `cancel-in-progress: true`: a
superseded run is cancelled and the new head's run is authoritative.

### Why reviews are also a trigger (clause 4 would otherwise deadlock)

The workflow additionally runs on `pull_request_review`
(`submitted`, `dismissed`). This is **additive**, not a return to the old
review-event-only design: the PR-lifecycle triggers above already produce a
verdict for every head on their own, so the check is never *only* driven by
reviews.

It is required to make clause 4 usable. A gate-changing PR needs an admin
approval **on the current head**, but an approval is not a PR lifecycle event, so
without this trigger the check would keep its pre-approval (failing) verdict.
Pushing a commit to force a re-run does not help either: `dismiss_stale_reviews`
drops the approval on the new head, so *approve → push → dismissed → approve*
loops indefinitely, leaving a manual "Re-run jobs" as the only escape. With the
review trigger, approving simply re-evaluates the current head and the gate
clears.

### Policy integrity, and the residual risk (stated precisely)

**Guaranteed:** the gate job checks out **`base.sha`**, so the decision script and
config it executes are always the **base's** versions. A PR **cannot change the
policy logic that judges it**; its edits to those files are *detected* through the
API diff (clause 4) and never executed. Fork PRs are evaluated identically
(read-only token, no secrets), and a fork PR touching a gate file still needs the
admin approval.

**Why `pull_request` and not `pull_request_target`:** a required status check must
land on the PR's **head SHA**. `pull_request` runs attach there.
`pull_request_target` would run the **base's** workflow file — attractive for
tamper-resistance — but its run attaches to the **base** SHA, so it cannot satisfy
a head-SHA required check; and GitHub no longer permits a workflow to publish its
own check-run/status onto the head (the constraint the previous mechanism also
hit). So `pull_request` is the only trigger that actually gates.

**Residual risk (not overclaimed):** with `pull_request`, the *workflow file
itself* comes from the merge ref. A PR that **rewrites
`.github/workflows/automated-review.yml`** (e.g. to skip the script) would run its
rewritten version, and clause 4 cannot catch that because the gutted job never
calls the script.

- **Deleting or renaming the job is safe**: the required `automated-review`
  context is then never produced, so the PR stays blocked.
- **A trivially-passing rewrite is not self-detectable.** Mitigate at the
  **platform** layer, which is where this class of risk belongs:
  - add a ruleset **"Restrict file paths"** rule covering `.github/workflows/**`
    (and `.github/scripts/**`), **or**
  - require admin review for `.github/**` changes.

  Note this repo deliberately leaves native **"Require review from Code Owners"
  OFF** (a single-owner `CODEOWNERS` would deadlock the owner's own PRs), so the
  path-restriction rule is the recommended form.

There is intentionally **no `workflow_dispatch`** path: a dispatched run cannot
satisfy a PR's required check, so offering one only misleads.

## One-time GitHub ruleset change (manual, admin)

Do this **after** the PR adding `automated-review.yml` merges, so the new check
exists and has produced at least one run.

In **Settings → Rules → Rulesets → the `main` ruleset** (or Branch protection):

1. **Require status checks to pass** → **add** `automated-review` to the required
   checks. (Optionally also add `automated-review-tests`.)
2. **Remove** `approval-policy` from the required checks.
3. **Require a pull request before merging** → set **Required approvals to `0`**.
   The automated check now carries the gate; gate-file changes still demand an
   admin approval, enforced by clause 4 rather than by a blanket count.
4. **Leave unchanged** (do **not** weaken):
   - ✅ **Require branches to be up to date before merging** (strict) — clause 2
     depends on it and re-asserts it.
   - ✅ **Do not allow bypassing the above settings** / `enforce_admins: true`.
   - ✅ **Block force pushes**; no direct pushes to `main`.
   - ✅ Existing required CI checks (`build-test-clippy`,
     `build-test-clippy-aarch64`, `supply-chain-audit`) stay required — clause 3
     additionally binds them to the current head.
5. **Recommended (closes the residual risk above):** add a **"Restrict file
   paths"** rule to the same ruleset covering `.github/workflows/**` and
   `.github/scripts/**`, so a PR cannot rewrite the gate workflow to trivially
   pass. Without it, clause 4 covers *script/config* tampering but not a rewrite
   of the workflow file itself.
6. **Then** delete `.github/workflows/approval-policy.yml` in a trivial follow-up
   PR (it is retained until this step so the still-required `approval-policy`
   check cannot become permanently unproduced).

Equivalent REST (illustrative — the UI is preferred):

```bash
# Inspect first; do NOT blind-apply.
gh api repos/SUM-INNOVATION/sum-chain/rulesets --jq '.[] | {id, name}'
gh api repos/SUM-INNOVATION/sum-chain/rulesets/<ID>
# Then edit the required_status_checks contexts: + automated-review, - approval-policy
# and set the pull_request rule's required_approving_review_count to 0.
```

## Verifying after the switch

- Push a trivial commit to an open PR → a **new** `automated-review` run appears
  for the new head within seconds (never a lingering "Expected").
- Merge another PR to move `main`, then update the branch → the check re-runs and
  passes without any human click.
- Open a PR that edits `.github/automated-review.config.json` → the gate **fails**
  until an admin approves that exact head.

## Tests

`.github/scripts/automated_review_test.py` (run in CI by the
`automated-review-tests` job, and locally with
`python3 .github/scripts/automated_review_test.py`) covers: successful
independent review, new commits, rebases, changed heads, stale successes against
an older head, failed / pending / missing / cancelled checks, not-up-to-date
branches, fork PRs (ordinary and gate-touching), gate-file tampering with and
without a current-head admin approval, and multi-failure reporting.

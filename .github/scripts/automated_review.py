#!/usr/bin/env python3
"""Independent automated-review gate (#219).

Replaces the review-event-only ``approval-policy`` mechanism. This job's own
success/failure is the required check that a branch-protection ruleset requires
in place of a human-approval *count*. It is **fail-closed**: any doubt is a fail.

Two halves, deliberately separated so the decision is unit-testable:

* :func:`evaluate` — a **pure function** of a fully-gathered ``State``. All the
  policy lives here; the tests drive it directly with fixtures.
* :func:`gather` / :func:`main` — the thin, impure wrapper that reads PR state
  from the GitHub API (via ``gh``) and the local checkout, then calls
  :func:`evaluate`.

Policy (every clause fail-closed):

1. **Current head only.** The head the run was triggered for must equal the PR's
   current head SHA. A run for a superseded head never passes (guards
   stale-result / changed-head races). The workflow triggers on
   ``opened``/``synchronize``/``reopened`` so a new head always gets a fresh run —
   the check is never merely "Expected" because the branch moved.
2. **Strict up-to-date.** The PR must be up to date with its base (``behind_by ==
   0``). This mirrors and re-asserts the branch-protection "require branches up to
   date" rule; the gate never substitutes for it.
3. **All designated checks pass on the current head.** Every check in
   ``designated_checks`` must exist *for the current head SHA*, be ``completed``,
   and have conclusion ``success``. A missing, pending, stale-head, or non-success
   check fails the gate. (A stale ``success`` recorded against an older head does
   NOT count — this is the core of "validate the current head, not an older one".)
4. **No self-weakening.** If the PR's diff touches any governance ``gate_paths``
   file, the gate requires a qualifying admin/maintainer **approval on the current
   head** (a non-author review whose ``commit_id`` is the current head). This is
   the one place human review is still mandatory: changing the gate itself.
   Ordinary PRs need no human approval.

Fork PRs are handled by GitHub, not here: ``pull_request`` runs THIS workflow
from the base branch (a PR cannot alter the evaluator that judges it) with a
read-only token; gathering is read-only. A fork PR that edits a gate file still
takes clause 4.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
# Pure decision core
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Check:
    name: str
    head_sha: str
    status: str  # "queued" | "in_progress" | "completed"
    conclusion: str | None  # "success" | "failure" | "cancelled" | ... | None


@dataclass(frozen=True)
class State:
    # The head SHA this evaluation run was triggered for (from the event).
    run_head_sha: str
    # The PR's current head SHA (re-read live at evaluation time).
    pr_head_sha: str
    # behind_by == 0 (base fully merged into the PR branch).
    base_up_to_date: bool
    # Check-runs + legacy statuses observed for pr_head_sha.
    checks: tuple[Check, ...]
    # Names that must all be success on the current head.
    designated_checks: tuple[str, ...]
    # Governance files whose change requires an admin override.
    gate_paths: tuple[str, ...]
    # Files the PR changes.
    changed_files: tuple[str, ...]
    # A qualifying non-author admin/maintainer approval whose commit_id == pr_head_sha.
    admin_approved_current_head: bool
    is_fork: bool = False


@dataclass
class Verdict:
    ok: bool
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"ok": self.ok, "reasons": self.reasons}


def evaluate(state: State) -> Verdict:
    """Pure fail-closed policy. Returns every failing reason (not just the first)
    so the check output is actionable."""
    reasons: list[str] = []

    # 1. Current head only — a run for a superseded head can never pass.
    if state.run_head_sha != state.pr_head_sha:
        reasons.append(
            f"stale run: evaluated head {state.run_head_sha[:12]} is not the PR's "
            f"current head {state.pr_head_sha[:12]} (a new commit/rebase supersedes "
            f"this run; the fresh run on the current head is authoritative)"
        )

    # 2. Strict up-to-date.
    if not state.base_up_to_date:
        reasons.append(
            "branch is not up to date with base (behind_by != 0); update the branch "
            "so all checks re-run on the merged result"
        )

    # 3. All designated checks pass ON the current head.
    by_name: dict[str, Check] = {}
    for c in state.checks:
        # Last writer wins only among checks for the CURRENT head; stale-head
        # entries are ignored so they can never satisfy a requirement.
        if c.head_sha == state.pr_head_sha:
            by_name[c.name] = c
    for name in state.designated_checks:
        c = by_name.get(name)
        if c is None:
            reasons.append(f"required check '{name}' is missing on the current head")
        elif c.status != "completed":
            reasons.append(f"required check '{name}' has not completed (status={c.status})")
        elif c.conclusion != "success":
            reasons.append(f"required check '{name}' did not succeed (conclusion={c.conclusion})")

    # 4. No self-weakening: gate-file changes need a current-head admin approval.
    touched = sorted(set(state.changed_files) & set(state.gate_paths))
    if touched:
        if not state.admin_approved_current_head:
            reasons.append(
                "this PR modifies governance gate file(s) "
                f"{touched}; a gate change requires a qualifying admin/maintainer "
                "approval on the current head SHA (self-weakening refusal)"
            )

    return Verdict(ok=(len(reasons) == 0), reasons=reasons)


# --------------------------------------------------------------------------- #
# Impure gathering wrapper (thin; not unit-tested — evaluate() carries the logic)
# --------------------------------------------------------------------------- #

def _gh_json(path: str, args: list[str] | None = None) -> object:
    cmd = ["gh", "api", path] + (args or [])
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None


def _load_config(repo_root: str) -> dict:
    with open(os.path.join(repo_root, ".github", "automated-review.config.json")) as f:
        return json.load(f)


def _gather_checks(owner: str, repo: str, head_sha: str) -> list[Check]:
    checks: list[Check] = []
    # Actions check-runs (paginated; one page-object per line).
    raw = subprocess.run(
        ["gh", "api", "--paginate",
         f"repos/{owner}/{repo}/commits/{head_sha}/check-runs"],
        check=True, capture_output=True, text=True).stdout
    for page in raw.strip().splitlines():
        if not page.strip():
            continue
        obj = json.loads(page)
        for run in obj.get("check_runs", []):
            checks.append(Check(run["name"], head_sha, run["status"], run.get("conclusion")))
    # Legacy commit statuses (context-based) — treat as completed checks.
    status = _gh_json(f"repos/{owner}/{repo}/commits/{head_sha}/status")
    for s in (status or {}).get("statuses", []):
        concl = "success" if s["state"] == "success" else (
            "failure" if s["state"] in ("failure", "error") else None)
        checks.append(Check(s["context"], head_sha, "completed" if concl else "in_progress", concl))
    return checks


def gather(owner: str, repo: str, pr: int, run_head_sha: str, poll_timeout_s: int) -> State:
    cfg = _load_config(os.getcwd())
    designated = tuple(cfg["designated_checks"])
    gate_paths = tuple(cfg["gate_paths"])

    meta = _gh_json(f"repos/{owner}/{repo}/pulls/{pr}")
    pr_head_sha = meta["head"]["sha"]
    author = meta["user"]["login"]
    is_fork = meta["head"]["repo"]["full_name"] != f"{owner}/{repo}"

    # Up-to-date: base fully merged into head (behind_by == 0).
    cmp = _gh_json(f"repos/{owner}/{repo}/compare/{meta['base']['sha']}...{pr_head_sha}")
    base_up_to_date = (cmp or {}).get("behind_by", 1) == 0

    changed = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{owner}/{repo}/pulls/{pr}/files",
         "-q", ".[].filename"], check=True, capture_output=True, text=True).stdout
    changed_files = tuple(f for f in changed.splitlines() if f.strip())

    # Poll until every designated check for the current head is completed (or
    # timeout — a timeout leaves them non-completed and fails the gate).
    deadline = time.time() + poll_timeout_s
    checks: list[Check] = []
    while True:
        checks = _gather_checks(owner, repo, pr_head_sha)
        by = {c.name: c for c in checks if c.head_sha == pr_head_sha}
        pending = [n for n in designated
                   if n not in by or by[n].status != "completed"]
        if not pending or time.time() >= deadline:
            break
        print(f"waiting for designated checks to complete: {pending}", flush=True)
        time.sleep(15)

    # Admin/maintainer approval bound to the CURRENT head (only relevant for a
    # gate-file change, but gather it unconditionally — cheap and explicit).
    admin_ok = _admin_approved_current_head(owner, repo, pr, author, pr_head_sha)

    return State(
        run_head_sha=run_head_sha,
        pr_head_sha=pr_head_sha,
        base_up_to_date=base_up_to_date,
        checks=tuple(checks),
        designated_checks=designated,
        gate_paths=gate_paths,
        changed_files=changed_files,
        admin_approved_current_head=admin_ok,
        is_fork=is_fork,
    )


def _admin_approved_current_head(owner: str, repo: str, pr: int, author: str,
                                 head_sha: str) -> bool:
    raw = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{owner}/{repo}/pulls/{pr}/reviews"],
        check=True, capture_output=True, text=True).stdout
    latest: dict[str, dict] = {}
    for page in raw.strip().splitlines() or ["[]"]:
        for r in json.loads(page):
            u = r["user"]["login"]
            if u == author:
                continue
            prev = latest.get(u)
            if prev is None or r["submitted_at"] > prev["submitted_at"]:
                latest[u] = r
    for u, r in latest.items():
        if r["state"] != "APPROVED" or r.get("commit_id") != head_sha:
            continue
        perm = subprocess.run(
            ["gh", "api", f"repos/{owner}/{repo}/collaborators/{u}/permission",
             "-q", ".permission"], capture_output=True, text=True).stdout.strip()
        if perm in ("admin", "maintain"):
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--run-head-sha", required=True)
    ap.add_argument("--poll-timeout-s", type=int, default=1500)
    args = ap.parse_args()

    state = gather(args.owner, args.repo, args.pr, args.run_head_sha, args.poll_timeout_s)
    verdict = evaluate(state)
    print(json.dumps(
        {"pr_head_sha": state.pr_head_sha, "run_head_sha": state.run_head_sha,
         "verdict": verdict.as_dict()}, indent=2))
    if not verdict.ok:
        for r in verdict.reasons:
            print(f"::error::automated-review: {r}")
        return 1
    print("automated-review: PASS — current head, up to date, all designated "
          "checks green, no unapproved gate change.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

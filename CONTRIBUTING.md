# Contributing to SUM Chain

Thanks for contributing. This guide covers the basics for building, testing, and
submitting changes.

## Prerequisites

- Rust (pinned via `rust-toolchain.toml`; currently `1.85.0`). `rustup` will pick
  it up automatically.
- For the TypeScript SDK / web frontends: Node.js 18+ and `npm`.

## Build & test

This is a Cargo workspace.

```bash
cargo build                         # whole workspace
cargo build -p <crate>              # a single crate (e.g. sumchain-rpc)

cargo test -p <crate>               # scoped tests (preferred — faster, focused)
cargo test                          # full suite

cargo clippy -p <crate> --all-targets
cargo fmt --all
```

Prefer **scoped** `-p <crate>` builds/tests while iterating. The TypeScript SDK
builds with `npm run build` in `sdk/typescript`.

## Documentation rules

- **Public docs present current, valid usage only.** Do not document
  non-working or incomplete surfaces as if they are current usage.
- **Token-family documentation lives in [`docs/tokens.md`](docs/tokens.md)** —
  the single source for token/token-family usage. Do not add separate per-`SRC`
  token docs.
- Start from [`docs/index.md`](docs/index.md); keep relative links resolving.
- RPC examples must use real, supported method names.

## Repository hygiene

- Do not commit generated artifacts or local data: `target/`, `node_modules/`,
  `dist/`, `out/`, `data/`, `keys/` are ignored — keep them that way.

## Branches & pull requests

- Branch off `main`; do not commit directly to `main`.
- Keep commits focused with clear messages.
- Open a pull request for review; ensure the workspace builds and relevant tests
  pass before requesting review.

## Review policy

`main` is protected, and the gate is an **independent automated review** rather
than a human-approval count (#219). See
[docs/governance/AUTOMATED-REVIEW.md](docs/governance/AUTOMATED-REVIEW.md).

The required [`automated-review`](.github/workflows/automated-review.yml) check
runs on PR `opened` / `synchronize` / `reopened` / `ready_for_review`, so a fresh
verdict is always produced for the **current head**. It passes only when all of:

1. the run's head SHA **is** the PR's current head (never an older reviewed head);
2. the branch is **up to date** with `main` (strict, unchanged);
3. every designated CI/security check is `completed` + `success` **on that head**
   (a success recorded against an older head does not count); and
4. if the PR touches a **governance gate file**, a qualifying admin/maintainer
   **approval on the current head** exists.

So an ordinary PR needs **no human approval** — it merges once its checks are
green on the current head. Human sign-off stays mandatory for exactly one class:
**changing the gate itself** (clause 4). The policy is a pure function in
`.github/scripts/automated_review.py` with unit tests
(`automated_review_test.py`, run by the `automated-review-tests` job).

This replaced the previous conditional "1 approval if the author is an
admin/maintainer, otherwise 2" rule enforced by the now-deleted
`approval-policy` workflow, which ran **only on review events**. Because strict up-to-date forces a branch update after every
other merge, and no review event fires on the new head, that check was never
produced there and the PR stalled at "Expected — waiting for status" until a
human re-approved — the recurring toil #219 removes. `approval-policy` has since been deleted; the switch is complete.

`.github/CODEOWNERS` is **path-scoped to the governance files** (the gate workflow,
its scripts, and CODEOWNERS itself), with **two** owners. That lets native
**"Require review from Code Owners" be enabled** while ordinary PRs still need no
human approval: code-owner review is demanded only for PRs touching owned paths.

This replaces the previous whole-tree entry (`* @sunhaoxiangwang`), under which
code-owner review had to stay OFF — a single owner cannot approve their own PR,
so it deadlocked the owner's changes. Scoping the file and naming two owners
removes both problems. It is the compensating control for setting the approval
count to zero, standing in for the ruleset "Restrict file paths" rule, which
GitHub rejects on this organization's plan
(see [docs/governance/AUTOMATED-REVIEW.md](docs/governance/AUTOMATED-REVIEW.md)).

## Branch protection setup (maintainers)

Current `main` protection (the #219 end state). Applied via the GitHub API/UI:

```bash
gh api -X PUT repos/SUM-INNOVATION/sum-chain/branches/main/protection \
  -H "Accept: application/vnd.github+json" --input - <<'JSON'
{
  "required_status_checks": { "strict": true,
    "contexts": ["automated-review", "build-test-clippy"] },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 0
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Equivalent UI settings under **Settings → Branches** for `main`:

1. **Require a pull request before merging** → **Require approvals: 0** →
   **Dismiss stale pull request approvals when new commits are pushed** →
   **Require review from Code Owners** ✅ (this is the compensating control; with
   the path-scoped `CODEOWNERS` it applies only to governance paths).
2. **Require status checks to pass before merging** → **Require branches to be up
   to date** → require **`automated-review`** and **`build-test-clippy`**.
3. **Do not allow bypassing the above settings** (**enforce admins**).
4. **Block force pushes** and **restrict deletions** for `main`.

`automated-review` transitively enforces the remaining CI/security checks: its
clause 3 requires every check in `.github/automated-review.config.json`
(`build-test-clippy`, `build-test-clippy-aarch64`, `supply-chain-audit`) to be
`completed` + `success` **on the PR's current head**.

⚠️ **Do not set approvals to 0 without "Require review from Code Owners" enabled.**
Together they are the policy; alone, zero approvals would leave a PR free to
rewrite the gate workflow itself with no human in the loop.

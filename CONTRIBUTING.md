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

`main` is protected. Approval count depends on who authored the PR, and
approvals only count from **admins or maintainers** (repo permission `admin` or
`maintain`):

- **PRs authored by `sunhaoxiangwang`** require **1** approving review from
  another admin/maintainer.
- **All other PRs** require **2** approving reviews from admins/maintainers.
- A PR author's own review never counts, and stale approvals are dismissed on
  new commits.

This conditional "1 if it's the owner, otherwise 2" rule is **not expressible in
native branch protection or CODEOWNERS**, so it is enforced by the
[`approval-policy`](.github/workflows/approval-policy.yml) GitHub Action, which
is wired in as a **required status check**. The required check is the workflow
job's own pass/fail conclusion (a single GitHub Actions check named
`approval-policy`) — it writes **no separate commit statuses**, so approved or
merged PRs never carry a stale failure mark; per-PR `cancel-in-progress`
concurrency retires obsolete runs. `.github/CODEOWNERS` keeps a single
owner entry (`* @sunhaoxiangwang`); native **"Require review from Code Owners"
is intentionally left OFF** — with a single-owner CODEOWNERS it would deadlock
the owner's own PRs (no other code owner could approve them).

## Branch protection setup (maintainers)

Applied via the GitHub API/UI once the repository is public (branch protection
is unavailable on private repositories under the free plan). The exact command:

```bash
gh api -X PUT repos/SUM-INNOVATION/sum-chain/branches/main/protection \
  -H "Accept: application/vnd.github+json" --input - <<'JSON'
{
  "required_status_checks": { "strict": true, "contexts": ["approval-policy"] },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Equivalent UI settings under **Settings → Branches** for `main`:

1. **Require a pull request before merging** → **Require approvals: 1** →
   **Dismiss stale pull request approvals when new commits are pushed**.
   (Leave **Require review from Code Owners** unchecked — the `approval-policy`
   check enforces the real rule.)
2. **Require status checks to pass before merging** → **Require branches to be
   up to date** → add the **`approval-policy`** check (and CI once green).
3. **Do not allow bypassing the above settings** (**enforce admins**).
4. **Block force pushes** and **restrict deletions** for `main`.

The native single-approval count is a floor; the **`approval-policy` required
check** enforces the conditional 1-vs-2 admin/maintainer rule.

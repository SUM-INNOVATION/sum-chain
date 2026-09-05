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

`main` is protected. Merging a pull request needs:

1. **one approving human review** (ordinary code review), and
2. **green CI**: `build-test-clippy`, `build-test-clippy-aarch64` and
   `supply-chain-audit`, with **"require branches to be up to date"** on.

That is all. Review here is a **development control** — it is not chain
consensus or runtime authority.

### No repository-governance automation

This repository does **not** run approval bots, automated GitHub reviewers,
governance workflows, or CODEOWNERS gating machinery. An earlier iteration (#219)
built an "automated review" workflow that replaced the human approval count with
a scripted policy check; it was removed in #239.

The reason is worth keeping: **automation means deterministic protocol validation
and execution performed directly by on-chain code.** The chain must not depend on
a human authority, board, administrator, or manual approval to execute a valid
state transition. CI and code review are how *developers* keep the tree healthy;
they are not, and must not become, a substitute for on-chain validation. If a rule
matters to the protocol, it belongs in consensus code with tests and vectors — not
in a `.github/` workflow.

`.github/CODEOWNERS` is therefore advisory: it suggests a default reviewer and
gates nothing ("Require review from Code Owners" is off).

## Branch protection setup (maintainers)

Applied via the GitHub API/UI:

```bash
gh api -X PUT repos/SUM-INNOVATION/sum-chain/branches/main/protection \
  -H "Accept: application/vnd.github+json" --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["build-test-clippy", "build-test-clippy-aarch64", "supply-chain-audit"]
  },
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
   Leave **Require review from Code Owners** unchecked.
2. **Require status checks to pass before merging** → **Require branches to be up
   to date** → require `build-test-clippy`, `build-test-clippy-aarch64` and
   `supply-chain-audit`.
3. **Do not allow bypassing the above settings** (**enforce admins**).
4. **Block force pushes** and **restrict deletions** for `main`.

The devnet health/readiness E2E (`health-e2e.yml`) also runs on pull requests. It
is not a required context because it builds and boots a 3-validator compose
stack, but a red E2E should be treated as blocking in practice.

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

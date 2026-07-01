# sumchain-integration-tests

End-to-end integration tests spanning multiple SUM Chain crates.

## Purpose

A test-harness crate that verifies end-to-end behaviour across components —
storage, state, consensus, p2p, RPC, and NFT — wired together as they are in a
running node.

## Main modules

Test suites under `src/`:

- `education_e2e_tests` — education-suite end-to-end flow.
- `nft_tests` — NFT (SUM-721) flows.
- `security_tests` — security-focused scenarios.
- `snip_v2_tests` — SNIP V2 storage/mirror scenarios.
- `stress_tests` — load/stress scenarios.

## Public interfaces

None — this crate ships no library API. Run the suites with:

```bash
cargo test -p sumchain-integration-tests
```

## Not for

- Production/library use — it is a test harness, not a dependency of other
  crates.
- Unit tests of a single crate — those live alongside each crate's sources.

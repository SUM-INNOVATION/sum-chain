# Dependency & Supply-Chain Audit

Reviewed supply-chain snapshot for the `sum-chain` workspace, established by the
#127 (BR1 beacon) reconciliation. It records the license policy, the RustSec
advisory posture, and the reviewed advisory-database revision, and it explains
the two automated gates that enforce them in CI.

- **Workspace toolchain:** Rust `1.85.0` (pinned in `rust-toolchain.toml`).
- **Dependency graph:** 734 packages (all targets, `all-features = true`).
- **Reviewed advisory-db revision:** `rustsec/advisory-db@4b27756f` (2026-09-01).
- **Tracking issue for residual advisories:** SUM-INNOVATION/sum-chain#200.

> **Beacon crypto path is clean.** None of the advisories below are reachable
> from `sumchain-beacon-crypto`, `sumchain-beacon-runtime`, or `sumchain-crypto`
> (verified with `cargo tree -i`). The beacon suite depends only on
> `blstrs`/`blst`, `sha2`, `hkdf`, `chacha20poly1305`, `blake3`, `group`,
> `zeroize`, `thiserror`, `hex` — all permissively licensed and advisory-free at
> this snapshot.

## Gates (CI job `supply-chain-audit` in `.github/workflows/rust-ci.yml`)

The owner-specified split is **`cargo deny` for license/source/duplicate policy**
and **`cargo audit` for RustSec advisories**. They are complementary:

| Tool | Config | Enforces |
|---|---|---|
| `cargo deny check licenses sources bans` | `deny.toml` | license allow-list, crates.io-only sources, duplicate/wildcard hygiene |
| `cargo audit` | `.cargo/audit.toml` | RustSec advisories; **fails the build on any vulnerability** |

`cargo audit` runs the advisory check because cargo-deny's advisory loader cannot
parse the current DB's CVSS-4.0 entries. **Both tools fetch the LIVE advisory
database on every CI run**, so a newly published advisory against an
already-present crate fails the build even though it is not enumerated here. The
snapshot revision above is recorded for provenance only — it is **not** pinned in
CI, so detection of newer advisories is preserved.

`deny.toml` keeps an `[advisories].ignore` list identical to `.cargo/audit.toml`
purely as documentation (and for the day cargo-deny's loader supports CVSS 4.0);
it is not the live advisory gate.

## License policy

`cargo deny check licenses` passes against the allow-list in `deny.toml`. The full
per-crate license inventory is committed at
[`dependency-license-inventory.txt`](./dependency-license-inventory.txt)
(regenerate with `cargo deny --locked list --layout crate`).

Allowed families and why each appears:

| License | Notes |
|---|---|
| MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception | dominant permissive set |
| BSD-2-Clause, BSD-3-Clause | e.g. `subtle`, `curve25519-dalek`, `bindgen` |
| ISC | `untrusted`, `rustls`, `simple_asn1` |
| Zlib, 0BSD, Unlicense, BSL-1.0 | permissive / public-domain-equivalent (`ryu`, `xxhash-rust`, `enum-iterator`) |
| Unicode-3.0 | ICU / `unicode-ident` (Unicode-DFS-style permissive) |
| CC0-1.0 | public-domain dedication (`constant_time_eq`, `tiny-keccak`, `more-asserts`, `dunce`) |
| MPL-2.0 | **file-level** weak copyleft; unmodified use imposes no obligation on our sources (`webpki-roots`, `colored`, `dynasm`/`dynasmrt`) |
| OpenSSL | **only** via the `ring` 0.16 clarification below |

**`ring` clarification.** Two `ring` versions resolve: `0.17.14` carries a normal
SPDX expression, while `0.16.20` (reached through the `ethers` EVM-bridge client
stack) ships a non-SPDX `LICENSE` amalgam. `deny.toml` clarifies `ring` to
`ISC AND MIT AND OpenSSL` with the `0.16.20` `LICENSE` file hash; the hash only
matches `0.16.20`, so `0.17.14` keeps its own expression.

GPL-2.0 / LGPL-2.1-or-later appear only inside `OR` expressions (`self_cell`,
`r-efi`) that resolve via an allowed permissive alternative, so neither copyleft
term is ever selected.

**Duplicate / wildcard hygiene.** `bans.multiple-versions = "warn"` surfaces
transitive version skew without failing (a 734-crate graph legitimately carries
some). `bans.wildcards` is left permissive here: publishable workspace crates
currently inherit internal path deps without an explicit version req — a
publish-readiness concern owned by **#117** (version convergence / leaf-guard),
not this reconciliation.

## RustSec advisories

### Fixed in this change (semver-compatible bumps, zero API risk)

| Advisory | Crate | Bump |
|---|---|---|
| RUSTSEC-2026-0007 | bytes | 1.11.0 → 1.11.1 |
| RUSTSEC-2026-0204 | crossbeam-epoch | 0.9.18 → 0.9.20 |
| RUSTSEC-2026-0185, -0037 | quinn-proto | 0.11.13 → 0.11.15 |
| RUSTSEC-2026-0001 | rkyv | 0.7.45 → 0.7.46 |
| RUSTSEC-2026-0049 | rustls-webpki | 0.103.8 → 0.103.10 |

### Tracked exceptions (fix needs a MAJOR cross-stack bump — issue #200)

Each is individually justified in `.cargo/audit.toml` / `deny.toml`. The gate
still fails on any advisory **not** on this list.

| Advisory | Crate | Reach | Required fix |
|---|---|---|---|
| RUSTSEC-2026-0119 | hickory-proto 0.24 (sumchain-p2p) | production | → 0.26 (DNS stack) |
| RUSTSEC-2026-0235 | rkyv 0.7 (sumchain-state/consensus) | production | → 0.8 (API migration) |
| RUSTSEC-2026-0009 | time 0.3.44 | production | → 0.3.47 (**requires Rust 1.88 > pinned 1.85**) |
| RUSTSEC-2026-0258 | h2 0.3 (ethers bridge) | 0 default-feature prod roots | → 0.4 |
| RUSTSEC-2025-0009 | ring 0.16 (jsonwebtoken/ethers bridge) | 0 default-feature prod roots | → 0.17 |
| RUSTSEC-2026-0104, -0098, -0099 | rustls-webpki 0.101 (ethers bridge) | 0 default-feature prod roots | → 0.103 |

`ring` / `rustls-webpki` / `h2` all arrive via the `ethers` EVM-bridge client
stack; a coordinated `ethers` upgrade likely clears several at once. The `time`
fix is coupled to a workspace MSRV bump (1.85 → 1.88).

### Non-security warnings (documented, non-blocking)

RustSec informational warnings present at this snapshot — surfaced by `cargo
audit`, not failed, and not broadly allowed:

- **unmaintained:** bincode, derivative, paste, proc-macro-error, instant, fxhash, rustls-pemfile
- **unsound:** anyhow, lru, memmap2, rand, keccak
- **yanked:** core2, keccak

## Maintenance

- **Remediating an advisory (#200):** apply the version bump, then delete that
  advisory's line from **both** `.cargo/audit.toml` and `deny.toml` so the gate
  re-tightens. Keep the two lists identical.
- **Refreshing the snapshot:** re-run `cargo audit` and
  `cargo deny --locked list --layout crate > docs/security/dependency-license-inventory.txt`,
  and update the revision/date at the top of this file.
- **A new license appears:** `cargo deny check licenses` fails; add it to the
  `deny.toml` allow-list with a rationale row here, or remove the offending dep.

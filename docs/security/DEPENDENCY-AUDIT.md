# Dependency & Supply-Chain Audit

Reviewed supply-chain snapshot for the `sum-chain` workspace, established by the
#127 (BR1 beacon) reconciliation. It records the license policy, the RustSec
advisory posture, and the reviewed advisory-database revision, and it explains
the two automated gates that enforce them in CI.

- **Workspace toolchain:** Rust `1.85.0` (pinned in `rust-toolchain.toml`).
- **Dependency graph:** 734 packages (all targets, `all-features = true`).
- **Reviewed advisory-db revision:** `rustsec/advisory-db@4b27756f` (2026-09-01).
- **Tracking:** umbrella SUM-INNOVATION/sum-chain#200, decomposed into six
  remediation tracks — #202 (hickory-proto), #203 (rkyv 0.7→0.8), #204 (time +
  MSRV), #205 (h2), #206 (ring), #207 (rustls-webpki legacy).

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

### Fixed in this change (semver-compatible bumps)

Semver-compatible (patch/minor) bumps — the compatibility guarantee is the
crate authors', not a claim of zero risk; they are covered by the full
`cargo build/test --workspace --locked` regression evidence retained for this
change (1388 passed, 0 failed).

| Advisory | Crate | Bump |
|---|---|---|
| RUSTSEC-2026-0007 | bytes | 1.11.0 → 1.11.1 |
| RUSTSEC-2026-0204 | crossbeam-epoch | 0.9.18 → 0.9.20 |
| RUSTSEC-2026-0185, -0037 | quinn-proto | 0.11.13 → 0.11.15 |
| RUSTSEC-2026-0001 | rkyv | 0.7.45 → 0.7.46 |
| RUSTSEC-2026-0049 | rustls-webpki | 0.103.8 → 0.103.10 |

### Tracked exceptions — six remediation tracks (umbrella #200)

Each track is individually justified in `.cargo/audit.toml` / `deny.toml`. The
gate still fails on any advisory **not** on this list.

**Blocker classification.** The three PRODUCTION tracks are **hard blockers for
the consolidated mainnet release**. The three DEV tracks are **signed-release
blockers absent explicit security-owner acceptance**.

| Issue | Advisory | Crate → fix | Class | Dependency path | Owner | Target release | Expiry |
|---|---|---|---|---|---|---|---|
| #202 | RUSTSEC-2026-0119 | hickory-proto 0.24 → 0.26 | **PROD** (hard) | node/rpc → p2p → libp2p-mdns → hickory-proto | networking / p2p | consolidated mainnet | hickory-proto ≥ 0.26.1 in lock |
| #203 | RUSTSEC-2026-0235 | rkyv 0.7 → 0.8 | **PROD** (hard) | consensus/node → state → sumc-runtime → wasmer → rkyv | execution / wasmer-runtime | consolidated mainnet | rkyv ≥ 0.8.17 in lock |
| #204 | RUSTSEC-2026-0009 | time 0.3.44 → 0.3.47 | **PROD** (hard) | bridge → ethers → jsonwebtoken → simple_asn1 → time | platform / toolchain (MSRV) | consolidated mainnet | MSRV 1.85→1.88 **and** time ≥ 0.3.47 |
| #205 | RUSTSEC-2026-0258 | h2 0.3 → 0.4 | dev | node/rpc → jsonrpsee → hyper 0.14 → h2 | bridge / RPC-client | signed release | h2 ≥ 0.4.16, or security-owner acceptance |
| #206 | RUSTSEC-2025-0009 | ring 0.16 → 0.17 | dev | bridge → ethers → jsonwebtoken 8.3 → ring 0.16 | bridge / EVM-client | signed release | ring 0.16 leaves lock, or security-owner acceptance |
| #207 | RUSTSEC-2026-0104/-0098/-0099 | rustls-webpki 0.101 → 0.103 | dev | node/rpc → jsonrpsee → hyper-rustls 0.24 → rustls 0.21 → rustls-webpki 0.101 | bridge / RPC-client | signed release | rustls-webpki 0.101 leaves lock, or security-owner acceptance |

`time` reaches the graph via the same `ethers`/`jsonwebtoken` bridge stack as the
dev tracks, but is a **production** track because its fix (≥ 0.3.47) requires a
**workspace-wide MSRV bump** (Rust 1.85 → 1.88) — a production-wide decision, not
a localized bridge bump. `ring` / `rustls-webpki` / `h2` all arrive via the
`ethers` EVM-bridge client stack; a coordinated `ethers` / `jsonwebtoken` /
`rustls` upgrade likely clears several dev tracks at once.

### Non-security warnings (documented, non-blocking)

RustSec informational warnings present at this snapshot — surfaced by `cargo
audit`, not failed, and not broadly allowed:

- **unmaintained:** bincode, derivative, paste, proc-macro-error, instant, fxhash, rustls-pemfile
- **unsound:** anyhow, lru, memmap2, rand, keccak
- **yanked:** core2, keccak

## Maintenance

- **Remediating a track (#202–#207):** land the fix so the track's **expiry
  condition** is met, then delete that advisory's line from **both**
  `.cargo/audit.toml` and `deny.toml` so the gate re-tightens. Keep the two lists
  identical. A dev track (#205/#206/#207) may alternatively be cleared for a
  signed release by the **security-owner recording explicit acceptance** — record
  that acceptance in the child issue before removing/annotating the line.
- **Refreshing the snapshot:** re-run `cargo audit` and
  `cargo deny --locked list --layout crate > docs/security/dependency-license-inventory.txt`,
  and update the revision/date at the top of this file.
- **A new license appears:** `cargo deny check licenses` fails; add it to the
  `deny.toml` allow-list with a rationale row here, or remove the offending dep.

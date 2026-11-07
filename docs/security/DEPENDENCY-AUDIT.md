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

**One crate needs its own advisory check:** the vendored `object` 0.32.2 (#306).
Neither `cargo audit` nor `cargo deny check advisories` matches an advisory against
a `[patch]` path crate. `scripts/check-vendored-object.sh advisories` audits the
crates.io `object` 0.32.2 that the vendored copy is (apart from one manifest hunk)
in `supply-chain-audit` and daily in `vendored-object.yml`, and
`scripts/check-vendored-object.sh` (CI job `rollout-tooling`) checks that the copy
matches crates.io. See the #306 section below. The vendored `memmap2` 0.5.10 and
0.6.2 (RUSTSEC-2026-0186) are checked the same way by
`scripts/check-vendored-memmap2.sh`, and the vendored `lru` 0.12.5
(RUSTSEC-2026-0253, RUSTSEC-2026-0002) by `scripts/check-vendored-lru.sh`; see
their sections below.

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
| ~~#203~~ **RESOLVED** | RUSTSEC-2026-0235 | rkyv 0.7 → 0.8 ✅ | **PROD** (hard) — cleared | consensus/node → state → sumc-runtime → wasmer → rkyv | execution / wasmer-runtime | ✅ done | **met**: wasmer 4.x→5.0.6 migration brought rkyv **0.8.18** (≥ 0.8.17) and rkyv 0.7.46 left the lock; exception removed. (5.0.6 = last MIT Singlepass; 6.0.0+ is BUSL-1.1 — see WASMER-5-MIGRATION.md) |
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

### Resolved — #306, RUSTSEC-2026-0344 (`ruzstd` 0.5.0), by a vendored `object` 0.32.2

[RUSTSEC-2026-0344](https://rustsec.org/advisories/RUSTSEC-2026-0344.html) (2026-10-11, denial of service): a crafted zstd input makes `ruzstd` < 0.9.1
allocate gigabytes; fixed in ≥ 0.9.1. `cargo audit` began failing on it on 2026-10-13 (advisory-db `6aed8466`), and it was
then carried as a tracked exception. That exception is now removed from `.cargo/audit.toml` and `deny.toml`, and both
`ignore` lists are empty. **Class:** PRODUCTION path; this is the remediation proposed for the #306 blocker for the next
consolidated mainnet release, and #306 is closed separately by the owner.

`ruzstd 0.5.0` came from `object 0.32.2`'s `compression` feature, which `object`'s `default` enables. `wasmer-compiler 5.0.6`
declares `object = { version = "0.32.0", features = ["write"] }` without `default-features = false`. Cargo features are
additive and the workspace has no direct dependency on `object`, so no setting of ours can drop the feature. A newer wasmer
is not an option either: wasmer ≥ 6.0.0 is BUSL-1.1 (see `WASMER-5-MIGRATION.md`). The fix therefore patches `object`.

| Item | Finding |
|---|---|
| Change | The root `Cargo.toml` has `[patch.crates-io] object = { path = "crates/third_party/object-0.32.2" }`. That directory is the crates.io `object-0.32.2.crate` extracted verbatim (sha256 `a6a622008b6e321afc04970976f62ee297fdbaa6f95318ca343e3eebb9648441`, the checksum `Cargo.lock` recorded for it). The only edit is its `Cargo.toml` `default` list, from `["read", "compression"]` to `["read"]`, under a `# SUM-CHAIN #306` comment. It is not a workspace member. Both `Dockerfile` and `tools/release/native.Dockerfile` copy it with `COPY crates crates`. |
| `Cargo.lock` | `object 0.32.2` loses its `source` and `checksum` lines and its `flate2` and `ruzstd` edges. `ruzstd 0.5.0` and `twox-hash 1.6.3` leave the lock (606 → 604 packages). Every `wasmer*` entry is byte-identical. `flate2` stays, through `ureq`, a wasmer build dependency. |
| Features | `object 0.32.2` still has `default`, `read` (with its format features), `write`, `write_core`, `write_std` and `std`. Only `compression` is gone; `std` is still enabled through `write`. `wasmer-compiler` uses `object` only through `object::write`, which `compression` does not affect. Feature unification also changes for two shared crates: `crc32fast` loses only `default` (= `std`, still on), and `miniz_oxide` 0.8.9, now reached only through `backtrace` (debug-info decompression when symbolizing), loses `simd`, `simd-adler32` and `with-alloc`, which `flate2` had enabled. `flate2`, `simd-adler32`, `ruzstd` and `twox-hash` leave the runtime graph. |
| Behaviour | `compression` gates two read-side items: the zlib and zstd arms of `CompressedData::decompress` (`src/read/mod.rs`), which now return the crate's "Unsupported compressed data." error, and the ELF `.zdebug_*` section fallback (`src/read/elf/file.rs`). No wasmer 5.0.6 crate and no workspace crate calls `object`'s read API. |
| Equivalence | `scripts/compare-wasmer-artifacts.sh <base> <head>` builds `crates/sumc-runtime/examples/artifact_hash.rs` (release profile, `--locked`) in a temporary worktree of each revision, runs each binary twice, and requires every `Module::serialize()` artifact and the manifest to be byte-identical. The corpus is 5 built-in modules plus every raw-string WAT module in the runtime, state, consensus and RPC tests (39 modules today, 34 of them from the tests; 3 `format!` templates are skipped), each compiled with plain Singlepass (the block executor's engine) and with Singlepass plus `Metering` (the public part of the local executor's engine). The `wasmer artifacts base vs head` jobs of `vendored-object.yml` run it on x86_64 (`ubuntu-latest`) and aarch64 (`ubuntu-24.04-arm`) Linux for PRs that touch the lock, the root or `sumc-runtime` manifest, `crates/third_party/**`, the harness or the scripts; it also matched on aarch64-darwin. Execution is covered by the workspace tests in `rust-ci.yml` on both architectures, including `wasmer_determinism_vectors`, `consensus_metering`, `local_execution_limits` and the `contract_*` suites. |
| Verify | `bash scripts/check-vendored-object.sh` (CI job `rollout-tooling`, and `vendored-object.yml`) downloads the crate from crates.io, checks the pinned sha256, extracts it, and fails unless `diff -r` against the vendored directory is exactly the `default` hunk. `cargo tree --workspace --all-features --target all -i ruzstd` matches nothing, and `-i object@0.32.2` shows only `wasmer-compiler`. |
| Coverage | Measured with cargo-audit 0.22.2 and cargo-deny 0.20.2. Neither matches an advisory against a path crate: against a local probe database (test-only advisories for `object` 0.32.2 and its four dependencies), both reported the `object` probe on the base lock, where `object` is a crates.io entry, and not with the patch; both reported the `crc32fast` 1.5.0, `hashbrown` 0.14.5, `indexmap` 2.12.1 and `memchr` 2.7.6 probes with and without it, since those stay crates.io entries. Likewise the real RUSTSEC-2026-0344 fails `cargo audit` on the base lock and passes once `ruzstd` loses its `source` line. `cargo deny` still applies `licenses` (it reads the vendored manifest: a probe relicensing it to GPL-3.0-only was rejected) and `bans` (an explicit ban on `object@0.32.2` fires, and it counts in duplicate detection) to the path crate; `sources` has nothing to check for it. The lock holds no checksum for it. |
| Monitoring | `scripts/check-vendored-object.sh advisories` writes a synthetic `Cargo.lock` declaring `object` 0.32.2 with its crates.io source and the pinned checksum, and runs `cargo audit --file Cargo.lock --deny warnings` on it with the repository's `.cargo/audit.toml`. Any vulnerability, unsound, unmaintained or yanked advisory against `object` 0.32.2 fails it (checked with the probe database); an exception recorded in `.cargo/audit.toml` applies to it as to the main gate. It runs in `supply-chain-audit` (`rust-ci.yml`) on every PR and push to main, and daily at 05:17 UTC in `vendored-object.yml`. Both modes of the script fail first if the pin drifts from what is built: the vendored manifest must be `object` 0.32.2, `[patch.crates-io]` must point at it, and `Cargo.lock` must resolve `object` 0.32.2 to that path crate only, with no unused patch. `cargo deny` takes no lockfile (it builds its graph from `cargo metadata`), so it is not part of this check. GitHub disables a public repository's scheduled workflows after 60 days without repository activity. |
| Exit | Delete the patch and the vendored directory once wasmer resolves to an `object` without `compression` in its defaults, or with `ruzstd` ≥ 0.9.1. That is an engine dependency change and needs review for consensus impact. If `wasmer-compiler` stops resolving to `object 0.32.2`, cargo reports the patch as unused; remove it then. |

### Resolved — RUSTSEC-2026-0186 (`memmap2` 0.5.10 / 0.6.2), by vendored backports

[RUSTSEC-2026-0186](https://rustsec.org/advisories/RUSTSEC-2026-0186.html) (2026-06-20, informational: unsound): before 0.9.11,
`MmapMut::flush_range`, `MmapMut::flush_async_range`, and `Mmap`/`MmapMut`/`MmapRaw` `advise_range` (and their `unchecked_`
forms) pass an unchecked offset to `pointer::offset`/`add` before `msync`/`madvise` (`FlushViewOfFile` on Windows), which is
undefined behaviour for an out-of-range offset or length. `wasmer 5.0.6` reaches `memmap2` 0.6.2 through `shared-buffer` 0.1.4 and
`wasmer-compiler-singlepass 5.0.6` reaches 0.5.10 through `dynasmrt` 1.2.3, both in the validator binary through `sumc-runtime`.
Every `shared-buffer` 0.1.x requires `memmap2` ^0.6.1, the `dynasmrt` lines on 0.9 need `wasmer-compiler-singlepass` ≥ 6.0.1,
and wasmer ≥ 6.0.0 is BUSL-1.1 (`WASMER-5-MIGRATION.md`), so no version update reaches 0.9.11. The fix patches both versions.

| Item | Finding |
|---|---|
| Change | The root `Cargo.toml` `[patch.crates-io]` points `memmap2` at `crates/third_party/memmap2-0.6.2` and `memmap2-0510` (`package = "memmap2"`) at `crates/third_party/memmap2-0.5.10`. Each directory is the crates.io `.crate` extracted verbatim (0.6.2 sha256 `6d28bba84adfe6646737845bc5ebbfa2c08424eb1c37e94a1fd2a82adb56a872`, 0.5.10 `83faa42c0a078c393f6b29d5db232d8be22776a891f8f56e5284faee4a20b327`, the checksums `Cargo.lock` recorded), including its `Cargo.lock`, which the crate's own `.gitignore` would otherwise drop. The only edits are memmap2 0.9.11's bounds checks, each under a `// SUM-CHAIN` comment: `offset > len \|\| len > len - offset` → `InvalidInput` at the top of `MmapInner::flush` and `flush_async` (`unix.rs`) and `flush_async` (`windows.rs`), and upstream's `offset > len \|\| len > len` in `MmapInner::advise` (`unix.rs`). Neither is a workspace member. |
| `Cargo.lock` | Both `memmap2` entries lose their `source` and `checksum` lines. Nothing else changes. |
| Callers | A scan of the source of every crates.io package in the lock (572) finds no call to `flush_range`, `flush_async_range`, `advise_range` or `unchecked_advise_range` outside `memmap2` itself, and the workspace calls none. `flush()`, `flush_async()` and `advise()` pass `0` and the map's length, which the checks accept, so in-range behaviour is unchanged; only a call that was undefined behaviour now returns an error. |
| Equivalence | `vendored-object.yml`'s `wasmer artifacts base vs head` jobs run on PRs that touch `crates/third_party/**`, so `scripts/compare-wasmer-artifacts.sh` requires every `Module::serialize()` artifact to be byte-identical at base and head on x86_64 and aarch64 Linux. |
| Verify | `bash scripts/check-vendored-memmap2.sh` (CI job `rollout-tooling`, and `vendored-object.yml`) downloads both crates from crates.io, checks the pinned sha256s, and fails unless `diff -r` against each vendored directory is exactly the backport hunks. Mutations checked: an extra line in a vendored file, a weakened check, and a removed `[patch]` entry each fail it. |
| Monitoring | `scripts/check-vendored-memmap2.sh advisories` writes a synthetic `Cargo.lock` with both crates.io identities and runs `cargo audit --file Cargo.lock --deny warnings --ignore RUSTSEC-2026-0186` with the repository's `.cargo/audit.toml`: any other advisory against either version fails. It runs in `supply-chain-audit` on every PR and push to main, and daily in `vendored-object.yml`. Both modes fail first if a pin drifts from what is built. Checked with local probe databases: the real database passes, and a test unsound advisory and a test vulnerability against `memmap2`, and a test advisory against 0.5.x only, each fail it. |
| Exception | **Adopted by the owner on 2026-11-06, for the verified, backported 0.5.10 and 0.6.2 copies only.** RUSTSEC-2026-0186 is ignored in the `advisories` check above and nowhere else: `.cargo/audit.toml` and `deny.toml` keep empty `ignore` lists, and the workspace `cargo audit` gate has no exception for it. The `source` check keeps verifying that each vendored directory is the crates.io crate plus exactly the backported checks, and any other advisory against either version still fails. |
| Exit | Delete a patch and its directory once its dependent no longer resolves to that version (cargo then reports the patch as unused, which the script refuses). That is an engine dependency change and needs review for consensus impact. |

### Resolved — RUSTSEC-2026-0386 (`tokio` 1.48.0), by tokio 1.51.6

[RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) (2026-10-13, informational: unsound): `tokio::io::unix::AsyncFd`'s safe
constructors (`new`, `with_interest`, `try_new`, `try_with_interest`) accept any `AsRawFd`. If the registered descriptor is closed, or
duplicated and then closed, while the `AsyncFd` lives, and its number is reused on the same runtime, the I/O driver frees a registration
still in epoll: a use-after-free on the next readiness event. Fixed in 1.51.6 (and ≥ 1.53.3), which deprecates them for the `unsafe`
`AsyncFd::register`.

| Item | Finding |
|---|---|
| Callers | A scan of every crates.io package in the lock finds one caller, `netlink-sys` 0.8.7 (`TokioSocket`), in the validator on Linux through `sumchain-p2p` → `libp2p-tcp` 0.41 (`tokio`) → `if-watch` 3.2.1 → `rtnetlink` 0.13.1 / `netlink-proto` 0.11.5. `libp2p-tcp` starts the interface watcher when it listens on an unspecified address. The workspace has no `AsyncFd`. |
| Trigger | Not reached: `TokioSocket` owns its `Socket` inside the `AsyncFd` (`Socket::drop` closes the descriptor; `AsyncFd` deregisters before dropping it), the only mutable use on this path is `if-watch`'s `bind()`, and the `unsafe` `FromRawFd` constructor is not used. |
| Change | `tokio` 1.48.0 → 1.51.6, with `tokio-macros` 2.7.2, `mio` 1.2.4, `socket2` 0.6.5 and `libc` 0.2.191, which 1.51.6 and `mio` 1.2.4 require; `hyper-util`'s `socket2` edge follows to 0.6.5; `windows-sys` 0.60.2 leaves the lock. No manifest change. |

### Resolved — RUSTSEC-2026-0253 and RUSTSEC-2026-0002 (`lru`): the state cache on 0.18.5, libp2p's 0.12.5 by vendored backport

[RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html) (unsound): before 0.18.2, `LruCache::pop()` frees a node before
detaching it, so a key whose `Drop` panics under `catch_unwind` leaves a dangling list pointer that a later eviction writes through.
[RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002.html) (unsound): before 0.16.3, `IterMut` violates Stacked Borrows.

| Item | Finding |
|---|---|
| Callers | `sumchain-state`'s `StateCache` (`pop()` on `LruCache<Address, …>` and `LruCache<(Address, Hash), …>`), and `libp2p-swarm` 0.44.2's `PeerAddresses` (`pop()` on `LruCache<PeerId, LruCache<Multiaddr, ()>>`; `libp2p-identify` uses it). No `LruCache::iter_mut` anywhere. |
| Trigger | Not reached: none of these key types has a `Drop` that can panic, the workspace has no `catch_unwind`, and release builds use `panic = "abort"`. |
| Change (state cache) | `crates/state` moves to `lru` 0.18.5 (the API it uses is unchanged). |
| Change (libp2p) | `lru` 0.12.5 stays the version `libp2p-swarm` and `libp2p-identify` 0.44.2 require (`^0.12.3`); removing it needs libp2p ≥ 0.46, a breaking networking upgrade of the validator. Instead the root `Cargo.toml` `[patch.crates-io]` points `lru` at `crates/third_party/lru-0.12.5`: the crates.io `.crate` extracted verbatim (sha256 `234cf4f4a04dc1f57e24b96cc0cd600cf2af460d4161ac5ecdd0af8e1f3b2a38`, the checksum `Cargo.lock` recorded), with upstream's two fixes backported into `src/lib.rs`, each under a `// SUM-CHAIN` comment: `LruCache::pop` detaches the node before freeing it and dropping the key (lru 0.18.2, jeromefroe/lru-rs#238), and `IterMut::next` / `next_back` hand out the key as `&K` (lru 0.16.3, jeromefroe/lru-rs#224). It is not a workspace member. The patch applies only to the `^0.12` requirement; `sumchain-state`'s 0.18.5 is not patched. |
| `Cargo.lock` | The `lru` 0.12.5 entry loses its `source` and `checksum` lines. Nothing else changes. |
| Regressions | Upstream's tests are added to the vendored crate's tests: `test_pop_panicking_key_drop_keeps_list_consistent` (a key's `Drop` panics inside `pop`, the panic is caught, then the cache is reused: insertions, an eviction, a lookup and a full iteration) and `iter_mut_stacked_borrows_violation`, plus `iter_mut_rev_stacked_borrows_violation` for `next_back`. `scripts/check-vendored-lru.sh regressions` runs them from a copy outside the workspace, natively and with `--miri` under Miri (pinned `nightly-2026-10-23`). With `--miri --without-fixes` it runs them on the crates.io source plus only the tests and requires Miri to report undefined behaviour in each: it does (a Stacked Borrows retag violation in both `IterMut` directions, and failed pointer arithmetic on the freed node in `pop`). |
| Verify | `bash scripts/check-vendored-lru.sh` (CI job `rollout-tooling`, and `vendored-object.yml`) downloads the crate from crates.io, checks the pinned sha256, and fails unless git's diff of it against the vendored directory (`git diff --no-index`, Myers with the indent heuristic, no context, full blob ids: the same on every platform) is exactly the backported fixes and their regressions. Mutations checked: an extra line in the vendored source, the `pop` fix reverted, the `[patch]` entry removed, and `Cargo.lock` resolving 0.12.5 from the registry each fail it. |
| Monitoring | `scripts/check-vendored-lru.sh advisories` writes a synthetic `Cargo.lock` declaring the crates.io identity and runs `cargo audit --file Cargo.lock --deny warnings --ignore RUSTSEC-2026-0253 --ignore RUSTSEC-2026-0002` with the repository's `.cargo/audit.toml`: any other advisory against `lru` 0.12.5 fails. It runs in `supply-chain-audit` on every PR and push to main, and daily in `vendored-object.yml` with the source check and the regressions job. Every mode fails first if the pin drifts from what is built. Checked with local probe databases: the real database passes, and a test unsound advisory and a test vulnerability against `lru` each fail it. |
| Exception | **Adopted by the owner on 2026-11-07, for this verified, patched `lru` 0.12.5 copy only.** RUSTSEC-2026-0253 and RUSTSEC-2026-0002 are ignored in the `advisories` check above and nowhere else: `.cargo/audit.toml` and `deny.toml` keep empty `ignore` lists, and the workspace `cargo audit` gate has no exception for them. Other advisories and any source drift fail the guards. |
| Exit | Delete the patch and the directory once libp2p no longer resolves `lru` 0.12.x (cargo then reports the patch as unused, which the script refuses). That is the libp2p upgrade, tracked separately. |

### Non-security warnings (documented, non-blocking)

RustSec informational warnings present at this snapshot — surfaced by `cargo
audit`, not failed, and not broadly allowed:

- **unmaintained:** bincode, derivative, paste, proc-macro-error, instant, fxhash, rustls-pemfile
- **unsound:** anyhow, lru, memmap2, rand, keccak (memmap2: resolved by the vendored backports above, RUSTSEC-2026-0186; lru: `sumchain-state` on 0.18.5, libp2p's 0.12.5 resolved by the vendored backport above; tokio, RUSTSEC-2026-0386 after this snapshot: resolved above)
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
- **The vendored `object` 0.32.2 (#306):** never edit
  `crates/third_party/object-0.32.2` beyond its `default` list;
  `scripts/check-vendored-object.sh` fails on any other difference.
  `scripts/check-vendored-object.sh advisories` fails `supply-chain-audit` and the
  daily `vendored-object.yml` run on any RustSec advisory against `object` 0.32.2;
  assess it on #306, and record an accepted exception in `.cargo/audit.toml`.
  Re-evaluate the patch on any wasmer change, and compare compiled artifacts with
  `scripts/compare-wasmer-artifacts.sh <base> <head>` for any change under the
  engine.

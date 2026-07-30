# B0-PRE builder capability — pin-coverage matrix + proposed amendments

Status: **PROPOSAL — UNRATIFIED.** Prepared by the coder per the owner's execution-contract
audit ruling. Nothing here is ratified; no value is authoritative until the owner ratifies
it. This exists so the two builder images can be made *capability-complete* (Stage 1 →
import) without inventing pins. See `PIN-PROPOSAL.md` (the existing ratified-pin shape) and
`S1-V2-X86-SMOKE.md`.

## 1. Pin-coverage matrix

"Existing record covers it?" is judged against the ratified pin shape in `PIN-PROPOSAL.md`
(`tool_identities`: `sp1-verifier` 6.3.1 ×{x86_64,aarch64}, `risc0-zkvm` 3.0.5 x86_64,
`risc0-groth16` 3.0.4 x86_64) — whose real `artifact_identity` / `install_entrypoint` /
`checksum_hex` **values are owner-held and not in this repo**.

| Required executable | Candidate | Arch | Existing ratified record covers it? | Missing field / input |
|---|---|---|---|---|
| `cargo` / `rustc` 1.88 | both | x86_64, aarch64 | **YES** — `rustup_init` pin (URL+sha256 per arch), `ENV PATH` | none |
| `cargo metadata` (Stage 2) | both | x86_64, aarch64 | **YES** (ships with cargo) | none |
| `cargo generate-lockfile` / `cargo run/build` (Stage 1/4-5/5c) | both | x86_64, aarch64 | **YES** (ships with cargo) | none |
| **`cargo-audit`** (Stage 2 `cargo audit --json`) | both (candidate-neutral) | x86_64, aarch64 | **NO** — no `tool_identity` exists | NEW amendment §2 |
| **RustSec advisory DB** (Stage 2 audit data) | both | data (per-arch identical) | **NO** — no pin exists | NEW amendment §3 (policy A) |
| **`cargo prove`** (SP1 guest build + prove, Stage 5c) | SP1 | x86_64, aarch64 | **UNKNOWN** — an `sp1-verifier` tool_identity exists per arch *with* an `install_entrypoint`, but whether that entrypoint installs the `cargo prove` **prover CLI** (vs only fetching the verifier crate) and yields a point-of-use executable hash depends on the **owner-held value** | owner confirmation §4; else minimal amendment |
| **`cargo risczero`** (RISC0 guest build, Stage 5c) | RISC0 | x86_64 | **UNKNOWN** — `risc0-zkvm`/`risc0-groth16` tool_identities exist (x86 only) with entrypoints; prover-CLI coverage depends on the owner-held value | owner confirmation §4; else minimal amendment |
| **`rzup`** (RISC0 toolchain manager) | RISC0 | x86_64 | **UNKNOWN** — same | owner confirmation §4; else minimal amendment |
| **`r0vm`** (RISC0 zkVM runtime) | RISC0 | x86_64 | **UNKNOWN** — same | owner confirmation §4; else minimal amendment |

Not required in-container (host tools; OK): `python3`, `sha256sum`, `docker`, `git`,
`venue-verify`. RISC Zero is **x86_64 only** — never installed on aarch64 (VENUE.md §2).

## 2. Proposed amendment — `cargo-audit` (collected from primary sources; **verify + ratify**)

| Field | Proposed value |
|---|---|
| name | `cargo-audit` |
| version | `0.22.2` (crates.io `max_stable_version`, not yanked; MSRV `1.88` — matches the pinned toolchain) |
| source tag / commit | `rustsec/rustsec` release `cargo-audit/v0.22.2` (2026-06-05) — resolve tag→commit and pin the commit |
| immutable locator | crates.io `.crate`: `https://crates.io/api/v1/crates/cargo-audit/0.22.2/download` |
| checksum (sha256 of the `.crate`) | `700c2b240f7fd330c24b675fe429f73a5b676531fcc6300400b2b67f155ba12a` (crates.io-published; **independently re-download + re-hash before ratifying**) |
| install method | `cargo install cargo-audit --version =0.22.2 --locked` (never unversioned; `--locked` pins its dependency graph) |
| per-arch executable identity | recompute `sha256(cargo-audit)` on x86_64 **and** aarch64 at install and record both (they differ per arch) |

Caveats to resolve before ratifying: `cargo install … --locked` still resolves crates.io at
build time — for byte-determinism, pin cargo-audit's own `Cargo.lock` (vendor or a committed
lock) or install from a pinned vendored source, so its dependency bytes are fixed.

## 3. Proposed amendment — RustSec advisory database (policy A: immutable snapshot)

Per the owner's ruling (policy A): pin the DB repo + exact commit, materialize it read-only
before the audit, run `cargo audit` against that exact DB with implicit update disabled,
record the commit + content digest in Stage-2 evidence, and have import verify them.

| Field | Proposed value |
|---|---|
| repository | `https://github.com/rustsec/advisory-db` |
| commit (40-hex) | `7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2` (HEAD of `main` at 2026-07-29T15:17:10Z) |
| tree/content digest | git tree `2d3ab21e05f8b06ad2e232f92894b5e247d817ce`; also record a domain-separated BLAKE3 over the checked-out tree at acquisition |
| acquisition method | `git clone` + `git checkout <commit>` (verify `git rev-parse HEAD` == commit), OR fetch the commit tarball + verify; then `cargo audit --db <path> --no-fetch --stale` (exact flags to confirm against cargo-audit 0.22.2) |
| verification result | recorded: repo, commit, tree digest, acquisition method, checkout verification |

Stage-2 evidence records `advisory_db_commit` + `advisory_db_content_blake3`; **import
verifies both against the ratified record** and fails on disagreement. A moving online DB is
not acceptable for authoritative evidence.

## 4. Prover-toolchain coverage — needs owner confirmation (do NOT duplicate pins)

The existing `sp1-verifier` / `risc0-zkvm` / `risc0-groth16` records each carry an
`install_entrypoint`. **Please confirm, from the ratified values you hold, whether:**
- the `sp1-verifier` entrypoint installs `cargo prove` on **both** x86_64 and aarch64, with a
  point-of-use executable hash we can re-verify; and
- the `risc0-*` entrypoints install `cargo risczero` + `rzup` + `r0vm` on **x86_64**, likewise.

If **yes**, no new pin is needed — I implement the **consumer** (the Dockerfile installs via
the ratified entrypoint; point-of-use code re-hashes and executes the exact authenticated
binary; the capability preflight validates version + identity). If **any** executable or
arch-specific byte is **not** covered, I will prepare a **minimal** amendment naming only the
missing input, and stop for your ratification.

## 5. What is implemented now vs gated on ratification

**Implemented (pure code, no new pin):** RT-2 non-login `bash -c` for all Stage-5 in-container
execution; removal of the fixture's PATH-repair hack; Stage-2 audit that distinguishes
"executed" from "could-not-execute" (missing tool / DB failure / empty / unparseable is never
a clean audit); corrected Dockerfile docs (no nonexistent entrypoint).

**Gated on your ratification (then I wire the consumers + capability preflight + first-class
smoke to reach real SP1/RISC0 Stage 5):** the `cargo-audit` pin (§2), the advisory-DB pin
(§3), and the prover-toolchain coverage decision (§4).

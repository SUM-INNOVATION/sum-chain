# B0-PRE candidate reproducibility-input scaffolding

Status: **NOT_YET_REPRODUCED**

This tree is *turnkey scaffolding* for resolving the three B0-PRE Stage-1
implementation-produced input categories:

- `candidate_container_digests`
- `cargo_lock_hashes`
- `verifier_material_manifests`

It contains **no** authoritative outputs. No candidate `Cargo.lock`, no container
OCI digest, no verifier-material bytes, and no `candidate_dep_lock_hash` are
present or may be fabricated here. Every real value is produced only by running
[`scripts/run_authoritative.sh`](scripts/run_authoritative.sh) on the native
Linux builders described in [`VENUE.md`](VENUE.md).

## Why nothing is built here

This scaffolding was authored on an arm64 macOS workstation that is deliberately
**not** provisioned as a build venue: docker daemon down, no `buildx`/QEMU (so no
native x86_64), no Rust 1.88, no SP1/RISC Zero toolchains, and a near-full disk.
RISC Zero Groth16 receipt generation and verifier-material extraction must run
**natively on x86_64** — emulated results are ineligible. See `VENUE.md`.

## Layout

| Path | Purpose |
|------|---------|
| `VENUE.md` | Authoritative execution-venue contract (prerequisites, invariants). |
| `candidates/sp1/`, `candidates/risc0/` | Exact-pinned candidate manifests. No lockfiles (the venue generates them). |
| `containers/` | Dockerfiles requiring immutable base-image digests + Rust 1.88 by exact checksum. |
| `harness/` | Verifier-material extraction + contract-test crates (build/run only in the venue). |
| `scripts/` | Build / extract / orchestrate / probe scripts. Refuse to run outside the venue. |

## Producer → Stage-6 pipeline (two architectures, three commands)

No single host satisfies both architectures, and RISC Zero material is x86_64-only,
so the run is split into three explicit `run_authoritative.sh` commands:

1. **`produce-arch <x86_64|aarch64> <bundle_dir>`** — produce ONLY this arch's
   evidence into an exported per-arch bundle:
   - `build_container.sh` — TWO independent clean OCI builds (`--no-cache`). The
     recorded image identity is the **real OCI manifest content address parsed from
     the exported layout's `index.json`** (`venue-verify oci-manifest`), never
     `sha256(the exported tar)`; the tar-byte BLAKE3s are kept only as raw `*_hex`
     witnesses. Both build logs are captured. The `base` entry is modeled as an
     **immutable input** resolved by pull-by-digest — its identity IS `BASE_DIGEST`
     and its provenance is the base-resolution `docker manifest inspect`, never a
     copy of the builder build.
   - `resolve_lock.sh` — runs `cargo generate-lockfile` INSIDE the just-built builder
     image, exports the lock, binds it to `(candidate, arch, container_digest,
     source_commit, command_log)`, and **rejects any host-originated lock**; the hash
     is recomputed from the exported bytes and re-verified (`venue-verify verify-lock`).
   - `venue-verify stage2-audit` — a real resolved-graph audit (dependency / source /
     advisory / license) emitting machine-readable fatal-vs-recorded findings; a fatal
     finding stops the run.
   - `harness/{sp1,risc0}-verifier-material` — verifier material (identity via the
     shared canonical primitive). SP1 per arch; **RISC Zero x86_64 ONLY**.
   - `tool_identities.sh` — for each proof tool: DOWNLOAD → verify declared checksum
     over the bytes → install via the declared entrypoint → verify the installed
     binary → BIND the verified-artifact hash + installed-binary hash
     (`venue-verify verify-tool`). A JSON assertion alone is not evidence; fail-closed,
     never invents installer metadata.
2. **`import-verify <bundle_dir>`** — independently re-validate a RETURNED per-arch
   bundle (arch coverage, native-ness, two-build reproducibility, RISC-Zero-only-on-
   x86_64).
3. **`aggregate <x86_64_dir> <aarch64_dir> <workdir>`** — assemble the full
   `AUTHORITATIVE_STAGE1` bundle ONLY after BOTH per-arch bundles pass import
   verification, sourcing RISC Zero material from the x86_64 bundle
   (`venue-verify aggregate-arches`), then `stage6-assemble` → `stage1-ingest`.

The assembler emits a strict `AUTHORITATIVE_STAGE1`-classified bundle; `stage1-ingest`
is the single insertion gate and REFUSES any `TEST_ONLY` / `NON_SELECTION` bundle.

**Off-venue dry run** (`SUMCHAIN_B0PRE_DRYRUN=1`): the producers emit real-SHAPED
sample files matching the exact production schema (no Docker / toolchains / b3sum),
for the producer→consumer compatibility tests. Dry-run tool identities are
unmistakably synthetic (they carry the `TEST_ONLY_SYNTHETIC` sentinel) and can never
substitute for real venue metadata.

## Hard boundaries (in force)

- No production nodes, validator config, deployments, registries, GitHub, or CI touched.
- No image pushed to any registry; no host-global toolchain installed.
- No commit / push / PR; no real `b0-pre-protocol-v1.hash` written.
- No final statement materialization, official guests, populated allowlist, or `r0_guest_set_hash`.
- Any proof produced only to validate a verifier contract is stamped
  `TEST_ONLY / NON_SELECTION / INVALID_FOR_R0 / NOT_AN_OFFICIAL_GUEST`; its guest
  identity never enters the normative protocol artifact.

This tree is workspace-excluded (`exclude = ["tools"]`) and has no production
dependency edge.

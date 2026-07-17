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

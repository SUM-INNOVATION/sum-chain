# B0-PRE authoritative venue runbook (provider-neutral, two-host)

This runbook drives the authoritative Stage-1 resolution over **two operator-controlled
native Linux hosts** using only SSH + the scripts in `tools/b0-pre-candidates/scripts`.
It is **provider-neutral**: identical commands run on AWS EC2, Azure VMs, or any native
Linux machine. It does **not** provision infrastructure (no Terraform, no cloud API
calls) — you bring two hosts, this runbook uses them.

> The workflow is pinned to the canonical `main` merge commit
> **`5994bed018fdf38d4913b5b166dd5a662d9cf919`**. Evidence produced from any other commit
> is non-authoritative (VENUE.md §4) and must be discarded. Nothing here commits, pushes,
> computes the real `b0_pre_spec_hash`, or mutates `main`.

## 0. Prerequisites (both hosts)

| Host | Arch | Requirements |
|------|------|--------------|
| HOST_X64 | native `x86_64` Linux | Docker (OCI builder, daemon running), `git`, `python3`, `b3sum`, `cargo`/rust toolchain, **≥ 100 GiB** free ephemeral SSD |
| HOST_ARM | native `aarch64` Linux | same as above |

- **No emulation** (QEMU/Rosetta/buildx cross-platform) — RISC Zero material and all
  extraction must run natively on `x86_64` (VENUE.md §2).
- **No production secrets** on either host. Venue-input pins are supplied as environment
  variables from the ratified pin set (see `docs/b0-pre/venue/PIN-PROPOSAL.md`); scoped,
  temporary credentials only.
- Temporary machines are expected: provision, run, collect evidence, destroy.

## 1. Prepare each host (identical on HOST_X64 and HOST_ARM)

```sh
# clone at the EXACT canonical commit; refuse to proceed from any other HEAD.
git clone https://github.com/SUM-INNOVATION/sum-chain.git
cd sum-chain
git checkout 5994bed018fdf38d4913b5b166dd5a662d9cf919
test "$(git rev-parse HEAD)" = "5994bed018fdf38d4913b5b166dd5a662d9cf919" \
  || { echo "WRONG COMMIT — abort"; exit 1; }

# ratified immutable venue-input pins (values from the ratified PIN-PROPOSAL, NOT invented here)
export BASE_IMAGE=...            # immutable base image ref
export BASE_DIGEST=sha256:...    # per-arch base manifest digest (use this host's arch)
export APT_SNAPSHOT=...          # pinned OS package snapshot
export RUSTUP_INIT_SHA256=...    # Rust 1.88.0 installer checksum for THIS arch
export SP1_TOOL_IDENTITY=...     # path to the ratified SP1 tool-identity metadata
export RISC0_TOOL_IDENTITY=...   # path to the ratified RISC Zero tool-identity metadata
```

## 2. Produce each architecture's sealed bundle (on its own native host)

The producer runs Stage 0 gates, two clean OCI builds per candidate, in-container lock
resolution, **in-container Stage-2 generation** (`cargo metadata` + `cargo audit` typed +
audited + bound), verifier-material extraction, tool-identity binding, and **in-container
Stage-5 generation** (genuine verifier fixture + the five required mutations, `overall_pass`
derived), then seals + typed-imports the bundle. Disk telemetry (free/peak/final) is written
to `<evidence>.work/disk-telemetry.tsv`, and each large stage is refused if its estimated
headroom is unavailable.

```sh
# on HOST_X64 (x86_64 — carries RISC Zero material + both Stage-5 results):
bash tools/b0-pre-candidates/scripts/run_authoritative.sh produce-arch x86_64 /run/b0pre/ev-x64

# on HOST_ARM (aarch64 — SP1 only; NEVER RISC Zero):
bash tools/b0-pre-candidates/scripts/run_authoritative.sh produce-arch aarch64 /run/b0pre/ev-arm
```

Each ends with `per-arch bundle READY ... sealed + import-verified`. The evidence
directory contains exactly `required_files(arch)` plus its `arch-evidence-manifest.json`.

## 3. Collect both sealed bundles onto one host (unmodified)

Copy the ARM bundle to HOST_X64 (or both to a third aggregation host) **without touching
its bytes** — the manifest hashes are re-verified on import, so any modification is caught.

```sh
# from HOST_X64, pull the arm bundle over SSH (tar preserves bytes; no re-encoding):
ssh HOST_ARM 'tar -C /run/b0pre -cf - ev-arm' | tar -C /run/b0pre -xf -
```

## 4. Independently import-verify each returned bundle

```sh
bash tools/b0-pre-candidates/scripts/run_authoritative.sh import-verify /run/b0pre/ev-x64
bash tools/b0-pre-candidates/scripts/run_authoritative.sh import-verify /run/b0pre/ev-arm
```

Both must report `import-verified` (every hash recomputed, every typed record bound).

## 5. Aggregate + assemble + ingest (one host)

```sh
bash tools/b0-pre-candidates/scripts/run_authoritative.sh \
  aggregate /run/b0pre/ev-x64 /run/b0pre/ev-arm /run/b0pre/work
```

This import-verifies both sealed bundles again, runs `aggregate-bundles` (every Stage-6
input sourced from the typed records — no directory copy), then `stage6-assemble` →
`stage1-ingest`, writing the temporary finalizable artifact to
`/run/b0pre/work/b0-pre-protocol-v1.finalizable.json`. **It never writes the real
`.hash`, never touches the committed normative artifact, and never mutates `main`.**

## 6. Independent verification before any Stage-1 evidence PR

Before proposing any Stage-1 evidence upstream (VENUE.md §6):

1. Re-run steps 4–5 on a **second, independent** operator host from the same commit;
   the `bundle_content_hash` of each per-arch bundle and the aggregate outputs must match
   bit-for-bit.
2. Confirm the committed artifact upstream is still `not_finalizable` and no `.hash`
   exists.
3. Record each per-arch bundle's `source_commit` = `5994bed018fdf38d4913b5b166dd5a662d9cf919`
   in the evidence set.
4. Retain only the committable set (VENUE.md §7): locks, canonical verifier-material
   artifacts, minimal fixtures, hashes, provenance, telemetry — never caches / `target/`
   / OCI layers / proof blobs.

## 7. Teardown

Destroy the temporary hosts. Nothing authoritative persists on them; the evidence set is
the only retained output, pending independent review and owner ratification.

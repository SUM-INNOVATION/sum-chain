# B0-PRE authoritative venue runbook (provider-neutral, two-host)

This runbook drives the authoritative Stage-1 resolution over **two operator-controlled
native Linux hosts** using only SSH + the scripts in `tools/b0-pre-candidates/scripts`.
It is **provider-neutral**: identical commands run on AWS EC2, Azure VMs, or any native
Linux machine. It does **not** provision infrastructure (no Terraform, no cloud API
calls) — you bring two hosts, this runbook uses them.

> The workflow binds to a single **ratified source commit**, supplied out-of-band as
> `RATIFIED_SOURCE_COMMIT` from the same owner-ratified record as the venue-input pins
> (see `PIN-PROPOSAL.md` §Ratification). It is deliberately **not** hard-coded here: a
> runbook cannot authoritatively pin the very commit that must already contain it, and a
> hard-coded hash goes stale the moment the pipeline is corrected. Both hosts export the
> **same** value, so both bind the same commit; each bundle records that commit as its
> `source_commit`, and any mismatch fails closed (VENUE.md §4). The ratified commit MUST
> be one whose tree already carries this complete venue pipeline (this runbook, the
> official guests, and `scripts/`). Nothing here commits, pushes, computes the real
> `b0_pre_spec_hash`, or mutates `main`.

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
# The ratified source commit comes from the owner-ratified record (NOT invented here),
# supplied alongside the pins below and IDENTICAL on both hosts. It must be a commit
# whose tree already carries this complete venue pipeline (runbook + official guests +
# scripts) — e.g. the ratified `main` merge commit.
export RATIFIED_SOURCE_COMMIT=...   # from the ratified record; same value on HOST_X64 and HOST_ARM

# clone, check out THAT commit, and refuse to proceed unless HEAD matches it AND the
# checked-out tree actually contains the pipeline (fail closed on either).
git clone https://github.com/SUM-INNOVATION/sum-chain.git
cd sum-chain
[ -n "${RATIFIED_SOURCE_COMMIT:-}" ] || { echo "RATIFIED_SOURCE_COMMIT unset (owner-ratified) — abort"; exit 1; }
git checkout "$RATIFIED_SOURCE_COMMIT"
test "$(git rev-parse HEAD)" = "$RATIFIED_SOURCE_COMMIT" \
  || { echo "WRONG COMMIT — abort"; exit 1; }
test -f tools/b0-pre-candidates/scripts/run_authoritative.sh \
  || { echo "ratified commit lacks the venue pipeline — abort"; exit 1; }

# ratified immutable venue-input pins (values from the ratified PIN-PROPOSAL, NOT invented here)

# --- identical on BOTH hosts ---
export BASE_IMAGE=...                      # immutable base image ref
export APT_DEBIAN_URL=...                  # pinned immutable snapshot base URL, trailing '/'
export APT_DEBIAN_INRELEASE_SHA256=...     # expected sha256 of its bookworm InRelease
export APT_SECURITY_URL=...                # pinned immutable debian-security snapshot base URL
export APT_SECURITY_INRELEASE_SHA256=...   # expected sha256 of its bookworm-security InRelease

# --- THIS host's architecture only ---
export BASE_DIGEST=sha256:...              # per-arch base manifest digest, a child of the pinned index
export RUSTUP_INIT_URL=...                 # EXACT immutable rustup archive URL for THIS arch
export RUSTUP_INIT_SHA256=...              # sha256 of that exact artifact

# --- tool identities: ONE file per (candidate, architecture) ---
# Each file declares the arch it is for; the producer selects it only after the native-arch
# gate passes and refuses a file whose declared arch is not this host's, so a swapped or
# cross-architecture identity fails before any download, build, or evidence.
export SP1_TOOL_IDENTITY_X86_64=...        # on HOST_X64
export SP1_TOOL_IDENTITY_AARCH64=...       # on HOST_ARM
export RISC0_TOOL_IDENTITY_X86_64=...      # HOST_X64 ONLY — RISC Zero is native-x86_64-only
```

> **Architecture acceptance contract (aarch64 RISC Zero).** There is no
> `RISC0_TOOL_IDENTITY_AARCH64`, and that is correct rather than a gap: VENUE.md §2 keeps
> Groth16 / `stark2snark` / verifier-material extraction native-x86_64-only, and upstream
> publishes no aarch64-linux RISC Zero artifact. The validator's `required_files()` matches
> that policy — an **x86_64** bundle must carry the RISC Zero material
> (`risc0-verifier-material.json`, `Risc0.stage5-result.json`, `Risc0.tool-binding.json`)
> and an **aarch64** bundle must not carry any of it. `tool_identities.sh` skips RISC Zero
> on aarch64 rather than binding x86_64 bytes as aarch64 evidence, which the former
> single-variable contract would have done. Both candidates still contribute their
> container and dependency-graph records on both architectures; those need the pinned
> builder image, not a RISC Zero prover.

## 1b. Preflight before spending venue time (off-venue safe, read-only)

Before the (credit-consuming) native run, confirm the pipeline is READY to target the
OFFICIAL candidate guests. This is off-venue safe and fabricates nothing — it verifies
the official-guest wiring, the container-context staging, the `not_finalizable`
protocol boundary, and that the authoritative producers fail closed off-venue, then
prints exactly which prove/measure stages remain venue/credit-gated:

```sh
bash tools/b0-pre-candidates/scripts/preflight_venue.sh          # fast structural checks
bash tools/b0-pre-candidates/scripts/preflight_venue.sh --deep   # + cargo offline proofs
```

Expect `LOCAL PREFLIGHT PASS` — every venue-independent (non-proving, non-credit)
readiness check passed. On a real venue
host the fail-closed sub-check is skipped (the authoritative run is available there and
must not be launched by the preflight); the readiness assertions still apply.

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

`import-verify` is an **internal** check: it recomputes every file hash and re-binds
every typed record, and deliberately does **not** require the ratified `pins.env` /
`RATIFIED_SOURCE_COMMIT`, so any reviewer can run it on a returned bundle without holding
the out-of-band ratification record. A clean `import-verify` means the bundle is
internally consistent; it does **not** make the bundle eligible for aggregation or
selection. The ratified-commit authority — both bundles must report the **same**
`RATIFIED_SOURCE_COMMIT` — is enforced at `aggregate` (Step 5), the boundary where
bundles become eligible to feed Stage-6 / selection.

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
3. Record each per-arch bundle's `source_commit` = `$RATIFIED_SOURCE_COMMIT` in the
   evidence set; both hosts must record the same ratified commit. `run_authoritative.sh`
   binds it from `git rev-parse HEAD`, and independent import-verify re-reads it, so a
   diverging host is caught on aggregation.
4. Retain only the committable set (VENUE.md §7): locks, canonical verifier-material
   artifacts, minimal fixtures, hashes, provenance, telemetry — never caches / `target/`
   / OCI layers / proof blobs.

## 7. Teardown

Destroy the temporary hosts. Nothing authoritative persists on them; the evidence set is
the only retained output, pending independent review and owner ratification.

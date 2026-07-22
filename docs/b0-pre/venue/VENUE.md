# B0-PRE authoritative execution-venue contract

Authoritative resolution of the three Stage-1 categories
(`candidate_container_digests`, `cargo_lock_hashes`, `verifier_material_manifests`)
is valid **only** when produced by a venue meeting every requirement below. Any
output produced outside this contract is non-authoritative and must never enter
`b0_pre_spec_hash`.

## 1. Builders

- **Native Linux x86_64 builder** — no emulation.
- **Native Linux arm64 builder** — no emulation.
- Both builders OCI-capable, producing **content-addressed** manifest/index
  outputs (exported OCI image layout on disk; no registry push).
- Rust **1.88.0** installed **inside** the builder images (verified by exact
  release + checksum), never assumed present on the host.
- Network access to the pinned package registry/index and to immutable
  base-image digests only.
- No production credentials or secrets present in the environment.
- Clean, ephemeral workspaces per run; ≥ **100 GB** free ephemeral storage
  recommended per builder.
- **Two** clean builds per candidate per architecture, with all content digests
  compared; any mismatch is a hard failure.
- `b3sum` and `python3` present on the builder (used by `build_container.sh` /
  `aggregate_stage6_inputs.sh` to hash build evidence and serialize the Stage-6
  inputs); `build_container.sh` is fail-closed if `b3sum` is missing.

## 2. Architecture rule (non-negotiable)

RISC Zero Groth16 receipt generation (`stark2snark` / `shrink_wrap`) and all
verifier-material extraction **must run natively on x86_64**. Emulated (QEMU /
Rosetta / buildx cross-platform) results are **ineligible** and must be rejected,
not recorded. arm64-only evidence is incomplete and does not resolve the
category.

Because no single host satisfies both architectures, the run is split into a
per-architecture **producer** (`run_authoritative.sh produce-arch <arch>`), an
independent **import verification** of each returned per-arch bundle
(`import-verify`), and a cross-architecture **aggregation** (`aggregate`) that
assembles the full `AUTHORITATIVE_STAGE1` bundle ONLY after BOTH per-arch bundles
pass — sourcing RISC Zero material from the x86_64 bundle. A per-arch producer emits
only that arch's evidence; the aarch64 producer never attempts RISC Zero, and an
aarch64 bundle carrying RISC Zero material is refused on import.

## 3. What the venue produces (and only the venue)

1. Candidate `Cargo.lock` files, resolved **inside** the pinned container, that
   are the full transitive source of truth.
2. `candidate_dep_lock_hash` per candidate, via the frozen
   `SUMCHAIN/B0PRE/CARGOLOCK/v1`-prefixed BLAKE3 rule, over the
   container-generated lock.
3. Base + per-architecture builder OCI digests (full sha256 manifest/index
   digests + media types). The **builder** is reproduced by TWO independent clean
   builds (independent empty cache scopes), compared by their **OCI manifest
   content address** (parsed from the exported layout's `index.json`, never a hash
   of the exported tar). The **base is an immutable INPUT**, not a built image: it
   is resolved by pull-by-digest (`BASE_DIGEST` is preregistered), so its recorded
   identity IS the pinned base digest and its provenance is the base-resolution
   command/output — distinct from, and never a copy of, the builder's two-build
   evidence.
4. `VerifierMaterialManifestV1` per candidate, from deterministic extraction of
   the immutable non-code material actually consumed by the pinned terminal
   verifier, proven by an executable contract fixture that is
   `TEST_ONLY / NON_SELECTION / INVALID_FOR_R0 / NOT_AN_OFFICIAL_GUEST`.
5. Complete tool identities per candidate: for each proof tool, its name, version,
   immutable artifact identity or URL, checksum algorithm, full checksum, and
   installation command / entrypoint. A version string alone does not preregister
   the executable bytes; **authoritative assembly is fail-closed on any absent or
   synthetic tool-identity value** and never invents an installer URL/checksum.

### Digest representation (one coherent form)

- OCI / base / builder **manifest identities** are full `sha256:<64hex>` digests
  (matching `lib.sh` `require_full_sha256_digest` and `BASE_DIGEST`); the `sha256:`
  algorithm prefix is never stripped.
- Raw BLAKE3 / SHA-256 fields — command-log, raw-output, lock, and material hashes,
  each named `*_hex` — are bare 64-hex (the algorithm is named in the field).

### Bundle classification (finalization boundary)

Every Stage-1 result bundle carries a REQUIRED classification. Only
`AUTHORITATIVE_STAGE1` — produced solely from complete real venue inputs — reaches
`stage1-ingest` and can build a finalizable artifact. `TEST_ONLY` / `NON_SELECTION`
bundles are validated but REFUSED by authoritative ingest, so no synthetic-input
bundle ever reaches finalization. There is no shippable command that mints an
`AUTHORITATIVE_STAGE1` bundle from synthetic data.

## 4. Completeness / refusal

The orchestration refuses **partial** insertion. A candidate is either complete
and reproducible across all three categories or the normative artifact stays
`not_finalizable`. If any pinned candidate cannot resolve securely or
reproducibly, or its immutable verifier material cannot be extracted and verified
natively, the run stops and records an **evidence-backed ineligibility finding**;
it must not invent a replacement version, a placeholder digest, or synthetic
material.

## 5. Version / audit policy

The **stable-only rule binds the selected candidate release**, not its whole
transitive graph:

- **Fatal** (candidate ineligible): the selected release is not the pinned stable
  version (`sp1 = 6.3.1`, `risc0-zkvm/build = 3.0.5`, `risc0-groth16 = 3.0.4`,
  `risc0-zkvm-platform = 2.2.2`); an unexpected `git`/`path` source on a
  proof-stack crate; duplicate *incompatible* proof-stack versions; an unresolved
  security advisory; a license outside the allow-list.
- **Recorded, not auto-fatal**: transitive **prerelease** crates. SP1's Plonky3
  `p3-*` stack resolves to prerelease versions; this is expected and does not by
  itself invalidate stable SP1 6.3.1. Every such crate is enumerated and passes
  through the security / source / reproducibility gates at the venue.

The non-authoritative host probe recorded ~19 `p3-*` prereleases for SP1 and none
for RISC Zero; the venue re-audits the in-container graph authoritatively.

## 6. Partner / external-venue handoff

An R0 execution partner (e.g. a third-party prover) may contribute evidence only
under these conditions, and only after separate authorization:

- The uncommitted working tree is **not** exposed before the B0-PRE PR merges.
- No source is transmitted until a native arm64 Linux venue is confirmed
  (independently — do not assume any single partner provides both architectures)
  **and** a content-addressed source handoff bundle is prepared and separately
  authorized.
- An x86_64-only partner can contribute at most **one half** of the architecture
  matrix; emulated arm64/x86_64 runs are ineligible and cannot close R0.
- Returned artifacts (exact `Cargo.lock`, raw proof/receipt files, verifier
  material, command logs, machine-readable samples, OCI digests, provenance) must
  pass **local independent verification** before any Stage-1 input is accepted.
  Aggregate metrics alone are never sufficient.
- Anything run before `b0_pre_spec_hash` is finalized is NON_SELECTION /
  INVALID_FOR_B0 and is not selection evidence.

## 7. Excluded from the committable set

Build caches, `target/` directories, downloaded SDK archives, OCI layers, proof
blobs, and scratch data are never committed. Only Dockerfiles, manifests,
venue-generated locks, canonical verifier-material artifacts, minimal TEST_ONLY
contract fixtures (when required), hashes, and reproducibility metadata are
retained.

## 8. Contributor-resource policy (device-neutral)

This contract governs *how* the paired benchmark is run, not *who* may
contribute. OmniNode participation has **no hardware eligibility**: no minimum
CPU, RAM, GPU, storage, or device class determines whether a contributor is
protocol-eligible. A valid proof from any device is eligible; a slower device
only takes longer. Prover time, peak RAM, configured/physical cores, device
architecture, GPU use, storage usage, and timing variance are **reported-only**
metrics recorded in provenance — they never gate qualification, candidate
selection, or the B0-FINAL tie-break. (This is a preregistration correction:
the former `>= 16`-core / `>= 64`-GiB / 35%-cap proving-resource gate is removed.)

- **Benchmark fairness** comes from running *both* candidates under identical
  controlled conditions on the same physical host per architecture (same cpuset,
  memory limit, governor, isolation, workload, warmup, and iteration policy) and
  recording all configured/detected resources — not from excluding weaker devices
  or requiring a particular absolute host size.
- The **35% resource budget** is a recommended *default local operating policy* an
  operator may configure for their device. It is not consensus, proof validity,
  candidate selection, or hardware eligibility.
- The **prove watchdog** is a run-management timeout only. A timeout produces an
  incomplete run requiring continuation/retry; it is not a candidate performance
  failure or a disqualification.
- **Validators** have no hardware-class eligibility either: qualification is
  performance-based, not device-based, with no minimum CPU or RAM to participate.
  The controlled chain-verification reference envelope is a configured 2-core
  cpuset and 4-GiB memory limit (detected host hardware need only be sufficient to
  establish those limits, and is never gated), under which the candidate gates are
  worst-architecture verify p99 `<= 75 ms` and aggregate verification
  `<= 300 ms/block`. A validator whose machine cannot keep that pace has an
  operational-liveness condition, not a consensus or proof-system disqualification.

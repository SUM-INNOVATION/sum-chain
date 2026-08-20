# Runner path-independence — venue real-embed §G proof

The canonical runner-build recipe makes the runner byte-identical regardless of where the operator's
checkout lives by **materializing the source at one ratified canonical build path (`/b0/tooling`) and
compiling it THERE** — not by remapping the source. This is required because rustc's package
`-Cmetadata`/StableCrateId encodes the absolute source path into symbol mangling, and
`rustc --remap-path-prefix` rewrites compiler-visible source *locations* only (debuginfo, panic strings),
NOT that metadata hash; so two builds at different source paths are NOT byte-identical, but two builds at
the *same* canonical path are. Only `CARGO_HOME`→`/b0/cargo` and `CARGO_TARGET_DIR`→`/b0/target` are
remapped (two `--remap-path-prefix` args, via `CARGO_ENCODED_RUSTFLAGS`, unit-separator delimited),
enforced by the transparent, output-neutral `b0_rustc_remap_wrapper.sh`, as defense-in-depth against a
future debuginfo/`OUT_DIR` leak and to prove `CARGO_HOME`/target independence.

`tools/b0-pre-candidates/scripts/double_build_runner.sh` builds the runner TWICE from clean, from two
GENUINELY-DISTINCT original checkout roots, BOTH materialized at `/b0/tooling`, with two distinct
`CARGO_HOME`/target roots, and requires the two runner binaries — and, for RISC Zero, the two embedded
guests — byte-identical. The distinct original roots never reach the compiler; they are retained as
provenance + leakage-refused and proven not to affect the bytes. It retains the exact bytes (argv vector,
env, canonical build path, per-build `CARGO_ENCODED_RUSTFLAGS`, exact per-invocation `--remap-path-prefix`
argv, A/B runner sha256+blake3, RISC0 guest image id + canonical `methods.rs` digest, cross-bound leakage
roots) that the validator + independent verifier re-prove at sealed import.

> Cross-venue identity note: because the runner identity depends on the absolute *build* path (via the
> metadata hash), every venue MUST build at the identical ratified literal `/b0/tooling`. The validator
> pins `canonical_build_path == /b0/tooling`; a build at any other path is refused.

### Securing + authenticating the shared materialization boundary

`/b0/tooling` is a shared, mutable path, so `double_build_runner.sh` hardens it:

- **Pinned (literal).** `--canonical-build-path` must be the exact literal `/b0/tooling` (a pure-string
  gate before any filesystem work), and — under the lock, before any deletion — `/b0` and `/b0/tooling`
  must be real directories, not symlinks or aliases (`readlink -f` must resolve to themselves).
- **Locked (exclusive).** A fixed non-blocking `flock` on `/b0/.b0-tooling.lock` is acquired before the
  first canonical-path filesystem check/mutation and held through cleanup after build B. A second
  concurrent candidate/operator run is refused immediately — it never waits silently.
- **Authenticated (manifests).** Each build's ORIGIN checkout and its MATERIALIZED copy at `/b0/tooling`
  are hashed into a full-build-input manifest (every file's relpath/mode/size/content-hash; symlinks,
  devices, sockets, FIFOs, control chars and `..` traversal are refused; covers Cargo manifests/locks
  and everything outside the 164-file tooling set). The run requires and BINDS
  `origin_A == materialized_A == origin_B == materialized_B` into the double-build proof, so both import
  verifiers re-enforce it. A stale/mutated file left at the canonical path is removed by the fresh
  per-build `rm -rf`+`cp -Rp` and, if it somehow survived, would fail the materialized-manifest check.
- **Fail-hard cleanup.** A failure to remove the canonical source FAILS the run (never leaves
  authoritative source behind while reporting success), preserving the diagnostics/evidence written
  outside `/b0/tooling`.

Provision `/b0` writable once (`sudo mkdir -p /b0 && sudo chown "$(id -un)" /b0`) before running.

## Where each part is proven

| Proof | Where | What runs |
|---|---|---|
| Recipe mechanism (byte-identical across distinct original roots at the canonical path; leakage) | CI | `double_build_runner.sh` materializes two `git archive` roots at `/b0/tooling` |
| Runner CRATE + full SDK closure path-independence (real-backend, **stub** embed) | CI `b0-pre.yml` | `double_build_runner.sh --candidate risc0 --embed 0 --canonical-build-path /b0/tooling` |
| `methods.rs` canonicalization (§G) | Unit test | byte-identical canonical `methods.rs` across path-distinct `OUT_DIR`s |
| **REAL RISC Zero guest embed** (`B0_VENUE_EMBED=1`) | **VENUE only (this runbook)** | `double_build_runner.sh --candidate risc0 --embed 1 --risc0-home <pinned>` |

The real guest embed needs the **pinned venue RISC Zero guest toolchain** (`PROVER_RISC0_HOME`), which is
NOT available in CI (owner decision B: no `rzup` / no guest-builder image / no network for the embed; the
guest RISC-V rust toolchain is not a pinned archive). CI therefore proves everything EXCEPT the real
embed with the honest stub, and the real embed is proven here.

## Venue procedure (x86_64 only; RISC Zero is native-x86-only)

Run from a clean ratified checkout, with the pinned RISC Zero toolchain provisioned at `$PROVER_RISC0_HOME`.

```bash
SCRIPTS=tools/b0-pre-candidates/scripts
. "$SCRIPTS/lib.sh"
# Two GENUINELY-DISTINCT original checkout roots (identical content, different absolute paths). /b0 must
# be writable: the script materializes each checkout at the canonical build path /b0/tooling and builds
# there (this is what makes the runner path-independent — see the metadata-hash note above).
sudo mkdir -p /b0-input/a /b0-input/b /b0-build /b0 && sudo chown "$(id -un)" /b0-input/a /b0-input/b /b0-build /b0
git archive HEAD | tar -x -C /b0-input/a
git archive HEAD | tar -x -C /b0-input/b

# ONE disclosed network PROVISIONING phase (this is the runner toolchain + offline-seed correction): the
# exact committed dependency GRAPH SET (RISC0 = host runner lock + candidate WORKSPACE lock the guest is
# built against) and the NATIVE host-toolchain attestation (x86 = 1.90.0). Everything after is OFFLINE.
b0_runner_dependency_seed risc0 1.90.0 "$PWD" /b0-build/seeds /b0-build/dep-seed.json
b0_host_toolchain_attestation 1.90.0 x86_64 /b0-build/host-tc.json

bash "$SCRIPTS/double_build_runner.sh" \
  --candidate risc0 --manifest tools/b0-pre-measure-risc0/Cargo.toml \
  --artifact release/b0-pre-measure-risc0 --embed 1 --risc0-home "$PROVER_RISC0_HOME" \
  --toolchain 1.90.0 \
  --src-a /b0-input/a --src-b /b0-input/b --root-a /b0-build/a --root-b /b0-build/b \
  --canonical-build-path /b0/tooling --guest-home /b0/guesthome \
  --arch x86_64 --expect-build-git-sha 507281e21e95a6a98e3480e25e12d1baab586e07 \
  --wrapper "$SCRIPTS/b0_rustc_remap_wrapper.sh" \
  --per-arch-toolchain-identity "$RISC0_PER_ARCH_TOOLCHAIN_IDENTITY" \
  --dep-seed-dir /b0-build/seeds --dep-seed-json /b0-build/dep-seed.json \
  --host-toolchain-attestation /b0-build/host-tc.json \
  --recipe-out /b0-build/recipe.risc0.x86_64.json
```

`--toolchain 1.90.0` is MANDATORY (the 1.85 rust-toolchain floor cannot resolve the runner lock; the
ratified per-arch native toolchain is x86 = 1.90.0, ARM = 1.88.0). The build is OFFLINE: `--offline` +
`CARGO_NET_OFFLINE=true`, every dependency materialized from `--dep-seed-dir` (host graph → each build's
`CARGO_HOME`; the RISC0 guest workspace graph → the pinned canonical `--guest-home /b0/guesthome`, because
`risc0_build` strips every `CARGO*` env from the guest sub-build and it can only be forced onto the
controlled seed via `HOME`). `--embed 1` runs `risc0_build::embed_methods()` (build.rs) with the pinned
toolchain and the §G `methods.rs` canonicalization (the guest ELF is COPIED into `OUT_DIR` and every
build-specific path stripped; `RISC0_BUILD_LOCKED=1`). The script fails closed unless BOTH clean builds
are byte-identical AND the embedded guest image id + guest ELF + canonical `methods.rs` are identical
across build A and build B. It emits the retained recipe facts JSON (now also binding the dependency-seed
+ host-toolchain + (SP1) protoc authority addresses), which the venue runner splices into each provenance
role and the validator/independent verifiers re-prove at sealed import.

### SP1 (both arches; ARM = aarch64/1.88.0)

SP1 is the same flow with `--candidate sp1 --toolchain <1.90.0|1.88.0> --embed 0` (no guest embed, so no
`--guest-home`/`--risc0-home`) and the native protoc authority, since the SP1 SDK (prost-build) needs a
`protoc` + the committed protobuf include-authority. The SP1 dependency seed is TWO graphs unioned into
one host unit (the main runner lock + the checksum-bound nested `sp1-core-executor-runner` lock, whose
`build.rs` runs a nested inner-binary build):

```bash
b0_runner_dependency_seed sp1 1.88.0 "$PWD" /b0-build/seeds-sp1 /b0-build/dep-seed.sp1.json
b0_host_toolchain_attestation 1.88.0 aarch64 /b0-build/host-tc.sp1.json
b0_protoc_authority sp1 aarch64 "$VENUE_PROTOC" "$PROTOC_INCLUDE_AUTHORITY" /b0-build/protoc-auth.json
bash "$SCRIPTS/double_build_runner.sh" --candidate sp1 --manifest tools/b0-pre-measure-sp1/Cargo.toml \
  --artifact release/b0-pre-measure-sp1 --embed 0 --toolchain 1.88.0 --arch aarch64 \
  --src-a /b0-input/a --src-b /b0-input/b --root-a /b0-build/a --root-b /b0-build/b \
  --canonical-build-path /b0/tooling --expect-build-git-sha <RATIFIED_SOURCE_COMMIT> \
  --wrapper "$SCRIPTS/b0_rustc_remap_wrapper.sh" --per-arch-toolchain-identity "$SP1_PER_ARCH_TOOLCHAIN_IDENTITY" \
  --dep-seed-dir /b0-build/seeds-sp1 --dep-seed-json /b0-build/dep-seed.sp1.json \
  --host-toolchain-attestation /b0-build/host-tc.sp1.json \
  --protoc "$VENUE_PROTOC" --protoc-include "$PROTOC_INCLUDE_AUTHORITY" --protoc-authority /b0-build/protoc-auth.json \
  --recipe-out /b0-build/recipe.sp1.aarch64.json
```

The nested `sp1-core-executor-runner` build strips `CARGO_ENCODED_RUSTFLAGS` (its own comment: to avoid
cross-compilation issues), so its compiles into `<target>/sp1-native-bins` carry no `--remap-path-prefix`;
the wrapper records them `kind=nested` and does not remap-enforce them (they are path-independent by
construction — VENUE-PROVEN byte-identical across the two path-distinct builds).

The `per_arch_toolchain_identity` is bound SEPARATELY from the cross-arch structural recipe id (which is
identical for SP1/x86, SP1/aarch64, RISC0/x86 and names only the RULE "use the ratified per-arch
toolchain", never a digest).

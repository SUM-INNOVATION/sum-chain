# Stage 1 release artifact — merged `main` @ `8954b0d0ace726ab9491cac8a7757f11158c3d1a`

This records what the release candidate for Stage 1 is, what CI did and did not
produce for it, and how anyone can re-derive every value here without trusting
this file. Every field has the command that re-derives it. Investigation date:
2026-09-23.

**Summary: CI produced no deployable artifact for this commit.** No release
binary was uploaded, no container image was pushed, and nothing is signed or
attested. The only release-profile build CI ran (inside `health-e2e`) used
**rustc 1.85**, not the pinned 1.88.0. Its image existed only on the runner
and was discarded when the job ended. The node binary cannot report its commit
(`GIT_HASH` is never set, so it prints `Commit: unknown`), so operators must
record the binary by its SHA-256.

## 1. Identity of the candidate

| field | value | re-derive |
|---|---|---|
| commit | `8954b0d0ace726ab9491cac8a7757f11158c3d1a` | `git ls-remote origin refs/heads/main refs/heads/lane-a/final` (both return this SHA) |
| `Cargo.lock` sha256 | `c78c4039b75af095506afa759e215e0e6355cbbe94cfef8f5fe2070c31fcaab4` | `git show 8954b0d0ace726ab9491cac8a7757f11158c3d1a:Cargo.lock \| shasum -a 256` |
| `Cargo.lock` git blob | `48a7fd826911a7e8395303de9c9de031261a1048` | `git rev-parse 8954b0d0ace726ab9491cac8a7757f11158c3d1a:Cargo.lock` |
| workspace / node version | `0.4.0` (this is what `node_info.version` and `/health` report) | `git show 8954b0d0ace726ab9491cac8a7757f11158c3d1a:Cargo.toml \| sed -n '/^\[workspace.package\]/,/^version/p'` |
| pinned toolchain | `1.88.0` | `git show 8954b0d0ace726ab9491cac8a7757f11158c3d1a:rust-toolchain.toml` |
| node binary | package `sumchain-node`, bin `sumchain` (installed at `/usr/local/bin/sumchain` by the `Dockerfile`) | `grep -A2 '^\[\[bin\]\]' crates/node/Cargo.toml`; `grep 'usr/local/bin' Dockerfile` |

## 2. CI runs for this SHA

All six runs concluded `success`. The merge was a fast-forward, so the PR runs
on `lane-a/final` and the push runs on `main` are for the same tree.

| run id | workflow | event / branch | jobs | uploaded artifacts |
|---|---|---|---|---|
| 35553211824 | Rust CI | push / main | build-test-clippy, build-test-clippy-aarch64, supply-chain-audit | **none** |
| 35553211836 | health-e2e | push / main | devnet health/readiness E2E | `health-e2e-evidence` (1031 B text log, expires 2026-12-20) |
| 35553211834 | B0-PRE tools | push / main | b0-pre | **none** |
| 35551601837 | Rust CI | pull_request / lane-a/final | same three | **none** |
| 35551601868 | health-e2e | pull_request / lane-a/final | E2E | `health-e2e-evidence` (1033 B text log) |
| 35551601917 | B0-PRE tools | pull_request / lane-a/final | b0-pre | **none** |
| — | Publish sumchain-wire | — | — | **never run** (no runs exist for this workflow) |

Re-derive:

```bash
gh run list -R SUM-INNOVATION/sum-chain --commit 8954b0d0ace726ab9491cac8a7757f11158c3d1a \
  --json databaseId,workflowName,event,headBranch,conclusion
for id in 35553211824 35553211836 35553211834 35551601837 35551601868 35551601917; do
  gh api repos/SUM-INNOVATION/sum-chain/actions/runs/$id/artifacts \
    --jq '"\(.total_count) \([.artifacts[].name])"'
done
gh run list -R SUM-INNOVATION/sum-chain --workflow publish-wire.yml   # empty
```

### What each workflow builds (from the YAML, not the job names)

* **`rust-ci.yml`**: `cargo build --workspace --locked`, `cargo test --workspace --locked`
  and `cargo clippy --workspace --tests --locked` on x86_64 (`ubuntu-latest`)
  and aarch64 (`ubuntu-24.04-arm`). This is the **`dev` profile**
  (the logs say `Finished \`dev\` profile [unoptimized + debuginfo]`). It has
  no upload step. `Swatinem/rust-cache` saves `target/` to the Actions
  **cache**, which is a build cache and not a release artifact. Result: a debug
  build that was not deployable and was not kept.
* **`health-e2e.yml`**: runs `deploy/health-e2e-harness.sh`, which runs
  `docker compose build` using the repo `Dockerfile`. The Dockerfile runs
  `cargo build --release --bin sumchain --bin sumchain-wallet`. The resulting
  image was tagged locally (`docker.io/library/health-e2e-validator-{1,2,3}`
  and `health-e2e-fullnode`, image ID
  `sha256:409e864987ce57a4958bb8bdc4f8acacbf673e054ef561dc1b2b330713099db8`),
  used for the devnet test, and **never pushed**. There is no `docker push`,
  no registry login and no `docker save` in the workflow or the harness. The
  only uploaded file is the text evidence log. Result: **built and
  discarded**. That image ID is a local config digest. It is not a registry
  manifest digest and nothing can pull it.
* **`b0-pre.yml`**: builds and tests the frozen `tools/b0-pre-*` crates under
  `RUSTUP_TOOLCHAIN=1.85.0`. It does not touch the node.
* **`publish-wire.yml`**: triggers only on a `wire-v*` tag push or a manual
  dispatch (see §5).

Re-derive the build facts from the logs:

```bash
gh api repos/SUM-INNOVATION/sum-chain/actions/jobs/106191724658/logs > x86.log     # build-test-clippy
gh api repos/SUM-INNOVATION/sum-chain/actions/jobs/106191724500/logs > arm.log     # aarch64
gh api repos/SUM-INNOVATION/sum-chain/actions/jobs/106191724363/logs > e2e.log     # health-e2e
grep -E 'rustc [0-9]|Default host|Image: |Finished `' x86.log arm.log
grep -E 'FROM docker.io/library/rust|cargo build --release|Finished `release`|writing image|naming to' e2e.log
grep -nE 'docker (push|save|login)|upload-artifact' .github/workflows/*.yml deploy/health-e2e-harness.sh
```

## 3. Release-candidate fields

| field | value | status |
|---|---|---|
| image tag + registry digest | **none exists** | CI never pushed an image. `deploy/kubernetes/statefulset*.yaml` reference `sumchain/node:latest`, which is a mutable tag. `https://hub.docker.com/v2/repositories/sumchain/node/tags` returns `object not found` publicly. GHCR could not be checked (see §7). |
| binary sha256 | **none exists** | CI uploaded no binary. The only CI release binary was inside the discarded health-e2e image. |
| Rust toolchain, pinned | `1.88.0` (`rust-toolchain.toml`) | verified |
| Rust toolchain, CI `rust-ci` | `rustc 1.88.0 (6b00bc388 2025-06-23)`, `cargo 1.88.0 (873a06493 2025-05-10)` on both arches | verified from the job logs |
| Rust toolchain, CI Docker release build | `rust:1.85-slim-bookworm@sha256:9f841bbe9e7d8e37ceb96ed907265a3a0df7f44e3737d0b100e7907a679acb36`, which is **1.85.x, not 1.88.0** | verified from the e2e log. The Dockerfile does not copy `rust-toolchain.toml`, so rustup never switches. The exact 1.85 patch version was not printed. |
| target architectures | CI compiled and tested `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` (dev profile). The only release build was x86_64 (`linux/amd64` runner). | verified |
| CI build commands | `cargo build --workspace --locked` (rust-ci). In Docker: `cargo build --release --bin sumchain --bin sumchain-wallet` with **no `--locked`**. | verified |
| SBOM | none | no SBOM step in any workflow |
| provenance / attestation | none | no `actions/attest-*`, no SLSA generator, and no `id-token: write` permission in any workflow |
| signature | none | no cosign or GPG signing step. `RELEASE.md` states that artifact signing is not part of the repo. |

Re-derive the "none" rows:

```bash
grep -nE 'attest|cosign|sigstore|sbom|syft|slsa|id-token|docker/build-push|docker push' .github/workflows/*.yml   # no output
```

### Dockerfile gaps (recorded here, not fixed in this round)

1. It builds with `rust:1.85`, while the workspace pins `1.88.0`, and it does
   not copy `rust-toolchain.toml`. As a result the health-e2e image was built
   by a different compiler from the one `rust-ci` tested.
2. The release `cargo build` has no `--locked`. The e2e log shows
   `Updating crates.io index` and no `Locking` line, so the lockfile appears
   to have been honoured in this run, but nothing enforces it.
3. The dependency-cache layer (`cargo build --release --workspace || true`)
   fails every time with `failed to load manifest for workspace member
   /build/crates/sumchain-wire`. The failure is masked by `|| true`. It costs
   build time but does not affect correctness.
4. No `GIT_HASH` build argument exists (see §4).

## 4. Can the binary report its own commit? **No, not as built by CI or the Dockerfile.**

* `crates/node/src/main.rs` defines
  `GIT_HASH = option_env!("GIT_HASH")`, falling back to `"unknown"`. The value
  is printed in the startup banner (`Commit: …`) and in the panic crash report.
* Nothing ever sets `GIT_HASH`. No `build.rs` exists in the node crate, there
  is no `vergen`, the Dockerfile has no `ARG`/`ENV`, and no workflow sets it.
  **Every CI or Dockerfile build therefore logs `Commit: unknown`.**
* The clap `Cli` has no `version` attribute, so `sumchain --version` is not a
  flag. The RPC `node_info.version` and the `/health` `version` return only
  `CARGO_PKG_VERSION` (`0.4.0`). That value is shared by every commit since
  `5444d2ae673fd6500845341d6273c080246f70fb`, so it cannot tell commits apart.
* **Consequence for `activation-rollout-evidence.md` §1:** the SHA-256 of
  the binary file is the **only** identity an operator can record. Build the
  binary with `GIT_HASH` set (below) so the banner at least carries the commit,
  but do not treat the banner as proof. It is a string the builder controls.
* **Path mismatch in that procedure:** §1 and §1.1 hash
  `/usr/local/bin/sumchain-node`, but the `Dockerfile` installs
  `/usr/local/bin/sumchain`. With `set -euo pipefail`, `rollout-record.sh`
  fails at that line against an image built from this Dockerfile. Until that
  document is corrected, use `/usr/local/bin/sumchain`.

Re-derive:

```bash
grep -n 'GIT_HASH' -r crates/ Dockerfile .github/ deploy/ scripts/
find crates/node -name build.rs      # no output
grep -n '#\[command(' crates/node/src/main.rs
grep -n 'usr/local/bin' Dockerfile docs/operations/activation-rollout-evidence.md
```

## 5. `sumchain-wire 0.5.0`: path dependency, no crates.io publish needed

* The root `Cargo.toml` has
  `sumchain-wire = { path = "crates/sumchain-wire", version = "0.5.0" }`.
  `primitives`, `rpc` and `beacon-runtime` consume it via `{ workspace = true }`.
* In `Cargo.lock` the only `sumchain-wire` entry (version `0.5.0`) has **no
  `source` line**, so it resolves to the in-tree path and not to the registry.
* crates.io has `0.1.1` through `0.4.0`. **`0.5.0` is not published, and the
  node build does not need it:** `--locked` resolves it from the workspace.
* `publish-wire.yml` triggers only on `push: tags: wire-v*` or on
  `workflow_dispatch`. A dispatch is a dry run only. No `wire-v*` tag exists
  on the remote and none points at this commit. The workflow has never run.
  The merge did not fire it, and it can fire only if someone pushes a
  `wire-v*` tag.

Re-derive:

```bash
grep -n 'sumchain-wire' Cargo.toml crates/*/Cargo.toml
awk '/^name = "sumchain-wire"/{p=1} p&&/^$/{exit} p' Cargo.lock      # no "source =" line
git ls-remote --tags origin 'wire-v*'                                  # no output
curl -s -H 'User-Agent: verify' https://crates.io/api/v1/crates/sumchain-wire | jq -r '.versions[].num'
```

## 6. Deployed production versus this release

Read-only probes of `https://rpc.sumchain.io` (chain_id 1) on 2026-09-23:

* `chain_getActivationStatus` returns `-32601 Method not found`. This method
  first appears in `crates/rpc/src/api.rs` at
  `de38103325b0b42020220ac99a6051d06bfbf358` (2026-09-17).
* `node_info` returns `"version":"0.2.0"`, `is_validator: true`,
  `peer_count: 1`, `uptime_seconds: 1079141` (about 12.5 days), and
  `current_height: 13241118`.

What this shows: the node behind that endpoint was not built from
`8954b0d`. It lacks the method, and it reports `0.2.0`, while `8954b0d`
reports `0.4.0`. In this repository's history the workspace version was
`0.2.0` from `c51eead1230f5f5e698de359f773b953c11e06f9` (2026-07-09) through
`8abbd3044a3cddca06d4df2d2ef7064339dc5492` (2026-09-01), which is 170
commits. What it does **not** show: which commit is deployed. The deployed
build prints `Commit: unknown` like any other build. It could also come from a
local or unmerged tree. The probe also covers only the one node behind the
load-balanced endpoint.

Re-derive:

```bash
for m in chain_getActivationStatus node_info; do
  curl -s -X POST https://rpc.sumchain.io -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$m\",\"params\":[]}"; echo
done
git log --format='%H %ad %s' --date=short -S chain_getActivationStatus -- crates/rpc/src/api.rs | tail -1
git log --format='%H %s' -L '/^\[workspace.package\]/,+2:Cargo.toml' | grep -E '^[0-9a-f]{40}'
```

## 7. Producing the artifact (operator actions, NOT run in this round)

No CI artifact exists, so the operator builds one. The commands below were
written out but **not executed**. No build and no push was done.

**Binary (reproduces the CI toolchain and lockfile, and embeds the commit):**

```bash
git clone https://github.com/SUM-INNOVATION/sum-chain && cd sum-chain
git checkout --detach 8954b0d0ace726ab9491cac8a7757f11158c3d1a
test "$(git rev-parse HEAD)" = 8954b0d0ace726ab9491cac8a7757f11158c3d1a
test "$(shasum -a 256 Cargo.lock | awk '{print $1}')" = c78c4039b75af095506afa759e215e0e6355cbbe94cfef8f5fe2070c31fcaab4
rustup show active-toolchain          # must be 1.88.0-<host> (from rust-toolchain.toml)
export CXXFLAGS="-include cstdint"    # GCC 13+ RocksDB workaround, as in rust-ci.yml
GIT_HASH=$(git rev-parse HEAD) cargo build --release --locked -p sumchain-node --bin sumchain
sha256sum target/release/sumchain     # record this; it is the rollout identity
```

Build once per target architecture that validators run on (x86_64 and/or
aarch64 Linux). Record one SHA-256 per architecture. Builds are not
guaranteed to be bit-reproducible: nothing in the repo configures
reproducible-build flags. Two operators should therefore compare their hashes
before distributing a binary, not assume the hashes match.

**Container image (the path the Kubernetes manifests use):** the Dockerfile
as committed builds with rustc 1.85, has no `--locked` and sets no
`GIT_HASH` (§3). Building it unchanged gives an image whose compiler differs
from the one CI tested. The owner should decide whether to accept that or fix
the Dockerfile first. The literal commands, with `<REGISTRY>` left for the
owner to choose:

```bash
docker build --platform linux/amd64 \
  -t <REGISTRY>/sumchain/node:8954b0d0ace726ab9491cac8a7757f11158c3d1a .
docker push <REGISTRY>/sumchain/node:8954b0d0ace726ab9491cac8a7757f11158c3d1a   # DO NOT run without owner approval
docker buildx imagetools inspect <REGISTRY>/sumchain/node:8954b0d0ace726ab9491cac8a7757f11158c3d1a \
  --format '{{json .Manifest.Digest}}'                                           # the immutable digest
docker run --rm --entrypoint sha256sum <REGISTRY>/sumchain/node@<digest> /usr/local/bin/sumchain
```

Deploy by `@sha256:<digest>`, not by `:latest`. Record the digest and the
in-container `sha256sum /usr/local/bin/sumchain` for each validator.

## 8. Unresolved

* Whether any image exists in a private registry (GHCR or a private Docker
  Hub repo). `gh` lacks the `read:packages` scope, and the public Docker Hub
  lookup for `sumchain/node` returns not-found.
* The exact commit, image and binary hash of each production validator. Only
  one RPC-facing node was observed, and it reports only `0.2.0`.
* The exact rustc patch version inside `rust:1.85-slim-bookworm@sha256:9f841bbe…`.
  The build log does not print it.

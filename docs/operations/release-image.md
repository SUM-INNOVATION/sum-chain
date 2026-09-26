# Release image: one manifest for Linux amd64 and arm64, verified by digest

The node's release artifact is one multi-platform OCI image index in GHCR:

    ghcr.io/sum-innovation/sum-chain:<40-hex commit>   ->   sha256:<canonical manifest digest>

It holds exactly two runnable images, `linux/amd64` and `linux/arm64`, each
with its BuildKit attestation manifest (an SPDX SBOM and SLSA v1 provenance).
Those attestation manifests carry the platform `unknown/unknown`; they are not
images, and every tool here classifies and checks them separately.

* **Production's CPU architecture does not need to be known** — not to publish,
  not to deploy, not to record evidence. Kubernetes and every OCI container
  runtime pull the child that matches the node's own platform from the one
  canonical manifest.
* **The deployment-facing identity is the canonical manifest digest.** It is
  what a rollout approves, what goes into the StatefulSet
  (`ghcr.io/sum-innovation/sum-chain@sha256:<canonical>`), and what the rollout
  checker is given. The two children are joined into it by digest; no
  per-platform tag exists.
* **The tag is immutable.** The workflow refuses to push a commit tag that
  already exists, and `latest` is never pushed.
* **After start, the rollout evidence proves which child each validator
  pulled** and that it belongs to the approved manifest
  (`tools/lane-b/rollout-check.py --release-record`, §5).
* **Publication is not deployment.** The image stays unusable for the
  production rollout until every production-only check in
  `docs/operations/stage1-local-evidence.md` §5 is complete.

## 1. The workflow (`.github/workflows/release-image.yml`)

Manual only (`workflow_dispatch`), with one input: `commit`, the full 40-hex
commit that is **the head of `main` at dispatch**. There is no platform input.

| job | runs on | permissions | does |
|---|---|---|---|
| `gate` | ubuntu-24.04 | contents, pull-requests: read | Refuses unless dispatched from `main`, the commit equals `GITHUB_SHA` (the head of `main`) and is on `main`, and it is the head or merge result of a merged PR whose head has an APPROVED review. |
| `build` × 2 | ubuntu-24.04 and ubuntu-24.04-arm, **natively** | contents: read, **no registry credential** | `tools/release/build-child.sh`: builds its platform from the pinned Dockerfile with `--locked` and `GIT_HASH`, requires `--version` = the commit and the smoke test (/health, /ready, /metrics), then exports an OCI layout with SBOM and SLSA v1 provenance (builder id = this run). |
| `publish` | ubuntu-24.04, environment **`release`** | contents: read; **packages: write**; id-token, attestations: write | Refuses an existing tag; pushes both layouts **by digest** (no tags) and checks each matches what was built; joins them by digest into the canonical index under the commit tag; reads it back and runs `verify-release.py`; attests the canonical index and both children; verifies all three attestations. |
| `verify` × 2 | ubuntu-24.04 and ubuntu-24.04-arm, natively | contents, packages, attestations: read | Pulls its platform's child **by digest** from GHCR and runs `verify-child-runtime.sh` (--version, /health, /ready, /metrics), requires the binary to hash as built, and re-verifies the index and attestations independently. |
| `record` | ubuntu-24.04 | contents: read | Writes `release-record.txt` and the job summary. |

`publish` is the **only** job with `packages: write`, and it is the only job
in environment `release`, so one approval covers the whole publication. The
long compile runs in `build`, which holds no credential at all.

`gate` requires the commit to be the head of `main` because GitHub's signed
provenance records `GITHUB_SHA` as the source commit. With the two equal, the
signed source commit and the built commit are the same commit.

**Native builds, no emulation.** GitHub-hosted `ubuntu-24.04-arm` runners are
available to this public repository, so arm64 is built and tested on arm64
hardware. No QEMU or binfmt action is used anywhere in the release path
(`tools/release/release-workflow-test.py` checks this).

Third-party actions are pinned by commit sha:

| action | tag | commit |
|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| docker/setup-buildx-action | v4.4.1 | `f87e5991a6d7451dcb8d9637bfbc97413f497069` |
| docker/login-action | v4.6.0 | `dbcb813823bdd20940b903addbd779551569679f` |
| actions/attest-build-provenance | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| actions/download-artifact | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |

Registry traffic in the release path goes through `tools/release/oci.py`,
a standard-library-only client, so no extra binary is trusted inside the
job that holds `packages: write`.

**The Dockerfile is pinned for both platforms.** The builder stage uses
`rust:1.88.0-slim-bookworm@sha256:38bc5a86…` and the runtime stage
`debian:bookworm-slim@sha256:3783cc01…`. Both are multi-platform indexes, so
each platform's build resolves its own child from the same pin. The committed
`Cargo.lock` is restored immediately before the `--locked` release build.
**Limitation:** the `apt-get install` steps in both stages take the current
Debian bookworm packages. They are not pinned to a snapshot; the provenance
records the base-image digests, not the apt package versions.

### The `release` environment (configured 2026-09-25, read back through the API)

- **Required reviewer:** Mike-Mans.
- **Self-review prevented:** whoever dispatches cannot approve their own run.
  Mike-Mans must not be the dispatcher.
- **Deployment branches:** `main` only.
- **Admin bypass:** disabled.
- **Secrets and variables:** none.

Confirm before any dispatch:
`gh api repos/SUM-INNOVATION/sum-chain/environments/release --jq '{can_admins_bypass, rules: [.protection_rules[] | {type, prevent_self_review, reviewers: [.reviewers[]?.reviewer.login]}]}'`

### Permissions the repository needs

| setting | why |
|---|---|
| Actions → Workflow permissions allow `GITHUB_TOKEN` to be granted `packages: write` | The `publish` job pushes to `ghcr.io/sum-innovation/sum-chain` |
| Organization → Packages: members may create container packages | The first push creates the package |
| `id-token: write`, `attestations: write` on `publish` only | GitHub artifact attestations (supported for this public repository) |
| Package visibility, or an `imagePullSecret` in the cluster | A new GHCR package may be private; the cluster must be able to pull it. Changing visibility is a separate decision. |

## 2. What verification requires

### 2a. The canonical index, the children, SBOMs and provenance (`tools/release/verify-release.py`)

```bash
python3 tools/release/verify-release.py --mode release \
  --image ghcr.io/sum-innovation/sum-chain --commit <commit> --digest sha256:<canonical> \
  --child linux/amd64=sha256:<amd64 image> --child linux/arm64=sha256:<arm64 image>
```

Every digest is recomputed from the bytes the registry returns. The rules:
- **Tag:** the tag must be the commit, never `latest`, and must resolve to
  exactly the canonical digest. A moved tag fails.
- **Index shape:** the canonical digest must be an OCI index. Its runnable
  descriptors must be exactly one `linux/amd64` and one `linux/arm64`, equal to
  the child digests this release produced. A missing, duplicate, extra or
  substituted child fails.
- **Attestation manifests:** every other descriptor must be an attestation
  manifest pointing at one of those children, one per child. Nothing
  unclassified may be present.
- **Per child, image:** an OCI image manifest whose config agrees on os and
  architecture and carries `org.opencontainers.image.revision` = the commit.
- **Per child, SBOM:** a valid SPDX 2.x SBOM (document id, namespace,
  creators, named packages) whose in-toto subject is that child.
- **Per child, provenance:** exactly one SLSA v1 provenance about that child.
  It must record:
  - the `dockerfile.v0` frontend and `configSource.path` = `Dockerfile`;
  - `build-arg:GIT_HASH` = the commit;
  - the VCS source (this repository) and revision (the commit);
  - a builder id that is a run of this repository (`--run-url`: this run);
  - every base image the Dockerfile **at the commit** pins by digest, among
    its resolved dependencies. An unpinned `FROM` fails verification.

Mode `release` verifies only `ghcr.io/sum-innovation/sum-chain`. Mode `ci`
verifies only a registry on localhost.

### 2b. Who signed it (`tools/release/verify-attestation.sh`)

```bash
bash tools/release/verify-attestation.sh ghcr.io/sum-innovation/sum-chain sha256:<digest> <commit>
```

Run it for the canonical digest **and** both child digests; the release
workflow attests all three. The policy is read-only constants in the script,
not arguments or environment:

| rule | how |
|---|---|
| subject is the immutable digest | `gh attestation verify oci://<repo>@sha256:<digest>`. A tag, or a reference carrying one, is refused before `gh` runs |
| linked repository | `--repo SUM-INNOVATION/sum-chain` |
| signing workflow **and** the ref it ran from | `--cert-identity https://github.com/SUM-INNOVATION/sum-chain/.github/workflows/release-image.yml@refs/heads/main` (exact) |
| source ref | `--source-ref refs/heads/main` |
| GitHub-hosted runner | `--deny-self-hosted-runners` |
| certificate re-checked on the result | every attestation must carry that exact `subjectAlternativeName` and `buildSignerURI`, `sourceRepositoryRef` `refs/heads/main`, `sourceRepositoryURI` this repository, and name the digest |
| signed provenance re-checked | `buildType` `https://actions.github.io/buildtypes/workflow/v1`; `externalParameters.workflow` = this repository, `.github/workflows/release-image.yml`, `refs/heads/main`; the source `gitCommit` = the release commit |

**Why `--cert-identity` and not `--signer-workflow`:** in gh 2.100.0,
`--signer-workflow` becomes a prefix regular expression with no end anchor
and no ref (`validateSignerWorkflow`, `pkg/cmd/attestation/verify/policy.go`).
So `release-image.yml` would also match `release-image.yml-other.yml` on any
branch. The two flags are mutually exclusive.

### 2c. The running images (`tools/release/verify-child-runtime.sh`)

Pulls one child **by digest** on a runner of its own platform, with no
emulation. Requires the pulled image to be that platform, `--version` to be
`sumchain <commit>`, and the smoke test to pass (`tools/release/smoke-image.sh`):
- `/health` → 200;
- `/ready` → 200 after a block;
- `/metrics` passing `tools/lane-b/wave1-monitor.sh verify`: all nine Wave 1
  subsystems, two bounded labels.

It prints the binary's sha256 for the release record.

### 2d. Threat model: two controls, two different attackers

* **The `release` environment** controls **the approved workflow**. The
  `publish` job cannot run without Mike-Mans's approval, cannot run from
  another branch, and no admin can bypass it.
* **It does not control other workflows.** Anyone with write access can push
  a branch with a *new* workflow that grants itself `packages: write` and
  pushes to the same package. Environment protection covers only jobs that
  name the environment.
* **Consumer-side verification closes that gap.** An image pushed by any
  other workflow has no attestation, or one signed by that workflow or
  branch; §2b rejects both. A rollout takes the canonical digest from a
  release record, and verifies it and both children with §2a and §2b
  before the digest goes into any manifest.
* **Out of scope:** a compromise of `main` itself, such as a malicious change
  to `release-image.yml` that passes review, or of GitHub's signing
  infrastructure.

## 3. The release record

The `record` job writes `release-record.txt` (also in the job summary and the
`release-<commit>` artifact, with the verification summary, both SBOMs and
both runtime results):

```
release_commit:            <40-hex>
pull_request:              #<n>
approved_by:               <login>
workflow_run:              https://github.com/SUM-INNOVATION/sum-chain/actions/runs/<id>
canonical_tag:             ghcr.io/sum-innovation/sum-chain:<commit>
canonical_digest:          sha256:<canonical>
canonical_reference:       ghcr.io/sum-innovation/sum-chain@sha256:<canonical>
linux_amd64_digest:        sha256:<child>
linux_amd64_binary_sha256: <64-hex>
linux_amd64_version:       sumchain <commit>
linux_amd64_sbom:          <statement digest> SPDX-2.3 <n> packages
linux_amd64_provenance:    <statement digest> https://slsa.dev/provenance/v1 builder <run> vcs <repo>@<commit> dockerfile Dockerfile
linux_amd64_smoke:         health, ready, metrics OK
linux_arm64_…              (the same six lines)
attestation:               verified for the canonical index and both children: …
```

The per-platform lines are release metadata. No operator uses them to choose
anything: the rollout approves `canonical_digest`, and the checker maps
whatever child a node pulled back to this record (§5).

## 4. CI (`.github/workflows/docker-image.yml`)

On every relevant PR and `main` push, CI runs the release path end to end,
with the real Dockerfile and the release tools:

- **`build`, per platform, natively:** `build-child.sh`, including the smoke
  test. The amd64 leg also checks that the build refuses to run without
  `GIT_HASH`.
- **`assemble-verify`, per platform, natively:** pushes both layouts by
  digest to a throwaway `registry:2` on the runner, and joins them into the
  canonical index. Then:
  - `verify-release.py` accepts the index;
  - its own platform's child is run by digest with `verify-child-runtime.sh`,
    and its binary must hash as built.
- **Refusals, against the real registry (amd64 leg):** the tools must refuse
  an existing tag, a release missing a platform, `latest`, a substituted child,
  verification by tag, the wrong platform's child, and a moved tag.

The GitHub attestation step cannot run outside a release, since it needs the
signed workflow on `main`. `verify-attestation-test.sh` covers the policy with
a recording `gh` stub (30 cases). `release-test.py` covers the registry-level
rules against a fake registry (50 cases). `release-workflow-test.py` checks
the workflow's structure (16 checks).

## 5. Rolling out a release

1. Take `canonical_digest` from the release record of the run, and verify it
   (§2a, §2b). That digest is what gets approved.
2. The StatefulSets reference `ghcr.io/sum-innovation/sum-chain@sha256:<canonical>`.
   Each node's runtime pulls the child for its own platform.
3. After start, record evidence and run:
   ```bash
   python3 tools/lane-b/rollout-check.py --release-record release-record.txt \
     --expected-commit <commit> --expected-image-digest sha256:<canonical> …
   ```
   For each validator it proves:
   - `image_id` is the canonical manifest or one of its two children;
   - the running binary is the binary of a child of that manifest, and of
     *that* child when `image_id` names a child;
   - `--version` reports the release commit.

   Validators on different platforms are fine as long as both run children
   of the same manifest. `node_architecture` is recorded when available,
   purely as a diagnostic; its absence never blocks anything.

## 6. Publishing, after the change is approved and merged

Do not dispatch until the merge is verified on `main` and the owner has
authorized publication naming the commit and tag. The dispatcher must not be
Mike-Mans (self-review is prevented):

```bash
C=$(git rev-parse origin/main)       # must be the head of main when dispatched
gh workflow run release-image.yml -R SUM-INNOVATION/sum-chain --ref main -f commit="$C"
gh run list -R SUM-INNOVATION/sum-chain --workflow release-image.yml -L 1
```

The run pauses at `publish` until Mike-Mans approves it. Nothing is written
to GHCR before that approval.

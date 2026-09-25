# Release image: how one is published, and how it is verified

The node's release artifact is one container image in GHCR, addressed by
digest:

    ghcr.io/sum-innovation/sum-chain:<40-hex commit>-<arch>   ->   sha256:<digest>

The tag is immutable: the workflow refuses to push a tag that already exists.
`latest` is never pushed. Rollout records, `rollout-check.py
--expected-image-digest` and every manifest use the **digest**, never the tag.

## 1. What the workflow does (`.github/workflows/release-image.yml`)

It is triggered manually (`workflow_dispatch`) with two inputs: `commit` (the
full 40-hex commit) and `platform` (`linux/amd64` by default, or
`linux/arm64`).

**Job `gate`** (`contents: read`, `pull-requests: read`) refuses unless all
of these hold:
1. The run was dispatched from `main`, so it uses the workflow as reviewed.
2. `commit` is a full 40-hex sha and an ancestor of `main`.
3. `commit` is the head or merge commit of a **merged** pull request into
   `main`, and that PR has an **APPROVED** review on its head. An unmerged or
   unapproved commit is never published.

**Job `publish`** runs in environment `release`, with `contents: read`,
`packages: write`, `id-token: write` and `attestations: write`:
1. It checks out `commit` and confirms `HEAD` equals it.
2. It refuses if `<commit>-<arch>` already exists in GHCR.
3. It runs `docker buildx build` using the Dockerfile. That means the pinned
   `rust:1.88.0-slim-bookworm@sha256:38bc5a86…`, `cargo build --release
   --locked`, and the `GIT_HASH` guard (a full 40-hex hash, or the build
   fails). The build also:
   - adds an OCI `revision` label;
   - attaches an SPDX SBOM (`--sbom=true`) and SLSA provenance
     (`--provenance=mode=max`);
   - pushes, and reads the registry digest from the build metadata.
4. It runs `tools/release/verify-image.sh` against the pushed digest (§2).
5. It runs `tools/release/smoke-image.sh` against the pushed digest (§3).
6. It creates a GitHub artifact attestation, `actions/attest-build-provenance`,
   and pushes it to the registry.
7. It runs `verify-image.sh --require-github-attestation` on the pushed
   digest. The attestation must have been signed by this workflow on
   `refs/heads/main` (§2a). Then it records the
   release: commit, PR, platform, `image@digest`, the sha256 of
   `/usr/local/bin/sumchain`, and the run URL. The record goes into the job
   summary and an artifact, together with the SBOM and the build metadata.

Each run builds one platform, natively: `ubuntu-latest` for amd64 and
`ubuntu-24.04-arm` for arm64. No multi-architecture manifest is created.
`linux/amd64` is the platform CI builds and tests on every change
(`docker-image.yml`). Publish `linux/arm64` only if production runs arm64.
Production's architecture is production-only evidence.

Third-party actions are pinned by commit sha, resolved from their release
tags:

| action | tag | commit |
|---|---|---|
| actions/checkout | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| docker/setup-buildx-action | v4.4.1 | `f87e5991a6d7451dcb8d9637bfbc97413f497069` |
| docker/login-action | v4.6.0 | `dbcb813823bdd20940b903addbd779551569679f` |
| actions/attest-build-provenance | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

### Environment protection: required, and NOT configured today

Checked 2026-09-25: `GET /repos/SUM-INNOVATION/sum-chain/environments`
returned `total_count: 0`, and `GET .../environments/release` returned 404.
**There is no `release` environment.** GitHub creates a missing environment
automatically on first use, *with no protection rules*. Until an admin
configures it, a dispatch by anyone with write access would publish **without
any environment approval**. The gate job's merged-and-approved-PR check would
be the only barrier.

So publication does **not** require environment approval today. Before the
first dispatch, an admin must:
1. Create environment `release`.
2. Add required reviewers.
3. Restrict its deployment branches to `main`.
4. Confirm the result:
   `gh api repos/SUM-INNOVATION/sum-chain/environments/release --jq '.protection_rules'`
   must list a `required_reviewers` rule.

A publication authorization should name that confirmed state.

### Permissions the repository needs

| setting | why |
|---|---|
| Actions → Workflow permissions: the org and repo allow `GITHUB_TOKEN` to be granted `packages: write` | Push to `ghcr.io/sum-innovation/sum-chain` |
| Organization → Packages: members may create container packages | The first push creates the package |
| `id-token: write`, `attestations: write` (declared per job) | Artifact attestations. Supported for public repositories, and this one is public. |
| **Required before the first dispatch:** environment `release` with **required reviewers**, and deployment branches limited to `main` | A human approves each publish run, in addition to the gate job's PR-approval check |
| Package visibility, or an `imagePullSecret` in the cluster | A new GHCR package is private until made public; the cluster must be able to pull it |

## 2. Verifying an image (`tools/release/verify-image.sh`)

```bash
bash tools/release/verify-image.sh --image ghcr.io/sum-innovation/sum-chain \
  --tag <commit>-amd64 --digest sha256:<digest> --commit <commit> --platform linux/amd64 \
  [--require-github-attestation]
```

Every check fails closed:
1. **Tag drift:** the tag must resolve to exactly the digest.
2. **Platform:** the digest must carry exactly one runnable platform.
3. **Commit:** the image, pulled by digest, must print `sumchain <commit>` for
   `--version`, and the revision label must agree.
4. **SBOM:** an SPDX SBOM must be attached.
5. **Provenance:** SLSA provenance must be attached and must name the commit.
6. **Genesis:** the image must contain no genesis file, and no tracked genesis
   at the commit may set a gate outside `GATES_PREDATING_ACTIVATION_RECORDING`
   (`tools/release/check-genesis-gates.py`).
7. **Attestation (with `--require-github-attestation`):** under the fixed
   release policy of §2a.

### 2a. Attestation policy (`tools/release/verify-attestation.sh`)

An image is accepted only if its GitHub artifact attestation, looked up for
the **digest**, was signed by exactly this repository's release workflow
running from `main`. The policy is a set of read-only constants in the script,
not arguments: a caller cannot pass another workflow, branch or repository,
and environment variables do not override it.

| rule | how |
|---|---|
| subject is the immutable digest | `gh attestation verify oci://<repo>@sha256:<digest>`. A tag, or a repository reference carrying one, is refused before `gh` runs. |
| linked repository | `--repo SUM-INNOVATION/sum-chain` |
| signer workflow **and** the ref it ran from | `--cert-identity https://github.com/SUM-INNOVATION/sum-chain/.github/workflows/release-image.yml@refs/heads/main`: an exact match on the signing certificate's identity |
| source ref | `--source-ref refs/heads/main` |
| GitHub-hosted runner | `--deny-self-hosted-runners` |
| re-checked on the result | every attestation `gh` returns must carry that exact `subjectAlternativeName` and `buildSignerURI`, `sourceRepositoryRef` `refs/heads/main`, `sourceRepositoryURI` `https://github.com/SUM-INNOVATION/sum-chain`, and name the digest as a subject |

**Why `--cert-identity` and not `--signer-workflow`.** In gh 2.100.0,
`--signer-workflow` becomes the regular expression
`^https://github.com/<repo>/<path>`, which has no end anchor. As a result,
`.github/workflows/release-image.yml` also matches
`.github/workflows/release-image.yml-other.yml`, at any ref. That comes from
`validateSignerWorkflow` in `pkg/cmd/attestation/verify/policy.go`. The two
flags are also mutually exclusive in `gh`. `--cert-identity` names the
workflow file and its ref exactly.

`tools/release/verify-attestation-test.sh` (29 cases) tests two layers
independently, using a recording `gh` stub:
- the flags `gh` is asked to enforce;
- the script's own check of `gh`'s result: another workflow, a prefix-named
  workflow, another branch, a fork, another digest, a mixed result, or no
  attestation.

It also checks the wiring: `release-image.yml` verifies the digest after
attesting it, and `verify-image.sh` passes the digest, never the tag.

### 2b. Threat model: two controls, two different attackers

* **The `release` environment** (required reviewer Mike-Mans, self-review
  prevented, admin bypass off, deployments from `main` only) controls **the
  approved workflow**. `release-image.yml`'s publish job cannot run without
  that approval, and cannot run from another branch.
* **It does not control other workflows.** Anyone with write access can push
  a branch carrying a *new* workflow that grants itself `packages: write` and
  pushes to `ghcr.io/sum-innovation/sum-chain`. Environment protection covers
  only jobs that name the environment. Such an image may even reuse a
  legitimate-looking tag.
* **Consumer-side attestation verification closes that gap for anyone who
  runs it.** An image pushed by another workflow has either no attestation,
  or one signed by that workflow or branch. §2a rejects both. So a rollout
  must take its image digest from a release record, and must pass
  `verify-image.sh --require-github-attestation` on that digest before the
  digest goes into any manifest. A digest that fails is not a release, whatever
  its tag says.
* **Out of scope:** a compromise of `main` itself, such as a malicious change
  to `release-image.yml` that passes review, or of GitHub's signing
  infrastructure.

`docker-image.yml` runs the same script on every relevant PR and `main` push,
against a throwaway `registry:2` on the runner. It also requires the script
to refuse a wrong commit, a wrong platform, `latest`, and a tag moved to
another image.

## 3. Smoke test (`tools/release/smoke-image.sh`)

The test boots the image as a one-validator NONPRODUCTION devnet (chain
1337). The fixture key is generated inside the container, never on the host,
and never printed. The test requires:
- `GET /health` → 200;
- `GET /ready` → 200 after a block past genesis;
- `tools/lane-b/wave1-monitor.sh verify` to pass on `/metrics`: all nine Wave 1
  subsystems, with two bounded labels.

## 4. Publishing, once the repair PR is approved and merged

Do not dispatch until the merge is verified on `main` and the owner has
authorized publication:

```bash
C=<merged commit, from: git rev-parse origin/main>
gh workflow run release-image.yml -R SUM-INNOVATION/sum-chain --ref main \
  -f commit="$C" -f platform=linux/amd64
gh run list -R SUM-INNOVATION/sum-chain --workflow release-image.yml -L 1
```

The run's release record supplies three values for the rollout:
- `--expected-commit` and `--expected-image-digest` for
  `tools/lane-b/rollout-check.py`;
- `--new-image-digest` for `tools/lane-b/rollout-preflight.py`;
- `--expected-binary-sha256` for `rollout-check.py`.

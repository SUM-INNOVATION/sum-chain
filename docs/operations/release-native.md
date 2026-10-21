# Native release publication: verify before publication, and recovery

`.github/workflows/release-native.yml` publishes the production release `release-<40-hex commit>`. Its `publish` job is the only job that writes. It runs in environment `release`, which requires an approving reviewer, is limited to `main` and has no admin bypass.

GitHub records each run of that job as a **deployment to the `release` environment**, because the environment gates the job. That record is the release publication, and its URL is the published release. It is not a deployment to any node. Installing a release on a validator is a separate, manual procedure (`docs/operations/stage1-native-runbook.md`).

## Verify before publication

The job runs these steps in order:

1. **Record and check.** Write `release-record.txt` and `SHA256SUMS`, and verify every asset (`tools/release/native-release.py verify`).
2. **Refuse anything existing.** Stop if a tag, a release **or a draft** named `release-<commit>` already exists. A draft has no git tag, so all releases are listed, drafts included.
3. **Attest.** Create GitHub artifact attestations for every asset and for both binaries.
4. **Upload a draft.** Upload everything as an **unpublished draft**, visible only to people with write access.
5. **Read the draft back.**
   - Record each asset's id, name, size and digest.
   - Download the assets by id and verify their digests.
   - Verify the attestation of every file, and of both binaries extracted from the downloaded archives.
   - Every item is checked even after one fails. The step summary and the failure message list what was **verified** and what is **NOT verified**: "attestation service unavailable", or "rejected or failed".
6. **Publish.**
   - The draft's assets (ids, names, sizes, digests) must equal the recorded ones.
   - The tag must not exist. It is then created at the commit, and must resolve (peeled) to the commit.
   - Only then is the draft published against that tag, with `make_latest=false`.
   - Afterwards the release must show as published under that tag, the tag must still resolve to the commit, and the assets must still equal the recorded ones.
7. **Install and smoke-test** (`verify` job, read-only). Each architecture downloads the published release, installs it with `install-native.sh --verify-attestation`, and runs the smoke test.

`tools/release/verify-attestation.sh` separates two kinds of failure:
- **The attestation service did not answer** (HTTP 5xx or 429, a timeout, a network error). It retries with backoff (5, 15 and 45 s). If there is still no answer, it reports `ATTESTATION UNAVAILABLE: <subject> is NOT verified`, exit 3.
- **The attestation was rejected.** This is never retried: `ATTESTATION FAIL`, exit 1.

Neither is ever accepted.

## No atomic transaction

GitHub has **no transaction spanning tag creation, asset upload, artifact attestations and release publication**. Each is a separate API call, and the workflow can only order them:
- nothing becomes public before it is verified;
- what was verified is re-checked after publication.

A failure between two calls leaves one of the intermediate states below. The job then fails, and the failed run and its deployment record stay as they are. A failed record is accurate; it is never deleted or edited to look green. The attestations from step 3 remain in any case. They describe bytes that were built by this workflow, and they are not a publication.

**Recovery is always a deliberate action by a person** with release authorization. It is never automatic, and it **never** moves a tag, overwrites an asset or reuses a published tag.

## Recovery

First, inspect what exists:

```bash
R=SUM-INNOVATION/sum-chain C=<40-hex commit> TAG=release-$C
gh api --paginate repos/$R/releases --jq ".[] | select(.tag_name == \"$TAG\") | {id, draft, html_url, assets: [.assets[] | {id, name, size, digest}]}"
gh api repos/$R/git/ref/tags/$TAG       # 404: no tag
```

### Draft left

**Symptom:** verification of the draft failed (a digest, an attestation, a binary), or the assets changed before publication. **State:** an unpublished draft. No tag, nothing public.

1. Read the run's step summary: it lists what was verified and what is NOT verified.
2. A **rejected** item means the draft must not be published. Keep the run URL, the draft id and the asset digests as evidence, then delete the draft deliberately (`gh api -X DELETE repos/$R/releases/<id>`). Investigate before any new run.
3. An item that was only **unavailable** is covered under [Attestation service unavailable](#attestation-service-unavailable).
4. A new run for the same commit is possible only while that commit is still the head of `main`, because the gate refuses anything else. Otherwise, release a newer commit.

### Draft and tag left

**Symptom:** the tag was created, but it does not resolve to the commit, or the publish call failed. **State:** an unpublished draft, plus tag `release-<commit>`.

1. Check where the tag resolves (`gh api repos/$R/git/ref/tags/$TAG`).
2. **If it is not the commit:** delete the draft and the tag deliberately, record the evidence and investigate. The tag was never published, so removing it reuses nothing.
3. **If it is the commit** and the run's summary shows every item verified, a person with release authorization chooses one of two paths. Recording which path was taken, and why, is required.
   - **Publish this draft manually:**
     1. Read its assets (`id, name, size, digest`) and compare them with the run's verified list.
     2. Re-verify the downloaded assets with `tools/release/verify-attestation.sh`.
     3. Publish with `gh api -X PATCH repos/$R/releases/<id> -f tag_name=$TAG -F draft=false -f make_latest=false`.
     4. Confirm the tag still resolves to the commit.
   - **Discard it:** delete the draft, then delete the tag (`gh api -X DELETE repos/$R/git/refs/tags/$TAG`), and dispatch a new run while the commit is the head of `main`.

### Published, post-check failed

**Symptom:** the release was published, but afterwards it did not show as published under the tag, the tag no longer resolved to the commit, or the assets differed from the verified ones. **State:** a **public** release.

1. Do not delete, re-upload or retag anything. Published releases and tags are immutable.
2. Compare the current assets with the verified list from the run, and check where the tag resolves now.
3. **If the assets or the tag changed after publication,** treat it as a security incident:
   - tell the release owner;
   - do not install the release;
   - `install-native.sh --verify-attestation` re-verifies on every install and refuses bytes that are not attested.
4. **If it was a transient read failure,** re-run the read-only checks (`release-verify.yml` for this commit) and record the result. The failed run stays failed.

### Attestation service unavailable

**Symptom:** `ATTESTATION UNAVAILABLE: … is NOT verified … after N attempts`. **State:** the draft is left unpublished (as in [Draft left](#draft-left)), and the summary lists the items still unverified.

1. This is an outage, not a rejection. Check GitHub's status.
2. Once the service is back, re-verify the unverified items read-only: download the draft's assets by id, and run `tools/release/verify-attestation.sh --file` on each one, and on the binaries inside each archive.
3. Then decide as in [Draft and tag left](#draft-and-tag-left), step 3. Publish manually only after every item is verified; otherwise discard the draft and run again.

### Existing draft or tag

**Symptom:** the run stops at "a release or draft for release-<commit> already exists", or "tag release-<commit> already exists". Nothing was written by this run.

- Inspect the existing draft or tag as shown above.
- A **published** release is never replaced.
- For an **unpublished** draft or a draft-only tag, follow [Draft left](#draft-left) or [Draft and tag left](#draft-and-tag-left). A new run can only start after a person has deliberately removed that draft or tag.

#!/usr/bin/env python3
"""Structural checks of .github/workflows/release-native.yml and native-release-ci.yml.

The release workflow cannot run before it is on main and is never rehearsed
against a real release, so what can be checked statically is checked here.

    python3 tools/release/release-native-workflow-test.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = (ROOT / ".github/workflows/release-native.yml").read_text()
CI = (ROOT / ".github/workflows/native-release-ci.yml").read_text()
RESULTS: list[tuple[str, bool, str]] = []


def jobs_of(workflow: str) -> dict[str, str]:
    body = workflow.split("\njobs:\n", 1)[1]
    out, cur = {}, None
    for line in body.splitlines():
        m = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", line)
        if m:
            cur = m.group(1)
            out[cur] = ""
        elif cur:
            out[cur] += line + "\n"
    return out


def check(name: str, cond, detail: str = "") -> None:
    RESULTS.append((name, bool(cond), detail))


def main() -> int:
    jobs = jobs_of(WF)
    top = WF.split("\njobs:\n", 1)[0]
    pub = jobs.get("publish", "")
    check("manual-only: workflow_dispatch is the only trigger",
          re.search(r"(?m)^on:\n  workflow_dispatch:", top)
          and not re.search(r"(?m)^  (push|pull_request|pull_request_target|schedule|workflow_run|release):", top))
    check("no permission granted at workflow level", "permissions: {}" in top)
    writers = sorted(j for j, t in jobs.items() if re.search(r"(contents|packages|attestations|id-token): write", t))
    check("exactly one job may write", writers == ["publish"], str(writers))
    check("  ...and it runs in environment release",
          re.search(r"(?m)^    environment:\n      name: release\n", pub))
    check("  ...whose deployment record links the published release",
          "      url: ${{ steps.publish.outputs.url }}" in pub)
    check("  ...and whose name says it publishes a release and deploys no node",
          re.search(r"(?m)^    name: publish GitHub Release .*release publication; deploys no node", pub))
    check("no step or job may hide a failure (continue-on-error)", "continue-on-error" not in WF)
    check("no other job names an environment", all("environment:" not in t for j, t in jobs.items() if j != "publish"))
    check("no packages permission anywhere: GHCR is not the production path", "packages:" not in WF)
    b = jobs.get("build", "")
    check("both architectures build on native runners",
          "{ arch: x86_64, runner: ubuntu-24.04 }" in b and "{ arch: aarch64, runner: ubuntu-24.04-arm }" in b)
    check("no emulation, no cross-compilation", not re.search(r"qemu|binfmt|--target [a-z0-9_]+-unknown", WF))
    check("builds go through build-native.sh", "tools/release/build-native.sh" in b)
    check("the gate requires the commit to be the head of main", '"$COMMIT" == "$GITHUB_SHA"' in jobs.get("gate", ""))
    check("the gate requires an approved, merged PR", "APPROVED" in jobs.get("gate", "") and "merged_at" in
          jobs.get("gate", ""))
    check("the tag is release-<commit>", "TAG: release-${{ inputs.commit }}" in pub)
    order = [pub.find(s) for s in ("native-release.py verify", "Refuse an existing tag, release or draft",
                                   "attest-build-provenance@", "gh release create", "releases/assets/$aid",
                                   "verify-attestation.sh --file", "assets.prepublish.json",
                                   '"$api/git/refs" -f ref="refs/tags/$TAG" -f sha="$COMMIT"', "-F draft=false",
                                   "assets.published.json")]
    check("order: verify, refuse existing, attest, upload draft, read back, verify attestations, "
          "re-check assets, create tag, publish, re-check",
          all(i >= 0 for i in order) and order == sorted(order), str(order))
    create = pub[pub.find("gh release create"):pub.find("gh release create") + 300]
    check("the release is uploaded as a draft, never published directly", "--draft" in create)
    check("publication happens in exactly one place, after verification",
          pub.count("draft=false") == 1 and "gh release edit" not in WF)
    check("an existing draft is refused like an existing release (drafts have no tag)",
          'select(.tag_name == \\"$TAG\\")' in pub and "already exists" in pub)
    check("asset identity is id, name, size and digest",
          pub.count("{id, name, size, digest}") >= 2)
    check("the draft is unchanged immediately before publishing",
          'cmp -s "$RUNNER_TEMP/assets.verified.json" "$RUNNER_TEMP/assets.prepublish.json"' in pub)
    check("...and immediately after publishing",
          'cmp -s "$RUNNER_TEMP/assets.verified.json" "$RUNNER_TEMP/assets.published.json"' in pub)
    tagc, publish = pub.find('-f ref="refs/tags/$TAG"'), pub.find("-F draft=false")
    peel_checks = [i for i in range(len(pub)) if pub.startswith('[[ $(peeled || true) == "$COMMIT" ]]', i)]
    check("the tag is created explicitly at the commit, after checking it is absent",
          pub.rfind('git/ref/tags/$TAG" >/dev/null 2>&1', 0, tagc) != -1 and tagc != -1)
    check("the tag resolves (peeled) to the commit before publication and again after",
          len(peel_checks) == 2 and peel_checks[0] < publish < peel_checks[1], str(peel_checks))
    check("the draft is published against that tag", '-f tag_name="$TAG" -F draft=false' in pub)
    check("the binaries checked are the ones inside the downloaded archives",
          "readback-bins/$t/$b" in pub)
    check("every read-back item is checked; the result lists verified and NOT verified",
          "verified+=(" in pub and "unverified+=(" in pub and "**NOT verified**" in pub
          and "GITHUB_STEP_SUMMARY" in pub)
    AT = (ROOT / "tools/release/verify-attestation.sh").read_text()
    check("an unavailable result names its subject and claims nothing about others",
          "is NOT verified" in AT and "nothing was verified" not in AT + WF)
    DOC_PATH = ROOT / "docs/operations/release-native.md"
    DOC = DOC_PATH.read_text() if DOC_PATH.exists() else ""
    anchors = set(re.findall(r"release-native\.md#([a-z0-9-]+)", WF))
    headings = {re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-")
                for h in re.findall(r"(?m)^#{2,4} (.+)$", DOC)}
    check("every recovery link in the workflow names a section of docs/operations/release-native.md",
          anchors and anchors <= headings, f"{sorted(anchors - headings)}")
    check("the documentation calls it verify before publication and denies any atomic transaction",
          "Verify before publication" in DOC and "No atomic transaction" in DOC
          and "no transaction spanning" in DOC.lower())
    check("recovery is documented for each intermediate state",
          all(h in headings for h in ("draft-left", "draft-and-tag-left", "published-post-check-failed",
                                      "attestation-service-unavailable", "existing-draft-or-tag")))
    check("the workflow does not call the publication atomic", "atomic" not in WF.lower())
    check("nothing is ever overwritten", "--clobber" not in WF and "--force" not in WF)
    check("the release is not marked latest", "--latest=false" in pub)
    check("both binaries are attested as well as every asset",
          "bins/*/sumchain\n" in pub and "bins/*/sumchain-wallet" in pub and "release/*.tar.gz" in pub)
    v = jobs.get("verify", "")
    check("post-publish: each architecture installs the release natively with attestation checks",
          "install-native.sh" in v and "--verify-attestation" in v and "ubuntu-24.04-arm" in v)
    check("post-publish: the installed binary runs the smoke test", "smoke-native.sh" in v)
    check("CI builds, assembles, verifies and installs with the same tools",
          all(x in CI for x in ("build-native.sh", "native-release.py record", "native-release.py verify",
                                "install-native.sh", "smoke-native.sh", "runner: ubuntu-24.04-arm")))
    fails = 0
    for name, ok, got in RESULTS:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
        if not ok:
            fails += 1
            print(f"          | {got[:200]}")
    print()
    if fails:
        print(f"NATIVE RELEASE WORKFLOW CHECKS FAILED: {fails} of {len(RESULTS)}")
        return 1
    print(f"NATIVE RELEASE WORKFLOW CHECKS OK: {len(RESULTS)} checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())

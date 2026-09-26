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
    check("  ...and it runs in environment release", "environment: release" in pub)
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
    order = [pub.find(s) for s in ("native-release.py verify", "Refuse an existing tag or release",
                                   "attest-build-provenance@", "gh release create", "gh release download",
                                   "verify-attestation.sh --file")]
    check("order: verify, refuse existing, attest, create, read back, verify attestations",
          all(i >= 0 for i in order) and order == sorted(order), str(order))
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

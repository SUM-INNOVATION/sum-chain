#!/usr/bin/env python3
"""Structural checks of .github/workflows/release-image.yml and docker-image.yml.

The release workflow cannot run before it is on main, and publishing is never
rehearsed against GHCR, so what CAN be checked statically is checked here:
manual-only; one job, and only one, holds packages: write and it is protected
by environment `release`; both platforms build natively; the canonical index
and both children are attested, then verified by digest; nothing pushes a tag
other than the commit; and CI runs the same tools.

    python3 tools/release/release-workflow-test.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS: list[tuple[str, bool, str]] = []


def jobs_of(workflow: str) -> dict[str, str]:
    """{job id: its YAML text}, split on two-space-indented keys under `jobs:`."""
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


def workflow_cases():
    wf = (ROOT / ".github/workflows/release-image.yml").read_text()
    ci = (ROOT / ".github/workflows/docker-image.yml").read_text()
    jobs = jobs_of(wf)

    def check(name, cond, detail=""):
        RESULTS.append((f"workflow: {name}", bool(cond), detail))

    top = wf.split("\njobs:\n", 1)[0]
    check("manual-only: workflow_dispatch is the only trigger",
          re.search(r"(?m)^on:\n  workflow_dispatch:", top) and not re.search(
              r"(?m)^  (push|pull_request|pull_request_target|schedule|workflow_run|release):", top))
    check("no token permission granted at workflow level", "permissions: {}" in top)
    writers = [j for j, t in jobs.items() if "packages: write" in t]
    check("exactly one job holds packages: write", writers == ["publish"], str(writers))
    check("  ...and it runs in environment release", "environment: release" in jobs.get("publish", ""))
    check("no other job names an environment or writes attestations",
          all("environment:" not in t and "attestations: write" not in t and "id-token: write" not in t
              for j, t in jobs.items() if j != "publish"))
    check("both platforms build on native runners",
          "{ platform: linux/amd64, arch: amd64, runner: ubuntu-24.04 }" in jobs.get("build", "")
          and "{ platform: linux/arm64, arch: arm64, runner: ubuntu-24.04-arm }" in jobs.get("build", ""))
    check("no emulation", "setup-qemu" not in wf and "binfmt" not in wf)
    check("the gate requires the commit to be the head of main", '"$COMMIT" == "$GITHUB_SHA"' in jobs.get("gate", ""))
    pub = jobs.get("publish", "")
    attests = re.findall(r"subject-digest: \$\{\{ (steps\.[a-z]+\.outputs\.[a-z0-9]+) \}\}", pub)
    check("the canonical index and both children are attested",
          sorted(attests) == sorted(["steps.join.outputs.digest", "steps.push.outputs.amd64",
                                     "steps.push.outputs.arm64"]), str(attests))
    last_attest = max(m.start() for m in re.finditer("attest-build-provenance@", pub))
    first_verify = pub.find("verify-attestation.sh")
    check("attestations are verified after they are created", first_verify > last_attest)
    calls = re.findall(r'verify-attestation\.sh "\$IMAGE" "([^"]+)" "\$COMMIT"', wf)
    check("every attestation check passes a digest and the commit, never a tag",
          calls and all(c in ("$d",) for c in calls) and wf.count("verify-attestation.sh") == len(calls) + 0,
          str(calls))
    check("verification reads the canonical index back by digest", '--digest "${{ steps.join.outputs.digest }}"' in pub)
    check("children are pushed by digest, with no tag", "push-layout" in pub and "--tag" not in
          pub.split("Push both children", 1)[1].split("Join them", 1)[0])
    check("the only tag pushed is the commit, never latest",
          'assemble "$IMAGE" --tag "$COMMIT"' in pub and "latest" not in pub)
    check("no step bypasses the release policy with --signer-workflow or a repo argument",
          "--signer-workflow" not in wf and "--require-github-attestation" not in wf)
    check("CI runs the same build and verification tools on both native runners",
          all(x in ci for x in ("build-child.sh", "oci.py push-layout", "oci.py assemble", "verify-release.py",
                                "verify-child-runtime.sh", "runner: ubuntu-24.04-arm")))


def main() -> int:
    workflow_cases()
    fails = 0
    for name, ok, got in RESULTS:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
        if not ok:
            fails += 1
            print(f"          | {got[:300]}")
    print()
    if fails:
        print(f"RELEASE WORKFLOW CHECKS FAILED: {fails} of {len(RESULTS)}")
        return 1
    print(f"RELEASE WORKFLOW CHECKS OK: {len(RESULTS)} checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())

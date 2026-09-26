#!/usr/bin/env python3
"""Write release-record.txt from the release workflow's verified outputs.

    python3 tools/release/release-record.py \\
        --summary verify-release.json \\
        --runtime runtime-linux-amd64.json --runtime runtime-linux-arm64.json \\
        --pr <number> --approved-by <login[,login]> --run-url <url> \\
        --attestation "<result line>" > release-record.txt

The record is `key: value` lines. tools/lane-b/rollout-check.py reads it with
--release-record: the operator approves ONE canonical manifest digest, and the
record maps each child of that manifest to the binary it carries. The platform
names in it are release metadata; no operator has to know which platform
production runs, because the container runtime pulls the matching child of the
canonical manifest by itself.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PLATFORMS = ("linux/amd64", "linux/arm64")


def key(platform: str) -> str:
    return platform.replace("/", "_")


def render(summary: dict, runtimes: list[dict], pr: str, approved_by: str, run_url: str,
           attestation: str) -> str:
    rt = {r["platform"]: r for r in runtimes}
    if sorted(rt) != sorted(PLATFORMS):
        raise ValueError(f"runtime results for {sorted(rt)}, need {list(PLATFORMS)}")
    lines = [
        ("release_commit", summary["commit"]),
        ("pull_request", f"#{pr}"),
        ("approved_by", approved_by),
        ("workflow_run", run_url),
        ("canonical_tag", f"{summary['image']}:{summary['tag']}"),
        ("canonical_digest", summary["canonical_digest"]),
        ("canonical_reference", f"{summary['image']}@{summary['canonical_digest']}"),
    ]
    for p in PLATFORMS:
        c, r = summary["children"][p], rt[p]
        if r["digest"] != c["digest"]:
            raise ValueError(f"{p}: runtime verified {r['digest']}, the index holds {c['digest']}")
        if r.get("smoke") != "OK" or r.get("version") != f"sumchain {summary['commit']}":
            raise ValueError(f"{p}: runtime verification did not pass: {r}")
        sb = "; ".join(f"{s['layer']} {s['spdxVersion']} {s['packages']} packages" for s in c["sboms"])
        pv = c["provenance"]
        lines += [
            (f"{key(p)}_digest", c["digest"]),
            (f"{key(p)}_binary_sha256", r["binary_sha256"]),
            (f"{key(p)}_version", r["version"]),
            (f"{key(p)}_sbom", sb),
            (f"{key(p)}_provenance", f"{pv['layer']} {pv['predicateType']} builder {pv['builder']} "
                                     f"vcs {pv['vcs_source']}@{pv['vcs_revision']} dockerfile {pv['dockerfile']}"),
            (f"{key(p)}_smoke", "health, ready, metrics OK"),
        ]
    if rt["linux/amd64"]["binary_sha256"] == rt["linux/arm64"]["binary_sha256"]:
        raise ValueError("the two platforms report the same binary sha256")
    lines.append(("attestation", attestation))
    width = max(len(k) for k, _ in lines) + 1
    return "".join(f"{(k + ':').ljust(width)} {v}\n" for k, v in lines)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--summary", type=Path, required=True)
    ap.add_argument("--runtime", type=Path, action="append", required=True)
    ap.add_argument("--pr", required=True)
    ap.add_argument("--approved-by", required=True)
    ap.add_argument("--run-url", required=True)
    ap.add_argument("--attestation", required=True)
    a = ap.parse_args(argv)
    try:
        text = render(json.loads(a.summary.read_text()), [json.loads(p.read_text()) for p in a.runtime],
                      a.pr, a.approved_by, a.run_url, a.attestation)
    except (ValueError, KeyError) as e:
        print(f"RELEASE RECORD FAIL: {e}", file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

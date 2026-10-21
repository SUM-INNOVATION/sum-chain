#!/usr/bin/env python3
"""Dry walk of release-native.yml's publish steps against a stateful `gh` stub.

The publish job cannot be rehearsed against real releases, so this runs the
job's own `run:` scripts, taken verbatim from the workflow, in order (refuse
existing -> upload draft -> read back and verify -> publish), with a `gh` stub
that keeps release, asset and tag state, and stubbed verifiers. Each scenario
checks what is left behind: draft or published, tag or none, which items the
step reports as verified and NOT verified, and the recovery section named.
NONPRODUCTION commit and fixture bytes throughout; nothing touches the network.

    python3 tools/release/release-native-publish-test.py
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = (ROOT / ".github/workflows/release-native.yml").read_text()
REPO = "SUM-INNOVATION/sum-chain"
COMMIT = "c" * 40
TAG = f"release-{COMMIT}"
OTHER = "d" * 40
STEPS = ["Refuse an existing tag, release or draft", "Upload the release as an unpublished draft",
         "Read the draft back and verify it", "Publish the verified draft"]
ARCHES = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")


def publish_run_scripts() -> dict[str, str]:
    """The `run: |` script of each named step of the publish job, as written."""
    job = WF.split("\n  publish:\n", 1)[1].split("\n  verify:\n", 1)[0]
    out: dict[str, str] = {}
    for block in re.split(r"(?m)^      - ", job)[1:]:
        m = re.match(r"name: (.+)", block)
        if not m or "\n        run: |\n" not in block:
            continue
        body = block.split("\n        run: |\n", 1)[1]
        lines = []
        for line in body.splitlines():
            if line.strip() and not line.startswith(" " * 10):
                break
            lines.append(line[10:])
        out[m.group(1)] = "\n".join(lines) + "\n"
    return out


GH_STUB = r'''#!/usr/bin/env python3
import hashlib, json, os, subprocess, sys
st_path = os.environ["STUB_STATE"]; st = json.load(open(st_path)); a = sys.argv[1:]
E = os.environ.get
def save(): json.dump(st, open(st_path, "w"))
def jq(obj, expr):
    if not expr: print(json.dumps(obj)); sys.exit(0)
    r = subprocess.run(["jq", "-r", expr], input=json.dumps(obj), capture_output=True, text=True)
    sys.stdout.write(r.stdout); sys.exit(r.returncode)
def opt(flag): return a[a.index(flag) + 1] if flag in a else None
def fields():
    f = {}
    for i, x in enumerate(a):
        if x in ("-f", "-F"): k, v = a[i + 1].split("=", 1); f[k] = v
    return f
def rj(r): return {"id": r["id"], "tag_name": r["tag_name"], "draft": r["draft"], "html_url": r["html_url"],
                   "assets": [{k: x[k] for k in ("id", "name", "size", "digest")} for x in r["assets"]]}
repo, tag = os.environ["GITHUB_REPOSITORY"], os.environ["TAG"]
if a[:2] == ["release", "create"]:
    files = [x for i, x in enumerate(a[3:], 3) if os.path.isfile(x) and a[i - 1] != "--notes-file"]
    rid = 2000 + len(st["releases"]); assets = []
    for i, f in enumerate(sorted(files)):
        b = open(f, "rb").read()
        assets.append({"id": rid * 100 + i, "name": os.path.basename(f), "size": len(b),
                       "digest": "sha256:" + hashlib.sha256(b).hexdigest(), "path": f})
    st["releases"].append({"id": rid, "tag_name": a[2], "draft": "--draft" in a, "target": opt("--target"),
                           "html_url": "https://github.com/%s/releases/tag/%s" % (repo, a[2]), "assets": assets})
    st["events"].append("upload draft" if "--draft" in a else "upload PUBLISHED"); save(); sys.exit(0)
if a[0] != "api":
    sys.exit("stub: unsupported " + " ".join(a))
path = next(x for x in a[1:] if x.startswith("repos/")); expr = opt("--jq"); method = opt("-X") or "GET"
if path.endswith("/git/ref/tags/" + tag):
    if not st.get("tag"):
        sys.stderr.write("gh: Not Found (HTTP 404)\n"); sys.exit(1)
    sha = st["tag"]
    if st.get("published") and E("STUB_TAG_MOVES_AFTER_PUBLISH"): sha = "d" * 40
    if E("STUB_ANNOTATED"): jq({"ref": "refs/tags/" + tag, "object": {"type": "tag", "sha": "a" * 40}}, expr)
    jq({"ref": "refs/tags/" + tag, "object": {"type": "commit", "sha": sha}}, expr)
if path.endswith("/git/tags/" + "a" * 40):
    jq({"object": {"type": "commit", "sha": st["tag"]}}, expr)
if path.endswith("/git/refs") and method == "POST":
    if E("STUB_REFCREATE_FAIL"): sys.stderr.write("HTTP 500: Internal Server Error\n"); sys.exit(1)
    if st.get("tag"): sys.stderr.write("HTTP 422: Reference already exists\n"); sys.exit(1)
    f = fields(); st["tag"] = E("STUB_TAG_RESOLVES_TO") or f["sha"]; st["events"].append("create tag"); save()
    print(json.dumps({"ref": f["ref"]})); sys.exit(0)
if path == "repos/%s/releases" % repo:
    jq([rj(r) for r in st["releases"]], expr)
if "/releases/assets/" in path:
    aid = int(path.rsplit("/", 1)[1])
    for r in st["releases"]:
        for x in r["assets"]:
            if x["id"] == aid: sys.stdout.buffer.write(open(x["path"], "rb").read()); sys.exit(0)
    sys.exit(1)
if "/releases/" in path:
    rid = int(path.rsplit("/", 1)[1]); r = next(r for r in st["releases"] if r["id"] == rid)
    if method == "PATCH":
        if E("STUB_PATCH_FAIL"): sys.stderr.write("HTTP 502: Bad Gateway\n"); sys.exit(1)
        f = fields()
        if not st.get("tag"): st["tag"] = r["target"]; st["events"].append("tag created by publish")
        r["draft"] = f.get("draft") != "false"; r["tag_name"] = f.get("tag_name", r["tag_name"])
        st["published"] = not r["draft"]; st["events"].append("publish"); save(); jq(rj(r), expr)
    if expr and expr.startswith("[.assets[]"):
        st["asset_reads"] = st.get("asset_reads", 0) + 1
        if str(st["asset_reads"]) == E("STUB_MUTATE_ON_ASSET_READ", ""):
            r["assets"][0]["digest"] = "sha256:" + "0" * 64
        if str(st["asset_reads"]) == E("STUB_TAG_APPEARS_ON_ASSET_READ", ""):
            st["tag"] = "d" * 40; st["events"].append("foreign tag appears")
        save()
    jq(rj(r), expr)
sys.exit("stub: unsupported " + " ".join(a))
'''


def scenario(env_extra=None, pre=None, attest_unavailable=None, attest_reject=None, verify_fail=False):
    scripts = publish_run_scripts()
    w = Path(tempfile.mkdtemp(prefix="publish-walk-"))
    try:
        rt, rel, tools, stub = w / "rt", w / "rt/release", w / "tools/release", w / "bin"
        for d in (rel, tools, stub):
            d.mkdir(parents=True)
        for t in ARCHES:
            n = f"sumchain-{COMMIT}-{t}"
            with tarfile.open(rel / f"{n}.tar.gz", "w:gz") as tf:
                for b in ("sumchain", "sumchain-wallet"):
                    data = f"{t}/{b} NONPRODUCTION".encode()
                    ti = tarfile.TarInfo(f"{n}/{b}"); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
            for ext in (".spdx.json", ".provenance.json"):
                (rel / f"{n}{ext}").write_text("{}")
        (rel / "SHA256SUMS").write_text("fixture\n"); (rel / "release-record.txt").write_text("fixture record\n")
        (tools / "native-release.py").write_text(f"import sys\nsys.exit({1 if verify_fail else 0})\n")
        va = "#!/usr/bin/env bash\n"
        if attest_unavailable:
            va += f'case "$2" in *{attest_unavailable}) echo "ATTESTATION UNAVAILABLE: $2 is NOT verified" >&2; exit 3;; esac\n'
        if attest_reject:
            va += f'case "$2" in *{attest_reject}) echo "ATTESTATION FAIL: rejected" >&2; exit 1;; esac\n'
        (tools / "verify-attestation.sh").write_text(va + 'echo "ATTESTATION OK: $2"\n')
        (stub / "gh").write_text(GH_STUB); (stub / "gh").chmod(0o755)
        state = w / "state.json"
        state.write_text(json.dumps({"releases": pre or [], "events": [], "tag": (env_extra or {}).pop("PRE_TAG", None)}))
        summary = w / "summary"; summary.write_text("")
        env = dict(os.environ, PATH=f"{stub}:{os.environ['PATH']}", STUB_STATE=str(state), GITHUB_REPOSITORY=REPO,
                   TAG=TAG, COMMIT=COMMIT, RUNNER_TEMP=str(rt), GITHUB_STEP_SUMMARY=str(summary),
                   **(env_extra or {}))
        outputs: dict[str, str] = {}
        ran, failed = 0, None
        for prefix in STEPS:
            name = next(n for n in scripts if n.startswith(prefix))
            out = w / f"out{ran}"; out.write_text("")
            e = dict(env, GITHUB_OUTPUT=str(out), RELEASE_ID=outputs.get("id", ""))
            r = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", scripts[name]],
                               cwd=w, env=e, capture_output=True, text=True)
            ran += 1
            outputs.update(dict(l.split("=", 1) for l in out.read_text().splitlines() if "=" in l))
            if r.returncode != 0:
                failed = (prefix, r.stdout + r.stderr)
                break
        st = json.loads(state.read_text())
        return {"ran": ran, "failed": failed, "state": st, "outputs": outputs, "summary": summary.read_text()}
    finally:
        shutil.rmtree(w)


RESULTS: list[tuple[str, bool, str]] = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), str(detail)[:300]))


def rel(s):
    return s["state"]["releases"][-1] if s["state"]["releases"] else {}


def main() -> int:
    if not shutil.which("jq"):
        print("jq is required"); return 2
    s = scenario()
    check("happy path: all four steps pass", s["failed"] is None and s["ran"] == 4, s["failed"])
    check("  ...draft uploaded, then the tag created, then published, in that order",
          s["state"]["events"] == ["upload draft", "create tag", "publish"], s["state"]["events"])
    check("  ...the tag resolves to the commit and the release is published",
          s["state"]["tag"] == COMMIT and rel(s).get("draft") is False and rel(s).get("tag_name") == TAG)
    check("  ...the environment URL is the published release", s["outputs"].get("url", "").endswith("/" + TAG))
    check("  ...the summary lists all 12 items verified, none NOT verified",
          "12 of 12 verified" in s["summary"] and s["summary"].count("- verified:") == 12
          and "NOT verified" not in s["summary"], s["summary"])

    s = scenario(attest_unavailable="x86_64-unknown-linux-gnu.provenance.json")
    msg = s["failed"][1] if s["failed"] else ""
    check("service unavailable for one asset: read-back fails, nothing published",
          s["failed"] and s["failed"][0].startswith("Read the draft back") and rel(s).get("draft") is True
          and not s["state"].get("tag"), msg)
    check("  ...the failure names exactly what is NOT verified, and why",
          "1 of 12 not verified" in msg and "x86_64-unknown-linux-gnu.provenance.json (attestation service unavailable)" in msg, msg)
    check("  ...and lists the 11 items that were verified",
          "Verified: " in msg and msg.split("Verified: ", 1)[1].count(";") == 10 and "11 of 12 verified" in s["summary"], msg)
    check("  ...and points at the recovery section", "release-native.md#draft-left" in msg, msg)

    s = scenario(attest_reject="aarch64-unknown-linux-gnu/sumchain-wallet")
    msg = s["failed"][1] if s["failed"] else ""
    check("a rejected binary inside the archive is reported as rejected, not unavailable",
          "aarch64-unknown-linux-gnu/sumchain-wallet (inside the downloaded archive) (rejected or failed, exit 1)" in msg
          and "unavailable" not in msg and rel(s).get("draft") is True, msg)

    s = scenario(attest_unavailable="SHA256SUMS", attest_reject="x86_64-unknown-linux-gnu/sumchain")
    msg = s["failed"][1] if s["failed"] else ""
    check("an unavailable asset and a rejected binary are both listed, 10 verified",
          "2 of 12 not verified" in msg and "SHA256SUMS (attestation service unavailable)" in msg
          and "x86_64-unknown-linux-gnu/sumchain (inside the downloaded archive) (rejected" in msg, msg)

    s = scenario(verify_fail=True)
    check("a digest/record failure stops the read-back before any attestation is trusted",
          s["failed"] and s["failed"][0].startswith("Read the draft back") and rel(s).get("draft") is True
          and not s["state"].get("tag"))

    pre = [{"id": 900, "tag_name": TAG, "draft": True, "target": COMMIT, "html_url": "x", "assets": []}]
    s = scenario(pre=pre)
    check("an existing draft is refused before anything is uploaded",
          s["failed"] and s["failed"][0].startswith("Refuse") and "900 draft=true" in s["failed"][1]
          and s["state"]["events"] == [], s["failed"])

    s = scenario(env_extra={"PRE_TAG": OTHER})
    check("an existing tag is refused before anything is uploaded",
          s["failed"] and s["failed"][0].startswith("Refuse") and s["state"]["events"] == [] and s["state"]["tag"] == OTHER)

    s = scenario(env_extra={"STUB_MUTATE_ON_ASSET_READ": "2"})
    msg = s["failed"][1] if s["failed"] else ""
    check("assets changed before publication: refused, no tag created, draft left",
          s["failed"] and s["failed"][0].startswith("Publish") and "changed after they were verified" in msg
          and not s["state"].get("tag") and rel(s).get("draft") is True, msg)

    s = scenario(env_extra={"STUB_TAG_APPEARS_ON_ASSET_READ": "2"})
    msg = s["failed"][1] if s["failed"] else ""
    check("a tag that appears during verification is never reused: refused, foreign tag untouched",
          s["failed"] and "appeared while the draft was being verified" in msg and s["state"]["tag"] == OTHER
          and "create tag" not in s["state"]["events"] and rel(s).get("draft") is True, msg)

    s = scenario(env_extra={"STUB_REFCREATE_FAIL": "1"})
    msg = s["failed"][1] if s["failed"] else ""
    check("tag creation fails: not published, draft left, recovery named",
          s["failed"] and "could not create tag" in msg and "#draft-left" in msg
          and not s["state"].get("tag") and rel(s).get("draft") is True, msg)

    s = scenario(env_extra={"STUB_TAG_RESOLVES_TO": OTHER})
    msg = s["failed"][1] if s["failed"] else ""
    check("tag created but not resolving to the commit: not published, draft and tag left",
          s["failed"] and "does not resolve to" in msg and "#draft-and-tag-left" in msg
          and "publish" not in s["state"]["events"] and rel(s).get("draft") is True, msg)

    s = scenario(env_extra={"STUB_ANNOTATED": "1"})
    check("a tag reported as annotated is peeled to its commit", s["failed"] is None and s["ran"] == 4, s["failed"])

    s = scenario(env_extra={"STUB_PATCH_FAIL": "1"})
    msg = s["failed"][1] if s["failed"] else ""
    check("publication call fails: draft and tag left, recovery named",
          s["failed"] and "publishing failed; the verified draft and tag" in msg and "#draft-and-tag-left" in msg
          and s["state"]["tag"] == COMMIT and rel(s).get("draft") is True and not s["outputs"].get("url"), msg)

    s = scenario(env_extra={"STUB_MUTATE_ON_ASSET_READ": "3"})
    msg = s["failed"][1] if s["failed"] else ""
    check("assets differ after publication: the job fails, the release is published, the URL is recorded",
          s["failed"] and "was published, but its post-publication check failed" in msg
          and "published assets differ" in msg and "#published-post-check-failed" in msg
          and rel(s).get("draft") is False and s["outputs"].get("url"), msg)

    s = scenario(env_extra={"STUB_TAG_MOVES_AFTER_PUBLISH": "1"})
    msg = s["failed"][1] if s["failed"] else ""
    check("the tag no longer resolving to the commit after publication fails the job",
          s["failed"] and "no longer resolves to" in msg and "#published-post-check-failed" in msg, msg)

    fails = 0
    for name, ok, got in RESULTS:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
        if not ok:
            fails += 1
            print(f"          | {got}")
    print()
    if fails:
        print(f"NATIVE RELEASE PUBLISH WALK FAILED: {fails} of {len(RESULTS)}")
        return 1
    print(f"NATIVE RELEASE PUBLISH WALK OK: {len(RESULTS)} checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())

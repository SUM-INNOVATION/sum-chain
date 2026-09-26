#!/usr/bin/env python3
"""Verify a published release by digest: one canonical OCI index, exactly two
runnable Linux children, their SBOMs and BuildKit provenance.

    python3 tools/release/verify-release.py --mode release \\
        --image ghcr.io/sum-innovation/sum-chain --commit <40-hex> \\
        --digest sha256:<canonical index> \\
        --child linux/amd64=sha256:<image> --child linux/arm64=sha256:<image> \\
        [--run-url https://github.com/SUM-INNOVATION/sum-chain/actions/runs/<id>] \\
        [--summary out.json]

Exit 0 only when every rule holds; 1 otherwise; 2 on usage.

Fixed policy, not input:
  * the tag is the full commit; `latest` is never a release;
  * mode `release` accepts only ghcr.io/sum-innovation/sum-chain; mode `ci`
    accepts only a registry on localhost (the throwaway registry in CI);
  * provenance must come from a build of THIS repository: builder id under
    https://github.com/SUM-INNOVATION/sum-chain/actions/runs/, VCS source this
    repository, VCS revision and GIT_HASH the release commit, the Dockerfile at
    the repository root, and every base image the Dockerfile pins by digest
    (read from the Dockerfile AT THE COMMIT) among the resolved dependencies.

Checked, in order, every digest recomputed from the bytes received:
  1. the tag resolves to exactly --digest (a moved tag fails);
  2. --digest is an OCI index whose runnable descriptors are exactly one
     linux/amd64 and one linux/arm64, equal to the --child digests this run
     produced; every other descriptor is an attestation manifest that points
     at one of them, one per child; nothing else is present;
  3. per child: an OCI image manifest whose config agrees on os/arch and
     carries the revision label = the commit;
  4. per child: an SPDX SBOM and exactly one SLSA v1 provenance, both in-toto
     statements about that child's digest, and both valid under the policy.
The GitHub artifact attestations (who signed, from which workflow and ref) are
checked separately by tools/release/verify-attestation.sh; the running binaries
by tools/release/verify-child-runtime.sh.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# No __pycache__ beside the tools: CI requires the tree to stay clean.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import oci  # noqa: E402

POLICY_REPO = "SUM-INNOVATION/sum-chain"
POLICY_IMAGE = "ghcr.io/sum-innovation/sum-chain"
POLICY_BUILDER_PREFIX = f"https://github.com/{POLICY_REPO}/actions/runs/"
POLICY_VCS_SOURCES = (f"https://github.com/{POLICY_REPO}", f"https://github.com/{POLICY_REPO}.git")
ROOT = Path(__file__).resolve().parents[2]


class Refused(Exception):
    pass


def pinned_bases(commit: str) -> list[tuple[str, str]]:
    """(image, sha256 digest) of every `FROM image@sha256:...` in the Dockerfile at the commit."""
    try:
        text = subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:Dockerfile"], check=True,
                              capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        raise Refused(f"cannot read the Dockerfile at {commit}: {e.stderr.strip()}")
    froms = re.findall(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", text)
    pins, stages = [], set()
    for f, alias in froms:
        if f.lower() in stages:          # FROM <an earlier stage>: not a base image
            stages.add((alias or "").lower())
            continue
        stages.add((alias or "").lower())
        name, at, d = f.partition("@")
        if not at:
            raise Refused(f"Dockerfile at {commit} has an unpinned base image: FROM {f}")
        if not oci.DIGEST.match(d):
            raise Refused(f"Dockerfile at {commit} pins {name} to a non-sha256 digest {d!r}")
        pins.append((name, d))
    if not pins:
        raise Refused(f"no FROM lines in the Dockerfile at {commit}")
    return pins


def check_sbom(st: dict, where: str) -> dict:
    p = st.get("predicate") or {}
    pk = p.get("packages")
    problems = []
    if not str(p.get("spdxVersion", "")).startswith("SPDX-2."):
        problems.append(f"spdxVersion {p.get('spdxVersion')!r}")
    if p.get("SPDXID") != "SPDXRef-DOCUMENT":
        problems.append(f"SPDXID {p.get('SPDXID')!r}")
    if not p.get("documentNamespace"):
        problems.append("no documentNamespace")
    if not ((p.get("creationInfo") or {}).get("creators")):
        problems.append("no creationInfo.creators")
    if not isinstance(pk, list) or not pk:
        problems.append("no packages")
    elif any(not (x.get("name") and x.get("SPDXID")) for x in pk):
        problems.append("a package without name or SPDXID")
    if problems:
        raise Refused(f"{where}: invalid SPDX SBOM: {', '.join(problems)}")
    return {"spdxVersion": p["spdxVersion"], "packages": len(pk), "name": p.get("name")}


def check_provenance(st: dict, where: str, commit: str, pins: list[tuple[str, str]],
                     run_url: str | None) -> dict:
    p = st.get("predicate") or {}
    bd = p.get("buildDefinition") or {}
    ext = bd.get("externalParameters") or {}
    req = ext.get("request") or {}
    args = req.get("args") or {}
    cfg = ext.get("configSource") or {}
    rd = p.get("runDetails") or {}
    builder = (rd.get("builder") or {}).get("id", "")
    vcs = ((rd.get("metadata") or {}).get("buildkit_metadata") or {}).get("vcs") or {}
    deps = bd.get("resolvedDependencies") or []
    problems = []
    if req.get("frontend") != "dockerfile.v0":
        problems.append(f"frontend {req.get('frontend')!r}, not dockerfile.v0")
    if cfg.get("path") != "Dockerfile":
        problems.append(f"configSource.path {cfg.get('path')!r}, not the repository's Dockerfile")
    if args.get("build-arg:GIT_HASH") != commit:
        problems.append(f"GIT_HASH build arg {args.get('build-arg:GIT_HASH')!r}, not {commit}")
    if vcs.get("revision") != commit:
        problems.append(f"VCS revision {vcs.get('revision')!r}, not {commit}")
    if vcs.get("source") not in POLICY_VCS_SOURCES:
        problems.append(f"VCS source {vcs.get('source')!r}, not {POLICY_VCS_SOURCES[0]}")
    if not builder.startswith(POLICY_BUILDER_PREFIX):
        problems.append(f"builder id {builder!r} is not a run of {POLICY_REPO}")
    elif run_url is not None and not (builder == run_url or builder.startswith(run_url.rstrip("/") + "/")):
        problems.append(f"builder id {builder!r} is not this run {run_url}")
    for name, d in pins:
        hexd = d.split(":", 1)[1]
        if not any(f"digest={d}" in (x.get("uri") or "") or (x.get("digest") or {}).get("sha256") == hexd
                   for x in deps):
            problems.append(f"base image {name}@{d} is not among the resolved dependencies")
    if problems:
        raise Refused(f"{where}: provenance does not match the release policy: {'; '.join(problems)}")
    return {"predicateType": st.get("predicateType"), "builder": builder, "vcs_source": vcs.get("source"),
            "vcs_revision": vcs.get("revision"), "dockerfile": cfg.get("path"),
            "bases": [f"{n}@{d}" for n, d in pins]}


def verify(image: str, mode: str, commit: str, digest: str, children: dict[str, str],
           run_url: str | None) -> dict:
    tag = commit
    if mode == "release" and image != POLICY_IMAGE:
        raise Refused(f"mode release verifies only {POLICY_IMAGE}, not {image}")
    reg, repo = oci.split_repo(image)
    if mode == "ci" and reg.host.split(":")[0] not in ("localhost", "127.0.0.1"):
        raise Refused(f"mode ci verifies only a registry on localhost, not {reg.host}")
    if run_url is not None and not run_url.startswith(POLICY_BUILDER_PREFIX):
        raise Refused(f"--run-url {run_url} is not a run of {POLICY_REPO}")
    pins = pinned_bases(commit)

    # 1. The tag, then the digest.
    _, _, tagged = reg.manifest(repo, tag)
    if tagged != digest:
        raise Refused(f"TAG MOVED: {image}:{tag} is {tagged}, the release record says {digest}")
    body, mt, _ = reg.manifest(repo, digest)
    if mt != oci.INDEX:
        raise Refused(f"{digest} is {mt}, not an OCI image index")

    # 2. Exactly two runnable children, the ones this run produced.
    idx = json.loads(body)
    run, att, other = oci.classify(idx)
    if other:
        raise Refused(f"unclassified descriptors in the index: "
                      f"{[(o.get('digest'), o.get('platform')) for o in other]}")
    plats = [oci.platform_of(r) for r in run]
    if sorted(set(plats)) != sorted(plats):
        raise Refused(f"DUPLICATE PLATFORM in the index: {plats}")
    for p in oci.RELEASE_PLATFORMS:
        if p not in plats:
            raise Refused(f"MISSING CHILD: no runnable {p} in the index (has {plats})")
    extra = [p for p in plats if p not in oci.RELEASE_PLATFORMS]
    if extra:
        raise Refused(f"EXTRA PLATFORM in the index: {extra}")
    by_plat = {oci.platform_of(r): r for r in run}
    for p in oci.RELEASE_PLATFORMS:
        if by_plat[p]["digest"] != children[p]:
            raise Refused(f"SUBSTITUTED CHILD: the index's {p} is {by_plat[p]['digest']}, "
                          f"this release produced {children[p]}")
    owners = [a["annotations"][oci.REF_DIGEST] for a in att]
    for p in oci.RELEASE_PLATFORMS:
        if owners.count(children[p]) != 1:
            raise Refused(f"the {p} child has {owners.count(children[p])} attestation manifests, not 1")
    stray = [o for o in owners if o not in children.values()]
    if stray:
        raise Refused(f"attestation manifests for images outside the release: {stray}")

    # 3-4. Each child, its SBOM and provenance.
    gm = lambda d: reg.manifest(repo, d)[0]  # noqa: E731
    gb = lambda d: reg.blob(repo, d)  # noqa: E731
    summary = {"image": image, "tag": tag, "canonical_digest": digest, "commit": commit, "children": {}}
    for p in oci.RELEASE_PLATFORMS:
        d = children[p]
        a = next(x for x in att if x["annotations"][oci.REF_DIGEST] == d)
        try:
            info = oci.check_image(gm, gb, d, p, commit)
            sts = oci.statements(gm, gb, a["digest"], d)
        except oci.OciError as e:
            raise Refused(f"{p} child {d}: {e}")
        sboms = [s for s in sts if s["predicateType"] == oci.SPDX]
        provs = [s for s in sts if s["predicateType"] == oci.SLSA_V1]
        if not sboms:
            raise Refused(f"MISSING SBOM for the {p} child {d}")
        if len(provs) != 1:
            raise Refused(f"MISSING PROVENANCE for the {p} child {d} ({len(provs)} SLSA v1 statements)")
        summary["children"][p] = {
            "digest": d,
            "config": info["config"],
            "attestation_manifest": a["digest"],
            "sboms": [{"layer": s["layer"], **check_sbom(s["statement"], f"{p} SBOM {s['layer']}")}
                      for s in sboms],
            "provenance": {"layer": provs[0]["layer"],
                           **check_provenance(provs[0]["statement"], f"{p} provenance {provs[0]['layer']}",
                                              commit, pins, run_url)},
        }
    return summary


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", choices=("release", "ci"), required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--digest", required=True)
    ap.add_argument("--child", action="append", default=[], metavar="PLATFORM=DIGEST")
    ap.add_argument("--run-url")
    ap.add_argument("--summary", type=Path)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    try:
        if a.commit == "latest" or not re.fullmatch(r"[0-9a-f]{40}", a.commit):
            raise Refused(f"--commit must be the full 40-hex release commit (the tag); '{a.commit}' is not")
        if not oci.DIGEST.match(a.digest):
            raise Refused(f"--digest '{a.digest}' is not sha256:<64-hex>; a tag is never verified")
        children: dict[str, str] = {}
        for c in a.child:
            p, eq, d = c.partition("=")
            if not eq or p not in oci.RELEASE_PLATFORMS or not oci.DIGEST.match(d) or p in children:
                raise Refused(f"--child {c!r}: want one linux/amd64=sha256:... and one linux/arm64=sha256:...")
            children[p] = d
        if sorted(children) != sorted(oci.RELEASE_PLATFORMS):
            raise Refused(f"--child must name exactly {list(oci.RELEASE_PLATFORMS)}")
        if children["linux/amd64"] == children["linux/arm64"]:
            raise Refused("the two children cannot have the same digest")
        summary = verify(a.image, a.mode, a.commit, a.digest, children, a.run_url)
    except (Refused, oci.OciError) as e:
        print(f"RELEASE VERIFY FAIL: {e}", file=sys.stderr)
        return 1
    if a.summary:
        a.summary.write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    c = summary["children"]
    print(f"RELEASE VERIFIED: {a.image}:{a.commit} = {a.digest}; "
          f"linux/amd64 {c['linux/amd64']['digest']}, linux/arm64 {c['linux/arm64']['digest']}; "
          f"SBOM and SLSA v1 provenance valid for both.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Native Linux release archives: write the release record, and verify a release.

    native-release.py check-arch <dir> --commit <sha> --triple <x86_64|aarch64>-unknown-linux-gnu
    native-release.py record     <dir> --commit <sha> --pr <n> --approved-by <login> --run-url <url>
    native-release.py verify     <dir> --commit <sha>

A release of commit C is exactly these assets, and nothing else:

    sumchain-C-x86_64-unknown-linux-gnu.tar.gz       sumchain-C-aarch64-unknown-linux-gnu.tar.gz
    sumchain-C-x86_64-unknown-linux-gnu.spdx.json    sumchain-C-aarch64-unknown-linux-gnu.spdx.json
    sumchain-C-x86_64-unknown-linux-gnu.provenance.json
    sumchain-C-aarch64-unknown-linux-gnu.provenance.json
    release-record.txt                               SHA256SUMS

under the GitHub Release tag `release-C`. The operator never names an
architecture: the installer picks the archive from `uname -m`.

`verify` refuses unless: SHA256SUMS lists exactly those assets and every hash
matches; the record is for C and names both archives, both binaries and both
SBOMs with the hashes found; each archive holds exactly
`sumchain-C-<triple>/{sumchain,sumchain-wallet}` as regular executable files
(no links, no absolute or `..` paths); each binary is an ELF64 executable for
its triple's machine and hashes as recorded; each SBOM is a valid SPDX 2.x
document; each provenance is SLSA v1 from a BuildKit build of THIS repository
(builder id a run of SUM-INNOVATION/sum-chain, VCS source this repository and
revision C, GIT_HASH = C, the native Dockerfile, and every base image that
Dockerfile pins by digest AT C among the resolved dependencies).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

REPO = "SUM-INNOVATION/sum-chain"
BUILDER_PREFIX = f"https://github.com/{REPO}/actions/runs/"
VCS_SOURCES = (f"https://github.com/{REPO}", f"https://github.com/{REPO}.git")
DOCKERFILE = "tools/release/native.Dockerfile"
TRIPLES = {"x86_64-unknown-linux-gnu": 62, "aarch64-unknown-linux-gnu": 183}   # ELF e_machine
BINARIES = ("sumchain", "sumchain-wallet")
ROOT = Path(__file__).resolve().parents[2]
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class Refused(Exception):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def names(commit: str, triple: str) -> dict[str, str]:
    base = f"sumchain-{commit}-{triple}"
    return {"archive": f"{base}.tar.gz", "sbom": f"{base}.spdx.json", "provenance": f"{base}.provenance.json",
            "dir": base}


def expected_assets(commit: str) -> set[str]:
    out = {"release-record.txt", "SHA256SUMS"}
    for t in TRIPLES:
        n = names(commit, t)
        out |= {n["archive"], n["sbom"], n["provenance"]}
    return out


def pinned_bases(commit: str) -> list[tuple[str, str]]:
    try:
        text = subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{DOCKERFILE}"], check=True,
                              capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        raise Refused(f"cannot read {DOCKERFILE} at {commit}: {e.stderr.strip()}")
    pins, stages = [], set()
    for f, alias in re.findall(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", text):
        low = f.lower()
        if low in stages or low == "scratch":
            stages.add((alias or "").lower())
            continue
        stages.add((alias or "").lower())
        name, at, d = f.partition("@")
        if not at or not re.fullmatch(r"sha256:[0-9a-f]{64}", d):
            raise Refused(f"{DOCKERFILE} at {commit} has an unpinned base image: FROM {f}")
        pins.append((name, d))
    if not pins:
        raise Refused(f"no pinned FROM in {DOCKERFILE} at {commit}")
    return pins


def predicate(doc: dict) -> dict:
    """The predicate, whether the file holds an in-toto statement or the bare predicate."""
    return doc.get("predicate", doc) if isinstance(doc, dict) and "_type" in doc else doc


def check_sbom(data: bytes, where: str) -> dict:
    try:
        p = predicate(json.loads(data))
    except json.JSONDecodeError as e:
        raise Refused(f"{where}: SBOM is not JSON ({e})")
    pk, problems = p.get("packages"), []
    if not str(p.get("spdxVersion", "")).startswith("SPDX-2."):
        problems.append(f"spdxVersion {p.get('spdxVersion')!r}")
    if p.get("SPDXID") != "SPDXRef-DOCUMENT":
        problems.append(f"SPDXID {p.get('SPDXID')!r}")
    if not p.get("documentNamespace"):
        problems.append("no documentNamespace")
    if not (p.get("creationInfo") or {}).get("creators"):
        problems.append("no creationInfo.creators")
    if not isinstance(pk, list) or not pk:
        problems.append("no packages")
    elif any(not (x.get("name") and x.get("SPDXID")) for x in pk):
        problems.append("a package without name or SPDXID")
    if problems:
        raise Refused(f"{where}: invalid SPDX SBOM: {', '.join(problems)}")
    return {"spdxVersion": p["spdxVersion"], "packages": len(pk)}


def check_provenance(data: bytes, where: str, commit: str, pins: list[tuple[str, str]],
                     run_url: str | None = None) -> dict:
    try:
        p = predicate(json.loads(data))
    except json.JSONDecodeError as e:
        raise Refused(f"{where}: provenance is not JSON ({e})")
    bd = p.get("buildDefinition") or {}
    ext = bd.get("externalParameters") or {}
    req = ext.get("request") or {}
    args = req.get("args") or {}
    rd = p.get("runDetails") or {}
    builder = (rd.get("builder") or {}).get("id", "")
    vcs = ((rd.get("metadata") or {}).get("buildkit_metadata") or {}).get("vcs") or {}
    deps = bd.get("resolvedDependencies") or []
    problems = []
    if req.get("frontend") != "dockerfile.v0":
        problems.append(f"frontend {req.get('frontend')!r}")
    cfg = (ext.get("configSource") or {}).get("path") or args.get("filename")
    if cfg not in (DOCKERFILE, "native.Dockerfile"):
        problems.append(f"Dockerfile {cfg!r}, not {DOCKERFILE}")
    if args.get("build-arg:GIT_HASH") != commit:
        problems.append(f"GIT_HASH {args.get('build-arg:GIT_HASH')!r}, not {commit}")
    if vcs.get("revision") != commit:
        problems.append(f"VCS revision {vcs.get('revision')!r}, not {commit}")
    if vcs.get("source") not in VCS_SOURCES:
        problems.append(f"VCS source {vcs.get('source')!r}, not {VCS_SOURCES[0]}")
    if not builder.startswith(BUILDER_PREFIX):
        problems.append(f"builder {builder!r} is not a run of {REPO}")
    elif run_url and not (builder == run_url or builder.startswith(run_url.rstrip("/") + "/")):
        problems.append(f"builder {builder!r} is not this run {run_url}")
    for n, d in pins:
        if not any(f"digest={d}" in (x.get("uri") or "") or (x.get("digest") or {}).get("sha256") == d[7:]
                   for x in deps):
            problems.append(f"base image {n}@{d} is not among the resolved dependencies")
    if problems:
        raise Refused(f"{where}: provenance does not match the release policy: {'; '.join(problems)}")
    return {"builder": builder, "vcs_revision": vcs.get("revision"), "dockerfile": cfg}


def elf_machine(data: bytes) -> int | None:
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    return int.from_bytes(data[18:20], "little")


def check_archive(path: Path, commit: str, triple: str) -> dict[str, str]:
    """{binary name: sha256} of a valid archive for `triple`."""
    top = names(commit, triple)["dir"]
    want = {top, f"{top}/sumchain", f"{top}/sumchain-wallet"}
    got, out = set(), {}
    try:
        with tarfile.open(path, "r:gz") as t:
            for m in t.getmembers():
                n = m.name.rstrip("/")
                if n.startswith("/") or ".." in n.split("/") or "\\" in n:
                    raise Refused(f"{path.name}: unsafe path {m.name!r}")
                if m.issym() or m.islnk() or not (m.isfile() or m.isdir()):
                    raise Refused(f"{path.name}: {m.name!r} is not a regular file or directory")
                got.add(n)
                if m.isfile():
                    if not m.mode & 0o111:
                        raise Refused(f"{path.name}: {m.name!r} is not executable")
                    data = t.extractfile(m).read()
                    mach = elf_machine(data)
                    if mach != TRIPLES[triple]:
                        raise Refused(f"{path.name}: {m.name!r} is not an ELF64 {triple} executable "
                                      f"(e_machine {mach})")
                    out[n.rsplit("/", 1)[1]] = sha(data)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise Refused(f"{path.name}: not a readable .tar.gz ({e})")
    if got != want:
        raise Refused(f"{path.name}: members {sorted(got)}, want exactly {sorted(want)}")
    return out


def check_arch(d: Path, commit: str, triple: str, run_url: str | None = None) -> dict:
    n = names(commit, triple)
    meta_p = d / f"{triple}.json"
    if not meta_p.is_file():
        raise Refused(f"no {meta_p.name}")
    meta = json.loads(meta_p.read_text())
    pins = pinned_bases(commit)
    bins = check_archive(d / n["archive"], commit, triple)
    problems = []
    for key, got in (("archive_sha256", sha((d / n["archive"]).read_bytes())), ("binary_sha256", bins["sumchain"]),
                     ("wallet_sha256", bins["sumchain-wallet"]), ("sbom_sha256", sha((d / n["sbom"]).read_bytes())),
                     ("provenance_sha256", sha((d / n["provenance"]).read_bytes()))):
        if meta.get(key) != got:
            problems.append(f"{key} {meta.get(key)} != {got}")
    if meta.get("commit") != commit or meta.get("triple") != triple or meta.get("archive") != n["archive"]:
        problems.append("the metadata names another commit, triple or archive")
    if problems:
        raise Refused(f"{triple}: {'; '.join(problems)}")
    return {**meta, "sbom_check": check_sbom((d / n["sbom"]).read_bytes(), n["sbom"]),
            "provenance_check": check_provenance((d / n["provenance"]).read_bytes(), n["provenance"], commit,
                                                 pins, run_url)}


RECORD_KEYS = ("archive", "archive_sha256", "binary_sha256", "wallet_sha256", "sbom", "sbom_sha256",
               "provenance", "provenance_sha256")


def write_record(d: Path, commit: str, pr: str, approved_by: str, run_url: str) -> str:
    metas = {t: check_arch(d, commit, t, run_url) for t in TRIPLES}
    if metas["x86_64-unknown-linux-gnu"]["binary_sha256"] == metas["aarch64-unknown-linux-gnu"]["binary_sha256"]:
        raise Refused("the two architectures have the same binary")
    lines = [("release_commit", commit), ("release_tag", f"release-{commit}"), ("pull_request", f"#{pr}"),
             ("approved_by", approved_by), ("workflow_run", run_url)]
    for t, m in metas.items():
        k = t.split("-", 1)[0]
        lines += [(f"{k}_{f}", m[f]) for f in RECORD_KEYS]
        lines += [(f"{k}_version", m["version"]),
                  (f"{k}_sbom_summary", f"{m['sbom_check']['spdxVersion']} {m['sbom_check']['packages']} packages"),
                  (f"{k}_provenance_builder", m["provenance_check"]["builder"])]
    width = max(len(k) for k, _ in lines) + 1
    record = "".join(f"{(k + ':').ljust(width)} {v}\n" for k, v in lines)
    (d / "release-record.txt").write_text(record)
    files = sorted(expected_assets(commit) - {"SHA256SUMS"})
    (d / "SHA256SUMS").write_text("".join(f"{sha((d / f).read_bytes())}  {f}\n" for f in files))
    return record


def parse_record(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def verify(d: Path, commit: str) -> dict:
    present = {p.name for p in d.iterdir() if p.is_file()}
    want = expected_assets(commit)
    if present != want:
        raise Refused(f"assets {sorted(present ^ want)} differ from the release set "
                      f"(missing {sorted(want - present)}, unexpected {sorted(present - want)})")
    sums = {}
    for line in (d / "SHA256SUMS").read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not m:
            raise Refused(f"SHA256SUMS line {line!r} is malformed")
        sums[m.group(2)] = m.group(1)
    if set(sums) != want - {"SHA256SUMS"}:
        raise Refused(f"SHA256SUMS lists {sorted(sums)}, want {sorted(want - {'SHA256SUMS'})}")
    for f, h in sums.items():
        if sha((d / f).read_bytes()) != h:
            raise Refused(f"SHA256SUMS MISMATCH for {f}")
    rec = parse_record((d / "release-record.txt").read_text())
    if rec.get("release_commit") != commit or rec.get("release_tag") != f"release-{commit}":
        raise Refused(f"the release record is for {rec.get('release_commit')!r} / {rec.get('release_tag')!r}")
    pins = pinned_bases(commit)
    out = {}
    for t in TRIPLES:
        k, n = t.split("-", 1)[0], names(commit, t)
        bins = check_archive(d / n["archive"], commit, t)
        exp = {"archive": n["archive"], "archive_sha256": sums[n["archive"]], "binary_sha256": bins["sumchain"],
               "wallet_sha256": bins["sumchain-wallet"], "sbom": n["sbom"], "sbom_sha256": sums[n["sbom"]],
               "provenance": n["provenance"], "provenance_sha256": sums[n["provenance"]]}
        bad = [f"{k}_{f}: record {rec.get(f'{k}_{f}')!r}, found {v!r}" for f, v in exp.items() if rec.get(f"{k}_{f}") != v]
        if bad:
            raise Refused(f"RECORD MISMATCH {'; '.join(bad)}")
        check_sbom((d / n["sbom"]).read_bytes(), n["sbom"])
        check_provenance((d / n["provenance"]).read_bytes(), n["provenance"], commit, pins)
        out[t] = exp
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=("check-arch", "record", "verify"))
    ap.add_argument("dir", type=Path)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--triple")
    ap.add_argument("--pr")
    ap.add_argument("--approved-by")
    ap.add_argument("--run-url")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    try:
        if not HEX40.match(a.commit):
            raise Refused(f"--commit must be a full 40-hex sha, not {a.commit!r}")
        if a.cmd == "check-arch":
            if a.triple not in TRIPLES:
                raise Refused(f"--triple must be one of {sorted(TRIPLES)}")
            m = check_arch(a.dir, a.commit, a.triple, a.run_url)
            print(f"ARCH OK: {m['archive']} sha256 {m['archive_sha256']}, binary {m['binary_sha256']}")
        elif a.cmd == "record":
            if not (a.pr and a.approved_by and a.run_url):
                raise Refused("record needs --pr, --approved-by and --run-url")
            sys.stdout.write(write_record(a.dir, a.commit, a.pr, a.approved_by, a.run_url))
        else:
            v = verify(a.dir, a.commit)
            print(f"RELEASE VERIFIED: release-{a.commit}: " + "; ".join(
                f"{t} archive {m['archive_sha256']} binary {m['binary_sha256']}" for t, m in v.items()))
    except (Refused, OSError, KeyError, ValueError) as e:
        print(f"NATIVE RELEASE FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

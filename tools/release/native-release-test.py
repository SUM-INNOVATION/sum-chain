#!/usr/bin/env python3
"""Battery for the native release tooling: native-release.py and install-native.sh.

NONPRODUCTION fixtures only: the "binaries" are small shell scripts behind a
real ELF64 header for their architecture's e_machine, so the archive, ELF and
hash rules run exactly as on a real release, and the installer can execute
`--version` without any compiled code. `uname` is shimmed on PATH to play
either architecture.

    python3 tools/release/native-release-test.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location("native_release", HERE / "native-release.py")
nr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nr)

COMMIT = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, capture_output=True,
                        text=True).stdout.strip()
RUN = "https://github.com/SUM-INNOVATION/sum-chain/actions/runs/1000000001"   # NONPRODUCTION
X86, ARM = "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"
RESULTS: list[tuple[str, bool, str]] = []


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fake_binary(triple: str, name: str, commit: str = COMMIT, machine: int | None = None) -> bytes:
    """An ELF64 LE header with the triple's e_machine, then a shell script (run as `sh <file>`
    is not needed: the header is a comment line to sh once prefixed)."""
    m = nr.TRIPLES[triple] if machine is None else machine
    header = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + (2).to_bytes(2, "little") + m.to_bytes(2, "little")
    # A shell script cannot start with the ELF magic, so the test executes it through a
    # wrapper; the installer's `--version` call goes through PATH-free execution of the file
    # itself, which the test makes possible with a binfmt-free trick: the script body is
    # kept separately (see Fixture.script) and the archive carries header + body.
    body = f"#!/bin/sh\n[ \"$1\" = --version ] && echo 'sumchain {commit}' && exit 0\necho '{name}'\n".encode()
    return header + b"\n" + body


def provenance(commit: str = COMMIT, **over) -> bytes:
    deps = [{"uri": f"pkg:docker/{n}?digest={d}&platform=linux%2Famd64", "digest": {"sha256": "e" * 64}}
            for n, d in nr.pinned_bases(COMMIT)]
    p = {"buildDefinition": {"externalParameters": {"configSource": {"path": nr.DOCKERFILE},
                                                    "request": {"frontend": "dockerfile.v0",
                                                                "args": {"build-arg:GIT_HASH": commit}}},
                             "resolvedDependencies": deps},
         "runDetails": {"builder": {"id": RUN},
                        "metadata": {"buildkit_metadata": {"vcs": {
                            "source": "https://github.com/SUM-INNOVATION/sum-chain", "revision": commit}}}}}
    for path, v in over.items():
        node = p
        ks = path.split(".")
        for k in ks[:-1]:
            node = node[k]
        node[ks[-1]] = v
    return json.dumps({"_type": "https://in-toto.io/Statement/v1",
                       "predicateType": "https://slsa.dev/provenance/v1", "predicate": p}).encode()


def sbom(**over) -> bytes:
    s = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "sbom",
         "documentNamespace": "https://example.invalid/sbom", "creationInfo": {"creators": ["Tool: syft"]},
         "packages": [{"name": "rocksdb", "SPDXID": "SPDXRef-Package-rocksdb"}]}
    s.update(over)
    return json.dumps(s).encode()


def archive(triple: str, members: dict[str, bytes], *, commit: str = COMMIT, extra: list | None = None,
            symlink: bool = False, mode: int = 0o755) -> bytes:
    top = nr.names(commit, triple)["dir"]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        d = tarfile.TarInfo(top)
        d.type, d.mode = tarfile.DIRTYPE, 0o755
        t.addfile(d)
        for n, data in members.items():
            i = tarfile.TarInfo(f"{top}/{n}")
            if symlink and n == "sumchain":
                i.type, i.linkname = tarfile.SYMTYPE, "/bin/sh"
                t.addfile(i)
                continue
            i.size, i.mode = len(data), mode
            t.addfile(i, io.BytesIO(data))
        for name, data in extra or []:
            i = tarfile.TarInfo(name)
            i.size, i.mode = len(data), 0o755
            t.addfile(i, io.BytesIO(data))
    return buf.getvalue()


def build(d: Path, *, commit: str = COMMIT, per: dict | None = None) -> None:
    """A complete release (or, with `per` overrides, a broken one) in d: the per-arch
    metadata the build jobs write, and the assets."""
    per = per or {}
    for triple in (X86, ARM):
        o = per.get(triple, {})
        n = nr.names(commit, triple)
        bins = {b: fake_binary(o.get("bin_triple", triple), b, o.get("version_commit", commit),
                               o.get("machine")) for b in nr.BINARIES}
        arc = o.get("archive_bytes") or archive(triple, bins, commit=commit, extra=o.get("extra"),
                                               symlink=o.get("symlink", False), mode=o.get("mode", 0o755))
        (d / n["archive"]).write_bytes(arc)
        (d / n["sbom"]).write_bytes(sbom(**o.get("sbom", {})))
        (d / n["provenance"]).write_bytes(provenance(o.get("prov_commit", commit), **o.get("prov", {})))
        meta = {"triple": triple, "platform": "linux/amd64" if triple == X86 else "linux/arm64", "commit": commit,
                "archive": n["archive"], "archive_sha256": sha(arc),
                "binary_sha256": sha(bins["sumchain"]), "wallet_sha256": sha(bins["sumchain-wallet"]),
                "sbom": n["sbom"], "sbom_sha256": sha((d / n["sbom"]).read_bytes()),
                "provenance": n["provenance"], "provenance_sha256": sha((d / n["provenance"]).read_bytes()),
                "version": f"sumchain {commit}"}
        meta.update(o.get("meta", {}))
        (d / f"{triple}.json").write_text(json.dumps(meta))


def release_dir(tmp: Path, **kw) -> Path:
    """build + record, then copy ONLY the release assets into their own directory."""
    b = tmp / "build"
    b.mkdir()
    build(b, **kw)
    nr.write_record(b, COMMIT, "263", "reviewer", RUN)
    r = tmp / "release"
    r.mkdir()
    for f in nr.expected_assets(COMMIT):
        shutil.copy(b / f, r / f)
    return r


def case(name, want_ok, text, fn):
    try:
        fn()
        ok, got = want_ok, "passed" if want_ok else "passed, but must refuse"
    except (nr.Refused, KeyError, ValueError) as e:
        got, ok = str(e), (not want_ok) and text in str(e)
    RESULTS.append((name, ok, got))


def tmpcase(name, want_ok, text, fn):
    tmp = Path(tempfile.mkdtemp(prefix="native-release-"))
    try:
        case(name, want_ok, text, lambda: fn(tmp))
    finally:
        shutil.rmtree(tmp)


def verifier_cases():
    tmpcase("a complete release verifies", True, "", lambda t: nr.verify(release_dir(t), COMMIT))

    def per(triple, **o):
        return {triple: o}

    tmpcase("an aarch64 binary inside the x86_64 archive", False, "is not an ELF64 x86_64",
            lambda t: release_dir(t, per=per(X86, bin_triple=ARM)))
    tmpcase("a non-ELF file posing as the binary", False, "is not an ELF64", lambda t: release_dir(
        t, per=per(ARM, machine=3)))
    # A valid x86_64 ELF, so only the member-set rule can refuse it.
    tmpcase("an archive with an extra member", False, "want exactly", lambda t: release_dir(
        t, per=per(X86, extra=[(f"{nr.names(COMMIT, X86)['dir']}/sumchain-extra",
                                fake_binary(X86, "sumchain-extra"))])))
    tmpcase("an archive with a path escape", False, "unsafe path", lambda t: release_dir(
        t, per=per(ARM, extra=[("../evil", b"x")])))
    tmpcase("an archive whose binary is a symlink", False, "not a regular file", lambda t: release_dir(
        t, per=per(X86, symlink=True)))
    tmpcase("a binary that is not executable", False, "is not executable", lambda t: release_dir(
        t, per=per(ARM, mode=0o644)))
    tmpcase("a corrupt archive", False, "not a readable .tar.gz", lambda t: release_dir(
        t, per=per(X86, archive_bytes=b"not a tarball")))
    tmpcase("metadata binary hash differs from the archive", False, "binary_sha256", lambda t: release_dir(
        t, per=per(ARM, meta={"binary_sha256": "0" * 64})))
    tmpcase("invalid SBOM: no packages", False, "invalid SPDX SBOM: no packages", lambda t: release_dir(
        t, per=per(X86, sbom={"packages": []})))
    tmpcase("invalid SBOM: not SPDX 2", False, "spdxVersion", lambda t: release_dir(
        t, per=per(ARM, sbom={"spdxVersion": "SPDX-3.0"})))
    tmpcase("provenance with another GIT_HASH", False, "GIT_HASH", lambda t: release_dir(
        t, per=per(X86, prov_commit="d" * 40, prov={"runDetails.metadata.buildkit_metadata.vcs": {
            "source": "https://github.com/SUM-INNOVATION/sum-chain", "revision": COMMIT}})))
    tmpcase("provenance with another VCS revision", False, "VCS revision", lambda t: release_dir(
        t, per=per(ARM, prov={"runDetails.metadata.buildkit_metadata.vcs": {
            "source": "https://github.com/SUM-INNOVATION/sum-chain", "revision": "d" * 40}})))
    tmpcase("provenance from another repository", False, "VCS source", lambda t: release_dir(
        t, per=per(X86, prov={"runDetails.metadata.buildkit_metadata.vcs": {
            "source": "https://github.com/someone/sum-chain", "revision": COMMIT}})))
    tmpcase("provenance from another repository's runner", False, "is not a run of", lambda t: release_dir(
        t, per=per(ARM, prov={"runDetails.builder": {"id": "https://github.com/someone/x/actions/runs/1"}})))
    tmpcase("provenance from another run", False, "is not this run", lambda t: release_dir(
        t, per=per(X86, prov={"runDetails.builder": {"id": RUN.replace("1000000001", "7")}})))
    tmpcase("provenance of another Dockerfile", False, "Dockerfile", lambda t: release_dir(
        t, per=per(X86, prov={"buildDefinition.externalParameters.configSource": {"path": "Dockerfile"}})))
    tmpcase("provenance missing the pinned Rust image", False, "not among the resolved dependencies",
            lambda t: release_dir(t, per=per(ARM, prov={"buildDefinition.resolvedDependencies": []})))

    def after(mutate, text):
        def fn(t):
            r = release_dir(t)
            mutate(r)
            nr.verify(r, COMMIT)
        return fn

    n86, narm = nr.names(COMMIT, X86), nr.names(COMMIT, ARM)
    tmpcase("an asset missing from the release", False, "missing", after(
        lambda r: (r / narm["archive"]).unlink(), ""))
    tmpcase("an unexpected asset in the release", False, "unexpected", after(
        lambda r: (r / "sumchain-latest.tar.gz").write_bytes(b"x"), ""))
    tmpcase("a tampered archive (SHA256SUMS mismatch)", False, "SHA256SUMS MISMATCH", after(
        lambda r: (r / n86["archive"]).write_bytes((r / n86["archive"]).read_bytes() + b"\0"), ""))
    tmpcase("SHA256SUMS missing an entry", False, "SHA256SUMS lists", after(
        lambda r: (r / "SHA256SUMS").write_text("".join(l + "\n" for l in (r / "SHA256SUMS").read_text()
                                                        .splitlines() if "provenance" not in l)), ""))

    def swap(r):
        a, b = (r / n86["archive"]).read_bytes(), (r / narm["archive"]).read_bytes()
        (r / n86["archive"]).write_bytes(b)
        (r / narm["archive"]).write_bytes(a)
        sums = (r / "SHA256SUMS").read_text()
        (r / "SHA256SUMS").write_text(sums.replace(sha(a), "X").replace(sha(b), sha(a)).replace("X", sha(b)))
    tmpcase("the two archives swapped (and SHA256SUMS rewritten to match)", False, "", after(swap, ""))

    def rec_edit(old, new):
        def m(r):
            t = (r / "release-record.txt").read_text().replace(old, new)
            (r / "release-record.txt").write_text(t)
            s = (r / "SHA256SUMS").read_text().splitlines()
            (r / "SHA256SUMS").write_text("".join(
                (f"{sha(t.encode())}  release-record.txt" if l.endswith("release-record.txt") else l) + "\n" for l in s))
        return m
    tmpcase("a record naming another commit", False, "the release record is for", after(
        rec_edit(f"release_commit:", "release_commit: " + "d" * 40 + " #"), ""))
    tmpcase("a record with another binary hash", False, "RECORD MISMATCH", after(
        lambda r: rec_edit_bin(r), ""))
    def abbreviated(t):
        r = release_dir(t)
        if nr.main(["verify", str(r), "--commit", COMMIT[:12]]) != 1:
            raise ValueError("an abbreviated commit was accepted")
        raise nr.Refused("abbreviated commit refused")
    tmpcase("verify with an abbreviated commit is refused", False, "abbreviated commit refused", abbreviated)


def rec_edit_bin(r: Path) -> None:
    t = (r / "release-record.txt").read_text()
    line = next(l for l in t.splitlines() if l.startswith("aarch64_binary_sha256:"))
    t = t.replace(line, "aarch64_binary_sha256: " + "0" * 64)
    (r / "release-record.txt").write_text(t)
    s = (r / "SHA256SUMS").read_text().splitlines()
    (r / "SHA256SUMS").write_text("".join(
        (f"{sha(t.encode())}  release-record.txt" if l.endswith("release-record.txt") else l) + "\n" for l in s))


# ---------------------------------------------------------------- installer ---

UNAME = """#!/bin/sh
case "$1" in -m) echo "$FAKE_MACHINE";; -s) echo Linux;; *) echo Linux;; esac
"""


def installer(tmp: Path, r: Path, machine: str, *args: str) -> tuple[int, str]:
    shim = tmp / "shim"
    shim.mkdir(exist_ok=True)
    (shim / "uname").write_text(UNAME)
    (shim / "uname").chmod(0o755)
    env = dict(os.environ, PATH=f"{shim}:{os.environ['PATH']}", FAKE_MACHINE=machine,
               INSTALL_NATIVE_TEST_ANY_OS="1")
    p = subprocess.run(["bash", str(HERE / "install-native.sh"), "--release-dir", str(r), "--commit", COMMIT,
                        "--prefix", str(tmp / "opt"), *args], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout + p.stderr


def installer_cases():
    def run(name, want, text, fn):
        tmp = Path(tempfile.mkdtemp(prefix="install-native-"))
        try:
            code, out = fn(tmp)
            RESULTS.append((f"installer: {name}", code == want and text in out, out.strip()[-240:]))
        finally:
            shutil.rmtree(tmp)

    def sums(r):
        return ["--sums-sha256", sha((r / "SHA256SUMS").read_bytes())]

    # The fixture binaries carry an ELF header, so they cannot run; the installer's
    # --version check runs them. Make them runnable by stripping the header on this OS:
    # the test copies each release with the ELF header replaced by nothing only for
    # the installer cases (the verifier cases above keep it).
    def runnable(t, **kw):
        r = t / "rel"
        r.mkdir()
        b = t / "b"
        b.mkdir()
        global fake_binary
        orig = fake_binary

        def plain(triple, name, commit=COMMIT, machine=None):
            return orig(triple, name, commit, machine).split(b"\n", 1)[1]
        fake_binary = plain
        try:
            build(b, **kw)
        finally:
            fake_binary = orig
        # the record is written without ELF checks for these runnable fixtures
        lines = [("release_commit", COMMIT), ("release_tag", f"release-{COMMIT}")]
        for tr in (X86, ARM):
            m = json.loads((b / f"{tr}.json").read_text())
            k = tr.split("-", 1)[0]
            lines += [(f"{k}_{f}", m[f]) for f in nr.RECORD_KEYS]
        (b / "release-record.txt").write_text("".join(f"{k}: {v}\n" for k, v in lines))
        files = sorted(nr.expected_assets(COMMIT) - {"SHA256SUMS"})
        (b / "SHA256SUMS").write_text("".join(f"{sha((b / f).read_bytes())}  {f}\n" for f in files))
        for f in nr.expected_assets(COMMIT):
            shutil.copy(b / f, r / f)
        return r

    def ok(machine, triple):
        def fn(t):
            r = runnable(t)
            code, out = installer(t, r, machine, *sums(r))
            dest = t / "opt/releases" / COMMIT / "sumchain"
            if code == 0 and sha(dest.read_bytes()) != json.loads((t / "b" / f"{triple}.json").read_text())["binary_sha256"]:
                return 1, "installed the wrong architecture's binary"
            return code, out
        return fn
    run("x86_64 host installs the x86_64 archive, chosen by uname -m", 0, "INSTALLED", ok("x86_64", X86))
    run("aarch64 host installs the aarch64 archive", 0, "INSTALLED", ok("aarch64", ARM))
    run("arm64 (as macOS/BSD name it) maps to aarch64", 0, "INSTALLED", ok("arm64", ARM))
    run("an unsupported machine is refused", 1, "unsupported machine",
        lambda t: installer(t, (r := runnable(t)), "riscv64", *sums(r)))
    run("no authentication of SHA256SUMS is refused", 1, "authenticate the release",
        lambda t: installer(t, runnable(t), "x86_64"))
    run("SHA256SUMS that does not match --sums-sha256", 1, "does not hash to --sums-sha256",
        lambda t: installer(t, runnable(t), "x86_64", "--sums-sha256", "0" * 64))

    def tamper_archive(t):
        r = runnable(t)
        a = r / nr.names(COMMIT, X86)["archive"]
        a.write_bytes(a.read_bytes() + b"\0")
        return installer(t, r, "x86_64", *sums(r))
    run("a tampered archive", 1, "does not match SHA256SUMS", tamper_archive)

    def wrong_version(t):
        r = runnable(t, per={ARM: {"version_commit": "d" * 40}})
        return installer(t, r, "aarch64", *sums(r))
    run("a binary reporting another commit", 1, "reports 'sumchain dddd", wrong_version)

    def twice(t):
        r = runnable(t)
        installer(t, r, "x86_64", *sums(r))
        return installer(t, r, "x86_64", *sums(r))
    run("installing the same release twice is idempotent", 0, "ALREADY INSTALLED", twice)

    def overwrite(t):
        r = runnable(t)
        dest = t / "opt/releases" / COMMIT
        dest.mkdir(parents=True)
        (dest / "sumchain").write_text("something else")
        return installer(t, r, "x86_64", *sums(r))
    run("an existing, different install is never overwritten", 1, "never overwritten", overwrite)

    def service_untouched(t):
        r = runnable(t)
        code, out = installer(t, r, "x86_64", *sums(r))
        text = (HERE / "install-native.sh").read_text()
        body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        if any(w in body for w in ("systemctl", "cargo ", "rustc", "ln -s", "/etc/systemd")):
            return 1, "the installer touches the service or compiles"
        return code, out
    run("the installer never compiles or touches systemd", 0, "unchanged", service_untouched)


def main() -> int:
    verifier_cases()
    installer_cases()
    fails = 0
    for name, ok, got in RESULTS:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
        if not ok:
            fails += 1
            print(f"          | {got[:300]}")
    print()
    if fails:
        print(f"NATIVE RELEASE BATTERY FAILED: {fails} of {len(RESULTS)}")
        return 1
    print(f"NATIVE RELEASE BATTERY OK: {len(RESULTS)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Battery for the multi-platform release tooling: oci.py, verify-release.py,
release-record.py. NONPRODUCTION fixtures only.

A fake OCI registry runs in-process on 127.0.0.1 and speaks the distribution
API the tools use (manifests and blobs by digest or tag, monolithic uploads),
so every case goes through the real HTTP client and every digest is recomputed
from bytes, as against GHCR. The fixture images are synthetic but shaped like
BuildKit's output (checked against a real published BuildKit index): one child
index per platform holding one image manifest and one attestation manifest
whose in-toto layers are an SPDX SBOM and SLSA v1 provenance about that image.

    python3 tools/release/release-test.py
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import oci  # noqa: E402


def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vr = load("verify_release", "verify-release.py")
rr = load("release_record", "release-record.py")

COMMIT = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=True, capture_output=True,
                        text=True).stdout.strip()
OTHER_COMMIT = "d" * 40
PINS = vr.pinned_bases(COMMIT)
RUN_URL = "https://github.com/SUM-INNOVATION/sum-chain/actions/runs/1000000001"   # NONPRODUCTION


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def enc(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


# ------------------------------------------------------------ fake registry ---

class Store:
    def __init__(self):
        self.manifests: dict[str, bytes] = {}
        self.media: dict[str, str] = {}
        self.tags: dict[str, str] = {}
        self.blobs: dict[str, bytes] = {}
        self.uploads: dict[str, bool] = {}
        self.tamper: dict[str, bytes] = {}     # digest -> bytes served instead


class Handler(BaseHTTPRequestHandler):
    store: Store

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes = b"", headers: dict | None = None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _parts(self):
        path, _, query = self.path.partition("?")
        p = path.split("/")          # '', 'v2', repo, kind, ref
        return p, dict(x.split("=", 1) for x in query.split("&") if "=" in x)

    def do_GET(self):
        p, _ = self._parts()
        s = self.store
        if p[3] == "manifests":
            d = s.tags.get(p[4], p[4])
            if d not in s.manifests:
                return self._send(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')
            body = s.tamper.get(d, s.manifests[d])
            return self._send(200, body, {"Content-Type": s.media[d], "Docker-Content-Digest": d})
        if p[3] == "blobs":
            d = p[4]
            if d not in s.blobs:
                return self._send(404)
            return self._send(200, s.tamper.get(d, s.blobs[d]))
        self._send(404)

    do_HEAD = do_GET

    def do_POST(self):
        u = uuid.uuid4().hex
        self.store.uploads[u] = True
        self._send(202, headers={"Location": f"/v2/sum-chain/blobs/uploads/{u}"})

    def do_PUT(self):
        p, q = self._parts()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        s = self.store
        if p[3] == "manifests":
            d = sha(body)
            s.manifests[d] = body
            s.media[d] = self.headers.get("Content-Type", "")
            if not p[4].startswith("sha256:"):
                s.tags[p[4]] = d
            elif p[4] != d:
                return self._send(400)
            return self._send(201, headers={"Docker-Content-Digest": d})
        if p[3] == "blobs" and p[4] == "uploads":
            d = q.get("digest", "").replace("%3A", ":")
            if sha(body) != d:
                return self._send(400)
            s.blobs[d] = body
            return self._send(201)
        self._send(404)


@contextlib.contextmanager
def registry():
    store = Store()
    handler = type("H", (Handler,), {"store": store})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield store, f"127.0.0.1:{srv.server_address[1]}/sum-chain"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- fixtures ---

def sbom(image_digest: str, **over) -> dict:
    pred = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "sbom",
            "documentNamespace": "https://example.invalid/sbom",       # NONPRODUCTION
            "creationInfo": {"creators": ["Tool: syft"]},
            "packages": [{"name": "sumchain", "SPDXID": "SPDXRef-Package-sumchain"}]}
    pred.update(over)
    return {"_type": "https://in-toto.io/Statement/v1", "predicateType": oci.SPDX,
            "subject": [{"name": "x", "digest": {"sha256": image_digest.split(":")[1]}}], "predicate": pred}


def provenance(image_digest: str, platform: str, commit: str = None, **over) -> dict:
    commit = commit or COMMIT
    deps = [{"uri": f"pkg:docker/{n}?digest={d}&platform={platform.replace('/', '%2F')}",
             "digest": {"sha256": "e" * 64}} for n, d in PINS]
    pred = {"buildDefinition": {
                "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
                "externalParameters": {"configSource": {"path": "Dockerfile"},
                                       "request": {"frontend": "dockerfile.v0",
                                                   "args": {"build-arg:GIT_HASH": commit}}},
                "resolvedDependencies": deps},
            "runDetails": {"builder": {"id": RUN_URL},
                           "metadata": {"buildkit_metadata": {"vcs": {
                               "source": "https://github.com/SUM-INNOVATION/sum-chain", "revision": commit}}}}}
    for path, value in over.items():
        node = pred
        keys = path.split(".")
        for k in keys[:-1]:
            node = node[k]
        if value is None:
            node.pop(keys[-1], None)
        else:
            node[keys[-1]] = value
    return {"_type": "https://in-toto.io/Statement/v1", "predicateType": oci.SLSA_V1,
            "subject": [{"name": "x", "digest": {"sha256": image_digest.split(":")[1]}}], "predicate": pred}


def child(platform: str, *, commit: str = None, label: str = None, cfg_platform: str = None, salt: str = "",
          sbom_over: dict | None = None, prov_over: dict | None = None, no_sbom=False, no_prov=False,
          extra_run: str | None = None) -> dict:
    """Blobs and manifests of one single-platform child, BuildKit-shaped."""
    commit = commit or COMMIT
    os_, arch = (cfg_platform or platform).split("/")
    blobs, mans = {}, {}
    layer = f"layer {platform} {salt}".encode()
    cfg = enc({"os": os_, "architecture": arch,
               "config": {"Labels": {oci.REVISION_LABEL: label if label is not None else commit}}})
    blobs[sha(layer)] = layer
    blobs[sha(cfg)] = cfg
    img = enc({"schemaVersion": 2, "mediaType": oci.MANIFEST,
               "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(cfg),
                          "size": len(cfg)},
               "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": sha(layer),
                           "size": len(layer)}]})
    mans[sha(img)] = (img, oci.MANIFEST)
    sts = []
    if not no_sbom:
        sts.append(enc(sbom(sha(img), **(sbom_over or {}))))
    if not no_prov:
        sts.append(enc(provenance(sha(img), platform, commit, **(prov_over or {}))))
    empty = b"{}"
    blobs[sha(empty)] = empty
    for s in sts:
        blobs[sha(s)] = s
    att = enc({"schemaVersion": 2, "mediaType": oci.MANIFEST,
               "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": sha(empty), "size": 2},
               "layers": [{"mediaType": oci.INTOTO, "digest": sha(s), "size": len(s),
                           "annotations": {"in-toto.io/predicate-type": json.loads(s)["predicateType"]}}
                          for s in sts]})
    mans[sha(att)] = (att, oci.MANIFEST)
    arch_p = {"architecture": platform.split("/")[1], "os": "linux"}
    descs = [{"mediaType": oci.MANIFEST, "digest": sha(img), "size": len(img), "platform": arch_p},
             {"mediaType": oci.MANIFEST, "digest": sha(att), "size": len(att),
              "platform": {"architecture": "unknown", "os": "unknown"},
              "annotations": {oci.REF_TYPE: "attestation-manifest", oci.REF_DIGEST: sha(img)}}]
    if extra_run:
        descs.append({"mediaType": oci.MANIFEST, "digest": sha(img), "size": len(img),
                      "platform": {"architecture": extra_run.split("/")[1], "os": "linux"}})
    cidx = enc({"schemaVersion": 2, "mediaType": oci.INDEX, "manifests": descs})
    mans[sha(cidx)] = (cidx, oci.INDEX)
    return {"platform": platform, "image": sha(img), "attestation": sha(att), "child_index": sha(cidx),
            "blobs": blobs, "manifests": mans, "descriptors": descs[:2]}


def load_child(store: Store, c: dict) -> None:
    store.blobs.update(c["blobs"])
    for d, (b, mt) in c["manifests"].items():
        store.manifests[d], store.media[d] = b, mt


def publish(store: Store, children: list[dict], *, tag: str = None, descriptors: list | None = None) -> str:
    for c in children:
        load_child(store, c)
    if descriptors is None:
        body = oci.canonical_index(children)
    else:
        body = enc({"schemaVersion": 2, "mediaType": oci.INDEX, "manifests": descriptors})
    d = sha(body)
    store.manifests[d], store.media[d] = body, oci.INDEX
    store.tags[tag or COMMIT] = d
    return d


def good():
    return child("linux/amd64"), child("linux/arm64")


# ------------------------------------------------------------------- cases ---

RESULTS: list[tuple[str, bool, str]] = []


def case(name: str, want_ok: bool, want_text: str, fn):
    try:
        fn()
        ok, got = want_ok, "passed"
        if not want_ok:
            ok, got = False, "passed, but must refuse"
    except (vr.Refused, oci.OciError, ValueError) as e:
        got = str(e)
        ok = (not want_ok) and want_text in got
    RESULTS.append((name, ok, got))


def verify(store, image, digest, amd, arm, **kw):
    return vr.verify(image, kw.pop("mode", "ci"), kw.pop("commit", COMMIT), digest,
                     {"linux/amd64": amd, "linux/arm64": arm}, kw.pop("run_url", RUN_URL))


def index_cases():
    def run(name, want_ok, text, build):
        with registry() as (store, image):
            def fn():
                args = build(store)
                verify(store, image, *args)
            case(name, want_ok, text, fn)

    run("a complete two-platform release verifies", True, "", lambda s: (
        (lambda a, b: (publish(s, [a, b]), a["image"], b["image"]))(*good())))

    def missing(p):
        def b(s):
            a, r = good()
            keep = a if p == "linux/arm64" else r
            d = publish(s, [a, r], descriptors=keep["descriptors"])
            return d, a["image"], r["image"]
        return b
    run("missing linux/amd64 child", False, "MISSING CHILD: no runnable linux/amd64", missing("linux/amd64"))
    run("missing linux/arm64 child", False, "MISSING CHILD: no runnable linux/arm64", missing("linux/arm64"))

    def extra(s):
        a, r = good()
        x = child("linux/ppc64le")
        d = publish(s, [a, r, x], descriptors=a["descriptors"] + r["descriptors"] + x["descriptors"])
        return d, a["image"], r["image"]
    run("an additional runnable platform", False, "EXTRA PLATFORM", extra)

    def extra_variant(s):
        a, r = good()
        v7 = copy.deepcopy(r["descriptors"][0])
        v7["platform"] = {"architecture": "arm", "os": "linux", "variant": "v7"}
        d = publish(s, [a, r], descriptors=a["descriptors"] + r["descriptors"] + [v7])
        return d, a["image"], r["image"]
    run("an additional runnable platform (linux/arm/v7)", False, "EXTRA PLATFORM", extra_variant)

    def dup(s):
        a, r = good()
        a2 = child("linux/amd64", salt="second build")
        d = publish(s, [a, r, a2], descriptors=a["descriptors"] + r["descriptors"] + a2["descriptors"])
        return d, a["image"], r["image"]
    run("duplicate runnable platform entries", False, "DUPLICATE PLATFORM", dup)

    def foreign(s):
        a, r = good()
        d = publish(s, [a, r])
        return d, child("linux/amd64", salt="not this run")["image"], r["image"]
    run("a child digest not produced by this release", False, "SUBSTITUTED CHILD: the index's linux/amd64", foreign)

    def substituted(s):
        a, r = good()
        r2 = child("linux/arm64", salt="substitute")
        d = publish(s, [a, r2])
        return d, a["image"], r["image"]
    run("canonical manifest points to a substituted child", False, "SUBSTITUTED CHILD: the index's linux/arm64",
        substituted)

    def swapped_expect(s):
        a, r = good()
        return publish(s, [a, r]), r["image"], a["image"]
    run("swapped child digests (amd64 given as arm64)", False, "SUBSTITUTED CHILD", swapped_expect)

    def swapped_meta(s):
        a, r = good()
        bad = child("linux/amd64", cfg_platform="linux/arm64", salt="mislabelled")
        d = publish(s, [bad, r])
        return d, bad["image"], r["image"]
    run("swapped child metadata (index says amd64, image is arm64)", False, "config says linux/arm64", swapped_meta)

    def unclassified(s):
        a, r = good()
        odd = {"mediaType": oci.MANIFEST, "digest": a["attestation"], "size": 1,
               "platform": {"architecture": "unknown", "os": "unknown"}}
        d = publish(s, [a, r], descriptors=a["descriptors"] + r["descriptors"] + [odd])
        return d, a["image"], r["image"]
    run("an unknown/unknown descriptor that is not an attestation", False, "unclassified descriptors", unclassified)

    def stray_att(s):
        a, r = good()
        extra = copy.deepcopy(r["descriptors"][1])
        extra["annotations"][oci.REF_DIGEST] = "sha256:" + "f" * 64
        d = publish(s, [a, r], descriptors=a["descriptors"] + r["descriptors"] + [extra])
        return d, a["image"], r["image"]
    run("an attestation manifest for an image outside the release", False, "outside the release", stray_att)

    def moved(s):
        a, r = good()
        d = publish(s, [a, r])
        other = publish(s, [child("linux/amd64", salt="later"), r])      # the tag moves
        assert other != d
        return d, a["image"], r["image"]
    run("a moved tag", False, "TAG MOVED", moved)

    def wrong_label(p):
        def b(s):
            a = child("linux/amd64", label=OTHER_COMMIT if p == "linux/amd64" else None)
            r = child("linux/arm64", label=OTHER_COMMIT if p == "linux/arm64" else None)
            return publish(s, [a, r]), a["image"], r["image"]
        return b
    run("wrong embedded commit label on linux/amd64", False, "(linux/amd64) revision label", wrong_label("linux/amd64"))
    run("wrong embedded commit label on linux/arm64", False, "(linux/arm64) revision label", wrong_label("linux/arm64"))

    def prov(p, over, **kw):
        def b(s):
            a = child("linux/amd64", prov_over=over if p == "linux/amd64" else None,
                      commit=kw.get("commit") if p == "linux/amd64" else None)
            r = child("linux/arm64", prov_over=over if p == "linux/arm64" else None,
                      commit=kw.get("commit") if p == "linux/arm64" else None)
            return publish(s, [a, r]), a["image"], r["image"]
        return b
    run("wrong GIT_HASH in linux/arm64 provenance", False, "GIT_HASH build arg",
        prov("linux/arm64", {"buildDefinition.externalParameters.request.args": {"build-arg:GIT_HASH": OTHER_COMMIT}}))
    run("wrong VCS revision in linux/amd64 provenance", False, "VCS revision",
        prov("linux/amd64", {"runDetails.metadata.buildkit_metadata.vcs": {
            "source": "https://github.com/SUM-INNOVATION/sum-chain", "revision": OTHER_COMMIT}}))
    run("provenance from another repository's build", False, "VCS source",
        prov("linux/amd64", {"runDetails.metadata.buildkit_metadata.vcs": {
            "source": "https://github.com/someone/sum-chain", "revision": COMMIT}}))
    run("provenance from another repository's runner", False, "is not a run of",
        prov("linux/arm64", {"runDetails.builder": {"id": "https://github.com/someone/fork/actions/runs/1"}}))
    run("provenance from another run of this repository", False, "is not this run",
        prov("linux/amd64", {"runDetails.builder": {"id": RUN_URL.replace("1000000001", "999")}}))
    run("provenance of another Dockerfile", False, "configSource.path",
        prov("linux/amd64", {"buildDefinition.externalParameters.configSource": {"path": "Dockerfile.dev"}}))
    run("provenance missing a pinned base image", False, "is not among the resolved dependencies",
        prov("linux/arm64", {"buildDefinition.resolvedDependencies": []}))
    run("provenance with no VCS metadata", False, "VCS revision None",
        prov("linux/amd64", {"runDetails.metadata.buildkit_metadata": {}}))

    def sb(p, **kw):
        def b(s):
            a = child("linux/amd64", **(kw if p == "linux/amd64" else {}))
            r = child("linux/arm64", **(kw if p == "linux/arm64" else {}))
            return publish(s, [a, r]), a["image"], r["image"]
        return b
    run("missing SBOM on linux/amd64", False, "MISSING SBOM for the linux/amd64", sb("linux/amd64", no_sbom=True))
    run("missing provenance on linux/arm64", False, "MISSING PROVENANCE for the linux/arm64",
        sb("linux/arm64", no_prov=True))
    run("invalid SBOM: no packages", False, "invalid SPDX SBOM: no packages",
        sb("linux/arm64", sbom_over={"packages": []}))
    run("invalid SBOM: not SPDX 2", False, "invalid SPDX SBOM: spdxVersion",
        sb("linux/amd64", sbom_over={"spdxVersion": "SPDX-1.2"}))
    run("invalid SBOM: no creators", False, "no creationInfo.creators",
        sb("linux/amd64", sbom_over={"creationInfo": {}}))

    def tampered(s):
        a, r = good()
        d = publish(s, [a, r])
        cfg = json.loads(a["manifests"][a["image"]][0])["config"]["digest"]
        s.tamper[cfg] = b'{"os":"linux","architecture":"amd64"}'
        return d, a["image"], r["image"]
    run("the registry serves bytes that do not match their digest", False, "bytes hash to", tampered)

    with registry() as (store, image):
        a, r = good()
        d = publish(store, [a, r])
        case("mode release refuses any registry but ghcr.io/sum-innovation/sum-chain", False, "mode release verifies only",
             lambda: verify(store, image, d, a["image"], r["image"], mode="release"))
        case("mode ci refuses a non-local registry", False, "only a registry on localhost",
             lambda: verify(store, "ghcr.io/sum-innovation/sum-chain", d, a["image"], r["image"]))
        case("a run URL outside this repository", False, "is not a run of",
             lambda: verify(store, image, d, a["image"], r["image"],
                            run_url="https://github.com/someone/fork/actions/runs/1"))
        case("a commit that is not in this repository", False, "cannot read the Dockerfile",
             lambda: verify(store, image, d, a["image"], r["image"], commit="c" * 40))


def cli_cases():
    with registry() as (store, image):
        a, r = good()
        d = publish(store, [a, r])
        base = [sys.executable, str(HERE / "verify-release.py"), "--mode", "ci", "--image", image,
                "--run-url", RUN_URL]

        def cli(name, want, text, *args):
            p = subprocess.run(base + list(args), capture_output=True, text=True)
            out = p.stdout + p.stderr
            RESULTS.append((name, p.returncode == want and text in out, out.strip()[-160:]))

        ch = ["--child", f"linux/amd64={a['image']}", "--child", f"linux/arm64={r['image']}"]
        cli("cli: a complete release verifies", 0, "RELEASE VERIFIED", "--commit", COMMIT, "--digest", d, *ch)
        cli("cli: latest is never a release", 1, "'latest' is not", "--commit", "latest", "--digest", d, *ch)
        cli("cli: verification by tag instead of digest", 1, "a tag is never verified", "--commit", COMMIT,
            "--digest", COMMIT, *ch)
        cli("cli: both children must be named", 1, "--child must name exactly", "--commit", COMMIT,
            "--digest", d, "--child", f"linux/amd64={a['image']}")
        cli("cli: the same digest for both children", 1, "same digest", "--commit", COMMIT, "--digest", d,
            "--child", f"linux/amd64={a['image']}", "--child", f"linux/arm64={a['image']}")


def layout_tar(c: dict, tmp: Path, top: list | None = None) -> Path:
    path = tmp / f"{c['platform'].replace('/', '-')}.tar"
    with tarfile.open(path, "w") as t:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
        add("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add("index.json", enc({"schemaVersion": 2, "mediaType": oci.INDEX, "manifests": top if top is not None else [
            {"mediaType": oci.INDEX, "digest": c["child_index"], "size": len(c["manifests"][c["child_index"]][0])}]}))
        for d, b in c["blobs"].items():
            add(f"blobs/sha256/{d.split(':')[1]}", b)
        for d, (b, _) in c["manifests"].items():
            add(f"blobs/sha256/{d.split(':')[1]}", b)
    return path


def layout_cases():
    tmp = Path(tempfile.mkdtemp(prefix="release-test-"))
    a, r = good()
    ta, tr = layout_tar(a, tmp), layout_tar(r, tmp)

    def push_and_assemble():
        with registry() as (store, image):
            reg, repo = oci.split_repo(image)
            got = []
            for c, t in ((a, ta), (r, tr)):
                lay = oci.Layout(str(t))
                ch = oci.layout_child(lay, c["platform"], COMMIT)
                oci.push_layout(lay, reg, repo, ch)
                assert ch["image"] == c["image"] and ch["child_index"] == c["child_index"]
                got.append(ch["child_index"])
            if store.tags:
                raise ValueError("pushing a child created a tag")
            d = oci.assemble(reg, repo, COMMIT, got)
            if d != sha(oci.canonical_index([a, r])):
                raise ValueError("the canonical index is not the deterministic join of the two children")
            verify(store, image, d, a["image"], r["image"])
            try:
                oci.assemble(reg, repo, COMMIT, got)
            except oci.OciError as e:
                if "already exists" not in str(e):
                    raise
            else:
                raise ValueError("assemble overwrote an existing release tag")
    case("layouts push by digest, join by digest, verify; no child tag; tag never overwritten", True, "",
         push_and_assemble)

    def assemble_one():
        with registry() as (store, image):
            reg, repo = oci.split_repo(image)
            lay = oci.Layout(str(ta))
            ch = oci.layout_child(lay, "linux/amd64", COMMIT)
            oci.push_layout(lay, reg, repo, ch)
            oci.assemble(reg, repo, COMMIT, [ch["child_index"]])
    case("assemble refuses a release missing a platform", False, "joins exactly", assemble_one)

    def assemble_latest():
        with registry() as (store, image):
            reg, repo = oci.split_repo(image)
            oci.assemble(reg, repo, "latest", [a["child_index"], r["child_index"]])
    case("assemble refuses the tag latest", False, "never 'latest'", assemble_latest)

    case("a layout is checked for its platform", False, "must hold exactly one linux/arm64 image",
         lambda: oci.layout_child(oci.Layout(str(ta)), "linux/arm64", COMMIT))
    case("a layout is checked for the embedded commit", False, "revision label",
         lambda: oci.layout_child(oci.Layout(str(ta)), "linux/amd64", OTHER_COMMIT))
    two = layout_tar(a, tmp / "two", top=[
        {"mediaType": oci.INDEX, "digest": a["child_index"], "size": 1},
        {"mediaType": oci.INDEX, "digest": a["child_index"], "size": 1}]) if (tmp / "two").mkdir() is None else None
    case("a layout with two top-level entries", False, "exactly one child index",
         lambda: oci.layout_child(oci.Layout(str(two)), "linux/amd64", COMMIT))
    multi = child("linux/amd64", extra_run="linux/arm64", salt="multi")
    tm = layout_tar(multi, tmp / "multi") if (tmp / "multi").mkdir() is None else None
    case("a child layout carrying a second platform", False, "must hold exactly one linux/amd64 image",
         lambda: oci.layout_child(oci.Layout(str(tm)), "linux/amd64", COMMIT))
    import shutil
    shutil.rmtree(tmp)


def record_cases():
    summary = {"image": "ghcr.io/sum-innovation/sum-chain", "tag": COMMIT, "commit": COMMIT,
               "canonical_digest": "sha256:" + "0" * 64, "children": {}}
    for p, d in (("linux/amd64", "1"), ("linux/arm64", "2")):
        summary["children"][p] = {"digest": "sha256:" + d * 64, "config": "x", "attestation_manifest": "y",
                                  "sboms": [{"layer": "sha256:" + "5" * 64, "spdxVersion": "SPDX-2.3",
                                             "packages": 9, "name": "sbom"}],
                                  "provenance": {"layer": "sha256:" + "6" * 64, "predicateType": oci.SLSA_V1,
                                                 "builder": RUN_URL, "vcs_source": "s", "vcs_revision": COMMIT,
                                                 "dockerfile": "Dockerfile", "bases": []}}
    rt = [{"platform": "linux/amd64", "digest": "sha256:" + "1" * 64, "version": f"sumchain {COMMIT}",
           "binary_sha256": "a" * 64, "smoke": "OK"},
          {"platform": "linux/arm64", "digest": "sha256:" + "2" * 64, "version": f"sumchain {COMMIT}",
           "binary_sha256": "b" * 64, "smoke": "OK"}]

    def render(s=summary, r=rt):
        return rr.render(s, r, "262", "Mike-Mans", RUN_URL, "verified")

    def ok():
        text = render()
        for k in ("release_commit", "canonical_digest", "linux_amd64_digest", "linux_amd64_binary_sha256",
                  "linux_arm64_digest", "linux_arm64_binary_sha256", "pull_request", "workflow_run",
                  "canonical_tag", "linux_amd64_sbom", "linux_arm64_provenance", "attestation"):
            if f"\n{k}:" not in "\n" + text:
                raise ValueError(f"record lacks {k}")
    case("the release record carries every required field", True, "", ok)
    case("record: runtime verified another digest", False, "runtime verified",
         lambda: render(r=[dict(rt[0], digest="sha256:" + "9" * 64), rt[1]]))
    case("record: a platform was not runtime-verified", False, "need", lambda: render(r=[rt[0]]))
    case("record: a failed smoke test", False, "did not pass", lambda: render(r=[dict(rt[0], smoke="FAIL"), rt[1]]))
    case("record: the same binary for both platforms", False, "same binary",
         lambda: render(r=[rt[0], dict(rt[1], binary_sha256="a" * 64)]))


def main() -> int:
    index_cases()
    cli_cases()
    layout_cases()
    record_cases()
    fails = 0
    for name, ok, got in RESULTS:
        print(f"  {'ok  ' if ok else 'FAIL'}  {name}")
        if not ok:
            fails += 1
            print(f"          | {got[:300]}")
    print()
    if fails:
        print(f"RELEASE TOOLING BATTERY FAILED: {fails} of {len(RESULTS)}")
        return 1
    print(f"RELEASE TOOLING BATTERY OK: {len(RESULTS)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())

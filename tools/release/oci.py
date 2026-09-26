#!/usr/bin/env python3
"""Minimal OCI registry client and layout reader for the release. Stdlib only.

Why not a third-party tool: the release needs to push two single-platform OCI
layouts BY DIGEST, join them into one index BY DIGEST, and read everything back
with every digest recomputed from the bytes received. Each step here is small
enough to test against a fake registry (tools/release/release-test.py), and no
extra binary has to be trusted inside the job that holds `packages: write`.

    oci.py inspect-layout <layout.tar> --platform linux/amd64 --commit <sha>
    oci.py push-layout    <layout.tar> <registry/repo> --platform ... --commit ...
    oci.py assemble       <registry/repo> --tag <commit> <child-index-digest> <child-index-digest>
    oci.py absent         <registry/repo> <tag>                 (exit 0 only if the tag does not exist)
    oci.py manifest       <registry/repo>@<digest|tag>          (raw bytes to stdout)
    oci.py blob           <registry/repo> <digest>              (raw bytes to stdout)

Credentials, when the registry asks for them: OCI_USERNAME / OCI_PASSWORD.
A registry on localhost or 127.0.0.1 is spoken to over plain HTTP; every other
registry over HTTPS.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
ACCEPT = ", ".join([INDEX, MANIFEST, DOCKER_LIST, DOCKER_MANIFEST])
INTOTO = "application/vnd.in-toto+json"
SPDX = "https://spdx.dev/Document"
SLSA_V1 = "https://slsa.dev/provenance/v1"
REF_TYPE = "vnd.docker.reference.type"
REF_DIGEST = "vnd.docker.reference.digest"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RELEASE_PLATFORMS = ("linux/amd64", "linux/arm64")
REVISION_LABEL = "org.opencontainers.image.revision"


class OciError(Exception):
    pass


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def platform_of(desc: dict) -> str | None:
    """"os/arch" of a RUNNABLE descriptor, or None for anything else.

    An arm64 child may carry variant v8; that is the same platform. Any other
    variant is a different platform and is reported with it.
    """
    p = desc.get("platform") or {}
    os_, arch = p.get("os"), p.get("architecture")
    if not os_ or not arch or os_ == "unknown" or arch == "unknown":
        return None
    variant = p.get("variant")
    if variant and not (arch == "arm64" and variant == "v8"):
        return f"{os_}/{arch}/{variant}"
    return f"{os_}/{arch}"


def is_attestation(desc: dict) -> bool:
    a = desc.get("annotations") or {}
    p = desc.get("platform") or {}
    return (a.get(REF_TYPE) == "attestation-manifest" and DIGEST.match(a.get(REF_DIGEST, "") or "") is not None
            and p.get("os") == "unknown" and p.get("architecture") == "unknown")


def classify(index: dict) -> tuple[list[dict], list[dict], list[dict]]:
    """(runnable, attestation, unclassified) descriptors of an index."""
    run, att, other = [], [], []
    for d in index.get("manifests") or []:
        if is_attestation(d):
            att.append(d)
        elif platform_of(d) is not None:
            run.append(d)
        else:
            other.append(d)
    return run, att, other


# ---------------------------------------------------------------- registry ---

class Registry:
    def __init__(self, host: str):
        self.host = host
        local = host.split(":")[0] in ("localhost", "127.0.0.1")
        self.base = ("http://" if local else "https://") + host
        self.tokens: dict[str, str] = {}

    def _auth_header(self, www: str, scope_hint: str) -> str | None:
        if www.lower().startswith("basic"):
            u, p = os.environ.get("OCI_USERNAME", ""), os.environ.get("OCI_PASSWORD", "")
            return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode() if u or p else None
        if not www.lower().startswith("bearer"):
            return None
        params = dict(re.findall(r'(\w+)="([^"]*)"', www))
        q = {"service": params.get("service", "")}
        scope = params.get("scope") or scope_hint
        if scope:
            q["scope"] = scope
        req = urllib.request.Request(params["realm"] + "?" + urllib.parse.urlencode(q))
        u, p = os.environ.get("OCI_USERNAME", ""), os.environ.get("OCI_PASSWORD", "")
        if u or p:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode())
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.load(r)
        tok = body.get("token") or body.get("access_token")
        return "Bearer " + tok if tok else None

    def request(self, method: str, path: str, repo: str, *, data: bytes | None = None,
                headers: dict | None = None, push: bool = False) -> tuple[int, dict, bytes]:
        url = path if path.startswith("http") else self.base + path
        scope = f"repository:{repo}:" + ("pull,push" if push else "pull")
        for attempt in (0, 1):
            h = dict(headers or {})
            if scope in self.tokens:
                h["Authorization"] = self.tokens[scope]
            req = urllib.request.Request(url, data=data, method=method, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=300) as r:
                    return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
            except urllib.error.HTTPError as e:
                body = e.read()
                if e.code == 401 and attempt == 0:
                    auth = self._auth_header(e.headers.get("WWW-Authenticate", ""), scope)
                    if auth:
                        self.tokens[scope] = auth
                        continue
                return e.code, {k.lower(): v for k, v in e.headers.items()}, body
        raise OciError("unreachable")

    # Reads -- every digest recomputed from the bytes.
    def manifest(self, repo: str, ref: str) -> tuple[bytes, str, str]:
        """(bytes, media type, digest computed from the bytes)."""
        st, h, body = self.request("GET", f"/v2/{repo}/manifests/{ref}", repo, headers={"Accept": ACCEPT})
        if st != 200:
            raise OciError(f"GET manifest {repo}:{ref} -> HTTP {st}: {body[:200]!r}")
        d = sha256(body)
        if ref.startswith("sha256:") and d != ref:
            raise OciError(f"manifest {repo}@{ref} bytes hash to {d}")
        mt = json.loads(body).get("mediaType") or h.get("content-type", "")
        return body, mt, d

    def manifest_exists(self, repo: str, ref: str) -> bool:
        st, _, body = self.request("GET", f"/v2/{repo}/manifests/{ref}", repo, headers={"Accept": ACCEPT},
                                   push=True)
        if st == 200:
            return True
        if st == 404:
            return False
        raise OciError(f"cannot tell whether {repo}:{ref} exists: HTTP {st}: {body[:200]!r}")

    def blob(self, repo: str, digest: str) -> bytes:
        st, _, body = self.request("GET", f"/v2/{repo}/blobs/{digest}", repo)
        if st != 200:
            raise OciError(f"GET blob {repo}@{digest} -> HTTP {st}")
        if sha256(body) != digest:
            raise OciError(f"blob {repo}@{digest} bytes hash to {sha256(body)}")
        return body

    # Writes.
    def blob_exists(self, repo: str, digest: str) -> bool:
        st, _, _ = self.request("HEAD", f"/v2/{repo}/blobs/{digest}", repo, push=True)
        return st == 200

    def push_blob(self, repo: str, digest: str, data: bytes) -> None:
        if sha256(data) != digest:
            raise OciError(f"refusing to push {digest}: bytes hash to {sha256(data)}")
        if self.blob_exists(repo, digest):
            return
        st, h, body = self.request("POST", f"/v2/{repo}/blobs/uploads/", repo, push=True, data=b"")
        if st not in (201, 202):
            raise OciError(f"start upload {repo}: HTTP {st}: {body[:200]!r}")
        loc = h.get("location", "")
        if not loc.startswith("http"):
            loc = self.base + loc
        sep = "&" if "?" in loc else "?"
        st, _, body = self.request("PUT", f"{loc}{sep}digest={urllib.parse.quote(digest)}", repo, push=True,
                                   data=data, headers={"Content-Type": "application/octet-stream"})
        if st != 201:
            raise OciError(f"upload {digest} to {repo}: HTTP {st}: {body[:200]!r}")

    def put_manifest(self, repo: str, ref: str, data: bytes, media_type: str) -> str:
        d = sha256(data)
        if ref.startswith("sha256:") and ref != d:
            raise OciError(f"refusing to put {ref}: bytes hash to {d}")
        st, _, body = self.request("PUT", f"/v2/{repo}/manifests/{ref}", repo, push=True, data=data,
                                   headers={"Content-Type": media_type})
        if st != 201:
            raise OciError(f"PUT manifest {repo}:{ref}: HTTP {st}: {body[:200]!r}")
        return d


def split_repo(ref: str) -> tuple[Registry, str]:
    host, _, repo = ref.partition("/")
    if not repo or "." not in host and ":" not in host and host != "localhost":
        raise OciError(f"'{ref}' is not <registry>/<repository>")
    return Registry(host), repo


# ------------------------------------------------------------------ layout ---

class Layout:
    """An OCI image layout tarball, as `docker buildx build --output type=oci,tar=true` writes."""

    def __init__(self, path: str):
        self.blobs: dict[str, bytes] = {}
        with tarfile.open(path) as t:
            members = {m.name.lstrip("./"): m for m in t.getmembers() if m.isfile()}
            if "oci-layout" not in members or "index.json" not in members:
                raise OciError(f"{path} is not an OCI layout (no oci-layout / index.json)")
            self.index = json.loads(t.extractfile(members["index.json"]).read())
            for name, m in members.items():
                if name.startswith("blobs/sha256/"):
                    data = t.extractfile(m).read()
                    d = "sha256:" + name.rsplit("/", 1)[1]
                    if sha256(data) != d:
                        raise OciError(f"{path}: blob {d} bytes hash to {sha256(data)}")
                    self.blobs[d] = data

    def get(self, digest: str) -> bytes:
        if digest not in self.blobs:
            raise OciError(f"layout is missing blob {digest}")
        return self.blobs[digest]


def describe_child(get_manifest, get_blob, child_index_digest: str, platform: str, commit: str) -> dict:
    """Validate one single-platform child index and describe it.

    get_manifest(digest) -> bytes and get_blob(digest) -> bytes read from a
    layout or a registry; either way every digest was recomputed on read.
    """
    idx = json.loads(get_manifest(child_index_digest))
    if idx.get("mediaType") != INDEX:
        raise OciError(f"child {child_index_digest} is {idx.get('mediaType')}, not an OCI index")
    run, att, other = classify(idx)
    if other:
        raise OciError(f"child {child_index_digest} has unclassified descriptors {[o.get('digest') for o in other]}")
    if len(run) != 1 or platform_of(run[0]) != platform:
        raise OciError(f"child {child_index_digest} must hold exactly one {platform} image; "
                       f"it holds {[platform_of(r) for r in run]}")
    image = run[0]
    refs = [a for a in att if a["annotations"][REF_DIGEST] == image["digest"]]
    if len(att) != 1 or len(refs) != 1:
        raise OciError(f"child {child_index_digest} must hold exactly one attestation manifest for "
                       f"{image['digest']}; it holds {len(att)}")
    return {
        "platform": platform,
        "child_index": child_index_digest,
        "image": image["digest"],
        "attestation": refs[0]["digest"],
        **check_image(get_manifest, get_blob, image["digest"], platform, commit),
        **check_attestation(get_manifest, get_blob, refs[0]["digest"], image["digest"]),
    }


def check_image(get_manifest, get_blob, digest: str, platform: str, commit: str) -> dict:
    m = json.loads(get_manifest(digest))
    if m.get("mediaType") != MANIFEST:
        raise OciError(f"image {digest} is {m.get('mediaType')}, not an OCI image manifest")
    cfg = json.loads(get_blob(m["config"]["digest"]))
    got = f"{cfg.get('os')}/{cfg.get('architecture')}"
    if got != platform:
        raise OciError(f"image {digest} config says {got}, its index says {platform}")
    label = ((cfg.get("config") or {}).get("Labels") or {}).get(REVISION_LABEL)
    if label != commit:
        raise OciError(f"image {digest} ({platform}) revision label is {label!r}, not {commit}")
    return {"config": m["config"]["digest"], "revision_label": label}


def statements(get_manifest, get_blob, att_digest: str, image_digest: str) -> list[dict]:
    m = json.loads(get_manifest(att_digest))
    out = []
    for layer in m.get("layers") or []:
        if layer.get("mediaType") != INTOTO:
            raise OciError(f"attestation {att_digest} layer {layer.get('digest')} is {layer.get('mediaType')}")
        s = json.loads(get_blob(layer["digest"]))
        subjects = [x.get("digest", {}).get("sha256") for x in s.get("subject") or []]
        if image_digest.split(":", 1)[1] not in subjects:
            raise OciError(f"statement {layer['digest']} is not about {image_digest} (subjects {subjects})")
        out.append({"layer": layer["digest"], "predicateType": s.get("predicateType"), "statement": s})
    return out


def check_attestation(get_manifest, get_blob, att_digest: str, image_digest: str) -> dict:
    sts = statements(get_manifest, get_blob, att_digest, image_digest)
    sboms = [s for s in sts if s["predicateType"] == SPDX]
    provs = [s for s in sts if s["predicateType"] == SLSA_V1]
    if not sboms:
        raise OciError(f"no SPDX SBOM statement in {att_digest}")
    if len(provs) != 1:
        raise OciError(f"expected exactly one SLSA v1 provenance statement in {att_digest}, found {len(provs)}")
    return {"sboms": [{"layer": s["layer"]} for s in sboms], "provenance": {"layer": provs[0]["layer"]}}


def layout_child(layout: Layout, platform: str, commit: str) -> dict:
    tops = layout.index.get("manifests") or []
    if len(tops) != 1 or tops[0].get("mediaType") != INDEX:
        raise OciError(f"layout must hold exactly one child index; index.json lists {len(tops)} "
                       f"({[t.get('mediaType') for t in tops]})")
    return describe_child(layout.get, layout.get, tops[0]["digest"], platform, commit)


def push_layout(layout: Layout, reg: Registry, repo: str, child: dict) -> None:
    idx = json.loads(layout.get(child["child_index"]))
    for d in (child["image"], child["attestation"]):
        m = json.loads(layout.get(d))
        for blob in [m["config"]] + (m.get("layers") or []):
            reg.push_blob(repo, blob["digest"], layout.get(blob["digest"]))
        reg.put_manifest(repo, d, layout.get(d), m["mediaType"])
    reg.put_manifest(repo, child["child_index"], layout.get(child["child_index"]), idx["mediaType"])


def canonical_index(children: list[dict]) -> bytes:
    """One OCI index holding each child's image and attestation descriptors,
    copied byte-for-byte from the child indexes, ordered by platform. Deterministic:
    the same children always give the same bytes and so the same digest."""
    manifests = []
    for c in sorted(children, key=lambda c: c["platform"]):
        manifests.extend(sorted(c["descriptors"], key=lambda d: 1 if is_attestation(d) else 0))
    doc = {"schemaVersion": 2, "mediaType": INDEX, "manifests": manifests}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def assemble(reg: Registry, repo: str, tag: str, child_indexes: list[str]) -> str:
    if tag == "latest" or not re.fullmatch(r"[0-9a-f]{40}", tag):
        raise OciError(f"the canonical tag must be the full 40-hex commit, never '{tag}'")
    if reg.manifest_exists(repo, tag):
        raise OciError(f"{repo}:{tag} already exists; a published release tag is never overwritten")
    children, seen = [], set()
    for ci in child_indexes:
        body, mt, _ = reg.manifest(repo, ci)
        run, att, other = classify(json.loads(body))
        if mt != INDEX or other or len(run) != 1 or len(att) != 1:
            raise OciError(f"{ci} is not a single-platform child index with one attestation manifest")
        p = platform_of(run[0])
        if p in seen:
            raise OciError(f"two children for {p}")
        seen.add(p)
        children.append({"platform": p, "descriptors": run + att})
    if sorted(seen) != sorted(RELEASE_PLATFORMS):
        raise OciError(f"a release joins exactly {list(RELEASE_PLATFORMS)}; got {sorted(seen)}")
    data = canonical_index(children)
    d = reg.put_manifest(repo, tag, data, INDEX)
    back, _, got = reg.manifest(repo, tag)
    if got != d:
        raise OciError(f"{repo}:{tag} reads back as {got}, pushed {d}")
    return d


# --------------------------------------------------------------------- cli ---

def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]

    def opt(name: str) -> str:
        if name not in args:
            raise OciError(f"{cmd}: {name} is required")
        i = args.index(name)
        v = args[i + 1]
        del args[i:i + 2]
        return v

    try:
        if cmd in ("inspect-layout", "push-layout"):
            platform, commit = opt("--platform"), opt("--commit")
            if platform not in RELEASE_PLATFORMS or not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise OciError("--platform must be linux/amd64 or linux/arm64 and --commit a 40-hex sha")
            layout = Layout(args[0])
            child = layout_child(layout, platform, commit)
            if cmd == "push-layout":
                reg, repo = split_repo(args[1])
                push_layout(layout, reg, repo, child)
                got = describe_child(lambda d: reg.manifest(repo, d)[0], lambda d: reg.blob(repo, d),
                                     child["child_index"], platform, commit)
                if got != child:
                    raise OciError("the pushed child does not read back identical to the layout")
            print(json.dumps(child, sort_keys=True))
        elif cmd == "assemble":
            tag = opt("--tag")
            reg, repo = split_repo(args[0])
            print(assemble(reg, repo, tag, args[1:]))
        elif cmd == "absent":
            reg, repo = split_repo(args[0])
            if reg.manifest_exists(repo, args[1]):
                print(f"OCI FAIL: {args[0]}:{args[1]} already exists; a release tag is never overwritten",
                      file=sys.stderr)
                return 1
            print(f"{args[0]}:{args[1]} does not exist")
        elif cmd == "manifest":
            ref = args[0]
            name, sep, digest = ref.rpartition("@")
            if not sep:
                name, _, digest = ref.rpartition(":")
            reg, repo = split_repo(name)
            sys.stdout.buffer.write(reg.manifest(repo, digest)[0])
        elif cmd == "blob":
            reg, repo = split_repo(args[0])
            sys.stdout.buffer.write(reg.blob(repo, args[1]))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (OciError, OSError, KeyError, ValueError, IndexError, tarfile.TarError) as e:
        print(f"OCI FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

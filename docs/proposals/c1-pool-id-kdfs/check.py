#!/usr/bin/env python3
"""Mechanical checks for the C1 pool identifier PROPOSAL. Exits nonzero on any
failure.

UNRATIFIED DRAFT — NEW PROPOSAL. Not recovered §K bytes; not previously
ratified; not consensus; do not implement until ratified.

    python3 check.py           # Python-only checks
    python3 check.py --rust    # also build and run rust-generator/ (offline,
                               # locked) twice and compare it byte for byte

Checks:
 1. The pure-Python BLAKE3 in generate.py reproduces all 35 official BLAKE3
    test vectors (hash mode, first 32 bytes).
 2. It reproduces the frozen job_id/unit_id KATs, read from
    crates/sumchain-wire/src/compute_pool_graph.rs, and the frozen tag bytes.
 3. generate.py run twice gives identical bytes, equal to vectors.json.
 4. Every tag, field, preimage and output length; each preimage equals
    tag ‖ fields; each output equals BLAKE3(preimage).
 5. The proposed tags are ASCII, end in their only 0x0a byte, and are neither
    equal to nor prefix-related with each other or any byte-string literal in
    crates/ (frozen tags included).
 6. Rejections: entitlement kinds 3 and 255; a nonzero occurrence for the
    one-time kinds 0 and 2. README.md carries the draft header and shows
    every preimage and output.
 7. With --rust: the Rust generator (blake3 crate + frozen sumchain-wire
    functions) agrees byte for byte with the Python generator on every official
    vector, frozen id, PROPOSAL vector and rejection, and two runs are identical.
"""
import ast
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True  # keep __pycache__ out of the tree
import generate as g  # noqa: E402

# Official BLAKE3 test vectors: test_vectors/test_vectors.json at tag 1.8.2 of
# https://github.com/BLAKE3-team/BLAKE3 (file sha256
# dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624). Input is
# bytes(i % 251 for i in range(input_len)); value = first 32 bytes of "hash".
OFFICIAL = [
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
    (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"),
    (4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"),
    (5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"),
    (6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"),
    (7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"),
    (8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"),
    (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
    (127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"),
    (128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"),
    (129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"),
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
    (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
    (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"),
    (5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"),
    (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"),
    (6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"),
    (6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"),
    (7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"),
    (7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817"),
    (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
    (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
    (16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"),
    (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
    (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"),
]

# Expected fixed widths, in preimage order after the tag.
LAYOUT = {
    "job_id": [("chain_id", 8), ("requester", 20), ("requester_nonce", 8), ("client_job_salt", 32)],
    "unit_id": [("job_id", 32), ("unit_index", 4)],
    "offer_bond_id": [("chain_id", 8), ("sender", 20), ("offer_seq", 8)],
    "reservation_id": [("job_id", 32), ("unit_id", 32), ("generation", 8), ("offer_bond_id", 32)],
    "entitlement_id": [("job_id", 32), ("unit_id", 32), ("generation", 8),
                       ("entitlement_kind", 1), ("occurrence", 4)],
}
TAG_OF_KDF = {"job_id": "JOB", "unit_id": "UNIT", "offer_bond_id": "OFFERBOND",
              "reservation_id": "RESERVATION", "entitlement_id": "ENTITLEMENT"}
PREIMAGE_LEN = {"job_id": 89, "unit_id": 58, "offer_bond_id": 63,
                "reservation_id": 133, "entitlement_id": 106}

failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


def official_input(n):
    return bytes(i % 251 for i in range(n))


def all_tags():
    return {**g.FROZEN_TAGS, **g.PROPOSED_TAGS}


def rust_byte_literals():
    """Every b"..." literal in crates/**/*.rs, decoded (escapes included)."""
    lit = re.compile(r'\bb"((?:[^"\\\n]|\\.)*)"')
    out = set()
    for root, _, files in os.walk(os.path.join(REPO, "crates")):
        for f in files:
            if f.endswith(".rs"):
                with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                    for m in lit.finditer(fh.read()):
                        try:
                            out.add(ast.literal_eval('b"' + m.group(1) + '"'))
                        except (ValueError, SyntaxError):
                            pass
    return out


def main():
    run_rust = "--rust" in sys.argv[1:]

    # 1. BLAKE3 against the official vectors.
    bad = [n for n, h in OFFICIAL if g.blake3(official_input(n)).hex() != h]
    check(len(OFFICIAL) == 35 and not bad,
          f"pure-Python BLAKE3 reproduces the 35 official test vectors (mismatches: {bad})")

    # 2. Frozen tags and KATs, read from the code.
    src_path = os.path.join(REPO, "crates", "sumchain-wire", "src", "compute_pool_graph.rs")
    src = open(src_path, encoding="utf-8").read()
    for name, const in [("JOB", "POOL_JOB_TAG"), ("UNIT", "POOL_UNIT_TAG"),
                        ("GRAPHDEF", "POOL_GRAPHDEF_TAG")]:
        m = re.search(r"pub const %s: &\[u8\] = b\"([^\"]*)\";" % const, src)
        check(m is not None and ast.literal_eval('b"' + m.group(1) + '"') == g.FROZEN_TAGS[name],
              f"frozen tag {const} equals the code")
    kats = {}
    for fn in ("job_id_matches_independent_b3sum_vector", "unit_id_matches_independent_b3sum_vector"):
        m = re.search(r"fn %s\(\)[^}]*?\"([0-9a-f]{64})\"" % fn, src, re.S)
        kats[fn] = m.group(1) if m else None
    _, _, job = g.job_id(g.KAT_CHAIN_ID, g.KAT_ADDRESS, g.KAT_NONCE, g.KAT_SALT)
    _, _, unit = g.unit_id(job, g.KAT_UNIT_INDEX)
    check(kats["job_id_matches_independent_b3sum_vector"] == job.hex(),
          f"frozen job_id KAT reproduced ({job.hex()})")
    check(kats["unit_id_matches_independent_b3sum_vector"] == unit.hex(),
          f"frozen unit_id KAT reproduced ({unit.hex()})")

    # 3. Determinism and the committed file.
    gen = [subprocess.run([sys.executable, os.path.join(HERE, "generate.py")],
                          check=True, capture_output=True).stdout for _ in range(2)]
    check(gen[0] == gen[1], "generate.py: two runs give identical bytes")
    with open(os.path.join(HERE, "vectors.json"), "rb") as fh:
        committed = fh.read()
    check(committed == gen[0], "vectors.json equals the generated output byte for byte")
    doc = json.loads(gen[0])
    check(doc["status"].startswith("PROPOSAL — UNRATIFIED DRAFT"), "vectors.json is labelled PROPOSAL")

    # 4. Lengths and structure.
    tags = all_tags()
    for t in doc["tags"]:
        raw = bytes.fromhex(t["hex"])
        check(raw == tags[t["name"]] and t["len"] == len(raw)
              and t["ascii"] == raw.decode("ascii").replace("\n", "\\n"),
              f"tag {t['name']}: {len(raw)} bytes, hex/ascii/len consistent")
    for t, n in [("OFFERBOND", 27), ("RESERVATION", 29), ("ENTITLEMENT", 29)]:
        check(len(g.PROPOSED_TAGS[t]) == n, f"tag {t} is {n} bytes")
    entries = doc["frozen_context"] + doc["vectors"]
    check(len(doc["frozen_context"]) == 2 and len(doc["vectors"]) == 8,
          "2 frozen-context entries and 8 PROPOSAL vectors")
    for e in entries:
        kdf, pre = e["kdf"], bytes.fromhex(e["preimage_hex"])
        tag = tags[TAG_OF_KDF[kdf]]
        widths = [(f["name"], f["width"]) for f in e["fields"]]
        body = b"".join(bytes.fromhex(f["hex"]) for f in e["fields"])
        ok = (widths == LAYOUT[kdf]
              and all(len(bytes.fromhex(f["hex"])) == f["width"] for f in e["fields"])
              and pre == tag + body
              and e["preimage_len"] == len(pre) == PREIMAGE_LEN[kdf]
              and e["output_len"] == 32 and len(bytes.fromhex(e["output_hex"])) == 32
              and g.blake3(pre).hex() == e["output_hex"])
        check(ok, f"{e['name']}: fields {[w for _, w in widths]}, preimage {len(pre)} B "
                  f"= tag ‖ fields, output 32 B = BLAKE3(preimage)")
    by_name = {e["name"]: e for e in entries}
    job_hex, unit_hex = by_name["job_id/kat"]["output_hex"], by_name["unit_id/kat"]["output_hex"]
    ob_hex = by_name["offer_bond_id/base"]["output_hex"]
    for e in doc["vectors"]:
        f = {x["name"]: x["hex"] for x in e["fields"]}
        if e["kdf"] in ("reservation_id", "entitlement_id"):
            check(f["job_id"] == job_hex and f["unit_id"] == unit_hex,
                  f"{e['name']}: carries the complete frozen job_id and unit_id")
        if e["kdf"] == "reservation_id":
            check(f["offer_bond_id"] == ob_hex, f"{e['name']}: carries offer_bond_id/base")

    # 5. Tags: ASCII, single trailing 0x0a, prefix-free.
    proposed = list(g.PROPOSED_TAGS.values())
    for t in proposed:
        check(all(32 <= b < 127 for b in t[:-1]) and t.endswith(b"\n") and t.count(b"\n") == 1,
              f"{t!r}: ASCII, ends in its only 0x0a")
    literals = rust_byte_literals()
    clashes = []
    for t in proposed:
        if t in literals:
            clashes.append((t, "already a literal in crates/"))
        for other in (set(g.FROZEN_TAGS.values()) | literals | set(proposed)) - {t, b""}:
            if t.startswith(other) or other.startswith(t):
                clashes.append((t, other))
    check(not clashes and len(set(proposed)) == len(proposed),
          f"proposed tags are distinct and prefix-free against each other, the frozen tags "
          f"and all {len(literals)} byte-string literals in crates/ (clashes: {clashes[:5]})")

    # 6. Rejections.
    expected_rejects = [(3, 0), (255, 0), (0, 1), (2, 1)]
    got = [(r["entitlement_kind"], r["occurrence"]) for r in doc["rejected"]]
    check(got == expected_rejects, f"rejections recorded: {got}")
    for kind, occ in expected_rejects:
        try:
            g.entitlement_id(job, unit, 1, kind, occ)
            refused = False
        except g.Rejected:
            refused = True
        check(refused, f"entitlement_id refuses kind {kind}, occurrence {occ}")

    # README consistency: header label, and every preimage/output appears.
    with open(os.path.join(HERE, "README.md"), encoding="utf-8") as fh:
        readme = fh.read()
    check(readme.startswith("# UNRATIFIED DRAFT — NEW PROPOSAL. Not recovered §K bytes; "
                            "not previously ratified; not consensus; do not implement until ratified"),
          "README.md carries the UNRATIFIED DRAFT header")
    flat = re.sub(r"\s+", "", readme)
    missing = [e["name"] for e in entries
               if e["preimage_hex"] not in flat or e["output_hex"] not in flat]
    missing += [t["name"] for t in doc["tags"] if f"`{t['hex']}`|{t['len']}|" not in flat]
    check(not missing, f"README.md shows every tag (hex, len), preimage and output (missing: {missing})")

    # 7. Rust generator.
    if run_rust:
        env = dict(os.environ, RUSTUP_AUTO_INSTALL="0")
        cmd = ["cargo", "run", "--offline", "--locked", "--release", "-q"]
        runs = [subprocess.run(cmd, cwd=os.path.join(HERE, "rust-generator"), env=env,
                               check=True, capture_output=True).stdout for _ in range(2)]
        check(runs[0] == runs[1], "rust-generator: two runs give identical bytes")
        lines = [ln.split("\t") for ln in runs[0].decode().splitlines()]
        rust_official = [(int(x[1]), x[2]) for x in lines if x[0] == "official"]
        check(rust_official == OFFICIAL, "rust blake3 crate reproduces the 35 official vectors")
        rust_ids = {x[1]: (x[2], x[3]) for x in lines if x[0] in ("frozen", "vector")}
        py_ids = {e["name"]: (e["preimage_hex"], e["output_hex"]) for e in entries}
        check(rust_ids == py_ids,
              f"rust and python agree byte for byte on {len(py_ids)} preimages and outputs")
        rust_rejects = [(int(x[1]), int(x[2])) for x in lines if x[0] == "reject"]
        check(rust_rejects == expected_rejects, f"rust rejects the same cases: {rust_rejects}")
        check(rust_ids.get("job_id/kat", ("", ""))[1] == kats["job_id_matches_independent_b3sum_vector"]
              and rust_ids.get("unit_id/kat", ("", ""))[1] == kats["unit_id_matches_independent_b3sum_vector"],
              "rust (frozen sumchain-wire functions) matches the code KATs")
    else:
        print("skip  rust-generator cross-check (run with --rust)")

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("all checks passed" + ("" if run_rust else " (python only)"))


if __name__ == "__main__":
    main()

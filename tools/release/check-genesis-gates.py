#!/usr/bin/env python3
"""No activation height may be baked into tracked genesis configuration.

    python3 tools/release/check-genesis-gates.py [--commit <sha>]

Reads every tracked genesis JSON file (at <sha>, or in the working tree) and
fails on any key ending in `_from_height` with a non-null value, anywhere in
the document, unless the gate is on GATES_PREDATING_ACTIVATION_RECORDING in
crates/genesis/src/lib.rs (read at the same commit). Those predate activation
recording and may carry the heights they have run at for millions of blocks;
every other gate is a Stage 2 decision, taken with production evidence, and a
release must not ship with one set.

Exit 0 clean, 1 on a baked height, 2 on usage.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENESIS_FILE = re.compile(r"(^|/)[^/]*genesis[^/]*\.json$")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True, text=True).stdout


def read(commit: str | None, path: str) -> str:
    return git("show", f"{commit}:{path}") if commit else (ROOT / path).read_text()


def predating(commit: str | None) -> set[str]:
    src = read(commit, "crates/genesis/src/lib.rs")
    i = src.index("GATES_PREDATING_ACTIVATION_RECORDING")
    body = src[src.index("[", i): src.index("];", i)]
    names = set(re.findall(r'"([a-z_0-9]+_from_height)"', body))
    if len(names) < 10:
        raise SystemExit(f"could not read GATES_PREDATING_ACTIVATION_RECORDING ({len(names)} names)")
    return names


def heights(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else k
            if k.endswith("_from_height") and v is not None:
                yield p, k, v
            yield from heights(v, p)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from heights(v, f"{path}[{i}]")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--commit")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    commit = a.commit
    if commit and not re.fullmatch(r"[0-9a-f]{40}", commit):
        print("usage: --commit must be a full 40-hex sha")
        return 2
    files = [f for f in (git("ls-tree", "-r", "--name-only", commit) if commit else git("ls-files")).splitlines()
             if GENESIS_FILE.search(f)]
    if not files:
        print("FAIL: no tracked genesis files found")
        return 1
    allowed = predating(commit)
    bad: list[str] = []
    for f in files:
        try:
            doc = json.loads(read(commit, f))
        except json.JSONDecodeError as e:
            bad.append(f"{f}: not valid JSON ({e})")
            continue
        for path, key, value in heights(doc):
            if key not in allowed:
                bad.append(f"{f}: {path} = {value}: a remediation height baked into tracked genesis")
    for b in bad:
        print("FAIL:", b)
    if bad:
        return 1
    print(f"GENESIS GATES OK: {len(files)} tracked genesis file(s) at {commit or 'the working tree'}; "
          f"no height outside the {len(allowed)} predating gates.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

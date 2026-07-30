#!/usr/bin/env python3
"""INDEPENDENT reference implementation of the canonical advisory-checkout digest.

Shares NO code with src/venue/checkout_digest.rs — it re-derives the serialization spec
(the ambiguity-prone part) in Python and hashes via the `b3sum` CLI (BLAKE3 is a fixed
standard). Used by a Rust agreement test to prove the digest is reproducible across two
independent implementations, and runnable by hand to reproduce a checkout's digest.

Digest = BLAKE3( TAG=pad32("SUMCHAIN/B0PRE/ADVDB/v1")
                 ‖ u64_le(entry_count)
                 ‖ for each entry, sorted by relative-path BYTES:
                     u64_le(len(relpath)) ‖ relpath
                     ‖ type: b'd' dir | b'f' file | b'l' symlink
                     ‖ file:    u16_le(git_mode 0o644|0o755) ‖ BLAKE3(content)   [32 bytes]
                     ‖ symlink: u64_le(len(target)) ‖ target
                     ‖ dir:     (nothing) )
A top-level `.git` entry (exact name) is excluded. Fails closed on unsupported file types,
absolute/`..` symlink targets, and `..`/absolute relative paths.

Usage: advdb_digest_ref.py <checkout-dir>   -> prints the bare 64-hex digest
"""
import os
import struct
import subprocess
import sys

TAG = b"SUMCHAIN/B0PRE/ADVDB/v1"
TAG = TAG + b"\x00" * (32 - len(TAG))  # pad32


def b3(data: bytes) -> bytes:
    p = subprocess.run(["b3sum", "--no-names"], input=data, capture_output=True, check=True)
    return bytes.fromhex(p.stdout.decode().strip())


def unsafe_rel(rel: str) -> bool:
    if rel.startswith("/"):
        return True
    return any(part in ("", "..", ".") or "\x00" in part for part in rel.split("/"))


def unsafe_symlink(target: str) -> bool:
    return target.startswith("/") or any(part == ".." for part in target.split("/"))


def collect(root: str):
    entries = {}  # relpath(str) -> serialized tail bytes

    def walk(rel: str):
        absdir = os.path.join(root, rel) if rel else root
        with os.scandir(absdir) as it:
            for e in it:
                child = f"{rel}/{e.name}" if rel else e.name
                if rel == "" and e.name == ".git":  # exact top-level .git only
                    continue
                if unsafe_rel(child):
                    sys.exit(f"UNSAFE_PATH: {child}")
                st = os.lstat(e.path)
                mode = st.st_mode
                if os.path.islink(e.path):
                    target = os.readlink(e.path)
                    if unsafe_symlink(target):
                        sys.exit(f"UNSAFE_SYMLINK: {child} -> {target}")
                    tb = target.encode()
                    tail = b"l" + struct.pack("<Q", len(tb)) + tb
                elif os.path.isdir(e.path) and not os.path.islink(e.path):
                    tail = b"d"
                    entries[child] = tail
                    walk(child)
                    continue
                elif os.path.isfile(e.path):
                    execbit = 0o755 if (mode & 0o111) else 0o644
                    with open(e.path, "rb") as fh:
                        tail = b"f" + struct.pack("<H", execbit) + b3(fh.read())
                else:
                    sys.exit(f"UNSUPPORTED_TYPE: {child}")
                if child in entries:
                    sys.exit(f"DUPLICATE: {child}")
                entries[child] = tail

    walk("")
    return entries


def digest(root: str) -> str:
    entries = collect(root)
    buf = bytearray(TAG)
    buf += struct.pack("<Q", len(entries))
    for rel in sorted(entries, key=lambda s: s.encode()):
        rb = rel.encode()
        buf += struct.pack("<Q", len(rb)) + rb + entries[rel]
    return b3(bytes(buf)).hex()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: advdb_digest_ref.py <checkout-dir>")
    print(digest(sys.argv[1]))

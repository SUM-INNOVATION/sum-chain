#!/usr/bin/env bash
# Fail-closed negatives for lib.sh:safe_extract_tar — the untrusted vendor-tar extraction guard.
# Crafts malicious tars (traversal / absolute / symlink / duplicate) with python's tarfile (arbitrary
# member names) and asserts each is REFUSED before extraction, and that a clean tar is accepted.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

# safe_extract_tar calls die() on refusal (exit 1). Run it in a subshell so we can catch it.
try_extract() { ( safe_extract_tar "$1" "$2" ) >/dev/null 2>&1; }

craft() { python3 - "$@"; }

# ---- clean tar is accepted ----
mkdir -p "$T/clean/crate-1.0.0"; printf 'MIT\n' > "$T/clean/crate-1.0.0/LICENSE"
( cd "$T/clean" && tar -cf "$T/clean.tar" . )
if try_extract "$T/clean.tar" "$T/out-clean" && [ -f "$T/out-clean/crate-1.0.0/LICENSE" ]; then
  ok "clean vendor tar accepted + extracted"; else bad "clean tar rejected"; fi

# ---- `..` traversal entry refused ----
craft "$T/trav.tar" <<'PY'
import tarfile,sys,io
with tarfile.open(sys.argv[1],"w") as t:
    d=b"x"; ti=tarfile.TarInfo("../evil"); ti.size=len(d)
    t.addfile(ti, io.BytesIO(d))
PY
try_extract "$T/trav.tar" "$T/out-trav" && bad "traversal (..) NOT refused" || ok "traversal (..) entry refused"

# ---- absolute path entry refused ----
craft "$T/abs.tar" <<'PY'
import tarfile,sys,io
with tarfile.open(sys.argv[1],"w") as t:
    d=b"x"; ti=tarfile.TarInfo("/etc/evil"); ti.size=len(d)
    t.addfile(ti, io.BytesIO(d))
PY
try_extract "$T/abs.tar" "$T/out-abs" && bad "absolute path NOT refused" || ok "absolute path entry refused"

# ---- symlink entry refused ----
craft "$T/sym.tar" <<'PY'
import tarfile,sys
with tarfile.open(sys.argv[1],"w") as t:
    ti=tarfile.TarInfo("crate-1.0.0/LINK"); ti.type=tarfile.SYMTYPE; ti.linkname="/etc/passwd"
    t.addfile(ti)
PY
try_extract "$T/sym.tar" "$T/out-sym" && bad "symlink NOT refused" || ok "symlink entry refused"

# ---- hardlink entry refused ----
craft "$T/hard.tar" <<'PY'
import tarfile,sys,io
with tarfile.open(sys.argv[1],"w") as t:
    d=b"x"; a=tarfile.TarInfo("crate-1.0.0/A"); a.size=len(d); t.addfile(a, io.BytesIO(d))
    h=tarfile.TarInfo("crate-1.0.0/B"); h.type=tarfile.LNKTYPE; h.linkname="crate-1.0.0/A"; t.addfile(h)
PY
try_extract "$T/hard.tar" "$T/out-hard" && bad "hardlink NOT refused" || ok "hardlink entry refused"

# ---- duplicate member refused ----
craft "$T/dup.tar" <<'PY'
import tarfile,sys,io
with tarfile.open(sys.argv[1],"w") as t:
    for _ in range(2):
        d=b"x"; ti=tarfile.TarInfo("crate-1.0.0/LICENSE"); ti.size=len(d); t.addfile(ti, io.BytesIO(d))
PY
try_extract "$T/dup.tar" "$T/out-dup" && bad "duplicate member NOT refused" || ok "duplicate member refused"

echo "safe_extract_tar: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

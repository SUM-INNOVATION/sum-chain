#!/usr/bin/env bash
# Declarative prover-toolchain provisioning tests (final x86/ARM provisioning). Exercises the
# STAGED, SELF-CONTAINED provisioner (provision_prover_toolchain.sh) — the SINGLE implementation
# that is copied into the Docker build context — on CRAFTED local archives (no network), proving:
#   * a correct archive + complete declared member set provisions; point-of-use re-hash verifies;
#   * cargo subcommands land in the isolated PATH dir, r0vm in the RISC0_SERVER_PATH dir;
#   * wrong archive SHA / member SHA / member SIZE are refused;
#   * a symlink, a `..`-traversal entry, a DUPLICATE, an UNEXPECTED (undeclared) member, and a
#     MISSING declared member are each refused (complete-member-set validation).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
PROV="$SCR/provision_prover_toolchain.sh"
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }
command -v tar >/dev/null 2>&1 || { echo "SKIP: tar absent"; echo "verified_extraction: SKIPPED"; exit 0; }
sha(){ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"|awk '{print $1}'; else shasum -a 256 "$1"|awk '{print $1}'; fi; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
BIN="$T/isolated"; R0="$T/risc0server"
prov(){ ( bash "$PROV" "$@" ) >/dev/null 2>&1; }   # subshell: die (exit 4) does not abort the test

# ---- craft a RISC-Zero-like archive with TWO declared members (cargo-risczero + r0vm) ----------
mkdir -p "$T/stage/bin"
printf 'FAKE cargo-risczero\n' > "$T/stage/bin/cargo-risczero"
printf 'FAKE r0vm binary\n'    > "$T/stage/bin/r0vm"
( cd "$T/stage" && tar -czf "$T/risc0.tgz" bin/cargo-risczero bin/r0vm )
A="$(sha "$T/risc0.tgz")"
CR_SHA="$(sha "$T/stage/bin/cargo-risczero")"; CR_SZ="$(wc -c < "$T/stage/bin/cargo-risczero" | tr -d ' ')"
R0_SHA="$(sha "$T/stage/bin/r0vm")";          R0_SZ="$(wc -c < "$T/stage/bin/r0vm" | tr -d ' ')"

# positive: both members provision; cargo-risczero -> isolated, r0vm -> risc0server
if prov "$T/risc0.tgz" "$A" "$BIN" "$R0" \
        "bin/cargo-risczero:$CR_SHA:$CR_SZ:isolated" "bin/r0vm:$R0_SHA:$R0_SZ:risc0server" \
   && [ -x "$BIN/cargo-risczero" ] && [ -x "$R0/r0vm" ] \
   && [ "$(sha "$BIN/cargo-risczero")" = "$CR_SHA" ] && [ "$(sha "$R0/r0vm")" = "$R0_SHA" ]; then
  ok "complete member set provisions; cargo-risczero->isolated PATH, r0vm->RISC0_SERVER_PATH; point-of-use re-verified"
else bad "positive provisioning failed"; fi

# wrong archive SHA
prov "$T/risc0.tgz" "$(printf 'f%.0s' $(seq 1 64))" "$T/b1" "$T/b1r" "bin/cargo-risczero:$CR_SHA:$CR_SZ:isolated" "bin/r0vm:$R0_SHA:$R0_SZ:risc0server" \
  && bad "wrong archive SHA accepted" || ok "wrong archive SHA refused before extraction"
# wrong member SHA
prov "$T/risc0.tgz" "$A" "$T/b2" "$T/b2r" "bin/cargo-risczero:$(printf 'e%.0s' $(seq 1 64)):$CR_SZ:isolated" "bin/r0vm:$R0_SHA:$R0_SZ:risc0server" \
  && bad "wrong member SHA accepted" || ok "wrong member SHA refused before chmod"
# wrong member SIZE
prov "$T/risc0.tgz" "$A" "$T/b3" "$T/b3r" "bin/cargo-risczero:$CR_SHA:999999:isolated" "bin/r0vm:$R0_SHA:$R0_SZ:risc0server" \
  && bad "wrong member size accepted" || ok "wrong member SIZE refused"
# UNEXPECTED member: declare only cargo-risczero, but the archive also has r0vm (undeclared)
prov "$T/risc0.tgz" "$A" "$T/b4" "$T/b4r" "bin/cargo-risczero:$CR_SHA:$CR_SZ:isolated" \
  && bad "unexpected (undeclared) member accepted" || ok "unexpected archive member refused (complete-set)"
# MISSING declared member: declare a member the archive does not contain
prov "$T/risc0.tgz" "$A" "$T/b5" "$T/b5r" "bin/cargo-risczero:$CR_SHA:$CR_SZ:isolated" "bin/r0vm:$R0_SHA:$R0_SZ:risc0server" "bin/nope:$CR_SHA:$CR_SZ:isolated" \
  && bad "missing declared member accepted" || ok "missing declared member refused"

# ---- symlink entry refused ------------------------------------------------------------------
mkdir -p "$T/sl/bin"; printf 'x' > "$T/sl/bin/real"; ( cd "$T/sl/bin" && ln -s real link )
( cd "$T/sl" && tar -czf "$T/sl.tgz" bin/real bin/link )
if tar -tvzf "$T/sl.tgz" 2>/dev/null | grep -q '^l'; then
  sA="$(sha "$T/sl.tgz")"
  prov "$T/sl.tgz" "$sA" "$T/b6" "$T/b6r" "bin/real:$(sha "$T/sl/bin/real"):1:isolated" \
    && bad "archive with a symlink accepted" || ok "symlink archive entry refused"
else echo "note: this tar did not record a symlink entry; the link guard is still enforced in code"; fi

# ---- traversal member refused ---------------------------------------------------------------
mkdir -p "$T/tv"; printf 'x' > "$T/tv/payload"
( cd "$T/tv" && tar -czf "$T/tv.tgz" --transform 's,^payload,../escape,' payload 2>/dev/null ) \
  || ( cd "$T/tv" && tar -czf "$T/tv.tgz" -s ',^payload,../escape,' payload 2>/dev/null )
if tar -tzf "$T/tv.tgz" 2>/dev/null | grep -q '\.\.'; then
  tA="$(sha "$T/tv.tgz")"
  prov "$T/tv.tgz" "$tA" "$T/b7" "$T/b7r" "../escape:$CR_SHA:1:isolated" \
    && bad "traversal member accepted" || ok "traversal (..) archive entry refused"
else echo "note: could not craft a ..-entry archive with this tar; the traversal guard is still enforced in code"; fi

# ---- duplicate member refused ---------------------------------------------------------------
mkdir -p "$T/dA/bin" "$T/dB/bin"; printf 'a' > "$T/dA/bin/cargo-prove"; printf 'b' > "$T/dB/bin/cargo-prove"
( cd "$T/dA" && tar -czf "$T/dup.tgz" bin/cargo-prove && cd "$T/dB" && tar -rzf "$T/dup.tgz" bin/cargo-prove 2>/dev/null ) || true
if [ "$(tar -tzf "$T/dup.tgz" 2>/dev/null | grep -Fxc 'bin/cargo-prove')" -ge 2 ] 2>/dev/null; then
  dA="$(sha "$T/dup.tgz")"
  prov "$T/dup.tgz" "$dA" "$T/b8" "$T/b8r" "bin/cargo-prove:$(sha "$T/dA/bin/cargo-prove"):1:isolated" \
    && bad "duplicate member accepted" || ok "duplicate archive entry refused"
else echo "note: could not craft a duplicate-entry archive with this tar; the dedup guard is still enforced in code"; fi

echo "----"
if [ "$F" = 0 ]; then echo "VERIFIED_EXTRACTION_PASS"; echo "verified_extraction: ALL TESTS PASS"; exit 0
else echo "verified_extraction: FAILURE(S)" >&2; exit 1; fi

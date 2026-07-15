#!/usr/bin/env bash
# Dependency reproducibility guard for the committed B0-PRE tool lockfiles.
#
# Pure text inspection (no network, read-only). Asserts that each committed
# Cargo.lock is present, that the Rust-1.85-compatible transitive resolutions
# are pinned, and that the forbidden ICU-2.2 / network-stack subtree has not
# returned. Prints a BLAKE3 digest per lock when a hasher is available.
#
# Exit 0 = reproducible; non-zero = a violation was found.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
VAL="$ROOT/tools/b0-pre-validator/Cargo.lock"
IND="$ROOT/tools/b0-pre-independent/Cargo.lock"

fail=0
note() { printf '%s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fail=1; }

have_line() { grep -Fq "$1" "$2"; }
count()     { grep -c "$1" "$2" 2>/dev/null || true; }

for lk in "$VAL" "$IND"; do
  [ -s "$lk" ] || { bad "missing or empty lockfile: $lk"; continue; }
done
[ "$fail" = 0 ] || exit "$fail"

# Validator transitive pins that keep the crate on Rust 1.85.
if have_line 'name = "idna_adapter"' "$VAL" && grep -A1 'name = "idna_adapter"' "$VAL" | grep -Fq 'version = "1.1.0"'; then
  note "PASS: validator idna_adapter pinned to 1.1.0"
else
  bad "validator idna_adapter is not pinned to 1.1.0"
fi
if grep -A1 'name = "time"' "$VAL" | grep -Fq 'version = "0.3.36"'; then
  note "PASS: validator time pinned to 0.3.36"
else
  bad "validator time is not pinned to 0.3.36"
fi

# Forbidden subtree must be absent from BOTH locks.
for lk in "$VAL" "$IND"; do
  name="$(basename "$(dirname "$lk")")"
  icu="$(count 'name = "icu' "$lk")"
  rq="$(count 'name = "reqwest"' "$lk")"
  if [ "$icu" = 0 ] && [ "$rq" = 0 ]; then
    note "PASS: $name lock has no ICU / reqwest subtree"
  else
    bad "$name lock reintroduced forbidden deps (icu=$icu reqwest=$rq)"
  fi
done

# Optional digests for the provenance record.
hasher=""
command -v b3sum >/dev/null 2>&1 && hasher="b3sum"
if [ -n "$hasher" ]; then
  for lk in "$VAL" "$IND"; do
    note "digest $(basename "$(dirname "$lk")")/Cargo.lock: $($hasher "$lk" | awk '{print $1}')"
  done
else
  note "note: no BLAKE3 CLI found; skipping lock digests (content checks still enforced)"
fi

exit "$fail"

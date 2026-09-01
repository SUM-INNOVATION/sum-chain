#!/usr/bin/env bash
# B0-PRE RETIREMENT contract (#196): current `main` is retired and CANNOT produce a new official B0
# measurement. Asserts (1) the retirement marker + UNBOUND live authority in tooling_authority.rs, and
# (2) the shared production gate `require_two_roots` refuses fail-closed with B0_PRE_RETIRED. Prints
# the terminal marker B0_PRE_RETIRED_TEST_PASS on success (the CI step asserts it).
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$SCRIPTS/../../.." && pwd)"
TA="$ROOT/tools/b0-pre-validator/src/tooling_authority.rs"
fail() { echo "B0_PRE_RETIRED_TEST FAIL: $*" >&2; exit 1; }

# (1) retirement marker + UNBOUND live authority.
grep -qE '^pub const B0_PRE_RETIRED: bool = true;' "$TA" || fail "B0_PRE_RETIRED marker absent in $TA"
grep -qE 'RATIFIED_MEASUREMENT_TOOLING_COMMIT: &str = UNBOUND;' "$TA" \
  || fail "live RATIFIED_MEASUREMENT_TOOLING_COMMIT is not UNBOUND"
grep -qE 'RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3: &str = UNBOUND;' "$TA" \
  || fail "live RATIFIED_MEASUREMENT_TOOLING_PATHSET_BLAKE3 is not UNBOUND"
echo "ok - retirement marker present; live tooling authority is UNBOUND"

# (2) require_two_roots refuses fail-closed with B0_PRE_RETIRED. Use a distinct throwaway measured
# root; the tooling root is this (retired) repo. The retirement gate fires before any authority work.
# shellcheck source=../two_root_authority.sh
. "$SCRIPTS/two_root_authority.sh"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/measured"
out="$( (require_two_roots --measured-source-root "$tmp/measured" --tooling-root "$ROOT") 2>&1 )"
rc=$?
[ "$rc" -eq 9 ] || fail "require_two_roots exit was $rc, expected 9 (fail-closed refusal)"
printf '%s\n' "$out" | grep -q 'B0_PRE_RETIRED' || fail "refusal did not carry the B0_PRE_RETIRED marker; got: $out"
echo "ok - require_two_roots refuses production measurement fail-closed (B0_PRE_RETIRED, exit 9)"

echo "B0_PRE_RETIRED_TEST_PASS"

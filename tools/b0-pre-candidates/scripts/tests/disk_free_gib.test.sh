#!/usr/bin/env bash
# Deterministic unit tests for the portable disk-free helpers in lib.sh (Blocker 4).
#
# The KiB->GiB parse (`df_avail_gib_from_posix_k`) is tested against CANNED `df -Pk`
# output so the assertions are platform-independent and reproducible; the whole-function
# and threshold cases exercise the real filesystem so `require_free_gib` is proven to
# observe actual free space rather than the constant 0 the BSD-only `df -g` produced on
# GNU/Linux. No network, no toolchain, nothing fabricated. Runs on GNU/Linux and macOS.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"
set +e   # manage pass/fail manually; lib.sh's `set -e` must not abort the harness

fails=0
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then printf 'ok    %s (=%s)\n' "$1" "$3"
  else printf 'FAIL  %s: expected %s got %s\n' "$1" "$2" "$3" >&2; fails=$((fails + 1)); fi
}
check_rc() { # check_rc <name> <expected_rc> <actual_rc>
  if [ "$2" = "$3" ]; then printf 'ok    %s (rc=%s)\n' "$1" "$3"
  else printf 'FAIL  %s: expected rc %s got %s\n' "$1" "$2" "$3" >&2; fails=$((fails + 1)); fi
}

# GNU coreutils and BSD/macOS both emit POSIX `df -Pk`: a header row and one data row
# whose 4th column is Available in KiB. They differ only in column spacing / device
# names, which the field-split parse must tolerate. Samples use exact-GiB values so the
# expected whole-GiB result is unambiguous.

# 1. GNU-style `df -Pk` — Available 524288000 KiB = 500 GiB exactly.
gnu_df='Filesystem     1024-blocks      Used  Available Capacity Mounted on
/dev/root        536870912  12582912  524288000      3% /'
check "GNU df -Pk -> 500 GiB" 500 "$(printf '%s\n' "$gnu_df" | df_avail_gib_from_posix_k)"

# 2. BSD/macOS-style `df -Pk` — Available 83886080 KiB = 80 GiB exactly.
bsd_df='Filesystem 1024-blocks     Used Available Capacity  Mounted on
/dev/disk3s1  976490576 800000000  83886080    91%    /'
check "BSD df -Pk -> 80 GiB" 80 "$(printf '%s\n' "$bsd_df" | df_avail_gib_from_posix_k)"

# 3. Sub-GiB Available floors to 0 (integer-GiB behavior preserved).
sub='Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/x 100 90 1000 1% /'
check "sub-GiB avail floors to 0" 0 "$(printf '%s\n' "$sub" | df_avail_gib_from_posix_k)"

# 4. Malformed output (non-numeric Available) -> 0 (fail-closed on garbage).
mal='Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/x N/A N/A N/A - /'
check "malformed avail -> 0" 0 "$(printf '%s\n' "$mal" | df_avail_gib_from_posix_k)"

# 5. Header-only and empty input -> 0 (no data row).
check "header-only -> 0" 0 "$(printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n' | df_avail_gib_from_posix_k)"
check "empty -> 0" 0 "$(printf '' | df_avail_gib_from_posix_k)"

# 6. Missing path via disk_free_gib -> 0 (df errors; substitution yields 0, fail-closed).
check "missing path -> 0" 0 "$(disk_free_gib "/no/such/path/xyzzy_$$")"

# 7. Live regression: a real filesystem is observed as > 0, NOT stuck at 0.
live="$(disk_free_gib "$HERE")"
if printf '%s' "$live" | grep -Eq '^[0-9]+$' && [ "$live" -gt 0 ]; then
  printf 'ok    real fs observed > 0 (=%s GiB)\n' "$live"
else
  printf 'FAIL  real fs should be > 0, got "%s"\n' "$live" >&2; fails=$((fails + 1))
fi

# 8. Sufficient threshold passes (>= 1 GiB against the real fs).
( require_free_gib "$HERE" 1 ) >/dev/null 2>&1; check_rc "require_free_gib min=1 passes" 0 $?

# 9. Insufficient threshold refuses fail-closed (absurd minimum -> die, exit 2).
( require_free_gib "$HERE" 100000000 ) >/dev/null 2>&1; check_rc "require_free_gib min=1e8 refuses" 2 $?

# 10. require_headroom_gib shares the same helper and also refuses fail-closed.
( require_headroom_gib "$HERE" 100000000 "unit-test stage" ) >/dev/null 2>&1; check_rc "require_headroom_gib huge refuses" 2 $?

echo "----"
if [ "$fails" -eq 0 ]; then echo "disk_free_gib: ALL TESTS PASS"; exit 0
else echo "disk_free_gib: $fails FAILURE(S)" >&2; exit 1; fi

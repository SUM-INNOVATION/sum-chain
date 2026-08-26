#!/usr/bin/env bash
# Lifecycle-mode boundary guard tests (no Docker/network/toolchain). Drives the
# SHARED lib.sh:b0pre_lifecycle_guard against fabricated docs/b0-pre trees and
# asserts it splits the two frozen phases correctly and fails closed on every
# mismatch:
#   preregistration => committed artifact not_finalizable + NO spec-hash sidecar;
#   measurement     => committed artifact finalizable + b0-pre-protocol-v1.json.hash
#                      == the merged b0_pre_spec_hash EXACTLY.
# It also proves the guard keys on the STATE field, not the "not_finalizable" prose
# that legitimately appears in the frozen finalization-rule text.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
# shellcheck source=../lib.sh
. "$SCR/lib.sh" >/dev/null 2>&1

MERGED="e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2"
T="$(mktemp -d "${TMPDIR:-/tmp}/b0-lifecycle-XXXXXX")"; trap 'rm -rf "$T"' EXIT
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }

# b0pre_lifecycle_guard calls `die` (exit 2) on refusal; run it in a SUBSHELL so a
# fail-closed guard does not abort the test.
gate() { ( b0pre_lifecycle_guard "$@" ) >/dev/null 2>&1; }
expect_pass() { local l="$1"; shift; if gate "$@"; then ok "$l (guard PASSES)"; else bad "$l — guard should PASS"; fi; }
expect_fail() { local l="$1"; shift; if gate "$@"; then bad "$l — guard should FAIL CLOSED"; else ok "$l (guard fails closed)"; fi; }

# mkfix <dir> <artifact-json> [<sidecar-content>] : build a docs/b0-pre tree, echo <dir>.
mkfix() {
  local d="$1" art="$2" side="${3:-}"
  mkdir -p "$d/protocol"
  printf '%s\n' "$art" > "$d/protocol/b0-pre-protocol-v1.json"
  if [ -n "$side" ]; then printf '%s\n' "$side" > "$d/protocol/b0-pre-protocol-v1.json.hash"; fi
  printf '%s' "$d"
}

# Fixtures use the committed pretty-print form ("state": "..."). The finalizable
# fixture also carries "not_finalizable" as rule PROSE (never as the state value).
PRE="$(mkfix "$T/pre" '{"finalization":{"state": "not_finalizable","note":"blocked"}}')"
MEAS="$(mkfix "$T/meas" '{"finalization":{"state": "finalizable"},"rule":"a not_finalizable artifact cannot be hashed"}' "$MERGED")"
MEAS_NOHASH="$(mkfix "$T/meas_nohash" '{"finalization":{"state": "finalizable"}}')"
MEAS_WRONG="$(mkfix "$T/meas_wrong" '{"finalization":{"state": "finalizable"}}' "deadbeef$(printf '%056d' 0)")"
PRE_WITHHASH="$(mkfix "$T/pre_withhash" '{"finalization":{"state": "not_finalizable"}}' "$MERGED")"

# preregistration
expect_pass "preregistration: not_finalizable + no sidecar"                 preregistration "$PRE"
expect_fail "preregistration: finalizable state rejected"                   preregistration "$MEAS"
expect_fail "preregistration: sidecar present rejected"                     preregistration "$PRE_WITHHASH"
# measurement
expect_pass "measurement: finalizable + correct sidecar (prose ignored)"    measurement "$MEAS" "$MERGED"
expect_fail "measurement: not_finalizable state rejected"                   measurement "$PRE" "$MERGED"
expect_fail "measurement: missing sidecar rejected"                         measurement "$MEAS_NOHASH" "$MERGED"
expect_fail "measurement: wrong sidecar hash rejected"                      measurement "$MEAS_WRONG" "$MERGED"
expect_fail "measurement: missing expected-hash arg rejected"               measurement "$MEAS"
expect_fail "measurement: non-hex expected hash rejected"                   measurement "$MEAS" "not-a-hex-value-00000000000000000000000000000000000000000000000000"
# misc
expect_fail "unknown mode rejected"                                         bogus "$MEAS" "$MERGED"
expect_fail "missing committed artifact rejected"                           measurement "$T/does-not-exist" "$MERGED"

echo "----"
if [ "$F" = 0 ]; then echo "lifecycle_mode: ALL PASS"; else echo "lifecycle_mode: FAILURES" >&2; fi
exit "$F"

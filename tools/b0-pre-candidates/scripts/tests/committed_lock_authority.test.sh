#!/usr/bin/env bash
# Regression for the SHARED committed-candidate-lock AUTHORITY (committed_lock_authority.sh) — the
# single source of truth consumed by BOTH the CI workspace guard (check_no_prod_dep.sh) and the
# native-venue measurement preflight (preflight_venue.sh).
#
# Proves, against throwaway git-repo fixtures whose committed locks are copied byte-for-byte from the
# real repo:
#   * the two EXACT committed locks pass;
#   * either lock missing / untracked / empty / symlink / one-byte mutation / swapped / wrong file at
#     a canonical path all refuse;
#   * an additional unexpected committed candidate Cargo.lock refuses (exact-set);
# and, against the REAL tree, that `preflight_venue.sh --mode=measurement` PASSES the lock gate and
# REACHES the next gate (staged-context §2) rather than failing on the valid committed locks.
#
# Pure shell for the helper cases (no network/toolchain); the preflight assertion greps §1/§2 output
# (both reached without a toolchain).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$SCRIPTS/../../.." && pwd)"
# shellcheck source=../committed_lock_authority.sh
. "$SCRIPTS/committed_lock_authority.sh"

SP1_REL="tools/b0-pre-candidates/candidates/sp1/Cargo.lock"
RISC0_REL="tools/b0-pre-candidates/candidates/risc0/Cargo.lock"
REAL_SP1="$REPO/$SP1_REL"
REAL_RISC0="$REPO/$RISC0_REL"
{ [ -f "$REAL_SP1" ] && [ -f "$REAL_RISC0" ]; } || { echo "missing real committed candidate locks"; exit 1; }

pass=0
auth_case() {  # <name> <accept|reject> <root>
  local name="$1" expect="$2" root="$3" rc=0
  require_committed_lock_authority "$root" >/dev/null 2>&1 || rc=$?
  if [ "$expect" = reject ]; then
    if [ "$rc" -ne 0 ]; then echo "PASS: $name rejected (rc=$rc)"; else echo "FAIL: $name should reject"; pass=1; fi
  else
    if [ "$rc" -eq 0 ]; then echo "PASS: $name accepted"; else echo "FAIL: $name should accept (rc=$rc)"; pass=1; fi
  fi
}

scaffold() {  # <root> — a git repo carrying BOTH exact committed locks
  local root="$1"
  mkdir -p "$root/$(dirname "$SP1_REL")" "$root/$(dirname "$RISC0_REL")"
  cp "$REAL_SP1" "$root/$SP1_REL"
  cp "$REAL_RISC0" "$root/$RISC0_REL"
  git init -q "$root"
  git -C "$root" add -A
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# positive: the two exact committed locks
P="$tmp/ok"; scaffold "$P"
auth_case "both exact committed locks present+tracked+correct-sha" accept "$P"

M="$tmp/miss";  scaffold "$M";  rm -f "$M/$SP1_REL";                                      auth_case "sp1 missing" reject "$M"
E="$tmp/empty"; scaffold "$E";  : > "$E/$RISC0_REL";                                      auth_case "risc0 empty" reject "$E"
S="$tmp/sym";   scaffold "$S";  rm -f "$S/$SP1_REL"; ln -s /dev/null "$S/$SP1_REL";       auth_case "sp1 symlink" reject "$S"
U="$tmp/untr";  scaffold "$U";  git -C "$U" rm --cached -q -- "$RISC0_REL";               auth_case "risc0 untracked" reject "$U"
T="$tmp/mut";   scaffold "$T";  printf '\n# drift\n' >> "$T/$SP1_REL";                    auth_case "sp1 one-byte mutation" reject "$T"
W="$tmp/wrong"; scaffold "$W";  printf 'not a Cargo.lock\n' > "$W/$SP1_REL"; git -C "$W" add -A; auth_case "wrong file at sp1 canonical path" reject "$W"
SW="$tmp/swap"; scaffold "$SW"; cp "$REAL_RISC0" "$SW/$SP1_REL"; cp "$REAL_SP1" "$SW/$RISC0_REL"; git -C "$SW" add -A
auth_case "candidate locks swapped" reject "$SW"

# exact-set: an ADDITIONAL unexpected committed candidate Cargo.lock is detected.
X="$tmp/extra"; scaffold "$X"
mkdir -p "$X/tools/b0-pre-candidates/candidates/sp1/guest"
printf 'version = 3\n' > "$X/tools/b0-pre-candidates/candidates/sp1/guest/Cargo.lock"
git -C "$X" add -A
extra="$(committed_lock_authority_extra_locks "$X" tools/b0-pre-candidates/candidates tools/b0-pre-candidates/guest-core)"
if [ -n "$extra" ]; then echo "PASS: unexpected extra committed candidate lock detected ($extra)"; else echo "FAIL: extra committed lock not detected"; pass=1; fi
# clean fixture has NO extra lock.
extra_clean="$(committed_lock_authority_extra_locks "$P" tools/b0-pre-candidates/candidates tools/b0-pre-candidates/guest-core)"
if [ -z "$extra_clean" ]; then echo "PASS: exact authority set has no unexpected committed lock"; else echo "FAIL: false extra on the exact set ($extra_clean)"; pass=1; fi

# preflight measurement mode PASSES the lock gate and REACHES the next gate on the real tree.
pf="$(bash "$SCRIPTS/preflight_venue.sh" --mode=measurement 2>&1 || true)"
if printf '%s\n' "$pf" | grep -q 'committed candidate lock authority OK.*sp1/Cargo.lock' \
   && printf '%s\n' "$pf" | grep -q 'committed candidate lock authority OK.*risc0/Cargo.lock' \
   && printf '%s\n' "$pf" | grep -q 'no unexpected committed Cargo.lock in the guest graph' \
   && printf '%s\n' "$pf" | grep -q 'staged context reproduces the official guest graph' \
   && ! printf '%s\n' "$pf" | grep -qE 'FAIL: .*committed candidate lock'; then
  echo "PASS: preflight --mode=measurement passes the lock gate and reaches the staging gate"
else
  echo "FAIL: preflight --mode=measurement did not clear the lock gate / reach the next gate"; pass=1
fi

echo "----"
if [ "$pass" = 0 ]; then echo "committed_lock_authority: ALL PASS"; else echo "committed_lock_authority: FAILURES" >&2; fi
exit "$pass"

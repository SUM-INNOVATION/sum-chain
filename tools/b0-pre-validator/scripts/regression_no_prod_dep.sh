#!/usr/bin/env bash
# Regression harness for check_no_prod_dep.sh.
#
# Part 1 (production-dependency confinement — unchanged): a PRODUCTION or rogue-TOOL edge to
# b0-pre-vmat is REJECTED; the SAME edge in an APPROVED path is ACCEPTED.
#
# Part 2 (committed-candidate-lock AUTHORITY, guard 6): the two canonical committed candidate
# Cargo.locks are the dependency-selection authority — each must be present, Git-tracked, a regular
# non-symlink nonempty file, and byte-identical to its ratified SHA-256. Refusal is proven for:
# either lock missing, empty, a symlink, an untracked drop-in, a one-byte mutation (hash mismatch),
# swapped candidates, and a wrong file at a canonical path. Acceptance holds only for the two exact
# committed files.
#
# No network, no cargo build. Fixtures are throwaway git repos (guard 6 checks Git-tracking) whose
# committed locks are copied byte-for-byte from the real repo. Exit 0 = the guard behaves as
# specified.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CHECK="$HERE/check_no_prod_dep.sh"
[ -f "$CHECK" ] || { echo "missing $CHECK"; exit 1; }
SP1_REL="tools/b0-pre-candidates/candidates/sp1/Cargo.lock"
RISC0_REL="tools/b0-pre-candidates/candidates/risc0/Cargo.lock"
REAL_SP1="$REPO/$SP1_REL"
REAL_RISC0="$REPO/$RISC0_REL"
{ [ -f "$REAL_SP1" ] && [ -f "$REAL_RISC0" ]; } || { echo "missing real committed candidate locks"; exit 1; }

pass=0
run_case() {  # <name> <reject|accept> <fixture-root>
  local name="$1" expect="$2" root="$3" rc=0
  CHECK_ROOT="$root" bash "$CHECK" >/dev/null 2>&1 || rc=$?
  if [ "$expect" = reject ]; then
    if [ "$rc" -ne 0 ]; then printf 'PASS: %s rejected (rc=%s)\n' "$name" "$rc"
    else printf 'FAIL: %s should have been rejected but passed\n' "$name"; pass=1; fi
  else
    if [ "$rc" -eq 0 ]; then printf 'PASS: %s accepted\n' "$name"
    else printf 'FAIL: %s should have been accepted but rc=%s\n' "$name" "$rc"; pass=1; fi
  fi
}

git_track() { git init -q "$1"; git -C "$1" add -A; }  # stage everything; guard 6 checks the index

scaffold() {  # <root> — excluded-tools workspace + real b0-pre-vmat leaf + BOTH committed locks
  local root="$1"
  mkdir -p "$root/tools/b0-pre-vmat" "$root/$(dirname "$SP1_REL")" "$root/$(dirname "$RISC0_REL")"
  cat > "$root/Cargo.toml" <<'TOML'
[workspace]
exclude = ["tools"]
TOML
  cat > "$root/tools/b0-pre-vmat/Cargo.toml" <<'TOML'
[package]
name = "b0-pre-vmat"
version = "0.0.0"
edition = "2021"
[dependencies]
blake3 = "=1.5.4"
TOML
  cp "$REAL_SP1" "$root/$SP1_REL"
  cp "$REAL_RISC0" "$root/$RISC0_REL"
  git_track "$root"
}

vmat_dep() {  # a Cargo.toml body with a b0-pre-vmat path edge
  cat <<'TOML'
[package]
name = "evil"
version = "0.0.0"
edition = "2021"
[dependencies]
b0-pre-vmat = { path = "../../tools/b0-pre-vmat" }
TOML
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- Part 1: production-dependency confinement (behavior preserved) --------------------------
A="$tmp/prod"; scaffold "$A"; mkdir -p "$A/crates/evil"; vmat_dep > "$A/crates/evil/Cargo.toml"
run_case "production edge to b0-pre-vmat" reject "$A"

B="$tmp/rogue"; scaffold "$B"; mkdir -p "$B/tools/rogue-tool"; vmat_dep > "$B/tools/rogue-tool/Cargo.toml"
run_case "rogue tool edge to b0-pre-vmat" reject "$B"

C="$tmp/ok"; scaffold "$C"
mkdir -p "$C/tools/b0-pre-candidates/harness/sp1-verifier-material"
vmat_dep > "$C/tools/b0-pre-candidates/harness/sp1-verifier-material/Cargo.toml"
git -C "$C" add -A
run_case "approved harness edge to b0-pre-vmat" accept "$C"

# ---- Part 2: committed-candidate-lock authority (guard 6) ------------------------------------
# Positive: the two exact committed locks, present + Git-tracked + correct SHA-256 -> ACCEPTED.
P="$tmp/authority"; scaffold "$P"
run_case "both committed locks present+tracked+correct-sha" accept "$P"

# either lock missing
M="$tmp/miss-sp1"; scaffold "$M"; rm -f "$M/$SP1_REL"
run_case "sp1 lock missing" reject "$M"

# empty lock (tracked but zero bytes)
E="$tmp/empty-risc0"; scaffold "$E"; : > "$E/$RISC0_REL"
run_case "risc0 lock empty" reject "$E"

# symlink at a canonical path
S="$tmp/symlink-sp1"; scaffold "$S"; rm -f "$S/$SP1_REL"; ln -s /dev/null "$S/$SP1_REL"
run_case "sp1 lock symlink" reject "$S"

# present + correct bytes but UNTRACKED (drop-in, not committed)
U="$tmp/untracked-risc0"; scaffold "$U"; git -C "$U" rm --cached -q -- "$RISC0_REL"
run_case "risc0 lock present but untracked" reject "$U"

# one-byte mutation -> hash mismatch (path still tracked)
MUT="$tmp/mutate-sp1"; scaffold "$MUT"; printf '\n# drift\n' >> "$MUT/$SP1_REL"
run_case "sp1 lock one-byte mutation (hash mismatch)" reject "$MUT"

# candidates swapped -> both hashes mismatch
SW="$tmp/swapped"; scaffold "$SW"; cp "$REAL_RISC0" "$SW/$SP1_REL"; cp "$REAL_SP1" "$SW/$RISC0_REL"; git -C "$SW" add -A
run_case "candidate locks swapped (hash mismatch)" reject "$SW"

# wrong (non-lock) file at a canonical path -> hash mismatch
W="$tmp/wrong-sp1"; scaffold "$W"; printf 'not a Cargo.lock\n' > "$W/$SP1_REL"; git -C "$W" add -A
run_case "wrong file at sp1 canonical path (hash mismatch)" reject "$W"

exit "$pass"

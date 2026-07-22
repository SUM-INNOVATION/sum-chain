#!/usr/bin/env bash
# Regression harness for check_no_prod_dep.sh (Correction 8).
#
# Proves, on a throwaway fixture repo:
#   * a PRODUCTION Cargo.toml edge to b0-pre-vmat is REJECTED, and
#   * a rogue non-approved TOOL edge to b0-pre-vmat is REJECTED,
# and, as a positive control, that a fixture with the same b0-pre-vmat edge moved
# into an APPROVED path is ACCEPTED.
#
# No network, no cargo build; the fixture is pure text. Exit 0 = the guard behaves
# as specified.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHECK="$HERE/check_no_prod_dep.sh"
[ -f "$CHECK" ] || { echo "missing $CHECK"; exit 1; }

pass=0
run_case() {  # <name> <expect: reject|accept> <fixture-root>
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

scaffold() {  # <root> — a minimal excluded-tools workspace + a real b0-pre-vmat leaf
  local root="$1"
  mkdir -p "$root/tools/b0-pre-vmat"
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
}

vmat_dep() {  # emit a Cargo.toml body with a b0-pre-vmat path edge
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

# Case A: a PRODUCTION crate depends on b0-pre-vmat -> must be rejected.
A="$tmp/prod"; scaffold "$A"; mkdir -p "$A/crates/evil"; vmat_dep > "$A/crates/evil/Cargo.toml"
run_case "production edge to b0-pre-vmat" reject "$A"

# Case B: a rogue TOOL crate (not in the approved allowlist) depends on
# b0-pre-vmat -> must be rejected by the confinement check even though it is
# under tools/ (which the production-edge check skips).
B="$tmp/rogue"; scaffold "$B"; mkdir -p "$B/tools/rogue-tool"; vmat_dep > "$B/tools/rogue-tool/Cargo.toml"
run_case "rogue tool edge to b0-pre-vmat" reject "$B"

# Case C (positive control): the SAME edge in an APPROVED path is accepted.
C="$tmp/ok"; scaffold "$C"
mkdir -p "$C/tools/b0-pre-candidates/harness/sp1-verifier-material"
vmat_dep > "$C/tools/b0-pre-candidates/harness/sp1-verifier-material/Cargo.toml"
run_case "approved harness edge to b0-pre-vmat" accept "$C"

exit "$pass"

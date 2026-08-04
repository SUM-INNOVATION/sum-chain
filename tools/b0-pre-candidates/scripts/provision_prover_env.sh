#!/usr/bin/env bash
# Verify + EXPOSE the genuine-proof proving environment consumed by prove_fixture.sh.
#
# The pinned terminal-Groth16 backends (sp1-gnark prove+verify / risc0 stark2snark) are run
# by the pinned SDK under the Docker invocation FIREWALL (docker_firewall.sh). This script is
# the single fail-closed gate that asserts every pinned proving input is present and correctly
# constrained, then prints the `export PROVER_*` lines the producer (verifier_fixtures.sh ->
# prove_fixture.sh) inherits. It PROVISIONS nothing itself (no download, no extraction, no
# world-writable mode change) — it only verifies pre-provisioned pins and surfaces them, so it
# is safe to run inside the reproducible smoke and records exactly what the attestation will
# bind. Any missing/misconstrained input is a hard error (never a synthetic proof downstream).
#
# Verified:
#   * the firewall script exists (installed as `docker` on a scoped PATH by prove_fixture.sh);
#   * the REAL docker is an absolute, executable, non-firewall binary;
#   * the pinned SP1 gnark circuit surfaced at ~/.sp1/circuits/groth16/<ver> resolves to a
#     content-store object (read-only canonical input; the firewall mounts it RO);
#   * the pinned r0vm 3.0.5 (the causal RISC Zero prover) is executable;
#   * the isolated RISC0_HOME carries the pinned r0.1.91.1 guest toolchain.
#
# Usage:  eval "$(provision_prover_env.sh <content_store> <r0vm_dir> <risc0_home> [circuit_version])"
#   emits, on success, the PROVER_* export lines to STDOUT (diagnostics go to STDERR).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { printf 'PROVER-ENV-REFUSED: %s\n' "$*" >&2; exit 6; }

CSTORE="${1:-}"; R0VM_DIR="${2:-}"; RISC0_HOME_HOST="${3:-}"; CIRC_VER="${4:-v6.1.0}"
[ -n "$CSTORE" ] && [ -d "$CSTORE" ]                 || die "content_store arg is not a directory: '${CSTORE:-<unset>}'"
[ -n "$R0VM_DIR" ] && [ -x "$R0VM_DIR/r0vm" ]        || die "r0vm_dir/r0vm is not executable: '${R0VM_DIR:-<unset>}'"
[ -n "$RISC0_HOME_HOST" ] && [ -f "$RISC0_HOME_HOST/settings.toml" ] || die "risc0_home is not a provisioned RISC0_HOME: '${RISC0_HOME_HOST:-<unset>}'"

# --- firewall + real docker -----------------------------------------------------------------
FIREWALL_SH="${PROVER_FIREWALL_SH:-$HERE/docker_firewall.sh}"
[ -f "$FIREWALL_SH" ] || die "the Docker invocation firewall is absent: $FIREWALL_SH"
REAL_DOCKER="${PROVER_REAL_DOCKER:-$(command -v docker 2>/dev/null || true)}"
REAL_DOCKER="$(readlink -f "$REAL_DOCKER" 2>/dev/null || echo "$REAL_DOCKER")"
[ -n "$REAL_DOCKER" ] && [ -x "$REAL_DOCKER" ] || die "the real docker binary was not found/executable: '$REAL_DOCKER'"
case "$REAL_DOCKER" in /*) ;; *) die "real docker must be an absolute path: $REAL_DOCKER" ;; esac

# --- SP1 pinned gnark circuit: ~/.sp1 surface must resolve under the content store -----------
CSTORE_CANON="$(readlink -f "$CSTORE")"
CIRC_LINK="$HOME/.sp1/circuits/groth16/$CIRC_VER"
[ -e "$CIRC_LINK" ] || die "SP1 gnark circuit is not provisioned at $CIRC_LINK (the SDK reads it here)"
CIRC_CANON="$(readlink -f "$CIRC_LINK")"
case "$CIRC_CANON/" in
  "$CSTORE_CANON"/*) ;;
  *) die "SP1 circuit $CIRC_LINK resolves to $CIRC_CANON, NOT under the content store $CSTORE_CANON; the firewall would refuse it" ;;
esac
# The circuit must be a read-only canonical input (never world-writable): assert no group/other
# write bit on the resolved directory (defence-in-depth beyond the firewall's own RO mount).
cmode="$(stat -c '%a' "$CIRC_CANON" 2>/dev/null || stat -f '%Lp' "$CIRC_CANON" 2>/dev/null || echo '')"
case "$cmode" in *[2367]) die "SP1 circuit object $CIRC_CANON is group/other-writable (mode $cmode); canonical inputs must stay read-only" ;; esac

R0VM_DIR_ABS="$(cd "$R0VM_DIR" && pwd)"
RISC0_HOME_ABS="$(cd "$RISC0_HOME_HOST" && pwd)"

printf 'verified proving-env: firewall=%s real-docker=%s circuit=%s(mode %s) r0vm=%s risc0_home=%s\n' \
  "$FIREWALL_SH" "$REAL_DOCKER" "$CIRC_CANON" "$cmode" "$R0VM_DIR_ABS/r0vm" "$RISC0_HOME_ABS" >&2

# --- emit the PROVER_* exports the producer inherits ----------------------------------------
printf 'export PROVER_FIREWALL_SH=%q\n'          "$FIREWALL_SH"
printf 'export PROVER_REAL_DOCKER=%q\n'          "$REAL_DOCKER"
printf 'export PROVER_SP1_CONTENT_STORE=%q\n'    "$CSTORE_CANON"
printf 'export PROVER_SP1_CIRCUIT_VERSION=%q\n'  "$CIRC_VER"
printf 'export PROVER_R0VM_DIR=%q\n'             "$R0VM_DIR_ABS"
printf 'export PROVER_RISC0_HOME=%q\n'           "$RISC0_HOME_ABS"

#!/usr/bin/env bash
# Contract test for the host-side prover sandbox (run_prover_backend.sh). Verifies, WITHOUT
# docker, that the constructed container argv carries every required restriction and NONE of
# the forbidden ones, and that the fail-closed preconditions refuse bad input.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN="$HERE/../run_prover_backend.sh"
fails=0
ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/circuit" "$WORK/out"
printf 'x' > "$WORK/input.bin"
IMG="ghcr.io/succinctlabs/sp1-gnark@sha256:be8555f1ad90870acd8c6ec7fd3ba0b1a2133ea9cddf25e130665aa651129e54"
CFG="sha256:ceb60d80f46cd8e5869abd778f26dc34c4f3bab205f3d1d5275e532121cced4e"

# Capture the NUL-delimited argv the runner would exec.
argv="$(bash "$RUN" --image-digest "$IMG" --config-digest "$CFG" \
  --circuit-ro "$WORK/circuit" --input-ro "$WORK/input.bin" --output "$WORK/out" \
  --print-argv -- prove --system groth16 /circuit /input /output | tr '\0' '\n')"

have() { printf '%s\n' "$argv" | grep -Fqx -e "$1"; }
haveseq() { printf '%s\n' "$argv" | grep -Fq -e "$1"; }

# Required restrictions.
have "--network"      && haveseq "none"                        && ok "network none"        || fail "missing --network none"
have "--read-only"                                             && ok "read-only rootfs"    || fail "missing --read-only"
have "--cap-drop"     && have "ALL"                            && ok "cap-drop ALL"        || fail "missing --cap-drop ALL"
have "--security-opt" && have "no-new-privileges"              && ok "no-new-privileges"   || fail "missing no-new-privileges"
have "--pull"         && have "never"                          && ok "pull never"          || fail "missing --pull never"
haveseq "type=bind,source=$WORK/circuit,target=/circuit,readonly" && ok "circuit mounted read-only" || fail "circuit not read-only"
haveseq "type=bind,source=$WORK/input.bin,target=/input,readonly" && ok "input mounted read-only"   || fail "input not read-only"
haveseq "type=bind,source=$WORK/out,target=/output"           && ok "output is the writable mount" || fail "output mount missing"
haveseq "$IMG"                                                && ok "image referenced by digest"  || fail "image ref missing"

# Forbidden postures must be ABSENT.
haveseq "docker.sock"   && fail "docker socket present" || ok "no docker socket"
haveseq "/var/run/docker" && fail "docker runtime dir present" || ok "no docker runtime dir"
have "--privileged"     && fail "--privileged present" || ok "not privileged"
have "--cap-add"        && fail "--cap-add present" || ok "no --cap-add"
haveseq "network=host"  && fail "host network present" || ok "no host network"
# The output mount must NOT carry ,readonly (it is the single writable mount).
printf '%s\n' "$argv" | grep -Fq "target=/output,readonly" && fail "output mount is read-only" || ok "output mount is writable"

# --- fail-closed preconditions ---
reject() { # <label> <args...>
  local label="$1"; shift
  if bash "$RUN" "$@" --print-argv -- x >/dev/null 2>&1; then fail "$label was accepted"; else ok "$label refused"; fi
}
reject "mutable tag image ref" --image-digest "ghcr.io/succinctlabs/sp1-gnark:v6.1.0" --config-digest "$CFG" --circuit-ro "$WORK/circuit" --output "$WORK/out2"
reject "missing config-digest"  --image-digest "$IMG" --circuit-ro "$WORK/circuit" --output "$WORK/out2"
reject "non-sha256 config"      --image-digest "$IMG" --config-digest "deadbeef" --circuit-ro "$WORK/circuit" --output "$WORK/out2"
# Reused / non-empty output dir must be refused.
mkdir -p "$WORK/dirty"; printf 'stale' > "$WORK/dirty/old"
reject "reused (non-empty) output dir" --image-digest "$IMG" --config-digest "$CFG" --circuit-ro "$WORK/circuit" --output "$WORK/dirty"

echo
if [ "$fails" -eq 0 ]; then echo "prover sandbox contract: ALL PASS"; exit 0
else echo "prover sandbox contract: $fails FAILED"; exit 1; fi

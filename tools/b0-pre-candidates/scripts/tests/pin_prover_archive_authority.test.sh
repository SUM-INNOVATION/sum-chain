#!/usr/bin/env bash
# Network AUTHORITY test: downloads the REAL immutable prover archives and drives each through the
# SINGLE verified-extraction implementation (provision_prover_toolchain.sh) — the exact path
# verify_pins.sh's (5b) block now invokes. Confirms (positive) the real archive sha256 + every
# member sha256/size verify against the actual bytes, and (mutations) that a realistic ONE-
# CHARACTER change to the archive sha OR to any member sha/size is refused. Covers every archive
# SHA and every member SHA/size across SP1 (x86_64 + aarch64) and the shared RISC Zero archive.
# Opt-in (needs network): B0PRE_PIN_NET_IT=1, else SKIP (so no-network CI stays green).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
PROV="$SCR/provision_prover_toolchain.sh"
[ "${B0PRE_PIN_NET_IT:-0}" = "1" ] || { echo "SKIP: set B0PRE_PIN_NET_IT=1 for the network prover-archive authority test"; echo "pin_prover_archive_authority: SKIPPED"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "SKIP: curl absent"; echo "pin_prover_archive_authority: SKIPPED"; exit 0; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
F=0
ok(){ printf 'ok    %s\n' "$1"; }
nok(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }
# flip the first hex char to a DIFFERENT one -> a genuine one-character mutation (bash-3.2 safe)
mut1(){ local s="$1"; if [ "${s:0:1}" = "0" ]; then printf 'f%s' "${s:1}"; else printf '0%s' "${s:1}"; fi; }
prov(){ ( bash "$PROV" "$@" ) >/dev/null 2>&1; }   # subshell: provisioner die (exit 4) does not abort the test

# check <label> <url> <arch_sha> <member_spec: path:sha:size:delivery>...
check(){
  local label="$1" url="$2" asha="$3"; shift 3
  local af="$T/$label.tgz"
  if ! curl -fsSL --max-redirs 5 "$url" -o "$af"; then nok "$label: download failed ($url)"; return; fi
  # positive — the real archive sha + complete member set verify against the actual bytes
  if prov "$af" "$asha" "$T/$label.i" "$T/$label.r" "$@"; then ok "$label: real archive sha256 + $# member(s) verify against bytes"
  else nok "$label: real pinned values FAILED to verify (unexpected)"; fi
  # archive sha one-char mutation
  if prov "$af" "$(mut1 "$asha")" "$T/$label.i.a" "$T/$label.r.a" "$@"; then nok "$label: archive_sha one-char mutation ACCEPTED"; else ok "$label: archive_sha256 one-char mutation refused"; fi
  # per-member sha + size one-char/off-by-one mutations (other members left correct)
  local n=0 spec s2 mp rest ms mz dv muts
  for spec in "$@"; do
    mp="${spec%%:*}"; rest="${spec#*:}"; ms="${rest%%:*}"; rest="${rest#*:}"; mz="${rest%%:*}"; dv="${rest#*:}"
    n=$((n + 1))
    muts=""; for s2 in "$@"; do if [ "$s2" = "$spec" ]; then muts="$muts $mp:$(mut1 "$ms"):$mz:$dv"; else muts="$muts $s2"; fi; done
    # shellcheck disable=SC2086
    if prov "$af" "$asha" "$T/$label.ms$n" "$T/$label.msr$n" $muts; then nok "$label: member $mp sha mutation ACCEPTED"; else ok "$label: member $mp sha256 one-char mutation refused"; fi
    muts=""; for s2 in "$@"; do if [ "$s2" = "$spec" ]; then muts="$muts $mp:$ms:$((mz + 1)):$dv"; else muts="$muts $s2"; fi; done
    # shellcheck disable=SC2086
    if prov "$af" "$asha" "$T/$label.mz$n" "$T/$label.mzr$n" $muts; then nok "$label: member $mp size mutation ACCEPTED"; else ok "$label: member $mp size off-by-one refused"; fi
  done
}

check "sp1_x86" \
  "https://github.com/succinctlabs/sp1/releases/download/v6.3.1/cargo_prove_v6.3.1_linux_amd64.tar.gz" \
  "c9d6ee7667fa9e0a2302324a6bb0295c55f6acf0e17a242ad11ee45767bb08df" \
  "cargo-prove:e21aa7bd13ace2049ca5115ba89236cbf1d3cf716aa6dafc35c10fab6ac7e969:53287520:isolated"

check "sp1_arm" \
  "https://github.com/succinctlabs/sp1/releases/download/v6.3.1/cargo_prove_v6.3.1_linux_arm64.tar.gz" \
  "9befbd3f5eead2c150579daf8d40bb25550a295dfcc406bf8ea53eaffe9aeed2" \
  "cargo-prove:b2591c397f0ee377d5db08ee84dc4cf902e9c247a8fd09b4c41ee5a77a86149f:45420240:isolated"

check "risc0" \
  "https://github.com/risc0/risc0/releases/download/v3.0.5/cargo-risczero-x86_64-unknown-linux-gnu.tgz" \
  "936ef988b78f20e3bd9f80e375f3adc934b13addc6ae2680f2e5fc0bcc966158" \
  "cargo-risczero:45aba69689cef25d81237f3ff62456fc96ff1e23f75adfcd16f7c8b8c1606619:15355120:isolated" \
  "r0vm:36c016a5bb2ded5bd1f8f92cc487e6ffaeb1e95ec05850c983081a0f716b515b:108998816:risc0server"

echo "----"
if [ "$F" = 0 ]; then echo "PIN_PROVER_ARCHIVE_AUTHORITY_PASS"; echo "pin_prover_archive_authority: ALL TESTS PASS"; exit 0
else echo "pin_prover_archive_authority: FAILURE(S)" >&2; exit 1; fi

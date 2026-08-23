#!/usr/bin/env bash
# TRANSPARENT rustc wrapper for the canonical runner-build path-independence recipe (RUSTC_WRAPPER).
#
# Cargo invokes a RUSTC_WRAPPER as:  <wrapper> <REAL_RUSTC> <rustc-arg>...   (argv[0] is the wrapper
# itself; "$@" is REAL_RUSTC followed by the rustc arguments). This wrapper is STRICTLY OUTPUT-NEUTRAL:
# it inspects the argv WITHOUT rewriting/reordering/reconstructing it, records evidence to a directory
# OUTSIDE the source/CARGO_HOME/target roots, adds NO rustc argument, emits NOTHING on success, and
# hands off with exactly `exec "$@"` (preserving exit status + signals).
#
# Fail-closed argv checks for a real crate COMPILE invocation (one carrying a `.rs` input / `--emit`):
#   * exactly ONE `--remap-path-prefix` argument — destination /b0/target. A MISSING / DUPLICATE /
#     ALTERED destination or an EXTRA remap all refuse. NEITHER the source NOR the cargo-home is remapped:
#     the source is materialized + compiled at the canonical build path /b0/tooling, and the
#     compiler-visible cargo home is the literal canonical /b0/cargo (materialized fresh per build), both
#     universal by construction — so /b0/tooling AND /b0/cargo must NEVER appear as a remap destination
#     (a /b0/cargo remap would be a fake identity mapping that no longer reflects the effective mapping).
# A non-compile PROBE invocation (rustc `-vV`/`--print` with no crate input) carries no source and is
# recorded (kind=probe) but not remap-checked. Evidence records are CONTENT-ADDRESSED (filename =
# BLAKE3(record)) so identical invocations collapse and there is no nondeterministic append order.
set -euo pipefail

wdie() { printf 'RUSTC-WRAPPER-REFUSED: %s\n' "$*" >&2; exit 9; }

CANON_CARGO='/b0/cargo'
CANON_TARGET='/b0/target'

[ "$#" -ge 1 ] || wdie "no REAL rustc in argv (RUSTC_WRAPPER contract: <wrapper> <rustc> <args>)"
command -v b3sum >/dev/null 2>&1 || wdie "b3sum not available (required to record invocation evidence)"
EVID="${B0_RUSTC_EVIDENCE_DIR:-}"
[ -n "$EVID" ] || wdie "B0_RUSTC_EVIDENCE_DIR is not set (refusing an unrecorded compile)"
[ -d "$EVID" ] || mkdir -p "$EVID" || wdie "cannot create evidence dir: $EVID"

# --- inspect argv[1..] (argv[0] == "$1" is REAL rustc); never mutate it -----------------------------
is_compile=0
declare -a remaps=()
k=1
while [ "$k" -le "$#" ]; do
  a="${!k}"
  if [ "$k" -eq 1 ]; then k=$((k+1)); continue; fi   # skip the REAL rustc path
  case "$a" in
    --remap-path-prefix)
      nk=$((k+1)); [ "$nk" -le "$#" ] || wdie "--remap-path-prefix with no value"
      remaps+=("${!nk}"); k=$((k+2)); continue ;;
    --remap-path-prefix=*) remaps+=("${a#--remap-path-prefix=}") ;;
    --out-dir) nk=$((k+1)); [ "$nk" -le "$#" ] && out_dir="${!nk}" ;;
    --out-dir=*) out_dir="${a#--out-dir=}" ;;
    *.rs) is_compile=1 ;;
    --emit=*|--emit) is_compile=1 ;;
  esac
  k=$((k+1))
done
# The sp1-core-executor-runner build.rs builds an inner HOST binary into `<target>/sp1-native-bins`,
# stripping CARGO_ENCODED_RUSTFLAGS (its own comment: "avoid cross-compilation issues"), so those
# compiles carry NO remaps. It is path-independent BY CONSTRUCTION because the compiler-visible cargo
# home is the literal canonical /b0/cargo (materialized fresh per build), so its vendored-dep source
# paths are canonical without any remap. Recorded (kind=nested) but NOT remap-enforced here. Detected by
# the fixed nested target-dir segment.
is_nested=0
case "${out_dir:-}" in */sp1-native-bins/*|*/sp1-native-bins) is_nested=1 ;; esac

seen_target=0
n_remaps=${#remaps[@]}
if [ "$n_remaps" -gt 0 ]; then
  for m in "${remaps[@]}"; do
    [ -n "$m" ] || continue
    to="${m##*=}"
    case "$to" in
      "$CANON_TARGET")  seen_target=$((seen_target+1)) ;;
      "$CANON_CARGO")   wdie "a --remap-path-prefix to $CANON_CARGO is refused: the cargo home is the literal canonical $CANON_CARGO (fresh per build), so it is NOT remapped" ;;
      *) wdie "altered/extra --remap-path-prefix destination '$to' (only $CANON_TARGET allowed; the source and the canonical cargo-home are NOT remapped)" ;;
    esac
  done
fi

if [ "$is_compile" -eq 1 ] && [ "$is_nested" -eq 1 ]; then
  kind=nested   # sp1-core-executor-runner inner host-binary build (canonical /b0/cargo home; not remap-enforced, path-independent by construction)
elif [ "$is_compile" -eq 1 ]; then
  [ "$n_remaps" -eq 1 ] || wdie "compile invocation has $n_remaps --remap-path-prefix args (require exactly 1: target -> $CANON_TARGET; the canonical cargo-home $CANON_CARGO is not remapped)"
  [ "$seen_target"  -eq 1 ] || wdie "compile is missing/duplicating the target remap -> $CANON_TARGET (count=$seen_target)"
  kind=compile
else
  kind=probe
fi

# --- content-addressed evidence record: the EXACT --remap-path-prefix argv in argv order -----------
# v2 retains the exact remap ARGUMENT bytes (`--remap-path-prefix=<from>=<to>`), one `remap_arg=` line
# per remap, IN THE ORDER rustc saw them — not a sorted destination CSV. The importer re-parses these
# to prove exactly ONE remap (the per-build target -> /b0/target), the exact FROM root (== the recipe's
# per-build target root), the exact canonical destination, and that there is no second remap (the
# canonical cargo-home is not remapped). The filename is BLAKE3(record), so the retained record_address
# can be re-derived from the record bytes (at import).
rec="$(
  printf 'b0-final-rustc-invocation/v2\n'
  printf 'kind=%s\n' "$kind"
  if [ "$n_remaps" -gt 0 ]; then
    for m in "${remaps[@]}"; do printf 'remap_arg=--remap-path-prefix=%s\n' "$m"; done
  fi
)"
addr="$(printf '%s' "$rec" | b3sum | awk '{print $1}')"
[ "${#addr}" -eq 64 ] || wdie "failed to content-address the invocation record"
printf '%s' "$rec" > "$EVID/$addr.rec" || wdie "cannot write invocation evidence to $EVID/$addr.rec"

# --- hand off to the REAL rustc, argv + environment UNCHANGED; silent on success --------------------
exec "$@"

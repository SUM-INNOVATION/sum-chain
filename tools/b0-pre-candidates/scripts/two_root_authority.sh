#!/usr/bin/env bash
# Shared TWO-ROOT authority resolver for the B0-FINAL identity/measurement path.
#
# The two-root model keeps the FROZEN measured source and the REVIEWED measurement tooling in two
# separate clean checkouts, recorded + verified INDEPENDENTLY. This file is meant to be SOURCED; it
# defines `require_two_roots` which parses explicit `--measured-source-root` / `--tooling-root` flags
# (never positional/env — ambiguity refuses), verifies each root, and exports the verified identities:
#
#   B0_MEASURED_ROOT   B0_MEASURED_COMMIT   B0_MEASURED_CLEAN
#   B0_TOOLING_ROOT    B0_TOOLING_COMMIT    B0_TOOLING_PATHSET_BLAKE3
#
# It prints an attestation of both roots + commits + digest to STDERR (so callers can keep STDOUT for
# machine output). Every check is fail-closed.
#
# Authority separation, enforced here:
#   * measured root HEAD MUST == RATIFIED_SOURCE_COMMIT (the frozen measured source), clean tree;
#   * tooling root supplies the reviewed tooling; its HEAD is the tooling commit and is NEVER compared
#     to RATIFIED_SOURCE_COMMIT;
#   * the two roots MUST be distinct real paths, neither nested in the other, neither a symlink, and
#     each must actually contain its own role's files (no cross-root substitution).

# The frozen MEASURED-SOURCE authority (mirrors b0_pre_validator::guest_set::RATIFIED_SOURCE_COMMIT).
: "${RATIFIED_SOURCE_COMMIT:=507281e21e95a6a98e3480e25e12d1baab586e07}"

_tr_die() { printf 'TWO-ROOT-REFUSED: %s\n' "$*" >&2; exit 9; }

# Resolve a real, existing, non-symlink directory to its absolute canonical path.
_tr_realdir() {
  local p="$1" role="$2"
  [ -n "$p" ] || _tr_die "$role root path is empty"
  [ -L "$p" ] && _tr_die "$role root is a symlink (refused): $p"
  [ -d "$p" ] || _tr_die "$role root is not a directory: $p"
  ( cd "$p" && pwd -P ) || _tr_die "$role root unresolvable: $p"
}

# require_two_roots "$@" — consumes the full arg list, requires EXACTLY the two flags.
require_two_roots() {
  local measured="" tooling=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --measured-source-root)
        [ $# -ge 2 ] || _tr_die "--measured-source-root needs a value"
        [ -z "$measured" ] || _tr_die "--measured-source-root given twice (ambiguous)"
        measured="$2"; shift 2 ;;
      --tooling-root)
        [ $# -ge 2 ] || _tr_die "--tooling-root needs a value"
        [ -z "$tooling" ] || _tr_die "--tooling-root given twice (ambiguous)"
        tooling="$2"; shift 2 ;;
      *) _tr_die "unexpected/positional argument (roots must be explicit flags): $1" ;;
    esac
  done
  [ -n "$measured" ] || _tr_die "--measured-source-root is required (never inferred from cwd/env)"
  [ -n "$tooling" ] || _tr_die "--tooling-root is required (never inferred from cwd/env)"
  command -v git >/dev/null 2>&1 || _tr_die "git not available"

  local m_abs t_abs
  m_abs="$(_tr_realdir "$measured" measured)"
  t_abs="$(_tr_realdir "$tooling" tooling)"

  # B0-PRE RETIREMENT GATE (#196). The B0 measurement phase is closed: production measurement is
  # permanently disabled on a retired tooling tree. Refuse fail-closed BEFORE any authority work, so
  # every shell producer that funnels through require_two_roots (measure_fragment, derive_guest_set,
  # produce_canonical_sp1_guest, produce_measurement_input_authority) cannot produce a new official B0
  # measurement. Historical evidence is verified from the tagged historical commit/release (see
  # docs/b0-final/B0-PRE-RETIREMENT.md), never from current main.
  if grep -qE '^pub const B0_PRE_RETIRED: bool = true;' \
       "$t_abs/tools/b0-pre-validator/src/tooling_authority.rs" 2>/dev/null; then
    _tr_die "B0_PRE_RETIRED: the B0 measurement phase is closed; this tooling tree cannot produce a new official B0 measurement (verify historical evidence from tag b0-final-evidence-60ace32c; see docs/b0-final/B0-PRE-RETIREMENT.md)"
  fi

  # Distinct, non-nested (the exact defect the two-root model removes: one checkout serving both).
  [ "$m_abs" = "$t_abs" ] && _tr_die "measured and tooling roots are the SAME path ($m_abs); two clean roots are mandatory"
  case "$t_abs/" in "$m_abs"/*) _tr_die "tooling root is nested under measured root" ;; esac
  case "$m_abs/" in "$t_abs"/*) _tr_die "measured root is nested under tooling root" ;; esac

  # No cross-root substitution: each root must actually carry its own role's files.
  [ -e "$m_abs/guest-core" ] || _tr_die "measured root lacks guest-core (not a measured-source tree): $m_abs"
  [ -e "$t_abs/tools/b0-pre-candidates/scripts/measure_fragment.sh" ] \
    || _tr_die "tooling root lacks the B0-FINAL scripts (not a tooling tree): $t_abs"

  # Each root is its own clean git work tree.
  git -C "$m_abs" rev-parse --is-inside-work-tree >/dev/null 2>&1 || _tr_die "measured root is not a git work tree"
  git -C "$t_abs" rev-parse --is-inside-work-tree >/dev/null 2>&1 || _tr_die "tooling root is not a git work tree"
  local m_commit t_commit m_dirty t_dirty
  m_commit="$(git -C "$m_abs" rev-parse HEAD)"
  t_commit="$(git -C "$t_abs" rev-parse HEAD)"
  [ "${#m_commit}" -eq 40 ] || _tr_die "measured root HEAD is not a 40-hex commit"
  [ "${#t_commit}" -eq 40 ] || _tr_die "tooling root HEAD is not a 40-hex commit"
  m_dirty="$(git -C "$m_abs" status --porcelain)"
  t_dirty="$(git -C "$t_abs" status --porcelain)"
  [ -z "$m_dirty" ] || _tr_die "measured root is DIRTY (uncommitted changes); refusing"
  [ -z "$t_dirty" ] || _tr_die "tooling root is DIRTY (uncommitted changes); refusing"

  # Measured-source authority: HEAD MUST equal the ratified measured source. (Tooling HEAD is NEVER
  # compared to this — that conflation is exactly what the two-root model removes.)
  [ "$m_commit" = "$RATIFIED_SOURCE_COMMIT" ] \
    || _tr_die "measured root HEAD ($m_commit) != RATIFIED_SOURCE_COMMIT ($RATIFIED_SOURCE_COMMIT)"

  # Tooling authority: recompute the path-set digest over the CLEAN tooling root.
  local pathset_digest
  pathset_digest="$("$t_abs/tools/b0-pre-candidates/scripts/tooling_pathset.sh" --root "$t_abs" --require-clean)" \
    || _tr_die "tooling path-set digest computation failed"
  [ "${#pathset_digest}" -eq 64 ] || _tr_die "tooling path-set digest is not 64-hex"

  export B0_MEASURED_ROOT="$m_abs" B0_MEASURED_COMMIT="$m_commit" B0_MEASURED_CLEAN=1
  export B0_TOOLING_ROOT="$t_abs" B0_TOOLING_COMMIT="$t_commit" B0_TOOLING_PATHSET_BLAKE3="$pathset_digest"

  {
    printf 'two-root authority verified:\n'
    printf '  measured_source_root=%s\n' "$m_abs"
    printf '  measured_source_commit=%s (== RATIFIED_SOURCE_COMMIT, clean)\n' "$m_commit"
    printf '  tooling_root=%s\n' "$t_abs"
    printf '  tooling_commit=%s (clean; NOT compared to the measured source)\n' "$t_commit"
    printf '  tooling_pathset_blake3=%s\n' "$pathset_digest"
  } >&2
}

#!/usr/bin/env bash
# Verify the sumchain release set (#241) — wire + primitives + crypto as ONE
# reproducible set.
#
# WHY THIS EXISTS
# ---------------
# `sumchain-wire 0.3.0` was published, then three more public modules
# (`compute_pool_wire`, `compute_pool_graph`, `registry_wire`) landed on main
# under the SAME version. Two different crates then shared one version number:
# SNIP pinned `=0.3.0` and silently built against the crate WITHOUT the C1/C5
# wire, while sum-chain's tree built against the one with it. An exact pin cannot
# distinguish them, so no truthful cross-repository pin could be stated.
#
# Two independent checks, either of which catches that class of defect:
#
#   local   — `cargo package` each crate and confirm the packaged tarball's
#             contents match the working tree. Catches "about to publish
#             something that isn't the source you tagged".
#
#   remote  — download the published .crate tarball for the SAME version and
#             diff it against the tagged source. Catches "already published
#             something that isn't the source" — the #241 defect itself.
#
# Usage:
#   scripts/verify-release-set.sh local            # pre-publish (no network)
#   scripts/verify-release-set.sh remote <version> # post-publish verification
set -euo pipefail

# Topological publish order within the set, from `cargo metadata` normal edges:
#   sumchain-wire      -> (no in-set deps)
#   sumchain-primitives -> sumchain-wire
#   sumchain-crypto     -> sumchain-primitives
# cargo resolves a crate's dependencies from the REGISTRY when packaging, so each
# crate can only be packaged once the one before it is published. Publishing out
# of this order fails; that is a property of cargo, not of this script.
CRATES="sumchain-wire sumchain-primitives sumchain-crypto"

# Plain function rather than an associative array: macOS ships bash 3.2, which
# has no `declare -A`, and this script must run on a developer laptop as well as
# in CI.
crate_dir() {
  case "$1" in
    sumchain-wire)       echo crates/sumchain-wire ;;
    sumchain-primitives) echo crates/primitives ;;
    sumchain-crypto)     echo crates/crypto ;;
    *) fail "unknown crate $1" ;;
  esac
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
mode="${1:-local}"

fail() { printf '  FAIL  %s\n' "$*" >&2; exit 1; }
ok()   { printf '  ok    %s\n' "$*"; }

# Every crate in the set must carry the SAME version — that is what "one
# reproducible set" means, and it is what makes a single exact pin meaningful.
check_set_version() {
  local seen=""
  for c in $CRATES; do
    local v
    v="$(cargo metadata --no-deps --format-version 1 \
         | python3 -c "import json,sys;m=json.load(sys.stdin);print(next(p['version'] for p in m['packages'] if p['name']=='$c'))")"
    printf '  %-22s %s\n' "$c" "$v"
    if [ -z "$seen" ]; then seen="$v"
    elif [ "$seen" != "$v" ]; then
      fail "release set is not uniform: $c is $v but a sibling is $seen"
    fi
  done
  SET_VERSION="$seen"
  ok "release set is uniform at $SET_VERSION"
}

# Packaged tarball must contain exactly the tracked sources of the crate.
verify_local() {
  for c in $CRATES; do
    local dir; dir="$(crate_dir "$c")"
    local err; err="$(mktemp)"
    if ! cargo package -p "$c" --allow-dirty --no-verify >/dev/null 2>"$err"; then
      # A crate whose in-set dependency is not yet published cannot be packaged
      # until that dependency is live. Report it as DEFERRED, not as a failure:
      # it is the expected state before the first publish of a new set version.
      if grep -q "failed to select a version for the requirement .sumchain-" "$err"; then
        local need; need="$(grep -o "sumchain-[a-z]* = \"^[0-9.]*\"" "$err" | head -1)"
        printf '  defer %s: needs %s published first (publish order: %s)\n' \
          "$c" "${need:-an in-set dependency}" "$CRATES"
        rm -f "$err"; continue
      fi
      sed 's/^/        /' "$err" >&2; rm -f "$err"
      fail "$c: cargo package failed"
    fi
    rm -f "$err"
    local tarball="target/package/${c}-${SET_VERSION}.crate"
    [ -f "$tarball" ] || fail "$c: expected $tarball"

    # Compare every .rs in the tarball against the working tree byte-for-byte.
    local tmp; tmp="$(mktemp -d)"
    tar xzf "$tarball" -C "$tmp"
    local pkg="$tmp/${c}-${SET_VERSION}"
    local diffs=0
    while IFS= read -r f; do
      local rel="${f#"$pkg/"}"
      if ! cmp -s "$f" "$dir/$rel"; then
        printf '        differs: %s\n' "$rel" >&2
        diffs=$((diffs+1))
      fi
    done < <(find "$pkg" -name '*.rs' -type f)
    rm -rf "$tmp"
    [ "$diffs" -eq 0 ] || fail "$c: $diffs packaged file(s) differ from the working tree"
    ok "$c: packaged tarball matches the source tree"
  done
}

# Downloaded crates.io tarball must match the tagged source. This is the check
# that would have caught #241 at publish time.
verify_remote() {
  local version="${2:-$SET_VERSION}"
  for c in $CRATES; do
    local dir; dir="$(crate_dir "$c")"
    local tmp; tmp="$(mktemp -d)"
    local url="https://static.crates.io/crates/${c}/${c}-${version}.crate"
    if ! curl -fsSL "$url" -o "$tmp/dl.crate"; then
      rm -rf "$tmp"; fail "$c: could not download $url (not published, or no network)"
    fi
    tar xzf "$tmp/dl.crate" -C "$tmp"
    local pkg="$tmp/${c}-${version}"

    # Public module surface is the cheapest high-signal comparison, and is
    # exactly what diverged in #241 (27 modules published vs 30 on main).
    local pub_dl pub_src
    pub_dl="$(grep -c '^pub mod' "$pkg/src/lib.rs" || true)"
    pub_src="$(grep -c '^pub mod' "$dir/src/lib.rs" || true)"
    [ "$pub_dl" = "$pub_src" ] \
      || { rm -rf "$tmp"; fail "$c: published exposes $pub_dl public modules, source has $pub_src"; }

    local diffs=0
    while IFS= read -r f; do
      local rel="${f#"$pkg/"}"
      if [ -f "$dir/$rel" ] && ! cmp -s "$f" "$dir/$rel"; then
        printf '        differs: %s\n' "$rel" >&2
        diffs=$((diffs+1))
      fi
    done < <(find "$pkg" -name '*.rs' -type f)
    rm -rf "$tmp"
    [ "$diffs" -eq 0 ] || fail "$c: $diffs published file(s) differ from the tagged source"
    ok "$c $version: published tarball matches the tagged source ($pub_src public modules)"
  done
}

echo "release set version:"
check_set_version
case "$mode" in
  local)  echo "local verification (pre-publish):";  verify_local ;;
  remote) echo "remote verification (post-publish):"; verify_remote "$@" ;;
  *) echo "usage: $0 [local|remote <version>]" >&2; exit 2 ;;
esac
echo "release set verified."

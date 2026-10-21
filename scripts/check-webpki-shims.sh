#!/usr/bin/env bash
# Guard for the two scoped RustSec exceptions in .cargo/audit.toml / deny.toml:
#   RUSTSEC-2026-0381  webpki-roots      0.26.11
#   RUSTSEC-2026-0383  webpki-root-certs 0.26.11
#
# Both packages are 0.26.x compatibility shims whose entire API is a re-export of
# the 1.x crate (`pub use parent::TLS_SERVER_ROOTS` / `TLS_SERVER_ROOT_CERTS`,
# `parent = { package = "...", version = "1" }`). The advisories ("bundled root
# certificates allow trust in distrusted emSign intermediates", patched >= 1.0.10)
# are version-range findings against the shims: their root data is whatever 1.x
# Cargo.lock resolves `parent` to, and 1.0.10 removes emSign ECC Root CA - G3.
#
# The exceptions are only sound while ALL of the following hold, and this script
# fails (`::error::`) when any of them stops holding:
#   1. each shim is exactly the reviewed release (version and checksum pinned);
#   2. every 1.x webpki-roots / webpki-root-certs in Cargo.lock, and each shim's
#      `parent`, is >= 1.0.10 (cargo-audit ignores are per advisory ID, so this
#      also stops the ignore from hiding a regression of the 1.x line);
#   3. webpki-roots 0.26.11 has no normal-dependency path on any shipped target
#      (today it is reached only through ureq 2.12.1, a build-dependency of wasmer);
#   4. wasmer stays at the reviewed 5.0.6 without its "wamr" / "v8" features, the
#      only build-script code paths in which ureq makes a network call;
#   5. webpki-root-certs 0.26.11 is not built for any shipped target (today it is
#      a wasm32-only dependency of rustls-platform-verifier 0.5.3);
#   6. the shims have no dependent other than ureq 2.12.1 / rustls-platform-verifier
#      0.5.3;
#   7. an exception is removed once its shim has left Cargo.lock, and the two
#      ignore lists agree.
# Remove an exception (and its block below) when its removal condition in
# .cargo/audit.toml is met; delete this script when both are gone.
#
# Needs cargo (for `cargo tree --locked`), awk and sort -V.
# Run locally:  bash scripts/check-webpki-shims.sh
# SHIM_GUARD_ROOT=<dir> checks another checkout (used to test the guard itself).
set -uo pipefail
ROOT="${SHIM_GUARD_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || { echo "::error::webpki shim guard: cannot enter $ROOT"; exit 1; }

LOCK=Cargo.lock
AUDIT=.cargo/audit.toml
DENY=deny.toml
MIN_FIXED=1.0.10
SHIPPED_TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-apple-darwin"

# name  advisory  shim-version  shim-checksum  only-allowed-dependent
SHIMS="webpki-roots RUSTSEC-2026-0381 0.26.11 521bc38abb08001b01866da9f51eb7c5d647a19260e00054a8c7fd5f9e57f7a9 ureq@2.12.1
webpki-root-certs RUSTSEC-2026-0383 0.26.11 75c7f0ef91146ebfb530314f5f1d24528d7f0767efbfd31dce919275413e393e rustls-platform-verifier@0.5.3"
WASMER_REVIEWED=5.0.6

failures=0
fail() { echo "::error::webpki shim guard: $1"; failures=$((failures + 1)); }
ok() { echo "ok - $1"; }

[ -f "$LOCK" ] || { echo "::error::webpki shim guard: $LOCK missing in $ROOT"; exit 1; }

# One line per package: name<TAB>version<TAB>checksum<TAB>dep;dep;...
packages() {
  awk '
    function emit() { if (name != "") print name "\t" version "\t" checksum "\t" deps }
    /^\[\[package\]\]$/ { emit(); name = ""; version = ""; checksum = ""; deps = ""; indeps = 0; next }
    /^name = "/     { sub(/^name = "/, ""); sub(/"$/, ""); name = $0; next }
    /^version = "/  { sub(/^version = "/, ""); sub(/"$/, ""); version = $0; next }
    /^checksum = "/ { sub(/^checksum = "/, ""); sub(/"$/, ""); checksum = $0; next }
    /^dependencies = \[/ { indeps = 1; next }
    indeps && /^\]/ { indeps = 0; next }
    indeps { d = $0; gsub(/^ *"|",? *$/, "", d); deps = deps (deps == "" ? "" : ";") d; next }
    END { emit() }
  ' "$LOCK"
}
PKGS="$(packages)"

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# Is advisory $1 listed as an ignore entry (a quoted string on its own line)?
ignored_in() { grep -Eq "^[[:space:]]*\"$1\",?[[:space:]]*(#.*)?$" "$2" 2>/dev/null; }

while read -r name adv shim_ver shim_sum allowed_dep; do
  [ -n "$name" ] || continue
  in_audit=0; ignored_in "$adv" "$AUDIT" && in_audit=1
  in_deny=0;  ignored_in "$adv" "$DENY"  && in_deny=1

  # (7b) the two lists agree for this advisory.
  if [ "$in_audit" != "$in_deny" ]; then
    fail "$adv is ignored in $([ $in_audit = 1 ] && echo "$AUDIT but not $DENY" || echo "$DENY but not $AUDIT"); keep the two lists identical"
  fi

  shim_lines="$(printf '%s\n' "$PKGS" | awk -F'\t' -v n="$name" '$1 == n && $2 ~ /^0\.26\./')"
  if [ -z "$shim_lines" ]; then
    # (7) the shim is gone: its exception must go too.
    if [ "$in_audit" = 1 ] || [ "$in_deny" = 1 ]; then
      fail "$name 0.26.x has left $LOCK but $adv is still ignored; remove the exception (and its block in this script)"
    else
      ok "$name 0.26.x absent and $adv not ignored"
    fi
    continue
  fi

  # (1) exactly the reviewed shim release.
  if [ "$(printf '%s\n' "$shim_lines" | wc -l | tr -d ' ')" != 1 ] \
     || [ "$(printf '%s\n' "$shim_lines" | cut -f2)" != "$shim_ver" ] \
     || [ "$(printf '%s\n' "$shim_lines" | cut -f3)" != "$shim_sum" ]; then
    fail "$name 0.26.x in $LOCK is not exactly the reviewed $shim_ver ($shim_sum): $(printf '%s' "$shim_lines" | cut -f2,3 | tr '\t\n' ' ')"
  else
    ok "$name $shim_ver is the reviewed release (checksum pinned)"
  fi

  # (2) every 1.x copy, and the shim's parent, is >= MIN_FIXED.
  bad=""
  while IFS=$'\t' read -r _ v _ _; do
    ver_ge "$v" "$MIN_FIXED" || bad="$bad $v"
  done < <(printf '%s\n' "$PKGS" | awk -F'\t' -v n="$name" '$1 == n && $2 ~ /^1\./')
  [ -z "$bad" ] && ok "every $name 1.x in $LOCK is >= $MIN_FIXED" || fail "$name 1.x below $MIN_FIXED in $LOCK:$bad"
  parent="$(printf '%s\n' "$shim_lines" | cut -f4 | tr ';' '\n' | awk -v n="$name" '$1 == n && $2 ~ /^1\./ {print $2}')"
  if [ -z "$parent" ]; then
    fail "$name $shim_ver has no resolved 1.x parent in $LOCK"
  elif ver_ge "$parent" "$MIN_FIXED"; then
    ok "$name $shim_ver re-exports $name $parent (>= $MIN_FIXED)"
  else
    fail "$name $shim_ver resolves its parent to $parent, below $MIN_FIXED"
  fi

  # (6) the only dependent is the reviewed one.
  dependents="$(printf '%s\n' "$PKGS" | awk -F'\t' -v d="$name $shim_ver" '
    { n = split($4, a, ";"); for (i = 1; i <= n; i++) if (a[i] == d) print $1 "@" $2 }' | sort -u | tr '\n' ' ' | sed 's/ $//')"
  if [ "$dependents" = "$allowed_dep" ]; then
    ok "$name $shim_ver has the single reviewed dependent $allowed_dep"
  else
    fail "$name $shim_ver dependents are [$dependents], expected [$allowed_dep]"
  fi
done <<< "$SHIMS"

# `cargo tree --locked`; prints the tree (empty if nothing matches). On error it
# prints the error and returns 1; callers record that with tree_failed (a
# command substitution runs in a subshell, so fail() cannot be called here).
tree() {
  local out err rc
  err="$(mktemp)"
  out="$(cargo tree --locked "$@" 2>"$err")"; rc=$?
  if [ $rc -ne 0 ]; then
    printf '%s' "$(head -n3 "$err" | tr '\n' ' ')"; rm -f "$err"; return 1
  fi
  rm -f "$err"; printf '%s' "$out"
}
tree_failed() { fail "cargo tree $1 failed: $2"; }

if printf '%s\n' "$PKGS" | awk -F'\t' '$1 == "webpki-roots" && $2 == "0.26.11"' | grep -q .; then
  # (3) no normal-dependency path to webpki-roots 0.26.11 on a shipped target.
  for t in $SHIPPED_TARGETS; do
    if out="$(tree -e normal --target "$t" -i webpki-roots@0.26.11)"; then
      [ -z "$out" ] && ok "no normal-dependency path to webpki-roots 0.26.11 on $t" \
        || fail "webpki-roots 0.26.11 is a normal dependency on $t: $(printf '%s' "$out" | head -n4 | tr '\n' ' ')"
    else
      tree_failed "-e normal --target $t -i webpki-roots@0.26.11" "$out"
    fi
  done
  # (4) wasmer is the reviewed release, without the build-script download features.
  wasmer_vers="$(printf '%s\n' "$PKGS" | awk -F'\t' '$1 == "wasmer" {print $2}' | sort -u | tr '\n' ' ' | sed 's/ $//')"
  [ "$wasmer_vers" = "$WASMER_REVIEWED" ] && ok "wasmer is the reviewed $WASMER_REVIEWED" \
    || fail "wasmer in $LOCK is [$wasmer_vers], not the reviewed $WASMER_REVIEWED (re-review its build script)"
  if out="$(tree -e features --target all -i wasmer)"; then
    live="$(printf '%s\n' "$out" | grep -oE 'wasmer feature "(wamr|v8)"' | sort -u | tr '\n' ' ')"
    [ -z "$live" ] && ok "wasmer features exclude wamr and v8" \
      || fail "wasmer enables $live: its build script then downloads with ureq"
  else
    tree_failed "-e features --target all -i wasmer" "$out"
  fi
fi

if printf '%s\n' "$PKGS" | awk -F'\t' '$1 == "webpki-root-certs" && $2 == "0.26.11"' | grep -q .; then
  # (5) webpki-root-certs 0.26.11 is not built for any shipped target.
  for t in $SHIPPED_TARGETS; do
    if out="$(tree --target "$t" -i webpki-root-certs@0.26.11)"; then
      [ -z "$out" ] && ok "webpki-root-certs 0.26.11 is not built for $t" \
        || fail "webpki-root-certs 0.26.11 is built for $t: $(printf '%s' "$out" | head -n4 | tr '\n' ' ')"
    else
      tree_failed "--target $t -i webpki-root-certs@0.26.11" "$out"
    fi
  done
fi

if [ "$failures" -ne 0 ]; then
  echo "webpki shim guard: $failures check(s) failed"
  exit 1
fi
echo "webpki shim guard: all checks passed"

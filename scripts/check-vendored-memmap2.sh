#!/usr/bin/env bash
# Vendored `memmap2` 0.5.10 and 0.6.2 guard (RUSTSEC-2026-0186).
#
# Cargo.toml patches memmap2 0.6.2 (shared-buffer, from wasmer 5.0.6) and 0.5.10
# (dynasmrt, from wasmer-compiler-singlepass 5.0.6) to
# crates/third_party/memmap2-<version>, each the crates.io crate with memmap2
# 0.9.11's bounds checks backported into MmapInner::flush, flush_async and
# advise (unix.rs) and flush_async (windows.rs). A path crate has no Cargo.lock
# source or checksum, and neither `cargo audit` nor `cargo deny check
# advisories` matches RustSec advisories against it. This script covers the gap,
# as scripts/check-vendored-object.sh does for object 0.32.2:
#
#   source      (default) Integrity. Downloads each memmap2-<version>.crate from
#               crates.io, checks its sha256 against the pin below (the checksum
#               Cargo.lock carried before the patch), extracts it, and requires
#               `diff -r` against the vendored directory to be exactly the
#               expected backport hunks.
#   advisories  Monitoring. Writes a synthetic Cargo.lock declaring both crates.io
#               identities and runs `cargo audit --file` on it with the
#               repository's .cargo/audit.toml and `--deny warnings`. Any RustSec
#               advisory against either version fails, except RUSTSEC-2026-0186,
#               which the backport fixes and which is ignored here only. Extra
#               arguments go to cargo audit, e.g. `--db <dir> --no-fetch`.
#
# Both modes first check that the pins cannot drift from what is built: each
# vendored manifest is its version, the root Cargo.toml patches memmap2 to those
# directories, and Cargo.lock resolves both versions to them (and to nothing from
# a registry) with no unused patch.
#
# Needs curl, tar, diff and sha256sum (or shasum); `advisories` needs
# cargo-audit. Writes only to a temp dir.
# Run locally:  bash scripts/check-vendored-memmap2.sh [source|advisories]
set -euo pipefail
cd "$(dirname "$0")/.."

CRATE=memmap2
FIXED_ADVISORY=RUSTSEC-2026-0186
REGISTRY="registry+https://github.com/rust-lang/crates.io-index"
# version, crates.io sha256, the [patch.crates-io] line that points at it
PINS=(
  "0.6.2 6d28bba84adfe6646737845bc5ebbfa2c08424eb1c37e94a1fd2a82adb56a872 memmap2"
  "0.5.10 83faa42c0a078c393f6b29d5db232d8be22776a891f8f56e5284faee4a20b327 memmap2-0510"
)

fail() { echo "::error::vendored ${CRATE}: $1"; exit 1; }

mode="${1:-source}"
[ $# -eq 0 ] || shift
case "$mode" in
  source) [ $# -eq 0 ] || fail "source takes no further arguments" ;;
  advisories) ;;
  *) echo "usage: $0 [source|advisories [cargo-audit args...]]" >&2; exit 2 ;;
esac

# `key = value` from one [table] of a TOML file; prints nothing if absent.
toml_value() {
  awk -v t="[$2]" -v k="$3" '
    /^\[/ { in_t = ($0 == t); next }
    in_t && $1 == k && $2 == "=" { print; exit }' "$1"
}

# Every Cargo.lock [[package]] as "name version source" ("path" when none).
lock_entries() {
  awk '
    function flush() { if (name != "") print name, version, (source == "" ? "path" : source); name = version = source = "" }
    /^\[\[package\]\]$/ { flush(); pkg = 1; next }
    /^\[/ { flush(); pkg = 0; next }
    pkg && $1 == "name" { name = $3 }
    pkg && $1 == "version" { version = $3 }
    pkg && $1 == "source" { source = $3 }
    END { flush() }' Cargo.lock | tr -d '"' | awk -v n="$CRATE" -v v="$1" '$1 == n && $2 == v'
}

# --- The pins match what is built ---------------------------------------------
for pin in "${PINS[@]}"; do
  read -r version _ key <<<"$pin"
  vendored="crates/third_party/${CRATE}-${version}"
  [ -d "$vendored" ] || fail "$vendored is missing"
  [ "$(toml_value "$vendored/Cargo.toml" package name)" = "name = \"${CRATE}\"" ] \
    || fail "$vendored/Cargo.toml is not package ${CRATE}"
  [ "$(toml_value "$vendored/Cargo.toml" package version)" = "version = \"${version}\"" ] \
    || fail "$vendored/Cargo.toml is not version ${version}; update this script's pin with the vendored copy"
  if [ "$key" = "$CRATE" ]; then
    want="${CRATE} = { path = \"${vendored}\" }"
  else
    want="${key} = { package = \"${CRATE}\", path = \"${vendored}\" }"
  fi
  [ "$(toml_value Cargo.toml patch.crates-io "$key")" = "$want" ] \
    || fail "Cargo.toml [patch.crates-io] does not point ${CRATE} ${version} at ${vendored} (want: ${want})"
  got="$(lock_entries "$version")"
  [ "$got" = "${CRATE} ${version} path" ] \
    || fail "Cargo.lock must resolve ${CRATE} ${version} to the vendored path crate only; it has: ${got:-no such entry}"
done
if grep -q '^\[\[patch.unused\]\]' Cargo.lock; then
  fail "Cargo.lock lists an unused patch; if wasmer no longer resolves a vendored ${CRATE} version, remove its patch and directory"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- advisories ---------------------------------------------------------------
if [ "$mode" = advisories ]; then
  command -v cargo-audit >/dev/null 2>&1 || fail "cargo-audit is not installed"
  mkdir -p "$tmp/audit/.cargo"
  cp .cargo/audit.toml "$tmp/audit/.cargo/audit.toml"
  {
    echo "# Synthetic, written by scripts/check-vendored-memmap2.sh: the crates.io"
    echo "# identities of crates/third_party/${CRATE}-*."
    echo "version = 4"
    for pin in "${PINS[@]}"; do
      read -r version sha256 _ <<<"$pin"
      printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\n' \
        "$CRATE" "$version" "$REGISTRY" "$sha256"
    done
  } > "$tmp/audit/Cargo.lock"
  echo "synthetic Cargo.lock:"
  sed 's/^/  /' "$tmp/audit/Cargo.lock"
  if ! (cd "$tmp/audit" && cargo audit --file Cargo.lock --deny warnings --ignore "$FIXED_ADVISORY" "$@"); then
    fail "RustSec reports an advisory other than ${FIXED_ADVISORY} against crates.io ${CRATE} 0.5.10 or 0.6.2, which the vendored copies are apart from the backported bounds checks. Assess it against the vendored copies (docs/security/DEPENDENCY-AUDIT.md)."
  fi
  echo "ok - no RustSec advisory except ${FIXED_ADVISORY} (fixed by the backport) against crates.io ${CRATE} 0.5.10 or 0.6.2"
  exit 0
fi

# --- source -------------------------------------------------------------------
# The backport hunks; only the windows.rs line numbers differ between versions.
expected_diff() {
  local w="$1"
  cat <<EOF
diff -r upstream/src/unix.rs vendored/src/unix.rs
177a178,181
>         // SUM-CHAIN: bounds check backported from memmap2 0.9.11 (RUSTSEC-2026-0186).
>         if offset > self.len || len > self.len - offset {
>             return Err(io::ErrorKind::InvalidInput.into());
>         }
190a195,198
>         // SUM-CHAIN: bounds check backported from memmap2 0.9.11 (RUSTSEC-2026-0186).
>         if offset > self.len || len > self.len - offset {
>             return Err(io::ErrorKind::InvalidInput.into());
>         }
244a253,256
>         // SUM-CHAIN: bounds check backported from memmap2 0.9.11 (RUSTSEC-2026-0186).
>         if offset > self.len || len > self.len {
>             return Err(io::ErrorKind::InvalidInput.into());
>         }
diff -r upstream/src/windows.rs vendored/src/windows.rs
${w}a$((w + 1)),$((w + 4))
>         // SUM-CHAIN: bounds check backported from memmap2 0.9.11 (RUSTSEC-2026-0186).
>         if offset > self.len || len > self.len - offset {
>             return Err(io::ErrorKind::InvalidInput.into());
>         }
EOF
}

for pin in "${PINS[@]}"; do
  read -r version sha256 _ <<<"$pin"
  vendored="crates/third_party/${CRATE}-${version}"
  case "$version" in 0.6.2) wline=402 ;; 0.5.10) wline=399 ;; esac
  url="https://static.crates.io/crates/${CRATE}/${CRATE}-${version}.crate"
  rm -rf "$tmp/x" "$tmp/upstream" "$tmp/vendored"
  curl -fsSL --retry 3 "$url" -o "$tmp/dl.crate" || fail "could not download $url"
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$tmp/dl.crate" | cut -d' ' -f1)"
  else
    got="$(shasum -a 256 "$tmp/dl.crate" | cut -d' ' -f1)"
  fi
  [ "$got" = "$sha256" ] || fail "downloaded ${CRATE} ${version} crate sha256 is $got, pinned $sha256"
  mkdir "$tmp/x"
  tar -xzf "$tmp/dl.crate" -C "$tmp/x"
  mv "$tmp/x/${CRATE}-${version}" "$tmp/upstream"
  cp -R "$vendored" "$tmp/vendored"

  rc=0
  actual="$(cd "$tmp" && diff -r upstream vendored)" || rc=$?
  [ "$rc" -le 1 ] || fail "diff -r failed for ${version} (exit $rc)"
  expected="$(expected_diff "$wline")"
  if [ "$actual" != "$expected" ]; then
    echo "expected:"; printf '%s\n' "$expected"
    echo "actual:"; printf '%s\n' "$actual"
    fail "$vendored differs from the crates.io crate by more than the backported bounds checks"
  fi
  echo "ok - $vendored is crates.io ${CRATE} ${version} (sha256 $sha256) except for the backported bounds checks"
done

#!/usr/bin/env bash
# Vendored `object` 0.32.2 guard (#306, RUSTSEC-2026-0344).
#
# Cargo.toml patches object 0.32.2 to crates/third_party/object-0.32.2 so that
# its `default` features no longer pull `compression` (and with it ruzstd
# 0.5.0). A path crate has no Cargo.lock source or checksum, and neither
# `cargo audit` nor `cargo deny check advisories` matches RustSec advisories
# against it. (Both still match its crates.io dependencies, and `cargo deny`
# still applies its license and ban rules to it.) This script covers the gap:
#
#   source      (default) Integrity. Downloads object-0.32.2.crate from
#               crates.io, checks its sha256 against the pin below (the checksum
#               Cargo.lock carried for object 0.32.2 before the patch), extracts
#               it, and requires `diff -r` against the vendored directory to be
#               exactly the one expected hunk in Cargo.toml.
#   advisories  Monitoring. Writes a synthetic Cargo.lock declaring object 0.32.2
#               with its crates.io source and the pinned checksum (the upstream
#               crate the vendored copy is byte-identical to apart from that
#               hunk) and runs `cargo audit --file` on it with the repository's
#               .cargo/audit.toml and `--deny warnings`: any RustSec advisory
#               against object 0.32.2 (vulnerability, unsound, unmaintained,
#               yanked) fails. Extra arguments go to cargo audit, e.g.
#               `--db <dir> --no-fetch` to run it against a local database.
#
# Both modes first check that the pin cannot drift from what is built: the
# vendored manifest is object 0.32.2, the root Cargo.toml patches object to that
# directory, and Cargo.lock resolves object 0.32.2 to it (and to nothing from a
# registry) with no unused patch. Change VERSION and SHA256 only together with
# the vendored directory.
#
# Needs curl, tar, diff and sha256sum (or shasum); `advisories` needs
# cargo-audit. Writes only to a temp dir.
# Run locally:  bash scripts/check-vendored-object.sh [source|advisories]
set -euo pipefail
cd "$(dirname "$0")/.."

CRATE=object
VERSION=0.32.2
SHA256=a6a622008b6e321afc04970976f62ee297fdbaa6f95318ca343e3eebb9648441
VENDORED="crates/third_party/${CRATE}-${VERSION}"
URL="https://static.crates.io/crates/${CRATE}/${CRATE}-${VERSION}.crate"
REGISTRY="registry+https://github.com/rust-lang/crates.io-index"

fail() { echo "::error::vendored ${CRATE} ${VERSION}: $1"; exit 1; }

mode="${1:-source}"
[ $# -eq 0 ] || shift
case "$mode" in
  source) [ $# -eq 0 ] || fail "source takes no further arguments" ;;
  advisories) ;;
  *) echo "usage: $0 [source|advisories [cargo-audit args...]]" >&2; exit 2 ;;
esac

# --- The pin matches what is built --------------------------------------------
[ -d "$VENDORED" ] || fail "$VENDORED is missing"

# `key = value` from one [table] of a TOML file; prints nothing if absent.
toml_value() {
  awk -v t="[$2]" -v k="$3" '
    /^\[/ { in_t = ($0 == t); next }
    in_t && $1 == k && $2 == "=" { print; exit }' "$1"
}
[ "$(toml_value "$VENDORED/Cargo.toml" package name)" = "name = \"${CRATE}\"" ] \
  || fail "$VENDORED/Cargo.toml is not package ${CRATE}"
[ "$(toml_value "$VENDORED/Cargo.toml" package version)" = "version = \"${VERSION}\"" ] \
  || fail "$VENDORED/Cargo.toml is not version ${VERSION}; update this script's pin with the vendored copy"
[ "$(toml_value Cargo.toml patch.crates-io "$CRATE")" = "${CRATE} = { path = \"${VENDORED}\" }" ] \
  || fail "Cargo.toml [patch.crates-io] does not point ${CRATE} at ${VENDORED}"

# Every Cargo.lock [[package]] as "name version source" ("path" when none).
lock_entries="$(awk '
  function flush() { if (name != "") print name, version, (source == "" ? "path" : source); name = version = source = "" }
  /^\[\[package\]\]$/ { flush(); pkg = 1; next }
  /^\[/ { flush(); pkg = 0; next }
  pkg && $1 == "name" { name = $3 }
  pkg && $1 == "version" { version = $3 }
  pkg && $1 == "source" { source = $3 }
  END { flush() }' Cargo.lock | tr -d '"' | awk -v n="$CRATE" -v v="$VERSION" '$1 == n && $2 == v')"
[ "$lock_entries" = "${CRATE} ${VERSION} path" ] \
  || fail "Cargo.lock must resolve ${CRATE} ${VERSION} to the vendored path crate only; it has: ${lock_entries:-no such entry}"
if grep -q '^\[\[patch.unused\]\]' Cargo.lock; then
  fail "Cargo.lock lists an unused patch; if wasmer no longer resolves ${CRATE} ${VERSION}, remove the patch and ${VENDORED}"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- advisories ---------------------------------------------------------------
if [ "$mode" = advisories ]; then
  command -v cargo-audit >/dev/null 2>&1 || fail "cargo-audit is not installed"
  mkdir -p "$tmp/audit/.cargo"
  cp .cargo/audit.toml "$tmp/audit/.cargo/audit.toml"
  cat > "$tmp/audit/Cargo.lock" <<EOF
# Synthetic, written by scripts/check-vendored-object.sh (#306): the crates.io
# identity of ${VENDORED}.
version = 4

[[package]]
name = "${CRATE}"
version = "${VERSION}"
source = "${REGISTRY}"
checksum = "${SHA256}"
EOF
  echo "synthetic Cargo.lock:"
  sed 's/^/  /' "$tmp/audit/Cargo.lock"
  if ! (cd "$tmp/audit" && cargo audit --file Cargo.lock --deny warnings "$@"); then
    fail "RustSec reports an advisory against crates.io ${CRATE} ${VERSION}, which ${VENDORED} is apart from its default features. Assess it on #306 and the vendored copy (docs/security/DEPENDENCY-AUDIT.md)."
  fi
  echo "ok - no RustSec advisory against crates.io ${CRATE} ${VERSION} (sha256 ${SHA256}), the identity of ${VENDORED}"
  exit 0
fi

# --- source -------------------------------------------------------------------
curl -fsSL --retry 3 "$URL" -o "$tmp/dl.crate" || fail "could not download $URL"
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/dl.crate" | cut -d' ' -f1)"
else
  got="$(shasum -a 256 "$tmp/dl.crate" | cut -d' ' -f1)"
fi
[ "$got" = "$SHA256" ] || fail "downloaded crate sha256 is $got, pinned $SHA256"

mkdir "$tmp/x"
tar -xzf "$tmp/dl.crate" -C "$tmp/x"
mv "$tmp/x/${CRATE}-${VERSION}" "$tmp/upstream"
cp -R "$VENDORED" "$tmp/vendored"

expected="$(cat <<'EOF'
diff -r upstream/Cargo.toml vendored/Cargo.toml
99,102c99,100
< default = [
<     "read",
<     "compression",
< ]
---
> # SUM-CHAIN #306: "compression" removed from default (drops ruzstd 0.5.0, RUSTSEC-2026-0344)
> default = ["read"]
EOF
)"

rc=0
actual="$(cd "$tmp" && diff -r upstream vendored)" || rc=$?
[ "$rc" -le 1 ] || fail "diff -r failed (exit $rc)"

if [ "$actual" != "$expected" ]; then
  echo "expected:"; printf '%s\n' "$expected"
  echo "actual:"; printf '%s\n' "$actual"
  fail "$VENDORED differs from the crates.io crate by more than the default-features line"
fi
echo "ok - $VENDORED is crates.io ${CRATE} ${VERSION} (sha256 $SHA256) except for its default features"

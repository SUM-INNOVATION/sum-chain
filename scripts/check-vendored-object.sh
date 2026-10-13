#!/usr/bin/env bash
# Vendored `object` 0.32.2 guard (#306, RUSTSEC-2026-0344).
#
# Cargo.toml patches object 0.32.2 to crates/third_party/object-0.32.2 so that
# its `default` features no longer pull `compression` (and with it ruzstd
# 0.5.0). A path crate has no Cargo.lock checksum and is not scanned by
# `cargo audit` or `cargo deny`, so this check is what ties the vendored source
# to the published crate: it downloads object-0.32.2.crate from crates.io,
# checks its sha256 against the pin below (the checksum Cargo.lock carried for
# object 0.32.2 before the patch), extracts it, and requires `diff -r` against
# the vendored directory to be exactly the one expected hunk in Cargo.toml.
#
# Needs curl, tar, diff and sha256sum (or shasum). Writes only to a temp dir.
# Run locally:  bash scripts/check-vendored-object.sh
set -euo pipefail
cd "$(dirname "$0")/.."

CRATE=object
VERSION=0.32.2
SHA256=a6a622008b6e321afc04970976f62ee297fdbaa6f95318ca343e3eebb9648441
VENDORED="crates/third_party/${CRATE}-${VERSION}"
URL="https://static.crates.io/crates/${CRATE}/${CRATE}-${VERSION}.crate"

fail() { echo "::error::vendored ${CRATE} ${VERSION}: $1"; exit 1; }

[ -d "$VENDORED" ] || fail "$VENDORED is missing"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

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

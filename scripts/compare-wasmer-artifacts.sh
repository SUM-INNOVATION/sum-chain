#!/usr/bin/env bash
# Compiled-artifact comparison between two revisions (#306).
#
# Builds crates/sumc-runtime/examples/artifact_hash.rs (release profile,
# --locked) in a temporary detached worktree of each revision, runs each binary
# twice over the same WAT corpus, requires the two runs of each binary to agree,
# and then requires the two revisions' outputs (every Module::serialize()
# artifact and the manifest) to be byte-identical.
#
# The harness and the corpus always come from THIS checkout: the harness file
# is copied into both worktrees (the base revision may predate it), and both
# binaries read the corpus from here. The only difference between the two
# builds is therefore the revisions' own trees and Cargo.lock.
#
# Usage: bash scripts/compare-wasmer-artifacts.sh <base-rev> <head-rev>
# Env:   CARGO_TARGET_DIR  shared by both builds (default: inside the temp dir)
#        CARGO_BUILD_JOBS  passed through to cargo
#        ARTIFACT_OUT      keep the outputs in this directory (default: deleted)
set -euo pipefail
cd "$(dirname "$0")/.."

HARNESS=crates/sumc-runtime/examples/artifact_hash.rs
CORPUS=(crates/sumc-runtime/tests crates/state/tests crates/consensus/tests crates/rpc/tests)

fail() { echo "::error::wasmer artifacts: $1"; exit 1; }
[ $# -eq 2 ] || { echo "usage: $0 <base-rev> <head-rev>" >&2; exit 2; }
[ -f "$HARNESS" ] || fail "$HARNESS is missing"
base="$(git rev-parse --verify "$1^{commit}")"
head="$(git rev-parse --verify "$2^{commit}")"

work="$(mktemp -d)"
cleanup() {
  for side in base head; do git worktree remove --force "$work/$side" 2>/dev/null || true; done
  git worktree prune
  rm -rf "$work"
}
trap cleanup EXIT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$work/target}"
out="${ARTIFACT_OUT:-$work/out}"
mkdir -p "$out"

if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$@"; }; else sha() { shasum -a 256 "$@"; }; fi

echo "host: $(uname -sm)"
echo "base: $base"
echo "head: $head"
for side in base head; do
  rev="$base"; [ "$side" = head ] && rev="$head"
  git worktree add --quiet --detach "$work/$side" "$rev"
  mkdir -p "$work/$side/$(dirname "$HARNESS")"
  cp "$HARNESS" "$work/$side/$HARNESS"
  echo "== $side: $(cd "$work/$side" && rustc --version), lock sha256 $(sha "$work/$side/Cargo.lock" | cut -d' ' -f1)"
  (cd "$work/$side" && cargo build --release --locked -p sumc-runtime --example artifact_hash)
  cp "$CARGO_TARGET_DIR/release/examples/artifact_hash" "$work/$side.bin"
  for run in 1 2; do
    "$work/$side.bin" "$out/$side-$run" "${CORPUS[@]}" > "$out/$side-$run.log"
  done
  diff -r "$out/$side-1" "$out/$side-2" > /dev/null \
    || fail "$side: two runs of the same binary differ, so the harness output is not deterministic"
done

echo "== head manifest"
cat "$out/head-1/manifest.txt"
bins="$(find "$out/head-1" -name '*.bin' | wc -l | tr -d ' ')"
errors="$(grep -c ' compile-error=' "$out/head-1/manifest.txt" || true)"
echo "== manifest sha256: base $(sha "$out/base-1/manifest.txt" | cut -d' ' -f1), head $(sha "$out/head-1/manifest.txt" | cut -d' ' -f1)"
if ! diff -r "$out/base-1" "$out/head-1" > "$out/base-vs-head.diff"; then
  cat "$out/base-vs-head.diff" | head -100
  fail "the base and head builds compile the corpus to different artifacts"
fi
echo "ok - $bins serialized artifacts and the manifest are byte-identical between base and head ($errors compile errors, identical on both sides; each binary agreed with itself over two runs)"

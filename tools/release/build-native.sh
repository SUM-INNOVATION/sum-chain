#!/usr/bin/env bash
# build-native.sh <x86_64|aarch64> <40-hex commit> <out-dir> <builder-id URL>
#
# Builds ONE native Linux release archive, on a runner of that architecture
# (no emulation, no cross-compilation), from the checked-out commit:
#
#   sumchain-<commit>-<arch>-unknown-linux-gnu.tar.gz   (sumchain, sumchain-wallet)
#   sumchain-<commit>-<arch>-unknown-linux-gnu.spdx.json        SPDX SBOM
#   sumchain-<commit>-<arch>-unknown-linux-gnu.provenance.json  SLSA v1 provenance
#   <arch>-unknown-linux-gnu.json                                hashes, for the record
#
# Compiled in tools/release/native.Dockerfile (pinned Rust image, the
# repository's pinned toolchain, --locked, the exact GIT_HASH). Then the
# extracted binary itself is proven: --version, ELF architecture, shared
# libraries, and tools/release/smoke-native.sh (health, readiness, metrics,
# graceful SIGTERM). The archive is deterministic: sorted names, owner 0,
# mtime = the commit time, gzip without a timestamp.
# Holds no credential; nothing leaves the runner.
set -euo pipefail
[[ $# -eq 4 ]] || { echo "usage: build-native.sh <x86_64|aarch64> <commit> <out-dir> <builder-id>" >&2; exit 2; }
ARCH=$1 COMMIT=$2 OUT=$3 BUILDER_ID=$4
HERE=$(cd "$(dirname "$0")" && pwd)
fail() { echo "BUILD FAIL [$ARCH]: $*" >&2; exit 1; }
case $ARCH in
  x86_64)  PLATFORM=linux/amd64 ;;
  aarch64) PLATFORM=linux/arm64 ;;
  *) fail "architecture must be x86_64 or aarch64" ;;
esac
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "commit must be a full 40-hex sha"
[[ $(git rev-parse HEAD) == "$COMMIT" ]] || fail "checked out $(git rev-parse HEAD), not $COMMIT"
[[ -z $(git status --porcelain) ]] || fail "the checkout is not clean"
[[ $(uname -m) == "$ARCH" ]] || fail "this runner is $(uname -m); $ARCH is built natively on an $ARCH runner"
TRIPLE="$ARCH-unknown-linux-gnu"
NAME="sumchain-$COMMIT-$TRIPLE"
mkdir -p "$OUT"
case "$(cd "$OUT" && pwd -P)/" in "$(git rev-parse --show-toplevel)"/*) fail "out-dir must be outside the checkout" ;; esac
X="$OUT/.export-$ARCH"
rm -rf "$X"

docker buildx build -f tools/release/native.Dockerfile --target artifacts --platform "$PLATFORM" \
  --build-arg GIT_HASH="$COMMIT" \
  --sbom=true --provenance="mode=max,version=v1,builder-id=$BUILDER_ID" \
  --output "type=local,dest=$X" .

# The local exporter writes the attestations beside the files.
ls -la "$X" >&2
[[ -f $X/sumchain && -f $X/sumchain-wallet ]] || fail "the build exported no binaries"
prov=$(find "$X" -maxdepth 1 -name 'provenance*.json' | head -1)
[[ -n $prov ]] || fail "the build exported no provenance"
sboms=$(find "$X" -maxdepth 1 -name 'sbom*.spdx.json' | sort)
[[ -n $sboms ]] || fail "the build exported no SPDX SBOM"
# One SBOM per archive: the builder stage's (it catalogs Cargo.lock) when present.
sbom=$(grep -m1 -v '/sbom.spdx.json$' <<<"$sboms" || head -1 <<<"$sboms")

chmod 0755 "$X/sumchain" "$X/sumchain-wallet"
bash "$HERE/smoke-native.sh" "$X/sumchain" "$COMMIT"

S="$OUT/stage/$NAME"
rm -rf "$OUT/stage"; mkdir -p "$S"
cp "$X/sumchain" "$X/sumchain-wallet" "$S/"
epoch=$(git log -1 --format=%ct "$COMMIT")
(cd "$OUT/stage" && tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
   --mode='u=rwx,go=rx' -cf - "$NAME" | gzip -n -9 > "$OUT/$NAME.tar.gz")
cp "$sbom" "$OUT/$NAME.spdx.json"
cp "$prov" "$OUT/$NAME.provenance.json"
h() { sha256sum "$1" | cut -d' ' -f1; }
python3 - "$OUT/$TRIPLE.json" <<EOF
import json, sys
json.dump({"triple": "$TRIPLE", "platform": "$PLATFORM", "commit": "$COMMIT",
           "archive": "$NAME.tar.gz", "archive_sha256": "$(h "$OUT/$NAME.tar.gz")",
           "binary_sha256": "$(h "$S/sumchain")", "wallet_sha256": "$(h "$S/sumchain-wallet")",
           "sbom": "$NAME.spdx.json", "sbom_sha256": "$(h "$OUT/$NAME.spdx.json")",
           "provenance": "$NAME.provenance.json", "provenance_sha256": "$(h "$OUT/$NAME.provenance.json")",
           "version": "sumchain $COMMIT"}, open(sys.argv[1], "w"), indent=1, sort_keys=True)
EOF
rm -rf "$X" "$OUT/stage"
python3 "$HERE/native-release.py" check-arch "$OUT" --commit "$COMMIT" --triple "$TRIPLE" \
  || fail "the archive does not verify"
echo "BUILT $NAME.tar.gz sha256 $(h "$OUT/$NAME.tar.gz")"

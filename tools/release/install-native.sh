#!/usr/bin/env bash
# install-native.sh --release-dir <dir> --commit <40-hex> [--prefix /opt/sumchain]
#                   (--verify-attestation | --sums-sha256 <64-hex>)
#
# Installs one native release on a validator host, SIDE BY SIDE, without
# touching the running service:
#
#   <prefix>/releases/<commit>/sumchain, sumchain-wallet   (read-only, 0555)
#
# * The archive is chosen from `uname -m` (x86_64, or aarch64/arm64). Nobody
#   names an architecture; any other machine is refused.
# * The release is authenticated through SHA256SUMS, either by
#   --verify-attestation (tools/release/verify-attestation.sh --file: signed by
#   release-image workflow policy -- this repository's release workflow on
#   main), or by --sums-sha256, the hash of a SHA256SUMS whose attestation the
#   operator verified on another machine. Then the archive and the release
#   record must match SHA256SUMS, and the extracted binary must hash as the
#   record says.
# * The binary must report `sumchain <commit>` and have no missing library.
# * An existing install of the same commit is accepted only if identical, and
#   never overwritten.
# Never compiles anything, never edits systemd, never switches what runs:
# switching is a separate, verified runbook step.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
DIR="" COMMIT="" PREFIX=/opt/sumchain ATTEST=0 SUMS_SHA=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --release-dir) DIR=$2; shift 2 ;; --commit) COMMIT=$2; shift 2 ;; --prefix) PREFIX=$2; shift 2 ;;
    --verify-attestation) ATTEST=1; shift ;; --sums-sha256) SUMS_SHA=$2; shift 2 ;;
    *) echo "usage: see the header of $0" >&2; exit 2 ;;
  esac
done
fail() { echo "INSTALL FAIL: $*" >&2; exit 1; }
h() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
[[ -d $DIR ]] || fail "--release-dir '$DIR' is not a directory"
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "--commit must be the full 40-hex release commit"
[[ $ATTEST -eq 1 || $SUMS_SHA =~ ^[0-9a-f]{64}$ ]] \
  || fail "authenticate the release: --verify-attestation, or --sums-sha256 of an attestation-verified SHA256SUMS"

case $(uname -m) in
  x86_64) TRIPLE=x86_64-unknown-linux-gnu ;;
  aarch64|arm64) TRIPLE=aarch64-unknown-linux-gnu ;;
  *) fail "unsupported machine $(uname -m); releases exist for x86_64 and aarch64 Linux" ;;
esac
[[ $(uname -s) == Linux || -n ${INSTALL_NATIVE_TEST_ANY_OS:-} ]] || fail "release archives are for Linux"
NAME="sumchain-$COMMIT-$TRIPLE"
ARCHIVE="$DIR/$NAME.tar.gz"
[[ -f $DIR/SHA256SUMS && -f $DIR/release-record.txt && -f $ARCHIVE ]] \
  || fail "the release directory lacks SHA256SUMS, release-record.txt or $NAME.tar.gz"

# 1. Authenticate SHA256SUMS.
if [[ $ATTEST -eq 1 ]]; then
  bash "$HERE/verify-attestation.sh" --file "$DIR/SHA256SUMS" "$COMMIT" >&2 \
    || fail "SHA256SUMS is not attested by the release workflow on main"
else
  [[ $(h "$DIR/SHA256SUMS") == "$SUMS_SHA" ]] || fail "SHA256SUMS does not hash to --sums-sha256"
fi

# 2. The archive and the record, against SHA256SUMS.
sum_of() { awk -v f="$1" '$2==f {print $1}' "$DIR/SHA256SUMS"; }
[[ -n $(sum_of "$NAME.tar.gz") && $(h "$ARCHIVE") == "$(sum_of "$NAME.tar.gz")" ]] \
  || fail "$NAME.tar.gz does not match SHA256SUMS"
[[ -n $(sum_of release-record.txt) && $(h "$DIR/release-record.txt") == "$(sum_of release-record.txt)" ]] \
  || fail "release-record.txt does not match SHA256SUMS"
rec() { awk -v k="$1:" '$1==k {print $2}' "$DIR/release-record.txt"; }
[[ $(rec release_commit) == "$COMMIT" ]] || fail "the release record is for $(rec release_commit), not $COMMIT"
K=${TRIPLE%%-*}
WANT_BIN=$(rec "${K}_binary_sha256") WANT_WALLET=$(rec "${K}_wallet_sha256")
[[ $WANT_BIN =~ ^[0-9a-f]{64}$ && $WANT_WALLET =~ ^[0-9a-f]{64}$ ]] || fail "the record has no $K binary hashes"
[[ $(rec "${K}_archive") == "$NAME.tar.gz" ]] || fail "the record names another $K archive"

# 3. Extract beside the destination, and prove the binary.
DEST="$PREFIX/releases/$COMMIT"
mkdir -p "$PREFIX/releases"
TMP=$(mktemp -d "$PREFIX/releases/.install-$COMMIT.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
tar -xzf "$ARCHIVE" -C "$TMP" --no-same-owner
SRC="$TMP/$NAME"
[[ -f $SRC/sumchain && -f $SRC/sumchain-wallet && ! -L $SRC/sumchain && ! -L $SRC/sumchain-wallet ]] \
  || fail "the archive does not hold $NAME/{sumchain,sumchain-wallet} as regular files"
[[ $(h "$SRC/sumchain") == "$WANT_BIN" ]] || fail "the extracted sumchain does not hash as the release record says"
[[ $(h "$SRC/sumchain-wallet") == "$WANT_WALLET" ]] || fail "the extracted sumchain-wallet does not hash as recorded"
ver=$("$SRC/sumchain" --version) || fail "sumchain --version failed"
[[ $ver == "sumchain $COMMIT" ]] || fail "the binary reports '$ver', not 'sumchain $COMMIT'"
if command -v ldd >/dev/null && ldd "$SRC/sumchain" 2>&1 | grep -q 'not found'; then
  fail "missing shared libraries: $(ldd "$SRC/sumchain" | grep 'not found' | tr '\n' ' ')"
fi

# 4. Side by side, never over an existing install.
if [[ -e $DEST ]]; then
  [[ -f $DEST/sumchain && $(h "$DEST/sumchain") == "$WANT_BIN" && $(h "$DEST/sumchain-wallet") == "$WANT_WALLET" ]] \
    || fail "$DEST exists and differs from this release; it is never overwritten"
  echo "ALREADY INSTALLED: $DEST/sumchain ($ver), identical"
  exit 0
fi
chmod 0555 "$SRC/sumchain" "$SRC/sumchain-wallet"
chmod 0755 "$SRC"
mv "$SRC" "$DEST"
echo "INSTALLED: $DEST/sumchain ($ver, $TRIPLE, sha256 $WANT_BIN)"
echo "The running service is unchanged. Switching it is a separate runbook step."

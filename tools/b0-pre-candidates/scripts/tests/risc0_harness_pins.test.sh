#!/usr/bin/env bash
# RISC Zero verifier-material harness MSRV-pin policy regression (SMOKE-BLOCKED-006).
#
# The harness has no committed lock (it resolves fresh in-container), and the pinned RISC Zero
# 3.0.5 stack pulls rolling-MSRV transitives (ruint, enum-ordinalize + its derive) that float past
# the pinned Rust 1.88. The fix is EXPLICIT EXACT PINS — not a loosened range and not Cargo's
# incompatible-rust-versions resolver fallback. This test fails closed if either policy regresses:
#   * each MSRV-sensitive dep is pinned exactly (=X.Y.Z), no range operator;
#   * the harness declares its rust-version compiler contract;
#   * no incompatible-rust-versions resolver-fallback config is introduced anywhere that would
#     make the harness rely on the resolver instead of the explicit pins.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$(cd "$HERE/../../.." && pwd)"
ROOT="$(cd "$TOOLS/.." && pwd)"
MANIFEST="$TOOLS/b0-pre-candidates/harness/risc0-verifier-material/Cargo.toml"

set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }

[ -f "$MANIFEST" ] || { bad "missing RISC0 harness manifest"; echo "risc0_harness_pins: 1 FAILURE(S)"; exit 1; }

# The MSRV-sensitive deps that MUST be exact-pinned (=), with the expected version.
declare_pin() { # <crate> <expected-exact-version>
  local crate="$1" want="$2"
  # match:  crate = "=X"   OR   crate = { version = "=X", ... }
  local line
  line="$(grep -nE "^[[:space:]]*${crate}[[:space:]]*=" "$MANIFEST" | head -1)"
  if [ -z "$line" ]; then bad "$crate not present in harness manifest"; return; fi
  # The version is the first quoted token that looks like a version (optional '=' then a digit) —
  # works for both `crate = "=X"` and `crate = { version = "=X", features = [...] }`.
  local ver
  ver="$(grep -oE '"=?[0-9][^"]*"' <<<"$line" | head -1 | tr -d '"')"
  if [ "$ver" = "=$want" ]; then
    ok "$crate pinned exactly =$want"
  else
    bad "$crate is '$ver', expected exact '=$want' (loose range or wrong version)"
  fi
  # explicit range-operator rejection on the whole dep line
  case "$ver" in
    *'^'*|*'~'*|*'>'*|*'<'*|*'*'*|*' - '*) bad "$crate uses a RANGE ('$ver'); must be an exact = pin" ;;
  esac
}
declare_pin ruint "1.17.2"
declare_pin enum-ordinalize "4.3.2"
declare_pin enum-ordinalize-derive "4.3.2"

# ruint must keep default-features off + the serde/borsh features risc0-binfmt requests.
grep -qE 'ruint.*default-features[[:space:]]*=[[:space:]]*false' "$MANIFEST" \
  && ok "ruint keeps default-features = false" || bad "ruint must set default-features = false"
grep -qE 'ruint.*features[[:space:]]*=[[:space:]]*\[[^]]*"serde"[^]]*"borsh"' "$MANIFEST" \
  && ok "ruint keeps the serde + borsh features" || bad "ruint must keep features = [serde, borsh]"

# The rust-version compiler contract must be declared (documentary, 1.88).
grep -qE '^[[:space:]]*rust-version[[:space:]]*=[[:space:]]*"1\.88"' "$MANIFEST" \
  && ok "harness declares rust-version = 1.88" || bad "harness must declare rust-version = 1.88"

# NO incompatible-rust-versions resolver fallback may enter the harness or any .cargo/config the
# harness would inherit (repo root, harness dir).
fb=0
for cfg in "$ROOT/.cargo/config.toml" "$ROOT/.cargo/config" \
           "$TOOLS/b0-pre-candidates/harness/risc0-verifier-material/.cargo/config.toml"; do
  [ -f "$cfg" ] && grep -qiE 'incompatible-rust-versions' "$cfg" && { bad "resolver fallback present in $cfg"; fb=1; }
done
[ "$fb" = 0 ] && ok "no incompatible-rust-versions resolver fallback in inherited cargo config"
# Ignore comment lines (the manifest documents that fallback is deliberately NOT used).
if grep -vE '^[[:space:]]*#' "$MANIFEST" | grep -qiE 'incompatible-rust-versions'; then
  bad "resolver fallback leaked into the harness manifest (non-comment)"
else
  ok "no resolver fallback config in the harness manifest"
fi

echo "----"
if [ "$fails" = 0 ]; then echo "risc0_harness_pins: ALL PASS"; else echo "risc0_harness_pins: $fails FAILURE(S)" >&2; fi
exit "$fails"

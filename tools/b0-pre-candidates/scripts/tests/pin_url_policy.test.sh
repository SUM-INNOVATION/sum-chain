#!/usr/bin/env bash
# Pin URL / redirect-host policy tests (findings F1, F6, F7).
#
# The former allow-list matched a host by SUBSTRING against a space-joined string,
# accepted any redirect target, and named the stale delivery host
# `objects.githubusercontent.com`. These tests pin the replacement behaviour: EXACT host
# matching, https end to end, an explicit delivery-host list including the observed
# `release-assets.githubusercontent.com`, and outright refusal of the mutable
# unversioned `rustup/dist/` path.
#
# Every assertion here is OFFLINE: the URL policy is evaluated without fetching, and the
# verify_pins probes are built so the refusal happens BEFORE any download.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
FIXTURE="$HERE/fixtures/proposed-pins.documented-shape.json"
VERIFY="$SCRIPTS/verify_pins.sh"
TMPD="${TMPDIR:-/tmp}"
# shellcheck source=../lib.sh
. "$SCRIPTS/lib.sh"
set +e

fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }

RUSTUP_X86="https://static.rust-lang.org/rustup/archive/1.29.0/x86_64-unknown-linux-gnu/rustup-init"
RUSTUP_ARM="https://static.rust-lang.org/rustup/archive/1.29.0/aarch64-unknown-linux-gnu/rustup-init"
GH_ASSET="https://github.com/example/example/releases/download/v1/asset.tar.gz"

# ---- exact-host allow-listing ----------------------------------------------
host_in_allowlist "github.com" github.com static.rust-lang.org \
  && ok "exact host accepted" || bad "exact host must be accepted"

host_in_allowlist "evil-github.com" github.com \
  && bad "'evil-github.com' must NOT match 'github.com'" || ok "prefix lookalike rejected (not a substring match)"

host_in_allowlist "github.com.attacker.net" github.com \
  && bad "'github.com.attacker.net' must NOT match 'github.com'" || ok "suffix lookalike rejected"

host_in_allowlist "" github.com \
  && bad "empty host must not match" || ok "empty host rejected"

# ---- scheme / primary-host policy for artifact pins -------------------------
require_https_primary_url probe "$RUSTUP_X86" 2>/dev/null \
  && ok "https primary artifact URL accepted" || bad "https primary URL must be accepted"

require_https_primary_url probe "http://static.rust-lang.org/rustup/archive/1.29.0/x86_64-unknown-linux-gnu/rustup-init" 2>/dev/null \
  && bad "http artifact URL must be rejected" || ok "http artifact URL rejected (no protocol downgrade)"

require_https_primary_url probe "https://cdn.example.invalid/rustup-init" 2>/dev/null \
  && bad "non-primary host must be rejected" || ok "non-primary initial host rejected"

require_https_primary_url probe "https://release-assets.githubusercontent.com/x" 2>/dev/null \
  && bad "a delivery-only host must not be accepted as an INITIAL url" \
  || ok "delivery host rejected as an initial URL (it is a redirect target only)"

# ---- redirect-chain policy (pure, no network) -------------------------------
eff="$(require_allowed_effective_url probe "$GH_ASSET" "https://release-assets.githubusercontent.com/xyz?token=redacted" 2>/dev/null)"
[ "$eff" = "release-assets.githubusercontent.com" ] \
  && ok "github.com -> release-assets.githubusercontent.com redirect accepted (observed primary behaviour)" \
  || bad "the observed GitHub delivery host must be accepted; got '$eff'"

eff="$(require_allowed_effective_url probe "$GH_ASSET" "https://objects.githubusercontent.com/xyz" 2>/dev/null)"
[ "$eff" = "objects.githubusercontent.com" ] \
  && ok "legacy objects.githubusercontent.com delivery host still accepted" \
  || bad "legacy delivery host should remain accepted; got '$eff'"

require_allowed_effective_url probe "$GH_ASSET" "https://evil.example.invalid/xyz" 2>/dev/null \
  && bad "unexpected redirect host must be rejected" || ok "unexpected redirect host rejected"

require_allowed_effective_url probe "$GH_ASSET" "http://release-assets.githubusercontent.com/xyz" 2>/dev/null \
  && bad "http redirect target must be rejected" || ok "redirect protocol downgrade to http rejected"

require_allowed_effective_url probe "$GH_ASSET" "https://release-assets.githubusercontent.com.attacker.net/x" 2>/dev/null \
  && bad "lookalike redirect host must be rejected" || ok "lookalike redirect host rejected"

# ---- APT snapshot URL policy ------------------------------------------------
require_apt_pin_url probe "http://snapshot.debian.org/archive/debian/20200101T000000Z/" 2>/dev/null \
  && ok "immutable snapshot service accepted over http (no ca-certificates pre-install)" \
  || bad "snapshot.debian.org base URL must be accepted"

require_apt_pin_url probe "https://snapshot.debian.org/archive/debian/20200101T000000Z/" 2>/dev/null \
  && ok "immutable snapshot service accepted over https" || bad "https snapshot URL must be accepted"

require_apt_pin_url probe "http://deb.debian.org/debian/" 2>/dev/null \
  && bad "rolling mirror must be rejected as an apt pin" || ok "rolling deb.debian.org rejected as an apt pin"

require_apt_pin_url probe "http://snapshot.debian.org/archive/debian/20200101T000000Z" 2>/dev/null \
  && bad "a base URL without a trailing slash must be rejected" || ok "apt base URL requires a trailing slash"

# The http bootstrap exception is scoped to ONE host and is not a general http allowance.
require_apt_pin_url probe "http://snapshot.ubuntu.com/ubuntu/20200101T000000Z/" 2>/dev/null \
  && bad "http must be confined to snapshot.debian.org" \
  || ok "http exception scoped to snapshot.debian.org only (other snapshot hosts need https)"

require_apt_pin_url probe "https://snapshot.ubuntu.com/ubuntu/20200101T000000Z/" 2>/dev/null \
  && ok "other snapshot services accepted over https" || bad "https snapshot.ubuntu.com must be accepted"

require_apt_pin_url probe "http://evil.example.invalid/debian/" 2>/dev/null \
  && bad "an arbitrary http host must be rejected" || ok "arbitrary http host rejected"

# An apt locator may never be redirected off the pinned snapshot host, and an https pin
# may never be downgraded to http.
APT_HTTP="http://snapshot.debian.org/archive/debian/20200101T000000Z/dists/bookworm/InRelease"
APT_HTTPS="https://snapshot.debian.org/archive/debian/20200101T000000Z/dists/bookworm/InRelease"

eff="$(require_apt_effective_url probe "$APT_HTTP" "http://snapshot.debian.org/file/abc123/InRelease" 2>/dev/null)"
[ "$eff" = "snapshot.debian.org" ] \
  && ok "apt redirect to a content-addressed path on the SAME host accepted" \
  || bad "same-host content-addressed redirect must be accepted; got '$eff'"

require_apt_effective_url probe "$APT_HTTP" "http://mirror.example.invalid/file/abc/InRelease" 2>/dev/null \
  && bad "apt redirect to another origin must be rejected" || ok "apt redirect off the pinned host rejected"

require_apt_effective_url probe "$APT_HTTPS" "http://snapshot.debian.org/file/abc/InRelease" 2>/dev/null \
  && bad "https apt pin must not be downgraded to http" || ok "https apt pin downgraded to http rejected"

eff="$(require_apt_effective_url probe "$APT_HTTPS" "https://snapshot.debian.org/file/abc/InRelease" 2>/dev/null)"
[ "$eff" = "snapshot.debian.org" ] && ok "https apt pin staying https accepted" \
  || bad "https->https same-host redirect must be accepted; got '$eff'"

# ---- rustup: mutable dist path and architecture swap, via verify_pins --------
# Probes are built from the committed EMPTY fixture and set ONLY the rustup fields, so
# every refusal below happens before any network fetch.
probe() { # <x86_url> -> verify_pins output
  local url="$1" f="$TMPD/pinurl.$$.json"
  python3 - "$FIXTURE" "$f" "$url" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["rustup_init"]["x86_64"]["url"] = sys.argv[3]
d["rustup_init"]["x86_64"]["sha256"] = "0" * 64
json.dump(d, open(sys.argv[2], "w"))
PY
  bash "$VERIFY" "$f" 2>&1
  rm -f "$f"
}

out="$(probe "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init")"
grep -q "MUTABLE unversioned rustup/dist" <<<"$out" \
  && ok "unversioned rustup/dist URL rejected (mutable 'latest' artifact)" \
  || bad "the mutable rustup/dist path must be rejected; got: $out"

out="$(probe "$RUSTUP_ARM")"
grep -q "not the exact immutable archive locator" <<<"$out" \
  && ok "rustup URL architecture swap rejected (aarch64 URL under the x86_64 key)" \
  || bad "an architecture-swapped rustup URL must be rejected; got: $out"

out="$(probe "https://static.rust-lang.org/rustup/archive/1.28.0/x86_64-unknown-linux-gnu/rustup-init")"
grep -q "not the exact immutable archive locator" <<<"$out" \
  && ok "wrong rustup version in the archive locator rejected" \
  || bad "a non-1.29.0 archive locator must be rejected; got: $out"

out="$(probe "$RUSTUP_X86")"
grep -qE "MUTABLE unversioned|not the exact immutable archive locator" <<<"$out" \
  && bad "the exact immutable archive URL must pass URL policy; got: $out" \
  || ok "exact immutable rustup archive URL accepted by URL policy"

echo "----"
if [ "$fails" -eq 0 ]; then echo "pin_url_policy: ALL TESTS PASS"; exit 0
else echo "pin_url_policy: $fails FAILURE(S)" >&2; exit 1; fi

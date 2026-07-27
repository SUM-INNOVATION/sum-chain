#!/usr/bin/env bash
# Pinned-APT contract tests (findings F2, F4, F8).
#
# The bare-timestamp APT contract was unverifiable and, as consumed, ineffective:
#   * verify_pins.sh needed a URL while both Dockerfiles needed a bare timestamp (F2);
#   * the base image's rolling deb822 source stayed active alongside the snapshot (F4);
#   * snapshot.debian.org resolves ANY timestamp to the nearest PRECEDING snapshot, so
#     "reachable + immutable" passed even for a nonexistent date (F8).
#
# The contract is now four exact fields consumed identically by verify_pins.sh and both
# Dockerfiles, with the InRelease content hash as the snapshot's real identity.
#
# Structural assertions are offline. The live snapshot assertions are network-gated and
# derive every expected hash AT RUNTIME, so no pin value is committed to this repository.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
CONTAINERS="$(cd "$SCRIPTS/../containers" && pwd)"
FIXTURE="$HERE/fixtures/proposed-pins.documented-shape.json"
VERIFY="$SCRIPTS/verify_pins.sh"
TMPD="${TMPDIR:-/tmp}"
# shellcheck source=../lib.sh
. "$SCRIPTS/lib.sh"
set +e

fails=0
ok()   { printf 'ok    %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }
skip() { printf 'SKIP  %s\n' "$1"; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; exit 0; }

# ---- 1. the assertion itself, against fabricated /etc/apt trees -------------
mktree() { # <root> <file> <content>
  mkdir -p "$1/etc/apt/sources.list.d"; : > "$1/etc/apt/sources.list"
  [ -n "${2:-}" ] && printf '%s\n' "$3" > "$1/etc/apt/sources.list.d/$2"
  true
}
R="$TMPD/aptroot.$$"
rm -rf "$R"; mktree "$R" debian.sources 'Types: deb
URIs: http://deb.debian.org/debian
Suites: bookworm'
assert_no_rolling_apt_sources "$R" 2>/dev/null \
  && bad "a rolling deb.debian.org source must be detected" \
  || ok "rolling deb.debian.org source detected and refused"

rm -rf "$R"; mktree "$R" other.list 'deb http://security.debian.org/debian-security bookworm-security main'
assert_no_rolling_apt_sources "$R" 2>/dev/null \
  && bad "a rolling security.debian.org source must be detected" \
  || ok "rolling security.debian.org source detected and refused"

rm -rf "$R"; mkdir -p "$R/etc/apt/sources.list.d"
printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20200101T000000Z/ bookworm main\n' > "$R/etc/apt/sources.list"
assert_no_rolling_apt_sources "$R" 2>/dev/null \
  && ok "only pinned snapshot sources -> assertion passes" \
  || bad "a snapshot-only tree must pass the assertion"
rm -rf "$R"

# ---- 2. both Dockerfiles implement the pinned-only contract -----------------
for df in "$CONTAINERS/sp1.Dockerfile" "$CONTAINERS/risc0.Dockerfile"; do
  n="$(basename "$df")"
  grep -q 'rm -f /etc/apt/sources.list.d/\*.sources /etc/apt/sources.list.d/\*.list' "$df" \
    && ok "$n removes every pre-existing apt source" \
    || bad "$n must remove pre-existing apt sources before the first update"

  grep -qE "grep -RIqsE '\(deb\|security\)\\\\.debian\\\\.org'" "$df" \
    && ok "$n asserts no rolling Debian source survives" \
    || bad "$n must assert that no rolling Debian source survives"

  # The InRelease hash check must come BEFORE apt-get install, not after.
  hl="$(grep -n 'sha256sum -c -' "$df" | head -1 | cut -d: -f1)"
  il="$(grep -n 'apt-get install' "$df" | head -1 | cut -d: -f1)"
  if [ -n "$hl" ] && [ -n "$il" ] && [ "$hl" -lt "$il" ]; then
    ok "$n verifies InRelease hashes BEFORE apt installs"
  else
    bad "$n must verify InRelease hashes before apt-get install (hash line=$hl install line=$il)"
  fi

  grep -q 'Acquire::Check-Valid-Until=false' "$df" \
    && ok "$n preserves the required expired-Release handling" \
    || bad "$n must keep the Valid-Until override (bookworm-security InRelease is expired)"

  grep -q 'APT_SNAPSHOT' "$df" \
    && bad "$n still references the retired bare-timestamp APT_SNAPSHOT" \
    || ok "$n no longer uses the ambiguous bare-timestamp contract"

  # The literal mutable locator must be gone. `rustup/dist/` still appears inside the
  # REFUSAL case pattern, so match the constructed URL, not any mention of the path.
  grep -q 'static\.rust-lang\.org/rustup/dist/' "$df" \
    && bad "$n still fetches the mutable unversioned rustup/dist URL" \
    || ok "$n no longer fetches the mutable rustup/dist URL"

  grep -q 'REFUSED: RUSTUP_INIT_URL uses the mutable unversioned rustup/dist path' "$df" \
    && ok "$n refuses a mutable rustup/dist URL supplied at build time" \
    || bad "$n must refuse a mutable rustup/dist RUSTUP_INIT_URL"

  grep -q 'RUSTUP_INIT_URL is not for this builder' "$df" \
    && ok "$n refuses a cross-architecture RUSTUP_INIT_URL" \
    || bad "$n must refuse a rustup URL for another architecture"

  for a in APT_DEBIAN_URL APT_DEBIAN_INRELEASE_SHA256 APT_SECURITY_URL APT_SECURITY_INRELEASE_SHA256 RUSTUP_INIT_URL; do
    grep -q "ARG $a\$" "$df" || bad "$n is missing build-arg $a"
  done

  # ARG scope regression: BASE_IMAGE/BASE_DIGEST are declared before FROM, which makes
  # them GLOBAL args that fall out of scope inside the build stage. Without a re-declaration
  # after FROM, "${BASE_DIGEST}" expands to the empty string and the fail-closed check
  # below it silently tests nothing (it was never caught because no ratified pins existed).
  froml="$(grep -n '^FROM ' "$df" | head -1 | cut -d: -f1)"
  redecl="$(awk -v s="$froml" 'NR>s && /^ARG BASE_DIGEST$/{print NR; exit}' "$df")"
  gate="$(grep -n 'BASE_DIGEST.*grep -Eq' "$df" | head -1 | cut -d: -f1)"
  if [ -n "$redecl" ] && [ -n "$gate" ] && [ "$redecl" -lt "$gate" ]; then
    ok "$n re-declares ARG BASE_DIGEST after FROM (in scope for the fail-closed gate)"
  else
    bad "$n must re-declare ARG BASE_DIGEST after FROM before referencing it (FROM=$froml redecl=${redecl:-none} gate=${gate:-none})"
  fi

  # The gate must test the VALUE, not merely that the arg is non-empty: a truncated,
  # uppercased or placeholder digest must be refused before any work happens.
  grep -q "BASE_DIGEST.*grep -Eq '\^sha256:\[0-9a-f\]{64}\$'" "$df" \
    && ok "$n gate validates the BASE_DIGEST value shape (sha256:<64hex>)" \
    || bad "$n gate must validate the BASE_DIGEST value, not just non-emptiness"

  for h in APT_DEBIAN_INRELEASE_SHA256 APT_SECURITY_INRELEASE_SHA256 RUSTUP_INIT_SHA256; do
    grep -q "$h.*grep -Eq '\^\[0-9a-f\]{64}\$'" "$df" \
      || bad "$n gate must validate the $h value shape (bare 64-hex)"
  done
  ok "$n gate validates all pinned checksum value shapes"
done
ok "both Dockerfiles declare the four exact APT fields + RUSTUP_INIT_URL"

# ---- 3. missing apt fields fail closed (offline) ----------------------------
out="$(bash "$VERIFY" "$FIXTURE" 2>&1)"
printf '%s' "$out" | grep -q "apt.debian_url / apt.debian_inrelease_sha256 missing" \
  && ok "empty apt fields fail closed" || bad "empty apt fields must fail closed; got: $out"

# ---- 4. live snapshot behaviour (network-gated, values derived at runtime) --
if ! curl -fsS --max-time 20 -o /dev/null "http://snapshot.debian.org/archive/debian/20240101T000000Z/dists/bookworm/InRelease" 2>/dev/null; then
  skip "snapshot.debian.org unreachable — live InRelease hash assertions not run"
else
  T_A=20250101T000000Z
  T_B=20240101T000000Z
  U_A="http://snapshot.debian.org/archive/debian/$T_A/"
  U_B="http://snapshot.debian.org/archive/debian/$T_B/"
  H_A="$(curl -fsSL "${U_A}dists/bookworm/InRelease" | sha256_hex_stdin)"
  H_B="$(curl -fsSL "${U_B}dists/bookworm/InRelease" | sha256_hex_stdin)"

  if [ -z "$H_A" ] || [ "$H_A" = "$H_B" ]; then
    skip "the two probe snapshots serve identical bytes — redirect assertion inconclusive"
  else
    mkpins() { # <debian_url> <debian_hash> -> path
      local f="$TMPD/aptpins.$$.$RANDOM.json"
      python3 - "$FIXTURE" "$f" "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["apt"]["debian_url"] = sys.argv[3]
d["apt"]["debian_inrelease_sha256"] = sys.argv[4]
json.dump(d, open(sys.argv[2], "w"))
PY
      printf '%s' "$f"
    }

    p="$(mkpins "$U_A" "$H_A")"; out="$(bash "$VERIFY" "$p" 2>&1)"; rm -f "$p"
    printf '%s' "$out" | grep -q "apt.debian InRelease sha256 matches the pinned value" \
      && ok "exact snapshot URL + InRelease hash accepted" \
      || bad "the exact snapshot URL/hash pair must be accepted; got: $(printf '%s' "$out" | grep -i apt)"

    # F8: a URL that serves a DIFFERENT (nearest-preceding) snapshot than the pinned
    # hash must be rejected, even though the service responds 200 for both.
    p="$(mkpins "$U_B" "$H_A")"; out="$(bash "$VERIFY" "$p" 2>&1)"; rm -f "$p"
    printf '%s' "$out" | grep -q "served a DIFFERENT snapshot than pinned" \
      && ok "timestamp serving a preceding snapshot rejected by content hash" \
      || bad "a URL serving different bytes than the pinned hash must be rejected; got: $(printf '%s' "$out" | grep -i apt)"

    # A mutated expected hash must be rejected against the correct URL.
    MUT="${H_A%?}$( [ "${H_A: -1}" = "0" ] && echo 1 || echo 0 )"
    p="$(mkpins "$U_A" "$MUT")"; out="$(bash "$VERIFY" "$p" 2>&1)"; rm -f "$p"
    printf '%s' "$out" | grep -q "InRelease sha256 MISMATCH" \
      && ok "mutated InRelease hash rejected" \
      || bad "a mutated InRelease hash must be rejected; got: $(printf '%s' "$out" | grep -i apt)"
  fi
fi

echo "----"
if [ "$fails" -eq 0 ]; then echo "apt_pins: ALL TESTS PASS"; exit 0
else echo "apt_pins: $fails FAILURE(S)" >&2; exit 1; fi

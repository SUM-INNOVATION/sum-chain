#!/usr/bin/env bash
# blake3 shared-leaf cluster pin regression (SMOKE-BLOCKED-005).
#
# The b0-pre-vmat identity leaf is depended on by b0-pre-validator AND both
# verifier-material harnesses (sp1/risc0). Because it sits in the SP1 harness graph
# next to sp1-verifier 6.3.1 (which requires blake3 ^1.6.1), the whole cluster must
# exact-pin ONE blake3 version or the harness lock cannot be generated in-container.
#
# Part 1 (always, no network): the cluster invariant — every cluster manifest pins
#   blake3 to the IDENTICAL exact `=1.6.1` (no range, no skew, no residual 1.5.4),
#   and both committed locks carry blake3 1.6.1 at the crates.io-verified checksum.
#   This prevents a future version skew or a loose range from silently returning.
# Part 2 (opt-in network): reproduces the ORIGINAL shared-leaf conflict — a leaf
#   pinned blake3 =1.5.4 consumed alongside sp1-verifier =6.3.1 fails to resolve —
#   and proves the corrected =1.6.1 leaf resolves. Mirrors the smoke's real failure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$(cd "$HERE/../../.." && pwd)"   # tests -> scripts -> b0-pre-candidates -> tools

# The blake3 the whole cluster is pinned to, and its verified crates.io .crate sha256.
EXPECT_PIN='=1.6.1'
EXPECT_LOCK_VER='1.6.1'
EXPECT_CHECKSUM='675f87afced0413c9bb02843499dbbd3882a237645883f71a2b59644a6d2f753'

# The cluster manifests (path dep on b0-pre-vmat) that must move together.
CLUSTER_MANIFESTS=(
  "$TOOLS/b0-pre-vmat/Cargo.toml"
  "$TOOLS/b0-pre-validator/Cargo.toml"
  "$TOOLS/b0-pre-candidates/harness/sp1-verifier-material/Cargo.toml"
  "$TOOLS/b0-pre-candidates/harness/risc0-verifier-material/Cargo.toml"
)
# The committed locks that must record the moved version + checksum.
CLUSTER_LOCKS=(
  "$TOOLS/b0-pre-vmat/Cargo.lock"
  "$TOOLS/b0-pre-validator/Cargo.lock"
)

set +e
fails=0
ok()  { printf 'ok    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1" >&2; fails=$((fails + 1)); }

# Extract the exact pinned value of the direct `blake3 = "..."` dep from a manifest.
blake3_pin() { grep -oE '^[[:space:]]*blake3[[:space:]]*=[[:space:]]*"[^"]*"' "$1" | head -1 | sed -E 's/.*"([^"]*)".*/\1/'; }

echo "== Part 1: cluster exact-pin invariant (no network) =="
for m in "${CLUSTER_MANIFESTS[@]}"; do
  rel="${m#"$TOOLS"/}"
  [ -f "$m" ] || { bad "missing cluster manifest $rel"; continue; }
  pin="$(blake3_pin "$m")"
  if [ "$pin" = "$EXPECT_PIN" ]; then
    ok "$rel pins blake3 exactly $EXPECT_PIN"
  else
    bad "$rel blake3 pin is '$pin', expected exact '$EXPECT_PIN' (skew or loose range)"
  fi
  # Reject any range operator explicitly (defends against a future ^/~/>=/*/comma loosening).
  case "$pin" in
    *'^'*|*'~'*|*'>'*|*'<'*|*'*'*|*','*|*' '*) bad "$rel blake3 uses a RANGE ('$pin'); the cluster must stay exact-pinned" ;;
  esac
  # No residual old version anywhere in the manifest.
  grep -qE 'blake3.*1\.5\.4' "$m" && bad "$rel still references blake3 1.5.4" || true
done

for l in "${CLUSTER_LOCKS[@]}"; do
  rel="${l#"$TOOLS"/}"
  [ -f "$l" ] || { bad "missing cluster lock $rel"; continue; }
  # Pull the version + checksum from the blake3 [[package]] block.
  blk="$(awk '/^\[\[package\]\]/{p=0} /^name = "blake3"$/{p=1} p{print}' "$l")"
  ver="$(printf '%s\n' "$blk" | grep -oE '^version = "[^"]*"' | sed -E 's/.*"([^"]*)".*/\1/')"
  sum="$(printf '%s\n' "$blk" | grep -oE '^checksum = "[0-9a-f]{64}"' | sed -E 's/.*"([0-9a-f]{64})".*/\1/')"
  [ "$ver" = "$EXPECT_LOCK_VER" ] && ok "$rel lock: blake3 $EXPECT_LOCK_VER" || bad "$rel lock blake3 version '$ver' != $EXPECT_LOCK_VER"
  [ "$sum" = "$EXPECT_CHECKSUM" ] && ok "$rel lock: blake3 checksum matches crates.io primary source" || bad "$rel lock blake3 checksum '$sum' != $EXPECT_CHECKSUM"
done

# All four manifests must agree on the SAME pin (no skew across the shared leaf).
distinct="$(for m in "${CLUSTER_MANIFESTS[@]}"; do blake3_pin "$m"; done | sort -u)"
n_distinct="$(printf '%s\n' "$distinct" | grep -c .)"
if [ "$n_distinct" -eq 1 ] && [ "$distinct" = "$EXPECT_PIN" ]; then
  ok "all cluster manifests agree on one blake3 pin ($distinct)"
else
  bad "cluster blake3 pins are not uniform/expected: [$(printf '%s' "$distinct" | tr '\n' ' ')]"
fi

echo "== Part 2: reproduce the shared-leaf conflict + prove the fix resolves (opt-in network) =="
REQUIRED="${B0PRE_PIN_NET_REQUIRED:-0}"
net_ok=1
if [ "${B0PRE_PIN_NET_IT:-}" != "1" ] && [ "$REQUIRED" != "1" ]; then net_ok=0; fi
if [ "$net_ok" = "1" ]; then command -v cargo >/dev/null 2>&1 || { [ "$REQUIRED" = "1" ] && { echo "FAIL (required): cargo absent" >&2; exit 1; }; net_ok=0; }; fi

if [ "$net_ok" != "1" ]; then
  printf 'SKIP: shared-leaf resolution repro is opt-in (set B0PRE_PIN_NET_IT=1 or B0PRE_PIN_NET_REQUIRED=1 with cargo)\n'
else
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  # Build a leaf + a consumer that deps the leaf AND sp1-verifier =6.3.1 (^1.6.1 blake3).
  make_case() { # <dir> <leaf-blake3-pin> <consumer-blake3-pin>
    local d="$1" leafpin="$2" conspin="$3"
    mkdir -p "$d/leaf/src" "$d/consumer/src"
    printf 'fn main(){}\n' > "$d/consumer/src/main.rs"
    printf 'pub fn _x(){}\n' > "$d/leaf/src/lib.rs"
    cat > "$d/leaf/Cargo.toml" <<TOML
[package]
name = "shared-leaf"
version = "0.0.0"
edition = "2021"
[dependencies]
blake3 = "$leafpin"
TOML
    cat > "$d/consumer/Cargo.toml" <<TOML
[package]
name = "consumer"
version = "0.0.0"
edition = "2021"
[dependencies]
shared-leaf = { path = "../leaf" }
sp1-verifier = "=6.3.1"
blake3 = "$conspin"
TOML
  }

  # NEGATIVE: old shared leaf =1.5.4 + sp1-verifier ^1.6.1 -> unsatisfiable.
  make_case "$T/old" '=1.5.4' '=1.5.4'
  out="$(cd "$T/old/consumer" && cargo generate-lockfile 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && grep -qiE 'failed to select a version for `blake3`|could resolve this conflict' <<<"$out"; then
    ok "old shared-leaf blake3 =1.5.4 + sp1-verifier =6.3.1 fails to resolve (reproduces SMOKE-BLOCKED-005)"
  else
    bad "old =1.5.4 combination did NOT fail as expected (rc=$rc): $(tail -3 <<<"$out")"
  fi

  # POSITIVE: corrected shared leaf =1.6.1 + sp1-verifier ^1.6.1 -> resolves at 1.6.1.
  make_case "$T/new" '=1.6.1' '=1.6.1'
  out="$(cd "$T/new/consumer" && cargo generate-lockfile 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    got="$(awk '/^name = "blake3"$/{p=1} p&&/^version =/{print;exit}' "$T/new/consumer/Cargo.lock" | grep -oE '1\.[0-9]+\.[0-9]+')"
    [ "$got" = "$EXPECT_LOCK_VER" ] && ok "corrected shared-leaf =1.6.1 resolves (blake3 $got)" \
      || bad "corrected fixture resolved blake3 $got, expected $EXPECT_LOCK_VER"
  else
    bad "corrected =1.6.1 fixture failed to resolve (rc=$rc): $(tail -3 <<<"$out")"
  fi
fi

echo "----"
if [ "$fails" = 0 ]; then echo "blake3_cluster_pin: ALL PASS"; else echo "blake3_cluster_pin: $fails FAILURE(S)" >&2; fi
exit "$fails"

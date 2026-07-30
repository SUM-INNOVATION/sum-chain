#!/usr/bin/env bash
# Primary-source verification tests for the cargo-audit + advisory-DB pin blocks (Item 2).
#
# These exercise verify_pins.sh block (6) [cargo-audit: crate sha256 + packaged Cargo.lock]
# and block (7) [advisory-DB: commit -> tree via the canonical GitHub API] against their REAL
# primary sources, so they require network. They are OPT-IN and skip cleanly by default; CI
# may make a skip a hard failure with B0PRE_PIN_NET_REQUIRED=1.
#
# The fixture fills ONLY the cargo-audit + advisory-DB blocks with the proposed values; the
# rest stay empty, so the overall verify_pins run is (correctly) fail-closed. We assert on the
# per-block PASS/FAIL lines, never on the overall rc. No repo file is edited; nothing ratifies.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$(cd "$HERE/.." && pwd)"
FIXTURE="$HERE/fixtures/proposed-pins.documented-shape.json"
VERIFY="$SCRIPTS/verify_pins.sh"
REQUIRED="${B0PRE_PIN_NET_REQUIRED:-0}"

skip_or_fail() {
  if [ "$REQUIRED" = "1" ]; then printf 'FAIL (required mode): %s\n' "$1" >&2; exit 1; fi
  printf 'SKIP: %s\n' "$1"
  printf '\npin_cargo_audit_advdb: SKIPPED (opt-in; set B0PRE_PIN_NET_IT=1 or B0PRE_PIN_NET_REQUIRED=1)\n'
  exit 0
}
[ "${B0PRE_PIN_NET_IT:-}" = "1" ] || [ "$REQUIRED" = "1" ] || skip_or_fail "opt-in flag not set"
command -v python3 >/dev/null 2>&1 || skip_or_fail "python3 absent"
command -v curl    >/dev/null 2>&1 || skip_or_fail "curl absent"
curl -fsSL --proto '=https' -o /dev/null "https://static.crates.io/crates/cargo-audit/cargo-audit-0.22.2.crate" 2>/dev/null \
  || skip_or_fail "static.crates.io unreachable"

# Proposed (UNRATIFIED) values, each re-derived from its primary source in this PR.
CA_VER="0.22.2"
CA_CRATE_SHA="700c2b240f7fd330c24b675fe429f73a5b676531fcc6300400b2b67f155ba12a"
CA_COMMIT="281452c35cf0870969042374110f099a411bc185"
CA_LOCK_SHA="1762e201cbd2cd6992bb9250f45dda4ebbdde2f79d6393f37ee89bda4e0d9fd6"
ADV_REPO="https://github.com/rustsec/advisory-db"
ADV_COMMIT="7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2"
ADV_TREE="2d3ab21e05f8b06ad2e232f92894b5e247d817ce"
# content_blake3 is format-checked in verify_pins (re-derived in full at produce time); this
# is the value `venue-verify checkout-digest` produced over the pinned advisory-DB checkout.
ADV_CONTENT="2682964ab6c5b529e2307efb0e42601c8560b2b8208f5c73b2a2b6e8b4c432ff"

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }

mkfix() { # <out> <crate_sha> ; fills cargo_audit + advisory_db with real values (crate_sha overridable)
  CRATE="$2" python3 - "$FIXTURE" "$1" "$CA_VER" "$CA_COMMIT" "$CA_LOCK_SHA" \
    "$ADV_REPO" "$ADV_COMMIT" "$ADV_TREE" "$ADV_CONTENT" <<'PY'
import json, os, sys
src, out, ca_ver, ca_commit, ca_lock, adv_repo, adv_commit, adv_tree, adv_content = sys.argv[1:10]
d = json.load(open(src))
d["cargo_audit"] = {"version": ca_ver, "crate_sha256": os.environ["CRATE"],
                    "source_commit": ca_commit, "packaged_lock_sha256": ca_lock}
d["advisory_db"] = {"repo": adv_repo, "commit": adv_commit, "git_tree": adv_tree,
                    "content_blake3": adv_content}
json.dump(d, open(out, "w"))
PY
}

# ---- positive: real crate sha256 -> both cargo-audit lines + advisory-DB tree line pass ----
mkfix "$T/good.json" "$CA_CRATE_SHA"
out="$(bash "$VERIFY" "$T/good.json" 2>&1)"
grep -q "cargo-audit $CA_VER .crate sha256 matches primary source" <<<"$out" \
  && ok "cargo-audit .crate sha256 verified against static.crates.io" \
  || bad "cargo-audit .crate sha256 PASS line absent; out: $(grep -i cargo-audit <<<"$out")"
grep -q "cargo-audit $CA_VER packaged Cargo.lock sha256 matches the verified .crate" <<<"$out" \
  && ok "cargo-audit packaged Cargo.lock sha256 verified from the .crate" \
  || bad "cargo-audit packaged-lock PASS line absent; out: $(grep -i cargo-audit <<<"$out")"
grep -q "advisory_db commit $ADV_COMMIT -> tree $ADV_TREE confirmed" <<<"$out" \
  && ok "advisory-DB commit->tree confirmed by the canonical GitHub repo" \
  || bad "advisory-DB tree PASS line absent; out: $(grep -i advisory <<<"$out")"

# ---- negative: a wrong crate sha256 must be reported as a MISMATCH (fail-closed) ----------
mkfix "$T/bad.json" "$(printf 'f%.0s' $(seq 1 64))"
out2="$(bash "$VERIFY" "$T/bad.json" 2>&1)"
grep -qi "cargo-audit .crate sha256 MISMATCH" <<<"$out2" \
  && ok "wrong cargo-audit crate sha256 is reported as a MISMATCH (fail-closed)" \
  || bad "wrong crate sha256 not reported as MISMATCH; out: $(grep -i cargo-audit <<<"$out2")"

# ---- negative: a wrong advisory-DB tree must be reported as a MISMATCH --------------------
ADV_TREE="ffffffffffffffffffffffffffffffffffffffff" \
  python3 - "$FIXTURE" "$T/badtree.json" "$CA_VER" "$CA_COMMIT" "$CA_LOCK_SHA" "$CA_CRATE_SHA" "$ADV_REPO" "$ADV_COMMIT" "$ADV_CONTENT" <<'PY'
import json, os, sys
src, out, ca_ver, ca_commit, ca_lock, ca_crate, adv_repo, adv_commit, adv_content = sys.argv[1:10]
d = json.load(open(src))
d["cargo_audit"] = {"version": ca_ver, "crate_sha256": ca_crate,
                    "source_commit": ca_commit, "packaged_lock_sha256": ca_lock}
d["advisory_db"] = {"repo": adv_repo, "commit": adv_commit, "git_tree": os.environ["ADV_TREE"],
                    "content_blake3": adv_content}
json.dump(d, open(out, "w"))
PY
out3="$(bash "$VERIFY" "$T/badtree.json" 2>&1)"
grep -qi "advisory_db.git_tree MISMATCH" <<<"$out3" \
  && ok "wrong advisory-DB tree is reported as a MISMATCH (fail-closed)" \
  || bad "wrong advisory-DB tree not reported as MISMATCH; out: $(grep -i advisory <<<"$out3")"

echo "----"
if [ "$F" = 0 ]; then
  # Terminal marker: required CI greps for this to prove the test EXECUTED (a SKIP prints its
  # own line and never this marker), so a skipped/absent run fails the required check.
  echo "PIN_CARGO_AUDIT_ADVDB_PASS"
  echo "pin_cargo_audit_advdb: ALL TESTS PASS"; exit 0
else echo "pin_cargo_audit_advdb: FAILURE(S)" >&2; exit 1; fi

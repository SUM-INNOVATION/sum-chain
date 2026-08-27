#!/usr/bin/env bash
# CI test — the SP1 GUEST dependency-seed AUTHORITY (one authenticated, content-addressed OFFLINE vendor
# seed) + the RISC0 Option-B authenticated-runner binding. Both are enforced through ONE shared lib.sh
# helper each, so the producer, the identity emitter, and the measurement path cannot drift:
#   * b0_authenticate_sp1_guest_seed_pkg  — re-authenticates a sealed seed package and materializes its
#       exact COPIED bytes offline; refuses missing / mutated / substituted / superseded / wrong-lock /
#       wrong-toolchain seeds. produce_canonical_sp1_guest.sh consumes EXACTLY this (no re-vendor).
#   * b0_verify_risc0_authenticated_runner — the RISC0 guest single-source-of-truth: runner blake3 == the
#       recipe's authenticated build-A runner (real embed, arch, ratified toolchain). derive_guest_set.sh
#       (Phase-1 identity) AND measure_fragment.sh (measurement) drive the SAME helper -> identity==measurement.
#
# The REAL two-provision reproduction (cargo +1.90.0 vendor --locked) and the real A/B guest builds are
# VENUE work (the burn-in): this CI test proves the AUTHENTICATION + refusal matrix + determinism +
# path-independence of the addressing, plus source-level guards (offline, no re-vendor, no legacy RISC0
# build, seed-authority bound into both verifier preimages). No network / Docker / toolchain required.
# Terminal marker: SP1_GUEST_DEP_SEED_TEST_PASS.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"          # .../b0-pre-candidates/scripts
CROOT="$(cd "$SCR/.." && pwd)"         # .../b0-pre-candidates
REPO="$(cd "$CROOT/../.." && pwd)"     # repo root
SRC=507281e21e95a6a98e3480e25e12d1baab586e07
VALIDATOR_CANON="$REPO/tools/b0-pre-validator/src/venue/canonical_sp1_guest_artifact.rs"
INDEP_CANON="$REPO/tools/b0-pre-independent/src/canonical_sp1_guest.rs"
export PATH="$HOME/.cargo/bin:$PATH"; [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env" 2>/dev/null
for c in b3sum sha256sum python3; do command -v "$c" >/dev/null || { echo "SKIP: $c not available"; exit 0; }; done
PASS=0; FAIL=0
ok(){ echo "ok - $*"; PASS=$((PASS+1)); }
bad(){ echo "not ok - $*"; FAIL=$((FAIL+1)); }
# shellcheck source=../lib.sh
. "$SCR/lib.sh"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
LOCK_SHA="$(printf 'canonical-sp1-cargo-lock' | sha256sum | awk '{print $1}')"

# Build a minimal, SELF-CONSISTENT sealed SP1 guest dep-seed package. Uses the REAL address helpers
# (b0_seed_inventory_address + b0_sp1_dep_seed_authority_address) so there is no preimage duplication.
# Prints the authority address. Optional overrides let the negatives inject exactly one defect.
mk_seed_pkg() { # <outdir> [toolchain] [lock_sha] [seed_inv_override]
  local out="$1" tc="${2:-1.90.0-x86_64-unknown-linux-gnu}" lock="${3:-$LOCK_SHA}" ovr="${4:-}"
  rm -rf "$out"; mkdir -p "$out/vendor/demo-crate/src"
  printf 'pub fn x() -> u32 { 7 }\n' > "$out/vendor/demo-crate/src/lib.rs"
  printf '{"files":{},"package":"%s"}\n' "$(printf 'demo' | sha256sum | awk '{print $1}')" \
    > "$out/vendor/demo-crate/.cargo-checksum.json"
  printf '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "/b0/canonical/sp1-guest-vendor"\n[net]\noffline = true\n' \
    > "$out/config.toml"
  # seed inventory over {vendor,config} ONLY (record + .content-address are written afterwards).
  local seed_inv; seed_inv="$(b0_seed_inventory_address "$out")" || return 1
  [ -n "$ovr" ] && seed_inv="$ovr"
  local vcfg; vcfg="$(sha256sum "$out/config.toml" | awk '{print $1}')"
  local rec="$out/sp1-guest-dep-seed-authority.v1.json"
  python3 - "$rec" "$B0_SP1_DEP_SEED_AUTHORITY_DOMAIN" "$SRC" "$lock" "$seed_inv" "$vcfg" "$tc" <<'PY'
import json,sys
rec_p,domain,src,lock,seed_inv,vcfg,tc=sys.argv[1:8]
rec={"schema":domain,"measured_source_commit":src,"guest_lock_sha256":lock,"guest_lock_blake3":"b"*64,
 "seed_inventory_address":seed_inv,"vendor_config_sha256":vcfg,
 "provisioning":{"cargo_version":"cargo 1.90.0 (test)","cargo_bin_blake3":"c"*64,"toolchain":tc,
   "command":"cargo +1.90.0 vendor --locked"},
 "package_count":1,
 "packages":[{"name":"demo-crate","version":"0.1.0",
   "source":"registry+https://github.com/rust-lang/crates.io-index","crates_io_checksum":"d"*64}],
 "address":""}
json.dump(rec,open(rec_p,"w"),indent=1,sort_keys=True); open(rec_p,"a").write("\n")
PY
  local addr; addr="$(b0_sp1_dep_seed_authority_address "$rec")" || return 1
  python3 - "$rec" "$addr" <<'PY'
import json,sys
p,addr=sys.argv[1:3]; r=json.load(open(p)); r["address"]=addr
json.dump(r,open(p,"w"),indent=1,sort_keys=True); open(p,"a").write("\n")
PY
  printf '%s' "$addr" > "$out/.content-address"
  printf '%s\n' "$addr"
}
# run the shared authenticator; return its exit code (0 accept / 1 refuse), silence stdout.
auth() { b0_authenticate_sp1_guest_seed_pkg "$1" "${2:-$LOCK_SHA}" "$WORK/dest.$RANDOM" >/dev/null 2>"$WORK/err"; }

echo "### 1. SP1 dep-seed: POSITIVE — a valid sealed package authenticates + materializes"
PKG="$WORK/pkg-ok"; AUTH_ADDR="$(mk_seed_pkg "$PKG")"
line="$(b0_authenticate_sp1_guest_seed_pkg "$PKG" "$LOCK_SHA" "$WORK/dest-ok" 2>"$WORK/err")" \
  && ok "valid sealed seed authenticates" || bad "valid sealed seed REFUSED unexpectedly: $(cat "$WORK/err")"
read -r a_auth a_seed a_vcfg <<<"$line"
[ "$a_auth" = "$AUTH_ADDR" ] && ok "prints the sealed authority address" || bad "authority address mismatch ($a_auth != $AUTH_ADDR)"
[ -d "$WORK/dest-ok/vendor" ] && [ -s "$WORK/dest-ok/config.toml" ] && ok "materialized {vendor,config} offline" || bad "materialization missing"
[ -e "$WORK/dest-ok/sp1-guest-dep-seed-authority.v1.json" ] && bad "materialized dest leaked the record (should be vendor+config only)" || ok "dest carries ONLY the build seed (no record/.content-address)"

echo "### 2. SP1 dep-seed: REFUSAL MATRIX (missing / mutated / substituted / superseded / wrong-lock / wrong-toolchain)"
# missing components
for miss in vendor config.toml sp1-guest-dep-seed-authority.v1.json; do
  P="$WORK/miss-$RANDOM"; mk_seed_pkg "$P" >/dev/null; rm -rf "${P:?}/$miss"
  auth "$P" && bad "missing $miss NOT refused" || ok "missing $miss refused"
done
# superseded ambient-1.97.1 seed (8584a56d…) — record self-consistent but seed inventory is the superseded one
P="$WORK/superseded"; mk_seed_pkg "$P" 1.90.0-x86_64-unknown-linux-gnu "$LOCK_SHA" "$B0_SP1_DEP_SEED_SUPERSEDED_ADDR" >/dev/null
auth "$P" && bad "superseded 8584a56d NOT refused" || ok "superseded ambient-1.97.1 seed refused"
# wrong provisioning toolchain (ambient cargo)
P="$WORK/wrong-tc"; mk_seed_pkg "$P" 1.97.1-x86_64-unknown-linux-gnu >/dev/null
auth "$P" && bad "non-1.90 toolchain NOT refused" || ok "wrong provisioning toolchain (not cargo 1.90.0) refused"
# wrong guest lock (seed for a different lock)
P="$WORK/ok2"; mk_seed_pkg "$P" >/dev/null
b0_authenticate_sp1_guest_seed_pkg "$P" "$(printf other | sha256sum | awk '{print $1}')" "$WORK/d.$RANDOM" >/dev/null 2>&1 \
  && bad "wrong guest_lock NOT refused" || ok "seed for a different lock refused"
# mutated authority record (field changed WITHOUT recomputing address)
P="$WORK/mut-rec"; mk_seed_pkg "$P" >/dev/null
python3 -c 'import json,sys;p=sys.argv[1];r=json.load(open(p));r["measured_source_commit"]="0"*40;json.dump(r,open(p,"w"),indent=1,sort_keys=True)' "$P/sp1-guest-dep-seed-authority.v1.json"
auth "$P" && bad "tampered authority record NOT refused" || ok "tampered authority record (address recompute mismatch) refused"
# mutated .content-address
P="$WORK/mut-ca"; mk_seed_pkg "$P" >/dev/null; printf '%s' "$(printf 0 | sha256sum | awk '{print $1}')" > "$P/.content-address"
auth "$P" && bad "tampered .content-address NOT refused" || ok "tampered .content-address refused"
# mutated vendored bytes (substitution) — sealed record, but a vendor file changed afterward
P="$WORK/mut-bytes"; mk_seed_pkg "$P" >/dev/null; printf 'X' >> "$P/vendor/demo-crate/src/lib.rs"
auth "$P" && bad "mutated vendored bytes NOT refused" || ok "mutated vendored bytes (materialized inventory != sealed) refused"
# extra vendored file
P="$WORK/extra"; mk_seed_pkg "$P" >/dev/null; printf 'y' > "$P/vendor/demo-crate/EXTRA"
auth "$P" && bad "extra vendored file NOT refused" || ok "extra vendored file refused"
# missing vendored file
P="$WORK/rmfile"; mk_seed_pkg "$P" >/dev/null; rm -f "$P/vendor/demo-crate/.cargo-checksum.json"
auth "$P" && bad "removed vendored file NOT refused" || ok "removed vendored file refused"

echo "### 3. SP1 dep-seed: DETERMINISM + PATH-INDEPENDENCE (content-addressed; two roots -> same addresses)"
PA="$WORK/rootA/pkg"; PB="$WORK/rootB-different-depth/x/y/pkg"; mkdir -p "$(dirname "$PA")" "$(dirname "$PB")"
AA="$(mk_seed_pkg "$PA")"; AB="$(mk_seed_pkg "$PB")"
[ "$AA" = "$AB" ] && ok "identical seed content at two DIFFERENT roots -> identical authority address" || bad "authority address is path-dependent ($AA != $AB)"
SA="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["seed_inventory_address"])' "$PA/sp1-guest-dep-seed-authority.v1.json")"
SB="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["seed_inventory_address"])' "$PB/sp1-guest-dep-seed-authority.v1.json")"
[ "$SA" = "$SB" ] && ok "seed inventory address reproduces across roots" || bad "seed inventory address path-dependent"

echo "### 4. RISC0 Option-B: the shared runner<->recipe binding (identity==measurement single source of truth)"
RUN="$WORK/runner.bin"; printf 'authenticated-double-build-runner-bytes\n' > "$RUN"; chmod +x "$RUN"
RB3="$(b3sum "$RUN" | awk '{print $1}')"; GIMG="$(printf 'guest-image' | sha256sum | awk '{print $1}')"
TCID="$(printf 'ratified-risc0-tc' | sha256sum | awk '{print $1}')"
mk_recipe() { # <out> <runner_blake3> <candidate> <arch> <embed> <tc> <gimg>
  python3 -c 'import json,sys
json.dump({"candidate":sys.argv[3],"arch":sys.argv[4],"b0_venue_embed":int(sys.argv[5]),
"per_arch_toolchain_identity":sys.argv[6],"build_a":{"runner_blake3":sys.argv[2],"guest_image_id":sys.argv[7]}},
open(sys.argv[1],"w"))' "$@"
}
REC="$WORK/recipe.json"; mk_recipe "$REC" "$RB3" risc0 x86_64 1 "$TCID" "$GIMG"
out="$(b0_verify_risc0_authenticated_runner "$RUN" "$REC" x86_64 "$TCID" 2>"$WORK/err")" \
  && ok "authenticated runner==recipe accepted" || bad "valid runner/recipe REFUSED: $(cat "$WORK/err")"
read -r o_rb3 o_gimg <<<"$out"
{ [ "$o_rb3" = "$RB3" ] && [ "$o_gimg" = "$GIMG" ]; } && ok "returns runner blake3 + recipe guest_image_id" || bad "helper output wrong"
# altered runner: recipe claims a different authenticated runner
mk_recipe "$REC" "$(printf other | sha256sum | awk '{print $1}')" risc0 x86_64 1 "$TCID" "$GIMG"
b0_verify_risc0_authenticated_runner "$RUN" "$REC" x86_64 "$TCID" >/dev/null 2>&1 && bad "altered runner NOT refused" || ok "altered runner (blake3 != recipe) refused"
# altered candidate / arch / embed / toolchain
mk_recipe "$REC" "$RB3" sp1 x86_64 1 "$TCID" "$GIMG";     b0_verify_risc0_authenticated_runner "$RUN" "$REC" x86_64 "$TCID" >/dev/null 2>&1 && bad "candidate!=risc0 NOT refused" || ok "recipe candidate != risc0 refused"
mk_recipe "$REC" "$RB3" risc0 aarch64 1 "$TCID" "$GIMG";  b0_verify_risc0_authenticated_runner "$RUN" "$REC" x86_64 "$TCID" >/dev/null 2>&1 && bad "arch mismatch NOT refused" || ok "recipe arch mismatch refused"
mk_recipe "$REC" "$RB3" risc0 x86_64 0 "$TCID" "$GIMG";   b0_verify_risc0_authenticated_runner "$RUN" "$REC" x86_64 "$TCID" >/dev/null 2>&1 && bad "embed=0 NOT refused" || ok "recipe b0_venue_embed != 1 refused"
mk_recipe "$REC" "$RB3" risc0 x86_64 1 "$(printf wrong | sha256sum | awk '{print $1}')" "$GIMG"; b0_verify_risc0_authenticated_runner "$RUN" "$REC" x86_64 "$TCID" >/dev/null 2>&1 && bad "wrong toolchain NOT refused" || ok "recipe per_arch_toolchain != ratified refused"

echo "### 5. SOURCE GUARDS: offline / no-re-vendor / no legacy RISC0 build / seed-authority bound in BOTH verifiers"
# the canonical guest producer NEVER re-vendors (the ONE cargo vendor lives in provision_sp1_guest_seed.sh).
# strip comment lines first — the docstring legitimately NAMES the forbidden command.
grep -vE '^[[:space:]]*#' "$SCR/produce_canonical_sp1_guest.sh" | grep -q 'cargo vendor' && bad "produce_canonical re-vendors (must consume the sealed seed)" || ok "produce_canonical never re-vendors"
grep -q 'b0_authenticate_sp1_guest_seed_pkg' "$SCR/produce_canonical_sp1_guest.sh" && ok "produce_canonical consumes the shared seed authenticator" || bad "produce_canonical does not use the shared authenticator"
# regression: produce_canonical sources ONLY lib.sh + two_root_authority.sh, so it must NOT call need_env
# (that helper is defined locally in derive_guest_set.sh / measure_fragment.sh, NOT in lib.sh) — it uses
# the inline `[ -n "${VAR:-}" ] || die` guard style instead. A stray need_env is a runtime not-found.
grep -q 'need_env' "$SCR/produce_canonical_sp1_guest.sh" && bad "produce_canonical calls need_env (undefined in its sourced scope; use inline [ -n ... ] || die)" || ok "produce_canonical avoids the out-of-scope need_env helper"
# the A/B guest builds are offline + locked + network-denied
{ grep -q -- '--network none' "$SCR/produce_canonical_sp1_guest.sh" && grep -q 'CARGO_NET_OFFLINE=true' "$SCR/produce_canonical_sp1_guest.sh" && grep -q 'cargo prove build --locked' "$SCR/produce_canonical_sp1_guest.sh"; } \
  && ok "guest A/B build is --network none + CARGO_NET_OFFLINE + --locked" || bad "guest build is not fully offline/locked"
# no legacy checkout-local RISC0 build in identity emission (strip comments — they name the removed path)
grep -vE '^[[:space:]]*#' "$SCR/derive_guest_set.sh" | grep -qE 'cargo (build|prove)' && bad "derive_guest_set has a checkout-local cargo build (legacy RISC0 path must be removed)" || ok "derive_guest_set has NO legacy checkout-local build"
# both RISC0 phases drive the SAME shared binding helper
grep -q 'b0_verify_risc0_authenticated_runner' "$SCR/derive_guest_set.sh" && ok "derive_guest_set (identity) uses the shared runner<->recipe helper" || bad "derive_guest_set missing the shared helper"
grep -q 'b0_verify_risc0_authenticated_runner' "$SCR/measure_fragment.sh" && ok "measure_fragment (measurement) uses the shared runner<->recipe helper" || bad "measure_fragment missing the shared helper"
# regression: the ratified risc0 toolchain home is a SEALED, possibly READ-ONLY authority; rzup (risc0-build)
# writes state under RISC0_HOME, so double_build_runner MUST materialize a fresh WRITABLE working copy at a
# fixed canonical path per build, NOT point RISC0_HOME at the sealed home directly (that panics on a
# read-only provisioned home: rzup Permission denied).
grep -qF 'RISC0_HOME="$RISC0_HOME_IN"' "$SCR/double_build_runner.sh" && bad "double_build_runner points RISC0_HOME at the sealed (possibly read-only) home directly" || ok "double_build_runner never sets RISC0_HOME to the sealed home directly"
{ grep -qF 'RISC0_HOME="$R0_HOME_CANON"' "$SCR/double_build_runner.sh" && grep -qF 'chmod -R u+w "$R0_HOME_CANON"' "$SCR/double_build_runner.sh"; } \
  && ok "double_build_runner materializes a writable risc0-home working copy for rzup" || bad "double_build_runner does not materialize a writable risc0-home copy"
# the working copy is AUTHENTICATED content-equal to the sealed authority BEFORE use (manifest incl. modes,
# computed on the mode-preserving cp -a copy, compared == the sealed authority address, before chmod)
{ grep -qF 'R0_SEALED_ADDR="$(b0_source_manifest_addr "$RISC0_HOME_IN")"' "$SCR/double_build_runner.sh" \
  && grep -qF '[ "$r0_mat_addr" = "$R0_SEALED_ADDR" ]' "$SCR/double_build_runner.sh"; } \
  && ok "double_build_runner authenticates the risc0-home copy content-equal to the sealed authority before use" \
  || bad "double_build_runner does not authenticate the risc0-home copy against the sealed authority"
# fail-hard cleaned AFTER each build (rzup's mutable state never shared A->B) + retained recipe evidence
grep -qF 'rm -rf /b0/risc0home || cleanup_fail=' "$SCR/double_build_runner.sh" \
  && ok "double_build_runner fail-hard removes the risc0-home working copy after each build" \
  || bad "double_build_runner does not fail-hard clean the risc0-home copy after each build"
grep -qF 'd["risc0_home_seed"]=' "$SCR/double_build_runner.sh" \
  && ok "double_build_runner retains the risc0-home authority evidence in the recipe (origin + per-build materialized)" \
  || bad "double_build_runner does not retain risc0-home authority evidence in the recipe"
# the seed authority is bound into the artifact address preimage on BOTH the producer AND both verifiers
pc="$(grep -c 'dependency_seed_authority_address' "$SCR/produce_canonical_sp1_guest.sh")"
[ "${pc:-0}" -ge 2 ] && ok "produce_canonical binds dependency_seed_authority_address (produce + verify preimages)" || bad "produce_canonical does not bind seed authority in both preimages"
grep -q 'dependency_seed_authority_address' "$VALIDATOR_CANON" && ok "validator verifier binds dependency_seed_authority_address in its recompute preimage" || bad "validator verifier missing seed-authority binding"
grep -q 'dependency_seed_authority_address' "$INDEP_CANON" && ok "independent verifier binds dependency_seed_authority_address in its recompute preimage" || bad "independent verifier missing seed-authority binding"

echo "----"
echo "SP1_GUEST_DEP_SEED: PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" = 0 ]; then echo "SP1_GUEST_DEP_SEED_TEST_PASS"; exit 0; else echo "SP1_GUEST_DEP_SEED_TEST_FAIL" >&2; exit 1; fi

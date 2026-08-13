#!/usr/bin/env bash
# TEST_ONLY / NON_SELECTION — ONE continuous REAL-CONTAINER v2 E2E: it produces the S1
# Stage-5 evidence on real Docker via the ACTUAL production seam FUNCTIONS (the shared
# lib.sh cores + the real venue-verify subcommands — NOT reconstructed command sequences),
# injects it into a production-assembled per-arch bundle, and drives it all the way through
# the REAL `venue-verify seal-bundle` + `import-bundle` to import verification — then proves
# post-seal mutations fail closed. On success it prints the unambiguous terminal marker
# REAL_CONTAINER_V2_SEAL_IMPORT_PASS, ONLY after import verification completes.
#
# Chain (aarch64 SP1-only bundle — sufficient per the reviewer; RISC Zero is x86-only):
#   gen_lock_in_container (shared)         -> Stage-1 candidate lock
#   require_stage1_lock (real)             -> validated
#   run_stage2_locked (shared)             -> read-only Stage-2 `cargo metadata --locked` (D1)
#   causal_build_hash_exec_runner (shared) -> build the runner, HASH the exact binary, EXEC it
#   venue-verify stage5-generate (real)    -> schema-v2 Stage5Result
#   venue-verify lock-hash (real)          -> domain-separated runner-lock hash bound in the record
#   emit-test-only-bundle + assemble names -> complete required_files set (production assembler)
#   venue-verify seal-bundle (real)        -> immutable per-file manifest
#   venue-verify import-bundle (real)      -> recompute every hash + structurally verify the
#                                             sealed runner lock pins the declared SDK
# Post-seal negatives (all must FAIL closed): altered runner lock; missing file; extra file;
# swapped-candidate file; a v1 Stage5Result; and a TEST_ONLY bundle refused by authoritative
# finalization (stage1-ingest).
#
# Isolated under $HOME; never satisfies authoritative Stage 0; the source_commit is a
# fixture value (never RATIFIED_SOURCE_COMMIT); nothing is aggregated into normative state,
# no protocol hash is written, no proving/selection/deployment.
#
# CI "required-execution" mode: set B0PRE_E2E_REQUIRED=1 to make unavailable Docker / a
# skipped run / a missing terminal marker a FAILURE (the CI job sets it). Local runs may
# opt in with B0PRE_DOCKER_IT=1 (skips cleanly when Docker is absent).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$SCR/.." && pwd)"
VALDIR="$(cd "$ROOT/../b0-pre-validator" && pwd)"
IMG="${B0PRE_E2E_IMAGE:-rust:1-slim-bookworm}"
MARKER="REAL_CONTAINER_V2_SEAL_IMPORT_PASS"
REQUIRED="${B0PRE_E2E_REQUIRED:-0}"

# In required mode, a skip is a hard failure; otherwise it is an allowed opt-out.
skip_or_fail() {
  if [ "$REQUIRED" = "1" ]; then
    printf 'FAIL (required mode): %s\n' "$1" >&2
    printf '%s\n' "e2e_v2_produce_chain: REQUIRED but could not execute -> FAILURE" >&2
    exit 1
  fi
  printf 'SKIP (docker): %s\n' "$1"
  printf '\ne2e_v2_produce_chain: SKIPPED (opt-in; set B0PRE_DOCKER_IT=1 locally or B0PRE_E2E_REQUIRED=1 in CI)\n'
  exit 0
}
[ "${B0PRE_DOCKER_IT:-}" = "1" ] || [ "$REQUIRED" = "1" ] || skip_or_fail "opt-in flag not set"
command -v docker >/dev/null 2>&1 || skip_or_fail "docker not on PATH"
docker version >/dev/null 2>&1 || skip_or_fail "docker daemon not reachable"

VV="$VALDIR/target/debug/venue-verify"
[ -x "$VV" ] || cargo build --quiet --locked --manifest-path "$VALDIR/Cargo.toml" --bin venue-verify \
  || { echo "cannot build venue-verify" >&2; exit 1; }
VAL="$VALDIR/Cargo.toml"

T="$(mktemp -d "$HOME/.b0-e2e-v2-XXXXXX")"; trap 'rm -rf "$T"' EXIT
F=0; pass(){ printf 'ok    %s\n' "$1"; }; fail(){ printf 'FAIL  %s\n' "$1"; F=1; }
vvh(){ "$VV" lock-hash "$1"; }
imports(){ "$VV" import-bundle "$1" >/dev/null 2>"$2"; }   # rc + stderr file

# Source the REAL production functions (Q6 source-execution guard -> no authoritative
# dispatch on source): require_stage1_lock, extract_material_core, gen_lock_in_container,
# run_stage2_locked, causal_build_hash_exec_runner.
# shellcheck source=/dev/null
. "$SCR/extract_material.sh" >/dev/null 2>&1

CDIR_IN="/work/tools/b0-pre-candidates/candidates/sp1"

# ---- lock-less fixture builder image: fixture SP1 candidate baked; login-PATH cargo -----
CTX="$T/ctx"; mkdir -p "$CTX$CDIR_IN/src"
cat > "$CTX$CDIR_IN/Cargo.toml" <<'E'
[package]
name = "sp1-fixture-candidate"
version = "0.0.0"
edition = "2021"
publish = false
[dependencies]
itoa = "=1.0.11"
E
printf 'fn main(){println!("{}", itoa::Buffer::new().format(1u8));}\n' > "$CTX$CDIR_IN/src/main.rs"
# Build the Dockerfile via printf (no heredoc). NO artificial PATH repair: the shared
# cores run NON-login `bash -c`, which honors the base image's `ENV PATH` (cargo on PATH)
# exactly as the pinned venue image does — the fixture must not repair a PATH defect that
# would be absent from production (RT-2).
{
  printf 'FROM %s\n' "$IMG"
  printf 'COPY .%s /work/tools/b0-pre-candidates/candidates/sp1\n' "$CDIR_IN"
  printf 'RUN rm -f %s/Cargo.lock\n' "$CDIR_IN"
} > "$T/Dockerfile"
FIMG="b0-e2e-v2-produce:test-only"
docker build -q -t "$FIMG" -f "$T/Dockerfile" "$CTX" >/dev/null 2>"$T/build.err" \
  && pass "built lock-less fixture builder image (login-PATH cargo)" || { fail "image build"; cat "$T/build.err"; exit 1; }

# The production TEST_ONLY assembler emits the exact required_files for a complete,
# internally-consistent aarch64 bundle (fixed fixture commit + per-candidate builder
# digests). We then OVERWRITE the SP1 S1-evidence files with the REAL-Docker-produced ones,
# aligned to this bundle's Sp1 builder digest + commit, and re-seal + import.
EV="$T/evidence"; mkdir -p "$EV"
"$VV" emit-test-only-bundle "$EV" Aarch64 >/dev/null 2>"$T/emit.err" \
  && pass "production assembler emitted a complete aarch64 bundle base" || { fail "emit-test-only-bundle"; cat "$T/emit.err"; exit 1; }
COMMIT="abcdef0123456789abcdef0123456789abcdef01"          # matches write_test_only_bundle_dir
# Read the base bundle's Sp1 BUILDER-role digest directly from its container.json (robust;
# no b3sum dependency, no coupling to the digest-derivation formula). Our injected v2
# Stage-5 evidence must carry exactly this container_digest.
SP1_DIG="$(python3 -c 'import json,sys
b=json.load(open(sys.argv[1]))
print(next(e["builder_oci_digest"] for e in b if e.get("role")=="builder"))' "$EV/Sp1.container.json")"
grep -Eq '^sha256:[0-9a-f]{64}$' <<<"$SP1_DIG" || { fail "could not read Sp1 builder digest from bundle"; exit 1; }

# ===== Stage 1 (shared gen) + validate (real) =====
gen_lock_in_container "$FIMG" "$CDIR_IN" "$T/Sp1.Cargo.lock" >/dev/null 2>&1 \
  && pass "Stage 1: gen_lock_in_container (shared fn) produced the candidate lock" || fail "gen_lock_in_container"
LH="$(vvh "$T/Sp1.Cargo.lock")"
SH="$(sha256_hex_stdin < "$T/Sp1.Cargo.lock")"
# committed-source-of-truth provenance over the mounted lock (this fixture lock stands in for the
# committed one): the recorded committed sha256/blake3 recompute from these exact bytes.
P="$T/Sp1.lock-provenance.json" LH="$LH" SH="$SH" D="$SP1_DIG" C="$COMMIT" python3 -c 'import json,os;json.dump({"candidate":"Sp1","arch":"Aarch64","origin":"committed-source-of-truth","container_digest":os.environ["D"],"source_commit":os.environ["C"],"committed_lock_sha256_hex":os.environ["SH"],"committed_lock_blake3_hex":os.environ["LH"],"post_lock_sha256_hex":os.environ["SH"],"locked_command_log_blake3_hex":"c"*64,"materialized_closure_blake3_hex":"d"*64,"vendor_inputs_blake3_hex":"e"*64},open(os.environ["P"],"w"))'
( require_stage1_lock "$T/Sp1.Cargo.lock" "$T/Sp1.lock-provenance.json" Sp1 "$VAL" ) >/dev/null 2>"$T/rsl.err" \
  && pass "Stage 1: require_stage1_lock (real fn) accepts it" || { fail "require_stage1_lock"; cat "$T/rsl.err"; }

# ===== Stage 2 (shared read-only-locked mount, D1) =====
run_stage2_locked "$FIMG" "$CDIR_IN" "$T/Sp1.Cargo.lock" "$CDIR_IN/Cargo.lock" "cargo metadata --format-version 1 --locked" "$T/meta.json" 2>"$T/s2.err" \
  && grep -q '"packages"' "$T/meta.json" && pass "Stage 2: run_stage2_locked (shared fn) --locked SUCCEEDS with the RO lock (D1)" || { fail "run_stage2_locked"; tail -3 "$T/s2.err"; }
[ "$(vvh "$T/Sp1.Cargo.lock")" = "$LH" ] && pass "Stage 2: host lock byte-unchanged (read-only proof)" || fail "host lock changed"

# ===== Stage 5 (shared causal build->hash->exec) + real stage5-generate =====
RUN="$T/s5/_runner"; mkdir -p "$RUN/src" "$T/s5"
printf '[package]\nname="b0-pre-sp1-stage5-runner"\nversion="0.0.0"\nedition="2021"\npublish=false\n[dependencies]\nitoa="=1.0.11"\n' > "$RUN/Cargo.toml"
cat > "$RUN/src/main.rs" <<'E'
fn main(){ let out=std::env::args().nth(2).unwrap_or("/out".into());
  for f in ["terminal-proof.bin","public-values.bin","groth16-vk.bin","vkey-hash-claim.bin"]{ std::fs::write(format!("{out}/{f}"), b"x").unwrap(); }
  let cases=["flip_public_input_bit","truncate_proof","swap_verifier_material","corrupt_terminal_claim","zero_fill_receipt"];
  let m:String=cases.iter().map(|c|format!("{{\"name\":\"{c}\",\"actual_rejected\":true}}")).collect::<Vec<_>>().join(",");
  std::fs::write(format!("{out}/mutations.json"),format!("[{m}]")).unwrap();
  println!("VERIFIER_RAN"); }
E
docker run --rm -v "$T/s5:/out" -e CARGO_TARGET_DIR=/tmp/tgt "$FIMG" bash -c "cd /out/_runner && cargo generate-lockfile >/dev/null 2>&1" || fail "runner generate-lockfile"
causal_build_hash_exec_runner "$FIMG" "/out/_runner" "b0-pre-sp1-stage5-runner" "$T/s5" "" >/dev/null 2>"$T/s5.err" \
  && pass "Stage 5: causal_build_hash_exec_runner (shared fn) built+hashed+exec'd the exact binary" || { fail "causal runner"; tail -5 "$T/s5.err"; }
RBIN="$(tr -d ' \n' < "$T/s5/runner-bin.sha256" 2>/dev/null)"
RLOCKHEX="$(vvh "$T/s5/runner-cargo.lock")"
P="$T/s5params.json" RBIN="$RBIN" RL="$RLOCKHEX" D="$SP1_DIG" C="$COMMIT" python3 -c 'import json,os;json.dump({"candidate":"Sp1","arch":"Aarch64","verifier_identity":"itoa fixture verifier (descriptive)","verifier_executed_binary_sha256":os.environ["RBIN"],"verifier_sdk_lock_blake3":os.environ["RL"],"verifier_sdk_name":"itoa","verifier_sdk_version":"1.0.11","container_digest":os.environ["D"],"source_commit":os.environ["C"]},open(os.environ["P"],"w"))'
P="$T/s5/terminal-proof.bin" O="$T/fixtures.json" python3 -c 'import json,os;json.dump([{"label":"terminal-proof","path":os.environ["P"]}],open(os.environ["O"],"w"))'
printf 'e2e causal stage5\n' > "$T/s5cmd.log"
"$VV" stage5-generate "$T/s5params.json" "$T/fixtures.json" "$T/s5/mutations.json" "$T/s5cmd.log" "$T/Sp1.stage5-result.json" >/dev/null 2>"$T/s5gen.err" \
  && pass "Stage 5: vv stage5-generate (real fn) produced a schema-v2 Stage5Result" || { fail "vv stage5-generate"; tail -5 "$T/s5gen.err"; }

# ===== Inject the REAL-Docker v2 STAGE-5 evidence (the S1 fix) into the assembled bundle,
# re-seal, import. The Stage-5 record + its sealed runner lock are the artifacts this PR
# adds/changes; they are self-consistent with the base bundle's Sp1 builder digest + commit
# (set above). The candidate-lock D1 seam (gen -> validate -> read-only Stage-2 --locked) is
# exercised INLINE above on the real lock; it is not injected into the sealed bundle because
# a consistent candidate lock also requires a matching real Stage-2 graph (cargo-audit is an
# image-provisioning detail exercised by the native-x86 smoke, not this lightweight tier).
cp "$T/Sp1.stage5-result.json"    "$EV/Sp1.stage5-result.json"
cp "$T/s5/runner-cargo.lock"      "$EV/Sp1.stage5-runner.lock"
"$VV" seal-bundle "$EV" Aarch64 "$COMMIT" >/dev/null 2>"$T/seal.err" \
  && pass "Assemble+seal: vv seal-bundle (real fn) sealed the bundle with the injected real-Docker S1 evidence" || { fail "seal-bundle"; cat "$T/seal.err"; }
if imports "$EV" "$T/imp.err"; then
  pass "Import: vv import-bundle (real fn) VERIFIED (recomputed the runner-lock domain hash + structurally checked the SDK)"
else
  fail "import-bundle rejected a valid bundle"; tail -6 "$T/imp.err"
fi

# ===== Post-seal negatives (each MUST fail closed) =====
neg(){ # <label> ; mutates $EV via the preceding setup, reseals, expects import failure
  local label="$1"
  if "$VV" seal-bundle "$EV" Aarch64 "$COMMIT" >/dev/null 2>>"$T/neg.err" && imports "$EV" "$T/neg.imp"; then
    fail "negative NOT rejected: $label"
  else
    pass "negative rejected (fail-closed): $label"
  fi
}
# 1) altered runner lock (bytes changed -> recomputed hash != record) — reseal keeps the
#    manifest consistent, so import's record/lock cross-check is what rejects it.
printf '\n# tampered\n' >> "$EV/Sp1.stage5-runner.lock"; neg "altered runner lock"
cp "$T/s5/runner-cargo.lock" "$EV/Sp1.stage5-runner.lock"   # restore
# 2) missing required file.
mv "$EV/Sp1.stage5-runner.lock" "$T/held.lock"
"$VV" seal-bundle "$EV" Aarch64 "$COMMIT" >/dev/null 2>"$T/miss.err" && fail "missing file NOT rejected at seal" || pass "negative rejected (fail-closed): missing runner lock (seal exact-set)"
mv "$T/held.lock" "$EV/Sp1.stage5-runner.lock"              # restore
# 3) extra unmanifested file.
printf 'x' > "$EV/UNEXPECTED.extra"
"$VV" seal-bundle "$EV" Aarch64 "$COMMIT" >/dev/null 2>"$T/extra.err" && fail "extra file NOT rejected at seal" || pass "negative rejected (fail-closed): extra file (seal exact-set)"
rm -f "$EV/UNEXPECTED.extra"
# 4) swapped-candidate stage5 record (Sp1 record claims candidate Risc0).
cp "$EV/Sp1.stage5-result.json" "$T/s5.bak"
python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));d["candidate"]="Risc0";json.dump(d,open(sys.argv[1],"w"))' "$EV/Sp1.stage5-result.json"; neg "swapped-candidate stage5 record"
cp "$T/s5.bak" "$EV/Sp1.stage5-result.json"                 # restore
# 5) a v1 Stage5Result (drop schema_version + causal fields, reinstate installed-CLI hash).
cp "$EV/Sp1.stage5-result.json" "$T/s5.bak2"
python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
for k in ("schema_version","verifier_executed_binary_sha256","verifier_sdk_lock_blake3","verifier_sdk_name","verifier_sdk_version"): d.pop(k,None)
d["tool_identity_hex"]="a"*64
json.dump(d,open(sys.argv[1],"w"))' "$EV/Sp1.stage5-result.json"; neg "v1 Stage5Result (inadequate for authoritative)"
cp "$T/s5.bak2" "$EV/Sp1.stage5-result.json"                # restore
# 6) authoritative finalization refuses this TEST_ONLY evidence. `stage1-ingest` builds a
#    finalizable artifact ONLY from an AUTHORITATIVE_STAGE1 stage1-result-bundle; feeding
#    it the sealed TEST_ONLY per-arch evidence is refused, and it writes NO artifact. (The
#    classification-level guarantee — build_finalizable_artifact / validate_test_only_bundle
#    reject non-AUTHORITATIVE_STAGE1 — is covered by the validator unit suite.)
cp "$T/s5.bak2" "$EV/Sp1.stage5-result.json" 2>/dev/null || true
"$VV" seal-bundle "$EV" Aarch64 "$COMMIT" >/dev/null 2>/dev/null
ART="$T/should-not-exist.finalizable.json"
if cargo run --quiet --locked --manifest-path "$VAL" --bin stage1-ingest -- "$EV/Sp1.stage5-result.json" "$ART" >/dev/null 2>&1; then
  fail "authoritative stage1-ingest accepted TEST_ONLY per-arch evidence"
else
  pass "negative rejected (fail-closed): authoritative stage1-ingest refuses the TEST_ONLY evidence"
fi
[ -f "$ART" ] && fail "stage1-ingest wrote a finalizable artifact from TEST_ONLY evidence" || true

echo "----"
if [ "$F" = 0 ]; then
  printf '%s\n' "$MARKER"
  echo "e2e_v2_produce_chain: ALL PASS (real Docker, real/shared production fns, seal->import-verified, TEST_ONLY / NON_SELECTION)"
else
  echo "e2e_v2_produce_chain: FAILURES (no terminal marker emitted)"; exit 1
fi

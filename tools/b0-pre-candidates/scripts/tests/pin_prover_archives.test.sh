#!/usr/bin/env bash
# verify_pins.sh prover-archive block: positive + full negative matrix (no network — the block
# validates SHAPE + coverage + shared-archive + delivery + no-rzup + forbidden-transcription; the
# member bytes are content-verified IN-IMAGE by the staged provisioner). Uses the real verified
# values. Deterministic; needs only python3.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCR="$(cd "$HERE/.." && pwd)"
VERIFY="$SCR/verify_pins.sh"
F=0; ok(){ printf 'ok    %s\n' "$1"; }; bad(){ printf 'FAIL  %s\n' "$1" >&2; F=1; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 absent"; echo "pin_prover_archives: SKIPPED"; exit 0; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

# Build a proposed-pins JSON with a complete, well-formed prover_archives (other blocks empty).
# $1 = a python expression mutating the `pa` list in place (or "" for none).
build() {
  MUT="$1" OUT="$2" python3 - <<'PY'
import json, os
CP_X86="e21aa7bd13ace2049ca5115ba89236cbf1d3cf716aa6dafc35c10fab6ac7e969"
CP_ARM="b2591c397f0ee377d5db08ee84dc4cf902e9c247a8fd09b4c41ee5a77a86149f"
CR="45aba69689cef25d81237f3ff62456fc96ff1e23f75adfcd16f7c8b8c1606619"
R0="36c016a5bb2ded5bd1f8f92cc487e6ffaeb1e95ec05850c983081a0f716b515b"
A_SP1_X86="c9d6ee7667fa9e0a2302324a6bb0295c55f6acf0e17a242ad11ee45767bb08df"
A_SP1_ARM="9befbd3f5eead2c150579daf8d40bb25550a295dfcc406bf8ea53eaffe9aeed2"
A_R0="936ef988b78f20e3bd9f80e375f3adc934b13addc6ae2680f2e5fc0bcc966158"
def cp(arch, sha, out):
    return {"executable_name":"cargo-prove","member_path":"cargo-prove","member_sha256":sha,
            "member_size_bytes":45420240,"version_argv":"cargo-prove prove --version",
            "version_output":out,"expected_release_commit":"8252c29","delivery":"isolated-path"}
pa=[
  {"archive_name":"sp1-prover","arch":"x86_64","archive_url":"","archive_sha256":A_SP1_X86,
   "members":[cp("x86_64",CP_X86,"cargo-prove sp1 (8252c29 2026-06-25T11:50:01.543258355Z)")]},
  {"archive_name":"sp1-prover","arch":"aarch64","archive_url":"","archive_sha256":A_SP1_ARM,
   "members":[cp("aarch64",CP_ARM,"cargo-prove sp1 (8252c29 2026-06-25T11:49:20.735796629Z)")]},
  {"archive_name":"risc0-toolchain","arch":"x86_64","archive_url":"","archive_sha256":A_R0,
   "members":[
     {"executable_name":"cargo-risczero","member_path":"cargo-risczero","member_sha256":CR,
      "member_size_bytes":15355120,"version_argv":"cargo-risczero risczero --version",
      "version_output":"cargo-risczero 3.0.5","expected_release_commit":"3.0.5","delivery":"isolated-path"},
     {"executable_name":"r0vm","member_path":"r0vm","member_sha256":R0,
      "member_size_bytes":15000000,"version_argv":"r0vm --version",
      "version_output":"risc0-r0vm 3.0.5","expected_release_commit":"3.0.5","delivery":"risc0-server-path"}]},
]
FORBIDDEN_R0="36c01a65bb2ded5bd1f8f92cc487e6ffaeb1e95ec05850c983081a0f716b515b"
mut=os.environ["MUT"]
if mut: exec(mut)
doc={"prover_archives":pa}
json.dump(doc, open(os.environ["OUT"],"w"))
PY
}
runv(){ bash "$VERIFY" "$1" 2>&1; }

# positive
build "" "$T/ok.json"
if grep -q "prover_archives: cargo-prove x86_64+aarch64, cargo-risczero x86_64, r0vm x86_64 (cargo-risczero + r0vm share one archive)" <<<"$(runv "$T/ok.json")"; then
  ok "complete prover_archives passes the shape/coverage/shared-archive/no-rzup check"
else bad "valid prover_archives did not pass"; fi

# negative matrix
expect_fail(){ local label="$1" needle="$2" out; out="$(runv "$T/m.json")"
  grep -qi "$needle" <<<"$out" && ok "$label" || bad "$label — expected FAIL matching '$needle'"; }

build 'pa[0]["archive_sha256"]="z"*64' "$T/m.json";                         expect_fail "altered archive digest refused" "archive_sha256 is not bare 64-hex"
build 'pa[0]["members"][0]["member_sha256"]="00"' "$T/m.json";              expect_fail "malformed member digest refused" "member_sha256 is not bare 64-hex"
build 'pa[2]["members"][1]["member_sha256"]=FORBIDDEN_R0' "$T/m.json";      expect_fail "forbidden r0vm transcription refused" "FORBIDDEN r0vm"
build 'pa[0]["members"][0]["member_size_bytes"]=0' "$T/m.json";             expect_fail "wrong/zero member size refused" "member_size_bytes must be a positive integer"
build 'pa[0]["members"][0]["version_output"]="cargo-prove sp1 (deadbee ...)"' "$T/m.json"; expect_fail "incorrect version output refused" "version_output lacks the expected release identity"
build 'pa[2]["arch"]="aarch64"' "$T/m.json";                                expect_fail "swapped-arch RISC Zero (aarch64) refused" "RISC Zero is x86_64-only"
build 'pa[2]["members"][1]["delivery"]="isolated-path"' "$T/m.json";        expect_fail "r0vm wrong delivery refused" "r0vm must use risc0-server-path"
build 'pa[2]["members"][0]["executable_name"]="rzup"' "$T/m.json";          expect_fail "rzup member refused" "rzup"
build 'pa[2]["members"].pop(1); pa.append({"archive_name":"r0vm-only","arch":"x86_64","archive_url":"","archive_sha256":"a"*64,"members":[{"executable_name":"r0vm","member_path":"r0vm","member_sha256":R0,"member_size_bytes":15000000,"version_argv":"r0vm --version","version_output":"risc0-r0vm 3.0.5","expected_release_commit":"3.0.5","delivery":"risc0-server-path"}]})' "$T/m.json"; expect_fail "cargo-risczero + r0vm not sharing one archive refused" "NOT the same shared archive"
build 'pa.pop(1)' "$T/m.json";                                              expect_fail "missing cargo-prove aarch64 refused" "no cargo-prove for aarch64"

echo "----"
if [ "$F" = 0 ]; then echo "PIN_PROVER_ARCHIVES_PASS"; echo "pin_prover_archives: ALL TESTS PASS"; exit 0
else echo "pin_prover_archives: FAILURE(S)" >&2; exit 1; fi

#!/usr/bin/env bash
# Fixture identity guard (no network, read-only).
#
# Checks that every committed digest file is well-formed 64-hex, that each
# referenced fixture exists, and that the normative protocol artifact embeds
# exactly the exp-table / certificate digests carried by the committed .hash
# files and well-formed 64-hex official-statement / model identities.
#
# The AUTHORITATIVE recomputation (rebuild the table, re-derive the statements,
# re-hash) lives in the Rust test suite; this script is the fast structural /
# cross-consistency gate. Exit 0 = consistent; non-zero = a violation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DOCS="$ROOT/docs/b0-pre"
ART="$DOCS/protocol/b0-pre-protocol-v1.json"

fail=0
note() { printf '%s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fail=1; }

is_hex64() { printf '%s' "$1" | grep -Eq '^[0-9a-f]{64}$'; }

# 1. digest files are well-formed 64-hex.
for hf in "$DOCS"/exp/*.hash; do
  [ -s "$hf" ] || { bad "missing digest file $hf"; continue; }
  if is_hex64 "$(tr -d '\n' < "$hf")"; then
    note "PASS: $(basename "$hf") is 64-hex"
  else
    bad "$(basename "$hf") is not a 64-hex digest"
  fi
done

# 2. referenced fixtures exist and are non-empty.
for f in \
  protocol/b0-pre-protocol-v1.json protocol/b0-pre-protocol-v1.schema.json \
  protocol/hash-golden.json exp/exp_table_q16.json exp/exp_table_certificate.json \
  fixtures/workload/official.json fixtures/encoding-golden/vectors.json \
  fixtures/closure-golden/vectors.json fixtures/evidence-harness/spec.json \
  fixtures/measurement-input-authority/measurement-input-authority.v1.json \
  fixtures/measurement-input-authority/malformed-corpus-report.v1.json \
  fixtures/measurement-input-authority/harness-source-inventory.txt \
  fixtures/measurement-input-authority/eligibility-matrix.v1.json; do
  [ -s "$DOCS/$f" ] && note "PASS: fixture present $f" || bad "missing fixture $f"
done

# 2b. the MIA binds the eligibility record's address, and the eligibility record is the frozen two-cell
#     model (3 identity cells, 2 native-measurement cells, exact unsupported set) self-addressed over its
#     preimage. Structural cross-consistency (the authoritative recompute is in the Rust suite).
python3 - "$DOCS/fixtures/measurement-input-authority" <<'PY' || fail=1
import json, hashlib, sys
d = sys.argv[1]
ok = True
def check(cond, msg):
    global ok; print(("PASS: " if cond else "FAIL: ") + msg); ok = ok and cond
mia = json.load(open(f"{d}/measurement-input-authority.v1.json"))
elig = json.load(open(f"{d}/eligibility-matrix.v1.json"))
# eligibility: exactly the 4 canonical rows, 2 measurement-eligible, 2 unsupported.
rows = [(e["candidate"], e["arch"]) for e in elig["entries"]]
check(rows == [("Sp1","x86_64"),("Sp1","aarch64"),("Risc0","x86_64"),("Risc0","aarch64")],
      "eligibility rows are exactly the 4 canonical (candidate,arch) in order")
meas = [(e["candidate"],e["arch"]) for e in elig["entries"] if e["native_measurement_eligible"]]
unsup = [(e["candidate"],e["arch"]) for e in elig["entries"] if e["unsupported"]]
check(meas == [("Sp1","x86_64"),("Risc0","x86_64")], "exactly two native-measurement cells (x86_64)")
check(unsup == [("Sp1","aarch64"),("Risc0","aarch64")], "exactly the ratified unsupported set")
# eligibility self-address recompute (SHA-256 over the frozen NUL-joined preimage).
def b(x): return "true" if x else "false"
parts = [elig["schema"], elig["b0_pre_spec_hash"], str(len(elig["entries"]))]
for e in elig["entries"]:
    parts += [e["candidate"], e["arch"], b(e["identity_eligible"]), b(e["native_measurement_eligible"]),
              b(e["unsupported"]), e["reason_code"], e["backend"], e["backend_version"],
              e["arch_manifest_evidence"], e["governing_authority"]]
check(hashlib.sha256("\0".join(parts).encode()).hexdigest() == elig["address"],
      "eligibility record address recomputes")
check(mia["eligibility_matrix_address"] == elig["address"],
      "MIA binds the eligibility record's address")
sys.exit(0 if ok else 1)
PY

# 3. artifact embeds the committed digests and well-formed identities.
tbl="$(tr -d '\n' < "$DOCS/exp/exp_table_q16.json.hash")"
crt="$(tr -d '\n' < "$DOCS/exp/exp_table_certificate.json.hash")"
python3 - "$ART" "$tbl" "$crt" <<'PY' || fail=1
import json, re, sys
art, tbl, crt = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(art))
ok = True
def check(cond, msg):
    global ok
    print(("PASS: " if cond else "FAIL: ") + msg)
    ok = ok and cond
hex64 = re.compile(r'^[0-9a-f]{64}$')
check(d["exp_table"]["table_hash_hex"] == tbl, "artifact exp table_hash == committed .hash")
check(d["exp_table"]["certificate_hash_hex"] == crt, "artifact cert hash == committed .hash")
check(bool(hex64.match(d["official_statements"]["model_id_hex"])), "model_id is 64-hex")
sts = d["official_statements"]["statements"]
check(len(sts) == 2, "exactly two official statements")
for s in sts:
    check(bool(hex64.match(s["template_hash_hex"])), f'{s["unit_kind"]} template hash is 64-hex')
sys.exit(0 if ok else 1)
PY

exit "$fail"

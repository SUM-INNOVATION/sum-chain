#!/usr/bin/env bash
# Provider-neutral GENUINE fixture generator (docs/b0-pre/venue/VENUE.md §3.4): PROVE a
# frozen candidate guest with the pinned prover toolchain INSIDE the pinned container to
# produce a genuine SP1/RISC Zero terminal proof/receipt fixture, then hand its path to
# the Stage-5 mutation harness (verifier_fixtures.sh).
#
# STATUS: the command path + fail-closed contracts are IMPLEMENTED; the in-container
# proving is VENUE-UNEXECUTED. The candidate guests now carry OFFICIAL guest SOURCE
# (candidates/<cand>/guest/src/main.rs routing through b0-pre-guest-core), so the
# OFFICIAL-GUEST gate below locates/builds the real guest rather than a placeholder
# marker. Generation still fails closed everywhere off-venue: it requires the pinned
# prover toolchain, the pinned container (VERIFIER_REF), a native builder, and the
# bound tool identity — none of which exist off-venue. The guest SOURCE is official,
# but the guest has NOT been reproduced at a venue (no Cargo.lock / program id /
# receipt / measured cost exists), so any fixture it eventually proves is STILL
# self-labeled NON_SELECTION / NOT_AN_OFFICIAL_GUEST (four stamps): no venue-built
# guest identity or allowlist enters the normative artifact. NOTHING here fabricates a
# canned/synthetic proof: no genuine fixture is produced until a real venue proves the
# real frozen guest.
#
# Usage: prove_fixture.sh <sp1|risc0> <arch> <out_fixture.json>
#   env: VERIFIER_REF  pinned builder image the prover toolchain runs INSIDE
#        CMD_LOG       command-log file the exact in-container prove commands append to
#        SCHEMA_ARCH   X86_64 | Aarch64
#        TOOL_BINDING  path to the BOUND prover tool identity (<Cand>.tool-binding.json);
#                      the pinned prover is installed from this verified identity, never
#                      an invented URL/checksum (a version string alone is not evidence)
#   optional env: PROVER_GUEST_INPUT  path to the frozen guest's fixed input bytes
#
# Emits <out_fixture.json>: {stamp:[4 non-selection stamps], candidate, + the genuine
# proof/receipt fields the mutation runner consumes}. The four stamps mark the guest
# NON-SELECTION so it can never be mistaken for official evidence. Fail closed on any
# absent toolchain / guest / material; never substitutes synthetic evidence.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

REQUIRED_STAMPS='["TEST_ONLY","NON_SELECTION","INVALID_FOR_R0","NOT_AN_OFFICIAL_GUEST"]'

CAND_LC="${1:-}"
ARCH="${2:-}"
OUT_FIXTURE="${3:-}"
case "$CAND_LC" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${CAND_LC:-}')" ;; esac
case "$ARCH" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64 (got '${ARCH:-}')" ;; esac
[ -n "$OUT_FIXTURE" ] || die "output fixture path argument required"

[ -n "${VERIFIER_REF:-}" ] || die "VERIFIER_REF (pinned image the prover runs inside) is required"
[ -n "${CMD_LOG:-}" ]     || die "CMD_LOG (command-log file to bind the run to) is required"
[ -n "${SCHEMA_ARCH:-}" ] || die "SCHEMA_ARCH (X86_64|Aarch64) is required"
case "$SCHEMA_ARCH" in X86_64|Aarch64) ;; *) die "SCHEMA_ARCH must be X86_64|Aarch64 (got '$SCHEMA_ARCH')" ;; esac

# CLASSIFICATION SEPARATION: genuine proving must never run in the off-venue dry-run
# (TEST_ONLY) mode — no synthetic proof can enter the authoritative path.
if is_dryrun; then
  die "fixture generation must not run in SUMCHAIN_B0PRE_DRYRUN (TEST_ONLY) mode; synthetic proofs can never reach authoritative Stage-5 ingestion"
fi

# ARCHITECTURE RULE (docs/b0-pre/venue/VENUE.md §2): RISC Zero proving is native x86_64 only.
if [ "$CAND_LC" = "risc0" ]; then
  [ "$SCHEMA_ARCH" = "X86_64" ] || die "RISC Zero proving is x86_64-only (docs/b0-pre/venue/VENUE.md §2); refused for $SCHEMA_ARCH"
  require_native_arch x86_64
fi

# OFFICIAL-GUEST gate (deterministic, before any tool/container work): a genuine
# fixture can only be PROVED from the frozen OFFICIAL guest SOURCE — the zkVM
# entrypoint that routes through the candidate-neutral b0-pre-guest-core. This is a
# POSITIVE locate-the-official-guest check (not a placeholder-marker absence check):
# refuse a candidate that has no official entrypoint, or one that does not go through
# the shared core, rather than fabricate. It does NOT weaken fail-closed: proving still
# requires the pinned toolchain / container / native builder / bound tool identity
# (asserted below), all absent off-venue.
local_guest="$ROOT/candidates/$CAND_LC/guest"
[ -d "$local_guest" ] || nyr "candidate $CAND_LC guest crate not found at $local_guest"
[ -f "$local_guest/src/main.rs" ] \
  || nyr "candidate $CAND_LC has no official guest entrypoint ($local_guest/src/main.rs); a genuine fixture requires the frozen official guest source"
[ -f "$local_guest/src/lib.rs" ] \
  && die "candidate $CAND_LC guest still carries a placeholder src/lib.rs; the official guest is a src/main.rs entrypoint"
grep -q 'b0_pre_guest_core::run' "$local_guest/src/main.rs" \
  || die "candidate $CAND_LC guest entrypoint does not route through the official b0-pre-guest-core::run; refusing to prove a non-official guest"
# VENUE PACKAGING (IMPLEMENTED; the guest ELF build/prove stays VENUE-UNEXECUTED): the
# official guest depends on the shared `b0-pre-guest-core`, which adopts the frozen
# `sumchain-wire::b0` wire types directly. The builder image now BAKES IN the curated
# staged guest graph (scripts/stage_context.sh): the candidate workspace, `guest-core`,
# and `sumchain-wire` sit at their reproduced repo-relative paths under /work, so the
# path deps (`../../../guest-core`, `../../../crates/sumchain-wire`) and sumchain-wire's
# `.workspace` inheritance resolve. The in-container build below therefore runs from the
# candidate's staged path (`$(incontainer_candidate_dir <cand>)/guest`). Off-venue there
# is no pinned toolchain / container / native builder, so proving still fails closed (a
# missing toolchain is a hard error, never a synthetic proof).
CAND_DIR="$(incontainer_candidate_dir "$CAND_LC")"

# Required host commands + the BOUND pinned prover identity.
require_cmd docker
require_cmd python3
require_cmd b3sum
[ -n "${TOOL_BINDING:-}" ] || nyr "TOOL_BINDING (path to the bound prover tool identity <Cand>.tool-binding.json) is required to install the pinned prover"
[ -f "$TOOL_BINDING" ]     || nyr "TOOL_BINDING points to '$TOOL_BINDING', which is not a readable file"

OUT_DIR="$(cd "$(dirname "$OUT_FIXTURE")" && pwd)"
FIXTURE_NAME="$(basename "$OUT_FIXTURE")"

# ---- materialize the pinned GENUINE prover-runner (venue-confirmed, VENUE-UNEXECUTED)
# Pinned to the candidate's exact prover SDK. It PROVES the built frozen-guest ELF to a
# genuine Groth16 proof/receipt and serializes ONLY that genuine output + the four
# non-selection stamps into the fixture the mutation runner consumes. No outcome is
# fabricated; a build/prove failure exits non-zero (fail closed).
PROVER="$OUT_DIR/_prover"
rm -rf "$PROVER"
mkdir -p "$PROVER/src"

if [ "$CAND_LC" = "sp1" ]; then
  cat > "$PROVER/Cargo.toml" <<'TOML'
[package]
name = "b0-pre-sp1-prove-runner"
version = "0.0.0"
edition = "2021"
publish = false
license = "MIT OR Apache-2.0"

# Pinned to the SP1 6.3.1 prover SDK. Proving is genuine; nothing is canned. Runs only
# on the pinned container venue. Cargo.lock is generated IN-CONTAINER and bound.
[dependencies]
sp1-sdk = "=6.3.1"
serde_json = "=1.0.149"
TOML
  cat > "$PROVER/src/main.rs" <<'RUST'
//! Genuine SP1 6.3.1 Groth16 prover-runner (venue-only, VENUE-UNEXECUTED).
//!
//! Args: <guest_elf_path> <out_fixture.json> [guest_input_path]. Proves the FROZEN
//! guest ELF to a genuine Groth16 proof and serializes proof/public-values/vkey-hash
//! (the exact shape the SP1 mutation runner consumes) plus the four NON-SELECTION
//! stamps. SDK symbols are venue-confirmed (the crate is present there); a wrong
//! detail fails the build/prove and exits non-zero — never a canned proof.
use std::fs;
use std::process::ExitCode;

use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let elf_path = args.get(1).ok_or("usage: prove-runner <guest_elf> <out_fixture> [input]")?;
    let out = args.get(2).ok_or("usage: prove-runner <guest_elf> <out_fixture> [input]")?;
    let elf = fs::read(elf_path).map_err(|e| format!("read guest elf: {e}"))?;
    if elf.is_empty() {
        return Err("INELIGIBLE: empty guest ELF (frozen guest did not build)".into());
    }
    let mut stdin = SP1Stdin::new();
    if let Some(input_path) = args.get(3) {
        // The frozen guest-input envelope bytes; the official guest reads them
        // back with `sp1_zkvm::io::read::<Vec<u8>>()`.
        let bytes = fs::read(input_path).map_err(|e| format!("read guest input: {e}"))?;
        stdin.write(&bytes);
    }

    // Genuine proving: setup the verifying key from the ELF, prove Groth16.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(&elf);
    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .map_err(|e| format!("INELIGIBLE: genuine SP1 Groth16 proving failed: {e}"))?;

    let fixture = serde_json::json!({
        "stamp": ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0", "NOT_AN_OFFICIAL_GUEST"],
        "candidate": "Sp1",
        "proof_hex": hex(&proof.bytes()),
        "public_values_hex": hex(proof.public_values.as_slice()),
        "vkey_hash": vk.bytes32(),
        "note": "genuine SP1 6.3.1 Groth16 proof of a frozen NON-OFFICIAL guest; \
                 venue-produced. Guest identity never enters the normative artifact.",
    });
    fs::write(out, serde_json::to_string_pretty(&fixture).map_err(|e| e.to_string())?)
        .map_err(|e| format!("write fixture: {e}"))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
RUST
  # The frozen SP1 guest ELF is built with the pinned SP1 guest toolchain (cargo-prove
  # installed from the bound tool identity), then proved by the runner. Built from the
  # staged candidate path so the guest-core/sumchain-wire path deps resolve.
  BUILD_GUEST="cd $CAND_DIR/guest && cargo prove build --output-directory /out/guest --elf-name guest.elf"
  ELF_PATH="/out/guest/guest.elf"
else
  cat > "$PROVER/Cargo.toml" <<'TOML'
[package]
name = "b0-pre-risc0-prove-runner"
version = "0.0.0"
edition = "2021"
publish = false
license = "MIT OR Apache-2.0"

# Pinned to RISC Zero 3.0.5. Proving is genuine; nothing is canned. Runs only on a
# native x86_64 container venue. Cargo.lock is generated IN-CONTAINER and bound.
[dependencies]
risc0-zkvm = "=3.0.5"
serde_json = "=1.0.149"
bincode = "=1.3.3"
TOML
  cat > "$PROVER/src/main.rs" <<'RUST'
//! Genuine RISC Zero 3.0.5 Groth16 prover-runner (venue-only, native x86_64,
//! VENUE-UNEXECUTED).
//!
//! Args: <guest_elf_path> <out_fixture.json> [guest_input_path]. Proves the FROZEN
//! guest ELF to a genuine Groth16 receipt and serializes receipt/image-id (the exact
//! shape the RISC Zero mutation runner consumes) plus the four NON-SELECTION stamps.
//! Symbols/codec are venue-confirmed; a wrong detail fails the build/prove and exits
//! non-zero — never a canned receipt.
use std::fs;
use std::process::ExitCode;

use risc0_zkvm::{compute_image_id, default_prover, ExecutorEnv, ProverOpts};

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let elf_path = args.get(1).ok_or("usage: prove-runner <guest_elf> <out_fixture> [input]")?;
    let out = args.get(2).ok_or("usage: prove-runner <guest_elf> <out_fixture> [input]")?;
    let elf = fs::read(elf_path).map_err(|e| format!("read guest elf: {e}"))?;
    if elf.is_empty() {
        return Err("INELIGIBLE: empty guest ELF (frozen guest did not build)".into());
    }
    let mut builder = ExecutorEnv::builder();
    if let Some(input_path) = args.get(3) {
        // The frozen guest-input envelope bytes; the official guest reads them
        // back with `risc0_zkvm::guest::env::read::<Vec<u8>>()`.
        let bytes = fs::read(input_path).map_err(|e| format!("read guest input: {e}"))?;
        builder
            .write(&bytes)
            .map_err(|e| format!("write guest input: {e}"))?;
    }
    let env = builder.build().map_err(|e| format!("executor env: {e}"))?;

    // Genuine Groth16 proving of the frozen guest.
    let receipt = default_prover()
        .prove_with_opts(env, &elf, &ProverOpts::groth16())
        .map_err(|e| format!("INELIGIBLE: genuine RISC Zero Groth16 proving failed: {e}"))?
        .receipt;
    let image_id = compute_image_id(&elf).map_err(|e| format!("compute image id: {e}"))?;
    let receipt_hex = hex(&bincode::serialize(&receipt).map_err(|e| format!("serialize receipt: {e}"))?);

    let fixture = serde_json::json!({
        "stamp": ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0", "NOT_AN_OFFICIAL_GUEST"],
        "candidate": "Risc0",
        "receipt_hex": receipt_hex,
        "image_id": hex(image_id.as_bytes()),
        "note": "genuine RISC Zero 3.0.5 Groth16 receipt of a frozen NON-OFFICIAL guest; \
                 venue-produced. Guest identity never enters the normative artifact.",
    });
    fs::write(out, serde_json::to_string_pretty(&fixture).map_err(|e| e.to_string())?)
        .map_err(|e| format!("write fixture: {e}"))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
RUST
  # Built from the staged candidate path so the guest-core/sumchain-wire path deps resolve.
  BUILD_GUEST="cd $CAND_DIR/guest && cargo risczero build --output /out/guest/guest.elf"
  ELF_PATH="/out/guest/guest.elf"
fi

INPUT_ARG=""
INPUT_MOUNT=""
if [ -n "${PROVER_GUEST_INPUT:-}" ]; then
  [ -f "$PROVER_GUEST_INPUT" ] || die "PROVER_GUEST_INPUT '$PROVER_GUEST_INPUT' is not a readable file"
  local_input_abs="$(cd "$(dirname "$PROVER_GUEST_INPUT")" && pwd)/$(basename "$PROVER_GUEST_INPUT")"
  INPUT_MOUNT="-v $local_input_abs:/guest-input.bin:ro"
  INPUT_ARG="/guest-input.bin"
fi

# ---- PHASE A: generate the prover-runner lock IN-CONTAINER, then BIND it -----------
GEN_CMD="docker run --rm --pull never -v $OUT_DIR:/out -e CARGO_TARGET_DIR=/tmp/b0pre-prove-target $VERIFIER_REF bash -lc 'cd /out/_prover && cargo generate-lockfile'"
{
  printf '# Stage-5 GENUINE fixture generation (prove frozen %s guest) inside %s\n' "$CAND_LC" "$VERIFIER_REF"
  printf '# pinned prover installed from bound tool identity %s\n' "$TOOL_BINDING"
  printf '%s\n' "$GEN_CMD"
} >> "$CMD_LOG"
docker run --rm --pull never \
  -v "$OUT_DIR:/out" \
  -e CARGO_TARGET_DIR=/tmp/b0pre-prove-target \
  "$VERIFIER_REF" \
  bash -lc 'cd /out/_prover && cargo generate-lockfile' \
  || die "in-container 'cargo generate-lockfile' failed for the $CAND_LC prover-runner (no unlocked build is attempted)"
[ -s "$OUT_DIR/_prover/Cargo.lock" ] || die "prover-runner Cargo.lock was not generated in-container for $CAND_LC"
cp "$OUT_DIR/_prover/Cargo.lock" "$OUT_DIR/prover-runner-cargo.lock"
PROVER_LOCK_B3="$(blake3_hex_file "$OUT_DIR/prover-runner-cargo.lock")"
printf 'prove-runner-cargo-lock\tprover-runner-cargo.lock\tblake3:%s\n' "$PROVER_LOCK_B3" >> "$CMD_LOG"

# ---- PHASE B: build the frozen guest ELF + PROVE it, emit the stamped fixture ------
mkdir -p "$OUT_DIR/guest"
RUN_CMD="docker run --rm --pull never -v $OUT_DIR:/out $INPUT_MOUNT -e CARGO_TARGET_DIR=/tmp/b0pre-prove-target $VERIFIER_REF bash -lc '$BUILD_GUEST && cd /out/_prover && cargo run --quiet --release --locked -- $ELF_PATH /out/$FIXTURE_NAME $INPUT_ARG'"
printf '%s\n' "$RUN_CMD" >> "$CMD_LOG"
# shellcheck disable=SC2086  # INPUT_MOUNT intentionally expands to 0-or-2 docker args
docker run --rm --pull never \
  -v "$OUT_DIR:/out" \
  $INPUT_MOUNT \
  -e CARGO_TARGET_DIR=/tmp/b0pre-prove-target \
  "$VERIFIER_REF" \
  bash -lc "$BUILD_GUEST && cd /out/_prover && cargo run --quiet --release --locked -- $ELF_PATH /out/$FIXTURE_NAME $INPUT_ARG" \
  || die "genuine in-container $CAND_LC guest build + Groth16 proving failed closed (toolchain absent, guest not built, or proving did not reproduce)"

# The genuine fixture must exist, be non-empty, and carry the four NON-SELECTION stamps
# + the candidate-specific proof/receipt fields — else fail closed (never accept a
# malformed or unstamped generated fixture).
[ -s "$OUT_FIXTURE" ] || die "prover did not emit a genuine $CAND_LC fixture at $OUT_FIXTURE"
python3 - "$OUT_FIXTURE" "$REQUIRED_STAMPS" "$CAND_LC" <<'PY' || die "generated $CAND_LC fixture is malformed, unstamped, or missing required proof/receipt fields"
import json, sys
path, required, cand = sys.argv[1], set(json.loads(sys.argv[2])), sys.argv[3]
try:
    doc = json.load(open(path))
except Exception as e:
    sys.exit(f"generated fixture is not valid JSON: {e}")
missing = required - set(doc.get("stamp") or [])
if missing:
    sys.exit(f"generated fixture missing non-selection stamps: {sorted(missing)}")
need = ["proof_hex", "public_values_hex", "vkey_hash"] if cand == "sp1" else ["receipt_hex", "image_id"]
absent = [k for k in need if not doc.get(k)]
if absent:
    sys.exit(f"generated fixture missing required fields: {absent}")
PY

note "genuine $CAND_LC fixture PROVED and validated -> $OUT_FIXTURE (lock blake3:$PROVER_LOCK_B3)"

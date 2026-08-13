#!/usr/bin/env bash
# Provider-neutral GENUINE fixture generator (docs/b0-pre/venue/VENUE.md §3.4): PROVE a
# frozen candidate guest to a genuine SP1/RISC Zero terminal Groth16 proof/receipt, then
# hand its path to the Stage-5 mutation harness (verifier_fixtures.sh).
#
# EXECUTION MODEL (venue-confirmed): the terminal Groth16 backend is a `docker run` the
# pinned SDK invokes ITSELF (sp1-gnark prove+verify / risc0 stark2snark). Those calls run
# UNDER THE DOCKER INVOCATION FIREWALL (docker_firewall.sh) — installed as `docker` on a
# dedicated PATH dir for the prover subprocess only — which replaces the SDK image with the
# immutable v4 digest, reconciles OCI identity, injects the full sandbox (--network none,
# --read-only, --cap-drop ALL, no-new-privileges, tmpfs), mounts the pinned circuit
# read-only + an isolated writable per-proof output, hashes inputs before/after, records an
# execution attestation (incl. ownership/modes of the ephemeral world-accessible copies), and
# refuses everything else. The prover therefore runs HOST-SIDE (not docker-in-docker):
#   * SP1   — the guest ELF is built IN the pinned candidate container (`cargo prove build`);
#             the host prover (sp1-sdk 6.3.1 blocking) reads that ELF, proves + self-verifies.
#   * RISC0 — the guest is built HOST-SIDE by `risc0_build::embed_methods()` (owner decision
#             B: pinned local r0.1.91.1 toolchain via an isolated RISC0_HOME; NO cargo-risczero
#             CLI, NO risc0-guest-builder image, NO rzup/network/inherited ~/.risc0). The host
#             prover (risc0-zkvm 3.0.5, default ExternalProver -> the pinned r0vm 3.0.5) proves
#             + self-verifies; r0vm makes the ONE stark2snark docker call the firewall intercepts.
#
# Nothing here fabricates a canned/synthetic proof: generation fails closed everywhere off
# the provisioned venue (missing pinned toolchain / container / firewall / backend / circuit
# / bound tool identity). Any proved fixture stays self-labeled NON_SELECTION /
# NOT_AN_OFFICIAL_GUEST (four stamps): no venue-built guest identity enters the normative
# artifact.
#
# Usage: prove_fixture.sh <sp1|risc0> <arch> <out_fixture.json>
#   env: VERIFIER_REF   pinned candidate builder image (SP1 guest ELF is built INSIDE it)
#        CMD_LOG        command-log file the exact prove commands + lineage bindings append to
#        SCHEMA_ARCH    X86_64 | Aarch64
#        TOOL_BINDING   path to the BOUND prover tool identity (<Cand>.tool-binding.json),
#                       RECORDED as upstream proof-tool provenance (NOT claimed causal; this
#                       fixture is NON_SELECTION and never enters the authoritative bundle).
#   proving-env (provisioned once; all mandatory for the eligible candidate):
#        PROVER_REAL_DOCKER      absolute path to the REAL docker (default: resolved via PATH)
#        PROVER_FIREWALL_SH      docker_firewall.sh (default: alongside this script)
#     SP1:
#        PROVER_SP1_CONTENT_STORE  digest-addressed store holding the pinned gnark circuit
#        PROVER_SP1_CIRCUIT_VERSION  circuit version dir under ~/.sp1/circuits/groth16 (def v6.1.0)
#     RISC0:
#        PROVER_R0VM_DIR         dir containing the pinned r0vm 3.0.5 (prepended to PATH)
#        PROVER_RISC0_HOME       isolated RISC0_HOME with the pinned r0.1.91.1 guest toolchain
#   optional env: PROVER_GUEST_INPUT  path to the frozen guest-input envelope bytes
#
# Emits <out_fixture.json>: {stamp:[4 non-selection stamps], candidate, + the genuine
# proof/receipt fields the mutation runner consumes}. Fail closed on any absent
# toolchain / guest / backend / circuit / material; never substitutes synthetic evidence.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

REQUIRED_STAMPS='["TEST_ONLY","NON_SELECTION","INVALID_FOR_R0","NOT_AN_OFFICIAL_GUEST"]'

CAND_LC="${1:-}"
ARCH="${2:-}"
OUT_FIXTURE="${3:-}"
case "$CAND_LC" in sp1|risc0) ;; *) die "candidate must be sp1|risc0 (got '${CAND_LC:-}')" ;; esac
case "$ARCH" in x86_64|aarch64) ;; *) die "arch must be x86_64|aarch64 (got '${ARCH:-}')" ;; esac
[ -n "$OUT_FIXTURE" ] || die "output fixture path argument required"

[ -n "${VERIFIER_REF:-}" ] || die "VERIFIER_REF (pinned image the SP1 guest ELF builds inside) is required"
[ -n "${CMD_LOG:-}" ]     || die "CMD_LOG (command-log file to bind the run to) is required"
[ -n "${SCHEMA_ARCH:-}" ] || die "SCHEMA_ARCH (X86_64|Aarch64) is required"
case "$SCHEMA_ARCH" in X86_64|Aarch64) ;; *) die "SCHEMA_ARCH must be X86_64|Aarch64 (got '$SCHEMA_ARCH')" ;; esac

# CLASSIFICATION SEPARATION: genuine proving must never run in the off-venue dry-run
# (TEST_ONLY) mode — no synthetic proof can enter the authoritative path.
if is_dryrun; then
  die "fixture generation must not run in SUMCHAIN_B0PRE_DRYRUN (TEST_ONLY) mode; synthetic proofs can never reach authoritative Stage-5 ingestion"
fi

# ARCHITECTURE RULE (docs/b0-pre/venue/VENUE.md §2): terminal Groth16 production is native
# x86_64 only — the sp1-gnark backend publishes NO linux/arm64 manifest and RISC Zero proving
# is x86_64-only. ARM stays eligible for compile/identity/verify, NEVER terminal Groth16.
[ "$SCHEMA_ARCH" = "X86_64" ] || die "terminal Groth16 production is x86_64-only (VENUE.md §2); refused for $SCHEMA_ARCH — ARM supports compile/identity/verify only"
require_native_arch x86_64

# OFFICIAL-GUEST gate (deterministic, before any tool/container/prover work): a genuine
# fixture can only be PROVED from the frozen OFFICIAL guest SOURCE — the zkVM entrypoint that
# routes through the candidate-neutral b0-pre-guest-core. POSITIVE locate-the-official-guest
# check; refuse a candidate with no official entrypoint (never fabricate).
local_guest="$ROOT/candidates/$CAND_LC/guest"
[ -d "$local_guest" ] || nyr "candidate $CAND_LC guest crate not found at $local_guest"
[ -f "$local_guest/src/main.rs" ] \
  || nyr "candidate $CAND_LC has no official guest entrypoint ($local_guest/src/main.rs); a genuine fixture requires the frozen official guest source"
[ -f "$local_guest/src/lib.rs" ] \
  && die "candidate $CAND_LC guest still carries a placeholder src/lib.rs; the official guest is a src/main.rs entrypoint"
grep -q 'b0_pre_guest_core::run' "$local_guest/src/main.rs" \
  || die "candidate $CAND_LC guest entrypoint does not route through the official b0-pre-guest-core::run; refusing to prove a non-official guest"

# Required host commands + the BOUND pinned prover identity + host cargo.
require_cmd docker
require_cmd python3
require_cmd b3sum
HOST_CARGO="${CARGO:-$(command -v cargo 2>/dev/null || true)}"
[ -n "$HOST_CARGO" ] && [ -x "$HOST_CARGO" ] || die "host cargo is required to build the host-side prover (not found on PATH)"
[ -n "${TOOL_BINDING:-}" ] || nyr "TOOL_BINDING (path to the bound prover tool identity <Cand>.tool-binding.json) is required as recorded upstream proof-tool provenance (NOT claimed to install/cause the proof; this fixture is NON_SELECTION)"
[ -f "$TOOL_BINDING" ]     || nyr "TOOL_BINDING points to '$TOOL_BINDING', which is not a readable file"

OUT_DIR="$(cd "$(dirname "$OUT_FIXTURE")" && pwd)"
FIXTURE_NAME="$(basename "$OUT_FIXTURE")"
case "$CAND_LC" in sp1) CAND=Sp1 ;; risc0) CAND=Risc0 ;; esac

# ============================================================================================
# PROVING ENVIRONMENT — the Docker invocation FIREWALL + isolated per-proof roots.
# ============================================================================================
FIREWALL_SH="${PROVER_FIREWALL_SH:-$HERE/docker_firewall.sh}"
[ -f "$FIREWALL_SH" ] || die "the Docker invocation firewall ($FIREWALL_SH) is required; genuine proving runs the terminal backend under it"
REAL_DOCKER="${PROVER_REAL_DOCKER:-$(command -v docker 2>/dev/null || true)}"
REAL_DOCKER="$(readlink -f "$REAL_DOCKER" 2>/dev/null || echo "$REAL_DOCKER")"
[ -n "$REAL_DOCKER" ] && [ -x "$REAL_DOCKER" ] || die "the REAL docker binary was not found/executable (set PROVER_REAL_DOCKER): '$REAL_DOCKER'"
case "$REAL_DOCKER" in /*) ;; *) die "PROVER_REAL_DOCKER must be an absolute path: $REAL_DOCKER" ;; esac

# Install the firewall as `docker` on a dedicated dir prepended to PATH for the prover only.
FWDIR="$OUT_DIR/_fw"; rm -rf "$FWDIR"; mkdir -p "$FWDIR"
cp "$FIREWALL_SH" "$FWDIR/docker"; chmod 0755 "$FWDIR/docker"
[ "$(readlink -f "$FWDIR/docker")" != "$REAL_DOCKER" ] || die "firewall recursion: installed docker resolves to the real docker"

# Fresh per-proof root (the ONLY writable-output root the firewall permits) + attestation.
PROOF_DIR="$OUT_DIR/_proof"; rm -rf "$PROOF_DIR"; mkdir -p "$PROOF_DIR"
FW_ATTEST="$OUT_DIR/$CAND.firewall-attestation.jsonl"; : > "$FW_ATTEST"
FW_DIAG="$OUT_DIR/_fwdiag"; rm -rf "$FW_DIAG"; mkdir -p "$FW_DIAG"

# Candidate-specific backend provisioning (fail closed if the pinned inputs are absent).
if [ "$CAND_LC" = "sp1" ]; then
  CSTORE="${PROVER_SP1_CONTENT_STORE:-}"
  [ -n "$CSTORE" ] && [ -d "$CSTORE" ] || die "PROVER_SP1_CONTENT_STORE (digest-addressed store holding the pinned gnark circuit) is required for SP1: '${CSTORE:-<unset>}'"
  CSTORE_CANON="$(readlink -f "$CSTORE")"
  CIRC_VER="${PROVER_SP1_CIRCUIT_VERSION:-v6.1.0}"
  CIRC_LINK="$HOME/.sp1/circuits/groth16/$CIRC_VER"
  [ -e "$CIRC_LINK" ] || die "SP1 gnark circuit is not provisioned at $CIRC_LINK (the SDK reads it here; it must resolve into the content store)"
  CIRC_CANON="$(readlink -f "$CIRC_LINK")"
  case "$CIRC_CANON/" in "$CSTORE_CANON"/*) ;; *) die "SP1 circuit $CIRC_LINK resolves to $CIRC_CANON, NOT under the content store $CSTORE_CANON; the firewall would refuse it" ;; esac
  note "SP1 pinned circuit $CIRC_VER resolves under the content store: $CIRC_CANON"
else
  R0VM_DIR="${PROVER_R0VM_DIR:-}"
  [ -n "$R0VM_DIR" ] && [ -x "$R0VM_DIR/r0vm" ] || die "PROVER_R0VM_DIR (dir with the pinned r0vm 3.0.5, the causal RISC Zero prover) is required: '${R0VM_DIR:-<unset>}'"
  RISC0_HOME_HOST="${PROVER_RISC0_HOME:-}"
  [ -n "$RISC0_HOME_HOST" ] && [ -f "$RISC0_HOME_HOST/settings.toml" ] || die "PROVER_RISC0_HOME (isolated home with the pinned r0.1.91.1 guest toolchain) is required: '${RISC0_HOME_HOST:-<unset>}'"
  R0VM_VER="$("$R0VM_DIR/r0vm" --version 2>/dev/null | head -1 || true)"
  note "RISC Zero pinned backend: $R0VM_VER ; isolated RISC0_HOME=$RISC0_HOME_HOST"
fi

# Optional frozen guest-input envelope (the official guest reads it as raw bytes).
INPUT_ABS=""
if [ -n "${PROVER_GUEST_INPUT:-}" ]; then
  [ -f "$PROVER_GUEST_INPUT" ] || die "PROVER_GUEST_INPUT '$PROVER_GUEST_INPUT' is not a readable file"
  INPUT_ABS="$(cd "$(dirname "$PROVER_GUEST_INPUT")" && pwd)/$(basename "$PROVER_GUEST_INPUT")"
fi

# ============================================================================================
# GUEST BUILD.
#   SP1   — build the frozen guest ELF INSIDE the pinned candidate container (cargo prove build).
#   RISC0 — stage the guest graph HOST-SIDE (outside the repo, reproduced layout) so
#           embed_methods can build it --locked at host prover-build time without dirtying the tree.
# ============================================================================================
mkdir -p "$OUT_DIR/guest"
CAND_DIR_INCONTAINER="$(incontainer_candidate_dir "$CAND_LC")"

if [ "$CAND_LC" = "sp1" ]; then
  ELF_HOST="$OUT_DIR/guest/guest.elf"
  BUILD_GUEST_CMD="docker run --rm --pull never -v $OUT_DIR:/out -e CARGO_TARGET_DIR=/tmp/b0pre-guest-target $VERIFIER_REF bash -c 'cd $CAND_DIR_INCONTAINER/guest && cargo prove build --output-directory /out/guest --elf-name guest.elf'"
  {
    printf '# Stage-5 GENUINE fixture: build frozen SP1 guest ELF inside %s\n' "$VERIFIER_REF"
    printf '# upstream proof-tool provenance recorded (NOT causal; NON_SELECTION): %s\n' "$TOOL_BINDING"
    printf '%s\n' "$BUILD_GUEST_CMD"
  } >> "$CMD_LOG"
  docker run --rm --pull never \
    -v "$OUT_DIR:/out" \
    -e CARGO_TARGET_DIR=/tmp/b0pre-guest-target \
    "$VERIFIER_REF" \
    bash -c "cd $CAND_DIR_INCONTAINER/guest && cargo prove build --output-directory /out/guest --elf-name guest.elf" \
    || die "in-container SP1 guest ELF build failed (pinned succinct toolchain absent, or guest did not build); no synthetic ELF is substituted"
  [ -s "$ELF_HOST" ] || die "SP1 guest ELF was not produced at $ELF_HOST"
  ELF_B3="$(blake3_hex_file "$ELF_HOST")"
  printf 'sp1-guest-elf\tguest/guest.elf\tblake3:%s\n' "$ELF_B3" >> "$CMD_LOG"
  note "SP1 frozen guest ELF built in-container (blake3:$ELF_B3, $(wc -c <"$ELF_HOST") bytes)"
else
  GSTAGE="$OUT_DIR/_gstage"; rm -rf "$GSTAGE"
  bash "$HERE/stage_context.sh" risc0 "$GSTAGE" >/dev/null \
    || die "host-side staging of the RISC Zero guest graph failed"
  GUEST_STAGED="$GSTAGE/tools/b0-pre-candidates/candidates/risc0/guest"
  [ -f "$GUEST_STAGED/src/main.rs" ] || die "staged RISC Zero guest not found at $GUEST_STAGED"
  # Generate + bind the guest's own Cargo.lock (embed_methods builds it --locked). The staged
  # candidate workspace root receives the lock; it lives OUTSIDE the repo (clean-tree safe).
  ( cd "$GUEST_STAGED" && RISC0_HOME="$RISC0_HOME_HOST" "$HOST_CARGO" generate-lockfile ) \
    || die "host 'cargo generate-lockfile' failed for the staged RISC Zero guest (staged path deps / pinned deps unresolved)"
  GUEST_LOCK="$GSTAGE/tools/b0-pre-candidates/candidates/risc0/Cargo.lock"
  [ -s "$GUEST_LOCK" ] || GUEST_LOCK="$GUEST_STAGED/Cargo.lock"
  [ -s "$GUEST_LOCK" ] || die "staged RISC Zero guest Cargo.lock was not generated"
  cp "$GUEST_LOCK" "$OUT_DIR/risc0-guest-cargo.lock"
  GUEST_LOCK_B3="$(blake3_hex_file "$OUT_DIR/risc0-guest-cargo.lock")"
  printf 'risc0-guest-cargo-lock\trisc0-guest-cargo.lock\tblake3:%s\n' "$GUEST_LOCK_B3" >> "$CMD_LOG"
  note "RISC Zero guest graph staged host-side; guest lock bound (blake3:$GUEST_LOCK_B3)"
fi

# ============================================================================================
# HOST-SIDE PROVER-RUNNER — pinned to the candidate's exact prover SDK. PROVES the frozen
# guest to a genuine Groth16 proof/receipt, SELF-VERIFIES, and serializes ONLY that genuine
# output + the four non-selection stamps. A build/prove/verify failure exits non-zero.
# ============================================================================================
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

# Pinned to the SP1 6.3.1 prover SDK. Proving is genuine; nothing is canned. The gnark
# Groth16 backend `docker run` is intercepted by the firewall. Cargo.lock is generated +
# bound below. The `blocking` feature exposes the synchronous 6.3.1 prover API this runner uses.
[dependencies]
sp1-sdk = { version = "=6.3.1", features = ["blocking"] }
serde_json = "=1.0.149"

[workspace]
TOML
  cat > "$PROVER/src/main.rs" <<'RUST'
//! Genuine SP1 6.3.1 Groth16 prover-runner (venue, native x86_64, host-side under the firewall).
//!
//! Args: <guest_elf_path> <out_fixture.json> [guest_input_path]. Proves the FROZEN guest ELF to
//! a genuine Groth16 proof, SELF-VERIFIES it, and serializes proof/public-values/vkey-hash (the
//! exact shape the SP1 mutation runner consumes) plus the four NON-SELECTION stamps.
//!
//! Written against the EXACT pinned SP1 6.3.1 blocking API: `setup(elf) -> pk`,
//! `pk.verifying_key()`, `prove(&pk, stdin).groth16().run()`, `verify(&proof, vk, None)`. A wrong
//! detail fails the build/prove/verify and exits non-zero — never a canned proof.
use std::fs;
use std::process::ExitCode;
use std::sync::Arc;

use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{HashableKey, ProvingKey};

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
    let elf_bytes = fs::read(elf_path).map_err(|e| format!("read guest elf: {e}"))?;
    if elf_bytes.is_empty() {
        return Err("INELIGIBLE: empty guest ELF (frozen guest did not build)".into());
    }
    let elf = Elf::Dynamic(Arc::from(elf_bytes.into_boxed_slice()));

    let prover = ProverClient::from_env();
    let pk = prover.setup(elf).map_err(|e| format!("INELIGIBLE: SP1 setup failed: {e}"))?;
    let vkey_hash = pk.verifying_key().bytes32();

    let mut stdin = SP1Stdin::new();
    if let Some(input_path) = args.get(3) {
        let bytes = fs::read(input_path).map_err(|e| format!("read guest input: {e}"))?;
        stdin.write(&bytes);
    }

    // Genuine proving of the frozen guest, then SELF-VERIFY (causal check before emit).
    let proof = prover
        .prove(&pk, stdin)
        .groth16()
        .run()
        .map_err(|e| format!("INELIGIBLE: genuine SP1 Groth16 proving failed: {e}"))?;
    prover
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| format!("INELIGIBLE: genuine SP1 Groth16 proof failed self-verification: {e}"))?;

    let fixture = serde_json::json!({
        "stamp": ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0", "NOT_AN_OFFICIAL_GUEST"],
        "candidate": "Sp1",
        "proof_hex": hex(&proof.bytes()),
        "public_values_hex": hex(proof.public_values.as_slice()),
        "vkey_hash": vkey_hash,
        "note": "genuine SP1 6.3.1 Groth16 proof of a frozen NON-OFFICIAL guest; venue-produced \
                 under the Docker firewall + self-verified. Guest identity never enters the normative artifact.",
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
  PROVER_ARGS=("$ELF_HOST" "$OUT_DIR/$FIXTURE_NAME")
  [ -n "$INPUT_ABS" ] && PROVER_ARGS+=("$INPUT_ABS")
else
  cat > "$PROVER/Cargo.toml" <<TOML
[package]
name = "b0-pre-risc0-prove-runner"
version = "0.0.0"
edition = "2021"
publish = false
license = "MIT OR Apache-2.0"

# Pinned to RISC Zero 3.0.5. Proving is genuine; nothing is canned. The stark2snark docker
# call (made by the pinned r0vm) is intercepted by the firewall. Cargo.lock is generated + bound.
[dependencies]
risc0-zkvm = "=3.0.5"
serde_json = "=1.0.149"
bincode = "=1.3.3"

[build-dependencies]
risc0-build = "=3.0.5"

[package.metadata.risc0]
methods = ["$GUEST_STAGED"]

[workspace]
TOML
  cat > "$PROVER/build.rs" <<'RUST'
// Official RISC Zero library build path: compiles the pinned candidate guest with the LOCAL
// r0.1.91.1 toolchain (resolved via the isolated RISC0_HOME set by the caller) and embeds its
// ELF + image id. use_docker defaults to None -> no docker guest-builder. RUSTFLAGS (custom
// getrandom backend, lower-atomic, panic=abort) are constructed by risc0-build itself.
fn main() {
    risc0_build::embed_methods();
}
RUST
  cat > "$PROVER/src/main.rs" <<'RUST'
//! Genuine RISC Zero 3.0.5 Groth16 prover-runner (venue, native x86_64, host-side under the firewall).
//!
//! The frozen candidate guest is compiled by `risc0_build::embed_methods()` (build.rs) with the
//! pinned LOCAL r0.1.91.1 toolchain; its ELF + image id are the embedded consts below. This runner
//! PROVES that exact embedded ELF to a genuine Groth16 receipt (via the default ExternalProver ->
//! the pinned r0vm, whose stark2snark docker call the firewall intercepts), SELF-VERIFIES it
//! against the embedded image id, and serializes receipt/image-id (the exact shape the RISC Zero
//! mutation runner consumes) plus the four NON-SELECTION stamps.
//!
//! Args: <out_fixture.json> [guest_input_path]. (No ELF path arg: the ELF is embedded, never a
//! host-prebuilt binary substituted into execution.)
use std::fs;
use std::process::ExitCode;

use risc0_zkvm::sha::Digest;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

// Emitted by embed_methods() into OUT_DIR (a build artifact, never written into source):
//   pub const B0_PRE_CANDIDATE_RISC0_GUEST_ELF: &[u8];
//   pub const B0_PRE_CANDIDATE_RISC0_GUEST_ID: [u32; 8];
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

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
    let out = args.get(1).ok_or("usage: prove-runner <out_fixture> [input]")?;
    let elf: &[u8] = B0_PRE_CANDIDATE_RISC0_GUEST_ELF;
    if elf.is_empty() {
        return Err("INELIGIBLE: empty embedded guest ELF (frozen guest did not build)".into());
    }
    let image_id: Digest = Digest::from(B0_PRE_CANDIDATE_RISC0_GUEST_ID);

    let mut builder = ExecutorEnv::builder();
    if let Some(input_path) = args.get(2) {
        let bytes = fs::read(input_path).map_err(|e| format!("read guest input: {e}"))?;
        builder
            .write(&bytes)
            .map_err(|e| format!("write guest input: {e}"))?;
    }
    let env = builder.build().map_err(|e| format!("executor env: {e}"))?;

    // Genuine Groth16 proving of the embedded frozen guest, then SELF-VERIFY (causal check).
    let receipt = default_prover()
        .prove_with_opts(env, elf, &ProverOpts::groth16())
        .map_err(|e| format!("INELIGIBLE: genuine RISC Zero Groth16 proving failed: {e}"))?
        .receipt;
    receipt
        .verify(B0_PRE_CANDIDATE_RISC0_GUEST_ID)
        .map_err(|e| format!("INELIGIBLE: genuine RISC Zero Groth16 receipt failed self-verification: {e}"))?;
    let receipt_hex = hex(&bincode::serialize(&receipt).map_err(|e| format!("serialize receipt: {e}"))?);

    let fixture = serde_json::json!({
        "stamp": ["TEST_ONLY", "NON_SELECTION", "INVALID_FOR_R0", "NOT_AN_OFFICIAL_GUEST"],
        "candidate": "Risc0",
        "receipt_hex": receipt_hex,
        "image_id": hex(image_id.as_bytes()),
        "note": "genuine RISC Zero 3.0.5 Groth16 receipt of a frozen NON-OFFICIAL guest, built via \
                 risc0_build::embed_methods() with the pinned local r0.1.91.1 toolchain (no docker \
                 guest-builder IMAGE; the guest embed uses the pinned LOCAL r0 toolchain, but a \
                 native x86 RISC0 builder container is still required for authoritative lock/build \
                 stages) + proved under the Docker firewall + self-verified. Guest identity \
                 never enters the normative artifact.",
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
  PROVER_ARGS=("$OUT_DIR/$FIXTURE_NAME")
  [ -n "$INPUT_ABS" ] && PROVER_ARGS+=("$INPUT_ABS")
fi

# ---- PHASE A: generate the prover-runner lock HOST-SIDE, then BIND it -----------------------
GEN_ENV=()
[ "$CAND_LC" = "risc0" ] && GEN_ENV=(RISC0_HOME="$RISC0_HOME_HOST")
{
  printf '# Stage-5 GENUINE %s prover-runner host-side lockfile generation\n' "$CAND_LC"
  printf 'cd %s && cargo generate-lockfile\n' "$PROVER"
} >> "$CMD_LOG"
( cd "$PROVER" && env "${GEN_ENV[@]}" "$HOST_CARGO" generate-lockfile ) \
  || die "host 'cargo generate-lockfile' failed for the $CAND_LC prover-runner"
[ -s "$PROVER/Cargo.lock" ] || die "prover-runner Cargo.lock was not generated for $CAND_LC"
cp "$PROVER/Cargo.lock" "$OUT_DIR/prover-runner-cargo.lock"
PROVER_LOCK_B3="$(blake3_hex_file "$OUT_DIR/prover-runner-cargo.lock")"
printf 'prove-runner-cargo-lock\tprover-runner-cargo.lock\tblake3:%s\n' "$PROVER_LOCK_B3" >> "$CMD_LOG"

# ---- PHASE B: build the host prover + PROVE under the firewall, emit the stamped fixture ----
# The firewall is on PATH ONLY for this subprocess. SP1: the gnark backend needs its scratch
# (witness/proof/output) under the per-proof root -> TMPDIR=$PROOF_DIR. RISC0: r0vm on PATH +
# RISC0_WORK_DIR under the per-proof root so the firewall accepts the stark2snark work dir.
declare -a RUN_ENV=(
  PATH="$FWDIR:${R0VM_DIR:+$R0VM_DIR:}$PATH"
  B0PRE_REAL_DOCKER="$REAL_DOCKER"
  B0PRE_FIREWALL_ATTEST="$FW_ATTEST"
  B0PRE_PROOF_DIR="$PROOF_DIR"
  B0PRE_CONTENT_STORE="${CSTORE:-$OUT_DIR/_nostore}"
  B0PRE_DIAG="$FW_DIAG"
  CARGO_TARGET_DIR="$OUT_DIR/_prover-target"
)
if [ "$CAND_LC" = "sp1" ]; then
  RUN_ENV+=(TMPDIR="$PROOF_DIR")
else
  mkdir -p "$PROOF_DIR/r0-work"
  RUN_ENV+=(RISC0_HOME="$RISC0_HOME_HOST" RISC0_BUILD_LOCKED=1 RISC0_WORK_DIR="$PROOF_DIR/r0-work")
fi
{
  printf '# Stage-5 GENUINE %s host-side prove UNDER the Docker firewall (backend image replaced by v4 digest; full sandbox)\n' "$CAND_LC"
  printf '# firewall=%s real-docker=%s attest=%s\n' "$FWDIR/docker" "$REAL_DOCKER" "$FW_ATTEST"
  printf 'cd %s && <proving-env> cargo run --quiet --release --locked -- %s\n' "$PROVER" "${PROVER_ARGS[*]}"
} >> "$CMD_LOG"
( cd "$PROVER" && env "${RUN_ENV[@]}" "$HOST_CARGO" run --quiet --release --locked -- "${PROVER_ARGS[@]}" ) \
  || die "genuine host-side $CAND_LC Groth16 proving failed closed (toolchain/backend/circuit absent, guest not built, or proving/self-verify did not reproduce)"

# The genuine fixture must exist, be non-empty, and carry the four NON-SELECTION stamps + the
# candidate-specific proof/receipt fields — else fail closed.
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

# ---- BIND the firewall execution attestation (incl. OCI reconciliation + ephemeral perms) into
#      the sealed command-log lineage. The attestation itself is preserved at $FW_ATTEST. ----
[ -s "$FW_ATTEST" ] || die "the firewall recorded NO execution attestation for $CAND_LC; refusing to accept a proof produced outside the sandbox"
python3 - "$FW_ATTEST" "$CAND_LC" <<'PY' || die "firewall attestation for $CAND_LC is malformed or did not reconcile OCI / preserve canonical-input immutability"
import json, re, sys
path, cand = sys.argv[1], sys.argv[2]
recs = [json.loads(l) for l in open(path) if l.strip()]
if not recs:
    sys.exit("no firewall attestation records")
for r in recs:
    if r.get("kind") != "b0pre-docker-firewall-exec/v1":
        sys.exit(f"unexpected attestation kind: {r.get('kind')}")
    if int(r.get("exit_status", 1)) != 0:
        sys.exit(f"firewall-recorded backend exit != 0: {r.get('exit_status')}")
    if not r.get("oci_reconciliation"):
        sys.exit("firewall attestation missing OCI reconciliation")
    if not r.get("ephemeral_perms"):
        sys.exit("firewall attestation missing ephemeral ownership/mode record")
    # Canonical-input immutability. RISC Zero mounts its seal.r0/input.json read-only, so the
    # whole pre/post hash set must be byte-identical. SP1's gnark backend opens the witness/proof
    # O_RDWR, so it runs against an isolated writable COPY (which it MAY mutate — expected) while
    # the CANONICAL stays unmounted+immutable; assert canonical == canonical_post directly (the
    # pre/post strings use different labels — copy_pre/canonical vs copy_post/canonical_post — so a
    # naive string compare never matches even when the canonical is preserved).
    pre, post = r.get("input_hashes_pre", ""), r.get("input_hashes_post", "")
    if cand == "risc0":
        if pre != post:
            sys.exit(f"firewall recorded a MUTATED immutable RISC Zero input (pre={pre} post={post})")
    else:
        mp = re.search(r"canonical:([0-9a-f]{64})", pre)
        mq = re.search(r"canonical_post:([0-9a-f]{64})", post)
        if not mp or not mq:
            sys.exit(f"SP1 attestation missing canonical/canonical_post hashes (pre={pre} post={post})")
        if mp.group(1) != mq.group(1):
            sys.exit(f"firewall recorded a MUTATED CANONICAL SP1 input ({mp.group(1)} -> {mq.group(1)})")
PY
FW_ATTEST_B3="$(blake3_hex_file "$FW_ATTEST")"
printf 'firewall-attestation\t%s.firewall-attestation.jsonl\tblake3:%s\n' "$CAND" "$FW_ATTEST_B3" >> "$CMD_LOG"
if [ "$CAND_LC" = "sp1" ]; then
  printf 'sp1-circuit-content-store-id\t%s\n' "$(basename "$CIRC_CANON")" >> "$CMD_LOG"
else
  printf 'risc0-backend-identity\t%s\n' "$R0VM_VER" >> "$CMD_LOG"
fi

note "genuine $CAND_LC fixture PROVED under the Docker firewall + validated -> $OUT_FIXTURE (runner lock blake3:$PROVER_LOCK_B3, firewall attestation blake3:$FW_ATTEST_B3)"

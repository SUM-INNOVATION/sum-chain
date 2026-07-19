#!/usr/bin/env bash
#
# deploy/health-e2e-harness.sh
#
# Docker-host execution harness for issue #120 — the devnet health/readiness
# server. It brings up the real three-validator `docker-compose.yaml` devnet and
# captures end-to-end evidence that the standalone health server behaves per
# spec:
#
#   1. images build
#   2. validator-1 alone: GET /health -> 200
#   3. validator-1 alone: GET /ready  -> 503   (no quorum -> pinned at genesis)
#   4. quorum via `up --wait`         -> all healthy (GET /health -> 200)
#   5. GET /ready transitions 503 -> 200 once blocks advance
#   6. chain height advances beyond the frozen initial height
#   7. `down -v --remove-orphans` teardown
#   8. a second run from wiped volumes reaches ready again
#   9. final teardown; the git worktree is unchanged throughout
#
# The captured evidence is DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0, chain
# id 1337. It proves the health surface only — it is not a benchmark, a proof,
# a measurement, or a selection signal of any kind.
#
# PREREQUISITES — a Docker-capable *Linux* host (GitHub's ubuntu-latest works):
#   - Docker Engine + Docker Compose v2 (REQUIRED; v1 is not supported — the
#     harness relies on `up --wait`)
#   - a Rust toolchain (`cargo`) to run the `setup-local-testnet` provisioner
#   - `curl` on the host (for the JSON-RPC height corroboration)
#
# ISOLATION / SAFETY (all mandated by the issue #120 harness rulings):
#   - keys + genesis are generated into a `mktemp` runtime dir; a *generated*
#     Compose override remaps every genesis/key bind SOURCE there. The tracked
#     `genesis/local_genesis.json` and every other tracked file are NEVER
#     modified.
#   - refuses to start if the worktree is dirty; asserts it stays clean.
#   - private keys are never printed.
#   - a trap tears the stack down and removes the runtime dir on success,
#     failure, and signals.
#
# TOPOLOGY GUARD:
#   The 503->200 transition test assumes validator-1 CANNOT advance the chain
#   alone (PoA round-robin has no skip-proposer, so a lone validator stalls at
#   genesis; see crates/consensus/src/poa.rs). If validator-1 DOES advance, or
#   /ready becomes 200 before the quorum starts, that premise is false for this
#   build: the harness STOPS and reports that an explicit consensus-pause
#   mechanism is required instead of a lone-validator baseline (exit code 3).
#
# Exit: 0 = all assertions passed and evidence captured; 1 = a failed assertion
# or precondition; 3 = invalid-topology halt (see TOPOLOGY GUARD).

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment).
# ---------------------------------------------------------------------------
REPO="$(git rev-parse --show-toplevel)"
COMPOSE_FILE="$REPO/docker-compose.yaml"
PROJECT="${HEALTH_E2E_PROJECT:-health-e2e}"

PRIMARY="validator-1"                 # bootnode; RPC published on the host
# Chain services only — the health surface under test. Prometheus/Grafana are
# intentionally left out (extra image pulls, no health endpoints); `down -v
# --remove-orphans` still cleans the whole project.
CHAIN_SERVICES=(validator-1 validator-2 validator-3 fullnode)
HEALTH_PORT="${HEALTH_PORT:-8546}"    # in-container health port (not published)
RPC_HOST_PORT="${RPC_HOST_PORT:-8545}" # validator-1 RPC, published to the host

READY_TIMEOUT="${READY_TIMEOUT:-180}"  # seconds to wait for /ready -> 200
SOLO_OBSERVE="${SOLO_OBSERVE:-20}"     # seconds to confirm validator-1 stalls
POLL_INTERVAL="${POLL_INTERVAL:-2}"
NO_CACHE="${NO_CACHE:-0}"              # NO_CACHE=1 -> `build --no-cache`

# Evidence log lives OUTSIDE the repo so the worktree stays clean; it is
# uploaded as a CI artifact, never committed. When CI does not supply it,
# preflight creates it atomically with `mktemp` (no race-prone `mktemp -u`).
EVIDENCE_LOG="${EVIDENCE_LOG:-}"

RUNTIME_DIR=""        # set by provision(); mktemp -d
OVERRIDE=""           # generated Compose override inside RUNTIME_DIR
PASS=0
FAIL=0
CHAIN_ID_VERIFIED=0   # flipped to 1 ONLY after the live RPC chain_id assertion

# ---------------------------------------------------------------------------
# Logging. log() -> curated, SANITIZED evidence artifact (+ stdout): high-level
# steps, HTTP codes, heights only — never absolute runtime/evidence paths or
# key material. note() -> console (stderr) ONLY, for paths kept out of the
# artifact.
# ---------------------------------------------------------------------------
log()  { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$EVIDENCE_LOG"; }
note() { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
# Calibrated chain-id phrase — only claims "verified" AFTER the live RPC check.
chain_id_status() {
  if [ "${CHAIN_ID_VERIFIED:-0}" = 1 ]; then echo "chain id 1337 verified"
  else echo "chain id not verified (expected 1337)"; fi
}
ok()   { PASS=$((PASS + 1)); log "PASS  $*"; }
die()  { FAIL=$((FAIL + 1)); log "FATAL $*"; exit 1; }
halt_invalid_topology() {
  log "HALT  invalid topology: $*"
  log "HALT  validator-1 must NOT advance alone for the 503->200 baseline;"
  log "HALT  use an explicit consensus-pause mechanism instead (per ruling)."
  exit 3
}

# ---------------------------------------------------------------------------
# Compose plumbing.
# ---------------------------------------------------------------------------
# Docker Compose v2 is required; v1's `up --wait` is unreliable.
DC=(docker compose)
require_compose_v2() {
  docker compose version >/dev/null 2>&1 \
    || die "Docker Compose v2 is required ('docker compose'); v1 does not reliably support 'up --wait'."
}
dc() { "${DC[@]}" -p "$PROJECT" -f "$COMPOSE_FILE" -f "$OVERRIDE" --project-directory "$REPO" "$@"; }

# HTTP status of an in-container health endpoint (health port is not published).
probe() { # $1=service $2=path -> "200"/"503"/"000"
  dc exec -T "$1" curl -s -o /dev/null -w '%{http_code}' \
     "http://localhost:${HEALTH_PORT}$2" 2>/dev/null || echo "000"
}

# Chain height via the published validator-1 JSON-RPC (eth_blockNumber passes
# current_height() straight through). Prints a decimal height, or fails.
rpc_height() {
  local hex
  hex=$(curl -s -X POST -H 'content-type: application/json' \
          --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
          "http://127.0.0.1:${RPC_HOST_PORT}/" 2>/dev/null \
        | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p')
  [ -n "$hex" ] || return 1
  printf '%d\n' "$((16#${hex#0x}))"
}

frozen_height() { # retry a few times while the node finishes binding
  local i h
  for i in $(seq 1 15); do
    if h=$(rpc_height); then printf '%s\n' "$h"; return 0; fi
    sleep 1
  done
  return 1
}

# Chain id via JSON-RPC (returns a bare integer, e.g. 1337).
rpc_chain_id() {
  curl -s -X POST -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"chain_id","params":[]}' \
       "http://127.0.0.1:${RPC_HOST_PORT}/" 2>/dev/null \
    | sed -n 's/.*"result":\([0-9][0-9]*\).*/\1/p'
}

# ---------------------------------------------------------------------------
# Cleanup (success, failure, signals) — never removes the evidence log.
# ---------------------------------------------------------------------------
cleanup() {
  local rc=$?
  set +e
  if [ -n "$OVERRIDE" ] && [ -f "$OVERRIDE" ]; then
    dc down -v --remove-orphans >/dev/null 2>&1
  fi
  [ -n "$RUNTIME_DIR" ] && rm -rf "$RUNTIME_DIR"

  # Guaranteed terminal status line on EVERY exit path (success, fatal die,
  # topology halt, signal), written straight to the artifact.
  local status
  case "$rc" in
    0)       status="PASS" ;;
    3)       status="HALT — invalid topology (needs consensus pause)" ;;
    130|143) status="ABORTED — signal" ;;
    *)       status="FAIL" ;;
  esac
  if [ -n "${EVIDENCE_LOG:-}" ] && [ -f "$EVIDENCE_LOG" ]; then
    printf '%s  RESULT: %s — %d passed, %d failed (exit %d) — DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0, %s\n' \
      "$(date -u +%H:%M:%SZ)" "$status" "$PASS" "$FAIL" "$rc" "$(chain_id_status)" >> "$EVIDENCE_LOG"
  fi
  return $rc
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------------
preflight() {
  # Create the evidence file atomically unless CI supplied a path.
  if [ -z "${EVIDENCE_LOG:-}" ]; then
    EVIDENCE_LOG="$(mktemp "${TMPDIR:-/tmp}/health-e2e-evidence.XXXXXX")" \
      || { echo "cannot create the evidence log" >&2; exit 1; }
  else
    mkdir -p "$(dirname "$EVIDENCE_LOG")" && : > "$EVIDENCE_LOG" \
      || { echo "cannot write the evidence log" >&2; exit 1; }
  fi
  note "evidence log (path kept out of the artifact): $EVIDENCE_LOG"
  log "================================================================"
  log "  SUM Chain devnet health/readiness E2E — issue #120"
  log "  DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0 — $(chain_id_status)"
  log "  Not a benchmark, proof, measurement, or selection signal."
  log "================================================================"

  command -v git   >/dev/null || die "git not found"
  command -v docker >/dev/null || die "docker not found"
  command -v cargo >/dev/null || die "cargo not found (needed for setup-local-testnet)"
  command -v curl  >/dev/null || die "curl not found"
  docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"
  require_compose_v2
  log "compose: docker compose v2"
  [ -f "$COMPOSE_FILE" ] || die "missing docker-compose.yaml at the repo root"

  # Refuse to start on a dirty worktree; record the baseline for the postcheck.
  if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
    die "refusing to run: git worktree is dirty (commit/stash/clean first)."
  fi
  ok "preflight: worktree clean, toolchain present"
}

# ---------------------------------------------------------------------------
# Provisioning — ephemeral keys/genesis + generated Compose override.
# ---------------------------------------------------------------------------
provision() {
  RUNTIME_DIR="$(mktemp -d)"
  OVERRIDE="$RUNTIME_DIR/docker-compose.harness-override.yaml"
  note "runtime dir (path kept out of the artifact): $RUNTIME_DIR"

  # setup-local-testnet writes keys/ + genesis/ relative to CWD; run it inside
  # the runtime dir so NOTHING under the repo is created or modified. --locked
  # keeps Cargo.lock (a tracked file) from changing.
  log "provisioning disposable devnet identity (keys + genesis, chain id 1337)..."
  ( cd "$RUNTIME_DIR" && cargo run --locked --quiet \
       --manifest-path "$REPO/Cargo.toml" --bin setup-local-testnet >/dev/null )

  [ -f "$RUNTIME_DIR/genesis/local_genesis.json" ] \
    || die "provisioning did not produce genesis/local_genesis.json in the runtime dir"
  local i
  for i in 1 2 3; do
    [ -f "$RUNTIME_DIR/keys/validator${i}.json" ] \
      || die "provisioning did not produce validator${i}.json in the runtime dir"
  done
  ok "provisioned 3 validator keys + genesis into the runtime dir (private keys not printed)"

  # Generated override: replace every genesis/key bind SOURCE by container
  # target path. Compose merges service `volumes` by target, so the named data
  # volume (/data) from the base file is preserved and only the two binds are
  # remapped.
  {
    echo "# GENERATED by deploy/health-e2e-harness.sh — do not commit."
    echo "# Remaps genesis/key bind sources into the ephemeral runtime dir so"
    echo "# no tracked file is touched."
    echo "services:"
    for i in 1 2 3; do
      cat <<YAML
  validator-${i}:
    volumes:
      - ${RUNTIME_DIR}/genesis/local_genesis.json:/config/genesis.json:ro
      - ${RUNTIME_DIR}/keys/validator${i}.json:/secrets/validator.key:ro
YAML
    done
    cat <<YAML
  fullnode:
    volumes:
      - ${RUNTIME_DIR}/genesis/local_genesis.json:/config/genesis.json:ro
YAML
  } > "$OVERRIDE"

  # Assert the MERGED compose config binds EXACTLY the runtime-dir sources and
  # never a tracked repo path: 4 genesis mounts (3 validators + fullnode), 3
  # validator-key mounts, and 0 repo genesis/keys sources. Fixed-string greps
  # (grep -F) so runtime/repo paths are never treated as regexes; `|| true`
  # keeps a zero count from tripping `set -e`.
  local cfg gcount kcount repocount
  cfg="$(dc config)" || die "merged compose config is invalid"
  gcount=$(printf '%s\n' "$cfg" | grep -cF "${RUNTIME_DIR}/genesis/local_genesis.json" || true)
  kcount=$(printf '%s\n' "$cfg" | grep -cF "${RUNTIME_DIR}/keys/" || true)
  repocount=$(printf '%s\n' "$cfg" | grep -cF -e "${REPO}/genesis/" -e "${REPO}/keys/" || true)
  [ "$gcount" -eq 4 ] || die "merged config has $gcount runtime genesis sources, want exactly 4"
  [ "$kcount" -eq 3 ] || die "merged config has $kcount runtime validator-key sources, want exactly 3"
  [ "$repocount" -eq 0 ] || die "merged config still binds $repocount tracked genesis/keys source(s), want 0"
  ok "merged config: exactly 4 runtime genesis + 3 runtime key mounts, 0 tracked-path mounts"
}

# ---------------------------------------------------------------------------
# Assertions.
# ---------------------------------------------------------------------------
build_images() { # (1)
  log "building images ($([ "$NO_CACHE" = 1 ] && echo '--no-cache' || echo 'cached'))..."
  if [ "$NO_CACHE" = 1 ]; then dc build --no-cache; else dc build; fi
  ok "(1) images built"
}

solo_baseline() { # (2)(3) + topology guard, freezes H0
  log "starting validator-1 ONLY (no quorum)..."
  dc up -d --wait --no-build "$PRIMARY"

  local code
  code="$(probe "$PRIMARY" /health)"
  [ "$code" = 200 ] || die "(2) validator-1 /health = $code, want 200"
  ok "(2) validator-1 /health = 200"

  H0="$(frozen_height)" || die "could not read initial chain height over RPC"
  log "frozen initial height H0 = $H0"

  # Verify the RUNNING node's chain id is exactly 1337 (the evidence header
  # asserts it — do not take it on faith).
  local cid
  cid="$(rpc_chain_id)"
  [ "$cid" = 1337 ] || die "node reports chain_id '$cid', want exactly 1337"
  CHAIN_ID_VERIFIED=1
  ok "(verify) running node reports chain_id 1337"

  # Observe validator-1 alone: it must report /ready 503 and must NOT advance.
  local saw_503=0 t code h
  for ((t = 0; t < SOLO_OBSERVE; t += POLL_INTERVAL)); do
    code="$(probe "$PRIMARY" /ready)"
    [ "$code" = 503 ] && saw_503=1
    if [ "$code" = 200 ]; then
      halt_invalid_topology "/ready became 200 while only validator-1 was up"
    fi
    if h="$(rpc_height)" && [ "$h" -gt "$H0" ]; then
      halt_invalid_topology "chain advanced to height $h (> H0=$H0) with only validator-1 up"
    fi
    sleep "$POLL_INTERVAL"
  done
  [ "$saw_503" = 1 ] || die "(3) validator-1 /ready was never observed as 503 before quorum"
  ok "(3) validator-1 /ready = 503 before quorum; chain frozen at height $H0"
}

quorum_ready_transition() { # (4)(5)(6)
  log "starting the remaining quorum with 'up --wait'..."
  dc up -d --wait --no-build "${CHAIN_SERVICES[@]}"
  local code
  code="$(probe "$PRIMARY" /health)"
  [ "$code" = 200 ] || die "(4) /health = $code after quorum, want 200"
  ok "(4) quorum healthy (up --wait returned); /health = 200"

  log "polling /ready for the 503->200 transition (<= ${READY_TIMEOUT}s)..."
  local t code
  for ((t = 0; t < READY_TIMEOUT; t += POLL_INTERVAL)); do
    code="$(probe "$PRIMARY" /ready)"
    [ "$code" = 200 ] && { ok "(5) /ready transitioned 503 -> 200 after ~${t}s"; break; }
    sleep "$POLL_INTERVAL"
  done
  [ "$code" = 200 ] || die "(5) /ready never reached 200 within ${READY_TIMEOUT}s"

  local h
  h="$(rpc_height)" || die "(6) could not read chain height after ready"
  [ "$h" -gt "$H0" ] || die "(6) chain height $h did not advance beyond frozen H0=$H0"
  ok "(6) chain height advanced to $h (> frozen H0=$H0)"
}

teardown() { # (7)/(9-final)
  log "tearing down (down -v --remove-orphans)..."
  dc down -v --remove-orphans
  ok "$1"
}

second_run() { # (8) from wiped volumes
  log "second run: bringing the full quorum up from wiped volumes..."
  dc up -d --wait --no-build "${CHAIN_SERVICES[@]}"
  local code
  code="$(probe "$PRIMARY" /health)"
  [ "$code" = 200 ] || die "(8) second run /health = $code, want 200"

  local t
  for ((t = 0; t < READY_TIMEOUT; t += POLL_INTERVAL)); do
    code="$(probe "$PRIMARY" /ready)"
    [ "$code" = 200 ] && break
    sleep "$POLL_INTERVAL"
  done
  [ "$code" = 200 ] || die "(8) second run /ready never reached 200 within ${READY_TIMEOUT}s"

  local h
  h="$(rpc_height)" || die "(8) second run: could not read chain height"
  [ "$h" -gt "$H0" ] || die "(8) second run: chain height $h did not advance beyond genesis"
  ok "(8) second run from wiped volumes reached /ready=200 at height $h"
}

worktree_clean() { # (9)
  [ -z "$(git -C "$REPO" status --porcelain)" ] \
    || die "(9) git worktree is dirty after the run (harness must leave no trace)"
  ok "(9) git worktree unchanged"
}

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
main() {
  preflight
  provision
  build_images                 # (1)
  solo_baseline                # (2)(3) + guard, sets H0
  quorum_ready_transition      # (4)(5)(6)
  teardown "(7) teardown after run 1 (volumes wiped)"
  second_run                   # (8)
  teardown "(final) teardown after run 2"
  worktree_clean               # (9)

  log "all assertions passed (${PASS} checks)"
  note "evidence log: $EVIDENCE_LOG"
  # The terminal RESULT summary line is appended by cleanup() on every exit.
  [ "$FAIL" -eq 0 ] || exit 1
}

main "$@"

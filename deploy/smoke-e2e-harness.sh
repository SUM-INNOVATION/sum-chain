#!/usr/bin/env bash
#
# deploy/smoke-e2e-harness.sh
#
# Native boot/verify/teardown/repeat harness for issue #119 — the SMOKE devnet:
# ONE validator plus all funded roles (three archives, one verifier, one client,
# one funder), chain id 1337, on the current dormant ChainParams (compute-pool
# and beacon gates both None).
#
# It mirrors the proven patterns of the #120 Docker harness
# (deploy/health-e2e-harness.sh) but runs NATIVELY (no Docker) because a single
# PoA validator is always its own round-robin proposer and produces blocks
# alone — no quorum is needed. It captures end-to-end evidence that:
#
#   1. the `setup-local-testnet --mode smoke` provisioner materializes keys +
#      a runnable genesis into a mktemp runtime dir OUTSIDE the repo
#   2. the generated genesis has EXACTLY ONE validator, chain id 1337, and both
#      dormant gates None
#   3. `sumchain run` boots that single validator against the runtime genesis
#   4. the live RPC reports chain_id == 1337
#   5. the chain PRODUCES BLOCKS (height advances beyond genesis)
#   6. deterministic teardown (node killed, the ENTIRE runtime dir removed)
#   7. a SECOND, freshly PROVISIONED run (new mktemp dir + fresh keys/genesis,
#      with a DISTINCT validator pubkey) boots + advances again
#   8. the git worktree is clean BEFORE and AFTER (no tracked file touched)
#
# The captured evidence is DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0, chain
# id 1337. It proves the smoke bootstrap only — it is not a benchmark, a proof,
# a measurement, or a selection signal of any kind. A passing smoke run does NOT
# constitute the deferred five-validator pool ecosystem.
#
# PREREQUISITES:
#   - a Rust toolchain (`cargo`) to build the `sumchain` + `setup-local-testnet`
#     binaries
#   - `curl` (for the JSON-RPC corroboration)
#   - `python3` (only to decode the genesis JSON in the provisioning assertion)
#
# ISOLATION / SAFETY (mirrors the #120 harness rulings):
#   - keys + genesis are generated into a `mktemp` runtime dir; the tracked
#     `genesis/local_genesis.json` and every other tracked file are NEVER
#     touched (smoke mode routes ALL output through --output-dir).
#   - refuses to start if the worktree is dirty; asserts it stays clean after.
#   - private keys are never printed.
#   - a trap kills the node and removes the runtime dir on success, failure, and
#     signals.
#
# Exit: 0 = all assertions passed; 1 = a failed assertion or precondition.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment).
# ---------------------------------------------------------------------------
REPO="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"

# Localhost, high, non-default ports keep collisions with anything else on the
# host unlikely. Only ONE node runs at a time, so these are reused across runs.
RPC_HOST="${SMOKE_RPC_HOST:-127.0.0.1}"
RPC_PORT="${SMOKE_RPC_PORT:-18545}"
P2P_PORT="${SMOKE_P2P_PORT:-38301}"
HEALTH_PORT="${SMOKE_HEALTH_PORT:-18546}"

# The node waits ~5s for the network mesh before producing its first block, then
# emits one per block_time (2s). Give height-advance a generous ceiling.
BOOT_TIMEOUT="${SMOKE_BOOT_TIMEOUT:-30}"   # seconds to wait for RPC to answer
ADVANCE_TIMEOUT="${SMOKE_ADVANCE_TIMEOUT:-60}" # seconds to wait for height > 0
POLL_INTERVAL="${SMOKE_POLL_INTERVAL:-2}"

# Evidence log lives OUTSIDE the repo so the worktree stays clean.
EVIDENCE_LOG="${EVIDENCE_LOG:-}"

RUNTIME_DIR=""     # set by provision(); mktemp -d
GENESIS=""         # set by provision()
VALIDATOR_KEY=""   # set by provision()
MANIFEST=""        # set by provision()
VALIDATOR_PUBKEY="" # set by provision(); compared across the two fresh runs
NODE_PID=""        # set by boot(); killed by cleanup()/teardown()
PASS=0
FAIL=0
CHAIN_ID_VERIFIED=0

# ---------------------------------------------------------------------------
# Logging. log() -> sanitized evidence artifact (+ stdout). note() -> stderr
# only, for absolute runtime paths kept out of the artifact.
# ---------------------------------------------------------------------------
log()  { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$EVIDENCE_LOG"; }
note() { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
chain_id_status() {
  if [ "${CHAIN_ID_VERIFIED:-0}" = 1 ]; then echo "chain id 1337 verified"
  else echo "chain id not verified (expected 1337)"; fi
}
ok()  { PASS=$((PASS + 1)); log "PASS  $*"; }
die() { FAIL=$((FAIL + 1)); log "FATAL $*"; exit 1; }

# ---------------------------------------------------------------------------
# JSON-RPC helpers (against the single validator's published RPC).
# ---------------------------------------------------------------------------
rpc_url() { printf 'http://%s:%s/' "$RPC_HOST" "$RPC_PORT"; }

# Chain id via JSON-RPC (returns a bare integer, e.g. 1337, or empty).
# The trailing `|| true` is load-bearing: under `set -e` + `pipefail`, curl's
# connection-refused (exit 7) while the RPC is still binding during the boot
# poll would otherwise abort the whole script — the caller must retry instead.
rpc_chain_id() {
  curl -s -X POST -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"chain_id","params":[]}' \
       "$(rpc_url)" 2>/dev/null \
    | sed -n 's/.*"result":\([0-9][0-9]*\).*/\1/p' || true
}

# Chain height via eth_blockNumber (hex result -> decimal), or non-zero if the
# RPC is not answering yet.
rpc_height() {
  local hex
  hex=$(curl -s -X POST -H 'content-type: application/json' \
          --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
          "$(rpc_url)" 2>/dev/null \
        | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p' || true)
  [ -n "$hex" ] || return 1
  printf '%d\n' "$((16#${hex#0x}))"
}

# ---------------------------------------------------------------------------
# Teardown of a running node (used between runs AND by the exit trap).
# ---------------------------------------------------------------------------
kill_node() {
  if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill "$NODE_PID" 2>/dev/null || true
    # Wait for the process to actually exit so the RPC/P2P ports are released
    # before the next run rebinds them.
    local t
    for t in $(seq 1 20); do
      kill -0 "$NODE_PID" 2>/dev/null || break
      sleep 0.5
    done
    kill -9 "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
  fi
  NODE_PID=""
}

# ---------------------------------------------------------------------------
# Cleanup (success, failure, signals) — never removes the evidence log.
# ---------------------------------------------------------------------------
cleanup() {
  local rc=$?
  set +e
  kill_node
  [ -n "$RUNTIME_DIR" ] && rm -rf "$RUNTIME_DIR"

  local status
  case "$rc" in
    0)       status="PASS" ;;
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
  if [ -z "${EVIDENCE_LOG:-}" ]; then
    EVIDENCE_LOG="$(mktemp "${TMPDIR:-/tmp}/smoke-e2e-evidence.XXXXXX")" \
      || { echo "cannot create the evidence log" >&2; exit 1; }
  else
    if ! { mkdir -p "$(dirname "$EVIDENCE_LOG")" && : > "$EVIDENCE_LOG"; }; then
      echo "cannot write the evidence log" >&2
      exit 1
    fi
  fi
  note "evidence log (path kept out of the artifact): $EVIDENCE_LOG"
  log "================================================================"
  log "  SUM Chain SMOKE devnet boot E2E — issue #119"
  log "  DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0 — $(chain_id_status)"
  log "  One validator + funded roles. Not the deferred 5-validator pool."
  log "================================================================"

  command -v git    >/dev/null || die "git not found"
  command -v cargo  >/dev/null || die "cargo not found (needed to build the binaries)"
  command -v curl   >/dev/null || die "curl not found"
  command -v python3 >/dev/null || die "python3 not found (needed for the genesis assertion)"

  # Refuse to start on a dirty worktree; assert it stays clean afterwards.
  if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
    die "refusing to run: git worktree is dirty (commit/stash/clean first)."
  fi
  ok "preflight: worktree clean, toolchain present"

  log "building sumchain + setup-local-testnet (release-free dev build)..."
  ( cd "$REPO" && cargo build --locked --quiet \
      -p sumchain-scripts --bin setup-local-testnet \
      -p sumchain-node --bin sumchain ) \
    || die "cargo build failed"
  SUMCHAIN_BIN="$REPO/target/debug/sumchain"
  SETUP_BIN="$REPO/target/debug/setup-local-testnet"
  [ -x "$SUMCHAIN_BIN" ] || die "missing built binary: $SUMCHAIN_BIN"
  [ -x "$SETUP_BIN" ]    || die "missing built binary: $SETUP_BIN"
  ok "built sumchain + setup-local-testnet"
}

# ---------------------------------------------------------------------------
# Provisioning — smoke keys + genesis into a mktemp runtime dir OUTSIDE the repo.
# ---------------------------------------------------------------------------
provision() {
  RUNTIME_DIR="$(mktemp -d)"
  note "runtime dir (path kept out of the artifact): $RUNTIME_DIR"

  log "provisioning smoke devnet (1 validator + funded roles, chain id 1337)..."
  "$SETUP_BIN" --mode smoke --output-dir "$RUNTIME_DIR" >/dev/null \
    || die "smoke provisioning failed"

  GENESIS="$RUNTIME_DIR/genesis.json"
  VALIDATOR_KEY="$RUNTIME_DIR/keys/validator.json"
  MANIFEST="$RUNTIME_DIR/manifest.json"
  [ -f "$GENESIS" ]       || die "provisioning did not produce genesis.json in the runtime dir"
  [ -f "$VALIDATOR_KEY" ] || die "provisioning did not produce keys/validator.json in the runtime dir"
  [ -f "$MANIFEST" ]      || die "provisioning did not produce manifest.json in the runtime dir"

  # Strengthened pre-boot assertion (BEFORE booting anything): single validator,
  # chain 1337, both gates None, EXACTLY SEVEN funded identities, and the EXACT
  # six non-validator role names — not merely "all allocations are positive".
  python3 - "$GENESIS" "$MANIFEST" <<'PY' || die "generated genesis/manifest failed the strengthened assertions"
import json, sys
g = json.load(open(sys.argv[1]))
m = json.load(open(sys.argv[2]))
assert g["chain_id"] == 1337, g["chain_id"]
assert len(g["validators"]) == 1, g["validators"]
p = g["params"]
assert p["compute_pool_enabled_from_height"] is None, p["compute_pool_enabled_from_height"]
assert p["beacon_enabled_from_height"] is None, p["beacon_enabled_from_height"]
# Exactly seven funded identities, every balance > 0.
assert len(g["alloc"]) == 7, ("alloc size", len(g["alloc"]))
assert all(v > 0 for v in g["alloc"].values()), "every alloc balance must be > 0"
# The exact six non-validator role names.
EXPECTED = ["archive1", "archive2", "archive3", "verifier", "client", "funder"]
names = sorted(r["name"] for r in m["roles"])
assert names == sorted(EXPECTED), ("role names", names)
# Alloc addresses are EXACTLY the validator + the six role addresses.
addrs = {m["validator"]["address"]} | {r["address"] for r in m["roles"]}
assert len(addrs) == 7, ("distinct addrs", len(addrs))
assert set(g["alloc"].keys()) == addrs, "alloc must fund exactly the validator + 6 roles"
PY

  VALIDATOR_PUBKEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validator"]["pubkey"])' "$MANIFEST")"
  [ -n "$VALIDATOR_PUBKEY" ] || die "could not read validator pubkey from manifest"
  ok "provisioned: 1 validator, chain id 1337, gates None, exactly 7 funded (validator + 6 named roles)"
}

# ---------------------------------------------------------------------------
# Boot the single validator + verify chain_id 1337 and block production.
# $1 = a human label for the run (e.g. "run 1", "run 2 (wiped dir)").
# ---------------------------------------------------------------------------
boot_and_verify() {
  local label="$1"
  local datadir="$RUNTIME_DIR/data"
  rm -rf "$datadir"

  # A minimal config file only to pin the health port off any default; genesis,
  # data dir, validator key, RPC + P2P addresses are supplied on the CLI.
  local cfg="$RUNTIME_DIR/node.toml"
  printf '[health]\naddr = "%s:%s"\n' "$RPC_HOST" "$HEALTH_PORT" > "$cfg"

  log "[$label] booting the single validator (RPC $RPC_HOST:$RPC_PORT)..."
  "$SUMCHAIN_BIN" run \
    --config "$cfg" \
    --genesis "$GENESIS" \
    --data-dir "$datadir" \
    --validator-key "$VALIDATOR_KEY" \
    --p2p-addr "/ip4/127.0.0.1/tcp/$P2P_PORT" \
    --rpc-addr "$RPC_HOST:$RPC_PORT" \
    --log-level warn \
    >"$RUNTIME_DIR/node.$label.log" 2>&1 &
  NODE_PID=$!

  # Wait for the RPC to answer chain_id.
  local t cid=""
  for ((t = 0; t < BOOT_TIMEOUT; t += POLL_INTERVAL)); do
    kill -0 "$NODE_PID" 2>/dev/null || die "[$label] node process exited during boot (see node log)"
    cid="$(rpc_chain_id)"
    [ -n "$cid" ] && break
    sleep "$POLL_INTERVAL"
  done
  [ -n "$cid" ] || die "[$label] RPC never answered chain_id within ${BOOT_TIMEOUT}s"
  [ "$cid" = 1337 ] || die "[$label] node reports chain_id '$cid', want exactly 1337"
  CHAIN_ID_VERIFIED=1
  ok "[$label] live RPC reports chain_id 1337"

  # Wait for the height to advance beyond genesis (block production).
  local h=0
  for ((t = 0; t < ADVANCE_TIMEOUT; t += POLL_INTERVAL)); do
    kill -0 "$NODE_PID" 2>/dev/null || die "[$label] node process exited before producing blocks (see node log)"
    if h="$(rpc_height)" && [ "$h" -gt 0 ]; then
      ok "[$label] chain produced blocks — height advanced to $h (> genesis 0)"
      break
    fi
    sleep "$POLL_INTERVAL"
  done
  [ "${h:-0}" -gt 0 ] || die "[$label] chain height never advanced beyond genesis within ${ADVANCE_TIMEOUT}s"
}

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
main() {
  preflight

  # Run 1: fresh provision, boot, verify chain_id + block production, tear down.
  provision
  local pubkey1="$VALIDATOR_PUBKEY"
  boot_and_verify "run-1"
  kill_node
  ok "run-1 teardown: node stopped, ports released"

  # FRESH second provisioning run — the approved contract requires a second
  # CLEAN provisioning, not a data-only wipe. Remove the ENTIRE run-1 runtime
  # dir, mktemp a NEW one, and reprovision fresh keys + genesis.
  local old_runtime="$RUNTIME_DIR"
  RUNTIME_DIR=""
  rm -rf "$old_runtime"
  [ -e "$old_runtime" ] && die "run-1 runtime dir was not removed" || true
  ok "run-1 runtime dir fully removed"
  provision
  local pubkey2="$VALIDATOR_PUBKEY"

  # The fresh provisioning must yield a DIFFERENT validator identity.
  [ -n "$pubkey1" ] && [ -n "$pubkey2" ] || die "could not capture validator pubkeys to compare"
  [ "$pubkey1" != "$pubkey2" ] \
    || die "second provisioning reused the first validator pubkey — not a fresh run"
  ok "second provisioning produced a DISTINCT validator pubkey"

  # Run 2 against the freshly provisioned runtime dir: boot + advance again.
  boot_and_verify "run-2"
  kill_node
  ok "run-2 teardown: node stopped, ports released"

  # Worktree must be untouched throughout.
  [ -z "$(git -C "$REPO" status --porcelain)" ] \
    || die "git worktree is dirty after the run (harness must leave no trace)"
  ok "git worktree unchanged (no tracked file touched)"

  log "all assertions passed (${PASS} checks)"
  note "evidence log: $EVIDENCE_LOG"
  [ "$FAIL" -eq 0 ] || exit 1
}

main "$@"

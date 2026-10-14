#!/usr/bin/env bash
#
# deploy/topology-e2e-harness.sh
#
# Docker-host E2E harness for issue #118's SYNTHETIC five-validator devnet. It
# runs the tracked `deploy/snip-local-mirror.yaml` exactly as a developer would
# — from the generated, ignored runtime directory `devnet/` at the repository
# root — and checks that the round-robin consensus actually works:
#
#   1. the merged compose config binds ONLY devnet/genesis.json and
#      devnet/keys/validator<i>.json, for exactly five validators, each bind
#      fail-closed (no create_host_path)
#   2. images build from this commit
#   3. ABSENT runtime files fail `up` before any container starts, naming the
#      missing devnet/ path, and Docker creates nothing in their place
#   4. `setup-local-testnet --mode topology --validator-count 5 --output-dir
#      devnet` provisions a consensus-only genesis (chain id 1337, five
#      validators, compute-pool and beacon gates None); devnet/ is git-ignored
#   5. absent devnet/genesis.json alone (keys present) fails `up`, naming it
#   6. validator-1 alone: GET /health 200, GET /ready 503, chain frozen at
#      genesis (validator-2 owns height 1 and is down)
#   7. all five up (`up --wait`): GET /health 200 and GET /ready 200 on EVERY
#      validator
#   8. every node reports chain_id 1337 and the genesis validator set, in order
#   9. every node's height advances to TARGET_HEIGHT (four full rotations)
#  10. every node returns the IDENTICAL blocks 1..C (C = the lowest node height):
#      same hashes, parent links intact; block h was proposed by
#      validators[h mod 5]; every one of the five proposed at least one block
#      (per-validator counts in the evidence)
#  11. teardown (`down -v`), devnet/ removed, the git worktree unchanged
#
# SYNTHETIC TEST TOPOLOGY. All five validator keys are throwaway keys generated
# on this host for this run and deleted when it ends; none is committed, and
# none belongs to any real network. This harness never describes, proposes or
# changes a production validator set. Consensus only: the pool and beacon gates
# stay unset (the genesis loader refuses them).
#
# The captured evidence is DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0, chain
# id 1337. It is not a benchmark, a proof, a measurement, or a selection signal.
#
# PREREQUISITES — a Docker-capable Linux host (GitHub's ubuntu-latest works):
#   - Docker Engine + Docker Compose v2 (`up --wait`, `config --format json`)
#   - a Rust toolchain (`cargo`) for the `setup-local-testnet` provisioner
#   - python3 (JSON checks)
#
# ISOLATION / SAFETY:
#   - refuses to start if the worktree is dirty, or if devnet/ already exists
#     (it never touches a developer's own devnet); asserts both at the end.
#   - the only paths it writes inside the repository are under the ignored
#     devnet/ (mode 0700). No tracked file, and no tracked genesis, is read for
#     the chain or modified.
#   - private keys are never printed. The containers run as uid 1000; when the
#     host user is not uid 1000 the throwaway VALIDATOR keys are made 0644 so
#     the containers can read them, which the 0700 devnet/ still keeps from
#     every other host user.
#   - a trap tears the stack down and removes devnet/ and the work dir on
#     success, failure and signals.
#
# Exit: 0 = all assertions passed; 1 = a failed assertion or precondition;
# 3 = validator-1 advanced alone (the solo baseline's premise is false).

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment).
# ---------------------------------------------------------------------------
REPO="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
COMPOSE_FILE="$REPO/deploy/snip-local-mirror.yaml"
DEVNET_DIR="$REPO/devnet"
PROJECT="${TOPOLOGY_E2E_PROJECT:-topology-e2e}"

# The compose file runs exactly these; check (1) asserts it.
SERVICES=(validator-1 validator-2 validator-3 validator-4 validator-5)
N=${#SERVICES[@]}
HEALTH_PORT=8546    # in-container health/readiness port
RPC_PORT=8545       # in-container JSON-RPC port

READY_TIMEOUT="${READY_TIMEOUT:-180}"     # seconds for /ready -> 200 on every node
SOLO_OBSERVE="${SOLO_OBSERVE:-20}"        # seconds to confirm validator-1 stalls alone
POLL_INTERVAL="${POLL_INTERVAL:-2}"
TARGET_HEIGHT="${TARGET_HEIGHT:-$((4 * N))}" # four full round-robin rotations
HEIGHT_TIMEOUT="${HEIGHT_TIMEOUT:-300}"   # seconds for every node to reach TARGET_HEIGHT
NO_CACHE="${NO_CACHE:-0}"                 # NO_CACHE=1 -> `build --no-cache`

# Evidence log lives OUTSIDE the repo; uploaded as a CI artifact, never committed.
EVIDENCE_LOG="${EVIDENCE_LOG:-}"

WORK=""              # mktemp -d, outside the repo: RPC captures, moved-aside genesis
CREATED_DEVNET=0     # 1 once this run created devnet/ (and so must remove it)
STACK_TOUCHED=0      # 1 once any `up` ran (cleanup must `down -v`)
PASS=0
FAIL=0
CHAIN_ID_VERIFIED=0

# ---------------------------------------------------------------------------
# Logging. log() -> sanitized evidence artifact (+ stdout): steps, HTTP codes,
# heights, public block data only — never absolute paths or key material.
# note() -> console (stderr) only.
# ---------------------------------------------------------------------------
log()  { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$EVIDENCE_LOG"; }
note() { printf '%s  %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
sanitize() { local s="${1//"$REPO"/<repo>}"; printf '%s' "${s//$'\n'/ | }"; }
chain_id_status() {
  if [ "${CHAIN_ID_VERIFIED:-0}" = 1 ]; then echo "chain id 1337 verified"
  else echo "chain id not verified (expected 1337)"; fi
}
ok()  { PASS=$((PASS + 1)); log "PASS  $*"; }
die() { FAIL=$((FAIL + 1)); log "FATAL $*"; exit 1; }
halt_invalid_topology() {
  log "HALT  invalid topology: $*"
  log "HALT  validator-1 must NOT advance alone: height 1 belongs to validator-2."
  exit 3
}

# ---------------------------------------------------------------------------
# Compose plumbing. No --project-directory: relative paths in the compose file
# resolve against deploy/, so ../devnet is <repo>/devnet — the contract under
# test.
# ---------------------------------------------------------------------------
dc() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

probe() { # $1=service $2=path -> "200"/"503"/"000"
  dc exec -T "$1" curl -s -o /dev/null -w '%{http_code}' \
     "http://localhost:${HEALTH_PORT}$2" 2>/dev/null || echo "000"
}

rpc() { # $1=service $2=method $3=JSON params -> raw JSON-RPC response (or empty)
  dc exec -T "$1" curl -s -m 10 -X POST -H 'content-type: application/json' \
     --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" \
     "http://localhost:${RPC_PORT}/" 2>/dev/null || true
}

height() { # $1=service -> decimal height, or non-zero
  local hex
  hex="$(rpc "$1" eth_blockNumber '[]' | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
  [ -n "$hex" ] || return 1
  printf '%d\n' "$((16#${hex#0x}))"
}

chain_id() { # $1=service -> bare integer, or empty
  rpc "$1" chain_id '[]' | sed -n 's/.*"result":\([0-9][0-9]*\).*/\1/p'
}

wait_height() { # $1=service -> its height once its RPC answers (<= ~30s)
  local i h
  for i in $(seq 1 15); do
    if h="$(height "$1")"; then printf '%s\n' "$h"; return 0; fi
    sleep 2
  done
  return 1
}

# ---------------------------------------------------------------------------
# Cleanup (success, failure, signals) — never removes the evidence log.
# ---------------------------------------------------------------------------
cleanup() {
  local rc=$?
  set +e
  if [ "$STACK_TOUCHED" = 1 ]; then
    if [ "$rc" -ne 0 ]; then
      note "container logs (console only, last 60 lines per service):"
      dc logs --no-color --tail 60 >&2 2>&1
    fi
    dc down -v --remove-orphans >/dev/null 2>&1
  fi
  [ "$CREATED_DEVNET" = 1 ] && rm -rf "$DEVNET_DIR"
  [ -n "$WORK" ] && rm -rf "$WORK"

  local status
  case "$rc" in
    0)       status="PASS" ;;
    3)       status="HALT — validator-1 advanced alone" ;;
    130|143) status="ABORTED — signal" ;;
    *)       status="FAIL" ;;
  esac
  if [ -n "${EVIDENCE_LOG:-}" ] && [ -f "$EVIDENCE_LOG" ]; then
    printf '%s  RESULT: %s — %d passed, %d failed (exit %d) — SYNTHETIC %d-validator topology — DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0, %s\n' \
      "$(date -u +%H:%M:%SZ)" "$status" "$PASS" "$FAIL" "$rc" "$N" "$(chain_id_status)" >> "$EVIDENCE_LOG"
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
    EVIDENCE_LOG="$(mktemp "${TMPDIR:-/tmp}/topology-e2e-evidence.XXXXXX")" \
      || { echo "cannot create the evidence log" >&2; exit 1; }
  else
    if ! { mkdir -p "$(dirname "$EVIDENCE_LOG")" && : > "$EVIDENCE_LOG"; }; then
      echo "cannot write the evidence log" >&2
      exit 1
    fi
  fi
  note "evidence log (path kept out of the artifact): $EVIDENCE_LOG"
  log "================================================================"
  log "  SUM Chain SYNTHETIC ${N}-validator devnet E2E — issue #118"
  log "  Throwaway keys generated for this run; not a production validator set."
  log "  Consensus only (pool/beacon gates unset). DEVNET_ONLY / NON_SELECTION / INVALID_FOR_B0"
  log "  Not a benchmark, proof, measurement, or selection signal."
  log "================================================================"

  command -v git     >/dev/null || die "git not found"
  command -v docker  >/dev/null || die "docker not found"
  command -v cargo   >/dev/null || die "cargo not found (needed for setup-local-testnet)"
  command -v python3 >/dev/null || die "python3 not found (needed for the JSON checks)"
  docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"
  docker compose version >/dev/null 2>&1 \
    || die "Docker Compose v2 is required ('docker compose')"
  log "compose: docker compose v2"
  [ -f "$COMPOSE_FILE" ] || die "missing deploy/snip-local-mirror.yaml"

  if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
    die "refusing to run: git worktree is dirty (commit/stash/clean first)."
  fi
  if [ -e "$DEVNET_DIR" ] || [ -L "$DEVNET_DIR" ]; then
    die "refusing to run: devnet/ already exists (move it away; this harness never touches an existing devnet)"
  fi
  git -C "$REPO" check-ignore -q devnet/genesis.json \
    || die "devnet/ is not git-ignored (.gitignore must carry /devnet/)"
  WORK="$(mktemp -d)"
  note "work dir (path kept out of the artifact): $WORK"
  ok "preflight: worktree clean, no existing devnet/, devnet/ ignored, toolchain present"
}

# ---------------------------------------------------------------------------
# (1) Docker's own reading of the compose file.
# ---------------------------------------------------------------------------
check_compose_config() {
  dc config --format json > "$WORK/config.json" 2>"$WORK/config.err" \
    || die "(1) docker compose config failed: $(sanitize "$(cat "$WORK/config.err")")"
  python3 - "$WORK/config.json" "$REPO" "$N" <<'PY' || die "(1) merged compose config does not match the devnet/ runtime-path contract"
import json, os, sys
cfg = json.load(open(sys.argv[1]))
repo = os.path.realpath(sys.argv[2])
n = int(sys.argv[3])
services = cfg["services"]
want = [f"validator-{i}" for i in range(1, n + 1)]
assert sorted(services) == sorted(want), ("services", sorted(services))
for i, name in enumerate(want, 1):
    svc = services[name]
    binds = [v for v in svc.get("volumes", []) if v.get("type") == "bind"]
    got = sorted((os.path.realpath(v["source"]), v["target"]) for v in binds)
    exp = sorted([
        (os.path.join(repo, "devnet", "genesis.json"), "/config/genesis.json"),
        (os.path.join(repo, "devnet", "keys", f"validator{i}.json"), "/secrets/validator.key"),
    ])
    assert got == exp, (name, got)
    for v in binds:
        assert v.get("read_only") is True, (name, v["target"], "read_only")
        assert not (v.get("bind") or {}).get("create_host_path", False), (name, v["target"], "create_host_path")
    cmd = svc["command"]
    assert cmd[cmd.index("--genesis") + 1] == "/config/genesis.json", (name, cmd)
    assert cmd[cmd.index("--validator-key") + 1] == "/secrets/validator.key", (name, cmd)
PY
  ok "(1) merged config: ${N} validators, each binding only devnet/genesis.json + its own devnet/keys/validator<i>.json, read-only, fail-closed"
}

# ---------------------------------------------------------------------------
# (2) Images.
# ---------------------------------------------------------------------------
build_images() {
  # The Dockerfile requires the full commit. The worktree is clean (preflight
  # refuses otherwise), so HEAD is exactly the tree being built.
  export GIT_HASH="${GIT_HASH:-$(git -C "$REPO" rev-parse HEAD)}"
  log "building images for commit ${GIT_HASH} ($([ "$NO_CACHE" = 1 ] && echo '--no-cache' || echo 'cached'))..."
  if [ "$NO_CACHE" = 1 ]; then dc build --no-cache; else dc build; fi
  ok "(2) images built"
}

# ---------------------------------------------------------------------------
# (3)/(5) Absent runtime files fail `up`, naming the path; nothing is created.
# $1 = label, $2 = the path (relative to the repo) the failure must name.
# ---------------------------------------------------------------------------
expect_up_refused() {
  local label="$1" must_name="$2" out rc
  STACK_TOUCHED=1
  set +e
  out="$(dc up -d --no-build validator-1 2>&1)"
  rc=$?
  set -e
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  [ "$rc" -ne 0 ] || die "$label: \`up\` SUCCEEDED although $must_name is absent"
  grep -qF "$REPO/$must_name" <<<"$out" \
    || die "$label: the failure does not name $must_name: $(sanitize "$out")"
  grep -qiE 'does not exist|no such file' <<<"$out" \
    || die "$label: the failure does not say the file is absent: $(sanitize "$out")"
  log "      docker: $(sanitize "$(grep -iE 'does not exist|no such file' <<<"$out" | head -1)")"
}

absent_devnet_fails_closed() { # (3)
  expect_up_refused "(3)" "devnet/"
  [ ! -e "$DEVNET_DIR" ] && [ ! -L "$DEVNET_DIR" ] \
    || die "(3) Docker created devnet/ in place of the absent runtime files"
  ok "(3) devnet/ absent: \`up\` refused before any container started, naming the missing path; nothing created"
}

absent_genesis_fails_closed() { # (5)
  mv "$DEVNET_DIR/genesis.json" "$WORK/genesis.json.aside"
  expect_up_refused "(5)" "devnet/genesis.json"
  [ ! -e "$DEVNET_DIR/genesis.json" ] \
    || die "(5) Docker created something at devnet/genesis.json in place of the absent file"
  mv "$WORK/genesis.json.aside" "$DEVNET_DIR/genesis.json"
  ok "(5) devnet/genesis.json absent (keys present): \`up\` refused, naming devnet/genesis.json; nothing created"
}

# ---------------------------------------------------------------------------
# (4) Provisioning into the ignored runtime directory.
# ---------------------------------------------------------------------------
provision() {
  mkdir -m 0700 "$DEVNET_DIR"
  CREATED_DEVNET=1
  log "provisioning the synthetic ${N}-validator topology into devnet/ (throwaway keys, chain id 1337)..."
  ( cd "$REPO" && cargo run --locked --quiet --bin setup-local-testnet -- \
       --mode topology --validator-count "$N" --output-dir devnet >/dev/null ) \
    || die "(4) topology provisioning failed"

  python3 - "$DEVNET_DIR/genesis.json" "$DEVNET_DIR/manifest.json" "$N" <<'PY' || die "(4) generated genesis/manifest failed the topology assertions"
import json, sys
g = json.load(open(sys.argv[1])); m = json.load(open(sys.argv[2])); n = int(sys.argv[3])
assert g["chain_id"] == 1337, g["chain_id"]
assert len(g["validators"]) == n == len(set(g["validators"])), g["validators"]
p = g["params"]
for gate in ("compute_pool_enabled_from_height", "beacon_enabled_from_height"):
    assert p.get(gate) is None, (gate, p.get(gate))
for surface in ("compute_pool_params", "beacon_params", "beacon_schedule"):
    assert p.get(surface) is None, (surface, p.get(surface))
assert m["mode"] == "topology" and m["synthetic_test_topology"] is True
assert [v["pubkey"] for v in m["validators"]] == g["validators"]
assert len(g["alloc"]) == n + 6 and all(int(b) > 0 for b in g["alloc"].values())
PY
  local i
  for i in $(seq 1 "$N"); do
    [ -f "$DEVNET_DIR/keys/validator${i}.json" ] || die "(4) missing devnet/keys/validator${i}.json"
  done
  [ -z "$(git -C "$REPO" status --porcelain)" ] || die "(4) provisioning dirtied the worktree"
  git -C "$REPO" check-ignore -q devnet/keys/validator1.json || die "(4) devnet/keys is not ignored"

  # Containers run as uid 1000 (Dockerfile). The provisioner wrote the keys
  # 0600 for the host user; let the containers read the throwaway validator
  # keys when that user is someone else. devnet/ itself stays 0700.
  if [ "$(id -u)" != 1000 ]; then
    chmod 0644 "$DEVNET_DIR"/keys/validator*.json
    note "validator keys made container-readable (host uid $(id -u) != 1000); devnet/ stays 0700"
  fi
  ok "(4) provisioned devnet/: ${N} validators, chain id 1337, pool/beacon gates None, $((N + 6)) funded identities; ignored by git, worktree clean"
}

# ---------------------------------------------------------------------------
# (6) validator-1 alone: live, not ready, frozen.
# ---------------------------------------------------------------------------
solo_baseline() {
  log "starting validator-1 ONLY (validator-2 owns height 1)..."
  STACK_TOUCHED=1
  dc up -d --wait --no-build validator-1

  local code h0 cid
  code="$(probe validator-1 /health)"
  [ "$code" = 200 ] || die "(6) validator-1 /health = $code, want 200"
  h0="$(wait_height validator-1)" || die "(6) validator-1's RPC never answered"
  [ "$h0" = 0 ] || die "(6) validator-1 started at height $h0, want 0 (fresh genesis)"
  cid="$(chain_id validator-1)"
  [ "$cid" = 1337 ] || die "(6) validator-1 reports chain_id '$cid', want exactly 1337"

  local saw_503=0 t h
  for ((t = 0; t < SOLO_OBSERVE; t += POLL_INTERVAL)); do
    code="$(probe validator-1 /ready)"
    [ "$code" = 503 ] && saw_503=1
    [ "$code" = 200 ] && halt_invalid_topology "/ready became 200 while only validator-1 was up"
    if h="$(height validator-1)" && [ "$h" -gt 0 ]; then
      halt_invalid_topology "chain advanced to height $h with only validator-1 up"
    fi
    sleep "$POLL_INTERVAL"
  done
  [ "$saw_503" = 1 ] || die "(6) validator-1 /ready was never 503 before the quorum"
  ok "(6) validator-1 alone: /health 200, /ready 503, chain frozen at height 0"
}

# ---------------------------------------------------------------------------
# (7)(8) Everyone up: health, readiness, chain id, validator set.
# ---------------------------------------------------------------------------
quorum_up() {
  log "starting all ${N} validators with 'up --wait'..."
  dc up -d --wait --no-build "${SERVICES[@]}"

  local s code t
  for s in "${SERVICES[@]}"; do
    code="$(probe "$s" /health)"
    [ "$code" = 200 ] || die "(7) $s /health = $code, want 200"
  done
  for s in "${SERVICES[@]}"; do
    for ((t = 0; t < READY_TIMEOUT; t += POLL_INTERVAL)); do
      code="$(probe "$s" /ready)"
      [ "$code" = 200 ] && break
      sleep "$POLL_INTERVAL"
    done
    [ "$code" = 200 ] || die "(7) $s /ready never reached 200 within ${READY_TIMEOUT}s"
  done
  ok "(7) all ${N} validators: /health 200 and /ready 200"

  local cid
  for s in "${SERVICES[@]}"; do
    cid="$(chain_id "$s")"
    [ "$cid" = 1337 ] || die "(8) $s reports chain_id '$cid', want exactly 1337"
    rpc "$s" get_validators '[]' > "$WORK/validators.$s.json"
  done
  CHAIN_ID_VERIFIED=1
  python3 - "$DEVNET_DIR/genesis.json" "$WORK" "${SERVICES[@]}" <<'PY' || die "(8) a node's live validator set differs from the genesis set"
import json, sys
genesis = json.load(open(sys.argv[1]))["validators"]
for s in sys.argv[3:]:
    r = json.load(open(f"{sys.argv[2]}/validators.{s}.json"))
    live = [v["public_key"] for v in r["result"]["validators"]]
    assert live == genesis, (s, "live validator set differs from genesis order")
PY
  ok "(8) every node reports chain_id 1337 and the ${N} genesis validators in genesis order"
}

# ---------------------------------------------------------------------------
# (9) Heights advance on every node.
# ---------------------------------------------------------------------------
heights_advance() {
  log "waiting for every node to reach height ${TARGET_HEIGHT} (<= ${HEIGHT_TIMEOUT}s)..."
  local t s h all line=""
  for ((t = 0; t < HEIGHT_TIMEOUT; t += POLL_INTERVAL)); do
    all=1
    line=""
    for s in "${SERVICES[@]}"; do
      h="$(height "$s")" || h=-1
      line+="$s=$h "
      [ "$h" -ge "$TARGET_HEIGHT" ] || all=0
    done
    [ "$all" = 1 ] && break
    sleep "$POLL_INTERVAL"
  done
  [ "$all" = 1 ] || die "(9) not every node reached height ${TARGET_HEIGHT} within ${HEIGHT_TIMEOUT}s: ${line}"
  ok "(9) every node advanced from 0 to >= ${TARGET_HEIGHT} after ~${t}s: ${line% }"
}

# ---------------------------------------------------------------------------
# (10) Identical blocks everywhere; every validator proposes in its slots.
# ---------------------------------------------------------------------------
blocks_agree_round_robin() {
  local s h c="" from to
  for s in "${SERVICES[@]}"; do
    h="$(height "$s")" || die "(10) could not read $s's height"
    if [ -z "$c" ] || [ "$h" -lt "$c" ]; then c="$h"; fi
  done
  log "common height C = $c; fetching blocks 1..$c from every node..."
  for s in "${SERVICES[@]}"; do
    : > "$WORK/blocks.$s.jsonl"
    for ((from = 1; from <= c; from += 50)); do
      to=$((from + 49)); [ "$to" -le "$c" ] || to="$c"
      { rpc "$s" get_blocks "[$from,$to]"; echo; } >> "$WORK/blocks.$s.jsonl"
    done
  done

  local args=()
  for s in "${SERVICES[@]}"; do args+=("$s=$WORK/blocks.$s.jsonl"); done
  local report
  report="$(python3 - "$DEVNET_DIR/genesis.json" "$DEVNET_DIR/manifest.json" "$c" "${args[@]}" <<'PY'
import json, sys
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + ALPHABET.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw

genesis = json.load(open(sys.argv[1]))
manifest = json.load(open(sys.argv[2]))
c = int(sys.argv[3])
nodes = [a.split("=", 1) for a in sys.argv[4:]]

# Genesis order is the round-robin order; block headers carry the key as hex.
vals = [b58decode(v).hex() for v in genesis["validators"]]
assert all(len(v) == 64 for v in vals), "a validator key is not 32 bytes"
assert vals == [v["pubkey_hex"] for v in manifest["validators"]], "base58/hex mismatch"
n = len(vals)

chains = {}
for name, path in nodes:
    blocks = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        assert "result" in r, (name, r.get("error"))
        blocks.extend(r["result"])
    chains[name] = [(b["height"], b["hash"], b["parent_hash"], b["proposer"].lower()) for b in blocks]

ref_name, ref = nodes[0][0], chains[nodes[0][0]]
assert [b[0] for b in ref] == list(range(1, c + 1)), (ref_name, "heights 1..C not contiguous")
for name, chain in chains.items():
    assert chain == ref, f"{name} disagrees with {ref_name} on blocks 1..{c}"
for prev, cur in zip(ref, ref[1:]):
    assert cur[2] == prev[1], f"block {cur[0]} does not link to block {prev[0]}"

counts = [0] * n
for height, _hash, _parent, proposer in ref:
    want = vals[height % n]
    assert proposer == want, f"block {height} proposed by {proposer[:8]}, round-robin wants {want[:8]}"
    counts[height % n] += 1
assert all(k >= 1 for k in counts), f"a validator never proposed: {counts}"

print(f"agreement: all {len(nodes)} nodes return identical blocks 1..{c} (hash, parent, proposer); "
      f"block {c} hash {ref[-1][1]}; block 1 parent (genesis) {ref[0][2]}")
print("round-robin: block h proposed by validators[h mod %d] for every h in 1..%d" % (n, c))
for i, k in enumerate(counts):
    print(f"proposer validator{i + 1} (key {vals[i][:8]}...): {k} blocks in 1..{c}")
PY
)" || die "(10) block agreement / round-robin check failed: $(sanitize "$report")"
  local line
  while IFS= read -r line; do log "      $line"; done <<<"$report"
  ok "(10) ${N} nodes agree on every block 1..$c; each block's proposer is validators[h mod ${N}]; all ${N} validators proposed"
}

# ---------------------------------------------------------------------------
# (11) Teardown and trace check.
# ---------------------------------------------------------------------------
teardown_and_verify() {
  log "tearing down (down -v --remove-orphans) and removing devnet/..."
  dc down -v --remove-orphans
  rm -rf "$DEVNET_DIR"
  CREATED_DEVNET=0
  [ ! -e "$DEVNET_DIR" ] || die "(11) devnet/ still exists after teardown"
  [ -z "$(git -C "$REPO" status --porcelain)" ] \
    || die "(11) git worktree is dirty after the run (harness must leave no trace)"
  ok "(11) torn down; devnet/ (keys + genesis) removed; git worktree unchanged"
}

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
main() {
  preflight
  check_compose_config         # (1)
  build_images                 # (2)
  absent_devnet_fails_closed   # (3)
  provision                    # (4)
  absent_genesis_fails_closed  # (5)
  solo_baseline                # (6)
  quorum_up                    # (7)(8)
  heights_advance              # (9)
  blocks_agree_round_robin     # (10)
  teardown_and_verify          # (11)

  log "all assertions passed (${PASS} checks)"
  note "evidence log: $EVIDENCE_LOG"
  [ "$FAIL" -eq 0 ] || exit 1
}

main "$@"

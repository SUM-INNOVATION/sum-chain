#!/usr/bin/env bash
# smoke-image.sh <image-ref>
#
# Boots the image as a one-validator NONPRODUCTION devnet (chain id 1337) and
# requires, from the host:
#   GET /health  -> 200
#   GET /ready   -> 200 once a block past genesis exists
#   GET /metrics -> tools/lane-b/wave1-monitor.sh verify passes (the counter
#                   family, all nine Wave 1 subsystems, two bounded labels)
#
# The fixture key is generated INSIDE the container by the image's own
# `sumchain keygen`, never written to the host and never printed. The
# container is removed on every exit path.
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: smoke-image.sh <image-ref>" >&2; exit 2; }
IMG=$1
HERE=$(cd "$(dirname "$0")" && pwd)
HP=${SMOKE_HEALTH_PORT:-18546}
NAME="sumchain-smoke-$$"
fail() { echo "SMOKE FAIL: $*" >&2; docker logs --tail 40 "$NAME" 2>&1 | grep -v -i 'private' >&2 || true; exit 1; }
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

# Everything below the entrypoint runs inside the container.
docker run -d --name "$NAME" -p "127.0.0.1:$HP:8546" --entrypoint sh "$IMG" -c '
  set -eu
  sumchain keygen --output /tmp/fixture-validator.json > /tmp/keygen.txt
  PK=$(sed -n "s/^Public key: //p" /tmp/keygen.txt)
  cat > /tmp/genesis.json <<EOF
{"chain_id":1337,"genesis_time":$(date +%s)000,"validators":["$PK"],"alloc":{},
 "params":{"block_time_ms":1000,"max_block_bytes":1000000,"max_txs_per_block":1000,"min_fee":1}}
EOF
  cat > /tmp/node.toml <<EOF
[node]
genesis = "/tmp/genesis.json"
data_dir = "/data"
validator_key = "/tmp/fixture-validator.json"
[consensus]
engine = "poa"
[network]
listen_addr = "/ip4/127.0.0.1/tcp/30303"
mdns = false
[rpc]
addr = "127.0.0.1:8545"
[health]
addr = "0.0.0.0:8546"
[logging]
level = "info"
json = false
EOF
  exec sumchain run --config /tmp/node.toml' >/dev/null

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$HP$1" || true; }
wait_for() {  # path, want, seconds
  local i
  for ((i = 0; i < $3; i++)); do
    [[ $(code "$1") == "$2" ]] && return 0
    docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -q true || fail "the container exited"
    sleep 1
  done
  fail "GET $1 did not return $2 within $3 s (last: $(code "$1"))"
}

wait_for /health 200 60
echo "ok   GET /health  -> 200"
wait_for /ready 200 90
echo "ok   GET /ready   -> 200 (a block past genesis exists)"
[[ $(code /metrics) == 200 ]] || fail "GET /metrics -> $(code /metrics)"
bash "$HERE/../lane-b/wave1-monitor.sh" verify "http://127.0.0.1:$HP" || fail "wave1-monitor.sh verify failed"
echo "SMOKE OK: $IMG serves /health, /ready and a complete /metrics."

#!/bin/sh
# snip-mirror-entrypoint.sh — entrypoint for the SNIP local-mirror compose preset.
#
# This is the disposable single-validator devnet SNIP uses for V2 client
# integration tests. NOT a production validator deployment. Production
# validators run on host/systemd with their own committed config.toml +
# operator-managed `keys/validator1.json` outside this Docker preset.
#
# Decision matrix (DB existence × mounted-key × extra-alloc):
#
#   chain DB? | mounted key? | auto key? | extra alloc? | action
#   ----------|--------------|-----------|--------------|---------------------------
#    no       | no           | n/a       | n/a          | fresh-dev: keygen +
#                                                          render + boot
#    no       | yes          | n/a       | n/a          | render from mounted +
#                                                          boot
#    yes      | yes          | *         | no           | resume with mounted key
#    yes      | no           | yes       | no           | resume with auto key
#    yes      | no           | no        | *            | HARD FAIL: orphan DB
#    yes      | *            | *         | yes          | HARD FAIL: alloc overlay
#                                                          is fresh-genesis-only
#
# Chain-DB detection uses the RocksDB sentinel `$DATA_DIR/CURRENT` plus at
# least one `MANIFEST-*` file. Neither the cached genesis nor the dev
# validator key alone count as DB presence.
#
# `down` (no -v): volume is preserved → resumes the same chain with the same
# validator. `down -v`: volume wiped → next `up` starts a new chain (fresh
# validator pubkey + fresh genesis).
#
# Genesis rendering uses Python rather than jq: Debian bookworm's jq (1.6)
# serializes integers above 2^53 as IEEE-754 floats (e.g. 1000000000000000000
# → 1e+18), which the chain's serde JSON balance parser rejects. Python's
# json module preserves arbitrary-precision integers natively.
set -eu

DATA_DIR="${DATA_DIR:-/data}"
KEY_FILE="${KEY_FILE:-$DATA_DIR/validator.key}"
GENESIS_OUT="${GENESIS_OUT:-$DATA_DIR/genesis.json}"
GENESIS_TEMPLATE="${GENESIS_TEMPLATE:-/config/genesis.template.json}"
MOUNTED_KEY="${MOUNTED_KEY:-/secrets/validator.key}"
EXTRA_ALLOC="${EXTRA_ALLOC:-/config/extra-alloc.json}"
RPC_ADDR="${RPC_ADDR:-0.0.0.0:8545}"
P2P_ADDR="${P2P_ADDR:-/ip4/0.0.0.0/tcp/30303}"

log() { printf '[snip-mirror] %s\n' "$*"; }
err() { printf '[snip-mirror] ERROR: %s\n' "$*" >&2; }

mkdir -p "$DATA_DIR"

db_exists() {
    [ -f "$DATA_DIR/CURRENT" ] && \
        ls "$DATA_DIR"/MANIFEST-* >/dev/null 2>&1
}

mounted_key_present() {
    [ -f "$MOUNTED_KEY" ]
}

auto_key_present() {
    [ -f "$KEY_FILE" ]
}

extra_alloc_present() {
    [ -f "$EXTRA_ALLOC" ]
}

# Render the genesis from $GENESIS_TEMPLATE: substitute __VALIDATOR_PUBKEY__,
# defensively strip a top-level `_` doc field, optionally merge an extra-alloc
# JSON object after fail-on-overlap and integer-balance validation, and write
# the result to $GENESIS_OUT. The Python interpreter is used in place of jq
# (see header comment); arbitrary-precision integers in alloc balances must
# survive round-trip without scientific-notation lossy reformatting.
render_genesis() {
    pubkey_arg="$1"
    out_arg="$2"
    extra_arg="${3:-}"
    PUBKEY_ARG="$pubkey_arg" OUT_ARG="$out_arg" EXTRA_ARG="$extra_arg" \
    TEMPLATE_PATH="$GENESIS_TEMPLATE" python3 - <<'PY'
import json
import os
import sys

template_path = os.environ["TEMPLATE_PATH"]
out_path = os.environ["OUT_ARG"]
pubkey = os.environ["PUBKEY_ARG"]
extra_path = os.environ.get("EXTRA_ARG", "")


def fail(msg):
    sys.stderr.write(f"[snip-mirror] ERROR: {msg}\n")
    sys.exit(1)


try:
    with open(template_path) as f:
        template = json.load(f)
except (OSError, ValueError) as e:
    fail(f"failed to read genesis template at {template_path}: {e}")

if not isinstance(template, dict):
    fail(f"genesis template at {template_path} must be a JSON object.")

template.pop("_", None)
template["validators"] = [pubkey]

if extra_path and os.path.exists(extra_path):
    try:
        with open(extra_path) as f:
            extra = json.load(f)
    except (OSError, ValueError) as e:
        fail(f"failed to read extra-alloc at {extra_path}: {e}")

    if not isinstance(extra, dict):
        fail(f"{extra_path} must be a JSON object of address->balance pairs.")

    extra.pop("_", None)

    for addr, bal in extra.items():
        # bool is a subclass of int in Python; reject it explicitly so a
        # mistyped `true`/`false` doesn't silently fund an address.
        if isinstance(bal, bool) or not isinstance(bal, int):
            fail(
                f"extra-alloc balance for {addr!r} must be an integer; got "
                f"{type(bal).__name__}={bal!r}"
            )

    template_alloc = template.get("alloc", {})
    if not isinstance(template_alloc, dict):
        fail("template .alloc must be a JSON object.")

    overlap = sorted(set(template_alloc) & set(extra))
    if overlap:
        for a in overlap:
            sys.stderr.write(
                f"[snip-mirror] ERROR: extra-alloc address {a!r} "
                f"already present in template alloc.\n"
            )
        fail(
            "extra-alloc.json overlaps with template alloc. Almost certainly "
            "a copy-paste error; remove the duplicates or use distinct "
            "addresses for your SNIP test keypairs."
        )

    merged = dict(template_alloc)
    merged.update(extra)
    template["alloc"] = merged

try:
    with open(out_path, "w") as f:
        json.dump(template, f, indent=2)
        f.write("\n")
except OSError as e:
    fail(f"failed to write rendered genesis to {out_path}: {e}")
PY
}

# ── Decision branch ──────────────────────────────────────────────────────────
if db_exists; then
    log "existing chain DB detected at $DATA_DIR — resume mode"

    if extra_alloc_present; then
        err "/config/extra-alloc.json is mounted but a chain DB already exists."
        err "Genesis allocations cannot fund accounts after the chain has started."
        err "Use a transaction/faucet from an externally-mounted funded key, or"
        err "wipe the volume with 'docker-compose down -v' to start a fresh chain."
        exit 1
    fi

    if mounted_key_present; then
        KEY_TO_USE="$MOUNTED_KEY"
        log "using mounted validator key at $MOUNTED_KEY"
    elif auto_key_present; then
        KEY_TO_USE="$KEY_FILE"
        log "using auto-generated dev validator key at $KEY_FILE"
    else
        err "Existing chain DB at $DATA_DIR but no validator key found at"
        err "$MOUNTED_KEY (mounted) or $KEY_FILE (auto). Mount the operator key,"
        err "or wipe the volume with 'docker-compose down -v' to start fresh."
        exit 1
    fi

    if [ ! -f "$GENESIS_OUT" ]; then
        err "Existing chain DB at $DATA_DIR but no cached genesis at $GENESIS_OUT."
        err "The volume is in an inconsistent state. Wipe with 'down -v' and retry."
        exit 1
    fi

    log "reusing cached genesis at $GENESIS_OUT (no re-render)"
else
    log "no chain DB at $DATA_DIR — fresh boot"

    if mounted_key_present; then
        KEY_TO_USE="$MOUNTED_KEY"
        log "using mounted validator key at $MOUNTED_KEY"
    else
        log "generating disposable dev validator key at $KEY_FILE"
        # Discard stdout: keygen prints the address (public info) but we
        # re-derive it via key-info below; suppressing reduces log noise.
        # The private seed is written to $KEY_FILE only — never logged.
        sumchain keygen --output "$KEY_FILE" >/dev/null
        KEY_TO_USE="$KEY_FILE"
    fi

    PUBKEY="$(sumchain key-info --key "$KEY_TO_USE" | awk '/Public Key:/ {print $3}')"
    if [ -z "${PUBKEY:-}" ]; then
        err "failed to extract validator pubkey from $KEY_TO_USE"
        exit 1
    fi
    log "validator pubkey: $PUBKEY"

    if [ ! -f "$GENESIS_TEMPLATE" ]; then
        err "genesis template not found at $GENESIS_TEMPLATE"
        exit 1
    fi

    if extra_alloc_present; then
        log "merging extra-alloc from $EXTRA_ALLOC (fail-on-overlap)"
        render_genesis "$PUBKEY" "$GENESIS_OUT" "$EXTRA_ALLOC"
    else
        render_genesis "$PUBKEY" "$GENESIS_OUT"
    fi
    log "rendered genesis written to $GENESIS_OUT"
fi

log "exec sumchain run --genesis $GENESIS_OUT --data-dir $DATA_DIR --validator-key <key>"
exec sumchain run \
    --genesis "$GENESIS_OUT" \
    --data-dir "$DATA_DIR" \
    --validator-key "$KEY_TO_USE" \
    --rpc-addr "$RPC_ADDR" \
    --p2p-addr "$P2P_ADDR"

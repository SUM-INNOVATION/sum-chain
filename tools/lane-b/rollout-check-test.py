#!/usr/bin/env python3
"""Fixture battery for the stage-1 rollout collector and `rollout-check.py`.

    python3 tools/lane-b/rollout-check-test.py [ROLLOUT_DOC]

EVERY FIXTURE HERE IS NONPRODUCTION. Peer IDs, digests, hashes and log lines
are constructed by this file. Nothing it prints is a measurement of any
validator, and none of it may be recorded as rollout evidence.

What it proves:

1. **The binary path the procedure hashes is the one the image contains.**
   The path is DERIVED from the Dockerfile (`ENTRYPOINT` binary name joined to
   the destination of the runtime-stage `COPY --from=builder` line that installs
   it) and every `sha256sum /usr/local/bin/...` in the rollout document must
   equal it. A rename on either side fails here instead of at the rollout.
   The same derived name must be the program every `<bin> backup|restore|info|
   run` line in the document invokes.

2. **The collector, run end to end.** `rollout-record.sh` is extracted from the
   document verbatim and run against `kubectl` and `curl` shims that emulate
   the image filesystem from (1): only the Dockerfile-derived path exists. Its
   output is then judged by `rollout-check.py`.

3. **Every rule bites.** Each case below breaks exactly one rule and asserts
   the checker exits NON-ZERO and names that rule. The `complete` case asserts
   exit 0, so a checker hard-wired to fail cannot pass this battery.

Nothing under the real tree is written to; every case works in a temp dir.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs/operations/activation-rollout-evidence.md"
CHECKER = ROOT / "tools/lane-b/rollout-check.py"
MONITOR = ROOT / "tools/lane-b/wave1-monitor.sh"

FIXTURE_SHA = "f" * 63 + "1"  # NONPRODUCTION
OTHER_SHA = "e" * 63 + "2"  # NONPRODUCTION
ACT = "a" * 64  # NONPRODUCTION activation digest
PROTO = "b" * 64  # NONPRODUCTION protocol digest
PROTO_OTHER = "c" * 64
CHAIN = "1"
GENESIS = "9" * 64  # NONPRODUCTION genesis sha256
GENESIS_OTHER = "8" * 64
# The production predecessor gates at their live heights (the checker's
# default). Every complete case below is production-shaped.
PRODUCTION_PREDECESSORS = {"v2_enabled_from_height": 5200000, "omninode_enabled_from_height": 6000000,
                           "education_enabled_from_height": 8900000,
                           "governance_enabled_from_height": 8900000}
STRAY_GATE = "subsystem_proof_unsupported_enabled_from_height"  # a remediation gate
COMMIT = "c" * 40  # NONPRODUCTION release commit
OTHER_COMMIT = "d" * 40
IMAGE_DIGEST = "sha256:" + "0" * 64  # NONPRODUCTION canonical manifest digest
OTHER_DIGEST = "sha256:" + "1" * 64
# The two children of that manifest, and the binary each carries (NONPRODUCTION).
CHILD_AMD64, BIN_AMD64 = "sha256:" + "2" * 64, FIXTURE_SHA
CHILD_ARM64, BIN_ARM64 = "sha256:" + "3" * 64, "f" * 63 + "3"
FOREIGN_CHILD = "sha256:" + "4" * 64


def ident(i: int) -> str:
    """A NONPRODUCTION 64-hex validator public key per validator index."""
    return format(i + 1, "x") * 64


def dockerfile_binary_path() -> str:
    text = (ROOT / "Dockerfile").read_text()
    runtime = text[text.rindex("\nFROM "):]  # the last stage is the runtime image
    entry = re.search(r'^ENTRYPOINT \["([^"]+)"', runtime, re.M)
    assert entry, "Dockerfile has no ENTRYPOINT [\"...\"] in its runtime stage"
    name = entry.group(1)
    copy = re.search(rf"^COPY --from=\S+ \S*/{re.escape(name)} (\S+)$", runtime, re.M)
    assert copy, f"no runtime COPY installs the ENTRYPOINT binary {name!r}"
    dest = copy.group(1)
    return dest + name if dest.endswith("/") else dest


def check_binary_path() -> list[str]:
    fails: list[str] = []
    want = dockerfile_binary_path()
    name = want.rsplit("/", 1)[1]
    doc = DOC.read_text()
    # The path ends at whitespace, a backtick, a pipe, a closing paren or a
    # quote -- `$(... sha256sum /usr/local/bin/sumchain)` must not read as
    # `sumchain)`.
    hashed = re.findall(r"sha256sum (/usr/local/bin/\S+?)[`\s|)\"']", doc)
    if not hashed:
        fails.append("the rollout document hashes no /usr/local/bin binary at all")
    for path in hashed:
        if path != want:
            fails.append(f"document hashes {path}; the Dockerfile installs {want}")
    for m in re.finditer(r"^\s*(sumchain[\w-]*) (backup|restore|info|run)\b", doc, re.M):
        if m.group(1) != name:
            fails.append(f"document invokes `{m.group(1)} {m.group(2)}`; the binary is `{name}`")
    print(f"  binary path derived from Dockerfile: {want}; document hashes {sorted(set(hashed))}")
    return fails


def extract_record_script() -> str:
    doc = DOC.read_text()
    m = re.search(r"```bash\n(#!/usr/bin/env bash\n# rollout-record\.sh.*?)```", doc, re.S)
    assert m, "rollout-record.sh not found in the document"
    return m.group(1)


KUBECTL = r"""#!/usr/bin/env bash
# NONPRODUCTION SHIM. Emulates the image: only $BINARY exists.
args=("$@")
while [[ ${args[0]} == -n || ${args[0]} == --namespace ]]; do args=("${args[@]:2}"); done
case "${args[0]}" in
  exec) pod=${args[1]}; cmd=${args[3]}; path=${args[4]}
        if [[ $cmd == sha256sum && $path == "$BINARY" ]]; then echo "$(cat "$FX/$pod.sha")  $path"
        elif [[ $cmd == "$BINARY" && $path == --version && -f "$FX/$pod.ver" ]]; then cat "$FX/$pod.ver"
        elif [[ $cmd == "$BINARY" && $path == --version ]]; then echo "error: unexpected argument '--version' found" >&2; exit 2
        elif [[ $cmd == sha256sum && $path == /config/genesis.json ]]; then echo "$(cat "$FX/$pod.genesis")  $path"
        else echo "$cmd: $path: No such file or directory" >&2; exit 1; fi ;;
  get)  if [[ ${args[1]} == node ]]; then cat "$FX/${args[2]}.arch" 2>/dev/null || exit 1
        elif [[ ${args[4]:-} == *nodeName* ]]; then echo "node-${args[2]}"
        else cat "$FX/${args[2]}.imageid"; fi ;;
  logs) cat "$FX/${args[1]}.log" ;;
  *) echo "shim: unsupported $*" >&2; exit 9 ;;
esac
"""

CURL = r"""#!/usr/bin/env bash
# NONPRODUCTION SHIM. http://<pod>.fixture/... -> $FX/<pod>.*
url=""; data=""
while [[ $# -gt 0 ]]; do case $1 in -d) data=$2; shift 2;; -H|-X|--max-time) shift 2;; -*) shift;; *) url=$1; shift;; esac; done
host=${url#http://}; pod=${host%%.fixture*}
if [[ $url == */metrics ]]; then cat "$FX/$pod.metrics"; exit 0; fi
case "$data" in
  *chain_getActivationStatus*) cat "$FX/$pod.status" ;;
  *get_block_by_height*) echo "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"proposer\":\"$(cat "$FX/$pod.ident")\"}}" ;;
  *get_peers*) echo '{"jsonrpc":"2.0","id":1,"result":[]}' ;;
  *) echo '{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}' ;;
esac
"""

METRICS = "# TYPE sumchain_tx_execution_errors_total counter\n" + "".join(
    f'sumchain_tx_execution_errors_total{{subsystem="{s}",code="{c}"}} 0\n'
    for s, c in [("nft", 2), ("docclass", 8), ("tax", 9), ("agreement", 11), ("legal", 12),
                 ("property", 13), ("healthcare", 14), ("employment", 15), ("finance", 16)]
)


def peer(i: int) -> str:
    return f"12D3KooWFixtureValidator{i}NONPRODUCTION"


def log_line(level: str, target: str, msg: str, ansi: bool) -> str:
    if ansi:  # what tracing's text formatter writes with colour on
        msg = re.sub(r"(\w+)=(\S+)", "\x1b[3m\\1\x1b[0m\x1b[2m=\x1b[0m\\2", msg)
        return f"\x1b[2m2026-09-23T00:00:00.000000Z\x1b[0m \x1b[32m {level}\x1b[0m \x1b[2m{target}\x1b[0m\x1b[2m:\x1b[0m {msg}"
    return f"2026-09-23T00:00:00.000000Z  {level} {target}: {msg}"


def make_pods(fx: Path, n: int, *, drop_handshake=None, refusal_on=None,
              digest_off=None, empty_log=None, no_image_digest=None,
              status_without_digest=None, metrics_missing=None, dup_ident=None,
              genesis_off=None, no_produced=None, gates=None, no_version=None,
              bad_version=None, silent=None, images=None, bins=None, archs=None,
              ver_commit=None) -> None:
    """images/bins/archs: {validator index: image digest / binary sha256 / node arch}."""
    gates = PRODUCTION_PREDECESSORS if gates is None else gates
    for i in range(n):
        pod = f"sumchain-validator-{i + 1}-0"
        proto = PROTO_OTHER if digest_off == i else PROTO
        (fx / f"{pod}.sha").write_text((bins or {}).get(i, BIN_AMD64) + "\n")
        if (archs or {}).get(i):
            (fx / f"node-{pod}.arch").write_text(archs[i])
        if no_version != i:  # 0.2.0 has no --version at all
            (fx / f"{pod}.ver").write_text(
                "sumchain 0.4.0\n" if bad_version == i else f"sumchain {(ver_commit or {}).get(i, COMMIT)}\n")
        (fx / f"{pod}.ident").write_text(ident(0) if dup_ident == i else ident(i))
        (fx / f"{pod}.genesis").write_text(GENESIS_OTHER if genesis_off == i else GENESIS)
        (fx / f"{pod}.imageid").write_text(
            "docker.io/fixture/node:latest" if no_image_digest == i
            else "docker.io/fixture/node@" + (images or {}).get(i, IMAGE_DIGEST))
        (fx / f"{pod}.metrics").write_text(
            "\n".join(l for l in METRICS.split("\n") if 'subsystem="healthcare"' not in l)
            if metrics_missing == i else METRICS)
        (fx / f"{pod}.status").write_text(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
            **({} if status_without_digest == i else {"digest": ACT}),
            "protocol_digest": proto, "chain_id": int(CHAIN),
            "current_height": 1000 + i,  # NONPRODUCTION
            "gates": [{"gate": g, "height": h, "active": True} for g, h in gates.items()]
                     + [{"gate": "x", "height": None, "active": False}]}}))
        lines = [log_line("INFO", "sumchain_p2p::network", f"Local peer ID: {peer(i)}", i == 0)
                 + ("\x1b[0m" if i == 0 else "")]
        if no_produced != i:
            lines.append(log_line("INFO", "sumchain::node",
                                  f"Produced block 0x{'ab' * 32} at height {1000 + i}", i == 0))
        for j in range(n):
            if j == i or drop_handshake == (i, j) or silent == i:
                continue
            peer_proto = PROTO_OTHER if digest_off == j else PROTO
            if peer_proto == proto:
                lines.append(log_line("INFO", "sumchain_node::node",
                                      "compatibility handshake accepted: peer enforces our "
                                      f"protocol digest peer={peer(j)} digest={proto}", i == 0))
            else:
                lines.append(log_line("WARN", "sumchain_node::node",
                                      f"REFUSING peer {peer(j)}: it enforces protocol digest "
                                      f"{peer_proto} but this node enforces {proto}.", False))
        if refusal_on == i:
            lines.append(log_line("WARN", "sumchain_node::node",
                                  f"REFUSING peer 12D3KooWStranger: it enforces protocol digest "
                                  f"{PROTO_OTHER} but this node enforces {proto}.", False))
        (fx / f"{pod}.log").write_text("" if empty_log == i else "\n".join(lines) + "\n")


# Tools the recorder and `wave1-monitor.sh verify` need, linked into a sandbox
# so a case can run with NO kubectl on PATH at all. Hermetic on purpose: GitHub's
# runners ship a real kubectl, which would otherwise be found and make the
# "kubectl missing" case test nothing.
SANDBOX_TOOLS = ["bash", "env", "jq", "awk", "grep", "sed", "tr", "wc", "cat", "mktemp",
                 "mv", "mkdir", "rm", "head", "tail", "sort", "cut", "date", "dirname", "basename"]


def sandbox_path(tmp: Path) -> str:
    box = tmp / "sandbox"
    box.mkdir()
    for t in SANDBOX_TOOLS:
        real = shutil.which(t)
        assert real, f"sandbox needs {t}"
        (box / t).symlink_to(real)
    return str(box)


def collect(tmp: Path, n: int, *, no_kubectl=False, binary=None, **kw) -> tuple[Path, str]:
    fx, out, shim = tmp / "fx", tmp / "out", tmp / "bin"
    for d in (fx, out, shim):
        d.mkdir()
    make_pods(fx, n, **kw)
    if not no_kubectl:
        (shim / "kubectl").write_text(KUBECTL)
    (shim / "curl").write_text(CURL)
    for s in shim.iterdir():
        s.chmod(0o755)
    script = tmp / "rollout-record.sh"
    script.write_text(extract_record_script())
    script.chmod(0o755)
    path = f"{shim}:{sandbox_path(tmp)}" if no_kubectl else f"{shim}:{os.environ['PATH']}"
    env = dict(os.environ, FX=str(fx), BINARY=binary or dockerfile_binary_path(), PATH=path)
    errs = ""
    for i in range(n):
        pod = f"sumchain-validator-{i + 1}-0"
        r = subprocess.run([str(script), pod, f"http://{pod}.fixture/", f"http://{pod}.fixture:8546",
                            str(out)], cwd=ROOT, env=env, capture_output=True, text=True)
        errs += r.stderr if r.returncode == 0 else f"[{pod} exit {r.returncode}] {r.stderr}"
    return out, errs


def parse_arch(record: Path) -> str | None:
    for line in record.read_text().splitlines():
        if line.startswith("node_architecture:"):
            return line.split(":", 1)[1].strip()
    return None


def write_record(path: Path, how: str | None = None) -> Path:
    """A release record as tools/release/release-record.py writes it (NONPRODUCTION)."""
    lines = {"release_commit": OTHER_COMMIT if how == "record_other_commit" else COMMIT,
             "pull_request": "#262", "approved_by": "reviewer", "workflow_run": "https://example.invalid/run",
             "canonical_tag": f"ghcr.io/sum-innovation/sum-chain:{COMMIT}",
             "canonical_digest": OTHER_DIGEST if how == "record_other_canonical" else IMAGE_DIGEST,
             "linux_amd64_digest": CHILD_AMD64, "linux_amd64_binary_sha256": BIN_AMD64,
             "linux_arm64_digest": CHILD_ARM64, "linux_arm64_binary_sha256": BIN_ARM64}
    if how == "record_no_arm64":
        del lines["linux_arm64_digest"], lines["linux_arm64_binary_sha256"]
    path.write_text("".join(f"{k}: {v}\n" for k, v in lines.items()))
    return path


def run_checker(out: Path, n: int, record: Path | None, *, genesis: str | None = GENESIS,
                validators: list[str] | None = None, commit: str | None = COMMIT,
                digest: str | None = IMAGE_DIGEST, extra: list[str] | None = None) -> tuple[int, str]:
    args = [sys.executable, str(CHECKER), "--validators", str(n),
            "--expected-chain-id", CHAIN] + (extra or [])
    if record is not None:
        args += ["--release-record", str(record)]
    if commit is not None:
        args += ["--expected-commit", commit]
    if digest is not None:
        args += ["--expected-image-digest", digest]
    for v in (validators if validators is not None else [ident(i) for i in range(n)]):
        args += ["--expected-validator", v]
    if genesis is not None:
        args += ["--expected-genesis-sha256", genesis]
    r = subprocess.run(args + [str(out)], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


# (name, validators, fixture kwargs, post-collect mutation, expected exit, must-contain)
CASES = [
    ("complete N=2", 2, {}, None, 0, "2/2 directed handshakes, 0 refusals"),
    ("complete N=3", 3, {}, None, 0, "6/6 directed handshakes, 0 refusals"),
    ("missing handshake v1->v0", 2, {"drop_handshake": (1, 0)}, None, 1, "MISSING HANDSHAKE"),
    ("missing handshake v0->v1", 2, {"drop_handshake": (0, 1)}, None, 1, "MISSING HANDSHAKE"),
    ("incompatibility refusal", 2, {"refusal_on": 0}, None, 1, "INCOMPATIBILITY REFUSAL"),
    ("validator on a different digest", 2, {"digest_off": 1}, None, 1, "DIGEST DISAGREEMENT"),
    ("activation digest differs, no refusal", 2, {}, "act_digest", 1, "DIGEST DISAGREEMENT on activation_digest"),
    ("empty log", 2, {"empty_log": 0}, None, 1, "MISSING RECORD"),
    ("missing validator record", 2, {}, "drop_record", 1, "MISSING RECORD"),
    ("missing log file", 2, {}, "drop_log", 1, "MISSING LOG"),
    ("binary of neither child", 2, {"bins": {0: OTHER_SHA}}, None, 1,
     "BINARY MISMATCH binary_sha256 " + OTHER_SHA + " is not the binary of either child"),
    # Architecture is never an input: the runtime picks the child for its node,
    # and the binary identifies which one it picked.
    ("validators on different platforms, same manifest", 2, {"bins": {1: BIN_ARM64}}, None, 0,
     "2/2 directed handshakes"),
    ("image_id names a child of the manifest", 2, {"images": {0: CHILD_AMD64, 1: CHILD_ARM64},
                                                  "bins": {1: BIN_ARM64}}, None, 0, "2/2 directed handshakes"),
    ("image_id is a child outside the approved manifest", 2, {"images": {1: FOREIGN_CHILD}}, None, 1,
     "IMAGE NOT FROM THE APPROVED MANIFEST"),
    ("swapped: amd64 child running the arm64 binary", 2, {"images": {0: CHILD_AMD64}, "bins": {0: BIN_ARM64}},
     None, 1, "image_id is the linux/amd64 child, but binary_sha256"),
    ("node architecture recorded as a diagnostic", 2, {"archs": {0: "amd64", 1: "arm64"},
                                                      "bins": {1: BIN_ARM64}}, "expect_arch", 0,
     "2/2 directed handshakes"),
    ("node architecture unavailable: recorded as such, never blocks", 2, {}, "expect_arch_unavailable", 0,
     "2/2 directed handshakes"),
    ("release record for another commit", 2, {}, "record_other_commit", 1, "RELEASE RECORD MISMATCH: it is for"),
    ("release record for another manifest", 2, {}, "record_other_canonical", 1,
     "RELEASE RECORD MISMATCH: its canonical digest"),
    ("release record missing the arm64 child", 2, {}, "record_no_arm64", 1, "lacks a valid linux/arm64"),
    ("no release record", 2, {}, "no_record", 1, "STOP: no --release-record"),
    ("missing binary_sha256 field", 2, {}, "blank_sha", 1, "MISSING FIELD binary_sha256"),
    ("gates_set recorded as a bare count", 2, {}, "gates_count", 1, "gates_set is a count"),
    # Production's genesis legitimately carries four predecessor heights; every
    # complete case above is that shape. The old count-of-0 rule refused it.
    ("a remediation gate set", 2, {"gates": {**PRODUCTION_PREDECESSORS, STRAY_GATE: 13300000}}, None, 1,
     "REMEDIATION GATE SET subsystem_proof_unsupported_enabled_from_height=13300000"),
    ("a predecessor gate missing (wrong genesis)", 2,
     {"gates": {k: v for k, v in PRODUCTION_PREDECESSORS.items() if not k.startswith("governance")}},
     None, 1, "MISSING PREDECESSOR GATE governance_enabled_from_height"),
    ("a predecessor gate at the wrong height", 2,
     {"gates": {**PRODUCTION_PREDECESSORS, "v2_enabled_from_height": 0}}, None, 1,
     "PREDECESSOR HEIGHT MISMATCH v2_enabled_from_height=0"),
    ("no gate set at all", 2, {"gates": {}}, None, 1, "MISSING PREDECESSOR GATE v2_enabled_from_height"),
    # The same gates in another order is the same set, not a disagreement.
    ("gates_set listed in another order", 2, {}, "gates_other", 0, "2/2 directed handshakes"),
    ("gates_set entry without a height", 2, {}, "gates_names", 1, "is not name=height"),
    ("nonproduction predecessors given explicitly", 2,
     {"gates": {"v2_enabled_from_height": 0, "education_enabled_from_height": 0}}, "devnet_predecessors", 0,
     "NOTE: nonproduction predecessor gates"),
    ("a remediation gate passed off as a predecessor", 2,
     {"gates": {STRAY_GATE: 0}}, "stray_as_predecessor", 1, "not on GATES_PREDATING_ACTIVATION_RECORDING"),
    ("operator's commit differs from the release record", 2, {}, "wrong_commit", 1,
     "RELEASE RECORD MISMATCH: it is for"),
    ("a validator's binary reports another commit", 2, {"ver_commit": {1: OTHER_COMMIT}}, None, 1,
     "COMMIT MISMATCH binary_version 'sumchain " + OTHER_COMMIT),
    ("release commit not supplied", 2, {}, "no_commit", 1, "STOP: --expected-commit"),
    ("approved manifest differs from the record", 2, {}, "wrong_digest", 1, "RELEASE RECORD MISMATCH"),
    ("image given by tag, not digest", 2, {}, "tag_digest", 1, "STOP: --expected-image-digest"),
    ("blank binary_version", 2, {}, "blank_version", 1, "MISSING FIELD binary_version"),
    ("blank validator_pubkey", 2, {}, "blank_ident", 1, "MISSING FIELD validator_pubkey"),
    ("blank genesis_sha256", 2, {}, "blank_genesis", 1, "MISSING FIELD genesis_sha256"),
    ("partial record (truncated)", 2, {}, "truncate", 1, "MISSING FIELD telemetry"),
    ("silence: a validator logged no handshake", 2, {"silent": 0}, None, 1, "MISSING HANDSHAKE"),
    ("duplicate validator identity", 2, {"dup_ident": 1}, None, 1, "DUPLICATE VALIDATOR IDENTITY"),
    ("unequal genesis hashes", 2, {"genesis_off": 1}, None, 1, "GENESIS DISAGREEMENT"),
    ("production genesis hash not supplied", 2, {}, "no_expected_genesis", 1,
     "STOP: the production genesis sha256 was not supplied"),
    ("genesis differs from the production hash", 2, {}, "wrong_expected_genesis", 1, "GENESIS MISMATCH"),
    ("expected identity not recorded", 2, {}, "wrong_expected_ident", 1, "VALIDATOR SET MISMATCH"),
    ("wrong chain id", 2, {}, "chain", 1, "CHAIN ID MISMATCH"),
    ("empty evidence directory", 2, {}, "empty_dir", 1, "MISSING RECORD"),
]


# The recorder ITSELF must refuse: exit non-zero, name the reason, and leave no
# record behind. Every case in CASES above runs the recorder successfully and
# then edits the record, so none of them tests this. (fixture kwargs,
# recorder-stderr text that must appear)
RECORDER_REFUSALS = [
    ("kubectl not installed", {"no_kubectl": True}, "required command 'kubectl' not found"),
    ("binary missing from the pod", {"binary": "/usr/local/bin/not-the-binary"},
     "hashing /usr/local/bin/sumchain in the pod failed"),
    ("image id carries no digest", {"no_image_digest": 0}, "carries no digest"),
    ("activation status lacks its digest", {"status_without_digest": 0},
     "chain_getActivationStatus returned no digest"),
    ("telemetry series absent", {"metrics_missing": 0}, "telemetry verify failed"),
    ("empty log (no peer ID)", {"empty_log": 0}, "no 'Local peer ID' line"),
    ("no produced block (identity unprovable)", {"no_produced": 0}, "no 'Produced block' line"),
    ("binary has no --version (0.2.0)", {"no_version": 0}, "cannot report its commit"),
    ("binary reports a version, not a commit", {"bad_version": 0},
     "is not 'sumchain <40-hex commit>'"),
]


def mutate(out: Path, how: str | None) -> None:
    rec = out / "sumchain-validator-1-0.record"
    if how == "drop_record":
        rec.unlink()
    elif how == "drop_log":
        (out / "sumchain-validator-1-0.log").unlink()
    elif how == "blank_sha":
        rec.write_text(re.sub(r"(?m)^binary_sha256:.*$", "binary_sha256:  ", rec.read_text()))
    elif how == "act_digest":
        rec.write_text(re.sub(r"(?m)^activation_digest:.*$", "activation_digest: " + "d" * 64, rec.read_text()))
    elif how == "gates_count":
        rec.write_text(re.sub(r"(?m)^gates_set:.*$", "gates_set:         3", rec.read_text()))
    elif how == "gates_other":
        rec.write_text(re.sub(r"(?m)^gates_set:.*$",
                              "gates_set:         " + ",".join(f"{k}={v}" for k, v in
                                                            reversed(list(PRODUCTION_PREDECESSORS.items()))),
                              rec.read_text()))
    elif how == "gates_names":
        rec.write_text(re.sub(r"(?m)^gates_set:.*$", "gates_set:         " + ",".join(PRODUCTION_PREDECESSORS),
                              rec.read_text()))
    elif how in ("blank_version", "blank_ident", "blank_genesis"):
        key = {"blank_version": "binary_version", "blank_ident": "validator_pubkey",
               "blank_genesis": "genesis_sha256"}[how]
        rec.write_text(re.sub(rf"(?m)^{key}:.*$", f"{key}: ", rec.read_text()))
    elif how == "truncate":
        rec.write_text("\n".join(rec.read_text().splitlines()[:4]) + "\n")
    elif how == "chain":
        rec.write_text(re.sub(r"(?m)^chain_id:.*$", "chain_id:          7", rec.read_text()))
    elif how == "empty_dir":
        for f in out.iterdir():
            f.unlink()


def main() -> int:
    failures: list[str] = []
    print("binary path:")
    failures += check_binary_path()

    print("cases (NONPRODUCTION fixtures):")
    for name, n, kw, how, want_exit, want_text in CASES:
        tmp = Path(tempfile.mkdtemp(prefix="rollout-check-"))
        try:
            out, errs = collect(tmp, n, **kw)
            if how in ("expect_arch", "expect_arch_unavailable"):
                want = ["amd64", "arm64"] if how == "expect_arch" else ["unavailable", "unavailable"]
                got = [parse_arch(out / f"sumchain-validator-{i + 1}-0.record") for i in range(n)]
                if got != want:
                    failures.append(f"{name}: node_architecture recorded as {got}, want {want}")
            mutate(out, how)
            record = None if how == "no_record" else write_record(tmp / "release-record.txt", how)
            kw_chk = {}
            if how == "no_expected_genesis":
                kw_chk["genesis"] = None
            elif how == "wrong_expected_genesis":
                kw_chk["genesis"] = GENESIS_OTHER
            elif how == "wrong_expected_ident":
                kw_chk["validators"] = [ident(0), ident(7)]
            elif how == "wrong_commit":
                kw_chk["commit"] = OTHER_COMMIT
            elif how == "no_commit":
                kw_chk["commit"] = None
            elif how == "wrong_digest":
                kw_chk["digest"] = OTHER_DIGEST
            elif how == "tag_digest":
                kw_chk["digest"] = "latest"
            elif how == "devnet_predecessors":
                kw_chk["extra"] = ["--predecessor-gate", "v2_enabled_from_height=0",
                                   "--predecessor-gate", "education_enabled_from_height=0"]
            elif how == "stray_as_predecessor":
                kw_chk["extra"] = ["--predecessor-gate", f"{STRAY_GATE}=0"]
            code, text = run_checker(out, n, record, **kw_chk)
            ok = code == want_exit and want_text in text
            print(f"  {'ok  ' if ok else 'FAIL'} {name:34s} expected exit {want_exit}, got {code}")
            if not ok:
                failures.append(f"{name}: exit {code}, wanted {want_exit} with {want_text!r}\n"
                                f"    collector stderr: {errs.strip()}\n    checker: {text.strip()}")
        finally:
            shutil.rmtree(tmp)

    print("recorder refusals (NONPRODUCTION fixtures): the recorder must exit non-zero and write nothing")
    for name, kw, want in RECORDER_REFUSALS:
        tmp = Path(tempfile.mkdtemp(prefix="rollout-record-"))
        try:
            out, errs = collect(tmp, 1, **kw)
            record = out / "sumchain-validator-1-0.record"
            leftover = sorted(p.name for p in out.glob(".*.record.*"))
            ok = ("exit 1]" in errs) and (want in errs) and not record.exists() and not leftover
            print(f"  {'ok  ' if ok else 'FAIL'} {name:34s} refused={'exit 1]' in errs} "
                  f"record_written={record.exists()}")
            if not ok:
                failures.append(f"recorder {name}: wanted a refusal naming {want!r} and no record; "
                                f"stderr: {errs.strip()} record={record.exists()} partial={leftover}")
        finally:
            shutil.rmtree(tmp)

    for f in failures:
        print(f"FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print(f"ROLLOUT CHECK BATTERY OK: {len(CASES)} checker cases + {len(RECORDER_REFUSALS)} "
          f"recorder refusals, binary path matches the Dockerfile.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
        else echo "$cmd: $path: No such file or directory" >&2; exit 1; fi ;;
  get)  cat "$FX/${args[2]}.imageid" ;;
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
              status_without_digest=None, metrics_missing=None) -> None:
    for i in range(n):
        pod = f"sumchain-validator-{i + 1}-0"
        proto = PROTO_OTHER if digest_off == i else PROTO
        (fx / f"{pod}.sha").write_text(FIXTURE_SHA + "\n")
        (fx / f"{pod}.imageid").write_text(
            "docker.io/fixture/node:latest" if no_image_digest == i
            else "docker.io/fixture/node@sha256:" + "0" * 64)
        (fx / f"{pod}.metrics").write_text(
            "\n".join(l for l in METRICS.split("\n") if 'subsystem="healthcare"' not in l)
            if metrics_missing == i else METRICS)
        (fx / f"{pod}.status").write_text(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
            **({} if status_without_digest == i else {"digest": ACT}),
            "protocol_digest": proto, "chain_id": int(CHAIN),
            "current_height": 1000 + i,  # NONPRODUCTION
            "gates": [{"gate": "x", "height": None, "active": False}]}}))
        lines = [log_line("INFO", "sumchain_p2p::network", f"Local peer ID: {peer(i)}", i == 0)
                 + ("\x1b[0m" if i == 0 else "")]
        for j in range(n):
            if j == i or drop_handshake == (i, j):
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


def run_checker(out: Path, n: int, sha: str = FIXTURE_SHA) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(CHECKER), "--validators", str(n),
                        "--expected-binary-sha256", sha, "--expected-chain-id", CHAIN, str(out)],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


# (name, validators, fixture kwargs, post-collect mutation, expected exit, must-contain)
CASES = [
    ("complete N=2", 2, {}, None, 0, "2/2 handshakes, 0 refusals"),
    ("complete N=3", 3, {}, None, 0, "6/6 handshakes, 0 refusals"),
    ("missing handshake line", 2, {"drop_handshake": (1, 0)}, None, 1, "MISSING HANDSHAKE"),
    ("incompatibility refusal", 2, {"refusal_on": 0}, None, 1, "INCOMPATIBILITY REFUSAL"),
    ("validator on a different digest", 2, {"digest_off": 1}, None, 1, "DIGEST DISAGREEMENT"),
    ("activation digest differs, no refusal", 2, {}, "act_digest", 1, "DIGEST DISAGREEMENT on activation_digest"),
    ("empty log", 2, {"empty_log": 0}, None, 1, "MISSING RECORD"),
    ("missing validator record", 2, {}, "drop_record", 1, "MISSING RECORD"),
    ("missing log file", 2, {}, "drop_log", 1, "MISSING LOG"),
    ("wrong binary sha", 2, {}, "wrong_sha", 1, "BINARY MISMATCH"),
    ("missing binary_sha256 field", 2, {}, "blank_sha", 1, "MISSING FIELD binary_sha256"),
    ("gates set at stage 1", 2, {}, "gates", 1, "gates_set is 3"),
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
    elif how == "gates":
        rec.write_text(re.sub(r"(?m)^gates_set:.*$", "gates_set:         3", rec.read_text()))
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
            mutate(out, how)
            sha = OTHER_SHA if how == "wrong_sha" else FIXTURE_SHA
            code, text = run_checker(out, n, sha)
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

#!/usr/bin/env python3
"""Stage 1 binary-rollout gate: decide from recorded evidence, not by eye.

    python3 tools/lane-b/rollout-check.py \\
        --validators N \\
        --expected-binary-sha256 <sha256 of the release binary file> \\
        --expected-chain-id <chain id> \\
        <evidence-dir>

`<evidence-dir>` holds, for every validator, the two files `rollout-record.sh`
(docs/operations/activation-rollout-evidence.md section 1.1) writes:

    <validator>.record   "key: value" lines
    <validator>.log      that validator's node log (kubectl logs, whole
                         current container, not a --since window)

Exit 0 only when EVERY rule holds. Exit 1 otherwise, exit 2 on usage.

The rule this file exists for is that SILENCE IS FAILURE. A missing record, a
missing field, a missing log, or a missing handshake line fails; nothing passes
by being absent. Below the enforcement height a peer that declares nothing is
admitted, so an absent handshake line means the exchange did not happen, not
that it passed.

Per validator, required and checked:
  * binary_sha256      equal to --expected-binary-sha256. The binary cannot
                       report its own commit (GIT_HASH is unset in every build,
                       so it logs "Commit: unknown"); the file hash is the only
                       identity it has.
  * image_id           present.
  * activation_digest  present, not "unavailable", identical on every validator.
  * protocol_digest    present, not "unavailable", identical on every validator.
  * chain_id           equal to --expected-chain-id.
  * current_height     an integer > 0.
  * gates_set          exactly 0 (stage 1 ships with every gate unset).
  * local_peer_id      present and distinct across validators; it is how the
                       handshake lines below are attributed to a validator.
  * telemetry          "OK" (wave1-monitor.sh verify passed).

Across the set:
  * exactly N validators with a record, N >= 2;
  * for every ordered pair (v, u), v != u, a line in v's log
    "compatibility handshake accepted" with peer=<u's local_peer_id> and
    digest=<the common protocol_digest>: N*(N-1) pairs, every one present;
  * ZERO refusal lines ("REFUSING peer ..." / "declared protocol digest ...
    but this binary enforces ...") in any log.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED = (
    "binary_sha256",
    "image_id",
    "activation_digest",
    "protocol_digest",
    "chain_id",
    "current_height",
    "gates_set",
    "local_peer_id",
    "telemetry",
)

ANSI = re.compile(r"\x1b\[[0-9;]*m")
ACCEPTED = "compatibility handshake accepted"
REFUSAL = re.compile(
    r"REFUSING peer \S+: it enforces protocol digest"
    r"|declared protocol digest \S+ but this binary enforces"
)
FIELD = re.compile(r"\b(peer|digest)=(\S+)")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def parse_record(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        out[key.strip()] = value.strip()
    return out


def handshake_lines(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """(accepted (peer, digest) pairs, refusal lines) from a node log.

    Handles the default text format (ANSI stripped) and the JSON format.
    """
    accepted: list[tuple[str, str]] = []
    refusals: list[str] = []
    for raw in text.splitlines():
        line = ANSI.sub("", raw).strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                fields = obj.get("fields", {}) or {}
                msg = str(fields.get("message", ""))
                if ACCEPTED in msg:
                    accepted.append((str(fields.get("peer", "")), str(fields.get("digest", ""))))
                elif REFUSAL.search(msg):
                    refusals.append(line)
                continue
        if REFUSAL.search(line):
            refusals.append(line)
        elif ACCEPTED in line:
            f = dict(FIELD.findall(line))
            accepted.append((f.get("peer", ""), f.get("digest", "")))
    return accepted, refusals


def check(evidence: Path, n: int, expected_sha: str, expected_chain: str) -> list[str]:
    failures: list[str] = []
    if n < 2:
        return [f"--validators {n}: a handshake needs at least two validators"]
    if not evidence.is_dir():
        return [f"evidence directory {evidence} does not exist"]

    records = {p.stem: parse_record(p) for p in sorted(evidence.glob("*.record"))}
    if len(records) != n:
        failures.append(
            f"MISSING RECORD: {len(records)} validator record(s) found, {n} required "
            f"({', '.join(records) or 'none'})"
        )
    if not records:
        return failures

    for name, rec in records.items():
        for key in REQUIRED:
            if not rec.get(key):
                failures.append(f"{name}: MISSING FIELD {key}")
        sha = rec.get("binary_sha256", "").lower()
        if sha and not HEX64.match(sha):
            failures.append(f"{name}: binary_sha256 {sha!r} is not a sha256")
        elif sha and sha != expected_sha.lower():
            failures.append(
                f"{name}: BINARY MISMATCH binary_sha256 {sha} != expected {expected_sha.lower()}"
            )
        for key in ("activation_digest", "protocol_digest"):
            if rec.get(key, "").startswith("unavailable"):
                failures.append(f"{name}: {key} is unavailable: {rec[key]}")
        if rec.get("chain_id") and rec["chain_id"] != expected_chain:
            failures.append(
                f"{name}: CHAIN ID MISMATCH chain_id {rec['chain_id']} != expected {expected_chain}"
            )
        h = rec.get("current_height", "")
        if h and (not h.isdigit() or int(h) <= 0):
            failures.append(f"{name}: current_height {h!r} is not a height above genesis")
        if rec.get("gates_set") and rec["gates_set"] != "0":
            failures.append(
                f"{name}: gates_set is {rec['gates_set']}; stage 1 requires 0 (this "
                f"validator is running a genesis with heights in it)"
            )
        if rec.get("telemetry") and rec["telemetry"] != "OK":
            failures.append(f"{name}: telemetry is {rec['telemetry']!r}, not OK")

    for key in ("activation_digest", "protocol_digest"):
        values = {name: rec.get(key, "") for name, rec in records.items() if rec.get(key)}
        if len(set(values.values())) > 1:
            failures.append(
                f"DIGEST DISAGREEMENT on {key}: "
                + ", ".join(f"{k}={v}" for k, v in values.items())
            )

    peer_of = {name: rec.get("local_peer_id", "") for name, rec in records.items()}
    ids = [p for p in peer_of.values() if p]
    if len(set(ids)) != len(ids):
        failures.append(f"local_peer_id is not distinct across validators: {peer_of}")

    digests = {rec.get("protocol_digest", "") for rec in records.values()}
    common = digests.pop() if len(digests) == 1 else None

    pairs_found = 0
    for name in records:
        log = evidence / f"{name}.log"
        if not log.is_file():
            failures.append(f"{name}: MISSING LOG {log.name}")
            continue
        accepted, refusals = handshake_lines(log.read_text(encoding="utf-8", errors="replace"))
        for line in refusals:
            failures.append(f"{name}: INCOMPATIBILITY REFUSAL: {line}")
        for other, other_peer in peer_of.items():
            if other == name:
                continue
            ok = bool(other_peer) and any(
                peer == other_peer and common is not None and digest == common
                for peer, digest in accepted
            )
            if ok:
                pairs_found += 1
            else:
                failures.append(
                    f"{name}: MISSING HANDSHAKE with {other} (peer={other_peer or '?'}, "
                    f"digest={common or '?'}): no accepted line"
                )

    required_pairs = n * (n - 1)
    if pairs_found != required_pairs:
        failures.append(f"HANDSHAKES {pairs_found}/{required_pairs} (N*(N-1) required)")
    return failures


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--validators", type=int, required=True)
    ap.add_argument("--expected-binary-sha256", required=True)
    ap.add_argument("--expected-chain-id", required=True)
    ap.add_argument("evidence", type=Path)
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2

    failures = check(
        args.evidence, args.validators, args.expected_binary_sha256, args.expected_chain_id
    )
    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        print(f"STAGE 1 NOT COMPLETE: {len(failures)} failure(s).")
        return 1
    n = args.validators
    print(
        f"STAGE 1 ROLLOUT EVIDENCE COMPLETE: {n} validators, identical binary, "
        f"digests and chain id, {n * (n - 1)}/{n * (n - 1)} handshakes, 0 refusals."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

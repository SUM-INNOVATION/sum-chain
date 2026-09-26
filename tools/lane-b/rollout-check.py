#!/usr/bin/env python3
"""Stage 1 binary-rollout gate: decide from recorded evidence, not by eye.

    python3 tools/lane-b/rollout-check.py \\
        --validators N \\
        --release-record <release-record.txt from the release workflow run> \\
        --expected-commit <40-hex release commit> \\
        --expected-image-digest sha256:<the approved CANONICAL manifest digest> \\
        --expected-chain-id <chain id> \\
        --expected-validator <64-hex public key>   (once per validator) \\
        --expected-genesis-sha256 <sha256 of the PRODUCTION genesis bytes> \\
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
  * image_id           pinned by digest to the approved canonical manifest
                       (--expected-image-digest), or to one of its two children
                       as the release record lists them. The container runtime
                       pulls the child for the node's own platform; nobody has
                       to say which platform that is.
  * binary_sha256      the binary of a child of that manifest, per the release
                       record. When image_id names a child, it must be THAT
                       child's binary (a swapped binary fails).
  * binary_version     exactly "sumchain <--expected-commit>".
  * node_architecture  optional diagnostic only; never required, never checked.
  * activation_digest  present, not "unavailable", identical on every validator.
  * protocol_digest    present, not "unavailable", identical on every validator.
  * chain_id           equal to --expected-chain-id.
  * current_height     an integer > 0.
  * gates_set          name=height pairs, EXACTLY the production predecessor
                       gates at their live heights (PREDECESSOR_GATES, or
                       --predecessor-gate for a nonproduction network). A
                       missing one means a genesis that silently disables a
                       live feature; an extra one is a Stage 1 remediation
                       height, and Stage 1 sets none.
  * validator_pubkey   64-hex, proven by possession; distinct; equal as a set
                       to the --expected-validator values.
  * genesis_sha256     64-hex; identical on every validator; equal to
                       --expected-genesis-sha256.
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
    "binary_version",
    "image_id",
    "activation_digest",
    "protocol_digest",
    "chain_id",
    "current_height",
    "gates_set",
    "local_peer_id",
    "validator_pubkey",
    "genesis_sha256",
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
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RELEASE_PLATFORMS = ("linux/amd64", "linux/arm64")

# The four gates production's genesis carries, at the heights live
# chain_getChainParams reported on 2026-09-23 (docs/operations/
# stage1-rollout-runbook.md section 2.2(d)). All four passed millions of blocks
# ago, and all four are on GATES_PREDATING_ACTIVATION_RECORDING. Any other gate
# with a height is a Stage 1 remediation height, and Stage 1 sets none.
PREDECESSOR_GATES = {
    "v2_enabled_from_height": 5_200_000,
    "omninode_enabled_from_height": 6_000_000,
    "education_enabled_from_height": 8_900_000,
    "governance_enabled_from_height": 8_900_000,
}
GENESIS_SRC = Path(__file__).resolve().parents[2] / "crates" / "genesis" / "src" / "lib.rs"


def predating_gates() -> set[str]:
    """GATES_PREDATING_ACTIVATION_RECORDING, read from the genesis crate.

    The gates that shipped in binaries which produced existing blocks, and may
    legitimately carry a height at or below the head. Read from the source, not
    copied, so the list cannot drift from the one the node enforces.
    """
    src = GENESIS_SRC.read_text()
    i = src.index("GATES_PREDATING_ACTIVATION_RECORDING")
    body = src[src.index("[", i): src.index("];", i)]
    names = set(re.findall(r'"([a-z_0-9]+_(?:enabled|required)_from_height)"', body))
    if len(names) < 10:
        raise SystemExit(f"could not read the predating gate list from {GENESIS_SRC} ({len(names)} names)")
    return names


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


def parse_gates(gs: str) -> dict[str, int] | str:
    """{gate: height} from a gates_set field, or an error message."""
    if gs == "none":
        return {}
    if gs.isdigit():
        return f"gates_set is a count ({gs}); the recorder must list name=height pairs"
    out: dict[str, int] = {}
    for item in gs.split(","):
        name, eq, height = item.partition("=")
        if not eq or not name or not height.isdigit():
            return f"gates_set entry {item!r} is not name=height"
        if name in out:
            return f"gates_set names {name} twice"
        out[name] = int(height)
    return out


def load_release(path: Path, commit: str, canonical: str) -> tuple[dict, list[str]]:
    """The release record, as tools/release/release-record.py writes it, checked
    against the commit and canonical digest the operator approved.

    Returns ({"canonical": digest, "children": {digest: (platform, binary sha256)}}, problems).
    """
    if not path.is_file():
        return {}, [f"release record {path} does not exist"]
    rec = parse_record(path)
    problems = []
    if rec.get("release_commit", "").lower() != commit.lower():
        problems.append(f"RELEASE RECORD MISMATCH: it is for commit {rec.get('release_commit')!r}, "
                        f"not {commit.lower()}")
    if rec.get("canonical_digest", "").lower() != canonical.lower():
        problems.append(f"RELEASE RECORD MISMATCH: its canonical digest is {rec.get('canonical_digest')!r}, "
                        f"the approved one is {canonical.lower()}")
    children: dict[str, tuple[str, str]] = {}
    for p in RELEASE_PLATFORMS:
        k = p.replace("/", "_")
        d, b = rec.get(f"{k}_digest", "").lower(), rec.get(f"{k}_binary_sha256", "").lower()
        if not DIGEST.match(d) or not HEX64.match(b):
            problems.append(f"release record lacks a valid {p} child digest and binary sha256")
            continue
        children[d] = (p, b)
    if len(children) == 2:
        ds, bs = list(children), [b for _, b in children.values()]
        if canonical.lower() in ds or len(set(bs)) != 2:
            problems.append("release record children are not distinct from each other and the manifest")
    return {"canonical": canonical.lower(), "children": children}, problems


def check(evidence: Path, n: int, release: dict, expected_chain: str,
          expected_validators: list[str] | None = None,
          expected_genesis: str | None = None,
          expected_commit: str | None = None,
          expected_image_digest: str | None = None,
          predecessors: dict[str, int] | None = None) -> list[str]:
    failures: list[str] = []
    predecessors = PREDECESSOR_GATES if predecessors is None else predecessors
    not_predating = sorted(set(predecessors) - predating_gates())
    if not_predating:
        return [f"predecessor gate(s) {not_predating} are not on GATES_PREDATING_ACTIVATION_RECORDING"]
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
        # The image: the approved canonical manifest, or one of its children.
        # Which child a node runs follows from its platform, which nobody has to
        # supply: the runtime chose it, and the binary hash identifies it.
        children = release["children"]
        img = rec.get("image_id", "").lower()
        pulled = img.rsplit("@", 1)[1] if "@" in img else ""
        if img and pulled != release["canonical"] and pulled not in children:
            failures.append(f"{name}: IMAGE NOT FROM THE APPROVED MANIFEST image_id {img!r} is neither "
                            f"@{release['canonical']} nor one of its children {sorted(children)}")
        sha = rec.get("binary_sha256", "").lower()
        by_bin = {b: (p, d) for d, (p, b) in children.items()}
        if sha and not HEX64.match(sha):
            failures.append(f"{name}: binary_sha256 {sha!r} is not a sha256")
        elif sha and sha not in by_bin:
            failures.append(f"{name}: BINARY MISMATCH binary_sha256 {sha} is not the binary of either child "
                            f"of the approved manifest")
        elif sha and pulled in children and children[pulled][1] != sha:
            failures.append(f"{name}: BINARY MISMATCH image_id is the {children[pulled][0]} child, but "
                            f"binary_sha256 {sha} is the {by_bin[sha][0]} child's binary")
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
        # Stage 1 sets no gate of its own. The predecessor gates production's
        # genesis carries must be present, at their live heights: a genesis
        # missing one starts normally and silently disables a live feature (the
        # consensus split of runbook section 2.2(d)). Any other gate with a
        # height is a remediation height, which Stage 1 must not set.
        gs = rec.get("gates_set", "")
        if gs:
            parsed = parse_gates(gs)
            if isinstance(parsed, str):
                failures.append(f"{name}: {parsed}")
            else:
                for g in sorted(set(predecessors) - set(parsed)):
                    failures.append(f"{name}: MISSING PREDECESSOR GATE {g} (live height "
                                    f"{predecessors[g]}); this genesis disables a live feature")
                for g in sorted(set(parsed) - set(predecessors)):
                    failures.append(f"{name}: REMEDIATION GATE SET {g}={parsed[g]}; Stage 1 "
                                    f"sets no height outside the predecessor gates")
                for g in sorted(set(parsed) & set(predecessors)):
                    if parsed[g] != predecessors[g]:
                        failures.append(f"{name}: PREDECESSOR HEIGHT MISMATCH {g}={parsed[g]}, "
                                        f"live height {predecessors[g]}")
        if rec.get("telemetry") and rec["telemetry"] != "OK":
            failures.append(f"{name}: telemetry is {rec['telemetry']!r}, not OK")
        for key in ("validator_pubkey", "genesis_sha256"):
            v = rec.get(key, "").lower()
            if v and not HEX64.match(v):
                failures.append(f"{name}: {key} {v!r} is not 64-hex")
        ver = rec.get("binary_version", "")
        if ver and expected_commit is not None and ver != f"sumchain {expected_commit.lower()}":
            failures.append(f"{name}: COMMIT MISMATCH binary_version {ver!r} != "
                            f"'sumchain {expected_commit.lower()}'")

    # The public validator identity, proven by possession: the recorder takes it
    # from a block this workload's own log says it produced. Two records naming
    # the same identity means one key is running in two places -- or one
    # workload was recorded twice -- and either way a validator is unaccounted
    # for.
    ident = {name: rec.get("validator_pubkey", "").lower() for name, rec in records.items()}
    present = [v for v in ident.values() if v]
    if len(set(present)) != len(present):
        failures.append(f"DUPLICATE VALIDATOR IDENTITY across records: {ident}")
    if expected_validators is not None:
        want = {v.lower() for v in expected_validators}
        if set(present) != want:
            failures.append(
                f"VALIDATOR SET MISMATCH: recorded {sorted(set(present))}, expected {sorted(want)}"
            )

    # Every validator must run byte-identical genesis, and it must be the
    # production genesis -- whose bytes are supplied separately, not taken from
    # any file in this repository.
    gen = {name: rec.get("genesis_sha256", "").lower() for name, rec in records.items()}
    if len({v for v in gen.values() if v}) > 1:
        failures.append("GENESIS DISAGREEMENT: " + ", ".join(f"{k}={v}" for k, v in gen.items()))
    if expected_genesis is not None:
        for name, v in gen.items():
            if v and v != expected_genesis.lower():
                failures.append(
                    f"{name}: GENESIS MISMATCH genesis_sha256 {v} != expected {expected_genesis.lower()}"
                )

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
    ap.add_argument("--release-record", type=Path,
                    help="release-record.txt from the release workflow run that published the manifest")
    ap.add_argument("--expected-chain-id", required=True)
    ap.add_argument("--expected-validator", action="append", default=[],
                    help="a validator public key, 64-hex; give it once per validator")
    ap.add_argument("--expected-genesis-sha256",
                    help="sha256 of the PRODUCTION genesis bytes, supplied by the owner")
    ap.add_argument("--expected-commit", help="the 40-hex commit the release image was built from")
    ap.add_argument("--expected-image-digest",
                    help="sha256:<64-hex> digest of the approved CANONICAL manifest (never a tag, never a platform)")
    ap.add_argument("--predecessor-gate", action="append", default=None, metavar="NAME=HEIGHT",
                    help="NONPRODUCTION networks only: replace the production predecessor gates")
    ap.add_argument("evidence", type=Path)
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2

    # These two are not optional, and their absence is a STOP with its own
    # message rather than a usage error: the rollout must not proceed on any
    # substitute, and a local or committed genesis is exactly the substitute an
    # operator under time pressure reaches for.
    if not args.expected_genesis_sha256:
        print("STOP: the production genesis sha256 was not supplied (--expected-genesis-sha256).")
        print("      Stage 1 evidence cannot be complete without it. Do not substitute the")
        print("      hash of any committed or locally generated genesis file.")
        return 1
    if not args.expected_commit or not HEX40.match(args.expected_commit.lower()):
        print("STOP: --expected-commit must be the full 40-hex release commit.")
        return 1
    if not args.expected_image_digest or not DIGEST.match(args.expected_image_digest.lower()):
        print("STOP: --expected-image-digest must be the approved canonical manifest's "
              "sha256:<64-hex> digest, never a tag.")
        return 1
    if args.release_record is None:
        print("STOP: no --release-record. The approved manifest's children and their binaries are")
        print("      read from the release record of the run that published it.")
        return 1
    release, problems = load_release(args.release_record, args.expected_commit, args.expected_image_digest)
    if problems:
        for pr in problems:
            print(f"FAIL: {pr}")
        print("STAGE 1 NOT COMPLETE: the release record does not describe the approved manifest.")
        return 1
    predecessors = None
    if args.predecessor_gate is not None:
        parsed = parse_gates(",".join(args.predecessor_gate))
        if isinstance(parsed, str):
            print(f"usage: --predecessor-gate: {parsed}")
            return 2
        predecessors = parsed
        print(f"NOTE: nonproduction predecessor gates {parsed}; production uses {PREDECESSOR_GATES}.")
    if len(args.expected_validator) != args.validators:
        print(f"STOP: {len(args.expected_validator)} --expected-validator given, "
              f"{args.validators} required -- one public key per validator.")
        return 1

    failures = check(
        args.evidence, args.validators, release, args.expected_chain_id,
        args.expected_validator, args.expected_genesis_sha256,
        args.expected_commit, args.expected_image_digest, predecessors,
    )
    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        print(f"STAGE 1 NOT COMPLETE: {len(failures)} failure(s).")
        return 1
    n = args.validators
    print(
        f"STAGE 1 ROLLOUT EVIDENCE COMPLETE: {n} validators with the expected public "
        f"identities, release commit, children of the approved manifest, genesis, "
        f"predecessor gates, digests and chain id, "
        f"{n * (n - 1)}/{n * (n - 1)} directed handshakes, 0 refusals."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

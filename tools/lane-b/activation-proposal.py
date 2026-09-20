#!/usr/bin/env python3
"""Derive, and then re-derive on demand, the tracked activation proposal.

# Why this exists

The proposal used to be an untracked `PROPOSED-ACTIVATION.json` at the
repository root, generated once and then deleted. Two things were wrong with
that. It was not reviewable -- nothing in a pull request showed it, and nothing
noticed when it drifted from the packet it was supposed to summarise. And it
carried ABSOLUTE HEIGHTS, which are stale at roughly 57,524 blocks a day: a
number written on Monday describes a chain that no longer exists on Tuesday,
and there is no marker in a bare integer that says so.

This script writes `docs/lane-a/ACTIVATION-PROPOSAL.json` instead, under a
tracked path, and it writes **no heights at all**.

# What it derives rather than restates

The wave membership is READ OUT OF the packet, from the `**6. Recommended
wave.**` line under each `### R<n>` heading. Hand-typing thirty-nine gate names
into a second file is how the two files come to disagree; the disagreement is
then invisible, because both look plausible. `--check` re-runs the derivation
against the committed artifact and fails on any difference.

# What it refuses

Four things must not acquire a height, and `--check` fails if any of them does:

* `docclass_stake_escrow_enabled_from_height` (R2) -- deferred INDEFINITELY on
  an owner decision about value that has already been destroyed (packet 3.1).
* `account_root_enabled_from_height` (N3) -- blocked on an external
  measurement of the production `cf::STATE` row count (packet 3.3).
* OC-3 and SC-8 -- audit rows in `ACTIVATION-AUDIT.md`, **not gates.** Neither
  has an `*_enabled_from_height` field anywhere in the tree, and the check
  asserts that rather than assuming it: if a gate is ever added for either,
  this fails and somebody has to decide deliberately.

It also fails if ANY gate in the artifact carries something other than the
unset marker, which is the stage-1 invariant: heights belong to the later
activation-configuration commit, which is not this one.

Usage:
    python3 tools/lane-b/activation-proposal.py            # check (exit 1 on drift)
    python3 tools/lane-b/activation-proposal.py --write    # regenerate
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "docs/lane-a/ACTIVATION-DECISION-PACKET.md"
AUDIT = ROOT / "docs/lane-a/ACTIVATION-AUDIT.md"
ARTIFACT = ROOT / "docs/lane-a/ACTIVATION-PROPOSAL.json"
GENESIS_SRC = ROOT / "crates/genesis/src/lib.rs"

#: The marker every height carries. Not `null`, not `0`, not `"TBD"` -- a
#: string that cannot be mistaken for a number by any reader, and that a
#: `ChainParams` loader would refuse outright rather than silently coerce.
UNSET = "UNSET-PENDING-OWNER-AUTHORIZATION"

#: The wave sizes the packet's Part 2 states. Asserted against the derivation,
#: so a packet edit that moves a gate between waves fails here instead of
#: producing a proposal nobody compared with anything.
EXPECTED_COUNTS = {"1": 24, "2a": 4, "2b": 8, "2c": 2, "3": 1}

#: Days after the recalculation head, from packet 2.3/2.4. These are the LEAD
#: TIMES, and they are preserved across recalculation -- see
#: `lead_time_rule` in the artifact.
WAVE_OFFSET_DAYS = {"1": 14, "2a": 28, "2b": 42, "2c": 56, "3": 70}

WAVE_COST_SHAPE = {
    "1": "refusal only",
    "2a": "key space",
    "2b": "row content / existence",
    "2c": "value and fee",
    "3": "block existence",
}

PEER_GATE = "peer_protocol_declaration_required_from_height"

MUST_REMAIN_UNSET = [
    "docclass_stake_escrow_enabled_from_height",
    "account_root_enabled_from_height",
]

#: Audit rows with NO gate. Confirmed by `no_gate_exists_for` below.
EXTERNAL_EVIDENCE_ROWS = ["OC-3", "SC-8"]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def derive_waves() -> dict[str, list[dict[str, str]]]:
    """`{wave: [{id, field}]}`, read out of the packet's field 6."""
    text = read(PACKET)
    current: tuple[str, str] | None = None
    waves: dict[str, list[dict[str, str]]] = {}
    for line in text.splitlines():
        heading = re.match(r"^### (R\d+) — `([a-z0-9_]+)`", line)
        if heading:
            current = (heading.group(1), heading.group(2))
            continue
        field6 = re.match(r"^\*\*6\. Recommended wave\.\*\*\s*(.*)$", line)
        if not field6:
            continue
        if current is None:
            continue
        wave = re.match(r"Wave (\w+)[.,]", field6.group(1))
        if wave:
            waves.setdefault(wave.group(1), []).append(
                {"id": current[0], "field": current[1]}
            )
        current = None
    return waves


def no_gate_exists_for(row: str) -> bool:
    """Is `row` really an audit row with no activation gate behind it?

    Derived, not assumed: the audit row's own text is searched for an
    `*_enabled_from_height` field name, and the genesis gate declarations are
    searched for anything naming the row. Either hit means the row has grown a
    gate and the proposal has to account for it.
    """
    audit = read(AUDIT)
    rows = [l for l in audit.splitlines() if l.strip().startswith(f"| {row} |")]
    if not rows:
        raise SystemExit(f"{row}: no such audit row -- the audit was renumbered")
    for line in rows:
        if re.search(r"[a-z0-9_]+_enabled_from_height", line):
            return False
    genesis = read(GENESIS_SRC)
    for line in genesis.splitlines():
        if row in line and "_from_height" in line:
            return False
    return True


def build() -> dict:
    waves = derive_waves()
    counts = {w: len(g) for w, g in waves.items()}
    if counts != EXPECTED_COUNTS:
        raise SystemExit(
            f"derived wave counts {counts} != the packet's Part 2 table "
            f"{EXPECTED_COUNTS}. One of the two moved; neither is edited here."
        )
    for row in EXTERNAL_EVIDENCE_ROWS:
        if not no_gate_exists_for(row):
            raise SystemExit(
                f"{row} now names an activation gate. It was carried as an "
                f"external-evidence row with no gate; that is no longer true "
                f"and the proposal has to be re-decided, not regenerated."
            )

    common_prereqs = [
        "STAGE 1 COMPLETE: every validator is running the exact release binary "
        "with all activation gates UNSET, proven per "
        "docs/operations/activation-rollout-evidence.md §1 (binary sha256, "
        "activation digest, chain id, current height, and a successful peer "
        "compatibility handshake recorded for EVERY validator).",
        "Every validator received BYTE-IDENTICAL genesis bytes "
        "(docs/operations/activation-rollout-evidence.md §3).",
        "`ChainParams::validate` run against the EXACT committed genesis, and a "
        "restart performed from an EXISTING populated database, not a fresh one "
        "(docs/operations/activation-rollout-evidence.md §2).",
    ]

    wave_entries = []
    for wave in ["1", "2a", "2b", "2c", "3"]:
        days = WAVE_OFFSET_DAYS[wave]
        prereqs = list(common_prereqs) if wave == "1" else []
        if wave == "1":
            prereqs = [
                f"`{PEER_GATE}` is set STRICTLY BELOW the earliest behavioural "
                f"gate in this wave -- not merely at or below it -- with at "
                f"least 48 hours of observation between the two heights. The "
                f"load rule (packet §0.7 rule 4) only requires `<=`; 48 hours "
                f"earlier is the acceptance criterion, because a shared height "
                f"gives an operator no window in which to see enforcement "
                f"working before behaviour changes under it.",
                "R5 `healthcare_authorization_enabled_from_height` at or below "
                "R30 `healthcare_consent_subject_signature_enabled_from_height` "
                "(packet §0.7 rule 5, refused at load otherwise). A shared wave "
                "height satisfies it.",
                "Every client that submits `GrantConsent` upgraded to the "
                "`ConsentGrantRequest` payload (R30), and the four R36-R39 "
                "client payload changes rolled out (packet 2.3, Wave 0).",
                "`tax_getActiveIssuers` and `finance_getActiveIssuers` "
                "enumerated and recorded: R31 freezes whatever is there.",
                "`docclass_getConfig` read: R25 is the one gate whose direction "
                "of effect depends on deployed configuration.",
                "`sumchain_tx_execution_errors_total` scraping and alerting "
                "live on every validator, per "
                "docs/operations/wave1-activation-monitoring.md.",
            ] + prereqs
        else:
            previous = {"2a": "1", "2b": "2a", "2c": "2b", "3": "2c"}[wave]
            prereqs = [
                f"Wave {previous} observed for its full interval with no "
                f"unexplained movement in its stated signal.",
                f"`{PEER_GATE}` already enforcing from Wave 1 (it is a single "
                f"height and is not re-set per wave).",
            ]
        if wave == "2a":
            prereqs.append(
                "Node-level disk usage baselined before the height: R3, R12 and "
                "R22 add rows and no metric exposes per-family row counts."
            )
            prereqs.append(
                "Every off-chain consumer that recomputes a `CollectionId` told "
                "the height (R28). This is invisible on-chain and is the single "
                "most likely silent break in the schedule."
            )
        if wave == "2b":
            prereqs.append(
                "`docclass_getIssuers` and the identity roots enumerated: R21 "
                "and R24 freeze whatever is there."
            )
        wave_entries.append(
            {
                "wave": wave,
                "cost_shape": WAVE_COST_SHAPE[wave],
                "gate_count": len(waves[wave]),
                "offset_from_recalculation_head": {
                    "expression": f"H + {days} * BLOCKS_PER_DAY",
                    "days": days,
                    "note": (
                        "H is the chain head at the moment of recalculation, and "
                        "BLOCKS_PER_DAY must be RE-MEASURED then. The last "
                        "measurement was 57,524 blocks/day against a "
                        "two-validator set (packet §0.3); it is not a constant "
                        "of the protocol and changes when the validator set "
                        "changes."
                    ),
                },
                "prerequisites": prereqs,
                "gates": [
                    {"id": g["id"], "field": g["field"], "height": UNSET}
                    for g in sorted(waves[wave], key=lambda g: int(g["id"][1:]))
                ],
            }
        )

    return {
        "schema": "sumchain.activation-proposal/v1",
        "generated_by": "tools/lane-b/activation-proposal.py",
        "derived_from": {
            "packet": "docs/lane-a/ACTIVATION-DECISION-PACKET.md",
            "field": "**6. Recommended wave.**",
            "audit": "docs/lane-a/ACTIVATION-AUDIT.md",
        },
        "status": (
            "STAGE 1 ARTIFACT. NO HEIGHT IS SET ANYWHERE IN THIS FILE AND NONE "
            "MAY BE ADDED HERE. The owner has not authorized recalculation. "
            "Absolute heights belong to the separate stage-2 "
            "activation-configuration commit."
        ),
        "deployment_stages": [
            {
                "stage": 1,
                "name": "binary rollout",
                "what": (
                    "Deploy the exact release binary to every validator with "
                    "ALL activation gates still UNSET. The failed-receipt "
                    "telemetry (`sumchain_tx_execution_errors_total`, labelled "
                    "by subsystem and code) must already be present in that "
                    "binary, because it is the signal the stage-2 waves are "
                    "monitored with."
                ),
                "complete_when": (
                    "Every validator has all five records of "
                    "docs/operations/activation-rollout-evidence.md §1."
                ),
            },
            {
                "stage": 2,
                "name": "activation configuration",
                "what": (
                    "Only after stage 1 completion is PROVEN: recalculate the "
                    "heights from the then-current head, commit the release "
                    "genesis configuration, validate it, deploy it."
                ),
                "not_in_this_commit": True,
            },
        ],
        "height_marker": UNSET,
        "derivation_rule": {
            "floor": (
                "Every height must be STRICTLY ABOVE the chain head at the "
                "moment the genesis is written (packet §0.4). A height that has "
                "already passed is refused at startup, which is the safe "
                "direction."
            ),
            "peer_protocol": (
                f"`{PEER_GATE}` must be at or below the earliest open "
                f"remediation gate or the genesis is refused at load (packet "
                f"§0.7 rule 4). ACCEPTANCE CRITERION, stricter than the load "
                f"rule: it goes BEFORE the earliest behavioural gate, with at "
                f"least 48 hours of observation before Wave 1."
            ),
            "healthcare_pair": (
                "`healthcare_authorization_enabled_from_height` (R5) at or "
                "before `healthcare_consent_subject_signature_enabled_from_height` "
                "(R30). Refused at load otherwise, on the genesis path and the "
                "restart path alike (packet §0.7 rule 5)."
            ),
            "lead_time_rule": (
                "THE EXISTING WAVE 1 LEAD TIME IS PRESERVED AFTER "
                "RECALCULATION. Fourteen days from the recalculation head, not "
                "fourteen days from the head this schedule was first drafted "
                "against, and NOT shortened to recover time lost to a slipped "
                "rollout. Compressing the lead to catch up is precisely the "
                "move that produces a mixed-binary fork: the whole function of "
                "the lead is to give every operator time to be on the new "
                "binary before behaviour changes under it, and a slipped "
                "rollout is evidence that MORE time is needed, not less."
            ),
            "abort_rule": (
                "If any validator misses the configuration rollout, STOP BEFORE "
                f"the `{PEER_GATE}` enforcement height. Do not continue toward "
                "Wave 1. See docs/operations/activation-rollout-evidence.md §4 "
                "for the stop condition and the two ways out of it."
            ),
        },
        "wave_0": {
            "name": "compatibility enforcement -- a prerequisite, not an activation",
            "gates": [{"id": "N1", "field": PEER_GATE, "height": UNSET}],
            "note": (
                "Not a choice: the genesis is refused at load unless this is set "
                "at or below the earliest open remediation gate. It is decided "
                "WITH Wave 1, not after it. Wave 0 also holds the thing that is "
                "not a height at all -- the binary rollout, which is stage 1."
            ),
        },
        "waves": wave_entries,
        "must_remain_unset": [
            {
                "field": "docclass_stake_escrow_enabled_from_height",
                "id": "R2",
                "why": (
                    "DEFERRED INDEFINITELY. Blocked on an owner decision about "
                    "value that has already been destroyed, not on a schedule "
                    "(packet 3.1). It is not in a wave and deliberately has no "
                    "proposed height."
                ),
            },
            {
                "field": "account_root_enabled_from_height",
                "id": "N3",
                "why": (
                    "Blocked on an EXTERNAL MEASUREMENT -- the production "
                    "`cf::STATE` row count, against the acceptance threshold in "
                    "docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md §1.5 (packet "
                    "3.3). Not settleable from this worktree."
                ),
            },
            {
                "row": "OC-3",
                "why": (
                    "An audit row, NOT a gate. No `*_enabled_from_height` field "
                    "exists for it anywhere in the tree, which this generator "
                    "derives rather than assumes. External evidence: the "
                    "identity of the tree the designated count of thirteen was "
                    "taken against."
                ),
            },
            {
                "row": "SC-8",
                "why": (
                    "An audit row, NOT a gate. No `*_enabled_from_height` field "
                    "exists for it anywhere in the tree. External evidence: the "
                    "deployed operator configuration for the RPC surface."
                ),
            },
        ],
        "out_of_band": [
            {
                "id": "N2",
                "field": "application_journal_enabled_from_height",
                "height": UNSET,
                "why": "Not a member of any wave; its own readiness question.",
            }
        ],
        "counts": {
            "scheduled_remediation_gates": sum(EXPECTED_COUNTS.values()),
            "plus_peer_protocol": 1,
            "total_in_this_proposal": sum(EXPECTED_COUNTS.values()) + 1,
            "by_wave": EXPECTED_COUNTS,
        },
    }


def every_height(obj) -> list[tuple[str, object]]:
    """`(json path, value)` for every `height` key, at any depth."""
    out: list[tuple[str, object]] = []

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "height":
                    out.append((f"{path}.{k}", v))
                else:
                    walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")

    walk(obj, "$")
    return out


def check(doc: dict) -> list[str]:
    """Every invariant, as a list of failures."""
    failures: list[str] = []

    for path, value in every_height(doc):
        if value != UNSET:
            failures.append(
                f"{path} carries {value!r}. Stage 1 sets NO heights; the owner "
                f"has not authorized recalculation."
            )

    # No bare integer anywhere that could be a stale absolute height.
    flat = json.dumps(doc)
    for m in re.finditer(r"\b1[0-9]{7}\b", flat):
        failures.append(
            f"a bare eight-digit number {m.group(0)!r} appears; that is the "
            f"shape of a stale absolute height"
        )

    fields = {g["field"] for w in doc["waves"] for g in w["gates"]}
    fields |= {g["field"] for g in doc["wave_0"]["gates"]}
    for entry in doc["must_remain_unset"]:
        field = entry.get("field")
        if field and field in fields:
            failures.append(
                f"{field} appears in a wave. It must remain unset: {entry['why']}"
            )

    for row in EXTERNAL_EVIDENCE_ROWS:
        if not no_gate_exists_for(row):
            failures.append(f"{row} has acquired an activation gate")

    counts = {w["wave"]: w["gate_count"] for w in doc["waves"]}
    if counts != EXPECTED_COUNTS:
        failures.append(f"wave counts {counts} != {EXPECTED_COUNTS}")

    total = sum(len(w["gates"]) for w in doc["waves"]) + len(doc["wave_0"]["gates"])
    if total != 40:
        failures.append(f"{total} gates carried, expected 39 + the peer gate = 40")

    return failures


def main() -> int:
    write = "--write" in sys.argv
    built = build()

    if write:
        ARTIFACT.write_text(json.dumps(built, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {ARTIFACT.relative_to(ROOT)}")

    if not ARTIFACT.exists():
        print(f"FAIL: {ARTIFACT.relative_to(ROOT)} does not exist", file=sys.stderr)
        return 1

    committed = json.loads(read(ARTIFACT))
    failures = check(committed)

    if committed != built:
        failures.append(
            "the committed artifact differs from what the packet derives. "
            "Re-run with --write and review the diff; do not edit the artifact "
            "by hand."
        )

    for f in failures:
        print(f"FAIL: {f}", file=sys.stderr)
    if failures:
        return 1

    print(
        f"ACTIVATION PROPOSAL OK: {sum(EXPECTED_COUNTS.values())} scheduled "
        f"remediation gates + {PEER_GATE}, "
        f"{ {w: EXPECTED_COUNTS[w] for w in ['1','2a','2b','2c','3']} }, "
        f"every height {UNSET}, "
        f"{len([e for e in committed['must_remain_unset'] if 'field' in e])} gates "
        f"and {len(EXTERNAL_EVIDENCE_ROWS)} gateless audit rows held unset."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

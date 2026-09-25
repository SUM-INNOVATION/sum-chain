#!/usr/bin/env python3
"""Stage 1 rollback preflight: refuse to start without a rollback that works.

    python3 tools/lane-b/rollout-preflight.py \\
        --validators N \\
        --expected-old-image-digest sha256:<digest production runs now> \\
        --new-image-digest sha256:<release image registry digest> \\
        --restore-rehearsal <rehearsal record> \\
        <preflight-dir>

`<preflight-dir>` holds one `<pod>.preflight` per validator, written by
tools/lane-b/rollout-preflight-record.sh BEFORE the Stage 1 image is set on any
pod (runbook section 4.1). Exit 0 only when every rule holds; 1 otherwise; 2 on
usage.

Why this gate exists: 0.2.0 does not refuse a database Stage 1 has opened. It
"repairs" it, falls back below its own finalized height and produces different
blocks (docs/operations/stage1-local-evidence.md section 1.2). The only
rollback is to restore a pre-upgrade snapshot into a NEW volume and start the
EXACT old image on it. So the rollout does not start unless, for every
validator, that snapshot exists and is ready, the old image is known by digest,
and a restore has been rehearsed and timed.

Per validator (record):
  * every field present;
  * old_image_id pinned by digest and equal to --expected-old-image-digest;
  * pv_reclaim Retain;
  * snapshot_ready true, snapshot_source equal to the pod's pvc, a
    snapshot_handle;
  * stage1_opened "no".
Across the set: exactly N records, N >= 2, and distinct pods, claims, volumes,
snapshots and handles.

The rehearsal record (key: value lines), from restoring one of these
snapshots into a scratch volume and starting the old image on it:
  * snapshot_handle        one of the recorded handles;
  * restored_into          a claim that is not any validator's live claim;
  * old_image_digest       equal to --expected-old-image-digest;
  * repair_lines           0: the old binary logged no "attempting repair";
  * state_rows_snapshot    cf::STATE rows in the snapshot (read-only count);
  * state_rows_restored    the same count on the restored copy; must be equal;
  * snapshot_seconds       measured, a number;
  * restore_seconds        measured, a number;
  * old_binary_started     yes.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RECORD_FIELDS = ("pod", "pod_uid", "old_image_id", "pvc", "pv", "pv_reclaim", "snapshot_name",
                 "snapshot_source", "snapshot_ready", "snapshot_created", "snapshot_size",
                 "snapshot_handle", "stage1_opened")
REHEARSAL_FIELDS = ("snapshot_handle", "restored_into", "old_image_digest", "repair_lines",
                    "state_rows_snapshot", "state_rows_restored", "snapshot_seconds",
                    "restore_seconds", "old_binary_started")
NUMBER = re.compile(r"^[0-9]+(\.[0-9]+)?$")


def parse(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" in raw and not raw.lstrip().startswith("#"):
            k, _, v = raw.partition(":")
            out[k.strip()] = v.strip()
    return out


def check(pre: Path, n: int, old: str, new: str, rehearsal: Path) -> list[str]:
    f: list[str] = []
    if n < 2:
        return [f"--validators {n}: production runs at least two validators"]
    if old == new:
        f.append(f"the new image digest equals the old one ({old}): nothing would change")
    if not pre.is_dir():
        return f + [f"preflight directory {pre} does not exist"]
    recs = {p.stem: parse(p) for p in sorted(pre.glob("*.preflight"))}
    if len(recs) != n:
        f.append(f"MISSING RECORD: {len(recs)} preflight record(s), {n} required ({', '.join(recs) or 'none'})")
    for name, r in recs.items():
        for k in RECORD_FIELDS:
            if not r.get(k):
                f.append(f"{name}: MISSING FIELD {k}")
        img = r.get("old_image_id", "")
        if img and not img.endswith("@" + old):
            f.append(f"{name}: OLD IMAGE MISMATCH {img} is not @{old}")
        if r.get("pv_reclaim") and r["pv_reclaim"] != "Retain":
            f.append(f"{name}: volume reclaim policy {r['pv_reclaim']}, not Retain")
        if r.get("snapshot_ready") and r["snapshot_ready"] != "true":
            f.append(f"{name}: SNAPSHOT NOT READY ({r['snapshot_ready']})")
        if r.get("snapshot_source") and r.get("pvc") and r["snapshot_source"] != r["pvc"]:
            f.append(f"{name}: snapshot is of claim {r['snapshot_source']}, not {r['pvc']}")
        if r.get("stage1_opened") and r["stage1_opened"] != "no":
            f.append(f"{name}: STAGE 1 ALREADY OPENED THIS VOLUME; its snapshot is not a rollback target")
    for key in ("pod", "pvc", "pv", "snapshot_name", "snapshot_handle"):
        vals = [r[key] for r in recs.values() if r.get(key)]
        if len(set(vals)) != len(vals):
            f.append(f"DUPLICATE {key} across records: {vals}")

    if not rehearsal.is_file():
        return f + [f"MISSING RESTORE REHEARSAL {rehearsal}"]
    h = parse(rehearsal)
    for k in REHEARSAL_FIELDS:
        if not h.get(k):
            f.append(f"rehearsal: MISSING FIELD {k}")
    handles = {r.get("snapshot_handle") for r in recs.values()}
    if h.get("snapshot_handle") and h["snapshot_handle"] not in handles:
        f.append(f"rehearsal: snapshot_handle {h['snapshot_handle']} is not one of the recorded snapshots")
    live = {r.get("pvc") for r in recs.values()}
    if h.get("restored_into") and h["restored_into"] in live:
        f.append(f"rehearsal: restored into {h['restored_into']}, a live validator claim; "
                 f"a rehearsal restores into a scratch volume")
    if h.get("old_image_digest") and h["old_image_digest"] != old:
        f.append(f"rehearsal: old_image_digest {h['old_image_digest']} != expected {old}")
    if h.get("repair_lines") and h["repair_lines"] != "0":
        f.append(f"rehearsal: the old binary logged {h['repair_lines']} repair line(s) on the restored copy")
    a, b = h.get("state_rows_snapshot", ""), h.get("state_rows_restored", "")
    if a and b and (not a.isdigit() or not b.isdigit() or a != b):
        f.append(f"rehearsal: STATE ROWS DIFFER snapshot {a} restored {b}")
    for k in ("snapshot_seconds", "restore_seconds"):
        if h.get(k) and not NUMBER.match(h[k]):
            f.append(f"rehearsal: {k} {h[k]!r} is not a measured number of seconds")
    if h.get("old_binary_started") and h["old_binary_started"] != "yes":
        f.append(f"rehearsal: old_binary_started is {h['old_binary_started']!r}")
    return f


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--validators", type=int, required=True)
    ap.add_argument("--expected-old-image-digest")
    ap.add_argument("--new-image-digest")
    ap.add_argument("--restore-rehearsal", type=Path)
    ap.add_argument("preflight", type=Path)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    for flag, v in (("--expected-old-image-digest", a.expected_old_image_digest),
                    ("--new-image-digest", a.new_image_digest)):
        if not v or not DIGEST.match(v):
            print(f"STOP: {flag} must be a sha256:<64-hex> digest, never a tag. Without the exact")
            print("      old digest there is no rollback target; do not start.")
            return 1
    if a.restore_rehearsal is None:
        print("STOP: no --restore-rehearsal record. A snapshot that has never been restored")
        print("      is not a rollback procedure; do not start.")
        return 1
    fails = check(a.preflight, a.validators, a.expected_old_image_digest, a.new_image_digest,
                  a.restore_rehearsal)
    for x in fails:
        print(f"FAIL: {x}")
    if fails:
        print(f"PREFLIGHT NOT COMPLETE: {len(fails)} failure(s). Do not set the Stage 1 image.")
        return 1
    print(f"PREFLIGHT COMPLETE: {a.validators} validators with a ready snapshot of their own "
          f"volume, Retain volumes, the old image pinned at {a.expected_old_image_digest}, "
          f"and a rehearsed restore.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

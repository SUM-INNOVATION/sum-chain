#!/usr/bin/env python3
"""Battery for the rollback preflight: rollout-preflight-record.sh and rollout-preflight.py.

Every fixture is NONPRODUCTION: made-up pods, claims, volumes, snapshot handles
and digests, served by a kubectl shim. Nothing here talks to a cluster.

    python3 tools/lane-b/rollout-preflight-test.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORDER = ROOT / "tools/lane-b/rollout-preflight-record.sh"
CHECKER = ROOT / "tools/lane-b/rollout-preflight.py"
OLD = "sha256:" + "a" * 64  # NONPRODUCTION
NEW = "sha256:" + "b" * 64  # NONPRODUCTION

# kubectl shim: `get <kind> <name> -o jsonpath=<expr>` and `logs <pod> [--previous]`,
# answered from $FX/<kind>.<name>.<field>. A missing file is a NotFound.
KUBECTL = r"""#!/usr/bin/env bash
args=("$@")
while [[ ${args[0]} == -n ]]; do args=("${args[@]:2}"); done
serve() { [[ -f "$FX/$1" ]] || { echo "Error from server (NotFound): $1" >&2; exit 1; }; cat "$FX/$1"; }
case "${args[0]}" in
  get)
    kind=${args[1]} name=${args[2]} jp=${args[4]}
    case "$jp" in
      *metadata.uid*) f=uid ;; *imageID*) f=img ;; *claimName*) f=pvc ;; *volumeName*) f=pv ;;
      *ReclaimPolicy*) f=reclaim ;; *persistentVolumeClaimName*) f=src ;; *readyToUse*) f=ready ;;
      *creationTime*) f=created ;; *restoreSize*) f=size ;; *boundVolumeSnapshotContentName*) f=content ;;
      *snapshotHandle*) f=handle ;; *) echo "shim: unsupported jsonpath $jp" >&2; exit 9 ;;
    esac
    serve "$kind.$name.$f" ;;
  logs) if [[ ${args[2]:-} == --previous ]]; then serve "pod.${args[1]}.prevlog"; else serve "pod.${args[1]}.log"; fi ;;
  *) echo "shim: unsupported $*" >&2; exit 9 ;;
esac
"""


def pods(fx: Path, n: int, *, tag_image=None, delete_policy=None, not_ready=None, other_claim=None,
         stage1_opened=None, stage1_previous=None, dup_handle=None, no_handle=None, old_other=None) -> None:
    for i in range(n):
        pod, pvc, pv, vs, vsc = (f"sumchain-validator-{i + 1}-0", f"data-sumchain-validator-{i + 1}-0",
                                 f"pv-{i}", f"stage1-pre-{i}", f"snapcontent-{i}")
        w = lambda name, v: (fx / name).write_text(v)  # noqa: E731
        w(f"pod.{pod}.uid", f"uid-{i}")
        img = "docker.io/sumchain/node:latest" if tag_image == i else \
            f"docker.io/sumchain/node@{'sha256:' + 'c' * 64 if old_other == i else OLD}"
        w(f"pod.{pod}.img", img)
        w(f"pod.{pod}.pvc", pvc)
        w(f"pvc.{pvc}.pv", pv)
        w(f"pv.{pv}.reclaim", "Delete" if delete_policy == i else "Retain")
        w(f"volumesnapshot.{vs}.src", "data-someone-else" if other_claim == i else pvc)
        w(f"volumesnapshot.{vs}.ready", "false" if not_ready == i else "true")
        w(f"volumesnapshot.{vs}.created", "2026-01-01T00:00:00Z")
        w(f"volumesnapshot.{vs}.size", "100Gi")
        w(f"volumesnapshot.{vs}.content", vsc)
        # A field that is absent prints as empty from real kubectl jsonpath.
        w(f"volumesnapshotcontent.{vsc}.handle",
          "" if no_handle == i else "snap-handle-0" if dup_handle == i else f"snap-handle-{i}")
        log = "INFO sumchain::node: Opening database at /data\n"
        if stage1_opened == i:
            log += "INFO sumchain::node: Application journal format: binary v1\n"
        w(f"pod.{pod}.log", log)
        if stage1_previous == i:
            w(f"pod.{pod}.prevlog", "INFO sumchain::node: Application journal format: binary v1\n")


def rehearsal(path: Path, **over) -> None:
    fields = {"snapshot_handle": "snap-handle-0", "restored_into": "scratch-restore-0",
              "old_image_digest": OLD, "repair_lines": "0", "state_rows_snapshot": "123",
              "state_rows_restored": "123", "snapshot_seconds": "41", "restore_seconds": "212.5",
              "old_binary_started": "yes"}
    fields.update(over)
    path.write_text("".join(f"{k}: {v}\n" for k, v in fields.items() if v is not None))


def record(tmp: Path, n: int, **kw) -> tuple[Path, str]:
    fx, out, shim = tmp / "fx", tmp / "out", tmp / "bin"
    for d in (fx, out, shim):
        d.mkdir()
    pods(fx, n, **kw)
    (shim / "kubectl").write_text(KUBECTL)
    (shim / "kubectl").chmod(0o755)
    env = dict(os.environ, FX=str(fx), PATH=f"{shim}:{os.environ['PATH']}")
    errs = ""
    for i in range(n):
        r = subprocess.run(["bash", str(RECORDER), f"sumchain-validator-{i + 1}-0", f"stage1-pre-{i}", str(out)],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            errs += f"[exit {r.returncode}] {r.stderr}"
    return out, errs


def checker(out: Path, n: int, *, old=OLD, new=NEW, reh: Path | None) -> tuple[int, str]:
    args = [sys.executable, str(CHECKER), "--validators", str(n)]
    if old is not None:
        args += ["--expected-old-image-digest", old]
    if new is not None:
        args += ["--new-image-digest", new]
    if reh is not None:
        args += ["--restore-rehearsal", str(reh)]
    r = subprocess.run(args + [str(out)], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


# (name, fixture kwargs, rehearsal overrides or "absent", checker overrides, post-step, exit, text)
CASES = [
    ("complete", {}, {}, {}, None, 0, "PREFLIGHT COMPLETE: 2 validators"),
    ("old digest not supplied", {}, {}, {"old": None}, None, 1, "STOP: --expected-old-image-digest"),
    ("old digest given as a tag", {}, {}, {"old": "latest"}, None, 1, "STOP: --expected-old-image-digest"),
    ("new digest not supplied", {}, {}, {"new": None}, None, 1, "STOP: --new-image-digest"),
    ("restore rehearsal not supplied", {}, "absent", {}, None, 1, "STOP: no --restore-rehearsal"),
    ("restore rehearsal file missing", {}, "missing", {}, None, 1, "MISSING RESTORE REHEARSAL"),
    ("a pod runs a different old digest", {"old_other": 1}, {}, {}, None, 1, "OLD IMAGE MISMATCH"),
    ("new digest equals old", {}, {}, {"new": OLD}, None, 1, "nothing would change"),
    ("one snapshot record missing", {}, {}, {}, "drop_one", 1, "MISSING RECORD"),
    ("snapshot_handle blank in a record", {}, {}, {}, "blank_handle", 1, "MISSING FIELD snapshot_handle"),
    ("two records share a snapshot handle", {"dup_handle": 1}, {}, {}, None, 1, "DUPLICATE snapshot_handle"),
    ("rehearsal restored into a live claim", {}, {"restored_into": "data-sumchain-validator-1-0"}, {}, None, 1,
     "a live validator claim"),
    ("rehearsal used another old digest", {}, {"old_image_digest": NEW}, {}, None, 1, "rehearsal: old_image_digest"),
    ("rehearsal: old binary repaired the copy", {}, {"repair_lines": "1"}, {}, None, 1, "repair line(s)"),
    ("rehearsal: cf::STATE rows differ", {}, {"state_rows_restored": "120"}, {}, None, 1, "STATE ROWS DIFFER"),
    ("rehearsal: restore not timed", {}, {"restore_seconds": None}, {}, None, 1, "MISSING FIELD restore_seconds"),
    ("rehearsal: time is not a measurement", {}, {"snapshot_seconds": "fast"}, {}, None, 1,
     "is not a measured number"),
    ("rehearsal of an unrecorded snapshot", {}, {"snapshot_handle": "snap-handle-9"}, {}, None, 1,
     "is not one of the recorded snapshots"),
    ("stage1_opened edited to yes", {}, {}, {}, "opened_yes", 1, "STAGE 1 ALREADY OPENED"),
    ("reclaim edited to Delete", {}, {}, {}, "reclaim_delete", 1, "not Retain"),
]

# The recorder itself must refuse and write nothing.
RECORDER_REFUSALS = [
    ("old image by tag", {"tag_image": 0}, "is not pinned by digest"),
    ("volume reclaim Delete", {"delete_policy": 0}, "not Retain"),
    ("snapshot not ready", {"not_ready": 0}, "is not readyToUse"),
    ("snapshot of another claim", {"other_claim": 0}, "not this pod's claim"),
    ("Stage 1 already opened the volume", {"stage1_opened": 0}, "already opened this volume"),
    ("Stage 1 opened it in a previous container", {"stage1_previous": 0}, "already opened this volume"),
    ("snapshot content has no handle", {"no_handle": 0}, "carries no snapshotHandle"),
]


def post(out: Path, how: str | None) -> None:
    rec = out / "sumchain-validator-1-0.preflight"
    if how == "drop_one":
        rec.unlink()
    elif how in ("blank_handle", "opened_yes", "reclaim_delete"):
        key, val = {"blank_handle": ("snapshot_handle", ""), "opened_yes": ("stage1_opened", "yes"),
                    "reclaim_delete": ("pv_reclaim", "Delete")}[how]
        lines = [f"{key}: {val}" if l.startswith(key + ":") else l for l in rec.read_text().splitlines()]
        rec.write_text("\n".join(lines) + "\n")


def main() -> int:
    fails: list[str] = []
    print("preflight checker cases (NONPRODUCTION fixtures):")
    for name, kw, reh, chk, how, want, text in CASES:
        tmp = Path(tempfile.mkdtemp(prefix="preflight-"))
        try:
            out, errs = record(tmp, 2, **kw)
            post(out, how)
            rp = tmp / "rehearsal.txt"
            if reh not in ("absent", "missing"):
                rehearsal(rp, **reh)
            code, msg = checker(out, 2, reh=None if reh == "absent" else rp, **chk)
            ok = code == want and text in msg
            print(f"  {'ok  ' if ok else 'FAIL'} {name:44s} expected exit {want}, got {code}")
            if not ok:
                fails.append(f"{name}: exit {code}, wanted {want} with {text!r}\n  recorder: {errs}\n  checker: {msg}")
        finally:
            shutil.rmtree(tmp)
    print("preflight recorder refusals: exit non-zero, write nothing")
    for name, kw, text in RECORDER_REFUSALS:
        tmp = Path(tempfile.mkdtemp(prefix="preflight-rec-"))
        try:
            out, errs = record(tmp, 1, **kw)
            rec = out / "sumchain-validator-1-0.preflight"
            leftover = list(out.glob(".*")) if out.exists() else []
            ok = "[exit 1]" in errs and text in errs and not rec.exists() and not leftover
            print(f"  {'ok  ' if ok else 'FAIL'} {name:44s} refused={'[exit 1]' in errs} written={rec.exists()}")
            if not ok:
                fails.append(f"recorder {name}: wanted refusal naming {text!r}; stderr: {errs}")
        finally:
            shutil.rmtree(tmp)
    for f in fails:
        print("FAIL:", f, file=sys.stderr)
    if fails:
        return 1
    print(f"ROLLOUT PREFLIGHT BATTERY OK: {len(CASES)} checker cases + {len(RECORDER_REFUSALS)} recorder refusals.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Native (systemd) validator upgrade preflight: decide from recorded facts.

    python3 tools/lane-b/native-preflight.py \\
        --before before.record [--stopped stopped.record] \\
        --expected-current-sha256 <64-hex of the binary running now> \\
        [--expected-current-commit <40-hex, when known>] \\
        --expected-genesis-sha256 <64-hex of the PRODUCTION genesis> \\
        --release-record release-record.txt --release-commit <40-hex> \\
        [--allow-health-addr <addr>]        (only if the owner chose a non-loopback, protected address)
        [--provider-snapshot <id> --restore-rehearsal <file>]   (instead of a local rollback copy)

Records come from tools/lane-b/native-preflight-record.sh, run on the host.
`--before` alone checks everything that can be checked while the old binary
runs; adding `--stopped` completes the gate that must pass before the new
binary is started. Exit 0 only when every rule holds; 1 otherwise; 2 on usage.

Refuses (never passes by absence) unless:
  identity   the unit runs the expected executable, and the running image
             hashes as the file on disk and as --expected-current-sha256 (and
             the checkout is at --expected-current-commit when given);
  genesis    genesis_sha256 = --expected-genesis-sha256;
  release    the installed new binary is THIS machine's binary in the release
             record (the record is chosen by `uname -m`, never by the operator)
             and reports `sumchain <release commit>`;
  health     the config binds health/readiness/metrics to loopback. An absent
             [health] section FAILS: the node would bind 0.0.0.0:8546. Another
             address passes only if the owner named it with --allow-health-addr;
  capacity   installed memory >= the 4 GiB supported floor, measured as online
             memory blocks (lsmem), not MemTotal; a unit MemoryMax, if set, is
             not below it; free disk holds the rollback copy, a restore copy and
             growth (25% of the database, at least 2 GiB), or, with a provider
             snapshot, a restore copy and growth;
  topology   recorded (dialer when bootnodes are configured, listener
             otherwise) and the restart order derived from it;
  stopped    the unit is inactive, no process runs the old executable, the
             database lock is free, the rollback copy's tree digest equals the
             live data directory's (or a provider snapshot and a restore
             rehearsal are named), and the preserved rollback binary hashes as
             the current one.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

FLOOR = 4 * 1024 ** 3                       # docs/operations/validator-memory-floor.md
GROWTH_FRACTION, GROWTH_MIN = 0.25, 2 * 1024 ** 3
HEX64, HEX40 = re.compile(r"^[0-9a-f]{64}$"), re.compile(r"^[0-9a-f]{40}$")
MACHINE = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


def parse(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


def num(v: str | None) -> int | None:
    return int(v) if v and v.isdigit() else None


def gib(n: int) -> str:
    return f"{n / 1024 ** 3:.2f} GiB"


def loopback(addr: str) -> bool:
    host = addr.rsplit(":", 1)[0].strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check(before: dict, stopped: dict | None, a: argparse.Namespace, release: dict) -> tuple[list[str], list[str]]:
    f, notes = [], []
    need = ("unit", "executable", "executable_sha256", "running_image_sha256", "config_sha256", "genesis_sha256",
            "health_addr", "data_dir", "data_bytes", "disk_available_bytes", "mem_installed_online_bytes",
            "bootnodes_configured", "machine", "installed_binary_sha256", "installed_binary_version")
    for k in need:
        if not before.get(k):
            f.append(f"before: MISSING FIELD {k}")
    if before.get("phase") != "before":
        f.append("the --before record is not a before-phase record")
    if before.get("unit_active") != "active":
        f.append(f"before: the unit is {before.get('unit_active')!r}, not active")

    # identity
    cur = a.expected_current_sha256
    if before.get("executable_sha256") != cur:
        f.append(f"IDENTITY: the unit's executable hashes {before.get('executable_sha256')}, expected {cur}")
    if before.get("running_image_sha256") != before.get("executable_sha256"):
        f.append("IDENTITY: the running process image differs from the executable on disk (replaced under it?)")
    if a.expected_current_commit and before.get("source_checkout_commit") != a.expected_current_commit:
        f.append(f"IDENTITY: checkout at {before.get('source_checkout_commit')}, expected {a.expected_current_commit}")

    # genesis
    if before.get("genesis_sha256") != a.expected_genesis_sha256:
        f.append(f"GENESIS MISMATCH: {before.get('genesis_sha256')} != expected {a.expected_genesis_sha256}")

    # release, chosen by this machine's architecture
    arch = MACHINE.get(before.get("machine", ""))
    if arch is None:
        f.append(f"RELEASE: no release archive for machine {before.get('machine')!r}")
    else:
        want = release.get(f"{arch}_binary_sha256")
        if before.get("installed_binary_sha256") != want:
            f.append(f"RELEASE: the installed binary hashes {before.get('installed_binary_sha256')}, the release "
                     f"record's {arch} binary is {want}")
        if before.get("installed_binary_version") != f"sumchain {a.release_commit}":
            f.append(f"RELEASE: the installed binary reports {before.get('installed_binary_version')!r}")
        notes.append(f"release binary for this machine ({before.get('machine')} -> {arch}): {want}")

    # health binding
    h = before.get("health_addr", "")
    if h == "absent":
        f.append("HEALTH BINDING: the config has no [health] section, so the new node would bind "
                 "0.0.0.0:8546 (health, readiness and /metrics on every interface). Add [health] "
                 "addr = \"127.0.0.1:8546\" (or an owner-chosen protected address) first")
    elif not loopback(h) and h != (a.allow_health_addr or ""):
        f.append(f"HEALTH BINDING: health binds {h}, which is not loopback and not the owner-chosen "
                 f"--allow-health-addr")
    elif h:
        notes.append(f"health, readiness and metrics on {h}" + ("" if loopback(h) else " (owner-chosen)"))

    # capacity
    online = num(before.get("mem_installed_online_bytes"))
    total = num(before.get("mem_total_bytes"))
    if online is None:
        f.append("CAPACITY: installed memory is unavailable (lsmem); MemTotal alone cannot tell a 4 GiB "
                 "machine from an undersized one, so the floor cannot be established")
    elif online < FLOOR:
        f.append(f"CAPACITY: {gib(online)} of memory installed, below the 4 GiB supported floor")
    else:
        notes.append(f"memory: {gib(online)} installed (floor 4 GiB); {gib(total or 0)} usable after kernel "
                     f"reservations")
    mm = before.get("memory_max", "")
    if mm.isdigit() and int(mm) < FLOOR:
        f.append(f"CAPACITY: the unit's MemoryMax {gib(int(mm))} is below the 4 GiB floor")
    db = num(before.get("data_bytes")) or 0
    avail = num(before.get("disk_available_bytes")) or 0
    growth = max(int(db * GROWTH_FRACTION), GROWTH_MIN)
    local_copy = not (a.provider_snapshot and a.restore_rehearsal)
    need_disk = (2 * db if local_copy else db) + growth
    if avail < need_disk:
        f.append(f"CAPACITY: {gib(avail)} free, {gib(need_disk)} needed "
                 f"({'rollback copy + ' if local_copy else ''}restore copy {gib(db)} each + growth {gib(growth)}); "
                 f"a safe rollback copy cannot coexist with the database")
    else:
        notes.append(f"disk: {gib(avail)} free for a {gib(db)} database; {gib(need_disk)} needed")

    # topology
    role = {"yes": "dialer", "no": "listener"}.get(before.get("bootnodes_configured", ""), "unknown")
    if role == "unknown":
        f.append("TOPOLOGY: whether bootnodes are configured is unknown")
    else:
        notes.append(f"topology: this node is the {role.upper()} (bootnodes configured: "
                     f"{before.get('bootnodes_configured')}; outbound {before.get('p2p_outbound')}, inbound "
                     f"{before.get('p2p_inbound')}); validator {before.get('validator_pubkey', 'unavailable')[:12]}…")
        notes.append("restart order: the listener must be running before the dialer starts; "
                     + ("confirm the peer this node dials is up before starting this node."
                        if role == "dialer" else
                        "after restarting this node, the dialer reconnects on its own redial (up to ~30 s)."))

    # stopped
    if stopped is not None:
        if stopped.get("phase") != "stopped":
            f.append("the --stopped record is not a stopped-phase record")
        if stopped.get("unit_active") in ("active", "activating", "deactivating", "reloading"):
            f.append(f"STOPPED: the unit is still {stopped.get('unit_active')}")
        if stopped.get("process_exited") != "yes":
            f.append("STOPPED: a process still runs the old executable")
        if stopped.get("db_lock") != "free":
            f.append(f"STOPPED: the database lock is {stopped.get('db_lock')!r}, not free")
        if stopped.get("executable_sha256") != cur:
            f.append("STOPPED: the unit's executable changed between the records")
        if stopped.get("rollback_binary_sha256") != cur:
            f.append(f"ROLLBACK BINARY: the preserved binary hashes {stopped.get('rollback_binary_sha256')!r}, "
                     f"not the current {cur}")
        if local_copy:
            if not stopped.get("rollback_copy_tree_sha256"):
                f.append("ROLLBACK COPY: none recorded, and no provider snapshot with a restore rehearsal named")
            elif stopped.get("rollback_copy_tree_sha256") != stopped.get("data_tree_sha256"):
                f.append("ROLLBACK COPY: its tree digest differs from the stopped data directory's")
            elif stopped.get("rollback_copy") and stopped.get("rollback_copy") == stopped.get("data_dir"):
                f.append("ROLLBACK COPY: it is the data directory itself")
            else:
                notes.append(f"rollback copy {stopped.get('rollback_copy_tree_sha256')[:12]}… = data directory")
        else:
            if not Path(a.restore_rehearsal).is_file():
                f.append(f"ROLLBACK: restore rehearsal {a.restore_rehearsal} does not exist")
            else:
                notes.append(f"rollback: provider snapshot {a.provider_snapshot}, rehearsal {a.restore_rehearsal}")
        after = num(stopped.get("disk_available_after_copy_bytes")) or 0
        if local_copy and after < db + growth:
            f.append(f"CAPACITY: after the rollback copy {gib(after)} is free; a restore copy and growth need "
                     f"{gib(db + growth)}")
    return f, notes


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--before", type=Path, required=True)
    ap.add_argument("--stopped", type=Path)
    ap.add_argument("--expected-current-sha256")
    ap.add_argument("--expected-current-commit")
    ap.add_argument("--expected-genesis-sha256")
    ap.add_argument("--release-record", type=Path)
    ap.add_argument("--release-commit")
    ap.add_argument("--allow-health-addr")
    ap.add_argument("--provider-snapshot")
    ap.add_argument("--restore-rehearsal")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    stops = []
    if not (a.expected_current_sha256 and HEX64.match(a.expected_current_sha256)):
        stops.append("--expected-current-sha256: the sha256 of the binary running now (the rollback target)")
    if not (a.expected_genesis_sha256 and HEX64.match(a.expected_genesis_sha256)):
        stops.append("--expected-genesis-sha256: the PRODUCTION genesis hash, supplied by the owner")
    if not (a.release_commit and HEX40.match(a.release_commit)):
        stops.append("--release-commit: the full 40-hex release commit")
    if not (a.release_record and a.release_record.is_file()):
        stops.append("--release-record: release-record.txt of the verified release")
    if bool(a.provider_snapshot) != bool(a.restore_rehearsal):
        stops.append("--provider-snapshot and --restore-rehearsal go together")
    if a.expected_current_commit and not HEX40.match(a.expected_current_commit):
        stops.append("--expected-current-commit must be a full 40-hex sha")
    if stops:
        for s in stops:
            print(f"STOP: {s}")
        return 1
    release = parse(a.release_record)
    if release.get("release_commit") != a.release_commit:
        print(f"STOP: the release record is for {release.get('release_commit')!r}, not {a.release_commit}")
        return 1
    fails, notes = check(parse(a.before), parse(a.stopped) if a.stopped else None, a, release)
    for n in notes:
        print(f"NOTE: {n}")
    for x in fails:
        print(f"FAIL: {x}")
    if fails:
        print(f"PREFLIGHT NOT COMPLETE: {len(fails)} failure(s). Do not switch the service.")
        return 1
    print("PREFLIGHT COMPLETE: " + ("old process exited, lock free, rollback ready; the new binary may be started."
                                    if a.stopped else "running-phase checks pass; stop the service and record "
                                                      "--phase stopped next."))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

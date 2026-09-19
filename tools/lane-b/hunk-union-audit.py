#!/usr/bin/env python3
"""Hunk-level union audit: every line a parent added, found or classified in the merge.

# Why this exists, and why the symbol audit was not enough

`union-audit.py` enumerates SYMBOLS -- functions, tests, pub items -- and asks
whether each survived the merge. That is a real check and it has caught real
losses, but its resolution is one symbol. This branch has since lost, inside
symbols the symbol audit reported present:

  * two WIRING table entries and two dormant-list entries, when a conflict
    opened in the MIDDLE of a tuple and the halves were spliced into one
    malformed entry holding six strings instead of three;
  * an `activation_heights` tuple, the same way;
  * a string literal fused with its neighbour into an unterminated literal.

None of those is a missing symbol. The enclosing function was present and
correctly named throughout. So this audit works at the line a parent ADDED: for
every added line in every hunk of every merged parent, is that line present in
the final tree?

# Classification

Lines that are not found are not automatically losses. Each is reported for
classification into one of:

    PRESENT                  the line is in the final tree
    SUPERSEDED               later work replaced it; the replacement is named
    CUMULATIVELY RECONCILED  two parents changed the same number and the final
                             value is the union (13 and 16 becoming 17)
    INTENTIONALLY REMOVED    removed on purpose, with the reason
    DROPPED                  none of the above -- a loss, and must be restored

Only DROPPED is a failure. The other four are decisions, and the point of the
audit is that each one has to be MADE rather than assumed.

# Noise control

Lines shorter than MIN_LEN, and lines that are pure punctuation or a bare
closing brace, carry no identity: thousands of `    }` lines match anything.
They are counted but not reported. Everything else is reported verbatim.
"""
import re
import subprocess
import sys
from collections import defaultdict

MIN_LEN = 12
TRIVIAL = re.compile(r'^[\s{}()\[\],;:+\-*/=<>&|!?.]*$')


def sh(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True).stdout


def added_lines(base: str, parent: str) -> dict:
    """{path: [line, ...]} for every line `parent` added over `base`."""
    out = defaultdict(list)
    diff = sh("git", "diff", "--no-color", "-U0", base, parent)
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++") and path:
            out[path].append(line[1:])
    return out


def main() -> int:
    if len(sys.argv) < 3:
        sys.exit("usage: hunk-union-audit.py <head> <parent> [<parent> ...]")
    head, parents = sys.argv[1], sys.argv[2:]

    head_sha = sh("git", "rev-parse", head).strip()
    if not head_sha:
        sys.exit(f"unresolvable head: {head}")
    print(f"head: {head} = {head_sha}\n")

    # One read of the final tree per file, reused across parents.
    final_cache: dict = {}

    def final_text(path: str) -> str:
        if path not in final_cache:
            final_cache[path] = sh("git", "show", f"{head_sha}:{path}")
        return final_cache[path]

    total_missing = 0
    for parent in parents:
        psha = sh("git", "rev-parse", parent).strip()
        if not psha:
            sys.exit(f"unresolvable parent: {parent}")
        base = sh("git", "merge-base", head_sha, psha).strip()
        adds = added_lines(base, psha)

        checked = trivial = missing = 0
        report = defaultdict(list)
        for path, lines in adds.items():
            text = final_text(path)
            for raw in lines:
                stripped = raw.strip()
                if len(stripped) < MIN_LEN or TRIVIAL.match(stripped):
                    trivial += 1
                    continue
                checked += 1
                # Matched by content anywhere in the file: a line that moved is
                # present. A line that was reflowed by rustfmt is not, and that
                # is deliberate -- reflowing is a change worth classifying.
                if stripped not in text:
                    missing += 1
                    report[path].append(stripped)

        total_missing += missing
        print(f"=== {parent} = {psha}")
        print(f"    base {base[:12]}  files {len(adds)}  "
              f"lines checked {checked} (+{trivial} trivial)  NOT FOUND {missing}")
        for path in sorted(report):
            print(f"    --- {path}  ({len(report[path])})")
            for line in report[path][:40]:
                print(f"        {line[:150]}")
            if len(report[path]) > 40:
                print(f"        ... and {len(report[path]) - 40} more")
        print()

    print(f"TOTAL lines added by a parent and not present in {head}: {total_missing}")
    print("Every one needs a classification. Only DROPPED is a failure.")
    return 1 if total_missing else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Source-union audit over both parent branches.

A textual merge reporting success is not evidence: resolving one conflicted test
file with `git apply --3way` once discarded 267 lines and still compiled, because
the only symbol the loss broke was an import the dropped code alone used.

So every symbol from each parent is enumerated and required to be present in the
union, or classified. Classes:

    RENAMED   old -> new, with the commit that renamed it
    REMOVED   with a reason and a replacement
    DROPPED   accidental, must be restored

Symbol kinds: production fns, test fns, pub API, EXECUTION_FNS declarations,
MANIFEST rows, ChainParams activation fields, error variants, #[test] names.
"""
import json, re, subprocess, sys, os

W = "/Users/0x1e0/Documents/Developers/sum/lane-a-wave/integrated"
PARENTS = ["lane-b/deploy-journal", "lane-b/deploy-account"]
os.chdir(W)

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout

def files(ref):
    return [f for f in sh("git", "ls-tree", "-r", "--name-only", ref).splitlines()
            if f.endswith(".rs")]

def blob(ref, path):
    return sh("git", "show", f"{ref}:{path}")

PATTERNS = {
    "fn":            re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z_][a-zA-Z_0-9]*)', re.M),
    "pub_item":      re.compile(r'^\s*pub\s+(?:struct|enum|trait|type|const|static|mod)\s+([A-Za-z_][A-Za-z_0-9]*)', re.M),
    "test":          re.compile(r'#\[test\][^\n]*\n(?:[^\n]*\n)??\s*(?:async\s+)?fn\s+([a-z_0-9]+)', re.M),
    "boundary_decl": re.compile(r'\("([a-z_0-9]+\.rs)",\s*"(fn v_[a-z_0-9]+\()"\)'),
    "manifest_row":  re.compile(r'\("(crates/[^"]+\.rs)",\s*"([^"]+)",\s*"([^"]+)"'),
    "activation":    re.compile(r'pub\s+([a-z_0-9]*enabled_from_height)\s*:'),
    "err_variant":   re.compile(r'^\s{4}([A-Z][A-Za-z0-9]*)\s*\{', re.M),
}

def symbols(ref):
    out = {k: set() for k in PATTERNS}
    for f in files(ref):
        t = blob(ref, f)
        for k, p in PATTERNS.items():
            for m in p.finditer(t):
                out[k].add(m.group(1) if m.lastindex == 1 else "::".join(m.groups()))
    return out

head = symbols("HEAD")
report = {"head": "HEAD", "parents": {}, "missing_total": 0}
for p in PARENTS:
    s = symbols(p)
    miss = {k: sorted(s[k] - head[k]) for k in s}
    n = sum(len(v) for v in miss.values())
    report["parents"][p] = {"counts": {k: len(s[k]) for k in s}, "missing": {k: v for k, v in miss.items() if v}}
    report["missing_total"] += n
    print(f"=== {p} ===")
    for k in PATTERNS:
        extra = f"   MISSING {len(miss[k])}" if miss[k] else ""
        print(f"  {k:14} {len(s[k]):5}{extra}")
        for sym in miss[k]:
            print(f"      - {sym}")
json.dump(report, open("/tmp/union-audit.json", "w"), indent=1)
print(f"\ntotal symbols missing from the union: {report['missing_total']}")
print("machine-readable report: /tmp/union-audit.json")

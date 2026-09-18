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

INVOKED_FROM = os.getcwd()

def _sh_out(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout.strip()

# A hardcoded path once made this tool audit a worktree that was not the one
# under test, and the failure read as log noise. Derive the repository from the
# invocation instead, and refuse outside a checkout.
W = os.environ.get("UNION_AUDIT_REPO") or _sh_out("git", "rev-parse", "--show-toplevel")
if not W:
    sys.exit("union-audit: run inside a git checkout, or set UNION_AUDIT_REPO")
os.chdir(W)

PARENTS = sys.argv[1:] or ["lane-b/deploy-journal", "lane-b/deploy-account"]
HEAD_REF = os.environ.get("UNION_AUDIT_HEAD", "HEAD")
OUT = os.environ.get("UNION_AUDIT_OUT") or os.path.join(INVOKED_FROM, "union-audit.json")

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

# Every ref is resolved once, in full: an abbreviated or reconstructed SHA is
# not evidence about which tree was audited.
HEAD_SHA = _sh_out("git", "rev-parse", HEAD_REF)
PARENT_SHA = {p: _sh_out("git", "rev-parse", p) for p in PARENTS}
if not HEAD_SHA or not all(PARENT_SHA.values()):
    sys.exit(f"union-audit: unresolvable ref among {[HEAD_REF] + PARENTS}")

print(f"repository: {W}")
print(f"head:    {HEAD_REF} = {HEAD_SHA}")
for p in PARENTS:
    print(f"parent:  {p} = {PARENT_SHA[p]}")
print()

head = symbols(HEAD_SHA)
report = {"head": {"ref": HEAD_REF, "sha": HEAD_SHA}, "repo": W,
          "parents": {}, "missing_total": 0}
for p in PARENTS:
    s = symbols(PARENT_SHA[p])
    miss = {k: sorted(s[k] - head[k]) for k in s}
    n = sum(len(v) for v in miss.values())
    report["parents"][p] = {"sha": PARENT_SHA[p], "counts": {k: len(s[k]) for k in s}, "missing": {k: v for k, v in miss.items() if v}}
    report["missing_total"] += n
    print(f"=== {p} ({PARENT_SHA[p][:12]}...) ===")
    for k in PATTERNS:
        extra = f"   MISSING {len(miss[k])}" if miss[k] else ""
        print(f"  {k:14} {len(s[k]):5}{extra}")
        for sym in miss[k]:
            print(f"      - {sym}")
json.dump(report, open(OUT, "w"), indent=1)
print(f"\ntotal symbols missing from the union: {report['missing_total']}")
print(f"machine-readable report: {OUT}")

#!/usr/bin/env python3
"""Prove a milestone's changed-file claims WITHOUT any repository-management command.

mtime + size + SHA-256, compared against an explicit work-window start. Answers the
one question a no-git audit must answer mechanically: did the files the milestone
CLAIMS to have changed actually change, and are the authority/pipeline modules it
CLAIMS to have left alone still older than the window?

Usage:
    python3 scripts/changed_file_inventory.py '<json>' [<json>]

Two optional JSON args, each:
    {"window": "YYYY-MM-DD HH:MM",
     "touched":  ["lib/foo.py", "reports/bar.md"],
     "untouched": ["lib/authority.py"]}

A missing `untouched` entry prints `n/a` and does NOT fail the verdict — a module
that does not exist on this install was neither created nor modified. A `touched`
entry that is missing, or older than the window, DOES fail: that is a claim the
milestone cannot support.
"""
import hashlib
import json
import os
import sys
import time

ROOT = os.environ.get("HERMES_ROOT", "/root/hermes-recon")


def parse(ts):
    return time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M"))


def sha256(rel):
    h = hashlib.sha256()
    with open(os.path.join(ROOT, rel), "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def report(spec):
    win = parse(spec["window"])
    bad = 0
    print("=" * 76)
    print("work window start: %s  (epoch %.0f)" % (spec["window"], win))
    print("=" * 76)

    print("--- CLAIMED TOUCHED (%d) ---" % len(spec.get("touched") or []))
    for rel in spec.get("touched") or []:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            print("  MISSING  %s" % rel)
            bad += 1
            continue
        st = os.stat(p)
        ok = st.st_mtime >= win
        bad += 0 if ok else 1
        print("  %s %-52s mtime=%s size=%d"
              % ("OK " if ok else "STALE", rel,
                 time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
                 st.st_size))
        print("       sha256=%s" % sha256(rel))

    print("--- CLAIMED UNTOUCHED (%d) ---" % len(spec.get("untouched") or []))
    for rel in spec.get("untouched") or []:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            print("  n/a      %s  (absent: neither created nor modified)" % rel)
            continue
        st = os.stat(p)
        ok = st.st_mtime < win
        bad += 0 if ok else 1
        print("  %s %-52s mtime=%s"
              % ("OK " if ok else "**TOUCHED**", rel,
                 time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))))

    print()
    print("VERDICT=%s" % ("CLEAN" if bad == 0 else "VIOLATION (%d)" % bad))
    print("Note: mtime proves WHEN, not WHAT. The semantic evidence is the suite's")
    print("own AST/scope assertions; this script only corroborates the inventory.")
    return bad


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    bad = 0
    for arg in argv:
        bad += report(json.loads(arg))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Probe a HERMES layer for CONSUMERS of its output. READ-ONLY.

Run from the repo root:

    python3 scripts/audit_layer_consumption.py recondiff
    python3 scripts/audit_layer_consumption.py recondiff --tables recon_changes,diff_baselines

Answers "is this layer wired to matter, or only wired to run?" with five
independent measurements, so the next milestone's objective is measured rather
than inferred:

  1. which modules import the layer (and whether an importer only GATES on it)
  2. which modules reference its output TABLES (the consumer count)
  3. AST: does the layer write OUTSIDE its own tables? (cross-milestone writes)
  4. does the user-facing reporter / dispatcher mention it?
  5. live row counts of its tables

A layer whose tables have zero consumers outside itself, an empty cross-write
list, and no reporter surface is the seam the next milestone should close.

Table names default to every live table whose name appears as a literal in the
module under audit, so no registry needs maintaining.
"""

import argparse
import ast
import io
import os
import re
import sqlite3
import sys

WRITE_CALLS = ("add_finding", "enqueue_job", "add_job", "enqueue_alert",
               "enqueue_case_alert", "register_finding_alert",
               "attach_member", "add_target_to_campaign", "persist_plans",
               "record_decision")
REPORTERS = ("scripts/reporter.py", "scripts/status.py", "lib/notify.py")
SKIP_DIRS = {"__pycache__", ".git"}


def py_files(root):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            if f.endswith(".py"):
                yield os.path.join(base, f)


def read(path):
    try:
        return io.open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def live_tables(db):
    if not os.path.exists(db):
        return [], {}
    con = sqlite3.connect(db)
    try:
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        counts = {}
        for t in tables:
            try:
                counts[t] = con.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
            except sqlite3.Error:
                counts[t] = None
        return tables, counts
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("module", help="module name under lib/, e.g. recondiff")
    ap.add_argument("--tables", help="comma-separated output tables (default: auto)")
    ap.add_argument("--db", default="state/hermes.db")
    args = ap.parse_args()

    mod_path = os.path.join("lib", args.module + ".py")
    if not os.path.exists(mod_path):
        print("no such module: %s" % mod_path)
        return 2
    src = read(mod_path)
    tables, counts = live_tables(args.db)

    if args.tables:
        owned = [t.strip() for t in args.tables.split(",") if t.strip()]
    else:
        owned = [t for t in tables if re.search(r"\b" + re.escape(t) + r"\b", src)]

    print("=== LAYER: %s  (%d lines) ===" % (mod_path, src.count(chr(10)) + 1))
    print("=== OWNED TABLES: %s" % (owned or "(none detected)"))

    print()
    print("=== 1. IMPORTERS ===")
    importers = []
    for p in py_files("lib"):
        if p == mod_path:
            continue
        s = read(p)
        if re.search(r"\b(import|from)\s+%s\b" % re.escape(args.module), s):
            importers.append(p)
            gate = bool(re.search(r"_work_exists|_job_pending|_due\b", s))
            print("  %-28s %s" % (p, "GATE-ONLY (wired to run)" if gate else "uses it"))
    for p in py_files("scripts"):
        if args.module in p or "m11_regression" in p:
            continue
        s = read(p)
        if re.search(r"\b(import|from)\s+%s\b" % re.escape(args.module), s):
            importers.append(p)
            print("  %-28s dispatch/CLI" % p)
    if not importers:
        print("  (none)")

    print()
    print("=== 2. TABLE CONSUMERS (the count that matters) ===")
    consumer_hits = {t: [] for t in owned}
    for root in ("lib", "scripts"):
        for p in py_files(root):
            if p == mod_path or "/m" in os.path.basename(p) or p.startswith("scripts/test_"):
                continue
            s = read(p)
            for t in owned:
                if re.search(r"\b" + re.escape(t) + r"\b", s):
                    consumer_hits[t].append(p)
    for t in owned:
        hits = consumer_hits[t]
        print("  %-22s consumers=%d  %s"
              % (t, len(hits), hits[:6] if hits else "NONE OUTSIDE THE LAYER"))

    print()
    print("=== 3. CROSS-MILESTONE WRITES (AST) ===")
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        print("  parse error: %s" % e)
        return 1
    called = sorted({n.func.id for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)})
    cross = [c for c in called if c in WRITE_CALLS]
    print("  %s" % (cross if cross else "[] -- writes NOTHING outside its own tables"))
    imps = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            imps.update(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            imps.add(n.module or "")
    banned = [m for m in ("socket", "requests", "urllib", "http.client", "subprocess",
                          "urllib3", "httpx") if m in imps]
    print("  imports: %s" % sorted(imps))
    print("  network/process imports: %s" % (banned or "NONE"))

    print()
    print("=== 4. USER-FACING SURFACE ===")
    for p in REPORTERS:
        s = read(p)
        hit = bool(re.search(r"\b%s\b" % re.escape(args.module), s)) \
            or any(re.search(r"\b" + re.escape(t) + r"\b", s) for t in owned)
        print("  %-26s %s" % (p, "present" if hit else "ABSENT"))

    print()
    print("=== 5. LIVE ROW COUNTS ===")
    for t in owned:
        print("  %-22s %s" % (t, counts.get(t, "(table absent)")))

    print()
    print("=== VERDICT ===")
    zero = [t for t in owned if not consumer_hits.get(t)]
    if owned and len(zero) == len(owned) and not cross:
        print("  SEAM FOUND: every owned table has ZERO external consumers and the")
        print("  module performs no cross-milestone writes. The layer detects and")
        print("  persists; nothing acts on it. That is the next milestone's objective.")
    else:
        print("  This layer already has consumers; audit a different seam.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

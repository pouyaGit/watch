#!/usr/bin/env python3
"""watch_redirect_hunt.py -- end-to-end redirect-param hunt on Watch targets,
writing results into the Finding collection.

Two tiers:
  1. DISCOVER  mine auth-flow endpoints carrying a redirect-style param from
     Watch's already-crawled data (no requests) and store each as a candidate
     finding (source=redirect-param, severity=info).
  2. CONFIRM   run the nuclei DAST fuzzing template against those in-scope
     endpoints; any endpoint that actually redirects to the external canary is
     stored as a confirmed finding (source=redirect, severity=medium) and alerted.

Confirmation sends live requests, so it only runs against in-scope hosts
(scope + ooscopes checked against Programs), exactly like the nuclei lane.

Usage:
  ./.venv/bin/python scripts/watch_redirect_hunt.py                 # all programs, discover+confirm
  ./.venv/bin/python scripts/watch_redirect_hunt.py --program dell
  ./.venv/bin/python scripts/watch_redirect_hunt.py --no-confirm    # discover only (no requests)
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT)

from database.db import upsert_finding  # noqa: E402
from utils.recon import (  # noqa: E402
    alert, host_of, in_scope, log, run_tool, scope_index,
)

PY = os.path.join(ROOT, ".venv", "bin", "python")
DISCOVER = os.path.join(ROOT, "scripts", "find_redirect_params.py")
TEMPLATE = os.path.join(ROOT, "nuclei", "private_templates", "open-redirect-auth.yaml")


def discover(program, write=True):
    """Run the discovery script (also writing candidate findings) and return
    the list of full endpoint URLs it printed."""
    argv = [PY, DISCOVER]
    if program:
        argv += ["--program", program]
    if write:
        argv += ["--write"]
    out = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    sys.stderr.write(out.stderr)
    endpoints = []
    for line in out.stdout.splitlines():
        # format: [program] <url>  <=  <params>
        if "]" in line and "<=" in line:
            url = line.split("]", 1)[1].split("  <=", 1)[0].strip()
            if url.startswith("http"):
                endpoints.append(url)
    return endpoints


def confirm(endpoints):
    """Run the nuclei DAST template against in-scope endpoints; upsert confirmed."""
    index = scope_index()

    def is_in_scope(url):
        host = host_of(url)
        for prog, (scopes, ooscopes) in index.items():
            if in_scope(host, scopes, ooscopes):
                return prog
        return None

    scoped = [(u, p) for u in endpoints for p in [is_in_scope(u)] if p]
    if not scoped:
        log("redirect-confirm: no in-scope endpoints")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        targets = os.path.join(tmp, "targets.txt")
        out_file = os.path.join(tmp, "out.jsonl")
        with open(targets, "w") as fh:
            fh.write("\n".join(u for u, _ in scoped) + "\n")
        prog_of = {u: p for u, p in scoped}

        argv = ["nuclei", "-dast", "-t", TEMPLATE, "-l", targets,
                "-jsonl", "-o", out_file, "-silent", "-disable-update-check",
                "-rate-limit", "30"]
        log(f"redirect-confirm: nuclei -dast on {len(scoped)} in-scope endpoints")
        rc, _ = run_tool(argv, 1200, quiet=True)
        log(f"redirect-confirm: nuclei rc={rc}")

        found = 0
        if not os.path.exists(out_file):
            return 0
        for line in open(out_file):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            matched = obj.get("matched-at") or obj.get("host") or ""
            host = host_of(matched) or matched
            program = prog_of.get(matched) or next(
                (p for u, p in scoped if host_of(u) == host), "unknown")
            is_new = upsert_finding({
                "program_name": program,
                "target": matched,
                "source": "redirect",
                "name": "open-redirect-auth-confirmed",
                "severity": "medium",
                "matched": matched,
                "extra": {"template": "open-redirect-auth-custom",
                          "confirmed": "Location -> external canary"},
            })
            if is_new:
                found += 1
                alert(f"[redirect] MEDIUM confirmed open-redirect · {matched}")
        return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program")
    ap.add_argument("--no-confirm", action="store_true",
                    help="discover + write candidates only; send no requests")
    args = ap.parse_args()

    endpoints = discover(args.program, write=True)
    log(f"redirect-hunt: {len(endpoints)} candidate endpoints discovered")
    if args.no_confirm:
        return
    n = confirm(endpoints)
    log(f"redirect-hunt: {n} confirmed open-redirect finding(s)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
watch_ffuf_run.py -- opt-in, bounded content discovery for the heavy worker.

For each live in-scope Http service (least-recently-fuzzed first), runs ffuf with a
small wordlist and status filter. Hits become Finding rows with source "content":
paths that look sensitive (.env, .git, backups, admin panels, actuator, swagger...)
are medium and alert once; everything else is info and stays quiet.

ffuf does not follow redirects, so a redirect to another host is never requested.
Results go to Findings only; Endpoints stays limited to crawl output.

This lane is NOT in WATCH_HEAVY_LANES by default. Add it explicitly to enable it.

Usage:
  python3 content/watch_ffuf_run.py --max-minutes 20

Env knobs:
  FFUF_BATCH_HOSTS     hosts per run (default 20)
  FFUF_HOST_TIMEOUT    hard cap seconds per host (default 240)
  FFUF_RATE            requests per second (default 10)
  FFUF_THREADS         concurrent threads (default 4)
  FFUF_RESCAN_DAYS     refuzz a host after this many days (default 14)
  FFUF_WORDLIST        wordlist path (default wordlists/watch_content_small.txt)
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta
from urllib.parse import urlparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mongoengine import Q  # noqa: E402

from database.db import Http, upsert_finding  # noqa: E402
from utils.common import require_tools  # noqa: E402
from utils.recon import (  # noqa: E402
    Deadline, alert, env_int, host_of, in_scope, log, meets_floor, run_tool, scope_index,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DEFAULT_WORDLIST = os.path.join(ROOT, "wordlists", "watch_content_small.txt")
MATCH_CODES = "200,204,301,302,307,401,403"
MIN_HOST_BUDGET_S = 30
GRACE_S = 20

SENSITIVE = re.compile(
    r"(\.env|\.git|\.svn|\.aws|\.npmrc|\.sql|\.bak|\.zip|id_rsa|config|backup|dump|terraform|"
    r"phpinfo|wp-config|server-status|actuator|heapdump|swagger|openapi|api-docs|admin|"
    r"administrator|phpmyadmin|debug|console|web\.config|\.htaccess|crossdomain|docker)",
    re.I,
)


def classify(path):
    return "medium" if SENSITIVE.search(path) else "info"


def _read_results(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh).get("results") or []
    except (ValueError, AttributeError):
        return []


def run_host(http, budget_s, tmp, wordlist):
    host_timeout = min(env_int("FFUF_HOST_TIMEOUT", 240), budget_s)
    out_file = os.path.join(tmp, f"ffuf_{http.id}.json")
    argv = [
        "ffuf", "-u", f"{http.url.rstrip('/')}/FUZZ", "-w", wordlist,
        "-mc", MATCH_CODES, "-ac", "-noninteractive", "-s",
        "-t", str(env_int("FFUF_THREADS", 4)), "-rate", str(env_int("FFUF_RATE", 10)),
        "-timeout", "8", "-maxtime", str(max(10, host_timeout - GRACE_S)),
        "-o", out_file, "-of", "json",
    ]
    rc, _ = run_tool(argv, host_timeout, quiet=True)
    log(f"ffuf {http.url} rc={rc}")
    return _read_results(out_file)


def persist(http, results):
    new_findings = 0
    for r in results:
        url = r.get("url") or ""
        path = (r.get("input") or {}).get("FUZZ") or urlparse(url).path or "/"
        status = r.get("status")
        severity = classify(path)
        is_new = upsert_finding({
            "program_name": http.program_name,
            "scope": http.scope,
            "target": http.url,
            "source": "content",
            "name": "/" + path.lstrip("/"),
            "severity": severity,
            "matched": url,
            "extra": {"status": status, "length": r.get("length")},
        })
        if is_new:
            new_findings += 1
            if meets_floor(severity):
                alert(f"[content] {severity.upper()} · {url} · HTTP {status}")
    return new_findings


def run(deadline, index, cutoff, tmp, wordlist):
    docs = list(
        Http.objects(url__exists=True, url__ne=None)
        .filter(Q(last_ffuf_run=None) | Q(last_ffuf_run__lt=cutoff))
        .order_by("last_ffuf_run", "-created_date")
        .limit(env_int("FFUF_BATCH_HOSTS", 20))
    )
    scanned = findings_total = 0
    for doc in docs:
        if deadline.expired():
            break
        host = host_of(doc.url) or doc.subdomain
        scopes, ooscopes = index.get(doc.program_name, ([], []))
        if not in_scope(host, scopes, ooscopes):
            Http.objects(id=doc.id).update(set__last_ffuf_run=datetime.now())
            continue

        budget = deadline.remaining(env_int("FFUF_HOST_TIMEOUT", 240))
        if budget < MIN_HOST_BUDGET_S:
            break
        log(f"--- ffuf host: {doc.url}")
        results = run_host(doc, budget, tmp, wordlist)
        findings_total += persist(doc, results)
        Http.objects(id=doc.id).update(set__last_ffuf_run=datetime.now())
        scanned += 1

    log(f"=== ffuf pass: {scanned} hosts fuzzed, {findings_total} new findings ===")
    return scanned


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-minutes", type=float, default=None)
    args = parser.parse_args()

    require_tools(["ffuf"])
    wordlist = os.environ.get("FFUF_WORDLIST", DEFAULT_WORDLIST)
    if not os.path.exists(wordlist):
        raise SystemExit(f"ffuf wordlist not found: {wordlist}")

    deadline = Deadline(args.max_minutes)
    index = scope_index()
    cutoff = datetime.now() - timedelta(days=env_int("FFUF_RESCAN_DAYS", 14))

    tmp = tempfile.mkdtemp(prefix="watch-ffuf-")
    try:
        run(deadline, index, cutoff, tmp, wordlist)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()

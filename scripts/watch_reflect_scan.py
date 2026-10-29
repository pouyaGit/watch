"""Fast reflected-XSS triage scanner (a kxss/Gxss we don't have installed).

The param surface is huge (dell: 253k URLs → 26k unique host/path/param-set
signatures) and dalfox is far too slow to cover it. This scans ONE representative
per unique signature, on LIVE hosts only (from the Http collection), injecting a
canary with the four chars that matter for XSS (' " < >) into every param in a
SINGLE request, and reports which params reflect which chars UNENCODED.

Output tiers (what survives next to the canary marker):
  HOT   both < and > survive       -> HTML-tag injection possible -> real XSS candidate
  WARN  " or ' survives            -> attribute/JS-string breakout possible
  echo  only the marker reflects   -> reflected but encoded (not XSS by itself)

This does NOT prove XSS (check context + CSP per HUNT_GUIDE §11b, then dalfox/manual
on the HOT/WARN hits). It just turns 26k candidates into the few worth that effort.
Read-only: one GET per URL with a benign marker; no payload execution.

Usage:
  python3 scripts/watch_reflect_scan.py --program dell --limit 3000
  python3 scripts/watch_reflect_scan.py --program wien           # all live sigs
"""
import argparse
import random
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlencode

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch")
from database.db import Urls, Http  # noqa: E402

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
CHARS = "'\"<>"            # the four that decide XSS
OUT = "/opt/watch/logs/xss"


def live_hosts(program, days=5):
    fresh = datetime.now() - timedelta(days=days)
    hs = set()
    for h in Http.objects(program_name=program).only("subdomain", "status_code", "last_update"):
        if h.status_code and (not h.last_update or h.last_update >= fresh):
            hs.add((h.subdomain or "").lower())
    return hs


def signatures(program, live):
    """One representative URL per unique (host, path, sorted param-set), live hosts only."""
    seen, reps = set(), []
    for u in Urls.objects(program_name=program).only("url", "params", "subdomain", "path"):
        if not u.params or not u.subdomain:
            continue
        host = u.subdomain.lower()
        if host not in live:
            continue
        key = (host, u.path or urlsplit(u.url).path, tuple(sorted(u.params)))
        if key in seen:
            continue
        seen.add(key)
        reps.append((u.url, list(u.params)))
    return reps


def probe(url, params):
    # unique marker per param so we know which one reflected
    tag = "kx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
    markers = {}
    sp = urlsplit(url)
    base = f"{sp.scheme or 'https'}://{sp.netloc}{sp.path}"
    q = {}
    for i, p in enumerate(params):
        m = f"{tag}{i}z"
        markers[p] = m
        q[p] = m + CHARS           # marker + ' " < >
    try:
        r = requests.get(base + "?" + urlencode(q), headers={"User-Agent": UA},
                         timeout=8, verify=False, allow_redirects=False)
        body = r.text
        ctype = (r.headers.get("Content-Type") or "").lower()
        nosniff = "nosniff" in (r.headers.get("X-Content-Type-Options") or "").lower()
    except Exception:
        return []
    is_html = "text/html" in ctype or ctype == ""
    # Reflection in application/javascript or application/json with nosniff can't be
    # rendered as HTML (the Jira batch.js locale class) -> NOT an HTML-XSS; downgrade it.
    non_html_safe = (not is_html) and nosniff
    hits = []
    for p, m in markers.items():
        idx = body.find(m)
        if idx < 0:
            continue
        after = body[idx + len(m): idx + len(m) + 6]
        got = {c for c in CHARS if c in after}
        tag_inj = "<" in got and ">" in got
        quote = '"' in got or "'" in got
        if tag_inj and is_html:
            tier = "HOT"                      # HTML tag injection -> real XSS candidate
        elif (tag_inj or quote) and non_html_safe:
            tier = "js-nosniff"               # reflected in JS/JSON+nosniff -> not HTML-XSS
        elif quote and is_html:
            tier = "WARN"                     # attribute/JS-string breakout in HTML
        elif tag_inj or quote:
            tier = "js-reflect"               # non-HTML without nosniff -> manual (string breakout?)
        else:
            tier = "echo"
        hits.append((tier, base, p, "".join(sorted(got)) or "(encoded)", ctype.split(";")[0]))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", required=True)
    ap.add_argument("--limit", type=int, help="cap signatures (for a bounded run)")
    ap.add_argument("--workers", type=int, default=40)
    args = ap.parse_args()

    live = live_hosts(args.program)
    reps = signatures(args.program, live)
    if args.limit:
        reps = reps[:args.limit]
    print(f"[*] {args.program}: {len(live)} live hosts, scanning {len(reps)} unique param signatures",
          flush=True)

    buckets = {"HOT": [], "WARN": [], "js-reflect": [], "js-nosniff": []}
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(probe, u, p): u for u, p in reps}
        for f in as_completed(futs):
            done += 1
            for tier, base, p, got, ctype in f.result():
                if tier == "echo":
                    continue
                line = f"{base}  [{p}]  -> {got}  ({ctype})"
                buckets[tier].append(line)
                if tier == "HOT":
                    print(f"[HOT ] {line}", flush=True)
            if done % 500 == 0:
                print(f"  [{done}/{len(reps)}] HOT={len(buckets['HOT'])} "
                      f"WARN={len(buckets['WARN'])} js={len(buckets['js-reflect'])}", flush=True)

    import os
    os.makedirs(OUT, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{OUT}/reflect_{args.program}_{stamp}.txt"
    labels = {
        "HOT": "HTML tag injection (< and > unencoded in text/html) -> REAL XSS candidate",
        "WARN": "quote breakout in text/html (attribute / JS-string)",
        "js-reflect": "reflected in non-HTML without nosniff -> manual (string breakout?)",
        "js-nosniff": "reflected in JS/JSON + nosniff -> NOT HTML-XSS (e.g. Jira batch.js locale)",
    }
    with open(path, "w") as fh:
        for tier in ("HOT", "WARN", "js-reflect", "js-nosniff"):
            fh.write(f"\n# {tier} — {labels[tier]}: {len(buckets[tier])}\n")
            fh.write("\n".join(buckets[tier]) + "\n")
    print(f"\n=== {args.program}: HOT={len(buckets['HOT'])} WARN={len(buckets['WARN'])} "
          f"js-reflect={len(buckets['js-reflect'])} js-nosniff={len(buckets['js-nosniff'])} ===")
    print(f"wrote {path}")
    print("Next: for each HOT, check context + CSP (HUNT_GUIDE §11b), then dalfox/manual to confirm.")


if __name__ == "__main__":
    main()

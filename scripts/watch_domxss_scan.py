"""DOM-XSS source->sink triage over the program's JavaScript.

The reflection scanner (watch_reflect_scan.py) only finds SERVER-side reflections.
DOM XSS lives in the client JS: an attacker-controlled SOURCE (location.hash/search,
document.referrer, window.name, postMessage .data, storage) flowing into a dangerous
SINK (innerHTML, document.write, eval, setTimeout(str), location=, jQuery .html(), …).

This fetches the program's live .js files, finds every sink, and reports the ones with a
SOURCE within ~400 chars before them (the flow is plausible). Static co-occurrence is a
LEAD, not proof — DOM XSS only counts when it FIRES in a real browser, so confirm each HOT
with the built-in browser / Playwright per HUNT_GUIDE §12 item 12 (hermes-domxss-verifier).

Read-only: GETs each JS once. Does not execute anything.

Usage:
  python3 scripts/watch_domxss_scan.py --program dell --limit 1500
  python3 scripts/watch_domxss_scan.py --program wien
"""
import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch")
from database.db import Urls, Http  # noqa: E402

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
OUT = "/opt/watch/logs/xss"
MAX_BYTES = 2_000_000
PROX = 400  # a source this many chars before a sink = plausible flow

# HTML-injection / code-exec sinks = DOM XSS if an attacker source reaches them.
SINKS_XSS = re.compile(
    r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|"
    r"\.insertAdjacentHTML\s*\(|\beval\s*\(|new\s+Function\s*\(|"
    r"setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]|"
    r"\.html\s*\(|dangerouslySetInnerHTML", re.I)
# Navigation sinks = DOM open-redirect, or XSS only via a javascript:/data: URI.
SINKS_NAV = re.compile(
    r"location\s*=|location\.href\s*=|location\.assign\s*\(|location\.replace\s*\(|"
    r"\.setAttribute\s*\(|\bwindow\.open\s*\(", re.I)
SINKS = re.compile(SINKS_XSS.pattern + "|" + SINKS_NAV.pattern, re.I)

# Directly attacker-controlled sources (the classic DOM-XSS entry points).
# NOTE: bare `e.data`/`event.data` is dropped — it matches jQuery event data (huge FP
# source). postMessage is caught by the `addEventListener('message'` registration instead.
SOURCES_STRONG = re.compile(
    r"location\.hash|location\.search|document\.documentURI|document\.referrer|"
    r"window\.name|\.searchParams|addEventListener\s*\(\s*['\"]message['\"]", re.I)
# Weaker / often-sanitised or same-origin sources (more noise).
SOURCES = re.compile(SOURCES_STRONG.pattern +
    r"|location\.href|document\.URL|URLSearchParams|localStorage|sessionStorage",
    re.I)


def live_hosts(program, days=5):
    fresh = datetime.now() - timedelta(days=days)
    return {(h.subdomain or "").lower() for h in
            Http.objects(program_name=program).only("subdomain", "status_code", "last_update")
            if h.status_code and (not h.last_update or h.last_update >= fresh)}


def js_urls(program, live):
    seen = []
    s = set()
    for u in Urls.objects(program_name=program).only("url", "subdomain"):
        if not u.url or not u.url.lower().split("?")[0].endswith(".js"):
            continue
        if (u.subdomain or "").lower() not in live or u.url in s:
            continue
        s.add(u.url)
        seen.append(u.url)
    return seen


def scan(url):
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=10, verify=False, stream=True)
        body = r.raw.read(MAX_BYTES, decode_content=True).decode("utf-8", "replace")
    except Exception:
        return []
    src_pos = [(m.start(), m.group(0)) for m in SOURCES.finditer(body)]
    if not src_pos:
        return []
    hits = []
    for m in SINKS.finditer(body):
        s = m.start()
        near = [(p, t) for p, t in src_pos if 0 <= s - p <= PROX]
        if not near:
            continue
        sink_txt = body[s:m.end()].strip()
        src_txt = near[-1][1]
        is_xss_sink = bool(SINKS_XSS.match(sink_txt)) or bool(SINKS_XSS.search(sink_txt))
        is_strong_src = bool(SOURCES_STRONG.search(src_txt))
        if is_xss_sink and is_strong_src:
            tier = "HOT"            # strong source -> html/exec sink = real DOM-XSS candidate
        elif is_xss_sink:
            tier = "review"         # weak source -> html/exec sink
        elif is_strong_src:
            tier = "redirect"       # strong source -> navigation sink (DOM open-redirect / js: URI)
        else:
            tier = "low"
        snippet = re.sub(r"\s+", " ", body[max(0, s - 90):s + 50]).strip()
        hits.append((tier, url, sink_txt, src_txt, snippet[:170]))
    out, seen = [], set()
    for h in hits:
        k = (h[1], h[2], h[3])
        if k not in seen:
            seen.add(k); out.append(h)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=30)
    args = ap.parse_args()

    live = live_hosts(args.program)
    urls = js_urls(args.program, live)
    if args.limit:
        urls = urls[:args.limit]
    print(f"[*] {args.program}: {len(live)} live hosts, scanning {len(urls)} live .js files", flush=True)

    buckets = {"HOT": [], "review": [], "redirect": [], "low": []}
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for f in as_completed({ex.submit(scan, u): u for u in urls}):
            done += 1
            for tier, url, sink, src, snip in f.result():
                buckets[tier].append((url, sink, src, snip))
                if tier == "HOT":
                    print(f"[HOT] {url}\n      {src!r} -> {sink!r}\n      {snip!r}", flush=True)
            if done % 200 == 0:
                print(f"  [{done}/{len(urls)}] HOT={len(buckets['HOT'])} "
                      f"review={len(buckets['review'])} redirect={len(buckets['redirect'])}", flush=True)

    import os
    os.makedirs(OUT, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{OUT}/domxss_{args.program}_{stamp}.txt"
    labels = {
        "HOT": "STRONG source (hash/search/referrer/window.name/postMessage) -> html/exec sink = real DOM-XSS candidate",
        "review": "weak source -> html/exec sink (often library noise, but check)",
        "redirect": "STRONG source -> navigation sink = DOM open-redirect / javascript:-URI XSS",
        "low": "weak source -> navigation sink (mostly noise)",
    }
    with open(path, "w") as fh:
        for tier in ("HOT", "redirect", "review", "low"):
            fh.write(f"\n# {tier} — {labels[tier]}: {len(buckets[tier])}\n")
            for url, sink, src, snip in buckets[tier]:
                fh.write(f"{url}\n  {src!r} -> {sink!r}\n  {snip!r}\n\n")
    print(f"\n=== {args.program}: HOT={len(buckets['HOT'])} redirect={len(buckets['redirect'])} "
          f"review={len(buckets['review'])} low={len(buckets['low'])} ===")
    print(f"wrote {path}")
    print("Confirm each HOT: read the function, verify the attacker source reaches the sink unsanitised,")
    print("then FIRE it in a real browser (hermes-domxss-verifier). A static match is a LEAD, not XSS.")


if __name__ == "__main__":
    main()

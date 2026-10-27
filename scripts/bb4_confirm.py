#!/usr/bin/env python3
"""bb4_confirm.py -- active confirmation of open redirects on the harvested
candidate list.

For every finding line in the 4-platform report it rebuilds the URL with EVERY
redirect-style parameter set to the canary value (default https://google.com),
sends ONE GET (no follow-redirects), and records the result. A hit is:

  * HTTP 30x with Location pointing at the canary host (google.com, or any
    *.google.com / //google.com / encoded form), or
  * a 200/30x body or Location carrying the canary in a JS/meta refresh.

Everything is passive-first: only the endpoint's own parameter is changed, no
fuzzing, no auth, one request per endpoint. Output is resumable (jsonl append)
so a slow run can be restarted without re-hitting confirmed endpoints.

Usage:
  ./.venv/bin/python scripts/bb4_confirm.py --limit 50          # smoke
  ./.venv/bin/python scripts/bb4_confirm.py --workers 8         # full list
  ./.venv/bin/python scripts/bb4_confirm.py --platform yeswehack
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import threading
import time
import urllib.parse
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings()

ROOT = "/opt/watch"
OUTDIR = os.path.join(ROOT, "logs", "bb4", "confirm")
REPORT = os.path.join(ROOT, "reports", "redirect-params-4platforms-20261026.md")
CANARY_DEFAULT = "https://google.com"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")

_lock = threading.Lock()
_lockdata = {"requests": 0, "hits": 0}


def load_candidates(path, platforms=None, only=None):
    """Yield (platform, program, program_url, raw_url, param_names)."""
    plat = prog = prog_url = None
    out = []
    with open(path) as fh:
        for ln in fh:
            s = ln.rstrip("\n")
            if s.startswith("## "):
                head = s[3:]
                plat = head.split(" (")[0].lower().replace(" ", "")
                plat = {"hackerone": "hackerone", "bugcrowd": "bugcrowd",
                        "yeswehack": "yeswehack", "intigriti": "intigriti"}.get(plat, plat)
            elif s.startswith("### "):
                prog = s[4:].rsplit(" — ", 1)[0]
                prog_url = None
            elif s.startswith("program: "):
                prog_url = s[9:].strip()
            elif s.startswith("http"):
                if platforms and plat not in platforms:
                    continue
                if only and only.lower() not in (prog or "").lower():
                    continue
                names = [kv.split("=", 1)[0]
                         for kv in (urlsplit(s).query or "").split("&")
                         if "=" in kv]
                if not names:
                    continue
                out.append((plat, prog, prog_url, s, names))
    return out


def with_canary(url, names=None, canary=None):
    """Set EVERY redirect-style parameter (wordlist names) to the canary and
    leave every other parameter untouched — rewriting unrelated params (flow,
    pid, state) breaks the endpoint and hides real redirects.
    Callable as with_canary(url, canary) or with_canary(url, names, canary)."""
    if canary is None:
        canary, names = names, None
    sp = urlsplit(url)
    parts = []
    for kv in sp.query.split("&"):
        if "=" not in kv:
            parts.append(kv)
            continue
        k = kv.split("=", 1)[0]
        if k.lower() in REDIRECT_NAMES:
            parts.append(f"{k}={urllib.parse.quote(canary, safe='')}")
        else:
            parts.append(kv)
    return urllib.parse.urlunsplit(
        (sp.scheme, sp.netloc, sp.path, "&".join(parts), sp.fragment))


def load_redirect_names():
    p = os.path.join(ROOT, "wordlists", "redirect-params.txt")
    with open(p) as fh:
        return {ln.strip().lower() for ln in fh if ln.strip()}


REDIRECT_NAMES = load_redirect_names()


CANARY_HOST_RE = re.compile(r"(^|[/.\-=])google\.com(\.|/|:|\?|#|$)", re.I)


def location_offhost(loc, canary):
    """True when the Location header sends the browser to our canary host."""
    if not loc:
        return False
    loc = loc.strip()
    try:
        loc = urllib.parse.unquote(loc)
    except Exception:
        pass
    low = loc.lower()
    if not (low.startswith("http://") or low.startswith("https://")
            or low.startswith("//")):
        return False
    host = urlsplit(low if not low.startswith("//") else "https:" + low).hostname or ""
    return host == "google.com" or host.endswith(".google.com")


def probe(session, cand, canary, timeout, verify=False):
    plat, prog, prog_url, url, names = cand
    test = with_canary(url, names, canary)
    res = {"platform": plat, "program": prog, "program_url": prog_url,
           "endpoint": url, "tested": test, "params": names,
           "status": None, "location": None, "hit": False, "why": None,
           "error": None}
    try:
        r = session.get(test, allow_redirects=False, timeout=timeout,
                        verify=verify, headers={"User-Agent": UA})
        res["status"] = r.status_code
        loc = r.headers.get("Location") or r.headers.get("location")
        res["location"] = (loc or "")[:500]
        if r.status_code in (301, 302, 303, 307, 308) and location_offhost(loc, canary):
            res["hit"] = True
            res["why"] = "3xx Location -> canary host"
        elif r.status_code < 400:
            body = r.text[:200000] if r.text else ""
            if CANARY_HOST_RE.search(body) and re.search(
                    r"(location\s*[=:]|http-equiv=[\"']?refresh|window\.location|"
                    r"document\.location)", body, re.I):
                res["hit"] = True
                res["why"] = "client-side redirect carries canary"
    except requests.exceptions.SSLError as e:
        res["error"] = f"ssl: {str(e)[:120]}"
    except requests.exceptions.RequestException as e:
        res["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=REPORT)
    ap.add_argument("--canary", default=CANARY_DEFAULT)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--platform", action="append", default=None)
    ap.add_argument("--program", default=None, help="substring of program name")
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--tag", default="run1")
    args = ap.parse_args()

    os.makedirs(OUTDIR, exist_ok=True)
    cands = load_candidates(args.report, args.platform, args.program)
    if args.limit:
        cands = cands[:args.limit]

    out_path = os.path.join(OUTDIR, f"confirm_{args.tag}.jsonl")
    done = set()
    if os.path.exists(out_path):
        with open(out_path) as fh:
            for ln in fh:
                try:
                    done.add(json.loads(ln)["tested"])
                except Exception:
                    continue
    todo = [c for c in cands if with_canary(c[3], c[4], args.canary) not in done]
    print(f"[*] {len(cands)} candidates, {len(done)} already probed, "
          f"{len(todo)} to go, canary={args.canary}", flush=True)

    sess_local = threading.local()

    def get_session():
        s = getattr(sess_local, "s", None)
        if s is None:
            s = requests.Session()
            sess_local.s = s
        return s

    hits = 0
    with open(out_path, "a") as fh:
        def work(c):
            return probe(get_session(), c, args.canary, args.timeout,
                         verify=args.verify_tls)

        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(work, c): c for c in todo}
            for i, fut in enumerate(cf.as_completed(futs), 1):
                try:
                    res = fut.result()
                except Exception as e:  # noqa: BLE001
                    continue
                with _lock:
                    fh.write(json.dumps(res) + "\n")
                    fh.flush()
                    _lockdata["requests"] += 1
                    if res["hit"]:
                        hits += 1
                        _lockdata["hits"] += 1
                if res["hit"]:
                    print(f"[HIT] {res['program']} :: {res['status']} -> "
                          f"{res['location'][:90]}  ({res['endpoint'][:90]})",
                          flush=True)
                elif i % 100 == 0:
                    print(f"[{i}/{len(todo)}] {hits} hits, "
                          f"{_lockdata['requests']} req", flush=True)

    print(f"\n[+] done: {_lockdata['requests']} requests, {hits} redirect hits"
          f" -> {out_path}", flush=True)


if __name__ == "__main__":
    main()

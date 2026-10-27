"""Strict confirmation of the recovered Watch redirect candidates.

A finding requires: canary run lands on google.com AND the untouched baseline
does not. Everything else is recorded with its actual behaviour.
"""
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch/scripts")
import bb4_confirm as C  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"}
CANARY = "https://google.com"
REDIR = (301, 302, 303, 307, 308)
SRC = "/opt/watch/logs/bb4/watch_redirect_candidates.json"


def host(loc):
    if not loc or not loc.strip().startswith(("http://", "https://", "//")):
        return ""
    loc = loc.strip()
    try:
        return (urlsplit(loc if not loc.startswith("//") else "https:" + loc)
                .hostname or "").lower()
    except ValueError:
        return ""


def probe(url):
    try:
        r = requests.get(url, allow_redirects=False, timeout=15, verify=False,
                         headers=UA)
        return {"status": r.status_code,
                "location": (r.headers.get("Location") or "")[:300]}
    except Exception as e:  # noqa: BLE001
        return {"status": None, "location": "", "err": type(e).__name__}


def work(rec):
    url = rec["url"]
    base = probe(url)
    test = C.with_canary(url, CANARY)
    can = probe(test)
    bh, ch = host(base["location"]), host(can["location"])
    real = can["status"] in REDIR and ch == "google.com" and bh != "google.com"
    if real:
        verdict = "open-redirect"
    elif base["status"] is None and can["status"] is None:
        verdict = "unreachable"
    elif can["status"] in REDIR and bh != ch and ch:
        verdict = "redirect-changed-host"
    elif base["status"] in REDIR and can["status"] and can["status"] >= 400:
        verdict = "validated-rejected"
    elif base["status"] and can["status"] and base["status"] >= 400 and can["status"] >= 400:
        verdict = "blocked"
    elif (base["status"] or 0) < 300 and (can["status"] or 0) < 300:
        verdict = "no-redirect"
    else:
        verdict = "other"
    return dict(rec, baseline=base, canary_resp=can, test_url=test,
                verdict=verdict)


def main():
    recs = json.load(open(SRC))
    print(f"[*] {len(recs)} recovered candidates", flush=True)
    out = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for i, r in enumerate(ex.map(work, recs), 1):
            out.append(r)
            if r["verdict"] == "open-redirect":
                print(f"[HIT] {r['program']} {r['url'][:100]} -> "
                      f"{r['canary_resp']['location'][:60]}", flush=True)
            if i % 25 == 0:
                print(f"[{i}/{len(recs)}]", flush=True)

    import collections
    c = collections.Counter(r["verdict"] for r in out)
    print("\n[+]", dict(c))
    with open("/opt/watch/logs/bb4/watch_redirect_confirmed.json", "w") as fh:
        json.dump(out, fh, indent=1)

    print("\n== detailed verdicts")
    for r in out:
        print(f"{r['verdict']:20} {r['program']:9} "
              f"base {r['baseline']['status']}->{host(r['baseline']['location'])[:28]!r:30} "
              f"cana {r['canary_resp']['status']}->{host(r['canary_resp']['location'])[:28]!r}")
        print(f"   {r['url'][:150]}")


if __name__ == "__main__":
    main()

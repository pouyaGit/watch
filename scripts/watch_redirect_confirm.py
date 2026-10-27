"""Confirm the redirect-param findings that Watch wrote into the Finding
collection (dell / digicert / indeed), using the strict differential:
  * untouched archived URL  vs  URL with redirect params -> https://google.com
  * a hit requires the canary run to land on google.com while the baseline does not
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch")
sys.path.insert(0, "/opt/watch/scripts")
from database.db import Finding  # noqa: E402
import bb4_confirm as C  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"}
CANARY = "https://google.com"


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
        return {"status": r.status_code, "location": (r.headers.get("Location") or "")[:300]}
    except Exception as e:  # noqa: BLE001
        return {"status": None, "location": "", "err": type(e).__name__}


def work(f):
    url = f.matched or f.target
    base = probe(url)
    test = C.with_canary(url, CANARY)
    can = probe(test)
    bh, ch = host(base["location"]), host(can["location"])
    redir = (301, 302, 303, 307, 308)
    real = can["status"] in redir and ch == "google.com" and bh != "google.com"
    return f, url, test, base, can, real


def main():
    rows = list(Finding.objects(source="redirect-param", status="open"))
    print(f"[*] {len(rows)} redirect-param candidates", flush=True)
    hits, fps, untested = [], [], []
    with ThreadPoolExecutor(max_workers=10) as ex:
        for i, (f, url, test, base, can, real) in enumerate(ex.map(work, rows), 1):
            if real:
                hits.append((f, url, test, base, can))
                print(f"[HIT] {f.program_name} {url[:90]} -> {can['location'][:60]}")
            elif base["status"] is None and can["status"] is None:
                untested.append((f, url, base))
            else:
                fps.append((f, url, base, can))
            if i % 40 == 0:
                print(f"[{i}/{len(rows)}] hits={len(hits)}", flush=True)

    print(f"\n[+] real={len(hits)} disproved={len(fps)} unreachable={len(untested)}")

    # persist verdicts
    for f, url, test, base, can in hits:
        ex = f.extra if isinstance(f.extra, dict) else {}
        ex.update(verified="open redirect confirmed", test_url=test,
                  baseline=f"{base['status']} {base['location'][:120]}",
                  canary=f"{can['status']} {can['location'][:120]}")
        f.extra, f.status = ex, "triaged"
        f.save()
    for f, url, base, can in fps:
        ex = f.extra if isinstance(f.extra, dict) else {}
        ex.update(verified="not an open redirect (baseline comparison)",
                  baseline=f"{base['status']} {base['location'][:120]}",
                  canary=f"{can['status']} {can['location'][:120]}")
        f.extra, f.status = ex, "false_positive"
        f.save()

    out = "/opt/watch/logs/bb4/watch_redirect_confirm.json"
    json.dump({"hits": [{"program": h[0].program_name, "url": h[1],
                         "test": h[2], "canary_loc": h[4]["location"]} for h in hits],
               "counts": {"total": len(rows), "hits": len(hits),
                          "disproved": len(fps), "unreachable": len(untested)}},
              open(out, "w"), indent=1)
    print("wrote", out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""watch_api_posture.py -- unauthenticated API posture sweep.

For every host that exposes /api paths in the corpus: fetch each recorded path
plus a nonexistent control on the same host. A host whose control also returns
403/404-with-shell is WAF-masked and its results are discarded as untested.
A hit = 200 + JSON content-type + body starting { or [ + differs from control,
and the body is not an auth/permission message.
"""
import collections
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch")
from database.db import Endpoints  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Accept": "application/json, text/html;q=0.9,*/*;q=0.8"}
T = 15
DENY = ("unauthoriz", "forbidden", "access denied", "not authorized",
        "authentication required", "login", "permission")


def get(url, **kw):
    try:
        return requests.get(url, timeout=T, verify=False, headers=UA,
                            allow_redirects=False, **kw)
    except Exception:
        return None


def probe_host(args):
    host, paths = args
    base = f"https://{host}"
    ctl = get(base + "/zq-nonexistent-7c1f9")
    if ctl is None:
        return host, [], "dead"
    ctl_len = len(ctl.content or b"")
    masked = ctl.status_code in (401, 403, 429, 503)

    hits = []
    for p in paths[:12]:
        r = get(base + p)
        if r is None:
            continue
        ct = (r.headers.get("content-type") or "").lower()
        body = (r.text or "").strip()
        if r.status_code != 200 or "json" not in ct:
            continue
        if body[:1] not in ("{", "["):
            continue
        if abs(len(r.content or b"") - ctl_len) < 40 and ctl_len:
            continue
        low = body[:400].lower()
        if any(d in low for d in DENY):
            continue
        hits.append({"path": p, "len": len(r.content), "snippet": body[:220]})
    return host, hits, ("masked" if masked else "testable")


def main():
    byhost = collections.defaultdict(set)
    for e in Endpoints.objects(path__startswith="/api").only("example_url", "path"):
        h = urlsplit(e.example_url or "").netloc
        if h:
            byhost[h].add(e.path or "")
    tasks = [(h.replace(":443", ""), sorted(ps)) for h, ps in byhost.items() if ps]
    print(f"[*] {len(tasks)} hosts with /api paths", flush=True)

    allhits, masked, dead, testable = [], 0, 0, 0
    with ThreadPoolExecutor(max_workers=20) as ex:
        for host, hits, st in ex.map(probe_host, tasks):
            if st == "masked":
                masked += 1
            elif st == "dead":
                dead += 1
            else:
                testable += 1
            for h in hits:
                allhits.append({"host": host, **h})
                print(f"[JSON] {host}{h['path'][:60]} len={h['len']}", flush=True)

    print(f"\n[+] testable={testable} waf-masked={masked} dead={dead} "
          f"json_hits={len(allhits)}")
    json.dump({"hits": allhits, "testable": testable, "masked": masked,
               "dead": dead},
              open("/opt/watch/logs/bb4/api_posture.json", "w"), indent=1)


if __name__ == "__main__":
    main()

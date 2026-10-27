"""Recorded admin/internal/user-listing paths on hosts that are NOT WAF-masked,
tested unauthenticated. Only paths already present in the corpus are used - no
path guessing. A host whose nonexistent control is 401/403/503 is skipped as
masked (its answers carry no information)."""
import collections
import json
import re
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
      "Accept": "application/json, */*"}
KEY = re.compile(r"/(admin|internal|manage|user|users|account|accounts|"
                 r"listing|export|download|report|audit|staff|employee)", re.I)
DENY = ("unauthoriz", "forbidden", "access denied", "not authenticated",
        "authentication is required", "login")
T = 15


def probe(item):
    host, paths = item
    base = f"https://{host}"
    try:
        c = requests.get(base + "/zq-nonexistent-7c1f9", timeout=T, verify=False,
                         headers=UA, allow_redirects=False)
    except Exception:
        return host, [], "dead"
    if c.status_code in (401, 403, 429, 503):
        return host, [], "masked"
    hits = []
    for p in paths:
        try:
            r = requests.get(base + p, timeout=T, verify=False, headers=UA,
                             allow_redirects=False)
        except Exception:
            continue
        ct = (r.headers.get("content-type") or "").lower()
        body = (r.text or "").strip()
        if r.status_code != 200 or "json" not in ct or body[:1] not in ("{", "["):
            continue
        if any(d in body[:400].lower() for d in DENY):
            continue
        if c.status_code == 200 and abs(len(r.content) - len(c.content)) < 40:
            continue
        hits.append({"path": p, "len": len(r.content), "snip": body[:200]})
    return host, hits, "testable"


def main():
    byhost = collections.defaultdict(set)
    for e in Endpoints.objects(path__startswith="/").only("example_url", "path"):
        p = e.path or ""
        if not KEY.search(p):
            continue
        h = urlsplit(e.example_url or "").netloc
        if h:
            byhost[h.replace(":443", "")].add(p)
    tasks = [(h, sorted(ps)[:10]) for h, ps in byhost.items() if ps]
    print(f"[*] {len(tasks)} hosts carry admin/user paths", flush=True)

    hits, masked, testable = [], 0, 0
    with ThreadPoolExecutor(max_workers=20) as ex:
        for host, h, st in ex.map(probe, tasks):
            if st == "masked":
                masked += 1
            elif st == "testable":
                testable += 1
            for x in h:
                hits.append({"host": host, **x})
                print(f"[JSON] {host}{x['path'][:60]} len={x['len']}", flush=True)

    print(f"\n[+] testable={testable} masked={masked} hits={len(hits)}")
    json.dump(hits, open("/opt/watch/logs/bb4/admin_posture.json", "w"), indent=1)


if __name__ == "__main__":
    main()

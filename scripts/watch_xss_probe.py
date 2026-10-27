"""Reflection/XSS probe for the Watch redirect-param endpoints that echo the
value (Location or body).

Marker discipline per hunt-xss: a unique random alphanumeric token, built so it
survives escaping CONTIGUOUSLY. For every endpoint+param we send:

  1. <tok>            -- does the value reach the response at all?
  2. <tok><           -- is '<' escaped in that context?
  3. <tok>"><         -- does the quote break out of an attribute?
  4. <tok>'><         -- single-quote variant

and classify raw / escaped / absent by searching for the token first, then
looking at the bytes immediately around it.
"""
import json
import random
import re
import string

import requests
import urllib3
from urllib.parse import urlsplit, urlunsplit, quote, parse_qsl, urlencode

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

SRC = "/opt/watch/logs/bb4/watch_redirect_confirmed.json"
OUT = "/opt/watch/logs/bb4/watch_xss_probe.json"

PARAM_NAMES = {ln.strip().lower() for ln in open("/opt/watch/wordlists/redirect-params.txt")}


def tok(n=10):
    return "zq" + "".join(random.choice(string.ascii_lowercase + string.digits)
                          for _ in range(n))


def swap(url, param, value):
    sp = urlsplit(url)
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    out = [(k, value if k == param else v) for k, v in pairs]
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(out), ""))


def fetch(url, timeout=20):
    try:
        r = requests.get(url, timeout=timeout, verify=False, headers=UA,
                         allow_redirects=False)
        return {"status": r.status_code, "body": r.text[:300000],
                "location": r.headers.get("Location") or ""}
    except Exception as e:  # noqa: BLE001
        return {"status": None, "body": "", "location": "", "err": type(e).__name__}


def context(body, mark):
    """Return ~120 chars around the first occurrence of mark."""
    i = body.find(mark)
    if i < 0:
        return ""
    return re.sub(r"\s+", " ", body[max(0, i - 90):i + len(mark) + 90])


def classify(text, mark):
    if not text or mark not in text:
        return "absent", ""
    return "present", context(text, mark)


def main():
    recs = json.load(open(SRC))
    cands = [r for r in recs if r["verdict"] in
             ("other", "redirect-changed-host", "validated-rejected")]
    results = []
    for r in cands:
        sp = urlsplit(r["url"])
        params = [k for k, _ in parse_qsl(sp.query, keep_blank_values=True)
                  if k.lower() in PARAM_NAMES]
        if not params:
            continue
        for p in params:
            t = tok()
            res = {"program": r["program"], "url": r["url"], "param": p,
                   "token": t, "probes": {}}

            base = fetch(swap(r["url"], p, t))
            res["probes"]["plain"] = {
                "url": swap(r["url"], p, t),
                "status": base["status"],
                "body": classify(base["body"], t)[0],
                "loc": classify(base["location"], t)[0],
                "ctx": classify(base["body"], t)[1] or
                       ("LOCATION: " + base["location"][:200]
                        if t in base["location"] else ""),
            }
            # control: token must not appear when we do NOT send it
            ctl = fetch(r["url"])
            res["control_body_has_token"] = t in ctl["body"]

            for name, payload in (("lt", f"{t}<"), ("qt", f'{t}">"<'),
                                  ("sq", f"{t}'>'<")):
                p2 = fetch(swap(r["url"], p, payload))
                res["probes"][name] = {
                    "payload": payload,
                    "status": p2["status"],
                    "body": classify(p2["body"], t)[0],
                    "raw_lt": "raw" if f"{t}</" in p2["body"] or
                                       f"{t}<" in p2["body"] else
                              ("escaped" if "&lt;" in p2["body"] and t in p2["body"]
                               else "unknown"),
                    "ctx": classify(p2["body"], t)[1],
                }
            results.append(res)
            print(f"{r['program']:9} {p:16} body={res['probes']['plain']['body']:8} "
                  f"loc={res['probes']['plain']['loc']:8} "
                  f"lt={res['probes']['lt']['raw_lt']:8} {r['url'][:70]}", flush=True)

    json.dump(results, open(OUT, "w"), indent=1)
    refl = [x for x in results if x["probes"]["plain"]["body"] == "present"
            or x["probes"]["plain"]["loc"] == "present"]
    raw = [x for x in refl if x["probes"]["lt"]["raw_lt"] == "raw"]
    print(f"\n[+] {len(results)} param probes, {len(refl)} echo the value, "
          f"{len(raw)} with a RAW '<' -> {OUT}")


if __name__ == "__main__":
    main()

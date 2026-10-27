#!/usr/bin/env python3
"""bb4_verify_hits.py -- strict second pass over the redirect hits.

Why strict: the first pass accepted any `*.google.com` Location as "canary"
which is wrong (accounts.google.com is a legit Google host, not our payload),
and it treated an <meta og:url> echo of the request URL as a client-side
redirect. Both produced false positives.

Rules here:
  * Location host must EQUAL the canary host (no subdomain wildcard).
  * A client-side hit needs real redirect semantics (location assignment,
    location.replace, meta http-equiv=refresh, window.open) whose target is the
    canary — an echo inside og:url / canonical / href metadata is NOT a redirect.
  * Each endpoint is tested with TWO different external canaries; a genuine open
    redirect follows both.
"""
import argparse
import glob
import json
import os
import re
import time
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings()

CANARIES = ["https://example.org/", "https://www.bing.com/"]
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")
ROOT = "/opt/watch"
WL = os.path.join(ROOT, "wordlists", "redirect-params.txt")
with open(WL) as fh:
    REDIRECT_NAMES = {ln.strip().lower() for ln in fh if ln.strip()}

REAL_REDIRECT = re.compile(
    r"(location\s*(?:\.href)?\s*=\s*|location\.(?:replace|assign)\s*\(\s*|"
    r"window\.location\s*=\s*|window\.open\s*\(\s*|"
    r"http-equiv\s*=\s*[\"']?refresh)", re.I)


def with_canary(url, canary):
    sp = urlsplit(url)
    parts = []
    for kv in sp.query.split("&"):
        if "=" not in kv:
            parts.append(kv)
            continue
        k = kv.split("=", 1)[0]
        if k.lower() in REDIRECT_NAMES:
            from urllib.parse import quote
            parts.append(f"{k}={quote(canary, safe='')}")
        else:
            parts.append(kv)
    return sp._replace(query="&".join(parts)).geturl()


def host_is_canary(loc, canary):
    """Exact-host match: the Location must land on the canary host itself."""
    if not loc:
        return False
    loc = loc.strip()
    from urllib.parse import unquote
    loc = unquote(loc)
    low = loc.lower()
    if not low.startswith(("http://", "https://", "//")):
        return False
    try:
        h = urlsplit(low if not low.startswith("//") else "https:" + low).hostname
    except ValueError:
        return False
    want = urlsplit(canary).hostname.lower()
    return (h or "").lower() == want


def client_side_targets_canary(body, canary):
    """Look for a real redirect statement whose target contains the canary."""
    for m in REAL_REDIRECT.finditer(body):
        seg = body[m.start(): m.start() + 400]
        if canary.lower() in seg.lower() or canary.rstrip("/").lower() in seg.lower():
            return re.sub(r"\s+", " ", seg)[:300]
    return ""


def probe(url, canary, timeout=20):
    test = with_canary(url, canary)
    out = {"tested": test, "status": None, "location": None,
           "serverside": False, "clientside": "", "err": None}
    try:
        r = requests.get(test, allow_redirects=False, timeout=timeout,
                         verify=False, headers={"User-Agent": UA})
        out["status"] = r.status_code
        loc = r.headers.get("Location") or ""
        out["location"] = loc[:300]
        if r.status_code in (301, 302, 303, 307, 308) and host_is_canary(loc, canary):
            out["serverside"] = True
        elif r.status_code < 400 and r.text:
            out["clientside"] = client_side_targets_canary(r.text[:400000], canary)
    except Exception as e:  # noqa: BLE001
        out["err"] = f"{type(e).__name__}: {str(e)[:100]}"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file")
    ap.add_argument("--out", default=os.path.join(ROOT, "logs", "bb4",
                                                  "confirm", "verified.jsonl"))
    a = ap.parse_args()
    f = a.file
    if not f:
        files = [x for x in sorted(glob.glob(os.path.join(
            ROOT, "logs/bb4/confirm/confirm_*.jsonl"))) if "smoke" not in x]
        f = files[-1]
    rows = [json.loads(l) for l in open(f)]
    rows = [r for r in rows if r.get("hit")]
    print(f"[*] {len(rows)} first-pass hits from {f}", flush=True)

    out = []
    for r in rows:
        c1 = probe(r["endpoint"], CANARIES[0])
        time.sleep(0.25)
        c2 = probe(r["endpoint"], CANARIES[1])
        ss = c1["serverside"] and c2["serverside"]
        cs = bool(c1["clientside"]) and bool(c2["clientside"])
        v = dict(r, control1=c1, control2=c2,
                 serverside=ss, clientside=cs,
                 verdict=("open-redirect" if (ss or cs) else "false-positive"))
        out.append(v)
        print(f"{v['verdict']:15} {'SS' if ss else ('CS' if cs else '--')} "
              f"{r['platform']:10} {r['program'][:18]:18} "
              f"{r['endpoint'][:75]}", flush=True)

    with open(a.out, "w") as fh:
        for v in out:
            fh.write(json.dumps(v) + "\n")
    n = sum(1 for v in out if v["verdict"] == "open-redirect")
    ss = sum(1 for v in out if v["serverside"])
    cs = sum(1 for v in out if v["clientside"])
    print(f"\n[+] {n}/{len(out)} real open redirects (server-side {ss}, "
          f"client-side {cs})")


if __name__ == "__main__":
    main()

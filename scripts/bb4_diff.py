#!/usr/bin/env python3
"""bb4_diff.py -- differential test: does the endpoint actually HONOR the
redirect parameter?

For every candidate we already probed with the canary (confirm_*.jsonl) we send
the ORIGINAL url (archived param value) and compare:
  * baseline Location/status  vs  canary Location/status

Classification:
  open-redirect   canary run lands on the canary host (exact match)
  honored         response changes because of our value, but it lands somewhere
                  else (internal path, allowlisted host) -> the parameter is
                  consumed; the bypass work (subdomain, @, backslash, %2f%2f,
                  path traversal) belongs here
  ignored         identical status+Location with original and canary value ->
                  the parameter does not drive the redirect at all
  unknown         both 200 / both error, no redirect seen without a session

Writes logs/bb4/confirm/diff.jsonl
"""
import argparse
import glob
import json
import os
import time
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings()

ROOT = "/opt/watch"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126.0 Safari/537.36")


def norm(loc, base):
    """Reduce a Location to something comparable across runs."""
    if not loc:
        return ""
    loc = loc.strip()
    sp = urlsplit(loc)
    if sp.scheme and sp.netloc:
        return f"{sp.netloc.lower()}{sp.path}"
    return urlsplit(base)._replace(query="", fragment="").geturl().split("//")[-1] \
        .split("/")[0] + (sp.path or "")


def probe(url, timeout=15):
    out = {"status": None, "location": "", "err": None}
    try:
        r = requests.get(url, allow_redirects=False, timeout=timeout,
                         verify=False, headers={"User-Agent": UA})
        out["status"] = r.status_code
        out["location"] = (r.headers.get("Location") or "")[:300]
    except Exception as e:  # noqa: BLE001
        out["err"] = f"{type(e).__name__}: {str(e)[:90]}"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file")
    ap.add_argument("--out", default=os.path.join(ROOT, "logs", "bb4", "confirm",
                                                  "diff.jsonl"))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=15)
    a = ap.parse_args()

    f = a.file
    if not f:
        files = [x for x in sorted(glob.glob(os.path.join(
            ROOT, "logs/bb4/confirm/confirm_*.jsonl"))) if "smoke" not in x]
        f = files[-1]
    rows = [json.loads(l) for l in open(f)]
    print(f"[*] {len(rows)} candidates from {f}", flush=True)

    import concurrent.futures as cf
    out = []
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = {ex.submit(probe, r["endpoint"], a.timeout): r for r in rows}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            r = futs[fut]
            base = fut.result()
            can = {"status": r["status"], "location": r["location"] or ""}
            if r.get("error"):
                can["err"] = r["error"]
            b_stat, c_stat = base["status"], can["status"]
            b_loc, c_loc = base["location"], can["location"]
            canary_host = "google.com"
            is_canary = False
            if c_loc:
                try:
                    h = urlsplit(c_loc if c_loc.startswith(("http", "//"))
                                 else "https://" + c_loc.lstrip("/")).hostname or ""
                    is_canary = h.lower() == canary_host
                except ValueError:
                    is_canary = False
            redir = (301, 302, 303, 307, 308)
            if is_canary and c_stat in redir:
                verdict = "open-redirect"
            elif base["err"] and can.get("err"):
                verdict = "unknown"
            elif b_stat in redir and c_stat in redir and \
                    norm(b_loc, r["endpoint"]) != norm(c_loc, r["endpoint"]):
                verdict = "honored"
            elif b_stat in redir and c_stat in redir:
                verdict = "ignored"
            elif (b_stat in redir) != (c_stat in redir):
                verdict = "honored"
            else:
                verdict = "unknown"
            rec = {"platform": r["platform"], "program": r["program"],
                   "program_url": r.get("program_url"), "endpoint": r["endpoint"],
                   "params": r.get("params"),
                   "baseline": base, "canary": can,
                   "verdict": verdict}
            out.append(rec)
            if verdict == "honored":
                print(f"[honored] {r['program'][:20]:20} "
                      f"{b_stat}->{b_loc[:50]!r} / {c_stat}->{c_loc[:50]!r}",
                      flush=True)
            elif i % 200 == 0:
                print(f"[{i}/{len(rows)}]", flush=True)

    with open(a.out, "w") as fh:
        for rec in out:
            fh.write(json.dumps(rec) + "\n")
    import collections
    c = collections.Counter(x["verdict"] for x in out)
    print(f"\n[+] {dict(c)} -> {a.out}")


if __name__ == "__main__":
    main()

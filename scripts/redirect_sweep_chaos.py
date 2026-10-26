#!/usr/bin/env python3
"""redirect_sweep_chaos.py -- sweep every bounty:true program in
projectdiscovery/public-bugbounty-programs for auth-flow endpoints that carry a
redirect-style parameter. Passive by default (OSINT archives only: gau +
waybackurls), so it sends no traffic to the targets themselves.

For each root domain it harvests historical URLs, keeps the ones on an auth-flow
path whose query holds a redirect-style parameter (names from
wordlists/redirect-params.txt), and writes a de-duplicated report.

Output (timestamped under --out dir, default /opt/watch/logs/redirect-sweep):
  report.txt    human-readable  "<endpoint>  <=  <param(s)>"
  report.jsonl  one json object per endpoint {domain, url, params}

Usage:
  ./.venv/bin/python scripts/redirect_sweep_chaos.py                 # all bounty:true roots
  ./.venv/bin/python scripts/redirect_sweep_chaos.py --limit 50      # first 50 roots (smoke test)
  ./.venv/bin/python scripts/redirect_sweep_chaos.py --match foo     # only roots containing "foo"
  ./.venv/bin/python scripts/redirect_sweep_chaos.py --active        # also run katana (SENDS traffic)

Scope note: this is reconnaissance over public archive data. Any CONFIRMATION of
an open redirect / OAuth hijack against a live host must respect each program's
own scope and rules -- confirm per-program before testing. Pairs with the
hunt-redirect-params skill.
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORDLIST = os.path.join(ROOT, "wordlists", "redirect-params.txt")
CHAOS_URL = ("https://raw.githubusercontent.com/projectdiscovery/"
             "public-bugbounty-programs/main/dist/data.json")

# Word-boundary anchored so a keyword does not match inside an unrelated slug
# (e.g. "auth" inside "authority", "return" inside "returned").
AUTH_PATH = re.compile(
    r"\b(login|log-?in|signin|sign-?in|logon|auth|authorize|authentication|"
    r"oauth|oauth2|openid|connect|sso|saml|cas|idp|adfs|wsfed|session|"
    r"register|signup|sign-?up|join|logout|log-?out|signout|sign-?out|"
    r"password|passwd|pwd|reset|forgot|recover|recovery|verify|confirm|"
    r"activate|callback|return|continue|redirect|relaystate|acs)\b",
    re.I,
)


def redirect_names():
    with open(WORDLIST) as fh:
        return {ln.strip().lower() for ln in fh if ln.strip()}


def bounty_domains(match=None):
    data = json.loads(urllib.request.urlopen(CHAOS_URL, timeout=60).read())
    roots = []
    for p in data.get("programs", []):
        if not p.get("bounty"):
            continue
        for d in p.get("domains", []):
            d = d.strip().lstrip("*.").lower()
            if d and (not match or match in d):
                roots.append(d)
    return sorted(set(roots))


def harvest(domain, active=False, timeout=120, limit=20000):
    """Collect URLs for a domain. Primary source is the Wayback CDX API queried
    directly (reliable here; gau/waybackurls egress is unreliable on this box).
    Subdomains are included via matchType=domain. Optionally also runs katana."""
    urls = set()
    cdx = ("http://web.archive.org/cdx/search/cdx?"
           f"url={domain}&matchType=domain&output=text&fl=original"
           f"&collapse=urlkey&limit={limit}")
    try:
        req = urllib.request.Request(cdx, headers={"User-Agent": "watch-recon"})
        data = urllib.request.urlopen(req, timeout=timeout).read().decode(errors="ignore")
        urls.update(ln.strip() for ln in data.splitlines() if ln.strip())
    except Exception:
        pass
    # best-effort secondary (harmless if the tools return nothing)
    for cmd in (["gau", "--subs", domain], ["waybackurls", domain]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, input=domain)
            urls.update(r.stdout.splitlines())
        except Exception:
            pass
    if active:
        try:
            k = subprocess.run(["katana", "-u", f"https://{domain}", "-d", "2",
                               "-silent"], capture_output=True, text=True, timeout=timeout)
            urls.update(k.stdout.splitlines())
        except Exception:
            pass
    return urls


def mine(domain, urls, names):
    hits, seen = [], set()
    for u in urls:
        if "?" not in u:
            continue
        sp = urlsplit(u)
        if not AUTH_PATH.search((sp.path or "").lower()):
            continue
        params = [kv.split("=", 1)[0] for kv in sp.query.split("&") if kv]
        matched = sorted({p for p in params if p.lower() in names})
        if not matched:
            continue
        key = (sp.netloc + sp.path, tuple(matched))
        if key in seen:
            continue
        seen.add(key)
        hits.append({"domain": domain, "url": u, "params": matched})
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="only the first N roots")
    ap.add_argument("--match", help="only roots whose name contains this substring")
    ap.add_argument("--active", action="store_true", help="also run katana (sends traffic)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default=os.path.join(ROOT, "logs", "redirect-sweep"))
    args = ap.parse_args()

    names = redirect_names()
    roots = bounty_domains(args.match)
    if args.limit:
        roots = roots[:args.limit]
    print(f"[*] {len(roots)} bounty:true root domains to sweep "
          f"({'passive+active' if args.active else 'passive'})", file=sys.stderr)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(args.out, stamp)
    os.makedirs(outdir, exist_ok=True)
    txt_path = os.path.join(outdir, "report.txt")
    jsonl_path = os.path.join(outdir, "report.jsonl")

    total = 0
    with open(txt_path, "w") as txt, open(jsonl_path, "w") as jl, \
            cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(harvest, d, args.active): d for d in roots}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            d = futs[fut]
            try:
                hits = mine(d, fut.result(), names)
            except Exception as e:
                print(f"[!] {d}: {e}", file=sys.stderr)
                continue
            for h in hits:
                txt.write(f"{h['url']}  <=  {', '.join(h['params'])}\n")
                jl.write(json.dumps(h) + "\n")
            txt.flush(); jl.flush()
            total += len(hits)
            if hits:
                print(f"[{i}/{len(roots)}] {d}: {len(hits)} endpoint(s)", file=sys.stderr)

    print(f"\n[+] {total} auth-flow redirect-param endpoints across {len(roots)} roots",
          file=sys.stderr)
    print(f"[+] report: {txt_path}", file=sys.stderr)
    print(txt_path)  # stdout = path, so Hermes can read/attach it


if __name__ == "__main__":
    main()

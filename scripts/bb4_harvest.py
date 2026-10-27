#!/usr/bin/env python3
"""bb4_harvest.py -- passive harvest of auth-flow URLs carrying redirect-style
parameters, for bounty:true programs on HackerOne / Bugcrowd / YesWeHack /
Intigriti (seed: projectdiscovery/public-bugbounty-programs dist/data.json,
filtered by _bb4_extract.py).

No traffic is sent to the targets: every source is a public archive/index.

Sources:
  1. Wayback CDX  -- .*[?].* filter, NO collapse=urlkey (collapse is what makes
     the archive 502/504 on big roots); a retry ladder lowers `limit` when a
     root times out.
  2. urlscan.io   -- page URLs only (the /result/ endpoint needs an API key).
  3. AlienVault OTX -- url_list; the free tier is 100 req/hour, so the source
     self-disables on 429 for 10 minutes and is retried on a later pass.
  4. arquivo.pt   -- Portuguese web archive, thin but cheap.

Outputs:
  logs/bb4/hits/hits_<ts>_<tag>.jsonl   one row per (host+path, param set)
  logs/bb4/status.jsonl                 per-root coverage (resume marker)
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlsplit

ROOT = "/opt/watch"
WORDLIST = os.path.join(ROOT, "wordlists", "redirect-params.txt")
OUTDIR = os.path.join(ROOT, "logs", "bb4")
HITDIR = os.path.join(OUTDIR, "hits")
STATUS = os.path.join(OUTDIR, "status.jsonl")
UA = "Mozilla/5.0 (compatible; watch-recon/1.0)"

AUTH_PATH = re.compile(
    r"\b(login|log-?in|signin|sign-?in|signon|logon|authenticate|authentication|"
    r"auth|authorize|authorization|oauth|oauth2|openid|connect|sso|saml|cas|idp|"
    r"adfs|wsfed|session|account|register|signup|sign-?up|join|enroll|logout|"
    r"log-?out|signout|sign-?out|password|passwd|pwd|reset|forgot|recover|"
    r"recovery|verify|verification|confirm|activation|activate|callback|return|"
    r"continue|redirect|relaystate|acs|error|denied|mfa|2fa|otp|checkout|"
    r"onboarding|invite|accept|link)\b", re.I)

_ssl = ssl.create_default_context()
_ssl.check_hostname = False
_ssl.verify_mode = ssl.CERT_NONE

stats = {"ok": 0, "err": 0, "limit": 0}
_wb_sem = threading.Semaphore(4)          # wayback dislikes >4 parallel queries
_lock = threading.Lock()
_otx_block = [0.0]                        # epoch until which OTX is skipped


def load_names():
    with open(WORDLIST) as fh:
        return {ln.strip().lower() for ln in fh if ln.strip()}


def http_get(url, timeout=60, retries=0, headers=None, sleep=1.0):
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_ssl) as r:
                stats["ok"] += 1
                return r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            stats["err"] += 1
            if e.code in (400, 404):
                return ""
            if e.code in (429, 502, 503, 504):
                stats["limit"] += 1
            if attempt < retries:
                time.sleep(sleep)
                continue
            return None
        except Exception:  # noqa: BLE001
            stats["err"] += 1
            if attempt < retries:
                time.sleep(sleep * (attempt + 1))
                continue
            return None
    return None


# ---------------------------------------------------------------- sources
def src_wayback(domain, ladder=((20000, 150), (8000, 120), (3000, 90))):
    for limit, timeout in ladder:
        p = urllib.parse.urlencode({
            "url": domain, "matchType": "domain", "output": "text",
            "fl": "original", "limit": limit, "filter": "original:.*[?].*",
        })
        with _wb_sem:
            body = http_get(f"https://web.archive.org/cdx/search/cdx?{p}",
                            timeout=timeout)
        if body and "<html" not in body[:200].lower():
            return {ln.strip() for ln in body.splitlines() if ln.strip()}
    return set()


def src_urlscan(domain, maxpages=2, timeout=40):
    urls, after = set(), None
    for _ in range(maxpages):
        u = ("https://urlscan.io/api/v1/search/?q="
             f"domain%3A{urllib.parse.quote(domain)}&size=100")
        if after:
            u += f"&search_after={after}"
        body = http_get(u, timeout=timeout, retries=1)
        if not body:
            break
        try:
            d = json.loads(body)
        except Exception:
            break
        res = d.get("results") or []
        for r in res:
            p = (r.get("page") or {}).get("url")
            if p:
                urls.add(p)
        if len(res) < 100 or not res[-1].get("_id"):
            break
        after = res[-1]["_id"]
        time.sleep(0.8)
    return urls


def src_otx(domain, pages=2, timeout=25):
    with _lock:
        if _otx_block[0] and time.time() < _otx_block[0]:
            return set()
    urls = set()
    for page in range(1, pages + 1):
        u = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
             f"{urllib.parse.quote(domain)}/url_list?limit=500&page={page}")
        body = http_get(u, timeout=timeout)
        if body is None:
            with _lock:
                _otx_block[0] = time.time() + 600
            break
        if not body:
            break
        try:
            d = json.loads(body)
        except Exception:
            break
        batch = d.get("url_list") or []
        urls.update(x.get("url", "") for x in batch if x.get("url"))
        if not d.get("has_next") or len(batch) < 500:
            break
        time.sleep(0.5)
    return urls


def src_arquivo(domain, limit=2000, timeout=60):
    p = urllib.parse.urlencode({
        "url": domain, "matchType": "domain", "output": "json",
        "limit": limit, "filter": "url:.*%5C%3F.*",
    })
    body = http_get(f"https://arquivo.pt/wayback/cdx?{p}", timeout=timeout)
    if not body:
        return set()
    urls = set()
    for ln in body.splitlines():
        try:
            d = json.loads(ln)
        except Exception:
            continue
        u = d.get("url")
        if u:
            urls.add(u)
    return urls


def harvest(domain, sources):
    urls = set()
    if "wayback" in sources:
        urls |= src_wayback(domain)
    if "urlscan" in sources:
        urls |= src_urlscan(domain)
    if "otx" in sources and len(urls) < 300:
        urls |= src_otx(domain)
    if "arquivo" in sources and len(urls) < 200:
        urls |= src_arquivo(domain)
    return urls


# ---------------------------------------------------------------- mining
def mine(domain, urls, names, any_path=False, max_hits=600):
    hits, seen = [], set()
    for u in urls:
        if not u or "?" not in u or "=" not in u or len(u) > 2000:
            continue
        try:
            sp = urlsplit(u.strip())
            host = (sp.hostname or "").lower()
        except ValueError:
            continue
        if not host or not (host == domain or host.endswith("." + domain)):
            continue
        if not any_path and not AUTH_PATH.search(sp.path or ""):
            continue
        params = {}
        for kv in sp.query.split("&"):
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if k.lower() in names:
                params.setdefault(k, v)
        if not params:
            continue
        key = (sp.netloc.lower() + (sp.path or "").lower(),
               tuple(sorted(params)))
        if key in seen:
            continue
        seen.add(key)
        hits.append({"domain": domain, "url": u.strip(),
                     "params": {k: v[:300] for k, v in params.items()}})
        if len(hits) >= max_hits:
            break
    return hits


# ---------------------------------------------------------------- driver
def load_done():
    done, failed = set(), set()
    if os.path.exists(STATUS):
        with open(STATUS) as fh:
            for ln in fh:
                try:
                    d = json.loads(ln)
                except Exception:
                    continue
                (done if d.get("ok") else failed).add(d["domain"])
    return done - failed, failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--programs", default=os.path.join(ROOT, "logs",
                                                       "bb4_programs.json"))
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--platform", action="append", default=None)
    ap.add_argument("--sources", default="wayback,urlscan,otx,arquivo")
    ap.add_argument("--any-path", action="store_true")
    ap.add_argument("--failed-only", action="store_true",
                    help="only roots that yielded 0 URLs last time")
    ap.add_argument("--tag", default="")
    args = ap.parse_args()

    os.makedirs(HITDIR, exist_ok=True)
    names = load_names()
    progs = json.load(open(args.programs))
    if args.platform:
        progs = [p for p in progs if p["platform"] in args.platform]

    dmap = {}
    for p in progs:
        for d in p["domains"]:
            dmap.setdefault(d, []).append((p["platform"], p["program"]))

    done, failed = load_done()
    todo = sorted(failed - done) if args.failed_only else sorted(set(dmap) - done)
    if args.limit:
        todo = todo[:args.limit]

    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    print(f"[*] {len(dmap)} roots | done={len(done)} failed={len(failed)} "
          f"todo={len(todo)} sources={sorted(sources)}", flush=True)

    stamp = time.strftime("%Y%m%d_%H%M%S")
    tag = f"_{args.tag}" if args.tag else ""
    hitfile = os.path.join(HITDIR, f"hits_{stamp}{tag}.jsonl")
    total = 0

    with open(hitfile, "w") as hf, open(STATUS, "a") as sf:
        def work(d):
            try:
                urls = harvest(d, sources)
            except Exception as e:  # noqa: BLE001
                return d, [], str(e), 0
            return d, mine(d, urls, names, any_path=args.any_path), None, len(urls)

        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(work, d): d for d in todo}
            for i, fut in enumerate(cf.as_completed(futs), 1):
                d = futs[fut]
                try:
                    d2, hits, err, nurl = fut.result()
                except Exception as e:  # noqa: BLE001
                    d2, hits, err, nurl = d, [], str(e), 0
                with _lock:
                    for h in hits:
                        h["programs"] = dmap.get(d2, [])
                        hf.write(json.dumps(h) + "\n")
                    hf.flush()
                    # a root that yielded 0 URLs is a source failure -> retry later
                    sf.write(json.dumps({"ts": round(time.time()), "domain": d2,
                                         "ok": err is None and nurl > 0,
                                         "urls": nurl, "hits": len(hits),
                                         "err": err}) + "\n")
                    sf.flush()
                    total += len(hits)
                if hits:
                    print(f"[{i}/{len(todo)}] {d2}: {len(hits)} hits "
                          f"({nurl} urls)", flush=True)
                elif i % 40 == 0:
                    print(f"[{i}/{len(todo)}] ... {total} hits, stats={stats}",
                          flush=True)

    print(f"\n[+] {total} hits -> {hitfile}", flush=True)


if __name__ == "__main__":
    main()

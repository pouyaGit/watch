#!/usr/bin/env python3
"""ind_domxss.py -- source->sink scan over Indeed's own JS, deduped by content.

21,515 crawl-discovered JS URLs are mostly the same chunk mirrored across ~60
country domains, so fetching all of them would be wasted work. Identical
basenames + identical size are treated as one artifact; the scan then runs once
per distinct artifact and the result is mapped back to every host carrying it.
"""
import hashlib
import json
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, "/opt/watch/scripts")

import requests  # noqa: E402
import urllib3  # noqa: E402

urllib3.disable_warnings()
from digi_domxss import slice_file  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
MAX_BYTES = 2_500_000
SKIP = re.compile(r"(cdn-cgi/|challenge-platform|/gtm\.js|googletagmanager|"
                  r"google-analytics|doubleclick|hotjar|segment\.|sentry|"
                  r"newrelic|optimizely|qualtrics|fonts\.|\.map$)", re.I)


def fetch(u):
    try:
        r = requests.get(u, timeout=20, verify=False, headers=UA,
                         allow_redirects=True)
        if r.status_code != 200:
            return None
        if len(r.content or b"") > MAX_BYTES:
            return ("SKIP", u, len(r.content))
        return (u, hashlib.sha256(r.content).hexdigest(), (r.text or ""),
                len(r.content))
    except Exception:
        return None


def main():
    files = json.load(open("/opt/watch/logs/indeed/js_files.json"))
    cand = [u for u in files if not SKIP.search(u)]
    # one representative per (basename) to cut cross-country mirrors
    by_base = defaultdict(list)
    for u in cand:
        by_base[u.rsplit("/", 1)[-1]].append(u)
    reps = [v[0] for v in by_base.values()]
    print(f"[*] {len(files)} JS urls -> {len(cand)} plausible -> "
          f"{len(reps)} distinct basenames", flush=True)

    results, seen_sha = [], set()
    skipped = 0
    done = 0
    with ThreadPoolExecutor(max_workers=25) as ex:
        for res in ex.map(fetch, reps):
            done += 1
            if not res:
                continue
            if res[0] == "SKIP":
                skipped += 1
                print(f"  [skip {res[2]:,}B] {res[1][:80]}", flush=True)
                continue
            u, sha, code, size = res
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
            for f in slice_file(code, u):
                results.append(f)
            if done % 500 == 0:
                print(f"  [{done}/{len(reps)}] unique={len(seen_sha)} "
                      f"flows={len(results)}", flush=True)

    json.dump(results, open("/opt/watch/logs/indeed/dom_flows.json", "w"), indent=1)
    print(f"\n[+] {len(results)} flows over {len(seen_sha)} unique artifacts "
          f"({skipped} skipped for size)")


if __name__ == "__main__":
    main()

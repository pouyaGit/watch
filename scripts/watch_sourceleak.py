#!/usr/bin/env python3
"""watch_sourceleak.py -- exposed VCS/env/config file sweep per hunt-source-leak.

Every candidate must satisfy a *format* assertion, not just "200 and the word
appears" -- a soft-404 or an SPA catch-all answers 200 to everything:
  /.env        -> >=2 lines of KEY=VALUE, and at least one secret-shaped key
  /.git/config -> [core] + repositoryformatversion
  /.git/HEAD   -> "ref: refs/heads/" or a 40-hex sha, body < 120 bytes
  /.svn/entries-> "dir" + a bare integer line
  /server-status-> "Apache Server Status"
  /phpinfo.php -> "PHP Version" + "php.ini"
A random control path is fetched per host; if it returns 200 with a similar
length, every assertion for that host is discarded (catch-all server).
"""
import hashlib
import json
import random
import re
import string
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch")
from database.db import Http  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
T = 10
SECRET_KEY = re.compile(
    r"(?im)^\s*[A-Z0-9_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE|"
    r"ACCESS_KEY|CLIENT_SECRET|DB_PASS|MYSQL|REDIS|AWS|SMTP|MAIL)[A-Z0-9_]*\s*=")
KV = re.compile(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]{1,60}\s*=\s*\S")


def rand_path():
    return "/" + "".join(random.choices(string.ascii_lowercase, k=14)) + "-zq"


def validate(path, body):
    b = body or ""
    if path == "/.env":
        return len(KV.findall(b)) >= 2 and bool(SECRET_KEY.search(b))
    if path == "/.git/config":
        return "[core]" in b and "repositoryformatversion" in b
    if path == "/.git/HEAD":
        return len(b) < 120 and (b.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}\s*", b))
    if path == "/.svn/entries":
        return "dir" in b and re.search(r"(?m)^\d+\s*$", b) is not None
    if path == "/server-status":
        return "Apache Server Status" in b
    if path == "/phpinfo.php":
        return "PHP Version" in b and "php.ini" in b
    return False


PATHS = ["/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
         "/server-status", "/phpinfo.php"]


def probe(host):
    base = host.rstrip("/")
    out = []
    ctl_path = rand_path()
    try:
        c = requests.get(base + ctl_path, timeout=T, verify=False, headers=UA,
                         allow_redirects=False)
        ctl_len, ctl_status = len(c.content or b""), c.status_code
    except Exception:
        return host, [], "unreachable"
    for p in PATHS:
        try:
            r = requests.get(base + p, timeout=T, verify=False, headers=UA,
                             allow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        body = r.text or ""
        ln = len(r.content or b"")
        # catch-all / soft-404 guard
        if ctl_status == 200 and abs(ln - ctl_len) < 30 and ln > 0:
            continue
        if not validate(p, body):
            continue
        out.append({
            "host": host, "path": p, "status": r.status_code, "len": ln,
            "ctl_status": ctl_status, "ctl_len": ctl_len,
            "sha": hashlib.sha256(r.content).hexdigest()[:16],
            "secret_keys": SECRET_KEY.findall(body)[:8],
            "preview": "\n".join(body.splitlines()[:12])[:600],
        })
        print(f"[HIT] {host}{p} len={ln} ctl={ctl_status}/{ctl_len}", flush=True)
    return host, out, "ok"


def main():
    hosts = sorted({h.url.rstrip("/") for h in Http.objects.only("url") if h.url})
    print(f"[*] source-leak sweep: {len(hosts)} hosts x {len(PATHS)} paths", flush=True)
    hits, unreachable = [], 0
    with ThreadPoolExecutor(max_workers=30) as ex:
        for i, (host, found, st) in enumerate(ex.map(probe, hosts), 1):
            if st == "unreachable":
                unreachable += 1
            hits.extend(found)
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] hits={len(hits)} unreachable={unreachable}",
                      flush=True)

    json.dump(hits, open("/opt/watch/logs/bb4/sourceleak.json", "w"), indent=1)
    print(f"\n[+] {len(hits)} validated hits, {unreachable} unreachable")
    for h in hits:
        print(f"    {h['host']}{h['path']}  keys={h['secret_keys']}")


if __name__ == "__main__":
    main()

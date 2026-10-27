#!/usr/bin/env python3
"""watch_legacy_probe.py -- Legacy-Protocol Matrix probe (hunt-auth-bypass).

Two false-positive traps this avoids, both hit for real on this corpus:
  1. A WAF that 403s every path makes every surface "match".
  2. Soft-404s echo the requested path, so a 1-2 byte body-length delta
     "differs" from the control and every host looks vulnerable.
So status+length is NOT used as the discriminator. A hit requires the response
to carry the SERVICE'S OWN protocol marker (X-Powered-By/Set-Cookie/jsonapi
structure/actuator JSON/XMLRPC methodResponse/FormDigest), and the control must
not carry it.

Read-only: GET only. No POST, no credentials, no brute force.
"""
import json
import random
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
TIMEOUT = 10

PATHS = {
    "wp-login": "/wp-login.php",
    "wp-rest-users": "/wp-json/wp/v2/users",
    "xmlrpc": "/xmlrpc.php",
    "drupal-jsonapi": "/jsonapi/",
    "jira-serverinfo": "/rest/api/2/serverInfo",
    "actuator-health": "/actuator/health",
    "actuator-env": "/actuator/env",
    "sp-contextinfo": "/_api/contextinfo",
}


def sig(r):
    """Protocol-level fingerprint, ignoring status/length and path echo.

    The control branch matters: many servers answer 404/301 with a body that
    contains the requested path ("No static resource xmlrpc.php",
    "Moved Permanently ... /xmlrpc.php"), so a naive substring search fires on
    the echo. When the response is a 3xx/4xx/5xx we require a POSITIVE service
    marker (header, cookie, JSON schema) instead of a body keyword.
    """
    h = {k.lower(): v for k, v in r.headers.items()}
    ct = (h.get("content-type") or "").lower()
    body = (r.text or "")[:40000].lower()
    cookie = h.get("set-cookie", "").lower()
    powered = h.get("x-powered-by", "").lower()
    is_ok = 200 <= r.status_code < 300
    marks = set()
    if "wordpress" in cookie or "wp-settings" in cookie or "wordpress" in powered:
        marks.add("wordpress-cookie")
    if '"jsonapi"' in body and "json" in ct:
        marks.add("drupal-jsonapi")
    if is_ok and ("xmlrpc" in body or "methodresponse" in body):
        marks.add("xmlrpc")
    if is_ok and '"slug"' in body and '"name"' in body and "json" in ct:
        marks.add("wp-rest-users")
    if is_ok and "json" in ct and ('"basename"' in body or '"servertitle"' in body
                                   or '"deploymenttype"' in body):
        marks.add("jira-serverinfo")
    if is_ok and "json" in ct and ('"status":"up"' in body.replace(" ", "")
                                   or '"components"' in body):
        marks.add("actuator")
    if is_ok and ("soap" in body or "formdigest" in body):
        marks.add("sharepoint")
    return marks


def probe(host):
    base = host.rstrip("/")
    rnd = "zq" + "".join(random.choice(string.ascii_lowercase + string.digits)
                         for _ in range(8))
    try:
        ctl = requests.get(f"{base}/{rnd}", timeout=TIMEOUT, verify=False,
                           headers=UA, allow_redirects=False)
        ctl_marks = sig(ctl)
    except Exception:
        return host, [], {"waf": False, "control": None}
    ctl_status = ctl.status_code
    waf = ctl_status in (403, 429, 503)
    hits = []
    if not waf:
        for name, path in PATHS.items():
            try:
                r = requests.get(base + path, timeout=TIMEOUT, verify=False,
                                 headers=UA, allow_redirects=False)
            except Exception:
                continue
            new = sig(r) - ctl_marks
            if not new:
                continue
            hits.append({"name": name, "url": base + path,
                         "status": r.status_code,
                         "markers": sorted(new),
                         "control": f"{ctl_status}",
                         "content_type": (r.headers.get("content-type") or "")[:50]})
    return host, hits, {"waf": waf, "control": ctl_status}


def main():
    hosts = sorted({h.url.rstrip("/") for h in Http.objects.only("url") if h.url})
    print(f"[*] {len(hosts)} live hosts, marker-gated legacy probe", flush=True)
    findings, waf_hosts = [], 0
    with ThreadPoolExecutor(max_workers=20) as ex:
        for i, (host, hits, ctl) in enumerate(ex.map(probe, hosts), 1):
            if ctl.get("waf"):
                waf_hosts += 1
            for h in hits:
                findings.append({"host": host, **h})
                print(f"[hit] {h['name']:16} {h['status']} "
                      f"{','.join(h['markers'])} {h['url'][:85]}", flush=True)
            if i % 300 == 0:
                print(f"  [{i}/{len(hosts)}] hits={len(findings)} "
                      f"waf={waf_hosts}", flush=True)

    json.dump(findings, open("/opt/watch/logs/bb4/legacy_probe.json", "w"),
              indent=1)
    import collections
    c = collections.Counter(f["name"] for f in findings)
    print(f"\n[+] {len(findings)} marker-confirmed hits; {waf_hosts} hosts "
          f"fully WAF-blocked (untested, not clean)")
    for k, v in c.most_common():
        print(f"    {v:5} {k}")


if __name__ == "__main__":
    main()

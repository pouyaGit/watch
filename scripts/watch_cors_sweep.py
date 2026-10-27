#!/usr/bin/env python3
"""watch_cors_sweep.py -- CORS misconfiguration sweep per hunt-cors.

Rules encoded here (each one killed a real false positive on this corpus):
  * GET, not HEAD; per-route, so API-shaped paths are probed not just /.
  * NEGATIVE CONTROL: request with no Origin. If ACAO is still present it is a
    static header, not a reflection.
  * Reflection universality: several unrelated origins + null + a subdomain
    pretend-origin.
  * A hit requires ACAO == our canary origin AND ACAC: true AND a non-empty
    body. ACAO:* with credentials is inert (browser refuses) - counted apart.
  * localhost/127.0.0.1 allowlist = dev leak, not remotely exploitable.
"""
import json
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
CANARY = "https://zq-cors-canary.example"
OTHER = ["https://zq-other.example", "null", "https://zq-cors-canary.example.evil.net"]
PATHS = ["/", "/api", "/api/", "/api/me", "/api/v1/", "/api/v1/me",
         "/api/user", "/api/session", "/api/account", "/api/graphql",
         "/graphql", "/api/v2/"]


def hdr(r):
    h = {k.lower(): v for k, v in r.headers.items()}
    return (h.get("access-control-allow-origin"),
            (h.get("access-control-allow-credentials") or "").lower())


def probe(host):
    base = host.rstrip("/")
    out = []
    # negative control: no Origin at all
    try:
        c = requests.get(base + "/", timeout=TIMEOUT, verify=False,
                         headers=UA, allow_redirects=False)
    except Exception:
        return host, [], "unreachable"
    ctl_acao, _ = hdr(c)
    for path in PATHS:
        try:
            r = requests.get(base + path, timeout=TIMEOUT, verify=False,
                             headers={**UA, "Origin": CANARY},
                             allow_redirects=False)
        except Exception:
            continue
        acao, acac = hdr(r)
        if not acao:
            continue
        reflected = acao.strip().lower() == CANARY.lower()
        if not reflected:
            continue
        # universality: do other origins also get echoed?
        others = {}
        for o in OTHER:
            try:
                r2 = requests.get(base + path, timeout=TIMEOUT, verify=False,
                                  headers={**UA, "Origin": o},
                                  allow_redirects=False)
                others[o] = hdr(r2)[0]
            except Exception:
                others[o] = None
        blen = len(r.content or b"")
        out.append({
            "host": host, "path": path, "status": r.status_code,
            "acao": acao, "acac": acac, "body_len": blen,
            "control_acao": ctl_acao,
            "other_origins": others,
            "universal": sum(1 for v in others.values()
                             if v and CANARY.lower() in v.lower()
                             or (v and v.strip().lower() in
                                 (o.strip().lower() for o in OTHER))),
            "exploitable": bool(acac == "true" and blen > 0),
        })
    return host, out, "ok"


def main():
    hosts = sorted({h.url.rstrip("/") for h in Http.objects.only("url") if h.url})
    print(f"[*] CORS sweep on {len(hosts)} hosts x {len(PATHS)} paths",
          flush=True)
    findings, unreachable = [], 0
    with ThreadPoolExecutor(max_workers=30) as ex:
        for i, (host, hits, st) in enumerate(ex.map(probe, hosts), 1):
            if st == "unreachable":
                unreachable += 1
            for h in hits:
                findings.append(h)
                flag = "EXPLOITABLE?" if h["exploitable"] else "reflect-no-creds/or-empty"
                print(f"[{flag}] {h['acao']} acac={h['acac']} len={h['body_len']} "
                      f"ctl={h['control_acao']} {h['host']}{h['path']}"[:150],
                      flush=True)
            if i % 400 == 0:
                print(f"  [{i}/{len(hosts)}] candidates={len(findings)} "
                      f"unreachable={unreachable}", flush=True)

    json.dump(findings, open("/opt/watch/logs/bb4/cors_sweep.json", "w"),
              indent=1)
    exp = [f for f in findings if f["exploitable"]]
    print(f"\n[+] {len(findings)} origin-reflecting responses, "
          f"{len(exp)} with ACAC:true and a non-empty body -> browser test")
    for f in exp:
        print(f"    {f['host']}{f['path']}  acao={f['acao']} len={f['body_len']}")


if __name__ == "__main__":
    main()

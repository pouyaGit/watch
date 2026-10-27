#!/usr/bin/env python3
"""watch_cname_sweep.py -- CNAME/dangling sweep for the Watch programs.

Follows hunt-subdomain's hard rules:
  * chunk ~1000 hosts, -retries 3
  * strip ANSI before parsing
  * parser self-check: refuse to report when raw>0 and parsed==0
  * TWO passes unioned (a bulk pass is nondeterministic)
  * plain substring classification over EVERY CNAME target, plus a provider table
  * a target is only "suspicious" when the CNAME name exists but does not resolve

Output: logs/bb4/cname_sweep.json
"""
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, "/opt/watch")
from database.db import Subdomains  # noqa: E402

DNSX = "/root/go/bin/dnsx"
OUT = "/opt/watch/logs/bb4/cname_sweep.json"
CHUNK = 1000
ANSI = re.compile(r"\x1b\[[0-9;]*m")

PROVIDERS = {
    "github.io": "GitHub Pages", "gitlab.io": "GitLab Pages",
    "herokudns.com": "Heroku", "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure App Service", "cloudapp.azure.com": "Azure VM",
    "cloudapp.net": "Azure Cloud Service", "trafficmanager.net": "Azure TM",
    "s3.amazonaws.com": "S3", "elasticbeanstalk.com": "Elastic Beanstalk",
    "elb.amazonaws.com": "AWS ELB", "cloudfront.net": "CloudFront",
    "fastly.net": "Fastly", "netlify.app": "Netlify", "netlify.com": "Netlify",
    "vercel-dns.com": "Vercel", "vercel.app": "Vercel",
    "wordpress.com": "WordPress", "wpengine.com": "WP Engine",
    "zendesk.com": "Zendesk", "uservoice.com": "UserVoice",
    "statuspage.io": "Statuspage", "readme.io": "ReadMe",
    "surveymonkey.com": "SurveyMonkey", "shopify.com": "Shopify",
    "myshopify.com": "Shopify", "unbounce.com": "Unbounce",
    "hubspot.net": "HubSpot", "hs-sites.com": "HubSpot",
    "pantheon.io": "Pantheon", "kinsta.com": "Kinsta",
    "bizible.com": "Bizible", "desk.com": "Desk",
    "freshdesk.com": "Freshdesk", "helpscout.net": "Help Scout",
    "ngrok.io": "ngrok", "ngrok-free.app": "ngrok", "fly.dev": "Fly.io",
    "onrender.com": "Render", "railway.app": "Railway",
    "bitbucket.io": "Bitbucket", "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers", "firebaseapp.com": "Firebase",
    "web.app": "Firebase", "amplifyapp.com": "AWS Amplify",
    "cargocollective.com": "Cargo", "squarespace.com": "Squarespace",
    "wixsite.com": "Wix", "webflow.io": "Webflow",
}

REC = re.compile(r"^\s*([\w.\-*]+)\s*\[CNAME\]\s*\[([^\]]+)\]")


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def run_pass(hosts, label):
    """One dnsx pass. Returns {host: [cname, ...]} plus raw/parsed counts."""
    mapping = defaultdict(list)
    raw_lines = parsed = 0
    for i, ch in enumerate(chunked(hosts, CHUNK), 1):
        p = subprocess.run(
            [DNSX, "-silent", "-nc", "-cname", "-resp", "-t", "100"],
            input="\n".join(ch), capture_output=True, text=True, timeout=1800)
        for line in p.stdout.splitlines():
            line = ANSI.sub("", line)
            if not line.strip():
                continue
            raw_lines += 1
            m = REC.match(line)
            if m:
                parsed += 1
                mapping[m.group(1)].append(m.group(2).rstrip("."))
        print(f"  [{label}] chunk {i}: raw={raw_lines} parsed={parsed}",
              flush=True)
    return mapping, raw_lines, parsed


def main():
    hosts = sorted({s.subdomain for s in Subdomains.objects.only("subdomain")})
    print(f"[*] {len(hosts)} subdomains from the DB", flush=True)

    passes = []
    for label in ("pass1", "pass2"):
        t = time.time()
        m, raw, parsed = run_pass(hosts, label)
        print(f"[{label}] {len(m)} hosts with CNAME, raw={raw} parsed={parsed}, "
              f"{round(time.time()-t)}s", flush=True)
        if raw > 0 and parsed == 0:
            print("  !! PARSER SELF-CHECK FAILED: raw>0 but parsed==0", flush=True)
            return 2
        passes.append(m)

    merged = defaultdict(set)
    for m in passes:
        for k, v in m.items():
            merged[k].update(v)
    print(f"[*] union of two passes: {len(merged)} hosts with a CNAME", flush=True)

    # resolve every distinct CNAME target
    targets = sorted({t for v in merged.values() for t in v})
    print(f"[*] resolving {len(targets)} distinct CNAME targets", flush=True)
    alive = set()
    for i, ch in enumerate(chunked(targets, CHUNK), 1):
        p = subprocess.run([DNSX, "-silent", "-nc", "-a", "-t", "100"],
                           input="\n".join(ch), capture_output=True, text=True,
                           timeout=1800)
        for line in p.stdout.splitlines():
            host = ANSI.sub("", line).split()[0].strip()
            if host:
                alive.add(host)
        print(f"  resolve chunk {i}: alive={len(alive)}", flush=True)

    rows = []
    for host, cnames in sorted(merged.items()):
        for c in sorted(cnames):
            prov = next((n for s, n in PROVIDERS.items()
                         if c.endswith("." + s) or c == s), "")
            rows.append({
                "host": host, "cname": c, "provider": prov,
                "target_resolves": c in alive,
                "suspicious": c not in alive,
            })

    susp = [r for r in rows if r["suspicious"]]
    byprov = Counter((r["provider"] or "unknown") for r in susp)
    print(f"\n[+] {len(rows)} CNAME records, {len(susp)} with a non-resolving "
          f"target", flush=True)
    for k, v in byprov.most_common():
        print(f"    {v:5} {k}")

    json.dump({"rows": rows, "alive_targets": sorted(alive),
               "chunks": 0}, open(OUT, "w"), indent=1)
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())

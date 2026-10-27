import json
from collections import Counter

d = json.load(open('/opt/watch/logs/bb4/cname_sweep.json'))
alive = json.load(open('/opt/watch/logs/bb4/cname_alive_correction.json'))
dead = {r['cname'] for r in d['rows'] if r['suspicious']} - set(alive)
rows = [r for r in d['rows'] if r['cname'] in dead]
hosts = sorted({r['host'] for r in rows})
print(f"{len(dead)} dead targets across {len(hosts)} subdomains\n")

SELF = {"herokudns.com", "herokuapp.com", "github.io", "gitlab.io",
        "azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
        "s3.amazonaws.com", "elasticbeanstalk.com", "netlify.app",
        "vercel-dns.com", "vercel.app", "zendesk.com", "uservoice.com",
        "statuspage.io", "readme.io", "surveymonkey.com", "myshopify.com",
        "hubspot.net", "pantheon.io", "freshdesk.com", "helpscout.net",
        "fly.dev", "onrender.com", "railway.app", "pages.dev", "web.app",
        "firebaseapp.com", "amplifyapp.com", "webflow.io", "surge.sh"}

self_serv = []
for r in rows:
    for s in SELF:
        if r['cname'].endswith('.' + s):
            self_serv.append((r['host'], r['cname'], s))
print("== self-service (claimable by an attacker) ==")
if self_serv:
    for h, c, s in self_serv:
        print(f"  {s:22} {h[:48]:48} -> {c}")
else:
    print("  NONE")

print("\n== all 87, grouped by class ==")
g = {}
for r in rows:
    key = '.'.join(r['cname'].split('.')[-3:])
    g.setdefault(key, []).append(r)
for key, rs in sorted(g.items(), key=lambda kv: -len(kv[1])):
    print(f"\n-- {key} ({len(rs)})")
    for r in rs[:6]:
        print(f"     {r['host'][:50]:50} -> {r['cname'][:62]}")
    if len(rs) > 6:
        print(f"     ... +{len(rs)-6} more")

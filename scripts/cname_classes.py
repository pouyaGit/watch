"""Per-subnamespace control + full provider suffix sweep.

For every CNAME suffix class in the corpus, ask: does ANY name in this class
resolve? A class where nothing resolves is a vendor-blackhole namespace (not
evidence). A class where some resolve but specific targets do not is a real
dangling candidate that must then be checked for claimability.
"""
import collections
import json
import subprocess

d = json.load(open('/opt/watch/logs/bb4/cname_sweep.json'))
rows = d['rows']
susp = [r for r in rows if r['suspicious']]

# 3-label suffix to separate k8s.indeed.tech from us-east-2.indeed.tech
def suffix3(t):
    p = t.split('.')
    return '.'.join(p[-3:]) if len(p) >= 3 else t

cls = collections.defaultdict(lambda: {"total": set(), "alive": set()})
for r in rows:
    s = suffix3(r['cname'])
    cls[s]["total"].add(r['cname'])
    if r['target_resolves']:
        cls[s]["alive"].add(r['cname'])

print("== suffix classes with 20+ targets, sorted by non-resolving count")
print(f"{'suffix':45} {'targets':>8} {'alive':>6} {'dead':>6}  verdict")
verdicts = {}
for s, v in sorted(cls.items(), key=lambda kv: -(len(kv[1]["total"]) - len(kv[1]["alive"]))):
    t, a = len(v["total"]), len(v["alive"])
    if t < 20:
        continue
    if a == 0:
        verdict = "BLACKHOLE - no name in class resolves (not evidence)"
    elif a == t:
        verdict = "all resolve"
    else:
        verdict = f"MIXED - {t-a} dead of {t} (real candidates)"
    verdicts[s] = verdict
    print(f"{s:45} {t:8} {a:6} {t-a:6}  {verdict}")

print("\n== self-service takeover providers (the only classes an attacker can claim)")
SELF = {
    "herokudns.com", "herokuapp.com", "github.io", "gitlab.io", "bitbucket.io",
    "azurewebsites.net", "cloudapp.azure.com", "cloudapp.net", "s3.amazonaws.com",
    "elasticbeanstalk.com", "netlify.app", "netlify.com", "vercel-dns.com",
    "vercel.app", "wordpress.com", "zendesk.com", "uservoice.com",
    "statuspage.io", "readme.io", "surveymonkey.com", "shopify.com",
    "myshopify.com", "unbounce.com", "hubspot.net", "hs-sites.com",
    "pantheon.io", "kinsta.com", "freshdesk.com", "helpscout.net",
    "ngrok.io", "ngrok-free.app", "fly.dev", "onrender.com", "railway.app",
    "pages.dev", "workers.dev", "firebaseapp.com", "web.app",
    "amplifyapp.com", "squarespace.com", "wixsite.com", "webflow.io",
    "surge.sh", "ghost.io", "teamwork.com", "aftership.com", "tumblr.com",
    "cargocollective.com", "bigcartel.com", "desk.com", "mashery.com",
}
found = collections.Counter()
for r in rows:
    for s in SELF:
        if r['cname'] == s or r['cname'].endswith('.' + s):
            found[(s, r['target_resolves'])] += 1
if not found:
    print("  NONE - no CNAME points at a self-service claimable provider")
for (s, alive), n in sorted(found.items(), key=lambda kv: -kv[1]):
    print(f"  {n:5} {s:28} target_resolves={alive}")

print("\n== the MIXED classes: dead targets listed for verification")
mixed = [s for s, v in verdicts.items() if v.startswith("MIXED")]
allmixed = {k for k, v in verdicts.items() if v.startswith("MIXED")}
cands = [r for r in susp if suffix3(r['cname']) in allmixed]
print(f"  {len(cands)} dead targets inside a namespace that otherwise resolves")
for r in cands[:40]:
    print(f"    {r['host'][:55]:55} -> {r['cname'][:70]}")

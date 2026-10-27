"""Follow the whole redirect chain with the canary in the param and see where it
finally lands. A param that is reflected into a relative Location may open up
after 1-2 hops."""
import sys

import requests
import urllib3

urllib3.disable_warnings()
sys.path.insert(0, "/opt/watch/scripts")
import bb4_confirm as C  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"}
CANARY = "https://google.com"

URLS = [
    "https://secure.indeed.com/account/login?from=zdhcnav&continue=https%3A%2F%2Fads.indeed.com",
    "https://adh.indeed.com/user/login?next=/page/browse-metric/unique_visitors_per_month_us/",
    "https://feedbackcentral.dell.com/login.html?ref=%2Fcommunity%2Fagreements%2Fview.html%3Fnuid%3D&err=Session_Expired_Server_B&lr=0",
    "https://powercalculator.dell.com/Account/Login?ReturnUrl=%2f",
    "https://www.dell.com/di/v3/fp/oidc/authorize?redirect_uri=https://dsp-portal-preprod",
]

for u in URLS:
    test = C.with_canary(u, CANARY)
    print("=" * 100)
    print(test[:170])
    try:
        r = requests.get(test, allow_redirects=True, timeout=25, verify=False,
                         headers=UA)
        print(f"  final: {r.status_code} {r.url[:110]}")
        hist = r.history
        print(f"  hops: {len(hist)}")
        for h in hist:
            loc = h.headers.get("Location") or ""
            mark = "  <== CANARY" if "google.com" in loc.lower() else ""
            print(f"    {h.status_code} {loc[:100]}{mark}")
        from urllib.parse import urlsplit
        fin_host = (urlsplit(r.url).hostname or "").lower()
        if fin_host in ("google.com", "www.google.com"):
            print("  *** FINAL HOST IS THE CANARY")
        else:
            print(f"  final host stays on {fin_host} -> NOT an open redirect")
    except Exception as e:
        print("  ERR", type(e).__name__, str(e)[:90])

